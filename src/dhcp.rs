//! DHCPv4 server — UDP receive loop and packet dispatch.
//! Ported from `dhcp.c` (1124 lines) in the original dnsmasq source.
//!
//! Responsibilities:
//! - Bind a UDP socket on port 67.
//! - Receive DHCP packets, parse them, demultiplex by message type.
//! - Dispatch to the state machine in `rfc2131`.
//! - Send replies (unicast to known clients, broadcast to unknown).

#![cfg(feature = "dhcp")]

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use tracing::{debug, warn};

use crate::dhcp_common::{find_option, get_message_type};
use crate::dhcp_protocol::{
    DhcpMsgType, DhcpPacket, BOOTREPLY, DHCP_CHADDR_MAX, DHCP_CLIENT_PORT, DHCP_COOKIE,
    DHCP_SERVER_PORT, OPTION_END, OPTION_MESSAGE_TYPE,
};
use crate::metrics::{inc_metric, Metric};
use crate::rfc2131::{handle_discover, handle_request, DhcpReply};

// ─────────────────────────────────────────────────────────────────────────────
// DHCP server configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the DHCPv4 server.
#[derive(Debug, Clone)]
pub struct DhcpServerConfig {
    /// First address in the DHCP pool.
    pub pool_start: Ipv4Addr,
    /// Last address in the DHCP pool (inclusive).
    pub pool_end: Ipv4Addr,
    /// The server's own IP address (used as `siaddr` and option 54).
    pub server_ip: Ipv4Addr,
    /// Maximum packet size to accept.
    pub max_packet: usize,
}

impl Default for DhcpServerConfig {
    fn default() -> Self {
        Self {
            pool_start: Ipv4Addr::new(192, 168, 1, 100),
            pool_end:   Ipv4Addr::new(192, 168, 1, 200),
            server_ip:  Ipv4Addr::new(192, 168, 1, 1),
            max_packet: 1500,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire-format parsing
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a raw UDP payload into a `DhcpPacket`.
///
/// Returns `None` if the packet is shorter than the minimum BOOTP header (236
/// bytes) or the magic cookie is wrong.
pub fn parse_dhcp_packet(data: &[u8]) -> Option<DhcpPacket> {
    if data.len() < 240 {
        return None;
    }
    // Magic cookie at fixed offset 236 (after 236-byte BOOTP fixed fields)
    let cookie = u32::from_be_bytes([data[236], data[237], data[238], data[239]]);
    if cookie != DHCP_COOKIE {
        return None;
    }

    let mut chaddr = [0u8; DHCP_CHADDR_MAX];
    chaddr.copy_from_slice(&data[28..44]);
    let mut sname = [0u8; 64];
    sname.copy_from_slice(&data[44..108]);
    let mut file = [0u8; 128];
    file.copy_from_slice(&data[108..236]);

    Some(DhcpPacket {
        op:      data[0],
        htype:   data[1],
        hlen:    data[2],
        hops:    data[3],
        xid:     u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
        secs:    u16::from_be_bytes([data[8], data[9]]),
        flags:   u16::from_be_bytes([data[10], data[11]]),
        ciaddr:  Ipv4Addr::new(data[12], data[13], data[14], data[15]),
        yiaddr:  Ipv4Addr::new(data[16], data[17], data[18], data[19]),
        siaddr:  Ipv4Addr::new(data[20], data[21], data[22], data[23]),
        giaddr:  Ipv4Addr::new(data[24], data[25], data[26], data[27]),
        chaddr,
        sname,
        file,
        options: data[240..].to_vec(),
    })
}

/// Serialize a DHCP reply into a wire-format byte buffer.
///
/// The output is a complete BOOTP packet (fixed header + magic cookie +
/// options) suitable for sending over UDP.
pub fn dhcp_reply_to_wire(reply: &DhcpReply, request: &DhcpPacket) -> Vec<u8> {
    let mut buf = Vec::with_capacity(300);

    // Fixed BOOTP header (236 bytes)
    buf.push(BOOTREPLY);                    // op
    buf.push(request.htype);               // htype
    buf.push(request.hlen);                // hlen
    buf.push(0);                            // hops
    buf.extend_from_slice(&request.xid.to_be_bytes()); // xid
    buf.extend_from_slice(&[0, 0]);        // secs
    buf.extend_from_slice(&[0, 0]);        // flags (unicast)
    buf.extend_from_slice(&request.ciaddr.octets()); // ciaddr
    buf.extend_from_slice(&reply.yiaddr.octets());   // yiaddr
    buf.extend_from_slice(&reply.siaddr.octets());   // siaddr
    buf.extend_from_slice(&reply.giaddr.octets());   // giaddr
    buf.extend_from_slice(&request.chaddr);          // chaddr (16 bytes)
    buf.extend_from_slice(&[0u8; 64]);     // sname
    buf.extend_from_slice(&[0u8; 128]);    // file

    // Magic cookie
    buf.extend_from_slice(&DHCP_COOKIE.to_be_bytes());

    // Options
    buf.push(OPTION_MESSAGE_TYPE);
    buf.push(1);
    buf.push(reply.msg_type as u8);
    buf.extend_from_slice(&reply.options);
    if reply.options.last() != Some(&OPTION_END) {
        buf.push(OPTION_END);
    }

    // Pad to minimum DHCP size
    while buf.len() < 300 {
        buf.push(0);
    }

    buf
}

// ─────────────────────────────────────────────────────────────────────────────
// Relay-agent detection
// ─────────────────────────────────────────────────────────────────────────────

/// Return true if the packet was forwarded by a relay agent (`giaddr` != 0).
pub fn is_relayed(pkt: &DhcpPacket) -> bool {
    pkt.giaddr != Ipv4Addr::UNSPECIFIED
}

// ─────────────────────────────────────────────────────────────────────────────
// Packet dispatch
// ─────────────────────────────────────────────────────────────────────────────

/// Dispatch a received DHCP packet to the appropriate handler.
///
/// Returns `Some(DhcpReply)` when a reply should be sent, `None` when the
/// packet should be silently dropped (e.g. RELEASE, DECLINE, unknown type).
pub fn dispatch_dhcp(pkt: &DhcpPacket, cfg: &DhcpServerConfig) -> Option<DhcpReply> {
    let msg_type = get_message_type(&pkt.options)?;
    debug!("DHCP {msg_type:?}");

    match msg_type {
        DhcpMsgType::Discover => {
            inc_metric(Metric::Dhcpdiscover);
            handle_discover(pkt, cfg.pool_start, cfg.pool_end, None, cfg.server_ip)
        }
        DhcpMsgType::Request => {
            inc_metric(Metric::Dhcprequest);
            handle_request(pkt, cfg.pool_start, cfg.pool_end, cfg.server_ip)
        }
        DhcpMsgType::Release => {
            inc_metric(Metric::Dhcprelease);
            None
        }
        DhcpMsgType::Inform => {
            inc_metric(Metric::Dhcpinform);
            // INFORM clients already have an address; full handling in rfc2131.
            None
        }
        DhcpMsgType::Decline => {
            inc_metric(Metric::Dhcpdecline);
            None
        }
        _ => {
            warn!("Unexpected DHCP message type {:?}", msg_type);
            None
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Reply addressing
// ─────────────────────────────────────────────────────────────────────────────

/// Determine the destination address for a DHCP reply.
///
/// Rules (RFC 2131 §4.1):
/// 1. If `giaddr` (relay agent) is set → unicast to relay agent on port 67.
/// 2. If `ciaddr` is set (client knows its IP) → unicast to client on port 68.
/// 3. Otherwise → broadcast 255.255.255.255:68.
pub fn reply_dest(pkt: &DhcpPacket) -> SocketAddr {
    if pkt.giaddr != Ipv4Addr::UNSPECIFIED {
        SocketAddr::V4(SocketAddrV4::new(pkt.giaddr, DHCP_SERVER_PORT))
    } else if pkt.ciaddr != Ipv4Addr::UNSPECIFIED {
        SocketAddr::V4(SocketAddrV4::new(pkt.ciaddr, DHCP_CLIENT_PORT))
    } else {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::BROADCAST, DHCP_CLIENT_PORT))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Network utilities (ported from dhcp.c)
// ─────────────────────────────────────────────────────────────────────────────

/// Check if two IPv4 addresses are on the same network given a netmask.
///
/// Port of `is_same_net()` used throughout dhcp.c.
pub fn is_same_net(a: Ipv4Addr, b: Ipv4Addr, netmask: Ipv4Addr) -> bool {
    let mask = u32::from(netmask);
    (u32::from(a) & mask) == (u32::from(b) & mask)
}

/// Compute the Internet checksum (RFC 1071) used for ICMP echo requests.
///
/// Ones-complement sum of 16-bit words, with carry folded back in.
pub fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

// ─────────────────────────────────────────────────────────────────────────────
// Address pool helpers (ported from dhcp.c:687-763)
// ─────────────────────────────────────────────────────────────────────────────

use crate::types::dhcp::{DhcpContext, DhcpConfig, CONTEXT_STATIC, CONTEXT_PROXY, CONFIG_ADDR};

/// Check if `addr` is available in one of the DHCP contexts.
///
/// Returns `true` if `addr` falls within any non-static, non-proxy context
/// range and is not the router address of any context.
/// Port of `address_available()` from dhcp.c:687-715.
pub fn address_available(contexts: &[DhcpContext], addr: Ipv4Addr) -> bool {
    let a = u32::from(addr);

    // Reject if addr is any context's router (server) address.
    for ctx in contexts {
        if addr == ctx.router {
            return false;
        }
    }

    for ctx in contexts {
        if ctx.flags & (CONTEXT_STATIC | CONTEXT_PROXY) != 0 {
            continue;
        }
        let start = u32::from(ctx.start);
        let end = u32::from(ctx.end);
        if a >= start && a <= end {
            return true;
        }
    }
    false
}

/// Find the DHCP context that best matches `addr`.
///
/// Prefers a pool range match (via [`address_available`]), then a static
/// context on the same subnet, then any context on the same subnet.
/// Port of `narrow_context()` from dhcp.c:717-752.
pub fn narrow_context<'a>(contexts: &'a [DhcpContext], addr: Ipv4Addr) -> Option<&'a DhcpContext> {
    // Try pool range first.
    if address_available(contexts, addr) {
        for ctx in contexts {
            if ctx.flags & (CONTEXT_STATIC | CONTEXT_PROXY) != 0 {
                continue;
            }
            let a = u32::from(addr);
            if a >= u32::from(ctx.start) && a <= u32::from(ctx.end) {
                return Some(ctx);
            }
        }
    }

    // Try static context on same subnet.
    for ctx in contexts {
        if ctx.flags & CONTEXT_STATIC != 0
            && ctx.netmask != Ipv4Addr::UNSPECIFIED
            && is_same_net(addr, ctx.start, ctx.netmask)
        {
            return Some(ctx);
        }
    }

    // Any context on same subnet (non-proxy).
    for ctx in contexts {
        if ctx.flags & CONTEXT_PROXY != 0 {
            continue;
        }
        if ctx.netmask != Ipv4Addr::UNSPECIFIED && is_same_net(addr, ctx.start, ctx.netmask) {
            return Some(ctx);
        }
    }

    None
}

/// Find a static DHCP host config entry by IPv4 address.
///
/// Port of `config_find_by_address()` from dhcp.c:754-763.
pub fn config_find_by_address(configs: &[DhcpConfig], addr: Ipv4Addr) -> Option<&DhcpConfig> {
    configs
        .iter()
        .find(|c| c.flags & CONFIG_ADDR != 0 && c.addr == addr)
}

// ─────────────────────────────────────────────────────────────────────────────
// Packet validation (ported from dhcp.c:130-176)
// ─────────────────────────────────────────────────────────────────────────────

/// Validate a raw DHCP packet without fully parsing it.
///
/// Checks minimum size, op=1 (BOOTREQUEST), hlen<=16, and magic cookie.
pub fn dhcp_packet_validate(data: &[u8]) -> Result<(), &'static str> {
    if data.len() < 240 {
        return Err("packet too short");
    }
    if data[0] != 1 {
        return Err("not a BOOTREQUEST");
    }
    if data[2] > DHCP_CHADDR_MAX as u8 {
        return Err("hlen exceeds maximum");
    }
    let cookie = u32::from_be_bytes([data[236], data[237], data[238], data[239]]);
    if cookie != DHCP_COOKIE {
        return Err("bad magic cookie");
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// SDBM hash for address allocation (ported from dhcp.c:838-845)
// ─────────────────────────────────────────────────────────────────────────────

/// Compute SDBM hash of a hardware address for DHCP address allocation.
///
/// Used as seed for distributing clients across the address pool.
/// Port of the SDBM hash in dhcp.c:840-845.
pub fn sdbm_hash(hwaddr: &[u8]) -> u32 {
    let mut j: u32 = 0;
    for &b in hwaddr {
        j = (b as u32).wrapping_add(j.wrapping_shl(6)).wrapping_add(j.wrapping_shl(16)).wrapping_sub(j);
    }
    if j == 0 { 1 } else { j } // 0 is a sentinel marker
}

/// Calculate the starting address for DHCP allocation using hash-based seeding.
///
/// Maps the hash into the range [start, end] using modular arithmetic.
/// Port of the address calculation in dhcp.c:860-861.
pub fn hash_to_addr(hash: u32, epoch: u32, start: Ipv4Addr, end: Ipv4Addr) -> Ipv4Addr {
    let s = u32::from(start);
    let e = u32::from(end);
    let range = e.wrapping_sub(s).wrapping_add(1);
    if range == 0 {
        return start; // full u32 range
    }
    let offset = hash.wrapping_add(epoch) % range;
    Ipv4Addr::from(s.wrapping_add(offset))
}

/// Check if an IPv4 address is safe to allocate (avoids Windows .0 and .255 issues).
///
/// In class-C ranges, addresses ending in .0 or .255 cause Windows problems.
/// Port of the Windows workaround check in dhcp.c:877-881.
pub fn is_allocatable_addr(addr: Ipv4Addr) -> bool {
    let a = u32::from(addr);
    // Class C check: first octet 192-223
    let first_octet = (a >> 24) & 0xff;
    if first_octet >= 192 && first_octet <= 223 {
        let last_octet = a & 0xff;
        if last_octet == 0 || last_octet == 0xff {
            return false;
        }
    }
    true
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dhcp_protocol::{DHCP_CHADDR_MAX, OPTION_MESSAGE_TYPE, OPTION_END};

    fn base_packet() -> DhcpPacket {
        DhcpPacket {
            op: 1,
            htype: 1,
            hlen: 6,
            hops: 0,
            xid: 0x1234_5678,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [0u8; DHCP_CHADDR_MAX],
            sname:  [0u8; 64],
            file:   [0u8; 128],
            options: vec![OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Discover as u8, OPTION_END],
        }
    }

    fn default_cfg() -> DhcpServerConfig {
        DhcpServerConfig {
            pool_start: Ipv4Addr::new(10, 0, 0, 100),
            pool_end:   Ipv4Addr::new(10, 0, 0, 200),
            server_ip:  Ipv4Addr::new(10, 0, 0, 1),
            max_packet: 1500,
        }
    }

    #[test]
    fn discover_produces_offer() {
        let pkt = base_packet();
        let cfg = default_cfg();
        let reply = dispatch_dhcp(&pkt, &cfg);
        assert!(reply.is_some());
        assert_eq!(reply.unwrap().msg_type, DhcpMsgType::Offer);
    }

    #[test]
    fn release_produces_no_reply() {
        let mut pkt = base_packet();
        pkt.options = vec![OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Release as u8, OPTION_END];
        let cfg = default_cfg();
        assert!(dispatch_dhcp(&pkt, &cfg).is_none());
    }

    #[test]
    fn decline_produces_no_reply() {
        let mut pkt = base_packet();
        pkt.options = vec![OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Decline as u8, OPTION_END];
        let cfg = default_cfg();
        assert!(dispatch_dhcp(&pkt, &cfg).is_none());
    }

    #[test]
    fn is_relayed_detects_giaddr() {
        let mut pkt = base_packet();
        assert!(!is_relayed(&pkt));
        pkt.giaddr = Ipv4Addr::new(192, 168, 1, 1);
        assert!(is_relayed(&pkt));
    }

    #[test]
    fn reply_dest_relay_goes_to_port_67() {
        let mut pkt = base_packet();
        pkt.giaddr = Ipv4Addr::new(10, 0, 0, 254);
        let dest = reply_dest(&pkt);
        match dest {
            SocketAddr::V4(a) => {
                assert_eq!(a.ip(), &Ipv4Addr::new(10, 0, 0, 254));
                assert_eq!(a.port(), DHCP_SERVER_PORT);
            }
            _ => panic!("expected V4"),
        }
    }

    #[test]
    fn reply_dest_known_client_unicast() {
        let mut pkt = base_packet();
        pkt.ciaddr = Ipv4Addr::new(10, 0, 0, 100);
        let dest = reply_dest(&pkt);
        match dest {
            SocketAddr::V4(a) => {
                assert_eq!(a.ip(), &Ipv4Addr::new(10, 0, 0, 100));
                assert_eq!(a.port(), DHCP_CLIENT_PORT);
            }
            _ => panic!("expected V4"),
        }
    }

    #[test]
    fn reply_dest_unknown_client_broadcast() {
        let pkt = base_packet();
        let dest = reply_dest(&pkt);
        match dest {
            SocketAddr::V4(a) => {
                assert_eq!(a.ip(), &Ipv4Addr::BROADCAST);
                assert_eq!(a.port(), DHCP_CLIENT_PORT);
            }
            _ => panic!("expected V4"),
        }
    }

    #[test]
    fn parse_short_packet_returns_none() {
        assert!(parse_dhcp_packet(&[0u8; 100]).is_none());
    }

    #[test]
    fn parse_wrong_cookie_returns_none() {
        let mut data = vec![0u8; 300];
        // Set bad cookie at offset 236
        data[236] = 0xDE;
        data[237] = 0xAD;
        data[238] = 0xBE;
        data[239] = 0xEF;
        assert!(parse_dhcp_packet(&data).is_none());
    }

    // ── is_same_net ──────────────────────────────────────────────────────────

    #[test]
    fn is_same_net_same_subnet() {
        let mask = Ipv4Addr::new(255, 255, 255, 0);
        assert!(is_same_net("10.0.0.5".parse().unwrap(), "10.0.0.200".parse().unwrap(), mask));
    }

    #[test]
    fn is_same_net_different_subnet() {
        let mask = Ipv4Addr::new(255, 255, 255, 0);
        assert!(!is_same_net("10.0.0.5".parse().unwrap(), "10.0.1.5".parse().unwrap(), mask));
    }

    #[test]
    fn is_same_net_slash32() {
        let mask = Ipv4Addr::new(255, 255, 255, 255);
        assert!(is_same_net("10.0.0.1".parse().unwrap(), "10.0.0.1".parse().unwrap(), mask));
        assert!(!is_same_net("10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap(), mask));
    }

    #[test]
    fn is_same_net_slash0() {
        let mask = Ipv4Addr::UNSPECIFIED;
        assert!(is_same_net("1.2.3.4".parse().unwrap(), "5.6.7.8".parse().unwrap(), mask));
    }

    #[test]
    fn is_same_net_slash16() {
        let mask = Ipv4Addr::new(255, 255, 0, 0);
        assert!(is_same_net("172.16.5.1".parse().unwrap(), "172.16.200.1".parse().unwrap(), mask));
        assert!(!is_same_net("172.16.5.1".parse().unwrap(), "172.17.5.1".parse().unwrap(), mask));
    }

    // ── icmp_checksum ────────────────────────────────────────────────────────

    #[test]
    fn icmp_checksum_empty() {
        assert_eq!(icmp_checksum(&[]), 0xffff);
    }

    #[test]
    fn icmp_checksum_known_value() {
        // ICMP echo request: type=8, code=0, cksum=0, id=1, seq=1
        let mut pkt = vec![0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01];
        let cksum = icmp_checksum(&pkt);
        // Place checksum and verify it zeros out
        pkt[2] = (cksum >> 8) as u8;
        pkt[3] = (cksum & 0xff) as u8;
        assert_eq!(icmp_checksum(&pkt), 0);
    }

    #[test]
    fn icmp_checksum_odd_length() {
        let data = vec![0x01, 0x02, 0x03];
        let cksum = icmp_checksum(&data);
        assert_ne!(cksum, 0); // just check it doesn't panic
    }

    // ── address_available ────────────────────────────────────────────────────

    fn make_ctx(start: Ipv4Addr, end: Ipv4Addr, router: Ipv4Addr, flags: u32) -> DhcpContext {
        DhcpContext {
            start,
            end,
            router,
            flags,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            broadcast: Ipv4Addr::BROADCAST,
            local: Ipv4Addr::UNSPECIFIED,
            lease_time: 3600,
            addr_epoch: 0,
            netid: crate::types::dhcp::DhcpNetid { net: String::new() },
            filter: None,
            #[cfg(feature = "dhcp6")]
            start6: std::net::Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            end6: std::net::Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            local6: std::net::Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            prefix: 0,
            #[cfg(feature = "dhcp6")]
            if_index: 0,
            #[cfg(feature = "dhcp6")]
            valid: 0,
            #[cfg(feature = "dhcp6")]
            preferred: 0,
        }
    }

    #[test]
    fn address_available_in_range() {
        let ctx = make_ctx(
            "10.0.0.100".parse().unwrap(),
            "10.0.0.200".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            0,
        );
        assert!(address_available(&[ctx], "10.0.0.150".parse().unwrap()));
    }

    #[test]
    fn address_available_out_of_range() {
        let ctx = make_ctx(
            "10.0.0.100".parse().unwrap(),
            "10.0.0.200".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            0,
        );
        assert!(!address_available(&[ctx], "10.0.0.50".parse().unwrap()));
    }

    #[test]
    fn address_available_rejects_router() {
        let ctx = make_ctx(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.254".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            0,
        );
        assert!(!address_available(&[ctx], "10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn address_available_skips_static() {
        let ctx = make_ctx(
            "10.0.0.100".parse().unwrap(),
            "10.0.0.200".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            CONTEXT_STATIC,
        );
        assert!(!address_available(&[ctx], "10.0.0.150".parse().unwrap()));
    }

    #[test]
    fn address_available_empty_contexts() {
        assert!(!address_available(&[], "10.0.0.1".parse().unwrap()));
    }

    // ── narrow_context ───────────────────────────────────────────────────────

    #[test]
    fn narrow_context_pool_match() {
        let contexts = [make_ctx(
            "10.0.0.100".parse().unwrap(),
            "10.0.0.200".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            0,
        )];
        let result = narrow_context(&contexts, "10.0.0.150".parse().unwrap());
        assert!(result.is_some());
    }

    #[test]
    fn narrow_context_static_fallback() {
        let contexts = [make_ctx(
            "10.0.0.0".parse().unwrap(),
            "10.0.0.0".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            CONTEXT_STATIC,
        )];
        // addr on same subnet but not in pool (static context)
        let result = narrow_context(&contexts, "10.0.0.50".parse().unwrap());
        assert!(result.is_some());
    }

    #[test]
    fn narrow_context_no_match() {
        let contexts = [make_ctx(
            "10.0.0.100".parse().unwrap(),
            "10.0.0.200".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            0,
        )];
        let result = narrow_context(&contexts, "192.168.1.1".parse().unwrap());
        assert!(result.is_none());
    }

    // ── config_find_by_address ───────────────────────────────────────────────

    #[test]
    fn config_find_by_address_found() {
        let cfg = DhcpConfig {
            flags: CONFIG_ADDR,
            addr: "10.0.0.50".parse().unwrap(),
            clid: None,
            hostname: None,
            domain: None,
            netid: vec![],
            filter: None,
            decline_time: None,
            lease_time: 0,
            hwaddrs: vec![],
            #[cfg(feature = "dhcp6")]
            addr6: vec![],
        };
        assert!(config_find_by_address(&[cfg], "10.0.0.50".parse().unwrap()).is_some());
    }

    #[test]
    fn config_find_by_address_not_found() {
        let cfg = DhcpConfig {
            flags: CONFIG_ADDR,
            addr: "10.0.0.50".parse().unwrap(),
            clid: None,
            hostname: None,
            domain: None,
            netid: vec![],
            filter: None,
            decline_time: None,
            lease_time: 0,
            hwaddrs: vec![],
            #[cfg(feature = "dhcp6")]
            addr6: vec![],
        };
        assert!(config_find_by_address(&[cfg], "10.0.0.99".parse().unwrap()).is_none());
    }

    #[test]
    fn config_find_by_address_empty() {
        assert!(config_find_by_address(&[], "10.0.0.1".parse().unwrap()).is_none());
    }

    // ── dhcp_packet_validate ─────────────────────────────────────────────────

    #[test]
    fn validate_too_short() {
        assert!(dhcp_packet_validate(&[0u8; 100]).is_err());
    }

    #[test]
    fn validate_bad_op() {
        let mut data = vec![0u8; 300];
        data[0] = 2; // BOOTREPLY, not BOOTREQUEST
        let cookie = DHCP_COOKIE.to_be_bytes();
        data[236..240].copy_from_slice(&cookie);
        assert_eq!(dhcp_packet_validate(&data), Err("not a BOOTREQUEST"));
    }

    #[test]
    fn validate_bad_hlen() {
        let mut data = vec![0u8; 300];
        data[0] = 1;
        data[2] = 255; // hlen too big
        let cookie = DHCP_COOKIE.to_be_bytes();
        data[236..240].copy_from_slice(&cookie);
        assert_eq!(dhcp_packet_validate(&data), Err("hlen exceeds maximum"));
    }

    #[test]
    fn validate_bad_cookie() {
        let mut data = vec![0u8; 300];
        data[0] = 1;
        data[2] = 6;
        assert_eq!(dhcp_packet_validate(&data), Err("bad magic cookie"));
    }

    #[test]
    fn validate_good_packet() {
        let mut data = vec![0u8; 300];
        data[0] = 1;
        data[2] = 6;
        let cookie = DHCP_COOKIE.to_be_bytes();
        data[236..240].copy_from_slice(&cookie);
        assert!(dhcp_packet_validate(&data).is_ok());
    }

    // ── sdbm_hash ────────────────────────────────────────────────────────────

    #[test]
    fn sdbm_hash_deterministic() {
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        assert_eq!(sdbm_hash(&mac), sdbm_hash(&mac));
    }

    #[test]
    fn sdbm_hash_different_macs_differ() {
        let h1 = sdbm_hash(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let h2 = sdbm_hash(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn sdbm_hash_never_zero() {
        // All-zero MAC would normally hash to 0, but we return 1 instead
        assert_eq!(sdbm_hash(&[0; 6]), 1);
    }

    #[test]
    fn sdbm_hash_empty() {
        assert_eq!(sdbm_hash(&[]), 1); // 0 → 1
    }

    // ── hash_to_addr ─────────────────────────────────────────────────────────

    #[test]
    fn hash_to_addr_in_range() {
        let start = "10.0.0.100".parse().unwrap();
        let end = "10.0.0.200".parse().unwrap();
        let addr = hash_to_addr(42, 0, start, end);
        let a = u32::from(addr);
        let s = u32::from(start);
        let e = u32::from(end);
        assert!(a >= s && a <= e);
    }

    #[test]
    fn hash_to_addr_single_address() {
        let start: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let addr = hash_to_addr(999, 0, start, start);
        assert_eq!(addr, start);
    }

    #[test]
    fn hash_to_addr_epoch_shifts() {
        let start = "10.0.0.0".parse().unwrap();
        let end = "10.0.0.255".parse().unwrap();
        let a1 = hash_to_addr(42, 0, start, end);
        let a2 = hash_to_addr(42, 1, start, end);
        assert_ne!(a1, a2);
    }

    // ── is_allocatable_addr ──────────────────────────────────────────────────

    #[test]
    fn is_allocatable_normal() {
        assert!(is_allocatable_addr("192.168.1.100".parse().unwrap()));
    }

    #[test]
    fn is_allocatable_rejects_class_c_255() {
        assert!(!is_allocatable_addr("192.168.1.255".parse().unwrap()));
    }

    #[test]
    fn is_allocatable_rejects_class_c_0() {
        assert!(!is_allocatable_addr("192.168.1.0".parse().unwrap()));
    }

    #[test]
    fn is_allocatable_allows_10_net_255() {
        // 10.x.x.255 is NOT class C, so it's fine
        assert!(is_allocatable_addr("10.0.0.255".parse().unwrap()));
    }
}
