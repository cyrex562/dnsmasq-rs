//! DHCPv6 server — UDP receive loop and packet dispatch.
//! Ported from `dhcp6.c` (881 lines) in the original dnsmasq source.
//!
//! DHCPv6 uses UDP on port 547 (server) / 546 (client), sending to the
//! all-servers multicast group FF05::1:3 or all-agents FF02::1:2.

#![cfg(feature = "dhcp6")]

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};

use tracing::{debug, warn};

use crate::dhcp6_protocol::{
    Dhcp6MsgType, DHCPV6_CLIENT_PORT, DHCPV6_SERVER_PORT,
    OPTION6_CLIENT_ID, OPTION6_SERVER_ID,
};
use crate::metrics::{inc_metric, Metric};

// ─────────────────────────────────────────────────────────────────────────────
// DHCPv6 packet representation
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed DHCPv6 message (non-relay).
#[derive(Debug, Clone)]
pub struct Dhcp6Packet {
    /// Message type byte.
    pub msg_type: Dhcp6MsgType,
    /// Transaction ID (3 bytes, stored in the low 24 bits of a u32).
    pub xid: u32,
    /// Raw options bytes (remainder of the packet after the 4-byte header).
    pub options: Vec<u8>,
}

/// A DHCPv6 relay message (RELAY-FORW or RELAY-REPL).
#[derive(Debug, Clone)]
pub struct Dhcp6RelayMsg {
    pub msg_type:  Dhcp6MsgType,
    pub hop_count: u8,
    pub link_addr: Ipv6Addr,
    pub peer_addr: Ipv6Addr,
    pub options:   Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire-format parsing
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a raw UDP payload into a `Dhcp6Packet`.
///
/// Returns `None` if the packet is shorter than 4 bytes or the message type
/// is not recognized.  Relay messages (RELAY-FORW / RELAY-REPL) require at
/// least 34 bytes and are returned as `Err(Dhcp6RelayMsg)`.
pub fn parse_dhcp6_packet(data: &[u8]) -> Result<Dhcp6Packet, Option<Dhcp6RelayMsg>> {
    if data.len() < 4 {
        return Err(None);
    }
    let msg_type = Dhcp6MsgType::from_u8(data[0]).ok_or(None)?;

    // Relay messages have a different header layout.
    if matches!(msg_type, Dhcp6MsgType::RelayForw | Dhcp6MsgType::RelayRepl) {
        if data.len() < 34 {
            return Err(None);
        }
        let hop_count = data[1];
        let link_addr = Ipv6Addr::from(<[u8; 16]>::try_from(&data[2..18]).unwrap());
        let peer_addr = Ipv6Addr::from(<[u8; 16]>::try_from(&data[18..34]).unwrap());
        return Err(Some(Dhcp6RelayMsg {
            msg_type,
            hop_count,
            link_addr,
            peer_addr,
            options: data[34..].to_vec(),
        }));
    }

    let xid = u32::from_be_bytes([0, data[1], data[2], data[3]]);
    Ok(Dhcp6Packet {
        msg_type,
        xid,
        options: data[4..].to_vec(),
    })
}

/// Find a DHCPv6 option by code in a raw options buffer.
///
/// Returns a slice of the option *value* (excluding the 4-byte TLV header)
/// or `None` if not present.
pub fn find_option6(options: &[u8], code: u16) -> Option<&[u8]> {
    let mut i = 0;
    while i + 4 <= options.len() {
        let opt_code = u16::from_be_bytes([options[i], options[i + 1]]);
        let opt_len  = u16::from_be_bytes([options[i + 2], options[i + 3]]) as usize;
        i += 4;
        if i + opt_len > options.len() {
            break;
        }
        if opt_code == code {
            return Some(&options[i..i + opt_len]);
        }
        i += opt_len;
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Reply construction
// ─────────────────────────────────────────────────────────────────────────────

/// A minimal DHCPv6 reply.
#[derive(Debug, Clone)]
pub struct Dhcp6Reply {
    pub msg_type: Dhcp6MsgType,
    pub xid:      u32,
    pub options:  Vec<u8>,
}

impl Dhcp6Reply {
    /// Serialize to wire format.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + self.options.len());
        buf.push(self.msg_type as u8);
        buf.push(((self.xid >> 16) & 0xFF) as u8);
        buf.push(((self.xid >>  8) & 0xFF) as u8);
        buf.push(( self.xid        & 0xFF) as u8);
        buf.extend_from_slice(&self.options);
        buf
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Packet dispatch
// ─────────────────────────────────────────────────────────────────────────────

/// Dispatch a parsed DHCPv6 packet.
///
/// Returns `Some(Dhcp6Reply)` when a reply should be sent, `None` to drop.
pub fn dispatch_dhcp6(pkt: &Dhcp6Packet) -> Option<Dhcp6Reply> {
    debug!("DHCPv6 {:?} xid={:#x}", pkt.msg_type, pkt.xid);

    match pkt.msg_type {
        Dhcp6MsgType::Solicit => {
            // Respond with Advertise (stub — full address assignment in rfc3315).
            Some(Dhcp6Reply {
                msg_type: Dhcp6MsgType::Advertise,
                xid:      pkt.xid,
                options:  Vec::new(),
            })
        }
        Dhcp6MsgType::Request | Dhcp6MsgType::Renew | Dhcp6MsgType::Rebind |
        Dhcp6MsgType::Confirm => {
            // Respond with Reply.
            Some(Dhcp6Reply {
                msg_type: Dhcp6MsgType::Reply,
                xid:      pkt.xid,
                options:  Vec::new(),
            })
        }
        Dhcp6MsgType::Release | Dhcp6MsgType::Decline => {
            // No reply needed in most cases; send empty Reply to confirm receipt.
            Some(Dhcp6Reply {
                msg_type: Dhcp6MsgType::Reply,
                xid:      pkt.xid,
                options:  Vec::new(),
            })
        }
        Dhcp6MsgType::InfoReq => {
            // Information-only request — reply without IA options.
            Some(Dhcp6Reply {
                msg_type: Dhcp6MsgType::Reply,
                xid:      pkt.xid,
                options:  Vec::new(),
            })
        }
        // Relay messages handled separately by relay_dispatch().
        Dhcp6MsgType::RelayForw | Dhcp6MsgType::RelayRepl |
        Dhcp6MsgType::Advertise | Dhcp6MsgType::Reply |
        Dhcp6MsgType::Reconfigure => {
            warn!("Unexpected DHCPv6 message type {:?}", pkt.msg_type);
            None
        }
    }
}

/// Determine where to send a DHCPv6 reply.
///
/// DHCPv6 replies go to the client's link-local address on port 546.
/// If the source address is unspecified, use all-nodes multicast.
pub fn dhcp6_reply_dest(src: SocketAddr) -> SocketAddr {
    match src {
        SocketAddr::V6(v6) => {
            SocketAddr::V6(SocketAddrV6::new(*v6.ip(), DHCPV6_CLIENT_PORT, 0, v6.scope_id()))
        }
        _ => {
            // Fallback: all-nodes link-local multicast
            let all_nodes: Ipv6Addr = "ff02::1".parse().unwrap();
            SocketAddr::V6(SocketAddrV6::new(all_nodes, DHCPV6_CLIENT_PORT, 0, 0))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IPv6 address helpers (ported from dhcp6.c:575-615)
// ─────────────────────────────────────────────────────────────────────────────

/// Extract the lower 64 bits of an IPv6 address (the host part).
fn addr6part(addr: &Ipv6Addr) -> u64 {
    let o = addr.octets();
    u64::from_be_bytes(o[8..16].try_into().unwrap())
}

/// Check if two IPv6 addresses share the same prefix of `prefix_len` bits.
pub fn is_same_net6(a: &Ipv6Addr, b: &Ipv6Addr, prefix_len: i32) -> bool {
    let a_oct = a.octets();
    let b_oct = b.octets();
    let mut remaining = prefix_len as usize;
    for i in 0..16 {
        if remaining == 0 {
            break;
        }
        if remaining >= 8 {
            if a_oct[i] != b_oct[i] {
                return false;
            }
            remaining -= 8;
        } else {
            let mask = 0xFF << (8 - remaining);
            if (a_oct[i] & mask) != (b_oct[i] & mask) {
                return false;
            }
            remaining = 0;
        }
    }
    true
}

/// Check if `addr` can be dynamically allocated from one of the DHCPv6 contexts.
///
/// Returns `true` if addr falls within any non-static context range on the same prefix.
/// Port of `address6_available()` from dhcp6.c:575-599.
pub fn address6_available(contexts: &[crate::types::dhcp::DhcpContext], addr: &Ipv6Addr) -> bool {
    let a = addr6part(addr);
    for ctx in contexts {
        #[cfg(feature = "dhcp6")]
        {
            use crate::types::dhcp::{CONTEXT_STATIC, CONTEXT_RA_STATELESS};
            if ctx.flags & (CONTEXT_STATIC | CONTEXT_RA_STATELESS) != 0 {
                continue;
            }
            if !is_same_net6(&ctx.start6, addr, ctx.prefix) {
                continue;
            }
            let start = addr6part(&ctx.start6);
            let end = addr6part(&ctx.end6);
            if a >= start && a <= end {
                return true;
            }
        }
    }
    false
}

/// Check if `addr` is valid for any configured DHCPv6 context (static or dynamic).
///
/// Returns `true` if addr is on the same prefix as any context.
/// Port of `address6_valid()` from dhcp6.c:601-615.
pub fn address6_valid(contexts: &[crate::types::dhcp::DhcpContext], addr: &Ipv6Addr) -> bool {
    for ctx in contexts {
        #[cfg(feature = "dhcp6")]
        {
            if is_same_net6(&ctx.start6, addr, ctx.prefix) {
                return true;
            }
        }
    }
    false
}

/// Find a static DHCPv6 host config matching an address.
///
/// Port of `config_find_by_address6()` from dhcp6.c:474-490.
#[cfg(feature = "dhcp6")]
pub fn config_find_by_address6(
    configs: &[crate::types::dhcp::DhcpConfig],
    addr: &Ipv6Addr,
) -> bool {
    use crate::types::addr::AllAddr;
    use crate::types::dhcp::CONFIG_ADDR6;
    for config in configs {
        if config.flags & CONFIG_ADDR6 == 0 {
            continue;
        }
        for a6 in &config.addr6 {
            if let AllAddr::Addr6(ref v6) = a6.addr {
                if is_same_net6(v6, addr, 128) {
                    return true;
                }
            }
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn solicit_pkt(xid: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(Dhcp6MsgType::Solicit as u8);
        v.push(((xid >> 16) & 0xFF) as u8);
        v.push(((xid >>  8) & 0xFF) as u8);
        v.push(( xid        & 0xFF) as u8);
        v
    }

    #[test]
    fn parse_solicit_ok() {
        let data = solicit_pkt(0xABCD12);
        let pkt = parse_dhcp6_packet(&data).unwrap();
        assert_eq!(pkt.msg_type, Dhcp6MsgType::Solicit);
        assert_eq!(pkt.xid, 0xABCD12);
    }

    #[test]
    fn parse_short_returns_err() {
        assert!(parse_dhcp6_packet(&[1, 2, 3]).is_err());
    }

    #[test]
    fn parse_unknown_type_returns_err() {
        assert!(parse_dhcp6_packet(&[0xFF, 0, 0, 0]).is_err());
    }

    #[test]
    fn solicit_dispatches_to_advertise() {
        let data = solicit_pkt(0x1234);
        let pkt = parse_dhcp6_packet(&data).unwrap();
        let reply = dispatch_dhcp6(&pkt);
        assert!(reply.is_some());
        assert_eq!(reply.unwrap().msg_type, Dhcp6MsgType::Advertise);
    }

    #[test]
    fn request_dispatches_to_reply() {
        let mut data = solicit_pkt(0x5678);
        data[0] = Dhcp6MsgType::Request as u8;
        let pkt = parse_dhcp6_packet(&data).unwrap();
        let reply = dispatch_dhcp6(&pkt);
        assert_eq!(reply.unwrap().msg_type, Dhcp6MsgType::Reply);
    }

    #[test]
    fn find_option6_present() {
        // Build an option buffer with option code 1, length 2, value [0xAB, 0xCD]
        let opts = [0, 1, 0, 2, 0xAB, 0xCD, 0, 2, 0, 1, 0xFF];
        let val = find_option6(&opts, 1).unwrap();
        assert_eq!(val, &[0xAB, 0xCD]);
    }

    #[test]
    fn find_option6_missing() {
        let opts = [0, 1, 0, 2, 0xAB, 0xCD];
        assert!(find_option6(&opts, 99).is_none());
    }

    #[test]
    fn reply_to_wire_roundtrip() {
        let reply = Dhcp6Reply {
            msg_type: Dhcp6MsgType::Advertise,
            xid:      0xAABBCC,
            options:  vec![0x00, 0x01, 0x00, 0x00], // empty option 1
        };
        let wire = reply.to_wire();
        assert_eq!(wire[0], Dhcp6MsgType::Advertise as u8);
        assert_eq!(wire[1], 0xAA);
        assert_eq!(wire[2], 0xBB);
        assert_eq!(wire[3], 0xCC);
    }

    #[test]
    fn parse_relay_forw() {
        let mut data = vec![0u8; 34];
        data[0] = Dhcp6MsgType::RelayForw as u8;
        data[1] = 5; // hop count
        // link_addr and peer_addr are all zeros
        let result = parse_dhcp6_packet(&data);
        assert!(result.is_err());
        let relay = result.err().unwrap().unwrap();
        assert_eq!(relay.msg_type, Dhcp6MsgType::RelayForw);
        assert_eq!(relay.hop_count, 5);
    }

    // ── is_same_net6 ─────────────────────────────────────────────────────────

    #[test]
    fn is_same_net6_same_prefix() {
        let a: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let b: Ipv6Addr = "2001:db8::ffff".parse().unwrap();
        assert!(is_same_net6(&a, &b, 64));
    }

    #[test]
    fn is_same_net6_different_prefix() {
        let a: Ipv6Addr = "2001:db8:1::1".parse().unwrap();
        let b: Ipv6Addr = "2001:db8:2::1".parse().unwrap();
        assert!(!is_same_net6(&a, &b, 48));
    }

    #[test]
    fn is_same_net6_exact_match() {
        let a: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let b: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(is_same_net6(&a, &b, 128));
    }

    #[test]
    fn is_same_net6_exact_mismatch() {
        let a: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let b: Ipv6Addr = "2001:db8::2".parse().unwrap();
        assert!(!is_same_net6(&a, &b, 128));
    }

    #[test]
    fn is_same_net6_zero_prefix() {
        let a: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let b: Ipv6Addr = "fe80::1".parse().unwrap();
        assert!(is_same_net6(&a, &b, 0));
    }

    // ── addr6part ────────────────────────────────────────────────────────────

    #[test]
    fn addr6part_extracts_low64() {
        let a: Ipv6Addr = "2001:db8::42".parse().unwrap();
        assert_eq!(addr6part(&a), 0x42);
    }

    #[test]
    fn addr6part_max() {
        let a: Ipv6Addr = "::ffff:ffff:ffff:ffff".parse().unwrap();
        assert_eq!(addr6part(&a), u64::MAX);
    }

    // ── address6_available / address6_valid ───────────────────────────────────

    #[cfg(feature = "dhcp6")]
    fn make_v6_ctx(start6: Ipv6Addr, end6: Ipv6Addr, prefix: i32, flags: u32) -> crate::types::dhcp::DhcpContext {
        use std::net::Ipv4Addr;
        crate::types::dhcp::DhcpContext {
            start: Ipv4Addr::UNSPECIFIED,
            end: Ipv4Addr::UNSPECIFIED,
            router: Ipv4Addr::UNSPECIFIED,
            flags,
            netmask: Ipv4Addr::new(0,0,0,0),
            broadcast: Ipv4Addr::new(0,0,0,0),
            local: Ipv4Addr::new(0,0,0,0),
            lease_time: 3600,
            addr_epoch: 0,
            netid: crate::types::dhcp::DhcpNetid { net: String::new() },
            filter: None,
            start6,
            end6,
            local6: Ipv6Addr::UNSPECIFIED,
            prefix,
            if_index: 0,
            valid: 0,
            preferred: 0,
        }
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn address6_available_in_range() {
        let ctx = make_v6_ctx(
            "2001:db8::100".parse().unwrap(),
            "2001:db8::200".parse().unwrap(),
            64, 0,
        );
        assert!(address6_available(&[ctx], &"2001:db8::150".parse().unwrap()));
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn address6_available_out_of_range() {
        let ctx = make_v6_ctx(
            "2001:db8::100".parse().unwrap(),
            "2001:db8::200".parse().unwrap(),
            64, 0,
        );
        assert!(!address6_available(&[ctx], &"2001:db8::50".parse().unwrap()));
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn address6_available_skips_static() {
        use crate::types::dhcp::CONTEXT_STATIC;
        let ctx = make_v6_ctx(
            "2001:db8::100".parse().unwrap(),
            "2001:db8::200".parse().unwrap(),
            64, CONTEXT_STATIC,
        );
        assert!(!address6_available(&[ctx], &"2001:db8::150".parse().unwrap()));
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn address6_valid_on_prefix() {
        let ctx = make_v6_ctx(
            "2001:db8::100".parse().unwrap(),
            "2001:db8::200".parse().unwrap(),
            64, 0,
        );
        assert!(address6_valid(&[ctx], &"2001:db8::999".parse().unwrap()));
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn address6_valid_wrong_prefix() {
        let ctx = make_v6_ctx(
            "2001:db8:1::100".parse().unwrap(),
            "2001:db8:1::200".parse().unwrap(),
            48, 0,
        );
        assert!(!address6_valid(&[ctx], &"2001:db8:2::1".parse().unwrap()));
    }
}
