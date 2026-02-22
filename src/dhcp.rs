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
}
