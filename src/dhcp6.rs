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
}
