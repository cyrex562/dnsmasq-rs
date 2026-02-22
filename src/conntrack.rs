//! Linux conntrack socket-mark setting via nfnetlink (message builder only).
#![cfg(feature = "conntrack")]

use std::net::{IpAddr, SocketAddr};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ConntrackMark {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub mark: u32,
}

// ---------------------------------------------------------------------------
// Netlink / nfct protocol constants
// ---------------------------------------------------------------------------

// NETLINK_NETFILTER subsystem for conntrack
const NFNL_SUBSYS_CTNETLINK: u16 = 1;
const IPCTNL_MSG_CT_NEW: u8 = 0;

// CTA attributes
const CTA_TUPLE_ORIG: u16 = 1;
const CTA_MARK: u16 = 8;

// CTA_TUPLE sub-attrs
const CTA_TUPLE_IP: u16 = 1;
const CTA_TUPLE_PROTO: u16 = 2;

// CTA_IP sub-attrs
const CTA_IP_V4_SRC: u16 = 1;
const CTA_IP_V4_DST: u16 = 2;
const CTA_IP_V6_SRC: u16 = 3;
const CTA_IP_V6_DST: u16 = 4;

// CTA_PROTO sub-attrs
const CTA_PROTO_NUM: u16 = 1;
const CTA_PROTO_SRC_PORT: u16 = 2;
const CTA_PROTO_DST_PORT: u16 = 3;

const NLA_F_NESTED: u16 = 1 << 15;
const IPPROTO_UDP: u8 = 17;

// Address families
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn append_u16_le(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn append_u32_le(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn append_nla(buf: &mut Vec<u8>, nla_type: u16, data: &[u8]) {
    let len = 4 + data.len();
    append_u16_le(buf, len as u16);
    append_u16_le(buf, nla_type);
    buf.extend_from_slice(data);
    let pad = (4 - (len % 4)) % 4;
    for _ in 0..pad {
        buf.push(0);
    }
}

fn append_nested(buf: &mut Vec<u8>, nla_type: u16, body: Vec<u8>) {
    append_nla(buf, nla_type | NLA_F_NESTED, &body);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Build a netlink nfct message to set a conntrack mark for a flow.
///
/// Layout:
///   nlmsghdr (16) | nfgenmsg (4) | CTA_TUPLE_ORIG | CTA_MARK
pub fn build_ctmark_msg(mark: &ConntrackMark) -> Vec<u8> {
    let family = match mark.src.ip() {
        IpAddr::V4(_) => AF_INET,
        IpAddr::V6(_) => AF_INET6,
    };

    // --- CTA_TUPLE_IP ---
    let mut ip_body: Vec<u8> = Vec::new();
    match (mark.src.ip(), mark.dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            append_nla(&mut ip_body, CTA_IP_V4_SRC, &s.octets());
            append_nla(&mut ip_body, CTA_IP_V4_DST, &d.octets());
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            append_nla(&mut ip_body, CTA_IP_V6_SRC, &s.octets());
            append_nla(&mut ip_body, CTA_IP_V6_DST, &d.octets());
        }
        _ => {
            // Mixed address families — emit empty ip body
        }
    }

    // --- CTA_TUPLE_PROTO ---
    let mut proto_body: Vec<u8> = Vec::new();
    append_nla(&mut proto_body, CTA_PROTO_NUM, &[IPPROTO_UDP]);
    append_nla(
        &mut proto_body,
        CTA_PROTO_SRC_PORT,
        &mark.src.port().to_be_bytes(),
    );
    append_nla(
        &mut proto_body,
        CTA_PROTO_DST_PORT,
        &mark.dst.port().to_be_bytes(),
    );

    // --- CTA_TUPLE_ORIG (nested) ---
    let mut tuple_body: Vec<u8> = Vec::new();
    append_nested(&mut tuple_body, CTA_TUPLE_IP, ip_body);
    append_nested(&mut tuple_body, CTA_TUPLE_PROTO, proto_body);

    // --- Top-level NLAs ---
    let mut nlas: Vec<u8> = Vec::new();
    append_nested(&mut nlas, CTA_TUPLE_ORIG, tuple_body);
    // CTA_MARK is big-endian u32
    append_nla(&mut nlas, CTA_MARK, &mark.mark.to_be_bytes());

    // --- nfgenmsg ---
    let nfgenmsg = vec![family, 0u8, 0u8, 0u8];

    // --- nlmsghdr ---
    let msg_type: u16 = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_NEW as u16;
    let total_len = 16u32 + nfgenmsg.len() as u32 + nlas.len() as u32;

    let mut buf: Vec<u8> = Vec::new();
    append_u32_le(&mut buf, total_len);
    append_u16_le(&mut buf, msg_type);
    append_u16_le(&mut buf, 0x0501); // NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE
    append_u32_le(&mut buf, 1); // seq
    append_u32_le(&mut buf, 0); // pid
    buf.extend_from_slice(&nfgenmsg);
    buf.extend_from_slice(&nlas);
    buf
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn test_build_ctmark_msg_ipv4_nonempty() {
        let m = ConntrackMark {
            src: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 12345)),
            dst: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53)),
            mark: 0xDEADBEEF,
        };
        let buf = build_ctmark_msg(&m);
        assert!(!buf.is_empty(), "message must be non-empty");
        // Mark value (big-endian) must appear somewhere in the payload
        let mark_be = 0xDEADBEEFu32.to_be_bytes();
        assert!(
            buf.windows(4).any(|w| w == mark_be),
            "mark value must be present in the message"
        );
    }

    #[test]
    fn test_build_ctmark_msg_family_byte() {
        let m = ConntrackMark {
            src: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 1024)),
            dst: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(5, 6, 7, 8), 53)),
            mark: 42,
        };
        let buf = build_ctmark_msg(&m);
        // nfgenmsg family is at offset 16
        assert_eq!(buf[16], AF_INET, "family must be AF_INET for IPv4");
    }

    #[test]
    fn test_build_ctmark_msg_mark_zero() {
        let m = ConntrackMark {
            src: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9999)),
            dst: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53)),
            mark: 0,
        };
        let buf = build_ctmark_msg(&m);
        assert!(!buf.is_empty());
    }
}
