//! DHCPv6 protocol state machine: Solicit/Advertise/Request/Reply/etc.
//! Ported from `rfc3315.c`.

#[cfg(feature = "dhcp6")]
use std::net::Ipv6Addr;
#[cfg(feature = "dhcp6")]
use crate::dhcp6_protocol::{
    Dhcp6MsgType,
    OPTION6_CLIENT_ID, OPTION6_SERVER_ID, OPTION6_IA_NA, OPTION6_IAADDR, OPTION6_STATUS_CODE,
};

/// A single DHCPv6 option (code + raw data bytes).
#[cfg(feature = "dhcp6")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dhcp6Option {
    pub code: u16,
    pub data: Vec<u8>,
}

/// A parsed DHCPv6 packet.
#[cfg(feature = "dhcp6")]
#[derive(Debug, Clone)]
pub struct Dhcp6Packet {
    pub msg_type: Dhcp6MsgType,
    pub txn_id:   [u8; 3],
    pub options:  Vec<Dhcp6Option>,
}

/// Errors that can occur when parsing or building a DHCPv6 packet.
#[cfg(feature = "dhcp6")]
#[derive(Debug, thiserror::Error)]
pub enum Dhcp6Error {
    #[error("packet too short")]
    TooShort,
    #[error("invalid message type: {0}")]
    InvalidMsgType(u8),
    #[error("malformed option")]
    MalformedOption,
}

/// Parse a DHCPv6 packet from wire bytes.
///
/// Wire format: 1-byte msg-type | 3-byte txn-id | options …
/// Each option: 2-byte code | 2-byte length | `length` bytes data
#[cfg(feature = "dhcp6")]
pub fn parse_dhcp6_packet(pkt: &[u8]) -> Result<Dhcp6Packet, Dhcp6Error> {
    if pkt.len() < 4 {
        return Err(Dhcp6Error::TooShort);
    }
    let msg_type = Dhcp6MsgType::from_u8(pkt[0])
        .ok_or(Dhcp6Error::InvalidMsgType(pkt[0]))?;
    let txn_id = [pkt[1], pkt[2], pkt[3]];

    let mut options = Vec::new();
    let mut pos = 4usize;
    while pos < pkt.len() {
        if pos + 4 > pkt.len() {
            return Err(Dhcp6Error::MalformedOption);
        }
        let code = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
        let len  = u16::from_be_bytes([pkt[pos + 2], pkt[pos + 3]]) as usize;
        pos += 4;
        if pos + len > pkt.len() {
            return Err(Dhcp6Error::MalformedOption);
        }
        options.push(Dhcp6Option { code, data: pkt[pos..pos + len].to_vec() });
        pos += len;
    }

    Ok(Dhcp6Packet { msg_type, txn_id, options })
}

/// Serialize a DHCPv6 packet to wire bytes.
#[cfg(feature = "dhcp6")]
pub fn write_dhcp6_packet(pkt: &Dhcp6Packet) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(pkt.msg_type as u8);
    out.extend_from_slice(&pkt.txn_id);
    for opt in &pkt.options {
        out.extend_from_slice(&opt.code.to_be_bytes());
        out.extend_from_slice(&(opt.data.len() as u16).to_be_bytes());
        out.extend_from_slice(&opt.data);
    }
    out
}

/// Find an option by code in a packet's options list.
#[cfg(feature = "dhcp6")]
pub fn find_option6<'a>(opts: &'a [Dhcp6Option], code: u16) -> Option<&'a Dhcp6Option> {
    opts.iter().find(|o| o.code == code)
}

/// Encode an IPv6 address as 16 raw bytes.
#[cfg(feature = "dhcp6")]
fn addr6_bytes(addr: Ipv6Addr) -> [u8; 16] {
    addr.octets()
}

/// Build a status-code option (code 13) with status 0 (Success).
#[cfg(feature = "dhcp6")]
fn status_success() -> Dhcp6Option {
    Dhcp6Option {
        code: OPTION6_STATUS_CODE,
        data: vec![0x00, 0x00], // status code 0 = Success, no message
    }
}

/// Build an IA_NA option containing one IAADDR sub-option for `addr`.
///
/// Layout (per RFC 3315):
///   IA_NA: 4-byte IAID | 4-byte T1 | 4-byte T2 | sub-options …
///   IAADDR sub-option: 16-byte addr | 4-byte preferred-lt | 4-byte valid-lt | sub-options …
#[cfg(feature = "dhcp6")]
fn build_ia_na(iaid: [u8; 4], addr: Ipv6Addr) -> Dhcp6Option {
    let preferred_lt: u32 = 3600;
    let valid_lt:     u32 = 7200;
    let t1:           u32 = 1800;
    let t2:           u32 = 2880;

    // Build IAADDR sub-option data
    let mut iaaddr_data = Vec::with_capacity(24);
    iaaddr_data.extend_from_slice(&addr6_bytes(addr));
    iaaddr_data.extend_from_slice(&preferred_lt.to_be_bytes());
    iaaddr_data.extend_from_slice(&valid_lt.to_be_bytes());

    // Encode IAADDR as a sub-option TLV inside IA_NA data
    let mut ia_na_data = Vec::new();
    ia_na_data.extend_from_slice(&iaid);
    ia_na_data.extend_from_slice(&t1.to_be_bytes());
    ia_na_data.extend_from_slice(&t2.to_be_bytes());
    ia_na_data.extend_from_slice(&OPTION6_IAADDR.to_be_bytes());
    ia_na_data.extend_from_slice(&(iaaddr_data.len() as u16).to_be_bytes());
    ia_na_data.extend_from_slice(&iaaddr_data);

    Dhcp6Option { code: OPTION6_IA_NA, data: ia_na_data }
}

/// Build a simple Advertise reply to a Solicit.
#[cfg(feature = "dhcp6")]
pub fn handle_solicit(
    solicit: &Dhcp6Packet,
    server_duid: &[u8],
    offered_addr: Ipv6Addr,
) -> Dhcp6Packet {
    // Extract IAID from the client's IA_NA option (bytes 0..4), default to zeros
    let iaid = if let Some(ia) = find_option6(&solicit.options, OPTION6_IA_NA) {
        if ia.data.len() >= 4 {
            [ia.data[0], ia.data[1], ia.data[2], ia.data[3]]
        } else {
            [0u8; 4]
        }
    } else {
        [0u8; 4]
    };

    let client_id_opt = find_option6(&solicit.options, OPTION6_CLIENT_ID)
        .cloned()
        .unwrap_or(Dhcp6Option { code: OPTION6_CLIENT_ID, data: vec![] });

    let mut options = Vec::new();
    options.push(client_id_opt);
    options.push(Dhcp6Option { code: OPTION6_SERVER_ID, data: server_duid.to_vec() });
    options.push(build_ia_na(iaid, offered_addr));
    options.push(status_success());

    Dhcp6Packet {
        msg_type: Dhcp6MsgType::Advertise,
        txn_id:   solicit.txn_id,
        options,
    }
}

/// Build a Reply to a Request.
#[cfg(feature = "dhcp6")]
pub fn handle_request6(
    req: &Dhcp6Packet,
    server_duid: &[u8],
    assigned_addr: Ipv6Addr,
) -> Dhcp6Packet {
    let iaid = if let Some(ia) = find_option6(&req.options, OPTION6_IA_NA) {
        if ia.data.len() >= 4 {
            [ia.data[0], ia.data[1], ia.data[2], ia.data[3]]
        } else {
            [0u8; 4]
        }
    } else {
        [0u8; 4]
    };

    let client_id_opt = find_option6(&req.options, OPTION6_CLIENT_ID)
        .cloned()
        .unwrap_or(Dhcp6Option { code: OPTION6_CLIENT_ID, data: vec![] });

    let mut options = Vec::new();
    options.push(client_id_opt);
    options.push(Dhcp6Option { code: OPTION6_SERVER_ID, data: server_duid.to_vec() });
    options.push(build_ia_na(iaid, assigned_addr));
    options.push(status_success());

    Dhcp6Packet {
        msg_type: Dhcp6MsgType::Reply,
        txn_id:   req.txn_id,
        options,
    }
}

#[cfg(all(test, feature = "dhcp6"))]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn make_solicit() -> Dhcp6Packet {
        let client_duid = vec![0x00, 0x01, 0xAA, 0xBB];
        let iaid: [u8; 4] = [0x00, 0x00, 0x00, 0x01];
        // IA_NA data: IAID(4) + T1(4) + T2(4)  — no sub-options for the solicit
        let mut ia_na_data = Vec::new();
        ia_na_data.extend_from_slice(&iaid);
        ia_na_data.extend_from_slice(&1800u32.to_be_bytes());
        ia_na_data.extend_from_slice(&2880u32.to_be_bytes());

        Dhcp6Packet {
            msg_type: Dhcp6MsgType::Solicit,
            txn_id:   [0x11, 0x22, 0x33],
            options: vec![
                Dhcp6Option { code: OPTION6_CLIENT_ID, data: client_duid },
                Dhcp6Option { code: OPTION6_IA_NA,     data: ia_na_data },
            ],
        }
    }

    #[test]
    fn roundtrip() {
        let pkt = make_solicit();
        let bytes = write_dhcp6_packet(&pkt);
        let parsed = parse_dhcp6_packet(&bytes).unwrap();
        assert_eq!(parsed.msg_type, pkt.msg_type);
        assert_eq!(parsed.txn_id,   pkt.txn_id);
        assert_eq!(parsed.options.len(), pkt.options.len());
        for (a, b) in parsed.options.iter().zip(pkt.options.iter()) {
            assert_eq!(a.code, b.code);
            assert_eq!(a.data, b.data);
        }
    }

    #[test]
    fn find_option6_hit_and_miss() {
        let pkt = make_solicit();
        assert!(find_option6(&pkt.options, OPTION6_CLIENT_ID).is_some());
        assert!(find_option6(&pkt.options, OPTION6_IA_NA).is_some());
        assert!(find_option6(&pkt.options, OPTION6_SERVER_ID).is_none());
    }

    #[test]
    fn too_short_error() {
        assert!(matches!(parse_dhcp6_packet(&[]), Err(Dhcp6Error::TooShort)));
        assert!(matches!(parse_dhcp6_packet(&[1, 0, 0]), Err(Dhcp6Error::TooShort)));
    }

    #[test]
    fn invalid_msg_type_error() {
        let data = [0x00u8, 0x11, 0x22, 0x33]; // msg-type 0 is invalid
        assert!(matches!(parse_dhcp6_packet(&data), Err(Dhcp6Error::InvalidMsgType(0))));
    }

    #[test]
    fn malformed_option_error() {
        // Header is fine but option header is truncated
        let data = [0x01u8, 0x11, 0x22, 0x33, 0x00, 0x01]; // 2 option bytes, need 4
        assert!(matches!(parse_dhcp6_packet(&data), Err(Dhcp6Error::MalformedOption)));
    }

    #[test]
    fn handle_solicit_returns_advertise_with_ia_na() {
        let solicit = make_solicit();
        let server_duid = vec![0x00, 0x02, 0xDE, 0xAD];
        let offered = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let adv = handle_solicit(&solicit, &server_duid, offered);
        assert_eq!(adv.msg_type, Dhcp6MsgType::Advertise);
        assert_eq!(adv.txn_id, solicit.txn_id);
        assert!(find_option6(&adv.options, OPTION6_IA_NA).is_some());
        assert!(find_option6(&adv.options, OPTION6_SERVER_ID).is_some());
    }

    #[test]
    fn handle_request6_returns_reply() {
        let solicit = make_solicit();
        let server_duid = vec![0x00, 0x02, 0xDE, 0xAD];
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

        // Turn solicit into a Request
        let mut req = solicit.clone();
        req.msg_type = Dhcp6MsgType::Request;
        req.options.push(Dhcp6Option { code: OPTION6_SERVER_ID, data: server_duid.clone() });

        let reply = handle_request6(&req, &server_duid, addr);
        assert_eq!(reply.msg_type, Dhcp6MsgType::Reply);
        assert_eq!(reply.txn_id, req.txn_id);
        assert!(find_option6(&reply.options, OPTION6_IA_NA).is_some());
    }
}
