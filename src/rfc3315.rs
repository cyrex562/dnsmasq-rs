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

// ─── Wire-level option helpers ────────────────────────────────────────────────
//
// These operate on raw DHCPv6 options wire bytes where each option is:
//   code (2 BE) | length (2 BE) | data (length bytes)
//
// All `opt` slices passed to these helpers include the 4-byte header.
// Mirrors the C opt6_find / opt6_next / opt6_uint helpers in rfc3315.c.

/// Scan a raw options buffer and return the first option whose code equals
/// `search` and whose data length is at least `minsize`.
///
/// Returns a sub-slice covering the full option (header + data), or `None`.
///
/// Mirrors `opt6_find()` in `rfc3315.c`.
#[cfg(feature = "dhcp6")]
pub fn opt6_find(mut opts: &[u8], search: u16, minsize: usize) -> Option<&[u8]> {
    loop {
        if opts.len() < 4 { return None; }
        let code = u16::from_be_bytes([opts[0], opts[1]]);
        let len  = u16::from_be_bytes([opts[2], opts[3]]) as usize;
        if 4 + len > opts.len() { return None; }
        if code == search && len >= minsize {
            return Some(&opts[..4 + len]);
        }
        opts = &opts[4 + len..];
    }
}

/// Advance past the current option and return a slice starting at the next
/// option header, or `None` if there is no next option.
///
/// `opts` must start at an option header (code field).
///
/// Mirrors `opt6_next()` in `rfc3315.c`.
#[cfg(feature = "dhcp6")]
pub fn opt6_next(opts: &[u8]) -> Option<&[u8]> {
    if opts.len() < 4 { return None; }
    let len = u16::from_be_bytes([opts[2], opts[3]]) as usize;
    let next = 4 + len;
    if next >= opts.len() { return None; }
    Some(&opts[next..])
}

/// Read a big-endian unsigned integer of `size` bytes from an option slice.
///
/// `offset` is relative to byte 0 of the slice (the code field).
/// - `offset=0, size=2` → option type code
/// - `offset=2, size=2` → option data length
/// - `offset=4, size=N` → first N bytes of option data
///
/// Returns 0 if the range is out of bounds.
///
/// Mirrors `opt6_uint()` in `rfc3315.c` (where the C version uses a DATA
/// pointer and negative offsets; here we use the full option slice with
/// zero-based offsets from the header start, which avoids unsafe indexing).
#[cfg(feature = "dhcp6")]
pub fn opt6_uint(opt: &[u8], offset: usize, size: usize) -> u32 {
    let end = offset.saturating_add(size);
    if size == 0 || size > 4 || end > opt.len() { return 0; }
    let mut result: u32 = 0;
    for &b in &opt[offset..end] {
        result = (result << 8) | (b as u32);
    }
    result
}

/// Return the option code of a full-option slice.
#[cfg(feature = "dhcp6")]
pub fn opt6_type(opt: &[u8]) -> u16 {
    opt6_uint(opt, 0, 2) as u16
}

/// Return the data length of a full-option slice.
#[cfg(feature = "dhcp6")]
pub fn opt6_len(opt: &[u8]) -> usize {
    opt6_uint(opt, 2, 2) as usize
}

/// Return the data portion of a full-option slice (everything after the 4-byte header).
#[cfg(feature = "dhcp6")]
pub fn opt6_data(opt: &[u8]) -> &[u8] {
    if opt.len() > 4 { &opt[4..] } else { &[] }
}

// ─── DHCPv6 logging helpers ───────────────────────────────────────────────────

/// Build a log line for a single DHCPv6 option (and recursively for IA sub-options).
///
/// Returns a list of log strings (one per option / sub-option level).
/// The caller is responsible for emitting them via `log::info!` or similar.
///
/// Mirrors `log6_opts()` in `rfc3315.c`.
#[cfg(feature = "dhcp6")]
pub fn log6_opts(opts: &[u8], xid: u32, nest: bool) -> Vec<String> {
    use crate::dhcp6_protocol::{OPTION6_IA_NA, OPTION6_IA_TA, OPTION6_IAADDR, OPTION6_STATUS_CODE};

    let desc = if nest { "nest" } else { "sent" };
    let mut lines = Vec::new();
    let mut cursor = opts;

    loop {
        if cursor.len() < 4 { break; }

        let opt_len  = opt6_len(cursor);
        let opt_type = opt6_type(cursor);
        let data     = opt6_data(cursor);

        let (optname, detail, ia_opts_start) = if opt_type == OPTION6_IA_NA {
            let iaid = opt6_uint(cursor, 4, 4);
            let t1   = opt6_uint(cursor, 8, 4);
            let t2   = opt6_uint(cursor, 12, 4);
            let detail = format!("IAID={iaid} T1={t1} T2={t2}");
            let sub = if data.len() > 12 { Some(&data[12..]) } else { None };
            ("ia-na", detail, sub)
        } else if opt_type == OPTION6_IA_TA {
            let iaid   = opt6_uint(cursor, 4, 4);
            let detail = format!("IAID={iaid}");
            let sub    = if data.len() > 4 { Some(&data[4..]) } else { None };
            ("ia-ta", detail, sub)
        } else if opt_type == OPTION6_IAADDR {
            let addr_bytes: [u8; 16] = data.get(..16)
                .and_then(|b| b.try_into().ok())
                .unwrap_or([0u8; 16]);
            let addr  = std::net::Ipv6Addr::from(addr_bytes);
            let pref  = opt6_uint(cursor, 4 + 16, 4);
            let valid = opt6_uint(cursor, 4 + 20, 4);
            let detail = format!("{addr} PL={pref} VL={valid}");
            let sub = if data.len() > 24 { Some(&data[24..]) } else { None };
            ("iaaddr", detail, sub)
        } else if opt_type == OPTION6_STATUS_CODE {
            let code = opt6_uint(cursor, 4, 2);
            let msg  = std::str::from_utf8(data.get(2..).unwrap_or(&[])).unwrap_or("").to_string();
            let detail = format!("{code} {msg}");
            ("status", detail, None)
        } else {
            let detail = format!("{} bytes", opt_len);
            ("unknown", detail, None)
        };

        lines.push(format!(
            "{xid} {desc} size:{opt_len:3} option:{opt_type:3} {optname}  {detail}"
        ));

        if let Some(sub) = ia_opts_start {
            let sub_lines = log6_opts(sub, xid, true);
            lines.extend(sub_lines);
        }

        match opt6_next(cursor) {
            Some(next) => cursor = next,
            None       => break,
        }
    }
    lines
}

/// Build a formatted log line for a DHCPv6 packet event.
///
/// Returns a `String` like:
/// `"<xid> <type>(<iface>) <addr_str><clid_hex> <extra>"`
///
/// Mirrors `log6_packet()` in `rfc3315.c` but returns a `String` rather
/// than calling `my_syslog` directly, so callers can route to any logger.
#[cfg(feature = "dhcp6")]
pub fn log6_packet(
    xid:       u32,
    msg_type:  &str,
    iface:     &str,
    clid:      &[u8],
    addr:      Option<std::net::Ipv6Addr>,
    extra:     Option<&str>,
    log_opts:  bool,
) -> String {
    // Format client-id as colon-separated hex (up to 100 bytes).
    let clid_display: String = clid.iter()
        .take(100)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");

    let addr_str = match addr {
        Some(a) => format!("{a} "),
        None    => String::new(),
    };

    let extra_str = extra.unwrap_or("");

    if log_opts {
        format!("{xid} {msg_type}({iface}) {addr_str}{clid_display} {extra_str}")
    } else {
        format!("{msg_type}({iface}) {addr_str}{clid_display} {extra_str}")
    }
}

/// Conditionally build a log line for a DHCPv6 packet.
///
/// Returns `Some(log_line)` if logging should occur (either `log_opts` is true
/// or `quiet` is false), otherwise `None`.
///
/// Mirrors `log6_quiet()` in `rfc3315.c` (which calls `log6_packet` unless
/// both `OPT_QUIET_DHCP6` is set and `OPT_LOG_OPTS` is unset).
#[cfg(feature = "dhcp6")]
pub fn log6_quiet(
    log_opts:  bool,
    quiet:     bool,
    xid:       u32,
    msg_type:  &str,
    iface:     &str,
    clid:      &[u8],
    addr:      Option<std::net::Ipv6Addr>,
    extra:     Option<&str>,
) -> Option<String> {
    if log_opts || !quiet {
        Some(log6_packet(xid, msg_type, iface, clid, addr, extra, log_opts))
    } else {
        None
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

    // Helper: build a minimal raw options buffer with one option.
    fn raw_option(code: u16, data: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&code.to_be_bytes());
        v.extend_from_slice(&(data.len() as u16).to_be_bytes());
        v.extend_from_slice(data);
        v
    }

    // ── opt6_find ─────────────────────────────────────────────────────────────

    #[test]
    fn opt6_find_finds_first_match() {
        let mut buf = raw_option(1, &[0xAA, 0xBB]);
        buf.extend(raw_option(2, &[0xCC]));
        let found = opt6_find(&buf, 1, 2).unwrap();
        assert_eq!(opt6_type(found), 1);
        assert_eq!(opt6_data(found), &[0xAA, 0xBB]);
    }

    #[test]
    fn opt6_find_skips_to_second_option() {
        let mut buf = raw_option(1, &[0xAA]);
        buf.extend(raw_option(2, &[0xBB, 0xCC]));
        let found = opt6_find(&buf, 2, 1).unwrap();
        assert_eq!(opt6_type(found), 2);
        assert_eq!(opt6_data(found), &[0xBB, 0xCC]);
    }

    #[test]
    fn opt6_find_none_on_missing() {
        let buf = raw_option(1, &[0xAA]);
        assert!(opt6_find(&buf, 99, 0).is_none());
    }

    #[test]
    fn opt6_find_minsize_filter() {
        let buf = raw_option(1, &[0xAA]); // data len = 1
        // Require minsize=2 → should not match
        assert!(opt6_find(&buf, 1, 2).is_none());
    }

    // ── opt6_next ─────────────────────────────────────────────────────────────

    #[test]
    fn opt6_next_advances_to_second() {
        let mut buf = raw_option(1, &[0xAA, 0xBB]);
        buf.extend(raw_option(2, &[0xCC]));
        let next = opt6_next(&buf).unwrap();
        assert_eq!(opt6_type(next), 2);
    }

    #[test]
    fn opt6_next_returns_none_when_only_one() {
        let buf = raw_option(1, &[0xAA]);
        assert!(opt6_next(&buf).is_none());
    }

    // ── opt6_uint ─────────────────────────────────────────────────────────────

    #[test]
    fn opt6_uint_reads_code_and_len() {
        let buf = raw_option(0x0042, &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(opt6_uint(&buf, 0, 2), 0x0042, "code");
        assert_eq!(opt6_uint(&buf, 2, 2), 4,      "len");
        assert_eq!(opt6_uint(&buf, 4, 4), 0x01020304, "data");
    }

    #[test]
    fn opt6_uint_out_of_bounds_returns_zero() {
        let buf = raw_option(1, &[0xAA]);
        assert_eq!(opt6_uint(&buf, 100, 2), 0);
    }

    // ── opt6_type / opt6_len / opt6_data ──────────────────────────────────────

    #[test]
    fn opt6_type_len_data_helpers() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let buf  = raw_option(0x001A, &data);
        assert_eq!(opt6_type(&buf), 0x001A);
        assert_eq!(opt6_len(&buf),  4);
        assert_eq!(opt6_data(&buf), data.as_slice());
    }

    // ── log6_packet / log6_quiet ──────────────────────────────────────────────

    #[test]
    fn log6_packet_includes_key_fields() {
        let line = log6_packet(
            0xABCD, "Solicit", "eth0",
            &[0x01, 0x02], None, Some("hostname"), true,
        );
        assert!(line.contains("Solicit"));
        assert!(line.contains("eth0"));
        assert!(line.contains("01:02"));
        assert!(line.contains("hostname"));
    }

    #[test]
    fn log6_packet_with_addr() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let line = log6_packet(0x1234, "Reply", "eth0", &[], Some(addr), None, false);
        assert!(line.contains("2001:db8"));
    }

    #[test]
    fn log6_quiet_suppresses_when_quiet_and_no_log_opts() {
        let r = log6_quiet(false, true, 1, "Solicit", "eth0", &[], None, None);
        assert!(r.is_none(), "quiet=true, log_opts=false → no output");
    }

    #[test]
    fn log6_quiet_emits_when_not_quiet() {
        let r = log6_quiet(false, false, 1, "Solicit", "eth0", &[], None, None);
        assert!(r.is_some());
    }

    #[test]
    fn log6_quiet_emits_when_log_opts_even_if_quiet() {
        let r = log6_quiet(true, true, 1, "Solicit", "eth0", &[], None, None);
        assert!(r.is_some());
    }

    // ── log6_opts ─────────────────────────────────────────────────────────────

    #[test]
    fn log6_opts_empty_returns_empty() {
        let lines = log6_opts(&[], 1, false);
        assert!(lines.is_empty());
    }

    #[test]
    fn log6_opts_single_unknown_option() {
        let buf = raw_option(999, &[0x01, 0x02, 0x03]);
        let lines = log6_opts(&buf, 0xABCD, false);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("999"));
        assert!(lines[0].contains("sent"));
    }

    #[test]
    fn log6_opts_status_code_option() {
        use crate::dhcp6_protocol::OPTION6_STATUS_CODE;
        // Status code 0 (Success), no message
        let mut data = vec![0x00, 0x00];
        data.extend_from_slice(b"Success");
        let buf = raw_option(OPTION6_STATUS_CODE, &data);
        let lines = log6_opts(&buf, 1, false);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("status"));
        assert!(lines[0].contains('0'));
    }
}
