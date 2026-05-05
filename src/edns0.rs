//! EDNS0 (RFC 2671 / RFC 6891) option processing.
//!
//! Ported from `edns0.c` in dnsmasq.

use std::net::IpAddr;

use crate::dns_protocol::{DnsHeader, RrType, EDNS0_OPTION_CLIENT_SUBNET};
use crate::rfc1035::{DnsError, skip_name};

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

/// Information extracted from an OPT pseudo-RR.
#[derive(Debug, Clone)]
pub struct Edns0Info {
    /// Byte offset of the OPT RR inside the packet.
    pub offset: usize,
    /// Client's UDP payload size (OPT CLASS field).
    pub udp_size: u16,
    /// Extended RCODE (high byte of OPT TTL).
    pub ext_rcode: u8,
    /// EDNS version (should be 0).
    pub version: u8,
    /// Flags word (DO bit = 0x8000).
    pub flags: u16,
    /// Decoded EDNS0 options contained in the OPT RDATA.
    pub options: Vec<Edns0Option>,
}

/// A single EDNS0 option (code + opaque payload).
#[derive(Debug, Clone)]
pub struct Edns0Option {
    pub code: u16,
    pub data: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Advance `*offset` past `count` DNS questions.
fn skip_questions(pkt: &[u8], offset: &mut usize, count: u16) -> Result<(), DnsError> {
    for _ in 0..count {
        skip_name(pkt, offset)?;
        if *offset + 4 > pkt.len() {
            return Err(DnsError::PacketTooShort);
        }
        *offset += 4; // QTYPE + QCLASS
    }
    Ok(())
}

/// Advance `*offset` past `count` resource records.
fn skip_rrs(pkt: &[u8], offset: &mut usize, count: u16) -> Result<(), DnsError> {
    for _ in 0..count {
        skip_name(pkt, offset)?;
        if *offset + 10 > pkt.len() {
            return Err(DnsError::PacketTooShort);
        }
        let rdlen = u16::from_be_bytes([pkt[*offset + 8], pkt[*offset + 9]]) as usize;
        *offset += 10 + rdlen;
        if *offset > pkt.len() {
            return Err(DnsError::UnexpectedEof);
        }
    }
    Ok(())
}

/// Parse EDNS0 options from the RDATA of an OPT RR.
fn parse_opt_options(data: &[u8]) -> Result<Vec<Edns0Option>, DnsError> {
    let mut opts = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        if pos + 4 > data.len() {
            return Err(DnsError::UnexpectedEof);
        }
        let code = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if pos + len > data.len() {
            return Err(DnsError::UnexpectedEof);
        }
        opts.push(Edns0Option { code, data: data[pos..pos + len].to_vec() });
        pos += len;
    }
    Ok(opts)
}

/// Serialise a slice of EDNS0 options into OPT RDATA bytes.
fn build_opt_rdata(options: &[Edns0Option]) -> Vec<u8> {
    let mut out = Vec::new();
    for opt in options {
        out.extend_from_slice(&opt.code.to_be_bytes());
        out.extend_from_slice(&(opt.data.len() as u16).to_be_bytes());
        out.extend_from_slice(&opt.data);
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Find the OPT (EDNS0) pseudo-RR in a DNS packet.
///
/// Returns [`Edns0Info`] if an OPT record is present, or `None` otherwise.
pub fn find_pseudoheader(pkt: &[u8]) -> Option<Edns0Info> {
    let hdr = DnsHeader::from_bytes(pkt)?;
    let mut offset = 12usize;

    skip_questions(pkt, &mut offset, hdr.qdcount).ok()?;
    skip_rrs(pkt, &mut offset, hdr.ancount).ok()?;
    skip_rrs(pkt, &mut offset, hdr.nscount).ok()?;

    for _ in 0..hdr.arcount {
        let rr_start = offset;
        skip_name(pkt, &mut offset).ok()?;

        if offset + 10 > pkt.len() {
            return None;
        }
        let rtype    = u16::from_be_bytes([pkt[offset],     pkt[offset + 1]]);
        let udp_size = u16::from_be_bytes([pkt[offset + 2], pkt[offset + 3]]);
        let ext_rcode = pkt[offset + 4];
        let version   = pkt[offset + 5];
        let flags    = u16::from_be_bytes([pkt[offset + 6], pkt[offset + 7]]);
        let rdlen    = u16::from_be_bytes([pkt[offset + 8], pkt[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlen > pkt.len() {
            return None;
        }

        if rtype == RrType::OPT as u16 {
            let opt_data = &pkt[offset..offset + rdlen];
            let options = parse_opt_options(opt_data).ok()?;
            return Some(Edns0Info { offset: rr_start, udp_size, ext_rcode, version, flags, options });
        }

        offset += rdlen;
    }

    None
}

/// Add or update the OPT pseudo-RR in a DNS packet.
///
/// If an OPT record already exists it is removed and a fresh one is appended
/// at the end of the packet.  The provided `options` become the complete
/// contents of the new OPT RDATA (callers that need to preserve existing
/// options should merge them before calling).
pub fn add_pseudoheader(
    pkt: &[u8],
    udp_size: u16,
    flags: u16,
    options: &[Edns0Option],
) -> Result<Vec<u8>, DnsError> {
    // Validate the header before doing anything.
    DnsHeader::from_bytes(pkt).ok_or(DnsError::PacketTooShort)?;

    // Strip any existing OPT RR first.
    let base = if let Some(info) = find_pseudoheader(pkt) {
        // Determine the end of the OPT RR.
        let mut end_offset = info.offset;
        skip_name(pkt, &mut end_offset)?;
        if end_offset + 10 > pkt.len() {
            return Err(DnsError::PacketTooShort);
        }
        let rdlen = u16::from_be_bytes([pkt[end_offset + 8], pkt[end_offset + 9]]) as usize;
        let opt_end = end_offset + 10 + rdlen;
        if opt_end > pkt.len() {
            return Err(DnsError::UnexpectedEof);
        }

        // Build packet without the OPT RR.
        let mut stripped = pkt[..info.offset].to_vec();
        stripped.extend_from_slice(&pkt[opt_end..]);

        // Decrement arcount.
        let hdr = DnsHeader::from_bytes(pkt).ok_or(DnsError::PacketTooShort)?;
        let new_ar = hdr.arcount.saturating_sub(1);
        stripped[10] = (new_ar >> 8) as u8;
        stripped[11] = (new_ar & 0xFF) as u8;
        stripped
    } else {
        pkt.to_vec()
    };

    // Append new OPT RR at end.
    let rdata = build_opt_rdata(options);
    let mut result = base;

    result.push(0x00); // root label (empty name)
    result.extend_from_slice(&(RrType::OPT as u16).to_be_bytes());
    result.extend_from_slice(&udp_size.to_be_bytes());
    result.push(0); // ext_rcode
    result.push(0); // EDNS version
    result.extend_from_slice(&flags.to_be_bytes());
    result.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    result.extend_from_slice(&rdata);

    // Increment arcount.
    let hdr = DnsHeader::from_bytes(&result).ok_or(DnsError::PacketTooShort)?;
    let new_ar = hdr.arcount + 1;
    result[10] = (new_ar >> 8) as u8;
    result[11] = (new_ar & 0xFF) as u8;

    Ok(result)
}

/// Check whether the packet contains an ECS (client-subnet) option.
///
/// Returns the source IP address encoded in the option, or `None`.
pub fn check_source_subnet(pkt: &[u8]) -> Option<IpAddr> {
    let info = find_pseudoheader(pkt)?;
    for opt in &info.options {
        if opt.code == EDNS0_OPTION_CLIENT_SUBNET {
            return parse_ecs_addr(&opt.data);
        }
    }
    None
}

/// Parse the source address from ECS option payload bytes.
fn parse_ecs_addr(data: &[u8]) -> Option<IpAddr> {
    if data.len() < 4 {
        return None;
    }
    let family = u16::from_be_bytes([data[0], data[1]]);
    let addr_bytes = &data[4..];
    match family {
        1 => {
            let mut octets = [0u8; 4];
            let copy = addr_bytes.len().min(4);
            octets[..copy].copy_from_slice(&addr_bytes[..copy]);
            Some(IpAddr::V4(std::net::Ipv4Addr::from(octets)))
        }
        2 => {
            let mut bytes = [0u8; 16];
            let copy = addr_bytes.len().min(16);
            bytes[..copy].copy_from_slice(&addr_bytes[..copy]);
            Some(IpAddr::V6(std::net::Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

/// Insert or overwrite the ECS option with the given client address and prefix.
pub fn add_source_addr(
    pkt: &[u8],
    addr: IpAddr,
    prefix: u8,
) -> Result<Vec<u8>, DnsError> {
    let ecs_payload = build_ecs_payload(addr, prefix);
    let ecs_opt = Edns0Option { code: EDNS0_OPTION_CLIENT_SUBNET, data: ecs_payload };

    if let Some(info) = find_pseudoheader(pkt) {
        // Keep existing options except any prior ECS option.
        let mut merged: Vec<Edns0Option> = info.options
            .into_iter()
            .filter(|o| o.code != EDNS0_OPTION_CLIENT_SUBNET)
            .collect();
        merged.push(ecs_opt);
        add_pseudoheader(pkt, info.udp_size, info.flags, &merged)
    } else {
        add_pseudoheader(pkt, 512, 0, &[ecs_opt])
    }
}

/// Build the ECS option payload for `addr` masked to `prefix` bits.
fn build_ecs_payload(addr: IpAddr, prefix: u8) -> Vec<u8> {
    let mut out = Vec::new();
    let (family, full_octets): (u16, Vec<u8>) = match addr {
        IpAddr::V4(v4) => (1, v4.octets().to_vec()),
        IpAddr::V6(v6) => (2, v6.octets().to_vec()),
    };
    out.extend_from_slice(&family.to_be_bytes());
    out.push(prefix); // source netmask
    out.push(0);      // scope netmask

    // Only include the bytes that carry significant bits.
    if prefix > 0 {
        let n_bytes = ((prefix - 1) / 8 + 1) as usize;
        let n_bytes = n_bytes.min(full_octets.len());
        out.extend_from_slice(&full_octets[..n_bytes]);
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// DO bit helper (ported from edns0.c:250-253)
// ─────────────────────────────────────────────────────────────────────────────

/// Add an OPT pseudo-header with the DO (DNSSEC OK) bit set.
///
/// If an OPT already exists, sets the DO bit in its flags.
/// Port of `add_do_bit()` from edns0.c:250-253.
pub fn add_do_bit(pkt: &[u8], udp_size: u16) -> Result<Vec<u8>, DnsError> {
    // DO bit is bit 15 of the flags field (0x8000)
    add_pseudoheader(pkt, udp_size, 0x8000, &[])
}

// ─────────────────────────────────────────────────────────────────────────────
// Base64 encoding for MAC (ported from edns0.c:255-266)
// ─────────────────────────────────────────────────────────────────────────────

const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode a single base64 character (6-bit index).
fn char64(c: u8) -> u8 {
    BASE64_CHARS[(c & 0x3f) as usize]
}

/// Encode 3 bytes into 4 base64 characters.
fn encoder(input: &[u8; 3]) -> [u8; 4] {
    [
        char64(input[0] >> 2),
        char64((input[0] << 4) | (input[1] >> 4)),
        char64((input[1] << 2) | (input[2] >> 6)),
        char64(input[2]),
    ]
}

/// Encode a 6-byte MAC address into an 8-character base64 string.
///
/// Used by the `add_dns_client` option to encode MAC in device ID.
/// Port of the encoding logic in edns0.c:296-299.
pub fn mac_to_base64(mac: &[u8; 6]) -> String {
    let first: [u8; 3] = [mac[0], mac[1], mac[2]];
    let second: [u8; 3] = [mac[3], mac[4], mac[5]];
    let e1 = encoder(&first);
    let e2 = encoder(&second);
    let mut out = String::with_capacity(8);
    for &b in e1.iter().chain(e2.iter()) {
        out.push(b as char);
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// ECS source verification (ported from edns0.c:445-488)
// ─────────────────────────────────────────────────────────────────────────────

/// Verify that the ECS (EDNS Client Subnet) option in a reply matches a request.
///
/// Returns `true` if:
/// - No ECS option exists (valid — server doesn't support it), or
/// - The ECS option source fields match the expected source.
/// Returns `false` if there is a mismatch.
///
/// Port of `check_source()` from edns0.c:445-488.
pub fn verify_ecs_reply(reply_pkt: &[u8], expected_source: Option<(IpAddr, u8)>) -> bool {
    let info = match find_pseudoheader(reply_pkt) {
        Some(i) => i,
        None => return true, // no OPT → ok
    };

    // Look for ECS option
    let ecs_opt = info.options.iter().find(|o| o.code == EDNS0_OPTION_CLIENT_SUBNET);

    match (ecs_opt, expected_source) {
        (None, _) => true, // no ECS in reply → ok
        (Some(opt), None) => {
            // No source expected; check that source_netmask is 0
            if opt.data.len() >= 3 {
                opt.data[2] == 0 // source_netmask
            } else {
                true
            }
        }
        (Some(opt), Some((addr, prefix))) => {
            // Verify family and source match
            if opt.data.len() < 4 {
                return false;
            }
            let expected = build_ecs_payload(addr, prefix);
            if opt.data.len() < expected.len() {
                return false;
            }
            // Compare everything except scope_netmask (byte 3)
            opt.data[0..2] == expected[0..2]     // family
                && opt.data[2] == expected[2]     // source_netmask
                && opt.data[4..] == expected[4..] // address bytes
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Build a minimal DNS query packet for `example.com IN A` (no OPT RR).
    fn base_query() -> Vec<u8> {
        let mut pkt = vec![
            0x00, 0x01, // ID
            0x01, 0x00, // flags: RD=1, QR=0
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, // ANCOUNT=0
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00, // ARCOUNT=0
        ];
        pkt.extend_from_slice(b"\x07example\x03com\x00"); // QNAME
        pkt.extend_from_slice(&[0x00, 0x01]); // QTYPE=A
        pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
        pkt
    }

    /// Append an OPT RR to `pkt` with given params and return the modified packet.
    fn append_opt(mut pkt: Vec<u8>, udp_size: u16, flags: u16, rdata: &[u8]) -> Vec<u8> {
        pkt.push(0x00); // root name
        pkt.extend_from_slice(&(RrType::OPT as u16).to_be_bytes());
        pkt.extend_from_slice(&udp_size.to_be_bytes());
        pkt.push(0); // ext_rcode
        pkt.push(0); // version
        pkt.extend_from_slice(&flags.to_be_bytes());
        pkt.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        pkt.extend_from_slice(rdata);
        // increment arcount
        let ar = u16::from_be_bytes([pkt[10], pkt[11]]) + 1;
        pkt[10] = (ar >> 8) as u8;
        pkt[11] = (ar & 0xFF) as u8;
        pkt
    }

    // ── find_pseudoheader ─────────────────────────────────────────────────────

    #[test]
    fn find_pseudoheader_present() {
        let pkt = append_opt(base_query(), 4096, 0x8000, &[]);
        let info = find_pseudoheader(&pkt).expect("OPT not found");
        assert_eq!(info.udp_size, 4096);
        assert_eq!(info.flags, 0x8000);
        assert_eq!(info.ext_rcode, 0);
        assert_eq!(info.version, 0);
        assert!(info.options.is_empty());
    }

    #[test]
    fn find_pseudoheader_absent() {
        let pkt = base_query();
        assert!(find_pseudoheader(&pkt).is_none());
    }

    #[test]
    fn find_pseudoheader_truncated_returns_none() {
        // Truncated to just the header — should not panic.
        let pkt = &base_query()[..12];
        // qdcount=1 but no question data → skip_questions fails → None
        assert!(find_pseudoheader(pkt).is_none());
    }

    // ── add_pseudoheader ──────────────────────────────────────────────────────

    #[test]
    fn add_pseudoheader_no_existing_opt() {
        let pkt = base_query();
        let result = add_pseudoheader(&pkt, 1232, 0, &[]).expect("add failed");
        let info = find_pseudoheader(&result).expect("OPT not found after add");
        assert_eq!(info.udp_size, 1232);
        assert_eq!(info.flags, 0);
        // arcount should now be 1
        let hdr = DnsHeader::from_bytes(&result).unwrap();
        assert_eq!(hdr.arcount, 1);
    }

    #[test]
    fn add_pseudoheader_replaces_existing_opt() {
        let pkt = append_opt(base_query(), 512, 0, &[]);
        let result = add_pseudoheader(&pkt, 4096, 0x8000, &[]).expect("add failed");
        let info = find_pseudoheader(&result).expect("OPT not found after update");
        assert_eq!(info.udp_size, 4096);
        assert_eq!(info.flags, 0x8000);
        // arcount stays at 1
        let hdr = DnsHeader::from_bytes(&result).unwrap();
        assert_eq!(hdr.arcount, 1);
    }

    #[test]
    fn add_pseudoheader_too_short_returns_err() {
        assert!(add_pseudoheader(&[0u8; 3], 512, 0, &[]).is_err());
    }

    // ── check_source_subnet ───────────────────────────────────────────────────

    #[test]
    fn check_source_subnet_present() {
        // ECS payload: family=1 (IPv4), src_mask=24, scope=0, addr=192.168.1.x
        let ecs: Vec<u8> = {
            let mut v = Vec::new();
            v.extend_from_slice(&1u16.to_be_bytes()); // family
            v.push(24); // source mask
            v.push(0);  // scope
            v.extend_from_slice(&[192, 168, 1]); // /24 → 3 bytes
            v
        };
        let opt_rdata: Vec<u8> = {
            let mut v = Vec::new();
            v.extend_from_slice(&EDNS0_OPTION_CLIENT_SUBNET.to_be_bytes());
            v.extend_from_slice(&(ecs.len() as u16).to_be_bytes());
            v.extend_from_slice(&ecs);
            v
        };
        let pkt = append_opt(base_query(), 4096, 0, &opt_rdata);
        let addr = check_source_subnet(&pkt).expect("ECS not found");
        match addr {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                assert_eq!(&o[..3], &[192, 168, 1]);
            }
            _ => panic!("expected IPv4"),
        }
    }

    #[test]
    fn check_source_subnet_absent() {
        let pkt = append_opt(base_query(), 4096, 0, &[]);
        assert!(check_source_subnet(&pkt).is_none());
    }

    #[test]
    fn check_source_subnet_no_opt() {
        assert!(check_source_subnet(&base_query()).is_none());
    }

    // ── add_source_addr ───────────────────────────────────────────────────────

    #[test]
    fn add_source_addr_ipv4() {
        let pkt = base_query();
        let addr = IpAddr::V4("10.0.0.1".parse().unwrap());
        let result = add_source_addr(&pkt, addr, 32).expect("add_source_addr failed");
        let found = check_source_subnet(&result).expect("ECS missing");
        assert!(matches!(found, IpAddr::V4(_)));
    }

    #[test]
    fn add_source_addr_ipv6() {
        let pkt = base_query();
        let addr: IpAddr = "2001:db8::1".parse().unwrap();
        let result = add_source_addr(&pkt, addr, 48).expect("add_source_addr failed");
        let found = check_source_subnet(&result).expect("ECS missing");
        assert!(matches!(found, IpAddr::V6(_)));
    }

    #[test]
    fn add_source_addr_replaces_existing() {
        let pkt = base_query();
        let addr1 = IpAddr::V4("1.2.3.4".parse().unwrap());
        let pkt2 = add_source_addr(&pkt, addr1, 32).unwrap();
        let addr2 = IpAddr::V4("5.6.7.8".parse().unwrap());
        let pkt3 = add_source_addr(&pkt2, addr2, 32).unwrap();
        // Only one OPT, one ECS
        let hdr = DnsHeader::from_bytes(&pkt3).unwrap();
        assert_eq!(hdr.arcount, 1);
        let found = check_source_subnet(&pkt3).expect("ECS missing");
        if let IpAddr::V4(v4) = found {
            assert_eq!(v4.octets(), [5, 6, 7, 8]);
        } else {
            panic!("expected IPv4");
        }
    }

    #[test]
    fn truncated_input_does_not_panic() {
        // Various truncated lengths — none should panic.
        for len in 0..=15usize {
            let pkt = &base_query()[..len.min(base_query().len())];
            let _ = find_pseudoheader(pkt);
            let _ = add_pseudoheader(pkt, 512, 0, &[]);
            let _ = check_source_subnet(pkt);
        }
    }

    // ── add_do_bit ───────────────────────────────────────────────────────────

    #[test]
    fn add_do_bit_sets_flag() {
        let pkt = base_query();
        let result = add_do_bit(&pkt, 4096).unwrap();
        let info = find_pseudoheader(&result).unwrap();
        assert_eq!(info.flags & 0x8000, 0x8000);
    }

    #[test]
    fn add_do_bit_on_existing_opt() {
        let pkt = append_opt(base_query(), 512, 0, &[]);
        let result = add_do_bit(&pkt, 4096).unwrap();
        let info = find_pseudoheader(&result).unwrap();
        assert_eq!(info.flags & 0x8000, 0x8000);
        assert_eq!(info.udp_size, 4096);
    }

    // ── base64 encoding ──────────────────────────────────────────────────────

    #[test]
    fn char64_maps_correctly() {
        assert_eq!(char64(0), b'A');
        assert_eq!(char64(25), b'Z');
        assert_eq!(char64(26), b'a');
        assert_eq!(char64(51), b'z');
        assert_eq!(char64(52), b'0');
        assert_eq!(char64(62), b'+');
        assert_eq!(char64(63), b'/');
    }

    #[test]
    fn encoder_encodes_3_bytes() {
        let input = [0x4d, 0x61, 0x6e]; // "Man"
        let out = encoder(&input);
        assert_eq!(&out, b"TWFu");
    }

    #[test]
    fn mac_to_base64_6_bytes() {
        let mac = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
        let b64 = mac_to_base64(&mac);
        assert_eq!(b64.len(), 8);
        // Verify it's valid base64 chars
        assert!(b64.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/'));
    }

    #[test]
    fn mac_to_base64_all_zeros() {
        let mac = [0u8; 6];
        let b64 = mac_to_base64(&mac);
        assert_eq!(b64, "AAAAAAAA"); // all zeros → all A's
    }

    // ── verify_ecs_reply ─────────────────────────────────────────────────────

    #[test]
    fn verify_ecs_reply_no_opt_ok() {
        let pkt = base_query();
        assert!(verify_ecs_reply(&pkt, None));
    }

    #[test]
    fn verify_ecs_reply_no_ecs_option_ok() {
        let pkt = append_opt(base_query(), 4096, 0, &[]);
        assert!(verify_ecs_reply(&pkt, None));
    }

    #[test]
    fn verify_ecs_reply_matching_source() {
        let addr = IpAddr::V4("10.0.0.0".parse().unwrap());
        let pkt = add_source_addr(&base_query(), addr, 24).unwrap();
        assert!(verify_ecs_reply(&pkt, Some((addr, 24))));
    }

    #[test]
    fn verify_ecs_reply_mismatched_source() {
        let addr1 = IpAddr::V4("10.0.0.0".parse().unwrap());
        let addr2 = IpAddr::V4("192.168.0.0".parse().unwrap());
        let pkt = add_source_addr(&base_query(), addr1, 24).unwrap();
        assert!(!verify_ecs_reply(&pkt, Some((addr2, 24))));
    }
}
