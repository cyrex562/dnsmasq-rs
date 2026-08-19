//! EDNS0 (RFC 2671 / RFC 6891) option processing.
//!
//! Ported from `edns0.c` in dnsmasq.

use std::net::IpAddr;

use crate::dns_protocol::{
    DnsHeader, RrType, EDNS0_OPTION_CLIENT_SUBNET, EDNS0_OPTION_MAC, EDNS0_OPTION_NOMCPEID,
    EDNS0_OPTION_NOMDEVICEID, EDNS0_OPTION_UMBRELLA,
};
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
///
/// A thin wrapper over [`calc_subnet_opt`] with no `add-subnet` constant
/// address override configured, so the client's own address is always used.
fn build_ecs_payload(addr: IpAddr, prefix: u8) -> Vec<u8> {
    let sub = AddSubnetOpt { mask: prefix, const_addr: None };
    let (opt, _cacheable, len) = calc_subnet_opt(addr, Some(&sub), Some(&sub));
    opt.to_wire(len)
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
// `--add-subnet` constant-address override (ported from edns0.c:336-407)
// ─────────────────────────────────────────────────────────────────────────────

/// The on-the-wire ECS option fields, mirroring C's `struct subnet_opt`
/// (`edns0.c:336-340`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubnetOpt {
    pub family: u16,
    pub source_netmask: u8,
    pub scope_netmask: u8,
    pub addr: [u8; 16],
}

impl SubnetOpt {
    /// Serialise to the wire form: family(2) + source_netmask(1) +
    /// scope_netmask(1) + the first `addr_len` bytes of `addr`.
    fn to_wire(&self, addr_len: usize) -> Vec<u8> {
        let addr_len = addr_len.min(self.addr.len());
        let mut out = Vec::with_capacity(4 + addr_len);
        out.extend_from_slice(&self.family.to_be_bytes());
        out.push(self.source_netmask);
        out.push(self.scope_netmask);
        out.extend_from_slice(&self.addr[..addr_len]);
        out
    }
}

/// `--add-subnet`/`--add-subnet6` configuration, mirroring C's
/// `daemon->add_subnet4`/`add_subnet6` (`struct mysubnet`, `dnsmasq.h`).
///
/// `const_addr` is `Some` exactly when C's `addr_used` is set: a fixed address
/// configured in place of the real client address (e.g. `--add-subnet=1.2.3.4/24`
/// as opposed to `--add-subnet=24` which just sets the mask).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddSubnetOpt {
    pub mask: u8,
    pub const_addr: Option<IpAddr>,
}

/// Build the ECS option that should be attached to a query from `source`.
///
/// Port of `calc_subnet_opt()` (`edns0.c:350-407`). Consults the `add_subnet4`/
/// `add_subnet6` config matching `source`'s address family: if a constant
/// address is configured (`const_addr`), that address is sent instead of the
/// real client address and the result is always cacheable (the option no
/// longer varies per-client); otherwise the real `source` address is used and
/// the result is cacheable only when no address ends up in the option at all
/// (mask 0, or no `add_subnet` config for this family).
///
/// Returns `(option, cacheable, addr_len)`; `addr_len` is the number of
/// significant bytes in `option.addr` (C's `len`, before the `+4` header is
/// added to make its returned `size_t`).
pub fn calc_subnet_opt(
    source: IpAddr,
    add_subnet4: Option<&AddSubnetOpt>,
    add_subnet6: Option<&AddSubnetOpt>,
) -> (SubnetOpt, bool, usize) {
    let mut source_netmask: u8 = 0;
    let mut addrp: Option<IpAddr> = None;
    let mut is_v6 = matches!(source, IpAddr::V6(_));
    let mut cacheable = false;

    if let (IpAddr::V6(_), Some(sub)) = (source, add_subnet6) {
        source_netmask = sub.mask;
        if let Some(a) = sub.const_addr {
            is_v6 = matches!(a, IpAddr::V6(_));
            addrp = Some(a);
            cacheable = true; // Address is constant.
        } else {
            addrp = Some(source);
        }
    }

    if let (IpAddr::V4(_), Some(sub)) = (source, add_subnet4) {
        source_netmask = sub.mask;
        if let Some(a) = sub.const_addr {
            is_v6 = matches!(a, IpAddr::V6(_));
            addrp = Some(a);
            cacheable = true; // Address is constant.
        } else {
            addrp = Some(source);
        }
    }

    let family: u16 = if is_v6 { 2 } else { 1 };
    let mut addr = [0u8; 16];
    let len;

    if let (Some(a), true) = (addrp, source_netmask != 0) {
        let full: [u8; 16] = match a {
            IpAddr::V4(v4) => {
                let mut b = [0u8; 16];
                b[..4].copy_from_slice(&v4.octets());
                b
            }
            IpAddr::V6(v6) => v6.octets(),
        };
        let l = (((source_netmask as usize - 1) >> 3) + 1).min(16);
        addr[..l].copy_from_slice(&full[..l]);
        if source_netmask & 7 != 0 {
            addr[l - 1] &= 0xffu8 << (8 - (source_netmask & 7));
        }
        len = l;
    } else {
        cacheable = true; // No address ever supplied.
        len = 0;
    }

    (SubnetOpt { family, source_netmask, scope_netmask: 0, addr }, cacheable, len)
}

// ─────────────────────────────────────────────────────────────────────────────
// ECS source verification (ported from edns0.c:445-488)
// ─────────────────────────────────────────────────────────────────────────────

/// Verify that the ECS (EDNS Client Subnet) option in a reply matches what we
/// (would have) sent, protecting against a spoofed/mismatched ECS echo.
///
/// Port of `check_source()` (`edns0.c:445-488`). Two modes, selected by `peer`:
///
/// - `peer = Some(addr)` (the reply-verification use, `forward.c:727-731`):
///   recomputes the ECS option that should have been sent for `addr` via
///   [`calc_subnet_opt`], then requires every field of the reply's ECS option
///   to match *except* `scope_netmask`, which a server is allowed to set.
/// - `peer = None` (the outgoing-query use, `edns0.c:434-437`): only checks
///   whether the packet already carries a non-zero `source_netmask` — i.e.
///   whether the client stamped their own real ECS on this query.
///
/// No ECS option present at all is `true` (ok) in both modes, matching C.
pub fn check_source(
    pkt: &[u8],
    peer: Option<IpAddr>,
    add_subnet4: Option<&AddSubnetOpt>,
    add_subnet6: Option<&AddSubnetOpt>,
) -> bool {
    let info = match find_pseudoheader(pkt) {
        Some(i) => i,
        None => return true,
    };

    let expected = peer.map(|p| calc_subnet_opt(p, add_subnet4, add_subnet6));

    for opt in &info.options {
        if opt.code != EDNS0_OPTION_CLIENT_SUBNET {
            continue;
        }
        match &expected {
            Some((exp, _cacheable, exp_len)) => {
                let calc_len = exp_len + 4;
                if opt.data.len() != calc_len || opt.data.len() < 4 {
                    return false;
                }
                // `scope_netmask` (byte 3) is set by the server and excluded
                // from the comparison, matching C copying the reply's value
                // into `opt.scope_netmask` before the `memcmp`.
                let family_ok = opt.data[0..2] == exp.family.to_be_bytes();
                let mask_ok = opt.data[2] == exp.source_netmask;
                let addr_ok = opt.data[4..] == exp.addr[..*exp_len];
                if !(family_ok && mask_ok && addr_ok) {
                    return false;
                }
            }
            None => {
                if opt.data.len() >= 3 && opt.data[2] != 0 {
                    return false;
                }
            }
        }
    }

    true
}

// ─────────────────────────────────────────────────────────────────────────────
// Outgoing-query EDNS0 option construction (ported from edns0.c:271-573)
// ─────────────────────────────────────────────────────────────────────────────

/// Whether any MAC-consuming option is enabled, so the caller should warm the
/// MAC/ARP cache (`find_mac`) before forwarding — needed because the source
/// socket info differs over TCP.
///
/// Port of `edns0_needs_mac()` (`edns0.c:271-275`). This module has no
/// socket/ARP access, so unlike C it only reports whether a lookup is needed;
/// the caller performs the actual `find_mac`/ARP-cache lookup.
pub fn edns0_needs_mac(mac_b64: bool, mac_hex: bool, add_mac: bool) -> bool {
    mac_b64 || mac_hex || add_mac
}

/// `replace` argument shared by every `add_pseudoheader()` call site in
/// `edns0.c`'s query-construction helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpsertMode {
    /// `replace == 0`: add only if the option isn't already present.
    AddIfAbsent,
    /// `replace == 1`: remove any existing occurrence, then add the new value.
    Replace,
    /// `replace == 2`: remove any existing occurrence; never add a new value.
    ReplaceOnly,
}

/// Add, replace, or remove a single EDNS0 option in an option list, per
/// `UpsertMode`. Because this module represents the OPT RDATA as a decoded
/// option list rather than C's raw buffer, this replaces the manual
/// search-and-memmove loop in `add_pseudoheader()` (`edns0.c:144-175`) with
/// the same observable behaviour.
fn upsert_option(options: &mut Vec<Edns0Option>, code: u16, data: Option<Vec<u8>>, mode: UpsertMode) {
    match mode {
        UpsertMode::AddIfAbsent => {
            if !options.iter().any(|o| o.code == code) {
                if let Some(d) = data {
                    options.push(Edns0Option { code, data: d });
                }
            }
        }
        UpsertMode::Replace => {
            options.retain(|o| o.code != code);
            if let Some(d) = data {
                options.push(Edns0Option { code, data: d });
            }
        }
        UpsertMode::ReplaceOnly => {
            options.retain(|o| o.code != code);
        }
    }
}

/// `OPT_ADD_MAC`/`OPT_STRIP_MAC` handling for `EDNS0_OPTION_MAC`.
///
/// Port of `add_mac()` (`edns0.c:315-334`). `mac` is the resolved hardware
/// address for this client, already looked up by the caller (see
/// [`edns0_needs_mac`]) — this module has no ARP/socket access of its own.
fn add_mac(options: &mut Vec<Edns0Option>, mac: Option<&[u8]>, add_mac: bool, strip_mac: bool, cacheable: &mut bool) {
    let found = if add_mac { mac.filter(|m| !m.is_empty()) } else { None };
    if found.is_some() {
        *cacheable = false;
    }

    let mode = if found.is_some() {
        if strip_mac { UpsertMode::Replace } else { UpsertMode::AddIfAbsent }
    } else if strip_mac {
        UpsertMode::ReplaceOnly
    } else {
        return;
    };

    upsert_option(options, EDNS0_OPTION_MAC, found.map(|m| m.to_vec()), mode);
}

/// `OPT_MAC_B64`/`OPT_MAC_HEX`/`OPT_STRIP_MAC` handling for
/// `EDNS0_OPTION_NOMDEVICEID`.
///
/// Port of `add_dns_client()` (`edns0.c:280-309`). Only 6-byte MACs are
/// encoded, matching C's `encode[18]` buffer sized for exactly that case.
fn add_dns_client(
    options: &mut Vec<Edns0Option>,
    mac: Option<&[u8]>,
    mac_b64: bool,
    mac_hex: bool,
    strip_mac: bool,
    cacheable: &mut bool,
) {
    let mac6 = if mac_b64 || mac_hex { mac.filter(|m| m.len() == 6) } else { None };

    let encoded: Option<String> = mac6.map(|m| {
        *cacheable = false;
        if mac_hex {
            crate::util::print_mac(m)
        } else {
            let arr: [u8; 6] = m.try_into().expect("mac6 filtered to len == 6");
            mac_to_base64(&arr)
        }
    });

    let mode = if encoded.is_some() {
        if strip_mac { UpsertMode::Replace } else { UpsertMode::AddIfAbsent }
    } else if strip_mac {
        UpsertMode::ReplaceOnly
    } else {
        return;
    };

    upsert_option(options, EDNS0_OPTION_NOMDEVICEID, encoded.map(String::into_bytes), mode);
}

/// `OPT_CLIENT_SUBNET`/`OPT_STRIP_ECS` handling for `EDNS0_OPTION_CLIENT_SUBNET`
/// on an *outgoing* query.
///
/// Port of `add_source_addr()` (`edns0.c:412-443`). When neither option is
/// set, falls back to [`check_source`] in its `peer = None` mode to detect
/// whether the client already stamped their own ECS option on the query, in
/// which case the answer must not be cached (`edns0.c:430-437`).
pub fn add_client_subnet(
    options: &mut Vec<Edns0Option>,
    source: IpAddr,
    client_subnet: bool,
    strip_ecs: bool,
    add_subnet4: Option<&AddSubnetOpt>,
    add_subnet6: Option<&AddSubnetOpt>,
    cacheable: &mut bool,
) {
    if client_subnet {
        let mode = if strip_ecs { UpsertMode::Replace } else { UpsertMode::AddIfAbsent };
        let (opt, cache, len) = calc_subnet_opt(source, add_subnet4, add_subnet6);
        *cacheable = cache;
        upsert_option(options, EDNS0_OPTION_CLIENT_SUBNET, Some(opt.to_wire(len)), mode);
    } else if strip_ecs {
        upsert_option(options, EDNS0_OPTION_CLIENT_SUBNET, None, UpsertMode::ReplaceOnly);
    } else if *cacheable {
        let has_own_ecs = options
            .iter()
            .any(|o| o.code == EDNS0_OPTION_CLIENT_SUBNET && o.data.len() >= 3 && o.data[2] != 0);
        if has_own_ecs {
            *cacheable = false;
        }
    }
}

/// Cisco Umbrella identification option (`EDNS0_OPTION_UMBRELLA`).
///
/// Port of `add_umbrella_opt()` (`edns0.c:517-574`). See
/// <https://docs.umbrella.com/umbrella-api/docs/identifying-dns-traffic> for
/// the wire format. Always marks the answer uncacheable, matching C
/// unconditionally clearing `*cacheable` before building the option.
#[allow(clippy::too_many_arguments)]
fn add_umbrella_opt(
    options: &mut Vec<Edns0Option>,
    source: IpAddr,
    umbrella_devid: bool,
    umbrella_org: u32,
    umbrella_asset: u32,
    umbrella_device: &[u8; 8],
    cacheable: &mut bool,
) {
    const UMBRELLA_VERSION: u8 = 1;
    const UMBRELLA_ASSET: u16 = 0x0004;
    const UMBRELLA_ORG: u16 = 0x0008;
    const UMBRELLA_IPV4: u16 = 0x0010;
    const UMBRELLA_IPV6: u16 = 0x0020;
    const UMBRELLA_DEVICE: u16 = 0x0040;

    *cacheable = false;

    let mut payload = Vec::new();
    payload.extend_from_slice(b"ODNS");
    payload.push(UMBRELLA_VERSION);
    payload.push(0); // flags, unused

    if umbrella_org != 0 {
        payload.extend_from_slice(&UMBRELLA_ORG.to_be_bytes());
        payload.extend_from_slice(&umbrella_org.to_be_bytes());
    }

    match source {
        IpAddr::V4(v4) => {
            payload.extend_from_slice(&UMBRELLA_IPV4.to_be_bytes());
            payload.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            payload.extend_from_slice(&UMBRELLA_IPV6.to_be_bytes());
            payload.extend_from_slice(&v6.octets());
        }
    }

    if umbrella_devid {
        payload.extend_from_slice(&UMBRELLA_DEVICE.to_be_bytes());
        payload.extend_from_slice(umbrella_device);
    }

    if umbrella_asset != 0 {
        payload.extend_from_slice(&UMBRELLA_ASSET.to_be_bytes());
        payload.extend_from_slice(&umbrella_asset.to_be_bytes());
    }

    upsert_option(options, EDNS0_OPTION_UMBRELLA, Some(payload), UpsertMode::Replace);
}

/// Configuration consulted by [`add_edns0_config`], mirroring the `Daemon`
/// fields and option bits `add_edns0_config()` reads in C.
#[derive(Debug, Clone, Copy, Default)]
pub struct Edns0QueryConfig<'a> {
    pub add_mac: bool,
    pub strip_mac: bool,
    pub mac_b64: bool,
    pub mac_hex: bool,
    pub client_subnet: bool,
    pub strip_ecs: bool,
    pub add_subnet4: Option<&'a AddSubnetOpt>,
    pub add_subnet6: Option<&'a AddSubnetOpt>,
    pub dns_client_id: Option<&'a str>,
    pub umbrella: bool,
    pub umbrella_devid: bool,
    pub umbrella_org: u32,
    pub umbrella_asset: u32,
    pub umbrella_device: [u8; 8],
}

/// Build the full set of client-specific EDNS0 options for an outgoing query.
///
/// Port of `add_edns0_config()` (`edns0.c:555-573`): MAC, then MAC device-id,
/// then client-id, then Umbrella, then ECS — in that order, since a later
/// step may need to see (and not duplicate) an earlier one's option code.
/// Returns the merged option list plus whether the resulting answer may be
/// cached (`false` once any client-dependent option was actually added).
pub fn add_edns0_config(
    existing: &[Edns0Option],
    source: IpAddr,
    mac: Option<&[u8]>,
    cfg: &Edns0QueryConfig<'_>,
) -> (Vec<Edns0Option>, bool) {
    let mut options: Vec<Edns0Option> = existing.to_vec();
    let mut cacheable = true;

    add_mac(&mut options, mac, cfg.add_mac, cfg.strip_mac, &mut cacheable);
    add_dns_client(&mut options, mac, cfg.mac_b64, cfg.mac_hex, cfg.strip_mac, &mut cacheable);

    if let Some(id) = cfg.dns_client_id {
        upsert_option(
            &mut options,
            EDNS0_OPTION_NOMCPEID,
            Some(id.as_bytes().to_vec()),
            UpsertMode::Replace,
        );
    }

    if cfg.umbrella {
        add_umbrella_opt(
            &mut options,
            source,
            cfg.umbrella_devid,
            cfg.umbrella_org,
            cfg.umbrella_asset,
            &cfg.umbrella_device,
            &mut cacheable,
        );
    }

    add_client_subnet(
        &mut options,
        source,
        cfg.client_subnet,
        cfg.strip_ecs,
        cfg.add_subnet4,
        cfg.add_subnet6,
        &mut cacheable,
    );

    (options, cacheable)
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

    // ── check_source ─────────────────────────────────────────────────────────

    #[test]
    fn check_source_no_opt_ok() {
        let pkt = base_query();
        assert!(check_source(&pkt, None, None, None));
    }

    #[test]
    fn check_source_no_ecs_option_ok() {
        let pkt = append_opt(base_query(), 4096, 0, &[]);
        assert!(check_source(&pkt, None, None, None));
    }

    #[test]
    fn check_source_peer_matching_source() {
        let addr = IpAddr::V4("10.0.0.0".parse().unwrap());
        let pkt = add_source_addr(&base_query(), addr, 24).unwrap();
        let sub4 = AddSubnetOpt { mask: 24, const_addr: None };
        assert!(check_source(&pkt, Some(addr), Some(&sub4), None));
    }

    #[test]
    fn check_source_peer_mismatched_address() {
        let addr1 = IpAddr::V4("10.0.0.0".parse().unwrap());
        let addr2 = IpAddr::V4("192.168.0.0".parse().unwrap());
        let pkt = add_source_addr(&base_query(), addr1, 24).unwrap();
        let sub4 = AddSubnetOpt { mask: 24, const_addr: None };
        assert!(!check_source(&pkt, Some(addr2), Some(&sub4), None));
    }

    #[test]
    fn check_source_peer_mismatched_mask() {
        // Same address, but the reply's mask doesn't match the mask we would
        // have computed for this peer given the current `add_subnet4` config.
        let addr = IpAddr::V4("10.0.0.0".parse().unwrap());
        let pkt = add_source_addr(&base_query(), addr, 16).unwrap();
        let sub4 = AddSubnetOpt { mask: 24, const_addr: None };
        assert!(!check_source(&pkt, Some(addr), Some(&sub4), None));
    }

    #[test]
    fn check_source_peer_ignores_scope_netmask() {
        // The server is allowed to set scope_netmask in its reply; that byte
        // must not affect the comparison.
        let addr = IpAddr::V4("10.0.0.0".parse().unwrap());
        let mut pkt = add_source_addr(&base_query(), addr, 24).unwrap();
        let info = find_pseudoheader(&pkt).unwrap();
        let ecs = info.options.iter().find(|o| o.code == EDNS0_OPTION_CLIENT_SUBNET).unwrap();
        let mut data = ecs.data.clone();
        data[3] = 20; // scope_netmask, server-settable
        let mut opts: Vec<Edns0Option> =
            info.options.iter().filter(|o| o.code != EDNS0_OPTION_CLIENT_SUBNET).cloned().collect();
        opts.push(Edns0Option { code: EDNS0_OPTION_CLIENT_SUBNET, data });
        pkt = add_pseudoheader(&pkt, info.udp_size, info.flags, &opts).unwrap();

        let sub4 = AddSubnetOpt { mask: 24, const_addr: None };
        assert!(check_source(&pkt, Some(addr), Some(&sub4), None));
    }

    #[test]
    fn check_source_no_peer_rejects_nonzero_source_netmask() {
        let addr = IpAddr::V4("10.0.0.0".parse().unwrap());
        let pkt = add_source_addr(&base_query(), addr, 24).unwrap();
        assert!(!check_source(&pkt, None, None, None));
    }

    #[test]
    fn check_source_no_peer_allows_zero_source_netmask() {
        let addr = IpAddr::V4("10.0.0.0".parse().unwrap());
        let pkt = add_source_addr(&base_query(), addr, 0).unwrap();
        assert!(check_source(&pkt, None, None, None));
    }

    // ── calc_subnet_opt ──────────────────────────────────────────────────────

    #[test]
    fn calc_subnet_opt_no_config_is_cacheable() {
        let addr = IpAddr::V4("10.0.0.1".parse().unwrap());
        let (opt, cacheable, len) = calc_subnet_opt(addr, None, None);
        assert_eq!(len, 0);
        assert!(cacheable);
        assert_eq!(opt.family, 1);
        assert_eq!(opt.source_netmask, 0);
    }

    #[test]
    fn calc_subnet_opt_real_address_is_not_cacheable() {
        let addr = IpAddr::V4("10.1.2.3".parse().unwrap());
        let sub4 = AddSubnetOpt { mask: 24, const_addr: None };
        let (opt, cacheable, len) = calc_subnet_opt(addr, Some(&sub4), None);
        assert!(!cacheable);
        assert_eq!(len, 3);
        assert_eq!(&opt.addr[..3], &[10, 1, 2]);
    }

    #[test]
    fn calc_subnet_opt_constant_address_is_cacheable() {
        let addr = IpAddr::V4("10.1.2.3".parse().unwrap());
        let constant = IpAddr::V4("192.0.2.1".parse().unwrap());
        let sub4 = AddSubnetOpt { mask: 32, const_addr: Some(constant) };
        let (opt, cacheable, len) = calc_subnet_opt(addr, Some(&sub4), None);
        assert!(cacheable);
        assert_eq!(len, 4);
        assert_eq!(&opt.addr[..4], &[192, 0, 2, 1]);
    }

    #[test]
    fn calc_subnet_opt_masks_partial_byte() {
        let addr = IpAddr::V4("10.1.2.255".parse().unwrap());
        let sub4 = AddSubnetOpt { mask: 22, const_addr: None };
        let (opt, _cacheable, len) = calc_subnet_opt(addr, Some(&sub4), None);
        assert_eq!(len, 3);
        // /22 keeps the top 6 bits of the third octet: 2 (0000_0010) stays 0.
        assert_eq!(&opt.addr[..3], &[10, 1, 0]);
    }

    #[test]
    fn calc_subnet_opt_ipv6() {
        let addr: IpAddr = "2001:db8::1".parse().unwrap();
        let sub6 = AddSubnetOpt { mask: 48, const_addr: None };
        let (opt, cacheable, len) = calc_subnet_opt(addr, None, Some(&sub6));
        assert!(!cacheable);
        assert_eq!(opt.family, 2);
        assert_eq!(len, 6);
        assert_eq!(&opt.addr[..6], &[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00]);
    }

    // ── edns0_needs_mac ──────────────────────────────────────────────────────

    #[test]
    fn edns0_needs_mac_false_when_nothing_enabled() {
        assert!(!edns0_needs_mac(false, false, false));
    }

    #[test]
    fn edns0_needs_mac_true_for_any_consumer() {
        assert!(edns0_needs_mac(true, false, false));
        assert!(edns0_needs_mac(false, true, false));
        assert!(edns0_needs_mac(false, false, true));
    }

    // ── add_mac / add_dns_client (via add_edns0_config) ──────────────────────

    #[test]
    fn add_edns0_config_add_mac() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let cfg = Edns0QueryConfig { add_mac: true, ..Default::default() };
        let (options, cacheable) =
            add_edns0_config(&[], IpAddr::V4("1.2.3.4".parse().unwrap()), Some(&mac), &cfg);
        let opt = options.iter().find(|o| o.code == EDNS0_OPTION_MAC).expect("MAC option missing");
        assert_eq!(opt.data, mac);
        assert!(!cacheable);
    }

    #[test]
    fn add_edns0_config_no_mac_available_is_noop() {
        let cfg = Edns0QueryConfig { add_mac: true, ..Default::default() };
        let (options, cacheable) =
            add_edns0_config(&[], IpAddr::V4("1.2.3.4".parse().unwrap()), None, &cfg);
        assert!(options.iter().all(|o| o.code != EDNS0_OPTION_MAC));
        assert!(cacheable);
    }

    #[test]
    fn add_edns0_config_strip_mac_removes_existing() {
        let existing = vec![Edns0Option { code: EDNS0_OPTION_MAC, data: vec![1, 2, 3] }];
        let cfg = Edns0QueryConfig { strip_mac: true, ..Default::default() };
        let (options, _cacheable) =
            add_edns0_config(&existing, IpAddr::V4("1.2.3.4".parse().unwrap()), None, &cfg);
        assert!(options.iter().all(|o| o.code != EDNS0_OPTION_MAC));
    }

    #[test]
    fn add_edns0_config_mac_b64_device_id() {
        let mac = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
        let cfg = Edns0QueryConfig { mac_b64: true, ..Default::default() };
        let (options, cacheable) =
            add_edns0_config(&[], IpAddr::V4("1.2.3.4".parse().unwrap()), Some(&mac), &cfg);
        let opt = options
            .iter()
            .find(|o| o.code == EDNS0_OPTION_NOMDEVICEID)
            .expect("device-id option missing");
        assert_eq!(String::from_utf8(opt.data.clone()).unwrap(), mac_to_base64(&mac));
        assert!(!cacheable);
    }

    #[test]
    fn add_edns0_config_mac_hex_device_id() {
        let mac = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
        let cfg = Edns0QueryConfig { mac_hex: true, ..Default::default() };
        let (options, _cacheable) =
            add_edns0_config(&[], IpAddr::V4("1.2.3.4".parse().unwrap()), Some(&mac), &cfg);
        let opt = options
            .iter()
            .find(|o| o.code == EDNS0_OPTION_NOMDEVICEID)
            .expect("device-id option missing");
        assert_eq!(String::from_utf8(opt.data.clone()).unwrap(), crate::util::print_mac(&mac));
    }

    #[test]
    fn add_edns0_config_ignores_non_6_byte_mac() {
        let mac = [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F];
        let cfg = Edns0QueryConfig { mac_b64: true, ..Default::default() };
        let (options, cacheable) =
            add_edns0_config(&[], IpAddr::V4("1.2.3.4".parse().unwrap()), Some(&mac), &cfg);
        assert!(options.iter().all(|o| o.code != EDNS0_OPTION_NOMDEVICEID));
        assert!(cacheable);
    }

    // ── dns_client_id / add_edns0_config ordering ─────────────────────────────

    #[test]
    fn add_edns0_config_dns_client_id() {
        let cfg = Edns0QueryConfig { dns_client_id: Some("cpe-123"), ..Default::default() };
        let (options, _cacheable) =
            add_edns0_config(&[], IpAddr::V4("1.2.3.4".parse().unwrap()), None, &cfg);
        let opt = options.iter().find(|o| o.code == EDNS0_OPTION_NOMCPEID).expect("client-id missing");
        assert_eq!(opt.data, b"cpe-123");
    }

    // ── add_client_subnet ─────────────────────────────────────────────────────

    #[test]
    fn add_client_subnet_adds_ecs_and_marks_uncacheable() {
        let mut options = Vec::new();
        let mut cacheable = true;
        let sub4 = AddSubnetOpt { mask: 24, const_addr: None };
        add_client_subnet(
            &mut options,
            IpAddr::V4("10.0.0.1".parse().unwrap()),
            true,
            false,
            Some(&sub4),
            None,
            &mut cacheable,
        );
        assert!(!cacheable);
        assert!(options.iter().any(|o| o.code == EDNS0_OPTION_CLIENT_SUBNET));
    }

    #[test]
    fn add_client_subnet_strip_removes_existing() {
        let mut options =
            vec![Edns0Option { code: EDNS0_OPTION_CLIENT_SUBNET, data: vec![0, 1, 24, 0, 10] }];
        let mut cacheable = true;
        add_client_subnet(
            &mut options,
            IpAddr::V4("10.0.0.1".parse().unwrap()),
            false,
            true,
            None,
            None,
            &mut cacheable,
        );
        assert!(options.iter().all(|o| o.code != EDNS0_OPTION_CLIENT_SUBNET));
    }

    #[test]
    fn add_client_subnet_neither_option_but_client_sent_own_ecs_marks_uncacheable() {
        let mut options: Vec<Edns0Option> = find_pseudoheader(
            &add_source_addr(&base_query(), IpAddr::V4("10.0.0.1".parse().unwrap()), 24).unwrap(),
        )
        .unwrap()
        .options;
        let mut cacheable = true;
        add_client_subnet(
            &mut options,
            IpAddr::V4("10.0.0.1".parse().unwrap()),
            false,
            false,
            None,
            None,
            &mut cacheable,
        );
        assert!(!cacheable);
    }

    #[test]
    fn add_client_subnet_neither_option_no_existing_ecs_stays_cacheable() {
        let mut options = Vec::new();
        let mut cacheable = true;
        add_client_subnet(
            &mut options,
            IpAddr::V4("10.0.0.1".parse().unwrap()),
            false,
            false,
            None,
            None,
            &mut cacheable,
        );
        assert!(cacheable);
    }

    // ── add_umbrella_opt (via add_edns0_config) ───────────────────────────────

    #[test]
    fn add_edns0_config_umbrella_well_formed() {
        let cfg = Edns0QueryConfig {
            umbrella: true,
            umbrella_devid: true,
            umbrella_org: 0xAABBCCDD,
            umbrella_asset: 0x11223344,
            umbrella_device: [1, 2, 3, 4, 5, 6, 7, 8],
            ..Default::default()
        };
        let (options, cacheable) =
            add_edns0_config(&[], IpAddr::V4("192.0.2.1".parse().unwrap()), None, &cfg);
        let opt = options.iter().find(|o| o.code == EDNS0_OPTION_UMBRELLA).expect("umbrella missing");
        assert!(!cacheable);

        // magic "ODNS" + version(1) + flags(1)
        assert_eq!(&opt.data[0..4], b"ODNS");
        assert_eq!(opt.data[4], 1);
        assert_eq!(opt.data[5], 0);

        let mut u = &opt.data[6..];
        // org field: type(2)=0x0008, value(4)
        assert_eq!(u16::from_be_bytes([u[0], u[1]]), 0x0008);
        assert_eq!(u32::from_be_bytes([u[2], u[3], u[4], u[5]]), 0xAABBCCDD);
        u = &u[6..];
        // IPv4 field: type(2)=0x0010, value(4)
        assert_eq!(u16::from_be_bytes([u[0], u[1]]), 0x0010);
        assert_eq!(&u[2..6], &[192, 0, 2, 1]);
        u = &u[6..];
        // device field: type(2)=0x0040, value(8)
        assert_eq!(u16::from_be_bytes([u[0], u[1]]), 0x0040);
        assert_eq!(&u[2..10], &[1, 2, 3, 4, 5, 6, 7, 8]);
        u = &u[10..];
        // asset field: type(2)=0x0004, value(4)
        assert_eq!(u16::from_be_bytes([u[0], u[1]]), 0x0004);
        assert_eq!(u32::from_be_bytes([u[2], u[3], u[4], u[5]]), 0x11223344);
    }

    #[test]
    fn add_edns0_config_umbrella_ipv6() {
        let cfg = Edns0QueryConfig { umbrella: true, ..Default::default() };
        let addr: IpAddr = "2001:db8::1".parse().unwrap();
        let (options, _cacheable) = add_edns0_config(&[], addr, None, &cfg);
        let opt = options.iter().find(|o| o.code == EDNS0_OPTION_UMBRELLA).unwrap();
        let u = &opt.data[6..];
        assert_eq!(u16::from_be_bytes([u[0], u[1]]), 0x0020); // UMBRELLA_IPV6
        assert_eq!(&u[2..18], &addr_to_v6_octets(addr));
    }

    fn addr_to_v6_octets(addr: IpAddr) -> [u8; 16] {
        match addr {
            IpAddr::V6(v6) => v6.octets(),
            IpAddr::V4(_) => panic!("expected IPv6"),
        }
    }

    #[test]
    fn add_edns0_config_full_orchestration_order() {
        // With every option enabled, all four kinds should be present and the
        // answer marked uncacheable by the client-dependent ones.
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let sub4 = AddSubnetOpt { mask: 24, const_addr: None };
        let cfg = Edns0QueryConfig {
            add_mac: true,
            client_subnet: true,
            add_subnet4: Some(&sub4),
            dns_client_id: Some("id"),
            umbrella: true,
            ..Default::default()
        };
        let (options, cacheable) =
            add_edns0_config(&[], IpAddr::V4("10.0.0.1".parse().unwrap()), Some(&mac), &cfg);
        for code in [
            EDNS0_OPTION_MAC,
            EDNS0_OPTION_NOMCPEID,
            EDNS0_OPTION_UMBRELLA,
            EDNS0_OPTION_CLIENT_SUBNET,
        ] {
            assert!(options.iter().any(|o| o.code == code), "missing option {code}");
        }
        assert!(!cacheable);
    }
}
