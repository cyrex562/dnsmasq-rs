//! DNS packet parser — Rust port of dnsmasq's `rfc1035.c`.
//!
//! Provides wire-format encode/decode for DNS messages: names, questions,
//! resource records, and full packets.  No `unsafe` code; no C FFI.

use bytes::{BufMut, BytesMut};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use crate::cache::{CacheRecord, DnsCache};
use crate::types::constants::UID_NONE;
use crate::dns_protocol::{DnsHeader, RrType, HB3_AA, HB3_QR, HB3_TC, HB4_AD, HB4_RA};
use crate::types::addr::{AllAddr, CnameAddr, RrDataAddr};
use crate::types::constants::{
    F_CNAME, F_DNSSECOK, F_FORWARD, F_IPV4, F_IPV6, F_NEG, F_NXDOMAIN, F_RCODE, F_REVERSE, F_RR,
};
use crate::types::dns_records::{BogusAddr, Cname, Doctor, HostRecord, MxSrvRecord, Naptr, PtrRecord, TxtRecord};

// ──────────────────────────────────────────────────────────────────────────────
// Error type
// ──────────────────────────────────────────────────────────────────────────────

/// Errors that can occur while parsing or constructing DNS messages.
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("packet too short")]
    PacketTooShort,
    #[error("invalid name: {0}")]
    InvalidName(String),
    #[error("compression loop detected")]
    CompressionLoop,
    #[error("name too long")]
    NameTooLong,
    #[error("unexpected end of data")]
    UnexpectedEof,
}

// ──────────────────────────────────────────────────────────────────────────────
// Name codec
// ──────────────────────────────────────────────────────────────────────────────

/// Parse a DNS wire-format name starting at `*offset` inside `pkt`.
///
/// Follows pointer compression (top two bits of a length byte == `0xC0`).
/// Updates `*offset` to the byte immediately following the name on the wire
/// (or to the byte after the first pointer encountered, when compression is
/// used).  Returns the dot-separated name string, or `""` for the root label.
///
/// # Errors
/// Returns [`DnsError::CompressionLoop`] after more than 255 pointer hops,
/// [`DnsError::NameTooLong`] if the wire-format name exceeds 255 bytes, and
/// [`DnsError::UnexpectedEof`] / [`DnsError::PacketTooShort`] on truncation.
pub fn extract_name(pkt: &[u8], offset: &mut usize) -> Result<String, DnsError> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = *offset;
    // Byte-position to restore `*offset` to once we have followed ≥1 pointer.
    let mut end_offset: Option<usize> = None;
    let mut hops: usize = 0;
    // Wire-format length counter (label-length octets + label octets + root 0).
    // Starts at 1 to account for the mandatory root zero byte.
    let mut wire_len: usize = 1;

    loop {
        if pos >= pkt.len() {
            return Err(DnsError::UnexpectedEof);
        }
        let b = pkt[pos] as usize;

        if b == 0 {
            // Root label — end of name.
            if end_offset.is_none() {
                *offset = pos + 1;
            } else {
                *offset = end_offset.unwrap();
            }
            break;
        }

        if (b & 0xC0) == 0xC0 {
            // Pointer compression: lower 14 bits are the target offset.
            if pos + 1 >= pkt.len() {
                return Err(DnsError::PacketTooShort);
            }
            // Only the *first* pointer sets the caller's new offset.
            if end_offset.is_none() {
                end_offset = Some(pos + 2);
            }
            hops += 1;
            if hops > 255 {
                return Err(DnsError::CompressionLoop);
            }
            let ptr = ((b & 0x3F) << 8) | (pkt[pos + 1] as usize);
            if ptr >= pkt.len() {
                return Err(DnsError::InvalidName(
                    "compression pointer out of bounds".into(),
                ));
            }
            pos = ptr;
        } else if (b & 0xC0) == 0x00 {
            // Normal label: b is the label length.
            let label_len = b;
            pos += 1;
            if pos + label_len > pkt.len() {
                return Err(DnsError::UnexpectedEof);
            }
            // +1 for the length octet itself.
            wire_len += label_len + 1;
            if wire_len > 255 {
                return Err(DnsError::NameTooLong);
            }
            let label_bytes = &pkt[pos..pos + label_len];
            let label = std::str::from_utf8(label_bytes)
                .map_err(|_| DnsError::InvalidName("non-UTF8 label bytes".into()))?;
            labels.push(label.to_owned());
            pos += label_len;
        } else {
            return Err(DnsError::InvalidName(format!(
                "unknown label type 0x{:02x}",
                b
            )));
        }
    }

    Ok(labels.join("."))
}

/// Encode a domain name as DNS wire-format labels (no compression).
///
/// An empty string or `"."` encodes as a single zero byte (root label).
pub fn write_name(buf: &mut BytesMut, name: &str) {
    // Normalise the root-zone presentation form.
    let name = if name == "." { "" } else { name };
    if name.is_empty() {
        buf.put_u8(0);
        return;
    }
    for label in name.split('.') {
        let lb = label.as_bytes();
        buf.put_u8(lb.len() as u8);
        buf.put_slice(lb);
    }
    buf.put_u8(0);
}

/// Advance `*offset` past a DNS wire-format name without extracting it.
///
/// Stops at the root label or at the first pointer (which is always 2 bytes).
pub fn skip_name(pkt: &[u8], offset: &mut usize) -> Result<(), DnsError> {
    let mut pos = *offset;
    loop {
        if pos >= pkt.len() {
            return Err(DnsError::UnexpectedEof);
        }
        let b = pkt[pos] as usize;
        if b == 0 {
            *offset = pos + 1;
            return Ok(());
        }
        if (b & 0xC0) == 0xC0 {
            if pos + 1 >= pkt.len() {
                return Err(DnsError::PacketTooShort);
            }
            *offset = pos + 2;
            return Ok(());
        }
        if (b & 0xC0) != 0x00 {
            return Err(DnsError::InvalidName(format!(
                "unknown label type 0x{:02x}",
                b
            )));
        }
        pos += 1 + b;
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Question
// ──────────────────────────────────────────────────────────────────────────────

/// A DNS question record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    /// Raw wire QTYPE value.
    pub qtype: u16,
    /// Raw wire QCLASS value.
    pub qclass: u16,
}

impl DnsQuestion {
    /// Return the `RrType` if the wire value corresponds to a known type.
    pub fn rrtype(&self) -> Option<RrType> {
        RrType::from_u16(self.qtype)
    }
}

/// Parse a single DNS question from `pkt` starting at `*offset`.
pub fn parse_question(pkt: &[u8], offset: &mut usize) -> Result<DnsQuestion, DnsError> {
    let name = extract_name(pkt, offset)?;
    if *offset + 4 > pkt.len() {
        return Err(DnsError::PacketTooShort);
    }
    let qtype = u16::from_be_bytes([pkt[*offset], pkt[*offset + 1]]);
    let qclass = u16::from_be_bytes([pkt[*offset + 2], pkt[*offset + 3]]);
    *offset += 4;
    Ok(DnsQuestion { name, qtype, qclass })
}

/// Encode a DNS question into wire format.
pub fn write_question(buf: &mut BytesMut, q: &DnsQuestion) {
    write_name(buf, &q.name);
    buf.put_u16(q.qtype);
    buf.put_u16(q.qclass);
}

// ──────────────────────────────────────────────────────────────────────────────
// Resource Record
// ──────────────────────────────────────────────────────────────────────────────

/// A DNS resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRr {
    pub name: String,
    /// Raw wire TYPE value.
    pub rtype: u16,
    /// Raw wire CLASS value.
    pub class: u16,
    pub ttl: u32,
    /// Raw RDATA bytes (opaque; not decompressed).
    pub rdata: Vec<u8>,
}

impl DnsRr {
    /// Return the `RrType` if the wire value corresponds to a known type.
    pub fn rrtype(&self) -> Option<RrType> {
        RrType::from_u16(self.rtype)
    }
}

/// Parse a single resource record from `pkt` starting at `*offset`.
pub fn parse_rr(pkt: &[u8], offset: &mut usize) -> Result<DnsRr, DnsError> {
    let name = extract_name(pkt, offset)?;
    // Fixed part: TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 bytes.
    if *offset + 10 > pkt.len() {
        return Err(DnsError::PacketTooShort);
    }
    let rtype = u16::from_be_bytes([pkt[*offset], pkt[*offset + 1]]);
    let class = u16::from_be_bytes([pkt[*offset + 2], pkt[*offset + 3]]);
    let ttl = u32::from_be_bytes([
        pkt[*offset + 4],
        pkt[*offset + 5],
        pkt[*offset + 6],
        pkt[*offset + 7],
    ]);
    let rdlen = u16::from_be_bytes([pkt[*offset + 8], pkt[*offset + 9]]) as usize;
    *offset += 10;
    if *offset + rdlen > pkt.len() {
        return Err(DnsError::UnexpectedEof);
    }
    let rdata_start = *offset;
    let raw_rdata = pkt[*offset..*offset + rdlen].to_vec();
    *offset += rdlen;

    // For record types whose rdata contains domain names that may use DNS
    // pointer compression, decompress them here so stored rdata is always
    // self-contained (no references back into the original packet).
    let rdata = match rtype {
        2 | 5 | 12 => {
            // NS, CNAME, PTR: rdata is a single domain name.
            let mut pos = rdata_start;
            match extract_name(pkt, &mut pos) {
                Ok(n) => {
                    let mut buf = BytesMut::new();
                    write_name(&mut buf, &n);
                    buf.to_vec()
                }
                Err(_) => raw_rdata,
            }
        }
        15 => {
            // MX: 2-byte preference then a domain name.
            if raw_rdata.len() >= 2 {
                let mut pos = rdata_start + 2;
                match extract_name(pkt, &mut pos) {
                    Ok(n) => {
                        let mut buf = BytesMut::new();
                        buf.put_u16(u16::from_be_bytes([raw_rdata[0], raw_rdata[1]]));
                        write_name(&mut buf, &n);
                        buf.to_vec()
                    }
                    Err(_) => raw_rdata,
                }
            } else {
                raw_rdata
            }
        }
        6 => {
            // SOA: MNAME (name) + RNAME (name) + 5 × u32 fixed fields.
            let mut pos = rdata_start;
            let ok = extract_name(pkt, &mut pos)
                .and_then(|mname| extract_name(pkt, &mut pos).map(|rname| (mname, rname)));
            match ok {
                Ok((mname, rname)) if pos + 20 <= pkt.len() => {
                    let mut buf = BytesMut::new();
                    write_name(&mut buf, &mname);
                    write_name(&mut buf, &rname);
                    buf.put_slice(&pkt[pos..pos + 20]);
                    buf.to_vec()
                }
                _ => raw_rdata,
            }
        }
        _ => raw_rdata,
    };

    Ok(DnsRr { name, rtype, class, ttl, rdata })
}

/// Encode a resource record into wire format (rdata written verbatim).
pub fn write_rr(buf: &mut BytesMut, rr: &DnsRr) {
    write_name(buf, &rr.name);
    buf.put_u16(rr.rtype);
    buf.put_u16(rr.class);
    buf.put_u32(rr.ttl);
    buf.put_u16(rr.rdata.len() as u16);
    buf.put_slice(&rr.rdata);
}

// ──────────────────────────────────────────────────────────────────────────────
// Full packet
// ──────────────────────────────────────────────────────────────────────────────

/// A fully parsed DNS packet.
#[derive(Debug, Clone)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRr>,
    pub authority: Vec<DnsRr>,
    pub additional: Vec<DnsRr>,
}

impl DnsPacket {
    /// Parse a complete DNS packet from a byte slice.
    pub fn parse(pkt: &[u8]) -> Result<Self, DnsError> {
        let header = DnsHeader::from_bytes(pkt).ok_or(DnsError::PacketTooShort)?;
        let mut offset = 12usize;

        let mut questions = Vec::with_capacity(header.qdcount as usize);
        for _ in 0..header.qdcount {
            questions.push(parse_question(pkt, &mut offset)?);
        }
        let mut answers = Vec::with_capacity(header.ancount as usize);
        for _ in 0..header.ancount {
            answers.push(parse_rr(pkt, &mut offset)?);
        }
        let mut authority = Vec::with_capacity(header.nscount as usize);
        for _ in 0..header.nscount {
            authority.push(parse_rr(pkt, &mut offset)?);
        }
        let mut additional = Vec::with_capacity(header.arcount as usize);
        for _ in 0..header.arcount {
            additional.push(parse_rr(pkt, &mut offset)?);
        }

        Ok(DnsPacket { header, questions, answers, authority, additional })
    }

    /// Serialise the packet to wire format without name compression.
    ///
    /// The section counts written in the header are derived from the stored
    /// `Vec` lengths so that they remain consistent even if the caller modified
    /// `header.{qd,an,ns,ar}count`.
    pub fn write(&self) -> BytesMut {
        let mut hdr = self.header;
        hdr.qdcount = self.questions.len() as u16;
        hdr.ancount = self.answers.len() as u16;
        hdr.nscount = self.authority.len() as u16;
        hdr.arcount = self.additional.len() as u16;

        let mut buf = BytesMut::new();
        buf.put_slice(&hdr.to_bytes());
        for q in &self.questions {
            write_question(&mut buf, q);
        }
        for r in &self.answers {
            write_rr(&mut buf, r);
        }
        for r in &self.authority {
            write_rr(&mut buf, r);
        }
        for r in &self.additional {
            write_rr(&mut buf, r);
        }
        buf
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// PTR-name ↔ address conversion
// ──────────────────────────────────────────────────────────────────────────────

/// Convert a PTR domain name to the IP address it represents.
///
/// Handles:
/// * `4.3.2.1.in-addr.arpa` → [`AllAddr::Addr4`]`(1.2.3.4)`
/// * 32-nibble `…ip6.arpa` form → [`AllAddr::Addr6`]
///
/// Returns `None` if the name is not a valid PTR name.
pub fn in_arpa_name_2_addr(name: &str) -> Option<AllAddr> {
    let lower = name.to_lowercase();
    // Strip an optional trailing dot (FQDN form).
    let lower = lower.strip_suffix('.').unwrap_or(&lower);

    if let Some(rest) = lower.strip_suffix(".in-addr.arpa") {
        // IPv4: labels are the four octets in *reverse* order.
        let parts: Vec<&str> = rest.split('.').collect();
        if parts.len() != 4 {
            return None;
        }
        // Parse and reverse so index 0 is the most-significant octet.
        let octets: Vec<u8> = parts
            .iter()
            .rev()
            .map(|s| s.parse::<u8>().ok())
            .collect::<Option<Vec<_>>>()?;
        Some(AllAddr::Addr4(Ipv4Addr::new(
            octets[0], octets[1], octets[2], octets[3],
        )))
    } else if let Some(rest) = lower.strip_suffix(".ip6.arpa") {
        // IPv6: 32 single-hex-digit labels in reverse nibble order.
        let nibbles: Vec<u8> = rest
            .split('.')
            .map(|s| {
                if s.len() == 1 {
                    u8::from_str_radix(s, 16).ok()
                } else {
                    None
                }
            })
            .collect::<Option<Vec<_>>>()?;
        if nibbles.len() != 32 {
            return None;
        }
        // Reconstruct the 16 address bytes.
        // nibbles[0] is the *least-significant nibble of the last byte*,
        // nibbles[31] is the *most-significant nibble of the first byte*.
        // So for byte i (0 = most significant):
        //   high nibble = nibbles[31 - i*2]
        //   low  nibble = nibbles[30 - i*2]
        let mut bytes = [0u8; 16];
        for i in 0..16 {
            let hi = nibbles[31 - i * 2];
            let lo = nibbles[30 - i * 2];
            bytes[i] = (hi << 4) | lo;
        }
        Some(AllAddr::Addr6(Ipv6Addr::from(bytes)))
    } else {
        None
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Private / special-use address checks
// ──────────────────────────────────────────────────────────────────────────────

/// Returns `true` if `addr` falls within a private, link-local, or (when
/// `ban_localhost` is set) loopback IPv4 range.
///
/// Covered ranges:
/// * `10.0.0.0/8`     — RFC 1918
/// * `172.16.0.0/12`  — RFC 1918
/// * `192.168.0.0/16` — RFC 1918
/// * `169.254.0.0/16` — link-local (RFC 3927)
/// * `127.0.0.0/8`    — loopback (only when `ban_localhost == true`)
pub fn private_net(addr: Ipv4Addr, ban_localhost: bool) -> bool {
    let o = addr.octets();
    // 10.0.0.0/8
    if o[0] == 10 {
        return true;
    }
    // 172.16.0.0/12  (172.16.x.x – 172.31.x.x)
    if o[0] == 172 && (o[1] & 0xF0) == 0x10 {
        return true;
    }
    // 192.168.0.0/16
    if o[0] == 192 && o[1] == 168 {
        return true;
    }
    // 169.254.0.0/16  link-local
    if o[0] == 169 && o[1] == 254 {
        return true;
    }
    // 127.0.0.0/8  loopback
    if ban_localhost && o[0] == 127 {
        return true;
    }
    false
}

/// Returns `true` if `addr` is a private, link-local, or (when
/// `ban_localhost` is set) loopback IPv6 address.
///
/// Covered ranges:
/// * `fc00::/7`   — ULA (RFC 4193)
/// * `fe80::/10`  — link-local (RFC 4291)
/// * `::1`        — loopback (only when `ban_localhost == true`)
pub fn private_net6(addr: &Ipv6Addr, ban_localhost: bool) -> bool {
    let b = addr.octets();
    // fc00::/7 — ULA: first byte has top 7 bits == 0b1111110x
    if b[0] & 0xFE == 0xFC {
        return true;
    }
    // fe80::/10 — link-local: 1111 1110 10xx xxxx …
    if b[0] == 0xFE && (b[1] & 0xC0) == 0x80 {
        return true;
    }
    // ::1 — loopback
    if ban_localhost && *addr == Ipv6Addr::LOCALHOST {
        return true;
    }
    false
}

// ──────────────────────────────────────────────────────────────────────────────
// Convenience helper
// ──────────────────────────────────────────────────────────────────────────────

/// Parse the first question of a DNS query packet and return `(name, qtype)`.
///
/// Returns `None` if the packet is malformed, has no questions, or the QTYPE
/// is not a recognised [`RrType`].
pub fn extract_request(pkt: &[u8]) -> Option<(String, RrType)> {
    let header = DnsHeader::from_bytes(pkt)?;
    if header.qdcount == 0 {
        return None;
    }
    let mut offset = 12usize;
    let q = parse_question(pkt, &mut offset).ok()?;
    let rtype = RrType::from_u16(q.qtype)?;
    Some((q.name, rtype))
}

// ──────────────────────────────────────────────────────────────────────────────
// Cache population: extract_addresses
// ──────────────────────────────────────────────────────────────────────────────

/// Configuration for [`extract_addresses`].
#[derive(Debug, Clone)]
pub struct ExtractConfig {
    /// Maximum TTL to cache, in seconds.  `0` means no limit.
    pub max_ttl: u32,
    /// Default negative-caching TTL when no SOA record is present.
    /// `0` means do not cache negative responses without a SOA.
    pub neg_ttl: u32,
    /// Reject DNS replies containing RFC 1918 / private IPv4 or
    /// ULA / link-local IPv6 addresses (DNS rebind protection).
    pub check_rebind: bool,
    /// Suppress negative caching entirely.
    pub no_neg_cache: bool,
    /// The reply was DNSSEC-validated; set `F_DNSSECOK` on cached records.
    pub secure: bool,
}

impl Default for ExtractConfig {
    fn default() -> Self {
        Self {
            max_ttl: 0,
            neg_ttl: 0,
            check_rebind: false,
            no_neg_cache: false,
            secure: false,
        }
    }
}

/// Return value of [`extract_addresses`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractResult {
    /// Records were cached (or there was nothing to cache).
    Cached,
    /// DNS-rebind protection blocked a private/ULA address in the reply.
    RebindBlocked,
    /// The packet is structurally malformed.
    BadPacket,
}

/// Maximum CNAME chain depth we will follow in a single reply.
const CNAME_CHAIN_LIMIT: usize = 10;

/// Clamp `ttl` to `max_ttl` when `max_ttl > 0`.
fn clamp_ttl(ttl: u32, max_ttl: u32) -> u32 {
    if max_ttl != 0 && ttl > max_ttl { max_ttl } else { ttl }
}

/// Scan `authority` for a SOA record and return the effective negative TTL.
///
/// The negative TTL is `min(soa_ttl, soa_minimum)` as defined by RFC 2308.
fn find_soa_minimum_ttl(authority: &[DnsRr]) -> Option<u32> {
    for rr in authority {
        if rr.rtype != 6 /* SOA */ { continue; }
        // rdata layout after parse_rr decompression:
        //   MNAME (wire-format labels) | RNAME (wire-format labels) |
        //   serial(4) | refresh(4) | retry(4) | expire(4) | minimum(4)
        let mut pos = 0usize;
        extract_name(&rr.rdata, &mut pos).ok()?; // mname
        extract_name(&rr.rdata, &mut pos).ok()?; // rname
        if pos + 20 <= rr.rdata.len() {
            let minimum = u32::from_be_bytes([
                rr.rdata[pos + 16],
                rr.rdata[pos + 17],
                rr.rdata[pos + 18],
                rr.rdata[pos + 19],
            ]);
            return Some(rr.ttl.min(minimum));
        }
    }
    None
}

/// Extract DNS records from a parsed reply and insert them into `cache`.
///
/// This is the Rust port of `extract_addresses()` from `rfc1035.c`.
///
/// Handles A, AAAA, CNAME, PTR, and arbitrary RR types.
/// Performs negative caching for `NXDOMAIN` and `NODATA` replies.
pub fn extract_addresses(
    packet: &DnsPacket,
    cache: &mut DnsCache,
    now: Instant,
    config: &ExtractConfig,
) -> ExtractResult {
    // Only process replies with exactly one question.
    if packet.questions.len() != 1 {
        return ExtractResult::BadPacket;
    }
    let q = &packet.questions[0];
    // Only cache IN (class 1) answers.
    if q.qclass != 1 {
        return ExtractResult::Cached;
    }

    let qname_lower = q.name.to_lowercase();
    let qtype       = q.qtype;
    let is_nxdomain = packet.header.rcode() == 3;
    let secflag     = if config.secure { F_DNSSECOK } else { 0 };

    // ── PTR reverse lookup ────────────────────────────────────────────────────
    if qtype == 12 /* PTR */ {
        // Only cache when the question name is a valid .arpa reverse zone name.
        if let Some(ip_addr) = in_arpa_name_2_addr(&qname_lower) {
            let addr_flag = match &ip_addr {
                AllAddr::Addr4(_) => F_IPV4,
                AllAddr::Addr6(_) => F_IPV6,
                _ => 0,
            };
            let mut found = false;
            for rr in &packet.answers {
                if rr.rtype != 12 || rr.class != 1 { continue; }
                if !rr.name.eq_ignore_ascii_case(&q.name) { continue; }
                let mut off = 0usize;
                let target = match extract_name(&rr.rdata, &mut off) {
                    Ok(t)  => t,
                    Err(_) => return ExtractResult::BadPacket,
                };
                let ttl = clamp_ttl(rr.ttl, config.max_ttl);
                cache.insert(CacheRecord {
                    name:    target,
                    flags:   addr_flag | F_REVERSE | secflag,
                    ttl,
                    expires: now + Duration::from_secs(u64::from(ttl)),
                    addr:    Some(ip_addr.clone()),
                    rdata:   None,
                    uid:     UID_NONE,
                });
                found = true;
            }
            if found {
                return ExtractResult::Cached;
            }
        }
        // For PTR queries with no PTR answer we do not cache a negative entry.
        return ExtractResult::Cached;
    }

    // ── Forward lookup (A, AAAA, or arbitrary RR) ─────────────────────────────
    let addr_flag = match qtype {
        1  /* A    */ => F_IPV4,
        28 /* AAAA */ => F_IPV6,
        _             => F_RR,
    };

    // Follow the CNAME chain beginning at the question name.
    let mut current_name = qname_lower.clone();
    let mut cname_hops   = 0usize;
    let mut found        = false;

    'cname_loop: loop {
        for rr in &packet.answers {
            if rr.class != 1 { continue; }
            if !rr.name.eq_ignore_ascii_case(&current_name) { continue; }
            let ttl = clamp_ttl(rr.ttl, config.max_ttl);

            if rr.rtype == 5 /* CNAME */ {
                if cname_hops >= CNAME_CHAIN_LIMIT { break 'cname_loop; }
                let mut off = 0usize;
                let target = match extract_name(&rr.rdata, &mut off) {
                    Ok(t)  => t.to_lowercase(),
                    Err(_) => return ExtractResult::BadPacket,
                };
                cache.insert(CacheRecord {
                    name:    current_name.clone(),
                    flags:   F_CNAME | F_FORWARD | secflag,
                    ttl,
                    expires: now + Duration::from_secs(u64::from(ttl)),
                    addr:    Some(AllAddr::Cname(CnameAddr {
                        is_name_ptr:  true,
                        target_name:  Some(target.clone()),
                        uid:          0,
                    })),
                    rdata: None,
                    uid:   UID_NONE,
                });
                cname_hops += 1;
                current_name = target;
                continue 'cname_loop; // restart loop for the CNAME target
            }

            if rr.rtype != qtype || is_nxdomain { continue; }

            let addr = match qtype {
                1 /* A */ => {
                    if rr.rdata.len() < 4 { return ExtractResult::BadPacket; }
                    let ip = Ipv4Addr::new(
                        rr.rdata[0], rr.rdata[1], rr.rdata[2], rr.rdata[3],
                    );
                    if config.check_rebind && private_net(ip, true) {
                        return ExtractResult::RebindBlocked;
                    }
                    AllAddr::Addr4(ip)
                }
                28 /* AAAA */ => {
                    if rr.rdata.len() < 16 { return ExtractResult::BadPacket; }
                    let mut b = [0u8; 16];
                    b.copy_from_slice(&rr.rdata[..16]);
                    let ip = Ipv6Addr::from(b);
                    if config.check_rebind && private_net6(&ip, true) {
                        return ExtractResult::RebindBlocked;
                    }
                    AllAddr::Addr6(ip)
                }
                _ => AllAddr::RrData(RrDataAddr {
                    rrtype: rr.rtype,
                    data:   rr.rdata.clone(),
                }),
            };
            cache.insert(CacheRecord {
                name:    current_name.clone(),
                flags:   addr_flag | F_FORWARD | secflag,
                ttl,
                expires: now + Duration::from_secs(u64::from(ttl)),
                addr:    Some(addr),
                rdata:   None,
                uid:     UID_NONE,
            });
            found = true;
        }
        break 'cname_loop;
    }

    // ── Negative caching ──────────────────────────────────────────────────────
    if !found && !config.no_neg_cache {
        let neg_ttl = find_soa_minimum_ttl(&packet.authority)
            .map(|t| clamp_ttl(t, config.max_ttl))
            .or_else(|| if config.neg_ttl > 0 { Some(config.neg_ttl) } else { None });
        if let Some(ttl) = neg_ttl {
            let neg_flags = if is_nxdomain {
                F_NXDOMAIN | F_NEG | F_FORWARD | secflag
            } else {
                addr_flag | F_NEG | F_FORWARD | secflag
            };
            cache.insert(CacheRecord {
                name:    qname_lower,
                flags:   neg_flags,
                ttl,
                expires: now + Duration::from_secs(u64::from(ttl)),
                addr:    None,
                rdata:   None,
                uid:     UID_NONE,
            });
        }
    }

    ExtractResult::Cached
}

// ──────────────────────────────────────────────────────────────────────────────
// Answer local queries
// ──────────────────────────────────────────────────────────────────────────────

/// Configuration for answering DNS queries from local data and cache.
pub struct LocalConfig<'a> {
    pub local_ttl:     u32,
    pub txt_records:   &'a [TxtRecord],
    pub rr_records:    &'a [TxtRecord],   // arbitrary cached-RR types (class field = rrtype)
    pub mx_records:    &'a [MxSrvRecord],
    pub ptr_records:   &'a [PtrRecord],
    pub host_records:  &'a [HostRecord],
    pub cnames:        &'a [Cname],
    pub naptr_records: &'a [Naptr],
}

/// Port of C's `setup_reply()`.  Sets standard response flags on a DnsHeader.
pub fn setup_reply(header: &mut DnsHeader, flags: u32) {
    header.hb3 = (header.hb3 & !(HB3_AA | HB3_TC)) | HB3_QR;
    header.hb4 = (header.hb4 & !HB4_AD) | HB4_RA;
    header.nscount = 0;
    header.arcount = 0;
    header.ancount = 0;
    if flags == F_NXDOMAIN {
        header.set_rcode(3);
    } else if flags == F_RCODE {
        header.set_rcode(4); // NOTIMP
    } else if flags & (F_IPV4 | F_IPV6) != 0 {
        header.set_rcode(0);
        header.hb3 |= HB3_AA;
    } else {
        header.set_rcode(0);
    }
}

/// Port of C's `answer_request()`.  Answers DNS queries from local config and cache.
///
/// Returns `None` when the query should be forwarded to an upstream resolver.
pub fn answer_request(
    query:  &DnsPacket,
    cache:  &mut DnsCache,
    now:    Instant,
    config: &LocalConfig<'_>,
) -> Option<DnsPacket> {
    // 1. Validate: exactly 1 question, no answers/authority, opcode=QUERY(0).
    if query.questions.len() != 1
        || !query.answers.is_empty()
        || !query.authority.is_empty()
        || query.header.opcode() != 0
    {
        return None;
    }

    let q      = &query.questions[0];
    let qtype  = q.qtype;
    let qclass = q.qclass;

    // 2. Only handle IN (1) or CH (3).
    if qclass != 1 && qclass != 3 {
        return None;
    }

    // 3. Build response with header copy: QR=1, RA=1, clear AA & AD.
    let mut resp_hdr = query.header;
    resp_hdr.hb3 = (resp_hdr.hb3 & !(HB3_AA | HB3_TC)) | HB3_QR;
    resp_hdr.hb4 = (resp_hdr.hb4 & !HB4_AD) | HB4_RA;
    resp_hdr.ancount = 0;
    resp_hdr.nscount = 0;
    resp_hdr.arcount = 0;

    let mut response = DnsPacket {
        header:     resp_hdr,
        questions:  query.questions.clone(),
        answers:    Vec::new(),
        authority:  Vec::new(),
        additional: Vec::new(),
    };

    // 4. CH class: reply NOTIMP for well-known chaos names, otherwise forward.
    if qclass == 3 {
        let lower = q.name.to_lowercase();
        if lower == "bind"
            || lower == "server"
            || lower.ends_with(".bind")
            || lower.ends_with(".server")
        {
            response.header.set_rcode(4); // NOTIMP
            return Some(response);
        }
        return None;
    }

    // 5. IN class processing.
    let mut name     = q.name.to_lowercase();
    let mut answers: Vec<DnsRr> = Vec::new();
    let mut ans      = false;
    let mut nxdomain = false;
    let mut auth     = false;
    let ttl          = config.local_ttl;

    // 5a. CNAME chain (max 16 hops).
    for _ in 0..16 {
        // Config CNAMEs first.
        if let Some(c) = config.cnames.iter().find(|c| c.alias.to_lowercase() == name) {
            let target = c.target.clone();
            let mut rd = BytesMut::new();
            write_name(&mut rd, &target);
            answers.push(DnsRr { name: name.clone(), rtype: 5, class: 1, ttl, rdata: rd.to_vec() });
            name = target.to_lowercase();
            ans  = true;
            continue;
        }

        // Cached CNAME.
        let cname_target: Option<String> = cache
            .lookup_by_name(&name, F_CNAME, now)
            .and_then(|r| {
                if let Some(AllAddr::Cname(ref c)) = r.addr {
                    c.target_name.clone()
                } else {
                    None
                }
            });
        if let Some(target) = cname_target {
            let mut rd = BytesMut::new();
            write_name(&mut rd, &target);
            answers.push(DnsRr { name: name.clone(), rtype: 5, class: 1, ttl, rdata: rd.to_vec() });
            name = target.to_lowercase();
            ans  = true;
            continue;
        }

        // Cached NXDOMAIN.
        if cache.lookup_by_name(&name, F_NXDOMAIN | F_NEG, now).is_some() {
            nxdomain = true;
            ans      = true;
        }
        break;
    }

    // 5b. TXT (qtype 16 or ANY=255).
    if qtype == 16 || qtype == 255 {
        for t in config.txt_records.iter()
            .filter(|t| t.class == qclass && t.name.to_lowercase() == name)
        {
            answers.push(DnsRr {
                name: name.clone(), rtype: 16, class: 1, ttl, rdata: t.txt.clone(),
            });
            ans  = true;
            auth = true;
        }
    }

    // 5c. Arbitrary cached-RR (qclass IN only).
    if qclass == 1 {
        for t in config.rr_records.iter()
            .filter(|t| t.name.to_lowercase() == name && (t.class == qtype || qtype == 255))
        {
            answers.push(DnsRr {
                name: name.clone(), rtype: t.class, class: 1, ttl, rdata: t.txt.clone(),
            });
            ans  = true;
            auth = true;
        }
    }

    // 5d. PTR (qtype 12 or ANY).
    if qtype == 12 || qtype == 255 {
        let mut found_ptr = false;
        for p in config.ptr_records.iter().filter(|p| p.name.to_lowercase() == name) {
            let mut rd = BytesMut::new();
            write_name(&mut rd, &p.ptr);
            answers.push(DnsRr { name: name.clone(), rtype: 12, class: 1, ttl, rdata: rd.to_vec() });
            ans       = true;
            auth      = true;
            found_ptr = true;
        }
        if !found_ptr {
            if let Some(addr) = in_arpa_name_2_addr(&name) {
                // Try host_records reverse lookup.
                if let Some(hostname) = host_records_find_by_addr(&addr, config.host_records) {
                    let mut rd = BytesMut::new();
                    write_name(&mut rd, &hostname);
                    answers.push(DnsRr {
                        name: name.clone(), rtype: 12, class: 1, ttl, rdata: rd.to_vec(),
                    });
                    ans       = true;
                    auth      = true;
                    found_ptr = true;
                }
                if !found_ptr {
                    // Try cache reverse lookup.
                    let cached = cache
                        .lookup_by_addr(&addr, now)
                        .map(|r| (r.name.clone(), r.flags));
                    if let Some((hostname, flags)) = cached {
                        if flags & F_NXDOMAIN != 0 {
                            nxdomain = true;
                            ans      = true;
                        } else {
                            let mut rd = BytesMut::new();
                            write_name(&mut rd, &hostname);
                            answers.push(DnsRr {
                                name: name.clone(), rtype: 12, class: 1, ttl, rdata: rd.to_vec(),
                            });
                            ans = true;
                        }
                    }
                }
            }
        }
    }

    // 5e. A / AAAA (qtype 1, 28, or ANY).
    if qtype == 1 || qtype == 28 || qtype == 255 {
        let want_a    = qtype == 1  || qtype == 255;
        let want_aaaa = qtype == 28 || qtype == 255;
        let mut found_in_host = false;

        for hr in config.host_records.iter() {
            if !hr.names.iter().any(|n| n.to_lowercase() == name) {
                continue;
            }
            if want_a {
                if let Some(ip4) = hr.addr4 {
                    answers.push(DnsRr {
                        name: name.clone(), rtype: 1, class: 1, ttl, rdata: ip4.octets().to_vec(),
                    });
                    ans           = true;
                    auth          = true;
                    found_in_host = true;
                }
            }
            if want_aaaa {
                if let Some(ip6) = hr.addr6 {
                    answers.push(DnsRr {
                        name: name.clone(), rtype: 28, class: 1, ttl, rdata: ip6.octets().to_vec(),
                    });
                    ans           = true;
                    auth          = true;
                    found_in_host = true;
                }
            }
        }

        if !found_in_host {
            if want_a {
                let cached = cache
                    .lookup_by_name(&name, F_IPV4, now)
                    .map(|r| (r.addr.clone(), r.flags, r.ttl));
                if let Some((addr, flags, cached_ttl)) = cached {
                    if flags & F_NEG != 0 {
                        if flags & F_NXDOMAIN != 0 {
                            nxdomain = true;
                        }
                        ans = true;
                    } else if let Some(AllAddr::Addr4(ip)) = addr {
                        answers.push(DnsRr {
                            name: name.clone(), rtype: 1, class: 1,
                            ttl: cached_ttl, rdata: ip.octets().to_vec(),
                        });
                        ans = true;
                    }
                }
            }
            if want_aaaa {
                let cached = cache
                    .lookup_by_name(&name, F_IPV6, now)
                    .map(|r| (r.addr.clone(), r.flags, r.ttl));
                if let Some((addr, flags, cached_ttl)) = cached {
                    if flags & F_NEG != 0 {
                        if flags & F_NXDOMAIN != 0 {
                            nxdomain = true;
                        }
                        ans = true;
                    } else if let Some(AllAddr::Addr6(ip)) = addr {
                        answers.push(DnsRr {
                            name: name.clone(), rtype: 28, class: 1,
                            ttl: cached_ttl, rdata: ip.octets().to_vec(),
                        });
                        ans = true;
                    }
                }
            }
        }
    }

    // 5f. MX (qtype 15 or ANY).
    if qtype == 15 || qtype == 255 {
        for m in config.mx_records.iter()
            .filter(|m| !m.is_srv && m.name.to_lowercase() == name)
        {
            let mut rd = BytesMut::new();
            rd.put_u16(m.priority as u16);
            write_name(&mut rd, &m.target);
            answers.push(DnsRr { name: name.clone(), rtype: 15, class: 1, ttl, rdata: rd.to_vec() });
            ans  = true;
            auth = true;
        }
    }

    // 5g. SRV (qtype 33 or ANY).
    if qtype == 33 || qtype == 255 {
        for s in config.mx_records.iter()
            .filter(|m| m.is_srv && m.name.to_lowercase() == name)
        {
            let mut rd = BytesMut::new();
            rd.put_u16(s.priority as u16);
            rd.put_u16(s.weight as u16);
            rd.put_u16(s.srv_port);
            write_name(&mut rd, &s.target);
            answers.push(DnsRr { name: name.clone(), rtype: 33, class: 1, ttl, rdata: rd.to_vec() });
            ans  = true;
            auth = true;
        }
    }

    // 5h. NAPTR (qtype 35 or ANY).
    if qtype == 35 || qtype == 255 {
        for n in config.naptr_records.iter()
            .filter(|n| n.name.to_lowercase() == name)
        {
            let mut rd = BytesMut::new();
            rd.put_u16(n.order as u16);
            rd.put_u16(n.pref as u16);
            rd.put_u8(n.flags.len() as u8);
            rd.put_slice(n.flags.as_bytes());
            rd.put_u8(n.services.len() as u8);
            rd.put_slice(n.services.as_bytes());
            rd.put_u8(n.regexp.len() as u8);
            rd.put_slice(n.regexp.as_bytes());
            write_name(&mut rd, &n.replace);
            answers.push(DnsRr { name: name.clone(), rtype: 35, class: 1, ttl, rdata: rd.to_vec() });
            ans  = true;
            auth = true;
        }
    }

    // 6. No answer found → forward upstream.
    if !ans {
        return None;
    }

    // 7. Finalise response header.
    response.answers        = answers;
    response.header.ancount = response.answers.len() as u16;
    if nxdomain {
        response.header.set_rcode(3);
        response.header.hb3 &= !HB3_AA;
    } else if auth {
        response.header.hb3 |= HB3_AA;
        response.header.set_rcode(0);
    } else {
        response.header.hb3 &= !HB3_AA;
        response.header.set_rcode(0);
    }
    response.header.hb3 |= HB3_QR;
    response.header.hb4 |= HB4_RA;

    Some(response)
}

/// Search `host_records` for the first record whose `addr4` or `addr6` matches
/// `addr`.  Returns the first name from the matching record's `names` vec.
fn host_records_find_by_addr(addr: &AllAddr, host_records: &[HostRecord]) -> Option<String> {
    for hr in host_records {
        let matched = match addr {
            AllAddr::Addr4(ip4) => hr.addr4.as_ref() == Some(ip4),
            AllAddr::Addr6(ip6) => hr.addr6.as_ref() == Some(ip6),
            _                   => false,
        };
        if matched {
            return hr.names.first().cloned();
        }
    }
    None
}

// ──────────────────────────────────────────────────────────────────────────────
// Check helpers: bogus addresses, ignored addresses, local domain, do_doctor
// ──────────────────────────────────────────────────────────────────────────────

/// Returns `true` if `sub` is equal to `domain` or is a subdomain of it
/// (case-insensitive).
pub fn hostname_issubdomain(sub: &str, domain: &str) -> bool {
    let s = sub.to_lowercase();
    let d = domain.to_lowercase();
    s == d || s.ends_with(&format!(".{d}"))
}

/// Returns `true` if `addr` falls within the range / prefix described by `ba`.
fn addr_in_bogus_range(addr: &AllAddr, ba: &BogusAddr) -> bool {
    match addr {
        AllAddr::Addr4(ip) if !ba.is6 => match &ba.addr {
            AllAddr::Addr4(ba_ip) => {
                let prefix = ba.prefix.clamp(0, 32) as u32;
                let mask = if prefix == 0 {
                    0u32
                } else if prefix >= 32 {
                    u32::MAX
                } else {
                    !((1u32 << (32 - prefix)) - 1)
                };
                (u32::from_be_bytes(ip.octets()) & mask)
                    == (u32::from_be_bytes(ba_ip.octets()) & mask)
            }
            _ => false,
        },
        AllAddr::Addr6(ip) if ba.is6 => match &ba.addr {
            AllAddr::Addr6(ba_ip) => {
                let prefix = ba.prefix.clamp(0, 128) as u32;
                let full  = (prefix / 8) as usize;
                let rem   = prefix % 8;
                let ib = ip.octets();
                let bb = ba_ip.octets();
                if ib[..full] != bb[..full] {
                    return false;
                }
                if rem > 0 && full < 16 {
                    let mask = !((1u8 << (8 - rem)) - 1);
                    (ib[full] & mask) == (bb[full] & mask)
                } else {
                    true
                }
            }
            _ => false,
        },
        _ => false,
    }
}

/// Check whether any A record in `packet` matches a bogus-address list.
///
/// If a match is found, inserts an NXDOMAIN negative cache entry for the
/// question name (TTL = `local_ttl`) and returns `true`.
pub fn check_for_bogus_wildcard(
    packet:     &DnsPacket,
    cache:      &mut DnsCache,
    now:        Instant,
    bogus_addrs: &[BogusAddr],
    local_ttl:  u32,
) -> bool {
    if bogus_addrs.is_empty() { return false; }

    let qname = packet.questions.first().map(|q| q.name.to_lowercase());

    for rr in &packet.answers {
        if rr.class != 1 || rr.rdata.len() < 4 { continue; }
        let addr_opt: Option<AllAddr> = match rr.rtype {
            1 if rr.rdata.len() >= 4 => Some(AllAddr::Addr4(Ipv4Addr::new(
                rr.rdata[0], rr.rdata[1], rr.rdata[2], rr.rdata[3],
            ))),
            _ => None,
        };
        if let Some(addr) = addr_opt {
            for ba in bogus_addrs {
                if addr_in_bogus_range(&addr, ba) {
                    if let Some(ref name) = qname {
                        cache.insert(CacheRecord {
                            name:    name.clone(),
                            flags:   F_FORWARD | F_NEG | F_NXDOMAIN,
                            ttl:     local_ttl,
                            expires: now + Duration::from_secs(u64::from(local_ttl)),
                            addr:    None,
                            rdata:   None,
                            uid:     UID_NONE,
                        });
                    }
                    return true;
                }
            }
        }
    }
    false
}

/// Check whether any A or AAAA record in `packet` matches an address in the
/// ignore list.  If so, the reply should be silently dropped.
pub fn check_for_ignored_address(packet: &DnsPacket, ignore_addrs: &[BogusAddr]) -> bool {
    if ignore_addrs.is_empty() { return false; }

    for rr in &packet.answers {
        if rr.class != 1 { continue; }
        let addr_opt: Option<AllAddr> = match rr.rtype {
            1 if rr.rdata.len() >= 4 => Some(AllAddr::Addr4(Ipv4Addr::new(
                rr.rdata[0], rr.rdata[1], rr.rdata[2], rr.rdata[3],
            ))),
            28 if rr.rdata.len() >= 16 => {
                let mut b = [0u8; 16];
                b.copy_from_slice(&rr.rdata[..16]);
                Some(AllAddr::Addr6(Ipv6Addr::from(b)))
            }
            _ => None,
        };
        if let Some(addr) = addr_opt {
            for ia in ignore_addrs {
                if addr_in_bogus_range(&addr, ia) {
                    return true;
                }
            }
        }
    }
    false
}

/// Returns `true` if `name` matches any locally-configured record type.
///
/// Checks NAPTR, MX/SRV, TXT, and PTR records for an exact match or subdomain
/// relationship (mirrors C's `check_for_local_domain()`).
pub fn check_for_local_domain(name: &str, config: &LocalConfig<'_>) -> bool {
    config.naptr_records.iter().any(|n| hostname_issubdomain(name, &n.name))
        || config.mx_records.iter().any(|m| hostname_issubdomain(name, &m.name))
        || config.txt_records.iter().any(|t| hostname_issubdomain(name, &t.name))
        || config.ptr_records.iter().any(|p| hostname_issubdomain(name, &p.name))
        || config.host_records.iter().any(|h| {
            h.names.iter().any(|n| hostname_issubdomain(name, n))
        })
}

/// Rewrite A-record addresses in `packet.answers` according to `doctors`.
///
/// Returns `true` if any rewrite was performed.  Clears the AA flag on the
/// header when a rewrite happens (data is no longer authoritative).
pub fn do_doctor(packet: &mut DnsPacket, doctors: &[Doctor]) -> bool {
    if doctors.is_empty() { return false; }
    let mut done = false;
    for rr in &mut packet.answers {
        if rr.class != 1 || rr.rtype != 1 || rr.rdata.len() < 4 { continue; }
        let ip = u32::from_be_bytes([rr.rdata[0], rr.rdata[1], rr.rdata[2], rr.rdata[3]]);
        for doctor in doctors {
            let in_u32  = u32::from_be_bytes(doctor.in_addr.octets());
            let end_u32 = u32::from_be_bytes(doctor.end_addr.octets());
            let out_u32 = u32::from_be_bytes(doctor.out_addr.octets());
            let mask    = u32::from_be_bytes(doctor.mask.octets());
            let matches = if end_u32 == 0 {
                (ip & mask) == (in_u32 & mask)
            } else {
                ip >= in_u32 && ip <= end_u32
            };
            if matches {
                let new_ip = (ip & !mask) | (out_u32 & mask);
                let bytes = new_ip.to_be_bytes();
                rr.rdata[..4].copy_from_slice(&bytes);
                packet.header.hb3 &= !HB3_AA;
                done = true;
                break;
            }
        }
    }
    done
}

// ──────────────────────────────────────────────────────────────────────────────
// resize_packet: trim raw wire bytes and optionally re-attach EDNS0 OPT
// ──────────────────────────────────────────────────────────────────────────────

/// Trim a raw DNS packet to the actual end of its content and optionally
/// re-attach an EDNS0 OPT pseudo-header.
///
/// Port of C's `resize_packet()` from `rfc1035.c`.
///
/// * If the packet is malformed at any point, returns the original bytes
///   unchanged.
/// * If `edns_opt` is `Some(bytes)` **and** the current `arcount` is zero,
///   appends the bytes and sets `arcount = 1` in the returned packet.
pub fn resize_packet(pkt: &[u8], edns_opt: Option<&[u8]>) -> Vec<u8> {
    if pkt.len() < 12 {
        return pkt.to_vec();
    }
    let qdcount = u16::from_be_bytes([pkt[4],  pkt[5]])  as usize;
    let ancount = u16::from_be_bytes([pkt[6],  pkt[7]])  as usize;
    let nscount = u16::from_be_bytes([pkt[8],  pkt[9]])  as usize;
    let arcount = u16::from_be_bytes([pkt[10], pkt[11]]) as usize;

    let mut off = 12usize;

    // Skip questions: name + QTYPE(2) + QCLASS(2).
    for _ in 0..qdcount {
        if skip_name(pkt, &mut off).is_err() { return pkt.to_vec(); }
        if off + 4 > pkt.len()               { return pkt.to_vec(); }
        off += 4;
    }
    // Skip all resource records (answers + authority + additional).
    for _ in 0..(ancount + nscount + arcount) {
        if skip_name(pkt, &mut off).is_err()  { return pkt.to_vec(); }
        if off + 10 > pkt.len()               { return pkt.to_vec(); }
        let rdlen = u16::from_be_bytes([pkt[off + 8], pkt[off + 9]]) as usize;
        off += 10 + rdlen;
        if off > pkt.len()                    { return pkt.to_vec(); }
    }

    let mut result = pkt[..off].to_vec();

    // Re-attach the EDNS0 pseudo-header if provided and packet has no AR records.
    if let Some(opt) = edns_opt {
        if arcount == 0 {
            result.extend_from_slice(opt);
            // Update arcount field in the header.
            result[10] = 0x00;
            result[11] = 0x01;
        }
    }
    result
}


// ─────────────────────────────────────────────────────────────────────────────
// Name safety and TTL helpers (ported from rfc1035.c)
// ─────────────────────────────────────────────────────────────────────────────

/// Check if a domain name contains only printable ASCII characters.
///
/// Used to filter names before passing to external systems (uBus, conntrack).
/// Port of `safe_name()` from rfc1035.c:1137-1146.
pub fn safe_name(name: &str) -> bool {
    name.bytes().all(|b| b >= 0x20 && b < 0x7f)
}

/// Parse a TXT record payload into printable strings.
///
/// TXT records contain length-prefixed strings. Non-printable characters are
/// stripped. Returns the list of decoded strings.
/// Port of `log_txt()` from rfc1035.c:653-682.
pub fn parse_txt_record(data: &[u8]) -> Option<Vec<String>> {
    let mut result = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let len = data[pos] as usize;
        pos += 1;
        if pos + len > data.len() {
            return None; // bad packet
        }
        let s: String = data[pos..pos + len]
            .iter()
            .filter(|&&b| b >= 0x20 && b < 0x7f)
            .map(|&b| b as char)
            .collect();
        result.push(s);
        pos += len;
    }
    Some(result)
}

/// Check if a cache record is stale (TTL expired).
///
/// Returns true if the record is not immortal and its TTD is in the past.
/// Port of `crec_isstale()` from rfc1035.c:1565-1568.
pub fn crec_isstale(ttd: u64, immortal: bool, now: u64) -> bool {
    !immortal && ttd < now
}

/// Calculate the remaining TTL for a cache record.
///
/// Handles DHCP entries (configurable TTL), immortal entries (TTL in TTD field),
/// stale entries (0), and normal entries (clamped to max_ttl).
/// Port of `crec_ttl()` from rfc1035.c:1570-1601.
pub fn crec_ttl(ttd: u64, now: u64, flags: u32, max_ttl: u32, local_ttl: u32) -> u32 {
    use crate::types::constants::{F_DHCP, F_IMMORTAL};

    let ttl = if ttd >= now { (ttd - now) as i64 } else { -1 };

    // DHCP entries use configured TTL, capped by actual lease length
    if flags & F_DHCP != 0 {
        let conf_ttl = local_ttl;
        if flags & F_IMMORTAL == 0 && (ttl >= 0) && (ttl as u32) < conf_ttl {
            return ttl as u32;
        }
        return conf_ttl;
    }

    // Immortal entries (local records) hold TTL in TTD field
    if flags & F_IMMORTAL != 0 {
        return ttd as u32;
    }

    // Stale
    if ttl < 0 {
        return 0;
    }

    // Clamp to max_ttl if configured
    if max_ttl == 0 || (ttl as u32) < max_ttl {
        ttl as u32
    } else {
        max_ttl
    }
}

mod tests {
    use super::*;
    use crate::dns_protocol::{HB3_QR, HB3_RD, HB4_RA};

    // ── helper ────────────────────────────────────────────────────────────────

    /// Wire bytes for a standard query: `example.com IN A`
    fn query_bytes() -> Vec<u8> {
        let mut pkt = vec![
            0x12, 0x34, // ID
            HB3_RD, 0x00, // flags: RD=1, QR=0
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, // ANCOUNT=0
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00, // ARCOUNT=0
        ];
        // QNAME: \x07example\x03com\x00
        pkt.extend_from_slice(b"\x07example\x03com\x00");
        pkt.extend_from_slice(&[0x00, 0x01]); // QTYPE=A
        pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
        pkt
    }

    /// Wire bytes for a response to the query above, with one A-record answer.
    /// The answer name uses pointer compression back to the question name at
    /// offset 12 (`0xC0 0x0C`).
    fn response_bytes() -> Vec<u8> {
        let mut pkt = vec![
            0x12, 0x34,           // ID
            HB3_QR | HB3_RD, HB4_RA, // flags: QR=1, RD=1, RA=1
            0x00, 0x01,           // QDCOUNT=1
            0x00, 0x01,           // ANCOUNT=1
            0x00, 0x00,           // NSCOUNT=0
            0x00, 0x00,           // ARCOUNT=0
        ];
        // Question (same as above)
        pkt.extend_from_slice(b"\x07example\x03com\x00");
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        // Answer: compressed name, TYPE A, CLASS IN, TTL 300, RDATA 93.184.216.34
        pkt.extend_from_slice(&[0xC0, 0x0C]); // pointer → offset 12
        pkt.extend_from_slice(&[0x00, 0x01]); // TYPE A
        pkt.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        pkt.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // TTL 300
        pkt.extend_from_slice(&[0x00, 0x04]); // RDLENGTH 4
        pkt.extend_from_slice(&[93, 184, 216, 34]); // 93.184.216.34
        pkt
    }

    // ── parse a real A-record query ───────────────────────────────────────────

    #[test]
    fn parse_a_query() {
        let pkt = query_bytes();
        let dp = DnsPacket::parse(&pkt).expect("parse failed");
        assert_eq!(dp.header.id, 0x1234);
        assert!(dp.header.is_query());
        assert!(dp.header.is_rd());
        assert_eq!(dp.questions.len(), 1);
        let q = &dp.questions[0];
        assert_eq!(q.name, "example.com");
        assert_eq!(q.rrtype(), Some(RrType::A));
        assert!(dp.answers.is_empty());
    }

    // ── parse a real A-record response ────────────────────────────────────────

    #[test]
    fn parse_a_response() {
        let pkt = response_bytes();
        let dp = DnsPacket::parse(&pkt).expect("parse failed");
        assert!(dp.header.is_response());
        assert_eq!(dp.questions.len(), 1);
        assert_eq!(dp.answers.len(), 1);

        let q = &dp.questions[0];
        assert_eq!(q.name, "example.com");
        assert_eq!(q.rrtype(), Some(RrType::A));

        let rr = &dp.answers[0];
        assert_eq!(rr.name, "example.com"); // pointer was followed
        assert_eq!(rr.rrtype(), Some(RrType::A));
        assert_eq!(rr.ttl, 300);
        assert_eq!(rr.rdata, vec![93, 184, 216, 34]);
    }

    // ── roundtrip: write → parse yields the same data ─────────────────────────

    #[test]
    fn roundtrip_packet() {
        let original = DnsPacket::parse(&response_bytes()).unwrap();
        let wire = original.write();
        let parsed = DnsPacket::parse(&wire).expect("re-parse failed");

        assert_eq!(parsed.header.id, original.header.id);
        assert_eq!(parsed.questions.len(), original.questions.len());
        assert_eq!(parsed.answers.len(), original.answers.len());

        assert_eq!(parsed.questions[0].name, original.questions[0].name);
        assert_eq!(parsed.questions[0].qtype, original.questions[0].qtype);

        let orig_rr = &original.answers[0];
        let rt_rr = &parsed.answers[0];
        assert_eq!(rt_rr.name, orig_rr.name);
        assert_eq!(rt_rr.rtype, orig_rr.rtype);
        assert_eq!(rt_rr.ttl, orig_rr.ttl);
        assert_eq!(rt_rr.rdata, orig_rr.rdata);
    }

    // ── in_arpa_name_2_addr ───────────────────────────────────────────────────

    #[test]
    fn arpa_ipv4() {
        let addr = in_arpa_name_2_addr("34.216.184.93.in-addr.arpa").unwrap();
        assert_eq!(addr.as_ipv4(), Some(Ipv4Addr::new(93, 184, 216, 34)));
    }

    #[test]
    fn arpa_ipv4_trailing_dot() {
        let addr = in_arpa_name_2_addr("1.0.168.192.in-addr.arpa.").unwrap();
        assert_eq!(addr.as_ipv4(), Some(Ipv4Addr::new(192, 168, 0, 1)));
    }

    #[test]
    fn arpa_ipv6() {
        // 2001:db8::1
        let name = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0\
                    .0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa";
        let addr = in_arpa_name_2_addr(name).unwrap();
        let expected: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(addr.as_ipv6(), Some(expected));
    }

    #[test]
    fn arpa_invalid_returns_none() {
        assert!(in_arpa_name_2_addr("not-arpa.example.com").is_none());
        assert!(in_arpa_name_2_addr("1.2.3.in-addr.arpa").is_none()); // only 3 parts
    }

    // ── private_net ───────────────────────────────────────────────────────────

    #[test]
    fn private_net_rfc1918() {
        // 10/8
        assert!(private_net(Ipv4Addr::new(10, 0, 0, 1), false));
        assert!(private_net(Ipv4Addr::new(10, 255, 255, 255), false));
        // 172.16/12
        assert!(private_net(Ipv4Addr::new(172, 16, 0, 1), false));
        assert!(private_net(Ipv4Addr::new(172, 31, 255, 255), false));
        // 192.168/16
        assert!(private_net(Ipv4Addr::new(192, 168, 1, 1), false));
        // link-local
        assert!(private_net(Ipv4Addr::new(169, 254, 1, 1), false));
    }

    #[test]
    fn private_net_not_private() {
        assert!(!private_net(Ipv4Addr::new(8, 8, 8, 8), false));
        assert!(!private_net(Ipv4Addr::new(93, 184, 216, 34), false));
        assert!(!private_net(Ipv4Addr::new(172, 32, 0, 1), false)); // just outside /12
    }

    #[test]
    fn private_net_loopback() {
        assert!(!private_net(Ipv4Addr::new(127, 0, 0, 1), false)); // not blocked when false
        assert!(private_net(Ipv4Addr::new(127, 0, 0, 1), true)); // blocked when true
    }

    // ── private_net6 ─────────────────────────────────────────────────────────

    #[test]
    fn private_net6_ula() {
        let ula: Ipv6Addr = "fd00::1".parse().unwrap();
        assert!(private_net6(&ula, false));
        let ula2: Ipv6Addr = "fc00::1".parse().unwrap();
        assert!(private_net6(&ula2, false));
    }

    #[test]
    fn private_net6_link_local() {
        let ll: Ipv6Addr = "fe80::1".parse().unwrap();
        assert!(private_net6(&ll, false));
    }

    #[test]
    fn private_net6_loopback() {
        assert!(!private_net6(&Ipv6Addr::LOCALHOST, false));
        assert!(private_net6(&Ipv6Addr::LOCALHOST, true));
    }

    #[test]
    fn private_net6_public() {
        let public: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(!private_net6(&public, false));
        assert!(!private_net6(&public, true));
    }

    // ── extract_name error cases ──────────────────────────────────────────────

    #[test]
    fn extract_name_truncated_label() {
        // Claim a 7-byte label but the packet is too short.
        let pkt = [0x07u8, b'e', b'x', b'a']; // only 3 bytes of a 7-byte label
        let mut off = 0;
        assert!(matches!(
            extract_name(&pkt, &mut off),
            Err(DnsError::UnexpectedEof)
        ));
    }

    #[test]
    fn extract_name_empty_packet() {
        let pkt: [u8; 0] = [];
        let mut off = 0;
        assert!(matches!(
            extract_name(&pkt, &mut off),
            Err(DnsError::UnexpectedEof)
        ));
    }

    #[test]
    fn extract_name_compression_loop() {
        // Two pointers that point at each other: offset 0 → offset 2 → offset 0 …
        let pkt = [0xC0u8, 0x02, 0xC0, 0x00];
        let mut off = 0;
        assert!(matches!(
            extract_name(&pkt, &mut off),
            Err(DnsError::CompressionLoop)
        ));
    }

    #[test]
    fn extract_name_pointer_out_of_bounds() {
        // Pointer targets offset 100 but packet is only 4 bytes.
        let pkt = [0xC0u8, 0x64, 0x00, 0x00];
        let mut off = 0;
        assert!(matches!(
            extract_name(&pkt, &mut off),
            Err(DnsError::InvalidName(_))
        ));
    }

    // ── extract_request ───────────────────────────────────────────────────────

    #[test]
    fn extract_request_ok() {
        let pkt = query_bytes();
        let (name, rtype) = extract_request(&pkt).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(rtype, RrType::A);
    }

    #[test]
    fn extract_request_no_questions() {
        // A packet with QDCOUNT=0.
        let mut pkt = query_bytes();
        pkt[4] = 0x00;
        pkt[5] = 0x00;
        assert!(extract_request(&pkt).is_none());
    }

    // ── write_name / skip_name ────────────────────────────────────────────────

    #[test]
    fn write_name_roundtrip() {
        let mut buf = BytesMut::new();
        write_name(&mut buf, "www.example.com");
        let mut off = 0;
        let name = extract_name(&buf, &mut off).unwrap();
        assert_eq!(name, "www.example.com");
        assert_eq!(off, buf.len()); // consumed everything
    }

    #[test]
    fn write_name_root() {
        let mut buf = BytesMut::new();
        write_name(&mut buf, "");
        assert_eq!(&buf[..], &[0x00]);
    }

    #[test]
    fn skip_name_advances_correctly() {
        // Build: \x07example\x03com\x00 then sentinel byte 0xFF.
        let mut buf = BytesMut::new();
        write_name(&mut buf, "example.com");
        buf.put_u8(0xFF);
        let mut off = 0;
        skip_name(&buf, &mut off).unwrap();
        assert_eq!(buf[off], 0xFF);
    }

    // ── extract_addresses ─────────────────────────────────────────────────────

    use crate::cache::DnsCache;
    use crate::types::constants::{F_FORWARD, F_IPV4, F_IPV6, F_CNAME, F_NEG, F_NXDOMAIN, F_REVERSE};

    /// Build a minimal DNS reply header (12 bytes) with the given rcode.
    fn reply_header(id: u16, qd: u16, an: u16, ns: u16, rcode: u8) -> Vec<u8> {
        let mut v = vec![
            (id >> 8) as u8, id as u8,
            0x84, rcode, // QR=1, AA=1, rcode
            (qd >> 8) as u8, qd as u8,
            (an >> 8) as u8, an as u8,
            (ns >> 8) as u8, ns as u8,
            0x00, 0x00,
        ];
        v
    }

    /// Append a DNS question section for `name` IN `qtype`.
    fn push_question(buf: &mut Vec<u8>, name: &str, qtype: u16) {
        let mut bm = BytesMut::new();
        write_name(&mut bm, name);
        buf.extend_from_slice(&bm);
        buf.extend_from_slice(&qtype.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x01]); // class IN
    }

    /// Append a DNS resource record for `name` IN `rtype` with the given rdata.
    fn push_rr(buf: &mut Vec<u8>, name: &str, rtype: u16, ttl: u32, rdata: &[u8]) {
        let mut bm = BytesMut::new();
        write_name(&mut bm, name);
        buf.extend_from_slice(&bm);
        buf.extend_from_slice(&rtype.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x01]); // class IN
        buf.extend_from_slice(&ttl.to_be_bytes());
        buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        buf.extend_from_slice(rdata);
    }

    #[test]
    fn extract_a_record() {
        // Build: example.com IN A → 93.184.216.34, TTL 300
        let mut pkt = reply_header(1, 1, 1, 0, 0);
        push_question(&mut pkt, "example.com", 1);
        push_rr(&mut pkt, "example.com", 1, 300, &[93, 184, 216, 34]);
        let dp = DnsPacket::parse(&pkt).unwrap();

        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        let result = extract_addresses(&dp, &mut cache, now, &ExtractConfig::default());
        assert_eq!(result, ExtractResult::Cached);

        let rec = cache.lookup_by_name("example.com", F_IPV4, now).expect("A record not cached");
        assert_eq!(rec.addr.as_ref().unwrap().as_ipv4(), Some(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(rec.ttl, 300);
        assert!(rec.flags & F_FORWARD != 0);
    }

    #[test]
    fn extract_aaaa_record() {
        let ip6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let mut pkt = reply_header(2, 1, 1, 0, 0);
        push_question(&mut pkt, "example.com", 28);
        push_rr(&mut pkt, "example.com", 28, 600, &ip6.octets());
        let dp = DnsPacket::parse(&pkt).unwrap();

        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        assert_eq!(
            extract_addresses(&dp, &mut cache, now, &ExtractConfig::default()),
            ExtractResult::Cached
        );
        let rec = cache.lookup_by_name("example.com", F_IPV6, now).unwrap();
        assert_eq!(rec.addr.as_ref().unwrap().as_ipv6(), Some(ip6));
    }

    #[test]
    fn extract_cname_chain() {
        // www.example.com CNAME → example.com, then example.com A → 1.2.3.4
        let mut bm = BytesMut::new();
        write_name(&mut bm, "example.com");
        let cname_rdata = bm.to_vec();

        let mut pkt = reply_header(3, 1, 2, 0, 0);
        push_question(&mut pkt, "www.example.com", 1);
        push_rr(&mut pkt, "www.example.com", 5, 60, &cname_rdata);  // CNAME
        push_rr(&mut pkt, "example.com", 1, 300, &[1, 2, 3, 4]);    // A

        let dp = DnsPacket::parse(&pkt).unwrap();
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        assert_eq!(
            extract_addresses(&dp, &mut cache, now, &ExtractConfig::default()),
            ExtractResult::Cached
        );

        // CNAME record must be in cache
        assert!(cache.lookup_by_name("www.example.com", F_CNAME, now).is_some(), "CNAME not cached");

        // Terminal A record for the CNAME target must be in cache
        let rec = cache.lookup_by_name("example.com", F_IPV4, now).unwrap();
        assert_eq!(rec.addr.as_ref().unwrap().as_ipv4(), Some(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn extract_ptr_record() {
        // 34.216.184.93.in-addr.arpa PTR → example.com
        let ptr_name = "34.216.184.93.in-addr.arpa";
        let mut bm = BytesMut::new();
        write_name(&mut bm, "example.com");

        let mut pkt = reply_header(4, 1, 1, 0, 0);
        push_question(&mut pkt, ptr_name, 12);
        push_rr(&mut pkt, ptr_name, 12, 120, &bm);

        let dp = DnsPacket::parse(&pkt).unwrap();
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        assert_eq!(
            extract_addresses(&dp, &mut cache, now, &ExtractConfig::default()),
            ExtractResult::Cached
        );

        // PTR stores the hostname with F_REVERSE and the IP as the address.
        let rec = cache.lookup_by_name("example.com", F_IPV4 | F_REVERSE, now).expect("PTR record not cached");
        assert_eq!(
            rec.addr.as_ref().unwrap().as_ipv4(),
            Some(Ipv4Addr::new(93, 184, 216, 34))
        );
    }

    #[test]
    fn extract_nxdomain_cached() {
        // Build an NXDOMAIN reply with a SOA in authority (minimum TTL = 300).
        // SOA rdata: mname=ns.example.com, rname=admin.example.com, then 5 u32s.
        let mut soa_rdata = BytesMut::new();
        write_name(&mut soa_rdata, "ns.example.com");
        write_name(&mut soa_rdata, "admin.example.com");
        soa_rdata.put_u32(1);   // serial
        soa_rdata.put_u32(3600); // refresh
        soa_rdata.put_u32(900);  // retry
        soa_rdata.put_u32(86400); // expire
        soa_rdata.put_u32(300);  // minimum TTL

        // Header: QR=1, AA=1, RCODE=3 (NXDOMAIN), QDCOUNT=1, NSCOUNT=1
        let mut pkt = vec![
            0x00, 0x05,       // ID
            0x84, 0x03,       // QR=1, AA=1, RCODE=NXDOMAIN
            0x00, 0x01,       // QDCOUNT=1
            0x00, 0x00,       // ANCOUNT=0
            0x00, 0x01,       // NSCOUNT=1
            0x00, 0x00,       // ARCOUNT=0
        ];
        push_question(&mut pkt, "noexist.example.com", 1);
        push_rr(&mut pkt, "example.com", 6, 600, &soa_rdata); // SOA in authority

        let dp = DnsPacket::parse(&pkt).unwrap();
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        assert_eq!(
            extract_addresses(&dp, &mut cache, now, &ExtractConfig::default()),
            ExtractResult::Cached
        );

        let rec = cache.lookup_by_name("noexist.example.com", F_NXDOMAIN | F_NEG, now).expect("NXDOMAIN not cached");
        assert_eq!(rec.ttl, 300); // clamp to SOA minimum
    }

    #[test]
    fn extract_rebind_blocked() {
        // Reply with a private address should be rejected when check_rebind = true.
        let mut pkt = reply_header(6, 1, 1, 0, 0);
        push_question(&mut pkt, "evil.example.com", 1);
        push_rr(&mut pkt, "evil.example.com", 1, 300, &[192, 168, 1, 1]);

        let dp = DnsPacket::parse(&pkt).unwrap();
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        let cfg = ExtractConfig { check_rebind: true, ..Default::default() };
        assert_eq!(
            extract_addresses(&dp, &mut cache, now, &cfg),
            ExtractResult::RebindBlocked
        );
        // Nothing should be cached.
        assert_eq!(cache.inserts, 0);
    }

    #[test]
    fn extract_max_ttl_clamped() {
        let mut pkt = reply_header(7, 1, 1, 0, 0);
        push_question(&mut pkt, "example.com", 1);
        push_rr(&mut pkt, "example.com", 1, 86400, &[1, 2, 3, 4]);

        let dp = DnsPacket::parse(&pkt).unwrap();
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        let cfg = ExtractConfig { max_ttl: 3600, ..Default::default() };
        extract_addresses(&dp, &mut cache, now, &cfg);

        let rec = cache.lookup_by_name("example.com", F_IPV4, now).unwrap();
        assert_eq!(rec.ttl, 3600); // clamped from 86400
    }

    // ── setup_reply ───────────────────────────────────────────────────────────

    #[test]
    fn test_setup_reply_nxdomain() {
        use crate::dns_protocol::HB3_QR;
        let mut h = DnsHeader::default();
        setup_reply(&mut h, F_NXDOMAIN);
        assert_eq!(h.rcode(), 3);
        assert!(h.hb3 & HB3_QR != 0, "QR must be set");
    }

    #[test]
    fn test_setup_reply_noerror_auth() {
        use crate::dns_protocol::{HB3_AA, HB3_QR};
        let mut h = DnsHeader::default();
        setup_reply(&mut h, F_IPV4);
        assert_eq!(h.rcode(), 0);
        assert!(h.hb3 & HB3_QR != 0, "QR must be set");
        assert!(h.hb3 & HB3_AA != 0, "AA must be set for F_IPV4");
    }

    // ── answer_request ────────────────────────────────────────────────────────

    fn make_query(name: &str, qtype: u16) -> DnsPacket {
        let mut buf = BytesMut::new();
        let mut h = DnsHeader::default();
        h.qdcount = 1;
        buf.put_slice(&h.to_bytes());
        write_name(&mut buf, name);
        buf.put_u16(qtype);
        buf.put_u16(1); // IN
        DnsPacket::parse(&buf).unwrap()
    }

    fn empty_config<'a>() -> LocalConfig<'a> {
        LocalConfig {
            local_ttl:    60,
            txt_records:  &[],
            rr_records:   &[],
            mx_records:   &[],
            ptr_records:  &[],
            host_records: &[],
            cnames:       &[],
            naptr_records: &[],
        }
    }

    #[test]
    fn test_answer_request_a_from_host_records() {
        use crate::types::dns_records::HostRecord;
        let hr = HostRecord {
            ttl:   60,
            flags: 0,
            names: vec!["myhost.local".into()],
            addr4: Some(Ipv4Addr::new(10, 0, 0, 1)),
            addr6: None,
        };
        let cfg = LocalConfig { host_records: std::slice::from_ref(&hr), ..empty_config() };
        let query = make_query("myhost.local", 1);
        let mut cache = DnsCache::new(100);
        let resp = answer_request(&query, &mut cache, Instant::now(), &cfg)
            .expect("should answer from host_records");
        assert_eq!(resp.answers.len(), 1);
        let rr = &resp.answers[0];
        assert_eq!(rr.rtype, 1);
        assert_eq!(rr.rdata, vec![10, 0, 0, 1]);
        assert!(resp.header.is_aa(), "AA should be set for host_records answer");
    }

    #[test]
    fn test_answer_request_mx() {
        use crate::types::dns_records::MxSrvRecord;
        let mx = MxSrvRecord {
            name:     "example.com".into(),
            target:   "mail.example.com".into(),
            is_srv:   false,
            srv_port: 0,
            priority: 10,
            weight:   0,
            offset:   0,
        };
        let cfg = LocalConfig { mx_records: std::slice::from_ref(&mx), ..empty_config() };
        let query = make_query("example.com", 15);
        let mut cache = DnsCache::new(100);
        let resp = answer_request(&query, &mut cache, Instant::now(), &cfg)
            .expect("should answer MX");
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(resp.answers[0].rtype, 15);
        let pref = u16::from_be_bytes([resp.answers[0].rdata[0], resp.answers[0].rdata[1]]);
        assert_eq!(pref, 10);
    }

    #[test]
    fn test_answer_request_nxdomain_from_cache() {
        use crate::cache::CacheRecord;
        let now = Instant::now();
        let mut cache = DnsCache::new(100);
        cache.insert(CacheRecord {
            name:    "noexist.local".into(),
            flags:   F_NXDOMAIN | F_NEG,
            ttl:     300,
            expires: now + std::time::Duration::from_secs(300),
            addr:    None,
            rdata:   None,
            uid:     crate::types::constants::UID_NONE,
        });
        let cfg   = empty_config();
        let query = make_query("noexist.local", 1);
        let resp  = answer_request(&query, &mut cache, now, &cfg)
            .expect("should return NXDOMAIN response");
        assert_eq!(resp.header.rcode(), 3);
    }

    #[test]
    fn test_answer_request_no_match_returns_none() {
        let cfg   = empty_config();
        let query = make_query("unknown.example.com", 1);
        let mut cache = DnsCache::new(100);
        let resp = answer_request(&query, &mut cache, Instant::now(), &cfg);
        assert!(resp.is_none(), "unknown name should return None");
    }

    #[test]
    fn test_answer_request_txt() {
        use crate::types::dns_records::TxtRecord;
        let txt = TxtRecord {
            name:  "example.com".into(),
            txt:   b"v=spf1 ~all".to_vec(),
            class: 1,
            stat:  0,
        };
        let cfg   = LocalConfig { txt_records: std::slice::from_ref(&txt), ..empty_config() };
        let query = make_query("example.com", 16);
        let mut cache = DnsCache::new(100);
        let resp = answer_request(&query, &mut cache, Instant::now(), &cfg)
            .expect("should answer TXT");
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(resp.answers[0].rtype, 16);
        assert_eq!(resp.answers[0].rdata, b"v=spf1 ~all".to_vec());
    }

    // ── check helpers ─────────────────────────────────────────────────────────

    use crate::types::dns_records::{BogusAddr, Doctor};

    #[test]
    fn hostname_issubdomain_eq_and_sub() {
        assert!(hostname_issubdomain("example.com", "example.com"));
        assert!(hostname_issubdomain("www.example.com", "example.com"));
        assert!(!hostname_issubdomain("notexample.com", "example.com"));
        assert!(!hostname_issubdomain("other.com", "example.com"));
    }

    #[test]
    fn check_for_local_domain_matches() {
        let hr = HostRecord {
            ttl: -1, flags: 0,
            names: vec!["myhost.local".into()],
            addr4: Some(Ipv4Addr::new(1, 2, 3, 4)),
            addr6: None,
        };
        let cfg = LocalConfig { host_records: std::slice::from_ref(&hr), ..empty_config() };
        assert!(check_for_local_domain("myhost.local", &cfg));
        assert!(check_for_local_domain("sub.myhost.local", &cfg));
        assert!(!check_for_local_domain("other.example.com", &cfg));
    }

    #[test]
    fn do_doctor_rewrites_a_record() {
        // Doctor rule: rewrite 192.168.1.0/24 → 10.0.0.0/24 (mask /24)
        let doctor = Doctor {
            in_addr:  Ipv4Addr::new(192, 168, 1, 0),
            end_addr: Ipv4Addr::new(0, 0, 0, 0), // 0 = use subnet
            out_addr: Ipv4Addr::new(10, 0, 0, 0),
            mask:     Ipv4Addr::new(255, 255, 255, 0),
        };
        let mut pkt = reply_header(10, 1, 1, 0, 0);
        push_question(&mut pkt, "h.test", 1);
        push_rr(&mut pkt, "h.test", 1, 60, &[192, 168, 1, 5]);
        let mut dp = DnsPacket::parse(&pkt).unwrap();
        assert!(do_doctor(&mut dp, std::slice::from_ref(&doctor)));
        // host octet preserved (5), network bits rewritten → 10.0.0.5
        assert_eq!(dp.answers[0].rdata, vec![10, 0, 0, 5]);
        assert_eq!(dp.header.hb3 & 0x04, 0); // AA cleared
    }

    #[test]
    fn do_doctor_no_match() {
        let doctor = Doctor {
            in_addr:  Ipv4Addr::new(10, 0, 0, 0),
            end_addr: Ipv4Addr::new(0, 0, 0, 0),
            out_addr: Ipv4Addr::new(172, 16, 0, 0),
            mask:     Ipv4Addr::new(255, 0, 0, 0),
        };
        let mut pkt = reply_header(11, 1, 1, 0, 0);
        push_question(&mut pkt, "h.test", 1);
        push_rr(&mut pkt, "h.test", 1, 60, &[8, 8, 8, 8]);
        let mut dp = DnsPacket::parse(&pkt).unwrap();
        assert!(!do_doctor(&mut dp, std::slice::from_ref(&doctor)));
        assert_eq!(dp.answers[0].rdata, vec![8, 8, 8, 8]); // unchanged
    }

    #[test]
    fn check_bogus_wildcard_caches_nxdomain() {
        let ba = BogusAddr {
            is6: false,
            prefix: 32,
            addr: AllAddr::Addr4(Ipv4Addr::new(1, 2, 3, 4)),
        };
        let mut pkt = reply_header(12, 1, 1, 0, 0);
        push_question(&mut pkt, "evil.example.com", 1);
        push_rr(&mut pkt, "evil.example.com", 1, 60, &[1, 2, 3, 4]);
        let dp = DnsPacket::parse(&pkt).unwrap();

        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        assert!(check_for_bogus_wildcard(&dp, &mut cache, now, std::slice::from_ref(&ba), 300));
        // NXDOMAIN entry should now be in cache
        let rec = cache.lookup_by_name("evil.example.com", F_NXDOMAIN | F_NEG, now);
        assert!(rec.is_some());
    }

    #[test]
    fn check_ignored_address_matches() {
        let ia = BogusAddr {
            is6: false,
            prefix: 24,
            addr: AllAddr::Addr4(Ipv4Addr::new(192, 0, 2, 0)),
        };
        let mut pkt = reply_header(13, 1, 1, 0, 0);
        push_question(&mut pkt, "h.test", 1);
        push_rr(&mut pkt, "h.test", 1, 60, &[192, 0, 2, 99]);
        let dp = DnsPacket::parse(&pkt).unwrap();
        assert!(check_for_ignored_address(&dp, std::slice::from_ref(&ia)));
    }

    #[test]
    fn check_ignored_address_no_match() {
        let ia = BogusAddr {
            is6: false,
            prefix: 32,
            addr: AllAddr::Addr4(Ipv4Addr::new(1, 2, 3, 4)),
        };
        let mut pkt = reply_header(14, 1, 1, 0, 0);
        push_question(&mut pkt, "h.test", 1);
        push_rr(&mut pkt, "h.test", 1, 60, &[8, 8, 8, 8]);
        let dp = DnsPacket::parse(&pkt).unwrap();
        assert!(!check_for_ignored_address(&dp, std::slice::from_ref(&ia)));
    }

    // ── resize_packet ─────────────────────────────────────────────────────────

    #[test]
    fn resize_packet_trims_to_end() {
        // Build a minimal A-record response and add trailing garbage bytes.
        let mut pkt = reply_header(15, 1, 1, 0, 0);
        push_question(&mut pkt, "example.com", 1);
        push_rr(&mut pkt, "example.com", 1, 300, &[1, 2, 3, 4]);
        let valid_len = pkt.len();
        pkt.extend_from_slice(&[0xFF, 0xFF, 0xFF]); // trailing garbage

        let result = resize_packet(&pkt, None);
        assert_eq!(result.len(), valid_len);
    }

    #[test]
    fn resize_packet_attaches_edns_when_no_ar() {
        // Simple query packet (arcount == 0).
        let pkt = query_bytes();
        // Fake EDNS0 OPT record: root name (0x00) + type OPT (41) + class 4096 + ttl 0 + rdlen 0
        let edns_opt: Vec<u8> = vec![
            0x00,                   // root name
            0x00, 0x29,             // TYPE OPT (41)
            0x10, 0x00,             // CLASS 4096 (UDP payload size)
            0x00, 0x00, 0x00, 0x00, // TTL (extended rcode + flags)
            0x00, 0x00,             // RDLENGTH 0
        ];
        let result = resize_packet(&pkt, Some(&edns_opt));
        // arcount should now be 1.
        let arcount = u16::from_be_bytes([result[10], result[11]]);
        assert_eq!(arcount, 1);
        // The EDNS OPT bytes should be at the end.
        assert!(result.ends_with(&edns_opt));
    }

    #[test]
    fn resize_packet_does_not_attach_when_ar_nonzero() {
        // Build a packet that already has 1 additional record.
        let mut pkt = reply_header(16, 1, 1, 0, 0);
        // Manually set arcount = 1 in header.
        pkt[10] = 0x00;
        pkt[11] = 0x01;
        push_question(&mut pkt, "example.com", 1);
        push_rr(&mut pkt, "example.com", 1, 60, &[1, 2, 3, 4]);
        push_rr(&mut pkt, "example.com", 1, 60, &[5, 6, 7, 8]); // the "additional"
        let original_len = pkt.len();

        let edns_opt = vec![0x00u8, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let result = resize_packet(&pkt, Some(&edns_opt));
        // No EDNS appended because arcount was already 1.
        assert_eq!(result.len(), original_len);
    }

    // ── safe_name ────────────────────────────────────────────────────────────

    #[test]
    fn safe_name_printable() {
        assert!(safe_name("example.com"));
        assert!(safe_name("hello world"));
    }

    #[test]
    fn safe_name_control_chars() {
        assert!(!safe_name("bad\x01name"));
        assert!(!safe_name("bad\x00name"));
    }

    #[test]
    fn safe_name_high_bytes() {
        assert!(!safe_name("café")); // non-ASCII
    }

    #[test]
    fn safe_name_empty() {
        assert!(safe_name("")); // empty is safe (no bad chars)
    }

    // ── parse_txt_record ─────────────────────────────────────────────────────

    #[test]
    fn parse_txt_record_single() {
        let data = [5, b'h', b'e', b'l', b'l', b'o'];
        let result = parse_txt_record(&data).unwrap();
        assert_eq!(result, vec!["hello"]);
    }

    #[test]
    fn parse_txt_record_multiple() {
        let data = [2, b'h', b'i', 3, b'b', b'y', b'e'];
        let result = parse_txt_record(&data).unwrap();
        assert_eq!(result, vec!["hi", "bye"]);
    }

    #[test]
    fn parse_txt_record_strips_control() {
        let data = [3, b'a', 0x01, b'b'];
        let result = parse_txt_record(&data).unwrap();
        assert_eq!(result, vec!["ab"]); // 0x01 stripped
    }

    #[test]
    fn parse_txt_record_bad_length() {
        let data = [10, b'x']; // claims 10 bytes but only 1 available
        assert!(parse_txt_record(&data).is_none());
    }

    #[test]
    fn parse_txt_record_empty() {
        let result = parse_txt_record(&[]).unwrap();
        assert!(result.is_empty());
    }

    // ── crec_isstale ─────────────────────────────────────────────────────────

    #[test]
    fn crec_isstale_expired() {
        assert!(crec_isstale(100, false, 200));
    }

    #[test]
    fn crec_isstale_not_expired() {
        assert!(!crec_isstale(200, false, 100));
    }

    #[test]
    fn crec_isstale_immortal_never_stale() {
        assert!(!crec_isstale(0, true, 999));
    }

    // ── crec_ttl ─────────────────────────────────────────────────────────────

    #[test]
    fn crec_ttl_normal() {
        use crate::types::constants::F_IMMORTAL;
        let ttl = crec_ttl(200, 100, 0, 0, 0);
        assert_eq!(ttl, 100);
    }

    #[test]
    fn crec_ttl_clamped_by_max() {
        let ttl = crec_ttl(1100, 100, 0, 300, 0);
        assert_eq!(ttl, 300); // max_ttl=300 < actual 1000
    }

    #[test]
    fn crec_ttl_stale() {
        let ttl = crec_ttl(50, 100, 0, 0, 0);
        assert_eq!(ttl, 0);
    }

    #[test]
    fn crec_ttl_immortal() {
        use crate::types::constants::F_IMMORTAL;
        let ttl = crec_ttl(3600, 100, F_IMMORTAL, 0, 0);
        assert_eq!(ttl, 3600); // TTD field holds TTL directly
    }

    #[test]
    fn crec_ttl_dhcp() {
        use crate::types::constants::F_DHCP;
        let ttl = crec_ttl(500, 100, F_DHCP, 0, 60);
        assert_eq!(ttl, 60); // local_ttl=60
    }

    #[test]
    fn crec_ttl_dhcp_capped_by_lease() {
        use crate::types::constants::F_DHCP;
        // Lease has 30s remaining but local_ttl=60 → cap at 30
        let ttl = crec_ttl(130, 100, F_DHCP, 0, 60);
        assert_eq!(ttl, 30);
    }
}


