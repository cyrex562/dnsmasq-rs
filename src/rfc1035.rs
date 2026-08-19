//! DNS packet parser — Rust port of dnsmasq's `rfc1035.c`.
//!
//! Provides wire-format encode/decode for DNS messages: names, questions,
//! resource records, and full packets.  No `unsafe` code; no C FFI.

use bytes::{BufMut, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use crate::cache::{CacheRecord, DnsCache};
use crate::types::constants::UID_NONE;
use crate::dns_protocol::{DnsHeader, RrType, HB3_AA, HB3_QR, HB3_TC, HB4_AD, HB4_CD, HB4_RA};
use crate::types::addr::{AllAddr, CnameAddr, RrBlockAddr, RrDataAddr};
use crate::types::constants::{
    F_CNAME, F_DNSSECOK, F_FORWARD, F_IPV4, F_IPV6, F_KEYTAG, F_NEG, F_NOERR, F_NXDOMAIN, F_RCODE,
    F_REVERSE, F_RR,
};
use crate::types::dns_records::{
    BogusAddr, Cname, Doctor, HostRecord, InterfaceName, MxSrvRecord, Naptr, PtrRecord, TxtRecord,
};
use crate::types::network::Ipsets;
use crate::domain::CondDomain;

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
    /// `--rebind-localhost-ok` (`OPT_LOCAL_REBIND`): exempt `127.0.0.0/8` and
    /// `::1` from the rebind check.  C passes the negation of this option as
    /// `private_net()`'s `ban_localhost` argument (`rfc1035.c:997,1001`).
    pub local_rebind_ok: bool,
    /// Suppress negative caching entirely.
    pub no_neg_cache: bool,
    /// The reply was DNSSEC-validated; set `F_DNSSECOK` on cached records.
    pub secure: bool,
    /// `--cache-rr` (`daemon->cache_rr`): RR types, beyond the always-cached
    /// `T_SRV`/`T_PTR`, that may be cached via the `F_RR` fallback.  A `T_ANY`
    /// (255) entry on this list means "cache every RR type" (`rfc1035.c:801`).
    pub cache_rr: Vec<u16>,
    /// `--ipset` (`daemon->ipsets`): domain-suffix → set-name mappings.
    /// [`extract_addresses`] matches the query name against this list once
    /// (mirroring `domain_find_sets(daemon->ipsets, ...)` at `forward.c:713`)
    /// and reports every A/AAAA address extracted for the matched entry's set
    /// names via [`ExtractOutcome::ipset_hits`]. Actually adding the address to
    /// the kernel ipset is not yet implemented — see `tasks.md`.
    pub ipsets: Vec<Ipsets>,
}

impl Default for ExtractConfig {
    fn default() -> Self {
        Self {
            max_ttl: 0,
            neg_ttl: 0,
            check_rebind: false,
            local_rebind_ok: false,
            no_neg_cache: false,
            secure: false,
            cache_rr: Vec::new(),
            ipsets: Vec::new(),
        }
    }
}

/// An address extracted by [`extract_addresses`] that matched a configured
/// `--ipset`/`--nftset` domain entry (`rfc1035.c:1009-1028`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpsetHit {
    pub set_name: String,
    pub addr:     IpAddr,
}

/// Find the most-specific [`Ipsets`] entry whose `domain` suffix matches `name`.
///
/// Same longest-suffix-match algorithm as upstream's `domain_find_sets()`
/// (`forward.c:674-690`). A duplicate of [`crate::forward::domain_find_sets`],
/// which operates on the unrelated `crate::forward::IpSet` type that nothing
/// currently constructs from parsed config — see `tasks.md` for unifying them.
fn domain_find_sets<'a>(setlist: &'a [Ipsets], name: &str) -> Option<&'a Ipsets> {
    let namelen = name.len();
    let mut matchlen: usize = 0;
    let mut result: Option<&Ipsets> = None;

    for entry in setlist {
        let domainlen = entry.domain.len();
        if namelen >= domainlen {
            let matchstart = namelen - domainlen;
            let suffix = &name[matchstart..];
            let boundary_ok = domainlen == 0
                || namelen == domainlen
                || name.as_bytes().get(matchstart.wrapping_sub(1)) == Some(&b'.');
            if suffix.eq_ignore_ascii_case(&entry.domain) && boundary_ok && domainlen >= matchlen {
                matchlen = domainlen;
                result = Some(entry);
            }
        }
    }
    result
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

/// Full return value of [`extract_addresses`]: the cache outcome plus any
/// `--ipset`/`--nftset` matches found along the way.
#[derive(Debug, Clone)]
pub struct ExtractOutcome {
    pub result: ExtractResult,
    /// Addresses extracted for a query name that matched a configured
    /// `--ipset`/`--nftset` domain entry (`rfc1035.c:1009-1028`). Actually
    /// adding these to the kernel set is not yet implemented — see `tasks.md`.
    pub ipset_hits: Vec<IpsetHit>,
}

/// Lets every existing `assert_eq!(extract_addresses(...), ExtractResult::X)`
/// call keep comparing against the bare result, without threading
/// `ipset_hits` through call sites that don't care about it.
impl PartialEq<ExtractResult> for ExtractOutcome {
    fn eq(&self, other: &ExtractResult) -> bool {
        self.result == *other
    }
}

/// Maximum CNAME chain depth we will follow in a single reply.
const CNAME_CHAIN_LIMIT: usize = 10;

/// Clamp `ttl` to `max_ttl` when `max_ttl > 0`.
fn clamp_ttl(ttl: u32, max_ttl: u32) -> u32 {
    if max_ttl != 0 && ttl > max_ttl { max_ttl } else { ttl }
}

/// A SOA record found by [`find_soa`] whose owner name covers the queried name.
struct SoaMatch {
    /// RFC 2308 negative-cache TTL: `min(rr.ttl, minimum)`.
    neg_ttl: u32,
    /// The SOA's own (lower-cased) owner name — a suffix of the queried name.
    owner:   String,
    /// The SOA RR's own TTL, *not* capped by `minimum` — this is what C caches
    /// the SOA record itself under (`rfc1035.c:620`); the RFC 2308 capping only
    /// applies to the derived negative-cache TTL.
    rr_ttl:  u32,
    /// Wire-format MNAME + RNAME + the 20 raw bytes (SERIAL/REFRESH/RETRY/
    /// EXPIRE/MINIMUM), matching the blockdata C builds at `rfc1035.c:567-607`
    /// so the SOA RR itself can be cached as `F_RR`.
    rdata:   Vec<u8>,
}

/// Find the SOA record in `authority` whose owner name is `name` itself or a
/// byte suffix of it, and compute the RFC 2308 negative-cache TTL.
///
/// Port of `find_soa()` (`rfc1035.c:519-650`). Upstream's suffix test is a raw
/// byte `memcmp` (`rfc1035.c:554-556`), not a dot-boundary check — preserved
/// here rather than "fixed" to `hostname_issubdomain`, to match observed
/// upstream behavior exactly.
///
/// Unlike upstream, this always returns data for the SOA RR itself when a
/// name match is found. C conditionally skips caching the SOA
/// (`cache = cpp == NULL`, `rfc1035.c:1092`) purely to keep a pending CNAME
/// target's cache entry immediately adjacent to its CNAME in the hash-bucket
/// linked list C's cache relies on for lookup order; re-calling `find_soa()`
/// a second time afterwards (`rfc1035.c:1117`) to insert the SOA once that
/// ordering constraint no longer applies. [`DnsCache`] is a keyed map with no
/// such adjacency requirement (see [`extract_addresses`]'s `staged` buffer),
/// so the caller here can always stage the SOA record in one pass.
fn find_soa(name: &str, authority: &[DnsRr]) -> Option<SoaMatch> {
    let name_len = name.len();
    for rr in authority {
        if rr.rtype != 6 /* SOA */ || rr.class != 1 /* IN */ {
            continue;
        }
        let owner = rr.name.to_lowercase();
        let soa_len = owner.len();
        // "SOA must be for the name we're interested in" (rfc1035.c:554-556).
        if soa_len > name_len || !name[name_len - soa_len..].eq_ignore_ascii_case(&owner) {
            continue;
        }

        // rdata layout: MNAME (wire-format labels) | RNAME (wire-format labels)
        // | serial(4) | refresh(4) | retry(4) | expire(4) | minimum(4).
        let mut pos = 0usize;
        let mname = extract_name(&rr.rdata, &mut pos).ok()?;
        let rname = extract_name(&rr.rdata, &mut pos).ok()?;
        if pos + 20 > rr.rdata.len() {
            return None; // bad packet, matching C's CHECK_LEN failure (rfc1035.c:589-594)
        }
        let minimum = u32::from_be_bytes([
            rr.rdata[pos + 16],
            rr.rdata[pos + 17],
            rr.rdata[pos + 18],
            rr.rdata[pos + 19],
        ]);

        let mut rdata = BytesMut::new();
        write_name(&mut rdata, &mname);
        write_name(&mut rdata, &rname);
        rdata.extend_from_slice(&rr.rdata[pos..pos + 20]);

        return Some(SoaMatch {
            neg_ttl: rr.ttl.min(minimum),
            owner,
            rr_ttl: rr.ttl,
            rdata: rdata.to_vec(),
        });
    }
    None
}

/// Commit the records staged by [`extract_addresses`], the way C commits its
/// `new_chain` list in `cache_end_insert()` (`rfc1035.c:1121-1128`).
///
/// Two header bits are tested there, and they behave very differently in
/// practice:
///
/// * `CD` set — the client asked to do its own validation, so the answer is not
///   ours to keep.  This is a live gate: the bit is the client's, echoed by the
///   upstream server.
/// * `RA` clear — "don't cache replies from non-recursive nameservers, since we
///   may get a reply containing a CNAME but not its target, even though the
///   target does exist".  This one is vestigial on the forwarding path, because
///   `process_reply()` sets `HB4_RA` on the reply (`forward.c:776`) before it
///   calls `extract_addresses()` (`forward.c:824`) — see
///   `forward::set_recursion_available`.  The test is kept here so this function
///   stays a faithful port for any caller that has *not* been through that step;
///   it is deliberately not what stops a non-recursive server's answers from
///   being cached, because upstream does cache them.
///
/// Staging is also what makes a bail-out leave *nothing* behind: C never reaches
/// `cache_end_insert()` when `extract_addresses()` returns 1 (rebind) or 2 (bad
/// packet), so the records it processed before the offending one are discarded
/// with it.
fn commit_staged(
    cache: &mut DnsCache,
    staged: Vec<CacheRecord>,
    header: &DnsHeader,
    now: Instant,
) {
    if header.hb4 & HB4_CD != 0 || header.hb4 & HB4_RA == 0 {
        return;
    }
    for rec in staged {
        cache.really_insert(rec, now);
    }
}

/// Extract DNS records from a parsed reply and insert them into `cache`.
///
/// This is the Rust port of `extract_addresses()` from `rfc1035.c`.
///
/// Handles A, AAAA, CNAME, PTR, and arbitrary RR types.
/// Performs negative caching for `NXDOMAIN` and `NODATA` replies.
///
/// Records are staged and only committed once the whole reply has been walked
/// successfully — see [`commit_staged`].
pub fn extract_addresses(
    packet: &DnsPacket,
    cache: &mut DnsCache,
    now: Instant,
    config: &ExtractConfig,
) -> ExtractOutcome {
    // Staged inserts, committed together at the end.  C builds the same list in
    // `new_chain` and commits it in `cache_end_insert()` (`rfc1035.c:1128`).
    let mut staged: Vec<CacheRecord> = Vec::new();
    let mut ipset_hits: Vec<IpsetHit> = Vec::new();

    let bad_packet = |ipset_hits| ExtractOutcome { result: ExtractResult::BadPacket, ipset_hits };
    let rebind_blocked =
        |ipset_hits| ExtractOutcome { result: ExtractResult::RebindBlocked, ipset_hits };
    let cached = |ipset_hits| ExtractOutcome { result: ExtractResult::Cached, ipset_hits };

    // Only process replies with exactly one question.
    if packet.questions.len() != 1 {
        return bad_packet(ipset_hits);
    }
    let q = &packet.questions[0];
    // Only cache IN (class 1) answers.
    if q.qclass != 1 {
        return cached(ipset_hits);
    }
    let header = &packet.header;

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
                    Err(_) => return bad_packet(ipset_hits),
                };
                let ttl = clamp_ttl(rr.ttl, config.max_ttl);
                staged.push(CacheRecord {
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
                commit_staged(cache, staged, header, now);
                return cached(ipset_hits);
            }
        }
        // For PTR queries with no PTR answer we do not cache a negative entry.
        return cached(ipset_hits);
    }

    // ── Forward lookup (A, AAAA, or arbitrary RR) ─────────────────────────────
    // `insert` mirrors C's local of the same name (`rfc1035.c:788-804`): A and
    // AAAA are always cacheable, SRV/PTR/an explicit `cache_rr` entry (or a
    // `T_ANY` wildcard entry) make an arbitrary RR type cacheable via `F_RR`,
    // and everything else — explicitly including a `T_CNAME` query — caches
    // nothing at all, not even the CNAME hops leading to it.
    let (addr_flag, insert) = match qtype {
        1  /* A    */ => (F_IPV4, true),
        28 /* AAAA */ => (F_IPV6, true),
        _ if qtype != 5 /* CNAME */
            && (qtype == 33 /* SRV */
                || qtype == 12 /* PTR */
                || config.cache_rr.contains(&qtype)
                || config.cache_rr.contains(&255) /* ANY wildcard */) =>
        {
            (F_RR, true)
        }
        _ => (0, false),
    };

    // `daemon->ipsets`/`daemon->nftsets` are matched once against the
    // *original* question name (`forward.c:713,717` matches against
    // `daemon->namebuff` before any CNAME-following), and applied to every
    // A/AAAA address extracted below regardless of which name in the chain it
    // belongs to (`rfc1035.c:1005-1028`).
    let ipset_match = domain_find_sets(&config.ipsets, &qname_lower);

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
                    Err(_) => return bad_packet(ipset_hits),
                };
                if insert {
                    staged.push(CacheRecord {
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
                }
                cname_hops += 1;
                current_name = target;
                // A query for the CNAME itself does not chase the chain
                // further (`rfc1035.c:879-882`) — it stops here with `found`
                // set, so the missing target does not fall through to a
                // spurious negative-cache entry.
                if qtype == 5 /* CNAME */ {
                    found = true;
                    break 'cname_loop;
                }
                continue 'cname_loop; // restart loop for the CNAME target
            }

            if rr.rtype != qtype || is_nxdomain { continue; }

            let addr = match qtype {
                1 /* A */ => {
                    if rr.rdata.len() < 4 { return bad_packet(ipset_hits); }
                    let ip = Ipv4Addr::new(
                        rr.rdata[0], rr.rdata[1], rr.rdata[2], rr.rdata[3],
                    );
                    if config.check_rebind && private_net(ip, !config.local_rebind_ok) {
                        return rebind_blocked(ipset_hits);
                    }
                    AllAddr::Addr4(ip)
                }
                28 /* AAAA */ => {
                    if rr.rdata.len() < 16 { return bad_packet(ipset_hits); }
                    let mut b = [0u8; 16];
                    b.copy_from_slice(&rr.rdata[..16]);
                    let ip = Ipv6Addr::from(b);
                    if config.check_rebind && private_net6(&ip, !config.local_rebind_ok) {
                        return rebind_blocked(ipset_hits);
                    }
                    AllAddr::Addr6(ip)
                }
                16 /* TXT */ => {
                    log_txt(&current_name, &rr.rdata);
                    AllAddr::RrData(RrDataAddr { rrtype: rr.rtype, data: rr.rdata.clone() })
                }
                _ => AllAddr::RrData(RrDataAddr {
                    rrtype: rr.rtype,
                    data:   rr.rdata.clone(),
                }),
            };
            if let (Some(set), Some(ip)) = (ipset_match, addr.as_ip()) {
                for set_name in &set.sets {
                    ipset_hits.push(IpsetHit { set_name: set_name.clone(), addr: ip });
                }
            }
            if insert {
                staged.push(CacheRecord {
                    name:    current_name.clone(),
                    flags:   addr_flag | F_FORWARD | secflag,
                    ttl,
                    expires: now + Duration::from_secs(u64::from(ttl)),
                    addr:    Some(addr),
                    rdata:   None,
                    uid:     UID_NONE,
                });
            }
            // C sets `found` from the answer section, not from whether the
            // insert committed (`rfc1035.c:1036`): a refused or dropped insert
            // must not turn a real answer into a negative-cache entry.
            found = true;
        }
        break 'cname_loop;
    }

    // ── Negative caching ──────────────────────────────────────────────────────
    // Gated on `insert` too, except NXDOMAIN overrides it: "Can store NXDOMAIN
    // reply for any qtype" (`rfc1035.c:1074-1076`) — a NODATA answer to an
    // uncacheable qtype is not negatively cached, but a true NXDOMAIN is.
    //
    // The SOA lookup uses `current_name` — the name after any CNAME chase —
    // not the original question name: C reassigns its `name` local as it
    // follows the chain, and `find_soa()` (like the negative cache entry
    // itself, below) is keyed off that reassigned name (`rfc1035.c:1092`).
    if !found && !config.no_neg_cache && (insert || is_nxdomain) {
        let soa = find_soa(&current_name, &packet.authority);
        let ttl = soa.as_ref()
            .map(|s| clamp_ttl(s.neg_ttl, config.max_ttl))
            .or_else(|| if config.neg_ttl > 0 { Some(config.neg_ttl) } else { None });
        if let Some(ttl) = ttl {
            if let Some(soa) = &soa {
                let rr_ttl = clamp_ttl(soa.rr_ttl, config.max_ttl);
                staged.push(CacheRecord {
                    name:    soa.owner.clone(),
                    flags:   F_FORWARD | F_RR | F_KEYTAG | secflag,
                    ttl:     rr_ttl,
                    expires: now + Duration::from_secs(u64::from(rr_ttl)),
                    addr:    Some(AllAddr::RrBlock(RrBlockAddr { rrtype: 6, rrdata: soa.rdata.clone() })),
                    rdata:   None,
                    uid:     UID_NONE,
                });
            }
            let neg_flags = if is_nxdomain {
                F_NXDOMAIN | F_NEG | F_FORWARD | secflag
            } else {
                addr_flag | F_NEG | F_FORWARD | secflag
            };
            staged.push(CacheRecord {
                name:    current_name.clone(),
                flags:   neg_flags,
                ttl,
                expires: now + Duration::from_secs(u64::from(ttl)),
                addr:    None,
                rdata:   None,
                uid:     UID_NONE,
            });
        }
    }

    commit_staged(cache, staged, header, now);
    cached(ipset_hits)
}

// ──────────────────────────────────────────────────────────────────────────────
// Answer local queries
// ──────────────────────────────────────────────────────────────────────────────

/// Configuration for answering DNS queries from local data and cache.
pub struct LocalConfig<'a> {
    pub local_ttl:     u32,
    /// Advertised EDNS0 UDP payload size (`daemon->edns_pktsz`).  Used only to
    /// re-attach the OPT pseudo-header to a locally generated answer.
    pub edns_pktsz:    u16,
    pub txt_records:   &'a [TxtRecord],
    pub rr_records:    &'a [TxtRecord],   // arbitrary cached-RR types (class field = rrtype)
    pub mx_records:    &'a [MxSrvRecord],
    pub ptr_records:   &'a [PtrRecord],
    pub host_records:  &'a [HostRecord],
    pub cnames:        &'a [Cname],
    pub naptr_records: &'a [Naptr],
    /// `--interface-name` (`daemon->int_names`): domain names that resolve to
    /// an interface's runtime address. Only the domain-suffix check in
    /// [`check_for_local_domain`] consults this; answering the query with the
    /// interface's actual address is not implemented (see `tasks.md`).
    pub int_names:     &'a [InterfaceName],
    /// `--domain-needed` (`OPT_NODOTS_LOCAL`): don't forward A/AAAA queries
    /// for single-label names — answer them locally as NXDOMAIN, or NOERR if
    /// the name matches other local config (`forward.c:355-361`).
    pub nodots_local:  bool,
    /// `--synth-domain` (`daemon->synth_domains`): IP-range-to-domain-name
    /// synthesis rules consulted for A/AAAA and PTR queries that have no
    /// other local answer (`domain.c:is_name_synthetic`/`is_rev_synth`).
    pub synth_domains: &'a [CondDomain],
    /// Domains with a `SERV_LITERAL_ADDRESS` `server` entry and no upstream
    /// address (`local=/domain/` with no address, or `rev-server` with the
    /// server part omitted): never forwarded, and answered NXDOMAIN here
    /// when nothing else matches, for any query type.
    pub literal_domains: &'a [String],
}

/// Port of C's `setup_reply()`.  Sets standard response flags on a DnsHeader.
pub fn setup_reply(header: &mut DnsHeader, flags: u32) {
    header.hb3 = (header.hb3 & !(HB3_AA | HB3_TC)) | HB3_QR;
    header.hb4 = (header.hb4 & !HB4_AD) | HB4_RA;
    header.nscount = 0;
    header.arcount = 0;
    header.ancount = 0;
    if flags == F_NOERR {
        header.set_rcode(0); // empty domain
    } else if flags == F_NXDOMAIN {
        header.set_rcode(3);
    } else if flags == F_RCODE {
        header.set_rcode(4); // NOTIMP
    } else if flags & (F_IPV4 | F_IPV6) != 0 {
        header.set_rcode(0);
        header.hb3 |= HB3_AA;
    } else {
        // "nowhere to forward to" — C's final `else` (`rfc1035.c:setup_reply`).
        // This is the answer a query gets when the forward table is full or no
        // server matches, so it must not be NOERROR: a client told NOERROR with
        // an empty answer caches a negative result we never established.
        header.set_rcode(5); // REFUSED
    }
}

/// True when `name` equals or is a subdomain of any entry in `domains`
/// (case-insensitive, label-boundary-aware suffix match).
fn domain_matches_any_suffix(name: &str, domains: &[String]) -> bool {
    domains.iter().any(|domain| {
        let dlen = domain.len();
        if dlen == 0 || name.len() < dlen {
            return false;
        }
        let start = name.len() - dlen;
        let suffix = &name[start..];
        suffix.eq_ignore_ascii_case(domain)
            && (name.len() == dlen || name.as_bytes().get(start.wrapping_sub(1)) == Some(&b'.'))
    })
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
    //
    // `ans` is what decides, at the end, whether this query is answered locally
    // or forwarded.  A CNAME on its own only sets it when the record came from
    // config or the client asked for `T_CNAME` (`rfc1035.c:1704-1705`); a
    // cached, upstream-derived CNAME leaves `ans` alone, so the chain has to
    // bottom out in something that actually answers.  Otherwise a cached CNAME
    // whose target has expired — the everyday CDN TTL pattern — would be served
    // as a CNAME-only NOERROR, which is a resolution failure, instead of being
    // re-resolved upstream.
    for _ in 0..16 {
        // Config CNAMEs first.  These are C's `F_CONFIG` cache entries, and
        // they do answer the question on their own.
        if let Some(c) = config.cnames.iter().find(|c| c.alias.to_lowercase() == name) {
            let target = c.target.clone();
            let mut rd = BytesMut::new();
            write_name(&mut rd, &target);
            answers.push(DnsRr { name: name.clone(), rtype: 5, class: 1, ttl, rdata: rd.to_vec() });
            name = target.to_lowercase();
            ans  = true;
            if qtype == 5 /* CNAME */ {
                break;
            }
            continue;
        }

        // Cached CNAME.  It carries its own TTL — `ttl` here is `local-ttl`,
        // a static-record default that says nothing about an upstream answer.
        let cname_target: Option<(String, u32)> = cache
            .lookup_by_name(&name, F_CNAME, now)
            .and_then(|r| {
                if let Some(AllAddr::Cname(ref c)) = r.addr {
                    c.target_name.clone().map(|t| (t, DnsCache::crec_ttl(r, now)))
                } else {
                    None
                }
            });
        if let Some((target, cname_ttl)) = cname_target {
            let mut rd = BytesMut::new();
            write_name(&mut rd, &target);
            answers.push(DnsRr {
                name: name.clone(), rtype: 5, class: 1, ttl: cname_ttl, rdata: rd.to_vec(),
            });
            name = target.to_lowercase();
            if qtype == 5 /* CNAME */ {
                // The CNAME *is* the answer the client asked for.
                ans = true;
                break;
            }
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
                        .map(|r| (r.name.clone(), r.flags, DnsCache::crec_ttl(r, now)));
                    if let Some((hostname, flags, cached_ttl)) = cached {
                        if flags & F_NXDOMAIN != 0 {
                            nxdomain = true;
                            ans      = true;
                        } else {
                            let mut rd = BytesMut::new();
                            write_name(&mut rd, &hostname);
                            answers.push(DnsRr {
                                name: name.clone(), rtype: 12, class: 1,
                                ttl: cached_ttl, rdata: rd.to_vec(),
                            });
                            ans = true;
                        }
                        found_ptr = true;
                    }
                }
                // `--synth-domain` reverse synthesis, tried after host
                // records and cache both miss.  Port of `is_rev_synth()`
                // (domain.c:153-215).
                if !found_ptr {
                    let synth_name = match addr {
                        AllAddr::Addr4(a) => crate::domain::rev_synth_ipv4(a, config.synth_domains),
                        AllAddr::Addr6(a) => crate::domain::rev_synth_ipv6(a, config.synth_domains),
                        _ => None,
                    };
                    if let Some(hostname) = synth_name {
                        let mut rd = BytesMut::new();
                        write_name(&mut rd, &hostname);
                        answers.push(DnsRr {
                            name: name.clone(), rtype: 12, class: 1, ttl, rdata: rd.to_vec(),
                        });
                        ans  = true;
                        auth = true;
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
                    .lookup_forward(&name, F_IPV4, now)
                    .map(|r| (r.addr.clone(), r.flags, DnsCache::crec_ttl(r, now)));
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
                } else if let Some(ip4) = crate::domain::synthesize_ipv4(&name, config.synth_domains) {
                    // `--synth-domain` forward synthesis, tried only when the
                    // name is uncached.  Port of `is_name_synthetic()`
                    // (domain.c:24-140), gated the same way upstream gates it
                    // (`rfc1035.c:2086`: only reached when `crecp` is NULL).
                    answers.push(DnsRr {
                        name: name.clone(), rtype: 1, class: 1, ttl, rdata: ip4.octets().to_vec(),
                    });
                    ans  = true;
                    auth = true;
                }
            }
            if want_aaaa {
                let cached = cache
                    .lookup_forward(&name, F_IPV6, now)
                    .map(|r| (r.addr.clone(), r.flags, DnsCache::crec_ttl(r, now)));
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
                } else if let Some(ip6) = crate::domain::synthesize_ipv6(&name, config.synth_domains) {
                    answers.push(DnsRr {
                        name: name.clone(), rtype: 28, class: 1, ttl, rdata: ip6.octets().to_vec(),
                    });
                    ans  = true;
                    auth = true;
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

    // 6. No answer found: don't forward simple (dot-free) A/AAAA names when
    // `--domain-needed` is set, except the empty name (`forward.c:355-361`).
    // Upstream's `extract_request()` returns `F_IPV4|F_IPV6` for a `T_ANY`
    // (255) query too, so ANY is covered by the same `gotname & (F_IPV4|F_IPV6)`
    // gate (rfc1035.c:1223) — include it here alongside A/AAAA.
    if !ans && config.nodots_local && (qtype == 1 || qtype == 28 || qtype == 255) && !name.contains('.') && !name.is_empty() {
        ans = true;
        nxdomain = !check_for_local_domain(&name, config, &*cache, now);
    }

    // 6b. A domain with a `SERV_LITERAL_ADDRESS` server entry and no
    // upstream (`local=/domain/` with no address, or `rev-server` with the
    // server part omitted) is never forwarded, for any query type — answer
    // NXDOMAIN instead of falling through to forwarding.
    if !ans && domain_matches_any_suffix(&name, config.literal_domains) {
        ans      = true;
        nxdomain = true;
    }

    if !ans {
        return None;
    }

    // 6a. Re-attach the EDNS0 pseudo-header when the query carried one.
    //
    // C strips the whole additional section while building the answer and then
    // calls `add_pseudoheader()` again in `receive_query()` (`forward.c:1969`)
    // if `FREC_HAS_PHEADER` was set.  The re-added OPT advertises *our* payload
    // size (`daemon->edns_pktsz`, `edns0.c:207`) rather than the client's, drops
    // whatever options the client sent, and carries only the DO bit forward.
    // Without this, every locally answered query — which is now every cache hit
    // — comes back looking as though this server does not speak EDNS0 at all.
    if let Some(opt) = query.additional.iter().find(|rr| rr.rtype == 41) {
        const EDNS_DO: u32 = 0x8000;
        response.additional.push(DnsRr {
            name:  String::new(), // root: OPT always has an empty name
            rtype: 41,            // T_OPT
            class: config.edns_pktsz,
            ttl:   opt.ttl & EDNS_DO, // extended rcode 0, version 0, DO copied
            rdata: Vec::new(),
        });
    }

    // 7. Finalise response header.
    response.answers        = answers;
    response.header.ancount = response.answers.len() as u16;
    response.header.arcount = response.additional.len() as u16;
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

/// The address an answer RR carries, if it is an A or AAAA in class IN.
///
/// The `class == C_IN` test and the two record types are exactly what C's
/// `check_bad_address()` looks at (`rfc1035.c:1330-1370`).
fn answer_address(rr: &DnsRr) -> Option<AllAddr> {
    if rr.class != 1 {
        return None;
    }
    match rr.rtype {
        1 if rr.rdata.len() >= 4 => Some(AllAddr::Addr4(Ipv4Addr::new(
            rr.rdata[0], rr.rdata[1], rr.rdata[2], rr.rdata[3],
        ))),
        28 if rr.rdata.len() >= 16 => {
            let mut b = [0u8; 16];
            b.copy_from_slice(&rr.rdata[..16]);
            Some(AllAddr::Addr6(Ipv6Addr::from(b)))
        }
        _ => None,
    }
}

/// The first answer RR whose address falls in one of `ranges`, with its owner
/// name and TTL.
///
/// Port of `check_bad_address()` (`rfc1035.c:1319`), the shared engine behind
/// both `check_for_bogus_wildcard()` and `check_for_ignored_address()`.
///
/// C's `name` parameter is an in/out buffer that `extract_name()` overwrites
/// with each answer's owner as the walk proceeds (`rfc1035.c:1332-1333`), so
/// when the function returns 1 the caller's buffer holds the *matching*
/// record's owner name — which after a CNAME chain is the chain target, not the
/// question.  Returning the name here keeps that observable.
fn find_bad_address<'a>(packet: &'a DnsPacket, ranges: &[BogusAddr]) -> Option<(&'a str, u32)> {
    if ranges.is_empty() {
        return None;
    }
    packet.answers.iter().find_map(|rr| {
        let addr = answer_address(rr)?;
        ranges
            .iter()
            .any(|r| addr_in_bogus_range(&addr, r))
            .then_some((rr.name.as_str(), rr.ttl))
    })
}

/// Check whether any A or AAAA record in `packet` matches a bogus-address list
/// (`--bogus-nxdomain`).
///
/// If a match is found, inserts an NXDOMAIN negative cache entry for the
/// offending record's owner name and returns `true`.  The TTL comes from that
/// same record: C notes that there is "no SOA record to get the ttl from in the
/// normal processing" and uses the bogus answer's own TTL (`rfc1035.c:1406`).
///
/// The insert goes through [`DnsCache::really_insert`] because C reaches it via
/// `cache_insert()` (`cache.c:661-687`), which applies `max-cache-ttl` /
/// `min-cache-ttl` clamping and zero-TTL rejection before the entry lands.
/// Calling `insert()` directly here would make both directives silent no-ops on
/// this path.
pub fn check_for_bogus_wildcard(
    packet:      &DnsPacket,
    cache:       &mut DnsCache,
    now:         Instant,
    bogus_addrs: &[BogusAddr],
) -> bool {
    let Some((name, ttl)) = find_bad_address(packet, bogus_addrs) else { return false };

    cache.really_insert(
        CacheRecord {
            name:    name.to_lowercase(),
            flags:   F_FORWARD | F_NEG | F_NXDOMAIN,
            ttl,
            expires: now + Duration::from_secs(u64::from(ttl)),
            addr:    None,
            rdata:   None,
            uid:     UID_NONE,
        },
        now,
    );
    true
}

/// Check whether any A or AAAA record in `packet` matches an address in the
/// ignore list.  If so, the reply should be silently dropped.
pub fn check_for_ignored_address(packet: &DnsPacket, ignore_addrs: &[BogusAddr]) -> bool {
    find_bad_address(packet, ignore_addrs).is_some()
}

/// Returns `true` if `name` matches any locally-configured record type.
///
/// Checks NAPTR, MX/SRV, TXT, interface-name, and PTR records for an exact
/// match or subdomain relationship, then falls back to any non-terminal cache
/// entry or a synthesised (`--synth-domain`) name. Port of C's
/// `check_for_local_domain()` (`rfc1035.c:1301-1338`).
///
/// Deliberately does *not* check `config.host_records`: upstream's version of
/// this function never does, because a host record that matches `name`
/// exactly for the queried type would already have been answered earlier in
/// `answer_request`'s local-data pass — this function only decides NOERR vs
/// NXDOMAIN for query types host records can't themselves answer (NAPTR, TXT,
/// PTR, ...). Checking `host_records` here as well as upstream's checks would
/// answer NOERR for combinations upstream answers NXDOMAIN.
pub fn check_for_local_domain(
    name:  &str,
    config: &LocalConfig<'_>,
    cache: &DnsCache,
    now:   Instant,
) -> bool {
    config.naptr_records.iter().any(|n| hostname_issubdomain(name, &n.name))
        || config.mx_records.iter().any(|m| hostname_issubdomain(name, &m.name))
        || config.txt_records.iter().any(|t| hostname_issubdomain(name, &t.name))
        || config.int_names.iter().any(|i| hostname_issubdomain(name, &i.name))
        || config.ptr_records.iter().any(|p| hostname_issubdomain(name, &p.name))
        || crate::cache::cache_find_non_terminal(name, now, cache)
        || crate::domain::synthesize_ipv4(name, config.synth_domains).is_some()
        || crate::domain::synthesize_ipv6(name, config.synth_domains).is_some()
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

/// Parse a TXT record payload into its counted strings, truncating each one
/// at its first non-printable byte.
///
/// TXT records contain length-prefixed strings. Port of the sanitisation loop
/// in `log_txt()` (`rfc1035.c:653-682`): C shifts each string's bytes left in
/// place, *stopping* (`break`, `rfc1035.c:668-671`) at the first byte that
/// fails `isprint()`, so a non-printable byte truncates the string rather than
/// being skipped over. Returns `None` for a malformed payload (a length byte
/// that overruns `data`), matching C's `return 0`.
pub fn parse_txt_record(data: &[u8]) -> Option<Vec<String>> {
    let mut result = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let len = data[pos] as usize;
        if pos + 1 + len > data.len() {
            return None; // bad packet
        }
        let s: String = data[pos + 1..pos + 1 + len]
            .iter()
            .take_while(|&&b| b == b' ' || b.is_ascii_graphic())
            .map(|&b| b as char)
            .collect();
        result.push(s);
        pos += 1 + len;
    }
    Some(result)
}

/// Sanitise and log a TXT answer's counted strings, one `tracing::debug!` per
/// string. Port of `log_txt()` (`rfc1035.c:653-682`) — C calls `log_query()`
/// per string via the daemon's general query-logging facility, which this
/// port does not otherwise have (see `tasks.md`); `tracing` is the nearest
/// equivalent already used for reply-path diagnostics elsewhere in this crate.
///
/// Returns `false` for a malformed payload (nothing is logged), matching C's
/// `return 0`.
pub fn log_txt(name: &str, rdata: &[u8]) -> bool {
    match parse_txt_record(rdata) {
        Some(strings) => {
            for s in strings {
                tracing::debug!(name, txt = %s, "reply");
            }
            true
        }
        None => false,
    }
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

#[cfg(test)]
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
    ///
    /// `RA` is set: a recursive resolver sets it, and nothing from a reply with
    /// it clear is ever committed to the cache (`rfc1035.c:1124-1127`).
    fn reply_header(id: u16, qd: u16, an: u16, ns: u16, rcode: u8) -> Vec<u8> {
        let mut v = vec![
            (id >> 8) as u8, id as u8,
            0x84, HB4_RA | rcode, // QR=1, AA=1, RA=1, rcode
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

    /// Upstream only caches `T_SRV`, `T_PTR`, or a type explicitly on
    /// `daemon->cache_rr` (`rr_on_list`, `rfc1035.c:800-804`); everything else
    /// falls into `insert = 0` and nothing is staged.
    #[test]
    fn extract_unlisted_rr_type_is_not_cached() {
        let mut pkt = reply_header(30, 1, 1, 0, 0);
        push_question(&mut pkt, "example.com", 16 /* TXT */);
        push_rr(&mut pkt, "example.com", 16, 300, b"\x05hello");

        let dp = DnsPacket::parse(&pkt).unwrap();
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        assert_eq!(
            extract_addresses(&dp, &mut cache, now, &ExtractConfig::default()),
            ExtractResult::Cached
        );
        assert_eq!(cache.inserts, 0, "TXT is not on any allowlist by default");
    }

    /// `--cache-rr=TXT` puts TXT on `daemon->cache_rr`, so a TXT reply to a
    /// TXT query is now cached via the `F_RR` fallback.
    #[test]
    fn extract_cache_rr_allowlist_enables_caching() {
        let mut pkt = reply_header(31, 1, 1, 0, 0);
        push_question(&mut pkt, "example.com", 16 /* TXT */);
        push_rr(&mut pkt, "example.com", 16, 300, b"\x05hello");

        let dp = DnsPacket::parse(&pkt).unwrap();
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        let cfg = ExtractConfig { cache_rr: vec![16], ..Default::default() };
        assert_eq!(extract_addresses(&dp, &mut cache, now, &cfg), ExtractResult::Cached);
        assert_eq!(cache.inserts, 1);
    }

    /// A `T_ANY` (255) entry on `cache_rr` is a wildcard: cache every RR type,
    /// not just the type literally named `ANY` (`rfc1035.c:801`).
    #[test]
    fn extract_cache_rr_any_wildcard_enables_caching() {
        let mut pkt = reply_header(32, 1, 1, 0, 0);
        push_question(&mut pkt, "example.com", 16 /* TXT */);
        push_rr(&mut pkt, "example.com", 16, 300, b"\x05hello");

        let dp = DnsPacket::parse(&pkt).unwrap();
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        let cfg = ExtractConfig { cache_rr: vec![255], ..Default::default() };
        assert_eq!(extract_addresses(&dp, &mut cache, now, &cfg), ExtractResult::Cached);
        assert_eq!(cache.inserts, 1);
    }

    /// `T_SRV` and `T_PTR`-as-forward-type are cached unconditionally, with no
    /// `cache_rr` entry required (`rfc1035.c:801`).
    #[test]
    fn extract_srv_is_cached_without_allowlist() {
        let mut pkt = reply_header(33, 1, 1, 0, 0);
        push_question(&mut pkt, "_svc._tcp.example.com", 33 /* SRV */);
        push_rr(&mut pkt, "_svc._tcp.example.com", 33, 300, &[0, 1, 0, 1, 0, 80, 0]);

        let dp = DnsPacket::parse(&pkt).unwrap();
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        assert_eq!(
            extract_addresses(&dp, &mut cache, now, &ExtractConfig::default()),
            ExtractResult::Cached
        );
        assert_eq!(cache.inserts, 1);
    }

    /// Upstream never caches the answer to a `T_CNAME` query, including the
    /// literal CNAME record itself: `insert = 0` for `qtype == T_CNAME`
    /// (`rfc1035.c:800-804`), and it stops chasing the chain rather than
    /// falling through to negative caching (`rfc1035.c:879-882`).
    #[test]
    fn extract_cname_query_is_not_cached() {
        let mut cname_rdata = BytesMut::new();
        write_name(&mut cname_rdata, "target.example.com");

        let mut pkt = reply_header(34, 1, 1, 0, 0);
        push_question(&mut pkt, "alias.example.com", 5 /* CNAME */);
        push_rr(&mut pkt, "alias.example.com", 5, 300, &cname_rdata);

        let dp = DnsPacket::parse(&pkt).unwrap();
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        assert_eq!(
            extract_addresses(&dp, &mut cache, now, &ExtractConfig::default()),
            ExtractResult::Cached
        );
        assert_eq!(cache.inserts, 0, "a CNAME query's own answer must not be cached");
        assert!(cache.lookup_by_name("alias.example.com", F_CNAME, now).is_none());
        assert!(cache.lookup_by_name("alias.example.com", F_NEG, now).is_none());
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
            0x84, 0x83,       // QR=1, AA=1, RA=1, RCODE=NXDOMAIN
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

        // The SOA RR itself must now also be cached, as F_RR (`rfc1035.c:620`).
        let soa = cache.lookup_by_name("example.com", F_RR, now).expect("SOA not cached");
        assert_eq!(soa.ttl, 600); // the SOA's own TTL, not capped by `minimum`
    }

    /// A SOA in the authority section whose owner name is *not* a suffix of
    /// the queried name must be ignored — `find_soa()`'s "SOA must be for the
    /// name we're interested in" check (`rfc1035.c:554-556`).
    #[test]
    fn find_soa_ignores_soa_for_an_unrelated_zone() {
        let mut soa_rdata = BytesMut::new();
        write_name(&mut soa_rdata, "ns.other.com");
        write_name(&mut soa_rdata, "admin.other.com");
        soa_rdata.put_u32(1);
        soa_rdata.put_u32(3600);
        soa_rdata.put_u32(900);
        soa_rdata.put_u32(86400);
        soa_rdata.put_u32(300);

        let mut pkt = vec![
            0x00, 0x05, 0x84, 0x83, // QR=1 AA=1 RA=1 NXDOMAIN
            0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        ];
        push_question(&mut pkt, "noexist.example.com", 1);
        push_rr(&mut pkt, "other.com", 6, 600, &soa_rdata); // unrelated zone

        let dp = DnsPacket::parse(&pkt).unwrap();
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        // No `neg_ttl` fallback configured, so the unrelated SOA must not be
        // used and nothing gets negatively cached.
        assert_eq!(
            extract_addresses(&dp, &mut cache, now, &ExtractConfig::default()),
            ExtractResult::Cached
        );
        assert!(cache.lookup_by_name("noexist.example.com", F_NXDOMAIN | F_NEG, now).is_none());
        assert!(cache.lookup_by_name("other.com", F_RR, now).is_none());
    }

    /// When a query CNAME-chains to a target with NODATA, the negative cache
    /// entry (and the `find_soa()` lookup that produces its TTL) must key off
    /// the CNAME *target*, not the original question name — otherwise it lands
    /// on the same cache key as the CNAME record just inserted a few lines
    /// above (`rfc1035.c:1092` re-derives `name` from the CNAME chase before
    /// calling `find_soa`).
    #[test]
    fn negative_cache_lands_under_cname_target_not_original_qname() {
        let mut soa_rdata = BytesMut::new();
        write_name(&mut soa_rdata, "ns.example.com");
        write_name(&mut soa_rdata, "admin.example.com");
        soa_rdata.put_u32(1);
        soa_rdata.put_u32(3600);
        soa_rdata.put_u32(900);
        soa_rdata.put_u32(86400);
        soa_rdata.put_u32(120);

        let mut pkt = reply_header(7, 1, 1, 1, 0);
        push_question(&mut pkt, "foo.com", 1); // A
        let mut cname_rdata = BytesMut::new();
        write_name(&mut cname_rdata, "bar.com");
        push_rr(&mut pkt, "foo.com", 5 /* CNAME */, 300, &cname_rdata);
        push_rr(&mut pkt, "bar.com", 6 /* SOA */, 600, &soa_rdata); // authority

        let dp = DnsPacket::parse(&pkt).unwrap();
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        assert_eq!(
            extract_addresses(&dp, &mut cache, now, &ExtractConfig::default()),
            ExtractResult::Cached
        );

        // The CNAME record for foo.com must survive untouched.
        let cname_rec = cache.lookup_by_name("foo.com", F_CNAME, now).expect("CNAME not cached");
        assert_eq!(cname_rec.ttl, 300);

        // The negative entry belongs to bar.com (the chase target), not foo.com.
        assert!(cache.lookup_by_name("foo.com", F_IPV4 | F_NEG, now).is_none());
        let neg = cache.lookup_by_name("bar.com", F_IPV4 | F_NEG, now).expect("negative entry on target");
        assert_eq!(neg.ttl, 120);
    }

    #[test]
    fn extract_addresses_reports_ipset_hits_for_a_matching_domain() {
        let mut pkt = reply_header(8, 1, 1, 0, 0);
        push_question(&mut pkt, "www.example.com", 1);
        push_rr(&mut pkt, "www.example.com", 1, 300, &[10, 20, 30, 40]);
        let dp = DnsPacket::parse(&pkt).unwrap();
        let mut cache = DnsCache::new(100);
        let now = Instant::now();

        let cfg = ExtractConfig {
            ipsets: vec![Ipsets { domain: "example.com".into(), sets: vec!["blocked".into(), "logged".into()] }],
            ..Default::default()
        };
        let outcome = extract_addresses(&dp, &mut cache, now, &cfg);
        assert_eq!(outcome, ExtractResult::Cached);
        assert_eq!(
            outcome.ipset_hits,
            vec![
                IpsetHit { set_name: "blocked".into(), addr: IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)) },
                IpsetHit { set_name: "logged".into(), addr: IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)) },
            ]
        );
    }

    #[test]
    fn extract_addresses_reports_no_ipset_hits_for_a_non_matching_domain() {
        let mut pkt = reply_header(9, 1, 1, 0, 0);
        push_question(&mut pkt, "www.other.com", 1);
        push_rr(&mut pkt, "www.other.com", 1, 300, &[10, 20, 30, 40]);
        let dp = DnsPacket::parse(&pkt).unwrap();
        let mut cache = DnsCache::new(100);
        let now = Instant::now();

        let cfg = ExtractConfig {
            ipsets: vec![Ipsets { domain: "example.com".into(), sets: vec!["blocked".into()] }],
            ..Default::default()
        };
        let outcome = extract_addresses(&dp, &mut cache, now, &cfg);
        assert!(outcome.ipset_hits.is_empty());
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

    /// `rebind-localhost-ok` is C's `private_net(addr, !option_bool(OPT_LOCAL_REBIND))`
    /// (`rfc1035.c:997`): loopback stops counting as private, everything else
    /// still does.
    #[test]
    fn extract_rebind_localhost_ok_exempts_loopback_only() {
        let cfg = ExtractConfig { check_rebind: true, local_rebind_ok: true, ..Default::default() };

        let mut pkt = reply_header(22, 1, 1, 0, 0);
        push_question(&mut pkt, "lo.example.com", 1);
        push_rr(&mut pkt, "lo.example.com", 1, 300, &[127, 0, 0, 1]);
        let dp = DnsPacket::parse(&pkt).unwrap();
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        assert_eq!(extract_addresses(&dp, &mut cache, now, &cfg), ExtractResult::Cached);
        assert!(cache.lookup_by_name("lo.example.com", F_IPV4, now).is_some());

        // ::1 likewise, via private_net6().
        let mut v6 = reply_header(23, 1, 1, 0, 0);
        push_question(&mut v6, "lo6.example.com", 28);
        push_rr(&mut v6, "lo6.example.com", 28, 300, &Ipv6Addr::LOCALHOST.octets());
        let dp6 = DnsPacket::parse(&v6).unwrap();
        assert_eq!(extract_addresses(&dp6, &mut cache, now, &cfg), ExtractResult::Cached);
        assert!(cache.lookup_by_name("lo6.example.com", F_IPV6, now).is_some());

        // RFC1918 space is still blocked: the option narrows the check, it does
        // not disable it.
        let mut priv4 = reply_header(24, 1, 1, 0, 0);
        push_question(&mut priv4, "evil.example.com", 1);
        push_rr(&mut priv4, "evil.example.com", 1, 300, &[10, 1, 2, 3]);
        let dp4 = DnsPacket::parse(&priv4).unwrap();
        assert_eq!(
            extract_addresses(&dp4, &mut cache, now, &cfg),
            ExtractResult::RebindBlocked
        );
    }

    /// Without the option, loopback is private — the default `ban_localhost`
    /// argument is `true`.
    #[test]
    fn extract_rebind_blocks_loopback_by_default() {
        let mut pkt = reply_header(25, 1, 1, 0, 0);
        push_question(&mut pkt, "lo.example.com", 1);
        push_rr(&mut pkt, "lo.example.com", 1, 300, &[127, 0, 0, 1]);

        let dp = DnsPacket::parse(&pkt).unwrap();
        let mut cache = DnsCache::new(100);
        let cfg = ExtractConfig { check_rebind: true, ..Default::default() };
        assert_eq!(
            extract_addresses(&dp, &mut cache, Instant::now(), &cfg),
            ExtractResult::RebindBlocked
        );
    }

    /// C never reaches `cache_end_insert()` when `extract_addresses()` bails out
    /// with the rebind code, so the records it walked *before* the offending one
    /// are discarded with it.  Committing record-by-record would leave the
    /// public A (and any CNAME) behind, and the client would then be served a
    /// stripped answer while the cache quietly held half of a blocked reply.
    #[test]
    fn rebind_bailout_discards_the_records_staged_before_it() {
        let mut cname_rdata = BytesMut::new();
        write_name(&mut cname_rdata, "hidden.example.com");

        let mut pkt = reply_header(20, 1, 3, 0, 0);
        push_question(&mut pkt, "evil.example.com", 1);
        push_rr(&mut pkt, "evil.example.com", 5, 300, &cname_rdata);      // CNAME
        push_rr(&mut pkt, "hidden.example.com", 1, 300, &[198, 51, 100, 1]); // public A
        push_rr(&mut pkt, "hidden.example.com", 1, 300, &[192, 168, 1, 5]);  // rebind

        let dp = DnsPacket::parse(&pkt).unwrap();
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        let cfg = ExtractConfig { check_rebind: true, ..Default::default() };
        assert_eq!(
            extract_addresses(&dp, &mut cache, now, &cfg),
            ExtractResult::RebindBlocked
        );
        assert_eq!(cache.inserts, 0, "a blocked reply must leave no partial state");
        assert!(cache.lookup_by_name("evil.example.com", F_CNAME, now).is_none());
        assert!(cache.lookup_by_name("hidden.example.com", F_IPV4, now).is_none());
    }

    /// A malformed reply must leave nothing behind, exactly like the rebind
    /// bailout above: a truncated A record mid-CNAME-chain returns `BadPacket`
    /// before `commit_staged` is ever reached, so the CNAME staged before it
    /// is discarded too.
    #[test]
    fn bad_packet_leaves_cache_unchanged() {
        let mut cname_rdata = BytesMut::new();
        write_name(&mut cname_rdata, "target.example.com");

        let mut pkt = reply_header(26, 1, 2, 0, 0);
        push_question(&mut pkt, "alias.example.com", 1);
        push_rr(&mut pkt, "alias.example.com", 5, 300, &cname_rdata); // CNAME
        push_rr(&mut pkt, "target.example.com", 1, 300, &[1, 2]);     // truncated A (< 4 bytes)

        let dp = DnsPacket::parse(&pkt).unwrap();
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        assert_eq!(
            extract_addresses(&dp, &mut cache, now, &ExtractConfig::default()),
            ExtractResult::BadPacket
        );
        assert_eq!(cache.inserts, 0, "a bad packet must leave no partial state");
        assert!(cache.lookup_by_name("alias.example.com", F_CNAME, now).is_none());
    }

    /// "Don't cache replies from non-recursive nameservers, since we may get a
    /// reply containing a CNAME but not its target, even though the target does
    /// exist." (`rfc1035.c:1121-1127`).
    ///
    /// This tests the gate at *this* layer only.  The forwarding path sets `RA`
    /// on every reply before extraction (`forward.c:776`), so a real
    /// non-recursive answer is cached — see
    /// `tests/forward_cache_integration.rs::reply_without_the_ra_bit_is_cached_and_relayed_with_ra_set`.
    #[test]
    fn reply_without_ra_is_parsed_but_not_committed() {
        let mut pkt = reply_header(21, 1, 1, 0, 0);
        pkt[3] &= !HB4_RA;
        push_question(&mut pkt, "norec.example.com", 1);
        push_rr(&mut pkt, "norec.example.com", 1, 300, &[1, 2, 3, 4]);

        let dp = DnsPacket::parse(&pkt).unwrap();
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        assert_eq!(
            extract_addresses(&dp, &mut cache, now, &ExtractConfig::default()),
            ExtractResult::Cached
        );
        assert_eq!(cache.inserts, 0, "RA clear means nothing is committed");
    }

    /// `CD` set means the client validates for itself, so the answer is not
    /// ours to keep (`rfc1035.c:1124`).
    #[test]
    fn reply_with_cd_is_parsed_but_not_committed() {
        let mut pkt = reply_header(22, 1, 1, 0, 0);
        pkt[3] |= HB4_CD;
        push_question(&mut pkt, "cd.example.com", 1);
        push_rr(&mut pkt, "cd.example.com", 1, 300, &[1, 2, 3, 4]);

        let dp = DnsPacket::parse(&pkt).unwrap();
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        assert_eq!(
            extract_addresses(&dp, &mut cache, now, &ExtractConfig::default()),
            ExtractResult::Cached
        );
        assert_eq!(cache.inserts, 0, "CD set means nothing is committed");
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
            edns_pktsz:   4096,
            txt_records:  &[],
            rr_records:   &[],
            mx_records:   &[],
            ptr_records:  &[],
            host_records: &[],
            cnames:       &[],
            naptr_records: &[],
            int_names:    &[],
            nodots_local: false,
            synth_domains: &[],
            literal_domains: &[],
        }
    }

    /// Seed `cache` with an upstream-derived CNAME (no `F_CONFIG`).
    fn cache_cname(cache: &mut DnsCache, alias: &str, target: &str, ttl: u32, now: Instant) {
        cache.insert(CacheRecord {
            name:    alias.to_string(),
            flags:   F_CNAME | F_FORWARD,
            ttl,
            expires: now + Duration::from_secs(u64::from(ttl)),
            addr:    Some(AllAddr::Cname(CnameAddr {
                is_name_ptr: true,
                target_name: Some(target.to_string()),
                uid:         0,
            })),
            rdata: None,
            uid:   UID_NONE,
        });
    }

    /// A cached CNAME does not answer an A query on its own: upstream only sets
    /// `ans` for `F_CONFIG` CNAMEs or `qtype == T_CNAME` (`rfc1035.c:1704-1705`),
    /// so a chain that dead-ends is forwarded rather than returned as a
    /// CNAME-only NOERROR.
    #[test]
    fn cached_cname_without_a_resolvable_target_is_not_an_answer() {
        let now = Instant::now();
        let mut cache = DnsCache::new(100);
        cache_cname(&mut cache, "www.example.com", "edge.example.com", 3600, now);

        let query = make_query("www.example.com", 1);
        assert!(
            answer_request(&query, &mut cache, now, &empty_config()).is_none(),
            "a dangling cached CNAME must send the query upstream",
        );
    }

    /// …but once the target resolves, the chain answers and the CNAME rides
    /// along in the answer section.
    #[test]
    fn cached_cname_answers_once_its_target_is_cached() {
        let now = Instant::now();
        let mut cache = DnsCache::new(100);
        cache_cname(&mut cache, "www.example.com", "edge.example.com", 3600, now);
        cache.insert(CacheRecord {
            name:    "edge.example.com".into(),
            flags:   F_IPV4 | F_FORWARD,
            ttl:     60,
            expires: now + Duration::from_secs(60),
            addr:    Some(AllAddr::Addr4(Ipv4Addr::new(203, 0, 113, 5))),
            rdata:   None,
            uid:     UID_NONE,
        });

        let query = make_query("www.example.com", 1);
        let resp = answer_request(&query, &mut cache, now, &empty_config())
            .expect("a resolvable chain must be answered from cache");
        assert_eq!(resp.answers.len(), 2, "CNAME + A");
        assert_eq!(resp.answers[0].rtype, 5);
        assert_eq!(resp.answers[1].rtype, 1);
        assert_eq!(resp.answers[1].rdata, vec![203, 0, 113, 5]);
    }

    /// `qtype == T_CNAME` is the one case where a cached CNAME answers by
    /// itself, and the chain stops there rather than being followed.
    #[test]
    fn explicit_cname_query_is_answered_by_the_cached_cname() {
        let now = Instant::now();
        let mut cache = DnsCache::new(100);
        cache_cname(&mut cache, "www.example.com", "edge.example.com", 3600, now);
        cache_cname(&mut cache, "edge.example.com", "deep.example.com", 3600, now);

        let query = make_query("www.example.com", 5);
        let resp = answer_request(&query, &mut cache, now, &empty_config())
            .expect("a CNAME query must be answered from cache");
        assert_eq!(resp.answers.len(), 1, "the chain must not be followed past the first hop");
        assert_eq!(resp.answers[0].rtype, 5);
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
            txt:   b"\x0bv=spf1 ~all".to_vec(),
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
        assert_eq!(resp.answers[0].rdata, b"\x0bv=spf1 ~all".to_vec());
    }

    #[test]
    fn test_answer_request_arbitrary_rr() {
        use crate::types::dns_records::TxtRecord;
        let caa = TxtRecord {
            name:  "example.com".into(),
            txt:   b"\x00\x05issueletsencrypt.org".to_vec(),
            class: crate::dns_protocol::RrType::CAA as u16,
            stat:  0,
        };
        let cfg   = LocalConfig { rr_records: std::slice::from_ref(&caa), ..empty_config() };
        let query = make_query("example.com", crate::dns_protocol::RrType::CAA as u16);
        let mut cache = DnsCache::new(100);
        let resp = answer_request(&query, &mut cache, Instant::now(), &cfg)
            .expect("should answer arbitrary RR");
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(resp.answers[0].rtype, crate::dns_protocol::RrType::CAA as u16);
        assert_eq!(resp.answers[0].rdata, b"\x00\x05issueletsencrypt.org".to_vec());
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
    fn check_for_local_domain_matches_naptr_subdomain() {
        let n = Naptr {
            name: "myhost.local".into(), replace: "r.test".into(), regexp: String::new(),
            services: "SIP+D2U".into(), flags: "s".into(), order: 1, pref: 2,
        };
        let cfg = LocalConfig { naptr_records: std::slice::from_ref(&n), ..empty_config() };
        let cache = DnsCache::new(16);
        let now = Instant::now();
        assert!(check_for_local_domain("myhost.local", &cfg, &cache, now));
        assert!(check_for_local_domain("sub.myhost.local", &cfg, &cache, now));
        assert!(!check_for_local_domain("other.example.com", &cfg, &cache, now));
    }

    /// Upstream's `check_for_local_domain()` never checks host records
    /// (`rfc1035.c:1301-1338` has no `daemon->hosts` walk) — a single-label
    /// name reachable *only* via `--host-record`, queried with a type host
    /// records can't answer, must stay NXDOMAIN, not become NOERR.
    #[test]
    fn check_for_local_domain_does_not_match_host_records() {
        let hr = HostRecord {
            ttl: -1, flags: 0,
            names: vec!["myhost.local".into()],
            addr4: Some(Ipv4Addr::new(1, 2, 3, 4)),
            addr6: None,
        };
        let cfg = LocalConfig { host_records: std::slice::from_ref(&hr), ..empty_config() };
        let cache = DnsCache::new(16);
        let now = Instant::now();
        assert!(!check_for_local_domain("myhost.local", &cfg, &cache, now));
    }

    #[test]
    fn check_for_local_domain_matches_interface_name_subdomain() {
        let intr = InterfaceName {
            name: "router.lan".into(), intr: "eth0".into(), flags: 0,
            proto4: None, proto6: None, addrs: vec![],
        };
        let cfg = LocalConfig { int_names: std::slice::from_ref(&intr), ..empty_config() };
        let cache = DnsCache::new(16);
        let now = Instant::now();
        assert!(check_for_local_domain("router.lan", &cfg, &cache, now));
        assert!(check_for_local_domain("sub.router.lan", &cfg, &cache, now));
        assert!(!check_for_local_domain("other.lan", &cfg, &cache, now));
    }

    #[test]
    fn check_for_local_domain_matches_non_terminal_cache_entry() {
        let cfg = empty_config();
        let mut cache = DnsCache::new(16);
        let now = Instant::now();
        let future = now + Duration::from_secs(300);
        cache.insert(CacheRecord {
            name:    "cached.example.com".into(),
            flags:   F_IPV4 | F_FORWARD,
            ttl:     300,
            expires: future,
            addr:    Some(AllAddr::Addr4(Ipv4Addr::new(9, 9, 9, 9))),
            rdata:   None,
            uid:     UID_NONE,
        });
        assert!(check_for_local_domain("cached.example.com", &cfg, &cache, now));
        assert!(!check_for_local_domain("uncached.example.com", &cfg, &cache, now));
    }

    #[test]
    fn check_for_local_domain_matches_synthetic_name() {
        let sd = CondDomain {
            domain: "synth.test".into(), prefix: None, interface: None,
            start: Ipv4Addr::new(10, 0, 0, 0), end: Ipv4Addr::new(10, 0, 0, 255),
            start6: Ipv6Addr::UNSPECIFIED, end6: Ipv6Addr::UNSPECIFIED,
            is6: false, indexed: false, prefixlen: 0,
        };
        let cfg = LocalConfig { synth_domains: std::slice::from_ref(&sd), ..empty_config() };
        let cache = DnsCache::new(16);
        let now = Instant::now();
        assert!(check_for_local_domain("10-0-0-5.synth.test", &cfg, &cache, now));
        assert!(!check_for_local_domain("not-an-address.synth.test", &cfg, &cache, now));
    }

    // ── domain-needed / OPT_NODOTS_LOCAL (forward.c:355-361) ────────────────

    /// A single-label A query with no local match becomes a synthesised
    /// NXDOMAIN instead of `None` (forwarded) when `nodots_local` is set.
    #[test]
    fn nodots_local_answers_unmatched_single_label_a_query_nxdomain() {
        let now = Instant::now();
        let mut cache = DnsCache::new(100);
        let query = make_query("foo", 1); // A, no dot
        let cfg = LocalConfig { nodots_local: true, ..empty_config() };

        let resp = answer_request(&query, &mut cache, now, &cfg).expect("should answer locally");
        assert_eq!(resp.header.rcode(), 3); // NXDOMAIN
        assert!(resp.header.hb3 & HB3_QR != 0);
        assert!(resp.header.hb3 & HB3_AA == 0);
    }

    /// Same as above but the name matches locally configured data: the
    /// synthesised reply is F_NOERR (empty NOERROR), not NXDOMAIN.
    #[test]
    fn nodots_local_answers_unmatched_single_label_a_query_noerr_when_locally_known() {
        let now = Instant::now();
        let mut cache = DnsCache::new(100);
        let query = make_query("foo", 1); // A, no dot
        let mx = MxSrvRecord {
            name: "foo".into(), target: "mail.example.com".into(),
            priority: 10, is_srv: false, weight: 0, srv_port: 0, offset: 0,
        };
        let cfg = LocalConfig {
            nodots_local: true,
            mx_records: std::slice::from_ref(&mx),
            ..empty_config()
        };

        let resp = answer_request(&query, &mut cache, now, &cfg).expect("should answer locally");
        assert_eq!(resp.header.rcode(), 0); // NOERROR
        assert_eq!(resp.header.ancount, 0);
    }

    /// A dotted name is unaffected: still forwarded (`None`) even with
    /// `nodots_local` set, matching upstream's `!strchr(name, '.')` guard.
    #[test]
    fn nodots_local_does_not_affect_dotted_names() {
        let now = Instant::now();
        let mut cache = DnsCache::new(100);
        let query = make_query("foo.example.com", 1);
        let cfg = LocalConfig { nodots_local: true, ..empty_config() };

        assert!(answer_request(&query, &mut cache, now, &cfg).is_none());
    }

    /// A single-label `T_ANY` (255) query is covered too: upstream's
    /// `extract_request()` reports `F_IPV4|F_IPV6` for ANY, so it hits the
    /// same `gotname & (F_IPV4|F_IPV6)` gate as A/AAAA (rfc1035.c:1223,
    /// forward.c:355-361) rather than being forwarded.
    #[test]
    fn nodots_local_answers_unmatched_single_label_any_query_nxdomain() {
        let now = Instant::now();
        let mut cache = DnsCache::new(100);
        let query = make_query("foo", 255); // ANY, no dot
        let cfg = LocalConfig { nodots_local: true, ..empty_config() };

        let resp = answer_request(&query, &mut cache, now, &cfg).expect("should answer locally");
        assert_eq!(resp.header.rcode(), 3); // NXDOMAIN
    }

    /// Without `nodots_local` set, an unmatched single-label query is still
    /// forwarded — the default, upstream-compatible behaviour.
    #[test]
    fn without_nodots_local_single_label_query_is_forwarded() {
        let now = Instant::now();
        let mut cache = DnsCache::new(100);
        let query = make_query("foo", 1);
        let cfg = LocalConfig { nodots_local: false, ..empty_config() };

        assert!(answer_request(&query, &mut cache, now, &cfg).is_none());
    }

    // ── synth-domain wiring (domain.c: is_name_synthetic / is_rev_synth) ────

    fn v4_synth_domain(domain: &str, prefix: Option<&str>, start: Ipv4Addr, end: Ipv4Addr) -> CondDomain {
        CondDomain {
            domain: domain.to_string(),
            prefix: prefix.map(|s| s.to_string()),
            interface: None,
            start,
            end,
            start6: Ipv6Addr::UNSPECIFIED,
            end6: Ipv6Addr::UNSPECIFIED,
            is6: false,
            indexed: false,
            prefixlen: 0,
        }
    }

    /// An A query for a dashed synthetic name resolves to the embedded
    /// address when it matches a configured `synth-domain` range.
    #[test]
    fn synth_domain_answers_forward_a_query() {
        let now = Instant::now();
        let mut cache = DnsCache::new(100);
        let query = make_query("10-0-0-7.example.com", 1);
        let sd = v4_synth_domain("example.com", None, "10.0.0.0".parse().unwrap(), "10.0.0.255".parse().unwrap());
        let cfg = LocalConfig { synth_domains: std::slice::from_ref(&sd), ..empty_config() };

        let resp = answer_request(&query, &mut cache, now, &cfg).expect("should answer locally");
        assert_eq!(resp.header.rcode(), 0); // NOERROR
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(resp.answers[0].rdata, vec![10, 0, 0, 7]);
    }

    /// A PTR query for an address in a `synth-domain` range synthesises the
    /// dashed hostname when there's no host record or cache entry.
    #[test]
    fn synth_domain_answers_reverse_ptr_query() {
        let now = Instant::now();
        let mut cache = DnsCache::new(100);
        let query = make_query("7.0.0.10.in-addr.arpa", 12);
        let sd = v4_synth_domain("example.com", None, "10.0.0.0".parse().unwrap(), "10.0.0.255".parse().unwrap());
        let cfg = LocalConfig { synth_domains: std::slice::from_ref(&sd), ..empty_config() };

        let resp = answer_request(&query, &mut cache, now, &cfg).expect("should answer locally");
        assert_eq!(resp.header.rcode(), 0); // NOERROR
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(resp.answers[0].rtype, 12);
    }

    /// A cached NODATA entry for the requested type takes precedence over
    /// synth-domain synthesis (upstream only reaches `is_name_synthetic()`
    /// when the per-type cache lookup finds nothing at all — mirrors the
    /// `else if (is_name_synthetic(...))` in `rfc1035.c:2086`, reached only
    /// when the preceding `cache_find_by_name(..., flag)` came up empty).
    #[test]
    fn synth_domain_does_not_override_a_cache_hit() {
        let now = Instant::now();
        let mut cache = DnsCache::new(100);
        cache.really_insert(
            CacheRecord {
                name:    "10-0-0-7.example.com".to_string(),
                flags:   F_IPV4 | F_NEG,
                ttl:     60,
                expires: now + Duration::from_secs(60),
                addr:    None,
                rdata:   None,
                uid:     UID_NONE,
            },
            now,
        );
        let query = make_query("10-0-0-7.example.com", 1);
        let sd = v4_synth_domain("example.com", None, "10.0.0.0".parse().unwrap(), "10.0.0.255".parse().unwrap());
        let cfg = LocalConfig { synth_domains: std::slice::from_ref(&sd), ..empty_config() };

        let resp = answer_request(&query, &mut cache, now, &cfg).expect("should answer locally");
        assert_eq!(resp.header.rcode(), 0); // NOERROR/NODATA from the cache, not a synthesised answer
        assert_eq!(resp.answers.len(), 0);
    }

    /// A name outside the configured range is still forwarded (`None`).
    #[test]
    fn synth_domain_out_of_range_still_forwards() {
        let now = Instant::now();
        let mut cache = DnsCache::new(100);
        let query = make_query("192-168-1-1.example.com", 1);
        let sd = v4_synth_domain("example.com", None, "10.0.0.0".parse().unwrap(), "10.0.0.255".parse().unwrap());
        let cfg = LocalConfig { synth_domains: std::slice::from_ref(&sd), ..empty_config() };

        assert!(answer_request(&query, &mut cache, now, &cfg).is_none());
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
        assert!(check_for_bogus_wildcard(&dp, &mut cache, now, std::slice::from_ref(&ba)));
        // NXDOMAIN entry should now be in cache, at the offending answer's TTL.
        let rec = cache.lookup_by_name("evil.example.com", F_NXDOMAIN | F_NEG, now);
        assert_eq!(rec.map(|r| r.ttl), Some(60));
    }

    /// C caches the NXDOMAIN under the owner name of the *matching* answer RR,
    /// not the question name: `check_bad_address()` re-extracts `name` from
    /// every answer as it walks (`rfc1035.c:1332-1333`), so whatever is left in
    /// the buffer when it returns 1 is the offending record's owner.  After a
    /// CNAME chain that is the chain target, not the question.
    #[test]
    fn check_bogus_wildcard_caches_under_the_matching_owner_name() {
        let ba = BogusAddr {
            is6: false,
            prefix: 32,
            addr: AllAddr::Addr4(Ipv4Addr::new(1, 2, 3, 4)),
        };
        let mut pkt = reply_header(16, 1, 2, 0, 0);
        push_question(&mut pkt, "www.example.com", 1);
        // CNAME www.example.com -> wildcard.isp.example, then the bogus A.
        let mut target = BytesMut::new();
        write_name(&mut target, "wildcard.isp.example");
        push_rr(&mut pkt, "www.example.com", 5, 60, &target);
        push_rr(&mut pkt, "wildcard.isp.example", 1, 60, &[1, 2, 3, 4]);
        let dp = DnsPacket::parse(&pkt).unwrap();

        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        assert!(check_for_bogus_wildcard(&dp, &mut cache, now, std::slice::from_ref(&ba)));
        assert!(cache.lookup_by_name("wildcard.isp.example", F_NXDOMAIN | F_NEG, now).is_some());
        assert!(cache.lookup_by_name("www.example.com", F_NXDOMAIN | F_NEG, now).is_none());
    }

    /// The insert goes through `really_insert()`, so `--max-cache-ttl` clamps it
    /// exactly as it clamps every other DNS answer.  C reaches this entry via
    /// `cache_insert()` (`cache.c:661-687`), which applies the clamp before
    /// `really_insert()` ever sees the record.
    #[test]
    fn check_bogus_wildcard_insert_obeys_max_cache_ttl() {
        let ba = BogusAddr {
            is6: false,
            prefix: 32,
            addr: AllAddr::Addr4(Ipv4Addr::new(1, 2, 3, 4)),
        };
        let mut pkt = reply_header(17, 1, 1, 0, 0);
        push_question(&mut pkt, "evil.example.com", 1);
        push_rr(&mut pkt, "evil.example.com", 1, 86400, &[1, 2, 3, 4]);
        let dp = DnsPacket::parse(&pkt).unwrap();

        let mut cache = DnsCache::with_ttl_limits(100, 0, 60);
        let now = Instant::now();
        assert!(check_for_bogus_wildcard(&dp, &mut cache, now, std::slice::from_ref(&ba)));
        let rec = cache.lookup_by_name("evil.example.com", F_NXDOMAIN | F_NEG, now);
        assert_eq!(rec.map(|r| r.ttl), Some(60));
    }

    /// `--min-cache-ttl` raises the floor on the same path.
    #[test]
    fn check_bogus_wildcard_insert_obeys_min_cache_ttl() {
        let ba = BogusAddr {
            is6: false,
            prefix: 32,
            addr: AllAddr::Addr4(Ipv4Addr::new(1, 2, 3, 4)),
        };
        let mut pkt = reply_header(18, 1, 1, 0, 0);
        push_question(&mut pkt, "evil.example.com", 1);
        push_rr(&mut pkt, "evil.example.com", 1, 5, &[1, 2, 3, 4]);
        let dp = DnsPacket::parse(&pkt).unwrap();

        let mut cache = DnsCache::with_ttl_limits(100, 600, 0);
        let now = Instant::now();
        assert!(check_for_bogus_wildcard(&dp, &mut cache, now, std::slice::from_ref(&ba)));
        let rec = cache.lookup_by_name("evil.example.com", F_NXDOMAIN | F_NEG, now);
        assert_eq!(rec.map(|r| r.ttl), Some(600));
    }

    /// A zero-TTL bogus answer is rejected by `really_insert()` rather than
    /// stored as an instantly-stale entry — but the reply is still rewritten to
    /// NXDOMAIN, since the return value drives the caller, not the insert.
    #[test]
    fn check_bogus_wildcard_drops_a_zero_ttl_insert_but_still_fires() {
        let ba = BogusAddr {
            is6: false,
            prefix: 32,
            addr: AllAddr::Addr4(Ipv4Addr::new(1, 2, 3, 4)),
        };
        let mut pkt = reply_header(19, 1, 1, 0, 0);
        push_question(&mut pkt, "evil.example.com", 1);
        push_rr(&mut pkt, "evil.example.com", 1, 0, &[1, 2, 3, 4]);
        let dp = DnsPacket::parse(&pkt).unwrap();

        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        assert!(check_for_bogus_wildcard(&dp, &mut cache, now, std::slice::from_ref(&ba)));
        assert!(cache.lookup_by_name("evil.example.com", F_NXDOMAIN | F_NEG, now).is_none());
    }

    /// `--bogus-nxdomain` takes an IPv6 prefix too, and `check_bad_address()`
    /// looks at AAAA records as well as A.
    #[test]
    fn check_bogus_wildcard_matches_an_ipv6_prefix() {
        let ba = BogusAddr {
            is6: true,
            prefix: 32,
            addr: AllAddr::Addr6("2001:db8::".parse().unwrap()),
        };
        let mut pkt = reply_header(15, 1, 1, 0, 0);
        push_question(&mut pkt, "evil6.example.com", 28);
        let v6: std::net::Ipv6Addr = "2001:db8::dead".parse().unwrap();
        push_rr(&mut pkt, "evil6.example.com", 28, 60, &v6.octets());
        let dp = DnsPacket::parse(&pkt).unwrap();

        let mut cache = DnsCache::new(100);
        assert!(check_for_bogus_wildcard(&dp, &mut cache, Instant::now(), std::slice::from_ref(&ba)));
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
    fn parse_txt_record_truncates_at_first_non_printable() {
        // C's log_txt() breaks the sanitisation loop at the first
        // non-printable byte rather than skipping it, so "b" after the 0x01
        // is dropped entirely, not just the 0x01 (rfc1035.c:668-671).
        let data = [3, b'a', 0x01, b'b'];
        let result = parse_txt_record(&data).unwrap();
        assert_eq!(result, vec!["a"]);
    }

    #[test]
    fn parse_txt_record_bad_length() {
        let data = [10, b'x']; // claims 10 bytes but only 1 available
        assert!(parse_txt_record(&data).is_none());
    }

    #[test]
    fn parse_txt_record_exact_length_is_not_bad() {
        // len == remaining bytes exactly must succeed (off-by-one boundary).
        let data = [5, b'h', b'e', b'l', b'l', b'o'];
        assert_eq!(parse_txt_record(&data).unwrap(), vec!["hello"]);
    }

    #[test]
    fn parse_txt_record_empty() {
        let result = parse_txt_record(&[]).unwrap();
        assert!(result.is_empty());
    }

    // ── log_txt ──────────────────────────────────────────────────────────────

    #[test]
    fn log_txt_returns_true_for_well_formed_payload() {
        let data = [5, b'h', b'e', b'l', b'l', b'o'];
        assert!(log_txt("example.com", &data));
    }

    #[test]
    fn log_txt_returns_false_for_malformed_payload() {
        let data = [10, b'x'];
        assert!(!log_txt("example.com", &data));
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
