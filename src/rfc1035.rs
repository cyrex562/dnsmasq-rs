//! DNS packet parser — Rust port of dnsmasq's `rfc1035.c`.
//!
//! Provides wire-format encode/decode for DNS messages: names, questions,
//! resource records, and full packets.  No `unsafe` code; no C FFI.

use bytes::{BufMut, BytesMut};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::dns_protocol::{DnsHeader, RrType};
use crate::types::addr::AllAddr;

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
    let rdata = pkt[*offset..*offset + rdlen].to_vec();
    *offset += rdlen;
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
// Tests
// ──────────────────────────────────────────────────────────────────────────────

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
}
