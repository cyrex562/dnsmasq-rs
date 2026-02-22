//! DNS resource record filtering.
//!
//! Provides utilities to strip RRs from a DNS packet by type.
//! Ported from `rrfilter.c` in dnsmasq.

use crate::dns_protocol::{DnsHeader, RrType};
use crate::rfc1035::{DnsError, skip_name};

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Advance `*offset` past `count` DNS questions and return the new offset.
fn skip_questions_to(pkt: &[u8], offset: &mut usize, count: u16) -> Result<(), DnsError> {
    for _ in 0..count {
        skip_name(pkt, offset)?;
        if *offset + 4 > pkt.len() {
            return Err(DnsError::PacketTooShort);
        }
        *offset += 4;
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Remove all RRs whose wire TYPE value is in `remove_types` from the
/// answer, authority, and additional sections of `pkt`.
///
/// Returns the new (possibly shorter) packet bytes.
///
/// # Notes
/// * The question section is left untouched.
/// * Section counts in the header are updated to match the filtered result.
/// * Name compression pointers in retained RRs are preserved verbatim; pointers
///   that referred only to removed RRs are not rewritten (this is safe for the
///   common cases — OPT and DNSSEC — that this function is used for).
pub fn filter_rr_types(pkt: &[u8], remove_types: &[u16]) -> Result<Vec<u8>, DnsError> {
    if pkt.len() < 12 {
        return Err(DnsError::PacketTooShort);
    }
    if remove_types.is_empty() {
        return Ok(pkt.to_vec());
    }

    let hdr = DnsHeader::from_bytes(pkt).ok_or(DnsError::PacketTooShort)?;

    // Locate start of RR sections (right after the question section).
    let mut rr_start = 12usize;
    skip_questions_to(pkt, &mut rr_start, hdr.qdcount)?;

    // Collect (start, end, rtype) for every RR.
    let total = hdr.ancount as usize + hdr.nscount as usize + hdr.arcount as usize;
    let mut rr_info: Vec<(usize, usize, u16)> = Vec::with_capacity(total);
    let mut offset = rr_start;

    for _ in 0..total {
        let start = offset;
        skip_name(pkt, &mut offset)?;
        if offset + 10 > pkt.len() {
            return Err(DnsError::PacketTooShort);
        }
        let rtype = u16::from_be_bytes([pkt[offset], pkt[offset + 1]]);
        let rdlen = u16::from_be_bytes([pkt[offset + 8], pkt[offset + 9]]) as usize;
        offset += 10 + rdlen;
        if offset > pkt.len() {
            return Err(DnsError::UnexpectedEof);
        }
        rr_info.push((start, offset, rtype));
    }

    // Build output: header + questions + kept RRs.
    let mut result = pkt[..rr_start].to_vec(); // header + question section
    let mut new_an = hdr.ancount;
    let mut new_ns = hdr.nscount;
    let mut new_ar = hdr.arcount;

    for (i, (start, end, rtype)) in rr_info.iter().enumerate() {
        if remove_types.contains(rtype) {
            if i < hdr.ancount as usize {
                new_an -= 1;
            } else if i < (hdr.ancount + hdr.nscount) as usize {
                new_ns -= 1;
            } else {
                new_ar -= 1;
            }
        } else {
            result.extend_from_slice(&pkt[*start..*end]);
        }
    }

    // Patch section counts.
    result[6]  = (new_an >> 8) as u8;
    result[7]  = (new_an & 0xFF) as u8;
    result[8]  = (new_ns >> 8) as u8;
    result[9]  = (new_ns & 0xFF) as u8;
    result[10] = (new_ar >> 8) as u8;
    result[11] = (new_ar & 0xFF) as u8;

    Ok(result)
}

/// Remove DNSSEC records (RRSIG, NSEC, NSEC3, DNSKEY) from a packet,
/// **unless** the DO bit is set in the OPT RR.
pub fn strip_dnssec_if_not_requested(pkt: &[u8]) -> Result<Vec<u8>, DnsError> {
    // Check the DO bit via the edns0 module.
    if let Some(info) = crate::edns0::find_pseudoheader(pkt) {
        if info.flags & 0x8000 != 0 {
            return Ok(pkt.to_vec());
        }
    }

    const DNSSEC_TYPES: &[u16] = &[
        RrType::RRSIG  as u16,
        RrType::NSEC   as u16,
        RrType::NSEC3  as u16,
        RrType::DNSKEY as u16,
    ];

    filter_rr_types(pkt, DNSSEC_TYPES)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_protocol::RrType;
    use crate::rfc1035::{write_name, write_rr, DnsRr};
    use bytes::BytesMut;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn make_rr(name: &str, rtype: u16, rdata: &[u8]) -> Vec<u8> {
        let rr = DnsRr {
            name: name.to_owned(),
            rtype,
            class: 1,
            ttl: 300,
            rdata: rdata.to_vec(),
        };
        let mut buf = BytesMut::new();
        write_rr(&mut buf, &rr);
        buf.to_vec()
    }

    /// Build a minimal response packet with the given RRs in the answer section.
    fn response_with_answers(rrs: &[Vec<u8>]) -> Vec<u8> {
        let ancount = rrs.len() as u16;
        let mut pkt = vec![
            0x00, 0x01, // ID
            0x81, 0x80, // flags: QR+RD+RA
            0x00, 0x01, // QDCOUNT=1
            (ancount >> 8) as u8, (ancount & 0xFF) as u8,
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00, // ARCOUNT=0
        ];
        // Question: example.com A IN
        pkt.extend_from_slice(b"\x07example\x03com\x00");
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        for rr in rrs {
            pkt.extend_from_slice(rr);
        }
        pkt
    }

    // ── filter_rr_types ───────────────────────────────────────────────────────

    #[test]
    fn filter_removes_matching_rr() {
        let a_rr   = make_rr("example.com", RrType::A as u16, &[1, 2, 3, 4]);
        let txt_rr = make_rr("example.com", RrType::TXT as u16, b"\x05hello");
        let pkt = response_with_answers(&[a_rr, txt_rr]);

        let hdr_before = DnsHeader::from_bytes(&pkt).unwrap();
        assert_eq!(hdr_before.ancount, 2);

        let filtered = filter_rr_types(&pkt, &[RrType::TXT as u16]).unwrap();
        let hdr_after = DnsHeader::from_bytes(&filtered).unwrap();
        assert_eq!(hdr_after.ancount, 1);
    }

    #[test]
    fn filter_is_idempotent() {
        let a_rr   = make_rr("example.com", RrType::A as u16, &[1, 2, 3, 4]);
        let txt_rr = make_rr("example.com", RrType::TXT as u16, b"\x05hello");
        let pkt = response_with_answers(&[a_rr, txt_rr]);

        let once  = filter_rr_types(&pkt, &[RrType::TXT as u16]).unwrap();
        let twice = filter_rr_types(&once, &[RrType::TXT as u16]).unwrap();
        assert_eq!(once, twice);
    }

    #[test]
    fn filter_absent_type_returns_unchanged() {
        let a_rr = make_rr("example.com", RrType::A as u16, &[1, 2, 3, 4]);
        let pkt = response_with_answers(&[a_rr]);

        let filtered = filter_rr_types(&pkt, &[RrType::TXT as u16]).unwrap();
        // Packet bytes should be identical when nothing was removed.
        assert_eq!(pkt, filtered);
    }

    #[test]
    fn filter_empty_remove_list() {
        let pkt = response_with_answers(&[]);
        let result = filter_rr_types(&pkt, &[]).unwrap();
        assert_eq!(pkt, result);
    }

    #[test]
    fn filter_too_short_returns_err() {
        assert!(filter_rr_types(&[0u8; 4], &[1]).is_err());
    }

    // ── strip_dnssec_if_not_requested ─────────────────────────────────────────

    /// Append an OPT RR with the given flags to a packet.
    fn append_opt(mut pkt: Vec<u8>, udp_size: u16, flags: u16) -> Vec<u8> {
        pkt.push(0x00); // root name
        pkt.extend_from_slice(&(RrType::OPT as u16).to_be_bytes());
        pkt.extend_from_slice(&udp_size.to_be_bytes());
        pkt.push(0); pkt.push(0); // ext_rcode + version
        pkt.extend_from_slice(&flags.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes()); // rdlen=0
        let ar = u16::from_be_bytes([pkt[10], pkt[11]]) + 1;
        pkt[10] = (ar >> 8) as u8;
        pkt[11] = (ar & 0xFF) as u8;
        pkt
    }

    #[test]
    fn strip_dnssec_removes_rrsig_when_do_not_set() {
        let a_rr     = make_rr("example.com", RrType::A     as u16, &[1, 2, 3, 4]);
        let rrsig_rr = make_rr("example.com", RrType::RRSIG as u16, &[0xde, 0xad]);
        let base = response_with_answers(&[a_rr, rrsig_rr]);
        // OPT with DO=0
        let pkt = append_opt(base, 4096, 0x0000);

        let stripped = strip_dnssec_if_not_requested(&pkt).unwrap();
        let hdr = DnsHeader::from_bytes(&stripped).unwrap();
        assert_eq!(hdr.ancount, 1); // only A record remains
    }

    #[test]
    fn strip_dnssec_keeps_rrsig_when_do_set() {
        let a_rr     = make_rr("example.com", RrType::A     as u16, &[1, 2, 3, 4]);
        let rrsig_rr = make_rr("example.com", RrType::RRSIG as u16, &[0xde, 0xad]);
        let base = response_with_answers(&[a_rr, rrsig_rr]);
        // OPT with DO=1 (flags = 0x8000)
        let pkt = append_opt(base, 4096, 0x8000);

        let result = strip_dnssec_if_not_requested(&pkt).unwrap();
        let hdr = DnsHeader::from_bytes(&result).unwrap();
        assert_eq!(hdr.ancount, 2); // both records kept
    }

    #[test]
    fn strip_dnssec_no_opt_removes_dnssec() {
        let a_rr    = make_rr("example.com", RrType::A    as u16, &[1, 2, 3, 4]);
        let nsec_rr = make_rr("example.com", RrType::NSEC as u16, &[0xbe, 0xef]);
        let pkt = response_with_answers(&[a_rr, nsec_rr]);

        let stripped = strip_dnssec_if_not_requested(&pkt).unwrap();
        let hdr = DnsHeader::from_bytes(&stripped).unwrap();
        assert_eq!(hdr.ancount, 1);
    }

    #[test]
    fn strip_dnssec_removes_all_four_types() {
        let rrs = vec![
            make_rr("example.com", RrType::A      as u16, &[1, 2, 3, 4]),
            make_rr("example.com", RrType::RRSIG  as u16, &[0x01]),
            make_rr("example.com", RrType::NSEC   as u16, &[0x02]),
            make_rr("example.com", RrType::NSEC3  as u16, &[0x03]),
            make_rr("example.com", RrType::DNSKEY as u16, &[0x04]),
        ];
        let pkt = response_with_answers(&rrs);
        let stripped = strip_dnssec_if_not_requested(&pkt).unwrap();
        let hdr = DnsHeader::from_bytes(&stripped).unwrap();
        assert_eq!(hdr.ancount, 1); // only A remains
    }
}
