//! Hash the DNS question section for query deduplication.
//!
//! Ported from the `hash_questions` function in dnsmasq's `forward.c`.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

// Minimum DNS header size: 12 bytes (ID + flags + 4 × 16-bit counts).
const DNS_HEADER_LEN: usize = 12;

/// Hash the question section of a DNS packet for deduplication.
///
/// Returns a 128-bit digest (as `[u8; 16]`) covering the canonicalised qname
/// (lowercased labels), qtype, and qclass.  Returns `None` for packets that
/// are too short or structurally invalid.
pub fn hash_questions(pkt: &[u8]) -> Option<[u8; 16]> {
    if pkt.len() < DNS_HEADER_LEN {
        return None;
    }

    // Number of questions is in bytes 4–5 of the DNS header.
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    if qdcount == 0 {
        return None;
    }

    let mut h1 = DefaultHasher::new();
    let mut h2 = DefaultHasher::new();
    // Seed the two halves differently so we get a 128-bit output.
    0xdead_beef_u64.hash(&mut h1);
    0xcafe_babe_u64.hash(&mut h2);

    let mut pos = DNS_HEADER_LEN;

    for _ in 0..qdcount {
        // Canonicalise and hash qname label by label.
        loop {
            if pos >= pkt.len() {
                return None;
            }
            let len = pkt[pos] as usize;

            // Compression pointer — we do not follow it for hashing; treat as end.
            if (len & 0xC0) == 0xC0 {
                if pos + 1 >= pkt.len() {
                    return None;
                }
                pos += 2;
                break;
            }

            if len == 0 {
                // Root label: end of name.
                pos += 1;
                break;
            }

            pos += 1;
            if pos + len > pkt.len() {
                return None;
            }
            let label = &pkt[pos..pos + len];
            // Hash each byte lowercased for case-insensitive deduplication.
            for &b in label {
                let lc = b.to_ascii_lowercase();
                lc.hash(&mut h1);
                lc.hash(&mut h2);
            }
            // Separator so "foo.bar" ≠ "foob.ar".
            b'.'.hash(&mut h1);
            b'.'.hash(&mut h2);
            pos += len;
        }

        // qtype + qclass: 4 bytes.
        if pos + 4 > pkt.len() {
            return None;
        }
        let qtype  = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
        let qclass = u16::from_be_bytes([pkt[pos + 2], pkt[pos + 3]]);
        qtype.hash(&mut h1);
        qclass.hash(&mut h1);
        qtype.hash(&mut h2);
        qclass.hash(&mut h2);
        pos += 4;
    }

    let lo = h1.finish().to_le_bytes();
    let hi = h2.finish().to_le_bytes();
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&lo);
    out[8..].copy_from_slice(&hi);
    Some(out)
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DNS query packet: header + one question.
    fn make_query(qname: &str, qtype: u16, qclass: u16) -> Vec<u8> {
        let mut pkt = vec![
            0x00, 0x01, // ID = 1
            0x01, 0x00, // flags: standard query, recursion desired
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
        ];
        // Encode qname as DNS wire-format labels.
        for label in qname.split('.') {
            if label.is_empty() {
                continue;
            }
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0); // root label
        pkt.push((qtype >> 8) as u8);
        pkt.push((qtype & 0xFF) as u8);
        pkt.push((qclass >> 8) as u8);
        pkt.push((qclass & 0xFF) as u8);
        pkt
    }

    #[test]
    fn same_question_same_hash() {
        let a = make_query("example.com", 1, 1);
        let b = make_query("example.com", 1, 1);
        assert_eq!(hash_questions(&a), hash_questions(&b));
    }

    #[test]
    fn case_insensitive() {
        let a = make_query("Example.COM", 1, 1);
        let b = make_query("example.com", 1, 1);
        assert_eq!(hash_questions(&a), hash_questions(&b));
    }

    #[test]
    fn different_name_different_hash() {
        let a = make_query("example.com", 1, 1);
        let b = make_query("other.com", 1, 1);
        assert_ne!(hash_questions(&a), hash_questions(&b));
    }

    #[test]
    fn different_qtype_different_hash() {
        let a = make_query("example.com", 1 /*A*/, 1);
        let b = make_query("example.com", 28 /*AAAA*/, 1);
        assert_ne!(hash_questions(&a), hash_questions(&b));
    }

    #[test]
    fn different_qclass_different_hash() {
        let a = make_query("example.com", 1, 1 /*IN*/);
        let b = make_query("example.com", 1, 3 /*CH*/);
        assert_ne!(hash_questions(&a), hash_questions(&b));
    }

    #[test]
    fn truncated_packet_returns_none() {
        // Only 6 bytes — shorter than DNS_HEADER_LEN.
        assert_eq!(hash_questions(&[0u8; 6]), None);
    }

    #[test]
    fn empty_packet_returns_none() {
        assert_eq!(hash_questions(&[]), None);
    }

    #[test]
    fn zero_qdcount_returns_none() {
        // Valid header but QDCOUNT = 0.
        let pkt = vec![0u8; 12]; // all zeros → QDCOUNT = 0
        assert_eq!(hash_questions(&pkt), None);
    }

    #[test]
    fn truncated_question_returns_none() {
        // Header says QDCOUNT=1 but question body is truncated.
        let mut pkt = vec![
            0x00, 0x01, 0x01, 0x00,
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        pkt.push(7); // label length = 7 but no label bytes follow
        assert_eq!(hash_questions(&pkt), None);
    }
}
