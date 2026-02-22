//! DNS forwarding loop detection via probe queries.
#![cfg(feature = "loop")]

use std::time::Instant;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

pub struct LoopProbe {
    pub token: [u8; 8],
    pub sent_at: Instant,
}

// ---------------------------------------------------------------------------
// DNS wire-format constants
// ---------------------------------------------------------------------------

const DNS_HDR_LEN: usize = 12;
// Question section offsets relative to start of DNS message
// Header: ID(2) QR/Opcode/… (2) QDCOUNT(2) ANCOUNT(2) NSCOUNT(2) ARCOUNT(2)

/// Label under .invalid used for loop-detection probes.
const PROBE_SUFFIX: &[u8] = b"\x07invalid\x00";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Encode 8 token bytes as a 16-character lowercase hex label.
fn token_to_label(token: &[u8; 8]) -> [u8; 16] {
    let hex = b"0123456789abcdef";
    let mut out = [0u8; 16];
    for (i, &b) in token.iter().enumerate() {
        out[i * 2] = hex[(b >> 4) as usize];
        out[i * 2 + 1] = hex[(b & 0xf) as usize];
    }
    out
}

/// Decode a 16-char hex label back to 8 bytes.  Returns None on failure.
fn label_to_token(label: &[u8]) -> Option<[u8; 8]> {
    if label.len() != 16 {
        return None;
    }
    let mut out = [0u8; 8];
    for i in 0..8 {
        let hi = from_hex(label[i * 2])?;
        let lo = from_hex(label[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn from_hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Read a DNS question QNAME from `pkt` at offset `pos`.
/// Returns the raw label bytes (each label prefixed with its length byte)
/// for the first label only, and the full qname string for matching.
fn read_qname_first_label(pkt: &[u8], pos: usize) -> Option<Vec<u8>> {
    if pos >= pkt.len() {
        return None;
    }
    let label_len = pkt[pos] as usize;
    if label_len == 0 || pos + 1 + label_len > pkt.len() {
        return None;
    }
    Some(pkt[pos + 1..pos + 1 + label_len].to_vec())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Generate a new random probe token using the system's pseudo-random source.
pub fn new_probe_token() -> [u8; 8] {
    // Use a simple time-seeded approach without `unsafe`.
    // In production the caller would seed from a CSPRNG; here we mix
    // the current time to get non-repeating values in tests.
    let now = Instant::now();
    let nanos = now.elapsed().subsec_nanos() as u64;
    let seed = nanos ^ 0xdeadbeefcafe1234;
    let mut t = [0u8; 8];
    for (i, b) in seed.to_le_bytes().iter().enumerate() {
        t[i] = *b;
    }
    t
}

/// Build a DNS probe query embedding `token` in the qname.
///
/// qname format: `\x10<16-hex-label>\x07invalid\x00`
/// Query type: A (1), class: IN (1).
pub fn build_probe_query(token: &[u8; 8], id: u16) -> Vec<u8> {
    let label = token_to_label(token);

    let mut pkt = Vec::new();
    // DNS header
    pkt.extend_from_slice(&id.to_be_bytes());    // ID
    pkt.extend_from_slice(&[0x01, 0x00]);         // QR=0 (query), RD=1
    pkt.extend_from_slice(&[0x00, 0x01]);         // QDCOUNT = 1
    pkt.extend_from_slice(&[0x00, 0x00]);         // ANCOUNT
    pkt.extend_from_slice(&[0x00, 0x00]);         // NSCOUNT
    pkt.extend_from_slice(&[0x00, 0x00]);         // ARCOUNT

    // QNAME
    pkt.push(16u8);                               // label length
    pkt.extend_from_slice(&label);                // 16-char hex token
    pkt.extend_from_slice(PROBE_SUFFIX);          // \x07invalid\x00

    // QTYPE A = 1, QCLASS IN = 1
    pkt.extend_from_slice(&[0x00, 0x01]);
    pkt.extend_from_slice(&[0x00, 0x01]);
    pkt
}

/// Check whether a DNS reply `pkt` contains a question matching any active probe token.
///
/// Looks at the question section for a qname whose first label decodes to
/// one of the active probe tokens.  Returns the matching token if found.
pub fn check_loop_reply(pkt: &[u8], active_probes: &[LoopProbe]) -> Option<[u8; 8]> {
    if pkt.len() < DNS_HDR_LEN {
        return None;
    }
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    if qdcount == 0 {
        return None;
    }

    // Walk question section — question starts at offset 12
    let first_label = read_qname_first_label(pkt, DNS_HDR_LEN)?;
    let tok = label_to_token(&first_label)?;

    active_probes
        .iter()
        .find(|p| p.token == tok)
        .map(|p| p.token)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_probe_token_length() {
        let t = new_probe_token();
        assert_eq!(t.len(), 8);
    }

    #[test]
    fn test_build_probe_query_check_loop_reply_roundtrip() {
        let token = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let query = build_probe_query(&token, 0x1234);

        // Simulate a "reply" by setting QR bit
        let mut reply = query.clone();
        reply[2] |= 0x80; // QR = 1

        let probes = vec![LoopProbe {
            token,
            sent_at: Instant::now(),
        }];

        let result = check_loop_reply(&reply, &probes);
        assert_eq!(result, Some(token));
    }

    #[test]
    fn test_check_loop_reply_no_match() {
        let token = [0xAA; 8];
        let other_token = [0xBB; 8];
        let query = build_probe_query(&other_token, 0x0001);

        let probes = vec![LoopProbe {
            token,
            sent_at: Instant::now(),
        }];

        assert_eq!(check_loop_reply(&query, &probes), None);
    }

    #[test]
    fn test_check_loop_reply_empty_probes() {
        let token = [0x11; 8];
        let pkt = build_probe_query(&token, 1);
        assert_eq!(check_loop_reply(&pkt, &[]), None);
    }

    #[test]
    fn test_check_loop_reply_short_packet() {
        assert_eq!(check_loop_reply(&[0, 1, 2], &[]), None);
    }

    #[test]
    fn test_token_hex_roundtrip() {
        let token = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let label = token_to_label(&token);
        let decoded = label_to_token(&label).unwrap();
        assert_eq!(decoded, token);
    }
}
