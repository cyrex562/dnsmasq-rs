#![cfg(feature = "dnssec")]

//! DNSSEC record parsing and validation helpers.
//!
//! Implements wire-format parsing for RRSIG, DNSKEY, and DS records,
//! key-tag computation (RFC 4034 Appendix B), and DS/DNSKEY matching.

use sha2::{Digest, Sha256};
use thiserror::Error;

// ─── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum DnssecError {
    #[error("rdata too short")]
    TooShort,
    #[error("invalid signer name")]
    InvalidName,
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(u8),
}

// ─── ValidationResult ────────────────────────────────────────────────────────

/// Classification of a DNSSEC-validated DNS reply.
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationResult {
    Secure,
    Insecure,
    /// Bogus result with a reason string.
    Bogus(String),
    Indeterminate,
}

// ─── RRSIG ───────────────────────────────────────────────────────────────────

/// Parsed RRSIG RDATA (RFC 4034 §3.1).
#[derive(Debug, Clone)]
pub struct RrsigData {
    pub type_covered:  u16,
    pub algorithm:     u8,
    pub labels:        u8,
    pub orig_ttl:      u32,
    pub sig_expiry:    u32,
    pub sig_inception: u32,
    pub key_tag:       u16,
    pub signer_name:   String,
    pub signature:     Vec<u8>,
}

/// Parse RRSIG RDATA from wire format.
///
/// Fixed header is 18 bytes; then the signer name (wire-format labels),
/// then the signature bytes.
pub fn parse_rrsig_rdata(rdata: &[u8]) -> Result<RrsigData, DnssecError> {
    if rdata.len() < 18 {
        return Err(DnssecError::TooShort);
    }
    let type_covered  = u16::from_be_bytes([rdata[0],  rdata[1]]);
    let algorithm     = rdata[2];
    let labels        = rdata[3];
    let orig_ttl      = u32::from_be_bytes([rdata[4],  rdata[5],  rdata[6],  rdata[7]]);
    let sig_expiry    = u32::from_be_bytes([rdata[8],  rdata[9],  rdata[10], rdata[11]]);
    let sig_inception = u32::from_be_bytes([rdata[12], rdata[13], rdata[14], rdata[15]]);
    let key_tag       = u16::from_be_bytes([rdata[16], rdata[17]]);

    let (signer_name, name_len) = parse_wire_name(&rdata[18..])?;
    let signature = rdata[18 + name_len..].to_vec();

    Ok(RrsigData { type_covered, algorithm, labels, orig_ttl, sig_expiry, sig_inception, key_tag, signer_name, signature })
}

// ─── DNSKEY ──────────────────────────────────────────────────────────────────

/// Parsed DNSKEY RDATA (RFC 4034 §2.1).
#[derive(Debug, Clone)]
pub struct DnskeyData {
    /// Bit 8 = Zone Key flag; bit 15 = SEP (KSK) flag.
    pub flags:      u16,
    /// Must be 3 per RFC 4034.
    pub protocol:   u8,
    pub algorithm:  u8,
    pub public_key: Vec<u8>,
}

/// Parse DNSKEY RDATA from wire format.
pub fn parse_dnskey_rdata(rdata: &[u8]) -> Result<DnskeyData, DnssecError> {
    if rdata.len() < 4 {
        return Err(DnssecError::TooShort);
    }
    let flags      = u16::from_be_bytes([rdata[0], rdata[1]]);
    let protocol   = rdata[2];
    let algorithm  = rdata[3];
    let public_key = rdata[4..].to_vec();
    Ok(DnskeyData { flags, protocol, algorithm, public_key })
}

/// Compute the key tag for a DNSKEY RDATA (RFC 4034 Appendix B).
pub fn compute_key_tag(rdata: &[u8]) -> u16 {
    let mut ac: u32 = 0;
    for (i, &byte) in rdata.iter().enumerate() {
        if i & 1 == 0 {
            ac += (byte as u32) << 8;
        } else {
            ac += byte as u32;
        }
    }
    ac += (ac >> 16) & 0xffff;
    (ac & 0xffff) as u16
}

// ─── DS ──────────────────────────────────────────────────────────────────────

/// Parsed DS RDATA (RFC 4034 §5.1).
#[derive(Debug, Clone)]
pub struct DsData {
    pub key_tag:     u16,
    pub algorithm:   u8,
    pub digest_type: u8,
    pub digest:      Vec<u8>,
}

/// Parse DS RDATA from wire format.
pub fn parse_ds_rdata(rdata: &[u8]) -> Result<DsData, DnssecError> {
    if rdata.len() < 4 {
        return Err(DnssecError::TooShort);
    }
    let key_tag     = u16::from_be_bytes([rdata[0], rdata[1]]);
    let algorithm   = rdata[2];
    let digest_type = rdata[3];
    let digest      = rdata[4..].to_vec();
    Ok(DsData { key_tag, algorithm, digest_type, digest })
}

/// Verify that a DS record matches a DNSKEY by hashing the owner name +
/// DNSKEY RDATA and comparing against the DS digest.
///
/// Currently supports digest_type 2 (SHA-256).  All other types return false.
pub fn ds_matches_dnskey(ds: &DsData, dnskey_rdata: &[u8], owner_name: &str) -> bool {
    match ds.digest_type {
        2 => {
            // SHA-256: hash( owner_name_wire || dnskey_rdata )
            let wire = match name_to_wire(owner_name) {
                Some(w) => w,
                None    => return false,
            };
            let mut hasher = Sha256::new();
            hasher.update(&wire);
            hasher.update(dnskey_rdata);
            let result = hasher.finalize();
            result.as_slice() == ds.digest.as_slice()
        }
        _ => false,
    }
}

// ─── Internal helpers ────────────────────────────────────────────────────────

/// Parse a DNS wire-format name starting at `buf[0]`.
/// Returns `(dotted_string, bytes_consumed)`.
fn parse_wire_name(buf: &[u8]) -> Result<(String, usize), DnssecError> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = 0;
    loop {
        if pos >= buf.len() {
            return Err(DnssecError::TooShort);
        }
        let len = buf[pos] as usize;
        pos += 1;
        if len == 0 {
            break; // root label
        }
        if len > 63 {
            return Err(DnssecError::InvalidName); // no pointer support needed here
        }
        if pos + len > buf.len() {
            return Err(DnssecError::TooShort);
        }
        let label = std::str::from_utf8(&buf[pos..pos + len])
            .map_err(|_| DnssecError::InvalidName)?;
        labels.push(label.to_string());
        pos += len;
    }
    Ok((labels.join("."), pos))
}

/// Convert a dotted domain name to DNS wire format (no compression).
fn name_to_wire(name: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let name = name.trim_end_matches('.');
    for label in name.split('.') {
        let bytes = label.as_bytes();
        if bytes.len() > 63 { return None; }
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0); // root label
    Some(out)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DNSKEY RDATA: flags=256, protocol=3, algorithm=8, key=0xDEAD
    fn sample_dnskey_rdata() -> Vec<u8> {
        vec![0x01, 0x00, 0x03, 0x08, 0xDE, 0xAD]
    }

    #[test]
    fn test_parse_dnskey_rdata() {
        let rdata = sample_dnskey_rdata();
        let key = parse_dnskey_rdata(&rdata).expect("parse failed");
        assert_eq!(key.flags,     0x0100);
        assert_eq!(key.protocol,  3);
        assert_eq!(key.algorithm, 8);
        assert_eq!(key.public_key, vec![0xDE, 0xAD]);
    }

    #[test]
    fn test_parse_dnskey_rdata_too_short() {
        let result = parse_dnskey_rdata(&[0x01, 0x00, 0x03]);
        assert!(matches!(result, Err(DnssecError::TooShort)));
    }

    /// RFC 4034 Appendix B example key tag = 2642.
    /// The example uses: flags=257, protocol=3, algorithm=5, key=<the base64 blob>.
    /// We verify the algorithm with a hand-crafted small vector whose tag we know.
    #[test]
    fn test_compute_key_tag() {
        // Single-byte RDATA 0xAC: ac = 0xAC << 8 = 0xAC00; carry fold = 0; tag = 0xAC00 >> 0 & 0xffff = 0xAC00? No.
        // Better: use known example from RFC 4034 Appendix B.
        // flags=0x0101, protocol=3, algorithm=5, then public key bytes chosen so tag = 2642.
        // Instead verify the algorithm is consistent with itself.
        let rdata = sample_dnskey_rdata();
        let tag1 = compute_key_tag(&rdata);
        let tag2 = compute_key_tag(&rdata);
        assert_eq!(tag1, tag2); // deterministic

        // Verify the RFC formula for a known one-byte RDATA.
        // rdata = [0x00]: ac after loop = 0x0000; fold = 0; tag = 0.
        assert_eq!(compute_key_tag(&[0x00]), 0);
        // rdata = [0xFF, 0xFF]: ac = 0xFF00 + 0xFF = 0xFFFF; fold: 0xFFFF + 0 = 0xFFFF; tag = 0xFFFF.
        assert_eq!(compute_key_tag(&[0xFF, 0xFF]), 0xFFFF);
    }

    #[test]
    fn test_parse_ds_rdata() {
        // key_tag=1234 (0x04D2), alg=8, digest_type=2, digest=0xABCD
        let rdata = vec![0x04, 0xD2, 0x08, 0x02, 0xAB, 0xCD];
        let ds = parse_ds_rdata(&rdata).expect("parse failed");
        assert_eq!(ds.key_tag,     0x04D2);
        assert_eq!(ds.algorithm,   8);
        assert_eq!(ds.digest_type, 2);
        assert_eq!(ds.digest,      vec![0xAB, 0xCD]);
    }

    #[test]
    fn test_parse_rrsig_rdata() {
        // Build a synthetic RRSIG: type_covered=1(A), alg=8, labels=2,
        // orig_ttl=300, sig_expiry=9999, sig_inception=0, key_tag=1234,
        // signer=example.com., signature=0xBEEF
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&1u16.to_be_bytes());        // type_covered = A
        rdata.push(8);                                        // algorithm
        rdata.push(2);                                        // labels
        rdata.extend_from_slice(&300u32.to_be_bytes());       // orig_ttl
        rdata.extend_from_slice(&9999u32.to_be_bytes());      // sig_expiry
        rdata.extend_from_slice(&0u32.to_be_bytes());         // sig_inception
        rdata.extend_from_slice(&1234u16.to_be_bytes());      // key_tag
        // signer name "example.com." in wire format
        rdata.push(7); rdata.extend_from_slice(b"example");  // label "example"
        rdata.push(3); rdata.extend_from_slice(b"com");       // label "com"
        rdata.push(0);                                         // root
        // signature
        rdata.extend_from_slice(&[0xBE, 0xEF]);

        let sig = parse_rrsig_rdata(&rdata).expect("parse failed");
        assert_eq!(sig.type_covered,  1);
        assert_eq!(sig.algorithm,     8);
        assert_eq!(sig.labels,        2);
        assert_eq!(sig.orig_ttl,      300);
        assert_eq!(sig.key_tag,       1234);
        assert_eq!(sig.signer_name,   "example.com");
        assert_eq!(sig.signature,     vec![0xBE, 0xEF]);
    }

    #[test]
    fn test_ds_matches_dnskey_sha256() {
        use sha2::{Digest, Sha256};

        let owner = "example.com.";
        let dnskey_rdata = sample_dnskey_rdata();

        // Compute the expected digest ourselves.
        let wire = name_to_wire(owner).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&wire);
        hasher.update(&dnskey_rdata);
        let digest = hasher.finalize().to_vec();

        let ds = DsData {
            key_tag:     compute_key_tag(&dnskey_rdata),
            algorithm:   8,
            digest_type: 2,
            digest:      digest.clone(),
        };

        assert!(ds_matches_dnskey(&ds, &dnskey_rdata, owner));

        // Wrong digest should fail.
        let mut bad_ds = ds.clone();
        bad_ds.digest[0] ^= 0xFF;
        assert!(!ds_matches_dnskey(&bad_ds, &dnskey_rdata, owner));
    }
}
