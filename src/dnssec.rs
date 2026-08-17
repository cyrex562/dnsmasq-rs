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

// ─── Low-level DNSSEC helpers ─────────────────────────────────────────────────

/// Count the number of labels in a DNS name.
///
/// A label is a dot-separated component.  The root label (empty string) returns
/// 0.  A leading dot (e.g. `.foo.example`) is not counted.
/// Mirrors C's `count_labels()` in `dnssec.c`.
///
/// # Examples
/// ```ignore
/// assert_eq!(count_labels("example.com"), 2);
/// assert_eq!(count_labels("a.b.c.d"),     4);
/// assert_eq!(count_labels(""),            0);
/// ```
pub fn count_labels(name: &str) -> u32 {
    if name.is_empty() {
        return 0;
    }
    let dots = name.chars().filter(|&c| c == '.').count() as u32;
    // A leading dot is not a label separator for the first label.
    if name.starts_with('.') { dots } else { dots + 1 }
}

/// RFC 1982 32-bit serial number comparison result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerialCmp {
    Equal,
    Less,
    Greater,
    Undefined,
}

/// RFC 1982 §3.2 wrapped comparison for 32-bit sequence numbers.
///
/// Mirrors C's `serial_compare_32()`.
pub fn serial_compare_32(s1: u32, s2: u32) -> SerialCmp {
    if s1 == s2 {
        return SerialCmp::Equal;
    }
    let lt = (s1 < s2 && (s2.wrapping_sub(s1)) < (1u32 << 31))
        || (s1 > s2 && (s1.wrapping_sub(s2)) > (1u32 << 31));
    let gt = (s1 < s2 && (s2.wrapping_sub(s1)) > (1u32 << 31))
        || (s1 > s2 && (s1.wrapping_sub(s2)) < (1u32 << 31));
    if lt { SerialCmp::Less }
    else if gt { SerialCmp::Greater }
    else { SerialCmp::Undefined }
}

/// Decrement a work-limit counter.
///
/// Returns `true` (counter exceeded) if the counter was already 0 before
/// decrement, `false` otherwise.  The caller supplies the counter; callers
/// typically pass a per-query crypto-work budget.
///
/// Mirrors C's `dec_counter()`.
pub fn dec_counter(counter: &mut i32) -> bool {
    if *counter == 0 {
        return true; // limit exceeded
    }
    *counter -= 1;
    false
}

/// Decode a base-32 extended hex string (RFC 4648 §7, used by NSEC3) into bytes.
///
/// Decodes up to the first `'.'` or end-of-string.  Returns `None` if the
/// input contains invalid characters or the bit count is not a multiple of 8.
///
/// Mirrors C's `base32_decode()` in `dnssec.c` which uses the extended-hex
/// alphabet `0–9 A–V` (case insensitive).
pub fn base32_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut oc: u32 = 0; // accumulator
    let mut on: u32 = 0; // bits accumulated so far

    for ch in input.chars().take_while(|&c| c != '.') {
        let val: u32 = match ch {
            '0'..='9' => (ch as u32) - ('0' as u32),
            'a'..='v' => (ch as u32) - ('a' as u32) + 10,
            'A'..='V' => (ch as u32) - ('A' as u32) + 10,
            _         => return None,
        };
        // Each base-32 symbol is 5 bits; accumulate MSB-first.
        for i in (0..5).rev() {
            oc <<= 1;
            if val & (1 << i) != 0 {
                oc |= 1;
            }
            on += 1;
            if on & 7 == 0 {
                out.push(oc as u8);
                oc = 0;
            }
        }
    }

    if (on & 7) != 0 {
        return None; // incomplete byte
    }
    Some(out)
}

/// Hash a DNS owner name for NSEC3 (RFC 5155 §5).
///
/// Applies the hash algorithm `hash_fn` to the wire-format owner name,
/// followed by `salt`, then iterates `iterations` more times.
/// Returns the digest bytes, or `None` if the name is invalid.
///
/// Mirrors C's `hash_name()` (but without the nettle abstraction — here the
/// caller provides a closure that behaves like a digest function).
///
/// The canonical use-case is SHA-1: pass `|data| sha1(data)`.
pub fn hash_name<F>(name: &str, salt: &[u8], iterations: u32, mut hash_fn: F) -> Option<Vec<u8>>
where
    F: FnMut(&[u8]) -> Vec<u8>,
{
    let wire = name_to_wire(name)?;
    let mut input: Vec<u8> = wire;
    input.extend_from_slice(salt);
    let mut digest = hash_fn(&input);

    for _ in 0..iterations {
        let mut next_input = digest;
        next_input.extend_from_slice(salt);
        digest = hash_fn(&next_input);
    }

    Some(digest)
}

// ─── RRset canonical ordering & exploration ───────────────────────────────────

/// Sort a slice of RRs from the same RRset into the canonical wire-format order
/// defined by RFC 4034 §6.3.
///
/// The canonical order compares the RDATA bytes lexicographically.  Duplicate
/// RRs (identical RDATA) are removed (RFC 4034 §6.3 requires de-duplication
/// before signing).
///
/// The sort is stable with respect to equal RDATA.
///
/// Mirrors `sort_rrset()` from `dnssec.c`.
pub fn sort_rrset(rrset: &mut Vec<crate::rfc1035::DnsRr>) {
    // Bubble-sort with de-duplication, matching the C implementation.
    loop {
        let mut swapped = false;
        let mut i = 0;
        while i + 1 < rrset.len() {
            match rrset[i].rdata.cmp(&rrset[i + 1].rdata) {
                std::cmp::Ordering::Greater => {
                    rrset.swap(i, i + 1);
                    swapped = true;
                    i += 1;
                }
                std::cmp::Ordering::Equal => {
                    // De-duplicate: remove the later copy.
                    rrset.remove(i + 1);
                    // Don't advance i; re-examine position i with the new i+1.
                }
                std::cmp::Ordering::Less => {
                    i += 1;
                }
            }
        }
        if !swapped { break; }
    }
}

/// Partition `records` into the **RRset** (records whose type equals `rrtype`
/// and class equals `rrclass` and name case-insensitively equals `name`) and
/// the associated **RRSIG** records that cover that type.
///
/// Returns `(rrset, rrsigs)`.  The RRSIG slice contains only those signatures
/// whose `type_covered` field matches `rrtype` and whose signer name is equal
/// to or encloses `name` (RFC 4035 §5.3.1).
///
/// Mirrors `explore_rrset()` from `dnssec.c`, but without global mutable
/// arrays; all output is returned as owned `Vec`s.
pub fn explore_rrset<'a>(
    records:  &'a [crate::rfc1035::DnsRr],
    name:     &str,
    rrclass:  u16,
    rrtype:   u16,
) -> (Vec<&'a crate::rfc1035::DnsRr>, Vec<&'a crate::rfc1035::DnsRr>) {
    const T_RRSIG: u16 = 46;

    let name_lower = name.to_lowercase();

    let mut rrset: Vec<&crate::rfc1035::DnsRr> = Vec::new();
    let mut rrsigs: Vec<&crate::rfc1035::DnsRr> = Vec::new();

    for rr in records {
        if rr.name.to_lowercase() != name_lower || rr.class != rrclass {
            continue;
        }
        if rr.rtype == rrtype {
            rrset.push(rr);
            continue;
        }
        if rr.rtype == T_RRSIG && rr.rdata.len() >= 18 {
            // type_covered is the first two bytes of RRSIG RDATA.
            let tc = u16::from_be_bytes([rr.rdata[0], rr.rdata[1]]);
            if tc != rrtype { continue; }

            // Parse the signer name (starts at byte 18 in RRSIG RDATA).
            if let Ok((signer, _)) = parse_wire_name(&rr.rdata[18..]) {
                // RFC 4035 §5.3.1: signer name must be equal to or enclose the
                // owner name (i.e., owner is a sub-domain of the signer).
                let signer_lower = signer.to_lowercase();
                let is_root_or_subdomain = signer_lower.is_empty()
                    || name_lower == signer_lower
                    || name_lower.ends_with(&format!(".{}", signer_lower));
                if is_root_or_subdomain {
                    rrsigs.push(rr);
                }
            }
        }
    }

    (rrset, rrsigs)
}

/// Result of an RRset validation attempt.
#[derive(Debug, Clone, PartialEq)]
pub enum RrsetValidation {
    /// At least one RRSIG verified correctly.
    Secure {
        /// TTL to use (minimum of record and RRSIG origTTL, capped by
        /// remaining sig validity window).
        ttl: u32,
        /// Key tag of the DNSKEY that verified the signature.
        key_tag: u16,
    },
    /// A DNSKEY is needed to continue validation.
    NeedKey { signer: String, key_tag: u16 },
    /// All signatures failed validation.
    Bogus(String),
    /// No signatures were found for this RRset.
    NoSignatures,
}

/// Validate an RRset by verifying its RRSIG signatures against a provided
/// public key.
///
/// This is the pure-Rust equivalent of `validate_rrset()` in `dnssec.c`.
/// Rather than fetching keys from a global cache it accepts an explicit
/// `dnskey_rdata` byte slice (the RDATA of the matching DNSKEY record).
///
/// Steps performed (RFC 4034 §6, RFC 4035 §5.3):
/// 1. Sort the RRset into canonical order (`sort_rrset`).
/// 2. For each RRSIG, check validity window (using provided `now_ts`).
/// 3. Build the signed data (type code, original TTL, owner name, RDATA).
/// 4. Verify the cryptographic signature via `crypto::verify_sig`, trying
///    RSA-SHA1/256/512, ECDSA P-256/P-384, and Ed25519 (algorithms 5, 8, 10,
///    13, 14, 15 — matching `crypto::DnssecAlgorithm`). Algorithms 7
///    (RSASHA1-NSEC3-SHA1) and 16 (Ed448), and anything else, are
///    unsupported and skipped.
///
/// An unsupported algorithm, a parse failure, or a signature that fails to
/// verify all `continue` to the next candidate RRSIG rather than failing the
/// whole call outright, mirroring `hash_find()`'s skip-on-unsupported and the
/// per-signature `verify()` gate in `dnssec.c:479-703`. Only after every
/// RRSIG has been tried does the call return `Bogus`.
///
/// Mirrors `validate_rrset()` in `dnssec.c`.
pub fn validate_rrset(
    rrset_in: &[crate::rfc1035::DnsRr],
    rrsigs:   &[&crate::rfc1035::DnsRr],
    name:     &str,
    rrtype:   u16,
    rrclass:  u16,
    now_ts:   u32,
    dnskey_rdata: Option<&[u8]>,
    counter:  &mut i32,
) -> RrsetValidation {
    if rrsigs.is_empty() { return RrsetValidation::NoSignatures; }

    // Clone and sort the RRset.
    let mut sorted: Vec<crate::rfc1035::DnsRr> = rrset_in.to_vec();
    sort_rrset(&mut sorted);

    let name_labels = count_labels(name);

    for rrsig_rr in rrsigs {
        if dec_counter(counter) { break; }

        let rdata = &rrsig_rr.rdata;
        if rdata.len() < 18 { continue; }

        let algo   = rdata[2];
        let labels = rdata[3] as u32;
        let orig_ttl  = u32::from_be_bytes([rdata[4],  rdata[5],  rdata[6],  rdata[7]]);
        let sig_expiry   = u32::from_be_bytes([rdata[8],  rdata[9],  rdata[10], rdata[11]]);
        let sig_inception = u32::from_be_bytes([rdata[12], rdata[13], rdata[14], rdata[15]]);
        let key_tag = u16::from_be_bytes([rdata[16], rdata[17]]);

        // Validity window check (RFC 4035 §5.3.1).
        // Inception/expiry are absolute UTC timestamps; use plain comparison.
        if now_ts < sig_inception { continue; }
        if now_ts > sig_expiry   { continue; }

        // Labels check (wildcard expansion detection).
        if labels > name_labels { continue; }

        // If no key is provided, signal that we need one.
        if dnskey_rdata.is_none() {
            let signer = parse_wire_name(&rdata[18..])
                .map(|(n, _)| n)
                .unwrap_or_default();
            return RrsetValidation::NeedKey { signer, key_tag };
        }

        let key = dnskey_rdata.unwrap();
        // Skip (don't fail outright) unsupported algorithms, mirroring
        // upstream's `hash_find(algo_digest_name(algo))` skip at
        // dnssec.c:522-523: try the next RRSIG/key combination instead of
        // aborting the whole validation.
        let algorithm = match crate::crypto::DnssecAlgorithm::try_from(algo) {
            Ok(a) => a,
            Err(_) => continue,
        };

        // Build the signed data per RFC 4034 §6.2.
        // signed_data = RRSIG_RDATA[0..18] + wire(signer_name) + for each RR: wire(owner) + type + class + orig_ttl + rdlen + rdata
        let mut signed_data: Vec<u8> = Vec::new();

        // RRSIG fixed header (first 18 bytes) minus the signature.
        signed_data.extend_from_slice(&rdata[..18]);

        // Signer name in wire format.
        let signer_str = parse_wire_name(&rdata[18..])
            .map(|(n, _)| n)
            .unwrap_or_default();
        if let Some(wire_signer) = name_to_wire(&signer_str) {
            signed_data.extend_from_slice(&wire_signer);
        } else {
            continue;
        }

        // Each RR from the sorted RRset.
        let owner_name = if labels < name_labels {
            // Wildcard expansion: prepend "*." to the labels-truncated name.
            let parts: Vec<&str> = name.split('.').collect();
            let skip = (name_labels - labels) as usize;
            let mut wc = String::from("*.");
            wc.push_str(&parts[skip..].join("."));
            wc
        } else {
            name.to_string()
        };

        let Some(wire_owner) = name_to_wire(&owner_name) else { continue };
        let orig_ttl_be = orig_ttl.to_be_bytes();

        for rr in &sorted {
            signed_data.extend_from_slice(&wire_owner);
            signed_data.extend_from_slice(&rrtype.to_be_bytes());
            signed_data.extend_from_slice(&rrclass.to_be_bytes());
            signed_data.extend_from_slice(&orig_ttl_be);
            let rdlen = rr.rdata.len() as u16;
            signed_data.extend_from_slice(&rdlen.to_be_bytes());
            signed_data.extend_from_slice(&rr.rdata);
        }

        // Signature bytes follow the signer name in RRSIG RDATA.
        let name_wire_len = name_to_wire(&signer_str).map(|v| v.len()).unwrap_or(0);
        let sig_start = 18 + name_wire_len;
        if sig_start >= rdata.len() { continue; }
        let signature = &rdata[sig_start..];

        // Parse the DNSKEY RDATA (flags/protocol/algorithm header + raw key
        // material) and verify the signature against the reconstructed
        // signed-data blob. Any parse or verification failure means this
        // RRSIG/key combination does not validate; try the next signature
        // rather than failing the whole RRset outright (dnssec.c:673-697).
        let Ok(dnskey) = parse_dnskey_rdata(key) else { continue };
        let Ok(pubkey) = crate::crypto::parse_dnskey(algo, &dnskey.public_key) else { continue };

        match crate::crypto::verify_sig(&signed_data, signature, &pubkey, algorithm) {
            Ok(true) => {
                // Compute effective TTL (RFC 4035 §5.3.3).
                let remaining = sig_expiry.saturating_sub(now_ts);
                let ttl = rr_ttl(&sorted)
                    .min(orig_ttl)
                    .min(remaining);

                return RrsetValidation::Secure { ttl, key_tag };
            }
            _ => continue,
        }
    }

    RrsetValidation::Bogus("no valid signatures found".to_string())
}

/// Return the minimum TTL across all RRs in a set, or `u32::MAX` if empty.
fn rr_ttl(rrset: &[crate::rfc1035::DnsRr]) -> u32 {
    rrset.iter().map(|r| r.ttl).min().unwrap_or(u32::MAX)
}

// ─── Canonical DNS name comparison (ported from dnssec.c:1183-1244) ──────────

/// Compare two DNS names in canonical (RFC 4034 §6.1) order.
///
/// Labels are compared right-to-left, case-insensitively.
/// Returns `Ordering::Less`, `Equal`, or `Greater`.
pub fn hostname_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let a_labels: Vec<&str> = a.trim_end_matches('.').split('.').collect();
    let b_labels: Vec<&str> = b.trim_end_matches('.').split('.').collect();

    let mut ai = a_labels.len();
    let mut bi = b_labels.len();

    loop {
        if ai == 0 && bi == 0 {
            return std::cmp::Ordering::Equal;
        }
        if ai == 0 {
            return std::cmp::Ordering::Less;
        }
        if bi == 0 {
            return std::cmp::Ordering::Greater;
        }

        ai -= 1;
        bi -= 1;

        let la = a_labels[ai].to_ascii_lowercase();
        let lb = b_labels[bi].to_ascii_lowercase();

        match la.cmp(&lb) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
}

// ─── Error flags to EDE mapping (ported from dnssec.c:2380-2409) ─────────────

/// DNSSEC failure flag constants.
pub const DNSSEC_FAIL_UPSTREAM:    u32 = 1 << 0;
pub const DNSSEC_FAIL_NYV:        u32 = 1 << 1;
pub const DNSSEC_FAIL_EXP:        u32 = 1 << 2;
pub const DNSSEC_FAIL_NOKEYSUP:   u32 = 1 << 3;
pub const DNSSEC_FAIL_NOZONE:     u32 = 1 << 4;
pub const DNSSEC_FAIL_NOKEY:      u32 = 1 << 5;
pub const DNSSEC_FAIL_NODSSUP:    u32 = 1 << 6;
pub const DNSSEC_FAIL_NSEC3_ITERS: u32 = 1 << 7;
pub const DNSSEC_FAIL_NONSEC:     u32 = 1 << 8;
pub const DNSSEC_FAIL_INDET:      u32 = 1 << 9;
pub const DNSSEC_FAIL_NOSIG:      u32 = 1 << 10;

/// Extended DNS Error (EDE) codes.
pub const EDE_UNSET:        u16 = 0;
pub const EDE_US_SERVFAIL:  u16 = 23;
pub const EDE_SIG_NYV:      u16 = 8;
pub const EDE_SIG_EXP:      u16 = 7;
pub const EDE_USUPDNSKEY:   u16 = 11;
pub const EDE_NO_ZONEKEY:   u16 = 9;
pub const EDE_NO_DNSKEY:    u16 = 10;
pub const EDE_USUPDS:       u16 = 12;
pub const EDE_UNS_NS3_ITER: u16 = 27;
pub const EDE_NO_NSEC:      u16 = 14;
pub const EDE_DNSSEC_IND:   u16 = 13;
pub const EDE_NO_RRSIG:     u16 = 15;

/// Map DNSSEC failure flags to the highest-priority EDE code.
///
/// When multiple flags are set, returns the most specific error.
/// Port of `errflags_to_ede()` from dnssec.c:2380-2409.
pub fn errflags_to_ede(status: u32) -> u16 {
    if status & DNSSEC_FAIL_UPSTREAM != 0    { EDE_US_SERVFAIL }
    else if status & DNSSEC_FAIL_NYV != 0    { EDE_SIG_NYV }
    else if status & DNSSEC_FAIL_EXP != 0    { EDE_SIG_EXP }
    else if status & DNSSEC_FAIL_NOKEYSUP != 0 { EDE_USUPDNSKEY }
    else if status & DNSSEC_FAIL_NOZONE != 0 { EDE_NO_ZONEKEY }
    else if status & DNSSEC_FAIL_NOKEY != 0  { EDE_NO_DNSKEY }
    else if status & DNSSEC_FAIL_NODSSUP != 0 { EDE_USUPDS }
    else if status & DNSSEC_FAIL_NSEC3_ITERS != 0 { EDE_UNS_NS3_ITER }
    else if status & DNSSEC_FAIL_NONSEC != 0 { EDE_NO_NSEC }
    else if status & DNSSEC_FAIL_INDET != 0  { EDE_DNSSEC_IND }
    else if status & DNSSEC_FAIL_NOSIG != 0  { EDE_NO_RRSIG }
    else { EDE_UNSET }
}

/// Compute the DNSKEY key tag per RFC 4034 Appendix B.
///
/// Algorithm 1 (RSAMD5) uses a special calculation; all others use the
/// standard checksum. `alg`, `flags`, and `key` come from the DNSKEY RDATA.
/// Port of `dnskey_keytag()` from dnssec.c:2332-2351.
pub fn dnskey_keytag(alg: u8, flags: u16, key: &[u8]) -> u16 {
    if alg == 1 {
        // RSAMD5 special case
        if key.len() >= 4 {
            (key[key.len() - 4] as u16) * 256 + key[key.len() - 3] as u16
        } else {
            0
        }
    } else {
        let mut ac: u32 = flags as u32 + 0x300 + alg as u32;
        for (i, &b) in key.iter().enumerate() {
            if i & 1 != 0 {
                ac += b as u32;
            } else {
                ac += (b as u32) << 8;
            }
        }
        ac += (ac >> 16) & 0xffff;
        (ac & 0xffff) as u16
    }
}

// ─── NSEC type bitmap checking (ported from dnssec.c NSEC handling) ──────────

/// Check if `rr_type` is present in an NSEC/NSEC3 type bitmap.
///
/// The bitmap is a sequence of window blocks:
///   window(1) | bitmap_len(1) | bitmap(bitmap_len)
/// Each window covers 256 types starting at `window * 256`.
/// Port of the type-bitmap checking logic used in `prove_non_existence_nsec`.
pub fn type_in_bitmap(bitmap: &[u8], rr_type: u16) -> bool {
    let window_wanted = (rr_type >> 8) as u8;
    let offset = ((rr_type & 0xff) >> 3) as usize;
    let mask = 0x80u8 >> (rr_type & 0x07);

    let mut i = 0;
    while i + 2 <= bitmap.len() {
        let window = bitmap[i];
        let bm_len = bitmap[i + 1] as usize;
        if i + 2 + bm_len > bitmap.len() {
            break;
        }
        if window == window_wanted {
            if offset < bm_len {
                return (bitmap[i + 2 + offset] & mask) != 0;
            }
            return false;
        }
        i += 2 + bm_len;
    }
    false
}

// ─── DNSSEC query builder (ported from dnssec.c:2353-2378) ───────────────────

/// Build a DNS query packet for DNSSEC key retrieval (DNSKEY or DS).
///
/// Returns a complete DNS packet with RD set, a single question, and no
/// additional records. The DO bit should be added separately via
/// `edns0::add_do_bit`.
/// Port of `dnssec_generate_query()` from dnssec.c:2353-2378.
pub fn dnssec_generate_query(name: &str, qclass: u16, qtype: u16, id: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(128);

    // DNS header (12 bytes)
    pkt.extend_from_slice(&id.to_be_bytes());       // ID
    pkt.push(0x01); // hb3: RD=1
    pkt.push(0x00); // hb4: 0 (or CD for debug)
    pkt.extend_from_slice(&1u16.to_be_bytes());     // QDCOUNT=1
    pkt.extend_from_slice(&0u16.to_be_bytes());     // ANCOUNT=0
    pkt.extend_from_slice(&0u16.to_be_bytes());     // NSCOUNT=0
    pkt.extend_from_slice(&0u16.to_be_bytes());     // ARCOUNT=0

    // Question: encode name as wire-format labels
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0); // root label

    pkt.extend_from_slice(&qtype.to_be_bytes());    // QTYPE
    pkt.extend_from_slice(&qclass.to_be_bytes());   // QCLASS

    pkt
}

// ─── DNSSEC timestamp validation (ported from dnssec.c:114-141) ──────────────

/// Check if DNSSEC timestamp validation should be performed.
///
/// If a timestamp file is configured, timestamps are only checked after
/// the system time has advanced past the timestamp file's mtime
/// (indicating the clock is set correctly).
/// Port of `is_check_date()` from dnssec.c:114-141.
pub fn is_check_date(
    has_timestamp_file: bool,
    back_to_the_future: bool,
    no_time_check: bool,
) -> bool {
    if has_timestamp_file {
        back_to_the_future
    } else {
        !no_time_check
    }
}

/// Check if a DNSSEC signature's time window is valid.
///
/// Returns true if `now` falls within `[inception, expiration]`.
/// Handles serial-number arithmetic for wraparound.
pub fn check_signature_time(inception: u32, expiration: u32, now: u32) -> bool {
    // RFC 4034 §3.1.5: using serial number arithmetic
    // sig_inception <= now <= sig_expiration
    let now_after_inception = now.wrapping_sub(inception) < 0x80000000;
    let now_before_expiry = expiration.wrapping_sub(now) < 0x80000000;
    now_after_inception && now_before_expiry
}

// ─── RR data canonicalization (ported from dnssec.c:152-218) ─────────────────

/// RR type descriptor for canonicalization.
///
/// Describes the structure of an RR's RDATA for DNSSEC signature verification.
/// Each entry is either:
/// - A positive value: number of plain data bytes
/// - 0: a domain name (to be lowercased/canonicalized)
/// - -1: remaining bytes to the end (terminal)
#[derive(Debug, Clone)]
pub struct RrDescriptor {
    pub fields: Vec<i16>,
}

impl RrDescriptor {
    /// Get the descriptor for common RR types.
    ///
    /// Returns field descriptions for canonicalization.
    pub fn for_type(rr_type: u16) -> Self {
        let fields = match rr_type {
            // A: 4 bytes address
            1 => vec![-1],
            // NS, CNAME, PTR: domain name
            2 | 5 | 12 => vec![0],
            // SOA: mname, rname, 5*u32
            6 => vec![0, 0, -1],
            // MX: 2-byte preference + domain name
            15 => vec![2, 0],
            // AAAA: 16 bytes
            28 => vec![-1],
            // SRV: 6 bytes + domain name
            33 => vec![6, 0],
            // RRSIG: 18 bytes + signer name + signature
            46 => vec![18, 0, -1],
            // DNSKEY, DS, NSEC, NSEC3, TLSA, etc.: all plain bytes
            _ => vec![-1],
        };
        Self { fields }
    }
}

/// Canonicalize RDATA for DNSSEC signature verification.
///
/// Domain names in the RDATA are lowercased. Plain data bytes are left unchanged.
/// Returns the canonicalized bytes, or `None` on malformed data.
/// Port of `get_rdata()` iteration from dnssec.c:159-218.
pub fn canonicalize_rdata(rdata: &[u8], rr_type: u16) -> Option<Vec<u8>> {
    let desc = RrDescriptor::for_type(rr_type);
    let mut result = Vec::with_capacity(rdata.len());
    let mut pos = 0;

    for &field in &desc.fields {
        if field == -1 {
            // Remaining bytes to end
            result.extend_from_slice(&rdata[pos..]);
            pos = rdata.len();
            break;
        } else if field == 0 {
            // Domain name: read wire-format labels and lowercase
            let start = pos;
            loop {
                if pos >= rdata.len() {
                    return None;
                }
                let label_len = rdata[pos] as usize;
                if label_len == 0 {
                    result.push(0); // root label
                    pos += 1;
                    break;
                }
                if label_len >= 0xc0 {
                    // Compression pointer — shouldn't appear in canonical form
                    return None;
                }
                if pos + 1 + label_len > rdata.len() {
                    return None;
                }
                result.push(label_len as u8);
                for i in 0..label_len {
                    result.push(rdata[pos + 1 + i].to_ascii_lowercase());
                }
                pos += 1 + label_len;
            }
        } else {
            // Plain data bytes
            let n = field as usize;
            if pos + n > rdata.len() {
                return None;
            }
            result.extend_from_slice(&rdata[pos..pos + n]);
            pos += n;
        }
    }

    Some(result)
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

    // ─── count_labels ──────────────────────────────────────────────────────

    #[test]
    fn count_labels_basic() {
        assert_eq!(count_labels(""),              0);
        assert_eq!(count_labels("com"),           1);
        assert_eq!(count_labels("example.com"),   2);
        assert_eq!(count_labels("a.b.c.d"),       4);
        assert_eq!(count_labels("sub.example.com"), 3);
    }

    #[test]
    fn count_labels_leading_dot_not_counted() {
        // C: counts dots, then returns i (not i+1) when name starts with '.'.
        // ".foo.example.com" = 3 dots → 3 (leading dot skips the +1)
        // "foo.example.com"  = 2 dots → 2+1 = 3  (same count)
        assert_eq!(count_labels(".foo.example.com"), 3);
        assert_eq!(count_labels(".foo"), 1); // 1 dot, starts with '.' → 1
    }

    // ─── serial_compare_32 ────────────────────────────────────────────────

    #[test]
    fn serial_compare_equal() {
        assert_eq!(serial_compare_32(42, 42), SerialCmp::Equal);
        assert_eq!(serial_compare_32(0,  0),  SerialCmp::Equal);
        assert_eq!(serial_compare_32(u32::MAX, u32::MAX), SerialCmp::Equal);
    }

    #[test]
    fn serial_compare_less_and_greater() {
        assert_eq!(serial_compare_32(1,  2),  SerialCmp::Less);
        assert_eq!(serial_compare_32(2,  1),  SerialCmp::Greater);
        // Wrap-around: s1=0xFFFFFFFF, s2=1  →  s1 > s2 by RFC 1982 (diff = 2 < 2^31)
        assert_eq!(serial_compare_32(0xFFFF_FFFE, 0xFFFF_FFFF), SerialCmp::Less);
        assert_eq!(serial_compare_32(0xFFFF_FFFF, 0xFFFF_FFFE), SerialCmp::Greater);
    }

    #[test]
    fn serial_compare_wrap() {
        // The wrap-around case: 0xFFFFFFFF < 1 in RFC 1982 because diff = 2
        assert_eq!(serial_compare_32(0xFFFF_FFFF, 1), SerialCmp::Less);
        assert_eq!(serial_compare_32(1, 0xFFFF_FFFF), SerialCmp::Greater);
    }

    // ─── dec_counter ──────────────────────────────────────────────────────

    #[test]
    fn dec_counter_decrements() {
        let mut c = 3i32;
        assert!(!dec_counter(&mut c)); c_check_eq(c, 2);
        assert!(!dec_counter(&mut c)); c_check_eq(c, 1);
        assert!(!dec_counter(&mut c)); c_check_eq(c, 0);
        assert!( dec_counter(&mut c)); // limit exceeded
        c_check_eq(c, 0);              // not decremented past 0
    }

    fn c_check_eq(actual: i32, expected: i32) {
        assert_eq!(actual, expected, "counter mismatch");
    }

    // ─── base32_decode ────────────────────────────────────────────────────

    #[test]
    fn base32_decode_empty_string() {
        assert_eq!(base32_decode(""), Some(vec![]));
    }

    #[test]
    fn base32_decode_stops_at_dot() {
        // "00.garbage" → same as "00"
        assert_eq!(base32_decode("00.garbage"), base32_decode("00"));
    }

    #[test]
    fn base32_decode_invalid_char() {
        assert!(base32_decode("Z0").is_none()); // 'Z' is not in 0-9/A-V
    }

    #[test]
    fn base32_decode_roundtrip_known() {
        // "00" in base-32 extended hex = 0b00000_00000 = 0x00 0x00? No — 10 bits for 2 chars,
        // but we need 16 bits for 2 bytes. Let's use a 3-char (15-bit) and pad.
        // "000" = 3 × 5 = 15 bits — not divisible by 8 → None.
        assert!(base32_decode("000").is_none());
        // "0000" = 4 × 5 = 20 bits → 2 bytes + 4 leftover → None.
        assert!(base32_decode("0000").is_none());
        // "00000000" = 8 × 5 = 40 bits = 5 bytes, all zero.
        let result = base32_decode("00000000");
        assert_eq!(result, Some(vec![0u8; 5]));
    }

    #[test]
    fn base32_decode_case_insensitive() {
        let upper = base32_decode("AABBCCDD");
        let lower = base32_decode("aabbccdd");
        assert_eq!(upper, lower);
    }

    // ─── hash_name ────────────────────────────────────────────────────────

    #[test]
    fn hash_name_produces_consistent_output() {
        // Use a trivial "hash" that just returns the input concatenated.
        // Real use-case would be SHA-1 per RFC 5155.
        let salt    = b"salty";
        let result1 = hash_name("example.com", salt, 0, |data| data.to_vec());
        let result2 = hash_name("example.com", salt, 0, |data| data.to_vec());
        assert_eq!(result1, result2, "hash_name must be deterministic");
        assert!(result1.is_some());
    }

    #[test]
    fn hash_name_iterations_change_result() {
        let salt   = b"";
        let result0 = hash_name("example.com", salt, 0, |d| {
            // identity hash — makes the iteration effect visible
            let mut v = d.to_vec(); v.push(0xFF); v
        });
        let result1 = hash_name("example.com", salt, 1, |d| {
            let mut v = d.to_vec(); v.push(0xFF); v
        });
        assert_ne!(result0, result1, "additional iterations must change output");
    }

    #[test]
    fn hash_name_invalid_name_returns_none() {
        // A label longer than 63 bytes is invalid for wire format.
        let long_label = "a".repeat(64);
        let result = hash_name(&long_label, b"", 0, |d| d.to_vec());
        assert!(result.is_none());
    }

    // ─── sort_rrset ───────────────────────────────────────────────────────

    fn make_rr(rdata: &[u8]) -> crate::rfc1035::DnsRr {
        crate::rfc1035::DnsRr {
            name:  "example.com".to_string(),
            rtype: 1,
            class: 1,
            ttl:   300,
            rdata: rdata.to_vec(),
        }
    }

    #[test]
    fn sort_rrset_orders_lexicographically() {
        let mut rrset = vec![
            make_rr(&[3, 0, 0, 1]),
            make_rr(&[1, 0, 0, 1]),
            make_rr(&[2, 0, 0, 1]),
        ];
        sort_rrset(&mut rrset);
        assert_eq!(rrset[0].rdata[0], 1);
        assert_eq!(rrset[1].rdata[0], 2);
        assert_eq!(rrset[2].rdata[0], 3);
    }

    #[test]
    fn sort_rrset_deduplicates() {
        let mut rrset = vec![
            make_rr(&[1, 2, 3]),
            make_rr(&[1, 2, 3]),
            make_rr(&[4, 5, 6]),
        ];
        sort_rrset(&mut rrset);
        assert_eq!(rrset.len(), 2, "duplicate should be removed");
    }

    #[test]
    fn sort_rrset_single_element_unchanged() {
        let mut rrset = vec![make_rr(&[10, 20])];
        sort_rrset(&mut rrset);
        assert_eq!(rrset.len(), 1);
        assert_eq!(rrset[0].rdata, [10, 20]);
    }

    // ─── explore_rrset ────────────────────────────────────────────────────

    fn make_typed_rr(name: &str, rtype: u16, rdata: &[u8]) -> crate::rfc1035::DnsRr {
        crate::rfc1035::DnsRr {
            name: name.to_string(), rtype, class: 1, ttl: 300, rdata: rdata.to_vec(),
        }
    }

    /// Build minimal RRSIG RDATA: type_covered=A(1), algo=8, labels=2,
    /// orig_ttl=300, expiry=u32::MAX, inception=0, key_tag=1234,
    /// signer="example.com" (wire), sig=0x01.
    fn rrsig_rdata_for(type_covered: u16, signer: &str) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&type_covered.to_be_bytes()); // type_covered
        r.push(8);                                         // algorithm
        r.push(2);                                         // labels
        r.extend_from_slice(&300u32.to_be_bytes());        // orig_ttl
        r.extend_from_slice(&u32::MAX.to_be_bytes());      // sig_expiry
        r.extend_from_slice(&0u32.to_be_bytes());          // sig_inception
        r.extend_from_slice(&1234u16.to_be_bytes());       // key_tag
        r.extend_from_slice(&name_to_wire(signer).unwrap());
        r.push(0x01); // dummy signature byte
        r
    }

    #[test]
    fn explore_rrset_splits_rrs_and_rrsigs() {
        let records = vec![
            make_typed_rr("example.com", 1,  &[1, 2, 3, 4]),   // A record
            make_typed_rr("example.com", 1,  &[5, 6, 7, 8]),   // A record
            make_typed_rr("example.com", 46, &rrsig_rdata_for(1, "example.com")), // RRSIG(A)
            make_typed_rr("example.com", 28, &[0u8; 16]),       // AAAA (not A)
        ];
        let (rrset, rrsigs) = explore_rrset(&records, "example.com", 1, 1);
        assert_eq!(rrset.len(),  2, "two A records");
        assert_eq!(rrsigs.len(), 1, "one RRSIG covering A");
    }

    #[test]
    fn explore_rrset_ignores_wrong_class() {
        let records = vec![
            make_typed_rr("example.com", 1, &[1, 2, 3, 4]),
        ];
        // class=2 (CHAOS) — should not match class=1 (IN)
        let mut rr = make_typed_rr("example.com", 1, &[1, 2, 3, 4]);
        rr.class = 2;
        let records2 = vec![rr];
        let (rrset, _) = explore_rrset(&records2, "example.com", 1, 1);
        assert!(rrset.is_empty(), "wrong class must be excluded");
    }

    #[test]
    fn explore_rrset_excludes_rrsig_for_other_type() {
        // RRSIG that covers AAAA (28), not A (1)
        let rrsig_aaaa = make_typed_rr("example.com", 46, &rrsig_rdata_for(28, "example.com"));
        let records = vec![
            make_typed_rr("example.com", 1, &[1, 2, 3, 4]),
            rrsig_aaaa,
        ];
        let (_, rrsigs) = explore_rrset(&records, "example.com", 1, 1);
        assert!(rrsigs.is_empty(), "RRSIG for AAAA must not be included for A query");
    }

    // ─── validate_rrset ───────────────────────────────────────────────────

    #[test]
    fn validate_rrset_no_signatures_returns_no_signatures() {
        let rrset = vec![make_rr(&[1, 2, 3, 4])];
        let mut counter = 100i32;
        let result = validate_rrset(&rrset, &[], "example.com", 1, 1, 1000, None, &mut counter);
        assert_eq!(result, RrsetValidation::NoSignatures);
    }

    #[test]
    fn validate_rrset_need_key_when_no_dnskey_provided() {
        let rrsig_rr = make_typed_rr(
            "example.com", 46,
            &rrsig_rdata_for(1, "example.com"),
        );
        let rrset = vec![make_rr(&[1, 2, 3, 4])];
        let mut counter = 100i32;
        let result = validate_rrset(
            &rrset, &[&rrsig_rr], "example.com", 1, 1,
            /* now */ 500_000, None, &mut counter,
        );
        match result {
            RrsetValidation::NeedKey { key_tag, .. } => assert_eq!(key_tag, 1234),
            other => panic!("expected NeedKey, got {other:?}"),
        }
    }

    #[test]
    fn validate_rrset_expired_signature_is_bogus() {
        let mut rdata = rrsig_rdata_for(1, "example.com");
        // Overwrite sig_expiry (bytes 8..12) to be 100 (< now=1000).
        rdata[8..12].copy_from_slice(&100u32.to_be_bytes());
        let rrsig_rr = make_typed_rr("example.com", 46, &rdata);
        let rrset = vec![make_rr(&[1, 2, 3, 4])];
        let mut counter = 100i32;
        // Provide a dummy key so we get past the NeedKey branch.
        let fake_key = vec![0u8; 4];
        let result = validate_rrset(
            &rrset, &[&rrsig_rr], "example.com", 1, 1,
            /* now */ 1000, Some(&fake_key), &mut counter,
        );
        // expired → all sigs fail → Bogus
        assert!(matches!(result, RrsetValidation::Bogus(_)));
    }

    #[test]
    fn validate_rrset_not_yet_valid_signature_is_bogus() {
        let mut rdata = rrsig_rdata_for(1, "example.com");
        // Overwrite sig_inception (bytes 12..16) to be far in the future (> now=1000).
        rdata[12..16].copy_from_slice(&2_000_000u32.to_be_bytes());
        let rrsig_rr = make_typed_rr("example.com", 46, &rdata);
        let rrset = vec![make_rr(&[1, 2, 3, 4])];
        let mut counter = 100i32;
        let fake_key = vec![0u8; 4];
        let result = validate_rrset(
            &rrset, &[&rrsig_rr], "example.com", 1, 1,
            /* now */ 1000, Some(&fake_key), &mut counter,
        );
        // not yet valid → all sigs fail → Bogus
        assert!(matches!(result, RrsetValidation::Bogus(_)));
    }

    // ─── validate_rrset: real cryptographic verification ──────────────────
    //
    // Uses ECDSA P-256 (algorithm 13), which was already in the pre-fix
    // hardcoded allow-list (`algo != 8 && algo != 13`). That matters: it
    // proves these tests exercise actual signature verification rather than
    // merely hitting the "unsupported algorithm" path.

    /// Build a self-consistent (rrset, RRSIG RR) pair, signed with
    /// `signing_key` over exactly the bytes `validate_rrset` will
    /// reconstruct internally (RFC 4034 §6.2 signed-data blob).
    fn build_ecdsa_p256_scenario(
        signing_key: &p256::ecdsa::SigningKey,
        sig_inception: u32,
        sig_expiry: u32,
    ) -> (Vec<crate::rfc1035::DnsRr>, crate::rfc1035::DnsRr) {
        use p256::ecdsa::signature::Signer;

        const ALGO: u8 = 13; // ECDSA P-256/SHA-256
        let name = "example.com";
        let rrtype: u16 = 1;
        let rrclass: u16 = 1;
        let orig_ttl: u32 = 300;
        let key_tag: u16 = 1234;
        let labels: u8 = 2;

        let rr = make_rr(&[1, 2, 3, 4]);

        let mut header = Vec::new();
        header.extend_from_slice(&rrtype.to_be_bytes());
        header.push(ALGO);
        header.push(labels);
        header.extend_from_slice(&orig_ttl.to_be_bytes());
        header.extend_from_slice(&sig_expiry.to_be_bytes());
        header.extend_from_slice(&sig_inception.to_be_bytes());
        header.extend_from_slice(&key_tag.to_be_bytes());

        let wire_name = name_to_wire(name).unwrap();

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&header);
        signed_data.extend_from_slice(&wire_name); // signer name
        signed_data.extend_from_slice(&wire_name); // owner name (== signer, no wildcard)
        signed_data.extend_from_slice(&rrtype.to_be_bytes());
        signed_data.extend_from_slice(&rrclass.to_be_bytes());
        signed_data.extend_from_slice(&orig_ttl.to_be_bytes());
        let rdlen = rr.rdata.len() as u16;
        signed_data.extend_from_slice(&rdlen.to_be_bytes());
        signed_data.extend_from_slice(&rr.rdata);

        let signature: p256::ecdsa::Signature = signing_key.sign(&signed_data);
        let sig_bytes = signature.to_bytes().to_vec(); // fixed 64-byte r||s

        let mut rrsig_rdata = header.clone();
        rrsig_rdata.extend_from_slice(&wire_name);
        rrsig_rdata.extend_from_slice(&sig_bytes);

        let rrsig_rr = make_typed_rr(name, 46, &rrsig_rdata);

        (vec![rr], rrsig_rr)
    }

    fn dnskey_rdata_for_ecdsa_p256(verifying_key: &p256::ecdsa::VerifyingKey) -> Vec<u8> {
        use p256::elliptic_curve::sec1::ToEncodedPoint;

        let point = verifying_key.to_encoded_point(false); // 0x04 || x(32) || y(32)
        let uncompressed = point.as_bytes();

        let mut dnskey_rdata = Vec::new();
        dnskey_rdata.extend_from_slice(&0x0100u16.to_be_bytes()); // zone key flag
        dnskey_rdata.push(3); // protocol
        dnskey_rdata.push(13); // algorithm: ECDSA P-256
        dnskey_rdata.extend_from_slice(&uncompressed[1..]); // strip 0x04 prefix
        dnskey_rdata
    }

    #[test]
    fn validate_rrset_valid_ecdsa_signature_is_secure() {
        use p256::ecdsa::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::random(&mut OsRng);
        let (rrset, rrsig_rr) = build_ecdsa_p256_scenario(&signing_key, 0, u32::MAX);
        let dnskey_rdata = dnskey_rdata_for_ecdsa_p256(signing_key.verifying_key());

        let mut counter = 100i32;
        let result = validate_rrset(
            &rrset, &[&rrsig_rr], "example.com", 1, 1,
            /* now */ 500_000, Some(&dnskey_rdata), &mut counter,
        );
        assert!(matches!(result, RrsetValidation::Secure { .. }), "expected Secure, got {result:?}");
    }

    #[test]
    fn validate_rrset_corrupted_signature_is_bogus() {
        use p256::ecdsa::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::random(&mut OsRng);
        let (rrset, mut rrsig_rr) = build_ecdsa_p256_scenario(&signing_key, 0, u32::MAX);
        let dnskey_rdata = dnskey_rdata_for_ecdsa_p256(signing_key.verifying_key());

        // Corrupt the last byte of the signature (end of RRSIG RDATA).
        let last = rrsig_rr.rdata.len() - 1;
        rrsig_rr.rdata[last] ^= 0xff;

        let mut counter = 100i32;
        let result = validate_rrset(
            &rrset, &[&rrsig_rr], "example.com", 1, 1,
            /* now */ 500_000, Some(&dnskey_rdata), &mut counter,
        );
        assert!(matches!(result, RrsetValidation::Bogus(_)), "corrupted signature must not validate, got {result:?}");
    }

    #[test]
    fn validate_rrset_wrong_key_is_bogus() {
        use p256::ecdsa::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::random(&mut OsRng);
        let (rrset, rrsig_rr) = build_ecdsa_p256_scenario(&signing_key, 0, u32::MAX);

        // Present a DNSKEY belonging to an unrelated key pair.
        let wrong_key = SigningKey::random(&mut OsRng);
        let dnskey_rdata = dnskey_rdata_for_ecdsa_p256(wrong_key.verifying_key());

        let mut counter = 100i32;
        let result = validate_rrset(
            &rrset, &[&rrsig_rr], "example.com", 1, 1,
            /* now */ 500_000, Some(&dnskey_rdata), &mut counter,
        );
        assert!(matches!(result, RrsetValidation::Bogus(_)), "wrong key must not validate, got {result:?}");
    }

    #[test]
    fn validate_rrset_unsupported_algorithm_is_bogus() {
        // Algorithm 1 (RSA/MD5) is explicitly unsupported (RFC 6944 Must Not
        // Implement) and must not be treated as valid.
        let mut rdata = rrsig_rdata_for(1, "example.com");
        rdata[2] = 1; // algorithm byte
        let rrsig_rr = make_typed_rr("example.com", 46, &rdata);
        let rrset = vec![make_rr(&[1, 2, 3, 4])];
        let mut counter = 100i32;
        let fake_key = vec![0u8; 4];
        let result = validate_rrset(
            &rrset, &[&rrsig_rr], "example.com", 1, 1,
            /* now */ 500_000, Some(&fake_key), &mut counter,
        );
        assert!(matches!(result, RrsetValidation::Bogus(_)), "unsupported algorithm must not validate, got {result:?}");
    }

    // ─── hostname_cmp ────────────────────────────────────────────────────────

    #[test]
    fn hostname_cmp_equal() {
        assert_eq!(hostname_cmp("example.com", "example.com"), std::cmp::Ordering::Equal);
    }

    #[test]
    fn hostname_cmp_case_insensitive() {
        assert_eq!(hostname_cmp("Example.COM", "example.com"), std::cmp::Ordering::Equal);
    }

    #[test]
    fn hostname_cmp_different_tld() {
        // "com" < "org"
        assert_eq!(hostname_cmp("a.com", "a.org"), std::cmp::Ordering::Less);
        assert_eq!(hostname_cmp("a.org", "a.com"), std::cmp::Ordering::Greater);
    }

    #[test]
    fn hostname_cmp_subdomain_before_parent() {
        // "a.example.com" < "b.example.com" (label 'a' < 'b')
        assert_eq!(hostname_cmp("a.example.com", "b.example.com"), std::cmp::Ordering::Less);
    }

    #[test]
    fn hostname_cmp_fewer_labels_is_less() {
        // "com" < "example.com"
        assert_eq!(hostname_cmp("com", "example.com"), std::cmp::Ordering::Less);
    }

    #[test]
    fn hostname_cmp_trailing_dot() {
        assert_eq!(hostname_cmp("example.com.", "example.com"), std::cmp::Ordering::Equal);
    }

    // ─── errflags_to_ede ─────────────────────────────────────────────────────

    #[test]
    fn errflags_to_ede_upstream() {
        assert_eq!(errflags_to_ede(DNSSEC_FAIL_UPSTREAM), EDE_US_SERVFAIL);
    }

    #[test]
    fn errflags_to_ede_expired() {
        assert_eq!(errflags_to_ede(DNSSEC_FAIL_EXP), EDE_SIG_EXP);
    }

    #[test]
    fn errflags_to_ede_nosig() {
        assert_eq!(errflags_to_ede(DNSSEC_FAIL_NOSIG), EDE_NO_RRSIG);
    }

    #[test]
    fn errflags_to_ede_zero() {
        assert_eq!(errflags_to_ede(0), EDE_UNSET);
    }

    #[test]
    fn errflags_to_ede_priority_upstream_wins() {
        // Multiple flags: upstream should take priority
        assert_eq!(
            errflags_to_ede(DNSSEC_FAIL_UPSTREAM | DNSSEC_FAIL_NOSIG),
            EDE_US_SERVFAIL
        );
    }

    // ─── dnskey_keytag ───────────────────────────────────────────────────────

    #[test]
    fn dnskey_keytag_standard() {
        // flags=256, alg=8 (RSASHA256), key=[0x03, 0x01, 0x00, 0x01, ...]
        let key = vec![0x03, 0x01, 0x00, 0x01, 0xAB, 0xCD];
        let tag = dnskey_keytag(8, 256, &key);
        assert!(tag > 0);
    }

    #[test]
    fn dnskey_keytag_rsamd5_special() {
        // Algorithm 1 uses special calculation from last 4 bytes
        let key = vec![0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
        let tag = dnskey_keytag(1, 256, &key);
        // key[len-4]*256 + key[len-3] = 0xDE*256 + 0xAD = 57005
        assert_eq!(tag, 0xDE * 256 + 0xAD);
    }

    #[test]
    fn dnskey_keytag_empty_key() {
        let tag = dnskey_keytag(8, 256, &[]);
        assert!(tag > 0); // still produces a tag from flags+alg
    }

    // ─── type_in_bitmap ──────────────────────────────────────────────────────

    #[test]
    fn type_in_bitmap_a_record() {
        // Window 0, bitmap length 4, bits for types 0-31
        // Type A = 1, so byte offset = 1>>3 = 0, mask = 0x80 >> 1 = 0x40
        let bitmap = vec![0u8, 4, 0x40, 0x00, 0x00, 0x00]; // A bit set
        assert!(type_in_bitmap(&bitmap, 1)); // A
        assert!(!type_in_bitmap(&bitmap, 2)); // NS not set
    }

    #[test]
    fn type_in_bitmap_ns_and_soa() {
        // Type NS=2: byte 0, mask 0x20
        // Type SOA=6: byte 0, mask 0x02
        let bitmap = vec![0u8, 1, 0x22]; // NS (0x20) + SOA (0x02)
        assert!(type_in_bitmap(&bitmap, 2));  // NS
        assert!(type_in_bitmap(&bitmap, 6));  // SOA
        assert!(!type_in_bitmap(&bitmap, 1)); // A not set
    }

    #[test]
    fn type_in_bitmap_high_type() {
        // RRSIG = 46. Window 0, byte offset = 46>>3 = 5, mask = 0x80>>(46&7) = 0x80>>6 = 0x02
        let mut bitmap = vec![0u8, 6, 0, 0, 0, 0, 0, 0x02];
        assert!(type_in_bitmap(&bitmap, 46)); // RRSIG
        assert!(!type_in_bitmap(&bitmap, 45));
    }

    #[test]
    fn type_in_bitmap_empty() {
        assert!(!type_in_bitmap(&[], 1));
    }

    #[test]
    fn type_in_bitmap_type_not_in_any_window() {
        // Only window 0, types 0-7
        let bitmap = vec![0u8, 1, 0xFF]; // all types 0-7 set
        assert!(!type_in_bitmap(&bitmap, 256)); // window 1 — not present
    }

    // ─── dnssec_generate_query ───────────────────────────────────────────────

    #[test]
    fn dnssec_generate_query_structure() {
        let pkt = dnssec_generate_query("example.com", 1, 48, 0x1234); // DNSKEY=48, IN=1
        // Header check
        assert_eq!(pkt[0], 0x12); // ID high
        assert_eq!(pkt[1], 0x34); // ID low
        assert_eq!(pkt[2], 0x01); // RD=1
        // QDCOUNT=1
        assert_eq!(u16::from_be_bytes([pkt[4], pkt[5]]), 1);
        // ANCOUNT, NSCOUNT, ARCOUNT = 0
        assert_eq!(u16::from_be_bytes([pkt[6], pkt[7]]), 0);
        assert_eq!(u16::from_be_bytes([pkt[8], pkt[9]]), 0);
        assert_eq!(u16::from_be_bytes([pkt[10], pkt[11]]), 0);
        // QNAME starts at offset 12
        assert_eq!(pkt[12], 7); // "example" label length
        assert_eq!(&pkt[13..20], b"example");
        assert_eq!(pkt[20], 3); // "com" label length
        assert_eq!(&pkt[21..24], b"com");
        assert_eq!(pkt[24], 0); // root
        // QTYPE=48 (DNSKEY)
        assert_eq!(u16::from_be_bytes([pkt[25], pkt[26]]), 48);
        // QCLASS=1 (IN)
        assert_eq!(u16::from_be_bytes([pkt[27], pkt[28]]), 1);
    }

    #[test]
    fn dnssec_generate_query_ds() {
        let pkt = dnssec_generate_query("sub.example.com", 1, 43, 0xABCD); // DS=43
        assert_eq!(u16::from_be_bytes([pkt[0], pkt[1]]), 0xABCD);
        // Check label: "sub"(3) "example"(7) "com"(3)
        assert_eq!(pkt[12], 3);
        assert_eq!(&pkt[13..16], b"sub");
    }

    #[test]
    fn dnssec_generate_query_trailing_dot() {
        let pkt1 = dnssec_generate_query("example.com.", 1, 48, 1);
        let pkt2 = dnssec_generate_query("example.com", 1, 48, 1);
        assert_eq!(pkt1, pkt2);
    }

    // ─── is_check_date ───────────────────────────────────────────────────────

    #[test]
    fn is_check_date_no_timestamp_file() {
        assert!(is_check_date(false, false, false));
        assert!(!is_check_date(false, false, true)); // no_time_check → don't check
    }

    #[test]
    fn is_check_date_with_timestamp_file() {
        assert!(!is_check_date(true, false, false)); // not yet back_to_the_future
        assert!(is_check_date(true, true, false)); // back_to_the_future → check
    }

    // ─── check_signature_time ────────────────────────────────────────────────

    #[test]
    fn check_signature_time_valid() {
        assert!(check_signature_time(100, 200, 150));
    }

    #[test]
    fn check_signature_time_at_boundaries() {
        assert!(check_signature_time(100, 200, 100)); // at inception
        assert!(check_signature_time(100, 200, 200)); // at expiry
    }

    #[test]
    fn check_signature_time_expired() {
        assert!(!check_signature_time(100, 200, 201));
    }

    #[test]
    fn check_signature_time_not_yet_valid() {
        assert!(!check_signature_time(100, 200, 99));
    }

    #[test]
    fn check_signature_time_wraparound() {
        // inception near max u32, expiry after wrap
        assert!(check_signature_time(u32::MAX - 10, 10, u32::MAX));
        assert!(check_signature_time(u32::MAX - 10, 10, 5));
    }

    // ─── RrDescriptor ────────────────────────────────────────────────────────

    #[test]
    fn rr_descriptor_a_record() {
        let desc = RrDescriptor::for_type(1);
        assert_eq!(desc.fields, vec![-1]); // all plain bytes
    }

    #[test]
    fn rr_descriptor_mx() {
        let desc = RrDescriptor::for_type(15);
        assert_eq!(desc.fields, vec![2, 0]); // 2 bytes pref + domain
    }

    #[test]
    fn rr_descriptor_soa() {
        let desc = RrDescriptor::for_type(6);
        assert_eq!(desc.fields, vec![0, 0, -1]); // mname, rname, rest
    }

    // ─── canonicalize_rdata ──────────────────────────────────────────────────

    #[test]
    fn canonicalize_rdata_a_record() {
        let rdata = [1, 2, 3, 4];
        let result = canonicalize_rdata(&rdata, 1).unwrap();
        assert_eq!(result, rdata);
    }

    #[test]
    fn canonicalize_rdata_ns_lowercases() {
        // NS record: domain name "Example.COM" in wire format
        let rdata = [7, b'E', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'C', b'O', b'M', 0];
        let result = canonicalize_rdata(&rdata, 2).unwrap();
        // Should be lowercased
        let expected = [7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0];
        assert_eq!(result, expected);
    }

    #[test]
    fn canonicalize_rdata_mx() {
        // MX: 2 bytes preference + domain name
        let mut rdata = vec![0x00, 0x0A]; // preference = 10
        rdata.extend_from_slice(&[4, b'M', b'A', b'I', b'L', 0]); // "MAIL."
        let result = canonicalize_rdata(&rdata, 15).unwrap();
        assert_eq!(&result[0..2], &[0x00, 0x0A]); // preference unchanged
        assert_eq!(result[3], b'm'); // lowercased
    }

    #[test]
    fn canonicalize_rdata_empty() {
        let result = canonicalize_rdata(&[], 1).unwrap();
        assert!(result.is_empty());
    }
}
