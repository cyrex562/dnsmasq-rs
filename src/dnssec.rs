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
    let Some(wire) = name_to_wire(owner_name) else { return false };
    match ds.digest_type {
        1 => {
            use sha1::{Digest, Sha1};
            let mut hasher = Sha1::new();
            hasher.update(&wire);
            hasher.update(dnskey_rdata);
            hasher.finalize()[..] == ds.digest[..]
        }
        2 => {
            // SHA-256: hash( owner_name_wire || dnskey_rdata )
            let mut hasher = Sha256::new();
            hasher.update(&wire);
            hasher.update(dnskey_rdata);
            hasher.finalize()[..] == ds.digest[..]
        }
        4 => {
            use sha2::Sha384;
            let mut hasher = Sha384::new();
            hasher.update(&wire);
            hasher.update(dnskey_rdata);
            hasher.finalize()[..] == ds.digest[..]
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
#[allow(clippy::too_many_arguments)]
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
pub const DNSSEC_FAIL_BADPACKET:  u32 = 1 << 11;
pub const DNSSEC_FAIL_WORK:       u32 = 1 << 12;

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

// ─── Boot-time clock sanity check (ported from dnssec.c:68-141) ──────────────

/// Outcome of the boot-time timestamp-file check. Decoupled from the actual
/// file IO (stat/create/touch of `--dnssec-timestamp`'s file is a
/// daemon-init concern; see tasks.md for the still-open wiring). The caller
/// reads the configured file's mtime (if any) and passes it in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampSetup {
    /// No timestamp file configured: don't gate signature-time checks on it.
    NotConfigured,
    /// The file's mtime is already in the past (or now): the clock looks
    /// sane, so `back_to_the_future` should be set and signature timestamps
    /// checked from the start. Upstream also re-touches the file here.
    ClockSane,
    /// The file's mtime is still in the future: hold off on checking
    /// signature timestamps until the clock catches up.
    ClockNotYetSane,
}

/// Decide the boot-time clock-sanity outcome from a timestamp file's mtime
/// (`None` if no `--dnssec-timestamp` file is configured). Port of
/// `setup_timestamp()`'s decision logic (dnssec.c:68-111), minus the file
/// creation/touch side effects (caller's responsibility).
pub fn setup_timestamp(timestamp_file_mtime: Option<u64>, now: u64) -> TimestampSetup {
    match timestamp_file_mtime {
        None => TimestampSetup::NotConfigured,
        Some(mtime) if mtime <= now => TimestampSetup::ClockSane,
        Some(_) => TimestampSetup::ClockNotYetSane,
    }
}

/// Pure re-check of whether the system clock has become sane since boot,
/// given the timestamp file's recorded mtime. Mirrors the mutating
/// condition in `is_check_date()` (dnssec.c:126) that flips
/// `daemon->back_to_the_future` and queues a cache purge — those side
/// effects belong at the caller (daemon init/reload), not here.
pub fn timestamp_clock_now_sane(timestamp_file_mtime: u64, now: u64) -> bool {
    now >= timestamp_file_mtime
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

// ─── Trust-chain orchestration (ported from dnssec.c:716-2331) ───────────────
//
// Upstream walks a global `struct crec` cache directly from raw packet
// buffers via pointer arithmetic. This codebase already parses replies into
// `Vec<DnsRr>` (see `explore_rrset`/`validate_rrset` above), and has no live
// DNSSEC-aware cache wiring yet (`cache.rs` supports `F_DS`/`F_DNSKEY`
// storage, but nothing currently populates it — tasks.md tracks that as
// separate, still-open work). `DnssecCache` here is a self-contained trust
// store with the same observable state machine as upstream's cache walk
// (positive DS entries, "proved insecure" negative entries, and "not a zone
// cut" negative entries per RFC 4035 §5.2), so `zone_status`/
// `dnssec_validate_by_ds`/`dnssec_validate_ds`/`dnssec_validate_reply` are
// real and testable now; wiring it to the live cache is future work.

use std::collections::HashMap;

/// Composite validation outcome, mirroring upstream's `STAT_*` codes.
///
/// Unlike upstream (which ORs a `STAT_*` code with `DNSSEC_FAIL_*` bits into
/// a single `int`), this keeps the outcome and diagnostic bits as separate
/// fields on `ValidateStatus`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatCode {
    Secure,
    Insecure,
    Bogus,
    /// A DNSKEY RRset for `name`/`class` is required to continue.
    NeedKey { name: String, class: u16 },
    /// A DS RRset for `name`/`class` is required to continue.
    NeedDs { name: String, class: u16 },
    /// Crypto work-budget counter exhausted (DoS guard).
    Abandoned,
}

/// A `StatCode` plus the `DNSSEC_FAIL_*` diagnostic bitmask (see
/// `errflags_to_ede`), matching upstream's combined `STAT_BOGUS |
/// DNSSEC_FAIL_*` return values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidateStatus {
    pub code: StatCode,
    pub fail: u32,
}

impl ValidateStatus {
    pub fn secure() -> Self { Self { code: StatCode::Secure, fail: 0 } }
    pub fn insecure() -> Self { Self { code: StatCode::Insecure, fail: 0 } }
    pub fn bogus(fail: u32) -> Self { Self { code: StatCode::Bogus, fail } }
    pub fn need_key(name: impl Into<String>, class: u16) -> Self {
        Self { code: StatCode::NeedKey { name: name.into(), class }, fail: 0 }
    }
    pub fn need_ds(name: impl Into<String>, class: u16) -> Self {
        Self { code: StatCode::NeedDs { name: name.into(), class }, fail: 0 }
    }
    pub fn abandoned() -> Self { Self { code: StatCode::Abandoned, fail: 0 } }
    pub fn is_secure(&self) -> bool { self.code == StatCode::Secure }
}

/// Normalize a name for use as a cache/lookup key: lowercase, no trailing dot.
fn norm_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// Per-name DS cache state, mirroring the three outcomes of upstream's
/// `cache_find_by_name(..., F_DS)` walk in `zone_status` (dnssec.c:1908-1942).
#[derive(Debug, Clone)]
enum DsState {
    /// One or more DS records, each tagged with the class they apply to.
    Positive(Vec<(DsData, u16)>),
    /// Proven (via NSEC/NSEC3) that no DS exists here, AND this is a zone
    /// cut (an NS record exists) => the zone below is unsigned.
    /// Upstream: `F_NEG && F_DNSSECOK`.
    NegInsecure,
    /// Proven that no DS exists here, but this isn't a zone cut (no NS
    /// record either) => not meaningful for zone status, skip this level.
    /// Upstream: `F_NEG && !F_DNSSECOK`.
    NegNotZoneCut,
}

/// Self-contained DS/DNSKEY trust store used by the orchestration functions
/// below. See the module-level note above for why this exists instead of
/// wiring directly into `cache.rs`.
#[derive(Debug, Clone, Default)]
pub struct DnssecCache {
    ds: HashMap<String, DsState>,
    dnskey: HashMap<String, Vec<(Vec<u8>, u16)>>,
}

impl DnssecCache {
    pub fn new() -> Self { Self::default() }

    /// Seed a configured trust anchor (`--trust-anchor=`) as a positive DS
    /// entry, exactly as if it had been validated and cached.
    pub fn insert_trust_anchor(&mut self, name: &str, ds: DsData, class: u16) {
        self.ds
            .entry(norm_name(name))
            .and_modify(|s| {
                if let DsState::Positive(v) = s { v.push((ds.clone(), class)); }
                else { *s = DsState::Positive(vec![(ds.clone(), class)]); }
            })
            .or_insert_with(|| DsState::Positive(vec![(ds.clone(), class)]));
    }

    pub fn insert_ds_positive(&mut self, name: &str, entries: Vec<(DsData, u16)>) {
        self.ds.insert(norm_name(name), DsState::Positive(entries));
    }

    pub fn insert_ds_neg_insecure(&mut self, name: &str) {
        self.ds.insert(norm_name(name), DsState::NegInsecure);
    }

    pub fn insert_ds_neg_not_zone_cut(&mut self, name: &str) {
        self.ds.insert(norm_name(name), DsState::NegNotZoneCut);
    }

    fn find_ds(&self, name: &str) -> Option<&DsState> {
        self.ds.get(&norm_name(name))
    }

    /// Cache a validated DNSKEY RDATA blob for `name`/`class`.
    pub fn insert_dnskey(&mut self, name: &str, rdata: Vec<u8>, class: u16) {
        self.dnskey.entry(norm_name(name)).or_default().push((rdata, class));
    }

    pub fn find_dnskeys(&self, name: &str, class: u16) -> Vec<&[u8]> {
        self.dnskey
            .get(&norm_name(name))
            .map(|v| v.iter().filter(|(_, c)| *c == class).map(|(k, _)| k.as_slice()).collect())
            .unwrap_or_default()
    }
}

/// Ordered list of suffixes of `name`, from the root (`""`) to the full
/// name, e.g. `"a.b.com"` -> `["", "com", "b.com", "a.b.com"]`.
fn dns_suffixes(name: &str) -> Vec<String> {
    let name = norm_name(name);
    if name.is_empty() {
        return vec![String::new()];
    }
    let labels: Vec<&str> = name.split('.').collect();
    let mut out = vec![String::new()];
    for i in (0..labels.len()).rev() {
        out.push(labels[i..].join("."));
    }
    out
}

/// A DS entry is usable for validation only if both its digest type and
/// signing algorithm are supported (RFC 4035 §2.2 — if an algorithm appears
/// in the DS, matching RRSIGs MUST exist, so an unsupported combination
/// makes the zone effectively insecure to us).
fn ds_entry_supported(ds: &DsData) -> bool {
    crate::crypto::ds_digest_supported(ds.digest_type) && crate::crypto::algo_supported(ds.algorithm)
}

/// Check the signing status of `name`. Port of `zone_status()`
/// (dnssec.c:1881-1956).
pub fn zone_status(name: &str, class: u16, cache: &DnssecCache) -> ValidateStatus {
    let suffixes = dns_suffixes(name);

    // Phase 1: walk from `name` towards the root looking for the first
    // cached DS entry (a previously-found trust anchor). If none is found,
    // assume a trust anchor exists at the root (name_start = "").
    let mut start_idx = 0usize; // index into `suffixes`; 0 == root
    for (i, suf) in suffixes.iter().enumerate().rev() {
        if cache.find_ds(suf).is_some() {
            start_idx = i;
            break;
        }
    }

    // Phase 2: walk from the trust anchor back down towards `name`.
    for suf in &suffixes[start_idx..] {
        match cache.find_ds(suf) {
            None => return ValidateStatus::need_ds(suf.clone(), class),
            Some(DsState::NegInsecure) => return ValidateStatus::insecure(),
            Some(DsState::NegNotZoneCut) => continue, // not a delegation point, skip
            Some(DsState::Positive(entries)) => {
                let usable = entries.iter().any(|(ds, c)| *c == class && ds_entry_supported(ds));
                if !usable {
                    return ValidateStatus::insecure();
                }
                // Zone at this level is provably signed; keep walking down.
            }
        }
    }

    ValidateStatus::secure()
}

const T_DNSKEY: u16 = 48;

/// Validate a DNSKEY RRset against a cached DS record, and cache the
/// resulting zone-key DNSKEYs on success. Port of `dnssec_validate_by_ds()`
/// (dnssec.c:716-972).
///
/// `records` is the full set of RRs from the answer to a DNSKEY query for
/// `name` (the DNSKEY records plus their covering RRSIG(s)).
pub fn dnssec_validate_by_ds(
    records: &[crate::rfc1035::DnsRr],
    name: &str,
    class: u16,
    now_ts: u32,
    cache: &mut DnssecCache,
    counter: &mut i32,
) -> ValidateStatus {
    let (rrset, rrsigs) = explore_rrset(records, name, class, T_DNSKEY);

    if rrset.is_empty() {
        return ValidateStatus::bogus(DNSSEC_FAIL_NOKEY);
    }
    if rrsigs.is_empty() {
        return ValidateStatus::bogus(DNSSEC_FAIL_NOSIG);
    }

    let ds_entries: &[(DsData, u16)] = match cache.find_ds(name) {
        None => return ValidateStatus::need_ds(norm_name(name), class),
        Some(DsState::Positive(entries)) => entries.as_slice(),
        Some(DsState::NegInsecure) | Some(DsState::NegNotZoneCut) => &[],
    };

    let mut fail = DNSSEC_FAIL_NODSSUP | DNSSEC_FAIL_NOZONE;
    let owned_rrset: Vec<crate::rfc1035::DnsRr> = rrset.iter().map(|r| (*r).clone()).collect();

    for key_rr in &rrset {
        let Ok(key) = parse_dnskey_rdata(&key_rr.rdata) else { continue };
        if key.protocol != 3 { continue; }
        if key.flags & 0x0100 == 0 { continue; } // not a zone key
        fail &= !DNSSEC_FAIL_NOZONE;

        let keytag = compute_key_tag(&key_rr.rdata);

        for (ds, ds_class) in ds_entries {
            if *ds_class != class { continue; }
            if !crate::crypto::ds_digest_supported(ds.digest_type) { continue; }
            fail &= !DNSSEC_FAIL_NODSSUP;
            if ds.algorithm != key.algorithm || ds.key_tag != keytag { continue; }

            if dec_counter(counter) { return ValidateStatus::abandoned(); }

            if !ds_matches_dnskey(ds, &key_rr.rdata, name) { continue; }

            let result = validate_rrset(
                &owned_rrset, &rrsigs, name, T_DNSKEY, class, now_ts,
                Some(&key_rr.rdata), counter,
            );

            match result {
                RrsetValidation::Secure { .. } => {
                    for k in &rrset {
                        if let Ok(kd) = parse_dnskey_rdata(&k.rdata) {
                            if kd.protocol == 3 && kd.flags & 0x0100 != 0 {
                                cache.insert_dnskey(name, k.rdata.clone(), class);
                            }
                        }
                    }
                    return ValidateStatus::secure();
                }
                // Can't validate with this key/DS pair; try the next one.
                _ => continue,
            }
        }
    }

    ValidateStatus::bogus(fail | DNSSEC_FAIL_NOKEY)
}

// ─── NSEC/NSEC3 negative proofs (ported from dnssec.c:1247-1871) ─────────────

const T_NS: u16 = 2;
const T_CNAME: u16 = 5;
const T_SOA: u16 = 6;
const T_DNAME: u16 = 39;
const T_RRSIG: u16 = 46;
const T_NSEC: u16 = 47;
const T_NSEC3: u16 = 50;
const T_DS: u16 = 43;

/// Default `LIMIT_NSEC3_ITERS` (`config.h: DNSSEC_LIMIT_NSEC3_ITERS`).
pub const DEFAULT_NSEC3_ITERS_LIMIT: u32 = 150;

/// A parsed NSEC record plus the `labels` field from its covering RRSIG
/// (needed to detect wildcard-expanded NSECs, RFC 4035 §5.3.1 note in
/// dnssec.c:1274-1292).
#[derive(Debug, Clone)]
pub struct ParsedNsec {
    pub owner: String,
    pub next: String,
    pub bitmap: Vec<u8>,
    pub sig_labels: u8,
}

/// Parse NSEC RDATA (next-domain-name + type bitmap), RFC 4034 §4.1.
pub fn parse_nsec_rdata(rdata: &[u8]) -> Option<(String, Vec<u8>)> {
    let (next, len) = parse_wire_name(rdata).ok()?;
    Some((next, rdata[len..].to_vec()))
}

/// Prove that `name`/`qtype` doesn't exist, using a set of NSEC records from
/// the authority section. Returns `(Ok(()), nons)` on success, where `nons`
/// is `false` if the proof also showed there's no NS record at `name`
/// (used by DS validation to detect "not a zone cut"). Port of
/// `prove_non_existence_nsec()` (dnssec.c:1247-1373).
pub fn prove_non_existence_nsec(nsecs: &[ParsedNsec], name: &str, qtype: u16) -> (Result<(), u32>, bool) {
    let mut nons = true;

    for nsec in nsecs {
        let name_labels = count_labels(&nsec.owner);
        let sig_labels = nsec.sig_labels as u32;

        let owner = if sig_labels < name_labels {
            // NSEC comes from wildcard expansion; use the original wildcard
            // owner for comparison.
            let parts: Vec<&str> = nsec.owner.split('.').collect();
            let skip = (name_labels - sig_labels) as usize;
            format!("*.{}", parts[skip.min(parts.len())..].join("."))
        } else {
            nsec.owner.clone()
        };

        // RFC 6672 §5.3.4.1: a DNAME at an enclosing owner can synthesise
        // an answer, so an NSEC covering a subdomain of a DNAME owner isn't
        // proof of non-existence.
        if type_in_bitmap(&nsec.bitmap, T_DNAME) && crate::rfc1035::hostname_issubdomain(name, &owner) {
            return (Err(DNSSEC_FAIL_NONSEC), nons);
        }

        match hostname_cmp(&owner, name) {
            std::cmp::Ordering::Equal => {
                // RFC 4035 §5.4 last sentence.
                if qtype == T_NSEC || qtype == T_RRSIG {
                    return (Ok(()), nons);
                }
                if !nsec.bitmap.is_empty() {
                    if type_in_bitmap(&nsec.bitmap, T_NS) {
                        nons = false;
                    }
                    if type_in_bitmap(&nsec.bitmap, T_CNAME) {
                        return (Err(DNSSEC_FAIL_NONSEC), nons);
                    }
                    if name_labels != 0 && qtype == T_DS && type_in_bitmap(&nsec.bitmap, T_SOA) {
                        return (Err(DNSSEC_FAIL_NONSEC), nons);
                    }
                }
                if type_in_bitmap(&nsec.bitmap, qtype) {
                    return (Err(DNSSEC_FAIL_NONSEC), nons);
                }
                return (Ok(()), nons);
            }
            std::cmp::Ordering::Less => {
                // Normal case: owner < name. Covers if name < next, or if
                // next <= owner (the NSEC wraps around the end of the zone).
                if hostname_cmp(&nsec.next, name) != std::cmp::Ordering::Less
                    || hostname_cmp(&owner, &nsec.next) != std::cmp::Ordering::Less
                {
                    return (Ok(()), nons);
                }
            }
            std::cmp::Ordering::Greater => {
                // Wrap-around case: name falls between the start of the
                // zone and next.
                if hostname_cmp(&owner, &nsec.next) != std::cmp::Ordering::Less
                    && hostname_cmp(&nsec.next, name) != std::cmp::Ordering::Less
                {
                    return (Ok(()), nons);
                }
            }
        }
    }

    (Err(DNSSEC_FAIL_NONSEC), nons)
}

/// An NSEC3 record pruned to the algo/iterations/salt shared by the set
/// being checked, exposing just the fields `check_nsec3_coverage` needs.
#[derive(Debug, Clone)]
pub struct ParsedNsec3 {
    pub owner_hash: Vec<u8>,
    pub next_hashed: Vec<u8>,
    pub flags: u8,
    pub bitmap: Vec<u8>,
}

/// A fully-parsed NSEC3 record, before pruning to a common algo/iterations/salt.
#[derive(Debug, Clone)]
pub struct ParsedNsec3Raw {
    pub algo: u8,
    pub flags: u8,
    pub iterations: u32,
    pub salt: Vec<u8>,
    pub owner_hash: Vec<u8>,
    pub next_hashed: Vec<u8>,
    pub bitmap: Vec<u8>,
}

/// Parse NSEC3 RDATA (RFC 5155 §3.2): algo, flags, iterations, salt,
/// next-hashed-owner, type bitmap. `owner_hash` must be supplied separately
/// (decoded from the owner name's first label, base32).
struct Nsec3RdataFields {
    algo: u8,
    flags: u8,
    iterations: u32,
    salt: Vec<u8>,
    next_hashed: Vec<u8>,
    bitmap: Vec<u8>,
}

fn parse_nsec3_rdata(rdata: &[u8]) -> Option<Nsec3RdataFields> {
    if rdata.len() < 5 { return None; }
    let algo = rdata[0];
    let flags = rdata[1];
    let iterations = u16::from_be_bytes([rdata[2], rdata[3]]) as u32;
    let salt_len = rdata[4] as usize;
    let mut pos = 5;
    if rdata.len() < pos + salt_len + 1 { return None; }
    let salt = rdata[pos..pos + salt_len].to_vec();
    pos += salt_len;
    let hash_len = rdata[pos] as usize;
    pos += 1;
    if rdata.len() < pos + hash_len { return None; }
    let next_hashed = rdata[pos..pos + hash_len].to_vec();
    pos += hash_len;
    let bitmap = rdata[pos..].to_vec();
    Some(Nsec3RdataFields { algo, flags, iterations, salt, next_hashed, bitmap })
}

/// Find whether `digest` (the hashed query name) is covered by, or exactly
/// matches, one of `nsec3s`. On an exact match, also checks the type
/// bitmap for `qtype`/NS/CNAME/SOA per RFC 5155 §8.3. Port of
/// `check_nsec3_coverage()` (dnssec.c:1440-1551).
pub fn check_nsec3_coverage(
    digest: &[u8], qtype: u16, nsec3s: &[ParsedNsec3], nons: &mut bool, name_labels: u32,
) -> bool {
    for n in nsec3s {
        if n.owner_hash.len() != digest.len() || n.next_hashed.len() != digest.len() {
            continue;
        }
        match n.owner_hash.as_slice().cmp(digest) {
            std::cmp::Ordering::Equal => {
                if !n.bitmap.is_empty() {
                    if type_in_bitmap(&n.bitmap, T_NS) {
                        *nons = false;
                    }
                    if type_in_bitmap(&n.bitmap, T_CNAME) {
                        return false;
                    }
                    if name_labels != 0 && qtype == T_DS && type_in_bitmap(&n.bitmap, T_SOA) {
                        return false;
                    }
                }
                return !type_in_bitmap(&n.bitmap, qtype);
            }
            std::cmp::Ordering::Less => {
                // Normal case: owner_hash < digest.
                if n.next_hashed.as_slice() >= digest || n.owner_hash.as_slice() >= n.next_hashed.as_slice() {
                    if n.flags & 0x01 != 0 {
                        *nons = false; // opt-out
                    }
                    return true;
                }
            }
            std::cmp::Ordering::Greater => {
                // Wrap-around case.
                if n.owner_hash.as_slice() >= n.next_hashed.as_slice() && n.next_hashed.as_slice() >= digest {
                    if n.flags & 0x01 != 0 {
                        *nons = false;
                    }
                    return true;
                }
            }
        }
    }
    false
}

fn sha1_hash(data: &[u8]) -> Vec<u8> {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(data);
    h.finalize().to_vec()
}

/// Prove that `name`/`qtype` doesn't exist, using NSEC3 records (RFC 5155).
/// `wild_offset` (in labels stripped from `name`) stops the closest-encloser
/// walk early when re-checking a wildcard-replay attempt; pass 0 for a plain
/// negative-answer proof. Port of `prove_non_existence_nsec3()`
/// (dnssec.c:1554-1716).
pub fn prove_non_existence_nsec3(
    raw: &[ParsedNsec3Raw],
    name: &str,
    qtype: u16,
    wild_offset: usize,
    nons: &mut bool,
    counter: &mut i32,
    iters_limit: u32,
) -> Result<(), u32> {
    *nons = true;

    // Pick the algo/iterations/salt from the first record with a supported
    // algorithm, then prune to only records that match all three.
    let Some(chosen) = raw.iter().find(|r| crate::crypto::nsec3_digest_name(r.algo).is_some()) else {
        return Err(DNSSEC_FAIL_NONSEC);
    };
    let (algo, iterations, salt) = (chosen.algo, chosen.iterations, chosen.salt.clone());

    if iterations > iters_limit {
        return Err(DNSSEC_FAIL_NSEC3_ITERS);
    }

    let pruned: Vec<ParsedNsec3> = raw
        .iter()
        .filter(|r| r.algo == algo && (r.flags == 0 || r.flags == 1) && r.iterations == iterations && r.salt == salt)
        .map(|r| ParsedNsec3 {
            owner_hash: r.owner_hash.clone(),
            next_hashed: r.next_hashed.clone(),
            flags: r.flags,
            bitmap: r.bitmap.clone(),
        })
        .collect();

    if dec_counter(counter) { return Err(DNSSEC_FAIL_WORK); }
    let Some(digest) = hash_name(name, &salt, iterations, sha1_hash) else { return Err(DNSSEC_FAIL_NONSEC) };

    if check_nsec3_coverage(&digest, qtype, &pruned, nons, count_labels(name)) {
        return Ok(());
    }

    // No NSEC3 directly covers `name`; find the closest-encloser NSEC3 and
    // the "next closest" (one label below it) that doesn't exist.
    let mut candidate = norm_name(name);
    let mut next_closest: Option<String> = None;
    let mut found_closest = false;
    let mut stripped = 0usize;

    loop {
        if wild_offset != 0 && stripped == wild_offset {
            break;
        }
        if dec_counter(counter) { return Err(DNSSEC_FAIL_WORK); }
        let Some(cand_digest) = hash_name(&candidate, &salt, iterations, sha1_hash) else {
            return Err(DNSSEC_FAIL_NONSEC);
        };
        if pruned.iter().any(|n| n.owner_hash == cand_digest) {
            found_closest = true;
            break;
        }
        next_closest = Some(candidate.clone());
        stripped += 1;
        match candidate.split_once('.') {
            Some((_, rest)) => candidate = rest.to_string(),
            None => break,
        }
    }

    let (Some(next_closest), true) = (next_closest, found_closest) else {
        return Err(DNSSEC_FAIL_NONSEC);
    };

    if dec_counter(counter) { return Err(DNSSEC_FAIL_WORK); }
    let Some(nc_digest) = hash_name(&next_closest, &salt, iterations, sha1_hash) else {
        return Err(DNSSEC_FAIL_NONSEC);
    };
    let mut ignored = false;
    if !check_nsec3_coverage(&nc_digest, qtype, &pruned, &mut ignored, 1) {
        return Err(DNSSEC_FAIL_NONSEC);
    }

    // Finally, rule out wildcard synthesis at the closest encloser.
    if wild_offset == 0 {
        let Some((_, rest)) = next_closest.split_once('.') else { return Err(DNSSEC_FAIL_NONSEC) };
        if rest.is_empty() { return Err(DNSSEC_FAIL_NONSEC); }
        let wildcard = format!("*.{rest}");

        if dec_counter(counter) { return Err(DNSSEC_FAIL_WORK); }
        let Some(wc_digest) = hash_name(&wildcard, &salt, iterations, sha1_hash) else {
            return Err(DNSSEC_FAIL_NONSEC);
        };
        let mut ignored2 = false;
        if !check_nsec3_coverage(&wc_digest, qtype, &pruned, &mut ignored2, 1) {
            return Err(DNSSEC_FAIL_NONSEC);
        }
    }

    Ok(())
}

/// Find NSEC/NSEC3 records in `authority` (the authority section of a
/// reply) proving that `name`/`qtype` doesn't exist, and dispatch to the
/// matching proof routine. Port of `prove_non_existence()`
/// (dnssec.c:1719-1871).
#[allow(clippy::too_many_arguments)]
pub fn prove_non_existence(
    authority: &[crate::rfc1035::DnsRr],
    name: &str,
    qtype: u16,
    qclass: u16,
    wild_offset: usize,
    nons: &mut bool,
    counter: &mut i32,
    iters_limit: u32,
) -> Result<(), u32> {
    let nsec_rrs: Vec<&crate::rfc1035::DnsRr> =
        authority.iter().filter(|r| r.rtype == T_NSEC && r.class == qclass).collect();
    let nsec3_rrs: Vec<&crate::rfc1035::DnsRr> =
        authority.iter().filter(|r| r.rtype == T_NSEC3 && r.class == qclass).collect();

    if !nsec_rrs.is_empty() && !nsec3_rrs.is_empty() {
        return Err(DNSSEC_FAIL_NONSEC); // no mixed NSECing.
    }

    if !nsec_rrs.is_empty() {
        let mut parsed = Vec::with_capacity(nsec_rrs.len());
        for rr in &nsec_rrs {
            let Some((next, bitmap)) = parse_nsec_rdata(&rr.rdata) else { return Err(DNSSEC_FAIL_BADPACKET) };

            // Find the covering RRSIG(NSEC)'s `labels` field; all sigs for
            // this NSEC must agree (dnssec.c:1817-1821).
            let mut sig_labels: Option<u8> = None;
            for sig in authority.iter().filter(|s| s.rtype == T_RRSIG && s.class == qclass && s.name.eq_ignore_ascii_case(&rr.name)) {
                if sig.rdata.len() < 18 { return Err(DNSSEC_FAIL_BADPACKET); }
                let type_covered = u16::from_be_bytes([sig.rdata[0], sig.rdata[1]]);
                if type_covered != T_NSEC { continue; }
                let labels = sig.rdata[3];
                match sig_labels {
                    None => sig_labels = Some(labels),
                    Some(l) if l != labels => return Err(DNSSEC_FAIL_NONSEC),
                    _ => {}
                }
            }
            let Some(sig_labels) = sig_labels else { return Err(DNSSEC_FAIL_NONSEC) };

            parsed.push(ParsedNsec { owner: rr.name.clone(), next, bitmap, sig_labels });
        }
        let (result, found_nons) = prove_non_existence_nsec(&parsed, name, qtype);
        *nons = found_nons;
        return result;
    }

    if !nsec3_rrs.is_empty() {
        let mut raw = Vec::with_capacity(nsec3_rrs.len());
        for rr in &nsec3_rrs {
            let Some(owner_hash) = base32_decode(&rr.name) else { return Err(DNSSEC_FAIL_BADPACKET) };
            let Some(fields) = parse_nsec3_rdata(&rr.rdata) else {
                return Err(DNSSEC_FAIL_BADPACKET);
            };
            raw.push(ParsedNsec3Raw {
                algo: fields.algo,
                flags: fields.flags,
                iterations: fields.iterations,
                salt: fields.salt,
                owner_hash,
                next_hashed: fields.next_hashed,
                bitmap: fields.bitmap,
            });
        }
        return prove_non_existence_nsec3(&raw, name, qtype, wild_offset, nons, counter, iters_limit);
    }

    Err(DNSSEC_FAIL_NONSEC)
}

const RCODE_NOERROR:  u8 = 0;
const RCODE_SERVFAIL: u8 = 2;
const RCODE_NXDOMAIN: u8 = 3;
const T_CNAME_Q: u16 = 5;
const T_ANY: u16 = 255;

/// Validate all RRsets in the answer and authority sections of a reply
/// (RFC 4035 §3.2.3). Top-level entry point. Port of
/// `dnssec_validate_reply()` (dnssec.c:1974-2331).
///
/// `nons`, when supplied, switches to "DS-reply mode": unsigned RRsets in
/// the authority section don't make the reply insecure (only NSEC/NSEC3
/// must be signed there), matching upstream's `nons != NULL` branch.
///
/// Not ported (see tasks.md): DNAME-synthesizes-CNAME pre-qualification,
/// and the wildcard-replay wildcard-non-existence recheck — both are
/// defense-in-depth refinements on top of the core validate/prove-negative
/// state machine implemented here.
#[allow(clippy::too_many_arguments)]
pub fn dnssec_validate_reply(
    answer: &[crate::rfc1035::DnsRr],
    authority: &[crate::rfc1035::DnsRr],
    qname: &str,
    qtype: u16,
    qclass: u16,
    rcode: u8,
    now_ts: u32,
    cache: &mut DnssecCache,
    counter: &mut i32,
    check_unsigned: bool,
    nons: Option<&mut bool>,
    iters_limit: u32,
) -> ValidateStatus {
    if rcode == RCODE_SERVFAIL {
        return ValidateStatus::bogus(DNSSEC_FAIL_UPSTREAM);
    }
    if rcode != RCODE_NXDOMAIN && rcode != RCODE_NOERROR {
        return ValidateStatus::insecure();
    }
    if qtype == T_RRSIG {
        return ValidateStatus::insecure();
    }

    // Chase the CNAME chain (if any) from `qname` to find the name that
    // actually needs an answer or a non-existence proof.
    let mut target = norm_name(qname);
    let mut answered = false;
    if qtype != T_CNAME_Q && qtype != T_ANY {
        loop {
            if answer.iter().any(|r| norm_name(&r.name) == target && r.rtype == qtype && r.class == qclass) {
                answered = true;
                break;
            }
            let cname = answer.iter().find(|r| norm_name(&r.name) == target && r.rtype == T_CNAME_Q && r.class == qclass);
            match cname {
                Some(rr) => match parse_wire_name(&rr.rdata) {
                    Ok((next, _)) => target = norm_name(&next),
                    Err(_) => break,
                },
                None => break,
            }
        }
    } else {
        answered = answer.iter().any(|r| norm_name(&r.name) == target && r.class == qclass && (qtype == T_ANY || r.rtype == qtype));
    }

    // Validate every distinct (name, type, class) RRset present in the
    // answer + authority sections (RRSIG records themselves are never
    // validated directly).
    let mut combined: Vec<crate::rfc1035::DnsRr> = Vec::with_capacity(answer.len() + authority.len());
    combined.extend_from_slice(answer);
    combined.extend_from_slice(authority);

    let mut seen: std::collections::HashSet<(String, u16, u16)> = std::collections::HashSet::new();
    let mut secure_flag = ValidateStatus::secure();

    for rr in &combined {
        if rr.rtype == T_RRSIG { continue; }
        let key = (norm_name(&rr.name), rr.rtype, rr.class);
        if !seen.insert(key.clone()) { continue; }

        let in_answer = answer.iter().any(|a| norm_name(&a.name) == key.0 && a.rtype == key.1 && a.class == key.2);

        let (rrset, rrsigs) = explore_rrset(&combined, &rr.name, rr.class, rr.rtype);

        if rrsigs.is_empty() {
            if rr.rtype == T_NSEC || rr.rtype == T_NSEC3 {
                return ValidateStatus::bogus(DNSSEC_FAIL_NOSIG);
            }
            if nons.is_some() && !in_answer {
                // DS-reply mode: unsigned non-NSEC RRsets in the authority
                // section don't affect the overall secure/insecure verdict.
                continue;
            }
            if !check_unsigned || !in_answer {
                secure_flag = ValidateStatus::insecure();
                continue;
            }
            // check_unsigned && in_answer: fall through to a strict
            // validate attempt below, which will fail closed (no sigs).
        }

        // All RRSIGs covering an RRset must share one signer name
        // (dnssec.c:388-393) — otherwise this could be a mix-and-match
        // forgery across zones.
        let mut signer: Option<String> = None;
        for sig in &rrsigs {
            if sig.rdata.len() < 18 { return ValidateStatus::bogus(DNSSEC_FAIL_BADPACKET); }
            let Ok((s, _)) = parse_wire_name(&sig.rdata[18..]) else { return ValidateStatus::bogus(DNSSEC_FAIL_BADPACKET) };
            match &signer {
                None => signer = Some(s),
                Some(existing) if !existing.eq_ignore_ascii_case(&s) => return ValidateStatus::bogus(DNSSEC_FAIL_NOSIG),
                _ => {}
            }
        }
        let zone_name = signer.unwrap_or_else(|| rr.name.clone());

        let zs = zone_status(&zone_name, rr.class, cache);
        match &zs.code {
            StatCode::NeedKey { .. } | StatCode::NeedDs { .. } | StatCode::Bogus | StatCode::Abandoned => return zs,
            StatCode::Insecure => {
                secure_flag = ValidateStatus::insecure();
                continue;
            }
            StatCode::Secure => {}
        }

        let owned_rrset: Vec<crate::rfc1035::DnsRr> = rrset.iter().map(|r| (*r).clone()).collect();
        let keys = cache.find_dnskeys(&zone_name, rr.class);
        if keys.is_empty() {
            return ValidateStatus::need_key(zone_name, rr.class);
        }

        let mut rrset_secure = false;
        for key in &keys {
            match validate_rrset(&owned_rrset, &rrsigs, &rr.name, rr.rtype, rr.class, now_ts, Some(key), counter) {
                RrsetValidation::Secure { .. } => { rrset_secure = true; break; }
                _ => continue,
            }
        }
        if !rrset_secure {
            return ValidateStatus::bogus(DNSSEC_FAIL_NOKEY);
        }
    }

    if answered {
        return secure_flag;
    }

    // Missing answer (NXDOMAIN or NODATA): require an NSEC/NSEC3 proof.
    let rc_nsec = prove_non_existence(authority, &target, qtype, qclass, 0, nons.unwrap_or(&mut true), counter, iters_limit);
    match rc_nsec {
        Ok(()) => secure_flag,
        Err(fail) => {
            if fail & (DNSSEC_FAIL_NONSEC | DNSSEC_FAIL_NSEC3_ITERS) != 0 {
                let zs = zone_status(&target, qclass, cache);
                if !zs.is_secure() {
                    return zs;
                }
            }
            ValidateStatus::bogus(fail)
        }
    }
}

/// Validate (or accept a negative proof for) the answer to a DS query, and
/// cache the result. Port of `dnssec_validate_ds()` (dnssec.c:990-1179).
///
/// Not ported (see tasks.md): the RFC-1918/domain-specific-server insecure-DS
/// fallback carve-outs (dnssec.c:1026-1047), and the CNAME-proves-DS-absence
/// `prim_ok` path — both require config/cache surfaces (`--bogus-priv`,
/// `lookup_domain`) this module doesn't have access to yet.
#[allow(clippy::too_many_arguments)]
pub fn dnssec_validate_ds(
    answer: &[crate::rfc1035::DnsRr],
    authority: &[crate::rfc1035::DnsRr],
    name: &str,
    class: u16,
    rcode: u8,
    now_ts: u32,
    cache: &mut DnssecCache,
    counter: &mut i32,
    iters_limit: u32,
) -> ValidateStatus {
    let servfail = rcode == RCODE_SERVFAIL;
    let neganswer = !answer.iter().any(|r| r.rtype == T_DS && r.class == class);
    let mut nons = false;

    if !servfail {
        let rc = dnssec_validate_reply(
            answer, authority, name, T_DS, class, rcode, now_ts, cache, counter, false, Some(&mut nons), iters_limit,
        );

        match &rc.code {
            StatCode::Insecure => {
                if !neganswer {
                    return ValidateStatus::bogus(DNSSEC_FAIL_INDET);
                }
                // Negative + insecure is acceptable; fall through to caching.
            }
            StatCode::NeedKey { name: needed, .. } if norm_name(needed) == norm_name(name) => {
                // The key needed to validate the DS lives at the DS's own
                // name: this would loop forever asking for the same thing.
                return ValidateStatus::bogus(0);
            }
            StatCode::Secure => {}
            _ => return rc, // NeedKey (elsewhere), NeedDs, Bogus, Abandoned
        }
    }

    if !servfail && !neganswer {
        let mut found_supported = false;
        let mut entries = Vec::new();
        for rr in answer.iter().filter(|r| r.rtype == T_DS && r.class == class) {
            if let Ok(ds) = parse_ds_rdata(&rr.rdata) {
                if crate::crypto::ds_digest_supported(ds.digest_type) && crate::crypto::algo_supported(ds.algorithm) {
                    entries.push((ds, class));
                    found_supported = true;
                }
            }
        }
        if found_supported {
            cache.insert_ds_positive(name, entries);
            return ValidateStatus::secure();
        }
        // Fall through: an answer with only unsupported algorithms is
        // treated as proof of no (usable) DS, RFC 4035 §5.2.
    }

    if servfail || nons {
        cache.insert_ds_neg_not_zone_cut(name);
    } else {
        cache.insert_ds_neg_insecure(name);
    }

    ValidateStatus::secure()
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
    fn test_ds_matches_dnskey_sha1() {
        use sha1::{Digest, Sha1};

        let owner = "example.com.";
        let dnskey_rdata = sample_dnskey_rdata();

        let wire = name_to_wire(owner).unwrap();
        let mut hasher = Sha1::new();
        hasher.update(&wire);
        hasher.update(&dnskey_rdata);
        let digest = hasher.finalize().to_vec();

        let ds = DsData {
            key_tag:     compute_key_tag(&dnskey_rdata),
            algorithm:   8,
            digest_type: 1,
            digest:      digest.clone(),
        };

        assert!(ds_matches_dnskey(&ds, &dnskey_rdata, owner));

        let mut bad_ds = ds.clone();
        bad_ds.digest[0] ^= 0xFF;
        assert!(!ds_matches_dnskey(&bad_ds, &dnskey_rdata, owner));
    }

    #[test]
    fn test_ds_matches_dnskey_sha384() {
        use sha2::{Digest, Sha384};

        let owner = "example.com.";
        let dnskey_rdata = sample_dnskey_rdata();

        let wire = name_to_wire(owner).unwrap();
        let mut hasher = Sha384::new();
        hasher.update(&wire);
        hasher.update(&dnskey_rdata);
        let digest = hasher.finalize().to_vec();

        let ds = DsData {
            key_tag:     compute_key_tag(&dnskey_rdata),
            algorithm:   8,
            digest_type: 4,
            digest:      digest.clone(),
        };

        assert!(ds_matches_dnskey(&ds, &dnskey_rdata, owner));

        let mut bad_ds = ds.clone();
        bad_ds.digest[0] ^= 0xFF;
        assert!(!ds_matches_dnskey(&bad_ds, &dnskey_rdata, owner));
    }

    #[test]
    fn test_ds_matches_dnskey_unsupported_digest_type() {
        let owner = "example.com.";
        let dnskey_rdata = sample_dnskey_rdata();
        let ds = DsData {
            key_tag:     compute_key_tag(&dnskey_rdata),
            algorithm:   8,
            digest_type: 3, // GOST, unsupported
            digest:      vec![0u8; 32],
        };
        assert!(!ds_matches_dnskey(&ds, &dnskey_rdata, owner));
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

    // ─── zone_status ──────────────────────────────────────────────────────

    fn sample_ds() -> DsData {
        DsData { key_tag: 1234, algorithm: 8, digest_type: 2, digest: vec![0xAB; 32] }
    }

    #[test]
    fn zone_status_no_trust_anchor_anywhere_needs_ds_at_root() {
        let cache = DnssecCache::new();
        let status = zone_status("example.com", 1, &cache);
        assert_eq!(status.code, StatCode::NeedDs { name: String::new(), class: 1 });
    }

    #[test]
    fn zone_status_trust_anchor_at_queried_name_is_secure() {
        let mut cache = DnssecCache::new();
        cache.insert_ds_positive("example.com", vec![(sample_ds(), 1)]);
        let status = zone_status("example.com", 1, &cache);
        assert_eq!(status.code, StatCode::Secure);
    }

    #[test]
    fn zone_status_trust_anchor_at_ancestor_walks_down_to_secure() {
        let mut cache = DnssecCache::new();
        cache.insert_ds_positive("com", vec![(sample_ds(), 1)]);
        cache.insert_ds_positive("example.com", vec![(sample_ds(), 1)]);
        let status = zone_status("sub.example.com", 1, &cache);
        // No DS cached at sub.example.com itself -> NEED_DS for that name.
        assert_eq!(status.code, StatCode::NeedDs { name: "sub.example.com".to_string(), class: 1 });
    }

    #[test]
    fn zone_status_negative_insecure_proof_short_circuits() {
        let mut cache = DnssecCache::new();
        cache.insert_ds_neg_insecure("com");
        let status = zone_status("example.com", 1, &cache);
        assert_eq!(status.code, StatCode::Insecure);
    }

    #[test]
    fn zone_status_not_zone_cut_is_skipped() {
        let mut cache = DnssecCache::new();
        cache.insert_ds_neg_not_zone_cut("com");
        cache.insert_ds_positive("example.com", vec![(sample_ds(), 1)]);
        // "com" is a non-zone-cut (skip), "example.com" has a usable DS -> Secure.
        let status = zone_status("example.com", 1, &cache);
        assert_eq!(status.code, StatCode::Secure);
    }

    #[test]
    fn zone_status_unsupported_ds_algo_is_insecure() {
        let mut cache = DnssecCache::new();
        let unsupported = DsData { key_tag: 1, algorithm: 1 /* RSAMD5, unsupported */, digest_type: 2, digest: vec![0u8; 32] };
        cache.insert_ds_positive("example.com", vec![(unsupported, 1)]);
        let status = zone_status("example.com", 1, &cache);
        assert_eq!(status.code, StatCode::Insecure);
    }

    #[test]
    fn zone_status_wrong_class_is_ignored() {
        let mut cache = DnssecCache::new();
        cache.insert_ds_positive("example.com", vec![(sample_ds(), 2 /* CHAOS */)]);
        let status = zone_status("example.com", 1, &cache);
        // A DS entry exists at this name, but none for class 1 -> treated
        // like "no usable DS", i.e. insecure (matches upstream: a found
        // crec with no class/algo match falls through to STAT_INSECURE,
        // not STAT_NEED_DS).
        assert_eq!(status.code, StatCode::Insecure);
    }

    // ─── dnssec_validate_by_ds ────────────────────────────────────────────

    /// Build a self-signed DNSKEY RRset: one zone-key DNSKEY record plus an
    /// RRSIG(DNSKEY) signed by that same key, using ECDSA P-256 (algorithm 13).
    /// Returns (dnskey_rr, rrsig_rr, dnskey_rdata, ds_matching_the_key).
    fn build_dnskey_self_sign_scenario(
        name: &str,
        class: u16,
    ) -> (crate::rfc1035::DnsRr, crate::rfc1035::DnsRr, Vec<u8>, DsData, p256::ecdsa::SigningKey) {
        use p256::ecdsa::signature::Signer;
        use p256::ecdsa::SigningKey;
        use rand::rngs::OsRng;

        const ALGO: u8 = 13;
        let signing_key = SigningKey::random(&mut OsRng);
        let dnskey_rdata = dnskey_rdata_for_ecdsa_p256(signing_key.verifying_key());
        let key_tag = compute_key_tag(&dnskey_rdata);

        let dnskey_rr = make_typed_rr(name, 48 /* DNSKEY */, &dnskey_rdata);
        let orig_ttl: u32 = 300;
        let labels = count_labels(name) as u8;

        let mut header = Vec::new();
        header.extend_from_slice(&48u16.to_be_bytes()); // type_covered = DNSKEY
        header.push(ALGO);
        header.push(labels);
        header.extend_from_slice(&orig_ttl.to_be_bytes());
        header.extend_from_slice(&u32::MAX.to_be_bytes()); // expiry
        header.extend_from_slice(&0u32.to_be_bytes());     // inception
        header.extend_from_slice(&key_tag.to_be_bytes());

        let wire_name = name_to_wire(name).unwrap();

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&header);
        signed_data.extend_from_slice(&wire_name); // signer
        signed_data.extend_from_slice(&wire_name); // owner
        signed_data.extend_from_slice(&48u16.to_be_bytes());
        signed_data.extend_from_slice(&class.to_be_bytes());
        signed_data.extend_from_slice(&orig_ttl.to_be_bytes());
        let rdlen = dnskey_rdata.len() as u16;
        signed_data.extend_from_slice(&rdlen.to_be_bytes());
        signed_data.extend_from_slice(&dnskey_rdata);

        let signature: p256::ecdsa::Signature = signing_key.sign(&signed_data);
        let mut rrsig_rdata = header.clone();
        rrsig_rdata.extend_from_slice(&wire_name);
        rrsig_rdata.extend_from_slice(&signature.to_bytes());

        let rrsig_rr = make_typed_rr(name, 46, &rrsig_rdata);

        // DS matching this key via SHA-256.
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&wire_name);
        hasher.update(&dnskey_rdata);
        let digest = hasher.finalize().to_vec();
        let ds = DsData { key_tag, algorithm: ALGO, digest_type: 2, digest };

        (dnskey_rr, rrsig_rr, dnskey_rdata, ds, signing_key)
    }

    #[test]
    fn dnssec_validate_by_ds_valid_chain_caches_key() {
        let name = "example.com";
        let class = 1u16;
        let (dnskey_rr, rrsig_rr, dnskey_rdata, ds, _signing_key) = build_dnskey_self_sign_scenario(name, class);

        let mut cache = DnssecCache::new();
        cache.insert_ds_positive(name, vec![(ds, class)]);

        let records = vec![dnskey_rr, rrsig_rr];
        let mut counter = 100i32;
        let status = dnssec_validate_by_ds(&records, name, class, 500_000, &mut cache, &mut counter);

        assert_eq!(status.code, StatCode::Secure, "expected Secure, got {status:?}");
        let keys = cache.find_dnskeys(name, class);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], dnskey_rdata.as_slice());
    }

    #[test]
    fn dnssec_validate_by_ds_no_ds_cached_needs_ds() {
        let name = "example.com";
        let class = 1u16;
        let (dnskey_rr, rrsig_rr, _rdata, _ds, _sk) = build_dnskey_self_sign_scenario(name, class);

        let mut cache = DnssecCache::new();
        let records = vec![dnskey_rr, rrsig_rr];
        let mut counter = 100i32;
        let status = dnssec_validate_by_ds(&records, name, class, 500_000, &mut cache, &mut counter);

        assert_eq!(status.code, StatCode::NeedDs { name: name.to_string(), class });
    }

    #[test]
    fn dnssec_validate_by_ds_wrong_digest_is_bogus() {
        let name = "example.com";
        let class = 1u16;
        let (dnskey_rr, rrsig_rr, _rdata, mut ds, _sk) = build_dnskey_self_sign_scenario(name, class);
        ds.digest[0] ^= 0xFF; // corrupt the DS digest

        let mut cache = DnssecCache::new();
        cache.insert_ds_positive(name, vec![(ds, class)]);

        let records = vec![dnskey_rr, rrsig_rr];
        let mut counter = 100i32;
        let status = dnssec_validate_by_ds(&records, name, class, 500_000, &mut cache, &mut counter);

        assert_eq!(status.code, StatCode::Bogus, "expected Bogus, got {status:?}");
        assert!(cache.find_dnskeys(name, class).is_empty());
    }

    #[test]
    fn dnssec_validate_by_ds_no_rrsig_is_bogus() {
        let name = "example.com";
        let class = 1u16;
        let (dnskey_rr, _rrsig_rr, _rdata, ds, _sk) = build_dnskey_self_sign_scenario(name, class);

        let mut cache = DnssecCache::new();
        cache.insert_ds_positive(name, vec![(ds, class)]);

        let records = vec![dnskey_rr]; // no RRSIG
        let mut counter = 100i32;
        let status = dnssec_validate_by_ds(&records, name, class, 500_000, &mut cache, &mut counter);

        assert_eq!(status.code, StatCode::Bogus);
    }

    // ─── prove_non_existence_nsec ──────────────────────────────────────────

    /// Build NSEC RDATA: next-domain-name (wire) + type bitmap.
    fn nsec_rdata(next: &str, bitmap: &[u8]) -> Vec<u8> {
        let mut r = name_to_wire(next).unwrap();
        r.extend_from_slice(bitmap);
        r
    }

    // Window 0, length 1, NS(2)+SOA(6) set: mask 0x20 (NS) | 0x02 (SOA) = 0x22
    const BM_NS_SOA: [u8; 3] = [0, 1, 0x22];
    // Window 0, length 1, A(1) only: mask 0x40
    const BM_A: [u8; 3] = [0, 1, 0x40];
    // Empty bitmap (no types at all, just NSEC/RRSIG normally but keep empty for tests)
    const BM_EMPTY: [u8; 0] = [];

    #[test]
    fn prove_non_existence_nsec_covers_missing_name() {
        // NSEC a.com -> c.com proves b.com doesn't exist.
        let nsecs = vec![ParsedNsec {
            owner: "a.com".to_string(), next: "c.com".to_string(),
            bitmap: BM_NS_SOA.to_vec(), sig_labels: 2,
        }];
        let (result, _nons) = prove_non_existence_nsec(&nsecs, "b.com", 1 /* A */);
        assert!(result.is_ok(), "expected proof to succeed, got {result:?}");
    }

    #[test]
    fn prove_non_existence_nsec_no_covering_record_fails() {
        let nsecs = vec![ParsedNsec {
            owner: "x.com".to_string(), next: "y.com".to_string(),
            bitmap: BM_NS_SOA.to_vec(), sig_labels: 2,
        }];
        let (result, _nons) = prove_non_existence_nsec(&nsecs, "b.com", 1);
        assert_eq!(result, Err(DNSSEC_FAIL_NONSEC));
    }

    #[test]
    fn prove_non_existence_nsec_nodata_type_absent_succeeds() {
        // NSEC at exactly "a.com" with only NS+SOA in the bitmap proves no A record.
        let nsecs = vec![ParsedNsec {
            owner: "a.com".to_string(), next: "z.com".to_string(),
            bitmap: BM_NS_SOA.to_vec(), sig_labels: 2,
        }];
        let (result, _nons) = prove_non_existence_nsec(&nsecs, "a.com", 1 /* A */);
        assert!(result.is_ok(), "expected NODATA proof to succeed, got {result:?}");
    }

    #[test]
    fn prove_non_existence_nsec_nodata_type_present_fails() {
        // Bitmap says A exists -> can't prove non-existence of an A record.
        let nsecs = vec![ParsedNsec {
            owner: "a.com".to_string(), next: "z.com".to_string(),
            bitmap: BM_A.to_vec(), sig_labels: 2,
        }];
        let (result, _nons) = prove_non_existence_nsec(&nsecs, "a.com", 1 /* A */);
        assert_eq!(result, Err(DNSSEC_FAIL_NONSEC));
    }

    #[test]
    fn prove_non_existence_nsec_wraparound_covers() {
        // NSEC z.com -> a.com is the last record in the zone (wraps back to
        // the first name, "a.com"). A name sorting before "a.com" (e.g.
        // "0.com", digit < letter in canonical order) is covered by the wrap.
        let nsecs = vec![ParsedNsec {
            owner: "z.com".to_string(), next: "a.com".to_string(),
            bitmap: BM_NS_SOA.to_vec(), sig_labels: 2,
        }];
        let (result, _nons) = prove_non_existence_nsec(&nsecs, "0.com", 1);
        assert!(result.is_ok(), "expected wraparound proof to succeed, got {result:?}");
    }

    #[test]
    fn prove_non_existence_nsec_empty_bitmap_nodata() {
        let nsecs = vec![ParsedNsec {
            owner: "a.com".to_string(), next: "z.com".to_string(),
            bitmap: BM_EMPTY.to_vec(), sig_labels: 2,
        }];
        let (result, _nons) = prove_non_existence_nsec(&nsecs, "a.com", 1);
        assert!(result.is_ok());
    }

    // ─── check_nsec3_coverage / prove_non_existence_nsec3 ──────────────────

    fn n3(owner_hash: &[u8], next_hashed: &[u8], flags: u8, bitmap: &[u8]) -> ParsedNsec3 {
        ParsedNsec3 {
            owner_hash: owner_hash.to_vec(),
            next_hashed: next_hashed.to_vec(),
            flags,
            bitmap: bitmap.to_vec(),
        }
    }

    #[test]
    fn check_nsec3_coverage_exact_match_nodata() {
        let digest = vec![5u8; 4];
        let recs = vec![n3(&[5, 5, 5, 5], &[9, 9, 9, 9], 0, &BM_NS_SOA)];
        let mut nons = true;
        assert!(check_nsec3_coverage(&digest, 1 /* A */, &recs, &mut nons, 2));
    }

    #[test]
    fn check_nsec3_coverage_exact_match_type_exists_fails() {
        let digest = vec![5u8; 4];
        let recs = vec![n3(&[5, 5, 5, 5], &[9, 9, 9, 9], 0, &BM_A)];
        let mut nons = true;
        assert!(!check_nsec3_coverage(&digest, 1 /* A */, &recs, &mut nons, 2));
    }

    #[test]
    fn check_nsec3_coverage_covering_range() {
        // owner_hash=2 < digest=5 < next_hashed=8: normal covering range.
        let digest = vec![5u8];
        let recs = vec![n3(&[2], &[8], 0, &BM_NS_SOA)];
        let mut nons = true;
        assert!(check_nsec3_coverage(&digest, 1, &recs, &mut nons, 2));
    }

    #[test]
    fn check_nsec3_coverage_opt_out_clears_nons() {
        let digest = vec![5u8];
        let recs = vec![n3(&[2], &[8], 0x01 /* opt-out */, &BM_NS_SOA)];
        let mut nons = true;
        assert!(check_nsec3_coverage(&digest, 1, &recs, &mut nons, 2));
        assert!(!nons, "opt-out flag must clear nons");
    }

    #[test]
    fn check_nsec3_coverage_no_match_fails() {
        let digest = vec![50u8];
        let recs = vec![n3(&[2], &[8], 0, &BM_NS_SOA)];
        let mut nons = true;
        assert!(!check_nsec3_coverage(&digest, 1, &recs, &mut nons, 2));
    }

    #[test]
    fn prove_non_existence_nsec3_iterations_over_limit_fails() {
        let raw = vec![ParsedNsec3Raw {
            algo: 1, flags: 0, iterations: DEFAULT_NSEC3_ITERS_LIMIT + 1,
            salt: vec![], owner_hash: vec![], next_hashed: vec![], bitmap: vec![],
        }];
        let mut nons = true;
        let mut counter = 100i32;
        let result = prove_non_existence_nsec3(
            &raw, "example.com", 1, 0, &mut nons, &mut counter, DEFAULT_NSEC3_ITERS_LIMIT,
        );
        assert_eq!(result, Err(DNSSEC_FAIL_NSEC3_ITERS));
    }

    #[test]
    fn prove_non_existence_nsec3_no_usable_algo_fails() {
        let raw = vec![ParsedNsec3Raw {
            algo: 99 /* unsupported */, flags: 0, iterations: 0,
            salt: vec![], owner_hash: vec![], next_hashed: vec![], bitmap: vec![],
        }];
        let mut nons = true;
        let mut counter = 100i32;
        let result = prove_non_existence_nsec3(
            &raw, "example.com", 1, 0, &mut nons, &mut counter, DEFAULT_NSEC3_ITERS_LIMIT,
        );
        assert_eq!(result, Err(DNSSEC_FAIL_NONSEC));
    }

    /// Build an NSEC3 chain covering `example.com` end-to-end: one record
    /// whose owner hash is the SHA-1 hash of "example.com" itself (proving
    /// NODATA when the bitmap lacks `qtype`), so `check_nsec3_coverage`
    /// finds a direct hit without needing the closest-encloser walk.
    #[test]
    fn prove_non_existence_nsec3_direct_hit_nodata() {
        use sha1::{Digest, Sha1};
        let salt: Vec<u8> = vec![];
        let digest = hash_name("example.com", &salt, 0, |d| {
            let mut h = Sha1::new();
            h.update(d);
            h.finalize().to_vec()
        }).unwrap();

        let raw = vec![ParsedNsec3Raw {
            algo: 1, flags: 0, iterations: 0, salt: salt.clone(),
            owner_hash: digest.clone(),
            next_hashed: vec![0xFFu8; digest.len()],
            bitmap: BM_NS_SOA.to_vec(),
        }];
        let mut nons = true;
        let mut counter = 100i32;
        let result = prove_non_existence_nsec3(
            &raw, "example.com", 1 /* A */, 0, &mut nons, &mut counter, DEFAULT_NSEC3_ITERS_LIMIT,
        );
        assert!(result.is_ok(), "expected direct-hit NODATA proof to succeed, got {result:?}");
    }

    // ─── prove_non_existence (dispatcher) ───────────────────────────────────

    /// Build an RRSIG(NSEC) RR with the given `labels` field, matching the
    /// owner name given.
    fn rrsig_for_nsec(owner: &str, labels: u8) -> crate::rfc1035::DnsRr {
        let mut r = Vec::new();
        r.extend_from_slice(&T_NSEC.to_be_bytes());
        r.push(8); // algorithm
        r.push(labels);
        r.extend_from_slice(&300u32.to_be_bytes());
        r.extend_from_slice(&u32::MAX.to_be_bytes());
        r.extend_from_slice(&0u32.to_be_bytes());
        r.extend_from_slice(&1234u16.to_be_bytes());
        r.extend_from_slice(&name_to_wire("example.com").unwrap());
        r.push(0x01);
        make_typed_rr(owner, 46, &r)
    }

    #[test]
    fn prove_non_existence_dispatches_to_nsec() {
        let nsec_rr = make_typed_rr("a.com", T_NSEC, &nsec_rdata("c.com", &BM_NS_SOA));
        let sig_rr = rrsig_for_nsec("a.com", 2);
        let authority = vec![nsec_rr, sig_rr];

        let mut nons = true;
        let mut counter = 100i32;
        let result = prove_non_existence(&authority, "b.com", 1, 1, 0, &mut nons, &mut counter, DEFAULT_NSEC3_ITERS_LIMIT);
        assert!(result.is_ok(), "expected NSEC proof to succeed, got {result:?}");
    }

    #[test]
    fn prove_non_existence_mixed_nsec_and_nsec3_fails() {
        let nsec_rr = make_typed_rr("a.com", T_NSEC, &nsec_rdata("c.com", &BM_NS_SOA));
        let sig_rr = rrsig_for_nsec("a.com", 2);

        let mut nsec3_rdata = vec![1u8, 0, 0, 0, 0]; // algo=1, flags=0, iters=0, salt_len=0
        nsec3_rdata.push(4); // hash_len
        nsec3_rdata.extend_from_slice(&[0xFFu8; 4]); // next_hashed
        nsec3_rdata.extend_from_slice(&BM_NS_SOA);
        let nsec3_rr = make_typed_rr("abcdefgh.com", T_NSEC3, &nsec3_rdata);

        let authority = vec![nsec_rr, sig_rr, nsec3_rr];
        let mut nons = true;
        let mut counter = 100i32;
        let result = prove_non_existence(&authority, "b.com", 1, 1, 0, &mut nons, &mut counter, DEFAULT_NSEC3_ITERS_LIMIT);
        assert_eq!(result, Err(DNSSEC_FAIL_NONSEC));
    }

    #[test]
    fn prove_non_existence_no_nsec_records_fails() {
        let authority: Vec<crate::rfc1035::DnsRr> = vec![];
        let mut nons = true;
        let mut counter = 100i32;
        let result = prove_non_existence(&authority, "b.com", 1, 1, 0, &mut nons, &mut counter, DEFAULT_NSEC3_ITERS_LIMIT);
        assert_eq!(result, Err(DNSSEC_FAIL_NONSEC));
    }

    // ─── dnssec_validate_reply ───────────────────────────────────────────────

    /// Sign a single RR with ECDSA P-256, given an explicit `key_tag` (must
    /// match the caller's DNSKEY).
    #[allow(clippy::too_many_arguments)]
    fn sign_single_rr(
        signing_key: &p256::ecdsa::SigningKey,
        owner: &str,
        rrtype: u16,
        class: u16,
        rdata: &[u8],
        signer_name: &str,
        key_tag: u16,
        orig_ttl: u32,
    ) -> (crate::rfc1035::DnsRr, crate::rfc1035::DnsRr) {
        use p256::ecdsa::signature::Signer;
        const ALGO: u8 = 13;
        let labels = count_labels(owner) as u8;
        let rr = make_typed_rr(owner, rrtype, rdata);

        let mut header = Vec::new();
        header.extend_from_slice(&rrtype.to_be_bytes());
        header.push(ALGO);
        header.push(labels);
        header.extend_from_slice(&orig_ttl.to_be_bytes());
        header.extend_from_slice(&u32::MAX.to_be_bytes()); // expiry
        header.extend_from_slice(&0u32.to_be_bytes());     // inception
        header.extend_from_slice(&key_tag.to_be_bytes());

        let wire_signer = name_to_wire(signer_name).unwrap();
        let wire_owner = name_to_wire(owner).unwrap();

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&header);
        signed_data.extend_from_slice(&wire_signer);
        signed_data.extend_from_slice(&wire_owner);
        signed_data.extend_from_slice(&rrtype.to_be_bytes());
        signed_data.extend_from_slice(&class.to_be_bytes());
        signed_data.extend_from_slice(&orig_ttl.to_be_bytes());
        signed_data.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        signed_data.extend_from_slice(rdata);

        let signature: p256::ecdsa::Signature = signing_key.sign(&signed_data);
        let mut rrsig_rdata = header;
        rrsig_rdata.extend_from_slice(&wire_signer);
        rrsig_rdata.extend_from_slice(&signature.to_bytes());

        let sig_rr = make_typed_rr(owner, 46, &rrsig_rdata);
        (rr, sig_rr)
    }

    /// Set up a fully-trusted chain: DS in cache -> self-signed DNSKEY
    /// validated & cached, ready for `dnssec_validate_reply` to trust
    /// RRsets signed by this key for `zone`. Returns the signing key (to
    /// sign additional test RRsets) and its key tag.
    fn setup_trusted_zone(zone: &str, class: u16) -> (p256::ecdsa::SigningKey, u16, DnssecCache) {
        let (dnskey_rr, dnskey_sig_rr, dnskey_rdata, ds, signing_key) = build_dnskey_self_sign_scenario(zone, class);
        let mut cache = DnssecCache::new();
        cache.insert_ds_positive(zone, vec![(ds, class)]);
        let mut counter = 1000i32;
        let status = dnssec_validate_by_ds(&[dnskey_rr, dnskey_sig_rr], zone, class, 500_000, &mut cache, &mut counter);
        assert_eq!(status.code, StatCode::Secure, "test setup: DNSKEY chain must validate");
        let key_tag = compute_key_tag(&dnskey_rdata);
        (signing_key, key_tag, cache)
    }

    #[test]
    fn dnssec_validate_reply_secure_a_record() {
        let zone = "example.com";
        let class = 1u16;
        let (signing_key, key_tag, mut cache) = setup_trusted_zone(zone, class);

        let (a_rr, a_sig_rr) = sign_single_rr(&signing_key, zone, 1 /* A */, class, &[1, 2, 3, 4], zone, key_tag, 300);

        let mut counter = 1000i32;
        let status = dnssec_validate_reply(
            &[a_rr, a_sig_rr], &[], zone, 1, class, 0 /* NOERROR */,
            500_000, &mut cache, &mut counter, false, None, DEFAULT_NSEC3_ITERS_LIMIT,
        );
        assert_eq!(status.code, StatCode::Secure, "expected Secure, got {status:?}");
    }

    #[test]
    fn dnssec_validate_reply_corrupted_signature_is_bogus() {
        let zone = "example.com";
        let class = 1u16;
        let (signing_key, key_tag, mut cache) = setup_trusted_zone(zone, class);

        let (a_rr, mut a_sig_rr) = sign_single_rr(&signing_key, zone, 1, class, &[1, 2, 3, 4], zone, key_tag, 300);
        let last = a_sig_rr.rdata.len() - 1;
        a_sig_rr.rdata[last] ^= 0xFF;

        let mut counter = 1000i32;
        let status = dnssec_validate_reply(
            &[a_rr, a_sig_rr], &[], zone, 1, class, 0,
            500_000, &mut cache, &mut counter, false, None, DEFAULT_NSEC3_ITERS_LIMIT,
        );
        assert_eq!(status.code, StatCode::Bogus, "corrupted signature must not validate, got {status:?}");
    }

    #[test]
    fn dnssec_validate_reply_no_ds_needs_ds() {
        // DNSKEY validated but the A record's zone has no DS cached at all:
        // zone_status must ask for it.
        let zone = "example.com";
        let class = 1u16;
        let (signing_key, key_tag, _cache) = setup_trusted_zone(zone, class);
        let mut empty_cache = DnssecCache::new(); // no DS, no DNSKEY known

        let (a_rr, a_sig_rr) = sign_single_rr(&signing_key, zone, 1, class, &[1, 2, 3, 4], zone, key_tag, 300);

        let mut counter = 1000i32;
        let status = dnssec_validate_reply(
            &[a_rr, a_sig_rr], &[], zone, 1, class, 0,
            500_000, &mut empty_cache, &mut counter, false, None, DEFAULT_NSEC3_ITERS_LIMIT,
        );
        assert_eq!(status.code, StatCode::NeedDs { name: String::new(), class });
    }

    #[test]
    fn dnssec_validate_reply_unsigned_zone_is_insecure() {
        let zone = "example.com";
        let class = 1u16;
        let mut cache = DnssecCache::new();
        cache.insert_ds_neg_insecure(""); // root proves no DS -> whole tree insecure

        let signing_key = { use p256::ecdsa::SigningKey; use rand::rngs::OsRng; SigningKey::random(&mut OsRng) };
        let (a_rr, a_sig_rr) = sign_single_rr(&signing_key, zone, 1, class, &[1, 2, 3, 4], zone, 0xFFFF, 300);

        let mut counter = 1000i32;
        let status = dnssec_validate_reply(
            &[a_rr, a_sig_rr], &[], zone, 1, class, 0,
            500_000, &mut cache, &mut counter, false, None, DEFAULT_NSEC3_ITERS_LIMIT,
        );
        assert_eq!(status.code, StatCode::Insecure, "expected Insecure, got {status:?}");
    }

    #[test]
    fn dnssec_validate_reply_nxdomain_with_valid_nsec_proof() {
        let zone = "example.com";
        let class = 1u16;
        let (signing_key, key_tag, mut cache) = setup_trusted_zone(zone, class);

        // NSEC covering "b.example.com" (which doesn't exist): owner a.example.com -> c.example.com
        let nsec_rdata_bytes = nsec_rdata("c.example.com", &BM_NS_SOA);
        let (nsec_rr, nsec_sig_rr) = sign_single_rr(
            &signing_key, "a.example.com", T_NSEC, class, &nsec_rdata_bytes, zone, key_tag, 300,
        );

        let mut counter = 1000i32;
        let status = dnssec_validate_reply(
            &[], &[nsec_rr, nsec_sig_rr], "b.example.com", 1, class, 3 /* NXDOMAIN */,
            500_000, &mut cache, &mut counter, false, None, DEFAULT_NSEC3_ITERS_LIMIT,
        );
        assert_eq!(status.code, StatCode::Secure, "expected Secure (validated NXDOMAIN), got {status:?}");
    }

    #[test]
    fn dnssec_validate_reply_nxdomain_without_nsec_is_bogus() {
        let zone = "example.com";
        let class = 1u16;
        let (_signing_key, _key_tag, mut cache) = setup_trusted_zone(zone, class);
        // Prove "b.example.com" is known not to be a separate zone cut, so
        // zone_status is Secure there too (isolating the "missing NSEC
        // proof" failure from a "still need more DS" failure).
        cache.insert_ds_neg_not_zone_cut("b.example.com");

        let mut counter = 1000i32;
        let status = dnssec_validate_reply(
            &[], &[], "b.example.com", 1, class, 3 /* NXDOMAIN */,
            500_000, &mut cache, &mut counter, false, None, DEFAULT_NSEC3_ITERS_LIMIT,
        );
        assert_eq!(status.code, StatCode::Bogus, "signed zone with no NSEC proof must be Bogus, got {status:?}");
    }

    #[test]
    fn dnssec_validate_reply_servfail_is_bogus() {
        let mut cache = DnssecCache::new();
        let mut counter = 1000i32;
        let status = dnssec_validate_reply(
            &[], &[], "example.com", 1, 1, 2 /* SERVFAIL */,
            500_000, &mut cache, &mut counter, false, None, DEFAULT_NSEC3_ITERS_LIMIT,
        );
        assert_eq!(status.code, StatCode::Bogus);
        assert_eq!(status.fail & DNSSEC_FAIL_UPSTREAM, DNSSEC_FAIL_UPSTREAM);
    }

    // ─── dnssec_validate_ds ──────────────────────────────────────────────────

    #[test]
    fn dnssec_validate_ds_positive_answer_caches_ds() {
        let parent = "com";
        let class = 1u16;
        let (signing_key, key_tag, mut cache) = setup_trusted_zone(parent, class);

        let mut ds_rdata = Vec::new();
        ds_rdata.extend_from_slice(&9999u16.to_be_bytes()); // key_tag
        ds_rdata.push(13); // algorithm: ECDSA P-256 (supported)
        ds_rdata.push(2);  // digest_type: SHA-256 (supported)
        ds_rdata.extend_from_slice(&[0xAB; 32]);

        let (ds_rr, ds_sig_rr) = sign_single_rr(&signing_key, "example.com", T_DS, class, &ds_rdata, parent, key_tag, 300);

        let mut counter = 1000i32;
        let status = dnssec_validate_ds(
            &[ds_rr, ds_sig_rr], &[], "example.com", class, RCODE_NOERROR,
            500_000, &mut cache, &mut counter, DEFAULT_NSEC3_ITERS_LIMIT,
        );
        assert_eq!(status.code, StatCode::Secure, "expected Secure, got {status:?}");

        // The DS is now cached, so example.com's own zone_status resolves
        // to Secure directly (it's now a trust point on its own).
        let zs = zone_status("example.com", class, &cache);
        assert_eq!(zs.code, StatCode::Secure);
    }

    #[test]
    fn dnssec_validate_ds_negative_at_zone_cut_is_insecure() {
        let parent = "com";
        let class = 1u16;
        let (signing_key, key_tag, mut cache) = setup_trusted_zone(parent, class);

        // Exact-match NSEC at "example.com" with only the NS bit set: a real
        // delegation (zone cut) with no DS record => insecure below here.
        let bm_ns_only = vec![0u8, 1, 0x20];
        let nsec_bytes = nsec_rdata("z.example.com", &bm_ns_only);
        let (nsec_rr, nsec_sig_rr) = sign_single_rr(&signing_key, "example.com", T_NSEC, class, &nsec_bytes, parent, key_tag, 300);

        let mut counter = 1000i32;
        let status = dnssec_validate_ds(
            &[], &[nsec_rr, nsec_sig_rr], "example.com", class, RCODE_NXDOMAIN,
            500_000, &mut cache, &mut counter, DEFAULT_NSEC3_ITERS_LIMIT,
        );
        assert_eq!(status.code, StatCode::Secure, "expected Secure (processing done), got {status:?}");

        let zs = zone_status("example.com", class, &cache);
        assert_eq!(zs.code, StatCode::Insecure, "proven no-DS at a zone cut must make the zone insecure");
    }

    #[test]
    fn dnssec_validate_ds_negative_not_a_zone_cut_is_skipped() {
        let parent = "com";
        let class = 1u16;
        let (signing_key, key_tag, mut cache) = setup_trusted_zone(parent, class);

        // Exact-match NSEC at "example.com" with NO NS bit: not a zone cut
        // at all, so this level should be skipped by zone_status, not
        // treated as proof of insecurity.
        let bm_a_only = vec![0u8, 1, 0x40]; // just A
        let nsec_bytes = nsec_rdata("z.example.com", &bm_a_only);
        let (nsec_rr, nsec_sig_rr) = sign_single_rr(&signing_key, "example.com", T_NSEC, class, &nsec_bytes, parent, key_tag, 300);

        let mut counter = 1000i32;
        let status = dnssec_validate_ds(
            &[], &[nsec_rr, nsec_sig_rr], "example.com", class, RCODE_NXDOMAIN,
            500_000, &mut cache, &mut counter, DEFAULT_NSEC3_ITERS_LIMIT,
        );
        assert_eq!(status.code, StatCode::Secure);

        // Now a DS shows up for a name below example.com: zone_status for
        // it should skip the non-zone-cut "example.com" level and see
        // straight through to "com"'s trust anchor.
        cache.insert_ds_positive("sub.example.com", vec![(sample_ds(), class)]);
        let zs = zone_status("sub.example.com", class, &cache);
        assert_eq!(zs.code, StatCode::Secure);
    }

    #[test]
    fn dnssec_validate_ds_servfail_treated_as_not_a_zone_cut() {
        let mut cache = DnssecCache::new();
        let mut counter = 1000i32;
        let status = dnssec_validate_ds(
            &[], &[], "example.com", 1, RCODE_SERVFAIL,
            500_000, &mut cache, &mut counter, DEFAULT_NSEC3_ITERS_LIMIT,
        );
        assert_eq!(status.code, StatCode::Secure, "processing a SERVFAIL DS answer must still complete, got {status:?}");
    }

    // ─── setup_timestamp ─────────────────────────────────────────────────────

    #[test]
    fn setup_timestamp_not_configured() {
        assert_eq!(setup_timestamp(None, 1_000_000), TimestampSetup::NotConfigured);
    }

    #[test]
    fn setup_timestamp_mtime_in_past_is_clock_sane() {
        assert_eq!(setup_timestamp(Some(100), 200), TimestampSetup::ClockSane);
    }

    #[test]
    fn setup_timestamp_mtime_equal_now_is_clock_sane() {
        assert_eq!(setup_timestamp(Some(200), 200), TimestampSetup::ClockSane);
    }

    #[test]
    fn setup_timestamp_mtime_in_future_is_not_yet_sane() {
        assert_eq!(setup_timestamp(Some(2_000_000_000), 200), TimestampSetup::ClockNotYetSane);
    }

    #[test]
    fn timestamp_clock_now_sane_transitions() {
        assert!(!timestamp_clock_now_sane(1_420_070_400, 1_000_000));
        assert!(timestamp_clock_now_sane(1_420_070_400, 1_420_070_400));
        assert!(timestamp_clock_now_sane(1_420_070_400, 1_500_000_000));
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
