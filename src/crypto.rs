#![cfg(feature = "dnssec")]

//! DNSSEC cryptographic verification primitives.
//!
//! Supports RSA/SHA-256, RSA/SHA-512, ECDSA P-256, ECDSA P-384, and Ed25519
//! as defined in RFC 4034 / RFC 8080 / IANA DNSSEC algorithm numbers.

use p256::ecdsa::signature::Verifier as P256Verifier;
use p384::ecdsa::signature::Verifier as P384Verifier;
use rsa::{
    pkcs1v15::VerifyingKey as RsaVerifyingKey,
    sha2::{Sha256, Sha512},
    signature::Verifier as _,
    BigUint, RsaPublicKey,
};
use sha1::Sha1;

// ─── Algorithm IDs ────────────────────────────────────────────────────────────

/// DNSSEC algorithm IDs (RFC 4034 / IANA).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecAlgorithm {
    RsaSha1   = 5,
    RsaSha256 = 8,
    RsaSha512 = 10,
    EcdsaP256 = 13,
    EcdsaP384 = 14,
    Ed25519   = 15,
    Ed448     = 16,
}

impl TryFrom<u8> for DnssecAlgorithm {
    type Error = CryptoError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            5  => Ok(Self::RsaSha1),
            8  => Ok(Self::RsaSha256),
            10 => Ok(Self::RsaSha512),
            13 => Ok(Self::EcdsaP256),
            14 => Ok(Self::EcdsaP384),
            15 => Ok(Self::Ed25519),
            16 => Ok(Self::Ed448),
            _  => Err(CryptoError::UnsupportedAlgorithm(v)),
        }
    }
}

// ─── Public-key enum ──────────────────────────────────────────────────────────

/// A parsed DNSSEC public key ready for signature verification.
pub enum DnssecPublicKey {
    RsaSha256(RsaPublicKey),
    RsaSha512(RsaPublicKey),
    EcdsaP256(p256::ecdsa::VerifyingKey),
    EcdsaP384(p384::ecdsa::VerifyingKey),
    Ed25519(ed25519_dalek::VerifyingKey),
}

// ─── Error type ───────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(u8),
    /// `verify_sig` was asked to check a signature against a `DnssecPublicKey`
    /// whose variant doesn't match `requested` — e.g. an `EcdsaP256` key
    /// checked against `DnssecAlgorithm::Ed25519`. Distinct from
    /// `UnsupportedAlgorithm`: the algorithm itself is one this crate
    /// implements, the caller just paired it with the wrong key. This is an
    /// internal-caller bug (mismatched key/algorithm pairing), never a
    /// property of the wire data alone.
    #[error("algorithm {requested:?} does not match the parsed key's algorithm")]
    KeyAlgorithmMismatch { requested: DnssecAlgorithm },
    #[error("invalid key data")]
    InvalidKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("signature verification failed")]
    VerificationFailed,
}

// ─── RSA key parsing helpers ──────────────────────────────────────────────────

/// Parse an RSA public key from DNSKEY RDATA (RFC 3110).
///
/// Wire format:
///   - 1 byte:  exponent length (0 means next 2 bytes are the length)
///   - n bytes: public exponent
///   - rest:    modulus
fn parse_rsa_key(key_data: &[u8]) -> Result<RsaPublicKey, CryptoError> {
    if key_data.is_empty() {
        return Err(CryptoError::InvalidKey);
    }

    let (exp_len, rest) = if key_data[0] == 0 {
        if key_data.len() < 3 {
            return Err(CryptoError::InvalidKey);
        }
        let len = u16::from_be_bytes([key_data[1], key_data[2]]) as usize;
        (len, &key_data[3..])
    } else {
        (key_data[0] as usize, &key_data[1..])
    };

    if rest.len() < exp_len {
        return Err(CryptoError::InvalidKey);
    }

    let e_bytes = &rest[..exp_len];
    let n_bytes = &rest[exp_len..];

    if n_bytes.is_empty() {
        return Err(CryptoError::InvalidKey);
    }

    let e = BigUint::from_bytes_be(e_bytes);
    let n = BigUint::from_bytes_be(n_bytes);

    RsaPublicKey::new(n, e).map_err(|_| CryptoError::InvalidKey)
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// Parse a DNSKEY RR's public-key material from its RDATA wire format.
pub fn parse_dnskey(algorithm: u8, key_data: &[u8]) -> Result<DnssecPublicKey, CryptoError> {
    match DnssecAlgorithm::try_from(algorithm)? {
        DnssecAlgorithm::RsaSha1 => {
            // RSA/SHA-1 (algorithm 5) shares the same RFC 3110 key wire
            // format as RSA/SHA-256, so it reuses the RsaSha256 storage
            // variant. verify_sig dispatches on the algorithm ID (not the
            // key variant) to pick SHA-1 vs SHA-256 as the signature hash.
            let key = parse_rsa_key(key_data)?;
            Ok(DnssecPublicKey::RsaSha256(key))
        }
        DnssecAlgorithm::RsaSha256 => {
            let key = parse_rsa_key(key_data)?;
            Ok(DnssecPublicKey::RsaSha256(key))
        }
        DnssecAlgorithm::RsaSha512 => {
            let key = parse_rsa_key(key_data)?;
            Ok(DnssecPublicKey::RsaSha512(key))
        }
        DnssecAlgorithm::EcdsaP256 => {
            // Uncompressed point: 64 bytes (no 0x04 prefix in DNSKEY wire format)
            if key_data.len() != 64 {
                return Err(CryptoError::InvalidKey);
            }
            let mut uncompressed = Vec::with_capacity(65);
            uncompressed.push(0x04);
            uncompressed.extend_from_slice(key_data);
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&uncompressed)
                .map_err(|_| CryptoError::InvalidKey)?;
            Ok(DnssecPublicKey::EcdsaP256(key))
        }
        DnssecAlgorithm::EcdsaP384 => {
            // Uncompressed point: 96 bytes
            if key_data.len() != 96 {
                return Err(CryptoError::InvalidKey);
            }
            let mut uncompressed = Vec::with_capacity(97);
            uncompressed.push(0x04);
            uncompressed.extend_from_slice(key_data);
            let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(&uncompressed)
                .map_err(|_| CryptoError::InvalidKey)?;
            Ok(DnssecPublicKey::EcdsaP384(key))
        }
        DnssecAlgorithm::Ed25519 => {
            let bytes: [u8; 32] = key_data
                .try_into()
                .map_err(|_| CryptoError::InvalidKey)?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
                .map_err(|_| CryptoError::InvalidKey)?;
            Ok(DnssecPublicKey::Ed25519(key))
        }
        DnssecAlgorithm::Ed448 => Err(CryptoError::UnsupportedAlgorithm(algorithm)),
    }
}

/// Verify a DNSSEC signature.
///
/// - `data`      – wire-format signed data (the concatenated RRset)
/// - `sig`       – raw signature bytes from the RRSIG RDATA
/// - `key`       – previously parsed public key
/// - `algorithm` – DNSSEC algorithm ID (must match `key` variant)
pub fn verify_sig(
    data: &[u8],
    sig: &[u8],
    key: &DnssecPublicKey,
    algorithm: DnssecAlgorithm,
) -> Result<bool, CryptoError> {
    match (key, algorithm) {
        (DnssecPublicKey::RsaSha256(rsa_key), DnssecAlgorithm::RsaSha256) => {
            let vk: RsaVerifyingKey<Sha256> = RsaVerifyingKey::new(rsa_key.clone());
            vk.verify(data, &rsa::pkcs1v15::Signature::try_from(sig).map_err(|_| CryptoError::InvalidSignature)?)
                .map(|_| true)
                .map_err(|_| CryptoError::VerificationFailed)
        }
        (DnssecPublicKey::RsaSha256(rsa_key), DnssecAlgorithm::RsaSha1) => {
            // Algorithm 5 (RSA/SHA-1) hashes with SHA-1, per crypto.c:192-200 —
            // it shares the same wire key format as RsaSha256 but not the hash.
            let vk: RsaVerifyingKey<Sha1> = RsaVerifyingKey::new(rsa_key.clone());
            vk.verify(data, &rsa::pkcs1v15::Signature::try_from(sig).map_err(|_| CryptoError::InvalidSignature)?)
                .map(|_| true)
                .map_err(|_| CryptoError::VerificationFailed)
        }
        (DnssecPublicKey::RsaSha512(rsa_key), DnssecAlgorithm::RsaSha512) => {
            let vk: RsaVerifyingKey<Sha512> = RsaVerifyingKey::new(rsa_key.clone());
            vk.verify(data, &rsa::pkcs1v15::Signature::try_from(sig).map_err(|_| CryptoError::InvalidSignature)?)
                .map(|_| true)
                .map_err(|_| CryptoError::VerificationFailed)
        }
        (DnssecPublicKey::EcdsaP256(vk), DnssecAlgorithm::EcdsaP256) => {
            // DNSSEC ECDSA P-256 sigs are fixed-size r||s (64 bytes, RFC 6605 §4).
            if sig.len() != 64 {
                return Err(CryptoError::InvalidSignature);
            }
            let p256_sig = p256::ecdsa::Signature::try_from(sig)
                .map_err(|_| CryptoError::InvalidSignature)?;
            P256Verifier::verify(vk, data, &p256_sig)
                .map(|_| true)
                .map_err(|_| CryptoError::VerificationFailed)
        }
        (DnssecPublicKey::EcdsaP384(vk), DnssecAlgorithm::EcdsaP384) => {
            // DNSSEC ECDSA P-384 sigs are fixed-size r||s (96 bytes, RFC 6605 §4).
            if sig.len() != 96 {
                return Err(CryptoError::InvalidSignature);
            }
            let p384_sig = p384::ecdsa::Signature::try_from(sig)
                .map_err(|_| CryptoError::InvalidSignature)?;
            P384Verifier::verify(vk, data, &p384_sig)
                .map(|_| true)
                .map_err(|_| CryptoError::VerificationFailed)
        }
        (DnssecPublicKey::Ed25519(vk), DnssecAlgorithm::Ed25519) => {
            let sig_bytes: [u8; 64] = sig
                .try_into()
                .map_err(|_| CryptoError::InvalidSignature)?;
            let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
            use ed25519_dalek::Verifier as _;
            vk.verify(data, &signature)
                .map(|_| true)
                .map_err(|_| CryptoError::VerificationFailed)
        }
        // `Ed448` has no `DnssecPublicKey` variant at all (`parse_dnskey`
        // rejects it before one could ever be constructed), so it alone is
        // genuinely unsupported here; every other combination reaching this
        // arm is a real key, just paired with the wrong algorithm.
        (_, DnssecAlgorithm::Ed448) => Err(CryptoError::UnsupportedAlgorithm(algorithm as u8)),
        _ => Err(CryptoError::KeyAlgorithmMismatch { requested: algorithm }),
    }
}



// ─── Digest/Algorithm name lookups (ported from crypto.c:422-472) ────────────

/// Return the hash algorithm name for a DS digest type.
///
/// Per IANA ds-rr-types registry.
/// Port of `ds_digest_name()` from crypto.c:422-434.
pub fn ds_digest_name(digest: u8) -> Option<&'static str> {
    match digest {
        1 => Some("sha1"),
        2 => Some("sha256"),
        4 => Some("sha384"),
        _ => None,
    }
}

/// Return the hash algorithm name for a DNSSEC signing algorithm.
///
/// Per IANA dns-sec-alg-numbers registry.
/// Port of `algo_digest_name()` from crypto.c:437-462.
pub fn algo_digest_name(algo: u8) -> Option<&'static str> {
    match algo {
        1 => None,              // RSA/MD5 — Must Not Implement (RFC 6944)
        2 => None,              // Diffie-Hellman
        3 => None,              // DSA/SHA1 — Must Not Implement (RFC 8624)
        5 => Some("sha1"),      // RSA/SHA1
        6 => None,              // DSA-NSEC3-SHA1 — Must Not Implement (RFC 8624)
        7 => Some("sha1"),      // RSASHA1-NSEC3-SHA1
        8 => Some("sha256"),    // RSA/SHA-256
        10 => Some("sha512"),   // RSA/SHA-512
        13 => Some("sha256"),   // ECDSAP256SHA256
        14 => Some("sha384"),   // ECDSAP384SHA384
        15 => Some("null_hash"), // ED25519
        // ED448 is unimplemented here (parse_dnskey/verify_sig both reject
        // algorithm 16), so it must not be advertised as supported — unlike
        // upstream crypto.c:456, which lists it under MIN_VERSION(3,6).
        16 => None,
        // GOST R 34.10-2001 (algorithm 12, upstream crypto.c:279-317, also
        // gated MIN_VERSION(3,6)) is unimplemented and falls through to `_`.
        _ => None,
    }
}

/// Return the hash algorithm name for an NSEC3 digest type.
///
/// Per IANA dnssec-nsec3-parameters registry.
/// Port of `nsec3_digest_name()` from crypto.c:465-472.
pub fn nsec3_digest_name(digest: u8) -> Option<&'static str> {
    match digest {
        1 => Some("sha1"),
        _ => None,
    }
}

/// Check if a DNSSEC algorithm is supported for signature verification.
pub fn algo_supported(algo: u8) -> bool {
    algo_digest_name(algo).is_some()
}

/// Check if a DS digest type is supported.
pub fn ds_digest_supported(digest: u8) -> bool {
    ds_digest_name(digest).is_some()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_numeric_values() {
        assert_eq!(DnssecAlgorithm::RsaSha1   as u8, 5);
        assert_eq!(DnssecAlgorithm::RsaSha256 as u8, 8);
        assert_eq!(DnssecAlgorithm::RsaSha512 as u8, 10);
        assert_eq!(DnssecAlgorithm::EcdsaP256 as u8, 13);
        assert_eq!(DnssecAlgorithm::EcdsaP384 as u8, 14);
        assert_eq!(DnssecAlgorithm::Ed25519   as u8, 15);
        assert_eq!(DnssecAlgorithm::Ed448     as u8, 16);
    }

    #[test]
    fn parse_dnskey_unknown_algorithm_returns_err() {
        let result = parse_dnskey(99, &[0u8; 32]);
        assert!(matches!(result, Err(CryptoError::UnsupportedAlgorithm(99))));
    }

    #[test]
    fn ed25519_good_signature_verifies() {
        use ed25519_dalek::{Signer, SigningKey};
        use rand::rngs::OsRng;

        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let data = b"example DNSSEC RRset data";
        let signature = signing_key.sign(data);

        // Build a DnssecPublicKey directly from the verifying key.
        let dnskey = DnssecPublicKey::Ed25519(verifying_key);

        let result = verify_sig(data, signature.to_bytes().as_ref(), &dnskey, DnssecAlgorithm::Ed25519);
        assert!(matches!(result, Ok(true)));
    }

    #[test]
    fn ed25519_tampered_signature_fails() {
        use ed25519_dalek::{Signer, SigningKey};
        use rand::rngs::OsRng;

        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let data = b"example DNSSEC RRset data";
        let signature = signing_key.sign(data);

        // Flip one byte of the signature.
        let mut bad_sig = signature.to_bytes();
        bad_sig[0] ^= 0xff;

        let dnskey = DnssecPublicKey::Ed25519(verifying_key);

        let result = verify_sig(data, &bad_sig, &dnskey, DnssecAlgorithm::Ed25519);
        assert!(matches!(result, Err(CryptoError::VerificationFailed)));
    }

    #[test]
    fn ed25519_parse_and_verify_roundtrip() {
        use ed25519_dalek::{Signer, SigningKey};
        use rand::rngs::OsRng;

        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        let key_bytes = verifying_key.to_bytes();

        // Parse through the public API.
        let dnskey = parse_dnskey(15, &key_bytes).expect("parse_dnskey failed");

        let data = b"round-trip test data";
        let signature = signing_key.sign(data);

        let result = verify_sig(data, signature.to_bytes().as_ref(), &dnskey, DnssecAlgorithm::Ed25519);
        assert!(matches!(result, Ok(true)));
    }

    // ── Algorithm TryFrom tests ──

    #[test]
    fn algorithm_try_from_valid() {
        assert_eq!(DnssecAlgorithm::try_from(5).unwrap(), DnssecAlgorithm::RsaSha1);
        assert_eq!(DnssecAlgorithm::try_from(8).unwrap(), DnssecAlgorithm::RsaSha256);
        assert_eq!(DnssecAlgorithm::try_from(10).unwrap(), DnssecAlgorithm::RsaSha512);
        assert_eq!(DnssecAlgorithm::try_from(13).unwrap(), DnssecAlgorithm::EcdsaP256);
        assert_eq!(DnssecAlgorithm::try_from(14).unwrap(), DnssecAlgorithm::EcdsaP384);
        assert_eq!(DnssecAlgorithm::try_from(15).unwrap(), DnssecAlgorithm::Ed25519);
        assert_eq!(DnssecAlgorithm::try_from(16).unwrap(), DnssecAlgorithm::Ed448);
    }

    #[test]
    fn algorithm_try_from_invalid() {
        for bad in [0u8, 1, 2, 3, 4, 6, 7, 9, 11, 12, 17, 255] {
            assert!(matches!(
                DnssecAlgorithm::try_from(bad),
                Err(CryptoError::UnsupportedAlgorithm(v)) if v == bad
            ));
        }
    }

    // ── RSA key parsing tests ──

    #[test]
    fn parse_rsa_key_empty_data() {
        let result = parse_dnskey(8, &[]);
        assert!(matches!(result, Err(CryptoError::InvalidKey)));
    }

    #[test]
    fn parse_rsa_key_short_exponent_length_zero() {
        // First byte 0 means next 2 bytes are exponent length, but only 1 byte follows
        let result = parse_dnskey(8, &[0, 0]);
        assert!(matches!(result, Err(CryptoError::InvalidKey)));
    }

    #[test]
    fn parse_rsa_key_exponent_longer_than_data() {
        // exp_len=10 but only 2 bytes of data after length
        let result = parse_dnskey(8, &[10, 0x01, 0x02]);
        assert!(matches!(result, Err(CryptoError::InvalidKey)));
    }

    #[test]
    fn parse_rsa_key_no_modulus() {
        // exp_len=3, exponent=3 bytes, no modulus
        let result = parse_dnskey(8, &[3, 0x01, 0x00, 0x01]);
        assert!(matches!(result, Err(CryptoError::InvalidKey)));
    }

    /// Build a minimal DNSKEY wire-format RSA key: [exp_len][exponent][modulus]
    /// Uses e=65537 and a 256-byte (2048-bit) random modulus.
    fn make_rsa_wire_key() -> Vec<u8> {
        let e_bytes: [u8; 3] = [0x01, 0x00, 0x01]; // 65537
        // 256 bytes of 0xff is not a valid RSA modulus mathematically,
        // but we just need the parser to accept the structure.
        // Use a large odd number for the modulus.
        let mut n_bytes = vec![0xffu8; 256];
        n_bytes[0] = 0x00; // leading zero won't matter, BigUint strips it
        n_bytes[1] = 0xc1; // make it look like a real modulus

        let mut wire = Vec::new();
        wire.push(e_bytes.len() as u8);
        wire.extend_from_slice(&e_bytes);
        wire.extend_from_slice(&n_bytes);
        wire
    }

    #[test]
    fn parse_rsa_key_valid() {
        let wire = make_rsa_wire_key();
        let result = parse_dnskey(8, &wire);
        assert!(result.is_ok());
        match result.unwrap() {
            DnssecPublicKey::RsaSha256(_) => {} // expected
            _ => panic!("expected RsaSha256 variant"),
        }
    }

    #[test]
    fn parse_rsa_sha512_returns_correct_variant() {
        let wire = make_rsa_wire_key();
        let result = parse_dnskey(10, &wire);
        assert!(result.is_ok());
        match result.unwrap() {
            DnssecPublicKey::RsaSha512(_) => {} // expected
            _ => panic!("expected RsaSha512 variant"),
        }
    }

    // ── ECDSA key parsing tests ──

    #[test]
    fn parse_ecdsa_p256_wrong_size() {
        let result = parse_dnskey(13, &[0u8; 63]); // should be 64
        assert!(matches!(result, Err(CryptoError::InvalidKey)));
        let result = parse_dnskey(13, &[0u8; 65]); // should be 64
        assert!(matches!(result, Err(CryptoError::InvalidKey)));
    }

    #[test]
    fn parse_ecdsa_p384_wrong_size() {
        let result = parse_dnskey(14, &[0u8; 95]); // should be 96
        assert!(matches!(result, Err(CryptoError::InvalidKey)));
        let result = parse_dnskey(14, &[0u8; 97]); // should be 96
        assert!(matches!(result, Err(CryptoError::InvalidKey)));
    }

    #[test]
    fn parse_ed25519_wrong_size() {
        let result = parse_dnskey(15, &[0u8; 31]); // should be 32
        assert!(matches!(result, Err(CryptoError::InvalidKey)));
        let result = parse_dnskey(15, &[0u8; 33]); // should be 32
        assert!(matches!(result, Err(CryptoError::InvalidKey)));
    }

    #[test]
    fn parse_ed448_returns_unsupported() {
        let result = parse_dnskey(16, &[0u8; 57]);
        assert!(matches!(result, Err(CryptoError::UnsupportedAlgorithm(16))));
    }

    // ── verify_sig algorithm mismatch ──

    #[test]
    fn verify_sig_algorithm_key_mismatch() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let vk = signing_key.verifying_key();
        let dnskey = DnssecPublicKey::Ed25519(vk);

        // Try to verify with wrong algorithm
        let result = verify_sig(b"data", &[0u8; 64], &dnskey, DnssecAlgorithm::RsaSha256);
        assert!(matches!(
            result,
            Err(CryptoError::KeyAlgorithmMismatch { requested: DnssecAlgorithm::RsaSha256 })
        ));
    }

    #[test]
    fn verify_sig_ed448_algorithm_is_unsupported_not_a_mismatch() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        // Ed448 has no DnssecPublicKey variant at all, so it must report
        // UnsupportedAlgorithm even when paired with an unrelated real key —
        // never KeyAlgorithmMismatch, which implies the algorithm itself is
        // one this crate implements.
        let signing_key = SigningKey::generate(&mut OsRng);
        let dnskey = DnssecPublicKey::Ed25519(signing_key.verifying_key());
        let result = verify_sig(b"data", &[0u8; 64], &dnskey, DnssecAlgorithm::Ed448);
        assert!(matches!(result, Err(CryptoError::UnsupportedAlgorithm(16))));
    }

    #[test]
    fn verify_sig_ed25519_wrong_sig_size() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let vk = signing_key.verifying_key();
        let dnskey = DnssecPublicKey::Ed25519(vk);

        let result = verify_sig(b"data", &[0u8; 32], &dnskey, DnssecAlgorithm::Ed25519);
        assert!(matches!(result, Err(CryptoError::InvalidSignature)));
    }

    // ── RSA SHA-1 shares key format with SHA-256 ──

    #[test]
    fn parse_rsa_sha1_uses_sha256_variant() {
        let wire = make_rsa_wire_key();
        let result = parse_dnskey(5, &wire);
        assert!(result.is_ok());
        match result.unwrap() {
            DnssecPublicKey::RsaSha256(_) => {} // RSA/SHA-1 stored as RsaSha256
            _ => panic!("expected RsaSha256 variant for RSA/SHA-1"),
        }
    }

    // ── RSA/SHA-1 (algorithm 5) must hash with SHA-1, not SHA-256 ──

    fn make_rsa_signing_key() -> rsa::RsaPrivateKey {
        use rand::rngs::OsRng;
        rsa::RsaPrivateKey::new(&mut OsRng, 2048).expect("failed to generate RSA key")
    }

    fn rsa_dnskey_wire(public: &RsaPublicKey) -> Vec<u8> {
        use rsa::traits::PublicKeyParts;
        let e_bytes = public.e().to_bytes_be();
        let n_bytes = public.n().to_bytes_be();
        let mut wire = Vec::new();
        if e_bytes.len() < 256 {
            wire.push(e_bytes.len() as u8);
        } else {
            wire.push(0);
            wire.extend_from_slice(&(e_bytes.len() as u16).to_be_bytes());
        }
        wire.extend_from_slice(&e_bytes);
        wire.extend_from_slice(&n_bytes);
        wire
    }

    #[test]
    fn rsa_sha1_good_signature_verifies() {
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::{RandomizedSigner, SignatureEncoding};

        let private = make_rsa_signing_key();
        let public = RsaPublicKey::from(&private);
        let signing_key: SigningKey<sha1::Sha1> = SigningKey::new(private);

        let data = b"RSA/SHA-1 DNSSEC test data";
        let signature = signing_key.sign_with_rng(&mut rand::rngs::OsRng, data);

        let dnskey = DnssecPublicKey::RsaSha256(public);
        let result = verify_sig(
            data,
            signature.to_bytes().as_ref(),
            &dnskey,
            DnssecAlgorithm::RsaSha1,
        );
        assert!(matches!(result, Ok(true)), "expected Ok(true), got {result:?}");
    }

    #[test]
    fn rsa_sha1_signature_does_not_verify_as_sha256() {
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::{RandomizedSigner, SignatureEncoding};

        let private = make_rsa_signing_key();
        let public = RsaPublicKey::from(&private);
        let signing_key: SigningKey<sha1::Sha1> = SigningKey::new(private);

        let data = b"RSA/SHA-1 DNSSEC test data";
        let signature = signing_key.sign_with_rng(&mut rand::rngs::OsRng, data);

        let dnskey = DnssecPublicKey::RsaSha256(public);
        let result = verify_sig(
            data,
            signature.to_bytes().as_ref(),
            &dnskey,
            DnssecAlgorithm::RsaSha256,
        );
        assert!(
            matches!(result, Err(CryptoError::VerificationFailed)),
            "SHA-1 signature must not verify under the SHA-256 arm, got {result:?}"
        );
    }

    #[test]
    fn parse_dnskey_and_verify_rsa_sha1_roundtrip() {
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::{RandomizedSigner, SignatureEncoding};

        let private = make_rsa_signing_key();
        let public = RsaPublicKey::from(&private);
        let wire = rsa_dnskey_wire(&public);
        let signing_key: SigningKey<sha1::Sha1> = SigningKey::new(private);

        let dnskey = parse_dnskey(5, &wire).expect("parse_dnskey(5, ..) failed");

        let data = b"round-trip RSA/SHA-1 data";
        let signature = signing_key.sign_with_rng(&mut rand::rngs::OsRng, data);

        let result = verify_sig(
            data,
            signature.to_bytes().as_ref(),
            &dnskey,
            DnssecAlgorithm::RsaSha1,
        );
        assert!(matches!(result, Ok(true)), "expected Ok(true), got {result:?}");
    }

    // ── ds_digest_name ───────────────────────────────────────────────────────

    #[test]
    fn ds_digest_name_sha1() {
        assert_eq!(ds_digest_name(1), Some("sha1"));
    }

    #[test]
    fn ds_digest_name_sha256() {
        assert_eq!(ds_digest_name(2), Some("sha256"));
    }

    #[test]
    fn ds_digest_name_sha384() {
        assert_eq!(ds_digest_name(4), Some("sha384"));
    }

    #[test]
    fn ds_digest_name_unknown() {
        assert_eq!(ds_digest_name(99), None);
    }

    // ── algo_digest_name ─────────────────────────────────────────────────────

    #[test]
    fn algo_digest_name_rsa_sha256() {
        assert_eq!(algo_digest_name(8), Some("sha256"));
    }

    #[test]
    fn algo_digest_name_rsa_sha512() {
        assert_eq!(algo_digest_name(10), Some("sha512"));
    }

    #[test]
    fn algo_digest_name_ecdsa_p256() {
        assert_eq!(algo_digest_name(13), Some("sha256"));
    }

    #[test]
    fn algo_digest_name_ed25519() {
        assert_eq!(algo_digest_name(15), Some("null_hash"));
    }

    #[test]
    fn algo_digest_name_ed448_matches_parse_dnskey_rejection() {
        // parse_dnskey(16, ..) rejects Ed448 as unsupported, so algo_digest_name
        // must not advertise it as supported either.
        assert_eq!(algo_digest_name(16), None);
    }

    #[test]
    fn algo_digest_name_rsa_md5_not_impl() {
        assert_eq!(algo_digest_name(1), None);
    }

    #[test]
    fn algo_digest_name_dsa_not_impl() {
        assert_eq!(algo_digest_name(3), None);
    }

    // ── nsec3_digest_name ────────────────────────────────────────────────────

    #[test]
    fn nsec3_digest_name_sha1() {
        assert_eq!(nsec3_digest_name(1), Some("sha1"));
    }

    #[test]
    fn nsec3_digest_name_unknown() {
        assert_eq!(nsec3_digest_name(0), None);
        assert_eq!(nsec3_digest_name(2), None);
    }

    // ── algo_supported / ds_digest_supported ─────────────────────────────────

    #[test]
    fn algo_supported_checks() {
        assert!(algo_supported(8));  // RSA/SHA-256
        assert!(algo_supported(15)); // ED25519
        assert!(!algo_supported(1)); // RSA/MD5 (not implemented)
        assert!(!algo_supported(99));
    }

    #[test]
    fn algo_supported_ed448_matches_parse_dnskey() {
        // parse_dnskey(16, ..) fails closed, so algo_supported must agree.
        assert!(!algo_supported(16));
    }

    #[test]
    fn ds_digest_supported_checks() {
        assert!(ds_digest_supported(1));  // SHA-1
        assert!(ds_digest_supported(2));  // SHA-256
        assert!(!ds_digest_supported(0));
        assert!(!ds_digest_supported(99));
    }
}
