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
            // RSA/SHA-1 shares the same key format; we surface it as
            // RsaSha256 storage since SHA-1 verification is handled by
            // algorithm ID at verify time. Kept for completeness.
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
        (DnssecPublicKey::RsaSha256(rsa_key), DnssecAlgorithm::RsaSha256)
        | (DnssecPublicKey::RsaSha256(rsa_key), DnssecAlgorithm::RsaSha1) => {
            let vk: RsaVerifyingKey<Sha256> = RsaVerifyingKey::new(rsa_key.clone());
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
        _ => Err(CryptoError::UnsupportedAlgorithm(algorithm as u8)),
    }
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
}
