//! XChaCha20-Poly1305 authenticated encryption with associated data (AEAD).
//!
//! # Ciphertext Format
//!
//! ```text
//! ┌──────────────────┬────────────────────────────┐
//! │  Nonce (24 bytes) │  Ciphertext + Tag (N + 16) │
//! └──────────────────┴────────────────────────────┘
//! ```
//!
//! The 24-byte nonce is prepended to the ciphertext so callers don't need
//! to manage nonces separately. With a 192-bit nonce space, random nonce
//! collision is negligible even across billions of encryptions.
//!
//! # Associated Data (AAD)
//!
//! Both [`encrypt`] and [`decrypt`] accept optional associated data that
//! is authenticated but not encrypted. Use this for context binding (e.g.,
//! database row ID, document type) to prevent ciphertext relocation attacks.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use rand::RngCore;

use crate::crypto::keys::VaultKey;
use crate::error::CryptoError;

/// Nonce size for XChaCha20-Poly1305 (192 bits).
pub const NONCE_LEN: usize = 24;

/// Poly1305 authentication tag size (128 bits).
const TAG_LEN: usize = 16;

/// Minimum ciphertext length: nonce + tag (no plaintext).
const MIN_CIPHERTEXT_LEN: usize = NONCE_LEN + TAG_LEN;

/// Encrypts `plaintext` using XChaCha20-Poly1305.
///
/// Returns `nonce || ciphertext || tag` as a single `Vec<u8>`.
///
/// # Errors
///
/// Returns [`CryptoError::Rng`] if nonce generation fails, or
/// [`CryptoError::Encryption`] if the cipher fails internally.
///
/// # Example
///
/// ```
/// use privacysuite_core_sdk::crypto::keys::VaultKey;
/// use privacysuite_core_sdk::crypto::aead::{encrypt, decrypt};
/// use zeroize::Zeroize;
///
/// let key = VaultKey::from_bytes([0x42; 32]);
/// let ciphertext = encrypt(&key, b"hello world", b"context").unwrap();
/// let mut plaintext = decrypt(&key, &ciphertext, b"context").unwrap();
/// assert_eq!(plaintext, b"hello world");
/// // Zeroize plaintext when done — it contains decrypted secret data.
/// plaintext.zeroize();
/// ```
pub fn encrypt(key: &VaultKey, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|_| CryptoError::Rng)?;

    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_bytes()).map_err(|_| CryptoError::Encryption)?;

    let nonce = chacha20poly1305::XNonce::from_slice(&nonce_bytes);
    let payload = Payload { msg: plaintext, aad };

    let ciphertext_and_tag = cipher.encrypt(nonce, payload).map_err(|_| CryptoError::Encryption)?;

    let mut output = Vec::with_capacity(NONCE_LEN + ciphertext_and_tag.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext_and_tag);

    Ok(output)
}

/// Decrypts a ciphertext produced by [`encrypt`].
///
/// Expects the input format: `nonce (24 bytes) || ciphertext || tag (16 bytes)`.
///
/// # Security
///
/// The returned `Vec<u8>` contains decrypted plaintext. The caller **must**
/// call `.zeroize()` on it when done to scrub the secret from heap memory.
///
/// # Errors
///
/// Returns [`CryptoError::Decryption`] if:
/// - The ciphertext is too short (less than nonce + tag).
/// - The key is wrong.
/// - The ciphertext or AAD has been tampered with.
///
/// All failure modes return the same error to prevent oracle attacks.
pub fn decrypt(key: &VaultKey, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < MIN_CIPHERTEXT_LEN {
        return Err(CryptoError::Decryption);
    }

    let (nonce_bytes, encrypted) = ciphertext.split_at(NONCE_LEN);

    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_bytes()).map_err(|_| CryptoError::Decryption)?;

    let nonce = chacha20poly1305::XNonce::from_slice(nonce_bytes);
    let payload = Payload { msg: encrypted, aad };

    cipher.decrypt(nonce, payload).map_err(|_| CryptoError::Decryption)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::VaultKey;
    use zeroize::Zeroize;

    fn test_key() -> VaultKey {
        VaultKey::from_bytes([0x42; 32])
    }

    #[test]
    fn round_trip() {
        let key = test_key();
        let plaintext = b"the quick brown fox jumps over the lazy dog";
        let aad = b"test context";

        let ciphertext = encrypt(&key, plaintext, aad).unwrap();
        let mut recovered = decrypt(&key, &ciphertext, aad).unwrap();
        assert_eq!(recovered, plaintext);
        recovered.zeroize();
    }

    #[test]
    fn round_trip_empty_plaintext() {
        let key = test_key();
        let ciphertext = encrypt(&key, b"", b"").unwrap();
        let recovered = decrypt(&key, &ciphertext, b"").unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn round_trip_empty_aad() {
        let key = test_key();
        let ciphertext = encrypt(&key, b"data", b"").unwrap();
        let mut recovered = decrypt(&key, &ciphertext, b"").unwrap();
        assert_eq!(recovered, b"data");
        recovered.zeroize();
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = VaultKey::from_bytes([0x01; 32]);
        let key2 = VaultKey::from_bytes([0x02; 32]);

        let ciphertext = encrypt(&key1, b"secret", b"").unwrap();
        assert!(decrypt(&key2, &ciphertext, b"").is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = test_key();
        let mut ciphertext = encrypt(&key, b"secret", b"").unwrap();
        let idx = NONCE_LEN + 1;
        ciphertext[idx] ^= 0xFF;
        assert!(decrypt(&key, &ciphertext, b"").is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let key = test_key();
        let ciphertext = encrypt(&key, b"secret", b"correct aad").unwrap();
        assert!(decrypt(&key, &ciphertext, b"wrong aad").is_err());
    }

    #[test]
    fn truncated_ciphertext_fails() {
        let key = test_key();
        assert!(decrypt(&key, &[0u8; MIN_CIPHERTEXT_LEN - 1], b"").is_err());
    }

    #[test]
    fn ciphertext_format() {
        let key = test_key();
        let plaintext = b"hello";
        let ciphertext = encrypt(&key, plaintext, b"").unwrap();
        assert_eq!(ciphertext.len(), NONCE_LEN + plaintext.len() + TAG_LEN);
    }

    #[test]
    fn each_encryption_produces_unique_ciphertext() {
        let key = test_key();
        let ct1 = encrypt(&key, b"same", b"").unwrap();
        let ct2 = encrypt(&key, b"same", b"").unwrap();
        assert_ne!(ct1, ct2);

        let mut pt1 = decrypt(&key, &ct1, b"").unwrap();
        let mut pt2 = decrypt(&key, &ct2, b"").unwrap();
        assert_eq!(pt1, pt2);
        pt1.zeroize();
        pt2.zeroize();
    }
}
