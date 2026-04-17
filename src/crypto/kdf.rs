//! BLAKE3-based sub-key derivation.
//!
//! Derives purpose-specific [`VaultKey`]s from a master key using
//! [BLAKE3's `derive_key`](https://docs.rs/blake3/latest/blake3/fn.derive_key.html)
//! mode, which is designed exactly for this use case.
//!
//! Each sub-key is bound to a **context string** that describes its purpose.
//! Different context strings produce completely independent keys from the same
//! master, enabling a single master key to protect multiple data categories
//! (e.g., database encryption, field-level encryption, metadata encryption)
//! without key reuse.
//!
//! # Context String Requirements
//!
//! Context strings must be:
//! - Valid UTF-8 (BLAKE3 `derive_key` requirement).
//! - Globally unique to the application and purpose. The BLAKE3 spec
//!   recommends the format `"[application] [date] [purpose]"`.
//! - Hardcoded constants, **not** user-controlled input.
//!
//! # Example
//!
//! ```
//! use privacysuite_core_sdk::crypto::{keys, kdf};
//!
//! let master = keys::VaultKey::from_bytes([0x42; 32]);
//!
//! let db_key = kdf::derive_subkey(&master, "myapp 2026 database encryption").unwrap();
//! let field_key = kdf::derive_subkey(&master, "myapp 2026 field encryption").unwrap();
//!
//! // Different contexts produce different keys.
//! assert_ne!(db_key.as_bytes(), field_key.as_bytes());
//! ```

use crate::crypto::keys::{VaultKey, KEY_LEN};
use crate::error::CryptoError;

/// Derives a 32-byte key from input key material using BLAKE3's
/// `derive_key` mode, bound to the given UTF-8 `context`.
///
/// This is the shared primitive used by [`derive_subkey`] and
/// [`crate::crypto::pairing::derive_pairing_key`]. It exists so both
/// call sites route through the same BLAKE3 invariants.
///
/// # Errors
///
/// Returns [`CryptoError::KeyDerivation`] if `context` is empty.
pub(crate) fn blake3_derive(context: &str, ikm: &[u8]) -> Result<VaultKey, CryptoError> {
    if context.is_empty() {
        return Err(CryptoError::KeyDerivation);
    }
    let mut hasher = blake3::Hasher::new_derive_key(context);
    let _ = hasher.update(ikm);
    let hash = hasher.finalize();
    let mut key_bytes = [0u8; KEY_LEN];
    key_bytes.copy_from_slice(&hash.as_bytes()[..KEY_LEN]);
    Ok(VaultKey::from_bytes(key_bytes))
}

/// Derives a purpose-specific [`VaultKey`] from a master key using BLAKE3.
///
/// The `context` string binds the derived key to a specific purpose,
/// ensuring that the same master key produces independent sub-keys for
/// different uses.
///
/// # Errors
///
/// Returns [`CryptoError::KeyDerivation`] if `context` is empty.
pub fn derive_subkey(master: &VaultKey, context: &str) -> Result<VaultKey, CryptoError> {
    blake3_derive(context, master.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::VaultKey;

    fn test_master() -> VaultKey {
        VaultKey::from_bytes([0x42; 32])
    }

    #[test]
    fn derive_subkey_produces_32_bytes() {
        let key = derive_subkey(&test_master(), "test context").unwrap();
        assert_eq!(key.as_bytes().len(), KEY_LEN);
    }

    #[test]
    fn derive_subkey_deterministic() {
        let master = test_master();
        let k1 = derive_subkey(&master, "same context").unwrap();
        let k2 = derive_subkey(&master, "same context").unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn different_contexts_produce_different_keys() {
        let master = test_master();
        let k1 = derive_subkey(&master, "context A").unwrap();
        let k2 = derive_subkey(&master, "context B").unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn different_masters_produce_different_keys() {
        let m1 = VaultKey::from_bytes([0x01; 32]);
        let m2 = VaultKey::from_bytes([0x02; 32]);
        let k1 = derive_subkey(&m1, "same context").unwrap();
        let k2 = derive_subkey(&m2, "same context").unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn empty_context_rejected() {
        assert_eq!(
            derive_subkey(&test_master(), ""),
            Err(CryptoError::KeyDerivation)
        );
    }

    #[test]
    fn derived_key_differs_from_master() {
        let master = test_master();
        let derived = derive_subkey(&master, "any purpose").unwrap();
        assert_ne!(master.as_bytes(), derived.as_bytes());
    }

    #[test]
    fn unicode_context_works() {
        let key = derive_subkey(&test_master(), "boomleft 🔐 encryption v1");
        assert!(key.is_ok());
    }
}
