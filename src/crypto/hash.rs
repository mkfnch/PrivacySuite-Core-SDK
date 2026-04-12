//! BLAKE3 content hashing.
//!
//! Exposes BLAKE3 for content integrity verification and deduplication.
//! BLAKE3 is already an always-on dependency of this crate (used internally
//! for key derivation in [`super::kdf`] and [`super::pairing`]).
//!
//! # Example
//!
//! ```
//! use privacysuite_core_sdk::crypto::hash;
//!
//! let data = b"important document contents";
//! let digest = hash::blake3(data);
//!
//! // Later, verify integrity.
//! assert!(hash::blake3_verify(data, &digest));
//! assert!(!hash::blake3_verify(b"tampered", &digest));
//! ```

/// Length of a BLAKE3 digest in bytes (256 bits).
pub const BLAKE3_HASH_LEN: usize = 32;

/// Computes a BLAKE3 hash of `data`, returning a 32-byte digest.
#[must_use]
pub fn blake3(data: &[u8]) -> [u8; BLAKE3_HASH_LEN] {
    *blake3::hash(data).as_bytes()
}

/// Returns `true` if `data` hashes to the given BLAKE3 `digest`.
#[must_use]
pub fn blake3_verify(data: &[u8], expected: &[u8; BLAKE3_HASH_LEN]) -> bool {
    use subtle::ConstantTimeEq;
    let actual = blake3::hash(data);
    actual.as_bytes().ct_eq(expected).into()
}

/// Computes a keyed BLAKE3 MAC of `data`, returning a 32-byte digest.
///
/// The key must be exactly 32 bytes. This is suitable for blind indexes
/// and deterministic MACs where the key is secret.
#[must_use]
pub fn blake3_keyed(key: &[u8; BLAKE3_HASH_LEN], data: &[u8]) -> [u8; BLAKE3_HASH_LEN] {
    *blake3::keyed_hash(key, data).as_bytes()
}

/// Returns `true` if the keyed BLAKE3 MAC of `data` matches `expected`.
#[must_use]
pub fn blake3_keyed_verify(
    key: &[u8; BLAKE3_HASH_LEN],
    data: &[u8],
    expected: &[u8; BLAKE3_HASH_LEN],
) -> bool {
    use subtle::ConstantTimeEq;
    let actual = blake3::keyed_hash(key, data);
    actual.as_bytes().ct_eq(expected).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_produces_32_bytes() {
        let digest = blake3(b"hello");
        assert_eq!(digest.len(), BLAKE3_HASH_LEN);
    }

    #[test]
    fn hash_is_deterministic() {
        let d1 = blake3(b"same input");
        let d2 = blake3(b"same input");
        assert_eq!(d1, d2);
    }

    #[test]
    fn different_inputs_produce_different_hashes() {
        let d1 = blake3(b"input A");
        let d2 = blake3(b"input B");
        assert_ne!(d1, d2);
    }

    #[test]
    fn verify_correct_data() {
        let data = b"verify me";
        let digest = blake3(data);
        assert!(blake3_verify(data, &digest));
    }

    #[test]
    fn verify_rejects_wrong_data() {
        let digest = blake3(b"original");
        assert!(!blake3_verify(b"tampered", &digest));
    }

    #[test]
    fn verify_rejects_wrong_hash() {
        let data = b"some data";
        let wrong_hash = [0xFFu8; BLAKE3_HASH_LEN];
        assert!(!blake3_verify(data, &wrong_hash));
    }

    #[test]
    fn empty_input_hashes() {
        let digest = blake3(b"");
        assert_eq!(digest.len(), BLAKE3_HASH_LEN);
        assert!(blake3_verify(b"", &digest));
    }

    #[test]
    fn large_input_hashes() {
        let data = vec![0xABu8; 1_000_000];
        let digest = blake3(&data);
        assert!(blake3_verify(&data, &digest));
    }

    #[test]
    fn keyed_hash_produces_32_bytes() {
        let key = [0x42u8; BLAKE3_HASH_LEN];
        let digest = blake3_keyed(&key, b"hello");
        assert_eq!(digest.len(), BLAKE3_HASH_LEN);
    }

    #[test]
    fn keyed_hash_differs_from_unkeyed() {
        let key = [0x42u8; BLAKE3_HASH_LEN];
        let keyed = blake3_keyed(&key, b"hello");
        let unkeyed = blake3(b"hello");
        assert_ne!(keyed, unkeyed);
    }

    #[test]
    fn different_keys_produce_different_macs() {
        let k1 = [0x01u8; BLAKE3_HASH_LEN];
        let k2 = [0x02u8; BLAKE3_HASH_LEN];
        assert_ne!(blake3_keyed(&k1, b"same"), blake3_keyed(&k2, b"same"));
    }

    #[test]
    fn keyed_verify_correct() {
        let key = [0x42u8; BLAKE3_HASH_LEN];
        let mac = blake3_keyed(&key, b"verify me");
        assert!(blake3_keyed_verify(&key, b"verify me", &mac));
    }

    #[test]
    fn keyed_verify_rejects_wrong_data() {
        let key = [0x42u8; BLAKE3_HASH_LEN];
        let mac = blake3_keyed(&key, b"original");
        assert!(!blake3_keyed_verify(&key, b"tampered", &mac));
    }
}
