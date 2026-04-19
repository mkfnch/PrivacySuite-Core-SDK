//! Deterministic blind index via HMAC-BLAKE3 for FTS over encrypted columns.
//!
//! # Problem
//!
//! An encrypted SQLCipher database can't be indexed by content directly —
//! each row's `title` / `body` / whatever is ciphertext with a random
//! nonce, so LIKE / FTS5 scans of the ciphertext are useless. Full-text
//! search over encrypted data requires a deterministic *token* for each
//! searchable term that:
//!   * collides for equal inputs (so `"hello"` always maps to the same token),
//!   * doesn't collide across distinct inputs (so `"hello"` and `"world"` are
//!     distinguishable),
//!   * reveals nothing about plaintext without the key.
//!
//! HMAC-BLAKE3 is exactly that: deterministic keyed hashing. BLAKE3's
//! keyed-hash mode is a built-in MAC construction — there is no need to
//! layer an HMAC envelope on top of it. The SDK's existing
//! [`crate::crypto::hash::blake3_keyed`] is the underlying primitive.
//!
//! # Threat model
//!
//! Blind-index tokens ARE searchable in plaintext form inside the
//! SQLCipher DB. An attacker with read access to the DB + key for the
//! main data can't reverse a token without the blind-index key, BUT the
//! *distribution* of tokens (how often `"hello"` appears) leaks via
//! frequency analysis. This matters for low-entropy searchable fields
//! (email addresses in a ~1000-row contact list — the 26 most-common
//! top-level-domains produce obvious peaks). Mitigate at the schema
//! level: salt the blind index per-row / per-user if frequency analysis
//! is in scope.
//!
//! # Port provenance
//!
//! Direct port of BoomLeft Scanner's `HmacBlindIndex.kt` / `HMACBlindIndex.swift`
//! (`packages/android-crypto` + `packages/ios-crypto`). The Scanner helpers
//! wrap this primitive with tokenisation, bigram generation, and a padded
//! output list — those concerns stay at the caller layer. The SDK ships
//! only the cryptographic core (keyed hash over a single term) because the
//! tokeniser / padding strategy is app-specific (Scanner's
//! whitespace-split-and-lowercase is one reasonable shape, but Voice's
//! future contact search will want a different one).
//!
//! # Example
//!
//! ```
//! use privacysuite_core_sdk::crypto::{blind_index, keys};
//!
//! // Per-app master key.
//! let master = keys::VaultKey::from_bytes([0x42; 32]);
//!
//! // Domain-separate the blind-index key from the data-encryption key.
//! let idx_key = blind_index::BlindIndexKey::derive(
//!     &master,
//!     "myapp 2026 blind-index title",
//! ).unwrap();
//!
//! // Caller normalises the search term.
//! let term = b"hello";
//! let stored = blind_index::token(&idx_key, term);
//!
//! // Same input produces the same token — that's how the search works.
//! let query = blind_index::token(&idx_key, b"hello");
//! assert!(blind_index::tokens_equal(&stored, &query));
//! ```

use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::hash::{self, BLAKE3_HASH_LEN};
use crate::crypto::kdf;
use crate::crypto::keys::VaultKey;
use crate::error::CryptoError;

/// Length of a blind-index token, in bytes (256 bits — same width as the
/// underlying BLAKE3 MAC).
pub const BLIND_INDEX_TOKEN_LEN: usize = BLAKE3_HASH_LEN;

/// Opaque blind-index key. Derive one per searchable column via
/// [`BlindIndexKey::derive`].
///
/// The key material is zeroized when the value is dropped. This type
/// deliberately does **not** implement `Clone` — callers who need two
/// usage sites can derive again from the same master + context, which is
/// deterministic, or pass a reference.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct BlindIndexKey {
    bytes: [u8; BLIND_INDEX_TOKEN_LEN],
}

impl BlindIndexKey {
    /// Derive a blind-index key from a [`VaultKey`] + a domain-separation
    /// `context` string.
    ///
    /// Internally calls [`crate::crypto::kdf::derive_subkey`], so the same
    /// rules apply: use a unique context per searchable column. The
    /// canonical form is `"<appname> <year> blind-index <field>"`, for
    /// example `"scanner 2026 blind-index receipt_title"`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::KeyDerivation`] if `context` is empty. The
    /// context is a compile-time constant for every production caller, so
    /// this should never fire outside tests.
    pub fn derive(master: &VaultKey, context: &str) -> Result<Self, CryptoError> {
        let subkey = kdf::derive_subkey(master, context)?;
        let mut bytes = [0u8; BLIND_INDEX_TOKEN_LEN];
        bytes.copy_from_slice(subkey.as_bytes());
        Ok(Self { bytes })
    }

    /// Construct a [`BlindIndexKey`] from 32 raw bytes.
    ///
    /// Prefer [`BlindIndexKey::derive`] in production; direct construction
    /// is intended for tests and for the UniFFI boundary where the caller
    /// already holds a derived key.
    #[must_use]
    pub fn from_bytes(bytes: [u8; BLIND_INDEX_TOKEN_LEN]) -> Self {
        Self { bytes }
    }
}

impl fmt::Debug for BlindIndexKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BlindIndexKey(***)")
    }
}

/// Produce the deterministic index token for `term` under `key`.
///
/// Callers typically normalise `term` first (lowercase, trim, strip
/// diacritics) so case-variants collapse to a single token. Normalisation
/// is deliberately the caller's choice — different searchable fields want
/// different normalisations, and the SDK does not assume locale.
///
/// An empty `term` is accepted and returns a well-defined, key-specific
/// token; callers that want to reject empties should do so before the
/// call.
#[must_use]
pub fn token(key: &BlindIndexKey, term: &[u8]) -> [u8; BLIND_INDEX_TOKEN_LEN] {
    hash::blake3_keyed(&key.bytes, term)
}

/// Constant-time comparison of two blind-index tokens.
///
/// Use this whenever comparing a freshly-generated query token against a
/// stored token. Direct `==` on `[u8; 32]` is variable-time and would leak
/// the length of the matching prefix through timing — measurable in
/// practice on low-latency local queries.
#[must_use]
pub fn tokens_equal(
    a: &[u8; BLIND_INDEX_TOKEN_LEN],
    b: &[u8; BLIND_INDEX_TOKEN_LEN],
) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_master() -> VaultKey {
        VaultKey::from_bytes([0x42; 32])
    }

    // -- BlindIndexKey::derive --

    #[test]
    fn derive_is_deterministic() {
        let master = test_master();
        let k1 = BlindIndexKey::derive(&master, "app 2026 blind-index title").unwrap();
        let k2 = BlindIndexKey::derive(&master, "app 2026 blind-index title").unwrap();
        assert_eq!(k1.bytes, k2.bytes);
    }

    #[test]
    fn derive_is_context_dependent() {
        let master = test_master();
        let k1 = BlindIndexKey::derive(&master, "app 2026 blind-index title").unwrap();
        let k2 = BlindIndexKey::derive(&master, "app 2026 blind-index body").unwrap();
        assert_ne!(k1.bytes, k2.bytes);
    }

    #[test]
    fn derive_is_master_dependent() {
        let m1 = VaultKey::from_bytes([0x01; 32]);
        let m2 = VaultKey::from_bytes([0x02; 32]);
        let k1 = BlindIndexKey::derive(&m1, "app 2026 blind-index title").unwrap();
        let k2 = BlindIndexKey::derive(&m2, "app 2026 blind-index title").unwrap();
        assert_ne!(k1.bytes, k2.bytes);
    }

    #[test]
    fn derive_rejects_empty_context() {
        let master = test_master();
        assert_eq!(
            BlindIndexKey::derive(&master, "").map(|_| ()),
            Err(CryptoError::KeyDerivation),
        );
    }

    #[test]
    fn derive_produces_32_bytes() {
        let master = test_master();
        let k = BlindIndexKey::derive(&master, "ctx").unwrap();
        assert_eq!(k.bytes.len(), BLIND_INDEX_TOKEN_LEN);
    }

    #[test]
    fn derive_sub_key_independent_of_master_bytes() {
        // Sanity: the derived key is NOT just a memcpy of the master.
        let master = test_master();
        let k = BlindIndexKey::derive(&master, "ctx").unwrap();
        assert_ne!(k.bytes, *master.as_bytes());
    }

    // -- token --

    #[test]
    fn token_is_deterministic() {
        let key = BlindIndexKey::from_bytes([0x11; 32]);
        let a = token(&key, b"hello");
        let b = token(&key, b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn token_is_term_dependent() {
        let key = BlindIndexKey::from_bytes([0x11; 32]);
        let a = token(&key, b"hello");
        let b = token(&key, b"world");
        assert_ne!(a, b);
    }

    #[test]
    fn token_is_key_dependent() {
        let k1 = BlindIndexKey::from_bytes([0x11; 32]);
        let k2 = BlindIndexKey::from_bytes([0x22; 32]);
        let t1 = token(&k1, b"same term");
        let t2 = token(&k2, b"same term");
        assert_ne!(t1, t2);
    }

    #[test]
    fn token_accepts_empty_term() {
        let key = BlindIndexKey::from_bytes([0x11; 32]);
        let a = token(&key, b"");
        let b = token(&key, b"");
        // Same key + empty term is stable (spec: "empty term produces a
        // stable token; don't reject empty").
        assert_eq!(a, b);
        // And different from the token for a non-empty term.
        assert_ne!(a, token(&key, b"\0"));
    }

    #[test]
    fn token_is_32_bytes() {
        let key = BlindIndexKey::from_bytes([0x11; 32]);
        let t = token(&key, b"anything");
        assert_eq!(t.len(), BLIND_INDEX_TOKEN_LEN);
    }

    // -- tokens_equal --

    #[test]
    fn tokens_equal_true_for_equal_tokens() {
        let key = BlindIndexKey::from_bytes([0x11; 32]);
        let a = token(&key, b"same");
        let b = token(&key, b"same");
        assert!(tokens_equal(&a, &b));
    }

    #[test]
    fn tokens_equal_false_for_unequal_tokens() {
        let key = BlindIndexKey::from_bytes([0x11; 32]);
        let a = token(&key, b"foo");
        let b = token(&key, b"bar");
        assert!(!tokens_equal(&a, &b));
    }

    #[test]
    fn tokens_equal_false_for_last_byte_difference() {
        // Prefix match that only differs in the last byte — the naive
        // `==` on `[u8; 32]` also catches this, but the purpose of this
        // test is to exercise the constant-time path.
        let mut a = [0u8; BLIND_INDEX_TOKEN_LEN];
        let mut b = [0u8; BLIND_INDEX_TOKEN_LEN];
        a[BLIND_INDEX_TOKEN_LEN - 1] = 0x01;
        b[BLIND_INDEX_TOKEN_LEN - 1] = 0x02;
        assert!(!tokens_equal(&a, &b));
    }

    // -- collision check --

    #[test]
    fn one_hundred_distinct_terms_produce_one_hundred_distinct_tokens() {
        // Pool size 100 under a 256-bit output: the birthday bound for a
        // collision is ~2^128 draws, so a real collision here would
        // indicate a regression. This check anchors the "distinct inputs
        // don't collide" contract.
        let key = BlindIndexKey::from_bytes([0x33; 32]);
        let mut seen = std::collections::HashSet::with_capacity(100);
        for i in 0u32..100 {
            let term = format!("search-term-{i}");
            let t = token(&key, term.as_bytes());
            assert!(seen.insert(t), "unexpected collision at term {i}");
        }
        assert_eq!(seen.len(), 100);
    }

    // -- Debug redaction --

    #[test]
    fn debug_does_not_leak_bytes() {
        let key = BlindIndexKey::from_bytes([0xAB; 32]);
        let debug = format!("{key:?}");
        assert!(!debug.contains("AB"));
        assert!(debug.contains("***"));
    }

    // -- Scanner cross-check --

    #[test]
    fn token_matches_direct_blake3_keyed() {
        // Proof that the SDK primitive is literally HMAC-BLAKE3 over the
        // key bytes, not some additional envelope — this is what makes
        // Scanner's port an un-shim rather than a recomputation.
        let key_bytes = [0x77u8; 32];
        let key = BlindIndexKey::from_bytes(key_bytes);
        let term = b"receipts 2026-04";
        assert_eq!(token(&key, term), hash::blake3_keyed(&key_bytes, term));
    }
}
