//! Key types and Argon2id key derivation.
//!
//! All key material in this module implements [`Zeroize`] and [`ZeroizeOnDrop`]
//! to ensure secrets are scrubbed from memory when no longer needed.
//!
//! # Argon2id Parameters
//!
//! | Parameter   | Value | Rationale                          |
//! |-------------|-------|------------------------------------|
//! | Memory      | 64 MB | OWASP minimum for interactive login |
//! | Time        | 3     | Balances security vs. mobile UX    |
//! | Parallelism | 4     | Matches typical mobile core count  |
//! | Output      | 32 B  | 256-bit key for XChaCha20-Poly1305 |

use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::util::fill_random;
use crate::error::CryptoError;

/// Argon2id memory cost in KiB (64 MB = 65536 KiB).
const ARGON2_M_COST_KIB: u32 = 64 * 1024;

/// Argon2id time cost (iterations).
const ARGON2_T_COST: u32 = 3;

/// Argon2id parallelism degree.
const ARGON2_P_COST: u32 = 4;

/// Derived key length in bytes (256 bits).
pub const KEY_LEN: usize = 32;

/// Salt length in bytes (256 bits).
pub const SALT_LEN: usize = 32;

/// A 256-bit key derived from a user's passphrase via Argon2id.
///
/// The inner bytes are zeroized when this value is dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VaultKey {
    bytes: [u8; KEY_LEN],
}

impl VaultKey {
    /// Returns a reference to the raw key bytes.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }

    /// Creates a `VaultKey` from a 32-byte array.
    ///
    /// The caller is responsible for ensuring the source bytes are
    /// cryptographically derived (e.g., from Argon2id or BIP39 seed).
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self { bytes }
    }
}

impl fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultKey(***)")
    }
}

impl PartialEq for VaultKey {
    /// Constant-time equality comparison to prevent timing side-channels
    /// when comparing keys (e.g., during vault migration or key rotation).
    fn eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl Eq for VaultKey {}

/// A 256-bit random salt for Argon2id key derivation.
///
/// Does not implement `Clone` or `Copy` to prevent accidental duplication
/// that would leave unzeroized copies in memory.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Salt {
    bytes: [u8; SALT_LEN],
}

impl Salt {
    /// Generates a new cryptographically random salt.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Rng`] if the OS entropy source is unavailable.
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self { bytes: fill_random::<SALT_LEN>()? })
    }

    /// Creates a `Salt` from an existing 32-byte array.
    #[must_use]
    pub fn from_bytes(bytes: [u8; SALT_LEN]) -> Self {
        Self { bytes }
    }

    /// Creates a `Salt` from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidLength`] if the slice is not [`SALT_LEN`] bytes.
    pub fn from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        let bytes: [u8; SALT_LEN] =
            slice.try_into().map_err(|_| CryptoError::InvalidLength)?;
        Ok(Self { bytes })
    }

    /// Returns a reference to the raw salt bytes.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SALT_LEN] {
        &self.bytes
    }
}

impl fmt::Debug for Salt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Salt(***)")
    }
}

/// Validated Argon2id parameters for [`derive_key_with_params`].
///
/// Enforces minimum security floors to prevent downgrade attacks:
///
/// | Parameter   | Minimum | Maximum | Default (used by [`derive_key`]) |
/// |-------------|---------|---------|----------------------------------|
/// | Memory      | 64 MB   | 1 GB    | 64 MB                            |
/// | Time        | 3       | 32      | 3                                |
/// | Parallelism | 1       | 8       | 4                                |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in MiB. Must be ≥ 64.
    m_cost_mib: u32,
    /// Time cost (iterations). Must be ≥ 3.
    t_cost: u32,
    /// Parallelism degree. Must be 1..=8.
    p_cost: u32,
}

/// Minimum memory cost in MiB (64 MB).
const MIN_M_COST_MIB: u32 = 64;
/// Maximum memory cost in MiB (1 GB).
const MAX_M_COST_MIB: u32 = 1024;
/// Minimum time cost (iterations).
const MIN_T_COST: u32 = 3;
/// Maximum time cost (iterations).
const MAX_T_COST: u32 = 32;
/// Minimum parallelism.
const MIN_P_COST: u32 = 1;
/// Maximum parallelism.
const MAX_P_COST: u32 = 8;

impl KdfParams {
    /// Creates validated KDF parameters.
    ///
    /// # Arguments
    ///
    /// * `m_cost_mib` — Memory cost in MiB (64..=1024).
    /// * `t_cost` — Time cost / iterations (3..=32).
    /// * `p_cost` — Parallelism degree (1..=8).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::KeyDerivation`] if any parameter is outside
    /// the allowed range.
    pub fn new(m_cost_mib: u32, t_cost: u32, p_cost: u32) -> Result<Self, CryptoError> {
        if !(MIN_M_COST_MIB..=MAX_M_COST_MIB).contains(&m_cost_mib) {
            return Err(CryptoError::KeyDerivation);
        }
        if !(MIN_T_COST..=MAX_T_COST).contains(&t_cost) {
            return Err(CryptoError::KeyDerivation);
        }
        if !(MIN_P_COST..=MAX_P_COST).contains(&p_cost) {
            return Err(CryptoError::KeyDerivation);
        }
        Ok(Self {
            m_cost_mib,
            t_cost,
            p_cost,
        })
    }

    /// Returns the memory cost in MiB.
    #[must_use]
    pub fn m_cost_mib(&self) -> u32 {
        self.m_cost_mib
    }

    /// Returns the time cost (iterations).
    #[must_use]
    pub fn t_cost(&self) -> u32 {
        self.t_cost
    }

    /// Returns the parallelism degree.
    #[must_use]
    pub fn p_cost(&self) -> u32 {
        self.p_cost
    }
}

/// Derives a [`VaultKey`] from a passphrase and salt using Argon2id.
///
/// Parameters: m=64 MB, t=3, p=4 (hardcoded — prevents downgrade attacks).
///
/// For custom parameters see [`derive_key_with_params`].
///
/// # Errors
///
/// Returns [`CryptoError::KeyDerivation`] if the passphrase is empty or
/// Argon2id fails internally.
///
/// # Example
///
/// ```
/// use privacysuite_core_sdk::crypto::keys::{Salt, derive_key};
///
/// let salt = Salt::generate().unwrap();
/// let key = derive_key(b"correct horse battery staple", &salt).unwrap();
/// assert_eq!(key.as_bytes().len(), 32);
/// ```
pub fn derive_key(passphrase: &[u8], salt: &Salt) -> Result<VaultKey, CryptoError> {
    argon2id_derive(passphrase, salt, ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST)
}

/// Shared Argon2id derivation primitive — single place where we instantiate
/// the algorithm, feed it the passphrase and salt, and handle the error
/// path (zeroize the output buffer, return an opaque error).
fn argon2id_derive(
    passphrase: &[u8],
    salt: &Salt,
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<VaultKey, CryptoError> {
    if passphrase.is_empty() {
        return Err(CryptoError::KeyDerivation);
    }
    let params = Params::new(m_cost_kib, t_cost, p_cost, Some(KEY_LEN))
        .map_err(|_| CryptoError::KeyDerivation)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key_bytes = [0u8; KEY_LEN];
    if argon2
        .hash_password_into(passphrase, salt.as_bytes(), &mut key_bytes)
        .is_err()
    {
        key_bytes.zeroize();
        return Err(CryptoError::KeyDerivation);
    }
    Ok(VaultKey::from_bytes(key_bytes))
}

/// Derives a [`VaultKey`] from a passphrase and salt using Argon2id with
/// caller-specified parameters.
///
/// Use [`KdfParams::new`] to construct validated parameters. The defaults
/// used by [`derive_key`] are m=64 MB, t=3, p=4.
///
/// # When to use this
///
/// Most callers should use [`derive_key`] with its hardcoded defaults.
/// Use this variant only when a specific parallelism degree or higher
/// memory/time cost is required (e.g., single-threaded CLI tools that
/// need p=1).
///
/// # Errors
///
/// Returns [`CryptoError::KeyDerivation`] if the passphrase is empty or
/// Argon2id fails internally.
///
/// # Example
///
/// ```
/// use privacysuite_core_sdk::crypto::keys::{Salt, KdfParams, derive_key_with_params};
///
/// let salt = Salt::generate().unwrap();
/// let params = KdfParams::new(64, 3, 1).unwrap(); // parallelism = 1
/// let key = derive_key_with_params(b"passphrase", &salt, &params).unwrap();
/// assert_eq!(key.as_bytes().len(), 32);
/// ```
pub fn derive_key_with_params(
    passphrase: &[u8],
    salt: &Salt,
    kdf_params: &KdfParams,
) -> Result<VaultKey, CryptoError> {
    argon2id_derive(
        passphrase,
        salt,
        kdf_params.m_cost_mib.saturating_mul(1024),
        kdf_params.t_cost,
        kdf_params.p_cost,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_key_produces_32_bytes() {
        let salt = Salt::generate().unwrap();
        let key = derive_key(b"test passphrase", &salt).unwrap();
        assert_eq!(key.as_bytes().len(), KEY_LEN);
    }

    #[test]
    fn derive_key_deterministic() {
        let salt = Salt::from_bytes([42u8; SALT_LEN]);
        let key1 = derive_key(b"same passphrase", &salt).unwrap();
        let salt = Salt::from_bytes([42u8; SALT_LEN]);
        let key2 = derive_key(b"same passphrase", &salt).unwrap();
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn different_salts_produce_different_keys() {
        let salt1 = Salt::from_bytes([1u8; SALT_LEN]);
        let salt2 = Salt::from_bytes([2u8; SALT_LEN]);
        let key1 = derive_key(b"passphrase", &salt1).unwrap();
        let key2 = derive_key(b"passphrase", &salt2).unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn different_passphrases_produce_different_keys() {
        let salt = Salt::from_bytes([42u8; SALT_LEN]);
        let key1 = derive_key(b"passphrase one", &salt).unwrap();
        let salt = Salt::from_bytes([42u8; SALT_LEN]);
        let key2 = derive_key(b"passphrase two", &salt).unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn salt_from_slice_rejects_wrong_length() {
        assert!(Salt::from_slice(&[0u8; 16]).is_err());
    }

    #[test]
    fn salt_from_slice_accepts_correct_length() {
        let bytes = [7u8; SALT_LEN];
        let salt = Salt::from_slice(&bytes).unwrap();
        assert_eq!(salt.as_bytes(), &bytes);
    }

    #[test]
    fn vault_key_debug_does_not_leak() {
        let key = VaultKey::from_bytes([0xAB; KEY_LEN]);
        let debug = format!("{key:?}");
        assert!(!debug.contains("AB"));
        assert!(debug.contains("***"));
    }

    #[test]
    fn salt_debug_does_not_leak() {
        let salt = Salt::from_bytes([0xCD; SALT_LEN]);
        let debug = format!("{salt:?}");
        assert!(!debug.contains("CD"));
        assert!(debug.contains("***"));
    }

    #[test]
    fn empty_passphrase_rejected() {
        let salt = Salt::generate().unwrap();
        assert!(derive_key(b"", &salt).is_err());
    }

    #[test]
    fn vault_key_equality_same_bytes() {
        let key1 = VaultKey::from_bytes([0x42; KEY_LEN]);
        let key2 = VaultKey::from_bytes([0x42; KEY_LEN]);
        assert_eq!(key1, key2);
    }

    #[test]
    fn vault_key_equality_different_bytes() {
        let key1 = VaultKey::from_bytes([0x01; KEY_LEN]);
        let key2 = VaultKey::from_bytes([0x02; KEY_LEN]);
        assert_ne!(key1, key2);
    }

    // -- KdfParams validation --

    #[test]
    fn kdf_params_valid_defaults() {
        let params = KdfParams::new(64, 3, 4).unwrap();
        assert_eq!(params.m_cost_mib(), 64);
        assert_eq!(params.t_cost(), 3);
        assert_eq!(params.p_cost(), 4);
    }

    #[test]
    fn kdf_params_valid_minimums() {
        assert!(KdfParams::new(64, 3, 1).is_ok());
    }

    #[test]
    fn kdf_params_valid_maximums() {
        assert!(KdfParams::new(1024, 32, 8).is_ok());
    }

    #[test]
    fn kdf_params_rejects_low_memory() {
        assert!(KdfParams::new(63, 3, 4).is_err());
    }

    #[test]
    fn kdf_params_rejects_high_memory() {
        assert!(KdfParams::new(1025, 3, 4).is_err());
    }

    #[test]
    fn kdf_params_rejects_low_time() {
        assert!(KdfParams::new(64, 2, 4).is_err());
    }

    #[test]
    fn kdf_params_rejects_high_time() {
        assert!(KdfParams::new(64, 33, 4).is_err());
    }

    #[test]
    fn kdf_params_rejects_zero_parallelism() {
        assert!(KdfParams::new(64, 3, 0).is_err());
    }

    #[test]
    fn kdf_params_rejects_high_parallelism() {
        assert!(KdfParams::new(64, 3, 9).is_err());
    }

    // -- derive_key_with_params --

    #[test]
    fn derive_key_with_params_produces_32_bytes() {
        let salt = Salt::from_bytes([42u8; SALT_LEN]);
        let params = KdfParams::new(64, 3, 1).unwrap();
        let key = derive_key_with_params(b"test", &salt, &params).unwrap();
        assert_eq!(key.as_bytes().len(), KEY_LEN);
    }

    #[test]
    fn derive_key_with_params_deterministic() {
        let salt = Salt::from_bytes([42u8; SALT_LEN]);
        let params = KdfParams::new(64, 3, 1).unwrap();
        let k1 = derive_key_with_params(b"passphrase", &salt, &params).unwrap();
        let salt = Salt::from_bytes([42u8; SALT_LEN]);
        let k2 = derive_key_with_params(b"passphrase", &salt, &params).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn derive_key_with_params_empty_passphrase_rejected() {
        let salt = Salt::generate().unwrap();
        let params = KdfParams::new(64, 3, 1).unwrap();
        assert!(derive_key_with_params(b"", &salt, &params).is_err());
    }

    #[test]
    fn different_parallelism_produces_different_keys() {
        let salt = Salt::from_bytes([42u8; SALT_LEN]);
        let p1 = KdfParams::new(64, 3, 1).unwrap();
        let p4 = KdfParams::new(64, 3, 4).unwrap();
        let k1 = derive_key_with_params(b"same passphrase", &salt, &p1).unwrap();
        let salt = Salt::from_bytes([42u8; SALT_LEN]);
        let k4 = derive_key_with_params(b"same passphrase", &salt, &p4).unwrap();
        assert_ne!(k1.as_bytes(), k4.as_bytes());
    }

    #[test]
    fn default_derive_key_matches_p4_params() {
        let salt = Salt::from_bytes([42u8; SALT_LEN]);
        let default_key = derive_key(b"passphrase", &salt).unwrap();
        let salt = Salt::from_bytes([42u8; SALT_LEN]);
        let params = KdfParams::new(64, 3, 4).unwrap();
        let params_key = derive_key_with_params(b"passphrase", &salt, &params).unwrap();
        assert_eq!(default_key.as_bytes(), params_key.as_bytes());
    }
}
