//! Unified error types for `PrivacySuite` Core SDK.
//!
//! - **Fail closed**: every operation returns an explicit error.
//! - **No information leakage**: error messages never include key material
//!   or internal state.
//! - **Opaque decryption errors**: wrong key and corrupted ciphertext
//!   produce the same error to prevent oracle attacks.

use std::fmt;

/// Errors from cryptographic operations.
///
/// Variants are intentionally coarse-grained. `PartialEq` is derived so
/// callers can match errors structurally instead of comparing `Display`
/// strings (which could introduce timing side-channels).
#[derive(Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// Key derivation failed (bad parameters or empty passphrase).
    KeyDerivation,
    /// AEAD encryption failed.
    Encryption,
    /// AEAD decryption or authentication failed.
    Decryption,
    /// OS entropy source unavailable.
    Rng,
    /// Invalid BIP39 mnemonic phrase.
    InvalidMnemonic,
    /// Input has the wrong length.
    ///
    /// The specific expected/actual values are intentionally omitted: the
    /// variant is opaque by design so error matching depends on the class
    /// of failure rather than on a structured payload no caller reads.
    InvalidLength,
    /// Base64 decoding failed.
    Base64Decode,
    /// Ed25519 signature verification failed.
    SignatureInvalid,
    /// A key or public value is cryptographically invalid (e.g., an X25519
    /// low-order point that would yield a predictable shared secret).
    InvalidKey,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::KeyDerivation => "key derivation failed",
            Self::Encryption => "encryption failed",
            Self::Decryption => "decryption failed",
            Self::Rng => "random number generation failed",
            Self::InvalidMnemonic => "invalid mnemonic phrase",
            Self::InvalidLength => "input has the wrong length",
            Self::Base64Decode => "base64 decoding failed",
            Self::SignatureInvalid => "signature verification failed",
            Self::InvalidKey => "invalid cryptographic key",
        })
    }
}

impl std::error::Error for CryptoError {}
