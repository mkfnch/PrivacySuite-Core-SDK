//! Unified error types for `PrivacySuite` Core SDK.
//!
//! # Design Principles
//!
//! - **Fail closed**: every operation returns an explicit error rather than
//!   silently degrading to a weaker algorithm or returning partial data.
//! - **No information leakage**: error messages never include key material,
//!   plaintext fragments, or internal state that could aid an attacker.
//! - **Opaque to callers where needed**: decryption failures intentionally
//!   do not distinguish between "wrong key" and "corrupted ciphertext"
//!   to prevent adaptive chosen-ciphertext attacks.

use std::fmt;

/// Errors that can occur during cryptographic operations.
///
/// Error variants are intentionally coarse-grained to avoid leaking
/// information about internal cryptographic state.
#[derive(Debug)]
pub enum CryptoError {
    /// Argon2id key derivation failed.
    ///
    /// This typically means the parameter configuration is invalid.
    /// It should never occur with the SDK's hardcoded parameters.
    KeyDerivation,

    /// AEAD encryption failed.
    ///
    /// Indicates a nonce generation or cipher initialization failure.
    Encryption,

    /// AEAD decryption or authentication failed.
    ///
    /// Intentionally does not distinguish between wrong key, corrupted
    /// ciphertext, tampered AAD, or truncated data — all produce the
    /// same error to prevent oracle attacks.
    Decryption,

    /// Cryptographic random number generation failed.
    ///
    /// Indicates the OS entropy source is unavailable. The SDK will
    /// never fall back to a weaker RNG.
    Rng,

    /// The provided mnemonic phrase is invalid.
    ///
    /// Either a word is not in the BIP39 English wordlist, the word
    /// count is wrong, or the checksum does not match.
    InvalidMnemonic,

    /// Input data has an invalid length for the expected operation.
    InvalidLength {
        /// What the input represents (e.g., "salt", "ciphertext").
        context: &'static str,
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        actual: usize,
    },
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyDerivation => write!(f, "key derivation failed"),
            Self::Encryption => write!(f, "encryption failed"),
            Self::Decryption => write!(f, "decryption failed"),
            Self::Rng => write!(f, "random number generation failed"),
            Self::InvalidMnemonic => write!(f, "invalid mnemonic phrase"),
            Self::InvalidLength {
                context,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "invalid {context} length: expected {expected}, got {actual}"
                )
            }
        }
    }
}

impl std::error::Error for CryptoError {}
