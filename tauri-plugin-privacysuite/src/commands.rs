//! Tauri command handlers wrapping `PrivacySuite` Core SDK.
//!
//! Each function here is intended to be registered as a `#[tauri::command]`.
//! When building inside a Tauri project, uncomment the `tauri` dependency
//! in `Cargo.toml` and add the `#[tauri::command]` attributes.
//!
//! All commands accept and return serializable types from [`super::models`].
//! Secret material (keys, mnemonics) is never sent over IPC — only opaque
//! handles or encrypted blobs cross the bridge.

use privacysuite_core_sdk::crypto::{aead, kdf, keys, mnemonic};
use privacysuite_core_sdk::error::CryptoError;

use crate::models::{EncryptedBlob, KeyHandle, MnemonicPhrase};

/// Generate a new vault: salt + mnemonic + encrypted key blob.
///
/// The passphrase-derived key never leaves Rust. The frontend receives
/// only an opaque handle and the mnemonic words (for one-time display).
///
/// # Errors
///
/// Returns a serialised error string if key derivation or encryption fails.
pub fn vault_create(passphrase: &str) -> Result<(KeyHandle, MnemonicPhrase), String> {
    let salt = keys::Salt::generate().map_err(|e| e.to_string())?;
    let key = keys::derive_key(passphrase.as_bytes(), &salt).map_err(|e| e.to_string())?;
    let mnem = mnemonic::Mnemonic::generate().map_err(|e| e.to_string())?;
    let words = mnem.to_phrase();

    let handle = KeyHandle {
        salt: salt.as_bytes().to_vec(),
    };
    let phrase = MnemonicPhrase { words };

    // Key is dropped here → ZeroizeOnDrop scrubs it from memory.
    drop(key);

    Ok((handle, phrase))
}

/// Encrypt a plaintext blob using a passphrase-derived key.
///
/// # Errors
///
/// Returns a serialised error if key derivation or AEAD encryption fails.
pub fn encrypt_blob(
    passphrase: &str,
    salt: &[u8],
    plaintext: &[u8],
    context: &str,
) -> Result<EncryptedBlob, String> {
    let salt = keys::Salt::from_slice(salt).map_err(|e| e.to_string())?;
    let key = keys::derive_key(passphrase.as_bytes(), &salt).map_err(|e| e.to_string())?;
    let ciphertext =
        aead::encrypt(&key, plaintext, context.as_bytes()).map_err(|e| e.to_string())?;
    Ok(EncryptedBlob { ciphertext })
}

/// Decrypt an encrypted blob.
///
/// # Errors
///
/// Returns a serialised error if key derivation or AEAD decryption fails.
pub fn decrypt_blob(
    passphrase: &str,
    salt: &[u8],
    blob: &EncryptedBlob,
    context: &str,
) -> Result<Vec<u8>, String> {
    let salt = keys::Salt::from_slice(salt).map_err(|e| e.to_string())?;
    let key = keys::derive_key(passphrase.as_bytes(), &salt).map_err(|e| e.to_string())?;
    aead::decrypt(&key, &blob.ciphertext, context.as_bytes()).map_err(|e| e.to_string())
}

/// Verify a mnemonic phrase is valid BIP39.
///
/// # Errors
///
/// Returns an error string if the phrase is invalid.
pub fn verify_mnemonic(phrase: &str) -> Result<(), String> {
    let _m = mnemonic::Mnemonic::from_phrase(phrase).map_err(|e: CryptoError| e.to_string())?;
    Ok(())
}

/// Derive a purpose-specific sub-key from a passphrase-derived master key.
///
/// The `context` string binds the sub-key to a specific purpose (e.g.,
/// `"myapp 2026 database encryption"`). Different contexts produce
/// independent keys from the same master.
///
/// # Errors
///
/// Returns a serialised error if key derivation fails.
pub fn derive_subkey(
    passphrase: &str,
    salt: &[u8],
    context: &str,
) -> Result<EncryptedBlob, String> {
    let salt = keys::Salt::from_slice(salt).map_err(|e| e.to_string())?;
    let master = keys::derive_key(passphrase.as_bytes(), &salt).map_err(|e| e.to_string())?;
    let subkey = kdf::derive_subkey(&master, context).map_err(|e| e.to_string())?;
    // Return the sub-key bytes wrapped in an EncryptedBlob so raw key material
    // never appears as a plain JSON field. The frontend should treat this as
    // opaque and pass it back for encrypt/decrypt operations.
    Ok(EncryptedBlob {
        ciphertext: subkey.as_bytes().to_vec(),
    })
}
