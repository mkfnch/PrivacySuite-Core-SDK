//! Tauri command handlers wrapping `PrivacySuite` Core SDK.
//!
//! Each function here is intended to be registered as a `#[tauri::command]`.
//! When building inside a Tauri project, uncomment the `tauri` dependency
//! in `Cargo.toml` and add the `#[tauri::command]` attributes.
//!
//! Secret material (keys, mnemonics) is never sent over IPC — only opaque
//! handles or encrypted blobs cross the bridge.
//!
//! The former `derive_subkey` command that returned raw sub-key bytes has
//! been deliberately removed. Use [`encrypt_blob_with_subkey`] /
//! [`decrypt_blob_with_subkey`] instead so the sub-key is derived and
//! consumed inside Rust.

use privacysuite_core_sdk::crypto::{aead, kdf, keys, mnemonic};
use privacysuite_core_sdk::crypto::keys::VaultKey;

use crate::models::{EncryptedBlob, KeyHandle, MnemonicPhrase};

/// Derive the master key from a passphrase + salt pair supplied over IPC,
/// applying a non-empty-passphrase check at the boundary.
///
/// Returns a stringly-typed error so callers can propagate with `?` and
/// so the wire format stays flat.
fn derive_master(passphrase: &str, salt: &[u8]) -> Result<VaultKey, String> {
    if passphrase.is_empty() {
        return Err("passphrase must not be empty".to_string());
    }
    let salt = keys::Salt::from_slice(salt).map_err(|e| e.to_string())?;
    keys::derive_key(passphrase.as_bytes(), &salt).map_err(|e| e.to_string())
}

/// Generate a new vault: salt + mnemonic.
///
/// The passphrase-derived key never leaves Rust. The frontend receives only
/// an opaque salt handle and the mnemonic words (for one-time display).
///
/// # Errors
///
/// Returns a serialised error string if input validation, key derivation, or
/// mnemonic generation fails.
pub fn vault_create(passphrase: &str) -> Result<(KeyHandle, MnemonicPhrase), String> {
    if passphrase.is_empty() {
        return Err("passphrase must not be empty".to_string());
    }
    let salt = keys::Salt::generate().map_err(|e| e.to_string())?;
    // Surface Argon2id errors early. The derived key is scrubbed on drop.
    let _key = keys::derive_key(passphrase.as_bytes(), &salt).map_err(|e| e.to_string())?;
    let words = mnemonic::Mnemonic::generate().map_err(|e| e.to_string())?.to_phrase();
    Ok((
        KeyHandle { salt: salt.as_bytes().to_vec() },
        MnemonicPhrase { words },
    ))
}

/// Encrypt a plaintext blob under a passphrase-derived master key.
///
/// # Errors
///
/// Returns a serialised error if input validation, key derivation, or AEAD
/// encryption fails.
pub fn encrypt_blob(
    passphrase: &str,
    salt: &[u8],
    plaintext: &[u8],
    aad: &str,
) -> Result<EncryptedBlob, String> {
    let key = derive_master(passphrase, salt)?;
    let ciphertext = aead::encrypt(&key, plaintext, aad.as_bytes()).map_err(|e| e.to_string())?;
    Ok(EncryptedBlob { ciphertext })
}

/// Decrypt a blob produced by [`encrypt_blob`].
///
/// # Errors
///
/// Returns a serialised error if input validation, key derivation, or AEAD
/// decryption fails. All decryption failures produce the same error to
/// prevent oracle attacks.
pub fn decrypt_blob(
    passphrase: &str,
    salt: &[u8],
    blob: &EncryptedBlob,
    aad: &str,
) -> Result<Vec<u8>, String> {
    let key = derive_master(passphrase, salt)?;
    aead::decrypt(&key, &blob.ciphertext, aad.as_bytes()).map_err(|e| e.to_string())
}

/// Encrypt a plaintext blob under a **purpose-specific sub-key** derived
/// from the passphrase-derived master and `subkey_context`.
///
/// Raw key material never crosses the IPC boundary: the sub-key is derived
/// and consumed entirely inside Rust for this single operation.
///
/// # Errors
///
/// Returns a serialised error if input validation, key derivation, or AEAD
/// encryption fails.
pub fn encrypt_blob_with_subkey(
    passphrase: &str,
    salt: &[u8],
    subkey_context: &str,
    plaintext: &[u8],
    aad: &str,
) -> Result<EncryptedBlob, String> {
    if subkey_context.is_empty() {
        return Err("subkey_context must not be empty".to_string());
    }
    let master = derive_master(passphrase, salt)?;
    let subkey = kdf::derive_subkey(&master, subkey_context).map_err(|e| e.to_string())?;
    let ciphertext = aead::encrypt(&subkey, plaintext, aad.as_bytes()).map_err(|e| e.to_string())?;
    Ok(EncryptedBlob { ciphertext })
}

/// Decrypt a blob produced by [`encrypt_blob_with_subkey`].
///
/// # Errors
///
/// Returns a serialised error if input validation, key derivation, or AEAD
/// decryption fails.
pub fn decrypt_blob_with_subkey(
    passphrase: &str,
    salt: &[u8],
    subkey_context: &str,
    blob: &EncryptedBlob,
    aad: &str,
) -> Result<Vec<u8>, String> {
    if subkey_context.is_empty() {
        return Err("subkey_context must not be empty".to_string());
    }
    let master = derive_master(passphrase, salt)?;
    let subkey = kdf::derive_subkey(&master, subkey_context).map_err(|e| e.to_string())?;
    aead::decrypt(&subkey, &blob.ciphertext, aad.as_bytes()).map_err(|e| e.to_string())
}

/// Verify a mnemonic phrase is valid BIP39.
///
/// # Errors
///
/// Returns an error string if the phrase is invalid.
pub fn verify_mnemonic(phrase: &str) -> Result<(), String> {
    mnemonic::Mnemonic::from_phrase(phrase).map(|_| ()).map_err(|e| e.to_string())
}
