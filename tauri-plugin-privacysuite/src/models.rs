//! Serde-serializable IPC types for the Tauri bridge.
//!
//! These types cross the Rust ↔ TypeScript boundary via JSON serialization.
//! Secret material (raw key bytes, entropy) is **never** included — only
//! opaque handles and encrypted blobs.

use serde::{Deserialize, Serialize};

/// An opaque handle representing a vault's salt.
///
/// The frontend stores this and sends it back with every request so the
/// backend can re-derive the key. The actual key never crosses IPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyHandle {
    /// The 32-byte salt used for Argon2id key derivation.
    pub salt: Vec<u8>,
}

/// A BIP39 mnemonic phrase returned once during vault creation.
///
/// The frontend should display this to the user exactly once, then discard
/// it. It must **never** be persisted or sent to any server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MnemonicPhrase {
    /// Space-separated 24-word mnemonic.
    pub words: String,
}

/// An encrypted data blob produced by AEAD encryption.
///
/// Contains `nonce || ciphertext || tag` as a single byte vector.
/// The blob is opaque to the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBlob {
    /// The raw encrypted bytes (nonce + ciphertext + auth tag).
    pub ciphertext: Vec<u8>,
}
