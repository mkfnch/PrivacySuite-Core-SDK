//! # `PrivacySuite` Core SDK
//!
//! Zero-knowledge cryptographic foundation for every `BoomLeft` application.
//!
//! ## Privacy Guarantees
//!
//! This crate is the enforcement boundary for `BoomLeft`'s core promise:
//!
//! - **Zero user data collection** — no analytics, no crash reporting, no telemetry.
//! - **On-device first** — all data stays on the user's device unless explicitly
//!   E2EE-synced to another device the user controls.
//! - **Private by math, not policy** — even with full server access and a subpoena,
//!   no plaintext user data can be produced. Equivalent to Signal's disclosure posture.
//!
//! ## Modules
//!
//! - [`crypto`] — Key derivation (`Argon2id`), AEAD (`XChaCha20-Poly1305`),
//!   BIP39 mnemonic recovery, zeroization of all key material.
//! - [`error`] — Unified error types (fail-closed, no information leakage).
//!
//! ### Feature-gated modules
//!
//! - [`auth`] — OPAQUE zero-knowledge password authentication (**`auth`** feature, on by default).
//! - [`storage`] — Encrypted on-device storage backed by `SQLCipher` (**`storage`** feature).
//! - [`crdt`] — End-to-end encrypted CRDT documents backed by Automerge (**`sync`** feature).
//! - [`sync`] — E2EE sync protocol over a `WebSocket` relay (**`sync`** feature).
//! - [`networking`] — Multi-tier privacy networking: `DoH`, OHTTP, and Tor (**`networking`** feature).

#![forbid(unsafe_code)]
#![deny(warnings)]

#[cfg(feature = "auth")]
pub mod auth;
#[cfg(feature = "sync")]
pub mod crdt;
pub mod crypto;
pub mod error;
#[cfg(feature = "networking")]
pub mod networking;
pub mod privacy_utils;
#[cfg(feature = "storage")]
pub mod storage;
#[cfg(feature = "sync")]
pub mod sync;
