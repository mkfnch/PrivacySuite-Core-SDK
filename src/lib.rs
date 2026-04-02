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
//! ## Architecture
//!
//! The SDK is split into focused modules:
//!
//! - [`crypto`] — Key derivation (`Argon2id`), AEAD (`XChaCha20-Poly1305`), zeroization
//! - [`storage`] — `SQLCipher` encrypted database abstraction
//! - [`crdt`] — Automerge E2EE document sync
//! - [`sync`] — P2P + relay transport layer
//! - [`networking`] — `DoH` / OHTTP / Arti privacy tiers
//! - [`auth`] — OPAQUE (`aPAKE`) zero-knowledge authentication
//! - [`error`] — Unified error types (fail-closed, no information leakage)

// =============================================================================
// Compiler-enforced security invariants
// =============================================================================
//
// These directives are load-bearing. Removing any of them weakens the security
// posture of every BoomLeft application. Each is explained inline.

// SAFETY: Forbid unsafe code entirely. All cryptographic operations use
// pure-Rust RustCrypto crates. If a future contributor needs unsafe, it must
// go through security review and be isolated in a dedicated, audited module.
#![forbid(unsafe_code)]

// Fail the build on any compiler warning — warnings in a crypto SDK are bugs.
#![deny(warnings)]

// Require documentation on all public items. Undocumented crypto APIs invite
// misuse, which in a privacy SDK is a data-leak vector.
#![deny(missing_docs)]

// Prevent accidental data exposure through Debug formatting of key material.
#![deny(missing_debug_implementations)]

// Catch common mistakes that can lead to subtle security bugs.
#![deny(unused_must_use)]
#![deny(unused_imports)]
#![deny(unreachable_pub)]

pub mod crypto;
pub mod error;

// Future modules — uncomment as each is implemented:
// pub mod storage;
// pub mod crdt;
// pub mod sync;
// pub mod networking;
// pub mod auth;
