//! Tauri 2.x plugin wrapping `PrivacySuite` Core SDK.
//!
//! Drop this plugin into any Tauri application to get encrypted storage,
//! E2EE sync, zero-knowledge authentication, and privacy networking.
//!
//! # Usage
//!
//! ```rust,ignore
//! // src-tauri/src/main.rs
//! .plugin(tauri_plugin_privacysuite::init())
//! ```
//!
//! # Architecture
//!
//! The plugin exposes `#[tauri::command]` wrappers that delegate to the
//! pure-Rust core SDK.  TypeScript bindings are generated via `tauri-specta`.
//!
//! **No user data leaves this plugin.** All cryptographic operations run
//! locally; the only network calls are E2EE sync relay messages and
//! privacy-tier DNS/Tor.

pub mod commands;
pub mod models;
