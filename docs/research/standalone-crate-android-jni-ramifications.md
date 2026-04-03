# Ramifications of Publishing privacysuite-core as a Standalone Crate with Android JNI Bindings

## Context

While integrating PrivacySuite Core SDK into
[boomleft-voice](https://github.com/mkfnch/boomleft-voice), Claude recommended:

> "Rather than trying to retrofit the SDK into Voice, consider publishing
> privacysuite-core as a standalone Rust crate with Android JNI bindings (via
> jni-rs or UniFFI) — this would let all BoomLeft Android apps share the
> cryptographic primitives."

This document analyzes whether that recommendation is sound.

---

## 1. Current State: What Exists Today

The SDK is a two-crate Rust workspace:

| Crate | Purpose | Consumer |
|-------|---------|----------|
| `privacysuite-core-sdk` | Pure Rust crypto/storage/sync primitives | Library |
| `tauri-plugin-privacysuite` | Tauri 2.x IPC bridge (Kotlin/Swift via WebView) | Desktop/mobile Tauri apps |

**There is zero Android-native infrastructure today:**
- No `extern "C"` or `#[no_mangle]` exports
- No JNI bindings, no UniFFI definitions
- No `.cargo/config.toml` for Android targets
- `#![forbid(unsafe_code)]` at crate root blocks JNI/FFI in the core crate itself
- No feature flags to selectively compile modules

The Tauri plugin is the only consumer, and it bridges to the frontend via JSON-serialized
IPC — a pattern that does not translate to native Android apps.

---

## 2. The Core Question: Tauri Plugin vs. Native Bindings

The recommendation is essentially: **stop going through Tauri's WebView IPC for Android
apps and instead call Rust directly via JNI.**

This matters because:

| Concern | Tauri IPC (current) | Native JNI (proposed) |
|---------|--------------------|-----------------------|
| **Latency** | JSON serialize → WebView → deserialize | Direct function call via JNI/JNA |
| **App size** | Bundles Chromium/WebView runtime | Only Rust `.so` + thin Kotlin wrapper |
| **UX** | WebView-based UI (HTML/CSS/JS) | Native Jetpack Compose UI |
| **Platform APIs** | Limited access via Tauri plugins | Full Android SDK access |
| **Voice-specific** | No native audio API access | Direct access to AudioRecord, MediaCodec |

For a voice app specifically, Tauri is a poor fit — audio capture, real-time processing,
and background services all require native Android APIs that WebView cannot efficiently
access.

---

## 3. Technical Ramifications

### 3.1 Binding Technology Choice

Two viable approaches based on the ecosystem (April 2026):

**UniFFI (Mozilla) — Recommended for BoomLeft's situation:**
- Auto-generates Kotlin bindings from Rust via proc-macros or UDL files
- Same Rust code also generates Swift (iOS) and Python bindings
- Battle-tested: used by Firefox Android, Matrix SDK, Mozilla Application Services
- Async Rust (`async fn`) maps to Kotlin `suspend fun` (coroutines)
- **Downside**: Uses JNA under the hood (reflection-based FFI), adding ~2MB to APK and
  measurable per-call overhead vs. direct JNI. A direct JNI backend is in progress
  ([uniffi-rs#2672](https://github.com/mozilla/uniffi-rs/issues/2672))

**jni-rs — Alternative for performance-critical paths:**
- Direct JNI bindings, no reflection overhead
- Full access to `JNIEnv`, `JavaVM`, Android `Context`
- **Downside**: Manual type marshaling, Android-only (no iOS reuse), significantly more
  code to write and maintain

**Signal's approach (custom bridge macros):**
- Signal wrote their own `libsignal_bridge_macros` proc-macro system that generates JNI,
  Swift, and Node.js bindings from annotated Rust functions
- Maximum control and performance, but substantial upfront engineering investment
- Only justified at Signal's scale and security requirements

**Recommendation**: Start with UniFFI. It gets you Kotlin + Swift from one codebase with
minimal effort. If JNA overhead proves problematic for specific hot paths (unlikely for
crypto operations that are inherently compute-bound), drop to jni-rs for those paths only.

### 3.2 Architecture Change: New FFI Wrapper Crate

Because `privacysuite-core-sdk` has `#![forbid(unsafe_code)]`, JNI/UniFFI bindings
cannot live in the core crate. The workspace needs a new member:

```
PrivacySuite-Core-SDK/
├── Cargo.toml                          # workspace
├── src/                                # privacysuite-core-sdk (unchanged)
├── tauri-plugin-privacysuite/          # existing Tauri bridge
└── privacysuite-ffi/                   # NEW: UniFFI/JNI wrapper
    ├── Cargo.toml                      # depends on privacysuite-core-sdk
    ├── src/lib.rs                      # #[uniffi::export] functions
    └── uniffi.toml                     # UniFFI configuration
```

The FFI crate:
- Compiles as `crate-type = ["cdylib"]` (produces `.so` for Android)
- Allows `unsafe` (required for FFI) but contains ONLY the binding glue
- Re-exports a curated subset of the core API (not everything needs FFI exposure)
- Handles type translation (e.g., `VaultKey` → opaque handle, `Vec<u8>` → byte array)

This preserves the core crate's `forbid(unsafe_code)` guarantee while enabling FFI.

### 3.3 Dependency Challenges for Android Cross-Compilation

| Dependency | Android Viability | Mitigation |
|------------|-------------------|------------|
| **rusqlite + bundled-sqlcipher** | Requires C cross-compilation with NDK | Use `bundled-sqlcipher-vendored-openssl` feature; cargo-ndk handles toolchain setup. Adds build time (minutes per target) and ~1-3MB per ABI |
| **tokio** | Works on Android | Must construct runtime manually (no `#[tokio::main]`); use `spawn_blocking` for crypto; shut down on app background |
| **hickory-resolver (DoH)** | Should work (uses rustls) | May need feature flag to disable if app uses Android's DNS |
| **tokio-tungstenite** | Works with `native-tls` or `rustls` | Platform TLS on Android works automatically |
| **tokio-socks (Tor)** | Pure Rust, works | No issues expected |
| **automerge** | Pure Rust, works | No issues expected |
| **opaque-ke** | Pure Rust (RustCrypto), works | No issues expected |

**The long pole is SQLCipher.** Vendoring OpenSSL + SQLCipher for 3-4 Android ABIs is
the most complex part of the build. But this is a solved problem — Mozilla and Matrix
both do it in CI.

### 3.4 Feature Flags Become Essential

Not every BoomLeft app needs every module. A voice app probably needs:
- `crypto` (AEAD, key derivation) — yes
- `auth` (OPAQUE) — yes
- `storage` (SQLCipher) — maybe
- `sync` (CRDT, WebSocket relay) — maybe
- `networking` (DoH, Tor) — probably not

The core crate should be refactored to use Cargo feature flags:

```toml
[features]
default = ["crypto", "auth"]
crypto = ["argon2", "chacha20poly1305", "sha2", "hmac", "blake3", ...]
auth = ["opaque-ke", "crypto"]
storage = ["rusqlite", "crypto"]
sync = ["automerge", "tokio", "tokio-tungstenite", "crypto"]
networking = ["hickory-resolver", "tokio-socks"]
full = ["crypto", "auth", "storage", "sync", "networking"]
```

This reduces binary size and compilation time for apps that only need a subset.

### 3.5 Distribution: AAR on Maven

The standard model (used by Signal, Mozilla, Matrix):

1. CI (`cargo-ndk`) builds `.so` for `arm64-v8a`, `armeabi-v7a`, `x86_64`
2. UniFFI generates Kotlin binding classes
3. Thin Kotlin wrapper module provides idiomatic API (coroutines, `Closeable`, etc.)
4. Published as AAR artifact on Maven (Central or GitHub Packages)
5. Consumers add one Gradle dependency line — no Rust toolchain needed

**Gobley** (Gradle plugin, v0.3) is an emerging alternative that integrates `cargo` into
the Gradle build, but it requires the consumer to have Rust installed — not suitable for
external distribution.

### 3.6 Memory Management at the FFI Boundary

Key material handling changes significantly across JNI:

| Concern | Current (pure Rust) | With JNI |
|---------|--------------------|----------|
| Zeroization | `Zeroize + ZeroizeOnDrop` on all key types | Rust side still zeroizes, but JNA/JNI byte arrays on the JVM heap are NOT zeroized and subject to GC relocation |
| Key lifetime | Rust ownership guarantees | Must use opaque handles (Arc-pointer-based); Kotlin must call `destroy()` / use `use {}` blocks or leak memory |
| GC interaction | None | JVM GC can copy byte arrays, leaving unzeroized copies in memory |

**This is a real security concern.** The current guarantee — "key material is always
zeroized" — weakens at the JNI boundary because:
- JNA serializes data through `RustBuffer` byte arrays that traverse JVM heap
- Even if you zeroize on the Rust side, the JVM may have copied the bytes
- No way to force GC to zeroize freed memory

**Mitigation**: Never pass raw key bytes across JNI. Use opaque handles (pointers to
Rust-owned `Arc<VaultKey>`) and perform all crypto operations on the Rust side. The
Kotlin layer should only hold handles, never key material. This is exactly what the
Tauri plugin already does with `KeyHandle` — the pattern translates directly.

### 3.7 The `#![forbid(unsafe_code)]` Boundary

This is actually a **strength** of the proposed architecture:

```
┌─────────────────────────────────┐
│  privacysuite-core-sdk          │  ← #![forbid(unsafe_code)]
│  (all crypto, storage, sync)    │     Zero unsafe, fully auditable
└──────────────┬──────────────────┘
               │ Safe Rust API
┌──────────────▼──────────────────┐
│  privacysuite-ffi               │  ← Allows unsafe (minimal surface)
│  (UniFFI glue only)             │     Only type marshaling + FFI exports
└──────────────┬──────────────────┘
               │ JNI / JNA
┌──────────────▼──────────────────┐
│  Kotlin wrapper (AAR)           │  ← Pure Kotlin, idiomatic API
│  (coroutines, Closeable, etc.)  │
└─────────────────────────────────┘
```

The unsafe surface is confined to a thin, auditable FFI layer. The core crypto remains
`forbid(unsafe_code)`. This is the same architecture Signal and Mozilla use.

---

## 4. Strategic Ramifications

### 4.1 What You Gain

**Cross-app code sharing:**
Every BoomLeft Android app (Voice, and any future apps) gets the same audited crypto
primitives without duplicating code or depending on less-vetted Android-native crypto
libraries.

**iOS for free (with UniFFI):**
UniFFI generates Swift bindings from the same Rust code. If BoomLeft ever ships iOS apps,
the crypto layer is already portable. Matrix SDK and Mozilla both use this exact strategy.

**Faster native apps:**
Voice (and other apps) can use Jetpack Compose with native Android APIs instead of
Tauri's WebView. For a voice app this is likely a hard requirement — real-time audio
capture and processing through a WebView IPC bridge is impractical.

**Stronger security posture:**
Rust's memory safety guarantees extend to the crypto layer on Android, where the
alternative would be Java/Kotlin crypto libraries (Tink, Bouncy Castle) or C/C++ via
the Android NDK — both with larger attack surfaces than audited Rust.

**Ecosystem alignment:**
Signal, Matrix, Mozilla, and 1Password all publish Rust crypto as native mobile
libraries. This is the established pattern for security-critical mobile code.

### 4.2 What It Costs

**Build infrastructure (HIGH effort, one-time):**
- CI pipeline for cross-compiling to 3-4 Android ABIs
- UniFFI integration and Kotlin binding generation
- Maven publishing workflow
- Estimated: 2-4 weeks of focused infrastructure work

**Feature flag refactoring (MEDIUM effort, one-time):**
- Splitting the monolithic crate into feature-gated modules
- Ensuring each feature combination compiles cleanly
- Testing matrix expands (each feature combo × each target)
- Estimated: 1-2 weeks

**Ongoing maintenance (LOW-MEDIUM effort, continuous):**
- Keeping UniFFI version in sync with upstream
- Testing on Android hardware / emulators
- AAR publishing for each release
- Monitoring for NDK / Rust target regressions

**SQLCipher build complexity (MEDIUM effort, one-time):**
- The vendored OpenSSL + SQLCipher cross-compilation is the gnarliest part
- Once CI is set up, it's stable — but debugging the initial setup is painful
- If Voice doesn't need local encrypted storage, this can be deferred via feature flags

### 4.3 What Could Go Wrong

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| UniFFI breaking changes (pre-1.0) | Medium | Medium | Pin version, test on upgrade |
| SQLCipher cross-compile breaks on NDK update | Low | High | Pin NDK version in CI |
| JNA performance insufficient for hot paths | Low | Medium | Drop to jni-rs for specific functions |
| Key material leaked via JVM heap copies | Medium | High | Opaque handles only, never pass raw bytes |
| Binary size too large for Play Store | Low | Low | Feature flags, strip symbols, LTO |
| Tokio runtime lifecycle issues on Android | Medium | Medium | Graceful shutdown on `onPause`/`onStop` |

---

## 5. Verdict: Does This Make Sense?

### Short answer: **Yes, with caveats.**

### Long answer:

The recommendation is sound **if BoomLeft is building (or will build) more than one
native Android app that needs cryptographic primitives.** The evidence:

1. **The Tauri path is a dead end for Voice.** A voice app needs native audio APIs,
   background services, and real-time processing. Tauri's WebView IPC adds latency and
   blocks access to platform APIs. Even if you could make it work, you'd be fighting the
   framework constantly.

2. **The investment has compounding returns.** The first app (Voice) bears the full cost
   of the build infrastructure. Every subsequent app gets audited Rust crypto for the
   cost of one Gradle dependency line. This is exactly why Signal, Mozilla, and Matrix
   made the same investment.

3. **The crypto primitives are already cleanly separated.** The core crate has no Tauri
   dependencies and a well-defined public API. The hardest design work (key management,
   zeroization discipline, error types) is done. What remains is plumbing.

4. **The ecosystem is mature enough.** UniFFI 0.31 is production-proven. `cargo-ndk` is
   stable. `bundled-sqlcipher-vendored-openssl` works on Android. These are not
   experimental tools.

### Caveats:

- **Don't do this if Voice is the only app.** If BoomLeft will only ever have one
  Android app, the Tauri plugin approach (or just embedding the Rust crate directly
  into Voice's build) is simpler. The Maven-published AAR model only pays off with
  multiple consumers.

- **Feature-flag the crate first.** Before building any FFI layer, split the monolith
  into feature-gated modules. Voice likely doesn't need CRDT sync, DoH, or Tor. Don't
  drag those dependencies into the Voice APK.

- **Start with UniFFI, not jni-rs.** The JNA overhead is not going to matter for crypto
  operations (key derivation takes milliseconds; JNA overhead is microseconds). UniFFI
  gets you Kotlin + Swift from one codebase. Optimize later if profiling shows a need.

- **Budget 3-5 weeks for the initial setup.** Feature flags (1-2 weeks) + FFI wrapper
  crate + CI pipeline + Maven publishing (2-3 weeks). After that, incremental cost per
  app is low.

### Is it a reasonable long-term investment?

**Yes.** Publishing a standalone Rust crypto library with Android (and eventually iOS)
bindings is the same strategic bet that Signal, Matrix, Mozilla, and 1Password have all
made. The pattern is proven, the tooling is mature, and the alternative — rewriting crypto
primitives in Kotlin or depending on Java crypto libraries — is strictly worse from a
security, auditability, and code-sharing perspective.

The question isn't "should we do this?" but "do we have more than one app that needs it?"
If the answer is yes (or likely yes within 12 months), start now.

---

## References

- [mozilla/uniffi-rs](https://github.com/mozilla/uniffi-rs) — UniFFI binding generator
- [UniFFI JNI backend tracking issue](https://github.com/mozilla/uniffi-rs/issues/2672)
- [jni-rs](https://github.com/jni-rs/jni-rs) — Direct JNI bindings for Rust
- [signalapp/libsignal](https://github.com/signalapp/libsignal) — Signal's Rust crypto + custom JNI bridge
- [matrix-org/matrix-rust-sdk](https://github.com/matrix-org/matrix-rust-sdk) — Matrix SDK with UniFFI
- [Mozilla Application Services](https://mozilla.github.io/application-services/book/android-faqs.html)
- [cargo-ndk](https://github.com/bbqsrc/cargo-ndk) — Android NDK integration for Cargo
- [Gobley](https://gobley.dev/) — Gradle plugin for Rust integration
- [rusqlite bundled-sqlcipher](https://github.com/rusqlite/rusqlite) — SQLCipher via Rust
