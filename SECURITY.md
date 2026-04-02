# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in PrivacySuite Core SDK, please report it responsibly.

**Contact:** office@boomleft.com  
**PGP:** *(publish a PGP public key here before v1.0 release)*  
**Subject line:** `[SECURITY] PrivacySuite Core SDK — <brief description>`

Do not open a public GitHub issue for security vulnerabilities.

We will:
- Acknowledge your report within **48 hours**
- Provide an initial assessment within **5 business days**
- Aim to ship a fix or mitigation within **30 days**
- Credit you in the release notes (unless you prefer anonymity)

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes (current) |

We actively maintain the latest version. Once 1.0 ships, we will backport critical security fixes to the most recent minor release.

## Security Design Principles

1. **Unsafe code is forbidden** — `#![forbid(unsafe_code)]` is set at the crate root
2. **RustCrypto only** — no OpenSSL, no ring, no C/FFI crypto dependencies
3. **Fail closed** — every API returns an explicit error rather than degrading silently
4. **Zeroize all secrets** — all key material implements `Zeroize + ZeroizeOnDrop`
5. **No telemetry** — `cargo-deny` blocks telemetry/analytics crates at the dependency level
6. **Supply chain audited** — all dependencies checked via `cargo-deny` and `cargo-audit`

## Disclosure Policy

BoomLeft follows coordinated disclosure. We request a **90-day** disclosure window from the time we acknowledge a report, consistent with industry norms (Google Project Zero, etc.).
