//! TLS certificate pinning.
//!
//! Certificate pinning defends against compromised or coerced certificate
//! authorities by restricting which certificates the client will accept
//! for a given host.
//!
//! [`CertificatePinner`] is a verification primitive — it checks whether a
//! SHA-256 certificate hash matches a set of known pins. Integration with
//! a TLS library (e.g., `rustls`, `reqwest`) is the caller's responsibility.
//!
//! # Example
//!
//! ```
//! use privacysuite_core_sdk::crypto::pinning::CertificatePinner;
//!
//! let pin = [0xAB_u8; 32]; // SHA-256 hash of the certificate's SPKI
//! let pinner = CertificatePinner::new(vec![pin]);
//!
//! assert!(pinner.verify(&pin));
//! assert!(!pinner.verify(&[0x00; 32]));
//! ```

use std::collections::HashSet;

/// A set of SHA-256 certificate pins for TLS certificate pinning.
///
/// Stores SHA-256 hashes of Subject Public Key Info (SPKI) and verifies
/// presented certificates against them using constant-time comparison.
#[derive(Debug, Clone)]
pub struct CertificatePinner {
    pins: HashSet<[u8; 32]>,
}

impl CertificatePinner {
    /// Create a pinner from a list of SHA-256 certificate hashes.
    #[must_use]
    pub fn new(pins: Vec<[u8; 32]>) -> Self {
        Self {
            pins: pins.into_iter().collect(),
        }
    }

    /// Returns `true` if `cert_hash` matches one of the pinned certificates.
    ///
    /// Uses constant-time comparison against every pin to prevent
    /// timing side-channels that could reveal which pins are configured.
    #[must_use]
    pub fn verify(&self, cert_hash: &[u8; 32]) -> bool {
        use subtle::ConstantTimeEq;
        let mut found: u8 = 0;
        for pin in &self.pins {
            found |= pin.ct_eq(cert_hash).unwrap_u8();
        }
        found == 1
    }

    /// Returns the number of pinned certificates.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pins.len()
    }

    /// Returns `true` if no pins are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pins.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_known_pin() {
        let pin = [0xABu8; 32];
        let pinner = CertificatePinner::new(vec![pin]);
        assert!(pinner.verify(&pin));
    }

    #[test]
    fn rejects_unknown_pin() {
        let known = [0xABu8; 32];
        let unknown = [0xCDu8; 32];
        let pinner = CertificatePinner::new(vec![known]);
        assert!(!pinner.verify(&unknown));
    }

    #[test]
    fn empty_set_rejects_all() {
        let pinner = CertificatePinner::new(vec![]);
        assert!(!pinner.verify(&[0x00u8; 32]));
        assert!(pinner.is_empty());
    }

    #[test]
    fn multiple_pins() {
        let pin_a = [0x01u8; 32];
        let pin_b = [0x02u8; 32];
        let pinner = CertificatePinner::new(vec![pin_a, pin_b]);
        assert!(pinner.verify(&pin_a));
        assert!(pinner.verify(&pin_b));
        assert!(!pinner.verify(&[0x03u8; 32]));
        assert_eq!(pinner.len(), 2);
    }

    #[test]
    fn len_and_is_empty() {
        let pinner = CertificatePinner::new(vec![[0x01u8; 32]]);
        assert_eq!(pinner.len(), 1);
        assert!(!pinner.is_empty());
    }
}
