//! The server keys the core checks sender certificates against.
//!
//! The core opens a receiving session only from a certificate a server key vouches for, and
//! holds the keys in memory: the platform hands them over at every launch
//! (`Orchestrator::set_trusted_server_keys`, `admit_server_delegations`). Until it has, every
//! first message waits (`awaiting_server_key`).
//!
//! - The Ed25519 certificate-signing key is pinned in this build, as iOS pins it
//!   (`VEILConfig.pinnedBundleSigningKeys`). It is the key the server publishes as
//!   `bundle_verification_key`; taking it from the server instead would make the server the
//!   anchor (decisions/server-keys-rooted-offline-and-hybrid.md, rejected variant A).
//! - Delegations of the hybrid keys come from `GetServerTrust`; the core keeps only those a root
//!   pinned in the core signed, so fetching them unverified is safe.

use base64::Engine;

/// Ed25519 public keys that sign sender certificates, base64.
const PINNED_CERTIFICATE_KEYS: &[&str] = &["kDGyaafEFExKTdB7MJXl4xYf0pFnxEg7bZJh7BDP9LI="];

pub fn pinned_certificate_keys() -> Vec<Vec<u8>> {
    PINNED_CERTIFICATE_KEYS
        .iter()
        .map(|k| {
            base64::engine::general_purpose::STANDARD
                .decode(k)
                .expect("pinned key is valid base64")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pinned_key_is_a_32_byte_ed25519_key() {
        let keys = pinned_certificate_keys();
        assert!(!keys.is_empty());
        for key in keys {
            assert_eq!(key.len(), 32);
            ed25519_dalek::VerifyingKey::from_bytes(&key.try_into().unwrap())
                .expect("a valid Ed25519 point");
        }
    }
}
