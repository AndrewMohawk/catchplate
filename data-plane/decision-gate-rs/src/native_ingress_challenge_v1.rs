//! Fixed native outer-TLS session challenge recipe, not session admission.
//!
//! The actual TLS owner must export exactly 32 bytes with EXPORTER_LABEL and
//! the raw caller challenge as exporter context. Merely passing two arrays to
//! this helper does not establish exporter provenance, a live connection,
//! caller identity, freshness, nonce reservation or permission for an action.

use sha2::{Digest as _, Sha256};

pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-Catchplate-Native-Ingress-v1";
pub const CHALLENGE_HEADER: &str = "x-catchplate-ingress-challenge";

const NONCE_DOMAIN: &[u8] = b"catchplate/native-ingress-session-challenge/v1\0";

/// SHA256(fixed domain || caller challenge[32] || actual TLS exporter[32]).
/// Fixed array lengths make this preimage unambiguous without length prefixes.
/// The header's canonical unpadded base64url is an HTTP-owner responsibility;
/// neither encoded text nor a digest of that text belongs in this recipe.
pub fn derive_nonce(challenge: [u8; 32], exporter: [u8; 32]) -> Result<[u8; 32], String> {
    if challenge.iter().all(|byte| *byte == 0) || exporter.iter().all(|byte| *byte == 0) {
        return Err("native ingress challenge and exporter must be nonzero".to_owned());
    }
    let mut hash = Sha256::new();
    hash.update(NONCE_DOMAIN);
    hash.update(challenge);
    hash.update(exporter);
    Ok(hash.finalize().into())
}
