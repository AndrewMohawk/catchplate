//! One-use in-process X25519 recipient for the existing credential-lease KDF.
//!
//! Only the public key can be borrowed. Deriving the raw shared key consumes
//! this owner; callers retain their existing authenticated envelope and KDF
//! rules. PID checks reject use after fork, but are not enclave isolation,
//! attestation, parent-host confidentiality or KMS RSA/Recipient/CMS support.

use ring::rand::{SecureRandom, SystemRandom};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// No private-key export, Clone, Debug, serialization or caller-key constructor.
pub struct CredentialRecipientV1 {
    secret: StaticSecret,
    creator_pid: libc::pid_t,
}

impl CredentialRecipientV1 {
    pub fn generate() -> Result<Self, String> {
        let creator_pid = unsafe { libc::getpid() };
        if creator_pid <= 0 {
            return Err("credential recipient lacks a valid creator process".to_string());
        }
        // Zeroizing owns the temporary even when the entropy operation fails.
        let mut original = Zeroizing::new([0u8; 32]);
        SystemRandom::new().fill(original.as_mut())
            .map_err(|_| "generate credential recipient key failed".to_string())?;
        let secret = StaticSecret::from(*original);
        original.zeroize();
        let held = Self { secret, creator_pid };
        held.require_creator()?;
        Ok(held)
    }

    fn require_creator(&self) -> Result<(), String> {
        if unsafe { libc::getpid() } != self.creator_pid {
            return Err("credential recipient crossed its creator process".to_string());
        }
        Ok(())
    }

    pub fn public_key_bytes(&self) -> Result<[u8; 32], String> {
        self.require_creator()?;
        let public = PublicKey::from(&self.secret).to_bytes();
        self.require_creator()?;
        Ok(public)
    }

    /// Consume the recipient once. This is the raw X25519 result, NOT an AEAD
    /// key: the caller must apply the unchanged lease nonce/scope-bound KDF.
    pub fn derive_shared_key(self, peer: [u8; 32]) -> Result<Zeroizing<[u8; 32]>, String> {
        self.require_creator()?;
        let shared = self.secret.diffie_hellman(&PublicKey::from(peer));
        // Preserve the existing Dalek contributory check and explicitly deny
        // the all-zero output before any shared key reaches the caller's KDF.
        if !shared.was_contributory()
            || shared.as_bytes().iter().fold(0u8, |bits, byte| bits | byte) == 0 {
            return Err("credential recipient peer key is non-contributory".to_string());
        }
        let shared = Zeroizing::new(shared.to_bytes());
        self.require_creator()?;
        Ok(shared)
    }
}
