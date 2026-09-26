//! Generated response-proof key custody, not authorization or verified Nitro evidence.
//!
//! Only the existing custody runtime may call the crate-private signing seam,
//! after its actual authorization and durable attempt-ledger gates. Public
//! originals and declared scope do not prove hardware, freshness, admission,
//! rollback resistance or an independently observed response. No key import,
//! private-key export, Clone, Debug or public arbitrary-message signer exists.

use super::{live, EnclaveRuntimeIdentityV1, RuntimeKeyQuoteV1, RESPONSE_PROOF};
use ed25519_dalek::{Signer, SigningKey};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

// Match the existing custody request-frame ceiling; this is only a local work
// bound, not a replacement for its closed statement and authorization checks.
const MAX_RESPONSE_PROOF_STATEMENT_BYTES: usize = 256 * 1024;

struct HeldResponseProofKeyV1 {
    signing_key: SigningKey,
    owner_pid: libc::pid_t,
    deadline: u64,
    poisoned: bool,
}

impl HeldResponseProofKeyV1 {
    fn begin(&mut self, deadline: u64) -> Result<u64, String> {
        if std::mem::replace(&mut self.poisoned, true) {
            return Err("native response-proof key is poisoned".to_owned());
        }
        let deadline = deadline.min(self.deadline);
        live(deadline)?;
        if self.owner_pid <= 0 || unsafe { libc::getpid() } != self.owner_pid {
            return Err("native response-proof key crossed its creating process".to_owned());
        }
        Ok(deadline)
    }

    fn finish(&mut self, deadline: u64) -> Result<(), String> {
        live(deadline)?;
        if unsafe { libc::getpid() } != self.owner_pid {
            return Err("native response-proof key crossed its creating process".to_owned());
        }
        self.poisoned = false;
        Ok(())
    }

    fn public_key_bytes(&mut self) -> Result<[u8; 32], String> {
        let deadline = self.begin(self.deadline)?;
        let public_key = self.signing_key.verifying_key().to_bytes();
        self.finish(deadline)?;
        Ok(public_key)
    }
}

/// Unquoted generated Ed25519 key, retained while custody constructs the exact
/// boot/key/control-plane commitment. Only its creating CA owner may quote it.
pub struct PendingResponseProofKeyV1 {
    key: HeldResponseProofKeyV1,
    owner_ca_sha256: [u8; 32],
}

impl PendingResponseProofKeyV1 {
    pub fn public_key_bytes(&mut self) -> Result<[u8; 32], String> {
        self.key.public_key_bytes()
    }
}

/// Actual generated key and original NSM response naming that key. Mutating
/// operations require exclusive access; a shared custody runtime must retain
/// this owner under its mutex. Failed operations permanently poison the key.
pub struct QuotedResponseProofKeyV1 {
    key: HeldResponseProofKeyV1,
    quote: RuntimeKeyQuoteV1,
    owner_ca_sha256: [u8; 32],
    policy: [u8; 32],
    request_binding: [u8; 32],
}

impl QuotedResponseProofKeyV1 {
    /// Public originals only: inspection, including after expiry, grants no use.
    pub fn quote(&self) -> &RuntimeKeyQuoteV1 { &self.quote }

    pub fn public_key_bytes(&mut self) -> Result<[u8; 32], String> {
        self.key.public_key_bytes()
    }

    pub fn deadline(&self) -> u64 { self.key.deadline }

    pub fn verify_live(&mut self, deadline: u64) -> Result<(), String> {
        let deadline = self.key.begin(deadline)?;
        self.key.finish(deadline)
    }

    /// Permanently narrow local key custody; the original quote is not rewritten.
    pub fn restrict_deadline(&mut self, deadline: u64) -> Result<(), String> {
        let deadline = self.key.begin(deadline)?;
        self.key.deadline = deadline;
        self.key.finish(deadline)
    }

    pub fn verify_policy_commitment(&mut self, policy: [u8; 32], deadline: u64)
        -> Result<(), String> {
        let deadline = self.key.begin(deadline)?;
        if policy != self.policy {
            return Err("native response-proof policy differs from runtime scope".to_owned());
        }
        self.key.finish(deadline)
    }

    /// Rejoin the actual CA and all original role-4 scope bytes, then retain the
    /// minimum owner/identity/caller deadline. This is not quote verification.
    pub fn verify_identity(&mut self, identity: &mut EnclaveRuntimeIdentityV1,
        deadline: u64) -> Result<(), String> {
        let deadline = self.key.begin(deadline.min(identity.deadline()))?;
        self.key.deadline = deadline;
        let deadline = identity.begin(deadline)?;
        let actual_ca: [u8; 32] = Sha256::digest(identity.authority.certificate_der()).into();
        let public_key = self.key.signing_key.verifying_key().to_bytes();
        if self.owner_ca_sha256 != actual_ca || self.policy != identity.scope.policy
            || self.quote.public_key() != public_key.as_slice()
            || self.quote.user_data() != identity.binding(RESPONSE_PROOF, &public_key,
                self.request_binding).as_slice() {
            return Err("native response-proof key belongs to another runtime identity".to_owned());
        }
        identity.finish(deadline)?;
        self.key.finish(deadline)
    }

    /// Exact authorized canonical statement bytes only. No domain, message or
    /// policy is inferred here: the sole custody caller owns those real gates.
    pub(crate) fn sign(&mut self, statement: &[u8], deadline: u64)
        -> Result<[u8; 64], String> {
        let deadline = self.key.begin(deadline)?;
        if statement.is_empty() || statement.len() > MAX_RESPONSE_PROOF_STATEMENT_BYTES {
            return Err("native response-proof statement exceeds its fixed bound".to_owned());
        }
        let signature = self.key.signing_key.sign(statement).to_bytes();
        self.key.finish(deadline)?;
        Ok(signature)
    }
}

impl EnclaveRuntimeIdentityV1 {
    pub fn prepare_response_proof_key(&mut self, deadline: u64)
        -> Result<PendingResponseProofKeyV1, String> {
        let deadline = self.begin(deadline)?;
        let mut seed = Zeroizing::new([0u8; 32]);
        SystemRandom::new().fill(seed.as_mut())
            .map_err(|_| "generate native response-proof key failed".to_owned())?;
        let signing_key = SigningKey::from_bytes(&seed);
        seed.zeroize();
        let owner_ca_sha256 = Sha256::digest(self.authority.certificate_der()).into();
        let mut key = HeldResponseProofKeyV1 {
            signing_key, owner_pid: self.owner_pid, deadline, poisoned: false,
        };
        key.public_key_bytes()?;
        self.finish(deadline)?;
        Ok(PendingResponseProofKeyV1 { key, owner_ca_sha256 })
    }

    pub fn quote_response_proof_key(&mut self, mut pending: PendingResponseProofKeyV1,
        request_binding: [u8; 32], nonce: [u8; 32], deadline: u64)
        -> Result<QuotedResponseProofKeyV1, String> {
        let deadline = self.begin(deadline.min(pending.key.deadline))?;
        let deadline = pending.key.begin(deadline)?;
        if request_binding == [0; 32] {
            return Err("native response-proof key requires an original custody commitment".to_owned());
        }
        let actual_ca: [u8; 32] = Sha256::digest(self.authority.certificate_der()).into();
        if pending.owner_ca_sha256 != actual_ca {
            return Err("native response-proof key belongs to another runtime identity".to_owned());
        }
        let public_key = pending.key.signing_key.verifying_key().to_bytes().to_vec();
        let user_data = self.binding(RESPONSE_PROOF, &public_key, request_binding);
        let document = self.nsm.attest(&public_key, &nonce, &user_data, deadline)?;
        pending.key.deadline = deadline;
        pending.key.finish(deadline)?;
        self.finish(deadline)?;
        Ok(QuotedResponseProofKeyV1 {
            key: pending.key, owner_ca_sha256: actual_ca, policy: self.scope.policy,
            request_binding, quote: RuntimeKeyQuoteV1 { document, user_data, public_key, nonce },
        })
    }
}
