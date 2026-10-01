//! Acyclic cold-publication originals. These values are not owners or approval.
//! Only the separately admitted durable gates establish the initial state.
use super::*;
use super::ledger_spool_values::{sha, Stored};
use super::publication::RetrievalAuthority;
use super::spool_head_values::RoleKey;
use super::super::authority_history::{AuthorityEpochRefV3, HistoricalAuthorityRoleV3};
use crate::policy_shadow::{AuthorityRole, CanonicalEd25519Signature, PublicationReconciliationReceiptWire as Receipt,
    PublicationReconciliationState, PolicyShadowCustodySignerRole as Role, hash_domain_frames, signature_preimage};
use ed25519_dalek::Signer;

pub(super) const API: &str = "serverware.nativePublicationGenesis/v1";
pub(super) const PREPARED_DOMAIN: &str = "serverware.nativePublicationGenesisPreparation.signature/v1";
pub(super) const COMPLETION_DOMAIN: &str = "serverware.nativePublicationGenesisCompletion.signature/v1";
pub(super) const STORAGE_DOMAIN: &str = "serverware.nativePublicationGenesisStorage.signature/v1";
pub(super) const STORAGE_API: &str = "serverware.nativePublicationGenesisStorage/v1";
pub(super) const MAX_ORIGINAL: usize = 512 * 1024;
const GENESIS_DOMAIN: &[u8] = b"serverware.nativePublicationGenesisEvidence.signature/v1";
const WITNESS_DOMAIN: &[u8] = b"serverware.nativePublicationGenesisWitness.signature/v1";
pub(super) fn invalid() -> ServiceError { ServiceError::Invalid("cold publication original differs") }
pub(super) fn require(ok: bool) -> Result<(), ServiceError> { if ok { Ok(()) } else { Err(invalid()) } }
fn original<T: serde::de::DeserializeOwned + Serialize>(raw: &str) -> Result<T, ServiceError> {
    require(raw.is_ascii() && !raw.is_empty() && raw.len() <= MAX_ORIGINAL)?;
    decode_canonical_frame(raw.as_bytes())
}
fn text<T: Serialize>(value: &T) -> Result<String, ServiceError> {
    String::from_utf8(encode_canonical_frame(value)?).map_err(|_| invalid())
}

/// Independent pre-load scope: deliberately no policy generation, load,
/// driver-generation receipt, prior receipt, or future grant digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(super) struct Scope {
    pub(super) api_version: String,
    pub(super) commissioning_id_sha256: Sha256Digest,
    pub(super) production_configuration_binding_sha256: Sha256Digest,
    pub(super) assignment_payload_sha256: Sha256Digest,
    pub(super) assignment_revision: u64,
    pub(super) proof_scope_original: String,
    pub(super) retrieval_namespace_sha256: Sha256Digest,
    pub(super) initial_publication_revision: u64,
    pub(super) boot_id_base64url: String,
    pub(super) time_namespace_device: u64,
    pub(super) time_namespace_inode: u64,
    pub(super) issued_at_boottime_nanos: u64,
    pub(super) expires_at_boottime_nanos: u64,
}
impl Scope {
    pub(super) fn validate(&self) -> Result<(), ServiceError> {
        let boot = URL_SAFE_NO_PAD.decode(&self.boot_id_base64url).map_err(|_| invalid())?;
        require(self.api_version == "serverware.nativePublicationGenesisScope/v1"
            && self.commissioning_id_sha256 != Sha256Digest::compute(&[])
            && self.assignment_revision > 0 && self.initial_publication_revision > 0
            && boot.len() == 16 && boot.iter().any(|b| *b != 0) && URL_SAFE_NO_PAD.encode(&boot) == self.boot_id_base64url
            && self.time_namespace_inode > 0 && self.issued_at_boottime_nanos > 0
            && self.issued_at_boottime_nanos < self.expires_at_boottime_nanos
            && self.proof_scope_original.is_ascii() && !self.proof_scope_original.is_empty()
            && self.proof_scope_original.len() <= 16384)?;
        // Decode the existing closed proof-scope grammar, not arbitrary JSON.
        // Native admission additionally joins it to actual admitted keys.
        super::guest::native_keys::admission::publication::authority_payload(&self.proof_scope_original, b"[]")
            .map_err(|_| invalid())?;
        Ok(())
    }
    pub(super) fn live(&self, now: u64) -> Result<(), ServiceError> {
        self.validate()?;
        require(self.issued_at_boottime_nanos <= now && now < self.expires_at_boottime_nanos)
    }
    pub(super) fn guest(&self, guest: &guest::GuestClosureBinding) -> Result<(), ServiceError> {
        self.validate()?;
        require(self.boot_id_base64url == guest.boot_id_base64url
            && self.time_namespace_device == guest.time_namespace_device && self.time_namespace_inode == guest.time_namespace_inode
            && self.issued_at_boottime_nanos >= guest.issued_at_boottime_ns.parse::<u64>().map_err(|_| invalid())?
            && self.expires_at_boottime_nanos <= guest.lifetime_deadline_boottime_ns.parse::<u64>().map_err(|_| invalid())?)
    }
}

/// This is the *persisted definition* of initial policy-ledger/spool state.
/// Its roots are not supplied by a caller and are not directory observations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(super) struct InitialState {
    api_version: String, scope_sha256: Sha256Digest, publication_revision: u64,
    state: PublicationReconciliationState, ledger_event_ordinal: u64,
    predecessor_generation_sha256: Option<Sha256Digest>, committed_generation_sha256: Option<Sha256Digest>,
    published_generation_sha256: Option<Sha256Digest>, first_ingress_sequence: Option<u64>,
    last_ingress_sequence: Option<u64>, prepared_publication_sha256: Option<Sha256Digest>,
}
impl InitialState {
    pub(super) fn new(scope: &Scope) -> Result<Self, ServiceError> {
        scope.validate()?;
        Ok(Self { api_version: "serverware.nativePublicationInitialState/v1".into(), scope_sha256: sha(scope)?,
            publication_revision: scope.initial_publication_revision, state: PublicationReconciliationState::Uninstalled,
            ledger_event_ordinal: 0, predecessor_generation_sha256: None, committed_generation_sha256: None,
            published_generation_sha256: None, first_ingress_sequence: None, last_ingress_sequence: None,
            prepared_publication_sha256: None })
    }
    pub(super) fn original(scope: &Scope) -> Result<String, ServiceError> { text(&Self::new(scope)?) }
    pub(super) fn roots(&self) -> Result<(Sha256Digest, Sha256Digest), ServiceError> {
        let raw = encode_canonical_frame(self)?;
        Ok((hash_domain_frames(b"serverware.nativeInitialPolicyLedger/v1", &[&raw]),
            hash_domain_frames(b"serverware.nativeInitialPolicySpool/v1", &[&raw])))
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(super) struct GenesisEvidence {
    pub(super) api_version: String, pub(super) scope: Scope, pub(super) genesis_original: String,
    pub(super) grant_sha256: Sha256Digest, pub(super) authority_epoch: AuthorityEpochRefV3,
    pub(super) observed_at_boottime_nanos: u64, pub(super) signature_base64url: String,
}
impl GenesisEvidence {
    fn payload(&self) -> Result<Vec<u8>, ServiceError> { encode_canonical_frame(&(&self.api_version, &self.scope,
        &self.genesis_original, &self.grant_sha256, &self.authority_epoch, self.observed_at_boottime_nanos)) }
    pub(super) fn verify(&self, scope: &Scope, epoch: &AuthorityEpochRefV3, key: &VerifyingKey) -> Result<(), ServiceError> {
        scope.live(self.observed_at_boottime_nanos)?;
        require(self.api_version == API && &self.scope == scope && self.genesis_original == InitialState::original(scope)?
            && self.grant_sha256 != Sha256Digest::compute(&[])
            && self.authority_epoch == *epoch && epoch.authority_role == HistoricalAuthorityRoleV3::IsolatedService(
                HistoricalServiceRoleV3::DurableRecoveryStore))?;
        verify(epoch, key, GENESIS_DOMAIN, &self.payload()?, &self.signature_base64url)
    }
    pub(super) fn sign(scope: Scope, grant_sha256: Sha256Digest, epoch: AuthorityEpochRefV3, now: u64,
        key: &SigningKey) -> Result<Self, ServiceError> {
        let mut value = Self { api_version: API.into(), genesis_original: InitialState::original(&scope)?, scope,
            grant_sha256, authority_epoch: epoch, observed_at_boottime_nanos: now, signature_base64url: String::new() };
        value.signature_base64url = sign(key, GENESIS_DOMAIN, &value.payload()?)?;
        value.verify(&value.scope, &value.authority_epoch, &key.verifying_key())?;
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(super) struct Core {
    pub(super) api_version: String, pub(super) native_grant_sha256: Sha256Digest, pub(super) genesis: GenesisEvidence,
    pub(super) observed_at_unix_nanos: i64, pub(super) trust_checkpoint_sha256: Sha256Digest,
    pub(super) signing_key_id: Sha256Digest, pub(super) signing_key_spki_sha256: Sha256Digest,
}
impl Core {
    pub(super) fn new(scope: &Scope, genesis: GenesisEvidence, native: &RoleKey, now: i64, checkpoint: Sha256Digest)
        -> Result<Self, ServiceError> {
        let value = Self { api_version: "serverware.nativeInitialPublicationCore/v1".into(),
            native_grant_sha256: native.grant_sha256.clone(), genesis, observed_at_unix_nanos: now,
            trust_checkpoint_sha256: checkpoint, signing_key_id: native.key_id.clone(), signing_key_spki_sha256: native.key_spki_sha256.clone() };
        value.validate(scope, native)?; Ok(value)
    }
    pub(super) fn validate(&self, scope: &Scope, native: &RoleKey) -> Result<(), ServiceError> {
        scope.validate()?;
        require(self.api_version == "serverware.nativeInitialPublicationCore/v1" && native.role == AuthorityRole::CustodyPublicationReconciliation
            && self.native_grant_sha256 == native.grant_sha256 && self.genesis.scope == *scope
            && self.genesis.genesis_original == InitialState::original(scope)?
            && self.signing_key_id == native.key_id && self.signing_key_spki_sha256 == native.key_spki_sha256
            && self.observed_at_unix_nanos > 0 && self.trust_checkpoint_sha256 != Sha256Digest::compute(&[]))
    }
    pub(super) fn identity(&self) -> Result<Sha256Digest, ServiceError> {
        Ok(hash_domain_frames(b"serverware.nativeInitialPublicationCore/v1", &[&encode_canonical_frame(self)?]))
    }
    pub(super) fn retrieval_id(&self, namespace: &Sha256Digest) -> Result<Sha256Digest, ServiceError> {
        Ok(hash_domain_frames(b"serverware.nativeInitialPublicationRetrievalId/v1", &[namespace.as_str().as_bytes(), self.identity()?.as_str().as_bytes()]))
    }
    pub(super) fn retrieval_proof(&self, scope: &[u8], id: &Sha256Digest) -> Result<Sha256Digest, ServiceError> {
        Ok(hash_domain_frames(b"serverware.nativeInitialPublicationRetrievalProof/v1", &[scope, id.as_str().as_bytes(), &encode_canonical_frame(self)?]))
    }
    pub(super) fn payload(&self, stored: &Stored) -> Result<Vec<u8>, ServiceError> {
        let s = &self.genesis.scope; let (ledger, spool) = InitialState::new(s)?.roots()?;
        crate::policy_shadow::canonical_json_bytes(&serde_json::json!([PublicationReconciliationState::Uninstalled,
            s.initial_publication_revision, null, null, null, null, null, 0, ledger, spool, null,
            self.observed_at_unix_nanos, self.trust_checkpoint_sha256, sha(stored)?, stored.payload.retrieval_id_sha256,
            stored.payload.retrieval_proof_sha256, Role::PublicationReconciliation, self.signing_key_id, self.signing_key_spki_sha256]))
            .map_err(|_| invalid())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(super) struct Prepared { pub(super) core: Core, pub(super) prepared_at_boottime_nanos: u64, pub(super) signature: CanonicalEd25519Signature }
impl Prepared {
    pub(super) fn preimage(&self) -> Result<Vec<u8>, ServiceError> {
        Ok(signature_preimage(PREPARED_DOMAIN, &encode_canonical_frame(&(&self.core, self.prepared_at_boottime_nanos))?))
    }
    pub(super) fn verify(&self, scope: &Scope, native: &RoleKey, epoch: &AuthorityEpochRefV3, key: &VerifyingKey) -> Result<(), ServiceError> {
        self.core.validate(scope, native)?; self.core.genesis.verify(scope, epoch, key)?; scope.live(self.prepared_at_boottime_nanos)?;
        require(self.core.genesis.observed_at_boottime_nanos <= self.prepared_at_boottime_nanos)?;
        native.material()?.verify_strict(&self.preimage()?, &Signature::from_bytes(&self.signature.decode().map_err(|_| invalid())?)).map_err(|_| invalid())
    }
}
pub(super) fn stored_verify(stored: &Stored, prepared: &Prepared, scope: &Scope, retrieval: &RoleKey) -> Result<(), ServiceError> {
    require(retrieval.role == AuthorityRole::CustodyRetrievalResponse && stored.payload.grant_sha256 == retrieval.grant_sha256)?;
    stored_verify_key(stored, prepared, scope, &RetrievalAuthority { key_id: retrieval.key_id.clone(),
        key_spki_sha256: retrieval.key_spki_sha256.clone(), public_key_base64url: retrieval.public_key_base64url.clone() })
}
pub(super) fn stored_verify_assigned(stored: &Stored, prepared: &Prepared, scope: &Scope, retrieval: &RetrievalAuthority,
    guest: &guest::GuestClosureBinding) -> Result<(), ServiceError> {
    require(stored.payload.guest == *guest)?; stored_verify_key(stored, prepared, scope, retrieval)
}
fn stored_verify_key(stored: &Stored, prepared: &Prepared, scope: &Scope, retrieval: &RetrievalAuthority) -> Result<(), ServiceError> {
    let p = &stored.payload; let core = &prepared.core; scope.guest(&p.guest)?;
    require(p.api_version == STORAGE_API && p.grant_sha256 != Sha256Digest::compute(&[])
        && p.signing_key_id == retrieval.key_id && p.signing_key_spki_sha256 == retrieval.key_spki_sha256
        && p.core_sha256 == core.identity()? && p.object_sha256 == sha(core)? && p.fsverity_sha256 != Sha256Digest::compute(&[])
        && p.sequence == 1 && p.previous_head_sha256 != Sha256Digest::compute(&[])
        && p.retrieval_id_sha256 == core.retrieval_id(&scope.retrieval_namespace_sha256)?
        && p.retrieval_proof_sha256 == core.retrieval_proof(scope.proof_scope_original.as_bytes(), &p.retrieval_id_sha256)?
        && prepared.prepared_at_boottime_nanos <= p.stored_at_boottime_nanos
        && p.stored_at_boottime_nanos < p.original_deadline_boottime_nanos
        && p.original_deadline_boottime_nanos == scope.expires_at_boottime_nanos)?;
    retrieval.material()?.verify_strict(&signature_preimage(STORAGE_DOMAIN, &encode_canonical_frame(p)?),
        &Signature::from_bytes(&stored.signature.decode().map_err(|_| invalid())?)).map_err(|_| invalid())
}
pub(super) fn final_receipt(core: &Core, stored: &Stored, sign: impl FnOnce(&[u8]) -> Result<String, ServiceError>) -> Result<String, ServiceError> {
    let payload = core.payload(stored)?; let signature = sign(&payload)?;
    let signed = hash_domain_frames(b"serverware.policyShadowPublicationReconciliationReceipt/v1", &[&payload, signature.as_bytes()]);
    let s = &core.genesis.scope; let (ledger, spool) = InitialState::new(s)?.roots()?;
    let receipt = Receipt::from_custody(PublicationReconciliationState::Uninstalled, s.initial_publication_revision,
        None, None, None, None, None, 0, ledger, spool, None, core.observed_at_unix_nanos, core.trust_checkpoint_sha256.clone(),
        sha(stored)?, stored.payload.retrieval_id_sha256.clone(), stored.payload.retrieval_proof_sha256.clone(),
        core.signing_key_id.clone(), core.signing_key_spki_sha256.clone(), signature, signed).map_err(|_| invalid())?;
    text(&receipt)
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(super) struct Completion {
    pub(super) api_version: String, pub(super) prepared: Prepared, pub(super) stored: Stored,
    pub(super) receipt_original: String, pub(super) completed_at_boottime_nanos: u64, pub(super) signature: CanonicalEd25519Signature,
}
impl Completion {
    pub(super) fn payload(&self) -> Result<Vec<u8>, ServiceError> { encode_canonical_frame(&(&self.api_version, &self.prepared,
        &self.stored, &self.receipt_original, self.completed_at_boottime_nanos)) }
    pub(super) fn verify(&self, scope: &Scope, native: &RoleKey, retrieval: &RoleKey, epoch: &AuthorityEpochRefV3, key: &VerifyingKey)
        -> Result<(), ServiceError> {
        self.prepared.verify(scope, native, epoch, key)?; stored_verify(&self.stored, &self.prepared, scope, retrieval)?;
        self.verify_receipt(scope, native)
    }
    pub(super) fn verify_assigned(&self, scope: &Scope, native: &RoleKey, retrieval: &RetrievalAuthority, guest: &guest::GuestClosureBinding,
        epoch: &AuthorityEpochRefV3, key: &VerifyingKey) -> Result<(), ServiceError> {
        self.prepared.verify(scope, native, epoch, key)?; stored_verify_assigned(&self.stored, &self.prepared, scope, retrieval, guest)?;
        self.verify_receipt(scope, native)
    }
    fn verify_receipt(&self, scope: &Scope, native: &RoleKey) -> Result<(), ServiceError> {
        scope.live(self.completed_at_boottime_nanos)?;
        require(self.api_version == "serverware.nativePublicationGenesisCompletion/v1"
            && self.stored.payload.stored_at_boottime_nanos <= self.completed_at_boottime_nanos)?;
        let receipt: Receipt = original(&self.receipt_original)?;
        receipt.validate_deserialized_invariants().map_err(|_| invalid())?;
        let payload = receipt.canonical_payload().map_err(|_| invalid())?;
        require(payload == self.prepared.core.payload(&self.stored)?)?;
        let authority = super::guest::native_keys::admission::publication::authority_payload(&scope.proof_scope_original, &payload).map_err(|_| invalid())?;
        let key = native.material()?;
        key.verify_strict(&signature_preimage(Role::PublicationReconciliation.signature_domain(), &authority),
            &Signature::from_bytes(&receipt.signature.decode().map_err(|_| invalid())?)).map_err(|_| invalid())?;
        key.verify_strict(&signature_preimage(COMPLETION_DOMAIN, &self.payload()?),
            &Signature::from_bytes(&self.signature.decode().map_err(|_| invalid())?)).map_err(|_| invalid())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(super) struct Witness {
    pub(super) api_version: String, pub(super) scope_sha256: Sha256Digest, pub(super) commissioning_id_sha256: Sha256Digest,
    pub(super) completion_sha256: Sha256Digest, pub(super) predecessor_evidence_sha256: Sha256Digest,
    pub(super) grant_sha256: Sha256Digest, pub(super) authority_epoch: AuthorityEpochRefV3,
    pub(super) completed_at_boottime_nanos: u64, pub(super) signature_base64url: String,
}
impl Witness {
    fn payload(&self) -> Result<Vec<u8>, ServiceError> { encode_canonical_frame(&(&self.api_version, &self.scope_sha256,
        &self.commissioning_id_sha256, &self.completion_sha256, &self.predecessor_evidence_sha256, &self.grant_sha256,
        &self.authority_epoch, self.completed_at_boottime_nanos)) }
    pub(super) fn verify(&self, scope: &Scope, completion: &Completion, predecessor: &Sha256Digest,
        epoch: &AuthorityEpochRefV3, key: &VerifyingKey) -> Result<(), ServiceError> {
        scope.live(self.completed_at_boottime_nanos)?;
        require(self.api_version == "serverware.nativePublicationGenesisWitness/v1" && self.scope_sha256 == sha(scope)?
            && self.commissioning_id_sha256 == scope.commissioning_id_sha256 && self.completion_sha256 == sha(completion)?
            && &self.predecessor_evidence_sha256 == predecessor && self.authority_epoch == *epoch
            && self.grant_sha256 != Sha256Digest::compute(&[]) && completion.completed_at_boottime_nanos <= self.completed_at_boottime_nanos)?;
        verify(epoch, key, WITNESS_DOMAIN, &self.payload()?, &self.signature_base64url)
    }
    pub(super) fn sign(scope: &Scope, completion: &Completion, predecessor: Sha256Digest, grant_sha256: Sha256Digest,
        epoch: AuthorityEpochRefV3, now: u64, key: &SigningKey) -> Result<Self, ServiceError> {
        let mut value = Self { api_version: "serverware.nativePublicationGenesisWitness/v1".into(), scope_sha256: sha(scope)?,
            commissioning_id_sha256: scope.commissioning_id_sha256.clone(), completion_sha256: sha(completion)?,
            predecessor_evidence_sha256: predecessor, grant_sha256, authority_epoch: epoch,
            completed_at_boottime_nanos: now, signature_base64url: String::new() };
        value.signature_base64url = sign(key, WITNESS_DOMAIN, &value.payload()?)?;
        value.verify(scope, completion, &value.predecessor_evidence_sha256, &value.authority_epoch, &key.verifying_key())?; Ok(value)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(super) struct Bundle { pub(super) completion: Completion, pub(super) durable: Witness, pub(super) current: Witness }
impl Bundle {
    pub(super) fn verify(&self, scope: &Scope, native: &RoleKey, retrieval: &RoleKey,
        durable_epoch: &AuthorityEpochRefV3, durable_key: &VerifyingKey, current_epoch: &AuthorityEpochRefV3, current_key: &VerifyingKey)
        -> Result<(), ServiceError> {
        require(durable_epoch.authority_role == HistoricalAuthorityRoleV3::IsolatedService(HistoricalServiceRoleV3::DurableRecoveryStore)
            && current_epoch.authority_role == HistoricalAuthorityRoleV3::IsolatedService(HistoricalServiceRoleV3::CurrentSignatureAuthority)
            && durable_key != current_key)?;
        self.completion.verify(scope, native, retrieval, durable_epoch, durable_key)?;
        self.durable.verify(scope, &self.completion, &sha(&self.completion.prepared.core.genesis)?, durable_epoch, durable_key)?;
        self.current.verify(scope, &self.completion, &sha(&self.durable)?, current_epoch, current_key)?;
        require(self.current.completed_at_boottime_nanos >= self.durable.completed_at_boottime_nanos)
    }
}
fn verify(epoch: &AuthorityEpochRefV3, key: &VerifyingKey, domain: &[u8], payload: &[u8], signature: &str) -> Result<(), ServiceError> {
    require(verifying_key_spki_sha256(key).map_err(|_| invalid())? == epoch.service_signing_key_spki_sha256)?;
    let raw = URL_SAFE_NO_PAD.decode(signature).map_err(|_| invalid())?;
    require(raw.len() == 64 && URL_SAFE_NO_PAD.encode(&raw) == signature)?;
    key.verify_strict(&super::super::protocol::domain_separated_signature_preimage(domain, payload)?,
        &Signature::from_slice(&raw).map_err(|_| invalid())?).map_err(|_| invalid())
}
fn sign(key: &SigningKey, domain: &[u8], payload: &[u8]) -> Result<String, ServiceError> {
    Ok(URL_SAFE_NO_PAD.encode(key.sign(&super::super::protocol::domain_separated_signature_preimage(domain, payload)?).to_bytes()))
}

#[cfg(test)]
#[path="publication_genesis_tests.rs"]
mod tests;
