//! Independently approved, generation-independent cold-to-operational mapping.
//! These signed originals are not an owner or a durable adoption record. Each
//! actual consumer must join its current authority and retained runtime; DRS
//! and CSA separately persist the one-use mapping before operational access.
use super::*;
use super::ledger_spool_values::{sha, Scope};
use super::publication::{RetrievalAuthority, authority_payload_for_adoption};
use super::publication_genesis::{self as cold, invalid, require};
use super::publication_genesis_client::{Configuration, Handoff};
use super::publication_genesis_service::Grant;
use super::spool_head_values::RoleKey;
use super::super::authority_history::{AuthorityEpochRefV3, HistoricalAuthorityRoleV3};
use crate::policy_shadow::{AtomicTrustCheckpoint, AuthorityRole, CanonicalEd25519Signature,
    PublicationReconciliationReceiptWire as Receipt, ShadowError, MAX_ENVELOPE_AGE_NANOS,
    ed25519_public_key_material_sha256, signature_preimage};

pub(in crate::policy_shadow) const MAX_AUTHORIZATION: usize = 2 * 1024 * 1024;
const DOMAIN: &str = "serverware.nativePublicationAdoptionAuthorization.signature/v1";
const BOOTSTRAP_DOMAIN: &str = "serverware.nativePublicationAdoptionAuthorization.signature/v2";
const API: &str = "serverware.nativePublicationAdoptionAuthorization/v1";
const BOOTSTRAP_API: &str = "serverware.nativePublicationAdoptionAuthorization/v2";
fn profile(api: &str) -> Result<(bool, &'static str), ServiceError> {
    match api {
        API => Ok((false, DOMAIN)),
        BOOTSTRAP_API => Ok((true, BOOTSTRAP_DOMAIN)),
        _ => Err(invalid()),
    }
}

#[cfg(test)]
mod profile_tests {
    use super::*;

    #[test]
    fn bootstrap_adoption_is_an_explicit_separate_signature_domain() {
        assert_eq!(profile(API).unwrap(), (false, DOMAIN));
        assert_eq!(profile(BOOTSTRAP_API).unwrap(), (true, BOOTSTRAP_DOMAIN));
        assert_ne!(DOMAIN, BOOTSTRAP_DOMAIN);
        for api in ["", "serverware.nativePublicationAdoptionAuthorization/v3", DOMAIN] {
            assert!(profile(api).is_err());
        }
        let key = SigningKey::from_bytes(&[71; 32]);
        let original = b"same payload bytes";
        let signature = key.sign(&signature_preimage(DOMAIN, original));
        assert!(key.verifying_key().verify_strict(&signature_preimage(DOMAIN, original), &signature).is_ok());
        assert!(key.verifying_key().verify_strict(&signature_preimage(BOOTSTRAP_DOMAIN, original), &signature).is_err());
    }
}
fn shadow(_: impl std::fmt::Display) -> ShadowError { ShadowError::BindingDrift }
#[path="publication_adoption_validator.rs"]
pub(in crate::policy_shadow) mod validator;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct TargetHistory {
    service_role: TrustedHostServiceRoleV3,
    history_manifest_sha256: Sha256Digest,
    root_key_spki_sha256: Sha256Digest,
    root_public_key_base64url: String,
    authority_epoch: AuthorityEpochRefV3,
    public_key_base64url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
struct Payload {
    api_version: String,
    purpose: String,
    adoption_id_sha256: Sha256Digest,
    cold_configuration_original: String,
    cold_bundle_original: String,
    cold_native_grant_original: String,
    cold_retrieval_grant_original: String,
    prior_supervisor: RetrievalAuthority,
    assignment_payload_sha256: Sha256Digest,
    assignment_revision: u64,
    production_configuration_binding_sha256: Sha256Digest,
    proof_scope_original: String,
    retrieval_namespace_sha256: Sha256Digest,
    native: RetrievalAuthority,
    retrieval: RetrievalAuthority,
    target_histories: Vec<TargetHistory>,
    authority: RetrievalAuthority,
    trust_checkpoint_id: Sha256Digest,
    revocation_generation: u64,
    revocation_root_sha256: Sha256Digest,
    issued_at_unix_nanos: i64,
    expires_at_unix_nanos: i64,
    issued_at_boottime_nanos: u64,
    expires_at_boottime_nanos: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all="camelCase", deny_unknown_fields)]
pub(in crate::policy_shadow) struct Authorization {
    payload: Payload,
    signature: CanonicalEd25519Signature,
}

impl TargetHistory {
    fn keys(&self) -> Result<(VerifyingKey, VerifyingKey), ServiceError> {
        let root_bytes = URL_SAFE_NO_PAD.decode(&self.root_public_key_base64url).map_err(|_| invalid())?;
        require(root_bytes.len() == 32 && URL_SAFE_NO_PAD.encode(&root_bytes) == self.root_public_key_base64url)?;
        let root = VerifyingKey::from_bytes(&<[u8;32]>::try_from(root_bytes.as_slice()).map_err(|_| invalid())?)
            .map_err(|_| invalid())?;
        require(verifying_key_spki_sha256(&root).map_err(|_| invalid())? == self.root_key_spki_sha256
            && self.history_manifest_sha256 != Sha256Digest::compute(&[]))?;
        let role = match self.service_role {
            TrustedHostServiceRoleV3::DurableRecoveryStore => HistoricalServiceRoleV3::DurableRecoveryStore,
            TrustedHostServiceRoleV3::CurrentSignatureAuthority => HistoricalServiceRoleV3::CurrentSignatureAuthority,
            _ => return Err(invalid()),
        };
        require(self.authority_epoch.authority_role == HistoricalAuthorityRoleV3::IsolatedService(role))?;
        let key = super::publication_genesis_service::epoch_key(&self.authority_epoch, &self.public_key_base64url)?;
        require(root != key)?;
        Ok((root, key))
    }
}

impl Payload {
    // Shared unsigned semantics. The producer reaches this before signing;
    // consumers additionally verify the real authorization signature below.
    fn verified_cold(&self) -> Result<(Configuration, cold::Bundle), ServiceError> {
        let p = self;
        let (bootstrap, _) = profile(&p.api_version)?;
        // Exact canonical envelope overhead, including an 86-byte Ed25519
        // signature encoding. No provisional or fabricated signature exists.
        const ENVELOPE_OVERHEAD:usize=b"{\"payload\":,\"signature\":\"\"}".len()+86;
        require(encode_canonical_frame(self)?.len() <= MAX_AUTHORIZATION-ENVELOPE_OVERHEAD
            && p.purpose == "cold-publication-to-operational"
            && p.adoption_id_sha256 != Sha256Digest::compute(&[])
            && p.assignment_revision > 0 && p.revocation_generation > 0
            && p.issued_at_unix_nanos > 0 && p.issued_at_unix_nanos < p.expires_at_unix_nanos
            && p.issued_at_boottime_nanos > 0 && p.issued_at_boottime_nanos < p.expires_at_boottime_nanos
            && p.target_histories.len() == 2
            && p.target_histories.iter().map(|v| v.service_role).collect::<BTreeSet<_>>() == BTreeSet::from([
                TrustedHostServiceRoleV3::DurableRecoveryStore, TrustedHostServiceRoleV3::CurrentSignatureAuthority]))?;
        for raw in [&p.cold_configuration_original, &p.cold_bundle_original,
            &p.cold_native_grant_original, &p.cold_retrieval_grant_original] {
            require(!raw.is_empty() && raw.is_ascii() && raw.len() <= MAX_AUTHORIZATION)?;
        }
        let authority = p.authority.material()?;
        let configuration: Configuration = decode_canonical_frame(p.cold_configuration_original.as_bytes())?;
        // Explicit signed successor, never silently reinterpret v1 evidence.
        configuration.validate_selected(bootstrap).map_err(|_| invalid())?;
        let handoff = Handoff {
            api_version: "serverware.nativePublicationGenesisHandoff/v1".into(),
            commissioning_id_sha256: configuration.scope.commissioning_id_sha256.clone(),
            scope_sha256: sha(&configuration.scope)?, bundle_original: p.cold_bundle_original.clone(),
            bundle_sha256: Sha256Digest::compute(p.cold_bundle_original.as_bytes()),
        };
        let (original, _) = super::publication_genesis_handoff::admit(&encode_canonical_frame(&handoff)?, &configuration)
            .map_err(|_| invalid())?;
        require(original == p.cold_bundle_original.as_bytes())?;
        let bundle: cold::Bundle = decode_canonical_frame(&original)?;
        let scope = &configuration.scope;
        require(scope.issued_at_boottime_nanos <= p.issued_at_boottime_nanos
            && bundle.current.completed_at_boottime_nanos <= p.issued_at_boottime_nanos
            && p.expires_at_boottime_nanos <= scope.expires_at_boottime_nanos)?;
        let now = boottime_now_nanos().map_err(|_| invalid())?;
        require(p.issued_at_boottime_nanos <= now && now < p.expires_at_boottime_nanos)?;
        let durable: Grant = decode_canonical_frame(configuration.durable_grant_original.as_bytes())?;
        let prior = p.prior_supervisor.material()?;
        require(prior != durable.payload.native.material()? && prior != durable.payload.retrieval.material()?)?;
        let checkpoint = &bundle.completion.prepared.core.trust_checkpoint_sha256;
        let (native_start, native_end, native_revocation, native_root) = super::guest::native_keys::admission::publication::genesis::Configuration::verify_adoption_original(
            &p.cold_native_grant_original, &durable.payload.native.grant_sha256, scope, &p.prior_supervisor, checkpoint)
            .map_err(|_| invalid())?;
        let (retrieval_start, retrieval_end, retrieval_revocation, retrieval_root) = super::guest::native_keys::admission::ledger_retrieval::genesis::Configuration::verify_adoption_original(
            &p.cold_retrieval_grant_original, &durable.payload.retrieval.grant_sha256, scope, &p.prior_supervisor, checkpoint)
            .map_err(|_| invalid())?;
        let receipt: Receipt = decode_canonical_frame(bundle.completion.receipt_original.as_bytes())?;
        require(native_revocation == retrieval_revocation && native_root == retrieval_root
            && native_start <= p.issued_at_unix_nanos && retrieval_start <= p.issued_at_unix_nanos
            && p.expires_at_unix_nanos <= native_end && p.expires_at_unix_nanos <= retrieval_end
            && receipt.trusted_observed_at_unix_nanos <= p.issued_at_unix_nanos
            && p.expires_at_unix_nanos.checked_sub(receipt.trusted_observed_at_unix_nanos)
                .is_some_and(|age| age <= MAX_ENVELOPE_AGE_NANOS))?;
        authority_payload_for_adoption(&p.proof_scope_original, b"[]")?;
        let proof: serde_json::Value = decode_canonical_frame(p.proof_scope_original.as_bytes())?;
        require(proof.get("assignment_payload_sha256") == Some(&serde_json::to_value(&p.assignment_payload_sha256).map_err(|_| invalid())?)
            && proof.get("assignment_revision").and_then(serde_json::Value::as_u64) == Some(p.assignment_revision)
            && proof.get("production_configuration_binding_sha256") == Some(&serde_json::to_value(&p.production_configuration_binding_sha256).map_err(|_| invalid())?)
            && proof.get("retrieval_namespace_sha256") == Some(&serde_json::to_value(&p.retrieval_namespace_sha256).map_err(|_| invalid())?))?;
        let native = p.native.material()?;
        let retrieval = p.retrieval.material()?;
        let retrieval_proof = proof.get("retrieval_response_authority").ok_or_else(invalid)?;
        require(retrieval_proof.get("key_id") == Some(&serde_json::to_value(&p.retrieval.key_id).map_err(|_| invalid())?)
            && retrieval_proof.get("key_spki_sha256") == Some(&serde_json::to_value(&p.retrieval.key_spki_sha256).map_err(|_| invalid())?)
            && retrieval_proof.get("key_material_sha256") == Some(&serde_json::to_value(ed25519_public_key_material_sha256(&retrieval)).map_err(|_| invalid())?))?;
        let mut keys = vec![authority, native, retrieval];
        for target in &p.target_histories { let (root, key) = target.keys()?; keys.push(root); keys.push(key); }
        require(keys.iter().enumerate().all(|(i, key)| keys.iter().skip(i + 1).all(|other| key != other)))?;
        Ok((configuration, bundle))
    }
}
impl Authorization {
    // Key provenance comes from require_authority(actual current assignment)
    // or the independently root-signed grant carrying this exact authorization.
    fn verified_cold(&self)->Result<(Configuration,cold::Bundle),ServiceError>{
        require(encode_canonical_frame(self)?.len()<=MAX_AUTHORIZATION)?;
        let (_, domain) = profile(&self.payload.api_version)?;
        self.payload.authority.material()?.verify_strict(&signature_preimage(domain,&encode_canonical_frame(&self.payload)?),
            &Signature::from_bytes(&self.signature.decode().map_err(|_|invalid())?)).map_err(|_|invalid())?;
        self.payload.verified_cold()
    }
    pub(super) fn validate(&self) -> Result<(), ServiceError> { self.verified_cold().map(|_| ()) }
    pub(super) fn identity(&self) -> Result<Sha256Digest, ServiceError> { self.validate()?; sha(self) }
    pub(super) fn deadline(&self) -> Result<u64, ServiceError> { self.validate()?; Ok(self.payload.expires_at_boottime_nanos) }
    pub(super) fn cold_bundle(&self) -> Result<cold::Bundle, ServiceError> { self.verified_cold().map(|v| v.1) }
    pub(super) fn cold_scope(&self) -> Result<cold::Scope, ServiceError> { self.verified_cold().map(|v| v.0.scope) }
    pub(super) fn receipt(&self) -> Result<Receipt, ServiceError> {
        decode_canonical_frame(self.cold_bundle()?.completion.receipt_original.as_bytes())
    }
    pub(super) fn require_admission(&self, scope: &Scope, proof: &str, native: &RoleKey) -> Result<(), ServiceError> {
        self.validate()?;
        let p = &self.payload;
        require(scope.assignment_payload_sha256 == p.assignment_payload_sha256 && scope.assignment_revision == p.assignment_revision
            && scope.production_configuration_binding_sha256 == p.production_configuration_binding_sha256
            && scope.retrieval_namespace_sha256 == p.retrieval_namespace_sha256 && proof == p.proof_scope_original
            && scope.proof_scope_sha256 == Sha256Digest::compute(proof.as_bytes())
            && p.issued_at_boottime_nanos <= scope.issued_at_boottime_nanos
            && scope.expires_at_boottime_nanos <= p.expires_at_boottime_nanos
            && native.role == AuthorityRole::CustodyPublicationReconciliation && native.key_id == p.native.key_id
            && native.key_spki_sha256 == p.native.key_spki_sha256 && native.material()? == p.native.material()?)
    }
    pub(super) fn require_retrieval(&self, retrieval: &RetrievalAuthority) -> Result<(), ServiceError> {
        self.validate()?; require(retrieval == &self.payload.retrieval)
    }
    pub(super) fn require_guest(&self, guest: &guest::GuestClosureBinding) -> Result<(), ServiceError> {
        let scope = self.cold_scope()?;
        require(scope.boot_id_base64url == guest.boot_id_base64url
            && scope.time_namespace_device == guest.time_namespace_device && scope.time_namespace_inode == guest.time_namespace_inode
            && guest.issued_at_boottime_ns.parse::<u64>().map_err(|_| invalid())? <= self.payload.issued_at_boottime_nanos
            && self.payload.expires_at_boottime_nanos <= guest.lifetime_deadline_boottime_ns.parse::<u64>().map_err(|_| invalid())?)
    }
    pub(super) fn require_history(&self, role: TrustedHostServiceRoleV3, history: &RuntimeAuthorityHistory) -> Result<(), ServiceError> {
        self.validate()?;
        let target = self.payload.target_histories.iter().find(|v| v.service_role == role).ok_or_else(invalid)?;
        let (root, key) = target.keys()?;
        let current = history.current_epoch().map_err(|_| invalid())?;
        require(&target.history_manifest_sha256 == history.manifest_sha256() && &root == history.root_authority_key()
            && target.authority_epoch == current.epoch_reference() && &key == current.service_signing_key())
    }
    pub(super) fn require_durable_authority(&self, epoch: &AuthorityEpochRefV3, key: &VerifyingKey) -> Result<(), ServiceError> {
        self.validate()?;
        let target = self.payload.target_histories.iter().find(|v|
            v.service_role == TrustedHostServiceRoleV3::DurableRecoveryStore).ok_or_else(invalid)?;
        require(&target.authority_epoch == epoch && &target.keys()?.1 == key)
    }
    pub(in crate::policy_shadow) fn require_authority(&self, id: &Sha256Digest, spki: &Sha256Digest,
        key: &VerifyingKey, checkpoint: &AtomicTrustCheckpoint, now_unix: i64) -> Result<(), ShadowError> {
        self.validate().map_err(shadow)?;
        let p = &self.payload;
        require(id == &p.authority.key_id && spki == &p.authority.key_spki_sha256
            && key == &p.authority.material().map_err(shadow)? && p.trust_checkpoint_id == checkpoint.checkpoint_id
            && p.revocation_generation == checkpoint.revocation_generation && p.revocation_root_sha256 == checkpoint.revocation_root_sha256
            && p.issued_at_unix_nanos <= now_unix && now_unix < p.expires_at_unix_nanos).map_err(shadow)
    }
    pub(in crate::policy_shadow) fn verify_current(&self, assignment: &Sha256Digest, revision: u64,
        configuration: &Sha256Digest, proof: &str) -> Result<(), ShadowError> {
        self.validate().map_err(shadow)?;
        let p = &self.payload;
        require(assignment == &p.assignment_payload_sha256 && revision == p.assignment_revision
            && configuration == &p.production_configuration_binding_sha256 && proof == p.proof_scope_original).map_err(shadow)
    }
    pub(in crate::policy_shadow) fn baseline_original(&self) -> Result<String, ShadowError> {
        Ok(self.cold_bundle().map_err(shadow)?.completion.receipt_original)
    }
    pub(in crate::policy_shadow) fn baseline_receipt(&self) -> Result<Receipt, ShadowError> { self.receipt().map_err(shadow) }
    pub(in crate::policy_shadow) fn prior_authority_payload(&self, payload: &[u8]) -> Result<Vec<u8>, ShadowError> {
        let scope = self.cold_scope().map_err(shadow)?;
        let receipt = self.receipt().map_err(shadow)?;
        require(payload == receipt.canonical_payload()?.as_slice()).map_err(shadow)?;
        authority_payload_for_adoption(&scope.proof_scope_original, payload).map_err(shadow)
    }
    pub(in crate::policy_shadow) fn identity_sha256(&self) -> Result<Sha256Digest, ShadowError> { self.identity().map_err(shadow) }
    pub(in crate::policy_shadow) fn deadline_boottime(&self) -> Result<u64, ShadowError> { self.deadline().map_err(shadow) }
}
