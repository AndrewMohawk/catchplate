//! A real newly admitted opening, never an unsigned observation constructor.
use super::*;
use base64::Engine as _;

pub(crate) const PROFILE: &str = "serverware.nativeCustodyOpening/v1";

/// No Deserialize or public field. Only the completed production admission,
/// retained installed generation and current independently assigned key create
/// this value. It is not final ingress, active-decision or shadow coverage.
pub(crate) struct Opening { record: Value }

impl Opening {
    pub(crate) fn from_admission(admission: &PersistedIngressAdmission,
        generation: &ShadowGenerationIdentity, assignment: &VerifiedAssignment,
        runtime: &RuntimeIdentity, publication: &Sha256Digest,
        configuration: &Sha256Digest, trust: &dyn EnvelopeKeyTrust,
        time: &dyn TrustedTime) -> Result<Self, ShadowError> {
        revalidate_verified_freshness(assignment, trust, time, MAX_ENVELOPE_AGE_NANOS)?;
        let checkpoint = trust.current_checkpoint()?;
        revalidate_verified_at_checkpoint(assignment, &checkpoint, trust, MAX_ENVELOPE_AGE_NANOS)?;
        verify_assignment_authority_key_material_at_checkpoint(assignment, &checkpoint, trust)?;
        let a = assignment.payload();
        let receipt = &admission.opening_spill_receipt().wire;
        receipt.validate_deserialized_invariants()?;
        if !(25..=256).contains(&a.authority_key_independence.bindings.len())
            || receipt.canonical_event_bytes.len() > 16*1024
            || !matches!(&a.custody_authority.attestation_mode,
                CustodyAttestationMode::Tee { platform:TeePlatform::AwsNitroEnclave, .. }) {
            return Err(ShadowError::CustodyUnavailable);
        }
        if admission.generation_id() != generation.generation_id()
            || generation.assignment_sha256() != assignment.envelope_sha256()
            || generation.assignment_payload_sha256() != assignment.payload_sha256()
            || generation.runtime_boot_id_sha256() != runtime.boot_id_sha256()
            || !receipt.matches_opening(generation.generation_id(), admission.ingress_sequence(), admission.request_binding_sha256()) {
            return Err(ShadowError::BindingDrift);
        }
        let role = AuthorityRole::CustodyIngressAdmission;
        let binding = a.authority_key_independence.binding(role, &a.assignment_id)?;
        if receipt.signing_key_id != binding.key_id || receipt.signing_key_spki_sha256 != binding.key_spki_sha256 {
            return Err(ShadowError::SignerBindingMismatch);
        }
        let key = trust.resolve_ed25519_key(&checkpoint, authority_role_signature_domain(role),
            &binding.key_id, &binding.key_spki_sha256)?;
        if ed25519_public_key_material_sha256(&key) != binding.key_material_sha256 {
            return Err(ShadowError::SignerBindingMismatch);
        }
        let bindings = PRODUCTION_CUSTODY_AUTHORITY_ROLES.iter().map(|role| {
            let b = a.authority_key_independence.binding(*role, &a.assignment_id)?;
            Ok((*role, ProductionCustodyKeyBinding { role:*role, key_id:b.key_id.clone(),
                key_spki_sha256:b.key_spki_sha256.clone(), key_material_sha256:b.key_material_sha256.clone() }))
        }).collect::<Result<BTreeMap<_,_>,ShadowError>>()?;
        let authority = &a.custody_authority;
        let scope = hash_domain_frames(b"serverware.policyShadowProductionCustodyProofScope/v1", &[&canonical_json_bytes(&(
            &a.assignment_id, assignment.payload_sha256(), a.assignment_revision, &authority.authority_id,
            &authority.storage_realm_sha256, &authority.retrieval_namespace_sha256,
            &a.authority_key_independence.independence_root_sha256, configuration,
            production_custody_key_set_root(&bindings)?, &authority.execution_closure_manifest_sha256,
            &authority.structurally_verified_seccomp_policy_sha256))?]);
        let bound = canonical_json_bytes(&(
            "serverware.policyShadowAssignmentBoundCustodyReceipt/v1", scope,
            &authority.execution_closure_manifest_sha256, &authority.structurally_verified_seccomp_policy_sha256,
            PolicyShadowCustodySignerRole::IngressAdmission, Sha256Digest::compute(&receipt.canonical_signature_payload()?)))?;
        key.verify_strict(&signature_preimage(PolicyShadowCustodySignerRole::IngressAdmission.signature_domain(), &bound),
            &Signature::from_bytes(&receipt.signature.decode()?)).map_err(|_|ShadowError::SignatureInvalid)?;
        if trust.current_checkpoint()? != checkpoint { return Err(ShadowError::BindingDrift); }
        let record = serde_json::json!({"apiVersion":PROFILE,"canary_id":a.canary_id,
            "instance_id":runtime.instance_id(),"boot_id":runtime.boot_id_sha256(),
            "assignment_envelope_digest":assignment.envelope_sha256(),"assignment_payload_digest":assignment.payload_sha256(),
            "load_receipt_envelope_digest":generation.load_receipt_sha256(),"publication_envelope_digest":publication,
            "opening_receipt":receipt,"signing_public_key_base64url":URL_SAFE_NO_PAD.encode(key.as_bytes())});
        if canonical_json_bytes(&record)?.len() > 64*1024 { return Err(ShadowError::CustodyUnavailable); }
        Ok(Self {record})
    }
    pub(crate) fn into_record(self) -> Value { self.record }
}
