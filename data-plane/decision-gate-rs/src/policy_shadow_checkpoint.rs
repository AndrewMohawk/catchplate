//! A completed compaction interval, not a cumulative Fleet checkpoint.
use super::*;
use base64::Engine as _;

pub(crate) const PROFILE:&str="catchplate.nativeCustodyCheckpointObservation/v1";
pub(crate) struct Checkpoint {record:Value}
pub(crate) fn remaining_window(assignment:&VerifiedAssignment,load:&VerifiedLoadReceipt,
    generation:&ShadowGenerationIdentity,time:&dyn TrustedTime)->Result<u64,ShadowError> {
    let now=time.now_unix_nanos()?;
    let end=assignment.payload().expires_at_unix_nanos()
        .min(load.payload().expires_at_unix_nanos())
        .min(generation.assignment_ends_at_unix_nanos);
    if now<generation.assignment_starts_at_unix_nanos || now>=end {
        return Err(ShadowError::BindingDrift);
    }
    u64::try_from(end.checked_sub(now).ok_or(ShadowError::CounterOverflow)?)
        .map_err(|_|ShadowError::CounterOverflow)
}
impl Checkpoint {
    pub(crate) fn from_receipt(verified:&VerifiedSpoolCompactionReceipt,ordered_range:&Value,
        generation:&ShadowGenerationIdentity,assignment:&VerifiedAssignment,runtime:&RuntimeIdentity,
        publication:&Sha256Digest,configuration:&Sha256Digest,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)
        ->Result<Self,ShadowError> {
        revalidate_verified_freshness(assignment,trust,time,MAX_ENVELOPE_AGE_NANOS)?;
        let checkpoint=trust.current_checkpoint()?;
        revalidate_verified_at_checkpoint(assignment,&checkpoint,trust,MAX_ENVELOPE_AGE_NANOS)?;
        verify_assignment_authority_key_material_at_checkpoint(assignment,&checkpoint,trust)?;
        let a=assignment.payload();let receipt=&verified.wire;
        receipt.validate_deserialized_invariants()?;
        if receipt.generation_id!=*generation.generation_id()
            || generation.assignment_sha256()!=assignment.envelope_sha256()
            || generation.assignment_payload_sha256()!=assignment.payload_sha256()
            || generation.runtime_boot_id_sha256()!=runtime.boot_id_sha256()
            || receipt.compacted_record_count!=8
            || Sha256Digest::compute(&canonical_json_bytes(ordered_range)?)!=receipt.compacted_ordered_range_root_sha256
            || !(25..=256).contains(&a.authority_key_independence.bindings.len())
            || !matches!(&a.custody_authority.attestation_mode,CustodyAttestationMode::Tee{platform:TeePlatform::AwsNitroEnclave,..}) {
            return Err(ShadowError::BindingDrift);
        }
        let role=AuthorityRole::CustodySpoolCompaction;
        let signer=PolicyShadowCustodySignerRole::SpoolCompaction;
        let binding=a.authority_key_independence.binding(role,&a.assignment_id)?;
        if receipt.signing_key_id!=binding.key_id || receipt.signing_key_spki_sha256!=binding.key_spki_sha256 {
            return Err(ShadowError::SignerBindingMismatch);
        }
        let key=trust.resolve_ed25519_key(&checkpoint,authority_role_signature_domain(role),&binding.key_id,&binding.key_spki_sha256)?;
        if ed25519_public_key_material_sha256(&key)!=binding.key_material_sha256 {return Err(ShadowError::SignerBindingMismatch);}
        let bindings=PRODUCTION_CUSTODY_AUTHORITY_ROLES.iter().map(|role| {
            let b=a.authority_key_independence.binding(*role,&a.assignment_id)?;
            Ok((*role,ProductionCustodyKeyBinding{role:*role,key_id:b.key_id.clone(),key_spki_sha256:b.key_spki_sha256.clone(),key_material_sha256:b.key_material_sha256.clone()}))
        }).collect::<Result<BTreeMap<_,_>,ShadowError>>()?;
        let authority=&a.custody_authority;
        let scope=hash_domain_frames(b"catchplate.policyShadowProductionCustodyProofScope/v1",&[&canonical_json_bytes(&(
            &a.assignment_id,assignment.payload_sha256(),a.assignment_revision,&authority.authority_id,
            &authority.storage_realm_sha256,&authority.retrieval_namespace_sha256,
            &a.authority_key_independence.independence_root_sha256,configuration,production_custody_key_set_root(&bindings)?,
            &authority.execution_closure_manifest_sha256,&authority.structurally_verified_seccomp_policy_sha256))?]);
        let bound=canonical_json_bytes(&("catchplate.policyShadowAssignmentBoundCustodyReceipt/v1",scope,
            &authority.execution_closure_manifest_sha256,&authority.structurally_verified_seccomp_policy_sha256,
            signer,Sha256Digest::compute(&receipt.canonical_signature_payload()?)))?;
        key.verify_strict(&signature_preimage(signer.signature_domain(),&bound),&Signature::from_bytes(&receipt.signature.decode()?))
            .map_err(|_|ShadowError::SignatureInvalid)?;
        if trust.current_checkpoint()?!=checkpoint {return Err(ShadowError::BindingDrift);}
        let record=serde_json::json!({"apiVersion":PROFILE,"canary_id":a.canary_id,"instance_id":runtime.instance_id(),
            "boot_id":runtime.boot_id_sha256(),"assignment_envelope_digest":assignment.envelope_sha256(),
            "assignment_payload_digest":assignment.payload_sha256(),"load_receipt_envelope_digest":generation.load_receipt_sha256(),
            "publication_envelope_digest":publication,"receipt":receipt,"ordered_range":ordered_range,
            "signing_public_key_base64url":URL_SAFE_NO_PAD.encode(key.as_bytes())});
        if canonical_json_bytes(&record)?.len()>32*1024 {return Err(ShadowError::CustodyUnavailable);}
        Ok(Self{record})
    }
    pub(crate) fn into_event(self)->Value {serde_json::json!({"kind":"checkpoint","record":self.record})}
}
