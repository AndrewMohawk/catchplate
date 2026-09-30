//! Read-only scope from the genuinely installed native generation.
use super::*;
pub(crate) fn scope(generation:&ShadowGenerationIdentity,assignment:&VerifiedAssignment,load:&VerifiedLoadReceipt,
    runtime:&RuntimeIdentity,publication:&Sha256Digest,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<Value,ShadowError>{
    revalidate_verified_freshness(assignment,trust,time,MAX_ENVELOPE_AGE_NANOS)?;
    revalidate_verified_freshness(load,trust,time,MAX_ENVELOPE_AGE_NANOS)?;
    let checkpoint=trust.current_checkpoint()?;
    revalidate_verified_at_checkpoint(assignment,&checkpoint,trust,MAX_ENVELOPE_AGE_NANOS)?;
    verify_assignment_authority_key_material_at_checkpoint(assignment,&checkpoint,trust)?;
    if generation.assignment_sha256()!=assignment.envelope_sha256()
        || generation.assignment_payload_sha256()!=assignment.payload_sha256()
        || generation.load_receipt_sha256()!=load.envelope_sha256()
        || generation.runtime_boot_id_sha256()!=runtime.boot_id_sha256()
        || load.payload().runtime_identity()!=runtime {return Err(ShadowError::BindingDrift);}
    let value=serde_json::json!({"canary_id":assignment.payload().canary_id(),"instance_id":runtime.instance_id(),
        "boot_id":runtime.boot_id_sha256(),"assignment_envelope_digest":assignment.envelope_sha256(),
        "assignment_payload_digest":assignment.payload_sha256(),"load_receipt_envelope_digest":load.envelope_sha256(),
        "publication_envelope_digest":publication,"runtimeIdentitySha256":Sha256Digest::compute(&canonical_json_bytes(runtime)?),
        "expiresAtUnixNanos":assignment.payload().expires_at_unix_nanos.min(assignment.payload().observation_window.ends_at_unix_nanos),
        "startsAtUnixNanos":assignment.payload().observation_window.starts_at_unix_nanos});
    if trust.current_checkpoint()?!=checkpoint{return Err(ShadowError::BindingDrift);}Ok(value)
}
