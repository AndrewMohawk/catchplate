//! Original production custody receipts, not substitute Fleet* envelopes.
use super::*;
use base64::Engine as _;

pub(crate) const PROFILE:&str="serverware.nativeCustodyRuntimeObservation/v1";
pub(crate) const RESPONSE_PROFILE:&str="serverware.nativeCustodyResponseObservation/v1";
/// Count actual signed event originals without stripping their v2 preimages.
/// This is framing admission, not semantic readiness verification.
pub(super) fn accounting_label(event: &Value) -> Result<&str, ShadowError> {
    let label = event.get("event").and_then(Value::as_str).ok_or(ShadowError::BindingDrift)?;
    match event.get("domain").and_then(Value::as_str) {
        Some("serverware.policyShadowRuntimeAccountingEvent/v1") => Ok(label),
        Some("serverware.policyShadowRuntimeAccountingEvent/v2") => {
            const FIELDS: [&str; 20] = ["domain", "ingressSequence", "requestBindingSha256", "requestCommitmentSha256",
                "event", "phase", "terminalDetailSha256", "activePlanSha256", "finalActiveDecisionSha256",
                "activeEffectResultsSha256", "candidatePlanSha256", "activeDisposition", "candidateDisposition",
                "responseFactsSha256", "activeResponseValidationSha256", "candidateResponseValidationSha256",
                "decisionAtUnixNanos", "dispatchFinalRequestSha256", "dispatchEffectAuthoritySha256", "observationOriginal"];
            let object = event.as_object().ok_or(ShadowError::BindingDrift)?;
            if object.len() != FIELDS.len() || FIELDS.iter().any(|field| !object.contains_key(*field)) {
                return Err(ShadowError::BindingDrift);
            }
            let (phase, profiles):(&str,&[&str]) = match label {
                "candidate-evaluated" => ("candidate", &["serverware.nativeRequestObservationOriginal/v1", "serverware.nativeRequestObservationOriginal/v2",
                    "serverware.nativeRequestObservationOriginal/v3"]),
                "response-evaluated" => ("response", &["serverware.nativeResponseObservationOriginal/v1", "serverware.nativeResponseObservationOriginal/v2"]),
                _ => return Err(ShadowError::BindingDrift),
            };
            if event["phase"] != phase || !event["observationOriginal"]["apiVersion"].as_str().is_some_and(|profile|profiles.contains(&profile)) {
                return Err(ShadowError::BindingDrift);
            }
            Ok(label)
        }
        _ => Err(ShadowError::BindingDrift),
    }
}

pub(crate) struct Observation { record:Value, kind:&'static str }
impl Observation {
    pub(crate) fn from_receipt(receipt:&VerifiedShadowSpillReceipt,opening:&Sha256Digest,terminal:Option<&Sha256Digest>,
        generation:&ShadowGenerationIdentity,assignment:&VerifiedAssignment,runtime:&RuntimeIdentity,
        publication:&Sha256Digest,configuration:&Sha256Digest,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)
        ->Result<Self,ShadowError> {
        Self::admitted(receipt,opening,terminal,None,generation,assignment,runtime,publication,configuration,trust,time)
    }
    pub(crate) fn from_response(receipt:&VerifiedShadowSpillReceipt,opening:&Sha256Digest,terminal:&Sha256Digest,request:&Sha256Digest,
        generation:&ShadowGenerationIdentity,assignment:&VerifiedAssignment,runtime:&RuntimeIdentity,
        publication:&Sha256Digest,configuration:&Sha256Digest,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)
        ->Result<Self,ShadowError> {
        Self::admitted(receipt,opening,Some(terminal),Some(request),generation,assignment,runtime,publication,configuration,trust,time)
    }
    fn admitted(receipt:&VerifiedShadowSpillReceipt,opening:&Sha256Digest,terminal:Option<&Sha256Digest>,request:Option<&Sha256Digest>,
        generation:&ShadowGenerationIdentity,assignment:&VerifiedAssignment,runtime:&RuntimeIdentity,
        publication:&Sha256Digest,configuration:&Sha256Digest,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)
        ->Result<Self,ShadowError> {
        revalidate_verified_freshness(assignment,trust,time,MAX_ENVELOPE_AGE_NANOS)?;
        let checkpoint=trust.current_checkpoint()?;
        revalidate_verified_at_checkpoint(assignment,&checkpoint,trust,MAX_ENVELOPE_AGE_NANOS)?;
        verify_assignment_authority_key_material_at_checkpoint(assignment,&checkpoint,trust)?;
        let a=assignment.payload();let receipt=&receipt.wire;
        receipt.validate_deserialized_invariants()?;
        let (role,signer,kind)=match receipt.event_phase {
            ShadowSpoolPhase::PreDispatchTerminal|ShadowSpoolPhase::PostDispatchTerminal if terminal.is_none() && request.is_none()=>
                (AuthorityRole::CustodyTerminalAppend,PolicyShadowCustodySignerRole::TerminalAppend,"active-decision"),
            ShadowSpoolPhase::Candidate if terminal.is_some() && request.is_none()=>
                (AuthorityRole::CustodyLedgerAppend,PolicyShadowCustodySignerRole::LedgerAppend,"shadow-observation"),
            ShadowSpoolPhase::Response if terminal.is_some() && request.is_some()=>
                (AuthorityRole::CustodyLedgerAppend,PolicyShadowCustodySignerRole::LedgerAppend,"shadow-observation"),
            _=>return Err(ShadowError::BindingDrift),
        };
        if receipt.disposition!=ShadowSpoolDisposition::Appended || receipt.generation_id!=*generation.generation_id()
            || generation.assignment_sha256()!=assignment.envelope_sha256()
            || generation.assignment_payload_sha256()!=assignment.payload_sha256()
            || generation.runtime_boot_id_sha256()!=runtime.boot_id_sha256()
            || !(25..=256).contains(&a.authority_key_independence.bindings.len())
            || receipt.canonical_event_bytes.len()>16*1024
            || !matches!(&a.custody_authority.attestation_mode,CustodyAttestationMode::Tee{platform:TeePlatform::AwsNitroEnclave,..}) {
            return Err(ShadowError::BindingDrift);
        }
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
        let scope=hash_domain_frames(b"serverware.policyShadowProductionCustodyProofScope/v1",&[&canonical_json_bytes(&(
            &a.assignment_id,assignment.payload_sha256(),a.assignment_revision,&authority.authority_id,
            &authority.storage_realm_sha256,&authority.retrieval_namespace_sha256,
            &a.authority_key_independence.independence_root_sha256,configuration,production_custody_key_set_root(&bindings)?,
            &authority.execution_closure_manifest_sha256,&authority.structurally_verified_seccomp_policy_sha256))?]);
        let bound=canonical_json_bytes(&("serverware.policyShadowAssignmentBoundCustodyReceipt/v1",scope,
            &authority.execution_closure_manifest_sha256,&authority.structurally_verified_seccomp_policy_sha256,
            signer,Sha256Digest::compute(&receipt.canonical_signature_payload()?)))?;
        key.verify_strict(&signature_preimage(signer.signature_domain(),&bound),&Signature::from_bytes(&receipt.signature.decode()?))
            .map_err(|_|ShadowError::SignatureInvalid)?;
        if trust.current_checkpoint()?!=checkpoint {return Err(ShadowError::BindingDrift);}
        let mut record=serde_json::json!({"apiVersion":if request.is_some(){RESPONSE_PROFILE}else{PROFILE},"canary_id":a.canary_id,"instance_id":runtime.instance_id(),
            "boot_id":runtime.boot_id_sha256(),"assignment_envelope_digest":assignment.envelope_sha256(),
            "assignment_payload_digest":assignment.payload_sha256(),"load_receipt_envelope_digest":generation.load_receipt_sha256(),
            "publication_envelope_digest":publication,"receipt":receipt,"opening_receipt_sha256":opening,
            "terminal_receipt_sha256":terminal,"signing_public_key_base64url":URL_SAFE_NO_PAD.encode(key.as_bytes())});
        if let Some(request)=request {record["request_observation_receipt_sha256"]=serde_json::json!(request);}
        if canonical_json_bytes(&record)?.len()>64*1024 {return Err(ShadowError::CustodyUnavailable);}
        Ok(Self{record,kind})
    }
    pub(crate) fn into_event(self)->Value {serde_json::json!({"kind":self.kind,"record":self.record})}
}
