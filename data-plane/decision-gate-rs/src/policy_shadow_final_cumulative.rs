//! Complete ordered native ledger accounting. Not a readiness/seal decision.
use super::*;
use base64::Engine as _;

pub(crate) const PROFILE:&str="serverware.nativeCumulativeCheckpoint/v2";
const LABELS:[&str;12]=["admitted","active-pre-dispatch-terminal","response-terminal-appended",
    "dispatch-barrier-appended","response-capture-enqueued","candidate-evaluated","response-evaluated",
    "sampled-out","transport-excluded","unsupported-required-ingress","cleanup-quarantined","failure"];

pub(crate) struct Accounting {value:Value}
impl Accounting {
    pub(crate) fn from_originals<'a>(generation:&Sha256Digest,baseline:u64,baseline_head:&Sha256Digest,
        last:u64,head:&Sha256Digest,observed:i64,originals:impl Iterator<Item=&'a VerifiedShadowSpillReceipt>)
        ->Result<Self,ShadowError> {
        let mut counters=LABELS.into_iter().map(|label|(label.to_string(),0u64)).collect::<BTreeMap<_,_>>();
        let mut ordinal=baseline;let mut previous=baseline_head.clone();let mut receipts=Vec::new();
        let mut receipt_roots=Vec::new();let mut event_roots=Vec::new();
        let mut last_ingress=None;let mut previous_ingress=None;
        for receipt in originals {
            ordinal=ordinal.checked_add(1).ok_or(ShadowError::CounterOverflow)?;
            if receipts.len()>=64 || receipt.generation_id()!=generation || receipt.event_ordinal()!=ordinal
                || receipt.predecessor_event_ordinal()!=ordinal-1 || receipt.predecessor_head_sha256()!=&previous
                || receipt.trusted_observed_at_unix_nanos()>observed || receipt.canonical_event_bytes().len()>16*1024 {
                return Err(ShadowError::BindingDrift);
            }
            let event:Value=serde_json::from_slice(receipt.canonical_event_bytes()).map_err(|_|ShadowError::BindingDrift)?;
            if canonical_json_bytes(&event)?!=receipt.canonical_event_bytes() {return Err(ShadowError::BindingDrift);}
            let label=if native_ingress::is_opening_event(event.as_array().and_then(|values|values.first()).and_then(Value::as_str)) {
                if previous_ingress.is_some_and(|previous:u64|previous.checked_add(1)!=Some(receipt.ingress_sequence())) {return Err(ShadowError::BindingDrift);}
                previous_ingress=Some(receipt.ingress_sequence());
                last_ingress=Some(serde_json::json!({"ingressSequence":receipt.ingress_sequence(),"openingReceiptSha256":receipt.signed_receipt_sha256()}));
                "admitted"
            } else {
                native_runtime::accounting_label(&event)?
            };
            let counter=counters.get_mut(label).ok_or(ShadowError::BindingDrift)?;
            *counter=counter.checked_add(1).ok_or(ShadowError::CounterOverflow)?;
            previous=receipt.resulting_head_sha256().clone();
            let position=receipts.len() as u64+1;
            receipt_roots.push((position,receipt.signed_receipt_sha256().clone()));
            event_roots.push((position,receipt.event_sha256().clone()));
            receipts.push(serde_json::to_value(&**receipt).map_err(|_|ShadowError::BindingDrift)?);
        }
        if ordinal!=last || &previous!=head {return Err(ShadowError::BindingDrift);}
        if canonical_json_bytes(&serde_json::to_value(&receipts).map_err(|_|ShadowError::BindingDrift)?)?.len()>512*1024 {
            return Err(ShadowError::EvidenceBudgetExceeded);
        }
        let value=serde_json::json!({"generationId":generation,"baselineEventOrdinal":baseline,"baselineHeadSha256":baseline_head,
            "lastEventOrdinal":last,"lastHeadSha256":head,"observedAtUnixNanos":observed,"originalCount":receipts.len(),
            "receiptRootSha256":merkle_root(&receipt_roots)?,"eventRootSha256":merkle_root(&event_roots)?,
            "counters":counters,"lastIngress":last_ingress,"originals":receipts});
        if canonical_json_bytes(&value)?.len()>640*1024 {return Err(ShadowError::EvidenceBudgetExceeded);}
        Ok(Self{value})
    }
    pub(crate) fn into_value(self)->Value {self.value}
}

/// Complete native accounting plus a separately authorized, already delivered
/// heartbeat. Neither this carrier nor its counters asserts readiness.
pub(crate) struct Checkpoint {record:Value}

/// Read-only source interface to the gate's opaque drain snapshot. The actual
/// snapshot constructor remains in the closed-admission/last-lifecycle owner;
/// shared custody binaries do not acquire the gate runtime or a DTO constructor.
pub(crate) trait NativeDrainSnapshotView {
    fn generation_id(&self)->&str;
    fn value(&self)->Value;
}

impl Checkpoint {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_originals<'a,S:NativeDrainSnapshotView>(generation:&ShadowGenerationIdentity,baseline:u64,baseline_head:&Sha256Digest,
        last:u64,head:&Sha256Digest,observed:i64,originals:impl Iterator<Item=&'a VerifiedShadowSpillReceipt>,
        heartbeat:&str,heartbeat_sha256:&str,sequence:u64,previous:Option<&Sha256Digest>,interval:Option<&Sha256Digest>,seal:Option<&S>,
        assignment:&VerifiedAssignment,runtime:&RuntimeIdentity,publication:&Sha256Digest,
        configuration:&Sha256Digest,trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<Self,ShadowError> {
        let originals=originals.collect::<Vec<_>>();
        let accounting=Accounting::from_originals(generation.generation_id(),baseline,baseline_head,last,head,observed,
            originals.iter().copied())?.into_value();
        revalidate_verified_freshness(assignment,trust,time,MAX_ENVELOPE_AGE_NANOS)?;
        let checkpoint=trust.current_checkpoint()?;
        revalidate_verified_at_checkpoint(assignment,&checkpoint,trust,MAX_ENVELOPE_AGE_NANOS)?;
        verify_assignment_authority_key_material_at_checkpoint(assignment,&checkpoint,trust)?;
        let a=assignment.payload();
        if !(1..=32).contains(&sequence) || (sequence==1)!=previous.is_none()
            || generation.assignment_sha256()!=assignment.envelope_sha256()
            || generation.runtime_boot_id_sha256()!=runtime.boot_id_sha256()
            || !(25..=256).contains(&a.authority_key_independence.bindings.len())
            || !matches!(&a.custody_authority.attestation_mode,CustodyAttestationMode::Tee{platform:TeePlatform::AwsNitroEnclave,..}) {
            return Err(ShadowError::BindingDrift);
        }
        let heartbeat_value:Value=serde_json::from_str(heartbeat).map_err(|_|ShadowError::BindingDrift)?;
        if canonical_json_bytes(&heartbeat_value)?!=heartbeat.as_bytes()
            || Sha256Digest::compute(heartbeat.as_bytes()).as_str()!=heartbeat_sha256
            || heartbeat_value["apiVersion"]!="serverware.nativePolicyShadowHeartbeat/v2" {
            return Err(ShadowError::BindingDrift);
        }
        let statement=&heartbeat_value["evidence"]["statement"];
        for (field,expected) in [("generationId",accounting["generationId"].clone()),
            ("baselineEventOrdinal",accounting["baselineEventOrdinal"].clone()),("baselineHeadSha256",accounting["baselineHeadSha256"].clone()),
            ("eventOrdinal",accounting["lastEventOrdinal"].clone()),("headSha256",accounting["lastHeadSha256"].clone()),
            ("originalCount",accounting["originalCount"].clone()),("observedAtUnixNanos",accounting["observedAtUnixNanos"].clone())] {
            if statement[field]!=expected {return Err(ShadowError::BindingDrift);}
        }
        let ingress=&accounting["lastIngress"];
        if statement["lastIngressSequence"]!=ingress["ingressSequence"] || statement["openingReceiptSha256"]!=ingress["openingReceiptSha256"] {
            return Err(ShadowError::BindingDrift);
        }
        let seal_value=seal.map(|value|value.value()).unwrap_or(Value::Null);
        if statement["seal"]!=seal_value || seal.is_some_and(|value|value.generation_id()!=generation.generation_id().as_str())
            || observed<a.observation_window.starts_at_unix_nanos
            || observed>=a.observation_window.seal_deadline_unix_nanos
            || observed>=a.expires_at_unix_nanos {return Err(ShadowError::BindingDrift);}
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
        let mut public=BTreeMap::new();
        for original in originals {
            let receipt=&**original;let signer=receipt.signer_role();let role=authority_role_for_custody_signer(signer);
            if !matches!(role,AuthorityRole::CustodyIngressAdmission|AuthorityRole::CustodyDispatchBarrier
                |AuthorityRole::CustodyTerminalAppend|AuthorityRole::CustodyLedgerAppend) {return Err(ShadowError::BindingDrift);}
            let binding=a.authority_key_independence.binding(role,&a.assignment_id)?;
            if receipt.signing_key_id!=binding.key_id || receipt.signing_key_spki_sha256!=binding.key_spki_sha256 {
                return Err(ShadowError::SignerBindingMismatch);
            }
            let key=trust.resolve_ed25519_key(&checkpoint,authority_role_signature_domain(role),&binding.key_id,&binding.key_spki_sha256)?;
            if ed25519_public_key_material_sha256(&key)!=binding.key_material_sha256 {return Err(ShadowError::SignerBindingMismatch);}
            let bound=canonical_json_bytes(&("serverware.policyShadowAssignmentBoundCustodyReceipt/v1",&scope,
                &authority.execution_closure_manifest_sha256,&authority.structurally_verified_seccomp_policy_sha256,
                signer,Sha256Digest::compute(&receipt.canonical_signature_payload()?)))?;
            key.verify_strict(&signature_preimage(signer.signature_domain(),&bound),&Signature::from_bytes(&receipt.signature.decode()?))
                .map_err(|_|ShadowError::SignatureInvalid)?;
            let label=serde_json::to_value(signer).map_err(|_|ShadowError::BindingDrift)?;
            public.insert(label.as_str().ok_or(ShadowError::BindingDrift)?.to_string(),URL_SAFE_NO_PAD.encode(key.as_bytes()));
        }
        if trust.current_checkpoint()?!=checkpoint {return Err(ShadowError::BindingDrift);}
        let record=serde_json::json!({"apiVersion":PROFILE,"canary_id":a.canary_id,"instance_id":runtime.instance_id(),
            "boot_id":runtime.boot_id_sha256(),"assignment_envelope_digest":assignment.envelope_sha256(),
            "assignment_payload_digest":assignment.payload_sha256(),"load_receipt_envelope_digest":generation.load_receipt_sha256(),
            "publication_envelope_digest":publication,"checkpoint_sequence":sequence,"previous_checkpoint_sha256":previous,
            "heartbeat":heartbeat_value,"heartbeat_sha256":heartbeat_sha256,"interval_receipt_sha256":interval,
            "accounting":accounting,"signing_public_keys":public,"seal":seal.map(|value|value.value())});
        if canonical_json_bytes(&record)?.len()>768*1024 {return Err(ShadowError::EvidenceBudgetExceeded);}
        Ok(Self{record})
    }
    pub(crate) fn sha256(&self)->Result<Sha256Digest,ShadowError> {Ok(Sha256Digest::compute(&canonical_json_bytes(&self.record)?))}
    pub(crate) fn original(&self)->Result<String,ShadowError> {String::from_utf8(canonical_json_bytes(&self.record)?).map_err(|_|ShadowError::BindingDrift)}
    pub(crate) fn into_event(self)->Value {serde_json::json!({"kind":"checkpoint","record":self.record})}
}
