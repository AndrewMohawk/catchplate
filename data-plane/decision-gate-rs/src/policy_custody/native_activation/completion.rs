//! Purpose-specific admission of actual controlled PREPARE originals. The
//! independent planner, verifier and witness signatures cover the full roots,
//! human assertion and durable exclusion hold; a response-shaped JSON object
//! or a previous Fleet readiness receipt cannot construct this capability.
use super::*;
#[path="radix.rs"] mod radix;
#[path="approval.rs"] mod approval;
const RUNTIME:&str="serverware.policyAuthorityRuntimeRequest/v2";
const RESPONSE:&str="serverware.policyAuthorityNativeActivationRuntimeResponse/v1";
const PLAN:&str="serverware.signedPolicyAuthorityMeasuredPlan/v3";
const RESULT:&str="serverware.policyAuthorityControlledWriterResult/v2";
fn number(v:&Value,k:&str)->Result<u64,ShadowError>{v[k].as_u64().filter(|n|*n<=i64::MAX as u64).ok_or(ShadowError::BindingDrift)}
fn sha(v:&Value)->Result<Value,ShadowError>{serde_json::to_value(Sha256Digest::compute(&canonical_json_bytes(v)?)).map_err(fail)}
fn frame(domain:&str,v:&Value)->Result<Value,ShadowError>{serde_json::to_value(framed(domain,&[&canonical_json_bytes(v)?])).map_err(fail)}
pub(super) fn verify(native:&Request,authority:&Authority,assignment:&VerifiedAssignment,
    trust:&dyn EnvelopeKeyTrust,time:&dyn TrustedTime)->Result<Value,ShadowError>{
    authority.check(assignment,trust,time)?;
    let request=document(native.prepare_request_original.as_bytes(),MAX_REQUEST)?;
    let response=document(native.prepare_response_original.as_bytes(),MAX_REQUEST)?;
    exact(&request,&["schema","requestId","operation","input","configurationDigest","operationManifestDigest","startedMonotonicNs","deadlineMonotonicNs"])?;
    exact(&response,&["schema","requestId","operation","configurationDigest","requestDigest","issuedAtEpochNs","deadlineMonotonicNs","fence","result","resultDigest",
        "commitReceiptDigest","witnessCommitDigest","attestationReceiptDigest","attestationConsumptionReceipt","attestationConsumptionReceiptDigest","signature","authorityConfigurationOriginal","activationOriginals"])?;
    let payload=&authority.payload;let manifest=&payload["operationManifestDigest"];
    require(request["schema"]==RUNTIME && request["operation"]==OPERATION && response["operation"]==OPERATION
        && response["schema"]==RESPONSE && request["configurationDigest"]==serde_json::to_value(&authority.digest).map_err(fail)?
        && response["configurationDigest"]==request["configurationDigest"] && request["operationManifestDigest"]==*manifest
        && response["requestId"]==request["requestId"] && response["requestDigest"]==frame(RUNTIME,&request)?
        && response["deadlineMonotonicNs"]==request["deadlineMonotonicNs"] && number(&response,"fence")?>0
        && number(&request,"startedMonotonicNs")?<number(&request,"deadlineMonotonicNs")?
        && decode(text(&response,"authorityConfigurationOriginal")?,3*1024*1024)?==authority.configuration_original)?;
    let verifier=&payload["roles"]["verifier"];let planner=&payload["roles"]["planner"];
    signed(&response,text(verifier,"signingPublicKeyBase64Url")?,RESPONSE)?;
    require(response["attestationReceiptDigest"]==verifier["attestationReceiptDigest"]
        && response["attestationConsumptionReceiptDigest"]==frame(text(&response["attestationConsumptionReceipt"],"schema")?,&response["attestationConsumptionReceipt"])? )?;
    exact(&request["input"],&["schema","handler","operationManifestDigest","arguments"])?;
    require(request["input"]["schema"]=="serverware.policyAuthorityControlledWriterInput/v1"
        && request["input"]["handler"]==HANDLER && request["input"]["operationManifestDigest"]==*manifest)?;
    let arguments=&request["input"]["arguments"];
    // authn_evidence is retained in the actual typed request but excluded from
    // the authorization digest by the existing source commitment recipe.
    let mut business=arguments.clone();let map=business.as_object_mut().ok_or(ShadowError::BindingDrift)?;
    map.remove("authn_evidence");
    exact(&business,&["actor_id","control_plane_configuration_digest","request","approval_id","approval_original","credential_policy","before_original","activation_policy"])?;
    require(business["control_plane_configuration_digest"]==request["configurationDigest"]
        && business["activation_policy"]==payload["policyCanaryNativeActivationPolicy"])?;
    let mut expected=arguments.clone();expected.as_object_mut().ok_or(ShadowError::BindingDrift)?.insert("businessIntent".into(),json!({
        "schema":"serverware.policyAuthorityBusinessIntent/v2","operation":OPERATION,
        "planningAdapterId":format!("serverware.policyAuthorityPlanningAdapter/{HANDLER}/v1"),"arguments":business}));
    let mut commitment=expected.clone();commitment.as_object_mut().ok_or(ShadowError::BindingDrift)?.remove("authn_evidence");
    let request_digest=framed("serverware.policyAuthorityV9Request/v1",&[&canonical_json_bytes(&json!({
        "schema":"serverware.policyAuthorityV9Authorization/v1","operation":OPERATION,"handler":HANDLER,"operationManifestDigest":manifest,"arguments":commitment}))?]);
    let operation_id=framed("serverware.policyAuthorityOperation/v2",&[OPERATION.as_bytes(),request_digest.as_str().as_bytes()]);
    let originals=&response["activationOriginals"];
    exact(originals,&["signedMeasuredPlanOriginal","executorCompletionOriginal","witnessRequestOriginal","witnessResponseOriginal","nativeEffectHoldOriginal"])?;
    let signed_plan=document(text(originals,"signedMeasuredPlanOriginal")?.as_bytes(),MAX_REQUEST)?;
    exact(&signed_plan,&["schema","payload","signatureBase64Url"])?;require(signed_plan["schema"]==PLAN)?;
    verify_signature(text(planner,"signingPublicKeyBase64Url")?,text(&signed_plan,"signatureBase64Url")?,
        framed(PLAN,&[&canonical_json_bytes(&signed_plan["payload"])?]).as_str().as_bytes())?;
    let plan=&signed_plan["payload"];
    exact(plan,&["schema","measuredPlan","typedRequest","selectedBusinessRows","mutationPlan","queryMultiproofs","queryMultiproofsDigest","plannerTrace","plannerTraceDigest",
        "authorizationProjection","webauthnEvidence","expectedResult","expectedResultDigest","plannerIdentity","rootTransition"])?;
    require(plan["schema"]=="serverware.policyAuthorityPlannerResponse/v3" && plan["plannerIdentity"]==json!({
        "sessionIdentityDigest":planner["plannerSessionIdentityDigest"],"measurementDigest":planner["measurementDigest"],"attestationReceiptDigest":planner["attestationReceiptDigest"]}))?;
    let measured=&plan["measuredPlan"];let typed=&plan["typedRequest"];
    exact(measured,&["schema","plannerTransactionId","operation","operationId","requestDigest","capabilityId","sourceRevision","authoritySchemaVersion","operationContractDigest",
        "operationManifestDigest","handlerContractDigest","queryManifestDigest","selectedBusinessRowsDigest","mutationPlanDigest","workUnits","authorityRootSetBeforeDigest",
        "authorizationProjectionDigest","authoritySnapshotDigest","rootTransitionDigest","deadlineMonotonicNs","deadlineEpochNs","fence"])?;
    exact(typed,&["schema","operation","operationId","requestDigest","handler","operationManifestDigest","arguments"])?;
    require(typed["schema"]=="serverware.policyAuthorityV9Request/v1" && typed["handler"]==HANDLER && typed["arguments"]==expected
        && typed["operation"]==OPERATION && typed["operationManifestDigest"]==*manifest
        && typed["requestDigest"]==serde_json::to_value(&request_digest).map_err(fail)? && typed["operationId"]==serde_json::to_value(&operation_id).map_err(fail)?
        && measured["schema"]=="serverware.policyAuthorityMeasuredPlan/v3" && measured["authoritySchemaVersion"]==9
        && (1..=8194).contains(&number(measured,"workUnits")?) && measured["operation"]==OPERATION && measured["operationId"]==typed["operationId"]
        && measured["requestDigest"]==typed["requestDigest"] && measured["sourceRevision"]==payload["sourceRevision"]
        && measured["operationManifestDigest"]==*manifest && measured["operationContractDigest"]==*manifest
        && measured["queryManifestDigest"]==payload["queryManifestDigest"] && measured["fence"]==response["fence"]
        && measured["deadlineMonotonicNs"]==response["deadlineMonotonicNs"])?;
    require(measured["handlerContractDigest"]==serde_json::to_value(radix::handler_commitment(text(payload,"sourceRevision")?)?).map_err(fail)?)?;
    radix::verify(plan)?;
    let transition=&plan["rootTransition"];
    for(field,domain,value)in [("rootTransitionDigest","serverware.policyAuthorityPrimaryRootTransition/v1",transition),
        ("selectedBusinessRowsDigest","serverware.policyAuthoritySelectedBusinessRows/v1",&plan["selectedBusinessRows"]),
        ("mutationPlanDigest","serverware.policyAuthorityMutationPlan/v3",&plan["mutationPlan"]),
        ("authorityRootSetBeforeDigest","serverware.policyAuthorityRootSet/v1",&transition["businessBeforeRoots"]),
        ("authorizationProjectionDigest","serverware.policyAuthorityAuthorizationProjection/v1",&plan["authorizationProjection"])]{
        require(measured[field]==frame(domain,value)?)?;
    }
    require(plan["queryMultiproofsDigest"]==frame("serverware.policyAuthorityRadixMultiproofSet/v3",&plan["queryMultiproofs"])?
        && plan["plannerTraceDigest"]==frame("serverware.policyAuthorityPlannerTrace/v1",&plan["plannerTrace"])?
        && measured["plannerTransactionId"]==serde_json::to_value(framed("serverware.policyAuthorityPlannerTransaction/v1",
            &[operation_id.as_str().as_bytes(),request_digest.as_str().as_bytes(),text(measured,"capabilityId")?.as_bytes()])).map_err(fail)?)?;
    let fields=["operation","operationId","requestDigest","queryManifestDigest","authorityRootSetBeforeDigest","authorizationProjectionDigest","selectedBusinessRowsDigest","mutationPlanDigest","rootTransitionDigest"];
    let frames=fields.iter().map(|name|text(measured,name).map(str::as_bytes)).collect::<Result<Vec<_>,_>>()?;
    require(measured["authoritySnapshotDigest"]==serde_json::to_value(framed("serverware.policyAuthoritySnapshot/v3",&frames)).map_err(fail)?)?;
    let result=&response["result"];
    exact(result,&["ok","operation","requestDigest","auditEventDigest","idempotentReplay","approval","preparedOriginal","preparedSha256","readyOriginal"])?;
    let result_digest=frame(RESULT,result)?;
    require(result["ok"]==true && result["idempotentReplay"]==false && result["operation"]==OPERATION && result["requestDigest"]==typed["requestDigest"]
        && plan["expectedResult"]==*result && plan["expectedResultDigest"]==result_digest && response["resultDigest"]==result_digest)?;
    let prepared=document(text(result,"preparedOriginal")?.as_bytes(),MAX_PREPARED)?;
    require(result["preparedSha256"]==sha(&prepared)? && prepared["activationId"]==native.request_id && prepared["replayId"]==native.replay_id
        && result["readyOriginal"]==prepared["readyOriginal"])?;
    let intent=&business["request"];
    exact(intent,&["apiVersion","activationId","replayId","canaryId","readinessRequestId","readinessResultSha256","readinessCoreSha256","readyStateSha256",
        "generationPublicationEnvelopeSha256","generationId","publicationBefore","publicationAfter","trustCheckpoint","issuedAtUnixNanos","expiresAtUnixNanos"])?;
    require(intent["apiVersion"]=="serverware.nativePolicyActivationIntent/v1")?;
    for field in ["activationId","replayId","canaryId","readinessRequestId","readinessResultSha256","readinessCoreSha256","readyStateSha256",
        "generationPublicationEnvelopeSha256","generationId","publicationBefore","publicationAfter","trustCheckpoint","issuedAtUnixNanos","expiresAtUnixNanos"]{
        require(intent[field]==prepared[field])?;
    }
    let executed=document(text(originals,"executorCompletionOriginal")?.as_bytes(),MAX_REQUEST)?;
    exact(&executed,&["receipt","receiptDigest","result","resultDigest"])?;let receipt=&executed["receipt"];
    exact(receipt,&["schema","capabilityId","envelopeId","plannerTransactionId","authorizationProjectionDigest","operation","handlerName","requestDigest","resultDigest",
        "authorityRootSetBeforeDigest","authorityRootSetAfterDigest","authoritySnapshotDigest","operationManifestDigest","queryManifestDigest","witnessReservationDigest","witnessSequence",
        "deadlineMonotonicNs","fence","committedAtEpochNs","sourceRevision"])?;
    require(receipt["schema"]=="serverware.policyAuthorityWriterCommitReceipt/v2" && executed["result"]==*result && executed["resultDigest"]==result_digest
        && executed["receiptDigest"]==response["commitReceiptDigest"] && response["commitReceiptDigest"]==frame(text(receipt,"schema")?,receipt)?
        && receipt["handlerName"]==HANDLER && receipt["resultDigest"]==result_digest
        && receipt["authorityRootSetAfterDigest"]==frame("serverware.policyAuthorityRootSet/v1",&transition["businessAfterRoots"])?)?;
    for field in ["operation","requestDigest","capabilityId","plannerTransactionId","authorizationProjectionDigest","authoritySnapshotDigest","authorityRootSetBeforeDigest",
        "operationManifestDigest","queryManifestDigest","deadlineMonotonicNs","fence","sourceRevision"]{require(receipt[field]==measured[field])?;}
    let (earliest,latest)=time.now_interval_unix_nanos()?;
    require(integer(&prepared,"issuedAtUnixNanos")?<=integer(receipt,"committedAtEpochNs")?
        && integer(receipt,"committedAtEpochNs")?<=integer(&response,"issuedAtEpochNs")?
        && integer(&response,"issuedAtEpochNs")?<=latest && earliest>=integer(&prepared,"issuedAtUnixNanos")?
        && latest<integer(&prepared,"expiresAtUnixNanos")? && integer(receipt,"committedAtEpochNs")?<integer(measured,"deadlineEpochNs")?)?;
    witness(authority,originals,&response,receipt)?;
    approval::verify(plan,&business,result,&prepared,verifier,receipt)?;
    let hold=document(text(originals,"nativeEffectHoldOriginal")?.as_bytes(),16384)?;
    exact(&hold,&["scope","phase","canary_id","activation_id","prepared_sha256","prepare_request_digest","configuration_digest","guard_sha256",
        "issued_at_epoch_ns","expires_at_epoch_ns","publication_sha256","finalization_digest"])?;
    require(hold["scope"]=="native-policy-publication" && hold["phase"]=="held" && hold["canary_id"]==prepared["canaryId"]
        && hold["activation_id"]==prepared["activationId"] && hold["prepared_sha256"]==result["preparedSha256"]
        && hold["prepare_request_digest"]==typed["requestDigest"] && hold["configuration_digest"]==request["configurationDigest"]
        && hold["issued_at_epoch_ns"]==prepared["issuedAtUnixNanos"] && hold["expires_at_epoch_ns"]==prepared["expiresAtUnixNanos"]
        && hold["publication_sha256"].is_null() && hold["finalization_digest"].is_null()
        && hold["guard_sha256"]==serde_json::to_value(radix::guard_commitment()?).map_err(fail)?)?;
    let mutations=plan["mutationPlan"].as_array().ok_or(ShadowError::BindingDrift)?;
    let holds=mutations.iter().filter(|m|m["table"]=="policy_native_activation_holds").collect::<Vec<_>>();
    require(holds.len()==1 && holds[0]["row"]==hold && holds[0]["key"]==json!({"scope":"native-policy-publication"})
        && (holds[0]["operation"]=="INSERT" && holds[0]["expectedRow"].is_null()
            || holds[0]["operation"]=="UPDATE" && holds[0]["expectedRow"]["phase"]=="published"))?;
    authority.check(assignment,trust,time)?;Ok(prepared)
}

fn witness(authority:&Authority,originals:&Value,response:&Value,receipt:&Value)->Result<(),ShadowError>{
    let request=document(text(originals,"witnessRequestOriginal")?.as_bytes(),8192)?;
    let witness=document(text(originals,"witnessResponseOriginal")?.as_bytes(),8192)?;
    exact(&request,&["schema","envelopeId","parentEnvelopeId","phase","operation","requestDigest","capabilityId","resultDigest","predecessorReceiptDigest","deadlineMonotonicNs",
        "configurationDigest","operationManifestDigest","generationSequence","generationDigest","issuedAtEpochNs","signature"])?;
    exact(&witness,&["schema","envelopeId","parentEnvelopeId","phase","operation","requestDigest","capabilityId","resultDigest","witnessIdentityDigest","sequence","fence","headDigest",
        "predecessorHeadDigest","predecessorReceiptDigest","logPredecessorHeadDigest","deadlineMonotonicNs","issuedAtEpochNs","generationSequence","generationDigest","canonicalRequestDigest","signature"])?;
    let p=&authority.payload;
    signed(&request,text(&p["roles"]["verifier"],"signingPublicKeyBase64Url")?,"serverware.policyAuthorityReplayWitnessRequest/v2")?;
    signed(&witness,text(&p["replayWitness"],"signingPublicKeyBase64Url")?,"serverware.policyAuthorityReplayWitnessReceipt/v2")?;
    require(request["phase"]=="commit" && witness["phase"]=="commit" && request["configurationDigest"]==serde_json::to_value(&authority.digest).map_err(fail)?
        && request["operationManifestDigest"]==p["operationManifestDigest"] && witness["witnessIdentityDigest"]==p["replayWitness"]["identityDigest"]
        && response["witnessCommitDigest"]==frame("serverware.policyAuthorityReplayWitnessReceipt/v2",&witness)?
        && witness["canonicalRequestDigest"]==frame("serverware.policyAuthorityReplayWitnessRequest/v2",&request)?
        && request["predecessorReceiptDigest"]==receipt["witnessReservationDigest"] && witness["predecessorReceiptDigest"]==request["predecessorReceiptDigest"]
        && witness["fence"]==receipt["fence"] && number(&witness,"sequence")?>number(receipt,"witnessSequence")?)?;
    for field in ["operation","requestDigest","capabilityId","resultDigest","deadlineMonotonicNs"]{require(witness[field]==request[field] && request[field]==receipt[field])?;}
    for field in ["envelopeId","parentEnvelopeId","generationSequence","generationDigest"]{require(witness[field]==request[field])?;}
    require(witness["generationSequence"]==p["generationSequence"] && witness["generationDigest"]==p["generationBindingDigest"])?;
    let mut head=witness.clone();head.as_object_mut().ok_or(ShadowError::BindingDrift)?.remove("signature");head["headDigest"]=Value::Null;
    require(witness["headDigest"]==frame("serverware.policyAuthorityReplayWitnessHead/v2",&head)?)
}
