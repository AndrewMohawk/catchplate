use super::{configuration::{Authority,signed,verify},radix,wire::*};
use serde_json::{Value,json};
use std::collections::BTreeMap;

const RUNTIME_REQUEST:&str="catchplate.policyAuthorityRuntimeRequest/v2";
const PLAN_SCHEMA:&str="catchplate.signedPolicyAuthorityMeasuredPlan/v3";
const RESULT_SCHEMA:&str="catchplate.policyAuthorityControlledWriterResult/v2";
const COMPLETION_SCHEMA:&str="catchplate.policyCanaryDeliveryCompletionOriginal/v1";
const SLOT:&str="policy_canary_delivery_slots";
const HEAD:&str="policy_canary_delivery_heads";
const PART:&str="policy_canary_delivery_parts";
const BATCH:&str="policy_canary_intake_batches";

/// Authenticated data, not contact permission. Constructors are private; a
/// completed historical/new-boot recover is never promoted into a claim.
pub struct Observation { status:String, slot:Value, head:Value, http:Option<String>, intake:Value }
impl Observation {
    pub fn status(&self)->&str{&self.status}
    pub fn slot(&self)->&Value{&self.slot}
    pub fn head(&self)->&Value{&self.head}
    pub fn http_original(&self)->Option<&str>{self.http.as_deref()}
    pub fn intake(&self)->&Value{&self.intake}
}
pub struct Completion { original:String, observation:Observation, operation:Operation, statement:Value,
    request:Value, deadline:u64, pid:u32 }
impl Completion {
    pub fn original(&self)->&str{&self.original}
    pub fn observation(&self)->&Observation{&self.observation}
    pub fn operation(&self)->Operation{self.operation}
    pub fn verify(authority:&Authority,command:&Signed,raw:&[u8])->Result<Self,String>{
        authority.check()?;command.check()?;
        let http=document(raw,MAX_RESPONSE)?;exact(&http,&["apiVersion","requestOriginal","responseOriginal"])?;
        require(http["apiVersion"]=="catchplate.policyCanaryDeliveryResponse/v1","delivery HTTP response profile")?;
        let request_raw=decode(text(&http,"requestOriginal")?,MAX_ARGUMENT)?;
        let response_raw=decode(text(&http,"responseOriginal")?,MAX_RESPONSE)?;
        let request=document(&request_raw,MAX_ARGUMENT)?;let response=document(&response_raw,MAX_RESPONSE)?;
        let sent=document(command.original(),MAX_ARGUMENT)?;
        exact(&request,&["schema","requestId","operation","input","configurationDigest","operationManifestDigest","startedMonotonicNs","deadlineMonotonicNs"])?;
        exact(&response,&["schema","requestId","operation","configurationDigest","requestDigest","issuedAtEpochNs","deadlineMonotonicNs","fence","result","resultDigest",
            "commitReceiptDigest","witnessCommitDigest","attestationReceiptDigest","attestationConsumptionReceipt","attestationConsumptionReceiptDigest","signature","authorityConfigurationOriginal","deliveryOriginals"])?;
        let operation=command.operation();let handler=format!("catchplate_policy_authority_policy_canary_delivery_{}",operation.phase());
        let payload=&authority.payload;let manifest=&payload["operationManifestDigest"];
        require(request["schema"]==RUNTIME_REQUEST && request["operation"]==operation.label() && response["operation"]==request["operation"]
            && response["schema"]==RESPONSE && request["configurationDigest"]==authority.digest && response["configurationDigest"]==authority.digest
            && request["operationManifestDigest"]==*manifest && response["requestId"]==request["requestId"]
            && response["requestDigest"]==framed(RUNTIME_REQUEST,&[&request_raw]) && response["deadlineMonotonicNs"]==request["deadlineMonotonicNs"]
            && number(&response,"fence")?>0 && number(&request,"startedMonotonicNs")?<number(&request,"deadlineMonotonicNs")?
            && decode(text(&response,"authorityConfigurationOriginal")?,3*1024*1024)?==authority.original,"delivery original request/configuration scope")?;
        let verifier=&payload["roles"]["verifier"];let planner=&payload["roles"]["planner"];
        signed(&response,text(verifier,"signingPublicKeyBase64Url")?,RESPONSE)?;
        require(response["attestationReceiptDigest"]==verifier["attestationReceiptDigest"]
            && response["attestationConsumptionReceiptDigest"]==framed(text(&response["attestationConsumptionReceipt"],"schema")?,&[&ascii(&response["attestationConsumptionReceipt"])?]),"delivery retained verifier admission receipt")?;
        exact(&request["input"],&["schema","handler","operationManifestDigest","arguments"])?;
        let args=&request["input"]["arguments"];
        exact(args,&["control_plane_configuration_digest","request","native_evidence"])?;
        require(request["input"]["schema"]=="catchplate.policyAuthorityControlledWriterInput/v1" && request["input"]["handler"]==handler
            && request["input"]["operationManifestDigest"]==*manifest && args["control_plane_configuration_digest"]==authority.digest
            && args["request"]==sent["request"] && args["native_evidence"]==sent["nativeEvidence"],"delivery completion substituted exact native command")?;
        let statement=args["native_evidence"]["statement"].clone();authority.require_sender(&statement,true)?;
        require(number(&statement,"issuedAtEpochNs")?<=number(&response,"issuedAtEpochNs")?
            && number(&response,"issuedAtEpochNs")?<number(&statement,"expiresAtEpochNs")?
            && number(&response,"issuedAtEpochNs")?<=crate::native_canary_evidence_v1::now_epoch()?,"delivery original response interval")?;
        let originals=&response["deliveryOriginals"];
        exact(originals,&["signedMeasuredPlanOriginal","executorCompletionOriginal","witnessRequestOriginal","witnessResponseOriginal"])?;
        let signed_plan=document(text(originals,"signedMeasuredPlanOriginal")?.as_bytes(),MAX_RESPONSE)?;
        exact(&signed_plan,&["schema","payload","signatureBase64Url"])?;
        require(signed_plan["schema"]==PLAN_SCHEMA,"delivery signed plan schema")?;
        verify(text(planner,"signingPublicKeyBase64Url")?,text(&signed_plan,"signatureBase64Url")?,framed(PLAN_SCHEMA,&[&ascii(&signed_plan["payload"])?]).as_bytes())?;
        let plan=&signed_plan["payload"];
        exact(plan,&["schema","measuredPlan","typedRequest","selectedBusinessRows","mutationPlan","queryMultiproofs","queryMultiproofsDigest","plannerTrace","plannerTraceDigest",
            "authorizationProjection","webauthnEvidence","expectedResult","expectedResultDigest","plannerIdentity","rootTransition"])?;
        require(plan["schema"]=="catchplate.policyAuthorityPlannerResponse/v3" && plan["webauthnEvidence"].is_null()
            && plan["plannerIdentity"]==json!({"sessionIdentityDigest":planner["plannerSessionIdentityDigest"],"measurementDigest":planner["measurementDigest"],
                "attestationReceiptDigest":planner["attestationReceiptDigest"]}),"delivery actual planner admission")?;
        let measured=&plan["measuredPlan"];let typed=&plan["typedRequest"];
        exact(measured,&["schema","plannerTransactionId","operation","operationId","requestDigest","capabilityId","sourceRevision","authoritySchemaVersion","operationContractDigest",
            "operationManifestDigest","handlerContractDigest","queryManifestDigest","selectedBusinessRowsDigest","mutationPlanDigest","workUnits","authorityRootSetBeforeDigest",
            "authorizationProjectionDigest","authoritySnapshotDigest","rootTransitionDigest","deadlineMonotonicNs","deadlineEpochNs","fence"])?;
        exact(typed,&["schema","operation","operationId","requestDigest","handler","operationManifestDigest","arguments"])?;
        let mut typed_args=args.clone();typed_args.as_object_mut().ok_or("delivery arguments")?.insert("businessIntent".into(),json!({"schema":"catchplate.policyAuthorityBusinessIntent/v2",
            "operation":operation.label(),"planningAdapterId":format!("catchplate.policyAuthorityPlanningAdapter/{handler}/v1"),"arguments":args}));
        let request_digest=framed("catchplate.policyAuthorityV9Request/v1",&[&ascii(&json!({"schema":"catchplate.policyAuthorityV9Authorization/v1","operation":operation.label(),
            "handler":handler,"operationManifestDigest":manifest,"arguments":typed_args}))?]);
        let operation_id=framed("catchplate.policyAuthorityOperation/v2",&[operation.label().as_bytes(),request_digest.as_bytes()]);
        require(typed["schema"]=="catchplate.policyAuthorityV9Request/v1" && typed["handler"]==handler && typed["arguments"]==typed_args
            && typed["operation"]==operation.label() && typed["operationManifestDigest"]==*manifest && typed["requestDigest"]==request_digest && typed["operationId"]==operation_id
            && measured["schema"]=="catchplate.policyAuthorityMeasuredPlan/v3" && measured["authoritySchemaVersion"]==9
            && (1..=8194).contains(&number(measured,"workUnits")?) && measured["operation"]==operation.label() && measured["operationId"]==operation_id
            && measured["requestDigest"]==request_digest && measured["sourceRevision"]==payload["sourceRevision"] && measured["operationManifestDigest"]==*manifest
            && measured["operationContractDigest"]==*manifest && measured["queryManifestDigest"]==payload["queryManifestDigest"]
            && measured["fence"]==response["fence"] && measured["deadlineMonotonicNs"]==response["deadlineMonotonicNs"],"delivery measured source/request contract")?;
        require(measured["handlerContractDigest"]==radix::handler_commitment(operation,text(payload,"sourceRevision")?)?,"delivery exact source handler contract")?;
        radix::verify(operation,plan)?;
        let transition=&plan["rootTransition"];
        for(field,domain,value)in [("rootTransitionDigest","catchplate.policyAuthorityPrimaryRootTransition/v1",transition),
            ("selectedBusinessRowsDigest","catchplate.policyAuthoritySelectedBusinessRows/v1",&plan["selectedBusinessRows"]),
            ("mutationPlanDigest","catchplate.policyAuthorityMutationPlan/v3",&plan["mutationPlan"]),
            ("authorityRootSetBeforeDigest","catchplate.policyAuthorityRootSet/v1",&transition["businessBeforeRoots"]) ] {
            require(measured[field]==framed(domain,&[&ascii(value)?]),"delivery measured original digest")?;
        }
        require(plan["queryMultiproofsDigest"]==framed("catchplate.policyAuthorityRadixMultiproofSet/v3",&[&ascii(&plan["queryMultiproofs"])?])
            && plan["plannerTraceDigest"]==framed("catchplate.policyAuthorityPlannerTrace/v1",&[&ascii(&plan["plannerTrace"])?]),"delivery retained proof/trace digest")?;
        let projection=&plan["authorizationProjection"];
        require(projection["sourceRows"]==json!([]) && projection["authorizationReads"]==json!([])
            && projection["sourceHighWaterDigest"]==framed("catchplate.policyAuthorityAuthorizationRootSet/v1",&[b"[]"])
            && measured["authorizationProjectionDigest"]==framed("catchplate.policyAuthorityAuthorizationProjection/v1",&[&ascii(projection)?]),"delivery authorization projection")?;
        require(measured["plannerTransactionId"]==framed("catchplate.policyAuthorityPlannerTransaction/v1",&[operation_id.as_bytes(),request_digest.as_bytes(),text(measured,"capabilityId")?.as_bytes()]),"delivery planner transaction identity")?;
        let fields=["operation","operationId","requestDigest","queryManifestDigest","authorityRootSetBeforeDigest","authorizationProjectionDigest","selectedBusinessRowsDigest","mutationPlanDigest","rootTransitionDigest"];
        let frames=fields.iter().map(|name|text(measured,name).map(str::as_bytes)).collect::<Result<Vec<_>,_>>()?;
        require(measured["authoritySnapshotDigest"]==framed("catchplate.policyAuthoritySnapshot/v3",&frames),"delivery complete snapshot digest")?;
        let result=&response["result"];
        exact(result,&["ok","operation","requestDigest","auditEventDigest","idempotentReplay","status","observation"])?;
        let result_digest=framed(RESULT_SCHEMA,&[&ascii(result)?]);
        require(result["ok"]==true && result["idempotentReplay"]==false && result["operation"]==operation.label() && result["requestDigest"]==request_digest
            && plan["expectedResult"]==*result && plan["expectedResultDigest"]==result_digest && response["resultDigest"]==result_digest,"delivery actual controlled result")?;
        let executed=document(text(originals,"executorCompletionOriginal")?.as_bytes(),MAX_RESPONSE)?;
        exact(&executed,&["receipt","receiptDigest","result","resultDigest"])?;let receipt=&executed["receipt"];
        exact(receipt,&["schema","capabilityId","envelopeId","plannerTransactionId","authorizationProjectionDigest","operation","handlerName","requestDigest","resultDigest",
            "authorityRootSetBeforeDigest","authorityRootSetAfterDigest","authoritySnapshotDigest","operationManifestDigest","queryManifestDigest","witnessReservationDigest","witnessSequence",
            "deadlineMonotonicNs","fence","committedAtEpochNs","sourceRevision"])?;
        require(receipt["schema"]=="catchplate.policyAuthorityWriterCommitReceipt/v2" && executed["result"]==*result && executed["resultDigest"]==result_digest
            && executed["receiptDigest"]==response["commitReceiptDigest"] && response["commitReceiptDigest"]==framed(text(receipt,"schema")?,&[&ascii(receipt)?])
            && receipt["handlerName"]==handler && receipt["resultDigest"]==result_digest
            && receipt["authorityRootSetAfterDigest"]==framed("catchplate.policyAuthorityRootSet/v1",&[&ascii(&transition["businessAfterRoots"])?]),"delivery actual executor commit original")?;
        for field in ["operation","requestDigest","capabilityId","plannerTransactionId","authorizationProjectionDigest","authoritySnapshotDigest","authorityRootSetBeforeDigest",
            "operationManifestDigest","queryManifestDigest","deadlineMonotonicNs","fence","sourceRevision"]{require(receipt[field]==measured[field],"delivery executor/planner binding")?;}
        require(ascii(receipt)?.len()<=8192 && number(&statement,"issuedAtEpochNs")?<=number(receipt,"committedAtEpochNs")?
            && number(receipt,"committedAtEpochNs")?<=number(&response,"issuedAtEpochNs")? && number(receipt,"committedAtEpochNs")?<number(measured,"deadlineEpochNs")?,"delivery committed original deadline")?;
        verify_witness(authority,originals,&response,receipt)?;
        let observation=observe(operation,plan,result,&statement)?;
        if operation==Operation::Claim {
            let slot=&observation.slot;
            require(observation.status=="claimed" && slot["claim_request_digest"]==request_digest
                && slot["claim_evidence_original"]==String::from_utf8(ascii(&args["native_evidence"])?).map_err(|_|"delivery claim evidence ASCII")?
                && slot["prepare_completion_sha256"]==crate::sha256_prefixed(text(&sent["request"],"prepareCompletionOriginal")?.as_bytes())
                && slot["read_completion_sha256"]==crate::sha256_prefixed(text(&sent["request"],"readCompletionOriginal")?.as_bytes()),"delivery committed exact claim originals")?;
        }
        let original=String::from_utf8(ascii(&json!({"schema":COMPLETION_SCHEMA,"requestOriginal":String::from_utf8(request_raw).map_err(|_|"delivery request ASCII")?,
            "responseOriginal":String::from_utf8(response_raw).map_err(|_|"delivery response ASCII")?}))?).map_err(|_|"delivery completion ASCII")?;
        if operation!=Operation::Claim { require(original.len()<=MAX_COMPLETION,"delivery future claim completion bound")?; }
        command.check()?;authority.check()?;
        Ok(Self {original,observation,operation,statement,request:sent["request"].clone(),deadline:command.deadline(),pid:std::process::id()})
    }
    pub fn claim_request(&self,first:&Completion)->Result<Value,String>{
        require(self.operation==Operation::Recover && [Operation::Prepare,Operation::Recover].contains(&first.operation)
            && self.observation.status=="prepared" && first.observation.status=="prepared" && self.pid==std::process::id() && first.pid==self.pid
            && self.observation.slot==first.observation.slot && self.observation.head==first.observation.head
            && self.observation.http==first.observation.http,"delivery actual prepared and readback originals")?;
        for field in ["holderId","bootId","keyId","purposeAssignmentSha256","slotId","httpSha256","originalExpiresAtEpochNs"] {
            require(self.statement[field]==first.statement[field],"delivery proof cannot transfer ownership")?;
        }
        require(crate::native_canary_evidence_v1::now_epoch()?<number(&self.observation.slot,"expires_at_epoch_ns")?,"delivery original slot expired")?;
        Ok(json!({"slotId":self.observation.slot["id"],"httpSha256":self.observation.slot["http_sha256"],"partCount":self.observation.slot["part_count"],
            "slotSha256":crate::sha256_prefixed(&ascii(&self.observation.slot)?),"headSha256":crate::sha256_prefixed(&ascii(&self.observation.head)?),
            "prepareCompletionOriginal":first.original,"readCompletionOriginal":self.original}))
    }
    pub(crate) fn contact_original(&self,intake:&crate::native_canary_evidence_v1::SignedEvidence)->Result<&str,String>{
        intake.check()?;let original=self.observation.http.as_deref().ok_or("claim original absent")?;
        require(self.operation==Operation::Claim && self.observation.status=="claimed" && self.pid==std::process::id()
            && crate::native_canary_evidence_v1::now_boot()?<self.deadline && original.as_bytes()==intake.original()
            && self.statement["httpSha256"]==crate::sha256_prefixed(intake.original())
            && self.request["slotSha256"].is_string() && self.request["headSha256"].is_string(),"only definite original claim permits one contact")?;
        Ok(original)
    }
}

fn verify_witness(authority:&Authority,originals:&Value,response:&Value,receipt:&Value)->Result<(),String>{
    let request_raw=text(originals,"witnessRequestOriginal")?.as_bytes();let request=document(request_raw,8192)?;
    let witness=document(text(originals,"witnessResponseOriginal")?.as_bytes(),8192)?;
    exact(&request,&["schema","envelopeId","parentEnvelopeId","phase","operation","requestDigest","capabilityId","resultDigest","predecessorReceiptDigest","deadlineMonotonicNs",
        "configurationDigest","operationManifestDigest","generationSequence","generationDigest","issuedAtEpochNs","signature"])?;
    exact(&witness,&["schema","envelopeId","parentEnvelopeId","phase","operation","requestDigest","capabilityId","resultDigest","witnessIdentityDigest","sequence","fence","headDigest",
        "predecessorHeadDigest","predecessorReceiptDigest","logPredecessorHeadDigest","deadlineMonotonicNs","issuedAtEpochNs","generationSequence","generationDigest","canonicalRequestDigest","signature"])?;
    let payload=&authority.payload;
    signed(&request,text(&payload["roles"]["verifier"],"signingPublicKeyBase64Url")?,"catchplate.policyAuthorityReplayWitnessRequest/v2")?;
    signed(&witness,text(&payload["replayWitness"],"signingPublicKeyBase64Url")?,"catchplate.policyAuthorityReplayWitnessReceipt/v2")?;
    require(request["phase"]=="commit" && witness["phase"]=="commit" && request["configurationDigest"]==authority.digest
        && request["operationManifestDigest"]==payload["operationManifestDigest"] && witness["witnessIdentityDigest"]==payload["replayWitness"]["identityDigest"]
        && response["witnessCommitDigest"]==framed("catchplate.policyAuthorityReplayWitnessReceipt/v2",&[&ascii(&witness)?])
        && witness["canonicalRequestDigest"]==framed("catchplate.policyAuthorityReplayWitnessRequest/v2",&[request_raw])
        && request["predecessorReceiptDigest"]==receipt["witnessReservationDigest"] && witness["predecessorReceiptDigest"]==request["predecessorReceiptDigest"]
        && witness["fence"]==receipt["fence"] && number(&witness,"sequence")?>number(receipt,"witnessSequence")?,"delivery independent witness terminal original")?;
    for field in ["operation","requestDigest","capabilityId","resultDigest","deadlineMonotonicNs"]{require(witness[field]==request[field] && request[field]==receipt[field],"delivery witness/executor original")?;}
    for field in ["envelopeId","parentEnvelopeId","generationSequence","generationDigest"]{require(witness[field]==request[field],"delivery witness generation identity")?;}
    require(witness["generationSequence"]==payload["generationSequence"] && witness["generationDigest"]==payload["generationBindingDigest"],"delivery current enrolled generation")?;
    let mut head=witness.clone();head.as_object_mut().ok_or("delivery witness object")?.remove("signature");head["headDigest"]=Value::Null;
    require(witness["headDigest"]==framed("catchplate.policyAuthorityReplayWitnessHead/v2",&[&ascii(&head)?]),"delivery exact external witness head")
}

fn observe(operation:Operation,plan:&Value,result:&Value,statement:&Value)->Result<Observation,String>{
    let observation=&result["observation"];exact(observation,&["slotOriginal","headOriginal","httpOriginal","intakeOriginal"])?;
    let status=text(result,"status")?.to_owned();require(["unknown","prepared","claimed","consumed"].contains(&status.as_str()),"delivery status")?;
    let mut rows=BTreeMap::new();
    for selected in plan["selectedBusinessRows"].as_array().ok_or("delivery selected originals")? {
        rows.insert((text(selected,"table")?.to_owned(),ascii(&selected["key"])?),if selected["present"]==true{selected["row"].clone()}else{Value::Null});
    }
    for mutation in plan["mutationPlan"].as_array().ok_or("delivery changed originals")? {
        let table=text(mutation,"table")?;
        require(operation!=Operation::Recover || ![SLOT,HEAD,PART,BATCH].contains(&table),"delivery recovery cannot change authority")?;
        rows.insert((table.to_owned(),ascii(&mutation["key"])?),mutation["row"].clone());
    }
    let expected_head=crate::sha256_prefixed(&[b"catchplate/canary-delivery-head/v1\0".as_slice(),&ascii(&json!([statement["deploymentId"],statement["canaryId"],statement["instanceId"]]))?].concat());
    let slot=rows.get(&(SLOT.into(),ascii(&json!({"id":statement["slotId"]}))?)).ok_or("delivery slot proof absent")?.clone();
    let head=rows.get(&(HEAD.into(),ascii(&json!({"id":expected_head}))?)).ok_or("delivery head proof absent")?.clone();
    for(field,value)in [("slotOriginal",&slot),("headOriginal",&head)] {
        require(if value.is_null(){observation[field].is_null()}else{observation[field]==String::from_utf8(ascii(value)?).map_err(|_|"delivery row ASCII")?},"delivery authenticated row differs from observation")?;
    }
    if status=="unknown"{
        require(slot.is_null() && observation["httpOriginal"].is_null() && observation["intakeOriginal"].is_null(),"delivery unknown must prove exact absence")?;
        return Ok(Observation{status,slot,head,http:None,intake:Value::Null});
    }
    exact(&slot,&["id","head_id","deployment_id","canary_id","instance_id","holder_id","native_boot_id","key_id","delivery_assignment_digest","intake_assignment_digest",
        "canary_assignment_digest","canary_boot_id","configuration_digest","http_sha256","http_byte_count","part_count","status","prepare_request_digest","prepare_evidence_original",
        "claim_request_digest","claim_evidence_original","prepare_completion_sha256","read_completion_sha256","intake_request_digest","intake_result_sha256","issued_at_epoch_ns","expires_at_epoch_ns","created_at","updated_at"])?;
    exact(&head,&["id","deployment_id","canary_id","instance_id","sequence","slot_id","status","updated_at"])?;
    require(slot["status"]==status && slot["head_id"]==expected_head && head["id"]==expected_head && number(&head,"sequence")?>0
        && (status=="consumed" || head["status"]==status && head["slot_id"]==slot["id"]),"delivery immutable head/slot lineage")?;
    for(field,signed)in [("deployment_id","deploymentId"),("canary_id","canaryId"),("instance_id","instanceId")]{
        require(slot[field]==statement[signed] && head[field]==statement[signed],"delivery observed scope changed")?;
    }
    require(slot["expires_at_epoch_ns"]==statement["originalExpiresAtEpochNs"] && slot["http_sha256"]==statement["httpSha256"],"delivery original scope/expiry")?;
    let count=number(&slot,"part_count")?;require((1..=20).contains(&count),"delivery part count")?;
    let mut http=String::new();for ordinal in 0..count{
        let row=rows.get(&(PART.into(),ascii(&json!({"slot_id":slot["id"],"ordinal":ordinal}))?)).ok_or("delivery durable part proof absent")?;
        exact(row,&["slot_id","ordinal","original","original_sha256"])?;let raw=text(row,"original")?;
        require(row["slot_id"]==slot["id"] && number(row,"ordinal")?==ordinal && raw.is_ascii() && !raw.is_empty() && raw.len()<=PART_BYTES
            && (ordinal+1==count || raw.len()==PART_BYTES) && row["original_sha256"]==crate::sha256_prefixed(raw.as_bytes()),"delivery exact immutable part")?;http.push_str(raw);
    }
    require(http.len()<=crate::native_canary_evidence_v1::MAX_HTTP && http.len() as u64==number(&slot,"http_byte_count")?
        && count==http.len().div_ceil(PART_BYTES) as u64 && slot["http_sha256"]==crate::sha256_prefixed(http.as_bytes())
        && observation["httpOriginal"]==http,"delivery reassembled original")?;
    let selector=Selector::from_http(http.as_bytes())?;require(slot["id"]==selector.slot_id,"delivery intake request identity")?;
    let intake=if status=="consumed"{
        let row=rows.get(&(BATCH.into(),ascii(&json!({"request_id":slot["id"]}))?)).ok_or("delivery consumed intake proof absent")?;
        require(!row.is_null() && observation["intakeOriginal"]==String::from_utf8(ascii(row)?).map_err(|_|"delivery intake ASCII")?
            && row["request_digest"]==slot["intake_request_digest"] && crate::sha256_prefixed(text(row,"result_original")?.as_bytes())==slot["intake_result_sha256"],"delivery committed intake binding")?;row.clone()
    }else{require(observation["intakeOriginal"].is_null(),"delivery unconsumed intake projection")?;Value::Null};
    Ok(Observation{status,slot,head,http:Some(http),intake})
}
