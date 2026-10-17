//! Bind the actual two-person consumed approval and verifier-signed hardware
//! assertion to the proof-selected rows and committed CAS. This does not
//! replace physical authenticator verification by the independently pinned CP
//! verifier, nor accept an unverified assertion summary from a caller.
use super::*;
fn selected<'a>(plan:&'a Value,table:&str,key:&Value)->Result<&'a Value,ShadowError>{
    let values=plan["selectedBusinessRows"].as_array().ok_or(ShadowError::BindingDrift)?.iter()
        .filter(|v|v["table"]==table && v["key"]==*key).collect::<Vec<_>>();
    require(values.len()==1 && values[0]["present"]==true)?;Ok(&values[0]["row"])
}
fn mutation<'a>(plan:&'a Value,table:&str,key:&Value)->Result<&'a Value,ShadowError>{
    let values=plan["mutationPlan"].as_array().ok_or(ShadowError::BindingDrift)?.iter()
        .filter(|v|v["table"]==table && v["key"]==*key).collect::<Vec<_>>();require(values.len()==1)?;Ok(values[0])
}
fn stored(v:&Value,key:&str,bound:usize)->Result<Value,ShadowError>{document(text(v,key)?.as_bytes(),bound)}
fn role(plan:&Value,subject:&Value)->Result<(),ShadowError>{
    let row=selected(plan,"rbac_role_bindings",&json!({"subject_id":subject}))?;
    let raw=text(row,"roles_json")?.as_bytes();require(raw.len()<=65536)?;
    let value:Value=serde_json::from_slice(raw).map_err(fail)?;
    let roles=if value.is_object(){&value["roles"]}else{&value};
    require(row["status"]=="active" && roles.as_array().ok_or(ShadowError::BindingDrift)?.iter().any(|r|r=="policy_publisher"))
}
pub(super) fn verify(plan:&Value,args:&Value,result:&Value,prepared:&Value,verifier:&Value,receipt:&Value)->Result<(),ShadowError>{
    let consumed=stored(prepared,"approvalOriginal",MAX_PREPARED)?;
    exact(&consumed,&["id","action","resource_id","payload_digest","requester_id","request_json","status","requested_at","expires_at",
        "approved_by","approved_at","consumed_by","consumed_at","decision_note","approver_webauthn_credential_id","approval_authn"])?;
    require(consumed["id"]==args["approval_id"] && consumed["id"]==result["approval"]["id"] && consumed["action"]=="policy.native.activate"
        && consumed["resource_id"]=="native-policy-activation" && consumed["status"]=="consumed"
        && consumed["requester_id"]==args["actor_id"] && consumed["consumed_by"]==args["actor_id"]
        && consumed["approved_by"].is_string() && consumed["approved_by"]!=args["actor_id"]
        && consumed["approved_at"].is_string() && consumed["consumed_at"].is_string() && consumed["approver_webauthn_credential_id"].is_string()
        && stored(&consumed,"request_json",16384)?==args["request"] && consumed["payload_digest"]==sha(&args["request"])?)?;
    role(plan,&consumed["requester_id"])?;role(plan,&consumed["approved_by"])?;
    let prior=stored(args,"approval_original",MAX_PREPARED)?;
    require(prior["status"]=="approved" && selected(plan,"control_plane_approvals",&json!({"id":consumed["id"]}))?==&prior)?;
    let change=mutation(plan,"control_plane_approvals",&json!({"id":consumed["id"]}))?;
    require(change["operation"]=="UPDATE" && change["expectedRow"]==prior && change["row"]==consumed)?;
    let provenance=stored(&consumed,"approval_authn",16384)?;let old_provenance=stored(&prior,"approval_authn",16384)?;
    exact(&provenance,&["schema","requestDigest","requestEvidenceDigest","credentialPolicy","decisionDigest","decisionEvidenceDigest","consumptionDigest","consumptionEvidenceDigest"])?;
    require(provenance["schema"]=="catchplate.nativePolicyActivationApprovalProvenance/v1"
        && provenance["credentialPolicy"]==args["credential_policy"] && provenance["consumptionDigest"]==result["requestDigest"]
        && old_provenance["consumptionDigest"].is_null() && old_provenance["consumptionEvidenceDigest"].is_null())?;
    for field in ["requestDigest","requestEvidenceDigest","decisionDigest","decisionEvidenceDigest"]{digest(&provenance,field)?;}
    let mut expected_provenance=old_provenance.clone();expected_provenance["consumptionDigest"]=provenance["consumptionDigest"].clone();
    expected_provenance["consumptionEvidenceDigest"]=provenance["consumptionEvidenceDigest"].clone();require(expected_provenance==provenance)?;
    let mut expected=prior.clone();for field in ["status","consumed_by","consumed_at","approval_authn"]{expected[field]=consumed[field].clone();}require(expected==consumed)?;
    let mut public=consumed.clone();let object=public.as_object_mut().ok_or(ShadowError::BindingDrift)?;
    object.remove("approval_authn");object.remove("request_json");object.insert("request".into(),args["request"].clone());require(public==result["approval"])?;
    assertion(plan,args,&provenance,verifier,receipt)?;
    let ready=stored(prepared,"readyOriginal",16384)?;
    exact(&ready,&["apiVersion","canaryId","assignmentSha256","previousRevision","previousStateSha256","revision","readinessCoreSha256","readinessResultSha256","expiresAtUnixNanos"])?;
    let readiness=stored(prepared,"readinessOriginal",MAX_PREPARED)?;let core=&readiness["core"];
    require(ready==json!({"apiVersion":"catchplate.nativePolicyReadyState/v1","canaryId":core["canaryId"],"assignmentSha256":core["assignmentSha256"],
        "previousRevision":core["predecessorCanaryRevision"],"previousStateSha256":core["predecessorCanaryStateSha256"],"revision":core["designatedReadyRevision"],
        "readinessCoreSha256":prepared["readinessCoreSha256"],"readinessResultSha256":prepared["readinessResultSha256"],"expiresAtUnixNanos":core["expiresAtUnixNanos"]})
        && sha(&ready)?==prepared["readyStateSha256"] && core["trustCheckpoint"]==prepared["trustCheckpoint"])?;
    let ready_row=selected(plan,"policy_native_canary_ready",&json!({"canary_id":prepared["canaryId"]}))?;
    require(ready_row["ready_original"]==prepared["readyOriginal"] && ready_row["readiness_result_original"]==prepared["readinessOriginal"]
        && ready_row["readiness_request_id"]==prepared["readinessRequestId"] && ready_row["ready_state_digest"]==prepared["readyStateSha256"]
        && ready_row["configuration_digest"]==prepared["controlPlaneConfigurationSha256"] && ready_row["activation_policy_sha256"]==prepared["activationPolicySha256"])?;
    let predecessor=selected(plan,"policy_canary_heads",&json!({"canary_id":prepared["canaryId"]}))?;
    require(predecessor["status"]=="sealing" && predecessor["head_revision"]==ready["previousRevision"] && predecessor["head_state_digest"]==ready["previousStateSha256"])?;
    let head=selected(plan,"policy_native_canary_heads",&json!({"canary_id":prepared["canaryId"]}))?;
    exact(head,&["canary_id","source_profile","predecessor_revision","predecessor_state_digest","head_revision","head_state_digest","status","ready_state_digest","updated_at_epoch_ns"])?;
    require(head["source_profile"]=="native-policy-activation/v1" && head["status"]=="ready" && head["head_revision"]==ready["revision"]
        && head["head_state_digest"]==prepared["readyStateSha256"] && head["ready_state_digest"]==prepared["readyStateSha256"]
        && head["predecessor_revision"]==ready["previousRevision"] && head["predecessor_state_digest"]==ready["previousStateSha256"])?;
    let preparation=mutation(plan,"policy_native_activation_preparations",&json!({"canary_id":prepared["canaryId"]}))?;
    require(preparation["operation"]=="INSERT" && preparation["expectedRow"].is_null())?;
    let row=&preparation["row"];
    exact(row,&["canary_id","activation_id","replay_id","approval_id","requester_id","prepared_original","prepared_sha256","request_digest",
        "audit_outbox_id","audit_event_digest","publication_original","publication_sha256","publication_request_sha256","publication_audit_id","publication_audit_digest"])?;
    require(row["canary_id"]==prepared["canaryId"] && row["activation_id"]==prepared["activationId"] && row["replay_id"]==prepared["replayId"]
        && row["approval_id"]==consumed["id"] && row["requester_id"]==args["actor_id"] && row["prepared_original"]==result["preparedOriginal"]
        && row["prepared_sha256"]==result["preparedSha256"] && row["request_digest"]==result["requestDigest"] && row["audit_event_digest"]==result["auditEventDigest"])?;
    for field in ["publication_original","publication_sha256","publication_request_sha256","publication_audit_id","publication_audit_digest"]{require(row[field].is_null())?;}
    let before=&prepared["publicationBefore"];let after=&prepared["publicationAfter"];
    require(before["policySha256"]==core["currentPublication"]["policy_hash"] && before["policySequence"]==core["currentPublication"]["sequence"]
        && before["rollbackEpoch"]==core["currentPublication"]["rollback_epoch"] && after["policySha256"]==core["policyIdentity"]["candidatePolicySha256"]
        && after["policySequence"]==core["policyIdentity"]["candidatePolicySequence"] && after["rollbackEpoch"]==core["policyIdentity"]["rollbackEpoch"])?;
    let generation=selected(plan,"policy_shadow_generation_publications",&json!({"generation_publication_envelope_digest":prepared["generationPublicationEnvelopeSha256"]}))?;
    let publication=stored(generation,"generation_publication_payload_json",MAX_PREPARED)?;
    require(generation["canary_id"]==prepared["canaryId"] && generation["generation_id_digest"]==prepared["generationId"]
        && generation["assignment_envelope_digest"]==prepared["assignmentSha256"] && publication["custody"]["publicationRevision"]==before["revision"])?;
    // The independent planner signs the complete-row acquisition and its
    // source-fixed kernel. Also require every supplied population to equal
    // the complete authenticated leaves, not a selected subset of revocations.
    let populations=stored(args,"before_original",MAX_REQUEST)?;
    exact(&populations,&radix::population_tables())?;
    for(table,population)in populations.as_object().ok_or(ShadowError::BindingDrift)?{
        let rows=population.as_array().ok_or(ShadowError::BindingDrift)?;
        let roots=plan["rootTransition"]["businessBeforeRoots"].as_array().ok_or(ShadowError::BindingDrift)?.iter()
            .chain(plan["rootTransition"]["authorizationBeforeRoots"].as_array().ok_or(ShadowError::BindingDrift)?);
        let roots=roots.filter(|r|r["table"]==*table).collect::<Vec<_>>();require(roots.len()==1 && number(roots[0],"leafCount")?==rows.len() as u64)?;
        let present=plan["selectedBusinessRows"].as_array().ok_or(ShadowError::BindingDrift)?.iter()
            .filter(|r|r["table"]==*table && r["present"]==true).map(|r|&r["row"]).collect::<Vec<_>>();
        require(present.len()==rows.len() && rows.iter().all(|row|present.iter().filter(|v|**v==row).count()==1))?;
    }
    Ok(())
}

fn assertion(plan:&Value,args:&Value,provenance:&Value,verifier:&Value,receipt:&Value)->Result<(),ShadowError>{
    let e=&plan["webauthnEvidence"];let m=&plan["measuredPlan"];
    exact(e,&["operation","operationId","requestDigest","capabilityId","challengeId","challengeDigest","clientChallengeDigest","credentialRecordId","credentialId",
        "credentialPolicyDigest","authenticatorDataBase64url","authenticatorDataDigest","clientDataJSONBase64url","clientDataJSONDigest","signatureBase64url","signatureDigest",
        "rpId","rpIdHashDigest","origin","flags","userPresent","userVerified","priorCounter","counter","trustHighWaterDigest","metadataPublicationSequence",
        "verifierSessionIdentityDigest","verifierMeasurementDigest","verifierAttestationReceiptDigest","verifiedAssertionReceiptDigest","verifierSignatureBase64url",
        "verifierSignatureDigest","verifiedAtEpochNs","expiresAtEpochNs"])?;
    for field in ["operation","operationId","requestDigest","capabilityId"]{require(e[field]==m[field])?;}
    require(digest(e,"verifierSessionIdentityDigest")?==framed("catchplate.policyAuthorityVerifierSession/v2",&[
        text(args,"control_plane_configuration_digest")?.as_bytes(),text(verifier,"measurementDigest")?.as_bytes(),text(verifier,"attestationReceiptDigest")?.as_bytes()]))?;
    for(a,b)in [("verifierMeasurementDigest","measurementDigest"),("verifierAttestationReceiptDigest","attestationReceiptDigest")]{
        require(e[a]==verifier[b])?;}
    let mut unsigned=e.clone();let object=unsigned.as_object_mut().ok_or(ShadowError::BindingDrift)?;
    for name in ["verifiedAssertionReceiptDigest","verifierSignatureBase64url","verifierSignatureDigest"]{object.remove(name);}
    let receipt_digest=framed("catchplate.policyAuthorityVerifiedWebAuthnAssertionReceipt/v1",&[&canonical_json_bytes(&unsigned)?]);
    let signature=decode(text(e,"verifierSignatureBase64url")?,64)?;
    require(digest(e,"verifiedAssertionReceiptDigest")?==receipt_digest && digest(e,"verifierSignatureDigest")?==Sha256Digest::compute(&signature)
        && e["verifiedAssertionReceiptDigest"]==provenance["consumptionEvidenceDigest"])?;
    verify_signature(text(verifier,"signingPublicKeyBase64Url")?,text(e,"verifierSignatureBase64url")?,receipt_digest.as_str().as_bytes())?;
    let policy=&args["credential_policy"];
    exact(policy,&["rpId","origins","allowedAuthenticatorClasses","hardwareRequired","requireUserPresence","requireUserVerification","maxAssertionAgeSeconds"])?;
    require(policy["hardwareRequired"]==true && policy["requireUserPresence"]==true && policy["requireUserVerification"]==true
        && e["userPresent"]==true && e["userVerified"]==true && e["rpId"]==policy["rpId"]
        && policy["origins"].as_array().ok_or(ShadowError::BindingDrift)?.contains(&e["origin"])
        && (1..=120).contains(&number(policy,"maxAssertionAgeSeconds")?)
        && integer(e,"verifiedAtEpochNs")?<=integer(receipt,"committedAtEpochNs")?
        && integer(receipt,"committedAtEpochNs")?<integer(e,"expiresAtEpochNs")?
        && integer(e,"expiresAtEpochNs")?-integer(e,"verifiedAtEpochNs")?<=integer(policy,"maxAssertionAgeSeconds")?*1_000_000_000
        && number(e,"priorCounter")?<number(e,"counter")? && number(e,"counter")?<=2_147_483_647 && number(e,"flags")?<=255 && number(e,"flags")?&5==5)?;
    let authenticator=decode(text(e,"authenticatorDataBase64url")?,65536)?;let client=decode(text(e,"clientDataJSONBase64url")?,65536)?;
    let signature=decode(text(e,"signatureBase64url")?,65536)?;let rp=Sha256::digest(text(e,"rpId")?.as_bytes());
    require(authenticator.len()>=37 && authenticator[..32]==rp[..] && u64::from(authenticator[32])==number(e,"flags")?
        && u64::from(u32::from_be_bytes(authenticator[33..37].try_into().map_err(fail)?))==number(e,"counter")?
        && digest(e,"authenticatorDataDigest")?==Sha256Digest::compute(&authenticator) && digest(e,"clientDataJSONDigest")?==Sha256Digest::compute(&client)
        && digest(e,"signatureDigest")?==Sha256Digest::compute(&signature) && digest(e,"rpIdHashDigest")?==Sha256Digest::compute(text(e,"rpId")?.as_bytes()))?;
    let client:Value=serde_json::from_slice(&client).map_err(fail)?;exact(&client,&["type","challenge","origin","crossOrigin"])?;
    require(client["type"]=="webauthn.get" && client["origin"]==e["origin"] && client["crossOrigin"]==false
        && digest(e,"clientChallengeDigest")?==Sha256Digest::compute(&decode(text(&client,"challenge")?,65536)?))?;
    let credential=selected(plan,"webauthn_credentials",&json!({"id":e["credentialRecordId"]}))?;
    let challenge=selected(plan,"webauthn_challenges",&json!({"id":e["challengeId"]}))?;
    require(credential["user_id"]==args["actor_id"] && challenge["user_id"]==args["actor_id"] && credential["credential_id"]==e["credentialId"]
        && credential["sign_count"]==e["priorCounter"] && credential["revoked_at"].is_null() && challenge["used_at"].is_null()
        && challenge["challenge_type"]=="policy_authority" && challenge["scope_key"]==m["operationId"]
        && (credential["attestation_trusted"]==true||credential["attestation_trusted"]==1)
        && credential["attestation_leaf_sha256"].is_string() && credential["attestation_root_sha256"].is_string())?;
    let class=text(credential,"authenticator_class")?;let allowed=policy["allowedAuthenticatorClasses"].as_array().ok_or(ShadowError::BindingDrift)?;
    require(["hardware","yubikey"].contains(&class) && (allowed.iter().any(|v|v==class)||class=="yubikey"&&allowed.iter().any(|v|v=="hardware")))?;
    for(table,id,before)in [("webauthn_credentials",&e["credentialRecordId"],credential),("webauthn_challenges",&e["challengeId"],challenge)]{
        let change=mutation(plan,table,&json!({"id":id}))?;require(change["operation"]=="UPDATE" && change["expectedRow"]==*before)?;
        let mut expected=before.clone();if table=="webauthn_credentials"{expected["sign_count"]=e["counter"].clone();
            expected["last_used_at"]=change["row"]["last_used_at"].clone();expected["updated_at"]=change["row"]["updated_at"].clone();}
        else{expected["used_at"]=change["row"]["used_at"].clone();require(expected["used_at"].is_string())?;}
        require(change["row"]==expected)?;
    }
    let projection=&plan["authorizationProjection"];
    exact(projection,&["plannerTransactionId","operation","operationId","requestDigest","capabilityId","authorizationReads","sourceRows","sourceHighWaterDigest",
        "approverPolicyDigest","assertionEvidenceDigest","verifierSessionIdentityDigest","verifierMeasurementDigest","verifierAttestationReceiptDigest","createdAtEpochNs","expiresAtEpochNs"])?;
    for name in ["plannerTransactionId","operation","operationId","requestDigest","capabilityId"]{require(projection[name]==m[name])?;}
    for name in ["verifierSessionIdentityDigest","verifierMeasurementDigest","verifierAttestationReceiptDigest"]{require(projection[name]==e[name])?;}
    require(projection["assertionEvidenceDigest"]==e["verifiedAssertionReceiptDigest"] && projection["approverPolicyDigest"].is_null()
        && integer(projection,"createdAtEpochNs")?<=integer(receipt,"committedAtEpochNs")?
        && integer(receipt,"committedAtEpochNs")?<integer(projection,"expiresAtEpochNs")?)
}
