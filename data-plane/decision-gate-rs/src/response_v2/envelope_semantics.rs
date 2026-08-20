use super::*;

pub(super) fn response_observation_v2_verify_nested_authority_semantics(
    client: &ResponseObservationV2Client,
    descriptor:
        &serverware_decision_gate::CanonicalAuthorityEnvelopeDescriptorV2,
    inspection: &SignedV2ImmutableResponseInspectionV1,
    release_preparation: &SignedV2ExactReleasePreparationV1,
) -> Result<(), ResponseObservationV2TransactionError> {
    verify_nested_authority_semantics(
        client,
        &descriptor.authority_envelope.body,
        &descriptor.authority_envelope.authority_artifacts,
        &descriptor.public_envelope,
        &descriptor.finalization_id,
        inspection,
        release_preparation,
    )
}

pub(super) fn response_observation_v2_preverify_nested_authority_semantics(
    client: &ResponseObservationV2Client,
    proof:
        &serverware_decision_gate::CanonicalAuthorityEnvelopeProofInputV2,
    inspection: &SignedV2ImmutableResponseInspectionV1,
    release_preparation: &SignedV2ExactReleasePreparationV1,
) -> Result<(), ResponseObservationV2TransactionError> {
    verify_nested_authority_semantics(
        client,
        &proof.authority_body,
        &proof.authority_artifacts,
        &proof.public_envelope,
        &proof.finalization_id,
        inspection,
        release_preparation,
    )
}

fn verify_nested_authority_semantics(
    client: &ResponseObservationV2Client,
    body: &serverware_decision_gate::CanonicalFinalEnvelopeBody,
    artifacts: &[serverware_decision_gate::SignedAuthorityArtifact],
    public_envelope: &V2CanonicalFinalEnvelopeV1,
    finalization_id: &str,
    inspection: &SignedV2ImmutableResponseInspectionV1,
    release_preparation: &SignedV2ExactReleasePreparationV1,
) -> Result<(), ResponseObservationV2TransactionError> {
    let seed = &inspection.authority_proof_seed;
    if artifacts.len() != 10
        || seed.authority_artifacts.len() != 9
        || artifacts.first()
            != Some(
                &release_preparation
                    .authority_receipt
                    .release_preparation_artifact,
            )
        || artifacts.get(1..)
            != Some(seed.authority_artifacts.as_slice())
        || seed.generation_id != client.generation_id
        || seed.generation != client.provider_generation
        || public_envelope.generation_id != client.generation_id
        || public_envelope.generation != client.provider_generation
        || public_envelope.attempt_id != seed.attempt_id
        || public_envelope.stable_resume_id != seed.stable_resume_id
        || public_envelope.finalization_id != finalization_id
        || public_envelope.terminal_revision
            != body.attempt_revision
        || public_envelope.fencing_token != seed.fencing_token
        || public_envelope.raw_response_object_sha256
            != seed.raw_response_object.content_sha256.0
        || public_envelope.raw_response_byte_length
            != seed.raw_response_object.content_length
        || public_envelope.framing_validation_sha256
            != seed
                .http11_framing
                .canonical_framing_sha256
                .0
        || public_envelope.exact_policy_decision_sha256
            != seed.policy_decision_id.0
        || body.generation_id.0 != seed.generation_id
        || body.attempt_id.0 != seed.attempt_id
        || seed.attempt_revision.checked_add(1)
            != Some(body.attempt_revision)
        || body.attempt_revision
            != release_preparation.prepared_revision
        || body.attempt_revision
            != release_preparation
                .authority_receipt
                .successor_revision
        || body.fence_token.0 != seed.fencing_token.to_string()
        || body.stable_resume_id.0 != seed.stable_resume_id
        || body.finalization_id.0 != finalization_id
        || body.staged_request_object != seed.staged_request_object
        || body.raw_response_object != seed.raw_response_object
        || body.http11_framing != seed.http11_framing
        || body.credential_use_id != seed.credential_use_id
        || body.target_effect_id != seed.target_effect_id
        || body.policy_decision_id != seed.policy_decision_id
        || body.released_projection_sha256.0
            != public_envelope.released_projection_sha256
        || body.transition_chain_sha256.0
            != public_envelope.transition_chain_root_sha256
        || body.evidence_root_sha256.0
            != public_envelope.evidence_root_sha256
        || release_preparation.generation_id != seed.generation_id
        || release_preparation.generation != seed.generation
        || release_preparation.attempt_id != seed.attempt_id
        || release_preparation.predecessor_revision
            != seed.attempt_revision
        || release_preparation.stable_resume_id
            != seed.stable_resume_id
        || release_preparation.fencing_token != seed.fencing_token
        || release_preparation.raw_response_sha256
            != seed.raw_response_object.content_sha256.0
        || release_preparation.raw_response_byte_length
            != seed.raw_response_object.content_length
        || release_preparation.inspection_receipt_sha256
            != seed.inspection_receipt_sha256
        || release_preparation.authority_proof_seed_sha256
            != seed.seed_sha256
        || release_preparation
            .authority_prerequisites_root_sha256
            != seed.authority_artifacts_root_sha256
    {
        return invalid();
    }
    let payloads = artifacts
        .iter()
        .map(|artifact| {
            serde_json::to_value(&artifact.body.payload)
                .map_err(|_| {
                    ResponseObservationV2TransactionError::InvalidResponse
                })
        })
        .collect::<Result<Vec<_>, _>>()?;

    verify_payload_type(
        &payloads[0],
        "RELEASE_PREPARATION_RECEIPT",
    )?;
    let preparation = payload_body(&payloads[0])?;
    let preparation_receipt = &release_preparation.authority_receipt;
    let preparation_predecessor =
        u64_value(preparation, "predecessorRevision")?;
    if string(preparation, "releaseAuthorizationId")?
        != preparation_receipt.release_authorization_id
        || string(preparation, "releaseRequestSha256")?
            != preparation_receipt.exact_release_request_sha256
        || string(preparation, "inspectionResultSha256")?
            != preparation_receipt.inspection_receipt_sha256
        || string(preparation, "releaseObjectSha256")?
            != body.raw_response_object.content_sha256.0.as_str()
        || string(preparation, "clientBindingSha256")?
            != preparation_receipt.client_binding_sha256
        || string(preparation, "exactReplayKeySha256")?
            != preparation_receipt.exact_replay_key_sha256
        || string(preparation, "preauthorizationArtifactSha256")?
            != preparation_receipt
                .preauthorization_artifact_sha256
        || string(
            preparation,
            "signedStateMutationReceiptSha256",
        )? != preparation_receipt.state_mutation_receipt_sha256
        || string(preparation, "oneUseNonceSha256")?
            != preparation_receipt.one_use_nonce_sha256
        || string(preparation, "durableCanonicalResultSha256")?
            != preparation_receipt.durable_canonical_result_sha256
        || preparation_predecessor
            != preparation_receipt.predecessor_revision
        || preparation_predecessor.checked_add(1)
            != Some(u64_value(preparation, "successorRevision")?)
        || u64_value(preparation, "successorRevision")?
            != body.attempt_revision
        || string(preparation, "predecessorState")?
            != preparation_receipt.predecessor_state
        || string(preparation, "successorState")?
            != preparation_receipt.successor_state
        || string(preparation, "fenceToken")?
            != body.fence_token.0.as_str()
        || !all_digests(
            preparation,
            &[
                "releaseRequestSha256",
                "inspectionResultSha256",
                "releaseObjectSha256",
                "clientBindingSha256",
                "exactReplayKeySha256",
                "preauthorizationArtifactSha256",
                "signedStateMutationReceiptSha256",
                "oneUseNonceSha256",
                "durableCanonicalResultSha256",
            ],
        )?
    {
        return invalid();
    }

    verify_payload_type(&payloads[1], "CREDENTIAL_USE")?;
    let credential = payload_body(&payloads[1])?;
    if string(credential, "credentialUseId")?
        != body.credential_use_id.0.as_str()
        || string(credential, "targetEffectId")?
            != body.target_effect_id.0.as_str()
        || !all_digests(
            credential,
            &["credentialBindingSha256", "oneUseNonceSha256"],
        )?
    {
        return invalid();
    }

    verify_payload_type(&payloads[2], "TARGET_EFFECT")?;
    let target = payload_body(&payloads[2])?;
    if string(target, "targetEffectId")?
        != body.target_effect_id.0.as_str()
        || string(target, "requestObjectSha256")?
            != body.staged_request_object.content_sha256.0.as_str()
        || string(target, "responseObjectSha256")?
            != body.raw_response_object.content_sha256.0.as_str()
        || string(target, "outcome")? != "OBSERVED"
        || !all_digests(
            target,
            &[
                "idempotencyKeySha256",
                "requestObjectSha256",
                "responseObjectSha256",
            ],
        )?
    {
        return invalid();
    }

    verify_payload_type(&payloads[3], "POLICY_PROOF")?;
    let policy = payload_body(&payloads[3])?;
    if string(policy, "policyDecisionId")?
        != body.policy_decision_id.0.as_str()
        || string(policy, "rawResponseObjectSha256")?
            != body.raw_response_object.content_sha256.0.as_str()
        || string(policy, "responseFramingSha256")?
            != body
                .http11_framing
                .canonical_framing_sha256
                .0
                .as_str()
        || string(policy, "releasedProjectionSha256")?
            != body.released_projection_sha256.0.as_str()
        || !bool_value(policy, "passed")?
        || !all_digests(
            policy,
            &[
                "policyDecisionId",
                "policyGenerationSha256",
                "rawResponseObjectSha256",
                "responseFramingSha256",
                "releasedProjectionSha256",
            ],
        )?
    {
        return invalid();
    }

    verify_payload_type(
        &payloads[4],
        "TRANSITION_AUTHORIZATION",
    )?;
    let transition = payload_body(&payloads[4])?;
    let transition_predecessor =
        u64_value(transition, "expectedRevision")?;
    if string(transition, "policyDecisionId")?
        != body.policy_decision_id.0.as_str()
        || string(transition, "policyGenerationSha256")?
            != string(policy, "policyGenerationSha256")?
        || transition_predecessor.checked_add(1)
            != Some(u64_value(transition, "successorRevision")?)
        || u64_value(transition, "successorRevision")?
            >= body.attempt_revision
        || string(transition, "expectedState")? != "RESERVED"
        || string(transition, "successorState")? != "AUTHORIZED"
        || !bool_value(transition, "passed")?
        || !all_digests(
            transition,
            &["policyDecisionId", "policyGenerationSha256"],
        )?
    {
        return invalid();
    }

    verify_payload_type(&payloads[5], "IMMUTABLE_INSPECTION")?;
    let inspection = payload_body(&payloads[5])?;
    if string(inspection, "objectId")?
        != body.raw_response_object.object_id.0.as_str()
        || string(inspection, "objectKind")?
            != body.raw_response_object.object_kind.0.as_str()
        || string(inspection, "contentSha256")?
            != body.raw_response_object.content_sha256.0.as_str()
        || u64_value(inspection, "contentLength")?
            != body.raw_response_object.content_length
        || !bool_value(inspection, "bytesImmutable")?
        || !bool_value(inspection, "replacementProhibited")?
        || !all_digests(
            inspection,
            &[
                "contentSha256",
                "immutableStorageReceiptSha256",
                "inspectionPurposeSha256",
            ],
        )?
    {
        return invalid();
    }

    verify_payload_type(&payloads[6], "ATTESTATION")?;
    let attestation = payload_body(&payloads[6])?;
    let expected_mode = match client.attestation_mode {
        V2AttestationMode::TrustedHost => "TrustedHostNoTee",
        V2AttestationMode::TeeHardware => "TeeHardware",
    };
    let expected_hardware =
        client.attestation_mode == V2AttestationMode::TeeHardware;
    if string(attestation, "attestationMode")? != expected_mode
        || bool_value(attestation, "hardwareProof")?
            != expected_hardware
        || string(attestation, "sourceCommitSha256")?
            != client.expected_source_commit_sha256.as_str()
        || string(attestation, "sourceTreeSha256")?
            != client.expected_source_tree_sha256.as_str()
        || string(attestation, "executableSha256")?
            != artifacts[6]
                .body
                .authority_scope
                .executable_sha256
                .0
                .as_str()
        || string(attestation, "configurationSha256")?
            != artifacts[6]
                .body
                .authority_scope
                .configuration_sha256
                .0
                .as_str()
    {
        return invalid();
    }
    for field in [
        "sourceCommitSha256",
        "sourceTreeSha256",
        "executableSha256",
        "configurationSha256",
        "evidenceObjectSha256",
    ] {
        if !is_sha256_digest(string(attestation, field)?) {
            return invalid();
        }
    }

    verify_payload_type(&payloads[7], "ARTIFACT_COMMIT")?;
    let commit = payload_body(&payloads[7])?;
    if string(commit, "objectId")?
        != body.raw_response_object.object_id.0.as_str()
        || string(commit, "objectKind")?
            != body.raw_response_object.object_kind.0.as_str()
        || string(commit, "contentSha256")?
            != body.raw_response_object.content_sha256.0.as_str()
        || u64_value(commit, "contentLength")?
            != body.raw_response_object.content_length
        || string(commit, "immutableStorageReceiptSha256")?
            != string(inspection, "immutableStorageReceiptSha256")?
        || !is_sha256_digest(string(
            commit,
            "immutableStorageReceiptSha256",
        )?)
    {
        return invalid();
    }

    verify_payload_type(&payloads[8], "TRUSTED_TIME")?;
    let trusted_time = payload_body(&payloads[8])?;
    let trusted_time_sequence = u64_value(trusted_time, "sequence")?;
    if trusted_time_sequence == 0
        || u64_value(trusted_time, "predecessorSequence")?
            .checked_add(1)
            != Some(trusted_time_sequence)
        || u64_value(trusted_time, "epochMillis")? == 0
        || string(trusted_time, "clockId")?.is_empty()
    {
        return invalid();
    }

    verify_payload_type(
        &payloads[9],
        "TRANSPARENCY_CHECKPOINT",
    )?;
    let checkpoint_value = payloads[9]
        .as_object()
        .and_then(|payload| payload.get("artifact"))
        .cloned()
        .ok_or(ResponseObservationV2TransactionError::InvalidResponse)?;
    let checkpoint: ReleaseTransparencyArtifactV2 =
        serde_json::from_value(checkpoint_value).map_err(|_| {
            ResponseObservationV2TransactionError::InvalidResponse
        })?;
    let exact_proof_sha256 = canonical_transparency_sha256(
        &checkpoint.release_transparency_proof,
    )
    .map_err(|_| {
        ResponseObservationV2TransactionError::InvalidResponse
    })?;
    let runtime_pin = client
        .role_keys
        .get("runtime-attestation")
        .ok_or(ResponseObservationV2TransactionError::InvalidResponse)?;
    let verification_epoch_ms = u64::try_from(now_epoch_ms()).map_err(|_| {
        ResponseObservationV2TransactionError::InvalidResponse
    })?;
    let summary = verify_release_transparency_proof_with_pin(
        &checkpoint.release_transparency_proof,
        &client.transparency_trust_pin,
        &ReleaseTransparencyExpectation {
            generation_id: &client.generation_id,
            provider_generation: client.provider_generation,
            proof_pins_root_sha256: &client.proof_pins_root_sha256,
            trust_checkpoint_sha256: &client.trust_checkpoint_sha256,
            minimum_revocation_epoch: client.revocation_epoch,
            source_commit_sha256:
                &client.expected_source_commit_sha256,
            source_tree_sha256: &client.expected_source_tree_sha256,
            executable_sha256: string(attestation, "executableSha256")?,
            configuration_sha256:
                string(attestation, "configurationSha256")?,
            runtime_attestation_key_id: &runtime_pin.key_id,
            runtime_attestation_public_key_base64:
                &runtime_pin.public_key_base64,
            runtime_attestation_public_key_sha256:
                &runtime_pin.public_key_sha256,
            artifact_issued_at_epoch_ms:
                artifacts[9].body.issued_at_epoch_millis,
            verification_epoch_ms,
        },
    )
    .map_err(|_| {
        ResponseObservationV2TransactionError::InvalidResponse
    })?;
    if checkpoint.release_transparency_proof_sha256
        != exact_proof_sha256
        || summary.checkpoint_sha256
            != checkpoint.release_transparency_proof.checkpoint_sha256
        || checkpoint
            .release_transparency_proof
            .checkpoint
            .payload
            .issued_at_epoch_ms
            > u64_value(trusted_time, "epochMillis")?
    {
        return invalid();
    }
    Ok(())
}

fn verify_payload_type(
    payload: &Value,
    expected: &str,
) -> Result<(), ResponseObservationV2TransactionError> {
    if payload
        .as_object()
        .and_then(|object| object.get("artifactType"))
        .and_then(Value::as_str)
        != Some(expected)
    {
        return invalid();
    }
    Ok(())
}

fn payload_body(
    payload: &Value,
) -> Result<&Map<String, Value>, ResponseObservationV2TransactionError> {
    payload
        .as_object()
        .and_then(|object| object.get("artifact"))
        .and_then(Value::as_object)
        .ok_or(ResponseObservationV2TransactionError::InvalidResponse)
}

fn string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a str, ResponseObservationV2TransactionError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(ResponseObservationV2TransactionError::InvalidResponse)
}

fn u64_value(
    object: &Map<String, Value>,
    field: &str,
) -> Result<u64, ResponseObservationV2TransactionError> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(ResponseObservationV2TransactionError::InvalidResponse)
}

fn bool_value(
    object: &Map<String, Value>,
    field: &str,
) -> Result<bool, ResponseObservationV2TransactionError> {
    object
        .get(field)
        .and_then(Value::as_bool)
        .ok_or(ResponseObservationV2TransactionError::InvalidResponse)
}

fn all_digests(
    object: &Map<String, Value>,
    fields: &[&str],
) -> Result<bool, ResponseObservationV2TransactionError> {
    for field in fields {
        if !is_sha256_digest(string(object, field)?) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn invalid<T>() -> Result<T, ResponseObservationV2TransactionError> {
    Err(ResponseObservationV2TransactionError::InvalidResponse)
}
