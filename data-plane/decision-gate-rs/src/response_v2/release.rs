use super::*;

pub(super) fn response_observation_v2_release_request_commitment(
    binding: &V2ReadBinding,
    object: &ImmutableObjectReference,
    release_cas_expectation: &V2ReleaseCasExpectationV1,
    one_use_nonce: &str,
) -> Result<
    V2ReleaseRequestCommitmentDigestV1,
    ResponseObservationV2TransactionError,
> {
    let commitment = V2ReleaseRequestCommitmentV1 {
        api_version:
            V2_RELEASE_REQUEST_COMMITMENT_VERSION.to_owned(),
        request_id: binding.request_id.clone(),
        subject_client_identity_sha256:
            binding.client_identity_sha256.clone(),
        object: object.clone(),
        attempt_id: binding.attempt_id.clone(),
        lifecycle_state: binding.lifecycle_state,
        state_sha256: binding.state_sha256.clone(),
        attempt_revision: binding.attempt_revision,
        fencing_token: binding.fencing_token,
        monotonic_deadline:
            binding.monotonic_deadline.clone(),
        deadline_at_epoch_ms: binding.deadline_at_epoch_ms,
        one_use_nonce: one_use_nonce.to_owned(),
        release_cas_expectation:
            release_cas_expectation.clone(),
    };
    let commitment_sha256 =
        response_observation_v2_release_request_commitment_sha256(
            &commitment,
        )
        .ok_or(
            ResponseObservationV2TransactionError::InvalidResponse,
        )?;
    Ok(V2ReleaseRequestCommitmentDigestV1 {
        commitment,
        canonicalization:
            V2ReleaseRequestCommitmentCanonicalization::JcsRfc8785,
        digest_algorithm:
            V2ReleaseRequestCommitmentDigestAlgorithm::Sha256,
        commitment_sha256,
    })
}

pub(super) fn response_observation_v2_validate_public_release_authorization(
    bytes: &[u8],
    binding: &V2ReadBinding,
    object: &ImmutableObjectReference,
    release_cas_expectation: &V2ReleaseCasExpectationV1,
    one_use_nonce: &str,
    policy_sha256: &str,
    client: &ResponseObservationV2Client,
) -> Result<
    SignedPublicReleaseAuthorizationV1,
    ResponseObservationV2TransactionError,
> {
    let authorization: SignedPublicReleaseAuthorizationV1 =
        decode_canonical_custody_json(bytes).map_err(|_| {
            ResponseObservationV2TransactionError::InvalidResponse
        })?;
    let commitment =
        response_observation_v2_release_request_commitment(
            binding,
            object,
            release_cas_expectation,
            one_use_nonce,
        )?;
    let now_epoch_ms = u64::try_from(now_epoch_ms()).map_err(|_| {
        ResponseObservationV2TransactionError::InvalidResponse
    })?;
    if authorization.api_version
        != V2_PUBLIC_RELEASE_AUTHORIZATION_VERSION
        || authorization.authorization_id.is_empty()
        || authorization.request_id != binding.request_id
        || authorization.release_request_commitment_sha256
            != commitment.commitment_sha256
        || authorization.attempt_id != binding.attempt_id
        || authorization.fencing_token != binding.fencing_token
        || authorization.one_use_nonce != one_use_nonce
        || authorization.release_cas_expectation
            != *release_cas_expectation
        || authorization.subject_client_identity_sha256
            != binding.client_identity_sha256
        || authorization.object != *object
        || authorization.policy_sha256 != policy_sha256
        || authorization.trust_root_sha256
            != client.trust_root_sha256
        || authorization.trust_checkpoint_sha256
            != client.trust_checkpoint_sha256
        || authorization.revocation_epoch
            < client.revocation_epoch
        || authorization.issued_at_epoch_ms == 0
        || authorization.issued_at_epoch_ms > now_epoch_ms
        || authorization.expires_at_epoch_ms
            <= authorization.issued_at_epoch_ms
        || authorization.expires_at_epoch_ms <= now_epoch_ms
        || authorization.expires_at_epoch_ms
            > binding.deadline_at_epoch_ms
        || authorization.signer_role
            != V2ReleaseAuthorityRole::PublicRelease
        || authorization.signer_provider_id.is_empty()
        || authorization.provider_generation
            != client.provider_generation
        || !is_sha256_digest(
            &authorization.provider_operation_binding_sha256,
        )
        || !is_sha256_digest(&authorization.signer_key_id)
        || !is_sha256_digest(
            &authorization.signer_key_material_sha256,
        )
        || authorization.signature.is_empty()
    {
        return Err(
            ResponseObservationV2TransactionError::InvalidResponse,
        );
    }
    let mut unsigned = authorization.clone();
    let signature = std::mem::take(&mut unsigned.signature);
    verify_response_observation_v2_role_signature(
        client,
        "public-release",
        V2_RETRIEVE_OPERATION,
        &authorization.signer_provider_id,
        authorization.provider_generation,
        &authorization.signer_key_id,
        &authorization.signer_key_material_sha256,
        &signature,
        &unsigned,
    )?;
    Ok(authorization)
}

pub(super) fn response_observation_v2_validate_retrieve_result(
    request: &V2OperationRequest,
    result: &V2RetrieveResult,
    finalized_object: &ImmutableObjectReference,
    release_cas_expectation: &V2ReleaseCasExpectationV1,
    authorization: &SignedPublicReleaseAuthorizationV1,
    client: &ResponseObservationV2Client,
) -> Result<
    Option<V2DurableExactCanonicalResponseReferenceV1>,
    ResponseObservationV2TransactionError,
> {
    let V2OperationRequest::Retrieve { params, .. } = request else {
        return Err(
            ResponseObservationV2TransactionError::InvalidResponse,
        );
    };
    let request_bytes =
        custody_canonical_json_bytes(request).map_err(|_| {
            ResponseObservationV2TransactionError::InvalidResponse
        })?;
    let request_sha256 = sha256_prefixed(&request_bytes);
    let descriptor_manifest_sha256 =
        response_observation_v2_descriptor_manifest_sha256(
            &request.exact_object_descriptors(),
        );
    response_observation_v2_validate_provider_scope(
        client,
        &authorization.issuance_scope,
        "public-release",
        V2_RETRIEVE_OPERATION,
        &request_sha256,
        &params.binding.attempt_id,
        params.binding.attempt_revision,
        &params.binding.state_sha256,
        params.binding.fencing_token,
        &authorization.provider_operation_binding_sha256,
    )?;
    if result.object != *finalized_object
        || result.object.object_type
            != ImmutableObjectType::ReleasedResponse
        || result.exact_bytes.object_id
            != finalized_object.retrieval_id
        || result.exact_bytes.media_type
            != ExactObjectMediaType::Http11Response
        || result.exact_bytes.fd_index != 0
        || result.exact_bytes.byte_length
            != finalized_object.byte_length
        || result.exact_bytes.sha256
            != finalized_object.object_sha256
        || result.exact_bytes.required_seals
            != MemfdSealProfile::ImmutableV1
        || result.retrieval_evidence.evidence_type
            != V2EvidenceType::Retrieval
        || result.retrieval_evidence.retrieval_id.is_empty()
    {
        return Err(
            ResponseObservationV2TransactionError::InvalidResponse,
        );
    }
    let signed =
        &result.release_authorization_consumption;
    let now_epoch_ms = u64::try_from(now_epoch_ms()).map_err(|_| {
        ResponseObservationV2TransactionError::InvalidResponse
    })?;
    let consume = &signed.consume;
    let expected_commitment =
        response_observation_v2_release_request_commitment(
            &params.binding,
            finalized_object,
            release_cas_expectation,
            &authorization.one_use_nonce,
        )?;
    let expected_consume_sha256 =
        response_observation_v2_release_consume_binding_sha256(
            consume,
        )
        .ok_or(
            ResponseObservationV2TransactionError::InvalidResponse,
        )?;
    let expected_revision = release_cas_expectation
        .expected_authority_revision
        .checked_add(1)
        .ok_or(
            ResponseObservationV2TransactionError::InvalidResponse,
        )?;
    let (
        authority_revision,
        consume_sha256,
        receipt_sha256,
        exact_replay_reference,
    ) =
        match &signed.outcome {
            V2ReleaseAuthorizationConsumeOutcomeV1::
                ConsumedBeforeRelease {
                    authority_revision,
                    consume_binding_sha256,
                    consumption_receipt_sha256,
                } => (
                    *authority_revision,
                    consume_binding_sha256,
                    consumption_receipt_sha256,
                    None,
                ),
            V2ReleaseAuthorizationConsumeOutcomeV1::ExactReplay {
                authority_revision,
                consume_binding_sha256,
                consumption_receipt_sha256,
                replay_record_sha256,
                replay_key,
                exact_canonical_response,
            } => {
                if !is_sha256_digest(replay_record_sha256)
                    || replay_key.original_request_id
                        != params.binding.request_id
                    || replay_key.request_sha256
                        != request_sha256
                    || replay_key.descriptor_manifest_sha256
                        != descriptor_manifest_sha256
                    || replay_key.attempt_id
                        != params.binding.attempt_id
                    || replay_key.operation
                        != V2DurableReplayOperation::Retrieve
                    || replay_key.fencing_token
                        != params.binding.fencing_token
                    || exact_canonical_response.encoding
                        != V2CanonicalControlResponseEncoding::
                            CanonicalJsonUtf8
                    || exact_canonical_response.byte_length == 0
                    || !is_sha256_digest(
                        &exact_canonical_response.sha256,
                    )
                    || exact_canonical_response
                        .storage_reference_id
                        .is_empty()
                    || !is_sha256_digest(
                        &exact_canonical_response
                            .persistence_receipt_sha256,
                    )
                {
                    return Err(
                        ResponseObservationV2TransactionError::InvalidResponse,
                    );
                }
                (
                    *authority_revision,
                    consume_binding_sha256,
                    consumption_receipt_sha256,
                    Some(exact_canonical_response.clone()),
                )
            }
            V2ReleaseAuthorizationConsumeOutcomeV1::Denied {
                ..
            } => {
                return Err(
                    ResponseObservationV2TransactionError::Denied,
                )
            }
        };
    if signed.api_version
        != V2_RELEASE_AUTHORIZATION_CONSUME_OUTCOME_VERSION
        || consume.authorization_id
            != authorization.authorization_id
        || consume.request_sha256 != request_sha256
        || consume.descriptor_manifest_sha256
            != descriptor_manifest_sha256
        || consume.one_use_nonce != authorization.one_use_nonce
        || consume.subject_client_identity_sha256
            != params.binding.client_identity_sha256
        || consume.object != *finalized_object
        || consume.attempt_id != params.binding.attempt_id
        || consume.fencing_token != params.binding.fencing_token
        || consume.release_request_commitment
            != expected_commitment
        || consume.expected_authority_revision
            != release_cas_expectation
                .expected_authority_revision
        || consume.expected_unconsumed_state_sha256
            != release_cas_expectation
                .expected_unconsumed_state_sha256
        || authority_revision != expected_revision
        || consume_sha256 != &expected_consume_sha256
        || !is_sha256_digest(receipt_sha256)
        || signed.trust_root_sha256
            != authorization.trust_root_sha256
        || signed.trust_checkpoint_sha256
            != authorization.trust_checkpoint_sha256
        || signed.revocation_epoch
            != authorization.revocation_epoch
        || signed.recorded_at_epoch_ms == 0
        || signed.recorded_at_epoch_ms
            < authorization.issued_at_epoch_ms
        || signed.recorded_at_epoch_ms > now_epoch_ms
        || signed.recorded_at_epoch_ms
            > params.binding.deadline_at_epoch_ms
        || signed.signer_role
            != V2ReleaseConsumeAuthorityRole::
                PublicReleaseConsumption
        || signed.signer_provider_id.is_empty()
        || signed.provider_generation
            != client.provider_generation
        || !is_sha256_digest(
            &signed.provider_operation_binding_sha256,
        )
        || !is_sha256_digest(&signed.signer_key_id)
        || !is_sha256_digest(
            &signed.signer_key_material_sha256,
        )
        || signed.signature.is_empty()
    {
        return Err(
            ResponseObservationV2TransactionError::InvalidResponse,
        );
    }
    let mut unsigned = signed.clone();
    let signature = std::mem::take(&mut unsigned.signature);
    verify_response_observation_v2_role_signature(
        client,
        "public-release-consumption",
        V2_RETRIEVE_OPERATION,
        &signed.signer_provider_id,
        signed.provider_generation,
        &signed.signer_key_id,
        &signed.signer_key_material_sha256,
        &signature,
        &unsigned,
    )?;
    let evidence_binding = V2RetrievalEvidenceBindingV1 {
        api_version:
            V2_RETRIEVAL_EVIDENCE_BINDING_VERSION.to_owned(),
        request_sha256,
        descriptor_manifest_sha256,
        request_id: params.binding.request_id.clone(),
        client_identity_sha256:
            params.binding.client_identity_sha256.clone(),
        object: result.object.clone(),
        exact_bytes: result.exact_bytes.clone(),
        attempt_id: params.binding.attempt_id.clone(),
        lifecycle_state: params.binding.lifecycle_state,
        state_sha256: params.binding.state_sha256.clone(),
        attempt_revision: params.binding.attempt_revision,
        fencing_token: params.binding.fencing_token,
        monotonic_deadline:
            params.binding.monotonic_deadline.clone(),
        deadline_at_epoch_ms:
            params.binding.deadline_at_epoch_ms,
        release_consume_binding_sha256:
            expected_consume_sha256,
        consumption_receipt_sha256:
            receipt_sha256.clone(),
        retrieval_id:
            result.retrieval_evidence.retrieval_id.clone(),
    };
    if response_observation_v2_retrieval_evidence_sha256(
        &evidence_binding,
    )
    .as_deref()
        != Some(
            result
                .retrieval_evidence
                .evidence_sha256
                .as_str(),
        )
    {
        return Err(
            ResponseObservationV2TransactionError::InvalidResponse,
        );
    }
    Ok(exact_replay_reference)
}
