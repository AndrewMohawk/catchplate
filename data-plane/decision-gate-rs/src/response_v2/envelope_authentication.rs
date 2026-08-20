use super::*;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use std::collections::BTreeSet;

const NESTED_AUTHORITY_SIGNING_DOMAIN_NAME: &str =
    "serverware.responseV2.nestedAuthorityArtifact.signature/v1";
const NESTED_AUTHORITY_SIGNING_DOMAIN: &[u8] =
    b"SERVERWARE\0RESPONSE-V2-NESTED-AUTHORITY\0V1\0";

pub(super) struct NestedArtifactExpectation {
    pub(super) artifact_type: &'static str,
    pub(super) logical_role: &'static str,
    pub(super) service_role: &'static str,
    pub(super) operation: &'static str,
}

pub(super) const FINAL_ARTIFACTS:
    [NestedArtifactExpectation; 10] = [
    NestedArtifactExpectation {
        artifact_type: "RELEASE_PREPARATION_RECEIPT",
        logical_role: "linearizable-store",
        service_role: "state-authority",
        operation: "responseV2.release.consumeAndRetrieveExact/v1",
    },
    NestedArtifactExpectation {
        artifact_type: "CREDENTIAL_USE",
        logical_role: "credential-authority",
        service_role: "credential-transport",
        operation: "responseV2.dispatch.begin/v1",
    },
    NestedArtifactExpectation {
        artifact_type: "TARGET_EFFECT",
        logical_role: "target-transport",
        service_role: "credential-transport",
        operation: "responseV2.dispatch.recordOutcome/v1",
    },
    NestedArtifactExpectation {
        artifact_type: "POLICY_PROOF",
        logical_role: "evidence-trust",
        service_role: "policy-proof-verifier",
        operation: "responseV2.evidence.append/v1",
    },
    NestedArtifactExpectation {
        artifact_type: "TRANSITION_AUTHORIZATION",
        logical_role: "evidence-trust",
        service_role: "policy-proof-verifier",
        operation: "responseV2.attempt.authorize/v1",
    },
    NestedArtifactExpectation {
        artifact_type: "IMMUTABLE_INSPECTION",
        logical_role: "linearizable-store",
        service_role: "state-authority",
        operation: "responseV2.object.inspectImmutableRaw/v1",
    },
    NestedArtifactExpectation {
        artifact_type: "ATTESTATION",
        logical_role: "runtime-attestation",
        service_role: "release-attestor-publisher",
        operation: "responseV2.evidence.append/v1",
    },
    NestedArtifactExpectation {
        artifact_type: "ARTIFACT_COMMIT",
        logical_role: "persistence",
        service_role: "immutable-artifact-ledger",
        operation: "responseV2.object.commitRaw/v1",
    },
    NestedArtifactExpectation {
        artifact_type: "TRUSTED_TIME",
        logical_role: "trusted-time",
        service_role: "state-authority",
        operation: "responseV2.trustedTime.advance/v1",
    },
    NestedArtifactExpectation {
        artifact_type: "TRANSPARENCY_CHECKPOINT",
        logical_role: "transparency",
        service_role: "release-attestor-publisher",
        operation: "responseV2.transparency.checkpoint/v1",
    },
];

pub(super) struct ResponseObservationV2VerifiedNestedAuthorityArtifacts {
    generation_id: String,
    attempt_id: String,
    final_revision: u64,
    fencing_token: u64,
    signed_artifact_sha256: Vec<String>,
}

pub(super) fn response_observation_v2_preverify_nested_authority_artifacts(
    client: &ResponseObservationV2Client,
    release_preparation:
        &serverware_decision_gate::SignedAuthorityArtifact,
    prerequisite_artifacts:
        &[serverware_decision_gate::SignedAuthorityArtifact],
    expected_attempt_id: &str,
    expected_final_revision: u64,
    expected_fencing_token: u64,
    verification_epoch_ms: u64,
) -> Result<
    ResponseObservationV2VerifiedNestedAuthorityArtifacts,
    ResponseObservationV2TransactionError,
> {
    if prerequisite_artifacts.len() != FINAL_ARTIFACTS.len() - 1
        || expected_attempt_id.is_empty()
        || expected_final_revision == 0
        || expected_fencing_token == 0
    {
        return invalid();
    }

    let mut artifact_ids = BTreeSet::new();
    let mut signed_artifact_digests = BTreeSet::new();
    let mut signed_artifact_sha256 =
        Vec::with_capacity(FINAL_ARTIFACTS.len());
    for (artifact, expected) in std::iter::once(release_preparation)
        .chain(prerequisite_artifacts.iter())
        .zip(FINAL_ARTIFACTS.iter())
    {
        artifact.validate_contract().map_err(|_| {
            ResponseObservationV2TransactionError::InvalidResponse
        })?;
        let canonical_artifact =
            artifact.canonical_signed_bytes().map_err(|_| {
                ResponseObservationV2TransactionError::InvalidResponse
            })?;
        let signed_artifact_sha =
            sha256_prefixed(&canonical_artifact);
        if !artifact_ids.insert(artifact.body.artifact_id.0.as_str())
            || !signed_artifact_digests
                .insert(signed_artifact_sha.clone())
        {
            return Err(
                ResponseObservationV2TransactionError::InvalidResponse,
            );
        }
        verify_nested_authority_signature(
            client,
            artifact,
            expected,
            expected_attempt_id,
            expected_final_revision,
            expected_fencing_token,
            verification_epoch_ms,
        )?;
        signed_artifact_sha256.push(signed_artifact_sha);
    }
    Ok(ResponseObservationV2VerifiedNestedAuthorityArtifacts {
        generation_id: client.generation_id.clone(),
        attempt_id: expected_attempt_id.to_owned(),
        final_revision: expected_final_revision,
        fencing_token: expected_fencing_token,
        signed_artifact_sha256,
    })
}

pub(super) fn response_observation_v2_verify_nested_authority_envelope(
    client: &ResponseObservationV2Client,
    descriptor:
        &serverware_decision_gate::CanonicalAuthorityEnvelopeDescriptorV2,
    release_preparation:
        &serverware_decision_gate::SignedAuthorityArtifact,
    prerequisite_artifacts:
        &[serverware_decision_gate::SignedAuthorityArtifact],
    expected_public_envelope: &V2CanonicalFinalEnvelopeV1,
    verified: &ResponseObservationV2VerifiedNestedAuthorityArtifacts,
    verification_epoch_ms: u64,
) -> Result<(), ResponseObservationV2TransactionError> {
    serverware_decision_gate::validate_canonical_authority_envelope(
        descriptor,
    )
    .map_err(|_| ResponseObservationV2TransactionError::InvalidResponse)?;
    let authority = &descriptor.authority_envelope;
    if prerequisite_artifacts.len() != FINAL_ARTIFACTS.len() - 1
        || authority.authority_artifacts.len() != FINAL_ARTIFACTS.len()
        || verified.signed_artifact_sha256.len()
            != FINAL_ARTIFACTS.len()
        || verified.generation_id != client.generation_id
        || verified.attempt_id != authority.body.attempt_id.0
        || verified.final_revision != authority.body.attempt_revision
        || authority.body.fence_token.0
            != verified.fencing_token.to_string()
        || descriptor.public_envelope.generation_id
            != client.generation_id
        || descriptor.public_envelope.generation
            != client.provider_generation
        || authority.body.generation_id.0 != client.generation_id
        || !expected_public_envelope
            .authority_artifacts_root_sha256
            .is_empty()
        || !expected_public_envelope.final_envelope_sha256.is_empty()
    {
        return invalid();
    }

    let mut normalized_public = descriptor.public_envelope.clone();
    normalized_public.authority_artifacts_root_sha256.clear();
    normalized_public.final_envelope_sha256.clear();
    if normalized_public != *expected_public_envelope {
        return invalid();
    }

    for (index, (artifact, expected_artifact)) in authority
        .authority_artifacts
        .iter()
        .zip(
            std::iter::once(release_preparation)
                .chain(prerequisite_artifacts.iter()),
        )
        .enumerate()
    {
        let canonical_artifact =
            artifact.canonical_signed_bytes().map_err(|_| {
                ResponseObservationV2TransactionError::InvalidResponse
            })?;
        if artifact != expected_artifact
            || sha256_prefixed(&canonical_artifact)
                != verified.signed_artifact_sha256[index]
            || artifact.body.issued_at_epoch_millis
                > verification_epoch_ms
            || verification_epoch_ms
                >= artifact.body.expires_at_epoch_millis
        {
            return invalid();
        }
    }
    Ok(())
}

fn verify_nested_authority_signature(
    client: &ResponseObservationV2Client,
    artifact: &serverware_decision_gate::SignedAuthorityArtifact,
    expected: &NestedArtifactExpectation,
    expected_attempt_id: &str,
    expected_final_revision: u64,
    expected_fencing_token: u64,
    verification_epoch_ms: u64,
) -> Result<(), ResponseObservationV2TransactionError> {
    let body = &artifact.body;
    let scope = &body.authority_scope;
    let authentication = &artifact.authentication;
    let logical_role = body
        .producing_logical_role
        .as_ref()
        .map(|role| role.0.as_str())
        .ok_or(ResponseObservationV2TransactionError::InvalidResponse)?;
    let pin = client
        .role_keys
        .get(expected.logical_role)
        .ok_or(ResponseObservationV2TransactionError::InvalidResponse)?;
    let operation = body.operation.as_str();
    let scope_operations = scope
        .allowed_operations
        .iter()
        .map(|allowed| allowed.as_str())
        .collect::<BTreeSet<_>>();
    if body.artifact_class.as_str() != expected.artifact_type
        || body.payload.artifact_type().as_str()
            != expected.artifact_type
        || logical_role != expected.logical_role
        || body.producing_service_role.as_str()
            != expected.service_role
        || operation != expected.operation
        || body.generation_id.0 != client.generation_id
        || body.attempt_id.0 != expected_attempt_id
        || body.attempt_revision == 0
        || body.attempt_revision > expected_final_revision
        || body.fence_token.0 != expected_fencing_token.to_string()
        || body.issued_at_epoch_millis > verification_epoch_ms
        || verification_epoch_ms >= body.expires_at_epoch_millis
        || pin.role != expected.logical_role
        || pin.generation_id != client.generation_id
        || pin.provider_generation != client.provider_generation
        || body.producing_role_id.0 != pin.provider_id
        || body.producing_process_id.0 != pin.provider_id
        || body.key_id.0 != pin.key_id
        || body.key_material_sha256.0 != pin.key_material_sha256
        || !pin
            .allowed_operations
            .iter()
            .any(|allowed| allowed == operation)
        || scope.generation_id != body.generation_id
        || scope.process_id != body.producing_process_id
        || scope.service_role != body.producing_service_role
        || scope.logical_role.as_ref()
            != body.producing_logical_role.as_ref()
        || scope.role_id != body.producing_role_id
        || scope.key_id != body.key_id
        || scope.key_material_sha256
            != body.key_material_sha256
        || scope.executable_sha256.0
            != pin.executable_measurement_sha256
        || scope.configuration_sha256.0
            != pin.provider_config_sha256
        || scope.scope_sha256 != body.authority_scope_sha256
        || !scope_operations.contains(operation)
        || authentication.algorithm != "Ed25519"
        || authentication.key_id != body.key_id
        || authentication.key_material_sha256
            != body.key_material_sha256
        || authentication.authority_scope_sha256
            != body.authority_scope_sha256
        || authentication.signing_domain
            != NESTED_AUTHORITY_SIGNING_DOMAIN_NAME
    {
        return Err(
            ResponseObservationV2TransactionError::InvalidResponse,
        );
    }

    let canonical_body =
        artifact.canonical_body_bytes().map_err(|_| {
            ResponseObservationV2TransactionError::InvalidResponse
        })?;
    if authentication.signed_payload_sha256.0
        != sha256_prefixed(&canonical_body)
    {
        return Err(
            ResponseObservationV2TransactionError::InvalidResponse,
        );
    }
    let public_key = STANDARD
        .decode(&pin.public_key_base64)
        .map_err(|_| {
            ResponseObservationV2TransactionError::InvalidResponse
        })?;
    let signature = URL_SAFE_NO_PAD
        .decode(&authentication.signature_base64url)
        .map_err(|_| {
            ResponseObservationV2TransactionError::InvalidResponse
        })?;
    if public_key.len() != 32
        || signature.len() != 64
        || STANDARD.encode(&public_key) != pin.public_key_base64
        || URL_SAFE_NO_PAD.encode(&signature)
            != authentication.signature_base64url
        || sha256_prefixed(&public_key) != pin.public_key_sha256
        || pin.public_key_sha256 != pin.key_material_sha256
        || pin.key_id != pin.public_key_sha256
    {
        return Err(
            ResponseObservationV2TransactionError::InvalidResponse,
        );
    }
    let mut message_digest = Sha256::new();
    message_digest.update(NESTED_AUTHORITY_SIGNING_DOMAIN);
    message_digest.update(
        u64::try_from(canonical_body.len())
            .map_err(|_| {
                ResponseObservationV2TransactionError::InvalidResponse
            })?
            .to_be_bytes(),
    );
    message_digest.update(&canonical_body);
    let message: [u8; 32] = message_digest.finalize().into();
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::ED25519,
        &public_key,
    )
    .verify(&message, &signature)
    .map_err(|_| ResponseObservationV2TransactionError::InvalidResponse)
}

fn invalid<T>() -> Result<T, ResponseObservationV2TransactionError> {
    Err(ResponseObservationV2TransactionError::InvalidResponse)
}
