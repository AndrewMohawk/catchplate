use super::*;

const TEE_VERIFICATION_RESULT_API_VERSION: &str =
    "serverware.responseObservationV2AttestationVerifyResult/v2";
const LOCAL_TEE_BOUNDARY: &str = "local-response-v2-custody";
const LOCAL_TEE_SECURITY_CLAIM: &str =
    "hardware-attested-local-single-node-no-fault-tolerance";
const PINNED_TEE_VERIFIER_API_VERSION: &str =
    "serverware.responseObservationV2PinnedTeeVerifier/v1";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ResponseV2MeasuredVerifierInput {
    pub(super) path: PathBuf,
    pub(super) sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ResponseV2PinnedTeeVerifier {
    pub(super) api_version: String,
    pub(super) executable: PathBuf,
    #[serde(default)]
    pub(super) arguments: Vec<String>,
    pub(super) executable_sha256: String,
    #[serde(default)]
    pub(super) verifier_module:
        Option<ResponseV2MeasuredVerifierInput>,
    pub(super) expectations: ResponseV2MeasuredVerifierInput,
    pub(super) trust_roots: ResponseV2MeasuredVerifierInput,
}

impl ResponseV2PinnedTeeVerifier {
    pub(super) fn validate(&self) -> Result<(), String> {
        if self.api_version != PINNED_TEE_VERIFIER_API_VERSION
            || !response_v2_absolute_normal_path(&self.executable)
            || !is_sha256_digest(&self.executable_sha256)
            || !self.arguments.is_empty()
        {
            return Err(
                "response-observation v2 TEE verifier must be one descriptor-pinned executable with no command or interpreter arguments"
                    .to_string(),
            );
        }
        for input in [
            self.verifier_module.as_ref(),
            Some(&self.expectations),
            Some(&self.trust_roots),
        ]
        .into_iter()
        .flatten()
        {
            if !response_v2_absolute_normal_path(&input.path)
                || !is_sha256_digest(&input.sha256)
            {
                return Err(
                    "response-observation v2 TEE verifier inputs require absolute normalized paths and exact SHA-256 pins"
                        .to_string(),
                );
            }
        }
        Ok(())
    }
}

fn response_v2_absolute_normal_path(path: &Path) -> bool {
    path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir
                    | std::path::Component::Normal(_)
            )
        })
}

fn run_pinned_response_v2_tee_verifier(
    verifier: &ResponseV2PinnedTeeVerifier,
    request: &Value,
) -> Result<Value, String> {
    verifier.validate()?;
    let mut request = request.clone();
    request
        .as_object_mut()
        .ok_or(
            "response-observation v2 TEE verifier request is not an object",
        )?
        .insert(
            "verifierInputs".to_string(),
            json!({
                "module":&verifier.verifier_module,
                "expectations":&verifier.expectations,
                "trustRoots":&verifier.trust_roots,
            }),
        );
    let command = crate::PinnedVerifierCommand {
        executable: verifier.executable.clone(),
        arguments: verifier.arguments.clone(),
        expected_sha256: verifier.executable_sha256.clone(),
    };
    crate::run_pinned_bounded_json_command_with_output_limit(
        &command,
        &request,
        "response-observation v2 TEE verifier",
        128 * 1024,
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TeeHardwareVerificationResultV2 {
    api_version: String,
    ok: bool,
    claims: TeeHardwareVerificationClaimsV2,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TeeHardwareVerificationClaimsV2 {
    request_sha256: String,
    unsigned_response_sha256: String,
    output_manifest_sha256: String,
    custody_boot_id: String,
    challenge_nonce: String,
    signer_key_sha256: String,
    attestation_evidence_sha256: String,
    report_data_sha256: String,
    role_identity_root_sha256: String,
    proof_pins_root_sha256: String,
    release_transparency_trust_pin_sha256: String,
    generation_id: String,
    provider_generation: u64,
    source_commit_sha256: String,
    source_tree_sha256: String,
    custody_measurement_sha256: String,
    attestation_mode: String,
    topology_profile: String,
    fault_domain_count: u64,
    quorum_threshold: u64,
    external_witness_count: u64,
    fault_tolerance: u64,
    hardware_backed: bool,
    quote_verified: bool,
    debug: bool,
    tee_boundary: String,
    security_claim: String,
    verifier_executable_sha256: String,
    verifier_module_sha256: Option<String>,
    expectations_sha256: String,
    trust_roots_sha256: String,
}

pub(super) fn verify_response_observation_v2_attestation(
    config: &ResponseObservationV2ClientConfig,
    attestation: &V2FreshResponseAttestationV1,
    request_sha256: &str,
    unsigned_response_sha256: &str,
    output_manifest_sha256: &str,
    boot_id: &str,
    expected_deadline: Option<(&str, u64)>,
    lifecycle_deadline: ResponseObservationV2Deadline,
) -> Result<(), String> {
    let response_attester_pin = config
        .role_keys
        .get("runtime-attestation")
        .ok_or(
            "response-observation v2 runtime-attestation key is not pinned",
        )?;
    let custody_pin = config
        .role_keys
        .get("custody")
        .ok_or(
            "response-observation v2 custody identity is not pinned",
        )?;
    let now = u64::try_from(now_epoch_ms())
        .map_err(|_| "response-observation v2 clock is invalid")?;
    let observed_boottime_ns =
        response_observation_v2_boottime_ns()
            .map_err(|_| {
                "response-observation v2 boottime is unavailable"
                    .to_string()
            })?;
    let attested_boottime_ns = attestation
        .monotonic_deadline
        .absolute_boottime_ns
        .parse::<u64>()
        .map_err(|_| {
            "response-observation v2 attested deadline is invalid"
                .to_string()
        })?;
    let deadline_matches =
        attestation.monotonic_deadline.api_version
            == V2_MONOTONIC_DEADLINE_VERSION
            && attestation.monotonic_deadline.custody_boot_id
                == boot_id
            && attestation.monotonic_deadline.clock_id
                == V2MonotonicClockId::ClockBoottime
            && match expected_deadline {
        Some((absolute_boottime_ns, epoch_ms)) => {
            attestation
                .monotonic_deadline
                .absolute_boottime_ns
                == absolute_boottime_ns
                && attestation.deadline_at_epoch_ms == epoch_ms
        }
        None => {
            attested_boottime_ns > observed_boottime_ns
                && attested_boottime_ns
                    .saturating_sub(observed_boottime_ns)
                    <= RESPONSE_OBSERVATION_V2_MAX_OPERATION_MS
                        .saturating_mul(1_000_000)
                && attestation.deadline_at_epoch_ms > now
                && attestation
                    .deadline_at_epoch_ms
                    .saturating_sub(now)
                    <= RESPONSE_OBSERVATION_V2_MAX_OPERATION_MS
        }
    };
    if attestation.api_version
        != V2_FRESH_RESPONSE_ATTESTATION_VERSION
        || attestation.attestation_mode
            != config.attestation_mode
        || attestation.request_sha256 != request_sha256
        || attestation.unsigned_response_sha256
            != unsigned_response_sha256
        || attestation.output_manifest_sha256
            != output_manifest_sha256
        || attestation.custody_boot_id != boot_id
        || attestation.signature_algorithm
            != V2FreshAttestationSignatureAlgorithm::Ed25519
        || attestation.signer_key_material_sha256
            != config.signer_key_sha256
        || attestation.signer_provider_id
            != response_attester_pin.provider_id
        || response_attester_pin.generation_id
            != config.generation_id
        || attestation.signer_key_id
            != response_attester_pin.key_id
        || attestation.provider_generation
            != response_attester_pin.provider_generation
        || custody_pin.generation_id != config.generation_id
        || attestation.provider_generation
            != custody_pin.provider_generation
        || attestation.custody_executable_measurement_sha256
            != custody_pin.executable_measurement_sha256
        || attestation.custody_provider_config_sha256
            != custody_pin.provider_config_sha256
        || attestation.custody_key_material_sha256
            != custody_pin.key_material_sha256
        || attestation.custody_tee_measurement_sha256
            != custody_pin.tee_measurement_sha256
        || attestation.role_identity_root_sha256
            != config.role_identity_root_sha256
        || attestation.proof_independent_pins_root_sha256
            != config.proof_pins_root_sha256
        || config
            .expected_provider_generation
            .is_some_and(|expected| {
                expected != attestation.provider_generation
            })
        || config
            .expected_trust_root_sha256
            .as_ref()
            .is_some_and(|expected| {
                expected
                    != &attestation
                        .trust_evidence
                        .trust_root_sha256
            })
        || config
            .expected_trust_checkpoint_sha256
            .as_ref()
            .is_some_and(|expected| {
                expected != &attestation.trust_checkpoint_sha256
            })
        || attestation.revocation_epoch
            < config.minimum_revocation_epoch
        || !deadline_matches
        || attestation.issued_at_epoch_ms == 0
        || attestation.issued_at_epoch_ms > now
        || attestation.expires_at_epoch_ms <= now
        || attestation.signature.is_empty()
    {
        return Err(
            "response-observation v2 attestation binding mismatch"
                .to_string(),
        );
    }
    let evidence =
        general_purpose::STANDARD
            .decode(&attestation.attestation_evidence_base64)
            .map_err(|_| {
                "response-observation v2 attestation evidence is not base64"
                    .to_string()
            })?;
    if evidence.is_empty()
        || evidence.len() > 128 * 1024
        || sha256_prefixed(&evidence)
            != attestation.attestation_evidence_sha256
        || attestation.tee_report_binding
            .unsigned_response_sha256
            != unsigned_response_sha256
        || attestation.tee_report_binding
            .output_manifest_sha256
            != output_manifest_sha256
        || attestation.tee_report_binding
            .authenticated_session_sha256
            != attestation.authenticated_session_sha256
        || attestation.tee_report_binding.challenge_nonce
            != attestation.challenge_nonce
        || attestation.tee_report_binding.signer_key_sha256
            != config.signer_key_sha256
        || attestation.tee_report_binding
            .custody_measurement_sha256
            != attestation
                .custody_executable_measurement_sha256
        || attestation.tee_report_binding.provider_generation
            != attestation.provider_generation
        || attestation.trust_evidence.trust_root_sha256
            != response_observation_v2_trust_artifact_sha256(
                &attestation.trust_evidence.trust_chain,
            )?
        || attestation.trust_evidence.trust_checkpoint_sha256
            != response_observation_v2_trust_artifact_sha256(
                &attestation.trust_evidence.endorsements,
            )?
        || attestation.trust_evidence.trust_checkpoint_sha256
            != attestation.trust_checkpoint_sha256
        || attestation.trust_evidence.revocation_epoch
            != attestation.revocation_epoch
        || attestation
            .trust_evidence
            .signer_revocation_receipt_sha256
            != attestation.current_revocation_receipt_sha256
        || attestation.trust_evidence.verified_at_epoch_ms
            < attestation.issued_at_epoch_ms
        || attestation.trust_evidence.verified_at_epoch_ms
            > attestation.expires_at_epoch_ms
        || !is_sha256_digest(
            &attestation
                .trust_evidence
                .evidence_verification_receipt_sha256,
        )
        || !is_sha256_digest(
            &attestation.current_revocation_receipt_sha256,
        )
    {
        return Err(
            "response-observation v2 attestation evidence digest mismatch"
                .to_string(),
        );
    }
    let (
        V2AttestationSignerKeyV1::InlineEd25519PublicKey {
            public_key_base64,
            public_key_sha256,
        },
        signature,
    ) = (
        &attestation.signer_key,
        general_purpose::STANDARD
            .decode(&attestation.signature)
            .map_err(|_| {
                "response-observation v2 signature is not base64"
                    .to_string()
            })?,
    )
    else {
        return Err(
            "response-observation v2 requires the pinned inline response signer key"
                .to_string(),
        );
    };
    let public_key = general_purpose::STANDARD
        .decode(public_key_base64)
        .map_err(|_| {
            "response-observation v2 signer key is not base64"
                .to_string()
        })?;
    if public_key.len() != 32
        || public_key_sha256 != &config.signer_key_sha256
        || sha256_prefixed(&public_key)
            != config.signer_key_sha256
    {
        return Err(
            "response-observation v2 signer key pin mismatch"
                .to_string(),
        );
    }
    let mut unsigned_attestation = attestation.clone();
    unsigned_attestation.signature.clear();
    let unsigned_attestation_bytes =
        custody_canonical_json_bytes(&unsigned_attestation)
            .map_err(|_| {
                "canonicalize response-observation v2 attestation"
                    .to_string()
            })?;
    let mut signing_message =
        V2_FRESH_RESPONSE_ATTESTATION_SIGNATURE_DOMAIN.to_vec();
    signing_message.extend_from_slice(&unsigned_attestation_bytes);
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::ED25519,
        &public_key,
    )
    .verify(&signing_message, &signature)
    .map_err(|_| {
        "response-observation v2 attestation signature is invalid"
            .to_string()
    })?;
    match config.attestation_mode {
        V2AttestationMode::TrustedHost => {
            if attestation.attestation_evidence_format
                != V2FreshAttestationEvidenceFormat::TrustedHostMeasurementBundleJsonV1
            {
                return Err(
                    "trusted-host response-observation v2 evidence format mismatch"
                        .to_string(),
                );
            }
            let observed: Value =
                decode_canonical_custody_json(&evidence)
                    .map_err(|_| {
                        "trusted-host response-observation v2 evidence is not canonical JSON"
                            .to_string()
                    })?;
            let expected = json!({
                "apiVersion":
                    "serverware.trustedHostEvidence.measurementBundle/v1",
                "providerId":attestation.signer_provider_id,
                "providerGeneration":attestation.provider_generation,
                "requestSha256":request_sha256,
                "unsignedResponseSha256":unsigned_response_sha256,
                "outputManifestSha256":output_manifest_sha256,
                "authenticatedSessionSha256":
                    attestation.authenticated_session_sha256,
                "challengeNonce":attestation.challenge_nonce,
                "custodyExecutableMeasurementSha256":
                    attestation
                        .custody_executable_measurement_sha256,
                "custodyProviderConfigSha256":
                    attestation.custody_provider_config_sha256,
                "responseSignerKeySha256":
                    config.signer_key_sha256,
                "monotonicDeadline":
                    attestation.monotonic_deadline,
                "deadlineAtEpochMs":
                    attestation.deadline_at_epoch_ms,
                "reportDataSha256":
                    attestation
                        .tee_report_binding
                        .report_data_sha256,
            });
            if observed != expected {
                return Err(
                    "trusted-host response-observation v2 evidence does not bind the exact measured response"
                        .to_string(),
                );
            }
        }
        V2AttestationMode::TeeHardware => {
            if attestation.attestation_evidence_format
                == V2FreshAttestationEvidenceFormat::TrustedHostMeasurementBundleJsonV1
            {
                return Err(
                    "TEE response-observation v2 requires a real hardware quote"
                        .to_string(),
                );
            }
            let verifier = config
                .tee_verifier
                .as_ref()
                .ok_or(
                    "TEE response-observation v2 verifier is not configured",
                )?;
            let topology_profile = config
                .tee_topology_profile
                .ok_or(
                    "TEE response-observation v2 topology profile is not configured",
                )?
                .as_str();
            let release_transparency_trust_pin_sha256 =
                canonical_transparency_sha256(
                    config.transparency_trust_pin.as_ref(),
                )
                .map_err(|error| error.to_string())?;
            let remaining = lifecycle_deadline
                .remaining()
                .unwrap_or(Duration::ZERO);
            if remaining.is_zero() {
                return Err(
                    "response-observation v2 TEE verifier deadline elapsed"
                        .to_string(),
                );
            }
            let verification =
                run_pinned_response_v2_tee_verifier(
                    verifier,
                    &json!({
                        "apiVersion":
                            "serverware.responseObservationV2AttestationVerifyRequest/v2",
                        "purpose":"fresh-response",
                        "attestation":attestation,
                        "expected":{
                            "requestSha256":request_sha256,
                            "unsignedResponseSha256":
                                unsigned_response_sha256,
                            "outputManifestSha256":
                                output_manifest_sha256,
                            "custodyBootId":boot_id,
                            "signerKeySha256":
                                config.signer_key_sha256,
                            "roleIdentityRootSha256":
                                config.role_identity_root_sha256,
                            "proofPinsRootSha256":
                                config.proof_pins_root_sha256,
                            "releaseTransparencyTrustPinSha256":
                                release_transparency_trust_pin_sha256,
                            "generationId":config.generation_id,
                            "providerGeneration":
                                attestation.provider_generation,
                            "sourceCommitSha256":
                                config.expected_source_commit_sha256,
                            "sourceTreeSha256":
                                config.expected_source_tree_sha256,
                            "attestationMode":"tee-hardware",
                            "topologyProfile":topology_profile,
                            "faultDomainCount":1,
                            "quorumThreshold":1,
                            "externalWitnessCount":0,
                            "faultTolerance":0,
                            "teeBoundary":LOCAL_TEE_BOUNDARY,
                            "securityClaim":LOCAL_TEE_SECURITY_CLAIM,
                            "verifierExecutableSha256":
                                &verifier.executable_sha256,
                            "verifierModuleSha256":verifier
                                .verifier_module
                                .as_ref()
                                .map(|module| module.sha256.as_str()),
                            "expectationsSha256":
                                &verifier.expectations.sha256,
                            "trustRootsSha256":
                                &verifier.trust_roots.sha256,
                        },
                    }),
                )?;
            if lifecycle_deadline.expired() {
                return Err(
                    "response-observation v2 TEE verification crossed the absolute CLOCK_BOOTTIME deadline"
                        .to_string(),
                );
            }
            let verification: TeeHardwareVerificationResultV2 =
                serde_json::from_value(verification).map_err(|_| {
                    "response-observation v2 TEE verifier returned an open or invalid result contract"
                        .to_string()
                })?;
            let claims = verification.claims;
            if verification.api_version
                    != TEE_VERIFICATION_RESULT_API_VERSION
                || !verification.ok
                || claims.request_sha256 != request_sha256
                || claims.unsigned_response_sha256
                    != unsigned_response_sha256
                || claims.output_manifest_sha256
                    != output_manifest_sha256
                || claims.custody_boot_id != boot_id
                || claims.challenge_nonce != attestation.challenge_nonce
                || claims.signer_key_sha256
                    != config.signer_key_sha256
                || claims.attestation_evidence_sha256
                    != attestation.attestation_evidence_sha256
                || claims.report_data_sha256
                    != attestation.tee_report_binding.report_data_sha256
                || claims.role_identity_root_sha256
                    != config.role_identity_root_sha256
                || claims.proof_pins_root_sha256
                    != config.proof_pins_root_sha256
                || claims.release_transparency_trust_pin_sha256
                    != release_transparency_trust_pin_sha256
                || claims.generation_id != config.generation_id
                || claims.provider_generation
                    != attestation.provider_generation
                || claims.source_commit_sha256
                    != config.expected_source_commit_sha256
                || claims.source_tree_sha256
                    != config.expected_source_tree_sha256
                || claims.custody_measurement_sha256
                    != attestation.custody_tee_measurement_sha256
                || claims.attestation_mode != "tee-hardware"
                || claims.topology_profile != topology_profile
                || claims.fault_domain_count != 1
                || claims.quorum_threshold != 1
                || claims.external_witness_count != 0
                || claims.fault_tolerance != 0
                || !claims.hardware_backed
                || !claims.quote_verified
                || claims.debug
                || claims.tee_boundary != LOCAL_TEE_BOUNDARY
                || claims.security_claim != LOCAL_TEE_SECURITY_CLAIM
                || claims.verifier_executable_sha256
                    != verifier.executable_sha256
                || claims.verifier_module_sha256.as_deref()
                    != verifier
                        .verifier_module
                        .as_ref()
                        .map(|module| module.sha256.as_str())
                || claims.expectations_sha256
                    != verifier.expectations.sha256
                || claims.trust_roots_sha256
                    != verifier.trust_roots.sha256
            {
                return Err(
                    "response-observation v2 TEE verifier rejected the exact response, release pin, or honest local 1-of-1 topology binding"
                        .to_string(),
                );
            }
        }
    }
    Ok(())
}

pub(super) fn verify_response_observation_v2_role_signature<T>(
    client: &ResponseObservationV2Client,
    expected_role: &str,
    expected_operation: &str,
    provider_id: &str,
    provider_generation: u64,
    key_id: &str,
    key_material_sha256: &str,
    signature: &str,
    unsigned_payload: &T,
) -> Result<(), ResponseObservationV2TransactionError>
where
    T: Serialize,
{
    let domain: &[u8] = match expected_role {
        "linearizable-store" => {
            V2_DURABLE_REPLAY_RECORD_SIGNATURE_DOMAIN
        }
        "persistence"
            if expected_operation
                == V2_INSPECT_IMMUTABLE_RESPONSE_OPERATION =>
        {
            V2_IMMUTABLE_RESPONSE_INSPECTION_SIGNATURE_DOMAIN
        }
        "live-proof-verifier"
            if expected_operation
                == V2_VALIDATE_FINAL_ENVELOPE_OPERATION =>
        {
            V2_FINAL_ENVELOPE_VERIFICATION_SIGNATURE_DOMAIN
        }
        "recovery" => V2_RECOVERY_OUTCOME_SIGNATURE_DOMAIN,
        "outcome-reconciliation"
            if expected_operation == V2_SETTLE_ATTEMPT_OPERATION =>
        {
            V2_DURABLE_SETTLEMENT_SIGNATURE_DOMAIN
        }
        "outcome-reconciliation" => {
            V2_OUTCOME_UNKNOWN_SIGNATURE_DOMAIN
        }
        "public-release" => {
            V2_PUBLIC_RELEASE_AUTHORIZATION_SIGNATURE_DOMAIN
        }
        "public-release-consumption"
            if expected_operation
                == V2_CONSUME_AND_RETRIEVE_EXACT_OPERATION =>
        {
            V2_EXACT_RELEASE_CONSUMPTION_SIGNATURE_DOMAIN
        }
        "public-release-consumption" => {
            V2_RELEASE_CONSUMPTION_SIGNATURE_DOMAIN
        }
        _ => {
            return Err(
                ResponseObservationV2TransactionError::InvalidResponse,
            )
        }
    };
    verify_response_observation_v2_role_signature_in_domain(
        client,
        expected_role,
        expected_operation,
        provider_id,
        provider_generation,
        key_id,
        key_material_sha256,
        signature,
        unsigned_payload,
        domain,
    )
}

pub(super) fn verify_response_observation_v2_role_signature_in_domain<T>(
    client: &ResponseObservationV2Client,
    expected_role: &str,
    expected_operation: &str,
    provider_id: &str,
    provider_generation: u64,
    key_id: &str,
    key_material_sha256: &str,
    signature: &str,
    unsigned_payload: &T,
    domain: &[u8],
) -> Result<(), ResponseObservationV2TransactionError>
where
    T: Serialize,
{
    let pin = client
        .role_keys
        .get(expected_role)
        .ok_or(ResponseObservationV2TransactionError::InvalidResponse)?;
    if provider_generation != client.provider_generation
        || pin.generation_id != client.generation_id
        || pin.provider_generation != provider_generation
        || pin.provider_id != provider_id
        || pin.key_id != key_id
        || pin.key_material_sha256 != key_material_sha256
        || !pin
            .allowed_operations
            .iter()
            .any(|operation| operation == expected_operation)
    {
        return Err(
            ResponseObservationV2TransactionError::InvalidResponse,
        );
    }
    let public_key = general_purpose::STANDARD
        .decode(&pin.public_key_base64)
        .map_err(|_| {
            ResponseObservationV2TransactionError::InvalidResponse
        })?;
    let signature = general_purpose::STANDARD
        .decode(signature)
        .map_err(|_| {
            ResponseObservationV2TransactionError::InvalidResponse
        })?;
    if public_key.len() != 32
        || signature.len() != 64
        || sha256_prefixed(&public_key) != pin.public_key_sha256
    {
        return Err(
            ResponseObservationV2TransactionError::InvalidResponse,
        );
    }
    let payload = custody_canonical_json_bytes(unsigned_payload)
        .map_err(|_| {
            ResponseObservationV2TransactionError::InvalidResponse
        })?;
    let mut signing_message =
        Vec::with_capacity(domain.len() + payload.len());
    signing_message.extend_from_slice(domain);
    signing_message.extend_from_slice(&payload);
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::ED25519,
        &public_key,
    )
    .verify(&signing_message, &signature)
    .map_err(|_| {
        ResponseObservationV2TransactionError::InvalidResponse
    })
}

pub(super) fn response_observation_v2_validate_provider_scope(
    client: &ResponseObservationV2Client,
    scope: &V2ProviderAuthorityScopeV1,
    expected_role: &str,
    expected_operation: &str,
    expected_request_sha256: &str,
    expected_attempt_id: &str,
    expected_attempt_revision: u64,
    expected_predecessor_state_sha256: &str,
    expected_fencing_token: u64,
    expected_binding_sha256: &str,
) -> Result<(), ResponseObservationV2TransactionError> {
    let pin = client
        .role_keys
        .get(expected_role)
        .ok_or(ResponseObservationV2TransactionError::InvalidResponse)?;
    if scope.role != expected_role
        || scope.provider_id != pin.provider_id
        || scope.provider_generation != client.provider_generation
        || scope.provider_generation != pin.provider_generation
        || scope.provider_operation_id.is_empty()
        || scope.request_sha256 != expected_request_sha256
        || scope.attempt_id != expected_attempt_id
        || scope.attempt_revision != expected_attempt_revision
        || scope.predecessor_state_sha256
            != expected_predecessor_state_sha256
        || scope.launch_nonce.is_empty()
        || scope.fencing_token != expected_fencing_token
        || !is_sha256_digest(
            &scope.kernel_process_identity_sha256,
        )
        || scope.executable_measurement_sha256
            != pin.executable_measurement_sha256
        || scope.provider_config_sha256
            != pin.provider_config_sha256
        || scope.key_material_sha256
            != pin.key_material_sha256
        || scope.tee_measurement_sha256
            != pin.tee_measurement_sha256
        || !is_sha256_digest(&scope.launch_attestation_sha256)
        || !pin
            .allowed_operations
            .iter()
            .any(|operation| operation == expected_operation)
    {
        return Err(
            ResponseObservationV2TransactionError::InvalidResponse,
        );
    }
    let mut hasher = Sha256::new();
    response_observation_v2_hash_frame(
        &mut hasher,
        b"serverware.response-v2/provider-authority-scope/v1",
    );
    for value in [
        scope.role.as_bytes(),
        scope.provider_id.as_bytes(),
        scope.provider_operation_id.as_bytes(),
        scope.request_sha256.as_bytes(),
        scope.attempt_id.as_bytes(),
        scope.predecessor_state_sha256.as_bytes(),
        scope.launch_nonce.as_bytes(),
        scope.kernel_process_identity_sha256.as_bytes(),
        scope.executable_measurement_sha256.as_bytes(),
        scope.provider_config_sha256.as_bytes(),
        scope.key_material_sha256.as_bytes(),
        scope.tee_measurement_sha256.as_bytes(),
        scope.launch_attestation_sha256.as_bytes(),
    ] {
        response_observation_v2_hash_frame(&mut hasher, value);
    }
    for value in [
        scope.provider_generation,
        scope.attempt_revision,
        scope.fencing_token,
    ] {
        response_observation_v2_hash_frame(
            &mut hasher,
            &value.to_be_bytes(),
        );
    }
    if format!("sha256:{:x}", hasher.finalize())
        != expected_binding_sha256
    {
        return Err(
            ResponseObservationV2TransactionError::InvalidResponse,
        );
    }
    Ok(())
}

pub(super) fn response_observation_v2_trust_artifact_sha256(
    artifact: &V2AttestationTrustArtifactV1,
) -> Result<&str, String> {
    match artifact {
        V2AttestationTrustArtifactV1::InlineDerBundle {
            der_bundle_base64,
            der_bundle_sha256,
        } => {
            let bytes = general_purpose::STANDARD
                .decode(der_bundle_base64)
                .map_err(|_| {
                    "response-observation v2 trust artifact is not base64"
                        .to_string()
                })?;
            if bytes.is_empty()
                || sha256_prefixed(&bytes)
                    != der_bundle_sha256.as_str()
            {
                return Err(
                    "response-observation v2 inline trust artifact digest mismatch"
                        .to_string(),
                );
            }
            Ok(der_bundle_sha256)
        }
        V2AttestationTrustArtifactV1::ImmutableTrustReference {
            retrieval_id,
            artifact_sha256,
            persistence_receipt_sha256,
        } => {
            if retrieval_id.is_empty()
                || !is_sha256_digest(artifact_sha256)
                || !is_sha256_digest(
                    persistence_receipt_sha256,
                )
            {
                return Err(
                    "response-observation v2 immutable trust reference is invalid"
                        .to_string(),
                );
            }
            Ok(artifact_sha256)
        }
    }
}
