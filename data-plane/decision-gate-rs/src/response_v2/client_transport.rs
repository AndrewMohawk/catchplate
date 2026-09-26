use super::*;

const RESPONSE_OBSERVATION_V2_ROLE_KEYS_ENV: &str =
    "SERVERWARE_RESPONSE_OBSERVATION_V2_ROLE_KEYS_JSON";
const RESPONSE_OBSERVATION_V2_GENERATION_ID_ENV: &str =
    "SERVERWARE_RESPONSE_OBSERVATION_V2_GENERATION_ID";
const RESPONSE_OBSERVATION_V2_SOURCE_COMMIT_SHA256_ENV: &str =
    "SERVERWARE_RESPONSE_OBSERVATION_V2_SOURCE_COMMIT_SHA256";
const RESPONSE_OBSERVATION_V2_SOURCE_TREE_SHA256_ENV: &str =
    "SERVERWARE_RESPONSE_OBSERVATION_V2_SOURCE_TREE_SHA256";
const RESPONSE_OBSERVATION_V2_TRANSPARENCY_TRUST_PIN_ENV: &str =
    "SERVERWARE_RESPONSE_OBSERVATION_V2_TRANSPARENCY_TRUST_PIN_JSON";
const RESPONSE_OBSERVATION_V2_TEE_TOPOLOGY_PROFILE_ENV: &str =
    "SERVERWARE_RESPONSE_OBSERVATION_V2_TEE_TOPOLOGY_PROFILE";
const RESPONSE_OBSERVATION_V2_TEE_VERIFIER_API_VERSION: &str =
    "serverware.responseObservationV2PinnedTeeVerifier/v1";
const RESPONSE_OBSERVATION_V2_TEE_VERIFIER_MODULE_FILE_ENV: &str =
    "SERVERWARE_RESPONSE_V2_TEE_VERIFIER_MODULE_FILE";
const RESPONSE_OBSERVATION_V2_TEE_VERIFIER_MODULE_SHA256_ENV: &str =
    "SERVERWARE_RESPONSE_V2_TEE_VERIFIER_MODULE_SHA256";
const RESPONSE_OBSERVATION_V2_TEE_EXPECTATIONS_FILE_ENV: &str =
    "SERVERWARE_RESPONSE_V2_TEE_EXPECTATIONS_FILE";
const RESPONSE_OBSERVATION_V2_TEE_EXPECTATIONS_SHA256_ENV: &str =
    "SERVERWARE_RESPONSE_V2_TEE_EXPECTATIONS_SHA256";
const RESPONSE_OBSERVATION_V2_NITRO_TRUST_ROOTS_FILE_ENV: &str =
    "SERVERWARE_RESPONSE_V2_NITRO_TRUST_ROOTS_FILE";
const RESPONSE_OBSERVATION_V2_NITRO_TRUST_ROOTS_SHA256_ENV: &str =
    "SERVERWARE_RESPONSE_V2_NITRO_TRUST_ROOTS_SHA256";

fn response_observation_v2_measured_verifier_input(
    path: Option<OsString>,
    sha256: Option<OsString>,
    path_name: &str,
    sha256_name: &str,
    required: bool,
) -> Result<Option<ResponseV2MeasuredVerifierInput>, String> {
    let (path, sha256) = match (path, sha256) {
        (Some(path), Some(sha256)) => (path, sha256),
        (None, None) if !required => return Ok(None),
        _ => {
            return Err(format!(
                "{path_name} and {sha256_name} must be configured together"
            ));
        }
    };
    let path = PathBuf::from(path);
    let sha256 = sha256
        .into_string()
        .map_err(|_| format!("{sha256_name} must be UTF-8"))?;
    let input = ResponseV2MeasuredVerifierInput { path, sha256 };
    if !input.path.is_absolute() || !is_sha256_digest(&input.sha256) {
        return Err(format!(
            "{path_name} must be absolute and {sha256_name} must be a lowercase SHA-256 digest"
        ));
    }
    Ok(Some(input))
}

#[allow(clippy::too_many_arguments)]
fn response_observation_v2_pinned_tee_verifier(
    attestation_mode: V2AttestationMode,
    command: Option<OsString>,
    digest_manifest: Option<OsString>,
    module_path: Option<OsString>,
    module_sha256: Option<OsString>,
    expectations_path: Option<OsString>,
    expectations_sha256: Option<OsString>,
    trust_roots_path: Option<OsString>,
    trust_roots_sha256: Option<OsString>,
) -> Result<Option<ResponseV2PinnedTeeVerifier>, String> {
    let command = command
        .map(|value| {
            value.into_string().map_err(|_| {
                format!(
                    "{RESPONSE_OBSERVATION_V2_TEE_VERIFY_COMMAND_ENV} must be UTF-8"
                )
            })
        })
        .transpose()?
        .filter(|value| !value.trim().is_empty());
    let manifest = digest_manifest
        .map(|value| {
            value.into_string().map_err(|_| {
                format!(
                    "{ATTESTATION_EXECUTABLE_SHA256_MANIFEST_ENV} must be UTF-8"
                )
            })
        })
        .transpose()?;
    let manifest = manifest
        .as_deref()
        .map(|raw| {
            serde_json::from_str::<BTreeMap<String, String>>(raw).map_err(
                |_| {
                    format!(
                        "{ATTESTATION_EXECUTABLE_SHA256_MANIFEST_ENV} must be a JSON object of executable SHA-256 pins"
                    )
                },
            )
        })
        .transpose()?
        .unwrap_or_default();
    let executable_sha256 = manifest
        .get(RESPONSE_OBSERVATION_V2_TEE_VERIFY_COMMAND_ENV)
        .cloned();
    let any_input = module_path.is_some()
        || module_sha256.is_some()
        || expectations_path.is_some()
        || expectations_sha256.is_some()
        || trust_roots_path.is_some()
        || trust_roots_sha256.is_some();
    if attestation_mode == V2AttestationMode::TrustedHost {
        if command.is_some() || executable_sha256.is_some() || any_input {
            return Err(
                "response-observation v2 TEE verifier configuration is forbidden outside tee-hardware mode"
                    .to_string(),
            );
        }
        return Ok(None);
    }
    let command = command.ok_or_else(|| {
        format!(
            "{RESPONSE_OBSERVATION_V2_TEE_VERIFY_COMMAND_ENV} is required in tee-hardware mode"
        )
    })?;
    let executable_sha256 = executable_sha256.ok_or_else(|| {
        format!(
            "{ATTESTATION_EXECUTABLE_SHA256_MANIFEST_ENV}.{RESPONSE_OBSERVATION_V2_TEE_VERIFY_COMMAND_ENV} is required in tee-hardware mode"
        )
    })?;
    if !is_sha256_digest(&executable_sha256) {
        return Err(format!(
            "{ATTESTATION_EXECUTABLE_SHA256_MANIFEST_ENV}.{RESPONSE_OBSERVATION_V2_TEE_VERIFY_COMMAND_ENV} must be a lowercase SHA-256 digest"
        ));
    }
    let argv = shlex::split(&command).ok_or_else(|| {
        format!(
            "{RESPONSE_OBSERVATION_V2_TEE_VERIFY_COMMAND_ENV} has invalid quoting"
        )
    })?;
    let (executable, arguments) = argv.split_first().ok_or_else(|| {
        format!(
            "{RESPONSE_OBSERVATION_V2_TEE_VERIFY_COMMAND_ENV} is empty"
        )
    })?;
    let verifier_module = response_observation_v2_measured_verifier_input(
        module_path,
        module_sha256,
        RESPONSE_OBSERVATION_V2_TEE_VERIFIER_MODULE_FILE_ENV,
        RESPONSE_OBSERVATION_V2_TEE_VERIFIER_MODULE_SHA256_ENV,
        false,
    )?;
    let expectations = response_observation_v2_measured_verifier_input(
        expectations_path,
        expectations_sha256,
        RESPONSE_OBSERVATION_V2_TEE_EXPECTATIONS_FILE_ENV,
        RESPONSE_OBSERVATION_V2_TEE_EXPECTATIONS_SHA256_ENV,
        true,
    )?
    .ok_or("response-observation v2 TEE expectations are missing")?;
    let trust_roots = response_observation_v2_measured_verifier_input(
        trust_roots_path,
        trust_roots_sha256,
        RESPONSE_OBSERVATION_V2_NITRO_TRUST_ROOTS_FILE_ENV,
        RESPONSE_OBSERVATION_V2_NITRO_TRUST_ROOTS_SHA256_ENV,
        true,
    )?
    .ok_or("response-observation v2 Nitro trust roots are missing")?;
    let verifier = ResponseV2PinnedTeeVerifier {
        api_version:
            RESPONSE_OBSERVATION_V2_TEE_VERIFIER_API_VERSION.to_string(),
        executable: PathBuf::from(executable),
        arguments: arguments.to_vec(),
        executable_sha256,
        verifier_module,
        expectations,
        trust_roots,
    };
    verifier.validate()?;
    Ok(Some(verifier))
}

fn response_observation_v2_required_sha256(
    value: Option<std::ffi::OsString>,
    name: &str,
) -> Result<String, String> {
    let value = value
        .ok_or_else(|| format!("{name} is required with the v2 socket"))?
        .into_string()
        .map_err(|_| format!("{name} must be UTF-8"))?;
    if !is_sha256_digest(&value) {
        return Err(format!(
            "{name} must be a lowercase sha256 digest"
        ));
    }
    Ok(value)
}

fn response_observation_v2_role_keys(
    encoded: OsString,
    expected_root_sha256: &str,
    response_signer_key_sha256: &str,
    expected_generation_id: &str,
) -> Result<Arc<BTreeMap<String, V2PinnedRoleKeyV1>>, String> {
    let encoded = encoded.into_string().map_err(|_| {
        format!("{RESPONSE_OBSERVATION_V2_ROLE_KEYS_ENV} must be UTF-8")
    })?;
    let mut pins: Vec<V2PinnedRoleKeyV1> =
        decode_canonical_custody_json(encoded.as_bytes()).map_err(|_| {
            format!(
                "{RESPONSE_OBSERVATION_V2_ROLE_KEYS_ENV} must be canonical closed JSON"
            )
        })?;
    pins.sort_by(|left, right| left.role.cmp(&right.role));
    let mut result = BTreeMap::new();
    for pin in pins {
        if result.insert(pin.role.clone(), pin).is_some() {
            return Err(
                "response-observation v2 role-key pin is duplicated"
                    .to_string(),
            );
        }
    }
    validate_response_observation_v2_role_keys(
        &result,
        expected_root_sha256,
        response_signer_key_sha256,
        expected_generation_id,
    )?;
    Ok(Arc::new(result))
}

fn validate_response_observation_v2_role_keys(
    result: &BTreeMap<String, V2PinnedRoleKeyV1>,
    expected_root_sha256: &str,
    response_signer_key_sha256: &str,
    expected_generation_id: &str,
) -> Result<(), String> {
    if result.is_empty() {
        return Err(format!(
            "{RESPONSE_OBSERVATION_V2_ROLE_KEYS_ENV} must pin at least one authority role"
        ));
    }
    for (role, pin) in result {
        let mut operations = pin.allowed_operations.clone();
        operations.sort();
        operations.dedup();
        let public_key = general_purpose::STANDARD
            .decode(&pin.public_key_base64)
            .map_err(|_| {
                "response-observation v2 role public key is not base64"
                    .to_string()
            })?;
        if pin.role.is_empty()
            || role != &pin.role
            || pin.generation_id != expected_generation_id
            || pin.provider_id.is_empty()
            || pin.provider_generation == 0
            || !is_sha256_digest(&pin.key_id)
            || !is_sha256_digest(&pin.key_material_sha256)
            || !Path::new(&pin.key_material_path).is_absolute()
            || !is_sha256_digest(
                &pin.executable_measurement_sha256,
            )
            || !Path::new(&pin.executable_path).is_absolute()
            || !is_sha256_digest(&pin.provider_config_sha256)
            || !Path::new(&pin.provider_config_path).is_absolute()
            || !is_sha256_digest(&pin.tee_measurement_sha256)
            || public_key.len() != 32
            || sha256_prefixed(&public_key) != pin.public_key_sha256
            || pin.public_key_sha256 != pin.key_material_sha256
            || pin.key_id != pin.public_key_sha256
            || pin.allowed_operations.is_empty()
            || operations != pin.allowed_operations
            || pin
                .allowed_operations
                .iter()
                .any(|operation| operation.is_empty())
        {
            return Err(
                "response-observation v2 role-key pin is incomplete, duplicated, or inconsistent"
                    .to_string(),
            );
        }
    }
    let mut identity_root = Sha256::new();
    response_observation_v2_hash_frame(
        &mut identity_root,
        b"serverware.response-v2/role-identities/v2",
    );
    for pin in result.values() {
        response_observation_v2_hash_frame(
            &mut identity_root,
            pin.role.as_bytes(),
        );
        response_observation_v2_hash_frame(
            &mut identity_root,
            pin.provider_id.as_bytes(),
        );
        response_observation_v2_hash_frame(
            &mut identity_root,
            &pin.provider_generation.to_be_bytes(),
        );
        response_observation_v2_hash_frame(
            &mut identity_root,
            pin.key_id.as_bytes(),
        );
        response_observation_v2_hash_frame(
            &mut identity_root,
            pin.key_material_sha256.as_bytes(),
        );
        response_observation_v2_hash_frame(
            &mut identity_root,
            pin.key_material_path.as_bytes(),
        );
        response_observation_v2_hash_frame(
            &mut identity_root,
            pin.executable_measurement_sha256.as_bytes(),
        );
        response_observation_v2_hash_frame(
            &mut identity_root,
            pin.executable_path.as_bytes(),
        );
        response_observation_v2_hash_frame(
            &mut identity_root,
            pin.provider_config_sha256.as_bytes(),
        );
        response_observation_v2_hash_frame(
            &mut identity_root,
            pin.provider_config_path.as_bytes(),
        );
        response_observation_v2_hash_frame(
            &mut identity_root,
            pin.tee_measurement_sha256.as_bytes(),
        );
        for operation in &pin.allowed_operations {
            response_observation_v2_hash_frame(
                &mut identity_root,
                operation.as_bytes(),
            );
        }
    }
    if format!("sha256:{:x}", identity_root.finalize())
        != expected_root_sha256
    {
        return Err(
            "response-observation v2 role-key pins do not match the attested role identity root"
                .to_string(),
        );
    }
    let response_attester = result
        .get("runtime-attestation")
        .ok_or(
            "response-observation v2 role pins omit runtime-attestation",
        )?;
    let custody = result.get("custody").ok_or(
        "response-observation v2 role pins omit custody",
    )?;
    if FINAL_ARTIFACTS.iter().any(|expectation| {
        result
            .get(expectation.logical_role)
            .is_none_or(|pin| {
                !pin.allowed_operations.iter().any(|operation| {
                    operation == expectation.operation
                })
            })
    }) || response_attester.key_material_sha256
        != response_signer_key_sha256
        || custody.provider_generation
            != response_attester.provider_generation
        || !RESPONSE_OBSERVATION_V2_CAPABILITIES
            .iter()
            .all(|required| {
                response_attester
                    .allowed_operations
                    .iter()
                    .any(|observed| observed == required)
            })
    {
        return Err(
            "response-observation v2 role pins do not authorize the complete outer and nested response surface"
                .to_string(),
        );
    }
    Ok(())
}

fn response_observation_v2_transparency_trust_pin(
    encoded: OsString,
    generation_id: &str,
    proof_pins_root_sha256: &str,
) -> Result<Arc<ReleaseTransparencyTrustPinV2>, String> {
    let encoded = encoded.into_string().map_err(|_| {
        format!(
            "{RESPONSE_OBSERVATION_V2_TRANSPARENCY_TRUST_PIN_ENV} must be UTF-8"
        )
    })?;
    let pin: ReleaseTransparencyTrustPinV2 =
        decode_canonical_custody_json(encoded.as_bytes()).map_err(|_| {
            format!(
                "{RESPONSE_OBSERVATION_V2_TRANSPARENCY_TRUST_PIN_ENV} must be canonical closed JSON"
            )
        })?;
    validate_response_observation_v2_transparency_trust_pin(
        &pin,
        generation_id,
        proof_pins_root_sha256,
    )?;
    Ok(Arc::new(pin))
}

fn validate_response_observation_v2_transparency_trust_pin(
    pin: &ReleaseTransparencyTrustPinV2,
    generation_id: &str,
    proof_pins_root_sha256: &str,
) -> Result<(), String> {
    let now = u64::try_from(now_epoch_ms()).map_err(|_| {
        "response-observation v2 transparency pin clock is invalid"
            .to_string()
    })?;
    validate_release_transparency_trust_pin(pin, now)
        .map_err(|error| error.to_string())?;
    if pin.generation_id != generation_id
        || pin.proof_pins_root_sha256 != proof_pins_root_sha256
    {
        return Err(
            "response-observation v2 transparency pin does not match the independently pinned generation and proof root"
                .to_string(),
        );
    }
    Ok(())
}

pub(super) fn response_observation_v2_client_config(
    is_production: bool,
) -> Result<Option<ResponseObservationV2ClientConfig>, String> {
    let socket = env::var_os(RESPONSE_OBSERVATION_V2_SOCKET_ENV);
    let expected_uid =
        env::var_os(RESPONSE_OBSERVATION_V2_EXPECTED_UID_ENV);
    let timeout = env::var_os(
        RESPONSE_OBSERVATION_V2_STARTUP_TIMEOUT_MS_ENV,
    );
    let attestation_mode =
        env::var_os(RESPONSE_OBSERVATION_V2_ATTESTATION_MODE_ENV);
    let signer_key_sha256 =
        env::var_os(RESPONSE_OBSERVATION_V2_SIGNER_KEY_SHA256_ENV);
    let role_identity_root_sha256 = env::var_os(
        RESPONSE_OBSERVATION_V2_ROLE_IDENTITY_ROOT_SHA256_ENV,
    );
    let proof_pins_root_sha256 = env::var_os(
        RESPONSE_OBSERVATION_V2_PROOF_PINS_ROOT_SHA256_ENV,
    );
    let tee_verify_command =
        env::var_os(RESPONSE_OBSERVATION_V2_TEE_VERIFY_COMMAND_ENV);
    let tee_verifier_digest_manifest =
        env::var_os(ATTESTATION_EXECUTABLE_SHA256_MANIFEST_ENV);
    let tee_verifier_module_file = env::var_os(
        RESPONSE_OBSERVATION_V2_TEE_VERIFIER_MODULE_FILE_ENV,
    );
    let tee_verifier_module_sha256 = env::var_os(
        RESPONSE_OBSERVATION_V2_TEE_VERIFIER_MODULE_SHA256_ENV,
    );
    let tee_expectations_file = env::var_os(
        RESPONSE_OBSERVATION_V2_TEE_EXPECTATIONS_FILE_ENV,
    );
    let tee_expectations_sha256 = env::var_os(
        RESPONSE_OBSERVATION_V2_TEE_EXPECTATIONS_SHA256_ENV,
    );
    let tee_trust_roots_file = env::var_os(
        RESPONSE_OBSERVATION_V2_NITRO_TRUST_ROOTS_FILE_ENV,
    );
    let tee_trust_roots_sha256 = env::var_os(
        RESPONSE_OBSERVATION_V2_NITRO_TRUST_ROOTS_SHA256_ENV,
    );
    let role_keys =
        env::var_os(RESPONSE_OBSERVATION_V2_ROLE_KEYS_ENV);
    let generation_id =
        env::var_os(RESPONSE_OBSERVATION_V2_GENERATION_ID_ENV);
    let expected_source_commit_sha256 = env::var_os(
        RESPONSE_OBSERVATION_V2_SOURCE_COMMIT_SHA256_ENV,
    );
    let expected_source_tree_sha256 = env::var_os(
        RESPONSE_OBSERVATION_V2_SOURCE_TREE_SHA256_ENV,
    );
    let transparency_trust_pin = env::var_os(
        RESPONSE_OBSERVATION_V2_TRANSPARENCY_TRUST_PIN_ENV,
    );
    let tee_topology_profile = env::var_os(
        RESPONSE_OBSERVATION_V2_TEE_TOPOLOGY_PROFILE_ENV,
    );
    let Some(socket) = socket else {
        if expected_uid.is_some()
            || timeout.is_some()
            || attestation_mode.is_some()
            || signer_key_sha256.is_some()
            || role_identity_root_sha256.is_some()
            || proof_pins_root_sha256.is_some()
            || tee_verify_command.is_some()
            || tee_verifier_module_file.is_some()
            || tee_verifier_module_sha256.is_some()
            || tee_expectations_file.is_some()
            || tee_expectations_sha256.is_some()
            || tee_trust_roots_file.is_some()
            || tee_trust_roots_sha256.is_some()
            || role_keys.is_some()
            || generation_id.is_some()
            || expected_source_commit_sha256.is_some()
            || expected_source_tree_sha256.is_some()
            || transparency_trust_pin.is_some()
            || tee_topology_profile.is_some()
        {
            return Err(format!(
                "response-observation v2 UID, timeout, attestation mode, signer pin, and verifier require {RESPONSE_OBSERVATION_V2_SOCKET_ENV}"
            ));
        }
        if is_production {
            return Err(format!(
                "production requires the response-observation v2 custody client via {RESPONSE_OBSERVATION_V2_SOCKET_ENV}"
            ));
        }
        return Ok(None);
    };
    let socket_path = PathBuf::from(socket);
    if !socket_path.is_absolute() {
        return Err(format!(
            "{RESPONSE_OBSERVATION_V2_SOCKET_ENV} must be absolute"
        ));
    }
    let expected_uid = expected_uid
        .ok_or_else(|| {
            format!(
                "{RESPONSE_OBSERVATION_V2_EXPECTED_UID_ENV} is required with the v2 socket"
            )
        })?
        .into_string()
        .map_err(|_| {
            format!(
                "{RESPONSE_OBSERVATION_V2_EXPECTED_UID_ENV} must be UTF-8"
            )
        })?
        .parse::<libc::uid_t>()
        .map_err(|error| {
            format!(
                "{RESPONSE_OBSERVATION_V2_EXPECTED_UID_ENV} must be a UID: {error}"
            )
        })?;
    let startup_timeout_ms = timeout
        .map(|value| {
            value
                .into_string()
                .map_err(|_| {
                    format!(
                        "{RESPONSE_OBSERVATION_V2_STARTUP_TIMEOUT_MS_ENV} must be UTF-8"
                    )
                })?
                .parse::<u64>()
                .map_err(|error| {
                    format!(
                        "{RESPONSE_OBSERVATION_V2_STARTUP_TIMEOUT_MS_ENV} must be milliseconds: {error}"
                    )
                })
        })
        .transpose()?
        .unwrap_or(
            DEFAULT_RESPONSE_OBSERVATION_V2_STARTUP_TIMEOUT_MS,
        );
    if !(1..=MAX_RESPONSE_OBSERVATION_V2_STARTUP_TIMEOUT_MS)
        .contains(&startup_timeout_ms)
    {
        return Err(format!(
            "{RESPONSE_OBSERVATION_V2_STARTUP_TIMEOUT_MS_ENV} must be between 1 and {MAX_RESPONSE_OBSERVATION_V2_STARTUP_TIMEOUT_MS}"
        ));
    }
    let attestation_mode = attestation_mode
        .ok_or_else(|| {
            format!(
                "{RESPONSE_OBSERVATION_V2_ATTESTATION_MODE_ENV} is required with the v2 socket"
            )
        })?
        .into_string()
        .map_err(|_| {
            format!(
                "{RESPONSE_OBSERVATION_V2_ATTESTATION_MODE_ENV} must be UTF-8"
            )
        })?;
    let attestation_mode = match attestation_mode.as_str() {
        "trusted-host-no-tee" => V2AttestationMode::TrustedHost,
        "tee-hardware" => V2AttestationMode::TeeHardware,
        _ => {
            return Err(format!(
                "{RESPONSE_OBSERVATION_V2_ATTESTATION_MODE_ENV} must be trusted-host-no-tee or tee-hardware"
            ))
        }
    };
    let tee_topology_profile = tee_topology_profile
        .map(|value| {
            value.into_string().map_err(|_| {
                format!(
                    "{RESPONSE_OBSERVATION_V2_TEE_TOPOLOGY_PROFILE_ENV} must be UTF-8"
                )
            })
        })
        .transpose()?;
    let tee_topology_profile = match (
        attestation_mode,
        tee_topology_profile.as_deref(),
    ) {
        (
            V2AttestationMode::TeeHardware,
            Some("local-single-node-1-of-1"),
        ) => Some(
            ResponseObservationV2TeeTopologyProfile::
                LocalSingleNodeOneOfOne,
        ),
        (V2AttestationMode::TeeHardware, _) => {
            return Err(format!(
                "{RESPONSE_OBSERVATION_V2_TEE_TOPOLOGY_PROFILE_ENV} must explicitly be local-single-node-1-of-1 in tee-hardware mode"
            ))
        }
        (V2AttestationMode::TrustedHost, None) => None,
        (V2AttestationMode::TrustedHost, Some(_)) => {
            return Err(format!(
                "{RESPONSE_OBSERVATION_V2_TEE_TOPOLOGY_PROFILE_ENV} is forbidden outside tee-hardware mode"
            ))
        }
    };
    let signer_key_sha256 = signer_key_sha256
        .ok_or_else(|| {
            format!(
                "{RESPONSE_OBSERVATION_V2_SIGNER_KEY_SHA256_ENV} is required with the v2 socket"
            )
        })?
        .into_string()
        .map_err(|_| {
            format!(
                "{RESPONSE_OBSERVATION_V2_SIGNER_KEY_SHA256_ENV} must be UTF-8"
            )
        })?;
    if !is_sha256_digest(&signer_key_sha256) {
        return Err(format!(
            "{RESPONSE_OBSERVATION_V2_SIGNER_KEY_SHA256_ENV} must be a lowercase sha256 digest"
        ));
    }
    let role_identity_root_sha256 =
        role_identity_root_sha256
            .ok_or_else(|| {
                format!(
                    "{RESPONSE_OBSERVATION_V2_ROLE_IDENTITY_ROOT_SHA256_ENV} is required with the v2 socket"
                )
            })?
            .into_string()
            .map_err(|_| {
                format!(
                    "{RESPONSE_OBSERVATION_V2_ROLE_IDENTITY_ROOT_SHA256_ENV} must be UTF-8"
                )
            })?;
    if !is_sha256_digest(&role_identity_root_sha256) {
        return Err(format!(
            "{RESPONSE_OBSERVATION_V2_ROLE_IDENTITY_ROOT_SHA256_ENV} must be a lowercase sha256 digest"
        ));
    }
    let generation_id = generation_id
        .ok_or_else(|| {
            format!(
                "{RESPONSE_OBSERVATION_V2_GENERATION_ID_ENV} is required with the v2 socket"
            )
        })?
        .into_string()
        .map_err(|_| {
            format!(
                "{RESPONSE_OBSERVATION_V2_GENERATION_ID_ENV} must be UTF-8"
            )
        })?;
    if generation_id.is_empty()
        || generation_id.len() > 256
        || generation_id.bytes().any(|byte| {
            byte.is_ascii_control() || byte.is_ascii_whitespace()
        })
    {
        return Err(format!(
            "{RESPONSE_OBSERVATION_V2_GENERATION_ID_ENV} must be a nonempty bounded identifier"
        ));
    }
    let role_keys = response_observation_v2_role_keys(
        role_keys.ok_or_else(|| {
            format!(
                "{RESPONSE_OBSERVATION_V2_ROLE_KEYS_ENV} is required with the v2 socket"
            )
        })?,
        &role_identity_root_sha256,
        &signer_key_sha256,
        &generation_id,
    )?;
    let expected_source_commit_sha256 =
        response_observation_v2_required_sha256(
            expected_source_commit_sha256,
            RESPONSE_OBSERVATION_V2_SOURCE_COMMIT_SHA256_ENV,
        )?;
    let expected_source_tree_sha256 =
        response_observation_v2_required_sha256(
            expected_source_tree_sha256,
            RESPONSE_OBSERVATION_V2_SOURCE_TREE_SHA256_ENV,
        )?;
    let proof_pins_root_sha256 =
        proof_pins_root_sha256
            .ok_or_else(|| {
                format!(
                    "{RESPONSE_OBSERVATION_V2_PROOF_PINS_ROOT_SHA256_ENV} is required with the v2 socket"
                )
            })?
            .into_string()
            .map_err(|_| {
                format!(
                    "{RESPONSE_OBSERVATION_V2_PROOF_PINS_ROOT_SHA256_ENV} must be UTF-8"
                )
            })?;
    if !is_sha256_digest(&proof_pins_root_sha256) {
        return Err(format!(
            "{RESPONSE_OBSERVATION_V2_PROOF_PINS_ROOT_SHA256_ENV} must be a lowercase sha256 digest"
        ));
    }
    let transparency_trust_pin =
        response_observation_v2_transparency_trust_pin(
            transparency_trust_pin.ok_or_else(|| {
                format!(
                    "{RESPONSE_OBSERVATION_V2_TRANSPARENCY_TRUST_PIN_ENV} is required with the v2 socket"
                )
            })?,
            &generation_id,
            &proof_pins_root_sha256,
        )?;
    let tee_verifier = response_observation_v2_pinned_tee_verifier(
        attestation_mode,
        tee_verify_command,
        tee_verifier_digest_manifest,
        tee_verifier_module_file,
        tee_verifier_module_sha256,
        tee_expectations_file,
        tee_expectations_sha256,
        tee_trust_roots_file,
        tee_trust_roots_sha256,
    )?;
    Ok(Some(ResponseObservationV2ClientConfig {
        socket_path,
        expected_uid,
        startup_timeout:
            Duration::from_millis(startup_timeout_ms),
        attestation_mode,
        signer_key_sha256,
        role_identity_root_sha256,
        proof_pins_root_sha256,
        tee_verifier,
        tee_topology_profile,
        transparency_trust_pin,
        role_keys,
        generation_id,
        expected_source_commit_sha256,
        expected_source_tree_sha256,
        expected_provider_generation: None,
        expected_trust_root_sha256: None,
        expected_trust_checkpoint_sha256: None,
        minimum_revocation_epoch: 0,
    }))
}

/// Configuration preflight only: no custody contact, verifier execution or
/// health claim. The explicit constructor accepts only the production profile.
pub(super) fn validate_response_observation_v2_client_config(
    config: &ResponseObservationV2ClientConfig,
) -> Result<(), String> {
    validate_response_observation_v2_client_config_inner(config, true)
}

fn validate_response_observation_v2_client_config_inner(
    config: &ResponseObservationV2ClientConfig,
    require_production: bool,
) -> Result<(), String> {
    let socket_bytes = config.socket_path.as_os_str().as_bytes();
    let address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if !config.socket_path.is_absolute()
        || socket_bytes.len() >= address.sun_path.len()
        || socket_bytes.contains(&0)
        || config.startup_timeout < Duration::from_millis(1)
        || config.startup_timeout
            > Duration::from_millis(MAX_RESPONSE_OBSERVATION_V2_STARTUP_TIMEOUT_MS)
        || config.startup_timeout.subsec_nanos() % 1_000_000 != 0
    {
        return Err(
            "response-observation v2 socket path or startup timeout is invalid"
                .to_owned(),
        );
    }
    if require_production
        && (config.attestation_mode != V2AttestationMode::TeeHardware
            || config.expected_uid == unsafe { libc::geteuid() })
    {
        return Err(
            "explicit response-observation v2 startup requires hardware TEE mode and a distinct custody UID"
                .to_owned(),
        );
    }
    match (
        config.attestation_mode,
        config.tee_verifier.as_ref(),
        config.tee_topology_profile,
    ) {
        (
            V2AttestationMode::TeeHardware,
            Some(verifier),
            Some(ResponseObservationV2TeeTopologyProfile::LocalSingleNodeOneOfOne),
        ) => verifier.validate()?,
        (V2AttestationMode::TrustedHost, None, None) => {},
        _ => return Err(
            "response-observation v2 TEE verifier and topology must match the attestation mode"
                .to_owned(),
        ),
    }
    if config.generation_id.is_empty()
        || config.generation_id.len() > 256
        || config.generation_id.bytes().any(|byte| {
            byte.is_ascii_control() || byte.is_ascii_whitespace()
        })
        || [
            &config.signer_key_sha256,
            &config.role_identity_root_sha256,
            &config.proof_pins_root_sha256,
            &config.expected_source_commit_sha256,
            &config.expected_source_tree_sha256,
        ].iter().any(|digest| !is_sha256_digest(digest))
        || [
            config.expected_trust_root_sha256.as_ref(),
            config.expected_trust_checkpoint_sha256.as_ref(),
        ].into_iter().flatten().any(|digest| !is_sha256_digest(digest))
        || config.expected_provider_generation == Some(0)
    {
        return Err(
            "response-observation v2 generation or independent digest pins are invalid"
                .to_owned(),
        );
    }
    validate_response_observation_v2_role_keys(
        &config.role_keys,
        &config.role_identity_root_sha256,
        &config.signer_key_sha256,
        &config.generation_id,
    )?;
    validate_response_observation_v2_transparency_trust_pin(
        &config.transparency_trust_pin,
        &config.generation_id,
        &config.proof_pins_root_sha256,
    )?;
    let pin = &config.transparency_trust_pin;
    if config.expected_provider_generation
            .is_some_and(|generation| generation != pin.provider_generation)
        || config.expected_trust_checkpoint_sha256.as_ref()
            .is_some_and(|checkpoint| checkpoint != &pin.trust_checkpoint_sha256)
        || config.minimum_revocation_epoch > pin.revocation_epoch
        || config.role_keys.values().any(|role| {
            role.provider_generation != pin.provider_generation
        })
    {
        return Err(
            "response-observation v2 independent provider and transparency pins disagree"
                .to_owned(),
        );
    }
    Ok(())
}

pub(super) fn initialize_response_observation_v2_client_from_config(
    config: ResponseObservationV2ClientConfig,
    absolute_deadline: u64,
) -> Result<ResponseObservationV2Client, String> {
    // Sample before validation; neither validation nor retries renew the
    // original caller bound or the configured startup interval.
    let started = ResponseObservationV2Deadline::now_boottime_ns()?;
    if absolute_deadline <= started {
        return Err("response-observation v2 startup deadline elapsed".to_owned());
    }
    validate_response_observation_v2_client_config(&config)?;
    let timeout_ns = u64::try_from(config.startup_timeout.as_nanos())
        .map_err(|_| "response-observation v2 startup timeout overflows")?;
    let configured_deadline = started.checked_add(timeout_ns)
        .ok_or("response-observation v2 startup deadline overflows")?;
    initialize_response_observation_v2_client_until(
        config,
        ResponseObservationV2Deadline::from_absolute(
            absolute_deadline.min(configured_deadline),
        ),
    )
}

pub(super) fn initialize_response_observation_v2_client(
    is_production: bool,
) -> Result<Option<ResponseObservationV2Client>, String> {
    let Some(config) =
        response_observation_v2_client_config(is_production)?
    else {
        return Ok(None);
    };
    let deadline = ResponseObservationV2Deadline::after(
        config.startup_timeout,
    )?;
    validate_response_observation_v2_client_config_inner(&config, false)?;
    initialize_response_observation_v2_client_until(config, deadline)
        .map(Some)
}

fn initialize_response_observation_v2_client_until(
    config: ResponseObservationV2ClientConfig,
    deadline: ResponseObservationV2Deadline,
) -> Result<ResponseObservationV2Client, String> {
    loop {
        if deadline.expired() {
            return Err("response-observation v2 startup deadline elapsed".to_owned());
        }
        match response_observation_v2_hello_once(
            &config,
            deadline,
        ) {
            Ok(status) => {
                if deadline.expired() {
                    return Err("response-observation v2 startup hello completed after its deadline".to_owned());
                }
                validate_response_observation_v2_transparency_trust_pin(
                    &config.transparency_trust_pin,
                    &config.generation_id,
                    &config.proof_pins_root_sha256,
                )?;
                if config
                    .transparency_trust_pin
                    .provider_generation
                    != status.provider_generation
                    || config
                        .transparency_trust_pin
                        .trust_checkpoint_sha256
                        .as_str()
                        != status
                            .attestation
                            .trust_checkpoint_sha256
                            .as_str()
                    || config
                        .transparency_trust_pin
                        .revocation_epoch
                        < status.attestation.revocation_epoch
                {
                    return Err(
                        "response-observation v2 transparency pin is stale or belongs to a different attested provider generation"
                            .to_string(),
                    );
                }
                if deadline.expired() {
                    return Err("response-observation v2 startup validation exceeded its deadline".to_owned());
                }
                let client = ResponseObservationV2Client {
                    socket_path: config.socket_path,
                    expected_uid: config.expected_uid,
                    boot_id: status.boot_id,
                    authenticated_client_identity_sha256:
                        status
                            .authenticated_client_identity_sha256,
                    pinned_genesis_state_sha256:
                        status.pinned_genesis_state_sha256,
                    attestation_mode:
                        config.attestation_mode,
                    signer_key_sha256:
                        config.signer_key_sha256,
                    role_identity_root_sha256:
                        config.role_identity_root_sha256,
                    proof_pins_root_sha256:
                        config.proof_pins_root_sha256,
                    tee_verifier: config.tee_verifier,
                    tee_topology_profile:
                        config.tee_topology_profile,
                    transparency_trust_pin:
                        config.transparency_trust_pin,
                    generation_id: config.generation_id,
                    expected_source_commit_sha256:
                        config.expected_source_commit_sha256,
                    expected_source_tree_sha256:
                        config.expected_source_tree_sha256,
                    provider_generation:
                        status.provider_generation,
                    trust_root_sha256: status
                        .attestation
                        .trust_evidence
                        .trust_root_sha256
                        .clone(),
                    trust_checkpoint_sha256:
                        status.attestation.trust_checkpoint_sha256.clone(),
                    revocation_epoch:
                        status.attestation.revocation_epoch,
                    role_keys: config.role_keys,
                    healthy: Arc::new(AtomicU64::new(
                        u64::from(status.providers_ready),
                    )),
                };
                if deadline.expired() {
                    return Err("response-observation v2 client construction exceeded its deadline".to_owned());
                }
                return Ok(client);
            }
            Err(error) if !deadline.expired() => {
                let _ = error;
                thread::sleep(deadline.remaining()?.min(Duration::from_millis(25)));
            }
            Err(error) => {
                return Err(format!(
                    "response-observation v2 startup hello failed: {error}"
                ));
            }
        }
    }
}

pub(super) fn response_observation_v2_hello_once(
    config: &ResponseObservationV2ClientConfig,
    deadline: ResponseObservationV2Deadline,
) -> Result<ResponseObservationV2HelloStatus, String> {
    let socket = connect_response_observation_v2_socket(
        &config.socket_path,
        config.expected_uid,
        deadline,
    )?;
    let remaining_ms = u64::try_from(
        deadline
            .remaining()?
            .as_millis(),
    )
    .map_err(|_| {
        "response-observation v2 hello epoch deadline overflows"
            .to_string()
    })?;
    let hello_deadline_at_epoch_ms =
        u64::try_from(now_epoch_ms())
            .ok()
            .and_then(|now| now.checked_add(remaining_ms))
            .ok_or(
                "response-observation v2 hello epoch deadline is invalid",
            )?;
    let hello_absolute_boottime_ns =
        deadline.absolute_boottime_ns.to_string();
    let request_id =
        canonical_custody_request_id()?;
    let request = V2OperationRequest::Hello {
        api_version:
            RESPONSE_OBSERVATION_V2_API_VERSION.to_owned(),
        request_id: request_id.clone(),
        boot_id: None,
        params: V2HelloParams {
            clock_id: V2MonotonicClockId::ClockBoottime,
            absolute_boottime_ns:
                hello_absolute_boottime_ns.clone(),
            deadline_at_epoch_ms:
                hello_deadline_at_epoch_ms,
        },
    };
    let request_bytes =
        custody_canonical_json_bytes(&request).map_err(|_| {
            "canonicalize typed response-observation v2 hello"
                .to_string()
        })?;
    if request_bytes.is_empty()
        || request_bytes.len()
            > RESPONSE_OBSERVATION_V2_MAX_CONTROL_BYTES
    {
        return Err(
            "response-observation v2 hello exceeds control bounds"
                .to_string(),
        );
    }
    response_observation_v2_send_packet(
        socket.as_raw_fd(),
        &request_bytes,
        &[],
        deadline,
    )
    .map_err(|_| {
        "send complete response-observation v2 hello packet"
            .to_string()
    })?;
    let (response_bytes, response_files) =
        response_observation_v2_receive_packet(
            socket.as_raw_fd(),
            deadline,
        )
        .map_err(|_| {
            "receive bounded response-observation v2 hello packet"
                .to_string()
        })?;
    if !response_files.is_empty() {
        return Err(
            "response-observation v2 hello returned exact objects"
                .to_string(),
        );
    }
    let response: V2ControlResponse =
        decode_canonical_custody_json(&response_bytes)
            .map_err(|_| {
                "decode canonical response-observation v2 hello"
                    .to_string()
            })?;
    let V2ControlResponse::Success {
        api_version,
        request_id: observed_request_id,
        boot_id,
        result: V2OperationResult::Hello(result),
        attestation: Some(attestation),
    } = response
    else {
        return Err(
            "response-observation v2 hello returned an unexpected terminal"
                .to_string(),
        );
    };
    let expected_capabilities =
        RESPONSE_OBSERVATION_V2_CAPABILITIES
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
    if api_version != RESPONSE_OBSERVATION_V2_API_VERSION
        || observed_request_id != request_id
        || result.api_version
            != RESPONSE_OBSERVATION_V2_API_VERSION
        || result.boot_id != boot_id
        || !is_sha256_digest(
            &result.authenticated_client_identity_sha256,
        )
        || !is_sha256_digest(
            &result.pinned_genesis_state_sha256,
        )
        || result.capabilities != expected_capabilities
        || !result.attestation_present
        || result.attestation_mode != config.attestation_mode
        || result.hardware_proof
            != (config.attestation_mode
                == V2AttestationMode::TeeHardware)
        || result.transport.socket_type != "SOCK_SEQPACKET"
        || result.transport.max_control_bytes
            != RESPONSE_OBSERVATION_V2_MAX_CONTROL_BYTES
        || result.transport.insecure_fallback_available
    {
        return Err(
            "response-observation v2 hello lacks exact capabilities, measured providers, hardware proof, or fail-closed transport"
                .to_string(),
        );
    }
    let providers_ready = result.providers_ready;
    let authenticated_client_identity_sha256 =
        result.authenticated_client_identity_sha256.clone();
    let pinned_genesis_state_sha256 =
        result.pinned_genesis_state_sha256.clone();
    let unsigned_response =
        V2ControlResponse::Success {
            api_version:
                RESPONSE_OBSERVATION_V2_API_VERSION.to_owned(),
            request_id: request_id.clone(),
            boot_id: boot_id.clone(),
            result: V2OperationResult::Hello(result),
            attestation: None,
        };
    let unsigned_response_bytes =
        custody_canonical_json_bytes(&unsigned_response).map_err(
            |_| {
                "canonicalize unsigned response-observation v2 hello"
                    .to_string()
            },
        )?;
    verify_response_observation_v2_attestation(
        config,
        &attestation,
        &sha256_prefixed(&request_bytes),
        &sha256_prefixed(&unsigned_response_bytes),
        &response_observation_v2_empty_manifest_sha256(),
        &boot_id,
        Some((
            &hello_absolute_boottime_ns,
            hello_deadline_at_epoch_ms,
        )),
        deadline,
    )?;
    let provider_generation = attestation.provider_generation;
    if provider_generation == 0
        || config
            .expected_provider_generation
            .is_some_and(|expected| expected != provider_generation)
        || config.role_keys.values().any(|pin| {
            pin.provider_generation != provider_generation
        })
    {
        return Err(
            "response-observation v2 provider generation does not match every pinned authority key"
                .to_string(),
        );
    }
    Ok(ResponseObservationV2HelloStatus {
        boot_id,
        authenticated_client_identity_sha256,
        pinned_genesis_state_sha256,
        providers_ready,
        provider_generation,
        attestation,
    })
}

pub(super) fn response_observation_v2_empty_manifest_sha256() -> String {
    let mut hasher = Sha256::new();
    let domain =
        b"serverware.response-v2/exact-object-manifest/v1";
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    format!("sha256:{:x}", hasher.finalize())
}

impl ResponseObservationV2Client {
    pub(super) fn verifier_config(&self) -> ResponseObservationV2ClientConfig {
        ResponseObservationV2ClientConfig {
            socket_path: self.socket_path.clone(),
            expected_uid: self.expected_uid,
            startup_timeout: Duration::from_millis(
                RESPONSE_OBSERVATION_V2_MAX_OPERATION_MS,
            ),
            attestation_mode: self.attestation_mode,
            signer_key_sha256: self.signer_key_sha256.clone(),
            role_identity_root_sha256:
                self.role_identity_root_sha256.clone(),
            proof_pins_root_sha256:
                self.proof_pins_root_sha256.clone(),
            tee_verifier: self.tee_verifier.clone(),
            tee_topology_profile: self.tee_topology_profile,
            transparency_trust_pin:
                self.transparency_trust_pin.clone(),
            role_keys: self.role_keys.clone(),
            generation_id: self.generation_id.clone(),
            expected_source_commit_sha256:
                self.expected_source_commit_sha256.clone(),
            expected_source_tree_sha256:
                self.expected_source_tree_sha256.clone(),
            expected_provider_generation:
                Some(self.provider_generation),
            expected_trust_root_sha256:
                Some(self.trust_root_sha256.clone()),
            expected_trust_checkpoint_sha256:
                Some(self.trust_checkpoint_sha256.clone()),
            minimum_revocation_epoch: self.revocation_epoch,
        }
    }
}

impl<'a> ResponseObservationV2Session<'a> {
    pub(super) fn open(
        client: &'a ResponseObservationV2Client,
        lifecycle_deadline: ResponseObservationV2Deadline,
        monotonic_deadline: V2MonotonicDeadlineV1,
        deadline_at_epoch_ms: u64,
    ) -> Result<Self, ResponseObservationV2TransactionError> {
        if client.healthy.load(Ordering::Acquire) != 1 {
            return Err(
                ResponseObservationV2TransactionError::Unavailable,
            );
        }
        let socket = connect_response_observation_v2_socket(
            &client.socket_path,
            client.expected_uid,
            lifecycle_deadline,
        )
        .map_err(|_| {
            ResponseObservationV2TransactionError::Unavailable
        })?;
        let request_id = canonical_custody_request_id().map_err(|_| {
            ResponseObservationV2TransactionError::Unavailable
        })?;
        let request = V2OperationRequest::Hello {
            api_version:
                RESPONSE_OBSERVATION_V2_API_VERSION.to_owned(),
            request_id,
            boot_id: None,
            params: V2HelloParams {
                clock_id: V2MonotonicClockId::ClockBoottime,
                absolute_boottime_ns:
                    monotonic_deadline
                        .absolute_boottime_ns
                        .clone(),
                deadline_at_epoch_ms,
            },
        };
        let reply = response_observation_v2_exchange(
            client,
            socket.as_raw_fd(),
            &request,
            &[],
            lifecycle_deadline,
        )
        .map_err(response_observation_v2_exchange_error)?;
        let V2OperationResult::Hello(hello) = reply.result else {
            return Err(
                ResponseObservationV2TransactionError::InvalidResponse,
            );
        };
        let expected_capabilities =
            RESPONSE_OBSERVATION_V2_CAPABILITIES
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>();
        if hello.api_version
            != RESPONSE_OBSERVATION_V2_API_VERSION
            || hello.boot_id != client.boot_id
            || hello.authenticated_client_identity_sha256
                != client.authenticated_client_identity_sha256
            || hello.pinned_genesis_state_sha256
                != client.pinned_genesis_state_sha256
            || hello.capabilities != expected_capabilities
            || !hello.providers_ready
            || !hello.attestation_present
            || hello.attestation_mode != client.attestation_mode
            || hello.hardware_proof
                != (client.attestation_mode
                    == V2AttestationMode::TeeHardware)
            || hello.transport.socket_type != "SOCK_SEQPACKET"
            || hello.transport.max_control_bytes
                != RESPONSE_OBSERVATION_V2_MAX_CONTROL_BYTES
            || hello.transport.insecure_fallback_available
        {
            return Err(
                ResponseObservationV2TransactionError::Unavailable,
            );
        }
        let hello_attestation = reply
            .attestation
            .ok_or(
                ResponseObservationV2TransactionError::InvalidResponse,
            )?;
        Ok(Self {
            client,
            socket,
            lifecycle_deadline,
            monotonic_deadline,
            deadline_at_epoch_ms,
            hello_attestation,
        })
    }

    pub(super) fn execute(
        &self,
        request: &V2OperationRequest,
        objects: Vec<ResponseObservationV2ExactInput>,
    ) -> Result<
        ResponseObservationV2OperationReply,
        ResponseObservationV2TransactionError,
    > {
        if self.lifecycle_deadline.expired()
            || request.boot_id() != Some(self.client.boot_id.as_str())
            || request
                .mutation_binding()
                .map(|binding| &binding.monotonic_deadline)
                .or_else(|| {
                    request
                        .read_binding()
                        .map(|binding| &binding.monotonic_deadline)
                })
                != Some(&self.monotonic_deadline)
        {
            return Err(
                ResponseObservationV2TransactionError::Unavailable,
            );
        }
        let exchange = match response_observation_v2_exchange(
            self.client,
            self.socket.as_raw_fd(),
            request,
            &objects,
            self.lifecycle_deadline,
        ) {
            Ok(exchange) => exchange,
            Err(
                ResponseObservationV2ExchangeError::PostSendOutcomeUnknown(
                    stable_request,
                ),
            ) => {
                return self.recover_and_replay(
                    request,
                    &objects,
                    stable_request,
                )
            }
            Err(error) => {
                return Err(response_observation_v2_exchange_error(
                    error,
                ))
            }
        };
        if !response_observation_v2_validate_operation_result_binding(
            request,
            &exchange.result,
        ) {
            let request_bytes =
                custody_canonical_json_bytes(request).map_err(|_| {
                    ResponseObservationV2TransactionError::OutcomeUnknown
                })?;
            let stable_request =
                response_observation_v2_uncertain_stable_request(
                    request,
                    &request_bytes,
                )
                .ok_or(
                    ResponseObservationV2TransactionError::InvalidResponse,
                )?;
            return self.recover_and_replay(
                request,
                &objects,
                stable_request,
            );
        }
        Ok(ResponseObservationV2OperationReply {
            result: exchange.result,
            exact_bytes: exchange.exact_bytes,
            canonical_response: exchange.canonical_response,
        })
    }

    pub(super) fn execute_response_data(
        &self,
        request: &V2ResponseDataRequest,
        objects: Vec<ResponseObservationV2ExactInput>,
    ) -> Result<
        ResponseObservationV2ResponseDataReply,
        ResponseObservationV2TransactionError,
    > {
        let (deadline, deadline_at_epoch_ms) = request.deadline();
        if self.lifecycle_deadline.expired()
            || request.boot_id() != self.client.boot_id
            || deadline != &self.monotonic_deadline
            || deadline_at_epoch_ms != self.deadline_at_epoch_ms
        {
            return Err(
                ResponseObservationV2TransactionError::Unavailable,
            );
        }
        response_observation_v2_response_data_exchange(
            self.client,
            self.socket.as_raw_fd(),
            request,
            &objects,
            self.lifecycle_deadline,
        )
    }

    pub(super) fn recover_and_replay(
        &self,
        original_request: &V2OperationRequest,
        original_objects: &[ResponseObservationV2ExactInput],
        stable_request: V2DurableReplayKeyV1,
    ) -> Result<
        ResponseObservationV2OperationReply,
        ResponseObservationV2TransactionError,
    > {
        let Some((monotonic_deadline, deadline_at_epoch_ms)) =
            response_observation_v2_request_deadline(
                original_request,
            )
        else {
            return Err(
                ResponseObservationV2TransactionError::OutcomeUnknown,
            );
        };
        if self.lifecycle_deadline.expired()
            || monotonic_deadline != &self.monotonic_deadline
        {
            return Err(
                ResponseObservationV2TransactionError::OutcomeUnknown,
            );
        }
        let recovery_session = Self::open(
            self.client,
            self.lifecycle_deadline,
            self.monotonic_deadline.clone(),
            self.deadline_at_epoch_ms,
        )
        .map_err(|_| {
            ResponseObservationV2TransactionError::OutcomeUnknown
        })?;
        let recovery_request_id =
            canonical_custody_request_id().map_err(|_| {
                ResponseObservationV2TransactionError::OutcomeUnknown
            })?;
        let authorization_id =
            canonical_custody_request_id().map_err(|_| {
                ResponseObservationV2TransactionError::OutcomeUnknown
            })?;
        let one_use_nonce =
            canonical_custody_request_id().map_err(|_| {
                ResponseObservationV2TransactionError::OutcomeUnknown
            })?;
        let recover = V2OperationRequest::Recover {
            api_version:
                RESPONSE_OBSERVATION_V2_API_VERSION.to_owned(),
            request_id: recovery_request_id.clone(),
            boot_id: Some(self.client.boot_id.clone()),
            params: V2RecoverParams {
                stable_request: stable_request.clone(),
                recovery_authorization:
                    V2RecoveryAuthorizationV1::SameBootAuthenticatedClient {
                        authorization_id,
                        one_use_nonce,
                        original_custody_boot_id:
                            self.client.boot_id.clone(),
                        subject_client_identity_sha256:
                            self
                                .client
                                .authenticated_client_identity_sha256
                                .clone(),
                    },
                monotonic_deadline:
                    monotonic_deadline.clone(),
                deadline_at_epoch_ms,
            },
        };
        let recovery = response_observation_v2_exchange(
            self.client,
            recovery_session.socket.as_raw_fd(),
            &recover,
            &[],
            self.lifecycle_deadline,
        )
        .map_err(|_| {
            ResponseObservationV2TransactionError::OutcomeUnknown
        })?;
        if !recovery.exact_bytes.is_empty() {
            return Err(
                ResponseObservationV2TransactionError::InvalidResponse,
            );
        }
        let V2OperationResult::Recover(result) = recovery.result else {
            return Err(
                ResponseObservationV2TransactionError::InvalidResponse,
            );
        };
        let validated_recovery =
            response_observation_v2_validate_recovery_result(
            &result,
            &stable_request,
            &recovery_request_id,
            &self.client.authenticated_client_identity_sha256,
            self.client,
        )?;
        match validated_recovery.outcome {
            V2DurableReplayOutcome::Success => {
                let replay = response_observation_v2_exchange(
                    self.client,
                    recovery_session.socket.as_raw_fd(),
                    original_request,
                    original_objects,
                    self.lifecycle_deadline,
                )
                .map_err(|_| {
                    ResponseObservationV2TransactionError::OutcomeUnknown
                })?;
                if !response_observation_v2_validate_operation_result_binding(
                    original_request,
                    &replay.result,
                )
                    || u64::try_from(
                        replay.canonical_response.len(),
                    )
                    .ok()
                        != Some(
                            validated_recovery
                                .exact_canonical_response
                                .byte_length,
                        )
                    || sha256_prefixed(
                        &replay.canonical_response,
                    ) != validated_recovery
                        .exact_canonical_response
                        .sha256
                {
                    return Err(
                        ResponseObservationV2TransactionError::OutcomeUnknown,
                    );
                }
                Ok(ResponseObservationV2OperationReply {
                    result: replay.result,
                    exact_bytes: replay.exact_bytes,
                    canonical_response:
                        replay.canonical_response,
                })
            }
            V2DurableReplayOutcome::Denied => {
                Err(ResponseObservationV2TransactionError::Denied)
            }
            V2DurableReplayOutcome::OutcomeUnknown => Err(
                ResponseObservationV2TransactionError::OutcomeUnknown,
            ),
        }
    }
}

pub(super) fn response_observation_v2_exchange_error(
    error: ResponseObservationV2ExchangeError,
) -> ResponseObservationV2TransactionError {
    match error {
        ResponseObservationV2ExchangeError::Definitive(error) => {
            error
        }
        ResponseObservationV2ExchangeError::PostSendOutcomeUnknown(
            _,
        ) => ResponseObservationV2TransactionError::OutcomeUnknown,
    }
}

pub(super) fn response_observation_v2_validate_recovery_result(
    result: &V2RecoverResult,
    expected_stable: &V2DurableReplayKeyV1,
    recovery_request_id: &str,
    client_identity_sha256: &str,
    client: &ResponseObservationV2Client,
) -> Result<
    ResponseObservationV2ValidatedRecovery,
    ResponseObservationV2TransactionError,
> {
    let (record, evidence, signed, expected_outcome) = match result {
        V2RecoverResult::Success {
            replay_record,
            recovery_authority_evidence,
            signed_outcome,
        } => (
            replay_record,
            recovery_authority_evidence,
            signed_outcome,
            V2DurableReplayOutcome::Success,
        ),
        V2RecoverResult::Denied {
            replay_record,
            recovery_authority_evidence,
            signed_outcome,
        } => (
            replay_record,
            recovery_authority_evidence,
            signed_outcome,
            V2DurableReplayOutcome::Denied,
        ),
        V2RecoverResult::OutcomeUnknown {
            replay_record,
            recovery_authority_evidence,
            signed_outcome,
        } => (
            replay_record,
            recovery_authority_evidence,
            signed_outcome,
            V2DurableReplayOutcome::OutcomeUnknown,
        ),
    };
    let statement_matches = match (
        expected_outcome,
        &signed.statement,
    ) {
        (
            V2DurableReplayOutcome::Success,
            V2CrossBootRecoveryStatementV1::Success {
                replay_record_sha256,
                canonical_response_sha256,
                output_manifest_sha256,
            },
        )
        | (
            V2DurableReplayOutcome::Denied,
            V2CrossBootRecoveryStatementV1::Denied {
                replay_record_sha256,
                canonical_response_sha256,
                output_manifest_sha256,
            },
        ) => {
            replay_record_sha256 == &record.commit.record_sha256
                && canonical_response_sha256
                    == &record.exact_canonical_response.sha256
                && output_manifest_sha256
                    == &record.output_manifest_sha256
        }
        (
            V2DurableReplayOutcome::OutcomeUnknown,
            V2CrossBootRecoveryStatementV1::OutcomeUnknown {
                replay_record_sha256,
                canonical_response_sha256,
                output_manifest_sha256,
                provider_operation_id,
                durable_start_receipt_sha256,
            },
        ) => {
            replay_record_sha256 == &record.commit.record_sha256
                && canonical_response_sha256
                    == &record.exact_canonical_response.sha256
                && output_manifest_sha256
                    == &record.output_manifest_sha256
                && !provider_operation_id.is_empty()
                && is_sha256_digest(
                    durable_start_receipt_sha256,
                )
        }
        _ => false,
    };
    if record.api_version != V2_DURABLE_REPLAY_RECORD_VERSION
        || record.key != *expected_stable
        || record.outcome != expected_outcome
        || record.exact_canonical_response.encoding
            != V2CanonicalControlResponseEncoding::CanonicalJsonUtf8
        || record.exact_canonical_response.byte_length == 0
        || !is_sha256_digest(
            &record.exact_canonical_response.sha256,
        )
        || record
            .exact_canonical_response
            .storage_reference_id
            .is_empty()
        || !is_sha256_digest(
            &record
                .exact_canonical_response
                .persistence_receipt_sha256,
        )
        || !is_sha256_digest(&record.output_manifest_sha256)
        || record.commit.commit_order
            != V2DurableReplayCommitOrder::CommittedBeforeResponseSend
        || !is_sha256_digest(&record.commit.record_sha256)
        || !is_sha256_digest(
            &record.commit.persistence_receipt_sha256,
        )
        || record.commit.durable_index_revision == 0
        || record.commit.provider_generation
            != client.provider_generation
        || record.signature.is_empty()
        || evidence.evidence_type
            != V2EvidenceType::CrossBootRecoveryAuthority
        || !is_sha256_digest(&evidence.evidence_sha256)
        || evidence.retrieval_id.is_empty()
        || signed.api_version
            != V2_CROSS_BOOT_RECOVERY_OUTCOME_VERSION
        || signed.recovery_request_id != recovery_request_id
        || signed.subject_client_identity_sha256
            != client_identity_sha256
        || signed.stable_request != *expected_stable
        || signed.output_references != record.output_references
        || signed.reconciliation.evidence_type
            != V2EvidenceType::CrossBootRecoveryReconciliation
        || !is_sha256_digest(
            &signed.reconciliation.evidence_sha256,
        )
        || signed.reconciliation.retrieval_id.is_empty()
        || signed.trust_root_sha256
            != client.trust_root_sha256
        || signed.trust_checkpoint_sha256
            != client.trust_checkpoint_sha256
        || signed.revocation_epoch < client.revocation_epoch
        || signed.recorded_at_epoch_ms == 0
        || signed.provider_generation
            != client.provider_generation
        || signed.signer_role
            != serverware_decision_gate::V2RecoveryOutcomeAuthorityRole::RecoveryOutcome
        || record.signer_role
            != serverware_decision_gate::V2DurableReplayAuthorityRole::DurableReplayStore
        || !is_sha256_digest(
            &signed.provider_operation_binding_sha256,
        )
        || !is_sha256_digest(&signed.signer_key_id)
        || !is_sha256_digest(
            &signed.signer_key_material_sha256,
        )
        || signed.signature.is_empty()
        || !statement_matches
    {
        return Err(
            ResponseObservationV2TransactionError::InvalidResponse,
        );
    }
    let mut unsigned_record = record.clone();
    let record_signature =
        std::mem::take(&mut unsigned_record.signature);
    verify_response_observation_v2_role_signature(
        client,
        "linearizable-store",
        response_observation_v2_durable_operation_name(
            record.key.operation,
        ),
        &record.signer_provider_id,
        record.commit.provider_generation,
        &record.signer_key_id,
        &record.signer_key_material_sha256,
        &record_signature,
        &unsigned_record,
    )?;
    let mut unsigned_outcome = signed.clone();
    let outcome_signature =
        std::mem::take(&mut unsigned_outcome.signature);
    verify_response_observation_v2_role_signature(
        client,
        "recovery",
        V2_RECOVER_OPERATION,
        &signed.signer_provider_id,
        signed.provider_generation,
        &signed.signer_key_id,
        &signed.signer_key_material_sha256,
        &outcome_signature,
        &unsigned_outcome,
    )?;
    Ok(ResponseObservationV2ValidatedRecovery {
        outcome: expected_outcome,
        exact_canonical_response:
            record.exact_canonical_response.clone(),
    })
}

pub(super) struct ResponseObservationV2ValidatedRecovery {
    pub(super) outcome: V2DurableReplayOutcome,
    pub(super) exact_canonical_response:
        V2DurableExactCanonicalResponseReferenceV1,
}

fn response_observation_v2_durable_operation_name(
    operation: V2DurableReplayOperation,
) -> &'static str {
    match operation {
        V2DurableReplayOperation::Reserve => V2_RESERVE_OPERATION,
        V2DurableReplayOperation::Authority => V2_AUTHORITY_OPERATION,
        V2DurableReplayOperation::Stage => V2_STAGE_OPERATION,
        V2DurableReplayOperation::Dispatch => V2_DISPATCH_OPERATION,
        V2DurableReplayOperation::Terminal => V2_TERMINAL_OPERATION,
        V2DurableReplayOperation::Finalize => V2_FINALIZE_OPERATION,
        V2DurableReplayOperation::Attest => V2_ATTEST_OPERATION,
        V2DurableReplayOperation::Publish => V2_PUBLISH_OPERATION,
        V2DurableReplayOperation::Retrieve => V2_RETRIEVE_OPERATION,
        V2DurableReplayOperation::Recover => V2_RECOVER_OPERATION,
        V2DurableReplayOperation::VerifyArchive => {
            V2_VERIFY_ARCHIVE_OPERATION
        }
    }
}

pub(super) fn response_observation_v2_validate_operation_result_binding(
    request: &V2OperationRequest,
    result: &V2OperationResult,
) -> bool {
    if request.mutation_binding().is_some() {
        let observed = match result {
            V2OperationResult::Reserve(
                V2ReserveResult::Reserved {
                    reservation_evidence,
                    ..
                },
            ) => Some(reservation_evidence),
            V2OperationResult::Reserve(
                V2ReserveResult::Denied {
                    terminal_evidence,
                    ..
                },
            ) => Some(terminal_evidence),
            V2OperationResult::Authority(
                V2AuthorityResult::Ready {
                    authority_state,
                    ..
                },
            ) => Some(authority_state),
            V2OperationResult::Authority(
                V2AuthorityResult::Terminalized {
                    terminal_evidence,
                    ..
                },
            ) => Some(terminal_evidence),
            V2OperationResult::Stage(result) => {
                Some(&result.staging_evidence)
            }
            V2OperationResult::Dispatch(result) => {
                Some(&result.dispatch_evidence)
            }
            V2OperationResult::Terminal(result) => {
                Some(&result.terminal_evidence)
            }
            V2OperationResult::Finalize(result) => {
                Some(&result.finalization_checkpoint)
            }
            V2OperationResult::Attest(result) => {
                Some(&result.artifact_time_checkpoint)
            }
            V2OperationResult::Publish(result) => {
                Some(&result.artifact_time_checkpoint)
            }
            _ => None,
        };
        if observed
            .map(|evidence| evidence.evidence_sha256.as_str())
            != response_observation_v2_transition_evidence_sha256(
                request,
                result,
            )
            .as_deref()
        {
            return false;
        }
    }
    let valid_evidence =
        |evidence: &EvidenceReference, expected: V2EvidenceType| {
            evidence.evidence_type == expected
                && is_sha256_digest(&evidence.evidence_sha256)
                && !evidence.retrieval_id.is_empty()
        };
    let valid_object =
        |object: &ImmutableObjectReference,
         expected: ImmutableObjectType| {
            object.object_type == expected
                && is_sha256_digest(&object.object_sha256)
                && object.byte_length > 0
                && !object.retrieval_id.is_empty()
                && is_sha256_digest(
                    &object.persistence_receipt_sha256,
                )
        };
    let valid_attempt =
        |attempt: &AttemptStateReference,
         expected_state: V2AttemptState,
         transition_evidence_sha256: &str| {
            let Some(binding) = request.mutation_binding() else {
                return false;
            };
            let fence_matches =
                if binding.predecessor_lifecycle_state
                    == V2AttemptState::Genesis
                    && binding.fencing_token == 0
                {
                    attempt.fencing_token > 0
                } else {
                    attempt.fencing_token == binding.fencing_token
                };
            attempt.attempt_id == binding.attempt_id
                && attempt.state == expected_state
                && attempt.attempt_revision
                    == binding.attempt_revision.saturating_add(1)
                && fence_matches
                && attempt.state_sha256
                    == response_observation_v2_lifecycle_state_sha256(
                        request,
                        binding,
                        attempt,
                        transition_evidence_sha256,
                    )
        };
    match (request, result) {
        (
            V2OperationRequest::Hello { .. },
            V2OperationResult::Hello(hello),
        ) => {
            hello.api_version
                == RESPONSE_OBSERVATION_V2_API_VERSION
                && hello.boot_id
                    == request.boot_id().unwrap_or_default()
        }
        (
            V2OperationRequest::Reserve { .. },
            V2OperationResult::Reserve(
                V2ReserveResult::Reserved {
                    attempt,
                    reservation_evidence,
                },
            ),
        ) => {
            valid_evidence(
                reservation_evidence,
                V2EvidenceType::Reservation,
            ) && valid_attempt(
                attempt,
                V2AttemptState::Reserved,
                &reservation_evidence.evidence_sha256,
            )
        }
        (
            V2OperationRequest::Reserve { .. },
            V2OperationResult::Reserve(
                V2ReserveResult::Denied {
                    attempt,
                    terminal_evidence,
                },
            ),
        ) => {
            valid_evidence(
                terminal_evidence,
                V2EvidenceType::Terminal,
            ) && valid_attempt(
                attempt,
                V2AttemptState::Denied,
                &terminal_evidence.evidence_sha256,
            )
        }
        (
            V2OperationRequest::Authority { .. },
            V2OperationResult::Authority(
                V2AuthorityResult::Ready {
                    attempt,
                    authority_evidence_root,
                    authority_state,
                },
            ),
        ) => {
            valid_evidence(
                authority_evidence_root,
                V2EvidenceType::AuthorityEvidenceRoot,
            ) && valid_evidence(
                authority_state,
                V2EvidenceType::AuthorityState,
            ) && valid_attempt(
                attempt,
                V2AttemptState::AuthorityReady,
                &authority_state.evidence_sha256,
            )
        }
        (
            V2OperationRequest::Authority { .. },
            V2OperationResult::Authority(
                V2AuthorityResult::Terminalized {
                    attempt,
                    terminal_evidence,
                },
            ),
        ) => {
            valid_evidence(
                terminal_evidence,
                V2EvidenceType::Terminal,
            ) && valid_attempt(
                attempt,
                V2AttemptState::Terminalized,
                &terminal_evidence.evidence_sha256,
            )
        }
        (
            V2OperationRequest::Stage { .. },
            V2OperationResult::Stage(stage),
        ) => {
            valid_object(
                &stage.staged_request,
                ImmutableObjectType::StagedRequest,
            ) && valid_evidence(
                &stage.staging_evidence,
                V2EvidenceType::Staging,
            ) && valid_attempt(
                &stage.attempt,
                V2AttemptState::Staged,
                &stage.staging_evidence.evidence_sha256,
            )
        }
        (
            V2OperationRequest::Dispatch { .. },
            V2OperationResult::Dispatch(dispatch),
        ) => {
            valid_object(
                &dispatch.upstream_response,
                ImmutableObjectType::UpstreamResponse,
            ) && valid_evidence(
                &dispatch.dispatch_evidence,
                V2EvidenceType::Dispatch,
            ) && valid_attempt(
                &dispatch.attempt,
                V2AttemptState::Dispatched,
                &dispatch.dispatch_evidence.evidence_sha256,
            )
        }
        (
            V2OperationRequest::Terminal { params, .. },
            V2OperationResult::Terminal(terminal),
        ) => {
            let expected = match params.terminal_kind {
                V2TerminalKind::Cancelled => {
                    V2AttemptState::Cancelled
                }
                V2TerminalKind::Failed => V2AttemptState::Failed,
                V2TerminalKind::Completed => {
                    V2AttemptState::Completed
                }
                V2TerminalKind::ReleasePrepared => {
                    V2AttemptState::ReleasePrepared
                }
                V2TerminalKind::OutcomeUnknown => {
                    V2AttemptState::OutcomeUnknown
                }
            };
            valid_evidence(
                &terminal.terminal_evidence,
                V2EvidenceType::Terminal,
            ) && valid_attempt(
                &terminal.attempt,
                expected,
                &terminal.terminal_evidence.evidence_sha256,
            )
        }
        (
            V2OperationRequest::Finalize { .. },
            V2OperationResult::Finalize(finalized),
        ) => {
            valid_object(
                &finalized.envelope,
                ImmutableObjectType::ResponseObservationEnvelope,
            ) && valid_evidence(
                &finalized.persistence_evidence,
                V2EvidenceType::Persistence,
            ) && valid_evidence(
                &finalized.finalization_checkpoint,
                V2EvidenceType::FinalizationCheckpoint,
            ) && finalized.finalized_response.is_some()
                == finalized.release_cas_expectation.is_some()
                && finalized
                    .finalized_response
                    .as_ref()
                    .is_none_or(|object| {
                        valid_object(
                            object,
                            ImmutableObjectType::ReleasedResponse,
                        )
                    })
                && valid_attempt(
                    &finalized.attempt,
                    V2AttemptState::Finalized,
                    &finalized
                        .finalization_checkpoint
                        .evidence_sha256,
                )
        }
        (
            V2OperationRequest::Attest { .. },
            V2OperationResult::Attest(attested),
        ) => {
            valid_object(
                &attested.attestation_artifact,
                ImmutableObjectType::AttestationArtifact,
            ) && valid_evidence(
                &attested.artifact_time_checkpoint,
                V2EvidenceType::ArtifactTimeCheckpoint,
            ) && valid_attempt(
                &attested.attempt,
                V2AttemptState::Attested,
                &attested
                    .artifact_time_checkpoint
                    .evidence_sha256,
            )
        }
        (
            V2OperationRequest::Publish { params, .. },
            V2OperationResult::Publish(published),
        ) => {
            valid_object(
                &published.publication_artifact,
                ImmutableObjectType::PublicationArtifact,
            ) && valid_object(
                &published.released_object,
                ImmutableObjectType::ReleasedResponse,
            ) && published.released_object
                == params.release_intent.object
                && published.release_cas_expectation
                    == params
                        .release_intent
                        .release_cas_expectation
                && valid_evidence(
                    &published.artifact_time_checkpoint,
                    V2EvidenceType::ArtifactTimeCheckpoint,
                )
                && valid_attempt(
                    &published.attempt,
                    V2AttemptState::Published,
                    &published
                        .artifact_time_checkpoint
                        .evidence_sha256,
                )
        }
        (
            V2OperationRequest::Retrieve { params, .. },
            V2OperationResult::Retrieve(retrieved),
        ) => {
            retrieved.object == params.object
                && retrieved.exact_bytes.object_id
                    == params.object.retrieval_id
                && retrieved.exact_bytes.sha256
                    == params.object.object_sha256
                && retrieved.exact_bytes.byte_length
                    == params.object.byte_length
                && valid_evidence(
                    &retrieved.retrieval_evidence,
                    V2EvidenceType::Retrieval,
                )
                && !matches!(
                    &retrieved
                        .release_authorization_consumption
                        .outcome,
                    V2ReleaseAuthorizationConsumeOutcomeV1::Denied {
                        ..
                    }
                )
        }
        (
            V2OperationRequest::Recover { .. },
            V2OperationResult::Recover(_),
        ) => true,
        (
            V2OperationRequest::VerifyArchive { params, .. },
            V2OperationResult::VerifyArchive(verified),
        ) => {
            verified.attempt_id == params.binding.attempt_id
                && valid_object(
                    &verified.envelope,
                    ImmutableObjectType::ResponseObservationEnvelope,
                )
                && valid_evidence(
                    &verified.verification_evidence,
                    V2EvidenceType::ArchiveVerification,
                )
        }
        _ => false,
    }
}

struct ResponseObservationV2ExchangeReply {
    result: V2OperationResult,
    exact_bytes: BTreeMap<u16, Zeroizing<Vec<u8>>>,
    attestation: Option<V2FreshResponseAttestationV1>,
    canonical_response: Zeroizing<Vec<u8>>,
}

pub(super) fn response_observation_v2_exchange(
    client: &ResponseObservationV2Client,
    socket: RawFd,
    request: &V2OperationRequest,
    objects: &[ResponseObservationV2ExactInput],
    deadline: ResponseObservationV2Deadline,
) -> Result<
    ResponseObservationV2ExchangeReply,
    ResponseObservationV2ExchangeError,
> {
    if deadline.expired()
        || objects.len() > RESPONSE_OBSERVATION_V2_MAX_OBJECTS
        || request.exact_object_descriptors()
            != objects
                .iter()
                .map(|object| object.descriptor.clone())
                .collect::<Vec<_>>()
    {
        return Err(ResponseObservationV2ExchangeError::Definitive(
            ResponseObservationV2TransactionError::Unavailable,
        ));
    }
    let request_bytes = custody_canonical_json_bytes(request)
        .map_err(|_| {
            ResponseObservationV2ExchangeError::Definitive(
                ResponseObservationV2TransactionError::InvalidResponse,
            )
        })?;
    if request_bytes.is_empty()
        || request_bytes.len()
            > RESPONSE_OBSERVATION_V2_MAX_CONTROL_BYTES
    {
        return Err(ResponseObservationV2ExchangeError::Definitive(
            ResponseObservationV2TransactionError::InvalidResponse,
        ));
    }
    let stable_request =
        response_observation_v2_uncertain_stable_request(
            request,
            &request_bytes,
        );
    match response_observation_v2_send_packet(
        socket,
        &request_bytes,
        objects,
        deadline,
    ) {
        Ok(()) => {}
        Err(ResponseObservationV2PacketSendError::NotSent) => {
            return Err(
                ResponseObservationV2ExchangeError::Definitive(
                    ResponseObservationV2TransactionError::Unavailable,
                ),
            )
        }
        Err(
            ResponseObservationV2PacketSendError::OutcomeUnknown,
        ) => {
            return Err(response_observation_v2_post_send_error(
                &stable_request,
                ResponseObservationV2TransactionError::OutcomeUnknown,
            ))
        }
    }
    let (response_bytes, files) =
        response_observation_v2_receive_packet(socket, deadline)
            .map_err(|_| {
                response_observation_v2_post_send_error(
                    &stable_request,
                    ResponseObservationV2TransactionError::OutcomeUnknown,
                )
            })?;
    let response: V2ControlResponse =
        decode_canonical_custody_json(&response_bytes).map_err(
            |_| {
                response_observation_v2_post_send_error(
                    &stable_request,
                    ResponseObservationV2TransactionError::InvalidResponse,
                )
            },
        )?;
    let unsigned_response = match &response {
        V2ControlResponse::Success {
            api_version,
            request_id,
            boot_id,
            result,
            ..
        } => V2ControlResponse::Success {
            api_version: api_version.clone(),
            request_id: request_id.clone(),
            boot_id: boot_id.clone(),
            result: result.clone(),
            attestation: None,
        },
        V2ControlResponse::Error {
            api_version,
            request_id,
            boot_id,
            operation,
            error,
            ..
        } => V2ControlResponse::Error {
            api_version: api_version.clone(),
            request_id: request_id.clone(),
            boot_id: boot_id.clone(),
            operation: *operation,
            error: error.clone(),
            attestation: None,
        },
        V2ControlResponse::OutcomeUnknown {
            api_version,
            request_id,
            boot_id,
            operation,
            result,
            ..
        } => V2ControlResponse::OutcomeUnknown {
            api_version: api_version.clone(),
            request_id: request_id.clone(),
            boot_id: boot_id.clone(),
            operation: *operation,
            result: result.clone(),
            attestation: None,
        },
    };
    let unsigned_bytes =
        custody_canonical_json_bytes(&unsigned_response).map_err(
            |_| {
                response_observation_v2_post_send_error(
                    &stable_request,
                    ResponseObservationV2TransactionError::InvalidResponse,
                )
            },
        )?;
    let (api_version, request_id, boot_id, attestation) =
        match &response {
        V2ControlResponse::Success {
            api_version,
            request_id,
            boot_id,
            attestation,
            ..
        }
        | V2ControlResponse::Error {
            api_version,
            request_id,
            boot_id,
            attestation,
            ..
        }
        | V2ControlResponse::OutcomeUnknown {
            api_version,
            request_id,
            boot_id,
            attestation,
            ..
        } => (
            api_version,
            request_id,
            boot_id,
            attestation.as_ref(),
        ),
    };
    let operation_matches = match &response {
        V2ControlResponse::Success { result, .. } => {
            result.operation() == request.operation()
        }
        V2ControlResponse::Error { operation, .. }
        | V2ControlResponse::OutcomeUnknown {
            operation, ..
        } => *operation == request.error_operation(),
    };
    if api_version != RESPONSE_OBSERVATION_V2_API_VERSION
        || request_id != request.request_id()
        || boot_id != &client.boot_id
        || !operation_matches
    {
        return Err(response_observation_v2_post_send_error(
            &stable_request,
            ResponseObservationV2TransactionError::InvalidResponse,
        ));
    }
    let descriptors = match &response {
        V2ControlResponse::Success { result, .. } => {
            v2_result_exact_object_descriptors(result)
        }
        V2ControlResponse::Error { .. }
        | V2ControlResponse::OutcomeUnknown { .. } => Vec::new(),
    };
    let output_manifest =
        response_observation_v2_descriptor_manifest_sha256(
            &descriptors,
        );
    verify_response_observation_v2_attestation(
        &client.verifier_config(),
        attestation.ok_or_else(|| {
            response_observation_v2_post_send_error(
                &stable_request,
                ResponseObservationV2TransactionError::InvalidResponse,
            )
        })?,
        &sha256_prefixed(&request_bytes),
        &sha256_prefixed(&unsigned_bytes),
        &output_manifest,
        boot_id,
        match request {
            V2OperationRequest::Hello { params, .. } => Some((
                params.absolute_boottime_ns.as_str(),
                params.deadline_at_epoch_ms,
            )),
            _ => response_observation_v2_request_deadline(request)
                .map(|(deadline, epoch_ms)| {
                    (
                        deadline.absolute_boottime_ns.as_str(),
                        epoch_ms,
                    )
                }),
        },
        deadline,
    )
    .map_err(|_| {
        response_observation_v2_post_send_error(
            &stable_request,
            ResponseObservationV2TransactionError::InvalidResponse,
        )
    })?;
    let exact_bytes =
        response_observation_v2_validate_output_objects(
            &descriptors,
            files,
            deadline,
        )
        .map_err(|error| {
            response_observation_v2_post_send_error(
                &stable_request,
                error,
            )
        })?;
    match response {
        V2ControlResponse::Success {
            result,
            attestation,
            ..
        } => {
            Ok(ResponseObservationV2ExchangeReply {
                result,
                exact_bytes,
                attestation,
                canonical_response:
                    Zeroizing::new(response_bytes),
            })
        }
        V2ControlResponse::Error {
            error,
            operation,
            ..
        } => {
            use serverware_decision_gate::V2PublicErrorCode;
            let terminal = match error.code {
                V2PublicErrorCode::AuthorizationDenied
                | V2PublicErrorCode::UnauthorizedClient => {
                    ResponseObservationV2TransactionError::Denied
                }
                V2PublicErrorCode::Conflict => {
                    return Err(
                        response_observation_v2_post_send_error(
                            &stable_request,
                            ResponseObservationV2TransactionError::OutcomeUnknown,
                        ),
                    )
                }
                V2PublicErrorCode::ProviderUnavailable
                | V2PublicErrorCode::CapacityUnavailable
                | V2PublicErrorCode::DeadlineExceeded => {
                    ResponseObservationV2TransactionError::Unavailable
                }
                _ => {
                    ResponseObservationV2TransactionError::InvalidResponse
                }
            };
            if operation != request.error_operation() {
                return Err(response_observation_v2_post_send_error(
                    &stable_request,
                    ResponseObservationV2TransactionError::InvalidResponse,
                ));
            }
            Err(ResponseObservationV2ExchangeError::Definitive(
                terminal,
            ))
        }
        V2ControlResponse::OutcomeUnknown { result, .. } => {
            let stable_matches = stable_request.as_ref().is_some_and(
                |stable| {
                    stable.attempt_id == result.attempt.attempt_id
                        && stable.request_sha256
                            == result.request_sha256
                        && stable.descriptor_manifest_sha256
                            == result.descriptor_manifest_sha256
                        && stable.fencing_token
                            == result.attempt.fencing_token
                },
            );
            let mut unsigned_result = result.clone();
            let signature =
                std::mem::take(&mut unsigned_result.signature);
            if !stable_matches
                || result.signer_role
                    != serverware_decision_gate::V2OutcomeAuthorityRole::Reconciliation
                || result.trust_checkpoint_sha256
                    != client.trust_checkpoint_sha256
                || result.revocation_epoch < client.revocation_epoch
                || result.recorded_at_epoch_ms == 0
                || verify_response_observation_v2_role_signature(
                    client,
                    "outcome-reconciliation",
                    request.operation(),
                    &result.signer_provider_id,
                    result.provider_generation,
                    &result.signer_key_id,
                    &result.signer_key_material_sha256,
                    &signature,
                    &unsigned_result,
                )
                .is_err()
            {
                return Err(
                    ResponseObservationV2ExchangeError::Definitive(
                        ResponseObservationV2TransactionError::InvalidResponse,
                    ),
                );
            }
            Err(response_observation_v2_post_send_error(
                &stable_request,
                ResponseObservationV2TransactionError::OutcomeUnknown,
            ))
        }
    }
}

pub(super) fn response_observation_v2_response_data_exchange(
    client: &ResponseObservationV2Client,
    socket: RawFd,
    request: &V2ResponseDataRequest,
    objects: &[ResponseObservationV2ExactInput],
    deadline: ResponseObservationV2Deadline,
) -> Result<
    ResponseObservationV2ResponseDataReply,
    ResponseObservationV2TransactionError,
> {
    if deadline.expired()
        || objects.len() > RESPONSE_OBSERVATION_V2_MAX_OBJECTS
        || request.exact_object_descriptors()
            != objects
                .iter()
                .map(|object| object.descriptor.clone())
                .collect::<Vec<_>>()
    {
        return Err(
            ResponseObservationV2TransactionError::Unavailable,
        );
    }
    let request_bytes =
        custody_canonical_json_bytes(request).map_err(|_| {
            ResponseObservationV2TransactionError::InvalidResponse
        })?;
    if request_bytes.is_empty()
        || request_bytes.len()
            > RESPONSE_OBSERVATION_V2_MAX_CONTROL_BYTES
    {
        return Err(
            ResponseObservationV2TransactionError::InvalidResponse,
        );
    }
    match response_observation_v2_send_packet(
        socket,
        &request_bytes,
        objects,
        deadline,
    ) {
        Ok(()) => {}
        Err(ResponseObservationV2PacketSendError::NotSent) => {
            return Err(
                ResponseObservationV2TransactionError::Unavailable,
            )
        }
        Err(ResponseObservationV2PacketSendError::OutcomeUnknown) => {
            return Err(
                ResponseObservationV2TransactionError::OutcomeUnknown,
            )
        }
    }
    let (response_bytes, files) =
        response_observation_v2_receive_packet(socket, deadline)
            .map_err(|_| {
                ResponseObservationV2TransactionError::OutcomeUnknown
            })?;
    let response: V2ResponseDataControlResponse =
        decode_canonical_custody_json(&response_bytes).map_err(
            |_| {
                ResponseObservationV2TransactionError::InvalidResponse
            },
        )?;
    let unsigned_response = match &response {
        V2ResponseDataControlResponse::Success {
            api_version,
            request_id,
            boot_id,
            result,
            ..
        } => V2ResponseDataControlResponse::Success {
            api_version: api_version.clone(),
            request_id: request_id.clone(),
            boot_id: boot_id.clone(),
            result: result.clone(),
            attestation: None,
        },
        V2ResponseDataControlResponse::Error {
            api_version,
            request_id,
            boot_id,
            operation,
            error,
            ..
        } => V2ResponseDataControlResponse::Error {
            api_version: api_version.clone(),
            request_id: request_id.clone(),
            boot_id: boot_id.clone(),
            operation: *operation,
            error: error.clone(),
            attestation: None,
        },
    };
    let unsigned_bytes =
        custody_canonical_json_bytes(&unsigned_response).map_err(
            |_| {
                ResponseObservationV2TransactionError::InvalidResponse
            },
        )?;
    let (api_version, request_id, boot_id, operation, attestation) =
        match &response {
            V2ResponseDataControlResponse::Success {
                api_version,
                request_id,
                boot_id,
                result,
                attestation,
            } => (
                api_version,
                request_id,
                boot_id,
                result.operation(),
                attestation.as_ref(),
            ),
            V2ResponseDataControlResponse::Error {
                api_version,
                request_id,
                boot_id,
                operation,
                attestation,
                ..
            } => (
                api_version,
                request_id,
                boot_id,
                *operation,
                attestation.as_ref(),
            ),
        };
    if api_version != RESPONSE_OBSERVATION_V2_API_VERSION
        || request_id != request.request_id()
        || boot_id != request.boot_id()
        || operation != request.operation()
    {
        return Err(
            ResponseObservationV2TransactionError::InvalidResponse,
        );
    }
    let descriptors = match &response {
        V2ResponseDataControlResponse::Success { result, .. } => {
            response_data_result_exact_object_descriptors(result)
        }
        V2ResponseDataControlResponse::Error { .. } => Vec::new(),
    };
    let output_manifest =
        response_observation_v2_descriptor_manifest_sha256(
            &descriptors,
        );
    let (monotonic_deadline, deadline_at_epoch_ms) =
        request.deadline();
    verify_response_observation_v2_attestation(
        &client.verifier_config(),
        attestation.ok_or(
            ResponseObservationV2TransactionError::InvalidResponse,
        )?,
        &sha256_prefixed(&request_bytes),
        &sha256_prefixed(&unsigned_bytes),
        &output_manifest,
        boot_id,
        Some((
            monotonic_deadline.absolute_boottime_ns.as_str(),
            deadline_at_epoch_ms,
        )),
        deadline,
    )
    .map_err(|_| {
        ResponseObservationV2TransactionError::InvalidResponse
    })?;
    let exact_bytes =
        response_observation_v2_validate_output_objects(
            &descriptors,
            files,
            deadline,
        )?;
    match response {
        V2ResponseDataControlResponse::Success { result, .. } => {
            Ok(ResponseObservationV2ResponseDataReply {
                result,
                exact_bytes,
                canonical_response:
                    Zeroizing::new(response_bytes),
            })
        }
        V2ResponseDataControlResponse::Error { error, .. } => {
            if error.generation_id != client.generation_id
                || error.generation != client.provider_generation
                || error.operation != request.operation()
                || error.request_id != request.request_id()
                || error.attempt_id != request.attempt_id()
                || error.stable_resume_id
                    != request.stable_resume_id()
                || !is_sha256_digest(&error.request_sha256)
                || !is_sha256_digest(
                    &error.terminal_state_sha256,
                )
                || !is_sha256_digest(
                    &error.reconciliation_record_sha256,
                )
                || error.signature.is_empty()
            {
                return Err(
                    ResponseObservationV2TransactionError::InvalidResponse,
                );
            }
            if error.durable_terminalized {
                Err(
                    ResponseObservationV2TransactionError::OutcomeUnknown,
                )
            } else if error.retryable {
                Err(
                    ResponseObservationV2TransactionError::Unavailable,
                )
            } else {
                Err(
                    ResponseObservationV2TransactionError::InvalidResponse,
                )
            }
        }
    }
}

pub(super) fn response_observation_v2_post_send_error(
    stable_request: &Option<V2DurableReplayKeyV1>,
    fallback: ResponseObservationV2TransactionError,
) -> ResponseObservationV2ExchangeError {
    match stable_request {
        Some(stable_request) => {
            ResponseObservationV2ExchangeError::PostSendOutcomeUnknown(
                stable_request.clone(),
            )
        }
        None => ResponseObservationV2ExchangeError::Definitive(
            fallback,
        ),
    }
}

pub(super) fn response_observation_v2_uncertain_stable_request(
    request: &V2OperationRequest,
    request_bytes: &[u8],
) -> Option<V2DurableReplayKeyV1> {
    if !matches!(
        request,
        V2OperationRequest::Reserve { .. }
            | V2OperationRequest::Authority { .. }
            | V2OperationRequest::Stage { .. }
            | V2OperationRequest::Dispatch { .. }
            | V2OperationRequest::Terminal { .. }
            | V2OperationRequest::Finalize { .. }
            | V2OperationRequest::Attest { .. }
            | V2OperationRequest::Publish { .. }
            | V2OperationRequest::Retrieve { .. }
    ) {
        return None;
    }
    let (attempt_id, fencing_token) = request
        .mutation_binding()
        .map(|binding| {
            (
                binding.attempt_id.clone(),
                binding.fencing_token,
            )
        })
        .or_else(|| {
            request.read_binding().map(|binding| {
                (
                    binding.attempt_id.clone(),
                    binding.fencing_token,
                )
            })
        })?;
    Some(V2DurableReplayKeyV1 {
        original_request_id: request.request_id().to_owned(),
        request_sha256: sha256_prefixed(request_bytes),
        descriptor_manifest_sha256:
            response_observation_v2_descriptor_manifest_sha256(
                &request.exact_object_descriptors(),
            ),
        attempt_id,
        operation: request.durable_replay_operation()?,
        fencing_token,
    })
}

pub(super) fn response_observation_v2_exact_input(
    object_id: &str,
    media_type: ExactObjectMediaType,
    fd_index: u16,
    bytes: &[u8],
    deadline: ResponseObservationV2Deadline,
) -> Result<
    ResponseObservationV2ExactInput,
    ResponseObservationV2TransactionError,
> {
    if deadline.expired()
        || bytes.is_empty()
        || u64::try_from(bytes.len()).ok().is_none_or(|length| {
            length > RESPONSE_OBSERVATION_V2_MAX_OBJECT_BYTES
        })
    {
        return Err(
            ResponseObservationV2TransactionError::InvalidResponse,
        );
    }
    let name = CString::new("serverware-response-v2-object")
        .map_err(|_| {
            ResponseObservationV2TransactionError::Unavailable
        })?;
    let raw = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            name.as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    } as RawFd;
    if raw < 0 {
        return Err(ResponseObservationV2TransactionError::Unavailable);
    }
    let mut file =
        unsafe { File::from_raw_fd(raw) };
    if deadline.expired() {
        return Err(ResponseObservationV2TransactionError::Unavailable);
    }
    file.write_all(bytes).map_err(|_| {
        ResponseObservationV2TransactionError::Unavailable
    })?;
    if deadline.expired() {
        return Err(ResponseObservationV2TransactionError::Unavailable);
    }
    file.sync_all().map_err(|_| {
        ResponseObservationV2TransactionError::Unavailable
    })?;
    if deadline.expired() {
        return Err(ResponseObservationV2TransactionError::Unavailable);
    }
    let seals = libc::F_SEAL_WRITE
        | libc::F_SEAL_GROW
        | libc::F_SEAL_SHRINK
        | libc::F_SEAL_SEAL;
    if unsafe {
        libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, seals)
    } != 0
    {
        return Err(ResponseObservationV2TransactionError::Unavailable);
    }
    if deadline.expired() {
        return Err(ResponseObservationV2TransactionError::Unavailable);
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| {
        ResponseObservationV2TransactionError::Unavailable
    })?;
    Ok(ResponseObservationV2ExactInput {
        descriptor: ExactByteObjectDescriptor {
            object_id: object_id.to_owned(),
            media_type,
            fd_index,
            byte_length: bytes.len() as u64,
            sha256: sha256_prefixed(bytes),
            required_seals: MemfdSealProfile::ImmutableV1,
        },
        file,
    })
}

enum ResponseObservationV2PacketSendError {
    NotSent,
    OutcomeUnknown,
}

pub(super) fn response_observation_v2_wait_socket(
    socket: RawFd,
    events: libc::c_short,
    deadline: ResponseObservationV2Deadline,
) -> io::Result<()> {
    loop {
        let remaining =
            deadline.remaining().unwrap_or(Duration::ZERO);
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "response observation v2 packet deadline elapsed",
            ));
        }
        let timeout_ms = deadline.short_poll_timeout_ms();
        let mut pollfd = libc::pollfd {
            fd: socket,
            events,
            revents: 0,
        };
        let polled =
            unsafe { libc::poll(&mut pollfd, 1, timeout_ms) };
        if polled < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if polled == 0 {
            continue;
        }
        if pollfd.revents
            & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)
            != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "response observation v2 socket terminal event",
            ));
        }
        if pollfd.revents & events != 0 {
            return Ok(());
        }
    }
}

pub(super) fn response_observation_v2_send_packet(
    socket: RawFd,
    control: &[u8],
    objects: &[ResponseObservationV2ExactInput],
    deadline: ResponseObservationV2Deadline,
) -> Result<(), ResponseObservationV2PacketSendError> {
    if control.is_empty()
        || control.len() > RESPONSE_OBSERVATION_V2_MAX_CONTROL_BYTES
        || objects.len() > RESPONSE_OBSERVATION_V2_MAX_OBJECTS
    {
        return Err(ResponseObservationV2PacketSendError::NotSent);
    }
    let mut iovec = libc::iovec {
        iov_base: control.as_ptr() as *mut libc::c_void,
        iov_len: control.len(),
    };
    let mut message: libc::msghdr =
        unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    let raw_fds = objects
        .iter()
        .map(|object| object.file.as_raw_fd())
        .collect::<Vec<_>>();
    let mut ancillary = Vec::<libc::size_t>::new();
    if !raw_fds.is_empty() {
        let payload_bytes = raw_fds
            .len()
            .checked_mul(std::mem::size_of::<RawFd>())
            .ok_or(
                ResponseObservationV2PacketSendError::NotSent,
            )?;
        let control_bytes =
            unsafe { libc::CMSG_SPACE(payload_bytes as u32) }
                as usize;
        let words = control_bytes
            .checked_add(std::mem::size_of::<libc::size_t>() - 1)
            .ok_or(
                ResponseObservationV2PacketSendError::NotSent,
            )?
            / std::mem::size_of::<libc::size_t>();
        ancillary.resize(words, 0);
        message.msg_control = ancillary.as_mut_ptr().cast();
        message.msg_controllen = control_bytes;
        let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        if header.is_null() {
            return Err(
                ResponseObservationV2PacketSendError::NotSent,
            );
        }
        unsafe {
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len =
                libc::CMSG_LEN(payload_bytes as u32) as usize;
            std::ptr::copy_nonoverlapping(
                raw_fds.as_ptr(),
                libc::CMSG_DATA(header).cast::<RawFd>(),
                raw_fds.len(),
            );
        }
    }
    loop {
        response_observation_v2_wait_socket(
            socket,
            libc::POLLOUT,
            deadline,
        )
        .map_err(|_| {
            ResponseObservationV2PacketSendError::NotSent
        })?;
        if deadline.expired() {
            return Err(
                ResponseObservationV2PacketSendError::NotSent,
            );
        }
        let sent = unsafe {
            libc::sendmsg(
                socket,
                &message,
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        };
        if sent < 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::Interrupted
                    | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(
                ResponseObservationV2PacketSendError::NotSent,
            );
        }
        if sent as usize != control.len() {
            return Err(
                ResponseObservationV2PacketSendError::OutcomeUnknown,
            );
        }
        return Ok(());
    }
}

pub(super) fn response_observation_v2_receive_packet(
    socket: RawFd,
    deadline: ResponseObservationV2Deadline,
) -> io::Result<(Vec<u8>, Vec<File>)> {
    let mut control =
        vec![0u8; RESPONSE_OBSERVATION_V2_MAX_CONTROL_BYTES];
    let rights_bytes = RESPONSE_OBSERVATION_V2_MAX_OBJECTS
        .checked_mul(std::mem::size_of::<RawFd>())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "SCM_RIGHTS receive bound overflow",
            )
        })?;
    let ancillary_bytes =
        unsafe { libc::CMSG_SPACE(rights_bytes as u32) } as usize;
    let ancillary_words = ancillary_bytes
        .checked_add(std::mem::size_of::<libc::size_t>() - 1)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "SCM_RIGHTS receive alignment overflow",
            )
        })?
        / std::mem::size_of::<libc::size_t>();
    let mut ancillary =
        vec![0 as libc::size_t; ancillary_words];
    let mut iovec = libc::iovec {
        iov_base: control.as_mut_ptr().cast(),
        iov_len: control.len(),
    };
    let mut message: libc::msghdr =
        unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = ancillary.as_mut_ptr().cast();
    message.msg_controllen = ancillary_bytes;
    let received = loop {
        response_observation_v2_wait_socket(
            socket,
            libc::POLLIN,
            deadline,
        )?;
        if deadline.expired() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "response observation v2 receive deadline elapsed",
            ));
        }
        let received = unsafe {
            libc::recvmsg(
                socket,
                &mut message,
                libc::MSG_CMSG_CLOEXEC
                    | libc::MSG_TRUNC
                    | libc::MSG_DONTWAIT,
            )
        };
        if received < 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::Interrupted
                    | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
        }
        break received;
    };
    if received <= 0 {
        return Err(if received == 0 {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "response observation v2 peer closed",
            )
        } else {
            io::Error::last_os_error()
        });
    }
    let base = message.msg_control as usize;
    let end = base
        .checked_add(message.msg_controllen)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "ancillary region overflow",
            )
        })?;
    let header_bytes = unsafe { libc::CMSG_LEN(0) } as usize;
    let mut raw_fds = Vec::<RawFd>::new();
    let mut cursor = base;
    while cursor < end {
        if end.saturating_sub(cursor)
            < std::mem::size_of::<libc::cmsghdr>()
        {
            response_observation_v2_close_raw_fds(&raw_fds);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "partial ancillary header",
            ));
        }
        let header = unsafe {
            std::ptr::read_unaligned(
                cursor as *const libc::cmsghdr,
            )
        };
        if header.cmsg_len < header_bytes
            || header.cmsg_len > end.saturating_sub(cursor)
            || header.cmsg_level != libc::SOL_SOCKET
            || header.cmsg_type != libc::SCM_RIGHTS
        {
            response_observation_v2_close_raw_fds(&raw_fds);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid SCM_RIGHTS ancillary header",
            ));
        }
        let payload_bytes = header.cmsg_len - header_bytes;
        if payload_bytes == 0
            || payload_bytes % std::mem::size_of::<RawFd>() != 0
        {
            response_observation_v2_close_raw_fds(&raw_fds);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "partial SCM_RIGHTS payload",
            ));
        }
        let count = payload_bytes / std::mem::size_of::<RawFd>();
        if raw_fds.len().saturating_add(count)
            > RESPONSE_OBSERVATION_V2_MAX_OBJECTS
        {
            response_observation_v2_close_raw_fds(&raw_fds);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "too many SCM_RIGHTS descriptors",
            ));
        }
        let data = cursor
            .checked_add(header_bytes)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SCM_RIGHTS data overflow",
                )
            })?;
        if data
            .checked_add(payload_bytes)
            .is_none_or(|payload_end| payload_end > end)
        {
            response_observation_v2_close_raw_fds(&raw_fds);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SCM_RIGHTS payload outside ancillary region",
            ));
        }
        for index in 0..count {
            let offset = index
                .checked_mul(std::mem::size_of::<RawFd>())
                .and_then(|value| data.checked_add(value))
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SCM_RIGHTS descriptor offset overflow",
                    )
                })?;
            let fd = unsafe {
                std::ptr::read_unaligned(offset as *const RawFd)
            };
            if fd < 0
                || raw_fds.contains(&fd)
                || unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0
            {
                response_observation_v2_close_raw_fds(&raw_fds);
                if fd >= 0 && !raw_fds.contains(&fd) {
                    unsafe {
                        libc::close(fd);
                    }
                }
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid delivered SCM_RIGHTS descriptor",
                ));
            }
            raw_fds.push(fd);
        }
        let aligned = header
            .cmsg_len
            .checked_add(std::mem::size_of::<libc::size_t>() - 1)
            .map(|value| {
                value
                    & !(std::mem::size_of::<libc::size_t>() - 1)
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ancillary alignment overflow",
                )
            })?;
        cursor = cursor.checked_add(aligned).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "ancillary cursor overflow",
            )
        })?;
    }
    let files = raw_fds
        .into_iter()
        .map(|fd| unsafe { File::from_raw_fd(fd) })
        .collect::<Vec<_>>();
    if message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC)
        != 0
        || received as usize > control.len()
    {
        drop(files);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "response observation v2 packet was truncated",
        ));
    }
    control.truncate(received as usize);
    Ok((control, files))
}

pub(super) fn response_observation_v2_close_raw_fds(fds: &[RawFd]) {
    let mut closed = HashSet::new();
    for fd in fds {
        if *fd >= 0 && closed.insert(*fd) {
            unsafe {
                libc::close(*fd);
            }
        }
    }
}

pub(super) fn response_observation_v2_validate_output_objects(
    descriptors: &[ExactByteObjectDescriptor],
    files: Vec<File>,
    deadline: ResponseObservationV2Deadline,
) -> Result<
    BTreeMap<u16, Zeroizing<Vec<u8>>>,
    ResponseObservationV2TransactionError,
> {
    if deadline.expired()
        || descriptors.len() != files.len()
        || descriptors.len() > RESPONSE_OBSERVATION_V2_MAX_OBJECTS
    {
        return Err(
            ResponseObservationV2TransactionError::InvalidResponse,
        );
    }
    let mut output = BTreeMap::new();
    for (index, (descriptor, mut file)) in
        descriptors.iter().zip(files).enumerate()
    {
        if deadline.expired()
            || descriptor.fd_index != index as u16
            || descriptor.required_seals != MemfdSealProfile::ImmutableV1
            || descriptor.byte_length == 0
            || descriptor.byte_length
                > RESPONSE_OBSERVATION_V2_MAX_OBJECT_BYTES
        {
            return Err(
                ResponseObservationV2TransactionError::InvalidResponse,
            );
        }
        let metadata = file.metadata().map_err(|_| {
            ResponseObservationV2TransactionError::InvalidResponse
        })?;
        let required_seals = libc::F_SEAL_WRITE
            | libc::F_SEAL_GROW
            | libc::F_SEAL_SHRINK
            | libc::F_SEAL_SEAL;
        let observed_seals =
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
        if metadata.len() != descriptor.byte_length
            || observed_seals < 0
            || observed_seals & required_seals != required_seals
        {
            return Err(
                ResponseObservationV2TransactionError::InvalidResponse,
            );
        }
        file.seek(SeekFrom::Start(0)).map_err(|_| {
            ResponseObservationV2TransactionError::InvalidResponse
        })?;
        let capacity =
            usize::try_from(descriptor.byte_length).map_err(|_| {
                ResponseObservationV2TransactionError::InvalidResponse
            })?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
        if deadline.expired() {
            return Err(
                ResponseObservationV2TransactionError::Unavailable,
            );
        }
        file.take(descriptor.byte_length)
            .read_to_end(&mut bytes)
            .map_err(|_| {
                ResponseObservationV2TransactionError::InvalidResponse
            })?;
        if bytes.len() != capacity
            || sha256_prefixed(&bytes) != descriptor.sha256
            || deadline.expired()
        {
            return Err(
                ResponseObservationV2TransactionError::InvalidResponse,
            );
        }
        output.insert(descriptor.fd_index, bytes);
    }
    Ok(output)
}

pub(super) fn response_observation_v2_descriptor_manifest_sha256(
    descriptors: &[ExactByteObjectDescriptor],
) -> String {
    let mut ordered = descriptors.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|descriptor| descriptor.fd_index);
    let mut hasher = Sha256::new();
    response_observation_v2_hash_frame(
        &mut hasher,
        b"serverware.response-v2/exact-object-manifest/v1",
    );
    for descriptor in ordered {
        response_observation_v2_hash_frame(
            &mut hasher,
            &descriptor.fd_index.to_be_bytes(),
        );
        response_observation_v2_hash_frame(
            &mut hasher,
            &descriptor.byte_length.to_be_bytes(),
        );
        response_observation_v2_hash_frame(
            &mut hasher,
            descriptor.sha256.as_bytes(),
        );
        response_observation_v2_hash_frame(
            &mut hasher,
            descriptor.object_id.as_bytes(),
        );
        response_observation_v2_hash_frame(
            &mut hasher,
            match descriptor.media_type {
                ExactObjectMediaType::CanonicalJson => {
                    b"CANONICAL_JSON"
                }
                ExactObjectMediaType::Http11Request => {
                    b"HTTP11_REQUEST"
                }
                ExactObjectMediaType::Http11Response => {
                    b"HTTP11_RESPONSE"
                }
                ExactObjectMediaType::EvidenceBundle => {
                    b"EVIDENCE_BUNDLE"
                }
                ExactObjectMediaType::AttestationArtifact => {
                    b"ATTESTATION_ARTIFACT"
                }
                ExactObjectMediaType::PublicationArtifact => {
                    b"PUBLICATION_ARTIFACT"
                }
                ExactObjectMediaType::OpaqueProviderArtifact => {
                    b"OPAQUE_PROVIDER_ARTIFACT"
                }
            },
        );
        response_observation_v2_hash_frame(
            &mut hasher,
            b"IMMUTABLE_V1",
        );
    }
    format!("sha256:{:x}", hasher.finalize())
}

pub(super) fn response_observation_v2_hash_frame(
    hasher: &mut Sha256,
    value: &[u8],
) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

#[cfg(target_os = "linux")]
pub(super) fn response_observation_v2_boottime_ns(
) -> Result<u64, ResponseObservationV2TransactionError> {
    let mut observed = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: observed points to writable timespec storage and
    // CLOCK_BOOTTIME has no additional preconditions.
    if unsafe {
        libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut observed)
    } != 0
        || observed.tv_sec < 0
        || observed.tv_nsec < 0
        || observed.tv_nsec >= 1_000_000_000
    {
        return Err(
            ResponseObservationV2TransactionError::Unavailable,
        );
    }
    u64::try_from(observed.tv_sec)
        .ok()
        .and_then(|seconds| {
            seconds
                .checked_mul(1_000_000_000)
                .and_then(|value| {
                    value.checked_add(observed.tv_nsec as u64)
                })
        })
        .ok_or(ResponseObservationV2TransactionError::Unavailable)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn response_observation_v2_boottime_ns(
) -> Result<u64, ResponseObservationV2TransactionError> {
    Err(ResponseObservationV2TransactionError::Unavailable)
}
pub(super) fn connect_response_observation_v2_socket(
    path: &Path,
    expected_uid: libc::uid_t,
    deadline: ResponseObservationV2Deadline,
) -> Result<OwnedFd, String> {
    if deadline.expired() {
        return Err(
            "response-observation v2 connection deadline elapsed"
                .to_string(),
        );
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| {
            format!("inspect response-observation v2 socket: {error}")
        })?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o002 != 0
    {
        return Err(
            "response-observation v2 socket type, owner, or mode is unsafe"
                .to_string(),
        );
    }
    let bytes = path.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un =
        unsafe { std::mem::zeroed() };
    if bytes.is_empty()
        || bytes.len() >= address.sun_path.len()
        || bytes.contains(&0)
    {
        return Err(
            "response-observation v2 socket path is invalid"
                .to_string(),
        );
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (destination, source) in address
        .sun_path
        .iter_mut()
        .zip(bytes.iter().copied())
    {
        *destination = source as libc::c_char;
    }
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET
                | libc::SOCK_CLOEXEC
                | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        return Err(format!(
            "create response-observation v2 socket: {}",
            io::Error::last_os_error()
        ));
    }
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let address_length =
        std::mem::offset_of!(libc::sockaddr_un, sun_path)
            + bytes.len()
            + 1;
    let connect_result = unsafe {
        libc::connect(
            socket.as_raw_fd(),
            (&address as *const libc::sockaddr_un)
                .cast::<libc::sockaddr>(),
            libc::socklen_t::try_from(address_length)
                .unwrap_or(0),
        )
    };
    if connect_result != 0 {
        let error = io::Error::last_os_error();
        if !matches!(
            error.raw_os_error(),
            Some(libc::EINPROGRESS) | Some(libc::EAGAIN)
        ) {
            return Err(format!(
                "connect response-observation v2 socket: {error}"
            ));
        }
        loop {
            let remaining =
                deadline.remaining().unwrap_or(Duration::ZERO);
            if remaining.is_zero() {
                return Err(
                    "response-observation v2 nonblocking connection deadline elapsed"
                        .to_string(),
                );
            }
            let mut pollfd = libc::pollfd {
                fd: socket.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            let timeout = deadline.short_poll_timeout_ms();
            let polled =
                unsafe { libc::poll(&mut pollfd, 1, timeout) };
            if polled < 0
                && io::Error::last_os_error().kind()
                    == io::ErrorKind::Interrupted
            {
                continue;
            }
            if polled == 0 {
                continue;
            }
            if polled < 0 {
                return Err(
                    "response-observation v2 nonblocking connection failed"
                        .to_string(),
                );
            }
            let mut socket_error: libc::c_int = 0;
            let mut socket_error_length =
                std::mem::size_of::<libc::c_int>()
                    as libc::socklen_t;
            if unsafe {
                libc::getsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    (&mut socket_error as *mut libc::c_int)
                        .cast(),
                    &mut socket_error_length,
                )
            } != 0
                || socket_error_length as usize
                    != std::mem::size_of::<libc::c_int>()
                || socket_error != 0
            {
                return Err(
                    "response-observation v2 nonblocking connection failed"
                        .to_string(),
                );
            }
            break;
        }
    }
    let mut credentials: libc::ucred =
        unsafe { std::mem::zeroed() };
    let mut length =
        std::mem::size_of::<libc::ucred>()
            as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    } != 0
        || length as usize
            != std::mem::size_of::<libc::ucred>()
        || credentials.pid <= 0
        || credentials.uid != expected_uid
    {
        return Err(
            "response-observation v2 peer credentials mismatch"
                .to_string(),
        );
    }
    let remaining =
        deadline.remaining().unwrap_or(Duration::ZERO);
    if remaining.is_zero() {
        return Err(
            "response-observation v2 connection deadline elapsed before bounded packet I/O"
                .to_string(),
        );
    }
    Ok(socket)
}
