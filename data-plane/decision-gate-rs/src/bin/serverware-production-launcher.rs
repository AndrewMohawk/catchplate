#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fmt;
use std::path::{Component, Path, PathBuf};

const LAUNCH_MANIFEST_API_VERSION: &str = "serverware.productionReadinessLaunch/v3";
const LAUNCH_MANIFEST_KIND: &str = "ProductionReadinessLaunch";
const NONCE_ROLLBACK_ASSURANCE_BINDING_API_VERSION: &str =
    "serverware.productionNonceRollbackAssuranceBinding/v1";
const NONCE_ROLLBACK_ASSURANCE_PINS_API_VERSION: &str =
    "serverware.productionNonceRollbackAssurancePins/v1";
const NONCE_AUTHORITY_ASSURANCE_API_VERSION: &str =
    "serverware.nonceAuthorityAssurance/v1";
const CANONICAL_JSON_PROFILE: &str =
    "serverware.canonicalJson/integer-string-bool-null-array-object-nfc-v1";
const RECEIPT_API_VERSION: &str = "serverware.bootstrapReceipt/v3";
const RECEIPT_KIND: &str = "ProductionBootstrapReceipt";
const AUTHORIZATION_REQUEST_API_VERSION: &str = "serverware.launchAuthorizationRequest/v2";
const AUTHORIZATION_REQUEST_KIND: &str = "ProductionLaunchAuthorizationRequest";
const AUTHORIZATION_API_VERSION: &str = "serverware.launchAuthorization/v2";
const AUTHORIZATION_KIND: &str = "ProductionLaunchAuthorization";
const AUTHORIZATION_SCOPE: &str = "trusted-host-readiness";
const FRESHNESS_AUTHORITY: &str = "trusted-host-wall-clock";
const CAPABILITY_SEMANTICS: &str = "time-bounded-idempotent-readiness-authorization";
const WITNESS_API_VERSION: &str = "serverware.launchAuthorityWitnessTransition/v1";
const WITNESS_KIND: &str = "LaunchAuthorityWitnessTransition";
const WITNESS_OPERATION: &str = "authorize-trusted-host-readiness";
const WITNESS_STORE_ASSURANCE_API_VERSION: &str =
    "serverware.launchAuthorityWitnessStoreAssurance/v1";
const WITNESS_STORE_ASSURANCE_KIND: &str =
    "LaunchAuthorityWitnessStoreAssurance";
const GLOBAL_ROLE_REGISTRY_BINDING_API_VERSION: &str =
    "serverware.productionLaunchGlobalRoleRegistryBinding/v1";
const GLOBAL_ROLE_REGISTRY_API_VERSION: &str =
    "serverware.productionLaunchGlobalRoleRegistry/v1";
const GLOBAL_ROLE_REGISTRY_CLAIM_SCOPE: &str =
    "roles-present-in-native-launch-contract";
const ATTEMPT_JOURNAL_API_VERSION: &str =
    "serverware.launchAuthorizationAttemptJournal/v1";
const ATTEMPT_JOURNAL_KIND: &str = "LaunchAuthorizationAttemptJournal";
const ATTEMPT_JOURNAL_DOMAIN: &str =
    "serverware.launchAuthorizationAttemptJournal/v1";
const ATTEMPT_JOURNAL_CONSISTENCY_SCOPE: &str =
    "trusted-host-readiness-availability-and-consistency-only";
const ATTEMPT_JOURNAL_ROLLBACK_AUTHORITY: &str =
    "external-monotonic-witness";
const ATTEMPT_JOURNAL_FILE_NAME: &str =
    "launch-authorization-attempt.v1.json";
const ATTEMPT_JOURNAL_LOCK_FILE_NAME: &str =
    "launch-authorization-attempt.v1.lock";
const PRODUCTION_STATE_DIRECTORY: &str =
    "/var/lib/serverware/production-proof";
const AUTHORIZATION_SOCKET_PATH: &str = "/run/serverware/launch-authority.sock";
const AUTHORIZATION_MAX_BYTES: usize = 16 * 1024;
const AUTHORIZATION_TIMEOUT_MILLIS: i32 = 2_000;
const AUTHORIZATION_MAX_EXCHANGE_ATTEMPTS: usize = 2;
const AUTHORIZATION_MAX_FRESH_ATTEMPTS: usize = 2;
const AUTHORIZATION_MAX_LIFETIME_SECONDS: u64 = 30;
const AUTHORIZATION_MAX_FUTURE_SKEW_SECONDS: u64 = 5;
const PHASE_SUPERVISION_POLL_MILLIS: u64 = 10;
const PHASE_FORCE_REAP_TIMEOUT_MILLIS: u64 = 2_000;
const PHASE_REAP_BATCH_MAX: usize = 256;
const PHASE_EXECUTION_GO_TOKEN: u8 = 0xa5;
const NANOSECONDS_PER_SECOND: u32 = 1_000_000_000;
const JSON_SAFE_INTEGER_MAX: u64 = 9_007_199_254_740_991;
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const COMPILED_AUTHORITY_PUBLIC_KEY_HEX: &str =
    include_str!("../../trust/launch-authority-root.ed25519.hex");
const RECEIPT_FD: i32 = 198;
const EXPECTED_CONTROL_PLANE_ID: &str = "65532";
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_MEASURED_FILE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_PYTHON_EXECUTABLE_BYTES: usize = 64 * 1024 * 1024;
const MAX_TRUSTED_PUBLIC_KEY_BYTES: u64 = 64 * 1024;
const MAX_NONCE_ROLLBACK_ASSURANCE_PINS_BYTES: u64 = 64 * 1024;
const MAX_GLOBAL_ROLE_REGISTRY_PINS_BYTES: u64 = 64 * 1024;
const MAX_ATTEMPT_JOURNAL_BYTES: u64 = 64 * 1024;
const MAX_PRODUCTION_MANIFEST_PATH_BYTES: usize = 4096;
const RECEIPT_SHA256_PLACEHOLDER: &str = "sha256:<bootstrap-receipt>";
const ELF64_HEADER_SIZE: usize = 64;
const ELF64_PROGRAM_HEADER_SIZE: usize = 56;
const ELF64_SECTION_HEADER_SIZE: usize = 64;
const ELF64_SYMBOL_SIZE: usize = 24;
const ELF64_DYNAMIC_SIZE: usize = 16;
const ELF_MACHINE_X86_64: u16 = 62;
const ELF_SECTION_STRTAB: u32 = 3;
const ELF_SECTION_DYNAMIC: u32 = 6;
const ELF_SECTION_DYNSYM: u32 = 11;
const ELF_DYNAMIC_NEEDED: u64 = 1;
const GLOBAL_ROLE_NAMES: [&str; 10] = [
    "launchAuthority",
    "launchAuthorityWitness",
    "launchAuthorityWitnessStoreAssurance",
    "launchAuthorityWitnessTls",
    "nonceAuthorityAssuranceEvidence",
    "nonceAuthorityVerifierState",
    "nonceAuthorityVerifierStateStoreAttestation",
    "policyActivation",
    "policyIdentity",
    "reproducibleBuild",
];
const GLOBAL_ROLES_OUTSIDE_CLAIM: [&str; 10] = [
    "actionGate",
    "publicAttestationNonceStore",
    "publicAttestationProducer",
    "publicAttestationWitnessStore",
    "finalVerifier",
    "nonceAuthorityVerifierStateStoreAssurance",
    "release",
    "response",
    "verifierStateTlsClient",
    "verifierStateTlsServer",
];
const INDEPENDENT_ADMINISTRATION_BINDING_LABELS: [&str; 7] = [
    "launchAuthority.signingKeyId",
    "launchAuthorityWitness.signingKeyId",
    "launchAuthorityWitness.identitySha256",
    "launchAuthorityWitness.administrativeDomainSha256",
    "launchAuthorityWitnessStore.identitySha256",
    "launchAuthorityWitnessStore.administrativeDomainSha256",
    "launchAuthorityWitnessStore.assuranceIssuerKeyId",
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct LauncherError(String);

impl LauncherError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for LauncherError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for LauncherError {}

type Result<T> = std::result::Result<T, LauncherError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthorizationTimePolicy {
    CurrentRequired,
    RecoveryMayBeExpired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Cli {
    manifest: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LaunchManifest {
    api_version: String,
    kind: String,
    release_root: PathBuf,
    state_directory: PathBuf,
    source_tree_digest: String,
    authorization: LaunchAuthorizationConfiguration,
    launch_attempt_journal: LaunchAttemptJournalConfiguration,
    global_role_registry: GlobalRoleRegistryBinding,
    nonce_rollback_assurance: NonceRollbackAssuranceBinding,
    production_env: FileRecord,
    python: PythonRecord,
    scripts: ScriptsRecord,
    compose_file: FileRecord,
    inputs: Inputs,
    outputs: Outputs,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LaunchAuthorizationConfiguration {
    authorization_scope: String,
    deployment_audience: String,
    deployment_identity_sha256: String,
    freshness_authority: String,
    monotonic_witness: LaunchAuthorityWitnessConfiguration,
    release_sequence: u64,
    rollback_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LaunchAuthorityWitnessConfiguration {
    administrative_domain_sha256: String,
    identity_sha256: String,
    signing_key_id: String,
    signing_public_key_spki_der_base64url: String,
    store_assurance: LaunchAuthorityWitnessStoreAssuranceEnvelope,
    store_assurance_issuer_key_id: String,
    store_assurance_issuer_public_key_spki_der_base64url: String,
    store_assurance_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LaunchAuthorityWitnessStoreAssuranceEnvelope {
    api_version: String,
    kind: String,
    statement: LaunchAuthorityWitnessStoreAssuranceStatement,
    signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LaunchAuthorityWitnessStoreAssuranceStatement {
    assurance_issuer_key_id: String,
    witness_key_id: String,
    witness_identity_sha256: String,
    witness_administrative_domain_sha256: String,
    store_identity_sha256: String,
    store_administrative_domain_sha256: String,
    store_class: String,
    rollback_resistance: String,
    independent_administration: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LaunchAttemptJournalConfiguration {
    api_version: String,
    path: PathBuf,
    lock_path: PathBuf,
    domain: String,
    max_bytes: u64,
    consistency_scope: String,
    rollback_authority: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GlobalRoleRegistryBinding {
    api_version: String,
    canonical_profile: String,
    claim_scope: String,
    registry: GlobalRoleRegistry,
    registry_sha256: String,
    pins_file: FileRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GlobalRoleRegistry {
    api_version: String,
    claim_scope: String,
    roles: BTreeMap<String, String>,
    roles_outside_claim: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ReleaseProvenanceIdentity {
    provenance_digest: String,
    provenance: ReleaseProvenanceBodyIdentity,
}

#[derive(Debug, Deserialize)]
struct ReleaseProvenanceBodyIdentity {
    version: u64,
    source: String,
    source_tree: ReleaseSourceTreeIdentity,
}

#[derive(Debug, Deserialize)]
struct ReleaseSourceTreeIdentity {
    digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileRecord {
    path: PathBuf,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PythonRecord {
    path: PathBuf,
    sha256: String,
    import_roots: Vec<ImportRootRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportRootRecord {
    path: PathBuf,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScriptsRecord {
    preflight: FileRecord,
    runner: FileRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Inputs {
    production_images_build: FileRecord,
    production_images_env: FileRecord,
    production_images_published: FileRecord,
    release_provenance_summary: FileRecord,
    release_provenance: FileRecord,
    image_signatures_summary: FileRecord,
    image_signatures: FileRecord,
    bench: FileRecord,
    kms_materials: FileRecord,
    policy_bundle: FileRecord,
    policy_trusted_public_key: FileRecord,
    policy_identity_verification: FileRecord,
    policy_activation_verification: FileRecord,
    policy_activation_signature: FileRecord,
    policy_activation_trusted_public_key: FileRecord,
    reproducible_build_verification: FileRecord,
    reproducible_build_signature: FileRecord,
    reproducible_build_trusted_public_key: FileRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Outputs {
    config_out: PathBuf,
    claims_file: PathBuf,
    nitro_evidence_out: PathBuf,
    readiness_out: PathBuf,
    completion_proof_out: PathBuf,
    proxy_proof_summary_out: PathBuf,
    production_host_preflight: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NonceRollbackAssuranceBinding {
    api_version: String,
    canonical_profile: String,
    contract: NonceRollbackAssurancePins,
    contract_sha256: String,
    enforcement: String,
    pins_file: FileRecord,
    purpose: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NonceRollbackAssurancePins {
    api_version: String,
    independent_verifier_pins: IndependentVerifierPins,
    public_config_pins: PublicConfigPins,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IndependentVerifierPins {
    expected_nonce_authority_assurance_issuer_spki_sha256: String,
    expected_nonce_authority_assurance_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicConfigPins {
    nonce_authority_assurance: NonceAuthorityAssurance,
    nonce_authority_assurance_evidence_signing_public_key_spki_der_base64url: String,
    nonce_authority_assurance_sha256: String,
    nonce_authority_verifier_state_signing_public_key_spki_der_base64url: String,
    nonce_authority_verifier_state_store_administrative_domain_sha256: String,
    nonce_authority_verifier_state_store_assurance_evidence_sha256: String,
    nonce_authority_verifier_state_store_attestation_public_key_spki_der_base64url: String,
    nonce_authority_verifier_state_store_identity_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NonceAuthorityAssurance {
    api_version: String,
    administrative_domain_sha256: String,
    assurance_evidence_sha256: String,
    assurance_evidence_type: String,
    assurance_level: String,
    authority_epoch: u64,
    authority_generation: u64,
    authority_identity_sha256: String,
    backend_class: String,
    production_eligible: bool,
    rollback_protection: NonceRollbackProtection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NonceRollbackProtection {
    administrative_rollback_resistance: bool,
    backend_attestation_required: bool,
    exact_successor_required: bool,
    fresh_verifier_challenge_required: bool,
    key_protection: String,
    mechanism: String,
    state_commitment: String,
    verifier_state_store_class: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptMetadata {
    device: u64,
    inode: u64,
    mode: u32,
    owner_uid: u32,
    owner_gid: u32,
    link_count: u64,
    size: u64,
    modified_unix_nanos: i128,
    changed_unix_nanos: i128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ReceiptFile {
    path: String,
    sha256: String,
    metadata: ReceiptMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ReceiptImportRoot {
    path: String,
    sha256: String,
    metadata: ReceiptMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ReceiptPython {
    path: String,
    sha256: String,
    metadata: ReceiptMetadata,
    #[serde(rename = "importRoots")]
    import_roots: Vec<ReceiptImportRoot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ReceiptScripts {
    preflight: ReceiptFile,
    runner: ReceiptFile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptNonceRollbackAssurance {
    api_version: String,
    contract_sha256: String,
    pins_file: ReceiptFile,
    retained_snapshot_fd: i32,
    retained_snapshot_sha256: String,
    verifier_state_service: ReceiptVerifierStateService,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptVerifierStateService {
    signing_public_key_spki_der_base64url: String,
    store_administrative_domain_sha256: String,
    store_assurance_evidence_sha256: String,
    store_attestation_public_key_spki_der_base64url: String,
    store_identity_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptArgv {
    preflight_sha256: String,
    readiness_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ReceiptEnvironment {
    names: Vec<String>,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LaunchAuthorizationRequest {
    api_version: String,
    kind: String,
    launcher_nonce: String,
    boot_id_sha256: String,
    launcher_sha256: String,
    manifest_sha256: String,
    global_role_registry: GlobalRoleRegistry,
    global_role_registry_sha256: String,
    global_role_registry_pins_sha256: String,
    nonce_rollback_assurance_contract_sha256: String,
    nonce_rollback_assurance_pins_sha256: String,
    release_provenance_sha256: String,
    provenance_digest: String,
    reproducible_build_verification_sha256: String,
    source_tree_digest: String,
    deployment_audience: String,
    deployment_identity_sha256: String,
    release_sequence: u64,
    rollback_epoch: u64,
    authorization_scope: String,
    freshness_authority: String,
    launch_attempt_journal_domain: String,
    launch_attempt_recovery_identity_sha256: String,
    launch_authority_witness_challenge: String,
    launch_authority_witness_key_id: String,
    launch_authority_witness_identity_sha256: String,
    launch_authority_witness_administrative_domain_sha256: String,
    launch_authority_witness_store_assurance_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LaunchAuthorizationStatement {
    authorization_id: String,
    authority_key_id: String,
    request_sha256: String,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    authorization_scope: String,
    freshness_authority: String,
    capability_semantics: String,
    global_role_registry_sha256: String,
    monotonic_witness: LaunchAuthorityWitnessEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LaunchAuthorizationEnvelope {
    api_version: String,
    kind: String,
    statement: LaunchAuthorizationStatement,
    signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LaunchAuthorityWitnessStatement {
    operation: String,
    operation_id: String,
    authorization_id: String,
    request_sha256: String,
    challenge: String,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    authority_key_id: String,
    witness_key_id: String,
    witness_identity_sha256: String,
    witness_administrative_domain_sha256: String,
    store_assurance_sha256: String,
    registry_generation: u64,
    registry_sha256: String,
    predecessor_state_sha256: String,
    successor_state_sha256: String,
    deployment_audience: String,
    deployment_identity_sha256: String,
    release_sequence: u64,
    rollback_epoch: u64,
    authorization_scope: String,
    state_transition_committed: bool,
    checkpoint_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LaunchAuthorityWitnessEnvelope {
    api_version: String,
    kind: String,
    statement: LaunchAuthorityWitnessStatement,
    signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptLaunchAuthorization {
    request: LaunchAuthorizationRequest,
    request_sha256: String,
    envelope: LaunchAuthorizationEnvelope,
    authorization_sha256: String,
    witness_public_key_spki_der_base64url: String,
    verified_at_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct BootstrapReceipt {
    api_version: String,
    kind: String,
    launch_id: String,
    boot_id_sha256: String,
    launcher: ReceiptFile,
    manifest: ReceiptFile,
    source_tree_digest: String,
    launch_authorization: ReceiptLaunchAuthorization,
    nonce_rollback_assurance: ReceiptNonceRollbackAssurance,
    production_env: ReceiptFile,
    python: ReceiptPython,
    scripts: ReceiptScripts,
    compose_file: ReceiptFile,
    inputs: BTreeMap<String, ReceiptFile>,
    argv: ReceiptArgv,
    environment: ReceiptEnvironment,
}

fn parse_cli<I>(arguments: I) -> Result<Cli>
where
    I: IntoIterator<Item = OsString>,
{
    let mut arguments = arguments.into_iter();
    let _program = arguments.next();
    let mut manifest = None;

    while let Some(raw_name) = arguments.next() {
        let name = raw_name
            .into_string()
            .map_err(|_| LauncherError::new("launcher arguments must be valid UTF-8"))?;
        let raw_value = arguments
            .next()
            .ok_or_else(|| LauncherError::new(format!("missing value for {name}")))?;
        let value = raw_value
            .into_string()
            .map_err(|_| LauncherError::new("launcher arguments must be valid UTF-8"))?;
        match name.as_str() {
            "--manifest" => {
                if manifest.replace(PathBuf::from(value)).is_some() {
                    return Err(LauncherError::new("duplicate --manifest argument"));
                }
            }
            _ => {
                return Err(LauncherError::new(format!(
                    "unknown launcher argument: {name}"
                )))
            }
        }
    }

    let manifest = manifest.ok_or_else(|| LauncherError::new("missing --manifest argument"))?;
    require_normalized_absolute(&manifest, "manifest")?;
    Ok(Cli { manifest })
}

fn require_sha256(value: &str, label: &str) -> Result<()> {
    let Some(hex_value) = value.strip_prefix("sha256:") else {
        return Err(LauncherError::new(format!(
            "{label} must be sha256:<64 lowercase hex>"
        )));
    };
    if hex_value.len() != 64
        || !hex_value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(LauncherError::new(format!(
            "{label} must be sha256:<64 lowercase hex>"
        )));
    }
    Ok(())
}

fn require_lower_hex_64(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(LauncherError::new(format!(
            "{label} must contain 64 lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

fn require_deployment_audience(value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 128
        || !(bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        || !bytes.iter().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(*byte, b'.' | b'_' | b':' | b'-')
        })
    {
        return Err(LauncherError::new(
            "authorization.deploymentAudience is invalid",
        ));
    }
    Ok(())
}

fn require_json_safe_integer(value: u64, label: &str, allow_zero: bool) -> Result<()> {
    if value > JSON_SAFE_INTEGER_MAX || (!allow_zero && value == 0) {
        return Err(LauncherError::new(format!("{label} is invalid")));
    }
    Ok(())
}

fn require_digest_match(actual: &str, expected: &str, label: &str) -> Result<()> {
    require_sha256(actual, label)?;
    require_sha256(expected, label)?;
    if actual != expected {
        return Err(LauncherError::new(format!("{label} digest does not match")));
    }
    Ok(())
}

fn require_safe_ascii_path(path: &Path, label: &str) -> Result<()> {
    let value = path.to_str().ok_or_else(|| {
        LauncherError::new(format!(
            "{label} must use the safe printable-ASCII production path syntax"
        ))
    })?;
    let bytes = value.as_bytes();
    if bytes.len() < 2
        || bytes.len() > MAX_PRODUCTION_MANIFEST_PATH_BYTES
        || bytes.first() != Some(&b'/')
        || bytes[1..]
            .split(|byte| *byte == b'/')
            .any(|component| {
                component.is_empty()
                    || !component.iter().all(|byte| {
                        byte.is_ascii_alphanumeric()
                            || matches!(*byte, b'.' | b'_' | b'+' | b'@' | b':' | b'-')
                    })
            })
    {
        return Err(LauncherError::new(format!(
            "{label} must use the safe printable-ASCII production path syntax"
        )));
    }
    Ok(())
}

fn require_normalized_absolute(path: &Path, label: &str) -> Result<()> {
    require_safe_ascii_path(path, label)?;
    if !path.is_absolute() {
        return Err(LauncherError::new(format!("{label} must be absolute")));
    }
    let mut saw_normal = false;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(value) if !value.is_empty() => saw_normal = true,
            _ => {
                return Err(LauncherError::new(format!(
                    "{label} must be an absolute normalized path"
                )))
            }
        }
    }
    if !saw_normal {
        return Err(LauncherError::new(format!(
            "{label} must not be the filesystem root"
        )));
    }
    Ok(())
}

fn require_strict_descendant(path: &Path, root: &Path, label: &str) -> Result<()> {
    require_normalized_absolute(path, label)?;
    if path == root || !path.starts_with(root) {
        return Err(LauncherError::new(format!(
            "{label} must be below the configured root"
        )));
    }
    Ok(())
}

fn require_at_or_below(path: &Path, root: &Path, label: &str) -> Result<()> {
    require_normalized_absolute(path, label)?;
    if !path.starts_with(root) {
        return Err(LauncherError::new(format!(
            "{label} must equal or be below the configured root"
        )));
    }
    Ok(())
}

fn validate_python_layout(manifest: &LaunchManifest) -> Result<String> {
    let expected_python = manifest.release_root.join("runtime/python/bin/python3");
    if manifest.python.path != expected_python {
        return Err(LauncherError::new(
            "python must use releaseRoot/runtime/python/bin/python3",
        ));
    }
    if manifest.python.import_roots.len() != 4 {
        return Err(LauncherError::new(
            "python.importRoots must contain exactly four ordered roots",
        ));
    }
    let roots = &manifest.python.import_roots;
    let stdlib = &roots[1].path;
    let expected_stdlib_parent = manifest.release_root.join("runtime/python/lib");
    if stdlib.parent() != Some(expected_stdlib_parent.as_path()) {
        return Err(LauncherError::new(
            "python.importRoots[1] must be the release CPython stdlib",
        ));
    }
    let python_version = stdlib
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| LauncherError::new("python stdlib version is not valid UTF-8"))?;
    let minor = python_version.strip_prefix("python3.").ok_or_else(|| {
        LauncherError::new("python stdlib must use a canonical python3.X directory")
    })?;
    if minor.is_empty()
        || !minor.as_bytes().iter().all(u8::is_ascii_digit)
        || (minor.len() > 1 && minor.starts_with('0'))
    {
        return Err(LauncherError::new(
            "python stdlib must use a canonical python3.X directory",
        ));
    }
    let expected = [
        manifest.release_root.clone(),
        stdlib.clone(),
        stdlib.join("lib-dynload"),
        manifest.release_root.join("vendor"),
    ];
    if roots
        .iter()
        .zip(expected.iter())
        .any(|(record, expected_path)| record.path != *expected_path)
    {
        return Err(LauncherError::new(
            "python.importRoots must be ordered as releaseRoot, stdlib, lib-dynload, vendor",
        ));
    }
    Ok(python_version.to_string())
}

fn elf_range<'a>(data: &'a [u8], offset: usize, size: usize, label: &str) -> Result<&'a [u8]> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| LauncherError::new(format!("python ELF {label} range overflow")))?;
    data.get(offset..end)
        .ok_or_else(|| LauncherError::new(format!("python ELF {label} is out of bounds")))
}

fn elf_u16(data: &[u8], offset: usize, label: &str) -> Result<u16> {
    let bytes: [u8; 2] = elf_range(data, offset, 2, label)?
        .try_into()
        .map_err(|_| LauncherError::new(format!("python ELF {label} is invalid")))?;
    Ok(u16::from_le_bytes(bytes))
}

fn elf_u32(data: &[u8], offset: usize, label: &str) -> Result<u32> {
    let bytes: [u8; 4] = elf_range(data, offset, 4, label)?
        .try_into()
        .map_err(|_| LauncherError::new(format!("python ELF {label} is invalid")))?;
    Ok(u32::from_le_bytes(bytes))
}

fn elf_u64(data: &[u8], offset: usize, label: &str) -> Result<u64> {
    let bytes: [u8; 8] = elf_range(data, offset, 8, label)?
        .try_into()
        .map_err(|_| LauncherError::new(format!("python ELF {label} is invalid")))?;
    Ok(u64::from_le_bytes(bytes))
}

fn elf_usize(data: &[u8], offset: usize, label: &str) -> Result<usize> {
    usize::try_from(elf_u64(data, offset, label)?)
        .map_err(|_| LauncherError::new(format!("python ELF {label} is too large")))
}

#[derive(Clone, Copy)]
struct ElfSection {
    section_type: u32,
    offset: usize,
    size: usize,
    link: usize,
    entry_size: usize,
}

fn elf_c_string<'a>(table: &'a [u8], offset: usize, label: &str) -> Result<&'a [u8]> {
    let tail = table.get(offset..).ok_or_else(|| {
        LauncherError::new(format!("python ELF {label} string offset is invalid"))
    })?;
    let length = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| LauncherError::new(format!("python ELF {label} is not NUL-terminated")))?;
    Ok(&tail[..length])
}

fn compatible_libpython_name(value: &[u8], python_version: &str) -> bool {
    let prefix = format!("lib{python_version}.so");
    if value == prefix.as_bytes() {
        return true;
    }
    let Some(suffix) = value.strip_prefix(format!("{prefix}.").as_bytes()) else {
        return false;
    };
    !suffix.is_empty()
        && suffix
            .split(|byte| *byte == b'.')
            .all(|part| !part.is_empty() && part.iter().all(u8::is_ascii_digit))
}

fn validate_cpython_elf64(data: &[u8], python_version: &str) -> Result<()> {
    // This identifies the measured interpreter. PT_INTERP and recursive
    // non-libpython DSO closure remain an explicit production-host boundary.
    if data.len() < ELF64_HEADER_SIZE || data.get(..4) != Some(b"\x7fELF") {
        return Err(LauncherError::new(
            "python must be an ELF executable, not a script or arbitrary file",
        ));
    }
    if data.get(4..7) != Some(b"\x02\x01\x01") {
        return Err(LauncherError::new(
            "python must use the ELF64 little-endian version-1 format",
        ));
    }
    let elf_type = elf_u16(data, 16, "type")?;
    if !matches!(elf_type, 2 | 3)
        || elf_u16(data, 18, "machine")? != ELF_MACHINE_X86_64
        || elf_u32(data, 20, "version")? != 1
    {
        return Err(LauncherError::new(
            "python must be a Linux x86-64 ELF executable",
        ));
    }
    if usize::from(elf_u16(data, 52, "header size")?) != ELF64_HEADER_SIZE {
        return Err(LauncherError::new("python ELF header size is invalid"));
    }
    let program_offset = elf_usize(data, 32, "program-header offset")?;
    let program_entry_size = usize::from(elf_u16(data, 54, "program-header entry size")?);
    let program_count = usize::from(elf_u16(data, 56, "program-header count")?);
    if program_count == 0 || program_entry_size != ELF64_PROGRAM_HEADER_SIZE {
        return Err(LauncherError::new(
            "python ELF program-header table is invalid",
        ));
    }
    let program_size = program_count
        .checked_mul(program_entry_size)
        .ok_or_else(|| LauncherError::new("python ELF program-header table overflow"))?;
    elf_range(data, program_offset, program_size, "program-header table")?;

    let section_offset = elf_usize(data, 40, "section-header offset")?;
    let section_entry_size = usize::from(elf_u16(data, 58, "section-header entry size")?);
    let section_count = usize::from(elf_u16(data, 60, "section-header count")?);
    if section_count == 0
        || section_count > 4096
        || section_entry_size != ELF64_SECTION_HEADER_SIZE
        || elf_u16(data, 62, "section-name index")? == 0xffff
    {
        return Err(LauncherError::new(
            "python ELF section-header table is unsupported or invalid",
        ));
    }
    let section_table_size = section_count
        .checked_mul(section_entry_size)
        .ok_or_else(|| LauncherError::new("python ELF section-header table overflow"))?;
    elf_range(
        data,
        section_offset,
        section_table_size,
        "section-header table",
    )?;
    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let base = section_offset + index * ELF64_SECTION_HEADER_SIZE;
        let section = ElfSection {
            section_type: elf_u32(data, base + 4, "section type")?,
            offset: elf_usize(data, base + 24, "section offset")?,
            size: elf_usize(data, base + 32, "section size")?,
            link: usize::try_from(elf_u32(data, base + 40, "section link")?)
                .map_err(|_| LauncherError::new("python ELF section link is invalid"))?,
            entry_size: elf_usize(data, base + 56, "section entry size")?,
        };
        elf_range(data, section.offset, section.size, "section")?;
        sections.push(section);
    }

    let linked_strings = |link: usize, label: &str| -> Result<&[u8]> {
        let section = sections.get(link).ok_or_else(|| {
            LauncherError::new(format!("python ELF {label} string-table link is invalid"))
        })?;
        if section.section_type != ELF_SECTION_STRTAB {
            return Err(LauncherError::new(format!(
                "python ELF {label} does not link to a string table"
            )));
        }
        elf_range(data, section.offset, section.size, label)
    };

    let mut has_py_bytes_main = false;
    let mut has_compatible_libpython = false;
    for (index, section) in sections.iter().enumerate() {
        if section.section_type == ELF_SECTION_DYNSYM {
            if section.entry_size != ELF64_SYMBOL_SIZE || section.size % section.entry_size != 0 {
                return Err(LauncherError::new(
                    "python ELF dynamic symbol table is malformed",
                ));
            }
            let strings = linked_strings(section.link, "dynamic symbol")?;
            let symbols = elf_range(data, section.offset, section.size, "dynamic symbol table")?;
            for offset in (0..symbols.len()).step_by(ELF64_SYMBOL_SIZE) {
                let name_offset = usize::try_from(elf_u32(symbols, offset, "dynamic symbol name")?)
                    .map_err(|_| LauncherError::new("python ELF symbol name is invalid"))?;
                if name_offset != 0
                    && elf_c_string(strings, name_offset, "dynamic symbol")? == b"Py_BytesMain"
                {
                    has_py_bytes_main = true;
                }
            }
        } else if section.section_type == ELF_SECTION_DYNAMIC {
            if section.entry_size != ELF64_DYNAMIC_SIZE || section.size % section.entry_size != 0 {
                return Err(LauncherError::new(
                    "python ELF dynamic dependency table is malformed",
                ));
            }
            let strings = linked_strings(section.link, "dynamic dependency")?;
            let dynamic = elf_range(
                data,
                section.offset,
                section.size,
                "dynamic dependency table",
            )?;
            for offset in (0..dynamic.len()).step_by(ELF64_DYNAMIC_SIZE) {
                if elf_u64(dynamic, offset, "dynamic tag")? == ELF_DYNAMIC_NEEDED {
                    let name_offset = elf_usize(dynamic, offset + 8, "DT_NEEDED offset")?;
                    if compatible_libpython_name(
                        elf_c_string(strings, name_offset, "DT_NEEDED")?,
                        python_version,
                    ) {
                        has_compatible_libpython = true;
                    }
                }
            }
        }
        let _ = index;
    }
    if !has_py_bytes_main {
        return Err(LauncherError::new(
            "python ELF does not import the required Py_BytesMain symbol",
        ));
    }
    if !has_compatible_libpython {
        return Err(LauncherError::new(format!(
            "python ELF does not depend on a compatible lib{python_version}.so"
        )));
    }
    Ok(())
}

fn validate_output_path(value: &Path, state_directory: &Path, label: &str) -> Result<()> {
    require_strict_descendant(value, state_directory, label)?;
    if value.parent() != Some(state_directory) {
        return Err(LauncherError::new(format!(
            "{label} must be a direct child of stateDirectory"
        )));
    }
    Ok(())
}

fn all_input_records(inputs: &Inputs) -> [(&'static str, &FileRecord); 18] {
    [
        ("productionImagesBuild", &inputs.production_images_build),
        ("productionImagesEnv", &inputs.production_images_env),
        (
            "productionImagesPublished",
            &inputs.production_images_published,
        ),
        (
            "releaseProvenanceSummary",
            &inputs.release_provenance_summary,
        ),
        ("releaseProvenance", &inputs.release_provenance),
        ("imageSignaturesSummary", &inputs.image_signatures_summary),
        ("imageSignatures", &inputs.image_signatures),
        ("bench", &inputs.bench),
        ("kmsMaterials", &inputs.kms_materials),
        ("policyBundle", &inputs.policy_bundle),
        ("policyTrustedPublicKey", &inputs.policy_trusted_public_key),
        (
            "policyIdentityVerification",
            &inputs.policy_identity_verification,
        ),
        (
            "policyActivationVerification",
            &inputs.policy_activation_verification,
        ),
        (
            "policyActivationSignature",
            &inputs.policy_activation_signature,
        ),
        (
            "policyActivationTrustedPublicKey",
            &inputs.policy_activation_trusted_public_key,
        ),
        (
            "reproducibleBuildVerification",
            &inputs.reproducible_build_verification,
        ),
        (
            "reproducibleBuildSignature",
            &inputs.reproducible_build_signature,
        ),
        (
            "reproducibleBuildTrustedPublicKey",
            &inputs.reproducible_build_trusted_public_key,
        ),
    ]
}

fn canonical_ed25519_spki_sha256(value: &str, label: &str) -> Result<String> {
    if value.is_empty() || value.contains('=') {
        return Err(LauncherError::new(format!(
            "{label} must be canonical unpadded base64url"
        )));
    }
    let decoded = general_purpose::URL_SAFE_NO_PAD.decode(value).map_err(|_| {
        LauncherError::new(format!("{label} must be canonical unpadded base64url"))
    })?;
    if decoded.len() != ED25519_SPKI_PREFIX.len() + 32
        || decoded[..ED25519_SPKI_PREFIX.len()] != ED25519_SPKI_PREFIX
        || general_purpose::URL_SAFE_NO_PAD.encode(&decoded) != value
    {
        return Err(LauncherError::new(format!(
            "{label} must contain one canonical Ed25519 SPKI DER key"
        )));
    }
    Ok(sha256_prefixed(&decoded))
}

fn parse_ed25519_spki(value: &str, label: &str) -> Result<VerifyingKey> {
    let key_id = canonical_ed25519_spki_sha256(value, label)?;
    let decoded = general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| LauncherError::new(format!("{label} is invalid")))?;
    let bytes: [u8; 32] = decoded[ED25519_SPKI_PREFIX.len()..]
        .try_into()
        .map_err(|_| LauncherError::new(format!("{label} is invalid")))?;
    let key = VerifyingKey::from_bytes(&bytes)
        .map_err(|_| LauncherError::new(format!("{label} is invalid")))?;
    if launch_authority_key_id(&key) != key_id {
        return Err(LauncherError::new(format!(
            "{label} does not have a stable key identity"
        )));
    }
    Ok(key)
}

fn is_production_nonce_assurance_profile(
    assurance: &NonceAuthorityAssurance,
    rollback: &NonceRollbackProtection,
) -> bool {
    matches!(
        (
            assurance.assurance_evidence_type.as_str(),
            assurance.backend_class.as_str(),
            rollback.key_protection.as_str(),
            rollback.mechanism.as_str(),
            rollback.state_commitment.as_str(),
            rollback.verifier_state_store_class.as_str(),
        ),
        (
            "hardwareMonotonicCounterAttestation",
            "hardwareMonotonicCounter",
            "nonExportableHsm",
            "hardwareMonotonicCounter",
            "monotonicCounterCommitment",
            "hardwareProtectedStateStore",
        ) | (
            "linearizableCasOperatorAttestation",
            "independentlyAdministeredLinearizableCas",
            "nonExportableKmsHsm",
            "linearizableCasWithRollbackProtectedStorage",
            "hashChainedLinearizableCommitment",
            "independentlyAdministeredLinearizableCas",
        ) | (
            "transparencyLedgerOperatorAttestation",
            "appendOnlyTransparencyLedger",
            "nonExportableKmsHsm",
            "appendOnlyWitnessedLedger",
            "appendOnlyMerkleCommitment",
            "independentlyAdministeredLinearizableCas",
        )
    )
}

fn validate_nonce_rollback_assurance(
    binding: &NonceRollbackAssuranceBinding,
) -> Result<()> {
    if binding.api_version != NONCE_ROLLBACK_ASSURANCE_BINDING_API_VERSION
        || binding.canonical_profile != CANONICAL_JSON_PROFILE
        || binding.enforcement != "native-launcher-measured"
        || binding.purpose != "readiness-only"
        || binding.contract.api_version != NONCE_ROLLBACK_ASSURANCE_PINS_API_VERSION
    {
        return Err(LauncherError::new(
            "nonceRollbackAssurance does not use the enforced readiness contract",
        ));
    }
    require_strict_descendant(
        &binding.pins_file.path,
        Path::new("/etc/serverware"),
        "nonceRollbackAssurance.pinsFile.path",
    )?;
    require_sha256(
        &binding.pins_file.sha256,
        "nonceRollbackAssurance.pinsFile.sha256",
    )?;
    require_sha256(
        &binding.contract_sha256,
        "nonceRollbackAssurance.contractSha256",
    )?;
    let contract_bytes = canonical_json_bytes(&binding.contract)?;
    if sha256_prefixed(&contract_bytes) != binding.contract_sha256 {
        return Err(LauncherError::new(
            "nonceRollbackAssurance contract digest does not match canonical bytes",
        ));
    }

    let independent = &binding.contract.independent_verifier_pins;
    let public = &binding.contract.public_config_pins;
    let assurance = &public.nonce_authority_assurance;
    let rollback = &assurance.rollback_protection;
    for (value, label) in [
        (
            independent
                .expected_nonce_authority_assurance_issuer_spki_sha256
                .as_str(),
            "expected nonce authority assurance issuer key",
        ),
        (
            independent
                .expected_nonce_authority_assurance_sha256
                .as_str(),
            "expected nonce authority assurance",
        ),
        (
            public.nonce_authority_assurance_sha256.as_str(),
            "nonce authority assurance",
        ),
        (
            public
                .nonce_authority_verifier_state_store_administrative_domain_sha256
                .as_str(),
            "nonce authority verifier-state store administrative domain",
        ),
        (
            public
                .nonce_authority_verifier_state_store_assurance_evidence_sha256
                .as_str(),
            "nonce authority verifier-state store assurance evidence",
        ),
        (
            public
                .nonce_authority_verifier_state_store_identity_sha256
                .as_str(),
            "nonce authority verifier-state store identity",
        ),
        (
            assurance.administrative_domain_sha256.as_str(),
            "nonce authority administrative domain",
        ),
        (
            assurance.assurance_evidence_sha256.as_str(),
            "nonce authority assurance evidence",
        ),
        (
            assurance.authority_identity_sha256.as_str(),
            "nonce authority identity",
        ),
    ] {
        require_sha256(value, label)?;
    }
    let assurance_sha256 = sha256_prefixed(&canonical_json_bytes(assurance)?);
    if public.nonce_authority_assurance_sha256 != assurance_sha256
        || independent.expected_nonce_authority_assurance_sha256 != assurance_sha256
    {
        return Err(LauncherError::new(
            "nonce authority assurance canonical digest is not independently pinned",
        ));
    }
    let evidence_key_id = canonical_ed25519_spki_sha256(
        &public.nonce_authority_assurance_evidence_signing_public_key_spki_der_base64url,
        "nonce authority assurance evidence key",
    )?;
    let verifier_state_key_id = canonical_ed25519_spki_sha256(
        &public.nonce_authority_verifier_state_signing_public_key_spki_der_base64url,
        "nonce authority verifier-state key",
    )?;
    let verifier_state_store_attestation_key_id = canonical_ed25519_spki_sha256(
        &public
            .nonce_authority_verifier_state_store_attestation_public_key_spki_der_base64url,
        "nonce authority verifier-state store attestation key",
    )?;
    if independent.expected_nonce_authority_assurance_issuer_spki_sha256 != evidence_key_id
        || BTreeSet::from([
            evidence_key_id.as_str(),
            verifier_state_key_id.as_str(),
            verifier_state_store_attestation_key_id.as_str(),
        ])
        .len()
            != 3
    {
        return Err(LauncherError::new(
            "nonce rollback assurance signing roles are not independently pinned and separated",
        ));
    }
    let separated_identities = BTreeSet::from([
        assurance.administrative_domain_sha256.as_str(),
        assurance.authority_identity_sha256.as_str(),
        public
            .nonce_authority_verifier_state_store_administrative_domain_sha256
            .as_str(),
        public
            .nonce_authority_verifier_state_store_identity_sha256
            .as_str(),
        evidence_key_id.as_str(),
        verifier_state_key_id.as_str(),
        verifier_state_store_attestation_key_id.as_str(),
    ]);
    if separated_identities.len() != 7 {
        return Err(LauncherError::new(
            "nonce rollback assurance key, service, store, and administrative roles must be pairwise distinct",
        ));
    }
    if public.nonce_authority_verifier_state_store_assurance_evidence_sha256
        == assurance.assurance_evidence_sha256
    {
        return Err(LauncherError::new(
            "nonce authority and verifier-state store assurance evidence must be independently pinned",
        ));
    }
    if assurance.api_version != NONCE_AUTHORITY_ASSURANCE_API_VERSION
        || assurance.assurance_level != "productionRollbackProtected"
        || !assurance.production_eligible
        || require_json_safe_integer(
            assurance.authority_epoch,
            "nonce authority assurance authorityEpoch",
            false,
        )
        .is_err()
        || require_json_safe_integer(
            assurance.authority_generation,
            "nonce authority assurance authorityGeneration",
            false,
        )
        .is_err()
        || !rollback.administrative_rollback_resistance
        || !rollback.backend_attestation_required
        || !rollback.exact_successor_required
        || !rollback.fresh_verifier_challenge_required
        || !is_production_nonce_assurance_profile(assurance, rollback)
    {
        return Err(LauncherError::new(
            "nonce rollback assurance is not a complete production rollback profile",
        ));
    }
    Ok(())
}

fn validate_launch_authority_witness_store_assurance(
    witness: &LaunchAuthorityWitnessConfiguration,
    authority_key_id: &str,
) -> Result<()> {
    let envelope = &witness.store_assurance;
    let statement = &envelope.statement;
    if envelope.api_version != WITNESS_STORE_ASSURANCE_API_VERSION
        || envelope.kind != WITNESS_STORE_ASSURANCE_KIND
        || statement.witness_key_id != witness.signing_key_id
        || statement.witness_identity_sha256 != witness.identity_sha256
        || statement.witness_administrative_domain_sha256
            != witness.administrative_domain_sha256
        || statement.assurance_issuer_key_id
            != witness.store_assurance_issuer_key_id
        || statement.rollback_resistance != "externally-witnessed-monotonic"
        || !statement.independent_administration
        || !matches!(
            statement.store_class.as_str(),
            "hardwareMonotonicCounter"
                | "independentlyAdministeredLinearizableCas"
                | "appendOnlyTransparencyLedger"
        )
    {
        return Err(LauncherError::new(
            "launch-authority witness store assurance does not bind an independently administered rollback-resistant store",
        ));
    }
    for (value, label) in [
        (
            statement.assurance_issuer_key_id.as_str(),
            "authorization.monotonicWitness.storeAssurance.statement.assuranceIssuerKeyId",
        ),
        (
            statement.witness_key_id.as_str(),
            "authorization.monotonicWitness.storeAssurance.statement.witnessKeyId",
        ),
        (
            statement.witness_identity_sha256.as_str(),
            "authorization.monotonicWitness.storeAssurance.statement.witnessIdentitySha256",
        ),
        (
            statement.witness_administrative_domain_sha256.as_str(),
            "authorization.monotonicWitness.storeAssurance.statement.witnessAdministrativeDomainSha256",
        ),
        (
            statement.store_identity_sha256.as_str(),
            "authorization.monotonicWitness.storeAssurance.statement.storeIdentitySha256",
        ),
        (
            statement.store_administrative_domain_sha256.as_str(),
            "authorization.monotonicWitness.storeAssurance.statement.storeAdministrativeDomainSha256",
        ),
    ] {
        require_sha256(value, label)?;
    }
    let issuer_key_id = canonical_ed25519_spki_sha256(
        &witness.store_assurance_issuer_public_key_spki_der_base64url,
        "authorization.monotonicWitness.storeAssuranceIssuerPublicKeySpkiDerBase64url",
    )?;
    if issuer_key_id != witness.store_assurance_issuer_key_id {
        return Err(LauncherError::new(
            "launch-authority witness store assurance issuer key is not independently pinned",
        ));
    }
    require_pairwise_distinct_independent_administration_bindings([
        authority_key_id,
        witness.signing_key_id.as_str(),
        statement.witness_identity_sha256.as_str(),
        statement.witness_administrative_domain_sha256.as_str(),
        statement.store_identity_sha256.as_str(),
        statement.store_administrative_domain_sha256.as_str(),
        issuer_key_id.as_str(),
    ])?;
    let assurance_sha256 =
        sha256_prefixed(&canonical_json_bytes(&witness.store_assurance)?);
    if assurance_sha256 != witness.store_assurance_sha256 {
        return Err(LauncherError::new(
            "launch-authority witness store assurance digest does not match its exact envelope",
        ));
    }
    let issuer_key = parse_ed25519_spki(
        &witness.store_assurance_issuer_public_key_spki_der_base64url,
        "launch-authority witness store assurance issuer key",
    )?;
    issuer_key
        .verify_strict(
            &witness_store_assurance_signing_bytes(envelope)?,
            &decode_signature(
                &envelope.signature,
                "launch-authority witness store assurance signature",
            )?,
        )
        .map_err(|_| {
            LauncherError::new(
                "launch-authority witness store assurance signature verification failed",
            )
        })
}

fn require_pairwise_distinct_independent_administration_bindings(
    values: [&str; 7],
) -> Result<()> {
    let mut owners = BTreeMap::new();
    for (label, value) in INDEPENDENT_ADMINISTRATION_BINDING_LABELS
        .into_iter()
        .zip(values)
    {
        require_sha256(value, label)?;
        if let Some(previous) = owners.insert(value, label) {
            return Err(LauncherError::new(format!(
                "independentAdministration requires pairwise-distinct authority, witness, and witness-store bindings: {previous} collides with {label}"
            )));
        }
    }
    Ok(())
}

fn validate_launch_attempt_journal(
    configuration: &LaunchAttemptJournalConfiguration,
    state_directory: &Path,
) -> Result<()> {
    if configuration.api_version != ATTEMPT_JOURNAL_API_VERSION
        || configuration.domain != ATTEMPT_JOURNAL_DOMAIN
        || configuration.max_bytes != MAX_ATTEMPT_JOURNAL_BYTES
        || configuration.consistency_scope != ATTEMPT_JOURNAL_CONSISTENCY_SCOPE
        || configuration.rollback_authority != ATTEMPT_JOURNAL_ROLLBACK_AUTHORITY
    {
        return Err(LauncherError::new(
            "launchAttemptJournal does not match the closed host-consistency contract",
        ));
    }
    validate_output_path(
        &configuration.path,
        state_directory,
        "launchAttemptJournal.path",
    )?;
    validate_output_path(
        &configuration.lock_path,
        state_directory,
        "launchAttemptJournal.lockPath",
    )?;
    let expected_path = state_directory.join(ATTEMPT_JOURNAL_FILE_NAME);
    let expected_lock_path =
        state_directory.join(ATTEMPT_JOURNAL_LOCK_FILE_NAME);
    if configuration.path != expected_path
        || configuration.lock_path != expected_lock_path
    {
        return Err(LauncherError::new(
            "launchAttemptJournal path and lockPath must be the fixed v1 children of stateDirectory",
        ));
    }
    Ok(())
}

fn validate_global_role_registry(
    binding: &GlobalRoleRegistryBinding,
    authority_key_id: &str,
    witness: &LaunchAuthorityWitnessConfiguration,
    nonce: &NonceRollbackAssuranceBinding,
) -> Result<()> {
    if binding.api_version != GLOBAL_ROLE_REGISTRY_BINDING_API_VERSION
        || binding.canonical_profile != CANONICAL_JSON_PROFILE
        || binding.claim_scope != GLOBAL_ROLE_REGISTRY_CLAIM_SCOPE
        || binding.registry.api_version != GLOBAL_ROLE_REGISTRY_API_VERSION
        || binding.registry.claim_scope != GLOBAL_ROLE_REGISTRY_CLAIM_SCOPE
        || binding.registry.roles_outside_claim
            != GLOBAL_ROLES_OUTSIDE_CLAIM
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
    {
        return Err(LauncherError::new(
            "globalRoleRegistry does not match the closed launch-role contract",
        ));
    }
    let expected_roles = GLOBAL_ROLE_NAMES
        .into_iter()
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    let actual_roles = binding
        .registry
        .roles
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    if actual_roles != expected_roles {
        return Err(LauncherError::new(
            "globalRoleRegistry omitted, added, or claimed an unsupported role",
        ));
    }
    let mut unique_key_ids = BTreeSet::new();
    for (role, key_id) in &binding.registry.roles {
        require_sha256(key_id, &format!("globalRoleRegistry.roles.{role}"))?;
        if !unique_key_ids.insert(key_id.as_str()) {
            return Err(LauncherError::new(
                "globalRoleRegistry reused an SPKI across launch roles",
            ));
        }
    }
    let public = &nonce.contract.public_config_pins;
    let derived_roles = BTreeMap::from([
        ("launchAuthority", authority_key_id.to_string()),
        (
            "launchAuthorityWitness",
            witness.signing_key_id.clone(),
        ),
        (
            "launchAuthorityWitnessStoreAssurance",
            witness.store_assurance_issuer_key_id.clone(),
        ),
        (
            "nonceAuthorityAssuranceEvidence",
            canonical_ed25519_spki_sha256(
                &public
                    .nonce_authority_assurance_evidence_signing_public_key_spki_der_base64url,
                "nonce authority assurance-evidence role",
            )?,
        ),
        (
            "nonceAuthorityVerifierState",
            canonical_ed25519_spki_sha256(
                &public
                    .nonce_authority_verifier_state_signing_public_key_spki_der_base64url,
                "nonce authority verifier-state role",
            )?,
        ),
        (
            "nonceAuthorityVerifierStateStoreAttestation",
            canonical_ed25519_spki_sha256(
                &public
                    .nonce_authority_verifier_state_store_attestation_public_key_spki_der_base64url,
                "nonce authority verifier-state store-attestation role",
            )?,
        ),
    ]);
    // launchAuthorityWitnessTls has no raw native-manifest input. The launch
    // authority independently cross-binds that registry role to its TLS pin.
    for (role, expected_key_id) in derived_roles {
        if binding.registry.roles.get(role) != Some(&expected_key_id) {
            return Err(LauncherError::new(format!(
                "globalRoleRegistry {role} does not match its independently supplied SPKI"
            )));
        }
    }
    let registry_sha256 = global_role_registry_sha256(&binding.registry)?;
    if registry_sha256 != binding.registry_sha256 {
        return Err(LauncherError::new(
            "globalRoleRegistry digest does not match its canonical registry",
        ));
    }
    require_strict_descendant(
        &binding.pins_file.path,
        Path::new("/etc/serverware"),
        "globalRoleRegistry.pinsFile.path",
    )?;
    require_sha256(
        &binding.pins_file.sha256,
        "globalRoleRegistry.pinsFile.sha256",
    )
}

fn validate_manifest_path_encoding(manifest: &LaunchManifest) -> Result<()> {
    require_safe_ascii_path(&manifest.release_root, "releaseRoot")?;
    require_safe_ascii_path(&manifest.state_directory, "stateDirectory")?;
    require_safe_ascii_path(
        &manifest.launch_attempt_journal.path,
        "launchAttemptJournal.path",
    )?;
    require_safe_ascii_path(
        &manifest.launch_attempt_journal.lock_path,
        "launchAttemptJournal.lockPath",
    )?;
    require_safe_ascii_path(
        &manifest.global_role_registry.pins_file.path,
        "globalRoleRegistry.pinsFile.path",
    )?;
    require_safe_ascii_path(
        &manifest.nonce_rollback_assurance.pins_file.path,
        "nonceRollbackAssurance.pinsFile.path",
    )?;
    require_safe_ascii_path(&manifest.production_env.path, "productionEnv.path")?;
    require_safe_ascii_path(&manifest.python.path, "python.path")?;
    for (index, root) in manifest.python.import_roots.iter().enumerate() {
        require_safe_ascii_path(
            &root.path,
            &format!("python.importRoots[{index}].path"),
        )?;
    }
    require_safe_ascii_path(
        &manifest.scripts.preflight.path,
        "scripts.preflight.path",
    )?;
    require_safe_ascii_path(&manifest.scripts.runner.path, "scripts.runner.path")?;
    require_safe_ascii_path(&manifest.compose_file.path, "composeFile.path")?;
    for (name, record) in all_input_records(&manifest.inputs) {
        require_safe_ascii_path(&record.path, &format!("inputs.{name}.path"))?;
    }
    for (label, path) in [
        ("outputs.configOut", &manifest.outputs.config_out),
        ("outputs.claimsFile", &manifest.outputs.claims_file),
        (
            "outputs.nitroEvidenceOut",
            &manifest.outputs.nitro_evidence_out,
        ),
        ("outputs.readinessOut", &manifest.outputs.readiness_out),
        (
            "outputs.completionProofOut",
            &manifest.outputs.completion_proof_out,
        ),
        (
            "outputs.proxyProofSummaryOut",
            &manifest.outputs.proxy_proof_summary_out,
        ),
        (
            "outputs.productionHostPreflight",
            &manifest.outputs.production_host_preflight,
        ),
    ] {
        require_safe_ascii_path(path, label)?;
    }
    Ok(())
}

fn validate_manifest(manifest: &LaunchManifest) -> Result<()> {
    validate_manifest_path_encoding(manifest)?;
    if manifest.api_version != LAUNCH_MANIFEST_API_VERSION {
        return Err(LauncherError::new("unsupported launch manifest apiVersion"));
    }
    if manifest.kind != LAUNCH_MANIFEST_KIND {
        return Err(LauncherError::new("unsupported launch manifest kind"));
    }
    require_normalized_absolute(&manifest.release_root, "releaseRoot")?;
    require_normalized_absolute(&manifest.state_directory, "stateDirectory")?;
    if manifest.state_directory != Path::new(PRODUCTION_STATE_DIRECTORY) {
        return Err(LauncherError::new(
            "stateDirectory must be the compiled production state directory",
        ));
    }
    if manifest.release_root.starts_with(&manifest.state_directory)
        || manifest.state_directory.starts_with(&manifest.release_root)
    {
        return Err(LauncherError::new(
            "releaseRoot and stateDirectory must not overlap",
        ));
    }
    require_sha256(&manifest.source_tree_digest, "sourceTreeDigest")?;
    require_deployment_audience(&manifest.authorization.deployment_audience)?;
    require_sha256(
        &manifest.authorization.deployment_identity_sha256,
        "authorization.deploymentIdentitySha256",
    )?;
    if manifest.authorization.authorization_scope != AUTHORIZATION_SCOPE
        || manifest.authorization.freshness_authority != FRESHNESS_AUTHORITY
    {
        return Err(LauncherError::new(
            "authorization must be scoped to trusted-host readiness and trusted-host wall-clock freshness",
        ));
    }
    let witness = &manifest.authorization.monotonic_witness;
    let witness_key_id = canonical_ed25519_spki_sha256(
        &witness.signing_public_key_spki_der_base64url,
        "authorization.monotonicWitness.signingPublicKeySpkiDerBase64url",
    )?;
    for (value, label) in [
        (
            witness.signing_key_id.as_str(),
            "authorization.monotonicWitness.signingKeyId",
        ),
        (
            witness.identity_sha256.as_str(),
            "authorization.monotonicWitness.identitySha256",
        ),
        (
            witness.administrative_domain_sha256.as_str(),
            "authorization.monotonicWitness.administrativeDomainSha256",
        ),
        (
            witness.store_assurance_sha256.as_str(),
            "authorization.monotonicWitness.storeAssuranceSha256",
        ),
    ] {
        require_sha256(value, label)?;
    }
    let authority_key_id = launch_authority_key_id(&compiled_authority_public_key()?);
    if witness_key_id != witness.signing_key_id
        || witness.identity_sha256 == witness.store_assurance_sha256
        || witness.administrative_domain_sha256 == witness.store_assurance_sha256
    {
        return Err(LauncherError::new(
            "launch-authority witness key, identity, administrative domain, and store assurance are not independently pinned",
        ));
    }
    validate_launch_authority_witness_store_assurance(
        witness,
        &authority_key_id,
    )?;
    require_json_safe_integer(
        manifest.authorization.release_sequence,
        "authorization.releaseSequence",
        false,
    )?;
    require_json_safe_integer(
        manifest.authorization.rollback_epoch,
        "authorization.rollbackEpoch",
        true,
    )?;
    validate_nonce_rollback_assurance(&manifest.nonce_rollback_assurance)?;
    validate_launch_attempt_journal(
        &manifest.launch_attempt_journal,
        &manifest.state_directory,
    )?;
    validate_global_role_registry(
        &manifest.global_role_registry,
        &authority_key_id,
        witness,
        &manifest.nonce_rollback_assurance,
    )?;

    require_strict_descendant(
        &manifest.production_env.path,
        Path::new("/etc/serverware"),
        "productionEnv.path",
    )?;
    require_sha256(&manifest.production_env.sha256, "productionEnv.sha256")?;

    for (label, record) in [
        (
            "python",
            &FileRecord {
                path: manifest.python.path.clone(),
                sha256: manifest.python.sha256.clone(),
            },
        ),
        ("scripts.preflight", &manifest.scripts.preflight),
        ("scripts.runner", &manifest.scripts.runner),
        ("composeFile", &manifest.compose_file),
    ] {
        require_strict_descendant(&record.path, &manifest.release_root, label)?;
        require_sha256(&record.sha256, &format!("{label}.sha256"))?;
    }

    validate_python_layout(manifest)?;
    for (index, root) in manifest.python.import_roots.iter().enumerate() {
        let label = format!("python.importRoots[{index}]");
        require_at_or_below(&root.path, &manifest.release_root, &label)?;
        require_sha256(&root.sha256, &format!("{label}.sha256"))?;
    }

    let mut immutable_paths = BTreeSet::new();
    for (label, path) in [
        ("productionEnv", &manifest.production_env.path),
        (
            "nonceRollbackAssurance.pinsFile",
            &manifest.nonce_rollback_assurance.pins_file.path,
        ),
        (
            "globalRoleRegistry.pinsFile",
            &manifest.global_role_registry.pins_file.path,
        ),
        ("python", &manifest.python.path),
        ("scripts.preflight", &manifest.scripts.preflight.path),
        ("scripts.runner", &manifest.scripts.runner.path),
        ("composeFile", &manifest.compose_file.path),
    ] {
        if !immutable_paths.insert(path.clone()) {
            return Err(LauncherError::new(format!(
                "immutable path is duplicated at {label}"
            )));
        }
    }
    for (label, path) in [
        (
            "launchAttemptJournal.path",
            &manifest.launch_attempt_journal.path,
        ),
        (
            "launchAttemptJournal.lockPath",
            &manifest.launch_attempt_journal.lock_path,
        ),
    ] {
        if immutable_paths.contains(path) {
            return Err(LauncherError::new(format!(
                "{label} collides with an immutable measured path"
            )));
        }
    }
    for (index, root) in manifest.python.import_roots.iter().enumerate() {
        if !immutable_paths.insert(root.path.clone()) {
            return Err(LauncherError::new(format!(
                "immutable path is duplicated at python.importRoots[{index}]"
            )));
        }
    }
    for (label, record) in all_input_records(&manifest.inputs) {
        require_strict_descendant(&record.path, &manifest.release_root, label)?;
        require_sha256(&record.sha256, &format!("{label}.sha256"))?;
        if !immutable_paths.insert(record.path.clone()) {
            return Err(LauncherError::new(format!(
                "immutable input path is duplicated at {label}"
            )));
        }
    }

    let output_values = [
        ("outputs.configOut", &manifest.outputs.config_out),
        ("outputs.claimsFile", &manifest.outputs.claims_file),
        (
            "outputs.nitroEvidenceOut",
            &manifest.outputs.nitro_evidence_out,
        ),
        ("outputs.readinessOut", &manifest.outputs.readiness_out),
        (
            "outputs.completionProofOut",
            &manifest.outputs.completion_proof_out,
        ),
        (
            "outputs.proxyProofSummaryOut",
            &manifest.outputs.proxy_proof_summary_out,
        ),
        (
            "outputs.productionHostPreflight",
            &manifest.outputs.production_host_preflight,
        ),
    ];
    let mut output_names = BTreeSet::new();
    for (label, value) in output_values {
        validate_output_path(value, &manifest.state_directory, label)?;
        if immutable_paths.contains(value) {
            return Err(LauncherError::new(format!(
                "{label} collides with an immutable measured path"
            )));
        }
        if !output_names.insert(value) {
            return Err(LauncherError::new("output paths must be unique"));
        }
        if value == &manifest.launch_attempt_journal.path
            || value == &manifest.launch_attempt_journal.lock_path
        {
            return Err(LauncherError::new(format!(
                "{label} collides with launchAttemptJournal state"
            )));
        }
    }
    Ok(())
}

fn push_option(argv: &mut Vec<String>, name: &str, value: &Path) {
    argv.push(name.to_string());
    argv.push(value.to_string_lossy().into_owned());
}

fn push_nonce_rollback_assurance(
    argv: &mut Vec<String>,
    manifest: &LaunchManifest,
    retained_snapshot_fd: i32,
) {
    argv.extend([
        "--launcher-nonce-rollback-assurance-pins".to_string(),
        format!("/proc/self/fd/{retained_snapshot_fd}"),
        "--launcher-nonce-rollback-assurance-pins-sha256".to_string(),
        manifest
            .nonce_rollback_assurance
            .pins_file
            .sha256
            .clone(),
        "--launcher-nonce-rollback-assurance-contract-sha256".to_string(),
        manifest
            .nonce_rollback_assurance
            .contract_sha256
            .clone(),
    ]);
}

fn push_common_inputs(argv: &mut Vec<String>, manifest: &LaunchManifest) {
    let pairs = [
        (
            "--production-images-build",
            &manifest.inputs.production_images_build.path,
        ),
        (
            "--production-images-env",
            &manifest.inputs.production_images_env.path,
        ),
        (
            "--production-images-published",
            &manifest.inputs.production_images_published.path,
        ),
        (
            "--release-provenance-summary",
            &manifest.inputs.release_provenance_summary.path,
        ),
        (
            "--release-provenance",
            &manifest.inputs.release_provenance.path,
        ),
        (
            "--image-signatures-summary",
            &manifest.inputs.image_signatures_summary.path,
        ),
        ("--image-signatures", &manifest.inputs.image_signatures.path),
        ("--bench", &manifest.inputs.bench.path),
        ("--kms-materials", &manifest.inputs.kms_materials.path),
        ("--policy-bundle", &manifest.inputs.policy_bundle.path),
        (
            "--policy-trusted-public-key",
            &manifest.inputs.policy_trusted_public_key.path,
        ),
        (
            "--policy-identity-verification",
            &manifest.inputs.policy_identity_verification.path,
        ),
        (
            "--policy-activation-verification",
            &manifest.inputs.policy_activation_verification.path,
        ),
        (
            "--policy-activation-signature",
            &manifest.inputs.policy_activation_signature.path,
        ),
        (
            "--policy-activation-trusted-public-key",
            &manifest.inputs.policy_activation_trusted_public_key.path,
        ),
        (
            "--reproducible-build-verification",
            &manifest.inputs.reproducible_build_verification.path,
        ),
        (
            "--reproducible-build-signature",
            &manifest.inputs.reproducible_build_signature.path,
        ),
        (
            "--reproducible-build-trusted-public-key",
            &manifest.inputs.reproducible_build_trusted_public_key.path,
        ),
    ];
    for (name, path) in pairs {
        push_option(argv, name, path);
    }
}

fn build_preflight_argv(
    manifest: &LaunchManifest,
    retained_nonce_rollback_assurance_fd: i32,
) -> Vec<String> {
    let mut argv = vec![manifest
        .scripts
        .preflight
        .path
        .to_string_lossy()
        .into_owned()];
    push_option(&mut argv, "--env-file", &manifest.production_env.path);
    push_option(
        &mut argv,
        "--launcher-trusted-production-env-path",
        &manifest.production_env.path,
    );
    argv.push("--launcher-trusted-production-env-sha256".to_string());
    argv.push(manifest.production_env.sha256.clone());
    push_nonce_rollback_assurance(
        &mut argv,
        manifest,
        retained_nonce_rollback_assurance_fd,
    );
    push_option(&mut argv, "--compose-file", &manifest.compose_file.path);
    push_common_inputs(&mut argv, manifest);
    argv.extend([
        "--expected-control-plane-uid".to_string(),
        EXPECTED_CONTROL_PLANE_ID.to_string(),
        "--expected-control-plane-gid".to_string(),
        EXPECTED_CONTROL_PLANE_ID.to_string(),
        "--config-out".to_string(),
        manifest.outputs.config_out.to_string_lossy().into_owned(),
        "--out".to_string(),
        manifest
            .outputs
            .production_host_preflight
            .to_string_lossy()
            .into_owned(),
    ]);
    argv
}

fn build_readiness_argv(
    manifest: &LaunchManifest,
    retained_nonce_rollback_assurance_fd: i32,
) -> Vec<String> {
    let mut argv = vec![manifest.scripts.runner.path.to_string_lossy().into_owned()];
    push_option(&mut argv, "--env-file", &manifest.production_env.path);
    push_option(
        &mut argv,
        "--launcher-trusted-production-env-path",
        &manifest.production_env.path,
    );
    argv.push("--launcher-trusted-production-env-sha256".to_string());
    argv.push(manifest.production_env.sha256.clone());
    push_nonce_rollback_assurance(
        &mut argv,
        manifest,
        retained_nonce_rollback_assurance_fd,
    );
    push_option(&mut argv, "--python", &manifest.python.path);
    push_option(&mut argv, "--compose-file", &manifest.compose_file.path);
    argv.extend([
        "--verification-mode".to_string(),
        "readiness".to_string(),
        "--expected-control-plane-uid".to_string(),
        EXPECTED_CONTROL_PLANE_ID.to_string(),
        "--expected-control-plane-gid".to_string(),
        EXPECTED_CONTROL_PLANE_ID.to_string(),
    ]);
    push_common_inputs(&mut argv, manifest);
    argv.extend([
        "--config-out".to_string(),
        manifest.outputs.config_out.to_string_lossy().into_owned(),
        "--claims-file".to_string(),
        manifest.outputs.claims_file.to_string_lossy().into_owned(),
        "--nitro-evidence-out".to_string(),
        manifest
            .outputs
            .nitro_evidence_out
            .to_string_lossy()
            .into_owned(),
        "--readiness-out".to_string(),
        manifest
            .outputs
            .readiness_out
            .to_string_lossy()
            .into_owned(),
        "--completion-proof-out".to_string(),
        manifest
            .outputs
            .completion_proof_out
            .to_string_lossy()
            .into_owned(),
        "--production-host-preflight".to_string(),
        manifest
            .outputs
            .production_host_preflight
            .to_string_lossy()
            .into_owned(),
        "--proxy-proof-summary-out".to_string(),
        manifest
            .outputs
            .proxy_proof_summary_out
            .to_string_lossy()
            .into_owned(),
    ]);
    argv
}

fn fixed_environment(receipt_sha256: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("LANG".to_string(), "C.UTF-8".to_string()),
        ("LC_ALL".to_string(), "C.UTF-8".to_string()),
        (
            "PATH".to_string(),
            "/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
        ),
        ("TZ".to_string(), "UTC".to_string()),
        (
            "SERVERWARE_BOOTSTRAP_RECEIPT_API_VERSION".to_string(),
            RECEIPT_API_VERSION.to_string(),
        ),
        (
            "SERVERWARE_BOOTSTRAP_RECEIPT_FD".to_string(),
            RECEIPT_FD.to_string(),
        ),
        (
            "SERVERWARE_BOOTSTRAP_RECEIPT_SHA256".to_string(),
            receipt_sha256.to_string(),
        ),
        (
            "SERVERWARE_LAUNCHER_IMPORT_MODE".to_string(),
            "retained-fd-only".to_string(),
        ),
    ])
}

fn environment_commitment() -> Result<ReceiptEnvironment> {
    let environment = fixed_environment(RECEIPT_SHA256_PLACEHOLDER);
    let names = environment.keys().cloned().collect::<Vec<_>>();
    let bytes = canonical_json_bytes(&environment)?;
    Ok(ReceiptEnvironment {
        names,
        sha256: sha256_prefixed(&bytes),
    })
}

fn argv_digest(argv: &[String]) -> Result<String> {
    Ok(sha256_prefixed(&canonical_json_bytes(argv)?))
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn sort_json(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut entries = object.into_iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            let mut sorted = Map::new();
            for (key, value) in entries {
                sorted.insert(key, sort_json(value));
            }
            Value::Object(sorted)
        }
        Value::Array(values) => Value::Array(values.into_iter().map(sort_json).collect()),
        other => other,
    }
}

fn canonical_json_bytes<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value)
        .map_err(|_| LauncherError::new("could not construct canonical JSON value"))?;
    serde_json::to_vec(&sort_json(value))
        .map_err(|_| LauncherError::new("could not serialize canonical JSON"))
}

#[derive(Serialize)]
struct LaunchAuthorizationSignedValue<'a> {
    #[serde(rename = "apiVersion")]
    api_version: &'a str,
    kind: &'a str,
    statement: &'a LaunchAuthorizationStatement,
}

#[derive(Serialize)]
struct LaunchAuthorityWitnessSignedValue<'a> {
    #[serde(rename = "apiVersion")]
    api_version: &'a str,
    kind: &'a str,
    statement: &'a LaunchAuthorityWitnessStatement,
}

#[derive(Serialize)]
struct LaunchAuthorityWitnessStoreAssuranceSignedValue<'a> {
    #[serde(rename = "apiVersion")]
    api_version: &'a str,
    kind: &'a str,
    statement: &'a LaunchAuthorityWitnessStoreAssuranceStatement,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LaunchAttemptRecoveryIdentity<'a> {
    domain: &'a str,
    launcher_nonce: &'a str,
    witness_challenge: &'a str,
    boot_id_sha256: &'a str,
    manifest_sha256: &'a str,
    global_role_registry_sha256: &'a str,
}

fn domain_separated_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(bytes);
    format!("sha256:{}", hex::encode(digest.finalize()))
}

fn launch_authority_key_id(key: &VerifyingKey) -> String {
    let mut spki = Vec::with_capacity(ED25519_SPKI_PREFIX.len() + 32);
    spki.extend_from_slice(&ED25519_SPKI_PREFIX);
    spki.extend_from_slice(key.as_bytes());
    sha256_prefixed(&spki)
}

fn parse_authority_public_key(raw: &str) -> Result<VerifyingKey> {
    let trimmed = raw.strip_suffix('\n').ok_or_else(|| {
        LauncherError::new("compiled launch authority public key must end with one LF")
    })?;
    if trimmed.contains(['\r', '\n']) {
        return Err(LauncherError::new(
            "compiled launch authority public key has invalid whitespace",
        ));
    }
    require_lower_hex_64(trimmed, "compiled launch authority public key")?;
    let decoded = hex::decode(trimmed)
        .map_err(|_| LauncherError::new("compiled launch authority public key is invalid"))?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| LauncherError::new("compiled launch authority public key is invalid"))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|_| LauncherError::new("compiled launch authority public key is invalid"))
}

fn compiled_authority_public_key() -> Result<VerifyingKey> {
    parse_authority_public_key(COMPILED_AUTHORITY_PUBLIC_KEY_HEX)
}

fn authorization_request_digest(request: &LaunchAuthorizationRequest) -> Result<String> {
    Ok(domain_separated_digest(
        b"serverware.launchAuthorizationRequest/v2\0",
        &canonical_json_bytes(request)?,
    ))
}

fn launch_attempt_recovery_identity_sha256(
    request: &LaunchAuthorizationRequest,
) -> Result<String> {
    let identity = LaunchAttemptRecoveryIdentity {
        domain: &request.launch_attempt_journal_domain,
        launcher_nonce: &request.launcher_nonce,
        witness_challenge: &request.launch_authority_witness_challenge,
        boot_id_sha256: &request.boot_id_sha256,
        manifest_sha256: &request.manifest_sha256,
        global_role_registry_sha256: &request.global_role_registry_sha256,
    };
    Ok(domain_separated_digest(
        b"serverware.launchAuthorizationAttemptRecoveryIdentity/v1\0",
        &canonical_json_bytes(&identity)?,
    ))
}

fn global_role_registry_sha256(registry: &GlobalRoleRegistry) -> Result<String> {
    Ok(sha256_prefixed(&canonical_json_bytes(registry)?))
}

fn authorization_signing_bytes(envelope: &LaunchAuthorizationEnvelope) -> Result<Vec<u8>> {
    let signed = LaunchAuthorizationSignedValue {
        api_version: &envelope.api_version,
        kind: &envelope.kind,
        statement: &envelope.statement,
    };
    let canonical = canonical_json_bytes(&signed)?;
    let mut bytes = b"serverware.launchAuthorization/v2\0".to_vec();
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

fn witness_signing_bytes(envelope: &LaunchAuthorityWitnessEnvelope) -> Result<Vec<u8>> {
    let signed = LaunchAuthorityWitnessSignedValue {
        api_version: &envelope.api_version,
        kind: &envelope.kind,
        statement: &envelope.statement,
    };
    let canonical = canonical_json_bytes(&signed)?;
    let mut bytes = b"serverware.launchAuthorityWitnessTransition/v1\0".to_vec();
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

fn witness_store_assurance_signing_bytes(
    envelope: &LaunchAuthorityWitnessStoreAssuranceEnvelope,
) -> Result<Vec<u8>> {
    let signed = LaunchAuthorityWitnessStoreAssuranceSignedValue {
        api_version: &envelope.api_version,
        kind: &envelope.kind,
        statement: &envelope.statement,
    };
    let canonical = canonical_json_bytes(&signed)?;
    let mut bytes =
        b"serverware.launchAuthorityWitnessStoreAssurance/v1\0".to_vec();
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

fn decode_signature(value: &str, label: &str) -> Result<Signature> {
    if value.contains('=') {
        return Err(LauncherError::new(format!(
            "{label} must be unpadded base64url"
        )));
    }
    let decoded = general_purpose::URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| LauncherError::new(format!("{label} is not canonical base64url")))?;
    if decoded.len() != 64 || general_purpose::URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(LauncherError::new(format!(
            "{label} must contain exactly 64 canonical bytes"
        )));
    }
    let bytes: [u8; 64] = decoded
        .try_into()
        .map_err(|_| LauncherError::new(format!("{label} length is invalid")))?;
    Ok(Signature::from_bytes(&bytes))
}

fn verify_launch_authority_witness(
    request: &LaunchAuthorizationRequest,
    authorization_id: &str,
    authority_key_id: &str,
    envelope_issued_at_unix_seconds: u64,
    envelope_expires_at_unix_seconds: u64,
    witness: &LaunchAuthorityWitnessEnvelope,
    configuration: &LaunchAuthorityWitnessConfiguration,
) -> Result<()> {
    if witness.api_version != WITNESS_API_VERSION || witness.kind != WITNESS_KIND {
        return Err(LauncherError::new(
            "LAUTH_WITNESS_SCHEMA_INVALID: unsupported witness contract",
        ));
    }
    let statement = &witness.statement;
    if statement.operation != WITNESS_OPERATION
        || statement.operation_id != request.launcher_nonce
        || statement.authorization_id != authorization_id
        || statement.request_sha256 != authorization_request_digest(request)?
        || statement.challenge != request.launch_authority_witness_challenge
        || statement.issued_at_unix_seconds != envelope_issued_at_unix_seconds
        || statement.expires_at_unix_seconds != envelope_expires_at_unix_seconds
        || statement.authority_key_id != authority_key_id
        || statement.witness_key_id != request.launch_authority_witness_key_id
        || statement.witness_identity_sha256
            != request.launch_authority_witness_identity_sha256
        || statement.witness_administrative_domain_sha256
            != request.launch_authority_witness_administrative_domain_sha256
        || statement.store_assurance_sha256
            != request.launch_authority_witness_store_assurance_sha256
        || statement.deployment_audience != request.deployment_audience
        || statement.deployment_identity_sha256 != request.deployment_identity_sha256
        || statement.release_sequence != request.release_sequence
        || statement.rollback_epoch != request.rollback_epoch
        || statement.authorization_scope != AUTHORIZATION_SCOPE
        || !statement.state_transition_committed
    {
        return Err(LauncherError::new(
            "LAUTH_WITNESS_BINDING_MISMATCH: witness does not bind the exact readiness operation",
        ));
    }
    for (value, label) in [
        (&statement.request_sha256, "requestSha256"),
        (&statement.authority_key_id, "authorityKeyId"),
        (&statement.witness_key_id, "witnessKeyId"),
        (&statement.witness_identity_sha256, "witnessIdentitySha256"),
        (
            &statement.witness_administrative_domain_sha256,
            "witnessAdministrativeDomainSha256",
        ),
        (&statement.store_assurance_sha256, "storeAssuranceSha256"),
        (&statement.registry_sha256, "registrySha256"),
        (
            &statement.predecessor_state_sha256,
            "predecessorStateSha256",
        ),
        (&statement.successor_state_sha256, "successorStateSha256"),
        (
            &statement.deployment_identity_sha256,
            "deploymentIdentitySha256",
        ),
    ] {
        require_sha256(value, label).map_err(|_| {
            LauncherError::new(format!("LAUTH_WITNESS_SCHEMA_INVALID: {label} is invalid"))
        })?;
    }
    require_lower_hex_64(&statement.operation_id, "operationId")
        .and_then(|_| require_lower_hex_64(&statement.authorization_id, "authorizationId"))
        .and_then(|_| require_lower_hex_64(&statement.challenge, "challenge"))
        .map_err(|_| {
            LauncherError::new("LAUTH_WITNESS_SCHEMA_INVALID: witness identifier is invalid")
        })?;
    require_json_safe_integer(statement.registry_generation, "registryGeneration", false)?;
    require_json_safe_integer(statement.checkpoint_sequence, "checkpointSequence", false)?;
    if statement.predecessor_state_sha256 == statement.successor_state_sha256 {
        return Err(LauncherError::new(
            "LAUTH_WITNESS_IDENTITY_TRANSITION: predecessor and successor must differ",
        ));
    }
    if configuration.signing_key_id == authority_key_id
        || configuration.signing_key_id != statement.witness_key_id
        || configuration.identity_sha256 != statement.witness_identity_sha256
        || configuration.administrative_domain_sha256
            != statement.witness_administrative_domain_sha256
        || configuration.store_assurance_sha256 != statement.store_assurance_sha256
    {
        return Err(LauncherError::new(
            "LAUTH_WITNESS_TRUST_MISMATCH: witness does not match manifest trust pins",
        ));
    }
    let key = parse_ed25519_spki(
        &configuration.signing_public_key_spki_der_base64url,
        "launch-authority witness signing key",
    )?;
    key.verify_strict(
        &witness_signing_bytes(witness)?,
        &decode_signature(&witness.signature, "launch-authority witness signature")?,
    )
    .map_err(|_| {
        LauncherError::new(
            "LAUTH_WITNESS_SIGNATURE_INVALID: witness signature verification failed",
        )
    })
}

fn require_authorization_current(
    statement: &LaunchAuthorizationStatement,
    now_unix_seconds: u64,
) -> Result<()> {
    let issued = statement.issued_at_unix_seconds;
    let expires = statement.expires_at_unix_seconds;
    if expires <= issued || expires - issued > AUTHORIZATION_MAX_LIFETIME_SECONDS {
        return Err(LauncherError::new(
            "LAUTH_TIME_INVALID: authorization validity interval is invalid",
        ));
    }
    if issued > now_unix_seconds.saturating_add(AUTHORIZATION_MAX_FUTURE_SKEW_SECONDS) {
        return Err(LauncherError::new(
            "LAUTH_FUTURE: authorization issuance time is too far in the future",
        ));
    }
    if now_unix_seconds >= expires {
        return Err(LauncherError::new(
            "LAUTH_EXPIRED: launch authorization has expired",
        ));
    }
    Ok(())
}

fn verify_launch_authorization(
    request: LaunchAuthorizationRequest,
    envelope: LaunchAuthorizationEnvelope,
    key: &VerifyingKey,
    witness_configuration: &LaunchAuthorityWitnessConfiguration,
    now_unix_seconds: u64,
    time_policy: AuthorizationTimePolicy,
) -> Result<ReceiptLaunchAuthorization> {
    if envelope.api_version != AUTHORIZATION_API_VERSION || envelope.kind != AUTHORIZATION_KIND {
        return Err(LauncherError::new(
            "LAUTH_SCHEMA_INVALID: unsupported launch authorization contract",
        ));
    }
    require_lower_hex_64(&envelope.statement.authorization_id, "authorizationId")
        .map_err(|_| LauncherError::new("LAUTH_SCHEMA_INVALID: authorizationId is invalid"))?;
    require_sha256(&envelope.statement.authority_key_id, "authorityKeyId")
        .map_err(|_| LauncherError::new("LAUTH_SCHEMA_INVALID: authorityKeyId is invalid"))?;
    require_sha256(&envelope.statement.request_sha256, "requestSha256")
        .map_err(|_| LauncherError::new("LAUTH_SCHEMA_INVALID: requestSha256 is invalid"))?;
    for (value, label) in [
        (
            envelope.statement.issued_at_unix_seconds,
            "issuedAtUnixSeconds",
        ),
        (
            envelope.statement.expires_at_unix_seconds,
            "expiresAtUnixSeconds",
        ),
    ] {
        require_json_safe_integer(value, label, false)
            .map_err(|_| LauncherError::new(format!("LAUTH_SCHEMA_INVALID: {label} is invalid")))?;
    }
    if envelope.statement.authorization_scope != AUTHORIZATION_SCOPE
        || envelope.statement.freshness_authority != FRESHNESS_AUTHORITY
        || envelope.statement.capability_semantics != CAPABILITY_SEMANTICS
        || request.authorization_scope != AUTHORIZATION_SCOPE
        || request.freshness_authority != FRESHNESS_AUTHORITY
    {
        return Err(LauncherError::new(
            "LAUTH_SCOPE_INVALID: native authorizations must be time-bounded trusted-host readiness capabilities",
        ));
    }
    require_sha256(
        &request.global_role_registry_sha256,
        "globalRoleRegistrySha256",
    )
    .map_err(|_| {
        LauncherError::new(
            "LAUTH_SCHEMA_INVALID: globalRoleRegistrySha256 is invalid",
        )
    })?;
    require_sha256(
        &request.global_role_registry_pins_sha256,
        "globalRoleRegistryPinsSha256",
    )
    .map_err(|_| {
        LauncherError::new(
            "LAUTH_SCHEMA_INVALID: globalRoleRegistryPinsSha256 is invalid",
        )
    })?;
    let registry = &request.global_role_registry;
    let expected_roles = GLOBAL_ROLE_NAMES
        .into_iter()
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    if registry.api_version != GLOBAL_ROLE_REGISTRY_API_VERSION
        || registry.claim_scope != GLOBAL_ROLE_REGISTRY_CLAIM_SCOPE
        || registry.roles_outside_claim
            != GLOBAL_ROLES_OUTSIDE_CLAIM
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
        || registry.roles.keys().cloned().collect::<BTreeSet<_>>()
            != expected_roles
        || registry.roles.values().collect::<BTreeSet<_>>().len()
            != registry.roles.len()
        || registry
            .roles
            .values()
            .any(|key_id| require_sha256(key_id, "global role key ID").is_err())
        || global_role_registry_sha256(registry)?
            != request.global_role_registry_sha256
        || envelope.statement.global_role_registry_sha256
            != request.global_role_registry_sha256
    {
        return Err(LauncherError::new(
            "LAUTH_GLOBAL_ROLE_REGISTRY_INVALID: request or authorization role registry binding is invalid",
        ));
    }
    if request.launch_attempt_journal_domain != ATTEMPT_JOURNAL_DOMAIN
        || request.launch_attempt_recovery_identity_sha256
            != launch_attempt_recovery_identity_sha256(&request)?
    {
        return Err(LauncherError::new(
            "LAUTH_ATTEMPT_RECOVERY_INVALID: request journal domain or recovery identity is invalid",
        ));
    }
    require_lower_hex_64(
        &request.launch_authority_witness_challenge,
        "launchAuthorityWitnessChallenge",
    )
    .map_err(|_| {
        LauncherError::new(
            "LAUTH_SCHEMA_INVALID: launchAuthorityWitnessChallenge is invalid",
        )
    })?;
    for (value, label) in [
        (
            request.launch_authority_witness_key_id.as_str(),
            "launchAuthorityWitnessKeyId",
        ),
        (
            request.launch_authority_witness_identity_sha256.as_str(),
            "launchAuthorityWitnessIdentitySha256",
        ),
        (
            request
                .launch_authority_witness_administrative_domain_sha256
                .as_str(),
            "launchAuthorityWitnessAdministrativeDomainSha256",
        ),
        (
            request
                .launch_authority_witness_store_assurance_sha256
                .as_str(),
            "launchAuthorityWitnessStoreAssuranceSha256",
        ),
    ] {
        require_sha256(value, label).map_err(|_| {
            LauncherError::new(format!("LAUTH_SCHEMA_INVALID: {label} is invalid"))
        })?;
    }
    let configured_witness_key_id = canonical_ed25519_spki_sha256(
        &witness_configuration.signing_public_key_spki_der_base64url,
        "launch-authority witness signing key",
    )?;
    if configured_witness_key_id != witness_configuration.signing_key_id
        || request.launch_authority_witness_key_id != witness_configuration.signing_key_id
        || request.launch_authority_witness_identity_sha256
            != witness_configuration.identity_sha256
        || request.launch_authority_witness_administrative_domain_sha256
            != witness_configuration.administrative_domain_sha256
        || request.launch_authority_witness_store_assurance_sha256
            != witness_configuration.store_assurance_sha256
    {
        return Err(LauncherError::new(
            "LAUTH_WITNESS_TRUST_MISMATCH: request does not match manifest witness pins",
        ));
    }

    let expected_key_id = launch_authority_key_id(key);
    if envelope.statement.authority_key_id != expected_key_id {
        return Err(LauncherError::new(
            "LAUTH_KEY_ID_MISMATCH: authority key identity does not match compiled trust root",
        ));
    }
    let request_sha256 = authorization_request_digest(&request)?;
    if envelope.statement.request_sha256 != request_sha256 {
        return Err(LauncherError::new(
            "LAUTH_REQUEST_MISMATCH: authorization does not bind this launch request",
        ));
    }

    match time_policy {
        AuthorizationTimePolicy::CurrentRequired => {
            require_authorization_current(&envelope.statement, now_unix_seconds)?
        }
        AuthorizationTimePolicy::RecoveryMayBeExpired => {
            let issued = envelope.statement.issued_at_unix_seconds;
            let expires = envelope.statement.expires_at_unix_seconds;
            if expires <= issued
                || expires - issued > AUTHORIZATION_MAX_LIFETIME_SECONDS
                || issued
                    > now_unix_seconds.saturating_add(
                        AUTHORIZATION_MAX_FUTURE_SKEW_SECONDS,
                    )
            {
                return Err(LauncherError::new(
                    "LAUTH_TIME_INVALID: recovered authorization validity interval is invalid",
                ));
            }
        }
    }

    if envelope.signature.contains('=') {
        return Err(LauncherError::new(
            "LAUTH_SIGNATURE_INVALID: signature must be unpadded base64url",
        ));
    }
    let decoded = general_purpose::URL_SAFE_NO_PAD
        .decode(envelope.signature.as_bytes())
        .map_err(|_| {
            LauncherError::new("LAUTH_SIGNATURE_INVALID: signature is not canonical base64url")
        })?;
    if decoded.len() != 64
        || general_purpose::URL_SAFE_NO_PAD.encode(&decoded) != envelope.signature
    {
        return Err(LauncherError::new(
            "LAUTH_SIGNATURE_INVALID: signature must contain exactly 64 canonical bytes",
        ));
    }
    let signature_bytes: [u8; 64] = decoded
        .try_into()
        .map_err(|_| LauncherError::new("LAUTH_SIGNATURE_INVALID: signature length is invalid"))?;
    key.verify_strict(
        &authorization_signing_bytes(&envelope)?,
        &Signature::from_bytes(&signature_bytes),
    )
    .map_err(|_| {
        LauncherError::new("LAUTH_SIGNATURE_INVALID: authority signature verification failed")
    })?;
    verify_launch_authority_witness(
        &request,
        &envelope.statement.authorization_id,
        &envelope.statement.authority_key_id,
        envelope.statement.issued_at_unix_seconds,
        envelope.statement.expires_at_unix_seconds,
        &envelope.statement.monotonic_witness,
        witness_configuration,
    )?;

    let envelope_bytes = canonical_json_bytes(&envelope)?;
    Ok(ReceiptLaunchAuthorization {
        request,
        request_sha256,
        authorization_sha256: sha256_prefixed(&envelope_bytes),
        witness_public_key_spki_der_base64url: witness_configuration
            .signing_public_key_spki_der_base64url
            .clone(),
        envelope,
        verified_at_unix_seconds: now_unix_seconds,
    })
}

fn parse_manifest(bytes: &[u8]) -> Result<LaunchManifest> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| LauncherError::new(format!("launch manifest is invalid: {error}")))?;
    let api_version = value.get("apiVersion").and_then(Value::as_str);
    if api_version == Some("serverware.productionReadinessLaunch/v2") {
        return Err(LauncherError::new(
            "legacy v2 launch manifests are readiness-only and cannot satisfy enforced nonce rollback assurance",
        ));
    }
    if api_version != Some(LAUNCH_MANIFEST_API_VERSION) {
        return Err(LauncherError::new(
            "unsupported launch manifest apiVersion",
        ));
    }
    let manifest: LaunchManifest = serde_json::from_value(value)
        .map_err(|error| LauncherError::new(format!("launch manifest is invalid: {error}")))?;
    validate_manifest(&manifest)?;
    let mut canonical = canonical_json_bytes(&manifest)?;
    canonical.push(b'\n');
    if canonical != bytes {
        return Err(LauncherError::new(
            "launch manifest must be canonical JSON plus one LF",
        ));
    }
    Ok(manifest)
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::ffi::{CStr, CString};
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::mem::{size_of, MaybeUninit};
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    use std::time::{Duration, Instant};

    const PYTHON_BOOTSTRAP_PREFIX: &str = "import os,sys\n";
    const IMMUTABLE_MEMFD_SEALS: libc::c_int =
        libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;

    #[derive(Debug)]
    struct MeasuredFile {
        file: File,
        receipt: ReceiptFile,
    }

    #[derive(Debug)]
    struct MeasuredScript {
        snapshot: OwnedFd,
        receipt: ReceiptFile,
    }

    #[derive(Debug)]
    struct MeasuredImportRoot {
        fd: OwnedFd,
        receipt: ReceiptImportRoot,
    }

    #[derive(Debug)]
    struct MeasuredNonceRollbackAssurancePins {
        snapshot: OwnedFd,
        receipt: ReceiptFile,
    }

    #[derive(Debug)]
    struct MeasuredGlobalRoleRegistryPins {
        snapshot: OwnedFd,
        receipt: ReceiptFile,
    }

    #[derive(Debug)]
    struct VerifiedLaunch {
        manifest: LaunchManifest,
        launcher: ReceiptFile,
        manifest_receipt: ReceiptFile,
        python: MeasuredFile,
        preflight: MeasuredScript,
        runner: MeasuredScript,
        import_roots: Vec<MeasuredImportRoot>,
        nonce_rollback_assurance_pins: MeasuredNonceRollbackAssurancePins,
        global_role_registry_pins: MeasuredGlobalRoleRegistryPins,
        production_env: ReceiptFile,
        compose_file: ReceiptFile,
        inputs: BTreeMap<String, ReceiptFile>,
        provenance_digest: String,
        release_root_fd: OwnedFd,
        state_directory_fd: OwnedFd,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct LaunchAttemptJournal {
        api_version: String,
        kind: String,
        domain: String,
        state: String,
        request: LaunchAuthorizationRequest,
        request_sha256: String,
        recovery_identity_sha256: String,
    }

    #[derive(Debug)]
    struct LaunchAttemptJournalGuard {
        _lock: OwnedFd,
    }

    #[derive(Debug)]
    struct ReadLaunchAttemptJournal {
        value: LaunchAttemptJournal,
        identity: FileIdentity,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct FileIdentity {
        device: u64,
        inode: u64,
        mode: u32,
        owner_uid: u32,
        owner_gid: u32,
        link_count: u64,
        size: u64,
        modified_unix_nanos: i128,
        changed_unix_nanos: i128,
    }

    impl FileIdentity {
        fn receipt(self) -> ReceiptMetadata {
            ReceiptMetadata {
                device: self.device,
                inode: self.inode,
                mode: self.mode & 0o7777,
                owner_uid: self.owner_uid,
                owner_gid: self.owner_gid,
                link_count: self.link_count,
                size: self.size,
                modified_unix_nanos: self.modified_unix_nanos,
                changed_unix_nanos: self.changed_unix_nanos,
            }
        }
    }

    fn errno_message(context: &str) -> LauncherError {
        LauncherError::new(format!("{context}: {}", std::io::Error::last_os_error()))
    }

    fn cstring_bytes(bytes: &[u8], label: &str) -> Result<CString> {
        CString::new(bytes).map_err(|_| LauncherError::new(format!("{label} contains NUL")))
    }

    fn file_identity(raw: libc::stat) -> FileIdentity {
        FileIdentity {
            device: raw.st_dev,
            inode: raw.st_ino,
            mode: raw.st_mode,
            owner_uid: raw.st_uid,
            owner_gid: raw.st_gid,
            link_count: u64::from(raw.st_nlink),
            size: u64::try_from(raw.st_size).unwrap_or(0),
            modified_unix_nanos: i128::from(raw.st_mtime) * 1_000_000_000
                + i128::from(raw.st_mtime_nsec),
            changed_unix_nanos: i128::from(raw.st_ctime) * 1_000_000_000
                + i128::from(raw.st_ctime_nsec),
        }
    }

    fn fstat(fd: RawFd, context: &str) -> Result<FileIdentity> {
        let mut raw = MaybeUninit::<libc::stat>::uninit();
        // SAFETY: raw points to writable storage and fd is owned by the caller.
        if unsafe { libc::fstat(fd, raw.as_mut_ptr()) } != 0 {
            return Err(errno_message(context));
        }
        // SAFETY: successful fstat initialized the complete stat structure.
        Ok(file_identity(unsafe { raw.assume_init() }))
    }

    fn fstatat_nofollow(
        directory_fd: RawFd,
        name: &CStr,
        context: &str,
    ) -> Result<Option<FileIdentity>> {
        let mut raw = MaybeUninit::<libc::stat>::uninit();
        // SAFETY: name is NUL-terminated and raw points to writable storage.
        if unsafe {
            libc::fstatat(
                directory_fd,
                name.as_ptr(),
                raw.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                return Ok(None);
            }
            return Err(errno_message(context));
        }
        // SAFETY: successful fstatat initialized the complete stat structure.
        Ok(Some(file_identity(unsafe { raw.assume_init() })))
    }

    fn require_secure_directory(identity: FileIdentity, label: &str) -> Result<()> {
        if identity.mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(LauncherError::new(format!("{label} must be a directory")));
        }
        if identity.owner_uid != 0 || identity.owner_gid != 0 {
            return Err(LauncherError::new(format!(
                "{label} must be owned by root:root"
            )));
        }
        if identity.mode & 0o022 != 0 {
            return Err(LauncherError::new(format!(
                "{label} must not be writable by group or other"
            )));
        }
        Ok(())
    }

    fn require_secure_regular(
        identity: FileIdentity,
        label: &str,
        exact_read_only_mode: bool,
        executable: bool,
    ) -> Result<()> {
        if identity.mode & libc::S_IFMT != libc::S_IFREG {
            return Err(LauncherError::new(format!(
                "{label} must be a regular file"
            )));
        }
        if identity.owner_uid != 0 || identity.owner_gid != 0 {
            return Err(LauncherError::new(format!(
                "{label} must be owned by root:root"
            )));
        }
        if identity.link_count != 1 {
            return Err(LauncherError::new(format!(
                "{label} must have one hard link"
            )));
        }
        if identity.mode & 0o6000 != 0 {
            return Err(LauncherError::new(format!(
                "{label} must not have set-id bits"
            )));
        }
        let permissions = identity.mode & 0o7777;
        if exact_read_only_mode {
            if permissions != 0o400 && permissions != 0o440 {
                return Err(LauncherError::new(format!(
                    "{label} mode must be exactly 0400 or 0440"
                )));
            }
        } else if permissions & 0o022 != 0 {
            return Err(LauncherError::new(format!(
                "{label} must not be writable by group or other"
            )));
        }
        if executable && permissions & 0o111 == 0 {
            return Err(LauncherError::new(format!("{label} must be executable")));
        }
        if identity.size > MAX_MEASURED_FILE_BYTES {
            return Err(LauncherError::new(format!("{label} is too large")));
        }
        Ok(())
    }

    fn open_root() -> Result<OwnedFd> {
        let root = c"/";
        // SAFETY: root is a static NUL-terminated string.
        let fd = unsafe {
            libc::open(
                root.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(errno_message("could not open filesystem root"));
        }
        // SAFETY: fd is newly returned and uniquely owned.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        require_secure_directory(
            fstat(fd.as_raw_fd(), "could not inspect filesystem root")?,
            "/",
        )?;
        Ok(fd)
    }

    fn secure_open(path: &Path, final_directory: bool, label: &str) -> Result<OwnedFd> {
        require_normalized_absolute(path, label)?;
        let mut current = open_root()?;
        let components = path
            .components()
            .filter_map(|component| match component {
                Component::Normal(value) => Some(value.as_bytes().to_vec()),
                _ => None,
            })
            .collect::<Vec<_>>();
        for (index, component) in components.iter().enumerate() {
            let final_component = index + 1 == components.len();
            let name = cstring_bytes(component, label)?;
            let mut flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
            if !final_component || final_directory {
                flags |= libc::O_DIRECTORY;
            }
            // SAFETY: current and name remain valid for the call.
            let next = unsafe { libc::openat(current.as_raw_fd(), name.as_ptr(), flags) };
            if next < 0 {
                return Err(errno_message(&format!("could not securely open {label}")));
            }
            // SAFETY: next is newly returned and uniquely owned.
            let next = unsafe { OwnedFd::from_raw_fd(next) };
            let identity = fstat(next.as_raw_fd(), &format!("could not inspect {label}"))?;
            if !final_component || final_directory {
                require_secure_directory(identity, label)?;
            }
            current = next;
        }
        Ok(current)
    }

    fn stable_digest_file(
        mut file: File,
        path: &Path,
        expected_digest: &str,
        label: &str,
        exact_read_only_mode: bool,
        executable: bool,
        mut snapshot: Option<&mut File>,
    ) -> Result<MeasuredFile> {
        let before = fstat(file.as_raw_fd(), &format!("could not inspect {label}"))?;
        require_secure_regular(before, label, exact_read_only_mode, executable)?;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| LauncherError::new(format!("could not seek {label}")))?;
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            let count = file
                .read(&mut buffer)
                .map_err(|_| LauncherError::new(format!("could not read {label}")))?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(count as u64)
                .ok_or_else(|| LauncherError::new(format!("{label} size overflow")))?;
            if total > MAX_MEASURED_FILE_BYTES {
                return Err(LauncherError::new(format!("{label} is too large")));
            }
            if let Some(snapshot) = snapshot.as_deref_mut() {
                snapshot
                    .write_all(&buffer[..count])
                    .map_err(|_| LauncherError::new(format!("could not snapshot {label}")))?;
            }
            digest.update(&buffer[..count]);
        }
        let after = fstat(file.as_raw_fd(), &format!("could not re-inspect {label}"))?;
        if before != after || total != before.size {
            return Err(LauncherError::new(format!(
                "{label} changed while it was measured"
            )));
        }
        let actual = format!("sha256:{}", hex::encode(digest.finalize()));
        if actual != expected_digest {
            return Err(LauncherError::new(format!("{label} digest does not match")));
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|_| LauncherError::new(format!("could not reset {label}")))?;
        Ok(MeasuredFile {
            file,
            receipt: ReceiptFile {
                path: path.to_string_lossy().into_owned(),
                sha256: actual,
                metadata: before.receipt(),
            },
        })
    }

    fn measure_file(record: &FileRecord, label: &str, executable: bool) -> Result<MeasuredFile> {
        let fd = secure_open(&record.path, false, label)?;
        stable_digest_file(
            File::from(fd),
            &record.path,
            &record.sha256,
            label,
            false,
            executable,
            None,
        )
    }

    fn measured_canonical_ed25519_spki_pem_sha256(
        file: &mut File,
        expected_file_sha256: &str,
        label: &str,
    ) -> Result<String> {
        const PEM_BEGIN: &[u8] = b"-----BEGIN PUBLIC KEY-----\n";
        const PEM_END: &[u8] = b"\n-----END PUBLIC KEY-----\n";

        let before = fstat(
            file.as_raw_fd(),
            &format!("could not inspect measured {label}"),
        )?;
        if before.size == 0 || before.size > MAX_TRUSTED_PUBLIC_KEY_BYTES {
            return Err(LauncherError::new(format!(
                "{label} must be a nonempty canonical Ed25519 SPKI PEM no larger than 64 KiB"
            )));
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|_| LauncherError::new(format!("could not reset measured {label}")))?;
        let mut pem = Vec::with_capacity(before.size as usize);
        (&mut *file)
            .take(MAX_TRUSTED_PUBLIC_KEY_BYTES + 1)
            .read_to_end(&mut pem)
            .map_err(|_| LauncherError::new(format!("could not read measured {label}")))?;
        let after = fstat(
            file.as_raw_fd(),
            &format!("could not re-inspect measured {label}"),
        )?;
        if before != after || pem.len() as u64 != before.size {
            return Err(LauncherError::new(format!(
                "measured {label} changed while its SPKI was parsed"
            )));
        }
        if sha256_prefixed(&pem) != expected_file_sha256 {
            return Err(LauncherError::new(format!(
                "measured {label} changed between digest measurement and SPKI binding"
            )));
        }
        let encoded = pem
            .strip_prefix(PEM_BEGIN)
            .and_then(|value| value.strip_suffix(PEM_END))
            .ok_or_else(|| {
                LauncherError::new(format!(
                    "{label} must be canonical Ed25519 SPKI PEM"
                ))
            })?;
        if encoded.is_empty()
            || encoded.contains(&b'\r')
            || encoded.contains(&b'\n')
        {
            return Err(LauncherError::new(format!(
                "{label} must be canonical Ed25519 SPKI PEM"
            )));
        }
        let der = general_purpose::STANDARD.decode(encoded).map_err(|_| {
            LauncherError::new(format!(
                "{label} must be canonical Ed25519 SPKI PEM"
            ))
        })?;
        if general_purpose::STANDARD.encode(&der).as_bytes() != encoded
            || der.len() != ED25519_SPKI_PREFIX.len() + 32
            || der[..ED25519_SPKI_PREFIX.len()] != ED25519_SPKI_PREFIX
        {
            return Err(LauncherError::new(format!(
                "{label} must contain one canonical Ed25519 SPKI DER key"
            )));
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|_| LauncherError::new(format!("could not reset measured {label}")))?;
        Ok(sha256_prefixed(&der))
    }

    fn validate_measured_global_role_registry_input(
        name: &str,
        measured: &mut MeasuredFile,
        registry: &GlobalRoleRegistry,
    ) -> Result<()> {
        let role = match name {
            "policyTrustedPublicKey" => "policyIdentity",
            "policyActivationTrustedPublicKey" => "policyActivation",
            "reproducibleBuildTrustedPublicKey" => "reproducibleBuild",
            _ => return Ok(()),
        };
        let expected_file_sha256 = measured.receipt.sha256.clone();
        let actual = measured_canonical_ed25519_spki_pem_sha256(
            &mut measured.file,
            &expected_file_sha256,
            &format!("{name} trusted public key"),
        )?;
        if registry.roles.get(role) != Some(&actual) {
            return Err(LauncherError::new(format!(
                "globalRoleRegistry {role} does not match measured {name} SPKI"
            )));
        }
        Ok(())
    }

    fn validate_measured_python(file: &mut File, python_version: &str) -> Result<()> {
        let before = fstat(file.as_raw_fd(), "could not inspect measured Python")?;
        if before.size > MAX_PYTHON_EXECUTABLE_BYTES as u64 {
            return Err(LauncherError::new(
                "python exceeds the bounded executable parser limit",
            ));
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|_| LauncherError::new("could not reset measured Python"))?;
        let mut bytes = Vec::with_capacity(before.size as usize);
        file.read_to_end(&mut bytes)
            .map_err(|_| LauncherError::new("could not read measured Python"))?;
        let after = fstat(file.as_raw_fd(), "could not re-inspect measured Python")?;
        if before != after || bytes.len() as u64 != before.size {
            return Err(LauncherError::new(
                "python changed while its ELF identity was validated",
            ));
        }
        validate_cpython_elf64(&bytes, python_version)?;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| LauncherError::new("could not reset measured Python"))?;
        Ok(())
    }

    fn validate_measured_nonce_rollback_assurance_pins(
        file: &mut File,
        binding: &NonceRollbackAssuranceBinding,
    ) -> Result<()> {
        let before = fstat(
            file.as_raw_fd(),
            "could not inspect measured nonce rollback assurance pins",
        )?;
        if before.size == 0 || before.size > MAX_NONCE_ROLLBACK_ASSURANCE_PINS_BYTES {
            return Err(LauncherError::new(
                "nonce rollback assurance pins size is outside the accepted bound",
            ));
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|_| LauncherError::new("could not reset nonce rollback assurance pins"))?;
        let mut bytes = Vec::with_capacity(before.size as usize);
        file.read_to_end(&mut bytes)
            .map_err(|_| LauncherError::new("could not read nonce rollback assurance pins"))?;
        let after = fstat(
            file.as_raw_fd(),
            "could not re-inspect nonce rollback assurance pins",
        )?;
        if before != after || bytes.len() as u64 != before.size {
            return Err(LauncherError::new(
                "nonce rollback assurance pins changed while canonical bytes were validated",
            ));
        }
        let mut expected = canonical_json_bytes(&binding.contract)?;
        expected.push(b'\n');
        if bytes != expected {
            return Err(LauncherError::new(
                "nonce rollback assurance pin file differs from the manifest-bound canonical contract",
            ));
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|_| LauncherError::new("could not reset nonce rollback assurance pins"))?;
        Ok(())
    }

    fn validate_measured_global_role_registry_pins(
        file: &mut File,
        binding: &GlobalRoleRegistryBinding,
    ) -> Result<()> {
        let before = fstat(
            file.as_raw_fd(),
            "could not inspect measured global role registry pins",
        )?;
        if before.size == 0 || before.size > MAX_GLOBAL_ROLE_REGISTRY_PINS_BYTES {
            return Err(LauncherError::new(
                "global role registry pins size is outside the accepted bound",
            ));
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|_| LauncherError::new("could not reset global role registry pins"))?;
        let mut bytes = Vec::with_capacity(before.size as usize);
        file.read_to_end(&mut bytes)
            .map_err(|_| LauncherError::new("could not read global role registry pins"))?;
        let after = fstat(
            file.as_raw_fd(),
            "could not re-inspect global role registry pins",
        )?;
        if before != after || bytes.len() as u64 != before.size {
            return Err(LauncherError::new(
                "global role registry pins changed while canonical bytes were validated",
            ));
        }
        let mut expected = canonical_json_bytes(&binding.registry)?;
        expected.push(b'\n');
        if bytes != expected {
            return Err(LauncherError::new(
                "global role registry pin file differs from the manifest-bound canonical registry",
            ));
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|_| LauncherError::new("could not reset global role registry pins"))?;
        Ok(())
    }

    fn create_sealable_memfd(name: &CStr, label: &str) -> Result<File> {
        // SAFETY: name is NUL-terminated and flags are valid.
        let raw_fd = unsafe {
            libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
        };
        if raw_fd < 0 {
            return Err(errno_message(&format!("could not create {label} memfd")));
        }
        // SAFETY: raw_fd is newly returned and uniquely owned.
        Ok(File::from(unsafe { OwnedFd::from_raw_fd(raw_fd) }))
    }

    fn seal_memfd(mut file: File, label: &str) -> Result<OwnedFd> {
        file.flush()
            .map_err(|_| LauncherError::new(format!("could not flush {label}")))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| LauncherError::new(format!("could not reset {label}")))?;
        // SAFETY: file descriptor is valid and the seal mask is supported for sealable memfds.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, IMMUTABLE_MEMFD_SEALS) } != 0 {
            return Err(errno_message(&format!("could not seal {label}")));
        }
        // SAFETY: the descriptor is valid and F_GET_SEALS returns the active mask.
        let active_seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
        if active_seals < 0 || active_seals & IMMUTABLE_MEMFD_SEALS != IMMUTABLE_MEMFD_SEALS {
            return Err(LauncherError::new(format!(
                "{label} immutable seals were not applied"
            )));
        }
        Ok(file.into())
    }

    fn measure_script(
        record: &FileRecord,
        label: &str,
        snapshot_name: &CStr,
    ) -> Result<MeasuredScript> {
        let source_fd = secure_open(&record.path, false, label)?;
        let mut snapshot = create_sealable_memfd(snapshot_name, label)?;
        let measured = stable_digest_file(
            File::from(source_fd),
            &record.path,
            &record.sha256,
            label,
            false,
            false,
            Some(&mut snapshot),
        )?;
        let snapshot_identity = fstat(
            snapshot.as_raw_fd(),
            &format!("could not inspect {label} snapshot"),
        )?;
        if snapshot_identity.size != measured.receipt.metadata.size {
            return Err(LauncherError::new(format!(
                "{label} snapshot size does not match measured source"
            )));
        }
        let snapshot = seal_memfd(snapshot, &format!("{label} snapshot"))?;
        Ok(MeasuredScript {
            snapshot,
            receipt: measured.receipt,
        })
    }

    fn measure_nonce_rollback_assurance_pins(
        binding: &NonceRollbackAssuranceBinding,
        label: &str,
    ) -> Result<MeasuredNonceRollbackAssurancePins> {
        let source_fd = secure_open(&binding.pins_file.path, false, label)?;
        let mut snapshot =
            create_sealable_memfd(c"serverware-nonce-rollback-assurance-pins", label)?;
        let measured = stable_digest_file(
            File::from(source_fd),
            &binding.pins_file.path,
            &binding.pins_file.sha256,
            label,
            true,
            false,
            Some(&mut snapshot),
        )?;
        validate_measured_nonce_rollback_assurance_pins(&mut snapshot, binding)?;
        let snapshot_identity = fstat(
            snapshot.as_raw_fd(),
            &format!("could not inspect {label} snapshot"),
        )?;
        if snapshot_identity.size != measured.receipt.metadata.size {
            return Err(LauncherError::new(format!(
                "{label} snapshot size does not match measured source"
            )));
        }
        Ok(MeasuredNonceRollbackAssurancePins {
            snapshot: seal_memfd(snapshot, &format!("{label} snapshot"))?,
            receipt: measured.receipt,
        })
    }

    fn measure_global_role_registry_pins(
        binding: &GlobalRoleRegistryBinding,
        label: &str,
    ) -> Result<MeasuredGlobalRoleRegistryPins> {
        let source_fd = secure_open(&binding.pins_file.path, false, label)?;
        let mut snapshot =
            create_sealable_memfd(c"serverware-global-role-registry-pins", label)?;
        let measured = stable_digest_file(
            File::from(source_fd),
            &binding.pins_file.path,
            &binding.pins_file.sha256,
            label,
            true,
            false,
            Some(&mut snapshot),
        )?;
        validate_measured_global_role_registry_pins(&mut snapshot, binding)?;
        let snapshot_identity = fstat(
            snapshot.as_raw_fd(),
            &format!("could not inspect {label} snapshot"),
        )?;
        if snapshot_identity.size != measured.receipt.metadata.size {
            return Err(LauncherError::new(format!(
                "{label} snapshot size does not match measured source"
            )));
        }
        Ok(MeasuredGlobalRoleRegistryPins {
            snapshot: seal_memfd(snapshot, &format!("{label} snapshot"))?,
            receipt: measured.receipt,
        })
    }

    fn read_manifest(cli: &Cli) -> Result<(LaunchManifest, ReceiptFile)> {
        let fd = secure_open(&cli.manifest, false, "manifest")?;
        let mut file = File::from(fd);
        let before = fstat(file.as_raw_fd(), "could not inspect manifest")?;
        require_secure_regular(before, "manifest", true, false)?;
        if before.size > MAX_MANIFEST_BYTES as u64 {
            return Err(LauncherError::new("manifest is too large"));
        }
        let mut bytes = Vec::with_capacity(before.size as usize);
        file.read_to_end(&mut bytes)
            .map_err(|_| LauncherError::new("could not read manifest"))?;
        let after = fstat(file.as_raw_fd(), "could not re-inspect manifest")?;
        if before != after || bytes.len() as u64 != before.size {
            return Err(LauncherError::new("manifest changed while it was measured"));
        }
        let digest = sha256_prefixed(&bytes);
        let manifest = parse_manifest(&bytes)?;
        Ok((
            manifest,
            ReceiptFile {
                path: cli.manifest.to_string_lossy().into_owned(),
                sha256: digest,
                metadata: before.receipt(),
            },
        ))
    }

    fn read_release_provenance_identity(
        file: &mut File,
        expected_source_tree_digest: &str,
    ) -> Result<String> {
        let before = fstat(
            file.as_raw_fd(),
            "could not inspect measured release provenance",
        )?;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| LauncherError::new("could not reset measured release provenance"))?;
        let mut bytes = Vec::with_capacity(before.size as usize);
        file.read_to_end(&mut bytes)
            .map_err(|_| LauncherError::new("could not read measured release provenance"))?;
        let after = fstat(
            file.as_raw_fd(),
            "could not re-inspect measured release provenance",
        )?;
        if before != after || bytes.len() as u64 != before.size {
            return Err(LauncherError::new(
                "measured release provenance changed while it was parsed",
            ));
        }
        let identity: ReleaseProvenanceIdentity = serde_json::from_slice(&bytes)
            .map_err(|_| LauncherError::new("release provenance identity fields are invalid"))?;
        if identity.provenance.version != 2 {
            return Err(LauncherError::new(
                "production release provenance payload must use version 2",
            ));
        }
        if identity.provenance.source != "serverware-digest-pinned-production-release" {
            return Err(LauncherError::new(
                "release provenance was not generated in digest-pinned production mode",
            ));
        }
        require_sha256(&identity.provenance_digest, "provenanceDigest")?;
        require_digest_match(
            &identity.provenance.source_tree.digest,
            expected_source_tree_digest,
            "release provenance source tree",
        )?;
        Ok(identity.provenance_digest)
    }

    fn directory_entries(fd: RawFd, label: &str) -> Result<Vec<Vec<u8>>> {
        // SAFETY: dup returns an independent descriptor consumed by fdopendir.
        let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicated < 0 {
            return Err(errno_message(&format!("could not duplicate {label}")));
        }
        // SAFETY: duplicated is a directory descriptor and ownership transfers to DIR.
        let directory = unsafe { libc::fdopendir(duplicated) };
        if directory.is_null() {
            // SAFETY: fdopendir did not take ownership on failure.
            unsafe { libc::close(duplicated) };
            return Err(errno_message(&format!("could not enumerate {label}")));
        }
        let mut names = Vec::new();
        loop {
            // SAFETY: directory remains valid until closed below.
            let entry = unsafe { libc::readdir(directory) };
            if entry.is_null() {
                break;
            }
            // SAFETY: d_name is NUL-terminated within dirent.
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if name != b"." && name != b".." {
                names.push(name.to_vec());
            }
        }
        // SAFETY: directory is valid and closes duplicated.
        if unsafe { libc::closedir(directory) } != 0 {
            return Err(errno_message(&format!("could not close {label}")));
        }
        names.sort();
        Ok(names)
    }

    fn hash_import_tree(
        directory_fd: RawFd,
        relative: &mut Vec<u8>,
        digest: &mut Sha256,
        label: &str,
    ) -> Result<()> {
        let before = fstat(directory_fd, &format!("could not inspect {label}"))?;
        require_secure_directory(before, label)?;
        for name in directory_entries(directory_fd, label)? {
            let c_name = cstring_bytes(&name, label)?;
            // SAFETY: directory fd and component remain valid for this call.
            let raw_fd = unsafe {
                libc::openat(
                    directory_fd,
                    c_name.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if raw_fd < 0 {
                return Err(errno_message(&format!("could not measure {label}")));
            }
            // SAFETY: raw_fd is newly returned and uniquely owned.
            let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
            let identity = fstat(fd.as_raw_fd(), &format!("could not inspect {label}"))?;
            let old_len = relative.len();
            if !relative.is_empty() {
                relative.push(b'/');
            }
            relative.extend_from_slice(&name);
            let path_length = u64::try_from(relative.len())
                .map_err(|_| LauncherError::new("import root path is too long"))?;
            match identity.mode & libc::S_IFMT {
                libc::S_IFDIR => {
                    require_secure_directory(identity, label)?;
                    digest.update(b"directory\0");
                    digest.update(path_length.to_be_bytes());
                    digest.update(relative.as_slice());
                    digest.update((identity.mode & 0o7777).to_be_bytes());
                    hash_import_tree(fd.as_raw_fd(), relative, digest, label)?;
                    let after = fstat(fd.as_raw_fd(), &format!("could not re-inspect {label}"))?;
                    if identity != after {
                        return Err(LauncherError::new(format!(
                            "{label} changed while it was measured"
                        )));
                    }
                }
                libc::S_IFREG => {
                    require_secure_regular(identity, label, false, false)?;
                    digest.update(b"file\0");
                    digest.update(path_length.to_be_bytes());
                    digest.update(relative.as_slice());
                    digest.update((identity.mode & 0o7777).to_be_bytes());
                    let mut file = File::from(fd);
                    let mut file_digest = Sha256::new();
                    let mut buffer = [0u8; 64 * 1024];
                    let mut total = 0u64;
                    loop {
                        let count = file
                            .read(&mut buffer)
                            .map_err(|_| LauncherError::new(format!("could not read {label}")))?;
                        if count == 0 {
                            break;
                        }
                        total += count as u64;
                        file_digest.update(&buffer[..count]);
                    }
                    let after = fstat(file.as_raw_fd(), &format!("could not re-inspect {label}"))?;
                    if identity != after || total != identity.size {
                        return Err(LauncherError::new(format!(
                            "{label} changed while it was measured"
                        )));
                    }
                    digest.update(total.to_be_bytes());
                    digest.update(file_digest.finalize());
                }
                _ => {
                    return Err(LauncherError::new(format!(
                        "{label} contains an unsupported filesystem entry"
                    )))
                }
            }
            relative.truncate(old_len);
        }
        let after = fstat(directory_fd, &format!("could not re-inspect {label}"))?;
        if before != after {
            return Err(LauncherError::new(format!(
                "{label} changed while it was measured"
            )));
        }
        Ok(())
    }

    fn measure_import_root(record: &ImportRootRecord, label: &str) -> Result<MeasuredImportRoot> {
        let fd = secure_open(&record.path, true, label)?;
        let identity = fstat(fd.as_raw_fd(), &format!("could not inspect {label}"))?;
        require_secure_directory(identity, label)?;
        let mut digest = Sha256::new();
        digest.update(b"serverware.importRoot/v1\0");
        hash_import_tree(fd.as_raw_fd(), &mut Vec::new(), &mut digest, label)?;
        let actual = format!("sha256:{}", hex::encode(digest.finalize()));
        require_digest_match(&actual, &record.sha256, label)?;
        Ok(MeasuredImportRoot {
            fd,
            receipt: ReceiptImportRoot {
                path: record.path.to_string_lossy().into_owned(),
                sha256: actual,
                metadata: identity.receipt(),
            },
        })
    }

    fn read_self() -> Result<ReceiptFile> {
        let path_bytes = std::fs::read_link("/proc/self/exe")
            .map_err(|_| LauncherError::new("could not resolve launcher executable"))?;
        require_normalized_absolute(&path_bytes, "launcher executable")?;
        let fd = secure_open(&path_bytes, false, "launcher executable")?;
        let measured = stable_digest_file(
            File::from(fd),
            &path_bytes,
            &format!(
                "sha256:{}",
                hex::encode({
                    let mut direct = File::open("/proc/self/exe")
                        .map_err(|_| LauncherError::new("could not open launcher executable"))?;
                    let mut hash = Sha256::new();
                    std::io::copy(&mut direct, &mut hash)
                        .map_err(|_| LauncherError::new("could not measure launcher executable"))?;
                    hash.finalize()
                })
            ),
            "launcher executable",
            false,
            true,
            None,
        )?;
        Ok(measured.receipt)
    }

    fn verify_launch(cli: &Cli) -> Result<VerifiedLaunch> {
        let launcher = read_self()?;
        let (manifest, manifest_receipt) = read_manifest(cli)?;
        let release_root_fd = secure_open(&manifest.release_root, true, "releaseRoot")?;
        let state_directory_fd =
            secure_open(&manifest.state_directory, true, "stateDirectory")?;
        let nonce_rollback_assurance_pins = measure_nonce_rollback_assurance_pins(
            &manifest.nonce_rollback_assurance,
            "nonceRollbackAssurance.pinsFile",
        )?;
        let global_role_registry_pins = measure_global_role_registry_pins(
            &manifest.global_role_registry,
            "globalRoleRegistry.pinsFile",
        )?;
        let production_env =
            measure_file(&manifest.production_env, "productionEnv", false)?.receipt;
        let python_record = FileRecord {
            path: manifest.python.path.clone(),
            sha256: manifest.python.sha256.clone(),
        };
        let mut python = measure_file(&python_record, "python", true)?;
        let python_version = validate_python_layout(&manifest)?;
        validate_measured_python(&mut python.file, &python_version)?;
        let preflight = measure_script(
            &manifest.scripts.preflight,
            "scripts.preflight",
            c"serverware-preflight-script-snapshot",
        )?;
        let runner = measure_script(
            &manifest.scripts.runner,
            "scripts.runner",
            c"serverware-readiness-script-snapshot",
        )?;
        let compose_file = measure_file(&manifest.compose_file, "composeFile", false)?.receipt;
        let mut import_roots = Vec::new();
        for (index, record) in manifest.python.import_roots.iter().enumerate() {
            import_roots.push(measure_import_root(
                record,
                &format!("python.importRoots[{index}]"),
            )?);
        }
        let mut inputs = BTreeMap::new();
        let mut provenance_digest = None;
        for (name, record) in all_input_records(&manifest.inputs) {
            let mut measured = measure_file(record, name, false)?;
            validate_measured_global_role_registry_input(
                name,
                &mut measured,
                &manifest.global_role_registry.registry,
            )?;
            if name == "releaseProvenance" {
                provenance_digest = Some(read_release_provenance_identity(
                    &mut measured.file,
                    &manifest.source_tree_digest,
                )?);
            }
            inputs.insert(name.to_string(), measured.receipt);
        }
        Ok(VerifiedLaunch {
            manifest,
            launcher,
            manifest_receipt,
            python,
            preflight,
            runner,
            import_roots,
            nonce_rollback_assurance_pins,
            global_role_registry_pins,
            production_env,
            compose_file,
            inputs,
            provenance_digest: provenance_digest
                .ok_or_else(|| LauncherError::new("release provenance input was not measured"))?,
            release_root_fd,
            state_directory_fd,
        })
    }

    fn revalidate_verified_launch(cli: &Cli, verified: &VerifiedLaunch) -> Result<()> {
        let launcher_record = FileRecord {
            path: PathBuf::from(&verified.launcher.path),
            sha256: verified.launcher.sha256.clone(),
        };
        let launcher = measure_file(&launcher_record, "launcher executable", true)?;
        if launcher.receipt != verified.launcher {
            return Err(LauncherError::new(
                "launcher executable changed after launch authorization",
            ));
        }
        let (_, manifest_receipt) = read_manifest(cli)?;
        if manifest_receipt != verified.manifest_receipt {
            return Err(LauncherError::new(
                "manifest changed after launch authorization",
            ));
        }
        let nonce_rollback_assurance_pins = measure_nonce_rollback_assurance_pins(
            &verified.manifest.nonce_rollback_assurance,
            "nonceRollbackAssurance.pinsFile post-authorization",
        )?;
        if nonce_rollback_assurance_pins.receipt
            != verified.nonce_rollback_assurance_pins.receipt
        {
            return Err(LauncherError::new(
                "nonce rollback assurance pins changed after launch authorization",
            ));
        }
        let global_role_registry_pins = measure_global_role_registry_pins(
            &verified.manifest.global_role_registry,
            "globalRoleRegistry.pinsFile post-authorization",
        )?;
        if global_role_registry_pins.receipt
            != verified.global_role_registry_pins.receipt
        {
            return Err(LauncherError::new(
                "global role registry pins changed after launch authorization",
            ));
        }
        let production_env =
            measure_file(&verified.manifest.production_env, "productionEnv", false)?;
        if production_env.receipt != verified.production_env {
            return Err(LauncherError::new(
                "production environment changed after launch authorization",
            ));
        }
        let python_record = FileRecord {
            path: verified.manifest.python.path.clone(),
            sha256: verified.manifest.python.sha256.clone(),
        };
        let python = measure_file(&python_record, "python", true)?;
        if python.receipt != verified.python.receipt {
            return Err(LauncherError::new(
                "Python executable changed after launch authorization",
            ));
        }
        for (index, record) in verified.manifest.python.import_roots.iter().enumerate() {
            let measured = measure_import_root(
                record,
                &format!("python.importRoots[{index}] post-authorization"),
            )?;
            if measured.receipt != verified.import_roots[index].receipt {
                return Err(LauncherError::new(
                    "Python import tree changed after launch authorization",
                ));
            }
        }
        for (record, expected, label, snapshot_name) in [
            (
                &verified.manifest.scripts.preflight,
                &verified.preflight.receipt,
                "scripts.preflight post-authorization",
                c"serverware-preflight-revalidation",
            ),
            (
                &verified.manifest.scripts.runner,
                &verified.runner.receipt,
                "scripts.runner post-authorization",
                c"serverware-runner-revalidation",
            ),
        ] {
            let measured = measure_script(record, label, snapshot_name)?;
            if &measured.receipt != expected {
                return Err(LauncherError::new(format!(
                    "{label} changed after launch authorization"
                )));
            }
        }
        let compose = measure_file(
            &verified.manifest.compose_file,
            "composeFile post-authorization",
            false,
        )?;
        if compose.receipt != verified.compose_file {
            return Err(LauncherError::new(
                "compose file changed after launch authorization",
            ));
        }
        for (name, record) in all_input_records(&verified.manifest.inputs) {
            let mut measured =
                measure_file(record, &format!("{name} post-authorization"), false)?;
            validate_measured_global_role_registry_input(
                name,
                &mut measured,
                &verified.manifest.global_role_registry.registry,
            )?;
            let expected = verified
                .inputs
                .get(name)
                .ok_or_else(|| LauncherError::new(format!("{name} was not measured")))?;
            if &measured.receipt != expected {
                return Err(LauncherError::new(format!(
                    "{name} changed after launch authorization"
                )));
            }
            if name == "releaseProvenance"
                && read_release_provenance_identity(
                    &mut measured.file,
                    &verified.manifest.source_tree_digest,
                )? != verified.provenance_digest
            {
                return Err(LauncherError::new(
                    "release provenance identity changed after launch authorization",
                ));
            }
        }
        for (path, retained_fd, label) in [
            (
                &verified.manifest.release_root,
                verified.release_root_fd.as_raw_fd(),
                "releaseRoot",
            ),
            (
                &verified.manifest.state_directory,
                verified.state_directory_fd.as_raw_fd(),
                "stateDirectory",
            ),
        ] {
            let reopened = secure_open(path, true, &format!("{label} post-authorization"))?;
            if fstat(
                reopened.as_raw_fd(),
                &format!("could not inspect reopened {label}"),
            )? != fstat(
                retained_fd,
                &format!("could not inspect retained {label}"),
            )? {
                return Err(LauncherError::new(format!(
                    "{label} changed after launch authorization"
                )));
            }
        }
        Ok(())
    }

    fn random_launch_id() -> Result<String> {
        let mut bytes = [0u8; 32];
        let mut offset = 0usize;
        while offset < bytes.len() {
            // SAFETY: the remaining byte slice is writable for the supplied length.
            let count = unsafe {
                libc::getrandom(bytes[offset..].as_mut_ptr().cast(), bytes.len() - offset, 0)
            };
            if count < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(LauncherError::new("could not obtain launch randomness"));
            }
            if count == 0 {
                return Err(LauncherError::new("launch randomness source returned EOF"));
            }
            offset += count as usize;
        }
        Ok(hex::encode(bytes))
    }

    fn boot_id_digest() -> Result<String> {
        let raw = std::fs::read("/proc/sys/kernel/random/boot_id")
            .map_err(|_| LauncherError::new("could not read kernel boot identity"))?;
        let mut trimmed = raw.as_slice();
        while matches!(trimmed.last(), Some(b'\n' | b'\r')) {
            trimmed = &trimmed[..trimmed.len() - 1];
        }
        if trimmed.is_empty() || trimmed.len() > 128 {
            return Err(LauncherError::new("kernel boot identity is invalid"));
        }
        Ok(sha256_prefixed(trimmed))
    }

    fn realtime_timespec() -> Result<libc::timespec> {
        let mut value = MaybeUninit::<libc::timespec>::uninit();
        // SAFETY: value points to writable storage for one timespec.
        if unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, value.as_mut_ptr()) } != 0 {
            return Err(errno_message("could not read realtime clock"));
        }
        // SAFETY: successful clock_gettime initialized value.
        let value = unsafe { value.assume_init() };
        if value.tv_nsec < 0 || value.tv_nsec >= 1_000_000_000 {
            return Err(LauncherError::new("realtime clock returned invalid nanoseconds"));
        }
        Ok(value)
    }

    fn unix_time_seconds() -> Result<u64> {
        u64::try_from(realtime_timespec()?.tv_sec)
            .map_err(|_| LauncherError::new("realtime clock is before the Unix epoch"))
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    struct BoottimeInstant {
        seconds: u64,
        nanoseconds: u32,
    }

    impl BoottimeInstant {
        fn from_timespec(value: libc::timespec, label: &str) -> Result<Self> {
            let seconds = u64::try_from(value.tv_sec)
                .map_err(|_| LauncherError::new(format!("{label} returned negative seconds")))?;
            let nanoseconds = u32::try_from(value.tv_nsec).map_err(|_| {
                LauncherError::new(format!("{label} returned negative nanoseconds"))
            })?;
            if nanoseconds >= NANOSECONDS_PER_SECOND {
                return Err(LauncherError::new(format!(
                    "{label} returned invalid nanoseconds"
                )));
            }
            Ok(Self {
                seconds,
                nanoseconds,
            })
        }

        fn checked_add_timespec_delta(
            self,
            seconds: u64,
            nanoseconds: u32,
        ) -> Result<Self> {
            if nanoseconds >= NANOSECONDS_PER_SECOND {
                return Err(LauncherError::new(
                    "launch authorization deadline delta has invalid nanoseconds",
                ));
            }
            let nanosecond_sum = u64::from(self.nanoseconds)
                .checked_add(u64::from(nanoseconds))
                .ok_or_else(|| {
                    LauncherError::new(
                        "launch authorization boottime nanosecond arithmetic overflow",
                    )
                })?;
            let carry = nanosecond_sum / u64::from(NANOSECONDS_PER_SECOND);
            let normalized_nanoseconds =
                (nanosecond_sum % u64::from(NANOSECONDS_PER_SECOND)) as u32;
            let normalized_seconds = self
                .seconds
                .checked_add(seconds)
                .and_then(|value| value.checked_add(carry))
                .ok_or_else(|| {
                    LauncherError::new("launch authorization boottime deadline overflow")
                })?;
            Ok(Self {
                seconds: normalized_seconds,
                nanoseconds: normalized_nanoseconds,
            })
        }

        fn to_timespec(self) -> Result<libc::timespec> {
            Ok(libc::timespec {
                tv_sec: libc::time_t::try_from(self.seconds).map_err(|_| {
                    LauncherError::new(
                        "launch authorization boottime deadline exceeds time_t",
                    )
                })?,
                tv_nsec: self.nanoseconds as libc::c_long,
            })
        }
    }

    fn boottime_now() -> Result<BoottimeInstant> {
        let mut value = MaybeUninit::<libc::timespec>::uninit();
        // SAFETY: value points to writable storage for one timespec.
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, value.as_mut_ptr()) } != 0 {
            return Err(errno_message("could not read suspend-aware boottime clock"));
        }
        // SAFETY: successful clock_gettime initialized value.
        BoottimeInstant::from_timespec(
            unsafe { value.assume_init() },
            "suspend-aware boottime clock",
        )
    }

    fn operation_deadline_from_samples(
        statement: &LaunchAuthorizationStatement,
        boottime_sample: BoottimeInstant,
        realtime_sample: libc::timespec,
    ) -> Result<BoottimeInstant> {
        if realtime_sample.tv_nsec < 0
            || realtime_sample.tv_nsec
                >= NANOSECONDS_PER_SECOND as libc::c_long
        {
            return Err(LauncherError::new(
                "realtime clock returned invalid nanoseconds",
            ));
        }
        let now_unix_seconds = u64::try_from(realtime_sample.tv_sec)
            .map_err(|_| LauncherError::new("realtime clock is before the Unix epoch"))?;
        require_authorization_current(statement, now_unix_seconds)?;
        project_wall_expiration_to_boottime(
            statement.expires_at_unix_seconds,
            now_unix_seconds,
            realtime_sample.tv_nsec as u32,
            boottime_sample,
        )
    }

    fn project_wall_expiration_to_boottime(
        expires_at_unix_seconds: u64,
        now_unix_seconds: u64,
        realtime_nanoseconds: u32,
        boottime_sample: BoottimeInstant,
    ) -> Result<BoottimeInstant> {
        if realtime_nanoseconds >= NANOSECONDS_PER_SECOND {
            return Err(LauncherError::new(
                "realtime clock returned invalid nanoseconds",
            ));
        }
        let whole_seconds = expires_at_unix_seconds
            .checked_sub(now_unix_seconds)
            .ok_or_else(|| LauncherError::new("LAUTH_EXPIRED: launch authorization has expired"))?;
        if whole_seconds == 0 {
            return Err(LauncherError::new(
                "LAUTH_EXPIRED: launch authorization has expired",
            ));
        }
        let (remaining_seconds, remaining_nanoseconds) = if realtime_nanoseconds == 0 {
            (whole_seconds, 0)
        } else {
            (
                whole_seconds.checked_sub(1).ok_or_else(|| {
                    LauncherError::new("LAUTH_EXPIRED: launch authorization has expired")
                })?,
                NANOSECONDS_PER_SECOND
                    .checked_sub(realtime_nanoseconds)
                    .ok_or_else(|| {
                        LauncherError::new(
                            "launch authorization realtime conversion underflow",
                        )
                })?,
            )
        };
        let deadline = boottime_sample
            .checked_add_timespec_delta(remaining_seconds, remaining_nanoseconds)?;
        deadline.to_timespec()?;
        Ok(deadline)
    }

    fn operation_deadline_from_authorization(
        statement: &LaunchAuthorizationStatement,
    ) -> Result<BoottimeInstant> {
        // Sample suspend-aware monotonic time first so time spent reading
        // trusted realtime can only shorten, never extend, the signed expiry.
        let boottime_sample = boottime_now()?;
        let realtime_sample = realtime_timespec()?;
        operation_deadline_from_samples(statement, boottime_sample, realtime_sample)
    }

    fn require_operation_deadline_current(
        operation_deadline: &BoottimeInstant,
    ) -> Result<()> {
        if boottime_now()? >= *operation_deadline {
            return Err(LauncherError::new(
                "LAUTH_EXPIRED: launch authorization operation deadline has expired",
            ));
        }
        Ok(())
    }

    fn sleep_until_next_phase_deadline_check(
        operation_deadline: &BoottimeInstant,
    ) -> Result<()> {
        let now = boottime_now()?;
        if now >= *operation_deadline {
            return Ok(());
        }
        let poll_nanoseconds = PHASE_SUPERVISION_POLL_MILLIS
            .checked_mul(1_000_000)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| LauncherError::new("phase supervision interval overflow"))?;
        let poll_deadline = now.checked_add_timespec_delta(0, poll_nanoseconds)?;
        let wake_at = std::cmp::min(poll_deadline, *operation_deadline).to_timespec()?;
        loop {
            // SAFETY: wake_at is a normalized absolute CLOCK_BOOTTIME timestamp.
            let result = unsafe {
                libc::clock_nanosleep(
                    libc::CLOCK_BOOTTIME,
                    libc::TIMER_ABSTIME,
                    &wake_at,
                    std::ptr::null_mut(),
                )
            };
            if result == 0 {
                return Ok(());
            }
            if result != libc::EINTR {
                return Err(LauncherError::new(format!(
                    "could not wait for the next suspend-aware phase deadline check: {}",
                    std::io::Error::from_raw_os_error(result),
                )));
            }
        }
    }

    fn build_authorization_request(
        verified: &VerifiedLaunch,
        launcher_nonce: String,
        boot_id_sha256: String,
        witness_challenge: String,
    ) -> Result<LaunchAuthorizationRequest> {
        let release_provenance = verified
            .inputs
            .get("releaseProvenance")
            .ok_or_else(|| LauncherError::new("release provenance input is missing"))?;
        let reproducible_build = verified
            .inputs
            .get("reproducibleBuildVerification")
            .ok_or_else(|| LauncherError::new("reproducible build input is missing"))?;
        let mut request = LaunchAuthorizationRequest {
            api_version: AUTHORIZATION_REQUEST_API_VERSION.to_string(),
            kind: AUTHORIZATION_REQUEST_KIND.to_string(),
            launcher_nonce,
            boot_id_sha256,
            launcher_sha256: verified.launcher.sha256.clone(),
            manifest_sha256: verified.manifest_receipt.sha256.clone(),
            global_role_registry: verified
                .manifest
                .global_role_registry
                .registry
                .clone(),
            global_role_registry_sha256: verified
                .manifest
                .global_role_registry
                .registry_sha256
                .clone(),
            global_role_registry_pins_sha256: verified
                .manifest
                .global_role_registry
                .pins_file
                .sha256
                .clone(),
            nonce_rollback_assurance_contract_sha256: verified
                .manifest
                .nonce_rollback_assurance
                .contract_sha256
                .clone(),
            nonce_rollback_assurance_pins_sha256: verified
                .manifest
                .nonce_rollback_assurance
                .pins_file
                .sha256
                .clone(),
            release_provenance_sha256: release_provenance.sha256.clone(),
            provenance_digest: verified.provenance_digest.clone(),
            reproducible_build_verification_sha256: reproducible_build.sha256.clone(),
            source_tree_digest: verified.manifest.source_tree_digest.clone(),
            deployment_audience: verified.manifest.authorization.deployment_audience.clone(),
            deployment_identity_sha256: verified
                .manifest
                .authorization
                .deployment_identity_sha256
                .clone(),
            release_sequence: verified.manifest.authorization.release_sequence,
            rollback_epoch: verified.manifest.authorization.rollback_epoch,
            authorization_scope: verified
                .manifest
                .authorization
                .authorization_scope
                .clone(),
            freshness_authority: verified
                .manifest
                .authorization
                .freshness_authority
                .clone(),
            launch_attempt_journal_domain: verified
                .manifest
                .launch_attempt_journal
                .domain
                .clone(),
            launch_attempt_recovery_identity_sha256: String::new(),
            launch_authority_witness_challenge: witness_challenge,
            launch_authority_witness_key_id: verified
                .manifest
                .authorization
                .monotonic_witness
                .signing_key_id
                .clone(),
            launch_authority_witness_identity_sha256: verified
                .manifest
                .authorization
                .monotonic_witness
                .identity_sha256
                .clone(),
            launch_authority_witness_administrative_domain_sha256: verified
                .manifest
                .authorization
                .monotonic_witness
                .administrative_domain_sha256
                .clone(),
            launch_authority_witness_store_assurance_sha256: verified
                .manifest
                .authorization
                .monotonic_witness
                .store_assurance_sha256
                .clone(),
        };
        request.launch_attempt_recovery_identity_sha256 =
            launch_attempt_recovery_identity_sha256(&request)?;
        Ok(request)
    }

    fn state_file_name(
        path: &Path,
        state_directory: &Path,
        label: &str,
    ) -> Result<CString> {
        validate_output_path(path, state_directory, label)?;
        let name = path
            .file_name()
            .ok_or_else(|| LauncherError::new(format!("{label} has no file name")))?;
        cstring_bytes(name.as_bytes(), label)
    }

    fn fsync_directory(fd: RawFd, label: &str) -> Result<()> {
        // SAFETY: fd is a retained directory descriptor.
        if unsafe { libc::fsync(fd) } != 0 {
            return Err(errno_message(&format!("could not fsync {label}")));
        }
        Ok(())
    }

    fn require_secure_attempt_state_file(
        identity: FileIdentity,
        label: &str,
        allow_empty: bool,
    ) -> Result<()> {
        if identity.mode & libc::S_IFMT != libc::S_IFREG
            || identity.owner_uid != 0
            || identity.owner_gid != 0
            || identity.link_count != 1
            || identity.mode & 0o7777 != 0o600
            || identity.size > MAX_ATTEMPT_JOURNAL_BYTES
            || (!allow_empty && identity.size == 0)
        {
            return Err(LauncherError::new(format!(
                "{label} must be root:root, mode 0600, single-linked, regular, and bounded"
            )));
        }
        Ok(())
    }

    fn acquire_attempt_journal_lock(
        verified: &VerifiedLaunch,
    ) -> Result<LaunchAttemptJournalGuard> {
        let name = state_file_name(
            &verified.manifest.launch_attempt_journal.lock_path,
            &verified.manifest.state_directory,
            "launchAttemptJournal.lockPath",
        )?;
        // SAFETY: the retained state directory and NUL-terminated leaf are valid.
        let raw_fd = unsafe {
            libc::openat(
                verified.state_directory_fd.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR
                    | libc::O_CREAT
                    | libc::O_CLOEXEC
                    | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if raw_fd < 0 {
            return Err(errno_message(
                "could not open launch attempt journal lock",
            ));
        }
        // SAFETY: raw_fd is newly returned and uniquely owned.
        let lock = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        require_secure_attempt_state_file(
            fstat(
                lock.as_raw_fd(),
                "could not inspect launch attempt journal lock",
            )?,
            "launch attempt journal lock",
            true,
        )?;
        // SAFETY: lock is an open regular file retained for the process lifetime.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(LauncherError::new(
                "LAUTH_CONCURRENT_ATTEMPT: another native launcher owns the attempt journal",
            ));
        }
        fsync_directory(
            verified.state_directory_fd.as_raw_fd(),
            "launch attempt journal directory",
        )?;
        Ok(LaunchAttemptJournalGuard { _lock: lock })
    }

    fn validate_attempt_journal(
        value: LaunchAttemptJournal,
        configuration: &LaunchAttemptJournalConfiguration,
    ) -> Result<LaunchAttemptJournal> {
        if value.api_version != ATTEMPT_JOURNAL_API_VERSION
            || value.kind != ATTEMPT_JOURNAL_KIND
            || value.domain != configuration.domain
            || !matches!(
                value.state.as_str(),
                "prepared" | "authorization-verified"
            )
            || value.request.api_version != AUTHORIZATION_REQUEST_API_VERSION
            || value.request.kind != AUTHORIZATION_REQUEST_KIND
            || value.request.launch_attempt_journal_domain
                != configuration.domain
            || value.request.launch_attempt_recovery_identity_sha256
                != launch_attempt_recovery_identity_sha256(&value.request)?
            || value.request_sha256 != authorization_request_digest(&value.request)?
            || value.recovery_identity_sha256
                != value.request.launch_attempt_recovery_identity_sha256
        {
            return Err(LauncherError::new(
                "LAUTH_JOURNAL_INVALID: launch attempt journal binding is invalid",
            ));
        }
        Ok(value)
    }

    fn read_attempt_journal_with_identity(
        verified: &VerifiedLaunch,
    ) -> Result<Option<ReadLaunchAttemptJournal>> {
        let name = state_file_name(
            &verified.manifest.launch_attempt_journal.path,
            &verified.manifest.state_directory,
            "launchAttemptJournal.path",
        )?;
        // SAFETY: the retained state directory and NUL-terminated leaf are valid.
        let raw_fd = unsafe {
            libc::openat(
                verified.state_directory_fd.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if raw_fd < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                return Ok(None);
            }
            return Err(errno_message("could not open launch attempt journal"));
        }
        // SAFETY: raw_fd is newly returned and uniquely owned.
        let mut file = File::from(unsafe { OwnedFd::from_raw_fd(raw_fd) });
        let before = fstat(
            file.as_raw_fd(),
            "could not inspect launch attempt journal",
        )?;
        require_secure_attempt_state_file(before, "launch attempt journal", false)?;
        let max_bytes = verified.manifest.launch_attempt_journal.max_bytes;
        let mut bytes = Vec::with_capacity(before.size.min(max_bytes) as usize);
        (&mut file)
            .take(max_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| LauncherError::new("could not read launch attempt journal"))?;
        if bytes.len() as u64 > max_bytes {
            return Err(LauncherError::new(
                "LAUTH_JOURNAL_INVALID: launch attempt journal exceeds its manifest-bound limit",
            ));
        }
        let after = fstat(
            file.as_raw_fd(),
            "could not re-inspect launch attempt journal",
        )?;
        if before != after || bytes.len() as u64 != before.size {
            return Err(LauncherError::new(
                "launch attempt journal changed while it was read",
            ));
        }
        let value: LaunchAttemptJournal = serde_json::from_slice(&bytes)
            .map_err(|_| LauncherError::new("LAUTH_JOURNAL_INVALID: journal JSON is invalid"))?;
        let mut canonical = canonical_json_bytes(&value)?;
        canonical.push(b'\n');
        if bytes != canonical {
            return Err(LauncherError::new(
                "LAUTH_JOURNAL_INVALID: journal is not canonical JSON plus LF",
            ));
        }
        Ok(Some(ReadLaunchAttemptJournal {
            value: validate_attempt_journal(
                value,
                &verified.manifest.launch_attempt_journal,
            )?,
            identity: after,
        }))
    }

    fn read_attempt_journal(
        verified: &VerifiedLaunch,
    ) -> Result<Option<LaunchAttemptJournal>> {
        Ok(read_attempt_journal_with_identity(verified)?
            .map(|journal| journal.value))
    }

    fn write_attempt_journal(
        verified: &VerifiedLaunch,
        value: &LaunchAttemptJournal,
    ) -> Result<()> {
        validate_attempt_journal(
            value.clone(),
            &verified.manifest.launch_attempt_journal,
        )?;
        let mut bytes = canonical_json_bytes(value)?;
        bytes.push(b'\n');
        if bytes.len() as u64 > verified.manifest.launch_attempt_journal.max_bytes {
            return Err(LauncherError::new(
                "launch attempt journal exceeds its manifest-bound limit",
            ));
        }
        if let Some(existing) = read_attempt_journal(verified)? {
            if existing.request_sha256 != value.request_sha256
                || existing.recovery_identity_sha256
                    != value.recovery_identity_sha256
            {
                return Err(LauncherError::new(
                    "LAUTH_CONCURRENT_ATTEMPT: refusing to replace a different prepared operation",
                ));
            }
        }
        let target = state_file_name(
            &verified.manifest.launch_attempt_journal.path,
            &verified.manifest.state_directory,
            "launchAttemptJournal.path",
        )?;
        let temporary_name = format!(
            ".serverware-launch-attempt-{}.tmp",
            random_launch_id()?
        );
        let temporary = cstring_bytes(
            temporary_name.as_bytes(),
            "launch attempt journal temporary file",
        )?;
        // SAFETY: the retained state directory and NUL-terminated leaf are valid.
        let raw_fd = unsafe {
            libc::openat(
                verified.state_directory_fd.as_raw_fd(),
                temporary.as_ptr(),
                libc::O_WRONLY
                    | libc::O_CREAT
                    | libc::O_EXCL
                    | libc::O_CLOEXEC
                    | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if raw_fd < 0 {
            return Err(errno_message(
                "could not create launch attempt journal temporary file",
            ));
        }
        // SAFETY: raw_fd is newly returned and uniquely owned.
        let mut file = File::from(unsafe { OwnedFd::from_raw_fd(raw_fd) });
        let write_result = (|| {
            require_secure_attempt_state_file(
                fstat(
                    file.as_raw_fd(),
                    "could not inspect launch attempt journal temporary file",
                )?,
                "launch attempt journal temporary file",
                true,
            )?;
            file.write_all(&bytes)
                .map_err(|_| LauncherError::new("could not write launch attempt journal"))?;
            file.flush()
                .map_err(|_| LauncherError::new("could not flush launch attempt journal"))?;
            // SAFETY: file is a regular file owned by this process.
            if unsafe { libc::fsync(file.as_raw_fd()) } != 0 {
                return Err(errno_message("could not fsync launch attempt journal"));
            }
            require_secure_attempt_state_file(
                fstat(
                    file.as_raw_fd(),
                    "could not re-inspect launch attempt journal temporary file",
                )?,
                "launch attempt journal temporary file",
                false,
            )?;
            // SAFETY: both leaf names are relative to the retained state directory.
            if unsafe {
                libc::renameat(
                    verified.state_directory_fd.as_raw_fd(),
                    temporary.as_ptr(),
                    verified.state_directory_fd.as_raw_fd(),
                    target.as_ptr(),
                )
            } != 0
            {
                return Err(errno_message("could not publish launch attempt journal"));
            }
            fsync_directory(
                verified.state_directory_fd.as_raw_fd(),
                "launch attempt journal directory",
            )
        })();
        if write_result.is_err() {
            // SAFETY: best-effort removal of the task-owned temporary leaf.
            unsafe {
                libc::unlinkat(
                    verified.state_directory_fd.as_raw_fd(),
                    temporary.as_ptr(),
                    0,
                )
            };
        }
        write_result?;
        let published = read_attempt_journal(verified)?.ok_or_else(|| {
            LauncherError::new("published launch attempt journal disappeared")
        })?;
        if published != *value {
            return Err(LauncherError::new(
                "published launch attempt journal does not match exact bytes",
            ));
        }
        Ok(())
    }

    fn remove_attempt_journal(verified: &VerifiedLaunch) -> Result<()> {
        let name = state_file_name(
            &verified.manifest.launch_attempt_journal.path,
            &verified.manifest.state_directory,
            "launchAttemptJournal.path",
        )?;
        let Some(journal) = read_attempt_journal_with_identity(verified)? else {
            return Ok(());
        };
        let pathname_identity = fstatat_nofollow(
            verified.state_directory_fd.as_raw_fd(),
            &name,
            "could not re-inspect launch attempt journal pathname",
        )?
        .ok_or_else(|| {
            LauncherError::new(
                "launch attempt journal disappeared before terminal finalization",
            )
        })?;
        require_secure_attempt_state_file(
            pathname_identity,
            "launch attempt journal pathname",
            false,
        )?;
        if pathname_identity != journal.identity {
            return Err(LauncherError::new(
                "launch attempt journal pathname no longer names the exact inode that was read",
            ));
        }
        // SAFETY: the retained state directory and NUL-terminated leaf are valid.
        if unsafe {
            libc::unlinkat(
                verified.state_directory_fd.as_raw_fd(),
                name.as_ptr(),
                0,
            )
        } != 0
        {
            return Err(errno_message("could not remove launch attempt journal"));
        }
        fsync_directory(
            verified.state_directory_fd.as_raw_fd(),
            "launch attempt journal directory",
        )?;
        if read_attempt_journal(verified)?.is_some() {
            return Err(LauncherError::new(
                "launch attempt journal remained after terminal finalization",
            ));
        }
        Ok(())
    }

    fn poll_socket(
        fd: RawFd,
        events: libc::c_short,
        deadline: Instant,
        timeout_code: &str,
    ) -> Result<()> {
        let mut poll_fd = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(LauncherError::new(format!(
                    "{timeout_code}: launch authority relay timed out"
                )));
            }
            let timeout_millis = remaining
                .as_millis()
                .min(AUTHORIZATION_TIMEOUT_MILLIS as u128)
                .max(1) as i32;
            // SAFETY: poll_fd points to one initialized poll descriptor.
            let result = unsafe { libc::poll(&mut poll_fd, 1, timeout_millis) };
            if result > 0 {
                if poll_fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                    return Err(LauncherError::new(
                        "LAUTH_SOCKET_UNAVAILABLE: launch authority relay failed",
                    ));
                }
                if poll_fd.revents & events != 0 {
                    return Ok(());
                }
                return Err(LauncherError::new(
                    "LAUTH_SOCKET_UNAVAILABLE: launch authority relay returned invalid readiness",
                ));
            }
            if result == 0 {
                return Err(LauncherError::new(format!(
                    "{timeout_code}: launch authority relay timed out"
                )));
            }
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                return Err(errno_message(
                    "LAUTH_SOCKET_UNAVAILABLE: could not poll launch authority relay",
                ));
            }
        }
    }

    fn connect_authority_socket(deadline: Instant) -> Result<OwnedFd> {
        let metadata = std::fs::symlink_metadata(AUTHORIZATION_SOCKET_PATH).map_err(|_| {
            LauncherError::new("LAUTH_SOCKET_UNAVAILABLE: launch authority socket is unavailable")
        })?;
        if !metadata.file_type().is_socket()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o002 != 0
        {
            return Err(LauncherError::new(
                "LAUTH_PEER_INVALID: launch authority socket metadata is not trusted",
            ));
        }

        // SAFETY: socket arguments describe a Unix sequenced-packet socket.
        let raw_fd = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        };
        if raw_fd < 0 {
            return Err(errno_message(
                "LAUTH_SOCKET_UNAVAILABLE: could not create launch authority socket",
            ));
        }
        // SAFETY: raw_fd is newly allocated and ownership transfers to OwnedFd.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        let path = AUTHORIZATION_SOCKET_PATH.as_bytes();
        if path.len() + 1
            > unsafe { std::mem::zeroed::<libc::sockaddr_un>() }
                .sun_path
                .len()
        {
            return Err(LauncherError::new(
                "LAUTH_SOCKET_UNAVAILABLE: launch authority socket path is too long",
            ));
        }
        // SAFETY: sockaddr_un is valid when zero-initialized before its fields are assigned.
        let mut address = unsafe { std::mem::zeroed::<libc::sockaddr_un>() };
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (target, source) in address.sun_path.iter_mut().zip(path.iter().copied()) {
            *target = source as libc::c_char;
        }
        let address_length = (size_of::<libc::sa_family_t>() + path.len() + 1)
            .try_into()
            .map_err(|_| LauncherError::new("launch authority socket path length is invalid"))?;
        // SAFETY: address contains a NUL-terminated Unix socket path for address_length bytes.
        let connect_result = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_un).cast(),
                address_length,
            )
        };
        if connect_result != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINPROGRESS) {
                return Err(LauncherError::new(format!(
                    "LAUTH_SOCKET_UNAVAILABLE: could not connect to launch authority relay: {error}"
                )));
            }
            poll_socket(fd.as_raw_fd(), libc::POLLOUT, deadline, "LAUTH_TIMEOUT")?;
            let mut socket_error: libc::c_int = 0;
            let mut socket_error_length = size_of::<libc::c_int>() as libc::socklen_t;
            // SAFETY: output pointers describe one socket error integer.
            if unsafe {
                libc::getsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    (&mut socket_error as *mut libc::c_int).cast(),
                    &mut socket_error_length,
                )
            } != 0
                || socket_error != 0
            {
                return Err(LauncherError::new(
                    "LAUTH_SOCKET_UNAVAILABLE: launch authority relay rejected the connection",
                ));
            }
        }

        let mut credentials = MaybeUninit::<libc::ucred>::uninit();
        let mut credentials_length = size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: output pointers describe one ucred structure.
        if unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                credentials.as_mut_ptr().cast(),
                &mut credentials_length,
            )
        } != 0
            || credentials_length as usize != size_of::<libc::ucred>()
        {
            return Err(LauncherError::new(
                "LAUTH_PEER_INVALID: could not authenticate launch authority relay peer",
            ));
        }
        // SAFETY: successful getsockopt initialized credentials.
        let credentials = unsafe { credentials.assume_init() };
        if credentials.uid != 0 || credentials.gid != 0 {
            return Err(LauncherError::new(
                "LAUTH_PEER_INVALID: launch authority relay must run as root",
            ));
        }
        Ok(fd)
    }

    fn exchange_launch_authorization_once(
        request: &LaunchAuthorizationRequest,
        witness_configuration: &LaunchAuthorityWitnessConfiguration,
        time_policy: AuthorizationTimePolicy,
    ) -> Result<ReceiptLaunchAuthorization> {
        let request_bytes = canonical_json_bytes(&request)?;
        if request_bytes.len() > AUTHORIZATION_MAX_BYTES {
            return Err(LauncherError::new(
                "LAUTH_FRAME_INVALID: launch authorization request is too large",
            ));
        }
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(AUTHORIZATION_TIMEOUT_MILLIS as u64))
            .ok_or_else(|| LauncherError::new("launch authorization deadline overflow"))?;
        let key = compiled_authority_public_key()?;
        let fd = connect_authority_socket(deadline)?;
        poll_socket(fd.as_raw_fd(), libc::POLLOUT, deadline, "LAUTH_TIMEOUT")?;
        // SAFETY: request_bytes is readable and fd is a connected sequenced-packet socket.
        let sent = unsafe {
            libc::send(
                fd.as_raw_fd(),
                request_bytes.as_ptr().cast(),
                request_bytes.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if sent < 0 || sent as usize != request_bytes.len() {
            return Err(LauncherError::new(
                "LAUTH_FRAME_INVALID: launch authorization request was not sent atomically",
            ));
        }

        poll_socket(fd.as_raw_fd(), libc::POLLIN, deadline, "LAUTH_TIMEOUT")?;
        let mut response = vec![0u8; AUTHORIZATION_MAX_BYTES];
        // SAFETY: response is writable and MSG_TRUNC reports the complete packet length.
        let received = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                response.as_mut_ptr().cast(),
                response.len(),
                libc::MSG_TRUNC,
            )
        };
        if received <= 0 || received as usize > response.len() {
            return Err(LauncherError::new(
                "LAUTH_FRAME_INVALID: launch authorization response is empty or truncated",
            ));
        }
        response.truncate(received as usize);
        let envelope: LaunchAuthorizationEnvelope =
            serde_json::from_slice(&response).map_err(|_| {
                LauncherError::new(
                    "LAUTH_SCHEMA_INVALID: launch authorization response is invalid JSON",
                )
            })?;
        let canonical = canonical_json_bytes(&envelope)?;
        if canonical != response {
            return Err(LauncherError::new(
                "LAUTH_FRAME_INVALID: launch authorization response is not canonical JSON",
            ));
        }
        verify_launch_authorization(
            request.clone(),
            envelope,
            &key,
            witness_configuration,
            unix_time_seconds()?,
            time_policy,
        )
    }

    fn retryable_authority_exchange_error(error: &LauncherError) -> bool {
        [
            "LAUTH_SOCKET_UNAVAILABLE:",
            "LAUTH_TIMEOUT:",
            "LAUTH_FRAME_INVALID:",
        ]
        .iter()
        .any(|prefix| error.0.starts_with(prefix))
    }

    fn exchange_launch_authorization(
        request: &LaunchAuthorizationRequest,
        witness_configuration: &LaunchAuthorityWitnessConfiguration,
        time_policy: AuthorizationTimePolicy,
    ) -> Result<ReceiptLaunchAuthorization> {
        let mut last_error = None;
        for attempt in 0..AUTHORIZATION_MAX_EXCHANGE_ATTEMPTS {
            match exchange_launch_authorization_once(
                request,
                witness_configuration,
                time_policy,
            ) {
                Ok(value) => return Ok(value),
                Err(error)
                    if attempt + 1 < AUTHORIZATION_MAX_EXCHANGE_ATTEMPTS
                        && retryable_authority_exchange_error(&error) =>
                {
                    last_error = Some(error);
                }
                Err(error) => return Err(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            LauncherError::new("LAUTH_SOCKET_UNAVAILABLE: authority exchange did not run")
        }))
    }

    fn attempt_journal_for_request(
        request: LaunchAuthorizationRequest,
        state: &str,
    ) -> Result<LaunchAttemptJournal> {
        let request_sha256 = authorization_request_digest(&request)?;
        Ok(LaunchAttemptJournal {
            api_version: ATTEMPT_JOURNAL_API_VERSION.to_string(),
            kind: ATTEMPT_JOURNAL_KIND.to_string(),
            domain: ATTEMPT_JOURNAL_DOMAIN.to_string(),
            state: state.to_string(),
            recovery_identity_sha256:
                launch_attempt_recovery_identity_sha256(&request)?,
            request,
            request_sha256,
        })
    }

    pub(super) fn recovered_request_matches_current_launch(
        recovered: &LaunchAuthorizationRequest,
        current: &LaunchAuthorizationRequest,
    ) -> bool {
        recovered == current
    }

    fn recover_or_create_launch_authorization(
        verified: &VerifiedLaunch,
    ) -> Result<ReceiptLaunchAuthorization> {
        let witness = &verified.manifest.authorization.monotonic_witness;
        let current_boot_id_sha256 = boot_id_digest()?;

        if let Some(journal) = read_attempt_journal(verified)? {
            let current_request_for_operation = build_authorization_request(
                verified,
                journal.request.launcher_nonce.clone(),
                current_boot_id_sha256.clone(),
                journal
                    .request
                    .launch_authority_witness_challenge
                    .clone(),
            )?;
            let recovered_request_is_current =
                recovered_request_matches_current_launch(
                    &journal.request,
                    &current_request_for_operation,
                );
            let recovered = exchange_launch_authorization(
                &journal.request,
                witness,
                AuthorizationTimePolicy::RecoveryMayBeExpired,
            )?;
            let terminal = attempt_journal_for_request(
                journal.request.clone(),
                "authorization-verified",
            )?;
            write_attempt_journal(verified, &terminal)?;
            // A successful exact replay is the relay contract's confirmation that
            // the same durable issuance saga committed and that its witness
            // successor is still the current head. The host journal itself is
            // never accepted as rollback authority.
            remove_attempt_journal(verified)?;
            if recovered_request_is_current
                && require_authorization_current(
                    &recovered.envelope.statement,
                    unix_time_seconds()?,
                )
                .is_ok()
            {
                return Ok(recovered);
            }
        }

        for _ in 0..AUTHORIZATION_MAX_FRESH_ATTEMPTS {
            let request = build_authorization_request(
                verified,
                random_launch_id()?,
                current_boot_id_sha256.clone(),
                random_launch_id()?,
            )?;
            let prepared = attempt_journal_for_request(request.clone(), "prepared")?;
            write_attempt_journal(verified, &prepared)?;
            let authorization = exchange_launch_authorization(
                &request,
                witness,
                AuthorizationTimePolicy::RecoveryMayBeExpired,
            )?;
            let terminal = attempt_journal_for_request(
                request,
                "authorization-verified",
            )?;
            write_attempt_journal(verified, &terminal)?;
            remove_attempt_journal(verified)?;
            if require_authorization_current(
                &authorization.envelope.statement,
                unix_time_seconds()?,
            )
            .is_ok()
            {
                return Ok(authorization);
            }
        }
        Err(LauncherError::new(
            "LAUTH_EXPIRED: exact saga recovery completed, but no current authorization was available",
        ))
    }

    fn build_receipt(
        verified: &VerifiedLaunch,
        launch_authorization: ReceiptLaunchAuthorization,
        preflight_argv: &[String],
        readiness_argv: &[String],
    ) -> Result<BootstrapReceipt> {
        Ok(BootstrapReceipt {
            api_version: RECEIPT_API_VERSION.to_string(),
            kind: RECEIPT_KIND.to_string(),
            launch_id: launch_authorization.request.launcher_nonce.clone(),
            boot_id_sha256: launch_authorization.request.boot_id_sha256.clone(),
            launcher: verified.launcher.clone(),
            manifest: verified.manifest_receipt.clone(),
            source_tree_digest: verified.manifest.source_tree_digest.clone(),
            launch_authorization,
            nonce_rollback_assurance: ReceiptNonceRollbackAssurance {
                api_version: NONCE_ROLLBACK_ASSURANCE_BINDING_API_VERSION.to_string(),
                contract_sha256: verified
                    .manifest
                    .nonce_rollback_assurance
                    .contract_sha256
                    .clone(),
                pins_file: verified.nonce_rollback_assurance_pins.receipt.clone(),
                retained_snapshot_fd: verified
                    .nonce_rollback_assurance_pins
                    .snapshot
                    .as_raw_fd(),
                retained_snapshot_sha256: verified
                    .manifest
                    .nonce_rollback_assurance
                    .pins_file
                    .sha256
                    .clone(),
                verifier_state_service: ReceiptVerifierStateService {
                    signing_public_key_spki_der_base64url: verified
                        .manifest
                        .nonce_rollback_assurance
                        .contract
                        .public_config_pins
                        .nonce_authority_verifier_state_signing_public_key_spki_der_base64url
                        .clone(),
                    store_administrative_domain_sha256: verified
                        .manifest
                        .nonce_rollback_assurance
                        .contract
                        .public_config_pins
                        .nonce_authority_verifier_state_store_administrative_domain_sha256
                        .clone(),
                    store_assurance_evidence_sha256: verified
                        .manifest
                        .nonce_rollback_assurance
                        .contract
                        .public_config_pins
                        .nonce_authority_verifier_state_store_assurance_evidence_sha256
                        .clone(),
                    store_attestation_public_key_spki_der_base64url: verified
                        .manifest
                        .nonce_rollback_assurance
                        .contract
                        .public_config_pins
                        .nonce_authority_verifier_state_store_attestation_public_key_spki_der_base64url
                        .clone(),
                    store_identity_sha256: verified
                        .manifest
                        .nonce_rollback_assurance
                        .contract
                        .public_config_pins
                        .nonce_authority_verifier_state_store_identity_sha256
                        .clone(),
                },
            },
            production_env: verified.production_env.clone(),
            python: ReceiptPython {
                path: verified.python.receipt.path.clone(),
                sha256: verified.python.receipt.sha256.clone(),
                metadata: verified.python.receipt.metadata.clone(),
                import_roots: verified
                    .import_roots
                    .iter()
                    .map(|root| root.receipt.clone())
                    .collect(),
            },
            scripts: ReceiptScripts {
                preflight: verified.preflight.receipt.clone(),
                runner: verified.runner.receipt.clone(),
            },
            compose_file: verified.compose_file.clone(),
            inputs: verified.inputs.clone(),
            argv: ReceiptArgv {
                preflight_sha256: argv_digest(preflight_argv)?,
                readiness_sha256: argv_digest(readiness_argv)?,
            },
            environment: environment_commitment()?,
        })
    }

    fn reserve_receipt_fd() -> Result<OwnedFd> {
        let reservation = create_sealable_memfd(
            c"serverware-bootstrap-receipt-reservation",
            "bootstrap receipt descriptor reservation",
        )?;
        if reservation.as_raw_fd() == RECEIPT_FD {
            return Ok(reservation.into());
        }
        // SAFETY: dup3 atomically replaces any inherited fixed descriptor and
        // keeps the reservation closed across exec until the receipt is ready.
        if unsafe {
            libc::dup3(
                reservation.as_raw_fd(),
                RECEIPT_FD,
                libc::O_CLOEXEC,
            )
        } < 0
        {
            return Err(errno_message(
                "could not reserve fixed bootstrap receipt descriptor",
            ));
        }
        // SAFETY: RECEIPT_FD is now uniquely owned independently of reservation.
        Ok(unsafe { OwnedFd::from_raw_fd(RECEIPT_FD) })
    }

    fn create_sealed_receipt(
        bytes: &[u8],
        reservation: OwnedFd,
    ) -> Result<OwnedFd> {
        if reservation.as_raw_fd() != RECEIPT_FD {
            return Err(LauncherError::new(
                "bootstrap receipt descriptor reservation is invalid",
            ));
        }
        let name = c"serverware-bootstrap-receipt";
        let mut file = create_sealable_memfd(name, "bootstrap receipt")?;
        file.write_all(bytes)
            .map_err(|_| LauncherError::new("could not write bootstrap receipt"))?;
        let file = seal_memfd(file, "bootstrap receipt")?;
        if file.as_raw_fd() == RECEIPT_FD {
            return Err(LauncherError::new(
                "bootstrap receipt allocation collided with its reserved descriptor",
            ));
        }
        let reserved_fd = reservation.into_raw_fd();
        // SAFETY: dup3 atomically replaces the fixed descriptor and clears CLOEXEC.
        if unsafe { libc::dup3(file.as_raw_fd(), RECEIPT_FD, 0) } < 0 {
            // SAFETY: ownership of the reservation was relinquished above.
            unsafe { libc::close(reserved_fd) };
            return Err(errno_message(
                "could not install fixed bootstrap receipt descriptor",
            ));
        }
        // SAFETY: RECEIPT_FD is now uniquely owned independently of file.
        Ok(unsafe { OwnedFd::from_raw_fd(RECEIPT_FD) })
    }

    fn clear_cloexec(fd: RawFd) -> Result<()> {
        // SAFETY: fd is valid.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            return Err(errno_message(
                "could not inspect inherited descriptor flags",
            ));
        }
        // SAFETY: fd is valid and flags only clears FD_CLOEXEC.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } != 0 {
            return Err(errno_message("could not retain measured descriptor"));
        }
        Ok(())
    }

    fn close_range_segment(first: u32, last: u32) -> bool {
        if first > last {
            return true;
        }
        // SAFETY: close_range has no memory-safety preconditions.
        unsafe { libc::syscall(libc::SYS_close_range, first, last, 0) == 0 }
    }

    fn close_unrelated_descriptors(keep: &[RawFd]) -> Result<()> {
        let mut retained = keep
            .iter()
            .copied()
            .filter(|fd| *fd >= 3)
            .collect::<Vec<_>>();
        retained.sort_unstable();
        retained.dedup();
        let mut first = 3u32;
        for fd in &retained {
            let fd = *fd as u32;
            if first < fd && !close_range_segment(first, fd - 1) {
                return close_unrelated_descriptors_fallback(&retained);
            }
            first = fd.saturating_add(1);
        }
        if !close_range_segment(first, u32::MAX) {
            return close_unrelated_descriptors_fallback(&retained);
        }
        Ok(())
    }

    fn close_unrelated_descriptors_fallback(keep: &[RawFd]) -> Result<()> {
        let entries = std::fs::read_dir("/proc/self/fd").map_err(|error| {
            LauncherError::new(format!(
                "could not enumerate inherited descriptors through /proc/self/fd: {error}"
            ))
        })?;
        let mut descriptors = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| {
                LauncherError::new(format!(
                    "could not enumerate inherited descriptors through /proc/self/fd: {error}"
                ))
            })?;
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(|| {
                LauncherError::new("/proc/self/fd contained a non-UTF-8 descriptor name")
            })?;
            let fd = name.parse::<RawFd>().map_err(|_| {
                LauncherError::new("/proc/self/fd contained an invalid descriptor name")
            })?;
            if fd >= 3 {
                descriptors.push(fd);
            }
        }
        descriptors.sort_unstable();
        descriptors.dedup();
        for fd in descriptors {
            if !keep.contains(&fd) {
                // SAFETY: closing an invalid descriptor is harmless here.
                unsafe { libc::close(fd) };
            }
        }
        Ok(())
    }

    fn python_bootstrap(script_fd: RawFd, import_fds: &[RawFd]) -> String {
        let roots = import_fds
            .iter()
            .map(|fd| format!("'/proc/self/fd/{fd}'"))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{PYTHON_BOOTSTRAP_PREFIX}fd={script_fd}\n\
             os.environ['SERVERWARE_EXECUTING_SCRIPT_FD']=str(fd)\n\
             _serverware_retained_import_paths=({roots},)\n\
             _serverware_allowed_import_paths=frozenset(_serverware_retained_import_paths)\n\
             def _serverware_retained_path(value):\n\
              return isinstance(value,str) and value in _serverware_allowed_import_paths\n\
             class _ServerwareRetainedPath(list):\n\
              def __setitem__(self,key,value):\n\
               if isinstance(key,slice): return super().__setitem__(key,[item for item in value if _serverware_retained_path(item)])\n\
               if _serverware_retained_path(value): return super().__setitem__(key,value)\n\
              def append(self,value):\n\
               if _serverware_retained_path(value): super().append(value)\n\
              def extend(self,values): super().extend(item for item in values if _serverware_retained_path(item))\n\
              def insert(self,index,value):\n\
               if _serverware_retained_path(value): super().insert(index,value)\n\
              def __iadd__(self,values):\n\
               self.extend(values); return self\n\
             sys.path=_ServerwareRetainedPath(_serverware_retained_import_paths)\n\
             sys.path_importer_cache.clear()\n\
             sys.argv=sys.argv[1:]\n\
             os.lseek(fd,0,os.SEEK_SET)\n\
             size=os.fstat(fd).st_size\n\
             data=b''\n\
             while len(data)<size:\n data+=os.read(fd,min(65536,size-len(data)))\n\
             if len(data)!=size: raise RuntimeError('measured Python script changed while executing')\n\
             scope={{'__name__':'__main__','__file__':sys.argv[0],'__package__':None,'__cached__':None}}\n\
             exec(compile(data,sys.argv[0],'exec',dont_inherit=True),scope,scope)"
        )
    }

    fn cstring_vector(values: &[String], label: &str) -> Result<Vec<CString>> {
        values
            .iter()
            .map(|value| {
                CString::new(value.as_bytes())
                    .map_err(|_| LauncherError::new(format!("{label} contains NUL")))
            })
            .collect()
    }

    fn child_error(message: &str) -> ! {
        let prefix = b"serverware production launcher child error: ";
        // SAFETY: static and borrowed byte buffers are valid for their lengths.
        unsafe {
            libc::write(libc::STDERR_FILENO, prefix.as_ptr().cast(), prefix.len());
            libc::write(libc::STDERR_FILENO, message.as_ptr().cast(), message.len());
            libc::write(libc::STDERR_FILENO, b"\n".as_ptr().cast(), 1);
            libc::_exit(126);
        }
    }

    fn create_phase_execution_barrier() -> Result<(OwnedFd, OwnedFd)> {
        let mut descriptors = [-1; 2];
        // SAFETY: descriptors points to storage for both pipe descriptors.
        if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(errno_message(
                "could not create production phase execution barrier",
            ));
        }
        // SAFETY: pipe2 returned two newly allocated, independently owned descriptors.
        let read_end = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
        // SAFETY: pipe2 returned two newly allocated, independently owned descriptors.
        let write_end = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
        Ok((read_end, write_end))
    }

    fn read_phase_barrier_byte(fd: RawFd, buffer: &mut [u8]) -> Result<usize> {
        loop {
            // SAFETY: buffer is writable for its length and fd is the barrier read end.
            let count = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
            if count >= 0 {
                return Ok(count as usize);
            }
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                return Err(errno_message(
                    "could not read production phase execution barrier",
                ));
            }
        }
    }

    fn consume_exact_phase_go_token(fd: RawFd) -> Result<()> {
        let mut token = [0u8; 1];
        if read_phase_barrier_byte(fd, &mut token)? != 1 {
            return Err(LauncherError::new(
                "production phase execution barrier closed before the go token",
            ));
        }
        if token[0] != PHASE_EXECUTION_GO_TOKEN {
            return Err(LauncherError::new(
                "production phase execution barrier returned the wrong go token",
            ));
        }
        let mut trailing = [0u8; 1];
        if read_phase_barrier_byte(fd, &mut trailing)? != 0 {
            return Err(LauncherError::new(
                "production phase execution barrier returned extra bytes",
            ));
        }
        Ok(())
    }

    fn release_phase_go_token(write_end: OwnedFd) -> Result<()> {
        let token = [PHASE_EXECUTION_GO_TOKEN];
        loop {
            // SAFETY: token is readable and write_end is the barrier write end.
            let count = unsafe {
                libc::write(
                    write_end.as_raw_fd(),
                    token.as_ptr().cast(),
                    token.len(),
                )
            };
            if count == 1 {
                drop(write_end);
                return Ok(());
            }
            if count < 0
                && std::io::Error::last_os_error().kind()
                    == std::io::ErrorKind::Interrupted
            {
                continue;
            }
            return Err(errno_message(
                "could not release production phase execution barrier",
            ));
        }
    }

    fn phase_status_code(status: libc::c_int) -> Result<i32> {
        if libc::WIFEXITED(status) {
            Ok(libc::WEXITSTATUS(status))
        } else if libc::WIFSIGNALED(status) {
            Ok(128 + libc::WTERMSIG(status))
        } else {
            Err(LauncherError::new(
                "production phase ended in an unsupported process state",
            ))
        }
    }

    fn wait_direct_child_nonblocking(child: libc::pid_t) -> Result<Option<i32>> {
        loop {
            let mut status = 0;
            // SAFETY: child is a direct child PID and status points to writable memory.
            let waited = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
            if waited == child {
                return phase_status_code(status).map(Some);
            }
            if waited == 0 {
                return Ok(None);
            }
            if waited < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
            }
            return Err(errno_message("could not inspect production phase child"));
        }
    }

    fn reap_phase_children_nonblocking(
        leader: libc::pid_t,
        leader_status: &mut Option<i32>,
    ) -> Result<bool> {
        for _ in 0..PHASE_REAP_BATCH_MAX {
            let mut status = 0;
            // SAFETY: the launcher is a subreaper and has no children other than
            // the active phase leader and descendants reparented from that leader.
            let waited = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if waited > 0 {
                let code = phase_status_code(status)?;
                if waited == leader {
                    *leader_status = Some(code);
                }
                continue;
            }
            if waited == 0 {
                return Ok(true);
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if error.raw_os_error() == Some(libc::ECHILD) {
                return Ok(false);
            }
            return Err(errno_message("could not reap production phase descendants"));
        }
        // A hostile phase may continuously create exiting adopted children.
        // Bound each reap batch so CLOCK_BOOTTIME supervision always runs.
        Ok(true)
    }

    fn phase_process_group_exists(process_group: libc::pid_t) -> Result<bool> {
        loop {
            // SAFETY: signal zero performs an existence and permission check only.
            if unsafe { libc::kill(-process_group, 0) } == 0 {
                return Ok(true);
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return match error.raw_os_error() {
                Some(libc::ESRCH) => Ok(false),
                Some(libc::EPERM) => Ok(true),
                _ => Err(errno_message(
                    "could not inspect production phase process group",
                )),
            };
        }
    }

    fn direct_phase_descendants(leader: libc::pid_t) -> Result<Vec<libc::pid_t>> {
        // PR_SET_CHILD_SUBREAPER makes an escaped or double-forked phase
        // descendant visible here as soon as its intermediate parent exits.
        // SAFETY: getpid has no memory-safety preconditions.
        let launcher_pid = unsafe { libc::getpid() };
        let children_path =
            format!("/proc/self/task/{launcher_pid}/children");
        let raw = std::fs::read_to_string(children_path).map_err(|_| {
            LauncherError::new("could not enumerate production phase descendants")
        })?;
        let mut descendants = Vec::new();
        for value in raw.split_ascii_whitespace() {
            let pid = value.parse::<libc::pid_t>().map_err(|_| {
                LauncherError::new(
                    "production phase descendant list contained an invalid PID",
                )
            })?;
            if pid > 0 && pid != leader {
                descendants.push(pid);
            }
        }
        descendants.sort_unstable();
        descendants.dedup();
        Ok(descendants)
    }

    fn signal_adopted_phase_descendants(
        leader: libc::pid_t,
        signal: libc::c_int,
    ) -> Result<()> {
        for descendant in direct_phase_descendants(leader)? {
            signal_phase_target(
                descendant,
                signal,
                "could not signal adopted production phase descendant",
            )?;
        }
        Ok(())
    }

    fn signal_phase_target(
        target: libc::pid_t,
        signal: libc::c_int,
        label: &str,
    ) -> Result<()> {
        loop {
            // SAFETY: target is either the verified child PID or its negative process-group ID.
            if unsafe { libc::kill(target, signal) } == 0 {
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if error.raw_os_error() == Some(libc::ESRCH) {
                return Ok(());
            }
            return Err(errno_message(label));
        }
    }

    fn signal_phase_processes(
        process_group: libc::pid_t,
        leader_status: Option<i32>,
        signal: libc::c_int,
    ) -> Result<()> {
        let group_result = signal_phase_target(
            -process_group,
            signal,
            "could not signal production phase process group",
        );
        let leader_result = if leader_status.is_none() {
            signal_phase_target(
                process_group,
                signal,
                "could not signal production phase leader",
            )
        } else {
            Ok(())
        };
        group_result.and(leader_result)
    }

    fn force_kill_and_reap_phase_processes(
        process_group: libc::pid_t,
        leader_status: &mut Option<i32>,
    ) -> Result<()> {
        let mut force_error =
            signal_phase_processes(process_group, *leader_status, libc::SIGKILL).err();
        let mut descendant_force_error =
            signal_adopted_phase_descendants(process_group, libc::SIGKILL).err();
        let mut reap_error = None;
        let mut group_inspection_error = None;
        let reap_deadline = Instant::now()
            .checked_add(Duration::from_millis(PHASE_FORCE_REAP_TIMEOUT_MILLIS))
            .ok_or_else(|| LauncherError::new("phase cleanup deadline overflow"))?;
        while Instant::now() < reap_deadline {
            if let Err(error) =
                signal_phase_processes(process_group, *leader_status, libc::SIGKILL)
            {
                if force_error.is_none() {
                    force_error = Some(error);
                }
            }
            if let Err(error) =
                signal_adopted_phase_descendants(process_group, libc::SIGKILL)
            {
                if descendant_force_error.is_none() {
                    descendant_force_error = Some(error);
                }
            }
            let has_children =
                match reap_phase_children_nonblocking(process_group, leader_status) {
                    Ok(value) => value,
                    Err(error) => {
                        if reap_error.is_none() {
                            reap_error = Some(error);
                        }
                        true
                    }
                };
            let process_group_exists =
                match phase_process_group_exists(process_group) {
                    Ok(value) => value,
                    Err(error) => {
                        if group_inspection_error.is_none() {
                            group_inspection_error = Some(error);
                        }
                        true
                    }
                };
            if leader_status.is_some()
                && !has_children
                && !process_group_exists
            {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(
                PHASE_SUPERVISION_POLL_MILLIS,
            ));
        }
        let detail = force_error
            .map(|error| format!("; force-kill error: {error}"))
            .unwrap_or_default();
        let descendant_detail = descendant_force_error
            .map(|error| format!("; descendant force-kill error: {error}"))
            .unwrap_or_default();
        let reap_detail = reap_error
            .map(|error| format!("; reap error: {error}"))
            .unwrap_or_default();
        let group_detail = group_inspection_error
            .map(|error| format!("; process-group inspection error: {error}"))
            .unwrap_or_default();
        Err(LauncherError::new(format!(
            "process-group force-kill and reap could not be proven before the cleanup deadline{detail}{descendant_detail}{reap_detail}{group_detail}"
        )))
    }

    fn terminate_phase_process_group(
        process_group: libc::pid_t,
        phase_name: &str,
        leader_status: &mut Option<i32>,
        reason: &str,
    ) -> Result<i32> {
        match force_kill_and_reap_phase_processes(process_group, leader_status) {
            Ok(()) => Err(LauncherError::new(format!(
                "LAUTH_PHASE_OUTCOME_UNKNOWN: {phase_name} {reason}; its process group, leader, and adopted descendants were immediately force-killed and reaped with SIGKILL and no later phase may run"
            ))),
            Err(error) => Err(LauncherError::new(format!(
                "LAUTH_PHASE_OUTCOME_UNKNOWN: {phase_name} {reason}; {error}; no later phase may run"
            ))),
        }
    }

    fn abort_phase_before_exec(
        child: libc::pid_t,
        write_end: OwnedFd,
        leader_status: &mut Option<i32>,
        error: LauncherError,
    ) -> Result<i32> {
        drop(write_end);
        match force_kill_and_reap_phase_processes(child, leader_status) {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(LauncherError::new(format!(
                "{error}; blocked phase cleanup failed: {cleanup_error}"
            ))),
        }
    }

    fn establish_phase_process_group_before_exec(
        child: libc::pid_t,
    ) -> Result<Option<i32>> {
        loop {
            // SAFETY: the parent may place its direct child into a group led by that child.
            if unsafe { libc::setpgid(child, child) } == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if error.raw_os_error() == Some(libc::ESRCH) {
                if let Some(status) = wait_direct_child_nonblocking(child)? {
                    return Ok(Some(status));
                }
            }
            return Err(LauncherError::new(
                "could not establish an isolated production phase process group before exec",
            ));
        }
        loop {
            // SAFETY: child is the direct child PID returned by fork.
            let process_group = unsafe { libc::getpgid(child) };
            if process_group == child {
                return Ok(None);
            }
            if process_group >= 0 {
                return Err(LauncherError::new(
                    "production phase child escaped its isolated process group before exec",
                ));
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if error.raw_os_error() == Some(libc::ESRCH) {
                if let Some(status) = wait_direct_child_nonblocking(child)? {
                    return Ok(Some(status));
                }
            }
            return Err(errno_message(
                "could not verify production phase process-group containment before exec",
            ));
        }
    }

    fn enable_phase_subreaper() -> Result<()> {
        // SAFETY: PR_SET_CHILD_SUBREAPER changes only this launcher's child-reaping policy.
        if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
            return Err(errno_message(
                "could not enable production phase descendant reaping",
            ));
        }
        Ok(())
    }

    fn run_phase(
        python: &MeasuredFile,
        import_roots: &[MeasuredImportRoot],
        release_root_fd: RawFd,
        script: &MeasuredScript,
        script_argv: &[String],
        receipt_fd: RawFd,
        nonce_rollback_assurance_pins_fd: RawFd,
        receipt_sha256: &str,
        operation_deadline: &BoottimeInstant,
        phase_name: &str,
    ) -> Result<i32> {
        require_operation_deadline_current(operation_deadline)?;
        let (barrier_read_end, barrier_write_end) =
            create_phase_execution_barrier()?;
        // Capture the expected parent before fork so the child can close the
        // fork-to-PR_SET_PDEATHSIG race without executing measured Python.
        // SAFETY: getpid has no memory-safety preconditions.
        let launcher_pid = unsafe { libc::getpid() };
        // SAFETY: fork is called from the single-threaded launcher before any worker threads exist.
        let child = unsafe { libc::fork() };
        if child < 0 {
            return Err(errno_message("could not fork production phase"));
        }
        if child == 0 {
            // SAFETY: the child must not retain the parent's barrier write end.
            unsafe { libc::close(barrier_write_end.as_raw_fd()) };
            // SAFETY: PR_SET_PDEATHSIG requests immediate child termination if
            // the supervising launcher disappears.
            if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
                child_error("could not bind phase lifetime to launcher");
            }
            // SAFETY: getppid has no memory-safety preconditions.
            if unsafe { libc::getppid() } != launcher_pid {
                child_error("launcher exited during phase setup");
            }
            // SAFETY: zero arguments place this child in a new group led by itself.
            if unsafe { libc::setpgid(0, 0) } != 0 {
                child_error("could not isolate phase process group");
            }
            // SAFETY: a fixed restrictive umask has no memory-safety preconditions.
            unsafe { libc::umask(0o077) };
            let dev_null = c"/dev/null";
            // SAFETY: path is static and flags are valid.
            let stdin_fd =
                unsafe { libc::open(dev_null.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
            if stdin_fd < 0 {
                child_error("could not open /dev/null");
            }
            // SAFETY: descriptors are valid.
            if unsafe { libc::dup2(stdin_fd, libc::STDIN_FILENO) } < 0 {
                child_error("could not sanitize stdin");
            }
            if stdin_fd > libc::STDERR_FILENO {
                // SAFETY: descriptor is no longer needed after dup2.
                unsafe { libc::close(stdin_fd) };
            }
            // SAFETY: release root descriptor is a verified directory.
            if unsafe { libc::fchdir(release_root_fd) } != 0 {
                child_error("could not enter release root");
            }

            let python_fd = python.file.as_raw_fd();
            let script_fd = script.snapshot.as_raw_fd();
            let import_fds = import_roots
                .iter()
                .map(|root| root.fd.as_raw_fd())
                .collect::<Vec<_>>();
            for fd in std::iter::once(python_fd)
                .chain(std::iter::once(script_fd))
                .chain(import_fds.iter().copied())
                .chain(std::iter::once(receipt_fd))
                .chain(std::iter::once(nonce_rollback_assurance_pins_fd))
            {
                if clear_cloexec(fd).is_err() {
                    child_error("could not retain a measured descriptor");
                }
            }
            // Both phases share one open-file description; reset it before each exec.
            // SAFETY: receipt_fd is the verified sealed memfd.
            if unsafe { libc::lseek(receipt_fd, 0, libc::SEEK_SET) } != 0 {
                child_error("could not reset bootstrap receipt descriptor");
            }
            if unsafe {
                libc::lseek(
                    nonce_rollback_assurance_pins_fd,
                    0,
                    libc::SEEK_SET,
                )
            } != 0
            {
                child_error("could not reset nonce rollback assurance pins descriptor");
            }
            let mut keep = vec![
                python_fd,
                script_fd,
                receipt_fd,
                nonce_rollback_assurance_pins_fd,
                barrier_read_end.as_raw_fd(),
            ];
            keep.extend(import_fds.iter().copied());
            if close_unrelated_descriptors(&keep).is_err() {
                child_error("could not close inherited descriptors");
            }

            let bootstrap = python_bootstrap(script_fd, &import_fds);
            let mut python_argv = vec![
                python.receipt.path.clone(),
                "-I".to_string(),
                "-S".to_string(),
                "-B".to_string(),
                "-u".to_string(),
                "-c".to_string(),
                bootstrap,
            ];
            python_argv.extend(script_argv.iter().cloned());
            let argv = match cstring_vector(&python_argv, "constructed argv") {
                Ok(value) => value,
                Err(_) => child_error("constructed argv is invalid"),
            };
            let argv_pointers = argv
                .iter()
                .map(|value| value.as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect::<Vec<_>>();
            let environment = fixed_environment(receipt_sha256)
                .into_iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>();
            let environment = match cstring_vector(&environment, "fixed environment") {
                Ok(value) => value,
                Err(_) => child_error("fixed environment is invalid"),
            };
            let environment_pointers = environment
                .iter()
                .map(|value| value.as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect::<Vec<_>>();
            let empty = c"";
            if let Err(error) =
                consume_exact_phase_go_token(barrier_read_end.as_raw_fd())
            {
                child_error(&error.to_string());
            }
            // SAFETY: the exact go token was consumed and the barrier is no longer needed.
            if unsafe { libc::close(barrier_read_end.as_raw_fd()) } != 0 {
                child_error("could not close production phase execution barrier");
            }
            if require_operation_deadline_current(operation_deadline).is_err() {
                child_error(
                    "launch authorization expired before descriptor-pinned execution",
                );
            }
            // SAFETY: all pointers refer to live CString storage and python_fd is verified.
            unsafe {
                libc::syscall(
                    libc::SYS_execveat,
                    python_fd,
                    empty.as_ptr(),
                    argv_pointers.as_ptr(),
                    environment_pointers.as_ptr(),
                    libc::AT_EMPTY_PATH,
                );
            }
            child_error("descriptor-pinned Python execution failed");
        }

        drop(barrier_read_end);
        let mut leader_status = None;
        match establish_phase_process_group_before_exec(child) {
            Ok(status) => leader_status = status,
            Err(error) => {
                return abort_phase_before_exec(
                    child,
                    barrier_write_end,
                    &mut leader_status,
                    error,
                )
            }
        }
        if let Some(status) = leader_status {
            drop(barrier_write_end);
            let group_exists = match phase_process_group_exists(child) {
                Ok(value) => value,
                Err(error) => {
                    return terminate_phase_process_group(
                        child,
                        phase_name,
                        &mut leader_status,
                        &format!(
                            "failed during blocked child setup and process-group inspection failed: {error}"
                        ),
                    )
                }
            };
            let has_descendants = match direct_phase_descendants(child) {
                Ok(value) => !value.is_empty(),
                Err(error) => {
                    return terminate_phase_process_group(
                        child,
                        phase_name,
                        &mut leader_status,
                        &format!(
                            "failed during blocked child setup and descendant inspection failed: {error}"
                        ),
                    )
                }
            };
            if group_exists || has_descendants {
                return terminate_phase_process_group(
                    child,
                    phase_name,
                    &mut leader_status,
                    "failed during blocked child setup and left live descendants",
                );
            }
            return Ok(status);
        }
        if let Err(error) =
            require_operation_deadline_current(operation_deadline)
        {
            return abort_phase_before_exec(
                child,
                barrier_write_end,
                &mut leader_status,
                error,
            );
        }
        if let Err(error) = release_phase_go_token(barrier_write_end) {
            let cleanup_result =
                force_kill_and_reap_phase_processes(child, &mut leader_status);
            return match cleanup_result {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(LauncherError::new(format!(
                    "{error}; blocked phase cleanup failed: {cleanup_error}"
                ))),
            };
        }
        loop {
            let has_children =
                match reap_phase_children_nonblocking(child, &mut leader_status) {
                    Ok(value) => value,
                    Err(error) => {
                        return terminate_phase_process_group(
                            child,
                            phase_name,
                            &mut leader_status,
                            &format!(
                                "lost bounded child-reaping supervision after execution may have begun: {error}"
                            ),
                        )
                    }
                };
            if let Some(status) = leader_status {
                let group_exists = match phase_process_group_exists(child) {
                    Ok(value) => value,
                    Err(error) => {
                        return terminate_phase_process_group(
                            child,
                            phase_name,
                            &mut leader_status,
                            &format!(
                                "could not prove process-group quiescence after the phase leader exited: {error}"
                            ),
                        )
                    }
                };
                let has_descendants = match direct_phase_descendants(child) {
                    Ok(value) => !value.is_empty(),
                    Err(error) => {
                        return terminate_phase_process_group(
                            child,
                            phase_name,
                            &mut leader_status,
                            &format!(
                                "could not prove descendant quiescence after the phase leader exited: {error}"
                            ),
                        )
                    }
                };
                if has_children || group_exists || has_descendants {
                    return terminate_phase_process_group(
                        child,
                        phase_name,
                        &mut leader_status,
                        "left a live descendant after its leader exited",
                    );
                }
                if status != 0 {
                    return Ok(status);
                }
                if let Err(deadline_error) =
                    require_operation_deadline_current(operation_deadline)
                {
                    return Err(LauncherError::new(format!(
                        "LAUTH_PHASE_OUTCOME_UNKNOWN: {phase_name} returned zero but completion within the suspend-aware launch authorization deadline could not be proven: {deadline_error}; no later phase may run"
                    )));
                }
                return Ok(status);
            }
            if let Err(deadline_error) =
                require_operation_deadline_current(operation_deadline)
            {
                return terminate_phase_process_group(
                    child,
                    phase_name,
                    &mut leader_status,
                    &format!(
                        "exceeded or could not prove the suspend-aware launch authorization deadline after execution may have begun: {deadline_error}"
                    ),
                );
            }
            if let Err(wait_error) =
                sleep_until_next_phase_deadline_check(operation_deadline)
            {
                return terminate_phase_process_group(
                    child,
                    phase_name,
                    &mut leader_status,
                    &format!(
                        "could not maintain suspend-aware deadline supervision after execution may have begun: {wait_error}"
                    ),
                );
            }
        }
    }

    pub(super) fn run(cli: Cli) -> Result<i32> {
        // SAFETY: geteuid has no memory-safety preconditions.
        if unsafe { libc::geteuid() } != 0 {
            return Err(LauncherError::new(
                "production launcher must run with effective UID 0",
            ));
        }
        let receipt_fd_reservation = reserve_receipt_fd()?;
        let verified = verify_launch(&cli)?;
        let _attempt_guard = acquire_attempt_journal_lock(&verified)?;
        let launch_authorization =
            recover_or_create_launch_authorization(&verified)?;
        let authorization_statement = launch_authorization.envelope.statement.clone();
        let operation_deadline =
            operation_deadline_from_authorization(&authorization_statement)?;
        revalidate_verified_launch(&cli, &verified)?;
        let nonce_rollback_assurance_pins_fd = verified
            .nonce_rollback_assurance_pins
            .snapshot
            .as_raw_fd();
        let preflight_argv = build_preflight_argv(
            &verified.manifest,
            nonce_rollback_assurance_pins_fd,
        );
        let readiness_argv = build_readiness_argv(
            &verified.manifest,
            nonce_rollback_assurance_pins_fd,
        );
        let receipt = build_receipt(
            &verified,
            launch_authorization,
            &preflight_argv,
            &readiness_argv,
        )?;
        let receipt_bytes = canonical_json_bytes(&receipt)?;
        let receipt_sha256 = sha256_prefixed(&receipt_bytes);
        let receipt_fd =
            create_sealed_receipt(&receipt_bytes, receipt_fd_reservation)?;

        enable_phase_subreaper()?;
        revalidate_verified_launch(&cli, &verified)?;
        require_operation_deadline_current(&operation_deadline)?;
        let preflight_status = run_phase(
            &verified.python,
            &verified.import_roots,
            verified.release_root_fd.as_raw_fd(),
            &verified.preflight,
            &preflight_argv,
            receipt_fd.as_raw_fd(),
            nonce_rollback_assurance_pins_fd,
            &receipt_sha256,
            &operation_deadline,
            "preflight",
        )?;
        if preflight_status != 0 {
            return Ok(preflight_status);
        }
        revalidate_verified_launch(&cli, &verified)?;
        require_operation_deadline_current(&operation_deadline)?;
        let readiness_status = run_phase(
            &verified.python,
            &verified.import_roots,
            verified.release_root_fd.as_raw_fd(),
            &verified.runner,
            &readiness_argv,
            receipt_fd.as_raw_fd(),
            nonce_rollback_assurance_pins_fd,
            &receipt_sha256,
            &operation_deadline,
            "readiness",
        )?;
        if readiness_status != 0 {
            return Ok(readiness_status);
        }
        revalidate_verified_launch(&cli, &verified)?;
        require_operation_deadline_current(&operation_deadline)?;
        Ok(0)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const FD_FALLBACK_CHILD_ENV: &str = "SERVERWARE_TEST_FD_FALLBACK_CHILD";

        fn consume_barrier_payload(payload: &[u8]) -> Result<()> {
            let (read_end, write_end) = create_phase_execution_barrier()?;
            let mut writer = File::from(write_end);
            writer
                .write_all(payload)
                .map_err(|error| LauncherError::new(error.to_string()))?;
            drop(writer);
            consume_exact_phase_go_token(read_end.as_raw_fd())
        }

        #[test]
        fn boottime_deadline_arithmetic_is_checked_and_normalized() {
            let carried = BoottimeInstant {
                seconds: 40,
                nanoseconds: NANOSECONDS_PER_SECOND - 1,
            }
            .checked_add_timespec_delta(1, 1)
            .unwrap();
            assert_eq!(
                carried,
                BoottimeInstant {
                    seconds: 42,
                    nanoseconds: 0,
                }
            );
            assert!(BoottimeInstant {
                seconds: 1,
                nanoseconds: 0,
            }
            .checked_add_timespec_delta(0, NANOSECONDS_PER_SECOND)
            .is_err());
            assert!(BoottimeInstant {
                seconds: u64::MAX,
                nanoseconds: NANOSECONDS_PER_SECOND - 1,
            }
            .checked_add_timespec_delta(0, 1)
            .is_err());
            assert!(BoottimeInstant::from_timespec(
                libc::timespec {
                    tv_sec: -1,
                    tv_nsec: 0,
                },
                "test boottime",
            )
            .is_err());
        }

        #[test]
        fn wall_expiration_projection_rejects_expiry_and_time_t_overflow() {
            let sample = BoottimeInstant {
                seconds: 50,
                nanoseconds: 250_000_000,
            };
            assert_eq!(
                project_wall_expiration_to_boottime(101, 100, 0, sample)
                    .unwrap(),
                BoottimeInstant {
                    seconds: 51,
                    nanoseconds: 250_000_000,
                }
            );
            assert_eq!(
                project_wall_expiration_to_boottime(
                    101,
                    100,
                    250_000_000,
                    sample,
                )
                .unwrap(),
                BoottimeInstant {
                    seconds: 51,
                    nanoseconds: 0,
                }
            );
            assert!(
                project_wall_expiration_to_boottime(100, 100, 0, sample)
                    .is_err()
            );
            assert!(project_wall_expiration_to_boottime(
                101,
                100,
                NANOSECONDS_PER_SECOND,
                sample,
            )
            .is_err());
            assert!(project_wall_expiration_to_boottime(
                101,
                100,
                0,
                BoottimeInstant {
                    seconds: libc::time_t::MAX as u64,
                    nanoseconds: 0,
                },
            )
            .is_err());
        }

        #[test]
        fn phase_execution_barrier_requires_one_exact_go_token_and_eof() {
            assert!(consume_barrier_payload(&[PHASE_EXECUTION_GO_TOKEN]).is_ok());
            assert!(consume_barrier_payload(&[]).is_err());
            assert!(consume_barrier_payload(&[PHASE_EXECUTION_GO_TOKEN ^ 0xff]).is_err());
            assert!(
                consume_barrier_payload(&[
                    PHASE_EXECUTION_GO_TOKEN,
                    PHASE_EXECUTION_GO_TOKEN,
                ])
                .is_err()
            );
        }

        #[test]
        fn clear_cloexec_retains_descriptor_across_exec() {
            let mut descriptors = [-1; 2];
            // SAFETY: descriptors points to storage for both pipe descriptors.
            assert_eq!(
                unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
                0
            );
            // SAFETY: pipe2 returned two newly allocated, independently owned descriptors.
            let read_fd = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
            // SAFETY: pipe2 returned two newly allocated, independently owned descriptors.
            let _write_fd = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };

            // SAFETY: read_fd is valid.
            let before = unsafe { libc::fcntl(read_fd.as_raw_fd(), libc::F_GETFD) };
            assert_ne!(before & libc::FD_CLOEXEC, 0);
            clear_cloexec(read_fd.as_raw_fd()).unwrap();
            // SAFETY: read_fd remains valid.
            let after = unsafe { libc::fcntl(read_fd.as_raw_fd(), libc::F_GETFD) };
            assert_eq!(after & libc::FD_CLOEXEC, 0);
        }

        #[test]
        fn proc_fd_fallback_ignores_a_reduced_soft_descriptor_limit() {
            if std::env::var_os(FD_FALLBACK_CHILD_ENV).is_none() {
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "linux::tests::proc_fd_fallback_ignores_a_reduced_soft_descriptor_limit",
                        "--nocapture",
                    ])
                    .env(FD_FALLBACK_CHILD_ENV, "1")
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "isolated descriptor fallback test failed: {}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                return;
            }

            let source = File::open("/dev/null").unwrap();
            let unrelated_fd = 256;
            let retained_fd = 257;
            let mut original_limit = MaybeUninit::<libc::rlimit>::uninit();
            // SAFETY: original_limit points to writable storage for one rlimit.
            assert_eq!(
                unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, original_limit.as_mut_ptr()) },
                0
            );
            // SAFETY: successful getrlimit initialized original_limit.
            let original_limit = unsafe { original_limit.assume_init() };
            assert!(original_limit.rlim_max > retained_fd as libc::rlim_t);
            let raised_limit = libc::rlimit {
                rlim_cur: original_limit
                    .rlim_cur
                    .max((retained_fd + 1) as libc::rlim_t),
                rlim_max: original_limit.rlim_max,
            };
            // SAFETY: raised_limit does not exceed the existing hard limit.
            assert_eq!(
                unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised_limit) },
                0
            );
            // SAFETY: source is valid and the target descriptors are below the soft limit.
            assert_eq!(
                unsafe { libc::dup2(source.as_raw_fd(), unrelated_fd) },
                unrelated_fd
            );
            assert_eq!(
                unsafe { libc::dup2(source.as_raw_fd(), retained_fd) },
                retained_fd
            );

            let lowered_limit = libc::rlimit {
                rlim_cur: 64,
                rlim_max: original_limit.rlim_max,
            };
            // SAFETY: lowering the soft limit preserves the hard limit.
            assert_eq!(
                unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lowered_limit) },
                0
            );
            let mut keep = std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .map(|entry| {
                    entry
                        .unwrap()
                        .file_name()
                        .to_str()
                        .unwrap()
                        .parse::<RawFd>()
                        .unwrap()
                })
                .filter(|fd| *fd >= 3 && *fd != unrelated_fd)
                .collect::<Vec<_>>();
            keep.sort_unstable();
            keep.dedup();
            close_unrelated_descriptors_fallback(&keep).unwrap();

            // SAFETY: fcntl only inspects descriptor validity.
            assert_eq!(unsafe { libc::fcntl(unrelated_fd, libc::F_GETFD) }, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EBADF)
            );
            assert!(unsafe { libc::fcntl(retained_fd, libc::F_GETFD) } >= 0);
            // SAFETY: restoring the original process limit and closing the raw duplicate are valid.
            assert_eq!(
                unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &original_limit) },
                0
            );
            unsafe { libc::close(retained_fd) };
        }

        #[test]
        fn sealed_script_snapshots_preserve_content_and_reject_mutation() {
            let expected = b"print('verified snapshot')\n";
            let mut snapshot =
                create_sealable_memfd(c"serverware-test-script-snapshot", "test script snapshot")
                    .unwrap();
            snapshot.write_all(expected).unwrap();
            let snapshot = seal_memfd(snapshot, "test script snapshot").unwrap();

            // SAFETY: snapshot is a valid sealed memfd.
            let seals = unsafe { libc::fcntl(snapshot.as_raw_fd(), libc::F_GET_SEALS) };
            assert_eq!(seals & IMMUTABLE_MEMFD_SEALS, IMMUTABLE_MEMFD_SEALS);

            let mut snapshot = File::from(snapshot);
            let mut actual = Vec::new();
            snapshot.read_to_end(&mut actual).unwrap();
            assert_eq!(actual, expected);
            let error = snapshot.write_all(b"mutated").unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EPERM));
        }
    }
}

fn main() {
    let cli = match parse_cli(env::args_os()) {
        Ok(cli) => cli,
        Err(error) => {
            eprintln!("serverware production launcher error: {error}");
            std::process::exit(2);
        }
    };

    #[cfg(target_os = "linux")]
    match linux::run(cli) {
        Ok(status) => std::process::exit(status),
        Err(error) => {
            eprintln!("serverware production launcher error: {error}");
            std::process::exit(1);
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = cli;
        eprintln!("serverware production launcher error: launcher execution requires Linux");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    fn digest(character: char) -> String {
        format!("sha256:{}", character.to_string().repeat(64))
    }

    fn file(path: &str, character: char) -> Value {
        json!({"path": path, "sha256": digest(character)})
    }

    fn witness_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x44; 32])
    }

    fn witness_store_assurance_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x45; 32])
    }

    fn witness_configuration() -> LaunchAuthorityWitnessConfiguration {
        let key = witness_signing_key().verifying_key();
        let spki = [
            ED25519_SPKI_PREFIX.as_slice(),
            key.as_bytes().as_slice(),
        ]
        .concat();
        let assurance_key =
            witness_store_assurance_signing_key().verifying_key();
        let assurance_spki = [
            ED25519_SPKI_PREFIX.as_slice(),
            assurance_key.as_bytes().as_slice(),
        ]
        .concat();
        let mut store_assurance =
            LaunchAuthorityWitnessStoreAssuranceEnvelope {
                api_version: WITNESS_STORE_ASSURANCE_API_VERSION.to_string(),
                kind: WITNESS_STORE_ASSURANCE_KIND.to_string(),
                statement:
                    LaunchAuthorityWitnessStoreAssuranceStatement {
                        assurance_issuer_key_id: sha256_prefixed(
                            &assurance_spki,
                        ),
                        witness_key_id: sha256_prefixed(&spki),
                        witness_identity_sha256: digest('6'),
                        witness_administrative_domain_sha256: digest('5'),
                        store_identity_sha256: digest('8'),
                        store_administrative_domain_sha256: digest('9'),
                        store_class:
                            "independentlyAdministeredLinearizableCas"
                                .to_string(),
                        rollback_resistance:
                            "externally-witnessed-monotonic".to_string(),
                        independent_administration: true,
                    },
                signature: String::new(),
            };
        store_assurance.signature = general_purpose::URL_SAFE_NO_PAD.encode(
            witness_store_assurance_signing_key()
                .sign(
                    &witness_store_assurance_signing_bytes(
                        &store_assurance,
                    )
                    .unwrap(),
                )
                .to_bytes(),
        );
        LaunchAuthorityWitnessConfiguration {
            administrative_domain_sha256: digest('5'),
            identity_sha256: digest('6'),
            signing_key_id: sha256_prefixed(&spki),
            signing_public_key_spki_der_base64url:
                general_purpose::URL_SAFE_NO_PAD.encode(spki),
            store_assurance_sha256: sha256_prefixed(
                &canonical_json_bytes(&store_assurance).unwrap(),
            ),
            store_assurance,
            store_assurance_issuer_key_id: sha256_prefixed(
                &assurance_spki,
            ),
            store_assurance_issuer_public_key_spki_der_base64url:
                general_purpose::URL_SAFE_NO_PAD.encode(assurance_spki),
        }
    }

    #[test]
    fn independent_administration_rejects_all_twenty_one_pair_collisions() {
        assert_eq!(
            INDEPENDENT_ADMINISTRATION_BINDING_LABELS,
            [
                "launchAuthority.signingKeyId",
                "launchAuthorityWitness.signingKeyId",
                "launchAuthorityWitness.identitySha256",
                "launchAuthorityWitness.administrativeDomainSha256",
                "launchAuthorityWitnessStore.identitySha256",
                "launchAuthorityWitnessStore.administrativeDomainSha256",
                "launchAuthorityWitnessStore.assuranceIssuerKeyId",
            ]
        );
        let distinct: [String; 7] = std::array::from_fn(|index| {
            format!("sha256:{:064x}", index + 1)
        });
        let mut collisions = 0usize;
        for left in 0..INDEPENDENT_ADMINISTRATION_BINDING_LABELS.len() {
            for right in left + 1..INDEPENDENT_ADMINISTRATION_BINDING_LABELS.len() {
                let mut candidate = distinct.clone();
                candidate[right] = candidate[left].clone();
                let values: [&str; 7] =
                    std::array::from_fn(|index| candidate[index].as_str());
                let error =
                    require_pairwise_distinct_independent_administration_bindings(values)
                        .unwrap_err()
                        .to_string();
                assert_eq!(
                    error,
                    format!(
                        "independentAdministration requires pairwise-distinct authority, witness, and witness-store bindings: {} collides with {}",
                        INDEPENDENT_ADMINISTRATION_BINDING_LABELS[left],
                        INDEPENDENT_ADMINISTRATION_BINDING_LABELS[right],
                    )
                );
                collisions += 1;
            }
        }
        assert_eq!(collisions, 21);
    }

    fn authorization_request_fixture() -> LaunchAuthorizationRequest {
        let witness = witness_configuration();
        let role_binding: GlobalRoleRegistryBinding = serde_json::from_value(
            global_role_registry_json(
                &witness,
                &nonce_rollback_assurance_json(),
            ),
        )
        .unwrap();
        let mut request = LaunchAuthorizationRequest {
            api_version: AUTHORIZATION_REQUEST_API_VERSION.to_string(),
            kind: AUTHORIZATION_REQUEST_KIND.to_string(),
            launcher_nonce: "1".repeat(64),
            boot_id_sha256: digest('2'),
            launcher_sha256: digest('3'),
            manifest_sha256: digest('4'),
            global_role_registry: role_binding.registry,
            global_role_registry_sha256: role_binding.registry_sha256,
            global_role_registry_pins_sha256: digest('0'),
            nonce_rollback_assurance_contract_sha256: digest('a'),
            nonce_rollback_assurance_pins_sha256: digest('b'),
            release_provenance_sha256: digest('5'),
            provenance_digest: digest('6'),
            reproducible_build_verification_sha256: digest('7'),
            source_tree_digest: digest('8'),
            deployment_audience: "prod.us-east-1.primary".to_string(),
            deployment_identity_sha256: digest('9'),
            release_sequence: 42,
            rollback_epoch: 7,
            authorization_scope: AUTHORIZATION_SCOPE.to_string(),
            freshness_authority: FRESHNESS_AUTHORITY.to_string(),
            launch_attempt_journal_domain: ATTEMPT_JOURNAL_DOMAIN.to_string(),
            launch_attempt_recovery_identity_sha256: String::new(),
            launch_authority_witness_challenge: "c".repeat(64),
            launch_authority_witness_key_id: witness.signing_key_id,
            launch_authority_witness_identity_sha256: witness.identity_sha256,
            launch_authority_witness_administrative_domain_sha256:
                witness.administrative_domain_sha256,
            launch_authority_witness_store_assurance_sha256:
                witness.store_assurance_sha256,
        };
        request.launch_attempt_recovery_identity_sha256 =
            launch_attempt_recovery_identity_sha256(&request).unwrap();
        request
    }

    fn signed_witness(
        request: &LaunchAuthorizationRequest,
        authorization_id: &str,
        authority_key_id: &str,
    ) -> LaunchAuthorityWitnessEnvelope {
        let configuration = witness_configuration();
        let mut envelope = LaunchAuthorityWitnessEnvelope {
            api_version: WITNESS_API_VERSION.to_string(),
            kind: WITNESS_KIND.to_string(),
            statement: LaunchAuthorityWitnessStatement {
                operation: WITNESS_OPERATION.to_string(),
                operation_id: request.launcher_nonce.clone(),
                authorization_id: authorization_id.to_string(),
                request_sha256: authorization_request_digest(request).unwrap(),
                challenge: request.launch_authority_witness_challenge.clone(),
                issued_at_unix_seconds: 1_000,
                expires_at_unix_seconds: 1_030,
                authority_key_id: authority_key_id.to_string(),
                witness_key_id: configuration.signing_key_id,
                witness_identity_sha256: configuration.identity_sha256,
                witness_administrative_domain_sha256:
                    configuration.administrative_domain_sha256,
                store_assurance_sha256: configuration.store_assurance_sha256,
                registry_generation: 3,
                registry_sha256: digest('8'),
                predecessor_state_sha256: digest('9'),
                successor_state_sha256: digest('a'),
                deployment_audience: request.deployment_audience.clone(),
                deployment_identity_sha256: request.deployment_identity_sha256.clone(),
                release_sequence: request.release_sequence,
                rollback_epoch: request.rollback_epoch,
                authorization_scope: AUTHORIZATION_SCOPE.to_string(),
                state_transition_committed: true,
                checkpoint_sequence: 11,
            },
            signature: String::new(),
        };
        envelope.signature = general_purpose::URL_SAFE_NO_PAD.encode(
            witness_signing_key()
                .sign(&witness_signing_bytes(&envelope).unwrap())
                .to_bytes(),
        );
        envelope
    }

    fn nonce_rollback_assurance_json() -> Value {
        let evidence_spki = [
            ED25519_SPKI_PREFIX.as_slice(),
            &[0x11; 32],
        ]
        .concat();
        let verifier_state_spki = [
            ED25519_SPKI_PREFIX.as_slice(),
            &[0x22; 32],
        ]
        .concat();
        let verifier_state_store_attestation_spki = [
            ED25519_SPKI_PREFIX.as_slice(),
            &[0x33; 32],
        ]
        .concat();
        let assurance = json!({
            "apiVersion": NONCE_AUTHORITY_ASSURANCE_API_VERSION,
            "administrativeDomainSha256": digest('1'),
            "assuranceEvidenceSha256": digest('2'),
            "assuranceEvidenceType": "linearizableCasOperatorAttestation",
            "assuranceLevel": "productionRollbackProtected",
            "authorityEpoch": 1,
            "authorityGeneration": 1,
            "authorityIdentitySha256": digest('3'),
            "backendClass": "independentlyAdministeredLinearizableCas",
            "productionEligible": true,
            "rollbackProtection": {
                "administrativeRollbackResistance": true,
                "backendAttestationRequired": true,
                "exactSuccessorRequired": true,
                "freshVerifierChallengeRequired": true,
                "keyProtection": "nonExportableKmsHsm",
                "mechanism": "linearizableCasWithRollbackProtectedStorage",
                "stateCommitment": "hashChainedLinearizableCommitment",
                "verifierStateStoreClass": "independentlyAdministeredLinearizableCas"
            }
        });
        let assurance_sha256 =
            sha256_prefixed(&canonical_json_bytes(&assurance).unwrap());
        let contract = json!({
            "apiVersion": NONCE_ROLLBACK_ASSURANCE_PINS_API_VERSION,
            "independentVerifierPins": {
                "expectedNonceAuthorityAssuranceIssuerSpkiSha256":
                    sha256_prefixed(&evidence_spki),
                "expectedNonceAuthorityAssuranceSha256": assurance_sha256.clone()
            },
            "publicConfigPins": {
                "nonceAuthorityAssurance": assurance,
                "nonceAuthorityAssuranceEvidenceSigningPublicKeySpkiDerBase64url":
                    general_purpose::URL_SAFE_NO_PAD.encode(&evidence_spki),
                "nonceAuthorityAssuranceSha256": assurance_sha256,
                "nonceAuthorityVerifierStateSigningPublicKeySpkiDerBase64url":
                    general_purpose::URL_SAFE_NO_PAD.encode(&verifier_state_spki),
                "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256":
                    digest('4'),
                "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256":
                    digest('6'),
                "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url":
                    general_purpose::URL_SAFE_NO_PAD.encode(
                        &verifier_state_store_attestation_spki
                    ),
                "nonceAuthorityVerifierStateStoreIdentitySha256": digest('5')
            }
        });
        json!({
            "apiVersion": NONCE_ROLLBACK_ASSURANCE_BINDING_API_VERSION,
            "canonicalProfile": CANONICAL_JSON_PROFILE,
            "contractSha256": sha256_prefixed(
                &canonical_json_bytes(&contract).unwrap()
            ),
            "contract": contract,
            "enforcement": "native-launcher-measured",
            "pinsFile": file(
                "/etc/serverware/production-nonce-rollback-assurance-pins.json",
                '6'
            ),
            "purpose": "readiness-only"
        })
    }

    fn manifest_bytes(value: &Value) -> Vec<u8> {
        let mut bytes = canonical_json_bytes(value).unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn rebind_nonce_rollback_assurance_contract(value: &mut Value) {
        let contract = &value["nonceRollbackAssurance"]["contract"];
        value["nonceRollbackAssurance"]["contractSha256"] =
            json!(sha256_prefixed(&canonical_json_bytes(contract).unwrap()));
    }

    fn global_role_registry_json(
        witness: &LaunchAuthorityWitnessConfiguration,
        nonce: &Value,
    ) -> Value {
        let public = &nonce["contract"]["publicConfigPins"];
        let key_id = |value: u8| {
            sha256_prefixed(
                &[
                    ED25519_SPKI_PREFIX.as_slice(),
                    &[value; 32],
                ]
                .concat(),
            )
        };
        let roles = BTreeMap::from([
            (
                "launchAuthority".to_string(),
                launch_authority_key_id(
                    &compiled_authority_public_key().unwrap(),
                ),
            ),
            (
                "launchAuthorityWitness".to_string(),
                witness.signing_key_id.clone(),
            ),
            (
                "launchAuthorityWitnessStoreAssurance".to_string(),
                witness.store_assurance_issuer_key_id.clone(),
            ),
            ("launchAuthorityWitnessTls".to_string(), key_id(0x41)),
            (
                "nonceAuthorityAssuranceEvidence".to_string(),
                canonical_ed25519_spki_sha256(
                    public[
                        "nonceAuthorityAssuranceEvidenceSigningPublicKeySpkiDerBase64url"
                    ]
                    .as_str()
                    .unwrap(),
                    "fixture assurance-evidence role",
                )
                .unwrap(),
            ),
            (
                "nonceAuthorityVerifierState".to_string(),
                canonical_ed25519_spki_sha256(
                    public[
                        "nonceAuthorityVerifierStateSigningPublicKeySpkiDerBase64url"
                    ]
                    .as_str()
                    .unwrap(),
                    "fixture verifier-state role",
                )
                .unwrap(),
            ),
            (
                "nonceAuthorityVerifierStateStoreAttestation".to_string(),
                canonical_ed25519_spki_sha256(
                    public[
                        "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url"
                    ]
                    .as_str()
                    .unwrap(),
                    "fixture verifier-state store-attestation role",
                )
                .unwrap(),
            ),
            ("policyActivation".to_string(), key_id(0x43)),
            ("policyIdentity".to_string(), key_id(0x44)),
            ("reproducibleBuild".to_string(), key_id(0x46)),
        ]);
        let registry = GlobalRoleRegistry {
            api_version: GLOBAL_ROLE_REGISTRY_API_VERSION.to_string(),
            claim_scope: GLOBAL_ROLE_REGISTRY_CLAIM_SCOPE.to_string(),
            roles,
            roles_outside_claim: GLOBAL_ROLES_OUTSIDE_CLAIM
                .into_iter()
                .map(str::to_string)
                .collect(),
        };
        let registry_sha256 = global_role_registry_sha256(&registry).unwrap();
        json!({
            "apiVersion": GLOBAL_ROLE_REGISTRY_BINDING_API_VERSION,
            "canonicalProfile": CANONICAL_JSON_PROFILE,
            "claimScope": GLOBAL_ROLE_REGISTRY_CLAIM_SCOPE,
            "registrySha256": registry_sha256,
            "registry": registry,
            "pinsFile": file(
                "/etc/serverware/production-launch-global-role-registry.json",
                '7'
            )
        })
    }

    fn write_u16(target: &mut [u8], offset: usize, value: u16) {
        target[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(target: &mut [u8], offset: usize, value: u32) {
        target[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(target: &mut [u8], offset: usize, value: u64) {
        target[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn minimal_cpython_elf(machine: u16, symbol: &[u8], needed: &[u8]) -> Vec<u8> {
        let mut strings = vec![0];
        let symbol_name_offset = strings.len();
        strings.extend_from_slice(symbol);
        strings.push(0);
        let needed_offset = strings.len();
        strings.extend_from_slice(needed);
        strings.push(0);

        let program_offset = ELF64_HEADER_SIZE;
        let strings_offset = program_offset + ELF64_PROGRAM_HEADER_SIZE;
        let symbols_offset = strings_offset + strings.len();
        let symbols_size = ELF64_SYMBOL_SIZE * 2;
        let dynamic_offset = symbols_offset + symbols_size;
        let dynamic_size = ELF64_DYNAMIC_SIZE * 2;
        let sections_offset = dynamic_offset + dynamic_size;
        let mut value = vec![0u8; sections_offset + ELF64_SECTION_HEADER_SIZE * 4];
        value[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        write_u16(&mut value, 16, 3);
        write_u16(&mut value, 18, machine);
        write_u32(&mut value, 20, 1);
        write_u64(&mut value, 32, program_offset as u64);
        write_u64(&mut value, 40, sections_offset as u64);
        write_u16(&mut value, 52, ELF64_HEADER_SIZE as u16);
        write_u16(&mut value, 54, ELF64_PROGRAM_HEADER_SIZE as u16);
        write_u16(&mut value, 56, 1);
        write_u16(&mut value, 58, ELF64_SECTION_HEADER_SIZE as u16);
        write_u16(&mut value, 60, 4);
        value[strings_offset..strings_offset + strings.len()].copy_from_slice(&strings);
        write_u32(
            &mut value,
            symbols_offset + ELF64_SYMBOL_SIZE,
            symbol_name_offset as u32,
        );
        write_u64(&mut value, dynamic_offset, ELF_DYNAMIC_NEEDED);
        write_u64(&mut value, dynamic_offset + 8, needed_offset as u64);

        let mut section = |index: usize,
                           section_type: u32,
                           offset: usize,
                           size: usize,
                           link: u32,
                           entry_size: usize| {
            let base = sections_offset + index * ELF64_SECTION_HEADER_SIZE;
            write_u32(&mut value, base + 4, section_type);
            write_u64(&mut value, base + 24, offset as u64);
            write_u64(&mut value, base + 32, size as u64);
            write_u32(&mut value, base + 40, link);
            write_u64(&mut value, base + 48, 1);
            write_u64(&mut value, base + 56, entry_size as u64);
        };
        section(1, ELF_SECTION_STRTAB, strings_offset, strings.len(), 0, 0);
        section(
            2,
            ELF_SECTION_DYNSYM,
            symbols_offset,
            symbols_size,
            1,
            ELF64_SYMBOL_SIZE,
        );
        section(
            3,
            ELF_SECTION_DYNAMIC,
            dynamic_offset,
            dynamic_size,
            1,
            ELF64_DYNAMIC_SIZE,
        );
        value
    }

    fn manifest_json() -> Value {
        let root = "/opt/serverware/releases/release-a";
        let witness = witness_configuration();
        let nonce = nonce_rollback_assurance_json();
        let role_registry = global_role_registry_json(&witness, &nonce);
        json!({
            "apiVersion": LAUNCH_MANIFEST_API_VERSION,
            "kind": LAUNCH_MANIFEST_KIND,
            "releaseRoot": root,
            "stateDirectory": "/var/lib/serverware/production-proof",
            "sourceTreeDigest": digest('a'),
            "authorization": {
                "authorizationScope": AUTHORIZATION_SCOPE,
                "deploymentAudience": "prod.us-east-1.primary",
                "deploymentIdentitySha256": digest('0'),
                "freshnessAuthority": FRESHNESS_AUTHORITY,
                "monotonicWitness": witness,
                "releaseSequence": 42,
                "rollbackEpoch": 7
            },
            "launchAttemptJournal": {
                "apiVersion": ATTEMPT_JOURNAL_API_VERSION,
                "path": "/var/lib/serverware/production-proof/launch-authorization-attempt.v1.json",
                "lockPath": "/var/lib/serverware/production-proof/launch-authorization-attempt.v1.lock",
                "domain": ATTEMPT_JOURNAL_DOMAIN,
                "maxBytes": MAX_ATTEMPT_JOURNAL_BYTES,
                "consistencyScope": ATTEMPT_JOURNAL_CONSISTENCY_SCOPE,
                "rollbackAuthority": ATTEMPT_JOURNAL_ROLLBACK_AUTHORITY
            },
            "globalRoleRegistry": role_registry,
            "nonceRollbackAssurance": nonce,
            "productionEnv": file("/etc/serverware/production-readiness.env", 'b'),
            "python": {
                "path": format!("{root}/runtime/python/bin/python3"),
                "sha256": digest('c'),
                "importRoots": [
                    {"path": root, "sha256": digest('d')},
                    {"path": format!("{root}/runtime/python/lib/python3.11"), "sha256": digest('e')},
                    {"path": format!("{root}/runtime/python/lib/python3.11/lib-dynload"), "sha256": digest('f')},
                    {"path": format!("{root}/vendor"), "sha256": digest('1')}
                ]
            },
            "scripts": {
                "preflight": file(&format!("{root}/scripts/production_host_preflight.py"), 'e'),
                "runner": file(&format!("{root}/scripts/run_production_readiness.py"), 'f')
            },
            "composeFile": file(&format!("{root}/docker-compose.production.yml"), '1'),
            "inputs": {
                "productionImagesBuild": file(&format!("{root}/evidence/production-images-build.json"), '2'),
                "productionImagesEnv": file(&format!("{root}/evidence/production-images.env"), '3'),
                "productionImagesPublished": file(&format!("{root}/evidence/production-images-published.json"), '4'),
                "releaseProvenanceSummary": file(&format!("{root}/evidence/release-provenance-summary.json"), '5'),
                "releaseProvenance": file(&format!("{root}/evidence/release-provenance.json"), '6'),
                "imageSignaturesSummary": file(&format!("{root}/evidence/image-signatures-summary.json"), '7'),
                "imageSignatures": file(&format!("{root}/evidence/image-signatures.json"), '8'),
                "bench": file(&format!("{root}/evidence/bench.json"), '9'),
                "kmsMaterials": file(&format!("{root}/evidence/kms-materials.json"), 'a'),
                "policyBundle": file(&format!("{root}/evidence/policy-bundle.json"), 'b'),
                "policyTrustedPublicKey": file(&format!("{root}/evidence/policy.pem"), 'c'),
                "policyIdentityVerification": file(&format!("{root}/evidence/policy-identity.json"), 'd'),
                "policyActivationVerification": file(&format!("{root}/evidence/policy-activation.json"), 'e'),
                "policyActivationSignature": file(&format!("{root}/evidence/policy-activation.sig"), 'f'),
                "policyActivationTrustedPublicKey": file(&format!("{root}/evidence/policy-activation.pem"), '1'),
                "reproducibleBuildVerification": file(&format!("{root}/evidence/reproducible-build.json"), '2'),
                "reproducibleBuildSignature": file(&format!("{root}/evidence/reproducible-build.sig"), '3'),
                "reproducibleBuildTrustedPublicKey": file(&format!("{root}/evidence/reproducible-build.pem"), '4')
            },
            "outputs": {
                "configOut": "/var/lib/serverware/production-proof/readiness-config.json",
                "claimsFile": "/var/lib/serverware/production-proof/claims.json",
                "nitroEvidenceOut": "/var/lib/serverware/production-proof/nitro-evidence.json",
                "readinessOut": "/var/lib/serverware/production-proof/readiness.json",
                "completionProofOut": "/var/lib/serverware/production-proof/completion-proof.json",
                "proxyProofSummaryOut": "/var/lib/serverware/production-proof/proxy-proof-summary.json",
                "productionHostPreflight": "/var/lib/serverware/production-proof/host-preflight.json"
            }
        })
    }

    fn manifest() -> LaunchManifest {
        parse_manifest(&manifest_bytes(&manifest_json())).unwrap()
    }

    #[test]
    fn cli_is_closed_and_requires_exact_arguments() {
        let cli = parse_cli([
            OsString::from("launcher"),
            OsString::from("--manifest"),
            OsString::from("/etc/serverware/launch.json"),
        ])
        .unwrap();
        assert_eq!(cli.manifest, Path::new("/etc/serverware/launch.json"));
        assert!(parse_cli([
            OsString::from("launcher"),
            OsString::from("--manifest"),
            OsString::from("/x"),
            OsString::from("--manifest"),
            OsString::from("/y"),
        ])
        .is_err());
        assert!(parse_cli([
            OsString::from("launcher"),
            OsString::from("--manifest"),
            OsString::from("/x"),
            OsString::from("--extra"),
            OsString::from("value"),
        ])
        .is_err());
    }

    #[test]
    fn digest_validation_is_lowercase_and_exact() {
        assert!(require_sha256(&digest('a'), "test").is_ok());
        assert!(require_sha256(&digest('A'), "test").is_err());
        assert!(require_sha256("sha256:abc", "test").is_err());
        assert!(require_sha256(&format!("sha256:{}g", "a".repeat(63)), "test").is_err());
        assert!(require_digest_match(&digest('a'), &digest('a'), "import root").is_ok());
        assert!(require_digest_match(&digest('a'), &digest('b'), "import root").is_err());
    }

    #[test]
    fn paths_and_output_names_are_normalized_and_confined() {
        assert!(require_normalized_absolute(Path::new("/opt/release"), "test").is_ok());
        assert!(require_normalized_absolute(Path::new("opt/release"), "test").is_err());
        assert!(require_normalized_absolute(Path::new("/opt/../etc"), "test").is_err());
        assert!(validate_output_path(
            Path::new("/var/lib/serverware/production-proof/proof.json"),
            Path::new("/var/lib/serverware/production-proof"),
            "test"
        )
        .is_ok());
        assert!(validate_output_path(
            Path::new("/var/lib/serverware/proof.json"),
            Path::new("/var/lib/serverware/production-proof"),
            "test"
        )
        .is_err());
        let mut value = manifest_json();
        value["inputs"]["bench"]["path"] = json!("/tmp/bench.json");
        assert!(parse_manifest(&manifest_bytes(&value)).is_err());

        let mut moved_state_directory = manifest_json();
        moved_state_directory["stateDirectory"] =
            json!("/var/lib/serverware/other-production-proof");
        assert!(parse_manifest(&manifest_bytes(&moved_state_directory))
            .unwrap_err()
            .to_string()
            .contains("compiled production state directory"));

        let mut moved_journal = manifest_json();
        moved_journal["launchAttemptJournal"]["path"] =
            json!("/var/lib/serverware/production-proof/other-attempt.json");
        assert!(parse_manifest(&manifest_bytes(&moved_journal))
            .unwrap_err()
            .to_string()
            .contains("fixed v1 children"));

        let mut moved_lock = manifest_json();
        moved_lock["launchAttemptJournal"]["lockPath"] =
            json!("/var/lib/serverware/production-proof/other-attempt.lock");
        assert!(parse_manifest(&manifest_bytes(&moved_lock))
            .unwrap_err()
            .to_string()
            .contains("fixed v1 children"));
    }

    #[test]
    fn python_runtime_layout_is_exact_and_ordered() {
        assert!(parse_manifest(&manifest_bytes(&manifest_json())).is_ok());

        let mut missing = manifest_json();
        missing["python"]["importRoots"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(parse_manifest(&manifest_bytes(&missing)).is_err());

        let mut reordered = manifest_json();
        reordered["python"]["importRoots"]
            .as_array_mut()
            .unwrap()
            .swap(1, 2);
        assert!(parse_manifest(&manifest_bytes(&reordered)).is_err());

        let mut wrong_dynload = manifest_json();
        wrong_dynload["python"]["importRoots"][2]["path"] =
            json!("/opt/serverware/releases/release-a/runtime/python/lib/lib-dynload");
        assert!(parse_manifest(&manifest_bytes(&wrong_dynload)).is_err());

        let mut noncanonical_version = manifest_json();
        noncanonical_version["python"]["importRoots"][1]["path"] =
            json!("/opt/serverware/releases/release-a/runtime/python/lib/python3.011");
        noncanonical_version["python"]["importRoots"][2]["path"] =
            json!("/opt/serverware/releases/release-a/runtime/python/lib/python3.011/lib-dynload");
        assert!(parse_manifest(&manifest_bytes(&noncanonical_version)).is_err());

        let mut wrong_vendor = manifest_json();
        wrong_vendor["python"]["importRoots"][3]["path"] =
            json!("/opt/serverware/releases/release-a/runtime/vendor");
        assert!(parse_manifest(&manifest_bytes(&wrong_vendor)).is_err());

        let mut wrong_python = manifest_json();
        wrong_python["python"]["path"] = json!("/opt/serverware/releases/release-a/bin/python3");
        assert!(parse_manifest(&manifest_bytes(&wrong_python)).is_err());
    }

    #[test]
    fn python_identity_requires_structured_cpython_elf() {
        let valid =
            minimal_cpython_elf(ELF_MACHINE_X86_64, b"Py_BytesMain", b"libpython3.11.so.1.0");
        assert!(validate_cpython_elf64(&valid, "python3.11").is_ok());
        assert!(validate_cpython_elf64(b"#!/usr/bin/python3\n", "python3.11").is_err());
        assert!(validate_cpython_elf64(b"arbitrary executable", "python3.11").is_err());
        assert!(validate_cpython_elf64(
            &minimal_cpython_elf(183, b"Py_BytesMain", b"libpython3.11.so.1.0"),
            "python3.11",
        )
        .is_err());
        assert!(validate_cpython_elf64(
            &minimal_cpython_elf(ELF_MACHINE_X86_64, b"main", b"libc.so.6"),
            "python3.11",
        )
        .is_err());
        assert!(validate_cpython_elf64(
            &minimal_cpython_elf(ELF_MACHINE_X86_64, b"Py_BytesMain", b"libpython3.12.so.1.0",),
            "python3.11",
        )
        .is_err());
    }

    #[test]
    fn typed_manifest_rejects_unknown_and_duplicate_fields() {
        let mut value = manifest_json();
        value["unexpected"] = json!(true);
        assert!(parse_manifest(&manifest_bytes(&value)).is_err());
        let raw = String::from_utf8(manifest_bytes(&manifest_json())).unwrap();
        let duplicated = raw.replacen(
            "\"kind\":",
            "\"kind\":\"ProductionReadinessLaunch\",\"kind\":",
            1,
        );
        assert!(parse_manifest(duplicated.as_bytes()).is_err());
    }

    #[test]
    fn nonce_rollback_assurance_contract_is_closed_and_not_downgradable() {
        let mut legacy = manifest_json();
        legacy["apiVersion"] =
            json!("serverware.productionReadinessLaunch/v2");
        assert!(parse_manifest(&manifest_bytes(&legacy))
            .unwrap_err()
            .to_string()
            .contains("legacy v2 launch manifests are readiness-only"));

        let mut unknown_binding = manifest_json();
        unknown_binding["nonceRollbackAssurance"]["unexpected"] = json!(true);
        assert!(parse_manifest(&manifest_bytes(&unknown_binding)).is_err());

        let mut unknown_contract = manifest_json();
        unknown_contract["nonceRollbackAssurance"]["contract"]["unexpected"] = json!(true);
        assert!(parse_manifest(&manifest_bytes(&unknown_contract)).is_err());

        let mut missing_store_attestation = manifest_json();
        missing_store_attestation["nonceRollbackAssurance"]["contract"]
            ["publicConfigPins"]
            .as_object_mut()
            .unwrap()
            .remove(
                "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url",
            );
        assert!(parse_manifest(&manifest_bytes(&missing_store_attestation)).is_err());

        let mut missing_store_evidence = manifest_json();
        missing_store_evidence["nonceRollbackAssurance"]["contract"]
            ["publicConfigPins"]
            .as_object_mut()
            .unwrap()
            .remove(
                "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256",
            );
        assert!(parse_manifest(&manifest_bytes(&missing_store_evidence)).is_err());

        let mut stale_store_evidence_alias = manifest_json();
        let stale_store_evidence = stale_store_evidence_alias
            ["nonceRollbackAssurance"]["contract"]["publicConfigPins"]
            .as_object_mut()
            .unwrap()
            .remove(
                "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256",
            )
            .unwrap();
        stale_store_evidence_alias["nonceRollbackAssurance"]["contract"]
            ["publicConfigPins"]
            ["nonceAuthorityVerifierStateStoreAssuranceSha256"] =
            stale_store_evidence;
        assert!(
            parse_manifest(&manifest_bytes(&stale_store_evidence_alias))
                .is_err()
        );

        let mut store_key_collision = manifest_json();
        let verifier_state_key =
            store_key_collision["nonceRollbackAssurance"]["contract"]["publicConfigPins"]
                ["nonceAuthorityVerifierStateSigningPublicKeySpkiDerBase64url"]
                .clone();
        store_key_collision["nonceRollbackAssurance"]["contract"]["publicConfigPins"]
            ["nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url"] =
            verifier_state_key;
        rebind_nonce_rollback_assurance_contract(&mut store_key_collision);
        assert!(parse_manifest(&manifest_bytes(&store_key_collision))
            .unwrap_err()
            .to_string()
            .contains("signing roles are not independently pinned"));

        let mut store_evidence_collision = manifest_json();
        let authority_assurance_evidence =
            store_evidence_collision["nonceRollbackAssurance"]["contract"]
                ["publicConfigPins"]["nonceAuthorityAssurance"]
                ["assuranceEvidenceSha256"]
                .clone();
        store_evidence_collision["nonceRollbackAssurance"]["contract"]["publicConfigPins"]
            ["nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"] =
            authority_assurance_evidence;
        rebind_nonce_rollback_assurance_contract(&mut store_evidence_collision);
        assert!(parse_manifest(&manifest_bytes(&store_evidence_collision))
            .unwrap_err()
            .to_string()
            .contains("assurance evidence must be independently pinned"));

        let mut wrong_profile = manifest_json();
        wrong_profile["nonceRollbackAssurance"]["contract"]["publicConfigPins"]
            ["nonceAuthorityAssurance"]["rollbackProtection"]["mechanism"] =
            json!("appendOnlyWitnessedLedger");
        rebind_nonce_rollback_assurance_contract(&mut wrong_profile);
        assert!(parse_manifest(&manifest_bytes(&wrong_profile))
            .unwrap_err()
            .to_string()
            .contains("complete production rollback profile"));

        let mut role_collision = manifest_json();
        let authority_identity =
            role_collision["nonceRollbackAssurance"]["contract"]["publicConfigPins"]
                ["nonceAuthorityAssurance"]["authorityIdentitySha256"]
                .clone();
        role_collision["nonceRollbackAssurance"]["contract"]["publicConfigPins"]
            ["nonceAuthorityVerifierStateStoreIdentitySha256"] =
            authority_identity;
        rebind_nonce_rollback_assurance_contract(&mut role_collision);
        assert!(parse_manifest(&manifest_bytes(&role_collision))
            .unwrap_err()
            .to_string()
            .contains("pairwise distinct"));

        let mut unsafe_integer = manifest_json();
        unsafe_integer["nonceRollbackAssurance"]["contract"]["publicConfigPins"]
            ["nonceAuthorityAssurance"]["authorityGeneration"] =
            json!(JSON_SAFE_INTEGER_MAX + 1);
        rebind_nonce_rollback_assurance_contract(&mut unsafe_integer);
        assert!(parse_manifest(&manifest_bytes(&unsafe_integer))
            .unwrap_err()
            .to_string()
            .contains("complete production rollback profile"));
    }

    #[test]
    fn constructed_argv_is_closed_and_readiness_only() {
        let manifest = manifest();
        let preflight = build_preflight_argv(&manifest, 199);
        let readiness = build_readiness_argv(&manifest, 199);
        assert_eq!(
            preflight[0],
            manifest.scripts.preflight.path.to_string_lossy()
        );
        assert_eq!(readiness[0], manifest.scripts.runner.path.to_string_lossy());
        assert!(readiness
            .windows(2)
            .any(|pair| pair == ["--verification-mode", "readiness"]));
        assert!(!readiness.iter().any(|value| value == "final"));
        for argv in [&preflight, &readiness] {
            assert!(argv.windows(2).any(|pair| {
                pair
                    == [
                        "--launcher-nonce-rollback-assurance-pins",
                        "/proc/self/fd/199",
                    ]
            }));
            assert!(argv.iter().any(|value| {
                value
                    == "--launcher-nonce-rollback-assurance-pins-sha256"
            }));
            assert!(argv.iter().any(|value| {
                value
                    == "--launcher-nonce-rollback-assurance-contract-sha256"
            }));
        }
        for forbidden in [
            "--dry-run",
            "--config-only",
            "--claims-arg",
            "--skip-host-check",
        ] {
            assert!(!preflight.iter().any(|value| value == forbidden));
            assert!(!readiness.iter().any(|value| value == forbidden));
        }
        assert!(readiness.iter().all(|value| !value.starts_with("../")));
    }

    #[test]
    fn fixed_environment_has_only_the_contract_names() {
        let environment = fixed_environment(&digest('f'));
        let expected = BTreeSet::from([
            "LANG".to_string(),
            "LC_ALL".to_string(),
            "PATH".to_string(),
            "SERVERWARE_BOOTSTRAP_RECEIPT_API_VERSION".to_string(),
            "SERVERWARE_BOOTSTRAP_RECEIPT_FD".to_string(),
            "SERVERWARE_BOOTSTRAP_RECEIPT_SHA256".to_string(),
            "SERVERWARE_LAUNCHER_IMPORT_MODE".to_string(),
            "TZ".to_string(),
        ]);
        assert_eq!(
            environment.keys().cloned().collect::<BTreeSet<_>>(),
            expected
        );
        assert!(!environment.keys().any(|name| name.starts_with("LD_")));
        let commitment = environment_commitment().unwrap();
        assert_eq!(commitment.names, expected.into_iter().collect::<Vec<_>>());
        require_sha256(&commitment.sha256, "environment.sha256").unwrap();
    }

    #[test]
    fn authorization_is_nonce_bound_signed_and_time_limited() {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let request = authorization_request_fixture();
        let authorization_id = "a".repeat(64);
        let authority_key_id = launch_authority_key_id(&verifying_key);
        let monotonic_witness =
            signed_witness(&request, &authorization_id, &authority_key_id);
        let mut envelope = LaunchAuthorizationEnvelope {
            api_version: AUTHORIZATION_API_VERSION.to_string(),
            kind: AUTHORIZATION_KIND.to_string(),
            statement: LaunchAuthorizationStatement {
                authorization_id,
                authority_key_id,
                request_sha256: authorization_request_digest(&request).unwrap(),
                issued_at_unix_seconds: 1_000,
                expires_at_unix_seconds: 1_030,
                authorization_scope: AUTHORIZATION_SCOPE.to_string(),
                freshness_authority: FRESHNESS_AUTHORITY.to_string(),
                capability_semantics: CAPABILITY_SEMANTICS.to_string(),
                global_role_registry_sha256:
                    request.global_role_registry_sha256.clone(),
                monotonic_witness,
            },
            signature: String::new(),
        };
        envelope.signature = general_purpose::URL_SAFE_NO_PAD.encode(
            signing_key
                .sign(&authorization_signing_bytes(&envelope).unwrap())
                .to_bytes(),
        );
        let verified =
            verify_launch_authorization(
                request.clone(),
                envelope.clone(),
                &verifying_key,
                &witness_configuration(),
                1_001,
                AuthorizationTimePolicy::CurrentRequired,
            )
                .unwrap();
        assert_eq!(verified.request.launcher_nonce, "1".repeat(64));
        assert_eq!(verified.request_sha256, envelope.statement.request_sha256);

        let mut other_request = request.clone();
        other_request.launcher_nonce = "b".repeat(64);
        other_request.launch_attempt_recovery_identity_sha256 =
            launch_attempt_recovery_identity_sha256(&other_request).unwrap();
        assert!(verify_launch_authorization(
            other_request,
            envelope.clone(),
            &verifying_key,
            &witness_configuration(),
            1_001,
            AuthorizationTimePolicy::CurrentRequired,
        )
        .unwrap_err()
        .to_string()
        .contains("LAUTH_REQUEST_MISMATCH"));
        assert!(
            verify_launch_authorization(
                request,
                envelope,
                &verifying_key,
                &witness_configuration(),
                1_030,
                AuthorizationTimePolicy::CurrentRequired,
            )
                .unwrap_err()
                .to_string()
                .contains("LAUTH_EXPIRED")
        );
    }

    #[test]
    fn recovered_prior_boot_request_is_never_current_launchable_request() {
        let prior_boot_request = authorization_request_fixture();
        let mut current_boot_request = prior_boot_request.clone();
        current_boot_request.boot_id_sha256 = digest('f');
        current_boot_request.launch_attempt_recovery_identity_sha256 =
            launch_attempt_recovery_identity_sha256(&current_boot_request)
                .unwrap();

        assert!(!linux::recovered_request_matches_current_launch(
            &prior_boot_request,
            &current_boot_request,
        ));
        assert!(linux::recovered_request_matches_current_launch(
            &current_boot_request,
            &current_boot_request,
        ));
    }

    #[test]
    fn authorization_currentness_uses_future_skew_and_strict_expiry() {
        let request = authorization_request_fixture();
        let authority_key = SigningKey::from_bytes(&[7u8; 32]).verifying_key();
        let statement = LaunchAuthorizationStatement {
            authorization_id: "a".repeat(64),
            authority_key_id: launch_authority_key_id(&authority_key),
            request_sha256: digest('2'),
            issued_at_unix_seconds: 1_005,
            expires_at_unix_seconds: 1_010,
            authorization_scope: AUTHORIZATION_SCOPE.to_string(),
            freshness_authority: FRESHNESS_AUTHORITY.to_string(),
            capability_semantics: CAPABILITY_SEMANTICS.to_string(),
            global_role_registry_sha256:
                request.global_role_registry_sha256.clone(),
            monotonic_witness: signed_witness(
                &request,
                &"a".repeat(64),
                &launch_authority_key_id(&authority_key),
            ),
        };
        assert!(require_authorization_current(&statement, 1_000).is_ok());

        let mut too_far_future = statement.clone();
        too_far_future.issued_at_unix_seconds = 1_006;
        assert!(require_authorization_current(&too_far_future, 1_000)
            .unwrap_err()
            .to_string()
            .contains("LAUTH_FUTURE"));

        assert!(require_authorization_current(&statement, 1_009).is_ok());
        assert!(require_authorization_current(&statement, 1_010)
            .unwrap_err()
            .to_string()
            .contains("LAUTH_EXPIRED"));
    }

    #[test]
    fn receipt_json_is_canonical_sorted_compact_and_stable() {
        let metadata = ReceiptMetadata {
            device: 1,
            inode: 2,
            mode: 0o500,
            owner_uid: 0,
            owner_gid: 0,
            link_count: 1,
            size: 3,
            modified_unix_nanos: 4,
            changed_unix_nanos: 5,
        };
        let receipt_file = |path: &str, character| ReceiptFile {
            path: path.to_string(),
            sha256: digest(character),
            metadata: metadata.clone(),
        };
        let request = authorization_request_fixture();
        let receipt_authorization_id = "9".repeat(64);
        let receipt_authority_key_id = digest('4');
        let receipt_witness = signed_witness(
            &request,
            &receipt_authorization_id,
            &receipt_authority_key_id,
        );
        let envelope = LaunchAuthorizationEnvelope {
            api_version: AUTHORIZATION_API_VERSION.to_string(),
            kind: AUTHORIZATION_KIND.to_string(),
            statement: LaunchAuthorizationStatement {
                authorization_id: receipt_authorization_id,
                authority_key_id: receipt_authority_key_id,
                request_sha256: authorization_request_digest(&request).unwrap(),
                issued_at_unix_seconds: 100,
                expires_at_unix_seconds: 120,
                authorization_scope: AUTHORIZATION_SCOPE.to_string(),
                freshness_authority: FRESHNESS_AUTHORITY.to_string(),
                capability_semantics: CAPABILITY_SEMANTICS.to_string(),
                global_role_registry_sha256:
                    request.global_role_registry_sha256.clone(),
                monotonic_witness: receipt_witness,
            },
            signature: general_purpose::URL_SAFE_NO_PAD.encode([5u8; 64]),
        };
        let launch_authorization = ReceiptLaunchAuthorization {
            request,
            request_sha256: envelope.statement.request_sha256.clone(),
            authorization_sha256: sha256_prefixed(&canonical_json_bytes(&envelope).unwrap()),
            witness_public_key_spki_der_base64url: witness_configuration()
                .signing_public_key_spki_der_base64url,
            envelope,
            verified_at_unix_seconds: 101,
        };
        let receipt = BootstrapReceipt {
            api_version: RECEIPT_API_VERSION.to_string(),
            kind: RECEIPT_KIND.to_string(),
            launch_id: "a".repeat(64),
            boot_id_sha256: digest('b'),
            launcher: receipt_file("/launcher", 'c'),
            manifest: receipt_file("/manifest", 'd'),
            source_tree_digest: digest('e'),
            launch_authorization,
            nonce_rollback_assurance: ReceiptNonceRollbackAssurance {
                api_version:
                    NONCE_ROLLBACK_ASSURANCE_BINDING_API_VERSION.to_string(),
                contract_sha256: digest('a'),
                pins_file: receipt_file("/pins", 'b'),
                retained_snapshot_fd: 199,
                retained_snapshot_sha256: digest('b'),
                verifier_state_service: ReceiptVerifierStateService {
                    signing_public_key_spki_der_base64url:
                        general_purpose::URL_SAFE_NO_PAD.encode([
                            ED25519_SPKI_PREFIX.as_slice(),
                            &[0x22; 32],
                        ]
                        .concat()),
                    store_administrative_domain_sha256: digest('4'),
                    store_assurance_evidence_sha256: digest('6'),
                    store_attestation_public_key_spki_der_base64url:
                        general_purpose::URL_SAFE_NO_PAD.encode([
                            ED25519_SPKI_PREFIX.as_slice(),
                            &[0x33; 32],
                        ]
                        .concat()),
                    store_identity_sha256: digest('5'),
                },
            },
            production_env: receipt_file("/env", 'f'),
            python: ReceiptPython {
                path: "/python".to_string(),
                sha256: digest('1'),
                metadata: metadata.clone(),
                import_roots: vec![ReceiptImportRoot {
                    path: "/imports".to_string(),
                    sha256: digest('2'),
                    metadata: metadata.clone(),
                }],
            },
            scripts: ReceiptScripts {
                preflight: receipt_file("/preflight", '3'),
                runner: receipt_file("/runner", '4'),
            },
            compose_file: receipt_file("/compose", '5'),
            inputs: BTreeMap::from([("bench".to_string(), receipt_file("/bench", '6'))]),
            argv: ReceiptArgv {
                preflight_sha256: digest('7'),
                readiness_sha256: digest('8'),
            },
            environment: environment_commitment().unwrap(),
        };
        let first = canonical_json_bytes(&receipt).unwrap();
        let second = canonical_json_bytes(&receipt).unwrap();
        assert_eq!(first, second);
        assert!(!first.ends_with(b"\n"));
        assert_eq!(first[0], b'{');
        assert!(String::from_utf8(first.clone())
            .unwrap()
            .starts_with("{\"apiVersion\":"));
        assert_eq!(sha256_prefixed(&first), sha256_prefixed(&second));
    }
}
