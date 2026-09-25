use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::path::{Component, Path};

#[path = "native_postgres_contract_v12.rs"]
pub mod native_postgres_contract_v12;

#[path = "body_output_contract_v12.rs"]
pub mod body_output_contract_v12;

pub type Digest = [u8; 32];
pub type PlanResult<T> = Result<T, PlanProtocolError>;

pub const PLAN_PROTOCOL_VERSION: &str = "serverware/controller-plan/v12";
pub const PLAN_PROXY_PROTOCOL_VERSION: &str =
    "serverware/controller-lane-proxy/v12";
pub const PLAN_SEQUENCE_LANES: [LogicalLane; 5] = [
    LogicalLane::Build,
    LogicalLane::Unit,
    LogicalLane::Integration,
    LogicalLane::E2e,
    LogicalLane::Attestation,
];
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_ENVIRONMENT_ENTRIES: usize = 128;
pub const MAX_ARGUMENTS: usize = 256;
pub const MAX_ENDPOINTS: usize = 64;
pub const MAX_OCI_OBJECTS: usize = 512;
pub const MAX_SERVICES: usize = 64;
pub const RUNNER_PRIVATE_DATA_PATH_V12: &str = "/var/lib/serverware-runner";

#[derive(Debug)]
pub enum PlanProtocolError {
    Invalid(&'static str),
    InvalidOwned(String),
    Invariant(String),
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl fmt::Display for PlanProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::InvalidOwned(message) => formatter.write_str(message),
            Self::Invariant(message) => formatter.write_str(message),
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Json(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for PlanProtocolError {}

impl From<std::io::Error> for PlanProtocolError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for PlanProtocolError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

pub trait DigestValidation {
    fn validate(&self, field: &str) -> PlanResult<()>;
}

impl DigestValidation for Digest {
    fn validate(&self, field: &str) -> PlanResult<()> {
        if *self == [0; 32] {
            Err(PlanProtocolError::InvalidOwned(format!(
                "{field} is empty"
            )))
        } else {
            Ok(())
        }
    }
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "camelCase")]
pub enum LogicalLane {
    Build,
    Unit,
    Integration,
    E2e,
    Attestation,
}

impl LogicalLane {
    pub fn ordinal(self) -> u8 {
        match self {
            Self::Build => 0,
            Self::Unit => 1,
            Self::Integration => 2,
            Self::E2e => 3,
            Self::Attestation => 4,
        }
    }

    pub fn is_no_build(self) -> bool {
        self != Self::Build
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PlanPhase {
    Prepare,
    Body,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum NetworkPolicy {
    None,
    ServiceEndpointsOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DindGenerationKind {
    Build,
    NoBuild,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RuntimeTrustProfile {
    TrustedHostNoTee,
    ImaEvmAppraised,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CasSealingPolicyV12 {
    RequiredFsVerity,
    RequiredImmutable,
    UserspaceDigestOnly,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CasSealingEvidenceV12 {
    pub policy: CasSealingPolicyV12,
    pub userspace_manifest_sha256: Digest,
    pub fs_verity_file_digests_sha256: Option<Digest>,
    pub immutable_file_set_sha256: Option<Digest>,
}

impl CasSealingEvidenceV12 {
    pub fn validate(&self) -> PlanResult<()> {
        require_digest(
            &self.userspace_manifest_sha256,
            "CAS userspace sealing manifest",
        )?;
        match self.policy {
            CasSealingPolicyV12::UserspaceDigestOnly
                if self.fs_verity_file_digests_sha256.is_none()
                    && self.immutable_file_set_sha256.is_none() => Ok(()),
            CasSealingPolicyV12::RequiredFsVerity
                if self.immutable_file_set_sha256.is_none() => {
                    require_digest(
                        self.fs_verity_file_digests_sha256.as_ref().ok_or(
                            PlanProtocolError::Invalid(
                                "fs-verity sealing evidence is absent",
                            ),
                        )?,
                        "fs-verity sealing evidence",
                    )
                }
            CasSealingPolicyV12::RequiredImmutable
                if self.fs_verity_file_digests_sha256.is_none() => {
                    require_digest(
                        self.immutable_file_set_sha256.as_ref().ok_or(
                            PlanProtocolError::Invalid(
                                "immutable sealing evidence is absent",
                            ),
                        )?,
                        "immutable sealing evidence",
                    )
                }
            _ => Err(PlanProtocolError::Invalid(
                "CAS sealing evidence overclaims or mixes sealing profiles",
            )),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SourceCasReference {
    pub manifest_sha256: Digest,
    pub object_sha256: Digest,
    pub entry_count: u64,
    pub total_bytes: u64,
    pub sealing_evidence: CasSealingEvidenceV12,
}

impl SourceCasReference {
    pub fn validate(&self) -> PlanResult<()> {
        require_digest(&self.manifest_sha256, "source manifest digest")?;
        require_digest(&self.object_sha256, "source object digest")?;
        self.sealing_evidence.validate()?;
        if self.entry_count == 0 {
            return Err(PlanProtocolError::Invalid(
                "source CAS object has no entries",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OciObjectReference {
    pub repository: String,
    pub manifest_digest_sha256: Digest,
    pub index_digest_sha256: Option<Digest>,
    pub platform: String,
    pub size: u64,
}

impl OciObjectReference {
    pub fn validate(&self) -> PlanResult<()> {
        require_identifier(&self.repository, 1, 256, "OCI repository")?;
        require_digest(
            &self.manifest_digest_sha256,
            "OCI manifest digest",
        )?;
        if let Some(index_digest) = &self.index_digest_sha256 {
            require_digest(index_digest, "OCI index digest")?;
        }
        require_platform(&self.platform)?;
        if self.size == 0 {
            return Err(PlanProtocolError::Invalid(
                "OCI object size must be nonzero",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ArtifactCasReference {
    pub manifest_sha256: Digest,
    pub object_sha256: Digest,
    pub source_manifest_sha256: Digest,
    pub build_plan_sha256: Digest,
    pub files_sha256: Digest,
    pub oci_objects: Vec<OciObjectReference>,
    pub sealing_evidence: CasSealingEvidenceV12,
}

impl ArtifactCasReference {
    pub fn validate(&self) -> PlanResult<()> {
        require_digest(&self.manifest_sha256, "artifact manifest digest")?;
        require_digest(&self.object_sha256, "artifact object digest")?;
        require_digest(
            &self.source_manifest_sha256,
            "artifact source digest",
        )?;
        require_digest(&self.build_plan_sha256, "artifact build-plan digest")?;
        require_digest(&self.files_sha256, "artifact files digest")?;
        self.sealing_evidence.validate()?;
        if self.oci_objects.is_empty()
            || self.oci_objects.len() > MAX_OCI_OBJECTS
        {
            return Err(PlanProtocolError::Invalid(
                "artifact OCI object set is empty or excessive",
            ));
        }
        let mut identities = BTreeSet::new();
        for object in &self.oci_objects {
            object.validate()?;
            if !identities.insert((
                object.repository.clone(),
                object.platform.clone(),
                object.manifest_digest_sha256,
            )) {
                return Err(PlanProtocolError::Invalid(
                    "artifact OCI object set contains a duplicate",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RequiredOciImportClosureV12 {
    pub manifest_sha256: Vec<Digest>,
    pub closure_sha256: Digest,
}

impl RequiredOciImportClosureV12 {
    pub fn new(manifest_sha256: Vec<Digest>) -> PlanResult<Self> {
        let closure_sha256 = canonical_sha256(&manifest_sha256)?;
        let closure = Self {
            manifest_sha256,
            closure_sha256,
        };
        closure.validate()?;
        Ok(closure)
    }

    pub fn validate(&self) -> PlanResult<()> {
        require_digest(
            &self.closure_sha256,
            "required OCI import closure digest",
        )?;
        if self.manifest_sha256.is_empty()
            || self.manifest_sha256.len() > MAX_OCI_OBJECTS
        {
            return Err(PlanProtocolError::Invalid(
                "required OCI import closure is empty or excessive",
            ));
        }
        let mut prior: Option<&Digest> = None;
        for digest in &self.manifest_sha256 {
            require_digest(digest, "required OCI import manifest")?;
            if prior.is_some_and(|prior| prior >= digest) {
                return Err(PlanProtocolError::Invalid(
                    "required OCI import closure is not strictly sorted",
                ));
            }
            prior = Some(digest);
        }
        if canonical_sha256(&self.manifest_sha256)?
            != self.closure_sha256
        {
            return Err(PlanProtocolError::Invalid(
                "required OCI import closure digest is not canonical",
            ));
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        artifacts: &ArtifactCasReference,
    ) -> PlanResult<()> {
        self.validate()?;
        artifacts.validate()?;
        let available: BTreeSet<Digest> = artifacts
            .oci_objects
            .iter()
            .map(|object| object.manifest_digest_sha256)
            .collect();
        if !self
            .manifest_sha256
            .iter()
            .all(|digest| available.contains(digest))
        {
            return Err(PlanProtocolError::Invalid(
                "required OCI import closure is outside sealed artifact CAS",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PinnedPull {
    pub registry: String,
    pub repository: String,
    pub manifest_digest_sha256: Digest,
    pub platform: String,
}

impl PinnedPull {
    pub fn validate(&self) -> PlanResult<()> {
        require_identifier(&self.registry, 1, 253, "registry")?;
        require_identifier(&self.repository, 1, 256, "repository")?;
        require_digest(
            &self.manifest_digest_sha256,
            "pinned pull manifest digest",
        )?;
        require_platform(&self.platform)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExactBuildTuple {
    pub source_manifest_sha256: Digest,
    pub context_relative_path: String,
    pub dockerfile_relative_path: String,
    pub dockerfile_sha256: Digest,
    pub target: String,
    pub platform: String,
    pub build_arguments: Vec<EnvironmentEntry>,
    pub pinned_pulls: Vec<PinnedPull>,
    pub expected_repositories: Vec<String>,
    pub output_kind: BuildOutputKind,
}

impl ExactBuildTuple {
    pub fn validate(&self) -> PlanResult<()> {
        require_digest(
            &self.source_manifest_sha256,
            "build source manifest digest",
        )?;
        require_relative_path(
            &self.context_relative_path,
            "build context path",
        )?;
        require_relative_path(
            &self.dockerfile_relative_path,
            "Dockerfile path",
        )?;
        require_digest(&self.dockerfile_sha256, "Dockerfile digest")?;
        require_identifier(&self.target, 1, 128, "build target")?;
        require_platform(&self.platform)?;
        validate_environment(&self.build_arguments, true)?;
        if self.pinned_pulls.is_empty() {
            return Err(PlanProtocolError::Invalid(
                "build must declare every pinned pull",
            ));
        }
        let mut prior_pull: Option<(&str, &str, &str, Digest)> = None;
        for pull in &self.pinned_pulls {
            pull.validate()?;
            let identity = (
                pull.registry.as_str(),
                pull.repository.as_str(),
                pull.platform.as_str(),
                pull.manifest_digest_sha256,
            );
            if prior_pull.is_some_and(|prior| prior >= identity) {
                return Err(PlanProtocolError::Invalid(
                    "pinned pulls are not strictly sorted",
                ));
            }
            prior_pull = Some(identity);
        }
        if self.expected_repositories.is_empty()
            || self.expected_repositories.len() > MAX_OCI_OBJECTS
        {
            return Err(PlanProtocolError::Invalid(
                "build expected repository set is empty or excessive",
            ));
        }
        let mut repositories = BTreeSet::new();
        let mut prior_repository: Option<&str> = None;
        for repository in &self.expected_repositories {
            require_identifier(repository, 1, 256, "expected repository")?;
            if !repositories.insert(repository)
                || prior_repository
                    .is_some_and(|prior| prior >= repository.as_str())
            {
                return Err(PlanProtocolError::Invalid(
                    "build expected repository set contains a duplicate",
                ));
            }
            prior_repository = Some(repository.as_str());
        }
        if self.output_kind != BuildOutputKind::OciCas {
            return Err(PlanProtocolError::Invalid(
                "build output must be an OCI CAS object",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BuildOutputKind {
    OciCas,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EnvironmentEntry {
    pub name: String,
    pub value: String,
}

impl EnvironmentEntry {
    fn validate(&self, build_argument: bool) -> PlanResult<()> {
        require_environment_name(&self.name)?;
        if self.value.len() > 16 * 1024 || self.value.as_bytes().contains(&0) {
            return Err(PlanProtocolError::Invalid(
                "environment value is invalid",
            ));
        }
        if forbidden_environment_name(&self.name) {
            return Err(PlanProtocolError::InvalidOwned(format!(
                "repository command may not receive {}",
                self.name,
            )));
        }
        if build_argument
            && self.name.to_ascii_lowercase().contains("secret")
        {
            return Err(PlanProtocolError::Invalid(
                "build arguments may not carry secrets",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ContainerCommand {
    pub executable: String,
    pub argv: Vec<String>,
    pub environment: Vec<EnvironmentEntry>,
    pub cwd: String,
    pub executable_sha256: Digest,
    pub command_sha256: Digest,
    pub timeout_ns: u64,
}

impl ContainerCommand {
    pub fn validate(&self) -> PlanResult<()> {
        require_absolute_container_path(&self.executable, "command executable")?;
        require_absolute_container_path(&self.cwd, "command working directory")?;
        require_digest(&self.executable_sha256, "command executable digest")?;
        require_digest(&self.command_sha256, "command identity digest")?;
        if self.argv.is_empty() || self.argv.len() > MAX_ARGUMENTS {
            return Err(PlanProtocolError::Invalid(
                "command argument vector is empty or excessive",
            ));
        }
        for argument in &self.argv {
            if argument.len() > 64 * 1024 || argument.as_bytes().contains(&0) {
                return Err(PlanProtocolError::Invalid(
                    "command argument is invalid",
                ));
            }
        }
        validate_environment(&self.environment, false)?;
        if self.timeout_ns == 0 {
            return Err(PlanProtocolError::Invalid(
                "command timeout must be nonzero",
            ));
        }
        let expected = command_identity_sha256(
            &self.executable,
            &self.argv,
            &self.environment,
            &self.cwd,
            &self.executable_sha256,
        )?;
        if expected != self.command_sha256 {
            return Err(PlanProtocolError::Invalid(
                "command identity digest is not canonical",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceEndpoint {
    pub endpoint_id: String,
    pub protocol: EndpointProtocol,
    pub authority: String,
    pub port: u16,
    pub identity_sha256: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceHealthContractV12 {
    pub protocol: EndpointProtocol,
    pub port: u16,
    pub path: String,
    pub expected_status: u16,
    pub expected_headers_sha256: Digest,
    pub expected_body_sha256: Digest,
    pub interval_ns: u64,
    pub timeout_ns: u64,
    pub success_threshold: u32,
    pub failure_threshold: u32,
}

impl ServiceHealthContractV12 {
    fn validate(&self) -> PlanResult<()> {
        if !matches!(
            self.protocol,
            EndpointProtocol::Http | EndpointProtocol::Https
        ) || self.port == 0
            || self.path.is_empty()
            || self.path.len() > 2048
            || !self.path.starts_with('/')
            || self.path.contains("..")
            || !(100..=599).contains(&self.expected_status)
            || self.expected_headers_sha256 == [0; 32]
            || self.expected_body_sha256 == [0; 32]
            || self.interval_ns == 0
            || self.timeout_ns == 0
            || self.timeout_ns > self.interval_ns
            || self.success_threshold == 0
            || self.failure_threshold == 0
        {
            return Err(PlanProtocolError::Invalid(
                "service health contract is invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceResourceLimitsV12 {
    pub cpu_quota_micros: u64,
    pub cpu_period_micros: u64,
    pub memory_bytes: u64,
    pub pids: u32,
    pub open_files: u32,
    pub writable_bytes: u64,
}

impl ServiceResourceLimitsV12 {
    fn validate(&self) -> PlanResult<()> {
        if self.cpu_quota_micros == 0
            || self.cpu_period_micros == 0
            || self
                .cpu_period_micros
                .checked_mul(64)
                .is_none_or(|maximum| {
                    self.cpu_quota_micros > maximum
                })
            || self.memory_bytes < 16 * 1024 * 1024
            || self.memory_bytes > 64 * 1024 * 1024 * 1024
            || self.pids == 0
            || self.pids > 65_536
            || self.open_files < 16
            || self.open_files > 1_048_576
            || self.writable_bytes > 64 * 1024 * 1024 * 1024
        {
            return Err(PlanProtocolError::Invalid(
                "service resource limits are invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceInstanceV12 {
    pub version: String,
    pub service_id: Digest,
    pub sealed_image: OciObjectReference,
    pub command: ContainerCommand,
    pub owner_namespace_sha256: Digest,
    pub private_alias: String,
    pub health: ServiceHealthContractV12,
    pub limits: ServiceResourceLimitsV12,
    pub expected_endpoint: ServiceEndpoint,
    pub instance_sha256: Digest,
    pub signer_key_id: String,
    pub signature: Vec<u8>,
}

impl ServiceInstanceV12 {
    pub fn validate(&self) -> PlanResult<()> {
        if self.version != "serverware/service-instance/v12"
            || self.service_id == [0; 32]
            || self.owner_namespace_sha256 == [0; 32]
            || self.instance_sha256 == [0; 32]
            || self.signer_key_id.is_empty()
            || self.signer_key_id.len() > 128
            || self.signature.len() != 64
        {
            return Err(PlanProtocolError::Invalid(
                "service instance envelope is invalid",
            ));
        }
        self.sealed_image.validate()?;
        self.command.validate()?;
        self.health.validate()?;
        self.limits.validate()?;
        validate_private_service_alias(&self.private_alias)?;
        self.expected_endpoint.validate()?;
        if self.expected_endpoint.authority != self.private_alias
            || self.expected_endpoint.port != self.health.port
            || self.expected_endpoint.protocol != self.health.protocol
            || self.expected_endpoint.identity_sha256
                != self.service_id
        {
            return Err(PlanProtocolError::Invalid(
                "service endpoint is not derived from its sealed instance",
            ));
        }
        let mut copy = self.clone();
        copy.instance_sha256 = [0; 32];
        copy.signature.clear();
        if canonical_sha256(&copy)? != self.instance_sha256 {
            return Err(PlanProtocolError::Invalid(
                "service instance digest is not canonical",
            ));
        }
        Ok(())
    }
}

impl ServiceEndpoint {
    pub fn validate(&self) -> PlanResult<()> {
        require_identifier(&self.endpoint_id, 1, 128, "endpoint ID")?;
        require_identifier(&self.authority, 1, 253, "endpoint authority")?;
        require_digest(&self.identity_sha256, "endpoint identity digest")?;
        if self.port == 0 {
            return Err(PlanProtocolError::Invalid(
                "service endpoint port must be nonzero",
            ));
        }
        let authority = self.authority.to_ascii_lowercase();
        if authority == "localhost"
            || authority == "host.docker.internal"
            || authority == "docker"
            || authority.ends_with(".local")
        {
            return Err(PlanProtocolError::Invalid(
                "service endpoint may not resolve to host authority",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum EndpointProtocol {
    Http,
    Https,
    Tcp,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RunnerExecutionBoundsV12 {
    pub user_uid: u32,
    pub user_gid: u32,
    pub cpu_quota_micros: u64,
    pub cpu_period_micros: u64,
    pub memory_bytes: u64,
    pub pids: u32,
    pub open_files: u32,
    pub shm_bytes: u64,
    pub run_tmpfs_bytes: u64,
    pub tmp_tmpfs_bytes: u64,
    pub private_data_bytes: u64,
    pub output_bytes: u64,
    pub output_inodes: u64,
}

impl RunnerExecutionBoundsV12 {
    pub fn validate(&self) -> PlanResult<()> {
        if !(1000..=2_147_483_647).contains(&self.user_uid)
            || !(1000..=2_147_483_647).contains(&self.user_gid)
            || self.cpu_period_micros != 100_000
            || !(1000..=6_400_000).contains(&self.cpu_quota_micros)
            || !(256 * 1024 * 1024..=64 * 1024 * 1024 * 1024)
                .contains(&self.memory_bytes)
            || !(16..=8192).contains(&self.pids)
            || !(64..=65_536).contains(&self.open_files)
            || !(16 * 1024 * 1024..=1024 * 1024 * 1024)
                .contains(&self.shm_bytes)
            || !(1024 * 1024..=256 * 1024 * 1024)
                .contains(&self.run_tmpfs_bytes)
            || !(16 * 1024 * 1024..=1024 * 1024 * 1024)
                .contains(&self.tmp_tmpfs_bytes)
            || !(16 * 1024 * 1024..=8 * 1024 * 1024 * 1024)
                .contains(&self.private_data_bytes)
            || !(16 * 1024 * 1024..=1024 * 1024 * 1024)
                .contains(&self.output_bytes)
            || self.output_bytes % (1024 * 1024) != 0
            || !(64..=65_536).contains(&self.output_inodes)
        {
            return Err(PlanProtocolError::Invalid(
                "runner execution bounds are invalid",
            ));
        }
        let writable_bytes = self
            .shm_bytes
            .checked_add(self.run_tmpfs_bytes)
            .and_then(|sum| sum.checked_add(self.tmp_tmpfs_bytes))
            .and_then(|sum| sum.checked_add(self.private_data_bytes))
            .and_then(|sum| sum.checked_add(self.output_bytes))
            .ok_or(PlanProtocolError::Invalid(
                "runner writable memory bound overflows",
            ))?;
        if writable_bytes > self.memory_bytes {
            return Err(PlanProtocolError::Invalid(
                "runner writable memory exceeds its memory bound",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RunnerIdentity {
    pub image: OciObjectReference,
    pub runtime_executable_sha256: Digest,
    pub rootfs_sha256: Digest,
    pub static_courier_sha256: Option<Digest>,
    pub executable_closure_sha256: Vec<Digest>,
    pub mount_policy: RunnerMountPolicy,
    pub execution_bounds: RunnerExecutionBoundsV12,
}

impl RunnerIdentity {
    pub fn validate(&self) -> PlanResult<()> {
        self.image.validate()?;
        require_digest(
            &self.runtime_executable_sha256,
            "runner runtime executable digest",
        )?;
        require_digest(&self.rootfs_sha256, "runner rootfs digest")?;
        let courier = self.static_courier_sha256.as_ref().ok_or(
            PlanProtocolError::Invalid(
                "runner identity lacks its static courier digest",
            ),
        )?;
        require_digest(courier, "static courier digest")?;
        if self.executable_closure_sha256.is_empty()
            || self.executable_closure_sha256.len() > 4096
        {
            return Err(PlanProtocolError::Invalid(
                "runner executable closure is empty or excessive",
            ));
        }
        let mut prior: Option<&Digest> = None;
        for digest in &self.executable_closure_sha256 {
            require_digest(digest, "runner executable closure digest")?;
            if prior.is_some_and(|prior| prior >= digest) {
                return Err(PlanProtocolError::Invalid(
                    "runner executable closure is not strictly sorted",
                ));
            }
            prior = Some(digest);
        }
        if self
            .executable_closure_sha256
            .binary_search(&self.runtime_executable_sha256)
            .is_err()
            || self
                .executable_closure_sha256
                .binary_search(courier)
                .is_err()
        {
            return Err(PlanProtocolError::Invalid(
                "runner or courier executable is outside its closure",
            ));
        }
        self.mount_policy.validate()?;
        self.execution_bounds.validate()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RunnerMountPolicy {
    pub source_destination: String,
    pub artifact_destination: String,
    pub output_destination: String,
    pub source_read_only: bool,
    pub artifacts_read_only: bool,
    pub root_filesystem_read_only: bool,
    pub no_host_bind_mounts: bool,
    pub no_socket_mounts: bool,
    pub private_run_tmpfs: bool,
    pub private_tmp_tmpfs: bool,
}

impl RunnerMountPolicy {
    pub fn validate(&self) -> PlanResult<()> {
        require_absolute_container_path(
            &self.source_destination,
            "runner source destination",
        )?;
        require_absolute_container_path(
            &self.artifact_destination,
            "runner artifact destination",
        )?;
        require_absolute_container_path(
            &self.output_destination,
            "runner output destination",
        )?;
        let destinations = [
            self.source_destination.as_str(),
            self.artifact_destination.as_str(),
            self.output_destination.as_str(),
        ];
        if paths_overlap(destinations[0], destinations[1])
            || paths_overlap(destinations[0], destinations[2])
            || paths_overlap(destinations[1], destinations[2])
            || destinations
                .iter()
                .any(|path| matches!(*path, "/run" | "/tmp" | "/"))
            || destinations.iter().any(|path| {
                paths_overlap(path, RUNNER_PRIVATE_DATA_PATH_V12)
            })
            || !self.source_read_only
            || !self.artifacts_read_only
            || !self.root_filesystem_read_only
            || !self.no_host_bind_mounts
            || !self.no_socket_mounts
            || !self.private_run_tmpfs
            || !self.private_tmp_tmpfs
        {
            return Err(PlanProtocolError::Invalid(
                "runner mount policy permits host or authority exposure",
            ));
        }
        Ok(())
    }
}

fn paths_overlap(left: &str, right: &str) -> bool {
    Path::new(left).starts_with(right) || Path::new(right).starts_with(left)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PrepareContract {
    pub lane: LogicalLane,
    pub generation_kind: DindGenerationKind,
    pub source: SourceCasReference,
    pub artifacts: Option<ArtifactCasReference>,
    pub runner: RunnerIdentity,
    pub exact_build: Option<ExactBuildTuple>,
    pub imported_oci_manifest_sha256: Vec<Digest>,
    pub services: Vec<ServiceInstanceV12>,
    pub prepare_sha256: Digest,
}

impl PrepareContract {
    pub fn validate(&self) -> PlanResult<()> {
        self.source.validate()?;
        self.runner.validate()?;
        require_digest(&self.prepare_sha256, "prepare contract digest")?;
        if self.services.len() > MAX_SERVICES {
            return Err(PlanProtocolError::Invalid(
                "prepare service set is excessive",
            ));
        }
        let mut prior_service: Option<&str> = None;
        for service in &self.services {
            service.validate()?;
            if prior_service
                .is_some_and(|prior| {
                    prior >= service.private_alias.as_str()
                })
            {
                return Err(PlanProtocolError::Invalid(
                    "prepare services are not strictly sorted",
                ));
            }
            prior_service = Some(service.private_alias.as_str());
        }
        match self.lane {
            LogicalLane::Build => {
                if self.generation_kind != DindGenerationKind::Build
                    || self.artifacts.is_some()
                    || self.exact_build.is_none()
                    || !self.imported_oci_manifest_sha256.is_empty()
                    || !self.services.is_empty()
                {
                    return Err(PlanProtocolError::Invalid(
                        "build prepare contract has no-build authority",
                    ));
                }
                let build = self.exact_build.as_ref().ok_or(
                    PlanProtocolError::Invalid(
                        "build prepare contract lacks exact tuple",
                    ),
                )?;
                build.validate()?;
                if build.source_manifest_sha256
                    != self.source.manifest_sha256
                {
                    return Err(PlanProtocolError::Invalid(
                        "build tuple is not bound to source CAS",
                    ));
                }
            }
            lane => {
                if self.generation_kind != DindGenerationKind::NoBuild
                    || self.exact_build.is_some()
                {
                    return Err(PlanProtocolError::Invalid(
                        "no-build prepare contract contains build authority",
                    ));
                }
                let artifacts = self.artifacts.as_ref().ok_or(
                    PlanProtocolError::Invalid(
                        "no-build prepare contract lacks artifact CAS",
                    ),
                )?;
                artifacts.validate()?;
                if artifacts.source_manifest_sha256
                    != self.source.manifest_sha256
                {
                    return Err(PlanProtocolError::Invalid(
                        "no-build artifacts are not bound to source CAS",
                    ));
                }
                if self.imported_oci_manifest_sha256.is_empty()
                    || self.imported_oci_manifest_sha256.len()
                        > MAX_OCI_OBJECTS
                {
                    return Err(PlanProtocolError::Invalid(
                        "no-build OCI import set is empty or excessive",
                    ));
                }
                let available: BTreeSet<Digest> = artifacts
                    .oci_objects
                    .iter()
                    .map(|object| object.manifest_digest_sha256)
                    .collect();
                let mut imported = BTreeSet::new();
                let mut prior_import: Option<&Digest> = None;
                for digest in &self.imported_oci_manifest_sha256 {
                    require_digest(digest, "imported OCI digest")?;
                    if !available.contains(digest)
                        || !imported.insert(*digest)
                        || prior_import.is_some_and(|prior| prior >= digest)
                    {
                        return Err(PlanProtocolError::Invalid(
                            "no-build OCI import is absent or duplicated",
                        ));
                    }
                    prior_import = Some(digest);
                }
                match lane {
                    LogicalLane::Integration | LogicalLane::E2e => {}
                    _ if !self.services.is_empty() => {
                        return Err(PlanProtocolError::Invalid(
                            "only integration and e2e prepare services",
                        ));
                    }
                    _ => {}
                }
            }
        }
        if canonical_sha256_without_digest(
            self,
            |value| value.prepare_sha256 = [0; 32],
        )? != self.prepare_sha256
        {
            return Err(PlanProtocolError::Invalid(
                "prepare contract digest is not canonical",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BodyContract {
    pub lane: LogicalLane,
    pub command: ContainerCommand,
    pub network_policy: NetworkPolicy,
    pub source_read_only: bool,
    pub artifacts_read_only: bool,
    pub docker_api_visible: bool,
    pub expected_output_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_postgres: Option<native_postgres_contract_v12::NativePostgresContractV12>,
    pub body_sha256: Digest,
}

impl BodyContract {
    pub fn validate(&self) -> PlanResult<()> {
        self.command.validate()?;
        require_digest(&self.body_sha256, "body contract digest")?;
        if !self.source_read_only
            || !self.artifacts_read_only
            || self.docker_api_visible
        {
            return Err(PlanProtocolError::Invalid(
                "repository body has writable inputs or Docker authority",
            ));
        }
        match self.lane {
            LogicalLane::Integration | LogicalLane::E2e => {
                if self.network_policy != NetworkPolicy::ServiceEndpointsOnly {
                    return Err(PlanProtocolError::Invalid(
                        "integration/e2e body lacks endpoint-only network policy",
                    ));
                }
            }
            _ => {
                if self.network_policy != NetworkPolicy::None {
                    return Err(PlanProtocolError::Invalid(
                        "non-service lane has network endpoints",
                    ));
                }
            }
        }
        body_output_contract_v12::validate_output_paths(&self.expected_output_paths)?;
        if let Some(native) = &self.native_postgres {
            native.validate()?;
            if self.lane != LogicalLane::Unit
                || self.command.timeout_ns < native_postgres_contract_v12::REQUIRED_RUNTIME_NS
                || native_postgres_contract_v12::expected_output_paths().iter()
                    .any(|path| !self.expected_output_paths.contains(path))
            {
                return Err(PlanProtocolError::Invalid(
                    "native PostgreSQL body lacks its signed unit, deadline or complete output scope",
                ));
            }
        }
        if canonical_sha256_without_digest(
            self,
            |value| value.body_sha256 = [0; 32],
        )? != self.body_sha256
        {
            return Err(PlanProtocolError::Invalid(
                "body contract digest is not canonical",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LogicalLaneContract {
    pub lane: LogicalLane,
    pub prepare: PrepareContract,
    pub body: BodyContract,
}

impl LogicalLaneContract {
    pub fn validate(&self) -> PlanResult<()> {
        if self.prepare.lane != self.lane || self.body.lane != self.lane {
            return Err(PlanProtocolError::Invalid(
                "lane prepare/body identity differs",
            ));
        }
        self.prepare.validate()?;
        self.body.validate()?;
        if self.body.native_postgres.is_some() {
            let runner = &self.prepare.runner;
            let bounds = &runner.execution_bounds;
            let mib = 1024 * 1024;
            if self.prepare.artifacts.is_none()
                || runner.image.platform != "linux/amd64"
                || runner.mount_policy.source_destination != "/opt/serverware/src"
                || runner.mount_policy.artifact_destination != "/opt/serverware/artifacts"
                || runner.mount_policy.output_destination != "/opt/serverware/output"
                || bounds.user_uid != 10001 || bounds.user_gid != 10001
                || bounds.memory_bytes < 4096 * mib
                || bounds.pids < 128 || bounds.open_files < 1024
                || bounds.shm_bytes < 64 * mib || bounds.run_tmpfs_bytes < 64 * mib
                || bounds.tmp_tmpfs_bytes < 256 * mib || bounds.private_data_bytes < 2048 * mib
                || bounds.output_bytes < 256 * mib || bounds.output_inodes < 4096
            {
                return Err(PlanProtocolError::Invalid(
                    "native PostgreSQL runner lacks its fixed prepared mount and bounded resource profile",
                ));
            }
        }
        if matches!(
            self.lane,
            LogicalLane::Integration | LogicalLane::E2e
        ) && self.prepare.services.is_empty()
        {
            return Err(PlanProtocolError::Invalid(
                "integration/e2e lane has no signed service instances",
            ));
        }
        if self
            .prepare
            .runner
            .executable_closure_sha256
            .binary_search(&self.body.command.executable_sha256)
            .is_err()
        {
            return Err(PlanProtocolError::Invalid(
                "repository body executable is outside runner closure",
            ));
        }
        Ok(())
    }

    pub fn derived_service_endpoints(
        &self,
    ) -> PlanResult<Vec<ServiceEndpoint>> {
        self.validate()?;
        if self.prepare.services.len() > MAX_ENDPOINTS {
            return Err(PlanProtocolError::Invalid(
                "derived service endpoint set is excessive",
            ));
        }
        Ok(self
            .prepare
            .services
            .iter()
            .map(|service| service.expected_endpoint.clone())
            .collect())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LogicalPlanV12 {
    pub protocol: String,
    pub plan_id: Digest,
    pub generation_sha256: Digest,
    pub boot_id_sha256: Digest,
    pub source: SourceCasReference,
    pub expected_artifact_manifest_sha256: Digest,
    pub no_build_oci_import_closure_sha256: Vec<Digest>,
    pub no_build_oci_import_set_sha256: Digest,
    pub deadline_boottime_ns: u64,
    pub trust_profile: RuntimeTrustProfile,
    pub lanes: [LogicalLaneContract; 5],
    pub plan_sha256: Digest,
}

impl LogicalPlanV12 {
    pub fn validate(&self) -> PlanResult<()> {
        if self.protocol != PLAN_PROTOCOL_VERSION {
            return Err(PlanProtocolError::Invalid(
                "logical plan protocol is not v12",
            ));
        }
        require_digest(&self.plan_id, "logical plan ID")?;
        require_digest(&self.generation_sha256, "logical plan generation")?;
        require_digest(&self.boot_id_sha256, "logical plan boot identity")?;
        if self.boot_id_sha256 != current_boot_id_sha256()? {
            return Err(PlanProtocolError::Invalid(
                "logical plan belongs to a different host boot",
            ));
        }
        require_digest(
            &self.expected_artifact_manifest_sha256,
            "expected artifact manifest digest",
        )?;
        require_digest(
            &self.no_build_oci_import_set_sha256,
            "no-build OCI import-set digest",
        )?;
        require_digest(&self.plan_sha256, "logical plan digest")?;
        self.source.validate()?;
        if self.deadline_boottime_ns == 0 {
            return Err(PlanProtocolError::Invalid(
                "logical plan deadline must be nonzero",
            ));
        }
        if self.trust_profile != RuntimeTrustProfile::TrustedHostNoTee {
            return Err(PlanProtocolError::Invalid(
                "IMA profile requires external activation evidence",
            ));
        }
        for (index, lane) in self.lanes.iter().enumerate() {
            if lane.lane != PLAN_SEQUENCE_LANES[index] {
                return Err(PlanProtocolError::Invalid(
                    "logical plan lanes are not in fixed order",
                ));
            }
            lane.validate()?;
            if lane.prepare.source != self.source {
                return Err(PlanProtocolError::Invalid(
                    "logical lane source differs from plan source",
                ));
            }
        }
        let build = &self.lanes[0].prepare;
        let build_tuple = build.exact_build.as_ref().ok_or(
            PlanProtocolError::Invalid("logical build tuple is absent"),
        )?;
        let build_plan_sha256 = canonical_sha256(build_tuple)?;
        if !build_tuple.pinned_pulls.iter().any(|pull| {
            pull.repository == build.runner.image.repository
                && pull.platform == build.runner.image.platform
                && pull.manifest_digest_sha256
                    == build.runner.image.manifest_digest_sha256
        }) {
            return Err(PlanProtocolError::Invalid(
                "build runner image is not one pinned pull",
            ));
        }
        let mut expected_artifact: Option<&ArtifactCasReference> = None;
        let mut required_no_build_images = BTreeSet::new();
        for lane in &self.lanes[1..] {
            let artifact = lane.prepare.artifacts.as_ref().ok_or(
                PlanProtocolError::Invalid(
                    "no-build lane artifact reference is absent",
                ),
            )?;
            if artifact.manifest_sha256
                != self.expected_artifact_manifest_sha256
                || artifact.build_plan_sha256 != build_plan_sha256
            {
                return Err(PlanProtocolError::Invalid(
                    "no-build artifact reference differs from build",
                ));
            }
            if !artifact.oci_objects.iter().any(|object| {
                object == &lane.prepare.runner.image
            }) {
                return Err(PlanProtocolError::Invalid(
                    "no-build runner image is outside sealed artifact CAS",
                ));
            }
            required_no_build_images.insert(
                lane.prepare.runner.image.manifest_digest_sha256,
            );
            for service in &lane.prepare.services {
                if !artifact.oci_objects.iter().any(|object| {
                    object == &service.sealed_image
                }) {
                    return Err(PlanProtocolError::Invalid(
                        "service image is outside sealed artifact CAS",
                    ));
                }
                required_no_build_images.insert(
                    service.sealed_image.manifest_digest_sha256,
                );
            }
            if lane.prepare.imported_oci_manifest_sha256
                != self.no_build_oci_import_closure_sha256
            {
                return Err(PlanProtocolError::Invalid(
                    "no-build lanes do not share one OCI import closure",
                ));
            }
            if let Some(expected) = expected_artifact {
                if expected != artifact {
                    return Err(PlanProtocolError::Invalid(
                        "no-build lanes do not share one sealed artifact set",
                    ));
                }
            } else {
                expected_artifact = Some(artifact);
            }
        }
        let canonical_imports: Vec<Digest> =
            required_no_build_images.into_iter().collect();
        if self.no_build_oci_import_closure_sha256 != canonical_imports
            || canonical_sha256(&canonical_imports)?
                != self.no_build_oci_import_set_sha256
        {
            return Err(PlanProtocolError::Invalid(
                "no-build OCI import closure is not exact or canonical",
            ));
        }
        if canonical_sha256_without_digest(
            self,
            |value| value.plan_sha256 = [0; 32],
        )? != self.plan_sha256
        {
            return Err(PlanProtocolError::Invalid(
                "logical plan digest is not canonical",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct InheritedLaneProxy {
    pub fd: i32,
    pub peer_uid: u32,
    pub peer_pid: u32,
    pub peer_identity_sha256: Digest,
    pub capability_sha256: Digest,
}

impl InheritedLaneProxy {
    pub fn validate(&self) -> PlanResult<()> {
        if self.fd < 3 || self.peer_uid == 0 || self.peer_pid == 0 {
            return Err(PlanProtocolError::Invalid(
                "lane proxy is not a retained unprivileged delegated-authority FD",
            ));
        }
        require_digest(
            &self.peer_identity_sha256,
            "lane proxy peer identity",
        )?;
        require_digest(
            &self.capability_sha256,
            "lane proxy capability",
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProxyOperation {
    CreateBuildDind,
    PullPinned,
    BuildExact,
    ExportOwnedOci,
    DestroyBuildDind,
    CreateNoBuildDind,
    ImportSealedOci,
    CreateRunner,
    CreateServices,
    RunRepositoryBody,
    StopRunner,
    DestroyServices,
    DestroyNoBuildDind,
    QueryAuthoritativeState,
    ReadinessDockerUpgrade,
    ReadinessService,
    ReadinessChromium,
    ReadinessTeardown,
}

impl ProxyOperation {
    pub fn is_readiness(self) -> bool {
        matches!(
            self,
            Self::ReadinessDockerUpgrade
                | Self::ReadinessService
                | Self::ReadinessChromium
                | Self::ReadinessTeardown
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AuthoritativeLaneState {
    Declared,
    Preparing,
    Prepared,
    BodyRunning,
    BodyTerminal,
    Exporting,
    Sealed,
    Destroying,
    Destroyed,
    OutcomeUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LaneProxyRequest {
    pub protocol: String,
    pub request_id: Digest,
    pub plan_id: Digest,
    pub lane: LogicalLane,
    pub phase: PlanPhase,
    pub sequence: u64,
    pub boot_id_sha256: Digest,
    pub deadline_boottime_ns: u64,
    pub capability_sha256: Digest,
    pub operation: ProxyOperation,
    pub expected_state: AuthoritativeLaneState,
    pub target_sha256: Digest,
    pub payload_sha256: Digest,
    pub payload: Vec<u8>,
    pub request_sha256: Digest,
}

impl LaneProxyRequest {
    pub fn validate(&self) -> PlanResult<()> {
        if self.protocol != PLAN_PROXY_PROTOCOL_VERSION {
            return Err(PlanProtocolError::Invalid(
                "lane proxy request protocol is not v12",
            ));
        }
        for (digest, name) in [
            (&self.request_id, "proxy request ID"),
            (&self.plan_id, "proxy plan ID"),
            (&self.capability_sha256, "proxy capability"),
            (&self.boot_id_sha256, "proxy boot identity"),
            (&self.target_sha256, "proxy target"),
            (&self.payload_sha256, "proxy payload"),
            (&self.request_sha256, "proxy request digest"),
        ] {
            require_digest(digest, name)?;
        }
        if self.sequence == 0
            || self.boot_id_sha256 != current_boot_id_sha256()?
            || self.deadline_boottime_ns == 0
            || self.payload.len() > MAX_FRAME_BYTES
            || sha256_bytes(&self.payload) != self.payload_sha256
        {
            return Err(PlanProtocolError::Invalid(
                "lane proxy request bounds are invalid",
            ));
        }
        if canonical_sha256_without_digest(
            self,
            |value| value.request_sha256 = [0; 32],
        )? != self.request_sha256
        {
            return Err(PlanProtocolError::Invalid(
                "lane proxy request digest is not canonical",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProxyDisposition {
    Applied,
    AlreadyApplied,
    Rejected,
    OutcomeUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LaneProxyResponse {
    pub protocol: String,
    pub request_id: Digest,
    pub request_sha256: Digest,
    pub plan_id: Digest,
    pub lane: LogicalLane,
    pub sequence: u64,
    pub disposition: ProxyDisposition,
    pub authoritative_state: AuthoritativeLaneState,
    pub result_sha256: Digest,
    pub result: Vec<u8>,
    pub terminal_destruction_receipt: Option<Vec<u8>>,
    pub response_sha256: Digest,
}

impl LaneProxyResponse {
    pub fn validate_for(&self, request: &LaneProxyRequest) -> PlanResult<()> {
        if self.protocol != PLAN_PROXY_PROTOCOL_VERSION
            || self.request_id != request.request_id
            || self.request_sha256 != request.request_sha256
            || self.plan_id != request.plan_id
            || self.lane != request.lane
            || self.sequence != request.sequence
            || self.result.len() > MAX_FRAME_BYTES
            || sha256_bytes(&self.result) != self.result_sha256
            || self
                .terminal_destruction_receipt
                .as_ref()
                .is_some_and(|receipt| {
                    receipt.is_empty() || receipt.len() > MAX_FRAME_BYTES
                })
            || ((self.authoritative_state
                == AuthoritativeLaneState::Destroyed)
                != self.terminal_destruction_receipt.is_some())
        {
            return Err(PlanProtocolError::Invalid(
                "lane proxy response lost request binding",
            ));
        }
        require_digest(&self.result_sha256, "proxy result digest")?;
        require_digest(&self.response_sha256, "proxy response digest")?;
        if canonical_sha256_without_digest(
            self,
            |value| value.response_sha256 = [0; 32],
        )? != self.response_sha256
        {
            return Err(PlanProtocolError::Invalid(
                "lane proxy response digest is not canonical",
            ));
        }
        Ok(())
    }
}

pub fn command_identity_sha256(
    executable: &str,
    argv: &[String],
    environment: &[EnvironmentEntry],
    cwd: &str,
    executable_sha256: &Digest,
) -> PlanResult<Digest> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct CommandIdentity<'a> {
        executable: &'a str,
        argv: &'a [String],
        environment: &'a [EnvironmentEntry],
        cwd: &'a str,
        executable_sha256: &'a Digest,
    }
    canonical_sha256(&CommandIdentity {
        executable,
        argv,
        environment,
        cwd,
        executable_sha256,
    })
}

pub fn canonical_bytes<T: Serialize>(value: &T) -> PlanResult<Vec<u8>> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(PlanProtocolError::Invalid(
            "canonical value exceeds frame bound",
        ));
    }
    Ok(bytes)
}

pub fn canonical_sha256<T: Serialize>(value: &T) -> PlanResult<Digest> {
    Ok(sha256_bytes(&canonical_bytes(value)?))
}

pub fn sha256_bytes(bytes: &[u8]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

pub fn current_boot_id_sha256() -> PlanResult<Digest> {
    let bytes = std::fs::read("/proc/sys/kernel/random/boot_id")?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| PlanProtocolError::Invalid("kernel boot identity is not UTF-8"))?
        .trim();
    if text.len() != 36
        || text.as_bytes().iter().enumerate().any(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte != b'-'
            } else {
                !byte.is_ascii_hexdigit()
            }
        })
    {
        return Err(PlanProtocolError::Invalid(
            "kernel boot identity is malformed",
        ));
    }
    Ok(sha256_bytes(text.as_bytes()))
}

pub(crate) fn canonical_sha256_without_digest<T, F>(
    value: &T,
    clear: F,
) -> PlanResult<Digest>
where
    T: Clone + Serialize,
    F: FnOnce(&mut T),
{
    let mut copy = value.clone();
    clear(&mut copy);
    canonical_sha256(&copy)
}

fn validate_environment(
    environment: &[EnvironmentEntry],
    build_argument: bool,
) -> PlanResult<()> {
    if environment.len() > MAX_ENVIRONMENT_ENTRIES {
        return Err(PlanProtocolError::Invalid(
            "environment set is excessive",
        ));
    }
    let mut previous: Option<&str> = None;
    for entry in environment {
        entry.validate(build_argument)?;
        if previous.is_some_and(|name| name >= entry.name.as_str()) {
            return Err(PlanProtocolError::Invalid(
                "environment entries are not strictly sorted",
            ));
        }
        previous = Some(&entry.name);
    }
    Ok(())
}

fn forbidden_environment_name(name: &str) -> bool {
    matches!(
        name,
        "DOCKER_HOST"
            | "DOCKER_CONTEXT"
            | "DOCKER_CONFIG"
            | "BUILDKIT_HOST"
            | "CONTAINER_HOST"
            | "CONTAINERD_ADDRESS"
            | "KUBECONFIG"
            | "SSH_AUTH_SOCK"
            | "SERVERWARE_CONTROLLER_PLAN_CAPABILITY"
            | "SERVERWARE_CONTROLLER_LANE_PROXY_FD"
    ) || name.ends_with("_TOKEN")
        || name.ends_with("_PASSWORD")
        || name.ends_with("_SECRET")
        || name.ends_with("_CREDENTIAL")
}

fn validate_private_service_alias(alias: &str) -> PlanResult<()> {
    let suffix = alias.strip_prefix("svc-").ok_or(
        PlanProtocolError::Invalid(
            "service alias is not controller-opaque",
        ),
    )?;
    if suffix.len() != 32
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        || alias.contains('.')
        || alias.contains(':')
        || alias.parse::<std::net::IpAddr>().is_ok()
    {
        return Err(PlanProtocolError::Invalid(
            "service alias is not one opaque private controller alias",
        ));
    }
    Ok(())
}

fn require_environment_name(name: &str) -> PlanResult<()> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .enumerate()
            .all(|(index, byte)| match byte {
                b'A'..=b'Z' | b'_' => true,
                b'0'..=b'9' => index > 0,
                _ => false,
            })
    {
        return Err(PlanProtocolError::Invalid(
            "environment name is invalid",
        ));
    }
    Ok(())
}

fn require_identifier(
    value: &str,
    minimum: usize,
    maximum: usize,
    field: &'static str,
) -> PlanResult<()> {
    if value.len() < minimum
        || value.len() > maximum
        || value.as_bytes().contains(&0)
        || value.chars().any(char::is_whitespace)
    {
        return Err(PlanProtocolError::InvalidOwned(format!(
            "{field} is invalid",
        )));
    }
    Ok(())
}

fn require_platform(value: &str) -> PlanResult<()> {
    let mut components = value.split('/');
    let os = components.next().unwrap_or_default();
    let architecture = components.next().unwrap_or_default();
    let variant = components.next();
    if components.next().is_some()
        || !matches!(os, "linux")
        || architecture.is_empty()
        || architecture.len() > 64
        || variant.is_some_and(|value| value.is_empty() || value.len() > 32)
    {
        return Err(PlanProtocolError::Invalid(
            "OCI platform is invalid",
        ));
    }
    Ok(())
}

fn require_digest(digest: &Digest, field: &'static str) -> PlanResult<()> {
    if *digest == [0; 32] {
        return Err(PlanProtocolError::InvalidOwned(format!(
            "{field} is empty",
        )));
    }
    Ok(())
}

fn require_relative_path(value: &str, field: &'static str) -> PlanResult<()> {
    let path = Path::new(value);
    if value.is_empty()
        || value.len() > 4096
        || path.is_absolute()
        || path.components().any(|component| {
            !matches!(component, Component::Normal(_))
        })
    {
        return Err(PlanProtocolError::InvalidOwned(format!(
            "{field} is not a canonical relative path",
        )));
    }
    Ok(())
}

fn require_absolute_container_path(
    value: &str,
    field: &'static str,
) -> PlanResult<()> {
    let path = Path::new(value);
    if value.is_empty()
        || value.len() > 4096
        || !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::CurDir
                    | Component::ParentDir
                    | Component::Prefix(_)
            )
        })
    {
        return Err(PlanProtocolError::InvalidOwned(format!(
            "{field} is not a canonical absolute path",
        )));
    }
    Ok(())
}

#[cfg(test)]
mod runner_execution_bounds_tests {
    use super::*;

    const MIB: u64 = 1024 * 1024;
    const FIELDS: [(&str, u64, u64); 13] = [
        ("userUid", 1000, 2_147_483_647),
        ("userGid", 1000, 2_147_483_647),
        ("cpuQuotaMicros", 1000, 6_400_000),
        ("cpuPeriodMicros", 100_000, 100_000),
        ("memoryBytes", 256 * MIB, 64 * 1024 * MIB),
        ("pids", 16, 8192),
        ("openFiles", 64, 65_536),
        ("shmBytes", 16 * MIB, 1024 * MIB),
        ("runTmpfsBytes", MIB, 256 * MIB),
        ("tmpTmpfsBytes", 16 * MIB, 1024 * MIB),
        ("privateDataBytes", 16 * MIB, 8 * 1024 * MIB),
        ("outputBytes", 16 * MIB, 1024 * MIB),
        ("outputInodes", 64, 65_536),
    ];

    fn bounds() -> RunnerExecutionBoundsV12 {
        RunnerExecutionBoundsV12 {
            user_uid: 1000,
            user_gid: 1000,
            cpu_quota_micros: 1000,
            cpu_period_micros: 100_000,
            memory_bytes: 256 * MIB,
            pids: 16,
            open_files: 64,
            shm_bytes: 16 * MIB,
            run_tmpfs_bytes: MIB,
            tmp_tmpfs_bytes: 16 * MIB,
            private_data_bytes: 16 * MIB,
            output_bytes: 16 * MIB,
            output_inodes: 64,
        }
    }

    fn runner() -> RunnerIdentity {
        RunnerIdentity {
            image: OciObjectReference {
                repository: "fixture/runner".into(),
                manifest_digest_sha256: [3; 32],
                index_digest_sha256: None,
                platform: "linux/amd64".into(),
                size: 1,
            },
            runtime_executable_sha256: [1; 32],
            rootfs_sha256: [4; 32],
            static_courier_sha256: Some([2; 32]),
            executable_closure_sha256: vec![[1; 32], [2; 32]],
            mount_policy: RunnerMountPolicy {
                source_destination: "/opt/serverware/src".into(),
                artifact_destination: "/opt/serverware/artifacts".into(),
                output_destination: "/opt/serverware/output".into(),
                source_read_only: true,
                artifacts_read_only: true,
                root_filesystem_read_only: true,
                no_host_bind_mounts: true,
                no_socket_mounts: true,
                private_run_tmpfs: true,
                private_tmp_tmpfs: true,
            },
            execution_bounds: bounds(),
        }
    }

    // Structural/digest fixture only; this does not attest a real CAS or signer.
    fn prepare() -> PrepareContract {
        let sealing = CasSealingEvidenceV12 {
            policy: CasSealingPolicyV12::UserspaceDigestOnly,
            userspace_manifest_sha256: [5; 32],
            fs_verity_file_digests_sha256: None,
            immutable_file_set_sha256: None,
        };
        let runner = runner();
        let mut value = PrepareContract {
            lane: LogicalLane::Unit,
            generation_kind: DindGenerationKind::NoBuild,
            source: SourceCasReference {
                manifest_sha256: [6; 32],
                object_sha256: [7; 32],
                entry_count: 1,
                total_bytes: 1,
                sealing_evidence: sealing.clone(),
            },
            artifacts: Some(ArtifactCasReference {
                manifest_sha256: [8; 32],
                object_sha256: [9; 32],
                source_manifest_sha256: [6; 32],
                build_plan_sha256: [10; 32],
                files_sha256: [11; 32],
                oci_objects: vec![runner.image.clone()],
                sealing_evidence: sealing,
            }),
            imported_oci_manifest_sha256: vec![
                runner.image.manifest_digest_sha256,
            ],
            runner,
            exact_build: None,
            services: vec![],
            prepare_sha256: [0; 32],
        };
        value.prepare_sha256 = canonical_sha256_without_digest(
            &value,
            |copy| copy.prepare_sha256 = [0; 32],
        )
        .unwrap();
        value
    }

    #[test]
    fn runner_bounds_accept_inclusive_minimum_and_maximum_profiles() {
        bounds().validate().unwrap();
        let mut maximum = serde_json::to_value(bounds()).unwrap();
        for (field, _, upper) in FIELDS {
            maximum[field] = serde_json::json!(upper);
        }
        serde_json::from_value::<RunnerExecutionBoundsV12>(maximum)
            .unwrap()
            .validate()
            .unwrap();
    }

    #[test]
    fn runner_bounds_reject_each_outside_boundary_and_extreme_integer() {
        for (field, lower, upper) in FIELDS {
            for invalid in [0, lower - 1, upper + 1, u64::MAX] {
                let mut value = serde_json::to_value(bounds()).unwrap();
                value[field] = serde_json::json!(invalid);
                if let Ok(parsed) =
                    serde_json::from_value::<RunnerExecutionBoundsV12>(value)
                {
                    assert!(parsed.validate().is_err(), "{field}={invalid}");
                }
            }
        }
    }

    #[test]
    fn runner_bounds_charge_all_writable_memory_at_the_exact_limit() {
        let mut value = bounds();
        value.run_tmpfs_bytes = 16 * MIB;
        value.private_data_bytes = 192 * MIB;
        value.validate().unwrap();
        for field in [
            "shmBytes", "runTmpfsBytes", "tmpTmpfsBytes", "privateDataBytes",
            "outputBytes",
        ] {
            let mut exceeded = serde_json::to_value(&value).unwrap();
            let previous = exceeded[field].as_u64().unwrap();
            let increment = if field == "outputBytes" { MIB } else { 1 };
            exceeded[field] = serde_json::json!(previous + increment);
            let exceeded: RunnerExecutionBoundsV12 =
                serde_json::from_value(exceeded).unwrap();
            assert_eq!(
                exceeded.validate().unwrap_err().to_string(),
                "runner writable memory exceeds its memory bound",
            );
        }
    }

    #[test]
    fn runner_bounds_serialization_is_closed_required_and_integer_only() {
        let value = serde_json::to_value(bounds()).unwrap();
        assert_eq!(value.as_object().unwrap().len(), FIELDS.len());
        assert_eq!(
            serde_json::from_value::<RunnerExecutionBoundsV12>(value.clone())
                .unwrap(),
            bounds(),
        );
        for (field, _, _) in FIELDS {
            let mut missing = value.clone();
            assert!(missing.as_object_mut().unwrap().remove(field).is_some());
            assert!(serde_json::from_value::<RunnerExecutionBoundsV12>(
                missing,
            )
            .is_err());
            for invalid in [
                serde_json::Value::Null,
                serde_json::json!(false),
                serde_json::json!("1000"),
                serde_json::json!(1000.0),
                serde_json::json!(-1),
            ] {
                let mut wrong_type = value.clone();
                wrong_type[field] = invalid;
                assert!(serde_json::from_value::<RunnerExecutionBoundsV12>(
                    wrong_type,
                )
                .is_err());
            }
        }
        let mut extra = value;
        extra["unbounded"] = serde_json::json!(false);
        assert!(serde_json::from_value::<RunnerExecutionBoundsV12>(extra)
            .is_err());
    }

    #[test]
    fn runner_identity_requires_and_validates_execution_bounds() {
        let mut runner = runner();
        runner.validate().unwrap();
        let mut missing = serde_json::to_value(&runner).unwrap();
        missing.as_object_mut().unwrap().remove("executionBounds");
        assert!(serde_json::from_value::<RunnerIdentity>(missing).is_err());
        runner.execution_bounds.user_uid = 0;
        assert_eq!(
            runner.validate().unwrap_err().to_string(),
            "runner execution bounds are invalid",
        );
    }

    #[test]
    fn runner_mounts_cannot_cover_or_enter_private_data_scratch() {
        assert_eq!(RUNNER_PRIVATE_DATA_PATH_V12, "/var/lib/serverware-runner");
        for field in [
            "sourceDestination", "artifactDestination", "outputDestination",
        ] {
            for path in [
                "/var", "/var/lib", "/var/lib/serverware-runner",
                "/var/lib/serverware-runner/pgdata",
                "/var//lib/serverware-runner",
                "/var/./lib/serverware-runner",
                "/var/lib/serverware-runner//pgdata",
                "/var/lib/serverware-runner/./pgdata",
                "/var//lib/", "/var/./lib", "/",
            ] {
                let mut value = serde_json::to_value(runner().mount_policy)
                    .unwrap();
                value[field] = serde_json::json!(path);
                assert!(serde_json::from_value::<RunnerMountPolicy>(value)
                    .unwrap()
                    .validate()
                    .is_err());
            }
            let mut sibling = serde_json::to_value(runner().mount_policy)
                .unwrap();
            sibling[field] = serde_json::json!(
                "/var/lib/serverware-runner-sibling"
            );
            serde_json::from_value::<RunnerMountPolicy>(sibling)
                .unwrap()
                .validate()
                .unwrap();
        }
        assert!(paths_overlap("/", RUNNER_PRIVATE_DATA_PATH_V12));
        assert!(paths_overlap(RUNNER_PRIVATE_DATA_PATH_V12, "/"));
        assert!(!paths_overlap(
            "/var/lib/serverware-runner-sibling",
            RUNNER_PRIVATE_DATA_PATH_V12,
        ));
        assert!(!paths_overlap("/opt/source", "/opt/artifacts"));
    }

    #[test]
    fn prepare_digest_binds_every_runner_execution_bound() {
        let prepared = prepare();
        prepared.validate().unwrap();
        for (field, lower, _) in FIELDS {
            let mut changed = serde_json::to_value(&prepared).unwrap();
            let increment = if field == "outputBytes" { MIB } else { 1 };
            changed["runner"]["executionBounds"][field] =
                serde_json::json!(lower + increment);
            let mut changed: PrepareContract =
                serde_json::from_value(changed).unwrap();
            let next_digest = canonical_sha256_without_digest(
                &changed,
                |copy| copy.prepare_sha256 = [0; 32],
            )
            .unwrap();
            assert_ne!(next_digest, prepared.prepare_sha256, "{field}");
            assert!(changed.validate().is_err(), "{field}");
            if field != "cpuPeriodMicros" {
                assert_eq!(
                    changed.validate().unwrap_err().to_string(),
                    "prepare contract digest is not canonical",
                );
                changed.prepare_sha256 = next_digest;
                changed.validate().unwrap();
            }
        }
    }
}
