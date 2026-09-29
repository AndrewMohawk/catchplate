use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use super::{
    RootOwnedResponseObservationV2Config, V2RuntimeError,
};

pub(crate) const TOPOLOGY_API_VERSION: &str =
    "serverware.responseObservationV2CustodyTopology/v1";
pub(crate) const TOPOLOGY_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.response-v2/custody-topology/v1\0";
pub(crate) const TRUSTED_HOST_FAULT_DOMAIN: &str = "host-1";
pub(crate) const TRUSTED_HOST_QUORUM_MODE: &str = "LOCAL_1_OF_1";
pub(crate) const TEE_HARDWARE_GENERATION_VERIFIER_API_VERSION: &str =
    "serverware.responseObservationV2TeeGenerationVerifier/v1";
pub(crate) const TRUSTED_HOST_SHARED_UDS_GID: u32 = 65_519;
pub(crate) const GENERATION_MANIFEST_CREDENTIAL: &str =
    "response-v2-provider-generation.json";
pub(crate) const TOPOLOGY_MANIFEST_CREDENTIAL: &str =
    "response-v2-topology-manifest.json";
pub(crate) const ROLE_MANIFEST_CREDENTIAL: &str =
    "response-v2-role-manifest.json";
pub(crate) const KEY_MANIFEST_CREDENTIAL: &str =
    "response-v2-key-manifest.json";
pub(crate) const GENERATION_TRUST_ANCHOR_CREDENTIAL: &str =
    "response-v2-generation-trust-anchor.pub";
pub(crate) const GENERATION_AUTHORITY_KEY_CREDENTIAL: &str =
    "response-v2-generation-authority.key";
pub(crate) const GENERATION_READINESS_PROOF_FILE: &str =
    "generation-bootstrap-readiness.json";
pub(crate) const GENERATION_ACTIVATION_CONTEXT_FILE: &str =
    "generation-activation-context.json";
pub(crate) const GENERATION_ROLE_READINESS_ARTIFACT_FILE: &str =
    "generation-role-readiness-artifact.json";
pub(crate) const GENERATION_ROUTER_TOPOLOGY_ATTESTATION_FILE: &str =
    "generation-router-topology-attestation.json";
pub(crate) const ROUTER_READINESS_LOGICAL_ROLE: &str =
    "readiness-topology-attestor";

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum CustodyAttestationProfile {
    TrustedHostNoTee,
    TeeHardware,
}

impl CustodyAttestationProfile {
    pub(crate) const fn generation_profile(
        self,
    ) -> super::super::state_authority::topology::GenerationAttestationProfile
    {
        use super::super::state_authority::topology::GenerationAttestationProfile;

        match self {
            Self::TrustedHostNoTee => {
                GenerationAttestationProfile::TrustedHostNoTee
            }
            Self::TeeHardware => {
                GenerationAttestationProfile::TeeHardware
            }
        }
    }

    pub(crate) const fn hardware_proof(self) -> bool {
        matches!(self, Self::TeeHardware)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct MeasuredTeeVerifierInputV1 {
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct NitroPcrSetV1 {
    pub pcr0: String,
    pub pcr1: String,
    pub pcr2: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct TeeHardwareGenerationVerifierV1 {
    pub api_version: String,
    pub executable: PathBuf,
    #[serde(default)]
    pub arguments: Vec<String>,
    pub executable_sha256: String,
    #[serde(default)]
    pub verifier_module: Option<MeasuredTeeVerifierInputV1>,
    pub expectations: MeasuredTeeVerifierInputV1,
    pub trust_roots: MeasuredTeeVerifierInputV1,
    pub expected_enclave_instance_id: String,
    pub expected_eif_sha384: String,
    pub expected_pcrs: NitroPcrSetV1,
    pub maximum_evidence_age_ms: u64,
    pub maximum_future_skew_ms: u64,
}

impl TeeHardwareGenerationVerifierV1 {
    pub(crate) fn validate(&self) -> Result<(), V2RuntimeError> {
        if self.api_version
            != TEE_HARDWARE_GENERATION_VERIFIER_API_VERSION
            || !absolute_normal_path(&self.executable)
            || !is_sha256(&self.executable_sha256)
            || !self.arguments.is_empty()
            || self.expected_enclave_instance_id.is_empty()
            || self.expected_enclave_instance_id.len() > 256
            || self.expected_enclave_instance_id.bytes().any(|byte| {
                byte.is_ascii_control() || byte.is_ascii_whitespace()
            })
            || !is_sha384(&self.expected_eif_sha384)
            || !is_sha384(&self.expected_pcrs.pcr0)
            || !is_sha384(&self.expected_pcrs.pcr1)
            || !is_sha384(&self.expected_pcrs.pcr2)
            || self.expected_pcrs.pcr0 != self.expected_eif_sha384
            || !(1..=300_000).contains(&self.maximum_evidence_age_ms)
            || self.maximum_future_skew_ms > 30_000
        {
            return Err(V2RuntimeError::new(
                "tee_generation_verifier_config_invalid",
                "TEE generation verifier must be one descriptor-pinned executable with no command or interpreter arguments and must pin the exact Nitro instance/EIF/PCR set and freshness policy",
            ));
        }
        for input in [
            self.verifier_module.as_ref(),
            Some(&self.expectations),
            Some(&self.trust_roots),
        ]
        .into_iter()
        .flatten()
        {
            if !absolute_normal_path(&input.path) || !is_sha256(&input.sha256)
            {
                return Err(V2RuntimeError::new(
                    "tee_generation_verifier_input_invalid",
                    "TEE verifier module, expectations, and trust roots require absolute normalized paths and exact SHA-256 pins",
                ));
            }
        }
        Ok(())
    }
}

#[derive(
    Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord,
)]
#[serde(rename_all = "kebab-case")]
pub enum CustodyServiceRole {
    CustodyRouter,
    StateAuthority,
    CredentialTransport,
    PolicyProofVerifier,
    ImmutableArtifactLedger,
    ReleaseAttestorPublisher,
    CleanupWatchdog,
}

impl CustodyServiceRole {
    pub const ALL: [Self; 7] = [
        Self::CustodyRouter,
        Self::StateAuthority,
        Self::CredentialTransport,
        Self::PolicyProofVerifier,
        Self::ImmutableArtifactLedger,
        Self::ReleaseAttestorPublisher,
        Self::CleanupWatchdog,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::CustodyRouter => "custody-router",
            Self::StateAuthority => "state-authority",
            Self::CredentialTransport => "credential-transport",
            Self::PolicyProofVerifier => "policy-proof-verifier",
            Self::ImmutableArtifactLedger => "immutable-artifact-ledger",
            Self::ReleaseAttestorPublisher => "release-attestor-publisher",
            Self::CleanupWatchdog => "cleanup-watchdog",
        }
    }

    pub fn may_have_network_egress(self) -> bool {
        self == Self::CredentialTransport
    }

    pub fn owns_logical_role(self, logical_role: &str) -> bool {
        expected_service_for_logical_role(logical_role) == Some(self)
    }
}

impl FromStr for CustodyServiceRole {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|role| role.as_str() == value)
            .ok_or_else(|| format!("unsupported custody service role: {value}"))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceRoleKeyDescriptorV1 {
    pub logical_role: String,
    pub key_id: String,
    pub public_key_sha256: String,
    pub public_key_path: PathBuf,
    pub secret_key_path: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CustodyProcessBindingV1 {
    pub service_role: CustodyServiceRole,
    pub service_id: String,
    pub uid: u32,
    pub gid: u32,
    pub socket_path: PathBuf,
    pub readiness_socket_path: PathBuf,
    pub readiness_record_path: PathBuf,
    pub state_directory: PathBuf,
    pub backend_socket_path: Option<PathBuf>,
    pub max_frame_bytes: usize,
    pub request_timeout_ms: u64,
    pub executable_sha256: String,
    pub configuration_sha256: String,
    pub network_egress: bool,
    pub role_keys: Vec<ServiceRoleKeyDescriptorV1>,
}

impl CustodyProcessBindingV1 {
    pub(crate) fn process_state_object_root(&self) -> PathBuf {
        self.state_directory.join("objects")
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LogicalRoleBindingV1 {
    pub logical_role: String,
    pub service_role: CustodyServiceRole,
    pub key_id: String,
    pub public_key_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedCustodyTopologyV1 {
    pub api_version: String,
    pub generation_id: String,
    pub generation: u64,
    pub attestation_mode: CustodyAttestationProfile,
    pub fault_domain_id: String,
    pub quorum_mode: String,
    pub fault_domain_count: u32,
    pub external_witness_count: u32,
    pub hardware_proof: bool,
    pub trust_checkpoint_sha256: String,
    pub topology_signer_key_id: String,
    pub topology_signer_public_key_base64: String,
    pub processes: Vec<CustodyProcessBindingV1>,
    pub logical_roles: Vec<LogicalRoleBindingV1>,
    pub signature: String,
}

impl SignedCustodyTopologyV1 {
    fn without_signature(&self) -> Self {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        unsigned
    }

    pub(crate) fn process(
        &self,
        role: CustodyServiceRole,
    ) -> Option<&CustodyProcessBindingV1> {
        self.processes
            .iter()
            .find(|candidate| candidate.service_role == role)
    }

    pub(crate) fn logical_role(
        &self,
        role: &str,
    ) -> Option<&LogicalRoleBindingV1> {
        self.logical_roles
            .iter()
            .find(|candidate| candidate.logical_role == role)
    }
}

#[derive(Debug, Clone)]
pub struct TrustedHostNoTeeTopology {
    pub generation_id: String,
    pub generation: u64,
    pub fault_domain_id: String,
    pub quorum_mode: String,
    pub fault_domain_count: u32,
    pub external_witness_count: u32,
    pub hardware_proof: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct ScopedCustodyServiceConfig {
    pub role: CustodyServiceRole,
    pub generation_id: String,
    pub generation: u64,
    pub trust_checkpoint_sha256: String,
    pub process: CustodyProcessBindingV1,
    pub logical_roles: Vec<LogicalRoleBindingV1>,
}

#[derive(Debug, Clone)]
pub(crate) struct GenerationBootstrapCredentialPaths {
    pub generation_manifest: PathBuf,
    pub topology_manifest: PathBuf,
    pub role_manifest: PathBuf,
    pub key_manifest: PathBuf,
    pub trust_anchor_public_key: PathBuf,
    pub generation_authority_secret_key: PathBuf,
    pub readiness_proof: PathBuf,
}

#[derive(Debug, Clone)]
pub(crate) struct GenerationPublicCredentialPaths {
    pub generation_manifest: PathBuf,
    pub trust_anchor_public_key: PathBuf,
    pub readiness_proof: PathBuf,
}

impl GenerationBootstrapCredentialPaths {
    pub(crate) fn for_config(
        config: &super::RootOwnedResponseObservationV2Config,
        scoped: &ScopedCustodyServiceConfig,
    ) -> Result<Self, V2RuntimeError> {
        if let Some(owner) = &config.guest_delivery {
            return owner.bootstrap_paths();
        }
        super::guest_delivery::require_host(config)?;
        Self::from_systemd_credentials(scoped)
    }
    pub(crate) fn from_systemd_credentials(
        scoped: &ScopedCustodyServiceConfig,
    ) -> Result<Self, V2RuntimeError> {
        if scoped.role != CustodyServiceRole::StateAuthority {
            return Err(V2RuntimeError::new(
                "generation_bootstrap_role_invalid",
                "only state-authority may load generation bootstrap credentials",
            ));
        }
        let directory = std::env::var_os("CREDENTIALS_DIRECTORY")
            .map(PathBuf::from)
            .ok_or_else(|| {
                V2RuntimeError::new(
                    "generation_bootstrap_credentials_missing",
                    "CREDENTIALS_DIRECTORY is required for generation bootstrap",
                )
            })?;
        validate_generation_credential_directory(&directory)?;
        let credential = |name: &str| directory.join(name);
        Ok(Self {
            generation_manifest: credential(
                GENERATION_MANIFEST_CREDENTIAL,
            ),
            topology_manifest: credential(
                TOPOLOGY_MANIFEST_CREDENTIAL,
            ),
            role_manifest: credential(ROLE_MANIFEST_CREDENTIAL),
            key_manifest: credential(KEY_MANIFEST_CREDENTIAL),
            trust_anchor_public_key: credential(
                GENERATION_TRUST_ANCHOR_CREDENTIAL,
            ),
            generation_authority_secret_key: credential(
                GENERATION_AUTHORITY_KEY_CREDENTIAL,
            ),
            readiness_proof: scoped
                .process
                .state_directory
                .join(GENERATION_READINESS_PROOF_FILE),
        })
    }
}

impl GenerationPublicCredentialPaths {
    pub(crate) fn for_config(
        config: &super::RootOwnedResponseObservationV2Config,
        scoped: &ScopedCustodyServiceConfig,
    ) -> Result<Self, V2RuntimeError> {
        if let Some(owner) = &config.guest_delivery {
            return owner.public_paths();
        }
        super::guest_delivery::require_host(config)?;
        Self::from_readiness_credentials(scoped)
    }
    pub(crate) fn from_readiness_credentials(
        scoped: &ScopedCustodyServiceConfig,
    ) -> Result<Self, V2RuntimeError> {
        if scoped.role != CustodyServiceRole::StateAuthority {
            return Err(V2RuntimeError::new(
                "generation_readiness_role_invalid",
                "only state-authority may verify generation bootstrap readiness",
            ));
        }
        let directory = std::env::var_os(
            "SERVERWARE_RESPONSE_V2_GENERATION_PUBLIC_CREDENTIALS_DIRECTORY",
        )
        .map(PathBuf::from)
        .ok_or_else(|| {
            V2RuntimeError::new(
                "generation_readiness_credentials_missing",
                "SERVERWARE_RESPONSE_V2_GENERATION_PUBLIC_CREDENTIALS_DIRECTORY is required for state-authority readiness",
            )
        })?;
        validate_generation_credential_directory(&directory)?;
        Ok(Self {
            generation_manifest:
                directory.join(GENERATION_MANIFEST_CREDENTIAL),
            trust_anchor_public_key:
                directory.join(GENERATION_TRUST_ANCHOR_CREDENTIAL),
            readiness_proof: scoped
                .process
                .state_directory
                .join(GENERATION_READINESS_PROOF_FILE),
        })
    }
}

fn validate_generation_credential_directory(
    directory: &Path,
) -> Result<(), V2RuntimeError> {
    if !absolute_normal_path(directory) {
        return Err(V2RuntimeError::new(
            "generation_credential_directory_invalid",
            "generation credential directory must be an absolute normalized path",
        ));
    }
    Ok(())
}

impl RootOwnedResponseObservationV2Config {
    pub(crate) fn custody_topology(
        &self,
    ) -> &SignedCustodyTopologyV1 {
        &self.custody_topology
    }

    pub(crate) fn trusted_host_topology(
        &self,
    ) -> TrustedHostNoTeeTopology {
        TrustedHostNoTeeTopology {
            generation_id: self.custody_topology.generation_id.clone(),
            generation: self.custody_topology.generation,
            fault_domain_id:
                self.custody_topology.fault_domain_id.clone(),
            quorum_mode: self.custody_topology.quorum_mode.clone(),
            fault_domain_count:
                self.custody_topology.fault_domain_count,
            external_witness_count:
                self.custody_topology.external_witness_count,
            hardware_proof: self.custody_topology.hardware_proof,
        }
    }

    pub(crate) fn scoped_service_config(
        &self,
        role: CustodyServiceRole,
    ) -> Result<ScopedCustodyServiceConfig, V2RuntimeError> {
        let process = self
            .custody_topology
            .process(role)
            .cloned()
            .ok_or_else(|| {
                V2RuntimeError::new(
                    "custody_service_unconfigured",
                    format!(
                        "signed topology does not configure {}",
                        role.as_str()
                    ),
                )
            })?;
        let logical_roles = self
            .custody_topology
            .logical_roles
            .iter()
            .filter(|binding| binding.service_role == role)
            .cloned()
            .collect::<Vec<_>>();
        if logical_roles.is_empty()
            || process.role_keys.len() != logical_roles.len()
        {
            return Err(V2RuntimeError::new(
                "custody_service_key_scope_invalid",
                "service role does not have exactly its assigned logical-role subkeys",
            ));
        }
        if role == CustodyServiceRole::CustodyRouter
            && (logical_roles.len() != 1
                || logical_roles[0].logical_role
                    != ROUTER_READINESS_LOGICAL_ROLE
                || process.role_keys.len() != 1
                || process.role_keys[0].logical_role
                    != ROUTER_READINESS_LOGICAL_ROLE)
        {
            return Err(V2RuntimeError::new(
                "custody_router_key_scope_invalid",
                "custody-router requires exactly one readiness/topology-attestation key",
            ));
        }
        Ok(ScopedCustodyServiceConfig {
            role,
            generation_id:
                self.custody_topology.generation_id.clone(),
            generation: self.custody_topology.generation,
            trust_checkpoint_sha256:
                self.custody_topology.trust_checkpoint_sha256.clone(),
            process,
            logical_roles,
        })
    }

    pub(crate) fn generation_activation_context_path(
        &self,
    ) -> Result<PathBuf, V2RuntimeError> {
        let authority =
            self.scoped_service_config(CustodyServiceRole::StateAuthority)?;
        authority
            .process
            .readiness_socket_path
            .parent()
            .map(|parent| parent.join(GENERATION_ACTIVATION_CONTEXT_FILE))
            .ok_or_else(|| {
                V2RuntimeError::new(
                    "generation_activation_context_path_invalid",
                    "state-authority readiness socket has no parent directory",
                )
            })
    }

    pub(crate) fn generation_role_readiness_artifact_path(
        &self,
        role: CustodyServiceRole,
    ) -> Result<PathBuf, V2RuntimeError> {
        Ok(self
            .scoped_service_config(role)?
            .process
            .state_directory
            .join(GENERATION_ROLE_READINESS_ARTIFACT_FILE))
    }

    pub(crate) fn generation_router_topology_attestation_path(
        &self,
    ) -> Result<PathBuf, V2RuntimeError> {
        Ok(self
            .scoped_service_config(CustodyServiceRole::CustodyRouter)?
            .process
            .state_directory
            .join(GENERATION_ROUTER_TOPOLOGY_ATTESTATION_FILE))
    }
}

pub(crate) fn validate_signed_topology(
    config: &RootOwnedResponseObservationV2Config,
) -> Result<(), V2RuntimeError> {
    let topology = &config.custody_topology;
    if topology.api_version != TOPOLOGY_API_VERSION
        || topology.generation == 0
        || topology.generation > 9_007_199_254_740_991
        || topology.generation_id.is_empty()
        || topology.generation_id.len() > 256
        || topology.hardware_proof
            != topology.attestation_mode.hardware_proof()
        || topology.fault_domain_id != TRUSTED_HOST_FAULT_DOMAIN
        || topology.quorum_mode != TRUSTED_HOST_QUORUM_MODE
        || topology.fault_domain_count != 1
        || topology.external_witness_count != 0
        || !is_sha256(&topology.trust_checkpoint_sha256)
        || !is_sha256(&topology.topology_signer_key_id)
    {
        return Err(V2RuntimeError::new(
            "custody_topology_claim_invalid",
            "custody topology must honestly declare either trusted-host-no-tee without hardware proof or tee-hardware with hardware proof, while retaining host-1, LOCAL_1_OF_1, one fault domain, zero external witnesses, and zero fault tolerance",
        ));
    }
    match (
        topology.attestation_mode,
        config.tee_hardware_generation_verifier.as_ref(),
    ) {
        (CustodyAttestationProfile::TrustedHostNoTee, None) => {}
        (CustodyAttestationProfile::TeeHardware, Some(verifier)) => {
            verifier.validate()?;
        }
        (CustodyAttestationProfile::TrustedHostNoTee, Some(_)) => {
            return Err(V2RuntimeError::new(
                "tee_generation_verifier_profile_mismatch",
                "trusted-host-no-tee must not configure a hardware generation verifier",
            ));
        }
        (CustodyAttestationProfile::TeeHardware, None) => {
            return Err(V2RuntimeError::new(
                "tee_generation_verifier_missing",
                "tee-hardware requires a descriptor-pinned independent generation verifier",
            ));
        }
    }
    verify_topology_signature(topology)?;
    validate_processes(topology)?;
    validate_logical_roles(config, topology)?;
    Ok(())
}

fn validate_processes(
    topology: &SignedCustodyTopologyV1,
) -> Result<(), V2RuntimeError> {
    if topology.processes.len() != CustodyServiceRole::ALL.len() {
        return Err(V2RuntimeError::new(
            "custody_process_set_invalid",
            "signed topology must contain exactly seven custody processes",
        ));
    }
    let mut roles = BTreeSet::new();
    let mut service_ids = BTreeSet::new();
    let mut uids = BTreeSet::new();
    let mut shared_gid = None;
    let mut sockets = BTreeSet::new();
    let mut readiness_sockets = BTreeSet::new();
    let mut readiness = BTreeSet::new();
    let mut state_directories = BTreeSet::new();
    let mut secret_paths = BTreeSet::new();
    for process in &topology.processes {
        let expected_shared_gid =
            *shared_gid.get_or_insert(process.gid);
        if !roles.insert(process.service_role)
            || !service_ids.insert(process.service_id.as_str())
            || process.service_id.is_empty()
            || process.service_id.len() > 256
            || process.uid == 0
            || process.gid == 0
            || !uids.insert(process.uid)
            || process.gid != TRUSTED_HOST_SHARED_UDS_GID
            || process.gid != expected_shared_gid
            || process.uid == process.gid
            || topology
                .processes
                .iter()
                .any(|other| other.uid == process.gid)
            || !absolute_normal_path(&process.socket_path)
            || !absolute_normal_path(&process.readiness_socket_path)
            || !absolute_normal_path(&process.readiness_record_path)
            || !absolute_normal_path(&process.state_directory)
            || process
                .backend_socket_path
                .as_ref()
                .is_some_and(|path| !absolute_normal_path(path))
            || process.max_frame_bytes == 0
            || process.max_frame_bytes > 256 * 1024
            || process.request_timeout_ms == 0
            || process.request_timeout_ms > 30_000
            || !sockets.insert(process.socket_path.as_path())
            || !readiness_sockets
                .insert(process.readiness_socket_path.as_path())
            || !readiness.insert(process.readiness_record_path.as_path())
            || !state_directories.insert(process.state_directory.as_path())
            || !is_sha256(&process.executable_sha256)
            || !is_sha256(&process.configuration_sha256)
            || process.network_egress
                != process.service_role.may_have_network_egress()
        {
            return Err(V2RuntimeError::new(
                "custody_process_binding_invalid",
                "custody processes require seven unique nonzero UIDs, signed shared UDS GID 65519, no UID/GID collision, distinct paths, exact digests, and role-bounded network scope",
            ));
        }
        // Retained for signed v1 topology compatibility only. Authority
        // engines execute in their service process and never connect to this
        // legacy path.
        if process.service_role == CustodyServiceRole::CustodyRouter
            && process.readiness_socket_path == process.socket_path
        {
            return Err(V2RuntimeError::new(
                "custody_router_readiness_socket_invalid",
                "custody-router requires a distinct non-mutating readiness UDS",
            ));
        }
        if process.service_role != CustodyServiceRole::CustodyRouter
            && process.readiness_socket_path != process.socket_path
        {
            return Err(V2RuntimeError::new(
                "custody_service_readiness_socket_invalid",
                "non-router services use their authenticated RPC UDS for readiness",
            ));
        }
        if process.service_role == CustodyServiceRole::CustodyRouter
            && (process.role_keys.len() != 1
                || process.role_keys[0].logical_role
                    != ROUTER_READINESS_LOGICAL_ROLE)
        {
            return Err(V2RuntimeError::new(
                "custody_router_key_scope_invalid",
                "custody-router must receive exactly its readiness/topology-attestation key",
            ));
        }
        let mut process_roles = BTreeSet::new();
        for key in &process.role_keys {
            if !process.service_role.owns_logical_role(&key.logical_role)
                || !process_roles.insert(key.logical_role.as_str())
                || !is_sha256(&key.key_id)
                || key.key_id != key.public_key_sha256
                || !is_sha256(&key.public_key_sha256)
                || !absolute_normal_path(&key.public_key_path)
                || !absolute_normal_path(&key.secret_key_path)
                || key.public_key_path == key.secret_key_path
                || !secret_paths.insert(key.secret_key_path.as_path())
            {
                return Err(V2RuntimeError::new(
                    "custody_process_key_scope_invalid",
                    "service subkey is duplicated, misassigned, unbound, or shares secret storage",
                ));
            }
        }
    }
    let expected =
        CustodyServiceRole::ALL.into_iter().collect::<BTreeSet<_>>();
    if roles != expected {
        return Err(V2RuntimeError::new(
            "custody_process_set_invalid",
            "signed topology omits one or more required custody processes",
        ));
    }
    Ok(())
}

fn validate_logical_roles(
    config: &RootOwnedResponseObservationV2Config,
    topology: &SignedCustodyTopologyV1,
) -> Result<(), V2RuntimeError> {
    let mut expected = super::REQUIRED_ROLE_IDENTITIES
        .into_iter()
        .collect::<BTreeSet<_>>();
    expected.insert(ROUTER_READINESS_LOGICAL_ROLE);
    let mut observed = BTreeSet::new();
    let mut key_ids = BTreeSet::new();
    let mut by_role = BTreeMap::new();
    for binding in &topology.logical_roles {
        if !expected.contains(binding.logical_role.as_str())
            || !observed.insert(binding.logical_role.as_str())
            || expected_service_for_logical_role(&binding.logical_role)
                != Some(binding.service_role)
            || !is_sha256(&binding.key_id)
            || binding.key_id != binding.public_key_sha256
            || !key_ids.insert(binding.key_id.as_str())
        {
            return Err(V2RuntimeError::new(
                "custody_logical_role_binding_invalid",
                "logical role is missing, duplicated, mapped to the wrong service, or reuses a subkey",
            ));
        }
        by_role.insert(binding.logical_role.as_str(), binding);
    }
    if observed != expected {
        return Err(V2RuntimeError::new(
            "custody_logical_role_set_invalid",
            "signed topology must map every closed logical role exactly once",
        ));
    }
    for identity in &config.role_identities {
        let binding = by_role
            .get(identity.role.as_str())
            .ok_or_else(|| {
                V2RuntimeError::new(
                    "custody_role_identity_unmapped",
                    "root-owned role identity is absent from the signed topology",
                )
            })?;
        let process = topology
            .process(binding.service_role)
            .ok_or_else(|| {
                V2RuntimeError::new(
                    "custody_role_process_unmapped",
                    "logical role references an absent service process",
                )
            })?;
        let process_key = process.role_keys.iter().find(|candidate| {
            candidate.logical_role == identity.role
        });
        if identity.provider_generation != topology.generation
            || identity.key_id != binding.key_id
            || identity.key_material_sha256
                != binding.public_key_sha256
            || identity.provider_id != process.service_id
            || process_key.is_none_or(|key| {
                key.key_id != identity.key_id
                    || key.public_key_sha256
                        != identity.key_material_sha256
                    || key.public_key_path
                        != identity.key_material_path
            })
        {
            return Err(V2RuntimeError::new(
                "custody_role_identity_binding_mismatch",
                "role identity does not match the signed service, generation, and subkey binding",
            ));
        }
    }
    Ok(())
}

fn verify_topology_signature(
    topology: &SignedCustodyTopologyV1,
) -> Result<(), V2RuntimeError> {
    let public_key = base64::engine::general_purpose::STANDARD
        .decode(&topology.topology_signer_public_key_base64)
        .map_err(|_| {
            V2RuntimeError::new(
                "custody_topology_signer_invalid",
                "topology signer public key is not canonical base64",
            )
        })?;
    if public_key.len() != 32
        || format!("sha256:{:x}", Sha256::digest(&public_key))
            != topology.topology_signer_key_id
    {
        return Err(V2RuntimeError::new(
            "custody_topology_signer_invalid",
            "topology signer key does not match its pinned digest",
        ));
    }
    let signature = base64::engine::general_purpose::STANDARD
        .decode(&topology.signature)
        .map_err(|_| {
            V2RuntimeError::new(
                "custody_topology_signature_invalid",
                "topology signature is not canonical base64",
            )
        })?;
    let canonical = crate::canonical_json_bytes(
        &topology.without_signature(),
    )
    .map_err(|_| {
        V2RuntimeError::new(
            "custody_topology_invalid",
            "topology cannot be canonicalized",
        )
    })?;
    let mut message = Vec::with_capacity(
        TOPOLOGY_SIGNATURE_DOMAIN.len() + canonical.len(),
    );
    message.extend_from_slice(TOPOLOGY_SIGNATURE_DOMAIN);
    message.extend_from_slice(&canonical);
    ring::signature::UnparsedPublicKey::new(
        &ring::signature::ED25519,
        public_key,
    )
    .verify(&message, &signature)
    .map_err(|_| {
        V2RuntimeError::new(
            "custody_topology_signature_invalid",
            "topology signature is invalid",
        )
    })
}

pub(crate) fn expected_service_for_logical_role(
    logical_role: &str,
) -> Option<CustodyServiceRole> {
    Some(match logical_role {
        ROUTER_READINESS_LOGICAL_ROLE => {
            CustodyServiceRole::CustodyRouter
        }
        "trusted-time"
        | "recovery"
        | "linearizable-store"
        | "quorum"
        | "public-release-consumption"
        | "emergency-fence-revoker" => {
            CustodyServiceRole::StateAuthority
        }
        "credential-authority"
        | "target-transport"
        | "mutation-supervisor" => {
            CustodyServiceRole::CredentialTransport
        }
        "evidence-trust"
        | "live-proof-verifier"
        | "archive-proof-verifier" => {
            CustodyServiceRole::PolicyProofVerifier
        }
        "persistence" | "archive-store" => {
            CustodyServiceRole::ImmutableArtifactLedger
        }
        "runtime-attestation"
        | "transparency"
        | "attester"
        | "publisher"
        | "public-release"
        | "custody" => {
            CustodyServiceRole::ReleaseAttestorPublisher
        }
        "outcome-reconciliation"
        | "emergency-cleanup-executor" => {
            CustodyServiceRole::CleanupWatchdog
        }
        _ => return None,
    })
}

fn absolute_normal_path(path: &Path) -> bool {
    path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir
                    | std::path::Component::Normal(_)
            )
        })
}

fn is_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_sha384(value: &str) -> bool {
    value.len() == 103
        && value.starts_with("sha384:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
}
