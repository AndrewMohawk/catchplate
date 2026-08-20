#![cfg(target_os = "linux")]

use crate::plan_protocol::{
    canonical_bytes, sha256_bytes, ArtifactCasReference, Digest,
    DigestValidation,
    OciObjectReference, PlanProtocolError, PlanResult,
    RuntimeTrustProfile, SourceCasReference,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};

pub const TRUSTED_HOST_CLAIM: &str =
    "userspace-digest/no-IMA-appraisal";
pub const IMA_APPRAISED_CLAIM: &str =
    "externally-verified-IMA-EVM-appraisal";
const EVIDENCE_VERSION: &str =
    "serverware/controller-runtime-evidence/v12";
const IMA_ACTIVATION_VERSION: &str =
    "serverware/controller-ima-activation/v12";
const FS_IOC_GETFLAGS: libc::c_ulong = 0x80086601;
const FS_IMMUTABLE_FL: libc::c_uint = 0x00000010;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const DT_NULL: i64 = 0;
const DT_NEEDED: i64 = 1;
type EvidenceError = PlanProtocolError;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ExecutableRole {
    StaticCourier,
    ControllerOwnedRunner,
    ContainerRuntime,
    Browser,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StaticExecutableEvidenceV12 {
    pub role: ExecutableRole,
    pub content_sha256: Digest,
    pub size: u64,
    pub machine: u16,
    pub filesystem_immutable: bool,
    pub root_owned: bool,
    pub no_interpreter: bool,
    pub no_needed_libraries: bool,
    pub no_writable_executable_segment: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum MappingProvenance {
    StaticExecutable,
    OciRootFilesystem,
    RuntimeProvided,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExecutableMappingEvidenceV12 {
    pub start: u64,
    pub end: u64,
    pub writable: bool,
    pub executable: bool,
    pub anonymous: bool,
    pub path: Option<String>,
    pub content_sha256: Digest,
    pub provenance: MappingProvenance,
}

impl ExecutableMappingEvidenceV12 {
    fn validate(&self) -> PlanResult<()> {
        if self.start >= self.end || !self.executable || self.writable {
            return Err(PlanProtocolError::Invalid(
                "runtime executable mapping bounds or permissions are invalid",
            ));
        }
        if self.anonymous
            || self.path.as_ref().is_none_or(|path| {
                path.is_empty()
                    || !path.starts_with('/')
                    || path.contains(" (deleted)")
            })
            || self.content_sha256 == [0; 32]
        {
            return Err(PlanProtocolError::Invalid(
                "runtime executable mapping lacks file-backed identity",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RuntimeNamespaceIdentityV12 {
    pub user_namespace_inode: u64,
    pub mount_namespace_inode: u64,
    pub pid_namespace_inode: u64,
    pub network_namespace_inode: u64,
    pub cgroup_v2_path_sha256: Digest,
}

impl RuntimeNamespaceIdentityV12 {
    fn validate(&self) -> Result<(), EvidenceError> {
        if self.user_namespace_inode == 0
            || self.mount_namespace_inode == 0
            || self.pid_namespace_inode == 0
            || self.network_namespace_inode == 0
        {
            return Err(EvidenceError::Invariant(
                "runtime namespace inode identities must be non-zero".into(),
            ));
        }
        self.cgroup_v2_path_sha256.validate("cgroup v2 path digest")
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeMappingObservationV12 {
    pub host_start: u64,
    pub host_end_exclusive: u64,
    pub runner_start: u64,
    pub runner_end_exclusive: u64,
    pub permissions: String,
    pub backing_identity_sha256: Digest,
}

impl RuntimeMappingObservationV12 {
    fn validate(&self) -> Result<(), EvidenceError> {
        if self.host_start >= self.host_end_exclusive
            || self.runner_start >= self.runner_end_exclusive
            || self.host_end_exclusive - self.host_start
                != self.runner_end_exclusive - self.runner_start
        {
            return Err(EvidenceError::Invariant(
                "runtime mapping interval is empty or changes length".into(),
            ));
        }
        if self.permissions.len() != 4
            || !self
                .permissions
                .bytes()
                .all(|byte| matches!(byte, b'r' | b'w' | b'x' | b'p' | b's' | b'-'))
        {
            return Err(EvidenceError::Invariant(
                "runtime mapping permissions are not canonical".into(),
            ));
        }
        self.backing_identity_sha256
            .validate("runtime mapping backing identity")
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeObserverEvidenceV12 {
    pub version: String,
    pub observer_executable_sha256: Digest,
    pub target_pid: u32,
    pub target_start_ticks: u64,
    pub pidfd_inode: u64,
    pub launch_sequence: u64,
    pub terminal_sequence: u64,
    pub launch_event_sha256: Digest,
    pub terminal_event_sha256: Digest,
    pub mappings: Vec<RuntimeMappingObservationV12>,
    pub mapping_log_root_sha256: Digest,
    pub canonical_evidence_sha256: Digest,
    pub observer_key_id: String,
    pub observer_signature_b64: String,
}

impl AuthoritativeObserverEvidenceV12 {
    pub const VERSION: &'static str = "serverware/runtime-observer-evidence/v12";

    fn validate_structure(&self) -> Result<(), EvidenceError> {
        if self.version != Self::VERSION
            || self.target_pid == 0
            || self.target_start_ticks == 0
            || self.pidfd_inode == 0
            || self.launch_sequence >= self.terminal_sequence
            || self.observer_key_id.is_empty()
            || self.observer_signature_b64.is_empty()
        {
            return Err(EvidenceError::Invariant(
                "runtime observer evidence header is invalid".into(),
            ));
        }
        self.observer_executable_sha256
            .validate("observer executable digest")?;
        self.launch_event_sha256.validate("observer launch event")?;
        self.terminal_event_sha256
            .validate("observer terminal event")?;
        self.mapping_log_root_sha256
            .validate("observer mapping log root")?;

        let mut previous_host_end = None;
        let mut previous_runner_end = None;
        for mapping in &self.mappings {
            mapping.validate()?;
            if previous_host_end.is_some_and(|end| mapping.host_start < end)
                || previous_runner_end.is_some_and(|end| mapping.runner_start < end)
            {
                return Err(EvidenceError::Invariant(
                    "runtime mappings are not sorted or overlap".into(),
                ));
            }
            previous_host_end = Some(mapping.host_end_exclusive);
            previous_runner_end = Some(mapping.runner_end_exclusive);
        }

        let mapping_root = canonical_digest(&self.mappings)?;
        if mapping_root != self.mapping_log_root_sha256 {
            return Err(EvidenceError::Invariant(
                "runtime mapping log root mismatch".into(),
            ));
        }
        let mut unsigned = self.clone();
        unsigned.canonical_evidence_sha256 = [0; 32];
        unsigned.observer_signature_b64.clear();
        if canonical_digest(&unsigned)? != self.canonical_evidence_sha256 {
            return Err(EvidenceError::Invariant(
                "runtime observer canonical digest mismatch".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedRuntimeObserverPolicyV12 {
    pub version: String,
    pub expected_observer_executable_sha256: Digest,
    pub authorized_observer_keys_b64: std::collections::BTreeMap<String, String>,
    pub revoked_observer_keys: std::collections::BTreeSet<String>,
}

impl PinnedRuntimeObserverPolicyV12 {
    pub const VERSION: &'static str = "serverware/runtime-observer-policy/v12";

    pub fn into_runtime(self) -> Result<RuntimeObserverPolicy, EvidenceError> {
        use base64::Engine as _;

        if self.version != Self::VERSION || self.authorized_observer_keys_b64.is_empty() {
            return Err(EvidenceError::Invariant(
                "pinned runtime observer policy header is invalid".into(),
            ));
        }
        self.expected_observer_executable_sha256
            .validate("pinned runtime observer executable")?;
        let mut authorized_observer_keys = std::collections::BTreeMap::new();
        for (key_id, encoded) in self.authorized_observer_keys_b64 {
            if key_id.is_empty() || self.revoked_observer_keys.contains(&key_id) {
                return Err(EvidenceError::Invariant(
                    "runtime observer policy authorizes an empty or revoked key".into(),
                ));
            }
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded.as_bytes())
                .map_err(|_| {
                    EvidenceError::Invariant(
                        "runtime observer public key is not valid base64".into(),
                    )
                })?;
            let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
                EvidenceError::Invariant(
                    "runtime observer public key is not 32 bytes".into(),
                )
            })?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| {
                EvidenceError::Invariant(
                    "runtime observer public key is not valid Ed25519".into(),
                )
            })?;
            authorized_observer_keys.insert(key_id, key);
        }
        Ok(RuntimeObserverPolicy {
            expected_observer_executable_sha256: self.expected_observer_executable_sha256,
            authorized_observer_keys,
            revoked_observer_keys: self.revoked_observer_keys,
        })
    }
}

#[derive(Clone, Debug)]
pub struct RuntimeObserverPolicy {
    pub expected_observer_executable_sha256: Digest,
    pub authorized_observer_keys:
        std::collections::BTreeMap<String, ed25519_dalek::VerifyingKey>,
    pub revoked_observer_keys: std::collections::BTreeSet<String>,
}

impl RuntimeObserverPolicy {
    pub fn verify(
        &self,
        evidence: &AuthoritativeObserverEvidenceV12,
    ) -> Result<(), EvidenceError> {
        evidence.validate_structure()?;
        if evidence.observer_executable_sha256 != self.expected_observer_executable_sha256 {
            return Err(EvidenceError::Invariant(
                "runtime observer executable is not the pinned observer".into(),
            ));
        }
        if self.revoked_observer_keys.contains(&evidence.observer_key_id) {
            return Err(EvidenceError::Invariant(
                "runtime observer signing key is revoked".into(),
            ));
        }
        let key = self
            .authorized_observer_keys
            .get(&evidence.observer_key_id)
            .ok_or_else(|| {
                EvidenceError::Invariant("runtime observer signing key is not authorized".into())
            })?;
        verify_observer_signature(
            key,
            b"serverware/runtime-observer-evidence/v12\0",
            &evidence.canonical_evidence_sha256,
            &evidence.observer_signature_b64,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerRuntimeEvidenceV12 {
    pub runner: OciObjectReference,
    pub runtime_executable_sha256: Digest,
    pub rootfs_sha256: Digest,
    pub source: SourceCasReference,
    pub artifacts: Option<ArtifactCasReference>,
    pub proxy_peer_identity_sha256: Digest,
    pub pid_namespace_inode: u64,
    pub mount_namespace_inode: u64,
    pub network_namespace_inode: u64,
    pub cgroup_identity_sha256: Digest,
    pub executable_mappings: Vec<ExecutableMappingEvidenceV12>,
    pub runner_identity_sha256: Digest,
    pub inherited_proxy_executable_sha256: Digest,
    pub command_sha256: Digest,
    pub namespaces: RuntimeNamespaceIdentityV12,
    pub observer: AuthoritativeObserverEvidenceV12,
    pub runtime_report_sha256: Digest,
}

fn verify_observer_signature(
    key: &ed25519_dalek::VerifyingKey,
    domain: &[u8],
    digest: &Digest,
    encoded_signature: &str,
) -> Result<(), EvidenceError> {
    use base64::Engine as _;

    let digest_value = serde_json::to_value(digest).map_err(|error| {
        EvidenceError::Invariant(format!("serialize runtime observer digest: {error}"))
    })?;
    let digest_text = digest_value.as_str().ok_or_else(|| {
        EvidenceError::Invariant("runtime observer digest is not encoded as a string".into())
    })?;
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded_signature.as_bytes())
        .map_err(|_| {
            EvidenceError::Invariant("runtime observer signature is not valid base64".into())
        })?;
    let signature = ed25519_dalek::Signature::from_slice(&signature_bytes).map_err(|_| {
        EvidenceError::Invariant("runtime observer signature is not valid Ed25519".into())
    })?;
    let mut message = Vec::with_capacity(domain.len() + digest_text.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(digest_text.as_bytes());
    key.verify_strict(&message, &signature).map_err(|_| {
        EvidenceError::Invariant("runtime observer signature verification failed".into())
    })
}

impl RunnerRuntimeEvidenceV12 {
    pub fn validate(
        &self,
        expected_source: &SourceCasReference,
        expected_artifacts: Option<&ArtifactCasReference>,
        expected_runner: &OciObjectReference,
        allowed_executable_digests: &BTreeSet<Digest>,
    ) -> PlanResult<()> {
        self.runner.validate()?;
        self.source.validate()?;
        if let Some(artifacts) = &self.artifacts {
            artifacts.validate()?;
        }
        if &self.source != expected_source
            || self.artifacts.as_ref() != expected_artifacts
            || &self.runner != expected_runner
            || self.runtime_executable_sha256 == [0; 32]
            || self.rootfs_sha256 == [0; 32]
            || self.proxy_peer_identity_sha256 == [0; 32]
            || self.cgroup_identity_sha256 == [0; 32]
            || self.pid_namespace_inode == 0
            || self.mount_namespace_inode == 0
            || self.network_namespace_inode == 0
            || self.executable_mappings.is_empty()
            || self.observer.target_pid == 0
            || self.runner_identity_sha256.validate("runner identity").is_err()
            || self
                .inherited_proxy_executable_sha256
                .validate("inherited proxy executable")
                .is_err()
            || self.command_sha256.validate("runner command").is_err()
            || self.namespaces.validate().is_err()
            || self.observer.validate_structure().is_err()
            || self.pid_namespace_inode != self.namespaces.pid_namespace_inode
            || self.mount_namespace_inode
                != self.namespaces.mount_namespace_inode
            || self.network_namespace_inode
                != self.namespaces.network_namespace_inode
        {
            return Err(PlanProtocolError::Invalid(
                "runner runtime evidence lost execution binding",
            ));
        }
        for mapping in &self.executable_mappings {
            mapping.validate()?;
            if !allowed_executable_digests
                .contains(&mapping.content_sha256)
            {
                return Err(PlanProtocolError::Invalid(
                    "runner executable mapping is outside declared closure",
                ));
            }
        }
        let mut copy = self.clone();
        copy.runtime_report_sha256 = [0; 32];
        if self.runtime_report_sha256 == [0; 32]
            || sha256_bytes(&canonical_bytes(&copy)?)
                != self.runtime_report_sha256
        {
            return Err(PlanProtocolError::Invalid(
                "runner runtime report digest is not canonical",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExternalImaActivationEvidenceV12 {
    pub version: String,
    pub host_identity_sha256: Digest,
    pub boot_measurement_sha256: Digest,
    pub kernel_identity_sha256: Digest,
    pub appraisal_policy_sha256: Digest,
    pub protected_keyring_sha256: Digest,
    pub ima_log_sha256: Digest,
    pub tpm_quote_sha256: Digest,
    pub rollback_highwater: u64,
    pub verified_at_boottime_ns: u64,
    pub expires_at_boottime_ns: u64,
    pub verifier_key_id: String,
    pub evidence_sha256: Digest,
    pub signature: Vec<u8>,
}

impl ExternalImaActivationEvidenceV12 {
    fn validate(
        &self,
        policy: &ImaActivationPolicy,
        now_boottime_ns: u64,
    ) -> PlanResult<()> {
        if self.version != IMA_ACTIVATION_VERSION
            || self.verifier_key_id != policy.verifier_key_id
            || self.host_identity_sha256 != policy.host_identity_sha256
            || self.appraisal_policy_sha256
                != policy.appraisal_policy_sha256
            || self.rollback_highwater < policy.minimum_rollback_highwater
            || self.verified_at_boottime_ns == 0
            || self.expires_at_boottime_ns
                <= self.verified_at_boottime_ns
            || now_boottime_ns < self.verified_at_boottime_ns
            || now_boottime_ns >= self.expires_at_boottime_ns
            || self.signature.len() != 64
        {
            return Err(PlanProtocolError::Invalid(
                "IMA activation evidence policy binding is invalid",
            ));
        }
        for digest in [
            &self.host_identity_sha256,
            &self.boot_measurement_sha256,
            &self.kernel_identity_sha256,
            &self.appraisal_policy_sha256,
            &self.protected_keyring_sha256,
            &self.ima_log_sha256,
            &self.tpm_quote_sha256,
            &self.evidence_sha256,
        ] {
            if *digest == [0; 32] {
                return Err(PlanProtocolError::Invalid(
                    "IMA activation evidence contains an empty digest",
                ));
            }
        }
        let mut copy = self.clone();
        copy.evidence_sha256 = [0; 32];
        copy.signature.clear();
        if sha256_bytes(&canonical_bytes(&copy)?)
            != self.evidence_sha256
        {
            return Err(PlanProtocolError::Invalid(
                "IMA activation evidence digest is not canonical",
            ));
        }
        let signature_bytes: [u8; 64] =
            self.signature.as_slice().try_into().map_err(|_| {
                PlanProtocolError::Invalid(
                    "IMA activation signature length is invalid",
                )
            })?;
        let signature = Signature::from_bytes(&signature_bytes);
        let mut signed =
            Vec::with_capacity(64);
        signed.extend_from_slice(
            b"serverware/controller-ima-activation-signature/v12\0",
        );
        signed.extend_from_slice(&self.evidence_sha256);
        policy
            .verifier_key
            .verify(&signed, &signature)
            .map_err(|_| {
                PlanProtocolError::Invalid(
                    "IMA activation evidence signature is invalid",
                )
            })
    }
}

#[derive(Clone)]
pub struct ImaActivationPolicy {
    pub verifier_key_id: String,
    pub verifier_key: VerifyingKey,
    pub host_identity_sha256: Digest,
    pub appraisal_policy_sha256: Digest,
    pub minimum_rollback_highwater: u64,
}

#[derive(Clone, Debug)]
pub enum ActiveRuntimeTrust {
    TrustedHostNoTee,
    ImaEvmAppraised(ExternalImaActivationEvidenceV12),
}

impl ActiveRuntimeTrust {
    pub fn trusted_host() -> Self {
        Self::TrustedHostNoTee
    }

    pub fn activate_ima(
        policy: &ImaActivationPolicy,
        evidence: ExternalImaActivationEvidenceV12,
    ) -> PlanResult<Self> {
        evidence.validate(policy, boottime_ns()?)?;
        Ok(Self::ImaEvmAppraised(evidence))
    }

    pub fn profile(&self) -> RuntimeTrustProfile {
        match self {
            Self::TrustedHostNoTee => RuntimeTrustProfile::TrustedHostNoTee,
            Self::ImaEvmAppraised(_) => RuntimeTrustProfile::ImaEvmAppraised,
        }
    }

    pub fn claim(&self) -> &'static str {
        match self {
            Self::TrustedHostNoTee => TRUSTED_HOST_CLAIM,
            Self::ImaEvmAppraised(_) => IMA_APPRAISED_CLAIM,
        }
    }

    pub fn hardware_proof(&self) -> bool {
        false
    }

    pub fn ima_appraisal(&self) -> bool {
        matches!(self, Self::ImaEvmAppraised(_))
    }

    fn activation_sha256(&self) -> Option<Digest> {
        match self {
            Self::TrustedHostNoTee => None,
            Self::ImaEvmAppraised(evidence) => {
                Some(evidence.evidence_sha256)
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RuntimeEvidenceEnvelopeV12 {
    pub version: String,
    pub trust_profile: RuntimeTrustProfile,
    pub trust_claim: String,
    pub hardware_proof: bool,
    pub ima_appraisal: bool,
    pub ima_activation_sha256: Option<Digest>,
    pub courier: StaticExecutableEvidenceV12,
    pub runner: RunnerRuntimeEvidenceV12,
    pub evidence_sha256: Digest,
}

impl RuntimeEvidenceEnvelopeV12 {
    pub fn create(
        trust: &ActiveRuntimeTrust,
        courier: StaticExecutableEvidenceV12,
        runner: RunnerRuntimeEvidenceV12,
    ) -> PlanResult<Self> {
        let mut envelope = Self {
            version: EVIDENCE_VERSION.to_string(),
            trust_profile: trust.profile(),
            trust_claim: trust.claim().to_string(),
            hardware_proof: trust.hardware_proof(),
            ima_appraisal: trust.ima_appraisal(),
            ima_activation_sha256: trust.activation_sha256(),
            courier,
            runner,
            evidence_sha256: [0; 32],
        };
        envelope.evidence_sha256 =
            sha256_bytes(&canonical_bytes(&envelope)?);
        Ok(envelope)
    }

    pub fn validate_claim(&self) -> PlanResult<()> {
        if self.version != EVIDENCE_VERSION
            || self.hardware_proof
            || self.evidence_sha256 == [0; 32]
        {
            return Err(PlanProtocolError::Invalid(
                "runtime evidence envelope overclaims hardware proof",
            ));
        }
        match self.trust_profile {
            RuntimeTrustProfile::TrustedHostNoTee => {
                if self.trust_claim != TRUSTED_HOST_CLAIM
                    || self.ima_appraisal
                    || self.ima_activation_sha256.is_some()
                {
                    return Err(PlanProtocolError::Invalid(
                        "TrustedHostNoTee evidence overclaims IMA appraisal",
                    ));
                }
            }
            RuntimeTrustProfile::ImaEvmAppraised => {
                if self.trust_claim != IMA_APPRAISED_CLAIM
                    || !self.ima_appraisal
                    || self
                        .ima_activation_sha256
                        .is_none_or(|digest| digest == [0; 32])
                {
                    return Err(PlanProtocolError::Invalid(
                        "IMA evidence lacks external activation binding",
                    ));
                }
            }
        }
        let mut copy = self.clone();
        copy.evidence_sha256 = [0; 32];
        if sha256_bytes(&canonical_bytes(&copy)?)
            != self.evidence_sha256
        {
            return Err(PlanProtocolError::Invalid(
                "runtime evidence envelope digest is not canonical",
            ));
        }
        Ok(())
    }
}

pub fn verify_static_executable_fd(
    fd: RawFd,
    role: ExecutableRole,
) -> PlanResult<StaticExecutableEvidenceV12> {
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut file = unsafe { File::from_raw_fd(duplicate) };
    let identity = executable_identity(file.as_raw_fd())?;
    let elf = parse_static_elf(&mut file, identity.size)?;
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut read_total = 0u64;
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        read_total = read_total.checked_add(count as u64).ok_or(
            PlanProtocolError::Invalid(
                "static executable byte count overflow",
            ),
        )?;
        hasher.update(&buffer[..count]);
    }
    if read_total != identity.size {
        return Err(PlanProtocolError::Invalid(
            "static executable changed while measured",
        ));
    }
    let after = executable_identity(file.as_raw_fd())?;
    if identity != after {
        return Err(PlanProtocolError::Invalid(
            "static executable identity changed while measured",
        ));
    }
    Ok(StaticExecutableEvidenceV12 {
        role,
        content_sha256: hasher.finalize().into(),
        size: identity.size,
        machine: elf.machine,
        filesystem_immutable: identity.filesystem_immutable,
        root_owned: identity.owner == 0,
        no_interpreter: true,
        no_needed_libraries: true,
        no_writable_executable_segment: true,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecutableIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    owner: u32,
    size: u64,
    modified_sec: i64,
    modified_nsec: i64,
    changed_sec: i64,
    changed_nsec: i64,
    filesystem_immutable: bool,
}

fn executable_identity(fd: RawFd) -> PlanResult<ExecutableIdentity> {
    let mut stat: libc::stat = unsafe { mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0
        || stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_size <= 0
        || stat.st_nlink != 1
        || stat.st_uid != 0
        || stat.st_mode & 0o022 != 0
    {
        return Err(PlanProtocolError::Invalid(
            "executable is not one immutable root-owned regular file",
        ));
    }
    let mut flags: libc::c_uint = 0;
    let immutable = unsafe {
        libc::ioctl(fd, FS_IOC_GETFLAGS, &mut flags)
    } == 0
        && flags & FS_IMMUTABLE_FL != 0;
    if !immutable {
        return Err(PlanProtocolError::Invalid(
            "static executable lacks filesystem immutable enforcement",
        ));
    }
    Ok(ExecutableIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
        mode: stat.st_mode,
        owner: stat.st_uid,
        size: stat.st_size as u64,
        modified_sec: stat.st_mtime,
        modified_nsec: stat.st_mtime_nsec,
        changed_sec: stat.st_ctime,
        changed_nsec: stat.st_ctime_nsec,
        filesystem_immutable: immutable,
    })
}

struct ParsedElf {
    machine: u16,
}

impl RunnerRuntimeEvidenceV12 {
    pub fn validate_authoritative_join(
        &self,
        expected_runner_identity_sha256: &Digest,
        expected_inherited_proxy_executable_sha256: &Digest,
        expected_command_sha256: &Digest,
        expected_namespaces: &RuntimeNamespaceIdentityV12,
        observer_policy: &RuntimeObserverPolicy,
    ) -> Result<(), EvidenceError> {
        self.namespaces.validate()?;
        self.observer.validate_structure()?;
        if &self.runner_identity_sha256 != expected_runner_identity_sha256
            || &self.inherited_proxy_executable_sha256
                != expected_inherited_proxy_executable_sha256
            || &self.command_sha256 != expected_command_sha256
            || canonical_digest(&self.namespaces)?
                != canonical_digest(expected_namespaces)?
        {
            return Err(EvidenceError::Invariant(
                "runtime evidence does not join the exact runner launch contract".into(),
            ));
        }
        observer_policy.verify(&self.observer)
    }
}

pub fn validate_executable_file_v12(path: &Path) -> Result<(), EvidenceError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = std::fs::metadata(path)?;
    if !metadata.file_type().is_file() || metadata.mode() & 0o111 == 0 {
        return Err(EvidenceError::Invariant(
            "trusted executable must be a regular file with an execute bit".into(),
        ));
    }
    let bytes = std::fs::read(path)?;
    if bytes.len() < 64
        || &bytes[..4] != b"\x7fELF"
        || bytes[4] != 2
        || bytes[5] != 1
    {
        return Err(EvidenceError::Invariant(
            "trusted executable is not little-endian ELF64".into(),
        ));
    }
    let elf_type = u16::from_le_bytes([bytes[16], bytes[17]]);
    if !matches!(elf_type, 2 | 3) {
        return Err(EvidenceError::Invariant(
            "ELF object is neither ET_EXEC nor ET_DYN".into(),
        ));
    }
    let entrypoint = u64::from_le_bytes(bytes[24..32].try_into().map_err(|_| {
        EvidenceError::Invariant("trusted executable has a truncated entrypoint".into())
    })?);
    let program_header_offset =
        u64::from_le_bytes(bytes[32..40].try_into().map_err(|_| {
            EvidenceError::Invariant("trusted executable has a truncated PHDR offset".into())
        })?) as usize;
    let program_header_size = u16::from_le_bytes([bytes[54], bytes[55]]) as usize;
    let program_header_count = u16::from_le_bytes([bytes[56], bytes[57]]) as usize;
    if entrypoint == 0 || program_header_size < 56 || program_header_count == 0 {
        return Err(EvidenceError::Invariant(
            "trusted executable has an invalid entrypoint or PHDR table".into(),
        ));
    }
    let table_size = program_header_size
        .checked_mul(program_header_count)
        .and_then(|size| program_header_offset.checked_add(size))
        .ok_or_else(|| EvidenceError::Invariant("ELF PHDR table overflow".into()))?;
    if table_size > bytes.len() {
        return Err(EvidenceError::Invariant(
            "trusted executable has a truncated PHDR table".into(),
        ));
    }
    let mut entry_in_executable_segment = false;
    for index in 0..program_header_count {
        let offset = program_header_offset + index * program_header_size;
        let header = &bytes[offset..offset + program_header_size];
        let segment_type = u32::from_le_bytes(header[0..4].try_into().map_err(|_| {
            EvidenceError::Invariant("truncated ELF segment type".into())
        })?);
        let flags = u32::from_le_bytes(header[4..8].try_into().map_err(|_| {
            EvidenceError::Invariant("truncated ELF segment flags".into())
        })?);
        let virtual_address =
            u64::from_le_bytes(header[16..24].try_into().map_err(|_| {
                EvidenceError::Invariant("truncated ELF segment address".into())
            })?);
        let memory_size = u64::from_le_bytes(header[40..48].try_into().map_err(|_| {
            EvidenceError::Invariant("truncated ELF segment size".into())
        })?);
        if segment_type == 1
            && flags & 0x1 != 0
            && entrypoint >= virtual_address
            && entrypoint < virtual_address.saturating_add(memory_size)
        {
            entry_in_executable_segment = true;
        }
    }
    if !entry_in_executable_segment {
        return Err(EvidenceError::Invariant(
            "ELF entrypoint is not inside an executable PT_LOAD segment".into(),
        ));
    }
    parse_static_elf(&bytes).map(|_| ())
}

fn parse_static_elf(
    file: &mut File,
    file_size: u64,
) -> PlanResult<ParsedElf> {
    let mut header = [0u8; 64];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut header)?;
    if header[0..4] != *b"\x7fELF"
        || header[4] != 2
        || header[5] != 1
        || header[6] != 1
    {
        return Err(PlanProtocolError::Invalid(
            "courier/runner must be a 64-bit little-endian ELF",
        ));
    }
    let machine = u16::from_le_bytes([header[18], header[19]]);
    #[cfg(target_arch = "x86_64")]
    if machine != 62 {
        return Err(PlanProtocolError::Invalid(
            "static ELF machine is not x86_64",
        ));
    }
    #[cfg(target_arch = "aarch64")]
    if machine != 183 {
        return Err(PlanProtocolError::Invalid(
            "static ELF machine is not aarch64",
        ));
    }
    let table_offset = read_u64(&header[32..40])?;
    let entry_size = read_u16(&header[54..56])? as u64;
    let entry_count = read_u16(&header[56..58])? as u64;
    if entry_size < 56 || entry_count == 0 || entry_count > 1024 {
        return Err(PlanProtocolError::Invalid(
            "static ELF program table is invalid",
        ));
    }
    let table_end = table_offset
        .checked_add(entry_size.checked_mul(entry_count).ok_or(
            PlanProtocolError::Invalid(
                "static ELF table size overflow",
            ),
        )?)
        .ok_or(PlanProtocolError::Invalid(
            "static ELF table end overflow",
        ))?;
    if table_end > file_size {
        return Err(PlanProtocolError::Invalid(
            "static ELF program table exceeds file",
        ));
    }
    let mut has_executable_load = false;
    let mut dynamic_segments = Vec::new();
    for index in 0..entry_count {
        let offset = table_offset + index * entry_size;
        let mut entry = [0u8; 56];
        pread_exact(file.as_raw_fd(), &mut entry, offset)?;
        let kind = read_u32(&entry[0..4])?;
        let flags = read_u32(&entry[4..8])?;
        let file_offset = read_u64(&entry[8..16])?;
        let file_bytes = read_u64(&entry[32..40])?;
        if file_offset
            .checked_add(file_bytes)
            .is_none_or(|end| end > file_size)
        {
            return Err(PlanProtocolError::Invalid(
                "static ELF segment exceeds file",
            ));
        }
        if kind == PT_INTERP {
            return Err(PlanProtocolError::Invalid(
                "static courier/runner may not contain PT_INTERP",
            ));
        }
        if kind == PT_LOAD {
            if flags & PF_X != 0 {
                has_executable_load = true;
            }
            if flags & PF_X != 0 && flags & PF_W != 0 {
                return Err(PlanProtocolError::Invalid(
                    "static ELF contains a writable executable segment",
                ));
            }
        }
        if kind == PT_DYNAMIC {
            dynamic_segments.push((file_offset, file_bytes));
        }
    }
    if !has_executable_load {
        return Err(PlanProtocolError::Invalid(
            "static ELF lacks an executable load segment",
        ));
    }
    for (offset, bytes) in dynamic_segments {
        if bytes % 16 != 0 || bytes > 16 * 1024 * 1024 {
            return Err(PlanProtocolError::Invalid(
                "static ELF dynamic segment is invalid",
            ));
        }
        let mut saw_null = false;
        for index in 0..(bytes / 16) {
            let mut entry = [0u8; 16];
            pread_exact(
                file.as_raw_fd(),
                &mut entry,
                offset + index * 16,
            )?;
            let tag = i64::from_le_bytes(
                entry[0..8].try_into().map_err(|_| {
                    PlanProtocolError::Invalid(
                        "static ELF dynamic tag is invalid",
                    )
                })?,
            );
            if tag == DT_NEEDED {
                return Err(PlanProtocolError::Invalid(
                    "static courier/runner declares DT_NEEDED",
                ));
            }
            if tag == DT_NULL {
                saw_null = true;
                break;
            }
        }
        if !saw_null {
            return Err(PlanProtocolError::Invalid(
                "static ELF dynamic segment lacks DT_NULL",
            ));
        }
    }
    Ok(ParsedElf { machine })
}

fn pread_exact(fd: RawFd, bytes: &mut [u8], offset: u64) -> PlanResult<()> {
    let mut read = 0usize;
    while read < bytes.len() {
        let position: libc::off_t = offset
            .checked_add(read as u64)
            .ok_or(PlanProtocolError::Invalid(
                "ELF read offset overflow",
            ))?
            .try_into()
            .map_err(|_| {
                PlanProtocolError::Invalid(
                    "ELF read offset exceeds off_t",
                )
            })?;
        let count = unsafe {
            libc::pread(
                fd,
                bytes[read..].as_mut_ptr() as *mut libc::c_void,
                bytes.len() - read,
                position,
            )
        };
        if count <= 0 {
            return Err(if count < 0 {
                std::io::Error::last_os_error().into()
            } else {
                PlanProtocolError::Invalid(
                    "ELF read ended before expected length",
                )
            });
        }
        read += count as usize;
    }
    Ok(())
}

fn read_u16(bytes: &[u8]) -> PlanResult<u16> {
    Ok(u16::from_le_bytes(bytes.try_into().map_err(|_| {
        PlanProtocolError::Invalid("ELF u16 field is invalid")
    })?))
}

fn read_u32(bytes: &[u8]) -> PlanResult<u32> {
    Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| {
        PlanProtocolError::Invalid("ELF u32 field is invalid")
    })?))
}

fn read_u64(bytes: &[u8]) -> PlanResult<u64> {
    Ok(u64::from_le_bytes(bytes.try_into().map_err(|_| {
        PlanProtocolError::Invalid("ELF u64 field is invalid")
    })?))
}

fn boottime_ns() -> PlanResult<u64> {
    let mut time: libc::timespec = unsafe { mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0
        || time.tv_sec < 0
        || time.tv_nsec < 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    (time.tv_sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(time.tv_nsec as u64))
        .ok_or(PlanProtocolError::Invalid(
            "CLOCK_BOOTTIME value overflow",
        ))
}
