#![cfg(target_os = "linux")]

use crate::plan_protocol::{
    canonical_bytes, sha256_bytes, Digest, DigestValidation, OciObjectReference,
    PlanProtocolError, PlanResult, RuntimeTrustProfile, MAX_FRAME_BYTES,
};
use crate::docker_contract::{
    DOCKER_INTERNAL_STORAGE_ABSENCE_PROOF_V12,
    DOCKER_TOP_LEVEL_OBJECT_COUNT_SCOPE_V12,
};
use crate::runtime_evidence::TRUSTED_HOST_CLAIM;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::mem;

const READINESS_FIXTURE_VERSION: &str =
    "catchplate/controller-readiness-fixture/v12";
const READINESS_PROTOCOL_VERSION: &str =
    "catchplate/controller-readiness/v12";
const MAX_FIXTURE_BYTES: usize = 8 * 1024 * 1024;
const MAX_PROBE_RESULT_BYTES: usize = 8 * 1024 * 1024;
type ReadinessError = PlanProtocolError;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ReadinessFixtureOrigin {
    ControllerOwned,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DockerUpgradeFixtureV12 {
    pub api_version: String,
    pub request_target: String,
    pub request_headers_sha256: Digest,
    pub client_stream_sha256: Digest,
    pub server_stream_sha256: Digest,
    pub require_status_101: bool,
    pub require_full_duplex: bool,
    pub require_client_half_close: bool,
    pub require_server_after_half_close: bool,
}

impl DockerUpgradeFixtureV12 {
    fn validate(&self) -> PlanResult<()> {
        if self.api_version.is_empty()
            || self.api_version.len() > 32
            || self.request_target.is_empty()
            || self.request_target.len() > 1024
            || !self.request_target.starts_with('/')
            || self.request_target.contains("..")
            || self.request_headers_sha256 == [0; 32]
            || self.client_stream_sha256 == [0; 32]
            || self.server_stream_sha256 == [0; 32]
            || !self.require_status_101
            || !self.require_full_duplex
            || !self.require_client_half_close
            || !self.require_server_after_half_close
        {
            return Err(PlanProtocolError::Invalid(
                "Docker upgrade readiness fixture is incomplete",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceHealthFixtureV12 {
    pub fixture_image: OciObjectReference,
    pub service_identity_sha256: Digest,
    pub protocol: String,
    pub port: u16,
    pub health_path: String,
    pub expected_status: u16,
    pub expected_headers_sha256: Digest,
    pub expected_body_sha256: Digest,
}

impl ServiceHealthFixtureV12 {
    fn validate(&self) -> PlanResult<()> {
        self.fixture_image.validate()?;
        if self.service_identity_sha256 == [0; 32]
            || !matches!(self.protocol.as_str(), "http" | "https")
            || self.port == 0
            || self.health_path.is_empty()
            || !self.health_path.starts_with('/')
            || self.health_path.contains("..")
            || !(100..=599).contains(&self.expected_status)
            || self.expected_headers_sha256 == [0; 32]
            || self.expected_body_sha256 == [0; 32]
        {
            return Err(PlanProtocolError::Invalid(
                "service readiness fixture is incomplete",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ChromiumFixtureV12 {
    pub browser_image: OciObjectReference,
    pub browser_executable_sha256: Digest,
    pub browser_version: String,
    pub cdp_protocol_version: String,
    pub document_sha256: Digest,
    pub expected_dom_sha256: Digest,
    pub javascript_source_sha256: Digest,
    pub expected_javascript_result_sha256: Digest,
    pub fetch_request_sha256: Digest,
    pub expected_fetch_response_sha256: Digest,
    pub require_headless: bool,
    pub require_private_network: bool,
}

impl ChromiumFixtureV12 {
    fn validate(&self) -> PlanResult<()> {
        self.browser_image.validate()?;
        if self.browser_executable_sha256 == [0; 32]
            || self.browser_version.is_empty()
            || self.browser_version.len() > 128
            || self.cdp_protocol_version.is_empty()
            || self.cdp_protocol_version.len() > 64
            || !self.require_headless
            || !self.require_private_network
        {
            return Err(PlanProtocolError::Invalid(
                "Chromium readiness fixture identity is incomplete",
            ));
        }
        for digest in [
            &self.document_sha256,
            &self.expected_dom_sha256,
            &self.javascript_source_sha256,
            &self.expected_javascript_result_sha256,
            &self.fetch_request_sha256,
            &self.expected_fetch_response_sha256,
        ] {
            if *digest == [0; 32] {
                return Err(PlanProtocolError::Invalid(
                    "Chromium readiness fixture contains an empty digest",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TeardownFixtureV12 {
    pub owner_namespace_sha256: Digest,
    pub docker_top_level_object_count_scope: String,
    pub docker_internal_storage_absence_proof: String,
    pub require_zero_containers: bool,
    pub require_zero_images: bool,
    pub require_zero_networks: bool,
    pub require_zero_volumes: bool,
    pub require_zero_mounts: bool,
    pub require_zero_cgroup_processes: bool,
    pub require_state_root_absent: bool,
}

impl TeardownFixtureV12 {
    fn validate(&self) -> PlanResult<()> {
        if self.owner_namespace_sha256 == [0; 32]
            || self.docker_top_level_object_count_scope
                != DOCKER_TOP_LEVEL_OBJECT_COUNT_SCOPE_V12
            || self.docker_internal_storage_absence_proof
                != DOCKER_INTERNAL_STORAGE_ABSENCE_PROOF_V12
            || !self.require_zero_containers
            || !self.require_zero_images
            || !self.require_zero_networks
            || !self.require_zero_volumes
            || !self.require_zero_mounts
            || !self.require_zero_cgroup_processes
            || !self.require_state_root_absent
        {
            return Err(PlanProtocolError::Invalid(
                "readiness teardown fixture is incomplete",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SignedReadinessFixtureV12 {
    pub version: String,
    pub controller_generation: u64,
    pub fixture_assets_sha256: Digest,
    pub origin: ReadinessFixtureOrigin,
    pub fixture_id: Digest,
    pub controller_generation_sha256: Digest,
    pub runner_generation_sha256: Digest,
    pub created_at_boottime_ns: u64,
    pub expires_at_boottime_ns: u64,
    pub docker_upgrade: DockerUpgradeFixtureV12,
    pub service: ServiceHealthFixtureV12,
    pub chromium: ChromiumFixtureV12,
    pub teardown: TeardownFixtureV12,
    pub fixture_sha256: Digest,
    pub signer_key_id: String,
    pub signature: Vec<u8>,
}

impl SignedReadinessFixtureV12 {
    pub fn validate_canonical_binding(
        &self,
        now_boottime_ns: u64,
    ) -> PlanResult<()> {
        if self.version != READINESS_FIXTURE_VERSION
            || self.controller_generation == 0
            || self
                .fixture_assets_sha256
                .validate("readiness fixture assets")
                .is_err()
            || self.origin != ReadinessFixtureOrigin::ControllerOwned
            || self.fixture_id == [0; 32]
            || self.controller_generation_sha256 == [0; 32]
            || self.runner_generation_sha256 == [0; 32]
            || self.created_at_boottime_ns == 0
            || self.expires_at_boottime_ns
                <= self.created_at_boottime_ns
            || now_boottime_ns < self.created_at_boottime_ns
            || now_boottime_ns >= self.expires_at_boottime_ns
            || self.signer_key_id.is_empty()
            || self.signature.len() != 64
        {
            return Err(PlanProtocolError::Invalid(
                "readiness fixture envelope is invalid or expired",
            ));
        }
        self.docker_upgrade.validate()?;
        self.service.validate()?;
        self.chromium.validate()?;
        self.teardown.validate()?;
        let mut copy = self.clone();
        copy.fixture_sha256 = [0; 32];
        copy.signature.clear();
        let canonical = canonical_bytes(&copy)?;
        if canonical.len() > MAX_FIXTURE_BYTES
            || self.fixture_sha256 == [0; 32]
            || sha256_bytes(&canonical) != self.fixture_sha256
        {
            return Err(PlanProtocolError::Invalid(
                "readiness fixture digest is not canonical",
            ));
        }
        Ok(())
    }

    pub fn validate(
        &self,
        trust: &ReadinessFixtureTrust,
        now_boottime_ns: u64,
    ) -> PlanResult<()> {
        self.validate_canonical_binding(now_boottime_ns)?;
        if self.signer_key_id != trust.key_id {
            return Err(PlanProtocolError::Invalid(
                "readiness fixture signing key is not pinned",
            ));
        }
        let signature_bytes: [u8; 64] =
            self.signature.as_slice().try_into().map_err(|_| {
                PlanProtocolError::Invalid(
                    "readiness fixture signature length is invalid",
                )
            })?;
        let signature = Signature::from_bytes(&signature_bytes);
        let mut signed = Vec::with_capacity(96);
        signed.extend_from_slice(
            b"catchplate/controller-readiness-fixture-signature/v12\0",
        );
        signed.extend_from_slice(&self.fixture_sha256);
        trust
            .key
            .verify(&signed, &signature)
            .map_err(|_| {
                PlanProtocolError::Invalid(
                    "readiness fixture signature is invalid",
                )
            })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedReadinessTrustV12 {
    pub version: String,
    pub controller_generation: u64,
    pub fixture_assets_sha256: String,
    pub fixture_key_id: String,
    pub fixture_public_key_b64: String,
}

impl PinnedReadinessTrustV12 {
    pub const VERSION: &'static str = "catchplate/readiness-trust/v12";

    pub fn verify_binding(
        &self,
        fixture: &SignedReadinessFixtureV12,
    ) -> Result<(), ReadinessError> {
        if fixture.controller_generation != self.controller_generation
            || fixture.fixture_assets_sha256
                != self.fixture_assets_digest()?
            || fixture.signer_key_id != self.fixture_key_id
        {
            return Err(ReadinessError::Invariant(
                "readiness fixture generation, assets, or signing key are not pinned".into(),
            ));
        }
        Ok(())
    }

    pub fn into_runtime(self) -> Result<ReadinessFixtureTrust, ReadinessError> {
        use base64::Engine as _;

        if self.version != Self::VERSION
            || self.controller_generation == 0
            || self.fixture_key_id.is_empty()
        {
            return Err(ReadinessError::Invariant(
                "pinned readiness trust header is invalid".into(),
            ));
        }
        self.fixture_assets_digest()?;
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(self.fixture_public_key_b64.as_bytes())
            .map_err(|_| {
                ReadinessError::Invariant("pinned readiness key is not valid base64".into())
            })?;
        let key_bytes: [u8; 32] = key_bytes.try_into().map_err(|_| {
            ReadinessError::Invariant("pinned readiness key is not 32 bytes".into())
        })?;
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes).map_err(|_| {
            ReadinessError::Invariant("pinned readiness key is not valid Ed25519".into())
        })?;
        Ok(ReadinessFixtureTrust {
            key_id: self.fixture_key_id,
            key: verifying_key,
        })
    }

    pub fn fixture_assets_digest(&self) -> Result<Digest, ReadinessError> {
        if self.fixture_assets_sha256.len() != 64
            || !self.fixture_assets_sha256.bytes().all(|byte| {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            })
        {
            return Err(ReadinessError::Invariant(
                "pinned readiness fixture assets must be exact lowercase sha256".into(),
            ));
        }
        hex::decode(&self.fixture_assets_sha256)
            .map_err(|_| {
                ReadinessError::Invariant(
                    "pinned readiness fixture assets are not hexadecimal".into(),
                )
            })?
            .try_into()
            .map_err(|_| {
                ReadinessError::Invariant(
                    "pinned readiness fixture assets are not 32 bytes".into(),
                )
            })
    }
}

#[derive(Clone)]
pub struct ReadinessFixtureTrust {
    pub key_id: String,
    pub key: VerifyingKey,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ReadinessProbe {
    DockerUpgrade,
    ServiceHealth,
    Chromium,
    Teardown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReadinessRequestV12 {
    pub protocol: String,
    pub request_id: Digest,
    pub fixture_id: Digest,
    pub fixture_sha256: Digest,
    pub signed_fixture: SignedReadinessFixtureV12,
    pub sequence: u64,
    pub probe: ReadinessProbe,
    pub deadline_boottime_ns: u64,
    pub request_sha256: Digest,
}

impl ReadinessRequestV12 {
    fn new(
        fixture: &SignedReadinessFixtureV12,
        sequence: u64,
        probe: ReadinessProbe,
        deadline_boottime_ns: u64,
    ) -> PlanResult<Self> {
        let mut request = Self {
            protocol: READINESS_PROTOCOL_VERSION.to_string(),
            request_id: random_digest()?,
            fixture_id: fixture.fixture_id,
            fixture_sha256: fixture.fixture_sha256,
            signed_fixture: fixture.clone(),
            sequence,
            probe,
            deadline_boottime_ns,
            request_sha256: [0; 32],
        };
        request.request_sha256 =
            sha256_bytes(&canonical_bytes(&request)?);
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> PlanResult<()> {
        if self.protocol != READINESS_PROTOCOL_VERSION
            || self.request_id == [0; 32]
            || self.fixture_id == [0; 32]
            || self.fixture_sha256 == [0; 32]
            || self.sequence == 0
            || self.deadline_boottime_ns == 0
            || self.request_sha256 == [0; 32]
        {
            return Err(PlanProtocolError::Invalid(
                "readiness request envelope is invalid",
            ));
        }
        self.signed_fixture
            .validate_canonical_binding(boottime_ns()?)?;
        if self.fixture_id != self.signed_fixture.fixture_id
            || self.fixture_sha256
                != self.signed_fixture.fixture_sha256
            || self.deadline_boottime_ns
                > self.signed_fixture.expires_at_boottime_ns
        {
            return Err(PlanProtocolError::Invalid(
                "readiness request differs from its exact signed fixture",
            ));
        }
        let mut copy = self.clone();
        copy.request_sha256 = [0; 32];
        let canonical = canonical_bytes(&copy)?;
        if canonical.len() > MAX_FRAME_BYTES
            || sha256_bytes(&canonical) != self.request_sha256
        {
            return Err(PlanProtocolError::Invalid(
                "readiness request digest or frame bound is invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DockerUpgradeResultV12 {
    pub status: u16,
    pub full_duplex_observed: bool,
    pub client_half_close_observed: bool,
    pub server_after_half_close_observed: bool,
    pub client_stream_sha256: Digest,
    pub server_stream_sha256: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServiceHealthResultV12 {
    pub fixture_image_manifest_sha256: Digest,
    pub service_identity_sha256: Digest,
    pub status: u16,
    pub headers_sha256: Digest,
    pub body_sha256: Digest,
    pub healthy: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ChromiumResultV12 {
    pub browser_image_manifest_sha256: Digest,
    pub browser_executable_sha256: Digest,
    pub browser_version: String,
    pub cdp_protocol_version: String,
    pub cdp_connected: bool,
    pub dom_sha256: Digest,
    pub javascript_result_sha256: Digest,
    pub fetch_response_sha256: Digest,
    pub headless: bool,
    pub private_network: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TeardownResultV12 {
    pub owner_namespace_sha256: Digest,
    pub docker_top_level_object_count_scope: String,
    pub docker_internal_storage_absence_proof: String,
    pub drained_containers: u64,
    pub drained_images: u64,
    pub drained_networks: u64,
    pub drained_volumes: u64,
    pub containers: u64,
    pub images: u64,
    pub networks: u64,
    pub volumes: u64,
    pub docker_authority_established: bool,
    pub mounts: u64,
    pub cgroup_processes: u64,
    pub ledger_terminal: bool,
    pub dind_reaped: bool,
    pub state_root_absent: bool,
    pub terminal_receipt_sha256: Digest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "result", rename_all = "camelCase")]
pub enum ReadinessProbeResultV12 {
    DockerUpgrade(DockerUpgradeResultV12),
    ServiceHealth(ServiceHealthResultV12),
    Chromium(ChromiumResultV12),
    Teardown(TeardownResultV12),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReadinessResponseV12 {
    pub protocol: String,
    pub request_id: Digest,
    pub request_sha256: Digest,
    pub fixture_id: Digest,
    pub sequence: u64,
    pub probe: ReadinessProbe,
    pub result: ReadinessProbeResultV12,
    pub result_sha256: Digest,
    pub response_sha256: Digest,
}

impl ReadinessResponseV12 {
    fn validate_for(&self, request: &ReadinessRequestV12) -> PlanResult<()> {
        if self.protocol != READINESS_PROTOCOL_VERSION
            || self.request_id != request.request_id
            || self.request_sha256 != request.request_sha256
            || self.fixture_id != request.fixture_id
            || self.sequence != request.sequence
            || self.probe != request.probe
            || self.result_sha256 == [0; 32]
            || self.response_sha256 == [0; 32]
        {
            return Err(PlanProtocolError::Invalid(
                "readiness response lost request binding",
            ));
        }
        let result_bytes = canonical_bytes(&self.result)?;
        if result_bytes.len() > MAX_PROBE_RESULT_BYTES
            || sha256_bytes(&result_bytes) != self.result_sha256
        {
            return Err(PlanProtocolError::Invalid(
                "readiness result digest is not canonical",
            ));
        }
        let mut copy = self.clone();
        copy.response_sha256 = [0; 32];
        if sha256_bytes(&canonical_bytes(&copy)?)
            != self.response_sha256
        {
            return Err(PlanProtocolError::Invalid(
                "readiness response digest is not canonical",
            ));
        }
        Ok(())
    }
}

pub trait ReadinessTransport {
    fn execute(
        &mut self,
        request: &ReadinessRequestV12,
    ) -> PlanResult<ReadinessResponseV12>;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReadinessEvidenceV12 {
    pub protocol: String,
    pub fixture_id: Digest,
    pub fixture_sha256: Digest,
    pub controller_generation_sha256: Digest,
    pub runner_generation_sha256: Digest,
    pub trust_profile: RuntimeTrustProfile,
    pub trust_claim: String,
    pub docker_upgrade_result_sha256: Digest,
    pub service_result_sha256: Digest,
    pub chromium_result_sha256: Digest,
    pub teardown_result_sha256: Digest,
    pub completed_at_boottime_ns: u64,
    pub evidence_sha256: Digest,
}

pub struct ReadinessRunner<T: ReadinessTransport> {
    transport: T,
    trust: ReadinessFixtureTrust,
}

impl<T: ReadinessTransport> ReadinessRunner<T> {
    pub fn new(transport: T, trust: ReadinessFixtureTrust) -> Self {
        Self { transport, trust }
    }

    pub fn run(
        mut self,
        fixture: &SignedReadinessFixtureV12,
        deadline_boottime_ns: u64,
        cleanup_deadline_boottime_ns: u64,
    ) -> PlanResult<ReadinessEvidenceV12> {
        let now = boottime_ns()?;
        fixture.validate(&self.trust, now)?;
        if deadline_boottime_ns <= now
            || cleanup_deadline_boottime_ns <= deadline_boottime_ns
            || cleanup_deadline_boottime_ns
                > fixture.expires_at_boottime_ns
        {
            return Err(PlanProtocolError::Invalid(
                "readiness execution deadline is invalid",
            ));
        }
        let primary: PlanResult<(
            ReadinessResponseV12,
            ReadinessResponseV12,
            ReadinessResponseV12,
        )> = (|| {
            let docker = self.run_probe(
                fixture,
                1,
                ReadinessProbe::DockerUpgrade,
                deadline_boottime_ns,
            )?;
            validate_docker_result(fixture, &docker.result)?;
            let service = self.run_probe(
                fixture,
                2,
                ReadinessProbe::ServiceHealth,
                deadline_boottime_ns,
            )?;
            validate_service_result(fixture, &service.result)?;
            let chromium = self.run_probe(
                fixture,
                3,
                ReadinessProbe::Chromium,
                deadline_boottime_ns,
            )?;
            validate_chromium_result(fixture, &chromium.result)?;
            Ok((docker, service, chromium))
        })();
        let teardown = self
            .run_probe(
                fixture,
                4,
                ReadinessProbe::Teardown,
                cleanup_deadline_boottime_ns,
            )
            .and_then(|teardown| {
                validate_teardown_result(
                    fixture,
                    &teardown.result,
                )?;
                Ok(teardown)
            });
        let teardown = match teardown {
            Ok(teardown) => teardown,
            Err(teardown_error) => {
                return match primary {
                    Ok(_) => Err(teardown_error),
                    Err(primary_error) => {
                        Err(PlanProtocolError::InvalidOwned(format!(
                            "{primary_error}; readiness teardown also failed: {teardown_error}",
                        )))
                    }
                };
            }
        };
        let (docker, service, chromium) = primary?;
        let completed = boottime_ns()?;
        if completed >= cleanup_deadline_boottime_ns {
            return Err(PlanProtocolError::Invalid(
                "readiness completed after its cleanup deadline",
            ));
        }
        let mut evidence = ReadinessEvidenceV12 {
            protocol: READINESS_PROTOCOL_VERSION.to_string(),
            fixture_id: fixture.fixture_id,
            fixture_sha256: fixture.fixture_sha256,
            controller_generation_sha256:
                fixture.controller_generation_sha256,
            runner_generation_sha256:
                fixture.runner_generation_sha256,
            trust_profile: RuntimeTrustProfile::TrustedHostNoTee,
            trust_claim: TRUSTED_HOST_CLAIM.to_string(),
            docker_upgrade_result_sha256: docker.result_sha256,
            service_result_sha256: service.result_sha256,
            chromium_result_sha256: chromium.result_sha256,
            teardown_result_sha256: teardown.result_sha256,
            completed_at_boottime_ns: completed,
            evidence_sha256: [0; 32],
        };
        evidence.evidence_sha256 =
            sha256_bytes(&canonical_bytes(&evidence)?);
        Ok(evidence)
    }

    fn run_probe(
        &mut self,
        fixture: &SignedReadinessFixtureV12,
        sequence: u64,
        probe: ReadinessProbe,
        deadline_boottime_ns: u64,
    ) -> PlanResult<ReadinessResponseV12> {
        if boottime_ns()? >= deadline_boottime_ns {
            return Err(PlanProtocolError::Invalid(
                "readiness deadline expired before probe",
            ));
        }
        let request = ReadinessRequestV12::new(
            fixture,
            sequence,
            probe,
            deadline_boottime_ns,
        )?;
        let response = self.transport.execute(&request)?;
        response.validate_for(&request)?;
        if boottime_ns()? >= deadline_boottime_ns {
            return Err(PlanProtocolError::Invalid(
                "readiness deadline expired during probe",
            ));
        }
        Ok(response)
    }
}

fn validate_docker_result(
    fixture: &SignedReadinessFixtureV12,
    result: &ReadinessProbeResultV12,
) -> PlanResult<()> {
    let result = match result {
        ReadinessProbeResultV12::DockerUpgrade(result) => result,
        _ => {
            return Err(PlanProtocolError::Invalid(
                "Docker readiness returned the wrong result kind",
            ));
        }
    };
    if result.status != 101
        || !result.full_duplex_observed
        || !result.client_half_close_observed
        || !result.server_after_half_close_observed
        || result.client_stream_sha256
            != fixture.docker_upgrade.client_stream_sha256
        || result.server_stream_sha256
            != fixture.docker_upgrade.server_stream_sha256
    {
        return Err(PlanProtocolError::Invalid(
            "Docker 101/full-duplex/half-close readiness failed",
        ));
    }
    Ok(())
}

fn validate_service_result(
    fixture: &SignedReadinessFixtureV12,
    result: &ReadinessProbeResultV12,
) -> PlanResult<()> {
    let result = match result {
        ReadinessProbeResultV12::ServiceHealth(result) => result,
        _ => {
            return Err(PlanProtocolError::Invalid(
                "service readiness returned the wrong result kind",
            ));
        }
    };
    if !result.healthy
        || result.fixture_image_manifest_sha256
            != fixture.service.fixture_image.manifest_digest_sha256
        || result.service_identity_sha256
            != fixture.service.service_identity_sha256
        || result.status != fixture.service.expected_status
        || result.headers_sha256
            != fixture.service.expected_headers_sha256
        || result.body_sha256
            != fixture.service.expected_body_sha256
    {
        return Err(PlanProtocolError::Invalid(
            "service readiness fixture failed",
        ));
    }
    Ok(())
}

fn validate_chromium_result(
    fixture: &SignedReadinessFixtureV12,
    result: &ReadinessProbeResultV12,
) -> PlanResult<()> {
    let result = match result {
        ReadinessProbeResultV12::Chromium(result) => result,
        _ => {
            return Err(PlanProtocolError::Invalid(
                "Chromium readiness returned the wrong result kind",
            ));
        }
    };
    if !result.cdp_connected
        || !result.headless
        || !result.private_network
        || result.browser_image_manifest_sha256
            != fixture.chromium.browser_image.manifest_digest_sha256
        || result.browser_executable_sha256
            != fixture.chromium.browser_executable_sha256
        || result.browser_version != fixture.chromium.browser_version
        || result.cdp_protocol_version
            != fixture.chromium.cdp_protocol_version
        || result.dom_sha256 != fixture.chromium.expected_dom_sha256
        || result.javascript_result_sha256
            != fixture.chromium.expected_javascript_result_sha256
        || result.fetch_response_sha256
            != fixture.chromium.expected_fetch_response_sha256
    {
        return Err(PlanProtocolError::Invalid(
            "Chromium CDP/DOM/JS/fetch readiness failed",
        ));
    }
    Ok(())
}

fn validate_teardown_result(
    fixture: &SignedReadinessFixtureV12,
    result: &ReadinessProbeResultV12,
) -> PlanResult<()> {
    let result = match result {
        ReadinessProbeResultV12::Teardown(result) => result,
        _ => {
            return Err(PlanProtocolError::Invalid(
                "teardown readiness returned the wrong result kind",
            ));
        }
    };
    if result.owner_namespace_sha256
        != fixture.teardown.owner_namespace_sha256
        || result.docker_top_level_object_count_scope
            != fixture.teardown.docker_top_level_object_count_scope
        || result.docker_internal_storage_absence_proof
            != fixture.teardown.docker_internal_storage_absence_proof
        || result.containers != 0
        || result.images != 0
        || result.networks != 0
        || result.volumes != 0
        || !result.docker_authority_established
        || result.mounts != 0
        || result.cgroup_processes != 0
        || !result.ledger_terminal
        || !result.dind_reaped
        || !result.state_root_absent
        || result.terminal_receipt_sha256 == [0; 32]
    {
        return Err(PlanProtocolError::Invalid(
            "readiness teardown did not prove zero retained resources",
        ));
    }
    Ok(())
}

fn random_digest() -> PlanResult<Digest> {
    let mut digest = [0u8; 32];
    let result = unsafe {
        libc::syscall(
            libc::SYS_getrandom,
            digest.as_mut_ptr(),
            digest.len(),
            0,
        )
    };
    if result != digest.len() as libc::c_long || digest == [0; 32] {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(digest)
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
