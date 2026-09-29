//! Public staging is owned by the actual StateAuthority, not the router.
//! Only independently admitted measured originals construct VerifiedRequest.
pub mod wire;
pub mod process;
pub(crate) mod inputs;
pub(crate) mod verification;
pub(crate) mod policy;
pub(crate) mod ledger;
pub(crate) mod transport;
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};
use super::{RootOwnedResponseObservationV2Config as Config, V2RuntimeError};
use crate::native_staging_v1 as native;
use super::super::state_authority::contract::BootDeadline;

pub(crate) fn fail(reason: impl Into<String>) -> V2RuntimeError {
    V2RuntimeError::new("native_staging_refused", reason)
}
pub(crate) fn epoch_ns() -> Result<u64, V2RuntimeError> {
    SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| fail("staging epoch clock invalid"))?
        .as_nanos().try_into().map_err(|_| fail("staging epoch overflow"))
}
pub(crate) fn configuration_profile<'de,D:serde::Deserializer<'de>>(value:D)
    -> Result<Option<native::Configuration>,D::Error> { native::Configuration::deserialize(value).map(Some) }

pub(crate) fn validate_configuration(config:&Config) -> Result<(),V2RuntimeError> {
    let Some(profile)=&config.native_staging else { return Ok(()) };
    profile.validate().map_err(fail)?;
    if config.guest_delivery_authority.is_none() || config.guest_listener.is_none()
        || config.target_dispatch.is_none() || config.ledger_exact_read.is_none()
        || config.custody_topology.attestation_mode != super::config::CustodyAttestationProfile::TeeHardware
        || profile.generation_id != config.custody_topology.generation_id
        || profile.generation != config.custody_topology.generation
        || profile.assignment.expected_binary_digest != config.expected_client_executable_measurement_sha256
        || config.expected_client_uid != 65534 {
        return Err(fail("staging needs exact independently admitted guest gate, ledger and separate dispatch purpose"));
    }
    for role in [super::config::CustodyServiceRole::StateAuthority,
        super::config::CustodyServiceRole::PolicyProofVerifier,super::config::CustodyServiceRole::ImmutableArtifactLedger] {
        let process=config.custody_topology.process(role).ok_or_else(|| fail("staging role absent"))?;
        if process.max_frame_bytes != super::super::state_authority::postgres::sequence_originals::REQUIRED_CUSTODY_FRAME_BYTES {
            return Err(fail("staging role does not admit the exact bounded-original transport"));
        }
    }
    Ok(())
}

/// No Deserialize/Clone implementation and no caller-provided verification bit.
/// The retained native envelope is rechecked, including original expiry, for
/// each actual authority effect; this does not permit a new nonce or timeout.
pub(crate) struct VerifiedRequest {
    request:wire::StagingRequest,
    original_sha256:String,
    exact_request:Vec<u8>,
    deadline:BootDeadline,
}
impl VerifiedRequest {
    pub(crate) fn original(&self)->&wire::Original { &self.request.evidence.statement.original }
    pub(crate) fn evidence(&self)->&wire::NativeEvidence { &self.request.evidence }
    pub(crate) fn original_sha256(&self)->&str { &self.original_sha256 }
    pub(crate) fn exact_request(&self)->&[u8] { &self.exact_request }
    pub(crate) fn deadline(&self)->&BootDeadline { &self.deadline }
    pub(crate) fn binding(&self)->&crate::response_observation_v2_api::V2OperationBinding {
        // Construction below admits only these three actual closed variants.
        match &self.original().request {
            crate::response_observation_v2_api::V2OperationRequest::Reserve {params,..}=>&params.binding,
            crate::response_observation_v2_api::V2OperationRequest::Authority {params,..}=>&params.binding,
            crate::response_observation_v2_api::V2OperationRequest::Stage {params,..}=>&params.binding,
            _=>unreachable!("VerifiedRequest has a closed admitted phase"),
        }
    }
    pub(crate) fn phase(&self)->&'static str {
        match &self.original().request {
            crate::response_observation_v2_api::V2OperationRequest::Reserve {..}=>"RESERVE",
            crate::response_observation_v2_api::V2OperationRequest::Authority {..}=>"AUTHORIZE",
            crate::response_observation_v2_api::V2OperationRequest::Stage {..}=>"STAGE",
            _=>unreachable!("VerifiedRequest has a closed admitted phase"),
        }
    }
    pub(crate) fn check(&self,config:&Config)->Result<(),V2RuntimeError> {
        validate_configuration(config)?;
        config.guest_delivery.as_ref().ok_or_else(|| fail("staging retained delivery absent"))?.check()?;
        let selected=config.native_staging.as_ref().ok_or_else(|| fail("staging purpose absent"))?;
        if super::recovery::kernel_boot_id()? != self.deadline.boot_id.0
            || selected.assignment.kernel_boot_id != self.deadline.boot_id.0
            || super::recovery::boottime_ns()? >= native::deadline(self.original()).map_err(fail)? {
            return Err(fail("staging original kernel boot or allowance expired"));
        }
        native::verify(selected,self.evidence(),epoch_ns()?).map_err(fail)
    }
}
pub(crate) fn admit(config:&Config,request:wire::StagingRequest)->Result<VerifiedRequest,V2RuntimeError> {
    validate_configuration(config)?;
    let selected=config.native_staging.as_ref().ok_or_else(|| fail("staging purpose absent"))?;
    if request.api_version != wire::REQUEST { return Err(fail("staging request profile differs")); }
    native::verify(selected,&request.evidence,epoch_ns()?).map_err(fail)?;
    let original=&request.evidence.statement.original;
    let exact_request=native::canonical(&request).map_err(fail)?;
    if exact_request.len()>wire::MAX_METADATA { return Err(fail("staging envelope exceeds fixed bound")); }
    let value=VerifiedRequest {original_sha256:native::original_sha256(original).map_err(fail)?,
        deadline:BootDeadline {clock:"CLOCK_BOOTTIME".into(),
            boot_id:super::super::state_authority::contract::Identifier(selected.assignment.kernel_boot_id.clone()),
            deadline_boot_millis:native::deadline(original).map_err(fail)?/1_000_000},
        request,exact_request};
    value.check(config)?; Ok(value)
}

pub(crate) fn require_session(config:&Config,request:&wire::StagingRequest,
    client:&super::AuthenticatedClientIdentity,session:&super::AuthenticatedSessionIdentity,
    actual_process_sha256:&str,actual_cgroup_sha256:&str)->Result<(),V2RuntimeError> {
    let verified=admit(config,request.clone())?;
    if verified.binding().client_identity_sha256 != client.identity_sha256()
        || session.client_identity_sha256 != client.identity_sha256()
        || verified.original().session_sha256 != session.session_sha256()
        || verified.original().owner.process_binding_sha256 != actual_process_sha256
        || verified.original().owner.cgroup_sha256 != actual_cgroup_sha256 {
        return Err(fail("staging is not from this actual measured packet sender and authenticated session"));
    }
    Ok(())
}
