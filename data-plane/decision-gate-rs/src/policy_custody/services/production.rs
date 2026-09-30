//! Owned v4 production RPC serving bridge.
//!
//! The facade supplies only already-authenticated connected sessions. The
//! launcher/service composition supplies the five verified authority histories,
//! one dedicated durable journal directory capability, and an implementation
//! backed by the existing five v3 authorities. This module never reconstructs
//! a verified parent capability from caller-authored bytes.

use super::common::{
    decode_canonical_frame, encode_canonical_frame,
    perform_authenticated_client_handshake, AuthenticatedInheritedSeqpacket,
    DurableAppendJournal, ExpectedPeerCredentials,
    ServiceHandshakeRequestV3, TrustedHostServiceRoleV3,
    MAX_SERVICE_FRAME_BYTES, validate_exact_peer_path,
};
use super::super::authority_history::{
    AuthorityHistoryManifestV3, HistoricalAuthorityRoleV3,
    HistoricalServiceRoleV3,
};
use super::super::boottime::boottime_now_nanos;
use super::super::operation_driver::{
    ValidatedServiceHandshakeV3, VerifiedFiveServiceReadinessV3,
};
use super::super::protocol::{
    domain_separated_signature_preimage, PolicyCustodyEndpointRole,
    PolicyCustodyOperation,
};
use super::super::production_dispatch::{
    CanonicalProductionArtifactV4, ClosedProductionDispatchRequestV4,
    ClosedProductionDispatchResponseV4,
    ClosedProductionGenerationRequestV4,
    ClosedProductionGenerationResponseV4,
    ProductionRpcRejectionCodeV4, ProductionRpcRejectionV4,
    ProductionRpcRequestBodyV4, ProductionRpcRequestV4,
    ProductionRpcResponseBodyV4, ProductionRpcResponseV4,
    PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION,
    PRODUCTION_RPC_PROTOCOL_VERSION,
    production_dispatch_protocol_set_sha256,
};
use super::super::terminal_settlement::FiveServiceHistoricalKeyringsV4;
use super::{
    ActivationDirectoryIdentityV3, ExpectedPeerCredentialV3,
    RuntimeAuthorityHistory, ServiceRunnerError,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::pkcs8::EncodePublicKey;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::mpsc::{
    sync_channel, Receiver, SyncSender, TrySendError,
};
use std::sync::{Arc, Mutex};
use std::thread;
use super::guest::native_guest::{self, retrieval_client};

const PRODUCTION_RPC_SESSION_COUNT: usize = 4;
const PRODUCTION_RPC_WORKER_COUNT: usize = 4;
const PRODUCTION_RPC_QUEUE_DEPTH: usize = 32;
const MAX_PRODUCTION_RPC_REPLAY_RECORDS: usize = 65_536;
const MAX_PRODUCTION_RPC_REPLAY_BYTES: usize = 256 * 1024 * 1024;
const PRODUCTION_RPC_POLL_SLICE_MILLIS: i32 = 250;
const PRODUCTION_RPC_RUNTIME_CONFIG_VERSION: &str =
    "serverware.policyCustodyProductionRpcRuntime/v4";
const PRODUCTION_RPC_CONFIG_CREDENTIAL: &str =
    "serverware-policy-custody-production-rpc.json";
const PRODUCTION_RPC_LISTENER_FD_NAME: &str = "production-listener";
const PRODUCTION_RPC_JOURNAL_FD_NAME: &str = "production-journal";
const PRODUCTION_AUTHORITY_ENDPOINT_REQUEST_DOMAIN: &[u8] =
    b"serverware.policyCustodyProductionAuthorityEndpointRequest/v4";
const PRODUCTION_AUTHORITY_ENDPOINT_RESPONSE_DOMAIN: &[u8] =
    b"serverware.policyCustodyProductionAuthorityEndpointResponse/v4";
const PRODUCTION_AUTHORITY_ENDPOINT_SIGNATURE_DOMAIN: &[u8] =
    b"serverware.policyCustodyProductionAuthorityEndpointSignature/v4";
const MAX_PRODUCTION_ENDPOINT_SIGNATURE_BASE64_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ProductionPrimitiveRejectionV4 {
    pub(super) code: ProductionRpcRejectionCodeV4,
    pub(super) reason: &'static str,
}

impl ProductionPrimitiveRejectionV4 {
    pub(super) const fn rejected(
        code: ProductionRpcRejectionCodeV4,
        reason: &'static str,
    ) -> Self {
        Self { code, reason }
    }
}

/// Closed authority contract implemented by the composition that owns the
/// existing five v3 authority clients. Every method must return exact v4
/// signed service transitions; unavailable artifacts must use a typed
/// rejection rather than synthesized bytes.
pub(super) trait ExistingFiveServiceProductionAuthoritiesV4: Send {
    fn take_native_commitment_original(&mut self,_request:&ClosedProductionDispatchRequestV4,
        _response:&ClosedProductionDispatchResponseV4)->Result<Option<serde_json::Value>,ProductionPrimitiveRejectionV4>{Ok(None)}
    // Legacy profiles keep their existing independently owned clock contract.
    // Only the explicit native proof bridge constructs this sampled owner.
    fn trusted_time_for_operation(&self,_request:&ProductionRpcRequestV4)
        ->Result<Option<native_guest::trusted_time_sample::VerifiedSample>,ProductionPrimitiveRejectionV4> {Ok(None)}
    fn recover_current_state(
        &mut self,
        request: &ClosedProductionDispatchRequestV4,
    ) -> Result<ClosedProductionDispatchResponseV4, ProductionPrimitiveRejectionV4>;
    fn verify_checkpoint_successor(
        &mut self,
        request: &ClosedProductionDispatchRequestV4,
    ) -> Result<ClosedProductionDispatchResponseV4, ProductionPrimitiveRejectionV4>;
    fn verify_current_checkpoint_head(
        &mut self,
        request: &ClosedProductionDispatchRequestV4,
    ) -> Result<ClosedProductionDispatchResponseV4, ProductionPrimitiveRejectionV4>;
    fn verify_observation_evidence(
        &mut self,
        request: &ClosedProductionDispatchRequestV4,
    ) -> Result<ClosedProductionDispatchResponseV4, ProductionPrimitiveRejectionV4>;
    fn prepare_generation_publication(
        &mut self,
        request: &ClosedProductionDispatchRequestV4,
    ) -> Result<ClosedProductionDispatchResponseV4, ProductionPrimitiveRejectionV4>;
    fn commit_generation_publication(
        &mut self,
        request: &ClosedProductionDispatchRequestV4,
    ) -> Result<ClosedProductionDispatchResponseV4, ProductionPrimitiveRejectionV4>;
    fn abort_generation_publication(
        &mut self,
        request: &ClosedProductionDispatchRequestV4,
    ) -> Result<ClosedProductionDispatchResponseV4, ProductionPrimitiveRejectionV4>;
    fn begin_ingress(
        &mut self,
        request: &ClosedProductionDispatchRequestV4,
    ) -> Result<ClosedProductionDispatchResponseV4, ProductionPrimitiveRejectionV4>;
    fn reserve_spool_append(
        &mut self,
        request: &ClosedProductionDispatchRequestV4,
    ) -> Result<ClosedProductionDispatchResponseV4, ProductionPrimitiveRejectionV4>;
    fn append_spool_event(
        &mut self,
        request: &ClosedProductionDispatchRequestV4,
    ) -> Result<ClosedProductionDispatchResponseV4, ProductionPrimitiveRejectionV4>;
    fn compact_spool(
        &mut self,
        request: &ClosedProductionDispatchRequestV4,
    ) -> Result<ClosedProductionDispatchResponseV4, ProductionPrimitiveRejectionV4>;
    fn commit_request(
        &mut self,
        request: &ClosedProductionDispatchRequestV4,
    ) -> Result<ClosedProductionDispatchResponseV4, ProductionPrimitiveRejectionV4>;
    fn append_active_effect_barrier(
        &mut self,
        request: &ClosedProductionDispatchRequestV4,
    ) -> Result<ClosedProductionDispatchResponseV4, ProductionPrimitiveRejectionV4>;
    fn commit_active_effect(
        &mut self,
        request: &ClosedProductionDispatchRequestV4,
    ) -> Result<ClosedProductionDispatchResponseV4, ProductionPrimitiveRejectionV4>;
    fn reconcile_active_effect(
        &mut self,
        request: &ClosedProductionDispatchRequestV4,
    ) -> Result<ClosedProductionDispatchResponseV4, ProductionPrimitiveRejectionV4>;
    fn append_terminal(
        &mut self,
        request: &ClosedProductionDispatchRequestV4,
    ) -> Result<ClosedProductionDispatchResponseV4, ProductionPrimitiveRejectionV4>;
    fn consume_and_publish_activation(
        &mut self,
        request: &ClosedProductionDispatchRequestV4,
    ) -> Result<ClosedProductionDispatchResponseV4, ProductionPrimitiveRejectionV4>;

    fn recover_generation(
        &mut self,
        request: &ClosedProductionGenerationRequestV4,
    ) -> Result<ClosedProductionGenerationResponseV4, ProductionPrimitiveRejectionV4>;
    fn prepare_generation(
        &mut self,
        request: &ClosedProductionGenerationRequestV4,
    ) -> Result<ClosedProductionGenerationResponseV4, ProductionPrimitiveRejectionV4>;
    fn commit_generation(
        &mut self,
        request: &ClosedProductionGenerationRequestV4,
    ) -> Result<ClosedProductionGenerationResponseV4, ProductionPrimitiveRejectionV4>;
    fn abort_generation(
        &mut self,
        request: &ClosedProductionGenerationRequestV4,
    ) -> Result<ClosedProductionGenerationResponseV4, ProductionPrimitiveRejectionV4>;

    fn request_termination(
        &mut self,
        request: &ProductionRpcRequestV4,
    ) -> Result<(), ProductionPrimitiveRejectionV4>;
    fn settle_cleanup(
        &mut self,
        request: &ProductionRpcRequestV4,
    ) -> Result<CanonicalProductionArtifactV4, ProductionPrimitiveRejectionV4>;
    fn verify_persistence(
        &mut self,
        request: &ProductionRpcRequestV4,
    ) -> Result<(), ProductionPrimitiveRejectionV4>;
    fn verify_retrieval(
        &mut self,
        request: &ProductionRpcRequestV4,
    ) -> Result<(), ProductionPrimitiveRejectionV4>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductionServiceHandshakeConfigV4 {
    endpoint_role: PolicyCustodyEndpointRole,
    request: ServiceHandshakeRequestV3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductionServiceSessionConfigV4 {
    service_role: TrustedHostServiceRoleV3,
    activation_fd_name: String,
    expected_socket_path: PathBuf,
    expected_peer: ExpectedPeerCredentialV3,
    handshakes: Vec<ProductionServiceHandshakeConfigV4>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductionHistoryConfigV4 {
    service_role: HistoricalServiceRoleV3,
    manifest_credential: String,
    manifest_sha256: super::super::super::Sha256Digest,
    root_key_id: super::super::super::Sha256Digest,
    root_key_spki_sha256: super::super::super::Sha256Digest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProductionParentSignerEndpointConfigV4 {
    pub(super) signer_role: super::super::super::PolicyShadowCustodySignerRole,
    pub(super) authority_binding_credential: String,
    pub(super) activation_fd_name: String,
    pub(super) expected_socket_path: PathBuf,
    pub(super) expected_peer: ExpectedPeerCredentialV3,
    pub(super) authority_key_id: super::super::super::Sha256Digest,
    pub(super) authority_key_spki_sha256: super::super::super::Sha256Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum ProductionProofEndpointKindV4 {
    TrustedTime,
    Persistence,
    Retrieval,
    GenerationInstallEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProductionProofEndpointConfigV4 {
    pub(super) endpoint_kind: ProductionProofEndpointKindV4,
    pub(super) authority_binding_credential: String,
    pub(super) activation_fd_name: String,
    pub(super) expected_socket_path: PathBuf,
    pub(super) expected_peer: ExpectedPeerCredentialV3,
    pub(super) authority_key_id: super::super::super::Sha256Digest,
    pub(super) authority_key_spki_sha256: super::super::super::Sha256Digest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProductionRpcRuntimeConfigV4 {
    api_version: String,
    startup_timeout_millis: u64,
    listener_socket_path: PathBuf,
    expected_facade_peer: ExpectedPeerCredentialV3,
    journal_directory_identity: ActivationDirectoryIdentityV3,
    expected_helper_endpoint_roles: BTreeSet<PolicyCustodyEndpointRole>,
    expected_driver_process_identity_sha256:
        super::super::super::Sha256Digest,
    expected_driver_configuration_generation_sha256:
        super::super::super::Sha256Digest,
    expected_operation_generation: u64,
    expected_shared_configuration_sha256:
        super::super::super::Sha256Digest,
    expected_service_configuration_sha256: BTreeMap<
        TrustedHostServiceRoleV3,
        super::super::super::Sha256Digest,
    >,
    expected_service_signing_credential_sha256: BTreeMap<
        TrustedHostServiceRoleV3,
        super::super::super::Sha256Digest,
    >,
    expected_service_restart_epoch:
        BTreeMap<TrustedHostServiceRoleV3, u64>,
    expected_service_readiness_epoch:
        BTreeMap<TrustedHostServiceRoleV3, u64>,
    expected_service_authority_history_manifest_sha256: BTreeMap<
        TrustedHostServiceRoleV3,
        super::super::super::Sha256Digest,
    >,
    expected_production_dispatch_protocol_set_sha256:
        super::super::super::Sha256Digest,
    expected_maximum_durability_worker_nanos: u64,
    service_sessions: Vec<ProductionServiceSessionConfigV4>,
    histories: Vec<ProductionHistoryConfigV4>,
    pub(super) parent_signer_endpoints: Vec<ProductionParentSignerEndpointConfigV4>,
    pub(super) proof_endpoints: Vec<ProductionProofEndpointConfigV4>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    generation_admission:Option<super::generation_service_client::Selection>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    pub(super) commit_request:Option<super::dispatch_service::client::Selection>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    pub(super) spool:Option<super::spool_head_client::Selection>,
}

impl ProductionRpcRuntimeConfigV4 {
    pub(super) fn native_driver_selection(&self)->Result<(super::super::super::Sha256Digest,super::super::super::Sha256Digest),ServiceRunnerError>{
        self.validate()?;Ok((self.expected_driver_process_identity_sha256.clone(),
            self.expected_driver_configuration_generation_sha256.clone()))
    }
    pub(super) fn native_facade_selection(&self)->Result<(PathBuf,ExpectedPeerCredentials),ServiceRunnerError> {
        self.validate()?;
        Ok((self.listener_socket_path.clone(),self.expected_facade_peer.checked()?))
    }
    pub(super) fn native_outgoing_selections(&self)->Result<Vec<(String,PathBuf,ExpectedPeerCredentials)>,ServiceRunnerError> {
        self.validate()?;
        let mut selected=Vec::with_capacity(15);
        for entry in &self.service_sessions {
            selected.push((entry.activation_fd_name.clone(),entry.expected_socket_path.clone(),entry.expected_peer.checked()?));
        }
        for entry in &self.parent_signer_endpoints {
            selected.push((entry.activation_fd_name.clone(),entry.expected_socket_path.clone(),entry.expected_peer.checked()?));
        }
        selected.sort_by(|a,b|a.0.cmp(&b.0));
        if selected.windows(2).any(|pair|pair[0].0==pair[1].0) {
            return Err(ServiceRunnerError::invalid("native bridge outgoing activation is duplicated"));
        }
        Ok(selected)
    }
    pub(super) fn validate(&self) -> Result<(), ServiceRunnerError> {
        let expected_roles = BTreeSet::from([
            TrustedHostServiceRoleV3::DurableRecoveryStore,
            TrustedHostServiceRoleV3::CleanupAuthorizationConsumer,
            TrustedHostServiceRoleV3::RecoveryTargetProvider,
            TrustedHostServiceRoleV3::CurrentSignatureAuthority,
            TrustedHostServiceRoleV3::BoundedCleanupHelper,
        ]);
        let session_roles = self
            .service_sessions
            .iter()
            .map(|session| session.service_role)
            .collect::<BTreeSet<_>>();
        let history_roles = self
            .histories
            .iter()
            .map(|history| history.service_role)
            .collect::<BTreeSet<_>>();
        if !matches!((self.api_version.as_str(),self.generation_admission.as_ref(),self.commit_request.as_ref(),self.spool.as_ref()),
            (PRODUCTION_RPC_RUNTIME_CONFIG_VERSION,None,None,None)|(super::generation_service_client::RUNTIME,Some(_),None,None)
            |(super::dispatch_service::client::BRIDGE_RUNTIME,Some(_),Some(_),None)
            |(super::spool_head_client::RUNTIME,Some(_),Some(_),Some(_))
            |(super::spool_head_client::COMPLETION_RUNTIME,Some(_),Some(_),Some(_))
            |(super::spool_head_client::EFFECTS_RUNTIME,Some(_),Some(_),Some(_)))
            || self.spool.as_ref().is_some_and(|value|value.completion_selected())
                != matches!(self.api_version.as_str(),super::spool_head_client::COMPLETION_RUNTIME|super::spool_head_client::EFFECTS_RUNTIME)
            || self.spool.as_ref().is_some_and(|value|value.effects_selected())!=(self.api_version==super::spool_head_client::EFFECTS_RUNTIME)
            || self.startup_timeout_millis == 0
            || self.startup_timeout_millis > 30_000
            || !self.listener_socket_path.is_absolute()
            || self.expected_operation_generation == 0
            || self.service_sessions.len() != 5
            || session_roles != expected_roles
            || self.histories.len() != 5
            || history_roles
                != BTreeSet::from([
                    HistoricalServiceRoleV3::DurableRecoveryStore,
                    HistoricalServiceRoleV3::CleanupAuthorizationConsumer,
                    HistoricalServiceRoleV3::RecoveryTargetProvider,
                    HistoricalServiceRoleV3::CurrentSignatureAuthority,
                    HistoricalServiceRoleV3::BoundedCleanupHelper,
                ])
            || self.expected_helper_endpoint_roles.is_empty()
            || self.parent_signer_endpoints.len() != 10
            || self.proof_endpoints.len() != 4
            || production_dispatch_protocol_set_sha256()
                .map_or(true, |expected| {
                    expected
                        != self
                            .expected_production_dispatch_protocol_set_sha256
                })
        {
            return Err(ServiceRunnerError::invalid(
                "production RPC runtime config is incomplete or outside its fixed bounds",
            ));
        }
        self.expected_facade_peer.checked()?;
        if let Some(selection)=&self.generation_admission {selection.validate()?;}
        self.journal_directory_identity.validate()?;
        if let Some(selection)=&self.commit_request {selection.validate()?;}
        if let Some(selection)=&self.spool {selection.validate()?;}
        let mut names = BTreeSet::from([
            PRODUCTION_RPC_LISTENER_FD_NAME.to_owned(),
            PRODUCTION_RPC_JOURNAL_FD_NAME.to_owned(),
        ]);
        for session in &self.service_sessions {
            super::validate_fd_name(&session.activation_fd_name)?;
            session.expected_peer.checked()?;
            if !names.insert(session.activation_fd_name.clone())
                || !session.expected_socket_path.is_absolute()
                || session.handshakes.is_empty()
                || (session.service_role
                    != TrustedHostServiceRoleV3::BoundedCleanupHelper
                    && session.handshakes.len() != 1)
            {
                return Err(ServiceRunnerError::invalid(
                    "production RPC service session config is duplicated or incomplete",
                ));
            }
            for handshake in &session.handshakes {
                handshake.request.validate(
                    session.service_role,
                    handshake.endpoint_role,
                )?;
            }
        }
        for history in &self.histories {
            super::validate_credential_name(
                &history.manifest_credential,
            )?;
            if history.manifest_sha256
                    == super::super::super::Sha256Digest::compute(&[])
                || history.root_key_id
                    == super::super::super::Sha256Digest::compute(&[])
                || history.root_key_spki_sha256
                    == super::super::super::Sha256Digest::compute(&[])
            {
                return Err(ServiceRunnerError::invalid(
                    "production authority history pins must be nonzero",
                ));
            }
        }
        let mut signer_roles = Vec::new();
        for endpoint in &self.parent_signer_endpoints {
            super::validate_credential_name(&endpoint.authority_binding_credential)?;
            super::validate_fd_name(&endpoint.activation_fd_name)?;
            endpoint.expected_peer.checked()?;
            if !endpoint.expected_socket_path.is_absolute()
                || !names.insert(endpoint.activation_fd_name.clone())
                || signer_roles.contains(&endpoint.signer_role)
                || endpoint.authority_key_id
                    == super::super::super::Sha256Digest::compute(&[])
                || endpoint.authority_key_spki_sha256
                    == super::super::super::Sha256Digest::compute(&[])
            {
                return Err(ServiceRunnerError::invalid(
                    "production parent signer endpoint is duplicated or incomplete",
                ));
            }
            signer_roles.push(endpoint.signer_role);
        }
        let expected_signer_roles = [
            super::super::super::PolicyShadowCustodySignerRole::IngressAdmission,
            super::super::super::PolicyShadowCustodySignerRole::UnavailableIngress,
            super::super::super::PolicyShadowCustodySignerRole::DispatchBarrier,
            super::super::super::PolicyShadowCustodySignerRole::ActiveEffectBarrier,
            super::super::super::PolicyShadowCustodySignerRole::ActiveEffectCommit,
            super::super::super::PolicyShadowCustodySignerRole::TerminalAppend,
            super::super::super::PolicyShadowCustodySignerRole::LedgerAppend,
            super::super::super::PolicyShadowCustodySignerRole::SpoolCompaction,
            super::super::super::PolicyShadowCustodySignerRole::PublicationReconciliation,
            super::super::super::PolicyShadowCustodySignerRole::ActivationPublication,
        ];
        if signer_roles.len() != expected_signer_roles.len()
            || expected_signer_roles
                .iter()
                .any(|role| !signer_roles.contains(role))
        {
            return Err(ServiceRunnerError::invalid(
                "production parent signer endpoint roles are not exhaustive",
            ));
        }
        let mut proof_kinds = BTreeSet::new();
        for endpoint in &self.proof_endpoints {
            super::validate_credential_name(&endpoint.authority_binding_credential)?;
            super::validate_fd_name(&endpoint.activation_fd_name)?;
            endpoint.expected_peer.checked()?;
            if !endpoint.expected_socket_path.is_absolute()
                || !names.insert(endpoint.activation_fd_name.clone())
                || !proof_kinds.insert(endpoint.endpoint_kind)
                || endpoint.authority_key_id
                    == super::super::super::Sha256Digest::compute(&[])
                || endpoint.authority_key_spki_sha256
                    == super::super::super::Sha256Digest::compute(&[])
            {
                return Err(ServiceRunnerError::invalid(
                    "production proof endpoint is duplicated or incomplete",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "endpointKind",
    content = "endpointRole",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub(super) enum ProductionAuthorityEndpointIdentityV4 {
    ParentSigner(
        super::super::super::PolicyShadowCustodySignerRole,
    ),
    Proof(ProductionProofEndpointKindV4),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "requestKind",
    content = "body",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub(super) enum ProductionAuthorityEndpointRequestBodyV4 {
    SampleTrustedTime {operation_sha256:super::super::super::Sha256Digest},
    Dispatch(ClosedProductionDispatchRequestV4),
    PrepareCommitRequest {request:ClosedProductionDispatchRequestV4},
    FinishCommitRequest {computation:super::dispatch_commitment::Computation,
        service_transitions:Vec<super::super::production_dispatch::SignedProductionServiceTransitionV4>},
    /// Only the independently admitted acyclic retrieval successor accepts
    /// this effect. A legacy retrieval proof can never trigger a write.
    StoreLedgerCore {prepared:super::ledger_spool_values::Prepared},
    StoreActiveEffectCore {prepared:super::active_effect_values::Prepared},
    PrepareNativeActiveEffect {request:ClosedProductionDispatchRequestV4,allocation:super::active_effect_values::Allocation,head_grant_original:String},
    CompleteNativeActiveEffect {prepared:super::active_effect_values::Prepared,stored:super::ledger_spool_values::Stored},
    FinishNativeActiveEffect {completion:super::active_effect_values::Completion,result:super::super::production_dispatch::ClosedProductionDispatchResultV4,
        service_transitions:Vec<super::super::production_dispatch::SignedProductionServiceTransitionV4>},
    PrepareNativeIngress {request:ClosedProductionDispatchRequestV4,origin_original:Option<String>,head_grant_original:String},
    SampleNativeIngress {claim:super::spool_head_values::Claim,allocation:super::spool_head_values::Allocation,head_grant_original:String},
    PrepareNativeSpool {claim:super::spool_head_values::Claim,allocation:super::spool_head_values::Allocation,
        sampling:Option<super::spool_head_values::Sampling>,head_grant_original:String},
    CompleteNativeSpool {prepared:super::ledger_spool_values::Prepared,stored:super::ledger_spool_values::Stored},
    FinishNativeSpool {completion:super::spool_head_values::Completion,result:super::super::production_dispatch::ClosedProductionDispatchResultV4,
        service_transitions:Vec<super::super::production_dispatch::SignedProductionServiceTransitionV4>},
    Generation(ClosedProductionGenerationRequestV4),
    /// Explicit selected successor: actual five local effects/observations.
    /// The coordinator must verify them and perform its own durable effect;
    /// their existence is not a completed generation-installation receipt.
    GenerationAdmission {
        request:ClosedProductionGenerationRequestV4,
        services:super::generation_service_client::Replies,
    },
    GenerationConclude(Box<super::generation_certification::Conclude>),
    RequestTermination {
        request: ProductionRpcRequestV4,
    },
    Settle {
        request: ProductionRpcRequestV4,
    },
    VerifyProof {
        request: ProductionRpcRequestV4,
    },
    /// Explicit effect: never selected by a VerifyProof request.
    StoreDispatchOriginal {
        request_original_base64url: String,
        reply_original_base64url: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProductionAuthorityEndpointRequestV4 {
    pub(super) api_version: String,
    pub(super) endpoint: ProductionAuthorityEndpointIdentityV4,
    pub(super) replay_id_sha256: super::super::super::Sha256Digest,
    pub(super) deadline_boottime_nanos: u64,
    pub(super) request: ProductionAuthorityEndpointRequestBodyV4,
    pub(super) request_sha256: super::super::super::Sha256Digest,
}

impl ProductionAuthorityEndpointRequestV4 {
    fn new(
        endpoint: ProductionAuthorityEndpointIdentityV4,
        replay_id_sha256: super::super::super::Sha256Digest,
        deadline_boottime_nanos: u64,
        request: ProductionAuthorityEndpointRequestBodyV4,
    ) -> Result<Self, ProductionPrimitiveRejectionV4> {
        let mut wire = Self {
            api_version:
                PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION.to_owned(),
            endpoint,
            replay_id_sha256,
            deadline_boottime_nanos,
            request,
            request_sha256:
                super::super::super::Sha256Digest::compute(&[]),
        };
        wire.request_sha256 = wire.computed_request_sha256()?;
        Ok(wire)
    }

    pub(super) fn computed_request_sha256(
        &self,
    ) -> Result<
        super::super::super::Sha256Digest,
        ProductionPrimitiveRejectionV4,
    > {
        let payload = super::super::super::canonical_json_bytes(&(
            &self.api_version,
            self.endpoint,
            &self.replay_id_sha256,
            self.deadline_boottime_nanos,
            &self.request,
        ))
        .map_err(|_| {
            ProductionPrimitiveRejectionV4::rejected(
                ProductionRpcRejectionCodeV4::InvalidRequest,
                "production authority endpoint request is not canonical",
            )
        })?;
        Ok(super::super::super::hash_domain_frames(
            PRODUCTION_AUTHORITY_ENDPOINT_REQUEST_DOMAIN,
            &[&payload],
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "resultKind",
    content = "body",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub(super) enum ProductionAuthorityEndpointResultV4 {
    TrustedTimeInterval(native_guest::trusted_time_sample::Sample),
    PersistenceCommitted { commit_original_sha256: super::super::super::Sha256Digest },
    Dispatch(ClosedProductionDispatchResponseV4),
    CommitRequestPrepared(super::dispatch_commitment::Computation),
    LedgerCoreStored(super::ledger_spool_values::Stored),
    NativeIngressPrepared(super::spool_head_values::Ingress),
    NativeIngressSampling(super::spool_head_values::Sampling),
    NativeSpoolPrepared(super::ledger_spool_values::Prepared),
    NativeSpoolCompletion(super::spool_head_values::Completion),
    ActiveEffectCoreStored(super::ledger_spool_values::Stored),
    NativeActiveEffectPrepared(super::active_effect_values::Prepared),
    NativeActiveEffectCompletion(super::active_effect_values::Completion),
    Generation(ClosedProductionGenerationResponseV4),
    GenerationProposal(super::generation_certification::Proposal),
    TerminationRequested,
    Settlement(CanonicalProductionArtifactV4),
    Verified,
    Rejected(ProductionRpcRejectionV4),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ProductionShadowSpoolPhaseV4 {
    IngressOpen,
    Capture,
    Decision,
    PreDispatchTerminal,
    DispatchBarrier,
    PostDispatchTerminal,
    Response,
    Candidate,
    RangeClosure,
}

#[derive(Debug, Deserialize)]
struct ProductionShadowSpoolRoutingV4 {
    phase: ProductionShadowSpoolPhaseV4,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProductionAuthorityEndpointReplyV4 {
    pub(super) api_version: String,
    pub(super) endpoint: ProductionAuthorityEndpointIdentityV4,
    pub(super) request_sha256: super::super::super::Sha256Digest,
    pub(super) replay_id_sha256: super::super::super::Sha256Digest,
    pub(super) completed_at_boottime_nanos: u64,
    pub(super) authority_key_id: super::super::super::Sha256Digest,
    pub(super) authority_key_spki_sha256: super::super::super::Sha256Digest,
    pub(super) result: ProductionAuthorityEndpointResultV4,
    pub(super) result_sha256: super::super::super::Sha256Digest,
    pub(super) signature_base64: String,
}

impl ProductionAuthorityEndpointReplyV4 {
    pub(super) fn signature_payload(
        &self,
    ) -> Result<Vec<u8>, ProductionPrimitiveRejectionV4> {
        super::super::super::canonical_json_bytes(&(
            &self.api_version,
            self.endpoint,
            &self.request_sha256,
            &self.replay_id_sha256,
            self.completed_at_boottime_nanos,
            &self.authority_key_id,
            &self.authority_key_spki_sha256,
            &self.result_sha256,
        ))
        .map_err(|_| {
            ProductionPrimitiveRejectionV4::rejected(
                ProductionRpcRejectionCodeV4::InvalidRequest,
                "production authority endpoint reply is not canonical",
            )
        })
    }
}

struct ProductionPinnedEndpointV4 {
    identity: ProductionAuthorityEndpointIdentityV4,
    session: EndpointSession,
    authority_key_id: super::super::super::Sha256Digest,
    authority_key_spki_sha256: super::super::super::Sha256Digest,
    authority_key: VerifyingKey,
}
enum EndpointSession {
    Host(AuthenticatedInheritedSeqpacket),
    NativeRetrieval(retrieval_client::Session),
    NativeProof(native_guest::proof_client::Session),
}
struct EndpointPacket {
    frame:Vec<u8>,
    original:Option<native_guest::retrieval_peer::Packet>,
}
impl EndpointSession {
    fn revalidate_peer(&self)->Result<(),ServiceRunnerError> {match self {
        Self::Host(v)=>v.revalidate_peer().map_err(Into::into),
        Self::NativeRetrieval(v)=>v.check().map_err(|_|ServiceRunnerError::invalid("native retrieval owner changed")),
        Self::NativeProof(v)=>v.check().map_err(|_|ServiceRunnerError::invalid("native proof owner changed")),
    }}
    fn progress_fd(&self)->std::os::fd::BorrowedFd<'_> {match self {
        Self::Host(v)=>v.progress_fd(),Self::NativeRetrieval(v)=>v.progress_fd(),Self::NativeProof(v)=>v.progress_fd(),
    }}
    fn send(&self,raw:&[u8],deadline:u64)->Result<bool,ServiceRunnerError> {match self {
        Self::Host(v)=>v.try_send(raw,&[],0).map_err(Into::into),
        Self::NativeRetrieval(v)=>v.send(raw,deadline).map_err(|_|ServiceRunnerError::invalid("native retrieval send inspection refused")),
        Self::NativeProof(v)=>v.send(raw,deadline).map_err(|_|ServiceRunnerError::invalid("native proof send inspection refused")),
    }}
    fn receive(&self,deadline:u64)->Result<Option<EndpointPacket>,ServiceRunnerError> {match self {
        Self::Host(v)=>Ok(v.try_receive(0)?.map(|v|EndpointPacket{frame:v.frame,original:None})),
        Self::NativeProof(v)=>Ok(v.receive(deadline)
            .map_err(|_|ServiceRunnerError::invalid("native proof packet inspection refused"))?
            .map(|v|EndpointPacket{frame:v.bytes.clone(),original:Some(v)})),
        Self::NativeRetrieval(v)=>Ok(v.receive(deadline)
            .map_err(|_|ServiceRunnerError::invalid("native retrieval packet inspection refused"))?
            .map(|v|EndpointPacket{frame:v.bytes.clone(),original:Some(v)})),
    }}
    fn after_reply(&self,packet:&EndpointPacket,deadline:u64)->Result<(),ServiceRunnerError> {match self {
        Self::Host(v)=>v.revalidate_peer().map_err(Into::into),
        Self::NativeProof(v)=>{
            let original=packet.original.as_ref().ok_or_else(||ServiceRunnerError::invalid("native proof packet original absent"))?;
            if original.bytes!=packet.frame {return Err(ServiceRunnerError::invalid("native proof exact reply changed"));}
            v.after_verify(original,deadline).map_err(|_|ServiceRunnerError::invalid("native proof final inspection refused"))
        }
        Self::NativeRetrieval(v)=>{
            let original=packet.original.as_ref().ok_or_else(||ServiceRunnerError::invalid("native retrieval packet original absent"))?;
            if original.bytes!=packet.frame {return Err(ServiceRunnerError::invalid("native retrieval exact reply changed"));}
            v.after_verify(original,deadline).map_err(|_|ServiceRunnerError::invalid("native retrieval final inspection refused"))
        }
    }}
}

/// Concrete extracted composition. The five v3 sessions establish exact
/// service readiness and remain live for the lifetime of the v4 adapter. The
/// dedicated production endpoints expose the closed v4 mutation surface; no
/// request is reconstructed as an in-process authority call.
pub(super) struct ConcreteFiveV3ProductionAuthoritiesV4 {
    native_proof_owner:Option<Arc<native_guest::AdmittedGuest>>,
    sessions: BTreeMap<
        TrustedHostServiceRoleV3,
        AuthenticatedInheritedSeqpacket,
    >,
    _readiness: VerifiedFiveServiceReadinessV3,
    parent_signer_endpoints: Vec<ProductionPinnedEndpointV4>,
    proof_endpoints:
        BTreeMap<ProductionProofEndpointKindV4, ProductionPinnedEndpointV4>,
    generation_admission:Option<std::sync::Mutex<super::generation_service_client::Client>>,
    commit_request:Option<std::sync::Mutex<super::dispatch_service::client::Client>>,
    spool:Option<std::sync::Mutex<super::spool_head_client::Client>>,
}

impl ConcreteFiveV3ProductionAuthoritiesV4 {
    fn new(
        sessions: BTreeMap<
            TrustedHostServiceRoleV3,
            AuthenticatedInheritedSeqpacket,
        >,
        readiness: VerifiedFiveServiceReadinessV3,
        parent_signer_endpoints: Vec<ProductionPinnedEndpointV4>,
        proof_endpoints: BTreeMap<
            ProductionProofEndpointKindV4,
            ProductionPinnedEndpointV4,
        >,
    ) -> Result<Self, ServiceRunnerError> {
        let expected_services = BTreeSet::from([
            TrustedHostServiceRoleV3::DurableRecoveryStore,
            TrustedHostServiceRoleV3::CleanupAuthorizationConsumer,
            TrustedHostServiceRoleV3::RecoveryTargetProvider,
            TrustedHostServiceRoleV3::CurrentSignatureAuthority,
            TrustedHostServiceRoleV3::BoundedCleanupHelper,
        ]);
        let expected_proofs = BTreeSet::from([
            ProductionProofEndpointKindV4::TrustedTime,
            ProductionProofEndpointKindV4::Persistence,
            ProductionProofEndpointKindV4::Retrieval,
            ProductionProofEndpointKindV4::GenerationInstallEnvelope,
        ]);
        if sessions.keys().copied().collect::<BTreeSet<_>>()
                != expected_services
            || proof_endpoints.keys().copied().collect::<BTreeSet<_>>()
                != expected_proofs
            || parent_signer_endpoints.len() != 10
        {
            return Err(ServiceRunnerError::invalid(
                "concrete production composition requires all five services, ten signer authorities, and four proof authorities",
            ));
        }
        for session in sessions.values() {
            session.revalidate_peer()?;
        }
        for endpoint in parent_signer_endpoints
            .iter()
            .chain(proof_endpoints.values())
        {
            endpoint.session.revalidate_peer()?;
        }
        Ok(Self {
            native_proof_owner:None,
            sessions,
            _readiness: readiness,
            parent_signer_endpoints,
            proof_endpoints,
            generation_admission:None,
            commit_request:None,
            spool:None,
        })
    }

    fn parent_signer_endpoint(
        &self,
        role: super::super::super::PolicyShadowCustodySignerRole,
    ) -> Result<&ProductionPinnedEndpointV4, ProductionPrimitiveRejectionV4> {
        self.parent_signer_endpoints
            .iter()
            .find(|endpoint| {
                endpoint.identity
                    == ProductionAuthorityEndpointIdentityV4::ParentSigner(
                        role,
                    )
            })
            .ok_or_else(|| {
                ProductionPrimitiveRejectionV4::rejected(
                    ProductionRpcRejectionCodeV4::RecoveryNotReady,
                    "required production signer endpoint is not authenticated",
                )
            })
    }

    fn enable_native_proofs(&mut self,owner:Arc<native_guest::AdmittedGuest>)->Result<(),ServiceRunnerError> {
        owner.check().map_err(|_|ServiceRunnerError::invalid("native proof owner refused"))?;
        if self.native_proof_owner.is_some() || !owner.proof_bridge_selected()
            || self.proof_endpoints.values().any(|v|!matches!(&v.session,EndpointSession::NativeProof(_))) {
            return Err(ServiceRunnerError::invalid("native proof bridge lacks exact inspected endpoints"));
        }
        self.native_proof_owner=Some(owner);Ok(())
    }
    fn native_persistence_selected(&self)->Result<bool,ProductionPrimitiveRejectionV4> {
        let Some(owner)=&self.native_proof_owner else {return Ok(false);};
        owner.check().map_err(|_|native_time_refused())?;
        self.proof_endpoint(ProductionProofEndpointKindV4::Persistence)?.session.revalidate_peer()
            .map_err(|_|native_time_refused())?;Ok(true)
    }

    fn proof_endpoint(
        &self,
        kind: ProductionProofEndpointKindV4,
    ) -> Result<&ProductionPinnedEndpointV4, ProductionPrimitiveRejectionV4> {
        self.proof_endpoints.get(&kind).ok_or_else(|| {
            ProductionPrimitiveRejectionV4::rejected(
                ProductionRpcRejectionCodeV4::RecoveryNotReady,
                "required production proof endpoint is not authenticated",
            )
        })
    }

    fn call_endpoint(
        &self,
        endpoint: &ProductionPinnedEndpointV4,
        request: ProductionAuthorityEndpointRequestV4,
        rejected_code: ProductionRpcRejectionCodeV4,
    ) -> Result<
        ProductionAuthorityEndpointResultV4,
        ProductionPrimitiveRejectionV4,
    > {
        self.call_endpoint_original(endpoint,request,rejected_code).map(|reply|reply.result)
    }

    fn call_endpoint_original(
        &self,endpoint:&ProductionPinnedEndpointV4,request:ProductionAuthorityEndpointRequestV4,
        rejected_code:ProductionRpcRejectionCodeV4,
    )->Result<ProductionAuthorityEndpointReplyV4,ProductionPrimitiveRejectionV4> {
        endpoint.session.revalidate_peer().map_err(|_| {
            ProductionPrimitiveRejectionV4::rejected(
                ProductionRpcRejectionCodeV4::RecoveryNotReady,
                "production authority endpoint peer identity changed",
            )
        })?;
        require_live_deadline(request.deadline_boottime_nanos).map_err(|_| {
            ProductionPrimitiveRejectionV4::rejected(
                ProductionRpcRejectionCodeV4::DeadlineExpired,
                "production authority endpoint request deadline expired",
            )
        })?;
        if request.api_version
                != PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION
            || request.endpoint != endpoint.identity
            || request.request_sha256 != request.computed_request_sha256()?
        {
            return Err(ProductionPrimitiveRejectionV4::rejected(
                ProductionRpcRejectionCodeV4::InvalidRequest,
                "production authority endpoint request binding is invalid",
            ));
        }
        let exact = encode_canonical_frame(&request).map_err(|_| {
            ProductionPrimitiveRejectionV4::rejected(
                ProductionRpcRejectionCodeV4::InvalidRequest,
                "production authority endpoint request encoding failed",
            )
        })?;
        loop {
            if endpoint.session.send(&exact, request.deadline_boottime_nanos).map_err(|_| {
                ProductionPrimitiveRejectionV4::rejected(
                    ProductionRpcRejectionCodeV4::RecoveryNotReady,
                    "production authority endpoint send failed",
                )
            })? {
                break;
            }
            wait_for_session_fd(
                endpoint.session.progress_fd().as_raw_fd(),
                libc::POLLOUT,
                Some(request.deadline_boottime_nanos),
            )
            .map_err(|_| {
                ProductionPrimitiveRejectionV4::rejected(
                    ProductionRpcRejectionCodeV4::DeadlineExpired,
                    "production authority endpoint send deadline expired",
                )
            })?;
        }
        let packet = loop {
            if let Some(packet) = endpoint.session.receive(request.deadline_boottime_nanos).map_err(|_| {
                ProductionPrimitiveRejectionV4::rejected(
                    ProductionRpcRejectionCodeV4::RecoveryNotReady,
                    "production authority endpoint receive failed",
                )
            })? {
                break packet;
            }
            wait_for_session_fd(
                endpoint.session.progress_fd().as_raw_fd(),
                libc::POLLIN,
                Some(request.deadline_boottime_nanos),
            )
            .map_err(|_| {
                ProductionPrimitiveRejectionV4::rejected(
                    ProductionRpcRejectionCodeV4::DeadlineExpired,
                    "production authority endpoint receive deadline expired",
                )
            })?;
            endpoint.session.revalidate_peer().map_err(|_| {
                ProductionPrimitiveRejectionV4::rejected(
                    ProductionRpcRejectionCodeV4::RecoveryNotReady,
                    "production authority endpoint peer changed while waiting",
                )
            })?;
        };
        let reply: ProductionAuthorityEndpointReplyV4 =
            decode_canonical_frame(&packet.frame).map_err(|_| {
                ProductionPrimitiveRejectionV4::rejected(
                    rejected_code,
                    "production authority endpoint reply is not canonical",
                )
            })?;
        let result_bytes = super::super::super::canonical_json_bytes(
            &reply.result,
        )
        .map_err(|_| {
            ProductionPrimitiveRejectionV4::rejected(
                rejected_code,
                "production authority endpoint result is not canonical",
            )
        })?;
        let observed_at_boottime_nanos =
            require_live_deadline(request.deadline_boottime_nanos).map_err(
                |_| {
                    ProductionPrimitiveRejectionV4::rejected(
                        ProductionRpcRejectionCodeV4::DeadlineExpired,
                        "production authority endpoint reply arrived after its deadline",
                    )
                },
            )?;
        if reply.api_version
                != PRODUCTION_AUTHORITY_ENDPOINT_PROTOCOL_VERSION
            || reply.endpoint != request.endpoint
            || reply.request_sha256 != request.request_sha256
            || reply.replay_id_sha256 != request.replay_id_sha256
            || reply.completed_at_boottime_nanos == 0
            || reply.completed_at_boottime_nanos
                >= request.deadline_boottime_nanos
            || reply.completed_at_boottime_nanos
                > observed_at_boottime_nanos
            || reply.authority_key_id != endpoint.authority_key_id
            || reply.authority_key_spki_sha256
                != endpoint.authority_key_spki_sha256
            || reply.result_sha256
                != super::super::super::hash_domain_frames(
                    PRODUCTION_AUTHORITY_ENDPOINT_RESPONSE_DOMAIN,
                    &[&result_bytes],
                )
            || reply.signature_base64.is_empty()
            || reply.signature_base64.len()
                > MAX_PRODUCTION_ENDPOINT_SIGNATURE_BASE64_BYTES
        {
            return Err(ProductionPrimitiveRejectionV4::rejected(
                rejected_code,
                "production authority endpoint reply changed its exact request, key, deadline, or result",
            ));
        }
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(&reply.signature_base64)
            .map_err(|_| {
                ProductionPrimitiveRejectionV4::rejected(
                    rejected_code,
                    "production authority endpoint signature is not canonical base64url",
                )
            })?;
        if URL_SAFE_NO_PAD.encode(&signature_bytes)
            != reply.signature_base64
        {
            return Err(ProductionPrimitiveRejectionV4::rejected(
                rejected_code,
                "production authority endpoint signature encoding is not canonical",
            ));
        }
        let signature = Signature::from_slice(&signature_bytes).map_err(|_| {
            ProductionPrimitiveRejectionV4::rejected(
                rejected_code,
                "production authority endpoint signature has the wrong size",
            )
        })?;
        let signature_payload = reply.signature_payload()?;
        let signature_preimage = domain_separated_signature_preimage(
            PRODUCTION_AUTHORITY_ENDPOINT_SIGNATURE_DOMAIN,
            &signature_payload,
        )
        .map_err(|_| {
            ProductionPrimitiveRejectionV4::rejected(
                rejected_code,
                "production authority endpoint signature preimage is invalid",
            )
        })?;
        endpoint
            .authority_key
            .verify_strict(&signature_preimage, &signature)
            .map_err(|_| {
                ProductionPrimitiveRejectionV4::rejected(
                    rejected_code,
                    "production authority endpoint response signature is invalid",
                )
            })?;
        if let ProductionAuthorityEndpointResultV4::Rejected(rejection) =
            &reply.result
        {
            if rejection.request_sha256 != request.request_sha256
                || rejection.reason_sha256
                    == super::super::super::Sha256Digest::compute(&[])
            {
                return Err(ProductionPrimitiveRejectionV4::rejected(
                    rejected_code,
                    "production authority endpoint rejection is not bound to the exact request",
                ));
            }
        }
        endpoint.session.after_reply(&packet,request.deadline_boottime_nanos).map_err(|_| {
            ProductionPrimitiveRejectionV4::rejected(
                ProductionRpcRejectionCodeV4::RecoveryNotReady,
                "production authority endpoint peer identity changed after reply",
            )
        })?;
        Ok(reply)
    }

    fn require_all_services_current(
        &self,
    ) -> Result<(), ProductionPrimitiveRejectionV4> {
        for session in self.sessions.values() {
            session.revalidate_peer().map_err(|_| {
                ProductionPrimitiveRejectionV4::rejected(
                    ProductionRpcRejectionCodeV4::RecoveryNotReady,
                    "one authenticated v3 authority session is no longer current",
                )
            })?;
        }
        Ok(())
    }

    fn call_dispatch_endpoint(
        &self,
        request: &ClosedProductionDispatchRequestV4,
    ) -> Result<
        ClosedProductionDispatchResponseV4,
        ProductionPrimitiveRejectionV4,
    > {
        self.require_all_services_current()?;
        if let Some(owner)=&self.generation_admission {
            owner.try_lock().map_err(|_|ProductionPrimitiveRejectionV4::rejected(
                ProductionRpcRejectionCodeV4::RecoveryNotReady,"generation admission is busy"))?
                .require_committed().map_err(|_|ProductionPrimitiveRejectionV4::rejected(
                    ProductionRpcRejectionCodeV4::RecoveryNotReady,"cold generation is not definitely installed"))?;
        }
        request.validate().map_err(|_| {
            ProductionPrimitiveRejectionV4::rejected(
                ProductionRpcRejectionCodeV4::InvalidRequest,
                "production dispatch request is invalid",
            )
        })?;
        let role = production_signer_role(request)?;
        let endpoint = self.parent_signer_endpoint(role)?;
        let mut commitment=if matches!(request,ClosedProductionDispatchRequestV4::CommitRequest{..}) {
            self.commit_request.as_ref().map(|v|v.try_lock()).transpose().map_err(|_|ProductionPrimitiveRejectionV4::rejected(
                ProductionRpcRejectionCodeV4::ArtifactPrimitiveUnavailable,"CommitRequest owner is busy"))?
        } else {None};
        let mut spool=if matches!(request,ClosedProductionDispatchRequestV4::BeginIngress{..}
            |ClosedProductionDispatchRequestV4::ReserveSpoolAppend{..}|ClosedProductionDispatchRequestV4::AppendSpoolEvent{..}
            |ClosedProductionDispatchRequestV4::AppendTerminal{..}|ClosedProductionDispatchRequestV4::AppendActiveEffectBarrier{..}
            |ClosedProductionDispatchRequestV4::CommitActiveEffect{..}|ClosedProductionDispatchRequestV4::ReconcileActiveEffect{..}) {
            self.spool.as_ref().map(|v|v.try_lock()).transpose().map_err(|_|ProductionPrimitiveRejectionV4::rejected(
                ProductionRpcRejectionCodeV4::ArtifactPrimitiveUnavailable,"native spool owner is busy"))?
        }else{None};
        if matches!(request,ClosedProductionDispatchRequestV4::AppendTerminal{..})
            && spool.as_ref().is_some_and(|owner|!owner.completion_selected()) {
            // Old v7 keeps its independently configured legacy terminal path.
            spool=None;
        }
        if super::active_effect_values::selected(request) && spool.as_ref().is_some_and(|owner|!owner.effects_selected()){spool=None;}
        let (wire,reply)=if let Some(owner)=spool.as_mut(){
            owner.run(&self.sessions,request,|identity,body|{
                let target=match identity {
                    ProductionAuthorityEndpointIdentityV4::ParentSigner(role)=>self.parent_signer_endpoint(role),
                    ProductionAuthorityEndpointIdentityV4::Proof(kind)=>self.proof_endpoint(kind),
                }.map_err(|_|super::ledger_spool_values::invalid())?;
                let wire=ProductionAuthorityEndpointRequestV4::new(identity,request.binding().replay_id_sha256.clone(),
                    request.binding().operation_deadline_boottime_nanos,body).map_err(|_|super::ledger_spool_values::invalid())?;
                let reply=self.call_endpoint_original(target,wire.clone(),ProductionRpcRejectionCodeV4::ArtifactPrimitiveUnavailable)
                    .map_err(|_|super::ledger_spool_values::invalid())?;Ok((wire,reply))
            }).map_err(|_|ProductionPrimitiveRejectionV4::rejected(ProductionRpcRejectionCodeV4::ArtifactPrimitiveUnavailable,
                "native spool effect incomplete or uncertain"))?
        }else{
        let body=if let Some(owner)=commitment.as_mut() {
            owner.begin(request).map_err(|_|ProductionPrimitiveRejectionV4::rejected(
                ProductionRpcRejectionCodeV4::ArtifactPrimitiveUnavailable,"CommitRequest contact owner unavailable"))?;
            let prepare=ProductionAuthorityEndpointRequestV4::new(endpoint.identity,request.binding().replay_id_sha256.clone(),
                request.binding().operation_deadline_boottime_nanos,ProductionAuthorityEndpointRequestBodyV4::PrepareCommitRequest{request:request.clone()})?;
            let prepared=self.call_endpoint_original(endpoint,prepare,ProductionRpcRejectionCodeV4::ArtifactPrimitiveUnavailable)?;
            let ProductionAuthorityEndpointResultV4::CommitRequestPrepared(computation)=prepared.result else {
                return Err(ProductionPrimitiveRejectionV4::rejected(ProductionRpcRejectionCodeV4::ArtifactPrimitiveUnavailable,
                    "native HMAC computation original absent"));
            };
            if computation.request!=*request {return Err(ProductionPrimitiveRejectionV4::rejected(
                ProductionRpcRejectionCodeV4::InvalidRequest,"native computation request differs"));}
            let service_transitions=owner.exchange(&self.sessions,computation.clone(),&endpoint.authority_key,&endpoint.authority_key_id)
                .map_err(|_|ProductionPrimitiveRejectionV4::rejected(ProductionRpcRejectionCodeV4::ArtifactPrimitiveUnavailable,
                    "actual CommitRequest service transition incomplete"))?;
            ProductionAuthorityEndpointRequestBodyV4::FinishCommitRequest{computation,service_transitions}
        } else {ProductionAuthorityEndpointRequestBodyV4::Dispatch(request.clone())};
        let wire = ProductionAuthorityEndpointRequestV4::new(
            endpoint.identity,
            request.binding().replay_id_sha256.clone(),
            request.binding().operation_deadline_boottime_nanos,
            body,
        )?;
        let reply=self.call_endpoint_original(
            endpoint,
            wire.clone(),
            ProductionRpcRejectionCodeV4::ArtifactPrimitiveUnavailable,
        )?;
        (wire,reply)
        };
        if self.native_persistence_selected()? && matches!(&reply.result,ProductionAuthorityEndpointResultV4::Dispatch(_)) {
            // Same actual effect original and deadline. No later proof request
            // can trigger this write, renew it, or manufacture the reply.
            let endpoint=self.proof_endpoint(ProductionProofEndpointKindV4::Persistence)?;
            let commit=ProductionAuthorityEndpointRequestV4::new(endpoint.identity,
                request.binding().replay_id_sha256.clone(),request.binding().operation_deadline_boottime_nanos,
                ProductionAuthorityEndpointRequestBodyV4::StoreDispatchOriginal {
                    request_original_base64url:URL_SAFE_NO_PAD.encode(super::super::super::canonical_json_bytes(&wire).map_err(|_| {
                        ProductionPrimitiveRejectionV4::rejected(ProductionRpcRejectionCodeV4::PersistenceProofRejected,"dispatch original encoding failed")})?),
                    reply_original_base64url:URL_SAFE_NO_PAD.encode(super::super::super::canonical_json_bytes(&reply).map_err(|_| {
                        ProductionPrimitiveRejectionV4::rejected(ProductionRpcRejectionCodeV4::PersistenceProofRejected,"dispatch reply encoding failed")})?),
                })?;
            match self.call_endpoint(endpoint,commit,ProductionRpcRejectionCodeV4::PersistenceProofRejected)? {
                ProductionAuthorityEndpointResultV4::PersistenceCommitted{commit_original_sha256}
                    if commit_original_sha256!=super::super::super::Sha256Digest::compute(&[])=>{},
                _=>return Err(ProductionPrimitiveRejectionV4::rejected(ProductionRpcRejectionCodeV4::PersistenceProofRejected,
                    "native persistence commit did not return a definite signed original")),
            }
        }
        match reply.result {
            ProductionAuthorityEndpointResultV4::Dispatch(response) => {
                if let Some(owner)=spool.as_mut(){owner.completed(request,&response).map_err(|_|ProductionPrimitiveRejectionV4::rejected(
                    ProductionRpcRejectionCodeV4::ArtifactPrimitiveUnavailable,"native spool completion differs"))?;}
                if let Some(owner)=commitment.as_mut() {owner.completed(&response).map_err(|_|ProductionPrimitiveRejectionV4::rejected(
                    ProductionRpcRejectionCodeV4::ArtifactPrimitiveUnavailable,"CommitRequest completion differs"))?;}
                Ok(response)
            }
            ProductionAuthorityEndpointResultV4::Rejected(rejection) => {
                Err(ProductionPrimitiveRejectionV4::rejected(
                    rejection.code,
                    "production signer endpoint rejected the exact dispatch",
                ))
            }
            _ => Err(ProductionPrimitiveRejectionV4::rejected(
                ProductionRpcRejectionCodeV4::InvalidRequest,
                "production signer endpoint returned the wrong tagged result",
            )),
        }
    }

    fn call_generation_endpoint(
        &self,
        request: &ClosedProductionGenerationRequestV4,
    ) -> Result<
        ClosedProductionGenerationResponseV4,
        ProductionPrimitiveRejectionV4,
    > {
        self.call_generation_endpoint_inner(request).map_err(|rejection| {
            if self.generation_admission.is_some() && rejection.code==ProductionRpcRejectionCodeV4::RecoveryNotReady {
                ProductionPrimitiveRejectionV4::rejected(ProductionRpcRejectionCodeV4::GenerationConflict,
                    "native generation transport or authority is unavailable; absence was not proved")
            }else{rejection}
        })
    }
    fn call_generation_endpoint_inner(&self,request:&ClosedProductionGenerationRequestV4)
        ->Result<ClosedProductionGenerationResponseV4,ProductionPrimitiveRejectionV4>{
        self.require_all_services_current()?;
        request.request_sha256().map_err(|_| {
            ProductionPrimitiveRejectionV4::rejected(
                ProductionRpcRejectionCodeV4::InvalidRequest,
                "production generation request is invalid",
            )
        })?;
        if let Some(owner)=&self.native_proof_owner {
            owner.require_native_generation(request).map_err(|_|ProductionPrimitiveRejectionV4::rejected(
                ProductionRpcRejectionCodeV4::GenerationConflict,"generation request differs from actual activated native configuration"))?;
        }
        let endpoint = self.proof_endpoint(
            ProductionProofEndpointKindV4::GenerationInstallEnvelope,
        )?;
        let mut admission=self.generation_admission.as_ref().map(|v|v.try_lock())
            .transpose().map_err(|_|ProductionPrimitiveRejectionV4::rejected(
                ProductionRpcRejectionCodeV4::GenerationConflict,"generation admission is busy"))?;
        if admission.is_some() && (self.native_proof_owner.is_none() || !matches!(&endpoint.session,EndpointSession::NativeProof(_))) {
            return Err(ProductionPrimitiveRejectionV4::rejected(ProductionRpcRejectionCodeV4::GenerationConflict,
                "selected generation coordinator lacks the actual inspected native owner"));
        }
        let body=if let Some(owner)=admission.as_mut() {
            let services=owner.exchange(&self.sessions,request).map_err(|_|ProductionPrimitiveRejectionV4::rejected(
                ProductionRpcRejectionCodeV4::GenerationConflict,"service admission is incomplete or outcome unknown"))?;
            ProductionAuthorityEndpointRequestBodyV4::GenerationAdmission{request:request.clone(),services}
        } else {ProductionAuthorityEndpointRequestBodyV4::Generation(request.clone())};
        let wire = ProductionAuthorityEndpointRequestV4::new(
            endpoint.identity,
            request.replay_id_sha256().clone(),
            request.deadline_boottime_nanos(),
            body,
        )?;
        let original=self.call_endpoint_original(endpoint,wire.clone(),ProductionRpcRejectionCodeV4::GenerationConflict)?;
        let result=if let Some(owner)=admission.as_mut() {
            if matches!(&original.result,ProductionAuthorityEndpointResultV4::GenerationProposal(_)) {
                let spki=endpoint.authority_key.to_public_key_der().map_err(|_|ProductionPrimitiveRejectionV4::rejected(
                    ProductionRpcRejectionCodeV4::GenerationConflict,"coordinator public key encoding refused"))?;
                let certification=super::generation_certification::Certify{api_version:super::generation_certification::API.into(),
                    request:wire,reply:original,authority_public_key:super::super::authority_history::AuthorityPublicKeyV3{
                        key_id:endpoint.authority_key_id.clone(),key_spki_sha256:endpoint.authority_key_spki_sha256.clone(),
                        public_key_spki_base64:URL_SAFE_NO_PAD.encode(spki.as_bytes())}};
                let conclusion=owner.certify(&self.sessions,certification).map_err(|_|ProductionPrimitiveRejectionV4::rejected(
                    ProductionRpcRejectionCodeV4::GenerationConflict,"five actual result certifications are incomplete"))?;
                let wire=ProductionAuthorityEndpointRequestV4::new(endpoint.identity,request.replay_id_sha256().clone(),
                    request.deadline_boottime_nanos(),ProductionAuthorityEndpointRequestBodyV4::GenerationConclude(Box::new(conclusion)))?;
                self.call_endpoint(endpoint,wire,ProductionRpcRejectionCodeV4::GenerationConflict)?
            } else {original.result}
        } else {original.result};
        match result {
            ProductionAuthorityEndpointResultV4::Generation(response) => {
                if admission.is_none() && response.api_version==super::generation_recovery::RESPONSE_API {
                    return Err(ProductionPrimitiveRejectionV4::rejected(ProductionRpcRejectionCodeV4::GenerationConflict,
                        "native recovery requires the explicit five-service native profile"));
                }
                if let Some(owner)=admission.as_mut() {
                    owner.completed(request,&response).map_err(|_|ProductionPrimitiveRejectionV4::rejected(
                        ProductionRpcRejectionCodeV4::GenerationConflict,"coordinator did not prove actual complete installation"))?;
                }
                Ok(response)
            }
            ProductionAuthorityEndpointResultV4::Rejected(rejection) => {
                Err(ProductionPrimitiveRejectionV4::rejected(
                    rejection.code,
                    "production generation endpoint rejected the exact transition",
                ))
            }
            _ => Err(ProductionPrimitiveRejectionV4::rejected(
                ProductionRpcRejectionCodeV4::InvalidRequest,
                "production generation endpoint returned the wrong tagged result",
            )),
        }
    }
}

pub(super) fn production_signer_role(
    request: &ClosedProductionDispatchRequestV4,
) -> Result<
    super::super::super::PolicyShadowCustodySignerRole,
    ProductionPrimitiveRejectionV4,
> {
    use super::super::super::PolicyShadowCustodySignerRole as Role;
    let role = match request.operation() {
        PolicyCustodyOperation::RecoverCurrentState
        | PolicyCustodyOperation::VerifyCheckpointSuccessor
        | PolicyCustodyOperation::VerifyCurrentCheckpointHead
        | PolicyCustodyOperation::PrepareGenerationPublication
        | PolicyCustodyOperation::CommitGenerationPublication
        | PolicyCustodyOperation::AbortGenerationPublication => {
            Role::PublicationReconciliation
        }
        PolicyCustodyOperation::BeginIngress => Role::IngressAdmission,
        PolicyCustodyOperation::VerifyObservationEvidence
        | PolicyCustodyOperation::CommitRequest => Role::LedgerAppend,
        PolicyCustodyOperation::ReserveSpoolAppend
        | PolicyCustodyOperation::AppendSpoolEvent => {
            return production_spool_signer_role(request)
        }
        PolicyCustodyOperation::CompactSpool => Role::SpoolCompaction,
        PolicyCustodyOperation::AppendActiveEffectBarrier => {
            Role::ActiveEffectBarrier
        }
        PolicyCustodyOperation::CommitActiveEffect
        | PolicyCustodyOperation::ReconcileActiveEffect => {
            Role::ActiveEffectCommit
        }
        PolicyCustodyOperation::AppendTerminal => Role::TerminalAppend,
        PolicyCustodyOperation::ConsumeAndPublishActivation => {
            Role::ActivationPublication
        }
    };
    Ok(role)
}

fn production_spool_signer_role(
    request: &ClosedProductionDispatchRequestV4,
) -> Result<
    super::super::super::PolicyShadowCustodySignerRole,
    ProductionPrimitiveRejectionV4,
> {
    use super::super::super::PolicyShadowCustodySignerRole as Role;
    let artifact = match request {
        ClosedProductionDispatchRequestV4::ReserveSpoolAppend {
            event,
            ..
        }
        | ClosedProductionDispatchRequestV4::AppendSpoolEvent {
            event,
            ..
        } => event,
        _ => {
            return Err(ProductionPrimitiveRejectionV4::rejected(
                ProductionRpcRejectionCodeV4::InvalidRequest,
                "production spool signer routing received a non-spool request",
            ))
        }
    };
    let exact = artifact.exact_bytes().map_err(|_| {
        ProductionPrimitiveRejectionV4::rejected(
            ProductionRpcRejectionCodeV4::InvalidRequest,
            "production spool event artifact is invalid",
        )
    })?;
    let routing: ProductionShadowSpoolRoutingV4 =
        serde_json::from_slice(&exact).map_err(|_| {
            ProductionPrimitiveRejectionV4::rejected(
                ProductionRpcRejectionCodeV4::InvalidRequest,
                "production spool event phase is unavailable",
            )
        })?;
    Ok(match routing.phase {
        ProductionShadowSpoolPhaseV4::IngressOpen => Role::IngressAdmission,
        ProductionShadowSpoolPhaseV4::DispatchBarrier => {
            Role::DispatchBarrier
        }
        ProductionShadowSpoolPhaseV4::PreDispatchTerminal
        | ProductionShadowSpoolPhaseV4::PostDispatchTerminal => {
            Role::TerminalAppend
        }
        ProductionShadowSpoolPhaseV4::Capture
        | ProductionShadowSpoolPhaseV4::Decision
        | ProductionShadowSpoolPhaseV4::Response
        | ProductionShadowSpoolPhaseV4::Candidate
        | ProductionShadowSpoolPhaseV4::RangeClosure => Role::LedgerAppend,
    })
}

macro_rules! dispatch_primitive {
    ($name:ident) => {
        fn $name(
            &mut self,
            request: &ClosedProductionDispatchRequestV4,
        ) -> Result<
            ClosedProductionDispatchResponseV4,
            ProductionPrimitiveRejectionV4,
        > {
            self.call_dispatch_endpoint(request)
        }
    };
}

fn native_time_refused()->ProductionPrimitiveRejectionV4 {
    ProductionPrimitiveRejectionV4::rejected(ProductionRpcRejectionCodeV4::RecoveryNotReady,
        "native proof owner or original trusted time interval refused")
}
/// Source-private proof that this exact sample passed call_endpoint's
/// signature, request/replay/deadline and actual final peer checks.
pub(super) struct AuthenticatedTimeReply {
    sample:native_guest::trusted_time_sample::Sample,
    operation:super::super::super::Sha256Digest,deadline:u64,
}
impl AuthenticatedTimeReply {
    pub(super) fn consume(self,operation:&super::super::super::Sha256Digest,deadline:u64)
        ->Result<native_guest::trusted_time_sample::Sample,super::super::super::ShadowError> {
        if &self.operation!=operation || self.deadline!=deadline {
            return Err(super::super::super::ShadowError::BindingDrift);
        }
        Ok(self.sample)
    }
}
impl ExistingFiveServiceProductionAuthoritiesV4
    for ConcreteFiveV3ProductionAuthoritiesV4
{
    fn take_native_commitment_original(&mut self,request:&ClosedProductionDispatchRequestV4,
        response:&ClosedProductionDispatchResponseV4)->Result<Option<serde_json::Value>,ProductionPrimitiveRejectionV4>{
        let Some(owner)=&self.commit_request else{return Ok(None);};
        owner.try_lock().map_err(|_|native_time_refused())?.take_completed(request,response)
            .map_err(|_|ProductionPrimitiveRejectionV4::rejected(
                ProductionRpcRejectionCodeV4::ArtifactPrimitiveUnavailable,"native computation original was not retained"))
    }
    fn trusted_time_for_operation(&self,request:&ProductionRpcRequestV4)
        ->Result<Option<native_guest::trusted_time_sample::VerifiedSample>,ProductionPrimitiveRejectionV4> {
        let Some(owner)=&self.native_proof_owner else {return Ok(None);};
        owner.check().map_err(|_|native_time_refused())?;
        let replay=super::super::super::hash_domain_frames(b"serverware.nativeShadowTrustedTimeOperation/v1",
            &[request.replay_id_sha256.as_str().as_bytes(),request.request_sha256.as_str().as_bytes()]);
        let query=ProductionAuthorityEndpointRequestV4::new(
            ProductionAuthorityEndpointIdentityV4::Proof(ProductionProofEndpointKindV4::TrustedTime),replay,
            request.deadline_boottime_nanos,ProductionAuthorityEndpointRequestBodyV4::SampleTrustedTime {
                operation_sha256:request.request_sha256.clone()})?;
        let result=self.call_endpoint(self.proof_endpoint(ProductionProofEndpointKindV4::TrustedTime)?,query,
            ProductionRpcRejectionCodeV4::RecoveryNotReady)?;
        let ProductionAuthorityEndpointResultV4::TrustedTimeInterval(sample)=result else {return Err(native_time_refused());};
        // The raw sample crosses into a capability only after call_endpoint's
        // exact signature and post-reply retained-peer checks above.
        let original=AuthenticatedTimeReply{sample,operation:request.request_sha256.clone(),deadline:request.deadline_boottime_nanos};
        let verified=owner.admit_time_sample(original,&request.request_sha256,request.deadline_boottime_nanos)
            .map_err(|_|native_time_refused())?;
        verified.check().map_err(|_|native_time_refused())?;Ok(Some(verified))
    }
    dispatch_primitive!(recover_current_state);
    dispatch_primitive!(verify_checkpoint_successor);
    dispatch_primitive!(verify_current_checkpoint_head);
    dispatch_primitive!(verify_observation_evidence);
    dispatch_primitive!(prepare_generation_publication);
    dispatch_primitive!(commit_generation_publication);
    dispatch_primitive!(abort_generation_publication);
    dispatch_primitive!(begin_ingress);
    dispatch_primitive!(reserve_spool_append);
    dispatch_primitive!(append_spool_event);
    dispatch_primitive!(compact_spool);
    dispatch_primitive!(commit_request);
    dispatch_primitive!(append_active_effect_barrier);
    dispatch_primitive!(commit_active_effect);
    dispatch_primitive!(reconcile_active_effect);
    dispatch_primitive!(append_terminal);
    dispatch_primitive!(consume_and_publish_activation);

    fn recover_generation(
        &mut self,
        request: &ClosedProductionGenerationRequestV4,
    ) -> Result<ClosedProductionGenerationResponseV4, ProductionPrimitiveRejectionV4> {
        self.call_generation_endpoint(request)
    }

    fn prepare_generation(
        &mut self,
        request: &ClosedProductionGenerationRequestV4,
    ) -> Result<ClosedProductionGenerationResponseV4, ProductionPrimitiveRejectionV4> {
        self.call_generation_endpoint(request)
    }

    fn commit_generation(
        &mut self,
        request: &ClosedProductionGenerationRequestV4,
    ) -> Result<ClosedProductionGenerationResponseV4, ProductionPrimitiveRejectionV4> {
        self.call_generation_endpoint(request)
    }

    fn abort_generation(
        &mut self,
        request: &ClosedProductionGenerationRequestV4,
    ) -> Result<ClosedProductionGenerationResponseV4, ProductionPrimitiveRejectionV4> {
        self.call_generation_endpoint(request)
    }

    fn request_termination(
        &mut self,
        request: &ProductionRpcRequestV4,
    ) -> Result<(), ProductionPrimitiveRejectionV4> {
        self.require_all_services_current()?;
        let endpoint = self.proof_endpoint(
            ProductionProofEndpointKindV4::GenerationInstallEnvelope,
        )?;
        let wire = ProductionAuthorityEndpointRequestV4::new(
            endpoint.identity,
            request.replay_id_sha256.clone(),
            request.deadline_boottime_nanos,
            ProductionAuthorityEndpointRequestBodyV4::RequestTermination {
                request: request.clone(),
            },
        )?;
        match self.call_endpoint(
            endpoint,
            wire,
            ProductionRpcRejectionCodeV4::CleanupUnauthorized,
        )? {
            ProductionAuthorityEndpointResultV4::TerminationRequested => {
                Ok(())
            }
            ProductionAuthorityEndpointResultV4::Rejected(rejection) => {
                Err(ProductionPrimitiveRejectionV4::rejected(
                    rejection.code,
                    "production cleanup authority rejected termination",
                ))
            }
            _ => Err(ProductionPrimitiveRejectionV4::rejected(
                ProductionRpcRejectionCodeV4::InvalidRequest,
                "production cleanup authority returned the wrong tagged termination result",
            )),
        }
    }

    fn settle_cleanup(
        &mut self,
        request: &ProductionRpcRequestV4,
    ) -> Result<CanonicalProductionArtifactV4, ProductionPrimitiveRejectionV4> {
        self.require_all_services_current()?;
        let endpoint = self.proof_endpoint(
            ProductionProofEndpointKindV4::GenerationInstallEnvelope,
        )?;
        let wire = ProductionAuthorityEndpointRequestV4::new(
            endpoint.identity,
            request.replay_id_sha256.clone(),
            request.deadline_boottime_nanos,
            ProductionAuthorityEndpointRequestBodyV4::Settle {
                request: request.clone(),
            },
        )?;
        match self.call_endpoint(
            endpoint,
            wire,
            ProductionRpcRejectionCodeV4::CleanupUnauthorized,
        )? {
            ProductionAuthorityEndpointResultV4::Settlement(artifact) => {
                Ok(artifact)
            }
            ProductionAuthorityEndpointResultV4::Rejected(rejection) => {
                Err(ProductionPrimitiveRejectionV4::rejected(
                    rejection.code,
                    "production cleanup authority rejected settlement",
                ))
            }
            _ => Err(ProductionPrimitiveRejectionV4::rejected(
                ProductionRpcRejectionCodeV4::InvalidRequest,
                "production cleanup authority returned the wrong tagged settlement result",
            )),
        }
    }

    fn verify_persistence(
        &mut self,
        request: &ProductionRpcRequestV4,
    ) -> Result<(), ProductionPrimitiveRejectionV4> {
        call_verified_proof_endpoint(
            self,
            ProductionProofEndpointKindV4::Persistence,
            request,
            ProductionRpcRejectionCodeV4::PersistenceProofRejected,
        )
    }

    fn verify_retrieval(
        &mut self,
        request: &ProductionRpcRequestV4,
    ) -> Result<(), ProductionPrimitiveRejectionV4> {
        call_verified_proof_endpoint(
            self,
            ProductionProofEndpointKindV4::Retrieval,
            request,
            ProductionRpcRejectionCodeV4::RetrievalProofRejected,
        )
    }
}

fn call_verified_proof_endpoint(
    authority: &ConcreteFiveV3ProductionAuthoritiesV4,
    kind: ProductionProofEndpointKindV4,
    request: &ProductionRpcRequestV4,
    rejected_code: ProductionRpcRejectionCodeV4,
) -> Result<(), ProductionPrimitiveRejectionV4> {
    authority.require_all_services_current()?;
    let endpoint = authority.proof_endpoint(kind)?;
    let wire = ProductionAuthorityEndpointRequestV4::new(
        endpoint.identity,
        request.replay_id_sha256.clone(),
        request.deadline_boottime_nanos,
        ProductionAuthorityEndpointRequestBodyV4::VerifyProof {
            request: request.clone(),
        },
    )?;
    match authority.call_endpoint(endpoint, wire, rejected_code)? {
        ProductionAuthorityEndpointResultV4::Verified => Ok(()),
        ProductionAuthorityEndpointResultV4::Rejected(rejection) => {
            Err(ProductionPrimitiveRejectionV4::rejected(
                rejection.code,
                "production proof authority rejected the exact proof",
            ))
        }
        _ => Err(ProductionPrimitiveRejectionV4::rejected(
            ProductionRpcRejectionCodeV4::InvalidRequest,
            "production proof authority returned the wrong tagged result",
        )),
    }
}

pub(super) struct ProductionServiceHistoricalKeyringsV4 {
    pub(super) durable_recovery_store: RuntimeAuthorityHistory,
    pub(super) cleanup_authorization_consumer: RuntimeAuthorityHistory,
    pub(super) recovery_target_provider: RuntimeAuthorityHistory,
    pub(super) current_signature_authority: RuntimeAuthorityHistory,
    pub(super) bounded_cleanup_helper: RuntimeAuthorityHistory,
}

impl ProductionServiceHistoricalKeyringsV4 {
    pub(super) fn new(
        durable_recovery_store: RuntimeAuthorityHistory,
        cleanup_authorization_consumer: RuntimeAuthorityHistory,
        recovery_target_provider: RuntimeAuthorityHistory,
        current_signature_authority: RuntimeAuthorityHistory,
        bounded_cleanup_helper: RuntimeAuthorityHistory,
    ) -> Result<Self, ServiceRunnerError> {
        let histories = Self {
            durable_recovery_store,
            cleanup_authorization_consumer,
            recovery_target_provider,
            current_signature_authority,
            bounded_cleanup_helper,
        };
        histories.validate_roles()?;
        Ok(histories)
    }

    pub(super) fn borrowed(&self) -> FiveServiceHistoricalKeyringsV4<'_> {
        FiveServiceHistoricalKeyringsV4 {
            durable_recovery_store: &self.durable_recovery_store,
            cleanup_authorization_consumer:
                &self.cleanup_authorization_consumer,
            recovery_target_provider: &self.recovery_target_provider,
            current_signature_authority:
                &self.current_signature_authority,
            bounded_cleanup_helper: &self.bounded_cleanup_helper,
        }
    }

    fn validate_roles(&self) -> Result<(), ServiceRunnerError> {
        for (role, history) in [
            (
                HistoricalServiceRoleV3::DurableRecoveryStore,
                &self.durable_recovery_store,
            ),
            (
                HistoricalServiceRoleV3::CleanupAuthorizationConsumer,
                &self.cleanup_authorization_consumer,
            ),
            (
                HistoricalServiceRoleV3::RecoveryTargetProvider,
                &self.recovery_target_provider,
            ),
            (
                HistoricalServiceRoleV3::CurrentSignatureAuthority,
                &self.current_signature_authority,
            ),
            (
                HistoricalServiceRoleV3::BoundedCleanupHelper,
                &self.bounded_cleanup_helper,
            ),
        ] {
            if history.manifest().authority_role
                != super::super::authority_history::
                    HistoricalAuthorityRoleV3::IsolatedService(role)
            {
                return Err(ServiceRunnerError::invalid(
                    "production RPC historical keyring is bound to the wrong service role",
                ));
            }
        }
        Ok(())
    }
}

struct ReplayedProductionResponse {
    exact_request: Vec<u8>,
    exact_response: Vec<u8>,
}

pub(super) struct ProductionRpcServiceBridgeV4<A>
where
    A: ExistingFiveServiceProductionAuthoritiesV4,
{
    authority: A,
    histories: ProductionServiceHistoricalKeyringsV4,
    journal: DurableAppendJournal,
    replay: BTreeMap<String, ReplayedProductionResponse>,
    durable_requests: BTreeMap<String, Vec<u8>>,
    durable_responses: BTreeMap<String, Vec<u8>>,
    replay_bytes: usize,
    recovery_ready: bool,
}

impl<A> ProductionRpcServiceBridgeV4<A>
where
    A: ExistingFiveServiceProductionAuthoritiesV4,
{
    pub(super) fn recover(
        authority: A,
        histories: ProductionServiceHistoricalKeyringsV4,
        journal_directory: OwnedFd,
    ) -> Result<Self, ServiceRunnerError> {
        histories.validate_roles()?;
        let mut journal = DurableAppendJournal::from_directory(
            journal_directory,
            TrustedHostServiceRoleV3::DurableRecoveryStore,
            MAX_SERVICE_FRAME_BYTES,
        )?;
        let chain = journal.verified_complete_chain(
            MAX_PRODUCTION_RPC_REPLAY_RECORDS,
            MAX_PRODUCTION_RPC_REPLAY_BYTES,
        )?;
        let mut replay = BTreeMap::new();
        let mut durable_requests = BTreeMap::new();
        let mut durable_responses = BTreeMap::new();
        let mut replay_bytes = 0_usize;
        for record in chain.records {
            let request: ProductionRpcRequestV4 =
                decode_canonical_frame(&record.exact_request_bytes)?;
            let response: ProductionRpcResponseV4 =
                decode_canonical_frame(&record.exact_response_bytes)?;
            request.validate().map_err(ServiceRunnerError::invalid)?;
            response
                .validate_for_request(&request)
                .map_err(ServiceRunnerError::invalid)?;
            validate_authority_response(
                &histories.borrowed(),
                &request,
                &response,
            )?;
            let record_bytes = record
                .exact_request_bytes
                .len()
                .checked_add(record.exact_response_bytes.len())
                .ok_or_else(|| {
                    ServiceRunnerError::invalid(
                        "production RPC recovered replay bytes overflowed",
                    )
            })?;
            let key = request.replay_id_sha256.as_str().to_owned();
            if durable_requests
                .insert(key.clone(), record.exact_request_bytes.clone())
                .is_some()
                || durable_responses
                    .insert(
                        key.clone(),
                        record.exact_response_bytes.clone(),
                    )
                    .is_some()
            {
                return Err(ServiceRunnerError::invalid(
                    "production RPC recovery contains a duplicate replay identity",
                ));
            }
            if matches!(
                response.response,
                ProductionRpcResponseBodyV4::Dispatch(_)
                    | ProductionRpcResponseBodyV4::NativeCommitRequest{..}
                    | ProductionRpcResponseBodyV4::Generation(_)
            ) {
                replay.insert(
                    key,
                    ReplayedProductionResponse {
                        exact_request: record.exact_request_bytes,
                        exact_response: record.exact_response_bytes,
                    },
                );
            }
            replay_bytes = replay_bytes
                .checked_add(record_bytes)
                .ok_or_else(|| {
                    ServiceRunnerError::invalid(
                        "production RPC recovered replay bytes overflowed",
                    )
                })?;
            if replay_bytes > MAX_PRODUCTION_RPC_REPLAY_BYTES {
                return Err(ServiceRunnerError::invalid(
                    "production RPC recovered replay bytes exceed the fixed bound",
                ));
            }
        }
        Ok(Self {
            authority,
            histories,
            journal,
            replay,
            durable_requests,
            durable_responses,
            replay_bytes,
            recovery_ready: true,
        })
    }

    pub(super) fn recovery_ready(&self) -> bool {
        self.recovery_ready
    }

    fn handle_exact_request(
        &mut self,
        exact_request: &[u8],
    ) -> Result<Vec<u8>, ServiceRunnerError> {
        if !self.recovery_ready {
            return Err(ServiceRunnerError::invalid(
                "production RPC service has not completed durable recovery",
            ));
        }
        let request: ProductionRpcRequestV4 =
            decode_canonical_frame(exact_request)?;
        request.validate().map_err(ServiceRunnerError::invalid)?;
        require_live_deadline(request.deadline_boottime_nanos)?;
        let replay_key = request.replay_id_sha256.as_str().to_owned();
        if let Some(replayed) = self.replay.get(&replay_key) {
            if replayed.exact_request != exact_request {
                return Err(ServiceRunnerError::invalid(
                    "production RPC replay identity was reused for different exact request bytes",
                ));
            }
            return Ok(replayed.exact_response.clone());
        }
        let was_durable = self.durable_requests.contains_key(&replay_key);
        if self.durable_requests.get(&replay_key).is_some_and(
            |durable| durable.as_slice() != exact_request,
        ) {
            return Err(ServiceRunnerError::invalid(
                "production RPC durable replay identity was reused for different exact request bytes",
            ));
        }
        let reserved_replay_bytes = if was_durable {
            self.replay_bytes
        } else {
            self.replay_bytes
                .checked_add(exact_request.len())
                .and_then(|bytes| {
                    bytes.checked_add(MAX_SERVICE_FRAME_BYTES)
                })
                .ok_or_else(|| {
                    ServiceRunnerError::invalid(
                        "production RPC replay capacity overflowed",
                    )
                })?
        };
        if (self.durable_requests.len()
            >= MAX_PRODUCTION_RPC_REPLAY_RECORDS
            && !self.durable_requests.contains_key(&replay_key))
            || reserved_replay_bytes > MAX_PRODUCTION_RPC_REPLAY_BYTES
        {
            return Err(ServiceRunnerError::invalid(
                "production RPC durable replay capacity is exhausted",
            ));
        }

        let time_sample=self.authority.trusted_time_for_operation(&request)
            .map_err(|_|ServiceRunnerError::invalid("original trusted time interval refused operation"))?;
        let response_body = match self.dispatch_to_authority(&request) {
            Ok(response) => response,
            Err(rejection) => ProductionRpcResponseBodyV4::Rejected(
                ProductionRpcRejectionV4::new(
                    rejection.code,
                    request.request_sha256.clone(),
                    rejection.reason,
                ),
            ),
        };
        if let Some(sample)=&time_sample {
            sample.check().map_err(|_|ServiceRunnerError::invalid("original trusted time interval expired during operation"))?;
        }
        let completed_at_boottime_nanos =
            require_live_deadline(request.deadline_boottime_nanos)?;
        let mut response = ProductionRpcResponseV4 {
            api_version: PRODUCTION_RPC_PROTOCOL_VERSION.to_owned(),
            request_id_sha256: request.request_id_sha256.clone(),
            request_sha256: request.request_sha256.clone(),
            replay_id_sha256: request.replay_id_sha256.clone(),
            completed_at_boottime_nanos,
            response: response_body,
            response_sha256: super::super::super::Sha256Digest::compute(
                &[],
            ),
        };
        response.response_sha256 = response
            .computed_response_sha256()
            .map_err(ServiceRunnerError::invalid)?;
        response
            .validate_for_request(&request)
            .map_err(ServiceRunnerError::invalid)?;
        validate_authority_response(
            &self.histories.borrowed(),
            &request,
            &response,
        )?;
        if was_durable {
            let durable_response = self
                .durable_responses
                .get(&replay_key)
                .ok_or_else(|| {
                    ServiceRunnerError::invalid(
                        "production RPC durable response is missing",
                    )
                })?;
            let prior: ProductionRpcResponseV4 =
                decode_canonical_frame(durable_response)?;
            if prior.response != response.response {
                return Err(ServiceRunnerError::invalid(
                    "production RPC live authority recertification differs from the durable response body",
                ));
            }
            self.replay.insert(
                replay_key,
                ReplayedProductionResponse {
                    exact_request: exact_request.to_vec(),
                    exact_response: durable_response.clone(),
                },
            );
            return Ok(durable_response.clone());
        }
        let exact_response = encode_canonical_frame(&response)?;
        let persisted = self.journal.append_exact_exchange(
            request.replay_id_sha256.clone(),
            exact_request,
            &exact_response,
        )?;
        if persisted.exact_response_bytes() != exact_response {
            return Err(ServiceRunnerError::invalid(
                "production RPC journal replay differs from the newly validated response",
            ));
        }
        if !was_durable {
            self.replay_bytes = self
                .replay_bytes
                .checked_add(exact_request.len())
                .and_then(|bytes| {
                    bytes.checked_add(exact_response.len())
                })
                .ok_or_else(|| {
                    ServiceRunnerError::invalid(
                        "production RPC replay byte accounting overflowed",
                    )
                })?;
        }
        self.durable_requests
            .entry(replay_key.clone())
            .or_insert_with(|| exact_request.to_vec());
        self.durable_responses
            .entry(replay_key.clone())
            .or_insert_with(|| exact_response.clone());
        self.replay.insert(
            replay_key,
            ReplayedProductionResponse {
                exact_request: exact_request.to_vec(),
                exact_response: exact_response.clone(),
            },
        );
        Ok(exact_response)
    }

    fn dispatch_to_authority(
        &mut self,
        request: &ProductionRpcRequestV4,
    ) -> Result<ProductionRpcResponseBodyV4, ProductionPrimitiveRejectionV4>
    {
        match &request.request {
            ProductionRpcRequestBodyV4::Dispatch(dispatch) => {
                let response = match dispatch {
                    ClosedProductionDispatchRequestV4::RecoverCurrentState { .. } =>
                        self.authority.recover_current_state(dispatch),
                    ClosedProductionDispatchRequestV4::VerifyCheckpointSuccessor { .. } =>
                        self.authority.verify_checkpoint_successor(dispatch),
                    ClosedProductionDispatchRequestV4::VerifyCurrentCheckpointHead { .. } =>
                        self.authority.verify_current_checkpoint_head(dispatch),
                    ClosedProductionDispatchRequestV4::VerifyObservationEvidence { .. } =>
                        self.authority.verify_observation_evidence(dispatch),
                    ClosedProductionDispatchRequestV4::PrepareGenerationPublication { .. } =>
                        self.authority.prepare_generation_publication(dispatch),
                    ClosedProductionDispatchRequestV4::CommitGenerationPublication { .. } =>
                        self.authority.commit_generation_publication(dispatch),
                    ClosedProductionDispatchRequestV4::AbortGenerationPublication { .. } =>
                        self.authority.abort_generation_publication(dispatch),
                    ClosedProductionDispatchRequestV4::BeginIngress { .. } =>
                        self.authority.begin_ingress(dispatch),
                    ClosedProductionDispatchRequestV4::ReserveSpoolAppend { .. } =>
                        self.authority.reserve_spool_append(dispatch),
                    ClosedProductionDispatchRequestV4::AppendSpoolEvent { .. } =>
                        self.authority.append_spool_event(dispatch),
                    ClosedProductionDispatchRequestV4::CompactSpool { .. } =>
                        self.authority.compact_spool(dispatch),
                    ClosedProductionDispatchRequestV4::CommitRequest { .. } =>
                        self.authority.commit_request(dispatch),
                    ClosedProductionDispatchRequestV4::AppendActiveEffectBarrier { .. } =>
                        self.authority.append_active_effect_barrier(dispatch),
                    ClosedProductionDispatchRequestV4::CommitActiveEffect { .. } =>
                        self.authority.commit_active_effect(dispatch),
                    ClosedProductionDispatchRequestV4::ReconcileActiveEffect { .. } =>
                        self.authority.reconcile_active_effect(dispatch),
                    ClosedProductionDispatchRequestV4::AppendTerminal { .. } =>
                        self.authority.append_terminal(dispatch),
                    ClosedProductionDispatchRequestV4::ConsumeAndPublishActivation { .. } =>
                        self.authority.consume_and_publish_activation(dispatch),
                }?;
                if matches!(dispatch,ClosedProductionDispatchRequestV4::CommitRequest{..}) {
                    if let Some(computation)=self.authority.take_native_commitment_original(dispatch,&response)? {
                        return Ok(ProductionRpcResponseBodyV4::NativeCommitRequest{dispatch:response,computation});
                    }
                }
                Ok(ProductionRpcResponseBodyV4::Dispatch(response))
            }
            ProductionRpcRequestBodyV4::Generation(generation) => {
                let response = match generation {
                    ClosedProductionGenerationRequestV4::Recover { .. } =>
                        self.authority.recover_generation(generation),
                    ClosedProductionGenerationRequestV4::Prepare { .. } =>
                        self.authority.prepare_generation(generation),
                    ClosedProductionGenerationRequestV4::Commit { .. } =>
                        self.authority.commit_generation(generation),
                    ClosedProductionGenerationRequestV4::Abort { .. } =>
                        self.authority.abort_generation(generation),
                }?;
                Ok(ProductionRpcResponseBodyV4::Generation(response))
            }
            ProductionRpcRequestBodyV4::RequestTermination { .. } => {
                self.authority.request_termination(request)?;
                Ok(ProductionRpcResponseBodyV4::TerminationRequested)
            }
            ProductionRpcRequestBodyV4::Settle { .. } => {
                self.authority
                    .settle_cleanup(request)
                    .map(ProductionRpcResponseBodyV4::Settlement)
            }
            ProductionRpcRequestBodyV4::VerifyPersistence { .. }
            | ProductionRpcRequestBodyV4::VerifyAssignmentBoundPersistence { .. } => {
                self.authority.verify_persistence(request)?;
                Ok(ProductionRpcResponseBodyV4::Verified)
            }
            ProductionRpcRequestBodyV4::VerifyRetrieval { .. }
            | ProductionRpcRequestBodyV4::VerifyAssignmentBoundRetrieval { .. } => {
                self.authority.verify_retrieval(request)?;
                Ok(ProductionRpcResponseBodyV4::Verified)
            }
        }
    }
}

fn validate_authority_response(
    histories: &FiveServiceHistoricalKeyringsV4<'_>,
    request: &ProductionRpcRequestV4,
    response: &ProductionRpcResponseV4,
) -> Result<(), ServiceRunnerError> {
    match (&request.request, &response.response) {
        (
            ProductionRpcRequestBodyV4::Dispatch(request),
            ProductionRpcResponseBodyV4::Dispatch(response),
        ) => response
            .validate(request, histories)
            .map_err(ServiceRunnerError::invalid),
        (
            ProductionRpcRequestBodyV4::Dispatch(request @ ClosedProductionDispatchRequestV4::CommitRequest{..}),
            ProductionRpcResponseBodyV4::NativeCommitRequest{dispatch,computation},
        ) => {
            dispatch.validate(request,histories).map_err(ServiceRunnerError::invalid)?;
            let original:super::dispatch_commitment::Computation=
                decode_canonical_frame(&encode_canonical_frame(computation)?)?;
            if original.request!=*request || original.result!=dispatch.result || original.result_sha256!=dispatch.result_sha256 {
                return Err(ServiceRunnerError::invalid("native computation differs from completed dispatch"));
            }
            Ok(())
        },
        (
            ProductionRpcRequestBodyV4::Generation(request),
            ProductionRpcResponseBodyV4::Generation(response),
        ) => response
            .validate(request, histories)
            .map_err(ServiceRunnerError::invalid),
        (
            ProductionRpcRequestBodyV4::RequestTermination { .. },
            ProductionRpcResponseBodyV4::TerminationRequested,
        )
        | (
            ProductionRpcRequestBodyV4::VerifyPersistence { .. },
            ProductionRpcResponseBodyV4::Verified,
        )
        | (
            ProductionRpcRequestBodyV4::VerifyRetrieval { .. },
            ProductionRpcResponseBodyV4::Verified,
        )
        | (
            ProductionRpcRequestBodyV4::VerifyAssignmentBoundPersistence { .. },
            ProductionRpcResponseBodyV4::Verified,
        )
        | (
            ProductionRpcRequestBodyV4::VerifyAssignmentBoundRetrieval { .. },
            ProductionRpcResponseBodyV4::Verified,
        )
        | (_, ProductionRpcResponseBodyV4::Rejected(_)) => Ok(()),
        (
            ProductionRpcRequestBodyV4::Settle { .. },
            ProductionRpcResponseBodyV4::Settlement(artifact),
        ) if artifact.kind
            == super::super::production_dispatch::
                ProductionArtifactKindV4::TerminalCleanupAttestation => {
            artifact
                .exact_bytes()
                .map(|_| ())
                .map_err(ServiceRunnerError::invalid)
        }
        _ => Err(ServiceRunnerError::invalid(
            "production RPC response variant does not match its exact request",
        )),
    }
}

struct ProductionRpcJob {
    exact_request: Vec<u8>,
    completion: SyncSender<Result<Vec<u8>, ServiceRunnerError>>,
}

/// Runs exactly four authenticated sessions over a fixed queue and fixed
/// worker set. Every receive and send revalidates UID/GID/PID, pidfd/start
/// time, executable identity and hash, cgroup identity, process identity,
/// security label, and configuration generation through the retained session.
pub(super) fn run_production_rpc_service<A>(
    sessions: Vec<AuthenticatedInheritedSeqpacket>,
    bridge: ProductionRpcServiceBridgeV4<A>,
) -> Result<(), ServiceRunnerError>
where
    A: ExistingFiveServiceProductionAuthoritiesV4 + 'static,
{
    run_production_rpc_service_scoped(sessions, bridge, super::Bootstrap::Host)
}

fn run_production_rpc_service_scoped<A>(
    sessions: Vec<AuthenticatedInheritedSeqpacket>,
    bridge: ProductionRpcServiceBridgeV4<A>,
    bootstrap: super::Bootstrap,
) -> Result<(), ServiceRunnerError>
where
    A: ExistingFiveServiceProductionAuthoritiesV4 + 'static,
{
    bootstrap.check()?;
    if sessions.len() != PRODUCTION_RPC_SESSION_COUNT
        || !bridge.recovery_ready()
    {
        return Err(ServiceRunnerError::invalid(
            "production RPC runner requires exactly four authenticated sessions and completed durable recovery",
        ));
    }
    let bridge = Arc::new(Mutex::new(bridge));
    let (sender, receiver) =
        sync_channel::<ProductionRpcJob>(PRODUCTION_RPC_QUEUE_DEPTH);
    let receiver = Arc::new(Mutex::new(receiver));
    let mut workers = Vec::with_capacity(PRODUCTION_RPC_WORKER_COUNT);
    for ordinal in 0..PRODUCTION_RPC_WORKER_COUNT {
        let bridge = Arc::clone(&bridge);
        let receiver = Arc::clone(&receiver);
        let bootstrap = bootstrap.clone();
        workers.push(
            thread::Builder::new()
                .name(format!("policy-custody-production-worker-{ordinal}"))
                .spawn(move || production_worker(bridge, receiver, bootstrap))
                .map_err(|_| {
                    ServiceRunnerError::invalid(
                        "production RPC worker could not be created",
                    )
                })?,
        );
    }
    let mut session_threads = Vec::with_capacity(sessions.len());
    for (ordinal, session) in sessions.into_iter().enumerate() {
        let sender = sender.clone();
        let bootstrap = bootstrap.clone();
        session_threads.push(
            thread::Builder::new()
                .name(format!("policy-custody-production-session-{ordinal}"))
                .spawn(move || serve_session(session, sender, bootstrap))
                .map_err(|_| {
                    ServiceRunnerError::invalid(
                        "production RPC session could not be created",
                    )
                })?,
        );
    }
    drop(sender);
    for session in session_threads {
        session.join().map_err(|_| {
            ServiceRunnerError::invalid(
                "production RPC session panicked",
            )
        })??;
    }
    for worker in workers {
        worker.join().map_err(|_| {
            ServiceRunnerError::invalid(
                "production RPC worker panicked",
            )
        })??;
    }
    Ok(())
}

fn production_worker<A>(
    bridge: Arc<Mutex<ProductionRpcServiceBridgeV4<A>>>,
    receiver: Arc<Mutex<Receiver<ProductionRpcJob>>>,
    bootstrap: super::Bootstrap,
) -> Result<(), ServiceRunnerError>
where
    A: ExistingFiveServiceProductionAuthoritiesV4,
{
    loop {
        let job = match receiver.lock() {
            Ok(receiver) => receiver.recv(),
            Err(_) => {
                return Err(ServiceRunnerError::invalid(
                    "production RPC queue lock is poisoned",
                ))
            }
        };
        let Ok(job) = job else { return Ok(()) };
        bootstrap.check()?;
        let request: ProductionRpcRequestV4 = decode_canonical_frame(&job.exact_request)?;
        bootstrap.require_deadline(request.deadline_boottime_nanos)?;
        let result = match bridge.lock() {
            Ok(mut bridge) => bridge.handle_exact_request(&job.exact_request),
            Err(_) => Err(ServiceRunnerError::invalid(
                "production RPC bridge lock is poisoned",
            )),
        };
        let _ = job.completion.send(result);
    }
}

fn serve_session(
    session: AuthenticatedInheritedSeqpacket,
    sender: SyncSender<ProductionRpcJob>,
    bootstrap: super::Bootstrap,
) -> Result<(), ServiceRunnerError> {
    loop {
        let packet = loop {
            bootstrap.check()?;
            if let Some(packet) = session.try_receive(0)? {
                break packet;
            }
            wait_for_session_fd(
                session.progress_fd().as_raw_fd(),
                libc::POLLIN,
                bootstrap.receive_deadline(),
            )?;
        };
        session.revalidate_peer()?;
        let request: ProductionRpcRequestV4 =
            decode_canonical_frame(&packet.frame)?;
        request.validate().map_err(ServiceRunnerError::invalid)?;
        bootstrap.require_deadline(request.deadline_boottime_nanos)?;
        require_live_deadline(request.deadline_boottime_nanos)?;
        let (completion, completed) = sync_channel(1);
        match sender.try_send(ProductionRpcJob {
            exact_request: packet.frame,
            completion,
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                return Err(ServiceRunnerError::invalid(
                    "production RPC fixed work queue is full",
                ))
            }
            Err(TrySendError::Disconnected(_)) => {
                return Err(ServiceRunnerError::invalid(
                    "production RPC fixed work queue is unavailable",
                ))
            }
        }
        let exact_response = loop {
            bootstrap.check()?;
            match completed.try_recv() {
                Ok(result) => break result?,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    return Err(ServiceRunnerError::invalid(
                        "production RPC worker disconnected",
                    ))
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    wait_for_session_fd(
                        session.progress_fd().as_raw_fd(),
                        0,
                        Some(request.deadline_boottime_nanos),
                    )?;
                }
            }
        };
        loop {
            bootstrap.check()?;
            if session.try_send(&exact_response, &[], 0)? {
                break;
            }
            wait_for_session_fd(
                session.progress_fd().as_raw_fd(),
                libc::POLLOUT,
                Some(request.deadline_boottime_nanos),
            )?;
        }
        session.revalidate_peer()?;
    }
}

fn require_live_deadline(
    deadline_boottime_nanos: u64,
) -> Result<u64, ServiceRunnerError> {
    let now = boottime_now_nanos().map_err(|error| {
        ServiceRunnerError::invalid(error.to_string())
    })?;
    if deadline_boottime_nanos == 0 || now >= deadline_boottime_nanos {
        return Err(ServiceRunnerError::invalid(
            "production RPC crossed its absolute CLOCK_BOOTTIME deadline",
        ));
    }
    Ok(now)
}

fn wait_for_session_fd(
    fd: i32,
    events: i16,
    deadline: Option<u64>,
) -> Result<(), ServiceRunnerError> {
    let timeout = if let Some(deadline) = deadline {
        let now = require_live_deadline(deadline)?;
        i32::try_from(
            deadline
                .saturating_sub(now)
                .saturating_add(999_999)
                / 1_000_000,
        )
        .unwrap_or(i32::MAX)
        .min(PRODUCTION_RPC_POLL_SLICE_MILLIS)
        .max(1)
    } else {
        PRODUCTION_RPC_POLL_SLICE_MILLIS
    };
    if events == 0 {
        thread::park_timeout(std::time::Duration::from_millis(
            u64::try_from(timeout).unwrap_or(1),
        ));
        return Ok(());
    }
    let mut descriptor = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    loop {
        let ready = unsafe { libc::poll(&mut descriptor, 1, timeout) };
        if ready > 0
            && descriptor.revents
                & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)
                == 0
            && descriptor.revents & events != 0
        {
            return Ok(());
        }
        if ready == 0 {
            return Ok(());
        }
        if ready < 0
            && std::io::Error::last_os_error().raw_os_error()
                == Some(libc::EINTR)
        {
            continue;
        }
        return Err(ServiceRunnerError::invalid(
            "production RPC session poll failed closed",
        ));
    }
}

pub(super) fn authenticate_production_rpc_session(
    socket: OwnedFd,
    expected_peer: ExpectedPeerCredentials,
) -> Result<AuthenticatedInheritedSeqpacket, ServiceRunnerError> {
    AuthenticatedInheritedSeqpacket::from_inherited(socket, expected_peer)
        .map_err(Into::into)
}

pub(in crate::policy_shadow::policy_custody) fn run_production_rpc_service_from_env(
) -> Result<(), ServiceRunnerError> {
    super::close_unlisted_ambient_descriptors()?;
    let loaded: super::LoadedConfig<ProductionRpcRuntimeConfigV4> =
        super::load_config(PRODUCTION_RPC_CONFIG_CREDENTIAL)?;
    let activation = super::take_activation_fds()?;
    run_production_rpc_service_loaded(loaded, super::Bootstrap::Host, activation)
}

pub(super) fn run_production_rpc_service_loaded(
    loaded: super::LoadedConfig<ProductionRpcRuntimeConfigV4>,
    bootstrap: super::Bootstrap,
    activation: BTreeMap<String, OwnedFd>,
) -> Result<(), ServiceRunnerError> {
    run_production_rpc_service_loaded_inner(loaded,bootstrap,activation,None,None)
}

pub(super) fn run_production_rpc_service_inspected(
    loaded:super::LoadedConfig<ProductionRpcRuntimeConfigV4>,
    activation:BTreeMap<String,OwnedFd>,prepared:retrieval_client::Prepared,
    owner:Arc<native_guest::AdmittedGuest>,
)->Result<(),ServiceRunnerError> {
    owner.check().map_err(|_|ServiceRunnerError::invalid("native bridge admission refused"))?;
    let bootstrap=super::Bootstrap::NativeRetrieval(Arc::clone(&owner));
    run_production_rpc_service_loaded_inner(loaded,bootstrap,activation,Some((prepared,owner)),None)
}

pub(super) fn run_production_rpc_service_native_proofs(
    loaded:super::LoadedConfig<ProductionRpcRuntimeConfigV4>,activation:BTreeMap<String,OwnedFd>,
    prepared:native_guest::proof_client::Prepared,owner:Arc<native_guest::AdmittedGuest>,
)->Result<(),ServiceRunnerError> {
    owner.check().map_err(|_|ServiceRunnerError::invalid("native proof bridge admission refused"))?;
    let bootstrap=super::Bootstrap::NativeRetrieval(Arc::clone(&owner));
    run_production_rpc_service_loaded_inner(loaded,bootstrap,activation,None,Some((prepared,owner)))
}

fn run_production_rpc_service_loaded_inner(
    loaded:super::LoadedConfig<ProductionRpcRuntimeConfigV4>,bootstrap:super::Bootstrap,
    mut activation:BTreeMap<String,OwnedFd>,
    mut inspected:Option<(retrieval_client::Prepared,Arc<native_guest::AdmittedGuest>)>,
    mut inspected_proofs:Option<(native_guest::proof_client::Prepared,Arc<native_guest::AdmittedGuest>)>,
)->Result<(),ServiceRunnerError> {
    bootstrap.check()?;
    loaded.value.validate()?;
    let startup_deadline =
        bootstrap.deadline(loaded.value.startup_timeout_millis)?;
    if let Some((_,owner))=&inspected_proofs {
        if let Some(configuration)=owner.active_native_configuration()
            .map_err(|_|ServiceRunnerError::invalid("full native configuration admission refused"))? {
            if loaded.value.generation_admission.is_none()
                || configuration.dispatcher_protocol_set_sha256()!=&loaded.value.expected_production_dispatch_protocol_set_sha256 {
                return Err(ServiceRunnerError::invalid("activated native bridge requires actual generation coordinator and protocol"));
            }
        }
    }
    let mut required_names = vec![
        PRODUCTION_RPC_LISTENER_FD_NAME,
        PRODUCTION_RPC_JOURNAL_FD_NAME,
    ];
    required_names.extend(
        loaded
            .value
            .service_sessions
            .iter()
            .map(|session| session.activation_fd_name.as_str()),
    );
    required_names.extend(
        loaded
            .value
            .parent_signer_endpoints
            .iter()
            .map(|endpoint| endpoint.activation_fd_name.as_str()),
    );
    required_names.extend(
        loaded
            .value
            .proof_endpoints
            .iter()
            .map(|endpoint| endpoint.activation_fd_name.as_str()),
    );
    if loaded.value.spool.is_some(){required_names.push(super::spool_head_client::ORIGIN_FD);}
    super::require_exact_activation_names(&activation, &required_names)?;
    let origin_channel=if loaded.value.spool.is_some(){Some(super::take_activation_fd(&mut activation,super::spool_head_client::ORIGIN_FD)?)}else{None};

    // Connect only this selected socket as the actual final-role process,
    // before dependent handshakes consume the original startup interval.
    // This retains native originals, not a substitute readiness observation.
    let mut native_retrieval=if let Some((prepared,owner))=inspected.take() {
        let configured=loaded.value.proof_endpoints.iter()
            .find(|v|v.endpoint_kind==ProductionProofEndpointKindV4::Retrieval)
            .ok_or_else(||ServiceRunnerError::invalid("native retrieval endpoint absent"))?;
        let socket=super::take_activation_fd(&mut activation,&configured.activation_fd_name)?;
        Some(prepared.attach(socket,configured,owner)
            .map_err(|_|ServiceRunnerError::invalid("native retrieval factory refused"))?)
    } else {None};

    let native_proof_owner=inspected_proofs.as_ref().map(|(_,v)|Arc::clone(v));
    let (mut native_proofs,mut native_signers,mut native_facade)=if let Some((prepared,owner))=inspected_proofs.take() {
        prepared.attach(&mut activation,&loaded.value,owner)
            .map_err(|_|ServiceRunnerError::invalid("native proof endpoint construction refused"))?
    } else {(BTreeMap::new(),BTreeMap::new(),None)};
    if loaded.value.commit_request.is_some()!=native_signers.contains_key(&super::super::super::PolicyShadowCustodySignerRole::LedgerAppend)
        || loaded.value.spool.is_some()!=native_signers.contains_key(&super::super::super::PolicyShadowCustodySignerRole::IngressAdmission)
        || loaded.value.spool.as_ref().is_some_and(|value|value.completion_selected())
            !=native_signers.contains_key(&super::super::super::PolicyShadowCustodySignerRole::TerminalAppend)
        || [super::super::super::PolicyShadowCustodySignerRole::DispatchBarrier,
            super::super::super::PolicyShadowCustodySignerRole::ActiveEffectBarrier,super::super::super::PolicyShadowCustodySignerRole::ActiveEffectCommit]
            .into_iter().any(|role|loaded.value.spool.as_ref().is_some_and(|v|v.effects_selected())!=native_signers.contains_key(&role)) {
        return Err(ServiceRunnerError::invalid("CommitRequest requires its actual inspected native endpoint owner"));
    }

    let listener = super::take_activation_fd(
        &mut activation,
        PRODUCTION_RPC_LISTENER_FD_NAME,
    )?;
    let journal = super::take_activation_fd(
        &mut activation,
        PRODUCTION_RPC_JOURNAL_FD_NAME,
    )?;
    super::validate_listener(
        listener.as_fd(),
        &loaded.value.listener_socket_path,
    )?;
    super::validate_directory_capability(
        journal.as_fd(),
        PRODUCTION_RPC_JOURNAL_FD_NAME,
        &loaded.value.journal_directory_identity,
    )?;
    if let Some(acceptor)=native_facade.as_ref() {
        acceptor.listen(listener.as_fd())
            .map_err(|_|ServiceRunnerError::invalid("native final-role facade listen refused"))?;
    }

    let mut service_sessions = BTreeMap::new();
    let mut handshakes = Vec::new();
    for configured in &loaded.value.service_sessions {
        let socket = super::take_activation_fd(
            &mut activation,
            &configured.activation_fd_name,
        )?;
        let expected_peer = configured.expected_peer.checked()?;
        let authenticated = if let Some(acceptor)=native_facade.as_mut() {
            acceptor.outgoing(&configured.activation_fd_name,socket)
                .map_err(|_|ServiceRunnerError::invalid("native ordinary service connection refused"))?
        } else {
            AuthenticatedInheritedSeqpacket::from_inherited(socket,expected_peer)?
        };
        for configured_handshake in &configured.handshakes {
            if configured_handshake
                    .request
                    .deadline
                    .absolute_boottime_nanos()
                > startup_deadline
            {
                return Err(ServiceRunnerError::invalid(
                    "production service handshake exceeds the startup deadline",
                ));
            }
            let reply = perform_authenticated_client_handshake(
                &authenticated,
                &configured_handshake.request,
                configured.service_role,
                configured_handshake.endpoint_role,
                &configured.expected_socket_path,
                configured_handshake.request.request_rights_count,
                configured_handshake.request.reply_rights_count,
            )?;
            handshakes.push(ValidatedServiceHandshakeV3 {
                endpoint_role: configured_handshake.endpoint_role,
                request: configured_handshake.request.clone(),
                reply,
            });
        }
        if service_sessions
            .insert(configured.service_role, authenticated)
            .is_some()
        {
            return Err(ServiceRunnerError::invalid(
                "production service session role is duplicated",
            ));
        }
    }
    let readiness = VerifiedFiveServiceReadinessV3::from_handshakes(
        handshakes,
        None,
        loaded.value.expected_helper_endpoint_roles.clone(),
        loaded
            .value
            .expected_driver_process_identity_sha256
            .clone(),
        loaded
            .value
            .expected_driver_configuration_generation_sha256
            .clone(),
        loaded.value.expected_operation_generation,
        loaded.value.expected_shared_configuration_sha256.clone(),
        loaded.value.expected_service_configuration_sha256.clone(),
        loaded
            .value
            .expected_service_signing_credential_sha256
            .clone(),
        loaded.value.expected_service_restart_epoch.clone(),
        loaded.value.expected_service_readiness_epoch.clone(),
        loaded
            .value
            .expected_service_authority_history_manifest_sha256
            .clone(),
        loaded
            .value
            .expected_production_dispatch_protocol_set_sha256
            .clone(),
        loaded.value.expected_maximum_durability_worker_nanos,
    )?;

    let histories = load_production_histories(
        &loaded.value,
        &loaded.credentials,
    )?;
    let mut parent_signer_endpoints = Vec::with_capacity(10);
    for configured in &loaded.value.parent_signer_endpoints {
        if matches!(configured.signer_role,super::super::super::PolicyShadowCustodySignerRole::LedgerAppend
            |super::super::super::PolicyShadowCustodySignerRole::IngressAdmission|super::super::super::PolicyShadowCustodySignerRole::TerminalAppend
            |super::super::super::PolicyShadowCustodySignerRole::DispatchBarrier
            |super::super::super::PolicyShadowCustodySignerRole::ActiveEffectBarrier
            |super::super::super::PolicyShadowCustodySignerRole::ActiveEffectCommit) {
            if let Some(session)=native_signers.remove(&configured.signer_role) {
                parent_signer_endpoints.push(load_pinned_endpoint_session(
                    ProductionAuthorityEndpointIdentityV4::ParentSigner(configured.signer_role),EndpointSession::NativeProof(session),
                    &configured.authority_binding_credential,configured.authority_key_id.clone(),configured.authority_key_spki_sha256.clone(),
                    &loaded.credentials)?);
                continue;
            }
        }
        let socket = super::take_activation_fd(
            &mut activation,
            &configured.activation_fd_name,
        )?;
        let endpoint=if let Some(acceptor)=native_facade.as_mut() {
            let session=acceptor.outgoing(&configured.activation_fd_name,socket)
                .map_err(|_|ServiceRunnerError::invalid("native ordinary authority connection refused"))?;
            load_pinned_endpoint_session(
                ProductionAuthorityEndpointIdentityV4::ParentSigner(configured.signer_role),
                EndpointSession::Host(session),&configured.authority_binding_credential,
                configured.authority_key_id.clone(),configured.authority_key_spki_sha256.clone(),&loaded.credentials)?
        } else {load_pinned_endpoint(
            ProductionAuthorityEndpointIdentityV4::ParentSigner(
                configured.signer_role,
            ),
            socket,
            &configured.expected_socket_path,
            configured.expected_peer.checked()?,
            &configured.authority_binding_credential,
            configured.authority_key_id.clone(),
            configured.authority_key_spki_sha256.clone(),
            &loaded.credentials,
        )?};
        parent_signer_endpoints.push(endpoint);
    }
    let mut proof_endpoints = BTreeMap::new();
    for configured in &loaded.value.proof_endpoints {
        let identity=ProductionAuthorityEndpointIdentityV4::Proof(configured.endpoint_kind);
        let endpoint = if let Some(session)=native_proofs.remove(&configured.endpoint_kind) {
            load_pinned_endpoint_session(identity,EndpointSession::NativeProof(session),
                &configured.authority_binding_credential,configured.authority_key_id.clone(),
                configured.authority_key_spki_sha256.clone(),&loaded.credentials)?
        } else if configured.endpoint_kind==ProductionProofEndpointKindV4::Retrieval && native_retrieval.is_some() {
            let session=EndpointSession::NativeRetrieval(native_retrieval.take().expect("owned native retrieval endpoint"));
            load_pinned_endpoint_session(identity,session,
                &configured.authority_binding_credential,configured.authority_key_id.clone(),
                configured.authority_key_spki_sha256.clone(),&loaded.credentials)?
        } else {
            let socket=super::take_activation_fd(&mut activation,&configured.activation_fd_name)?;
            load_pinned_endpoint(
            ProductionAuthorityEndpointIdentityV4::Proof(
                configured.endpoint_kind,
            ),
            socket,
            &configured.expected_socket_path,
            configured.expected_peer.checked()?,
            &configured.authority_binding_credential,
            configured.authority_key_id.clone(),
            configured.authority_key_spki_sha256.clone(),
            &loaded.credentials,
            )?
        };
        if proof_endpoints
            .insert(configured.endpoint_kind, endpoint)
            .is_some()
        {
            return Err(ServiceRunnerError::invalid(
                "production proof endpoint is duplicated",
            ));
        }
    }
    if let Some(acceptor)=native_facade.as_ref() {
        acceptor.require_outgoing_complete()
            .map_err(|_|ServiceRunnerError::invalid("native ordinary endpoint owner remained unconsumed"))?;
    }
    if !activation.is_empty() {
        return Err(ServiceRunnerError::invalid(
            "production RPC retained an unexpected activation descriptor",
        ));
    }

    let mut authority = ConcreteFiveV3ProductionAuthoritiesV4::new(
        service_sessions,
        readiness,
        parent_signer_endpoints,
        proof_endpoints,
    )?;
    if let Some(owner)=native_proof_owner {
        if let Some(selection)=loaded.value.spool.clone(){
            authority.spool=Some(std::sync::Mutex::new(super::spool_head_client::Client::new(selection,
                load_production_histories(&loaded.value,&loaded.credentials)?,Arc::clone(&owner),
                origin_channel.ok_or_else(||ServiceRunnerError::invalid("native generation origin channel absent"))?,
                &loaded.value.expected_service_configuration_sha256)?));
        }
        if let Some(selection)=loaded.value.commit_request.clone() {
            if !owner.commitment_bridge_selected() {return Err(ServiceRunnerError::invalid("CommitRequest bridge purpose differs"));}
            authority.commit_request=Some(std::sync::Mutex::new(super::dispatch_service::client::Client::new(selection,
                load_production_histories(&loaded.value,&loaded.credentials)?,Arc::clone(&owner),&loaded.value.expected_service_configuration_sha256,
                loaded.value.api_version=="serverware.policyCustodyProductionRpcRuntime/v9")?));
        }
        authority.enable_native_proofs(owner)?;
    }
    if let Some(selection)=loaded.value.generation_admission.clone() {
        authority.generation_admission=Some(std::sync::Mutex::new(super::generation_service_client::Client::new(
            selection,load_production_histories(&loaded.value,&loaded.credentials)?,bootstrap.clone())?));
    }
    let bridge = ProductionRpcServiceBridgeV4::recover(
        authority,
        histories,
        journal,
    )?;
    let facade_peer = loaded.value.expected_facade_peer.checked()?;
    let mut facade_sessions = Vec::with_capacity(
        PRODUCTION_RPC_SESSION_COUNT,
    );
    for _ in 0..PRODUCTION_RPC_SESSION_COUNT {
        if let Some(acceptor)=native_facade.as_mut() {
            // The actual final-role bridge cannot inspect a nondumpable peer's
            // executable after drop. Its retained root parent performs every
            // original check on this exact accepted socket instead.
            let connection=super::accept_peer(listener.as_fd(),startup_deadline)?;
            facade_sessions.push(acceptor.authenticate(connection)
                .map_err(|_|ServiceRunnerError::invalid("native facade peer inspection refused"))?);
        } else {
            let connection = super::accept_authenticated_peer(listener.as_fd(), &facade_peer, startup_deadline)?;
            facade_sessions.push(authenticate_production_rpc_session(connection, facade_peer.clone())?);
        }
    }
    drop(listener);
    bootstrap.ready_status(
        "policy-custody production RPC recovered, authenticated, and ready",
    )?;
    run_production_rpc_service_scoped(facade_sessions, bridge, bootstrap)
}

fn load_pinned_endpoint(
    identity: ProductionAuthorityEndpointIdentityV4,
    socket: OwnedFd,
    expected_socket_path: &std::path::Path,
    expected_peer: ExpectedPeerCredentials,
    authority_key_credential: &str,
    authority_key_id: super::super::super::Sha256Digest,
    authority_key_spki_sha256: super::super::super::Sha256Digest,
    credentials: &super::CredentialDirectory,
) -> Result<ProductionPinnedEndpointV4, ServiceRunnerError> {
    validate_exact_peer_path(socket.as_raw_fd(), expected_socket_path)?;
    let session=EndpointSession::Host(AuthenticatedInheritedSeqpacket::from_inherited(socket,expected_peer)?);
    load_pinned_endpoint_session(identity,session,authority_key_credential,authority_key_id,authority_key_spki_sha256,credentials)
}
fn load_pinned_endpoint_session(
    identity:ProductionAuthorityEndpointIdentityV4,session:EndpointSession,authority_key_credential:&str,
    authority_key_id:super::super::super::Sha256Digest,authority_key_spki_sha256:super::super::super::Sha256Digest,
    credentials:&super::CredentialDirectory,
)->Result<ProductionPinnedEndpointV4,ServiceRunnerError> {
    let authority_key =
        credentials.read_verifying_key(authority_key_credential)?;
    let spki = authority_key.to_public_key_der().map_err(|_| {
        ServiceRunnerError::invalid(
            "production endpoint authority key has no canonical SPKI",
        )
    })?;
    if super::super::super::Sha256Digest::compute(spki.as_bytes())
            != authority_key_spki_sha256
        || authority_key_id
            == super::super::super::Sha256Digest::compute(&[])
    {
        return Err(ServiceRunnerError::invalid(
            "production endpoint authority credential differs from its key pins",
        ));
    }
    session.revalidate_peer()?;
    Ok(ProductionPinnedEndpointV4 {
        identity,
        session,
        authority_key_id,
        authority_key_spki_sha256,
        authority_key,
    })
}

pub(super) fn load_production_histories(
    runtime: &ProductionRpcRuntimeConfigV4,
    credentials: &super::CredentialDirectory,
) -> Result<ProductionServiceHistoricalKeyringsV4, ServiceRunnerError> {
    let mut histories = BTreeMap::new();
    for configured in &runtime.histories {
        let exact = credentials.read(
            &configured.manifest_credential,
            super::MAX_CONFIG_BYTES,
        )?;
        if expected_history_manifest_sha256(runtime, configured.service_role)
                != Some(&configured.manifest_sha256)
        {
            return Err(ServiceRunnerError::invalid(
                "production authority history credential differs from its exact configured manifest",
            ));
        }
        let manifest: AuthorityHistoryManifestV3 =
            decode_canonical_frame(&exact)?;
        let history = RuntimeAuthorityHistory::from_manifest(
            manifest,
            &configured.root_key_id,
            &configured.root_key_spki_sha256,
        )
        .map_err(|error| ServiceRunnerError::invalid(error.to_string()))?;
        if history.authority_role()
                != HistoricalAuthorityRoleV3::IsolatedService(
                    configured.service_role,
                )
            || history.manifest_sha256() != &configured.manifest_sha256
            || histories
                .insert(configured.service_role, history)
                .is_some()
        {
            return Err(ServiceRunnerError::invalid(
                "production authority history role, digest, or uniqueness check failed",
            ));
        }
    }
    ProductionServiceHistoricalKeyringsV4::new(
        take_history(
            &mut histories,
            HistoricalServiceRoleV3::DurableRecoveryStore,
        )?,
        take_history(
            &mut histories,
            HistoricalServiceRoleV3::CleanupAuthorizationConsumer,
        )?,
        take_history(
            &mut histories,
            HistoricalServiceRoleV3::RecoveryTargetProvider,
        )?,
        take_history(
            &mut histories,
            HistoricalServiceRoleV3::CurrentSignatureAuthority,
        )?,
        take_history(
            &mut histories,
            HistoricalServiceRoleV3::BoundedCleanupHelper,
        )?,
    )
}

fn expected_history_manifest_sha256(
    runtime: &ProductionRpcRuntimeConfigV4,
    role: HistoricalServiceRoleV3,
) -> Option<&super::super::super::Sha256Digest> {
    runtime
        .expected_service_authority_history_manifest_sha256
        .get(&trusted_service_role(role))
}

fn trusted_service_role(
    role: HistoricalServiceRoleV3,
) -> TrustedHostServiceRoleV3 {
    match role {
        HistoricalServiceRoleV3::DurableRecoveryStore => {
            TrustedHostServiceRoleV3::DurableRecoveryStore
        }
        HistoricalServiceRoleV3::CleanupAuthorizationConsumer => {
            TrustedHostServiceRoleV3::CleanupAuthorizationConsumer
        }
        HistoricalServiceRoleV3::RecoveryTargetProvider => {
            TrustedHostServiceRoleV3::RecoveryTargetProvider
        }
        HistoricalServiceRoleV3::CurrentSignatureAuthority => {
            TrustedHostServiceRoleV3::CurrentSignatureAuthority
        }
        HistoricalServiceRoleV3::BoundedCleanupHelper => {
            TrustedHostServiceRoleV3::BoundedCleanupHelper
        }
    }
}

fn take_history(
    histories: &mut BTreeMap<
        HistoricalServiceRoleV3,
        RuntimeAuthorityHistory,
    >,
    role: HistoricalServiceRoleV3,
) -> Result<RuntimeAuthorityHistory, ServiceRunnerError> {
    histories.remove(&role).ok_or_else(|| {
        ServiceRunnerError::invalid(
            "production authority history set is incomplete",
        )
    })
}
