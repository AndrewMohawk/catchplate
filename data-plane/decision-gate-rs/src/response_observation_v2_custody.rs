//! Server-side custody integration for response-observation v2.
//!
//! The implementation lives under `response_v2/custody`. This compatibility
//! facade preserves the crate surface used by the data-plane and custody
//! binary while the privilege-boundary contracts remain separately reviewable.

#[path = "response_v2/custody/config.rs"]
pub(crate) mod config;
#[path = "response_v2/custody/generation.rs"]
pub(crate) mod generation;
#[path = "response_v2/custody/guest_delivery.rs"]
pub(crate) mod guest_delivery;
#[path = "response_v2/custody/guest_listener.rs"]
pub(crate) mod guest_listener;
#[path = "response_v2/custody/protocol.rs"]
pub(crate) mod protocol;
#[path = "response_v2/custody/supervisor.rs"]
pub(crate) mod supervisor;
#[cfg(target_os = "linux")]
#[path = "response_v2/custody/peer_measurement.rs"]
pub(crate) mod peer_measurement;
#[path = "response_v2/custody/attestation.rs"]
pub(crate) mod attestation;
#[path = "response_v2/custody/recovery.rs"]
pub(crate) mod recovery;
#[path = "response_v2/custody/state/mod.rs"]
pub(crate) mod state;
#[path = "response_v2/custody/services/mod.rs"]
pub(crate) mod services;

pub use config::{
    CustodyServiceRole, SignedCustodyTopologyV1,
    TrustedHostNoTeeTopology,
};
pub use guest_listener::{GuestResponseV2ListenerProfile, GuestResponseV2ClientPath,
    PreparedGuestResponseV2Listener, GUEST_RESPONSE_V2_SOCKET};
pub use supervisor::{
    check_custody_service_readiness, dispatch_from_process_args,
    run_custody_service, run_provider_rpc_v1_compatibility,
};
pub use protocol::{
    build_canonical_authority_proof_input_from_seed,
    canonical_authority_envelope_preimage_sha256,
    canonical_final_envelope_preimage_sha256,
    ordered_authority_artifacts_root_sha256,
    released_projection_sha256_v2,
    stable_resume_id_sha256,
    validate_canonical_authority_envelope,
    CanonicalAuthorityEnvelopeDescriptorV2,
    CanonicalAuthorityEnvelopeProofInputV2,
    CanonicalAuthorityEnvelopeProofSeedV2,
    CanonicalFinalEnvelopeDescriptorV1,
    CommitReleaseMetadataRequestV1,
    ConsumeReleaseAndRetrieveExactRequestV1,
    CustodyAttestationRequestV1, CustodyRecoveryRequestV1,
    FinalEnvelopeVerificationRequestV1,
    InspectImmutableRawRequestV1, LifecycleTransitionV1,
    PublicCustodyOperationV1, PublicCustodyRequestV1,
    PublicCustodyResponseV1, PublicCustodyResultV1,
    PublicHelloRequestV1, PublicHelloResultV1,
    PublicLifecycleDeadlineV1, PublicRequestContextV1,
    ProviderAuthorityScopeV2,
    ReleaseAuthorizationRequestV2,
    ServiceOperationV1, ServiceRpcResultV1,
    SignedCustodyAttestationV1, SignedCustodyErrorV1,
    SignedCustodyRecoveryV1, SignedFinalEnvelopeVerificationV1,
    SignedImmutableRawInspectionV1, SignedReleaseAuthorizationV2,
    SignedReleasePreparationReceiptV1,
    SignedReleaseConsumptionV2, SignedReleaseMetadataV1,
    SignedStateMutationReceiptV1,
    SignedTransitionAuthorizationV1, SettlementRequestV1,
    SignedDurableTerminalReceiptV1, UnsignedStateAuthorityIntentV1,
    AUTHORITY_SCOPE_API_VERSION,
    AUTHORITY_ARTIFACTS_ROOT_API_VERSION,
    CANONICAL_AUTHORITY_ENVELOPE_API_VERSION,
    PRE_RELEASE_AUTHORITY_ARTIFACT_COUNT, PUBLIC_CUSTODY_API_VERSION,
};
pub use super::state_authority::rpc::{
    CanonicalFinalEnvelopeBody, SignedAuthorityArtifact,
};
pub use attestation::{
    verify_custody_attestation, verify_custody_error,
    verify_custody_recovery, verify_final_envelope_verification,
    verify_immutable_raw_inspection, verify_release_authorization,
    verify_release_consumption, verify_release_metadata,
    verify_service_rpc_result, verify_transition_authorization,
};

include!("response_v2/custody/mod.rs");
