use super::common::ServiceRuntime;
use super::super::{
    CustodyServiceRole, RootOwnedResponseObservationV2Config,
    V2RuntimeError,
};
use super::super::attestation::
    verify_final_envelope_verification;
use super::super::protocol::{
    FinalEnvelopeVerificationRequestV1,
    SignedFinalEnvelopeVerificationV1,
    ServiceOperationV1,
};

pub(crate) fn run(
    config: &RootOwnedResponseObservationV2Config,
) -> Result<(), V2RuntimeError> {
    ServiceRuntime::prepare(
        config,
        CustodyServiceRole::PolicyProofVerifier,
    )?
    .run()
}

pub(crate) fn verify_final_envelope(
    config: &RootOwnedResponseObservationV2Config,
    request_id: &str,
    request: &FinalEnvelopeVerificationRequestV1,
) -> Result<SignedFinalEnvelopeVerificationV1, V2RuntimeError> {
    let verification: SignedFinalEnvelopeVerificationV1 =
        super::invoke_service(
            config,
            CustodyServiceRole::PolicyProofVerifier,
            ServiceOperationV1::FinalEnvelopeVerify,
            request_id,
            request,
            request.deadline_boottime_ns,
        )?;
    verify_final_envelope_verification(
        config.custody_topology(),
        &verification,
    )?;
    if verification.request_id
            != request.envelope.request_id
        || verification.attempt_id
            != request.envelope.attempt_id
        || verification.stable_resume_id
            != request.envelope.stable_resume_id
        || verification.final_envelope_sha256
            != request.envelope.final_envelope_sha256
        || verification.canonical_envelope_bytes_sha256
            != request.canonical_envelope_bytes_sha256
        || verification.transition_chain_root_sha256
            != request.envelope.transition_chain_root_sha256
    {
        return Err(V2RuntimeError::new(
            "final_envelope_verification_binding_mismatch",
            "policy verifier did not sign the exact canonical final envelope and transition-chain root",
        ));
    }
    Ok(verification)
}
