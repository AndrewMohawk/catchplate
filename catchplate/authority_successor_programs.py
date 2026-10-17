"""Source-fixed factories for authenticated successor planning paths.

These owners require configured keys and original invocation work; they are
not legacy TransitionKernel adapters. Registration describes available source
paths, not admission, reservation, or business execution authority. Imports
stay lazy so the actual read owners can use planner primitives without an
import-time registry cycle. Transition read factories remain
read-acquisition producers; their separate operation-bound plan factories
add the actual configured signer without changing that base result contract.
Delivery consumption pairs its real read-acquisition factory with a stateless
original-replaying signer; it claims neither durable retention nor a legacy kernel.
Native review entries are explicitly read/replay components, not available
successor planners; their complete bounded plan/commit owners are still absent.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable, Final, Mapping

from catchplate import authority_contract


@dataclass(frozen=True, slots=True)
class SuccessorPlanningProgram:
    operation: str
    handler: str
    program_id: str
    planning_mode: str
    result_kind: str
    factory: Callable[..., object]
    kernel_factory: Callable[..., object] | None = None
    plan_factory: Callable[..., object] | None = None


def _revocation(*, read_dsn, connect_timeout_seconds, database_identity,
        planner_private_key, planner_public_key, verifier_public_key,
        expected_verifier_identity, maximum_assertion_age_ns,
        maximum_plan_age_ns, maximum_clock_skew_ns):
    from catchplate.authority_revocation_planning import RevocationObservedPlanner

    return RevocationObservedPlanner(read_dsn=read_dsn,
        connect_timeout_seconds=connect_timeout_seconds, database_identity=database_identity,
        planner_private_key=planner_private_key, planner_public_key=planner_public_key,
        verifier_public_key=verifier_public_key, expected_verifier_identity=expected_verifier_identity,
        maximum_assertion_age_ns=maximum_assertion_age_ns,
        maximum_plan_age_ns=maximum_plan_age_ns, maximum_clock_skew_ns=maximum_clock_skew_ns)


def _challenge_maintenance(*, read_dsn, connect_timeout_seconds, database_identity,
        planner_private_key, planner_public_key, planner_identity, planner_spki_digest,
        configuration_digest, maintenance_policy, maximum_plan_age_ns, maximum_clock_skew_ns):
    # The actual source owner owns a native SERIALIZABLE read-only snapshot,
    # two bounded raw-page passes and real signing. It is not an aggregate v3
    # TransitionKernel adapter and cannot produce a business execution grant.
    from catchplate.authority_challenge_planning import MaintenancePlanner

    return MaintenancePlanner(operation="webauthn.challenge.maintain", read_dsn=read_dsn,
        connect_timeout_seconds=connect_timeout_seconds, database_identity=database_identity,
        planner_private_key=planner_private_key, planner_public_key=planner_public_key,
        planner_identity=planner_identity, planner_spki_digest=planner_spki_digest,
        configuration_digest=configuration_digest, maintenance_policy=maintenance_policy,
        maximum_plan_age_ns=maximum_plan_age_ns, maximum_clock_skew_ns=maximum_clock_skew_ns)


def _jit_assertion(*, read_planner, page_caller):
    # The real owner joins one native pass, signing, original-page retention
    # and independent readback replay. Registration does not grant request,
    # current-root or execution admission, and never selects jit.decide.
    from catchplate.authority_jit_compound_production import _JitCompoundProducer

    return _JitCompoundProducer(read_planner=read_planner, page_caller=page_caller)


def _native_review_reader(operation, *, dsn, connect_timeout_seconds, database_role,
        tls_client_dn, tls_client_serial, tls_issuer_dn, query_manifest_digest,
        root_public_key, enrollment_original, current_root_client):
    from catchplate.authority_native_jit_review_current_read import NativeJitReviewCurrentReader

    return NativeJitReviewCurrentReader(operation=operation, dsn=dsn,
        connect_timeout_seconds=connect_timeout_seconds, database_role=database_role,
        tls_client_dn=tls_client_dn, tls_client_serial=tls_client_serial, tls_issuer_dn=tls_issuer_dn,
        query_manifest_digest=query_manifest_digest, root_public_key=root_public_key,
        enrollment_original=enrollment_original, current_root_client=current_root_client)


def _native_review_authorize(**configuration):
    return _native_review_reader("jit.review-open.authorize", **configuration)


def _native_review_receipt(**configuration):
    return _native_review_reader("jit.review-open.receipt.issue", **configuration)


def _native_review_authorize_kernel():
    from catchplate.authority_transition_native_jit_review_open import NativeJitReviewKernel

    return NativeJitReviewKernel("jit.review-open.authorize")


def _native_review_receipt_kernel():
    from catchplate.authority_transition_native_jit_review_open import NativeJitReviewKernel

    return NativeJitReviewKernel("jit.review-open.receipt.issue")


def _evidence_owner(operation, *, read_planner, planner_private_key, planner_public_key,
        expected_planner_identity, expected_planner_spki_digest, configuration_digest):
    from catchplate import authority_webauthn_evidence_plan_owner as owner
    from catchplate import authority_webauthn_evidence_planning as planning

    if type(read_planner) is not planning.EvidenceAdmissionPlanner:
        raise ValueError("successor evidence program requires its actual configured reader")
    configured = planning._configuration(read_planner._configured)
    if configured[3] != operation:
        raise ValueError("successor evidence program differs from its configured operation")
    return owner.EvidenceAdmissionPlanOwner(read_planner=read_planner,
        planner_private_key=planner_private_key, planner_public_key=planner_public_key,
        expected_planner_identity=expected_planner_identity,
        expected_planner_spki_digest=expected_planner_spki_digest,
        configuration_digest=configuration_digest)


def _registration_evidence(*, read_planner, planner_private_key, planner_public_key,
        expected_planner_identity, expected_planner_spki_digest, configuration_digest):
    return _evidence_owner("webauthn.registration.evidence.admit", read_planner=read_planner,
        planner_private_key=planner_private_key, planner_public_key=planner_public_key,
        expected_planner_identity=expected_planner_identity,
        expected_planner_spki_digest=expected_planner_spki_digest,
        configuration_digest=configuration_digest)


def _installation_evidence(*, read_planner, planner_private_key, planner_public_key,
        expected_planner_identity, expected_planner_spki_digest, configuration_digest):
    return _evidence_owner("webauthn.trust.installation.admit", read_planner=read_planner,
        planner_private_key=planner_private_key, planner_public_key=planner_public_key,
        expected_planner_identity=expected_planner_identity,
        expected_planner_spki_digest=expected_planner_spki_digest,
        configuration_digest=configuration_digest)


def _registration_evidence_kernel(*, public_key, expected_identity, expected_spki_digest,
        maximum_age_ns, maximum_clock_skew_ns, rp_id, origin, installation_target_digest):
    from catchplate.authority_webauthn_evidence_kernel import EvidenceAdmissionKernel

    return EvidenceAdmissionKernel(operation="webauthn.registration.evidence.admit",
        public_key=public_key, expected_identity=expected_identity,
        expected_spki_digest=expected_spki_digest, maximum_age_ns=maximum_age_ns,
        maximum_clock_skew_ns=maximum_clock_skew_ns, rp_id=rp_id, origin=origin,
        installation_target_digest=installation_target_digest)


def _installation_evidence_kernel(*, public_key, expected_identity, expected_spki_digest,
        maximum_age_ns, maximum_clock_skew_ns, rp_id, origin, installation_target_digest):
    from catchplate.authority_webauthn_evidence_kernel import EvidenceAdmissionKernel

    return EvidenceAdmissionKernel(operation="webauthn.trust.installation.admit",
        public_key=public_key, expected_identity=expected_identity,
        expected_spki_digest=expected_spki_digest, maximum_age_ns=maximum_age_ns,
        maximum_clock_skew_ns=maximum_clock_skew_ns, rp_id=rp_id, origin=origin,
        installation_target_digest=installation_target_digest)


def _registration(*, read_dsn, connect_timeout_seconds, database_identity,
        evidence_public_key, expected_signer_identity, expected_signer_spki_digest,
        expected_rp_id, expected_origin, maximum_age_ns, maximum_clock_skew_ns):
    from catchplate.authority_webauthn_transition_planning import RegistrationTransitionPlanner

    return RegistrationTransitionPlanner(read_dsn=read_dsn,
        connect_timeout_seconds=connect_timeout_seconds, database_identity=database_identity,
        evidence_public_key=evidence_public_key, expected_signer_identity=expected_signer_identity,
        expected_signer_spki_digest=expected_signer_spki_digest,
        expected_rp_id=expected_rp_id, expected_origin=expected_origin,
        maximum_age_ns=maximum_age_ns, maximum_clock_skew_ns=maximum_clock_skew_ns)


def _stage(*, read_dsn, connect_timeout_seconds, database_identity,
        verifier_public_key, verifier_identity, expected_candidate_signing_key_id,
        development_enabled, require_approval, require_approver_webauthn,
        maximum_age_ns, maximum_clock_skew_ns):
    from catchplate.authority_webauthn_transition_planning import TrustStageTransitionPlanner

    return TrustStageTransitionPlanner(read_dsn=read_dsn,
        connect_timeout_seconds=connect_timeout_seconds, database_identity=database_identity,
        verifier_public_key=verifier_public_key, verifier_identity=verifier_identity,
        expected_candidate_signing_key_id=expected_candidate_signing_key_id,
        development_enabled=development_enabled, require_approval=require_approval,
        require_approver_webauthn=require_approver_webauthn,
        maximum_age_ns=maximum_age_ns, maximum_clock_skew_ns=maximum_clock_skew_ns)


def _completion(*, read_dsn, connect_timeout_seconds, database_identity,
        installer_public_key, expected_installer_identity, expected_installer_spki_digest,
        installation_target_digest, maximum_age_ns, maximum_clock_skew_ns):
    from catchplate.authority_webauthn_transition_planning import TrustCompletionTransitionPlanner

    return TrustCompletionTransitionPlanner(read_dsn=read_dsn,
        connect_timeout_seconds=connect_timeout_seconds, database_identity=database_identity,
        installer_public_key=installer_public_key, expected_installer_identity=expected_installer_identity,
        expected_installer_spki_digest=expected_installer_spki_digest,
        installation_target_digest=installation_target_digest,
        maximum_age_ns=maximum_age_ns, maximum_clock_skew_ns=maximum_clock_skew_ns)


def _transition_owner(operation, *, read_planner, planner_private_key, planner_public_key,
        expected_planner_identity, expected_planner_spki_digest, configuration_digest, maximum_plan_age_ns):
    from catchplate import authority_webauthn_transition_plan_owner as owner
    from catchplate import authority_webauthn_transition_planning as planning

    owner_type = {
        "webauthn.registration.finalize": planning.RegistrationTransitionPlanner,
        "webauthn.trust.stage": planning.TrustStageTransitionPlanner,
        "webauthn.trust.complete": planning.TrustCompletionTransitionPlanner,
    }[operation]
    # The selected operation is source fixed; a reader for another successor
    # cannot turn this factory into a generic operation or legacy dispatcher.
    planning._snapshot(read_planner, owner_type, operation)
    return owner.TransitionPlanOwner(read_planner=read_planner,
        planner_private_key=planner_private_key, planner_public_key=planner_public_key,
        expected_planner_identity=expected_planner_identity,
        expected_planner_spki_digest=expected_planner_spki_digest,
        configuration_digest=configuration_digest, maximum_plan_age_ns=maximum_plan_age_ns)


def _registration_plan(*, read_planner, planner_private_key, planner_public_key,
        expected_planner_identity, expected_planner_spki_digest, configuration_digest, maximum_plan_age_ns):
    return _transition_owner("webauthn.registration.finalize", read_planner=read_planner,
        planner_private_key=planner_private_key, planner_public_key=planner_public_key,
        expected_planner_identity=expected_planner_identity,
        expected_planner_spki_digest=expected_planner_spki_digest,
        configuration_digest=configuration_digest, maximum_plan_age_ns=maximum_plan_age_ns)


def _stage_plan(*, read_planner, planner_private_key, planner_public_key,
        expected_planner_identity, expected_planner_spki_digest, configuration_digest, maximum_plan_age_ns):
    return _transition_owner("webauthn.trust.stage", read_planner=read_planner,
        planner_private_key=planner_private_key, planner_public_key=planner_public_key,
        expected_planner_identity=expected_planner_identity,
        expected_planner_spki_digest=expected_planner_spki_digest,
        configuration_digest=configuration_digest, maximum_plan_age_ns=maximum_plan_age_ns)


def _completion_plan(*, read_planner, planner_private_key, planner_public_key,
        expected_planner_identity, expected_planner_spki_digest, configuration_digest, maximum_plan_age_ns):
    return _transition_owner("webauthn.trust.complete", read_planner=read_planner,
        planner_private_key=planner_private_key, planner_public_key=planner_public_key,
        expected_planner_identity=expected_planner_identity,
        expected_planner_spki_digest=expected_planner_spki_digest,
        configuration_digest=configuration_digest, maximum_plan_age_ns=maximum_plan_age_ns)


def _activation(*, read_dsn, connect_timeout_seconds, database_identity, maximum_clock_skew_ns):
    from catchplate.authority_oidc_session_activation_planning import OidcSessionActivationReadPlanner

    return OidcSessionActivationReadPlanner(read_dsn=read_dsn,
        connect_timeout_seconds=connect_timeout_seconds, database_identity=database_identity,
        maximum_clock_skew_ns=maximum_clock_skew_ns)


def _activation_delivery(*, read_dsn, connect_timeout_seconds, database_identity, maximum_clock_skew_ns):
    from catchplate.authority_oidc_session_activation_delivery_planning import OidcSessionActivationDeliveryReadPlanner

    return OidcSessionActivationDeliveryReadPlanner(read_dsn=read_dsn,
        connect_timeout_seconds=connect_timeout_seconds, database_identity=database_identity,
        maximum_clock_skew_ns=maximum_clock_skew_ns)


def _activation_delivery_plan(*, read_planner, planner_private_key, planner_public_key,
        expected_planner_identity, expected_planner_spki_digest, configuration_digest,
        authn_policy, trust_policy, maximum_plan_age_ns, maximum_clock_skew_ns,
        state_enrollment_bytes, state_root_public_key, complete_root_vector_bytes,
        historical_custody, activation_expectations, activation_scope,
        activation_planner_public_key, operation_public_key, journal,
        live_window, transport_deadline_ns, work):
    from catchplate.authority_oidc_session_activation_delivery_plan_owner import OidcSessionActivationDeliveryPlanOwner

    return OidcSessionActivationDeliveryPlanOwner(read_planner=read_planner,
        planner_private_key=planner_private_key, planner_public_key=planner_public_key,
        expected_planner_identity=expected_planner_identity,
        expected_planner_spki_digest=expected_planner_spki_digest, configuration_digest=configuration_digest,
        authn_policy=authn_policy, trust_policy=trust_policy, maximum_plan_age_ns=maximum_plan_age_ns,
        maximum_clock_skew_ns=maximum_clock_skew_ns, state_enrollment_bytes=state_enrollment_bytes,
        state_root_public_key=state_root_public_key, complete_root_vector_bytes=complete_root_vector_bytes,
        historical_custody=historical_custody, activation_expectations=activation_expectations,
        activation_scope=activation_scope, activation_planner_public_key=activation_planner_public_key,
        operation_public_key=operation_public_key, journal=journal, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work)


def _activation_plan(*, read_planner, planner_private_key, planner_public_key,
        expected_planner_identity, expected_planner_spki_digest, configuration_digest,
        delivery_custody_key, journal, rp_id, origin, authn_policy, trust_policy,
        maximum_plan_age_ns, maximum_clock_skew_ns, delivery_ttl_seconds,
        state_enrollment_bytes, state_root_public_key, complete_root_vector_bytes,
        live_window, work, transport_deadline_ns=None):
    from catchplate.authority_oidc_session_activation_plan_owner import OidcSessionActivationPlanOwner

    return OidcSessionActivationPlanOwner(read_planner=read_planner,
        planner_private_key=planner_private_key, planner_public_key=planner_public_key,
        expected_planner_identity=expected_planner_identity,
        expected_planner_spki_digest=expected_planner_spki_digest,
        configuration_digest=configuration_digest, delivery_custody_key=delivery_custody_key,
        journal=journal, rp_id=rp_id, origin=origin, authn_policy=authn_policy, trust_policy=trust_policy,
        maximum_plan_age_ns=maximum_plan_age_ns, maximum_clock_skew_ns=maximum_clock_skew_ns,
        delivery_ttl_seconds=delivery_ttl_seconds, live_window=live_window, work=work,
        state_enrollment_bytes=state_enrollment_bytes, state_root_public_key=state_root_public_key,
        complete_root_vector_bytes=complete_root_vector_bytes,
        transport_deadline_ns=transport_deadline_ns)


def _program(operation, factory, result_kind, kernel_factory=None, plan_factory=None):
    return SuccessorPlanningProgram(operation=operation,
        handler=authority_contract.operation_spec(operation)["handler"],
        program_id=authority_contract.transition_program_id(operation),
        planning_mode="typed-successor-planning", result_kind=result_kind,
        factory=factory, kernel_factory=kernel_factory, plan_factory=plan_factory)


PROGRAMS: Final[Mapping[str, SuccessorPlanningProgram]] = MappingProxyType({
    program.operation: program for program in (
        _program("oidc.session.activate", _activation, "read-acquisition", plan_factory=_activation_plan),
        _program("oidc.session.activation-delivery.consume", _activation_delivery, "read-acquisition",
            plan_factory=_activation_delivery_plan),
        _program("webauthn.credential.revoke", _revocation, "signed-originals"),
        _program("webauthn.challenge.maintain", _challenge_maintenance, "signed-originals"),
        _program("jit.assertion.issue", _jit_assertion, "signed-originals"),
        _program("jit.review-open.authorize", _native_review_authorize, "read-replay-components",
            kernel_factory=_native_review_authorize_kernel),
        _program("jit.review-open.receipt.issue", _native_review_receipt, "read-replay-components",
            kernel_factory=_native_review_receipt_kernel),
        _program("webauthn.registration.evidence.admit", _registration_evidence,
            "signed-originals", _registration_evidence_kernel),
        _program("webauthn.registration.finalize", _registration, "read-acquisition",
            plan_factory=_registration_plan),
        _program("webauthn.trust.complete", _completion, "read-acquisition",
            plan_factory=_completion_plan),
        _program("webauthn.trust.installation.admit", _installation_evidence,
            "signed-originals", _installation_evidence_kernel),
        _program("webauthn.trust.stage", _stage, "read-acquisition", plan_factory=_stage_plan),
    )
})
