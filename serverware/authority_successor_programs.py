"""Source-fixed factories for authenticated successor planning paths.

These owners require configured keys and original invocation work; they are
not legacy TransitionKernel adapters. Registration describes available source
paths, not admission, reservation, or business execution authority. Imports
stay lazy so the actual read owners can use planner primitives without an
import-time registry cycle.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable, Final, Mapping

from serverware import authority_contract


@dataclass(frozen=True, slots=True)
class SuccessorPlanningProgram:
    operation: str
    handler: str
    program_id: str
    planning_mode: str
    result_kind: str
    factory: Callable[..., object]
    kernel_factory: Callable[..., object] | None = None


def _revocation(*, read_dsn, connect_timeout_seconds, database_identity,
        planner_private_key, planner_public_key, verifier_public_key,
        expected_verifier_identity, maximum_assertion_age_ns,
        maximum_plan_age_ns, maximum_clock_skew_ns):
    from serverware.authority_revocation_planning import RevocationObservedPlanner

    return RevocationObservedPlanner(read_dsn=read_dsn,
        connect_timeout_seconds=connect_timeout_seconds, database_identity=database_identity,
        planner_private_key=planner_private_key, planner_public_key=planner_public_key,
        verifier_public_key=verifier_public_key, expected_verifier_identity=expected_verifier_identity,
        maximum_assertion_age_ns=maximum_assertion_age_ns,
        maximum_plan_age_ns=maximum_plan_age_ns, maximum_clock_skew_ns=maximum_clock_skew_ns)


def _evidence_owner(operation, *, read_planner, planner_private_key, planner_public_key,
        expected_planner_identity, expected_planner_spki_digest, configuration_digest):
    from serverware import authority_webauthn_evidence_plan_owner as owner
    from serverware import authority_webauthn_evidence_planning as planning

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
    from serverware.authority_webauthn_evidence_kernel import EvidenceAdmissionKernel

    return EvidenceAdmissionKernel(operation="webauthn.registration.evidence.admit",
        public_key=public_key, expected_identity=expected_identity,
        expected_spki_digest=expected_spki_digest, maximum_age_ns=maximum_age_ns,
        maximum_clock_skew_ns=maximum_clock_skew_ns, rp_id=rp_id, origin=origin,
        installation_target_digest=installation_target_digest)


def _installation_evidence_kernel(*, public_key, expected_identity, expected_spki_digest,
        maximum_age_ns, maximum_clock_skew_ns, rp_id, origin, installation_target_digest):
    from serverware.authority_webauthn_evidence_kernel import EvidenceAdmissionKernel

    return EvidenceAdmissionKernel(operation="webauthn.trust.installation.admit",
        public_key=public_key, expected_identity=expected_identity,
        expected_spki_digest=expected_spki_digest, maximum_age_ns=maximum_age_ns,
        maximum_clock_skew_ns=maximum_clock_skew_ns, rp_id=rp_id, origin=origin,
        installation_target_digest=installation_target_digest)


def _registration(*, read_dsn, connect_timeout_seconds, database_identity,
        evidence_public_key, expected_signer_identity, expected_signer_spki_digest,
        expected_rp_id, expected_origin, maximum_age_ns, maximum_clock_skew_ns):
    from serverware.authority_webauthn_transition_planning import RegistrationTransitionPlanner

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
    from serverware.authority_webauthn_transition_planning import TrustStageTransitionPlanner

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
    from serverware.authority_webauthn_transition_planning import TrustCompletionTransitionPlanner

    return TrustCompletionTransitionPlanner(read_dsn=read_dsn,
        connect_timeout_seconds=connect_timeout_seconds, database_identity=database_identity,
        installer_public_key=installer_public_key, expected_installer_identity=expected_installer_identity,
        expected_installer_spki_digest=expected_installer_spki_digest,
        installation_target_digest=installation_target_digest,
        maximum_age_ns=maximum_age_ns, maximum_clock_skew_ns=maximum_clock_skew_ns)


def _program(operation, factory, result_kind, kernel_factory=None):
    return SuccessorPlanningProgram(operation=operation,
        handler=authority_contract.operation_spec(operation)["handler"],
        program_id=authority_contract.transition_program_id(operation),
        planning_mode="typed-successor-planning", result_kind=result_kind,
        factory=factory, kernel_factory=kernel_factory)


PROGRAMS: Final[Mapping[str, SuccessorPlanningProgram]] = MappingProxyType({
    program.operation: program for program in (
        _program("webauthn.credential.revoke", _revocation, "signed-originals"),
        _program("webauthn.registration.evidence.admit", _registration_evidence,
            "signed-originals", _registration_evidence_kernel),
        _program("webauthn.registration.finalize", _registration, "read-acquisition"),
        _program("webauthn.trust.complete", _completion, "read-acquisition"),
        _program("webauthn.trust.installation.admit", _installation_evidence,
            "signed-originals", _installation_evidence_kernel),
        _program("webauthn.trust.stage", _stage, "read-acquisition"),
    )
})
