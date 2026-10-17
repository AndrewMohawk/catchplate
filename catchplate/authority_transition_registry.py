from __future__ import annotations

from types import MappingProxyType
from typing import Final, Mapping

from catchplate import authority_contract
from catchplate import authority_successor_programs
from catchplate import authority_transition_core
from catchplate import authority_transition_policy
from catchplate import authority_transition_policy_candidate
from catchplate import authority_transition_setup_policy
from catchplate import authority_transition_setup_cancel
from catchplate import authority_transition_setup_create
from catchplate import authority_transition_setup_bind_credential
from catchplate import authority_transition_static_credential_create
from catchplate import authority_transition_static_credential_approval
from catchplate import authority_transition_static_credential_rotate
from catchplate import authority_transition_static_credential_rotation_approval
from catchplate import authority_transition_setup_native_enrollment
from catchplate import authority_transition_setup_native_ca
from catchplate import authority_transition_setup_native_canary
from catchplate import authority_transition_setup_native_runtime
from catchplate import authority_transition_setup_native_hardware
from catchplate import authority_transition_setup_native_final
from catchplate import authority_transition_policy_canary
from catchplate import authority_transition_policy_canary_delivery
from catchplate import authority_transition_policy_native_activation
from catchplate import authority_transition_quota
from catchplate import authority_transition_release
from catchplate import authority_transition_publication_approval
from catchplate import authority_transition_oauth_activation
from catchplate import authority_transition_oauth_exchange
from catchplate import authority_transition_oauth_measured_exchange
from catchplate import authority_transition_oauth_setup
from catchplate import authority_transition_oauth_reconnect
from catchplate import authority_transition_oauth_retirement_succession
from catchplate import authority_transition_oauth_refresh
from catchplate import authority_transition_oauth_measured_refresh
from catchplate import authority_transition_oauth_measured_cleanup
from catchplate import authority_transition_oauth_measured_pending_retirement
from catchplate import authority_transition_oauth_measured_capture_retirement
from catchplate import authority_transition_credential_currentness
from catchplate import authority_transition_oauth_revocation
from catchplate import authority_transition_oauth_refresh_cleanup
from catchplate import authority_transition_policy_file_approval
from catchplate import authority_transition_public_revocation_approval


WEBAUTHN_CHALLENGE_OPERATIONS: Final[frozenset[str]] = frozenset(
    {
        "webauthn.challenge.create",
        "webauthn.challenge.claim",
        "webauthn.challenge.consume",
    }
)
INTENTIONALLY_DISABLED_OPERATIONS: Final[frozenset[str]] = (
    authority_contract.INTENTIONALLY_DISABLED_OPERATIONS
)


def _merge_kernels() -> dict[
    str, authority_transition_core.TransitionKernel
]:
    merged: dict[str, authority_transition_core.TransitionKernel] = {}
    for registry in (
        authority_transition_policy.KERNELS,
        authority_transition_policy_candidate.KERNELS,
        authority_transition_setup_policy.KERNELS,
        authority_transition_setup_cancel.KERNELS,
        authority_transition_setup_create.KERNELS,
        authority_transition_setup_bind_credential.KERNELS,
        authority_transition_static_credential_create.KERNELS,
        authority_transition_static_credential_approval.KERNELS,
        authority_transition_static_credential_rotate.KERNELS,
        authority_transition_static_credential_rotation_approval.KERNELS,
        authority_transition_setup_native_enrollment.KERNELS,
        authority_transition_setup_native_ca.KERNELS,
        authority_transition_setup_native_canary.KERNELS,
        authority_transition_setup_native_runtime.KERNELS,
        authority_transition_setup_native_hardware.KERNELS,
        authority_transition_setup_native_final.KERNELS,
        authority_transition_policy_canary.KERNELS,
        authority_transition_policy_canary_delivery.KERNELS,
        authority_transition_policy_native_activation.KERNELS,
        authority_transition_quota.KERNELS,
        authority_transition_release.KERNELS,
        authority_transition_publication_approval.KERNELS,
        authority_transition_oauth_activation.KERNELS,
        authority_transition_oauth_exchange.KERNELS,
        authority_transition_oauth_measured_exchange.KERNELS,
        authority_transition_oauth_setup.KERNELS,
        authority_transition_oauth_reconnect.KERNELS,
        authority_transition_oauth_retirement_succession.KERNELS,
        authority_transition_oauth_refresh.KERNELS,
        authority_transition_oauth_measured_refresh.KERNELS,
        authority_transition_oauth_measured_cleanup.KERNELS,
        authority_transition_oauth_measured_pending_retirement.KERNELS,
        authority_transition_oauth_measured_capture_retirement.KERNELS,
        authority_transition_credential_currentness.KERNELS,
        authority_transition_oauth_revocation.KERNELS,
        authority_transition_oauth_refresh_cleanup.KERNELS,
        authority_transition_policy_file_approval.KERNELS,
        authority_transition_public_revocation_approval.KERNELS,
    ):
        overlap = set(merged) & set(registry)
        if overlap:
            raise RuntimeError(
                "authority transition kernel registries overlap: "
                + ", ".join(sorted(overlap))
            )
        merged.update(registry)
    return merged


KERNELS: Final[
    Mapping[str, authority_transition_core.TransitionKernel]
] = MappingProxyType(_merge_kernels())
INTENTIONALLY_DISABLED_MANIFEST: Final[
    Mapping[str, Mapping[str, object]]
] = MappingProxyType(
    {
        "jit.consume": MappingProxyType(
            {
                "schema":
                    "catchplate.policyAuthorityDisabledOperation/v1",
                "operation": "jit.consume",
                "status": "intentionally-disabled",
                "admissionDisposition": "deny",
                "kernelRegistered": False,
                "code": "atomic-release-authority-required",
                "externalAuthorityRequired": False,
                "details": (
                    "standalone JIT grant consumption is disabled because "
                    "the source commits grant use only with release outcome",
                ),
            }
        ),
        **{
            operation: MappingProxyType(
                {
                    "schema": "catchplate.policyAuthorityDisabledOperation/v1",
                    "operation": operation,
                    "status": "intentionally-disabled",
                    "admissionDisposition": "deny",
                    "kernelRegistered": False,
                    "code": "recovery-not-implemented",
                    "externalAuthorityRequired": False,
                    "details": (
                        "recovery is unavailable until its complete configured "
                        "successor planning and execution path is implemented",
                    ),
                }
            )
            for operation in (
                "webauthn.recovery.create", "webauthn.recovery.candidate",
                "webauthn.recovery.finalize", "webauthn.recovery.expire",
                "webauthn.recovery.prune", "webauthn.recovery.invalidate",
            )
        },
    }
)
LEGACY_PLANNABLE_OPERATIONS: Final[frozenset[str]] = frozenset(
    set(KERNELS) | set(WEBAUTHN_CHALLENGE_OPERATIONS)
)
SUCCESSOR_PROGRAMS: Final[
    Mapping[str, authority_successor_programs.SuccessorPlanningProgram]
] = authority_successor_programs.PROGRAMS
COMPONENT_ONLY_SUCCESSOR_OPERATIONS: Final[frozenset[str]] = frozenset({
    "jit.review-open.authorize", "jit.review-open.receipt.issue",
})
SUCCESSOR_PLANNABLE_OPERATIONS: Final[frozenset[str]] = frozenset(
    set(SUCCESSOR_PROGRAMS) - COMPONENT_ONLY_SUCCESSOR_OPERATIONS
)
# Source-complete planning paths only, not configured admission. The two native
# review entries own real read/replay components but no bounded plan/commit
# owner. Neither they nor a configured successor are interchangeable v3 kernels.
PLANNABLE_OPERATIONS: Final[frozenset[str]] = (
    LEGACY_PLANNABLE_OPERATIONS | SUCCESSOR_PLANNABLE_OPERATIONS
)


_EXPECTED_SUCCESSOR_OPERATIONS = {
    operation for operation in authority_contract.OPERATION_REGISTRY
    if authority_contract.operation_spec(operation)["planningMode"]
        == "typed-successor-planning"
}
_EXPECTED_TRANSITION_OPERATIONS = (
    set(authority_contract.OPERATION_REGISTRY)
    - set(WEBAUTHN_CHALLENGE_OPERATIONS)
    - set(INTENTIONALLY_DISABLED_OPERATIONS)
    - _EXPECTED_SUCCESSOR_OPERATIONS
)


def _registry_closure_errors() -> tuple[str, ...]:
    errors: list[str] = []
    if set(INTENTIONALLY_DISABLED_MANIFEST) != set(INTENTIONALLY_DISABLED_OPERATIONS):
        errors.append("disabled operation manifest coverage differs")
    for operation, manifest in INTENTIONALLY_DISABLED_MANIFEST.items():
        if (manifest.get("operation") != operation
                or manifest.get("status") != "intentionally-disabled"
                or manifest.get("admissionDisposition") != "deny"
                or manifest.get("kernelRegistered") is not False):
            errors.append(f"invalid disabled operation manifest=[{operation}]")
    for label, operations in (
        (
            "missing transition kernels",
            _EXPECTED_TRANSITION_OPERATIONS - set(KERNELS),
        ),
        (
            "unexpected transition kernels",
            set(KERNELS) - _EXPECTED_TRANSITION_OPERATIONS,
        ),
        (
            "missing successor programs",
            _EXPECTED_SUCCESSOR_OPERATIONS - set(SUCCESSOR_PROGRAMS),
        ),
        (
            "unexpected successor programs",
            set(SUCCESSOR_PROGRAMS) - _EXPECTED_SUCCESSOR_OPERATIONS,
        ),
        (
            "legacy and successor planning overlap",
            LEGACY_PLANNABLE_OPERATIONS & SUCCESSOR_PLANNABLE_OPERATIONS,
        ),
        (
            "component-only operations lack successor contracts",
            COMPONENT_ONLY_SUCCESSOR_OPERATIONS - _EXPECTED_SUCCESSOR_OPERATIONS,
        ),
        (
            "component-only operations are plannable",
            COMPONENT_ONLY_SUCCESSOR_OPERATIONS & PLANNABLE_OPERATIONS,
        ),
        (
            "uncovered operation contracts",
            set(authority_contract.OPERATION_REGISTRY)
            - set(PLANNABLE_OPERATIONS) - set(INTENTIONALLY_DISABLED_OPERATIONS)
            - COMPONENT_ONLY_SUCCESSOR_OPERATIONS,
        ),
        (
            "disabled operations are plannable",
            set(PLANNABLE_OPERATIONS)
            & set(INTENTIONALLY_DISABLED_OPERATIONS),
        ),
    ):
        if operations:
            errors.append(f"{label}=[{', '.join(sorted(operations))}]")

    for operation, kernel in sorted(KERNELS.items()):
        # Unknown operations already fail coverage above. Do not hide that
        # diagnostic behind a lookup error from the operation contract.
        if operation not in authority_contract.OPERATION_REGISTRY:
            continue
        spec = authority_contract.operation_spec(operation)
        invalid_fields = tuple(
            label
            for label, valid in (
                ("operation", kernel.operation == operation),
                ("handler", spec["handler"] == kernel.handler),
                (
                    "program-id",
                    authority_contract.transition_program_id(operation)
                    == kernel.program_id,
                ),
                (
                    "permits-empty-mutation",
                    isinstance(kernel.permits_empty_mutation, bool),
                ),
                ("planning-mode", spec["planningMode"] == "typed-pure-transition"),
            )
            if not valid
        )
        if invalid_fields:
            errors.append(
                f"invalid transition kernel {operation}"
                f"=[{', '.join(invalid_fields)}]"
            )

    for operation, program in sorted(SUCCESSOR_PROGRAMS.items()):
        if operation not in authority_contract.OPERATION_REGISTRY:
            continue
        if type(program) is not authority_successor_programs.SuccessorPlanningProgram:
            errors.append(f"invalid successor program type=[{operation}]")
            continue
        evidence_operation = operation in {
            "webauthn.registration.evidence.admit", "webauthn.trust.installation.admit"
        }
        component_only = operation in COMPONENT_ONLY_SUCCESSOR_OPERATIONS
        expected_result = (
            "read-replay-components" if component_only else
            "signed-originals" if evidence_operation or operation in {
                "webauthn.credential.revoke", "webauthn.challenge.maintain",
                "jit.assertion.issue"}
            else "read-acquisition"
        )
        spec = authority_contract.operation_spec(operation)
        invalid_fields = tuple(
            label for label, valid in (
                ("operation", program.operation == operation),
                ("handler", program.handler == spec["handler"]),
                ("program-id", program.program_id == authority_contract.transition_program_id(operation)),
                ("planning-mode", program.planning_mode == spec["planningMode"]
                    == "typed-successor-planning"),
                ("result-kind", program.result_kind == expected_result),
                ("factory", callable(program.factory)),
                ("kernel-factory", callable(program.kernel_factory) if evidence_operation or component_only
                    else program.kernel_factory is None),
                ("plan-factory", callable(program.plan_factory) if expected_result == "read-acquisition"
                    else program.plan_factory is None),
            ) if not valid
        )
        if invalid_fields:
            errors.append(f"invalid successor program {operation}=[{', '.join(invalid_fields)}]")

    for operations, expected_mode in (
        (WEBAUTHN_CHALLENGE_OPERATIONS, "typed-webauthn-challenge"),
        (INTENTIONALLY_DISABLED_OPERATIONS, "intentionally-disabled"),
    ):
        for operation in sorted(operations):
            if operation not in authority_contract.OPERATION_REGISTRY:
                errors.append(f"missing operation contract=[{operation}]")
            elif (
                authority_contract.operation_spec(operation)["planningMode"]
                != expected_mode
            ):
                errors.append(f"invalid planning mode=[{operation}]")
    return tuple(errors)


def successor_program(operation: str) -> authority_successor_programs.SuccessorPlanningProgram:
    """Select a fixed configured owner; never fall back to legacy planning."""
    if type(operation) is not str or operation not in SUCCESSOR_PLANNABLE_OPERATIONS:
        raise ValueError("operation has no source-registered successor planning program")
    return SUCCESSOR_PROGRAMS[operation]


_CLOSURE_ERRORS = _registry_closure_errors()
if _CLOSURE_ERRORS:
    raise RuntimeError(
        "authority transition registry is not closed: "
        + "; ".join(_CLOSURE_ERRORS)
    )
