from __future__ import annotations

from types import MappingProxyType
from typing import Final, Mapping

from serverware import authority_contract
from serverware import authority_transition_core
from serverware import authority_transition_policy
from serverware import authority_transition_quota
from serverware import authority_transition_release


WEBAUTHN_CHALLENGE_OPERATIONS: Final[frozenset[str]] = frozenset(
    {
        "webauthn.challenge.create",
        "webauthn.challenge.claim",
        "webauthn.challenge.consume",
    }
)
INTENTIONALLY_DISABLED_OPERATIONS: Final[frozenset[str]] = frozenset(
    {"jit.consume"}
)


def _merge_kernels() -> dict[
    str, authority_transition_core.TransitionKernel
]:
    merged: dict[str, authority_transition_core.TransitionKernel] = {}
    for registry in (
        authority_transition_policy.KERNELS,
        authority_transition_quota.KERNELS,
        authority_transition_release.KERNELS,
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
                    "serverware.policyAuthorityDisabledOperation/v1",
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
        )
    }
)
PLANNABLE_OPERATIONS: Final[frozenset[str]] = frozenset(
    set(KERNELS) | set(WEBAUTHN_CHALLENGE_OPERATIONS)
)


_EXPECTED_TRANSITION_OPERATIONS = (
    set(authority_contract.OPERATION_REGISTRY)
    - set(WEBAUTHN_CHALLENGE_OPERATIONS)
    - set(INTENTIONALLY_DISABLED_OPERATIONS)
)


def _registry_closure_errors() -> tuple[str, ...]:
    errors: list[str] = []
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


_CLOSURE_ERRORS = _registry_closure_errors()
if _CLOSURE_ERRORS:
    raise RuntimeError(
        "authority transition registry is not closed: "
        + "; ".join(_CLOSURE_ERRORS)
    )
