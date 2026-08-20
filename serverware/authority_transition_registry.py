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
                "authority transition kernel registries overlap"
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
if (
    set(KERNELS) != _EXPECTED_TRANSITION_OPERATIONS
    or set(PLANNABLE_OPERATIONS)
    & set(INTENTIONALLY_DISABLED_OPERATIONS)
    or any(
        kernel.operation != operation
        or authority_contract.operation_spec(operation)["handler"]
            != kernel.handler
        or authority_contract.transition_program_id(operation)
            != kernel.program_id
        or not isinstance(kernel.permits_empty_mutation, bool)
        or authority_contract.operation_spec(operation)["planningMode"]
            != "typed-pure-transition"
        for operation, kernel in KERNELS.items()
    )
    or any(
        authority_contract.operation_spec(operation)["planningMode"]
            != "typed-webauthn-challenge"
        for operation in WEBAUTHN_CHALLENGE_OPERATIONS
    )
    or any(
        authority_contract.operation_spec(operation)["planningMode"]
            != "intentionally-disabled"
        for operation in INTENTIONALLY_DISABLED_OPERATIONS
    )
):
    raise RuntimeError("authority transition registry is not closed")
