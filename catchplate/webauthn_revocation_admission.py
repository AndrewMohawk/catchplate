"""Unactivated standalone self-revocation client; not the aggregate HTTP endpoint.

This adapter accepts semantic address hints and a raw browser assertion. It
cannot accept transaction results, mutation plans, verified receipts, injected
connections or caller-built businessIntent. The authority service derives all
of those and the measured planner checks the complete dependency predicates.
No admin, offline recovery, or trust-withdrawal behavior is exposed here.
The candidate kernel is intentionally absent from the operation registry, so
the real service cannot admit this operation until completeness is established.
"""
from __future__ import annotations

from typing import Any, Mapping

from catchplate import authority_transition_core as core
from catchplate.authority_transition_webauthn import OPERATION, prepare_revocation_input


def _dispatch(operation: str, value: Mapping[str, Any]) -> dict[str, Any]:
    from catchplate import db

    return db.dispatch_policy_authority_operation(operation, value)


def issue_self_revocation_challenge(
    *, arguments: Mapping[str, Any], user_id: str, credential_id: str,
) -> dict[str, Any]:
    values = prepare_revocation_input(arguments)
    if user_id != values["actor_id"]:
        raise core.TransitionKernelError("revocation challenge actor changed")
    core.require_text(credential_id, "authorizing credential", maximum_bytes=4096)
    # Deliberately use the v9 semantic shape, not the legacy handler signature
    # adapter (which cannot carry the exact cascade address sets).
    return _dispatch("webauthn.challenge.create", {
        "operation": OPERATION, "input": values,
        "userId": user_id, "credentialId": credential_id,
    })


def revoke_own_credential(
    *, arguments: Mapping[str, Any], webauthn_authorization: Mapping[str, Any],
) -> dict[str, Any]:
    values = prepare_revocation_input(arguments)
    if not isinstance(webauthn_authorization, Mapping):
        raise core.TransitionKernelError("raw revocation assertion is absent")
    reference = dict(webauthn_authorization)
    if (
        set(reference) not in (
            {"challengeId", "credentialId", "assertion"},
            {"challengeId", "credentialRecordId", "assertion"},
        )
        or not isinstance(reference.get("assertion"), Mapping)
        or set(reference["assertion"]) != {
            "credentialId", "clientDataJSON", "authenticatorData", "signature",
        }
    ):
        raise core.TransitionKernelError("raw revocation assertion fields are not exact")
    core.require_text(reference["challengeId"], "assertion challenge", maximum_bytes=1024)
    for field in ("credentialId", "credentialRecordId"):
        if field in reference:
            core.require_text(reference[field], field, maximum_bytes=4096)
    assertion = dict(reference["assertion"])
    for field, value in assertion.items():
        core.require_text(value, field, maximum_bytes=4 * 1024 * 1024)
    reference["assertion"] = assertion
    return _dispatch(OPERATION, {
        "input": values, "webauthnAuthorization": reference,
    })
