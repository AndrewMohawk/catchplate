"""Typed dispatch-only facade entrypoints for the two evidence admission ops.

These functions submit semantic locators through the real runtime dispatcher.
They do not insert evidence, accept row/proof/connection authority, or construct
execution capabilities. The database facade installs its existing controlled
writer wrappers around these exact signatures; registry and typed admission
remain mandatory. Completing this callable surface does not activate the
successor evidence-plan execution protocol or make retained plans executable.

The unwrapped bodies also use the real dispatcher, whose privileged-process
guard prevents an executor-context fallback to a second Python write path.
"""
from __future__ import annotations

from typing import Any

from catchplate import authority_contract as authority


_REGISTRATION = "webauthn.registration.evidence.admit"
_INSTALLATION = "webauthn.trust.installation.admit"


def _dispatch(operation: str, arguments: dict[str, Any]) -> dict[str, Any]:
    # Import only when called, after the facade has installed its real guards.
    # The helper accepts no replacement dispatcher or operation callback.
    from catchplate import db

    if operation not in (_REGISTRATION, _INSTALLATION):
        raise db.MetadataStoreError("evidence entrypoint operation is not source fixed")
    try:
        authority.synthesize_business_intent(operation, arguments)
    except ValueError as exc:
        raise db.MetadataStoreError("evidence entrypoint arguments are not canonical") from exc
    return db.dispatch_policy_authority_operation(operation, {
        "schema": "catchplate.policyAuthorityControlledWriterInput/v1",
        "handler": authority.operation_spec(operation)["handler"],
        "operationManifestDigest": authority.OPERATION_MANIFEST_DIGEST,
        "arguments": arguments,
    })


def admit_webauthn_registration_evidence(*, evidence_digest: str,
        registration_challenge_id: str, published_publication_id: str,
        oidc_session_id: str | None = None) -> dict[str, Any]:
    """Dispatch registration evidence admission; return the real result unchanged."""
    return _dispatch(_REGISTRATION, {
        "evidence_digest": evidence_digest,
        "registration_challenge_id": registration_challenge_id,
        "published_publication_id": published_publication_id,
        "oidc_session_id": oidc_session_id,
    })


def admit_webauthn_trust_installation_evidence(*, evidence_digest: str,
        publication_id: str) -> dict[str, Any]:
    """Dispatch installation evidence admission without performing an INSERT."""
    return _dispatch(_INSTALLATION, {
        "evidence_digest": evidence_digest,
        "publication_id": publication_id,
    })
