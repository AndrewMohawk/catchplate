"""Pure JIT validation and projection, not custody or approval admission.

The legacy raw projection validates the facade's originals before commitment.
The current private-v2 ingress then places only their public commitments into
the authority request and businessIntent. Durable retention refuses raw input;
neither profile is rewritten after signing. This projection supplies commitments
and deterministic *lookup* identities only; it does not produce opaque custody,
approve a request, or initialize an aggregate.
The current production route helper supplies an explicit RP/origin policy. Its
legacy optional-policy callers are not admitted here: reading process settings
would make a deterministic transition depend on unsigned mutable configuration.
RP/origin syntax is checked here, not their authority/currentness. The existing
reader, assertion verifier and decision/writer checks still own those checks.
"""
from __future__ import annotations

import hashlib
import math
from collections.abc import Mapping
from typing import Any

from serverware import authority_approver_policy as policies
from serverware import authority_contract as contract
from serverware import authority_transition_core as core
from serverware.rbac import normalize_rbac_roles


OPERATION = "jit.request"
FIELDS = frozenset({
    "route_id", "method", "url", "principal_id", "credential_id",
    "credential_version", "policy_hash", "request_digest", "operation_digest",
    "canonical_request", "redacted_display", "pending_ttl_seconds",
    "grant_ttl_seconds", "grant_max_uses", "required_approver_roles",
    "allowed_approver_ids", "require_approver_webauthn", "approval_threshold",
    "approver_credential_policy",
})
MAX_PAYLOAD_BYTES = 64 * 1024
CANONICAL_OPAQUE_PURPOSE = "jit-canonical-request"
DISPLAY_OPAQUE_PURPOSE = "jit-redacted-display"
_CREDENTIAL_FIELDS = frozenset({
    "allowedCredentialRecordIds", "allowedAuthenticatorClasses", "allowedAaguids",
    "requireAttestationTrusted", "requiredTrustBundleDigest", "minimumTrustBundleSequence",
    "counterPolicy", "maxAssertionAgeSeconds", "rpId", "origins",
    "requireUserPresence", "requireUserVerification",
})


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise core.TransitionKernelError(message)


def _json(value: Any, *, depth: int = 0) -> Any:
    """Copy JSON without interpreting tagged-looking document keys as types."""
    _require(depth <= core.MAX_ARGUMENT_DEPTH, "JIT JSON nesting exceeds its bound")
    if value is None or type(value) in (bool, int, str):
        return value
    if type(value) is float:
        _require(math.isfinite(value), "JIT JSON number is not finite")
        return value
    if type(value) is list:
        return [_json(item, depth=depth + 1) for item in value]
    if isinstance(value, Mapping):
        _require(all(type(key) is str for key in value), "JIT JSON keys are not text")
        return {key: _json(item, depth=depth + 1) for key, item in value.items()}
    raise core.TransitionKernelError("JIT document is not JSON")


def _collection(value: Any, *, set_only: bool = False) -> list[str]:
    if type(value) is list and not set_only:
        items = value
    else:
        _require(isinstance(value, Mapping)
            and set(value) == {"$authorityType", "items"}
            and value["$authorityType"] in (("set",) if set_only else ("set", "tuple"))
            and type(value["items"]) is list,
            "JIT policy collection is not the facade representation")
        items = value["items"]
        if value["$authorityType"] == "set":
            _require(all(type(item) is str for item in items), "JIT policy set is not text")
            _require(items == sorted(set(items), key=core.canonical_bytes),
                "JIT policy set is not canonical")
    _require(all(type(item) is str for item in items), "JIT policy collection is not text")
    return list(items)


def _policy(arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Match db's policy defaults/normalization, with explicit RP/origin only."""
    roles = arguments["required_approver_roles"]
    roles = [] if roles is None else _collection(roles, set_only=True)
    roles = normalize_rbac_roles(roles, require_nonempty=False)
    allowed = arguments["allowed_approver_ids"]
    allowed_ids = [] if allowed is None else sorted(_collection(allowed, set_only=True))
    credential = arguments["approver_credential_policy"]
    _require(isinstance(credential, Mapping)
        and {"rpId", "origins"} <= set(credential) <= _CREDENTIAL_FIELDS,
        "JIT credential policy requires explicit relying-party fields")
    normalized = {
        "allowedCredentialRecordIds": [],
        "allowedAuthenticatorClasses": ["hardware", "yubikey"],
        "allowedAaguids": [],
        "requireAttestationTrusted": True,
        "requiredTrustBundleDigest": None,
        "minimumTrustBundleSequence": None,
        "counterPolicy": "strict-or-zero",
        "maxAssertionAgeSeconds": 30,
        "requireUserPresence": True,
        "requireUserVerification": True,
        **dict(credential),
    }
    for name in ("allowedCredentialRecordIds", "allowedAuthenticatorClasses", "allowedAaguids"):
        normalized[name] = sorted(set(_collection(normalized[name])))
    # Unlike the unordered policy lists, origins is the exact one-element JSON
    # list that the existing configured-policy normalizer produces and accepts.
    normalized["origins"] = _json(normalized["origins"])
    policy = {
        "schema": policies.JIT_SCHEMA,
        "requiredRoles": roles,
        "roleMatch": "any",
        "allowedApproverIds": allowed_ids,
        "allowAnyApproverId": allowed is None,
        "requireWebAuthn": arguments["require_approver_webauthn"],
        "threshold": arguments["approval_threshold"],
        "credentialPolicy": normalized,
    }
    # Reuse the existing closed policy validator. This projection digest is NOT
    # substituted for the stored JIT-domain digest or used as RP authority.
    policies.from_jit_policy(policy)
    return policy


def normalize(arguments: Mapping[str, Any], *, request_digest: str) -> dict[str, Any]:
    """Return kernel-local fields; never rewrite the signed input or its digest.

    request_digest is the immutable authority envelope digest, not the inner
    provider request_digest. Only the former seeds deterministic opaque IDs.
    Existing opaque bindings continue to use the latter and the document hash.
    """
    try:
        from serverware import authority_jit_private_request as private

        if isinstance(arguments, Mapping) and arguments.get("schema") == private.PUBLIC_SCHEMA:
            return private.public_arguments(arguments, typed=True, request_digest=request_digest)
        return _normalize(arguments, request_digest=request_digest)
    except core.TransitionKernelError:
        raise
    except (ValueError, TypeError, OverflowError, RecursionError):
        raise core.TransitionKernelError("JIT request facade projection is invalid") from None


def require_public_request(request: Mapping[str, Any]) -> None:
    """Require the explicit private-input profile before durable JIT retention.

    This validates public commitments, not native sealing or authorization.
    Raw v1 arguments are still understood by the isolated legacy projection,
    but cannot enter a new signed plan or execution envelope. Never transform
    an already committed request here: the facade/service must select v2 before
    creating its business intent and request digest.
    """
    from serverware import authority_jit_private_request as private
    from serverware import authority_request_commitment as commitment

    _require(isinstance(request, Mapping) and set(request) == {
        "schema", "operation", "operationId", "requestDigest", "handler",
        "operationManifestDigest", "arguments"}
        and request.get("schema") == "serverware.policyAuthorityV9Request/v1"
        and request.get("operation") == OPERATION,
        "JIT durable request requires its exact public envelope")
    private.public_arguments(request["arguments"], typed=True,
        request_digest=request["requestDigest"])
    try:
        digest = commitment._typed_request_digest(request, work=None)
    except commitment.AuthorityPlannerError:
        raise core.TransitionKernelError("JIT public request commitment is invalid") from None
    _require(request["requestDigest"] == digest
        and request["operationId"] == commitment.operation_id(OPERATION, digest),
        "JIT public request commitment differs")


def _normalize(arguments: Mapping[str, Any], *, request_digest: str) -> dict[str, Any]:
    core.require_digest(request_digest, "JIT request envelope")
    _require(isinstance(arguments, Mapping) and set(arguments) == FIELDS | {"businessIntent"},
        "JIT request arguments are not the exact facade fields")
    raw = {name: arguments[name] for name in FIELDS}
    # Validate the original intent, not an intent over the derived projection.
    _require(core.canonical_bytes(arguments["businessIntent"])
        == core.canonical_bytes(contract.synthesize_business_intent(OPERATION, raw)),
        "JIT request business intent differs from raw arguments")
    values = {}
    for name in ("route_id", "method", "url", "principal_id", "credential_id"):
        values[name] = core.require_text(raw[name], "JIT " + name,
            maximum_bytes=32 if name == "method" else MAX_PAYLOAD_BYTES if name == "url" else 512,
            allow_empty=name == "credential_id")
    _require(values["method"] == values["method"].upper(), "JIT method is not canonical uppercase")
    values["credential_version"] = core.require_integer(raw["credential_version"],
        "JIT credential version", minimum=0, maximum=2**63 - 1)
    for name in ("policy_hash", "request_digest", "operation_digest"):
        values[name] = None if name == "operation_digest" and raw[name] is None else (
            core.require_digest(raw[name], "JIT " + name))
    for name in ("pending_ttl_seconds", "grant_ttl_seconds", "grant_max_uses"):
        values[name] = core.require_integer(raw[name], "JIT " + name, minimum=1,
            maximum=1_000_000 if name == "grant_max_uses" else 3600)
    documents = {}
    for name in ("canonical_request", "redacted_display"):
        _require(isinstance(raw[name], Mapping), "JIT review documents must be objects")
        documents[name] = core.canonical_bytes(_json(raw[name]))
    policy = _policy(raw)
    policy_bytes = core.canonical_bytes(policy)
    # Same aggregate bound as _validate_pending_approval_payload, not two
    # independent 64 KiB document allowances.
    payload_bytes = sum(len((values[name] or "").encode("utf-8")) for name in (
        "route_id", "method", "url", "principal_id", "credential_id",
        "policy_hash", "request_digest", "operation_digest"))
    _require(payload_bytes + sum(map(len, documents.values())) + len(policy_bytes) <= MAX_PAYLOAD_BYTES,
        "JIT pending approval payload exceeds 64 KiB")
    values["url_commitment"] = "sha256:" + hashlib.sha256(values.pop("url").encode("utf-8")).hexdigest()
    for name, purpose in (("canonical_request", CANONICAL_OPAQUE_PURPOSE),
            ("redacted_display", DISPLAY_OPAQUE_PURPOSE)):
        values[name + "_digest"] = "sha256:" + hashlib.sha256(documents[name]).hexdigest()
        values[name + "_opaque_id"] = core.deterministic_uuid(
            operation=OPERATION, request_digest=request_digest, purpose=purpose)
    values["approver_policy"] = policy
    values["approver_policy_digest"] = core.framed_digest(policies.JIT_SCHEMA, policy_bytes)
    values["businessIntent"] = arguments["businessIntent"]
    return values
