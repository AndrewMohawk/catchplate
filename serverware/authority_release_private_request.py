"""Private nested-JIT projection for the v2 release.reserve facade only.

This is profile grammar and original-byte binding, NOT policy, caller, custody
or release admission. Every original parent argument is retained or committed;
only the child's URL and two review documents move to the private channel.
The public parent contains a child JIT-v2 commitment object without a nested
businessIntent. Neither parent nor child authority request/opaque lookup IDs
are created here. No signed input is rewritten, and the public raw-input
refusal remains applicable until genuine compound execution is implemented.

Intentionally public operation_context, quotas and durable policy claims are
copied as bounded JSON, not scrubbed or admitted. Their existing release owner
must validate their semantics and current authority before any state changes.
"""
from __future__ import annotations

from collections.abc import Mapping
from functools import wraps
import hashlib
from typing import Any

from serverware import authority_contract as contract
from serverware import authority_jit_private_request as child
from serverware import authority_jit_request as raw_child
from serverware import authority_transition_core as core
from serverware import release_authorization_profiles as profiles


OPERATION = "release.reserve"
HANDLER = "reserve_release_authorization_v2"
INPUT_SCHEMA = "serverware.policyAuthorityPrivateReleaseWriterInput/v1"
PUBLIC_SCHEMA = "serverware.releaseReserveCommitments/v1"
ERROR = "Private release input is invalid"
FIELDS = frozenset({
    "attempt_id", "flow_id", "principal_id", "route_id", "credential_id",
    "credential_version", "policy_hash", "request_digest", "operation_digest",
    "operation_context", "shared_quotas", "require_jit_grant",
    "reservation_ttl_seconds", "durable_policy_binding", "jit_approval_request",
    "now_epoch_ms", "actor_id", "authority_policy_hash", "authority_route_id",
    "required_approver_roles", "allowed_approver_ids", "require_approver_webauthn",
    "approval_threshold", "approver_credential_policy", "native_profile",
    "policy_aware_profile", "expected_approver_policy_sha256",
})
NESTED_FIELDS = frozenset({
    "method", "url", "canonical_request", "redacted_display",
    "pending_ttl_seconds", "grant_ttl_seconds", "grant_max_uses",
})
INHERITED_FIELDS = raw_child.FIELDS - NESTED_FIELDS
PRIVATE_FIELDS = child.PRIVATE_FIELDS
PUBLIC_FIELDS = FIELDS | {"schema", "original_arguments_digest"}
_ENVELOPE_FIELDS = frozenset({
    "schema", "handler", "operationManifestDigest", "arguments", "privateDocuments",
})
_SIGNED_BIGINT_MAX = 2**63 - 1


def _require(condition: bool) -> None:
    if not condition:
        raise core.TransitionKernelError(ERROR)


def _checked(function):
    @wraps(function)
    def checked(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except (core.TransitionKernelError, ValueError, TypeError, KeyError,
                OverflowError, RecursionError):
            # Never include private values, parser details or chained messages.
            raise core.TransitionKernelError(ERROR) from None
    return checked


def _sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _copy_fields(value: Mapping[str, Any], fields: frozenset[str], *,
                 nested_fields: frozenset[str] | None = None) -> dict[str, Any]:
    _require(isinstance(value, Mapping) and set(value) == fields)
    # Do not unmarshal tagged-looking keys inside the review JSON documents.
    # The explicit parent slot is not an extra document nesting level: each
    # child field retains the standalone private-JIT depth-zero contract.
    owned = {key: (_copy_fields(value[key], nested_fields)
        if key == "jit_approval_request" and nested_fields is not None
        else raw_child._json(value[key])) for key in fields}
    _require(len(core.canonical_bytes(owned)) <= contract.MAX_REQUEST_BYTES)
    return owned


def _parent_grammar(parent: Mapping[str, Any], normalized_child: Mapping[str, Any]) -> None:
    _require(parent["require_jit_grant"] is True)
    representation = profiles.representation(native=parent["native_profile"],
        policy_aware=parent["policy_aware_profile"])
    for name in ("attempt_id", "policy_hash", "request_digest", "operation_digest"):
        core.require_digest(parent[name], "release binding")
    core.require_text(parent["flow_id"], "release flow")
    _require(parent["flow_id"] == parent["attempt_id"])
    core.require_text(parent["actor_id"], "release actor")
    core.require_integer(parent["reservation_ttl_seconds"], "release TTL", minimum=1, maximum=300)
    if parent["now_epoch_ms"] is not None:
        core.require_integer(parent["now_epoch_ms"], "release original time",
            minimum=0, maximum=_SIGNED_BIGINT_MAX)
    # These are original public claims, not authenticated policy or a new
    # duplicate implementation of the existing release-state validators.
    for name in ("operation_context", "durable_policy_binding"):
        _require(isinstance(parent[name], Mapping))
    _require(len(core.canonical_bytes(parent["operation_context"])) <= 64 * 1024)
    quotas = parent["shared_quotas"]
    # Same query-set bound as authority_transition_release._reserve_quotas;
    # the database's quota normalization alone is not this authority bound.
    _require(type(quotas) is list and len(quotas) <= 12
        and all(isinstance(value, Mapping) for value in quotas))
    _require((parent["authority_policy_hash"] is None) == (parent["authority_route_id"] is None))
    if parent["authority_policy_hash"] is not None:
        _require(parent["authority_policy_hash"] == parent["policy_hash"]
            and parent["authority_route_id"] == parent["route_id"])
    policy = normalized_child["approver_policy"]
    if representation != "legacy":
        profiles.require_versioned_approver_policy(policy)
        core.require_digest(parent["expected_approver_policy_sha256"], "release prepared policy")
        _require(parent["expected_approver_policy_sha256"] == profiles.approver_policy_sha256(policy))
    else:
        _require(parent["expected_approver_policy_sha256"] is None)


def _public(arguments: Mapping[str, Any], *, typed: bool) -> dict[str, Any]:
    _require(type(typed) is bool)
    fields = PUBLIC_FIELDS | ({"businessIntent"} if typed else set())
    _require(isinstance(arguments, Mapping) and set(arguments) == fields)
    owned = _copy_fields({key: arguments[key] for key in PUBLIC_FIELDS},
        PUBLIC_FIELDS, nested_fields=child.PUBLIC_FIELDS)
    _require(owned["schema"] == PUBLIC_SCHEMA)
    core.require_digest(owned["original_arguments_digest"], "release original commitment")
    child_public = owned["jit_approval_request"]
    normalized = child.public_arguments(child_public)
    # Join the exact original facade representations, not just normalized
    # policy equivalence. Business principal/route/policy own the child, never
    # the optional authority_* aliases or independently supplied child fields.
    for name in INHERITED_FIELDS:
        _require(core.canonical_bytes(owned[name]) == core.canonical_bytes(child_public[name]))
    _parent_grammar(owned, normalized)
    public = {key: owned[key] for key in PUBLIC_FIELDS}
    # Also rejects any caller-supplied nested businessIntent, including one
    # hidden inside intentionally public JSON. Only the parent intent is added
    # later by its existing authority request owner.
    intent = contract.synthesize_business_intent(OPERATION, public)
    if typed:
        # Its wrapper does not reduce the already validated public fields'
        # depth allowance. Bound and copy its closed arguments at those same
        # roots before serialization (cycles/invalid JSON still fail closed).
        supplied = arguments["businessIntent"]
        _require(isinstance(supplied, Mapping) and set(supplied) == set(intent))
        for name in set(intent) - {"arguments"}:
            _require(type(supplied[name]) is str and supplied[name] == intent[name])
        intent_arguments = _copy_fields(supplied["arguments"], PUBLIC_FIELDS,
            nested_fields=child.PUBLIC_FIELDS)
        _require(core.canonical_bytes(intent_arguments) == core.canonical_bytes(public))
        # Return our owned synthesized intent, never a caller DTO alias.
        owned["businessIntent"] = intent
        _require(len(core.canonical_bytes(owned)) <= contract.MAX_REQUEST_BYTES)
    return owned


def _prepare(arguments: Mapping[str, Any]) -> dict[str, Any]:
    original = _copy_fields(arguments, FIELDS, nested_fields=NESTED_FIELDS)
    nested = original["jit_approval_request"]
    # Reject an already typed/signed graph before any projection. In particular
    # private documents cannot smuggle a nested businessIntent into the input.
    contract.synthesize_business_intent(OPERATION, original)
    derived_child = {name: original[name] for name in INHERITED_FIELDS}
    derived_child.update(nested)
    child_input = child.prepare(derived_child)
    public = {**original, "schema": PUBLIC_SCHEMA,
        "original_arguments_digest": _sha(core.canonical_bytes(original)),
        "jit_approval_request": child_input["arguments"]}
    public = _public(public, typed=False)
    envelope = {"schema": INPUT_SCHEMA, "handler": HANDLER,
        "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST,
        "arguments": public, "privateDocuments": child_input["privateDocuments"]}
    _require(len(core.canonical_bytes(envelope)) <= contract.MAX_REQUEST_BYTES)
    return envelope


@_checked
def prepare(marshaled_raw_args: Mapping[str, Any]) -> dict[str, Any]:
    """Project only an unsigned exact v2 facade input with new nested JIT."""
    return _prepare(marshaled_raw_args)


@_checked
def validate_runtime_input(envelope: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Reconstruct all originals and recheck both child and whole-parent hashes.

    Return owned public/private channels. Matching hashes are not custody or
    caller evidence; the private channel must not reach a planner or writer.
    """
    _require(isinstance(envelope, Mapping) and set(envelope) == _ENVELOPE_FIELDS)
    _require(envelope["schema"] == INPUT_SCHEMA and envelope["handler"] == HANDLER
        and envelope["operationManifestDigest"] == contract.OPERATION_MANIFEST_DIGEST)
    public = _public(envelope["arguments"], typed=False)
    private = _copy_fields(envelope["privateDocuments"], PRIVATE_FIELDS)
    reconstructed = {key: public[key] for key in FIELDS}
    reconstructed["jit_approval_request"] = {
        key: public["jit_approval_request"][key] for key in NESTED_FIELDS - PRIVATE_FIELDS}
    reconstructed["jit_approval_request"].update(private)
    expected = _prepare(reconstructed)
    # Canonical byte equality distinguishes booleans/integers and binds every
    # parent field, including fields excluded by the release business binding.
    _require(core.canonical_bytes(public) == core.canonical_bytes(expected["arguments"]))
    return expected["arguments"], expected["privateDocuments"]


@_checked
def public_arguments(arguments: Mapping[str, Any], *, typed: bool = False) -> dict[str, Any]:
    """Return an owned public projection, with optional exact parent intent.

    Without originals, their digests remain claims. This does not derive child
    opaque identities, produce a public authority request or admit execution.
    """
    return _public(arguments, typed=typed)
