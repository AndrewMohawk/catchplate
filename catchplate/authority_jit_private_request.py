"""Versioned private JIT ingress, not encryption or custody admission.

Only the returned public arguments may enter an authority request, signed plan
or execution envelope. The three private values remain transient runtime input.
Their original marshaled representation is committed before businessIntent is
added; this is a new input profile, never a rewrite of an existing signed input.
Public-only validation cannot establish possession, sealing or authenticity of
the unavailable private values. RP/origin syntax is not configured trust.
"""
from __future__ import annotations

from collections.abc import Mapping
from functools import wraps
import hashlib
from typing import Any

from catchplate import authority_approver_policy as policies
from catchplate import authority_contract as contract
from catchplate import authority_jit_request as raw
from catchplate import authority_transition_core as core


OPERATION = raw.OPERATION
HANDLER = "ensure_jit_approval_request"
INPUT_SCHEMA = "catchplate.policyAuthorityPrivateJitWriterInput/v2"
PUBLIC_SCHEMA = "catchplate.jitRequestCommitments/v2"
PRIVATE_FIELDS = frozenset({"url", "canonical_request", "redacted_display"})
_METADATA_FIELDS = raw.FIELDS - PRIVATE_FIELDS
_DIGEST_FIELDS = frozenset({"url_commitment", "canonical_request_digest",
    "redacted_display_digest", "original_arguments_digest"})
PUBLIC_FIELDS = _METADATA_FIELDS | _DIGEST_FIELDS | {"schema"}
_ENVELOPE_FIELDS = frozenset({"schema", "handler", "operationManifestDigest",
    "arguments", "privateDocuments"})
MAX_PAYLOAD_BYTES = raw.MAX_PAYLOAD_BYTES


def _require(condition: bool) -> None:
    if not condition:
        raise core.TransitionKernelError("Private JIT input is invalid")


def _checked(function):
    @wraps(function)
    def checked(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except (core.TransitionKernelError, ValueError, TypeError, KeyError,
                OverflowError, RecursionError):
            # Do not attach private documents, parser exceptions or raw values.
            raise core.TransitionKernelError("Private JIT input is invalid") from None
    return checked


def _sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _copy_fields(value: Mapping[str, Any], fields: frozenset[str]) -> dict[str, Any]:
    _require(isinstance(value, Mapping) and set(value) == fields)
    # Start each value at the same depth as the old document validator. Literal
    # tagged-looking keys in private JSON remain ordinary JSON, not type tags.
    copied = {key: raw._json(value[key]) for key in fields}
    _require(len(core.canonical_bytes(copied)) <= contract.MAX_REQUEST_BYTES)
    return copied


def _prepare(raw_arguments: Mapping[str, Any]) -> dict[str, Any]:
    original = _copy_fields(raw_arguments, raw.FIELDS)
    original_digest = _sha(core.canonical_bytes(original))
    intent = contract.synthesize_business_intent(OPERATION, original)
    # Reuse the complete legacy raw validation, including its aggregate 64 KiB
    # payload bound. Lookup IDs produced by this validation call are discarded:
    # the new public authority envelope digest does not exist at this point.
    normalized = raw.normalize({**original, "businessIntent": intent},
        request_digest=original_digest)
    public = {key: original[key] for key in _METADATA_FIELDS}
    public.update(schema=PUBLIC_SCHEMA, original_arguments_digest=original_digest,
        **{key: normalized[key] for key in _DIGEST_FIELDS - {"original_arguments_digest"}})
    envelope = {"schema": INPUT_SCHEMA, "handler": HANDLER,
        "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST,
        "arguments": public,
        "privateDocuments": {key: original[key] for key in PRIVATE_FIELDS}}
    _require(len(core.canonical_bytes(envelope)) <= contract.MAX_REQUEST_BYTES)
    return envelope


@_checked
def prepare(marshaled_raw_args: Mapping[str, Any]) -> dict[str, Any]:
    """Separate an unsigned facade input; never accept caller businessIntent."""
    return _prepare(marshaled_raw_args)


@_checked
def validate_runtime_input(envelope: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Reconstruct and validate exact private originals, returning owned copies.

    The recipient must discard the private channel from everything it signs or
    persists. A matching commitment is not a key-custody receipt or approval.
    """
    _require(isinstance(envelope, Mapping) and set(envelope) == _ENVELOPE_FIELDS)
    _require(envelope["schema"] == INPUT_SCHEMA and envelope["handler"] == HANDLER
        and envelope["operationManifestDigest"] == contract.OPERATION_MANIFEST_DIGEST)
    public = _copy_fields(envelope["arguments"], PUBLIC_FIELDS)
    private = _copy_fields(envelope["privateDocuments"], PRIVATE_FIELDS)
    reconstructed = {key: public[key] for key in _METADATA_FIELDS}
    reconstructed.update(private)
    expected = _prepare(reconstructed)
    # Canonical byte equality also distinguishes JSON booleans from integers.
    _require(core.canonical_bytes(public) == core.canonical_bytes(expected["arguments"]))
    return expected["arguments"], expected["privateDocuments"]


@_checked
def public_arguments(arguments: Mapping[str, Any], *, typed: bool = False,
                     request_digest: str | None = None) -> dict[str, Any]:
    """Validate commitment-only input and return kernel-local normalized fields.

    Only an explicit public authority envelope request_digest derives opaque
    lookup IDs. It is distinct from both the provider request_digest field and
    original_arguments_digest. Without private input, these hashes are claims;
    the runtime reconstruction and future genuine custody proof remain required.
    """
    _require(type(typed) is bool)
    fields = PUBLIC_FIELDS | ({"businessIntent"} if typed else set())
    owned = _copy_fields(arguments, fields)
    _require(owned["schema"] == PUBLIC_SCHEMA)
    public = {key: owned[key] for key in PUBLIC_FIELDS}
    if typed:
        expected = contract.synthesize_business_intent(OPERATION, public)
        _require(core.canonical_bytes(owned["businessIntent"]) == core.canonical_bytes(expected))
    values: dict[str, Any] = {}
    for name in ("route_id", "method", "principal_id", "credential_id"):
        values[name] = core.require_text(owned[name], "JIT " + name,
            maximum_bytes=32 if name == "method" else 512, allow_empty=name == "credential_id")
    _require(values["method"] == values["method"].upper())
    values["credential_version"] = core.require_integer(owned["credential_version"],
        "JIT credential version", minimum=0, maximum=2**63 - 1)
    for name in _DIGEST_FIELDS | {"policy_hash", "request_digest", "operation_digest"}:
        values[name] = None if name == "operation_digest" and owned[name] is None else (
            core.require_digest(owned[name], "JIT commitment"))
    for name in ("pending_ttl_seconds", "grant_ttl_seconds", "grant_max_uses"):
        values[name] = core.require_integer(owned[name], "JIT lifetime or uses", minimum=1,
            maximum=1_000_000 if name == "grant_max_uses" else 3600)
    policy = raw._policy(owned)
    policy_bytes = core.canonical_bytes(policy)
    # Necessary public subset of the old aggregate bound. The exact bound over
    # URL and both document bytes is checked only with their actual originals.
    size = sum(len((values[name] or "").encode("utf-8")) for name in (
        "route_id", "method", "principal_id", "credential_id", "policy_hash",
        "request_digest", "operation_digest")) + len(policy_bytes)
    _require(size <= MAX_PAYLOAD_BYTES)
    values.update(approver_policy=policy,
        approver_policy_digest=core.framed_digest(policies.JIT_SCHEMA, policy_bytes))
    if typed:
        values["businessIntent"] = owned["businessIntent"]
    if request_digest is not None:
        core.require_digest(request_digest, "JIT public authority envelope")
        for name, purpose in (("canonical_request", raw.CANONICAL_OPAQUE_PURPOSE),
                ("redacted_display", raw.DISPLAY_OPAQUE_PURPOSE)):
            values[name + "_opaque_id"] = core.deterministic_uuid(
                operation=OPERATION, request_digest=request_digest, purpose=purpose)
    return values
