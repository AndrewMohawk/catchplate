"""Closed public revocation originals, not requester or execution authority.

The typed semantic request is fixed before a WebAuthn challenge. The complete
HTTP/actor/policy/approval/assertion original is separately committed by the
dedicated cold caller's signature. Neither a locator nor this codec admits a
caller, consumes an approval, verifies an assertion or authorizes a retry.
"""
from __future__ import annotations

import hashlib

from catchplate import authority_contract as authority
from catchplate import authority_public_webauthn_revocation as aggregate
from catchplate import authority_public_revocation_caller_authorization as caller
from catchplate import authority_request_commitment as commitment
from catchplate import authority_transition_webauthn as transition


SCHEMA = "catchplate.publicWebAuthnRevocationRequest/v1"
OPTIONS_SCHEMA = "catchplate.publicWebAuthnRevocationOptions/v1"
FIELDS = frozenset({"schema", "request", "actor", "policy", "payloadDigest", "approval", "assertion"})
OPTIONS_FIELDS = frozenset({"schema", "request", "actorId", "policy", "payloadDigest", "approval",
    "issuedAtEpochNs", "expiresAtEpochNs"})
MAX_BYTES = authority.MAX_REQUEST_BYTES
MAX_NODES, MAX_DEPTH = 65536, 32
_ZERO = "sha256:" + "0" * 64


def _typed(request, work):
    from catchplate import authority_revocation_plan_contract as contract
    contract._request(request)
    caller.plan._same(request["operation"], aggregate.OPERATION, work,
        "public revocation typed request has another purpose")
    values = transition._arguments(request["arguments"], work=work)
    digest = commitment._typed_request_digest(request, work=work)
    identity = caller.plan._frame("catchplate.policyAuthorityOperation/v2",
        (aggregate.OPERATION.encode("ascii"), digest.encode("ascii")), work)
    caller.plan._same((request["requestDigest"], request["operationId"]), (digest, identity), work,
        "public revocation typed request differs from actual semantic originals")
    return values


def typed_request(arguments, *, work):
    """Source-fixed semantic preparation, before any physical assertion."""
    ledger = caller.capture._SharedLedger(work)
    owned = caller.capture._JSONCapture(ledger, maximum_bytes=MAX_BYTES).visit(arguments)
    values = transition._prepare_revocation_input(owned, work=work)
    intent = authority._synthesize_business_intent(aggregate.OPERATION, values, work=work)
    request = {"schema": "catchplate.policyAuthorityV9Request/v1", "operation": aggregate.OPERATION,
        "operationId": _ZERO, "requestDigest": _ZERO,
        "handler": authority.operation_spec(aggregate.OPERATION)["handler"],
        "operationManifestDigest": authority.OPERATION_MANIFEST_DIGEST,
        "arguments": {**values, "businessIntent": intent}}
    request["requestDigest"] = commitment._typed_request_digest(request, work=work)
    request["operationId"] = caller.plan._frame("catchplate.policyAuthorityOperation/v2",
        (aggregate.OPERATION.encode("ascii"), request["requestDigest"].encode("ascii")), work)
    _typed(request, work)
    return request


def _approval(value, *, policy, actor):
    if (value is not None) != policy["twoPersonRequired"]:
        raise aggregate.PublicRevocationError("configured two-person revocation approval is missing or unexpected")
    if value is not None:
        aggregate._object(value, aggregate.APPROVAL_FIELDS)
        aggregate._text(value["id"])
        aggregate._text(value["approvedBy"])
        aggregate._require(value["approvedBy"] != actor)
        aggregate.core.require_digest(value["originalSha256"], "approval original")
        if value["credentialRecordId"] is not None:
            aggregate._text(value["credentialRecordId"])


def _shape(value, *, options, work):
    aggregate._object(value, OPTIONS_FIELDS if options else FIELDS)
    aggregate._require(value["schema"] == (OPTIONS_SCHEMA if options else SCHEMA))
    arguments = _typed(value["request"], work)
    aggregate.policy_shape(value["policy"])
    aggregate.core.require_digest(value["payloadDigest"], "public revocation payload")
    if options:
        actor = value["actorId"]
        aggregate._text(actor)
        start, end = value["issuedAtEpochNs"], value["expiresAtEpochNs"]
        aggregate._require(type(start) is int and type(end) is int
            and 0 < start < end < 2**63 and end - start <= 30_000_000_000)
    else:
        actual = value["actor"]
        aggregate._object(actual, aggregate.ACTOR_FIELDS)
        actor = actual["userId"]
        aggregate._text(actor)
        aggregate._text(actual["authMethod"], 128)
        aggregate.core.require_digest(actual["requestSha256"], "actual HTTP original")
        roles = actual["roles"]
        aggregate._require(type(roles) is list and 1 <= len(roles) <= 32
            and all(type(role) is str and 1 <= len(role) <= 128 for role in roles)
            and roles == sorted(set(roles)) and bool(set(roles) & {"admin", "approver"}))
        assertion = value["assertion"]
        aggregate._require((assertion is not None) == value["policy"]["mfaRequired"])
        if assertion is not None:
            aggregate._object(assertion, frozenset({"authorityChallengeId", "credentialRecordId", "assertion"}))
            aggregate._text(assertion["authorityChallengeId"])
            aggregate._text(assertion["credentialRecordId"])
            aggregate._require(type(assertion["assertion"]) is dict)
    caller.plan._same(actor, arguments["actor_id"], work,
        "public revocation semantic request belongs to another actual actor")
    _approval(value["approval"], policy=value["policy"], actor=actor)
    return value


def encode(value, *, options=False, work):
    ledger = caller.capture._SharedLedger(work)
    owned = caller.capture._JSONCapture(ledger, maximum_bytes=MAX_BYTES).visit(value)
    _shape(owned, options=options, work=work)
    size, _nodes = work.prepare_encoding(owned)
    aggregate._require(size <= MAX_BYTES)
    return aggregate.core.canonical_bytes(owned)


def decode(original, *, options=False, work):
    value = caller.authorization.wire._decode_object(original, work=work,
        maximum_bytes=MAX_BYTES, maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    _shape(value, options=options, work=work)
    caller.primitives._unchanged(original, value, MAX_BYTES, work)
    return value


def original_digest(original, *, work):
    aggregate._require(type(original) is bytes and 2 <= len(original) <= MAX_BYTES)
    work.charge(hashes=1, input_bytes=len(original))
    return "sha256:" + hashlib.sha256(original).hexdigest()
