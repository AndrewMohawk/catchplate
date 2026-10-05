"""Owned challenge request data for the private measured maintenance family.

This reuses the real seven-field typed request and commitment recipe; it does
not admit a signer, root, clock, capability, SQL effect or public operation.
The existing measured lossless-JSON domain is retained. Historically direct
create payloads containing floats, NUL or lone surrogates are not added to the
signed/typed codec by this helper. Legacy public planner gates are unchanged.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from serverware import authority_challenge_id as identifiers
from serverware import authority_contract as authority
from serverware import authority_request_commitment as commitment
from serverware import authority_revocation_plan_contract as shape
from serverware import authority_revocation_wire as wire
from serverware.authority_query_read_work import _ValidationWork


OPERATIONS = frozenset({"webauthn.challenge.create", "webauthn.challenge.maintain"})
MAX_REQUEST_BYTES = authority.MAX_REQUEST_BYTES
_MAINTAIN_FIELDS = frozenset({"challenge_type", "user_id", "scope_key", "replace_scope", "businessIntent"})
_CREATE_FIELDS = frozenset({"challenge_id", "challenge", "challenge_type", "user_id", "payload",
    "approval_request_id", "scope_key", "ttl_seconds", "created_at", "expires_at", "businessIntent"})


class ChallengePlanRequestError(ValueError):
    pass


def _require(value):
    if not value:
        raise ChallengePlanRequestError("challenge typed request differs from its source contract")


def _same_bytes(left, right, work):
    work.charge(input_bytes=len(left) + len(right))
    _require(left == right)


def _text(value, maximum, work, *, utf8=False):
    _require(type(value) is str and 1 <= len(value) <= maximum)
    length = work.prepare_utf8(value)
    _require(not utf8 or length <= maximum)


def _timestamp(value, work):
    _require(type(value) is str and bool(value))
    work.prepare_scan(value)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ChallengePlanRequestError("challenge timestamp is not canonical UTC") from exc
    _require(parsed.tzinfo is not None and parsed.utcoffset() == timedelta(0))
    work.prepare_scan(value)
    _require(parsed.isoformat() == value)
    return parsed.astimezone(timezone.utc)


def _epoch_ns(value):
    delta = value - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return ((delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds) * 1000


def _create(arguments, work):
    identifiers.require_generated(arguments["challenge_id"])
    challenge = arguments["challenge"]
    _require(type(challenge) is str and 32 <= len(challenge) <= 128)
    work.prepare_scan(challenge)
    _require(all(character in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        for character in challenge))
    ttl = arguments["ttl_seconds"]
    _require(type(ttl) is int and 30 <= ttl <= 300)
    _require(arguments["approval_request_id"] is None or type(arguments["approval_request_id"]) is str)
    payload = arguments["payload"]
    _require(type(payload) is dict)
    _require(len(work.wire(payload)) <= 64 * 1024)
    created = _timestamp(arguments["created_at"], work)
    expires = _timestamp(arguments["expires_at"], work)
    _require(expires - created == timedelta(seconds=ttl))
    # Preserve the existing create program's special policy-authority payload
    # joins, without sampling time or substituting for its database admission.
    if payload.get("schema") == "serverware.policyAuthorityWebAuthnChallenge/v1":
        shape._object(payload, frozenset({"schema", "operationId", "rpId", "origin",
            "issuedAtEpochNs", "expiresAtEpochNs", "credentialId"}), "challenge payload")
        identifier = payload["operationId"]
        shape._digest(identifier)
        _require(arguments["scope_key"] == identifier and arguments["challenge_type"] == "policy_authority")
        domain = "serverware.policyAuthorityWebAuthnChallengeId/v1"
        work.prepare_utf8(identifier)
        work.prepare_utf8(challenge)
        work.charge(hashes=1, input_bytes=len(domain) + 1 + 16)
        derived = commitment.framed_digest(domain, identifier.encode("ascii"), challenge.encode("ascii"))
        _require(not commitment._request_different(derived, arguments["challenge_id"], work=work))
        issued, ended = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
        _require(type(issued) is int and type(ended) is int and ended - issued == ttl * 1000000000
            and _epoch_ns(created) == issued and _epoch_ns(expires) == ended)


def _validate(request, work):
    _require(type(work) is _ValidationWork)
    shape._object(request, shape.TYPED_REQUEST_FIELDS, "challenge typed request")
    operation = request["operation"]
    _require(type(operation) is str and operation in OPERATIONS)
    shape._literal(request["schema"], shape.TYPED_REQUEST_SCHEMA)
    shape._literal(request["handler"], authority.operation_spec(operation)["handler"])
    shape._literal(request["operationManifestDigest"], authority.OPERATION_MANIFEST_DIGEST)
    for field in ("requestDigest", "operationId"):
        shape._digest(request[field])
    arguments = request["arguments"]
    shape._object(arguments, _CREATE_FIELDS if operation == "webauthn.challenge.create" else _MAINTAIN_FIELDS,
        "challenge arguments")
    work.prepare_scan(request)
    _text(arguments["challenge_type"], 64, work)
    _text(arguments["user_id"], 512, work, utf8=True)
    if arguments["scope_key"] is not None:
        _text(arguments["scope_key"], 512, work, utf8=True)
    if operation == "webauthn.challenge.create":
        _create(arguments, work)
    else:
        _require(type(arguments["replace_scope"]) is bool)
    # The shared intent validator uses ordinary equality. Retain its actual
    # synthesizer and additionally join canonical bytes to reject bool/int
    # aliases anywhere in the repeated arguments, including payload values.
    work.prepare_copy(arguments)
    caller = {key: value for key, value in arguments.items() if key != "businessIntent"}
    intent = authority._synthesize_business_intent(operation, caller, work=work)
    _same_bytes(work.wire(arguments["businessIntent"]), work.wire(intent), work)
    digest = commitment._typed_request_digest(request, work=work)
    _require(not commitment._request_different(digest, request["requestDigest"], work=work))
    work.prepare_utf8(operation)
    work.prepare_utf8(digest)
    work.charge(hashes=1, input_bytes=len("serverware.policyAuthorityOperation/v2") + 1 + 16)
    expected_id = commitment.operation_id(operation, digest)
    _require(not commitment._request_different(expected_id, request["operationId"], work=work))
    return request


def capture_request(request_bytes, *, work):
    """Decode/own exact canonical bytes and recompute their real commitments."""
    _require(type(work) is _ValidationWork)
    request = wire._decode_object(request_bytes, work=work, maximum_bytes=MAX_REQUEST_BYTES)
    _same_bytes(work.wire(request), request_bytes, work)
    return _validate(request, work)


def context_subject(request, *, work):
    """Derive data only, rejoining the owned request instead of accepting a DTO."""
    _require(type(work) is _ValidationWork)
    owned = wire.batch._JSONCapture(wire.batch._SharedLedger(work),
        maximum_bytes=MAX_REQUEST_BYTES).visit(request)
    _validate(owned, work)
    arguments = owned["arguments"]
    # Reserve the actual seven-field projection before creating its container;
    # the already bounded full request is a conservative source-sized charge.
    work.prepare_copy(owned)
    result = {"operation": owned["operation"], "operationId": owned["operationId"],
        "requestDigest": owned["requestDigest"], "challengeType": arguments["challenge_type"],
        "userId": arguments["user_id"], "scopeKey": arguments["scope_key"],
        "replaceScope": arguments["scope_key"] is not None if owned["operation"] == "webauthn.challenge.create"
            else arguments["replace_scope"]}
    return result
