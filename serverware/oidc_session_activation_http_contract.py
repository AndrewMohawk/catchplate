"""Bounded activation POST data, not a route, permission or success result.

The future handler must authenticate the actual pending request and run the
single live permission/dispatch context. These projections neither verify the
two WebAuthn ceremonies nor obtain any independently issued authority original.
Failure helpers require the documented source-controlled dispatch boundary.
"""
from __future__ import annotations

import json

from serverware import authority_oidc_session_activation as activation
from serverware import control_plane_oidc_session_activation_permission_http as permission
from serverware.setup_receipts import JsonLimits, ReceiptVerificationError, parse_strict_json_object


REQUEST_SCHEMA = "serverware.oidcSessionActivationHttpRequest/v1"
RESPONSE_SCHEMA = "serverware.oidcSessionActivationHttpFailure/v1"
PURPOSE = "dispatch-oidc-session-activation"
PERMISSION_ACTION = permission.ACTION
MAX_REQUEST_BYTES = 256 * 1024
MAX_PERMISSION_BYTES = permission.MAX_REQUEST_BYTES
MAX_PLANNING_ASSERTION_BYTES = activation.MAX_ASSERTION_BYTES
MAX_CHALLENGE_ID_CHARACTERS = 1024
MAX_APPROVAL_ID_CHARACTERS = 4096
_REQUEST_FIELDS = frozenset({"schema", "purpose", "localDigest", "mfa", "planning"})
_PLANNING_FIELDS = frozenset({"assertion", "challengeId"})
_JSON_LIMITS = JsonLimits(max_bytes=MAX_REQUEST_BYTES, max_depth=16,
    max_object_keys=64, max_total_keys=512, max_array_items=128,
    max_total_nodes=4096, max_string_bytes=MAX_REQUEST_BYTES)


def _text(value, maximum, label):
    if (type(value) is not str or not 1 <= len(value) <= maximum
            or "\x00" in value or any(0xD800 <= ord(point) <= 0xDFFF for point in value)):
        raise ValueError(label + " is not bounded exact text")
    return value


def _wire(value, maximum, label):
    # Only a graph detached from the bounded strict parser reaches this helper.
    # Normalizing its JSON container leaves encoded authenticator/client-data
    # originals untouched; no signed WebAuthn field is decoded or regenerated.
    original = json.dumps(value, ensure_ascii=True, allow_nan=False,
        sort_keys=True, separators=(",", ":")).encode("ascii")
    if not 2 <= len(original) <= maximum:
        raise ValueError(label + " exceeds its original byte bound")
    return original


def _capture(raw_bytes):
    if type(raw_bytes) is not bytes or not 2 <= len(raw_bytes) <= MAX_REQUEST_BYTES:
        raise ValueError("activation dispatch requires bounded immutable JSON bytes")
    try:
        value = permission.framing._owned(parse_strict_json_object(raw_bytes, limits=_JSON_LIMITS))
    except (ReceiptVerificationError, ValueError, RecursionError):
        raise ValueError("activation dispatch requires bounded strict JSON") from None
    if (type(value) is not dict or value.keys() != _REQUEST_FIELDS
            or type(value["schema"]) is not str or value["schema"] != REQUEST_SCHEMA
            or type(value["purpose"]) is not str or value["purpose"] != PURPOSE):
        raise ValueError("activation dispatch fields, schema or purpose differ")
    local_digest = permission.framing._local_digest(value["localDigest"])
    mfa = value["mfa"]
    if (type(mfa) is not dict or "assertion" not in mfa
            or not mfa.keys() <= {"assertion", "approvalId"}
            or type(mfa["assertion"]) is not dict or not mfa["assertion"]):
        raise ValueError("activation dispatch requires its separate permission assertion carrier")
    if "approvalId" in mfa:
        _text(mfa["approvalId"], MAX_APPROVAL_ID_CHARACTERS, "activation approval ID")
    planning = value["planning"]
    if (type(planning) is not dict or planning.keys() != _PLANNING_FIELDS
            or type(planning["assertion"]) is not dict):
        raise ValueError("activation planning fields or assertion carrier differ")
    challenge = _text(planning["challengeId"], MAX_CHALLENGE_ID_CHARACTERS,
        "activation planning challenge ID")
    # The two independent carriers stay separate. Equality or inequality of
    # their bytes cannot establish their challenge, target or counter semantics.
    permission_bytes = _wire({"purpose": permission.PURPOSE,
        "localDigest": local_digest, "mfa": mfa}, MAX_PERMISSION_BYTES,
        "activation permission projection")
    permission.parse_request(permission_bytes, options=False)
    assertion_bytes = _wire(planning["assertion"], MAX_PLANNING_ASSERTION_BYTES,
        "activation planning assertion projection")
    return value, (permission_bytes, assertion_bytes, challenge)


def parse_request(raw_bytes):
    """Return newly owned request DATA, with both projection bounds checked."""
    value, _originals = _capture(raw_bytes)
    return value


def request_originals(raw_bytes):
    """Project permission bytes, planning assertion bytes and challenge ID.

    This accepts the immutable full body, never a previously parsed graph or
    successful permission object. Only the actual live owner may consume these
    ordinary inputs together with the actual authenticated HTTP Request.
    """
    _value, originals = _capture(raw_bytes)
    return originals


def _failure(local_digest, *, status, dispatch_state):
    digest = None if local_digest is None else permission.framing._local_digest(local_digest)
    return {"schema": RESPONSE_SCHEMA, "purpose": PURPOSE, "localDigest": digest,
        "status": status, "dispatchState": dispatch_state,
        "sessionState": "unknown", "automaticRetryAllowed": False}


def rejected_before_dispatch(local_digest=None):
    """DATA only: handler must know no activation dispatch was attempted.

    Invalid input or genuinely pre-dispatch refusal may use this projection;
    a missing response, retained claim or raised downstream exception may not.
    This says nothing about permission-assertion side effects or past requests.
    """
    return _failure(local_digest, status="rejected-before-dispatch", dispatch_state="not-dispatched")


def outcome_unknown(local_digest=None):
    """DATA only: use after dispatch or whenever its occurrence is uncertain.

    Neither this response nor its delivery proves nonexecution, recovery
    authority, token delivery or present session state. Preserve the pending
    cookie; automatic retry stays forbidden.
    """
    return _failure(local_digest, status="outcome-unknown", dispatch_state="unknown")
