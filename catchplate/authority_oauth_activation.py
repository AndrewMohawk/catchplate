"""Closed OAuth activation inputs and exact pending originals; no authority DTO."""
from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Mapping

from catchplate.authority_publication_approval import canonical, policy

ACTION = "credential.oauth.activate"
OPTIONS_SCHEMA = "catchplate.oauthActivationApprovalOptions/v1"
PROVENANCE_SCHEMA = "catchplate.oauthActivationApprovalProvenance/v1"
OP_REQUEST = "oauth-activation-approval.request"
OP_DECIDE = "oauth-activation-approval.decide"
OP_ACTIVATE = "oauth.pending.activate"
OPERATIONS = ASSERTION_OPERATIONS = frozenset({OP_REQUEST, OP_DECIDE, OP_ACTIVATE})
FIELDS = frozenset({"action", "resource_id", "payload_digest", "actor_id", "request", "approval_id", "credential_policy", "enrollment_original"})
REQUEST_FIELDS = frozenset({"pendingCredentialId", "pendingRowSha256", "enrollmentSha256", "payloadDigest"})
PENDING_FIELDS = frozenset({"id", "requester_id", "name", "kind", "encrypted_secret", "encrypted_dek", "secret_nonce", "secret_ciphertext", "secret_kek_id", "credential_version", "secret_updated_at", "metadata", "payload_digest", "review_json", "target_credential_id", "target_credential_version", "status", "revocation_status", "revocation_error", "revocation_attempts", "revocation_next_attempt_at", "revocation_lease_owner", "revocation_lease_until", "created_at", "expires_at", "updated_at"})
_NULLABLE = frozenset({"target_credential_id", "target_credential_version", "revocation_status", "revocation_error", "revocation_next_attempt_at", "revocation_lease_owner", "revocation_lease_until"})
_INTS = frozenset({"credential_version", "target_credential_version", "revocation_attempts"})
MAX_ENROLLMENT_BYTES = 64 * 1024
MAX_PENDING_BYTES = 1024 * 1024


def require(value, message="OAuth activation originals are not exact"):
    if not value:
        raise ValueError(message)


def digest(value):
    require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None)
    return value


def identifier(value):
    require(type(value) is str and re.fullmatch(r"[0-9a-f-]{36}", value) is not None)
    return value


def pending_original(row):
    # sqlite.Row and the private Postgres SELECT adapter both expose keys and
    # exact SQL scalars. Never stringify, strip, decode or omit ciphertext.
    value = dict(row)
    require(set(value) == PENDING_FIELDS)
    for name, item in value.items():
        if item is None:
            require(name in _NULLABLE)
        elif name in _INTS:
            require(type(item) is int and 0 <= item <= 9_223_372_036_854_775_807)
        else:
            require(type(item) is str)
    raw = canonical(value)
    require(len(raw) <= MAX_PENDING_BYTES)
    return raw


def pending_digest(row):
    return "sha256:" + hashlib.sha256(pending_original(row)).hexdigest()


def enrollment_bytes(value):
    require(type(value) is str and 1 <= len(value) <= (MAX_ENROLLMENT_BYTES * 4 + 2) // 3
        and re.fullmatch(r"[A-Za-z0-9_-]+", value) is not None)
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    require(2 <= len(raw) <= MAX_ENROLLMENT_BYTES
        and base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == value)
    return raw


def request_binding(value):
    require(type(value) is dict and set(value) == REQUEST_FIELDS)
    identifier(value["pendingCredentialId"])
    for field in REQUEST_FIELDS - {"pendingCredentialId"}:
        digest(value[field])
    return dict(value)


def arguments(operation, value, *, typed=False):
    require(operation in OPERATIONS and isinstance(value, Mapping))
    allowed = FIELDS | ({"businessIntent", "authn_evidence"} if typed else set())
    require(FIELDS <= set(value) <= allowed and (not typed or "businessIntent" in value))
    request = request_binding(value["request"])
    require(value["action"] == ACTION and value["resource_id"] == request["pendingCredentialId"]
        and digest(value["payload_digest"]) == request["payloadDigest"])
    actor = value["actor_id"]
    require(type(actor) is str and actor.startswith("oidc:") and actor == actor.strip()
        and 1 <= len(actor.encode("utf-8")) <= 512 and not any(ord(c) < 32 or ord(c) == 127 for c in actor))
    if operation == OP_REQUEST:
        require(value["approval_id"] is None)
    else:
        identifier(value["approval_id"])
    policy(value["credential_policy"])
    raw = enrollment_bytes(value["enrollment_original"])
    require("sha256:" + hashlib.sha256(raw).hexdigest() == request["enrollmentSha256"])
    originals = {name: value[name] for name in FIELDS}
    require(len(canonical(originals)) <= 96 * 1024)
    return originals


def request_digest(operation, value):
    from catchplate import authority_request_commitment as commitment
    return commitment.oauth_activation_request_digest(operation, value)
