"""Closed durable Setup originals for the separately authorized OAuth path.

These codecs grant no ownership or permission. The actual controlled kernels
re-read the retained row, current actor roles and verified assertion originals.
"""
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import uuid

from catchplate import authority_oauth_activation as activation
from catchplate import native_oauth_refresh as common

canonical, require, digest, sha256 = common.canonical, common.require, common.digest, common.sha
document, encoded, decoded = common.document, common.encoded, common.decoded
policy, pending_original, pending_digest = activation.policy, activation.pending_original, activation.pending_digest
enrollment_bytes = activation.enrollment_bytes
OP_CREATE = "oauth.setup.create"
OP_REQUEST = "oauth.setup.activation-request"
OP_DECIDE = "oauth.setup.activation-decide"
OP_ACTIVATE = "oauth.setup.activate"
OP_SETTLE = "oauth.setup.audit-settle"
OPERATIONS = frozenset({OP_CREATE, OP_REQUEST, OP_DECIDE, OP_ACTIVATE, OP_SETTLE})
ASSERTION_OPERATIONS = OPERATIONS - {OP_SETTLE}
ACTION_CREATE = "credential.oauth.setup-create"
ACTION = "credential.oauth.setup-activate"
OPTIONS_SCHEMA = "catchplate.oauthSetupApprovalOptions/v1"
PROVENANCE_SCHEMA = "catchplate.oauthSetupActivationApprovalProvenance/v1"
ORIGINAL_SCHEMA = "catchplate.oauthSetupActivationOriginal/v1"
AUDIT_LINK_TABLE = "oauth_setup_audit_links"
FIELDS = activation.FIELDS
BINDING_FIELDS = frozenset({"sessionId", "revision", "rowSha256", "ownerId", "currentAssigneeId", "expiresAtEpochNs"})
CREATE_FIELDS = frozenset({"sessionId", "providerId", "templateId", "principalId", "routeId", "routePolicyDigest",
    "enrollmentSha256", "issuedAtEpochNs", "expiresAtEpochNs"})
REQUEST_FIELDS = activation.REQUEST_FIELDS | {"setupBinding"}
ROW_FIELDS = frozenset({"id", "owner_id", "current_assignee_id", "status", "phase", "revision", "template_id", "principal_id",
    "route_id", "route_policy_digest", "credential_id", "credential_version", "policy_hash", "assignment_digest",
    "oauth_provider", "oauth_state_digest", "oauth_pending_credential_id", "canary_id", "enrollment_session_id",
    "enrollment_packet_digest", "verifier_nonce_hash", "enrollment_verifier_receipt_digest", "enrollment_verifier_key_id",
    "attestation_challenge_digest", "attestation_challenge_issued_at", "attestation_challenge_expires_at",
    "attestation_challenge_value", "runtime_evidence_digest", "hardware_assurance_digest", "hardware_verification_receipt_digest",
    "hardware_verifier_key_id", "release_identity_digest", "current_host_identity_digest", "proxy_server_statement_digest",
    "trust_profile_digest", "completion_identity_digest", "final_authority_key_id", "final_consumption_id", "final_receipt_digest",
    "created_at", "updated_at", "expires_at", "terminal_at"})
REQUIRED_ROW = frozenset({"id", "owner_id", "status", "phase", "revision", "created_at", "updated_at", "expires_at"})
EVENT_FIELDS = frozenset({"id", "session_id", "sequence", "transition", "actor_id", "payload_digest", "event_json", "created_at",
    "audit_status", "audit_claim_id", "audit_claimed_at", "audit_attempts", "audited_at", "audit_event_hash", "audit_last_error"})
AUDIT_LINK_FIELDS = frozenset({"id", "session_id", "event_id", "outbox_id", "outbox_event_digest", "request_digest", "created_at"})
MAX_ROW_BYTES = 64 * 1024
MAX_EVENT_BYTES = 64 * 1024
MAX_ARGUMENT_BYTES = 192 * 1024


def identifier(value):
    require(type(value) is str and str(uuid.UUID(value)) == value)
    return value


def text(value, maximum=512):
    common.text(value, maximum)
    require(value == value.strip() and not any(ord(c) < 32 or ord(c) == 127 for c in value))
    return value


def epoch(value):
    require(type(value) is str)
    stamp = datetime.fromisoformat(value)
    require(stamp.tzinfo is not None and stamp.utcoffset() == timezone.utc.utcoffset(stamp))
    # Exact SQL microseconds; never pass an absolute admission epoch through float.
    delta = stamp - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return common.integer((delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000)


def row_original(row):
    value = dict(row)
    require(set(value) == ROW_FIELDS)
    for name, item in value.items():
        if item is None:
            require(name not in REQUIRED_ROW)
        elif name in {"revision", "credential_version"}:
            require(type(item) is int and 0 <= item <= 9_223_372_036_854_775_807)
        else:
            require(type(item) is str)
    identifier(value["id"])
    for name in ("created_at", "updated_at", "expires_at"):
        epoch(value[name])
    raw = canonical(value)
    require(len(raw) <= MAX_ROW_BYTES)
    return raw


def binding(value):
    require(type(value) is dict and set(value) == BINDING_FIELDS)
    identifier(value["sessionId"]); digest(value["rowSha256"])
    # Reserve all three phase increments and the one-based event sequence.
    require(type(value["revision"]) is int and 0 <= value["revision"] <= 9_223_372_036_854_775_803)
    text(value["ownerId"])
    if value["currentAssigneeId"] is not None:
        text(value["currentAssigneeId"])
    common.integer(value["expiresAtEpochNs"])
    return dict(value)


def row_binding(row):
    original = row_original(row)
    return binding({"sessionId": row["id"], "revision": row["revision"], "rowSha256": sha256(original),
        "ownerId": row["owner_id"], "currentAssigneeId": row["current_assignee_id"], "expiresAtEpochNs": epoch(row["expires_at"])})


def event_id(session_id, sequence):
    identifier(session_id); common.integer(sequence)
    return str(uuid.uuid5(uuid.UUID(session_id), "catchplate.oauthSetupEvent/v1:" + str(sequence)))


def create_request(value):
    require(type(value) is dict and set(value) == CREATE_FIELDS)
    identifier(value["sessionId"]); digest(value["enrollmentSha256"])
    require(value["providerId"] in {"google", "x"})
    for name in ("templateId", "principalId", "routeId"):
        if value[name] is not None:
            text(value[name])
    # This creates the existing draft phase, not an authoritative route review.
    # The later genuine candidate/policy transition supplies that permission.
    require(value["routePolicyDigest"] is None)
    common.integer(value["issuedAtEpochNs"]); common.integer(value["expiresAtEpochNs"])
    require(value["issuedAtEpochNs"] % 1000 == 0 and value["expiresAtEpochNs"] % 1000 == 0)
    require(300_000_000_000 <= value["expiresAtEpochNs"] - value["issuedAtEpochNs"] <= 604_800_000_000_000)
    return dict(value)


def request_binding(value):
    require(type(value) is dict and set(value) == REQUEST_FIELDS)
    activation.request_binding({name: value[name] for name in activation.REQUEST_FIELDS})
    binding(value["setupBinding"])
    return dict(value)


def arguments(operation, value, *, typed=False):
    require(operation in OPERATIONS and isinstance(value, Mapping))
    if operation == OP_SETTLE:
        require(set(value) == {"event_id"} | ({"businessIntent"} if typed else set()))
        identifier(value["event_id"])
        return {"event_id": value["event_id"]}
    allowed = FIELDS | ({"businessIntent", "authn_evidence"} if typed else set())
    require(FIELDS <= set(value) <= allowed and (not typed or "businessIntent" in value))
    request = create_request(value["request"]) if operation == OP_CREATE else request_binding(value["request"])
    expected_id = request["sessionId"] if operation == OP_CREATE else request["pendingCredentialId"]
    expected_digest = sha256(canonical(request)) if operation == OP_CREATE else request["payloadDigest"]
    require(value["action"] == (ACTION_CREATE if operation == OP_CREATE else ACTION)
        and value["resource_id"] == expected_id and value["payload_digest"] == expected_digest)
    require(text(value["actor_id"]).startswith("oidc:"))
    if operation in {OP_CREATE, OP_REQUEST}:
        require(value["approval_id"] is None)
    else:
        identifier(value["approval_id"])
    activation.policy(value["credential_policy"])
    raw = activation.enrollment_bytes(value["enrollment_original"])
    require(sha256(raw) == request["enrollmentSha256"])
    originals = {name: value[name] for name in FIELDS}
    require(len(canonical(originals)) <= MAX_ARGUMENT_BYTES)
    return originals


def request_digest(operation, value):
    from catchplate import authority_request_commitment as commitment
    return commitment.oauth_setup_request_digest(operation, value)
