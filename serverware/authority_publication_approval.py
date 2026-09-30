"""Closed publication-resolution approval inputs; no file or SQL authority."""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping

ACTION = "control_plane.token.publication.resolve"
RESOURCE = "admin-token"
ROLE = "admin"
PROVENANCE_SCHEMA = "serverware.publicationApprovalProvenance/v1"
HANDLER_PREFIX = "serverware_policy_authority_publication_approval_"
AUDIT_PREFIX = "control_plane.publication_approval."
OPTIONS_SCHEMA = "serverware.publicationApprovalOptions/v1"
PREFIX = "publication-approval."
OPERATIONS = frozenset(PREFIX + phase for phase in ("request", "decide", "consume", "settle"))
ASSERTION_OPERATIONS = OPERATIONS - {PREFIX + "settle"}
FIELDS = frozenset({"action", "resource_id", "payload_digest", "actor_id", "request", "approval_id", "credential_policy"})
POLICY_FIELDS = frozenset({"rpId", "origins", "allowedAuthenticatorClasses", "hardwareRequired", "requireUserPresence", "requireUserVerification", "maxAssertionAgeSeconds"})
REQUEST_FIELDS = frozenset({"token", "publicationId", "intentSha256", "outcome", "reason"})
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def action(value):
    request_binding(value)
    return ACTION


def operation_profile(operation):
    from serverware import authority_policy_native_activation
    if operation in authority_policy_native_activation.OPERATIONS:
        return authority_policy_native_activation
    if operation in OPERATIONS:
        from serverware import authority_publication_approval
        return authority_publication_approval
    from serverware import authority_policy_file_approval
    if operation in authority_policy_file_approval.OPERATIONS:
        return authority_policy_file_approval
    raise ValueError("approval operation has no source-fixed purpose")


def assertion_operations():
    from serverware import authority_policy_file_approval
    from serverware import authority_policy_native_activation
    return ASSERTION_OPERATIONS | authority_policy_file_approval.ASSERTION_OPERATIONS | authority_policy_native_activation.ASSERTION_OPERATIONS


def canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


def require(value, message="publication approval originals are not exact"):
    if not value:
        raise ValueError(message)


def digest(value):
    require(type(value) is str and _DIGEST.fullmatch(value) is not None)
    return value


def request_binding(value):
    require(type(value) is dict and set(value) == REQUEST_FIELDS)
    require(value["token"] == "admin" and type(value["publicationId"]) is str
        and re.fullmatch(r"[0-9a-f]{32}", value["publicationId"]) is not None
        and value["outcome"] in ("finalize-installed", "abandon-uninstalled")
        and (value["reason"] is None or type(value["reason"]) is str and len(value["reason"]) <= 500))
    digest(value["intentSha256"])
    require(len(canonical(value)) <= 8192)
    return dict(value)


def policy(value):
    require(type(value) is dict and set(value) == POLICY_FIELDS)
    require(type(value["rpId"]) is str and 1 <= len(value["rpId"].encode("utf-8")) <= 253
        and type(value["origins"]) is list and 1 <= len(value["origins"]) <= 16
        and all(type(item) is str and 1 <= len(item.encode("utf-8")) <= 2048 for item in value["origins"]))
    classes = value["allowedAuthenticatorClasses"]
    require(type(classes) is list and classes == sorted(set(classes)) and classes
        and set(classes) <= {"hardware", "yubikey"}
        and value["hardwareRequired"] is True
        and value["requireUserPresence"] is True and value["requireUserVerification"] is True
        and type(value["maxAssertionAgeSeconds"]) is int and 1 <= value["maxAssertionAgeSeconds"] <= 120)
    return dict(value)


def arguments(operation, value, *, typed=False):
    require(operation in OPERATIONS and isinstance(value, Mapping))
    fields = FIELDS if operation in ASSERTION_OPERATIONS else (
        FIELDS - {"credential_policy"}) | {"consumption_request_digest", "completion_sha256"}
    allowed = fields | ({"businessIntent", "authn_evidence"} if typed else set())
    require(fields <= set(value) and set(value) <= allowed)
    if typed:
        require("businessIntent" in value)
    require(value["action"] == ACTION and value["resource_id"] == RESOURCE)
    actor = value["actor_id"]
    require(type(actor) is str and actor.startswith("oidc:") and actor == actor.strip()
        and 1 <= len(actor.encode("utf-8")) <= 512 and not any(ord(c) < 32 or ord(c) == 127 for c in actor))
    bound = request_binding(value["request"])
    require(digest(value["payload_digest"]) == "sha256:" + hashlib.sha256(canonical(bound)).hexdigest())
    approval = value["approval_id"]
    if operation == PREFIX + "request":
        require(approval is None)
    else:
        require(type(approval) is str and re.fullmatch(r"[0-9a-f-]{36}", approval) is not None)
    if operation in ASSERTION_OPERATIONS:
        policy(value["credential_policy"])
    else:
        digest(value["consumption_request_digest"])
        digest(value["completion_sha256"])
    require(len(canonical(dict(value))) <= 32 * 1024)
    return {name: value[name] for name in fields}


def request_digest(operation, value):
    """Use the real authority commitment body, never a supplied result hash."""
    from serverware import authority_request_commitment as commitment
    return commitment.publication_request_digest(operation, value)
