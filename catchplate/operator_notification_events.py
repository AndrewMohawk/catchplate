"""Committed operator-SQLite audit projections; never an approval authority.

The integration owns profile admission, a fresh read-only connection/snapshot,
and the separate cursor/outbox commit. No database, configuration, key, network
or runtime owner is imported here. Native/measured event sources need their own
owner; host-trusted approval metadata is a separate, explicitly labelled source.
Stored hashes bind the cursor, not an independent audit-chain verification.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
import sqlite3
import uuid

from catchplate import operator_notification_ecr as ecr

SCHEMA = "catchplate.operatorNotification/v1"
MAX_BATCH = 64
MAX_EVENT_BYTES = 16_384
_MAX_INT = 9_007_199_254_740_991
_ERROR = "operator notification source unavailable"
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_STAMP = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|\+00:00)\Z")
_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
_ACTORS = {"admin", "agent", "system", "proxy", "data-plane", "measured-data-plane"}
NATIVE_OBSERVATION_TYPE = "native_pilot.phase_observed"
NATIVE_EVENT_TYPES = ("native_pilot.confirmation_available", "native_pilot.prepare_available",
    "native_pilot.security_key_available")
_NATIVE_SUMMARIES = {
    "prepare_available": "Prepare the native pilot",
    "security_key_available": "Use your security key for the native pilot",
    "confirmation_available": "Confirm the native pilot action",
}
HOST_REQUESTED = "operator.host_approval.requested"
_HOST_SUMMARIES = {
    HOST_REQUESTED: "Host-trusted approval requested",
    "operator.host_approval.reviewed": "Host-trusted approval reviewed",
    "operator.host_approval.approved": "Host-trusted approval recorded",
    "operator.host_approval.denied": "Host-trusted approval denied",
    "operator.host_approval.expired": "Host-trusted approval expired",
    "operator.host_approval.claimed": "Host-trusted approval used once",
}
_HOST_COMMON = {"assurance", "approval_request_id", "principal_id", "route_id", "credential_id",
    "credential_version", "policy_hash", "request_digest", "operation_digest"}
_HOST_REQUEST = _HOST_COMMON | {"method", "requested_at", "expires_at", "reviewer_id", "approver_policy_digest", "url_commitment"}
_SUMMARIES = {
    "proxy.request_decision": "Proxy request decision recorded",
    "data_plane.credential.release_started": "Authorized credential use started",
    "data_plane.request.denied": "Proxy request denied",
    "data_plane.response.released": "Proxy response released",
    "data_plane.response.blocked": "Proxy response blocked",
    "data_plane.connect.denied": "Proxy connection denied",
    "data_plane.connect.established": "Proxy connection established",
    "data_plane.policy.reloaded": "Proxy policy loaded",
    "data_plane.policy.reload_failed": "Proxy policy loading failed",
    "operator_demo.connection.created": "Development connection saved",
    "operator_demo.connection.revoked": "Development connection revoked locally",
    "approval.requested": "Approval requested",
    "approval.review_opened": "Approval review opened",
    "approval.decision_recorded": "Approval decision recorded",
    "approval.approved": "Approval recorded",
    "approval.denied": "Approval denied",
    "control_plane.approval.requested": "Control-plane approval requested",
    "control_plane.approval.approved": "Control-plane approval recorded",
    "control_plane.approval.denied": "Control-plane approval denied",
    "control_plane.approval.consumed": "Control-plane approval consumed",
    "control_plane.approval.invalidated": "Control-plane approval invalidated",
}
_CATALOG = {
    "credential.created": "Provider key saved",
    "credential.github_token_created": "GitHub token saved",
    "credential.github_app_created": "GitHub App connection saved",
    "credential.github_app_key_replaced": "GitHub App private key replaced; assignments preserved",
    "credential.npm_token_created": "npm token saved",
    "credential.x_app_bearer_created": "X app-only token saved",
    "credential.alchemy_key_created": "Alchemy key saved",
    "credential.aws_sigv4_created": "AWS credentials saved locally",
    "credential.aws_sigv4_replaced": "AWS credentials replaced locally",
    "credential.key_replaced": "Provider key replaced",
    "credential.revoked": "Provider key revoked locally",
    "application.created": "Application identity created",
    "application.revoked": "Application identity revoked",
    "application.token_rotated": "Application token rotated",
    "application.renewal_enrolled": "Managed client renewal enrolled",
    "application.renewal_cancelled": "Managed client renewal cancelled",
    "application.token_renewed": "Managed client token renewed",
    "application.proxy_authentication_changed": "Application proxy login changed",
    "access_rule.created": "Application permission saved",
    "access_rule.github_created": "GitHub application permission saved",
    "access_rule.npm_metadata_created": "npm package metadata permission saved",
    "access_rule.npm_publish_created": "npm package publishing permission saved",
    "access_rule.npm_install_created": "npm installation permission saved",
    "access_rule.x_username_created": "X username lookup permission saved",
    "access_rule.alchemy_chain_status_created": "Alchemy chain status permission saved",
    "access_rule.revoked": "Application permission revoked",
    "upstream_setup.prepared": "Proxy destination change prepared; restart required",
    "upstream_setup.cancelled": "Prepared proxy destination change cancelled",
    "upstream_setup.activated": "Proxy destination configuration activated",
    "google_setup.prepared": "Google provider configuration prepared; restart required",
    "google_setup.cancelled": "Prepared Google provider configuration cancelled",
    "google_setup.activated": "Google provider configuration activated",
}
_SUMMARIES.update({"operator_catalog." + key: value for key, value in _CATALOG.items()})
_SUMMARIES.update(_HOST_SUMMARIES)
_SUMMARIES.update(ecr.SUMMARIES)
_GITHUB_APP_CREATED = "operator_catalog.credential.github_app_created"
_GITHUB_APP_KEY_REPLACED = "operator_catalog.credential.github_app_key_replaced"
_GITHUB_APP_EVENTS = {_GITHUB_APP_CREATED, _GITHUB_APP_KEY_REPLACED}
_X_CONFIGURATION_SAVED = "operator_catalog.x_oauth.configuration_saved"
_X_CONFIGURATION_PREFIX = "operator-x-configuration:"
_SUMMARIES[_X_CONFIGURATION_SAVED] = "X application configuration saved; account consent is separate"
# Ordinary Google lifecycle history, never a live action-required source. Keep
# intent/exchange bookkeeping and internal schema admission out of the filters.
_GOOGLE_SUMMARIES = {
    "operator_catalog.oauth.consent_started": "Google account consent started",
    "operator_catalog.oauth.account_connected": "Google account connected; application access is separate",
    "operator_catalog.oauth.consent_failed": "Google account consent failed; review account status",
    "credential.oauth_refreshed": "Google account access token refreshed",
    "credential.oauth_refresh_failed": "Google account refresh failed; review account status",
    "operator_catalog.oauth.reauthorization_started": "Google account reauthorization started",
    "operator_catalog.oauth.reauthorized": "Google account reauthorization committed",
    "operator_catalog.oauth.reauthorization_failed": "Google account reauthorization failed; review retained status",
    "operator_catalog.oauth.disconnect_requested": "Google disconnect requested; provider acceptance is not yet proven",
    "operator_catalog.oauth.disconnect_provider_accepted": "Google accepted disconnect; propagation is not proven",
    "operator_catalog.oauth.disconnect_retry_retained": "Google disconnect remains unconfirmed; retry retained",
    "operator_catalog.oauth.cleanup_quarantined": "Google account access quarantined; review cleanup status",
    "operator_catalog.oauth.cleanup_fenced": "Google cleanup locally fenced; provider outcome is separate",
    "operator_catalog.oauth.refresh_rejected": "Google rejected refresh; no new account material was issued",
}
_SUMMARIES.update(_GOOGLE_SUMMARIES)
_GOOGLE_IDS = {
    "operator_catalog.oauth.reauthorized": ("operator-google-reauthorized:", "operation_id"),
    "operator_catalog.oauth.refresh_rejected": ("operator-google-refresh-rejected:", "work_id"),
}
# These producers use idempotency keys as audit IDs, not generated event UUIDs.
# Only their six exact type/namespace/action pairings are admitted; this is not
# a general extension to notification IDs or to action-required sources.
_SETUP_IDS = {"operator_catalog." + kind + "." + action: (prefix, ":" + action)
    for kind, prefix in (("upstream_setup", "operator-upstream-setup:"),
                         ("google_setup", "operator-google-setup:"))
    for action in ("prepared", "cancelled", "activated")}
ACTION_EVENT_TYPES = tuple(sorted(("approval.requested", "control_plane.approval.requested", HOST_REQUESTED, ecr.STAGED, *NATIVE_EVENT_TYPES)))
AUDIT_EVENT_TYPES = tuple(sorted((*_SUMMARIES, *NATIVE_EVENT_TYPES)))
_LEGACY = {"approval_request_id", "route_id", "method", "url_commitment", "expires_at"}
_JIT = _LEGACY | {"principal_id", "credential_id", "credential_version", "policy_hash",
    "request_digest", "operation_digest", "grant_ttl_seconds", "grant_max_uses", "approver_policy_digest"}
_CONTROL = {"approval_id", "action", "resource_id", "payload_digest", "requester_id", "expires_at", "request"}


class NotificationEventError(ValueError):
    """Fixed, secret-safe source refusal."""


@dataclass(frozen=True)
class EventCursor:
    rowid: int = 0
    event_id: str | None = None
    event_hash: str | None = None


@dataclass(frozen=True)
class SourceEvent:
    event_id: str
    event_hash: str
    created_at: str
    event_type: str
    audit_payload: dict
    action_payload: dict | None
    # A native observation has one durable audit type, with independently
    # selectable closed phase filters. Its source metadata remains unchanged.
    filter_event_type: str | None = None


def _require(condition):
    if not condition:
        raise NotificationEventError(_ERROR)


def _integer(value, minimum=0, maximum=_MAX_INT):
    return type(value) is int and minimum <= value <= maximum


def _uuid(value):
    try:
        return isinstance(value, str) and len(value) == 36 and str(uuid.UUID(value)) == value
    except ValueError:
        return False


def _hash(value):
    return isinstance(value, str) and _HASH.fullmatch(value) is not None


def _setup_operation(identifier, event_type):
    pair = _SETUP_IDS.get(event_type)
    if pair is None or not isinstance(identifier, str):
        return None
    prefix, suffix = pair
    if not identifier.startswith(prefix) or not identifier.endswith(suffix):
        return None
    operation = identifier[len(prefix):-len(suffix)]
    return operation if _uuid(operation) else None


def _event_identifier(identifier, event_type):
    if event_type == _X_CONFIGURATION_SAVED:
        return (isinstance(identifier, str) and identifier.startswith(_X_CONFIGURATION_PREFIX)
            and _uuid(identifier[len(_X_CONFIGURATION_PREFIX):]))
    if event_type in _GITHUB_APP_EVENTS:
        return _uuid(identifier)
    if event_type in _SETUP_IDS:
        return _setup_operation(identifier, event_type) is not None
    if event_type in _GOOGLE_IDS:
        prefix, _ = _GOOGLE_IDS[event_type]
        return isinstance(identifier, str) and identifier.startswith(prefix) and _uuid(identifier[len(prefix):])
    if event_type in _GOOGLE_SUMMARIES:
        return _uuid(identifier)
    return _uuid(identifier) or _hash(identifier)


def _setup_binding(row, event):
    if row["event_type"] not in _SETUP_IDS:
        return True
    operation = _setup_operation(row["event_id"], row["event_type"])
    return (operation is not None and row["actor_type"] == "admin" and type(event) is dict
        and event.get("operation_id") == operation)


def _identifier(value):
    if _uuid(value):
        return True
    return isinstance(value, str) and any(value.startswith(prefix) and _uuid(value[len(prefix):])
        for prefix in ("operator.", "agent:operator-demo:"))


def _text(value, maximum):
    return isinstance(value, str) and 0 < len(value) <= maximum and value.isascii() and all(32 <= ord(c) <= 126 for c in value)


def _epoch(value):
    _require(isinstance(value, str) and _STAMP.fullmatch(value) is not None)
    instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
    delta = instant - datetime(1970, 1, 1, tzinfo=timezone.utc)
    result = delta.days * 86_400_000 + delta.seconds * 1000 + delta.microseconds // 1000
    _require(_integer(result))
    return result


def _snapshot(conn):
    # query_only alone can be enabled after a write. A fresh connection with
    # zero lifetime DML prevents reading its own uncommitted audit append.
    _require(isinstance(conn, sqlite3.Connection) and conn.in_transaction and conn.total_changes == 0)
    _require(conn.execute("PRAGMA query_only").fetchone()[0] == 1)
    _require(conn.execute("PRAGMA read_uncommitted").fetchone()[0] == 0)


def _cursor(value):
    _require(type(value) is EventCursor and _integer(value.rowid))
    if value.rowid == 0:
        _require(value.event_id is None and value.event_hash is None)
    else:
        _require(_text(value.event_id, 256) and _hash(value.event_hash))


def _bounded(name, maximum):
    # Keep actual NULL distinct from malformed/oversized values. Otherwise a
    # changed invalid nullable binding could accidentally compare equal to None.
    return (f"CASE WHEN {name} IS NULL THEN NULL WHEN typeof({name})='text' "
            f"AND length(CAST({name} AS BLOB)) BETWEEN 1 AND {maximum} "
            f"THEN {name} ELSE 0 END")


def _bounded_integer(name):
    return (f"CASE WHEN {name} IS NULL THEN NULL WHEN typeof({name})='integer' "
            f"AND {name} BETWEEN 1 AND {_MAX_INT} THEN {name} ELSE 0 END")


_COLUMNS = "rowid," + ",".join(_bounded(name, maximum) for name, maximum in (
    ("id", 256), ("event_hash", 71), ("prev_event_hash", 71), ("event_type", 128),
    ("created_at", 40), ("actor_type", 32), ("actor_id", 256)))


def _metadata(row):
    _require(row is not None)
    sequence, identifier, digest, previous, kind, created, actor_type, actor_id = tuple(row)
    _require(_integer(sequence, 1) and _text(identifier, 256) and _hash(digest))
    _require(previous is None or _hash(previous))
    _require(_text(kind, 128))
    _epoch(created)
    return dict(rowid=sequence, event_id=identifier, event_hash=digest,
        previous=previous, event_type=kind, created_at=created,
        actor_type=actor_type, actor_id=actor_id)


def _as_cursor(row):
    return EventCursor(row["rowid"], row["event_id"], row["event_hash"])


def head_cursor(conn) -> EventCursor:
    """Explicit initial baseline; does not replay history or mutate a cursor."""
    try:
        _snapshot(conn)
        row = conn.execute("SELECT " + _COLUMNS + " FROM audit_events ORDER BY rowid DESC LIMIT 1").fetchone()
        return EventCursor() if row is None else _as_cursor(_metadata(row))
    except (sqlite3.Error, ValueError, TypeError, OverflowError):
        raise NotificationEventError(_ERROR) from None


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result)
        result[key] = value
    return result


def _nonfinite(_value):
    raise NotificationEventError(_ERROR)


def _payload(conn, sequence):
    row = conn.execute("SELECT CAST(event_json AS BLOB) FROM audit_events WHERE rowid=? "
        "AND typeof(event_json)='text' AND length(CAST(event_json AS BLOB))<=?",
        (sequence, MAX_EVENT_BYTES)).fetchone()
    if row is None:
        return None
    try:
        value = json.loads(row[0].decode("utf-8", "strict"), object_pairs_hook=_pairs, parse_constant=_nonfinite)
        if not isinstance(value, dict):
            return None
        pending, count = [(value, 0)], 0
        while pending:
            item, depth = pending.pop()
            count += 1
            _require(depth <= 24 and count <= 2048)
            if isinstance(item, dict):
                pending.extend((child, depth + 1) for child in item.values())
            elif isinstance(item, list):
                pending.extend((child, depth + 1) for child in item)
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return None


def _details(row, event):
    result = {}
    if row["actor_type"] in _ACTORS:
        result["actor_type"] = row["actor_type"]
    if _identifier(row["actor_id"]):
        result["actor_id"] = row["actor_id"]
    if event is None:
        return result
    for key in ("resource_id", "application_id", "credential_id", "credential_ref",
                "connection_id", "approval_id", "approval_request_id", "route_id", "principal_id", "operation_id", "enrollment_id"):
        if _identifier(event.get(key)):
            result[key] = event[key]
    for key in ("policy_hash", "request_digest", "operation_digest", "payload_digest"):
        if _hash(event.get(key)):
            result[key] = event[key]
    for key in ("revision", "policy_sequence", "credential_version", "credential_generation", "token_generation"):
        if _integer(event.get(key)):
            result[key] = event[key]
    for key, choices in (("method", _METHODS), ("decision", {"allow", "deny"}),
                         ("outcome", {"released", "blocked", "allow", "deny"}),
                         ("resource_type", {"credential", "application", "access_rule"})):
        if isinstance(event.get(key), str) and event[key] in choices:
            result[key] = event[key]
    if _integer(event.get("upstream_status"), 100, 599):
        result["upstream_status"] = event["upstream_status"]
    return result


def _provider_configuration_details(row, event):
    """Exact committed producer records, not provider readiness or actions.

    Do not fall back to metadata-only delivery for these closed producers.
    Raw profiles, App keys, client IDs and secrets are never copied here.
    """
    _require(type(event) is dict and row["actor_type"] == "admin"
        and _text(row["actor_id"], 256))
    if row["event_type"] in _GITHUB_APP_EVENTS:
        replaced = row["event_type"] == _GITHUB_APP_KEY_REPLACED
        fields = {"resource_type", "resource_id", "revision", "policy_hash", "policy_sequence"}
        if replaced:
            fields |= {"previous_credential_generation", "credential_generation"}
        _require(set(event) == fields
            and event["resource_type"] == "credential" and _uuid(event["resource_id"])
            and _integer(event["revision"], 1) and _integer(event["policy_sequence"], 1)
            and _hash(event["policy_hash"]))
        result = {**_details(row, event), "provider": "github"}
        if replaced:
            _require(_integer(event["previous_credential_generation"], 1, _MAX_INT - 1)
                and _integer(event["credential_generation"], 2)
                and event["credential_generation"] == event["previous_credential_generation"] + 1)
            result["previous_credential_generation"] = event["previous_credential_generation"]
        return result
    _require(row["event_type"] == _X_CONFIGURATION_SAVED
        and set(event) == {"operation_id", "actor_id", "config_version", "reviewed_revision",
            "committed_revision", "policy_hash", "profile_binding_digest", "created_at"}
        and row["event_id"] == _X_CONFIGURATION_PREFIX + str(event["operation_id"])
        and _uuid(event["operation_id"]) and event["actor_id"] == row["actor_id"]
        and _integer(event["config_version"], 1, 1)
        and _integer(event["reviewed_revision"], 1, _MAX_INT - 2)
        and _integer(event["committed_revision"], 2)
        and event["committed_revision"] == event["reviewed_revision"] + 1
        and _hash(event["policy_hash"]) and _hash(event["profile_binding_digest"]))
    _epoch(event["created_at"])
    return {**_details(row, event), "provider": "x", **{key: event[key]
        for key in ("config_version", "reviewed_revision", "committed_revision")}}


def _google_details(row, event):
    """Closed producer-specific audit projection; no account or token reads.

    Rich producer receipts are not notification DTOs. Validate their public
    lifecycle bindings and copy only explicitly selected scalar references and
    counts. Malformed new-family events have no metadata-only fallback.
    """
    kind = row["event_type"]
    _require(type(event) is dict and _text(row["actor_id"], 256)
        and _event_identifier(row["event_id"], kind))
    system = kind in {"credential.oauth_refreshed", "credential.oauth_refresh_failed",
        "operator_catalog.oauth.refresh_rejected"}
    _require(row["actor_type"] == ("system" if system else "admin"))
    if kind in _GOOGLE_IDS:
        prefix, key = _GOOGLE_IDS[kind]
        _require(_uuid(event.get(key)) and row["event_id"] == prefix + event[key])
    result = {"actor_type": row["actor_type"], "provider": "google"}
    if _identifier(row["actor_id"]):
        result["actor_id"] = row["actor_id"]

    def references(*keys):
        for key in keys:
            _require(_uuid(event.get(key)))
            result[key] = event[key]

    def numbers(*keys):
        for key in keys:
            _require(_integer(event.get(key), 1))
            result[key] = event[key]

    def policy(revision="revision"):
        numbers(revision)
        _require(_hash(event.get("policy_hash")))
        result["policy_hash"] = event["policy_hash"]

    def count(key, output):
        value = event.get(key)
        _require(type(value) is list and len(value) <= 1024 and all(_uuid(item) for item in value)
            and value == sorted(set(value)))
        result[output] = len(value)

    if kind in {"credential.oauth_refreshed", "credential.oauth_refresh_failed"}:
        _require(row["actor_id"] == "oauth-refresh" and event.get("provider") == "google")
        references("credential_id")
        numbers("credential_version")
        if kind == "credential.oauth_refreshed":
            numbers("previous_credential_version")
            _require(event["credential_version"] > event["previous_credential_version"]
                and _integer(event.get("expires_at_epoch_ms"), 1)
                and type(event.get("refresh_token_rotated")) is bool)
        else:
            _require(event.get("reason") in ("OAuthError", "ValueError", "TypeError", "JSONDecodeError"))
    elif kind in {"operator_catalog.oauth.consent_started", "operator_catalog.oauth.account_connected",
                  "operator_catalog.oauth.consent_failed"}:
        _require(event.get("provider") == "google")
        references("intent_id")
        if kind == "operator_catalog.oauth.consent_failed":
            _require(event.get("reason") in ("consent_denied", "exchange_failed", "persistence_failed", "identity_conflict"))
        else:
            connected = kind == "operator_catalog.oauth.account_connected"
            _require(event.get("status") == ("connected" if connected else "awaiting_consent")
                and event.get("reason") is None)
            if connected:
                references("credential_id")
            else:
                _require("credential_id" in event and event["credential_id"] is None)
            policy()
    elif kind in {"operator_catalog.oauth.reauthorization_started", "operator_catalog.oauth.reauthorized",
                  "operator_catalog.oauth.reauthorization_failed"}:
        references("operation_id", "credential_id")
        if kind == "operator_catalog.oauth.reauthorization_failed":
            _require(event.get("status") in ("review_required", "denied", "failed")
                and event.get("reason") in ("start_failed", "state_changed", "consent_denied", "exchange_failed",
                    "adoption_uncertain", "identity_mismatch", "candidate_unavailable")
                and event.get("provider_revocation") == "not_requested")
        else:
            numbers("credential_generation")
            policy()
            count("affected_rule_ids", "affected_rule_count")
            if kind == "operator_catalog.oauth.reauthorized":
                _require(event.get("schema") == "catchplate.operatorGoogleReauthorizationReceipt/v1")
                references("original_oauth_intent_id")
                numbers("previous_credential_generation")
                _require(event["credential_generation"] == event["previous_credential_generation"] + 1)
                count("application_ids", "application_count")
    elif kind in {"operator_catalog.oauth.disconnect_requested", "operator_catalog.oauth.disconnect_provider_accepted",
                  "operator_catalog.oauth.disconnect_retry_retained"}:
        references("operation_id", "credential_id")
        if kind == "operator_catalog.oauth.disconnect_requested":
            _require(event.get("schema") == "catchplate.operatorGoogleDisconnectReceipt/v1"
                and event.get("actor_id") == row["actor_id"] and event.get("project_wide_acknowledged") is True)
            policy()
            numbers("policy_sequence")
            count("credential_ids", "credential_count")
            _require(event["credential_id"] in event["credential_ids"])
            count("affected_rule_ids", "affected_rule_count")
            count("affected_application_ids", "application_count")
        elif kind == "operator_catalog.oauth.disconnect_provider_accepted":
            _require(event.get("provider") == "google" and event.get("provider_outcome") == "accepted"
                and event.get("propagation") == "not_proven" and event.get("reconnect") == "blocked")
        else:
            _require(event.get("provider_outcome") == "not_proven")
            numbers("attempts")
            _epoch(event.get("next_attempt_at"))
    elif kind in {"operator_catalog.oauth.cleanup_quarantined", "operator_catalog.oauth.cleanup_fenced"}:
        references("work_id")
        count("credential_ids", "credential_count")
        if kind == "operator_catalog.oauth.cleanup_quarantined":
            policy()
            count("revoked_rule_ids", "revoked_rule_count")
            _require(event.get("reason") in ("operator_google_rejected", "google_grant_collision",
                "registration_failed", "refresh_failed", "explicit_disconnect"))
        else:
            _require(event.get("schema") == "catchplate.operatorGoogleCleanupFence/v1"
                and event.get("source") in ("operator_google_initial_v1", "operator_google_refresh_v1",
                    "operator_google_disconnect_v1", "operator_google_reauthorization_v1"))
            policy("catalog_revision")
    else:
        _require(kind == "operator_catalog.oauth.refresh_rejected"
            and event.get("schema") == "catchplate.operatorGoogleRefreshRejected/v1"
            and event.get("source") == "operator_google_refresh_v1"
            and event.get("outcome") == "definite_refresh_rejected" and event.get("issued_material") is False
            and event.get("provider_revocation") == "not_requested")
        references("work_id", "credential_id")
        numbers("credential_generation")
        status = event.get("http_status")
        codes = ("invalid_request", "invalid_client", "invalid_grant", "unauthorized_client",
            "unsupported_grant_type", "invalid_scope") if type(status) is int and status == 400 else (
            ("invalid_client",) if type(status) is int and status == 401 else ())
        _require(event.get("error_code") in codes)
    return result


def _envelope(row, channel, summary, details):
    return {"schema": SCHEMA, "channel": channel,
        "source": {key: row[key] for key in ("event_id", "event_hash", "event_type", "created_at")},
        "summary": summary, "review_path": "/#audit", "details": details}


def _native_record(value):
    # This parser is pure: no configured imports, socket, DNS, or custody access.
    # Historical records retain their original expiry; validation never renews it.
    from catchplate.operator_notification_pilot_source import validate_record
    result = validate_record(value)
    observation = result["observation"]
    _require(observation["actionAvailable"] is True and observation["phase"] in _NATIVE_SUMMARIES
        and observation["eventType"] == "native_pilot." + observation["phase"])
    return result


def native_event_identifier(record):
    """Stable audit key for one admitted selection and original native event."""
    record = _native_record(record)
    binding = {"selection_sha256": record["selection_sha256"],
        "native_event_id": record["observation"]["eventId"]}
    encoded = json.dumps(binding, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def native_expiry_unix_nanos(payload):
    """Exact original expiry, never converted through a float or rounded up."""
    _require(type(payload) is dict and type(payload.get("details")) is dict
        and set(payload["details"]) == {"native_pilot"})
    return int(_native_record(payload["details"]["native_pilot"])["observation"]["sourceExpiresAtUnixNanos"])


def _native_projection(row, record, channel):
    record = _native_record(record)
    observation = record["observation"]
    _require(row["event_type"] == NATIVE_OBSERVATION_TYPE
        and row["event_id"] == native_event_identifier(record)
        and row["actor_type"] == "system" and row["actor_id"] == "native-pilot-observer")
    summary = _NATIVE_SUMMARIES[observation["phase"]]
    result = _envelope(row, channel, summary if channel == "action_required" else
        "Native pilot phase observed: " + observation["phase"].replace("_", " "), {"native_pilot": record})
    if channel == "action_required":
        result["review_path"] = observation["reviewPath"]
    else:
        result["projection"] = "approved_fields"
    return result


def native_action_payload(payload) -> bool:
    """Closed shape/binding recognition, not live-owner or dispatch authority."""
    try:
        _require(type(payload) is dict and type(payload.get("source")) is dict)
        source = payload["source"]
        _require(set(source) == {"event_id", "event_hash", "event_type", "created_at"}
            and _hash(source["event_id"]) and _hash(source["event_hash"]))
        _epoch(source["created_at"])
        row = dict(source, actor_type="system", actor_id="native-pilot-observer")
        record = payload.get("details", {}).get("native_pilot")
        return _same_projection(payload, _native_projection(row, record, "action_required"))
    except (ValueError, TypeError, OverflowError, RecursionError, KeyError, AttributeError):
        return False


def native_action_matches_source(conn, payload, *, now_unix_nanos: int) -> bool:
    """Local committed-source and original-clock check; never polls the relay.

The worker must separately compare a fresh admitted relay observation immediately
before dispatch. A matching historical audit row alone cannot establish liveness.
"""
    try:
        _snapshot(conn)
        _require(type(now_unix_nanos) is int and now_unix_nanos >= 0 and native_action_payload(payload))
        source = payload["source"]
        row = _metadata(conn.execute("SELECT " + _COLUMNS + " FROM audit_events WHERE id=?", (source["event_id"],)).fetchone())
        expected = _native_projection(row, _payload(conn, row["rowid"]), "action_required")
        return (_same_projection(payload, expected) and _epoch(row["created_at"]) * 1_000_000 <= now_unix_nanos
            and now_unix_nanos < native_expiry_unix_nanos(expected))
    except (sqlite3.Error, ValueError, TypeError, OverflowError, RecursionError, KeyError, AttributeError):
        return False


def _host_details(row, event):
    """Closed host-trusted audit metadata; never a private request or note."""
    kind = row["event_type"]
    fields = set(_HOST_COMMON)
    if kind == HOST_REQUESTED:
        fields = _HOST_REQUEST
    elif kind in {"operator.host_approval.reviewed", "operator.host_approval.approved", "operator.host_approval.denied"}:
        fields |= {"review_receipt_id", "review_digest"}
        if kind != "operator.host_approval.reviewed":
            fields |= {"note"}
    elif kind == "operator.host_approval.claimed":
        fields |= {"attempt_id"}
    _require(kind in _HOST_SUMMARIES and type(event) is dict and set(event) == fields
        and event["assurance"] == "host-trusted" and _uuid(row["event_id"])
        and row["actor_type"] == ("proxy" if kind in {HOST_REQUESTED, "operator.host_approval.claimed"} else "admin")
        and _text(row["actor_id"], 256) and _uuid(event["approval_request_id"])
        and _uuid(event["credential_id"]) and _integer(event["credential_version"], 1)
        and _text(event["principal_id"], 256) and _text(event["route_id"], 256)
        and all(_hash(event[key]) for key in ("policy_hash", "request_digest", "operation_digest")))
    if row["actor_type"] == "proxy":
        _require(row["actor_id"] == event["principal_id"])
    if kind == HOST_REQUESTED:
        _require(event["method"] in _METHODS and _text(event["reviewer_id"], 256)
            and _hash(event["approver_policy_digest"]) and _hash(event["url_commitment"]))
        _epoch(event["expires_at"])
        _epoch(event["requested_at"])
    elif "review_receipt_id" in fields:
        _require(_uuid(event["review_receipt_id"]) and _hash(event["review_digest"]))
    elif "attempt_id" in fields:
        _require(_hash(event["attempt_id"]))
    return {key: event[key] for key in sorted(fields - {"note"})}


def _host_projection(row, event):
    _require(row["event_type"] == HOST_REQUESTED)
    details = _host_details(row, event)
    result = _envelope(row, "action_required", "Review host-trusted approval request", {"host_approval": details})
    result.update(review_path="/approvals/" + event["approval_request_id"] + "#pending-actions",
        approval_ref={"kind": "host_approval_request", "id": event["approval_request_id"],
            "source_digest": event["request_digest"]}, expires_at=event["expires_at"])
    return result


def host_action_payload(payload) -> bool:
    """Typed recognition only; configured reviewer and current row are separate."""
    try:
        _require(type(payload) is dict and type(payload.get("source")) is dict)
        source = payload["source"]
        _require(set(source) == {"event_id", "event_hash", "event_type", "created_at"}
            and _uuid(source["event_id"]) and _hash(source["event_hash"]))
        _epoch(source["created_at"])
        event = payload["details"]["host_approval"]
        row = dict(source, actor_type="proxy", actor_id=event["principal_id"])
        return _same_projection(payload, _host_projection(row, event))
    except (ValueError, TypeError, OverflowError, KeyError, AttributeError):
        return False


def _host_pending(conn, row, event, now):
    _host_details(row, event)
    if _epoch(row["created_at"]) > now or _epoch(event["expires_at"]) <= now:
        return False
    fields = ("route_id", "method", "expires_at", "principal_id", "credential_id", "credential_version",
        "policy_hash", "request_digest", "operation_digest", "approver_policy_digest")
    columns = [_bounded("status", 32), _bounded("requested_at", 40)] + [
        _bounded_integer(key) if key == "credential_version" else _bounded(key, 512) for key in fields]
    columns += [_bounded("url", 71), _bounded("approver_policy_json", 1024),
        _bounded_integer("grant_ttl_seconds"), _bounded_integer("grant_max_uses")]
    current = conn.execute("SELECT " + ",".join(columns) + " FROM approval_requests WHERE id=?",
        (event["approval_request_id"],)).fetchone()
    # Match the producer's exact closed host-reviewer policy, not any legacy or
    # native approval that happens to share its public request digests.
    policy = {"schema": "catchplate.hostTrustedApprovalReviewer/v1", "assurance": "host-trusted",
        "reviewerId": event["reviewer_id"], "maxUses": 1, "pendingTtlSeconds": 300, "approvalTtlSeconds": 60}
    encoded = json.dumps(policy, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return (current is not None and current[0] == "pending" and current[1] == event["requested_at"]
        and _epoch(current[1]) <= _epoch(row["created_at"])
        and all(current[index + 2] == event[key] for index, key in enumerate(fields))
        and tuple(current[-4:]) == (event["url_commitment"], encoded, 60, 1)
        and "sha256:" + hashlib.sha256(encoded.encode("ascii")).hexdigest() == event["approver_policy_digest"])


def host_action_matches_source(conn, payload, *, reviewer_id, now_epoch_ms) -> bool:
    """Fresh committed metadata only; runtime availability is owned by the store."""
    try:
        _snapshot(conn)
        _require(_integer(now_epoch_ms) and host_action_payload(payload))
        _require(payload["details"]["host_approval"]["reviewer_id"] == reviewer_id)
        row = _metadata(conn.execute("SELECT " + _COLUMNS + " FROM audit_events WHERE id=?",
            (payload["source"]["event_id"],)).fetchone())
        event = _payload(conn, row["rowid"])
        return (_same_projection(payload, _host_projection(row, event))
            and _host_pending(conn, row, event, now_epoch_ms))
    except (sqlite3.Error, ValueError, TypeError, OverflowError, KeyError, AttributeError):
        return False


def _approval(conn, row, event, now):
    """Read only selected metadata; never decrypt a request/review/challenge."""
    if event is None or row["event_type"] not in ACTION_EVENT_TYPES:
        return None
    expiry = _epoch(event.get("expires_at"))
    if expiry <= now or _epoch(row["created_at"]) > now:
        return None
    control = row["event_type"] == "control_plane.approval.requested"
    identifier = event.get("approval_id" if control else "approval_request_id")
    if not _uuid(identifier):
        return None
    if control:
        if set(event) != _CONTROL or not isinstance(event["request"], dict):
            return None
        if not _hash(event["payload_digest"]) or not _text(event["action"], 128) or not _text(event["requester_id"], 512):
            return None
        fields = ("action", "resource_id", "payload_digest", "requester_id", "expires_at")
        columns = _bounded("status", 32) + "," + _bounded("requested_at", 40) + "," + ",".join(_bounded(key, 512) for key in fields)
        current = conn.execute("SELECT " + columns + " FROM control_plane_approvals WHERE id=?", (identifier,)).fetchone()
        digest = event["payload_digest"]
    else:
        if set(event) not in (_LEGACY, _JIT) or event.get("method") not in _METHODS:
            return None
        if not _identifier(event.get("route_id")) or not _hash(event.get("url_commitment")):
            return None
        fields = ("route_id", "method", "expires_at", "principal_id", "credential_id", "credential_version",
            "policy_hash", "request_digest", "operation_digest", "grant_ttl_seconds", "grant_max_uses", "approver_policy_digest")
        if set(event) == _JIT and (not _identifier(event["principal_id"]) or not _uuid(event["credential_id"])
                or not all(_hash(event[key]) for key in ("policy_hash", "request_digest", "approver_policy_digest"))
                or (event["operation_digest"] is not None and not _hash(event["operation_digest"]))
                or not _integer(event["credential_version"], 1)
                or not _integer(event["grant_ttl_seconds"], 1, 3600) or not _integer(event["grant_max_uses"], 1)):
            return None
        integer_fields = {"credential_version", "grant_ttl_seconds", "grant_max_uses"}
        columns = _bounded("status", 32) + "," + _bounded("requested_at", 40) + "," + ",".join(
            _bounded_integer(key) if key in integer_fields else _bounded(key, 512) for key in fields)
        current = conn.execute("SELECT " + columns + "," + _bounded("url", 8192)
            + " FROM approval_requests WHERE id=?", (identifier,)).fetchone()
        if current is None or not isinstance(current[-1], str):
            return None
        stored_url = current[-1] if set(event) == _JIT else "sha256:" + hashlib.sha256(current[-1].encode("utf-8")).hexdigest()
        if stored_url != event["url_commitment"]:
            return None
        digest = event.get("request_digest", event["url_commitment"])
    if current is None or current[0] != "pending" or _epoch(current[1]) > _epoch(row["created_at"]):
        return None
    if any(current[index + 2] != event.get(key) for index, key in enumerate(fields)):
        return None
    result = _envelope(row, "action_required", "Review approval request", {})
    result.update(approval_ref={"kind": "control_plane_approval" if control else "approval_request",
        "id": identifier, "source_digest": digest}, expires_at=event["expires_at"])
    return result


def _audit_projection(row, event):
    if row["event_type"] in ecr.SUMMARIES:
        details = ecr.details(row, event)
    elif row["event_type"] in _HOST_SUMMARIES:
        details = _host_details(row, event)
    elif row["event_type"] in _GITHUB_APP_EVENTS | {_X_CONFIGURATION_SAVED}:
        details = _provider_configuration_details(row, event)
    else:
        details = _google_details(row, event) if row["event_type"] in _GOOGLE_SUMMARIES else _details(row, event)
    audit = _envelope(row, "audit_log", _SUMMARIES[row["event_type"]], details)
    audit["projection"] = "metadata_only" if event is None else "approved_fields"
    return audit


def _project(conn, row, now):
    if row["event_type"] == NATIVE_OBSERVATION_TYPE:
        try:
            record = _native_record(_payload(conn, row["rowid"]))
            audit = _native_projection(row, record, "audit_log")
            action = _native_projection(row, record, "action_required")
            if _epoch(row["created_at"]) > now or now * 1_000_000 >= native_expiry_unix_nanos(action):
                action = None
            return SourceEvent(row["event_id"], row["event_hash"], row["created_at"], row["event_type"],
                audit, action, record["observation"]["eventType"])
        except (ValueError, TypeError, OverflowError, RecursionError, KeyError, AttributeError):
            return None  # An invalid observation is not an actionable source.
    if row["event_type"] not in _SUMMARIES or not _event_identifier(row["event_id"], row["event_type"]):
        return None
    event = _payload(conn, row["rowid"])
    if not _setup_binding(row, event):
        return None
    try:
        audit = _audit_projection(row, event)
    except (ValueError, TypeError, OverflowError):
        return None
    try:
        if row["event_type"] == ecr.STAGED:
            action = ecr.action(conn, row, event, now)
        elif row["event_type"] == HOST_REQUESTED:
            action = _host_projection(row, event) if _host_pending(conn, row, event, now) else None
        else:
            action = _approval(conn, row, event, now)
    except (ValueError, TypeError, OverflowError, KeyError, AttributeError, sqlite3.Error):
        action = None  # No source owner/schema means no action claim.
    return SourceEvent(row["event_id"], row["event_hash"], row["created_at"], row["event_type"], audit, action)


def read_batch(conn, cursor: EventCursor, *, limit=32, now_epoch_ms: int) -> tuple[tuple[SourceEvent, ...], EventCursor]:
    """Bounded ascending scan. Unknown/notification events advance, not deliver."""
    try:
        _snapshot(conn)
        _cursor(cursor)
        _require(_integer(limit, 1, MAX_BATCH) and _integer(now_epoch_ms))
        if cursor.rowid:
            anchor = _metadata(conn.execute("SELECT " + _COLUMNS + " FROM audit_events WHERE rowid=?", (cursor.rowid,)).fetchone())
            _require(_as_cursor(anchor) == cursor)
        rows = conn.execute("SELECT " + _COLUMNS + " FROM audit_events WHERE rowid>? ORDER BY rowid LIMIT ?",
            (cursor.rowid, limit)).fetchall()
        result, next_cursor = [], cursor
        for raw in rows:
            row = _metadata(raw)
            _require(row["previous"] == next_cursor.event_hash and row["rowid"] > next_cursor.rowid)
            projected = _project(conn, row, now_epoch_ms)
            if projected is not None:
                result.append(projected)
            next_cursor = _as_cursor(row)
        return tuple(result), next_cursor
    except (sqlite3.Error, ValueError, TypeError, OverflowError, RecursionError):
        raise NotificationEventError(_ERROR) from None


def _same_projection(actual, expected):
    # Match against the small generated shape, not arbitrary retained JSON.
    # Plain dict equality would admit True in place of 1, or 200.0 for 200.
    if type(actual) is not type(expected):
        return False
    if type(expected) is dict:
        return actual.keys() == expected.keys() and all(
            _same_projection(actual[key], value) for key, value in expected.items())
    return actual == expected


def payload_matches_source(conn, payload, *, now_epoch_ms: int) -> bool:
    """Validate an undecorated queued audit copy against its exact safe source.

    Historical audit copies do not depend on an approval remaining pending.
    This reads no approval owner or ciphertext and never forwards an arbitrary
    request body. A stored hash is a reference, not an independent chain proof.
    """
    try:
        _snapshot(conn)
        _require(_integer(now_epoch_ms) and type(payload) is dict)
        source = payload.get("source")
        _require(type(source) is dict and _event_identifier(source.get("event_id"), source.get("event_type")))
        raw = conn.execute("SELECT " + _COLUMNS + " FROM audit_events WHERE id=?", (source["event_id"],)).fetchone()
        row = _metadata(raw)
        if row["event_type"] == NATIVE_OBSERVATION_TYPE:
            expected = _native_projection(row, _payload(conn, row["rowid"]), "audit_log")
        elif row["event_type"] not in _SUMMARIES:
            return False
        else:
            event = _payload(conn, row["rowid"])
            if not _event_identifier(row["event_id"], row["event_type"]) or not _setup_binding(row, event):
                return False
            expected = _audit_projection(row, event)
        return _same_projection(payload, expected)
    except (sqlite3.Error, ValueError, TypeError, OverflowError, RecursionError, KeyError, AttributeError):
        return False


def action_is_current(conn, payload, *, now_epoch_ms: int) -> bool:
    """Re-read the exact durable event and pending approval just before dispatch."""
    try:
        _snapshot(conn)
        _require(_integer(now_epoch_ms) and isinstance(payload, dict))
        source = payload.get("source")
        _require(isinstance(source, dict) and (_uuid(source.get("event_id")) or _hash(source.get("event_id"))))
        raw = conn.execute("SELECT " + _COLUMNS + " FROM audit_events WHERE id=?", (source["event_id"],)).fetchone()
        row = _metadata(raw)
        if row["event_type"] not in ACTION_EVENT_TYPES:
            return False
        projected = _project(conn, row, now_epoch_ms)
        return projected is not None and projected.action_payload is not None and projected.action_payload == payload
    except (sqlite3.Error, ValueError, TypeError, OverflowError, RecursionError):
        return False
