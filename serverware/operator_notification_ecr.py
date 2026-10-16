"""Closed ECR notification projections, not approval or publication authority.

Audit projection is pure. Only staged-action liveness calls the ordinary ECR
owner's read-only projection on the supplied committed snapshot. No artifact,
AWS tuple, signing header, reviewer note or client token is exported.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

PREFIX = "operator.ecr_publication."
STAGED = PREFIX + "staged"
SUMMARIES = {PREFIX + kind: summary for kind, summary in {
    "created": "ECR image publication created; staging required",
    "staged": "ECR image staged; whole-image review required",
    "reviewed": "Host-trusted ECR image review opened",
    "approved": "Host-trusted ECR image publication approved",
    "denied": "ECR image publication denied",
    "activated": "Approved ECR image publication started",
    "reserved": "ECR publication operation reserved",
    "possible_send": "ECR publication operation may have been sent",
    "acknowledged": "ECR publication response recorded",
    "recovered": "ECR publication state recovered after restart",
    "expired": "ECR image publication expired",
    "failed": "ECR image publication stopped",
    "uncertain": "ECR publication outcome is uncertain; do not retry automatically",
    "artifacts_retirement_requested": "Local ECR staging cleanup requested; no AWS image deletion",
    "artifacts_retired": "Local ECR staging cleanup completed; AWS images and audit history retained",
}.items()}
COMMON = {"assurance", "publication_id", "principal_id", "route_id", "credential_id",
    "credential_generation", "policy_hash", "manifest_digest", "artifact_sha256"}
PENDING = (COMMON - {"assurance"}) | {"created_at_epoch_ms", "expires_at_epoch_ms", "reviewer_id"}
REVIEW_PATH = "/#pending-actions"
_STATES = {"active", "published", "failed", "uncertain", "expired", "suspended"}
_ACTIONS = {"BatchCheckLayerAvailability", "InitiateLayerUpload", "UploadLayerPart", "CompleteLayerUpload", "PutImage"}


def details(row, event):
    from serverware import operator_notification_events as events
    need = events._require
    kind = row["event_type"]
    need(kind in SUMMARIES and type(event) is dict and COMMON <= set(event)
        and event["assurance"] == "host-trusted" and events._uuid(row["event_id"])
        and events._uuid(event["publication_id"]) and events._uuid(event["credential_id"])
        and events._integer(event["credential_generation"], 1)
        and events._text(event["principal_id"], 256) and events._text(event["route_id"], 256)
        and all(events._hash(event[key]) for key in ("policy_hash", "manifest_digest", "artifact_sha256")))
    admin = kind in {PREFIX + name for name in ("reviewed", "approved", "denied",
        "artifacts_retirement_requested", "artifacts_retired")}
    need(row["actor_type"] == ("admin" if admin else "proxy") and events._text(row["actor_id"], 256)
        and (admin or row["actor_id"] == event["principal_id"]))
    extra = set(event) - COMMON
    if kind == PREFIX + "reviewed":
        need(extra == {"review_receipt_id", "review_digest"}
            and events._uuid(event["review_receipt_id"]) and events._hash(event["review_digest"]))
    elif kind in {PREFIX + "approved", PREFIX + "denied"}:
        need(extra == {"review_digest"} and events._hash(event["review_digest"]))
    elif kind in {PREFIX + "reserved", PREFIX + "possible_send", PREFIX + "acknowledged"}:
        expected = {"child_id", "action", "request_sha256"}
        if kind == PREFIX + "acknowledged":
            expected |= {"response_sha256", "resulting_status", "authority_changed"}
            need(events._hash(event.get("response_sha256")) and event.get("resulting_status") in _STATES
                and type(event.get("authority_changed")) is bool)
        need(extra == expected and events._uuid(event["child_id"])
            and event["action"] in _ACTIONS and events._hash(event["request_sha256"]))
    elif kind == PREFIX + "recovered":
        need(extra == {"resulting_status"} and event["resulting_status"] in _STATES)
    elif kind == PREFIX + "artifacts_retired":
        need(extra == {"removed_files_this_attempt", "removed_bytes_this_attempt"}
            and all(events._integer(event[key]) for key in extra))
    elif kind in {PREFIX + "expired", PREFIX + "failed", PREFIX + "uncertain"}:
        need(extra == {"reason", "child_id", "action", "request_sha256"}
            and events._text(event["reason"], 128)
            and (event["child_id"] is None or events._uuid(event["child_id"]))
            and (event["action"] is None or event["action"] in _ACTIONS)
            and (event["request_sha256"] is None or events._hash(event["request_sha256"])))
    else:
        need(not extra)
    # Receipt IDs are not decision capabilities, but are unnecessary here.
    # Free-text terminal reasons and reviewer notes never leave the source.
    return {key: event[key] for key in sorted(set(event) - {"reason", "review_receipt_id"})}


def _projection(row, event, pending):
    from serverware import operator_notification_events as events
    events._require(row["event_type"] == STAGED)
    safe = details(row, event)
    events._require(type(pending) is dict and set(pending) == PENDING
        and all(pending[key] == safe[key] for key in COMMON - {"assurance"})
        and events._integer(pending["created_at_epoch_ms"], 1)
        and events._integer(pending["expires_at_epoch_ms"], pending["created_at_epoch_ms"] + 1)
        and events._text(pending["reviewer_id"], 256))
    expires = (datetime(1970, 1, 1, tzinfo=timezone.utc)
        + timedelta(milliseconds=pending["expires_at_epoch_ms"])).isoformat()
    result = events._envelope(row, "action_required", "Review the staged ECR image publication",
        {"ecr_publication": {**safe, **pending}})
    result.update(review_path=REVIEW_PATH, approval_ref={"kind": "ecr_image_publication",
        "id": event["publication_id"], "source_digest": event["artifact_sha256"]}, expires_at=expires)
    return result


def action(conn, row, event, now, *, reviewer_id=None):
    from serverware import operator_notification_events as events
    from serverware import operator_ecr_publications as owner
    details(row, event)
    pending = owner.notification_pending(conn, event["publication_id"],
        reviewer_id=reviewer_id, now_epoch_ms=now)
    if pending is None:
        return None
    if not pending["created_at_epoch_ms"] <= events._epoch(row["created_at"]) <= now < pending["expires_at_epoch_ms"]:
        return None
    return _projection(row, event, pending)


def action_payload(payload):
    from serverware import operator_notification_events as events
    try:
        events._require(type(payload) is dict and type(payload.get("source")) is dict
            and set(payload["source"]) == {"event_id", "event_hash", "event_type", "created_at"}
            and events._hash(payload["source"]["event_hash"]))
        source = payload["source"]
        events._epoch(source["created_at"])
        value = payload["details"]["ecr_publication"]
        event = {key: value[key] for key in COMMON}
        pending = {key: value[key] for key in PENDING}
        row = {**source, "actor_type": "proxy", "actor_id": event["principal_id"]}
        return events._same_projection(payload, _projection(row, event, pending))
    except (ValueError, TypeError, OverflowError, KeyError, AttributeError):
        return False


def matches_source(conn, payload, *, reviewer_id, now_epoch_ms):
    from serverware import operator_notification_events as events
    import sqlite3
    try:
        events._snapshot(conn)
        events._require(events._integer(now_epoch_ms) and action_payload(payload))
        events._require(payload["details"]["ecr_publication"]["reviewer_id"] == reviewer_id)
        row = events._metadata(conn.execute("SELECT " + events._COLUMNS + " FROM audit_events WHERE id=?",
            (payload["source"]["event_id"],)).fetchone())
        current = action(conn, row, events._payload(conn, row["rowid"]), now_epoch_ms, reviewer_id=reviewer_id)
        return current is not None and events._same_projection(payload, current)
    except (sqlite3.Error, ValueError, TypeError, OverflowError, KeyError, AttributeError):
        return False
