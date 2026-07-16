from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import queue
import re
import ssl
import threading
import time
import urllib.error
import urllib.request
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization

from serverware import db
from serverware.ca_material import ensure_mitm_ca_material
from serverware.config import (
    ATOMIC_RELEASE_AUTHORIZATION_ENABLED,
    AUDIT_ANCHOR_INTERVAL_SECONDS,
    AUDIT_ANCHOR_CA_BUNDLE,
    AUDIT_ANCHOR_TIMEOUT_SECONDS,
    AUDIT_ANCHOR_TOKEN,
    AUDIT_ANCHOR_URL,
    AUDIT_QUEUE_MAX,
    DATA_PLANE_AUDIT_TOKEN,
    DATA_PLANE_GID,
    DATA_PLANE_INSTANCE_ID,
    DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN,
    DATA_PLANE_UID,
    DATA_DIR,
    DECISION_GATE_CA_CERT_PATH,
    DECISION_GATE_CA_KEY_PATH,
    DECISION_GATE_BASE,
    DECISION_GATE_TIMEOUT_SECONDS,
    RELEASE_AUTHORIZATION_DISPATCH_TTL_SECONDS,
    RELEASE_AUTHORIZATION_RESERVATION_TTL_SECONDS,
    SECRET_LEASE_TTL_SECONDS,
)
from serverware.http_client import HttpClientError, http_error_body, request_bytes
from serverware.key_release import KeyReleaseError, ensure_material_released
from serverware.policy_bundle import canonical_json, strict_json_loads


@dataclass(frozen=True)
class LogEvent:
    route_id: str | None
    method: str
    url: str
    action: str
    status_code: int | None
    reason: str | None
    event: dict[str, Any] | None = None


@dataclass(frozen=True)
class CredentialLeaseBinding:
    credential_id: str
    credential_version: int
    secret_fingerprint: str
    expires_at_monotonic: float


@dataclass(frozen=True)
class BoundCredentialLease:
    credential: dict[str, Any]
    binding: CredentialLeaseBinding


@dataclass(frozen=True)
class _GmailProofExpiry:
    expires_at_monotonic: float
    expires_at_epoch_ms: int


class ReleaseAuthorizationClientError(RuntimeError):
    pass


_RELEASE_AUTHORIZATION_CANONICAL_REQUEST_MAX_BYTES = 64 * 1024
_RELEASE_AUTHORIZATION_ID_MAX_BYTES = 256
_RELEASE_AUTHORIZATION_RETRY_MAX_SECONDS = 31_536_000
_DEVELOPMENT_RELEASE_CHANNELS = {"dev", "development", "local", "test"}
_SHA256_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_UINT64_MAX = (1 << 64) - 1
_GMAIL_DIRECT_READ_PROOF_CACHE_MAX_ENTRIES = 4096
_RELEASE_AUTHORIZATION_RESPONSE_FIELDS = {
    "apiVersion",
    "ok",
    "authorized",
    "state",
    "reason",
    "attemptId",
    "bindingDigest",
    "idempotentReplay",
    "grantId",
    "approvalRequestId",
    "approvalStatus",
    "approvalExpiresAt",
    "approvalCreated",
    "reservationExpiresAtEpochMs",
    "dispatchStartedAtEpochMs",
    "dispatchExpiresAtEpochMs",
    "completionOutcome",
    "retryAfterSeconds",
    "quotas",
    "store",
}
_RELEASE_AUTHORIZATION_REQUIRED_RESPONSE_FIELDS = {
    "apiVersion",
    "ok",
    "authorized",
    "state",
    "reason",
    "attemptId",
    "bindingDigest",
    "idempotentReplay",
    "retryAfterSeconds",
    "quotas",
    "store",
}


_log_queue: queue.Queue[LogEvent] = queue.Queue(maxsize=AUDIT_QUEUE_MAX)
_worker_started = False
_worker_lock = threading.Lock()
_anchor_worker_started = False
_anchor_worker_lock = threading.Lock()
_decision_gate_ca_worker_started = False
_decision_gate_ca_worker_lock = threading.Lock()
_anchor_lock = threading.Lock()
_anchor_last_exported: tuple[int, str] | None = None
_anchor_last_error: str | None = None
_anchor_inflight = False
_credential_lock = threading.Lock()
_credential_cache: dict[tuple[str, int], tuple[float, dict[str, Any]]] = {}
_gmail_lock = threading.Lock()
_gmail_cache: OrderedDict[
    tuple[str, str, str, int, str, str, int, str], _GmailProofExpiry
] = OrderedDict()
_metrics_lock = threading.Lock()
_metrics: dict[str, int] = {
    "audit_events_enqueued": 0,
    "audit_events_written": 0,
    "audit_queue_full_sync_writes": 0,
    "audit_anchor_exports": 0,
    "audit_anchor_failures": 0,
    "audit_anchor_skips": 0,
    "credential_lease_hits": 0,
    "credential_lease_misses": 0,
    "gmail_cache_hits": 0,
    "gmail_cache_misses": 0,
    "decision_gate_grant_publish_success": 0,
    "decision_gate_grant_publish_failure": 0,
    "decision_gate_ca_key_release_success": 0,
    "decision_gate_ca_key_release_failure": 0,
    "legacy_credential_artifacts_removed": 0,
}


def _inc(name: str, value: int = 1) -> None:
    with _metrics_lock:
        _metrics[name] = _metrics.get(name, 0) + value


def metrics() -> dict[str, int]:
    with _metrics_lock:
        data = dict(_metrics)
    data["audit_queue_depth"] = _log_queue.qsize()
    with _anchor_lock:
        data["audit_anchor_inflight"] = 1 if _anchor_inflight else 0
    with _credential_lock:
        data["credential_lease_count"] = len(_credential_cache)
    with _gmail_lock:
        data["gmail_cache_entry_count"] = len(_gmail_cache)
    return data


def _cleanup_legacy_credential_artifacts() -> int:
    removed = 0
    for name in (
        "credential-generations.json",
        "credential-generations.json.tmp",
        "credential-leases.json",
        "credential-leases.json.tmp",
    ):
        try:
            (DATA_DIR / name).unlink()
        except FileNotFoundError:
            continue
        removed += 1
    _inc("legacy_credential_artifacts_removed", removed)
    return removed


def start_runtime_workers() -> None:
    global _worker_started
    with _worker_lock:
        if _worker_started:
            return
        _cleanup_legacy_credential_artifacts()
        thread = threading.Thread(target=_audit_worker, name="serverware-audit-spool", daemon=True)
        thread.start()
        _worker_started = True


def start_audit_anchor_worker() -> None:
    global _anchor_worker_started
    if not AUDIT_ANCHOR_URL:
        return
    with _anchor_worker_lock:
        if _anchor_worker_started:
            return
        anchor_thread = threading.Thread(
            target=_audit_anchor_worker,
            name="serverware-audit-anchor",
            daemon=True,
        )
        anchor_thread.start()
        _anchor_worker_started = True


def start_decision_gate_ca_publisher() -> None:
    global _decision_gate_ca_worker_started
    with _decision_gate_ca_worker_lock:
        if _decision_gate_ca_worker_started:
            return
        thread = threading.Thread(
            target=_decision_gate_ca_publisher_worker,
            name="serverware-decision-gate-ca-publisher",
            daemon=True,
        )
        thread.start()
        _decision_gate_ca_worker_started = True


def _write_owned(path: Path, data: bytes, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_bytes(data)
    try:
        os.chown(tmp, DATA_PLANE_UID, DATA_PLANE_GID)
    except (AttributeError, PermissionError, OSError):
        pass
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _publish_decision_gate_ca_after_key_release() -> bool:
    ca_key_path, ca_cert_path = ensure_mitm_ca_material()
    if not ca_key_path.exists() or not ca_cert_path.exists():
        return False
    if not db.list_credentials():
        return False
    release = ensure_material_released("decision-gate-ca")
    if not release.get("ok"):
        raise KeyReleaseError(f"decision-gate-ca key release failed: {release}")
    private_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
    pkcs8_key = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    _write_owned(DECISION_GATE_CA_CERT_PATH, ca_cert_path.read_bytes(), mode=0o444)
    _write_owned(DECISION_GATE_CA_KEY_PATH, pkcs8_key, mode=0o400)
    _inc("decision_gate_ca_key_release_success")
    return True


def _decision_gate_ca_publisher_worker() -> None:
    published = False
    while True:
        try:
            if not published:
                published = _publish_decision_gate_ca_after_key_release()
        except Exception:
            _inc("decision_gate_ca_key_release_failure")
        time.sleep(0.25 if not published else 2.0)


def _audit_worker() -> None:
    while True:
        event = _log_queue.get()
        try:
            db.log_request(
                event.route_id,
                event.method,
                event.url,
                event.action,
                event.status_code,
                event.reason,
                event.event,
            )
            _inc("audit_events_written")
        finally:
            _log_queue.task_done()


def _audit_anchor_worker() -> None:
    while True:
        try:
            export_audit_anchor_once()
        except Exception:
            pass
        time.sleep(max(0.25, AUDIT_ANCHOR_INTERVAL_SECONDS))


def audit_anchor_status() -> dict[str, Any]:
    with _anchor_lock:
        last = _anchor_last_exported
        last_error = _anchor_last_error
        inflight = _anchor_inflight
    return {
        "enabled": bool(AUDIT_ANCHOR_URL),
        "url": AUDIT_ANCHOR_URL or None,
        "last_exported": None if last is None else {"count": last[0], "head": last[1]},
        "last_error": last_error,
        "inflight": inflight,
        "metrics": metrics(),
    }


def _post_anchor(record: dict[str, Any]) -> dict[str, Any]:
    if not AUDIT_ANCHOR_URL:
        return {"enabled": False, "exported": False, "reason": "audit anchor URL is not configured"}
    body = json.dumps({"records": [record]}, separators=(",", ":"), sort_keys=True).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if AUDIT_ANCHOR_TOKEN:
        headers["X-Serverware-Audit-Anchor-Token"] = AUDIT_ANCHOR_TOKEN
    request = urllib.request.Request(AUDIT_ANCHOR_URL, data=body, headers=headers, method="POST")
    context = (
        ssl.create_default_context(cafile=AUDIT_ANCHOR_CA_BUNDLE)
        if AUDIT_ANCHOR_CA_BUNDLE
        else None
    )
    response = request_bytes(
        request,
        timeout=AUDIT_ANCHOR_TIMEOUT_SECONDS,
        max_bytes=1024 * 1024,
        context=context,
    )
    return json.loads(response.body)


def export_audit_anchor_once(*, force: bool = False) -> dict[str, Any]:
    global _anchor_last_error, _anchor_last_exported, _anchor_inflight
    if not AUDIT_ANCHOR_URL:
        return {"enabled": False, "exported": False, "reason": "audit anchor URL is not configured"}
    verification = db.verify_audit_chain()
    if not verification.get("ok") or not verification.get("complete"):
        _inc("audit_anchor_failures")
        with _anchor_lock:
            _anchor_last_error = f"local audit chain is not complete/valid: {verification}"
        return {"enabled": True, "exported": False, "verification": verification}
    head = verification.get("head")
    count = int(verification.get("count") or 0)
    if not isinstance(head, str) or not head.startswith("sha256:") or count <= 0:
        _inc("audit_anchor_skips")
        return {"enabled": True, "exported": False, "verification": verification, "reason": "empty chain"}
    with _anchor_lock:
        if not force and _anchor_last_exported == (count, head):
            _inc("audit_anchor_skips")
            return {"enabled": True, "exported": False, "verification": verification, "reason": "unchanged"}
        _anchor_inflight = True
    record = {
        "version": 1,
        "source": "serverware-control-plane",
        "created_at": db.iso_now(),
        "audit_count": count,
        "audit_head": head,
        "complete": True,
    }
    try:
        response = _post_anchor(record)
    except (HttpClientError, urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        _inc("audit_anchor_failures")
        with _anchor_lock:
            _anchor_last_error = str(exc)
            _anchor_inflight = False
        return {"enabled": True, "exported": False, "error": str(exc), "verification": verification}
    with _anchor_lock:
        _anchor_last_exported = (count, head)
        _anchor_last_error = None
        _anchor_inflight = False
    _inc("audit_anchor_exports")
    return {"enabled": True, "exported": True, "verification": verification, "anchor_response": response}


def flush_audit_anchor(timeout_seconds: float = 10.0) -> dict[str, Any]:
    flush_audit_queue(timeout_seconds=min(timeout_seconds, 5.0))
    deadline = time.monotonic() + timeout_seconds
    result = export_audit_anchor_once(force=True)
    while result.get("enabled") and not result.get("exported") and time.monotonic() < deadline:
        time.sleep(0.25)
        result = export_audit_anchor_once(force=True)
    return result


def log_request(
    route_id: str | None,
    method: str,
    url: str,
    action: str,
    status_code: int | None = None,
    reason: str | None = None,
    event: dict[str, Any] | None = None,
) -> None:
    start_runtime_workers()
    event = LogEvent(route_id, method, url, action, status_code, reason, event)
    try:
        _log_queue.put_nowait(event)
        _inc("audit_events_enqueued")
    except queue.Full:
        # Prototype fallback: preserve audit evidence if the bounded spool fills.
        # High-risk production routes should fail closed instead.
        _inc("audit_queue_full_sync_writes")
        db.log_request(route_id, method, url, action, status_code, reason, event.event)


def publish_decision_gate_grant(approval: dict[str, Any]) -> dict[str, Any]:
    if not DECISION_GATE_BASE:
        return {"enabled": False, "ok": False, "error": "decision gate base is not configured"}
    required = [
        "id",
        "principal_id",
        "route_id",
        "credential_id",
        "credential_version",
        "policy_hash",
        "request_digest",
        "operation_digest",
    ]
    missing = [field for field in required if approval.get(field) in (None, "")]
    if missing:
        _inc("decision_gate_grant_publish_failure")
        return {"enabled": True, "ok": False, "error": "approval is missing grant fields", "missing": missing}

    payload = {
        "grantId": f"approval:{approval['id']}",
        "approvalId": approval["id"],
        "principalId": approval["principal_id"],
        "routeId": approval["route_id"],
        "credentialRef": approval["credential_id"],
        "credentialVersion": int(approval["credential_version"]),
        "policyHash": approval["policy_hash"],
        "requestDigest": approval["request_digest"],
        "operationDigest": approval["operation_digest"],
        "maxUses": int(approval.get("grant_max_uses") or 1),
        "ttlSeconds": int(approval.get("grant_ttl_seconds") or 30),
    }
    request = urllib.request.Request(
        f"{DECISION_GATE_BASE}/v1/grants",
        data=json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Serverware-Data-Plane-Token": DATA_PLANE_AUDIT_TOKEN,
        },
        method="POST",
    )
    try:
        response = request_bytes(
            request,
            timeout=DECISION_GATE_TIMEOUT_SECONDS,
            max_bytes=256 * 1024,
        )
        body = json.loads(response.body)
    except (HttpClientError, urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        _inc("decision_gate_grant_publish_failure")
        return {"enabled": True, "ok": False, "error": str(exc), "payload": payload}
    expected_ack = {
        "grant_id": payload["grantId"],
        "approval_id": payload["approvalId"],
        "policy_hash": payload["policyHash"],
    }
    mismatched = [
        field for field, expected in expected_ack.items() if body.get(field) != expected
    ]
    ok = bool(body.get("ok")) and not mismatched
    error = str(body.get("error") or "")[:500] or None
    if body.get("ok") and mismatched:
        error = "decision gate grant acknowledgement binding mismatch: " + ", ".join(
            mismatched
        )
    _inc("decision_gate_grant_publish_success" if ok else "decision_gate_grant_publish_failure")
    return {
        "enabled": True,
        "ok": ok,
        "error": error,
        "response": body,
        "payload": payload,
    }


def flush_audit_queue(timeout_seconds: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if _log_queue.unfinished_tasks == 0:
            return True
        time.sleep(0.01)
    return _log_queue.unfinished_tasks == 0


def atomic_release_authorization_enabled() -> bool:
    configured = os.getenv("SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED")
    if configured is None:
        return ATOMIC_RELEASE_AUTHORIZATION_ENABLED
    return configured == "1"


def get_credential_version(credential_id: str | None) -> int | None:
    if not credential_id:
        return 0
    credential = db.get_credential(credential_id)
    if not credential:
        return None
    version = credential.get("credential_version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        return None
    return version


def _explicit_development_release_channel() -> bool:
    configured = os.getenv("SERVERWARE_RELEASE_CHANNEL")
    return (
        configured is not None
        and configured.strip().lower() in _DEVELOPMENT_RELEASE_CHANNELS
    )


def _release_authorization_base_url() -> str:
    value = os.getenv(
        "SERVERWARE_CONTROL_PLANE_RELEASE_AUTHORIZATION_BASE_URL", ""
    ).strip()
    if not value:
        return ""
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ReleaseAuthorizationClientError(
            "release authorization base URL is invalid"
        ) from exc
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or port is None and parsed.netloc.endswith(":")
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != "/api/data-plane/release-authorizations"
    ):
        raise ReleaseAuthorizationClientError(
            "release authorization base URL must use HTTP(S) and the exact API path "
            "without embedded credentials, query, or fragment"
        )
    if not _explicit_development_release_channel() and parsed.scheme.lower() != "https":
        raise ReleaseAuthorizationClientError(
            "production release authorization base URL must use HTTPS"
        )
    return value


def _release_authorization_token() -> str:
    return os.getenv(
        "SERVERWARE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN",
        DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN,
    ).strip()


def _release_authorization_ssl_context(base_url: str) -> ssl.SSLContext | None:
    if not base_url.lower().startswith("https://"):
        return None
    ca_bundle = os.getenv("SERVERWARE_CONTROL_PLANE_CA_BUNDLE", "").strip()
    return ssl.create_default_context(cafile=ca_bundle or None)


def _release_u64(value: Any, *, field: str, optional: bool = True) -> int | None:
    if value is None and optional:
        return None
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= _UINT64_MAX
    ):
        raise ReleaseAuthorizationClientError(
            f"release authorization response {field} is invalid"
        )
    return value


def _valid_release_authorization_identity(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value == value.strip()
        and len(value.encode("utf-8")) <= _RELEASE_AUTHORIZATION_ID_MAX_BYTES
        and all(character.isprintable() for character in value)
    )


def _release_calendar_window_bounds(
    window_kind: str, window_start_epoch_ms: int
) -> tuple[int, int]:
    start = datetime.fromtimestamp(window_start_epoch_ms / 1000, timezone.utc)
    midnight = start.replace(hour=0, minute=0, second=0, microsecond=0)
    if window_kind == "utcDay":
        expected_start = midnight
        expected_end = expected_start + timedelta(days=1)
    elif window_kind == "utcIsoWeek":
        expected_start = midnight - timedelta(days=midnight.weekday())
        expected_end = expected_start + timedelta(days=7)
    elif window_kind == "utcMonth":
        expected_start = midnight.replace(day=1)
        expected_end = (
            expected_start.replace(year=expected_start.year + 1, month=1)
            if expected_start.month == 12
            else expected_start.replace(month=expected_start.month + 1)
        )
    else:
        raise ReleaseAuthorizationClientError(
            "release authorization quota calendar window is invalid"
        )
    return (
        int(expected_start.timestamp() * 1000),
        int(expected_end.timestamp() * 1000),
    )


def _normalized_release_authorization_quota(
    item: Any, *, camel_case: bool
) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ReleaseAuthorizationClientError(
            "release authorization response quota must be an object"
        )
    if camel_case:
        allowed = {
            "counterKey",
            "constraintId",
            "operation",
            "windowKind",
            "windowSeconds",
            "calendarWindow",
            "windowStartEpochMs",
            "windowEndEpochMs",
            "max",
            "count",
            "remaining",
            "reservationState",
        }
        value = {
            "counter_key": item.get("counterKey"),
            "constraint_id": item.get("constraintId"),
            "operation": item.get("operation"),
            "window_kind": item.get("windowKind"),
            "window_seconds": item.get("windowSeconds"),
            "calendar_window": item.get("calendarWindow"),
            "window_start_epoch_ms": item.get("windowStartEpochMs"),
            "window_end_epoch_ms": item.get("windowEndEpochMs"),
            "max": item.get("max"),
            "count": item.get("count"),
            "remaining": item.get("remaining"),
            "reservation_state": item.get("reservationState"),
        }
    else:
        allowed = {
            "counter_key",
            "constraint_id",
            "operation",
            "window_kind",
            "window_seconds",
            "calendar_window",
            "window_span_seconds",
            "window_start_epoch_ms",
            "window_end_epoch_ms",
            "max",
            "count",
            "remaining",
            "reservation_state",
        }
        value = dict(item)
    if set(item) - allowed:
        raise ReleaseAuthorizationClientError(
            "release authorization response quota fields are invalid"
        )
    counter_key = value.get("counter_key")
    constraint_id = value.get("constraint_id")
    operation = value.get("operation")
    if (
        not isinstance(counter_key, str)
        or _SHA256_DIGEST_RE.fullmatch(counter_key) is None
        or not _valid_release_authorization_identity(constraint_id)
        or (
            operation is not None
            and not _valid_release_authorization_identity(operation)
        )
    ):
        raise ReleaseAuthorizationClientError(
            "release authorization response quota identity is invalid"
        )
    window_kind = value.get("window_kind")
    window_seconds = value.get("window_seconds")
    calendar_window = value.get("calendar_window")
    if window_kind == "fixed":
        if (
            not isinstance(window_seconds, int)
            or isinstance(window_seconds, bool)
            or not 1 <= window_seconds <= 31_536_000
            or calendar_window is not None
        ):
            raise ReleaseAuthorizationClientError(
                "release authorization fixed quota descriptor is invalid"
            )
    elif window_kind in {"utcDay", "utcIsoWeek", "utcMonth"}:
        if window_seconds is not None or calendar_window != window_kind:
            raise ReleaseAuthorizationClientError(
                "release authorization calendar quota descriptor is invalid"
            )
    else:
        raise ReleaseAuthorizationClientError(
            "release authorization quota window kind is invalid"
        )
    window_start = _release_u64(
        value.get("window_start_epoch_ms"), field="quota window start", optional=False
    )
    window_end = _release_u64(
        value.get("window_end_epoch_ms"), field="quota window end", optional=False
    )
    maximum = _release_u64(value.get("max"), field="quota maximum", optional=False)
    count = _release_u64(value.get("count"), field="quota count", optional=False)
    remaining = _release_u64(
        value.get("remaining"), field="quota remaining", optional=False
    )
    if (
        window_start is None
        or window_end is None
        or window_end <= window_start
        or maximum is None
        or not 1 <= maximum <= 1_000_000_000
        or count is None
        or count > maximum
        or remaining is None
        or remaining != maximum - count
    ):
        raise ReleaseAuthorizationClientError(
            "release authorization quota bounds are invalid"
        )
    if window_kind == "fixed":
        if window_end != window_start + int(window_seconds) * 1000:
            raise ReleaseAuthorizationClientError(
                "release authorization fixed quota boundaries are invalid"
            )
    elif (window_start, window_end) != _release_calendar_window_bounds(
        str(window_kind), window_start
    ):
        raise ReleaseAuthorizationClientError(
            "release authorization calendar quota boundaries are invalid"
        )
    reservation_state = value.get("reservation_state")
    if reservation_state not in {
        "reserved",
        "committed",
        "refunded",
        "refund_skipped_window",
    }:
        raise ReleaseAuthorizationClientError(
            "release authorization quota reservation state is invalid"
        )
    return {
        "counter_key": counter_key,
        "constraint_id": constraint_id,
        "operation": operation,
        "window_kind": window_kind,
        "window_seconds": window_seconds,
        "calendar_window": calendar_window,
        "window_start_epoch_ms": window_start,
        "window_end_epoch_ms": window_end,
        "max": maximum,
        "count": count,
        "remaining": remaining,
        "reservation_state": reservation_state,
    }


def _normalized_expected_release_authorization_quotas(
    shared_quotas: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not isinstance(shared_quotas, list):
        raise ReleaseAuthorizationClientError(
            "release authorization expected quotas must be an array"
        )
    normalized: dict[str, dict[str, Any]] = {}
    allowed = {
        "counter_key",
        "constraint_id",
        "operation",
        "window_kind",
        "window_seconds",
        "max_count",
    }
    for item in shared_quotas:
        if not isinstance(item, dict) or set(item) - allowed:
            raise ReleaseAuthorizationClientError(
                "release authorization expected quota fields are invalid"
            )
        counter_key = item.get("counter_key")
        constraint_id = item.get("constraint_id")
        operation = item.get("operation")
        window_kind = item.get("window_kind")
        window_seconds = item.get("window_seconds")
        maximum = item.get("max_count")
        if (
            not isinstance(counter_key, str)
            or _SHA256_DIGEST_RE.fullmatch(counter_key) is None
            or not _valid_release_authorization_identity(constraint_id)
            or (
                operation is not None
                and not _valid_release_authorization_identity(operation)
            )
            or not isinstance(maximum, int)
            or isinstance(maximum, bool)
            or not 1 <= maximum <= 1_000_000_000
        ):
            raise ReleaseAuthorizationClientError(
                "release authorization expected quota claim is invalid"
            )
        if window_kind == "fixed":
            if (
                not isinstance(window_seconds, int)
                or isinstance(window_seconds, bool)
                or not 1 <= window_seconds <= 31_536_000
            ):
                raise ReleaseAuthorizationClientError(
                    "release authorization expected fixed quota is invalid"
                )
        elif window_kind in {"utcDay", "utcIsoWeek", "utcMonth"}:
            if window_seconds is not None:
                raise ReleaseAuthorizationClientError(
                    "release authorization expected calendar quota is invalid"
                )
        else:
            raise ReleaseAuthorizationClientError(
                "release authorization expected quota window kind is invalid"
            )
        claim = {
            "counter_key": counter_key,
            "constraint_id": constraint_id,
            "operation": operation,
            "window_kind": window_kind,
            "max_count": maximum,
        }
        if window_kind == "fixed":
            claim["window_seconds"] = window_seconds
        previous = normalized.get(counter_key)
        if previous is not None and previous != claim:
            raise ReleaseAuthorizationClientError(
                "duplicate expected quota key has conflicting policy claims"
            )
        normalized[counter_key] = claim
    return [normalized[key] for key in sorted(normalized)]


def release_authorization_binding_digest(
    *,
    attempt_id: str,
    flow_id: str,
    principal_id: str,
    route_id: str,
    credential_ref: str | None,
    credential_version: int,
    policy_hash: str,
    request_digest: str,
    operation_digest: str | None,
    operation_context: dict[str, Any],
    shared_quotas: list[dict[str, Any]],
    require_jit_grant: bool,
) -> str:
    binding = {
        "attempt_id": attempt_id,
        "flow_id": flow_id,
        "principal_id": principal_id,
        "route_id": route_id,
        "credential_id": credential_ref or "",
        "credential_version": credential_version,
        "policy_hash": policy_hash,
        "request_digest": request_digest,
        "operation_digest": operation_digest,
        "operation_context": operation_context,
        "require_jit_grant": bool(require_jit_grant),
        "shared_quotas": _normalized_expected_release_authorization_quotas(
            shared_quotas
        ),
    }
    encoded = canonical_json(binding).encode("utf-8")
    if len(encoded) > _RELEASE_AUTHORIZATION_CANONICAL_REQUEST_MAX_BYTES:
        raise ReleaseAuthorizationClientError(
            "release authorization binding exceeds 64 KiB"
        )
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _release_authorization_quota_binding(quota: dict[str, Any]) -> dict[str, Any]:
    binding = {
        "counter_key": quota["counter_key"],
        "constraint_id": quota["constraint_id"],
        "operation": quota["operation"],
        "window_kind": quota["window_kind"],
        "max_count": quota["max"],
    }
    if quota["window_kind"] == "fixed":
        binding["window_seconds"] = quota["window_seconds"]
    return binding


def _normalized_release_authorization_quota_snapshot(
    value: Any,
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ReleaseAuthorizationClientError(
            "release authorization prior quota snapshot is missing"
        )
    quotas = [
        _normalized_release_authorization_quota(item, camel_case=False)
        for item in value
    ]
    counter_keys = [item["counter_key"] for item in quotas]
    if counter_keys != sorted(set(counter_keys)):
        raise ReleaseAuthorizationClientError(
            "release authorization prior quotas are not canonical"
        )
    return quotas


def _validate_release_authorization_quotas(
    response: dict[str, Any],
    *,
    expected_quotas: list[dict[str, Any]],
    previous_quotas: list[dict[str, Any]] | None,
    expected_reservation_state: str,
    temporal_anchor_epoch_ms: int | None,
    reservation_expires_at_epoch_ms: int,
) -> None:
    quotas = response.get("quotas")
    if not isinstance(quotas, list) or len(quotas) != len(expected_quotas):
        raise ReleaseAuthorizationClientError(
            "release authorization response quota set is incomplete"
        )
    if [_release_authorization_quota_binding(item) for item in quotas] != expected_quotas:
        raise ReleaseAuthorizationClientError(
            "release authorization quota policy claim substitution"
        )
    if previous_quotas is not None:
        if len(previous_quotas) != len(quotas):
            raise ReleaseAuthorizationClientError(
                "release authorization quota lifecycle substitution"
            )
        immutable_fields = {
            "counter_key",
            "constraint_id",
            "operation",
            "window_kind",
            "window_seconds",
            "calendar_window",
            "window_start_epoch_ms",
            "window_end_epoch_ms",
            "max",
            "count",
            "remaining",
        }
        if any(
            {field: previous.get(field) for field in immutable_fields}
            != {field: current.get(field) for field in immutable_fields}
            for previous, current in zip(previous_quotas, quotas)
        ):
            raise ReleaseAuthorizationClientError(
                "release authorization quota lifecycle substitution"
            )
    for quota in quotas:
        window_start = int(quota["window_start_epoch_ms"])
        window_end = int(quota["window_end_epoch_ms"])
        if temporal_anchor_epoch_ms is not None and not (
            window_start <= temporal_anchor_epoch_ms < window_end
        ):
            raise ReleaseAuthorizationClientError(
                "release authorization quota window is not active"
            )
        if reservation_expires_at_epoch_ms > window_end:
            raise ReleaseAuthorizationClientError(
                "release authorization expiry crosses a quota boundary"
            )
        reservation_state = quota.get("reservation_state")
        if reservation_state != expected_reservation_state and not (
            expected_reservation_state == "refunded"
            and reservation_state == "refund_skipped_window"
        ):
            raise ReleaseAuthorizationClientError(
                "release authorization quota reservation state is invalid"
            )


def _normalized_release_authorization_response(
    body: Any,
    *,
    attempt_id: str,
) -> dict[str, Any]:
    if not isinstance(body, dict):
        raise ReleaseAuthorizationClientError(
            "release authorization response must be an object"
        )
    unknown_fields = set(body) - _RELEASE_AUTHORIZATION_RESPONSE_FIELDS
    missing_fields = _RELEASE_AUTHORIZATION_REQUIRED_RESPONSE_FIELDS - set(body)
    if unknown_fields or missing_fields:
        raise ReleaseAuthorizationClientError(
            "release authorization response fields are invalid"
        )
    if body.get("apiVersion") != "serverware.releaseAuthorization/v1":
        raise ReleaseAuthorizationClientError(
            "release authorization response version is invalid"
        )
    if body.get("ok") is not True or body.get("attemptId") != attempt_id:
        raise ReleaseAuthorizationClientError(
            "release authorization response binding is invalid"
        )
    authorized = body.get("authorized")
    state = body.get("state")
    reason = body.get("reason")
    if not isinstance(authorized, bool):
        raise ReleaseAuthorizationClientError(
            "release authorization response authorized flag is invalid"
        )
    if not isinstance(state, str) or not state:
        raise ReleaseAuthorizationClientError(
            "release authorization response state is invalid"
        )
    if not isinstance(reason, str) or not reason:
        raise ReleaseAuthorizationClientError(
            "release authorization response reason is invalid"
        )
    binding_digest = body.get("bindingDigest")
    if (
        not isinstance(binding_digest, str)
        or _SHA256_DIGEST_RE.fullmatch(binding_digest) is None
    ):
        raise ReleaseAuthorizationClientError(
            "release authorization response binding digest is invalid"
        )
    idempotent_replay = body.get("idempotentReplay")
    if not isinstance(idempotent_replay, bool):
        raise ReleaseAuthorizationClientError(
            "release authorization response replay flag is invalid"
        )
    retry_after_seconds = _release_u64(
        body.get("retryAfterSeconds"),
        field="retry interval",
        optional=False,
    )
    if (
        retry_after_seconds is None
        or retry_after_seconds > _RELEASE_AUTHORIZATION_RETRY_MAX_SECONDS
    ):
        raise ReleaseAuthorizationClientError(
            "release authorization response retry interval is invalid"
        )

    grant_id = body.get("grantId")
    approval_request_id = body.get("approvalRequestId")
    approval_status = body.get("approvalStatus")
    approval_expires_at = body.get("approvalExpiresAt")
    approval_created = body.get("approvalCreated")
    for identity, field in (
        (grant_id, "grant identity"),
        (approval_request_id, "approval request identity"),
    ):
        if identity is not None and not _valid_release_authorization_identity(identity):
            raise ReleaseAuthorizationClientError(
                f"release authorization response {field} is invalid"
            )
    if approval_status is not None and not isinstance(approval_status, str):
        raise ReleaseAuthorizationClientError(
            "release authorization response approval status is invalid"
        )
    if approval_expires_at is not None and not isinstance(approval_expires_at, str):
        raise ReleaseAuthorizationClientError(
            "release authorization response approval expiry is invalid"
        )
    if approval_created is not None and not isinstance(approval_created, bool):
        raise ReleaseAuthorizationClientError(
            "release authorization response approval creation flag is invalid"
        )

    reservation_expires_at_epoch_ms = _release_u64(
        body.get("reservationExpiresAtEpochMs"),
        field="reservation expiry",
    )
    dispatch_started_at_epoch_ms = _release_u64(
        body.get("dispatchStartedAtEpochMs"),
        field="dispatch start",
    )
    dispatch_expires_at_epoch_ms = _release_u64(
        body.get("dispatchExpiresAtEpochMs"),
        field="dispatch expiry",
    )
    completion_outcome = body.get("completionOutcome")
    if completion_outcome is not None and not isinstance(completion_outcome, str):
        raise ReleaseAuthorizationClientError(
            "release authorization response completion outcome is invalid"
        )

    quotas = body.get("quotas")
    store = body.get("store")
    if not isinstance(quotas, list):
        raise ReleaseAuthorizationClientError(
            "release authorization response quotas are invalid"
        )
    quotas = [
        _normalized_release_authorization_quota(item, camel_case=True)
        for item in quotas
    ]
    counter_keys = [item["counter_key"] for item in quotas]
    if counter_keys != sorted(set(counter_keys)):
        raise ReleaseAuthorizationClientError(
            "release authorization response quotas are not canonical"
        )
    if (
        not isinstance(store, dict)
        or set(store) - {"backend", "ha"}
        or not isinstance(store.get("ha"), bool)
        or (
            store.get("backend") is not None
            and not isinstance(store.get("backend"), str)
        )
    ):
        raise ReleaseAuthorizationClientError(
            "release authorization response store is invalid"
        )

    if state == "denied" and reason in {"jit_grant_unavailable", "jit_grant_expired"}:
        try:
            expires_at = datetime.fromisoformat(
                str(approval_expires_at).replace("Z", "+00:00")
            )
        except (TypeError, ValueError):
            expires_at = None
        if (
            authorized
            or not isinstance(approval_request_id, str)
            or not approval_request_id
            or approval_request_id != approval_request_id.strip()
            or any(not character.isprintable() for character in approval_request_id)
            or len(approval_request_id.encode("utf-8")) > 256
            or approval_status != "pending"
            or not isinstance(approval_created, bool)
            or not isinstance(approval_expires_at, str)
            or not approval_expires_at
            or len(approval_expires_at.encode("utf-8")) > 128
            or expires_at is None
            or expires_at.tzinfo is None
            or expires_at <= datetime.now(timezone.utc)
            or retry_after_seconds < 1
        ):
            raise ReleaseAuthorizationClientError(
                "release authorization JIT approval response is incomplete"
            )
    return {
        "authorized": authorized,
        "state": state,
        "reason": reason,
        "attempt_id": body.get("attemptId"),
        "binding_digest": binding_digest,
        "idempotent_replay": idempotent_replay,
        "grant_id": grant_id,
        "approval_request_id": approval_request_id,
        "approval_status": approval_status,
        "approval_expires_at": approval_expires_at,
        "approval_created": approval_created,
        "reservation_expires_at_epoch_ms": reservation_expires_at_epoch_ms,
        "dispatch_started_at_epoch_ms": dispatch_started_at_epoch_ms,
        "dispatch_expires_at_epoch_ms": dispatch_expires_at_epoch_ms,
        "completion_outcome": completion_outcome,
        "retry_after_seconds": retry_after_seconds,
        "quotas": quotas,
        "store": store,
    }


def _validate_release_authorization_binding(
    response: dict[str, Any],
    *,
    attempt_id: str,
    binding_digest: str | None = None,
) -> None:
    actual_binding_digest = response.get("binding_digest")
    retry_after_seconds = response.get("retry_after_seconds")
    if response.get("attempt_id") != attempt_id:
        raise ReleaseAuthorizationClientError(
            "release authorization response attempt ID mismatch"
        )
    if (
        not isinstance(actual_binding_digest, str)
        or _SHA256_DIGEST_RE.fullmatch(actual_binding_digest) is None
        or (
            binding_digest is not None
            and not hmac.compare_digest(actual_binding_digest, binding_digest)
        )
    ):
        raise ReleaseAuthorizationClientError(
            "release authorization response binding digest is invalid"
        )
    if (
        not isinstance(retry_after_seconds, int)
        or isinstance(retry_after_seconds, bool)
        or not 0 <= retry_after_seconds <= _RELEASE_AUTHORIZATION_RETRY_MAX_SECONDS
    ):
        raise ReleaseAuthorizationClientError(
            "release authorization response retry interval is invalid"
        )


def _release_authorization_grant_identities_match(
    response: dict[str, Any],
    *,
    grant_id: str | None,
    approval_request_id: str | None,
) -> bool:
    return (
        response.get("grant_id") == grant_id
        and response.get("approval_request_id") == approval_request_id
    )


def validate_reserve_release_authorization_response(
    response: dict[str, Any],
    *,
    attempt_id: str,
    require_jit_grant: bool,
    expected_binding_digest: str,
    expected_shared_quotas: list[dict[str, Any]],
    now_epoch_ms: int | None = None,
) -> dict[str, Any]:
    _validate_release_authorization_binding(
        response,
        attempt_id=attempt_id,
        binding_digest=expected_binding_digest,
    )
    expected_quotas = _normalized_expected_release_authorization_quotas(
        expected_shared_quotas
    )
    now_ms = int(time.time() * 1000) if now_epoch_ms is None else now_epoch_ms
    authorized = response.get("authorized")
    state = response.get("state")
    reason = response.get("reason")
    grant_id = response.get("grant_id")
    approval_request_id = response.get("approval_request_id")
    if authorized is True:
        reservation_expires_at = _release_u64(
            response.get("reservation_expires_at_epoch_ms"),
            field="reservation expiry",
            optional=False,
        )
        exact = (
            state == "reserved"
            and reason == "reserved"
            and response.get("completion_outcome") is None
            and reservation_expires_at is not None
            and reservation_expires_at > now_ms
            and response.get("dispatch_started_at_epoch_ms") is None
            and response.get("dispatch_expires_at_epoch_ms") is None
            and response.get("retry_after_seconds") == 0
            and response.get("approval_status") is None
            and response.get("approval_expires_at") is None
            and response.get("approval_created") is None
        )
        if require_jit_grant:
            exact = exact and _valid_release_authorization_identity(
                grant_id
            ) and _valid_release_authorization_identity(approval_request_id)
        else:
            exact = exact and grant_id is None and approval_request_id is None
    else:
        jit_denial = reason in {"jit_grant_unavailable", "jit_grant_expired"}
        exact = (
            authorized is False
            and state == "denied"
            and reason
            in {
                "jit_grant_unavailable",
                "jit_grant_expired",
                "shared_quota_denied",
                "shared_quota_window_expired",
                "release_authorization_busy",
            }
            and (require_jit_grant or not jit_denial)
            and response.get("idempotent_replay") is False
            and grant_id is None
            and response.get("completion_outcome") is None
            and response.get("reservation_expires_at_epoch_ms") is None
            and response.get("dispatch_started_at_epoch_ms") is None
            and response.get("dispatch_expires_at_epoch_ms") is None
        )
        if jit_denial:
            exact = exact and (
                _valid_release_authorization_identity(approval_request_id)
                and response.get("approval_status") == "pending"
                and isinstance(response.get("approval_created"), bool)
                and isinstance(response.get("approval_expires_at"), str)
                and 1 <= response.get("retry_after_seconds", 0) <= 3600
            )
        else:
            exact = exact and (
                approval_request_id is None
                and response.get("approval_status") is None
                and response.get("approval_expires_at") is None
                and response.get("approval_created") is None
            )
    if not exact:
        raise ReleaseAuthorizationClientError(
            f"release authorization reserve returned invalid lifecycle state {state}"
        )
    if authorized is True:
        assert reservation_expires_at is not None
        _validate_release_authorization_quotas(
            response,
            expected_quotas=expected_quotas,
            previous_quotas=None,
            expected_reservation_state="reserved",
            temporal_anchor_epoch_ms=now_ms,
            reservation_expires_at_epoch_ms=reservation_expires_at,
        )
    elif response.get("quotas"):
        raise ReleaseAuthorizationClientError(
            "denied release authorization response must not carry quota reservations"
        )
    return response


def validate_dispatch_release_authorization_response(
    response: dict[str, Any],
    *,
    attempt_id: str,
    binding_digest: str,
    grant_id: str | None,
    approval_request_id: str | None,
    previous_lifecycle: dict[str, Any],
    now_epoch_ms: int | None = None,
) -> dict[str, Any]:
    _validate_release_authorization_binding(
        response,
        attempt_id=attempt_id,
        binding_digest=binding_digest,
    )
    now_ms = int(time.time() * 1000) if now_epoch_ms is None else now_epoch_ms
    dispatch_started_at = response.get("dispatch_started_at_epoch_ms")
    dispatch_expires_at = response.get("dispatch_expires_at_epoch_ms")
    reservation_expires_at = response.get("reservation_expires_at_epoch_ms")
    previous_quotas = _normalized_release_authorization_quota_snapshot(
        previous_lifecycle.get("quotas")
    )
    if any(item["reservation_state"] != "reserved" for item in previous_quotas):
        raise ReleaseAuthorizationClientError(
            "release authorization reserve quota state is invalid"
        )
    exact = (
        response.get("authorized") is True
        and response.get("state") == "dispatching"
        and response.get("reason") == "dispatching"
        and response.get("completion_outcome") is None
        and _release_u64(
            reservation_expires_at,
            field="reservation expiry",
            optional=False,
        )
        is not None
        and reservation_expires_at
        == previous_lifecycle.get("reservation_expires_at_epoch_ms")
        and isinstance(dispatch_started_at, int)
        and not isinstance(dispatch_started_at, bool)
        and 0 <= dispatch_started_at <= _UINT64_MAX
        and isinstance(dispatch_expires_at, int)
        and not isinstance(dispatch_expires_at, bool)
        and dispatch_started_at < dispatch_expires_at <= _UINT64_MAX
        and dispatch_started_at < reservation_expires_at
        and dispatch_expires_at > now_ms
        and response.get("retry_after_seconds") == 0
        and response.get("approval_status") is None
        and response.get("approval_expires_at") is None
        and response.get("approval_created") is None
        and _release_authorization_grant_identities_match(
            response,
            grant_id=grant_id,
            approval_request_id=approval_request_id,
        )
    )
    if not exact:
        raise ReleaseAuthorizationClientError(
            "release authorization dispatch did not return exact live dispatching state"
        )
    _validate_release_authorization_quotas(
        response,
        expected_quotas=[
            _release_authorization_quota_binding(item) for item in previous_quotas
        ],
        previous_quotas=previous_quotas,
        expected_reservation_state="reserved",
        temporal_anchor_epoch_ms=dispatch_started_at,
        reservation_expires_at_epoch_ms=reservation_expires_at,
    )
    return response


def validate_complete_release_authorization_response(
    response: dict[str, Any],
    *,
    attempt_id: str,
    binding_digest: str,
    outcome: str,
    grant_id: str | None,
    approval_request_id: str | None,
    previous_lifecycle: dict[str, Any],
) -> dict[str, Any]:
    _validate_release_authorization_binding(
        response,
        attempt_id=attempt_id,
        binding_digest=binding_digest,
    )
    state = response.get("state")
    completion_outcome = response.get("completion_outcome")
    replay = response.get("idempotent_replay") is True
    reason = response.get("reason")
    if outcome == "forwarded":
        exact = (
            response.get("authorized") is True
            and state == "committed"
            and completion_outcome == "forwarded"
            and reason in ({"forwarded", "committed"} if replay else {"forwarded"})
        )
    elif outcome == "not_forwarded":
        exact = (
            response.get("authorized") is False
            and state == "cancelled"
            and completion_outcome == "not_forwarded"
            and reason == "cancelled"
        )
    elif outcome == "unknown":
        exact = (
            response.get("authorized") is True
            and state == "committed_indeterminate"
            and completion_outcome == "unknown"
            and reason
            in (
                {"committed_indeterminate"}
                if replay
                else {"forward_outcome_indeterminate", "dispatch_ttl_expired"}
            )
        ) or (
            replay
            and (
                (
                    response.get("authorized") is True
                    and state == "committed"
                    and completion_outcome == "forwarded"
                    and reason == "committed"
                )
                or (
                    response.get("authorized") is False
                    and state == "cancelled"
                    and completion_outcome == "not_forwarded"
                    and reason == "cancelled"
                )
            )
        )
    else:
        exact = False
    dispatch_started_at = response.get("dispatch_started_at_epoch_ms")
    dispatch_expires_at = response.get("dispatch_expires_at_epoch_ms")
    reservation_expires_at = response.get("reservation_expires_at_epoch_ms")
    previous_dispatch_started_at = previous_lifecycle.get(
        "dispatch_started_at_epoch_ms"
    )
    previous_dispatch_expires_at = previous_lifecycle.get(
        "dispatch_expires_at_epoch_ms"
    )
    previous_quotas = _normalized_release_authorization_quota_snapshot(
        previous_lifecycle.get("quotas")
    )
    if any(item["reservation_state"] != "reserved" for item in previous_quotas):
        raise ReleaseAuthorizationClientError(
            "release authorization prior quota state is invalid"
        )
    dispatch_timestamps_match = (
        dispatch_started_at == previous_dispatch_started_at
        and dispatch_expires_at == previous_dispatch_expires_at
    )
    if (
        outcome == "unknown"
        and previous_lifecycle.get("dispatch_attempted") is True
        and previous_dispatch_started_at is None
        and previous_dispatch_expires_at is None
    ):
        dispatch_timestamps_match = (
            dispatch_started_at is None and dispatch_expires_at is None
        ) or (
            isinstance(dispatch_started_at, int)
            and not isinstance(dispatch_started_at, bool)
            and isinstance(dispatch_expires_at, int)
            and not isinstance(dispatch_expires_at, bool)
            and 0 <= dispatch_started_at < dispatch_expires_at <= _UINT64_MAX
        )
    exact = exact and (
        _release_u64(
            response.get("reservation_expires_at_epoch_ms"),
            field="reservation expiry",
            optional=False,
        )
        is not None
        and reservation_expires_at
        == previous_lifecycle.get("reservation_expires_at_epoch_ms")
        and dispatch_timestamps_match
        and (
            (dispatch_started_at is None and dispatch_expires_at is None)
            or (
                isinstance(dispatch_started_at, int)
                and not isinstance(dispatch_started_at, bool)
                and isinstance(dispatch_expires_at, int)
                and not isinstance(dispatch_expires_at, bool)
                and 0 <= dispatch_started_at < dispatch_expires_at <= _UINT64_MAX
            )
        )
        and response.get("retry_after_seconds") == 0
        and response.get("approval_status") is None
        and response.get("approval_expires_at") is None
        and response.get("approval_created") is None
        and _release_authorization_grant_identities_match(
            response,
            grant_id=grant_id,
            approval_request_id=approval_request_id,
        )
    )
    if not exact:
        raise ReleaseAuthorizationClientError(
            "release authorization completion returned invalid state "
            f"{state} outcome {completion_outcome!r} for {outcome}"
        )
    expected_reservation_state = "refunded" if state == "cancelled" else "committed"
    _validate_release_authorization_quotas(
        response,
        expected_quotas=[
            _release_authorization_quota_binding(item) for item in previous_quotas
        ],
        previous_quotas=previous_quotas,
        expected_reservation_state=expected_reservation_state,
        temporal_anchor_epoch_ms=None,
        reservation_expires_at_epoch_ms=reservation_expires_at,
    )
    return response


def _normalized_direct_release_authorization_response(
    result: Any,
) -> dict[str, Any]:
    if not isinstance(result, dict):
        raise ReleaseAuthorizationClientError(
            "release authorization direct response must be an object"
        )
    normalized = dict(result)
    normalized.setdefault("idempotent_replay", False)
    normalized.setdefault("grant_id", None)
    normalized.setdefault("approval_request_id", None)
    normalized.setdefault("approval_status", None)
    normalized.setdefault("approval_expires_at", None)
    normalized.setdefault("approval_created", None)
    normalized.setdefault("reservation_expires_at_epoch_ms", None)
    normalized.setdefault("dispatch_started_at_epoch_ms", None)
    normalized.setdefault("dispatch_expires_at_epoch_ms", None)
    normalized.setdefault("completion_outcome", None)
    normalized.setdefault("retry_after_seconds", 0)
    normalized.setdefault("quotas", [])
    if not isinstance(normalized["quotas"], list):
        raise ReleaseAuthorizationClientError(
            "release authorization direct quotas must be an array"
        )
    normalized["quotas"] = [
        _normalized_release_authorization_quota(item, camel_case=False)
        for item in normalized["quotas"]
    ]
    normalized.setdefault(
        "store",
        {
            "backend": normalized.get("release_authorization_store_backend"),
            "ha": bool(normalized.get("release_authorization_store_ha")),
        },
    )
    return normalized


def _bounded_release_canonical_request(
    canonical_request: dict[str, Any],
    *,
    request_digest: str,
) -> dict[str, Any]:
    if not isinstance(canonical_request, dict):
        raise ReleaseAuthorizationClientError(
            "release authorization canonical request must be an object"
        )
    try:
        encoded = canonical_json(canonical_request).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ReleaseAuthorizationClientError(
            "release authorization canonical request is invalid"
        ) from exc
    if len(encoded) > _RELEASE_AUTHORIZATION_CANONICAL_REQUEST_MAX_BYTES:
        raise ReleaseAuthorizationClientError(
            "release authorization canonical request exceeds 64 KiB"
        )
    actual_digest = "sha256:" + hashlib.sha256(encoded).hexdigest()
    if not isinstance(request_digest, str) or not hmac.compare_digest(
        request_digest, actual_digest
    ):
        raise ReleaseAuthorizationClientError(
            "release authorization canonical request digest does not match"
        )
    bounded = strict_json_loads(encoded)
    if not isinstance(bounded, dict):
        raise ReleaseAuthorizationClientError(
            "release authorization canonical request must be an object"
        )
    return bounded


def _release_authorization_http_post(
    action: str,
    payload: dict[str, Any],
    *,
    require_jit_grant: bool = False,
    grant_id: str | None = None,
    approval_request_id: str | None = None,
    expected_binding_digest: str | None = None,
    expected_shared_quotas: list[dict[str, Any]] | None = None,
    previous_lifecycle: dict[str, Any] | None = None,
) -> dict[str, Any]:
    base_url = _release_authorization_base_url()
    token = _release_authorization_token()
    if not base_url or not token:
        raise ReleaseAuthorizationClientError(
            "release authorization control-plane client is not configured"
        )
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    context = _release_authorization_ssl_context(base_url)
    last_error: BaseException | None = None
    for retry in range(2):
        request = urllib.request.Request(
            f"{base_url}/{action}",
            data=encoded,
            headers={
                "Content-Type": "application/json",
                "X-Serverware-Data-Plane-Token": token,
            },
            method="POST",
        )
        try:
            response = request_bytes(
                request,
                timeout=DECISION_GATE_TIMEOUT_SECONDS,
                max_bytes=256 * 1024,
                context=context,
            )
            body = strict_json_loads(response.body)
            normalized = _normalized_release_authorization_response(
                body,
                attempt_id=str(payload["attemptId"]),
            )
            if action == "reserve":
                if expected_binding_digest is None or expected_shared_quotas is None:
                    raise ReleaseAuthorizationClientError(
                        "release authorization reserve binding is missing"
                    )
                return validate_reserve_release_authorization_response(
                    normalized,
                    attempt_id=str(payload["attemptId"]),
                    require_jit_grant=require_jit_grant,
                    expected_binding_digest=expected_binding_digest,
                    expected_shared_quotas=expected_shared_quotas,
                )
            if action == "dispatch":
                if previous_lifecycle is None:
                    raise ReleaseAuthorizationClientError(
                        "release authorization reserve lifecycle is missing"
                    )
                return validate_dispatch_release_authorization_response(
                    normalized,
                    attempt_id=str(payload["attemptId"]),
                    binding_digest=str(payload["bindingDigest"]),
                    grant_id=grant_id,
                    approval_request_id=approval_request_id,
                    previous_lifecycle=previous_lifecycle,
                )
            if action == "complete":
                if previous_lifecycle is None:
                    raise ReleaseAuthorizationClientError(
                        "release authorization prior lifecycle is missing"
                    )
                return validate_complete_release_authorization_response(
                    normalized,
                    attempt_id=str(payload["attemptId"]),
                    binding_digest=str(payload["bindingDigest"]),
                    outcome=str(payload["outcome"]),
                    grant_id=grant_id,
                    approval_request_id=approval_request_id,
                    previous_lifecycle=previous_lifecycle,
                )
            raise ReleaseAuthorizationClientError(
                f"release authorization action is invalid: {action}"
            )
        except urllib.error.HTTPError as exc:
            try:
                error_body = strict_json_loads(
                    http_error_body(exc, max_bytes=64 * 1024)
                )
                detail = error_body.get("detail") if isinstance(error_body, dict) else None
            except Exception:
                detail = None
            last_error = ReleaseAuthorizationClientError(
                str(detail or f"release authorization HTTP {exc.code}")
            )
            if exc.code != 503 or retry:
                break
        except (
            HttpClientError,
            urllib.error.URLError,
            TimeoutError,
            OSError,
            json.JSONDecodeError,
            ValueError,
        ) as exc:
            last_error = exc
            if retry:
                break
        time.sleep(0.05)
    raise ReleaseAuthorizationClientError(
        f"release authorization {action} is uncertain: {last_error}"
    ) from last_error


def _require_development_release_authorization_fallback() -> None:
    if not _explicit_development_release_channel():
        raise ReleaseAuthorizationClientError(
            "direct release authorization database fallback requires an explicit "
            "development release channel"
        )


def reserve_release_authorization(
    *,
    attempt_id: str,
    flow_id: str,
    principal_id: str,
    route_id: str,
    credential_ref: str | None,
    credential_version: int,
    policy_hash: str,
    request_digest: str,
    operation_digest: str | None,
    operation_context: dict[str, Any],
    canonical_request: dict[str, Any],
    shared_quotas: list[dict[str, Any]],
    require_jit_grant: bool,
) -> dict[str, Any]:
    if not atomic_release_authorization_enabled():
        raise ReleaseAuthorizationClientError(
            "atomic release authorization is disabled"
        )
    bounded_canonical_request = _bounded_release_canonical_request(
        canonical_request,
        request_digest=request_digest,
    )
    expected_binding_digest = release_authorization_binding_digest(
        attempt_id=attempt_id,
        flow_id=flow_id,
        principal_id=principal_id,
        route_id=route_id,
        credential_ref=credential_ref,
        credential_version=credential_version,
        policy_hash=policy_hash,
        request_digest=request_digest,
        operation_digest=operation_digest,
        operation_context=operation_context,
        shared_quotas=shared_quotas,
        require_jit_grant=require_jit_grant,
    )
    if _release_authorization_base_url():
        return _release_authorization_http_post(
            "reserve",
            {
                "apiVersion": "serverware.releaseAuthorizationReserve/v1",
                "attemptId": attempt_id,
                "flowId": flow_id,
                "principalId": principal_id,
                "routeId": route_id,
                "credentialRef": credential_ref,
                "credentialVersion": credential_version,
                "policyHash": policy_hash,
                "requestDigest": request_digest,
                "operationDigest": operation_digest,
                "operationContext": operation_context,
                "canonicalRequest": bounded_canonical_request,
            },
            require_jit_grant=require_jit_grant,
            expected_binding_digest=expected_binding_digest,
            expected_shared_quotas=shared_quotas,
        )
    _require_development_release_authorization_fallback()
    if require_jit_grant:
        raise ReleaseAuthorizationClientError(
            "JIT release authorization requires the control-plane release authority"
        )
    try:
        result = _normalized_direct_release_authorization_response(
            db.reserve_release_authorization(
                attempt_id=attempt_id,
                flow_id=flow_id,
                principal_id=principal_id,
                route_id=route_id,
                credential_id=credential_ref or "",
                credential_version=credential_version,
                policy_hash=policy_hash,
                request_digest=request_digest,
                operation_digest=operation_digest,
                operation_context=operation_context,
                shared_quotas=shared_quotas,
                require_jit_grant=require_jit_grant,
                reservation_ttl_seconds=RELEASE_AUTHORIZATION_RESERVATION_TTL_SECONDS,
                actor_id=DATA_PLANE_INSTANCE_ID or "serverware-python-mitm",
            )
        )
        return validate_reserve_release_authorization_response(
            result,
            attempt_id=attempt_id,
            require_jit_grant=require_jit_grant,
            expected_binding_digest=expected_binding_digest,
            expected_shared_quotas=shared_quotas,
        )
    except Exception as exc:
        raise ReleaseAuthorizationClientError(
            f"release authorization reserve is uncertain: {exc}"
        ) from exc


def dispatch_release_authorization(
    *,
    attempt_id: str,
    binding_digest: str,
    grant_id: str | None = None,
    approval_request_id: str | None = None,
    previous_lifecycle: dict[str, Any],
) -> dict[str, Any]:
    if _release_authorization_base_url():
        return _release_authorization_http_post(
            "dispatch",
            {
                "apiVersion": "serverware.releaseAuthorizationDispatch/v1",
                "attemptId": attempt_id,
                "bindingDigest": binding_digest,
            },
            grant_id=grant_id,
            approval_request_id=approval_request_id,
            previous_lifecycle=previous_lifecycle,
        )
    _require_development_release_authorization_fallback()
    try:
        result = _normalized_direct_release_authorization_response(
            db.dispatch_release_authorization(
                attempt_id=attempt_id,
                binding_digest=binding_digest,
                dispatch_ttl_seconds=RELEASE_AUTHORIZATION_DISPATCH_TTL_SECONDS,
                actor_id=DATA_PLANE_INSTANCE_ID or "serverware-python-mitm",
            )
        )
        return validate_dispatch_release_authorization_response(
            result,
            attempt_id=attempt_id,
            binding_digest=binding_digest,
            grant_id=grant_id,
            approval_request_id=approval_request_id,
            previous_lifecycle=previous_lifecycle,
        )
    except Exception as exc:
        raise ReleaseAuthorizationClientError(
            f"release authorization dispatch is uncertain: {exc}"
        ) from exc


def complete_release_authorization(
    *,
    attempt_id: str,
    binding_digest: str,
    outcome: str,
    grant_id: str | None = None,
    approval_request_id: str | None = None,
    previous_lifecycle: dict[str, Any],
) -> dict[str, Any]:
    if outcome not in {"forwarded", "not_forwarded", "unknown"}:
        raise ReleaseAuthorizationClientError(
            "release authorization completion outcome is invalid"
        )
    if _release_authorization_base_url():
        return _release_authorization_http_post(
            "complete",
            {
                "apiVersion": "serverware.releaseAuthorizationComplete/v1",
                "attemptId": attempt_id,
                "bindingDigest": binding_digest,
                "outcome": outcome,
            },
            grant_id=grant_id,
            approval_request_id=approval_request_id,
            previous_lifecycle=previous_lifecycle,
        )
    _require_development_release_authorization_fallback()
    try:
        result = _normalized_direct_release_authorization_response(
            db.complete_release_authorization(
                attempt_id=attempt_id,
                binding_digest=binding_digest,
                outcome=outcome,
                actor_id=DATA_PLANE_INSTANCE_ID or "serverware-python-mitm",
            )
        )
        return validate_complete_release_authorization_response(
            result,
            attempt_id=attempt_id,
            binding_digest=binding_digest,
            outcome=outcome,
            grant_id=grant_id,
            approval_request_id=approval_request_id,
            previous_lifecycle=previous_lifecycle,
        )
    except Exception as exc:
        raise ReleaseAuthorizationClientError(
            f"release authorization completion is uncertain: {exc}"
        ) from exc


def invalidate_secret_leases(credential_id: str | None = None) -> None:
    with _credential_lock:
        if credential_id:
            for key in [key for key in _credential_cache if key[0] == credential_id]:
                _credential_cache.pop(key, None)
        else:
            _credential_cache.clear()


def _project_credential_for_data_plane(credential: dict[str, Any]) -> dict[str, Any] | None:
    if credential.get("kind") != "oauth2":
        return credential

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate OAuth token field")
            result[key] = value
        return result

    try:
        token = json.loads(str(credential.get("secret") or ""), object_pairs_hook=reject_duplicate_keys)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    access_token = token.get("access_token") if isinstance(token, dict) else None
    if not isinstance(access_token, str) or not access_token or len(access_token.encode("utf-8")) > 64 * 1024:
        return None
    projected = copy.deepcopy(credential)
    projected["secret"] = json.dumps(
        {"access_token": access_token},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return projected


def get_control_plane_credential(credential_id: str | None) -> dict[str, Any] | None:
    """Load full secret material for the control-plane OAuth refresh path only."""
    if not credential_id:
        return None
    return db.get_credential(credential_id, include_secret=True)


def get_credential(credential_id: str | None) -> dict[str, Any] | None:
    if not credential_id:
        return None
    start_runtime_workers()
    current = db.get_credential(credential_id)
    if not current:
        invalidate_secret_leases(credential_id)
        _inc("credential_lease_misses")
        return None

    now = time.monotonic()
    credential_version = int(current.get("credential_version") or 0)
    cache_key = (credential_id, credential_version)
    with _credential_lock:
        stale_keys = [
            key
            for key, (expires_at, _) in _credential_cache.items()
            if key[0] == credential_id and (key != cache_key or expires_at <= now)
        ]
        for key in stale_keys:
            _credential_cache.pop(key, None)
        cached = _credential_cache.get(cache_key)
        if cached and cached[0] > now:
            _inc("credential_lease_hits")
            return copy.deepcopy(cached[1])

    _inc("credential_lease_misses")
    credential = db.get_credential(credential_id, include_secret=True)
    if not credential:
        invalidate_secret_leases(credential_id)
        return None
    credential = _project_credential_for_data_plane(credential)
    if not credential:
        invalidate_secret_leases(credential_id)
        return None
    credential_version = int(credential.get("credential_version") or 0)
    with _credential_lock:
        for key in [key for key in _credential_cache if key[0] == credential_id]:
            _credential_cache.pop(key, None)
        _credential_cache[(credential_id, credential_version)] = (
            now + SECRET_LEASE_TTL_SECONDS,
            copy.deepcopy(credential),
        )
    return copy.deepcopy(credential)


def _credential_secret_fingerprint(credential: dict[str, Any]) -> str | None:
    secret = credential.get("secret")
    if not isinstance(secret, str) or not secret:
        return None
    return "sha256:" + hashlib.sha256(secret.encode("utf-8")).hexdigest()


def get_bound_credential_lease(credential_id: str | None) -> BoundCredentialLease | None:
    credential = get_credential(credential_id)
    if not credential_id or not isinstance(credential, dict):
        return None
    credential_version = credential.get("credential_version")
    fingerprint = _credential_secret_fingerprint(credential)
    if (
        type(credential_version) is not int
        or not 1 <= credential_version <= _UINT64_MAX
        or fingerprint is None
    ):
        return None
    now = time.monotonic()
    cache_key = (credential_id, credential_version)
    with _credential_lock:
        cached = _credential_cache.get(cache_key)
        if cached is None or cached[0] <= now:
            _credential_cache.pop(cache_key, None)
            return None
        cached_fingerprint = _credential_secret_fingerprint(cached[1])
        if cached_fingerprint is None or not hmac.compare_digest(
            cached_fingerprint, fingerprint
        ):
            return None
        expires_at = cached[0]
    return BoundCredentialLease(
        credential=copy.deepcopy(credential),
        binding=CredentialLeaseBinding(
            credential_id=credential_id,
            credential_version=credential_version,
            secret_fingerprint=fingerprint,
            expires_at_monotonic=expires_at,
        ),
    )


def _gmail_cache_string(value: Any, *, label: str, max_bytes: int) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"Gmail proof {label} is invalid")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(f"Gmail proof {label} is invalid") from exc
    if len(encoded) > max_bytes or any(byte < 32 or byte == 127 for byte in encoded):
        raise ValueError(f"Gmail proof {label} is invalid")
    return value


def _gmail_key(context: dict[str, Any], message_id: str) -> tuple[str, str, str, int, str, str, int, str]:
    if not isinstance(context, dict):
        raise ValueError("Gmail proof context is invalid")
    credential_version = context.get("credential_version")
    cutoff_epoch_ms = context.get("cutoff_epoch_ms")
    policy_hash = context.get("policy_hash")
    if (
        type(credential_version) is not int
        or not 1 <= credential_version <= _UINT64_MAX
        or type(cutoff_epoch_ms) is not int
        or not 0 <= cutoff_epoch_ms <= _UINT64_MAX
        or not isinstance(policy_hash, str)
        or _SHA256_DIGEST_RE.fullmatch(policy_hash) is None
    ):
        raise ValueError("Gmail proof context is invalid")
    return (
        _gmail_cache_string(context.get("route_id"), label="route ID", max_bytes=512),
        _gmail_cache_string(context.get("principal_id"), label="principal ID", max_bytes=512),
        _gmail_cache_string(context.get("credential_id"), label="credential ID", max_bytes=512),
        credential_version,
        policy_hash,
        _gmail_cache_string(context.get("gmail_user"), label="user", max_bytes=512),
        cutoff_epoch_ms,
        _gmail_cache_string(message_id, label="message ID", max_bytes=512),
    )


def cache_gmail_message_ids(
    context: dict[str, Any],
    message_ids: list[str],
    ttl_seconds: int,
    *,
    max_age_expires_at_epoch_ms: dict[str, int],
) -> None:
    if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 86_400:
        raise ValueError("Gmail proof TTL is invalid")
    if not isinstance(message_ids, list) or not 1 <= len(message_ids) <= 32:
        raise ValueError("Gmail proof message IDs are invalid")
    keys = [_gmail_key(context, message_id) for message_id in message_ids]
    if (
        not isinstance(max_age_expires_at_epoch_ms, dict)
        or set(max_age_expires_at_epoch_ms) != set(message_ids)
        or any(
            type(expiry) is not int or not 0 <= expiry <= _UINT64_MAX
            for expiry in max_age_expires_at_epoch_ms.values()
        )
    ):
        raise ValueError("Gmail proof max-age boundaries are invalid")
    now_monotonic = time.monotonic()
    now_epoch_ms = int(time.time() * 1000)
    ttl_expires_at_epoch_ms = min(
        _UINT64_MAX,
        now_epoch_ms + ttl_seconds * 1000,
    )
    expiries = {
        message_id: min(
            ttl_expires_at_epoch_ms,
            max_age_expires_at_epoch_ms[message_id],
        )
        for message_id in set(message_ids)
    }
    with _gmail_lock:
        for key in [
            key
            for key, expiry in _gmail_cache.items()
            if expiry.expires_at_monotonic <= now_monotonic
            or expiry.expires_at_epoch_ms <= now_epoch_ms
        ]:
            _gmail_cache.pop(key, None)
        for key, message_id in zip(keys, message_ids, strict=True):
            _gmail_cache.pop(key, None)
            expires_at_epoch_ms = expiries[message_id]
            if expires_at_epoch_ms <= now_epoch_ms:
                continue
            _gmail_cache[key] = _GmailProofExpiry(
                expires_at_monotonic=now_monotonic
                + (expires_at_epoch_ms - now_epoch_ms) / 1000,
                expires_at_epoch_ms=expires_at_epoch_ms,
            )
            while len(_gmail_cache) > _GMAIL_DIRECT_READ_PROOF_CACHE_MAX_ENTRIES:
                _gmail_cache.popitem(last=False)


def gmail_message_allowed(context: dict[str, Any], message_id: str) -> bool:
    now_monotonic = time.monotonic()
    now_epoch_ms = int(time.time() * 1000)
    try:
        key = _gmail_key(context, message_id)
    except ValueError:
        _inc("gmail_cache_misses")
        return False
    with _gmail_lock:
        expires = _gmail_cache.get(key)
        if (
            expires
            and expires.expires_at_monotonic > now_monotonic
            and expires.expires_at_epoch_ms > now_epoch_ms
        ):
            _inc("gmail_cache_hits")
            return True
        if expires:
            _gmail_cache.pop(key, None)
    _inc("gmail_cache_misses")
    return False


def prune_expired_caches() -> None:
    now = time.monotonic()
    with _credential_lock:
        expired_credentials = [key for key, (expires, _) in _credential_cache.items() if expires <= now]
        for key in expired_credentials:
            _credential_cache.pop(key, None)
    with _gmail_lock:
        now_epoch_ms = int(time.time() * 1000)
        expired_messages = [
            key
            for key, expires in _gmail_cache.items()
            if expires.expires_at_monotonic <= now
            or expires.expires_at_epoch_ms <= now_epoch_ms
        ]
        for key in expired_messages:
            _gmail_cache.pop(key, None)
