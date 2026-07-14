from __future__ import annotations

import copy
import json
import os
import queue
import ssl
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization

from serverware import db
from serverware.ca_material import ensure_mitm_ca_material
from serverware.config import (
    AUDIT_ANCHOR_INTERVAL_SECONDS,
    AUDIT_ANCHOR_CA_BUNDLE,
    AUDIT_ANCHOR_TIMEOUT_SECONDS,
    AUDIT_ANCHOR_TOKEN,
    AUDIT_ANCHOR_URL,
    AUDIT_QUEUE_MAX,
    DATA_PLANE_AUDIT_TOKEN,
    DATA_PLANE_GID,
    DATA_PLANE_UID,
    DATA_DIR,
    DECISION_GATE_CA_CERT_PATH,
    DECISION_GATE_CA_KEY_PATH,
    DECISION_GATE_BASE,
    DECISION_GATE_TIMEOUT_SECONDS,
    SECRET_LEASE_TTL_SECONDS,
)
from serverware.http_client import HttpClientError, request_bytes
from serverware.key_release import KeyReleaseError, ensure_material_released


@dataclass(frozen=True)
class LogEvent:
    route_id: str | None
    method: str
    url: str
    action: str
    status_code: int | None
    reason: str | None
    event: dict[str, Any] | None = None


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
_gmail_cache: dict[tuple[str, str, str, int, str, str, int, str], float] = {}
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
    ok = bool(body.get("ok"))
    _inc("decision_gate_grant_publish_success" if ok else "decision_gate_grant_publish_failure")
    return {"enabled": True, "ok": ok, "response": body, "payload": payload}


def flush_audit_queue(timeout_seconds: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if _log_queue.unfinished_tasks == 0:
            return True
        time.sleep(0.01)
    return _log_queue.unfinished_tasks == 0


def invalidate_secret_leases(credential_id: str | None = None) -> None:
    with _credential_lock:
        if credential_id:
            for key in [key for key in _credential_cache if key[0] == credential_id]:
                _credential_cache.pop(key, None)
        else:
            _credential_cache.clear()


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
    credential_version = int(credential.get("credential_version") or 0)
    with _credential_lock:
        for key in [key for key in _credential_cache if key[0] == credential_id]:
            _credential_cache.pop(key, None)
        _credential_cache[(credential_id, credential_version)] = (
            now + SECRET_LEASE_TTL_SECONDS,
            copy.deepcopy(credential),
        )
    return copy.deepcopy(credential)


def _gmail_key(context: dict[str, Any], message_id: str) -> tuple[str, str, str, int, str, str, int, str]:
    return (
        str(context.get("route_id") or ""),
        str(context.get("principal_id") or ""),
        str(context.get("credential_id") or ""),
        int(context.get("credential_version") or 0),
        str(context.get("policy_hash") or ""),
        str(context.get("gmail_user") or ""),
        int(context.get("cutoff_epoch_ms") or 0),
        message_id,
    )


def cache_gmail_message_ids(context: dict[str, Any], message_ids: list[str], ttl_seconds: int) -> None:
    if not message_ids:
        return
    expires = time.monotonic() + ttl_seconds
    with _gmail_lock:
        for message_id in message_ids:
            _gmail_cache[_gmail_key(context, message_id)] = expires


def gmail_message_allowed(context: dict[str, Any], message_id: str) -> bool:
    now = time.monotonic()
    key = _gmail_key(context, message_id)
    with _gmail_lock:
        expires = _gmail_cache.get(key)
        if expires and expires > now:
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
        expired_messages = [key for key, expires in _gmail_cache.items() if expires <= now]
        for key in expired_messages:
            _gmail_cache.pop(key, None)
