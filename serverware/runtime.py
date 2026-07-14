from __future__ import annotations

import copy
import json
import os
import queue
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
    AUDIT_ANCHOR_TOKEN,
    AUDIT_ANCHOR_URL,
    AUDIT_QUEUE_MAX,
    CREDENTIAL_GENERATION_POLL_SECONDS,
    CREDENTIAL_GENERATIONS_PATH,
    CREDENTIAL_LEASES_PATH,
    DATA_PLANE_AUDIT_TOKEN,
    DATA_PLANE_GID,
    DATA_PLANE_UID,
    DECISION_GATE_CA_CERT_PATH,
    DECISION_GATE_CA_KEY_PATH,
    DECISION_GATE_BASE,
    DECISION_GATE_TIMEOUT_SECONDS,
    SECRET_LEASE_TTL_SECONDS,
    ensure_data_dirs,
)
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
_generation_lock = threading.Lock()
_generation_mtime: float | None = None
_credential_generations: dict[str, int | None] = {}
_UNPUBLISHED = object()
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
    "credential_generation_updates": 0,
    "credential_generation_stale_evictions": 0,
    "credential_generation_deletes": 0,
    "gmail_cache_hits": 0,
    "gmail_cache_misses": 0,
    "decision_gate_grant_publish_success": 0,
    "decision_gate_grant_publish_failure": 0,
    "decision_gate_ca_key_release_success": 0,
    "decision_gate_ca_key_release_failure": 0,
    "credential_lease_publish_updates": 0,
    "credential_lease_publish_deletes": 0,
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
    data["credential_lease_count"] = len(_credential_cache)
    with _generation_lock:
        data["credential_generation_count"] = len(_credential_generations)
    data["gmail_cache_entry_count"] = len(_gmail_cache)
    return data


def start_runtime_workers() -> None:
    global _worker_started
    with _worker_lock:
        if _worker_started:
            return
        thread = threading.Thread(target=_audit_worker, name="serverware-audit-spool", daemon=True)
        thread.start()
        generation_thread = threading.Thread(
            target=_generation_worker,
            name="serverware-credential-generation-watch",
            daemon=True,
        )
        generation_thread.start()
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
    if not (CREDENTIAL_GENERATIONS_PATH.exists() or db.list_credentials()):
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


def _generation_worker() -> None:
    while True:
        try:
            refresh_credential_generations()
        except Exception:
            pass
        time.sleep(CREDENTIAL_GENERATION_POLL_SECONDS)


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
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read())


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
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
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
        with urllib.request.urlopen(request, timeout=DECISION_GATE_TIMEOUT_SECONDS) as response:
            body = json.loads(response.read())
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
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


def _generation_payload() -> dict[str, Any]:
    if not CREDENTIAL_GENERATIONS_PATH.exists():
        return {"version": 1, "credentials": {}}
    try:
        loaded = json.loads(CREDENTIAL_GENERATIONS_PATH.read_text())
    except Exception:
        return {"version": 1, "credentials": {}}
    if not isinstance(loaded, dict):
        return {"version": 1, "credentials": {}}
    loaded.setdefault("version", 1)
    loaded.setdefault("credentials", {})
    if not isinstance(loaded["credentials"], dict):
        loaded["credentials"] = {}
    return loaded


def _generation_map_from_payload(payload: dict[str, Any]) -> dict[str, int | None]:
    result: dict[str, int | None] = {}
    for credential_id, entry in (payload.get("credentials") or {}).items():
        if not isinstance(entry, dict):
            continue
        if entry.get("deleted"):
            result[str(credential_id)] = None
            continue
        try:
            result[str(credential_id)] = int(entry["credential_version"])
        except (KeyError, TypeError, ValueError):
            continue
    return result


def _apply_generation_map(generations: dict[str, int | None]) -> None:
    stale_keys: list[tuple[str, int]] = []
    with _generation_lock:
        _credential_generations.clear()
        _credential_generations.update(generations)
    with _credential_lock:
        for key in _credential_cache:
            credential_id, credential_version = key
            published_version = generations.get(credential_id)
            if published_version is None and credential_id in generations:
                stale_keys.append(key)
            elif published_version is not None and credential_version != published_version:
                stale_keys.append(key)
        for key in stale_keys:
            _credential_cache.pop(key, None)
    if stale_keys:
        _inc("credential_generation_stale_evictions", len(stale_keys))


def refresh_credential_generations(force: bool = False) -> None:
    global _generation_mtime
    try:
        mtime = CREDENTIAL_GENERATIONS_PATH.stat().st_mtime
    except FileNotFoundError:
        return
    if not force and _generation_mtime == mtime:
        return
    payload = _generation_payload()
    _apply_generation_map(_generation_map_from_payload(payload))
    _generation_mtime = mtime


def publish_credential_generation(
    credential_id: str,
    credential_version: int | None = None,
    *,
    deleted: bool = False,
) -> None:
    ensure_data_dirs()
    payload = _generation_payload()
    credentials = payload.setdefault("credentials", {})
    if deleted:
        credentials[credential_id] = {
            "deleted": True,
            "credential_version": credential_version,
            "updated_at": db.iso_now(),
        }
        _inc("credential_generation_deletes")
    else:
        if credential_version is None:
            raise ValueError("credential_version is required unless deleted=True")
        credentials[credential_id] = {
            "deleted": False,
            "credential_version": int(credential_version),
            "updated_at": db.iso_now(),
        }
        _inc("credential_generation_updates")
    payload["updated_at"] = db.iso_now()
    tmp_path = CREDENTIAL_GENERATIONS_PATH.with_suffix(".json.tmp")
    tmp_path.write_text(json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n")
    os.replace(tmp_path, CREDENTIAL_GENERATIONS_PATH)
    refresh_credential_generations(force=True)


def _lease_payload() -> dict[str, Any]:
    if not CREDENTIAL_LEASES_PATH.exists():
        return {"version": 1, "credentials": {}}
    try:
        loaded = json.loads(CREDENTIAL_LEASES_PATH.read_text())
    except Exception:
        return {"version": 1, "credentials": {}}
    if not isinstance(loaded, dict):
        return {"version": 1, "credentials": {}}
    loaded.setdefault("version", 1)
    loaded.setdefault("credentials", {})
    if not isinstance(loaded["credentials"], dict):
        loaded["credentials"] = {}
    return loaded


def _replace_data_plane_file(path, tmp_path) -> None:
    os.replace(tmp_path, path)
    try:
        os.chown(path, DATA_PLANE_UID, DATA_PLANE_GID)
    except (AttributeError, PermissionError, OSError):
        pass
    try:
        os.chmod(path, 0o640)
    except OSError:
        pass


def publish_credential_lease(
    credential_id: str,
    credential_version: int | None = None,
    secret: str | None = None,
    metadata: dict[str, Any] | None = None,
    *,
    deleted: bool = False,
) -> None:
    ensure_data_dirs()
    payload = _lease_payload()
    credentials = payload.setdefault("credentials", {})
    if deleted:
        credentials[credential_id] = {
            "deleted": True,
            "credential_version": credential_version,
            "updated_at": db.iso_now(),
        }
        _inc("credential_lease_publish_deletes")
    else:
        if credential_version is None or secret is None:
            raise ValueError("credential_version and secret are required unless deleted=True")
        credentials[credential_id] = {
            "deleted": False,
            "credential_version": int(credential_version),
            "secret": secret,
            "metadata": metadata or {},
            "updated_at": db.iso_now(),
        }
        _inc("credential_lease_publish_updates")
    payload["updated_at"] = db.iso_now()
    tmp_path = CREDENTIAL_LEASES_PATH.with_suffix(".json.tmp")
    tmp_path.write_text(json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n")
    _replace_data_plane_file(CREDENTIAL_LEASES_PATH, tmp_path)


def publish_credential_lease_from_db(credential_id: str) -> None:
    credential = db.get_credential(credential_id, include_secret=True)
    if not credential:
        publish_credential_lease(credential_id, deleted=True)
        return
    publish_credential_lease(
        credential_id,
        int(credential["credential_version"]),
        str(credential["secret"]),
        credential.get("metadata") or {},
    )


def _published_credential_version(credential_id: str) -> int | None | object:
    with _generation_lock:
        if credential_id not in _credential_generations:
            return _UNPUBLISHED
        return _credential_generations[credential_id]


def _cached_credential(credential_id: str, published_version: int | None | object, now: float) -> dict[str, Any] | None:
    with _credential_lock:
        if published_version is None:
            return None
        if isinstance(published_version, int):
            cached = _credential_cache.get((credential_id, published_version))
            if cached and cached[0] > now:
                _inc("credential_lease_hits")
                return copy.deepcopy(cached[1])
            return None
        candidates = [
            (version, cached)
            for (cached_credential_id, version), cached in _credential_cache.items()
            if cached_credential_id == credential_id and cached[0] > now
        ]
        if not candidates:
            return None
        version, cached = max(candidates, key=lambda item: item[0])
        _inc("credential_lease_hits")
        return copy.deepcopy(cached[1])


def get_credential(credential_id: str | None) -> dict[str, Any] | None:
    if not credential_id:
        return None
    start_runtime_workers()
    refresh_credential_generations()
    now = time.monotonic()
    published_version = _published_credential_version(credential_id)
    cached = _cached_credential(credential_id, published_version, now)
    if cached:
        return cached
    if published_version is None:
        _inc("credential_lease_misses")
        return None
    _inc("credential_lease_misses")
    credential = db.get_credential(credential_id, include_secret=True)
    if not credential:
        return None
    credential_version = int(credential.get("credential_version") or 0)
    if isinstance(published_version, int) and credential_version != published_version:
        return None
    with _credential_lock:
        _credential_cache[(credential_id, credential_version)] = (
            now + SECRET_LEASE_TTL_SECONDS,
            copy.deepcopy(credential),
        )
    return credential


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
