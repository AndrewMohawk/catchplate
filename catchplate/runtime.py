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

from catchplate import aws_credential_boundary, db, github_app_boundary
from catchplate.ca_material import ensure_mitm_ca_material
from catchplate.config import (
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
from catchplate.http_client import (
    HttpClientError,
    http_error_body,
    request_bytes,
    request_json_bytes,
)
from catchplate.key_release import KeyReleaseError, ensure_material_released
from catchplate.policy_bundle import canonical_json, strict_json_loads


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


class DurablePolicyStateError(RuntimeError):
    pass


def _durable_policy_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_json(value).encode("utf-8")
    ).hexdigest()


def _release_authorization_actor_id() -> str:
    return DATA_PLANE_INSTANCE_ID or "catchplate-python-mitm"


def _durable_policy_reservation_id(
    *,
    expected: ReleaseAuthorizationExpectedIdentity,
    claim_digest: str,
) -> str:
    return _durable_policy_digest(
        {
            "attemptId": expected.attempt_id,
            "policyHash": expected.policy_hash,
            "requestDigest": expected.request_digest,
            "operationDigest": expected.operation_digest,
            "claimDigest": claim_digest,
        }
    )


def durable_policy_reserve_binding(
    expected: ReleaseAuthorizationExpectedIdentity,
    claims: list[dict[str, Any]] | None,
) -> dict[str, Any] | None:
    if not claims:
        return None
    bounded_claims = strict_json_loads(
        canonical_json(copy.deepcopy(claims)).encode("utf-8")
    )
    if not isinstance(bounded_claims, list) or not bounded_claims:
        raise ReleaseAuthorizationClientError(
            "durable policy claims must be a non-empty array"
        )
    claim_digest = _durable_policy_digest(bounded_claims)
    return {
        "actorId": _release_authorization_actor_id(),
        "attemptId": expected.attempt_id,
        "claimDigest": claim_digest,
        "claims": bounded_claims,
        "reservationId": _durable_policy_reservation_id(
            expected=expected,
            claim_digest=claim_digest,
        ),
    }


def _durable_policy_transition_identity(
    durable: dict[str, Any],
) -> dict[str, Any]:
    required = {
        "attempt_id",
        "claim_digest",
        "reservation_id",
        "actor_id",
    }
    if (
        not isinstance(durable, dict)
        or not required.issubset(durable)
        or _SHA256_DIGEST_RE.fullmatch(str(durable.get("attempt_id") or ""))
        is None
        or _SHA256_DIGEST_RE.fullmatch(str(durable.get("claim_digest") or ""))
        is None
        or _SHA256_DIGEST_RE.fullmatch(str(durable.get("reservation_id") or ""))
        is None
        or not _valid_release_authorization_identity(durable.get("actor_id"))
    ):
        raise ReleaseAuthorizationClientError(
            "durable policy transition identity is invalid"
        )
    return {
        "actorId": str(durable["actor_id"]),
        "attemptId": str(durable["attempt_id"]),
        "claimDigest": str(durable["claim_digest"]),
        "reservationId": str(durable["reservation_id"]),
    }


def _durable_policy_response(
    raw: Any,
    *,
    expected_states: set[str],
    attempt_id: str,
    claim_digest: str,
    require_reservation_id: bool,
) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise DurablePolicyStateError(
            "durable policy state response must be an object"
        )
    allowed = {
        "state",
        "attempt_id",
        "claim_digest",
        "reservation_id",
        "reason",
        "retry_after_seconds",
    }
    if (
        set(raw) - allowed
        or raw.get("state") not in expected_states
        or raw.get("attempt_id") != attempt_id
        or raw.get("claim_digest") != claim_digest
    ):
        raise DurablePolicyStateError(
            "durable policy state response binding is invalid"
        )
    reason = raw.get("reason")
    retry_after = raw.get("retry_after_seconds")
    if (
        reason is not None
        and (
            not isinstance(reason, str)
            or not reason
            or reason != reason.strip()
            or len(reason.encode("utf-8")) > 256
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in reason
            )
        )
    ) or (
        retry_after is not None
        and (
            not isinstance(retry_after, int)
            or isinstance(retry_after, bool)
            or not 1 <= retry_after <= 31_536_000
        )
    ):
        raise DurablePolicyStateError(
            "durable policy state result metadata is invalid"
        )
    reservation_id = raw.get("reservation_id")
    if require_reservation_id and (
        not isinstance(reservation_id, str)
        or not reservation_id
        or reservation_id != reservation_id.strip()
        or len(reservation_id.encode("utf-8")) > 256
    ):
        raise DurablePolicyStateError(
            "durable policy reservation identity is invalid"
        )
    return dict(raw)


def reserve_durable_policy_state(
    *,
    attempt_id: str,
    policy_hash: str,
    request_digest: str,
    operation_digest: str,
    release_binding_digest: str,
    claims: list[dict[str, Any]],
) -> dict[str, Any] | None:
    raise DurablePolicyStateError(
        "standalone durable policy reservation is disabled; "
        "use releaseAuthorizationReserve/v2"
    )


def _transition_durable_policy_state(
    action: str,
    reservation: dict[str, Any] | None,
    *,
    response_evidence: list[dict[str, Any]] | None = None,
    failure_reason: str | None = None,
    response_body_sha256: str | None = None,
    dispatch_deadline_at_epoch_ms: int | None = None,
) -> dict[str, Any] | None:
    raise DurablePolicyStateError(
        "standalone durable policy transitions are disabled; "
        "use releaseAuthorizationDispatch/v2 or "
        "releaseAuthorizationComplete/v2"
    )


def dispatch_durable_policy_state(
    reservation: dict[str, Any] | None,
    *,
    dispatch_deadline_at_epoch_ms: int,
) -> dict[str, Any] | None:
    return _transition_durable_policy_state(
        "dispatch",
        reservation,
        dispatch_deadline_at_epoch_ms=dispatch_deadline_at_epoch_ms,
    )


def abort_durable_policy_state(
    reservation: dict[str, Any] | None,
) -> dict[str, Any] | None:
    return _transition_durable_policy_state("abort", reservation)


def complete_durable_policy_state(
    reservation: dict[str, Any] | None,
    *,
    response_evidence: list[dict[str, Any]],
) -> dict[str, Any] | None:
    return _transition_durable_policy_state(
        "response",
        reservation,
        response_evidence=response_evidence,
    )


def fail_durable_policy_state(
    reservation: dict[str, Any] | None,
    *,
    failure_reason: str,
    response_body_sha256: str,
    traversal_evidence: list[dict[str, Any]],
) -> dict[str, Any] | None:
    return _transition_durable_policy_state(
        "indeterminate",
        reservation,
        response_evidence=traversal_evidence,
        failure_reason=failure_reason,
        response_body_sha256=response_body_sha256,
    )


@dataclass(frozen=True)
class ReleaseAuthorizationExpectedIdentity:
    attempt_id: str
    flow_id: str
    principal_id: str
    route_id: str
    credential_ref: str | None
    credential_version: int
    policy_hash: str
    request_digest: str
    operation_digest: str | None
    require_jit_grant: bool
    binding_digest: str
    shared_quota_bindings: tuple[str, ...]


class ReleaseAuthorizationGuard:
    """Own one expected reservation from pre-transport through terminalization."""

    def __init__(
        self,
        expected: ReleaseAuthorizationExpectedIdentity,
        *,
        durable_policy: dict[str, Any] | None = None,
    ) -> None:
        if not isinstance(expected, ReleaseAuthorizationExpectedIdentity):
            raise TypeError("release authorization guard identity is invalid")
        self.expected = expected
        self.durable_policy = copy.deepcopy(durable_policy)
        self.phase = "reserve_pending"
        self.cleanup_emitted = False
        self.cleanup_result: dict[str, Any] | None = None
        self.cleanup_error = False
        self.cleanup_error_detail: str | None = None
        self._cleanup_lock = threading.Lock()

    @property
    def requires_not_forwarded(self) -> bool:
        return self.phase in {"reserve_pending", "reserved"}

    @property
    def dispatch_uncertain(self) -> bool:
        return self.phase in {"dispatch_authorized", "dispatch_uncertain"}

    def promote_reserved(self) -> None:
        if self.phase != "reserve_pending":
            raise ReleaseAuthorizationClientError(
                "release authorization guard cannot promote from its current phase"
            )
        self.phase = "reserved"

    def disarm_denial(self) -> None:
        if self.phase != "reserve_pending":
            raise ReleaseAuthorizationClientError(
                "release authorization guard cannot disarm from its current phase"
            )
        self.phase = "denied"

    def mark_dispatch_authorized(self) -> None:
        if self.phase != "reserved":
            raise ReleaseAuthorizationClientError(
                "release authorization guard is not reserved"
            )
        self.phase = "dispatch_authorized"

    def mark_dispatch_uncertain(self) -> None:
        if self.phase not in {"dispatch_authorized", "dispatch_uncertain"}:
            raise ReleaseAuthorizationClientError(
                "release authorization guard is not dispatch-authorized"
            )
        self.phase = "dispatch_uncertain"

    def mark_terminal(self) -> None:
        self.phase = "terminal"

    def cancel_not_forwarded_once(self) -> dict[str, Any] | None:
        with self._cleanup_lock:
            if self.cleanup_emitted:
                return self.cleanup_result
            if not self.requires_not_forwarded:
                return self.cleanup_result
            self.cleanup_emitted = True
            try:
                if self.durable_policy is None:
                    self.cleanup_result = (
                        cancel_expected_release_authorization(
                            self.expected
                        )
                    )
                else:
                    self.cleanup_result = (
                        cancel_expected_release_authorization(
                            self.expected,
                            durable_policy=self.durable_policy,
                        )
                    )
            except Exception as exc:
                self.cleanup_error = True
                self.cleanup_result = None
                self.phase = "cleanup_unknown"
                try:
                    self.cleanup_error_detail = str(exc)[:256]
                except Exception:
                    self.cleanup_error_detail = type(exc).__name__[:256]
            if self.cleanup_result is not None:
                self.phase = "terminal"
            return self.cleanup_result


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
    "durablePolicy",
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
_RELEASE_AUTHORIZATION_DURABLE_RESPONSE_FIELDS = {
    "state",
    "attemptId",
    "claimDigest",
    "reservationId",
    "actorId",
    "reservationDeadlineAtEpochMs",
    "dispatchDeadlineAtEpochMs",
    "responseEvidenceDigest",
    "failureReason",
    "responseBodySha256",
    "uncertainty",
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
        thread = threading.Thread(target=_audit_worker, name="catchplate-audit-spool", daemon=True)
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
            name="catchplate-audit-anchor",
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
            name="catchplate-decision-gate-ca-publisher",
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
        headers["X-Catchplate-Audit-Anchor-Token"] = AUDIT_ANCHOR_TOKEN
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
        "source": "catchplate-control-plane",
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
    # A recorded vote can still be pending below the approval threshold.
    # Only the authority's completed approval state permits grant publication;
    # do not construct or send a grant for a pending, terminal, or absent status.
    if approval.get("status") != "approved":
        return {"enabled": True, "ok": False, "error": "approval is not approved"}
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
            "X-Catchplate-Data-Plane-Token": DATA_PLANE_AUDIT_TOKEN,
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
    configured = os.getenv("CATCHPLATE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED")
    if configured is None:
        return ATOMIC_RELEASE_AUTHORIZATION_ENABLED
    return configured == "1"


def get_credential_generation(
    credential_id: str | None,
) -> dict[str, Any] | None:
    """Return bounded non-secret generation metadata for pre-reserve admission."""
    if not credential_id:
        return None
    with db.credential_generation_snapshot(credential_id) as generation:
        if (
            not isinstance(generation, dict)
            or set(generation)
            != {
                "id",
                "kind",
                "credential_version",
                "metadata",
                "lifecycle_status",
            }
        ):
            return None
        encoded = canonical_json(generation).encode("utf-8")
        if len(encoded) > 32 * 1024:
            raise ValueError("credential generation metadata exceeds 32 KiB")
        return copy.deepcopy(generation)


def get_credential_version(credential_id: str | None) -> int | None:
    if not credential_id:
        return 0
    credential = get_credential_generation(credential_id)
    if not credential:
        return None
    version = credential.get("credential_version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        return None
    return version


def _explicit_development_release_channel() -> bool:
    configured = os.getenv("CATCHPLATE_RELEASE_CHANNEL")
    return (
        configured is not None
        and configured.strip().lower() in _DEVELOPMENT_RELEASE_CHANNELS
    )


def _release_authorization_base_url() -> str:
    value = os.getenv(
        "CATCHPLATE_CONTROL_PLANE_RELEASE_AUTHORIZATION_BASE_URL", ""
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
        "CATCHPLATE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN",
        DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN,
    ).strip()


def _release_authorization_ssl_context(base_url: str) -> ssl.SSLContext | None:
    if not base_url.lower().startswith("https://"):
        return None
    ca_bundle = os.getenv("CATCHPLATE_CONTROL_PLANE_CA_BUNDLE", "").strip()
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


def expected_release_authorization_identity(
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
) -> ReleaseAuthorizationExpectedIdentity:
    identities = {
        "attempt_id": attempt_id,
        "flow_id": flow_id,
        "principal_id": principal_id,
        "route_id": route_id,
    }
    if any(
        not _valid_release_authorization_identity(value)
        for value in identities.values()
    ):
        raise ReleaseAuthorizationClientError(
            "release authorization expected identity is invalid"
        )
    if not hmac.compare_digest(attempt_id, flow_id):
        raise ReleaseAuthorizationClientError(
            "release authorization flow identity must equal attempt identity"
        )
    if credential_ref is not None and not _valid_release_authorization_identity(
        credential_ref
    ):
        raise ReleaseAuthorizationClientError(
            "release authorization expected credential identity is invalid"
        )
    if (
        type(credential_version) is not int
        or not 0 <= credential_version <= _UINT64_MAX
        or not isinstance(policy_hash, str)
        or _SHA256_DIGEST_RE.fullmatch(policy_hash) is None
        or not isinstance(request_digest, str)
        or _SHA256_DIGEST_RE.fullmatch(request_digest) is None
        or (
            operation_digest is not None
            and (
                not isinstance(operation_digest, str)
                or _SHA256_DIGEST_RE.fullmatch(operation_digest) is None
            )
        )
    ):
        raise ReleaseAuthorizationClientError(
            "release authorization expected digest or generation is invalid"
        )
    normalized_shared_quotas = _normalized_expected_release_authorization_quotas(
        shared_quotas
    )
    binding_digest = release_authorization_binding_digest(
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
        shared_quotas=normalized_shared_quotas,
        require_jit_grant=require_jit_grant,
    )
    return ReleaseAuthorizationExpectedIdentity(
        attempt_id=attempt_id,
        flow_id=flow_id,
        principal_id=principal_id,
        route_id=route_id,
        credential_ref=credential_ref,
        credential_version=credential_version,
        policy_hash=policy_hash,
        request_digest=request_digest,
        operation_digest=operation_digest,
        require_jit_grant=bool(require_jit_grant),
        binding_digest=binding_digest,
        shared_quota_bindings=tuple(
            canonical_json(item) for item in normalized_shared_quotas
        ),
    )


def release_reservation_id(attempt_id: str, binding_digest: str) -> str:
    if (
        not _valid_release_authorization_identity(attempt_id)
        or _SHA256_DIGEST_RE.fullmatch(binding_digest) is None
    ):
        raise ReleaseAuthorizationClientError(
            "release reservation identity input is invalid"
        )
    return "sha256:" + hashlib.sha256(
        canonical_json(
            {
                "apiVersion": "catchplate.releaseReservationIdentity/v1",
                "attemptId": attempt_id,
                "bindingDigest": binding_digest,
            }
        ).encode("utf-8")
    ).hexdigest()


def credential_lease_release_authorization(
    expected: ReleaseAuthorizationExpectedIdentity,
    reserved: dict[str, Any],
) -> dict[str, Any] | None:
    if not isinstance(expected, ReleaseAuthorizationExpectedIdentity):
        raise ReleaseAuthorizationClientError(
            "credential lease release identity is invalid"
        )
    if (
        reserved.get("authorized") is not True
        or reserved.get("state") != "reserved"
        or reserved.get("attempt_id") != expected.attempt_id
        or reserved.get("binding_digest") != expected.binding_digest
    ):
        raise ReleaseAuthorizationClientError(
            "credential lease release reservation is invalid"
        )
    quotas = _normalized_release_authorization_quota_snapshot(
        reserved.get("quotas")
    )
    if tuple(
        canonical_json(_release_authorization_quota_binding(quota))
        for quota in quotas
    ) != expected.shared_quota_bindings:
        raise ReleaseAuthorizationClientError(
            "credential release authority quota binding is invalid"
        )
    grant_id = reserved.get("grant_id")
    approval_request_id = reserved.get("approval_request_id")
    durable = reserved.get("durable_policy")
    if expected.require_jit_grant:
        kind = "jitGrant"
        if not (
            _valid_release_authorization_identity(grant_id)
            and _valid_release_authorization_identity(approval_request_id)
        ):
            raise ReleaseAuthorizationClientError(
                "JIT credential release authority is incomplete"
            )
    elif expected.shared_quota_bindings or durable is not None:
        kind = "atomicReservation"
        if (
            grant_id is not None
            or approval_request_id is not None
            or (not quotas and durable is None)
        ):
            raise ReleaseAuthorizationClientError(
                "atomic credential release authority conflicts with JIT state"
            )
    else:
        return None
    quota_claims = [
        {
            "counterKey": quota["counter_key"],
            "constraintId": quota["constraint_id"],
            "operation": quota["operation"],
            "windowKind": quota["window_kind"],
            "windowSeconds": quota["window_seconds"],
            "windowStartEpochMs": quota["window_start_epoch_ms"],
            "windowEndEpochMs": quota["window_end_epoch_ms"],
            "max": quota["max"],
            "count": quota["count"],
            "remaining": quota["remaining"],
            "reservationState": quota["reservation_state"],
        }
        for quota in quotas
    ]
    expires_at = reserved.get("reservation_expires_at_epoch_ms")
    if (
        type(expires_at) is not int
        or expires_at <= int(time.time() * 1000)
        or expected.credential_ref is None
        or expected.credential_version < 1
    ):
        raise ReleaseAuthorizationClientError(
            "credential release authority is expired or credentialless"
        )
    release = {
        "apiVersion": (
            "catchplate.credentialLeaseReleaseAuthorization/v2"
            if durable is not None
            else "catchplate.credentialLeaseReleaseAuthorization/v1"
        ),
        "kind": kind,
        "state": "reserved",
        "attemptId": expected.attempt_id,
        "reservationId": release_reservation_id(
            expected.attempt_id, expected.binding_digest
        ),
        "bindingDigest": expected.binding_digest,
        "principalId": expected.principal_id,
        "routeId": expected.route_id,
        "credentialId": expected.credential_ref,
        "credentialVersion": expected.credential_version,
        "policyHash": expected.policy_hash,
        "requestDigest": expected.request_digest,
        "operationDigest": expected.operation_digest,
        "quotaClaims": quota_claims,
        "grantId": grant_id,
        "approvalRequestId": approval_request_id,
        "reservationExpiresAtEpochMs": expires_at,
    }
    if durable is not None:
        if (
            not isinstance(durable, dict)
            or durable.get("state") != "reserved"
            or durable.get("attempt_id") != expected.attempt_id
            or durable.get("actor_id") != _release_authorization_actor_id()
            or durable.get("reservation_deadline_at_epoch_ms") != expires_at
        ):
            raise ReleaseAuthorizationClientError(
                "credential release durable authority is invalid"
            )
        release["durablePolicy"] = {
            "reservationId": durable["reservation_id"],
            "actorId": durable["actor_id"],
            "claimDigest": durable["claim_digest"],
            "reservationDeadlineAtEpochMs": durable[
                "reservation_deadline_at_epoch_ms"
            ],
            "releaseBindingDigest": expected.binding_digest,
        }
    return release


def credential_lease_request_authority(
    expected: ReleaseAuthorizationExpectedIdentity,
    reserved: dict[str, Any],
    *,
    operation_context: dict[str, Any],
    controlled: bool,
) -> dict[str, Any] | None:
    if not controlled:
        return None
    if not isinstance(expected, ReleaseAuthorizationExpectedIdentity):
        raise ReleaseAuthorizationClientError(
            "credential lease request identity is invalid"
        )
    if (
        expected.credential_ref is None
        or expected.credential_version < 1
        or expected.operation_digest is None
        or reserved.get("authorized") is not True
        or reserved.get("state") != "reserved"
        or reserved.get("attempt_id") != expected.attempt_id
        or reserved.get("binding_digest") != expected.binding_digest
    ):
        raise ReleaseAuthorizationClientError(
            "credential lease request reservation is invalid"
        )
    quotas = _normalized_release_authorization_quota_snapshot(
        reserved.get("quotas")
    )
    if tuple(
        canonical_json(_release_authorization_quota_binding(quota))
        for quota in quotas
    ) != expected.shared_quota_bindings:
        raise ReleaseAuthorizationClientError(
            "credential request authority quota binding is invalid"
        )
    expected_quotas = [
        strict_json_loads(binding)
        for binding in expected.shared_quota_bindings
    ]
    recomputed = release_authorization_binding_digest(
        attempt_id=expected.attempt_id,
        flow_id=expected.flow_id,
        principal_id=expected.principal_id,
        route_id=expected.route_id,
        credential_ref=expected.credential_ref,
        credential_version=expected.credential_version,
        policy_hash=expected.policy_hash,
        request_digest=expected.request_digest,
        operation_digest=expected.operation_digest,
        operation_context=operation_context,
        shared_quotas=expected_quotas,
        require_jit_grant=expected.require_jit_grant,
    )
    expires_at = reserved.get("reservation_expires_at_epoch_ms")
    if (
        not hmac.compare_digest(recomputed, expected.binding_digest)
        or type(expires_at) is not int
        or expires_at <= int(time.time() * 1000)
    ):
        raise ReleaseAuthorizationClientError(
            "credential request authority is expired or rebound"
        )
    return {
        "apiVersion": "catchplate.credentialLeaseRequestAuthority/v1",
        "attemptId": expected.attempt_id,
        "reservationId": release_reservation_id(
            expected.attempt_id, expected.binding_digest
        ),
        "bindingDigest": expected.binding_digest,
        "requestDigest": expected.request_digest,
        "operationDigest": expected.operation_digest,
        "operationContext": copy.deepcopy(operation_context),
        "reservationExpiresAtEpochMs": expires_at,
    }


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


def _normalized_release_authorization_durable_response(
    value: Any,
    *,
    attempt_id: str,
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != _RELEASE_AUTHORIZATION_DURABLE_RESPONSE_FIELDS
    ):
        raise ReleaseAuthorizationClientError(
            "release authorization durable response fields are invalid"
        )
    state = value.get("state")
    if state not in {
        "denied",
        "reserved",
        "dispatched",
        "committed",
        "aborted",
        "indeterminate",
    }:
        raise ReleaseAuthorizationClientError(
            "release authorization durable response state is invalid"
        )
    if (
        value.get("attemptId") != attempt_id
        or _SHA256_DIGEST_RE.fullmatch(str(value.get("claimDigest") or ""))
        is None
        or not _valid_release_authorization_identity(value.get("actorId"))
    ):
        raise ReleaseAuthorizationClientError(
            "release authorization durable response binding is invalid"
        )
    reservation_id = value.get("reservationId")
    reservation_deadline = _release_u64(
        value.get("reservationDeadlineAtEpochMs"),
        field="durable reservation deadline",
    )
    dispatch_deadline = _release_u64(
        value.get("dispatchDeadlineAtEpochMs"),
        field="durable dispatch deadline",
    )
    response_evidence_digest = value.get("responseEvidenceDigest")
    response_body_sha256 = value.get("responseBodySha256")
    for digest, field in (
        (response_evidence_digest, "durable response evidence digest"),
        (response_body_sha256, "durable response body digest"),
    ):
        if digest is not None and (
            not isinstance(digest, str)
            or _SHA256_DIGEST_RE.fullmatch(digest) is None
        ):
            raise ReleaseAuthorizationClientError(
                f"release authorization {field} is invalid"
            )
    failure_reason = value.get("failureReason")
    uncertainty = value.get("uncertainty")
    for text, field in (
        (failure_reason, "durable failure reason"),
        (uncertainty, "durable uncertainty"),
    ):
        if text is not None and not _valid_release_authorization_identity(text):
            raise ReleaseAuthorizationClientError(
                f"release authorization {field} is invalid"
            )
    if state == "denied" and reservation_id is None:
        if any(
            item is not None
            for item in (
                reservation_deadline,
                dispatch_deadline,
                response_evidence_digest,
                failure_reason,
                response_body_sha256,
                uncertainty,
            )
        ):
            raise ReleaseAuthorizationClientError(
                "reserve-denied durable response carries reservation state"
            )
    elif (
        not isinstance(reservation_id, str)
        or _SHA256_DIGEST_RE.fullmatch(reservation_id) is None
        or reservation_deadline is None
    ):
        raise ReleaseAuthorizationClientError(
            "release authorization durable reservation is incomplete"
        )
    if state == "reserved" and any(
        item is not None
        for item in (
            dispatch_deadline,
            response_evidence_digest,
            failure_reason,
            response_body_sha256,
            uncertainty,
        )
    ):
        raise ReleaseAuthorizationClientError(
            "reserved durable response carries terminal state"
        )
    if state == "dispatched" and (
        dispatch_deadline is None
        or any(
            item is not None
            for item in (
                response_evidence_digest,
                failure_reason,
                response_body_sha256,
                uncertainty,
            )
        )
    ):
        raise ReleaseAuthorizationClientError(
            "dispatched durable response is incomplete"
        )
    if state in {"committed", "indeterminate"} or (
        state == "denied" and reservation_id is not None
    ):
        if (
            response_evidence_digest is None
            or response_body_sha256 is None
        ):
            raise ReleaseAuthorizationClientError(
                "terminal durable response evidence is incomplete"
            )
    if (
        state in {"committed", "denied"}
        and reservation_id is not None
        and dispatch_deadline is None
    ):
        raise ReleaseAuthorizationClientError(
            "terminal durable response dispatch binding is incomplete"
        )
    if state == "indeterminate" and (
        failure_reason
        != "provider_outcome_or_response_validation_uncertain"
        or uncertainty != "charged_fail_closed"
    ):
        raise ReleaseAuthorizationClientError(
            "durable uncertainty semantics are invalid"
        )
    if (
        state == "denied"
        and reservation_id is not None
        and (failure_reason is None or uncertainty is not None)
    ):
        raise ReleaseAuthorizationClientError(
            "denied durable response reason is incomplete"
        )
    if state == "aborted" and any(
        item is not None
        for item in (
            dispatch_deadline,
            response_evidence_digest,
            failure_reason,
            response_body_sha256,
            uncertainty,
        )
    ):
        raise ReleaseAuthorizationClientError(
            "aborted durable response carries transition evidence"
        )
    if state == "committed" and (
        failure_reason is not None or uncertainty is not None
    ):
        raise ReleaseAuthorizationClientError(
            "durable terminal response carries conflicting failure state"
        )
    return {
        "state": state,
        "attempt_id": attempt_id,
        "claim_digest": str(value["claimDigest"]),
        "reservation_id": reservation_id,
        "actor_id": str(value["actorId"]),
        "reservation_deadline_at_epoch_ms": reservation_deadline,
        "dispatch_deadline_at_epoch_ms": dispatch_deadline,
        "response_evidence_digest": response_evidence_digest,
        "failure_reason": failure_reason,
        "response_body_sha256": response_body_sha256,
        "uncertainty": uncertainty,
    }


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
    api_version = body.get("apiVersion")
    if api_version not in {
        "catchplate.releaseAuthorization/v1",
        "catchplate.releaseAuthorization/v2",
    }:
        raise ReleaseAuthorizationClientError(
            "release authorization response version is invalid"
        )
    durable_present = "durablePolicy" in body
    if (api_version == "catchplate.releaseAuthorization/v2") != durable_present:
        raise ReleaseAuthorizationClientError(
            "release authorization response protocol is inconsistent"
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
    normalized = {
        "api_version": api_version,
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
    if durable_present:
        normalized["durable_policy"] = (
            _normalized_release_authorization_durable_response(
                body["durablePolicy"],
                attempt_id=attempt_id,
            )
        )
    return normalized


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


def _validate_durable_policy_response_binding(
    response: dict[str, Any],
    *,
    expected: dict[str, Any] | None,
    expected_states: set[str],
) -> dict[str, Any] | None:
    durable = response.get("durable_policy")
    if expected is None:
        if durable is not None or response.get("api_version") not in {
            None,
            "catchplate.releaseAuthorization/v1",
        }:
            raise ReleaseAuthorizationClientError(
                "release authorization unexpectedly changed protocol"
            )
        return None
    if (
        response.get("api_version") != "catchplate.releaseAuthorization/v2"
        or not isinstance(durable, dict)
        or durable.get("state") not in expected_states
        or durable.get("attempt_id") != expected.get("attemptId")
        or durable.get("claim_digest") != expected.get("claimDigest")
        or durable.get("actor_id") != expected.get("actorId")
    ):
        raise ReleaseAuthorizationClientError(
            "release authorization durable policy binding changed"
        )
    expected_reservation_id = expected.get("reservationId")
    if (
        durable.get("state") == "denied"
        and durable.get("reservation_id") is None
    ):
        return durable
    if (
        not isinstance(expected_reservation_id, str)
        or not hmac.compare_digest(
            str(durable.get("reservation_id") or ""),
            expected_reservation_id,
        )
    ):
        raise ReleaseAuthorizationClientError(
            "release authorization durable reservation changed"
        )
    return durable


def validate_reserve_release_authorization_response(
    response: dict[str, Any],
    *,
    attempt_id: str,
    require_jit_grant: bool,
    expected_binding_digest: str,
    expected_shared_quotas: list[dict[str, Any]],
    expected_durable_policy: dict[str, Any] | None = None,
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
                "durable_policy_denied",
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
    durable = _validate_durable_policy_response_binding(
        response,
        expected=expected_durable_policy,
        expected_states=({"reserved"} if authorized is True else {"denied"}),
    )
    if (
        durable is not None
        and authorized is True
        and durable.get("reservation_deadline_at_epoch_ms")
        != reservation_expires_at
    ):
        raise ReleaseAuthorizationClientError(
            "release authorization durable reservation deadline changed"
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
    expected_dispatch_deadline_at_epoch_ms: int | None = None,
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
    previous_durable = previous_lifecycle.get("durable_policy")
    durable = _validate_durable_policy_response_binding(
        response,
        expected=(
            {
                "attemptId": previous_durable.get("attempt_id"),
                "claimDigest": previous_durable.get("claim_digest"),
                "actorId": previous_durable.get("actor_id"),
                "reservationId": previous_durable.get("reservation_id"),
            }
            if isinstance(previous_durable, dict)
            else None
        ),
        expected_states={"dispatched"},
    )
    if durable is not None and durable.get(
        "dispatch_deadline_at_epoch_ms"
    ) != response.get("dispatch_expires_at_epoch_ms"):
        raise ReleaseAuthorizationClientError(
            "release authorization durable dispatch deadline changed"
        )
    if (
        expected_dispatch_deadline_at_epoch_ms is not None
        and dispatch_expires_at != expected_dispatch_deadline_at_epoch_ms
    ):
        raise ReleaseAuthorizationClientError(
            "release authorization submitted dispatch deadline changed"
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
    expected_durable_transition: dict[str, Any] | None = None,
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
    previous_durable = previous_lifecycle.get("durable_policy")
    durable_states = {
        ("committed", "forwarded"): {"committed", "denied"},
        ("cancelled", "not_forwarded"): {"aborted"},
        ("committed_indeterminate", "unknown"): {"indeterminate"},
    }.get((state, completion_outcome), set())
    durable = _validate_durable_policy_response_binding(
        response,
        expected=(
            {
                "attemptId": previous_durable.get("attempt_id"),
                "claimDigest": previous_durable.get("claim_digest"),
                "actorId": previous_durable.get("actor_id"),
                "reservationId": previous_durable.get("reservation_id"),
            }
            if isinstance(previous_durable, dict)
            else None
        ),
        expected_states=durable_states,
    )
    if durable is not None:
        if expected_durable_transition is not None:
            exact_terminal_evidence = durable.get("state") in {
                "committed",
                "denied",
                "indeterminate",
            }
            if exact_terminal_evidence:
                if (
                    durable.get("response_evidence_digest")
                    != expected_durable_transition.get(
                        "responseEvidenceDigest"
                    )
                    or durable.get("response_body_sha256")
                    != expected_durable_transition.get(
                        "responseBodySha256"
                    )
                ):
                    raise ReleaseAuthorizationClientError(
                        "release authorization durable terminal evidence changed"
                    )
            if (
                state == "committed"
                and durable.get("state") in {"committed", "denied"}
                and durable.get("dispatch_deadline_at_epoch_ms")
                != expected_durable_transition.get(
                    "dispatchDeadlineAtEpochMs"
                )
            ):
                raise ReleaseAuthorizationClientError(
                    "release authorization durable completion deadline changed"
                )
            if (
                state == "committed_indeterminate"
                and durable.get("state") == "indeterminate"
            ):
                if (
                    durable.get("dispatch_deadline_at_epoch_ms")
                    != expected_durable_transition.get(
                        "dispatchDeadlineAtEpochMs"
                    )
                    or durable.get("failure_reason")
                    != expected_durable_transition.get("failureReason")
                    or durable.get("uncertainty")
                    != expected_durable_transition.get("uncertainty")
                ):
                    raise ReleaseAuthorizationClientError(
                        "release authorization durable uncertainty changed"
                    )
            if state == "cancelled" and any(
                durable.get(field) is not None
                for field in (
                    "dispatch_deadline_at_epoch_ms",
                    "response_evidence_digest",
                    "failure_reason",
                    "response_body_sha256",
                    "uncertainty",
                )
            ):
                raise ReleaseAuthorizationClientError(
                    "release authorization durable abort carries completion evidence"
                )
        response["durable_policy"] = durable
    return response


def _normalized_direct_release_authorization_response(
    result: Any,
) -> dict[str, Any]:
    if not isinstance(result, dict):
        raise ReleaseAuthorizationClientError(
            "release authorization direct response must be an object"
        )
    normalized = dict(result)
    normalized.setdefault(
        "api_version",
        (
            "catchplate.releaseAuthorization/v2"
            if isinstance(normalized.get("durable_policy"), dict)
            else "catchplate.releaseAuthorization/v1"
        ),
    )
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
    if isinstance(normalized.get("durable_policy"), dict):
        durable = dict(normalized["durable_policy"])
        direct_fields = {
            "state": "state",
            "attempt_id": "attemptId",
            "claim_digest": "claimDigest",
            "reservation_id": "reservationId",
            "actor_id": "actorId",
            "reservation_deadline_at_epoch_ms": (
                "reservationDeadlineAtEpochMs"
            ),
            "dispatch_deadline_at_epoch_ms": "dispatchDeadlineAtEpochMs",
            "response_evidence_digest": "responseEvidenceDigest",
            "failure_reason": "failureReason",
            "response_body_sha256": "responseBodySha256",
            "uncertainty": "uncertainty",
        }
        if set(durable) != set(direct_fields):
            raise ReleaseAuthorizationClientError(
                "release authorization direct durable response fields are invalid"
            )
        normalized["durable_policy"] = (
            _normalized_release_authorization_durable_response(
                {
                    wire_name: durable[field]
                    for field, wire_name in direct_fields.items()
                },
                attempt_id=str(normalized.get("attempt_id") or ""),
            )
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
    expected_durable_policy: dict[str, Any] | None = None,
    expected_durable_transition: dict[str, Any] | None = None,
    expected_dispatch_deadline_at_epoch_ms: int | None = None,
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
    attempts = 1 if action == "reserve" else 2
    for retry in range(attempts):
        request = urllib.request.Request(
            f"{base_url}/{action}",
            data=encoded,
            headers={
                "Content-Type": "application/json",
                "X-Catchplate-Data-Plane-Token": token,
            },
            method="POST",
        )
        try:
            response = request_json_bytes(
                request,
                timeout=DECISION_GATE_TIMEOUT_SECONDS,
                max_bytes=256 * 1024,
                context=context,
                expected_statuses=(200,),
                expected_content_types=("application/json",),
            )
            normalized = _normalized_release_authorization_response(
                response.value,
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
                    expected_durable_policy=expected_durable_policy,
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
                    expected_dispatch_deadline_at_epoch_ms=(
                        expected_dispatch_deadline_at_epoch_ms
                    ),
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
                    expected_durable_transition=(
                        expected_durable_transition
                    ),
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
            finally:
                exc.close()
            last_error = ReleaseAuthorizationClientError(
                str(detail or f"release authorization HTTP {exc.code}")
            )
            if exc.code != 503 or retry + 1 >= attempts:
                break
        except Exception as exc:
            last_error = exc
            if retry + 1 >= attempts:
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


def _reserve_expected_release_authorization_once(
    *,
    expected: ReleaseAuthorizationExpectedIdentity,
    operation_context: dict[str, Any],
    canonical_request: dict[str, Any],
    shared_quotas: list[dict[str, Any]],
    durable_policy: dict[str, Any] | None,
) -> dict[str, Any]:
    if not isinstance(expected, ReleaseAuthorizationExpectedIdentity):
        raise ReleaseAuthorizationClientError(
            "release authorization expected identity is invalid"
        )
    if not atomic_release_authorization_enabled():
        raise ReleaseAuthorizationClientError(
            "atomic release authorization is disabled"
        )
    bounded_canonical_request = _bounded_release_canonical_request(
        canonical_request,
        request_digest=expected.request_digest,
    )
    recomputed = release_authorization_binding_digest(
        attempt_id=expected.attempt_id,
        flow_id=expected.flow_id,
        principal_id=expected.principal_id,
        route_id=expected.route_id,
        credential_ref=expected.credential_ref,
        credential_version=expected.credential_version,
        policy_hash=expected.policy_hash,
        request_digest=expected.request_digest,
        operation_digest=expected.operation_digest,
        operation_context=operation_context,
        shared_quotas=shared_quotas,
        require_jit_grant=expected.require_jit_grant,
    )
    if not hmac.compare_digest(recomputed, expected.binding_digest):
        raise ReleaseAuthorizationClientError(
            "release authorization outbound binding changed after guard creation"
        )
    if _release_authorization_base_url():
        payload = {
            "apiVersion": (
                "catchplate.releaseAuthorizationReserve/v2"
                if durable_policy is not None
                else "catchplate.releaseAuthorizationReserve/v1"
            ),
            "attemptId": expected.attempt_id,
            "flowId": expected.flow_id,
            "principalId": expected.principal_id,
            "routeId": expected.route_id,
            "credentialRef": expected.credential_ref,
            "credentialVersion": expected.credential_version,
            "policyHash": expected.policy_hash,
            "requestDigest": expected.request_digest,
            "operationDigest": expected.operation_digest,
            "operationContext": operation_context,
            "canonicalRequest": bounded_canonical_request,
        }
        if durable_policy is not None:
            payload["durablePolicy"] = {
                key: copy.deepcopy(durable_policy[key])
                for key in ("actorId", "claimDigest", "claims")
            }
        return _release_authorization_http_post(
            "reserve",
            payload,
            require_jit_grant=expected.require_jit_grant,
            expected_binding_digest=expected.binding_digest,
            expected_shared_quotas=shared_quotas,
            expected_durable_policy=durable_policy,
        )
    _require_development_release_authorization_fallback()
    if expected.require_jit_grant:
        raise ReleaseAuthorizationClientError(
            "JIT release authorization requires the control-plane release authority"
        )
    try:
        reserve = (
            db.reserve_release_authorization_v2
            if durable_policy is not None
            else db.reserve_release_authorization
        )
        reserve_arguments: dict[str, Any] = {
            "attempt_id": expected.attempt_id,
            "flow_id": expected.flow_id,
            "principal_id": expected.principal_id,
            "route_id": expected.route_id,
            "credential_id": expected.credential_ref or "",
            "credential_version": expected.credential_version,
            "policy_hash": expected.policy_hash,
            "request_digest": expected.request_digest,
            "operation_digest": expected.operation_digest,
            "operation_context": operation_context,
            "shared_quotas": shared_quotas,
            "require_jit_grant": expected.require_jit_grant,
            "reservation_ttl_seconds": (
                RELEASE_AUTHORIZATION_RESERVATION_TTL_SECONDS
            ),
            "actor_id": _release_authorization_actor_id(),
        }
        if durable_policy is not None:
            reserve_arguments["durable_policy_binding"] = {
                key: copy.deepcopy(durable_policy[key])
                for key in ("actorId", "claimDigest", "claims")
            }
        result = _normalized_direct_release_authorization_response(
            reserve(**reserve_arguments)
        )
        return validate_reserve_release_authorization_response(
            result,
            attempt_id=expected.attempt_id,
            require_jit_grant=expected.require_jit_grant,
            expected_binding_digest=expected.binding_digest,
            expected_shared_quotas=shared_quotas,
            expected_durable_policy=durable_policy,
        )
    except Exception as exc:
        raise ReleaseAuthorizationClientError(
            f"release authorization reserve is uncertain: {exc}"
        ) from exc


def reserve_expected_release_authorization(
    *,
    guard: ReleaseAuthorizationGuard,
    operation_context: dict[str, Any],
    canonical_request: dict[str, Any],
    shared_quotas: list[dict[str, Any]],
    durable_policy_claims: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if (
        not isinstance(guard, ReleaseAuthorizationGuard)
        or guard.phase != "reserve_pending"
        or guard.cleanup_emitted
    ):
        raise ReleaseAuthorizationClientError(
            "release authorization reserve guard is missing or already used"
        )
    try:
        durable_policy = durable_policy_reserve_binding(
            guard.expected,
            durable_policy_claims,
        )
        if durable_policy != guard.durable_policy:
            raise ReleaseAuthorizationClientError(
                "release authorization guard durable identity changed"
            )
        result = _reserve_expected_release_authorization_once(
            expected=guard.expected,
            operation_context=operation_context,
            canonical_request=canonical_request,
            shared_quotas=shared_quotas,
            durable_policy=durable_policy,
        )
        state = result.get("state")
        if state == "denied":
            guard.disarm_denial()
        elif state == "reserved":
            guard.promote_reserved()
        else:
            raise ReleaseAuthorizationClientError(
                "release authorization reserve returned an invalid lifecycle"
            )
        return result
    except Exception as exc:
        guard.cancel_not_forwarded_once()
        if isinstance(exc, ReleaseAuthorizationClientError):
            raise
        raise ReleaseAuthorizationClientError(
            "release authorization reserve is uncertain"
        ) from exc


def _validate_expected_not_forwarded_response(
    response: dict[str, Any],
    *,
    expected: ReleaseAuthorizationExpectedIdentity,
    durable_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    _validate_release_authorization_binding(
        response,
        attempt_id=expected.attempt_id,
        binding_digest=expected.binding_digest,
    )
    state = response.get("state")
    if state == "absent":
        exact = (
            response.get("authorized") is False
            and response.get("reason") == "reservation_absent"
            and response.get("idempotent_replay") is True
            and response.get("grant_id") is None
            and response.get("approval_request_id") is None
            and response.get("approval_status") is None
            and response.get("approval_expires_at") is None
            and response.get("approval_created") is None
            and response.get("reservation_expires_at_epoch_ms") is None
            and response.get("dispatch_started_at_epoch_ms") is None
            and response.get("dispatch_expires_at_epoch_ms") is None
            and response.get("completion_outcome") is None
            and response.get("retry_after_seconds") == 0
            and response.get("quotas") == []
        )
    else:
        quotas = response.get("quotas")
        grant_id = response.get("grant_id")
        approval_request_id = response.get("approval_request_id")
        jit_identities_match = (
            (
                _valid_release_authorization_identity(grant_id)
                and _valid_release_authorization_identity(approval_request_id)
            )
            if expected.require_jit_grant
            else grant_id is None and approval_request_id is None
        )
        quota_bindings = (
            tuple(
                canonical_json(_release_authorization_quota_binding(quota))
                for quota in quotas
            )
            if isinstance(quotas, list)
            else ()
        )
        exact = (
            response.get("authorized") is False
            and state == "cancelled"
            and response.get("reason") == "cancelled"
            and response.get("completion_outcome") == "not_forwarded"
            and jit_identities_match
            and response.get("approval_status") is None
            and response.get("approval_expires_at") is None
            and response.get("approval_created") is None
            and isinstance(
                response.get("reservation_expires_at_epoch_ms"),
                int,
            )
            and not isinstance(
                response.get("reservation_expires_at_epoch_ms"),
                bool,
            )
            and response.get("dispatch_started_at_epoch_ms") is None
            and response.get("dispatch_expires_at_epoch_ms") is None
            and response.get("retry_after_seconds") == 0
            and isinstance(quotas, list)
            and quota_bindings == expected.shared_quota_bindings
            and all(
                quota.get("reservation_state")
                in {"refunded", "refund_skipped_window"}
                for quota in quotas
            )
        )
    if not exact:
        raise ReleaseAuthorizationClientError(
            "release authorization expected cancellation response is invalid"
        )
    durable = _validate_durable_policy_response_binding(
        response,
        expected=durable_policy,
        expected_states={"aborted"},
    )
    if durable is not None and any(
        durable.get(field) is not None
        for field in (
            "dispatch_deadline_at_epoch_ms",
            "response_evidence_digest",
            "failure_reason",
            "response_body_sha256",
            "uncertainty",
        )
    ):
        raise ReleaseAuthorizationClientError(
            "release authorization durable abort carries transition evidence"
        )
    return response


def cancel_expected_release_authorization(
    expected: ReleaseAuthorizationExpectedIdentity,
    *,
    durable_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Emit one bound cleanup; transport loss is terminal and never retried/refunded."""
    if not isinstance(expected, ReleaseAuthorizationExpectedIdentity):
        raise ReleaseAuthorizationClientError(
            "release authorization cancellation identity is invalid"
        )
    if _release_authorization_base_url():
        base_url = _release_authorization_base_url()
        token = _release_authorization_token()
        if not token:
            raise ReleaseAuthorizationClientError(
                "release authorization control-plane client is not configured"
            )
        payload = {
            "apiVersion": (
                "catchplate.releaseAuthorizationComplete/v2"
                if durable_policy is not None
                else "catchplate.releaseAuthorizationComplete/v1"
            ),
            "attemptId": expected.attempt_id,
            "bindingDigest": expected.binding_digest,
            "outcome": "not_forwarded",
        }
        if durable_policy is not None:
            payload["durablePolicy"] = {
                "actorId": durable_policy["actorId"],
                "attemptId": expected.attempt_id,
                "claimDigest": durable_policy["claimDigest"],
                "reservationId": durable_policy["reservationId"],
            }
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        request = urllib.request.Request(
            f"{base_url}/complete",
            data=encoded,
            headers={
                "Content-Type": "application/json",
                "X-Catchplate-Data-Plane-Token": token,
            },
            method="POST",
        )
        try:
            response = request_json_bytes(
                request,
                timeout=DECISION_GATE_TIMEOUT_SECONDS,
                max_bytes=256 * 1024,
                context=_release_authorization_ssl_context(base_url),
                expected_statuses=(200,),
                expected_content_types=("application/json",),
            )
            normalized = _normalized_release_authorization_response(
                response.value,
                attempt_id=expected.attempt_id,
            )
            return _validate_expected_not_forwarded_response(
                normalized,
                expected=expected,
                durable_policy=durable_policy,
            )
        except urllib.error.HTTPError as exc:
            try:
                http_error_body(exc, max_bytes=64 * 1024)
            except Exception:
                pass
            finally:
                exc.close()
            raise ReleaseAuthorizationClientError(
                "release authorization expected cancellation is uncertain"
            ) from exc
        except Exception as exc:
            raise ReleaseAuthorizationClientError(
                "release authorization expected cancellation is uncertain"
            ) from exc

    _require_development_release_authorization_fallback()
    try:
        if durable_policy is None:
            raw_result = db.cancel_release_authorization_if_present(
                attempt_id=expected.attempt_id,
                binding_digest=expected.binding_digest,
                actor_id=_release_authorization_actor_id(),
            )
        else:
            raw_result = db.complete_release_authorization_v2(
                attempt_id=expected.attempt_id,
                binding_digest=expected.binding_digest,
                outcome="not_forwarded",
                actor_id=_release_authorization_actor_id(),
                durable_policy_transition={
                    "actorId": durable_policy["actorId"],
                    "attemptId": expected.attempt_id,
                    "claimDigest": durable_policy["claimDigest"],
                    "reservationId": durable_policy["reservationId"],
                },
            )
        result = _normalized_direct_release_authorization_response(raw_result)
        return _validate_expected_not_forwarded_response(
            result,
            expected=expected,
            durable_policy=durable_policy,
        )
    except Exception as exc:
        raise ReleaseAuthorizationClientError(
            "release authorization expected cancellation is uncertain"
        ) from exc


def release_authorization_dispatch_deadline(
    previous_lifecycle: dict[str, Any],
) -> int:
    reservation_expires_at = previous_lifecycle.get(
        "reservation_expires_at_epoch_ms"
    )
    now_epoch_ms = int(time.time() * 1000)
    if (
        type(reservation_expires_at) is not int
        or reservation_expires_at <= now_epoch_ms
    ):
        raise ReleaseAuthorizationClientError(
            "release authorization reservation is expired"
        )
    deadline = min(
        reservation_expires_at,
        now_epoch_ms + RELEASE_AUTHORIZATION_DISPATCH_TTL_SECONDS * 1000,
    )
    if deadline <= now_epoch_ms:
        raise ReleaseAuthorizationClientError(
            "release authorization dispatch deadline is empty"
        )
    return deadline


def dispatch_release_authorization(
    *,
    attempt_id: str,
    binding_digest: str,
    grant_id: str | None = None,
    approval_request_id: str | None = None,
    previous_lifecycle: dict[str, Any],
    dispatch_deadline_at_epoch_ms: int | None = None,
) -> dict[str, Any]:
    durable = previous_lifecycle.get("durable_policy")
    if durable is not None:
        if dispatch_deadline_at_epoch_ms is None:
            raise ReleaseAuthorizationClientError(
                "release authorization v2 dispatch deadline is missing"
            )
        durable_transition = {
            **_durable_policy_transition_identity(durable),
            "dispatchDeadlineAtEpochMs": dispatch_deadline_at_epoch_ms,
        }
        api_version = "catchplate.releaseAuthorizationDispatch/v2"
    else:
        if dispatch_deadline_at_epoch_ms is not None:
            raise ReleaseAuthorizationClientError(
                "release authorization v1 cannot carry a durable deadline"
            )
        durable_transition = None
        api_version = "catchplate.releaseAuthorizationDispatch/v1"
    if _release_authorization_base_url():
        payload = {
            "apiVersion": api_version,
            "attemptId": attempt_id,
            "bindingDigest": binding_digest,
        }
        if durable_transition is not None:
            payload["durablePolicy"] = durable_transition
        return _release_authorization_http_post(
            "dispatch",
            payload,
            grant_id=grant_id,
            approval_request_id=approval_request_id,
            previous_lifecycle=previous_lifecycle,
            expected_dispatch_deadline_at_epoch_ms=(
                dispatch_deadline_at_epoch_ms
            ),
        )
    _require_development_release_authorization_fallback()
    try:
        if durable_transition is None:
            raw_result = db.dispatch_release_authorization(
                attempt_id=attempt_id,
                binding_digest=binding_digest,
                dispatch_ttl_seconds=RELEASE_AUTHORIZATION_DISPATCH_TTL_SECONDS,
                actor_id=_release_authorization_actor_id(),
            )
        else:
            raw_result = db.dispatch_release_authorization_v2(
                attempt_id=attempt_id,
                binding_digest=binding_digest,
                actor_id=_release_authorization_actor_id(),
                durable_policy_transition=durable_transition,
            )
        result = _normalized_direct_release_authorization_response(raw_result)
        return validate_dispatch_release_authorization_response(
            result,
            attempt_id=attempt_id,
            binding_digest=binding_digest,
            grant_id=grant_id,
            approval_request_id=approval_request_id,
            previous_lifecycle=previous_lifecycle,
            expected_dispatch_deadline_at_epoch_ms=(
                dispatch_deadline_at_epoch_ms
            ),
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
    durable_completion: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if outcome not in {"forwarded", "not_forwarded", "unknown"}:
        raise ReleaseAuthorizationClientError(
            "release authorization completion outcome is invalid"
        )
    durable = previous_lifecycle.get("durable_policy")
    if outcome == "not_forwarded" and durable is None:
        raise ReleaseAuthorizationClientError(
            "not_forwarded completion requires a retained expected reservation guard"
        )
    durable_transition = None
    api_version = "catchplate.releaseAuthorizationComplete/v1"
    if durable is not None:
        durable_transition = _durable_policy_transition_identity(durable)
        completion = (
            {}
            if outcome == "not_forwarded" and durable_completion is None
            else durable_completion
        )
        if outcome == "forwarded":
            required = {
                "response_evidence",
                "response_body_sha256",
                "dispatch_deadline_at_epoch_ms",
            }
        elif outcome == "unknown":
            required = {
                "response_evidence",
                "response_body_sha256",
                "failure_reason",
                "uncertainty",
            }
        else:
            required = set()
        if not isinstance(completion, dict) or (
            set(completion) - {
                "response_evidence",
                "response_body_sha256",
                "dispatch_deadline_at_epoch_ms",
                "failure_reason",
                "uncertainty",
            }
        ) or not required.issubset(completion):
            raise ReleaseAuthorizationClientError(
                "release authorization v2 completion evidence is incomplete"
            )
        if outcome in {"forwarded", "unknown"}:
            evidence = copy.deepcopy(
                completion["response_evidence"]
            )
            body_digest = completion["response_body_sha256"]
            if (
                not isinstance(evidence, list)
                or not isinstance(body_digest, str)
                or _SHA256_DIGEST_RE.fullmatch(body_digest) is None
            ):
                raise ReleaseAuthorizationClientError(
                    "release authorization v2 completion evidence is invalid"
                )
            durable_transition.update(
                {
                    "responseEvidence": evidence,
                    "responseEvidenceDigest": _durable_policy_digest(
                        evidence
                    ),
                    "responseBodySha256": body_digest,
                }
            )
        deadline = completion.get(
            "dispatch_deadline_at_epoch_ms"
        )
        if deadline is not None:
            if type(deadline) is not int or deadline < 1:
                raise ReleaseAuthorizationClientError(
                    "release authorization v2 completion deadline is invalid"
                )
            durable_transition["dispatchDeadlineAtEpochMs"] = deadline
        if outcome == "unknown":
            if (
                completion.get("failure_reason")
                != "provider_outcome_or_response_validation_uncertain"
                or completion.get("uncertainty")
                != "charged_fail_closed"
            ):
                raise ReleaseAuthorizationClientError(
                    "release authorization v2 uncertainty semantics are invalid"
                )
            durable_transition.update(
                {
                    "failureReason": completion["failure_reason"],
                    "uncertainty": completion["uncertainty"],
                }
            )
        api_version = "catchplate.releaseAuthorizationComplete/v2"
    elif durable_completion is not None:
        raise ReleaseAuthorizationClientError(
            "release authorization v1 cannot carry durable evidence"
        )
    if _release_authorization_base_url():
        payload = {
            "apiVersion": api_version,
            "attemptId": attempt_id,
            "bindingDigest": binding_digest,
            "outcome": outcome,
        }
        if durable_transition is not None:
            payload["durablePolicy"] = durable_transition
        return _release_authorization_http_post(
            "complete",
            payload,
            grant_id=grant_id,
            approval_request_id=approval_request_id,
            previous_lifecycle=previous_lifecycle,
            expected_durable_transition=durable_transition,
        )
    _require_development_release_authorization_fallback()
    try:
        if durable_transition is None:
            raw_result = db.complete_release_authorization(
                attempt_id=attempt_id,
                binding_digest=binding_digest,
                outcome=outcome,
                actor_id=_release_authorization_actor_id(),
            )
        else:
            raw_result = db.complete_release_authorization_v2(
                attempt_id=attempt_id,
                binding_digest=binding_digest,
                outcome=outcome,
                actor_id=_release_authorization_actor_id(),
                durable_policy_transition=durable_transition,
            )
        result = _normalized_direct_release_authorization_response(raw_result)
        return validate_complete_release_authorization_response(
            result,
            attempt_id=attempt_id,
            binding_digest=binding_digest,
            outcome=outcome,
            grant_id=grant_id,
            approval_request_id=approval_request_id,
            previous_lifecycle=previous_lifecycle,
            expected_durable_transition=durable_transition,
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
    if isinstance(credential.get("metadata"), dict) and "operator_x_account" in credential["metadata"]:
        return None  # Only the retained X lifecycle may prepare a scoped lease.
    if github_app_boundary.credential_selected(credential):
        return None  # Only the dedicated App owner can derive a lease token.
    if aws_credential_boundary.credential_selected(credential):
        return None  # Stored tuples are not header secrets or signing grants.
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
    current = db.get_credential(credential_id, include_secret=False)
    if (current is None or aws_credential_boundary.credential_selected(current)
            or github_app_boundary.credential_selected(current)
            or isinstance(current.get("metadata"), dict) and "operator_x_account" in current["metadata"]):
        return None
    credential = db.get_credential(credential_id, include_secret=True)
    if credential is not None and (aws_credential_boundary.credential_selected(credential)
            or github_app_boundary.credential_selected(credential)
            or isinstance(credential.get("metadata"), dict) and "operator_x_account" in credential["metadata"]):
        return None
    return credential


def _claim_release_controlled_credential(
    credential_id: str,
    request_authority: dict[str, Any],
    release_authorization: dict[str, Any] | None,
    *,
    expected: ReleaseAuthorizationExpectedIdentity,
    jit_policy: dict[str, Any] | None,
) -> None:
    request_authority_fields = {
        "apiVersion",
        "attemptId",
        "reservationId",
        "bindingDigest",
        "requestDigest",
        "operationDigest",
        "operationContext",
        "reservationExpiresAtEpochMs",
    }
    if (
        not isinstance(expected, ReleaseAuthorizationExpectedIdentity)
        or expected.credential_ref != credential_id
        or not isinstance(request_authority, dict)
        or set(request_authority) != request_authority_fields
        or request_authority.get("apiVersion")
        != "catchplate.credentialLeaseRequestAuthority/v1"
        or request_authority.get("attemptId") != expected.attempt_id
        or request_authority.get("reservationId")
        != release_reservation_id(expected.attempt_id, expected.binding_digest)
        or request_authority.get("bindingDigest") != expected.binding_digest
        or request_authority.get("requestDigest") != expected.request_digest
        or request_authority.get("operationDigest") != expected.operation_digest
        or type(request_authority.get("reservationExpiresAtEpochMs")) is not int
        or int(request_authority["reservationExpiresAtEpochMs"])
        <= int(time.time() * 1000)
    ):
        raise ReleaseAuthorizationClientError(
            "credential request authority is malformed"
        )
    operation_context = request_authority.get("operationContext")
    if not isinstance(operation_context, dict):
        raise ReleaseAuthorizationClientError(
            "credential request operation context is malformed"
        )
    recomputed = release_authorization_binding_digest(
        attempt_id=expected.attempt_id,
        flow_id=expected.flow_id,
        principal_id=expected.principal_id,
        route_id=expected.route_id,
        credential_ref=expected.credential_ref,
        credential_version=expected.credential_version,
        policy_hash=expected.policy_hash,
        request_digest=expected.request_digest,
        operation_digest=expected.operation_digest,
        operation_context=operation_context,
        shared_quotas=[
            strict_json_loads(binding)
            for binding in expected.shared_quota_bindings
        ],
        require_jit_grant=expected.require_jit_grant,
    )
    if not hmac.compare_digest(recomputed, expected.binding_digest):
        raise ReleaseAuthorizationClientError(
            "credential request authority operation was rebound"
        )

    release_authorization_fields = {
        "apiVersion",
        "kind",
        "state",
        "attemptId",
        "reservationId",
        "bindingDigest",
        "principalId",
        "routeId",
        "credentialId",
        "credentialVersion",
        "policyHash",
        "requestDigest",
        "operationDigest",
        "quotaClaims",
        "grantId",
        "approvalRequestId",
        "reservationExpiresAtEpochMs",
    }
    if release_authorization is None:
        kind = "decisionBound"
        grant_id = None
        approval_request_id = None
        quota_claims: list[dict[str, Any]] = []
    elif (
        not isinstance(release_authorization, dict)
        or frozenset(release_authorization)
        not in {
            frozenset(release_authorization_fields),
            frozenset(release_authorization_fields | {"durablePolicy"}),
        }
        or release_authorization.get("apiVersion")
        not in {
            "catchplate.credentialLeaseReleaseAuthorization/v1",
            "catchplate.credentialLeaseReleaseAuthorization/v2",
        }
        or release_authorization.get("state") != "reserved"
        or release_authorization.get("attemptId") != expected.attempt_id
        or release_authorization.get("reservationId")
        != request_authority["reservationId"]
        or release_authorization.get("bindingDigest") != expected.binding_digest
        or release_authorization.get("principalId") != expected.principal_id
        or release_authorization.get("routeId") != expected.route_id
        or release_authorization.get("credentialId") != credential_id
        or release_authorization.get("credentialVersion")
        != expected.credential_version
        or release_authorization.get("policyHash") != expected.policy_hash
        or release_authorization.get("requestDigest") != expected.request_digest
        or release_authorization.get("operationDigest")
        != expected.operation_digest
        or release_authorization.get("reservationExpiresAtEpochMs")
        != request_authority["reservationExpiresAtEpochMs"]
    ):
        raise ReleaseAuthorizationClientError(
            "release-controlled credential authority is malformed"
        )
    else:
        kind = release_authorization.get("kind")
        grant_id = release_authorization.get("grantId")
        approval_request_id = release_authorization.get("approvalRequestId")
        quota_claims = release_authorization.get("quotaClaims")
    durable_policy = (
        release_authorization.get("durablePolicy")
        if isinstance(release_authorization, dict)
        else None
    )
    if release_authorization is not None:
        release_v2 = (
            release_authorization.get("apiVersion")
            == "catchplate.credentialLeaseReleaseAuthorization/v2"
        )
        if release_v2 != (durable_policy is not None):
            raise ReleaseAuthorizationClientError(
                "credential release authority protocol was downgraded"
            )
    if kind == "jitGrant":
        if not (
            _valid_release_authorization_identity(grant_id)
            and _valid_release_authorization_identity(approval_request_id)
        ):
            raise ReleaseAuthorizationClientError(
                "JIT credential authority is incomplete"
            )
    elif kind == "atomicReservation":
        if (
            grant_id is not None
            or approval_request_id is not None
            or not isinstance(quota_claims, list)
            or (not quota_claims and durable_policy is None)
        ):
            raise ReleaseAuthorizationClientError(
                "atomic credential authority conflicts with JIT fields"
            )
    elif kind == "decisionBound":
        if (
            release_authorization is not None
            or expected.require_jit_grant
            or expected.shared_quota_bindings
            or quota_claims
        ):
            raise ReleaseAuthorizationClientError(
                "decision-bound credential authority carries release controls"
            )
    else:
        raise ReleaseAuthorizationClientError(
            "credential release authority kind is invalid"
        )
    claim_nonce = os.urandom(32)
    request_binding_sha256 = "sha256:" + hashlib.sha256(
        canonical_json(
            {
                "apiVersion": "catchplate.pythonCredentialClaim/v2",
                "requestAuthority": request_authority,
                "releaseAuthorization": release_authorization,
                "nonceSha256": hashlib.sha256(claim_nonce).hexdigest(),
            }
        ).encode("utf-8")
    ).hexdigest()
    recipient_key_id = "sha256:" + hashlib.sha256(
        b"catchplate-python-development-proxy"
    ).hexdigest()
    recipient_nonce_sha256 = "sha256:" + hashlib.sha256(claim_nonce).hexdigest()
    jit = jit_policy if isinstance(jit_policy, dict) else {}
    jit_authority = (
        db.jit_approver_policy_arguments(jit)
        if kind == "jitGrant"
        else {}
    )
    db.claim_release_credential_issuance(
        release_kind=str(kind),
        attempt_id=str(request_authority["attemptId"]),
        reservation_id=str(request_authority["reservationId"]),
        binding_digest=str(request_authority["bindingDigest"]),
        request_digest=str(request_authority["requestDigest"]),
        operation_digest=str(request_authority["operationDigest"]),
        operation_context=copy.deepcopy(operation_context),
        quota_claims=quota_claims,
        durable_policy=copy.deepcopy(durable_policy),
        request_binding_sha256=request_binding_sha256,
        request_authority_sha256=(
            "sha256:"
            + hashlib.sha256(
                canonical_json(request_authority).encode("utf-8")
            ).hexdigest()
        ),
        recipient_key_id=recipient_key_id,
        recipient_nonce_sha256=recipient_nonce_sha256,
        principal_id=expected.principal_id,
        route_id=expected.route_id,
        credential_id=credential_id,
        credential_version=expected.credential_version,
        policy_hash=expected.policy_hash,
        grant_id=grant_id,
        approval_request_id=approval_request_id,
        reservation_expires_at_epoch_ms=int(
            request_authority["reservationExpiresAtEpochMs"]
        ),
        actor_id=_release_authorization_actor_id(),
        required_approver_roles=jit_authority.get(
            "required_approver_roles", set()
        ),
        allowed_approver_ids=jit_authority.get(
            "allowed_approver_ids"
        ),
        require_approver_webauthn=bool(
            jit_authority.get(
                "require_approver_webauthn",
                False,
            )
        ),
        approval_threshold=int(
            jit_authority.get("approval_threshold", 1)
        ),
        approver_credential_policy=jit_authority.get(
            "approver_credential_policy"
        ),
    )


def get_credential(
    credential_id: str | None,
    *,
    request_authority: dict[str, Any] | None = None,
    release_authorization: dict[str, Any] | None = None,
    expected_release_identity: ReleaseAuthorizationExpectedIdentity | None = None,
    jit_policy: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    if not credential_id:
        return None
    controlled_context = (
        request_authority,
        release_authorization,
        expected_release_identity,
        jit_policy,
    )
    if any(value is not None for value in controlled_context):
        current = db.get_credential(credential_id, include_secret=False)
        if current is not None and (aws_credential_boundary.credential_selected(current)
                or github_app_boundary.credential_selected(current)
                or isinstance(current.get("metadata"), dict) and "operator_x_account" in current["metadata"]):
            invalidate_secret_leases(credential_id)
            return None
        if request_authority is None or expected_release_identity is None:
            raise ReleaseAuthorizationClientError(
                "controlled credential dispatch requires exact request authority"
            )
        _claim_release_controlled_credential(
            credential_id,
            request_authority,
            release_authorization,
            expected=expected_release_identity,
            jit_policy=jit_policy,
        )
        start_runtime_workers()
        _inc("credential_lease_misses")
        credential = db.get_credential(credential_id, include_secret=True)
        if not credential:
            return None
        return _project_credential_for_data_plane(credential)
    current = db.get_credential(credential_id)
    if (not current or aws_credential_boundary.credential_selected(current)
            or github_app_boundary.credential_selected(current)
            or isinstance(current.get("metadata"), dict) and "operator_x_account" in current["metadata"]):
        invalidate_secret_leases(credential_id)
        _inc("credential_lease_misses")
        return None

    start_runtime_workers()

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
            if (github_app_boundary.credential_selected(cached[1])
                    or isinstance(cached[1].get("metadata"), dict) and "operator_x_account" in cached[1]["metadata"]):
                for key in [key for key in _credential_cache if key[0] == credential_id]:
                    _credential_cache.pop(key, None)
                return None
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


def get_bound_credential_lease(
    credential_id: str | None,
    *,
    request_authority: dict[str, Any] | None = None,
    release_authorization: dict[str, Any] | None = None,
    expected_release_identity: ReleaseAuthorizationExpectedIdentity | None = None,
    jit_policy: dict[str, Any] | None = None,
) -> BoundCredentialLease | None:
    if (
        request_authority is None
        and release_authorization is None
        and expected_release_identity is None
        and jit_policy is None
    ):
        credential = get_credential(credential_id)
    else:
        credential = get_credential(
            credential_id,
            request_authority=request_authority,
            release_authorization=release_authorization,
            expected_release_identity=expected_release_identity,
            jit_policy=jit_policy,
        )
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
    if request_authority is not None:
        remaining_seconds = (
            int(request_authority["reservationExpiresAtEpochMs"])
            - int(time.time() * 1000)
        ) / 1000
        if remaining_seconds <= 0:
            return None
        return BoundCredentialLease(
            credential=copy.deepcopy(credential),
            binding=CredentialLeaseBinding(
                credential_id=credential_id,
                credential_version=credential_version,
                secret_fingerprint=fingerprint,
                expires_at_monotonic=now
                + min(float(SECRET_LEASE_TTL_SECONDS), remaining_seconds),
            ),
        )
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
    db.reconcile_policy_state_bundles(limit=32)
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
