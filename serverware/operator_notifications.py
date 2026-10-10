"""Optional operator-development notification worker and public service view.

The store owns admission, custody and durable attempts. This module only joins
that owner to the typed source reader and bounded transport. Importing it never
starts a thread, initializes storage or sends a notification. Native ceremonies
are not notification sources here and cannot be started or approved here.
"""
from __future__ import annotations

import os
import threading
import time
from urllib.parse import urlsplit


_INTERVAL_SECONDS = 2.0
_POLICY_ENV = "SERVERWARE_OPERATOR_NOTIFICATIONS_PRIVATE_DESTINATIONS_JSON"
_LOCK = threading.Lock()
_STOP = threading.Event()
_THREAD: threading.Thread | None = None
_PID: int | None = None
_LAST_CYCLE: int | None = None
_LAST_CODE: str | None = None


def _now() -> int:
    return time.time_ns() // 1_000_000


def _egress_policy():
    from serverware import operator_notification_transport as transport

    return transport.parse_egress_policy(os.environ.get(_POLICY_ENV, '{"bindings":[]}'))


def _outbound_payload(claim) -> dict:
    """Attach transport metadata to a store-owned, already-safe projection."""
    from serverware import config

    origin = config.PUBLIC_URL
    parsed = urlsplit(origin)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.path not in {"", "/"}
            or parsed.query or parsed.fragment):
        raise ValueError("notification console origin unavailable")
    if type(claim.payload) is not dict:
        raise ValueError("notification projection unavailable")
    payload = dict(claim.payload)
    if (payload.get("schema") != "serverware.operatorNotification/v1"
            or payload.get("channel") != claim.channel
            or type(payload.get("summary")) is not str
            or not 1 <= len(payload["summary"]) <= 1000
            or payload.get("review_path") != "/#audit"):
        raise ValueError("notification projection unavailable")
    review_url = origin.rstrip("/") + payload["review_path"]
    if len(review_url) > 1024:
        raise ValueError("notification console origin unavailable")
    payload.update(delivery_id=claim.delivery_id, slot=claim.slot,
        revision=claim.revision, review_url=review_url)
    return payload


def run_once() -> bool:
    """Consume committed sources, then attempt at most one saved delivery.

    Marking a claim and recording its result are separate short transactions.
    Neither the publication lock nor a database transaction crosses network I/O.
    A post-claim unexpected error is recorded as uncertain, never replayed.
    """
    global _LAST_CODE
    from serverware import operator_notification_store as store
    from serverware import operator_notification_transport as transport

    if not store.enabled():
        return False
    policy = _egress_policy()
    with _LOCK:
        _LAST_CODE = "ready"
    try:
        store.consume_events(_now())
    except store.NotificationConflict:
        # A full queue retains its source cursor. Continue draining it, or
        # backpressure would permanently prevent the work that frees capacity.
        # Schema, custody and source-integrity failures are not conflicts and
        # deliberately still stop this cycle before any network attempt.
        with _LOCK:
            _LAST_CODE = "notification_source_backlog"
    claim = store.claim_next(_now())
    if claim is None:
        return False
    # current() also durably suppresses a disabled, replaced, resolved or
    # expired exact claim. Inspection cannot renew its original source clock.
    if not store.current(claim, _now()):
        return True
    if (claim.channel == "action_required" and store.ACTION_SOURCE_AVAILABLE is not True
            and claim.payload.get("test") is not True):
        # current() normally retains a suppressed receipt first. Even a future
        # store regression cannot turn this disconnected source into delivery.
        raise RuntimeError("notification action source unavailable")
    try:
        payload = _outbound_payload(claim)
    except Exception:
        result = transport.DeliveryResult("failed", "transport_unavailable")
    else:
        try:
            result = transport.deliver(claim.adapter, claim.url, payload, policy,
                before_dispatch=lambda: store.current(claim, _now()))
        except Exception:
            # Do not stringify an exception: it may contain a destination URL.
            result = transport.DeliveryResult("outcome_unknown", "delivery_unknown")
    store.finish(claim, result, _now())
    return True


def _worker() -> None:
    global _LAST_CYCLE, _LAST_CODE

    while not _STOP.is_set():
        try:
            run_once()
        except Exception:
            with _LOCK:
                _LAST_CODE = "notification_worker_unavailable"
        with _LOCK:
            _LAST_CYCLE = _now()
        _STOP.wait(_INTERVAL_SECONDS)


def start_worker() -> bool:
    """Called only after the ordinary app's existing startup owners admit it."""
    global _THREAD, _PID
    from serverware import operator_notification_store as store

    if not store.enabled():
        return False
    with _LOCK:
        if _PID is not None and _PID != os.getpid():
            raise RuntimeError("notification worker process changed")
        if _THREAD is not None and _THREAD.is_alive():
            if _STOP.is_set():
                raise RuntimeError("notification worker is draining")
            return True
        if _THREAD is not None and not _STOP.is_set():
            raise RuntimeError("notification worker unavailable")
        _PID = os.getpid()
        _STOP.clear()
        _THREAD = threading.Thread(target=_worker, name="operator-notifications", daemon=True)
        _THREAD.start()
    return True


def stop_worker() -> None:
    """Stop scheduling; an already-started bounded attempt keeps its receipt."""
    with _LOCK:
        _STOP.set()
        thread = _THREAD
    if thread is not None and thread is not threading.current_thread():
        thread.join(timeout=2.0)


def status() -> dict:
    from serverware import operator_notification_events as events
    from serverware import operator_notification_store as store

    value = store.status()
    available = value.get("available") is True
    value["capabilities"] = {
        "audit_log": {"source_available": available,
            "event_types": list(events.AUDIT_EVENT_TYPES)},
        "action_required": {"source_available": available and store.ACTION_SOURCE_AVAILABLE is True,
            "event_types": list(events.ACTION_EVENT_TYPES)},
        "native_hardware": {"source_available": False},
        "source_note": "Native security-key action notifications are not connected in this deployment.",
        "test_note": "A synthetic delivery test does not establish hardware readiness or approval.",
    }
    if not available:
        value["disabled_reason"] = "deployment_disabled"
    with _LOCK:
        running = _PID == os.getpid() and _THREAD is not None and _THREAD.is_alive()
        value["worker"] = {"state": "disabled" if not available else
            "unavailable" if _LAST_CODE == "notification_worker_unavailable" else
            "running" if running else "not_started",
            "last_cycle_at_epoch_ms": _LAST_CYCLE, "last_code": _LAST_CODE}
    return value
