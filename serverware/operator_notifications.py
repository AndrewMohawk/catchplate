"""Optional operator-development notification worker and public service view.

The store owns admission, custody and durable attempts. This module only joins
that owner to the typed source reader and bounded transport. Importing it never
starts a thread, initializes storage or sends a notification. An optional strict
Unix observer can report a native owner's already-published phase. Observation
cannot start, prepare, approve or extend that owner's ceremony.
"""
from __future__ import annotations

import os
import threading
import time
from urllib.parse import urlsplit


_INTERVAL_SECONDS = 2.0
_POLICY_ENV = "SERVERWARE_OPERATOR_NOTIFICATIONS_PRIVATE_DESTINATIONS_JSON"
_PILOT_ENV = "SERVERWARE_OPERATOR_NOTIFICATIONS_PILOT_SOURCE_JSON"
_OBSERVATION_DISPLAY_MS = 15_000
_LOCK = threading.Lock()
_STOP = threading.Event()
_THREAD: threading.Thread | None = None
_PID: int | None = None
_LAST_CYCLE: int | None = None
_LAST_CODE: str | None = None
_LAST_PILOT_OBSERVATION: dict | None = None
_PILOT_UNSET = object()
_PILOT_REFUSED = object()
_PILOT_CONFIGURATION = _PILOT_UNSET


def _now() -> int:
    return time.time_ns() // 1_000_000


def _egress_policy():
    from serverware import operator_notification_transport as transport

    return transport.parse_egress_policy(os.environ.get(_POLICY_ENV, '{"bindings":[]}'))


def _pilot_configuration():
    """Read only after ordinary operator admission pins the complete environment.

    The strict client owns this one cold source grammar. No default socket,
    source discovery or adoption of another native attempt is provided here.
    """
    global _PILOT_CONFIGURATION
    from serverware import operator_notification_pilot_source as source

    with _LOCK:
        if _PILOT_CONFIGURATION is _PILOT_UNSET:
            raw = os.environ.get(_PILOT_ENV)
            try:
                _PILOT_CONFIGURATION = None if raw is None else source.admit_config(raw)
            except source.SourceError:
                _PILOT_CONFIGURATION = _PILOT_REFUSED
                raise
        if _PILOT_CONFIGURATION is _PILOT_REFUSED:
            raise source.SourceError("native notification source unavailable")
        # Admission pins the first directory/socket identities. Re-admission
        # would silently adopt replacement files, even with unchanged JSON.
        return _PILOT_CONFIGURATION


def _remember_pilot(summary: dict) -> None:
    global _LAST_PILOT_OBSERVATION

    with _LOCK:
        _LAST_PILOT_OBSERVATION = dict(summary, observed_at_epoch_ms=_now())


def _pilot_unavailable() -> None:
    _remember_pilot({"state": "unavailable", "observer_available": False,
        "action_available": False, "phase": None,
        "source_expires_at_unix_nanos": None, "review_url": None})


def _poll_pilot():
    """Bounded observation only; no store/publication transaction may surround it."""
    from serverware import operator_notification_pilot_source as source

    try:
        selected = _pilot_configuration()
        if selected is None:
            return None
        observation = source.read_observation(selected)
        summary = source.observation_summary(selected, observation)
        notice = source.observation_notice(selected, observation)
    except source.SourceError:
        _pilot_unavailable()
        return None
    _remember_pilot(summary)
    return notice


def _pilot_status(available: bool) -> dict:
    """Describe configuration and the last read, never poll or assert readiness."""
    configured = available and bool(os.environ.get(_PILOT_ENV))
    empty = {"state": "not_observed" if configured else "not_configured",
        "observed_at_epoch_ms": None, "phase": None, "action_available": False,
        "source_expires_at_unix_nanos": None, "review_url": None}
    with _LOCK:
        retained = None if _LAST_PILOT_OBSERVATION is None else dict(_LAST_PILOT_OBSERVATION)
        malformed = _PILOT_CONFIGURATION is _PILOT_REFUSED
    if not configured or retained is None:
        observation, observer_available = empty, False
    else:
        observer_available = retained.pop("observer_available") is True and not malformed
        observation = retained
        # This is conservative presentation only. The actual dispatch performs
        # a new owner read and compares exact original nanosecond deadlines.
        age = _now() - observation["observed_at_epoch_ms"]
        expiry = observation["source_expires_at_unix_nanos"]
        if (malformed or age < 0 or age >= _OBSERVATION_DISPLAY_MS
                or expiry is None or time.time_ns() >= int(expiry)):
            observation["action_available"] = False
    return {"configured": configured, "source_available": observer_available,
        "observation_only": True, "last_observation": observation}


def _outbound_payload(claim) -> dict:
    """Attach transport metadata to a store-owned, already-safe projection."""
    from serverware import config, operator_notification_store as store

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
            or not 1 <= len(payload["summary"]) <= 1000):
        raise ValueError("notification projection unavailable")
    if store.is_native_action(claim):
        from serverware import operator_notification_pilot_source as source

        selected = _pilot_configuration()
        if selected is None:
            raise ValueError("notification native source unavailable")
        review_url = source.review_url(selected, payload)
    else:
        if payload.get("review_path") != "/#audit":
            raise ValueError("notification projection unavailable")
        review_url = origin.rstrip("/") + payload["review_path"]
    if len(review_url) > 1024:
        raise ValueError("notification console origin unavailable")
    payload.update(delivery_id=claim.delivery_id, slot=claim.slot,
        revision=claim.revision, review_url=review_url)
    return payload


def _before_dispatch(claim) -> bool:
    """Fresh source, then saved claim, then original expiry; no lock across I/O."""
    from serverware import operator_notification_store as store

    native = store.is_native_action(claim)
    if native:
        from serverware import operator_notification_pilot_source as source

        try:
            selected = _pilot_configuration()
            source_current = selected is not None and source.payload_is_current(selected, claim.payload)
        except source.SourceError:
            source_current = False
        if not source_current:
            _pilot_unavailable()
            store.suppress_native_claim(claim, _now())
            return False
    if not store.current(claim, _now()):
        return False
    # The source read or store recheck may consume the remainder of the native
    # window. Never round it to milliseconds or rely on a pre-read timestamp.
    if native and not source.payload_is_unexpired(claim.payload):
        store.suppress_native_claim(claim, _now())
        return False
    return True


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
    notice = _poll_pilot()
    if notice is not None:
        # The observer socket has closed before entering this mutation. A
        # durable source event survives a crash before the ordinary consumer.
        store.record_native_observation(notice, _now())
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
            and claim.payload.get("test") is not True and not store.is_native_action(claim)):
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
                before_dispatch=lambda: _before_dispatch(claim))
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
    native = _pilot_status(available)
    value["capabilities"] = {
        "audit_log": {"source_available": available,
            "event_types": list(events.AUDIT_EVENT_TYPES)},
        "action_required": {"source_available": available and (
            store.ACTION_SOURCE_AVAILABLE is True or native["source_available"]),
            "event_types": list(events.ACTION_EVENT_TYPES)},
        "native_hardware": native,
        "source_note": "Native source availability describes the last observer read, not live hardware readiness. "
            "Only a fresh exact owner observation can admit an action notification.",
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
