"""Closed observations of admitted operator audit requests, never authority.

The caller owns route/profile admission and activates only after existing token
and batch validation. Marks before activation remain private. Contended locks,
invalid inputs and diagnostic failures drop observations; absence proves nothing
about request completion or latency. The stderr sink is synchronous, not a
nonblocking transport. No worker or request lifetime is managed here.
"""

import json
import re
import sys
import threading
import time


_SCHEMA = "serverware.operatorAuditTiming/v1"
_LABELS = frozenset({
    "audit_queued", "audit_slot", "audit_worker", "audit_admitted", "audit_done",
    "outbox_queued", "outbox_slot", "outbox_worker", "outbox_done",
    "sign_queued", "sign_slot", "sign_worker", "sign_policy_done",
    "sign_manifest_done", "sign_artifacts_done", "sign_statement_done", "sign_crypto_done",
    "response_ready", "response_sent",
})
_OUTCOMES = frozenset({"complete", "failed", "cancelled"})
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_LIMIT = 64
_MAX_MS = (1 << 63) - 1
_limit_lock = threading.Lock()
_count = 0
_clock_ns = time.monotonic_ns


def _write_record(line: str) -> None:
    sys.stderr.write(line)


def _reserve() -> bool:
    global _count
    if not _limit_lock.acquire(blocking=False):
        return False
    try:
        if _count >= _LIMIT:
            return False
        _count += 1
        return True
    finally:
        _limit_lock.release()


class AuditTiming:
    """One request's bounded marks; finish closes it even when output fails."""

    __slots__ = ("_event_count", "_batch_digest", "_started", "_marks",
                 "_active", "_terminal", "_lock")

    def __init__(self, event_count: int, batch_digest: str) -> None:
        if (type(event_count) is not int or not 1 <= event_count <= 200
                or type(batch_digest) is not str or _DIGEST.fullmatch(batch_digest) is None):
            raise ValueError("operator audit timing input unavailable")
        self._event_count = event_count
        self._batch_digest = batch_digest
        self._started = _clock_ns()
        self._marks: dict[str, int] = {}
        self._active = False
        # A one-way latch, acquired without waiting and deliberately never
        # released. A contended mark lock must not allow a later finish to
        # replace a cancelled terminal observation with completion.
        self._terminal = threading.Lock()
        self._lock = threading.Lock()

    def _elapsed(self) -> int:
        return min(_MAX_MS, max(0, (_clock_ns() - self._started) // 1_000_000))

    def mark(self, label: str) -> None:
        try:
            if type(label) is not str or label not in _LABELS:
                return
            if not self._lock.acquire(blocking=False):
                return
            try:
                if not self._terminal.locked() and label not in self._marks:
                    self._marks[label] = self._elapsed()
            finally:
                self._lock.release()
        except Exception:
            pass

    def activate(self) -> None:
        try:
            if not self._lock.acquire(blocking=False):
                return
            try:
                if not self._terminal.locked():
                    self._active = True
            finally:
                self._lock.release()
        except Exception:
            pass

    def finish(self, outcome: str) -> None:
        try:
            if type(outcome) is not str or outcome not in _OUTCOMES:
                return
            if not self._terminal.acquire(blocking=False):
                return
            if not self._lock.acquire(blocking=False):
                return
            try:
                if not self._active:
                    return
                record = {
                    "schema": _SCHEMA,
                    "event_count": self._event_count,
                    "batch_digest": self._batch_digest,
                    "outcome": outcome,
                    "elapsed_ms": self._elapsed(),
                    "marks": dict(self._marks),
                }
            finally:
                self._lock.release()
            if _reserve():
                _write_record(json.dumps(record, ensure_ascii=True, sort_keys=True,
                                         separators=(",", ":")) + "\n")
        except Exception:
            pass


def create(event_count: int, batch_digest: str) -> AuditTiming | None:
    try:
        return AuditTiming(event_count, batch_digest)
    except Exception:
        return None


def mark(tracker: AuditTiming | None, label: str) -> None:
    if type(tracker) is AuditTiming:
        tracker.mark(label)


def activate(tracker: AuditTiming | None) -> None:
    if type(tracker) is AuditTiming:
        tracker.activate()


def finish(tracker: AuditTiming | None, outcome: str) -> None:
    if type(tracker) is AuditTiming:
        tracker.finish(outcome)
