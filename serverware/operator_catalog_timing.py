"""Bounded observations of admitted operator-development catalog mutations.

The caller owns profile, administrator, Origin and input admission. It creates
only for the operator-development profile and activates after those existing
checks. A request-scope owner may bind the same tracker through normal worker
context propagation; this module manages no worker, lock ownership or deadline.

Records describe observed stages and response outcome, not rollback, durable
commit proof, client acknowledgement or provider success. Missing marks are
absent, not inferred work. Contention, the process cap and diagnostic failures
drop observations. The bounded stderr write is synchronous, not a nonblocking
transport, and absence of a record proves nothing about completion or latency.

Already admitted application revocations also emit a separately capped subset
of first marks. These are progress observations, never completion claims. A
mark sampled before terminal sealing can race terminal output; record order is
not an authority or acknowledgement ordering guarantee.
"""

from contextlib import contextmanager
from contextvars import ContextVar
import json
import sys
import threading
import time


_SCHEMA = "serverware.operatorCatalogTiming/v1"
_PROGRESS_SCHEMA = "serverware.operatorCatalogProgress/v1"
_PROGRESS_LABELS = frozenset({
    "mutation_queued", "mutation_slot", "mutation_worker",
    "publication_wait", "publication_acquired", "sqlite_open", "sqlite_begin",
    "commit_started", "commit_done",
})
_OPERATIONS = frozenset({
    "create_credential", "revoke_credential", "create_github_credential",
    "replace_credential_key", "create_npm_credential", "create_application",
    "revoke_application", "rotate_application_token",
    "set_application_proxy_authentication", "create_rule", "revoke_rule",
    "create_gmail_rule", "create_github_rule", "create_npm_rule",
    "create_npm_publish_rule", "create_x_credential", "create_x_rule",
    "create_alchemy_credential", "create_alchemy_rule",
})
_LABELS = frozenset({
    "api_admitted", "payload_validated",
    "mutation_queued", "mutation_slot", "mutation_worker", "mutation_done",
    "publication_wait", "publication_acquired", "sqlite_open", "sqlite_begin",
    "bindings_validated", "change_done", "policy_published", "audit_appended",
    "commit_started", "commit_done", "materialize_started", "materialize_done",
    "publication_released", "receipt_ready",
    "outbox_queued", "outbox_slot", "outbox_worker", "outbox_done",
    "response_ready", "response_sent",
})
_OUTCOMES = frozenset({"complete", "failed", "cancelled"})
_LIMIT = 64
_PROGRESS_LIMIT = 64
_MAX_LINE_BYTES = 4096
_PROGRESS_MAX_LINE_BYTES = 512
_MAX_MS = (1 << 63) - 1
_limit_lock = threading.Lock()
_count = 0
_progress_limit_lock = threading.Lock()
_progress_count = 0
_clock_ns = time.monotonic_ns
_current = ContextVar("serverware.operator_catalog_timing", default=None)


def _write_record(line: str) -> None:
    sys.stderr.write(line)


def _reserve() -> int | None:
    global _count
    if not _limit_lock.acquire(blocking=False):
        return None
    try:
        if _count >= _LIMIT:
            return None
        _count += 1
        return _count
    finally:
        _limit_lock.release()


def _reserve_progress() -> int | None:
    global _progress_count
    if not _progress_limit_lock.acquire(blocking=False):
        return None
    try:
        if _progress_count >= _PROGRESS_LIMIT:
            return None
        _progress_count += 1
        return _progress_count
    finally:
        _progress_limit_lock.release()


class CatalogTiming:
    """One request's fixed marks; a terminal attempt permanently seals it."""

    __slots__ = ("_operation", "_started", "_marks", "_active", "_terminal", "_lock")

    def __init__(self, operation: str, *, operator_development: bool) -> None:
        if (operator_development is not True or type(operation) is not str
                or len(operation) > 64 or operation not in _OPERATIONS):
            raise ValueError("operator catalog timing input unavailable")
        self._operation = operation
        self._started = _clock_ns()
        self._marks: dict[str, int] = {}
        self._active = False
        # One-way, nonblocking latch: cancellation cannot later be upgraded by
        # a still-running worker, even when collecting the record is contended.
        self._terminal = threading.Lock()
        self._lock = threading.Lock()

    def _elapsed(self) -> int:
        return min(_MAX_MS, max(0, (_clock_ns() - self._started) // 1_000_000))

    def mark(self, label: str) -> None:
        try:
            if type(label) is not str or len(label) > 64 or label not in _LABELS:
                return
            progress = None
            if not self._lock.acquire(blocking=False):
                return
            try:
                if not self._terminal.locked() and label not in self._marks:
                    elapsed = self._elapsed()
                    self._marks[label] = elapsed
                    if (self._active and self._operation == "revoke_application"
                            and label in _PROGRESS_LABELS):
                        progress = {
                            "schema": _PROGRESS_SCHEMA,
                            "operation": "revoke_application",
                            "stage": label,
                            "elapsed_ms": elapsed,
                        }
            finally:
                self._lock.release()
            # Never hold collection or reservation locks across the sink. A
            # concurrent finish can still seal after this best-effort recheck;
            # no additional synchronization may delay or reopen cancellation.
            if progress is not None and not self._terminal.locked():
                ordinal = _reserve_progress()
                if ordinal is not None:
                    progress["ordinal"] = ordinal
                    line = json.dumps(progress, ensure_ascii=True, sort_keys=True,
                                      separators=(",", ":")) + "\n"
                    if len(line) <= _PROGRESS_MAX_LINE_BYTES:
                        _write_record(line)
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
            if type(outcome) is not str or len(outcome) > 16 or outcome not in _OUTCOMES:
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
                    "operation": self._operation,
                    "outcome": outcome,
                    "elapsed_ms": self._elapsed(),
                    "marks": dict(self._marks),
                }
            finally:
                self._lock.release()
            ordinal = _reserve()
            if ordinal is None:
                return
            record["ordinal"] = ordinal
            line = json.dumps(record, ensure_ascii=True, sort_keys=True,
                              separators=(",", ":")) + "\n"
            if len(line) <= _MAX_LINE_BYTES:  # ensure_ascii makes bytes == characters.
                _write_record(line)
        except Exception:
            pass


def create(operation: str, *, operator_development: bool) -> CatalogTiming | None:
    try:
        return CatalogTiming(operation, operator_development=operator_development)
    except Exception:
        return None


def mark(tracker: CatalogTiming | None, label: str) -> None:
    if type(tracker) is CatalogTiming:
        tracker.mark(label)


def activate(tracker: CatalogTiming | None) -> None:
    if type(tracker) is CatalogTiming:
        tracker.activate()


def finish(tracker: CatalogTiming | None, outcome: str) -> None:
    if type(tracker) is CatalogTiming:
        tracker.finish(outcome)


def current() -> CatalogTiming | None:
    try:
        tracker = _current.get()
        return tracker if type(tracker) is CatalogTiming else None
    except Exception:
        return None


@contextmanager
def bind(tracker: CatalogTiming | None):
    """Propagate observations only; never suppress the bound operation's error."""
    token = None
    try:
        token = _current.set(tracker if type(tracker) is CatalogTiming else None)
    except Exception:
        pass
    try:
        yield
    finally:
        if token is not None:
            try:
                _current.reset(token)
            except Exception:
                pass
