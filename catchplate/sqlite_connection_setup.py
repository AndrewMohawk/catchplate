"""Fresh SQLite metadata handles with bounded, process-local setup concurrency.

Only connection initialization is serialized. No handle, journal-mode result,
schema or authority state is cached, and no query/transaction after return holds
the setup gate. SQLite's busy timeout bounds lock waits, not arbitrary CPU or
filesystem stalls; every setup step also refuses a result past its deadline.
"""
from __future__ import annotations

import contextlib
import os
import sqlite3
import threading
import time

from catchplate.authority_store import metadata_schema
from catchplate import operator_google_cleanup_store


_SETUP_TIMEOUT_NS = 10_000_000_000
_NORMAL_BUSY_TIMEOUT_MS = 10_000
_SETUP_LOCK = threading.RLock()
_SETUP_STATE = threading.local()


def _after_fork_child() -> None:
    global _SETUP_LOCK, _SETUP_STATE
    # A child must not inherit another thread's acquired gate or setup window.
    # This does not make inherited SQLite connections safe to use after fork.
    _SETUP_LOCK = threading.RLock()
    _SETUP_STATE = threading.local()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_child)


def _remaining_ns(deadline_ns: int) -> int:
    remaining = deadline_ns - time.monotonic_ns()
    if remaining <= 0:
        raise sqlite3.OperationalError("SQLite metadata connection setup timed out")
    return remaining


def _setup_statement(conn: sqlite3.Connection, statement: str, deadline_ns: int) -> None:
    # Integer truncation cannot give SQLite more busy waiting than remains.
    remaining_ms = _remaining_ns(deadline_ns) // 1_000_000
    conn.execute(f"PRAGMA busy_timeout={remaining_ms}").close()
    _remaining_ns(deadline_ns)
    conn.execute(statement).close()
    _remaining_ns(deadline_ns)


def open_metadata_connection(path: str | os.PathLike[str]) -> sqlite3.Connection:
    previous_deadline = getattr(_SETUP_STATE, "deadline_ns", None)
    deadline = time.monotonic_ns() + _SETUP_TIMEOUT_NS
    if previous_deadline is not None:
        deadline = min(deadline, previous_deadline)
    gate = _SETUP_LOCK
    if not gate.acquire(timeout=_remaining_ns(deadline) / 1_000_000_000):
        raise sqlite3.OperationalError("SQLite metadata connection setup timed out")
    conn = None
    _SETUP_STATE.deadline_ns = deadline
    try:
        conn = sqlite3.connect(path, timeout=_remaining_ns(deadline) / 1_000_000_000)
        metadata_schema.configure_sqlite_metadata_connection(conn)
        operator_google_cleanup_store.configure_connection(conn)
        conn.row_factory = sqlite3.Row
        _setup_statement(conn, "PRAGMA journal_mode=WAL", deadline)
        _setup_statement(conn, "PRAGMA foreign_keys=ON", deadline)
        # Later caller-owned transactions retain the existing 10-second busy
        # timeout; waiting for this gate did not add another setup allowance.
        conn.execute(f"PRAGMA busy_timeout={_NORMAL_BUSY_TIMEOUT_MS}").close()
        _remaining_ns(deadline)
        return conn
    except BaseException:
        if conn is not None:
            with contextlib.suppress(BaseException):
                conn.close()
        raise
    finally:
        _SETUP_STATE.deadline_ns = previous_deadline
        gate.release()
