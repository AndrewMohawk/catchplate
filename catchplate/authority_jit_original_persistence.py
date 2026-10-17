"""Fixed native writer ownership for raw JIT originals.

The endpoint is inert and accepts no SQL or caller-selected operation. The
actual writer owner performs PostgreSQL/TLS/role/catalog admission and outer
SERIALIZABLE transaction closure; the actual store retains immutable bytes.
Only normal closure inside the original deadline can return. Failure after
commit is not rollback proof. No retry, authority verdict or new allowance is
created. Source table/ACL registration does not establish native deployment or
close the measured producer/service and independent current-root authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import threading
import time

from catchplate import authority_revocation_root_reader as reader
from catchplate import authority_revocation_writer_connection as writer
from catchplate.authority_query_read_work import _ValidationWork
from catchplate.authority_store import jit_original_pages as store


class JitOriginalPersistenceError(ValueError):
    pass


def _require(value):
    if not value:
        raise JitOriginalPersistenceError("JIT original writer lost its fixed custody")


def _configuration(values):
    _require(type(values) is tuple and len(values) == 3)
    dsn, timeout, identity = values
    reader._bounded_text(dsn, 65536)
    _require("\n" not in dsn and "\r" not in dsn
        and type(timeout) is int and 2 <= timeout <= 300)
    writer._validate_database_identity(identity)
    return values


def _snapshot(owner):
    _require(type(owner) is JitOriginalPersistence)
    return _configuration(owner._configured)


def _inputs(*, context, body_bytes, descriptor, persist, original_deadline_ns, work):
    _require(type(work) is _ValidationWork and type(persist) is bool
        and type(original_deadline_ns) is int and 0 < original_deadline_ns < 2**63)
    owned = store._context(context, work)
    if not persist:
        _require(body_bytes is None and descriptor is None)
        return owned, None
    _require(type(descriptor) is dict and len(descriptor) == 2
        and all(type(name) is str for name in descriptor)
        and set(descriptor) == {"digest", "byteCount"})
    # The exact scalar binding is held before any native/check callback; the
    # source store recomputes the hash, never trusting the claimed descriptor.
    work.charge(input_bytes=2048, json_nodes=32)
    binding = store._binding({**owned, "body_digest": descriptor["digest"],
        "body_byte_count": descriptor["byteCount"]}, work)
    return binding, store._body(body_bytes, binding, work)


def _guard(owner, configured, *, original_deadline_ns, check, work):
    _require(type(work) is _ValidationWork and callable(check)
        and type(original_deadline_ns) is int and 0 < original_deadline_ns < 2**63)
    reader.roots.batch._SharedLedger(work)
    limits = work.limits
    bounds = limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes
    identity = os.getpid(), threading.get_ident()
    previous = work.hash_work, work.input_bytes, work.json_nodes
    last_time = 0
    busy = False

    def local():
        nonlocal previous, last_time
        _require(owner._configured is configured and owner._active is True
            and owner._failed is False and identity == (os.getpid(), threading.get_ident())
            and work.limits is limits
            and (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes) == bounds)
        current = work.hash_work, work.input_bytes, work.json_nodes
        _require(all(type(value) is int and before <= value <= maximum
            for value, before, maximum in zip(current, previous, bounds, strict=True)))
        now = store.lifecycle._guard(work, time.monotonic_ns)
        _require(type(now) is int and last_time <= now < original_deadline_ns)
        previous, last_time = current, now

    def guarded():
        nonlocal busy
        try:
            local()
            _require(not busy)
            busy = True
            _require(store.lifecycle._guard(work, check) is None)
            local()
        except BaseException:
            object.__setattr__(owner, "_failed", True)
            raise
        finally:
            busy = False

    return guarded


def _connect(configured, *, check, work, psycopg, dict_row):
    connection = None

    def open_connection():
        nonlocal connection
        connection = psycopg.connect(configured[0], row_factory=dict_row,
            connect_timeout=configured[1], autocommit=False, options="-c search_path=pg_catalog")
        return connection

    try:
        check()
        result = store.lifecycle._guard(work, open_connection)
        check()
        return result
    except BaseException:
        if connection is not None:
            reader._close_after_failure(connection)
        raise


def _run(configured, owned, body, *, persist, original_deadline_ns, check, work):
    # Import and preserve the real facade's independent source registry gate.
    from catchplate import db
    import psycopg
    from psycopg.rows import dict_row

    _require(configured[2][0] == db._METADATA_STORE_AUTHORITY_PLANNER_WRITER_ROLE)
    check()

    def operation(*, connection, work):
        check()
        if persist:
            result = store.persist_page(binding=owned, body_bytes=body, connection=connection,
                original_deadline_ns=original_deadline_ns, check=check, work=work)
            _require(type(result) is bytes and len(result) == len(body))
            work.charge(input_bytes=len(result) + len(body))
            _require(result == body)
            result = None
        else:
            result = store.read_original(context=owned, connection=connection,
                original_deadline_ns=original_deadline_ns, check=check, work=work)
            _require(type(result) is bytes and 2 <= len(result) <= store.MAX_BODY_BYTES)
        check()
        return result

    connection = _connect(configured, check=check, work=work, psycopg=psycopg, dict_row=dict_row)
    try:
        result = writer._run_on_connection(connection, database_identity=configured[2],
            work=work, operation=operation, arguments={}, expectations={})
        # The source writer returns only after normal transaction/cursor/actual
        # connection closure. This final check cannot undo a committed write.
        check()
        return result
    except BaseException:
        reader._close_after_failure(connection)
        raise


def _invoke(owner, *, context, body_bytes, descriptor, persist, original_deadline_ns, check, work):
    configured = _snapshot(owner)
    if owner._active is not False or owner._failed is not False:
        object.__setattr__(owner, "_failed", True)
        _require(False)
    object.__setattr__(owner, "_active", True)
    try:
        owned, body = _inputs(context=context, body_bytes=body_bytes, descriptor=descriptor,
            persist=persist, original_deadline_ns=original_deadline_ns, work=work)
        guard = _guard(owner, configured, original_deadline_ns=original_deadline_ns,
            check=check, work=work)
        guard()
        return _run(configured, owned, body, persist=persist,
            original_deadline_ns=original_deadline_ns, check=guard, work=work)
    except BaseException:
        object.__setattr__(owner, "_failed", True)
        raise
    finally:
        object.__setattr__(owner, "_active", False)


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class JitOriginalPersistence:
    """One inert fixed writer endpoint, poisoned after any failed use."""

    _configured: tuple
    _active: bool
    _failed: bool

    def __init__(self, *, writer_dsn, connect_timeout_seconds, database_identity):
        object.__setattr__(self, "_configured", _configuration(
            (writer_dsn, connect_timeout_seconds, database_identity)))
        object.__setattr__(self, "_active", False)
        object.__setattr__(self, "_failed", False)

    def persist(self, *, context, body_bytes, descriptor, original_deadline_ns, check, work):
        return _invoke(self, context=context, body_bytes=body_bytes, descriptor=descriptor,
            persist=True, original_deadline_ns=original_deadline_ns, check=check, work=work)

    def read(self, *, context, original_deadline_ns, check, work):
        return _invoke(self, context=context, body_bytes=None, descriptor=None,
            persist=False, original_deadline_ns=original_deadline_ns, check=check, work=work)
