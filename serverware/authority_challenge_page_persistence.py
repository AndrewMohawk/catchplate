"""Native writer ownership for independently admitted maintenance-page custody.

This inert endpoint owner does not authenticate a control, enroll a parent or
accept a proof verdict. Its only operations call the real immutable page
binding through the existing PostgreSQL 16/SERIALIZABLE/TLS/ACL writer owner.
Results escape only after normal outer transaction exit and actual connection
closure, still inside the original absolute deadline. An uncertain exit or a
post-commit deadline failure is not rollback proof. There is no retry or new
clock/work allowance; a failed owner cannot be reused.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import threading
import time

from serverware import authority_challenge_page_binding as binding
from serverware import authority_revocation_root_reader as reader
from serverware import authority_revocation_writer_connection as writer
from serverware.authority_query_read_work import _ValidationWork


class ChallengePagePersistenceError(ValueError):
    pass


def _require(condition):
    if not condition:
        raise ChallengePagePersistenceError("maintenance page writer lost its original custody")


def _configuration(values):
    _require(type(values) is tuple and len(values) == 3)
    dsn, timeout, identity = values
    reader._bounded_text(dsn, 65536)
    _require("\n" not in dsn and "\r" not in dsn
        and type(timeout) is int and 2 <= timeout <= 300)
    writer._validate_database_identity(identity)
    return values


def _snapshot(owner):
    _require(type(owner) is MaintenancePagePersistence)
    return _configuration(owner._configured)


def _owned_arguments(arguments, *, persist, work):
    """Own every variable graph before the first connection/check callback."""
    fields = {name: value for name, value in arguments.items()
        if name not in {"body_bytes", "descriptor"}}
    owned, selected = binding._prepare(**fields, work=work)
    result = {**fields, "context": owned}
    for name in ("parent_plan_digest", "maintenance_manifest_digest", "phase_ordinal",
            "page_kind", "index_id", "page_ordinal"):
        result[name] = selected[name]
    if persist:
        result["body_bytes"] = arguments["body_bytes"]
        result["descriptor"] = binding._descriptor(arguments["body_bytes"], arguments["descriptor"], work)
    return result


def _guard(owner, configured, *, original_deadline_ns, check, work):
    """Original local custody around open, store, normal exit and close."""
    _require(type(work) is _ValidationWork and callable(check)
        and type(original_deadline_ns) is int and 0 < original_deadline_ns < 2**63)
    reader.roots.batch._SharedLedger(work)
    limits = work.limits
    bounds = limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes
    identity = os.getpid(), threading.get_ident()
    previous_work = work.hash_work, work.input_bytes, work.json_nodes
    previous_time = 0
    busy = False

    def local():
        nonlocal previous_work, previous_time
        _require(owner._configured is configured and owner._active is True and owner._failed is False
            and identity == (os.getpid(), threading.get_ident()) and work.limits is limits
            and (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes) == bounds)
        values = work.hash_work, work.input_bytes, work.json_nodes
        _require(all(type(value) is int and old <= value <= maximum
            for old, value, maximum in zip(previous_work, values, bounds, strict=True)))
        now = binding.store.lifecycle._guard(work, time.monotonic_ns)
        _require(type(now) is int and previous_time <= now < original_deadline_ns)
        previous_work, previous_time = values, now

    def guarded_check():
        nonlocal busy
        try:
            local()
            _require(not busy)
            busy = True
            _require(binding.store.lifecycle._guard(work, check) is None)
            local()
        except BaseException:
            object.__setattr__(owner, "_failed", True)
            raise
        finally:
            busy = False

    return guarded_check


def _connect(configured, *, check, work, psycopg, dict_row):
    """Keep cleanup custody even when the post-open guard refuses the handle."""
    connection = None

    def open_connection():
        nonlocal connection
        connection = psycopg.connect(configured[0], row_factory=dict_row,
            connect_timeout=configured[1], autocommit=False, options="-c search_path=pg_catalog")
        return connection

    try:
        check()
        result = binding.store.lifecycle._guard(work, open_connection)
        check()
        return result
    except BaseException:
        if connection is not None:
            reader._close_after_failure(connection)
        raise


def _run(configured, arguments, *, persist, check, work):
    # Preserve the real facade/registry gate before opening any socket.
    from serverware import db
    import psycopg
    from psycopg.rows import dict_row

    _require(configured[2][0] == db._METADATA_STORE_AUTHORITY_PLANNER_WRITER_ROLE)
    check()
    fixed = binding.retain_original if persist else binding.read_original

    def operation(*, connection, work):
        check()
        result = fixed(connection=connection, work=work, check=check, **arguments)
        _require(result is None if persist else
            type(result) is bytes and 1 <= len(result) <= binding.store.MAX_BODY_BYTES)
        # This check also precedes the real owner's normal outer transaction exit.
        check()
        return result

    connection = _connect(configured, check=check, work=work, psycopg=psycopg, dict_row=dict_row)
    try:
        result = writer._run_on_connection(connection, database_identity=configured[2],
            work=work, operation=operation, arguments={}, expectations={})
        # The existing owner verifies actual closure before returning. A deadline
        # which expired during COMMIT/close must not become a successful receipt.
        check()
        return result
    except BaseException:
        reader._close_after_failure(connection)
        raise


def _invoke(owner, arguments, *, persist, check, work):
    configured = _snapshot(owner)
    if owner._active is not False or owner._failed is not False:
        object.__setattr__(owner, "_failed", True)
        _require(False)
    object.__setattr__(owner, "_active", True)
    try:
        owned = _owned_arguments(arguments, persist=persist, work=work)
        guard = _guard(owner, configured, original_deadline_ns=owned["original_deadline_ns"],
            check=check, work=work)
        guard()
        return _run(configured, owned, persist=persist, check=guard, work=work)
    except BaseException:
        object.__setattr__(owner, "_failed", True)
        raise
    finally:
        object.__setattr__(owner, "_active", False)


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class MaintenancePagePersistence:
    """One fixed writer endpoint; successful calls may retain/read more pages."""

    _configured: tuple
    _active: bool
    _failed: bool

    def __init__(self, *, writer_dsn, connect_timeout_seconds, database_identity):
        object.__setattr__(self, "_configured", _configuration(
            (writer_dsn, connect_timeout_seconds, database_identity)))
        object.__setattr__(self, "_active", False)
        object.__setattr__(self, "_failed", False)

    def persist(self, *, parent_plan_digest, maintenance_manifest_digest, context,
            phase_ordinal, page_kind, index_id, page_ordinal, body_bytes, descriptor,
            original_deadline_ns, check, work) -> None:
        return _invoke(self, dict(parent_plan_digest=parent_plan_digest,
            maintenance_manifest_digest=maintenance_manifest_digest, context=context,
            phase_ordinal=phase_ordinal, page_kind=page_kind, index_id=index_id,
            page_ordinal=page_ordinal, body_bytes=body_bytes, descriptor=descriptor,
            original_deadline_ns=original_deadline_ns), persist=True, check=check, work=work)

    def read(self, *, parent_plan_digest, maintenance_manifest_digest, context,
            phase_ordinal, page_kind, index_id, page_ordinal,
            original_deadline_ns, check, work) -> bytes:
        return _invoke(self, dict(parent_plan_digest=parent_plan_digest,
            maintenance_manifest_digest=maintenance_manifest_digest, context=context,
            phase_ordinal=phase_ordinal, page_kind=page_kind, index_id=index_id,
            page_ordinal=page_ordinal, original_deadline_ns=original_deadline_ns),
            persist=False, check=check, work=work)
