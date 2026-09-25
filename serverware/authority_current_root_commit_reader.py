"""Fixed PostgreSQL owner for unsigned commit-marker/root observations.

Previously admitted immutable connection configuration selects only the
dedicated completion reader. Actual PostgreSQL 16 role/TLS and exact read
privileges are checked before observing one pending-decision marker and the
complete root vector in a SERIALIZABLE READ ONLY DEFERRABLE transaction.

The real observer uses the same physical connection and caller-owned work.
Results return only after normal cursor/connection exits and a closed-handle
check. The caller must independently join the marker and vector to its genuine
original execution candidate; these observations do not authenticate config,
enroll a database, establish latest-root currentness or authorize completion.
Catalog/driver admission exclusions match the existing configured root reader.
The caller's original live window and inherited monotonic deadline are never
reopened. Remaining time bounds libpq's per-host connect timeout and PostgreSQL
statement/lock/idle waits, with real checks around the outer phases. These are
not a hard total syscall watchdog or interruption of driver/native work.
No opener override, supplied observation, new allowance, write or retry exists.
"""
from __future__ import annotations

from dataclasses import dataclass
import time

from serverware import authority_current_root_vector as vector
from serverware import authority_revocation_root_reader as connection_owner
from serverware import authority_webauthn_evidence_plan_clock as clock
from serverware.authority_store import current_root_commit_observation as observation
from serverware.authority_store.completion_read_sql import (
    COMPLETION_READER_ROLE,
    completion_read_privilege_check,
)


class CurrentRootCommitReaderError(ValueError):
    pass


_WAIT_TIMEOUTS = ("lock_timeout", "idle_in_transaction_session_timeout", "statement_timeout")
_MILLISECOND = 1_000_000
_SECOND = 1_000_000_000


def _validate_configuration(config):
    connection_owner._validate_configuration(config)
    if "\r" in config[0] or "\n" in config[0]:
        raise CurrentRootCommitReaderError("commit-reader DSN is not one descriptor value")
    if config[2] != COMPLETION_READER_ROLE:
        raise CurrentRootCommitReaderError("commit-reader role is not the fixed completion reader")
    return config


def _read_on_configuration(config, *, pending_decision_digest, live_window, work,
        transport_deadline_ns=None):
    """Read on fixed real driver configuration, never an injectable adapter."""
    configured = _validate_configuration(config)
    vector.capture._SharedLedger(work)
    vector.counted._digest(pending_decision_digest, "pending decision digest")
    held_pending = pending_decision_digest
    window = clock._validate(live_window)
    if transport_deadline_ns is not None:
        clock.evidence.plan.contract._integer(transport_deadline_ns, minimum=1)
    bound = window[4] if transport_deadline_ns is None else min(window[4], transport_deadline_ns)
    callback = connection_owner.roots._callback
    last_epoch, last_monotonic = window[0], window[2]

    def remaining():
        nonlocal last_epoch, last_monotonic
        epoch = clock._check_on_work(window, work=work)
        monotonic = callback(work, time.monotonic_ns)
        clock.evidence.plan.contract._integer(monotonic, minimum=1)
        if epoch < last_epoch or monotonic < last_monotonic or monotonic >= bound:
            raise CurrentRootCommitReaderError("commit-reader original deadline expired or clock reversed")
        last_epoch, last_monotonic = epoch, monotonic
        return min(window[3] - epoch, bound - monotonic)

    def set_waits(guarded, milliseconds):
        if type(milliseconds) is not int or milliseconds < 1:
            raise CurrentRootCommitReaderError("commit-reader has no positive PostgreSQL wait budget")
        for name in _WAIT_TIMEOUTS:
            remaining()
            # Names are fixed source literals; the sole value is an internally
            # derived positive integer in PostgreSQL's millisecond base unit.
            guarded.execute("SET LOCAL " + name + " = " + str(milliseconds))
            remaining()

    # Both config and selector are now immutable source-bounded scalars. The
    # actual source, not a database catalogue or caller list, fixes the vector.
    remaining()
    bindings = vector._source_bindings_on_work(work=work)
    vector.framing._same(configured[6], bindings["queryManifestDigest"], work,
        "commit-reader query manifest differs from the actual source")
    import psycopg
    from psycopg.rows import dict_row

    available = remaining()
    connect_timeout = min(configured[1], available // _SECOND)
    if connect_timeout < 2:
        raise CurrentRootCommitReaderError("commit-reader has less than the minimum connection budget")
    startup_timeout = available // _MILLISECOND
    # Startup parameters bound the first SET TRANSACTION too. The fixed local
    # settings below narrow them after time spent establishing the connection.
    options = "-c search_path=pg_catalog" + "".join(
        " -c " + name + "=" + str(startup_timeout) for name in _WAIT_TIMEOUTS)
    connection = connection_owner._connect(work, lambda: psycopg.connect(
        configured[0], row_factory=dict_row, connect_timeout=connect_timeout,
        autocommit=False, options=options))
    try:
        remaining()
        physical = callback(work, connection_owner._connection_identity, connection, 0)
        with connection_owner._context(connection, work) as active_connection:
            remaining()
            if active_connection is not connection:
                raise CurrentRootCommitReaderError("commit-reader connection context replaced its handle")
            callback(work, connection_owner._require_connection, connection, physical, 0)
            cursor = callback(work, lambda: connection.cursor())
            with connection_owner._context(cursor, work) as active_cursor:
                if active_cursor is not cursor:
                    raise CurrentRootCommitReaderError("commit-reader admission cursor replaced its handle")
                guarded = connection_owner._ConnectionCursor(cursor, connection, physical, work)
                remaining()
                guarded.execute(connection_owner._SET_TRANSACTION)
                set_waits(guarded, remaining() // _MILLISECOND)
                remaining()
                connection_owner._admit_identity(
                    guarded.execute(connection_owner._IDENTITY_SQL).fetchone(), configured)
                remaining()
                set_waits(guarded, remaining() // _MILLISECOND)
                forbidden = guarded.execute(*completion_read_privilege_check(
                    role=configured[2], namespace="serverware_metadata")).fetchone()
                remaining()
                if forbidden is not None:
                    raise CurrentRootCommitReaderError("completion reader has unexpected privileges")
                callback(work, connection_owner._require_connection, connection, physical, 2)
                # Seven fixed observer SELECTs have no internal clock. Reserve
                # one more statement budget for normal outer exit and three
                # for these setup commands, never a whole window per query.
                observer_timeout = remaining() // _MILLISECOND // 11
                set_waits(guarded, observer_timeout)
            if callback(work, lambda: cursor.closed) is not True:
                raise CurrentRootCommitReaderError("commit-reader admission cursor did not close normally")
            callback(work, connection_owner._require_connection, connection, physical, 2)
            if remaining() < 8 * observer_timeout * _MILLISECOND:
                raise CurrentRootCommitReaderError("commit-reader observer setup exhausted its fixed budget")
            result = observation._observe_on_work(connection,
                pending_decision_digest=held_pending, work=work)
            remaining()
            if type(result) is not tuple or len(result) != 2:
                raise CurrentRootCommitReaderError("commit observer did not return its exact pair")
            marker, after_vector = result
            fields = vector.authority.CURRENT_ROOT_COMMIT_MARKER_COLUMNS
            if (type(marker) is not dict or len(marker) != len(fields)
                    or any(type(name) is not str for name in marker) or set(marker) != set(fields)
                    or type(after_vector) is not bytes or not 2 <= len(after_vector) <= vector.MAX_BYTES):
                raise CurrentRootCommitReaderError("commit observer returned an invalid bounded shape")
            vector.framing._same(marker["pending_decision_digest"], held_pending, work,
                "commit observer returned another pending decision")
            callback(work, connection_owner._require_connection, connection, physical, 2)
            remaining()
        if callback(work, lambda: connection.closed) is not True:
            raise CurrentRootCommitReaderError("commit-reader connection did not close normally")
        remaining()
        return marker, after_vector
    except BaseException:
        # Never replace the first failure with cleanup failure, including after
        # poisoned work or a normal-exit failure. No retry is implied.
        connection_owner._close_after_failure(connection)
        raise


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class CurrentRootCommitReader:
    """Hold admitted completion DB scalars without construction-time I/O."""

    _configuration: tuple

    def __init__(self, *, dsn, connect_timeout_seconds, database_role, tls_client_dn,
            tls_client_serial, tls_issuer_dn, query_manifest_digest):
        configured = _validate_configuration((dsn, connect_timeout_seconds, database_role,
            tls_client_dn, tls_client_serial, tls_issuer_dn, query_manifest_digest))
        object.__setattr__(self, "_configuration", configured)

    def _snapshot_configuration(self):
        if type(self) is not CurrentRootCommitReader:
            raise CurrentRootCommitReaderError("commit reader requires its exact configured owner")
        return _validate_configuration(self._configuration)

    def read(self, *, pending_decision_digest, live_window, work, transport_deadline_ns=None):
        configured = CurrentRootCommitReader._snapshot_configuration(self)
        return _read_on_configuration(configured,
            pending_decision_digest=pending_decision_digest, live_window=live_window,
            work=work, transport_deadline_ns=transport_deadline_ns)
