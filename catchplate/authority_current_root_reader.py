"""Configured PostgreSQL owner for complete unsigned root observations.

Previously admitted immutable connection configuration fixes the real driver,
PostgreSQL 16 verifier role/TLS identity and source-exact read privileges. One
SERIALIZABLE READ ONLY DEFERRABLE transaction contains the actual complete
root observer, on the same physical connection and caller-owned work.

Canonical bytes return only after normal cursor/connection exits and a closed
connection check. The observation does not authenticate configuration, enroll
a database, establish latest-root currentness, or authorize execution. Catalog,
driver and fixed configuration accounting exclusions match the existing root
reader; source-vector work and physical acquisition remain genuinely metered.
No injectable opener, SQL write, new allowance, service gate or retry is added.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_current_root_vector as vector
from catchplate import authority_revocation_root_reader as connection_owner
from catchplate.authority_store import current_root_observation as observation
from catchplate.authority_store.verifier_read_sql import verifier_read_privilege_check


class CurrentRootReaderError(ValueError):
    pass


def _validate_configuration(configuration):
    connection_owner._validate_configuration(configuration)
    if "\r" in configuration[0] or "\n" in configuration[0]:
        raise CurrentRootReaderError("complete-root DSN is not one descriptor value")
    return configuration


def _read_on_configuration(configuration, *, work):
    configured = _validate_configuration(configuration)
    vector.capture._SharedLedger(work)
    # Configuration is already an exact tuple of immutable source-bounded
    # scalars. Join its manifest to genuine source work before any database
    # callback; neither a database row nor a caller inventory selects tables.
    bindings = vector._source_bindings_on_work(work=work)
    vector.framing._same(configured[6], bindings["queryManifestDigest"], work,
        "complete-root reader query manifest differs from the actual source")
    import psycopg
    from psycopg.rows import dict_row

    connection = connection_owner._connect(work, lambda: psycopg.connect(
        configured[0], row_factory=dict_row, connect_timeout=configured[1],
        autocommit=False, options="-c search_path=pg_catalog"))
    callback = connection_owner.roots._callback
    try:
        physical = callback(work, connection_owner._connection_identity, connection, 0)
        with connection_owner._context(connection, work) as active_connection:
            if active_connection is not connection:
                raise CurrentRootReaderError("complete-root connection context replaced its handle")
            callback(work, connection_owner._require_connection, connection, physical, 0)
            cursor = callback(work, lambda: connection.cursor())
            with connection_owner._context(cursor, work) as active_cursor:
                if active_cursor is not cursor:
                    raise CurrentRootReaderError("complete-root admission cursor context replaced its handle")
                guarded = connection_owner._ConnectionCursor(cursor, connection, physical, work)
                guarded.execute(connection_owner._SET_TRANSACTION)
                connection_owner._admit_identity(
                    guarded.execute(connection_owner._IDENTITY_SQL).fetchone(), configured)
                forbidden = guarded.execute(*verifier_read_privilege_check(
                    role=configured[2], namespace="catchplate_metadata")).fetchone()
                if forbidden is not None:
                    raise CurrentRootReaderError("complete-root verifier role has unexpected privileges")
                callback(work, connection_owner._require_connection, connection, physical, 2)
            if callback(work, lambda: cursor.closed) is not True:
                raise CurrentRootReaderError("complete-root admission cursor did not close normally")
            callback(work, connection_owner._require_connection, connection, physical, 2)
            # The actual observer opens its own cursor inside this same admitted
            # transaction and spends the original work plus its fixed physical
            # ledger. No observer result or arbitrary callback is accepted.
            result = observation._observe_on_work(connection, work=work)
            if type(result) is not bytes or not 2 <= len(result) <= vector.MAX_BYTES:
                raise CurrentRootReaderError("complete-root observer did not return bounded canonical bytes")
            callback(work, connection_owner._require_connection, connection, physical, 2)
        if callback(work, lambda: connection.closed) is not True:
            raise CurrentRootReaderError("complete-root connection did not close normally")
        return result
    except BaseException:
        # Preserve the original failure even if cleanup also fails or the
        # shared work was poisoned. A post-exit failure grants no retry.
        connection_owner._close_after_failure(connection)
        raise


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class CurrentRootReader:
    """Hold admitted verifier DB scalars, without performing I/O at construction."""

    _configuration: tuple

    def __init__(self, *, dsn, connect_timeout_seconds, database_role, tls_client_dn,
            tls_client_serial, tls_issuer_dn, query_manifest_digest):
        configured = _validate_configuration((dsn, connect_timeout_seconds, database_role,
            tls_client_dn, tls_client_serial, tls_issuer_dn, query_manifest_digest))
        object.__setattr__(self, "_configuration", configured)

    def _snapshot_configuration(self):
        if type(self) is not CurrentRootReader:
            raise CurrentRootReaderError("complete-root reader requires its exact configured owner")
        return _validate_configuration(self._configuration)

    def read(self, *, work):
        configured = CurrentRootReader._snapshot_configuration(self)
        return _read_on_configuration(configured, work=work)
