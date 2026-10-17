"""Actual verifier read owner for source-fixed evidence-admission roots.

The service independently admits the measured verifier role, protected DSN,
TLS identity and source manifest pin. This inert owner checks those held
settings against an actual PostgreSQL 16 SERIALIZABLE READ ONLY DEFERRABLE
connection and the existing source-exact verifier ACL before the fixed root
worker runs. It opens no business-row or counted-head read surface.

One operation-specific physical acquisition uses the caller's original work.
Only after normal cursor and connection/transaction exit and an actual closed
handle check can the ordinary full primary-root observations return. Neither
construction nor returned data grants root provenance, historical authority,
current execution permission or a successful-proof token to another caller.

Connection/catalog/driver work and fixed source configuration scaffolding keep
their existing accounting exclusions. Guards detect exposed connection/meter
drift, not a hostile driver's hidden transaction replacement. There is no
public opener, callback override, new H/B/N allowance, SQL mutation, registry
activation, privilege change or automatic retry.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_revocation_root_reader as connection_owner
from catchplate import authority_webauthn_evidence_roots as roots
from catchplate.authority_store.verifier_read_sql import verifier_read_privilege_check


class WebAuthnEvidenceRootReaderError(ValueError):
    pass


def _validate_configuration(configuration):
    if type(configuration) is not tuple or len(configuration) != 8:
        raise WebAuthnEvidenceRootReaderError("evidence root reader configuration is not an exact eight-tuple")
    # The fixed worker admits only the two source operations. Its actual
    # physical limits are derived from that operation, never supplied here.
    roots._limits(configuration[0])
    connection_owner._validate_configuration(configuration[1:])
    return configuration


def _read_on_configuration(configuration, *, work):
    """Use only the actual fixed opener and return after every normal exit."""
    configured = _validate_configuration(configuration)
    operation, read_configuration = configured[0], configured[1:]
    connection_owner.roots.batch._SharedLedger(work)
    import psycopg
    from psycopg.rows import dict_row

    connection = connection_owner._connect(work, lambda: psycopg.connect(
        read_configuration[0], row_factory=dict_row,
        connect_timeout=read_configuration[1], autocommit=False,
        options="-c search_path=pg_catalog"))
    callback = connection_owner.roots._callback
    try:
        identity = callback(work, connection_owner._connection_identity, connection, 0)
        with connection_owner._context(connection, work) as active_connection:
            if active_connection is not connection:
                raise WebAuthnEvidenceRootReaderError("evidence root connection context replaced its handle")
            callback(work, connection_owner._require_connection, connection, identity, 0)
            cursor = callback(work, lambda: connection.cursor())
            with connection_owner._context(cursor, work) as active_cursor:
                if active_cursor is not cursor:
                    raise WebAuthnEvidenceRootReaderError("evidence root cursor context replaced its handle")
                guarded = roots._RootCursor(connection_owner._ConnectionCursor(
                    cursor, connection, identity, work), work, operation)
                guarded.execute(connection_owner._SET_TRANSACTION)
                connection_owner._admit_identity(
                    guarded.execute(connection_owner._IDENTITY_SQL).fetchone(), read_configuration)
                forbidden = guarded.execute(*verifier_read_privilege_check(
                    role=read_configuration[2], namespace="catchplate_metadata")).fetchone()
                if forbidden is not None:
                    raise WebAuthnEvidenceRootReaderError("evidence root verifier role has unexpected authority")
                trace = roots._RootTrace(operation=operation, work=work)
                acquisition = connection_owner.roots.reader._ReadAcquisitionBudget(
                    guarded, trace, work=work, limits=roots._limits(operation))
                result = roots._read_root_inventory_on_work(guarded, operation=operation,
                    expected_query_manifest_digest=read_configuration[6], work=work, acquisition=acquisition)
                callback(work, connection_owner._require_connection, connection, identity, 2)
            callback(work, connection_owner._require_connection, connection, identity, 2)
        if callback(work, lambda: connection.closed) is not True:
            raise WebAuthnEvidenceRootReaderError("evidence root connection was not closed")
        return result
    except BaseException:
        connection_owner._close_after_failure(connection)
        raise


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class EvidenceRootReader:
    """Hold one admitted operation and verifier database identity; no I/O."""

    _configuration: tuple

    def __init__(self, *, operation, dsn, connect_timeout_seconds, database_role,
            tls_client_dn, tls_client_serial, tls_issuer_dn, query_manifest_digest):
        configured = _validate_configuration((operation, dsn, connect_timeout_seconds,
            database_role, tls_client_dn, tls_client_serial, tls_issuer_dn, query_manifest_digest))
        object.__setattr__(self, "_configuration", configured)

    def _snapshot_configuration(self):
        if type(self) is not EvidenceRootReader:
            raise WebAuthnEvidenceRootReaderError("evidence root reader owner type changed")
        return _validate_configuration(self._configuration)

    def read(self, *, work):
        configured = EvidenceRootReader._snapshot_configuration(self)
        return _read_on_configuration(configured, work=work)
