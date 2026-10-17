"""Actual verifier read owner for three source-fixed successor root sets.

The full typed request is owned and commitment-validated before native or
connection callbacks. Its actual source operation and mode fix one two-SELECT
physical acquisition, including the full potential counted-head inventory.
The existing PostgreSQL 16 SERIALIZABLE READ ONLY DEFERRABLE, TLS identity and
source-exact verifier ACL admission is reused without another read surface.

Only after normal cursor and transaction/connection exits and a real closed
handle check may ordinary root observations return. These observations do not
admit request provenance, currentness, historical authority or execution. All
root acquisition spends the original cumulative work and physical ledger.
Existing fixed configuration/catalog/driver accounting exclusions remain; no
opener override, SQL mutation, new privilege, budget or retry is introduced.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_revocation_root_reader as connection_owner
from catchplate import authority_webauthn_transition_roots as roots
from catchplate import authority_webauthn_transition_roots_contract as contract
from catchplate.authority_store.verifier_read_sql import verifier_read_privilege_check


class WebAuthnTransitionRootReaderError(ValueError):
    pass


def _validate_configuration(configuration):
    if type(configuration) is not tuple or len(configuration) != 8:
        raise WebAuthnTransitionRootReaderError("transition root configuration is not an exact eight-tuple")
    if type(configuration[0]) is not str or configuration[0] not in contract.OPERATIONS:
        raise WebAuthnTransitionRootReaderError("transition root operation is not source fixed")
    connection_owner._validate_configuration(configuration[1:])
    if "\r" in configuration[1] or "\n" in configuration[1]:
        raise WebAuthnTransitionRootReaderError("transition root DSN is not one descriptor value")
    return configuration


def _read_on_configuration(configuration, *, request, work):
    configured = _validate_configuration(configuration)
    operation, read_configuration = configured[0], configured[1:]
    owned = contract._capture_request_on_work(request=request, operation=operation, work=work)
    limits = contract._limits(operation, owned["arguments"])
    # No original caller graph or mutable owner slot is consulted after this
    # point. The only opener is the real driver under the existing work guard.
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
                raise WebAuthnTransitionRootReaderError("transition root connection context replaced its handle")
            callback(work, connection_owner._require_connection, connection, identity, 0)
            cursor = callback(work, lambda: connection.cursor())
            with connection_owner._context(cursor, work) as active_cursor:
                if active_cursor is not cursor:
                    raise WebAuthnTransitionRootReaderError("transition root cursor context replaced its handle")
                guarded = roots._RootCursor(connection_owner._ConnectionCursor(
                    cursor, connection, identity, work), work, operation, owned)
                guarded.execute(connection_owner._SET_TRANSACTION)
                connection_owner._admit_identity(
                    guarded.execute(connection_owner._IDENTITY_SQL).fetchone(), read_configuration)
                forbidden = guarded.execute(*verifier_read_privilege_check(
                    role=read_configuration[2], namespace="catchplate_metadata")).fetchone()
                if forbidden is not None:
                    raise WebAuthnTransitionRootReaderError("transition root verifier role has unexpected authority")
                trace = roots._RootTrace(operation=operation, request=owned, work=work)
                acquisition = contract.reader._ReadAcquisitionBudget(
                    guarded, trace, work=work, limits=limits)
                result = roots._read_root_inventory_on_work(guarded, operation=operation, request=owned,
                    expected_query_manifest_digest=read_configuration[6], work=work, acquisition=acquisition)
                callback(work, connection_owner._require_connection, connection, identity, 2)
            callback(work, connection_owner._require_connection, connection, identity, 2)
        if callback(work, lambda: connection.closed) is not True:
            raise WebAuthnTransitionRootReaderError("transition root connection was not closed")
        return result
    except BaseException:
        connection_owner._close_after_failure(connection)
        raise


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class TransitionRootReader:
    """Hold one admitted operation and verifier connection identity; no I/O."""

    _configuration: tuple

    def __init__(self, *, operation, dsn, connect_timeout_seconds, database_role,
            tls_client_dn, tls_client_serial, tls_issuer_dn, query_manifest_digest):
        configured = _validate_configuration((operation, dsn, connect_timeout_seconds,
            database_role, tls_client_dn, tls_client_serial, tls_issuer_dn, query_manifest_digest))
        object.__setattr__(self, "_configuration", configured)

    def _snapshot_configuration(self):
        if type(self) is not TransitionRootReader:
            raise WebAuthnTransitionRootReaderError("transition root reader owner type changed")
        return _validate_configuration(self._configuration)

    def read(self, *, request, work):
        configured = TransitionRootReader._snapshot_configuration(self)
        return _read_on_configuration(configured, request=request, work=work)
