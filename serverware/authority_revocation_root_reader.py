"""Configured private verifier owner for independent root observations.

The actual service supplies previously admitted measured scalar configuration.
This module does not verify configuration signatures, enroll a database, or
turn observed roots into a proof/currentness token. It owns one PostgreSQL 16
SERIALIZABLE READ ONLY DEFERRABLE transaction and closes every read scope
before returning the genuine full primary/counting inventory.

Fixed configuration, source-manifest preparation, catalog/TLS admission and
driver/SQL work are explicitly outside H/B/N. Actual root acquisition uses the
caller's original work and the source-bounded physical ledger; no new work
allowance is created. Callback guards detect meter and connection drift, not a
hostile driver's hidden commit-and-BEGIN. Connection-exit errors may be
indeterminate; a post-exit guard cannot undo an already completed transaction.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass

from serverware import authority_revocation_roots as roots
from serverware.authority_store.verifier_read_sql import verifier_read_privilege_check


_SET_TRANSACTION = "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY DEFERRABLE"
_IDENTITY_SQL = (
    "SELECT pg_catalog.current_setting('server_version_num')::integer AS server_version_num, "
    "current_user AS role, session_user AS session_role, "
    "pg_catalog.current_setting('transaction_isolation') AS transaction_isolation, "
    "pg_catalog.current_setting('transaction_read_only') AS transaction_read_only, "
    "pg_catalog.current_setting('transaction_deferrable') AS transaction_deferrable, "
    "ssl.ssl, ssl.client_dn, ssl.client_serial::text AS client_serial, ssl.issuer_dn, "
    "role_record.rolcanlogin, role_record.rolsuper, role_record.rolcreaterole, "
    "role_record.rolcreatedb, role_record.rolreplication, role_record.rolbypassrls, "
    "pg_catalog.has_schema_privilege(current_user, 'serverware_metadata', 'CREATE') AS schema_create, "
    "pg_catalog.has_database_privilege(current_user, pg_catalog.current_database(), 'CREATE') AS database_create, "
    "pg_catalog.has_database_privilege(current_user, pg_catalog.current_database(), 'TEMPORARY') AS database_temporary "
    "FROM pg_catalog.pg_stat_ssl AS ssl JOIN pg_catalog.pg_roles AS role_record "
    "ON role_record.oid = current_user::pg_catalog.regrole::oid "
    "WHERE ssl.pid = pg_catalog.pg_backend_pid()"
)
_FALSE_FIELDS = ("rolsuper", "rolcreaterole", "rolcreatedb", "rolreplication",
    "rolbypassrls", "schema_create", "database_create", "database_temporary")
_IDENTITY_FIELDS = frozenset(("server_version_num", "role", "session_role",
    "transaction_isolation", "transaction_read_only", "transaction_deferrable",
    "ssl", "client_dn", "client_serial", "issuer_dn", "rolcanlogin", *_FALSE_FIELDS))


def _bounded_text(value, maximum):
    if (type(value) is not str or not 1 <= len(value) <= maximum or "\x00" in value):
        raise roots.RevocationRootReadError("revocation root configuration text is invalid")
    try:
        if len(value.encode("utf-8")) > maximum:
            raise roots.RevocationRootReadError("revocation root configuration text exceeds its byte bound")
    except UnicodeError as exc:
        raise roots.RevocationRootReadError("revocation root configuration text is not Unicode") from exc


def _validate_pins(pins):
    """Fixed scalar ownership before launch/descriptor/connection callbacks."""
    if type(pins) is not tuple or len(pins) != 6:
        raise roots.RevocationRootReadError("revocation root pins are not an exact six-tuple")
    timeout, role, client_dn, client_serial, issuer_dn, manifest = pins
    if type(timeout) is not int or not 2 <= timeout <= 300:
        raise roots.RevocationRootReadError("revocation root timeout is not a source-bounded integer")
    _bounded_text(role, 63)
    for value in (client_dn, client_serial, issuer_dn):
        _bounded_text(value, 4096)
    if (type(manifest) is not str or len(manifest) != 71 or manifest[:7] != "sha256:"
            or any(character not in "0123456789abcdef" for character in manifest[7:])):
        raise roots.RevocationRootReadError("revocation root manifest pin is not canonical SHA-256")


def _validate_configuration(configuration):
    if type(configuration) is not tuple or len(configuration) != 7:
        raise roots.RevocationRootReadError("revocation root configuration is not an exact seven-tuple")
    _bounded_text(configuration[0], 65536)
    _validate_pins(configuration[1:])


def _close_after_failure(connection):
    """Best-effort actual cleanup, including after poisoned-work rejection."""
    try:
        closed = connection.closed is True
    except BaseException:
        closed = False
    if not closed:
        try:
            connection.close()
        except BaseException:
            pass


def _connect(work, opener):
    connection = None

    def open_connection():
        nonlocal connection
        connection = opener()
        return connection

    try:
        return roots._callback(work, open_connection)
    except BaseException:
        if connection is not None:
            _close_after_failure(connection)
        raise


@contextmanager
def _context(manager, work):
    """Never let invalid counters prevent cleanup or suppression hide failure."""
    entered = False

    def enter():
        nonlocal entered
        value = manager.__enter__()
        entered = True
        return value

    try:
        value = roots._callback(work, enter)
        yield value
    except BaseException as exc:
        if entered:
            try:
                manager.__exit__(type(exc), exc, exc.__traceback__)
            except BaseException:
                pass
        raise
    else:
        exited = False

        def leave():
            nonlocal exited
            exited = True
            return manager.__exit__(None, None, None)

        try:
            roots._callback(work, leave)
        except BaseException as exc:
            if not exited:
                try:
                    manager.__exit__(type(exc), exc, exc.__traceback__)
                except BaseException:
                    pass
            raise


def _connection_identity(connection, status):
    # psycopg TransactionStatus is an IntEnum; bool/float aliases are forbidden.
    actual = connection.info.transaction_status
    identity = connection.pgconn
    if (connection.closed is not False or connection.autocommit is not False
            or not isinstance(actual, int) or isinstance(actual, bool) or actual != status
            or identity is None):
        raise roots.RevocationRootReadError("revocation root connection state changed")
    return identity


def _require_connection(connection, identity, status):
    if _connection_identity(connection, status) is not identity:
        raise roots.RevocationRootReadError("revocation root physical connection changed")


class _ConnectionResult:
    __slots__ = ("_result", "_cursor")

    def __init__(self, result, cursor):
        self._result, self._cursor = result, cursor

    def fetchone(self):
        return self._cursor._call(lambda: self._result.fetchone())

    def fetchall(self):
        return self._cursor._call(lambda: self._result.fetchall())

    def fetchmany(self, size):
        return self._cursor._call(lambda: self._result.fetchmany(size))


class _ConnectionCursor:
    """Pin actual raw connection continuity around every execute/fetch call."""
    __slots__ = ("_cursor", "_connection", "_identity", "_work", "_started", "_binding")

    def __init__(self, cursor, connection, identity, work):
        self._cursor, self._connection, self._identity, self._work = cursor, connection, identity, work
        self._binding = cursor, connection, identity, work
        self._started = False

    def _require(self, binding, started):
        if (self._binding is not binding or self._started is not started
                or any(actual is not expected for actual, expected in zip(
                    (self._cursor, self._connection, self._identity, self._work), binding))):
            raise roots.RevocationRootReadError("revocation root inner cursor binding changed")

    def _call(self, callback, *, start=False):
        binding = self._binding
        if type(binding) is not tuple or len(binding) != 4:
            raise roots.RevocationRootReadError("revocation root inner cursor binding is invalid")
        _, connection, identity, work = binding
        started = not start

        def invoke():
            self._require(binding, started)
            roots._callback(work, _require_connection, connection, identity, 0 if start else 2)
            self._require(binding, started)
            result = callback()
            self._require(binding, started)
            roots._callback(work, _require_connection, connection, identity, 2)
            self._require(binding, started)
            return result

        return roots._callback(work, invoke)

    def execute(self, sql, parameters=None):
        arguments = (sql,) if parameters is None else (sql, parameters)
        if self._started is True:
            return _ConnectionResult(self._call(lambda: self._cursor.execute(*arguments)), self)
        if sql != _SET_TRANSACTION or parameters is not None:
            raise roots.RevocationRootReadError("revocation root first statement is not the read transaction mode")
        result = self._call(lambda: self._cursor.execute(sql), start=True)
        self._started = True
        return _ConnectionResult(result, self)


def _admit_identity(identity, configuration):
    if (type(identity) is not dict or len(identity) != len(_IDENTITY_FIELDS)
            or any(type(name) is not str for name in identity) or set(identity) != _IDENTITY_FIELDS):
        raise roots.RevocationRootReadError("revocation root identity row is not closed")
    _, _, role, client_dn, client_serial, issuer_dn, _ = configuration
    expected = {"role": role, "session_role": role, "client_dn": client_dn,
        "client_serial": client_serial, "issuer_dn": issuer_dn,
        "transaction_isolation": "serializable", "transaction_read_only": "on",
        "transaction_deferrable": "on"}
    if (type(identity["server_version_num"]) is not int
            or not 160000 <= identity["server_version_num"] < 170000
            or any(type(identity[name]) is not str or identity[name] != value for name, value in expected.items())
            or identity["ssl"] is not True or identity["rolcanlogin"] is not True
            or any(identity[name] is not False for name in _FALSE_FIELDS)):
        raise roots.RevocationRootReadError("revocation root role, TLS or transaction admission changed")


def _read_on_configuration(configuration, *, work, opener):
    """Private deterministic adapter seam; a recorder is not PG/ACL evidence."""
    _validate_configuration(configuration)
    roots.batch._SharedLedger(work)
    # Configuration is an exact tuple of immutable scalars, captured before
    # any external callback. The public owner exposes no opener override.
    connection = _connect(work, opener)
    try:
        identity = roots._callback(work, _connection_identity, connection, 0)
        with _context(connection, work) as active_connection:
            if active_connection is not connection:
                raise roots.RevocationRootReadError("revocation root connection context replaced its handle")
            roots._callback(work, _require_connection, connection, identity, 0)
            cursor = roots._callback(work, lambda: connection.cursor())
            with _context(cursor, work) as active_cursor:
                if active_cursor is not cursor:
                    raise roots.RevocationRootReadError("revocation root cursor context replaced its handle")
                guarded = roots._RootCursor(_ConnectionCursor(cursor, connection, identity, work), work)
                guarded.execute(_SET_TRANSACTION)
                _admit_identity(guarded.execute(_IDENTITY_SQL).fetchone(), configuration)
                forbidden = guarded.execute(*verifier_read_privilege_check(
                    role=configuration[2], namespace="serverware_metadata")).fetchone()
                if forbidden is not None:
                    raise roots.RevocationRootReadError("revocation root verifier read role has unexpected authority")
                trace = roots._RootTrace(work)
                acquisition = roots.reader._ReadAcquisitionBudget(
                    guarded, trace, work=work, limits=roots._ROOT_LIMITS)
                result = roots._read_revocation_root_inventory_on_work(guarded,
                    expected_query_manifest_digest=configuration[6], work=work, acquisition=acquisition)
                roots._callback(work, _require_connection, connection, identity, 2)
            roots._callback(work, _require_connection, connection, identity, 2)
        if roots._callback(work, lambda: connection.closed) is not True:
            raise roots.RevocationRootReadError("revocation root connection was not closed")
        return result
    except BaseException:
        _close_after_failure(connection)
        raise


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class RevocationRootReader:
    """Fixed verifier database configuration, never caller-provided roots."""

    _configuration: tuple

    def __init__(self, *, dsn, connect_timeout_seconds, database_role, tls_client_dn,
                 tls_client_serial, tls_issuer_dn, query_manifest_digest):
        configuration = (dsn, connect_timeout_seconds, database_role, tls_client_dn,
            tls_client_serial, tls_issuer_dn, query_manifest_digest)
        _validate_configuration(configuration)
        object.__setattr__(self, "_configuration", configuration)

    def _snapshot_configuration(self):
        if type(self) is not RevocationRootReader:
            raise roots.RevocationRootReadError("revocation root reader requires its exact configured owner")
        configuration = self._configuration
        _validate_configuration(configuration)
        return configuration

    def read(self, *, work):
        configuration = self._snapshot_configuration()
        roots.batch._SharedLedger(work)
        import psycopg
        from psycopg.rows import dict_row

        return _read_on_configuration(configuration, work=work,
            opener=lambda: psycopg.connect(configuration[0], row_factory=dict_row,
                connect_timeout=configuration[1], autocommit=False,
                options="-c search_path=pg_catalog"))
