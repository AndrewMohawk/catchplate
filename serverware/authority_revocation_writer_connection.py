"""Private admission and continuity for an actual revocation writer connection.

The caller owns configuration and variable inputs before opening the connection.
This helper takes ownership of that real handle, admits fixed PostgreSQL/TLS/ACL
metadata, and closes it after the actual store operation and transaction finish.
It does not enroll a database, authenticate input graphs, or return an admission
token. The operation argument is the existing private composition seam, never a
public request callback. Database facade import remains lazy and registry-gated.
The proxy serves the actual persist/read/reserve consumers, which always enter
raw cursor scopes. It is not a general replacement for facade.execute(), whose
unentered cursor usage this narrow adapter intentionally does not support.

Fixed metadata/driver work is outside H/B/N, but every successful driver callback
must preserve the caller's original work. Actual replay may spend that work.
Observed pgconn/status cannot detect a hostile driver's hidden commit-and-BEGIN.
Cleanup preserves the first failure; post-exit rejection cannot undo a commit
which the real manager has already completed.
"""
from __future__ import annotations

from serverware import authority_revocation_root_reader as reader
from serverware.authority_store.planner_writer_sql import planner_writer_privilege_check


_ROLE = "serverware_policy_authority_planner_writer"
_SET_TRANSACTION = "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ WRITE NOT DEFERRABLE"
_IDENTITY_SQL = reader._IDENTITY_SQL


class RevocationWriterConnectionError(ValueError):
    pass


def _validate_database_identity(identity):
    if type(identity) is not tuple or len(identity) != 4:
        raise RevocationWriterConnectionError("revocation writer identity is not an exact four-tuple")
    for index, value in enumerate(identity):
        maximum = 63 if index == 0 else 4096
        if type(value) is not str or not 1 <= len(value) <= maximum or "\x00" in value:
            raise RevocationWriterConnectionError("revocation writer identity text is invalid")
        try:
            if len(value.encode("utf-8")) > maximum:
                raise RevocationWriterConnectionError("revocation writer identity text exceeds its byte bound")
        except UnicodeError as exc:
            raise RevocationWriterConnectionError("revocation writer identity text is not Unicode") from exc
    if identity[0] != _ROLE:
        raise RevocationWriterConnectionError("revocation writer database role differs from source")


def _callback(work, callback, *args):
    try:
        return reader.roots._callback(work, callback, *args)
    except reader.roots.RevocationRootReadError as exc:
        raise RevocationWriterConnectionError(str(exc)) from exc


def _admit_identity(row, identity):
    if (type(row) is not dict or len(row) != len(reader._IDENTITY_FIELDS)
            or any(type(name) is not str for name in row) or set(row) != reader._IDENTITY_FIELDS):
        raise RevocationWriterConnectionError("revocation writer identity row is not closed")
    role, client_dn, client_serial, issuer_dn = identity
    expected = {"role": role, "session_role": role, "client_dn": client_dn,
        "client_serial": client_serial, "issuer_dn": issuer_dn,
        "transaction_isolation": "serializable", "transaction_read_only": "off",
        "transaction_deferrable": "off"}
    if (type(row["server_version_num"]) is not int
            or not 160000 <= row["server_version_num"] < 170000
            or any(type(row[name]) is not str or row[name] != value for name, value in expected.items())
            or row["ssl"] is not True or row["rolcanlogin"] is not True
            or any(row[name] is not False for name in reader._FALSE_FIELDS)):
        raise RevocationWriterConnectionError("revocation writer role, TLS or transaction admission changed")


def _same_slots(actual, expected):
    return len(actual) == len(expected) and all(left is right for left, right in zip(actual, expected))


class _Connection:
    """Narrow active-transaction proxy; no commit, reconnect or fallback access."""

    __slots__ = ("_connection", "_original", "_work", "_binding")

    def __init__(self, connection, original, work):
        self._connection, self._original, self._work = connection, original, work
        self._binding = connection, original, work

    def _require(self, binding):
        if (self._binding is not binding
                or not _same_slots((self._connection, self._original, self._work), binding)):
            raise RevocationWriterConnectionError("revocation writer connection binding changed")

    def _call(self, callback):
        binding = self._binding
        if type(binding) is not tuple or len(binding) != 3:
            raise RevocationWriterConnectionError("revocation writer connection binding is invalid")
        connection, original, work = binding

        def invoke():
            self._require(binding)
            _callback(work, reader._require_connection, connection, original, 2)
            self._require(binding)
            result = callback()
            self._require(binding)
            _callback(work, reader._require_connection, connection, original, 2)
            self._require(binding)
            return result

        return _callback(work, invoke)

    @property
    def info(self):
        connection = self._connection
        return _Info(self._call(lambda: connection.info), self)

    @property
    def pgconn(self):
        connection = self._connection
        return self._call(lambda: connection.pgconn)

    @property
    def closed(self):
        connection = self._connection
        return self._call(lambda: connection.closed)

    @property
    def autocommit(self):
        connection = self._connection
        return self._call(lambda: connection.autocommit)

    def cursor(self):
        connection = self._connection
        return _Cursor(self._call(lambda: connection.cursor()), self)

    def transaction(self):
        connection = self._connection
        return _Scope(self._call(lambda: connection.transaction()), self)


class _Info:
    __slots__ = ("_info", "_connection", "_binding")

    def __init__(self, info, connection):
        self._info, self._connection = info, connection
        self._binding = info, connection

    @property
    def transaction_status(self):
        binding = self._binding
        if type(binding) is not tuple or len(binding) != 2:
            raise RevocationWriterConnectionError("revocation writer info binding is invalid")
        info, connection = binding

        def observe():
            if self._binding is not binding or not _same_slots((self._info, self._connection), binding):
                raise RevocationWriterConnectionError("revocation writer info binding changed")
            value = info.transaction_status
            if self._binding is not binding or not _same_slots((self._info, self._connection), binding):
                raise RevocationWriterConnectionError("revocation writer info binding changed")
            if not isinstance(value, int) or isinstance(value, bool) or value != 2:
                raise RevocationWriterConnectionError("revocation writer observed transaction is inactive")
            return value

        return connection._call(observe)


class _Scope:
    """A real cursor/savepoint manager with cleanup retained across failed entry."""

    __slots__ = ("_manager", "_connection", "_binding", "_scope", "_state", "_entry_binding")

    def __init__(self, manager, connection):
        self._manager, self._connection = manager, connection
        self._scope = reader._context(manager, connection._work)
        self._binding = manager, connection, self._scope
        self._state = 0
        self._entry_binding = None

    def _require(self, binding, scope, state):
        if (self._binding is not binding or self._entry_binding is not binding
                or self._scope is not scope or self._state is not state
                or not _same_slots((self._manager, self._connection, self._scope), binding)):
            raise RevocationWriterConnectionError("revocation writer scope binding changed")

    def _call(self, callback):
        binding = self._binding
        if type(binding) is not tuple or len(binding) != 3:
            raise RevocationWriterConnectionError("revocation writer scope binding is invalid")
        _, connection, scope = binding

        def invoke():
            self._require(binding, scope, 1)
            result = callback()
            self._require(binding, scope, 1)
            return result

        return connection._call(invoke)

    def __enter__(self):
        binding = self._binding
        if type(binding) is not tuple or len(binding) != 3:
            raise RevocationWriterConnectionError("revocation writer scope binding is invalid")
        manager, connection, scope = binding
        if self._entry_binding is not None:
            raise RevocationWriterConnectionError("revocation writer scope was already entered")
        # Cleanup custody is held independently of the callback-visible working
        # binding. A rejected replacement of _binding must not redirect exit.
        self._entry_binding = binding
        entered = False

        def enter():
            nonlocal entered
            self._require(binding, scope, 0)
            value = scope.__enter__()
            entered = True
            self._require(binding, scope, 0)
            if value is not manager:
                raise RevocationWriterConnectionError("revocation writer manager replaced its entered handle")
            return value

        try:
            connection._call(enter)
            self._state = 1
            return self
        except BaseException as exc:
            if entered:
                try:
                    scope.__exit__(type(exc), exc, exc.__traceback__)
                except BaseException:
                    pass
            self._state = 2
            raise

    def __exit__(self, kind, error, traceback):
        # On failure no mutable meter/connection guard can prevent the original
        # manager's rollback/close. A suppressing driver never hides failure.
        binding = self._entry_binding
        # Use the binding held at entry, never a fresh working-binding lookup
        # after the failing callback may have replaced that entire tuple.
        scope = binding[2] if type(binding) is tuple and len(binding) == 3 else self._scope
        if kind is not None:
            try:
                scope.__exit__(kind, error, traceback)
            except BaseException:
                pass
            self._state = 2
            return False
        exited = False

        def leave():
            nonlocal exited
            self._require(binding, scope, 1)
            exited = True
            value = scope.__exit__(None, None, None)
            self._require(binding, scope, 1)
            return value

        try:
            if type(binding) is not tuple or len(binding) != 3:
                raise RevocationWriterConnectionError("revocation writer scope binding is invalid")
            binding[1]._call(leave)
        except BaseException as exc:
            if not exited:
                try:
                    scope.__exit__(type(exc), exc, exc.__traceback__)
                except BaseException:
                    pass
            raise
        finally:
            self._state = 2
        return False


class _Cursor(_Scope):
    __slots__ = ()

    def execute(self, sql, parameters=None):
        arguments = (sql,) if parameters is None else (sql, parameters)
        cursor = self._manager
        result = self._call(lambda: cursor.execute(*arguments))
        if result is not cursor:
            raise RevocationWriterConnectionError("revocation writer execute replaced its cursor handle")
        return _Result(result, self)

    def fetchone(self):
        cursor = self._manager
        return self._call(lambda: cursor.fetchone())

    def fetchall(self):
        cursor = self._manager
        return self._call(lambda: cursor.fetchall())

    def fetchmany(self, size):
        cursor = self._manager
        return self._call(lambda: cursor.fetchmany(size))

    @property
    def rowcount(self):
        cursor = self._manager
        value = self._call(lambda: cursor.rowcount)
        if type(value) is not int:
            raise RevocationWriterConnectionError("revocation writer rowcount is not an exact integer")
        return value


class _Result:
    __slots__ = ("_result", "_cursor", "_binding")

    def __init__(self, result, cursor):
        self._result, self._cursor = result, cursor
        self._binding = result, cursor

    def _call(self, method, *args):
        binding = self._binding
        if type(binding) is not tuple or len(binding) != 2:
            raise RevocationWriterConnectionError("revocation writer result binding is invalid")
        result, cursor = binding

        def invoke():
            if self._binding is not binding or not _same_slots((self._result, self._cursor), binding):
                raise RevocationWriterConnectionError("revocation writer result binding changed")
            value = getattr(result, method)(*args)
            if self._binding is not binding or not _same_slots((self._result, self._cursor), binding):
                raise RevocationWriterConnectionError("revocation writer result binding changed")
            return value

        return cursor._call(invoke)

    def fetchone(self):
        return self._call("fetchone")

    def fetchall(self):
        return self._call("fetchall")

    def fetchmany(self, size):
        return self._call("fetchmany", size)

    @property
    def rowcount(self):
        # execute returns the same actual cursor, and this delegates to the
        # separately bound cursor's guarded real property, never a CAS boolean.
        binding = self._binding
        if (type(binding) is not tuple or len(binding) != 2
                or not _same_slots((self._result, self._cursor), binding)):
            raise RevocationWriterConnectionError("revocation writer result binding changed")
        value = binding[1].rowcount
        if self._binding is not binding or not _same_slots((self._result, self._cursor), binding):
            raise RevocationWriterConnectionError("revocation writer result binding changed")
        return value


def _run_on_connection(connection, *, database_identity, work, operation, arguments, expectations):
    """Own an already-open handle through real admission, custody and cleanup."""
    try:
        _validate_database_identity(database_identity)
        reader.roots.batch._SharedLedger(work)
        from serverware import db

        original = _callback(work, reader._connection_identity, connection, 0)
        with reader._context(connection, work) as active:
            if active is not connection:
                raise RevocationWriterConnectionError("revocation writer connection context replaced its handle")
            _callback(work, reader._require_connection, connection, original, 0)
            transaction = _callback(work, lambda: connection.transaction())
            _callback(work, reader._require_connection, connection, original, 0)
            with reader._context(transaction, work) as entered:
                if entered is not transaction:
                    raise RevocationWriterConnectionError("revocation writer outer transaction replaced its handle")
                _callback(work, reader._require_connection, connection, original, 2)
                guarded = _Connection(connection, original, work)
                with guarded.cursor() as cursor:
                    cursor.execute(_SET_TRANSACTION)
                    _admit_identity(cursor.execute(_IDENTITY_SQL).fetchone(), database_identity)
                    if cursor.execute(*planner_writer_privilege_check(
                            role=database_identity[0], namespace="serverware_metadata")).fetchone() is not None:
                        raise RevocationWriterConnectionError("revocation writer effective privileges are not source exact")
                guarded._call(lambda: None)
                result = operation(connection=db.PostgresMetadataConnection(guarded),
                    work=work, **arguments, **expectations)
                guarded._call(lambda: None)
            _callback(work, reader._require_connection, connection, original, 0)
        if _callback(work, lambda: connection.closed) is not True:
            raise RevocationWriterConnectionError("revocation writer connection was not closed")
        return result
    except reader.roots.RevocationRootReadError as exc:
        reader._close_after_failure(connection)
        raise RevocationWriterConnectionError(str(exc)) from exc
    except BaseException:
        reader._close_after_failure(connection)
        raise
