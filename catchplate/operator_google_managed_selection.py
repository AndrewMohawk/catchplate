"""Exact managed-Google operation selection, never configuration authority.

The setup transaction owns this single pointer alongside its retained setup,
audit and encrypted custody records. Reads require the caller's existing SQLite
snapshot and perform no initialization, key access or configured imports.
Cancelled history is retained; neither reads nor writes choose a latest row.
"""
from __future__ import annotations

import json
import sqlite3
import uuid

TABLE = "operator_google_managed_selection"
SCHEMA = "catchplate.operatorGoogleManagedSelection/v1"
_ERROR = "operator Google managed selection unavailable"
_SQL = f"""CREATE TABLE {TABLE} (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema TEXT NOT NULL,
    operation_id TEXT) WITHOUT ROWID"""
_IMMUTABLE = f"""CREATE TRIGGER {TABLE}_immutable BEFORE UPDATE ON {TABLE}
    WHEN NEW.singleton IS NOT OLD.singleton OR NEW.schema IS NOT OLD.schema
    BEGIN SELECT RAISE(ABORT,'operator Google selection identity is immutable'); END"""
_RETAINED = f"""CREATE TRIGGER {TABLE}_retained BEFORE DELETE ON {TABLE}
    BEGIN SELECT RAISE(ABORT,'operator Google selection must be retained'); END"""
_INSERT = f"""CREATE TRIGGER {TABLE}_insert_guard BEFORE INSERT ON {TABLE}
    WHEN EXISTS (SELECT 1 FROM {TABLE})
    BEGIN SELECT RAISE(ABORT,'operator Google selection already exists'); END"""
_DEFINITIONS = ((TABLE, "table", _SQL), (TABLE + "_immutable", "trigger", _IMMUTABLE),
    (TABLE + "_retained", "trigger", _RETAINED), (TABLE + "_insert_guard", "trigger", _INSERT))


class SelectionUnavailable(RuntimeError):
    """Fixed non-secret refusal; absence is represented only by a valid None."""


def _require(condition):
    if not condition:
        raise SelectionUnavailable(_ERROR)


def _identifier(value):
    _require(type(value) is str and len(value) == 36 and str(uuid.UUID(value)) == value)
    return value


def _transaction(conn, *, writing=False):
    _require(isinstance(conn, sqlite3.Connection) and conn.in_transaction)
    if writing:
        from catchplate.operator_publication import assert_held
        assert_held()


def _pointer(conn):
    """Return (schema present, exact pointer), rejecting partial/case aliases."""
    # Preserve the legacy setup decoder's no-transaction absence inspection.
    # A retained selector and the public read_selection API require a snapshot.
    _require(isinstance(conn, sqlite3.Connection))
    objects = conn.execute("SELECT name,type,tbl_name,sql FROM sqlite_master "
        "WHERE lower(name) GLOB 'operator_google_managed_selection*' "
        "OR lower(tbl_name)=? LIMIT 6", (TABLE,)).fetchall()
    if not objects:
        return False, None
    _transaction(conn)
    _require(len(objects) == len(_DEFINITIONS))
    found = {row[0]: row for row in objects}
    _require(set(found) == {item[0] for item in _DEFINITIONS})
    for name, kind, sql in _DEFINITIONS:
        row = found[name]
        _require(row[1] == kind and row[2] == TABLE and type(row[3]) is str
            and len(row[3]) <= 4096 and " ".join(row[3].split()) == " ".join(sql.split()))
    rows = conn.execute("SELECT singleton,schema,operation_id FROM " + TABLE + " LIMIT 2").fetchall()
    _require(len(rows) == 1 and type(rows[0][0]) is int and rows[0][0] == 1 and rows[0][1] == SCHEMA)
    operation_id = rows[0][2]
    if operation_id is not None:
        _identifier(operation_id)
    return True, operation_id


def _validate_items(conn, items):
    """Join already decoded setup/audit/custody rows without recursive reads."""
    from catchplate import operator_google_setup as setup
    present, operation_id = _pointer(conn)
    managed = [item for item in items if setup._managed(item)]
    selected = [item for item in managed if setup._managed_configuration(item)]
    if not selected:
        _require(not present)
        return None
    _require(present and len(selected) == len(managed))
    active = [item for item in selected if item["status"] != "cancelled"]
    if operation_id is None:
        _require(not active)
        return None
    _require(len(active) == 1 and active[0]["operation_id"] == operation_id
        and active[0]["status"] in {"pending", "activated"})
    return active[0]


def read_selection(conn):
    """Return the exact selected public v2 operation or a validated empty state.

    A v1 managed foundation is never adopted. A retained v2 namespace requires
    its original singleton; a null pointer is valid only for cancelled history.
    The caller separately admits runtime ownership and authenticates the secret.
    """
    try:
        from catchplate import operator_google_setup as setup
        _transaction(conn)
        items = setup._rows(conn)
        _require(not any(setup._managed(item) and not setup._managed_configuration(item) for item in items))
        selected = _validate_items(conn, items)
        return setup._public(selected) if selected is not None else None
    except (sqlite3.Error, ValueError, TypeError, KeyError, IndexError, AttributeError, RuntimeError):
        raise SelectionUnavailable(_ERROR) from None


def install_empty(conn):
    """Writer-only first installation; caller proved full retained-state absence."""
    try:
        from catchplate import operator_google_setup as setup
        _transaction(conn, writing=True)
        present, _ = _pointer(conn)
        _require(not present and not any(setup._managed(item) for item in setup._rows(conn)))
        for _, _, sql in _DEFINITIONS:
            conn.execute(sql)
        conn.execute("INSERT INTO " + TABLE + " VALUES(1,?,NULL)", (SCHEMA,))
    except (sqlite3.Error, ValueError, TypeError, KeyError, IndexError, AttributeError, RuntimeError):
        raise SelectionUnavailable(_ERROR) from None


def _change(conn, operation_id, *, clearing):
    try:
        from catchplate import operator_google_setup as setup
        _transaction(conn, writing=True)
        _identifier(operation_id)
        present, prior = _pointer(conn)
        _require(present and (prior == operation_id if clearing else prior is None))
        row = conn.execute("SELECT status,binding_json FROM " + setup.TABLE + " WHERE operation_id=?",
            (operation_id,)).fetchone()
        _require(row is not None and row[0] == ("cancelled" if clearing else "pending")
            and type(row[1]) is str and len(row[1].encode("utf-8")) <= 32768)
        binding = json.loads(row[1])
        _require(type(binding) is dict and binding.get("setup_contract") == setup.MANAGED_BINDING_V2
            and binding.get("operation_id") == operation_id)
        changed = conn.execute("UPDATE " + TABLE + " SET operation_id=? WHERE singleton=1 AND operation_id IS ?",
            (None if clearing else operation_id, prior))
        _require(changed.rowcount == 1)
        # The caller has already appended the matching prepared/cancelled audit.
        # Validate the complete resulting setup/custody/selection join now.
        setup._rows(conn)
    except (sqlite3.Error, ValueError, TypeError, KeyError, IndexError, AttributeError, RuntimeError):
        raise SelectionUnavailable(_ERROR) from None


def select_pending(conn, operation_id):
    _change(conn, operation_id, clearing=False)


def clear_cancelled(conn, operation_id):
    _change(conn, operation_id, clearing=True)
