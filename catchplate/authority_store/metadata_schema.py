from __future__ import annotations

import sqlite3
import re
from functools import lru_cache
from collections.abc import Mapping
from typing import Any

_DB_GLOBALS: Mapping[str, Any] | None = None


@lru_cache(maxsize=128)
def _sqlite_constraint_pattern(pattern: str):
    if not pattern.startswith("^") or not pattern.endswith("$"):
        raise ValueError("SQLite metadata constraints require anchored source patterns")
    return re.compile(pattern)


def configure_sqlite_metadata_connection(conn: sqlite3.Connection) -> None:
    """Preserve source-owned PostgreSQL regex CHECKs in the SQLite dialect."""
    def regexp(pattern, value):
        if value is None:
            return None
        return int(isinstance(value, str) and _sqlite_constraint_pattern(pattern).fullmatch(value) is not None)
    conn.create_function("regexp", 2, regexp, deterministic=True)


def _sqlite_schema_statement(statement: str) -> str:
    # Only operators outside SQL strings/comments are translated. PostgreSQL's
    # static schema remains byte-identical; no constraint is removed. The
    # current source patterns use the common anchored ASCII regex subset.
    tokens = re.compile(r"'(?:''|[^'])*'|--[^\n]*|/\*.*?\*/|COLLATE\s+\"C\"|~", re.DOTALL)
    return tokens.sub(lambda match: "REGEXP" if match[0] == "~" else
                      "COLLATE BINARY" if match[0].startswith("COLLATE") else match[0], statement)


def bind_db_globals(namespace: Mapping[str, Any]) -> None:
    global _DB_GLOBALS
    _DB_GLOBALS = namespace


def _db_value(name: str) -> Any:
    if _DB_GLOBALS is None:
        raise RuntimeError("database facade globals are not bound")
    return _DB_GLOBALS[name]


def _metadata_table_exists(conn: Any, table: str) -> bool:
    if isinstance(conn, _db_value("PostgresMetadataConnection")):
        row = conn.execute(
            "SELECT pg_catalog.to_regclass("
            "pg_catalog.current_schema() || '.' || ?) "
            "IS NOT NULL AS present",
            (table,),
        ).fetchone()
        return bool(row and row["present"])
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1",
        (table,),
    ).fetchone()
    return row is not None


def _sqlite_execute_fixed_statements(
    conn: sqlite3.Connection,
    script: str,
) -> None:
    """Execute a static DDL program without sqlite3.executescript auto-commits."""
    configure_sqlite_metadata_connection(conn)
    pending = ""
    statements: list[str] = []
    for line in script.splitlines(keepends=True):
        pending += line
        if sqlite3.complete_statement(pending):
            statement = pending.strip()
            pending = ""
            if statement:
                statements.append(statement)
    if pending.strip():
        raise _db_value("PolicyCandidateAuthorityError")(
            "candidate-authority static DDL contains an incomplete statement"
        )
    for statement in statements:
        leading = statement.lstrip().upper()
        if leading.startswith(
            (
                "BEGIN",
                "COMMIT",
                "END TRANSACTION",
                "ROLLBACK",
                "SAVEPOINT",
                "RELEASE",
                "PRAGMA FOREIGN_KEYS",
            )
        ):
            raise _db_value("PolicyCandidateAuthorityError")(
                "candidate-authority static DDL contains transaction control"
            )
        conn.execute(_sqlite_schema_statement(statement))


def _execute_metadata_schema_statements(conn: Any, script: str) -> None:
    if isinstance(conn, _db_value("PostgresMetadataConnection")):
        conn.executescript(script)
        return
    _sqlite_execute_fixed_statements(conn, script)


for _compatibility_export in (
    _metadata_table_exists,
    _sqlite_execute_fixed_statements,
    _execute_metadata_schema_statements,
):
    _compatibility_export.__module__ = "catchplate.db"
del _compatibility_export
