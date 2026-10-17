"""Shared actual PostgreSQL facade and planner-writer transaction admission.

This module is registry-free. Binding is owned by the database facade, not by
an individual persistence request; no caller-supplied admission callback is
accepted by the store APIs.
"""
from __future__ import annotations

from collections.abc import Mapping
import time
from typing import Any


_DB_GLOBALS: Mapping[str, Any] | None = None


def bind_db_globals(namespace: Mapping[str, Any]) -> None:
    global _DB_GLOBALS
    _DB_GLOBALS = namespace


def _db_value(name: str) -> Any:
    if _DB_GLOBALS is None or name not in _DB_GLOBALS:
        raise RuntimeError(f"database facade binding is missing {name}")
    return _DB_GLOBALS[name]


def _require_postgres_connection(connection: Any) -> Any:
    postgres_connection = _db_value("PostgresMetadataConnection")
    if not isinstance(connection, postgres_connection):
        raise _db_value("MetadataStoreError")(
            "authority v9 APIs require the measured PostgreSQL facade"
        )
    return connection.raw_connection


def _require_serializable(raw: Any) -> None:
    with raw.cursor() as cursor:
        row = cursor.execute("SHOW transaction_isolation").fetchone()
    if row is None or row["transaction_isolation"] != "serializable":
        raise _db_value("MetadataStoreError")(
            "authority v9 write APIs require SERIALIZABLE"
        )


def _require_database_role(raw: Any, expected_role: str) -> None:
    with raw.cursor() as cursor:
        row = cursor.execute(
            "SELECT current_user AS current_role, "
            "session_user AS session_role, "
            "current_setting('transaction_read_only') AS read_only, "
            "current_setting('transaction_deferrable') AS deferrable"
        ).fetchone()
    if (
        row is None
        or row["current_role"] != expected_role
        or row["session_role"] != expected_role
        or row["read_only"] != "off"
        or row["deferrable"] != "off"
    ):
        raise _db_value("MetadataStoreError")(
            "authority database role or writer transaction mode is not exact"
        )


def _require_planner_writer(connection: Any) -> Any:
    raw = _require_postgres_connection(connection)
    _require_serializable(raw)
    _require_database_role(
        raw,
        _db_value("_METADATA_STORE_AUTHORITY_PLANNER_WRITER_ROLE"),
    )
    return raw


def _require_fresh_deadline(
    *,
    deadline_monotonic_ns: int,
    deadline_epoch_ns: int,
    reserved_at_epoch_ns: int,
) -> None:
    if (
        any(
            not isinstance(value, int) or isinstance(value, bool)
            for value in (
                deadline_monotonic_ns,
                deadline_epoch_ns,
                reserved_at_epoch_ns,
            )
        )
    ):
        raise ValueError("authority v9 deadline is not integral")
    now_monotonic_ns = time.monotonic_ns()
    now_epoch_ns = time.time_ns()
    maximum_age_ns = int(
        _db_value("_POLICY_AUTHORITY_VERIFIER_RESPONSE_MAX_AGE_NS")
    )
    maximum_skew_ns = int(
        _db_value("_POLICY_AUTHORITY_VERIFIER_MAX_CLOCK_SKEW_NS")
    )
    monotonic_remaining = deadline_monotonic_ns - now_monotonic_ns
    epoch_remaining = deadline_epoch_ns - now_epoch_ns
    if (
        reserved_at_epoch_ns > now_epoch_ns + maximum_skew_ns
        or now_epoch_ns - reserved_at_epoch_ns > maximum_age_ns
        or monotonic_remaining <= 0
        or epoch_remaining <= 0
        or monotonic_remaining > maximum_age_ns
        or epoch_remaining > maximum_age_ns + maximum_skew_ns
        or abs(monotonic_remaining - epoch_remaining) > maximum_skew_ns
    ):
        raise ValueError(
            "authority v9 deadline binding is stale or inconsistent"
        )
