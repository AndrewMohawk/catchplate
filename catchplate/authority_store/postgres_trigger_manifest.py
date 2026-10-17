"""PostgreSQL trigger inventories shared by structural admission and diagnostics.

The connection is the native, already-authorized migration connection with
mapping rows. These readers neither install objects nor grant admission. Mode
codes are committed verbatim; only exact comparison with a source-generated
manifest decides whether a known mode is admissible.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any


def trigger_enabled_mode(row: Mapping[str, Any]) -> str:
    mode = row.get("enabled_mode")
    if not isinstance(mode, str) or mode not in {"O", "A", "R", "D"}:
        raise ValueError("PostgreSQL trigger enabled mode is missing or invalid")
    return mode


def table_trigger_manifest(
    connection: Any,
    *,
    namespace: str,
    table: str,
    canonical_definition: Callable[[Any], str],
    object_definition: Callable[..., dict[str, str]],
) -> list[dict[str, Any]]:
    rows = connection.execute(
        """
        SELECT trigger_record.tgname AS trigger_name,
               function_record.proname AS function_name,
               trigger_record.tgenabled::text AS enabled_mode,
               pg_catalog.pg_get_triggerdef(trigger_record.oid, true) AS definition
        FROM pg_catalog.pg_trigger AS trigger_record
        JOIN pg_catalog.pg_class AS relation
          ON relation.oid = trigger_record.tgrelid
        JOIN pg_catalog.pg_namespace AS namespace_record
          ON namespace_record.oid = relation.relnamespace
        JOIN pg_catalog.pg_proc AS function_record
          ON function_record.oid = trigger_record.tgfoid
        WHERE namespace_record.nspname = %s AND relation.relname = %s
          AND NOT trigger_record.tgisinternal
        ORDER BY trigger_record.tgname
        """,
        (namespace, table),
    ).fetchall()
    return [
        {
            "name": str(row["trigger_name"]),
            "function": str(row["function_name"]),
            "enabledMode": trigger_enabled_mode(row),
            "authority": {"owner": "table-owner", "acl": "not-applicable"},
            **object_definition(
                name=str(row["trigger_name"]),
                definition=canonical_definition(row["definition"]),
            ),
        }
        for row in rows
    ]


def schema_trigger_manifest(
    connection: Any, *, namespace: str,
) -> list[dict[str, Any]]:
    rows = connection.execute(
        """
        SELECT trigger_record.tgname AS trigger_name,
               relation.relname AS table_name,
               function_record.proname AS function_name,
               trigger_record.tgenabled::text AS enabled_mode
        FROM pg_catalog.pg_trigger AS trigger_record
        JOIN pg_catalog.pg_class AS relation
          ON relation.oid = trigger_record.tgrelid
        JOIN pg_catalog.pg_namespace AS namespace_record
          ON namespace_record.oid = relation.relnamespace
        JOIN pg_catalog.pg_proc AS function_record
          ON function_record.oid = trigger_record.tgfoid
        WHERE namespace_record.nspname = %s AND NOT trigger_record.tgisinternal
        ORDER BY relation.relname, trigger_record.tgname
        """,
        (namespace,),
    ).fetchall()
    return [
        {
            "name": str(row["trigger_name"]),
            "table": str(row["table_name"]),
            "function": str(row["function_name"]),
            "enabledMode": trigger_enabled_mode(row),
            "owner": "table-owner",
            "acl": "not-applicable",
        }
        for row in rows
    ]
