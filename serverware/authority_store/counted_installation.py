"""Transaction-local, fresh-only preparation of the dedicated counted store.

Existing stores are checked, never repaired or populated here. Genesis requires
all six source tables to be empty under write-excluding locks. These local
representation checks do not authenticate population, primary/count root
association, enrollment or currentness. The caller owns its active transaction,
catalog/ACL admission and installation of the real all-writer trigger.
"""
from __future__ import annotations

import re
from typing import Any

from serverware import authority_index_contract as counted
from serverware import authority_index_projection as projection
from serverware.authority_store import counted_hash_sql, counted_projection_sql
from serverware.authority_store import counted_path_sql, counted_maintenance_sql
from serverware.authority_store.counted_store_sql import (
    COUNTED_HEAD_COLUMNS, COUNTED_STORE_TABLES, counted_store_ddl,
)


COUNTED_SOURCE_TABLES = (
    "approval_grants", "control_plane_approvals", "oidc_browser_sessions",
    "webauthn_challenges", "webauthn_credentials", "webauthn_trust_publications",
)
_RELATIONS = tuple(sorted((*COUNTED_SOURCE_TABLES, *COUNTED_STORE_TABLES)))
_CATALOG_FIELDS = frozenset({"relation_name", "relation_oid", "relation_kind",
                             "persistence", "is_partition", "has_inheritance"})
_HEAD_FIELDS = frozenset(COUNTED_HEAD_COLUMNS)


class CountedInstallationError(ValueError):
    pass


def _namespace(value: str) -> str:
    if (type(value) is not str or len(value) > 65
            or re.fullmatch(r'"[a-z][a-z0-9_]{0,62}"', value) is None):
        raise CountedInstallationError("counted installation namespace is not an exact quoted identifier")
    return value


def _genesis_heads() -> tuple[dict[str, Any], ...]:
    profiles = tuple(projection.profile_for(name) for name in projection.INDEX_IDS)
    if (len(profiles) != 11 or len({item.index_id for item in profiles}) != 11
            or tuple(sorted({item.table for item in profiles})) != COUNTED_SOURCE_TABLES):
        raise CountedInstallationError("counted installation source inventory changed")
    manifest = projection.projection_manifest_digest()
    return tuple({"index_id": item.index_id, "table_name": item.table,
        "counted_profile": counted.PROFILE, "projection_digest": item.projection_digest,
        "projection_manifest_digest": manifest, "index_revision": 0,
        "root_digest": counted.empty_node(item, "").digest, "leaf_count": 0}
        for item in sorted(profiles, key=lambda item: item.index_id))


def counted_functions_sql(namespace: str) -> tuple[str, ...]:
    """Actual definitions in dependency order, after primary/wire helpers."""
    namespace = _namespace(namespace)
    return (counted_hash_sql.counted_hash_functions_sql(namespace)
            + counted_projection_sql.counted_projection_functions_sql(namespace)
            + counted_path_sql.counted_path_functions_sql(namespace)
            + counted_maintenance_sql.counted_maintenance_functions_sql(namespace))


def counted_installation_contract() -> dict[str, Any]:
    """Pure source material for the existing schema-contract digest, not trust."""
    namespace = '"serverware_metadata"'
    return {"schema": "serverware.policyAuthorityCountedInstallation/v1",
        "profile": "transaction-locked-fresh-empty-or-exact-existing-no-repair/v1",
        "sourceTables": list(COUNTED_SOURCE_TABLES),
        "storeTables": list(COUNTED_STORE_TABLES),
        "ddl": list(counted_store_ddl(namespace)),
        "functions": list(counted_functions_sql(namespace)),
        "genesisHeads": list(_genesis_heads())}


def _inventory(conn: Any, namespace: str) -> dict[str, int]:
    rows = conn.execute(
        "SELECT relation.relname::pg_catalog.text AS relation_name, "
        "relation.oid::pg_catalog.int8 AS relation_oid, "
        "relation.relkind::pg_catalog.text AS relation_kind, "
        "relation.relpersistence::pg_catalog.text AS persistence, "
        "relation.relispartition AS is_partition, "
        "EXISTS (SELECT 1 FROM pg_catalog.pg_inherits AS inheritance "
        "WHERE inheritance.inhrelid = relation.oid OR inheritance.inhparent = relation.oid) AS has_inheritance "
        "FROM pg_catalog.pg_class AS relation "
        "JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
        "WHERE namespace.nspname = ? AND relation.relname IN ("
        + ", ".join("?" for _ in _RELATIONS)
        + ") ORDER BY relation.relname COLLATE \"C\" LIMIT 10",
        (namespace[1:-1], *_RELATIONS),
    ).fetchmany(10)
    if type(rows) is not list or len(rows) > len(_RELATIONS):
        raise CountedInstallationError("counted installation relation inventory exceeds its bound")
    found = {}
    for row in rows:
        if (type(row) is not dict or len(row) != len(_CATALOG_FIELDS)
                or any(type(key) is not str or len(key) > 32 for key in row)
                or set(row) != _CATALOG_FIELDS):
            raise CountedInstallationError("counted installation catalog row is not closed")
        name, oid = row["relation_name"], row["relation_oid"]
        if (type(name) is not str or len(name) > 63 or name not in _RELATIONS
                or name in found or type(oid) is not int or not 1 <= oid <= 2**32 - 1
                or type(row["relation_kind"]) is not str or row["relation_kind"] != "r"
                or type(row["persistence"]) is not str or row["persistence"] != "p"
                or row["is_partition"] is not False or row["has_inheritance"] is not False):
            raise CountedInstallationError("counted installation requires unique permanent ordinary nonpartitioned tables")
        found[name] = oid
    if not set(COUNTED_SOURCE_TABLES) <= found.keys():
        raise CountedInstallationError("counted installation source tables are incomplete")
    present = sum(name in found for name in COUNTED_STORE_TABLES)
    if present not in (0, len(COUNTED_STORE_TABLES)):
        raise CountedInstallationError("counted installation refuses a partial store")
    return found


def _lock(conn: Any, namespace: str, tables: tuple[str, ...]) -> None:
    for table in sorted(tables):
        conn.execute(f'LOCK TABLE ONLY {namespace}."{table}" IN SHARE ROW EXCLUSIVE MODE')


def _stable(before: dict[str, int], after: dict[str, int], tables: tuple[str, ...]) -> None:
    if any(before.get(table) != after.get(table) for table in tables):
        raise CountedInstallationError("counted installation relation identity changed across locks")


def _text_column(name: str, maximum: int) -> str:
    # Only fixed source column names reach this renderer. Bad catalog types or
    # oversized stored scalars become rejecting sentinels before driver output.
    return (f"CASE WHEN pg_catalog.pg_typeof(head.{name}) = 'pg_catalog.text'::pg_catalog.regtype "
            f"AND pg_catalog.octet_length(head.{name}) BETWEEN 1 AND {maximum} "
            f"THEN head.{name} ELSE NULL END AS {name}")


_HEAD_SELECT = ", ".join(
    (f"CASE WHEN pg_catalog.pg_typeof(head.{name}) = 'pg_catalog.int8'::pg_catalog.regtype "
     f"AND head.{name} BETWEEN 0 AND {counted.I64_MAX} THEN head.{name} ELSE NULL END AS {name}")
    if name in ("index_revision", "leaf_count") else
    _text_column(name, 71 if name.endswith("digest") else 128)
    for name in COUNTED_HEAD_COLUMNS
)


def _validate_heads(conn: Any, namespace: str, expected: tuple[dict[str, Any], ...]) -> None:
    rows = conn.execute(f'SELECT {_HEAD_SELECT} FROM {namespace}."{COUNTED_STORE_TABLES[0]}" '
                        'AS head LIMIT 12').fetchmany(12)
    if type(rows) is not list or len(rows) != 11:
        raise CountedInstallationError("counted installation requires the complete eleven-head inventory")
    by_id = {item["index_id"]: item for item in expected}
    seen = set()
    for row in rows:
        if (type(row) is not dict or len(row) != len(_HEAD_FIELDS)
                or any(type(key) is not str or len(key) > 32 for key in row)
                or set(row) != _HEAD_FIELDS):
            raise CountedInstallationError("counted installation head row is not closed")
        identity = row["index_id"]
        if (type(identity) is not str or len(identity) > 128
                or identity not in by_id or identity in seen):
            raise CountedInstallationError("counted installation head identity is missing, duplicated or unknown")
        source = by_id[identity]
        if any(type(row[name]) is not str or row[name] != source[name]
               for name in COUNTED_HEAD_COLUMNS[:5]):
            raise CountedInstallationError("counted installation head source commitment differs")
        revision, count, digest = row["index_revision"], row["leaf_count"], row["root_digest"]
        if (type(revision) is not int or not 0 <= revision <= counted.I64_MAX
                or type(count) is not int or not 0 <= count <= counted.I64_MAX
                or type(digest) is not str or len(digest) != 71
                or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
                or (revision == 0 and count != 0)
                or (count == 0) != (digest == source["root_digest"])):
            raise CountedInstallationError("counted installation head revision, count or root is invalid")
        seen.add(identity)


def prepare_counted_store(conn: Any, quoted_namespace: str) -> None:
    """Prepare fresh empty storage or validate existing descriptors, never repair.

    Requires the caller's active PostgreSQL transaction and source-created base
    tables. Locks remain held by that transaction. No transaction control,
    functions, grants, triggers, population rebuild or authority receipt occurs.
    Actual constraints, ownership and function catalogs still need the caller's
    complete installed-schema admission; existing heads are not population proof.
    """
    namespace = _namespace(quoted_namespace)
    if getattr(conn, "in_transaction", None) is not True:
        raise CountedInstallationError("counted installation requires the caller's active transaction")
    expected = _genesis_heads()
    before = _inventory(conn, namespace)
    _lock(conn, namespace, COUNTED_SOURCE_TABLES)
    locked = _inventory(conn, namespace)
    _stable(before, locked, COUNTED_SOURCE_TABLES)
    if COUNTED_STORE_TABLES[0] in before:
        _stable(before, locked, COUNTED_STORE_TABLES)
    if COUNTED_STORE_TABLES[0] in locked:
        _lock(conn, namespace, COUNTED_STORE_TABLES)
        stable = _inventory(conn, namespace)
        _stable(locked, stable, _RELATIONS)
        _validate_heads(conn, namespace, expected)
        return
    for table in COUNTED_SOURCE_TABLES:
        rows = conn.execute(f'SELECT 1 AS present FROM ONLY {namespace}."{table}" LIMIT 1').fetchmany(1)
        if type(rows) is not list or rows:
            raise CountedInstallationError("counted genesis requires empty source tables; authenticated offline restage is required")
    for statement in counted_store_ddl(namespace):
        conn.execute(statement)
    columns = ", ".join(COUNTED_HEAD_COLUMNS)
    placeholders = ", ".join("?" for _ in COUNTED_HEAD_COLUMNS)
    for head in expected:
        conn.execute(f'INSERT INTO {namespace}."{COUNTED_STORE_TABLES[0]}" ({columns}) '
                     f'VALUES ({placeholders})', tuple(head[name] for name in COUNTED_HEAD_COLUMNS))
    _validate_heads(conn, namespace, expected)
