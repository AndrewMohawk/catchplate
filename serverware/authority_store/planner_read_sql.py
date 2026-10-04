"""Fixed planner SELECT-only ACL producer, run inside the bootstrap transaction.

This grants no runtime, writer, sequence or function authority. The caller owns
schema/object creation, PUBLIC/default ACL sealing and the transaction. Success
is catalog privilege evidence, not TLS authentication or database currentness.
"""
from __future__ import annotations

import re

from serverware import authority_contract
from serverware.authority_store.verifier_read_sql import (
    VERIFIER_READ_PRIVILEGE_SQL,
    VERIFIER_READ_PRIVILEGE_SQL_DIGEST,
)

ROLE = "serverware_policy_authority_planner"
EXCLUDED_TABLES = frozenset({
    authority_contract.CURRENT_ROOT_COMMIT_MARKER_TABLE,
    authority_contract.SUCCESSOR_EXECUTION_CUSTODY_TABLE,
})
PRIVILEGE_SQL_DIGEST = VERIFIER_READ_PRIVILEGE_SQL_DIGEST


def privilege_contract() -> dict:
    return dict(role=ROLE, excludedTables=sorted(EXCLUDED_TABLES),
                tablePrivileges=["SELECT"], relationKinds=["r", "p"],
                privilegeSqlDigest=PRIVILEGE_SQL_DIGEST)


def _identifier(value: str) -> str:
    if type(value) is not str or re.fullmatch(r"[a-z][a-z0-9_]{0,62}", value) is None:
        raise ValueError("planner read ACL identifier refused")
    return '"' + value + '"'


def seal_planner_read_acl(cur, *, namespace: str) -> None:
    """Apply and check the fixed role's ACL using a real dict-row cursor."""
    if namespace not in {"serverware_metadata", "serverware_candidate_authority_expected_v9"}:
        raise ValueError("planner read ACL namespace refused")
    schema, role = _identifier(namespace), _identifier(ROLE)
    rows = cur.execute(
        "SELECT relation.relname AS table_name FROM pg_catalog.pg_class AS relation "
        "JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
        "WHERE namespace.nspname = %s AND relation.relkind IN ('r', 'p') "
        "ORDER BY relation.relname", (namespace,),
    ).fetchall()
    tables = [row["table_name"] for row in rows if row["table_name"] not in EXCLUDED_TABLES]
    if not tables:
        raise ValueError("planner read ACL has no source tables")
    names = [_identifier(table) for table in tables]
    cur.execute("REVOKE ALL ON SCHEMA " + schema + " FROM " + role)
    for objects in ("TABLES", "SEQUENCES", "FUNCTIONS"):
        cur.execute("REVOKE ALL ON ALL " + objects + " IN SCHEMA " + schema + " FROM " + role)
    cur.execute("GRANT USAGE ON SCHEMA " + schema + " TO " + role)
    for name in names:
        cur.execute("GRANT SELECT ON " + schema + "." + name + " TO " + role)
    violation = cur.execute(VERIFIER_READ_PRIVILEGE_SQL, (ROLE, namespace, tables)).fetchone()
    if violation is not None:
        raise ValueError("PostgreSQL planner effective read privileges are not source exact")
