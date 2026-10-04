#!/usr/bin/env python3
"""Create only the absent PostgreSQL roles selected by the existing source.

This is not schema bootstrap, credential issuance or authority admission.
Existing roles are never adopted, altered or repaired.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import time


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
MODE = "metadata-bootstrap"
REQUIRED_ROLES = (
    "SERVERWARE_METADATA_STORE_RUNTIME_ROLE", "SERVERWARE_AUDIT_STORE_RUNTIME_ROLE",
    "SERVERWARE_METADATA_STORE_AUTHORITY_EXECUTOR_ROLE",
    "SERVERWARE_METADATA_STORE_AUTHORITY_VERIFIER_ROLE",
)
USAGE = """Usage: python -I -B scripts/provision_metadata_roles.py --plan | --apply

Requires explicit SERVERWARE_PROCESS_MODE=metadata-bootstrap, PostgreSQL
metadata/audit selection and their configured runtime/executor/verifier role
names. --plan reports source-selected names without connecting. --apply uses
SERVERWARE_METADATA_STORE_ADMIN_POSTGRES_DSN and requires its actual same-session
superuser on the supported PostgreSQL version. Every selected role must be absent.
LOGIN roles have PASSWORD NULL; no credentials, memberships or grants are issued.
This does not establish usable runtime authentication or issue TLS identities.
Existing metadata bootstrap must separately install and admit exact schema ACLs.
"""


def _preflight(apply: bool) -> None:
    if os.environ.get("SERVERWARE_PROCESS_MODE", "").strip() != MODE:
        raise ValueError("explicit offline process mode is required")
    for name in ("METADATA_STORE", "AUDIT_STORE"):
        if os.environ.get("SERVERWARE_" + name + "_BACKEND", "").strip().lower() not in {"postgres", "postgresql"}:
            raise ValueError("PostgreSQL selection is required")
    required = REQUIRED_ROLES + (("SERVERWARE_METADATA_STORE_ADMIN_POSTGRES_DSN",) if apply else ())
    if any(not os.environ.get(name, "").strip() for name in required):
        raise ValueError("explicit role configuration is required")


def _load_db():
    from serverware import db
    return db


def role_plan(db) -> tuple[tuple[str, bool], ...]:
    from serverware.authority_store.planner_read_sql import ROLE as planner_role

    roles = [
        (db._METADATA_STORE_RUNTIME_ROLE, True),
        (db._METADATA_STORE_AUTHORITY_EXECUTOR_ROLE, True),
        (db._METADATA_STORE_AUTHORITY_VERIFIER_ROLE, True),
        (db._METADATA_STORE_AUTHORITY_CAPABILITY_ISSUER_ROLE, True),
        (planner_role, True),
        (db._METADATA_STORE_AUTHORITY_PLANNER_WRITER_ROLE, True),
        (db._METADATA_STORE_AUTHORITY_COMPLETION_READER_ROLE, True),
        (db.authority_contract.SUCCESSOR_ISSUER_ROLE, True),
        (db.authority_contract.SUCCESSOR_EXECUTOR_ROLE, True),
        (db.authority_contract.SUCCESSOR_RECOVERY_ROLE, True),
        (db._policy_file_read_sql.ROLE, True),
        (db._policy_file_genesis_sql.ROLE, True),
        (db._METADATA_STORE_AUTHORITY_OWNER_ROLE, False),
    ]
    if len({name for name, _ in roles}) != len(roles):
        raise ValueError("authority roles must remain separate")
    # Auxiliary runtime schemas may use the same hot runtime login; they may
    # not turn an owner or separate authority purpose into that runtime login.
    runtime_names = {db._METADATA_STORE_RUNTIME_ROLE}
    auxiliary = [db._AUDIT_STORE_RUNTIME_ROLE]
    if db.recovery_witness_uses_postgres():
        auxiliary.append(db._RECOVERY_WITNESS_RUNTIME_ROLE)
    for name in auxiliary:
        if name not in runtime_names:
            if name in {role for role, _ in roles}:
                raise ValueError("auxiliary runtime role overlaps authority")
            roles.append((name, True))
            runtime_names.add(name)
    for name, _ in roles:
        if type(name) is not str or len(name) > 63:
            raise ValueError("role name exceeds the existing PostgreSQL role contract")
        db._policy_candidate_authority_identifier(name)
    return tuple(roles)


def create_roles(connection, db, roles, deadline: float) -> None:
    """Called only inside the actual administrator connection transaction."""
    identity = connection.execute(
        "SELECT current_user = session_user AS same_session, role_record.rolsuper AS superuser, "
        "pg_catalog.current_setting('server_version_num')::integer / 10000 AS major "
        "FROM pg_catalog.pg_roles AS role_record WHERE role_record.rolname = current_user"
    ).fetchone()
    if (identity is None or identity["same_session"] is not True or identity["superuser"] is not True
            or identity["major"] != db._POLICY_AUTHORITY_OWNER_POSTGRES_MAJOR):
        raise ValueError("administrator identity or PostgreSQL version refused")
    names = [name for name, _ in roles]
    if connection.execute("SELECT rolname FROM pg_catalog.pg_roles WHERE rolname = ANY(%s)", (names,)).fetchall():
        raise ValueError("a selected role already exists")
    for name, login in roles:
        if time.monotonic() >= deadline:
            raise TimeoutError("role provisioning deadline exceeded")
        connection.execute(
            "CREATE ROLE " + db._policy_candidate_authority_identifier(name)
            + (" LOGIN" if login else " NOLOGIN")
            + " NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD NULL"
        )
    observed = connection.execute(
        "SELECT rolname, rolcanlogin, (rolsuper OR rolcreatedb OR rolcreaterole OR rolinherit "
        "OR rolreplication OR rolbypassrls OR rolpassword IS NOT NULL OR EXISTS ("
        "SELECT 1 FROM pg_catalog.pg_auth_members AS membership "
        "WHERE membership.member = role_record.oid OR membership.roleid = role_record.oid)) AS unexpected "
        "FROM pg_catalog.pg_authid AS role_record WHERE rolname = ANY(%s)", (names,)
    ).fetchall()
    if (len(observed) != len(roles) or {row["rolname"]: row["rolcanlogin"] for row in observed} != dict(roles)
            or any(row["unexpected"] is not False for row in observed)):
        raise ValueError("created role attributes differ from the selected plan")
    if time.monotonic() >= deadline:
        raise TimeoutError("role provisioning deadline exceeded")


def _apply(db, roles) -> None:
    import psycopg
    from psycopg.rows import dict_row
    deadline = time.monotonic() + 30
    with psycopg.connect(os.environ["SERVERWARE_METADATA_STORE_ADMIN_POSTGRES_DSN"],
                         connect_timeout=5, row_factory=dict_row,
                         options="-c search_path=pg_catalog -c statement_timeout=5000 -c lock_timeout=1000") as connection:
        create_roles(connection, db, roles, deadline)


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments == ["--help"]:
        print(USAGE, end="")
        return 0
    if arguments not in (["--plan"], ["--apply"]):
        print("role provisioning refused: choose --plan or --apply; no argument secrets", file=sys.stderr)
        return 2
    try:
        applying = arguments == ["--apply"]
        _preflight(applying)
        db = _load_db()
        db._reject_runtime_metadata_admin_dsn()
        roles = role_plan(db)
        if applying:
            _apply(db, roles)
    except (Exception, KeyboardInterrupt):
        print("role provisioning refused or failed; inspect database outcome before retry; credentials withheld", file=sys.stderr)
        return 1
    print(json.dumps({"mode": "created" if applying else "plan",
                      "roles": [{"name": name, "login": login} for name, login in roles],
                      "credentialsIssued": False, "schemaGrantsInstalled": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
