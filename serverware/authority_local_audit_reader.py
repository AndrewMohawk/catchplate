"""Separate local first-inclusion reader; existing verifier grants are unchanged.

The fixed catalog guard reuses the existing SELECT-only privilege query with a
different, source-owned role and table roster. Provisioning is an explicit,
separate administrator operation, never performed by the signing issuer.
"""
from __future__ import annotations

ROLE = "serverware_local_audit_inclusion_reader"
SCHEMA = "serverware_metadata"
TABLES = frozenset({
    "policy_authority_genesis_finalizations", "policy_authority_audit_inclusion_heads",
    "policy_authority_audit_inclusion_receipts", "policy_high_water", "policy_publications",
    "policy_authority_genesis_preparations", "policy_authority_transition_audits",
    "metadata_audit_outbox", "policy_authority_evidence_verifications",
    "policy_authority_trusted_keys", "policy_authority_trusted_key_heads",
    "policy_authority_trusted_key_revocations", "policy_runtime_role_keys",
})


def privilege_check():
    from serverware.authority_store.verifier_read_sql import VERIFIER_READ_PRIVILEGE_SQL
    return VERIFIER_READ_PRIVILEGE_SQL, (ROLE, SCHEMA, sorted(TABLES))


def provision(connection, *, database, check):
    """Fixed role-only addition inside one actual offline admin transaction.

    No existing role is changed, no credentials are issued, and no application
    row is written. The complete schema must already have been bootstrapped.
    """
    from serverware import db
    from serverware.authority_local_audit_inclusion import require
    import re
    require(type(database) is str and re.fullmatch(r"[a-z][a-z0-9_]{0,62}", database) is not None)
    check()
    with connection.cursor() as cursor:
        actual = cursor.execute("SELECT current_user=session_user AS same_session, "
            "role_record.rolsuper AS superuser, pg_catalog.current_database() AS database, "
            "pg_catalog.current_setting('server_version_num')::integer/10000 AS major "
            "FROM pg_catalog.pg_roles role_record WHERE role_record.rolname=current_user").fetchone()
        require(actual is not None and actual["same_session"] is True and actual["superuser"] is True
            and actual["database"] == database and actual["major"] == db._POLICY_AUTHORITY_OWNER_POSTGRES_MAJOR)
        require(cursor.execute("SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=%s", (ROLE,)).fetchone() is None,
            "local audit reader already exists; no adoption or overwrite")
        relations = cursor.execute("SELECT relation.relname FROM pg_catalog.pg_class relation "
            "JOIN pg_catalog.pg_namespace namespace ON namespace.oid=relation.relnamespace "
            "WHERE namespace.nspname=%s AND relation.relkind IN ('r','p') AND relation.relname=ANY(%s)",
            (SCHEMA, sorted(TABLES))).fetchall()
        require({row["relname"] for row in relations} == TABLES,
            "local audit reader requires the already bootstrapped exact metadata tables")
        check()
        cursor.execute("CREATE ROLE " + ROLE + " LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
            "NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD NULL")
        cursor.execute("GRANT USAGE ON SCHEMA " + SCHEMA + " TO " + ROLE)
        for table in sorted(TABLES):
            check()
            cursor.execute("GRANT SELECT ON TABLE " + SCHEMA + "." + table + " TO " + ROLE)
        require(cursor.execute(*privilege_check()).fetchone() is None,
            "local audit reader exact SELECT-only privilege guard failed")
        actual = cursor.execute("SELECT rolinherit,rolpassword FROM pg_catalog.pg_authid WHERE rolname=%s", (ROLE,)).fetchone()
        require(actual is not None and actual["rolinherit"] is False and actual["rolpassword"] is None)
        check()
