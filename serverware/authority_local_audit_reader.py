"""Separate local first-inclusion reader; existing verifier grants are unchanged.

The fixed catalog guard reuses the existing SELECT-only privilege query with a
different, source-owned role and table roster. Provisioning is an explicit,
separate administrator operation, never performed by the signing issuer.
"""
from __future__ import annotations

ROLE = "serverware_local_audit_inclusion_reader"
SCHEMA = "serverware_metadata"
REFERENCE_SCHEMA = "serverware_candidate_authority_expected_v9"
PROFILE_ID = "serverware.localAuditReaderBootstrap/v1"
TABLES = frozenset({
    "policy_authority_genesis_finalizations", "policy_authority_audit_inclusion_heads",
    "policy_authority_audit_inclusion_receipts", "policy_high_water", "policy_publications",
    "policy_authority_genesis_preparations", "policy_authority_transition_audits",
    "metadata_audit_outbox", "policy_authority_evidence_verifications",
    "policy_authority_trusted_keys", "policy_authority_trusted_key_heads",
    "policy_authority_trusted_key_revocations", "policy_runtime_role_keys",
})


def require_profile(profile):
    if type(profile) is not str or profile != PROFILE_ID:
        raise ValueError("local audit reader bootstrap profile is not source exact")


def profile_contract():
    """Fixed supported profile; actual selection is committed by its full ACLs."""
    return dict(profile=PROFILE_ID, role=ROLE, schema=SCHEMA,
        schemaPrivileges=["USAGE"], tablePrivileges={table:["SELECT"] for table in sorted(TABLES)},
        freshRoleOnly=True, production=False, grantOption=False,
        inherit=False, passwordAbsent=True)


def privilege_check(*, schema=SCHEMA):
    if schema not in (SCHEMA, REFERENCE_SCHEMA):
        raise ValueError("local audit reader namespace is not source exact")
    from serverware.authority_store.verifier_read_sql import VERIFIER_READ_PRIVILEGE_SQL
    return VERIFIER_READ_PRIVILEGE_SQL, (ROLE, schema, sorted(TABLES))


def _grant_namespace(cursor, schema, check):
    if schema not in (SCHEMA, REFERENCE_SCHEMA):
        raise ValueError("local audit reader namespace is not source exact")
    cursor.execute("GRANT USAGE ON SCHEMA " + schema + " TO " + ROLE)
    for table in sorted(TABLES):
        check()
        cursor.execute("GRANT SELECT ON TABLE " + schema + "." + table + " TO " + ROLE)


def grant_reference_profile(connection, *, profile):
    """Reproduce fixed grants in the rollback-only source reference namespace.

    The same fresh bootstrap transaction has already created the role. This
    path never creates/adopts a role or grants anything in the live namespace.
    """
    require_profile(profile)
    from serverware.authority_local_audit_inclusion import require
    with connection.cursor() as cursor:
        actual = cursor.execute("SELECT pg_catalog.current_schema() AS namespace, "
            "current_user = session_user AS same_session").fetchone()
        require(actual is not None and actual["namespace"] == REFERENCE_SCHEMA
            and actual["same_session"] is True)
        # Verify the fresh live role before reproducing only its reference ACLs.
        require(cursor.execute(*privilege_check()).fetchone() is None)
        attributes = cursor.execute("SELECT rolinherit, rolpassword IS NULL AS password_absent "
            "FROM pg_catalog.pg_authid WHERE rolname=%s", (ROLE,)).fetchone()
        require(attributes is not None and attributes["rolinherit"] is False
            and attributes["password_absent"] is True)
        _grant_namespace(cursor, REFERENCE_SCHEMA, lambda: None)
        require(cursor.execute(*privilege_check(schema=REFERENCE_SCHEMA)).fetchone() is None)


def provision(connection, *, database, check):
    """Fixed role-only addition inside one actual offline admin transaction.

    No existing role is changed, no credentials are issued, and no application
    row is written. Tables and guards must exist, but their first exact schema
    contract must be recorded only after these grants are included.
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
        _grant_namespace(cursor, SCHEMA, check)
        require(cursor.execute(*privilege_check()).fetchone() is None,
            "local audit reader exact SELECT-only privilege guard failed")
        actual = cursor.execute("SELECT rolinherit,rolpassword FROM pg_catalog.pg_authid WHERE rolname=%s", (ROLE,)).fetchone()
        require(actual is not None and actual["rolinherit"] is False and actual["rolpassword"] is None)
        check()
