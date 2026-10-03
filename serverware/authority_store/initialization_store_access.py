"""Observed identity and least-privilege admission for the local candidate store.

The fixed queries below read the actual session/catalogs on every call. Input
objects are expectations, never admission tokens. The caller owns transaction,
deadline and relation-lock ordering and must separately check the source schema.
This is not a freeze against administrator GRANT/DDL races, authentication of
an externally provisioned enrollment, or independent rollback/currentness proof.
Unrelated database privileged functions and trusted-administrator stability are
outside this dedicated-namespace check. No grant or other mutation is emitted.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, fields

from serverware.authority_store.audit_initialization_store_sql import (
    CANDIDATES, ENROLLMENTS,
)


class InitializationStoreAdmissionError(ValueError):
    pass


def _identifier(value: str) -> None:
    if type(value) is not str or re.fullmatch(r"[a-z][a-z0-9_]{0,62}", value) is None:
        raise InitializationStoreAdmissionError("initialization store identifier is invalid")


def _oid(value: int) -> None:
    if type(value) is not int or not 1 <= value <= 2**32 - 1:
        raise InitializationStoreAdmissionError("initialization store OID is invalid")


@dataclass(frozen=True, slots=True)
class InitializationStoreDatabaseIdentity:
    """Bounded expected primitives, not proof that this database was enrolled."""

    namespace: str
    database_name: str
    database_oid: int
    system_identifier: str
    runtime_role: str
    runtime_role_oid: int
    owner_role: str
    owner_role_oid: int
    backend_incarnation_digest: str

    def __post_init__(self) -> None:
        for value in (self.namespace, self.runtime_role, self.owner_role):
            _identifier(value)
        for value in (self.database_oid, self.runtime_role_oid, self.owner_role_oid):
            _oid(value)
        if (self.runtime_role == self.owner_role
                or self.runtime_role_oid == self.owner_role_oid):
            raise InitializationStoreAdmissionError("initialization store owner and runtime are not separated")
        if (type(self.database_name) is not str or not 1 <= len(self.database_name) <= 63
                or "\x00" in self.database_name):
            raise InitializationStoreAdmissionError("initialization store database name is invalid")
        try:
            name_bytes = self.database_name.encode("utf-8")
        except UnicodeError as exc:
            raise InitializationStoreAdmissionError("initialization store database name is invalid") from exc
        if len(name_bytes) > 63:
            raise InitializationStoreAdmissionError("initialization store database name is invalid")
        if (type(self.system_identifier) is not str
                or re.fullmatch(r"0|[1-9][0-9]{0,19}", self.system_identifier) is None
                or int(self.system_identifier) > 2**64 - 1):
            raise InitializationStoreAdmissionError("initialization store system identifier is invalid")
        if (type(self.backend_incarnation_digest) is not str
                or re.fullmatch(r"sha256:[0-9a-f]{64}", self.backend_incarnation_digest) is None):
            raise InitializationStoreAdmissionError("initialization store backend incarnation is invalid")


_CONTEXT_SQL = """SELECT
    pg_catalog.current_database()::pg_catalog.text AS database_name,
    database_record.oid::pg_catalog.int8 AS database_oid,
    control.system_identifier::pg_catalog.text AS system_identifier,
    current_user::pg_catalog.text AS current_role,
    session_user::pg_catalog.text AS session_role,
    pg_catalog.current_setting('session_replication_role') AS replication_role,
    pg_catalog.getdatabaseencoding() AS server_encoding,
    pg_catalog.current_setting('client_encoding') AS client_encoding,
    (pg_catalog.current_setting('server_version_num')::pg_catalog.int4
        BETWEEN 160000 AND 169999) AS postgres_16,
    (database_record.datcollversion IS NOT DISTINCT FROM
        pg_catalog.pg_database_collation_actual_version(database_record.oid)) AS collation_current
FROM pg_catalog.pg_control_system() AS control
JOIN pg_catalog.pg_database AS database_record
  ON database_record.datname = pg_catalog.current_database()
LIMIT 2"""

_ROLES_SQL = """SELECT role_record.rolname::pg_catalog.text AS role_name,
    role_record.oid::pg_catalog.int8 AS role_oid, role_record.rolcanlogin AS can_login,
    role_record.rolsuper AS superuser, role_record.rolcreaterole AS create_role,
    role_record.rolcreatedb AS create_database, role_record.rolreplication AS replication,
    role_record.rolbypassrls AS bypass_rls,
    EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members AS membership
        WHERE membership.member = role_record.oid OR membership.roleid = role_record.oid) AS has_membership
FROM pg_catalog.pg_roles AS role_record
WHERE role_record.oid = ANY(%s::pg_catalog.oid[])
   OR role_record.rolname::pg_catalog.text = ANY(%s::pg_catalog.text[])
LIMIT 5"""

_SCHEMA_SQL = """SELECT namespace.oid::pg_catalog.int8 AS namespace_oid,
    namespace.nspname::pg_catalog.text AS namespace_name,
    namespace.nspowner::pg_catalog.int8 AS owner_oid
FROM pg_catalog.pg_namespace AS namespace
WHERE namespace.nspname = %s
LIMIT 2"""

_TABLES_SQL = """SELECT relation.oid::pg_catalog.int8 AS relation_oid,
    relation.relname::pg_catalog.text AS table_name,
    relation.relowner::pg_catalog.int8 AS owner_oid,
    relation.relkind::pg_catalog.text AS relation_kind
FROM pg_catalog.pg_class AS relation
WHERE relation.relnamespace = %s::pg_catalog.oid
  AND relation.relname::pg_catalog.text = ANY(%s::pg_catalog.text[])
LIMIT 3"""

_ENVIRONMENT_PRIVILEGES_SQL = """SELECT
    pg_catalog.has_schema_privilege(%s::pg_catalog.oid, %s::pg_catalog.oid, 'USAGE') AS schema_usage,
    pg_catalog.has_schema_privilege(%s::pg_catalog.oid, %s::pg_catalog.oid,
        'CREATE,USAGE WITH GRANT OPTION,CREATE WITH GRANT OPTION') AS schema_extra,
    pg_catalog.has_database_privilege(%s::pg_catalog.oid, %s::pg_catalog.oid, 'CONNECT') AS database_connect,
    pg_catalog.has_database_privilege(%s::pg_catalog.oid, %s::pg_catalog.oid,
        'CREATE,TEMPORARY,CREATE WITH GRANT OPTION,CONNECT WITH GRANT OPTION,TEMPORARY WITH GRANT OPTION') AS database_extra,
    pg_catalog.has_parameter_privilege(%s::pg_catalog.oid, 'session_replication_role',
        'SET,ALTER SYSTEM,SET WITH GRANT OPTION,ALTER SYSTEM WITH GRANT OPTION') AS replication_parameter_extra
LIMIT 2"""

_EFFECTIVE_PRIVILEGES_SQL = """WITH requested AS (
    SELECT %s::pg_catalog.oid AS runtime_oid, %s::pg_catalog.oid[] AS relation_oids
), relations AS (
    SELECT relation.oid, relation.relname::pg_catalog.text AS table_name, requested.runtime_oid
    FROM requested JOIN pg_catalog.pg_class AS relation ON relation.oid = ANY(requested.relation_oids)
), privileges AS (
    SELECT 'table'::pg_catalog.text AS scope, relations.table_name,
        ''::pg_catalog.text AS column_name, expected.privilege,
        pg_catalog.has_table_privilege(runtime_oid, oid, expected.privilege) AS allowed,
        pg_catalog.has_table_privilege(runtime_oid, oid, expected.privilege || ' WITH GRANT OPTION') AS grantable
    FROM relations CROSS JOIN (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'),
        ('TRUNCATE'), ('REFERENCES'), ('TRIGGER')) AS expected(privilege)
    UNION ALL
    SELECT 'column', relations.table_name, attribute.attname::pg_catalog.text, expected.privilege,
        CASE WHEN attribute.attisdropped IS FALSE THEN
            pg_catalog.has_column_privilege(runtime_oid, oid, attribute.attnum, expected.privilege) END,
        CASE WHEN attribute.attisdropped IS FALSE THEN
            pg_catalog.has_column_privilege(runtime_oid, oid, attribute.attnum,
                expected.privilege || ' WITH GRANT OPTION') END
    FROM relations JOIN pg_catalog.pg_attribute AS attribute
      ON attribute.attrelid = relations.oid AND attribute.attnum > 0
    CROSS JOIN (VALUES ('SELECT'), ('INSERT'), ('UPDATE'), ('REFERENCES')) AS expected(privilege)
)
SELECT scope, table_name, column_name, privilege, allowed, grantable FROM privileges LIMIT 55"""

_RAW_ACL_SQL = """WITH requested AS (
    SELECT %s::pg_catalog.oid AS namespace_oid, %s::pg_catalog.oid[] AS relation_oids
), grants AS (
    SELECT 'schema'::pg_catalog.text AS scope, namespace.nspname::pg_catalog.text AS object_name,
        ''::pg_catalog.text AS column_name, grant_entry.*
    FROM requested JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = requested.namespace_oid
    CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(namespace.nspacl,
        pg_catalog.acldefault('n'::pg_catalog."char", namespace.nspowner))) AS grant_entry
    UNION ALL
    SELECT 'table', relation.relname::pg_catalog.text, '', grant_entry.*
    FROM requested JOIN pg_catalog.pg_class AS relation ON relation.oid = ANY(requested.relation_oids)
    CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(relation.relacl,
        pg_catalog.acldefault('r'::pg_catalog."char", relation.relowner))) AS grant_entry
    UNION ALL
    SELECT 'column', relation.relname::pg_catalog.text, attribute.attname::pg_catalog.text, grant_entry.*
    FROM requested JOIN pg_catalog.pg_class AS relation ON relation.oid = ANY(requested.relation_oids)
    JOIN pg_catalog.pg_attribute AS attribute ON attribute.attrelid = relation.oid AND attribute.attnum > 0
    CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) AS grant_entry
)
SELECT scope, object_name, column_name, grantor::pg_catalog.int8 AS grantor,
    grantee::pg_catalog.int8 AS grantee, privilege_type, is_grantable FROM grants LIMIT 23"""

_COLUMNS = {
    ENROLLMENTS: ("database_identity_digest", "enrollment_digest", "enrollment_bytes", "head_sequence", "head_digest"),
    CANDIDATES: ("database_identity_digest", "enrollment_digest", "request_digest", "candidate_digest", "candidate_bytes"),
}
_TABLE_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")
_COLUMN_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "REFERENCES")


def _rows(session, statement, parameters, expected_count: int, label: str):
    rows = session.run(statement, parameters).fetchmany(expected_count + 1)
    if len(rows) != expected_count or any(type(row) is not dict for row in rows):
        raise InitializationStoreAdmissionError("initialization store " + label + " count differs")
    return rows


def _matches(row, expected) -> bool:
    return (type(row) is dict and set(row) == set(expected)
        and all(type(row[key]) is type(value) and row[key] == value for key, value in expected.items()))


def _exact_rows(rows, expected, fields_order, label: str) -> None:
    actual = []
    for row in rows:
        if set(row) != set(fields_order):
            raise InitializationStoreAdmissionError("initialization store " + label + " fields differ")
        actual.append(tuple(row[field] for field in fields_order))
    # Strict types must precede set comparison: Python considers True equal to 1.
    exemplar = next(iter(expected))
    if (any(any(type(value) is not type(kind) for value, kind in zip(item, exemplar)) for item in actual)
            or len(set(actual)) != len(actual) or set(actual) != expected):
        raise InitializationStoreAdmissionError("initialization store " + label + " differs")


def admit_store_access(session, identity: InitializationStoreDatabaseIdentity) -> None:
    """Check actual bounded identity/ACL observations; return no authority token.

    pg_control_system() must be explicitly executable by the pinned runtime.
    No grant is attempted here. backend_incarnation_digest remains a supplied
    enrollment binding: PostgreSQL's system identifier cannot prove anti-rollback
    incarnation or independent administration. The main recorder must join it
    to the exact enrollment, and must separately invoke structural admission.
    """
    if type(identity) is not InitializationStoreDatabaseIdentity:
        raise InitializationStoreAdmissionError("initialization store identity has the wrong type")
    try:
        accepted = InitializationStoreDatabaseIdentity(**{
            field.name: getattr(identity, field.name) for field in fields(InitializationStoreDatabaseIdentity)
        })
    except AttributeError as exc:
        raise InitializationStoreAdmissionError("initialization store identity is incomplete") from exc
    context = _rows(session, _CONTEXT_SQL, None, 1, "context")[0]
    if not _matches(context, {"database_name": accepted.database_name, "database_oid": accepted.database_oid,
            "system_identifier": accepted.system_identifier, "current_role": accepted.runtime_role,
            "session_role": accepted.runtime_role, "replication_role": "origin", "server_encoding": "UTF8",
            "client_encoding": "UTF8", "postgres_16": True, "collation_current": True}):
        raise InitializationStoreAdmissionError("initialization store actual identity or session differs")
    roles = _rows(session, _ROLES_SQL,
        ([accepted.runtime_role_oid, accepted.owner_role_oid], [accepted.runtime_role, accepted.owner_role]), 2, "roles")
    expected_roles = {(accepted.runtime_role, accepted.runtime_role_oid, True, False, False, False, False, False, False),
        (accepted.owner_role, accepted.owner_role_oid, False, False, False, False, False, False, False)}
    _exact_rows(roles, expected_roles, ("role_name", "role_oid", "can_login", "superuser", "create_role",
        "create_database", "replication", "bypass_rls", "has_membership"), "roles")
    namespace = _rows(session, _SCHEMA_SQL, (accepted.namespace,), 1, "namespace")[0]
    if set(namespace) != {"namespace_oid", "namespace_name", "owner_oid"}:
        raise InitializationStoreAdmissionError("initialization store namespace fields differ")
    _oid(namespace["namespace_oid"])
    namespace_oid = namespace["namespace_oid"]
    if not _matches(namespace, {"namespace_oid": namespace_oid, "namespace_name": accepted.namespace,
            "owner_oid": accepted.owner_role_oid}):
        raise InitializationStoreAdmissionError("initialization store namespace owner differs")
    tables = _rows(session, _TABLES_SQL, (namespace_oid, [ENROLLMENTS, CANDIDATES]), 2, "tables")
    relation_oids = []
    names = set()
    for row in tables:
        if set(row) != {"relation_oid", "table_name", "owner_oid", "relation_kind"}:
            raise InitializationStoreAdmissionError("initialization store table fields differ")
        _oid(row["relation_oid"])
        if (type(row["table_name"]) is not str or row["table_name"] not in _COLUMNS
                or row["table_name"] in names or row["relation_oid"] in relation_oids
                or not _matches(row, {"relation_oid": row["relation_oid"], "table_name": row["table_name"],
                    "owner_oid": accepted.owner_role_oid, "relation_kind": "r"})):
            raise InitializationStoreAdmissionError("initialization store table ownership differs")
        relation_oids.append(row["relation_oid"])
        names.add(row["table_name"])
    privileges = _rows(session, _ENVIRONMENT_PRIVILEGES_SQL,
        (accepted.runtime_role_oid, namespace_oid, accepted.runtime_role_oid, namespace_oid,
         accepted.runtime_role_oid, accepted.database_oid, accepted.runtime_role_oid, accepted.database_oid,
         accepted.runtime_role_oid), 1, "environment privileges")[0]
    if not _matches(privileges, {"schema_usage": True, "schema_extra": False,
            "database_connect": True, "database_extra": False, "replication_parameter_extra": False}):
        raise InitializationStoreAdmissionError("initialization store environment privileges differ")
    expected_effective = set()
    for table, columns in _COLUMNS.items():
        for privilege in _TABLE_PRIVILEGES:
            expected_effective.add(("table", table, "", privilege,
                privilege == "SELECT" or table == CANDIDATES and privilege == "INSERT", False))
        for column in columns:
            for privilege in _COLUMN_PRIVILEGES:
                allowed = (privilege == "SELECT" or table == CANDIDATES and privilege == "INSERT"
                    or table == ENROLLMENTS and column in ("head_sequence", "head_digest") and privilege == "UPDATE")
                expected_effective.add(("column", table, column, privilege, allowed, False))
    effective = _rows(session, _EFFECTIVE_PRIVILEGES_SQL,
        (accepted.runtime_role_oid, relation_oids), len(expected_effective), "effective privileges")
    _exact_rows(effective, expected_effective,
        ("scope", "table_name", "column_name", "privilege", "allowed", "grantable"), "effective privileges")
    expected_acl = set()
    for privilege in ("USAGE", "CREATE"):
        expected_acl.add(("schema", accepted.namespace, "", accepted.owner_role_oid, accepted.owner_role_oid, privilege, False))
    expected_acl.add(("schema", accepted.namespace, "", accepted.owner_role_oid, accepted.runtime_role_oid, "USAGE", False))
    for table in _COLUMNS:
        for privilege in _TABLE_PRIVILEGES:
            expected_acl.add(("table", table, "", accepted.owner_role_oid, accepted.owner_role_oid, privilege, False))
        for privilege in (("SELECT", "INSERT") if table == CANDIDATES else ("SELECT",)):
            expected_acl.add(("table", table, "", accepted.owner_role_oid, accepted.runtime_role_oid, privilege, False))
    for column in ("head_sequence", "head_digest"):
        expected_acl.add(("column", ENROLLMENTS, column, accepted.owner_role_oid, accepted.runtime_role_oid, "UPDATE", False))
    raw_acl = _rows(session, _RAW_ACL_SQL, (namespace_oid, relation_oids), len(expected_acl), "raw ACL")
    _exact_rows(raw_acl, expected_acl,
        ("scope", "object_name", "column_name", "grantor", "grantee", "privilege_type", "is_grantable"), "raw ACL")
