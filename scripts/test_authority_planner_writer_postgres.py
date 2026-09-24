#!/usr/bin/env python3
"""Native PG16 catalog controls for the actual planner-writer ACL query.

An approved external harness must provide a disposable UTF8 cluster through an
owned mode-0700 Unix socket. The required disposable flag is acknowledgement,
not proof of isolation. This fixture starts no engine and imports no DB facade
or active registry. Every test is one transaction that ALWAYS rolls back,
including setup failures; each catalog variant restores an admitted baseline.

The eleven tables and five trivial PL/pgSQL functions are minimal catalog
fixtures, not production DDL or function implementations. Only the production
query's returned violation is a denial oracle, never a SQL exception. This is
not execution, migration, function-body, TLS, session or service admission
evidence. All cases are authored; native execution requires the approved lane.
"""
from __future__ import annotations

import argparse
import sys
import unittest
import uuid
from contextlib import contextmanager
from pathlib import Path

import psycopg
from psycopg import sql


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware.native_postgres_results import run_native_fixture
from serverware.authority_store.audit_capacity_sql import AUDIT_CAPACITY_PLANNER_FUNCTION_SIGNATURES
from serverware.authority_store.planner_writer_sql import (
    PLANNER_WRITER_TABLE_PRIVILEGES, PLANNER_WRITER_FUNCTION_SIGNATURES,
    planner_writer_privilege_check,
)
from test_webauthn_trust_projection_postgres import local_connection_parameters


CONNECTION_PARAMETERS: dict[str, str | int] | None = None
DISPOSABLE_CLUSTER_ACKNOWLEDGED = False
# Independent literal expectations; never derive fixture grants from the query.
REQUIRED_PRIVILEGES = {
    "policy_authority_authorization_dependency_manifests": ("SELECT",),
    "policy_authority_authorization_projections": ("SELECT", "INSERT"),
    "policy_authority_execution_envelopes": ("SELECT", "INSERT", "UPDATE"),
    "policy_authority_fence_heads": ("SELECT",),
    "policy_authority_operation_mutation_templates": ("SELECT",),
    "policy_authority_planner_transactions": ("SELECT", "INSERT", "UPDATE"),
    "policy_authority_revocation_retained_plans": ("SELECT", "INSERT"),
    "policy_authority_query_dependency_manifests": ("SELECT",),
    "policy_authority_authenticated_table_roots": ("SELECT",),
    "policy_authority_webauthn_assertion_evidence": ("SELECT", "INSERT"),
    "policy_authority_writer_capabilities": ("SELECT", "UPDATE"),
}
REQUIRED_FUNCTIONS = (
    ("serverware_policy_authority_assert_audit_capacity", ("text", "jsonb", "jsonb", "bigint")),
    ("serverware_policy_authority_domain_digest", ("text", "text[]")),
    ("serverware_policy_authority_wire_json", ("jsonb",)),
    ("serverware_policy_authority_wire_string", ("text", "boolean", "bigint")),
    ("serverware_policy_authority_wire_walk", ("jsonb", "integer", "bigint", "bigint", "boolean")),
)
TABLE_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")
COLUMN_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "REFERENCES")


class AuthorityPlannerWriterPostgresTests(unittest.TestCase):
    def setUp(self) -> None:
        if CONNECTION_PARAMETERS is None or not DISPOSABLE_CLUSTER_ACKNOWLEDGED:
            raise RuntimeError("requires --postgres-dsn and --disposable-cluster")
        self.connection = psycopg.connect(**CONNECTION_PARAMETERS, autocommit=False)
        self.addCleanup(self.rollback_and_close)
        self.connection.execute("SET LOCAL search_path = pg_catalog")
        environment = self.connection.execute(
            "SELECT pg_catalog.inet_server_addr(), pg_catalog.getdatabaseencoding(), "
            "pg_catalog.current_setting('server_version_num')::integer, "
            "current_user = session_user, role_record.rolsuper, pg_catalog.current_database() "
            "FROM pg_catalog.pg_roles AS role_record WHERE role_record.rolname = current_user"
        ).fetchone()
        if (environment is None or environment[0] is not None or environment[1] != "UTF8"
                or not 160000 <= environment[2] < 170000
                or environment[3] is not True or environment[4] is not True):
            raise RuntimeError("requires a direct superuser session on disposable Unix-socket PG16/UTF8")
        self.database = environment[5]
        suffix = uuid.uuid4().hex
        self.schema = "planner_acl_" + suffix
        self.role = "planner_writer_" + suffix
        self.peer = "planner_peer_" + suffix
        self.execute("CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                     "NOREPLICATION NOBYPASSRLS NOINHERIT", sql.Identifier(self.role))
        self.execute("CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                     "NOREPLICATION NOBYPASSRLS NOINHERIT", sql.Identifier(self.peer))
        self.execute("CREATE SCHEMA {}", sql.Identifier(self.schema))
        self.execute("REVOKE ALL ON SCHEMA {} FROM PUBLIC", sql.Identifier(self.schema))
        self.execute("REVOKE TEMPORARY ON DATABASE {} FROM PUBLIC", sql.Identifier(self.database))
        self.execute("GRANT USAGE ON SCHEMA {} TO {}",
                     sql.Identifier(self.schema), sql.Identifier(self.role))
        for table in (*REQUIRED_PRIVILEGES, "extra"):
            self.execute("CREATE TABLE {} (id bigint PRIMARY KEY, payload text)", self.object(table))
        for table, privileges in REQUIRED_PRIVILEGES.items():
            self.execute("GRANT " + ", ".join(privileges) + " ON {} TO {}",
                         self.object(table), sql.Identifier(self.role))
        self.execute("CREATE VIEW {} AS SELECT id,payload FROM {}",
                     self.object("extra_view"), self.object("extra"))
        self.execute("CREATE SEQUENCE {}", self.object("extra_sequence"))
        for name, arguments in REQUIRED_FUNCTIONS:
            self.create_function(name, arguments)
            self.execute("GRANT EXECUTE ON FUNCTION {} TO {}",
                         self.function(name, arguments), sql.Identifier(self.role))
        self.create_function("extra_function", ())
        self.assert_admitted()

    def rollback_and_close(self) -> None:
        try:
            self.connection.rollback()
        finally:
            self.connection.close()

    def object(self, name: str) -> sql.Identifier:
        return sql.Identifier(self.schema, name)

    def function(self, name: str, arguments: tuple[str, ...]) -> sql.Composed:
        # Types are closed fixture literals, never SQL supplied by a caller.
        return sql.SQL("{}({})").format(self.object(name), sql.SQL(", ".join(arguments)))

    def execute(self, statement: str, *identifiers: sql.Composable) -> None:
        self.connection.execute(sql.SQL(statement).format(*identifiers))

    def create_function(self, name: str, arguments: tuple[str, ...], *, language="plpgsql") -> None:
        assertion = name == REQUIRED_FUNCTIONS[0][0]
        wire = name in {item[0] for item in REQUIRED_FUNCTIONS[2:]}
        path = sql.SQL("pg_catalog") if wire else sql.SQL("pg_catalog, {}, pg_temp").format(
            sql.Identifier(self.schema))
        body = "BEGIN RETURN 1; END;" if language == "plpgsql" else "SELECT 1"
        self.connection.execute(sql.SQL(
            "CREATE FUNCTION {} RETURNS integer LANGUAGE {} SECURITY INVOKER {} {} "
            "SET search_path TO {} AS {}"
        ).format(self.function(name, arguments), sql.Identifier(language),
                 sql.SQL("CALLED ON NULL INPUT" if assertion else "STRICT"),
                 sql.SQL("VOLATILE" if assertion else "IMMUTABLE"), path, sql.Literal(body)))
        self.execute("REVOKE ALL ON FUNCTION {} FROM PUBLIC", self.function(name, arguments))

    def verdict(self, *, role: str | None = None, namespace: str | None = None):
        return self.connection.execute(*planner_writer_privilege_check(
            role=self.role if role is None else role,
            namespace=self.schema if namespace is None else namespace,
        )).fetchone()

    def assert_admitted(self) -> None:
        self.assertIsNone(self.verdict())

    def assert_denied(self, **names: str) -> None:
        row = self.verdict(**names)
        self.assertIsNotNone(row)
        self.assertEqual(len(row), 1)
        self.assertIsInstance(row[0], str)
        self.assertTrue(row[0])

    @contextmanager
    def variant(self):
        self.assert_admitted()
        self.connection.execute("SAVEPOINT planner_acl_variant")
        try:
            yield
        finally:
            self.connection.execute("ROLLBACK TO SAVEPOINT planner_acl_variant")
            self.connection.execute("RELEASE SAVEPOINT planner_acl_variant")
            self.assert_admitted()

    def deny_change(self, statement: str, *identifiers: sql.Composable) -> None:
        with self.variant():
            self.execute(statement, *identifiers)
            self.assert_denied()

    def test_exact_eleven_tables_and_five_invoker_functions_admit(self) -> None:
        self.assertEqual(len(REQUIRED_PRIVILEGES), 11)
        self.assertEqual({name: frozenset(grants) for name, grants in REQUIRED_PRIVILEGES.items()},
                         PLANNER_WRITER_TABLE_PRIVILEGES)
        self.assertEqual(REQUIRED_FUNCTIONS, AUDIT_CAPACITY_PLANNER_FUNCTION_SIGNATURES)
        self.assertEqual(REQUIRED_FUNCTIONS, PLANNER_WRITER_FUNCTION_SIGNATURES)
        self.assert_admitted()

    def test_missing_role_or_namespace_denies(self) -> None:
        self.assert_denied(role="missing_" + uuid.uuid4().hex)
        self.assert_denied(namespace="missing_" + uuid.uuid4().hex)
        self.assert_admitted()

    def test_each_required_table_and_privilege_is_mandatory(self) -> None:
        for table, privileges in REQUIRED_PRIVILEGES.items():
            with self.subTest(table=table, missing=True):
                self.deny_change("DROP TABLE {}", self.object(table))
            for privilege in privileges:
                with self.subTest(table=table, privilege=privilege):
                    self.deny_change("REVOKE " + privilege + " ON {} FROM {}",
                                     self.object(table), sql.Identifier(self.role))

    def test_required_table_name_cannot_be_a_view(self) -> None:
        for table, privileges in REQUIRED_PRIVILEGES.items():
            with self.subTest(table=table), self.variant():
                self.execute("DROP TABLE {}", self.object(table))
                self.execute("CREATE VIEW {} AS SELECT id,payload FROM {}",
                             self.object(table), self.object("extra"))
                self.execute("GRANT " + ", ".join(privileges) + " ON {} TO {}",
                             self.object(table), sql.Identifier(self.role))
                self.assert_denied()

    def test_column_grants_cannot_replace_required_table_privileges(self) -> None:
        for table, privileges in REQUIRED_PRIVILEGES.items():
            for privilege in privileges:
                # The exact source surface has table ACLs only: even redundant
                # direct column ACLs are rejected rather than normalized away.
                with self.subTest(table=table, privilege=privilege, redundant=True):
                    self.deny_change("GRANT " + privilege + "(id) ON {} TO {}",
                                     self.object(table), sql.Identifier(self.role))
                with self.subTest(table=table, privilege=privilege), self.variant():
                    self.execute("REVOKE " + privilege + " ON {} FROM {}",
                                 self.object(table), sql.Identifier(self.role))
                    self.execute("GRANT " + privilege + "(id,payload) ON {} TO {}",
                                 self.object(table), sql.Identifier(self.role))
                    self.assert_denied()

    def test_unlisted_relation_and_column_privileges_deny(self) -> None:
        for table in ("extra", "extra_view"):
            for privilege in (TABLE_PRIVILEGES if table == "extra" else ("SELECT",)):
                with self.subTest(table=table, privilege=privilege):
                    self.deny_change("GRANT " + privilege + " ON {} TO {}",
                                     self.object(table), sql.Identifier(self.role))
            for privilege in COLUMN_PRIVILEGES:
                with self.subTest(table=table, column_privilege=privilege):
                    self.deny_change("GRANT " + privilege + "(id) ON {} TO {}",
                                     self.object(table), sql.Identifier(self.role))

    def test_each_excess_table_and_column_privilege_denies(self) -> None:
        for table, allowed in REQUIRED_PRIVILEGES.items():
            for privilege in TABLE_PRIVILEGES:
                if privilege not in allowed:
                    with self.subTest(table=table, privilege=privilege):
                        self.deny_change("GRANT " + privilege + " ON {} TO {}",
                                         self.object(table), sql.Identifier(self.role))
            for privilege in COLUMN_PRIVILEGES:
                if privilege not in allowed:
                    with self.subTest(table=table, column_privilege=privilege):
                        self.deny_change("GRANT " + privilege + "(id) ON {} TO {}",
                                         self.object(table), sql.Identifier(self.role))

    def test_table_column_schema_and_function_grant_options_deny(self) -> None:
        for table, privileges in REQUIRED_PRIVILEGES.items():
            for privilege in privileges:
                for column in ("", "(id)"):
                    with self.subTest(table=table, privilege=privilege, column=column):
                        self.deny_change("GRANT " + privilege + column + " ON {} TO {} WITH GRANT OPTION",
                                         self.object(table), sql.Identifier(self.role))
        self.deny_change("GRANT USAGE ON SCHEMA {} TO {} WITH GRANT OPTION",
                         sql.Identifier(self.schema), sql.Identifier(self.role))
        for name, arguments in REQUIRED_FUNCTIONS:
            with self.subTest(function=name):
                self.deny_change("GRANT EXECUTE ON FUNCTION {} TO {} WITH GRANT OPTION",
                                 self.function(name, arguments), sql.Identifier(self.role))

    def test_public_relation_and_column_privileges_deny(self) -> None:
        for table in (*REQUIRED_PRIVILEGES, "extra", "extra_view"):
            with self.subTest(table=table):
                self.deny_change("GRANT SELECT ON {} TO PUBLIC", self.object(table))
            for privilege in COLUMN_PRIVILEGES:
                with self.subTest(table=table, privilege=privilege):
                    self.deny_change("GRANT " + privilege + "(id) ON {} TO PUBLIC", self.object(table))

    def test_public_schema_function_and_sequence_privileges_deny(self) -> None:
        for privilege in ("USAGE", "CREATE"):
            with self.subTest(privilege=privilege):
                self.deny_change("GRANT " + privilege + " ON SCHEMA {} TO PUBLIC", sql.Identifier(self.schema))
        for name, arguments in (*REQUIRED_FUNCTIONS, ("extra_function", ())):
            with self.subTest(function=name):
                self.deny_change("GRANT EXECUTE ON FUNCTION {} TO PUBLIC", self.function(name, arguments))
        for privilege in ("SELECT", "USAGE", "UPDATE"):
            with self.subTest(sequence_privilege=privilege):
                self.deny_change("GRANT " + privilege + " ON SEQUENCE {} TO PUBLIC", self.object("extra_sequence"))

    def test_each_sequence_privilege_denies(self) -> None:
        for privilege in ("SELECT", "USAGE", "UPDATE"):
            with self.subTest(privilege=privilege):
                self.deny_change("GRANT " + privilege + " ON SEQUENCE {} TO {}",
                                 self.object("extra_sequence"), sql.Identifier(self.role))

    def test_membership_in_either_direction_denies(self) -> None:
        for granted, member in ((self.peer, self.role), (self.role, self.peer)):
            with self.subTest(granted=granted):
                self.deny_change("GRANT {} TO {}", sql.Identifier(granted), sql.Identifier(member))

    def test_login_and_elevated_role_flags_deny(self) -> None:
        for flag in ("NOLOGIN", "SUPERUSER", "CREATEDB", "CREATEROLE", "REPLICATION", "BYPASSRLS"):
            with self.subTest(flag=flag):
                self.deny_change("ALTER ROLE {} " + flag, sql.Identifier(self.role))

    def test_schema_usage_create_and_ownership_deny(self) -> None:
        self.deny_change("REVOKE USAGE ON SCHEMA {} FROM {}",
                         sql.Identifier(self.schema), sql.Identifier(self.role))
        self.deny_change("GRANT CREATE ON SCHEMA {} TO {}",
                         sql.Identifier(self.schema), sql.Identifier(self.role))
        self.deny_change("ALTER SCHEMA {} OWNER TO {}",
                         sql.Identifier(self.schema), sql.Identifier(self.role))

    def test_database_create_and_temporary_deny(self) -> None:
        for privilege in ("CREATE", "TEMPORARY"):
            with self.subTest(privilege=privilege):
                self.deny_change("GRANT " + privilege + " ON DATABASE {} TO {}",
                                 sql.Identifier(self.database), sql.Identifier(self.role))
        self.deny_change("GRANT TEMPORARY ON DATABASE {} TO PUBLIC", sql.Identifier(self.database))

    def test_each_required_function_and_execute_is_mandatory(self) -> None:
        for name, arguments in REQUIRED_FUNCTIONS:
            with self.subTest(function=name, missing=True):
                self.deny_change("DROP FUNCTION {}", self.function(name, arguments))
            with self.subTest(function=name, missing_execute=True):
                self.deny_change("REVOKE EXECUTE ON FUNCTION {} FROM {}",
                                 self.function(name, arguments), sql.Identifier(self.role))

    def test_function_overloads_cannot_replace_or_expand_exact_execute_closure(self) -> None:
        for name, arguments in REQUIRED_FUNCTIONS:
            for replace in (False, True):
                with self.subTest(function=name, replace=replace), self.variant():
                    if replace:
                        self.execute("DROP FUNCTION {}", self.function(name, arguments))
                    self.create_function(name, ("integer",))
                    self.execute("GRANT EXECUTE ON FUNCTION {} TO {}",
                                 self.function(name, ("integer",)), sql.Identifier(self.role))
                    self.assert_denied()

    def test_each_function_security_language_strictness_and_volatility_is_exact(self) -> None:
        for name, arguments in REQUIRED_FUNCTIONS:
            assertion = name == REQUIRED_FUNCTIONS[0][0]
            for clause in ("SECURITY DEFINER", "STRICT" if assertion else "CALLED ON NULL INPUT",
                           "STABLE"):
                with self.subTest(function=name, clause=clause):
                    self.deny_change("ALTER FUNCTION {} " + clause, self.function(name, arguments))
            with self.subTest(function=name, language="sql"), self.variant():
                self.execute("DROP FUNCTION {}", self.function(name, arguments))
                self.create_function(name, arguments, language="sql")
                self.execute("GRANT EXECUTE ON FUNCTION {} TO {}",
                             self.function(name, arguments), sql.Identifier(self.role))
                self.assert_denied()

    def test_each_function_search_path_is_exact(self) -> None:
        for name, arguments in REQUIRED_FUNCTIONS:
            for clause in ("RESET search_path", "SET search_path TO public, pg_catalog",
                           "SET statement_timeout TO '5s'"):
                with self.subTest(function=name, clause=clause):
                    self.deny_change("ALTER FUNCTION {} " + clause, self.function(name, arguments))

    def test_required_object_owners_match_namespace_owner(self) -> None:
        for table in REQUIRED_PRIVILEGES:
            with self.subTest(table=table):
                self.deny_change("ALTER TABLE {} OWNER TO {}", self.object(table), sql.Identifier(self.peer))
        for name, arguments in REQUIRED_FUNCTIONS:
            with self.subTest(function=name):
                self.deny_change("ALTER FUNCTION {} OWNER TO {}",
                                 self.function(name, arguments), sql.Identifier(self.peer))

    def test_unlisted_function_execute_denies(self) -> None:
        self.deny_change("GRANT EXECUTE ON FUNCTION {} TO {}",
                         self.function("extra_function", ()), sql.Identifier(self.role))

    def test_required_function_kind_is_not_a_procedure(self) -> None:
        for name, arguments in REQUIRED_FUNCTIONS:
            with self.subTest(function=name), self.variant():
                self.execute("DROP FUNCTION {}", self.function(name, arguments))
                self.execute("CREATE PROCEDURE {} LANGUAGE plpgsql SECURITY INVOKER "
                             "AS 'BEGIN NULL; END;'", self.function(name, arguments))
                self.execute("REVOKE ALL ON PROCEDURE {} FROM PUBLIC", self.function(name, arguments))
                self.execute("GRANT EXECUTE ON PROCEDURE {} TO {}",
                             self.function(name, arguments), sql.Identifier(self.role))
                self.assert_denied()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--postgres-dsn", required=True)
    parser.add_argument("--prepared-result")
    parser.add_argument("--disposable-cluster", action="store_true", required=True,
                        help="acknowledge the externally prepared cluster is disposable")
    arguments, test_arguments = parser.parse_known_args()
    CONNECTION_PARAMETERS = local_connection_parameters(arguments.postgres_dsn)
    DISPOSABLE_CLUSTER_ACKNOWLEDGED = arguments.disposable_cluster
    run_native_fixture("scripts/test_authority_planner_writer_postgres.py",
        argv=[sys.argv[0], *test_arguments], result_path=arguments.prepared_result)
