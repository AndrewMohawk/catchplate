#!/usr/bin/env python3
"""Native PostgreSQL 16 component controls for the actual verifier ACL query.

An external approved harness must provide a disposable UTF8 cluster through an
owned mode-0700 Unix socket. The explicit disposable-cluster flag is an operator
acknowledgement, not proof that a cluster is disposable. This file starts no
engine and imports no DB facade, registry, or mocked catalog functions.

Each test creates random roles/schema and changes database ACLs only inside one
transaction that is ALWAYS rolled back, including setup/test failures. Variant
savepoints restore the positive baseline. There is no commit or broad DROP.
The four tables are deliberately minimal catalog fixtures, not production DDL.
These tests exercise the production query against actual ACLs; they do not prove
installation, mTLS/session admission, schema migration, roots, or production
authorization. Native execution still requires the separately approved lane.
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

from serverware import authority_contract
from serverware.authority_store.verifier_read_sql import verifier_read_privilege_check
from test_webauthn_trust_projection_postgres import local_connection_parameters


CONNECTION_PARAMETERS: dict[str, str | int] | None = None
DISPOSABLE_CLUSTER_ACKNOWLEDGED = False
REQUIRED_TABLES = (
    "webauthn_challenges", "webauthn_credentials",
    "webauthn_trust_publication_high_water", "webauthn_trust_publications",
)


class AuthorityVerifierReadPostgresTests(unittest.TestCase):
    def setUp(self) -> None:
        if CONNECTION_PARAMETERS is None or not DISPOSABLE_CLUSTER_ACKNOWLEDGED:
            raise RuntimeError("requires --postgres-dsn and --disposable-cluster")
        self.connection = psycopg.connect(**CONNECTION_PARAMETERS, autocommit=False)
        # Register before even the first query; unittest runs cleanups when
        # setUp fails. Never use Connection's committing context manager here.
        self.addCleanup(self.rollback_and_close)
        self.connection.execute("SET LOCAL search_path = pg_catalog")
        environment = self.connection.execute(
            "SELECT pg_catalog.inet_server_addr(), pg_catalog.getdatabaseencoding(), "
            "pg_catalog.current_setting('server_version_num')::integer, "
            "current_user = session_user, role_record.rolsuper, "
            "pg_catalog.current_database() "
            "FROM pg_catalog.pg_roles AS role_record WHERE role_record.rolname = current_user"
        ).fetchone()
        if (environment is None or environment[0] is not None or environment[1] != "UTF8"
                or not 160000 <= environment[2] < 170000
                or environment[3] is not True or environment[4] is not True):
            raise RuntimeError("requires a direct superuser session on disposable Unix-socket PG16/UTF8")
        self.database = environment[5]
        suffix = uuid.uuid4().hex
        self.schema = "verifier_acl_" + suffix
        self.role = "verifier_read_" + suffix
        self.peer = "verifier_peer_" + suffix
        self.execute(
            "CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
            "NOREPLICATION NOBYPASSRLS NOINHERIT", sql.Identifier(self.role))
        self.execute(
            "CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
            "NOREPLICATION NOBYPASSRLS NOINHERIT", sql.Identifier(self.peer))
        self.execute("CREATE SCHEMA {}", sql.Identifier(self.schema))
        self.execute("REVOKE ALL ON SCHEMA {} FROM PUBLIC", sql.Identifier(self.schema))
        # The prepared cluster may retain PostgreSQL's default PUBLIC TEMP.
        # This change is visible only in this uncommitted test transaction.
        self.execute("REVOKE TEMPORARY ON DATABASE {} FROM PUBLIC", sql.Identifier(self.database))
        self.execute("GRANT USAGE ON SCHEMA {} TO {}",
                     sql.Identifier(self.schema), sql.Identifier(self.role))
        for table in (*REQUIRED_TABLES, "extra"):
            self.execute("CREATE TABLE {} (id bigint PRIMARY KEY, payload text)", self.object(table))
        for table in REQUIRED_TABLES:
            self.execute("GRANT SELECT ON {} TO {}", self.object(table), sql.Identifier(self.role))
        self.execute("CREATE VIEW {} AS SELECT id,payload FROM {}",
                     self.object("extra_view"), self.object("extra"))
        self.execute("CREATE SEQUENCE {}", self.object("extra_sequence"))
        self.execute("CREATE FUNCTION {}() RETURNS integer LANGUAGE sql AS 'SELECT 1'",
                     self.object("extra_function"))
        self.execute("REVOKE ALL ON FUNCTION {}() FROM PUBLIC", self.object("extra_function"))
        self.assert_admitted()

    def rollback_and_close(self) -> None:
        try:
            self.connection.rollback()
        finally:
            self.connection.close()

    def object(self, name: str) -> sql.Identifier:
        return sql.Identifier(self.schema, name)

    def execute(self, statement: str, *identifiers: sql.Composable) -> None:
        self.connection.execute(sql.SQL(statement).format(*identifiers))

    def verdict(self, *, role: str | None = None, namespace: str | None = None):
        return self.connection.execute(*verifier_read_privilege_check(
            role=self.role if role is None else role,
            namespace=self.schema if namespace is None else namespace,
        )).fetchone()

    def assert_admitted(self) -> None:
        self.assertIsNone(self.verdict())

    def assert_denied(self, **names: str) -> None:
        # A SQL exception is NOT a denial oracle. The real fixed query must
        # return a violation; several independent arms may apply to one case.
        row = self.verdict(**names)
        self.assertIsNotNone(row)
        self.assertEqual(len(row), 1)
        self.assertIsInstance(row[0], str)
        self.assertTrue(row[0])

    @contextmanager
    def variant(self):
        self.assert_admitted()
        self.connection.execute("SAVEPOINT verifier_acl_variant")
        try:
            yield
        finally:
            self.connection.execute("ROLLBACK TO SAVEPOINT verifier_acl_variant")
            self.connection.execute("RELEASE SAVEPOINT verifier_acl_variant")
            self.assert_admitted()

    def deny_change(self, statement: str, *identifiers: sql.Composable) -> None:
        with self.variant():
            self.execute(statement, *identifiers)
            self.assert_denied()

    def test_exact_four_table_positive(self) -> None:
        self.assertEqual(frozenset(REQUIRED_TABLES), authority_contract.VERIFIER_READ_TABLES)
        self.assert_admitted()

    def test_missing_role_or_namespace_denies(self) -> None:
        self.assert_denied(role="missing_" + uuid.uuid4().hex)
        self.assert_denied(namespace="missing_" + uuid.uuid4().hex)
        self.assert_admitted()

    def test_each_missing_required_table_denies(self) -> None:
        for table in REQUIRED_TABLES:
            with self.subTest(table=table), self.variant():
                self.execute("DROP TABLE {}", self.object(table))
                self.assert_denied()

    def test_required_name_cannot_be_a_view(self) -> None:
        with self.variant():
            self.execute("DROP TABLE {}", self.object(REQUIRED_TABLES[0]))
            self.execute("CREATE VIEW {} AS SELECT id,payload FROM {}",
                         self.object(REQUIRED_TABLES[0]), self.object("extra"))
            self.execute("GRANT SELECT ON {} TO {}",
                         self.object(REQUIRED_TABLES[0]), sql.Identifier(self.role))
            self.assert_denied()

    def test_all_column_select_is_not_full_table_select(self) -> None:
        for table in REQUIRED_TABLES:
            with self.subTest(table=table), self.variant():
                self.execute("REVOKE SELECT ON {} FROM {}", self.object(table), sql.Identifier(self.role))
                self.execute("GRANT SELECT(id,payload) ON {} TO {}",
                             self.object(table), sql.Identifier(self.role))
                self.assert_denied()

    def test_extra_table_and_view_select_denies(self) -> None:
        for table in ("extra", "extra_view"):
            with self.subTest(table=table):
                self.deny_change("GRANT SELECT ON {} TO {}", self.object(table), sql.Identifier(self.role))

    def test_extra_column_only_select_denies(self) -> None:
        for table in ("extra", "extra_view"):
            with self.subTest(table=table):
                self.deny_change("GRANT SELECT(id) ON {} TO {}", self.object(table), sql.Identifier(self.role))

    def test_table_writes_deny(self) -> None:
        for privilege in ("INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"):
            with self.subTest(privilege=privilege):
                self.deny_change("GRANT " + privilege + " ON {} TO {}",
                                 self.object(REQUIRED_TABLES[0]), sql.Identifier(self.role))

    def test_column_only_writes_deny(self) -> None:
        for privilege in ("INSERT", "UPDATE", "REFERENCES"):
            with self.subTest(privilege=privilege):
                self.deny_change("GRANT " + privilege + "(id) ON {} TO {}",
                                 self.object(REQUIRED_TABLES[0]), sql.Identifier(self.role))

    def test_table_column_and_schema_grant_options_deny(self) -> None:
        for statement, target in (
            ("GRANT SELECT ON {} TO {} WITH GRANT OPTION", self.object(REQUIRED_TABLES[0])),
            ("GRANT SELECT(id) ON {} TO {} WITH GRANT OPTION", self.object(REQUIRED_TABLES[0])),
            ("GRANT USAGE ON SCHEMA {} TO {} WITH GRANT OPTION", sql.Identifier(self.schema)),
        ):
            with self.subTest(statement=statement):
                self.deny_change(statement, target, sql.Identifier(self.role))

    def test_all_three_sequence_privileges_deny(self) -> None:
        for privilege in ("SELECT", "USAGE", "UPDATE"):
            with self.subTest(privilege=privilege):
                self.deny_change("GRANT " + privilege + " ON SEQUENCE {} TO {}",
                                 self.object("extra_sequence"), sql.Identifier(self.role))

    def test_function_execute_denies(self) -> None:
        self.deny_change("GRANT EXECUTE ON FUNCTION {}() TO {}",
                         self.object("extra_function"), sql.Identifier(self.role))

    def test_public_allowed_table_select_still_denies(self) -> None:
        self.deny_change("GRANT SELECT ON {} TO PUBLIC", self.object(REQUIRED_TABLES[0]))

    def test_public_column_select_and_write_deny(self) -> None:
        for privilege in ("SELECT", "INSERT", "UPDATE", "REFERENCES"):
            with self.subTest(privilege=privilege):
                self.deny_change("GRANT " + privilege + "(id) ON {} TO PUBLIC",
                                 self.object(REQUIRED_TABLES[0]))

    def test_public_schema_usage_and_create_deny(self) -> None:
        for privilege in ("USAGE", "CREATE"):
            with self.subTest(privilege=privilege):
                self.deny_change("GRANT " + privilege + " ON SCHEMA {} TO PUBLIC", sql.Identifier(self.schema))

    def test_public_function_execute_denies(self) -> None:
        self.deny_change("GRANT EXECUTE ON FUNCTION {}() TO PUBLIC", self.object("extra_function"))

    def test_public_sequence_privileges_deny(self) -> None:
        for privilege in ("SELECT", "USAGE", "UPDATE"):
            with self.subTest(privilege=privilege):
                self.deny_change("GRANT " + privilege + " ON SEQUENCE {} TO PUBLIC", self.object("extra_sequence"))

    def test_membership_in_either_direction_denies(self) -> None:
        for granted, member in ((self.peer, self.role), (self.role, self.peer)):
            with self.subTest(granted=granted):
                self.deny_change("GRANT {} TO {}", sql.Identifier(granted), sql.Identifier(member))

    def test_role_login_and_each_elevated_flag_deny(self) -> None:
        for flag in ("NOLOGIN", "SUPERUSER", "CREATEDB", "CREATEROLE", "REPLICATION", "BYPASSRLS"):
            with self.subTest(flag=flag):
                self.deny_change("ALTER ROLE {} " + flag, sql.Identifier(self.role))

    def test_schema_create_and_missing_usage_deny(self) -> None:
        self.deny_change("GRANT CREATE ON SCHEMA {} TO {}",
                         sql.Identifier(self.schema), sql.Identifier(self.role))
        self.deny_change("REVOKE USAGE ON SCHEMA {} FROM {}",
                         sql.Identifier(self.schema), sql.Identifier(self.role))

    def test_database_create_and_temporary_deny(self) -> None:
        for privilege in ("CREATE", "TEMPORARY"):
            with self.subTest(privilege=privilege):
                self.deny_change("GRANT " + privilege + " ON DATABASE {} TO {}",
                                 sql.Identifier(self.database), sql.Identifier(self.role))
        self.deny_change("GRANT TEMPORARY ON DATABASE {} TO PUBLIC", sql.Identifier(self.database))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--postgres-dsn", required=True)
    parser.add_argument("--disposable-cluster", action="store_true", required=True,
                        help="acknowledge the externally prepared cluster is disposable")
    arguments, test_arguments = parser.parse_known_args()
    CONNECTION_PARAMETERS = local_connection_parameters(arguments.postgres_dsn)
    DISPOSABLE_CLUSTER_ACKNOWLEDGED = arguments.disposable_cluster
    unittest.main(argv=[sys.argv[0], *test_arguments])
