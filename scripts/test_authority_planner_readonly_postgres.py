#!/usr/bin/env python3
"""One real-PG catalog regression for the planner/runtime credential split.

An external approved harness owns a fresh network-none PG16 cluster and private
Unix socket. This file starts no engine and accepts no production/network DSN.
The genuine planner grant producer runs against four small fixture tables, one
sequence and one writer-only function. All setup and variants roll back.

This proves grant execution, SQL permissions and the exact planner mutation
query, not TLS identity, full bootstrap, authority admission or writer function
bodies. The writer control checks that its fixture ACL is unchanged; it does
not replace the separate full planner-writer contract suite.
"""
from __future__ import annotations

import argparse
import ast
from contextlib import contextmanager
from pathlib import Path
import sys
import unittest
import uuid

import psycopg
from psycopg import sql
from psycopg.rows import dict_row

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from catchplate.authority_store.planner_read_sql import ROLE, seal_planner_read_acl
from test_webauthn_trust_projection_postgres import local_connection_parameters


CONNECTION_PARAMETERS = None
DISPOSABLE_CLUSTER_ACKNOWLEDGED = False
SCHEMA = "catchplate_metadata"
BUSINESS = "credentials"
WRITER_TABLE = "policy_authority_planner_transactions"
EXCLUDED = ("policy_authority_current_root_commit_markers",
            "policy_authority_successor_execution_custody")
SEQUENCE = "fixture_metadata_sequence"
FUNCTION = "fixture_writer_operation"
TABLE_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")


def planner_mutation_query():
    """Extract only the unchanged production catalog query; never fake TLS."""
    path = ROOT / "catchplate/authority_planner_read.py"
    if path.stat().st_size > 2 * 1024 * 1024:
        raise AssertionError("planner source exceeds fixture bound")
    tree = ast.parse(path.read_text(encoding="utf-8"))
    function, = (node for node in tree.body if isinstance(node, ast.FunctionDef)
                 and node.name == "_validate_database_identity")
    assignment, = (node for node in function.body if isinstance(node, ast.Assign)
        and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "mutation")
    query = assignment.value.func.value.args[0]
    statement = ast.literal_eval(query)
    if (type(statement) is not str or not statement.startswith("SELECT 1 FROM pg_catalog.pg_class")
            or "namespace.nspname = 'catchplate_metadata'" not in statement
            or not statement.endswith("LIMIT 1")):
        raise AssertionError("planner mutation query shape changed")
    return statement


class PlannerReadOnlyPostgresTests(unittest.TestCase):
    def setUp(self):
        if CONNECTION_PARAMETERS is None or not DISPOSABLE_CLUSTER_ACKNOWLEDGED:
            raise RuntimeError("requires approved disposable Unix-socket PostgreSQL")
        self.connection = psycopg.connect(**CONNECTION_PARAMETERS, row_factory=dict_row)
        self.addCleanup(self.rollback_and_close)
        self.connection.execute("SET LOCAL search_path = pg_catalog")
        observed = self.connection.execute(
            "SELECT pg_catalog.inet_server_addr() AS address, "
            "pg_catalog.getdatabaseencoding() AS encoding, "
            "pg_catalog.current_setting('server_version_num')::integer AS version, "
            "current_user = session_user AS direct, role_record.rolsuper AS superuser, "
            "pg_catalog.current_database() AS database FROM pg_catalog.pg_roles AS role_record "
            "WHERE role_record.rolname = current_user").fetchone()
        self.assertIsNotNone(observed)
        self.assertIsNone(observed["address"])
        self.assertEqual(observed["encoding"], "UTF8")
        self.assertTrue(160000 <= observed["version"] < 170000)
        self.assertIs(observed["direct"], True)
        self.assertIs(observed["superuser"], True)
        self.assertEqual(ROLE, "catchplate_policy_authority_planner")
        absent = self.connection.execute(
            "SELECT pg_catalog.to_regnamespace(%s) AS namespace, "
            "pg_catalog.to_regrole(%s) AS role", (SCHEMA, ROLE)).fetchone()
        self.assertEqual(absent, {"namespace": None, "role": None})
        suffix = uuid.uuid4().hex
        self.runtime = "fixture_runtime_" + suffix
        self.writer = "fixture_writer_" + suffix
        for role in (ROLE, self.runtime, self.writer):
            self.execute("CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                         "NOREPLICATION NOBYPASSRLS NOINHERIT", sql.Identifier(role))
        self.execute("CREATE SCHEMA {}", sql.Identifier(SCHEMA))
        self.execute("REVOKE CREATE, TEMPORARY ON DATABASE {} FROM PUBLIC",
                     sql.Identifier(observed["database"]))
        self.execute("REVOKE ALL ON SCHEMA {} FROM PUBLIC", sql.Identifier(SCHEMA))
        for table in (BUSINESS, WRITER_TABLE, *EXCLUDED):
            self.execute("CREATE TABLE {} (id bigint PRIMARY KEY, payload text)", self.object(table))
            self.execute("INSERT INTO {} VALUES (1, 'fixture')", self.object(table))
        self.execute("CREATE SEQUENCE {}", self.object(SEQUENCE))
        self.execute("CREATE FUNCTION {}() RETURNS integer LANGUAGE SQL SECURITY INVOKER "
                     "SET search_path = pg_catalog AS 'SELECT 1'", self.object(FUNCTION))
        for kind in ("TABLES", "SEQUENCES", "FUNCTIONS"):
            self.execute("REVOKE ALL ON ALL " + kind + " IN SCHEMA {} FROM PUBLIC",
                         sql.Identifier(SCHEMA))
        for role in (self.runtime, self.writer):
            self.execute("GRANT USAGE ON SCHEMA {} TO {}",
                         sql.Identifier(SCHEMA), sql.Identifier(role))
        self.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON {} TO {}",
                     self.object(BUSINESS), sql.Identifier(self.runtime))
        self.execute("GRANT SELECT ON {} TO {}",
                     self.object(WRITER_TABLE), sql.Identifier(self.runtime))
        self.execute("GRANT SELECT, INSERT, UPDATE ON {} TO {}",
                     self.object(WRITER_TABLE), sql.Identifier(self.writer))
        self.execute("GRANT EXECUTE ON FUNCTION {}() TO {}",
                     self.object(FUNCTION), sql.Identifier(self.writer))
        self.mutation_sql = planner_mutation_query()

    def rollback_and_close(self):
        try:
            self.connection.rollback()
        finally:
            self.connection.close()

    def object(self, name):
        return sql.Identifier(SCHEMA, name)

    def execute(self, statement, *identifiers):
        return self.connection.execute(sql.SQL(statement).format(*identifiers))

    @contextmanager
    def as_role(self, role):
        # Nested transaction gives failed statements their own rollback point.
        with self.connection.transaction():
            self.execute("SET LOCAL ROLE {}", sql.Identifier(role))
            try:
                yield
            finally:
                if self.connection.info.transaction_status == psycopg.pq.TransactionStatus.INTRANS:
                    self.connection.execute("RESET ROLE")

    def mutation(self):
        with self.as_role(ROLE):
            return self.connection.execute(self.mutation_sql).fetchone()

    def writer_snapshot(self):
        rows = self.connection.execute(
            "SELECT relation.relname, privilege.name, "
            "pg_catalog.has_table_privilege(%s, relation.oid, privilege.name) AS allowed "
            "FROM pg_catalog.pg_class AS relation "
            "JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace "
            "CROSS JOIN pg_catalog.unnest(%s::text[]) AS privilege(name) "
            "WHERE namespace.nspname = %s AND relation.relkind = 'r' "
            "ORDER BY relation.relname, privilege.name", (self.writer, list(TABLE_PRIVILEGES), SCHEMA)
        ).fetchall()
        function = self.connection.execute(
            "SELECT pg_catalog.has_function_privilege(%s, %s, 'EXECUTE') AS allowed",
            (self.writer, SCHEMA + "." + FUNCTION + "()")).fetchone()
        return rows, function

    def test_actual_grants_split_readonly_planner_from_runtime_and_writer(self):
        writer_before = self.writer_snapshot()
        expected = {(WRITER_TABLE, name) for name in ("SELECT", "INSERT", "UPDATE")}
        self.assertEqual({(row["relname"], row["name"]) for row in writer_before[0]
                          if row["allowed"]}, expected)
        self.assertEqual(writer_before[1], {"allowed": True})
        with self.connection.cursor() as cursor:
            seal_planner_read_acl(cursor, namespace=SCHEMA)
        self.assertIsNone(self.mutation())
        self.assertEqual(self.writer_snapshot(), writer_before)
        with self.as_role(ROLE):
            for table in (BUSINESS, WRITER_TABLE):
                self.assertEqual(self.execute("SELECT payload FROM {} WHERE id=1",
                    self.object(table)).fetchone(), {"payload": "fixture"})
        denied = tuple((statement, self.object(BUSINESS)) for statement in (
            "INSERT INTO {} VALUES (2, 'denied')", "UPDATE {} SET payload='denied' WHERE id=1",
            "DELETE FROM {} WHERE id=1", "TRUNCATE {}")) + tuple(
            ("SELECT * FROM {}", self.object(table)) for table in EXCLUDED)
        for statement, target in denied:
            with self.subTest(statement=statement), self.assertRaises(psycopg.errors.InsufficientPrivilege):
                with self.as_role(ROLE):
                    self.execute(statement, target)
        for statement in ("SELECT pg_catalog.nextval(%s)", "SELECT pg_catalog.setval(%s, 2)"):
            with self.subTest(statement=statement), self.assertRaises(psycopg.errors.InsufficientPrivilege):
                with self.as_role(ROLE):
                    self.connection.execute(statement, (SCHEMA + "." + SEQUENCE,))
        with self.as_role(self.runtime):
            self.execute("INSERT INTO {} VALUES (2, 'runtime')", self.object(BUSINESS))
            self.execute("UPDATE {} SET payload='updated' WHERE id=2", self.object(BUSINESS))
            self.assertEqual(self.execute("SELECT payload FROM {} WHERE id=2",
                self.object(BUSINESS)).fetchone(), {"payload": "updated"})
            self.execute("DELETE FROM {} WHERE id=2", self.object(BUSINESS))
        for kind, privilege, name in (("TABLE", "UPDATE", BUSINESS), ("SEQUENCE", "USAGE", SEQUENCE)):
            with self.subTest(contamination=kind):
                self.connection.execute("SAVEPOINT nearby_contamination")
                try:
                    self.execute("GRANT " + privilege + " ON " + kind + " {} TO {}",
                                 self.object(name), sql.Identifier(ROLE))
                    self.assertIsNotNone(self.mutation())
                finally:
                    self.connection.execute("ROLLBACK TO SAVEPOINT nearby_contamination")
                    self.connection.execute("RELEASE SAVEPOINT nearby_contamination")
                self.assertIsNone(self.mutation())
        self.assertEqual(self.writer_snapshot(), writer_before)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--postgres-dsn", required=True)
    parser.add_argument("--disposable-cluster", action="store_true", required=True)
    arguments = parser.parse_args()
    CONNECTION_PARAMETERS = local_connection_parameters(arguments.postgres_dsn)
    DISPOSABLE_CLUSTER_ACKNOWLEDGED = arguments.disposable_cluster
    unittest.main(argv=[sys.argv[0]], verbosity=2)
