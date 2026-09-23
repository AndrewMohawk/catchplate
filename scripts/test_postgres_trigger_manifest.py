#!/usr/bin/env python3
"""Real PostgreSQL trigger-manifest components, not full schema/startup admission.

An externally prepared runner owns the disposable, no-network Unix-socket
cluster. These tests call the same native catalog readers and definition
normalizer used by production. No missing-kernel registry is substituted.
"""
from __future__ import annotations

import argparse
import copy
import sys
import unittest
import uuid
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.rows import dict_row

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware.authority_store import postgres_trigger_manifest as catalog
from serverware.authority_store import schema as production_schema
from serverware.db_common import dumps
from test_webauthn_trust_projection_postgres import local_connection_parameters

CONNECTION_PARAMETERS: dict[str, str | int] | None = None


def component_digest(value: dict) -> str:
    # Same canonical serializer and framing used by the complete manifest,
    # but this preimage deliberately covers only these two catalog components.
    return production_schema._policy_candidate_authority_framed_digest(
        "serverware.policyCandidateAuthorityStructuralManifest/v1",
        dumps(value).encode("utf-8"),
    )


class PostgresTriggerManifestTests(unittest.TestCase):
    @classmethod
    def connection(cls) -> psycopg.Connection:
        if CONNECTION_PARAMETERS is None:
            raise RuntimeError("this real-engine test requires --postgres-dsn")
        return psycopg.connect(
            **CONNECTION_PARAMETERS, autocommit=True, row_factory=dict_row,
        )

    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = "serverware_trigger_" + uuid.uuid4().hex
        cls.other_schema = "serverware_trigger_" + uuid.uuid4().hex
        with cls.connection() as connection:
            if connection.execute("SELECT inet_server_addr() AS address").fetchone() != {"address": None}:
                raise RuntimeError("PostgreSQL fixture must use a Unix socket")
            for namespace in (cls.schema, cls.other_schema):
                connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(namespace)))
                cls.addClassCleanup(cls.drop_schema, namespace)
                connection.execute(sql.SQL(
                    "CREATE TABLE {}.target (value integer NOT NULL)"
                ).format(sql.Identifier(namespace)))
                connection.execute(sql.SQL("""
                    CREATE FUNCTION {}.bump() RETURNS trigger LANGUAGE plpgsql
                    SET search_path = pg_catalog AS $fixture$
                    BEGIN NEW.value := NEW.value + 1; RETURN NEW; END;
                    $fixture$
                """).format(sql.Identifier(namespace)))
                # Reverse creation order makes catalog ordering independently visible.
                for name in ("z_guard", "a_guard"):
                    connection.execute(sql.SQL(
                        "CREATE TRIGGER {} BEFORE INSERT ON {}.target "
                        "FOR EACH ROW EXECUTE FUNCTION {}.bump()"
                    ).format(sql.Identifier(name), sql.Identifier(namespace), sql.Identifier(namespace)))

    @classmethod
    def drop_schema(cls, namespace: str) -> None:
        with cls.connection() as connection:
            connection.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(namespace)))

    def setUp(self) -> None:
        with self.connection() as connection:
            for namespace in (self.schema, self.other_schema):
                self.set_mode(connection, namespace, "O")
                connection.execute(sql.SQL("TRUNCATE {}.target").format(sql.Identifier(namespace)))

    def set_mode(self, connection: psycopg.Connection, namespace: str, mode: str) -> None:
        command = {"O": "ENABLE", "A": "ENABLE ALWAYS", "R": "ENABLE REPLICA", "D": "DISABLE"}[mode]
        connection.execute(sql.SQL("ALTER TABLE {}.target {} TRIGGER a_guard").format(
            sql.Identifier(namespace), sql.SQL(command),
        ))

    def read(self, connection: psycopg.Connection, namespace: str | None = None) -> dict:
        namespace = namespace or self.schema
        return {
            "table": catalog.table_trigger_manifest(
                connection, namespace=namespace, table="target",
                canonical_definition=lambda value: production_schema._policy_candidate_authority_canonicalize_namespace(
                    value, actual_namespace=namespace, canonical_namespace="fixture_namespace",
                ),
                object_definition=production_schema._policy_candidate_authority_object_definition,
            ),
            "schema": catalog.schema_trigger_manifest(connection, namespace=namespace),
        }

    def assert_baseline(self, value: dict) -> None:
        for entries in value.values():
            self.assertEqual([item["name"] for item in entries], ["a_guard", "z_guard"])
            self.assertEqual([item["enabledMode"] for item in entries], ["O", "O"])
            self.assertEqual([item["function"] for item in entries], ["bump", "bump"])

    def test_each_mode_changes_both_manifests_without_changing_definition(self) -> None:
        with self.connection() as connection:
            baseline = self.read(connection)
            self.assert_baseline(baseline)
            for mode in ("D", "R", "A"):
                with self.subTest(mode=mode):
                    self.set_mode(connection, self.schema, mode)
                    actual = self.read(connection)
                    expected = copy.deepcopy(baseline)
                    for entries in expected.values():
                        entries[0]["enabledMode"] = mode
                    self.assertEqual(actual, expected)
                    self.assertNotEqual(actual, baseline)
                    self.assertNotEqual(component_digest(actual), component_digest(baseline))
                    self.assertEqual(actual["table"][0]["definition"], baseline["table"][0]["definition"])
                    self.assertEqual(actual["table"][0]["definitionDigest"], baseline["table"][0]["definitionDigest"])
            self.set_mode(connection, self.schema, "O")
            self.assertEqual(self.read(connection), baseline)

    def test_modes_are_not_boolean_equivalents_in_origin_session(self) -> None:
        with self.connection() as connection:
            self.assertEqual(connection.execute("SHOW session_replication_role").fetchone(), {"session_replication_role": "origin"})
            self.assert_baseline(self.read(connection))
            for mode, expected in (("O", 2), ("D", 1), ("R", 1), ("A", 2)):
                with self.subTest(mode=mode):
                    self.set_mode(connection, self.schema, mode)
                    row = connection.execute(sql.SQL(
                        "INSERT INTO {}.target VALUES (0) RETURNING value"
                    ).format(sql.Identifier(self.schema))).fetchone()
                    self.assertEqual(row, {"value": expected})

    def test_namespace_and_table_are_exact_not_search_path_or_prefix(self) -> None:
        with self.connection() as connection:
            baseline = self.read(connection)
            self.assert_baseline(baseline)
            self.set_mode(connection, self.other_schema, "D")
            connection.execute(sql.SQL("SET search_path TO {}, pg_catalog").format(sql.Identifier(self.other_schema)))
            self.assertEqual(self.read(connection), baseline)
            other = self.read(connection, self.other_schema)
            self.assertEqual(other["table"][0]["enabledMode"], "D")
            self.assertEqual(other["schema"][0]["enabledMode"], "D")
            self.assertEqual(catalog.schema_trigger_manifest(connection, namespace=self.schema + "x"), [])
            self.assertEqual(catalog.table_trigger_manifest(
                connection, namespace=self.schema, table="target_suffix",
                canonical_definition=production_schema._policy_candidate_authority_normalize_sql,
                object_definition=production_schema._policy_candidate_authority_object_definition,
            ), [])

    def test_legacy_mode_omission_is_not_normalized_to_current(self) -> None:
        with self.connection() as connection:
            actual = self.read(connection)
        self.assert_baseline(actual)
        legacy = copy.deepcopy(actual)
        for entries in legacy.values():
            for item in entries:
                del item["enabledMode"]
        self.assertNotEqual(actual, legacy)
        self.assertNotEqual(component_digest(actual), component_digest(legacy))

    def test_mode_serializer_rejects_missing_or_unknown_values(self) -> None:
        for mode in ("O", "A", "R", "D"):
            self.assertEqual(catalog.trigger_enabled_mode({"enabled_mode": mode}), mode)
        for row in ({}, *({"enabled_mode": value} for value in (None, True, False, 0, 1, "", "o", "OA", "X", [], {}))):
            with self.subTest(row=row), self.assertRaisesRegex(ValueError, "enabled mode is missing or invalid"):
                catalog.trigger_enabled_mode(row)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--postgres-dsn", required=True)
    arguments, test_arguments = parser.parse_known_args()
    CONNECTION_PARAMETERS = local_connection_parameters(arguments.postgres_dsn)
    unittest.main(argv=[sys.argv[0], *test_arguments])
