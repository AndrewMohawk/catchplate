#!/usr/bin/env python3
"""Real PostgreSQL tests of shared executor fragments, not full v9 admission.

The external prepared runner owns an isolated PostgreSQL engine. This fixture
accepts only a private owned Unix socket, creates/drops one random schema, and
never starts an engine, imports db/registry, or fabricates successful authority.
Synthetic typed tables isolate CAS semantics; the executed selector, closed
record, presence and mutation SQL is the SAME renderer used by the installer.
Signed manifests, roots, witnesses, kernel completeness and deployed migration
are deliberately outside this component proof boundary.
"""
from __future__ import annotations

import argparse
import ast
import sys
import unittest
import uuid
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.types.json import Jsonb


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware.authority_store.mutation_sql import (
    apply_mutation_sql,
    closed_record_sql,
    locked_primary_key_row_sql,
    selected_row_matches_sql,
)
from test_webauthn_trust_projection_postgres import local_connection_parameters


CONNECTION_PARAMETERS: dict[str, str | int] | None = None
DECLARATIONS = """
    key_predicate text;
    update_columns text;
    current_row pg_catalog.jsonb;
    post_row pg_catalog.jsonb;
    key_names text[];
    supplied_key_names text[];
    matched_count bigint;
"""


def row(identifier: str = "a", **changes: object) -> dict:
    return {"id": identifier, "value": "before", "note": None, "key": None, **changes}


def mutation(operation: str, before: dict | None, after: dict | None,
             *, key: dict | None = None, table: str = "items") -> dict:
    image = before if before is not None else after
    return {
        "templateId": "component-only-not-an-admitted-template",
        "operation": operation, "table": table,
        "key": key if key is not None else {"id": image["id"]},
        # Not an authenticated digest: this fixture starts AFTER admission.
        "keyDigest": "sha256:" + "0" * 64,
        "expectedRow": before, "row": after,
    }


class AuthorityMutationPostgresTests(unittest.TestCase):
    @classmethod
    def connection(cls, *, autocommit: bool = True) -> psycopg.Connection:
        if CONNECTION_PARAMETERS is None:
            raise RuntimeError("this real-engine test requires --postgres-dsn")
        connection = psycopg.connect(**CONNECTION_PARAMETERS, autocommit=autocommit)
        connection.isolation_level = psycopg.IsolationLevel.SERIALIZABLE
        return connection

    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = "serverware_mutation_" + uuid.uuid4().hex
        cls.namespace = '"' + cls.schema + '"'
        with cls.connection() as connection:
            if connection.execute("SELECT inet_server_addr()").fetchone() != (None,):
                raise RuntimeError("PostgreSQL fixture must use a Unix socket")
            connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(cls.schema)))
        cls.addClassCleanup(cls.drop_schema)
        with cls.connection() as connection:
            connection.execute(f"""
                CREATE TABLE {cls.namespace}.items (
                    id text PRIMARY KEY, value text, note text, key jsonb
                );
                CREATE TABLE {cls.namespace}.composite_items (
                    tenant text, sequence bigint, value text,
                    PRIMARY KEY (tenant, sequence)
                );
                CREATE TABLE {cls.namespace}.nullable_selector_rows (
                    tenant text, tag text, value text
                );
                CREATE TABLE {cls.namespace}.duplicate_rows (
                    id text, value text, note text, key jsonb
                );
                CREATE FUNCTION {cls.namespace}.fixture_rewrite()
                RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $trigger$
                BEGIN
                    IF NEW.note = 'suppress' THEN RETURN NULL; END IF;
                    IF NEW.note = 'rewrite' THEN NEW.value := 'trigger-changed'; END IF;
                    RETURN NEW;
                END;
                $trigger$;
                CREATE TRIGGER fixture_rewrite BEFORE INSERT OR UPDATE
                    ON {cls.namespace}.items FOR EACH ROW
                    EXECUTE FUNCTION {cls.namespace}.fixture_rewrite();
                CREATE FUNCTION {cls.namespace}.fixture_restore_deleted()
                RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $trigger$
                BEGIN
                    IF OLD.note = 'restore-deleted' THEN
                        INSERT INTO {cls.namespace}.items SELECT OLD.*;
                    END IF;
                    RETURN OLD;
                END;
                $trigger$;
                CREATE TRIGGER fixture_restore_deleted AFTER DELETE
                    ON {cls.namespace}.items FOR EACH ROW
                    EXECUTE FUNCTION {cls.namespace}.fixture_restore_deleted();
            """)
            connection.execute(f"""
                CREATE FUNCTION {cls.namespace}.apply_one(mutation jsonb, key_columns jsonb)
                RETURNS jsonb LANGUAGE plpgsql SET search_path = pg_catalog AS $apply$
                DECLARE {DECLARATIONS}
                BEGIN
                    IF NOT {closed_record_sql('mutation')} THEN
                        RAISE EXCEPTION 'fixture closed mutation rejected';
                    END IF;
                    {apply_mutation_sql(cls.namespace)}
                    RETURN post_row;
                END;
                $apply$;
                CREATE FUNCTION {cls.namespace}.apply_pair(first_mutation jsonb, second_mutation jsonb)
                RETURNS void LANGUAGE plpgsql SET search_path = pg_catalog AS $pair$
                BEGIN
                    PERFORM {cls.namespace}.apply_one(first_mutation, '["id"]'::jsonb);
                    PERFORM {cls.namespace}.apply_one(second_mutation, '["id"]'::jsonb);
                END;
                $pair$;
                CREATE FUNCTION {cls.namespace}.closed_shapes(mutation jsonb, authorization_source jsonb)
                RETURNS boolean[] LANGUAGE sql SET search_path = pg_catalog AS $shape$
                    SELECT ARRAY[{closed_record_sql('mutation')},
                        {closed_record_sql('authorization_source')}];
                $shape$;
            """)
            for record in ("selected_row", "authorization_source"):
                closed = (
                    f"IF NOT {closed_record_sql(record)} THEN "
                    "RAISE EXCEPTION 'fixture closed authorization rejected'; END IF;"
                    if record == "authorization_source" else ""
                )
                connection.execute(f"""
                    CREATE FUNCTION {cls.namespace}.read_{record}({record} jsonb, key_columns jsonb)
                    RETURNS jsonb LANGUAGE plpgsql SET search_path = pg_catalog AS $read$
                    DECLARE {DECLARATIONS}
                    BEGIN
                        {closed}
                        {locked_primary_key_row_sql(cls.namespace, record)}
                        IF NOT {selected_row_matches_sql(record)} THEN
                            RAISE EXCEPTION 'fixture selected image rejected';
                        END IF;
                        RETURN current_row;
                    END;
                    $read$;
                    CREATE FUNCTION {cls.namespace}.matches_{record}({record} jsonb, current_row jsonb)
                    RETURNS boolean LANGUAGE sql SET search_path = pg_catalog AS $matches$
                        SELECT {selected_row_matches_sql(record)};
                    $matches$;
                """)

    @classmethod
    def drop_schema(cls) -> None:
        with cls.connection() as connection:
            connection.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(cls.schema)))

    def setUp(self) -> None:
        with self.connection() as connection:
            connection.execute(f"""TRUNCATE {self.namespace}.items,
                {self.namespace}.composite_items, {self.namespace}.nullable_selector_rows,
                {self.namespace}.duplicate_rows""")

    def apply(self, value: dict, keys: object = ("id",),
              connection: psycopg.Connection | None = None) -> object:
        if connection is None:
            with self.connection() as local:
                return self.apply(value, keys, local)
        key_value = list(keys) if isinstance(keys, tuple) else keys
        return connection.execute(f"SELECT {self.namespace}.apply_one(%s, %s)",
                                  (Jsonb(value), Jsonb(key_value))).fetchone()[0]

    def rows(self, table: str = "items") -> list[dict]:
        with self.connection() as connection:
            return [entry[0] for entry in connection.execute(
                sql.SQL("SELECT to_jsonb(target) FROM {}.{} AS target ORDER BY to_jsonb(target)::text")
                .format(sql.Identifier(self.schema), sql.Identifier(table))
            ).fetchall()]

    def assert_rejected(self, value: dict, message: str, keys: object = ("id",)) -> None:
        before = self.rows(value["table"])
        with self.assertRaisesRegex(psycopg.errors.RaiseException, message):
            self.apply(value, keys)
        self.assertEqual(self.rows(value["table"]), before)

    def test_insert_update_delete_execute_exact_shared_sql(self) -> None:
        before = row()
        after = row(value="after", note="nullable field changed")
        self.assertEqual(self.apply(mutation("INSERT", None, before)), before)
        self.assertEqual(self.apply(mutation("UPDATE", before, after)), after)
        self.assertIsNone(self.apply(mutation("DELETE", after, None)))
        self.assertEqual(self.rows(), [])

    def test_insert_collision_and_absent_update_delete_are_rejected(self) -> None:
        before = row()
        for operation, after in (("UPDATE", row(value="after")), ("DELETE", None)):
            self.assert_rejected(mutation(operation, before, after), "CAS precondition changed")
        self.apply(mutation("INSERT", None, before))
        self.assert_rejected(mutation("INSERT", None, before), "CAS precondition changed")

    def test_expected_row_requires_explicit_null_or_exact_object(self) -> None:
        valid = mutation("INSERT", None, row())
        for invalid in ({}, [], False, "null", 0):
            self.assert_rejected({**valid, "expectedRow": invalid}, "CAS precondition changed")
        missing = dict(valid)
        del missing["expectedRow"]
        self.assert_rejected(missing, "fixture closed mutation rejected")
        self.apply(valid)
        for operation, after in (("UPDATE", row(value="after")), ("DELETE", None)):
            for invalid in (None, {}, [], False, "null", {**row(), "note": "stale"}):
                self.assert_rejected(mutation(operation, invalid, after, key={"id": "a"}),
                                     "CAS precondition changed")

    def test_post_rows_are_exact_and_missing_images_are_not_null(self) -> None:
        self.apply(mutation("INSERT", None, row()))
        for operation in ("UPDATE", "DELETE"):
            for invalid in ([], False, "null", 0):
                expected = "delete precondition is invalid" if operation == "DELETE" else "row image is invalid"
                self.assert_rejected(mutation(operation, row(), invalid), expected)
            missing = mutation(operation, row(), None)
            del missing["row"]
            self.assert_rejected(missing, "fixture closed mutation rejected")
        # Missing optional SQL-null columns in the planned JSON are not silently
        # equivalent to the complete post-row emitted by PostgreSQL.
        self.assert_rejected(mutation("UPDATE", row(), {"id": "a", "value": "after"}),
                             "mutation postcondition changed")
        self.assert_rejected(mutation("UPDATE", row(), {**row(), "extra": "not a column"}),
                             "mutation postcondition changed")
        self.assert_rejected(mutation("UPDATE", row(), None), "row image is invalid")
        self.assert_rejected(mutation("DELETE", row(), {}), "delete precondition is invalid")
        with self.assertRaises(psycopg.errors.NotNullViolation):
            self.apply(mutation("UPDATE", row(), {}))
        self.assertEqual(self.rows(), [row()])

    def test_payload_key_cannot_retarget_update_and_key_moves_roll_back(self) -> None:
        before, decoy = row(), row("decoy")
        self.apply(mutation("INSERT", None, before))
        self.apply(mutation("INSERT", None, decoy))
        after = row(value="only-a", key={"id": "decoy"})
        self.assertEqual(self.apply(mutation("UPDATE", before, after)), after)
        self.assertIn(decoy, self.rows())
        self.assert_rejected(mutation("UPDATE", after, {**after, "id": "moved"}),
                             "mutation postcondition changed")
        self.assert_rejected(mutation("INSERT", None, row("payload"), key={"id": "selector"}),
                             "mutation postcondition changed")

    def test_composite_keys_and_nullable_selector_fields_remain_typed(self) -> None:
        before = {"tenant": "tenant", "sequence": 7, "value": None}
        after = {**before, "value": "after"}
        key = {"tenant": "tenant", "sequence": 7}
        for operation, expected, result in (("INSERT", None, before), ("UPDATE", before, after),
                                            ("DELETE", after, None)):
            self.assertEqual(self.apply(mutation(operation, expected, result, key=key,
                                                 table="composite_items"), ("tenant", "sequence")), result)
        with self.assertRaises(psycopg.errors.NotNullViolation):
            self.apply(mutation("INSERT", None, {**before, "sequence": None},
                                key={**key, "sequence": None}, table="composite_items"),
                       ("tenant", "sequence"))
        self.assertEqual(self.rows("composite_items"), [])
        # A synthetic logical selector verifies IS NOT DISTINCT FROM null
        # semantics. It does NOT claim nullable fields are admitted physical PKs.
        before = {"tenant": "tenant", "tag": None, "value": "before"}
        after = {**before, "value": "after"}
        key = {"tenant": "tenant", "tag": None}
        for operation, expected, result in (("INSERT", None, before), ("UPDATE", before, after),
                                            ("DELETE", after, None)):
            self.assertEqual(self.apply(mutation(operation, expected, result, key=key,
                                                 table="nullable_selector_rows"), ("tenant", "tag")), result)

    def test_cardinality_zero_or_multiple_rolls_back(self) -> None:
        self.assert_rejected(mutation("INSERT", None, row(note="suppress")),
                             "mutation cardinality is not exact")
        self.apply(mutation("INSERT", None, row()))
        self.assert_rejected(mutation("UPDATE", row(), row(note="suppress")),
                             "mutation cardinality is not exact")
        with self.connection() as connection:
            connection.execute(f"INSERT INTO {self.namespace}.duplicate_rows SELECT * FROM {self.namespace}.items")
            connection.execute(f"INSERT INTO {self.namespace}.duplicate_rows SELECT * FROM {self.namespace}.items")
        for operation, after in (("UPDATE", row(value="after")), ("DELETE", None)):
            self.assert_rejected(mutation(operation, row(), after, table="duplicate_rows"),
                                 "mutation cardinality is not exact")

    def test_trigger_changed_postcondition_and_delete_survivor_roll_back(self) -> None:
        self.assert_rejected(mutation("INSERT", None, row(note="rewrite")), "mutation postcondition changed")
        self.apply(mutation("INSERT", None, row()))
        self.assert_rejected(mutation("UPDATE", row(), row(note="rewrite")), "mutation postcondition changed")
        restored = row("restored", note="restore-deleted")
        self.apply(mutation("INSERT", None, restored))
        self.assert_rejected(mutation("DELETE", restored, None), "mutation postcondition changed")

    def test_later_failed_mutation_rolls_back_prior_write_in_same_statement(self) -> None:
        with self.connection() as connection:
            with self.assertRaisesRegex(psycopg.errors.RaiseException, "CAS precondition changed"):
                connection.execute(f"SELECT {self.namespace}.apply_pair(%s, %s)", (
                    Jsonb(mutation("INSERT", None, row())),
                    Jsonb(mutation("UPDATE", row("absent"), row("absent", value="after"))),
                ))
        self.assertEqual(self.rows(), [])

    def test_closed_object_guards_use_real_postgres_for_exact_sets(self) -> None:
        valid_mutation = mutation("INSERT", None, row())
        valid_auth = {"table": "items", "selector": {"id": "a"}, "present": False,
                      "row": None, "rowDigest": "component-not-authority"}
        with self.connection() as connection:
            self.assertEqual(connection.execute(f"SELECT {self.namespace}.closed_shapes(%s, %s)",
                                                (Jsonb(valid_mutation), Jsonb(valid_auth))).fetchone()[0], [True, True])
            for index, valid in enumerate((valid_mutation, valid_auth)):
                missing = dict(valid)
                del missing[next(iter(missing))]
                swapped = {**missing, "unexpected": None}
                for invalid in (None, False, 0, "object", [], missing, swapped, {**valid, "extra": None}):
                    args = [Jsonb(valid_mutation), Jsonb(valid_auth)]
                    args[index] = Jsonb(invalid)
                    result = connection.execute(f"SELECT {self.namespace}.closed_shapes(%s, %s)", args).fetchone()[0]
                    self.assertIs(result[index], False)
                args = [Jsonb(valid_mutation), Jsonb(valid_auth)]
                args[index] = None  # SQL NULL, distinct from explicit JSON null.
                self.assertIs(connection.execute(f"SELECT {self.namespace}.closed_shapes(%s, %s)", args)
                              .fetchone()[0][index], False)

    def test_presence_matchers_reject_missing_coerced_and_stale_images(self) -> None:
        with self.connection() as connection:
            for record in ("selected_row", "authorization_source"):
                query = f"SELECT {self.namespace}.matches_{record}(%s, %s)"
                for actual, valid in ((None, {"present": False, "row": None}),
                                      (Jsonb(row()), {"present": True, "row": row()})):
                    self.assertIs(connection.execute(query, (Jsonb(valid), actual)).fetchone()[0], True)
                    missing_row = {"present": valid["present"]}
                    for invalid in ({}, {"row": valid["row"]}, missing_row, None, [],
                                    {**valid, "present": str(valid["present"]).lower()},
                                    {**valid, "present": int(valid["present"])},
                                    {**valid, "present": None}, {**valid, "row": []},
                                    {**valid, "row": "null"}, {**valid, "row": {"id": "a"}}):
                        self.assertIs(connection.execute(query, (Jsonb(invalid), actual)).fetchone()[0], False)
                self.assertIs(connection.execute(query, (Jsonb({"present": False, "row": None}),
                                                         Jsonb(row()))).fetchone()[0], False)
                self.assertIs(connection.execute(query, (Jsonb({"present": True, "row": row()}),
                                                         None)).fetchone()[0], False)

    def test_all_three_selector_paths_use_exact_quoted_namespace_and_hold_locks(self) -> None:
        self.apply(mutation("INSERT", None, row()))
        for record in ("selected_row", "authorization_source"):
            key_field = "selector" if record == "authorization_source" else "key"
            selected = {"table": "items", key_field: {"id": "a"}, "present": True, "row": row()}
            if record == "authorization_source":
                selected["rowDigest"] = "component-not-authority"
            with self.connection(autocommit=False) as holder:
                self.assertEqual(holder.execute("SHOW transaction_isolation").fetchone(), ("serializable",))
                self.assertEqual(holder.execute(f"SELECT {self.namespace}.read_{record}(%s, %s)",
                                               (Jsonb(selected), Jsonb(["id"]))).fetchone()[0], row())
                with self.connection() as waiter:
                    with self.assertRaises(psycopg.errors.LockNotAvailable):
                        waiter.execute(f"UPDATE {self.namespace}.items SET value=value WHERE id='a'")
                    holder.rollback()
                    self.assertEqual(waiter.execute(f"UPDATE {self.namespace}.items SET value=value WHERE id='a'").rowcount, 1)
            absent = {**selected, key_field: {"id": "absent"}, "present": False, "row": None}
            with self.connection() as connection:
                self.assertIsNone(connection.execute(f"SELECT {self.namespace}.read_{record}(%s, %s)",
                                                     (Jsonb(absent), Jsonb(["id"]))).fetchone()[0])
        with self.connection(autocommit=False) as holder:
            self.apply(mutation("UPDATE", row(), row(value="locked")), connection=holder)
            with self.connection() as waiter:
                with self.assertRaises(psycopg.errors.LockNotAvailable):
                    waiter.execute(f"UPDATE {self.namespace}.items SET value=value WHERE id='a'")
            holder.rollback()
        self.assertEqual(self.rows(), [row()])

    def test_key_catalog_closure_rejects_empty_partial_and_inexact_selectors(self) -> None:
        for keys, key, message in (
            ([], {}, "primary key columns are invalid"),
            (["id", "absent_column"], {"id": "a", "absent_column": None}, "catalog columns are not exact"),
            (["absent_column"], {"absent_column": None}, "catalog columns are not exact"),
            (["id", "id"], {"id": "a"}, "selector is not exact"),
            (["id"], {}, "selector is not exact"),
            (["id"], {"id": "a", "extra": None}, "selector is not exact"),
            ([1], {"1": "a"}, "primary key columns are invalid"),
            ({}, {"id": "a"}, "primary key selector is invalid"),
        ):
            self.assert_rejected(mutation("INSERT", None, row(), key=key), message, keys)

    def test_source_interpolation_and_namespace_input_boundary(self) -> None:
        # Source-only wiring, separate from the real PostgreSQL controls above.
        tree = ast.parse((ROOT / "serverware/authority_store/executor_v9.py").read_text(encoding="utf-8"))
        installer = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                         and node.name == "install_authority_v9_executor")
        calls = [node.func.id for node in ast.walk(installer)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
        for name, count in (("apply_mutation_sql", 1), ("locked_primary_key_row_sql", 2),
                            ("selected_row_matches_sql", 2), ("closed_record_sql", 2)):
            self.assertEqual(calls.count(name), count)
        for invalid in (None, "schema", '"a";SELECT 1', '"A"', '"a-b"', '"' + "a" * 129 + '"'):
            with self.subTest(namespace=invalid), self.assertRaisesRegex(ValueError, "exact quoted identifier"):
                apply_mutation_sql(invalid)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--postgres-dsn", required=True)
    arguments, test_arguments = parser.parse_known_args()
    CONNECTION_PARAMETERS = local_connection_parameters(arguments.postgres_dsn)
    unittest.main(argv=[sys.argv[0], *test_arguments])
