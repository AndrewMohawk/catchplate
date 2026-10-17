#!/usr/bin/env python3
"""Real PostgreSQL primary-tree triggers, not initialization authority.

An external approved harness supplies disposable PG16/UTF8 through an owned
mode-0700 Unix socket. No engine starts here. Each random schema, table, helper
and row lives inside one SERIALIZABLE transaction that is always rolled back;
there are no commits, concurrent sessions, registry replacements or DB-facade
imports. The executed DDL and tree SQL come from production source helpers.

Empty heads are explicit component setup, not accepted database genesis. The
initial-row case calls the real pure preparation and then inserts its exact
row, but supplies no signer, writer fence, one-use receipt or live installer.
Injected post-write failure proves transaction rollback only, not crash safety.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import unittest
import uuid
from contextlib import contextmanager
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate.native_postgres_results import run_native_fixture

from catchplate import authority_audit_initialization as initialization
from catchplate import authority_radix_proof as radix
from catchplate.authority_primary_contract import source_query_manifest_digest
from catchplate.authority_radix_mutation import PrimaryRoot
from catchplate.authority_store.metadata_schema_source import metadata_base_schema_source
from catchplate.authority_store.v9_schema_source import authority_v9_schema_source
from catchplate.authority_store import primary_tree_sql
from test_authority_audit_initialization import AGGREGATE, KEY, OUTBOX, aggregate_tree, absence, initial_row
from test_authority_audit_inventory import InventoryTree, outbox_row
from test_authority_radix_proof import sql_digest, sql_json, wire_digest, wire_json
from test_webauthn_trust_projection_postgres import local_connection_parameters


CONNECTION_PARAMETERS: dict[str, str | int] | None = None
ROOTS = "policy_authority_authenticated_table_roots"
NODES = "policy_authority_authenticated_tree_nodes"
LEAVES = "policy_authority_authenticated_leaves"
HISTORY = "policy_authority_authenticated_root_revisions"
BASE_TABLES = (OUTBOX, ROOTS, NODES, LEAVES, HISTORY)
ALL_TABLES = (*BASE_TABLES, AGGREGATE)
TRIGGER_FUNCTION = "catchplate_policy_authority_authenticated_trigger"
MANIFEST = source_query_manifest_digest()


class ReadTrace:
    """Observe real producer reads without replacing its psycopg cursor."""

    def __init__(self):
        self.entries = []

    def read(self, table, key):
        self.entries.append((table, key))


def production_table_statements() -> tuple[str, ...]:
    """Select six closed named declarations from actual pure schema sources."""
    base, extension = metadata_base_schema_source(), authority_v9_schema_source()
    if any(type(source) is not str or len(source.encode("utf-8")) > 16 * 1024 * 1024
           for source in (base, extension)):
        raise ValueError("production schema source exceeds fixture bound")
    statements = []
    for table in ALL_TABLES:
        source = extension if table == AGGREGATE else base
        matches = re.findall(r"^[ \t]*CREATE TABLE IF NOT EXISTS\s+" + re.escape(table)
            + r"\s*\(\n.*?^[ \t]*\);[ \t]*$", source, flags=re.MULTILINE | re.DOTALL)
        if len(matches) != 1:
            raise ValueError("production table declaration is not unique: " + table)
        statements.append(matches[0])
    return tuple(statements)


class AuthorityPrimaryTreePostgresTests(unittest.TestCase):
    def setUp(self) -> None:
        if CONNECTION_PARAMETERS is None:
            raise RuntimeError("requires an externally prepared --postgres-dsn")
        self.connection = psycopg.connect(**CONNECTION_PARAMETERS, autocommit=False)
        self.addCleanup(self.rollback_and_close)
        self.connection.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        self.connection.execute("SET LOCAL statement_timeout = '5s'")
        self.connection.execute("SET LOCAL lock_timeout = '250ms'")
        self.connection.execute("SET LOCAL idle_in_transaction_session_timeout = '10s'")
        environment = self.connection.execute(
            "SELECT pg_catalog.inet_server_addr(), pg_catalog.getdatabaseencoding(), "
            "pg_catalog.current_setting('server_version_num')::integer, "
            "current_user = session_user, pg_catalog.current_setting('transaction_isolation')"
        ).fetchone()
        if (environment is None or environment[0] is not None or environment[1] != "UTF8"
                or not 160000 <= environment[2] < 170000 or environment[3] is not True
                or environment[4] != "serializable"):
            raise RuntimeError("requires a direct Unix-socket PG16/UTF8 serializable session")
        self.schema = "primary_tree_" + uuid.uuid4().hex
        self.namespace = '"' + self.schema + '"'
        self.connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(self.schema)))
        self.connection.execute(sql.SQL("REVOKE ALL ON SCHEMA {} FROM PUBLIC").format(sql.Identifier(self.schema)))
        self.connection.execute(sql.SQL("SET LOCAL search_path TO {}, pg_catalog").format(sql.Identifier(self.schema)))
        for statement in production_table_statements():
            self.connection.execute(statement)
        self.install_functions()
        for table, key in ((OUTBOX, "id"), (AGGREGATE, "aggregate_id")):
            self.connection.execute(sql.SQL(
                "CREATE TRIGGER {} AFTER INSERT OR UPDATE OR DELETE ON {} "
                "FOR EACH ROW EXECUTE FUNCTION {}({})"
            ).format(sql.Identifier("component_primary_tree"), self.object(table),
                     self.object(TRIGGER_FUNCTION), sql.Literal(key)))
            self.connection.execute(sql.SQL(
                "INSERT INTO {} (table_name,root_revision,root_digest,leaf_count,tree_depth,tree_radix,"
                "manifest_digest,updated_at_epoch_ns) VALUES (%s,0,%s,0,64,16,%s,0)"
            ).format(self.object(ROOTS)), (table, InventoryTree([]).root.root_digest, MANIFEST))

    def install_functions(self) -> None:
        self.connection.execute(primary_tree_sql.canonical_json_function_sql(self.namespace))
        self.connection.execute(primary_tree_sql.framed_digest_function_sql(self.namespace))
        for statement in primary_tree_sql.authenticated_tree_functions_sql(self.namespace, manifest_digest=MANIFEST):
            self.connection.execute(statement)

    def rollback_and_close(self) -> None:
        try:
            self.connection.rollback()
        finally:
            self.connection.close()

    def object(self, table: str) -> sql.Identifier:
        return sql.Identifier(self.schema, table)

    @contextmanager
    def rollback_variant(self):
        self.connection.execute("SAVEPOINT primary_tree_variant")
        try:
            yield
        finally:
            self.connection.execute("ROLLBACK TO SAVEPOINT primary_tree_variant")
            self.connection.execute("RELEASE SAVEPOINT primary_tree_variant")

    def insert(self, table: str, row: dict) -> dict:
        return self.connection.execute(sql.SQL(
            "INSERT INTO {} AS inserted SELECT * FROM pg_catalog.jsonb_populate_record(NULL::{},%s) "
            "RETURNING pg_catalog.to_jsonb(inserted)"
        ).format(self.object(table), self.object(table)), (Jsonb(row),)).fetchone()[0]

    def stored_root(self, table: str) -> PrimaryRoot:
        result = self.connection.execute(sql.SQL(
            "SELECT root_revision,root_digest,leaf_count,tree_depth,tree_radix,manifest_digest FROM {} WHERE table_name=%s"
        ).format(self.object(ROOTS)), (table,)).fetchone()
        self.assertIsNotNone(result)
        self.assertEqual(result[3:], (64, 16, MANIFEST))
        return PrimaryRoot(table, result[0], result[1], result[2])

    def table_rows(self, table: str) -> list[dict]:
        return [row[0] for row in self.connection.execute(sql.SQL(
            'SELECT pg_catalog.to_jsonb(target) FROM {} AS target ORDER BY pg_catalog.to_jsonb(target)::text COLLATE "C"'
        ).format(self.object(table))).fetchall()]

    def snapshot(self) -> dict[str, list[dict]]:
        return {table: self.table_rows(table) for table in ALL_TABLES}

    def tree_snapshot(self, table: str) -> dict[str, list[dict]]:
        return {name: [row for row in self.table_rows(name) if row["table_name"] == table]
                for name in (ROOTS, NODES, LEAVES, HISTORY)}

    def assert_tree(self, tree) -> None:
        table = tree.root.table
        self.assertEqual(self.stored_root(table), tree.root)
        expected_nodes = dict(tree.nodes)
        if tree.root.root_revision and not tree.rows:
            # The real implementation retains a depth-zero empty node after
            # deleting its last leaf, unlike untouched empty genesis.
            expected_nodes[(0, "")] = tree.empty[0]
        actual_nodes = self.connection.execute(sql.SQL(
            "SELECT depth,path_prefix,node_digest,root_revision FROM {} WHERE table_name=%s"
        ).format(self.object(NODES)), (table,)).fetchall()
        self.assertEqual({(row[0], row[1]): row[2] for row in actual_nodes}, expected_nodes)
        self.assertTrue(all(0 < row[3] <= tree.root.root_revision for row in actual_nodes))
        expected_leaves = {}
        for key_bytes in tree.rows:
            address = sql_digest("catchplate.policyAuthorityAuthenticatedKey/v1", table.encode("ascii"), key_bytes)
            expected_leaves[address] = (key_bytes.decode("utf-8"), *tree.leaves[address])
        actual_leaves = self.connection.execute(sql.SQL(
            "SELECT key_digest,key_json,row_digest,leaf_digest,root_revision FROM {} WHERE table_name=%s"
        ).format(self.object(LEAVES)), (table,)).fetchall()
        self.assertEqual({row[0]: row[1:4] for row in actual_leaves}, expected_leaves)
        self.assertTrue(all(0 < row[4] <= tree.root.root_revision for row in actual_leaves))
        history = self.connection.execute(sql.SQL(
            "SELECT root_revision,previous_root_digest,root_digest,leaf_count,transaction_id,committed_at_epoch_ns "
            "FROM {} WHERE table_name=%s ORDER BY root_revision"
        ).format(self.object(HISTORY)), (table,)).fetchall()
        self.assertEqual([row[0] for row in history], list(range(1, tree.root.root_revision + 1)))
        if history:
            self.assertEqual(history[0][1], tree.empty[0])
            self.assertEqual(history[-1][2:4], (tree.root.root_digest, tree.root.leaf_count))
            self.assertTrue(all(later[1] == earlier[2] for earlier, later in zip(history, history[1:])))
            self.assertTrue(all(type(row[4]) is str and row[4] and type(row[5]) is int
                                and row[5] >= 0 and row[5] % 1000 == 0 for row in history))
        updated_at = self.connection.execute(sql.SQL(
            "SELECT updated_at_epoch_ns FROM {} WHERE table_name=%s"
        ).format(self.object(ROOTS)), (table,)).fetchone()[0]
        self.assertIs(type(updated_at), int)
        self.assertGreaterEqual(updated_at, 0)
        self.assertEqual(updated_at % 1000, 0)

    def assert_last_mutation(self, table: str, key: dict, row: dict | None, operation: str) -> None:
        actual = self.connection.execute(sql.SQL(
            "SELECT mutation_operation,mutation_key_digest,mutation_row_digest FROM {} "
            "WHERE table_name=%s ORDER BY root_revision DESC LIMIT 1"
        ).format(self.object(HISTORY)), (table,)).fetchone()
        expected_key = sql_digest("catchplate.policyAuthorityAuthenticatedKey/v1",
                                  table.encode("ascii"), sql_json(key))
        expected_row = None if row is None else sql_digest("catchplate.policyAuthorityAuthenticatedRow/v1",
                                                          table.encode("ascii"), sql_json(row))
        self.assertEqual(actual, (operation, expected_key, expected_row))

    def prepare_counter(self, rows: list[dict]):
        inventory = InventoryTree(rows, revision=self.stored_root(OUTBOX).root_revision)
        aggregate = aggregate_tree(revision=0)
        self.assert_tree(inventory)
        self.assert_tree(aggregate)
        return initialization.prepare_audit_capacity_initialization(
            outbox_root=self.stored_root(OUTBOX), outbox_records=inventory.records(),
            aggregate_root=self.stored_root(AGGREGATE), aggregate_absence=absence(aggregate),
            initialized_at_epoch_ns=1_000_000_000)

    def batch_fixture(self):
        # Seventeen actual rows leave populated off-path siblings, while four
        # selected identities cover presence and absence in both relations.
        rows = [outbox_row(f"batch-{index:02d}") for index in range(16)]
        for row in rows:
            self.assertEqual(self.insert(OUTBOX, row), row)
        # An ordinary aggregate identity, not the global counter that the live
        # planner deliberately keeps in its separate singleton proof block.
        aggregate_row = initial_row(16)
        aggregate_row.update(aggregate_id="native-batch-component",
                             aggregate_kind="native-batch-component")
        state = json.loads(aggregate_row["state_json"])
        state.update(aggregateId=aggregate_row["aggregate_id"],
                     aggregateKind=aggregate_row["aggregate_kind"])
        aggregate_row["state_json"] = wire_json(state).decode("ascii")
        aggregate_row["state_digest"] = wire_digest("catchplate.policyAuthorityAggregateState/v1", wire_json(state))
        self.assertEqual(self.insert(AGGREGATE, aggregate_row), aggregate_row)
        outbox, aggregate = InventoryTree(rows), aggregate_tree([aggregate_row])
        self.assert_tree(outbox)
        self.assert_tree(aggregate)
        first = outbox.record(rows[0]["id"])
        first_nibble = first["proof"]["siblings"][0]["selectedNibble"]
        # Pick from a fixed small corpus using the independent address hash.
        # Different first nibbles give exactly 127 outbox parents, so the
        # 16-parent schedule necessarily contains a physical cross-table batch.
        missing = next((f"absent-{index:02d}" for index in range(256)
            if sql_digest("catchplate.policyAuthorityAuthenticatedKey/v1",
                OUTBOX.encode("ascii"), sql_json({"id": f"absent-{index:02d}"}))[7] != first_nibble), None)
        self.assertIsNotNone(missing)
        records = [first, outbox.record(missing)]
        for key in ({"aggregate_id": aggregate_row["aggregate_id"]},
                    {"aggregate_id": "absent-component-aggregate"}):
            selected = aggregate.selected(key)
            records.append({"selectedRow": selected, "proof": aggregate.proof(selected)})
        selected = tuple(record["selectedRow"] for record in records)
        expected = tuple(sorted((record["proof"] for record in records),
                                key=lambda proof: (proof["table"], proof["keyDigest"])))
        roots = tuple(self.stored_root(table).json_projection() for table in (OUTBOX, AGGREGATE))
        return selected, roots, expected

    def read_batch(self, selected, roots, trace=None):
        with self.connection.cursor(row_factory=dict_row) as cursor:
            return radix.derive_multiproofs_batched(cursor, selected_rows=selected,
                roots=roots, trace=ReadTrace() if trace is None else trace, namespace=self.schema)

    def test_actual_schema_and_empty_ladder_match_independent_genesis(self) -> None:
        self.assertEqual(len(production_table_statements()), 6)
        for table, fields in ((OUTBOX, set(outbox_row())), (AGGREGATE, set(initial_row(0)))):
            actual = self.connection.execute(
                "SELECT column_name FROM information_schema.columns WHERE table_schema=%s AND table_name=%s",
                (self.schema, table),
            ).fetchall()
            self.assertEqual({row[0] for row in actual}, fields)
        self.assert_tree(InventoryTree([]))
        self.assert_tree(aggregate_tree())
        independent = InventoryTree([])
        for depth in (0, 1, 32, 63, 64):
            actual = self.connection.execute(sql.SQL(
                "SELECT {}(%s)"
            ).format(self.object("catchplate_policy_authority_authenticated_empty")), (depth,)).fetchone()[0]
            self.assertEqual(actual, independent.empty[depth])

    def test_real_trigger_insert_update_delete_roots_leaves_and_history(self) -> None:
        first = outbox_row("clé-雪😀", attempts=-2, actor_id=None)
        second = outbox_row("second", "claimed", claim_id="claim", last_error="café")

        def assert_equivalent(rows, revision):
            tree = InventoryTree(rows, revision=revision)
            self.assert_tree(tree)
            records = [tree.record(identifier) for identifier in
                       (first["id"], second["id"], "absent-rolling-empty-component")]
            selected = tuple(record["selectedRow"] for record in records)
            expected = tuple(sorted((record["proof"] for record in records),
                                    key=lambda proof: (proof["table"], proof["keyDigest"])))
            actual = self.read_batch(selected, (tree.root.json_projection(),))
            self.assertEqual(actual, expected)
            by_address = {(row["table"], row["keyDigest"]): row for row in selected}
            for proof in actual:
                self.assertEqual(radix.reconstruct_multiproof_root(proof,
                    selected=by_address[(proof["table"], proof["keyDigest"])]), tree.root.root_digest)
            # Real trigger statements retain their existing server-side bound.
            self.assertEqual(self.connection.execute("SHOW statement_timeout").fetchone(), ("5s",))

        self.assertEqual(self.insert(OUTBOX, first), first)
        assert_equivalent([first], revision=1)
        self.assert_last_mutation(OUTBOX, {"id": first["id"]}, first, "INSERT")
        self.assertEqual(self.insert(OUTBOX, second), second)
        assert_equivalent([first, second], revision=2)
        after = {**first, "status": "audited", "attempts": 3, "last_error": "終😀"}
        changed = self.connection.execute(sql.SQL(
            "UPDATE {} AS target SET status=%s,attempts=%s,last_error=%s WHERE id=%s "
            "RETURNING pg_catalog.to_jsonb(target)"
        ).format(self.object(OUTBOX)), (after["status"], after["attempts"], after["last_error"], first["id"])).fetchone()[0]
        self.assertEqual(changed, after)
        assert_equivalent([after, second], revision=3)
        self.assert_last_mutation(OUTBOX, {"id": first["id"]}, after, "UPDATE")
        self.assertEqual(self.connection.execute(sql.SQL("DELETE FROM {} WHERE id=%s")
            .format(self.object(OUTBOX)), (first["id"],)).rowcount, 1)
        assert_equivalent([second], revision=4)
        self.assert_last_mutation(OUTBOX, {"id": first["id"]}, None, "DELETE")
        self.assertEqual(self.connection.execute(sql.SQL("DELETE FROM {} WHERE id=%s")
            .format(self.object(OUTBOX)), (second["id"],)).rowcount, 1)
        assert_equivalent([], revision=5)
        self.assert_tree(aggregate_tree())

    def test_same_value_update_advances_revision_without_changing_digest_or_count(self) -> None:
        row = outbox_row("unchanged")
        self.insert(OUTBOX, row)
        before = self.stored_root(OUTBOX)
        self.assertEqual(self.connection.execute(sql.SQL(
            "UPDATE {} SET status=status WHERE id=%s"
        ).format(self.object(OUTBOX)), (row["id"],)).rowcount, 1)
        after = self.stored_root(OUTBOX)
        self.assertEqual((after.root_digest, after.leaf_count), (before.root_digest, before.leaf_count))
        self.assertEqual(after.root_revision, before.root_revision + 1)
        self.assert_tree(InventoryTree([row], revision=2))
        self.assert_last_mutation(OUTBOX, {"id": row["id"]}, row, "UPDATE")

    def test_duplicate_insert_changes_no_rows_nodes_roots_or_history(self) -> None:
        row = outbox_row("duplicate")
        self.insert(OUTBOX, row)
        before = self.snapshot()
        with self.assertRaises(psycopg.errors.UniqueViolation):
            with self.rollback_variant():
                self.insert(OUTBOX, {**row, "attempts": 999})
        self.assertEqual(self.snapshot(), before)
        self.assert_tree(InventoryTree([row], revision=1))

    def test_real_preparation_row_insert_matches_after_root_and_preserves_outbox(self) -> None:
        rows = [outbox_row("pending"), outbox_row("claimed", "claimed"), outbox_row("done", "audited")]
        for row in rows:
            self.insert(OUTBOX, row)
        preparation = self.prepare_counter(rows)
        document = preparation.json_projection()
        expected_row = initial_row(2, 1_000_000_000)
        self.assertEqual(document["counterRow"], expected_row)
        self.assertIs(document["installationPermitted"], False)
        unchanged = (self.table_rows(OUTBOX), self.tree_snapshot(OUTBOX))
        self.assertEqual(self.insert(AGGREGATE, document["counterRow"]), expected_row)
        self.assertEqual(self.table_rows(AGGREGATE), [expected_row])
        self.assert_tree(aggregate_tree([expected_row], revision=1))
        self.assert_last_mutation(AGGREGATE, KEY, expected_row, "INSERT")
        actual_after = [self.stored_root(table).json_projection() for table in (OUTBOX, AGGREGATE)]
        self.assertEqual(actual_after, document["afterRoots"])
        self.assertEqual((self.table_rows(OUTBOX), self.tree_snapshot(OUTBOX)), unchanged)

    def test_post_write_failure_rolls_back_entire_tree_and_allows_same_row_retry(self) -> None:
        rows = [outbox_row("rollback")]
        self.insert(OUTBOX, rows[0])
        row = self.prepare_counter(rows).json_projection()["counterRow"]
        before = self.snapshot()
        with self.assertRaises(psycopg.errors.DivisionByZero):
            with self.rollback_variant():
                self.insert(AGGREGATE, row)
                self.assert_tree(aggregate_tree([row], revision=1))
                # Deliberate post-write SQL failure inside this savepoint,
                # not a production receipt or initializer admission branch.
                self.connection.execute("SELECT 1 / 0")
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.insert(AGGREGATE, row), row)
        self.assert_tree(aggregate_tree([row], revision=1))
        self.assertEqual(self.tree_snapshot(OUTBOX), {
            name: [entry for entry in before[name] if entry["table_name"] == OUTBOX]
            for name in (ROOTS, NODES, LEAVES, HISTORY)})

    def test_missing_or_wrong_manifest_root_rejects_real_trigger_write_atomically(self) -> None:
        initial = self.snapshot()
        for remove in (False, True):
            with self.subTest(remove=remove), self.rollback_variant():
                if remove:
                    self.connection.execute(sql.SQL("DELETE FROM {} WHERE table_name=%s")
                        .format(self.object(ROOTS)), (OUTBOX,))
                else:
                    self.connection.execute(sql.SQL("UPDATE {} SET manifest_digest=%s WHERE table_name=%s")
                        .format(self.object(ROOTS)), ("sha256:" + "f" * 64, OUTBOX))
                before = self.snapshot()
                with self.assertRaisesRegex(psycopg.errors.RaiseException, "authenticated-tree root contract is unavailable"):
                    with self.rollback_variant():
                        self.insert(OUTBOX, outbox_row("denied"))
                self.assertEqual(self.snapshot(), before)
            self.assertEqual(self.snapshot(), initial)

    def test_batched_native_reader_matches_singletons_and_independent_cross_relation_proofs(self) -> None:
        selected, roots, expected = self.batch_fixture()
        before = self.snapshot()
        trace, singleton_trace = ReadTrace(), ReadTrace()
        actual = self.read_batch(selected, roots, trace)
        with self.connection.cursor(row_factory=dict_row) as cursor:
            singleton = radix.derive_multiproofs(cursor, selected_rows=selected,
                roots=roots, trace=singleton_trace, namespace=self.schema)
        self.assertEqual(actual, expected)
        self.assertEqual(actual, singleton)
        self.assertEqual(len(singleton_trace.entries), 65 * len(selected))
        parents = sorted({(proof["table"], level["depth"] + 1, level["pathPrefix"])
                          for proof in expected for level in proof["siblings"]})
        expected_batches = [parents[offset:offset + 16] for offset in range(0, len(parents), 16)]
        node_reads = [key for table, key in trace.entries if table == NODES]
        self.assertEqual(node_reads, [{"profile": "catchplate.policyAuthorityRadixReadBatch/v1",
            "parents": [{"tableName": table, "depth": depth, "pathPrefix": prefix}
                        for table, depth, prefix in batch]} for batch in expected_batches])
        self.assertTrue(any(len({parent["tableName"] for parent in key["parents"]}) == 2
                            for key in node_reads))
        self.assertEqual(len(trace.entries), len(selected) + len(expected_batches))
        self.assertLessEqual(len(trace.entries), 5 * len(selected))
        self.assertEqual([table for table, _ in trace.entries[:len(selected)]], [LEAVES] * len(selected))
        by_address = {(row["table"], row["keyDigest"]): row for row in selected}
        for proof in actual:
            self.assertEqual(radix.reconstruct_multiproof_root(proof,
                selected=by_address[(proof["table"], proof["keyDigest"])]),
                next(root["rootDigest"] for root in roots if root["table"] == proof["table"]))
        self.assertEqual(self.snapshot(), before)

    def test_batched_native_reader_rejects_bounded_projection_and_stale_node_revision(self) -> None:
        selected, roots, expected = self.batch_fixture()
        self.assertEqual(self.read_batch(selected, roots), expected)
        path = sql_digest("catchplate.policyAuthorityAuthenticatedKey/v1",
                          OUTBOX.encode("ascii"), sql_json(selected[0]["key"]))[7:]
        revision = self.stored_root(OUTBOX).root_revision
        before = self.snapshot()
        # Both changes obey the actual DDL: digest text is not syntax checked,
        # and a positive node revision need not be <= its relation head in SQL.
        # No constraint or trigger is disabled to inject these component faults.
        for column, value, diagnostic in (
            ("node_digest", "x" * 72, "authenticated batch child digest is not bounded database text"),
            ("root_revision", revision + 1, "authenticated batch child identity or revision changed"),
        ):
            with self.subTest(column=column), self.rollback_variant():
                self.assertEqual(self.connection.execute(sql.SQL(
                    "UPDATE {} SET {}=%s WHERE table_name=%s AND depth=1 AND path_prefix=%s"
                ).format(self.object(NODES), sql.Identifier(column)), (value, OUTBOX, path[:1])).rowcount, 1)
                with self.assertRaisesRegex(radix.RadixProofError, diagnostic):
                    self.read_batch(selected, roots)
            self.assertEqual(self.snapshot(), before)
            self.assertEqual(self.read_batch(selected, roots), expected)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--postgres-dsn", required=True)
    parser.add_argument("--prepared-result")
    arguments, test_arguments = parser.parse_known_args()
    CONNECTION_PARAMETERS = local_connection_parameters(arguments.postgres_dsn)
    run_native_fixture("scripts/test_authority_primary_tree_postgres.py",
        argv=[sys.argv[0], *test_arguments], result_path=arguments.prepared_result)
