#!/usr/bin/env python3
"""Native snapshot-relative audit initialization reads, never installation.

The external prepared harness supplies disposable PG16/UTF8 via an owned
0700 Unix socket. Production DDL, actual tree triggers and the actual bounded
SQL adapter are used. Independent tiny trees supply expected hashes/proofs,
not the adapter's DB proof producer. Every schema and mutation is rolled back.

The caller owns an already-active serializable transaction; acquiring locks
does not make its snapshot independently fresh. These tests grant no schema,
signer, writer-fence, one-use receipt, commit/crash or initializer authority.
There is no registry replacement, fabricated successful verifier, DB-facade
import, engine startup or concurrent committed-schema fixture.
"""
from __future__ import annotations

import argparse
import ast
import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.pq import TransactionStatus
from psycopg.rows import dict_row


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_audit_initialization_postgres as adapter
from serverware import authority_audit_initialization as initialization
from serverware import authority_radix_proof as radix
import test_authority_primary_tree_postgres as tree_fixture
import test_authority_audit_initialization as initialization_fixture
from test_authority_audit_inventory import InventoryTree, outbox_row
from test_authority_audit_initialization import AGGREGATE, OUTBOX, aggregate_tree, initial_row
from test_authority_radix_proof import sql_digest, sql_json, wire_digest, wire_json
from test_webauthn_trust_projection_postgres import local_connection_parameters


CONNECTION_PARAMETERS: dict[str, str | int] | None = None
TIME_NS = 1_000_000_000
WRONG_DIGEST = "sha256:" + "f" * 64


def read_limits(**changes):
    values = dict(max_rows=100, max_total_bytes=64 * 1024 * 1024,
        max_queries=10_000, statement_timeout_ms=5_000, lock_timeout_ms=250,
        total_timeout_ms=60_000, max_record_bytes=1024 * 1024)
    values.update(changes)
    return adapter.AuditInitializationReadLimits(**values)


def other_aggregate(identity):
    """DDL-valid opaque non-global row; not an admitted business operation."""
    row = initial_row(0)
    row["aggregate_kind"] = "native-component-other"
    row["partition_digest"] = wire_digest("fixture.otherAggregate/v1", identity.encode("utf-8"))
    row["aggregate_id"] = row["aggregate_kind"] + ":" + row["partition_digest"]
    state = json.loads(row["state_json"])
    state.update(aggregateId=row["aggregate_id"], aggregateKind=row["aggregate_kind"],
                 partitionDigest=row["partition_digest"])
    row["state_json"] = wire_json(state).decode("ascii")
    row["state_digest"] = wire_digest("serverware.policyAuthorityAggregateState/v1", wire_json(state))
    return row


class AuditInitializationPostgresTests(unittest.TestCase):
    def setUp(self):
        if CONNECTION_PARAMETERS is None:
            raise RuntimeError("requires an externally prepared --postgres-dsn")
        # Composition reuses the real rollback-only production-DDL setup, but
        # does not inherit or rediscover the other module's seven test methods.
        tree_fixture.CONNECTION_PARAMETERS = CONNECTION_PARAMETERS
        self.store = tree_fixture.AuthorityPrimaryTreePostgresTests("runTest")
        self.addCleanup(self.cleanup_store)
        self.store.setUp()
        self.connection = self.store.connection
        self.outbox = InventoryTree([])
        self.aggregate = aggregate_tree()

    def cleanup_store(self):
        # This composed TestCase is never run, so a cleanup failure must be
        # propagated to our real test result rather than lost in its outcome.
        self.assertTrue(self.store.doCleanups(), "tree fixture rollback or close failed")

    def seed(self, rows=(), aggregate_rows=()):
        for row in rows:
            self.store.insert(OUTBOX, row)
        for row in aggregate_rows:
            self.store.insert(AGGREGATE, row)
        self.outbox = InventoryTree(list(rows))
        self.aggregate = aggregate_tree(list(aggregate_rows))
        self.store.assert_tree(self.outbox)
        self.store.assert_tree(self.aggregate)

    def mixed(self):
        return [outbox_row("z-last", "pending"),
                {**outbox_row("clé-雪😀", "claimed"), "attempts": -3, "actor_id": "historical-雪"},
                {**outbox_row("", "audited"), "storage_format_version": None,
                 "claim_id": None, "audit_event_hash": "historical-not-authority"}]

    def prepare(self, **changes):
        arguments = dict(expected_outbox_root=self.outbox.root,
            expected_aggregate_root=self.aggregate.root, initialized_at_epoch_ns=TIME_NS,
            limits=read_limits(), namespace=self.store.schema)
        arguments.update(changes)
        return adapter.prepare_audit_capacity_initialization_from_postgres(
            self.connection, **arguments)

    def expected(self, timestamp=TIME_NS):
        return initialization_fixture.AuditCapacityInitializationTests.expected(
            self, outbox=self.outbox, aggregate=self.aggregate, timestamp=timestamp)

    def reject(self, expected_message=None, **changes):
        with self.assertRaises(adapter.AuditInitializationPostgresError) as raised:
            self.prepare(**changes)
        if expected_message is not None:
            self.assertEqual(str(raised.exception), expected_message)
        return raised.exception

    def without_tree_trigger(self, statement, parameters):
        # Privileged component corruption only: restore the real attachment
        # before the adapter runs, so no missing-trigger success is simulated.
        self.connection.execute(sql.SQL("ALTER TABLE {} DISABLE TRIGGER component_primary_tree")
            .format(self.store.object(OUTBOX)))
        try:
            self.connection.execute(statement, parameters)
        finally:
            self.connection.execute(sql.SQL("ALTER TABLE {} ENABLE TRIGGER component_primary_tree")
                .format(self.store.object(OUTBOX)))

    def test_mixed_unicode_rows_match_independent_full_preparation_without_writes(self):
        self.seed(self.mixed())
        before = self.store.snapshot()
        expected = self.expected()
        result = self.prepare(limits=read_limits(max_rows=3))
        self.assertIs(type(result), initialization.AuditCapacityInitializationPreparation)
        self.assertEqual(result.json_projection(), expected)
        self.assertEqual(result.canonical_bytes, wire_json(expected))
        self.assertEqual(result.digest, wire_digest(initialization_fixture.SCHEMA, wire_json(expected)))
        self.assertIs(result.json_projection()["installationPermitted"], False)
        self.assertEqual(self.store.snapshot(), before)
        self.assertEqual(self.store.table_rows(AGGREGATE), [])
        self.assertEqual(self.connection.info.transaction_status, TransactionStatus.INTRANS)

    def test_empty_and_empty_after_history_both_use_actual_empty_proofs(self):
        self.assertEqual(self.prepare(limits=read_limits(max_rows=0)).json_projection(), self.expected())
        row = outbox_row("deleted-history")
        self.store.insert(OUTBOX, row)
        self.connection.execute(sql.SQL("DELETE FROM {} WHERE id=%s")
            .format(self.store.object(OUTBOX)), (row["id"],))
        self.outbox = InventoryTree([], revision=2)
        self.store.assert_tree(self.outbox)
        self.assertEqual(self.prepare(limits=read_limits(max_rows=0)).json_projection(), self.expected())
        self.assertEqual(self.store.table_rows(AGGREGATE), [])

    def test_other_aggregate_leaves_are_preserved_by_real_absence_proof(self):
        others = [other_aggregate("one"), other_aggregate("Unicode-雪")]
        self.seed(self.mixed(), others)
        before = self.store.snapshot()
        result = self.prepare()
        self.assertEqual(result.json_projection(), self.expected())
        self.assertEqual(result.json_projection()["aggregateAbsence"], initialization_fixture.absence(self.aggregate))
        after = aggregate_tree([*others, initial_row(2)], revision=3)
        self.assertEqual(result.json_projection()["afterRoots"][1], after.root.json_projection())
        self.assertEqual(self.store.snapshot(), before)

    def test_unindexed_outbox_row_is_not_hidden_by_leaf_join(self):
        self.seed([outbox_row("indexed")])
        row = outbox_row("unindexed", "claimed")
        self.connection.execute(sql.SQL("ALTER TABLE {} DISABLE TRIGGER component_primary_tree")
            .format(self.store.object(OUTBOX)))
        try:
            self.store.insert(OUTBOX, row)
        finally:
            self.connection.execute(sql.SQL("ALTER TABLE {} ENABLE TRIGGER component_primary_tree")
                .format(self.store.object(OUTBOX)))
        before = self.store.snapshot()
        self.reject()
        self.assertEqual(self.store.snapshot(), before)

    def test_missing_base_row_with_retained_leaf_cannot_be_omitted(self):
        row = outbox_row("retained-leaf")
        self.seed([row])
        self.without_tree_trigger(sql.SQL("DELETE FROM {} WHERE id=%s")
            .format(self.store.object(OUTBOX)), (row["id"],))
        self.reject()

    def test_missing_stored_leaf_rejects_present_base_row(self):
        row = outbox_row("missing-leaf")
        self.seed([row])
        key_digest = sql_digest("serverware.policyAuthorityAuthenticatedKey/v1", OUTBOX.encode(), sql_json({"id": row["id"]}))
        self.assertEqual(self.connection.execute(sql.SQL("DELETE FROM {} WHERE table_name=%s AND key_digest=%s")
            .format(self.store.object(tree_fixture.LEAVES)), (OUTBOX, key_digest)).rowcount, 1)
        self.reject()

    def test_extra_orphan_leaf_metadata_rejects_unchanged_committed_root(self):
        self.seed([outbox_row("normal")])
        orphan = outbox_row("orphan")
        tree = InventoryTree([orphan])
        key_digest = next(iter(tree.leaves))
        row_digest, leaf_digest = tree.leaves[key_digest]
        self.connection.execute(sql.SQL(
            "INSERT INTO {} (table_name,key_digest,key_json,row_digest,leaf_digest,root_revision) "
            "VALUES (%s,%s,%s,%s,%s,1)"
        ).format(self.store.object(tree_fixture.LEAVES)),
            (OUTBOX, key_digest, sql_json({"id": orphan["id"]}).decode("utf-8"), row_digest, leaf_digest))
        self.assertEqual(self.store.stored_root(OUTBOX), self.outbox.root)
        self.reject()

    def test_changed_full_row_without_tree_update_rejects_stale_membership(self):
        row = outbox_row("changed-full-row")
        self.seed([row])
        self.without_tree_trigger(sql.SQL("UPDATE {} SET status=%s,last_error=%s WHERE id=%s")
            .format(self.store.object(OUTBOX)), ("audited", "changed-雪", row["id"]))
        self.reject()

    def test_corrupted_actual_proof_node_is_rejected(self):
        self.seed([outbox_row("node-corruption")])
        self.assertEqual(self.connection.execute(sql.SQL(
            "UPDATE {} SET node_digest=%s WHERE table_name=%s AND depth=1"
        ).format(self.store.object(tree_fixture.NODES)), (WRONG_DIGEST, OUTBOX)).rowcount, 1)
        self.reject()

    def test_crossed_expected_root_revision_digest_and_count_are_rejected(self):
        self.seed(self.mixed(), [other_aggregate("preserved")])
        for name, root in (("expected_outbox_root", self.outbox.root),
                           ("expected_aggregate_root", self.aggregate.root)):
            for changed in (replace(root, root_revision=root.root_revision + 1),
                            replace(root, root_digest=WRONG_DIGEST),
                            replace(root, leaf_count=root.leaf_count + 1)):
                with self.subTest(root=name, changed=changed):
                    self.reject(**{name: changed})

    def test_missing_head_or_wrong_source_manifest_fails_closed(self):
        self.seed([outbox_row("root-contract")])
        for table in (OUTBOX, AGGREGATE):
            for missing in (False, True):
                with self.subTest(table=table, missing=missing), self.store.rollback_variant():
                    if missing:
                        self.connection.execute(sql.SQL("DELETE FROM {} WHERE table_name=%s")
                            .format(self.store.object(tree_fixture.ROOTS)), (table,))
                    else:
                        self.connection.execute(sql.SQL("UPDATE {} SET manifest_digest=%s WHERE table_name=%s")
                            .format(self.store.object(tree_fixture.ROOTS)), (WRONG_DIGEST, table))
                    self.reject()

    def test_existing_global_counter_is_not_returned_as_new_initialization(self):
        self.seed([outbox_row("existing")], [initial_row(1)])
        before = self.store.snapshot()
        self.reject()
        self.assertEqual(self.store.snapshot(), before)

    def test_row_query_total_byte_and_record_budgets_fail_without_partial_success(self):
        self.seed(self.mixed())
        before = self.store.snapshot()
        cases = (
            (read_limits(max_rows=2), "offline expected outbox exceeds its row limit"),
            (read_limits(max_queries=1), "offline preparation exceeded its query limit"),
            (read_limits(max_total_bytes=1), "offline preparation exceeded its total byte limit"),
            (read_limits(max_record_bytes=1), "offline record exceeded its byte limit"),
        )
        for limits, message in cases:
            with self.subTest(limits=limits), self.store.rollback_variant():
                self.reject(message, limits=limits)
            self.assertEqual(self.store.snapshot(), before)

    def test_exact_empty_query_budget_includes_timeout_commands_and_eof_fetch(self):
        # Independent accounting: context + six-table LOCK + root read + two
        # leaf counts + counter-presence read + 65 absence-proof reads + DECLARE
        # + the terminal empty FETCH = 73 commands. Each has one timeout SELECT.
        self.assertEqual(self.prepare(limits=read_limits(max_rows=0, max_queries=146))
                         .json_projection(), self.expected())
        self.reject("offline preparation exceeded its query limit",
                    limits=read_limits(max_rows=0, max_queries=145))
        self.assertEqual(self.connection.info.transaction_status, TransactionStatus.INTRANS)

    def test_oversized_full_row_is_rejected_not_filtered_out(self):
        row = outbox_row("oversized-event")
        row["event_json"] = json.dumps({"payload": "x" * (1024 * 1024 + 1)}, separators=(",", ":"))
        self.seed([row])
        self.reject("offline outbox full row is missing, duplicated or oversized",
                    limits=read_limits(max_record_bytes=1024 * 1024))
        self.assertEqual(self.connection.execute(sql.SQL("SELECT count(*) FROM {}")
            .format(self.store.object(OUTBOX))).fetchone()[0], 1)

    def test_oversized_stored_proof_text_is_rejected_before_admission(self):
        self.seed([outbox_row("oversized-proof")])
        self.assertEqual(self.connection.execute(sql.SQL(
            "UPDATE {} SET node_digest=%s WHERE table_name=%s AND depth=1"
        ).format(self.store.object(tree_fixture.NODES)), ("x" * 72, OUTBOX)).rowcount, 1)
        failure = self.reject("offline snapshot preparation failed admission")
        self.assertIsInstance(failure.__cause__, radix.RadixProofError)
        self.assertEqual(str(failure.__cause__), "authenticated child digest is not bounded database text")

    def test_actual_stream_component_preserves_oversized_identity_as_rejection(self):
        # This is the actual stream component, not a full preparation: the
        # deliberately tiny identity cap is smaller than a normal absence
        # proof. It avoids depending on giant TEXT primary-key compression.
        self.seed([outbox_row("x" * 128)])
        with self.connection.cursor(row_factory=dict_row) as control, \
                self.connection.cursor(row_factory=dict_row) as raw:
            budget = adapter._Budget(read_limits(max_record_bytes=64), control)
            cursor = adapter._ReadCursor(raw, budget)
            adapter._locked_roots(cursor, self.store.schema, (self.outbox.root, self.aggregate.root))
            records = adapter._outbox_records(self.connection, cursor, budget,
                self.outbox.root, self.store.schema)
            try:
                with self.assertRaises(adapter.AuditInitializationPostgresError) as raised:
                    next(records)
                self.assertEqual(str(raised.exception), "offline outbox identity is oversized or malformed")
            finally:
                records.close()
        self.assertEqual(self.store.stored_root(OUTBOX), self.outbox.root)

    def test_adapter_leaves_transaction_and_savepoint_owned_by_caller(self):
        self.seed(self.mixed())
        before = self.store.snapshot()
        transaction_id = self.connection.execute("SELECT pg_catalog.txid_current()::text").fetchone()[0]
        with self.store.rollback_variant():
            result = self.prepare()
            self.assertEqual(result.json_projection(), self.expected())
            self.assertEqual(self.connection.execute("SELECT pg_catalog.txid_current()::text").fetchone()[0], transaction_id)
            # A caller mutation after calculation remains rollback-able; the
            # adapter did not commit, consume a receipt or insert its result.
            self.store.insert(OUTBOX, outbox_row("caller-only"))
            self.assertEqual(len(self.store.table_rows(OUTBOX)), 4)
        self.assertEqual(self.store.snapshot(), before)
        self.assertEqual(self.store.table_rows(AGGREGATE), [])

    def test_actual_nonserializable_readonly_and_idle_sessions_are_rejected(self):
        for mode in ("idle", "read-committed", "read-only"):
            with self.subTest(mode=mode):
                connection = psycopg.connect(**CONNECTION_PARAMETERS, autocommit=False)
                try:
                    if mode == "read-committed":
                        connection.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                    elif mode == "read-only":
                        connection.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY")
                    with self.assertRaises(adapter.AuditInitializationPostgresError) as raised:
                        adapter.prepare_audit_capacity_initialization_from_postgres(
                            connection, expected_outbox_root=self.outbox.root,
                            expected_aggregate_root=self.aggregate.root, initialized_at_epoch_ns=TIME_NS,
                            limits=read_limits(), namespace=self.store.schema)
                    self.assertEqual(str(raised.exception),
                        "offline preparation requires an active caller-owned transaction" if mode == "idle"
                        else "offline preparation requires a SERIALIZABLE read-write UTF8 session")
                    if mode == "idle":
                        self.assertEqual(connection.info.transaction_status, TransactionStatus.IDLE)
                finally:
                    connection.rollback()
                    connection.close()


class AuditInitializationPostgresSourceTests(unittest.TestCase):
    def test_actual_adapter_owns_no_transaction_or_dml_and_closes_stream(self):
        """Supplemental source inspection, not SQL/concurrency execution."""
        path = ROOT / "serverware/authority_audit_initialization_postgres.py"
        self.assertLessEqual(path.stat().st_size, 64 * 1024)
        parsed = ast.parse(path.read_text(encoding="utf-8"))
        methods = {node.name: node for node in parsed.body if isinstance(node, ast.FunctionDef)}
        all_calls = [node for node in ast.walk(parsed) if isinstance(node, ast.Call)]
        self.assertFalse(any(isinstance(node.func, ast.Attribute)
            and node.func.attr in {"commit", "rollback", "transaction", "executemany"} for node in all_calls))
        for node in ast.walk(parsed):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                self.assertNotIn(node.value.lstrip().split(" ", 1)[0].upper(),
                    {"INSERT", "UPDATE", "DELETE", "TRUNCATE", "BEGIN", "COMMIT", "ROLLBACK"})
        prepare = methods["prepare_audit_capacity_initialization_from_postgres"]
        closers = [node for node in ast.walk(prepare) if isinstance(node, ast.Try)
            and any(isinstance(item, ast.Expr) and isinstance(item.value, ast.Call)
                and ast.unparse(item.value.func) == "records.close" for item in node.finalbody)]
        self.assertEqual(len(closers), 1)
        self.assertTrue(any(isinstance(node, ast.Call)
            and ast.unparse(node.func) == "initialization.prepare_audit_capacity_initialization"
            for node in ast.walk(closers[0])))
        stream = methods["_outbox_records"]
        cursors = [node for node in ast.walk(stream) if isinstance(node, ast.Call)
                   and ast.unparse(node.func) == "connection.cursor"]
        self.assertEqual(len(cursors), 1)
        keywords = {item.arg: item.value for item in cursors[0].keywords}
        self.assertIs(keywords["withhold"].value, False)
        self.assertIs(keywords["scrollable"].value, False)
        self.assertTrue(any(isinstance(node, ast.Assign)
            and any(ast.unparse(target) == "raw_scan.itersize" for target in node.targets)
            and isinstance(node.value, ast.Constant) and node.value.value == 1 for node in ast.walk(stream)))
        self.assertTrue(any(isinstance(node, ast.Call) and ast.unparse(node.func) == "scan.fetchmany"
            and len(node.args) == 1 and isinstance(node.args[0], ast.Constant) and node.args[0].value == 1
            for node in ast.walk(stream)))
        self.assertTrue(any(isinstance(node, ast.Call)
            and ast.unparse(node.func) == "radix.derive_multiproofs"
            for node in ast.walk(methods["_proof"])))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--postgres-dsn", required=True)
    arguments, test_arguments = parser.parse_known_args()
    CONNECTION_PARAMETERS = local_connection_parameters(arguments.postgres_dsn)
    unittest.main(argv=[sys.argv[0], *test_arguments])
