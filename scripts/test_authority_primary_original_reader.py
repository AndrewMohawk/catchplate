#!/usr/bin/env python3
"""UNRUN synthetic SQL/real radix controls; no live database or admission.

The recording cursor returns independent tree rows, never a proof result. All
production SQL reads and actual primary replay execute in the component when
authorized to run; no native transaction/TLS/current-root claim is made here.
"""
from __future__ import annotations

import copy
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catchplate import authority_primary_original_reader as source
from catchplate.authority_query_read_work import _ValidationWork, QueryReadValidationLimits
from test_authority_radix_mutation import IndependentTree
from test_authority_radix_proof import sql_json, sql_digest


class Trace:
    def __init__(self, operation):
        self.operation, self.records = operation, []

    def read(self, table, key):
        self.records.append((table, copy.deepcopy(key)))


class Cursor:
    """Only exact row/leaf/child-vector replies from independently built trees."""

    def __init__(self, trees):
        self.trees, self.leaves, self.calls, self.pending = trees, {}, [], None
        self.transform = lambda sql, rows: rows
        for table, tree in trees.items():
            for row in tree.rows.values():
                selected = tree.selected(tree.key(row))
                proof = tree.proof(selected)
                key = sql_digest("catchplate.policyAuthorityAuthenticatedKey/v1",
                    table.encode("ascii"), sql_json(selected["key"]))
                self.leaves[(table, key)] = dict(key_json=sql_json(selected["key"]).decode("utf-8"),
                    row_digest=proof["rowDigest"], leaf_digest=proof["leafDigest"],
                    root_revision=tree.root.root_revision)

    def execute(self, sql, parameters):
        if self.pending is not None:
            raise AssertionError("synthetic result was not consumed")
        self.calls.append((sql, parameters))
        match = re.search(r"FROM catchplate_metadata\.([a-z_]+) AS target WHERE ", sql)
        if match:
            tree = self.trees[match.group(1)]
            key = dict(zip(sorted(tree.columns), parameters[:-1]))
            selected = tree.selected(key)
            rows = [{"row_value": selected["row"]}] if selected["present"] else []
        elif "FROM catchplate_metadata.policy_authority_authenticated_leaves " in sql:
            item = self.leaves.get((parameters[0], parameters[1]))
            rows = [] if item is None else [copy.deepcopy(item)]
        elif "FROM catchplate_metadata.policy_authority_authenticated_tree_nodes " in sql:
            tree, depth = self.trees[parameters[0]], parameters[1]
            rows = [dict(path_prefix=path, node_digest=tree.nodes[(depth, path)],
                root_revision=tree.root.root_revision) for path in parameters[2:-1] if (depth, path) in tree.nodes]
        else:
            raise AssertionError("unexpected synthetic primary query")
        self.pending = self.transform(sql, rows)
        return self

    def fetchmany(self, maximum):
        if self.pending is None:
            raise AssertionError("synthetic result missing")
        rows, self.pending = self.pending, None
        return rows[:maximum]


def query(operation, identity="one", *, absent=False):
    return source.core.BoundedQuery(
        query_id=source.core.query_program_id(operation, "challenge", "webauthn_challenges"),
        table="webauthn_challenges", predicates=(source.core.QueryPredicate("id", "eq", identity),),
        order_by=(source.core.QueryOrder("id"),), maximum_rows=1,
        absent_key={"id": identity}, require_absence=absent)


def json_nodes(value):
    """Independent tiny structure-count oracle, including every object key."""
    if type(value) is dict:
        return 1 + sum(json_nodes(key) + json_nodes(child) for key, child in value.items())
    if type(value) in (list, tuple):
        return 1 + sum(json_nodes(child) for child in value)
    return 1


class PrimaryOriginalReaderControls(unittest.TestCase):
    def setup(self, operation="jit.assertion.issue", *, rows=None, limits=None):
        tree = IndependentTree([{"id": "one", "value": "synthetic"}] if rows is None else rows,
            table="webauthn_challenges")
        cursor, trace = Cursor({tree.table: tree}), Trace(operation)
        work = _ValidationWork(QueryReadValidationLimits())
        collector = source.reader._ReadAcquisitionBudget(cursor, trace, work=work,
            limits=limits or source.reader._ReadAcquisitionLimits())
        manifest = tuple(item for item in source.contracts.source_query_manifest() if item["operation"] == operation)
        return cursor, trace, work, collector, manifest, tree

    def read(self, context, requested):
        cursor, trace, work, collector, manifest, tree = context
        return source.acquire_exact_primary(cursor, operation=trace.operation, query=requested,
            manifest=manifest, primary_root=tree.root, trace=trace, work=work, acquisition=collector)

    def proof(self, context, selected, *, root=None, work=None):
        cursor, trace, original_work, collector, _, tree = context
        return source.acquire_primary_proof(cursor, operation=trace.operation, selected_row=selected,
            primary_root=tree.root if root is None else root, trace=trace,
            work=original_work if work is None else work, acquisition=collector)

    def test_proof_only_present_and_absent_use_65_real_reads_each(self):
        for operation in sorted(source.OPERATIONS):
            context = self.setup(operation)
            cursor, trace, work, collector, _, tree = context
            with collector.read_phase(cursor, trace, work):
                for identity in ("one", "missing"):
                    selected = tree.selected({"id": identity})
                    self.assertEqual(self.proof(context, selected), tree.proof(selected))
                    self.assertTrue(collector._read_phase_active)
            self.assertEqual(collector.sql_reads, 130)
            self.assertEqual(len(cursor.calls), len(trace.records))
            self.assertFalse(any(" AS target WHERE " in sql for sql, _ in cursor.calls))
            self.assertGreater(collector.parameter_bytes, 0)
            self.assertGreater(collector.transport_bytes, 0)

    def test_proof_only_selected_envelope_ceiling_does_not_widen_row_reader(self):
        base = self.setup(rows=[{"id": "one", "value": ""}])[-1].selected({"id": "one"})
        amount = source.authority.MAX_PLAN_SELECTED_BYTES - len(source.core.canonical_bytes((base,)))
        rows = [{"id": "one", "value": "x" * amount}]
        context = self.setup(rows=rows)
        cursor, trace, work, collector, _, tree = context
        selected = tree.selected({"id": "one"})
        self.assertEqual(len(source.core.canonical_bytes((selected,))), source.authority.MAX_PLAN_SELECTED_BYTES)
        with collector.read_phase(cursor, trace, work):
            proof = self.proof(context, selected)
        self.assertEqual(proof, tree.proof(selected))
        self.assertEqual(collector.sql_reads, 65)
        self.assertLess(collector.transport_bytes, source.reader.MAX_PRIMARY_ROW_BYTES)
        self.assertGreater(work.input_bytes, source.authority.MAX_PLAN_SELECTED_BYTES)
        self.assertLess(work.input_bytes, 64 * 1024 * 1024)

        generic = self.setup(rows=rows)
        cursor, trace, work, collector, _, _ = generic
        with self.assertRaises(ValueError):
            with collector.read_phase(cursor, trace, work):
                self.read(generic, query(trace.operation))
        self.assertEqual(collector.sql_reads, 1)
        self.assertTrue(collector.failed)

        oversized = self.setup(rows=[{"id": "one", "value": "x" * (amount + 1)}])
        cursor, trace, work, collector, _, tree = oversized
        with self.assertRaises(ValueError):
            with collector.read_phase(cursor, trace, work):
                self.proof(oversized, tree.selected({"id": "one"}))
        self.assertEqual(cursor.calls, [])
        self.assertTrue(collector.failed)

    def test_membership_hidden_reservation_uses_actual_original_sizes_and_engine_metrics(self):
        for identity in ("one", "missing"):
            context = self.setup(rows=[{"id": "one", "value": "SQL UTF-8 and canonical \\ \u2603"}])
            tree = context[-1]
            selected = tree.selected({"id": identity})
            proof = tree.proof(selected)
            contract = next(item for item in source.contracts.primary_table_contracts("jit.assertion.issue")
                if item.table == tree.table)
            work = _ValidationWork(QueryReadValidationLimits())
            original_limits = work.limits
            work.charge(hashes=2, input_bytes=31, json_nodes=7)
            actual = source._membership(selected, proof, tree.root, contract, work)
            selected_bytes = len(source.core.canonical_bytes(selected))
            proof_bytes = len(source.core.canonical_bytes(proof))
            self.assertEqual(actual.selected_rows, (selected,))
            self.assertEqual(actual.before_proofs, (proof,))
            self.assertIsNot(actual.selected_rows[0], selected)
            self.assertEqual(work.input_bytes, 31 + 7 * selected_bytes + 8 * proof_bytes
                + 2 * 1024 * 1024 + actual.result.metrics.input_bytes)
            self.assertEqual(work.json_nodes, 7 + 3 * (json_nodes(selected) + json_nodes(proof))
                + 16384 + actual.result.metrics.json_nodes)
            self.assertEqual(work.hash_work, 2 + actual.result.metrics.hash_work)
            self.assertIs(work.limits, original_limits)

    def test_hidden_reservation_refuses_before_engine_when_original_work_is_exhausted(self):
        context = self.setup()
        tree = context[-1]
        selected = tree.selected({"id": "one"})
        proof = tree.proof(selected)
        contract = next(item for item in source.contracts.primary_table_contracts("jit.assertion.issue")
            if item.table == tree.table)
        for limits in (QueryReadValidationLimits(max_input_bytes=1024 * 1024),
                QueryReadValidationLimits(max_json_nodes=16384)):
            work = _ValidationWork(limits)
            original_limits = work.limits
            work.charge(input_bytes=17, json_nodes=1)
            # A failure-only spy proves the reservation precedes the genuine
            # engine; no membership or proof-success result is fabricated.
            with patch.object(source.primary, "evaluate_primary_radix_memberships",
                    wraps=source.primary.evaluate_primary_radix_memberships) as engine:
                with self.assertRaises(ValueError):
                    source._membership(selected, proof, tree.root, contract, work)
                engine.assert_not_called()
            self.assertIs(work.limits, original_limits)
            self.assertGreater(work.input_bytes, 17)
            self.assertGreater(work.json_nodes, 1)

    def test_proof_only_owns_selection_and_root_before_native_callbacks(self):
        context = self.setup()
        cursor, trace, work, collector, _, tree = context
        selected = tree.selected({"id": "one"})
        root = source.primary.PrimaryRoot(tree.root.table, tree.root.root_revision,
            tree.root.root_digest, tree.root.leaf_count)
        expected = tree.proof(selected)
        def change(sql, rows):
            selected["row"]["value"] = "caller alias changed"
            selected["key"]["id"] = "caller key changed"
            object.__setattr__(root, "root_digest", "sha256:" + "f" * 64)
            return rows
        cursor.transform = change
        with collector.read_phase(cursor, trace, work):
            self.assertEqual(self.proof(context, selected, root=root), expected)
        self.assertEqual(collector.sql_reads, 65)

    def test_proof_only_closed_wrapper_key_and_root_refusals_precede_sql(self):
        for fault in ("extra", "selector", "present", "null", "key", "key-digest", "row-key", "root"):
            context = self.setup()
            cursor, trace, work, collector, _, tree = context
            selected, root = tree.selected({"id": "one"}), tree.root
            if fault == "extra":
                selected["verdict"] = True
            elif fault == "selector":
                selected["contractSelector"] = "caller selector"
            elif fault == "present":
                selected["present"] = 1
            elif fault == "null":
                selected["row"] = None
            elif fault == "key":
                selected["key"]["id"] = True
            elif fault == "key-digest":
                selected["keyDigest"] = "sha256:" + "f" * 64
            elif fault == "row-key":
                selected["row"]["id"] = "different"
            else:
                root = source.primary.PrimaryRoot("approval_requests", tree.root.root_revision,
                    tree.root.root_digest, tree.root.leaf_count)
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                with collector.read_phase(cursor, trace, work):
                    self.proof(context, selected, root=root)
            self.assertEqual(cursor.calls, [])
            self.assertTrue(collector.failed)

    def test_proof_only_uses_original_phase_work_and_sticky_physical_limits(self):
        for fault in ("phase", "work", "sql", "parameters", "transport", "proof"):
            limits = {"sql": source.reader._ReadAcquisitionLimits(max_sql_reads=64),
                "parameters": source.reader._ReadAcquisitionLimits(max_parameter_bytes=32),
                "transport": source.reader._ReadAcquisitionLimits(max_transport_bytes=32)}.get(fault)
            context = self.setup(limits=limits)
            cursor, trace, work, collector, _, tree = context
            selected = tree.selected({"id": "one"})
            if fault == "proof":
                cursor.transform = lambda sql, rows: [] if "authenticated_tree_nodes " in sql else rows
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                if fault == "phase":
                    self.proof(context, selected)
                else:
                    with collector.read_phase(cursor, trace, work):
                        self.proof(context, selected,
                            work=_ValidationWork(QueryReadValidationLimits()) if fault == "work" else work)
            if fault in ("phase", "work"):
                self.assertEqual(cursor.calls, [])
            self.assertTrue(collector.failed)
            calls = len(cursor.calls)
            with self.assertRaises(ValueError):
                self.proof(context, selected)
            self.assertEqual(len(cursor.calls), calls)

    def test_present_and_absent_match_independent_proofs_on_one_original_phase(self):
        for operation in sorted(source.OPERATIONS):
            context = self.setup(operation)
            cursor, trace, work, collector, _manifest, tree = context
            with collector.read_phase(cursor, trace, work):
                for identity in ("one", "missing"):
                    selected, proof = self.read(context, query(operation, identity))
                    self.assertEqual(selected, tree.selected({"id": identity}))
                    self.assertEqual(proof, tree.proof(selected))
                    self.assertTrue(collector._read_phase_active)
            self.assertEqual(collector.sql_reads, 132)
            self.assertEqual(len(cursor.calls), len(trace.records))
            self.assertGreater(collector.parameter_bytes, 0)
            self.assertGreater(collector.transport_bytes, 0)

    def test_row_leaf_node_tampering_and_false_absence_are_refused(self):
        for target in ("row", "leaf", "node", "row-omitted", "duplicate", "absence-required"):
            context = self.setup()
            cursor, trace, work, collector, _, _ = context
            def change(sql, rows):
                if " AS target WHERE " in sql:
                    if target == "row":
                        rows[0]["row_value"]["value"] = "changed"
                    if target == "row-omitted":
                        return []
                    if target == "duplicate":
                        return rows + copy.deepcopy(rows)
                if target == "leaf" and "authenticated_leaves " in sql:
                    return []
                if target == "node" and "authenticated_tree_nodes " in sql and rows:
                    rows[0]["node_digest"] = "sha256:" + "f" * 64
                return rows
            cursor.transform = change
            with self.subTest(target=target), self.assertRaises(ValueError):
                with collector.read_phase(cursor, trace, work):
                    self.read(context, query(trace.operation, absent=target == "absence-required"))
            self.assertTrue(collector.failed)

    def test_physical_exhaustion_is_actual_sticky_and_never_replenished(self):
        for limits in (source.reader._ReadAcquisitionLimits(max_sql_reads=65),
                source.reader._ReadAcquisitionLimits(max_parameter_bytes=32),
                source.reader._ReadAcquisitionLimits(max_transport_bytes=32)):
            context = self.setup(limits=limits)
            cursor, trace, work, collector, _, _ = context
            with self.assertRaises(ValueError):
                with collector.read_phase(cursor, trace, work):
                    self.read(context, query(trace.operation))
            calls = len(cursor.calls)
            with self.assertRaises(ValueError):
                self.read(context, query(trace.operation))
            self.assertEqual(len(cursor.calls), calls)
            self.assertTrue(collector.failed)

    def test_missing_outer_phase_wrong_work_and_non_pk_query_fail_before_sql(self):
        for change in ("phase", "work", "range"):
            context = self.setup()
            cursor, trace, work, collector, manifest, tree = context
            if change == "phase":
                with self.assertRaises(ValueError):
                    self.read(context, query(trace.operation))
            else:
                requested = query(trace.operation)
                if change == "range":
                    requested = source.core.BoundedQuery(query_id=requested.query_id,
                        table=requested.table, predicates=(source.core.QueryPredicate("id", "gt", "one"),),
                        order_by=requested.order_by, maximum_rows=1)
                with self.assertRaises(ValueError):
                    with collector.read_phase(cursor, trace, work):
                        source.acquire_exact_primary(cursor, operation=trace.operation, query=requested,
                            manifest=manifest, primary_root=tree.root, trace=trace,
                            work=_ValidationWork(QueryReadValidationLimits()) if change == "work" else work,
                            acquisition=collector)
            self.assertEqual(cursor.calls, [])


if __name__ == "__main__":
    unittest.main()
