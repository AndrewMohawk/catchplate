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

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import authority_primary_original_reader as source
from serverware.authority_query_read_work import _ValidationWork, QueryReadValidationLimits
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
                key = sql_digest("serverware.policyAuthorityAuthenticatedKey/v1",
                    table.encode("ascii"), sql_json(selected["key"]))
                self.leaves[(table, key)] = dict(key_json=sql_json(selected["key"]).decode("utf-8"),
                    row_digest=proof["rowDigest"], leaf_digest=proof["leafDigest"],
                    root_revision=tree.root.root_revision)

    def execute(self, sql, parameters):
        if self.pending is not None:
            raise AssertionError("synthetic result was not consumed")
        self.calls.append((sql, parameters))
        match = re.search(r"FROM serverware_metadata\.([a-z_]+) AS target WHERE ", sql)
        if match:
            tree = self.trees[match.group(1)]
            key = dict(zip(sorted(tree.columns), parameters[:-1]))
            selected = tree.selected(key)
            rows = [{"row_value": selected["row"]}] if selected["present"] else []
        elif "FROM serverware_metadata.policy_authority_authenticated_leaves " in sql:
            item = self.leaves.get((parameters[0], parameters[1]))
            rows = [] if item is None else [copy.deepcopy(item)]
        elif "FROM serverware_metadata.policy_authority_authenticated_tree_nodes " in sql:
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
