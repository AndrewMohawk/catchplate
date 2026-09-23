#!/usr/bin/env python3
"""Actual batched proof producer against independent stored-tree fixtures.

These deterministic cursor responders are not PostgreSQL, predicate-completeness
proofs, root-currentness authority, or a launched planner. Expected hashes come
from the existing independent SQL/wire tree builders, never production digest
helpers. The real singleton producer is an additional byte-parity control.
Trace composition uses the actual pure budget, without importing the blocked
planner/database graph or replacing its registry. Source checks are supplemental.
"""
from __future__ import annotations

import ast
import copy
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_audit_trace as audit_trace
from serverware import authority_contract
from serverware import authority_radix_proof as radix
import test_authority_radix_proof as oracle
import test_authority_radix_mutation as generic_oracle


LEAVES = "policy_authority_authenticated_leaves"
NODES = "policy_authority_authenticated_tree_nodes"
AGGREGATE = "policy_authority_bounded_aggregate_states"
PROFILE = "serverware.policyAuthorityRadixReadBatch/v1"
PARTITION = oracle.wire_digest("serverware.metadataAuditOutboxCapacityPartition/v1", b"global")
COUNTER_ID = "metadata-audit-outbox-global-capacity-v1:" + PARTITION
COUNTER_KEY = {"aggregate_id": COUNTER_ID}


def tree_root(tree):
    return copy.deepcopy(tree.root if type(tree.root) is dict else tree.root.json_projection())


def expected_proofs(trees, selected):
    by_table = {tree.table: tree for tree in trees}
    return tuple(sorted((by_table[row["table"]].proof(row) for row in selected),
                        key=lambda proof: (proof["table"], proof["keyDigest"])))


def parent_identities(selected):
    parents = set()
    for row in selected:
        path = oracle.sql_digest("serverware.policyAuthorityAuthenticatedKey/v1",
                                 row["table"].encode("utf-8"), oracle.sql_json(row["key"]))[7:]
        parents.update((row["table"], depth + 1, path[:depth]) for depth in range(64))
    return tuple(sorted(parents))


class StoredTreeCursor:
    """Closed SQL responder, including hostile transport controls when explicit."""

    def __init__(self, *trees, namespace="serverware_metadata", change=None, reverse=False):
        self.namespace = namespace
        self.change = change
        self.reverse = reverse
        self.calls = []
        self.fetch_sizes = []
        self.leaves = {}
        self.nodes = {}
        self.result = []
        self.kind = None
        self.limit = None
        for tree in trees:
            root = tree_root(tree)
            if type(tree.root) is dict:
                for digest, leaf in tree.leaves.items():
                    self.leaves[(tree.table, digest)] = copy.deepcopy(leaf)
            else:
                for row in tree.rows.values():
                    key = tree.key(row)
                    digest = oracle.sql_digest("serverware.policyAuthorityAuthenticatedKey/v1",
                                               tree.table.encode("utf-8"), oracle.sql_json(key))
                    row_digest, leaf_digest = tree.leaves[digest]
                    self.leaves[(tree.table, digest)] = {
                        "key_json": oracle.sql_json(key).decode("utf-8"),
                        "row_digest": row_digest, "leaf_digest": leaf_digest,
                        "root_revision": root["rootRevision"],
                    }
            for (depth, path), digest in tree.nodes.items():
                self.nodes[(tree.table, depth, path)] = {
                    "table_name": tree.table, "depth": depth, "path_prefix": path,
                    "node_digest": digest, "root_revision": root["rootRevision"],
                }

    def execute(self, statement, parameters):
        self.calls.append((statement, copy.deepcopy(parameters)))
        if f'FROM "{self.namespace}".{LEAVES} ' in statement:
            self.kind = "leaf"
            if len(parameters) != 2:
                raise AssertionError("fixture leaf query escaped exact existing SQL")
            leaf = self.leaves.get(tuple(parameters))
            self.result = [] if leaf is None else [copy.deepcopy(leaf)]
            self.limit = 1
        elif f'FROM "{self.namespace}".{NODES} ' in statement:
            if "JOIN (VALUES " in statement:
                self.kind = "batch"
                if (len(parameters) - 1) % 3:
                    raise AssertionError("fixture batch parameters are not exact triples")
                children = [tuple(parameters[index:index + 3])
                            for index in range(0, len(parameters) - 1, 3)]
                self.limit = parameters[-1]
                if not 1 <= len(children) <= 256 or len(set(children)) != len(children):
                    raise AssertionError("fixture child inventory is duplicated or unbounded")
                if self.limit != len(children) + 1:
                    raise AssertionError("fixture batch does not retain an overflow sentinel")
                if "LIMIT %s" not in statement:
                    raise AssertionError("fixture batch SQL has no explicit limit")
                self.result = [copy.deepcopy(self.nodes[child]) for child in children if child in self.nodes]
            else:
                self.kind = "singleton"
                table, depth, paths, self.limit = parameters
                if len(paths) != 16 or len(set(paths)) != 16 or self.limit != 17:
                    raise AssertionError("fixture singleton child inventory changed")
                self.result = [{name: value for name, value in self.nodes[(table, depth, path)].items()
                                if name not in {"table_name", "depth"}}
                               for path in paths if (table, depth, path) in self.nodes]
        else:
            raise AssertionError("unexpected SQL, namespace, or mutation")
        if self.reverse:
            self.result.reverse()
        if self.change is not None:
            self.result = self.change(self.kind, copy.deepcopy(self.result), parameters)
        return self

    def fetchone(self):
        if self.kind != "leaf" or len(self.result) > 1:
            raise AssertionError("fixture singleton leaf is ambiguous")
        return copy.deepcopy(self.result[0]) if self.result else None

    def fetchmany(self, size):
        self.fetch_sizes.append(size)
        if self.kind not in {"batch", "singleton"} or size != self.limit or not 1 <= size <= 257:
            raise AssertionError("fixture child transport bound changed")
        # Return the whole configured result, deliberately without clipping it.
        # Hostile-driver controls must exercise the producer's own length guard.
        return copy.deepcopy(self.result)


class RecordingTrace:
    def __init__(self, *, operation=None):
        self.reads = []
        self.budget = None if operation is None else audit_trace.AuditTraceBudget(operation)

    def read(self, table, key):
        owned = copy.deepcopy(key)
        self.reads.append((table, owned))
        if self.budget is not None:
            self.budget.append({"ordinal": len(self.reads) - 1, "access": "read", "table": table, "key": owned})


class AuthorityRadixBatchTests(unittest.TestCase):
    def setUp(self):
        self.tree = oracle.TreeFixture(rows={
            "record-a": {"id": "record-a", "sign_count": 2, "label": "é雪"},
            "record-b": {"id": "record-b", "sign_count": 4, "label": None},
            "opaque": {"id": "opaque", "sign_count": 7},
        })
        self.rows = (self.tree.selected("record-b"), self.tree.selected("record-a"),
                     self.tree.selected("missing", absent=True))

    def derive(self, *, trees=None, rows=None, cursor=None, trace=None, roots=None, **kwargs):
        trees = (self.tree,) if trees is None else trees
        rows = self.rows if rows is None else rows
        cursor = StoredTreeCursor(*trees) if cursor is None else cursor
        trace = RecordingTrace() if trace is None else trace
        roots = tuple(tree_root(tree) for tree in trees) if roots is None else roots
        result = radix.derive_multiproofs_batched(
            cursor, selected_rows=rows, roots=roots, trace=trace, **kwargs)
        return result, cursor, trace

    def test_full_v3_bytes_match_independent_tree_and_real_singleton_producer(self):
        original = copy.deepcopy((self.rows, self.tree.root, self.tree.leaves, self.tree.nodes))
        result, cursor, trace = self.derive()
        expected = expected_proofs((self.tree,), self.rows)
        singleton = radix.derive_multiproofs(
            StoredTreeCursor(self.tree), selected_rows=self.rows, roots=(self.tree.root,), trace=RecordingTrace())
        self.assertEqual(result, expected)
        self.assertEqual(oracle.wire_json(result), oracle.wire_json(singleton))
        self.assertEqual(len(cursor.calls), len(trace.reads))
        for selected in self.rows:
            proof = next(item for item in result if item["keyDigest"] == selected["keyDigest"])
            self.assertEqual(radix.reconstruct_multiproof_root(proof, selected=selected), self.tree.root["rootDigest"])
            self.assertEqual(len(proof["siblings"]), 64)
            self.assertTrue(all(len(level["childDigests"]) == 16 for level in proof["siblings"]))
        self.assertEqual((self.rows, self.tree.root, self.tree.leaves, self.tree.nodes), original)

    def test_mixed_relations_and_composite_keys_do_not_alias_equal_prefixes(self):
        second = generic_oracle.IndependentTree([
            {"owner": "same", "id": "record-a", "value": "β"},
            {"owner": "different", "id": "record-a", "value": 9},
        ], table="second_relation", columns=("owner", "id"), revision=29)
        selected = self.rows + (second.selected({"owner": "same", "id": "record-a"}),
                                second.selected({"owner": "absent", "id": "record-a"}))
        result, cursor, trace = self.derive(trees=(self.tree, second), rows=selected)
        self.assertEqual(result, expected_proofs((self.tree, second), selected))
        self.assertEqual(len(cursor.calls), len(trace.reads))
        parents = [parent for table, key in trace.reads if table == NODES
                   for parent in radix.validate_batch_trace_key(key)]
        self.assertIn((self.tree.table, 1, ""), parents)
        self.assertIn((second.table, 1, ""), parents)
        self.assertEqual(len(parents), len(set(parents)))

    def test_selected_root_and_server_order_do_not_change_output_or_child_schedule(self):
        other = generic_oracle.IndependentTree([{"id": "one", "value": 8}], table="another", revision=7)
        selected = self.rows + (other.selected({"id": "one"}),)
        roots = (tree_root(self.tree), tree_root(other))
        first, cursor, trace = self.derive(trees=(self.tree, other), rows=selected, roots=roots)
        second, reverse_cursor, reverse_trace = self.derive(
            trees=(other, self.tree), rows=tuple(reversed(selected)), roots=tuple(reversed(roots)),
            cursor=StoredTreeCursor(other, self.tree, reverse=True))
        self.assertEqual(first, second)
        # Exact leaf reads retain the caller's selected ordering. Only the
        # deduplicated child schedule and final output are canonicalized.
        self.assertEqual(cursor.calls[len(selected):], reverse_cursor.calls[len(selected):])
        self.assertEqual(trace.reads[len(selected):], reverse_trace.reads[len(selected):])

    def test_parent_deduplication_and_sixteen_parent_chunks_are_exact(self):
        result, cursor, trace = self.derive()
        parents = parent_identities(self.rows)
        expected_chunks = [parents[index:index + 16] for index in range(0, len(parents), 16)]
        batches = [key for table, key in trace.reads if table == NODES]
        self.assertEqual([radix.validate_batch_trace_key(key) for key in batches], expected_chunks)
        self.assertLess(len(parents), 64 * len(self.rows))
        self.assertEqual(len(cursor.calls), len(self.rows) + (len(parents) + 15) // 16)
        self.assertEqual(result, expected_proofs((self.tree,), self.rows))
        for (statement, parameters), chunk in zip(cursor.calls[len(self.rows):], expected_chunks):
            children = [(table, depth, prefix + format(index, "x"))
                        for table, depth, prefix in chunk for index in range(16)]
            self.assertEqual(tuple(parameters[:-1]), tuple(value for child in children for value in child))
            self.assertEqual(parameters[-1], len(children) + 1)
            self.assertLessEqual(parameters[-1], 257)

    def test_one_hundred_ninety_two_and_two_hundred_fifty_six_rows_fit_real_read_bounds(self):
        for count, maximum in ((192, 960), (256, 1280)):
            with self.subTest(count=count):
                tree = oracle.TreeFixture(rows={f"row-{index:03}": {"id": f"row-{index:03}", "value": index}
                                               for index in range(count)})
                selected = tuple(tree.selected(identifier) for identifier in tree.rows)
                result, cursor, trace = self.derive(trees=(tree,), rows=selected)
                self.assertEqual(result, expected_proofs((tree,), selected))
                self.assertEqual(len(result), count)
                self.assertLessEqual(len(cursor.calls), maximum)
                self.assertEqual(len(trace.reads), len(cursor.calls))
                parents = parent_identities(selected)
                self.assertEqual(len(cursor.calls), count + (len(parents) + 15) // 16)
                self.assertTrue(all(size <= 257 for size in cursor.fetch_sizes))

    def test_empty_selected_inventory_has_no_cursor_or_trace_reads(self):
        result, cursor, trace = self.derive(rows=())
        self.assertEqual(result, ())
        self.assertEqual(cursor.calls, [])
        self.assertEqual(trace.reads, [])

    def test_cached_child_vectors_are_not_mutably_shared_between_output_proofs(self):
        result, _, _ = self.derive()
        first, second = result[:2]
        self.assertEqual(first["siblings"][0]["childDigests"], second["siblings"][0]["childDigests"])
        self.assertIsNot(first["siblings"][0]["childDigests"], second["siblings"][0]["childDigests"])
        original = copy.deepcopy(second)
        first["siblings"][0]["childDigests"][0] = "sha256:" + "f" * 64
        self.assertEqual(second, original)
        again, _, _ = self.derive()
        self.assertEqual(again, expected_proofs((self.tree,), self.rows))

    def test_namespace_and_inventory_bounds_reject_before_any_io(self):
        class StringSubclass(str):
            pass

        cases = [
            {"namespace": value} for value in (None, False, "", "M", "m.x", "m\0", "m\n",
                                                "a" * 64, StringSubclass("metadata"))
        ] + [
            {"rows": list(self.rows)}, {"rows": self.rows[:1] * 257},
            {"roots": [self.tree.root]}, {"roots": (self.tree.root,) * 257},
            {"rows": self.rows[:1] * 2}, {"roots": (self.tree.root, self.tree.root)},
            {"roots": ({**self.tree.root, "rootRevision": True},)},
            {"roots": ({**self.tree.root, "rootRevision": -1},)},
            {"roots": ({**self.tree.root, "rootRevision": 1 << 63},)},
            {"roots": ({**self.tree.root, "rootDigest": "sha256:" + "g" * 64},)},
            {"rows": ({**self.rows[0], "table": "bad.table"},)},
            {"rows": ({**self.rows[0], "key": []},)},
            {"rows": ({**self.rows[0], "keyDigest": None},)},
        ]
        for change in cases:
            cursor, trace = StoredTreeCursor(self.tree), RecordingTrace()
            with self.subTest(change=tuple(change)), self.assertRaises(radix.RadixProofError):
                self.derive(cursor=cursor, trace=trace, **change)
            self.assertEqual(cursor.calls, [])
            self.assertEqual(trace.reads, [])

    def test_missing_root_bad_presence_and_changed_business_address_deny_before_leaf_read(self):
        for change in (
            {"roots": ()},
            {"rows": ({**self.rows[0], "present": 1},)},
            {"rows": ({**self.rows[0], "row": None},)},
            {"rows": ({**self.rows[0], "keyDigest": "sha256:" + "f" * 64},)},
        ):
            cursor, trace = StoredTreeCursor(self.tree), RecordingTrace()
            with self.subTest(change=tuple(change)), self.assertRaises(radix.RadixProofError):
                self.derive(cursor=cursor, trace=trace, **change)
            self.assertEqual(cursor.calls, [])
            self.assertEqual(trace.reads, [])

    def test_actual_nonmembership_and_retained_invalid_leaf_never_conflate(self):
        missing = self.tree.selected("not-retained", absent=True)
        actual, _, _ = self.derive(rows=(missing,))
        self.assertEqual(actual, (self.tree.proof(missing),))
        retained = self.tree.selected("record-a", absent=True)
        with self.assertRaisesRegex(radix.RadixProofError, "nonmembership"):
            self.derive(rows=(retained,))
        def invalid_leaf(kind, rows, _parameters):
            if kind == "leaf" and rows:
                rows[0]["key_json"] = None
            return rows
        with self.assertRaisesRegex(radix.RadixProofError, "key JSON is not bounded"):
            self.derive(rows=(retained,), cursor=StoredTreeCursor(self.tree, change=invalid_leaf))

    def test_leaf_projection_sentinels_wrong_rows_and_revision_controls(self):
        changes = (
            ("key_json", None), ("key_json", "{"), ("key_json", "{}"),
            ("row_digest", None), ("row_digest", "sha256:" + "g" * 64),
            ("row_digest", "sha256:" + "f" * 64),
            ("leaf_digest", None), ("leaf_digest", "sha256:" + "f" * 64),
            ("root_revision", True), ("root_revision", 0), ("root_revision", 4),
        )
        for field, value in changes:
            def changed(kind, rows, _parameters):
                if kind == "leaf" and rows:
                    rows[0][field] = value
                return rows
            cursor = StoredTreeCursor(self.tree, change=changed)
            with self.subTest(field=field, value=value), self.assertRaises(radix.RadixProofError):
                self.derive(rows=(self.rows[0],), cursor=cursor)
            self.assertEqual(len(cursor.calls), 1)
        selected = copy.deepcopy(self.rows[0])
        selected["row"]["sign_count"] += 1
        with self.assertRaisesRegex(radix.RadixProofError, "authenticated leaf"):
            self.derive(rows=(selected,))

    def test_child_table_depth_prefix_digest_and_revision_are_exact(self):
        changes = (
            ("table_name", None), ("table_name", "other_relation"), ("table_name", "x" * 129),
            ("depth", True), ("depth", "1"), ("depth", 0), ("depth", 65),
            ("path_prefix", None), ("path_prefix", ""), ("path_prefix", "x" * 65),
            ("node_digest", None), ("node_digest", "sha256:" + "g" * 64),
            ("node_digest", "sha256:" + "0" * 65),
            ("root_revision", True), ("root_revision", 0), ("root_revision", 4),
        )
        for field, value in changes:
            def changed(kind, rows, _parameters):
                if kind == "batch" and rows:
                    rows[0][field] = value
                return rows
            cursor = StoredTreeCursor(self.tree, change=changed)
            with self.subTest(field=field, value=value), self.assertRaises(radix.RadixProofError):
                self.derive(cursor=cursor)
            self.assertEqual(len(cursor.calls), len(self.rows) + 1)

    def test_child_revision_is_checked_against_its_own_relation_root(self):
        other = generic_oracle.IndependentTree([{"id": "one", "value": 1}], table="z_other", revision=100)
        selected = (self.rows[0], other.selected({"id": "one"}))
        def changed(kind, rows, _parameters):
            if kind == "batch":
                for row in rows:
                    if row["table_name"] == self.tree.table:
                        row["root_revision"] = 4  # Below other root100, above this root3.
            return rows
        with self.assertRaisesRegex(radix.RadixProofError, "identity or revision"):
            self.derive(trees=(self.tree, other), rows=selected,
                        cursor=StoredTreeCursor(self.tree, other, change=changed))

    def test_duplicate_extra_unclosed_and_overflow_driver_rows_reject(self):
        def duplicate(_kind, rows, _parameters):
            return rows + [copy.deepcopy(rows[0])]
        def unclosed(_kind, rows, _parameters):
            rows[0]["unexpected"] = True
            return rows
        def wrong_record(_kind, rows, _parameters):
            return [None] + rows[1:]
        def tuple_result(_kind, rows, _parameters):
            return tuple(rows)
        def overflow(_kind, rows, parameters):
            return [copy.deepcopy(rows[0]) for _ in range(parameters[-1])]
        def over_transport(_kind, rows, parameters):
            return [copy.deepcopy(rows[0]) for _ in range(parameters[-1] + 1)]
        for mutation in (duplicate, unclosed, wrong_record, tuple_result, overflow, over_transport):
            def changed(kind, rows, parameters):
                return mutation(kind, rows, parameters) if kind == "batch" else rows
            cursor = StoredTreeCursor(self.tree, change=changed)
            with self.subTest(change=mutation.__name__), self.assertRaises(radix.RadixProofError):
                self.derive(cursor=cursor)
            self.assertEqual(len(cursor.calls), len(self.rows) + 1)

    def test_well_formed_missing_or_changed_child_is_rejected_by_real_root_reconstruction(self):
        # A producer does not authenticate sibling truth; its actual consumer
        # must reconstruct the supplied root. No false claim of producer-only
        # completeness is made for omitted or validly spelled changed nodes.
        for omit in (True, False):
            def changed(kind, rows, _parameters):
                if kind == "batch" and rows:
                    if omit:
                        return rows[1:]
                    rows[0]["node_digest"] = "sha256:" + "f" * 64
                return rows
            result, _, _ = self.derive(rows=(self.rows[0],), cursor=StoredTreeCursor(self.tree, change=changed))
            with self.subTest(omit=omit), self.assertRaises(radix.RadixProofError):
                radix.reconstruct_multiproof_root(result[0], selected=self.rows[0])

    def test_child_sql_has_closed_values_bounds_and_case_sentinels_not_filtering(self):
        _, cursor, _ = self.derive()
        for statement, parameters in cursor.calls[len(self.rows):]:
            children = (len(parameters) - 1) // 3
            self.assertEqual(statement.count("(%s::text,%s::integer,%s::text)"), children)
            self.assertEqual(parameters[-1], children + 1)
            self.assertEqual(statement.count("LIMIT %s"), 1)
            self.assertNotIn("WHERE", statement)
            self.assertIn("CASE WHEN pg_catalog.octet_length(node.table_name) BETWEEN 1 AND 128", statement)
            self.assertIn("CASE WHEN pg_catalog.octet_length(node.path_prefix) BETWEEN 1 AND 64", statement)
            self.assertIn("CASE WHEN pg_catalog.octet_length(node.node_digest) = 71", statement)
            self.assertEqual(statement.count("ELSE NULL END AS"), 3)
            self.assertIn("node.table_name = requested.table_name", statement)
            self.assertIn("node.depth = requested.depth", statement)
            self.assertIn("node.path_prefix = requested.path_prefix", statement)

    def test_explicit_valid_namespaces_keep_full_proof_bytes_and_bounded_reads(self):
        for namespace in ("serverware_metadata", "batch_fixture_a9", "a" * 63, "select"):
            with self.subTest(namespace=namespace):
                result, cursor, trace = self.derive(
                    rows=(self.rows[0],), namespace=namespace,
                    cursor=StoredTreeCursor(self.tree, namespace=namespace))
                self.assertEqual(result, expected_proofs((self.tree,), (self.rows[0],)))
                self.assertEqual(len(cursor.calls), 5)
                self.assertEqual(len(trace.reads), 5)
                self.assertTrue(all(f'FROM "{namespace}".' in statement for statement, _ in cursor.calls))

    def test_sixteen_parent_trace_profile_and_seventeenth_parent_rejection(self):
        self.assertEqual((radix.BATCH_TRACE_PROFILE, radix.MAX_BATCH_PARENTS, radix.MAX_BATCH_CHILDREN),
                         (PROFILE, 16, 256))
        parents = [{"tableName": f"table_{index:02}", "depth": 1, "pathPrefix": ""}
                   for index in range(16)]
        key = {"profile": PROFILE, "parents": parents}
        original = copy.deepcopy(key)
        self.assertEqual(radix.validate_batch_trace_key(key),
                         tuple((f"table_{index:02}", 1, "") for index in range(16)))
        budget = audit_trace.AuditTraceBudget("webauthn.counter.cas")
        budget.append({"access": "read", "table": NODES, "key": key})
        budget.close(())
        self.assertEqual((budget.business_entries, budget.framework_entries), (1, 0))
        self.assertEqual(key, original)
        excessive = {"profile": PROFILE, "parents": parents + [
            {"tableName": "table_16", "depth": 1, "pathPrefix": ""}]}
        with self.assertRaises(radix.RadixProofError):
            radix.validate_batch_trace_key(excessive)
        with self.assertRaisesRegex(audit_trace.AuditTraceError, "batch trace is not closed"):
            budget.append({"access": "read", "table": NODES, "key": excessive})

    def test_unknown_duplicate_unsorted_or_malformed_batch_trace_is_not_business_credit(self):
        valid = {"profile": PROFILE, "parents": [
            {"tableName": "first", "depth": 1, "pathPrefix": ""},
            {"tableName": "first", "depth": 2, "pathPrefix": "a"},
        ]}
        changes = [
            {**valid, "profile": "serverware.policyAuthorityRadixReadBatch/v999"},
            {**valid, "extra": 1}, {**valid, "parents": []},
            {**valid, "parents": tuple(valid["parents"])},
            {**valid, "parents": list(reversed(valid["parents"]))},
            {**valid, "parents": valid["parents"][:1] * 2},
        ]
        for field, value in (("tableName", None), ("tableName", "bad.table"),
                             ("depth", True), ("depth", 0), ("depth", 65),
                             ("pathPrefix", None), ("pathPrefix", "a"), ("extra", 1)):
            changes.append({"profile": PROFILE, "parents": [{**valid["parents"][0], field: value}]})
        for key in changes:
            budget = audit_trace.AuditTraceBudget("webauthn.counter.cas")
            with self.subTest(key=key), self.assertRaises(radix.RadixProofError):
                radix.validate_batch_trace_key(key)
            with self.assertRaisesRegex(audit_trace.AuditTraceError, "batch trace is not closed"):
                budget.append({"access": "read", "table": NODES, "key": key})
            self.assertEqual((budget.business_entries, budget.framework_entries), (0, 0))

    def test_batches_use_one_business_entry_per_physical_read_without_lifting_4096(self):
        result, cursor, trace = self.derive(trace=RecordingTrace(operation="webauthn.counter.cas"))
        trace.budget.close(())
        self.assertEqual(result, expected_proofs((self.tree,), self.rows))
        self.assertEqual(trace.budget.business_entries, len(cursor.calls))
        self.assertEqual(trace.budget.framework_entries, 0)
        key = {"profile": PROFILE, "parents": [{"tableName": "first", "depth": 1, "pathPrefix": ""}]}
        entry = {"access": "read", "table": NODES, "key": key}
        for _ in range(4096 - len(cursor.calls)):
            trace.budget.append(entry)
        self.assertEqual(trace.budget.business_entries, 4096)
        trace.budget.close(())
        with self.assertRaisesRegex(audit_trace.AuditTraceError, "trace bound was exceeded"):
            trace.budget.append(entry)

    def test_actual_counter_singleton_block_and_other_aggregate_batch_compose(self):
        # These rows support actual primary proofs and trace identities only;
        # no counter-population/state admission is claimed by this test.
        aggregate = generic_oracle.IndependentTree([
            {"aggregate_id": COUNTER_ID, "component_value": 0},
            {"aggregate_id": "other-business-aggregate", "component_value": 1},
        ], table=AGGREGATE, columns=("aggregate_id",), revision=9)
        counter = aggregate.selected(COUNTER_KEY)
        business = self.rows + (aggregate.selected({"aggregate_id": "other-business-aggregate"}),)
        roots = (tree_root(self.tree), tree_root(aggregate))
        cursor = StoredTreeCursor(self.tree, aggregate)
        trace = RecordingTrace(operation="webauthn.credential.revoke")
        trace.read("policy_authority_authenticated_table_roots", {"tableName": AGGREGATE})
        trace.read(AGGREGATE, {"globalAuditCapacityQuery": COUNTER_ID})
        trace.read(AGGREGATE, COUNTER_KEY)
        counter_proofs = radix.derive_multiproofs(
            cursor, selected_rows=(counter,), roots=roots, trace=trace)
        self.assertEqual(len(cursor.calls), 65)
        business_proofs = radix.derive_multiproofs_batched(
            cursor, selected_rows=business, roots=roots, trace=trace)
        trace.budget.close(())
        self.assertEqual(counter_proofs, (aggregate.proof(counter),))
        self.assertEqual(business_proofs, expected_proofs((self.tree, aggregate), business))
        self.assertEqual(trace.budget.framework_entries, 68)  # New root, scan, row,65proof reads.
        self.assertEqual(trace.budget.business_entries, len(cursor.calls) - 65)
        digest = oracle.sql_digest("serverware.policyAuthorityAuthenticatedKey/v1",
                                   AGGREGATE.encode("ascii"), oracle.sql_json(COUNTER_KEY))
        expected_counter_trace = [(LEAVES, {"tableName": AGGREGATE, "keyDigest": digest})] + [
            (NODES, {"tableName": AGGREGATE, "depth": depth + 1, "pathPrefix": digest[7:7 + depth]})
            for depth in range(64)]
        self.assertEqual(trace.reads[3:68], expected_counter_trace)
        batches = [key for table, key in trace.reads[68:] if table == NODES]
        self.assertTrue(any((AGGREGATE, 1, "") in radix.validate_batch_trace_key(key) for key in batches))

    def test_even_valid_batch_cannot_interrupt_reserved_counter_proof_block(self):
        digest = oracle.sql_digest("serverware.policyAuthorityAuthenticatedKey/v1",
                                   AGGREGATE.encode("ascii"), oracle.sql_json(COUNTER_KEY))
        budget = audit_trace.AuditTraceBudget("webauthn.credential.revoke")
        budget.append({"access": "read", "table": LEAVES,
                       "key": {"tableName": AGGREGATE, "keyDigest": digest}})
        key = {"profile": PROFILE, "parents": [{"tableName": AGGREGATE, "depth": 1, "pathPrefix": ""}]}
        with self.assertRaisesRegex(audit_trace.AuditTraceError, "not contiguous"):
            budget.append({"access": "read", "table": NODES, "key": key})

    def test_planner_source_splits_exact_counter_and_keeps_global_singleton_before_business_batch(self):
        # Inspect source only: no extracted code execution, fake registry, or
        # import of the presently blocked planner is used.
        tree = ast.parse((ROOT / "serverware/authority_planner.py").read_text())
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                     and node.name == "_derive_multiproofs"]
        self.assertEqual(len(functions), 1)
        function = functions[0]
        calls = [node for node in ast.walk(function) if isinstance(node, ast.Call)]
        singleton = [node for node in calls if ast.unparse(node.func) == "authority_radix_proof.derive_multiproofs"]
        batched = [node for node in calls if ast.unparse(node.func) == "authority_radix_proof.derive_multiproofs_batched"]
        self.assertEqual((len(singleton), len(batched)), (1, 1))
        self.assertLess(singleton[0].lineno, batched[0].lineno)
        for call, selected in ((singleton[0], "counter_rows"), (batched[0], "business_rows")):
            self.assertEqual([ast.unparse(arg) for arg in call.args], ["cursor"])
            self.assertEqual({item.arg: ast.unparse(item.value) for item in call.keywords},
                             {"selected_rows": selected, "roots": "roots", "trace": "trace"})
        assignments = {node.targets[0].id: node.value for node in ast.walk(function)
                       if isinstance(node, ast.Assign) and len(node.targets) == 1
                       and isinstance(node.targets[0], ast.Name)}
        exact = ("item.get('table') == authority_audit_capacity.AGGREGATE_TABLE and "
                 "item.get('key') == {'aggregate_id': authority_audit_capacity.AGGREGATE_ID}")
        for name, expression in (("counter_rows", exact), ("business_rows", "not (" + exact + ")")):
            value = assignments[name]
            self.assertIsInstance(value, ast.Call)
            self.assertEqual(ast.unparse(value.func), "tuple")
            self.assertIsInstance(value.args[0], ast.GeneratorExp)
            self.assertEqual(len(value.args[0].generators[0].ifs), 1)
            self.assertEqual(ast.dump(value.args[0].generators[0].ifs[0]),
                             ast.dump(ast.parse(expression, mode="eval").body))
        conditions = [ast.dump(node.test) for node in ast.walk(function) if isinstance(node, ast.If)]
        self.assertIn(ast.dump(ast.parse(
            "len(counter_rows) != int(participates) or len(business_rows) > authority_contract.MAX_QUERY_PROOFS",
            mode="eval").body), conditions)
        self.assertEqual(ast.unparse(assignments["participates"]),
                         "authority_contract.operation_spec(trace.operation)['globalAuditCapacity']")
        returned = [node.value for node in ast.walk(function) if isinstance(node, ast.Return)]
        self.assertEqual(len(returned), 1)
        self.assertEqual(ast.dump(returned[0]), ast.dump(ast.parse(
            "tuple(sorted((*counter_proofs, *business_proofs), key=lambda entry: (entry['table'], entry['keyDigest'])))",
            mode="eval").body))


if __name__ == "__main__":
    unittest.main()
