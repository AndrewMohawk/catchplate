#!/usr/bin/env python3
"""Real staged proof acquisition over independent in-memory stored trees.

The bounded cursor is a deterministic SQL responder, not PostgreSQL. Production
batched proof acquisition and the genuine membership engine verify independent
tree fixtures; no registry or successful verifier is replaced. These controls
do not establish SQL predicate completeness, current roots, a launched planner,
or an activated WebAuthn kernel. Supplemental source order is covered separately.
"""
from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError, fields
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_audit_capacity as capacity
from serverware import authority_audit_trace as audit_trace
from serverware import authority_contract
from serverware import authority_primary_contract as primary
from serverware import authority_query_reads as reads
from serverware import authority_query_staging as staging
from serverware import authority_query_read_work as accounting
from serverware import authority_radix_mutation as mutation
from serverware import authority_radix_proof as radix
from serverware import authority_root_transition as transition
from serverware import authority_transition_core as core
import test_authority_global_audit_capacity as capacity_oracle
import test_authority_radix_batch as batch_oracle
import test_authority_radix_proof as wire_oracle
import test_authority_root_transition as root_oracle
import test_authority_query_reads as query_oracle
import test_authority_query_reads_measured as query_work_oracle


OPERATION = "webauthn.credential.revoke"
CREDENTIALS = "webauthn_credentials"
CHALLENGES = "webauthn_challenges"


def definition(name, *, table=CREDENTIALS, predicates=(), maximum_rows=1, absent_key=None, operation=OPERATION):
    return core.BoundedQuery(
        query_id=f"serverware.policyAuthorityQuery/{operation}/{name}/{table}/v1",
        table=table, predicates=predicates, order_by=(), maximum_rows=maximum_rows,
        absent_key=absent_key)


def exact_query(name, selected):
    key = copy.deepcopy(selected["key"])
    return definition(name, table=selected["table"],
        predicates=tuple(core.QueryPredicate(column, "eq", value) for column, value in key.items()),
        absent_key=key)


def reference_query(name, *references, absent=False, table=CHALLENGES, operation=OPERATION):
    if absent:
        if len(references) != 1:
            raise AssertionError("exact absence fixture requires one source reference")
        return definition(name, table=table, operation=operation,
            predicates=(core.QueryPredicate("id", "eq", references[0]),), absent_key={"id": references[0]})
    return definition(name, table=table, operation=operation,
        predicates=tuple(core.QueryPredicate("user_id", "eq", reference) for reference in references))


def reference(selected, column="user_id"):
    return core.SelectedRowFieldReference(selected["table"], copy.deepcopy(selected["key"]), column)


def capture(query, selected, *, operation=OPERATION):
    resolved = reads.resolve_query(operation, query, prior_reads=(), selected_rows=())
    return reads.capture_query_read(operation, query, resolved_query=resolved,
        ordered_selected_rows=selected, returned_row_count=sum(row["present"] is True for row in selected))


def graph_nodes(value):
    if type(value) is dict:
        return 1 + len(value) + sum(graph_nodes(child) for child in value.values())
    if type(value) is list:
        return 1 + sum(graph_nodes(child) for child in value)
    return 1


def primary_document(inputs, selected, proofs):
    contracts = primary.primary_table_contracts(inputs["operation"])
    return {
        "contracts": [{"table": item.table, "keyColumns": list(item.key_columns),
                       "writeAccess": item.write_access, "rootClass": item.root_class} for item in contracts],
        "businessRoots": inputs["business_before_roots"],
        "authorizationRoots": inputs["authorization_before_roots"],
        "selected": list(selected), "proofs": list(proofs), "mutations": [],
    }


def expected_stage_query_work(query, records, selected):
    """Independent QueryRead-only schedule, excluding proof/stamp work.

    Staging snapshots once, then reference enumeration snapshots again. Each
    prior record has two real reconstruction passes plus budget/association
    scans: six header frames and four address frames. Selected address and
    referenced-key work are repeated even when primary proofs are cached.
    """
    result = query_work_oracle.ExpectedWork()
    values = tuple(predicate.value for predicate in query.predicates)
    if query.absent_key is not None:
        values += tuple(query.absent_key.values())
    references = tuple(value for value in values if type(value) is core.SelectedRowFieldReference)
    document = query_oracle.query_document(query)
    for _ in range(2):
        for value in values:
            if type(value) is core.SelectedRowFieldReference:
                result.copy(value.key)
                result.encoding(value.key, copies=1)
            else:
                result.copy(value)
        for name in (() if query.absent_key is None else query.absent_key):
            result.copy(name)
        for value in references:
            result.encoding(value.key)  # genuine contract projection's dict copy
        result.encoding(document)
        result.bytes += len(query_oracle.canonical(document))
    for record in records:
        addresses = sum(query_work_oracle.address_bytes(address) for address in record.addresses)
        header = query_work_oracle.record_bytes(record) - addresses
        result.bytes += 6 * header + 4 * addresses
    for row in selected:
        keys = (row["key"], {"id": row["row"]["id"]}) if row["present"] else (row["key"],)
        for key in keys:
            result.copy(key)
            result.encoding(key)
        result.hashes += 1
        result.bytes += (8 + len(row["table"]) + 8 + len(query_oracle.canonical(row["key"]))
                         + 8 + len(row["keyDigest"]) + 9)
    for value in references:
        result.copy(value.key)
        result.encoding(value.key)
    return result


class StageTrace(batch_oracle.RecordingTrace):
    def __init__(self, operation=OPERATION):
        super().__init__(operation=operation)
        self.operation = operation


class AuthorityQueryStagingTests(unittest.TestCase):
    def setUp(self):
        rows = {
            CREDENTIALS: [
                {"id": "credential-a-雪", "credential_id": "public-a", "user_id": "alice",
                 "sign_count": 1, "metadata": {"flags": [True, None]}},
                {"id": "credential-b", "credential_id": "public-b", "user_id": "bob", "sign_count": 2},
                {"id": "unselected", "credential_id": "public-other", "user_id": "other", "sign_count": 3},
            ],
            CHALLENGES: [{"id": "challenge-a", "user_id": "alice", "scope_key": "scope-雪"}],
            capacity.AGGREGATE_TABLE: [capacity_oracle.counter_row()],
        }
        self.inputs, self.trees = root_oracle.input_fixture(OPERATION, rows)
        self.first = self.trees[CREDENTIALS].selected({"id": "credential-a-雪"})
        self.second = self.trees[CREDENTIALS].selected({"id": "credential-b"})
        self.challenge = self.trees[CHALLENGES].selected({"id": "challenge-a"})
        self.counter = self.trees[capacity.AGGREGATE_TABLE].selected({"aggregate_id": capacity.AGGREGATE_ID})
        self.first_record = capture(exact_query("first", self.first), (self.first,))
        self.second_record = capture(exact_query("second", self.second), (self.second,))
        self.challenge_record = capture(exact_query("challenge", self.challenge), (self.challenge,))
        self.cursor = batch_oracle.StoredTreeCursor(*self.trees.values())
        self.trace = StageTrace()

    def collector(self, **changes):
        arguments = {name: self.inputs[name] for name in
            ("operation", "business_before_roots", "authorization_before_roots")}
        arguments.update(changes)
        return staging.StagedQueryProofs(**arguments)

    def authenticate(self, collector, query=None, *, selected=None, records=None, cursor=None, trace=None):
        return collector.authenticate_references(
            self.cursor if cursor is None else cursor,
            query=reference_query("dependent", reference(self.first)) if query is None else query,
            query_reads=(self.first_record,) if records is None else records,
            selected_rows=(self.first,) if selected is None else selected,
            trace=self.trace if trace is None else trace)

    def proof_calls(self, cursor=None):
        cursor = self.cursor if cursor is None else cursor
        return len(cursor.calls)

    def test_real_batched_membership_owns_source_before_actual_deferred_resolution(self):
        collector = self.collector()
        query = reference_query("dependent", reference(self.first))
        owned = self.authenticate(collector, query)
        self.assertEqual(owned, (self.first,))
        self.assertIsNot(owned[0], self.first)
        self.assertIsNot(owned[0]["row"], self.first["row"])
        self.assertIsNot(owned[0]["row"]["metadata"], self.first["row"]["metadata"])
        self.assertEqual(self.proof_calls(), 5)  # One leaf plus four real 16-parent batches.
        self.assertEqual(len(self.trace.reads), self.proof_calls())
        resolved = reads.resolve_query(OPERATION, query,
            prior_reads=(self.first_record,), selected_rows=owned)
        self.assertEqual(resolved.predicates[0].value, "alice")
        metric = collector.metrics
        self.assertEqual((metric.stages, metric.selected_rows, metric.hash_work,
                          metric.proof_vectors, metric.proof_child_slots), (1, 1, 202, 64, 1024))
        expected = self.trees[CREDENTIALS].proof(self.first)
        document = primary_document(self.inputs, owned, (expected,))
        self.assertEqual(metric.input_bytes, len(wire_oracle.wire_json(document)))
        self.assertEqual(metric.json_nodes, graph_nodes(document))
        row_bytes, proof_bytes = len(wire_oracle.wire_json(owned[0])), len(wire_oracle.wire_json(expected))
        row_nodes, proof_nodes = graph_nodes(owned[0]), graph_nodes(expected)
        self.assertEqual((metric.stamp_bytes, metric.stamp_nodes),
                         (2 * row_bytes + proof_bytes, 2 * row_nodes + proof_nodes))
        self.assertEqual(collector.unproved_rows(owned), ())
        self.assertEqual(collector.merge_proofs(selected_rows=owned, remaining_proofs=()), (expected,))
        self.assertEqual((collector.metrics.stamp_bytes, collector.metrics.stamp_nodes),
                         (6 * row_bytes + 2 * proof_bytes, 6 * row_nodes + 2 * proof_nodes))

    def test_predicate_and_absent_key_references_share_one_genuine_source_proof(self):
        collector = self.collector()
        query = reference_query("dependent-absence", reference(self.first, "credential_id"), absent=True)
        owned = self.authenticate(collector, query)
        resolved = reads.resolve_query(OPERATION, query,
            prior_reads=(self.first_record,), selected_rows=owned)
        self.assertEqual(resolved.absent_key, {"id": "public-a"})
        self.assertEqual(resolved.predicates, (core.QueryPredicate("id", "eq", "public-a"),))
        self.assertEqual(self.proof_calls(), 5)
        self.assertEqual(collector.metrics.selected_rows, 1)

    def test_equal_overlapping_sources_reuse_verified_cache_without_duplicate_reads(self):
        collector = self.collector()
        first_owned = self.authenticate(collector)
        metrics = collector.metrics
        owned = self.authenticate(collector,
            reference_query("later-column", reference(self.first, "credential_id")),
            selected=copy.deepcopy(first_owned))
        self.assertEqual(owned, first_owned)
        self.assertEqual(self.proof_calls(), 5)
        self.assertEqual((collector.metrics.stages, collector.metrics.selected_rows,
                          collector.metrics.hash_work, collector.metrics.input_bytes),
                         (metrics.stages, metrics.selected_rows, metrics.hash_work, metrics.input_bytes))
        resolved = reads.resolve_query(OPERATION,
            reference_query("later-column", reference(self.first, "credential_id")),
            prior_reads=(self.first_record,), selected_rows=owned)
        self.assertEqual(resolved.predicates[0].value, "public-a")

    def test_mixed_tables_and_duplicate_references_have_independent_full_proof_oracles(self):
        collector = self.collector()
        selected = (self.second, self.challenge, self.first)
        records = (self.first_record, self.second_record, self.challenge_record)
        query = reference_query("mixed", reference(self.second), reference(self.challenge),
                                reference(self.first), reference(self.first, "credential_id"))
        owned = self.authenticate(collector, query, selected=selected, records=records)
        self.assertEqual({row["keyDigest"] for row in owned}, {row["keyDigest"] for row in selected})
        expected = batch_oracle.expected_proofs(tuple(self.trees.values()), selected)
        self.assertEqual(collector.metrics.selected_rows, 3)
        self.assertEqual(collector.metrics.hash_work, 66 + 66 + 3 * 70)
        self.assertEqual(self.proof_calls(), 3 + (len(batch_oracle.parent_identities(selected)) + 15) // 16)
        self.assertEqual(collector.unproved_rows(owned), ())
        self.assertEqual(collector.merge_proofs(selected_rows=owned, remaining_proofs=()), expected)

    def test_no_reference_query_performs_no_proof_io_or_membership_work(self):
        collector = self.collector()
        query = definition("independent", maximum_rows=2)
        owned = self.authenticate(collector, query, selected=(self.first, self.second),
                                  records=(self.first_record, self.second_record))
        self.assertEqual(owned, (self.first, self.second))
        self.assertEqual(self.proof_calls(), 0)
        self.assertEqual(self.trace.reads, [])
        self.assertEqual((collector.metrics.stages, collector.metrics.selected_rows,
                          collector.metrics.hash_work, collector.metrics.input_bytes), (0, 0, 66, 0))
        pending = collector.unproved_rows(owned)
        self.assertEqual(pending, owned)
        actual = radix.derive_multiproofs_batched(self.cursor, selected_rows=pending,
            roots=tuple(self.inputs["business_before_roots"] + self.inputs["authorization_before_roots"]),
            trace=self.trace)
        self.assertEqual(collector.merge_proofs(selected_rows=owned, remaining_proofs=actual),
                         batch_oracle.expected_proofs(tuple(self.trees.values()), owned))

    def test_missing_forward_absent_and_missing_field_sources_fail_before_proof_reads(self):
        missing = self.trees[CREDENTIALS].selected({"id": "missing"})
        missing_record = capture(exact_query("missing", missing), (missing,))
        cases = (
            (reference(self.first), (), (self.first,)),
            (reference(self.first), (self.first_record,), ()),
            (reference(self.second), (self.first_record,), (self.first, self.second)),
            (reference(self.first, "missing_field"), (self.first_record,), (self.first,)),
            (reference(missing), (missing_record,), (missing,)),
        )
        for source, records, selected in cases:
            collector = self.collector()
            cursor = batch_oracle.StoredTreeCursor(*self.trees.values())
            with self.subTest(source=source), self.assertRaises(staging.QueryStagingError) as raised:
                self.authenticate(collector, reference_query("bad-reference", source),
                    records=records, selected=selected, cursor=cursor)
            self.assertIsInstance(raised.exception.__cause__, reads.QueryReadError)
            self.assertEqual(cursor.calls, [])
            with self.assertRaisesRegex(staging.QueryStagingError, "not ready"):
                collector.unproved_rows(())

    def test_changed_full_row_and_authentic_leaf_context_fail_before_resolution(self):
        changed = copy.deepcopy(self.first)
        changed["row"]["user_id"] = "attacker-value"
        collector = self.collector()
        with self.assertRaises(staging.QueryStagingError) as raised:
            self.authenticate(collector, selected=(changed,))
        self.assertIsInstance(raised.exception.__cause__, radix.RadixProofError)
        self.assertEqual(self.proof_calls(), 1)
        self.assertEqual(collector.metrics.input_bytes, 0)
        # A failed read reserves its allowance and permanently closes this
        # handle; correcting the caller's row is not an implicit retry.
        self.assertEqual(collector.metrics.hash_work, 202)
        with self.assertRaisesRegex(staging.QueryStagingError, "not ready"):
            self.authenticate(collector, reference_query("retry", reference(self.first)))
        self.assertEqual(self.proof_calls(), 1)

    def test_changed_real_node_digest_reaches_genuine_membership_engine_and_denies(self):
        altered = False
        def change(kind, rows, parameters):
            nonlocal altered
            if kind == "batch" and rows and not altered:
                rows[0]["node_digest"] = "sha256:" + "0" * 64
                altered = True
            return rows
        cursor = batch_oracle.StoredTreeCursor(*self.trees.values(), change=change)
        collector = self.collector()
        actual = staging.evaluate_primary_radix_memberships
        calls = []
        def observe(**arguments):
            calls.append(arguments)
            return actual(**arguments)
        with mock.patch.object(staging, "evaluate_primary_radix_memberships", new=observe):
            with self.assertRaises(staging.QueryStagingError) as raised:
                self.authenticate(collector, cursor=cursor)
        self.assertTrue(altered)
        self.assertEqual(len(calls), 1)
        self.assertIsInstance(raised.exception.__cause__, mutation.PrimaryRadixMutationError)
        self.assertEqual(len(cursor.calls), 5)

    def test_stale_leaf_revision_and_malformed_child_transport_poison_without_cache(self):
        def stale(kind, rows, parameters):
            if kind == "leaf" and rows:
                rows[0]["root_revision"] = self.trees[CREDENTIALS].root.root_revision + 1
            return rows
        def wrong_table(kind, rows, parameters):
            if kind == "batch" and rows:
                rows[0]["table_name"] = "not_the_requested_table"
            return rows
        for change in (stale, wrong_table):
            cursor = batch_oracle.StoredTreeCursor(*self.trees.values(), change=change)
            collector = self.collector()
            with self.subTest(change=change.__name__), self.assertRaises(staging.QueryStagingError) as raised:
                self.authenticate(collector, cursor=cursor)
            self.assertIsInstance(raised.exception.__cause__, radix.RadixProofError)
            observed = len(cursor.calls)
            with self.assertRaises(staging.QueryStagingError):
                collector.unproved_rows((self.first,))
            self.assertEqual(len(cursor.calls), observed)

    def test_original_and_returned_row_alias_mutation_never_supplies_later_parameter(self):
        for target in ("original", "owned", "same-key-boolean-alias"):
            original = copy.deepcopy(self.first)
            collector = self.collector()
            cursor = batch_oracle.StoredTreeCursor(*self.trees.values())
            owned = self.authenticate(collector, selected=(original,), cursor=cursor)
            if target == "original":
                original["row"]["user_id"] = "changed"
                incoming = (original,)
            elif target == "owned":
                owned[0]["row"]["metadata"]["flags"].append("changed")
                incoming = owned
            else:
                changed = copy.deepcopy(owned)
                changed[0]["row"]["sign_count"] = True  # Python 1 == True is not wire equality.
                incoming = changed
            with self.subTest(target=target), self.assertRaisesRegex(staging.QueryStagingError, "verified row changed"):
                self.authenticate(collector, reference_query("later", reference(self.first)),
                    selected=incoming, cursor=cursor)
            self.assertEqual(len(cursor.calls), 5)

    def test_actual_verifier_snapshot_survives_original_alias_change_during_acquisition(self):
        collector = self.collector()
        original = copy.deepcopy(self.first)
        actual = staging.evaluate_primary_radix_memberships
        calls = []
        def observe(**arguments):
            verified = actual(**arguments)
            calls.append(verified)
            original["row"]["user_id"] = "changed-after-real-verification"
            return verified
        with mock.patch.object(staging, "evaluate_primary_radix_memberships", new=observe):
            owned = self.authenticate(collector, selected=(original,))
        self.assertEqual(len(calls), 1)
        self.assertEqual(owned[0]["row"]["user_id"], "alice")
        self.assertIs(owned[0], calls[0].selected_rows[0])
        query = reference_query("later", reference(self.first))
        again = self.authenticate(collector, query, selected=owned)
        resolved = reads.resolve_query(OPERATION, query, prior_reads=(self.first_record,), selected_rows=again)
        self.assertEqual(resolved.predicates[0].value, "alice")
        self.assertEqual(self.proof_calls(), 5)

    def test_actual_cached_proof_alias_tampering_is_rejected_at_final_merge(self):
        collector = self.collector()
        actual = staging.evaluate_primary_radix_memberships
        results = []
        def observe(**arguments):
            verified = actual(**arguments)
            results.append(verified)
            return verified
        with mock.patch.object(staging, "evaluate_primary_radix_memberships", new=observe):
            owned = self.authenticate(collector)
        self.assertEqual(collector.unproved_rows(owned), ())
        # This is the actual verifier result retained by the collector, not a
        # fabricated successful result or replacement cache implementation.
        results[0].before_proofs[0]["rowDigest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(staging.QueryStagingError, "cached proof changed"):
            collector.merge_proofs(selected_rows=owned, remaining_proofs=())
        self.assertEqual(self.proof_calls(), 5)

    def test_roots_are_owned_and_wrong_revision_digest_inventory_or_class_denies(self):
        mutable_roots = copy.deepcopy(self.inputs["business_before_roots"])
        collector = self.collector(business_before_roots=mutable_roots)
        target = next(row for row in mutable_roots if row["table"] == CREDENTIALS)
        target["rootDigest"] = "sha256:" + "0" * 64
        self.authenticate(collector)
        self.assertEqual(collector.metrics.selected_rows, 1)
        for mode in ("missing", "duplicate", "wrong-class", "bool-revision", "bad-digest"):
            business = copy.deepcopy(self.inputs["business_before_roots"])
            authorization = copy.deepcopy(self.inputs["authorization_before_roots"])
            if mode == "missing":
                business.pop()
            elif mode == "duplicate":
                business[1] = copy.deepcopy(business[0])
            elif mode == "wrong-class":
                business, authorization = authorization, business
            elif mode == "bool-revision":
                business[0]["rootRevision"] = True
            else:
                business[0]["rootDigest"] = "not-a-digest"
            with self.subTest(mode=mode), self.assertRaises(staging.QueryStagingError):
                self.collector(business_before_roots=business, authorization_before_roots=authorization)
        stale = copy.deepcopy(self.inputs["business_before_roots"])
        next(row for row in stale if row["table"] == CREDENTIALS)["rootRevision"] = 1
        with self.assertRaises(staging.QueryStagingError) as raised:
            self.authenticate(self.collector(business_before_roots=stale))
        self.assertIsInstance(raised.exception.__cause__, radix.RadixProofError)

    def test_cursor_trace_operation_query_identity_and_phase_are_transaction_local(self):
        for mode in ("cursor", "trace", "operation", "duplicate-query", "missing-row"):
            collector = self.collector()
            cursor = batch_oracle.StoredTreeCursor(*self.trees.values())
            trace = StageTrace()
            owned = self.authenticate(collector, cursor=cursor, trace=trace)
            query = reference_query("later", reference(self.first))
            next_cursor, next_trace, selected = cursor, trace, owned
            if mode == "cursor":
                next_cursor = batch_oracle.StoredTreeCursor(*self.trees.values())
            elif mode == "trace":
                next_trace = StageTrace()
            elif mode == "operation":
                trace.operation = "webauthn.counter.cas"
            elif mode == "duplicate-query":
                query = reference_query("dependent", reference(self.first))
            else:
                selected = ()
            with self.subTest(mode=mode), self.assertRaises(staging.QueryStagingError):
                self.authenticate(collector, query, selected=selected, cursor=next_cursor, trace=next_trace)
            self.assertEqual(len(cursor.calls), 5)
        collector = self.collector()
        with self.assertRaisesRegex(staging.QueryStagingError, "not ready"):
            collector.merge_proofs(selected_rows=(), remaining_proofs=())
        with self.assertRaises(staging.QueryStagingError):
            collector.unproved_rows(())
        collector = self.collector()
        self.assertEqual(collector.unproved_rows(()), ())
        self.assertEqual(collector.merge_proofs(selected_rows=(), remaining_proofs=()), ())
        with self.assertRaisesRegex(staging.QueryStagingError, "not ready"):
            collector.merge_proofs(selected_rows=(), remaining_proofs=())

    def test_global_counter_stays_in_final_singleton_block_and_full_preflight_is_real(self):
        collector = self.collector()
        owned = self.authenticate(collector)
        global_rows = owned + (self.counter,)
        pending = collector.unproved_rows(global_rows)
        self.assertEqual(pending, (self.counter,))
        spec = authority_contract.operation_spec(OPERATION)
        if spec["auditCapacityAddsAggregateRoot"]:
            self.trace.read("policy_authority_authenticated_table_roots", {"tableName": capacity.AGGREGATE_TABLE})
        self.trace.read(capacity.AGGREGATE_TABLE, audit_trace.audit_capacity_scan_key())
        self.trace.read(capacity.AGGREGATE_TABLE, {"aggregate_id": capacity.AGGREGATE_ID})
        before = len(self.trace.reads)
        roots = tuple(self.inputs["business_before_roots"] + self.inputs["authorization_before_roots"])
        counter_proofs = radix.derive_multiproofs(self.cursor, selected_rows=pending, roots=roots, trace=self.trace)
        self.assertEqual(len(self.trace.reads) - before, 65)
        self.assertEqual(self.proof_calls(), 70)
        tail = self.trace.reads[before:]
        self.assertEqual(tail[0][0], batch_oracle.LEAVES)
        self.assertTrue(all(table == batch_oracle.NODES and "profile" not in key for table, key in tail[1:]))
        self.assertEqual([key["depth"] for _table, key in tail[1:]], list(range(1, 65)))
        self.trace.budget.close(())
        self.assertEqual(self.trace.budget.business_entries, 5)
        self.assertEqual(self.trace.budget.framework_entries, 67 + int(spec["auditCapacityAddsAggregateRoot"]))
        merged = collector.merge_proofs(selected_rows=global_rows, remaining_proofs=counter_proofs)
        self.assertEqual(merged, batch_oracle.expected_proofs(tuple(self.trees.values()), global_rows))
        verified = transition.verify_primary_plan_inputs(operation=OPERATION,
            business_before_roots=self.inputs["business_before_roots"],
            authorization_before_roots=self.inputs["authorization_before_roots"],
            selected_rows=global_rows, before_proofs=merged)
        self.assertEqual(verified.selected_rows, global_rows)
        self.assertEqual(verified.result.metrics.hash_work, 206)
        self.assertEqual(collector.metrics.selected_rows, 1)
        self.assertEqual(collector.metrics.hash_work, 202)
        # The source counter cannot be moved into an earlier batched-reference
        # stage, even with its genuine row and an actual observed query record.
        counter_query, = capacity.add_capacity_query(OPERATION, ())
        counter_record = capture(counter_query, (self.counter,))
        cursor = batch_oracle.StoredTreeCursor(*self.trees.values())
        with self.assertRaisesRegex(staging.QueryStagingError, "reserved global counter"):
            self.authenticate(self.collector(), reference_query("counter-source", reference(self.counter, "live_count")),
                selected=(self.counter,), records=(counter_record,), cursor=cursor, trace=StageTrace())
        self.assertEqual(cursor.calls, [])

    def test_completion_rejects_changed_rows_missing_extra_duplicate_and_non_tuple_proofs(self):
        for mode in ("missing", "duplicate", "extra", "list", "reordered", "changed-row"):
            collector = self.collector()
            cursor, trace = batch_oracle.StoredTreeCursor(*self.trees.values()), StageTrace()
            owned = self.authenticate(collector, selected=(self.first, self.second),
                records=(self.first_record, self.second_record), cursor=cursor, trace=trace)
            pending = collector.unproved_rows(owned)
            self.assertEqual(pending, (self.second,))
            proofs = radix.derive_multiproofs_batched(cursor, selected_rows=pending,
                roots=tuple(self.inputs["business_before_roots"] + self.inputs["authorization_before_roots"]),
                trace=trace)
            selected = owned
            if mode == "missing":
                proofs = ()
            elif mode == "duplicate":
                proofs = proofs + proofs
            elif mode == "extra":
                changed = copy.deepcopy(proofs[0])
                changed["keyDigest"] = self.first["keyDigest"]
                proofs = (changed,)
            elif mode == "list":
                proofs = list(proofs)
            elif mode == "reordered":
                selected = tuple(reversed(owned))
            else:
                selected = copy.deepcopy(owned)
                selected[1]["row"]["user_id"] = "different"
            with self.subTest(mode=mode), self.assertRaises(staging.QueryStagingError):
                collector.merge_proofs(selected_rows=selected, remaining_proofs=proofs)
            self.assertEqual(len(cursor.calls), 10)
            with self.assertRaisesRegex(staging.QueryStagingError, "not ready"):
                collector.unproved_rows(owned)

    def test_merge_identity_check_does_not_replace_final_proof_or_capacity_verification(self):
        collector = self.collector()
        owned = self.authenticate(collector, selected=(self.first, self.second, self.counter))
        pending = collector.unproved_rows(owned)
        roots = tuple(self.inputs["business_before_roots"] + self.inputs["authorization_before_roots"])
        counter_rows = tuple(row for row in pending if row["table"] == capacity.AGGREGATE_TABLE)
        business_rows = tuple(row for row in pending if row["table"] != capacity.AGGREGATE_TABLE)
        proofs = radix.derive_multiproofs(self.cursor, selected_rows=counter_rows, roots=roots, trace=self.trace)
        proofs += radix.derive_multiproofs_batched(self.cursor, selected_rows=business_rows, roots=roots, trace=self.trace)
        changed = copy.deepcopy(proofs)
        next(proof for proof in changed if proof["table"] == CREDENTIALS)["proofDigest"] = "sha256:" + "0" * 64
        merged = collector.merge_proofs(selected_rows=owned, remaining_proofs=changed)
        with self.assertRaises(mutation.PrimaryRadixMutationError):
            transition.verify_primary_plan_inputs(operation=OPERATION,
                business_before_roots=self.inputs["business_before_roots"],
                authorization_before_roots=self.inputs["authorization_before_roots"],
                selected_rows=owned, before_proofs=merged)
        # A successful partial stage is also insufficient without the required
        # independently initialized compact counter in the complete selection.
        collector = self.collector()
        owned = self.authenticate(collector)
        self.assertEqual(collector.unproved_rows(owned), ())
        merged = collector.merge_proofs(selected_rows=owned, remaining_proofs=())
        with self.assertRaisesRegex(mutation.PrimaryRadixMutationError, "audit capacity inputs"):
            transition.verify_primary_plan_inputs(operation=OPERATION,
                business_before_roots=self.inputs["business_before_roots"],
                authorization_before_roots=self.inputs["authorization_before_roots"],
                selected_rows=owned, before_proofs=merged)

    def test_cumulative_small_source_row_hash_and_engine_limits_are_not_reset_per_stage(self):
        # RBAC's real five-business-slot profile keeps this boundary tiny. The
        # collector ceiling alone is not a valid complete query-program claim:
        # close_queries separately charges the sum of all declared row bounds.
        operation, table = "rbac.binding.mutate", "rbac_role_bindings"
        self.assertEqual(authority_contract.operation_spec(operation)["maximumBusinessQueryRows"], 5)
        population = [{"subject_id": f"subject-{i}", "user_id": f"user-{i}"} for i in range(6)]
        inputs, trees = root_oracle.input_fixture(operation, {table: population})
        selected = tuple(trees[table].selected({"subject_id": row["subject_id"]}) for row in population)
        inventory = definition("inventory", table=table, maximum_rows=6, operation=operation)
        prior = (capture(inventory, selected, operation=operation),)
        collector = staging.StagedQueryProofs(operation=operation,
            business_before_roots=inputs["business_before_roots"],
            authorization_before_roots=inputs["authorization_before_roots"])
        cursor, trace = batch_oracle.StoredTreeCursor(*trees.values()), StageTrace(operation)
        actual = staging.evaluate_primary_radix_memberships
        limits = []
        def observe(**arguments):
            limits.append(arguments["limits"])
            return actual(**arguments)
        expected_bytes = expected_nodes = 0
        with mock.patch.object(staging, "evaluate_primary_radix_memberships", new=observe):
            for index in range(5):
                source = selected[index]
                expected_proof = trees[table].proof(source)
                document = primary_document(inputs, (source,), (expected_proof,))
                selected = collector.authenticate_references(cursor,
                    query=reference_query(f"step-{index}", reference(source), table=table, operation=operation),
                    query_reads=prior, selected_rows=selected, trace=trace)
                self.assertEqual(limits[-1].max_hashes, 136)
                self.assertEqual(limits[-1].max_selected_rows, 1)
                self.assertEqual(limits[-1].max_input_bytes, 64 * 1024 * 1024 - expected_bytes)
                self.assertEqual(limits[-1].max_json_nodes, 1_000_000 - expected_nodes)
                self.assertEqual(limits[-1].max_proof_vectors, (5 - index) * 64)
                self.assertEqual(limits[-1].max_proof_child_slots, (5 - index) * 1024)
                expected_bytes += len(wire_oracle.wire_json(document))
                expected_nodes += graph_nodes(document)
        self.assertEqual((collector.metrics.stages, collector.metrics.selected_rows, collector.metrics.hash_work),
                         (5, 5, 66 + 5 * 136))
        self.assertEqual((collector.metrics.input_bytes, collector.metrics.json_nodes), (expected_bytes, expected_nodes))
        self.assertEqual(len(cursor.calls), 25)
        with self.assertRaisesRegex(staging.QueryStagingError, "cumulative row, stage or hash"):
            collector.authenticate_references(cursor,
                query=reference_query("one-too-many", reference(selected[5]), table=table, operation=operation),
                query_reads=prior, selected_rows=selected, trace=trace)
        self.assertEqual(len(cursor.calls), 25)

    def test_real_cumulative_cache_stamp_byte_limit_denies_before_reuse_without_new_proof_io(self):
        row = copy.deepcopy(self.first["row"])
        row["padding"] = "😀" * 65536  # 256 KiB UTF-8, about 768 KiB ASCII wire JSON.
        inputs, trees = root_oracle.input_fixture(OPERATION, {CREDENTIALS: [row]})
        selected = (trees[CREDENTIALS].selected({"id": row["id"]}),)
        record = capture(exact_query("padded", selected[0]), selected)
        collector = staging.StagedQueryProofs(operation=OPERATION,
            business_before_roots=inputs["business_before_roots"],
            authorization_before_roots=inputs["authorization_before_roots"])
        cursor, trace = batch_oracle.StoredTreeCursor(*trees.values()), StageTrace()
        selected = collector.authenticate_references(cursor,
            query=reference_query("first-padded", reference(selected[0])),
            query_reads=(record,), selected_rows=selected, trace=trace)
        row_size = len(wire_oracle.wire_json(selected[0]))
        initial = collector.metrics
        successful_reuses = (64 * 1024 * 1024 - initial.stamp_bytes) // row_size
        self.assertLess(successful_reuses + 2, authority_contract.operation_spec(OPERATION)["maximumQueryRows"])
        for index in range(successful_reuses):
            selected = collector.authenticate_references(cursor,
                query=reference_query(f"reuse-{index}", reference(selected[0])),
                query_reads=(record,), selected_rows=selected, trace=trace)
        self.assertEqual(collector.metrics.stamp_bytes, initial.stamp_bytes + successful_reuses * row_size)
        self.assertLessEqual(collector.metrics.stamp_bytes, 64 * 1024 * 1024)
        with self.assertRaisesRegex(staging.QueryStagingError, "cache stamp byte budget"):
            collector.authenticate_references(cursor,
                query=reference_query("stamp-overflow", reference(selected[0])),
                query_reads=(record,), selected_rows=selected, trace=trace)
        self.assertEqual(len(cursor.calls), 5)
        self.assertEqual((collector.metrics.hash_work, collector.metrics.input_bytes, collector.metrics.json_nodes),
                         (initial.hash_work, initial.input_bytes, initial.json_nodes))
        with self.assertRaisesRegex(staging.QueryStagingError, "not ready"):
            collector.unproved_rows(selected)

    def test_query_call_ceiling_and_detached_metrics_do_not_create_alternate_policy(self):
        collector = self.collector()
        metric = collector.metrics
        self.assertEqual({field.name for field in fields(metric)}, {
            "stages", "selected_rows", "hash_work", "input_bytes", "json_nodes",
            "proof_vectors", "proof_child_slots", "stamp_bytes", "stamp_nodes"})
        with self.assertRaises(FrozenInstanceError):
            metric.hash_work = 0
        object.__setattr__(metric, "hash_work", 0)
        self.assertEqual(collector.metrics.hash_work, 66)
        maximum = authority_contract.operation_spec(OPERATION)["maximumQueryRows"]
        # This is the collector's call ceiling, not a claim that this complete
        # proposed program includes its mandatory framework counter selection.
        for index in range(maximum):
            self.assertEqual(self.authenticate(collector, definition(f"empty-{index}"), selected=(), records=()), ())
        self.assertEqual(self.proof_calls(), 0)
        self.assertEqual(collector.metrics.hash_work, 66)
        with self.assertRaisesRegex(staging.QueryStagingError, "query identity is repeated or exceeds"):
            self.authenticate(collector, definition("overflow"), selected=(), records=())
        with self.assertRaises(TypeError):
            staging.StagedQueryProofs(operation=OPERATION,
                business_before_roots=self.inputs["business_before_roots"],
                authorization_before_roots=self.inputs["authorization_before_roots"], limits=object())

    def test_shared_query_meter_accumulates_real_snapshot_reference_and_cached_rescans(self):
        work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
        work.charge(hashes=7, input_bytes=11, json_nodes=13)
        collector = self.collector(query_work=work)
        collector._require_query_work(work)
        records, selected = (self.first_record,), (self.first,)
        queries = tuple(reference_query(name, reference(self.first)) for name in ("shared-a", "shared-b"))
        expected = [expected_stage_query_work(query, records, selected) for query in queries]
        actual_snapshot, actual_references = reads._snapshot_queries, reads._reference_source_rows
        actual_membership = staging.evaluate_primary_radix_memberships
        with mock.patch.object(reads, "_snapshot_queries", wraps=actual_snapshot) as snapshots, \
                mock.patch.object(reads, "_reference_source_rows", wraps=actual_references) as references, \
                mock.patch.object(staging, "evaluate_primary_radix_memberships", wraps=actual_membership) as memberships:
            owned = self.authenticate(collector, queries[0])
            first = work.metrics
            proofs = collector.metrics
            again = self.authenticate(collector, queries[1], selected=owned)
        self.assertIs(again[0], owned[0])
        self.assertEqual(memberships.call_count, 1)
        self.assertEqual(self.proof_calls(), 5)
        self.assertEqual(snapshots.call_count, 4)  # staging and genuine reference enumeration per call
        for call in snapshots.call_args_list:
            passed = call.kwargs.get("work", call.args[2] if len(call.args) > 2 else None)
            self.assertIs(passed, work)
        self.assertEqual(references.call_count, 2)
        self.assertTrue(all(call.kwargs["work"] is work for call in references.call_args_list))
        self.assertEqual((first.hash_work, first.input_bytes, first.json_nodes),
            (7 + expected[0].hashes, 11 + expected[0].bytes, 13 + expected[0].nodes))
        self.assertEqual((work.hash_work, work.input_bytes, work.json_nodes),
            (7 + sum(item.hashes for item in expected), 11 + sum(item.bytes for item in expected),
             13 + sum(item.nodes for item in expected)))
        self.assertGreater(work.input_bytes, first.input_bytes)
        self.assertEqual((collector.metrics.stages, collector.metrics.selected_rows,
                          collector.metrics.hash_work, collector.metrics.input_bytes, collector.metrics.json_nodes),
                         (proofs.stages, proofs.selected_rows, proofs.hash_work, proofs.input_bytes, proofs.json_nodes))
        self.assertGreater(collector.metrics.stamp_bytes, proofs.stamp_bytes)
        self.assertEqual(collector.unproved_rows(again), ())
        self.assertEqual(collector.merge_proofs(selected_rows=again, remaining_proofs=()),
                         (self.trees[CREDENTIALS].proof(self.first),))

    def test_query_meter_exact_limits_and_exhaustion_deny_before_proof_sql(self):
        query = reference_query("meter-quota", reference(self.first))
        expected = expected_stage_query_work(query, (self.first_record,), (self.first,))
        exact = dict(max_hashes=expected.hashes + 1, max_input_bytes=expected.bytes + 1,
                     max_json_nodes=expected.nodes + 1)
        work = accounting._ValidationWork(accounting.QueryReadValidationLimits(**exact))
        work.charge(hashes=1, input_bytes=1, json_nodes=1)
        collector = self.collector(query_work=work)
        self.authenticate(collector, query)
        self.assertEqual((work.hash_work, work.input_bytes, work.json_nodes),
                         (exact["max_hashes"], exact["max_input_bytes"], exact["max_json_nodes"]))
        for field in exact:
            with self.subTest(field=field):
                limits = {**exact, field: exact[field] - 1}
                limited = accounting._ValidationWork(accounting.QueryReadValidationLimits(**limits))
                limited.charge(hashes=1, input_bytes=1, json_nodes=1)
                denied = self.collector(query_work=limited)
                cursor = batch_oracle.StoredTreeCursor(*self.trees.values())
                with self.assertRaises(staging.QueryStagingError):
                    self.authenticate(denied, query, cursor=cursor)
                self.assertEqual(cursor.calls, [])
                self.assertEqual((denied.metrics.stages, denied.metrics.selected_rows, denied.metrics.hash_work),
                                 (0, 0, 66))
                spent = limited.metrics
                with self.assertRaisesRegex(staging.QueryStagingError, "not ready"):
                    denied._require_query_work(limited)
                with self.assertRaisesRegex(staging.QueryStagingError, "not ready"):
                    self.authenticate(denied, query, cursor=cursor)
                self.assertEqual(limited.metrics, spent)
                self.assertEqual(cursor.calls, [])

    def test_query_meter_identity_is_pinned_and_exact_type_admission_is_sticky(self):
        class DerivedWork(accounting._ValidationWork):
            pass
        for invalid in ({}, object(), DerivedWork(accounting.QueryReadValidationLimits())):
            with self.subTest(constructor=type(invalid)), self.assertRaisesRegex(staging.QueryStagingError, "exact shared meter"):
                self.collector(query_work=invalid)
        for mode in ("none", "different", "subclass", "object", "legacy"):
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
            collector = self.collector(query_work=None if mode == "legacy" else work)
            incoming = {
                "none": None, "different": accounting._ValidationWork(accounting.QueryReadValidationLimits()),
                "subclass": DerivedWork(accounting.QueryReadValidationLimits()), "object": object(), "legacy": work,
            }[mode]
            with self.subTest(mode=mode), self.assertRaisesRegex(staging.QueryStagingError, "identity changed"):
                collector._require_query_work(incoming)
            with self.assertRaisesRegex(staging.QueryStagingError, "not ready"):
                collector._require_query_work(work)
            self.assertEqual((work.hash_work, work.input_bytes, work.json_nodes), (0, 0, 0))
        self.assertEqual(self.proof_calls(), 0)

    def test_cached_source_cannot_reset_an_exhausted_shared_query_allowance(self):
        first = reference_query("cache-a", reference(self.first))
        second = reference_query("cache-b", reference(self.first))
        expected = expected_stage_query_work(first, (self.first_record,), (self.first,))
        work = accounting._ValidationWork(accounting.QueryReadValidationLimits(
            max_hashes=expected.hashes, max_input_bytes=expected.bytes, max_json_nodes=expected.nodes))
        collector = self.collector(query_work=work)
        owned = self.authenticate(collector, first)
        spent, proof_usage = work.metrics, collector.metrics
        with self.assertRaises(staging.QueryStagingError):
            self.authenticate(collector, second, selected=owned)
        self.assertEqual(work.metrics, spent)
        self.assertEqual(self.proof_calls(), 5)
        self.assertEqual(collector.metrics, proof_usage)
        with self.assertRaisesRegex(staging.QueryStagingError, "not ready"):
            collector.unproved_rows(owned)

    def test_caught_nested_acquisition_poisons_outer_before_membership_without_refund(self):
        for action in ("authenticate", "close", "meter-check"):
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
            collector = self.collector(query_work=work)
            caught = []
            def change(kind, rows, parameters):
                if not caught:
                    try:
                        if action == "authenticate":
                            self.authenticate(collector, reference_query("nested", reference(self.first)), cursor=cursor)
                        elif action == "close":
                            collector.unproved_rows((self.first,))
                        else:
                            collector._require_query_work(work)
                    except staging.QueryStagingError as exc:
                        caught.append(exc)
                return rows
            cursor = batch_oracle.StoredTreeCursor(*self.trees.values(), change=change)
            with self.subTest(action=action), \
                    mock.patch.object(staging, "evaluate_primary_radix_memberships",
                        wraps=staging.evaluate_primary_radix_memberships) as actual_membership:
                with self.assertRaisesRegex(staging.QueryStagingError, "nested failure"):
                    self.authenticate(collector, cursor=cursor)
            self.assertEqual(len(caught), 1)
            self.assertEqual(actual_membership.call_count, 0)
            self.assertEqual(len(cursor.calls), 5)  # genuine producer finishes; poisoned result cannot be consumed
            self.assertEqual((collector.metrics.stages, collector.metrics.selected_rows, collector.metrics.hash_work),
                             (1, 1, 202))
            self.assertGreater(work.input_bytes, 0)
            spent = work.metrics
            with self.assertRaisesRegex(staging.QueryStagingError, "not ready"):
                collector.unproved_rows((self.first,))
            self.assertEqual(work.metrics, spent)
            self.assertEqual(len(cursor.calls), 5)

    def test_caught_nested_completion_cannot_overwrite_poison_with_a_success_phase(self):
        for phase in ("unproved", "merge"):
            collector = self.collector()
            owned = self.authenticate(collector)
            if phase == "merge":
                self.assertEqual(collector.unproved_rows(owned), ())
            caught = []
            actual_encoder = staging.canonical_bytes
            def encode(value):
                if not caught:
                    try:
                        if phase == "unproved":
                            collector.unproved_rows(owned)
                        else:
                            collector.merge_proofs(selected_rows=owned, remaining_proofs=())
                    except staging.QueryStagingError as exc:
                        caught.append(exc)
                return actual_encoder(value)
            with self.subTest(phase=phase), mock.patch.object(staging, "canonical_bytes", new=encode):
                with self.assertRaisesRegex(staging.QueryStagingError, "nested failure"):
                    if phase == "unproved":
                        collector.unproved_rows(owned)
                    else:
                        collector.merge_proofs(selected_rows=owned, remaining_proofs=())
            self.assertEqual(len(caught), 1)
            with self.assertRaisesRegex(staging.QueryStagingError, "not ready"):
                collector.merge_proofs(selected_rows=owned, remaining_proofs=())

    def test_legacy_none_keeps_public_query_routes_and_existing_proof_counters(self):
        collector = self.collector(query_work=None)
        with mock.patch.object(reads, "snapshot_queries", wraps=reads.snapshot_queries) as snapshots, \
                mock.patch.object(reads, "reference_source_rows", wraps=reads.reference_source_rows) as references:
            owned = self.authenticate(collector)
        self.assertEqual(snapshots.call_count, 1)
        self.assertEqual(references.call_count, 1)
        self.assertEqual((collector.metrics.stages, collector.metrics.selected_rows, collector.metrics.hash_work),
                         (1, 1, 202))
        self.assertEqual(self.proof_calls(), 5)
        self.assertEqual(owned, (self.first,))


if __name__ == "__main__":
    unittest.main()
