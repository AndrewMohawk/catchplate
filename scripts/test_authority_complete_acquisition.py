#!/usr/bin/env python3
"""Real complete acquisition and proof replay over independent stored trees.

The bounded SQL responder is not PostgreSQL or current-root authority. It
delegates the fixed head/range SQL checks and supplies full exact-key rows from
one independent population. Actual acquisition, global primary membership,
six joins and the shared work meter run without successful-verifier stubs.
The public planner registry and v3 complete-query admission remain untouched.
"""
from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError, fields, is_dataclass
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_complete_acquisition as acquisition
from serverware import authority_complete_query as complete
from serverware import authority_complete_query_batch as batch
from serverware import authority_index_heads as heads
from serverware import authority_index_join as joined
from serverware import authority_index_reader as reader
from serverware import authority_radix_mutation as primary
from serverware.authority_query_read_work import (
    _ValidationWork, QueryReadValidationLimits, QueryReadWorkError,
)
import test_authority_complete_query as declaration_oracle
import test_authority_complete_query_batch as batch_oracle
import test_authority_index_frontier as range_oracle
import test_authority_index_heads as head_oracle
import test_authority_index_join as join_oracle


OPERATION = "webauthn.credential.revoke"
EXPIRIES = {"past": 1_000_000, "future": 2_000_000, "used": 3_000_000}
HINTS = ("oidc_session_ids", "approval_grant_ids", "control_plane_approval_ids",
         "registration_challenge_ids")


def wire(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
                      sort_keys=True, separators=(",", ":")).encode("ascii")


def nodes(value):
    if type(value) is dict:
        return 1 + len(value) + sum(nodes(child) for child in value.values())
    if type(value) in (tuple, list):
        return 1 + sum(nodes(child) for child in value)
    return 1


def metric_values(value):
    if is_dataclass(value):
        return {field.name: metric_values(getattr(value, field.name)) for field in fields(value)}
    if type(value) is tuple:
        return tuple(metric_values(item) for item in value)
    return value


class WorkOracle:
    """Literal pass units, independent of production work counters/helpers."""
    def __init__(self):
        self.h = self.b = self.n = 0

    @property
    def total(self):
        return self.h, self.b, self.n

    def add(self, values):
        h, b, n = values
        self.h += h
        self.b += b
        self.n += n

    def graph(self, value, *, byte_passes=2, node_passes=2, ascii=True):
        data = json.dumps(value, ensure_ascii=ascii, allow_nan=False,
                          sort_keys=True, separators=(",", ":")).encode("ascii" if ascii else "utf-8")
        self.b += byte_passes * len(data)
        self.n += node_passes * nodes(value)

    def utf8(self, value):
        self.b += 2 * len(value.encode("utf-8"))
        self.n += 2

    def frames(self, values):
        size = 0
        for value in values:
            text = str(value) if type(value) is int else value
            self.utf8(text)
            self.b += 8
            size += 8 + len(text.encode("utf-8"))
        return size

    def copy(self, value):
        # The genuine source copier charges one extra separator per nonempty
        # container, then its actual scalar canonicalization for bool/int/null.
        def containers(item):
            if type(item) is dict:
                return int(bool(item)) + sum(containers(child) for child in item.values())
            if type(item) in (tuple, list):
                return int(bool(item)) + sum(containers(child) for child in item)
            return 0
        self.b += len(wire(value)) + containers(value)
        self.n += nodes(value)

        def scalars(item):
            if item is None or type(item) in (bool, int):
                self.graph(item)
            elif type(item) is dict:
                for child in item.values():
                    scalars(child)
            elif type(item) in (tuple, list):
                for child in item:
                    scalars(child)
        scalars(value)

    def profile(self, index_id):
        self.graph(join_oracle.descriptor(index_id), ascii=False)
        self.h += 1


def query_value(query):
    return query.operation, query.role, query.selector_items, query.maximum_rows


class Fixture:
    def __init__(self, *, empty=False, approval=False, pending_count=1, arguments=None):
        rows = batch_oracle.default_rows(approval=approval)
        rows["webauthn_credentials"][0].update(revoked_at=None, attestation_trusted=1)
        if pending_count == 2:
            rows["oidc_browser_sessions"].append(batch_oracle.session("pending-second", "pending_webauthn"))
        intent = declaration_oracle.arguments() if arguments is None else copy.deepcopy(arguments)
        if pending_count == 2:
            intent["oidc_session_ids"] = ["active", "pending", "pending-second"]
        if empty:
            for table in ("oidc_browser_sessions", "approval_grants", "control_plane_approvals",
                          "webauthn_challenges"):
                rows[table] = []
            for field in HINTS:
                intent[field] = []
        self.batch = batch_oracle.BatchFixture(rows, arguments=intent)
        self.rows, self.queries, self.intent = self.batch.rows, self.batch.queries, self.batch.intent
        self.stores = {query.role: range_oracle.IndependentStoredIndex(self.rows.get(query.table, []),
            query=query, expiry_us=EXPIRIES if query.table == "webauthn_challenges" else None,
            revision=29) for query in self.queries}
        indexes = {store.tree.profile.index_id: store.tree for store in self.stores.values()}
        extra_selectors = {
            "webauthn_credential_id": {"credential_id": "public-key"},
            "webauthn_credential_user_history": {"user_id": "user"},
            "webauthn_credential_live_trust": {},
            "webauthn_registration_unused_user": {"user_id": "user", "expires_after_us": self.batch.cutoff_us},
        }
        for index_id, selector in extra_selectors.items():
            table = join_oracle.descriptor(index_id)["table"]
            indexes[index_id] = join_oracle.JoinFixture(self.rows[table], index_id=index_id,
                selector=selector, expiry_us=EXPIRIES if table == "webauthn_challenges" else None,
                primary_revision=17, index_revision=29).index
        self.head_rows = head_oracle.source_rows()
        for row in self.head_rows:
            tree = indexes[row["index_id"]]
            row.update(index_revision=29, root_digest=tree.root.digest, leaf_count=tree.root.count)
        for query in self.queries:
            if self.stores[query.role].tree.root != self.batch.joins[query.role].index.root:
                raise AssertionError("range and primary-join oracles have different populations")

    def constructor(self):
        raw = self.batch.arguments()
        return {name: raw[name] for name in ("operation", "arguments", "cutoff_us", "queries",
                "business_before_roots", "authorization_before_roots")}

    def expected_rows(self, query):
        mapping = {row["id"]: row for row in self.rows.get(query.table, [])}
        return tuple(copy.deepcopy(mapping[identifier])
                     for _, identifier in self.stores[query.role].primary_ids())

    def selected(self, observed):
        # Retain independent point reads, then use the actual fetched full
        # rows at each independently committed address. Corrupted rows are
        # deliberately not replaced by oracle originals before verification.
        members = {(query.table, digest) for query in self.queries
                   for digest, _ in self.stores[query.role].primary_ids()}
        selected = {(item["table"], item["keyDigest"]): copy.deepcopy(item)
                    for item in self.batch.selected if (item["table"], item["keyDigest"]) not in members}
        for query, rows in zip(self.queries, observed):
            for raw in rows:
                item = self.batch.trees[query.table].selected({"id": raw["id"]})
                item["row"] = copy.deepcopy(raw)
                selected[(item["table"], item["keyDigest"])] = item
        return tuple(selected[key] for key in sorted(selected))


class Cursor:
    """One transaction-shaped responder, with no hidden fallback/full scans."""
    def __init__(self, fixture, *, change=None):
        self.fixture, self.change = fixture, change
        self.calls, self.fetch_bounds = [], []
        self.head = head_oracle.Cursor(fixture.head_rows)
        self.range = {store.query.index_id: range_oracle.StoredIndexCursor(store, reverse_nodes=True)
                      for store in fixture.stores.values()}
        self.target = self.kind = self.table = None
        self.parameters = ()

    def execute(self, sql, parameters):
        self.calls.append((sql, copy.deepcopy(parameters)))
        self.parameters = parameters
        if f"FROM serverware_metadata.{head_oracle.TABLE} AS head " in sql:
            self.kind, self.table, self.target = "head", head_oracle.TABLE, self.head
            self.target.execute(sql, parameters)
        elif f'FROM "serverware_metadata"."{range_oracle.LEAVES}" AS leaf ' in sql:
            self.kind, self.table, self.target = "leaf", range_oracle.LEAVES, self.range[parameters[0]]
            self.target.execute(sql, parameters)
        elif f'FROM "serverware_metadata"."{range_oracle.NODES}" AS node ' in sql:
            self.kind, self.table, self.target = "node", range_oracle.NODES, self.range[parameters[-2]]
            self.target.execute(sql, parameters)
        else:
            self.kind, self.target = "primary", None
            tables = {query.table for query in self.fixture.queries}
            matches = [table for table in tables if f"FROM serverware_metadata.{table} AS target " in sql]
            if len(matches) != 1 or type(parameters) is not tuple or len(parameters) != 2 or parameters[1] != 2:
                raise AssertionError("unexpected primary SQL or sentinel")
            self.table = matches[0]
            expected = ("SELECT CASE WHEN pg_catalog.octet_length(pg_catalog.to_jsonb(target)::pg_catalog.text) "
                "<= 1048576 THEN pg_catalog.to_jsonb(target) "
                "ELSE NULL END AS row_value "
                f"FROM serverware_metadata.{self.table} AS target WHERE target.id = %s LIMIT %s")
            if sql != expected:
                raise AssertionError("primary lookup is not the exact full-row source-key SELECT")
        return self

    def fetchmany(self, maximum):
        self.fetch_bounds.append(maximum)
        if self.target is not None:
            result = copy.deepcopy(self.target.fetchmany(maximum))
        else:
            if maximum != 2:
                raise AssertionError("primary driver fetch lost its extra-row sentinel")
            result = [{"row_value": copy.deepcopy(row)} for row in self.fixture.rows[self.table]
                      if row["id"] == self.parameters[0]][:2]
        if self.change is not None:
            result = self.change(self.kind, self.table, result, self.parameters)
        return result


class Trace:
    def __init__(self, callback=None):
        self.operation, self.entries, self.callback = OPERATION, [], callback

    def read(self, table, key):
        self.entries.append((table, copy.deepcopy(key)))
        if table == head_oracle.TABLE:
            if key != head_oracle.marker():
                raise AssertionError("head marker is not the independent source union")
        elif table not in (range_oracle.LEAVES, range_oracle.NODES):
            expected_fields = {"profile", "queryId", "indexId", "primaryId", "primaryKeyDigest", "limit"}
            if (set(key) != expected_fields or key["profile"] != acquisition.PRIMARY_READ_PROFILE
                    or key["limit"] != 2
                    or key["primaryKeyDigest"] != range_oracle.business_key(table, key["primaryId"])):
                raise AssertionError("primary trace is not an exact independently committed lookup")
        if self.callback is not None:
            self.callback(table, key)


def expected_work(fixture):
    """Whole successful schedule from independent values, not result metrics."""
    work = WorkOracle()
    raw = fixture.constructor()
    for name in ("arguments", "business_before_roots", "authorization_before_roots"):
        work.copy(raw[name])
    for query in fixture.queries:
        for _ in range(3):
            work.profile(query.index_id)
        document = declaration_oracle.complete_document(query.role, values=fixture.intent,
                                                        cutoff_us=fixture.batch.cutoff_us)
        work.graph(document, byte_passes=3)
    for query in fixture.queries:
        work.utf8(fixture.intent["record_id"])
        for field in HINTS:
            for identifier in fixture.intent[field]:
                work.utf8(identifier)
            work.graph(fixture.intent[field], byte_passes=12, node_passes=12)
        for name, value in query.selector_items:
            if type(value) is str:
                work.utf8(value)
                if name != "status":
                    work.utf8(value)
        work.graph(query.selector_items, byte_passes=4, node_passes=4)
        work.profile(query.index_id)
        work.graph(query_value(query), byte_passes=4, node_passes=4)
    constructed = work.total
    work.graph(tuple(query_value(query) for query in fixture.queries), byte_passes=4, node_passes=4)
    # Both canonical argument encodings and both byte comparison operands.
    work.graph(fixture.intent, byte_passes=6, node_passes=4)
    head_values = head_oracle.expected_work(fixture.head_rows)
    work.add(head_values[:3])
    begun = work.total
    sql_reads, parameter_bytes, transport_bytes = 1, head_values[3], head_values[4]
    for query in fixture.queries:
        work.graph(query_value(query), byte_passes=4, node_passes=4)
        values, physical = range_oracle.reader_work_oracle(fixture.stores[query.role])
        work.add(values)
        sql_reads += physical[0]
        parameter_bytes += physical[1]
        transport_bytes += physical[2]
        for row in fixture.expected_rows(query):
            parameter_bytes += work.frames((row["id"], 2))
            sql_reads += 1
            work.graph(row)
            frame = 8 + len(wire(row))
            work.b += frame
            transport_bytes += frame
            work.copy(row)
    acquired = work.total
    proof_metrics = batch_oracle.independent_batch_metrics(fixture.batch)
    work.add(batch_oracle.expected_totals(proof_metrics))
    return {"constructor": constructed, "begin": begun, "acquired": acquired,
            "total": work.total, "proof": proof_metrics,
            "physical": (sql_reads, parameter_bytes, transport_bytes)}


class CompleteAcquisitionTests(unittest.TestCase):
    def start(self, fixture=None, *, limits=None, change=None, callback=None, work=None):
        fixture = Fixture() if fixture is None else fixture
        work = _ValidationWork(QueryReadValidationLimits() if limits is None else limits) if work is None else work
        cursor, trace = Cursor(fixture, change=change), Trace(callback)
        worker = acquisition._CompleteQueryAcquisition(cursor, **fixture.constructor(), trace=trace, work=work)
        return fixture, cursor, trace, work, worker

    def begin(self, state, **changes):
        fixture, cursor, trace, work, worker = state
        inputs = {"operation": OPERATION, "arguments": copy.deepcopy(fixture.intent),
                  "queries": copy.deepcopy(fixture.queries), "trace": trace, "work": work}
        inputs.update(changes)
        worker.begin(cursor, **inputs)

    def collect(self, state):
        self.begin(state)
        fixture, _, _, _, worker = state
        rows = tuple(worker.read_rows(query) for query in fixture.queries)
        return rows, worker.finish_reads()

    def verify(self, state, observed):
        fixture, _, _, _, worker = state
        return worker.verify(selected_rows=fixture.selected(observed), before_proofs=copy.deepcopy(fixture.batch.proofs))

    def assert_totals(self, work, expected):
        self.assertEqual((work.hash_work, work.input_bytes, work.json_nodes), expected)

    def assert_sticky(self, worker):
        with self.assertRaises(acquisition.CompleteAcquisitionError):
            worker.finish_reads()

    def test_all_five_roles_fetch_full_rows_in_counted_key_order_and_replay_real_proofs(self):
        state = self.start(Fixture(approval=True, pending_count=2))
        fixture, cursor, trace, work, worker = state
        expected = expected_work(fixture)
        with mock.patch.object(batch, "_verify_complete_query_batch", wraps=batch._verify_complete_query_batch) as shared, \
                mock.patch.object(batch, "verify_complete_query_batch", wraps=batch.verify_complete_query_batch) as public, \
                mock.patch.object(primary, "evaluate_primary_radix_memberships", wraps=primary.evaluate_primary_radix_memberships) as memberships, \
                mock.patch.object(joined, "join_index_range", wraps=joined.join_index_range) as joins:
            observed, evidence = self.collect(state)
            self.assertIsNone(evidence)
            result = self.verify(state, observed)
            evidence = worker.retained_evidence()
        self.assertEqual(shared.call_count, 1)
        self.assertIs(shared.call_args.kwargs["work"], work)
        self.assertEqual(public.call_count, 0)
        self.assertEqual((memberships.call_count, joins.call_count), (7, 6))
        self.assertEqual(observed, tuple(fixture.expected_rows(query) for query in fixture.queries))
        self.assertEqual(tuple(item.index_id for item in evidence.heads), head_oracle.IDS)
        self.assertEqual(tuple(item.query_id for item in evidence.frontiers), tuple(query.query_id for query in fixture.queries))
        self.assertEqual(result.selected_rows, fixture.batch.selected)
        self.assertTrue(all(item["contractSelector"] is None for item in result.selected_rows))
        self.assertEqual(metric_values(result.metrics), expected["proof"])
        self.assert_totals(work, expected["total"])
        physical = worker._acquisition
        self.assertEqual((physical.sql_reads, physical.parameter_bytes, physical.transport_bytes), expected["physical"])
        self.assertEqual(len(cursor.calls), len(trace.entries))
        self.assertEqual(len(cursor.calls), physical.sql_reads)

    def test_shared_session_head_is_captured_once_but_both_real_role_ranges_are_read(self):
        state = self.start()
        observed, evidence = self.collect(state)
        self.assertIsNone(evidence)
        self.verify(state, observed)
        evidence = state[4].retained_evidence()
        session_heads = [item for item in evidence.heads if item.index_id == "webauthn_session_credential_status"]
        self.assertEqual(len(session_heads), 1)
        self.assertEqual(tuple(row["id"] for row in observed[0]), ("pending",))
        self.assertEqual(tuple(row["id"] for row in observed[1]), ("active",))
        leaves = [parameters for sql, parameters in state[1].calls if 'AS leaf WHERE' in sql]
        self.assertEqual(sum(parameters[0] == session_heads[0].index_id for parameters in leaves), 2)

    def test_empty_all_role_results_still_retain_five_frontiers_and_replay_five_joins(self):
        state = self.start(Fixture(empty=True))
        expected = expected_work(state[0])
        with mock.patch.object(joined, "join_index_range", wraps=joined.join_index_range) as joins:
            observed, evidence = self.collect(state)
            self.assertIsNone(evidence)
            result = self.verify(state, observed)
            evidence = state[4].retained_evidence()
        self.assertEqual(observed, ((), (), (), (), (), ()))
        self.assertEqual((len(evidence.frontiers), joins.call_count), (6, 6))
        self.assertFalse(any("AS target" in sql for sql, _ in state[1].calls))
        self.assertTrue(all(not value.leaves for _, value in result.joined_reads))
        self.assert_totals(state[3], expected["total"])

    def test_missing_duplicate_wrong_key_and_sql_oversize_primary_rows_fail_closed(self):
        def missing(rows):
            return []
        def duplicate(rows):
            return rows + copy.deepcopy(rows)
        def wrong_key(rows):
            rows[0]["row_value"]["id"] = "different"
            return rows
        def oversize(rows):
            return [{"row_value": None}]
        for fault in (missing, duplicate, wrong_key, oversize):
            with self.subTest(fault=fault.__name__):
                state = self.start(change=lambda kind, table, rows, parameters:
                                   fault(rows) if kind == "primary" else rows)
                self.begin(state)
                with self.assertRaises((acquisition.CompleteAcquisitionError, reader.IndexReadError)):
                    state[4].read_rows(state[0].queries[0])
                self.assert_sticky(state[4])
        # A broken driver ignoring the SQL text bound still cannot force a
        # canonical output allocation beyond the one-MiB row contract.
        def unbounded(kind, table, rows, parameters):
            if kind == "primary":
                rows[0]["row_value"]["large"] = "x" * (1024 * 1024)
            return rows
        state = self.start(change=unbounded)
        self.begin(state)
        with mock.patch.object(acquisition.reads, "_wire", wraps=acquisition.reads._wire) as encode:
            with self.assertRaises(acquisition.CompleteAcquisitionError):
                state[4].read_rows(state[0].queries[0])
        self.assertEqual(encode.call_count, 0)
        self.assert_sticky(state[4])

    def test_changed_full_primary_row_is_not_repaired_before_genuine_membership_rejection(self):
        def change(kind, table, rows, parameters):
            if kind == "primary":
                rows[0]["row_value"]["component_corruption"] = "kept"
            return rows
        state = self.start(change=change)
        observed, _ = self.collect(state)
        self.assertEqual(observed[0][0]["component_corruption"], "kept")
        with mock.patch.object(primary, "evaluate_primary_radix_memberships", wraps=primary.evaluate_primary_radix_memberships) as actual:
            with self.assertRaises(batch.CompleteQueryBatchError):
                self.verify(state, observed)
        self.assertEqual(actual.call_count, 1)
        self.assert_sticky(state[4])
        # A separately coherent primary tree is not enough: keep the genuine
        # acquired index at the old full-row commitment, but supply real
        # primary roots/proofs for the updated full row. The global proof must
        # succeed and the actual first index/primary join must reject.
        fixture = Fixture()
        updated = copy.deepcopy(fixture.rows)
        next(row for row in updated["oidc_browser_sessions"] if row["id"] == "pending")["metadata"]["note"] = "new primary population"
        fixture.batch = batch_oracle.BatchFixture(updated, arguments=fixture.intent)
        fixture.rows = fixture.batch.rows
        state = self.start(fixture)
        observed, _ = self.collect(state)
        with mock.patch.object(primary, "evaluate_primary_radix_memberships", wraps=primary.evaluate_primary_radix_memberships) as memberships, \
                mock.patch.object(joined, "join_index_range", wraps=joined.join_index_range) as joins:
            with self.assertRaises(batch.CompleteQueryBatchError):
                self.verify(state, observed)
        self.assertEqual((memberships.call_count, joins.call_count), (2, 1))
        self.assert_sticky(state[4])

    def test_stale_counted_root_or_revision_rejects_actual_range_before_primary_fetch(self):
        for field, value in (("root_digest", "sha256:" + "1" * 64), ("index_revision", 28)):
            with self.subTest(field=field):
                state = self.start()
                for row in state[1].head.rows:
                    if row["index_id"] == "webauthn_session_credential_status":
                        row[field] = value
                self.begin(state)
                with self.assertRaises((reader.IndexReadError, ValueError)):
                    state[4].read_rows(state[0].queries[0])
                self.assertFalse(any("AS target" in sql for sql, _ in state[1].calls))
                self.assert_sticky(state[4])

    def test_missing_potential_write_head_denies_before_any_range_or_primary_read(self):
        state = self.start()
        state[1].head.rows = [row for row in state[1].head.rows if row["index_id"] != "webauthn_credential_live_trust"]
        with self.assertRaises(heads.IndexHeadReadError):
            self.begin(state)
        self.assertEqual(len(state[1].calls), 1)
        self.assert_sticky(state[4])

    def test_context_change_and_bool_integer_alias_deny_before_first_sql(self):
        arguments = declaration_oracle.arguments()
        arguments["audit_event"] = {"nested": [True]}
        for field, value in (("actor_id", "another"), ("audit_event", {"nested": [1]})):
            with self.subTest(field=field):
                state = self.start(Fixture(arguments=arguments))
                changed = copy.deepcopy(arguments)
                changed[field] = value
                with self.assertRaises(acquisition.CompleteAcquisitionError):
                    self.begin(state, arguments=changed)
                self.assertEqual(state[1].calls, [])
                self.assert_sticky(state[4])

    def test_constructor_rebinds_actual_source_arguments_and_cutoff_before_sql(self):
        fixture = Fixture()
        for changed in ("cutoff", "record", "inventory", "work"):
            with self.subTest(changed=changed):
                cursor, trace = Cursor(fixture), Trace()
                work = _ValidationWork(QueryReadValidationLimits())
                inputs = fixture.constructor()
                if changed == "cutoff":
                    inputs["cutoff_us"] += 1
                elif changed == "record":
                    inputs["arguments"]["record_id"] = "other"
                elif changed == "inventory":
                    inputs["queries"] = inputs["queries"][:-1]
                else:
                    work = None
                with self.assertRaises((acquisition.CompleteAcquisitionError, ValueError)):
                    acquisition._CompleteQueryAcquisition(cursor, **inputs, trace=trace, work=work)
                self.assertEqual(cursor.calls, [])

    def test_roles_cannot_be_reordered_repeated_omitted_or_read_after_completion(self):
        for action in ("reorder", "repeat", "omit", "complete"):
            with self.subTest(action=action):
                state = self.start()
                worker, queries = state[4], state[0].queries
                self.begin(state)
                if action == "reorder":
                    call = lambda: worker.read_rows(queries[1])
                elif action == "repeat":
                    worker.read_rows(queries[0])
                    call = lambda: worker.read_rows(queries[0])
                elif action == "omit":
                    worker.read_rows(queries[0])
                    call = worker.finish_reads
                else:
                    observed = tuple(worker.read_rows(query) for query in queries)
                    worker.finish_reads()
                    self.verify(state, observed)
                    call = lambda: worker.read_rows(queries[0])
                prior = len(state[1].calls)
                with self.assertRaises(acquisition.CompleteAcquisitionError):
                    call()
                self.assertEqual(len(state[1].calls), prior)
                self.assert_sticky(worker)

    def test_begin_rejects_different_exact_work_cursor_or_trace_without_sql(self):
        for change in ("work", "cursor", "trace"):
            with self.subTest(change=change):
                state = self.start()
                fixture, cursor, trace, work, worker = state
                kwargs = {"operation": OPERATION, "arguments": fixture.intent,
                          "queries": fixture.queries, "trace": trace, "work": work}
                if change == "work":
                    kwargs["work"] = _ValidationWork(QueryReadValidationLimits())
                elif change == "cursor":
                    cursor = Cursor(fixture)
                else:
                    kwargs["trace"] = Trace()
                with self.assertRaises(acquisition.CompleteAcquisitionError):
                    worker.begin(cursor, **kwargs)
                self.assertEqual(state[1].calls, [])
                self.assert_sticky(worker)

    def test_pinned_work_cursor_and_trace_cannot_be_replaced_before_proof_replay(self):
        for attribute in ("_work", "_cursor", "_trace"):
            with self.subTest(attribute=attribute):
                state = self.start()
                observed, _ = self.collect(state)
                replacement = (_ValidationWork(QueryReadValidationLimits()) if attribute == "_work"
                               else Cursor(state[0]) if attribute == "_cursor" else Trace())
                setattr(state[4], attribute, replacement)
                with mock.patch.object(batch, "_verify_complete_query_batch", wraps=batch._verify_complete_query_batch) as proof:
                    with self.assertRaises(acquisition.CompleteAcquisitionError):
                        self.verify(state, observed)
                self.assertEqual(proof.call_count, 0)
                self.assert_sticky(state[4])

    def test_caught_nested_collector_calls_poison_head_range_and_primary_callbacks(self):
        for trigger in (head_oracle.TABLE, range_oracle.LEAVES, "oidc_browser_sessions"):
            with self.subTest(trigger=trigger):
                state = self.start()
                caught = []
                def callback(table, key):
                    if table == trigger and not caught:
                        try:
                            state[4].finish_reads()
                        except acquisition.CompleteAcquisitionError:
                            caught.append(table)
                state[2].callback = callback
                with self.assertRaises((acquisition.CompleteAcquisitionError, reader.IndexReadError)):
                    self.collect(state)
                self.assertEqual(caught, [trigger])
                self.assert_sticky(state[4])

    def test_caught_nested_acquisition_scope_failure_cannot_publish_outer_rows(self):
        state = self.start()
        self.begin(state)
        caught = []
        def callback(table, key):
            if not caught:
                try:
                    with state[4]._acquisition.scope(state[1], state[2], state[3]):
                        self.fail("nested acquisition unexpectedly entered")
                except reader.IndexReadError:
                    caught.append(table)
        state[2].callback = callback
        with self.assertRaises((acquisition.CompleteAcquisitionError, reader.IndexReadError)):
            state[4].read_rows(state[0].queries[0])
        self.assertEqual(len(caught), 1)
        self.assertTrue(state[4]._acquisition.failed)
        self.assert_sticky(state[4])

    def test_owned_context_rows_and_evidence_survive_external_mutation(self):
        fixture = Fixture()
        raw = fixture.constructor()
        cursor, trace, work = Cursor(fixture), Trace(), _ValidationWork(QueryReadValidationLimits())
        worker = acquisition._CompleteQueryAcquisition(cursor, **raw, trace=trace, work=work)
        raw["arguments"]["actor_id"] = "caller changed"
        raw["business_before_roots"][0]["rootDigest"] = "sha256:" + "0" * 64
        state = fixture, cursor, trace, work, worker
        observed, evidence = self.collect(state)
        self.assertIsNone(evidence)
        # The only pre-proof export is a fresh charged copy of the captured
        # primary roots, not an alias to the private proof inputs.
        before = work.hash_work, work.input_bytes, work.json_nodes
        root_work = WorkOracle()
        roots = fixture.constructor()
        root_work.copy(roots["business_before_roots"])
        root_work.copy(roots["authorization_before_roots"])
        exported = worker.roots_for_proofs()
        self.assertEqual(exported, tuple(roots["business_before_roots"] + roots["authorization_before_roots"]))
        self.assert_totals(work, tuple(left + right for left, right in zip(before, root_work.total)))
        exported[0]["rootDigest"] = "sha256:" + "f" * 64
        result = self.verify(state, observed)
        evidence = worker.retained_evidence()
        observed[0][0]["metadata"]["note"] = "caller changed after verification"
        self.assertEqual(result.arguments, fixture.intent)
        self.assertEqual(result.selected_rows, fixture.batch.selected)
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            evidence.cutoff_us = 0
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            evidence.heads[0].index_revision = 0
        state = self.start(fixture)
        self.collect(state)
        with self.assertRaises(acquisition.CompleteAcquisitionError):
            state[4].retained_evidence()
        self.assert_sticky(state[4])

    def test_external_query_mutation_during_actual_hash_cannot_redirect_owned_fetch(self):
        state = self.start()
        self.begin(state)
        original = copy.deepcopy(state[0].queries[0])
        mutable = copy.deepcopy(original)
        actual_sha = hashlib.sha256
        changed = []
        def digest(*args, **kwargs):
            if not changed:
                object.__setattr__(mutable, "role", "sessions_active")
                object.__setattr__(mutable, "selector_items", state[0].queries[1].selector_items)
                changed.append(True)
            return actual_sha(*args, **kwargs)
        with mock.patch.object(hashlib, "sha256", side_effect=digest):
            returned = state[4].read_rows(mutable)
        self.assertEqual(changed, [True])
        self.assertEqual(returned, state[0].expected_rows(original))
        self.assertEqual(tuple(row["id"] for row in returned), ("pending",))
        observed = (returned, *(state[4].read_rows(query) for query in state[0].queries[1:]))
        state[4].finish_reads()
        self.verify(state, observed)

    def test_exact_independent_whole_limits_and_preconsumed_work_do_not_reset(self):
        fixture = Fixture(approval=True)
        expected = expected_work(fixture)
        prefix = (7, 101, 13)
        maxima = tuple(left + right for left, right in zip(prefix, expected["total"]))
        work = _ValidationWork(QueryReadValidationLimits(*maxima))
        work.charge(hashes=prefix[0], input_bytes=prefix[1], json_nodes=prefix[2])
        state = self.start(fixture, work=work)
        self.assert_totals(work, tuple(left + right for left, right in zip(prefix, expected["constructor"])))
        self.begin(state)
        self.assert_totals(work, tuple(left + right for left, right in zip(prefix, expected["begin"])))
        observed = tuple(state[4].read_rows(query) for query in fixture.queries)
        state[4].finish_reads()
        self.assert_totals(work, tuple(left + right for left, right in zip(prefix, expected["acquired"])))
        original = batch._verify_complete_query_batch
        seen = []
        def verify(**kwargs):
            current = kwargs["work"]
            seen.append((current, current.limits.max_hashes - current.hash_work,
                         current.limits.max_input_bytes - current.input_bytes,
                         current.limits.max_json_nodes - current.json_nodes))
            return original(**kwargs)
        with mock.patch.object(batch, "_verify_complete_query_batch", side_effect=verify), \
                mock.patch.object(_ValidationWork, "__init__", side_effect=AssertionError("fresh work allowance")):
            result = self.verify(state, observed)
        self.assertEqual(seen, [(work, *batch_oracle.expected_totals(expected["proof"]))])
        self.assertEqual(metric_values(result.metrics), expected["proof"])
        self.assert_totals(work, maxima)

    def test_independent_minus_one_whole_quotas_deny_real_proof_without_retry(self):
        fixture = Fixture()
        expected = expected_work(fixture)["total"]
        for dimension in range(3):
            with self.subTest(dimension=dimension):
                limits = list(expected)
                limits[dimension] -= 1
                state = self.start(fixture, limits=QueryReadValidationLimits(*limits))
                observed, _ = self.collect(state)
                with mock.patch.object(batch, "_verify_complete_query_batch", wraps=batch._verify_complete_query_batch) as proof:
                    with self.assertRaises(batch.CompleteQueryBatchError):
                        self.verify(state, observed)
                    with self.assertRaises(acquisition.CompleteAcquisitionError):
                        self.verify(state, observed)
                self.assertEqual(proof.call_count, 1)
                self.assert_sticky(state[4])

    def test_exhausted_shared_work_denies_before_next_sql_and_stays_failed(self):
        state = self.start()
        self.begin(state)
        work = state[3]
        work.charge(input_bytes=work.limits.max_input_bytes - work.input_bytes)
        previous = len(state[1].calls)
        with self.assertRaises(QueryReadWorkError):
            state[4].read_rows(state[0].queries[0])
        self.assertEqual(len(state[1].calls), previous)
        self.assert_sticky(state[4])

    def test_real_sql_parameter_and_returned_frame_limits_accumulate_across_roles(self):
        fixture = Fixture()
        expected = expected_work(fixture)["physical"]
        for dimension in range(3):
            with self.subTest(dimension=dimension):
                state = self.start(fixture)
                limits = list(expected)
                limits[dimension] -= 1
                state[4]._acquisition.limits = reader._ReadAcquisitionLimits(*limits)
                with self.assertRaises(reader.IndexReadError):
                    self.collect(state)
                self.assert_sticky(state[4])
        state = self.start(fixture)
        state[4]._acquisition.limits = reader._ReadAcquisitionLimits(*expected)
        observed, _ = self.collect(state)
        self.verify(state, observed)
        physical = state[4]._acquisition
        self.assertEqual((physical.sql_reads, physical.parameter_bytes, physical.transport_bytes), expected)


if __name__ == "__main__":
    unittest.main()
