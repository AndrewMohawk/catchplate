#!/usr/bin/env python3
"""Canonical complement and real frontier-reader component regressions.

Independent integer tiling and counted-tree hashes provide the expected
results. The SQL cursor is a deterministic stored-row responder, not PostgreSQL;
the production reader and actual range reconstruction are never replaced by a
successful verifier. A supplied root remains declared data: no maintained
index, primary membership, current checkpoint, installed schema, launched
planner or operation authorization is established here.
"""
from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError, fields, replace
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_complete_query as complete
from serverware import authority_index_contract as contract
from serverware import authority_index_frontier as frontier
from serverware import authority_index_range as ranges
from serverware import authority_index_reader as reader
from serverware import authority_query_read_work as measured
import test_authority_index_join as join_oracle
import test_authority_index_range as tree_oracle


WIDTH = 160
TOP = 16**WIDTH
DIGITS = "0123456789abcdef"
LEAVES = "policy_authority_counted_index_leaves"
NODES = "policy_authority_counted_index_nodes"
LEAF_FIELDS = ("index_id", "projection_digest", "index_key", "primary_id",
               "primary_key_digest", "primary_row_digest", "index_revision")
NODE_FIELDS = ("index_id", "projection_digest", "depth", "path_prefix",
               "node_digest", "subtree_count", "index_revision")


def key(value):
    return f"{value:0160x}"


def interval(lower, upper):
    return contract.KeyInterval(key(lower), None if upper == TOP else key(upper))


def prefix_span(prefix):
    width = 16 ** (WIDTH - len(prefix))
    lower = int(prefix, 16) * width
    return lower, lower + width


def complement_oracle(bounds):
    """Greedy aligned integer blocks, independently of production's DFS."""
    lower = int(bounds.lower, 16)
    upper = TOP if bounds.upper is None else int(bounds.upper, 16)
    if lower == upper:
        return tuple(DIGITS)
    result = []
    for start, end in ((0, lower), (upper, TOP)):
        while start < end:
            power, size = 0, 1
            while size * 16 <= end - start and size * 16 < TOP and start % (size * 16) == 0:
                power += 1
                size *= 16
            result.append(key(start)[:WIDTH - power])
            start += size
    return tuple(result)


def values(value):
    return {field.name: getattr(value, field.name) for field in fields(value)}


def forged(value, **changes):
    result = object.__new__(type(value))
    for field in fields(value):
        object.__setattr__(result, field.name, changes.get(field.name, getattr(value, field.name)))
    return result


def bound_query(role="grants", *, maximum_rows=3, record_id="credential-雪", cutoff_us=0):
    hints = [f"hint-{number:02d}" for number in range(maximum_rows)]
    arguments = {"record_id": record_id, "source": "explicit",
                 "oidc_session_ids": list(hints), "approval_grant_ids": list(hints),
                 "control_plane_approval_ids": list(hints), "registration_challenge_ids": list(hints)}
    return complete.bind_query("webauthn.credential.revoke", role, arguments=arguments, cutoff_us=cutoff_us)


class IndependentStoredIndex:
    """Proposed SQL rows projected only from independent counted-tree nodes."""

    def __init__(self, rows, *, query=None, expiry_us=None, revision=11):
        self.query = bound_query() if query is None else query
        self.fixture = join_oracle.JoinFixture(rows, index_id=self.query.index_id,
            selector=self.query.selector(), expiry_us=expiry_us, index_revision=revision)
        self.tree = self.fixture.index
        self.revision = revision
        by_digest = {value["keyDigest"]: value["key"]["id"] for value in self.fixture.all_selected}
        self.leaves = {path: {
            "index_id": self.tree.profile.index_id,
            "projection_digest": self.tree.profile.projection_digest,
            "index_key": path, "primary_id": by_digest[value.primary_key_digest],
            "primary_key_digest": value.primary_key_digest, "primary_row_digest": value.primary_row_digest,
            "index_revision": revision,
        } for path, value in self.tree.leaves.items()}
        # At depth160 the persisted terminal is the independent leaf digest
        # with count1; no second branch hash is invented for these addresses.
        self.nodes = {(len(prefix), prefix): {
            "index_id": self.tree.profile.index_id,
            "projection_digest": self.tree.profile.projection_digest,
            "depth": len(prefix), "path_prefix": prefix,
            "node_digest": digest, "subtree_count": count, "index_revision": revision,
        } for prefix, (digest, count) in self.tree.nodes.items() if prefix and count > 0}

    def primary_ids(self):
        return tuple((value.primary_key_digest, self.leaves[value.key]["primary_id"])
                     for value in self.tree.matches(self.fixture.interval))


def scalar_bytes(kind, row):
    names = LEAF_FIELDS if kind == "leaf" else NODE_FIELDS
    return sum(8 + len((str(value) if type(value) is int else value).encode("utf-8"))
               for value in (kind, *(row[name] for name in names)))


def business_key(table, primary_id):
    material = json.dumps({"id": primary_id}, ensure_ascii=True, allow_nan=False,
                          sort_keys=True, separators=(",", ":")).encode("ascii")
    digest = hashlib.sha256(b"serverware.policyAuthorityBusinessKey/v1\0")
    for frame in (table.encode("ascii"), material):
        digest.update(len(frame).to_bytes(8, "big"))
        digest.update(frame)
    return "sha256:" + digest.hexdigest()


class ReaderWorkOracle:
    """Independent declared units; never calls a production work preparer."""
    def __init__(self):
        self.hashes = self.bytes = self.nodes = 0

    def json(self, value, *, ascii=True):
        def nodes(item):
            if type(item) is dict:
                return 1 + len(item) + sum(nodes(child) for child in item.values())
            if type(item) in (list, tuple):
                return 1 + sum(nodes(child) for child in item)
            return 1
        encoded = json.dumps(value, ensure_ascii=ascii, allow_nan=False,
                             sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.bytes += 2 * len(encoded)
        self.nodes += 2 * nodes(value)

    def utf8(self, value):
        self.bytes += 2 * len(value.encode("utf-8"))
        self.nodes += 2

    def frames(self, values):
        result = 0
        for value in values:
            value = str(value) if type(value) is int else value
            self.utf8(value)
            self.bytes += 8
            result += 8 + len(value.encode("utf-8"))
        return result

    @property
    def total(self):
        return self.hashes, self.bytes, self.nodes


def reader_work_oracle(store):
    query, profile = store.query, store.tree.profile
    selector = dict(query.selector_items)
    descriptor = join_oracle.descriptor(profile.index_id)
    work = ReaderWorkOracle()
    # One real constructor, explicit profile, and interval's own profile.
    for _ in range(3):
        work.json(descriptor, ascii=False)
    work.hashes += 4
    for name, value in query.selector_items:
        if type(value) is str:
            work.utf8(value)
            if name != "status":
                work.utf8(value)
    for _ in range(3):
        work.json(query.selector_items)
    work.json(selector)
    for value in selector.values():
        if type(value) is str:
            work.utf8(value)
    partition = {name: selector[name] for name in descriptor["partitionFields"]}
    work.json(partition)
    work.json(partition, ascii=False)
    for value in ("serverware.policyAuthorityIndexPartition/v1", contract.PROFILE,
                  profile.index_id, profile.table, profile.projection_digest):
        work.utf8(value)
    work.bytes += 8 * 6
    bounds = store.fixture.interval
    prefixes = complement_oracle(bounds)
    parameters = (profile.index_id, bounds.lower)
    if bounds.upper is not None:
        parameters += (bounds.upper,)
    parameter_bytes = work.frames((*parameters, query.maximum_rows + 1))
    for offset in range(0, len(prefixes), 256):
        batch = prefixes[offset:offset + 256]
        parameters = (*(value for prefix in batch for value in (len(prefix), prefix)),
                      profile.index_id, len(batch) + 1)
        parameter_bytes += work.frames(parameters)
    records = [("leaf", store.leaves[item.key]) for item in store.tree.matches(bounds)]
    records.extend(("node", store.nodes[(len(prefix), prefix)])
                   for prefix in prefixes if (len(prefix), prefix) in store.nodes)
    transport_bytes = 0
    for kind, row in records:
        fields = LEAF_FIELDS if kind == "leaf" else NODE_FIELDS
        work.json(row)
        for name in ("index_id", "projection_digest", "primary_id" if kind == "leaf" else "path_prefix"):
            work.utf8(row[name])
        transport_bytes += work.frames((kind, *(row[name] for name in fields)))
        if kind == "leaf":
            work.utf8(profile.table)
            work.json({"id": row["primary_id"]})
            work.bytes += 16
            work.hashes += 1
    proof = store.tree.frontier(bounds)
    hashes, size, nodes = tree_oracle.shared_work_oracle(profile, store.tree.root, bounds, proof)
    work.hashes += hashes
    work.bytes += size
    work.nodes += nodes
    return work.total, (1 + (len(prefixes) + 255) // 256, parameter_bytes, transport_bytes)


class RecordingTrace:
    """Local physical-read observer; this profile has no planner admission."""
    def __init__(self, events=None):
        self.reads = []
        self.events = [] if events is None else events

    def read(self, table, key):
        self.reads.append((table, copy.deepcopy(key)))
        self.events.append(("trace", table))


class StoredIndexCursor:
    """Bounded SQL responder with explicit adversarial driver-result hooks."""
    def __init__(self, store, *, change=None, reverse_nodes=False, events=None):
        self.store = store
        self.change = change
        self.reverse_nodes = reverse_nodes
        self.events = [] if events is None else events
        self.calls = []
        self.fetch_sizes = []
        self.returned = []
        self.result = None
        self.kind = None
        self.limit = None

    def execute(self, statement, parameters):
        self.calls.append((statement, copy.deepcopy(parameters)))
        if type(parameters) is not tuple or "LIMIT %s" not in statement:
            raise AssertionError("fixture SQL lost fixed tuple parameters or sentinel limit")
        if f'FROM "serverware_metadata"."{LEAVES}" AS leaf ' in statement:
            self.kind = "leaf"
            if len(parameters) not in (3, 4):
                raise AssertionError("fixture leaf range parameters changed")
            index_id, lower = parameters[:2]
            upper = parameters[2] if len(parameters) == 4 else None
            self.limit = parameters[-1]
            if not 2 <= self.limit <= 33:
                raise AssertionError("fixture source leaf bound changed")
            expected_tail = (f' FROM "serverware_metadata"."{LEAVES}" AS leaf '
                'WHERE leaf.index_id COLLATE "C" = %s AND leaf.index_key COLLATE "C" >= %s'
                + ('' if upper is None else ' AND leaf.index_key COLLATE "C" < %s')
                + ' ORDER BY leaf.index_key COLLATE "C" LIMIT %s')
            if statement[statement.index(' FROM '):] != expected_tail:
                raise AssertionError("fixture leaf SQL hides or changes matching rows")
            rows = [copy.deepcopy(row) for path, row in sorted(self.store.leaves.items())
                    if row["index_id"] == index_id and lower <= path and (upper is None or path < upper)]
        elif f'FROM "serverware_metadata"."{NODES}" AS node ' in statement:
            self.kind = "node"
            if (len(parameters) - 2) % 2:
                raise AssertionError("fixture node parameters are not exact depth/prefix pairs")
            identities = tuple(tuple(parameters[index:index + 2]) for index in range(0, len(parameters) - 2, 2))
            index_id, self.limit = parameters[-2:]
            if (not 1 <= len(identities) <= 256 or len(set(identities)) != len(identities)
                    or self.limit != len(identities) + 1):
                raise AssertionError("fixture node batch or overflow sentinel changed")
            if statement.count("(%s::pg_catalog.int4,%s::pg_catalog.text)") != len(identities):
                raise AssertionError("fixture node VALUES do not name every requested identity")
            requested_sql = ", ".join("(%s::pg_catalog.int4,%s::pg_catalog.text)" for _ in identities)
            expected_tail = (f' FROM "serverware_metadata"."{NODES}" AS node '
                f'JOIN (VALUES {requested_sql}) AS requested(depth, path_prefix) '
                'ON node.depth = requested.depth AND node.path_prefix COLLATE "C" = '
                'requested.path_prefix COLLATE "C" WHERE node.index_id COLLATE "C" = %s LIMIT %s')
            if statement[statement.index(' FROM '):] != expected_tail:
                raise AssertionError("fixture node SQL hides or changes matching rows")
            rows = [copy.deepcopy(self.store.nodes[address]) for address in identities
                    if address in self.store.nodes and self.store.nodes[address]["index_id"] == index_id]
            if self.reverse_nodes:
                rows.reverse()
        else:
            raise AssertionError("unexpected SQL, relation, namespace or mutation")
        self.events.append(("execute", self.kind))
        # Model the real SQL LIMIT. Fault hooks run afterward and may return
        # an unbounded/wrong driver collection to exercise Python admission.
        self.result = rows[:self.limit]
        if self.change is not None:
            self.result = self.change(self.kind, copy.deepcopy(self.result), parameters)
        return self

    def fetchmany(self, size):
        if size != self.limit or not 2 <= size <= 257:
            raise AssertionError("fixture bounded fetch differs from SQL sentinel")
        self.fetch_sizes.append(size)
        self.events.append(("fetch", self.kind))
        result = copy.deepcopy(self.result)
        self.returned.append((self.kind, copy.deepcopy(result)))
        return result


class OutsidePrefixTests(unittest.TestCase):
    def assert_cover(self, bounds):
        actual = frontier.outside_prefixes(bounds)
        self.assertIs(type(actual), tuple)
        self.assertEqual(actual, complement_oracle(bounds))
        self.assertEqual(actual, tuple(sorted(set(actual))))
        self.assertLessEqual(len(actual), 4800)
        lower = int(bounds.lower, 16)
        upper = TOP if bounds.upper is None else int(bounds.upper, 16)
        spans = []
        for prefix in actual:
            self.assertTrue(1 <= len(prefix) <= WIDTH)
            left, right = prefix_span(prefix)
            self.assertTrue(lower == upper or right <= lower or upper <= left)
            if len(prefix) > 1:
                parent_left, parent_right = prefix_span(prefix[:-1])
                self.assertTrue(parent_left < upper and lower < parent_right)
            spans.append((left, right))
        self.assertTrue(all(left_end <= right_start for (_, left_end), (right_start, _)
                            in zip(spans, spans[1:])))
        self.assertEqual(sum(end - start for start, end in spans), TOP - (upper - lower))
        return actual

    def test_empty_intervals_open_sixteen_root_children_and_fullspace_has_no_complement(self):
        for cut in (0, 1, TOP // 2, TOP - 1):
            with self.subTest(cut=cut):
                self.assertEqual(self.assert_cover(interval(cut, cut)), tuple(DIGITS))
        self.assertEqual(self.assert_cover(interval(0, TOP)), ())
        self.assertEqual((frontier.MAX_OUTSIDE_PREFIXES, frontier.MAX_VISITED_SLOTS), (4800, 5104))

    def test_each_root_partition_has_exact_other_fifteen_maximal_slots(self):
        width = TOP // 16
        for digit in range(16):
            with self.subTest(digit=digit):
                result = self.assert_cover(interval(digit * width, (digit + 1) * width))
                self.assertEqual(result, tuple(value for value in DIGITS if value != DIGITS[digit]))

    def test_deep_boundary_carries_top_sentinel_and_single_key_intervals(self):
        cases = ((0, 1), (TOP - 1, TOP), (1, TOP - 1),
                 (16**80 - 1, 16**80 + 1), (7 * 16**159, 9 * 16**159),
                 (int("a5" + "0" * 158, 16) + 7, int("a5" + "0" * 158, 16) + 257))
        for lower, upper in cases:
            with self.subTest(lower=key(lower), upper=upper):
                self.assert_cover(interval(lower, upper))
        for point in (0, 1, 16**80 - 1, TOP // 2, TOP - 1):
            with self.subTest(point=point):
                self.assertEqual(len(self.assert_cover(interval(point, point + 1))), 2400)

    def test_two_deep_boundaries_reach_fixed_traversal_edge_without_relaxing_caps(self):
        # Two partial paths survive every depth:16+32*159 visited slots.
        bounds = interval(8 * 16**159 - 1, 8 * 16**159 + 1)
        result = self.assert_cover(bounds)
        self.assertEqual(len(result), 2 * (7 + 159 * 15))
        self.assertEqual(len(result), 4784)
        self.assertEqual(max(map(len, result)), WIDTH)
        self.assertEqual(result.count("0"), 1)
        self.assertEqual(result.count("f"), 1)

    def test_malformed_subclass_and_constructor_bypassed_intervals_reject(self):
        class IntervalSubclass(contract.KeyInterval):
            pass
        valid = interval(1, 2)
        incomplete = object.__new__(contract.KeyInterval)
        for supplied in (None, {}, (valid.lower, valid.upper),
                         IntervalSubclass(valid.lower, valid.upper), incomplete,
                         forged(valid, lower=True), forged(valid, lower="0" * 159),
                         forged(valid, lower="A" * 160), forged(valid, upper="0" * 160),
                         forged(valid, upper="f" * 161)):
            with self.subTest(kind=type(supplied)), self.assertRaises(contract.IndexRangeError):
                frontier.outside_prefixes(supplied)

    def test_positive_outside_nodes_and_inside_leaves_reconstruct_independent_root(self):
        tree = tree_oracle.IndependentIndex([tree_oracle.leaf(key(point))
            for point in (0, 1, 15, 16, TOP // 2, TOP - 1)])
        for bounds in (interval(1, 16), interval(0, TOP), interval(5, 5), interval(TOP - 1, TOP)):
            with self.subTest(bounds=bounds):
                outside = tuple(tree.opaque(prefix) for prefix in self.assert_cover(bounds)
                                if prefix in tree.nodes and tree.nodes[prefix][1] > 0)
                terminals = tuple(sorted((*outside, *tree.matches(bounds)),
                    key=lambda value: value.key if type(value) is contract.IndexLeaf else value.prefix))
                self.assertEqual(terminals, tree.frontier(bounds))
                result = ranges.reconstruct_complete_index_range(profile=tree.profile, expected_root=tree.root,
                    interval=bounds, frontier=terminals, limits=ranges.IndexRangeLimits())
                self.assertEqual(result.root, tree.root)
                self.assertEqual(result.leaves, tree.matches(bounds))
                self.assertEqual(values(result.metrics), tree_oracle.metric_oracle(tree.profile, tree.root, bounds, terminals))
                if terminals:
                    with self.assertRaisesRegex(contract.IndexRangeError, "reconstructed root"):
                        ranges.reconstruct_complete_index_range(profile=tree.profile, expected_root=tree.root,
                            interval=bounds, frontier=terminals[1:], limits=ranges.IndexRangeLimits())


class IndexReaderTests(unittest.TestCase):
    def setUp(self):
        self.rows = [
            {"id": "grant-雪", "approver_webauthn_credential_id": "credential-雪", "state": "active"},
            {"id": "grant-b", "approver_webauthn_credential_id": "credential-雪", "state": "active"},
            {"id": "outside", "approver_webauthn_credential_id": "other", "state": "active"},
            {"id": "inactive", "approver_webauthn_credential_id": "credential-雪", "state": "inactive"},
        ]
        self.store = IndependentStoredIndex(self.rows)

    def acquire(self, store=None, *, cursor=None, trace=None, **changes):
        store = self.store if store is None else store
        cursor = StoredIndexCursor(store) if cursor is None else cursor
        trace = RecordingTrace() if trace is None else trace
        arguments = {"query": store.query, "expected_root": store.tree.root,
                     "index_revision": store.revision, "trace": trace}
        arguments.update(changes)
        return reader.read_complete_frontier(cursor, **arguments)

    def assert_acquired(self, store, *, reverse_nodes=False):
        events = []
        cursor = StoredIndexCursor(store, reverse_nodes=reverse_nodes, events=events)
        trace = RecordingTrace(events)
        result = self.acquire(store, cursor=cursor, trace=trace)
        expected_frontier = store.tree.frontier(store.fixture.interval)
        prefixes = complement_oracle(store.fixture.interval)
        batches = tuple(prefixes[offset:offset + 256] for offset in range(0, len(prefixes), 256))
        self.assertEqual(result.query, store.query)
        self.assertEqual(result.index_revision, store.revision)
        self.assertEqual(result.root, store.tree.root)
        self.assertEqual(result.interval, store.fixture.interval)
        self.assertEqual(result.frontier, expected_frontier)
        self.assertEqual(result.primary_ids, store.primary_ids())
        expected_range = tree_oracle.metric_oracle(store.tree.profile, store.tree.root,
                                                  store.fixture.interval, expected_frontier)
        self.assertEqual(values(result.metrics.range_metrics), expected_range)
        expected_returned = [("leaf", store.leaves[value.key])
                             for value in store.tree.matches(store.fixture.interval)]
        expected_returned.extend(("node", store.nodes[(len(prefix), prefix)])
                                 for prefix in prefixes if (len(prefix), prefix) in store.nodes)
        expected_bytes = sum(scalar_bytes(kind, row) for kind, row in expected_returned)
        self.assertEqual(values(result.metrics), {
            "sql_reads": 1 + len(batches), "node_reads": len(batches),
            "requested_prefixes": len(prefixes), "returned_rows": len(expected_frontier),
            "transport_bytes": expected_bytes, "context_hashes": 4,
            "business_key_hashes": len(result.primary_ids), "range_metrics": result.metrics.range_metrics})
        self.assertEqual(result.metrics.hashes, 4 + len(result.primary_ids) + expected_range["hashes"])
        context = {"profile": "serverware.policyAuthorityCountedIndexRead/v1",
            "queryId": store.query.query_id, "indexId": store.tree.profile.index_id,
            "projectionDigest": store.tree.profile.projection_digest, "indexRevision": store.revision,
            "rootDigest": store.tree.root.digest, "rootCount": store.tree.root.count}
        self.assertEqual(trace.reads, [(LEAVES, {**context, "lower": result.interval.lower,
            "upper": result.interval.upper, "limit": store.query.maximum_rows + 1})] + [
            (NODES, {**context, "prefixes": [{"depth": len(prefix), "pathPrefix": prefix}
                                            for prefix in batch], "limit": len(batch) + 1})
            for batch in batches])
        expected_events = [("trace", LEAVES), ("execute", "leaf"), ("fetch", "leaf")]
        for _ in batches:
            expected_events.extend((("trace", NODES), ("execute", "node"), ("fetch", "node")))
        self.assertEqual(events, expected_events)
        self.assertEqual(len(cursor.calls), result.metrics.sql_reads)
        self.assertEqual(cursor.fetch_sizes, [store.query.maximum_rows + 1]
                         + [len(batch) + 1 for batch in batches])
        leaf_parameters = (store.query.index_id, result.interval.lower)
        if result.interval.upper is not None:
            leaf_parameters += (result.interval.upper,)
        self.assertEqual(cursor.calls[0][1], (*leaf_parameters, store.query.maximum_rows + 1))
        for (_, parameters), batch in zip(cursor.calls[1:], batches):
            self.assertEqual(parameters, (*(value for prefix in batch for value in (len(prefix), prefix)),
                                          store.query.index_id, len(batch) + 1))
        return result, cursor, trace

    def test_actual_reader_matches_independent_frontier_bytes_trace_and_fixed_sql_schedule(self):
        result, _, _ = self.assert_acquired(self.store)
        self.assertEqual((len(result.primary_ids), result.root.count), (2, 3))
        self.assertEqual((result.metrics.requested_prefixes, result.metrics.sql_reads), (960, 5))
        self.assertEqual((reader.MAX_NODE_IDENTITIES, reader.MAX_SQL_READS,
                          reader.MAX_TRANSPORT_BYTES), (256, 20, 4 * 1024 * 1024))
        # SQL-tail equality in the cursor is supplemental emitted-source
        # coverage: it is not PostgreSQL parsing or catalog-type evidence.

    def test_all_five_source_roles_use_independent_partitions_and_expiry_cutoff(self):
        for role, status in (("sessions_pending_webauthn", "pending_webauthn"),
                             ("sessions_active", "active")):
            with self.subTest(role=role):
                rows = [{"id": "session", "bound_webauthn_credential_id": "credential-雪", "status": status},
                        {"id": "elsewhere", "bound_webauthn_credential_id": "other", "status": status}]
                result, _, _ = self.assert_acquired(IndependentStoredIndex(rows, query=bound_query(role)))
                self.assertEqual([identifier for _, identifier in result.primary_ids], ["session"])
        for role, field, status in (("grants", "state", "active"), ("approvals", "status", "approved")):
            with self.subTest(role=role):
                rows = [{"id": role, "approver_webauthn_credential_id": "credential-雪", field: status},
                        {"id": "elsewhere", "approver_webauthn_credential_id": "other", field: status}]
                self.assert_acquired(IndependentStoredIndex(rows, query=bound_query(role)))
        rows = [{"id": name, "challenge_type": "registration", "used_at": None, "expires_at": expiry}
                for name, expiry in (("before", "1969-12-31T23:59:59+00:00"),
                                     ("equal", "1970-01-01T00:00:00+00:00"),
                                     ("after", "1970-01-01T00:00:00.000001+00:00"))]
        store = IndependentStoredIndex(rows, query=bound_query("global_registration_challenges"),
                                       expiry_us={"before": -1000000, "equal": 0, "after": 1})
        result, _, _ = self.assert_acquired(store)
        self.assertEqual([identifier for _, identifier in result.primary_ids], ["after"])

    def test_empty_revision_zero_and_populated_empty_interval_still_reconstruct_root(self):
        empty = IndependentStoredIndex([], revision=0)
        result, _, _ = self.assert_acquired(empty)
        self.assertEqual(result.frontier, ())
        self.assertEqual(result.metrics.range_metrics.hashes, 1)
        rows = [{"id": "retained", "challenge_type": "registration", "used_at": None,
                 "expires_at": "1970-01-01T00:00:00+00:00"}]
        store = IndependentStoredIndex(rows,
            query=bound_query("global_registration_challenges", cutoff_us=2**63 - 1),
            expiry_us={"retained": 0})
        result, _, _ = self.assert_acquired(store)
        self.assertEqual(result.primary_ids, ())
        self.assertEqual(result.root.count, 1)
        self.assertEqual((result.metrics.requested_prefixes, result.metrics.sql_reads), (16, 2))
        self.assertTrue(all(type(value) is contract.OpaqueSubtree and len(value.prefix) == 1
                            for value in result.frontier))
        missing = StoredIndexCursor(store, change=lambda kind, rows, params: [] if kind == "node" else rows)
        with self.assertRaisesRegex(contract.IndexRangeError, "reconstructed root"):
            self.acquire(store, cursor=missing)

    def test_source_maximum_thirty_two_accepts_exact_rows_and_rejects_real_overflow_sentinel(self):
        rows = [{"id": f"grant-{number:02d}", "approver_webauthn_credential_id": "credential-雪", "state": "active"}
                for number in range(32)]
        query = bound_query(maximum_rows=32)
        store = IndependentStoredIndex(rows, query=query)
        result, _, _ = self.assert_acquired(store)
        self.assertEqual(len(result.primary_ids), 32)
        overflow = IndependentStoredIndex(rows + [{**rows[0], "id": "overflow"}], query=query)
        cursor = StoredIndexCursor(overflow)
        with self.assertRaisesRegex(reader.IndexReadError, "SQL result exceeds its row bound"):
            self.acquire(overflow, cursor=cursor)
        self.assertEqual((len(cursor.calls), cursor.fetch_sizes), (1, [33]))
        self.assertEqual(len(cursor.returned[0][1]), 33)

    def test_leaf_order_is_strict_but_node_driver_order_does_not_change_canonical_output(self):
        # Select two independently hashed outside partitions whose maximal
        # prefixes occupy the same physical batch. Do not make reversal a
        # vacuous check over the default single outside member.
        prefixes = complement_oracle(self.store.fixture.interval)
        groups = {}
        chosen = None
        for number in range(256):
            binding = f"outside-binding-{number}"
            partition = join_oracle.partition(self.store.tree.profile, {"credential_record_id": binding})
            path = partition + "0" * 96
            address = next((offset for offset, prefix in enumerate(prefixes) if path.startswith(prefix)), None)
            if address is None:
                continue
            group = groups.setdefault(address // 256, {})
            group.setdefault(prefixes[address], {"id": f"outside-{number}",
                "approver_webauthn_credential_id": binding, "state": "active"})
            if len(group) == 2:
                chosen = list(group.values())
                break
        self.assertIsNotNone(chosen)
        store = IndependentStoredIndex(self.rows[:2] + chosen)
        normal, normal_cursor, _ = self.assert_acquired(store)
        reversed_nodes, reversed_cursor, _ = self.assert_acquired(store, reverse_nodes=True)
        self.assertTrue(any(kind == "node" and len(rows) >= 2 for kind, rows in normal_cursor.returned))
        self.assertNotEqual(normal_cursor.returned, reversed_cursor.returned)
        self.assertEqual(normal, reversed_nodes)
        cursor = StoredIndexCursor(self.store, change=lambda kind, rows, params:
                                   list(reversed(rows)) if kind == "leaf" else rows)
        with self.assertRaisesRegex(reader.IndexReadError, "ordered unique inside range"):
            self.acquire(cursor=cursor)
        self.assertEqual(len(cursor.calls), 1)

    def test_real_hash_calls_and_reconstruction_use_source_clamped_limits(self):
        # All independent hashes are prepared before observing the actual
        # production SHA implementation; neither function is replaced by success.
        expected = self.store.tree.frontier(self.store.fixture.interval)
        actual_sha256 = hashlib.sha256
        actual_reconstruct = reader.reconstruct_complete_index_range
        for _ in range(2):
            with mock.patch.object(hashlib, "sha256", wraps=actual_sha256) as hashes, \
                    mock.patch.object(reader, "reconstruct_complete_index_range", wraps=actual_reconstruct) as verify:
                result = self.acquire()
                self.assertEqual(hashes.call_count, result.metrics.hashes)
            self.assertEqual(result.frontier, expected)
            self.assertEqual(verify.call_count, 1)
            arguments = verify.call_args.kwargs
            self.assertEqual(arguments["expected_root"], self.store.tree.root)
            self.assertEqual(arguments["interval"], self.store.fixture.interval)
            self.assertEqual(values(arguments["limits"]), {"max_entries": 4803, "max_leaves": 3,
                "max_opened_nodes": 801, "max_hashes": 12819, "max_input_bytes": 4 * 1024 * 1024})

    def test_missing_or_false_stored_commitments_reach_real_root_reconstruction_and_fail(self):
        def corrupt(mode):
            changed = False
            def alter(kind, rows, parameters):
                nonlocal changed
                target = "leaf" if mode in ("missing-leaf", "row-digest") else "node"
                if kind != target or not rows or changed:
                    return rows
                changed = True
                if mode.startswith("missing"):
                    return rows[1:]
                if mode == "count":
                    rows[0]["subtree_count"] += 1
                else:
                    field = "primary_row_digest" if kind == "leaf" else "node_digest"
                    original = rows[0][field]
                    rows[0][field] = "sha256:" + ("1" if original[7] == "0" else "0") + original[8:]
                return rows
            return alter
        genuine = reader.reconstruct_complete_index_range
        for mode in ("missing-leaf", "missing-node", "row-digest", "node-digest", "count"):
            cursor = StoredIndexCursor(self.store, change=corrupt(mode))
            with self.subTest(mode=mode), \
                    mock.patch.object(reader, "reconstruct_complete_index_range", wraps=genuine) as verify:
                with self.assertRaisesRegex(contract.IndexRangeError, "reconstructed root or count"):
                    self.acquire(cursor=cursor)
                self.assertEqual(verify.call_count, 1)
                self.assertEqual(len(cursor.calls), 5)
        for false_root in (replace(self.store.tree.root, count=self.store.tree.root.count + 1),
                           contract.CountedNode("sha256:" + "0" * 64, self.store.tree.root.count)):
            with self.subTest(root=false_root), self.assertRaisesRegex(contract.IndexRangeError, "reconstructed root"):
                self.acquire(expected_root=false_root)

    def test_leaf_inside_range_uniqueness_and_primary_lookup_commitments_are_rechecked(self):
        outside = next(copy.deepcopy(row) for path, row in self.store.leaves.items()
                       if not self.store.fixture.interval.lower <= path < self.store.fixture.interval.upper)
        def alter(mode):
            def change(kind, rows, parameters):
                if kind != "leaf":
                    return rows
                if mode == "outside":
                    return [copy.deepcopy(outside)]
                if mode == "duplicate-key":
                    return rows + [copy.deepcopy(rows[0])]
                if mode == "duplicate-primary":
                    rows[1]["primary_key_digest"] = rows[0]["primary_key_digest"]
                elif mode == "wrong-id":
                    rows[0]["primary_id"] += "-changed"
                elif mode == "wrong-suffix":
                    rows[0]["primary_id"] += "-changed"
                    rows[0]["primary_key_digest"] = business_key(self.store.query.table, rows[0]["primary_id"])
                return rows
            return change
        for mode in ("outside", "duplicate-key", "duplicate-primary", "wrong-id", "wrong-suffix"):
            message = "BusinessKey commitment" if mode.startswith("wrong") else "ordered unique inside range"
            cursor = StoredIndexCursor(self.store, change=alter(mode))
            with self.subTest(mode=mode), self.assertRaisesRegex(reader.IndexReadError, message):
                self.acquire(cursor=cursor)
            self.assertEqual(len(cursor.calls), 1)

    def test_closed_driver_records_and_malformed_column_names_reject_before_reconstruction(self):
        class RowSubclass(dict):
            pass
        class NameSubclass(str):
            pass
        def broken(row, mode):
            if mode == "subclass":
                return RowSubclass(row)
            if mode == "tuple":
                return tuple(row.values())
            result = dict(row)
            if mode == "extra":
                result["extra"] = 0
            else:
                value = result.pop("projection_digest")
                if mode != "missing":
                    name = {"long-name": "x" * 33, "integer-name": 7,
                            "subclass-name": NameSubclass("projection_digest")}[mode]
                    result[name] = value
            return result
        for target in ("leaf", "node"):
            for mode in ("missing", "extra", "tuple", "subclass", "long-name", "integer-name", "subclass-name"):
                def change(kind, rows, parameters, target=target, mode=mode):
                    if kind == target and rows:
                        rows[0] = broken(rows[0], mode)
                    return rows
                cursor = StoredIndexCursor(self.store, change=change)
                with self.subTest(target=target, mode=mode), \
                        self.assertRaisesRegex(reader.IndexReadError, "closed database record"):
                    self.acquire(cursor=cursor)

    def test_case_null_scalar_types_profiles_and_revisions_cannot_be_filtered_to_success(self):
        # The deterministic driver injects the values a rejecting CASE can
        # return; actual PostgreSQL CASE typing is intentionally not executed.
        cases = [("index_id", "other-index"), ("projection_digest", "sha256:" + "0" * 64),
                 ("index_revision", 0), ("index_revision", 12), ("index_revision", True),
                 ("index_revision", "11"), ("index_revision", 2**63)]
        for target, names in (("leaf", LEAF_FIELDS), ("node", NODE_FIELDS)):
            controls = [(name, None) for name in names] + cases
            if target == "leaf":
                controls += [("index_key", "A" * 160), ("index_key", "a" * 161),
                             ("primary_row_digest", "SHA256:" + "a" * 64)]
            else:
                controls += [("depth", True), ("depth", 0), ("depth", 161),
                             ("subtree_count", True), ("subtree_count", 0),
                             ("subtree_count", 2**63), ("node_digest", "not-a-digest")]
            for field, value in controls:
                def change(kind, rows, parameters, target=target, field=field, value=value):
                    if kind == target and rows:
                        rows[0][field] = value
                    return rows
                with self.subTest(target=target, field=field, value=value), \
                        self.assertRaises(contract.IndexRangeError):
                    self.acquire(cursor=StoredIndexCursor(self.store, change=change))

    def test_node_identity_must_be_requested_exact_once_and_match_its_depth(self):
        for mode in ("duplicate", "wrong-depth", "inside-prefix"):
            def change(kind, rows, parameters, mode=mode):
                if kind != "node" or not rows:
                    return rows
                if mode == "duplicate":
                    return rows + [copy.deepcopy(rows[0])]
                if mode == "wrong-depth":
                    rows[0]["depth"] += 1
                else:
                    rows[0]["depth"] = 64
                    rows[0]["path_prefix"] = self.store.fixture.interval.lower[:64]
                return rows
            with self.subTest(mode=mode), self.assertRaisesRegex(reader.IndexReadError, "node identity"):
                self.acquire(cursor=StoredIndexCursor(self.store, change=change))

    def test_driver_collections_and_leaf_or_node_overflow_sentinels_are_bounded(self):
        class RowsSubclass(list):
            pass
        for target in ("leaf", "node"):
            for mode in ("tuple", "dict", "subclass", "overflow"):
                def change(kind, rows, parameters, target=target, mode=mode):
                    if kind != target:
                        return rows
                    if mode == "tuple":
                        return tuple(rows)
                    if mode == "dict":
                        return {}
                    if mode == "subclass":
                        return RowsSubclass(rows)
                    # Sentinel validation precedes per-row validation. An
                    # otherwise empty batch must not mask an oversized list.
                    return [None] * parameters[-1]
                cursor = StoredIndexCursor(self.store, change=change)
                with self.subTest(target=target, mode=mode), \
                        self.assertRaisesRegex(reader.IndexReadError, "SQL result exceeds its row bound"):
                    self.acquire(cursor=cursor)
                self.assertEqual(len(cursor.calls), 1 if target == "leaf" else 2)

    def test_revision_and_constructor_bypassed_contexts_reject_before_first_sql(self):
        class QuerySubclass(complete.CompleteIndexQuery):
            pass
        class RootSubclass(contract.CountedNode):
            pass
        query = self.store.query
        root = self.store.tree.root
        cases = [{"query": value} for value in (
            None, {}, object(), object.__new__(complete.CompleteIndexQuery),
            QuerySubclass(**values(query)), forged(query, maximum_rows=True),
            forged(query, maximum_rows=0), forged(query, maximum_rows=33),
            forged(query, role="not-a-source-role"), forged(query, selector_items={}))]
        cases += [{"expected_root": value} for value in (
            None, {}, object.__new__(contract.CountedNode), RootSubclass(root.digest, root.count),
            forged(root, count=True), forged(root, digest="not-a-digest"))]
        cases += [{"index_revision": value} for value in (True, -1, 0, 2**63, "11")]
        for changes in cases:
            cursor, trace = StoredIndexCursor(self.store), RecordingTrace()
            with self.subTest(changes=changes), \
                    self.assertRaises((complete.CompleteQueryError, contract.IndexRangeError)):
                self.acquire(cursor=cursor, trace=trace, **changes)
            self.assertEqual((cursor.calls, trace.reads), ([], []))
        for name, value in (("namespace", "other"), ("interval", self.store.fixture.interval),
                            ("limits", ranges.IndexRangeLimits()), ("profile", self.store.tree.profile)):
            cursor = StoredIndexCursor(self.store)
            with self.subTest(keyword=name), self.assertRaises(TypeError):
                self.acquire(cursor=cursor, **{name: value})
            self.assertEqual(cursor.calls, [])
        # Positive old revisions do not themselves make a stale hash: the
        # declared anchor may include unchanged nodes from earlier revisions.
        old = IndependentStoredIndex(self.rows)
        for row in (*old.leaves.values(), *old.nodes.values()):
            row["index_revision"] = 1
        result, _, _ = self.assert_acquired(old)
        self.assertEqual(result.index_revision, 11)
        self.assertEqual(self.acquire(old, index_revision=1).root, old.tree.root)

    def test_primary_lookup_id_utf8_bounds_are_exact_and_null_is_not_empty(self):
        for identifier in ("", "é" * 2048):
            with self.subTest(size=len(identifier.encode("utf-8"))):
                store = IndependentStoredIndex([{**self.rows[0], "id": identifier}])
                result, _, _ = self.assert_acquired(store)
                self.assertEqual(result.primary_ids, ((business_key(store.query.table, identifier), identifier),))
        for identifier in (None, True, "a" * 4097, "é" * 2048 + "x", "\x00", "\ud800"):
            def change(kind, rows, parameters, identifier=identifier):
                if kind == "leaf":
                    rows[0]["primary_id"] = identifier
                return rows
            cursor = StoredIndexCursor(self.store, change=change)
            with self.subTest(identifier_type=type(identifier)), self.assertRaises(reader.IndexReadError):
                self.acquire(cursor=cursor)
            self.assertEqual(len(cursor.calls), 1)

    def test_inputs_are_snapshotted_before_sql_and_result_is_detached_frozen_data(self):
        store = IndependentStoredIndex(self.rows)
        expected = self.acquire(store)
        changed = False
        def mutate_originals(kind, rows, parameters):
            nonlocal changed
            if not changed:
                changed = True
                # Controlled caller mutation, not a concurrency proof. All
                # actual stored-row results and verifier work stay unchanged.
                object.__setattr__(store.query, "maximum_rows", 32)
                object.__setattr__(store.query, "selector_items", (("credential_record_id", "changed"),))
                object.__setattr__(store.tree.root, "count", 999)
            return rows
        cursor = StoredIndexCursor(store, change=mutate_originals)
        result = self.acquire(store, cursor=cursor)
        self.assertTrue(changed)
        self.assertEqual(result, expected)
        self.assertIsNot(result.query, store.query)
        self.assertIsNot(result.root, store.tree.root)
        cursor.returned[0][1][0]["primary_id"] = "later-driver-change"
        next(iter(store.leaves.values()))["primary_row_digest"] = "later-store-change"
        self.assertEqual(result, expected)
        for value, name, replacement in ((result, "primary_ids", ()),
                (result.query, "maximum_rows", 1), (result.root, "count", 0),
                (result.interval, "lower", key(0)), (result.metrics, "sql_reads", 0),
                (result.metrics.range_metrics, "hashes", 0),
                (next(item for item in result.frontier if type(item) is contract.IndexLeaf), "key", key(0))):
            with self.subTest(type=type(value)), self.assertRaises(FrozenInstanceError):
                setattr(value, name, replacement)

    def test_trace_execute_and_fetch_failures_propagate_without_retry_or_partial_result(self):
        class DriverFailure(RuntimeError):
            pass
        failure = DriverFailure("deterministic local I/O failure")
        class FailedTrace(RecordingTrace):
            def read(self, table, key):
                super().read(table, key)
                raise failure
        class FailedExecute(StoredIndexCursor):
            def execute(self, statement, parameters):
                super().execute(statement, parameters)
                raise failure
        class FailedFetch(StoredIndexCursor):
            def fetchmany(self, size):
                super().fetchmany(size)
                raise failure
        for cursor_type, trace_type, expected_calls, expected_fetches in (
                (StoredIndexCursor, FailedTrace, 0, 0),
                (FailedExecute, RecordingTrace, 1, 0), (FailedFetch, RecordingTrace, 1, 1)):
            cursor, trace = cursor_type(self.store), trace_type()
            with self.subTest(cursor=cursor_type, trace=trace_type), self.assertRaises(DriverFailure) as caught:
                self.acquire(cursor=cursor, trace=trace)
            self.assertIs(caught.exception, failure)
            self.assertEqual((len(cursor.calls), len(cursor.fetch_sizes), len(trace.reads)),
                             (expected_calls, expected_fetches, 1))

    def test_private_read_and_scalar_budgets_deny_exact_next_unit_without_relaxed_limits(self):
        # These are direct accounting-component boundaries, not claims that a
        # current source selector needs twenty queries or can return4MiB.
        _, baseline_cursor, baseline_trace = self.assert_acquired(self.store)
        statement, parameters = baseline_cursor.calls[0]
        table, trace_key = baseline_trace.reads[0]
        cursor, trace = StoredIndexCursor(self.store), RecordingTrace()
        budget = reader._ReadBudget(cursor, trace)
        for _ in range(20):
            self.assertEqual(len(budget.read(table, trace_key, statement, parameters, 3)), 2)
        self.assertEqual((budget.sql_reads, budget.returned_rows), (20, 40))
        with self.assertRaisesRegex(reader.IndexReadError, "physical read bound"):
            budget.read(table, trace_key, statement, parameters, 3)
        self.assertEqual((len(cursor.calls), len(trace.reads)), (20, 20))
        row = copy.deepcopy(next(iter(self.store.leaves.values())))
        row["primary_id"] = ""
        row["primary_key_digest"] = business_key(self.store.query.table, "")
        row["index_key"] = row["index_key"][:-64] + row["primary_key_digest"][7:]
        record_bytes = scalar_bytes("leaf", row)
        maximum = 4 * 1024 * 1024
        repetitions = maximum // record_bytes - 1
        for _ in range(repetitions):
            budget.charge("leaf", row, LEAF_FIELDS)
        last = dict(row)
        extra = maximum - repetitions * record_bytes - record_bytes
        self.assertTrue(0 <= extra <= 4096)
        last["primary_id"] = "x" * extra
        last["primary_key_digest"] = business_key(self.store.query.table, last["primary_id"])
        last["index_key"] = last["index_key"][:-64] + last["primary_key_digest"][7:]
        self.assertEqual(scalar_bytes("leaf", last), maximum - budget.transport_bytes)
        budget.charge("leaf", last, LEAF_FIELDS)
        self.assertEqual(budget.transport_bytes, maximum)
        with self.assertRaisesRegex(reader.IndexReadError, "scalar bytes exceed"):
            budget.charge("leaf", row, LEAF_FIELDS)
        self.assertEqual(budget.transport_bytes, maximum)

    def test_emitted_projection_keeps_catalog_types_byte_caps_and_null_sentinels(self):
        _, cursor, _ = self.assert_acquired(self.store)
        def text_column(alias, name, lower, upper):
            field = f"{alias}.{name}"
            return (f"CASE WHEN pg_catalog.pg_typeof({field}) = 'pg_catalog.text'::pg_catalog.regtype "
                f"AND pg_catalog.octet_length({field}) BETWEEN {lower} AND {upper} "
                f"THEN {field} ELSE NULL END AS {name}")
        def integer_column(alias, name, lower, upper, kind="int8"):
            field = f"{alias}.{name}"
            return (f"CASE WHEN pg_catalog.pg_typeof({field}) = 'pg_catalog.{kind}'::pg_catalog.regtype "
                f"AND {field} BETWEEN {lower} AND {upper} "
                f"THEN {field}::pg_catalog.int8 ELSE NULL END AS {name}")
        expected_leaf = [text_column("leaf", name, low, high) for name, low, high in (
            ("index_id", 1, 128), ("projection_digest", 71, 71), ("index_key", 160, 160),
            ("primary_id", 0, 4096), ("primary_key_digest", 71, 71), ("primary_row_digest", 71, 71))]
        expected_leaf.append(integer_column("leaf", "index_revision", 1, 2**63 - 1))
        expected_node = [text_column("node", "index_id", 1, 128),
            text_column("node", "projection_digest", 71, 71),
            integer_column("node", "depth", 1, 160, "int4"),
            text_column("node", "path_prefix", 1, 160), text_column("node", "node_digest", 71, 71),
            integer_column("node", "subtree_count", 1, 2**63 - 1),
            integer_column("node", "index_revision", 1, 2**63 - 1)]
        self.assertEqual(cursor.calls[0][0].split(" FROM ", 1)[0], "SELECT " + ", ".join(expected_leaf))
        for statement, _ in cursor.calls[1:]:
            self.assertEqual(statement.split(" FROM ", 1)[0], "SELECT " + ", ".join(expected_node))
        # This pins emitted SQL source spelling; the responder does not parse
        # SQL or establish PostgreSQL CASE/type/collation/index behavior.

    def shared_acquire(self, store, work, acquisition, cursor, trace):
        return reader._read_complete_frontier(cursor, query=store.query,
            expected_root=store.tree.root, index_revision=store.revision,
            trace=trace, work=work, acquisition=acquisition)

    def test_shared_reader_independent_full_work_and_real_sha_preserve_public_observation(self):
        expected, acquisition_expected = reader_work_oracle(self.store)
        legacy = self.acquire()
        work = measured._ValidationWork(measured.QueryReadValidationLimits())
        cursor, trace = StoredIndexCursor(self.store), RecordingTrace()
        acquisition = reader._ReadAcquisitionBudget(cursor, trace, work=work)
        actual_sha = hashlib.sha256
        actual_range = ranges._reconstruct_complete_index_range
        with mock.patch.object(hashlib, "sha256", wraps=actual_sha) as hashes, \
                mock.patch.object(ranges, "_reconstruct_complete_index_range", wraps=actual_range) as fold:
            result = self.shared_acquire(self.store, work, acquisition, cursor, trace)
        self.assertEqual(result, legacy)
        self.assertEqual((work.hash_work, work.input_bytes, work.json_nodes), expected)
        self.assertEqual(hashes.call_count, expected[0])
        self.assertEqual(expected[0], result.metrics.hashes)
        self.assertEqual((acquisition.sql_reads, acquisition.parameter_bytes, acquisition.transport_bytes),
                         acquisition_expected)
        self.assertIs(fold.call_args.kwargs["work"], work)
        self.assertFalse(acquisition.active or acquisition.failed)

    def test_shared_reader_independent_exact_and_each_minus_one_work_quota(self):
        expected, _ = reader_work_oracle(self.store)
        for dimension in (None, 0, 1, 2):
            limits = list(expected)
            if dimension is not None:
                limits[dimension] -= 1
            work = measured._ValidationWork(measured.QueryReadValidationLimits(*limits))
            cursor, trace = StoredIndexCursor(self.store), RecordingTrace()
            acquisition = reader._ReadAcquisitionBudget(cursor, trace, work=work)
            if dimension is None:
                self.assertEqual(self.shared_acquire(self.store, work, acquisition, cursor, trace).root,
                                 self.store.tree.root)
            else:
                with self.subTest(dimension=dimension), self.assertRaises(measured.QueryReadWorkError):
                    self.shared_acquire(self.store, work, acquisition, cursor, trace)
                self.assertTrue(acquisition.failed)
                before = len(cursor.calls)
                with self.assertRaises(reader.IndexReadError):
                    self.shared_acquire(self.store, work, acquisition, cursor, trace)
                self.assertEqual(len(cursor.calls), before)

    def test_shared_reader_prior_work_and_two_real_calls_are_cumulative_without_metric_leakage(self):
        expected, sql_expected = reader_work_oracle(self.store)
        prior = (7, 101, 13)
        limits = tuple(before + 2 * delta for before, delta in zip(prior, expected))
        work = measured._ValidationWork(measured.QueryReadValidationLimits(*limits))
        work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
        cursor, trace = StoredIndexCursor(self.store), RecordingTrace()
        acquisition = reader._ReadAcquisitionBudget(cursor, trace, work=work,
            limits=reader._ReadAcquisitionLimits(*(2 * value for value in sql_expected)))
        first = self.shared_acquire(self.store, work, acquisition, cursor, trace)
        second = self.shared_acquire(self.store, work, acquisition, cursor, trace)
        self.assertEqual(first, second)
        self.assertEqual((work.hash_work, work.input_bytes, work.json_nodes), limits)
        self.assertEqual((acquisition.sql_reads, acquisition.parameter_bytes, acquisition.transport_bytes),
                         tuple(2 * value for value in sql_expected))

    def test_five_actual_roles_reuse_one_work_cursor_trace_and_acquisition_without_new_allowances(self):
        stores = [IndependentStoredIndex([], query=bound_query(role), revision=0) for role in complete.ROLES]
        expected = [reader_work_oracle(store) for store in stores]
        work = measured._ValidationWork(measured.QueryReadValidationLimits())
        cursor, trace = StoredIndexCursor(stores[0]), RecordingTrace()
        acquisition = reader._ReadAcquisitionBudget(cursor, trace, work=work)
        with mock.patch.object(measured._ValidationWork, "__init__",
                               side_effect=AssertionError("replacement work allowance")):
            for store in stores:
                cursor.store = store
                result = self.shared_acquire(store, work, acquisition, cursor, trace)
                self.assertEqual(result.frontier, ())
                self.assertEqual(result.metrics.range_metrics.hashes, 1)
        self.assertEqual((work.hash_work, work.input_bytes, work.json_nodes),
                         tuple(sum(value[0][index] for value in expected) for index in range(3)))
        self.assertEqual((acquisition.sql_reads, acquisition.parameter_bytes, acquisition.transport_bytes),
                         tuple(sum(value[1][index] for value in expected) for index in range(3)))
        self.assertEqual(work.hash_work, 25)

    def test_cumulative_physical_parameter_and_transport_caps_reject_without_fresh_role_budget(self):
        _, expected = reader_work_oracle(self.store)
        for dimension in (0, 1, 2):
            limits = list(expected)
            limits[dimension] -= 1
            work = measured._ValidationWork(measured.QueryReadValidationLimits())
            cursor, trace = StoredIndexCursor(self.store), RecordingTrace()
            acquisition = reader._ReadAcquisitionBudget(cursor, trace, work=work,
                limits=reader._ReadAcquisitionLimits(*limits))
            with self.subTest(dimension=dimension), self.assertRaises(reader.IndexReadError):
                self.shared_acquire(self.store, work, acquisition, cursor, trace)
            self.assertTrue(acquisition.failed)
            if dimension == 0:
                self.assertEqual(len(cursor.calls), limits[0])
        work = measured._ValidationWork(measured.QueryReadValidationLimits())
        cursor, trace = StoredIndexCursor(self.store), RecordingTrace()
        acquisition = reader._ReadAcquisitionBudget(cursor, trace, work=work,
            limits=reader._ReadAcquisitionLimits(max_parameter_bytes=1))
        with self.assertRaises(reader.IndexReadError):
            self.shared_acquire(self.store, work, acquisition, cursor, trace)
        self.assertEqual((cursor.calls, trace.reads), ([], []))

    def test_caught_nested_reader_poison_is_checked_before_sql_and_never_returns_success(self):
        work = measured._ValidationWork(measured.QueryReadValidationLimits())
        cursor, trace = StoredIndexCursor(self.store), RecordingTrace()
        acquisition = reader._ReadAcquisitionBudget(cursor, trace, work=work)
        original_read = trace.read
        nested_failures = []
        def nested(table, key):
            original_read(table, key)
            try:
                self.shared_acquire(self.store, work, acquisition, cursor, trace)
            except reader.IndexReadError as exc:
                nested_failures.append(exc)
        with mock.patch.object(trace, "read", side_effect=nested):
            with self.assertRaisesRegex(reader.IndexReadError, "poisoned"):
                self.shared_acquire(self.store, work, acquisition, cursor, trace)
        self.assertEqual(len(nested_failures), 1)
        self.assertEqual(cursor.calls, [])
        self.assertTrue(acquisition.failed)
        # The physical-read method also rejects a callback that bypasses the
        # component entrypoint and attempts to reenter that very same read.
        work = measured._ValidationWork(measured.QueryReadValidationLimits())
        cursor, trace = StoredIndexCursor(self.store), RecordingTrace()
        acquisition = reader._ReadAcquisitionBudget(cursor, trace, work=work)
        def direct_nested(table, key):
            try:
                acquisition.read(table, key, "never executed", (), 1)
            except reader.IndexReadError:
                pass
        with mock.patch.object(trace, "read", side_effect=direct_nested):
            with self.assertRaises(reader.IndexReadError):
                self.shared_acquire(self.store, work, acquisition, cursor, trace)
        self.assertEqual(cursor.calls, [])
        self.assertTrue(acquisition.failed)

    def test_shared_context_exact_identity_and_limits_cannot_be_replaced_or_reset(self):
        class ForeignWork(measured._ValidationWork):
            pass
        with self.assertRaises(reader.IndexReadError):
            reader._ReadAcquisitionBudget(object(), object(),
                work=ForeignWork(measured.QueryReadValidationLimits()))
        for limits in (object(), object.__new__(reader._ReadAcquisitionLimits)):
            with self.assertRaises(reader.IndexReadError):
                reader._ReadAcquisitionBudget(object(), object(),
                    work=measured._ValidationWork(measured.QueryReadValidationLimits()), limits=limits)
        for field, maximum in (("max_sql_reads", 4096), ("max_parameter_bytes", 4194304),
                               ("max_transport_bytes", 4194304)):
            for value in (True, 0, -1, maximum + 1):
                with self.assertRaises(reader.IndexReadError):
                    reader._ReadAcquisitionLimits(**{field: value})
        for changed in ("cursor", "trace", "work"):
            work = measured._ValidationWork(measured.QueryReadValidationLimits())
            cursor, trace = StoredIndexCursor(self.store), RecordingTrace()
            acquisition = reader._ReadAcquisitionBudget(cursor, trace, work=work)
            actual = {"cursor": cursor, "trace": trace, "work": work}
            actual[changed] = (measured._ValidationWork(measured.QueryReadValidationLimits())
                               if changed == "work" else object())
            with self.assertRaises(reader.IndexReadError):
                self.shared_acquire(self.store, actual["work"], acquisition,
                                    actual["cursor"], actual["trace"])
            self.assertTrue(acquisition.failed)
            self.assertEqual(cursor.calls, [])

    def test_shared_root_is_owned_before_first_real_profile_hash_and_public_route_stays_none(self):
        store = IndependentStoredIndex(self.rows)
        expected_root = store.tree.root
        root_copy = contract.CountedNode(expected_root.digest, expected_root.count)
        work = measured._ValidationWork(measured.QueryReadValidationLimits())
        cursor, trace = StoredIndexCursor(store), RecordingTrace()
        acquisition = reader._ReadAcquisitionBudget(cursor, trace, work=work)
        actual_sha = hashlib.sha256
        called = False
        def mutate(*args, **kwargs):
            nonlocal called
            if not called:
                called = True
                object.__setattr__(root_copy, "count", root_copy.count + 1)
            return actual_sha(*args, **kwargs)
        with mock.patch.object(hashlib, "sha256", side_effect=mutate):
            result = reader._read_complete_frontier(cursor, query=store.query,
                expected_root=root_copy, index_revision=store.revision,
                trace=trace, work=work, acquisition=acquisition)
        self.assertTrue(called)
        self.assertEqual(result.root, expected_root)
        actual = reader._read_complete_frontier
        with mock.patch.object(reader, "_read_complete_frontier", wraps=actual) as worker:
            self.acquire()
        self.assertEqual(worker.call_count, 1)
        self.assertIsNone(worker.call_args.kwargs["work"])
        self.assertIsNone(worker.call_args.kwargs["acquisition"])

    def test_primary_row_frame_reuses_preencoded_bytes_and_cumulative_transport_without_parsing(self):
        raw = {"id": "full-row", "payload": "x" * 8192}
        encoded = json.dumps(raw, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
        work = measured._ValidationWork(measured.QueryReadValidationLimits())
        cursor, trace = object(), object()
        acquisition = reader._ReadAcquisitionBudget(cursor, trace, work=work,
            limits=reader._ReadAcquisitionLimits(max_transport_bytes=8 + len(encoded)))
        with acquisition.scope(cursor, trace, work):
            wire = work.wire(raw)
            before = work.metrics
            with mock.patch.object(json, "loads", side_effect=AssertionError("unexpected decoder")), \
                    mock.patch.object(json, "dumps", side_effect=AssertionError("unexpected re-encoder")):
                acquisition.charge_primary_row(wire)
            self.assertEqual(work.input_bytes - before.input_bytes, 8 + len(encoded))
            self.assertEqual((work.hash_work, work.json_nodes), (before.hash_work, before.json_nodes))
        self.assertEqual(acquisition.transport_bytes, 8 + len(encoded))
        with self.assertRaises(reader.IndexReadError):
            with acquisition.scope(cursor, trace, work):
                acquisition.charge_primary_row(b"{}")
        self.assertTrue(acquisition.failed)
        for wire in (bytearray(b"{}"), "{}", b"x" * (1024 * 1024 + 1)):
            work = measured._ValidationWork(measured.QueryReadValidationLimits())
            acquisition = reader._ReadAcquisitionBudget(cursor, trace, work=work)
            with self.assertRaises(reader.IndexReadError):
                with acquisition.scope(cursor, trace, work):
                    acquisition.charge_primary_row(wire)
            self.assertEqual(acquisition.transport_bytes, 0)
        self.assertEqual(reader.MAX_PRIMARY_ROW_BYTES, 1024 * 1024)
        work = measured._ValidationWork(measured.QueryReadValidationLimits())
        acquisition = reader._ReadAcquisitionBudget(cursor, trace, work=work)
        with self.assertRaisesRegex(reader.IndexReadError, "poisoned"):
            with acquisition.scope(cursor, trace, work):
                try:
                    acquisition.charge_primary_row("not bytes")
                except reader.IndexReadError:
                    pass
        self.assertTrue(acquisition.failed)


if __name__ == "__main__":
    unittest.main()
