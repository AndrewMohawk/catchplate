#!/usr/bin/env python3
"""Pure inventory components against independently built small radix trees.

These tests supply roots; they do not authenticate a database, root revision,
currentness, schema, delivery receipt or initializer permission. Complete
leaf-only reconstruction additionally checks cardinality against the supplied
tree digest; direct summary construction is not that verification.
No registry replacement, database, signer or clock is used. Capacity boundary
tests validate the compact summary, not a 100,000-proof load or native SQL.
"""
from __future__ import annotations

import copy
import hashlib
import json
import sys
import unittest
from dataclasses import FrozenInstanceError, replace
from decimal import Decimal
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_contract
from serverware.authority_audit_inventory import (
    AuditInventoryError,
    AuditInventoryObservation,
    _InventoryRootFrontier,
    verify_audit_inventory,
)
from serverware.authority_radix_mutation import PrimaryRadixMutationError, PrimaryRoot


TABLE = "metadata_audit_outbox"
SCHEMA = "serverware.metadataAuditOutboxInventoryObservation/v2"
PROOF_SCHEMA = "serverware.policyAuthorityRadixMultiproof/v3"
MAX_INTEGER = 2**63 - 1
MIN_INTEGER = -(2**63)


def sql_json(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False,
        sort_keys=True, separators=(",", ":")).encode("utf-8")


def wire_json(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
        sort_keys=True, separators=(",", ":")).encode("ascii")


def sql_digest(domain, *frames):
    encoded = domain.encode("ascii")
    digest = hashlib.sha256(len(encoded).to_bytes(8, "big") + encoded)
    for frame in frames:
        digest.update(len(frame).to_bytes(8, "big"))
        digest.update(frame)
    return "sha256:" + digest.hexdigest()


def wire_digest(domain, *frames):
    digest = hashlib.sha256(domain.encode("ascii") + b"\0")
    for frame in frames:
        digest.update(len(frame).to_bytes(8, "big"))
        digest.update(frame)
    return "sha256:" + digest.hexdigest()


def tree_key(identifier):
    return sql_digest("serverware.policyAuthorityAuthenticatedKey/v1",
        TABLE.encode("ascii"), sql_json({"id": identifier}))


def refresh_proof(proof):
    proof["proofDigest"] = wire_digest(PROOF_SCHEMA,
        wire_json({key: value for key, value in proof.items() if key != "proofDigest"}))


def outbox_row(identifier="one", status="pending", **changes):
    # Exact 15-column persisted DDL image. event_digest is well-spelled, but
    # this fixture makes no claim of event-body or receipt authentication.
    event = wire_json({"id": identifier, "event": "inventory.component"})
    return {
        "id": identifier, "event_type": "inventory.component", "actor_type": "admin",
        "actor_id": None, "event_json": event.decode("ascii"),
        "event_digest": "sha256:" + hashlib.sha256(event).hexdigest(),
        "storage_format_version": None, "status": status, "claim_id": None,
        "claimed_at": None, "attempts": 0, "audited_at": None,
        "audit_event_hash": None, "last_error": None,
        "created_at": "2026-01-02T03:04:05+00:00", **changes,
    }


class InventoryTree:
    """Independent SQL-framed radix16 tree; no production hash helpers."""

    def __init__(self, rows, *, revision=None):
        self.rows = {sql_json({"id": row["id"]}): copy.deepcopy(row) for row in rows}
        if len(self.rows) != len(rows):
            raise AssertionError("duplicate fixture row")
        self.empty = {64: sql_digest("serverware.policyAuthorityAuthenticatedEmptyLeaf/v1", b"64")}
        for depth in range(63, -1, -1):
            self.empty[depth] = sql_digest("serverware.policyAuthorityAuthenticatedNode/v1",
                str(depth).encode("ascii"), sql_json([self.empty[depth + 1]] * 16))
        self.nodes, self.leaves = {}, {}
        for key_bytes, row in self.rows.items():
            address = tree_key(row["id"])
            row_digest = sql_digest("serverware.policyAuthorityAuthenticatedRow/v1",
                TABLE.encode("ascii"), sql_json(row))
            leaf = sql_digest("serverware.policyAuthorityAuthenticatedLeaf/v1",
                TABLE.encode("ascii"), address.encode("ascii"), key_bytes, row_digest.encode("ascii"))
            self.leaves[address] = (row_digest, leaf)
            self.nodes[(64, address[7:])] = leaf
        for depth in range(63, -1, -1):
            prefixes = {prefix[:depth] for node_depth, prefix in self.nodes if node_depth == depth + 1}
            for prefix in prefixes:
                children = [self.nodes.get((depth + 1, prefix + format(index, "x")), self.empty[depth + 1])
                    for index in range(16)]
                self.nodes[(depth, prefix)] = sql_digest("serverware.policyAuthorityAuthenticatedNode/v1",
                    str(depth).encode("ascii"), sql_json(children))
        self.root = PrimaryRoot(TABLE, len(rows) if revision is None else revision,
            self.nodes.get((0, ""), self.empty[0]), len(rows))

    def record(self, identifier):
        key = {"id": identifier}
        row = self.rows.get(sql_json(key))
        selected = {"table": TABLE, "key": key,
            "keyDigest": wire_digest("serverware.policyAuthorityBusinessKey/v1",
                TABLE.encode("ascii"), wire_json(key)),
            "present": row is not None, "row": copy.deepcopy(row), "contractSelector": None}
        address, path = tree_key(identifier), tree_key(identifier)[7:]
        row_digest, leaf = self.leaves.get(address, (None, self.empty[64]))
        proof = {"schema": PROOF_SCHEMA, "table": TABLE, "key": copy.deepcopy(key),
            "keyDigest": selected["keyDigest"], "present": selected["present"],
            "rowDigest": row_digest, "leafDigest": leaf, "rootRevision": self.root.root_revision,
            "rootDigest": self.root.root_digest,
            "siblings": [{"depth": depth, "pathPrefix": path[:depth], "selectedNibble": path[depth],
                "childDigests": [self.nodes.get((depth + 1, path[:depth] + format(index, "x")),
                    self.empty[depth + 1]) for index in range(16)]} for depth in range(64)]}
        refresh_proof(proof)
        return {"selectedRow": selected, "proof": proof}

    def records(self):
        return [self.record(row["id"]) for row in sorted(self.rows.values(), key=lambda row: tree_key(row["id"]))]


def independent_sparse_root(leaf_by_path):
    """Small arbitrary-leaf component oracle, never an admitted inventory."""
    empty = InventoryTree([]).empty
    nodes = {(64, path): digest for path, digest in leaf_by_path.items()}
    for depth in range(63, -1, -1):
        prefixes = {path[:depth] for node_depth, path in nodes if node_depth == depth + 1}
        for prefix in prefixes:
            children = [nodes.get((depth + 1, prefix + format(index, "x")), empty[depth + 1])
                        for index in range(16)]
            nodes[(depth, prefix)] = sql_digest("serverware.policyAuthorityAuthenticatedNode/v1",
                str(depth).encode("ascii"), sql_json(children))
    return nodes.get((0, ""), empty[0])


class AuditInventoryTests(unittest.TestCase):
    def setUp(self):
        self.tree = InventoryTree([outbox_row("one"), outbox_row("two", "claimed"),
            outbox_row("three", "audited")], revision=17)
        self.records = self.tree.records()

    def test_empty_genesis_and_empty_after_history(self):
        for revision in (0, 29):
            with self.subTest(revision=revision):
                tree = InventoryTree([], revision=revision)
                result = verify_audit_inventory(root=tree.root, records=iter(()))
                self.assertEqual(result.root, tree.root)
                self.assertEqual((result.pending_count, result.claimed_count, result.audited_count,
                    result.outstanding_count), (0, 0, 0, 0))
                self.assertEqual(result.root.root_digest, tree.empty[0])

    def test_mixed_full_population_and_independent_observation_hash(self):
        result = verify_audit_inventory(root=self.tree.root, records=self.records)
        expected = {"schema": SCHEMA, "sourceRevision": authority_contract.SOURCE_REVISION,
            "root": {"table": TABLE, "rootRevision": 17, "rootDigest": self.tree.nodes[(0, "")], "leafCount": 3},
            "pendingCount": 1, "claimedCount": 1, "auditedCount": 1, "outstandingCount": 2}
        self.assertEqual(result.json_projection(), expected)
        self.assertEqual(result.digest, wire_digest(SCHEMA, wire_json(expected)))
        self.assertNotEqual(result.digest, sql_digest(SCHEMA, wire_json(expected)))
        previous = {**expected, "schema": "serverware.metadataAuditOutboxInventoryObservation/v1"}
        self.assertNotEqual(result.digest, wire_digest(previous["schema"], wire_json(previous)))

    def test_historical_text_ids_nullable_columns_and_signed_bigints_remain_valid(self):
        rows = [outbox_row("", attempts=MIN_INTEGER),
            outbox_row("é雪😀", "claimed", storage_format_version=MIN_INTEGER,
                actor_id="历史", claim_id="", claimed_at="not-a-clock-assertion"),
            outbox_row("x" * 257, "audited", attempts=MAX_INTEGER,
                storage_format_version=MAX_INTEGER, audited_at="", audit_event_hash="not-a-verified-receipt",
                last_error="quoted \" / backslash \\ newline\n")]
        tree = InventoryTree(rows)
        result = verify_audit_inventory(root=tree.root, records=tree.records())
        self.assertEqual((result.pending_count, result.claimed_count, result.audited_count), (1, 1, 1))

    def test_order_is_authenticated_key_not_id_or_business_digest(self):
        # Fixed, tiny corpus; neither sorting mode can stand in for tree order.
        tree = InventoryTree([outbox_row(f"order-{index:02}") for index in range(16)])
        records = tree.records()
        verify_audit_inventory(root=tree.root, records=records)
        by_id = sorted(records, key=lambda record: record["selectedRow"]["key"]["id"])
        by_business = sorted(records, key=lambda record: record["selectedRow"]["keyDigest"])
        self.assertNotEqual(by_id, records)
        self.assertNotEqual(by_business, records)
        for wrong in (by_id, by_business):
            with self.assertRaises(AuditInventoryError):
                verify_audit_inventory(root=tree.root, records=wrong)

    def test_real_authenticated_keys_with_shared_prefix_reconstruct_the_full_population(self):
        # A fixed bounded corpus guarantees a two-nibble bucket collision.
        # Only the selected pair gets row proofs; no hash hook is substituted.
        buckets = {}
        pair = None
        for index in range(257):
            identifier = f"inventory-close-prefix-{index:03}"
            prefix = tree_key(identifier)[7:9]
            if prefix in buckets:
                pair = (buckets[prefix], identifier)
                break
            buckets[prefix] = identifier
        self.assertIsNotNone(pair)
        left, right = pair
        self.assertEqual(tree_key(left)[7:9], tree_key(right)[7:9])
        self.assertNotEqual(tree_key(left), tree_key(right))
        tree = InventoryTree([outbox_row(left), outbox_row(right, "claimed")], revision=31)
        records = tree.records()
        before = copy.deepcopy(records)
        result = verify_audit_inventory(root=tree.root, records=records)
        self.assertEqual(result.root.root_digest, tree.nodes[(0, "")])
        self.assertEqual((result.pending_count, result.claimed_count, result.audited_count), (1, 1, 0))
        self.assertEqual(records, before)

    def test_omitted_duplicate_reordered_and_extra_members_fail(self):
        for records in ([], self.records[:-1], [self.records[0], self.records[0], self.records[2]],
                list(reversed(self.records)), [*self.records, self.records[0]]):
            with self.subTest(length=len(records)), self.assertRaises(AuditInventoryError):
                verify_audit_inventory(root=self.tree.root, records=records)

    def test_understated_count_and_proved_prefix_suffix_or_interior_cannot_hide_population(self):
        baseline = verify_audit_inventory(root=self.tree.root, records=self.records)
        self.assertEqual(baseline.root.root_digest, self.tree.nodes[(0, "")])
        # All supplied members retain genuine proofs against the FULL tree,
        # including valid opaque siblings for the omitted members. Those
        # siblings cannot populate the separately reconstructed inventory.
        for name, subset in (
            ("prefix-one", self.records[:1]),
            ("prefix-two", self.records[:2]),
            ("suffix-one", self.records[-1:]),
            ("suffix-two", self.records[-2:]),
            ("interior", self.records[1:2]),
            ("omitted-interior", [self.records[0], self.records[2]]),
        ):
            with self.subTest(subset=name):
                before = copy.deepcopy(subset)
                exhausted = []

                def stream():
                    yield from subset
                    exhausted.append(True)

                understated = replace(self.tree.root, leaf_count=len(subset))
                with self.assertRaisesRegex(AuditInventoryError,
                        "^audit inventory reconstructed root differs from the supplied root$"):
                    verify_audit_inventory(root=understated, records=stream())
                self.assertEqual(exhausted, [True])
                self.assertEqual(subset, before)

    def test_full_population_wrong_descriptor_count_still_rejects_before_root_comparison(self):
        # A zero count with this nonempty digest fails at descriptor creation,
        # not at the later inventory reconstruction comparison.
        with self.assertRaisesRegex(PrimaryRadixMutationError, "^root emptiness and leaf count disagree$"):
            replace(self.tree.root, leaf_count=0)
        for count, message in (
            (2, "audit inventory contains extra members"),
            (4, "audit inventory omits members from its supplied descriptor"),
        ):
            with self.subTest(count=count), self.assertRaisesRegex(AuditInventoryError, "^" + message + "$"):
                verify_audit_inventory(root=replace(self.tree.root, leaf_count=count), records=self.records)

    def test_supplied_root_table_hash_revision_and_count_are_exact_bindings(self):
        for root in (replace(self.tree.root, table="other_table"),
                replace(self.tree.root, root_digest="sha256:" + "a" * 64),
                replace(self.tree.root, root_revision=18),
                replace(self.tree.root, leaf_count=2), replace(self.tree.root, leaf_count=4),
                self.tree.root.json_projection(), None):
            with self.subTest(root=root), self.assertRaises(AuditInventoryError):
                verify_audit_inventory(root=root, records=self.records)

    def test_changed_selected_status_or_full_row_does_not_reuse_old_proof(self):
        for field, value in (("status", "audited"), ("event_json", "{}"),
                ("attempts", 1), ("actor_id", "different")):
            records = copy.deepcopy(self.records)
            row = records[0]["selectedRow"]["row"]
            if field == "status":
                value = "claimed" if row[field] != "claimed" else "pending"
            row[field] = value
            with self.subTest(field=field), self.assertRaises(AuditInventoryError):
                verify_audit_inventory(root=self.tree.root, records=records)

    def test_proof_self_digest_and_all_membership_bindings_reject_substitution(self):
        for field, value, refresh in (("proofDigest", "sha256:" + "b" * 64, False),
                ("rootDigest", "sha256:" + "b" * 64, True), ("rootRevision", 18, True),
                ("rowDigest", "sha256:" + "b" * 64, True),
                ("leafDigest", "sha256:" + "b" * 64, True),
                ("keyDigest", "sha256:" + "b" * 64, True), ("present", False, True),
                ("schema", "serverware.policyAuthorityRadixMultiproof/v2", True)):
            records = copy.deepcopy(self.records)
            records[0]["proof"][field] = value
            if refresh:
                refresh_proof(records[0]["proof"])
            with self.subTest(field=field), self.assertRaises(AuditInventoryError):
                verify_audit_inventory(root=self.tree.root, records=records)

    def test_changed_path_and_child_vector_fail_even_with_refreshed_proof_digest(self):
        for field, value in (("depth", 1), ("pathPrefix", "0"), ("selectedNibble", "z"),
                ("childDigests", ["sha256:" + "b" * 64] * 16), ("childDigests", [])):
            records = copy.deepcopy(self.records)
            records[0]["proof"]["siblings"][0][field] = value
            refresh_proof(records[0]["proof"])
            with self.subTest(field=field, value=value), self.assertRaises(AuditInventoryError):
                verify_audit_inventory(root=self.tree.root, records=records)

    def test_absence_nonnull_selector_and_crossed_selected_key_are_not_inventory_members(self):
        cases = [self.tree.record("missing")]
        for field, value in (("contractSelector", "caller-selector"), ("present", 1),
                ("table", "other_table"), ("key", {"id": "crossed"}),
                ("keyDigest", "sha256:" + "c" * 64)):
            record = copy.deepcopy(self.records[0])
            record["selectedRow"][field] = value
            cases.append(record)
        for record in cases:
            with self.assertRaises(AuditInventoryError):
                verify_audit_inventory(root=self.tree.root, records=[record, *self.records[1:]])

    def test_record_selected_and_row_fields_are_closed(self):
        for path in ((), ("selectedRow",), ("selectedRow", "row")):
            for extra in (False, True):
                records = copy.deepcopy(self.records)
                target = records[0]
                for field in path:
                    target = target[field]
                if extra:
                    target["unexpected"] = None
                else:
                    target.pop(next(iter(target)))
                with self.subTest(path=path, extra=extra), self.assertRaises(AuditInventoryError):
                    verify_audit_inventory(root=self.tree.root, records=records)

    def test_proved_malformed_sql_rows_are_rejected_before_counting(self):
        for changes in ({"id": 1}, {"id": True}, {"id": None}, {"event_type": None},
                {"actor_type": False}, {"actor_id": 1}, {"event_json": {}},
                {"created_at": None}, {"claim_id": []}, {"status": "unknown"},
                {"attempts": True}, {"attempts": 1.0}, {"attempts": MAX_INTEGER + 1},
                {"attempts": MIN_INTEGER - 1}, {"storage_format_version": True},
                {"storage_format_version": 2.0}, {"storage_format_version": MAX_INTEGER + 1},
                {"event_digest": "sha256:" + "g" * 64}):
            tree = InventoryTree([outbox_row(**changes)])
            with self.subTest(changes=changes), self.assertRaises(AuditInventoryError):
                verify_audit_inventory(root=tree.root, records=tree.records())

    def test_nonlossless_nul_surrogate_mutable_and_decimal_payloads_reject(self):
        for value in ("nul\0text", "\ud800", "\udfff", bytearray(b"bytes"),
                Decimal("1"), 1.25, float("nan"), float("inf")):
            records = copy.deepcopy(self.records)
            records[0]["selectedRow"]["row"]["last_error"] = value
            with self.subTest(kind=type(value).__name__), self.assertRaises(AuditInventoryError):
                verify_audit_inventory(root=self.tree.root, records=records)
        record = copy.deepcopy(self.records[0])
        record["proof"]["extra"] = []
        nested = record["proof"]["extra"]
        for _ in range(130):
            child = []
            nested.append(child)
            nested = child
        with self.assertRaises(AuditInventoryError):
            verify_audit_inventory(root=self.tree.root, records=[record])

    def test_input_graphs_unchanged_and_projection_is_fresh_and_frozen(self):
        before = copy.deepcopy(self.records)
        result = verify_audit_inventory(root=self.tree.root, records=self.records)
        self.assertEqual(self.records, before)
        self.assertIsNot(result.root, self.tree.root)
        projection = result.json_projection()
        projection["root"]["leafCount"] = 0
        projection["pendingCount"] = 900
        self.assertEqual(result.json_projection()["root"]["leafCount"], 3)
        self.assertEqual(result.pending_count, 1)
        with self.assertRaises(FrozenInstanceError):
            result.pending_count = 0
        with self.assertRaises(FrozenInstanceError):
            result.root.leaf_count = 0

    def test_stream_is_not_materialized_and_each_record_is_consumed_once(self):
        records = self.records

        class Stream:
            def __init__(self):
                self.position = 0
                self.next_calls = 0

            def __iter__(self):
                return self

            def __len__(self):
                raise AssertionError("must not size/materialize stream")

            def __length_hint__(self):
                raise AssertionError("must not size/materialize stream")

            def __next__(self):
                self.next_calls += 1
                if self.position == len(records):
                    raise StopIteration
                record = records[self.position]
                self.position += 1
                return record

        stream = Stream()
        result = verify_audit_inventory(root=self.tree.root, records=stream)
        self.assertEqual(result.outstanding_count, 2)
        self.assertEqual(stream.next_calls, len(records) + 1)

    def test_invalid_record_fails_before_the_next_stream_record_is_requested(self):
        def records():
            yield {"selectedRow": None, "proof": None}
            raise AssertionError("invalid first record must stop iteration")

        with self.assertRaises(AuditInventoryError):
            verify_audit_inventory(root=self.tree.root, records=records())

    def test_iterator_failure_after_valid_prefix_never_returns_an_observation(self):
        def records():
            yield self.records[0]
            raise RuntimeError("fixture producer interrupted")

        with self.assertRaisesRegex(RuntimeError, "fixture producer interrupted"):
            verify_audit_inventory(root=self.tree.root, records=records())

    def test_reused_mutable_generator_buffer_does_not_change_prior_counts(self):
        shared = {}

        def records():
            for record in self.records:
                shared.clear()
                shared.update(copy.deepcopy(record))
                yield shared
            shared.clear()

        result = verify_audit_inventory(root=self.tree.root, records=records())
        self.assertEqual(shared, {})
        self.assertEqual((result.pending_count, result.claimed_count, result.audited_count), (1, 1, 1))
        self.assertEqual(result.root.root_digest, self.tree.nodes[(0, "")])
        self.assertEqual(result.json_projection()["schema"], SCHEMA)

    def test_invalid_stream_containers_and_empty_root_extra_member_reject(self):
        for records in (None, 1, "", b"", bytearray(), {}, {"selectedRow": None, "proof": None}):
            with self.subTest(kind=type(records).__name__), self.assertRaises(AuditInventoryError):
                verify_audit_inventory(root=self.tree.root, records=records)
        empty = InventoryTree([])
        with self.assertRaises(AuditInventoryError):
            verify_audit_inventory(root=empty.root, records=[object()])

    def test_summary_capacity_boundary_is_arithmetic_not_a_large_inventory_proof(self):
        # No 100k proof loop: direct summaries are self-consistent, not verified.
        root = replace(self.tree.root, leaf_count=100_001)
        result = AuditInventoryObservation(root, 99_999, 1, 1)
        self.assertEqual(result.outstanding_count, 100_000)
        with self.assertRaises(AuditInventoryError):
            AuditInventoryObservation(root, 100_000, 1, 0)
        huge_audited = replace(self.tree.root, leaf_count=MAX_INTEGER)
        self.assertEqual(AuditInventoryObservation(huge_audited, 0, 0, MAX_INTEGER).outstanding_count, 0)

    def test_summary_rejects_noninteger_negative_overflow_and_wrong_totals(self):
        for counts in ((True, 1, 1), (1.0, 1, 1), ("1", 1, 1), (-1, 2, 2),
                (1, 1, 0), (MAX_INTEGER + 1, 0, 0)):
            with self.subTest(counts=counts), self.assertRaises(AuditInventoryError):
                AuditInventoryObservation(self.tree.root, *counts)
        with self.assertRaises(AuditInventoryError):
            AuditInventoryObservation(replace(self.tree.root, table="other_table"), 1, 1, 1)

    def test_revision_and_currentness_still_require_external_authority(self):
        # The reconstructed hash proves neither a root's provenance nor its
        # revision/currentness. A coherently relabeled COMPLETE population is
        # still accepted; that is not permission to use it as a current root.
        root = replace(self.tree.root, root_revision=999)
        records = copy.deepcopy(self.records)
        for record in records:
            record["proof"]["rootRevision"] = 999
            refresh_proof(record["proof"])
        self.assertEqual(verify_audit_inventory(root=root, records=records).root.root_revision, 999)
        stale = InventoryTree([outbox_row("historical", "claimed")], revision=1)
        result = verify_audit_inventory(root=stale.root, records=stale.records())
        self.assertEqual(result.outstanding_count, 1)
        self.assertNotEqual(result.root.root_digest, self.tree.root.root_digest)
        # No API input identifies the live database or selects its latest root.

    def test_private_frontier_empty_prefix_root_carry_and_all_sixteen_children(self):
        # Hashing/state-machine components only. Arbitrary canonical leaf
        # digests below are NOT membership-verified rows and never enter the
        # public verifier; no production hash or key function is monkeypatched.
        cases = {
            "empty": (),
            "one": ("0" * 64,),
            "lcp-zero-root-carry": ("0" + "f" * 63, "1" + "0" * 63, "f" * 64),
            "multiple-shared-depths": (
                "1234" + "0" * 60, "1234" + "1" * 60,
                "1235" + "0" * 60, "1240" + "0" * 60,
            ),
            "lcp-sixty-three": ("a" * 63 + "0", "a" * 63 + "1", "a" * 63 + "f"),
            "low-nibble-carry": ("b" * 62 + "0f", "b" * 62 + "10", "b" * 62 + "ff"),
            "all-root-children": tuple(format(index, "x") + "0" * 63 for index in range(16)),
            "all-last-children": tuple("e" * 63 + format(index, "x") for index in range(16)),
        }
        for name, paths in cases.items():
            with self.subTest(case=name):
                leaves = {path: "sha256:" + hashlib.sha256(("component leaf:" + path).encode("ascii")).hexdigest()
                          for path in paths}
                before = copy.deepcopy(leaves)
                frontier = _InventoryRootFrontier()
                self.assertEqual(len(frontier._children), 64)
                self.assertEqual(len(frontier._empty), 65)
                self.assertTrue(all(len(children) == 16 for children in frontier._children))
                for path, leaf in sorted(leaves.items()):
                    frontier.add("sha256:" + path, leaf)
                    # Fixed container shape, not a total Python heap/RSS claim.
                    self.assertEqual(len(frontier._children), 64)
                    self.assertTrue(all(len(children) == 16 for children in frontier._children))
                self.assertEqual(frontier.finish(), independent_sparse_root(leaves))
                self.assertEqual(leaves, before)

    def test_private_frontier_rejects_bad_digest_types_duplicates_and_descending_keys(self):
        class StringSubclass(str):
            pass

        key = "sha256:" + "8" * 64
        leaf = "sha256:" + "9" * 64
        invalid = (None, False, b"sha256:" + b"0" * 64, StringSubclass(key),
                   "", "0" * 64, "sha256:" + "a" * 63, "sha256:" + "A" * 64,
                   "sha256:" + "g" * 64)
        for value in invalid:
            for invalid_key in (False, True):
                with self.subTest(value=repr(value), invalid_key=invalid_key):
                    frontier = _InventoryRootFrontier()
                    with self.assertRaisesRegex(AuditInventoryError, "^audit inventory frontier digest is invalid$"):
                        frontier.add(value if invalid_key else key, leaf if invalid_key else value)
                    frontier.add(key, leaf)
                    self.assertEqual(frontier.finish(), independent_sparse_root({key[7:]: leaf}))
        for following in (key, "sha256:" + "7" * 64):
            with self.subTest(following=following):
                frontier = _InventoryRootFrontier()
                frontier.add(key, leaf)
                with self.assertRaisesRegex(AuditInventoryError,
                        "^audit inventory keys are duplicated or not in tree order$"):
                    frontier.add(following, leaf)
                self.assertEqual(frontier.finish(), independent_sparse_root({key[7:]: leaf}))

    def test_private_frontier_cannot_be_reopened_or_finalized_twice(self):
        key, leaf = "sha256:" + "0" * 64, "sha256:" + "1" * 64
        for occupied in (False, True):
            with self.subTest(occupied=occupied):
                frontier = _InventoryRootFrontier()
                if occupied:
                    frontier.add(key, leaf)
                expected = independent_sparse_root({key[7:]: leaf} if occupied else {})
                self.assertEqual(frontier.finish(), expected)
                with self.assertRaisesRegex(AuditInventoryError, "^audit inventory frontier is already finished$"):
                    frontier.finish()
                with self.assertRaisesRegex(AuditInventoryError, "^audit inventory frontier is already finished$"):
                    frontier.add("sha256:" + "2" * 64, leaf)


if __name__ == "__main__":
    unittest.main()
