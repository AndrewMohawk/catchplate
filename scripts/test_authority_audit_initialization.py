#!/usr/bin/env python3
"""Pure initialization preparation against independent full-tree fixtures.

No database, registry replacement, initializer authorization, SQL INSERT,
signer, fence or clock is provided. Outbox completeness is checked against a
supplied digest; aggregate revision/count/currentness and all root provenance
remain conditional inputs. Consumer continuity is only the real pure capacity
finalizer, not an executed business operation or installed baseline.
"""
from __future__ import annotations

import copy
import hashlib
import json
import sys
import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate import authority_audit_capacity as capacity
from catchplate import authority_audit_initialization as initialization
from catchplate import authority_contract
from catchplate import authority_transition_core as core
from catchplate.authority_audit_inventory import AuditInventoryObservation
from test_authority_audit_inventory import InventoryTree, outbox_row, wire_digest, wire_json
from test_authority_radix_mutation import IndependentTree, refresh_proof_digest


AGGREGATE = "policy_authority_bounded_aggregate_states"
OUTBOX = "metadata_audit_outbox"
KIND = "metadata-audit-outbox-global-capacity-v1"
MAX_INTEGER = 2**63 - 1
PARTITION = wire_digest("catchplate.metadataAuditOutboxCapacityPartition/v1", b"global")
IDENTITY = KIND + ":" + PARTITION
KEY = {"aggregate_id": IDENTITY}
EMPTY_EXPIRY = wire_digest("catchplate.policyAuthorityAggregateExpiryIndex/v1", b"[]")
TIME_NS = 1_000_000_000
SCHEMA = "catchplate.metadataAuditCapacityInitializationPreparation/v1"
PROFILE = "catchplate.metadataAuditCapacityInitializationProfile/v1"
INSERT_TEMPLATE = "catchplate.metadataAuditCapacityInitializationInsert/v1"
INVENTORY_SCHEMA = "catchplate.metadataAuditOutboxInventoryObservation/v2"


def initial_row(outstanding, timestamp=TIME_NS):
    state = {
        "schema": "catchplate.policyAuthorityAggregateState/v1",
        "aggregateId": IDENTITY, "aggregateKind": KIND, "partitionDigest": PARTITION,
        "revision": 1, "liveCount": outstanding, "activeCount": outstanding,
        "capacityLimit": 100_000, "reservedUnits": {}, "committedUnits": {},
        "nextSequence": 0, "minimumExpiryEpochNs": None,
        "expiryIndexRootDigest": EMPTY_EXPIRY, "workPageId": None,
    }
    return {
        "aggregate_id": IDENTITY, "aggregate_kind": KIND, "partition_digest": PARTITION,
        "revision": 1, "live_count": outstanding, "active_count": outstanding,
        "capacity_limit": 100_000, "reserved_units_json": "{}", "committed_units_json": "{}",
        "next_sequence": 0, "minimum_expiry_epoch_ns": None,
        "expiry_index_root_digest": EMPTY_EXPIRY, "work_page_id": None,
        "state_json": wire_json(state).decode("ascii"),
        "state_digest": wire_digest("catchplate.policyAuthorityAggregateState/v1", wire_json(state)),
        "updated_at_epoch_ns": timestamp, "source_revision": authority_contract.SOURCE_REVISION,
    }


def aggregate_tree(rows=(), *, revision=None):
    return IndependentTree(list(rows), table=AGGREGATE, columns=("aggregate_id",), revision=revision)


def absence(tree, key=None):
    selected = tree.selected(KEY if key is None else key)
    return {"selectedRow": selected, "proof": tree.proof(selected)}


def business_selected(table, key, row):
    return {
        "table": table, "key": copy.deepcopy(key),
        "keyDigest": wire_digest("catchplate.policyAuthorityBusinessKey/v1",
            table.encode("ascii"), wire_json(key)),
        "present": row is not None, "row": copy.deepcopy(row), "contractSelector": None,
    }


def graph_nodes(value):
    if type(value) is dict:
        return 1 + sum(graph_nodes(key) + graph_nodes(child) for key, child in value.items())
    if type(value) is list:
        return 1 + sum(graph_nodes(child) for child in value)
    return 1


class AuditCapacityInitializationTests(unittest.TestCase):
    def setUp(self):
        self.outbox = InventoryTree([outbox_row("one"), outbox_row("two", "claimed"),
                                    outbox_row("three", "audited")], revision=17)
        # Untouched leaves are opaque to the preparation; the independent
        # oracle retains them when rebuilding the expected aggregate root.
        self.other_rows = [{"aggregate_id": "other-a", "value": "opaque"},
                           {"aggregate_id": "other-z", "value": None}]
        self.aggregate = aggregate_tree(self.other_rows, revision=23)
        self.absence = absence(self.aggregate)
        self.records = self.outbox.records()

    def prepare(self, **changes):
        arguments = {
            "outbox_root": self.outbox.root, "outbox_records": self.records,
            "aggregate_root": self.aggregate.root, "aggregate_absence": self.absence,
            "initialized_at_epoch_ns": TIME_NS,
        }
        arguments.update(changes)
        return initialization.prepare_audit_capacity_initialization(**arguments)

    def expected(self, *, outbox=None, aggregate=None, timestamp=TIME_NS):
        outbox = self.outbox if outbox is None else outbox
        aggregate = self.aggregate if aggregate is None else aggregate
        counts = {status: sum(row["status"] == status for row in outbox.rows.values())
                  for status in ("pending", "claimed", "audited")}
        row = initial_row(counts["pending"] + counts["claimed"], timestamp)
        after = aggregate_tree([*aggregate.rows.values(), row], revision=aggregate.root.root_revision + 1)
        missing = absence(aggregate)
        contracts = [
            {"table": OUTBOX, "keyColumns": ["id"], "writeAccess": False, "rootClass": "business"},
            {"table": AGGREGATE, "keyColumns": ["aggregate_id"], "writeAccess": True, "rootClass": "business"},
        ]
        before_roots = [outbox.root.json_projection(), aggregate.root.json_projection()]
        after_roots = [outbox.root.json_projection(), after.root.json_projection()]
        inventory = {
            "schema": INVENTORY_SCHEMA, "sourceRevision": authority_contract.SOURCE_REVISION,
            "root": outbox.root.json_projection(), "pendingCount": counts["pending"],
            "claimedCount": counts["claimed"], "auditedCount": counts["audited"],
            "outstandingCount": counts["pending"] + counts["claimed"],
        }
        mutation = {
            "templateId": INSERT_TEMPLATE, "operation": "INSERT", "table": AGGREGATE,
            "key": copy.deepcopy(KEY), "keyDigest": missing["selectedRow"]["keyDigest"],
            "expectedRow": None, "row": row,
        }
        snapshot = {
            "contracts": contracts, "businessRoots": before_roots, "authorizationRoots": [],
            "selected": [missing["selectedRow"]], "proofs": [missing["proof"]], "mutations": [mutation],
        }
        metrics = {"selectedRows": 1, "mutations": 1, "proofVectors": 64, "proofChildSlots": 1024,
            "recomputedAncestors": 64, "hashWork": 66 + 68 + 2 + 64,
            "inputBytes": len(wire_json(snapshot)), "jsonNodes": graph_nodes(snapshot)}
        return {
            "schema": SCHEMA, "profile": PROFILE, "sourceRevision": authority_contract.SOURCE_REVISION,
            "initializationPolicy": {"initialCounterRevision": 1, "initialNextSequence": 0,
                "sequenceBasis": "fresh-pending-inserts-after-initialization",
                "timestampBasis": "explicit-input-not-time-authority"},
            "initializedAtEpochNs": timestamp, "inventory": inventory,
            "inventoryDigest": wire_digest(INVENTORY_SCHEMA, wire_json(inventory)),
            "tableContracts": contracts, "beforeRoots": before_roots, "afterRoots": after_roots,
            "aggregateAbsence": missing, "counterRow": row,
            "counterRowDigest": wire_digest("catchplate.metadataAuditCapacityInitialRow/v1", wire_json(row)),
            "prospectiveMutation": mutation, "radixMetrics": metrics, "installationPermitted": False,
        }

    def test_full_preparation_matches_independent_row_roots_commitments_and_metrics(self):
        result = self.prepare()
        expected = self.expected()
        self.assertIs(type(result), initialization.AuditCapacityInitializationPreparation)
        self.assertEqual(result.json_projection(), expected)
        self.assertIs(type(result.canonical_bytes), bytes)
        self.assertEqual(result.canonical_bytes, wire_json(expected))
        self.assertEqual(result.digest, wire_digest(SCHEMA, wire_json(expected)))
        self.assertEqual(len(expected["counterRow"]), 17)
        self.assertEqual(expected["afterRoots"][0], expected["beforeRoots"][0])
        self.assertFalse(expected["installationPermitted"])

    def test_empty_populations_and_historical_empty_roots_use_zero_sequence(self):
        for revision in (0, 29):
            with self.subTest(revision=revision):
                outbox = InventoryTree([], revision=revision)
                aggregate = aggregate_tree(revision=revision)
                result = self.prepare(outbox_root=outbox.root, outbox_records=(), aggregate_root=aggregate.root,
                                      aggregate_absence=absence(aggregate), initialized_at_epoch_ns=0)
                expected = self.expected(outbox=outbox, aggregate=aggregate, timestamp=0)
                self.assertEqual(result.json_projection(), expected)
                self.assertEqual(expected["counterRow"]["revision"], 1)
                self.assertEqual(expected["counterRow"]["next_sequence"], 0)
                self.assertEqual(expected["afterRoots"][1]["rootRevision"], revision + 1)

    def test_explicit_time_endpoints_are_exact_integer_inputs(self):
        for timestamp in (0, MAX_INTEGER):
            with self.subTest(timestamp=timestamp):
                self.assertEqual(self.prepare(initialized_at_epoch_ns=timestamp).json_projection(),
                                 self.expected(timestamp=timestamp))
        for value in (None, False, True, -1, MAX_INTEGER + 1, 1.0, "1", b"1"):
            with self.subTest(value=repr(value)), self.assertRaises(initialization.AuditCapacityInitializationError):
                self.prepare(initialized_at_epoch_ns=value)

    def test_time_is_committed_by_full_row_root_and_preparation_not_state_digest(self):
        first = self.prepare(initialized_at_epoch_ns=TIME_NS)
        later = self.prepare(initialized_at_epoch_ns=TIME_NS + 1)
        first_document, later_document = first.json_projection(), later.json_projection()
        self.assertEqual(first_document, self.expected(timestamp=TIME_NS))
        self.assertEqual(later_document, self.expected(timestamp=TIME_NS + 1))
        self.assertEqual(first_document["counterRow"]["state_digest"],
                         later_document["counterRow"]["state_digest"])
        self.assertEqual(first_document["inventoryDigest"], later_document["inventoryDigest"])
        self.assertEqual(first_document["beforeRoots"], later_document["beforeRoots"])
        self.assertNotEqual(first_document["counterRowDigest"], later_document["counterRowDigest"])
        first_after = next(root for root in first_document["afterRoots"] if root["table"] == AGGREGATE)
        later_after = next(root for root in later_document["afterRoots"] if root["table"] == AGGREGATE)
        self.assertNotEqual(first_after["rootDigest"], later_after["rootDigest"])
        self.assertNotEqual(first.digest, later.digest)

    def test_existing_global_key_is_not_reinitialized(self):
        aggregate = aggregate_tree([initial_row(2)], revision=7)
        with self.assertRaises(initialization.AuditCapacityInitializationError):
            self.prepare(aggregate_root=aggregate.root, aggregate_absence=absence(aggregate))

    def test_wrong_key_table_selector_and_non_absence_images_reject(self):
        wrong_key = absence(self.aggregate, {"aggregate_id": "different-global-row"})
        cases = [wrong_key]
        for field, value in (("table", OUTBOX), ("present", True), ("present", 0),
                             ("row", {}), ("contractSelector", "caller-selector"),
                             ("key", {"aggregate_id": IDENTITY, "extra": "x"})):
            changed = copy.deepcopy(self.absence)
            changed["selectedRow"][field] = value
            cases.append(changed)
        for value in cases:
            with self.subTest(selected=value["selectedRow"]), self.assertRaises(initialization.AuditCapacityInitializationError):
                self.prepare(aggregate_absence=value)

    def test_closed_absence_and_lossless_graph_are_required(self):
        cases = [None, [], (), self.absence["proof"], {**self.absence, "extra": None}]
        for target in ("selectedRow", "proof"):
            changed = copy.deepcopy(self.absence)
            del changed[target]
            cases.append(changed)
        for value in (bytearray(b"x"), 1.5, "\ud800", "\x00"):
            changed = copy.deepcopy(self.absence)
            changed["proof"]["extra"] = value
            cases.append(changed)
        for value in cases:
            with self.subTest(type=type(value).__name__), self.assertRaises(initialization.AuditCapacityInitializationError):
                self.prepare(aggregate_absence=value)

    def test_absence_proof_digest_root_leaf_and_path_substitutions_reject(self):
        for field, value, refresh in (("proofDigest", "sha256:" + "f" * 64, False),
                ("rootDigest", "sha256:" + "f" * 64, True), ("rootRevision", 24, True),
                ("rowDigest", "sha256:" + "f" * 64, True),
                ("leafDigest", "sha256:" + "f" * 64, True), ("present", True, True)):
            changed = copy.deepcopy(self.absence)
            changed["proof"][field] = value
            if refresh:
                refresh_proof_digest(changed["proof"])
            with self.subTest(field=field), self.assertRaises(initialization.AuditCapacityInitializationError):
                self.prepare(aggregate_absence=changed)
        changed = copy.deepcopy(self.absence)
        changed["proof"]["siblings"][0]["childDigests"][0] = "sha256:" + "f" * 64
        refresh_proof_digest(changed["proof"])
        with self.assertRaises(initialization.AuditCapacityInitializationError):
            self.prepare(aggregate_absence=changed)

    def test_outbox_omission_understatement_and_changed_proved_rows_reject(self):
        for records, root in ((self.records[:1], self.outbox.root),
                (self.records[:1], replace(self.outbox.root, leaf_count=1)),
                ([self.records[0], self.records[2]], replace(self.outbox.root, leaf_count=2))):
            with self.subTest(count=root.leaf_count), self.assertRaises(initialization.AuditCapacityInitializationError):
                self.prepare(outbox_records=records, outbox_root=root)
        changed = copy.deepcopy(self.records)
        changed[0]["selectedRow"]["row"]["attempts"] += 1
        with self.assertRaises(initialization.AuditCapacityInitializationError):
            self.prepare(outbox_records=changed)

    def test_supplied_root_types_tables_hashes_and_revisions_are_bound(self):
        for argument, value in (
            ("outbox_root", self.outbox.root.json_projection()), ("aggregate_root", None),
            ("outbox_root", replace(self.outbox.root, table=AGGREGATE)),
            ("aggregate_root", replace(self.aggregate.root, table=OUTBOX)),
            ("aggregate_root", replace(self.aggregate.root, root_revision=24)),
            ("aggregate_root", replace(self.aggregate.root, root_digest="sha256:" + "f" * 64)),
        ):
            with self.subTest(argument=argument, value=value), self.assertRaises(initialization.AuditCapacityInitializationError):
                self.prepare(**{argument: value})

    def test_aggregate_revision_and_count_increment_overflow_reject(self):
        for field in ("root_revision", "leaf_count"):
            root = replace(self.aggregate.root, **{field: MAX_INTEGER})
            missing = copy.deepcopy(self.absence)
            missing["proof"]["rootRevision"] = root.root_revision
            refresh_proof_digest(missing["proof"])
            with self.subTest(field=field), self.assertRaises(initialization.AuditCapacityInitializationError):
                self.prepare(aggregate_root=root, aggregate_absence=missing)

    def test_absence_is_owned_before_outbox_generator_can_mutate_caller_graph(self):
        expected = wire_json(self.expected())
        missing = copy.deepcopy(self.absence)

        def records():
            missing.clear()
            missing.update({"selectedRow": None, "proof": None})
            yield from self.records

        result = self.prepare(aggregate_absence=missing, outbox_records=records())
        self.assertEqual(result.canonical_bytes, expected)
        self.assertEqual(missing, {"selectedRow": None, "proof": None})

    def test_inputs_unchanged_and_output_is_frozen_canonical_bytes_with_fresh_projection(self):
        original = copy.deepcopy((self.records, self.absence))
        result = self.prepare()
        self.assertEqual((self.records, self.absence), original)
        document = result.json_projection()
        document["counterRow"]["live_count"] = 999
        document["aggregateAbsence"].clear()
        document["installationPermitted"] = True
        self.assertEqual(result.canonical_bytes, wire_json(self.expected()))
        self.assertEqual(result.json_projection(), self.expected())
        with self.assertRaises(FrozenInstanceError):
            result._document = b"{}"

    def test_aggregate_count_revision_and_currentness_remain_conditional_authority(self):
        # One exact nonmembership proof does NOT authenticate the aggregate
        # descriptor's total count or revision. No currentness input exists.
        supplied = replace(self.aggregate.root, leaf_count=42, root_revision=999)
        missing = copy.deepcopy(self.absence)
        missing["proof"]["rootRevision"] = 999
        refresh_proof_digest(missing["proof"])
        document = self.prepare(aggregate_root=supplied, aggregate_absence=missing).json_projection()
        after = next(root for root in document["afterRoots"] if root["table"] == AGGREGATE)
        real_after = aggregate_tree([*self.other_rows, initial_row(2)], revision=1000)
        self.assertEqual(after["rootDigest"], real_after.root.root_digest)
        self.assertEqual((after["rootRevision"], after["leafCount"]), (1000, 43))
        self.assertEqual(real_after.root.leaf_count, 3)
        self.assertIs(document["installationPermitted"], False)

    def test_invalid_preconditions_reject_before_starting_the_outbox_stream(self):
        for changes in (
            {"initialized_at_epoch_ns": True},
            {"aggregate_root": replace(self.aggregate.root, root_revision=MAX_INTEGER)},
            {"aggregate_absence": {"selectedRow": None, "proof": None}},
        ):
            def records():
                raise AssertionError("invalid preparation precondition must precede iteration")
                yield  # Make this a lazy generator without starting it here.

            with self.subTest(changes=changes), self.assertRaises(initialization.AuditCapacityInitializationError):
                self.prepare(outbox_records=records(), **changes)

    def test_interrupted_inventory_never_returns_a_prefix_preparation(self):
        def records():
            yield self.records[0]
            raise RuntimeError("component inventory producer interrupted")

        with self.assertRaisesRegex(RuntimeError, "^component inventory producer interrupted$"):
            self.prepare(outbox_records=records())

    def test_direct_serialization_or_constructed_observation_is_not_a_proof_stream(self):
        document = self.prepare().json_projection()
        document["inventory"]["outstandingCount"] = 0
        document["counterRow"]["live_count"] = 999
        # The class is a canonical serialization, explicitly not a proof token.
        forged_serialization = initialization.AuditCapacityInitializationPreparation(wire_json(document))
        self.assertEqual(forged_serialization.json_projection()["counterRow"]["live_count"], 999)
        self.assertIs(forged_serialization.json_projection()["installationPermitted"], False)
        constructed_observation = AuditInventoryObservation(self.outbox.root, 0, 0, 3)
        for supplied in (forged_serialization, constructed_observation):
            with self.subTest(type=type(supplied).__name__), self.assertRaises(initialization.AuditCapacityInitializationError):
                self.prepare(outbox_records=supplied)
        self.assertEqual(self.prepare().json_projection(), self.expected())

    def test_document_constructor_rejects_noncanonical_outer_shape_and_permission_changes(self):
        document = self.prepare().json_projection()
        for value in (None, bytearray(wire_json(document)), wire_json(document).decode("ascii"),
                      b"{}", b"[]", wire_json(document) + b"\n"):
            with self.subTest(type=type(value).__name__), self.assertRaises(initialization.AuditCapacityInitializationError):
                initialization.AuditCapacityInitializationPreparation(value)
        for field, value in (("schema", SCHEMA + ".other"), ("profile", PROFILE + ".other"),
                ("installationPermitted", True), ("installationPermitted", 0),
                ("initializedAtEpochNs", True)):
            changed = copy.deepcopy(document)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(initialization.AuditCapacityInitializationError):
                initialization.AuditCapacityInitializationPreparation(wire_json(changed))
        for count in (False, 2):
            changed = copy.deepcopy(document)
            changed["initializationPolicy"]["initialCounterRevision"] = count
            with self.assertRaises(initialization.AuditCapacityInitializationError):
                initialization.AuditCapacityInitializationPreparation(wire_json(changed))

    def test_prepared_row_is_accepted_by_real_capacity_finalizer_for_replay_and_fresh_insert(self):
        row = self.prepare().json_projection()["counterRow"]
        counter_selection = business_selected(AGGREGATE, KEY, row)
        fresh = outbox_row("fresh-after-initialization")
        fresh_selection = business_selected(OUTBOX, {"id": fresh["id"]}, None)
        operation = "policy.genesis.prepare"
        context = core.KernelContext(
            operation=operation, arguments={}, selected_rows=(counter_selection, fresh_selection),
            database_now=datetime(1970, 1, 1, 0, 0, 2, tzinfo=timezone.utc),
            request_digest="sha256:" + hashlib.sha256(b"initialization-consumer-component").hexdigest(),
        )
        self.assertEqual(capacity.finalize_capacity(context, ()), ())
        insert = core.mutation(operation=operation, selected=fresh_selection, row=fresh)
        result = capacity.finalize_capacity(context, (insert,))
        capacity.validate_capacity_transition(operation=operation, selected_rows=context.selected_rows, mutations=result)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], insert)
        self.assertEqual(result[1]["operation"], "UPDATE")
        self.assertEqual(result[1]["expectedRow"], row)
        state = json.loads(row["state_json"])
        state.update(revision=2, liveCount=3, activeCount=3, nextSequence=1)
        expected = {**row, "revision": 2, "live_count": 3, "active_count": 3,
            "next_sequence": 1, "updated_at_epoch_ns": 2_000_000_000,
            "state_json": wire_json(state).decode("ascii"),
            "state_digest": wire_digest("catchplate.policyAuthorityAggregateState/v1", wire_json(state))}
        self.assertEqual(result[1]["row"], expected)
        # The prospective initialization label does not become a source-owned
        # runtime mutation template by passing this pure consumer check.
        for spec in authority_contract.OPERATIONS.values():
            self.assertNotIn(INSERT_TEMPLATE, {template["templateId"] for template in spec["mutationTemplates"]})


if __name__ == "__main__":
    unittest.main()
