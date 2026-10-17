#!/usr/bin/env python3
"""Real pure trace-budget tests, not complete planner/SQL execution evidence.

Fixtures independently frame the global identity and persisted-tree key. The
actual capacity producer supplies mutation inputs, while these traces exercise
only the budget partition: business trace closure, row/proof validation and
count authority remain separate. No registry import/replacement or AST execution.
"""
from __future__ import annotations

import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate import authority_audit_capacity as capacity
from catchplate import authority_audit_trace as trace
from catchplate import authority_contract
from test_authority_global_audit_capacity import fixture, outbox_row


SHARED = "policy.genesis.prepare"
NEW_ROOT = "webauthn.trust.complete"
NONPARTICIPANT = "webauthn.counter.cas"
TABLE = "policy_authority_bounded_aggregate_states"
ROOT_TABLE = "policy_authority_authenticated_table_roots"
LEAF_TABLE = "policy_authority_authenticated_leaves"
NODE_TABLE = "policy_authority_authenticated_tree_nodes"


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      allow_nan=False, separators=(",", ":")).encode("ascii")


def wire_digest(domain, *frames):
    digest = hashlib.sha256(domain.encode("ascii") + b"\0")
    for frame in frames:
        digest.update(len(frame).to_bytes(8, "big"))
        digest.update(frame)
    return "sha256:" + digest.hexdigest()


PARTITION = wire_digest("catchplate.metadataAuditOutboxCapacityPartition/v1", b"global")
IDENTITY = "metadata-audit-outbox-global-capacity-v1:" + PARTITION
KEY = {"aggregate_id": IDENTITY}


def independent_tree_key(key=KEY):
    # Persisted tree framing includes the domain length, unlike the wire digest.
    domain = b"catchplate.policyAuthorityAuthenticatedKey/v1"
    digest = hashlib.sha256()
    for frame in (domain, TABLE.encode("ascii"), canonical(key)):
        digest.update(len(frame).to_bytes(8, "big"))
        digest.update(frame)
    return "sha256:" + digest.hexdigest()


def entry(table, key, access="read"):
    return {"ordinal": 0, "access": access, "table": table, "key": copy.deepcopy(key)}


def renumber(entries):
    return [{**copy.deepcopy(item), "ordinal": ordinal} for ordinal, item in enumerate(entries)]


def proof_entries(key=KEY):
    digest = independent_tree_key(key)
    path = digest[7:]
    return [entry(LEAF_TABLE, {"tableName": TABLE, "keyDigest": digest})] + [
        entry(NODE_TABLE, {"tableName": TABLE, "depth": depth + 1, "pathPrefix": path[:depth]})
        for depth in range(64)
    ]


def capacity_entries(*, write=False, root=False):
    entries = [entry(ROOT_TABLE, {"tableName": TABLE})] if root else []
    entries += [entry(TABLE, {"globalAuditCapacityQuery": IDENTITY}), entry(TABLE, KEY)]
    entries += proof_entries()
    if write:
        entries.append(entry(TABLE, KEY, "write"))
    return renumber(entries)


def business_entries(count):
    return [entry("policy_high_water", {"scope": "component-read"}) for _ in range(count)]


def mutations(operation=SHARED, *, write=False):
    context, raw = fixture([(None, outbox_row())] if write else [], operation=operation)
    return capacity.finalize_capacity(context, raw)


def evaluate(entries, changes, *, operation=SHARED):
    budget = trace.AuditTraceBudget(operation)
    for item in renumber(entries):
        budget.append(item)
    budget.close(changes)
    return budget


class AuditTraceTests(unittest.TestCase):
    def test_independently_framed_identity_and_exact_67_68_69_costs(self):
        self.assertEqual(capacity.AGGREGATE_ID, IDENTITY)
        self.assertEqual(trace.audit_capacity_scan_key(), {"globalAuditCapacityQuery": IDENTITY})
        self.assertEqual((trace.MAX_TRACE_ENTRIES, trace.MAX_AUDIT_CAPACITY_TRACE_ENTRIES,
                          trace.MAX_PLAN_TRACE_ENTRIES), (4096, 69, 4165))
        for operation, write, root, framework in (
            (SHARED, False, False, 67), (SHARED, True, False, 68),
            (NEW_ROOT, False, True, 68), (NEW_ROOT, True, True, 69),
        ):
            with self.subTest(operation=operation, write=write):
                budget = evaluate(capacity_entries(write=write, root=root),
                                  mutations(operation, write=write), operation=operation)
                self.assertEqual((budget.business_entries, budget.framework_entries), (0, framework))

    def test_real_source_flags_select_four_new_roots_not_caller_parameters(self):
        new_roots = set()
        participants = set()
        for operation, spec in authority_contract.OPERATIONS.items():
            if not spec["globalAuditCapacity"]:
                continue
            participants.add(operation)
            root = spec["auditCapacityAddsAggregateRoot"]
            if root:
                new_roots.add(operation)
            budget = evaluate(capacity_entries(root=root), mutations(operation), operation=operation)
            self.assertEqual(budget.framework_entries, 67 + int(root))
        self.assertEqual(len(participants), 19)
        self.assertEqual(new_roots, {"webauthn.trust.complete", "webauthn.registration.create",
                                    "webauthn.registration.finalize", "webauthn.credential.revoke"})

    def test_exact_4096_business_entries_plus_69_framework_entries(self):
        changes = mutations(NEW_ROOT, write=True)
        entries = business_entries(4096) + capacity_entries(root=True, write=True)
        original = copy.deepcopy(entries)
        budget = evaluate(entries, changes, operation=NEW_ROOT)
        self.assertEqual((budget.business_entries, budget.framework_entries), (4096, 69))
        self.assertEqual(entries, original)
        with self.assertRaisesRegex(trace.AuditTraceError, "trace bound was exceeded"):
            evaluate(entries + business_entries(1), changes, operation=NEW_ROOT)

    def test_shared_aggregate_root_is_business_charged_and_never_a_free_slot(self):
        entries = capacity_entries(root=True)
        budget = evaluate(entries, mutations())
        self.assertEqual((budget.business_entries, budget.framework_entries), (1, 67))
        evaluate(business_entries(4095) + entries, mutations())
        with self.assertRaisesRegex(trace.AuditTraceError, "trace bound was exceeded"):
            evaluate(business_entries(4096) + entries, mutations())
        with self.assertRaisesRegex(trace.AuditTraceError, "trace is not exact"):
            evaluate(capacity_entries(root=False), mutations(NEW_ROOT), operation=NEW_ROOT)

    def test_nonparticipant_has_no_framework_allowance_even_for_identical_markers(self):
        markers = capacity_entries(root=True, write=True)
        budget = evaluate(markers, (), operation=NONPARTICIPANT)
        self.assertEqual((budget.business_entries, budget.framework_entries), (69, 0))
        evaluate(business_entries(4096), (), operation=NONPARTICIPANT)
        with self.assertRaisesRegex(trace.AuditTraceError, "trace bound was exceeded"):
            evaluate(business_entries(4096) + markers[:1], (), operation=NONPARTICIPANT)

    def test_other_aggregate_proof_and_shared_prefixes_remain_business_charged(self):
        other = proof_entries({"aggregate_id": "different-business-aggregate"})
        global_proof = proof_entries()
        self.assertNotEqual(other[0]["key"]["keyDigest"], global_proof[0]["key"]["keyDigest"])
        self.assertEqual(other[1]["key"], global_proof[1]["key"])
        entries = other + capacity_entries() + [copy.deepcopy(global_proof[1])]
        budget = evaluate(entries, mutations())
        self.assertEqual((budget.business_entries, budget.framework_entries), (66, 67))
        evaluate(business_entries(4030) + entries, mutations())
        with self.assertRaisesRegex(trace.AuditTraceError, "trace bound was exceeded"):
            evaluate(business_entries(4031) + entries, mutations())

    def test_wrong_order_or_interruption_inside_global_proof_is_rejected(self):
        baseline = capacity_entries()
        for label in ("swap", "business-interruption", "repeat-node", "write-interruption"):
            changed = copy.deepcopy(baseline)
            if label == "swap":
                changed[3], changed[4] = changed[4], changed[3]
            elif label == "business-interruption":
                changed.insert(4, business_entries(1)[0])
            elif label == "repeat-node":
                changed.insert(4, copy.deepcopy(changed[3]))
            else:
                changed.insert(4, entry(TABLE, KEY, "write"))
            with self.subTest(case=label), self.assertRaisesRegex(trace.AuditTraceError, "proof is not contiguous"):
                evaluate(changed, mutations())

    def test_duplicate_source_owned_markers_cannot_create_extra_allowance(self):
        for label in ("scan", "row", "leaf", "write", "root"):
            operation = NEW_ROOT if label == "root" else SHARED
            entries = capacity_entries(write=True, root=label == "root")
            marker = {
                "scan": entry(TABLE, {"globalAuditCapacityQuery": IDENTITY}),
                "row": entry(TABLE, KEY), "leaf": proof_entries()[0],
                "write": entry(TABLE, KEY, "write"),
                "root": entry(ROOT_TABLE, {"tableName": TABLE}),
            }[label]
            with self.subTest(marker=label), self.assertRaisesRegex(trace.AuditTraceError, "identity is duplicated"):
                evaluate(entries + [marker], mutations(operation, write=True), operation=operation)

    def test_missing_scan_row_leaf_last_node_and_root_fail_complete_set(self):
        for removed in (0, 1, 2, 66):
            entries = capacity_entries()
            entries.pop(removed)
            with self.subTest(removed=removed), self.assertRaisesRegex(trace.AuditTraceError, "trace is not exact"):
                evaluate(entries, mutations())
        entries = capacity_entries()
        entries.pop(4)
        with self.assertRaisesRegex(trace.AuditTraceError, "proof is not contiguous"):
            evaluate(entries, mutations())
        with self.assertRaisesRegex(trace.AuditTraceError, "trace is not exact"):
            evaluate(capacity_entries(), mutations(NEW_ROOT), operation=NEW_ROOT)

    def test_global_write_is_required_exactly_when_finalized_counter_is_present(self):
        evaluate(capacity_entries(write=True), mutations(write=True))
        evaluate(capacity_entries(), mutations())
        with self.assertRaisesRegex(trace.AuditTraceError, "trace is not exact"):
            evaluate(capacity_entries(), mutations(write=True))
        with self.assertRaisesRegex(trace.AuditTraceError, "trace is not exact"):
            evaluate(capacity_entries(write=True), mutations())
        wrong_write = capacity_entries() + [entry(TABLE, {"aggregate_id": IDENTITY + "-alias"}, "write")]
        with self.assertRaisesRegex(trace.AuditTraceError, "trace is not exact"):
            evaluate(wrong_write, mutations(write=True))

    def test_wire_key_hash_or_other_leaf_does_not_substitute_for_tree_key(self):
        wrong_digests = (
            wire_digest("catchplate.policyAuthorityAuthenticatedKey/v1", TABLE.encode("ascii"), canonical(KEY)),
            independent_tree_key({"aggregate_id": IDENTITY + "-other"}),
        )
        for digest in wrong_digests:
            self.assertNotEqual(digest, independent_tree_key())
            entries = capacity_entries()
            entries[2]["key"]["keyDigest"] = digest
            with self.subTest(digest=digest), self.assertRaisesRegex(trace.AuditTraceError, "trace is not exact"):
                evaluate(entries, mutations())

    def test_exact_node_types_table_depth_and_prefix_are_not_coerced(self):
        for field, value in (("depth", True), ("depth", "1"), ("depth", 2),
                             ("pathPrefix", "0"), ("tableName", "metadata_audit_outbox")):
            entries = capacity_entries()
            entries[3]["key"][field] = value
            with self.subTest(field=field, value=value), self.assertRaisesRegex(trace.AuditTraceError, "proof is not contiguous"):
                evaluate(entries, mutations())

    def test_scan_key_freshness_and_all_input_graphs_are_unchanged(self):
        first = trace.audit_capacity_scan_key()
        first["globalAuditCapacityQuery"] = "changed-local-copy"
        self.assertEqual(trace.audit_capacity_scan_key(), {"globalAuditCapacityQuery": IDENTITY})
        entries = capacity_entries(write=True, root=True)
        changes = mutations(NEW_ROOT, write=True)
        original = copy.deepcopy((entries, changes))
        # Feed the original caller graphs directly, not evaluate()'s renumbered
        # copies, so this is an actual no-mutation/no-retention control.
        budget = trace.AuditTraceBudget(NEW_ROOT)
        for item in entries:
            budget.append(item)
        budget.close(changes)
        budget.close(changes)
        self.assertEqual((entries, changes), original)
        entries[3]["key"]["keyDigest"] = "changed-after-append"
        self.assertEqual(budget.framework_entries, 69)
        budget.close(changes)


if __name__ == "__main__":
    unittest.main()
