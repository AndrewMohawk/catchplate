#!/usr/bin/env python3
"""Pure audit-capacity admission components, not complete outbox-count proof.

Uses the real KernelContext and policy helper with independently hashed selected
row fixtures. The composed helper returns actual aggregate/outbox mutations,
but these tests do not execute the four complete caller kernels. No DB, registry
replacement, SQL, authenticated root, all-writer count maintenance, or trust-
completion success is simulated or claimed.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_contract
from serverware import authority_transition_core as core
from serverware import authority_transition_policy as policy
from serverware.audit_outbox_contract import MAX_PENDING


TABLE = "policy_authority_bounded_aggregate_states"
AUDIT_KIND = "metadata-audit-outbox-capacity"
NOW = datetime(1970, 1, 1, 0, 0, 2, tzinfo=timezone.utc)
NOW_NS = 2_000_000_000
CHARGES = {
    "policy.activation.prepare": 7,
    "policy.genesis.prepare": 1,
    "rbac.binding.mutate": 1,
    "policy.activation.abort": 1,
}
_DEFAULT = object()


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("ascii")


def framed(domain: str, *frames: bytes) -> str:
    # Independent spelling of the existing transition-core framing, not the
    # distinct SQL primary-tree hash or evidence of an authenticated DB read.
    digest = hashlib.sha256(domain.encode("ascii") + b"\0")
    for value in frames:
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    return "sha256:" + digest.hexdigest()


AUDIT_PARTITION = framed("serverware.policyAuthorityAggregatePartition/v1", b"metadata-audit-outbox")
AUDIT_ID = f"{AUDIT_KIND}:{AUDIT_PARTITION}"
EXPIRY_ROOT = framed("serverware.policyAuthorityAggregateExpiryIndex/v1", b"[]")
REQUEST_DIGEST = "sha256:" + hashlib.sha256(b"audit-capacity-local-component").hexdigest()


def operation_id(operation):
    return framed("serverware.policyAuthorityOperation/v2", operation.encode("utf-8"), REQUEST_DIGEST.encode("ascii"))


def state_material(row):
    return {
        "schema": "serverware.policyAuthorityAggregateState/v1",
        "aggregateId": row["aggregate_id"], "aggregateKind": row["aggregate_kind"],
        "partitionDigest": row["partition_digest"], "revision": row["revision"],
        "liveCount": row["live_count"], "activeCount": row["active_count"],
        "capacityLimit": row["capacity_limit"],
        "reservedUnits": json.loads(row["reserved_units_json"]),
        "committedUnits": json.loads(row["committed_units_json"]),
        "nextSequence": row["next_sequence"],
        "minimumExpiryEpochNs": row["minimum_expiry_epoch_ns"],
        "expiryIndexRootDigest": row["expiry_index_root_digest"],
        "workPageId": row["work_page_id"],
    }


def aggregate_row(*, capacity=MAX_PENDING, live=0, kind=AUDIT_KIND,
    partition=AUDIT_PARTITION, reserved=None, committed=None):
    row = {
        "aggregate_id": f"{kind}:{partition}", "aggregate_kind": kind,
        "partition_digest": partition, "revision": 7,
        "live_count": live, "active_count": live, "capacity_limit": capacity,
        "reserved_units_json": canonical({} if reserved is None else reserved).decode("ascii"),
        "committed_units_json": canonical({} if committed is None else committed).decode("ascii"),
        "next_sequence": 11, "minimum_expiry_epoch_ns": None,
        "expiry_index_root_digest": EXPIRY_ROOT, "work_page_id": None,
        "updated_at_epoch_ns": 1_000_000_000,
        "source_revision": authority_contract.SOURCE_REVISION,
    }
    row["state_json"] = canonical(state_material(row)).decode("ascii")
    row["state_digest"] = framed("serverware.policyAuthorityAggregateState/v1", row["state_json"].encode("ascii"))
    return row


def context(row, *, operation="policy.genesis.prepare", additional_selected=()):
    key = {"aggregate_id": row["aggregate_id"]}
    selected = {
        "table": TABLE, "key": key,
        "keyDigest": framed("serverware.policyAuthorityBusinessKey/v1", TABLE.encode("ascii"), canonical(key)),
        "present": True, "row": copy.deepcopy(row), "contractSelector": None,
    }
    return core.KernelContext(operation=operation, arguments={},
        selected_rows=(selected, *copy.deepcopy(additional_selected)),
        database_now=NOW, request_digest=REQUEST_DIGEST)


def read_aggregate(ctx):
    row = ctx.selected_rows[0]["row"]
    return ctx.bounded_aggregate(aggregate_id=row["aggregate_id"],
        aggregate_kind=row["aggregate_kind"], partition_digest=row["partition_digest"])


def charge(ctx, *, delta=_DEFAULT, identity=_DEFAULT):
    return policy._aggregate_mutation(ctx,
        operation_id=operation_id(ctx.operation) if identity is _DEFAULT else identity,
        live_delta=CHARGES[ctx.operation] if delta is _DEFAULT else delta)


def audit_rows(operation="policy.genesis.prepare"):
    rows = []
    for ordinal in range(CHARGES[operation]):
        event = canonical({"componentOperation": operation, "ordinal": ordinal})
        rows.append({
            "id": "policy-authority:" + hashlib.sha256(event).hexdigest(),
            "event_type": "policy.authority.component", "actor_type": "admin",
            "actor_id": "component-actor", "event_json": event.decode("ascii"),
            "event_digest": framed("serverware.metadataAuditOutboxEvent/v1", event),
            "storage_format_version": 2, "status": "pending", "claim_id": None,
            "claimed_at": None, "attempts": 0, "audited_at": None,
            "audit_event_hash": None, "last_error": None, "created_at": NOW.isoformat(),
        })
    return tuple(rows)


def audit_selection(item_id, *, present=False, row=None):
    key = {"id": item_id}
    return {"table": "metadata_audit_outbox", "key": key,
        "keyDigest": framed("serverware.policyAuthorityBusinessKey/v1",
            b"metadata_audit_outbox", canonical(key)),
        "present": present, "row": copy.deepcopy(row), "contractSelector": None}


def audit_context(operation="policy.genesis.prepare", *, live=0, selections=None):
    rows = audit_rows(operation)
    selected = tuple(audit_selection(row["id"]) for row in rows) if selections is None else selections
    return context(aggregate_row(live=live), operation=operation, additional_selected=selected), rows


def audit_mutations(ctx, rows, *, identity=_DEFAULT):
    return policy._audit_capacity_mutations(ctx,
        operation_id=operation_id(ctx.operation) if identity is _DEFAULT else identity,
        outbox_rows=rows)


class AuditCapacityTests(unittest.TestCase):
    def test_source_limit_and_both_real_consumers_share_the_contract(self):
        self.assertIs(type(MAX_PENDING), int)
        self.assertEqual(MAX_PENDING, 100_000)
        self.assertEqual(policy._AUDIT_CAPACITY_ID, AUDIT_ID)
        self.assertEqual(policy._AUDIT_CAPACITY_PARTITION_DIGEST, AUDIT_PARTITION)
        self.assertEqual(policy._EMPTY_EXPIRY_ROOT, EXPIRY_ROOT)
        # Supplemental source linkage only; do not import the DB/registry to
        # manufacture startup or pretend this exercises its global COUNT.
        for filename in ("db.py", "authority_transition_policy.py"):
            tree = ast.parse((ROOT / "serverware" / filename).read_text(encoding="utf-8"))
            aliases = {alias.asname or alias.name
                for node in tree.body if isinstance(node, ast.ImportFrom)
                and node.module == "serverware.audit_outbox_contract"
                for alias in node.names if alias.name == "MAX_PENDING"}
            self.assertEqual(len(aliases), 1, filename)
            if filename == "db.py":
                values = [node.value for node in tree.body if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == "_METADATA_AUDIT_OUTBOX_MAX_PENDING"
                        for target in node.targets)]
                self.assertEqual(len(values), 1)
                self.assertIsInstance(values[0], ast.Name)
                self.assertIn(values[0].id, aliases)
            else:
                helper = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == "_aggregate_mutation")
                self.assertTrue(any(isinstance(node, ast.Name) and node.id in aliases for node in ast.walk(helper)))

    def test_last_single_unit_is_planned_with_exact_cas_and_independent_state_hash(self):
        ctx = context(aggregate_row(live=99_999))
        before = copy.deepcopy(ctx.selected_rows)
        self.assertEqual(read_aggregate(ctx)["capacity_limit"], 100_000)
        mutation = charge(ctx)
        self.assertEqual(mutation["operation"], "UPDATE")
        self.assertEqual(mutation["table"], TABLE)
        self.assertEqual(mutation["key"], {"aggregate_id": AUDIT_ID})
        self.assertEqual(mutation["expectedRow"], before[0]["row"])
        self.assertEqual(mutation["keyDigest"], before[0]["keyDigest"])
        updated = mutation["row"]
        self.assertEqual((updated["live_count"], updated["active_count"], updated["capacity_limit"]),
            (100_000, 100_000, 100_000))
        self.assertEqual((updated["revision"], updated["next_sequence"], updated["updated_at_epoch_ns"]),
            (8, 12, NOW_NS))
        self.assertEqual(json.loads(updated["committed_units_json"]), {operation_id(ctx.operation): 1})
        self.assertEqual(updated["state_json"].encode("ascii"), canonical(state_material(updated)))
        self.assertEqual(updated["state_digest"], framed("serverware.policyAuthorityAggregateState/v1",
            canonical(state_material(updated))))
        self.assertEqual(read_aggregate(context(updated)), updated)
        self.assertEqual(ctx.selected_rows, before)

    def test_full_capacity_refuses_another_unit_without_mutating_input(self):
        ctx = context(aggregate_row(live=100_000))
        before = copy.deepcopy(ctx.selected_rows)
        read_aggregate(ctx)
        with self.assertRaisesRegex(core.TransitionKernelError, "bounded aggregate capacity transition is invalid"):
            charge(ctx)
        self.assertEqual(ctx.selected_rows, before)

    def test_all_four_source_operations_charge_their_exact_positive_count(self):
        for operation, units in CHARGES.items():
            with self.subTest(operation=operation):
                ctx = context(aggregate_row(live=100_000 - units), operation=operation)
                updated = charge(ctx)["row"]
                self.assertEqual(updated["live_count"], 100_000)
                self.assertEqual(updated["active_count"], 100_000)
                self.assertEqual(updated["next_sequence"], 11 + units)
                self.assertEqual(json.loads(updated["committed_units_json"]), {operation_id(operation): units})

    def test_seven_event_charge_cannot_partially_fit_six_free_slots(self):
        ctx = context(aggregate_row(live=99_994), operation="policy.activation.prepare")
        before = copy.deepcopy(ctx.selected_rows)
        read_aggregate(ctx)
        with self.assertRaisesRegex(core.TransitionKernelError, "bounded aggregate capacity transition is invalid"):
            charge(ctx)
        self.assertEqual(ctx.selected_rows, before)

    def test_coherently_rehashed_smaller_and_larger_capacity_cannot_set_audit_policy(self):
        for capacity in (99_999, 100_001):
            with self.subTest(capacity=capacity):
                row = aggregate_row(capacity=capacity, live=capacity - 1)
                ctx = context(row)
                # The row is self-consistent and its one-unit update would fit
                # the generic capacity. Only the audit's source policy rejects.
                self.assertEqual(read_aggregate(ctx), row)
                before = copy.deepcopy(ctx.selected_rows)
                with self.assertRaisesRegex(core.TransitionKernelError,
                    "audit capacity limit differs from the source contract"):
                    charge(ctx)
                self.assertEqual(ctx.selected_rows, before)

    def test_capacity_types_are_exact_without_loosening_generic_validation(self):
        for capacity in (True, False, None, "100000", 100000.0):
            with self.subTest(capacity=capacity, type=type(capacity).__name__):
                ctx = context(aggregate_row(capacity=capacity))
                with self.assertRaisesRegex(core.TransitionKernelError, "bounded aggregate state is not authoritative"):
                    charge(ctx)
        class IntegerSubclass(int):
            pass
        ctx = context(aggregate_row(capacity=IntegerSubclass(100_000)))
        read_aggregate(ctx)
        with self.assertRaisesRegex(core.TransitionKernelError,
            "audit capacity limit differs from the source contract"):
            charge(ctx)

    def test_reserved_and_committed_operation_ids_cannot_be_charged_again(self):
        identity = operation_id("policy.genesis.prepare")
        for field in ("reserved", "committed"):
            with self.subTest(field=field):
                ctx = context(aggregate_row(live=1, **{field: {identity: 1}}))
                before = copy.deepcopy(ctx.selected_rows)
                read_aggregate(ctx)
                with self.assertRaisesRegex(core.TransitionKernelError, "audit capacity reservation identity was reused"):
                    charge(ctx)
                self.assertEqual(ctx.selected_rows, before)

    def test_charge_identity_is_bound_to_the_actual_operation_and_request(self):
        ctx = context(aggregate_row())
        class StringSubclass(str):
            pass
        for identity in (None, True, "", "caller-selected", StringSubclass(operation_id(ctx.operation)),
            operation_id("policy.activation.prepare"),
            framed("serverware.policyAuthorityOperation/v2", ctx.operation.encode(), b"sha256:" + b"f" * 64)):
            with self.subTest(identity=identity), self.assertRaisesRegex(core.TransitionKernelError,
                "audit capacity charge differs from the source operation"):
                charge(ctx, identity=identity)

    def test_zero_negative_wrong_and_noninteger_charges_cannot_change_fixed_cost(self):
        for operation, units in CHARGES.items():
            ctx = context(aggregate_row(), operation=operation)
            for delta in (None, 0, -1, units + 1, True, False, float(units), str(units)):
                with self.subTest(operation=operation, delta=delta), self.assertRaisesRegex(core.TransitionKernelError,
                    "audit capacity charge differs from the source operation"):
                    charge(ctx, delta=delta)

    def test_other_manifest_operation_cannot_call_the_audit_charge_wrapper(self):
        ctx = context(aggregate_row(), operation="policy.genesis.finalize")
        read_aggregate(ctx)
        with self.assertRaisesRegex(core.TransitionKernelError,
            "audit capacity charge differs from the source operation"):
            charge(ctx, delta=1)
        with self.assertRaisesRegex(core.TransitionKernelError,
            "audit capacity records differ from the source operation"):
            audit_mutations(ctx, audit_rows())

    def test_existing_state_hash_and_source_revision_checks_still_apply(self):
        baseline = aggregate_row()
        for field, value in (("state_digest", "sha256:" + "f" * 64),
            ("live_count", 1), ("source_revision", "caller-revision")):
            row = {**baseline, field: value}
            with self.subTest(field=field), self.assertRaisesRegex(core.TransitionKernelError,
                "bounded aggregate state is not authoritative"):
                charge(context(row))

    def test_non_audit_generic_aggregates_keep_their_own_capacity_semantics(self):
        kind = "local-component-generic-capacity"
        partition = framed("serverware.policyAuthorityAggregatePartition/v1", b"non-audit-component")
        for limit in (3, 100_001):
            ctx = context(aggregate_row(capacity=limit, live=limit - 1, kind=kind, partition=partition))
            row = read_aggregate(ctx)
            kwargs = dict(aggregate_id=row["aggregate_id"], aggregate_kind=kind,
                partition_digest=partition, live_delta=1, active_delta=1,
                reserved_units={}, committed_units={"component-unit": 1}, next_sequence_delta=1,
                minimum_expiry_epoch_ns=None, expiry_index_root_digest=EXPIRY_ROOT, work_page_id=None)
            mutation = ctx.update_bounded_aggregate(**kwargs)
            self.assertEqual(mutation["row"]["capacity_limit"], limit)
            self.assertEqual(mutation["row"]["live_count"], limit)
            full = context(mutation["row"])
            with self.assertRaisesRegex(core.TransitionKernelError, "bounded aggregate capacity transition is invalid"):
                full.update_bounded_aggregate(**kwargs)

    def test_composed_helper_returns_exact_aggregate_update_and_all_actual_inserts(self):
        for operation, count in CHARGES.items():
            with self.subTest(operation=operation):
                ctx, rows = audit_context(operation, live=100_000 - count)
                before = copy.deepcopy((ctx.selected_rows, rows))
                mutations = audit_mutations(ctx, rows)
                self.assertIs(type(mutations), tuple)
                self.assertEqual(len(mutations), 1 + count)
                self.assertEqual(mutations[0], charge(ctx))
                self.assertEqual(mutations[0]["row"]["live_count"], 100_000)
                expected_template, = [entry["templateId"]
                    for entry in authority_contract.operation_spec(operation)["mutationTemplates"]
                    if entry["table"] == "metadata_audit_outbox" and entry["mutation"] == "INSERT"]
                for row, mutation in zip(rows, mutations[1:]):
                    self.assertEqual(set(mutation), {"templateId", "operation", "table", "key",
                        "keyDigest", "expectedRow", "row"})
                    self.assertEqual(mutation, {
                        "templateId": expected_template, "operation": "INSERT",
                        "table": "metadata_audit_outbox", "key": {"id": row["id"]},
                        "keyDigest": audit_selection(row["id"])["keyDigest"],
                        "expectedRow": None, "row": row,
                    })
                self.assertEqual((ctx.selected_rows, rows), before)

    def test_composed_helper_capacity_failure_returns_no_partial_mutations(self):
        for operation, count in CHARGES.items():
            ctx, rows = audit_context(operation, live=100_000 - count + 1)
            before = copy.deepcopy((ctx.selected_rows, rows))
            with self.subTest(operation=operation), self.assertRaisesRegex(core.TransitionKernelError,
                "bounded aggregate capacity transition is invalid"):
                audit_mutations(ctx, rows)
            self.assertEqual((ctx.selected_rows, rows), before)

    def test_composed_helper_rejects_existing_pending_claimed_and_audited_identities(self):
        for status in ("pending", "claimed", "audited"):
            proposed = audit_rows()[0]
            existing = {**proposed, "status": status}
            if status == "claimed":
                existing.update(claim_id="claim-component", claimed_at=NOW.isoformat())
            if status == "audited":
                existing.update(audited_at=NOW.isoformat(), audit_event_hash="sha256:" + "a" * 64)
            ctx, rows = audit_context(selections=(audit_selection(proposed["id"], present=True, row=existing),))
            before = copy.deepcopy((ctx.selected_rows, rows))
            # Even byte-identical pending data cannot silently become UPDATE
            # while the helper charges for a fresh INSERT.
            with self.subTest(status=status), self.assertRaisesRegex(core.TransitionKernelError,
                "fresh audit identity is not proven absent"):
                audit_mutations(ctx, rows)
            self.assertEqual((ctx.selected_rows, rows), before)

    def test_composed_helper_requires_exact_false_presence_and_null_absent_row(self):
        proposed = audit_rows()[0]
        cases = [audit_selection(proposed["id"], present=value) for value in (None, 0, "false")]
        cases.extend(audit_selection(proposed["id"], row=row) for row in ({}, proposed))
        missing_presence = audit_selection(proposed["id"])
        del missing_presence["present"]
        cases.append(missing_presence)
        missing_row = audit_selection(proposed["id"])
        del missing_row["row"]
        cases.append(missing_row)
        for selected in cases:
            ctx, rows = audit_context(selections=(selected,))
            with self.subTest(selected=selected), self.assertRaisesRegex(core.TransitionKernelError,
                "fresh audit identity is not proven absent"):
                audit_mutations(ctx, rows)

    def test_composed_helper_requires_one_exact_selector_for_every_requested_identity(self):
        proposed = audit_rows()[0]
        selected = audit_selection(proposed["id"])
        for selections in ((), (selected, copy.deepcopy(selected))):
            ctx, rows = audit_context(selections=selections)
            with self.subTest(count=len(selections)), self.assertRaisesRegex(core.TransitionKernelError,
                "authority transition exact row is absent or ambiguous"):
                audit_mutations(ctx, rows)

    def test_composed_helper_closes_record_container_count_mapping_and_id_types(self):
        ctx, rows = audit_context()
        class StringSubclass(str):
            pass
        invalid = [None, list(rows), {"rows": rows}, (), rows + rows,
            (None,), ("row",), (1,), ({},)]
        invalid.extend(({**rows[0], "id": value},) for value in (
            None, True, 1, "", "non-ascii-\u00e9", "x" * 257, StringSubclass(rows[0]["id"])))
        invalid.extend(({**rows[0], "status": value},) for value in (None, True, "claimed", "audited", "revoked"))
        invalid.append(({key: value for key, value in rows[0].items() if key != "status"},))
        for value in invalid:
            with self.subTest(value=value), self.assertRaisesRegex(core.TransitionKernelError,
                "audit capacity records differ from the source operation"):
                audit_mutations(ctx, value)
        ctx, rows = audit_context("policy.activation.prepare")
        for value in (rows[:-1], rows + ({**rows[0], "id": "additional-component-audit"},)):
            with self.subTest(count=len(value)), self.assertRaisesRegex(core.TransitionKernelError,
                "audit capacity records differ from the source operation"):
                audit_mutations(ctx, value)

    def test_composed_helper_accepts_the_declared_ascii_identity_size_boundary(self):
        identity = "x" * 256
        row = {**audit_rows()[0], "id": identity}
        ctx = context(aggregate_row(), additional_selected=(audit_selection(identity),))
        mutations = audit_mutations(ctx, (row,))
        self.assertEqual(len(mutations), 2)
        self.assertEqual(mutations[1]["operation"], "INSERT")
        self.assertEqual(mutations[1]["key"], {"id": identity})
        self.assertEqual(mutations[1]["row"], row)

    def test_composed_helper_rejects_duplicate_ids_even_with_exact_record_count(self):
        ctx, rows = audit_context("policy.activation.prepare")
        duplicates = (rows[0], {**rows[1], "id": rows[0]["id"]}, *rows[2:])
        self.assertEqual(len(duplicates), 7)
        with self.assertRaisesRegex(core.TransitionKernelError,
            "audit capacity records differ from the source operation"):
            audit_mutations(ctx, duplicates)

    def test_composed_helper_cannot_substitute_a_different_absent_identity_or_charge_id(self):
        ctx, rows = audit_context()
        changed = ({**rows[0], "id": "different-component-audit"},)
        with self.assertRaisesRegex(core.TransitionKernelError,
            "authority transition exact row is absent or ambiguous"):
            audit_mutations(ctx, changed)
        for identity in (None, "caller-selected", operation_id("policy.activation.prepare")):
            with self.subTest(identity=identity), self.assertRaisesRegex(core.TransitionKernelError,
                "audit capacity charge differs from the source operation"):
                audit_mutations(ctx, rows, identity=identity)


if __name__ == "__main__":
    unittest.main()
