#!/usr/bin/env python3
"""Pure global-capacity components using real source contracts and contexts.

No DB, registry replacement, authenticated baseline, delivery receipt, SQL,
planner integration, or independent currentness authority is simulated here.
Fixtures independently frame state/key hashes; this is not a whole-operation
business-kernel success fixture. Native SQL parity is a separate component.
"""
from __future__ import annotations

import copy
import hashlib
import json
import sys
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_audit_capacity as capacity
from serverware import authority_contract
from serverware import authority_transition_core as core


OPERATION = "policy.genesis.prepare"
TABLE = "policy_authority_bounded_aggregate_states"
OUTBOX = "metadata_audit_outbox"
KIND = "metadata-audit-outbox-global-capacity-v1"
NOW = datetime(1970, 1, 1, 0, 0, 2, tzinfo=timezone.utc)
NOW_NS = 2_000_000_000
MAX_INTEGER = 2**63 - 1
REQUEST = "sha256:" + hashlib.sha256(b"global-capacity-component").hexdigest()
_MISSING = object()


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode("ascii")


def framed(domain, *frames):
    digest = hashlib.sha256(domain.encode("ascii") + b"\0")
    for frame in frames:
        digest.update(len(frame).to_bytes(8, "big"))
        digest.update(frame)
    return "sha256:" + digest.hexdigest()


PARTITION = framed("serverware.metadataAuditOutboxCapacityPartition/v1", b"global")
IDENTITY = f"{KIND}:{PARTITION}"
EMPTY = framed("serverware.policyAuthorityAggregateExpiryIndex/v1", b"[]")


def refresh_state(row):
    material = {
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
    row["state_json"] = canonical(material).decode("ascii")
    row["state_digest"] = framed("serverware.policyAuthorityAggregateState/v1", canonical(material))
    return row


def counter_row(**changes):
    return refresh_state({
        "aggregate_id": IDENTITY, "aggregate_kind": KIND, "partition_digest": PARTITION,
        "revision": 7, "live_count": 0, "active_count": 0, "capacity_limit": 100_000,
        "reserved_units_json": "{}", "committed_units_json": "{}", "next_sequence": 19,
        "minimum_expiry_epoch_ns": None, "expiry_index_root_digest": EMPTY,
        "work_page_id": None, "updated_at_epoch_ns": 1_000_000_000,
        "source_revision": authority_contract.SOURCE_REVISION, **changes,
    })


def outbox_row(item_id="audit-one", status="pending", **changes):
    event = canonical({"event": item_id})
    return {
        "id": item_id, "event_type": "component.audit", "actor_type": "admin", "actor_id": "owner",
        "event_json": event.decode("ascii"),
        "event_digest": framed("serverware.metadataAuditOutboxEvent/v1", event),
        "storage_format_version": 2, "status": status, "claim_id": None, "claimed_at": None,
        "attempts": 0, "audited_at": None, "audit_event_hash": None, "last_error": None,
        "created_at": NOW.isoformat(), **changes,
    }


def selected(table, key, row):
    return {
        "table": table, "key": copy.deepcopy(key),
        "keyDigest": framed("serverware.policyAuthorityBusinessKey/v1", table.encode("ascii"), canonical(key)),
        "present": row is not None, "row": copy.deepcopy(row), "contractSelector": None,
    }


def mutation(selection, row, operation=OPERATION, *, kind=None):
    kind = kind or ("DELETE" if row is None else "UPDATE" if selection["present"] else "INSERT")
    templates = [item for item in authority_contract.operation_spec(operation)["mutationTemplates"]
        if item["table"] == selection["table"] and item["mutation"] == kind]
    if len(templates) != 1:
        raise AssertionError("fixture operation lacks the requested real mutation template")
    return {
        "templateId": templates[0]["templateId"], "operation": kind, "table": selection["table"],
        "key": copy.deepcopy(selection["key"]), "keyDigest": selection["keyDigest"],
        "expectedRow": copy.deepcopy(selection["row"]), "row": copy.deepcopy(row),
    }


def fixture(images, *, before=_MISSING, operation=OPERATION, now=NOW):
    before = counter_row() if before is _MISSING else before
    selections = [selected(TABLE, {"aggregate_id": IDENTITY}, before)]
    changes = []
    for old, new in images:
        image = new if new is not None else old
        selection = selected(OUTBOX, {"id": image["id"]}, old)
        selections.append(selection)
        changes.append(mutation(selection, new, operation))
    context = core.KernelContext(operation=operation, arguments={}, selected_rows=tuple(selections),
        database_now=now, request_digest=REQUEST)
    return context, tuple(changes)


def verify(context, mutations):
    capacity.validate_capacity_transition(operation=context.operation,
        selected_rows=context.selected_rows, mutations=mutations)


class GlobalAuditCapacityTests(unittest.TestCase):
    def test_source_identity_is_new_and_query_uses_real_contract(self):
        self.assertEqual(capacity.AGGREGATE_ID, IDENTITY)
        self.assertEqual(capacity.PARTITION_DIGEST, PARTITION)
        self.assertEqual(capacity.EMPTY_EXPIRY_DIGEST, EMPTY)
        self.assertEqual(capacity.MAX_PENDING, 100_000)
        for old in ("metadata-audit-outbox", "metadata-audit-outbox-capacity"):
            self.assertNotEqual(KIND, old)
        queries = capacity.add_capacity_query(OPERATION, ())
        self.assertEqual(len(queries), 1)
        self.assertEqual(queries[0].table, TABLE)
        self.assertEqual(queries[0].absent_key, {"aggregate_id": IDENTITY})
        self.assertFalse(queries[0].require_absence)
        self.assertEqual(queries[0].maximum_rows, 1)
        self.assertEqual(capacity.add_capacity_query("webauthn.counter.cas", ()), ())

    def test_query_collisions_and_ambiguous_aggregate_queries_reject(self):
        query = capacity.add_capacity_query(OPERATION, ())[0]
        for supplied in (query, replace(query, query_id=query.query_id + "_alias"),
                replace(query, absent_key=None, predicates=(), maximum_rows=2)):
            with self.subTest(query=supplied.query_id), self.assertRaisesRegex(
                    capacity.AuditCapacityError, "query identity is caller supplied"):
                capacity.add_capacity_query(OPERATION, (supplied,))
        other = replace(query, query_id=query.query_id + "_other",
            predicates=(core.QueryPredicate("aggregate_id", "eq", "different-source-counter"),),
            absent_key={"aggregate_id": "different-source-counter"})
        self.assertEqual(capacity.add_capacity_query(OPERATION, (other,))[0], other)
        with self.assertRaisesRegex(capacity.AuditCapacityError, "source declared"):
            capacity.add_capacity_query("unregistered.operation", ())

    def test_fresh_insert_returns_one_exact_counter_cas_at_capacity_boundary(self):
        before = counter_row(live_count=99_999, active_count=99_999)
        context, changes = fixture([(None, outbox_row())], before=before)
        original = copy.deepcopy((context.selected_rows, changes))
        result = capacity.finalize_capacity(context, changes)
        verify(context, result)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], changes[0])
        self.assertEqual(result[1]["operation"], "UPDATE")
        self.assertEqual(result[1]["expectedRow"], before)
        expected = refresh_state({**before, "revision": 8, "live_count": 100_000,
            "active_count": 100_000, "next_sequence": 20, "updated_at_epoch_ns": NOW_NS})
        self.assertEqual(result[1]["row"], expected)
        result[0]["row"]["event_json"] = "changed only returned copy"
        self.assertEqual((context.selected_rows, changes), original)

    def test_all_status_pairs_and_same_value_update(self):
        for old_status in ("pending", "claimed", "audited"):
            for new_status in ("pending", "claimed", "audited"):
                with self.subTest(old=old_status, new=new_status):
                    old = outbox_row(status=old_status)
                    new = {**old, "status": new_status}
                    count = int(old_status != "audited")
                    context, changes = fixture([(old, new)],
                        before=counter_row(live_count=count, active_count=count))
                    if old_status == "audited" and new_status != "audited":
                        with self.assertRaisesRegex(capacity.AuditCapacityError, "cannot reopen"):
                            capacity.finalize_capacity(context, changes)
                        continue
                    result = capacity.finalize_capacity(context, changes)
                    verify(context, result)
                    after = result[-1]["row"]
                    self.assertEqual(after["live_count"], int(new_status != "audited"))
                    self.assertEqual(after["revision"], 8)
                    self.assertEqual(after["next_sequence"], 19)

    def test_complete_batch_net_zero_still_records_insert_sequence_and_revision(self):
        pending, claimed = outbox_row("a"), outbox_row("b", "claimed")
        context, changes = fixture([
            (pending, {**pending, "status": "audited"}),
            (claimed, {**claimed, "status": "pending"}),
            (None, outbox_row("c")),
        ], before=counter_row(live_count=2, active_count=2))
        result = capacity.finalize_capacity(context, changes)
        verify(context, result)
        self.assertEqual(len(result), 4)
        self.assertEqual(result[-1]["row"]["live_count"], 2)
        self.assertEqual(result[-1]["row"]["next_sequence"], 20)
        self.assertEqual(result[-1]["row"]["revision"], 8)
        reverse = capacity.finalize_capacity(context, tuple(reversed(changes)))
        self.assertEqual(reverse[-1], result[-1])

    def test_empty_replay_stays_empty_but_still_requires_valid_baseline(self):
        context, _ = fixture([])
        self.assertEqual(capacity.finalize_capacity(context, ()), ())
        verify(context, ())
        for selections in ((), (selected(TABLE, {"aggregate_id": IDENTITY}, None),)):
            invalid = replace(context, selected_rows=selections)
            with self.assertRaisesRegex(capacity.AuditCapacityError, "before row"):
                capacity.finalize_capacity(invalid, ())
            with self.assertRaisesRegex(capacity.AuditCapacityError, "before row"):
                verify(invalid, ())
        for selector in ("caller-selector", "x" * 8192):
            selections = copy.deepcopy(context.selected_rows)
            selections[0]["contractSelector"] = selector
            with self.assertRaisesRegex(capacity.AuditCapacityError, "before row is not exact"):
                verify(replace(context, selected_rows=selections), ())

    def test_missing_extra_duplicate_and_kernel_supplied_counter_reject(self):
        context, changes = fixture([(None, outbox_row())])
        result = capacity.finalize_capacity(context, changes)
        with self.assertRaisesRegex(capacity.AuditCapacityError, "missing or duplicated"):
            verify(context, changes)
        with self.assertRaisesRegex(capacity.AuditCapacityError, "unique selected identity"):
            verify(context, (*result, result[-1]))
        with self.assertRaisesRegex(capacity.AuditCapacityError, "kernel supplied"):
            capacity.finalize_capacity(context, result)
        with self.assertRaisesRegex(capacity.AuditCapacityError, "no outbox mutations"):
            verify(context, (result[-1],))

    def test_fresh_insert_status_and_invalid_status_vocabulary_reject(self):
        for status in ("claimed", "audited", "", None, True, 1, "PENDING"):
            with self.subTest(status=status):
                context, changes = fixture([(None, outbox_row(status=status))])
                with self.assertRaises(capacity.AuditCapacityError):
                    capacity.finalize_capacity(context, changes)

    def test_capacity_underflow_and_numeric_overflow_reject(self):
        pending = outbox_row()
        cases = (
            (counter_row(live_count=100_000, active_count=100_000), [(None, pending)]),
            (counter_row(), [(pending, {**pending, "status": "audited"})]),
            (counter_row(revision=MAX_INTEGER), [(None, pending)]),
            (counter_row(next_sequence=MAX_INTEGER), [(None, pending)]),
        )
        for before, images in cases:
            with self.subTest(before=before):
                context, changes = fixture(images, before=before)
                with self.assertRaisesRegex(capacity.AuditCapacityError, "transition exceeds"):
                    capacity.finalize_capacity(context, changes)

    def test_compact_before_profile_rejects_self_consistent_alternatives(self):
        cases = (
            {"capacity_limit": 99_999}, {"capacity_limit": 100_001},
            {"live_count": 1, "active_count": 0}, {"live_count": True},
            {"revision": 0}, {"revision": MAX_INTEGER + 1},
            {"next_sequence": -1}, {"next_sequence": True},
            {"updated_at_epoch_ns": -1}, {"updated_at_epoch_ns": True},
            {"reserved_units_json": '{"caller":1}'}, {"committed_units_json": '{"old":1}'},
            {"reserved_units_json": "{ }"}, {"minimum_expiry_epoch_ns": 1},
            {"work_page_id": "page"}, {"expiry_index_root_digest": REQUEST},
            {"source_revision": "other-source"}, {"extra": 1},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                context, mutations = fixture([(None, outbox_row())], before=counter_row(**changes))
                with self.assertRaises(capacity.AuditCapacityError):
                    capacity.finalize_capacity(context, mutations)

    def test_old_counter_and_forged_commitments_do_not_supply_baseline(self):
        old = counter_row(aggregate_kind="metadata-audit-outbox-capacity", partition_digest=REQUEST,
            aggregate_id="metadata-audit-outbox-capacity:" + REQUEST)
        context, changes = fixture([(None, outbox_row())])
        legacy_selected = selected(TABLE, {"aggregate_id": old["aggregate_id"]}, old)
        with self.assertRaisesRegex(capacity.AuditCapacityError, "before row is missing"):
            capacity.finalize_capacity(replace(context, selected_rows=(legacy_selected, *context.selected_rows[1:])), changes)
        for field, value in (("state_json", "{}"), ("state_digest", REQUEST)):
            row = counter_row()
            row[field] = value
            context, changes = fixture([(None, outbox_row())], before=row)
            with self.assertRaisesRegex(capacity.AuditCapacityError, "before commitment changed"):
                capacity.finalize_capacity(context, changes)

    def test_selected_identity_old_image_and_original_key_are_exact(self):
        old = outbox_row()
        context, changes = fixture([(old, {**old, "status": "audited"})],
            before=counter_row(live_count=1, active_count=1))
        for mode in ("stale", "bool-integer", "moved-key", "wrong-key-digest", "missing-image", "extra-field"):
            bad = copy.deepcopy(changes[0])
            if mode == "stale":
                bad["expectedRow"]["event_json"] = "{}"
            elif mode == "bool-integer":
                bad["expectedRow"]["attempts"] = False
            elif mode == "moved-key":
                bad["row"]["id"] = "other"
            elif mode == "wrong-key-digest":
                bad["keyDigest"] = REQUEST
            elif mode == "missing-image":
                del bad["expectedRow"]
            else:
                bad["callerDelta"] = -1
            with self.subTest(mode=mode), self.assertRaises(capacity.AuditCapacityError):
                capacity.finalize_capacity(context, (bad,))
        with self.assertRaisesRegex(capacity.AuditCapacityError, "unique selected identity"):
            capacity.finalize_capacity(context, (*changes, changes[0]))
        with self.assertRaisesRegex(capacity.AuditCapacityError, "duplicated or changed"):
            capacity.finalize_capacity(replace(context,
                selected_rows=(*context.selected_rows, context.selected_rows[-1])), changes)

    def test_independently_rehashed_wrong_delta_and_counter_fields_reject(self):
        context, changes = fixture([(None, outbox_row())])
        result = capacity.finalize_capacity(context, changes)
        for updates in ({"live_count": 0, "active_count": 0}, {"revision": 9},
                {"next_sequence": 19}, {"capacity_limit": 100_001},
                {"committed_units_json": '{"injected":1}'},
                {"aggregate_id": "another-counter"}):
            bad = copy.deepcopy(result)
            bad[-1]["row"].update(updates)
            refresh_state(bad[-1]["row"])
            with self.subTest(updates=updates), self.assertRaises(capacity.AuditCapacityError):
                verify(context, bad)
        bad = copy.deepcopy(result)
        bad[-1]["key"] = {"aggregate_id": "another-counter"}
        with self.assertRaises(capacity.AuditCapacityError):
            verify(context, bad)

    def test_explicit_timestamp_binding_and_validator_time_limitation(self):
        context, changes = fixture([(None, outbox_row())])
        result = capacity.finalize_capacity(context, changes)
        for timestamp in (True, -1, 999_999_999, MAX_INTEGER + 1, "2000000000"):
            bad = copy.deepcopy(result)
            bad[-1]["row"]["updated_at_epoch_ns"] = timestamp
            with self.subTest(timestamp=timestamp), self.assertRaisesRegex(
                    capacity.AuditCapacityError, "update time is invalid"):
                verify(context, bad)
        # Validator proves only exact range/monotonicity, not fresh authority time.
        later = copy.deepcopy(result)
        later[-1]["row"]["updated_at_epoch_ns"] = MAX_INTEGER
        verify(context, later)
        with self.assertRaisesRegex(capacity.AuditCapacityError, "time is not explicit"):
            capacity.finalize_capacity(replace(context, database_now=NOW.replace(tzinfo=None)), changes)
        context, changes = fixture([(None, outbox_row())], before=counter_row(updated_at_epoch_ns=NOW_NS + 1))
        with self.assertRaisesRegex(capacity.AuditCapacityError, "update time is invalid"):
            capacity.finalize_capacity(context, changes)

    def test_id_utf8_bound_and_lossless_json_types(self):
        valid = "\U0001f680" * 64
        context, changes = fixture([(None, outbox_row(valid))])
        verify(context, capacity.finalize_capacity(context, changes))
        for identity in ("", True, 12, "a" * 257, valid + "x"):
            with self.subTest(identity=identity):
                context, changes = fixture([(None, outbox_row(identity))])
                with self.assertRaisesRegex(capacity.AuditCapacityError, "identity is not a bounded string"):
                    capacity.finalize_capacity(context, changes)
        context, changes = fixture([(None, outbox_row())])
        for value in (1.0, bytearray(b"x"), "\ud800", "\u0000"):
            bad = copy.deepcopy(changes)
            bad[0]["row"]["unsupported"] = value
            with self.subTest(value=repr(value)), self.assertRaisesRegex(capacity.AuditCapacityError, "not lossless"):
                capacity.finalize_capacity(context, bad)
        bad = copy.deepcopy(changes)
        bad[0]["row"]["\u0000"] = "unsupported key"
        with self.assertRaisesRegex(capacity.AuditCapacityError, "not lossless"):
            capacity.finalize_capacity(context, bad)

    def test_delete_arithmetic_does_not_grant_missing_delete_template(self):
        self.assertFalse(any(t["table"] == OUTBOX and t["mutation"] == "DELETE"
            for t in authority_contract.operation_spec(OPERATION)["mutationTemplates"]))
        old = outbox_row()
        context, changes = fixture([(old, {**old, "status": "audited"})],
            before=counter_row(live_count=1, active_count=1))
        forged = copy.deepcopy(changes[0])
        forged.update(operation="DELETE", row=None)
        with self.assertRaisesRegex(capacity.AuditCapacityError, "template changed"):
            capacity.finalize_capacity(context, (forged,))
        # Arithmetic-only oracle; NOT an admitted DELETE or registry override.
        self.assertEqual(capacity._delta((forged,)), (-1, 0))
        forged["expectedRow"]["status"] = "audited"
        self.assertEqual(capacity._delta((forged,)), (0, 0))

    def test_compact_row_bound_and_nonparticipant_noop(self):
        maximum = counter_row(revision=MAX_INTEGER, live_count=100_000,
            active_count=100_000, next_sequence=MAX_INTEGER, updated_at_epoch_ns=MAX_INTEGER)
        self.assertLessEqual(len(canonical(maximum)), capacity.MAX_COUNTER_BYTES)
        self.assertEqual(maximum["reserved_units_json"], "{}")
        self.assertEqual(maximum["committed_units_json"], "{}")
        context, _ = fixture([], before=maximum)
        verify(context, ())
        unrelated = core.KernelContext(operation="webauthn.counter.cas", arguments={},
            selected_rows=(), database_now=NOW, request_digest=REQUEST)
        self.assertEqual(capacity.finalize_capacity(unrelated, ()), ())
        verify(unrelated, ())
        with self.assertRaises(capacity.AuditCapacityError):
            verify(replace(context, operation="webauthn.counter.cas"), ())

    def test_named_query_allowance_replaces_old_slot_or_adds_only_one(self):
        def business_queries(operation, count):
            return tuple(core.BoundedQuery(
                query_id=core.query_program_id(operation, f"business_{index}", OUTBOX),
                table=OUTBOX, predicates=(core.QueryPredicate("id", "eq", f"audit-{index}"),),
                order_by=(core.QueryOrder("id"),), maximum_rows=1,
                absent_key={"id": f"audit-{index}"},
            ) for index in range(count))

        for operation, business_maximum, total in (
                (OPERATION, 255, 256), ("webauthn.registration.create", 256, 257)):
            with self.subTest(operation=operation):
                spec = authority_contract.operation_spec(operation)
                self.assertEqual(spec["maximumBusinessQueryRows"], business_maximum)
                queries = business_queries(operation, business_maximum)
                composed = capacity.add_capacity_query(operation, queries)
                self.assertEqual(len(composed), total)
                self.assertEqual(composed[:-1], queries)
                with self.assertRaisesRegex(capacity.AuditCapacityError, "business bound"):
                    capacity.add_capacity_query(operation, business_queries(operation, business_maximum + 1))

    def test_framework_mutation_slot_cannot_subsidize_extra_business_changes(self):
        operation = "rbac.binding.mutate"
        spec = authority_contract.operation_spec(operation)
        self.assertEqual((spec["maximumBusinessQueryRows"], spec["maximumBusinessMutations"]), (5, 4))
        context, changes = fixture([(None, outbox_row(f"audit-{i}")) for i in range(5)], operation=operation)
        self.assertEqual(len(context.selected_rows), spec["maximumQueryRows"])
        self.assertEqual(len(changes), spec["maximumMutations"])
        # Fits the total mutation cap only by stealing the reserved counter slot.
        with self.assertRaisesRegex(capacity.AuditCapacityError, "business bound"):
            capacity.finalize_capacity(context, changes)
        with self.assertRaisesRegex(capacity.AuditCapacityError, "business bound"):
            verify(context, changes)

    def test_selected_byte_allowance_belongs_only_to_the_counter(self):
        context, _ = fixture([])
        row = outbox_row(padding="")
        choice = selected(OUTBOX, {"id": row["id"]}, row)
        choice["row"]["padding"] = "x" * (authority_contract.MAX_REQUEST_BYTES - len(canonical([choice])))
        selections = (*context.selected_rows, choice)
        self.assertEqual(len(canonical([choice])), authority_contract.MAX_REQUEST_BYTES)
        self.assertLess(len(canonical(list(selections))), authority_contract.MAX_PLAN_SELECTED_BYTES)
        verify(replace(context, selected_rows=selections), ())
        choice["row"]["padding"] += "x"
        with self.assertRaisesRegex(capacity.AuditCapacityError, "business bound"):
            verify(replace(context, selected_rows=selections), ())

    def test_work_charges_actual_query_and_counter_without_giving_noop_a_write_slot(self):
        context, changes = fixture([(None, outbox_row())])
        mutations = capacity.finalize_capacity(context, changes)
        business_maximum = authority_contract.operation_spec(OPERATION)["maximumBusinessWorkUnits"]
        self.assertEqual(capacity.transition_work_units(OPERATION, 1, 1, mutations), 3)
        self.assertEqual(capacity.transition_work_units(OPERATION, 1, business_maximum, mutations), business_maximum + 2)
        self.assertEqual(capacity.transition_work_units(OPERATION, 1, business_maximum, ()), business_maximum + 1)
        for work in (True, False, "3", 0, 1, 2, business_maximum + 3):
            with self.subTest(work=work), self.assertRaises(capacity.AuditCapacityError):
                capacity.validate_transition_work_units(OPERATION, work, mutations)
        with self.assertRaises(capacity.AuditCapacityError):
            capacity.validate_transition_work_units(OPERATION, business_maximum + 2, ())
        for query, kernel in ((0, 1), (True, 1), (1, True), (1, 0), (2, business_maximum)):
            with self.subTest(query=query, kernel=kernel), self.assertRaises(capacity.AuditCapacityError):
                capacity.transition_work_units(OPERATION, query, kernel, mutations)
        self.assertEqual(capacity.transition_work_units("webauthn.counter.cas", 0, 1, ()), 1)
        with self.assertRaises(capacity.AuditCapacityError):
            capacity.validate_transition_work_units("webauthn.counter.cas", 3, mutations)


if __name__ == "__main__":
    unittest.main()
