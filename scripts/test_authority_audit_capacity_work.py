#!/usr/bin/env python3
"""Shared work accounting for the genuine global audit-capacity workers.

Independent states, source-template fixtures and literal pass arithmetic define
the expected result and work. No verifier, hash or successful result is faked.
The private meter assumes caller-owned inputs; it is not a proof or pre-hash
ownership entrypoint, initialized capacity, currentness or kernel authority.
These authored controls are source-only and unrun.
"""
from __future__ import annotations

import copy
from dataclasses import fields, replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate import authority_audit_capacity as capacity
from catchplate import authority_query_read_work as accounting
import test_authority_global_audit_capacity as oracle


PARTICIPATING = {"policy.genesis.prepare", "policy.activation.prepare", "webauthn.credential.revoke"}


def wire(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def nodes(value):
    if type(value) is dict:
        return 1 + sum(1 + nodes(item) for item in value.values())
    if type(value) in (list, tuple):
        return 1 + sum(nodes(item) for item in value)
    return 1


def state_document(row):
    return {"schema": "catchplate.policyAuthorityAggregateState/v1",
        "aggregateId": row["aggregate_id"], "aggregateKind": row["aggregate_kind"],
        "partitionDigest": row["partition_digest"], "revision": row["revision"],
        "liveCount": row["live_count"], "activeCount": row["active_count"],
        "capacityLimit": row["capacity_limit"], "reservedUnits": {}, "committedUnits": {},
        "nextSequence": row["next_sequence"], "minimumExpiryEpochNs": None,
        "expiryIndexRootDigest": oracle.EMPTY, "workPageId": None}


def after_counter(context, changes):
    before = next(item["row"] for item in context.selected_rows
                  if item["table"] == oracle.TABLE and item["key"] == {"aggregate_id": oracle.IDENTITY})
    delta = inserted = 0
    for change in changes:
        if change["table"] != oracle.OUTBOX:
            continue
        old, new = change["expectedRow"], change["row"]
        old_count = int(old is not None and old["status"] in ("pending", "claimed"))
        new_count = int(new is not None and new["status"] in ("pending", "claimed"))
        delta += new_count - old_count
        inserted += int(change["operation"] == "INSERT") * new_count
    elapsed = context.database_now.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    timestamp = (elapsed.days * 86_400 + elapsed.seconds) * 1_000_000_000 + elapsed.microseconds * 1000
    return oracle.refresh_state({**before, "revision": before["revision"] + 1,
        "live_count": before["live_count"] + delta, "active_count": before["active_count"] + delta,
        "next_sequence": before["next_sequence"] + inserted, "updated_at_epoch_ns": timestamp})


def expected_result(context, changes):
    if not any(item["table"] == oracle.OUTBOX for item in changes):
        return tuple(copy.deepcopy(changes))
    selected = next(item for item in context.selected_rows if item["table"] == oracle.TABLE
                    and item["key"] == {"aggregate_id": oracle.IDENTITY})
    return (*tuple(copy.deepcopy(changes)), oracle.mutation(selected, after_counter(context, changes), context.operation))


class ExpectedWork:
    """Independent canonical sizes and declared source-value pass classes."""
    def __init__(self):
        self.hashes = self.bytes = self.nodes = 0
        self.encodings = self.parses = self.state_decodes = 0

    def canonical(self, value):
        self.bytes += 2 * len(wire(value))
        self.nodes += 2 * nodes(value)
        self.encodings += 1

    def copy(self, value):
        self.bytes += 2 * len(wire(value))
        self.nodes += 2 * nodes(value)

    def clone_json(self, value):
        self.bytes += 4 * len(wire(value))
        self.nodes += 3 * nodes(value)
        self.encodings += 1
        self.parses += 1

    def compare(self, left, right):
        for value in (left, right):
            self.bytes += 2 * len(wire(value))
            self.nodes += 2 * nodes(value)

    def canonical_equal(self, left, right):
        self.canonical(left)
        self.canonical(right)
        self.bytes += len(wire(left)) + len(wire(right))

    def utf8(self, value):
        self.bytes += 2 * len(value.encode("utf-8"))
        self.nodes += 2

    def decode_state(self, value):
        self.bytes += len(wire(value))
        self.state_decodes += 1

    def hash(self):
        self.hashes += 1

    def tuple(self):
        return self.hashes, self.bytes, self.nodes


def row_key_work(work, row, key):
    work.copy(row)  # Actual projection copy is conservatively charged the full row.
    work.copy(key)
    work.canonical_equal({column: row[column] for column in key}, key)


def key_work(work, table, key):
    if table == oracle.OUTBOX:
        work.utf8(key["id"])
    work.canonical(key)


def inventory_work(work, selected, mutations):
    work.copy(selected)
    work.copy(mutations)
    work.canonical([list(selected), list(mutations)])
    work.copy(selected)
    work.copy(mutations)
    business = [item for item in selected if not (item["table"] == oracle.TABLE
                and item["key"] == {"aggregate_id": oracle.IDENTITY})]
    work.canonical(business)
    work.copy(selected)
    work.canonical(list(selected))
    by_address = {}
    for item in selected:
        key_work(work, item["table"], item["key"])
        work.utf8(item["table"])
        work.hash()
        work.compare(item["keyDigest"], item["keyDigest"])
        if item["present"]:
            row_key_work(work, item["row"], item["key"])
        by_address[item["table"], wire(item["key"])] = item
    for item in mutations:
        key_work(work, item["table"], item["key"])
        before = by_address[item["table"], wire(item["key"])]
        work.compare(item["keyDigest"], before["keyDigest"])
        work.canonical_equal(item["expectedRow"], before["row"])
        if item["operation"] != "DELETE":
            row_key_work(work, item["row"], item["key"])
    if type(mutations) is list:
        work.copy(mutations)


def counter_work(work, selected):
    wrapper = next(item for item in selected if item["table"] == oracle.TABLE
                   and item["key"] == {"aggregate_id": oracle.IDENTITY})
    row = wrapper["row"]
    state = state_document(row)
    work.canonical(wrapper)
    work.canonical(row)
    work.canonical(state)
    work.decode_state(state)
    work.compare(row["state_json"], wire(state).decode("ascii"))
    work.hash()
    work.compare(row["state_digest"], row["state_digest"])
    return row


def after_work(work, before, after):
    work.copy(before)
    state = state_document(after)
    work.canonical(state)
    work.decode_state(state)
    work.hash()
    work.canonical(after)


def validation_work(work, context, changes):
    inventory_work(work, context.selected_rows, changes)
    before = counter_work(work, context.selected_rows) if context.operation in PARTICIPATING else None
    if any(item["table"] == oracle.OUTBOX for item in changes):
        counter = next(item for item in changes if item["table"] == oracle.TABLE
                       and item["key"] == {"aggregate_id": oracle.IDENTITY})
        after_work(work, before, counter["row"])
        work.canonical_equal(counter["row"], counter["row"])


def expected_work(context, changes, *, validating=False):
    work = ExpectedWork()
    if validating:
        validation_work(work, context, changes)
        return work
    inventory_work(work, context.selected_rows, changes)
    before = counter_work(work, context.selected_rows) if context.operation in PARTICIPATING else None
    has_outbox = any(item["table"] == oracle.OUTBOX for item in changes)
    output = expected_result(context, changes)
    if has_outbox:
        counter = output[-1]
        after_work(work, before, counter["row"])
        work.canonical({"aggregate_id": oracle.IDENTITY})
        for value in (counter["key"], counter["expectedRow"], counter["row"]):
            work.copy(value)
    # The inventory returns a tuple before the finalizer's actual copies.
    entries = tuple(changes)
    work.copy(entries)
    work.clone_json(list(entries))
    work.copy(list(entries))
    if has_outbox:
        work.copy(entries)
        work.copy(output[-1])
        validation_work(work, context, output)
    return work


def metric_tuple(work):
    return work.hash_work, work.input_bytes, work.json_nodes


def fresh_work(limits=None):
    return accounting._ValidationWork(accounting.QueryReadValidationLimits() if limits is None else limits)


def nonparticipant_fixture():
    operation = "webauthn.counter.cas"
    old = {"id": "component-credential", "sign_count": 1}
    chosen = oracle.selected("webauthn_credentials", {"id": old["id"]}, old)
    context = oracle.core.KernelContext(operation=operation, arguments={}, selected_rows=(chosen,),
                                      database_now=oracle.NOW, request_digest=oracle.REQUEST)
    return context, (oracle.mutation(chosen, {**old, "sign_count": 2}, operation),)


class AuditCapacityWorkTests(unittest.TestCase):
    def finalize(self, context, mutations, work):
        return capacity._finalize_capacity(context, mutations, work=work)

    def validate(self, context, mutations, work):
        return capacity._validate_capacity_transition(operation=context.operation,
            selected_rows=context.selected_rows, mutations=mutations, work=work)

    def test_metered_and_public_finalizers_preserve_real_status_and_delta_semantics(self):
        pairs = ((None, "pending"), ("pending", "claimed"), ("claimed", "pending"),
                 ("pending", "audited"), ("claimed", "audited"), ("audited", "audited"))
        for old_status, new_status in pairs:
            old = None if old_status is None else oracle.outbox_row(status=old_status)
            new = oracle.outbox_row(status=new_status)
            live = int(old_status in ("pending", "claimed"))
            context, changes = oracle.fixture([(old, new)],
                before=oracle.counter_row(live_count=live, active_count=live))
            with self.subTest(old=old_status, new=new_status):
                expected = expected_result(context, changes)
                measured = self.finalize(context, changes, fresh_work())
                self.assertEqual(measured, expected)
                self.assertEqual(capacity.finalize_capacity(context, changes), expected)
                self.assertIsNone(self.validate(context, measured, fresh_work()))
                self.assertIsNone(capacity.validate_capacity_transition(operation=context.operation,
                    selected_rows=context.selected_rows, mutations=measured))

    def test_independent_complete_batch_counts_revision_sequence_and_capacity_boundary(self):
        pending = oracle.outbox_row("old-pending")
        claimed = oracle.outbox_row("old-claimed", "claimed")
        context, changes = oracle.fixture([
            (pending, {**pending, "status": "audited"}), (claimed, {**claimed, "status": "pending"}),
            (None, oracle.outbox_row("fresh")),
        ], before=oracle.counter_row(live_count=100_000, active_count=100_000))
        result = self.finalize(context, changes, fresh_work())
        self.assertEqual(result, expected_result(context, changes))
        self.assertEqual((result[-1]["row"]["live_count"], result[-1]["row"]["revision"],
                          result[-1]["row"]["next_sequence"]), (100_000, 8, 20))
        self.assertEqual(self.finalize(context, tuple(reversed(changes)), fresh_work())[-1], result[-1])

    def test_no_outbox_still_checks_participating_counter_and_runs_actual_output_copy(self):
        context, changes = oracle.fixture([])
        for validating in (False, True):
            work = fresh_work()
            with patch.object(hashlib, "sha256", wraps=hashlib.sha256) as hashes, \
                    patch.object(json, "loads", wraps=json.loads) as loads:
                result = self.validate(context, changes, work) if validating else self.finalize(context, changes, work)
            self.assertEqual(result, None if validating else ())
            self.assertEqual(hashes.call_count, len(context.selected_rows) + 1)
            self.assertEqual(loads.call_count, 0 if validating else 1)
            self.assertEqual(metric_tuple(work), expected_work(context, changes, validating=validating).tuple())
        absent = replace(context, selected_rows=(oracle.selected(oracle.TABLE,
            {"aggregate_id": oracle.IDENTITY}, None),))
        with self.assertRaises(capacity.AuditCapacityError):
            self.finalize(absent, (), fresh_work())

    def test_nonparticipant_noop_and_business_update_do_not_acquire_counter_authority(self):
        context, changes = nonparticipant_fixture()
        for selected, mutations in ((context.selected_rows, changes), ((), ())):
            scoped = replace(context, selected_rows=selected)
            work = fresh_work()
            result = self.finalize(scoped, mutations, work)
            self.assertEqual(result, mutations)
            self.assertEqual(work.hash_work, len(selected))
            self.assertEqual(metric_tuple(work), expected_work(scoped, mutations).tuple())
            self.assertEqual(capacity.finalize_capacity(scoped, mutations), result)
        forbidden = replace(context, selected_rows=(*context.selected_rows,
            oracle.selected(oracle.TABLE, {"aggregate_id": oracle.IDENTITY}, oracle.counter_row())))
        with self.assertRaises(capacity.AuditCapacityError):
            self.finalize(forbidden, changes, fresh_work())

    def test_finalizer_reuses_same_work_in_actual_validator_and_real_counter_constructor(self):
        context, changes = oracle.fixture([(None, oracle.outbox_row())])
        expected = expected_result(context, changes)
        work = fresh_work()
        validator = capacity._validate_capacity_transition
        seen = []

        def genuine(**kwargs):
            self.assertIs(kwargs["work"], work)
            self.assertGreater(work.hash_work, 0)
            seen.append(kwargs)
            return validator(**kwargs)

        with patch.object(capacity, "_validate_capacity_transition", side_effect=genuine) as actual, \
                patch.object(capacity.core, "mutation", wraps=capacity.core.mutation) as mutation, \
                patch.object(capacity, "validate_capacity_transition",
                    wraps=capacity.validate_capacity_transition) as public_validator, \
                patch.object(hashlib, "sha256", wraps=hashlib.sha256) as hashes:
            result = self.finalize(context, changes, work)
        self.assertEqual((actual.call_count, mutation.call_count, public_validator.call_count), (1, 1, 0))
        self.assertEqual(result, expected)
        self.assertIs(seen[0]["selected_rows"], context.selected_rows)
        self.assertIs(seen[0]["mutations"], result)
        self.assertEqual(hashes.call_count, 2 * len(context.selected_rows) + 4)
        self.assertEqual(work.hash_work, hashes.call_count)

    def test_output_detachment_preserves_inputs_without_claiming_prehash_input_ownership(self):
        context, changes = oracle.fixture([(None, oracle.outbox_row())])
        before = copy.deepcopy((context.selected_rows, changes))
        result = self.finalize(context, changes, fresh_work())
        result[0]["row"]["event_json"] = "changed only returned business image"
        result[-1]["key"]["aggregate_id"] = "changed only returned key"
        result[-1]["expectedRow"]["state_json"] = "changed only returned OLD"
        result[-1]["row"]["state_json"] = "changed only returned NEW"
        self.assertEqual((context.selected_rows, changes), before)
        # Unlike the retained proof wrapper, this worker accepts caller-owned
        # graphs and has no promise to detach every input before its first hash.

    def test_full_independent_schedule_covers_presence_status_and_list_conversion_paths(self):
        fixtures = [oracle.fixture([(None, oracle.outbox_row())]), oracle.fixture([]), nonparticipant_fixture()]
        old = oracle.outbox_row("old", "claimed")
        fixtures.append(oracle.fixture([(old, {**old, "status": "audited"}),
                                       (None, oracle.outbox_row("new-雪"))],
            before=oracle.counter_row(live_count=1, active_count=1)))
        for ordinal, (context, changes) in enumerate(fixtures):
            result = expected_result(context, changes)
            for as_list in (False, True):
                scoped = replace(context, selected_rows=list(context.selected_rows)) if as_list else context
                supplied = list(changes) if as_list else changes
                work = fresh_work()
                with self.subTest(case=ordinal, as_list=as_list, validating=False):
                    self.assertEqual(self.finalize(scoped, supplied, work), result)
                    self.assertEqual(metric_tuple(work), expected_work(scoped, supplied).tuple())
                supplied_result = list(result) if as_list else result
                work = fresh_work()
                with self.subTest(case=ordinal, as_list=as_list, validating=True):
                    self.assertIsNone(self.validate(scoped, supplied_result, work))
                    self.assertEqual(metric_tuple(work), expected_work(scoped, supplied_result, validating=True).tuple())

    def test_actual_hash_encoder_parse_and_state_decode_counts_match_pass_oracle(self):
        old = oracle.outbox_row("old", "pending")
        context, changes = oracle.fixture([(old, {**old, "status": "claimed"}),
                                           (None, oracle.outbox_row("new-雪"))],
            before=oracle.counter_row(live_count=1, active_count=1))
        result = expected_result(context, changes)
        for validating in (False, True):
            entries = result if validating else changes
            expected = expected_work(context, entries, validating=validating)
            work = fresh_work()
            with self.subTest(validating=validating), \
                    patch.object(hashlib, "sha256", wraps=hashlib.sha256) as hashes, \
                    patch.object(capacity.core, "canonical_bytes", wraps=capacity.core.canonical_bytes) as encodings, \
                    patch.object(json, "loads", wraps=json.loads) as parses, \
                    patch.object(capacity, "_decode_state", wraps=capacity._decode_state) as decodes:
                if validating:
                    self.validate(context, entries, work)
                else:
                    self.assertEqual(self.finalize(context, entries, work), result)
            self.assertEqual((hashes.call_count, encodings.call_count, parses.call_count, decodes.call_count),
                             (expected.hashes, expected.encodings, expected.parses, expected.state_decodes))
            self.assertEqual(hashes.call_count, len(context.selected_rows) + 2 if validating
                             else 2 * len(context.selected_rows) + 4)
            self.assertEqual(metric_tuple(work), expected.tuple())

    def test_canonical_and_json_copy_units_are_exact_for_escaped_keys_scalars_and_containers(self):
        values = (None, True, False, -123456789, "雪😀\n\"\\", [], {},
                  {"escaped-雪": [None, False, 7, {"nested": "😀\t"}]})
        for value in values:
            length, count = len(wire(value)), nodes(value)
            with self.subTest(value=value):
                work = fresh_work()
                self.assertEqual(capacity._canonical(value, work=work), wire(value))
                self.assertEqual(metric_tuple(work), (0, 2 * length, 2 * count))
                work = fresh_work()
                with patch.object(json, "loads", wraps=json.loads) as parser:
                    copied = capacity._copy(value, work=work)
                self.assertEqual(copied, value)
                self.assertEqual(metric_tuple(work), (0, 4 * length, 3 * count))
                self.assertEqual(parser.call_count, 1)
                self.assertIs(type(parser.call_args.args[0]), bytes)
                self.assertEqual(capacity.canonical_audit_json(value), wire(value))

    def test_exact_independent_quotas_admit_and_each_one_less_denies_with_bounded_real_hashes(self):
        context, changes = oracle.fixture([(None, oracle.outbox_row())])
        result = expected_result(context, changes)
        for validating in (False, True):
            entries = result if validating else changes
            expected = expected_work(context, entries, validating=validating)
            exact = accounting.QueryReadValidationLimits(*expected.tuple())
            work = fresh_work(exact)
            if validating:
                self.assertIsNone(self.validate(context, entries, work))
            else:
                self.assertEqual(self.finalize(context, entries, work), result)
            self.assertEqual(metric_tuple(work), expected.tuple())
            for name in ("max_hashes", "max_input_bytes", "max_json_nodes"):
                values = {item.name: getattr(exact, item.name) for item in fields(exact)}
                values[name] -= 1
                work = fresh_work(accounting.QueryReadValidationLimits(**values))
                with self.subTest(validating=validating, field=name), \
                        patch.object(hashlib, "sha256", wraps=hashlib.sha256) as hashes:
                    with self.assertRaises(accounting.QueryReadWorkError):
                        if validating:
                            self.validate(context, entries, work)
                        else:
                            self.finalize(context, entries, work)
                self.assertEqual(hashes.call_count, work.hash_work)
                self.assertLessEqual(hashes.call_count, values["max_hashes"])
                self.assertLessEqual(work.input_bytes, values["max_input_bytes"])
                self.assertLessEqual(work.json_nodes, values["max_json_nodes"])

    def test_already_spent_work_is_preserved_and_exact_remaining_allowance_is_used(self):
        context, changes = oracle.fixture([(None, oracle.outbox_row())])
        result = expected_result(context, changes)
        seed = (7, 1024, 31)
        for validating in (False, True):
            entries = result if validating else changes
            expected = expected_work(context, entries, validating=validating).tuple()
            total = tuple(before + added for before, added in zip(seed, expected))
            work = fresh_work(accounting.QueryReadValidationLimits(*total))
            work.charge(hashes=seed[0], input_bytes=seed[1], json_nodes=seed[2])
            with self.subTest(validating=validating):
                if validating:
                    self.validate(context, entries, work)
                else:
                    self.assertEqual(self.finalize(context, entries, work), result)
                self.assertEqual(metric_tuple(work), total)

    def test_repeated_generation_shares_one_meter_without_reset_or_refund(self):
        context, changes = oracle.fixture([(None, oracle.outbox_row())])
        expected = expected_work(context, changes).tuple()
        work = fresh_work(accounting.QueryReadValidationLimits(*(2 * value for value in expected)))
        result = expected_result(context, changes)
        for iteration in (1, 2):
            self.assertEqual(self.finalize(context, changes, work), result)
            self.assertEqual(metric_tuple(work), tuple(iteration * value for value in expected))
        with patch.object(hashlib, "sha256", wraps=hashlib.sha256) as hashes:
            with self.assertRaises(accounting.QueryReadWorkError):
                self.finalize(context, changes, work)
        self.assertEqual(hashes.call_count, 0)
        self.assertEqual(metric_tuple(work), tuple(2 * value for value in expected))
        # Repeating pure supplied-before computation is not permission to apply
        # its counter CAS repeatedly, nor evidence of stateful replay admission.

    def test_repeated_large_new_image_exhausts_real_shared_64mib_without_fresh_helper_budgets(self):
        event = wire({"payload": "x" * (1024 * 1024)})
        row = oracle.outbox_row(event_json=event.decode("ascii"),
            event_digest=oracle.framed("catchplate.metadataAuditOutboxEvent/v1", event))
        context, changes = oracle.fixture([(None, row)])
        expected = expected_work(context, changes).tuple()
        maximum = 64 * 1024 * 1024
        repetitions = maximum // expected[1]
        self.assertGreaterEqual(repetitions, 1)
        self.assertLessEqual(repetitions, 4)
        self.assertLess((repetitions + 1) * expected[0], 8_000_000)
        self.assertLess((repetitions + 1) * expected[2], 1_000_000)
        work = fresh_work()
        for iteration in range(1, repetitions + 1):
            result = self.finalize(context, changes, work)
            self.assertEqual(result[0]["row"]["event_json"], row["event_json"])
            self.assertEqual(metric_tuple(work), tuple(iteration * value for value in expected))
        before = metric_tuple(work)
        with self.assertRaises(accounting.QueryReadWorkError):
            self.finalize(context, changes, work)
        self.assertGreater(work.input_bytes, before[1])
        self.assertLessEqual(work.input_bytes, maximum)
        self.assertEqual(work.limits, accounting.QueryReadValidationLimits())

    def test_lossless_json_domain_stays_identical_and_denies_before_any_source_hash(self):
        context, changes = oracle.fixture([(None, oracle.outbox_row())])
        invalid = ((0.5, accounting.QueryReadWorkError), (float("nan"), accounting.QueryReadWorkError),
                   ("nul\0value", capacity.AuditCapacityError), ("\ud800", accounting.QueryReadWorkError),
                   (("nested-tuple",), capacity.AuditCapacityError), ({1: "integer-key"}, accounting.QueryReadWorkError))
        for value, measured_error in invalid:
            altered = copy.deepcopy(changes)
            altered[0]["row"]["component_value"] = value
            for metered in (False, True):
                with self.subTest(kind=type(value), metered=metered), \
                        patch.object(hashlib, "sha256", wraps=hashlib.sha256) as hashes:
                    # Generic metered copy preparation rejects some lossless
                    # representation errors before the capacity-specific walk.
                    with self.assertRaises(measured_error if metered else capacity.AuditCapacityError):
                        self.finalize(context, altered, fresh_work() if metered else None)
                self.assertEqual(hashes.call_count, 0)

    def test_source_templates_selected_keys_before_images_and_counter_ownership_stay_closed(self):
        context, changes = oracle.fixture([(None, oracle.outbox_row())])
        wrong_template = copy.deepcopy(changes)
        wrong_template[0]["templateId"] = "nonempty-but-not-a-source-template"
        wrong_digest = copy.deepcopy(changes)
        wrong_digest[0]["keyDigest"] = "sha256:" + "f" * 64
        wrong_before = copy.deepcopy(changes)
        wrong_before[0]["expectedRow"] = {"id": "unexpected-old"}
        moved = copy.deepcopy(changes)
        moved[0]["row"]["id"] = "moved-key"
        supplied = expected_result(context, changes)
        for altered in (wrong_template, wrong_digest, wrong_before, moved, supplied):
            for work in (None, fresh_work()):
                with self.assertRaises(capacity.AuditCapacityError):
                    self.finalize(context, altered, work)
        # The independently rehashed but wrong counter delta must fail the
        # actual validator rather than gain authority from its own commitment.
        wrong_after = copy.deepcopy(supplied)
        wrong_after[-1]["row"] = oracle.refresh_state({**wrong_after[-1]["row"],
                                                       "live_count": 2, "active_count": 2})
        with self.assertRaises(capacity.AuditCapacityError):
            self.validate(context, wrong_after, fresh_work())

    def test_missing_bad_baseline_capacity_overflow_and_time_semantics_are_not_weakened(self):
        contexts = []
        context, changes = oracle.fixture([(None, oracle.outbox_row())])
        contexts.append((replace(context, selected_rows=context.selected_rows[1:]), changes))
        contexts.append((replace(context, database_now=oracle.NOW.replace(tzinfo=None)), changes))
        contexts.append((replace(context, database_now=datetime(1970, 1, 1, tzinfo=timezone.utc)), changes))
        for before in (oracle.counter_row(live_count=100_000, active_count=100_000),
                       oracle.counter_row(revision=2**63-1), oracle.counter_row(next_sequence=2**63-1),
                       oracle.counter_row(active_count=1)):
            contexts.append(oracle.fixture([(None, oracle.outbox_row())], before=before))
        for ordinal, (scoped, supplied) in enumerate(contexts):
            for work in (None, fresh_work()):
                with self.subTest(case=ordinal, metered=work is not None):
                    with self.assertRaises(capacity.AuditCapacityError):
                        self.finalize(scoped, supplied, work)
        broken = copy.deepcopy(context.selected_rows)
        broken[0]["row"]["state_json"] = "{}"
        with patch.object(hashlib, "sha256", wraps=hashlib.sha256) as hashes:
            with self.assertRaises(capacity.AuditCapacityError):
                self.finalize(replace(context, selected_rows=broken), changes, fresh_work())
        self.assertEqual(hashes.call_count, len(context.selected_rows))

    def test_private_work_requires_exact_shared_type_and_none_preserves_public_observer_route(self):
        context, changes = oracle.fixture([(None, oracle.outbox_row())])
        result = expected_result(context, changes)

        class WorkSubclass(accounting._ValidationWork):
            pass

        for invalid in ({}, object(), accounting.QueryReadValidationLimits(),
                        WorkSubclass(accounting.QueryReadValidationLimits())):
            for validating in (False, True):
                with self.subTest(kind=type(invalid), validating=validating), \
                        patch.object(capacity, "_inventory", wraps=capacity._inventory) as inventory:
                    with self.assertRaises(capacity.AuditCapacityError):
                        if validating:
                            self.validate(context, result, invalid)
                        else:
                            self.finalize(context, changes, invalid)
                self.assertEqual(inventory.call_count, 0)
        with patch.object(capacity, "validate_capacity_transition",
                          wraps=capacity.validate_capacity_transition) as public_validator:
            self.assertEqual(self.finalize(context, changes, None), result)
        self.assertEqual(public_validator.call_count, 1)

    def test_remaining_structural_encode_and_parse_reservations_precede_real_allocations(self):
        value = {"name": "雪\n", "items": [None, True, 123]}
        length, count = len(wire(value)), nodes(value)
        for limits in (accounting.QueryReadValidationLimits(max_input_bytes=2 * length - 1),
                       accounting.QueryReadValidationLimits(max_json_nodes=2 * count - 1)):
            work = fresh_work(limits)
            with patch.object(capacity.core, "canonical_bytes", wraps=capacity.core.canonical_bytes) as encoder:
                with self.assertRaises(accounting.QueryReadWorkError):
                    capacity._canonical(value, work=work)
            self.assertEqual(encoder.call_count, 0)
            self.assertEqual(metric_tuple(work), (0, length, count))
        for limits in (accounting.QueryReadValidationLimits(max_input_bytes=4 * length - 1),
                       accounting.QueryReadValidationLimits(max_json_nodes=3 * count - 1)):
            work = fresh_work(limits)
            with patch.object(capacity.core, "canonical_bytes", wraps=capacity.core.canonical_bytes) as encoder, \
                    patch.object(json, "loads", wraps=json.loads) as parser:
                with self.assertRaises(accounting.QueryReadWorkError):
                    capacity._copy(value, work=work)
            self.assertEqual((encoder.call_count, parser.call_count), (1, 0))
            self.assertEqual(metric_tuple(work), (0, 2 * length, 2 * count))
        for oversized, limits in (([None] * 1024, accounting.QueryReadValidationLimits(max_json_nodes=1024)),
                                   ("x" * 1024, accounting.QueryReadValidationLimits(max_input_bytes=1025)),
                                   (10**200, accounting.QueryReadValidationLimits(max_input_bytes=8))):
            work = fresh_work(limits)
            with patch.object(capacity.core, "canonical_bytes", wraps=capacity.core.canonical_bytes) as encoder:
                with self.assertRaises(accounting.QueryReadWorkError):
                    capacity._canonical(oversized, work=work)
            self.assertEqual(encoder.call_count, 0)
            self.assertEqual(work.json_nodes, 1)


if __name__ == "__main__":
    unittest.main()
