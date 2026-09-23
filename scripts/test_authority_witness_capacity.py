#!/usr/bin/env python3
"""Pure witness completion accounting and supplemental production source links.

Only the guard-free accounting helper is imported. These deterministic controls
do not launch/import the guarded witness, fake its authority registry, reserve
physical disk space, authenticate journal records or prove crash recovery. The
source-linkage assertions are expressly not service/concurrency execution.
"""
from __future__ import annotations

import ast
import sys
import unittest
from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_witness_capacity as capacity


I64 = 2**63 - 1


def limits(*, byte_limit=128, record_limit=8, max_record_bytes=32):
    return capacity.WitnessCapacityLimits(byte_limit, record_limit, max_record_bytes)


def usage(records=0, byte_count=0, opened=0):
    return capacity.WitnessCapacityUsage(records, byte_count, opened)


def values(value):
    return tuple(getattr(value, field.name) for field in fields(value))


def bypassed(value, **changes):
    forged = object.__new__(type(value))
    for field in fields(value):
        object.__setattr__(forged, field.name, changes.get(field.name, getattr(value, field.name)))
    return forged


class WitnessCapacityTests(unittest.TestCase):
    def test_empty_usage_and_generation_record_hold_no_terminal_capacity(self):
        empty, bounded = usage(), limits(byte_limit=7, record_limit=1)
        self.assertIsNone(capacity.require_completion_capacity(empty, bounded))
        projected = capacity.plan_append(empty, bounded, kind="generation-activation", record_bytes=7)
        self.assertEqual(values(projected), (1, 7, 0))
        self.assertEqual(values(empty), (0, 0, 0))
        self.assertIsNone(capacity.require_completion_capacity(projected, bounded))

    def test_reservation_exact_byte_and_record_boundaries_include_full_terminal_hold(self):
        bounded = limits(byte_limit=39, record_limit=2)
        reserved = capacity.plan_append(usage(), bounded, kind="reservation", record_bytes=7)
        self.assertEqual(values(reserved), (1, 7, 1))
        self.assertEqual(reserved.bytes + reserved.open_reservations * 32, 39)
        self.assertEqual(reserved.records + reserved.open_reservations, 2)
        terminal = capacity.plan_append(reserved, bounded, kind="terminal", record_bytes=32)
        self.assertEqual(values(terminal), (2, 39, 0))
        self.assertIsNone(capacity.require_completion_capacity(terminal, bounded))

    def test_one_less_byte_or_record_rejects_reservation_without_mutating_inputs(self):
        empty = usage()
        for bounded in (limits(byte_limit=38, record_limit=2), limits(byte_limit=39, record_limit=1)):
            before = values(empty), values(bounded)
            with self.subTest(limits=values(bounded)), self.assertRaisesRegex(
                    capacity.WitnessCapacityError, "completion capacity"):
                capacity.plan_append(empty, bounded, kind="reservation", record_bytes=7)
            self.assertEqual((values(empty), values(bounded)), before)

    def test_every_open_reservation_retains_its_own_slot_and_worst_case_bytes(self):
        bounded = limits(byte_limit=84, record_limit=4)
        first = capacity.plan_append(usage(), bounded, kind="reservation", record_bytes=10)
        second = capacity.plan_append(first, bounded, kind="reservation", record_bytes=10)
        self.assertEqual(values(second), (2, 20, 2))
        with self.assertRaises(capacity.WitnessCapacityError):
            capacity.plan_append(second, bounded, kind="reservation", record_bytes=1)
        draining = capacity.plan_append(second, bounded, kind="terminal", record_bytes=32)
        self.assertEqual(values(draining), (3, 52, 1))
        drained = capacity.plan_append(draining, bounded, kind="terminal", record_bytes=32)
        self.assertEqual(values(drained), (4, 84, 0))
        self.assertIsNone(capacity.require_completion_capacity(drained, bounded))

    def test_shorter_terminal_releases_only_unused_byte_hold_not_historical_bytes(self):
        bounded = limits(byte_limit=45, record_limit=4)
        reserved = capacity.plan_append(usage(), bounded, kind="reservation", record_bytes=7)
        drained = capacity.plan_append(reserved, bounded, kind="terminal", record_bytes=1)
        self.assertEqual(values(drained), (2, 8, 0))
        reopened = capacity.plan_append(drained, bounded, kind="reservation", record_bytes=5)
        self.assertEqual(values(reopened), (3, 13, 1))
        self.assertEqual(reopened.bytes + 32, 45)
        self.assertEqual(values(reserved), (1, 7, 1))

    def test_generation_activation_denies_open_reservations_until_they_drain(self):
        bounded, reserved = limits(), usage(1, 7, 1)
        for append in (capacity.plan_append, capacity.replay_append):
            with self.subTest(append=append.__name__), self.assertRaisesRegex(
                    capacity.WitnessCapacityError, "generation activation has open reservations"):
                append(reserved, bounded, kind="generation-activation", record_bytes=1)
        drained = capacity.plan_append(reserved, bounded, kind="terminal", record_bytes=3)
        activated = capacity.plan_append(drained, bounded, kind="generation-activation", record_bytes=2)
        self.assertEqual(values(activated), (3, 12, 0))

    def test_terminal_without_an_open_reservation_is_never_accounted(self):
        for append in (capacity.plan_append, capacity.replay_append):
            for current in (usage(), usage(2, 10, 0)):
                with self.subTest(append=append.__name__, usage=values(current)), self.assertRaisesRegex(
                        capacity.WitnessCapacityError, "terminal record has no open reservation"):
                    append(current, limits(), kind="terminal", record_bytes=1)

    def test_replay_may_pass_an_old_oversubscribed_prefix_that_finishes_closed(self):
        bounded = limits(byte_limit=50, record_limit=2)
        with self.assertRaisesRegex(capacity.WitnessCapacityError, "completion capacity"):
            capacity.plan_append(usage(), bounded, kind="reservation", record_bytes=25)
        prefix = capacity.replay_append(usage(), bounded, kind="reservation", record_bytes=25)
        self.assertEqual(values(prefix), (1, 25, 1))
        with self.assertRaisesRegex(capacity.WitnessCapacityError, "completion capacity"):
            capacity.require_completion_capacity(prefix, bounded)
        complete = capacity.replay_append(prefix, bounded, kind="terminal", record_bytes=25)
        self.assertEqual(values(complete), (2, 50, 0))
        self.assertIsNone(capacity.require_completion_capacity(complete, bounded))

    def test_final_recovered_open_usage_requires_both_byte_and_slot_completion_capacity(self):
        for bounded, current in (
            (limits(byte_limit=38, record_limit=2), usage(1, 7, 1)),
            (limits(byte_limit=39, record_limit=1), usage(1, 7, 1)),
        ):
            with self.subTest(limits=values(bounded)), self.assertRaisesRegex(
                    capacity.WitnessCapacityError, "completion capacity"):
                capacity.require_completion_capacity(current, bounded)
        self.assertIsNone(capacity.require_completion_capacity(usage(1, 7, 1),
            limits(byte_limit=39, record_limit=2)))

    def test_replay_and_plan_always_enforce_actual_byte_and_record_limits(self):
        for append in (capacity.plan_append, capacity.replay_append):
            for current, bounded in (
                (usage(1, 10, 0), limits(byte_limit=10)),
                (usage(1, 10, 0), limits(record_limit=1)),
                (usage(1, 129, 0), limits()),
                (usage(9, 1, 0), limits()),
            ):
                with self.subTest(append=append.__name__, usage=values(current), limits=values(bounded)), \
                        self.assertRaisesRegex(capacity.WitnessCapacityError, "actual journal usage"):
                    append(current, bounded, kind="generation-activation", record_bytes=1)
        for current in (usage(9, 1, 0), usage(1, 129, 0)):
            with self.assertRaisesRegex(capacity.WitnessCapacityError, "actual journal usage"):
                capacity.require_completion_capacity(current, limits())

    def test_record_size_and_kind_are_exact_and_closed_for_plan_and_replay(self):
        class StringKind(str):
            pass

        for append in (capacity.plan_append, capacity.replay_append):
            for size in (None, True, False, 0, -1, 1.0, "1", b"1", 33, I64 + 1):
                with self.subTest(append=append.__name__, size=size), self.assertRaises(capacity.WitnessCapacityError):
                    append(usage(), limits(), kind="reservation", record_bytes=size)
            for kind in (None, True, b"reservation", "", "transition", "commit", "Reservation", StringKind("reservation")):
                with self.subTest(append=append.__name__, kind=repr(kind)), self.assertRaises(capacity.WitnessCapacityError):
                    append(usage(), limits(), kind=kind, record_bytes=1)

    def test_signed64_arithmetic_and_huge_completion_holds_fail_without_materialization(self):
        bounded = limits(byte_limit=I64, record_limit=I64, max_record_bytes=I64)
        for append in (capacity.plan_append, capacity.replay_append):
            for current, kind in ((usage(I64, 0, 0), "generation-activation"),
                    (usage(0, I64, 0), "generation-activation"), (usage(0, 0, I64), "reservation")):
                with self.subTest(append=append.__name__, usage=values(current)), self.assertRaisesRegex(
                        capacity.WitnessCapacityError, "overflows signed64"):
                    append(current, bounded, kind=kind, record_bytes=1)
        with self.assertRaisesRegex(capacity.WitnessCapacityError, "completion capacity"):
            capacity.require_completion_capacity(usage(0, 0, I64), bounded)
        exact = capacity.plan_append(usage(), bounded, kind="generation-activation", record_bytes=I64)
        self.assertEqual(values(exact), (1, I64, 0))

    def test_dataclasses_enforce_individual_exact_integer_bounds_not_authority(self):
        for field in ("byte_limit", "record_limit", "max_record_bytes"):
            for value in (None, True, False, 0, -1, 1.0, "1", I64 + 1):
                with self.subTest(field=field, value=value), self.assertRaises(capacity.WitnessCapacityError):
                    replace(limits(), **{field: value})
        for field in ("records", "bytes", "open_reservations"):
            for value in (None, True, False, -1, 1.0, "1", I64 + 1):
                with self.subTest(field=field, value=value), self.assertRaises(capacity.WitnessCapacityError):
                    replace(usage(), **{field: value})
        self.assertEqual(values(limits(byte_limit=1, record_limit=1, max_record_bytes=I64)), (1, 1, I64))
        self.assertEqual(values(usage(0, 0, I64)), (0, 0, I64))
        # Individual bounds do not authenticate protocol consistency or make
        # a supplied usage tuple a validated journal observation.

    def test_results_and_inputs_are_frozen_fresh_owned_accounting_values(self):
        current, bounded = usage(), limits()
        before = values(current), values(bounded)
        planned = capacity.plan_append(current, bounded, kind="reservation", record_bytes=7)
        replayed = capacity.replay_append(current, bounded, kind="reservation", record_bytes=7)
        self.assertIs(type(planned), capacity.WitnessCapacityUsage)
        self.assertIsNot(planned, replayed)
        self.assertIsNot(planned, current)
        self.assertEqual(planned, replayed)
        self.assertEqual((values(current), values(bounded)), before)
        for instance, field in ((current, "records"), (planned, "bytes"), (bounded, "record_limit")):
            with self.subTest(field=field), self.assertRaises(FrozenInstanceError):
                setattr(instance, field, 99)
        object.__setattr__(current, "bytes", 99)
        object.__setattr__(bounded, "max_record_bytes", 1)
        self.assertEqual(values(planned), (1, 7, 1))

    def test_incomplete_forged_or_wrong_contexts_are_revalidated_at_each_api(self):
        class UsageSubclass(capacity.WitnessCapacityUsage):
            pass

        bad_usage = (None, {}, (0, 0, 0), UsageSubclass(0, 0, 0),
            object.__new__(capacity.WitnessCapacityUsage), bypassed(usage(), bytes=True),
            bypassed(usage(), records=-1), bypassed(usage(), open_reservations=[]))
        bad_limits = (None, {}, (128, 8, 32), object.__new__(capacity.WitnessCapacityLimits),
            bypassed(limits(), byte_limit=True), bypassed(limits(), record_limit=0),
            bypassed(limits(), max_record_bytes=bytearray(b"32")))
        for current, bounded in (*((item, limits()) for item in bad_usage),
                                 *((usage(), item) for item in bad_limits)):
            for append in (capacity.plan_append, capacity.replay_append):
                with self.subTest(append=append.__name__, usage=type(current), limits=type(bounded)), \
                        self.assertRaises(capacity.WitnessCapacityError):
                    append(current, bounded, kind="reservation", record_bytes=1)
            with self.assertRaises(capacity.WitnessCapacityError):
                capacity.require_completion_capacity(current, bounded)

    def test_deterministic_full_sequence_matches_independent_totals_at_every_step(self):
        records = (("generation-activation", 4), ("reservation", 3), ("reservation", 5),
            ("terminal", 6), ("terminal", 7), ("generation-activation", 2),
            ("reservation", 8), ("terminal", 9))
        bounded = limits(byte_limit=92, record_limit=8, max_record_bytes=16)
        planned, replayed = usage(), usage()
        expected_records = expected_bytes = expected_open = 0
        for kind, size in records:
            previous = values(planned), values(replayed), values(bounded)
            next_planned = capacity.plan_append(planned, bounded, kind=kind, record_bytes=size)
            next_replayed = capacity.replay_append(replayed, bounded, kind=kind, record_bytes=size)
            expected_records += 1
            expected_bytes += size
            expected_open += {"generation-activation": 0, "reservation": 1, "terminal": -1}[kind]
            expected = (expected_records, expected_bytes, expected_open)
            self.assertEqual(values(next_planned), expected)
            self.assertEqual(values(next_replayed), expected)
            self.assertEqual((values(planned), values(replayed), values(bounded)), previous)
            self.assertLessEqual(expected_records + expected_open, 8)
            self.assertLessEqual(expected_bytes + 16 * expected_open, 92)
            planned, replayed = next_planned, next_replayed
        self.assertEqual(values(planned), (8, 44, 0))
        self.assertIsNone(capacity.require_completion_capacity(replayed, bounded))


def witness_source():
    path = ROOT / "serverware/authority_witness.py"
    if path.stat().st_size > 512 * 1024:
        raise AssertionError("witness source exceeds fixture inspection bound")
    source = path.read_text(encoding="utf-8")
    parsed = ast.parse(source)
    stores = [node for node in parsed.body
              if isinstance(node, ast.ClassDef) and node.name == "WitnessStateStore"]
    if len(stores) != 1:
        raise AssertionError("witness store source is not unique")
    methods = {node.name: node for node in stores[0].body if isinstance(node, ast.FunctionDef)}
    functions = {node.name: node for node in parsed.body if isinstance(node, ast.FunctionDef)}
    return source, parsed, methods, functions


def calls(node, expression):
    return [child for child in ast.walk(node)
            if isinstance(child, ast.Call) and ast.unparse(child.func) == expression]


class WitnessCapacitySourceLinkageTests(unittest.TestCase):
    """Inspect the guarded source; never execute extracted AST or import it."""

    def test_source_limits_are_signed_bounded_and_usage_starts_before_recovery(self):
        source, parsed, methods, _functions = witness_source()
        imports = [node for node in parsed.body if isinstance(node, ast.ImportFrom)
                   and node.module == "serverware"
                   and any(alias.name == "authority_witness_capacity" for alias in node.names)]
        self.assertEqual(len(imports), 1)
        self.assertEqual([(alias.name, alias.asname) for alias in imports[0].names],
                         [("authority_witness_capacity", "capacity")])
        constructor = methods["__init__"]
        bounded = calls(constructor, "capacity.WitnessCapacityLimits")
        initial = calls(constructor, "capacity.WitnessCapacityUsage")
        recovery = calls(constructor, "self._journal_io.recover")
        self.assertEqual(tuple(map(len, (bounded, initial, recovery))), (1, 1, 1))
        self.assertEqual({keyword.arg: ast.unparse(keyword.value) for keyword in bounded[0].keywords},
                         {"byte_limit": "self.state_quota_bytes", "record_limit": "self.state_record_limit",
                          "max_record_bytes": "MAX_STATE_RECORD_BYTES"})
        self.assertEqual([ast.unparse(argument) for argument in initial[0].args], ["0", "0", "0"])
        self.assertLess(bounded[0].lineno, initial[0].lineno)
        self.assertLess(initial[0].lineno, recovery[0].lineno)
        constructor_text = ast.get_source_segment(source, constructor)
        self.assertIn('type(self.state_binding["quotaBytes"]) is not int', constructor_text)
        self.assertIn('self.state_binding["quotaBytes"],\n            MAX_STATE_BYTES,', constructor_text)
        self.assertIn("max(1, self.state_quota_bytes // 128)", constructor_text)
        self.assertNotIn("state_record_count", source)
        self.assertNotIn("state_total_bytes", source)

    def test_kinds_come_from_closed_protocol_phases_and_accepted_receipts(self):
        _source, parsed, methods, functions = witness_source()
        expected = {
            "RESERVATION_PHASES": {"reserve", "webauthn-trust-publish", "credential-release"},
            "TERMINAL_PHASES": {"commit", "abort", "reconcile", "credential-release-consume"},
        }
        for name, phases in expected.items():
            assigned = [node for node in parsed.body if isinstance(node, ast.Assign)
                        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
            self.assertEqual(len(assigned), 1)
            self.assertIsInstance(assigned[0].value, ast.Set)
            self.assertTrue(all(isinstance(item, ast.Constant) and type(item.value) is str
                                for item in assigned[0].value.elts))
            self.assertEqual({item.value for item in assigned[0].value.elts}, phases)
        mapper = functions["_capacity_kind_for_phase"]
        self.assertEqual(len(mapper.body), 3)
        for branch, constant, kind in zip(mapper.body[:2], expected, ("reservation", "terminal")):
            self.assertIsInstance(branch, ast.If)
            self.assertEqual(ast.unparse(branch.test), "type(phase) is str and phase in " + constant)
            self.assertEqual([ast.unparse(item) for item in branch.body], ["return '" + kind + "'"])
        self.assertIsInstance(mapper.body[-1], ast.Raise)
        accepted = methods["_accepted_capacity_kind"]
        self.assertEqual(ast.unparse(accepted.body[0].test), "receipt_digest is None")
        self.assertEqual(ast.unparse(accepted.body[0].body[0]), "return 'generation-activation'")
        self.assertEqual(ast.unparse(accepted.body[1]),
                         "return _capacity_kind_for_phase(self.receipts[receipt_digest]['phase'])")
        for name, expression in (("_persist_generation_activation", "'generation-activation'"),
                                 ("transition_bytes", "_capacity_kind_for_phase(phase)")):
            appended = calls(methods[name], "self._persist_and_accept_state_record")
            self.assertEqual(len(appended), 1)
            self.assertEqual({keyword.arg: ast.unparse(keyword.value) for keyword in appended[0].keywords},
                             {"capacity_kind": expression})

    def test_recovery_counts_authenticated_records_and_checks_final_holds_before_ready(self):
        _source, parsed, methods, _functions = witness_source()
        load = methods["_load_state"]
        accepted = calls(load, "self._accept_stored_state_record")
        replay = calls(load, "capacity.replay_append")
        completion = calls(load, "capacity.require_completion_capacity")
        self.assertEqual(tuple(map(len, (accepted, replay, completion))), (1, 1, 1))
        self.assertEqual(calls(load, "capacity.plan_append"), [])
        self.assertEqual(calls(parsed, "capacity.replay_append"), replay)
        self.assertEqual(calls(parsed, "capacity.require_completion_capacity"), completion)
        self.assertLess(accepted[0].lineno, replay[0].lineno)
        self.assertEqual([ast.unparse(argument) for argument in replay[0].args],
                         ["self._capacity_usage", "self._capacity_limits"])
        self.assertEqual({keyword.arg: ast.unparse(keyword.value) for keyword in replay[0].keywords},
                         {"kind": "self._accepted_capacity_kind(receipt_digest)",
                          "record_bytes": "len(canonical_record)"})
        loops = [node for node in ast.walk(load) if isinstance(node, ast.For)
                 and replay[0] in tuple(ast.walk(node))]
        self.assertEqual(len(loops), 1)
        sequence = [node for node in loops[0].body if isinstance(node, ast.Assign)
                    and any(ast.unparse(target) == "self.state_sequence" for target in node.targets)]
        self.assertEqual(len(sequence), 1)
        self.assertLess(replay[0].lineno, sequence[0].lineno)
        self.assertLess(loops[0].end_lineno, completion[0].lineno)
        self.assertEqual([ast.unparse(argument) for argument in completion[0].args],
                         ["self._capacity_usage", "self._capacity_limits"])
        returned = [node for node in ast.walk(load) if isinstance(node, ast.Return)]
        self.assertEqual(len(returned), 1)
        self.assertLess(completion[0].lineno, returned[0].lineno)
        constructor = methods["__init__"]
        recovery = calls(constructor, "self._journal_io.recover")[0]
        self.assertEqual(ast.unparse(recovery.args[0]), "self._load_state")
        self.assertLess(recovery.lineno, calls(constructor, "self._persist_generation_activation")[0].lineno)

    def test_new_capacity_is_planned_before_publish_and_adopted_only_after_acceptance(self):
        _source, parsed, methods, _functions = witness_source()
        persist = methods["_persist_state_record"]
        planned = calls(persist, "capacity.plan_append")
        published = calls(persist, "self._journal_io.publish")
        self.assertEqual((len(planned), len(published)), (1, 1))
        self.assertEqual(calls(parsed, "capacity.plan_append"), planned)
        self.assertLess(planned[0].lineno, published[0].lineno)
        self.assertEqual([ast.unparse(argument) for argument in planned[0].args],
                         ["self._capacity_usage", "self._capacity_limits"])
        self.assertEqual({keyword.arg: ast.unparse(keyword.value) for keyword in planned[0].keywords},
                         {"kind": "capacity_kind", "record_bytes": "len(canonical_record)"})
        returned = [node for node in ast.walk(persist) if isinstance(node, ast.Return)]
        self.assertEqual([ast.unparse(node.value) for node in returned],
                         ["(record_name, canonical_record, planned_usage)"])
        self.assertEqual([node for node in ast.walk(persist) if isinstance(node, ast.Assign)
                          and any(ast.unparse(target) == "self._capacity_usage" for target in node.targets)], [])
        accept = methods["_persist_and_accept_state_record"]
        stored = calls(accept, "self._persist_state_record")[0]
        indexed = calls(accept, "self._accept_stored_state_record")[0]
        guarded = [node for node in ast.walk(accept) if isinstance(node, ast.Try)
                   and indexed in tuple(ast.walk(node))]
        self.assertEqual(len(guarded), 1)
        self.assertLess(stored.lineno, indexed.lineno)
        self.assertEqual(ast.unparse(guarded[0].body[1].test),
                         "self._accepted_capacity_kind(receipt_digest) != capacity_kind")
        self.assertIsInstance(guarded[0].body[1].body[0], ast.Raise)
        self.assertEqual(ast.unparse(guarded[0].body[2]), "self._capacity_usage = planned_usage")
        self.assertEqual(len(guarded[0].handlers), 1)
        self.assertEqual(ast.unparse(guarded[0].handlers[0].type), "BaseException")
        self.assertEqual(len(calls(guarded[0].handlers[0], "self._journal_io.poison")), 1)
        self.assertIsInstance(guarded[0].handlers[0].body[-1], ast.Raise)


if __name__ == "__main__":
    unittest.main()
