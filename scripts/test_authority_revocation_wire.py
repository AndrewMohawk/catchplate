#!/usr/bin/env python3
"""Original-byte ingestion with independent units and genuine signed replay.

All signatures/proofs/effects are actual workers over independently authored
fixture data. Keys, clocks, roots and identities remain synthetic external pins;
these source-only fixtures do not claim currentness, persistence or startup.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_query_read_work as accounting
from serverware import authority_revocation_plan as plan
from serverware import authority_revocation_plan_production as production
from serverware import authority_revocation_wire as wire_reader
import test_authority_revocation_plan as oracle


EXPECTATIONS = frozenset({
    "expected_request", "expected_planner_identity", "planner_public_key",
    "expected_verifier_identity", "verifier_public_key", "expected_capability_id",
    "expected_planner_transaction_id", "expected_fence", "reserved_at_epoch_ns",
    "deadline_epoch_ns", "deadline_monotonic_ns", "now_epoch_ns", "now_monotonic_ns",
    "database_now", "maximum_assertion_age_ns", "maximum_plan_age_ns",
    "maximum_clock_skew_ns", "expected_before", "expected_approver_policy_digest",
})


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("ascii")


def counts(value):
    """Independent structural oracle, never tokenizer/decoder output."""
    if type(value) is dict:
        children = [counts(child) for child in value.values()]
        return (1 + len(value) + sum(item[0] for item in children),
                1 + sum(item[1] for item in children),
                len(value) + sum(item[2] for item in children))
    if type(value) is list:
        children = [counts(child) for child in value]
        return tuple((1 if index == 0 else 0) + sum(item[index] for item in children)
                     for index in range(3))
    return 1, 0, 0


def decoder_units(raw, value):
    nodes, objects, pairs = counts(value)
    return 0, 4 * len(raw), nodes + objects + 2 * pairs


def decimal(value):
    """Independent inverse conversion; no host-limited str(large_integer)."""
    parts = []
    while value:
        value, chunk = divmod(value, 1_000_000_000)
        parts.append(chunk)
    return (str(parts[-1]) + "".join(f"{chunk:09d}" for chunk in reversed(parts[:-1]))).encode("ascii")


def expectations(fixture):
    value = fixture.arguments()
    value.pop("envelope")
    return value


class RevocationWireTests(unittest.TestCase):
    def test_actual_parser_matches_independent_nodes_objects_pairs_and_opaque_strings(self):
        values = ({}, {"x": {}}, {"x": [None, True, False, -17, 0, "雪", "😀"]},
            {"quote\\\"{:[]}": "\\\"}:,{[true 42 false null]",
             "opaqueQuery": '{"same":1,"same":2,"float":1.5}', "nested": [{"k": []}]})
        for value in values:
            raw = wire(value)
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
            with self.subTest(value=value), patch.object(wire_reader.json, "loads", wraps=json.loads) as loads:
                actual = wire_reader._decode_envelope(raw, work=work)
            self.assertEqual(actual, value)
            self.assertEqual(loads.call_count, 1)
            self.assertEqual(oracle.units(work.metrics), decoder_units(raw, value))
            self.assertIs(loads.call_args.kwargs["object_pairs_hook"], wire_reader._unique_object)
            self.assertIs(loads.call_args.kwargs["parse_int"], wire_reader._parse_integer)

    def test_exact_preconsumed_work_and_repeated_decodes_never_create_allowance(self):
        value = {"a": [1, {"b": "c"}], "d": False}
        raw, prior = wire(value), (1, 11, 7)
        each = decoder_units(raw, value)
        total = oracle.add(prior, each, each)
        work = accounting._ValidationWork(accounting.QueryReadValidationLimits(*total))
        work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
        limits = work.limits
        with patch.object(accounting._ValidationWork, "__init__", side_effect=AssertionError("fresh allowance")):
            self.assertEqual(wire_reader._decode_envelope(raw, work=work), value)
            self.assertEqual(wire_reader._decode_envelope(raw, work=work), value)
        self.assertIs(work.limits, limits)
        self.assertEqual(oracle.units(work.metrics), total)

    def test_byte_and_node_minus_one_fail_before_real_decode_parser_allocations(self):
        value = {"x": [{"a": 1}, {"b": [True, None]}]}
        raw = wire(value)
        expected = decoder_units(raw, value)
        for dimension in (1, 2):
            limits = [1, expected[1], expected[2]]
            limits[dimension] -= 1
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits(*limits))
            with self.subTest(dimension=dimension), patch.object(wire_reader.json, "loads", wraps=json.loads) as loads:
                with self.assertRaises(accounting.QueryReadWorkError):
                    wire_reader._decode_envelope(raw, work=work)
            self.assertEqual(loads.call_count, 0)
            self.assertEqual(oracle.units(work.metrics), (0, len(raw), 0))

    def test_scan_cost_is_debited_before_lexical_work_and_no_hash_quota_is_needed(self):
        raw = b'{"a":1}'
        work = accounting._ValidationWork(accounting.QueryReadValidationLimits(max_input_bytes=len(raw) - 1))
        with patch.object(wire_reader, "_integer", wraps=wire_reader._integer) as integer, \
                patch.object(wire_reader.json, "loads", wraps=json.loads) as loads:
            with self.assertRaises(accounting.QueryReadWorkError):
                wire_reader._decode_envelope(raw, work=work)
        self.assertEqual((integer.call_count, loads.call_count), (0, 0))
        self.assertEqual(oracle.units(work.metrics), (0, 0, 0))
        work = accounting._ValidationWork(accounting.QueryReadValidationLimits(max_hashes=1))
        work.charge(hashes=1)
        with patch.object(hashlib, "sha256", wraps=hashlib.sha256) as hashes:
            self.assertEqual(wire_reader._decode_envelope(raw, work=work), {"a": 1})
        self.assertEqual((hashes.call_count, work.hash_work), (0, 1))

    def test_exact_bytes_work_and_true_source_byte_bound_are_checked_before_scanning(self):
        class BytesSubclass(bytes):
            pass
        for raw in (None, "{}", bytearray(b"{}"), memoryview(b"{}"), BytesSubclass(b"{}"),
                    b"", b"0", b" " * (64 * 1024 * 1024 + 1)):
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
            with self.subTest(kind=type(raw).__name__), \
                    patch.object(wire_reader, "_preflight", wraps=wire_reader._preflight) as scan:
                with self.assertRaises(ValueError):
                    wire_reader._decode_envelope(raw, work=work)
            self.assertEqual(scan.call_count, 0)
            self.assertEqual(oracle.units(work.metrics), (0, 0, 0))
        class DerivedWork(accounting._ValidationWork):
            pass
        for work in (None, {}, DerivedWork(accounting.QueryReadValidationLimits())):
            with self.assertRaises(ValueError):
                wire_reader._decode_envelope(b"{}", work=work)

    def test_float_nonfinite_nonascii_nul_and_lone_surrogates_deny_before_loads(self):
        invalid = (b'{"x":1.0}', b'{"x":1e0}', b'{"x":NaN}', b'{"x":Infinity}',
            b'{"x":-Infinity}', b'{"x":"\x00"}', b'{"x":"\\u0000"}', b'{"x":"\xc3\xa9"}',
            b'{"x":"\\ud800"}', b'{"x":"\\udfff"}', b'{"x":"\\ud800\\u0061"}',
            b'{"x":"\\q"}', b'{"x":"\\u123"}', b'{"x":"unterminated}', b'{"x":]}')
        for raw in invalid:
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
            with self.subTest(raw=raw), patch.object(wire_reader.json, "loads", wraps=json.loads) as loads:
                with self.assertRaises(wire_reader.RevocationWireError):
                    wire_reader._decode_envelope(raw, work=work)
            self.assertEqual(loads.call_count, 0)
            self.assertEqual(oracle.units(work.metrics), (0, len(raw), 0))

    def test_unicode_pairs_and_escaped_backslashes_survive_without_scanning_query_contents(self):
        raw = b'{"\\ud83d\\ude00":"\\ud83d\\ude00","literal":"\\\\ud800","quoted":"\\\"{}:,[]"}'
        expected = {"😀": "😀", "literal": "\\ud800", "quoted": '"{}:,[]'}
        work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
        self.assertEqual(wire_reader._decode_envelope(raw, work=work), expected)
        self.assertEqual(oracle.units(work.metrics), decoder_units(raw, expected))

    def test_actual_object_hook_rejects_duplicate_decoded_keys_including_unicode_aliases(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":1,"\\u0061":2}',
                    b'{"\\ud83d\\ude00":1,"\\uD83D\\uDE00":2}'):
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
            with self.subTest(raw=raw), patch.object(wire_reader.json, "loads", wraps=json.loads) as loads:
                with self.assertRaisesRegex(wire_reader.RevocationWireError, "duplicate decoded key"):
                    wire_reader._decode_envelope(raw, work=work)
            self.assertEqual(loads.call_count, 1)
            # One object, two key/value pairs: N5 + O1 +2P4, even on failure.
            self.assertEqual(oracle.units(work.metrics), (0, 4 * len(raw), 10))

    def test_actual_json_parser_still_rejects_invalid_grammar_and_nonobject_roots(self):
        for raw in (b'{"a" 1}', b'{"a":01}', b'{"a":true,}', b'{}{}', b'[1,2]', b'42', b'null'):
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
            with self.subTest(raw=raw), patch.object(wire_reader.json, "loads", wraps=json.loads) as loads:
                with self.assertRaises(wire_reader.RevocationWireError):
                    wire_reader._decode_envelope(raw, work=work)
            self.assertEqual(loads.call_count, 1)
            self.assertEqual(work.input_bytes, 4 * len(raw))

    def test_depth128_empty_container_is_valid_but_scalar_key_or_container129_denies(self):
        accepted = b'{"a":' + b'[' * 128 + b']' * 128 + b'}'
        work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
        value = wire_reader._decode_envelope(accepted, work=work)
        self.assertEqual(oracle.units(work.metrics), decoder_units(accepted, value))
        accepted_objects = b'{"a":' * 128 + b'{}' + b'}' * 128
        work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
        value = wire_reader._decode_envelope(accepted_objects, work=work)
        self.assertEqual(oracle.units(work.metrics), decoder_units(accepted_objects, value))
        for raw in (b'{"a":' + b'[' * 128 + b'0' + b']' * 128 + b'}',
                    b'{"a":' + b'[' * 129 + b']' * 129 + b'}',
                    b'{"a":' * 129 + b'0' + b'}' * 129):
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
            with self.subTest(length=len(raw)), patch.object(wire_reader.json, "loads", wraps=json.loads) as loads:
                with self.assertRaisesRegex(wire_reader.RevocationWireError, "depth"):
                    wire_reader._decode_envelope(raw, work=work)
            self.assertEqual(loads.call_count, 0)

    def test_integer_ceiling_is_lossless_and_independent_of_host_decimal_conversion_limit(self):
        maximum = (1 << 16384) - 1
        digits = decimal(maximum)
        self.assertEqual(len(digits), 4933)
        before = sys.get_int_max_str_digits()
        for sign in (b"", b"-"):
            raw = b'{"n":' + sign + digits + b'}'
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
            with patch.object(sys, "set_int_max_str_digits", side_effect=AssertionError("global setting")):
                actual = wire_reader._decode_envelope(raw, work=work)
            self.assertEqual(actual["n"], -maximum if sign else maximum)
            self.assertEqual(oracle.units(work.metrics), (0, 4 * len(raw), 6))
        self.assertEqual(sys.get_int_max_str_digits(), before)
        for digits in (decimal(1 << 16384), b"9" * 4934):
            raw = b'{"n":' + digits + b'}'
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
            with patch.object(wire_reader.json, "loads", wraps=json.loads) as loads:
                with self.assertRaisesRegex(wire_reader.RevocationWireError, "bit bound"):
                    wire_reader._decode_envelope(raw, work=work)
            self.assertEqual(loads.call_count, 0)

    def test_raw_wrapper_requires_closed_independent_expectations_before_decode(self):
        fixture = oracle.PlanFixture(approval=False, include_audit=False)
        pins = expectations(fixture)
        self.assertEqual(set(pins), EXPECTATIONS)
        for bad in ({key: value for key, value in pins.items() if key != "expected_request"},
                    {**pins, "successful_result": {}}, {**pins, "limits": accounting.QueryReadValidationLimits()},
                    {**pins, "envelope": fixture.envelope}):
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
            with patch.object(wire_reader, "_decode_envelope", wraps=wire_reader._decode_envelope) as decode:
                with self.assertRaises(wire_reader.RevocationWireError):
                    wire_reader._verify_signed_envelope_on_work(wire(fixture.envelope), work=work, **bad)
            self.assertEqual(decode.call_count, 0)
            self.assertEqual(oracle.units(work.metrics), (0, 0, 0))

    def test_actual_producer_bytes_replay_one_genuine_shared_worker_with_independent_total(self):
        fixture = oracle.PlanFixture(approval=False, include_audit=False)
        builder_work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
        signed = production._build_and_sign(**oracle.production_arguments(fixture, builder_work))
        self.assertEqual(signed.envelope_bytes, wire(fixture.envelope))
        prior = (7, 101, 13)
        parsed = decoder_units(signed.envelope_bytes, fixture.envelope)
        expected = oracle.add(prior, parsed, (0, 2 * len(signed.envelope_bytes), 0),
                             oracle.independent_metrics(fixture)["total"])
        work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
        work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
        limits = work.limits
        with patch.object(plan, "_verify_signed_revocation_plan_on_work",
                wraps=plan._verify_signed_revocation_plan_on_work) as replay, \
                patch.object(plan.mixed, "_verify", wraps=plan.mixed._verify) as proof:
            actual = wire_reader._verify_signed_envelope_on_work(signed.envelope_bytes,
                work=work, **expectations(fixture))
        self.assertEqual((replay.call_count, proof.call_count), (1, 1))
        self.assertIs(replay.call_args.kwargs["work"], work)
        self.assertIs(replay.call_args.kwargs["original_envelope_bytes"], signed.envelope_bytes)
        self.assertEqual(actual.envelope_bytes, signed.envelope_bytes)
        self.assertEqual(actual.semantics.mutations, fixture.semantic.final_mutations)
        self.assertEqual((actual.metrics.planner_signature_attempts, actual.metrics.assertion_signature_attempts), (1, 1))
        self.assertEqual(oracle.units(work.metrics), expected)
        self.assertEqual((actual.metrics.total_hashes, actual.metrics.total_input_bytes,
                          actual.metrics.total_json_nodes), expected)
        self.assertIs(work.limits, limits)

    def test_noncanonical_equivalent_original_bytes_deny_before_any_signature_or_semantics(self):
        fixture = oracle.PlanFixture(approval=False, include_audit=False)
        canonical = wire(fixture.envelope)
        variants = (b" " + canonical, canonical + b"\n",
            canonical.replace(b'"schema":', b'"\\u0073chema":', 1),
            canonical.replace(b'/v4', b'\\/v4', 1))
        for raw in variants:
            self.assertNotEqual(raw, canonical)
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
            with self.subTest(length=len(raw)), \
                    patch.object(plan, "_expectations", wraps=plan._expectations) as authenticate, \
                    patch.object(plan.semantics, "_verify", wraps=plan.semantics._verify) as semantics, \
                    patch.object(hashlib, "sha256", wraps=hashlib.sha256) as hashes:
                with self.assertRaisesRegex(plan.RevocationPlanError, "original envelope bytes are not canonical"):
                    wire_reader._verify_signed_envelope_on_work(raw, work=work, **expectations(fixture))
            self.assertEqual((authenticate.call_count, semantics.call_count, hashes.call_count), (0, 0, 0))
            self.assertGreater(work.input_bytes, 4 * len(raw))

    def test_raw_replay_independent_full_peak_exact_and_minus_one_keep_original_work(self):
        fixture = oracle.PlanFixture(approval=False, include_audit=False)
        raw = wire(fixture.envelope)
        prior = (3, 17, 5)
        prefix = oracle.add(prior, decoder_units(raw, fixture.envelope), (0, 2 * len(raw), 0))
        phases = oracle.independent_metrics(fixture)
        peak = oracle.add(prefix, phases["admission"])
        total = oracle.add(prefix, phases["total"])
        for dimension in (None, 0, 1, 2):
            limits = list(peak)
            if dimension is not None:
                limits[dimension] -= 1
            work = accounting._ValidationWork(accounting.QueryReadValidationLimits(*limits))
            work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
            entering = work.limits
            with self.subTest(dimension=dimension):
                if dimension is None:
                    actual = wire_reader._verify_signed_envelope_on_work(raw, work=work, **expectations(fixture))
                    self.assertEqual(actual.envelope_bytes, raw)
                    self.assertEqual(oracle.units(work.metrics), total)
                else:
                    with self.assertRaises(ValueError):
                        wire_reader._verify_signed_envelope_on_work(raw, work=work, **expectations(fixture))
                    self.assertTrue(all(before <= after <= ceiling
                        for before, after, ceiling in zip(prior, oracle.units(work.metrics), limits)))
            self.assertIs(work.limits, entering)
            self.assertFalse(hasattr(work, "_revocation_packaging_owner"))

    def test_external_request_is_not_adopted_from_original_signed_payload(self):
        fixture = oracle.PlanFixture(approval=False, include_audit=False)
        supplied = expectations(fixture)
        supplied["expected_request"]["arguments"]["reason"] = "different independent request"
        work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
        with patch.object(plan.semantics, "_verify", wraps=plan.semantics._verify) as semantics:
            with self.assertRaises(plan.RevocationPlanError):
                wire_reader._verify_signed_envelope_on_work(wire(fixture.envelope), work=work, **supplied)
        self.assertEqual(semantics.call_count, 0)

    def test_canonical_false_signature_still_reaches_actual_verifier_and_denies(self):
        fixture = oracle.PlanFixture(approval=False, include_audit=False)
        envelope = copy.deepcopy(fixture.envelope)
        envelope["signatureBase64Url"] = "A" * 86
        work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
        with patch.object(plan, "_expectations", wraps=plan._expectations) as authenticated, \
                patch.object(plan.semantics, "_verify", wraps=plan.semantics._verify) as semantics:
            with self.assertRaises(plan.RevocationPlanError):
                wire_reader._verify_signed_envelope_on_work(wire(envelope), work=work, **expectations(fixture))
        self.assertEqual((authenticated.call_count, semantics.call_count), (1, 0))
        self.assertEqual(work.hash_work, 1)


if __name__ == "__main__":
    unittest.main()
