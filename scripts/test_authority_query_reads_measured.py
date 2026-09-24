#!/usr/bin/env python3
"""Measured query bookkeeping over the genuine existing validation body.

Independent canonical records and work oracles exercise actual source helpers;
observers delegate real encoders and hashes. No SQL, primary/range verifier,
operation kernel or successful proof token is substituted. These observations
still establish neither predicate truth nor completeness or authentication.
All source fixtures remain unrun until the frozen verification lane is admitted.
"""
from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError, fields, replace
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_complete_query as complete
from serverware import authority_query_read_work as work_component
from serverware import authority_query_reads as reads
from serverware import authority_transition_core as core
import test_authority_complete_query as complete_oracle
import test_authority_query_reads as legacy_oracle


OPERATION = "webauthn.credential.revoke"
CREDENTIALS = "webauthn_credentials"


def wire(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("ascii")


def graph_nodes(value):
    if type(value) is dict:
        return 1 + sum(1 + graph_nodes(child) for child in value.values())
    if type(value) in (tuple, list):
        return 1 + sum(graph_nodes(child) for child in value)
    return 1


def nonempty_containers(value):
    if type(value) is dict:
        return int(bool(value)) + sum(nonempty_containers(child) for child in value.values())
    if type(value) in (tuple, list):
        return int(bool(value)) + sum(nonempty_containers(child) for child in value)
    return 0


def address_bytes(address):
    return 8 + len(address.table) + 8 + len(address.key_json) + 8 + len(address.key_digest) + 9


def record_bytes(record):
    return (8 + len(record.query_id) + 8 + len(record.declared_query_json)
        + 8 + len(record.resolved_query_json) + 8 + len(str(record.returned_row_count))
        + sum(address_bytes(address) for address in record.addresses))


class ExpectedWork:
    """Independent units for an explicitly enumerated semantic work schedule."""

    def __init__(self):
        self.hashes = self.bytes = self.nodes = 0

    def encoding(self, value, *, copies=0, ensure_ascii=True):
        encoded = json.dumps(value, ensure_ascii=ensure_ascii, allow_nan=False,
            sort_keys=True, separators=(",", ":")).encode("ascii" if ensure_ascii else "utf-8")
        self.bytes += (2 + copies) * len(encoded)
        self.nodes += (2 + copies) * graph_nodes(value)

    def copy(self, value):
        self.bytes += len(wire(value)) + nonempty_containers(value)
        self.nodes += graph_nodes(value)

        def scalar_encodings(item):
            if item is None or type(item) in (bool, int):
                self.encoding(item)
            elif type(item) is dict:
                for child in item.values():
                    scalar_encodings(child)
            elif type(item) in (list, tuple):
                for child in item:
                    scalar_encodings(child)

        scalar_encodings(value)

    def record(self, record, count=1):
        self.bytes += count * record_bytes(record)

    def address(self, address, count=1):
        self.bytes += count * address_bytes(address)

    def profile(self, query):
        self.encoding(complete_oracle.index_oracle.descriptor(query.index_id), ensure_ascii=False)
        self.hashes += 1


def forged(value, **changes):
    result = object.__new__(type(value))
    for field in fields(value):
        object.__setattr__(result, field.name, changes.get(field.name, getattr(value, field.name)))
    return result


class MixedFixture:
    """Observational rows, deliberately not a claimed authenticated population."""

    def __init__(self, *, payload=None):
        self.arguments = complete_oracle.arguments()
        self.payload = {"flags": [True, None, -7], "label": "snow-雪"} if payload is None else payload
        self.first = legacy_oracle.selection(CREDENTIALS, {"id": "origin-雪"},
            {"id": "origin-雪", "payload": self.payload, "next_id": "missing", "user_id": "alice"})
        self.second = legacy_oracle.selection(CREDENTIALS, {"id": "second"},
            {"id": "second", "user_id": "alice"})
        self.absent = legacy_oracle.selection(CREDENTIALS, {"id": "missing"}, None)
        self.session = legacy_oracle.selection("oidc_browser_sessions", {"id": "session-a"},
            {"id": "session-a", "status": "pending_webauthn"})
        self.selected = (self.first, self.second, self.absent, self.session)
        reference = core.SelectedRowFieldReference(CREDENTIALS, {"id": "origin-雪"}, "payload")
        absent_reference = core.SelectedRowFieldReference(CREDENTIALS, {"id": "origin-雪"}, "next_id")
        self.source = legacy_oracle.exact("source", "origin-雪")
        self.dependent = legacy_oracle.query("dependent", maximum_rows=1,
            predicates=(core.QueryPredicate("metadata", "eq", reference),))
        self.empty = legacy_oracle.query("empty", maximum_rows=1,
            predicates=(core.QueryPredicate("user_id", "eq", "nobody"),))
        self.missing = legacy_oracle.query("missing", maximum_rows=1,
            predicates=(core.QueryPredicate("id", "eq", absent_reference),),
            absent_key={"id": absent_reference})
        self.complete_queries = tuple(complete.bind_query(OPERATION, role,
            arguments=self.arguments, cutoff_us=complete_oracle.CUTOFF_US) for role in complete_oracle.ROLES)
        self.overlap = legacy_oracle.query("overlap", maximum_rows=2,
            order_by=(core.QueryOrder("id", True),))
        self.queries = (self.source, self.dependent, self.empty, self.missing,
                        *self.complete_queries, self.overlap)
        self.ordered = ((self.first,), (self.second,), (), (self.absent,),
                        (self.session,), (), (), (), (), (self.second, self.first))
        self.resolved = tuple(self.resolve(query) for query in self.queries)
        self.records = tuple(self.record(query, resolved, ordered)
            for query, resolved, ordered in zip(self.queries, self.resolved, self.ordered))

    def resolve(self, query):
        if type(query) is complete.CompleteIndexQuery:
            return query

        def value(item):
            if type(item) is core.SelectedRowFieldReference:
                selected = next(row for row in self.selected
                    if row["table"] == item.table and wire(row["key"]) == wire(item.key))
                return copy.deepcopy(selected["row"][item.column])
            return copy.deepcopy(item)

        return replace(query,
            predicates=tuple(core.QueryPredicate(item.column, item.operator, value(item.value))
                             for item in query.predicates),
            absent_key=None if query.absent_key is None else
                {key: value(item) for key, item in query.absent_key.items()},
            order_by=query.order_by or (core.QueryOrder("id"),))

    def document(self, query):
        if type(query) is complete.CompleteIndexQuery:
            return complete_oracle.complete_document(query.role, values=self.arguments)
        return legacy_oracle.query_document(query)

    def record(self, query, resolved, selected):
        addresses = tuple(reads.QueryReadAddress(row["table"], wire(row["key"]),
            row["keyDigest"], row["present"]) for row in selected)
        return reads.QueryRead(query.query_id, wire(self.document(query)), wire(self.document(resolved)),
            addresses, sum(row["present"] for row in selected))

    def inputs(self):
        return {"queries": self.queries, "query_reads": self.records, "selected_rows": self.selected}


def expected_work(fixture):
    """Count the fixed semantic passes from independent fixture documents.

    No production accounting, encoder, source descriptor, association or copy
    helper supplies these totals. Immutable scalar frames are a separate unit
    from the repeated JSON traversals; neither represents heap allocations.
    """
    result = ExpectedWork()

    def values(query):
        return (tuple(item.value for item in query.predicates)
                + (() if query.absent_key is None else tuple(query.absent_key.values())))

    def reference_key_copies(query):
        # contract_value's hidden dict(key): a measurement plus a copy.
        for value in values(query):
            if type(value) is core.SelectedRowFieldReference:
                result.encoding(value.key)

    def key_work(key):
        result.copy(key)
        result.encoding(key)

    def selected_address(selected):
        key_work(selected["key"])
        if selected["present"]:
            key_work({"id": selected["row"]["id"]})
        result.hashes += 1
        result.address(reads.QueryReadAddress(selected["table"], wire(selected["key"]),
            selected["keyDigest"], selected["present"]))

    # Source snapshot, its actual constructor serializations, and closure.
    for query in fixture.queries:
        if type(query) is complete.CompleteIndexQuery:
            # Eight real profile calls across snapshot(2), closure(1),
            # resolution(1), shape comparison(2), and final capture(2).
            for _ in range(8):
                result.profile(query)
        else:
            for value in values(query):
                if type(value) is core.SelectedRowFieldReference:
                    result.copy(value.key)
                    result.encoding(value.key, copies=1)
                else:
                    result.copy(value)
            if query.absent_key is not None:
                for name in query.absent_key:
                    result.copy(name)
            reference_key_copies(query)
        document = fixture.document(query)
        result.encoding(document)
        result.bytes += len(wire(document))  # local source-copy reservation

    # Two real record reconstructions each inspect two outer headers and all
    # address fields. Other whole-record passes are budget, initial/final
    # associations, final equality, and every later query's prior prefix.
    for ordinal, record in enumerate(fixture.records):
        addresses = sum(address_bytes(address) for address in record.addresses)
        header = record_bytes(record) - addresses
        result.bytes += 2 * (2 * header + addresses)
        result.record(record, 4 + len(fixture.records) - 1 - ordinal)
        result.bytes += header  # final captured QueryRead constructor
    for selected in fixture.selected:
        selected_address(selected)

    for query, resolved, ordered, record in zip(
            fixture.queries, fixture.resolved, fixture.ordered, fixture.records):
        if type(query) is not complete.CompleteIndexQuery:
            for before, after in zip(values(query), values(resolved)):
                if type(before) is core.SelectedRowFieldReference:
                    key_work(before.key)
                result.copy(after)
            reference_key_copies(query)  # resolution-shape contract projection
        resolved_document = fixture.document(resolved)
        result.encoding(resolved_document)  # expected shape, after substitution
        result.encoding(resolved_document)  # actual resolved shape
        if type(query) is not complete.CompleteIndexQuery:
            reference_key_copies(query)  # retained declared contract projection
        declared_document = fixture.document(query)
        result.encoding(declared_document)
        result.encoding(resolved_document)
        result.bytes += len(wire(declared_document)) + len(wire(resolved_document))
        for selected in ordered:
            selected_address(selected)
        if (type(query) is not complete.CompleteIndexQuery
                and record.returned_row_count == 0 and resolved.absent_key is not None):
            key_work(resolved.absent_key)
    return result


class AuthorityQueryReadMeasuredTests(unittest.TestCase):
    def measured(self, fixture, *, limits=None, **changes):
        inputs = fixture.inputs()
        inputs.update(changes)
        return reads.validate_query_reads_measured(OPERATION,
            limits=reads.QueryReadValidationLimits() if limits is None else limits, **inputs)

    def test_mixed_observations_equal_actual_legacy_validation_and_independent_records(self):
        fixture = MixedFixture()
        expected = reads.validate_query_reads(OPERATION, **fixture.inputs())
        observed = self.measured(fixture)
        self.assertEqual(expected, fixture.records)
        self.assertEqual(observed.query_reads, expected)
        self.assertEqual(tuple(wire(fixture.document(query)) for query in observed.queries),
                         tuple(wire(fixture.document(query)) for query in fixture.queries))
        self.assertEqual(len(observed.query_reads), 10)
        self.assertEqual(tuple(record.returned_row_count for record in observed.query_reads),
                         (1, 1, 0, 0, 1, 0, 0, 0, 0, 2))

    def test_empty_complete_roles_absence_and_observed_overlap_remain_distinct(self):
        fixture = MixedFixture()
        observed = self.measured(fixture)
        self.assertEqual(observed.query_reads[2].addresses, ())
        self.assertEqual(observed.query_reads[3].addresses,
            (reads.QueryReadAddress(CREDENTIALS, b'{"id":"missing"}', fixture.absent["keyDigest"], False),))
        self.assertEqual(tuple(record.addresses for record in observed.query_reads[5:9]), ((), (), (), ()))
        self.assertEqual(observed.query_reads[-1].addresses,
            (observed.query_reads[1].addresses[0], observed.query_reads[0].addresses[0]))
        self.assertEqual(observed.metrics.hash_work, 8 * 5 + 4 + 6)

    def test_genuine_hash_calls_match_complete_snapshots_and_all_address_occurrences(self):
        fixture = MixedFixture()
        actual_sha = hashlib.sha256
        with patch.object(hashlib, "sha256", wraps=actual_sha) as observed_hashes:
            result = self.measured(fixture)
        self.assertEqual(result.metrics.hash_work, 50)
        self.assertEqual(observed_hashes.call_count, 50)

    def test_observation_result_is_not_primary_predicate_or_complete_range_authority(self):
        fixture = MixedFixture()
        # This authenticated-looking field is never proved by bookkeeping;
        # ordinary predicates and complete leaf/projection membership are not
        # evaluated here. Their actual verifiers remain separate requirements.
        fixture.first["row"]["user_id"] = "changed without a primary proof"
        fixture.session["row"]["status"] = "not-the-declared-status"
        result = self.measured(fixture)
        self.assertEqual(result.query_reads, fixture.records)
        self.assertNotIn("verified", {field.name for field in fields(result)})
        with self.assertRaises((TypeError, reads.QueryReadError)):
            reads.validate_query_reads_measured(OPERATION, queries=result,
                query_reads=result.query_reads, selected_rows=fixture.selected,
                limits=reads.QueryReadValidationLimits())
        # Present exact-key association is another intentional legacy boundary:
        # only the zero-result absence branch checks the resolved absent key.
        # New operation-level admission must independently bind this point key.
        point = legacy_oracle.exact("different_present_key", "requested-key")
        record = fixture.record(point, fixture.resolve(point), (fixture.second,))
        inputs = {"queries": (point,), "query_reads": (record,), "selected_rows": (fixture.second,)}
        self.assertEqual(reads.validate_query_reads(OPERATION, **inputs), (record,))
        measured = reads.validate_query_reads_measured(OPERATION, **inputs,
            limits=reads.QueryReadValidationLimits())
        self.assertEqual(measured.query_reads, (record,))
        self.assertEqual(record.addresses[0].key_json, b'{"id":"second"}')
        self.assertNotEqual(record.addresses[0].key_json, wire(point.absent_key))

    def test_actual_resolve_capture_and_source_closure_are_not_replaced_by_metrics(self):
        fixture = MixedFixture()
        actual_resolve, actual_capture = reads._resolve, reads._capture
        actual_close = core.close_queries
        with patch.object(reads, "_resolve", wraps=actual_resolve) as resolve_calls, \
                patch.object(reads, "_capture", wraps=actual_capture) as capture_calls, \
                patch.object(core, "close_queries", wraps=actual_close) as close_calls:
            result = self.measured(fixture)
        self.assertEqual(resolve_calls.call_count, len(fixture.queries))
        self.assertEqual(capture_calls.call_count, len(fixture.queries))
        self.assertEqual(close_calls.call_count, 1)
        self.assertEqual(result.query_reads, fixture.records)

    def test_actual_measured_limits_can_tighten_each_phase_but_not_expand_source_caps(self):
        fixture = MixedFixture()
        expected = expected_work(fixture)
        initial = self.measured(fixture)
        self.assertEqual((initial.metrics.hash_work, initial.metrics.input_bytes, initial.metrics.json_nodes),
                         (expected.hashes, expected.bytes, expected.nodes))
        exact = reads.QueryReadValidationLimits(max_hashes=expected.hashes,
            max_input_bytes=expected.bytes, max_json_nodes=expected.nodes)
        repeated = self.measured(fixture, limits=exact)
        self.assertEqual(repeated.metrics, initial.metrics)
        self.assertEqual(repeated.query_reads, initial.query_reads)
        for name in ("max_hashes", "max_input_bytes", "max_json_nodes"):
            with self.subTest(name=name), self.assertRaises(reads.QueryReadError):
                self.measured(fixture, limits=replace(exact, **{name: getattr(exact, name) - 1}))
        for name, maximum in (("max_hashes", 8_000_000),
                              ("max_input_bytes", 64 * 1024 * 1024),
                              ("max_json_nodes", 1_000_000)):
            with self.subTest(name=name), self.assertRaises(ValueError):
                reads.QueryReadValidationLimits(**{name: maximum + 1})

    def test_limits_reject_wrong_exact_types_missing_fields_and_constructor_bypasses(self):
        fixture = MixedFixture()
        defaults = reads.QueryReadValidationLimits()
        self.assertEqual((defaults.max_hashes, defaults.max_input_bytes, defaults.max_json_nodes),
                         (8_000_000, 64 * 1024 * 1024, 1_000_000))
        for name in ("max_hashes", "max_input_bytes", "max_json_nodes"):
            for value in (True, False, 0, -1, 1.5, "1", None):
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    reads.QueryReadValidationLimits(**{name: value})
        malformed = ({}, object.__new__(type(defaults)),
            forged(defaults, max_hashes=True), forged(defaults, max_input_bytes=64 * 1024 * 1024 + 1),
            forged(defaults, max_json_nodes=1_000_001))
        actual_sha = hashlib.sha256
        for value in malformed:
            with self.subTest(value=type(value)), \
                    patch.object(hashlib, "sha256", wraps=actual_sha) as hashes, \
                    self.assertRaises((ValueError, TypeError)):
                self.measured(fixture, limits=value)
            self.assertEqual(hashes.call_count, 0)

    def test_record_revalidation_does_not_trust_frozen_objects_or_ascii_byte_claims(self):
        fixture = MixedFixture()
        first = fixture.records[0]
        malformed = (
            forged(first, returned_row_count=True),
            forged(first, declared_query_json=b'{"not":"the declaration"}'),
            forged(first, resolved_query_json=first.resolved_query_json + b" "),
            forged(first, addresses=(forged(first.addresses[0], present=1),)),
            forged(first, addresses=(forged(first.addresses[0], key_json=b'{"id":"other"}'),)),
            object.__new__(reads.QueryRead),
        )
        for value in malformed:
            with self.subTest(value=type(value)), self.assertRaises(reads.QueryReadError):
                self.measured(fixture, query_reads=(value, *fixture.records[1:]))

    def test_query_inventory_and_global_coverage_fail_in_the_real_shared_body(self):
        fixture = MixedFixture()
        variants = (
            {"queries": fixture.queries[:-1]},
            {"query_reads": fixture.records[:-1]},
            {"query_reads": (fixture.records[1], fixture.records[0], *fixture.records[2:])},
            {"query_reads": (*fixture.records[:-1], fixture.records[0])},
            {"selected_rows": fixture.selected[:-1]},
            {"selected_rows": (*fixture.selected, fixture.selected[0])},
            {"selected_rows": (*fixture.selected,
                legacy_oracle.selection(CREDENTIALS, {"id": "unobserved"}, None))},
        )
        for changes in variants:
            with self.subTest(fields=tuple(changes)), self.assertRaises(reads.QueryReadError):
                self.measured(fixture, **changes)

    def test_deferred_values_replay_only_prior_present_fields_without_scalar_coercion(self):
        fixture = MixedFixture()
        reordered_queries = (fixture.dependent, fixture.source, *fixture.queries[2:])
        reordered_reads = (fixture.records[1], fixture.records[0], *fixture.records[2:])
        with self.assertRaises(reads.QueryReadError):
            self.measured(fixture, queries=reordered_queries, query_reads=reordered_reads)
        altered = copy.deepcopy(fixture.selected)
        altered[0]["row"]["payload"] = "different reference value"
        with self.assertRaises(reads.QueryReadError):
            self.measured(fixture, selected_rows=altered)
        for value in (False, 1, None):
            changed = copy.deepcopy(fixture.selected)
            changed[0]["row"]["id"] = value
            with self.subTest(value=value), self.assertRaises(reads.QueryReadError):
                self.measured(fixture, selected_rows=changed)

    def test_returned_query_snapshots_and_records_are_fresh_not_caller_aliases(self):
        fixture = MixedFixture()
        result = self.measured(fixture)
        self.assertIsNot(result.queries[0], fixture.queries[0])
        self.assertIsNot(result.query_reads[0], fixture.records[0])
        self.assertIsNot(result.query_reads[0].addresses[0], fixture.records[0].addresses[0])
        self.assertIsNot(result.queries[1].predicates[0].value.key,
                         fixture.queries[1].predicates[0].value.key)
        fixture.queries[1].predicates[0].value.key["id"] = "caller mutation"
        self.assertEqual(result.queries[1].predicates[0].value.key, {"id": "origin-雪"})
        self.assertEqual(result.query_reads[1], fixture.records[1])
        with self.assertRaises(FrozenInstanceError):
            result.metrics.hash_work = 0
        with self.assertRaises(FrozenInstanceError):
            result.query_reads = ()

    def test_repeated_large_reference_values_share_one_real_default_budget(self):
        fixture = MixedFixture(payload="x" * (256 * 1024))
        fixture.selected = (fixture.first,)
        queries, records = [fixture.source], [fixture.records[0]]
        for ordinal in range(32):
            reference = core.SelectedRowFieldReference(CREDENTIALS, {"id": "origin-雪"}, "payload")
            query = legacy_oracle.query(f"repeated_{ordinal}", maximum_rows=1,
                predicates=(core.QueryPredicate("metadata", "eq", reference),))
            queries.append(query)
            records.append(fixture.record(query, fixture.resolve(query), (fixture.first,)))
        fixture.queries, fixture.records = tuple(queries), tuple(records)
        self.assertLess(sum(len(record.declared_query_json) + len(record.resolved_query_json)
                            for record in fixture.records), 9 * 1024 * 1024)
        # Every original helper's local copy is small, and the retained byte
        # inventory remains admitted. Cumulative repeated scans/encodings are
        # what must deny under the unchanged 64 MiB measured-work ceiling.
        reads.validate_read_budget(OPERATION, query_reads=fixture.records)
        self.assertEqual(reads.validate_query_reads(OPERATION, **fixture.inputs()), fixture.records)
        with self.assertRaises(reads.QueryReadError):
            self.measured(fixture)

    def test_actual_encoder_measurement_and_encoding_are_both_charged_before_serialization(self):
        value = {"snow-雪": [None, True, False, -70, "\x00\t\n\"\\\x7f😀"], "empty": {}}
        expected, nodes = wire(value), graph_nodes(value)
        limits = reads.QueryReadValidationLimits(max_input_bytes=2 * len(expected), max_json_nodes=2 * nodes)
        meter = work_component._ValidationWork(limits)
        actual_dumps = json.dumps
        with patch.object(json, "dumps", wraps=actual_dumps) as encodings:
            encoded = meter.wire(value)
        self.assertEqual(encoded, expected)
        self.assertEqual(encodings.call_count, 1)
        self.assertEqual((meter.metrics.input_bytes, meter.metrics.json_nodes),
                         (2 * len(expected), 2 * nodes))
        for limited in (replace(limits, max_input_bytes=2 * len(expected) - 1),
                        replace(limits, max_json_nodes=2 * nodes - 1)):
            meter = work_component._ValidationWork(limited)
            with patch.object(json, "dumps", wraps=actual_dumps) as encodings, \
                    self.assertRaises(ValueError):
                meter.wire(value)
            self.assertEqual(encodings.call_count, 0)
        # These direct accounting controls are not successful query admission.

    def test_hidden_constructor_copy_and_utf8_profile_encoding_have_separate_real_work(self):
        key = {"id": "quoted-\"-雪-😀"}
        meter = work_component._ValidationWork(reads.QueryReadValidationLimits())
        encoded_size, nodes = len(wire(key)), graph_nodes(key)
        meter.prepare_encoding(key, shallow_copies=1)
        self.assertEqual((meter.metrics.input_bytes, meter.metrics.json_nodes),
                         (3 * encoded_size, 3 * nodes))
        descriptor = complete_oracle.index_oracle.descriptor("webauthn_session_credential_status")
        utf8 = json.dumps(descriptor, ensure_ascii=False, allow_nan=False, sort_keys=True,
                          separators=(",", ":")).encode("utf-8")
        descriptor_nodes = graph_nodes(descriptor)
        meter.prepare_encoding(descriptor, ensure_ascii=False)
        self.assertEqual((meter.metrics.input_bytes, meter.metrics.json_nodes),
            (3 * encoded_size + 2 * len(utf8), 3 * nodes + 2 * descriptor_nodes))
        meter.prepare_copy(key)
        self.assertEqual((meter.metrics.input_bytes, meter.metrics.json_nodes),
            (5 * encoded_size + 2 * len(utf8), 5 * nodes + 2 * descriptor_nodes))

    def test_measured_source_copy_rejects_unsupported_cycles_and_invalid_unicode(self):
        fixture = MixedFixture()
        cycle = []
        cycle.append(cycle)
        for value in (1.5, b"not JSON", {1: "nontext key"}, "\ud800", "nul\0value", cycle):
            definition = forged(fixture.empty,
                predicates=(core.QueryPredicate("metadata", "eq", value),))
            queries = (*fixture.queries[:2], definition, *fixture.queries[3:])
            with self.subTest(value=type(value)), self.assertRaises(reads.QueryReadError):
                self.measured(fixture, queries=queries)

    def test_closed_outer_inventories_and_limit_subclasses_do_not_acquire_admission(self):
        fixture = MixedFixture()
        for changes in ({"queries": list(fixture.queries)},
                        {"query_reads": list(fixture.records)},
                        {"selected_rows": list(fixture.selected)}):
            with self.subTest(fields=tuple(changes)), self.assertRaises(reads.QueryReadError):
                self.measured(fixture, **changes)
        with self.assertRaises(reads.QueryReadError):
            reads.validate_query_reads_measured("not.a.source.operation", **fixture.inputs(),
                limits=reads.QueryReadValidationLimits())

        class DerivedLimits(reads.QueryReadValidationLimits):
            pass

        with self.assertRaises(ValueError):
            self.measured(fixture, limits=DerivedLimits())

    def test_full_mixed_work_equals_independent_copy_encoding_frame_and_profile_schedule(self):
        fixture = MixedFixture()
        expected = expected_work(fixture)
        actual = self.measured(fixture)
        self.assertEqual(actual.metrics.hash_work, 50)
        self.assertEqual((actual.metrics.hash_work, actual.metrics.input_bytes, actual.metrics.json_nodes),
                         (expected.hashes, expected.bytes, expected.nodes))
        self.assertGreater(expected.bytes, sum(record_bytes(record) for record in fixture.records))
        self.assertGreater(expected.nodes, sum(graph_nodes(fixture.document(query))
                                              for query in fixture.queries))

    def test_hash_allowance_rejects_before_an_unreserved_actual_sha_call(self):
        fixture = MixedFixture()
        actual_sha = hashlib.sha256
        with patch.object(hashlib, "sha256", wraps=actual_sha) as hashes, \
                self.assertRaises(reads.QueryReadError):
            self.measured(fixture, limits=reads.QueryReadValidationLimits(max_hashes=49))
        self.assertEqual(hashes.call_count, 49)


if __name__ == "__main__":
    unittest.main()
