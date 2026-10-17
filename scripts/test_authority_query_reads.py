#!/usr/bin/env python3
"""Pure retained-query bookkeeping, not SQL or completeness verification.

The actual closed query/address functions and KernelContext accessor run here.
Independent wire/key encodings provide the expected observations. There is no
planner/registry import, synthetic successful verifier or claimed database
execution. A retained result records a query observation; it is not membership,
predicate completeness, maintained-index or current-root authority.
"""
from __future__ import annotations

import copy
import hashlib
import json
import sys
import unittest
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate import authority_contract
from catchplate import authority_query_reads as reads
from catchplate import authority_transition_core as core


OPERATION = "webauthn.credential.revoke"
CREDENTIALS = "webauthn_credentials"
CHALLENGES = "webauthn_challenges"


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("ascii")


def framed(domain, *frames):
    result = hashlib.sha256(domain.encode("ascii") + b"\0")
    for value in frames:
        result.update(len(value).to_bytes(8, "big"))
        result.update(value)
    return "sha256:" + result.hexdigest()


def selection(table, key, row):
    return {"table": table, "key": copy.deepcopy(key),
            "keyDigest": framed("catchplate.policyAuthorityBusinessKey/v1", table.encode("ascii"), canonical(key)),
            "present": row is not None, "row": copy.deepcopy(row), "contractSelector": None}


def query(name, *, table=CREDENTIALS, predicates=(), order_by=(), maximum_rows=4, **options):
    return core.BoundedQuery(query_id=f"catchplate.policyAuthorityQuery/{OPERATION}/{name}/{table}/v1",
        table=table, predicates=predicates, order_by=order_by, maximum_rows=maximum_rows, **options)


def exact(name, identifier):
    return query(name, predicates=(core.QueryPredicate("id", "eq", identifier),),
                 maximum_rows=1, absent_key={"id": identifier})


def encoded_value(value):
    if type(value) is core.SelectedRowFieldReference:
        return {"schema": "catchplate.policyAuthoritySelectedRowField/v1", "table": value.table,
                "key": dict(value.key), "column": value.column}
    return value


def query_document(value):
    return {"schema": "catchplate.policyAuthorityQueryProgram/v1", "queryId": value.query_id,
            "table": value.table,
            "predicates": [{"column": item.column, "operator": item.operator, "value": encoded_value(item.value)}
                           for item in value.predicates],
            "orderBy": [{"column": item.column, "descending": item.descending} for item in value.order_by],
            "maximumRows": value.maximum_rows, "overflowDisposition": "fail-closed",
            "absentKey": None if value.absent_key is None else {key: encoded_value(item) for key, item in value.absent_key.items()},
            "requireAbsence": value.require_absence, "proofPrimitive": value.proof_primitive,
            "workUnits": value.work_units, "exactPage": value.exact_page, "pageSize": value.page_size,
            "continuationTokenDigest": value.continuation_token_digest, "secondaryIndexName": value.secondary_index_name}


def forged(value, **changes):
    copied = object.__new__(type(value))
    for field in fields(value):
        object.__setattr__(copied, field.name, changes.get(field.name, getattr(value, field.name)))
    return copied


class AuthorityQueryReadTests(unittest.TestCase):
    def setUp(self):
        self.first = selection(CREDENTIALS, {"id": "a-雪"},
            {"id": "a-雪", "user_id": "alice", "credential_id": "public-a", "nested": {"flags": [True, None]}})
        self.second = selection(CREDENTIALS, {"id": "b"},
            {"id": "b", "user_id": "alice", "credential_id": "public-b"})
        self.one = exact("first", "a-雪")

    def capture(self, query_value, selected=(), *, prior=(), union=(), returned=None):
        resolved = reads.resolve_query(OPERATION, query_value, prior_reads=prior, selected_rows=union)
        if returned is None:
            returned = sum(row["present"] is True for row in selected)
        return reads.capture_query_read(OPERATION, query_value, resolved_query=resolved,
            ordered_selected_rows=selected, returned_row_count=returned)

    def validate(self, queries, records, selected=()):
        return reads.validate_query_reads(OPERATION, queries=queries,
            query_reads=records, selected_rows=selected)

    def test_present_record_has_independent_declared_resolved_and_key_bytes(self):
        record = self.capture(self.one, (self.first,))
        resolved_document = query_document(self.one)
        resolved_document["orderBy"] = [{"column": "id", "descending": False}]
        expected_address = reads.QueryReadAddress(CREDENTIALS, b'{"id":"a-\\u96ea"}',
            framed("catchplate.policyAuthorityBusinessKey/v1", CREDENTIALS.encode("ascii"),
                   b'{"id":"a-\\u96ea"}'), True)
        expected = reads.QueryRead(self.one.query_id, canonical(query_document(self.one)),
            canonical(resolved_document), (expected_address,), 1)
        self.assertEqual(record, expected)
        self.assertEqual(self.validate((self.one,), (record,), (self.first,)), (expected,))
        self.assertNotEqual(record.declared_query_json, record.resolved_query_json)
        with self.assertRaises(FrozenInstanceError):
            record.returned_row_count = 0
        with self.assertRaises(FrozenInstanceError):
            record.addresses[0].present = False

    def test_snapshot_detaches_mutable_values_and_deferred_keys(self):
        value = {"nested": ["雪", True, None, -7]}
        source_key = {"id": "a-雪"}
        reference = core.SelectedRowFieldReference(CREDENTIALS, source_key, "user_id")
        source = query("snapshot", predicates=(core.QueryPredicate("metadata", "eq", value),
            core.QueryPredicate("user_id", "eq", reference)), order_by=(core.QueryOrder("id", True),))
        snapshot, = reads.snapshot_queries(OPERATION, (source,))
        original = canonical(query_document(source))
        value["nested"].append("changed")
        source_key["id"] = "changed"
        self.assertEqual(canonical(query_document(snapshot)), original)
        self.assertIsNot(snapshot, source)
        self.assertIsNot(snapshot.predicates[0].value, value)
        self.assertIsNot(snapshot.predicates[1].value.key, source_key)
        snapshot.predicates[0].value["nested"].append("private mutation")
        self.assertNotIn("private mutation", value["nested"])

    def test_empty_predicate_and_exact_absence_are_distinct_retained_queries(self):
        ordinary = query("empty", predicates=(core.QueryPredicate("user_id", "eq", "nobody"),))
        absent_query = exact("absent", "missing")
        absent = selection(CREDENTIALS, {"id": "missing"}, None)
        empty_record = self.capture(ordinary)
        absent_record = self.capture(absent_query, (absent,))
        self.assertEqual(empty_record.addresses, ())
        self.assertEqual(absent_record.addresses,
            (reads.QueryReadAddress(CREDENTIALS, canonical({"id": "missing"}), absent["keyDigest"], False),))
        self.assertEqual((empty_record.returned_row_count, absent_record.returned_row_count), (0, 0))
        self.assertEqual(self.validate((ordinary, absent_query), (empty_record, absent_record), (absent,)),
                         (empty_record, absent_record))
        self.assertEqual(reads.query_rows(OPERATION, query_reads=(empty_record, absent_record),
            selected_rows=(absent,), query_id=ordinary.query_id), ())
        self.assertEqual(reads.query_rows(OPERATION, query_reads=(empty_record, absent_record),
            selected_rows=(absent,), query_id=absent_query.query_id), (absent,))

    def test_overlapping_queries_retain_each_order_but_share_one_global_address(self):
        ordered = query("ordered", predicates=(core.QueryPredicate("user_id", "eq", "alice"),),
            order_by=(core.QueryOrder("id", True),), maximum_rows=2)
        first_record = self.capture(self.one, (self.first,))
        second_record = self.capture(ordered, (self.second, self.first))
        self.first["contractSelector"] = "original-global-selector"
        validated = self.validate((self.one, ordered), (first_record, second_record), (self.first, self.second))
        self.assertEqual(validated[1].addresses, (
            reads.QueryReadAddress(CREDENTIALS, canonical({"id": "b"}), self.second["keyDigest"], True),
            first_record.addresses[0]))
        observed = reads.query_rows(OPERATION, query_reads=validated, selected_rows=(self.first, self.second),
            query_id=ordered.query_id)
        self.assertIs(observed[0], self.second)
        self.assertIs(observed[1], self.first)
        self.assertEqual(observed[1]["contractSelector"], "original-global-selector")
        self.assertEqual(json.loads(validated[1].resolved_query_json)["orderBy"],
                         [{"column": "id", "descending": True}])

    def test_query_program_missing_added_reordered_and_duplicate_ids_reject(self):
        other = exact("second", "b")
        first_record = self.capture(self.one, (self.first,))
        second_record = self.capture(other, (self.second,))
        valid = ((self.one, other), (first_record, second_record), (self.first, self.second))
        self.validate(*valid)
        cases = (
            ((self.one, other), (first_record,), (self.first,)),
            ((self.one,), (first_record, second_record), (self.first, self.second)),
            ((self.one, other), (second_record, first_record), (self.first, self.second)),
            ((other, self.one), (first_record, second_record), (self.first, self.second)),
            ((self.one, self.one), (first_record, first_record), (self.first,)),
            ((self.one, other), (first_record, first_record), (self.first, self.second)),
        )
        for queries, records, selected in cases:
            with self.subTest(queries=tuple(item.query_id for item in queries), records=records):
                with self.assertRaises(reads.QueryReadError):
                    self.validate(queries, records, selected)

    def test_altered_record_definitions_and_counts_reject_against_actual_source(self):
        record = self.capture(self.one, (self.first,))
        declared = query_document(self.one)
        resolved = json.loads(record.resolved_query_json)
        changed_declared = dict(declared, maximumRows=2)
        changed_resolved = dict(resolved, orderBy=[{"column": "id", "descending": True}])
        cases = (
            replace(record, declared_query_json=canonical(changed_declared)),
            replace(record, resolved_query_json=canonical(changed_resolved)),
            replace(record, declared_query_json=b"{}"),
            replace(record, resolved_query_json=b"[]"),
            replace(record, returned_row_count=0),
            replace(record, returned_row_count=2),
            replace(record, query_id=record.query_id.replace("/first/", "/other/")),
        )
        for changed in cases:
            with self.subTest(record=changed), self.assertRaises(reads.QueryReadError):
                self.validate((self.one,), (changed,), (self.first,))

    def test_deferred_reference_replays_original_field_and_detaches_resolved_value(self):
        first_record = self.capture(self.one, (self.first,))
        reference = core.SelectedRowFieldReference(CREDENTIALS, {"id": "a-雪"}, "nested")
        dependent = query("dependent", table=CHALLENGES,
            predicates=(core.QueryPredicate("context", "eq", reference),))
        resolved = reads.resolve_query(OPERATION, dependent,
            prior_reads=(first_record,), selected_rows=(self.first,))
        expected = query_document(dependent)
        expected["predicates"][0]["value"] = {"flags": [True, None]}
        expected["orderBy"] = [{"column": "id", "descending": False}]
        self.assertEqual(canonical(query_document(resolved)), canonical(expected))
        record = reads.capture_query_read(OPERATION, dependent, resolved_query=resolved,
            ordered_selected_rows=(), returned_row_count=0)
        self.assertEqual(record.resolved_query_json, canonical(expected))
        self.validate((self.one, dependent), (first_record, record), (self.first,))
        self.first["row"]["nested"]["flags"].append("changed")
        self.assertEqual(resolved.predicates[0].value, {"flags": [True, None]})
        self.assertEqual(record.resolved_query_json, canonical(expected))
        with self.assertRaisesRegex(reads.QueryReadError, "resolved fields"):
            self.validate((self.one, dependent), (first_record, record), (self.first,))

    def test_deferred_exact_absence_retains_original_and_resolved_key(self):
        first_record = self.capture(self.one, (self.first,))
        reference = core.SelectedRowFieldReference(CREDENTIALS, {"id": "a-雪"}, "credential_id")
        dependent = query("dependent-absence", table=CHALLENGES,
            predicates=(core.QueryPredicate("id", "eq", reference),), maximum_rows=1,
            absent_key={"id": reference}, require_absence=True)
        absent = selection(CHALLENGES, {"id": "public-a"}, None)
        record = self.capture(dependent, (absent,), prior=(first_record,), union=(self.first,))
        declared, resolved = json.loads(record.declared_query_json), json.loads(record.resolved_query_json)
        self.assertEqual(declared["absentKey"], {"id": encoded_value(reference)})
        self.assertEqual(resolved["absentKey"], {"id": "public-a"})
        self.assertEqual(resolved["predicates"], [{"column": "id", "operator": "eq", "value": "public-a"}])
        self.validate((self.one, dependent), (first_record, record), (self.first, absent))

    def test_deferred_fields_require_prior_present_observation_not_merely_union_row(self):
        record = self.capture(self.one, (self.first,))
        absent_query = exact("absent-source", "missing")
        absent = selection(CREDENTIALS, {"id": "missing"}, None)
        absent_record = self.capture(absent_query, (absent,))
        cases = (
            ({"id": "a-雪"}, "user_id", (), (self.first,)),
            ({"id": "a-雪"}, "user_id", (record,), ()),
            ({"id": "b"}, "user_id", (record,), (self.first, self.second)),
            ({"id": "a-雪"}, "missing_column", (record,), (self.first,)),
            ({"id": "missing"}, "user_id", (absent_record,), (absent,)),
        )
        for key, column, prior, selected in cases:
            dependent = query("dependent", predicates=(core.QueryPredicate("user_id", "eq",
                core.SelectedRowFieldReference(CREDENTIALS, key, column)),))
            with self.subTest(key=key, column=column, prior=prior), self.assertRaises(reads.QueryReadError):
                reads.resolve_query(OPERATION, dependent, prior_reads=prior, selected_rows=selected)

    def test_capture_shape_cannot_rewrite_non_reference_source_fields(self):
        resolved = reads.resolve_query(OPERATION, self.one, prior_reads=(), selected_rows=())
        changes = (
            replace(resolved, query_id=resolved.query_id.replace("/first/", "/other/")),
            replace(resolved, order_by=(core.QueryOrder("id", True),)),
            replace(resolved, work_units=2),
            replace(resolved, proof_primitive="ordered-exact-page", exact_page=True),
            exact("first", "b"),
        )
        for changed in changes:
            with self.subTest(query=changed), self.assertRaises(reads.QueryReadError):
                reads.capture_query_read(OPERATION, self.one, resolved_query=changed,
                    ordered_selected_rows=(self.first,), returned_row_count=1)

    def test_capture_rejects_overflow_duplicate_cross_table_and_presence_drift(self):
        absent_query = exact("missing", "missing")
        absent = selection(CREDENTIALS, {"id": "missing"}, None)
        other_absent = selection(CREDENTIALS, {"id": "different"}, None)
        challenge = selection(CHALLENGES, {"id": "a-雪"}, {"id": "a-雪"})
        ordinary = query("ordinary")
        cases = (
            (self.one, (self.first, self.second), 2),
            (ordinary, (self.first, self.first), 2),
            (ordinary, (challenge,), 1),
            (ordinary, (self.first,), 0),
            (ordinary, (absent,), 0),
            (ordinary, (absent,), 1),
            (ordinary, (), True),
            (ordinary, (), -1),
            (ordinary, (), 1),
            (absent_query, (), 0),
            (absent_query, (other_absent,), 0),
            (replace(self.one, require_absence=True), (self.first,), 1),
        )
        for definition, selected, returned in cases:
            with self.subTest(query=definition.query_id, selected=selected, count=returned):
                with self.assertRaises(reads.QueryReadError):
                    self.capture(definition, selected, returned=returned)

    def test_global_union_requires_exact_coverage_and_no_repeated_or_changed_address(self):
        record = self.capture(self.one, (self.first,))
        changed_presence = selection(CREDENTIALS, {"id": "a-雪"}, None)
        for selected in ((), (self.first, self.second), (self.first, self.first), (changed_presence,)):
            with self.subTest(selected=selected), self.assertRaises(reads.QueryReadError):
                self.validate((self.one,), (record,), selected)
        other = selection("credentials", {"id": "a-雪"}, {"id": "a-雪"})
        with self.assertRaises(reads.QueryReadError):
            self.validate((self.one,), (record,), (other,))

    def test_selected_wrapper_key_digest_and_exact_types_are_checked(self):
        cases = []
        for field, value in (("present", 1), ("row", None), ("keyDigest", "sha256:" + "0" * 64),
                             ("contractSelector", {}), ("key", {"wrong": "a-雪"}),
                             ("key", {"id": "a-雪", "extra": 1}), ("key", {"id": None})):
            changed = copy.deepcopy(self.first)
            changed[field] = value
            cases.append(changed)
        changed = copy.deepcopy(self.first)
        changed["row"]["id"] = "different"
        cases.append(changed)
        changed = copy.deepcopy(self.first)
        del changed["row"]["id"]
        cases.append(changed)
        changed = copy.deepcopy(self.first)
        changed["unexpected"] = True
        cases.append(changed)
        for changed in cases:
            with self.subTest(selected=changed), self.assertRaises(reads.QueryReadError):
                self.capture(self.one, (changed,))

    def test_kernel_context_accessor_uses_retained_order_and_wraps_record_errors(self):
        definition = query("ordered", maximum_rows=2, order_by=(core.QueryOrder("id", True),))
        record = self.capture(definition, (self.second, self.first))
        context = core.KernelContext(operation=OPERATION, arguments={}, selected_rows=(self.first, self.second),
            database_now=datetime(2030, 1, 1, tzinfo=timezone.utc), request_digest="sha256:" + "1" * 64,
            query_reads=self.validate((definition,), (record,), (self.first, self.second)))
        self.assertEqual(context.observed_query_rows(query_id=definition.query_id), (self.second, self.first))
        with self.assertRaisesRegex(core.TransitionKernelError, "retained query observation") as raised:
            context.observed_query_rows(query_id=self.one.query_id)
        self.assertIsInstance(raised.exception.__cause__, reads.QueryReadError)
        malformed = replace(context, query_reads=(replace(record, returned_row_count=0),))
        with self.assertRaises(core.TransitionKernelError):
            malformed.observed_query_rows(query_id=definition.query_id)

    def test_bookkeeping_does_not_authenticate_full_rows_predicates_or_completeness(self):
        record = self.capture(self.one, (self.first,))
        changed = copy.deepcopy(self.first)
        changed["row"]["user_id"] = "not-the-original-value"
        # Only keys and referenced fields are rebound here. Genuine primary
        # membership verification is a different mandatory planner phase.
        self.assertEqual(self.validate((self.one,), (record,), (changed,)), (record,))
        declared_predicate = query("observed-only", predicates=(core.QueryPredicate("user_id", "eq", "bob"),))
        observed = self.capture(declared_predicate, (self.first,))
        self.assertEqual(self.validate((declared_predicate,), (observed,), (self.first,)), (observed,))
        empty = self.capture(declared_predicate)
        self.assertEqual(self.validate((declared_predicate,), (empty,), ()), (empty,))
        # Capture accepts a reference replacement's shape; complete program
        # validation independently resolves it from the earlier retained row.
        ref = core.SelectedRowFieldReference(CREDENTIALS, {"id": "a-雪"}, "user_id")
        dependent = query("dependent", predicates=(core.QueryPredicate("user_id", "eq", ref),))
        invented = replace(dependent, predicates=(core.QueryPredicate("user_id", "eq", "invented"),),
            order_by=(core.QueryOrder("id"),))
        false_record = reads.capture_query_read(OPERATION, dependent, resolved_query=invented,
            ordered_selected_rows=(), returned_row_count=0)
        with self.assertRaisesRegex(reads.QueryReadError, "resolved fields"):
            self.validate((self.one, dependent), (record, false_record), (self.first,))

    def test_source_operation_closure_row_work_primitive_and_query_count_bounds(self):
        spec = authority_contract.operation_spec(OPERATION)
        maximum, work = spec["maximumQueryRows"], spec["maximumWorkUnits"]
        self.assertEqual((maximum, work), (193, 2050))
        row_boundary = query("row-boundary", maximum_rows=maximum)
        work_boundary = query("work-boundary", maximum_rows=1, work_units=work)
        self.assertEqual(reads.snapshot_queries(OPERATION, (row_boundary,)), (row_boundary,))
        self.assertEqual(reads.snapshot_queries(OPERATION, (work_boundary,)), (work_boundary,))
        many = tuple(query(f"empty-{index}", maximum_rows=1) for index in range(maximum))
        self.assertEqual(reads.snapshot_queries(OPERATION, many), many)
        cases = (
            (row_boundary, self.one),
            (work_boundary, self.one),
            many + (query("too-many", maximum_rows=1),),
            (replace(self.one, table="not_a_source_table"),),
            (replace(self.one, query_id=self.one.query_id.replace(OPERATION, "webauthn.counter.cas")),),
            (replace(self.one, proof_primitive="external-evidence-receipt"),),
        )
        for definitions in cases:
            with self.subTest(count=len(definitions)), self.assertRaises(reads.QueryReadError):
                reads.snapshot_queries(OPERATION, definitions)
        for operation in (None, 1, "not.a.source.operation"):
            with self.subTest(operation=operation), self.assertRaises(reads.QueryReadError):
                reads.snapshot_queries(operation, ())

    def test_exact_page_metadata_is_retained_without_manufacturing_range_evidence(self):
        definition = query("exact-page", predicates=(core.QueryPredicate("revoked_at", "is-null"),),
            order_by=(core.QueryOrder("id"),), maximum_rows=2,
            proof_primitive="ordered-exact-page", exact_page=True, work_units=7)
        record = self.capture(definition, (self.first, self.second))
        expected = canonical(query_document(definition))
        self.assertEqual((record.declared_query_json, record.resolved_query_json), (expected, expected))
        self.assertEqual(self.validate((definition,), (record,), (self.first, self.second)), (record,))
        # No range-proof callback or successful exact_page claim is created by
        # retaining the source primitive name and the observed two addresses.
        self.assertEqual(set(field.name for field in fields(record)), {
            "query_id", "declared_query_json", "resolved_query_json", "addresses", "returned_row_count"})

    def test_source_snapshots_reject_nonlossless_values_cycles_and_deep_graphs(self):
        cycle = []
        cycle.append(cycle)
        deep = None
        for _ in range(reads.MAX_JSON_DEPTH + 1):
            deep = [deep]
        values = (0.5, float("nan"), Decimal("1"), datetime(2030, 1, 1, tzinfo=timezone.utc),
            b"bytes", "NUL\0text", "\ud800", {1: "non-string-key"}, {"cycle": cycle}, deep,
            1 << 16385)
        for value in values:
            definition = query("invalid-value", predicates=(core.QueryPredicate("metadata", "eq", value),))
            with self.subTest(value_type=type(value).__name__), self.assertRaises(reads.QueryReadError):
                reads.snapshot_queries(OPERATION, (definition,))
        value = {"text": "雪\n😀", "array": [True, False, None, -7], "tuple": ("x", 3)}
        definition = query("lossless", predicates=(core.QueryPredicate("metadata", "eq", value),))
        owned, = reads.snapshot_queries(OPERATION, (definition,))
        self.assertEqual(canonical(query_document(owned)), canonical(query_document(definition)))
        self.assertIs(type(owned.predicates[0].value["tuple"]), tuple)

    def test_bypassed_source_models_and_subclasses_are_revalidated(self):
        class QuerySubclass(core.BoundedQuery):
            pass
        class StringSubclass(str):
            pass
        class DictionarySubclass(dict):
            pass
        incomplete = object.__new__(core.BoundedQuery)
        predicates = (forged(core.QueryPredicate("id", "eq", "a-雪"), operator=1),)
        cases = (
            incomplete,
            QuerySubclass(**{field.name: getattr(self.one, field.name) for field in fields(self.one)}),
            forged(self.one, query_id=StringSubclass(self.one.query_id)),
            forged(self.one, query_id="catchplate.policyAuthorityQuery/" + "x" * reads.MAX_QUERY_ID_BYTES),
            forged(self.one, table=StringSubclass(CREDENTIALS)),
            forged(self.one, maximum_rows=True), forged(self.one, work_units=True),
            forged(self.one, require_absence=1), forged(self.one, exact_page=0),
            forged(self.one, predicates=list(self.one.predicates)), forged(self.one, predicates=predicates),
            forged(self.one, order_by=(forged(core.QueryOrder("id"), descending=1),)),
            forged(self.one, absent_key=DictionarySubclass(self.one.absent_key)),
            forged(self.one, absent_key={f"key_{i}": i for i in range(core.MAX_QUERY_PREDICATES + 1)}),
        )
        for definition in cases:
            with self.subTest(type=type(definition).__name__), self.assertRaises(reads.QueryReadError):
                reads.snapshot_queries(OPERATION, (definition,))
        with self.assertRaises(reads.QueryReadError):
            reads.snapshot_queries(OPERATION, [self.one])
        reference = core.SelectedRowFieldReference(CREDENTIALS, {"id": "a-雪"}, "user_id")
        broken_reference = forged(reference, key=DictionarySubclass(reference.key))
        definition = query("bad-reference", predicates=(core.QueryPredicate("user_id", "eq", broken_reference),))
        with self.assertRaises(reads.QueryReadError):
            reads.snapshot_queries(OPERATION, (definition,))

    def test_record_and_address_exact_types_bounds_and_constructor_bypasses_reject(self):
        record = self.capture(self.one, (self.first,))
        address = record.addresses[0]
        for changes in ({"table": "Upper"}, {"key_json": bytearray(address.key_json)},
                        {"key_json": b"x"}, {"key_json": b"\xff\xff"},
                        {"key_digest": "sha256:" + "A" * 64}, {"present": 1}):
            with self.subTest(address=changes), self.assertRaises(reads.QueryReadError):
                replace(address, **changes)
        for changes in ({"query_id": "wrong"}, {"declared_query_json": b"x"},
                        {"resolved_query_json": bytearray(b"{}")}, {"addresses": list(record.addresses)},
                        {"returned_row_count": True}, {"returned_row_count": -1},
                        {"returned_row_count": authority_contract.MAX_PLAN_QUERY_ROWS + 1}):
            with self.subTest(record=changes), self.assertRaises(reads.QueryReadError):
                replace(record, **changes)
        incomplete_record = object.__new__(reads.QueryRead)
        incomplete_address = object.__new__(reads.QueryReadAddress)
        for value in (incomplete_record, forged(record, returned_row_count=True),
                      forged(record, addresses=(forged(address, present=1),)),
                      forged(record, addresses=(incomplete_address,))):
            with self.subTest(type=type(value).__name__), self.assertRaises(reads.QueryReadError):
                reads.validate_read_budget(OPERATION, query_reads=(value,))
        with self.assertRaises(reads.QueryReadError):
            reads.validate_read_budget(OPERATION, query_reads=[record])
        # Well-typed canonical bytes are data, not a validated source-program
        # token; their meaning is checked by the actual full validator.
        data_only = reads.QueryRead(record.query_id, b"{}", b"{}", record.addresses, 1)
        reads.validate_read_budget(OPERATION, query_reads=(data_only,))
        with self.assertRaises(reads.QueryReadError):
            self.validate((self.one,), (data_only,), (self.first,))

    def test_revalidation_returns_fresh_records_and_rejects_later_frozen_bypasses(self):
        original = self.capture(self.one, (self.first,))
        validated, = self.validate((self.one,), (original,), (self.first,))
        self.assertEqual(validated, original)
        self.assertIsNot(validated, original)
        self.assertIsNot(validated.addresses[0], original.addresses[0])
        object.__setattr__(original.addresses[0], "present", False)
        self.assertIs(validated.addresses[0].present, True)
        with self.assertRaises(reads.QueryReadError):
            self.validate((self.one,), (original,), (self.first,))

    def test_incremental_read_count_and_overlapping_address_budgets_use_source_limit(self):
        maximum = authority_contract.operation_spec(OPERATION)["maximumQueryRows"]
        selected = tuple(selection(CREDENTIALS, {"id": f"row-{i}"}, {"id": f"row-{i}"})
                         for i in range(maximum))
        definition = query("all-addresses", maximum_rows=maximum)
        record = self.capture(definition, selected)
        reads.validate_read_budget(OPERATION, query_reads=(record,))
        self.validate((definition,), (record,), selected)
        overlap = exact("overlap", "row-0")
        repeated = self.capture(overlap, (selected[0],))
        with self.assertRaisesRegex(reads.QueryReadError, "aggregate bookkeeping"):
            reads.validate_read_budget(OPERATION, query_reads=(record, repeated))
        empty = tuple(self.capture(query(f"empty-{i}", maximum_rows=1)) for i in range(maximum))
        reads.validate_read_budget(OPERATION, query_reads=empty)
        with self.assertRaisesRegex(reads.QueryReadError, "count exceeds"):
            reads.validate_read_budget(OPERATION, query_reads=empty + (self.capture(query("one-too-many")),))
        returned_only = replace(record, addresses=(), returned_row_count=maximum + 1)
        with self.assertRaisesRegex(reads.QueryReadError, "aggregate bookkeeping"):
            reads.validate_read_budget(OPERATION, query_reads=(returned_only,))
        with self.assertRaisesRegex(reads.QueryReadError, "global selected inventory"):
            reads.resolve_query(OPERATION, self.one, prior_reads=(), selected_rows=selected + (self.first,))

    def test_exact_retained_byte_ceiling_and_one_more_byte_without_bulk_allocation(self):
        # This exercises the real cheap retained-record budget, not source
        # program validation: immutable payload bytes are shared by 32 data
        # records, so the fixture allocates only a few MiB rather than 64 MiB.
        bound = 64 * 1024 * 1024
        self.assertEqual(reads.MAX_BOOKKEEPING_BYTES, bound)
        block_size = 1024 * 1024
        shared = b'"' + b"x" * (block_size - 2) + b'"'
        identities = [query(f"byte-{i}", maximum_rows=1).query_id for i in range(32)]
        framing_overhead = sum(8 + len(identity) + 8 + 8 + 8 + len("0") for identity in identities)
        last = b'"' + b"x" * (block_size - framing_overhead - 2) + b'"'
        records = tuple(reads.QueryRead(identity, shared, last if i == 31 else shared, (), 0)
                        for i, identity in enumerate(identities))
        independent_size = sum(8 + len(record.query_id) + 8 + len(record.declared_query_json)
            + 8 + len(record.resolved_query_json) + 8 + len(str(record.returned_row_count)) for record in records)
        self.assertEqual(independent_size, bound)
        reads.validate_read_budget(OPERATION, query_reads=records)
        one_more = replace(records[-1], resolved_query_json=b'"x' + last[1:])
        with self.assertRaisesRegex(reads.QueryReadError, "aggregate bookkeeping"):
            reads.validate_read_budget(OPERATION, query_reads=records[:-1] + (one_more,))

    def test_invalid_reference_value_and_primary_scalar_aliases_are_not_coerced(self):
        record = self.capture(self.one, (self.first,))
        dependent = query("reference-value", predicates=(core.QueryPredicate("user_id", "eq",
            core.SelectedRowFieldReference(CREDENTIALS, {"id": "a-雪"}, "user_id")),))
        for value in (Decimal("1"), datetime(2030, 1, 1, tzinfo=timezone.utc), "bad\0value", "\udfff"):
            selected = copy.deepcopy(self.first)
            selected["row"]["user_id"] = value
            with self.subTest(type=type(value).__name__), self.assertRaises(reads.QueryReadError):
                reads.resolve_query(OPERATION, dependent, prior_reads=(record,), selected_rows=(selected,))
        numeric = selection(CREDENTIALS, {"id": 1}, {"id": 1})
        boolean = selection(CREDENTIALS, {"id": True}, {"id": True})
        self.assertNotEqual(numeric["keyDigest"], boolean["keyDigest"])
        definition = query("scalar-identities", maximum_rows=2)
        observation = self.capture(definition, (numeric, boolean))
        self.validate((definition,), (observation,), (numeric, boolean))
        numeric["row"]["id"] = True
        with self.assertRaisesRegex(reads.QueryReadError, "original key"):
            self.capture(definition, (numeric,))

    def test_reference_source_enumeration_deduplicates_and_orders_actual_prior_addresses(self):
        first_record = self.capture(self.one, (self.first,))
        second_record = self.capture(exact("second", "b"), (self.second,))
        challenge = selection(CHALLENGES, {"id": "challenge-雪"}, {"id": "challenge-雪", "user_id": "bob"})
        challenge_query = query("challenge-source", table=CHALLENGES, maximum_rows=1,
            predicates=(core.QueryPredicate("id", "eq", "challenge-雪"),), absent_key={"id": "challenge-雪"})
        challenge_record = self.capture(challenge_query, (challenge,))
        selected = (self.second, challenge, self.first)
        prior = (first_record, second_record, challenge_record)
        references = (
            core.SelectedRowFieldReference(CREDENTIALS, {"id": "b"}, "user_id"),
            core.SelectedRowFieldReference(CHALLENGES, {"id": "challenge-雪"}, "user_id"),
            core.SelectedRowFieldReference(CREDENTIALS, {"id": "a-雪"}, "user_id"),
            core.SelectedRowFieldReference(CREDENTIALS, {"id": "b"}, "credential_id"),
        )
        dependent = query("reference-inventory", predicates=tuple(
            core.QueryPredicate("user_id", "eq", reference) for reference in references))
        expected = tuple(sorted(selected, key=lambda row: (row["table"], row["keyDigest"], canonical(row["key"]))))
        actual = reads.reference_source_rows(OPERATION, dependent, prior_reads=prior, selected_rows=selected)
        self.assertEqual(actual, expected)
        self.assertTrue(all(left is right for left, right in zip(actual, expected)))
        reordered = replace(dependent, predicates=tuple(reversed(dependent.predicates)))
        self.assertEqual(reads.reference_source_rows(OPERATION, reordered,
            prior_reads=prior, selected_rows=tuple(reversed(selected))), expected)
        self.assertEqual(reads.reference_source_rows(OPERATION, query("no-reference"),
            prior_reads=prior, selected_rows=selected), ())

    def test_reference_enumeration_includes_absent_key_but_never_copies_source_field_value(self):
        record = self.capture(self.one, (self.first,))
        reference = core.SelectedRowFieldReference(CREDENTIALS, {"id": "a-雪"}, "credential_id")
        dependent = query("reference-absence", table=CHALLENGES, maximum_rows=1,
            predicates=(core.QueryPredicate("id", "eq", reference),), absent_key={"id": reference})
        # An opaque unsupported value cannot pass actual resolution. Enumeration
        # only finds the original wrapper; it is not a successful proof/value
        # conversion and must not consume the value before staged verification.
        opaque = object()
        self.first["row"]["credential_id"] = opaque
        sources = reads.reference_source_rows(OPERATION, dependent,
            prior_reads=(record,), selected_rows=(self.first,))
        self.assertEqual(len(sources), 1)
        self.assertIs(sources[0], self.first)
        self.assertIs(sources[0]["row"]["credential_id"], opaque)
        with self.assertRaises(reads.QueryReadError):
            reads.resolve_query(OPERATION, dependent, prior_reads=(record,), selected_rows=(self.first,))

    def test_reference_enumeration_rejects_current_forward_absent_missing_and_malformed_sources(self):
        first_record = self.capture(self.one, (self.first,))
        missing = selection(CREDENTIALS, {"id": "missing"}, None)
        missing_record = self.capture(exact("missing", "missing"), (missing,))
        for key, column, prior, selected in (
            ({"id": "a-雪"}, "user_id", (), (self.first,)),
            ({"id": "a-雪"}, "user_id", (first_record,), ()),
            ({"id": "a-雪"}, "not_a_column", (first_record,), (self.first,)),
            ({"id": "missing"}, "user_id", (missing_record,), (missing,)),
            ({"wrong_key": "a-雪"}, "user_id", (first_record,), (self.first,)),
        ):
            dependent = query("reference-rejection", predicates=(core.QueryPredicate("user_id", "eq",
                core.SelectedRowFieldReference(CREDENTIALS, key, column)),))
            with self.subTest(key=key, column=column), self.assertRaises(reads.QueryReadError):
                reads.reference_source_rows(OPERATION, dependent, prior_reads=prior, selected_rows=selected)
        with self.assertRaisesRegex(reads.QueryReadError, "includes the current query"):
            reads.reference_source_rows(OPERATION, self.one,
                prior_reads=(first_record,), selected_rows=(self.first,))
        with self.assertRaises(reads.QueryReadError):
            reads.reference_source_rows(OPERATION, query("new"),
                prior_reads=(first_record,), selected_rows=(self.first, self.first))


if __name__ == "__main__":
    unittest.main()
