#!/usr/bin/env python3
"""Actual counted-head acquisition against independent source commitments.

The SQL responder is not PostgreSQL and establishes no currentness, population,
schema admission or enabled planner. It executes the real producer and shared
meter; no head/profile/hash verifier is replaced with a successful result.
"""
from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate import authority_index_heads as heads
from catchplate import authority_index_projection as projection
from catchplate import authority_index_reader as reader
from catchplate.authority_query_read_work import (
    _ValidationWork, QueryReadValidationLimits, QueryReadWorkError,
)
import test_authority_counted_installation as installation_oracle
import test_authority_index_join as profile_oracle
import test_authority_index_range as tree_oracle


OPERATION = "webauthn.credential.revoke"
PROFILE = "catchplate.policyAuthorityCountedHeadRead/v1"
TABLE = "policy_authority_counted_index_heads"
IDS = tuple(sorted((
    "webauthn_credential_id", "webauthn_credential_user_history", "webauthn_credential_live_trust",
    "webauthn_registration_unused_global", "webauthn_registration_unused_user",
    "webauthn_session_credential_status", "webauthn_grant_approver_active",
    "webauthn_control_approval_approved",
    "webauthn_publication_status",
)))
FIELDS = ("index_id", "table_name", "counted_profile", "projection_digest",
          "projection_manifest_digest", "index_revision", "root_digest", "leaf_count")


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def nodes(value):
    if type(value) is dict:
        return 1 + sum(1 + nodes(child) for child in value.values())
    if type(value) in (list, tuple):
        return 1 + sum(nodes(child) for child in value)
    return 1


def source_rows(*, populated=False):
    rows = [row for row in installation_oracle.expected_heads() if row["index_id"] in IDS]
    if populated:
        for row in rows:
            profile = profile_oracle.expected_profile(row["index_id"])
            leaf = tree_oracle.leaf("a" * 160, row["index_id"])
            tree, _, _ = tree_oracle.assembled(profile, {leaf.key: tree_oracle.member(profile, leaf)})
            row.update(index_revision=7, root_digest=tree[""][0], leaf_count=tree[""][1])
    return rows


def marker():
    return {"profile": PROFILE, "indexIds": list(IDS), "rowLimit": 10}


def expected_work(rows):
    """Literal successful pass schedule; never read production work counters."""
    byte_count = node_count = 0
    for identity in IDS:
        descriptor = profile_oracle.descriptor(identity)
        byte_count += 2 * len(wire(descriptor))
        node_count += 2 * nodes(descriptor)
        profile = profile_oracle.expected_profile(identity)
        values = ("catchplate.policyAuthorityCountedIndexEmpty/v1",
                  "catchplate.policyAuthorityCountedIndex/v1", identity, profile.table,
                  profile.projection_digest, "160", "0", "", "0")
        byte_count += sum(8 + 2 * len(value.encode("utf-8")) for value in values)
        node_count += 2 * len(values)
    manifest = [profile_oracle.descriptor(identity) for identity in installation_oracle.INDEX_IDS]
    byte_count += 2 * len(wire(manifest))
    node_count += 2 * nodes(manifest)
    parameters = (*IDS, 10)
    parameter_bytes = sum(8 + len(str(value).encode("utf-8")) for value in parameters)
    byte_count += sum(8 + 2 * len(str(value).encode("utf-8")) for value in parameters)
    node_count += 2 * len(parameters)
    transport_bytes = 0
    for row in rows:
        scalars = ("head", *(row[name] for name in FIELDS))
        transport_bytes += sum(8 + len(str(value).encode("utf-8")) for value in scalars)
        byte_count += sum(8 + 2 * len(str(value).encode("utf-8")) for value in scalars)
        node_count += 2 * len(scalars)
        byte_count += 2 * len(wire(row))
        node_count += 2 * nodes(row)
    return 19, byte_count, node_count, parameter_bytes, transport_bytes


class Trace:
    def __init__(self, callback=None):
        self.operation, self.entries, self.callback = OPERATION, [], callback

    def read(self, table, key):
        if table != TABLE or key != marker():
            raise AssertionError("head reader trace is not the independent source marker")
        heads.validate_head_trace_key(self.operation, key)
        self.entries.append((table, copy.deepcopy(key)))
        if self.callback is not None:
            self.callback()


class Cursor:
    def __init__(self, rows, *, execute_callback=None, fetch_callback=None):
        self.rows = copy.deepcopy(rows)
        self.calls, self.fetch_bounds = [], []
        self.execute_callback, self.fetch_callback = execute_callback, fetch_callback

    def execute(self, sql, parameters):
        expected_where = "WHERE head.index_id IN (" + ", ".join("%s" for _ in IDS) + ") "
        if (not sql.startswith("SELECT CASE WHEN pg_catalog.pg_typeof(head.index_id)")
                or f"FROM catchplate_metadata.{TABLE} AS head " not in sql
                or sql.split("WHERE ", 1)[1] != expected_where[6:] + 'ORDER BY head.index_id COLLATE "C" LIMIT %s'
                or parameters != (*IDS, 10)):
            raise AssertionError("head SQL is not the one bounded source-ID-only SELECT")
        for name in FIELDS:
            if f" AS {name}" not in sql:
                raise AssertionError("head SQL omitted a closed column")
        if any(value in sql for value in ("FOR UPDATE", "LOCK TABLE", "INSERT", "COMMIT", "BEGIN")):
            raise AssertionError("head reader escaped its caller's read transaction")
        self.calls.append((sql, parameters))
        if self.execute_callback is not None:
            self.execute_callback()
        return self

    def fetchmany(self, maximum):
        self.fetch_bounds.append(maximum)
        if self.fetch_callback is not None:
            self.fetch_callback()
        # Do not enforce/truncate in the responder: production must reject an
        # over-bound driver result independently of the SQL LIMIT.
        return self.rows


class AuthorityIndexHeadTests(unittest.TestCase):
    def fixture(self, rows=None, *, limits=None, acquisition_limits=None):
        rows = source_rows() if rows is None else rows
        work = _ValidationWork(limits or QueryReadValidationLimits())
        cursor, trace = Cursor(rows), Trace()
        acquisition = reader._ReadAcquisitionBudget(cursor, trace, work=work,
            limits=acquisition_limits or reader._ReadAcquisitionLimits())
        return cursor, trace, work, acquisition

    def acquire(self, fixture, **changes):
        cursor, trace, work, acquisition = fixture
        return heads.read_operation_index_heads(cursor, **{
            "operation": OPERATION, "trace": trace, "work": work, "acquisition": acquisition, **changes})

    def test_required_inventory_and_trace_are_hash_free_source_role_write_union(self):
        actual = projection.hashlib.sha256
        with mock.patch.object(projection.hashlib, "sha256", wraps=actual) as hashes:
            self.assertEqual(heads.required_index_ids(OPERATION), IDS)
            heads.validate_head_trace_key(OPERATION, marker())
        self.assertEqual(hashes.call_count, 0)
        self.assertIn("webauthn_publication_status", IDS)  # complete pending-publication absence
        self.assertIn("webauthn_registration_unused_user", IDS)  # potential write, not a read role

    def test_actual_empty_heads_one_sql_immutable_scalars_and_independent_work(self):
        rows = source_rows()
        expected = expected_work(rows)
        fixture = self.fixture(rows)
        actual = projection.hashlib.sha256
        with mock.patch.object(projection.hashlib, "sha256", wraps=actual) as hashes:
            result = self.acquire(fixture)
        cursor, trace, work, acquisition = fixture
        self.assertEqual(hashes.call_count, 19)
        self.assertEqual((work.hash_work, work.input_bytes, work.json_nodes), expected[:3])
        self.assertEqual((acquisition.sql_reads, acquisition.returned_rows,
                          acquisition.parameter_bytes, acquisition.transport_bytes), (1, 9, *expected[3:]))
        self.assertEqual((len(cursor.calls), cursor.fetch_bounds, trace.entries), (1, [10], [(TABLE, marker())]))
        for observed, row in zip(result, rows):
            self.assertEqual((observed.index_id, observed.table, observed.counted_profile,
                              observed.projection_digest, observed.projection_manifest_digest,
                              observed.index_revision, observed.index_root.digest, observed.index_root.count),
                             tuple(row[name] for name in FIELDS))
        with self.assertRaises(FrozenInstanceError):
            result[0].index_revision = 1
        with self.assertRaises(FrozenInstanceError):
            result[0].index_root.count = 1
        cursor.rows[0]["root_digest"] = "sha256:" + "f" * 64
        self.assertEqual(result[0].index_root.digest, rows[0]["root_digest"])

    def test_populated_independent_roots_and_positive_revision_empty_are_retained(self):
        rows = source_rows(populated=True)
        rows[-1] = source_rows()[-1]
        rows[-1]["index_revision"] = 19
        fixture = self.fixture(rows)
        result = self.acquire(fixture)
        self.assertEqual(tuple((item.index_revision, item.index_root.count) for item in result),
                         ((7, 1),) * 8 + ((19, 0),))
        self.assertEqual(tuple(item.index_root.digest for item in result), tuple(row["root_digest"] for row in rows))
        self.assertEqual((fixture[2].hash_work, fixture[2].input_bytes, fixture[2].json_nodes), expected_work(rows)[:3])

    def test_operations_without_complete_roles_deny_before_hash_trace_or_sql(self):
        for operation in ("webauthn.counter.cas", "webauthn.trust.stage", "unknown", "x" * 129, None, True):
            fixture = self.fixture()
            actual = projection.hashlib.sha256
            with self.subTest(operation=operation), mock.patch.object(projection.hashlib, "sha256", wraps=actual) as hashes:
                with self.assertRaises(heads.IndexHeadReadError):
                    self.acquire(fixture, operation=operation)
            self.assertEqual((hashes.call_count, fixture[0].calls, fixture[1].entries), (0, [], []))

    def test_trace_marker_exact_fields_order_types_and_full_union(self):
        cases = [None, {}, {**marker(), "extra": 1}, {**marker(), "profile": "other"},
            {**marker(), "indexIds": tuple(IDS)}, {**marker(), "indexIds": list(reversed(IDS))},
            {**marker(), "indexIds": list(IDS[:-1])}, {**marker(), "indexIds": [IDS[0]] * 9},
            {**marker(), "indexIds": ["x" * 129, *IDS[1:]]}, {**marker(), "rowLimit": True},
            {**marker(), "rowLimit": 9}, {**marker(), "rowLimit": 11}]
        for value in cases:
            with self.subTest(value=value), self.assertRaises(heads.IndexHeadReadError):
                heads.validate_head_trace_key(OPERATION, value)

    def test_missing_duplicate_reordered_unknown_and_overbound_heads_deny(self):
        rows = source_rows()
        unknown = copy.deepcopy(rows)
        unknown[0]["index_id"] = "webauthn_live_trust_global"
        for values in ([], rows[:-1], [rows[0], *rows[:-1]], list(reversed(rows)), unknown, rows + [rows[0]]):
            fixture = self.fixture(values)
            with self.subTest(length=len(values)), self.assertRaises(reader.IndexReadError):
                self.acquire(fixture)
            self.assertEqual((len(fixture[0].calls), fixture[0].fetch_bounds), (1, [10]))

    def test_each_source_commitment_rejects_a_canonical_but_wrong_value(self):
        for field, value in (("table_name", "webauthn_trust_publications"),
                ("counted_profile", "catchplate.policyAuthorityCountedIndex/v2"),
                ("projection_digest", "sha256:" + "e" * 64),
                ("projection_manifest_digest", "sha256:" + "d" * 64)):
            rows = source_rows()
            rows[0][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(heads.IndexHeadReadError, "source commitments"):
                self.acquire(self.fixture(rows))

    def test_closed_row_shape_and_exact_driver_types(self):
        class Row(dict):
            pass
        rows = source_rows()
        for value in (Row(rows[0]), {**rows[0], "extra": 1}, {name: item for name, item in rows[0].items() if name != "leaf_count"},
                      {**rows[0], 1: "unknown"}, None):
            with self.subTest(value=value), self.assertRaises(heads.IndexHeadReadError):
                self.acquire(self.fixture([value, *rows[1:]]))

    def test_scalar_sentinels_boolean_numeric_and_oversized_values_deny(self):
        for field, values in (("index_revision", (True, -1, 2**63, "0", None)),
                              ("leaf_count", (False, -1, 2**63, 0.0, None)),
                              ("index_id", (None, "x" * 129, "snow-雪", "bad\x00id")),
                              ("root_digest", (None, "sha256:" + "A" * 64, "sha256:" + "1" * 63))):
            for value in values:
                rows = source_rows()
                rows[0][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(heads.IndexHeadReadError):
                    self.acquire(self.fixture(rows))

    def test_revision_zero_and_empty_digest_equivalence_are_enforced(self):
        for revision, count, digest in ((0, 1, "sha256:" + "d" * 64),
                (3, 0, "sha256:" + "d" * 64), (3, 1, source_rows()[0]["root_digest"])):
            rows = source_rows()
            rows[0].update(index_revision=revision, leaf_count=count, root_digest=digest)
            with self.subTest(revision=revision, count=count), self.assertRaisesRegex(heads.IndexHeadReadError, "canonical empty"):
                self.acquire(self.fixture(rows))

    def test_exact_and_preconsumed_shared_work_quotas(self):
        rows = source_rows()
        expected = expected_work(rows)
        for prefix in ((0, 0, 0), (3, 5, 7)):
            limits = QueryReadValidationLimits(expected[0] + prefix[0], expected[1] + prefix[1], expected[2] + prefix[2])
            fixture = self.fixture(rows, limits=limits)
            fixture[2].charge(hashes=prefix[0], input_bytes=prefix[1], json_nodes=prefix[2])
            self.acquire(fixture)
            self.assertEqual((fixture[2].hash_work, fixture[2].input_bytes, fixture[2].json_nodes),
                             tuple(expected[index] + prefix[index] for index in range(3)))

    def test_each_work_dimension_minus_one_denies_and_never_resets(self):
        expected = expected_work(source_rows())
        for ordinal in range(3):
            caps = list(expected[:3])
            caps[ordinal] -= 1
            fixture = self.fixture(limits=QueryReadValidationLimits(*caps))
            with self.subTest(dimension=ordinal), self.assertRaises(QueryReadWorkError):
                self.acquire(fixture)
            self.assertEqual(len(fixture[0].calls), 0 if ordinal == 0 else 1)
            spent = fixture[2].metrics
            with self.assertRaises(reader.IndexReadError):
                self.acquire(fixture)
            self.assertEqual(fixture[2].metrics, spent)

    def test_parameter_and_transport_caps_are_cumulative_not_new_per_head(self):
        expected = expected_work(source_rows())
        for ordinal, field in ((3, "max_parameter_bytes"), (4, "max_transport_bytes")):
            fixture = self.fixture(acquisition_limits=reader._ReadAcquisitionLimits(**{field: expected[ordinal]}))
            self.acquire(fixture)
            with self.assertRaises(reader.IndexReadError):
                self.acquire(fixture)
            self.assertEqual(len(fixture[0].calls), 1 if ordinal == 3 else 2)
            denied = self.fixture(acquisition_limits=reader._ReadAcquisitionLimits(**{field: expected[ordinal] - 1}))
            with self.assertRaises(reader.IndexReadError):
                self.acquire(denied)
            self.assertEqual(len(denied[0].calls), 0 if ordinal == 3 else 1)

    def test_one_physical_read_quota_is_shared_across_repeated_calls(self):
        fixture = self.fixture(acquisition_limits=reader._ReadAcquisitionLimits(max_sql_reads=1))
        self.acquire(fixture)
        with self.assertRaises(reader.IndexReadError):
            self.acquire(fixture)
        self.assertEqual((fixture[3].sql_reads, len(fixture[0].calls)), (1, 1))

    def test_work_cursor_trace_identity_and_trace_operation_are_pinned(self):
        for replacement in ("work", "trace", "cursor", "operation"):
            fixture = self.fixture()
            cursor, trace, work, acquisition = fixture
            with self.subTest(replacement=replacement), self.assertRaises(reader.IndexReadError):
                if replacement == "cursor":
                    heads.read_operation_index_heads(Cursor(source_rows()), operation=OPERATION,
                        trace=trace, work=work, acquisition=acquisition)
                elif replacement == "operation":
                    trace.operation = "webauthn.counter.cas"
                    self.acquire(fixture)
                else:
                    self.acquire(fixture, **{replacement: Trace() if replacement == "trace"
                        else _ValidationWork(QueryReadValidationLimits())})
            self.assertEqual((cursor.calls, work.hash_work), ([], 0))
            with self.assertRaises(reader.IndexReadError):
                self.acquire(fixture)

    def test_caught_reentrancy_at_trace_execute_and_fetch_cannot_publish(self):
        for boundary in ("trace", "execute", "fetch"):
            fixture = self.fixture()
            caught = []
            def callback():
                try:
                    self.acquire(fixture)
                except reader.IndexReadError as exc:
                    caught.append(exc)
            if boundary == "trace":
                fixture[1].callback = callback
            elif boundary == "execute":
                fixture[0].execute_callback = callback
            else:
                fixture[0].fetch_callback = callback
            with self.subTest(boundary=boundary), self.assertRaises(reader.IndexReadError):
                self.acquire(fixture)
            self.assertEqual(len(caught), 1)
            self.assertEqual(len(fixture[0].calls), 0 if boundary == "trace" else 1)
            self.assertEqual(fixture[2].hash_work, 19)
            spent = fixture[2].metrics
            with self.assertRaises(reader.IndexReadError):
                self.acquire(fixture)
            self.assertEqual(fixture[2].metrics, spent)

    def test_no_caller_subset_root_or_success_token_parameter(self):
        fixture = self.fixture()
        for value in ({"index_ids": IDS[:1]}, {"heads": source_rows()}, {"verified": object()}):
            with self.subTest(argument=tuple(value)), self.assertRaises(TypeError):
                self.acquire(fixture, **value)
        self.assertEqual(fixture[0].calls, [])

    def test_local_trace_denial_precedes_sql_and_is_not_planner_admission(self):
        fixture = self.fixture()
        def deny():
            raise ValueError("component sink denies counted heads")
        fixture[1].callback = deny
        with self.assertRaisesRegex(ValueError, "component sink"):
            self.acquire(fixture)
        self.assertEqual(fixture[0].calls, [])
        with self.assertRaises(reader.IndexReadError):
            self.acquire(fixture)


if __name__ == "__main__":
    unittest.main()
