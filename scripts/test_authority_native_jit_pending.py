#!/usr/bin/env python3
"""Synthetic custody plus deterministic pending-kernel controls.

Actual local Ed25519/P-384/COSE/AES validators run with synthetic keys and
clocks. Selected database roots are explicit in-memory fixtures: these tests
do not establish a native owner, PostgreSQL commit, opening, or a live release.
No successful custody verifier is mocked, and no database/provider is called.
"""
from __future__ import annotations

import copy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
_violations = []


def no_external_effects(event, _arguments):
    if event.startswith(("socket.", "sqlite3.")) or event in {
        "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn",
    }:
        _violations.append(event)
        raise AssertionError("native JIT pending controls forbid external effects")


if __name__ == "__main__":
    os.environ["CATCHPLATE_PROCESS_MODE"] = "metadata-bootstrap"
    os.environ["CATCHPLATE_RELEASE_CHANNEL"] = "dev"
    sys.addaudithook(no_external_effects)

from scripts import test_authority_native_jit_review_custody as crypto
from catchplate import authority_audit_capacity as audit_capacity
from catchplate import authority_contract as contract
from catchplate import authority_native_jit_review_custody as custody
from catchplate import authority_native_jit_retention_contract as storage
from catchplate import authority_transition_core as core
from catchplate import authority_transition_native_jit_pending as pending
from catchplate import authority_transition_quota as quota
from catchplate import authority_transition_release as release

NOW = datetime.fromtimestamp(crypto.NOW // crypto.SECOND, timezone.utc)
AGGREGATES = "policy_authority_bounded_aggregate_states"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("ascii")


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def framed(domain, *frames):
    return sha(domain.encode("ascii") + b"\0" + b"".join(
        len(frame).to_bytes(8, "big") + frame for frame in frames))


def selection(table, key, row=None):
    return {"table": table, "key": copy.deepcopy(key),
        "keyDigest": framed("catchplate.policyAuthorityBusinessKey/v1", table.encode(), canonical(key)),
        "present": row is not None, "row": copy.deepcopy(row), "contractSelector": None}


def aggregate(kind, partition, *, limit, count=0, expiry=None):
    row = {"aggregate_id": kind + ":" + partition, "aggregate_kind": kind,
        "partition_digest": partition, "revision": 1, "live_count": count, "active_count": count,
        "capacity_limit": limit, "reserved_units_json": "{}", "committed_units_json": "{}",
        "next_sequence": count, "minimum_expiry_epoch_ns": expiry,
        "expiry_index_root_digest": framed("catchplate.policyAuthorityAggregateExpiryIndex/v1", b"[]"),
        "work_page_id": None, "updated_at_epoch_ns": crypto.NOW,
        "source_revision": contract.SOURCE_REVISION}
    state = {"schema": "catchplate.policyAuthorityAggregateState/v1",
        "aggregateId": row["aggregate_id"], "aggregateKind": kind, "partitionDigest": partition,
        "revision": 1, "liveCount": count, "activeCount": count, "capacityLimit": limit,
        "reservedUnits": {}, "committedUnits": {}, "nextSequence": count,
        "minimumExpiryEpochNs": expiry, "expiryIndexRootDigest": row["expiry_index_root_digest"], "workPageId": None}
    row.update(state_json=canonical(state).decode("ascii"),
        state_digest=framed("catchplate.policyAuthorityAggregateState/v1", canonical(state)))
    return selection(AGGREGATES, {"aggregate_id": row["aggregate_id"]}, row)


class Fixture:
    def __init__(self, pki):
        self.crypto = crypto.Fixture(pki)
        originals = self.crypto.arguments()
        self.retained = {name: originals[source] for name, source in (
            ("parentOriginal", "parent_original"), ("childOriginal", "child_original"),
            ("pairOriginal", "pair_original"), ("evidenceOriginal", "evidence_original"))}
        self.parent = self.crypto.parent
        self.child = self.crypto.child
        self.kernel = release.KERNELS["release.reserve"]
        self.queries = self.kernel.queries(arguments=self.parent["arguments"],
            database_now=NOW, request_digest=self.parent["requestDigest"])
        self.rows = [selection(query.table, query.absent_key)
            for query in self.queries if query.absent_key is not None
            and query.table != AGGREGATES]
        self.pending_id, self.pending_partition = quota._aggregate_key("jit-pending-approvals", "global")
        self.rows.extend((aggregate("jit-pending-approvals", self.pending_partition, limit=100),
            aggregate(audit_capacity.AGGREGATE_KIND, audit_capacity.PARTITION_DIGEST,
                limit=audit_capacity.MAX_PENDING)))

    def verify(self):
        with patch.object(custody.time, "time_ns", return_value=crypto.NOW), \
                patch.object(custody.time, "monotonic_ns", return_value=crypto.MONO):
            return custody.verify_original(**self.crypto.arguments())

    def context(self, *, at=NOW):
        return core.KernelContext(operation="release.reserve", arguments=copy.deepcopy(self.parent["arguments"]),
            selected_rows=tuple(copy.deepcopy(self.rows)), database_now=at,
            request_digest=self.parent["requestDigest"], native_jit_pending=copy.deepcopy(self.retained))

    def transition(self, *, at=NOW):
        context = self.context(at=at)
        before = copy.deepcopy((context.arguments, context.selected_rows, context.native_jit_pending))
        result = self.kernel.transition(context)
        if before != (context.arguments, context.selected_rows, context.native_jit_pending):
            raise AssertionError("kernel mutated its retained originals")
        return result

    def replace_row(self, replacement):
        for ordinal, selected in enumerate(self.rows):
            if selected["table"] == replacement["table"] and selected["key"] == replacement["key"]:
                self.rows[ordinal] = replacement
                return
        self.rows.append(replacement)


class NativeJitPendingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki = crypto.SyntheticNitro()

    def setUp(self):
        self.fixture = Fixture(self.pki)

    def tearDown(self):
        self.assertEqual(_violations, [], "external I/O refusal is not a passing negative")

    def test_real_synthetic_custody_then_source_owned_atomic_projection(self):
        f = self.fixture
        self.assertIsNone(f.verify())
        result = f.transition()
        self.assertEqual(len(result.mutations), 5)
        finalized = audit_capacity.finalize_capacity(f.context(), result.mutations)
        self.assertEqual(len(finalized), 6)
        self.assertEqual({item["table"] for item in finalized}, {
            storage.TABLE, "approval_requests", "routes", "metadata_audit_outbox", AGGREGATES})
        self.assertFalse(result.result["authorized"])
        self.assertEqual(result.result["state"], "denied")
        self.assertEqual(result.result["reason"], "jit_grant_unavailable")
        self.assertEqual(result.result["durable_policy"]["state"], "denied")
        self.assertIsNone(result.result["durable_policy"]["reservation_id"])
        self.assertEqual(result.result["quotas"], [])
        for name in ("synthetic-private-query", "runtimeOriginal", "runtimeInput", "privateDocuments"):
            self.assertNotIn(name, canonical(finalized).decode("ascii"))

    def test_queries_are_exact_bounded_and_framework_capacity_is_separate(self):
        f = self.fixture
        self.assertEqual(len(f.queries), 7)
        self.assertEqual(sum(query.maximum_rows for query in f.queries), 10)
        grants = next(query for query in f.queries if query.table == "approval_grants")
        self.assertEqual(grants.maximum_rows, 4)
        self.assertIn(core.QueryPredicate("uses_remaining", "gt", 0), grants.predicates)
        augmented = audit_capacity.add_capacity_query("release.reserve", f.queries)
        self.assertEqual(len(augmented), 8)
        spec = contract.operation_spec("release.reserve")
        self.assertEqual((spec["maximumBusinessQueryRows"], spec["maximumBusinessMutations"], spec["maximumBusinessWorkUnits"]),
            (64, 256, 4096))

    def test_approval_identity_uses_child_not_parent_request_digest(self):
        f = self.fixture
        actual = f.transition().result["approval_request_id"]
        child = core.deterministic_uuid(operation="jit.request", request_digest=f.child["requestDigest"],
            purpose="jit-approval-request")
        parent = core.deterministic_uuid(operation="jit.request", request_digest=f.parent["requestDigest"],
            purpose="jit-approval-request")
        self.assertEqual(actual, child)
        self.assertNotEqual(actual, parent)

    def test_retained_pair_has_exact_originals_and_insert_only_row(self):
        f = self.fixture
        item = next(item for item in f.transition().mutations if item["table"] == storage.TABLE)
        self.assertEqual(item["operation"], "INSERT")
        self.assertIsNone(item["expectedRow"])
        self.assertEqual(set(item["row"]), set(storage.COLUMNS))
        for column, field in (("parent_request_original", "parentOriginal"), ("child_request_original", "childOriginal"),
                ("pair_original", "pairOriginal"), ("proof_original", "evidenceOriginal")):
            self.assertEqual(item["row"][column], f.retained[field])
        self.assertEqual(item["row"]["pair_sha256"], sha(f.retained["pairOriginal"].encode("ascii")))
        self.assertEqual(item["row"]["recorded_at_epoch_ns"], crypto.NOW)

    def test_review_slots_are_reserved_opaque_refs_never_plaintext(self):
        f = self.fixture
        row = next(item["row"] for item in f.transition().mutations if item["table"] == "approval_requests")
        for field, kind in (("canonical_request", "approval-secret-json/v1"),
                ("redacted_display", "approval-review-json/v1")):
            self.assertTrue(row[field].startswith("native-jit:v1:"))
            value = json.loads(row[field][len("native-jit:v1:"):])
            self.assertEqual(value, {"schema": "catchplate.nativeJitReviewReference/v1",
                "approvalRequestId": row["id"], "parentRequestDigest": f.parent["requestDigest"],
                "pairSha256": sha(f.retained["pairOriginal"].encode()), "valueKind": kind})

    def test_existing_route_is_preserved_without_write(self):
        f = self.fixture
        selected = next(row for row in f.rows if row["table"] == "routes")
        f.replace_row(selection("routes", selected["key"], {**selected["key"], "enabled": 1, "name": "unchanged"}))
        result = f.transition()
        self.assertEqual(len(result.mutations), 4)
        self.assertNotIn("routes", {item["table"] for item in result.mutations})

    def test_existing_attempt_approval_pair_or_audit_is_not_caller_replay(self):
        for table in ("release_authorization_attempts", "approval_requests", storage.TABLE, "metadata_audit_outbox"):
            with self.subTest(table=table):
                f = Fixture(self.pki)
                selected = next(row for row in f.rows if row["table"] == table)
                f.replace_row(selection(table, selected["key"], dict(selected["key"])))
                with self.assertRaises(core.TransitionKernelError):
                    f.transition()

    def test_even_same_rows_are_not_a_new_execution_owner_replay(self):
        f = self.fixture
        result = f.transition()
        for item in result.mutations:
            f.replace_row(selection(item["table"], item["key"], item["row"]))
        with self.assertRaises(core.TransitionKernelError):
            f.transition(at=NOW + timedelta(seconds=1))

    def test_live_matching_grant_refuses_without_consumption(self):
        f = self.fixture
        f.rows.append(selection("approval_grants", {"id": "existing-grant"}, {"id": "existing-grant"}))
        with self.assertRaises(core.TransitionKernelError):
            f.transition()

    def test_pending_capacity_is_required_and_never_bootstrapped(self):
        f = self.fixture
        f.rows = [row for row in f.rows if row["key"] != {"aggregate_id": f.pending_id}]
        with self.assertRaises(core.TransitionKernelError):
            f.transition()

    def test_full_pending_capacity_refuses(self):
        f = self.fixture
        f.replace_row(aggregate("jit-pending-approvals", f.pending_partition, limit=100, count=100))
        with self.assertRaises(core.TransitionKernelError):
            f.transition()

    def test_full_audit_capacity_refuses_whole_framework_finalization(self):
        f = self.fixture
        f.replace_row(aggregate(audit_capacity.AGGREGATE_KIND, audit_capacity.PARTITION_DIGEST,
            limit=audit_capacity.MAX_PENDING, count=audit_capacity.MAX_PENDING))
        before = copy.deepcopy(f.rows)
        result = f.transition()
        with self.assertRaises(audit_capacity.AuditCapacityError):
            audit_capacity.finalize_capacity(f.context(), result.mutations)
        self.assertEqual(f.rows, before)  # No DB or model apply took place.

    def test_original_document_expiry_is_not_renewed_by_delayed_planning(self):
        f = self.fixture
        first = f.transition().result["approval_expires_at"]
        later = f.transition(at=NOW + timedelta(seconds=10)).result["approval_expires_at"]
        self.assertEqual(first, later)
        self.assertEqual(first, (NOW + timedelta(seconds=300)).isoformat())

    def test_fresh_seal_interval_is_half_open_at_database_time(self):
        for at in (NOW - timedelta(microseconds=1), NOW + timedelta(seconds=30)):
            with self.subTest(at=at), self.assertRaises(core.TransitionKernelError):
                self.fixture.transition(at=at)

    def test_earlier_pending_aggregate_expiry_is_not_moved_forward(self):
        f = self.fixture
        earlier = crypto.NOW + 10 * crypto.SECOND
        f.replace_row(aggregate("jit-pending-approvals", f.pending_partition, limit=100, count=1, expiry=earlier))
        item = next(item for item in f.transition().mutations if item["key"] == {"aggregate_id": f.pending_id})
        self.assertEqual(item["row"]["minimum_expiry_epoch_ns"], earlier)
        self.assertEqual(item["row"]["live_count"], 2)

    def test_missing_retention_or_raw_runtime_extra_is_refused(self):
        f = self.fixture
        for value in (None, {}, {**f.retained, "runtimeOriginal": f.crypto.arguments()["runtime_original"]}):
            with self.subTest(value_is_none=value is None), self.assertRaises(core.TransitionKernelError):
                f.kernel.transition(replace(f.context(), native_jit_pending=value))

    def test_changed_pair_commitment_or_original_format_is_refused(self):
        f = self.fixture
        for field in f.retained:
            changed = {**f.retained, field: f.retained[field] + " "}
            with self.subTest(field=field), self.assertRaises(core.TransitionKernelError):
                f.kernel.transition(replace(f.context(), native_jit_pending=changed))
        proof = json.loads(f.retained["evidenceOriginal"])
        proof["statement"]["pairSha256"] = sha(b"different pair")
        with self.assertRaises(core.TransitionKernelError):
            f.kernel.transition(replace(f.context(), native_jit_pending={**f.retained,
                "evidenceOriginal": canonical(proof).decode()}))

    def test_parent_or_business_intent_changes_do_not_select_another_identity(self):
        f = self.fixture
        changed = copy.deepcopy(f.parent["arguments"])
        changed["businessIntent"]["arguments"]["attempt_id"] = sha(b"another attempt")
        with self.assertRaises(core.TransitionKernelError):
            f.kernel.queries(arguments=changed, database_now=NOW, request_digest=f.parent["requestDigest"])
        with self.assertRaises(core.TransitionKernelError):
            f.kernel.queries(arguments=f.parent["arguments"], database_now=NOW, request_digest=sha(b"another parent"))

    def test_native_binding_is_plain_hash_of_independent_wire_roster(self):
        f = self.fixture
        raw = f.crypto.runtime["arguments"]
        expected = {field: raw[field] for field in ("attempt_id", "flow_id", "principal_id", "route_id",
            "credential_id", "credential_version", "policy_hash", "request_digest", "operation_digest",
            "operation_context", "require_jit_grant")}
        expected.update(api_version="catchplate.nativeReleaseAuthorizationBinding/v2",
            durable_policy=raw["durable_policy_binding"], approver_policy=crypto.preparation_fixture.approver_policy(),
            shared_quotas=[crypto.preparation_fixture.quota_claim()])
        result = f.transition().result
        self.assertEqual(result["binding_digest"], sha(canonical(expected)))
        self.assertEqual(result["durable_policy"], {"state": "denied", "attempt_id": raw["attempt_id"],
            "claim_digest": raw["durable_policy_binding"]["claimDigest"], "reservation_id": None,
            "actor_id": raw["actor_id"], "reservation_deadline_at_epoch_ms": None,
            "dispatch_deadline_at_epoch_ms": None, "response_evidence_digest": None,
            "failure_reason": None, "response_body_sha256": None, "uncertainty": None})


if __name__ == "__main__":
    unittest.main()
