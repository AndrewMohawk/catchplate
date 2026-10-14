#!/usr/bin/env python3
"""Legacy receipt kernel controls; no native-opening or admission claim.

Real query, mutation, audit and capacity helpers operate on explicitly synthetic
selected rows. No database, native owner, transport, provider or hardware runs.
An in-memory replay is not proof of a committed executor transaction.
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
_violations = []


def no_external_effects(event, _arguments):
    if event.startswith(("socket.", "sqlite3.")) or event in {
        "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn",
    }:
        _violations.append(event)
        raise AssertionError("receipt component controls forbid external effects")


if __name__ == "__main__":
    os.environ["SERVERWARE_PROCESS_MODE"] = "metadata-bootstrap"
    os.environ["SERVERWARE_RELEASE_CHANNEL"] = "dev"
    sys.addaudithook(no_external_effects)

from scripts import test_authority_audit_capacity as fixtures
from serverware import authority_audit_capacity as capacity
from serverware import authority_transition_core as core
from serverware import authority_transition_quota as quota

NOW = datetime(2026, 10, 13, 12, 0, 0, 123456, tzinfo=timezone.utc)
REQUEST = fixtures.framed("synthetic-jit-review-receipt", b"request")
REVIEW = fixtures.framed("synthetic-jit-review-receipt", b"review")
PRIVATE_FIELDS = ("url", "canonical_request", "redacted_display")


class Fixture:
    def __init__(self, *, remaining=timedelta(minutes=5)):
        self.kernel = quota._JitReviewReceiptKernel()
        self.arguments = {"approval_request_id": "approval:fixture", "reviewer_id": "oidc:reviewer",
            "review_digest": REVIEW, "ttl_seconds": 120, "businessIntent": {}}
        self.approval = {"id": "approval:fixture", "status": "pending",
            "url": "https://synthetic.invalid/resource", "canonical_request": "v2:opaque-canonical",
            "redacted_display": "v1:opaque-display", "expires_at": (NOW + remaining).isoformat()}
        self.rows = [fixtures.selection(query.table, query.absent_key)
            for query in self.kernel.queries(arguments=self.arguments,
                database_now=NOW, request_digest=REQUEST)]
        self.put("approval_requests", {"id": self.approval["id"]}, self.approval)
        kind = "jit-review-receipts"
        _identity, partition = quota._aggregate_key(kind, "global")
        for row in (fixtures.aggregate_row(kind=kind, partition=partition), fixtures.aggregate_row()):
            self.put(capacity.AGGREGATE_TABLE, {"aggregate_id": row["aggregate_id"]}, row)

    def put(self, table, key, row):
        selected = fixtures.selection(table, key, present=row is not None, row=row)
        for index, item in enumerate(self.rows):
            if item["table"] == table and item["key"] == key:
                self.rows[index] = selected
                break
        else:
            self.rows.append(selected)

    def context(self, *, now=NOW):
        self.put("approval_requests", {"id": self.approval["id"]}, self.approval)
        return core.KernelContext(operation=self.kernel.operation, arguments=copy.deepcopy(self.arguments),
            selected_rows=tuple(copy.deepcopy(self.rows)), database_now=now, request_digest=REQUEST)

    def transition(self, *, now=NOW):
        context = self.context(now=now)
        before = copy.deepcopy(context)
        result = self.kernel.transition(context)
        if context != before:
            raise AssertionError("receipt kernel mutated its input")
        return result

    def retain(self, result):
        for mutation in capacity.finalize_capacity(self.context(), result.mutations):
            self.put(mutation["table"], mutation["key"], mutation["row"])

    def receipt(self):
        return next(item["row"] for item in self.rows if item["table"] == "approval_review_receipts")


class JitReviewReceiptTests(unittest.TestCase):
    def tearDown(self):
        self.assertEqual(_violations, [], "an external-effect refusal is not a passing negative")

    def test_legacy_query_roster_and_result_stay_unchanged(self):
        f = Fixture()
        queries = f.kernel.queries(arguments=f.arguments, database_now=NOW, request_digest=REQUEST)
        self.assertEqual([query.table for query in queries], ["approval_requests", "approval_review_receipts",
            capacity.AGGREGATE_TABLE, "metadata_audit_outbox"])
        result = f.transition()
        self.assertEqual(set(result.result), {"id", "approval_request_id", "reviewer_id", "review_digest",
            "expires_at", "used_at", "created_at", "audit_event_digest", "idempotent_replay"})
        self.assertFalse(result.result["idempotent_replay"])
        self.assertEqual(result.result["expires_at"], (NOW + timedelta(seconds=120)).isoformat())
        self.assertEqual([item["table"] for item in result.mutations], ["approval_review_receipts",
            capacity.AGGREGATE_TABLE, "metadata_audit_outbox"])
        final = capacity.finalize_capacity(f.context(), result.mutations)
        self.assertEqual(len(final), 4)
        capacity.validate_capacity_transition(operation=f.kernel.operation,
            selected_rows=f.context().selected_rows, mutations=final)

    def test_plaintext_legacy_documents_remain_accepted(self):
        f = Fixture()
        f.approval.update(canonical_request='{"request":{"method":"GET"}}', redacted_display='{}')
        self.assertEqual(f.transition().result["review_digest"], REVIEW)

    def test_reserved_family_refused_in_each_field_before_any_receipt(self):
        forms = ("native-jit:", "native-jit:v1:{malformed", "native-jit:v9:unknown",
            "native-jit", "native-jit-not-a-reference", " NATIVE-JIT:v1:opaque", "\t\nnative-jit:v1:opaque")
        for field in PRIVATE_FIELDS:
            for form in forms:
                with self.subTest(field=field, form=form):
                    f = Fixture()
                    f.approval[field] = form
                    before = copy.deepcopy(f.context())
                    with self.assertRaisesRegex(core.TransitionKernelError, "native opening authority"):
                        f.kernel.transition(before)
                    self.assertEqual(before, f.context())

    def test_mixed_native_and_legacy_documents_are_not_a_legacy_review(self):
        for native_fields in (("canonical_request",), ("redacted_display",), PRIVATE_FIELDS):
            f = Fixture()
            for field in native_fields:
                f.approval[field] = "native-jit:v1:not-admitted"
            with self.assertRaisesRegex(core.TransitionKernelError, "native opening authority"):
                f.transition()

    def test_missing_and_non_text_reference_fields_fail_closed(self):
        for field in PRIVATE_FIELDS:
            for value in (None, {}, [], b"native-jit:v1:opaque", 1):
                f = Fixture()
                f.approval[field] = value
                with self.assertRaises(core.TransitionKernelError):
                    f.transition()
            f = Fixture()
            del f.approval[field]
            with self.assertRaises(core.TransitionKernelError):
                f.transition()

    def test_caller_native_opening_or_verified_flags_do_not_enable_a_branch(self):
        for name, value in (("native_opening", {}), ("verified", True), ("admitted", True)):
            f = Fixture()
            f.arguments[name] = value
            with self.assertRaisesRegex(core.TransitionKernelError, "arguments are not exact"):
                f.transition()

    def test_receipt_and_capacity_expiry_clip_to_original_approval(self):
        for remaining in (timedelta(seconds=45), timedelta(seconds=120), timedelta(microseconds=1)):
            f = Fixture(remaining=remaining)
            result = f.transition()
            self.assertEqual(result.result["expires_at"], f.approval["expires_at"])
            row = result.mutations[1]["row"]
            expiry = NOW + remaining
            delta = expiry - datetime(1970, 1, 1, tzinfo=timezone.utc)
            exact_ns = (delta.days * 86400 + delta.seconds) * 1_000_000_000 + delta.microseconds * 1000
            self.assertEqual(row["minimum_expiry_epoch_ns"], exact_ns)

    def test_expired_or_terminal_approval_refused(self):
        for remaining in (timedelta(0), timedelta(microseconds=-1)):
            with self.assertRaisesRegex(core.TransitionKernelError, "live pending approval"):
                Fixture(remaining=remaining).transition()
        for status in ("approved", "denied", "expired"):
            f = Fixture()
            f.approval["status"] = status
            with self.assertRaisesRegex(core.TransitionKernelError, "live pending approval"):
                f.transition()

    def test_invalid_non_utc_or_naive_approval_time_refused(self):
        for expiry in (None, 1, "bad", "9999-not-a-time", "2026-10-14T12:00:00",
                "2026-10-14T12:00:00+02:00"):
            f = Fixture()
            f.approval["expires_at"] = expiry
            with self.assertRaisesRegex(core.TransitionKernelError, "lifetime is invalid"):
                f.transition()

    def test_exact_replay_preserves_original_lifetime_and_has_no_mutations(self):
        f = Fixture(remaining=timedelta(seconds=45))
        first = f.transition()
        f.retain(first)
        replay = f.transition(now=NOW + timedelta(seconds=10))
        self.assertTrue(replay.result["idempotent_replay"])
        self.assertEqual(replay.mutations, ())
        for field in ("id", "created_at", "expires_at", "audit_event_digest"):
            self.assertEqual(replay.result[field], first.result[field])

    def test_expired_or_used_receipt_replay_does_not_restore_authority(self):
        f = Fixture()
        first = f.transition()
        f.retain(first)
        f.receipt()["used_at"] = (NOW + timedelta(seconds=1)).isoformat()
        result = f.transition(now=NOW + timedelta(seconds=150))
        self.assertEqual(result.mutations, ())
        self.assertEqual(result.result["expires_at"], first.result["expires_at"])
        self.assertEqual(result.result["used_at"], (NOW + timedelta(seconds=1)).isoformat())

    def test_replay_cannot_cross_approval_or_original_receipt_lifetime(self):
        for remaining, field, value in (
                (45, "expires_at", NOW + timedelta(seconds=46)),
                (300, "expires_at", NOW + timedelta(seconds=121)),
                (300, "created_at", NOW + timedelta(seconds=1)),
                (300, "expires_at", NOW)):
            f = Fixture(remaining=timedelta(seconds=remaining))
            f.retain(f.transition())
            f.receipt()[field] = value.isoformat()
            with self.assertRaisesRegex(core.TransitionKernelError, "lifetime was rebound"):
                f.transition()

    def test_replay_refuses_native_refs_even_with_existing_receipt_and_audit(self):
        for field in PRIVATE_FIELDS:
            f = Fixture()
            f.retain(f.transition())
            f.approval[field] = "native-jit:v1:not-opened"
            with self.assertRaisesRegex(core.TransitionKernelError, "native opening authority"):
                f.transition()

    def test_replay_reviewer_digest_and_audit_conflicts_remain_refused(self):
        for field in ("reviewer_id", "review_digest", "approval_request_id"):
            f = Fixture()
            f.retain(f.transition())
            f.receipt()[field] = "rebound"
            with self.assertRaisesRegex(core.TransitionKernelError, "identity was rebound"):
                f.transition()
        f = Fixture()
        first = f.transition()
        f.retain(first)
        audit = next(item for item in f.rows if item["table"] == "metadata_audit_outbox")
        audit["row"]["event_digest"] = REVIEW
        with self.assertRaisesRegex(core.TransitionKernelError, "audit outbox replay conflicts"):
            f.transition()


if __name__ == "__main__":
    unittest.main()
