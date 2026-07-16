#!/usr/bin/env python3
from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from serverware import runtime


def proof_context(**changes: object) -> dict[str, object]:
    context: dict[str, object] = {
        "route_id": "gmail.recent",
        "principal_id": "principal-a",
        "credential_id": "gmail-credential",
        "credential_version": 7,
        "policy_hash": "sha256:" + "a" * 64,
        "gmail_user": "me",
        "cutoff_epoch_ms": 1_700_000_000_000,
    }
    context.update(changes)
    return context


def cache_proofs(
    context: dict[str, object],
    message_ids: list[str],
    *,
    ttl_seconds: int = 60,
    max_age_expires_at_epoch_ms: dict[str, int] | None = None,
) -> None:
    boundaries = (
        {
            message_id: int(time.time() * 1000) + 86_400_000
            for message_id in message_ids
        }
        if max_age_expires_at_epoch_ms is None
        else max_age_expires_at_epoch_ms
    )
    runtime.cache_gmail_message_ids(
        context,
        message_ids,
        ttl_seconds=ttl_seconds,
        max_age_expires_at_epoch_ms=boundaries,
    )


class GmailProofCacheTests(unittest.TestCase):
    def setUp(self) -> None:
        with runtime._gmail_lock:
            runtime._gmail_cache.clear()

    def tearDown(self) -> None:
        with runtime._gmail_lock:
            runtime._gmail_cache.clear()

    def test_direct_read_proof_is_bound_to_every_security_context_field(self) -> None:
        context = proof_context()
        cache_proofs(context, ["message-1"])
        self.assertTrue(runtime.gmail_message_allowed(context, "message-1"))
        self.assertFalse(runtime.gmail_message_allowed(context, "message-2"))

        variants = {
            "route_id": "gmail.other",
            "principal_id": "principal-b",
            "credential_id": "other-credential",
            "credential_version": 8,
            "policy_hash": "sha256:" + "b" * 64,
            "gmail_user": "someone@example.test",
            "cutoff_epoch_ms": 1_800_000_000_000,
        }
        for field, value in variants.items():
            with self.subTest(field=field):
                self.assertFalse(
                    runtime.gmail_message_allowed(proof_context(**{field: value}), "message-1")
                )

    def test_limit_evicts_oldest_proof_deterministically(self) -> None:
        context = proof_context()
        with mock.patch.object(runtime, "_GMAIL_DIRECT_READ_PROOF_CACHE_MAX_ENTRIES", 3):
            cache_proofs(context, ["one", "two", "three"])
            cache_proofs(context, ["four"])
            self.assertFalse(runtime.gmail_message_allowed(context, "one"))
            for message_id in ("two", "three", "four"):
                self.assertTrue(runtime.gmail_message_allowed(context, message_id))

            cache_proofs(context, ["two"])
            cache_proofs(context, ["five"])
            self.assertFalse(runtime.gmail_message_allowed(context, "three"))
            for message_id in ("two", "four", "five"):
                self.assertTrue(runtime.gmail_message_allowed(context, message_id))
            self.assertEqual(runtime.metrics()["gmail_cache_entry_count"], 3)

    def test_large_duplicate_batch_never_exceeds_limit(self) -> None:
        context = proof_context()
        with mock.patch.object(runtime, "_GMAIL_DIRECT_READ_PROOF_CACHE_MAX_ENTRIES", 3):
            cache_proofs(context, ["one", "two", "one", "three", "four"])
            self.assertEqual(runtime.metrics()["gmail_cache_entry_count"], 3)
            self.assertFalse(runtime.gmail_message_allowed(context, "two"))
            for message_id in ("one", "three", "four"):
                self.assertTrue(runtime.gmail_message_allowed(context, message_id))

    def test_expired_proofs_are_pruned_before_live_proofs_are_evicted(self) -> None:
        context = proof_context()
        with mock.patch.object(runtime.time, "monotonic", return_value=100.0):
            cache_proofs(context, ["expired"], ttl_seconds=1)
        with mock.patch.object(runtime.time, "monotonic", return_value=102.0):
            cache_proofs(context, ["live"])
            self.assertFalse(runtime.gmail_message_allowed(context, "expired"))
            self.assertTrue(runtime.gmail_message_allowed(context, "live"))
            self.assertEqual(runtime.metrics()["gmail_cache_entry_count"], 1)

    def test_invalid_ttl_is_rejected_without_creating_a_proof(self) -> None:
        context = proof_context()
        for ttl in (0, -1, True, 86_401):
            with self.subTest(ttl=ttl), self.assertRaises(ValueError):
                cache_proofs(context, ["message"], ttl_seconds=ttl)
        self.assertEqual(runtime.metrics()["gmail_cache_entry_count"], 0)

    def test_missing_or_type_coerced_context_fails_closed(self) -> None:
        invalid_contexts = []
        for field in proof_context():
            context = proof_context()
            context.pop(field)
            invalid_contexts.append(context)
        invalid_contexts.extend(
            [
                proof_context(credential_version="7"),
                proof_context(credential_version=True),
                proof_context(cutoff_epoch_ms="1700000000000"),
                proof_context(policy_hash="a" * 64),
                proof_context(principal_id=""),
                proof_context(gmail_user="me\nadmin"),
            ]
        )
        for context in invalid_contexts:
            with self.subTest(context=context):
                with self.assertRaises(ValueError):
                    cache_proofs(context, ["message"])
                self.assertFalse(runtime.gmail_message_allowed(context, "message"))
        self.assertEqual(runtime.metrics()["gmail_cache_entry_count"], 0)

    def test_invalid_message_ids_fail_without_partial_cache_insertion(self) -> None:
        for message_ids in ([], ["valid", ""], ["valid", "bad\nmessage"], ["x"] * 33):
            with self.subTest(message_ids=message_ids), self.assertRaises(ValueError):
                cache_proofs(proof_context(), message_ids)
            self.assertEqual(runtime.metrics()["gmail_cache_entry_count"], 0)

    def test_proof_expires_at_exact_message_max_age_boundary(self) -> None:
        context = proof_context()
        boundary_epoch_ms = 1_700_000_001_000
        with mock.patch.object(runtime.time, "monotonic", return_value=100.0), mock.patch.object(
            runtime.time, "time", return_value=1_700_000_000.0
        ):
            cache_proofs(
                context,
                ["boundary"],
                ttl_seconds=60,
                max_age_expires_at_epoch_ms={"boundary": boundary_epoch_ms},
            )
        with mock.patch.object(runtime.time, "monotonic", return_value=100.999), mock.patch.object(
            runtime.time, "time", return_value=1_700_000_000.999
        ):
            self.assertTrue(runtime.gmail_message_allowed(context, "boundary"))
        with mock.patch.object(runtime.time, "monotonic", return_value=101.0), mock.patch.object(
            runtime.time, "time", return_value=1_700_000_001.0
        ):
            self.assertFalse(runtime.gmail_message_allowed(context, "boundary"))

    def test_already_aged_out_message_never_creates_direct_read_proof(self) -> None:
        context = proof_context()
        with mock.patch.object(runtime.time, "monotonic", return_value=100.0), mock.patch.object(
            runtime.time, "time", return_value=1_700_000_001.0
        ):
            cache_proofs(
                context,
                ["aged-out"],
                max_age_expires_at_epoch_ms={"aged-out": 1_700_000_001_000},
            )
            self.assertFalse(runtime.gmail_message_allowed(context, "aged-out"))
        self.assertEqual(runtime.metrics()["gmail_cache_entry_count"], 0)

    def test_invalid_max_age_boundaries_fail_without_partial_insertion(self) -> None:
        invalid_boundaries = (
            {},
            {"message": True},
            {"message": -1},
            {"other": int(time.time() * 1000) + 1000},
        )
        for boundaries in invalid_boundaries:
            with self.subTest(boundaries=boundaries), self.assertRaises(ValueError):
                cache_proofs(
                    proof_context(),
                    ["message"],
                    max_age_expires_at_epoch_ms=boundaries,
                )
            self.assertEqual(runtime.metrics()["gmail_cache_entry_count"], 0)


if __name__ == "__main__":
    unittest.main()
