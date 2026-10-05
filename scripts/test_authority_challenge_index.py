#!/usr/bin/env python3
"""Pure fresh-source challenge ordering/projection controls, not DB admission.

No database, installation, measured plan, proof acceptance or runtime authority
is simulated. Literal key tails and the existing independent old-descriptor
oracle check the exact codec boundary used by later integrated proof fixtures.
"""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import authority_challenge_id as ids
from serverware import authority_index_projection as projection
from serverware import authority_index_trace as trace
from serverware import authority_index_heads as heads
import test_authority_index_join as old_oracle


UUID0 = "00000000-0000-0000-0000-000000000000"
UUID1 = "00000000-0000-0000-0000-000000000001"
UUID_MAX = "ffffffff-ffff-ffff-ffff-ffffffffffff"
SHA0 = "sha256:" + "0" * 64
SHA1 = "sha256:" + "0" * 63 + "1"
PK = "sha256:" + "a" * 64
ROW = "sha256:" + "b" * 64
EPOCH = "1970-01-01T00:00:00+00:00"


def row(identifier=UUID0):
    return dict(id=identifier, challenge="challenge", challenge_type="authentication",
        user_id="user", scope_key=None, expires_at=EPOCH, created_at=EPOCH,
        used_at=None, retention_reference_mask=0)


def project(name, value):
    return projection.project_row(name, value, primary_key_digest=PK, primary_row_digest=ROW)


class ChallengeIndexTests(unittest.TestCase):
    def test_generated_id_tail_has_literal_layout_and_exact_text_order(self):
        expected = {
            UUID0: "00" + "0" * 64 + "0" * 14,
            UUID1: "00" + "0" * 31 + "1" + "0" * 32 + "0" * 14,
            UUID_MAX: "00" + "f" * 32 + "0" * 32 + "0" * 14,
            SHA0: "01" + "0" * 64 + "0" * 14,
            SHA1: "01" + "0" * 63 + "1" + "0" * 14,
        }
        for identifier, literal in expected.items():
            self.assertEqual(ids.order_suffix(identifier), literal)
            self.assertEqual(len(literal), 80)
        self.assertEqual(sorted(expected), sorted(expected, key=ids.order_suffix))

    def test_custom_and_noncanonical_ids_are_not_historically_adopted(self):
        class TextSubclass(str):
            pass
        for value in ("custom-id", UUID_MAX.upper(), UUID0.replace("-", ""),
                      SHA0 + "\n", "SHA256:" + "0" * 64, "sha256:" + "F" * 64,
                      None, 0, False, TextSubclass(UUID0)):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaisesRegex(ValueError, "fresh challenge source"):
                    ids.require_generated(value)

    def test_new_keys_keep_actual_commitments_and_source_timestamp_order(self):
        name = "webauthn_challenge_unused_global"
        ordered = []
        for timestamp, encoded in (("1969-12-31T23:59:59.999999+00:00", "7fffffffffffffff"),
                                   (EPOCH, "8000000000000000"),
                                   ("1970-01-01T00:00:00.000001+00:00", "8000000000000001")):
            for identifier in (UUID0, UUID1, UUID_MAX, SHA0, SHA1):
                value = row(identifier)
                value["expires_at"] = timestamp
                leaf = project(name, value)
                self.assertEqual(leaf.key[64:80], encoded)
                self.assertEqual(leaf.key[80:], ids.order_suffix(identifier))
                self.assertEqual((leaf.primary_key_digest, leaf.primary_row_digest), (PK, ROW))
                ordered.append(leaf.key)
        self.assertEqual(ordered, sorted(ordered))
        self.assertEqual(len(set(ordered)), len(ordered))

    def test_cutoff_inclusivity_and_i64_extremes_are_closed(self):
        name = "webauthn_challenge_unused_global"
        leaf = project(name, row())
        def contains(interval):
            return interval.lower <= leaf.key and (interval.upper is None or leaf.key < interval.upper)
        for direction, expected in (("at-or-before", True), ("strictly-after", False), ("all", True)):
            self.assertEqual(contains(projection.query_interval(name,
                dict(cutoff_us=0, direction=direction))), expected)
        empty = projection.query_interval(name, dict(cutoff_us=2**63 - 1, direction="strictly-after"))
        self.assertEqual(empty.lower, empty.upper)
        self.assertFalse(contains(projection.query_interval(name,
            dict(cutoff_us=-(2**63), direction="at-or-before"))))
        for selector in (dict(cutoff_us=False, direction="all"), dict(cutoff_us=0, direction="other"),
                         dict(cutoff_us=0, direction="all", lower="0" * 160)):
            with self.assertRaises(projection.IndexProjectionError):
                projection.query_interval(name, selector)

    def test_scope_null_is_not_empty_and_terminal_membership_uses_actual_mask(self):
        scope = "webauthn_challenge_scope_unused"
        selector = dict(challenge_type="authentication", user_id="user", scope_key=None)
        null_interval = projection.query_interval(scope, selector)
        empty_interval = projection.query_interval(scope, dict(selector, scope_key=""))
        self.assertNotEqual(null_interval, empty_interval)
        self.assertTrue(null_interval.lower <= project(scope, row()).key < null_interval.upper)
        terminal = "webauthn_challenge_terminal_unreferenced_global"
        self.assertIsNone(project(terminal, row()))
        used = dict(row(), used_at=EPOCH)
        self.assertIsNotNone(project(terminal, used))
        for mask in range(1, 8):
            self.assertIsNone(project(terminal, dict(used, retention_reference_mask=mask)))
        for invalid in (-1, 8, False, 0.0):
            with self.assertRaises(projection.IndexProjectionError):
                project(terminal, dict(used, retention_reference_mask=invalid))

    def test_older_profile_documents_are_unchanged(self):
        for name in ("webauthn_registration_unused_global", "webauthn_registration_unused_user"):
            self.assertEqual(projection._definition(name).document(), old_oracle.descriptor(name))
        self.assertEqual(len(projection.INDEX_IDS), 24)
        self.assertEqual(len(projection.index_ids_for_table("webauthn_challenges")), 9)

    def test_count_trace_shape_cannot_authorize_other_profiles_or_tables(self):
        key = dict(profile=trace.COUNT_READ_PROFILE,
            indexId="webauthn_challenge_unused_global", projectionDigest=PK,
            indexRevision=1, rootDigest=ROW, rootCount=50000,
            lower="0" * 160, upper=None, prefixes=[dict(depth=1, pathPrefix="0")], limit=2)
        trace.validate_count_read_trace("webauthn.challenge.create", "policy_authority_counted_index_nodes", key)
        for field, value in (("indexId", "webauthn_credential_id"), ("rootCount", True),
                             ("limit", 1), ("prefixes", [dict(depth=2, pathPrefix="0")])):
            changed = copy.deepcopy(key)
            changed[field] = value
            with self.assertRaises(trace.IndexTraceError):
                trace.validate_count_read_trace("webauthn.challenge.create", "policy_authority_counted_index_nodes", changed)
        with self.assertRaises(trace.IndexTraceError):
            trace.validate_count_read_trace("webauthn.challenge.create", "webauthn_challenges", key)
        with self.assertRaises(trace.IndexTraceError):
            trace.validate_count_read_trace("webauthn.challenge.claim", "policy_authority_counted_index_nodes", key)

    def test_private_head_inventories_are_exact_not_caller_subsets(self):
        self.assertEqual(len(heads.required_index_ids("webauthn.challenge.create")), 5)
        challenge = heads.required_index_ids("webauthn.challenge.create", include_write_heads=True)
        self.assertEqual(challenge, projection.index_ids_for_table("webauthn_challenges"))
        jit = heads.required_index_ids("jit.assertion.issue", include_write_heads=True)
        self.assertEqual(set(jit), set(challenge) | set(projection.index_ids_for_table("webauthn_credentials")))
        self.assertEqual(len(jit), 12)
        with self.assertRaises(heads.IndexHeadReadError):
            heads.required_index_ids("jit.assertion.issue")
        with self.assertRaises(heads.IndexHeadReadError):
            heads.validate_head_trace_key("webauthn.challenge.create",
                dict(profile=heads.READ_PROFILE, indexIds=list(challenge[:-1]), rowLimit=len(challenge)))
        for operation in heads.RECOVERY_OPERATIONS:
            expected = set(jit) if operation == "webauthn.recovery.finalize" else set(challenge)
            if operation in heads.RECOVERY_HISTORY_OPERATIONS:
                expected.add(heads.RECOVERY_HISTORY_ID)
            self.assertEqual(set(heads.required_index_ids(operation, include_write_heads=True)), expected)
            if operation in heads.RECOVERY_HISTORY_OPERATIONS:
                self.assertEqual(heads.required_index_ids(operation), (heads.RECOVERY_HISTORY_ID,))
            else:
                with self.assertRaises(heads.IndexHeadReadError):
                    heads.required_index_ids(operation)


if __name__ == "__main__":
    unittest.main()
