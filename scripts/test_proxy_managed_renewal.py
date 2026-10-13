#!/usr/bin/env python3
"""Synthetic renewal-policy controls, not renewal or CONNECT acceptance.

Only wall time is mocked. Real policy parsing, schema validation, matching and
identity-overlap admission run unchanged. No service, token store or provider
is contacted, and these fixtures do not establish deployment or continuity.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import policy_bundle as pb
from scripts.test_proxy_basic_transport import (
    CLIENT, MAX_EXPIRY, NOW, OTHER_USERNAME, TOKEN, USERNAME,
    authorization as basic_authorization, basic, document as basic_document,
)

OLD_TOKEN = "B" * 43
OTHER_TOKEN = "C" * 43
OTHER_OLD_TOKEN = "D" * 43
ENROLLMENT = "87654321-4321-4321-8321-cba987654321"
OTHER_ENROLLMENT = "87654321-4321-4321-8321-cba987654322"
NOW_MS = NOW * 1000
ROTATED = NOW_MS - 60_000
CUTOFF = ROTATED + 300_000
ORIGINAL_EXPIRY = NOW_MS + 600_000
CURRENT_EXPIRY = NOW_MS + 3_600_000
GRANT_EXPIRY = NOW_MS + 86_400_000
SCHEMA = "serverware.proxyTokenRenewal/v1"


def verifier(token):
    return "sha256:" + hashlib.sha256(token.encode("ascii")).hexdigest()


def authorization(*, enabled=True, previous=True):
    value = basic_authorization(enabled=enabled)
    value["expiresAtEpochMs"] = CURRENT_EXPIRY
    value["managedRenewal"] = {
        "schema": SCHEMA, "enrollmentId": ENROLLMENT,
        "enrollmentExpiresAtEpochMs": GRANT_EXPIRY,
        "rotatedAtEpochMs": ROTATED,
    }
    if previous:
        value["managedRenewal"]["previousToken"] = {
            "tokenSha256": verifier(OLD_TOKEN),
            "originalExpiresAtEpochMs": ORIGINAL_EXPIRY,
            "expiresAtEpochMs": CUTOFF,
        }
    return value


def document(raw=None):
    value = basic_document()
    value["principals"][0]["proxyAuthorization"] = (
        authorization() if raw is None else deepcopy(raw)
    )
    return value


def replace(raw, path, value):
    result = deepcopy(raw)
    node = result
    for name in path[:-1]:
        node = node[name]
    node[path[-1]] = value
    return result


class ProxyManagedRenewalTests(unittest.TestCase):
    def setUp(self):
        clock = patch.object(pb.time, "time", return_value=NOW)
        clock.start()
        self.addCleanup(clock.stop)

    def assert_invalid(self, raw):
        with self.assertRaises(pb.PolicyBundleError):
            pb.ProxyAuthorizationPolicy.from_raw(raw)
        for check_schema in (False, True):
            with self.subTest(validate_schema=check_schema):
                with self.assertRaises(pb.PolicyBundleError):
                    pb.compile_policy_bundle(document(raw), validate_schema=check_schema)

    def assert_at(self, policy, token, when, expected):
        with patch.object(pb.time, "time", return_value=when / 1000):
            for header in ("Bearer " + token, basic(token=token)):
                with self.subTest(header_scheme=header.split(" ", 1)[0], epoch_ms=when):
                    self.assertEqual(policy.matches(CLIENT, header), expected)

    def test_current_and_previous_identify_same_principal_in_both_transports(self):
        for enabled in (False, True):
            for check_schema in (False, True):
                snapshot = pb.compile_policy_bundle(
                    document(authorization(enabled=enabled)), validate_schema=check_schema
                )
                for token in (TOKEN, OLD_TOKEN):
                    for scheme in ("Bearer", "bEaReR", "Basic", "bAsIc"):
                        header = basic(token=token, scheme=scheme) if scheme.lower() == "basic" else scheme + " " + token
                        principal = snapshot.identify_principal(CLIENT, {"Proxy-Authorization": header})
                        with self.subTest(enabled=enabled, schema=check_schema, scheme=scheme, old=token == OLD_TOKEN):
                            if enabled or scheme.lower() == "bearer":
                                self.assertIsNotNone(principal)
                                self.assertEqual(principal.id, "agent:fixture")
                            else:
                                self.assertIsNone(principal)

    def test_previous_cutoff_is_exclusive_and_does_not_expire_current(self):
        policy = pb.ProxyAuthorizationPolicy.from_raw(authorization())
        self.assert_at(policy, OLD_TOKEN, CUTOFF - 1, True)
        self.assert_at(policy, OLD_TOKEN, CUTOFF, False)
        self.assert_at(policy, OLD_TOKEN, CUTOFF + 1, False)
        self.assert_at(policy, TOKEN, CUTOFF, True)
        self.assert_at(policy, TOKEN, CURRENT_EXPIRY - 1, True)
        self.assert_at(policy, TOKEN, CURRENT_EXPIRY, False)

    def test_current_expiry_does_not_replace_previous_slot_deadline(self):
        raw = authorization()
        raw["expiresAtEpochMs"] = NOW_MS + 1_000
        policy = pb.ProxyAuthorizationPolicy.from_raw(raw)
        self.assert_at(policy, TOKEN, NOW_MS + 999, True)
        self.assert_at(policy, TOKEN, NOW_MS + 1_000, False)
        self.assert_at(policy, OLD_TOKEN, NOW_MS + 1_000, True)
        self.assert_at(policy, OLD_TOKEN, CUTOFF, False)

    def test_original_expiry_clips_overlap_without_extending_it(self):
        raw = authorization()
        previous = raw["managedRenewal"]["previousToken"]
        previous["originalExpiresAtEpochMs"] = NOW_MS + 10_000
        previous["expiresAtEpochMs"] = NOW_MS + 10_000
        policy = pb.ProxyAuthorizationPolicy.from_raw(raw)
        self.assert_at(policy, OLD_TOKEN, NOW_MS + 9_999, True)
        self.assert_at(policy, OLD_TOKEN, NOW_MS + 10_000, False)
        self.assert_at(policy, TOKEN, NOW_MS + 10_000, True)
        previous["expiresAtEpochMs"] += 1
        self.assert_invalid(raw)

    def test_both_slots_stop_exactly_at_clipped_enrollment_deadline(self):
        raw = authorization()
        deadline = NOW_MS + 120_000
        raw["expiresAtEpochMs"] = deadline
        raw["managedRenewal"]["enrollmentExpiresAtEpochMs"] = deadline
        previous = raw["managedRenewal"]["previousToken"]
        previous["originalExpiresAtEpochMs"] = deadline
        previous["expiresAtEpochMs"] = deadline
        policy = pb.ProxyAuthorizationPolicy.from_raw(raw)
        for token in (TOKEN, OLD_TOKEN):
            self.assert_at(policy, token, deadline - 1, True)
            self.assert_at(policy, token, deadline, False)

    def test_cidr_username_and_unknown_verifier_restrictions_apply_to_both_slots(self):
        policy = pb.ProxyAuthorizationPolicy.from_raw(authorization())
        for token in (TOKEN, OLD_TOKEN):
            for header in ("Bearer " + token, basic(token=token)):
                for client in (None, "198.51.100.1", "::1", "not-an-address"):
                    with self.subTest(token=token, client=client):
                        self.assertFalse(policy.matches(client, header))
            self.assertFalse(policy.matches(CLIENT, basic(OTHER_USERNAME, token)))
            self.assertFalse(policy.matches(CLIENT, basic(USERNAME.upper(), token)))
        for header in ("Bearer " + OTHER_TOKEN, basic(token=OTHER_TOKEN), None, ""):
            self.assertFalse(policy.matches(CLIENT, header))

    def test_missing_previous_slot_and_cancellation_remove_only_old_acceptance(self):
        enrolled = authorization(previous=False)
        cancelled = authorization()
        cancelled.pop("managedRenewal")
        for raw in (enrolled, cancelled):
            for check_schema in (False, True):
                snapshot = pb.compile_policy_bundle(document(raw), validate_schema=check_schema)
                policy = snapshot.principals["agent:fixture"].proxy_authorization
                self.assert_at(policy, TOKEN, NOW_MS, True)
                self.assert_at(policy, OLD_TOKEN, NOW_MS, False)

    def test_initial_enrollment_of_expired_current_token_does_not_revive_it(self):
        for expiry in (ROTATED - 1, ROTATED, NOW_MS - 1):
            raw = authorization(previous=False)
            raw["expiresAtEpochMs"] = expiry
            policy = pb.ProxyAuthorizationPolicy.from_raw(raw)
            self.assert_at(policy, TOKEN, NOW_MS, False)
            self.assert_at(policy, OLD_TOKEN, NOW_MS, False)
            for check_schema in (False, True):
                snapshot = pb.compile_policy_bundle(document(raw), validate_schema=check_schema)
                for header in ("Bearer " + TOKEN, basic()):
                    self.assertIsNone(snapshot.identify_principal(CLIENT, {"Proxy-Authorization": header}))

    def test_managed_marker_is_closed_nonnull_and_complete(self):
        for value in (None, False, True, [], "renewal", 1, {}):
            with self.subTest(value=value):
                self.assert_invalid(replace(authorization(), ("managedRenewal",), value))
        for field in ("schema", "enrollmentId", "enrollmentExpiresAtEpochMs", "rotatedAtEpochMs"):
            raw = authorization()
            del raw["managedRenewal"][field]
            with self.subTest(missing=field):
                self.assert_invalid(raw)
        raw = authorization()
        raw["managedRenewal"]["tokenLifetimeSeconds"] = 3600
        self.assert_invalid(raw)

    def test_previous_marker_is_closed_nonnull_and_complete(self):
        for value in (None, False, True, [], "previous", 1, {}):
            with self.subTest(value=value):
                self.assert_invalid(replace(authorization(), ("managedRenewal", "previousToken"), value))
        for field in ("tokenSha256", "originalExpiresAtEpochMs", "expiresAtEpochMs"):
            raw = authorization()
            del raw["managedRenewal"]["previousToken"][field]
            with self.subTest(missing=field):
                self.assert_invalid(raw)
        raw = authorization()
        raw["managedRenewal"]["previousToken"]["tokenGeneration"] = 1
        self.assert_invalid(raw)

    def test_schema_and_enrollment_identifier_are_exact(self):
        for value in (None, True, 1, SCHEMA.upper(), SCHEMA + " ", "serverware.proxyTokenRenewal/v2"):
            with self.subTest(schema=value):
                self.assert_invalid(replace(authorization(), ("managedRenewal", "schema"), value))
        for value in (None, True, 1, "", ENROLLMENT.upper(), ENROLLMENT + "\n", ENROLLMENT.replace("-", "")):
            with self.subTest(enrollment=value):
                self.assert_invalid(replace(authorization(), ("managedRenewal", "enrollmentId"), value))

    def test_managed_token_id_is_required_canonical_even_without_basic(self):
        for enabled in (False, True):
            for value in (None, True, 1, "", "legacy-token-id", USERNAME.upper(), USERNAME + "\n", USERNAME.replace("-", "")):
                with self.subTest(basic=enabled, token_id=value):
                    self.assert_invalid(replace(authorization(enabled=enabled), ("tokenId",), value))
            raw = authorization(enabled=enabled)
            raw.pop("tokenId")
            self.assert_invalid(raw)

    def test_all_timestamps_are_finite_safe_integer_milliseconds(self):
        paths = (("expiresAtEpochMs",),
            ("managedRenewal", "enrollmentExpiresAtEpochMs"),
            ("managedRenewal", "rotatedAtEpochMs"),
            ("managedRenewal", "previousToken", "originalExpiresAtEpochMs"),
            ("managedRenewal", "previousToken", "expiresAtEpochMs"))
        for path in paths:
            for value in (None, True, False, 0, -1, 1.0, float("nan"), float("inf"),
                    [], {}, str(NOW_MS), MAX_EXPIRY + 1):
                with self.subTest(field=path, value=value):
                    self.assert_invalid(replace(authorization(enabled=False), path, value))
        raw = authorization(enabled=False)
        raw.pop("expiresAtEpochMs")
        self.assert_invalid(raw)

    def test_ordering_and_grant_bounds_reject_one_millisecond_violations(self):
        changes = (
            (("expiresAtEpochMs",), ROTATED),
            (("expiresAtEpochMs",), ROTATED - 1),
            (("expiresAtEpochMs",), GRANT_EXPIRY + 1),
            (("managedRenewal", "enrollmentExpiresAtEpochMs"), ROTATED),
            (("managedRenewal", "previousToken", "expiresAtEpochMs"), ROTATED),
            (("managedRenewal", "previousToken", "expiresAtEpochMs"), ROTATED - 1),
            (("managedRenewal", "previousToken", "expiresAtEpochMs"), ROTATED + 300_001),
            (("managedRenewal", "previousToken", "originalExpiresAtEpochMs"), CUTOFF - 1),
            (("managedRenewal", "previousToken", "originalExpiresAtEpochMs"), GRANT_EXPIRY + 1),
        )
        for path, value in changes:
            with self.subTest(field=path, value=value):
                self.assert_invalid(replace(authorization(), path, value))
        raw = authorization()
        raw["expiresAtEpochMs"] = NOW_MS + 1_000
        raw["managedRenewal"]["enrollmentExpiresAtEpochMs"] = NOW_MS + 2_000
        raw["managedRenewal"]["previousToken"]["originalExpiresAtEpochMs"] = NOW_MS + 2_000
        raw["managedRenewal"]["previousToken"]["expiresAtEpochMs"] = NOW_MS + 2_001
        self.assert_invalid(raw)

    def test_exact_five_minute_cap_and_safe_integer_maximum_are_valid(self):
        for raw in (authorization(), authorization(previous=False)):
            raw["expiresAtEpochMs"] = MAX_EXPIRY
            marker = raw["managedRenewal"]
            marker["enrollmentExpiresAtEpochMs"] = MAX_EXPIRY
            marker["rotatedAtEpochMs"] = MAX_EXPIRY - 300_000
            if "previousToken" in marker:
                marker["previousToken"]["originalExpiresAtEpochMs"] = MAX_EXPIRY
                marker["previousToken"]["expiresAtEpochMs"] = MAX_EXPIRY
            self.assertIsNotNone(pb.ProxyAuthorizationPolicy.from_raw(raw))
            for check_schema in (False, True):
                self.assertIsNotNone(pb.compile_policy_bundle(document(raw), validate_schema=check_schema))

    def test_current_and_previous_hashes_are_distinct_closed_sha256_values(self):
        for path in (("tokenSha256",), ("managedRenewal", "previousToken", "tokenSha256")):
            for value in (None, True, 1, "", verifier(TOKEN).upper(), "sha256:" + "a" * 63,
                    "sha256:" + "g" * 64, verifier(TOKEN) + "\n", " " + verifier(TOKEN)):
                with self.subTest(field=path, value=value):
                    self.assert_invalid(replace(authorization(), path, value))
        self.assert_invalid(replace(authorization(),
            ("managedRenewal", "previousToken", "tokenSha256"), verifier(TOKEN)))

    def test_parsing_matching_and_compilation_do_not_mutate_input(self):
        raw = authorization()
        value = document(raw)
        original_raw, original_document = deepcopy(raw), deepcopy(value)
        policy = pb.ProxyAuthorizationPolicy.from_raw(raw)
        self.assert_at(policy, OLD_TOKEN, NOW_MS, True)
        self.assert_at(policy, TOKEN, CUTOFF, True)
        for check_schema in (False, True):
            snapshot = pb.compile_policy_bundle(value, validate_schema=check_schema)
            self.assertEqual(snapshot.raw, original_document)
        self.assertEqual(raw, original_raw)
        self.assertEqual(value, original_document)

    def test_absent_renewal_preserves_legacy_bytes_expiry_and_exact_headers(self):
        value = basic_document(enabled=False)
        expected = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        snapshot = pb.compile_policy_bundle(value, validate_schema=True)
        self.assertEqual(pb.policy_signature_bytes(value), expected)
        self.assertEqual(snapshot.hash, "sha256:" + hashlib.sha256(expected).hexdigest())
        self.assertEqual(snapshot.raw, value)
        raw = basic_authorization(enabled=False)
        raw.pop("expiresAtEpochMs")
        raw["tokenId"] = "legacy-token-id"
        policy = pb.ProxyAuthorizationPolicy.from_raw(raw)
        self.assertTrue(policy.matches(CLIENT, "  Bearer " + TOKEN + "  "))
        self.assertFalse(policy.matches(CLIENT, "Bearer " + OLD_TOKEN))
        self.assertFalse(policy.matches(CLIENT, basic()))
        raw["expiresAtEpochMs"] = MAX_EXPIRY + 1
        self.assertIsNotNone(pb.ProxyAuthorizationPolicy.from_raw(raw))
        legacy = pb.ProxyAuthorizationPolicy.from_raw(basic(token=OLD_TOKEN))
        self.assertTrue(legacy.matches(None, basic(token=OLD_TOKEN)))
        self.assertFalse(legacy.matches(None, basic(token=OLD_TOKEN, scheme="basic")))

    def test_static_overlap_considers_every_slot_in_both_operand_orders(self):
        paths = (("tokenSha256",), ("managedRenewal", "previousToken", "tokenSha256"))
        for left_path in paths:
            for right_path in paths:
                left = authorization()
                right = authorization()
                right["tokenId"] = right["basicTransport"]["username"] = OTHER_USERNAME
                right["managedRenewal"]["enrollmentId"] = OTHER_ENROLLMENT
                right["tokenSha256"] = verifier(OTHER_TOKEN)
                right["managedRenewal"]["previousToken"]["tokenSha256"] = verifier(OTHER_OLD_TOKEN)
                common = verifier(TOKEN if len(left_path) == 1 else OLD_TOKEN)
                right = replace(right, right_path, common)
                policies = tuple(pb.ProxyAuthorizationPolicy.from_raw(raw) for raw in (left, right))
                with self.subTest(left_slot=left_path, right_slot=right_path):
                    for when in (NOW, GRANT_EXPIRY / 1000 + 1):
                        with patch.object(pb.time, "time", return_value=when):
                            self.assertTrue(pb._proxy_authorization_policies_overlap(*policies))
                            self.assertTrue(pb._proxy_authorization_policies_overlap(*reversed(policies)))
        left = pb.ProxyAuthorizationPolicy.from_raw(authorization())
        right_raw = replace(authorization(), ("tokenSha256",), verifier(OTHER_TOKEN))
        right_raw["managedRenewal"]["previousToken"]["tokenSha256"] = verifier(OTHER_OLD_TOKEN)
        right = pb.ProxyAuthorizationPolicy.from_raw(right_raw)
        self.assertFalse(pb._proxy_authorization_policies_overlap(left, right))
        self.assertFalse(pb._proxy_authorization_policies_overlap(right, left))

    def test_compiler_rejects_current_previous_and_previous_previous_collisions_even_expired(self):
        for first_token in (TOKEN, OLD_TOKEN):
            for second_slot in ("current", "previous"):
                value = document()
                second = authorization()
                second["tokenId"] = second["basicTransport"]["username"] = OTHER_USERNAME
                second["managedRenewal"]["enrollmentId"] = OTHER_ENROLLMENT
                second["tokenSha256"] = verifier(first_token if second_slot == "current" else OTHER_TOKEN)
                second["managedRenewal"]["previousToken"]["tokenSha256"] = verifier(first_token if second_slot == "previous" else OTHER_OLD_TOKEN)
                value["principals"].append({"id": "agent:second", "proxyAuthorization": second})
                for when in (NOW, GRANT_EXPIRY / 1000 + 1):
                    with patch.object(pb.time, "time", return_value=when):
                        for check_schema in (False, True):
                            with self.subTest(first_token=first_token, second_slot=second_slot, clock=when, schema=check_schema):
                                with self.assertRaisesRegex(pb.PolicyBundleError, "identity selector sets overlap"):
                                    pb.compile_policy_bundle(value, validate_schema=check_schema)

    def test_distinct_networks_still_disambiguate_overlapping_verifiers(self):
        value = document()
        second = basic_authorization(enabled=False)
        second["tokenSha256"] = verifier(OLD_TOKEN)
        second["sourceCidrs"] = ["198.51.100.0/24"]
        value["principals"].append({"id": "agent:second", "proxyAuthorization": second})
        for check_schema in (False, True):
            self.assertIsNotNone(pb.compile_policy_bundle(value, validate_schema=check_schema))
        second["sourceCidrs"] = ["192.0.2.0/25"]
        for check_schema in (False, True):
            with self.assertRaisesRegex(pb.PolicyBundleError, "identity selector sets overlap"):
                pb.compile_policy_bundle(value, validate_schema=check_schema)

    def test_previous_verifier_joins_legacy_exact_headers_with_basic_opt_in(self):
        for enabled in (False, True):
            managed = pb.ProxyAuthorizationPolicy.from_raw(authorization(enabled=enabled))
            for header in ("Bearer " + OLD_TOKEN, basic(token=OLD_TOKEN)):
                accepted = enabled or header.startswith("Bearer ")
                legacy = pb.ProxyAuthorizationPolicy.from_raw(header)
                self.assertEqual(pb._proxy_authorization_accepts_exact(managed, header), accepted)
                self.assertEqual(pb._proxy_authorization_policies_overlap(managed, legacy), accepted)
                self.assertEqual(pb._proxy_authorization_policies_overlap(legacy, managed), accepted)
                value = document(authorization(enabled=enabled))
                value["principals"].append({"id": "agent:legacy", "sourceCidrs": ["192.0.2.0/24"], "proxyAuthorization": header})
                for check_schema in (False, True):
                    if accepted:
                        with self.assertRaisesRegex(pb.PolicyBundleError, "identity selector sets overlap"):
                            pb.compile_policy_bundle(value, validate_schema=check_schema)
                    else:
                        self.assertIsNotNone(pb.compile_policy_bundle(value, validate_schema=check_schema))

    def test_required_exact_previous_header_uses_real_selector_join(self):
        for header in ("Bearer " + OLD_TOKEN, basic(token=OLD_TOKEN)):
            value = document()
            value["principals"][0]["requiredHeaders"] = {"Proxy-Authorization": header}
            for check_schema in (False, True):
                snapshot = pb.compile_policy_bundle(value, validate_schema=check_schema)
                self.assertIsNotNone(snapshot.identify_principal(CLIENT, {"Proxy-Authorization": header}))
                self.assertIsNone(snapshot.identify_principal(CLIENT, {"Proxy-Authorization": "Bearer " + TOKEN}))
            value["principals"].append({"id": "agent:legacy", "sourceCidrs": ["192.0.2.0/24"], "proxyAuthorization": header})
            with self.assertRaisesRegex(pb.PolicyBundleError, "identity selector sets overlap"):
                pb.compile_policy_bundle(value)
        value = document()
        value["principals"][0]["requiredHeaders"] = {"Proxy-Authorization": "Bearer " + OTHER_TOKEN}
        with self.assertRaises(pb.PolicyBundleError):
            pb.compile_policy_bundle(value)

    def test_duplicate_physical_old_new_headers_cannot_select_identity(self):
        snapshot = pb.compile_policy_bundle(document(), validate_schema=True)
        for old_header in ("Bearer " + OLD_TOKEN, basic(token=OLD_TOKEN)):
            headers = SimpleNamespace(fields=[
                (b"Proxy-Authorization", old_header.encode("ascii")),
                (b"proxy-authorization", ("Bearer " + TOKEN).encode("ascii")),
            ])
            self.assertIsNone(snapshot.identify_principal(CLIENT, headers))

    def test_invalid_marker_errors_do_not_echo_supplied_values(self):
        sentinel = "synthetic-renewal-redaction-sentinel"
        for path in (("managedRenewal", "schema"),
                ("managedRenewal", "enrollmentId"),
                ("managedRenewal", "previousToken", "tokenSha256")):
            raw = replace(authorization(), path, sentinel)
            with self.assertRaises(pb.PolicyBundleError) as error:
                pb.ProxyAuthorizationPolicy.from_raw(raw)
            self.assertNotIn(sentinel, str(error.exception))


if __name__ == "__main__":
    unittest.main()
