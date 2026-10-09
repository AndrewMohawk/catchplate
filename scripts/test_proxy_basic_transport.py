#!/usr/bin/env python3
"""Synthetic Python policy/schema checks, not proxy or provider acceptance.

Only the clock is controlled. Real schema, compiler, identity matching and
overlap admission run unchanged; no service, DB, transport or secret is read.
"""
from __future__ import annotations

import base64
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
from serverware.policy_route_authority import prepare_unsigned
from scripts.test_credential_header_replacement import bundle as route_fixture

USERNAME = "12345678-1234-4234-9234-123456789abc"
OTHER_USERNAME = "12345678-1234-4234-9234-123456789abd"
TOKEN = "A" * 41 + "_-"
NOW = 1_700_000_000
EXPIRY = (NOW + 3600) * 1000
MAX_EXPIRY = 9_007_199_254_740_991
CLIENT = "192.0.2.10"


def basic(username=USERNAME, token=TOKEN, *, scheme="Basic"):
    value = (username + ":" + token).encode("utf-8")
    return scheme + " " + base64.b64encode(value).decode("ascii")


def authorization(*, enabled=True):
    value = {"scheme": "Bearer", "tokenId": USERNAME,
        "tokenSha256": "sha256:" + hashlib.sha256(TOKEN.encode("ascii")).hexdigest(),
        "sourceCidrs": ["192.0.2.0/24"], "expiresAtEpochMs": EXPIRY}
    if enabled:
        value["basicTransport"] = {"username": USERNAME}
    return value


def document(*, enabled=True):
    value = route_fixture(replacement=False)
    value["metadata"]["id"] = "serverware-operator-demo"
    value["principals"] = [{"id": "agent:fixture", "proxyAuthorization": authorization(enabled=enabled)}]
    return value


class ProxyBasicTransportTests(unittest.TestCase):
    def setUp(self):
        clock = patch.object(pb.time, "time", return_value=NOW)
        clock.start()
        self.addCleanup(clock.stop)

    def test_basic_and_bearer_identify_the_same_principal(self):
        value = document()
        before = deepcopy(value)
        for check_schema in (False, True):
            snapshot = pb.compile_policy_bundle(value, validate_schema=check_schema)
            for header in (basic(), basic(scheme="bAsIc"), "Bearer " + TOKEN, "bEaReR " + TOKEN):
                principal = snapshot.identify_principal(CLIENT, {"Proxy-Authorization": header})
                self.assertIsNotNone(principal)
                self.assertEqual(principal.id, "agent:fixture")
            policy = snapshot.principals["agent:fixture"].proxy_authorization
            self.assertEqual(policy.basic_username, USERNAME)
            self.assertEqual(policy.scheme, "Bearer")
            self.assertEqual(policy.token_sha256, authorization()["tokenSha256"])
        self.assertEqual(value, before)

    def test_basic_wire_is_exact_and_canonical(self):
        policy = pb.ProxyAuthorizationPolicy.from_raw(authorization())
        good = basic()
        encoded = good[6:]
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        noncanonical = encoded[:-2] + alphabet[alphabet.index(encoded[-2]) + 1] + "="
        self.assertEqual(base64.b64decode(noncanonical), base64.b64decode(encoded))
        invalid = (None, "", "Basic", "Basic " + TOKEN, " " + good, good + " ",
            "Basic  " + encoded, "Basic\t" + encoded, "Basic\n" + encoded,
            "Basic " + encoded.rstrip("="), good + "=", "Basic -" + encoded[1:],
            "Basic _" + encoded[1:], "Basic " + noncanonical,
            "Basic " + encoded[:-1] + "!", good + "\r\n", "\x00" + good,
            "Basic " + "A" * 8192, "Basic " + encoded[:50] + "\t" + encoded[51:])
        for index, header in enumerate(invalid):
            with self.subTest(case=index):
                self.assertFalse(policy.matches(CLIENT, header))
                self.assertFalse(pb._proxy_authorization_accepts_exact(policy, header))

    def test_wrong_username_password_or_decoded_shape_refuses(self):
        policy = pb.ProxyAuthorizationPolicy.from_raw(authorization())
        invalid = (basic(OTHER_USERNAME), basic(USERNAME.upper()), basic(token="B" * 43),
            basic(token=TOKEN[:-1]), basic(token=TOKEN + "A"), basic(token="A" * 42 + ":"),
            basic(token="A" * 42 + "="), basic(token="A" * 42 + "/"),
            basic(token="A" * 42 + "+"), basic(token="A" * 42 + "\x7f"),
            basic(token="A" * 42 + "é"), basic(token="A" * 42 + "\n"),
            "Basic " + base64.b64encode(b"\xff" * 80).decode("ascii"))
        for index, header in enumerate(invalid):
            with self.subTest(case=index):
                self.assertFalse(policy.matches(CLIENT, header))
                self.assertFalse(pb._proxy_authorization_accepts_exact(policy, header))

    def test_expiry_and_cidr_apply_to_both_transports(self):
        policy = pb.ProxyAuthorizationPolicy.from_raw(authorization())
        for header in (basic(), "Bearer " + TOKEN):
            for client in (None, "198.51.100.1", "::1", "not-an-address"):
                self.assertFalse(policy.matches(client, header))
            with patch.object(pb.time, "time", return_value=EXPIRY / 1000):
                self.assertFalse(policy.matches(CLIENT, header))
            with patch.object(pb.time, "time", return_value=(EXPIRY - 1) / 1000):
                self.assertTrue(policy.matches(CLIENT, header))
        expired = document()
        expired["principals"][0]["proxyAuthorization"]["expiresAtEpochMs"] = 1
        snapshot = pb.compile_policy_bundle(expired, validate_schema=True)
        self.assertIsNone(snapshot.identify_principal(CLIENT, {"Proxy-Authorization": basic()}))

    def test_absent_option_preserves_legacy_bearer_and_policy_bytes(self):
        value = document(enabled=False)
        original = deepcopy(value)
        expected = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        snapshot = pb.compile_policy_bundle(value, validate_schema=True)
        self.assertEqual(pb.policy_signature_bytes(value), expected)
        self.assertEqual(snapshot.hash, "sha256:" + hashlib.sha256(expected).hexdigest())
        self.assertEqual(snapshot.raw, original)
        policy = snapshot.principals["agent:fixture"].proxy_authorization
        self.assertIsNone(policy.basic_username)
        self.assertTrue(policy.matches(CLIENT, "  Bearer " + TOKEN + "  "))
        self.assertFalse(policy.matches(CLIENT, basic()))
        no_expiry = authorization(enabled=False)
        no_expiry.pop("expiresAtEpochMs")
        self.assertTrue(pb.ProxyAuthorizationPolicy.from_raw(no_expiry).matches(CLIENT, "Bearer " + TOKEN))
        no_expiry["expiresAtEpochMs"] = MAX_EXPIRY + 1
        self.assertIsNotNone(pb.ProxyAuthorizationPolicy.from_raw(no_expiry))
        changed = document()
        self.assertNotEqual(pb.policy_hash(changed), snapshot.hash)

    def test_legacy_exact_basic_requires_opt_in_for_hashed_identity(self):
        legacy = pb.ProxyAuthorizationPolicy.from_raw(basic())
        opted = pb.ProxyAuthorizationPolicy.from_raw(authorization())
        old = pb.ProxyAuthorizationPolicy.from_raw(authorization(enabled=False))
        self.assertTrue(legacy.matches(None, basic()))
        self.assertFalse(legacy.matches(None, basic(scheme="basic")))
        self.assertTrue(pb._proxy_authorization_policies_overlap(legacy, opted))
        self.assertTrue(pb._proxy_authorization_policies_overlap(opted, legacy))
        self.assertFalse(pb._proxy_authorization_policies_overlap(legacy, old))

    def test_compiler_rejects_new_and_legacy_basic_identity_overlap(self):
        for expired in (False, True):
            value = document()
            if expired:
                value["principals"][0]["proxyAuthorization"]["expiresAtEpochMs"] = 1
            value["principals"].append({"id": "agent:legacy", "sourceCidrs": ["192.0.2.0/24"],
                "proxyAuthorization": basic()})
            for check_schema in (False, True):
                with self.assertRaisesRegex(pb.PolicyBundleError, "identity selector sets overlap"):
                    pb.compile_policy_bundle(value, validate_schema=check_schema)
            value["principals"][1]["sourceCidrs"] = ["198.51.100.0/24"]
            self.assertIsNotNone(pb.compile_policy_bundle(value, validate_schema=True))

    def test_same_hash_still_overlaps_through_bearer(self):
        value = document()
        second = authorization()
        second["tokenId"] = OTHER_USERNAME
        second["basicTransport"]["username"] = OTHER_USERNAME
        value["principals"].append({"id": "agent:second", "proxyAuthorization": second})
        for check_schema in (False, True):
            with self.assertRaisesRegex(pb.PolicyBundleError, "identity selector sets overlap"):
                pb.compile_policy_bundle(value, validate_schema=check_schema)
        value["principals"][1]["proxyAuthorization"] = authorization(enabled=False)
        with self.assertRaisesRegex(pb.PolicyBundleError, "identity selector sets overlap"):
            pb.compile_policy_bundle(value)

    def test_required_exact_basic_selector_uses_the_same_parser(self):
        value = document()
        value["principals"][0]["requiredHeaders"] = {"Proxy-Authorization": basic()}
        self.assertIsNotNone(pb.compile_policy_bundle(value))
        value["principals"][0]["requiredHeaders"]["Proxy-Authorization"] = basic(OTHER_USERNAME)
        with self.assertRaises(pb.PolicyBundleError):
            pb.compile_policy_bundle(value)

    def test_closed_basic_policy_shape_rejected_without_schema_shortcut(self):
        invalid = (None, False, [], "Basic", {}, {"username": USERNAME, "extra": True},
            {"username": None}, {"username": 1}, {"username": USERNAME.upper()},
            {"username": USERNAME + "\n"}, {"username": USERNAME.replace("-", "")})
        for index, basic_option in enumerate(invalid):
            value = document()
            raw = value["principals"][0]["proxyAuthorization"]
            raw["basicTransport"] = basic_option
            with self.subTest(case=index):
                with self.assertRaises(pb.PolicyBundleError):
                    pb.validate_policy_schema(value)
                with self.assertRaises(pb.PolicyBundleError):
                    pb.ProxyAuthorizationPolicy.from_raw(raw)
                for check_schema in (False, True):
                    with self.assertRaises(pb.PolicyBundleError):
                        pb.compile_policy_bundle(value, validate_schema=check_schema)
        raw = authorization()
        raw["unknown"] = "synthetic-redaction-sentinel"
        with self.assertRaises(pb.PolicyBundleError) as error:
            pb.ProxyAuthorizationPolicy.from_raw(raw)
        self.assertNotIn("synthetic-redaction-sentinel", str(error.exception))

    def test_username_join_and_finite_expiry_are_semantic_requirements(self):
        for field, replacement in (("tokenId", OTHER_USERNAME), ("tokenId", None),
                ("expiresAtEpochMs", None), ("expiresAtEpochMs", 0), ("expiresAtEpochMs", -1),
                ("expiresAtEpochMs", True), ("expiresAtEpochMs", 1.0),
                ("expiresAtEpochMs", MAX_EXPIRY + 1)):
            value = document()
            raw = value["principals"][0]["proxyAuthorization"]
            raw[field] = replacement
            with self.subTest(field=field, replacement=replacement):
                with self.assertRaises(pb.PolicyBundleError):
                    pb.ProxyAuthorizationPolicy.from_raw(raw)
                for check_schema in (False, True):
                    with self.assertRaises(pb.PolicyBundleError):
                        pb.compile_policy_bundle(value, validate_schema=check_schema)
        for field in ("tokenId", "expiresAtEpochMs"):
            value = document()
            del value["principals"][0]["proxyAuthorization"][field]
            with self.assertRaises(pb.PolicyBundleError):
                pb.validate_policy_schema(value)
        raw = authorization()
        raw["expiresAtEpochMs"] = MAX_EXPIRY
        self.assertIsNotNone(pb.ProxyAuthorizationPolicy.from_raw(raw))

    def test_only_operator_v1_policy_can_declare_transport(self):
        for option in ({"username": USERNAME}, None):
            for version, name in (("serverware.policy/v1", "another-policy"),
                    ("serverware.policy/v2", "serverware-operator-demo")):
                value = document()
                value["apiVersion"] = version
                value["metadata"]["id"] = name
                value["principals"][0]["proxyAuthorization"]["basicTransport"] = option
                if version == "serverware.policy/v2":
                    value = prepare_unsigned(value, [{"routeId": "route.header-fixture",
                        "operationName": "fixture.read", "operation": "read"}])
                with self.subTest(version=version, name=name, null=option is None):
                    for check_schema in (False, True):
                        if version == "serverware.policy/v2" and option is not None:
                            with self.assertRaisesRegex(pb.PolicyBundleError,
                                    "Basic transport requires the operator v1 policy profile"):
                                pb.compile_policy_bundle(value, validate_schema=check_schema)
                        else:
                            with self.assertRaises(pb.PolicyBundleError):
                                pb.compile_policy_bundle(value, validate_schema=check_schema)
        legacy = document(enabled=False)
        legacy["metadata"]["id"] = "another-policy"
        self.assertIsNotNone(pb.compile_policy_bundle(legacy, validate_schema=True))
        legacy["apiVersion"] = "serverware.policy/v2"
        legacy = prepare_unsigned(legacy, [{"routeId": "route.header-fixture",
            "operationName": "fixture.read", "operation": "read"}])
        self.assertIsNotNone(pb.compile_policy_bundle(legacy, validate_schema=True))

    def test_physical_duplicate_proxy_headers_cannot_select_an_identity(self):
        snapshot = pb.compile_policy_bundle(document())
        headers = SimpleNamespace(fields=[(b"Proxy-Authorization", basic().encode("ascii")),
            (b"proxy-authorization", ("Bearer " + TOKEN).encode("ascii"))])
        self.assertIsNone(snapshot.identify_principal(CLIENT, headers))


if __name__ == "__main__":
    unittest.main()
