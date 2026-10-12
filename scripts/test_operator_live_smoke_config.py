#!/usr/bin/env python3
"""Offline configuration/request controls, not live smoke or TLS acceptance.

All catalog documents and credentials are synthetic. Real validation methods
run with in-memory responses; the actual request encoder stops at a mocked send
boundary. No sockets, DNS, token reads, filesystem writes or provider requests.
"""
from copy import deepcopy
from io import StringIO
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import check_operator_live_smoke as smoke

FIXTURE = "https://demo-upstream:8443"
FOUR = [FIXTURE, "https://api.github.com", "https://registry.npmjs.org", "https://gmail.googleapis.com"]
PIN = "sha256:" + "a" * 64


def document(origins=None):
    return {"schema": "serverware.operatorCatalog/v1", "mode": "operator-development",
        "productionReady": False, "hardwareVerified": False,
        "allowed_upstreams": [FIXTURE] if origins is None else deepcopy(origins),
        "revision": 7, "credentials": [], "applications": [], "access_rules": [],
        "policy": {"policy_hash": PIN, "sequence": 3}}


def checker(raw=None, *, omitted=False):
    args = SimpleNamespace() if omitted else SimpleNamespace(expected_upstreams=raw)
    # Only skip endpoint construction. Catalog and roster validation are actual.
    with patch.object(smoke.OperatorCatalogCheck, "__init__", return_value=None):
        return smoke.LiveSmoke(args)


class SendBoundary(BaseException):
    pass


class LiveSmokeConfigurationTests(unittest.TestCase):
    def test_default_remains_synthetic_only_and_explicit_four_are_exact(self):
        self.assertEqual(smoke.parse_expected_upstreams(None), [FIXTURE])
        self.assertEqual(smoke.parse_expected_upstreams(json.dumps([FIXTURE])), [FIXTURE])
        self.assertEqual(smoke.parse_expected_upstreams(json.dumps(FOUR)), FOUR)
        self.assertEqual(checker(omitted=True).expected_upstreams, [FIXTURE])
        self.assertEqual(checker().expected_upstreams, [FIXTURE])
        self.assertEqual(checker(json.dumps(FOUR)).expected_upstreams, FOUR)
        first = smoke.parse_expected_upstreams(None)
        first.append("https://not-the-default.example.com")
        self.assertEqual(smoke.parse_expected_upstreams(None), [FIXTURE])

    def test_malformed_duplicate_unbounded_and_noncanonical_rosters_refuse(self):
        malformed = ["", "[", "null", "true", "{}", '"https://demo-upstream:8443"',
            "[NaN]", "[Infinity]", "[]", json.dumps([FOUR[1]]), json.dumps(FOUR + [FOUR[1]]),
            json.dumps([FIXTURE, None]), json.dumps([FIXTURE, True]), json.dumps([FIXTURE, {}]),
            json.dumps([FIXTURE] + [f"https://host{number}.example.com" for number in range(16)]),
            " " * 32769, b"[]", [], 1, True]
        aliases = ["http://api.github.com", "HTTPS://api.github.com", "https://API.github.com",
            "https://api.github.com/", "https://api.github.com:443", "https://api.github.com:8443",
            "https://api.github.com/path", "https://api.github.com?", "https://api.github.com#",
            "https://api.github.com?x=1", "https://api.github.com#fragment",
            "https://user:pass@api.github.com", "https://api.github.com.",
            "https://127.0.0.1", "https://[::1]", "https://", "api.github.com",
            " https://api.github.com", "https://api.github.com\n", "https://api.github.com\\evil",
            "https://demo-upstream", "https://demo-upstream:8443/"]
        malformed.extend(json.dumps([FIXTURE, value]) for value in aliases)
        for raw in malformed:
            with self.subTest(raw=repr(raw)), self.assertRaises(smoke.CheckFailure):
                smoke.parse_expected_upstreams(raw)
        maximum = [FIXTURE] + [f"https://host{number}.example.com" for number in range(15)]
        self.assertEqual(smoke.parse_expected_upstreams(json.dumps(maximum)), maximum)

    def test_catalog_requires_exact_selected_roster_and_preserves_previous_snapshot_on_refusal(self):
        for selection in (None, json.dumps(FOUR)):
            check = checker(selection)
            accepted = document([FIXTURE] if selection is None else FOUR)
            check.control_json = Mock(return_value=accepted)
            self.assertIs(check.catalog(), accepted)
            self.assertIs(check.snapshot, accepted)
            check.control_json.assert_called_once_with("/api/operator-demo/catalog", authenticated=True)
            mismatches = ([], list(reversed(FOUR)), FOUR + ["https://other.example.com"],
                FOUR + [FOUR[-1]], FOUR[:-1], None, "not-a-list")
            if selection is None:
                mismatches += (FOUR,)
            else:
                mismatches += ([FIXTURE],)
            for origins in mismatches:
                altered = document()
                altered["allowed_upstreams"] = origins
                check.control_json.return_value = altered
                with self.subTest(selection=selection, origins=origins), self.assertRaises(smoke.CheckFailure):
                    check.catalog()
                self.assertIs(check.snapshot, accepted)

    def test_existing_catalog_profile_revision_collection_and_policy_guards_remain(self):
        check = checker(json.dumps(FOUR))
        accepted = document(FOUR)
        check.control_json = Mock(return_value=accepted)
        check.catalog()
        changes = [(key, value) for key, value in (
            ("schema", "other"), ("mode", "production"), ("productionReady", True),
            ("productionReady", 0), ("hardwareVerified", True), ("hardwareVerified", 0),
            ("revision", True), ("revision", 0), ("revision", "7"),
            ("credentials", {}), ("applications", None), ("access_rules", "[]"),
            ("policy", {"policy_hash": "sha256:" + "A" * 64, "sequence": 3}),
            ("policy", {"policy_hash": PIN, "sequence": True}),
            ("policy", {"policy_hash": PIN, "sequence": 0}))]
        for key, value in changes:
            check.control_json.return_value = {**accepted, key: value}
            with self.subTest(key=key, value=value), self.assertRaises(smoke.CheckFailure):
                check.catalog()
            self.assertIs(check.snapshot, accepted)
        # The original isolated checker is not widened by the LiveSmoke override.
        ordinary = smoke.OperatorCatalogCheck.__new__(smoke.OperatorCatalogCheck)
        ordinary.control_json = Mock(return_value=document(FOUR))
        with self.assertRaises(smoke.CheckFailure):
            ordinary.catalog()
        ordinary.control_json.return_value = document()
        self.assertEqual(ordinary.catalog(), document())
        for method in ("mutate", "finalize_mutation", "warm_cas_snapshot"):
            self.assertIs(getattr(smoke.LiveSmoke, method), getattr(smoke.OperatorCatalogCheck, method))

    def test_invalid_selection_refuses_before_constructor_claim_or_network(self):
        for raw in ("[]", json.dumps([FOUR[1]]), json.dumps(FOUR + [FOUR[0]]), "not-json"):
            args = SimpleNamespace(execute=True, timeout_seconds=120, expected_binary_sha256=PIN,
                expected_upstreams=raw, run_claim_file=Path("/not-read/.operator-live-smoke.claim"))
            with self.subTest(raw=raw), patch.object(smoke, "LiveSmoke") as constructor, \
                    patch.object(smoke, "private_output") as output, patch.object(smoke, "token_file") as token:
                result = smoke.run_checks(args)
                self.assertIs(result["ok"], False)
                constructor.assert_not_called()
                output.assert_not_called()
                token.assert_not_called()
            with patch.object(smoke.OperatorCatalogCheck, "__init__") as base:
                with self.assertRaises(smoke.CheckFailure):
                    smoke.LiveSmoke(args)
                base.assert_not_called()

    def test_cli_forwards_explicit_roster_and_default_without_side_effects(self):
        argv = ["check_operator_live_smoke.py", "--execute", "--admin-token-file", "/not-read/admin",
            "--ca-file", "/not-read/ca", "--upstream-ca-file", "/not-read/upstream-ca",
            "--run-claim-file", "/not-read/.operator-live-smoke.claim", "--expected-binary-sha256", PIN]
        for raw in (None, json.dumps(FOUR)):
            extra = [] if raw is None else ["--expected-upstreams", raw]
            with self.subTest(raw=raw), patch.object(sys, "argv", argv + extra), \
                    patch.object(smoke, "run_checks", return_value={"ok": True}) as run, \
                    patch.object(smoke.signal, "signal"), patch.object(smoke.signal, "setitimer"), \
                    patch.object(sys, "stdout", new=StringIO()):
                self.assertEqual(smoke.main(), 0)
                self.assertEqual(run.call_args.args[0].expected_upstreams, raw)
                self.assertEqual(run.call_args.args[0].expected_binary_sha256, PIN)

    def test_explicit_provider_roster_never_changes_fixture_rule_or_encoded_request(self):
        check = checker(json.dumps(FOUR))
        check.run_id = "synthetic-config-control"
        check.credential, check.client_token = "synthetic-secret-not-real", "synthetic-token-not-real"
        check.ca, check.timeout = object(), lambda: 1.0
        raw = Mock()
        check.tunnel = Mock(return_value=raw)
        sent = []

        class InterceptedTLS:
            def __init__(self, observed_raw, _ca, _timeout):
                if observed_raw is not raw:
                    raise AssertionError("unexpected transport")
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                return False
            def sendall(self, payload):
                sent.append(payload)
                raise SendBoundary

        for dummy in (None, smoke.DUMMY, smoke.DUMMY + "_WRONG"):
            with self.subTest(dummy=dummy), patch.object(smoke, "TunnelTLS", InterceptedTLS), \
                    patch.object(smoke.http.client, "HTTPResponse") as response:
                with self.assertRaises(SendBoundary):
                    check.dispatch(dummy)
                response.assert_not_called()
            headers, body = sent[-1].split(b"\r\n\r\n", 1)
            lines = headers.decode("ascii").split("\r\n")
            self.assertTrue(lines[0].startswith("POST /echo?expectedAuthorizationSha256=sha256%3A"))
            self.assertTrue(lines[0].endswith(" HTTP/1.1"))
            self.assertIn("Host: demo-upstream:8443", lines)
            self.assertEqual(body, b'{"live_smoke":true,"nested":{"kept":"synthetic"}}')
            self.assertEqual([line for line in lines if line.startswith("Authorization:")],
                [] if dummy is None else ["Authorization: " + dummy])
            for provider in FOUR[1:]:
                self.assertNotIn(provider.encode("ascii"), sent[-1])
            self.assertNotIn(check.client_token.encode("ascii"), sent[-1])
        self.assertEqual(len(sent), 3)
        self.assertEqual(raw.close.call_count, 3)
        self.assertEqual(check.tunnel.call_count, 3)
        values = smoke.access_rule_values("synthetic-rule", "synthetic-app", "synthetic-credential")
        self.assertEqual(values["upstream_url"], "https://demo-upstream:8443/echo")
        self.assertEqual(values["methods"], ["POST"])
        self.assertEqual(values["response_mode"], "unfiltered_json_or_empty_v2")


if __name__ == "__main__":
    def deny_network(event, _args):
        if event.startswith("socket."):
            raise AssertionError("offline smoke configuration tests forbid network")
    sys.addaudithook(deny_network)
    unittest.main(verbosity=2)
