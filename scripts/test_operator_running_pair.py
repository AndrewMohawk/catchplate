#!/usr/bin/env python3
"""Pure read-only pair guard tests; no sockets, containers, tokens or runtime.

The actual boundary runs, but its parent transport is mocked. This proves only
request admission and delegation, not the state of any running app/gate pair.
"""
import copy
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

# Support direct script and unittest-module invocation without a lasting path
# change. Importing these checkers does not run their guarded CLI entry points.
with patch.object(sys, "path", [str(Path(__file__).resolve().parents[1]), *sys.path]):
    from scripts import check_operator_running_pair as checker
    from scripts.check_operator_demo import CheckFailure


CATALOG = "/api/operator-demo/catalog"
HEALTH = "/healthz"


class ReadonlyPairTests(unittest.TestCase):
    def setUp(self):
        # The normal constructor resolves endpoints and opens CA files. Neither
        # is needed to exercise this admission boundary with inert identities.
        self.check = checker.ReadonlyPair.__new__(checker.ReadonlyPair)
        self.check.control = SimpleNamespace(host="control.example.invalid", port=3000)
        self.check.management = SimpleNamespace(host="management.example.invalid", port=9091)
        self.result = (200, {"synthetic": True})
        parent = patch.object(checker.OperatorCatalogCheck, "json_request", autospec=True,
            return_value=self.result)
        self.addCleanup(parent.stop)
        self.parent = parent.start()

    def assert_refused(self, endpoint, path, **kwargs):
        self.parent.reset_mock()
        with self.assertRaises(CheckFailure):
            self.check.json_request(endpoint, path, **kwargs)
        self.parent.assert_not_called()

    def test_only_exact_catalog_and_health_gets_delegate_unchanged(self):
        context = object()
        options = ({}, {"method": "GET", "payload": None, "creation": False,
            "authenticated": True, "context": context})
        for endpoint, path in ((self.check.control, CATALOG), (self.check.management, HEALTH)):
            for kwargs in options:
                with self.subTest(path=path, explicit=bool(kwargs)):
                    self.parent.reset_mock()
                    self.assertIs(self.check.json_request(endpoint, path, **kwargs), self.result)
                    self.parent.assert_called_once_with(self.check, endpoint, path, **kwargs)

    def test_non_get_methods_refused_before_transport(self):
        for method in ("POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT", "get", "", None):
            for endpoint, path in ((self.check.control, CATALOG), (self.check.management, HEALTH)):
                with self.subTest(method=method, path=path):
                    self.assert_refused(endpoint, path, method=method)

    def test_every_non_null_payload_refused_including_falsy_values(self):
        for payload in ({}, [], "", b"", False, 0, {"synthetic": True}):
            for endpoint, path in ((self.check.control, CATALOG), (self.check.management, HEALTH)):
                with self.subTest(payload=repr(payload), path=path):
                    self.assert_refused(endpoint, path, payload=payload)

    def test_creation_mode_refused_before_transport(self):
        for creation in (True, 1, "true", {"synthetic": True}):
            for endpoint, path in ((self.check.control, CATALOG), (self.check.management, HEALTH)):
                with self.subTest(creation=repr(creation), path=path):
                    self.assert_refused(endpoint, path, creation=creation)

    def test_endpoint_identity_and_endpoint_path_pair_are_required(self):
        for endpoint, path in ((self.check.control, HEALTH), (self.check.management, CATALOG),
                (object(), CATALOG), (None, HEALTH),
                (SimpleNamespace(**vars(self.check.control)), CATALOG),
                (SimpleNamespace(**vars(self.check.management)), HEALTH)):
            with self.subTest(path=path, same_control=endpoint is self.check.control,
                    same_management=endpoint is self.check.management):
                self.assert_refused(endpoint, path)

    def test_unrelated_or_non_exact_paths_refused_before_transport(self):
        paths = ("/", "/api/operator-demo/status", "/api/operator-demo/credentials",
            "/api/operator-demo/proxy/ca", "/api/operator-demo/proxy/upstreams",
            "/api/operator-demo/notifications/test", "/echo", "/_fixture/observations",
            CATALOG + "/", CATALOG + "?", CATALOG + "?synthetic=1", CATALOG + "#fragment",
            CATALOG.upper(), "/api/operator-demo/%63atalog", "/healthz/", "/healthz?",
            "https://provider.example.invalid/healthz", "", None)
        for endpoint in (self.check.control, self.check.management):
            for path in paths:
                with self.subTest(path=path, control=endpoint is self.check.control):
                    self.assert_refused(endpoint, path)

    def test_parent_failure_propagates_without_retry_or_fallback(self):
        failure = RuntimeError("synthetic parent transport refusal")
        self.parent.side_effect = failure
        with self.assertRaises(RuntimeError) as raised:
            self.check.json_request(self.check.control, CATALOG)
        self.assertIs(raised.exception, failure)
        self.parent.assert_called_once_with(self.check, self.check.control, CATALOG)

    def catalog_fixture(self):
        origins = ["https://demo-upstream:8443"] + [f"https://provider-{index}.example.com" for index in range(15)]
        snapshot = {"schema": "serverware.operatorCatalog/v1", "mode": "operator-development",
            "productionReady": False, "hardwareVerified": False, "allowed_upstreams": origins,
            "revision": 17, "policy": {"policy_hash": "sha256:" + "a" * 64, "sequence": 12},
            **{key: [] for key in checker.COLLECTIONS}}
        env = patch.dict(os.environ, {"SERVERWARE_OPERATOR_DEMO_UPSTREAMS": json.dumps(origins),
            "SERVERWARE_OPERATOR_DEMO_FIXTURE_CIDRS": '["172.16.249.18/32"]'})
        env.start()
        self.addCleanup(env.stop)
        return snapshot

    def test_catalog_accepts_exact_configured_sixteen_origins_without_transport(self):
        snapshot = self.catalog_fixture()
        with patch.object(self.check, "control_json", return_value=snapshot) as transport:
            self.assertIs(self.check.catalog(), snapshot)
            self.assertIs(self.check.snapshot, snapshot)
            transport.assert_called_once_with(CATALOG, authenticated=True)
        self.parent.assert_not_called()

    def test_catalog_rejects_missing_extra_or_reordered_origins(self):
        snapshot = self.catalog_fixture()
        for origins in (snapshot["allowed_upstreams"][:-1], snapshot["allowed_upstreams"] +
                ["https://other.example.com"], list(reversed(snapshot["allowed_upstreams"]))):
            with self.subTest(origins=origins), patch.object(self.check, "control_json",
                    return_value={**snapshot, "allowed_upstreams": origins}):
                with self.assertRaises(CheckFailure):
                    self.check.catalog()
        self.parent.assert_not_called()

    def test_catalog_retains_schema_flags_revision_policy_and_collection_guards(self):
        snapshot = self.catalog_fixture()
        changes = (("schema", "other"), ("mode", "other"), ("productionReady", True),
            ("hardwareVerified", True), ("revision", True), ("revision", 0),
            ("policy", {"policy_hash": "invalid", "sequence": 12}),
            ("policy", {"policy_hash": "sha256:" + "a" * 64, "sequence": True}),
            ("policy", {"policy_hash": "sha256:" + "a" * 64, "sequence": 0}),
            *((key, {}) for key in checker.COLLECTIONS))
        for key, value in changes:
            changed = copy.deepcopy(snapshot)
            changed[key] = value
            with self.subTest(key=key, value=value), patch.object(self.check, "control_json", return_value=changed):
                with self.assertRaises(CheckFailure):
                    self.check.catalog()
        self.parent.assert_not_called()

    def test_catalog_invalid_configured_origin_is_refused_before_transport(self):
        snapshot = self.catalog_fixture()
        with patch.dict(os.environ, {"SERVERWARE_OPERATOR_DEMO_UPSTREAMS": '["http://provider.example.com"]'}), \
                patch.object(self.check, "control_json", return_value=snapshot) as transport:
            with self.assertRaises(ValueError):
                self.check.catalog()
            transport.assert_not_called()
        self.parent.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
