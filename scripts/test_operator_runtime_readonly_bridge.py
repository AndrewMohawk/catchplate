"""Pure route/screening checks; never reads a token or contacts an app/socket."""
from __future__ import annotations

import json
import os
import unittest
from unittest.mock import patch

from scripts import operator_runtime_readonly_bridge as bridge


class RuntimeReadonlyBridgeTests(unittest.TestCase):
    def test_original_four_get_routes_stay_available_without_managed_flag(self):
        expected = {"/", "/api/operator-demo/catalog", "/api/operator-demo/notifications",
            "/api/operator-demo/proxy/upstreams"}
        self.assertEqual(bridge.PATHS, expected)
        with patch.dict(os.environ, {}, clear=True):
            for path in expected:
                self.assertEqual(bridge.get_path({"op": "get", "path": path}), path)
            with self.assertRaises(ValueError):
                bridge.get_path({"op": "get", "path": bridge.GOOGLE_CONFIGURATION})

    def test_exact_opt_in_allows_only_discovery_on_enabled_managed_deployment(self):
        with patch.dict(os.environ, {"SERVERWARE_OPERATOR_MANAGED_GOOGLE_ENABLED": "1"}, clear=True):
            for path in bridge.PATHS | {bridge.GOOGLE_CONFIGURATION}:
                self.assertEqual(bridge.get_path({"op": "get", "path": path,
                    "managed_google_unconfigured": True}), path)
            # The flag is required on the command even when deployment mode is on.
            with self.assertRaises(ValueError):
                bridge.get_path({"op": "get", "path": bridge.GOOGLE_CONFIGURATION})

    def test_missing_or_noncanonical_deployment_and_command_flags_refuse(self):
        command = {"op": "get", "path": bridge.GOOGLE_CONFIGURATION, "managed_google_unconfigured": True}
        for flag in (None, "0", "true", "01", "1 ", ""):
            with self.subTest(flag=flag), patch.dict(os.environ, {} if flag is None else
                    {"SERVERWARE_OPERATOR_MANAGED_GOOGLE_ENABLED": flag}, clear=True):
                with self.assertRaises(ValueError):
                    bridge.get_path(command)
        with patch.dict(os.environ, {"SERVERWARE_OPERATOR_MANAGED_GOOGLE_ENABLED": "1"}, clear=True):
            for flag in (False, 0, 1, "1", "true", None, []):
                with self.subTest(flag=flag), self.assertRaises(ValueError):
                    bridge.get_path({**command, "managed_google_unconfigured": flag})

    def test_unknown_paths_operations_fields_and_types_refuse_before_secret_or_socket(self):
        valid = {"op": "get", "path": bridge.GOOGLE_CONFIGURATION, "managed_google_unconfigured": True}
        paths = [bridge.GOOGLE_CONFIGURATION + suffix for suffix in
            ("/", "/cancel", "/11111111-1111-4111-8111-111111111111", "?x=1", "#fragment")]
        paths += ["/api/operator-demo/oauth/google/start", "/api/oauth/start", "/ca.pem",
            "https://serverware-demo.example.com" + bridge.GOOGLE_CONFIGURATION,
            "/api/operator-demo/oauth/google/configuration/%76%32", "//api/operator-demo/catalog", "", None, []]
        commands = [{**valid, "path": path} for path in paths]
        commands += [{**valid, "op": op} for op in ("post", "POST", "source", True, None)]
        commands += [{**valid, "headers": {}}, {**valid, "body": ""}, {**valid, "method": "GET"},
            {**valid, "timeout": 1}, {"op": "get"}, [], None]
        with patch.dict(os.environ, {"SERVERWARE_OPERATOR_MANAGED_GOOGLE_ENABLED": "1"}, clear=True), \
                patch.object(bridge.os, "open", side_effect=AssertionError("token access forbidden")) as opened, \
                patch.object(bridge.http.client, "HTTPConnection", side_effect=AssertionError("socket access forbidden")) as connected:
            for command in commands:
                with self.subTest(command=command), self.assertRaises(ValueError):
                    bridge.get(command)
            opened.assert_not_called()
            connected.assert_not_called()

    def test_public_discovery_screening_keeps_private_field_and_token_guards(self):
        token = "TEST-ONLY-ADMIN-CANARY-DO-NOT-EXPORT-123456789"
        public = {"schema": "serverware.operatorGoogleConfiguration/v2", "state": "unconfigured",
            "operation": None, "revision": 13, "readiness": {"pair_ready": True, "consent_ready": False},
            "redirect_uri": bridge.PUBLIC + "/api/oauth/callback/google"}
        bridge.public_json(json.dumps(public).encode(), token)
        for key in ("client_secret", "access_token", "refresh-token", "private_key", "authorization", "cookie"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                bridge.public_json(json.dumps({**public, "nested": {key: "PRIVATE-CANARY"}}).encode(), token)
        for value in (token, "-----BEGIN PRIVATE KEY-----", "synthetic-operator-" + "a" * 32,
                      "oauth-sim-access-123-material"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                bridge.public_json(json.dumps({**public, "nested": [value]}).encode(), token)


if __name__ == "__main__":
    unittest.main(verbosity=2)
