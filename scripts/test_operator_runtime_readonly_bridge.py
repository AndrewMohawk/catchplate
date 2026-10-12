"""Pure route/screening and synthetic HTTP checks; no token file or real socket."""
from __future__ import annotations

import base64
import json
import os
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from scripts import operator_runtime_readonly_bridge as bridge


class RuntimeReadonlyBridgeTests(unittest.TestCase):
    def x_command(self):
        return {"op": "get", "path": bridge.X_CONFIGURATION, "x_configuration_disabled": True}

    def fake_get(self, *, command=None, status=404, headers=None, body=None):
        """Exercise actual get() with only private-file and HTTP edges replaced."""
        token = b"TEST-ONLY-ADMIN-CANARY-DO-NOT-EXPORT-123456789"
        if body is None:
            body = json.dumps({"detail": bridge.X_DISABLED_DETAIL}, separators=(",", ":")).encode()
        if headers is None:
            headers = [("Content-Type", "application/json"), ("Cache-Control", "no-store"),
                ("Content-Length", str(len(body)))]
        response = Mock(status=status)
        response.getheaders.return_value = headers
        response.read.return_value = body
        connection = Mock()
        connection.getresponse.return_value = response
        with patch.object(bridge.os, "open", return_value=991) as opened, \
                patch.object(bridge.os, "fstat", return_value=SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_size=len(token))), \
                patch.object(bridge.os, "read", return_value=token), patch.object(bridge.os, "close") as closed, \
                patch.object(bridge.http.client, "HTTPConnection", return_value=connection) as connected:
            try:
                result = bridge.get(self.x_command() if command is None else command)
            finally:
                closed.assert_called_once_with(991)
                connection.close.assert_called_once_with()
        opened.assert_called_once_with(bridge.TOKEN_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        connected.assert_called_once_with("127.0.0.1", 3000, timeout=5)
        return result, connection, response

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

    def test_x_disabled_route_requires_exact_command_and_actual_off_selection(self):
        for flag in (None, "0"):
            with patch.dict(os.environ, {} if flag is None else {"SERVERWARE_OPERATOR_MANAGED_X_ENABLED": flag}, clear=True):
                self.assertEqual(bridge.get_path(self.x_command()), bridge.X_CONFIGURATION)
                with self.assertRaises(ValueError):
                    bridge.get_path({"op": "get", "path": bridge.X_CONFIGURATION})
        for flag in ("1", "", "false", "00", "0 ", "true"):
            with self.subTest(flag=flag), patch.dict(os.environ,
                    {"SERVERWARE_OPERATOR_MANAGED_X_ENABLED": flag}, clear=True):
                with self.assertRaises(ValueError):
                    bridge.get_path(self.x_command())

    def test_x_flag_does_not_expand_other_routes_or_commands_before_io(self):
        commands = [{**self.x_command(), "x_configuration_disabled": value}
            for value in (False, None, 1, 0, "true", [])]
        commands += [{**self.x_command(), "path": path} for path in bridge.PATHS | {bridge.GOOGLE_CONFIGURATION,
            bridge.X_CONFIGURATION + "/", bridge.X_CONFIGURATION + "?x=1", bridge.X_CONFIGURATION + "/save",
            "/api/operator-demo/oauth/x/configuration/%76%31"}]
        commands += [{**self.x_command(), "op": "post"}, {**self.x_command(), "body": ""},
            {**self.x_command(), "managed_google_unconfigured": True}]
        with patch.dict(os.environ, {"SERVERWARE_OPERATOR_MANAGED_GOOGLE_ENABLED": "1"}, clear=True), \
                patch.object(bridge.os, "open", side_effect=AssertionError("token access forbidden")) as opened, \
                patch.object(bridge.http.client, "HTTPConnection", side_effect=AssertionError("socket access forbidden")) as connected:
            for command in commands:
                with self.subTest(command=command), self.assertRaises(ValueError):
                    bridge.get(command)
            opened.assert_not_called()
            connected.assert_not_called()

    def test_x_exact_disabled_404_preserves_normal_headers_and_original_body(self):
        body = b'{ "detail" : "X configuration is not supported by this deployment" }'
        with patch.dict(os.environ, {}, clear=True):
            result, connection, response = self.fake_get(body=body)
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], 404)
        self.assertEqual(base64.b64decode(result["body_base64"]), body)
        self.assertIn(("Cache-Control", "no-store"), result["headers"])
        response.read.assert_called_once_with(32769)
        args, kwargs = connection.request.call_args
        self.assertEqual(args, ("GET", bridge.X_CONFIGURATION))
        self.assertEqual(set(kwargs), {"headers"})
        self.assertEqual(kwargs["headers"]["Accept"], "application/json")
        self.assertEqual(kwargs["headers"]["Accept-Encoding"], "identity")
        self.assertNotIn("TEST-ONLY-ADMIN", json.dumps(result))

    def test_x_other_status_or_error_shape_never_becomes_accepted_404(self):
        with patch.dict(os.environ, {}, clear=True):
            for status in (200, 401, 403, 500):
                with self.subTest(status=status), self.assertRaises(ValueError):
                    self.fake_get(status=status)
            for body in (b'{"detail":"Not Found"}', b'{"detail":"X configuration is not supported by this deployment","extra":true}',
                    b'{"detail":"private first value","detail":"X configuration is not supported by this deployment"}',
                    b'{"detail":"X configuration is not supported by this deployment","client_secret":"synthetic"}',
                    b'[["detail","X configuration is not supported by this deployment"]]', b'{}', b'not-json', b''):
                with self.subTest(body_size=len(body)), self.assertRaises(ValueError):
                    self.fake_get(body=body)

    def test_x_404_retains_media_no_store_length_header_and_redaction_guards(self):
        baseline = [("Content-Type", "application/json"), ("Cache-Control", "no-store")]
        headers = [[("Content-Type", "application/json")],
            [("Content-Type", "text/plain"), ("Cache-Control", "no-store")],
            baseline + [("Location", "/")], baseline + [("Set-Cookie", "synthetic=1")],
            baseline + [("Content-Encoding", "gzip")], baseline + [("Content-Length", "1")],
            baseline + [("content-type", "application/json")],
            baseline + [("X-Private", "TEST-ONLY-ADMIN-CANARY-DO-NOT-EXPORT-123456789")]]
        with patch.dict(os.environ, {}, clear=True):
            for value in headers:
                with self.subTest(headers=value), self.assertRaises(ValueError):
                    self.fake_get(headers=value)
            for body in (b'x' * 32769,
                    b'{"detail":"TEST-ONLY-ADMIN-CANARY-DO-NOT-EXPORT-123456789"}',
                    b'{"detail":"-----BEGIN PRIVATE KEY-----"}'):
                with self.subTest(size=len(body)), self.assertRaises(ValueError):
                    self.fake_get(body=body)

    def test_existing_json_routes_still_require_200_and_do_not_accept_disabled_body(self):
        with patch.dict(os.environ, {"SERVERWARE_OPERATOR_MANAGED_GOOGLE_ENABLED": "1"}, clear=True):
            for path in (bridge.PATHS - {"/"}) | {bridge.GOOGLE_CONFIGURATION}:
                command = {"op": "get", "path": path, "managed_google_unconfigured": True}
                with self.subTest(path=path):
                    result, _, _ = self.fake_get(command=command, status=200, body=b'{"public":true}')
                    self.assertEqual(result["status"], 200)
                    with self.assertRaises(ValueError):
                        self.fake_get(command=command)


if __name__ == "__main__":
    unittest.main(verbosity=2)
