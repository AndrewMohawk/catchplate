"""Pure route/screening and synthetic HTTP checks; no token file or real socket."""
from __future__ import annotations

import base64
from copy import deepcopy
import io
import json
import os
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from scripts import operator_runtime_readonly_bridge as bridge


class RuntimeReadonlyBridgeTests(unittest.TestCase):
    def test_public_origin_defaults_old_and_uses_exact_admitted_environment_for_headers(self):
        for configured, expected in ((None, "https://serverware-demo.example.com"),
                ("https://serverware-demo.example.com", "https://serverware-demo.example.com"),
                ("https://serverware.example.com", "https://serverware.example.com")):
            with self.subTest(origin=configured), patch.dict(os.environ, {} if configured is None else
                    {"SERVERWARE_PUBLIC_URL": configured}, clear=True):
                self.assertEqual(bridge.public_origin(), expected)
                result, connection, _ = self.fake_get()
                self.assertTrue(result["ok"])
                args, kwargs = connection.request.call_args
                self.assertEqual(args, ("GET", bridge.X_CONFIGURATION))
                self.assertEqual(kwargs["headers"]["Origin"], expected)
                self.assertEqual(kwargs["headers"]["Host"], expected.removeprefix("https://"))
                self.assertNotIn("TEST-ONLY-ADMIN", json.dumps(result))

    def test_unrecognized_public_origin_refuses_before_token_and_socket_access(self):
        invalid = ("", "http://serverware.example.com", "https://serverware.example.com/",
            "https://serverware.example.com:443", "https://serverware.example.com.evil.invalid",
            "https://user@serverware.example.com", "https://serverware.example.com?x=1",
            " https://serverware.example.com", "https://SERVERWARE.example.com")
        with patch.object(bridge.os, "open") as opened, patch.object(bridge.http.client, "HTTPConnection") as connected:
            for origin in invalid:
                with self.subTest(origin=origin), patch.dict(os.environ, {"SERVERWARE_PUBLIC_URL": origin}, clear=True):
                    with self.assertRaises(ValueError):
                        bridge.get({"op": "get", "path": "/api/operator-demo/catalog"})
            opened.assert_not_called()
            connected.assert_not_called()

    def test_main_refuses_unrecognized_origin_before_source_or_get_dispatch(self):
        for origin in (None, "https://unreviewed.invalid"):
            output = io.StringIO()
            environment = {"SERVERWARE_OPERATOR_DEMO": "1", "SERVERWARE_ADMIN_TOKEN_FILE": bridge.TOKEN_FILE,
                "SERVERWARE_OPERATOR_NOTIFICATIONS_ENABLED": "1"}
            if origin is not None:
                environment["SERVERWARE_PUBLIC_URL"] = origin
            with self.subTest(origin=origin), patch.dict(os.environ, environment, clear=True), \
                    patch.object(bridge.sys, "argv", ["bridge", '{"op":"source"}']), \
                    patch.object(bridge.sys, "stdout", output), patch.object(bridge.signal, "signal"), \
                    patch.object(bridge.signal, "alarm"), patch.object(bridge, "source") as source, \
                    patch.object(bridge, "get") as get:
                with self.assertRaises(SystemExit) as caught:
                    bridge.main()
                self.assertEqual(caught.exception.code, 2)
                source.assert_not_called()
                get.assert_not_called()
            self.assertEqual(output.getvalue(), '{"ok":false,"reason":"runtime_readonly_bridge_refused"}\n')

    def x_command(self):
        return {"op": "get", "path": bridge.X_CONFIGURATION, "x_configuration_disabled": True}

    def x_enabled_command(self):
        return {"op": "get", "path": bridge.X_CONFIGURATION, "managed_x_unconfigured": True}

    def x_unconfigured(self):
        return {"schema": "serverware.operatorXConfiguration/v1", "state": "unconfigured", "revision": 81,
            "policy_hash": "sha256:" + "a" * 64,
            "redirect_uri": bridge.CANONICAL_PUBLIC + "/api/oauth/callback/x", "permission_preset": "x_text_post_v1",
            "scopes": ["offline.access", "tweet.read", "tweet.write", "users.read"],
            "configuration": None, "operation": None, "blocked_reason": None, "consent_ready": False,
            "review": {"expected_revision": 81, "expected_policy_hash": "sha256:" + "a" * 64}}

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

    def test_x_enabled_profile_is_explicit_exact_and_refuses_contradictions_before_io(self):
        environment = {"SERVERWARE_PUBLIC_URL": bridge.CANONICAL_PUBLIC, "SERVERWARE_OPERATOR_MANAGED_X_ENABLED": "1"}
        command = self.x_enabled_command()
        with patch.dict(os.environ, environment, clear=True):
            self.assertEqual(bridge.get_path(command), bridge.X_CONFIGURATION)
        environments = [{**environment, "SERVERWARE_OPERATOR_MANAGED_X_ENABLED": flag}
            for flag in ("0", "", "true", "01", "1 ")]
        environments += [{"SERVERWARE_PUBLIC_URL": bridge.CANONICAL_PUBLIC},
            {"SERVERWARE_OPERATOR_MANAGED_X_ENABLED": "1"}, {**environment, "SERVERWARE_PUBLIC_URL": bridge.PUBLIC}]
        commands = [{**command, "managed_x_unconfigured": value} for value in (False, 1, "true", None)]
        commands += [{**command, "path": path} for path in bridge.PATHS | {bridge.GOOGLE_CONFIGURATION,
            bridge.X_CONFIGURATION + "/", bridge.X_CONFIGURATION + "?x=1", "/api/operator-demo/oauth/x/start"}]
        commands += [{"op": "get", "path": bridge.X_CONFIGURATION}, self.x_command(),
            {**command, "x_configuration_disabled": True}, {**command, "managed_google_unconfigured": True},
            {**command, "headers": {}}, {**command, "body": ""}, {**command, "op": "post"}]
        with patch.object(bridge.os, "open") as opened, patch.object(bridge.http.client, "HTTPConnection") as connected:
            for changed in environments:
                with self.subTest(environment=changed), patch.dict(os.environ, changed, clear=True), self.assertRaises(ValueError):
                    bridge.get(command)
            with patch.dict(os.environ, environment, clear=True):
                for changed in commands:
                    with self.subTest(command=changed), self.assertRaises(ValueError):
                        bridge.get(changed)
            opened.assert_not_called(); connected.assert_not_called()

    def test_x_enabled_exact_unconfigured_200_preserves_original_bytes_and_private_token_boundary(self):
        body = json.dumps(self.x_unconfigured(), indent=2).encode()
        with patch.dict(os.environ, {"SERVERWARE_PUBLIC_URL": bridge.CANONICAL_PUBLIC,
                "SERVERWARE_OPERATOR_MANAGED_X_ENABLED": "1"}, clear=True):
            result, connection, response = self.fake_get(command=self.x_enabled_command(), status=200, body=body)
        self.assertEqual(result["status"], 200)
        self.assertEqual(base64.b64decode(result["body_base64"]), body)
        self.assertNotIn("TEST-ONLY-ADMIN", json.dumps(result))
        self.assertIn(("Cache-Control", "no-store"), result["headers"])
        response.read.assert_called_once_with(32769)
        args, kwargs = connection.request.call_args
        self.assertEqual(args, ("GET", bridge.X_CONFIGURATION))
        self.assertEqual(kwargs["headers"]["Origin"], bridge.CANONICAL_PUBLIC)
        self.assertEqual(kwargs["headers"]["Accept-Encoding"], "identity")

    def test_x_enabled_never_accepts_configured_pending_mixed_or_unbound_discovery(self):
        changes = [{"state": "configured"}, {"schema": "other"}, {"revision": True}, {"revision": 0},
            {"revision": 2**53}, {"policy_hash": "sha256:" + "A" * 64},
            {"redirect_uri": bridge.PUBLIC + "/api/oauth/callback/x"}, {"permission_preset": "x_readonly"},
            {"scopes": list(reversed(bridge.X_SCOPES))}, {"scopes": bridge.X_SCOPES + ["extra"]},
            {"configuration": {}}, {"operation": {}}, {"blocked_reason": "pending_google_configuration"},
            {"consent_ready": True}, {"extra": None}, {"review": None},
            {"review": {"expected_revision": 80, "expected_policy_hash": "sha256:" + "a" * 64}},
            {"review": {"expected_revision": 81, "expected_policy_hash": "sha256:" + "b" * 64}},
            {"review": {"expected_revision": 81, "expected_policy_hash": "sha256:" + "a" * 64, "extra": True}}]
        raw = json.dumps(self.x_unconfigured()).encode()
        bodies = [json.dumps({**self.x_unconfigured(), **change}).encode() for change in changes]
        bodies += [b'{}', b'[]', b'{"detail":"X configuration is not supported by this deployment"}',
            raw.replace(b'"unconfigured"', b'"configured", "state":"unconfigured"'),
            raw.replace(b'"configuration": null', b'"configuration":{"client_secret":"private-canary"},"configuration":null')]
        with patch.dict(os.environ, {"SERVERWARE_PUBLIC_URL": bridge.CANONICAL_PUBLIC,
                "SERVERWARE_OPERATOR_MANAGED_X_ENABLED": "1"}, clear=True):
            for body in bodies:
                with self.subTest(size=len(body)), self.assertRaises(ValueError):
                    self.fake_get(command=self.x_enabled_command(), status=200, body=body)
            boolean_review = deepcopy(self.x_unconfigured())
            boolean_review["revision"] = 1; boolean_review["review"]["expected_revision"] = True
            with self.assertRaises(ValueError):
                self.fake_get(command=self.x_enabled_command(), status=200, body=json.dumps(boolean_review).encode())

    def test_x_enabled_keeps_status_headers_bounds_and_redaction_fail_closed(self):
        body = json.dumps(self.x_unconfigured()).encode()
        with patch.dict(os.environ, {"SERVERWARE_PUBLIC_URL": bridge.CANONICAL_PUBLIC,
                "SERVERWARE_OPERATOR_MANAGED_X_ENABLED": "1"}, clear=True):
            for status in (201, 204, 302, 404, 503):
                with self.subTest(status=status), self.assertRaises(ValueError):
                    self.fake_get(command=self.x_enabled_command(), status=status, body=body)
            baseline = [("Content-Type", "application/json"), ("Cache-Control", "no-store")]
            for headers in (baseline[:1], baseline + [("Set-Cookie", "synthetic=1")],
                    baseline + [("Location", "/")], baseline + [("Content-Encoding", "gzip")],
                    baseline + [("Transfer-Encoding", "chunked")], baseline + [("Content-Length", "1")]):
                with self.subTest(headers=headers), self.assertRaises(ValueError):
                    self.fake_get(command=self.x_enabled_command(), status=200, headers=headers, body=body)
            for invalid in (b'x' * 32769, body.replace(b'unconfigured', b'TEST-ONLY-ADMIN-CANARY-DO-NOT-EXPORT-123456789'),
                    body.replace(b'unconfigured', b'-----BEGIN PRIVATE KEY-----')):
                with self.subTest(size=len(invalid)), self.assertRaises(ValueError):
                    self.fake_get(command=self.x_enabled_command(), status=200, body=invalid)


if __name__ == "__main__":
    unittest.main(verbosity=2)
