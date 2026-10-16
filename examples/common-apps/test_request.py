"""Focused offline checks with actual Requests; no sockets or provider writes."""
import io
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

import certifi
import requests
from requests.adapters import HTTPAdapter

import request as example


def no_network(event, _args):
    if event.startswith("socket.") or event in {"subprocess.Popen", "os.system"}:
        raise AssertionError("Offline example test attempted a network or process operation")


sys.addaudithook(no_network)
APP_ID = "12345678-1234-4234-8234-123456789abc"
RULE_ID = "00000000-0000-4000-8000-000000000002"
TOKEN = "synthetic-proxy-password:@/?#%"


def response(prepared, value=None, status=200, raw=None):
    result = requests.Response()
    result.status_code = status
    result.headers["Content-Type"] = "application/json"
    result._content = json.dumps({"ok": True} if value is None else value).encode() if raw is None else raw
    result._content_consumed = True
    result.request, result.url = prepared, prepared.url
    return result


class CommonAppsTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="serverware-common-apps-offline-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.config_path = self.root / "client.private.json"
        self.ca_path = self.root / "serverware-ca.pem"
        self.ca_path.write_bytes(re.search(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            Path(certifi.where()).read_bytes(), re.S).group())
        self.config = {"application_id": APP_ID, "access_rule_id": RULE_ID,
            "proxy_authentication": "basic_and_bearer_v1", "proxy_username": APP_ID,
            "proxy_password": TOKEN, "proxy_url": "https://proxy.example.test:8443",
            "token_expires_at_epoch_ms": 2**53 - 1, "ca_file": "./serverware-ca.pem",
            "app_preset": "gitlab", "app_operation": "project_issues", "scope": {"project_id": "12345"},
            "upstream_url": "https://gitlab.com/api/v4/projects/12345/issues", "methods": ["GET"],
            "request_headers": {"PRIVATE-TOKEN": "serverware-gitlab-placeholder-v1"},
            "request_query": {}, "query_keys": ["state", "page", "per_page"], "request_body": None,
            "credential_input": "replace_exact", "response_mode": "unfiltered_json_or_empty_v2",
            "client_recipe": {"automatic_retries": 0}}

    def write(self, config=None):
        self.config_path.write_text(json.dumps(self.config if config is None else config), encoding="utf-8")
        return self.config_path

    def load(self):
        return example.load_configuration(self.write())

    def test_installed_pins(self):
        example.check_versions()

    def check_cli(self, flags=()):
        with patch.object(example, "client_session") as session, \
                patch("sys.stdout", io.StringIO()) as out, patch("sys.stderr", io.StringIO()) as err:
            status = example.main(["--config", str(self.config_path), "--check-config", *flags])
        session.assert_not_called()
        self.assertNotIn(TOKEN, out.getvalue() + err.getvalue())
        self.assertNotIn("synthetic-proxy-password", out.getvalue() + err.getvalue())
        return status, out.getvalue(), err.getvalue()

    def test_local_preflight_checks_get_and_post_without_a_session(self):
        for method in ("GET", "POST"):
            self.write({**self.config, "methods": [method]})
            status, out, err = self.check_cli()
            self.assertEqual(status, 0)
            self.assertEqual(err, "")
            self.assertEqual(json.loads(out), {"status": "configuration_ready", "provider_calls": 0,
                "network_checked": False, "method": method, "write_confirmation_required": method == "POST"})

    def test_local_preflight_reports_closed_actionable_errors(self):
        status, _, err = self.check_cli()
        self.assertEqual(status, 1)
        self.assertIn("Private config not found", err)
        cases = [("token_expires_at_epoch_ms", 1, "Client token expired"),
            ("ca_file", "absent.pem", "Interception CA"),
            ("proxy_ca_file", "absent.pem", "Outer proxy CA"),
            ("request_headers", {"PRIVATE-TOKEN": TOKEN}, "invalid or incompatible")]
        for field, value, expected in cases:
            with self.subTest(field=field):
                self.write({**self.config, field: value})
                status, out, err = self.check_cli()
                self.assertEqual(status, 1)
                self.assertEqual(out, "")
                self.assertIn("Nothing was sent", err)
                self.assertIn(expected, err)
        self.write()
        with patch.object(example, "check_versions", side_effect=RuntimeError(TOKEN)):
            self.assertIn("Pinned dependencies", self.check_cli()[2])
        for flags in (["--body", "/not-read"], ["--execute-write"], ["--print-example-body"],
                ["--query", "unknown=" + TOKEN]):
            status, out, err = self.check_cli(flags)
            self.assertEqual(status, 1)
            self.assertEqual(out, "")
            self.assertIn("Nothing was sent", err)

    def test_normal_local_failure_is_not_misreported_as_a_dispatched_request(self):
        self.write({**self.config, "token_expires_at_epoch_ms": 1})
        with patch.object(example, "execute") as execute, patch("sys.stderr", io.StringIO()) as err:
            self.assertEqual(example.main(["--config", str(self.config_path)]), 1)
        execute.assert_not_called()
        self.assertIn("Nothing was sent. Client token expired", err.getvalue())
        self.write({**self.config, "methods": ["POST"]})
        with patch.object(example, "client_session") as session, patch("sys.stderr", io.StringIO()) as err:
            self.assertEqual(example.main(["--config", str(self.config_path), "--body",
                str(self.root / "missing-body.json"), "--execute-write"]), 1)
        session.assert_not_called()
        self.assertIn("Nothing was sent", err.getvalue())
        self.assertNotIn("outcome may be unknown", err.getvalue())

    def test_private_download_all_provider_auth_shapes_and_relative_ca(self):
        for provider, (host, auth, prefix) in example.PROVIDERS.items():
            with self.subTest(provider=provider):
                value = {**self.config, "app_preset": provider, "upstream_url": "https://" + host + "/api",
                    "request_headers": {auth: prefix + "serverware-" + provider + "-placeholder-v1"}}
                loaded = example.load_configuration(self.write(value))
                self.assertEqual(loaded["ca_file"], str(self.ca_path))
                self.assertIsNone(loaded["proxy_ca_file"])
                self.assertIn("synthetic-proxy-password%3A%40%2F%3F%23%25", loaded["_proxy_url"])

    def test_current_preset_descriptors_produce_runnable_downloads(self):
        root = Path(__file__).resolve().parents[2]
        if not (root / "serverware").is_dir():
            self.skipTest("Preset source checks require the full repository checkout")
        count = 0
        for name in ("operator_common_apps_ai", "operator_common_apps_services"):
            spec = importlib.util.spec_from_file_location(name, root / "serverware" / (name + ".py"))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            for app in module.PRESETS:
                for operation in app["operations"]:
                    scope = {field["key"]: (field.get("default", field["min"]) if field["type"] == "number"
                        else field["placeholder"]) for field in operation["scope_fields"]}
                    if "model" in scope:
                        scope["model"] = "vendor/fixture-model" if app["id"] == "openrouter" else "fixture-model"
                    def resolve(value):
                        if type(value) is dict:
                            return scope[value["$scope"]] if set(value) == {"$scope"} else {k: resolve(v) for k, v in value.items()}
                        if type(value) is list:
                            return [resolve(item) for item in value]
                        return value
                    config = {**self.config, "app_preset": app["id"], "app_operation": operation["id"], "scope": scope,
                        "methods": operation["methods"], "upstream_url": operation["origin"] + operation["path_template"].format(**scope),
                        "request_headers": {**operation.get("request_headers", {}), app["header_name"]: app["placeholder"]},
                        "query_keys": operation["query_keys"], "request_query": resolve(operation.get("example_query", {})),
                        "request_body": resolve(operation.get("example_body"))}
                    with self.subTest(provider=app["id"], operation=operation["id"]):
                        loaded = example.load_configuration(self.write(config))
                        self.assertTrue(example.request_url(loaded).startswith(config["upstream_url"]))
                    count += 1
        self.assertGreaterEqual(count, 12)

    def test_invalid_configuration_refuses_before_transport(self):
        cases = {"application_id": "bad", "access_rule_id": "bad", "proxy_username": "wrong",
            "proxy_authentication": "bearer", "proxy_password": "secret\n", "proxy_url": "http://proxy.test",
            "token_expires_at_epoch_ms": True, "app_preset": "unknown", "app_operation": "../elsewhere",
            "scope": [], "methods": ["GET", "POST"], "upstream_url": "https://evil.example.test/",
            "credential_input": "none", "response_mode": "passthrough", "ca_file": "",
            "request_headers": {"PRIVATE-TOKEN": "real-secret-never-use"}, "request_query": [],
            "client_recipe": {"automatic_retries": 3}}
        for key, value in cases.items():
            with self.subTest(field=key), self.assertRaises((ValueError, TypeError)):
                example.load_configuration(self.write({**self.config, key: value}))
        for raw in (b"", b"[]", b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1e309}', b" " * 65537):
            self.config_path.write_bytes(raw)
            with self.assertRaises(ValueError):
                example.load_configuration(self.config_path)

    def test_actual_requests_one_get_placeholder_basic_proxy_and_no_ambient_auth(self):
        seen = []
        def send(adapter, prepared, **kwargs):
            seen.append((adapter, prepared, kwargs))
            return response(prepared, [{"title": "Issue example"}])
        with patch.dict(os.environ, {"HTTPS_PROXY": "http://wrong", "NO_PROXY": "*", "NETRC": "/wrong"}), \
                patch.object(HTTPAdapter, "send", send):
            result = example.execute(self.load(), query=["state=opened", "per_page=5"])
        self.assertEqual(result, {"status": 200, "response": [{"title": "Issue example"}]})
        self.assertEqual(len(seen), 1)
        adapter, prepared, kwargs = seen[0]
        self.assertEqual(prepared.url, self.config["upstream_url"] + "?per_page=5&state=opened")
        self.assertEqual(prepared.headers["PRIVATE-TOKEN"], "serverware-gitlab-placeholder-v1")
        self.assertNotIn("Proxy-Authorization", prepared.headers)
        self.assertNotIn("Content-Type", prepared.headers)
        self.assertIsNone(prepared.body)
        self.assertEqual(adapter.max_retries.total, 0)
        self.assertEqual(kwargs["verify"], str(self.ca_path))
        self.assertTrue(kwargs["proxies"]["https"].startswith("https://" + APP_ID + ":"))

    def test_scoped_query_cannot_be_replaced_and_is_canonical(self):
        config = self.load()
        config.update(upstream_url="https://sentry.io/api/0/organizations/example/issues/",
            query_keys=["project", "query"], request_query={"project": "12345"})
        self.assertTrue(example.request_url(config, ["query=is:unresolved user@example.com"]).endswith(
            "?project=12345&query=is%3Aunresolved%20user%40example.com"))
        for query in (["project=99999"], ["unknown=x"], ["query=a", "query=b"]):
            with self.assertRaises(ValueError): example.request_url(config, query)

    def test_write_requires_explicit_body_and_confirmation_never_uses_suggestion(self):
        self.config.update(app_preset="slack", app_operation="post_message", scope={"channel": "C0123456789"},
            upstream_url="https://slack.com/api/chat.postMessage", methods=["POST"],
            request_headers={"Authorization": "Bearer serverware-slack-placeholder-v1"},
            request_body={"channel": "C0123456789", "text": "Not automatically sent"}, query_keys=[])
        config = self.load()
        body_path = self.root / "request.json"
        raw = b'{"channel":"C0123456789","text":"Reviewed","unfurl_links":false,"unfurl_media":false}\n'
        body_path.write_bytes(raw)
        with patch.object(example, "client_session") as session:
            for body, confirm in ((None, False), (body_path, False), (None, True)):
                with self.assertRaises(ValueError): example.execute(config, body, confirm)
            session.assert_not_called()
        seen = []
        def send(_adapter, prepared, **_kwargs):
            seen.append(prepared)
            return response(prepared, {"ok": True})
        with patch.object(HTTPAdapter, "send", send):
            example.execute(config, body_path, True)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].body, raw)
        self.assertEqual(seen[0].headers["Content-Type"], "application/json")

    def test_response_bounds_empty204_and_no_redirect_follow(self):
        for status, raw in ((200, b" " * 1048577), (428, b" " * 65537), (302, b" " * 65537)):
            def send(_adapter, prepared, **_kwargs): return response(prepared, status=status, raw=raw)
            with self.subTest(status=status), patch.object(HTTPAdapter, "send", send), self.assertRaises(ValueError):
                example.execute(self.load())
        seen = []
        def redirect(_adapter, prepared, **_kwargs):
            seen.append(prepared)
            result = response(prepared, status=302)
            result.headers["Location"] = "https://evil.example.test/"
            return result
        with patch.object(HTTPAdapter, "send", redirect):
            self.assertEqual(example.execute(self.load())["status"], 302)
        self.assertEqual(len(seen), 1)
        with patch.object(HTTPAdapter, "send", lambda _a, r, **_kw: response(r, status=204, raw=b"")):
            self.assertEqual(example.execute(self.load()), {"status": 204, "response": None})

    def test_428_is_visible_and_never_retried_and_transport_errors_redacted(self):
        seen = []
        def pending(_adapter, prepared, **_kwargs):
            seen.append(prepared)
            return response(prepared, {"payload": {"approval_url": "https://console.example.test/#pending-actions"}}, status=428)
        with patch.object(HTTPAdapter, "send", pending), patch("sys.stdout", io.StringIO()) as out, \
                patch("sys.stderr", io.StringIO()) as err:
            self.assertEqual(example.main(["--config", str(self.write())]), 2)
        self.assertEqual(len(seen), 1)
        self.assertIn("approval_url", out.getvalue())
        self.assertIn("identical command", err.getvalue())
        self.assertNotIn(TOKEN, out.getvalue() + err.getvalue())
        with patch.object(HTTPAdapter, "send", side_effect=RuntimeError(TOKEN)), \
                patch("sys.stdout", io.StringIO()) as out, patch("sys.stderr", io.StringIO()) as err:
            self.assertEqual(example.main(["--config", str(self.write())]), 1)
        self.assertNotIn(TOKEN, out.getvalue() + err.getvalue())
        self.assertIn("outcome may be unknown", err.getvalue())

    def test_print_example_body_and_unconfirmed_post_do_not_open_transport(self):
        self.config.update(methods=["POST"], request_body={"message": "Review me"})
        with patch.object(example, "client_session") as session, patch("sys.stdout", io.StringIO()) as out, \
                patch("sys.stderr", io.StringIO()) as err:
            self.assertEqual(example.main(["--config", str(self.write()), "--print-example-body"]), 0)
            self.assertEqual(json.loads(out.getvalue()), {"message": "Review me"})
            self.assertEqual(example.main(["--config", str(self.write())]), 2)
        session.assert_not_called()
        self.assertIn("Nothing was sent", err.getvalue())

    def test_http200_provider_failure_is_not_success(self):
        for provider, field in (("slack", "ok"), ("cloudflare", "success")):
            host, auth, prefix = example.PROVIDERS[provider]
            config = {**self.config, "app_preset": provider, "upstream_url": "https://" + host + "/api",
                "request_headers": {auth: prefix + "serverware-" + provider + "-placeholder-v1"}}
            with self.subTest(provider=provider), patch.object(example, "execute",
                    return_value={"status": 200, "response": {field: False}}), \
                    patch("sys.stdout", io.StringIO()), patch("sys.stderr", io.StringIO()) as err:
                self.assertEqual(example.main(["--config", str(self.write(config))]), 2)
            self.assertIn("did not return success", err.getvalue())

    def test_byte_body_helper_matches_file_wrapper_without_reencoding(self):
        config = self.load()
        config["methods"] = ["POST"]
        raw = b'{ "text" : "Reviewed\\ntext", "flag": false }\n'
        body_path = self.root / "body.json"
        body_path.write_bytes(raw)
        seen = []
        def send(_adapter, prepared, **kwargs):
            seen.append((prepared.method, prepared.url, dict(prepared.headers), prepared.body, kwargs))
            return response(prepared, {"id": "synthetic"}, status=201)
        with patch.object(HTTPAdapter, "send", send):
            direct = example.execute_body(config, raw, True, ["page=1"])
            wrapper = example.execute(config, body_path, True, ["page=1"])
        self.assertEqual(direct, wrapper)
        self.assertEqual(direct, {"status": 201, "response": {"id": "synthetic"}})
        self.assertEqual(len(seen), 2)  # One request for each separate explicit call.
        self.assertEqual(seen[0], seen[1])
        self.assertEqual(seen[0][3], raw)
        with patch.object(HTTPAdapter, "send", send):
            config["methods"] = ["GET"]
            self.assertEqual(example.execute_body(config), example.execute(config))

    def test_byte_body_helper_rejects_invalid_body_and_intent_before_transport(self):
        config = self.load()
        config["methods"] = ["POST"]
        invalid = ((None, True), ("{}", True), (bytearray(b"{}"), True), (b"", True),
            (b" " * (example.MAX_BODY_BYTES + 1), True), (b"[]", True),
            (b'{"a":1,"a":2}', True), (b'{"a":NaN}', True), (b"\xff", True),
            (b"{}", False), (b"{}", "true"), (b"{}", 1), (b"{}", None))
        with patch.object(example, "client_session") as session:
            for body, intent in invalid:
                with self.subTest(body=repr(body)[:40], intent=intent), \
                        self.assertRaises(example.RequestExecutionError) as error:
                    example.execute_body(config, body, intent)
                self.assertFalse(error.exception.request_started)
                self.assertFalse(error.exception.outcome_unknown)
            config["methods"] = ["GET"]
            for body, intent in ((b"{}", False), (None, True)):
                with self.assertRaises(example.RequestExecutionError):
                    example.execute_body(config, body, intent)
            with self.assertRaises(example.RequestExecutionError):
                example.execute_body(config, query=["unknown=value"])
            config["methods"] = ["DELETE"]
            with self.assertRaises(example.RequestExecutionError):
                example.execute_body(config)
            session.assert_not_called()
        config["methods"] = ["POST"]
        maximum = b"{}" + b" " * (example.MAX_BODY_BYTES - 2)
        with patch.object(HTTPAdapter, "send", lambda _a, r, **_kw: response(r)):
            self.assertEqual(example.execute_body(config, maximum, True)["status"], 200)

    def test_byte_body_helper_sanitizes_failures_without_private_exception_chains(self):
        config = self.load()
        for method in ("GET", "POST"):
            config["methods"] = [method]
            with patch.object(HTTPAdapter, "send", side_effect=RuntimeError(config["_proxy_url"])) as send, \
                    self.assertRaises(example.RequestExecutionError) as error:
                example.execute_body(config, b"{}" if method == "POST" else None, method == "POST")
            self.assertEqual(send.call_count, 1)
            failure = error.exception
            self.assertEqual(str(failure), example.FAILURE)
            self.assertEqual(failure.args, (example.FAILURE,))
            self.assertIsNone(failure.__context__)
            self.assertIsNone(failure.__cause__)
            self.assertTrue(failure.request_started)
            self.assertEqual(failure.outcome_unknown, method == "POST")
            self.assertNotIn(TOKEN, repr(failure.__dict__) + repr(failure))
        with patch.object(example, "client_session", side_effect=RuntimeError(TOKEN)), \
                self.assertRaises(example.RequestExecutionError) as error:
            example.execute_body(config, b"{}", True)
        self.assertFalse(error.exception.request_started)
        self.assertFalse(error.exception.outcome_unknown)

    def test_byte_body_helper_preserves_428_and_204_and_response_bound(self):
        config = self.load()
        pending = {"payload": {"approval_url": "/approvals/00000000-0000-4000-8000-000000000002"}}
        with patch.object(HTTPAdapter, "send", lambda _a, r, **_kw: response(r, pending, 428)):
            self.assertEqual(example.execute_body(config), {"status": 428, "response": pending})
        with patch.object(HTTPAdapter, "send", lambda _a, r, **_kw: response(r, status=204, raw=b"")):
            self.assertEqual(example.execute_body(config), {"status": 204, "response": None})
        with patch.object(HTTPAdapter, "send", lambda _a, r, **_kw: response(r, raw=b" " * 1048577)), \
                self.assertRaises(example.RequestExecutionError):
            example.execute_body(config)


if __name__ == "__main__":
    unittest.main()
