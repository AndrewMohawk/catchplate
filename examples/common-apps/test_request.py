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


if __name__ == "__main__":
    unittest.main()
