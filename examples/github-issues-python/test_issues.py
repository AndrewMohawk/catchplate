"""Offline stock-SDK serialization only: no proxy, TLS handshake or GitHub call."""
import base64
from contextlib import contextmanager
import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit


def no_network(event, args):
    if event.startswith("socket."):
        raise AssertionError("Offline test attempted socket access")


CONFIG_ONLY = "--config-only" in sys.argv
if CONFIG_ONLY:
    sys.argv.remove("--config-only")
else:
    import certifi
    import requests
    from requests.adapters import HTTPAdapter

import issues

# Install after imports: urllib3 may probe local IPv6 support while importing.
# Every test operation below, including all SDK calls, is denied socket access.
sys.addaudithook(no_network)

APP_ID = "12345678-1234-4234-8234-123456789abc"
TOKEN = "synthetic-app-password:@/?#%"
ENV = {"SERVERWARE_PROXY_URL": "https://proxy.example.test:8443",
    "SERVERWARE_APP_ID": APP_ID, "SERVERWARE_PROXY_TOKEN": TOKEN,
    "SERVERWARE_GITHUB_OWNER": "example", "SERVERWARE_GITHUB_REPO": "demo",
    "SERVERWARE_CA_FILE": "/fixture/ca.pem"}


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "serverware-client.private.json"
        self.value = {"application_id": APP_ID, "access_rule_id": "00000000-0000-4000-8000-000000000002",
            "proxy_url": ENV["SERVERWARE_PROXY_URL"], "proxy_authentication": "basic_and_bearer_v1",
            "proxy_username": APP_ID, "proxy_password": TOKEN, "token_expires_at_epoch_ms": 2**53 - 1,
            "ca_file": "./serverware-ca.pem", "repository": {"owner": "example", "name": "demo"},
            "upstream_url": "https://api.github.com/repos/example/demo/issues",
            "operation_bundle": "github_issues_read_v1", "methods": ["GET"],
            "request_headers": {"Authorization": "token " + issues.PLACEHOLDER},
            "client_recipe": {"packages": {"@octokit/rest": "22.0.1", "undici": "8.11.2"},
                "minimum_node": "22.19", "sdk_auth_token": issues.PLACEHOLDER,
                "proxy_ca_file": None, "destination_ca_file": "./serverware-ca.pem"}}

    def write(self, value=None):
        self.path.write_text(json.dumps(self.value if value is None else value), encoding="utf-8")
        return self.path

    def test_console_export_maps_scope_and_relative_ca_over_ambient_without_recipe_execution(self):
        ambient = {name: "ambient-conflict" for name in ENV}
        ambient.update(SERVERWARE_PROXY_CA_FILE="/ambient/proxy-ca.pem", GITHUB_TOKEN="do-not-use")
        original = dict(ambient)
        self.value["client_recipe"].update(entrypoint="do-not-execute", commands=["do-not-execute"],
            environment={"SERVERWARE_GITHUB_OWNER": "untrusted-recipe", "HTTPS_PROXY": "wrong"})
        for bundle in ("github_issues_read_v1", "github_issues_write_v1"):
            self.value["operation_bundle"] = bundle
            self.value["methods"] = ["GET"] if bundle == "github_issues_read_v1" else ["POST", "GET"]
            with self.subTest(bundle=bundle), patch.object(issues.subprocess, "run") as run:
                selected = issues.configuration_environment(self.write(), ambient)
            run.assert_not_called()
            self.assertEqual(ambient, original)
            self.assertEqual({key: selected[key] for key in ENV if key != "SERVERWARE_CA_FILE"},
                {key: value for key, value in ENV.items() if key != "SERVERWARE_CA_FILE"})
            self.assertEqual(selected["SERVERWARE_CA_FILE"], str(self.path.parent / "serverware-ca.pem"))
            self.assertNotIn("SERVERWARE_PROXY_CA_FILE", selected)
            self.assertNotIn("GITHUB_TOKEN", issues.child_environment(selected, selected["SERVERWARE_CA_FILE"]))
        del self.value["client_recipe"]
        self.assertNotIn("SERVERWARE_PROXY_CA_FILE", issues.configuration_environment(self.write(), ambient))

    def test_bundle_repository_upstream_identity_and_expiry_mismatches_refuse(self):
        for key, invalid in (("operation_bundle", "alchemy_chain_status_v1"),
                ("repository", {"owner": "example", "name": "other"}),
                ("repository", {"owner": "example", "name": ".."}),
                ("upstream_url", "https://api.github.com/repos/example/demo/issues?state=open"),
                ("upstream_url", "https://other.example/repos/example/demo/issues"),
                ("proxy_authentication", "bearer"), ("proxy_username", "different"),
                ("application_id", "not-a-uuid"), ("access_rule_id", "not-a-uuid"),
                ("proxy_password", "bad\npassword"), ("proxy_url", "https://user:pass@proxy.test"),
                ("methods", ["GET", "POST"]), ("methods", ["GET", "GET"]),
                ("methods", ["POST"]), ("methods", "GET"),
                ("token_expires_at_epoch_ms", 1), ("token_expires_at_epoch_ms", True),
                ("token_expires_at_epoch_ms", 2**53), ("token_expires_at_epoch_ms", 1.25),
                ("token_expires_at_epoch_ms", float("nan")), ("token_expires_at_epoch_ms", float("inf")),
                ("ca_file", "")):
            with self.subTest(field=key, kind=type(invalid).__name__), self.assertRaises(ValueError):
                issues.configuration_environment(self.write({**self.value, key: invalid}), ENV)

    def test_config_is_bounded_regular_duplicate_free_json(self):
        self.path.write_bytes(b" " * (issues.MAX_CONFIG_BYTES + 1))
        with self.assertRaises(ValueError):
            issues.configuration_environment(self.path, ENV)
        with self.assertRaises((ValueError, OSError)):
            issues.configuration_environment(self.path.parent, ENV)
        fifo = self.path.parent / "fifo"
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            issues.configuration_environment(fifo, ENV)
        for raw in (b"[]", b"{", b'{"application_id":"one","application_id":"two"}',
                b'{"ignored":NaN}', b'{"ignored":1e309}', b"\xff"):
            self.path.write_bytes(raw)
            with self.subTest(original=raw), self.assertRaises(ValueError):
                issues.configuration_environment(self.path, ENV)
        encoded = json.dumps(self.value).encode("utf-8")
        self.path.write_bytes(encoded + b" " * (issues.MAX_CONFIG_BYTES - len(encoded)))
        self.assertEqual(issues.configuration_environment(self.path, ENV)["SERVERWARE_APP_ID"], APP_ID)

    def test_config_cli_uses_parent_launcher_and_environment_only_mode_stays_available(self):
        path = self.write()
        with patch.dict(os.environ, {"SERVERWARE_GITHUB_OWNER": "wrong"}, clear=True), \
                patch.object(issues, "launch", return_value=[]) as launch, \
                patch("sys.stdout", io.StringIO()) as output:
            self.assertEqual(issues.main(["--config", str(path), "--limit", "7"]), 0)
        launch.assert_called_once()
        self.assertEqual(launch.call_args.args[0]["SERVERWARE_GITHUB_OWNER"], "example")
        self.assertEqual(launch.call_args.args[1], 7)
        self.assertEqual(output.getvalue(), "[]\n")
        with patch.object(issues, "launch", return_value=[]) as launch, patch("sys.stdout", io.StringIO()):
            self.assertEqual(issues.main([]), 0)
            self.assertIs(launch.call_args.args[0], os.environ)

    def test_child_config_combination_and_malformed_json_fail_before_launch_without_secret_output(self):
        for args in (["--child", "--config", str(self.path)], ["--config", str(self.path)]):
            self.path.write_text('{"secret":"' + TOKEN + '",', encoding="utf-8")
            with patch.object(issues, "launch") as launch, patch.object(issues, "read_issues") as read, \
                    patch.object(issues, "check_versions") as versions, \
                    patch("sys.stdout", io.StringIO()) as output, patch("sys.stderr", io.StringIO()) as errors:
                self.assertEqual(issues.main(args), 1)
            launch.assert_not_called(); read.assert_not_called(); versions.assert_not_called()
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(errors.getvalue(), issues.FAILURE + "\n")
            self.assertNotIn(TOKEN, errors.getvalue())

    def test_supplied_separate_proxy_ca_has_fixed_diagnostic_before_sdk_or_launch(self):
        self.value["client_recipe"]["proxy_ca_file"] = "./private-proxy-ca.pem"
        path = self.write()
        with patch.object(issues, "launch") as launch, patch.object(issues, "check_versions") as versions, \
                patch("sys.stdout", io.StringIO()) as output, patch("sys.stderr", io.StringIO()) as errors:
            self.assertEqual(issues.main(["--config", str(path)]), 1)
        launch.assert_not_called(); versions.assert_not_called()
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(errors.getvalue(), issues.PROXY_CA_FAILURE + "\n")
        self.assertNotIn(TOKEN, errors.getvalue())
        self.assertNotIn("private-proxy-ca.pem", errors.getvalue())


@unittest.skipIf(CONFIG_ONLY, "SDK checks require the prepared pinned dependencies")
class ExampleTests(unittest.TestCase):
    def test_pins(self):
        issues.check_versions()

    def test_minimal_child_environment_and_encoding(self):
        source = {**ENV, "GITHUB_TOKEN": "must-not-inherit", "https_proxy": "http://wrong",
            "NO_PROXY": "*", "REQUESTS_CA_BUNDLE": "/wrong", "PYTHONPATH": "/wrong"}
        before = dict(source)
        child = issues.child_environment(source, "/private/combined.pem")
        self.assertEqual(source, before)
        self.assertEqual(set(child), {"HTTPS_PROXY", "NO_PROXY", "SERVERWARE_GITHUB_OWNER",
            "SERVERWARE_GITHUB_REPO", "SERVERWARE_CA_FILE"})
        adapter = HTTPAdapter()
        expected = "Basic " + base64.b64encode((APP_ID + ":" + TOKEN).encode()).decode()
        self.assertEqual(adapter.proxy_headers(child["HTTPS_PROXY"]), {"Proxy-Authorization": expected})
        self.assertNotIn(TOKEN, child["HTTPS_PROXY"])
        self.assertEqual(child["NO_PROXY"], "")

    def test_refuse_unsafe_configuration(self):
        for key, value in [("SERVERWARE_PROXY_URL", "http://proxy.test"),
                ("SERVERWARE_PROXY_URL", "https://user:pass@proxy.test"),
                ("SERVERWARE_PROXY_URL", "https://proxy.test/path"),
                ("SERVERWARE_PROXY_URL", "https://proxy.test?query"),
                ("SERVERWARE_PROXY_URL", "https://proxy.test?"),
                ("SERVERWARE_PROXY_URL", "https://proxy.test#fragment"),
                ("SERVERWARE_PROXY_URL", "https://proxy.test:0"),
                ("SERVERWARE_PROXY_URL", "https://proxy.test:99999"),
                ("SERVERWARE_PROXY_URL", "https://proxy.test\n"),
                ("SERVERWARE_APP_ID", "not-an-application-id"),
                ("SERVERWARE_PROXY_TOKEN", "bad\npassword"),
                ("SERVERWARE_GITHUB_OWNER", "../other"),
                ("SERVERWARE_GITHUB_REPO", ".."),
                ("SERVERWARE_PROXY_CA_FILE", "")]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                issues.child_environment({**ENV, key: value}, "/ca.pem")

    def test_stock_pagination_without_repository_lookup(self):
        captured = []
        next_url = "https://api.github.com/repos/example/demo/issues?page=2&per_page=30&state=open"

        def send(adapter, request, **kwargs):
            captured.append((request, kwargs, adapter.max_retries))
            self.assertLessEqual(len(captured), 2)
            response = requests.Response()
            response.status_code = 200
            response.headers["Content-Type"] = "application/json; charset=utf-8"
            if len(captured) == 1:
                response.headers["Link"] = '<' + next_url + '>; rel="next"'
            number = len(captured)
            response._content = json.dumps([{"number": number, "title": "Issue " + str(number),
                "state": "open", "url": "https://api.github.com/repos/example/demo/issues/" + str(number)}]).encode()
            response.request = request
            response.url = request.url
            return response

        child = issues.child_environment(ENV, ENV["SERVERWARE_CA_FILE"])
        with patch.dict(os.environ, child, clear=True), patch.object(HTTPAdapter, "send", send):
            rows = issues.read_issues(child, 100)
        self.assertEqual([row["number"] for row in rows], [1, 2])
        self.assertEqual(len(captured), 2)
        for request, kwargs, retries in captured:
            target = urlsplit(request.url)
            self.assertEqual((request.method, target.scheme, target.hostname, target.port),
                ("GET", "https", "api.github.com", 443))
            self.assertEqual(target.path, "/repos/example/demo/issues")
            self.assertIsNone(request.body)
            self.assertEqual(request.headers["Authorization"], "token " + issues.PLACEHOLDER)
            self.assertEqual(request.headers["Accept"], "*/*")
            self.assertEqual(request.headers["X-GitHub-Api-Version"], "2022-11-28")
            self.assertNotIn("Proxy-Authorization", request.headers)
            self.assertNotIn(TOKEN, request.url)
            self.assertEqual(kwargs["verify"], ENV["SERVERWARE_CA_FILE"])
            self.assertEqual(kwargs["timeout"], 10)
            self.assertEqual(kwargs["proxies"]["https"], child["HTTPS_PROXY"])
            self.assertEqual(retries.total, 0)
        self.assertEqual(parse_qs(urlsplit(captured[0][0].url).query),
            {"direction": ["desc"], "sort": ["updated"], "state": ["open"]})
        self.assertEqual(parse_qs(urlsplit(captured[1][0].url).query),
            {"page": ["2"], "per_page": ["30"], "state": ["open"]})

    def test_stock_proxy_pool_keeps_tls_and_proxy_auth_separate(self):
        child = issues.child_environment(ENV, ENV["SERVERWARE_CA_FILE"])
        adapter = HTTPAdapter()
        try:
            request = requests.Request("GET", "https://api.github.com/repos/example/demo/issues",
                headers={"Authorization": "token " + issues.PLACEHOLDER}).prepare()
            pool = adapter.get_connection_with_tls_context(request, verify=ENV["SERVERWARE_CA_FILE"],
                proxies={"https": child["HTTPS_PROXY"]})
            self.assertEqual(pool.cert_reqs, "CERT_REQUIRED")
            self.assertEqual(pool.ca_certs, ENV["SERVERWARE_CA_FILE"])
            self.assertEqual(pool.proxy.scheme, "https")
            self.assertIsNone(pool.proxy_config.ssl_context)  # Stock inheritance, not independent outer trust.
            self.assertIn("Proxy-Authorization", pool.proxy_headers)
            self.assertNotIn("Proxy-Authorization", request.headers)
        finally:
            adapter.close()

    def test_temporary_client_ca_bundle(self):
        pem = re.search(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            Path(certifi.where()).read_bytes(), flags=re.S).group()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "downloaded.pem"
            path.write_bytes(pem)
            with issues.client_ca_bundle(str(path)) as combined:
                content = Path(combined).read_bytes()
                self.assertEqual(Path(combined).stat().st_mode & 0o777, 0o600)
                self.assertTrue(content.startswith(Path(certifi.where()).read_bytes()))
                self.assertTrue(content.endswith(pem + b"\n"))
            self.assertFalse(Path(combined).exists())

    def test_launcher_one_child_no_ambient_inheritance(self):
        @contextmanager
        def bundle(path):
            self.assertEqual(path, ENV["SERVERWARE_CA_FILE"])
            yield "/private/ca.pem"

        result = type("Result", (), {"returncode": 0, "stdout": b"[]", "stderr": b""})()
        with patch.object(issues, "client_ca_bundle", bundle), patch.object(issues.subprocess, "run", return_value=result) as run:
            before = dict(os.environ)
            self.assertEqual(issues.launch(ENV, 10), [])
            self.assertEqual(dict(os.environ), before)
        run.assert_called_once()
        args, kwargs = run.call_args
        self.assertNotIn(TOKEN, repr(args))
        self.assertEqual(kwargs["timeout"], 60)
        self.assertFalse(kwargs["check"])
        self.assertEqual(set(kwargs["env"]), set(issues.child_environment(ENV, "/private/ca.pem")))

    def test_failure_output_never_prints_exception(self):
        output, errors = io.StringIO(), io.StringIO()
        with patch.object(issues, "launch", side_effect=RuntimeError(TOKEN)), \
                patch("sys.stdout", output), patch("sys.stderr", errors):
            self.assertEqual(issues.main([]), 1)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(errors.getvalue(), issues.FAILURE + "\n")
        self.assertNotIn(TOKEN, errors.getvalue())


if __name__ == "__main__":
    unittest.main()
