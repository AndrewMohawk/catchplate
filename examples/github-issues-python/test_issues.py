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
