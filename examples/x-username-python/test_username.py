"""Offline SDK serialization/transport configuration, not proxy or X acceptance."""
import base64
import io
import json
import os
from pathlib import Path
import re
import ssl
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import certifi
import requests
from requests.adapters import HTTPAdapter
import urllib3.connection
from xdk import Client

import username


def no_network(event, args):
    if event.startswith("socket."):
        raise AssertionError("Offline test attempted socket access")


# Dependency imports may probe local IPv6 support. All test operations below
# refuse sockets; only the final stock HTTPAdapter.send boundary is substituted.
sys.addaudithook(no_network)
APP_ID = "12345678-1234-4234-8234-123456789abc"
TOKEN = "synthetic-app-password:@/?#%"
ROW = {"id": "123456789", "username": "Example", "name": "Synthetic account"}


def response(request, body=None, status=200):
    value = requests.Response()
    value.status_code = status
    value.headers["Content-Type"] = "application/json"
    value._content = json.dumps({"data": ROW} if body is None else body).encode()
    value._content_consumed = True
    value.request, value.url = request, request.url
    return value


class ExampleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="x-example-offline-")
        self.addCleanup(self.temp.cleanup)
        self.pem = re.search(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            Path(certifi.where()).read_bytes(), flags=re.S).group()
        self.ca = Path(self.temp.name) / "public.pem"
        self.ca.write_bytes(self.pem)
        self.env = {"SERVERWARE_PROXY_URL": "https://proxy.example.test:8443",
            "SERVERWARE_APP_ID": APP_ID, "SERVERWARE_PROXY_TOKEN": TOKEN,
            "SERVERWARE_CA_FILE": str(self.ca), "SERVERWARE_X_USERNAME": "example"}

    def test_installed_pins(self):
        username.check_versions()

    def test_explicit_environment_and_separate_proxy_authentication(self):
        source = {**self.env, "X_BEARER_TOKEN": "not-inherited", "NO_PROXY": "*",
            "HTTPS_PROXY": "http://wrong", "NETRC": "/wrong", "HOME": "/ambient",
            "SSLKEYLOGFILE": "/wrong", "REQUESTS_CA_BUNDLE": "/wrong", "PYTHONPATH": "/wrong"}
        original = dict(source)
        child = username.child_environment(source)
        self.assertEqual(source, original)
        self.assertEqual(child, self.env)
        _, proxy = username.settings(child)
        adapter = HTTPAdapter()
        try:
            expected = "Basic " + base64.b64encode((APP_ID + ":" + TOKEN).encode()).decode()
            self.assertEqual(adapter.proxy_headers(proxy), {"Proxy-Authorization": expected})
        finally:
            adapter.close()
        self.assertNotIn(TOKEN, proxy)
        self.assertNotIn("@", child["SERVERWARE_PROXY_URL"])

    def test_unsafe_configuration_refused(self):
        for key, value in [("SERVERWARE_X_USERNAME", "Example"), ("SERVERWARE_X_USERNAME", ""),
                ("SERVERWARE_X_USERNAME", "a" * 16), ("SERVERWARE_X_USERNAME", "example?x=1"),
                ("SERVERWARE_X_USERNAME", "../other"), ("SERVERWARE_X_USERNAME", "caf\u00e9"),
                ("SERVERWARE_PROXY_URL", "http://proxy.test"),
                ("SERVERWARE_PROXY_URL", "https://user:pass@proxy.test"),
                ("SERVERWARE_PROXY_URL", "https://proxy.test/path"),
                ("SERVERWARE_PROXY_URL", "https://proxy.test?"),
                ("SERVERWARE_PROXY_URL", "https://proxy.test#"),
                ("SERVERWARE_PROXY_URL", "https://proxy.test:0"),
                ("SERVERWARE_PROXY_URL", "https://proxy.test:99999"),
                ("SERVERWARE_PROXY_URL", "https://proxy.test\n"),
                ("SERVERWARE_APP_ID", "not-an-application-id"),
                ("SERVERWARE_PROXY_TOKEN", "bad\nsecret"),
                ("SERVERWARE_CA_FILE", "relative.pem"), ("SERVERWARE_PROXY_CA_FILE", "")]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                username.child_environment({**self.env, key: value})

    def test_real_sdk_one_get_no_ambient_auth_or_request_rewriting(self):
        captured = []

        def send(adapter, request, **kwargs):
            captured.append((request, kwargs, adapter.max_retries))
            return response(request)

        with patch.dict(os.environ, {"HTTPS_PROXY": "http://wrong", "NO_PROXY": "*",
                "NETRC": "/wrong", "REQUESTS_CA_BUNDLE": "/wrong"}, clear=True), \
                patch("requests.sessions.get_netrc_auth", side_effect=AssertionError("netrc")), \
                patch("requests.sessions.get_environ_proxies", side_effect=AssertionError("environment")), \
                patch.object(HTTPAdapter, "send", send):
            self.assertEqual(username.read_username(self.env), ROW)
        self.assertEqual(len(captured), 1)
        request, options, retries = captured[0]
        self.assertEqual(request.method, "GET")
        self.assertEqual(request.url, "https://api.x.com/2/users/by/username/example")
        self.assertIsNone(request.body)
        self.assertEqual(request.headers["Authorization"], "Bearer " + username.PLACEHOLDER)
        self.assertEqual(request.headers["User-Agent"], "xdk-python/0.10.6")
        self.assertEqual(request.headers["Accept"], "*/*")
        self.assertEqual(request.headers["Connection"], "keep-alive")
        self.assertNotIn("Content-Type", request.headers)
        self.assertNotIn("Proxy-Authorization", request.headers)
        self.assertNotIn(TOKEN, repr(dict(request.headers)))
        self.assertEqual(options["timeout"], (5, 10))
        self.assertEqual(options["proxies"], {"https": username.settings(self.env)[1]})
        self.assertIsInstance(options["verify"], str)
        self.assertFalse(Path(options["verify"]).exists())  # Removed after SDK close.
        self.assertEqual(retries.total, 0)

    def test_connection_and_provider_failures_are_not_retried(self):
        for failure in (requests.Timeout("synthetic timeout"), requests.ConnectionError("synthetic error")):
            with self.subTest(failure=type(failure).__name__), \
                    patch.object(HTTPAdapter, "send", side_effect=failure) as send:
                with self.assertRaises(type(failure)):
                    username.read_username(self.env)
                self.assertEqual(send.call_count, 1)
        calls = []

        def failed(adapter, request, **kwargs):
            calls.append(request)
            return response(request, {"detail": "synthetic failure"}, 429)

        with patch.object(HTTPAdapter, "send", failed), self.assertRaises(requests.HTTPError):
            username.read_username(self.env)
        self.assertEqual(len(calls), 1)

    def test_redirect_refused_before_second_request(self):
        calls = []

        def redirect(adapter, request, **kwargs):
            calls.append(request)
            value = response(request, {}, 302)
            value.headers["Location"] = "https://other.example.test/"
            return value

        with patch.object(HTTPAdapter, "send", redirect), self.assertRaises(requests.TooManyRedirects):
            username.read_username(self.env)
        self.assertEqual(len(calls), 1)

    def test_stock_pool_has_independent_verified_outer_context(self):
        with username.configured_client({**self.env, "SERVERWARE_PROXY_CA_FILE": str(self.ca)}) as client:
            self.assertIs(type(client), Client)
            self.assertFalse(client.session.trust_env)
            self.assertEqual(client.session.max_redirects, 0)
            self.assertIsNone(client.access_token)
            self.assertIsNone(client.oauth2_auth)
            adapter = client.session.get_adapter(username.BASE_URL)
            request = requests.Request("GET", username.BASE_URL + "/2/users/by/username/example").prepare()
            pool = adapter.get_connection_with_tls_context(request, verify=client.session.verify,
                proxies=client.session.proxies)
            self.assertEqual(pool.cert_reqs, "CERT_REQUIRED")
            self.assertEqual(pool.ca_certs, client.session.verify)
            self.assertIs(pool.proxy_config.ssl_context, adapter.outer_context)
            self.assertTrue(adapter.outer_context.check_hostname)
            self.assertEqual(adapter.outer_context.verify_mode, ssl.CERT_REQUIRED)
            self.assertIn("Proxy-Authorization", pool.proxy_headers)
            # This invokes the pinned urllib3 policy branch, NOT a TLS handshake.
            connection = pool._new_conn()
            sentinel = object()
            with patch.object(urllib3.connection, "_ssl_wrap_socket_and_match_hostname",
                    return_value=SimpleNamespace(socket=sentinel, is_verified=True)) as wrap:
                self.assertIs(connection._connect_tls_proxy("proxy.example.test", sentinel), sentinel)
            options = wrap.call_args.kwargs
            self.assertIs(options["ssl_context"], adapter.outer_context)
            self.assertIsNone(options["ca_certs"])  # Inner trust must not leak into outer context.
            self.assertIsNone(options["ca_cert_dir"])
            self.assertIsNone(options["ca_cert_data"])
            self.assertEqual(options["cert_reqs"], ssl.CERT_REQUIRED)

    def test_public_ca_validation_and_temporary_bundle_cleanup(self):
        with username.request_ca_bundle(str(self.ca)) as bundle:
            self.assertEqual(Path(bundle).stat().st_mode & 0o777, 0o600)
            content = Path(bundle).read_bytes()
            self.assertTrue(content.startswith(Path(certifi.where()).read_bytes()))
            self.assertTrue(content.endswith(self.pem + b"\n"))
        self.assertFalse(Path(bundle).exists())
        for raw in (b"", b"not a certificate", b"x" * 65537,
                b"-----BEGIN PRIVATE KEY-----\nnot-public\n"):
            self.ca.write_bytes(raw)
            with self.subTest(size=len(raw)), self.assertRaises((ValueError, ssl.SSLError)):
                username.public_ca(str(self.ca))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        with self.assertRaises(ValueError):
            username.BoundedAdapter(context)

    def test_incomplete_wrong_user_and_error_envelopes_are_not_success(self):
        bodies = ({}, {"data": {"id": "123"}}, {"data": {**ROW, "username": "other"}},
            {"data": {**ROW, "name": "x" * 201}},
            {"errors": [{"title": "Not found", "type": "about:blank"}]})
        for body in bodies:
            def send(adapter, request, **kwargs):
                return response(request, body)
            with self.subTest(body=body), patch.object(HTTPAdapter, "send", send), self.assertRaises(ValueError):
                username.read_username(self.env)

    def test_launcher_single_bounded_child_and_closed_result(self):
        result = SimpleNamespace(returncode=0, stdout=json.dumps(ROW).encode(), stderr=b"")
        with patch.object(username.subprocess, "run", return_value=result) as run:
            before = dict(os.environ)
            self.assertEqual(username.launch(self.env), ROW)
            self.assertEqual(dict(os.environ), before)
        run.assert_called_once()
        args, options = run.call_args
        self.assertNotIn(TOKEN, repr(args))
        self.assertEqual(options["env"], self.env)
        self.assertEqual(options["timeout"], 60)
        self.assertFalse(options["check"])
        for invalid in (SimpleNamespace(returncode=1, stdout=b"{}", stderr=TOKEN.encode()),
                SimpleNamespace(returncode=0, stdout=b"x" * 4097, stderr=b""),
                SimpleNamespace(returncode=0, stdout=b"{}", stderr=b"")):
            with patch.object(username.subprocess, "run", return_value=invalid), self.assertRaises(ValueError):
                username.launch(self.env)

    def test_failure_output_is_fixed_and_redacted(self):
        output, errors = io.StringIO(), io.StringIO()
        with patch.object(username, "launch", side_effect=RuntimeError(TOKEN)), \
                patch("sys.stdout", output), patch("sys.stderr", errors):
            self.assertEqual(username.main([]), 1)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(errors.getvalue(), username.FAILURE + "\n")
        self.assertNotIn(TOKEN, errors.getvalue())


if __name__ == "__main__":
    unittest.main()
