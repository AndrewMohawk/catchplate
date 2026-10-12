"""Actual pinned SDK with intercepted Requests sends; no proxy/provider calls."""
import base64
import io
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import certifi
import requests
from requests.adapters import HTTPAdapter
from xdk import Client

import post


def no_network(event, args):
    if event.startswith("socket.") or event in {"subprocess.Popen", "os.system"}:
        raise AssertionError("Offline test attempted network or process execution")


# Dependencies can probe IPv6 support at import. Every test operation below is
# socket/process forbidden; only the final HTTPAdapter.send is substituted.
sys.addaudithook(no_network)
APP_ID = "12345678-1234-4234-8234-123456789abc"
TOKEN = "synthetic-app-password:@/?#%"
TEXT = "Reviewed text\nwith\ttabs\rand a snowman \u2603"
RESULT = {"status": 201, "id": "123456789"}


def response(request, body=None, status=201, raw=None):
    value = requests.Response()
    value.status_code = status
    value.headers["Content-Type"] = "application/json"
    value._content = (json.dumps({"data": {"id": RESULT["id"], "text": TEXT}} if body is None else body).encode()
        if raw is None else raw)
    value._content_consumed = True
    value.request, value.url = request, request.url
    return value


class PostExampleTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="x-post-offline-")
        self.addCleanup(directory.cleanup)
        self.pem = re.search(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            Path(certifi.where()).read_bytes(), re.S).group()
        self.ca = Path(directory.name) / "public.pem"
        self.ca.write_bytes(self.pem)
        self.env = {"SERVERWARE_PROXY_URL": "https://proxy.example.test:8443", "SERVERWARE_APP_ID": APP_ID,
            "SERVERWARE_PROXY_TOKEN": TOKEN, "SERVERWARE_CA_FILE": str(self.ca),
            "SERVERWARE_X_POST_TEXT": TEXT, "SERVERWARE_X_POST_CONFIRM": "post-once"}

    def test_installed_pins(self):
        post.check_versions()

    def test_real_sdk_exact_one_text_only_post_and_user_access_token(self):
        calls = []
        def send(adapter, request, **kwargs):
            calls.append((request, kwargs, adapter.max_retries))
            return response(request)
        with patch.dict(os.environ, {"HTTPS_PROXY": "http://wrong", "NO_PROXY": "*", "NETRC": "/wrong"}, clear=True), \
                patch("requests.sessions.get_netrc_auth", side_effect=AssertionError("netrc")), \
                patch("requests.sessions.get_environ_proxies", side_effect=AssertionError("environment")), \
                patch.object(Client, "refresh_token", side_effect=AssertionError("refresh")), \
                patch.object(HTTPAdapter, "send", send):
            self.assertEqual(post.create_post(self.env), RESULT)
        self.assertEqual(len(calls), 1)
        request, options, retries = calls[0]
        self.assertEqual((request.method, request.url), ("POST", "https://api.x.com/2/tweets"))
        self.assertEqual(request.body, json.dumps({"text": TEXT}, allow_nan=False).encode())
        self.assertEqual(json.loads(request.body), {"text": TEXT})
        self.assertEqual(request.headers["Authorization"], "Bearer serverware-x-post-placeholder-v1")
        self.assertEqual(request.headers["Content-Type"], "application/json")
        self.assertEqual(request.headers["Content-Length"], str(len(request.body)))
        self.assertEqual(request.headers["User-Agent"], "xdk-python/0.10.6")
        self.assertNotIn("Proxy-Authorization", request.headers)
        self.assertNotIn(TOKEN, repr(dict(request.headers)))
        self.assertEqual(options["timeout"], (5, 10))
        self.assertTrue(options["stream"])
        self.assertEqual(options["proxies"], {"https": post.settings(self.env)[1]})
        self.assertFalse(Path(options["verify"]).exists())
        self.assertEqual(retries.total, 0)

    def test_text_utf8_and_actual_json_wire_bounds_without_normalization(self):
        for text in ("x", TEXT, "a" * 16384, '"' * 16378, "x" * 1000, "\n\t\r"):
            self.assertEqual(post.text_input(text), text)
        self.assertEqual(len(json.dumps({"text": '"' * 16378}).encode()), 32768)
        for text in (None, "", "a" * 16385, '"' * 16379, "\u2603" * 6000, "bad\0text", "\ud800"):
            with self.subTest(kind=type(text).__name__), self.assertRaises((ValueError, UnicodeError)):
                post.text_input(text)
        calls = []
        def send(adapter, request, **kwargs):
            calls.append(request)
            return response(request)
        with patch.object(HTTPAdapter, "send", send):
            self.assertEqual(post.create_post({**self.env, "SERVERWARE_X_POST_TEXT": '"' * 16378}), RESULT)
        self.assertEqual(len(calls[0].body), 32768)

    def test_confirmation_and_unsafe_configuration_fail_before_send(self):
        invalid = [("SERVERWARE_X_POST_CONFIRM", ""), ("SERVERWARE_X_POST_CONFIRM", "true"),
            ("SERVERWARE_X_POST_CONFIRM", "post-once "), ("SERVERWARE_X_POST_TEXT", ""),
            ("SERVERWARE_PROXY_URL", "http://proxy.test"), ("SERVERWARE_PROXY_URL", "https://user:secret@proxy.test"),
            ("SERVERWARE_PROXY_URL", "https://proxy.test/path"), ("SERVERWARE_PROXY_URL", "https://proxy.test?"),
            ("SERVERWARE_PROXY_URL", "https://proxy.test#"), ("SERVERWARE_PROXY_URL", "https://proxy.test:0"),
            ("SERVERWARE_PROXY_URL", "https://proxy.test:99999"), ("SERVERWARE_PROXY_URL", "https://proxy.test\n"),
            ("SERVERWARE_APP_ID", "wrong"), ("SERVERWARE_PROXY_TOKEN", "secret\n"),
            ("SERVERWARE_CA_FILE", "relative.pem"), ("SERVERWARE_PROXY_CA_FILE", "")]
        with patch.object(HTTPAdapter, "send", side_effect=AssertionError("send")) as send:
            for key, value in invalid:
                with self.subTest(key=key), self.assertRaises((ValueError, UnicodeError)):
                    post.create_post({**self.env, key: value})
        send.assert_not_called()

    def test_environment_and_outer_basic_are_separate_from_provider_authorization(self):
        ambient = {**self.env, "X_ACCESS_TOKEN": "never-forward", "X_BEARER_TOKEN": "never-forward",
            "HOME": "/ambient", "HTTPS_PROXY": "http://wrong", "NO_PROXY": "*", "NETRC": "/wrong",
            "REQUESTS_CA_BUNDLE": "/wrong", "SSLKEYLOGFILE": "/wrong", "PYTHONPATH": "/wrong"}
        original = dict(ambient)
        self.assertEqual(post.child_environment(ambient), self.env)
        self.assertEqual(ambient, original)
        _, proxy = post.settings(self.env)
        adapter = HTTPAdapter()
        try:
            self.assertEqual(adapter.proxy_headers(proxy), {"Proxy-Authorization":
                "Basic " + base64.b64encode((APP_ID + ":" + TOKEN).encode()).decode()})
        finally:
            adapter.close()
        self.assertNotIn(TOKEN, proxy)

    def test_client_has_no_oauth_exchange_refresh_or_ambient_auth(self):
        with post.configured_client(self.env) as client:
            self.assertIs(type(client), Client)
            self.assertEqual(client.access_token, post.PLACEHOLDER)
            self.assertIsNone(client.bearer_token)
            self.assertIsNone(client.oauth2_auth)
            self.assertIsNone(client.auth)
            self.assertIsNone(client.token)
            self.assertFalse(client.session.trust_env)
            self.assertEqual(client.session.max_redirects, 0)

    def test_both_tls_contexts_remain_verified_and_separate(self):
        with post.configured_client({**self.env, "SERVERWARE_PROXY_CA_FILE": str(self.ca)}) as client:
            adapter = client.session.get_adapter(post.BASE_URL)
            request = requests.Request("POST", post.BASE_URL + "/2/tweets", json={"text": TEXT}).prepare()
            pool = adapter.get_connection_with_tls_context(request, verify=client.session.verify,
                proxies=client.session.proxies)
            self.assertEqual(pool.cert_reqs, "CERT_REQUIRED")
            self.assertEqual(pool.ca_certs, client.session.verify)
            self.assertIs(pool.proxy_config.ssl_context, adapter.outer_context)
            self.assertEqual(adapter.outer_context.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(adapter.outer_context.check_hostname)
            self.assertGreaterEqual(adapter.outer_context.minimum_version, ssl.TLSVersion.TLSv1_2)
            self.assertIn("Proxy-Authorization", pool.proxy_headers)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        with self.assertRaises(ValueError): post.SinglePostAdapter(context, TEXT)

    def test_ca_files_are_public_bounded_and_temporary(self):
        with post.request_ca_bundle(str(self.ca)) as bundle:
            self.assertEqual(Path(bundle).stat().st_mode & 0o777, 0o600)
            self.assertTrue(Path(bundle).read_bytes().endswith(self.pem + b"\n"))
        self.assertFalse(Path(bundle).exists())
        for raw in (b"", b"bad", b"x" * 65537, b"-----BEGIN PRIVATE KEY-----\nprivate"):
            self.ca.write_bytes(raw)
            with self.assertRaises((ValueError, ssl.SSLError)): post.public_ca(str(self.ca))

    def test_all_non201_including_withheld409_are_unknown_and_not_retried(self):
        for status in (200, 204, 301, 302, 307, 308, 400, 401, 403, 409, 429, 500, 503):
            calls = []
            def send(adapter, request, **kwargs):
                calls.append(request)
                result = response(request, {"error": TOKEN + TEXT}, status)
                result.headers["Location"] = "https://elsewhere.invalid/"
                return result
            with self.subTest(status=status), patch.object(HTTPAdapter, "send", send), \
                    self.assertRaises(post.OutcomeUnknown) as error:
                post.create_post(self.env)
            self.assertEqual(str(error.exception), post.UNKNOWN)
            self.assertEqual(len(calls), 1)

    def test_transport_errors_interruption_and_lost_response_never_replay(self):
        for failure in (requests.Timeout(TOKEN), requests.ConnectionError(TOKEN),
                requests.exceptions.SSLError(TOKEN), OSError(TOKEN), KeyboardInterrupt()):
            with self.subTest(kind=type(failure).__name__), \
                    patch.object(HTTPAdapter, "send", side_effect=failure) as send, \
                    self.assertRaises(post.OutcomeUnknown):
                post.create_post(self.env)
            self.assertEqual(send.call_count, 1)

    def test_201_invalid_incomplete_or_oversized_response_is_unknown(self):
        bodies = [b"not JSON", b"{}", b'{"data":{"id":"123"}}',
            json.dumps({"data": {"id": "not-a-post", "text": TEXT}}).encode(),
            json.dumps({"data": {"id": "1" * 21, "text": TEXT}}).encode(),
            json.dumps({"errors": [{"title": "Withheld", "type": "about:blank"}]}).encode(),
            b" " * 65537]
        for raw in bodies:
            calls = []
            def send(adapter, request, **kwargs):
                calls.append(request)
                return response(request, raw=raw)
            with self.subTest(length=len(raw)), patch.object(HTTPAdapter, "send", send), self.assertRaises(post.OutcomeUnknown):
                post.create_post(self.env)
            self.assertEqual(len(calls), 1)

    def test_actual_adapter_refuses_second_dispatch_and_request_retargeting(self):
        with post.configured_client(self.env) as client:
            adapter = client.session.get_adapter(post.BASE_URL)
            prepared = client.session.prepare_request(requests.Request("POST", post.BASE_URL + "/2/tweets",
                json={"text": TEXT}, headers={"Authorization": "Bearer " + post.PLACEHOLDER}))
            with patch.object(HTTPAdapter, "send", side_effect=lambda request, **kwargs: response(request)) as send:
                adapter.send(prepared, verify=client.session.verify, proxies=client.session.proxies)
                with self.assertRaises(post.OutcomeUnknown): adapter.send(prepared, verify=client.session.verify)
            self.assertEqual(send.call_count, 1)
        for url, method, document in ((post.BASE_URL + "/2/tweets?extra=1", "POST", {"text": TEXT}),
                (post.BASE_URL + "/2/tweets", "PUT", {"text": TEXT}),
                (post.BASE_URL + "/2/tweets", "POST", {"text": TEXT, "reply": {}})):
            with post.configured_client(self.env) as client:
                adapter = client.session.get_adapter(post.BASE_URL)
                request = client.session.prepare_request(requests.Request(method, url, json=document,
                    headers={"Authorization": "Bearer " + post.PLACEHOLDER}))
                with patch.object(HTTPAdapter, "send") as send, self.assertRaises(ValueError):
                    adapter.send(request, verify=client.session.verify)
                send.assert_not_called()

    def test_launcher_has_one_deadline_and_no_raw_failure_output(self):
        returned = SimpleNamespace(returncode=0, stdout=json.dumps(RESULT).encode(), stderr=b"")
        with patch.object(post.subprocess, "run", return_value=returned) as run:
            self.assertEqual(post.launch(self.env), RESULT)
        run.assert_called_once()
        args, options = run.call_args
        self.assertEqual(options["env"], self.env)
        self.assertEqual(options["timeout"], 60)
        self.assertNotIn(TOKEN, repr(args))
        self.assertNotIn(TEXT, repr(args))
        for returned in (SimpleNamespace(returncode=2, stdout=b"", stderr=TOKEN.encode()),
                SimpleNamespace(returncode=-9, stdout=b"", stderr=b""),
                SimpleNamespace(returncode=0, stdout=b"{}", stderr=b""),
                SimpleNamespace(returncode=0, stdout=b"x" * 4097, stderr=b"")):
            with patch.object(post.subprocess, "run", return_value=returned) as run, self.assertRaises(post.OutcomeUnknown):
                post.launch(self.env)
            run.assert_called_once()
        with patch.object(post.subprocess, "run", side_effect=subprocess.TimeoutExpired("child", 60, output=TOKEN)) as run, \
                self.assertRaises(post.OutcomeUnknown):
            post.launch(self.env)
        run.assert_called_once()

    def test_cli_success_and_both_failures_are_closed_and_secret_free(self):
        self.assertEqual(post.summary({"status": 201, "id": "1" * 20}), {"status": 201, "id": "1" * 20})
        for value, code, expected in ((RESULT, 0, ""), (post.OutcomeUnknown(), 2, post.UNKNOWN + "\n"),
                (ValueError(TOKEN + TEXT), 1, post.FAILURE + "\n")):
            out, err = io.StringIO(), io.StringIO()
            behavior = {"side_effect": value} if isinstance(value, Exception) else {"return_value": value}
            with patch.object(post, "launch", **behavior), patch("sys.stdout", out), patch("sys.stderr", err):
                self.assertEqual(post.main([]), code)
            self.assertEqual(err.getvalue(), expected)
            self.assertEqual(out.getvalue(), json.dumps(RESULT) + "\n" if code == 0 else "")
            self.assertNotIn(TOKEN, out.getvalue() + err.getvalue())
            self.assertNotIn(TEXT, out.getvalue() + err.getvalue())
        # Losing the local acknowledgment after success is not a new assertion
        # that nothing was posted, and must not become exit 1/preparation-failed.
        out, err = io.StringIO(), io.StringIO()
        with patch.object(post, "launch", return_value=RESULT) as launch, \
                patch.object(out, "write", side_effect=OSError(TOKEN)), \
                patch("sys.stdout", out), patch("sys.stderr", err):
            self.assertEqual(post.main([]), 2)
        launch.assert_called_once()
        self.assertEqual(err.getvalue(), post.UNKNOWN + "\n")


if __name__ == "__main__":
    unittest.main()
