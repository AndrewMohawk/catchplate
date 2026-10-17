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
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

CONFIG_ONLY = "--config-only" in sys.argv
if CONFIG_ONLY:
    sys.argv.remove("--config-only")
    # Import-only stubs: this mode tests JSON/CLI behavior, never SDK transport.
    stubs = {name: ModuleType(name) for name in ("requests", "requests.adapters")}
    stubs["requests.adapters"].HTTPAdapter = type("UnavailableAdapter", (), {})
    with patch.dict(sys.modules, stubs):
        import username
else:
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


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="x-username-config-offline-")
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "catchplate-client.private.json"
        self.value = {"application_id": APP_ID, "access_rule_id": "00000000-0000-4000-8000-000000000002",
            "proxy_authentication": "basic_and_bearer_v1", "proxy_username": APP_ID, "proxy_password": TOKEN,
            "proxy_url": "https://proxy.example.test:8443", "token_expires_at_epoch_ms": 2**53 - 1,
            "ca_file": "./catchplate-ca.pem", "operation_bundle": "x_username_read_v1", "username": "example",
            "upstream_url": "https://api.x.com/2/users/by/username/example", "methods": ["GET"],
            "credential_input": "replace_exact", "response_mode": "x_app_read_json_v1",
            "request_headers": {"Authorization": "ignored"}, "request_body": {"text": "ignored"},
            "client_recipe": {"command": "never-execute", "environment": {"HTTPS_PROXY": "wrong"}}}

    def write(self, value=None):
        self.path.write_text(json.dumps(self.value if value is None else value), encoding="utf-8")
        return self.path

    def test_download_maps_exact_username_and_relative_ca_without_recipe_execution(self):
        with patch.object(username.subprocess, "run") as run:
            selected = username.configuration_environment(self.write())
        run.assert_not_called()
        self.assertEqual(set(selected), set(username.REQUIRED_ENV))
        self.assertEqual(selected["CATCHPLATE_CA_FILE"], str(self.path.parent / "catchplate-ca.pem"))
        self.assertEqual(selected["CATCHPLATE_X_USERNAME"], "example")
        self.assertEqual(selected["CATCHPLATE_PROXY_TOKEN"], TOKEN)
        self.value["proxy_ca_file"] = "./proxy's $literal.pem"
        selected = username.configuration_environment(self.write())
        self.assertEqual(selected["CATCHPLATE_PROXY_CA_FILE"], str(self.path.parent / "proxy's $literal.pem"))

    def test_scope_identity_expiry_and_connection_mismatches_refuse(self):
        cases = (("application_id", "bad"), ("access_rule_id", "bad"), ("proxy_username", "wrong"),
            ("proxy_authentication", "bearer"), ("operation_bundle", "x_text_post_v1"), ("username", "Example"),
            ("username", "other"), ("upstream_url", self.value["upstream_url"] + "?extra=1"),
            ("methods", ["POST"]), ("credential_input", "none"), ("response_mode", "passthrough"),
            ("proxy_url", "http://proxy.test"), ("proxy_password", "secret\n"), ("ca_file", ""),
            ("proxy_ca_file", False),
            *(("token_expires_at_epoch_ms", expiry) for expiry in (0, True, 2**53, 2**53 - 1.0, "future")))
        for key, invalid in cases:
            with self.subTest(key=key, value=invalid), self.assertRaises(ValueError):
                username.configuration_environment(self.write({**self.value, key: invalid}))
        with patch.object(username.time, "time_ns", return_value=1234 * 1_000_000), self.assertRaises(ValueError):
            username.configuration_environment(self.write({**self.value, "token_expires_at_epoch_ms": 1234}))

    def test_configuration_is_bounded_regular_and_strict_json(self):
        for raw in (b"", b"[]", b"{", b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1e309}',
                b"\xff", b" " * (username.MAX_CONFIG_BYTES + 1)):
            self.path.write_bytes(raw)
            with self.subTest(raw=raw[:20]), self.assertRaises(ValueError):
                username.configuration_environment(self.path)
        fifo = self.path.parent / "fifo"
        os.mkfifo(fifo)
        with self.assertRaises(ValueError): username.configuration_environment(fifo)
        link = self.path.parent / "link"
        link.symlink_to(self.path)
        with self.assertRaises(OSError): username.configuration_environment(link)
        raw = json.dumps(self.value).encode()
        self.path.write_bytes(raw + b" " * (username.MAX_CONFIG_BYTES - len(raw)))
        self.assertEqual(username.configuration_environment(self.path)["CATCHPLATE_APP_ID"], APP_ID)

    def test_cli_preserves_env_mode_and_uses_config_without_token_arguments(self):
        with patch.object(username, "launch", return_value=ROW) as launch, patch("sys.stdout", io.StringIO()):
            self.assertEqual(username.main([]), 0)
            self.assertIs(launch.call_args.args[0], os.environ)
        with patch.dict(os.environ, {"CATCHPLATE_X_USERNAME": "wrong", "HTTPS_PROXY": "wrong"}, clear=True), \
                patch.object(username, "check_versions"), patch.object(username.subprocess, "run",
                    return_value=SimpleNamespace(returncode=0, stdout=json.dumps(ROW).encode())) as run, \
                patch("sys.stdout", io.StringIO()):
            self.assertEqual(username.main(["--config", str(self.write())]), 0)
        self.assertNotIn(TOKEN, " ".join(run.call_args.args[0]))
        self.assertNotIn("--config", run.call_args.args[0])
        self.assertEqual(run.call_args.kwargs["env"]["CATCHPLATE_X_USERNAME"], "example")
        self.assertEqual(set(run.call_args.kwargs["env"]), set(username.REQUIRED_ENV))

    def test_bad_json_and_child_config_fail_before_launch_with_redacted_output(self):
        self.path.write_text('{"private":"' + TOKEN + '",', encoding="utf-8")
        for args in (["--config", str(self.path)], ["--child", "--config", str(self.path)]):
            with patch.object(username, "launch") as launch, patch.object(username, "check_versions") as versions, \
                    patch("sys.stdout", io.StringIO()) as out, patch("sys.stderr", io.StringIO()) as err:
                self.assertEqual(username.main(args), 1)
            launch.assert_not_called(); versions.assert_not_called()
            self.assertEqual(out.getvalue(), "")
            self.assertEqual(err.getvalue(), username.FAILURE + "\n")


@unittest.skipIf(CONFIG_ONLY, "SDK checks require the prepared pinned dependencies")
class ExampleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="x-example-offline-")
        self.addCleanup(self.temp.cleanup)
        self.pem = re.search(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            Path(certifi.where()).read_bytes(), flags=re.S).group()
        self.ca = Path(self.temp.name) / "public.pem"
        self.ca.write_bytes(self.pem)
        self.env = {"CATCHPLATE_PROXY_URL": "https://proxy.example.test:8443",
            "CATCHPLATE_APP_ID": APP_ID, "CATCHPLATE_PROXY_TOKEN": TOKEN,
            "CATCHPLATE_CA_FILE": str(self.ca), "CATCHPLATE_X_USERNAME": "example"}

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
        self.assertNotIn("@", child["CATCHPLATE_PROXY_URL"])

    def test_unsafe_configuration_refused(self):
        for key, value in [("CATCHPLATE_X_USERNAME", "Example"), ("CATCHPLATE_X_USERNAME", ""),
                ("CATCHPLATE_X_USERNAME", "a" * 16), ("CATCHPLATE_X_USERNAME", "example?x=1"),
                ("CATCHPLATE_X_USERNAME", "../other"), ("CATCHPLATE_X_USERNAME", "caf\u00e9"),
                ("CATCHPLATE_PROXY_URL", "http://proxy.test"),
                ("CATCHPLATE_PROXY_URL", "https://user:pass@proxy.test"),
                ("CATCHPLATE_PROXY_URL", "https://proxy.test/path"),
                ("CATCHPLATE_PROXY_URL", "https://proxy.test?"),
                ("CATCHPLATE_PROXY_URL", "https://proxy.test#"),
                ("CATCHPLATE_PROXY_URL", "https://proxy.test:0"),
                ("CATCHPLATE_PROXY_URL", "https://proxy.test:99999"),
                ("CATCHPLATE_PROXY_URL", "https://proxy.test\n"),
                ("CATCHPLATE_APP_ID", "not-an-application-id"),
                ("CATCHPLATE_PROXY_TOKEN", "bad\nsecret"),
                ("CATCHPLATE_CA_FILE", "relative.pem"), ("CATCHPLATE_PROXY_CA_FILE", "")]:
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
        with username.configured_client({**self.env, "CATCHPLATE_PROXY_CA_FILE": str(self.ca)}) as client:
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
