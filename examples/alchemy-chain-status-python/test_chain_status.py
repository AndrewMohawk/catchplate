"""Real pinned SDK, synthetic send boundary: no socket, TLS or proxy acceptance."""
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
        import chain_status as example
else:
    import certifi
    import requests
    from requests.adapters import HTTPAdapter
    import urllib3.connection
    from web3 import HTTPProvider, Web3
    from web3.exceptions import Web3Exception
    import chain_status as example


def no_network(event, args):
    if event.startswith("socket."):
        raise AssertionError("Offline SDK test attempted socket access")


# Imports may probe local IPv6 support. All test operations forbid sockets.
sys.addaudithook(no_network)
APP = "12345678-1234-4234-8234-123456789abc"
TOKEN = "synthetic-app-password:@/?#%"
EXPECTED = {"chain": "eth-mainnet", "chain_id": 1, "block_number": 123456}
UA = "web3.py/7.15.0/web3.providers.rpc.rpc.HTTPProvider"


def response(request, *, value=None, status=200, raw=None, headers=None):
    rpc = json.loads(request.body)
    if value is None:
        value = {"jsonrpc": "2.0", "id": rpc["id"],
            "result": "0x1" if rpc["method"] == "eth_chainId" else "0x1e240"}
    result = requests.Response()
    result.status_code = status
    result.request, result.url = request, request.url
    result.headers["Content-Type"] = "application/json"
    result.headers.update(headers or {})
    class Raw(io.BytesIO):
        def release_conn(self): self.close()
    result.raw = Raw(json.dumps(value).encode() if raw is None else raw)
    return result


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="alchemy-config-offline-")
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "serverware-client.private.json"
        self.value = {"application_id": APP, "access_rule_id": "00000000-0000-4000-8000-000000000002",
            "proxy_authentication": "basic_and_bearer_v1", "proxy_username": APP, "proxy_password": TOKEN,
            "proxy_url": "https://proxy.example.test:8443", "token_expires_at_epoch_ms": 2**53 - 1,
            "ca_file": "./serverware-ca.pem", "proxy_ca_file": None,
            "operation_bundle": "alchemy_chain_status_read_v1", "chain": "eth-mainnet",
            "upstream_url": "https://eth-mainnet.g.alchemy.com/v2", "methods": ["POST"],
            "rpc_methods": ["eth_chainId", "eth_blockNumber"], "credential_input": "replace_exact",
            "response_mode": "alchemy_rpc_read_json_v1", "request_headers": {"Authorization": "ignored"},
            "request_body": {"method": "eth_sendRawTransaction"},
            "client_recipe": {"command": "never-execute", "environment": {"HTTPS_PROXY": "wrong"}}}

    def write(self, value=None):
        self.path.write_text(json.dumps(self.value if value is None else value), encoding="utf-8")
        return self.path

    def test_download_maps_only_connection_data_and_relative_ca_paths(self):
        with patch.object(example.subprocess, "run") as run:
            selected = example.configuration_environment(self.write())
        run.assert_not_called()
        self.assertEqual(set(selected), set(example.REQUIRED_ENV))
        self.assertEqual(selected["SERVERWARE_CA_FILE"], str(self.path.parent / "serverware-ca.pem"))
        self.assertEqual(selected["SERVERWARE_PROXY_TOKEN"], TOKEN)
        self.assertEqual(example.settings(selected)[:2], ("eth-mainnet", self.value["upstream_url"]))
        self.value.update(chain="eth-sepolia", upstream_url="https://eth-sepolia.g.alchemy.com/v2",
            proxy_ca_file="./proxy's $literal.pem")
        selected = example.configuration_environment(self.write())
        self.assertEqual(selected["SERVERWARE_ALCHEMY_CHAIN"], "eth-sepolia")
        self.assertEqual(selected["SERVERWARE_PROXY_CA_FILE"], str(self.path.parent / "proxy's $literal.pem"))

    def test_scope_identity_expiry_and_connection_mismatches_refuse(self):
        cases = (("application_id", "bad"), ("access_rule_id", "bad"), ("proxy_username", "wrong"),
            ("proxy_authentication", "bearer"), ("operation_bundle", "x_text_post_v1"), ("chain", "polygon"),
            ("upstream_url", self.value["upstream_url"] + "/private-key"), ("methods", ["GET"]),
            ("rpc_methods", ["eth_chainId", "eth_sendRawTransaction"]), ("credential_input", "none"),
            ("response_mode", "passthrough"), ("proxy_url", "http://proxy.test"),
            ("proxy_password", "secret\n"), ("ca_file", ""), ("proxy_ca_file", False),
            *(("token_expires_at_epoch_ms", expiry) for expiry in (0, True, 2**53, 2**53 - 1.0, "future")))
        for key, invalid in cases:
            with self.subTest(key=key, value=invalid), self.assertRaises(ValueError):
                example.configuration_environment(self.write({**self.value, key: invalid}))
        with patch.object(example.time, "time_ns", return_value=1234 * 1_000_000), self.assertRaises(ValueError):
            example.configuration_environment(self.write({**self.value, "token_expires_at_epoch_ms": 1234}))

    def test_configuration_is_bounded_regular_and_strict_json(self):
        for raw in (b"", b"[]", b"{", b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1e309}',
                b"\xff", b" " * (example.MAX_CONFIG_BYTES + 1)):
            self.path.write_bytes(raw)
            with self.subTest(raw=raw[:20]), self.assertRaises(ValueError):
                example.configuration_environment(self.path)
        fifo = self.path.parent / "fifo"
        os.mkfifo(fifo)
        with self.assertRaises(ValueError): example.configuration_environment(fifo)
        link = self.path.parent / "link"
        link.symlink_to(self.path)
        with self.assertRaises(OSError): example.configuration_environment(link)
        raw = json.dumps(self.value).encode()
        self.path.write_bytes(raw + b" " * (example.MAX_CONFIG_BYTES - len(raw)))
        self.assertEqual(example.configuration_environment(self.path)["SERVERWARE_APP_ID"], APP)

    def test_cli_preserves_env_mode_and_uses_config_without_token_arguments(self):
        with patch.object(example, "launch", return_value=EXPECTED) as launch, patch("sys.stdout", io.StringIO()):
            self.assertEqual(example.main([]), 0)
            self.assertIs(launch.call_args.args[0], os.environ)
        with patch.dict(os.environ, {"SERVERWARE_PROXY_TOKEN": "wrong", "HTTPS_PROXY": "wrong"}, clear=True), \
                patch.object(example, "check_versions"), patch.object(example.subprocess, "run",
                    return_value=SimpleNamespace(returncode=0, stdout=json.dumps(EXPECTED).encode())) as run, \
                patch("sys.stdout", io.StringIO()):
            self.assertEqual(example.main(["--config", str(self.write())]), 0)
        self.assertNotIn(TOKEN, " ".join(run.call_args.args[0]))
        self.assertNotIn("--config", run.call_args.args[0])
        self.assertEqual(run.call_args.kwargs["env"]["SERVERWARE_PROXY_TOKEN"], TOKEN)
        self.assertEqual(set(run.call_args.kwargs["env"]), set(example.REQUIRED_ENV))

    def test_bad_json_and_child_config_fail_before_launch_with_redacted_output(self):
        self.path.write_text('{"private":"' + TOKEN + '",', encoding="utf-8")
        for args in (["--config", str(self.path)], ["--child", "--config", str(self.path)]):
            with patch.object(example, "launch") as launch, patch.object(example, "check_versions") as versions, \
                    patch("sys.stdout", io.StringIO()) as out, patch("sys.stderr", io.StringIO()) as err:
                self.assertEqual(example.main(args), 1)
            launch.assert_not_called(); versions.assert_not_called()
            self.assertEqual(out.getvalue(), "")
            self.assertEqual(err.getvalue(), example.FAILURE + "\n")


@unittest.skipIf(CONFIG_ONLY, "SDK checks require the prepared pinned dependencies")
class ExampleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="alchemy-sdk-offline-")
        self.addCleanup(self.temp.cleanup)
        self.pem = re.search(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            Path(certifi.where()).read_bytes(), re.S).group()
        self.ca = Path(self.temp.name) / "public.pem"
        self.ca.write_bytes(self.pem)
        self.env = {"SERVERWARE_PROXY_URL": "https://proxy.example.test:8443",
            "SERVERWARE_APP_ID": APP, "SERVERWARE_PROXY_TOKEN": TOKEN,
            "SERVERWARE_CA_FILE": str(self.ca), "SERVERWARE_ALCHEMY_CHAIN": "eth-mainnet"}

    def test_installed_pins(self):
        example.check_versions()

    def test_closed_config_and_basic_connect_auth_not_provider_auth(self):
        env = {**self.env, "ALCHEMY_API_KEY": "not-inherited", "WEB3_HTTP_PROVIDER_URI": "https://wrong/key",
            "HTTPS_PROXY": "http://wrong", "NO_PROXY": "*", "NETRC": "/wrong",
            "HOME": "/ambient", "SSLKEYLOGFILE": "/wrong", "REQUESTS_CA_BUNDLE": "/wrong",
            "PYTHONPATH": "/wrong"}
        original = dict(env)
        self.assertEqual(example.child_environment(env), self.env)
        self.assertEqual(env, original)
        chain, endpoint, proxy = example.settings(self.env)
        self.assertEqual((chain, endpoint), ("eth-mainnet", "https://eth-mainnet.g.alchemy.com/v2"))
        adapter = HTTPAdapter()
        try:
            self.assertEqual(adapter.proxy_headers(proxy), {"Proxy-Authorization":
                "Basic " + base64.b64encode((APP + ":" + TOKEN).encode()).decode()})
        finally: adapter.close()
        self.assertNotIn(TOKEN, proxy)
        for key, value in (("SERVERWARE_ALCHEMY_CHAIN", "mainnet"), ("SERVERWARE_ALCHEMY_CHAIN", "eth-mainnet/key"),
                ("SERVERWARE_PROXY_URL", "http://proxy.test"), ("SERVERWARE_PROXY_URL", "https://u:p@proxy.test"),
                ("SERVERWARE_PROXY_URL", "https://proxy.test/path"), ("SERVERWARE_PROXY_URL", "https://proxy.test?"),
                ("SERVERWARE_PROXY_URL", "https://proxy.test#"), ("SERVERWARE_PROXY_URL", "https://proxy.test:0"),
                ("SERVERWARE_PROXY_URL", "https://proxy.test:99999"), ("SERVERWARE_PROXY_URL", "https://proxy.test\n"),
                ("SERVERWARE_APP_ID", "wrong"), ("SERVERWARE_PROXY_TOKEN", "bad\nsecret"),
                ("SERVERWARE_PROXY_TOKEN", "x" * 8193), ("SERVERWARE_CA_FILE", "relative.pem"),
                ("SERVERWARE_PROXY_CA_FILE", "")):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                example.child_environment({**self.env, key: value})

    def test_actual_sdk_two_exact_posts_and_original_byte_serialization(self):
        calls = []
        def send(adapter, request, **options):
            calls.append((request, options, adapter.max_retries))
            return response(request)
        with patch.dict(os.environ, {"HTTPS_PROXY": "http://wrong", "NO_PROXY": "*", "NETRC": "/wrong"}, clear=True), \
                patch("requests.sessions.get_netrc_auth", side_effect=AssertionError("netrc")), \
                patch("requests.sessions.get_environ_proxies", side_effect=AssertionError("environment")), \
                patch.object(HTTPAdapter, "send", send):
            self.assertEqual(example.read_chain_status(self.env), EXPECTED)
        self.assertEqual(len(calls), 2)
        bodies = [b'{"jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 0}',
            b'{"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1}']
        for (request, options, retries), body in zip(calls, bodies):
            self.assertEqual((request.method, request.url, request.body),
                ("POST", "https://eth-mainnet.g.alchemy.com/v2", body))
            self.assertEqual(request.headers["Authorization"], "Bearer " + example.PLACEHOLDER)
            self.assertEqual(request.headers["User-Agent"], UA)
            self.assertEqual(request.headers["Content-Type"], "application/json")
            self.assertEqual(request.headers["Accept"], "*/*")
            self.assertEqual(request.headers["Connection"], "keep-alive")
            self.assertEqual(request.headers["Content-Length"], str(len(body)))
            self.assertEqual({name.lower() for name in request.headers}, {"authorization", "user-agent",
                "content-type", "accept", "accept-encoding", "connection", "content-length"})
            self.assertNotIn(TOKEN, repr(dict(request.headers)))
            self.assertNotIn(APP, repr(dict(request.headers)))
            self.assertEqual(options["proxies"], {"https": example.settings(self.env)[2]})
            self.assertEqual(options["timeout"], (5, 10))
            self.assertIs(options["stream"], True)
            self.assertEqual(retries.total, 0)
            self.assertFalse(Path(options["verify"]).exists())

    def test_actual_sepolia_and_wrong_chain_stops_before_second_call(self):
        for chain_id, expected_calls in ((11155111, 2), (1, 1)):
            calls = []
            def send(adapter, request, **options):
                calls.append(request)
                rpc = json.loads(request.body)
                return response(request, value={"jsonrpc": "2.0", "id": rpc["id"],
                    "result": hex(chain_id) if rpc["method"] == "eth_chainId" else "0x0"})
            env = {**self.env, "SERVERWARE_ALCHEMY_CHAIN": "eth-sepolia"}
            with patch.object(HTTPAdapter, "send", send):
                if chain_id == 1:
                    with self.assertRaises(ValueError): example.read_chain_status(env)
                else:
                    self.assertEqual(example.read_chain_status(env),
                        {"chain": "eth-sepolia", "chain_id": 11155111, "block_number": 0})
            self.assertEqual(len(calls), expected_calls)
            self.assertTrue(all(row.url == "https://eth-sepolia.g.alchemy.com/v2" for row in calls))

    def test_connection_http_and_rpc_errors_no_retry_or_success(self):
        for failure in (requests.Timeout("synthetic timeout"), requests.ConnectionError("synthetic error")):
            with patch.object(HTTPAdapter, "send", side_effect=failure) as send:
                with self.assertRaises(type(failure)): example.read_chain_status(self.env)
                self.assertEqual(send.call_count, 1)
        for status in (401, 403, 429, 503):
            with patch.object(HTTPAdapter, "send", side_effect=lambda request, **kw:
                    response(request, status=status)) as send:
                with self.assertRaises(requests.HTTPError): example.read_chain_status(self.env)
                self.assertEqual(send.call_count, 1)
        values = [{"jsonrpc": "2.0", "id": 0, "error": {"code": -32000, "message": "synthetic refusal"}},
            {"jsonrpc": "2.0", "id": 0}, {"jsonrpc": "wrong", "id": 0, "result": "0x1"}]
        for value in values:
            with patch.object(HTTPAdapter, "send", side_effect=lambda request, **kw:
                    response(request, value=value)) as send:
                with self.assertRaises((ValueError, Web3Exception)): example.read_chain_status(self.env)
                self.assertEqual(send.call_count, 1)

    def test_stream_bounds_media_redirects_and_framing_close_response(self):
        for raw, status, headers in ((b"{}", 302, {"Location": "https://other.test/"}),
                (b"{}", 200, {"Content-Encoding": "gzip"}),
                (b"{}", 200, {"Content-Type": "text/html"}),
                (b"x" * 65537, 200, {}), (b"{}", 200, {"Content-Length": "65537"}),
                (b"{}", 200, {"Content-Length": "02"}), (b"{}", 200, {"Content-Length": "3"})):
            captured = []
            def send(adapter, request, **options):
                result = response(request, raw=raw, status=status, headers=headers)
                captured.append(result)
                return result
            with patch.object(HTTPAdapter, "send", send), self.assertRaises(ValueError):
                example.read_chain_status(self.env)
            self.assertEqual(len(captured), 1)
            self.assertTrue(captured[0].raw.closed)
        # Exact boundary is accepted by the transport and decoded by the SDK.
        def padded(adapter, request, **options):
            rpc = json.loads(request.body)
            raw = json.dumps({"jsonrpc": "2.0", "id": rpc["id"],
                "result": "0x1" if rpc["method"] == "eth_chainId" else "0x1e240"}).encode()
            return response(request, raw=raw + b" " * (65536 - len(raw)), headers={"Content-Length": "65536"})
        with patch.object(HTTPAdapter, "send", padded):
            self.assertEqual(example.read_chain_status(self.env), EXPECTED)

    def test_actual_provider_and_separate_verified_proxy_tls_policies(self):
        with example.configured_client({**self.env, "SERVERWARE_PROXY_CA_FILE": str(self.ca)}) as client:
            self.assertIs(type(client), Web3)
            self.assertIs(type(client.provider), HTTPProvider)
            self.assertIsNone(client.provider.exception_retry_configuration)
            self.assertFalse(client.provider.cache_allowed_requests)
            session = client.provider._request_session_manager.cache_and_return_session(client.provider.endpoint_uri)
            self.assertFalse(session.trust_env)
            self.assertEqual(session.max_redirects, 0)
            adapter = session.get_adapter(client.provider.endpoint_uri)
            request = requests.Request("POST", client.provider.endpoint_uri, data=b"{}").prepare()
            pool = adapter.get_connection_with_tls_context(request, verify=session.verify, proxies=session.proxies)
            self.assertEqual(pool.cert_reqs, "CERT_REQUIRED")
            self.assertEqual(pool.ca_certs, session.verify)
            self.assertIs(pool.proxy_config.ssl_context, adapter.outer_context)
            self.assertTrue(adapter.outer_context.check_hostname)
            self.assertEqual(adapter.outer_context.verify_mode, ssl.CERT_REQUIRED)
            self.assertIn("Proxy-Authorization", pool.proxy_headers)
            connection, sentinel = pool._new_conn(), object()
            with patch.object(urllib3.connection, "_ssl_wrap_socket_and_match_hostname",
                    return_value=SimpleNamespace(socket=sentinel, is_verified=True)) as wrap:
                self.assertIs(connection._connect_tls_proxy("proxy.example.test", sentinel), sentinel)
            self.assertIs(wrap.call_args.kwargs["ssl_context"], adapter.outer_context)
            for field in ("ca_certs", "ca_cert_dir", "ca_cert_data"):
                self.assertIsNone(wrap.call_args.kwargs[field])
            self.assertEqual(wrap.call_args.kwargs["cert_reqs"], ssl.CERT_REQUIRED)

    def test_transport_refuses_direct_fallback_mutation_and_third_dispatch(self):
        with example.configured_client(self.env) as client:
            session = client.provider._request_session_manager.cache_and_return_session(client.provider.endpoint_uri)
            adapter = session.get_adapter(client.provider.endpoint_uri)
            request = session.prepare_request(requests.Request("POST", client.provider.endpoint_uri, data=b"{}"))
            good = {"verify": session.verify, "proxies": session.proxies}
            for changes in ({"verify": False}, {"proxies": {}}, {"cert": "private.pem"}):
                with patch.object(HTTPAdapter, "send") as send, self.assertRaises(ValueError):
                    adapter.send(request, **{**good, **changes})
                send.assert_not_called()
            for attribute, value in (("url", "https://other.test/v2"), ("method", "GET"), ("body", b"")):
                with patch.object(request, attribute, value), patch.object(HTTPAdapter, "send") as send, self.assertRaises(ValueError):
                    adapter.send(request, **good)
                send.assert_not_called()
            adapter.attempts = 2
            with patch.object(HTTPAdapter, "send") as send, self.assertRaises(ValueError):
                adapter.send(request, **good)
            send.assert_not_called()

    def test_ca_bounds_cleanup_and_closed_summary(self):
        with example.request_ca_bundle(str(self.ca)) as bundle:
            self.assertEqual(Path(bundle).stat().st_mode & 0o777, 0o600)
            self.assertTrue(Path(bundle).read_bytes().endswith(self.pem + b"\n"))
        self.assertFalse(Path(bundle).exists())
        for raw in (b"", b"invalid", b"x" * 65537, b"-----BEGIN PRIVATE KEY-----\n"):
            self.ca.write_bytes(raw)
            with self.assertRaises((ValueError, ssl.SSLError)): example.public_ca(str(self.ca))
        for changed in ({}, {**EXPECTED, "secret": TOKEN}, {**EXPECTED, "chain_id": True},
                {**EXPECTED, "block_number": True}, {**EXPECTED, "block_number": -1},
                {**EXPECTED, "block_number": 2**64}, {**EXPECTED, "chain": "eth-sepolia"}):
            with self.assertRaises(ValueError): example.summary(changed, "eth-mainnet")

    def test_launcher_deadline_single_child_and_fixed_redacted_failure(self):
        result = SimpleNamespace(returncode=0, stdout=json.dumps(EXPECTED).encode(), stderr=b"")
        with patch.object(example.subprocess, "run", return_value=result) as run:
            self.assertEqual(example.launch(self.env), EXPECTED)
        run.assert_called_once()
        args, options = run.call_args
        self.assertNotIn(TOKEN, repr(args))
        self.assertIn("-I", args[0])
        self.assertEqual(options["env"], self.env)
        self.assertEqual(options["timeout"], 60)
        self.assertEqual(options["stdin"], subprocess.DEVNULL)
        for invalid in (SimpleNamespace(returncode=1, stdout=b"{}", stderr=TOKEN.encode()),
                SimpleNamespace(returncode=0, stdout=b"x" * 4097, stderr=b""),
                SimpleNamespace(returncode=0, stdout=b"{}", stderr=b"")):
            with patch.object(example.subprocess, "run", return_value=invalid), self.assertRaises(ValueError):
                example.launch(self.env)
        output, errors = io.StringIO(), io.StringIO()
        with patch.object(example, "launch", side_effect=subprocess.TimeoutExpired("synthetic", 60, output=TOKEN)), \
                patch("sys.stdout", output), patch("sys.stderr", errors):
            self.assertEqual(example.main([]), 1)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(errors.getvalue(), example.FAILURE + "\n")
        self.assertNotIn(TOKEN, errors.getvalue())


if __name__ == "__main__":
    unittest.main()
