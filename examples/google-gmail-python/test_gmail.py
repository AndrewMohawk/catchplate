"""Real official SDK + Requests, synthetic send boundary; never contact Google.

TLS checks use real certificates and in-memory handshakes. These tests do not
claim a Catchplate lease, proxy acceptance, consent or deployed integration.
"""
import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import io
import json
import logging
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import ModuleType
from urllib.parse import parse_qs, urlsplit

CONFIG_ONLY = "--config-only" in sys.argv
if CONFIG_ONLY:
    sys.argv.remove("--config-only")
    # Only configuration/CLI tests run in this stdlib-only mode. These stubs do
    # not implement or test any SDK/transport behavior; actual SDK tests below
    # still require the real prepared dependencies.
    names = ("certifi", "httplib2", "requests", "requests.adapters",
        "googleapiclient", "googleapiclient.discovery")
    stubs = {name: ModuleType(name) for name in names}
    stubs["requests.adapters"].HTTPAdapter = type("UnavailableAdapter", (), {})
    def unavailable_sdk(*args, **kwargs):
        raise AssertionError("Configuration-only test reached the SDK")
    stubs["googleapiclient.discovery"].build = unavailable_sdk
    with patch.dict(sys.modules, stubs):
        import gmail as example
else:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import requests
    from requests.adapters import HTTPAdapter
    import gmail as example


def no_network(event, _):
    if event.startswith("socket."):
        raise AssertionError("Offline Gmail test attempted socket access")


sys.addaudithook(no_network)
APP = "12345678-1234-4234-8234-123456789abc"
TOKEN = base64.urlsafe_b64encode(b"synthetic-application-token-0001").decode().rstrip("=")


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="gmail-config-offline-")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "catchplate-client.private.json"
        self.token = base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")
        rule = "00000000-0000-4000-8000-000000000002"
        # Full workspace_proxy_audit download, including its nested SDK recipe;
        # not a detached recipe or an executable description.
        self.value = {"application_id": APP, "access_rule_id": rule,
            "proxy_url": "https://proxy.example.test:8443", "proxy_authentication": "basic_and_bearer_v1",
            "proxy_username": APP, "proxy_password": self.token, "token_expires_at_epoch_ms": 2**53 - 1,
            "ca_file": "./catchplate-ca.pem", "proxy_ca_file": None,
            "operation_bundle": "gmail_read_v1", "upstream_url": example.ORIGIN + example.LIST_PATH,
            "methods": ["GET"], "response_mode": "passthrough", "credential_input": "replace_exact",
            "request_headers": {"Authorization": example.PLACEHOLDER}, "query_mode": "orderedFormV1",
            "age_policy": {"mode": "unrestricted"}, "client_recipe": {
                "schema": "catchplate.gmailSdkClient/v1", "clear_environment": True,
                "example_directory": "examples/google-gmail-go", "entrypoint": "./gmail-example",
                "access_rule_id": rule, "token_expires_at_epoch_ms": 2**53 - 1,
                "environment": {"LANG": "C.UTF-8", "CATCHPLATE_PROXY_URL": "https://proxy.example.test:8443",
                    "CATCHPLATE_APP_ID": APP, "CATCHPLATE_PROXY_TOKEN": self.token,
                    "CATCHPLATE_CA_FILE": "./catchplate-ca.pem"}}}
        previous = logging.root.manager.disable
        self.addCleanup(logging.disable, previous)

    def write(self, value=None):
        self.path.write_text(json.dumps(self.value if value is None else value), encoding="utf-8")
        return self.path

    def test_optional_age_policy_and_internal_hint_are_strict(self):
        for days in (1, 7, 3650):
            value = {**self.value, "age_policy": {"mode": "recent_internal_date_v1", "max_age_days": days}}
            selected = example.configuration_environment(self.write(value))
            self.assertEqual(selected[example.AGE_ENV], str(days))
            self.assertEqual(example.child_environment(selected)[example.AGE_ENV], str(days))
        absent = deepcopy(self.value)
        absent.pop("age_policy")
        absent["client_recipe"]["environment"][example.AGE_ENV] = "9"
        self.assertNotIn(example.AGE_ENV, example.configuration_environment(self.write(absent)))
        self.assertNotIn(example.AGE_ENV, example.configuration_environment(self.write()))
        invalid = [None, {}, [], {"mode": "future"}, {"mode": "unrestricted", "max_age_days": 7}]
        invalid += [{"mode": "recent_internal_date_v1", "max_age_days": value} for value in (None, True, "7", 0, 1.5, 3651)]
        for policy in invalid:
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                example.configuration_environment(self.write({**self.value, "age_policy": policy}))
        for value in ("", "0", "01", "3651", "7.0"):
            with self.assertRaises(ValueError):
                example.age_days_environment({example.AGE_ENV: value})
        self.assertEqual(example.sample_query(7, 1800000000001), "after:1799395201")
        self.assertEqual(example.sample_query(7, 1800000000000), "after:1799395200")
        self.assertIsNone(example.sample_query(0, 1800000000001))

    def test_all_producer_languages_map_only_connection_data_and_resolve_ca_beside_json(self):
        for language in ("go", "node", "python"):
            value = deepcopy(self.value)
            recipe = value["client_recipe"]
            if language != "go":
                recipe.update(schema="catchplate.gmailSdkClient/v2", language=language,
                    arguments=["client.mjs"] if language == "node" else ["-I", "-B", "gmail.py"],
                    resolve_ca_paths=True, resolve_executable_from_path=language == "node",
                    entrypoint="node" if language == "node" else ".venv/bin/python",
                    example_directory="examples/google-gmail-" + language)
            with self.subTest(language=language), patch.object(example.subprocess, "run") as run:
                selected = example.configuration_environment(self.write(value))
            run.assert_not_called()
            self.assertEqual(selected, {"CATCHPLATE_PROXY_URL": value["proxy_url"], "CATCHPLATE_APP_ID": APP,
                "CATCHPLATE_PROXY_TOKEN": self.token, "CATCHPLATE_CA_FILE": str(self.path.parent / "catchplate-ca.pem")})
        recipe.update(language="ignored", entrypoint="do-not-execute", arguments=["do-not-execute"],
            example_directory="/not/the/path/base")
        recipe["environment"].update(HTTPS_PROXY="wrong", GOOGLE_APPLICATION_CREDENTIALS="wrong",
            SSLKEYLOGFILE="wrong", PATH="wrong", CATCHPLATE_PROXY_CA_FILE="./proxy's $literal.pem")
        value["proxy_ca_file"] = "./proxy's $literal.pem"
        before = deepcopy(value)
        with patch.object(example.subprocess, "run") as run:
            selected = example.configuration_environment(self.write(value))
        run.assert_not_called()
        self.assertEqual(value, before)
        self.assertEqual(set(selected), set(example.REQUIRED_ENV) | {"CATCHPLATE_PROXY_CA_FILE"})
        self.assertEqual(selected["CATCHPLATE_PROXY_CA_FILE"], str(self.path.parent / "proxy's $literal.pem"))

    def test_wrapper_and_recipe_connection_disagreements_refuse(self):
        mutations = (("application_id", "00000000-0000-4000-8000-000000000003"),
            ("access_rule_id", "00000000-0000-4000-8000-000000000003"),
            ("proxy_url", "https://different.example.test"), ("proxy_username", "wrong"),
            ("proxy_password", "d" * 43), ("ca_file", "./other.pem"),
            ("proxy_ca_file", "./other.pem"), ("token_expires_at_epoch_ms", 2**53 - 2),
            ("operation_bundle", "github_issues_read_v1"), ("proxy_authentication", "bearer"),
            ("upstream_url", "https://different.example.test"), ("methods", ["POST"]),
            ("query_mode", "none"), ("credential_input", "none"))
        for field, invalid in mutations:
            with self.subTest(field=field), self.assertRaises(ValueError):
                example.configuration_environment(self.write({**self.value, field: invalid}))
        for field, invalid in (("schema", "catchplate.gmailSdkClient/v3"), ("clear_environment", False),
                ("environment", []), ("access_rule_id", "not-a-uuid"), ("token_expires_at_epoch_ms", 2**53 - 2)):
            value = deepcopy(self.value)
            value["client_recipe"][field] = invalid
            with self.subTest(recipe_field=field), self.assertRaises(ValueError):
                example.configuration_environment(self.write(value))
        with self.assertRaises(ValueError):
            example.configuration_environment(self.write(self.value["client_recipe"]))

    def test_expiry_identity_and_connection_grammar_refuse_even_when_copies_agree(self):
        for expiry in (0, 1, True, 2**53, 2**53 - 1.0, "9007199254740991", float("nan"), float("inf")):
            value = deepcopy(self.value)
            value["token_expires_at_epoch_ms"] = value["client_recipe"]["token_expires_at_epoch_ms"] = expiry
            with self.subTest(expiry_type=type(expiry).__name__), self.assertRaises(ValueError):
                example.configuration_environment(self.write(value))
        value = deepcopy(self.value)
        value["token_expires_at_epoch_ms"] = value["client_recipe"]["token_expires_at_epoch_ms"] = 1234
        with patch.object(example.time, "time_ns", return_value=1234 * 1_000_000), self.assertRaises(ValueError):
            example.configuration_environment(self.write(value))
        for rule in ("bad", "{00000000-0000-4000-8000-000000000002}", "00000000000040008000000000000002"):
            value = deepcopy(self.value)
            value["access_rule_id"] = value["client_recipe"]["access_rule_id"] = rule
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                example.configuration_environment(self.write(value))
        for field, key, invalid in (("proxy_url", "CATCHPLATE_PROXY_URL", "http://proxy.example.test"),
                ("proxy_password", "CATCHPLATE_PROXY_TOKEN", "private-canary\n"),
                ("ca_file", "CATCHPLATE_CA_FILE", ""), ("ca_file", "CATCHPLATE_CA_FILE", "x" * 513),
                ("ca_file", "CATCHPLATE_CA_FILE", "./bad\n.pem"), ("ca_file", "CATCHPLATE_CA_FILE", None)):
            value = deepcopy(self.value)
            value[field] = value["client_recipe"]["environment"][key] = invalid
            with self.subTest(field=field, invalid_type=type(invalid).__name__), self.assertRaises(ValueError):
                example.configuration_environment(self.write(value))

    def test_file_is_bounded_regular_duplicate_free_json(self):
        self.path.write_bytes(b" " * (example.MAX_CONFIG_BYTES + 1))
        with self.assertRaises(ValueError): example.configuration_environment(self.path)
        with self.assertRaises((ValueError, OSError)): example.configuration_environment(self.path.parent)
        fifo = self.path.parent / "fifo"
        os.mkfifo(fifo)
        with self.assertRaises(ValueError): example.configuration_environment(fifo)
        link = self.path.parent / "link"
        link.symlink_to(self.path)
        with self.assertRaises(OSError): example.configuration_environment(link)
        for raw in (b"", b"[]", b"{", b'{"client_recipe":{},"client_recipe":{}}',
                b'{"ignored":NaN}', b'{"ignored":1e309}', b"\xff"):
            self.path.write_bytes(raw)
            with self.subTest(raw=raw), self.assertRaises(ValueError): example.configuration_environment(self.path)
        raw = json.dumps(self.value).encode()
        self.path.write_bytes(raw + b" " * (example.MAX_CONFIG_BYTES - len(raw)))
        self.assertEqual(example.configuration_environment(self.path)["CATCHPLATE_APP_ID"], APP)

    def test_cli_preserves_environment_only_mode_and_keeps_token_off_child_argv(self):
        good = {"pages": 1, "messages_read": 0, "more_pages": False}
        with patch.object(example, "launch", return_value=good) as launch, patch("sys.stdout", io.StringIO()):
            self.assertEqual(example.main([]), 0)
            self.assertIs(launch.call_args.args[0], os.environ)
        with patch.dict(os.environ, {"CATCHPLATE_PROXY_TOKEN": "wrong", "HTTPS_PROXY": "wrong"}, clear=True), \
                patch.object(example, "check_versions"), patch.object(example.subprocess, "run",
                    return_value=subprocess.CompletedProcess([], 0, json.dumps(good).encode(), b"")) as run, \
                patch("sys.stdout", io.StringIO()) as out, patch("sys.stderr", io.StringIO()) as err:
            self.assertEqual(example.main(["--config", str(self.write())]), 0)
        self.assertEqual(json.loads(out.getvalue()), good)
        self.assertEqual(err.getvalue(), "")
        argv, options = run.call_args.args[0], run.call_args.kwargs
        self.assertEqual(argv[1:3], ["-I", "-B"])
        self.assertEqual(argv[-1], "--child")
        self.assertNotIn(self.token, " ".join(argv))
        self.assertNotIn("--config", argv)
        self.assertEqual(options["env"]["CATCHPLATE_PROXY_TOKEN"], self.token)
        self.assertEqual(set(options["env"]), set(example.REQUIRED_ENV))
        self.assertEqual(options["timeout"], 120)

    def test_child_config_and_malformed_download_refuse_before_sdk_without_private_output(self):
        self.path.write_text('{"private-canary":"' + self.token + '",', encoding="utf-8")
        for args in (["--config", str(self.path)], ["--child", "--config", str(self.path)]):
            with patch.object(example, "launch") as launch, patch.object(example, "configured_http") as configure, \
                    patch.object(example, "check_versions") as versions, patch("sys.stdout", io.StringIO()) as out, \
                    patch("sys.stderr", io.StringIO()) as err:
                self.assertEqual(example.main(args), 1)
            launch.assert_not_called(); configure.assert_not_called(); versions.assert_not_called()
            self.assertEqual(out.getvalue(), "")
            self.assertEqual(err.getvalue(), example.FAILURE + "\n")
            self.assertNotIn(self.token, err.getvalue())


def certificate(path, name):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .sign(key, hashes.SHA256()))
    pem, private = path / (name + ".pem"), path / (name + ".key")
    pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return pem, private


def handshake(client_context, cert, key, name):
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert, key)
    ci, co, si, so = (ssl.MemoryBIO() for _ in range(4))
    client = client_context.wrap_bio(ci, co, server_hostname=name)
    server = server_context.wrap_bio(si, so, server_side=True)
    done = [False, False]
    for _ in range(12):
        for index, side in enumerate((client, server)):
            if not done[index]:
                try:
                    side.do_handshake()
                    done[index] = True
                except ssl.SSLWantReadError:
                    pass
        for source, target in ((co, si), (so, ci)):
            if source.pending:
                target.write(source.read())
        if all(done):
            return
    raise AssertionError("TLS handshake did not terminate")


def response(request, *, value=None, status=200, raw=None, headers=None):
    result = requests.Response()
    result.status_code, result.request, result.url = status, request, request.url
    result.headers["Content-Type"] = "application/json"
    result.headers.update(headers or {})
    class Raw(io.BytesIO):
        def release_conn(self): self.close()
    result.raw = Raw(json.dumps(value if value is not None else {}).encode() if raw is None else raw)
    return result


@unittest.skipIf(CONFIG_ONLY, "SDK checks require the prepared pinned dependencies")
class GmailTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="gmail-sdk-offline-")
        self.addCleanup(self.temp.cleanup)
        path = Path(self.temp.name)
        self.inner, self.inner_key = certificate(path, "gmail.googleapis.com")
        self.outer, self.outer_key = certificate(path, "proxy.example.test")
        self.env = {"CATCHPLATE_PROXY_URL": "https://proxy.example.test:8443", "CATCHPLATE_APP_ID": APP,
            "CATCHPLATE_PROXY_TOKEN": TOKEN, "CATCHPLATE_CA_FILE": str(self.inner),
            "CATCHPLATE_PROXY_CA_FILE": str(self.outer)}

    def run_job(self, send):
        with patch.object(HTTPAdapter, "send", send), example.configured_http(self.env) as http:
            return example.read_mail(http)

    def test_installed_pins_and_exact_lock(self):
        example.check_versions()
        from importlib.metadata import version
        requirements = Path(__file__).with_name("requirements.txt").read_text().splitlines()
        rows = [row.split("==") for row in requirements if row and not row.startswith("#")]
        self.assertEqual(len(rows), 22)
        for name, expected in rows:
            self.assertEqual(version(name), expected)

    def test_closed_configuration_and_clean_child_environment(self):
        ambient = {**self.env, "HTTPS_PROXY": "http://wrong", "NO_PROXY": "*", "HOME": "/wrong",
            "NETRC": "/wrong", "SSLKEYLOGFILE": "/wrong", "PYTHONPATH": "/wrong",
            "GOOGLE_APPLICATION_CREDENTIALS": "/wrong", "GOOGLE_API_USE_CLIENT_CERTIFICATE": "true",
            "REQUESTS_CA_BUNDLE": "/wrong"}
        original = dict(ambient)
        self.assertEqual(example.child_environment(ambient), self.env)
        self.assertEqual(ambient, original)
        for key, bad in (("CATCHPLATE_PROXY_URL", "http://proxy.example"),
                ("CATCHPLATE_PROXY_URL", "https://u:p@proxy.example"),
                ("CATCHPLATE_PROXY_URL", "https://proxy.example/path"),
                ("CATCHPLATE_PROXY_URL", "https://proxy.example?"),
                ("CATCHPLATE_PROXY_URL", "https://proxy.example#"),
                ("CATCHPLATE_PROXY_URL", "https://gmail.googleapis.com"),
                ("CATCHPLATE_PROXY_URL", "https://127.0.0.1"),
                ("CATCHPLATE_PROXY_URL", "https://Proxy.example"),
                ("CATCHPLATE_PROXY_URL", "https://proxy.example:0"),
                ("CATCHPLATE_PROXY_URL", "https://proxy.example:65536"),
                ("CATCHPLATE_APP_ID", "not-uuid"), ("CATCHPLATE_PROXY_TOKEN", TOKEN + "="),
                ("CATCHPLATE_PROXY_TOKEN", "B" * 43), ("CATCHPLATE_CA_FILE", "relative"),
                ("CATCHPLATE_PROXY_CA_FILE", "")):
            with self.subTest(key=key, bad=bad), self.assertRaises(ValueError):
                example.settings({**self.env, key: bad})

    def test_actual_sdk_pagination_get_ids_and_no_mail_output(self):
        calls = []
        token = "page+one/é="
        def send(adapter, request, **options):
            calls.append((request, options, adapter.max_retries.total))
            parts = urlsplit(request.url)
            query = parse_qs(parts.query)
            if parts.path == example.LIST_PATH:
                value = ({"messages": [{"id": "message-1"}], "nextPageToken": token} if "pageToken" not in query
                    else {"messages": [{"id": "message-2"}], "resultSizeEstimate": 1})
            else:
                value = {"id": parts.path.rsplit("/", 1)[-1], "snippet": "PRIVATE-MAIL-CANARY",
                    "payload": {"headers": [{"name": "Subject", "value": "PRIVATE-MAIL-CANARY"}]}}
            return response(request, value=value)
        with patch("google.auth.default", side_effect=AssertionError("ADC")), \
                patch("requests.sessions.get_netrc_auth", side_effect=AssertionError("netrc")), \
                patch("requests.sessions.get_environ_proxies", side_effect=AssertionError("ambient proxy")):
            result = self.run_job(send)
        self.assertEqual(result, {"pages": 2, "messages_read": 2, "more_pages": False})
        self.assertEqual(len(calls), 4)
        for request, options, retries in calls:
            self.assertEqual((request.method, request.body), ("GET", None))
            self.assertEqual(request.headers["Authorization"], "Bearer " + example.PLACEHOLDER)
            self.assertEqual(request.headers["Accept-Encoding"], "identity")
            self.assertEqual(request.headers["Content-Length"], "0")
            self.assertNotIn("Proxy-Authorization", request.headers)
            self.assertNotIn(TOKEN, repr(dict(request.headers)))
            self.assertEqual(options["proxies"], {"https": example.settings(self.env)})
            self.assertEqual(options["verify"], str(self.inner))
            self.assertEqual(options["timeout"], (5, 10))
            self.assertEqual(retries, 0)
            self.assertTrue(options["stream"])
        self.assertEqual(parse_qs(urlsplit(calls[0][0].url).query), {"maxResults": ["5"], "labelIds": ["INBOX"], "alt": ["json"]})
        self.assertEqual(parse_qs(urlsplit(calls[1][0].url).query), {"format": ["metadata"], "metadataHeaders": ["From", "Subject", "Date"], "alt": ["json"]})
        self.assertEqual(parse_qs(urlsplit(calls[2][0].url).query)["pageToken"], [token])

    def test_actual_sdk_recent_query_is_fixed_across_pages(self):
        calls = []
        def send(adapter, request, **options):
            calls.append(request.url)
            if urlsplit(request.url).path == example.LIST_PATH:
                value = {} if "pageToken=" in request.url else {"messages": [{"id": "one"}], "nextPageToken": "next+page /="}
            else:
                value = {"id": "one", "internalDate": "1800000000000"}
            return response(request, value=value)
        with patch.object(HTTPAdapter, "send", send), example.configured_http(self.env) as http, \
                patch.object(example.time, "time_ns", return_value=1800000000001000000) as clock:
            result = example.read_mail(http, 7)
        self.assertEqual(result, {"pages": 2, "messages_read": 1, "more_pages": False})
        clock.assert_called_once_with()
        self.assertEqual(urlsplit(calls[0]).query, "maxResults=5&labelIds=INBOX&q=after%3A1799395201&alt=json")
        self.assertEqual(urlsplit(calls[2]).query, "maxResults=5&labelIds=INBOX&q=after%3A1799395201&pageToken=next%2Bpage+%2F%3D&alt=json")
        self.assertNotIn("fields=", calls[1])

    def test_maximum_two_pages_and_ten_returned_ids(self):
        calls = []
        def send(adapter, request, **options):
            calls.append(request)
            parts = urlsplit(request.url)
            if parts.path == example.LIST_PATH:
                page = "b" if "pageToken" in parts.query else "a"
                value = {"messages": [{"id": page + str(i)} for i in range(5)], "nextPageToken": page}
            else: value = {"id": parts.path.rsplit("/", 1)[-1]}
            return response(request, value=value)
        self.assertEqual(self.run_job(send), {"pages": 2, "messages_read": 10, "more_pages": True})
        self.assertEqual(len(calls), 12)

    def test_empty_inbox_and_invalid_list_replies(self):
        self.assertEqual(self.run_job(lambda adapter, request, **kw: response(request)),
            {"pages": 1, "messages_read": 0, "more_pages": False})
        for value in ({"messages": None}, {"messages": [{"id": "../escape"}]},
                {"messages": [{"id": "same"}, {"id": "same"}]},
                {"messages": [{"id": str(i)} for i in range(6)]},
                {"nextPageToken": 1}, {"nextPageToken": "bad\\token"}, {"nextPageToken": "x" * 4097}):
            calls = []
            def send(adapter, request, **kw):
                calls.append(request)
                return response(request, value=value)
            with self.subTest(value=value), self.assertRaises(ValueError): self.run_job(send)
            self.assertEqual(len(calls), 1)

    def test_cycles_id_mismatch_and_long_get_never_becomes_post(self):
        for mode in ("cycle", "duplicate", "mismatch", "long"):
            calls = []
            def send(adapter, request, **kw):
                calls.append(request)
                if urlsplit(request.url).path != example.LIST_PATH:
                    value = {"id": "wrong" if mode == "mismatch" else "a"}
                else:
                    value = {"nextPageToken": "x" * 2050 if mode == "long" else "next"}
                    if mode in {"duplicate", "mismatch"}: value["messages"] = [{"id": "a"}]
                return response(request, value=value)
            with self.subTest(mode=mode), self.assertRaises(ValueError): self.run_job(send)
            self.assertTrue(all(call.method == "GET" for call in calls))
            self.assertLessEqual(len(calls), 3)

    def test_http_errors_redirects_and_transport_failures_never_retry(self):
        for status in (201, 204, 301, 302, 307, 401, 403, 409, 429, 500, 502, 503):
            calls = []
            def send(adapter, request, **kw):
                calls.append(request)
                return response(request, status=status, headers={"Location": "https://other.example/"}, raw=b"PRIVATE-CANARY")
            with self.subTest(status=status), self.assertRaises(ValueError): self.run_job(send)
            self.assertEqual(len(calls), 1)
        for error in (requests.Timeout("PRIVATE-CANARY"), requests.ConnectionError("PRIVATE-CANARY")):
            with patch.object(HTTPAdapter, "send", side_effect=error) as send, example.configured_http(self.env) as http:
                with self.assertRaises(type(error)): example.read_mail(http)
                self.assertEqual(send.call_count, 1)

    def test_response_bounds_json_ambiguity_and_closure(self):
        for raw, headers in ((b'{}', {"Content-Encoding": "gzip"}), (b'{}', {"Content-Type": "text/html"}),
                (b'{}', {"Content-Length": "02"}), (b'{}', {"Content-Length": "3"}),
                (b'{}', {"Content-Length": "1048577"}), (b'x' * 1048577, {}),
                (b'{"messages":[],"messages":[]}', {}), (b'{} {}', {}), (b'{"x":NaN}', {}),
                (b'[]', {}), (b'{"error":{"message":"PRIVATE-CANARY"}}', {})):
            responses = []
            def send(adapter, request, **kw):
                value = response(request, raw=raw, headers=headers)
                responses.append(value)
                return value
            with self.subTest(headers=headers, size=len(raw)), self.assertRaises(ValueError): self.run_job(send)
            self.assertEqual(len(responses), 1)
            self.assertTrue(responses[0].raw.closed)

    def test_transport_destination_method_count_deadline_and_auth_guards(self):
        valid = {"authorization": "Bearer " + example.PLACEHOLDER, "accept-encoding": "identity"}
        cases = [(("https://evil.example/",), {}), ((example.ORIGIN + example.LIST_PATH,), {"method": "POST"}),
            ((example.ORIGIN + example.LIST_PATH,), {"body": ""}),
            ((example.ORIGIN + example.LIST_PATH,), {"headers": {**valid, "Proxy-Authorization": "secret"}}),
            ((example.ORIGIN + example.LIST_PATH,), {"headers": {**valid, "authorization": "Bearer secret"}})]
        with example.configured_http(self.env) as http, patch.object(http.session, "request") as send:
            for args, kwargs in cases:
                with self.assertRaises(ValueError): http.request(*args, **{"headers": valid, **kwargs})
            http.attempts = 12
            with self.assertRaises(ValueError): http.request(example.ORIGIN + example.LIST_PATH, headers=valid)
            http.attempts, http.deadline = 0, 0
            with self.assertRaises(ValueError): http.request(example.ORIGIN + example.LIST_PATH, headers=valid)
            send.assert_not_called()

    def test_separate_ca_roles_and_actual_basic_proxy_manager(self):
        outer = example.outer_context(str(self.outer))
        inner = ssl.create_default_context(cafile=self.inner)
        handshake(outer, self.outer, self.outer_key, "proxy.example.test")
        handshake(inner, self.inner, self.inner_key, "gmail.googleapis.com")
        for context, cert, key, host in ((inner, self.outer, self.outer_key, "proxy.example.test"),
                (outer, self.inner, self.inner_key, "gmail.googleapis.com"),
                (inner, self.inner, self.inner_key, "wrong.example.test")):
            with self.assertRaises(ssl.SSLError): handshake(context, cert, key, host)
        adapter = example.ProxyAdapter(outer)
        self.addCleanup(adapter.close)
        manager = adapter.proxy_manager_for(example.settings(self.env))
        self.assertIs(manager.proxy_ssl_context, outer)
        self.assertEqual(manager.proxy_headers, {"Proxy-Authorization": "Basic " + base64.b64encode((APP + ":" + TOKEN).encode()).decode()})
        self.assertFalse(manager.connection_pool_kw["_proxy_config"].use_forwarding_for_https)
        with self.assertRaises(ValueError): example.ProxyAdapter(ssl._create_unverified_context())
        self.inner.write_bytes(self.inner_key.read_bytes())
        with self.assertRaises(ValueError): example.public_ca(str(self.inner))

    def test_redacted_cli_error_and_mail_free_summary(self):
        previous = logging.root.manager.disable
        self.addCleanup(logging.disable, previous)
        out, err = io.StringIO(), io.StringIO()
        with patch.object(example, "launch", side_effect=ValueError("PRIVATE-CANARY " + TOKEN)), \
                patch("sys.stdout", out), patch("sys.stderr", err):
            self.assertEqual(example.main([]), 1)
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(err.getvalue(), example.FAILURE + "\n")
        for value in ({"pages": True, "messages_read": 0, "more_pages": False},
                {"pages": 1, "messages_read": 6, "more_pages": False},
                {"pages": 1, "messages_read": 0, "more_pages": True},
                {"pages": 1, "messages_read": 0, "more_pages": False, "mail": "PRIVATE-CANARY"}):
            with self.assertRaises(ValueError): example.summary(value)

    def test_parent_deadline_child_isolation_and_failure_output_refusal(self):
        good = {"pages": 1, "messages_read": 0, "more_pages": False}
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, json.dumps(good).encode(), b"")) as run:
            self.assertEqual(example.launch({**self.env, "HOME": "/wrong", "GOOGLE_APPLICATION_CREDENTIALS": "/wrong"}), good)
            args, options = run.call_args
            self.assertEqual(args[0][1:3], ["-I", "-B"])
            self.assertEqual(options["env"], self.env)
            self.assertEqual(options["timeout"], 120)
            self.assertIs(options["stdin"], subprocess.DEVNULL)
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 1, b"PRIVATE-CANARY", b"PRIVATE-CANARY")):
            with self.assertRaisesRegex(ValueError, "^Gmail child failed$"): example.launch(self.env)

    def test_direct_child_refuses_ambient_key_logging_and_credentials(self):
        previous = logging.root.manager.disable
        self.addCleanup(logging.disable, previous)
        for key in ("SSLKEYLOGFILE", "GOOGLE_APPLICATION_CREDENTIALS", "HTTPS_PROXY", "NETRC", "HOME", "LC_CTYPE"):
            out, err = io.StringIO(), io.StringIO()
            with patch.dict(os.environ, {**self.env, key: "PRIVATE-CANARY"}, clear=True), \
                    patch.object(example, "configured_http") as configure, \
                    patch("sys.stdout", out), patch("sys.stderr", err):
                self.assertEqual(example.main(["--child"]), 1)
                configure.assert_not_called()
            self.assertEqual(out.getvalue(), "")
            self.assertEqual(err.getvalue(), example.FAILURE + "\n")
        out, err = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, {**self.env, "LC_CTYPE": "C.UTF-8"}, clear=True), \
                patch.object(HTTPAdapter, "send", lambda adapter, request, **kw: response(request)), \
                patch("sys.stdout", out), patch("sys.stderr", err):
            self.assertEqual(example.main(["--child"]), 0)
        self.assertEqual(json.loads(out.getvalue()), {"pages": 1, "messages_read": 0, "more_pages": False})
        self.assertEqual(err.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
