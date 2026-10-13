#!/usr/bin/env python3
"""Pure public-proxy parser/configuration controls; no curl, DNS or live traffic."""
import base64
from copy import deepcopy
from io import StringIO
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


def offline(event, _):
    if event.startswith("socket.") or event in {"subprocess.Popen", "os.system", "os.posix_spawn"}:
        raise RuntimeError("Network and process execution forbidden by pure test")


sys.addaudithook(offline)
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import check_operator_public_proxy as checker

# Public ISRG Root X2 certificate, used only to exercise actual stdlib PEM parsing.
PEM = """-----BEGIN CERTIFICATE-----
MIICGzCCAaGgAwIBAgIQQdKd0XLq7qeAwSxs6S+HUjAKBggqhkjOPQQDAzBPMQsw
CQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2gg
R3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yMDA5MDQwMDAwMDBaFw00
MDA5MTcxNjAwMDBaME8xCzAJBgNVBAYTAlVTMSkwJwYDVQQKEyBJbnRlcm5ldCBT
ZWN1cml0eSBSZXNlYXJjaCBHcm91cDEVMBMGA1UEAxMMSVNSRyBSb290IFgyMHYw
EAYHKoZIzj0CAQYFK4EEACIDYgAEzZvVn4CDCuwJSvMWSj5cz3es3mcFDR0HttwW
+1qLFNvicWDEukWVEYmO6gbf9yoWHKS5xcUy4APgHoIYOIvXRdgKam7mAHf7AlF9
ItgKbppbd9/w+kHsOdx1ymgHDB/qo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0T
AQH/BAUwAwEB/zAdBgNVHQ4EFgQUfEKWrt5LSDv6kviejM9ti6lyN5UwCgYIKoZI
zj0EAwMDaAAwZQIwe3lORlCEwkSHRhtFcP9Ymd70/aTSVaYgLXTWNLxBo1BfASdW
tL4ndQavEi51mI38AjEAi/V3bNTIZargCyzuFJ0nN6T5U6VR5CmD1/iQMVtCnwr1
/q4AaOeMSQ+2b1tbFfLn
-----END CERTIFICATE-----
"""


def config():
    return {"schema": "serverware.publicProxySmoke/v1", "run_id": "public-proxy-" + "a" * 32,
        "application_id": "11111111-1111-4111-8111-111111111111", "client_token": "s" * 43,
        "credential_id": "22222222-2222-4222-8222-222222222222", "rule_id": "33333333-3333-4333-8333-333333333333",
        "policy_hash": "sha256:" + "1" * 64, "authorization_sha256": "sha256:" + "2" * 64,
        "ca_pem": PEM, "ca_sha256": checker.sha(PEM.encode())}


def response_document():
    return {"method": "POST", "path": "/echo", "authorization_present": True, "authorization_scheme": "Bearer",
        "authorization_matches_expected": True, "proxy_authorization_seen": False,
        "query": {"_data_plane_token_seen": False, "_cookie_seen": False}, "credential_marker": "other",
        "proxy_authorization": None, "cookie": None, "x_api_key": None, "serverware_agent": None}


def response(value=None, *, extra=(), trailer=b"200:200:0:0:203.0.113.10\n", body=None):
    body = body if body is not None else json.dumps(response_document() if value is None else value, separators=(",", ":")).encode()
    headers = [("Content-Type", "application/json"), ("Content-Length", str(len(body))),
        ("X-Serverware-Policy-Hash", config()["policy_hash"]), ("X-Serverware-Response-Body-SHA256", checker.sha(body)),
        ("X-Serverware-Request-Digest", "sha256:" + "3" * 64), ("X-Serverware-Operation-Digest", "sha256:" + "4" * 64)]
    head = b"HTTP/1.1 200 OK\r\n" + b"\r\n".join((key + ": " + item).encode() for key, item in [*headers, *extra])
    return head + b"\r\n\r\n" + body + checker.TRAILER + trailer


class PublicProxyControls(unittest.TestCase):
    def refused(self, function, *args):
        with self.assertRaises(checker.CheckError) as caught:
            function(*args)
        self.assertEqual(str(caught.exception), "Public proxy check refused")

    def test_exact_config_and_public_certificate(self):
        self.assertEqual(checker.parse_config(json.dumps(config())), config())
        self.assertEqual(checker.BODY, b'{"public_proxy_smoke":true}')

    def test_config_closed_types_identity_and_no_injection(self):
        for key, value in (("schema", "wrong"), ("run_id", "public-proxy-" + "A" * 32),
            ("client_token", "secret\"\nurl = https://external.example"), ("client_token", "s" * 44),
            ("application_id", True), ("rule_id", config()["credential_id"]), ("policy_hash", "A" * 64),
            ("authorization_sha256", checker.sha(checker.DUMMY.encode())), ("extra", "private-canary")):
            value_config = config(); value_config[key] = value
            self.refused(checker.parse_config, json.dumps(value_config))
        for value in (None, "", "[1]", "null", "{\"schema\":1,\"schema\":2}", "NaN", "1.5", "x" * 32769):
            self.refused(checker.parse_config, value)

    def test_ca_original_bytes_hash_and_real_certificate_admission(self):
        for pem in (PEM + PEM, PEM.replace("CERTIFICATE", "PRIVATE KEY"), PEM + "private-canary", "\N{SNOWMAN}",
                    "-----BEGIN CERTIFICATE-----\naW52YWxpZA==\n-----END CERTIFICATE-----\n"):
            value = config(); value.update(ca_pem=pem, ca_sha256=checker.sha(pem.encode()))
            self.refused(checker.parse_config, json.dumps(value))
        value = config(); value["ca_pem"] = PEM.rstrip()
        self.refused(checker.parse_config, json.dumps(value))

    def test_curl_fixed_scope_tls_no_redirect_retry_or_secret_argv(self):
        args = checker.curl_arguments(config(), "/private/ca.pem", "/private/body.json")
        self.assertEqual(args[:4], ["/usr/bin/curl", "-q", "--config", "-"])
        self.assertEqual(args[args.index("--proxy") + 1], "https://serverware-proxy.example.com:443")
        self.assertEqual(args[-1], "https://demo-upstream:8443/echo?expectedAuthorizationSha256=sha256%3A" + "2" * 64)
        for option, value in (("--retry", "0"), ("--max-redirs", "0"), ("--max-time", "20"),
            ("--max-filesize", "65536"), ("--noproxy", ""), ("--cacert", "/private/ca.pem")):
            self.assertEqual(args[args.index(option) + 1], value)
        for forbidden in ("--insecure", "--proxy-insecure", "--proxy-cacert", "--location", "--resolve", "--connect-to", "--proxy-user"):
            self.assertNotIn(forbidden, args)
        self.assertNotIn(config()["client_token"], " ".join(args))
        self.assertIn("Accept-Encoding: identity", args)
        self.assertIn("User-Agent: serverware-test-run/" + config()["run_id"], args)
        with patch.object(checker.subprocess, "Popen", side_effect=checker.CheckError()) as launched:
            self.refused(checker.run_curl, args, b"private-canary")
        self.assertEqual(launched.call_args.kwargs["env"], {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
        self.assertTrue(launched.call_args.kwargs["start_new_session"])

    def test_positive_commitments_only(self):
        result = checker.validate_result(config(), "positive", 0, response(), b"")
        self.assertEqual(result["schema"], "serverware.publicProxySmokeResult/v1")
        self.assertEqual(result["request_digest"], "sha256:" + "3" * 64)
        self.assertEqual(result["operation_digest"], "sha256:" + "4" * 64)
        self.assertEqual(result["peer"], "203.0.113.10")
        for key in ("client_token", "ca_pem", "authorization_sha256", "body", "stderr", "provider_arrivals"):
            self.assertNotIn(key, result)
        self.assertNotIn(config()["client_token"], json.dumps(result))

    def test_header_commitment_body_and_framing_refusals(self):
        for changed in (response().replace(b'"POST"', b'"HEAD"'), response().replace(b"sha256:" + b"1" * 64, b"sha256:" + b"9" * 64),
            response().replace(b"sha256:" + b"3" * 64, b"bad-digest"), response().replace(b"HTTP/1.1 200", b"HTTP/1.1 302"),
            response().replace(b"Content-Length:", b"Other-Length:"), response() + b"trailing"):
            self.refused(checker.validate_result, config(), "positive", 0, changed, b"")
        for name in ("Content-Length", "Transfer-Encoding", "Trailer", "Set-Cookie", "Cookie", "Authorization",
            "Proxy-Authorization", "X-Serverware-Data-Plane-Token", "X-Serverware-Agent", "Location", "Content-Encoding"):
            self.refused(checker.validate_result, config(), "positive", 0, response(extra=[(name, "private-canary")]), b"")
        self.refused(checker.validate_result, config(), "positive", 0, response(body=b"{}" * 32769), b"")

    def test_echo_injection_leakage_and_bool_types(self):
        for key, value in (("method", "GET"), ("path", "/wrong"), ("authorization_present", 1),
            ("authorization_scheme", "Basic"), ("authorization_matches_expected", False), ("proxy_authorization_seen", 0),
            ("proxy_authorization", "private-canary"), ("cookie", "private-canary"), ("x_api_key", "private-canary"),
            ("serverware_agent", "private-canary"), ("extra", "private-canary"), ("credential_marker", "initial")):
            value_body = response_document(); value_body[key] = value
            self.refused(checker.validate_result, config(), "positive", 0, response(value_body), b"")
        for value in ({"_data_plane_token_seen": 0, "_cookie_seen": False}, {"_data_plane_token_seen": False, "_cookie_seen": True}):
            body = response_document(); body["query"] = value
            self.refused(checker.validate_result, config(), "positive", 0, response(body), b"")
        secret = (config()["application_id"] + ":" + config()["client_token"]).encode()
        for reflected in (checker.DUMMY.encode(), config()["client_token"].encode(), secret, base64.b64encode(secret)):
            self.refused(checker.validate_result, config(), "positive", 0, response(extra=[("X-Reflected", reflected.decode())]), b"")
            self.refused(checker.validate_result, config(), "revoked", 56, checker.TRAILER + b"403:000:0:0:203.0.113.10\n", reflected)

    def test_outer_inner_tls_peer_status_and_unknown_outcomes(self):
        for trailer in (b"200:200:60:0:203.0.113.10\n", b"200:200:0:60:203.0.113.10\n",
            b"200:200:0:0:127.0.0.1\n", b"403:200:0:0:203.0.113.10\n", b"200:302:0:0:203.0.113.10\n"):
            self.refused(checker.validate_result, config(), "positive", 0, response(trailer=trailer), b"")
        for status in (True, 28, 56, -9):
            self.refused(checker.validate_result, config(), "positive", status, response(), b"")
        self.refused(checker.validate_result, config(), "positive", 0, response(), b"private-canary")

    def test_revoked_is_connect_refusal_only_no_provider_claim(self):
        output = checker.TRAILER + b"403:000:0:0:203.0.113.10\n"
        result = checker.validate_result(config(), "revoked", 56, output, b"curl: (56) CONNECT tunnel failed, response 403\n")
        self.assertEqual(result["connect_status"], 403)
        for key in ("response_body_sha256", "response_body_bytes", "request_digest", "operation_digest"):
            self.assertIsNone(result[key])
        for changed in (b"origin-body" + output, response(), output.replace(b"403", b"407")):
            self.refused(checker.validate_result, config(), "revoked", 56, changed, b"")
        self.refused(checker.validate_result, config(), "revoked", 0, output, b"")

    def test_owned_ca_body_permissions_cleanup_and_no_retry(self):
        observed = []
        for fail in (False, True):
            def fake_run(args, private_input):
                ca = Path(args[args.index("--cacert") + 1]); body = Path(args[args.index("--data-binary") + 1][1:])
                observed.extend((ca, body))
                self.assertEqual(ca.stat().st_mode & 0o777, 0o600)
                self.assertEqual(body.stat().st_mode & 0o777, 0o600)
                self.assertEqual(ca.parent.stat().st_mode & 0o777, 0o700)
                self.assertEqual(ca.read_bytes(), PEM.encode()); self.assertEqual(body.read_bytes(), b'{"public_proxy_smoke":true}')
                self.assertEqual(private_input, ('proxy-user = "' + config()["application_id"] + ':' + config()["client_token"] + '"\n').encode())
                if fail:
                    raise checker.CheckError()
                return 0, response(), b""
            with patch.object(checker, "run_curl", side_effect=fake_run) as run:
                if fail:
                    self.refused(checker.execute, config(), "positive")
                else:
                    self.assertTrue(checker.execute(config(), "positive")["ok"])
                self.assertEqual(run.call_count, 1)
            self.assertTrue(all(not path.exists() and not path.parent.exists() for path in observed))

    def test_main_pops_private_env_and_failure_never_prints_exception(self):
        with patch.dict(os.environ, {checker.ENVIRONMENT: json.dumps(config())}), patch.object(sys, "argv", ["check", "positive"]), \
                patch.object(sys, "stdout", StringIO()) as output:
            def fail(*_):
                self.assertNotIn(checker.ENVIRONMENT, os.environ)
                raise RuntimeError("private-canary " + config()["client_token"])
            with patch.object(checker, "execute", side_effect=fail) as run:
                self.assertEqual(checker.main(), 1); self.assertEqual(run.call_count, 1)
            self.assertEqual(json.loads(output.getvalue()), {"schema": checker.SCHEMA, "ok": False, "mode": "positive",
                "error": "public_proxy_check_failed", "outcome": "unconfirmed", "retry_allowed": False})


if __name__ == "__main__":
    unittest.main(verbosity=2)
