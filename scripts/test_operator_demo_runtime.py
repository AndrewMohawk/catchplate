#!/usr/bin/env python3
"""Actual local HTTP runner with fresh encrypted data; no provider or proxy network."""
from __future__ import annotations

from contextlib import contextmanager
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOKEN_NAMES = ("ADMIN_TOKEN", "DATA_PLANE_CREDENTIAL_LEASE_TOKEN", "DATA_PLANE_AUDIT_TOKEN",
    "DATA_PLANE_GRANT_CONSUME_TOKEN", "DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN",
    "DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN", "DATA_PLANE_MANAGEMENT_TOKEN", "AUDIT_ANCHOR_TOKEN")


class OperatorDemoRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="operator-demo-http-", dir=os.getenv("TMPDIR"))
        self.addCleanup(self.scratch.cleanup)
        self.directory = Path(self.scratch.name)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        self.environment = {key: value for key, value in os.environ.items() if not key.startswith("SERVERWARE_")}
        self.origin = f"http://localhost:{self.port}"
        self.environment.update(PYTHONDONTWRITEBYTECODE="1", SERVERWARE_OPERATOR_DEMO="1",
            SERVERWARE_DATA_DIR=str(self.directory / "data"), SERVERWARE_WEB_HOST="127.0.0.1",
            SERVERWARE_WEB_PORT=str(self.port), SERVERWARE_PUBLIC_URL=self.origin,
            SERVERWARE_OPERATOR_DEMO_UPSTREAMS='["https://api.example.com"]',
            SERVERWARE_OPERATOR_DEMO_PROXY_URL="https://proxy.example.com:443",
            SERVERWARE_DIRECT_CA_DOWNLOAD_ENABLED="1")
        for name in TOKEN_NAMES:
            self.environment["SERVERWARE_" + name] = secrets.token_urlsafe(32)
        self.admin = self.environment["SERVERWARE_ADMIN_TOKEN"]
        self.provider_secret = secrets.token_urlsafe(32)

    def request(self, method, path, *, body=None, auth=True, origin=None):
        headers = {"Connection": "close"}
        if auth:
            headers["X-Serverware-Admin-Token"] = self.admin
        if origin is not None:
            headers["Origin"] = origin
        if body is not None:
            headers["Content-Type"] = "application/json"
            if not isinstance(body, bytes):
                body = json.dumps(body).encode()
        client = http.client.HTTPConnection("127.0.0.1", self.port, timeout=8)
        try:
            client.request(method, path, body=body, headers=headers)
            response = client.getresponse()
            result = response.read(2 * 1024 * 1024 + 1)
            self.assertLessEqual(len(result), 2 * 1024 * 1024)
            return response.status, result, dict(response.getheaders())
        finally:
            client.close()

    @contextmanager
    def runner(self):
        with tempfile.TemporaryFile(dir=self.directory) as log:
            process = subprocess.Popen([sys.executable, "-B", "-m", "serverware.operator_demo_runner"],
                cwd=ROOT, env=self.environment, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 35
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        self.fail("operator demo runner exited before listening")
                    try:
                        status, _, _ = self.request("GET", "/healthz")
                    except (OSError, http.client.HTTPException):
                        time.sleep(0.1)
                        continue
                    self.assertEqual(status, 200)
                    break
                else:
                    self.fail("operator demo did not listen within 35 seconds")
                yield
            except BaseException:
                log.seek(0, os.SEEK_END)
                log.seek(max(0, log.tell() - 16000))
                diagnostic = log.read().decode(errors="replace")
                for name in TOKEN_NAMES:
                    diagnostic = diagnostic.replace(self.environment["SERVERWARE_" + name], "[test token]")
                diagnostic = diagnostic.replace(self.provider_secret, "[test provider secret]")
                for token in getattr(self, "_private_client_tokens", ()):
                    diagnostic = diagnostic.replace(token, "[test client token]")
                print("Bounded operator-demo diagnostics:\n" + diagnostic, file=sys.stderr)
                raise
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=7)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)

    def payload(self):
        return {"name": "HTTP fixture", "upstream_url": "https://api.example.com/v1/account",
            "methods": ["GET"], "auth_type": "bearer", "secret": self.provider_secret,
            "response_fields": ["id", "name"]}

    def test_authenticated_create_validation_ca_and_restart(self):
        prefix = "/api/operator-demo/"
        collections = ("credentials", "applications", "access_rules")
        self._private_client_tokens = []

        def public_body(body):
            private = (self.provider_secret, self.admin, *self._private_client_tokens)
            self.assertFalse(any(value.encode() in body for value in private),
                "public response exposed synthetic private material")

        def catalog():
            code, body, headers = self.request("GET", prefix + "catalog")
            self.assertEqual(code, 200)
            public_body(body)
            self.assertEqual(headers.get("cache-control"), "no-store")
            return json.loads(body)

        def review(value):
            return {"expected_revision": value["revision"],
                "expected_policy_hash": value["policy"]["policy_hash"]}

        def authority(value):
            # Exclude live observation clocks, not any saved resource or policy.
            return {key: value[key] for key in (*collections, "revision", "policy")}

        def create(route, payload):
            code, body, headers = self.request("POST", prefix + route, body=payload, origin=self.origin)
            self.assertEqual(code, 201, "modern resource creation did not commit")
            public_body(body)
            self.assertEqual(headers.get("cache-control"), "no-store")
            result = json.loads(body)
            self.assertEqual(result["policy"]["activation"], "pending")
            self.assertIsNone(result["policy"]["loaded_policy_hash"])
            return result

        with self.runner():
            for path in (prefix + "catalog", prefix + "status"):
                code, _, _ = self.request("GET", path, auth=False)
                self.assertEqual(code, 401)
            initial = catalog()
            self.assertEqual(initial["schema"], "serverware.operatorCatalog/v1")
            self.assertEqual(initial["mode"], "operator-development")
            for key in collections:
                self.assertEqual(initial[key], [])
            self.assertIsNone(initial["policy"]["loaded_policy_hash"])
            self.assertFalse(initial["productionReady"])
            self.assertFalse(initial["hardwareVerified"])
            # The modern catalog has no legacy syntheticOnly field. The actual
            # authenticated profile endpoint distinguishes ordinary demo from
            # the development-sandbox runner without inventing gate readiness.
            code, body, _ = self.request("GET", "/api/auth/status")
            self.assertEqual(code, 200)
            public_body(body)
            profile = json.loads(body)
            self.assertTrue(profile["authenticated"])
            self.assertTrue(profile["operatorDemo"])
            self.assertFalse(profile["developmentSandbox"])
            self.assertEqual(profile["authMethod"], "operator-demo-header")
            for method, path, payload in (("GET", "status", None), ("POST", "connections", self.payload())):
                code, body, _ = self.request(method, prefix + path, body=payload, origin=self.origin)
                self.assertEqual(code, 409)
                public_body(body)
                refusal = json.loads(body)
                self.assertEqual(refusal["code"], "operator_demo_resource_model_changed")
                self.assertEqual(refusal["catalog_path"], prefix + "catalog")

            credential_payload = {**review(initial), "name": "HTTP fixture key",
                "auth_type": "bearer", "secret": self.provider_secret}
            code, _, _ = self.request("POST", prefix + "credentials",
                body=credential_payload, auth=False, origin=self.origin)
            self.assertEqual(code, 401)
            for origin in (None, "https://foreign.example.com"):
                code, _, _ = self.request("POST", prefix + "credentials", body=credential_payload, origin=origin)
                self.assertEqual(code, 403)
            code, body, _ = self.request("POST", prefix + "credentials",
                body={**credential_payload, "extra": self.provider_secret}, origin=self.origin)
            self.assertEqual(code, 422)
            public_body(body)
            code, _, _ = self.request("POST", prefix + "credentials", body=b"x" * 16385, origin=self.origin)
            self.assertEqual(code, 413)
            self.assertEqual(authority(catalog()), authority(initial))
            credential = create("credentials", credential_payload)["credential"]
            current = catalog()
            self.assertEqual(current["applications"], [])
            self.assertEqual(current["access_rules"], [])
            application_result = create("applications", {**review(current), "name": "HTTP fixture app",
                "token_lifetime_seconds": 3600})
            client_token = application_result["client_token"]
            self.assertGreaterEqual(len(client_token), 40)
            self._private_client_tokens.append(client_token)
            application = application_result["application"]
            self.assertEqual(application["access_status"], "unassigned")
            before_rule = catalog()
            self.assertEqual(before_rule["access_rules"], [])
            rule_payload = {**review(before_rule), "name": "HTTP fixture permission",
                "application_id": application["id"], "credential_id": credential["id"],
                "upstream_url": "https://api.example.com/v1/account", "methods": ["GET"],
                "response_mode": "projected_json", "response_fields": ["id", "name"]}
            for invalid in ({**rule_payload, "response_fields": []},
                    {**rule_payload, "extra": self.provider_secret}):
                code, body, _ = self.request("POST", prefix + "access-rules", body=invalid, origin=self.origin)
                self.assertEqual(code, 422)
                public_body(body)
            for methods in (["HEAD"], ["GET", "HEAD"], ["OPTIONS", "HEAD"]):
                with self.subTest(methods=methods):
                    code, body, _ = self.request("POST", prefix + "access-rules",
                        body={**rule_payload, "methods": methods}, origin=self.origin)
                    self.assertEqual(code, 422)
                    public_body(body)
            code, _, _ = self.request("POST", prefix + "access-rules", body=b"x" * 32769, origin=self.origin)
            self.assertEqual(code, 413)
            self.assertEqual(authority(catalog()), authority(before_rule))
            result = create("access-rules", rule_payload)
            self.assertEqual(result["access_rule"]["response_fields"], ["id", "name"])
            saved = catalog()
            for key in collections:
                self.assertEqual(len(saved[key]), 1)
            self.assertEqual(saved["credentials"][0]["id"], credential["id"])
            self.assertEqual(saved["applications"][0]["id"], application["id"])
            self.assertEqual(saved["applications"][0]["access_status"], "pending")
            self.assertEqual(saved["access_rules"][0]["enforcement"], "pending")
            self.assertEqual(saved["policy"], result["policy"])
            code, body, _ = self.request("GET", "/ca.pem", auth=False)
            self.assertEqual(code, 401)
            self.assertNotIn(b"BEGIN CERTIFICATE", body)
            public_body(body)
            code, body, _ = self.request("GET", "/ca.pem")
            self.assertEqual(code, 200)
            self.assertIn(b"BEGIN CERTIFICATE", body)
            self.assertNotIn(b"PRIVATE KEY", body)
            public_body(body)
            ca_bytes = body
            for route in ("/api/credentials", "/api/policy/publish", "/api/demo/seed"):
                code, _, _ = self.request("POST", route, body={}, origin=self.origin)
                self.assertEqual(code, 403)
        with self.runner():
            restarted = catalog()
            self.assertEqual(authority(restarted), authority(saved))
            self.assertIsNone(restarted["policy"]["loaded_policy_hash"])
            self.assertEqual(restarted["policy"]["activation"], "pending")
            code, body, _ = self.request("GET", "/ca.pem")
            self.assertEqual(code, 200)
            public_body(body)
            self.assertEqual(body, ca_bytes)


if __name__ == "__main__":
    unittest.main()
