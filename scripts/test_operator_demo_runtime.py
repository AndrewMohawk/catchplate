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
        with self.runner():
            code, _, _ = self.request("GET", "/api/operator-demo/status", auth=False)
            self.assertEqual(code, 401)
            code, body, _ = self.request("GET", "/api/operator-demo/status")
            self.assertEqual(code, 200)
            initial = json.loads(body)
            self.assertEqual(initial["mode"], "operator-development")
            self.assertEqual(initial["connections"], [])
            self.assertIsNone(initial["loaded_policy_hash"])
            self.assertFalse(initial["productionReady"])
            self.assertFalse(initial["hardwareVerified"])
            self.assertFalse(initial["syntheticOnly"])
            for origin in (None, "https://foreign.example.com"):
                code, _, _ = self.request("POST", "/api/operator-demo/connections", body=self.payload(), origin=origin)
                self.assertEqual(code, 403)
            invalid = dict(self.payload(), response_fields=[], extra=self.provider_secret)
            code, body, _ = self.request("POST", "/api/operator-demo/connections", body=invalid, origin=self.origin)
            self.assertEqual(code, 422)
            self.assertNotIn(self.provider_secret.encode(), body)
            for methods in (["HEAD"], ["GET", "HEAD"], ["OPTIONS", "HEAD"]):
                with self.subTest(methods=methods):
                    code, body, _ = self.request("POST", "/api/operator-demo/connections",
                        body=dict(self.payload(), methods=methods), origin=self.origin)
                    self.assertEqual(code, 422)
                    self.assertNotIn(self.provider_secret.encode(), body)
            code, body, _ = self.request("GET", "/api/operator-demo/status")
            self.assertEqual(code, 200)
            self.assertEqual(json.loads(body)["connections"], [])
            code, _, _ = self.request("POST", "/api/operator-demo/connections", body=b"x" * 32769, origin=self.origin)
            self.assertEqual(code, 413)
            code, body, headers = self.request("POST", "/api/operator-demo/connections", body=self.payload(), origin=self.origin)
            self.assertEqual(code, 200, "valid connection did not commit")
            self.assertNotIn(self.provider_secret.encode(), body)
            result = json.loads(body)
            client_token = result["client_token"]
            self.assertGreaterEqual(len(client_token), 40)
            self.assertEqual(result["activation"], "pending")
            self.assertEqual(headers.get("cache-control"), "no-store")
            self.assertEqual(result["connection"]["response_fields"], ["id", "name"])
            code, body, _ = self.request("GET", "/api/operator-demo/status")
            self.assertEqual(code, 200)
            saved = json.loads(body)
            self.assertEqual(len(saved["connections"]), 1)
            self.assertEqual(saved["connections"][0]["activation"], "pending")
            self.assertEqual(saved["connections"][0]["client_status"], "pending")
            self.assertNotIn(client_token.encode(), body)
            self.assertNotIn(self.provider_secret.encode(), body)
            self.assertEqual(saved["active_policy_hash"], result["policy_hash"])
            code, body, _ = self.request("GET", "/ca.pem")
            self.assertEqual(code, 200)
            self.assertIn(b"BEGIN CERTIFICATE", body)
            self.assertNotIn(b"PRIVATE KEY", body)
            for route in ("/api/credentials", "/api/policy/publish", "/api/demo/seed"):
                code, _, _ = self.request("POST", route, body={}, origin=self.origin)
                self.assertEqual(code, 403)
        with self.runner():
            code, body, _ = self.request("GET", "/api/operator-demo/status")
            self.assertEqual(code, 200)
            restarted = json.loads(body)
            self.assertEqual(restarted["connections"], saved["connections"])
            self.assertEqual(restarted["active_policy_hash"], saved["active_policy_hash"])
            self.assertIsNone(restarted["loaded_policy_hash"])


if __name__ == "__main__":
    unittest.main()
