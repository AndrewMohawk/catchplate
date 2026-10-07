#!/usr/bin/env python3
"""Bounded real-runner/UI/auth/restart checks using fresh synthetic local data.

Run in the dependency image with current source read-only, network=none,
non-root UID, bounded CPUs/memory/PIDs, and a private tmpfs TMPDIR. No proxy,
provider, pilot or production authority is started or accepted by this test.
"""
from __future__ import annotations

from contextlib import contextmanager
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
_MAX_RESPONSE = 4 * 1024 * 1024
_TOKEN_NAMES = ("ADMIN_TOKEN", "DATA_PLANE_CREDENTIAL_LEASE_TOKEN",
    "DATA_PLANE_AUDIT_TOKEN", "DATA_PLANE_GRANT_CONSUME_TOKEN",
    "DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN", "DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN",
    "DATA_PLANE_MANAGEMENT_TOKEN", "AUDIT_ANCHOR_TOKEN")


class DevelopmentSandboxRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="serverware-sandbox-runtime-",
            dir=os.getenv("TMPDIR", "/srv/catchplate-fast/tmp"))
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        self.environment = {key: value for key, value in os.environ.items()
                            if not key.startswith("SERVERWARE_")}
        self.environment.update({
            "PYTHONDONTWRITEBYTECODE": "1",
            "SERVERWARE_DEVELOPMENT_SANDBOX": "1",
            "SERVERWARE_PROCESS_MODE": "serverware-control-plane",
            "SERVERWARE_DATA_DIR": str(self.root / "data"),
            "SERVERWARE_WEB_HOST": "127.0.0.1",
            "SERVERWARE_WEB_PORT": str(self.port),
            "SERVERWARE_PUBLIC_URL": f"http://localhost:{self.port}",
        })
        for name in _TOKEN_NAMES:
            self.environment["SERVERWARE_" + name] = secrets.token_urlsafe(32)
        self.token = self.environment["SERVERWARE_ADMIN_TOKEN"]

    def command(self):
        return [sys.executable, "-B", "-m", "serverware.development_sandbox_runner"]

    def request(self, method, path, *, token=None, payload=None):
        headers = {}
        if token is not None:
            headers["X-Serverware-Admin-Token"] = token
        if payload is not None:
            headers["Content-Type"] = "application/json"
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.request(method, path, body=payload, headers=headers)
            response = connection.getresponse()
            body = response.read(_MAX_RESPONSE + 1)
            self.assertLessEqual(len(body), _MAX_RESPONSE)
            return response.status, body
        finally:
            connection.close()

    @contextmanager
    def runner(self):
        with tempfile.TemporaryFile(mode="w+b", dir=self.root) as log:
            process = subprocess.Popen(self.command(), cwd=ROOT, env=self.environment,
                                       stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        self.fail("sandbox runner exited before listening")
                    try:
                        status, body = self.request("GET", "/")
                    except (OSError, http.client.HTTPException):
                        time.sleep(0.2)
                        continue
                    self.assertEqual(status, 200)
                    self.assertIn(b"development-sandbox-banner", body)
                    break
                else:
                    self.fail("sandbox runner did not listen within 30 seconds")
                yield
            except BaseException:
                # Never print generated tokens or API bodies. Only bounded
                # actual runner diagnostics are retained when a check fails.
                log.seek(0, os.SEEK_END)
                log.seek(max(0, log.tell() - 32768))
                diagnostic = log.read().decode("utf-8", errors="replace")
                for name in _TOKEN_NAMES:
                    diagnostic = diagnostic.replace(self.environment["SERVERWARE_" + name], "[test token]")
                print("BOUNDED RUNNER DIAGNOSTICS\n" + diagnostic, file=sys.stderr)
                raise
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=7)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)

    def snapshot(self):
        data = self.root / "data"
        with sqlite3.connect((data / "serverware.sqlite3").as_uri() + "?mode=ro", uri=True) as connection:
            credentials = connection.execute("SELECT id, credential_version FROM credentials ORDER BY id").fetchall()
            routes = connection.execute("SELECT id FROM routes ORDER BY id").fetchall()
            seeds = connection.execute("SELECT COUNT(*) FROM audit_events WHERE event_type=?", ("demo.seeded",)).fetchone()[0]
        with sqlite3.connect((data / "development-sandbox.sqlite3").as_uri() + "?mode=ro", uri=True) as connection:
            policy = connection.execute("SELECT policy_hash, sequence, rollback_epoch FROM sandbox_policy").fetchall()
        return credentials, routes, seeds, policy

    def assert_portal_routes(self):
        code, body = self.request("GET", "/api/sandbox/status")
        self.assertEqual(code, 200)
        status = json.loads(body)
        self.assertTrue(status["syntheticOnly"])
        self.assertFalse(status["productionReady"])
        self.assertFalse(status["hardwareVerified"])
        code, body = self.request("GET", "/api/auth/status", token=self.token)
        self.assertEqual(code, 200)
        self.assertTrue(json.loads(body)["authenticated"])
        for token in (None, "invalid-synthetic-test-token"):
            code, body = self.request("GET", "/api/auth/status", token=token)
            self.assertEqual(code, 200)
            self.assertFalse(json.loads(body)["authenticated"])
            code, _ = self.request("GET", "/api/bootstrap", token=token)
            self.assertEqual(code, 401)
        code, body = self.request("GET", "/api/bootstrap", token=self.token)
        self.assertEqual(code, 200, "authenticated bootstrap did not return its real UI projection")
        bootstrap = json.loads(body)
        self.assertTrue(bootstrap["policy_ready"])
        self.assertTrue(bootstrap["ca_ready"])
        self.assertEqual(len(bootstrap["credentials"]), 1)
        self.assertEqual(len(bootstrap["routes"]), 12)
        self.assertEqual(bootstrap["credentials"][0]["id"], "cred-demo-bearer")
        self.assertNotIn(b"demo-token-from-vault", body)
        self.assertNotIn(self.token.encode("ascii"), body)
        code, _ = self.request("POST", "/api/credentials", token=self.token, payload=b"{}")
        self.assertEqual(code, 403)
        for path in ("/api/auth/oidc/start", "/api/auth/oidc/callback", "/api/oauth/callback/google"):
            code, _ = self.request("GET", path, token=self.token)
            self.assertEqual(code, 403)

    def test_real_ui_auth_bootstrap_and_restart_preserve_synthetic_data(self):
        with self.runner():
            self.assert_portal_routes()
        first = self.snapshot()
        self.assertEqual((len(first[0]), len(first[1]), first[2], len(first[3])), (1, 12, 1, 1))
        with self.runner():
            self.assert_portal_routes()
        self.assertEqual(self.snapshot(), first)

    def test_unmarked_existing_data_is_not_adopted(self):
        data = self.root / "data"
        data.mkdir(mode=0o700)
        sentinel = data / "existing-application-data"
        sentinel.write_text("preserve this existing fixture\n", encoding="ascii")
        result = subprocess.run(self.command(), cwd=ROOT, env=self.environment,
                                capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refuses existing unmarked", result.stderr)
        self.assertEqual(sentinel.read_text(encoding="ascii"), "preserve this existing fixture\n")
        self.assertEqual(list(data.iterdir()), [sentinel])

    def test_production_channel_and_image_are_refused_before_data_creation(self):
        for selection in ({"SERVERWARE_RELEASE_CHANNEL": "production"},
                          {"SERVERWARE_PRODUCTION_IMAGE": "1"}):
            with self.subTest(selection=selection):
                environment = dict(self.environment, **selection)
                result = subprocess.run(self.command(), cwd=ROOT, env=environment,
                                        capture_output=True, text=True, timeout=15)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / "data").exists())


if __name__ == "__main__":
    unittest.main()
