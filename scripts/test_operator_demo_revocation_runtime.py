#!/usr/bin/env python3
"""Real loopback HTTP revocation, private SQLite and actual runner restarts.

No external provider, proxy listener, TLS or native authority is contacted.
The absent gate keeps enforcement pending; gate enforcement is a separate test.
"""
from __future__ import annotations

from contextlib import closing
import http.client
import json
from pathlib import Path
import sqlite3
import unittest
import uuid

import test_operator_demo_runtime as runtime

REVOKE = "/api/operator-demo/connections/revoke"
STATUS = "/api/operator-demo/status"
TABLES = ("credentials", "credential_generations", "operator_demo_connections",
    "operator_demo_policy", "operator_demo_revocations", "audit_events")


class OperatorDemoRevocationRuntimeTests(unittest.TestCase):
    setUp = runtime.OperatorDemoRuntimeTests.setUp
    runner = runtime.OperatorDemoRuntimeTests.runner
    payload = runtime.OperatorDemoRuntimeTests.payload

    def request(self, method, path, *, body=None, auth=True, origin=None, extra_headers=None):
        headers = {"Connection": "close"}
        if auth:
            headers["X-Catchplate-Admin-Token"] = self.admin
        if origin is not None:
            headers["Origin"] = origin
        if body is not None:
            headers["Content-Type"] = "application/json"
            if not isinstance(body, bytes):
                body = json.dumps(body).encode()
        for name, value in (extra_headers or {}).items():
            if value is None:
                headers.pop(name, None)
            else:
                headers[name] = value
        client = http.client.HTTPConnection("127.0.0.1", self.port, timeout=8)
        try:
            client.request(method, path, body=body, headers=headers)
            response = client.getresponse()
            result = response.read(2 * 1024 * 1024 + 1)
            self.assertLessEqual(len(result), 2 * 1024 * 1024)
            self.assertNotIn(self.provider_secret.encode(), result)
            if getattr(self, "client_token", None) and path != "/api/operator-demo/connections":
                self.assertNotIn(self.client_token.encode(), result)
            return response.status, result, dict(response.getheaders())
        finally:
            client.close()

    def connection(self, *, readonly=False):
        path = self.directory / "data" / "catchplate.sqlite3"
        return sqlite3.connect(path.as_uri() + ("?mode=ro" if readonly else "?mode=rw"), uri=True)

    def snapshot(self):
        with closing(self.connection(readonly=True)) as connection:
            return {table: sorted(tuple(row) for row in connection.execute(f"SELECT * FROM {table}"))
                for table in TABLES}

    def create(self, name="HTTP revocation fixture"):
        code, body, _ = self.request("POST", "/api/operator-demo/connections",
            body={**self.payload(), "name": name}, origin=self.origin)
        self.assertEqual(code, 200)
        result = json.loads(body)
        self.client_token = result["client_token"]
        return {"connection_id": result["connection"]["id"], "expected_policy_hash": result["policy_hash"]}

    def status(self):
        code, body, _ = self.request("GET", STATUS)
        self.assertEqual(code, 200)
        return json.loads(body)

    def test_http_auth_origin_canonical_input_bounds_and_exact_replay(self):
        with self.runner():
            reviewed = self.create()
            before = self.snapshot()
            rejected = [
                ({"auth": False}, reviewed, 401),
                ({"extra_headers": {"X-Catchplate-Admin-Token": "synthetic-wrong-admin-token"}}, reviewed, 401),
                ({"origin": None}, reviewed, 403),
                ({"origin": "https://foreign.example.com"}, reviewed, 403),
                ({"origin": self.origin + "/"}, reviewed, 403),
                ({"extra_headers": {"Content-Type": "text/plain"}}, reviewed, 422),
                ({"extra_headers": {"Content-Type": None}}, reviewed, 422),
                ({}, b"{", 422), ({}, b"\xff", 422), ({}, {}, 422), ({}, [], 422),
                ({}, {**reviewed, "secret": self.provider_secret}, 422),
                ({}, {**reviewed, "connection_id": 1}, 422),
                ({}, {**reviewed, "connection_id": "AABBCCDD-1111-4222-8333-444444444444"}, 422),
                ({}, {**reviewed, "connection_id": reviewed["connection_id"].replace("-", "")}, 422),
                ({}, {**reviewed, "expected_policy_hash": "sha256:" + "A" * 64}, 422),
                ({}, {**reviewed, "expected_policy_hash": reviewed["expected_policy_hash"] + "\n"}, 422),
                ({}, {**reviewed, "expected_policy_hash": None}, 422),
                ({}, b" " * 1025, 413),
            ]
            for options, payload, expected in rejected:
                with self.subTest(expected=expected, options=options, input_type=type(payload).__name__):
                    code, body, _ = self.request("POST", REVOKE, body=payload,
                        **{"origin": self.origin, **options})
                    self.assertEqual(code, expected, body)
                    self.assertEqual(self.snapshot(), before)
            code, _, _ = self.request("POST", REVOKE + "?extra=1", body=reviewed, origin=self.origin)
            self.assertEqual(code, 422)
            code, _, _ = self.request("GET", REVOKE)
            self.assertEqual(code, 403)  # The operator profile admits only POST here.
            self.assertEqual(self.snapshot(), before)
            raw = json.dumps(reviewed).encode()
            code, body, headers = self.request("POST", REVOKE,
                body=raw + b" " * (1024 - len(raw)), origin=self.origin)
            self.assertEqual(code, 200)
            self.assertEqual(headers.get("cache-control"), "no-store")
            self.assertEqual(headers.get("pragma"), "no-cache")
            result = json.loads(body)
            self.assertEqual(result["revocation"]["enforcement"], "pending")
            self.assertIsNone(result["loaded_policy_hash"])
            committed = self.snapshot()
            code, replay, _ = self.request("POST", REVOKE, body=reviewed, origin=self.origin)
            self.assertEqual(code, 200)
            self.assertEqual(json.loads(replay), result)
            self.assertEqual(self.snapshot(), committed)
            status = self.status()
            self.assertEqual(status["connections"], [])
            self.assertEqual(status["revocations"], [result["revocation"]])
        with self.runner():
            self.assertEqual(self.status(), status)
            code, replay, _ = self.request("POST", REVOKE, body=reviewed, origin=self.origin)
            self.assertEqual(code, 200)
            self.assertEqual(json.loads(replay), result)
            self.assertEqual(self.snapshot(), committed)

    def test_lost_response_replay_after_new_policy_and_stale_unknown_failures(self):
        with self.runner():
            reviewed = self.create()
            self.create("Later live fixture")
            before = self.snapshot()
            code, _, _ = self.request("POST", REVOKE, body=reviewed, origin=self.origin)
            self.assertEqual(code, 409)
            code, _, _ = self.request("POST", REVOKE,
                body={**reviewed, "connection_id": str(uuid.uuid4())}, origin=self.origin)
            self.assertEqual(code, 404)
            self.assertEqual(self.snapshot(), before)
            reviewed["expected_policy_hash"] = self.status()["active_policy_hash"]
            # Discard the first successful response exactly as a lost client response.
            code, _, _ = self.request("POST", REVOKE, body=reviewed, origin=self.origin)
            self.assertEqual(code, 200)
            first_commit = self.snapshot()
            code, body, _ = self.request("POST", REVOKE, body=reviewed, origin=self.origin)
            self.assertEqual(code, 200)
            original = json.loads(body)["revocation"]
            self.assertEqual(self.snapshot(), first_commit)
            self.create("Post-revocation fixture")
            latest = self.status()["active_policy_hash"]
            before = self.snapshot()
            code, body, _ = self.request("POST", REVOKE, body=reviewed, origin=self.origin)
            self.assertEqual(code, 200)
            replay = json.loads(body)
            self.assertEqual(replay["policy_hash"], latest)
            self.assertEqual(replay["revocation"], {**original, "policy_hash": latest, "enforcement": "pending"})
            self.assertEqual(self.snapshot(), before)
            code, _, _ = self.request("POST", REVOKE,
                body={**reviewed, "expected_policy_hash": latest}, origin=self.origin)
            self.assertEqual(code, 409)
            self.assertEqual(self.snapshot(), before)

    def test_real_storage_failure_returns_sanitized_503_and_rolls_back(self):
        with self.runner():
            reviewed = self.create()
            before = self.snapshot()
            with closing(self.connection()) as connection, connection:
                connection.execute("CREATE TRIGGER revocation_http_abort AFTER INSERT ON audit_events "
                    "BEGIN SELECT RAISE(ABORT, 'synthetic private database failure'); END")
            try:
                code, body, _ = self.request("POST", REVOKE, body=reviewed, origin=self.origin)
                self.assertEqual(code, 503)
                self.assertNotIn(b"synthetic private database failure", body)
                self.assertEqual(self.snapshot(), before)
            finally:
                with closing(self.connection()) as connection, connection:
                    connection.execute("DROP TRIGGER revocation_http_abort")
            code, body, _ = self.request("POST", REVOKE, body=reviewed, origin=self.origin)
            self.assertEqual(code, 200)
            self.assertEqual(json.loads(body)["revocation"]["enforcement"], "pending")


if __name__ == "__main__":
    unittest.main(verbosity=2)
