#!/usr/bin/env python3
"""Actual loopback workspace HTTP tests; run with --network none/source read-only.

Uses a fresh operator-development runner and real SQLite for each test. The
decision gate is absent, so activation remains pending. These tests are not
Rust enforcement, provider integration, native acceptance, or live proof.
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
import test_operator_workspace_store as store_tests

PREFIX = "/api/operator-demo/"
CATALOG = PREFIX + "catalog"
BODY_LIMITS = {"credentials": 16384, "applications": 2048, "access-rules": 32768,
    "credentials/revoke": 1024, "applications/revoke": 1024,
    "access-rules/revoke": 1024, "applications/rotate-token": 2048}


class OperatorWorkspaceApiTests(unittest.TestCase):
    setUp = runtime.OperatorDemoRuntimeTests.setUp
    runner = runtime.OperatorDemoRuntimeTests.runner

    def request(self, method, path, *, body=None, auth=True, origin=None, headers=None):
        values = [("Connection", "close")]
        if auth:
            values.append(("X-Serverware-Admin-Token", self.admin))
        if origin is not None:
            values.append(("Origin", origin))
        if body is not None:
            if not isinstance(body, bytes):
                body = json.dumps(body).encode()
            values += [("Content-Type", "application/json"), ("Content-Length", str(len(body)))]
        for name, value in headers or []:
            if value is None:
                values = [(key, item) for key, item in values if key.lower() != name.lower()]
            else:
                values.append((name, value))
        client = http.client.HTTPConnection("127.0.0.1", self.port, timeout=8)
        try:
            client.putrequest(method, path)
            for name, value in values:
                client.putheader(name, value)
            client.endheaders(body)
            response = client.getresponse()
            content = response.read(2 * 1024 * 1024 + 1)
            self.assertLessEqual(len(content), 2 * 1024 * 1024)
            self.assertNotIn(self.provider_secret.encode(), content)
            return response.status, content, dict(response.getheaders())
        finally:
            client.close()

    def database(self):
        return sqlite3.connect((self.directory / "data" / "serverware.sqlite3").as_uri() + "?mode=rw", uri=True)

    def snapshot(self):
        with closing(self.database()) as connection:
            return {table: sorted(tuple(row) for row in connection.execute(f"SELECT * FROM {table}"))
                for table in store_tests.LEGACY_TABLES + store_tests.CATALOG_TABLES}

    def status(self):
        code, raw, headers = self.request("GET", CATALOG)
        self.assertEqual(code, 200, raw)
        self.assertEqual(headers.get("cache-control"), "no-store")
        return json.loads(raw)

    def review(self):
        current = self.status()
        return {"expected_revision": current["revision"],
            "expected_policy_hash": current["policy"]["policy_hash"]}

    def mutation(self, route, body, expected=201):
        code, raw, headers = self.request("POST", PREFIX + route, body=body, origin=self.origin)
        self.assertEqual(code, expected, raw)
        self.assertEqual(headers.get("cache-control"), "no-store")
        self.assertEqual(headers.get("pragma"), "no-cache")
        return json.loads(raw)

    def credential(self):
        return self.mutation("credentials", {**self.review(), "name": "HTTP shared credential",
            "auth_type": "bearer", "secret": self.provider_secret})

    def application(self, name="HTTP application"):
        return self.mutation("applications", {**self.review(), "name": name, "token_lifetime_seconds": 3600})

    def rule_body(self, application_id, credential_id):
        return {**self.review(), "name": "HTTP access rule", "application_id": application_id,
            "credential_id": credential_id, "upstream_url": "https://api.example.com/v1/items",
            "methods": ["GET"], "response_fields": ["status"]}

    def test_strict_http_auth_origin_json_media_bounds_and_fixed_errors(self):
        with self.runner():
            reviewed = self.review()
            payload = {**reviewed, "name": "Validated credential", "auth_type": "bearer", "secret": self.provider_secret}
            before = self.snapshot()
            cases = [
                ({"auth": False}, payload, 401),
                ({"headers": [("X-Serverware-Admin-Token", "synthetic-wrong")]}, payload, 401),
                ({"origin": None}, payload, 403),
                ({"origin": "https://foreign.example.com"}, payload, 403),
                ({"origin": self.origin + "/"}, payload, 403),
                ({"headers": [("Origin", self.origin)]}, payload, 403),
                ({"headers": [("Content-Type", None)]}, payload, 415),
                ({"headers": [("Content-Type", None), ("Content-Type", "text/plain")]}, payload, 415),
                ({"headers": [("Content-Type", "application/json")]}, payload, 415),
                ({"headers": [("Content-Encoding", "gzip")]}, payload, 415),
                ({}, b"{", 422), ({}, b"\xff", 422), ({}, [], 422), ({}, {}, 422),
                ({}, b'{"expected_revision":1,"expected_revision":1}', 422),
                ({}, {**payload, "unexpected": self.provider_secret}, 422),
                ({}, {**payload, "expected_revision": True}, 422),
                ({}, {**payload, "expected_revision": 1.0}, 422),
                ({}, {**payload, "expected_policy_hash": "sha256:" + "A" * 64}, 422),
                ({}, {**payload, "secret": self.provider_secret + "\n"}, 422),
                ({}, b" " * 16385, 413),
            ]
            for options, body, expected in cases:
                with self.subTest(expected=expected, options=options, input_type=type(body).__name__):
                    code, raw, headers = self.request("POST", PREFIX + "credentials", body=body,
                        **{"origin": self.origin, **options})
                    self.assertEqual(code, expected, raw)
                    self.assertEqual(headers.get("cache-control"), "no-store")
                    self.assertEqual(set(json.loads(raw)), {"detail"})
                    self.assertEqual(self.snapshot(), before)
            code, _, _ = self.request("POST", PREFIX + "credentials?extra=1", body=payload, origin=self.origin)
            self.assertEqual(code, 422)
            code, _, _ = self.request("GET", CATALOG, auth=False)
            self.assertEqual(code, 401)
            for route, limit in BODY_LIMITS.items():
                with self.subTest(route=route):
                    code, _, _ = self.request("POST", PREFIX + route, body=b" " * (limit + 1), origin=self.origin)
                    self.assertEqual(code, 413)
                    code, _, _ = self.request("GET", PREFIX + route)
                    self.assertEqual(code, 403)
            self.assertEqual(self.snapshot(), before)
            raw = json.dumps(payload).encode()
            result = self.mutation("credentials", raw + b" " * (16384 - len(raw)))
            self.assertEqual(result["revision"], reviewed["expected_revision"] + 1)

    def test_shared_lifecycle_legacy_refusal_tokens_and_restart(self):
        with self.runner():
            initial = self.status()
            credential = self.credential()["credential"]
            first, second = self.application("First HTTP app"), self.application("Second HTTP app")
            first_id, second_id = first["application"]["id"], second["application"]["id"]
            self.assertEqual(self.status()["policy"]["policy_hash"], initial["policy"]["policy_hash"])
            self.assertEqual(self.status()["access_rules"], [])
            self.mutation("access-rules", self.rule_body(first_id, credential["id"]))
            self.mutation("access-rules", self.rule_body(second_id, credential["id"]))
            self.mutation("credentials/revoke", {**self.review(), "id": credential["id"]}, expected=409)
            rotated = self.mutation("applications/rotate-token", {**self.review(), "id": second_id,
                "token_lifetime_seconds": 7200}, expected=200)
            self.assertNotEqual(rotated["client_token"], second["client_token"])
            self.assertEqual(rotated["application"]["token_generation"], 2)
            self.mutation("applications/revoke", {**self.review(), "id": first_id}, expected=200)
            current = self.status()
            self.assertEqual(current["credentials"][0]["status"], "active")
            self.assertEqual({item["application_id"] for item in current["access_rules"] if item["status"] == "active"}, {second_id})
            self.assertIsNone(current["policy"]["loaded_policy_hash"])
            self.assertEqual(current["policy"]["activation"], "pending")
            raw = json.dumps(current)
            for token in (first["client_token"], second["client_token"], rotated["client_token"]):
                self.assertNotIn(token, raw)
            for method, path, body in (("GET", "status", None), ("POST", "connections", {}),
                    ("POST", "connections/revoke", {})):
                code, raw, _ = self.request(method, PREFIX + path, body=body, origin=self.origin)
                self.assertEqual(code, 409, raw)
                self.assertEqual(json.loads(raw)["code"], "operator_demo_resource_model_changed")
                self.assertEqual(json.loads(raw)["catalog_path"], CATALOG)
            committed = self.snapshot()
        with self.runner():
            self.assertEqual(self.status(), current)
            self.assertEqual(self.snapshot(), committed)

    def test_cas_unknown_and_storage_failure_are_fixed_and_atomic(self):
        with self.runner():
            credential = self.credential()["credential"]
            app = self.application()["application"]
            payload = self.rule_body(app["id"], credential["id"])
            before = self.snapshot()
            for change in ({"expected_revision": 1}, {"expected_policy_hash": "sha256:" + "0" * 64}):
                result = self.mutation("access-rules", {**payload, **change}, expected=409)
                self.assertEqual(result, {"detail": "operator catalog or policy changed; refresh before trying again"})
                self.assertEqual(self.snapshot(), before)
            result = self.mutation("applications/revoke", {**self.review(), "id": str(uuid.uuid4())}, expected=404)
            self.assertEqual(result, {"detail": "operator catalog resource not found"})
            self.assertEqual(self.snapshot(), before)
            with closing(self.database()) as connection, connection:
                connection.execute("CREATE TRIGGER workspace_http_abort AFTER INSERT ON audit_events "
                    "BEGIN SELECT RAISE(ABORT, 'private synthetic HTTP storage failure'); END")
            try:
                result = self.mutation("access-rules", payload, expected=503)
                self.assertEqual(result, {"detail": "operator catalog storage unavailable; inspect saved status before retrying"})
                self.assertEqual(self.snapshot(), before)
            finally:
                with closing(self.database()) as connection, connection:
                    connection.execute("DROP TRIGGER workspace_http_abort")
            saved = self.mutation("access-rules", payload)
            self.assertEqual(saved["revision"], payload["expected_revision"] + 1)
            committed = self.snapshot()
            self.mutation("access-rules", payload, expected=409)
            self.assertEqual(self.snapshot(), committed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
