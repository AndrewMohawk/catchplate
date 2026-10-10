#!/usr/bin/env python3
"""Actual loopback X catalog HTTP/SQLite tests, not Rust or X acceptance.

Run with application dependencies, read-only source, private TMPDIR and a
network-none container. The existing real operator runner owns startup,
encryption, signing and persistence. A deliberately synthetic, loopback-only
health receiver supplies the public compatibility declaration through the real
loaded_gate_status HTTP client. It neither forwards requests nor follows new
policy publications automatically. No provider, proxy or native authority runs.

Each group starts a fresh runner; the lifecycle group also cold-restarts that
same private database. The inherited runner bounds startup/shutdown and redacts
its bounded failure log. Suggested outer bound: 300 seconds, no retries.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import threading
import unittest
import uuid

import test_operator_demo_runtime as runtime
import test_operator_workspace_api as workspace

PREFIX = workspace.PREFIX
CREDENTIAL = "credentials/x-app-bearer"
RULE = "access-rules/x-username"
CONNECTION = "x_app_bearer_v1"
BUNDLE = "x_username_read_v1"
USERNAME = "fixture_user"
DESCRIPTOR = {"schema": "serverware.operatorXAppReadGate/v1",
    "adapter": "x.app_read.v1", "operation": "x.username.read"}
CONFLICT = {"detail": "operator catalog or policy changed; refresh before trying again"}
STORAGE = {"detail": "operator catalog storage unavailable; inspect saved status before retrying"}


class OperatorCatalogXApiTests(unittest.TestCase):
    # Borrow only helpers, not the unrelated workspace test groups. No actual
    # application, catalog, health reader or persistence guard is substituted.
    runner = runtime.OperatorDemoRuntimeTests.runner
    request = workspace.OperatorWorkspaceApiTests.request
    database = workspace.OperatorWorkspaceApiTests.database
    snapshot = workspace.OperatorWorkspaceApiTests.snapshot
    status = workspace.OperatorWorkspaceApiTests.status
    review = workspace.OperatorWorkspaceApiTests.review
    mutation = workspace.OperatorWorkspaceApiTests.mutation
    application = workspace.OperatorWorkspaceApiTests.application

    def setUp(self):
        runtime.OperatorDemoRuntimeTests.setUp(self)
        self.environment["SERVERWARE_OPERATOR_DEMO_UPSTREAMS"] = '["https://api.x.com"]'
        self.health_response = (503, b'{}')
        self.health_requests = 0
        self.health_violations = []

    @contextmanager
    def paired_runner(self, *, policy_hash=None):
        owner = self

        class SyntheticHealth(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                owner.health_requests += 1
                if (self.path != "/healthz" or self.client_address[0] != "127.0.0.1"
                        or any(self.headers.get(name) is not None for name in (
                            "Authorization", "Proxy-Authorization", "X-Serverware-Admin-Token"))
                        or owner.health_requests > 256):
                    owner.health_violations.append("unexpected synthetic health request")
                    self.send_error(400)
                    return
                code, body = owner.health_response
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

        self.health_response = (503, b'{}')
        with HTTPServer(("127.0.0.1", 0), SyntheticHealth) as receiver:
            self.environment["SERVERWARE_DECISION_GATE_BASE"] = (
                "http://127.0.0.1:" + str(receiver.server_port))
            thread = threading.Thread(target=receiver.serve_forever,
                kwargs={"poll_interval": 0.05}, daemon=True)
            thread.start()
            try:
                with self.runner():
                    self.serve_gate(policy_hash=policy_hash)
                    yield
            finally:
                receiver.shutdown()
                thread.join(timeout=2)
                self.assertFalse(thread.is_alive(), "synthetic health receiver did not stop")
                self.assertEqual(self.health_violations, [])

    def policy_hash(self):
        with closing(self.database()) as connection:
            rows = connection.execute(
                "SELECT policy_hash FROM operator_demo_policy WHERE singleton=1").fetchall()
        self.assertEqual(len(rows), 1)
        return rows[0][0]

    def serve_gate(self, *, policy_hash=None):
        value = {"ok": True, "policy_hash": policy_hash or self.policy_hash(),
            "operator_x_app_read": dict(DESCRIPTOR)}
        self.health_response = (200, json.dumps(value).encode())
        return value

    def authority(self):
        return self.snapshot(), (self.directory / "data" / "policy-bundle.json").read_bytes()

    def credential_body(self):
        return {**self.review(), "name": "Synthetic X app bearer", "secret": self.provider_secret}

    def rule_body(self, application_id, credential_id):
        return {**self.review(), "name": "Synthetic X username", "application_id": application_id,
            "credential_id": credential_id, "operation_bundle": BUNDLE, "username": USERNAME}

    def failure(self, route, body, expected, *, options=None, exact=None):
        code, raw, headers = self.request("POST", PREFIX + route, body=body,
            **{"origin": self.origin, **(options or {})})
        self.assertEqual(code, expected, raw)
        self.assertEqual(headers.get("cache-control"), "no-store")
        self.assertEqual(headers.get("pragma"), "no-cache")
        value = json.loads(raw)
        self.assertEqual(set(value), {"detail"})
        if exact is not None:
            self.assertEqual(value, exact)
        return value

    def test_transport_and_strict_dto_admission_before_health_or_writes(self):
        with self.paired_runner():
            credential = self.credential_body()
            rule = self.rule_body(str(uuid.uuid4()), str(uuid.uuid4()))
            before = self.authority()
            for route, payload, maximum in ((CREDENTIAL, credential, 16384), (RULE, rule, 4096)):
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
                    ({}, b"{", 422), ({}, b"\xff", 422), ({}, [], 422),
                    ({}, b'{"expected_revision":1,"expected_revision":1}', 422),
                    ({}, {**payload, "unexpected": self.provider_secret}, 422),
                    ({}, {**payload, "expected_revision": True}, 422),
                    ({}, {**payload, "expected_revision": 1.0}, 422),
                    ({}, {**payload, "expected_policy_hash": "sha256:" + "A" * 64}, 422),
                    ({}, b" " * (maximum + 1), 413),
                ]
                invalid_fields = (("secret", "contains space"), ("secret", "x" * 8193)) if route == CREDENTIAL else (
                    ("username", "Upper"), ("username", "a/b"), ("username", "a" * 16),
                    ("application_id", "not-a-uuid"), ("operation_bundle", "x_write_v1"),
                    ("methods", ["POST"]), ("upstream_url", "https://api.x.com/2/users/me"),
                    ("placeholder", "Bearer other"))
                cases.extend(({}, {**payload, key: value}, 422) for key, value in invalid_fields)
                for index, (options, body, expected) in enumerate(cases):
                    with self.subTest(route=route, case=index):
                        count = self.health_requests
                        self.failure(route, body, expected, options=options)
                        self.assertEqual(self.health_requests, count)
                        self.assertEqual(self.authority(), before)
                self.failure(route + "?extra=1", payload, 422)
                code, _, _ = self.request("GET", PREFIX + route)
                self.assertEqual(code, 403)
            self.assertEqual(self.authority(), before)

    def test_old_malformed_and_stale_health_refuse_both_mutations_before_writes(self):
        with self.paired_runner():
            credential = self.mutation(CREDENTIAL, self.credential_body())["credential"]
            application = self.application()["application"]
            bodies = ((CREDENTIAL, self.credential_body()),
                (RULE, self.rule_body(application["id"], credential["id"])))
            healthy = self.serve_gate()
            before = self.authority()
            missing = {key: value for key, value in healthy.items() if key != "operator_x_app_read"}
            bad = [missing, {**healthy, "operator_x_app_read": None},
                {**healthy, "operator_x_app_read": {**DESCRIPTOR, "extra": True}},
                {**healthy, "operator_x_app_read": {**DESCRIPTOR, "schema": "old"}},
                {**healthy, "operator_x_app_read": {**DESCRIPTOR, "adapter": "generic.rest"}},
                {**healthy, "operator_x_app_read": {**DESCRIPTOR, "operation": "x.write"}},
                {**healthy, "policy_hash": "sha256:" + "0" * 64}, {**healthy, "ok": False}]
            responses = [(200, json.dumps(value).encode()) for value in bad]
            responses += [(503, b'{}'), (200, b'{"ok":true,"ok":true}'), (200, b'{')]
            for index, response in enumerate(responses):
                with self.subTest(health=index):
                    self.health_response = response
                    for route, body in bodies:
                        count = self.health_requests
                        self.failure(route, body, 409, exact=CONFLICT)
                        self.assertEqual(self.health_requests, count + 1)
                        self.assertEqual(self.authority(), before)
                    self.assertIsNone(self.status()["capabilities"]["x"])
                    self.assertEqual(self.authority(), before)
            self.serve_gate()
            capability = self.status()["capabilities"]["x"]
            self.assertEqual(capability["connection_type"], CONNECTION)
            self.assertTrue(capability["source_pair_required"])
            self.assertEqual(self.authority(), before)

    def test_real_encrypted_save_app_exact_username_pending_and_cold_restart(self):
        with self.paired_runner():
            initial_hash = self.policy_hash()
            body = self.credential_body()
            encoded = json.dumps(body).encode()
            saved = self.mutation(CREDENTIAL, encoded + b" " * (16384 - len(encoded)))
            credential = saved["credential"]
            self.assertEqual(saved["revision"], body["expected_revision"] + 1)
            self.assertEqual(credential["connection_type"], CONNECTION)
            self.assertEqual(credential["provider_id"], "x")
            self.assertEqual(credential["credential_generation"], 1)
            self.assertEqual(self.policy_hash(), initial_hash)
            self.assertEqual(self.status()["access_rules"], [])
            with closing(self.database()) as connection:
                columns = [row[1] for row in connection.execute("PRAGMA table_info(credentials)")]
                row = connection.execute("SELECT * FROM credentials WHERE id=?", (credential["id"],)).fetchone()
                core = dict(zip(columns, row))
            self.assertEqual(core["encrypted_secret"], "envelope:v2")
            for field in ("encrypted_dek", "secret_nonce", "secret_ciphertext", "secret_kek_id"):
                self.assertIsInstance(core[field], str)
                self.assertTrue(core[field])
            self.assertEqual(json.loads(core["metadata"])["connection_type"], CONNECTION)
            self.assertNotIn(self.provider_secret, repr(core))
            app = self.mutation("applications", {**self.review(), "name": "X ordinary client",
                "token_lifetime_seconds": 3600, "proxy_authentication": "basic_and_bearer_v1"})
            self.assertEqual(app["application"]["proxy_authentication"], "basic_and_bearer_v1")
            self.assertEqual(self.policy_hash(), initial_hash)
            body = self.rule_body(app["application"]["id"], credential["id"])
            encoded = json.dumps(body).encode()
            count = self.health_requests
            result = self.mutation(RULE, encoded + b" " * (4096 - len(encoded)))
            self.assertEqual(self.health_requests, count + 1)
            rule = result["access_rule"]
            self.assertEqual(result["revision"], body["expected_revision"] + 1)
            self.assertEqual(rule["operation_bundle"], BUNDLE)
            self.assertEqual(rule["username"], USERNAME)
            self.assertEqual(rule["upstream_url"], "https://api.x.com/2/users/by/username/" + USERNAME)
            self.assertEqual(rule["methods"], ["GET"])
            self.assertEqual(rule["response_mode"], "x_app_read_json_v1")
            self.assertEqual(rule["enforcement"], "pending")
            self.assertEqual(result["policy"]["activation"], "pending")
            self.assertIsNone(result["policy"]["loaded_policy_hash"])
            self.assertNotEqual(result["policy"]["policy_hash"], initial_hash)
            with closing(self.database()) as connection:
                signed = json.loads(connection.execute(
                    "SELECT signed_bundle_json FROM operator_demo_policy WHERE singleton=1").fetchone()[0])
            route = next(item for item in signed["routes"] if item["id"] == rule["route_id"])
            self.assertEqual(route["match"], {"scheme": "https", "host": "api.x.com", "port": 443,
                "methods": ["GET"], "paths": ["/2/users/by/username/" + USERNAME]})
            self.assertEqual(route["credentialRef"], credential["id"])
            self.assertEqual(route["adapter"]["type"], "x.app_read.v1")
            self.assertEqual(route["credentialHeader"], {"mode": "replaceExact",
                "expectedValue": "Bearer serverware-x-placeholder-v1"})
            committed = self.authority()
            current = self.status()
            self.assertEqual(current["policy"]["activation"], "pending")
            self.assertEqual(current["policy"]["loaded_policy_hash"], initial_hash)
            self.assertIsNone(current["capabilities"]["x"])
            for value in (current, signed, committed[0]):
                public = json.dumps(value)
                self.assertNotIn(self.provider_secret, public)
                self.assertNotIn(app["client_token"], public)
            self.assertEqual(self.authority(), committed)
        # Retain the old synthetic health observation, not a fake gate reload.
        with self.paired_runner(policy_hash=initial_hash):
            restarted = self.status()
            for field in ("revision", "policy", "credentials", "applications", "access_rules", "capabilities"):
                self.assertEqual(restarted[field], current[field])
            self.assertEqual(self.authority(), committed)

    def test_cas_crossed_credential_and_storage_errors_are_fixed_and_atomic(self):
        with self.paired_runner():
            credential = self.mutation(CREDENTIAL, self.credential_body())["credential"]
            application = self.application()["application"]
            generic = self.mutation("credentials", {**self.review(), "name": "Not an X connection",
                "auth_type": "bearer", "secret": self.provider_secret})["credential"]
            bodies = ((CREDENTIAL, self.credential_body()),
                (RULE, self.rule_body(application["id"], credential["id"])))
            before = self.authority()
            for route, body in bodies:
                for change in ({"expected_revision": 1}, {"expected_policy_hash": "sha256:" + "0" * 64}):
                    self.failure(route, {**body, **change}, 409, exact=CONFLICT)
                    self.assertEqual(self.authority(), before)
            rule_body = bodies[1][1]
            self.failure(RULE, {**rule_body, "credential_id": generic["id"]}, 422,
                exact={"detail": "invalid operator catalog input or unsupported policy"})
            self.failure(RULE, {**rule_body, "application_id": str(uuid.uuid4())}, 404,
                exact={"detail": "operator catalog resource not found"})
            self.assertEqual(self.authority(), before)
            with closing(self.database()) as connection, connection:
                connection.execute("CREATE TRIGGER x_http_abort AFTER INSERT ON audit_events "
                    "BEGIN SELECT RAISE(ABORT, 'private synthetic X storage canary'); END")
            try:
                for route, body in bodies:
                    self.failure(route, body, 503, exact=STORAGE)
                    self.assertEqual(self.authority(), before)
            finally:
                with closing(self.database()) as connection, connection:
                    connection.execute("DROP TRIGGER x_http_abort")
            result = self.mutation(RULE, rule_body)
            committed = self.authority()
            self.assertEqual(result["revision"], rule_body["expected_revision"] + 1)
            self.serve_gate()  # Explicit synthetic observation of the new hash.
            self.failure(RULE, rule_body, 409, exact=CONFLICT)
            self.assertEqual(self.authority(), committed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
