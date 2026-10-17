#!/usr/bin/env python3
"""Real loopback HTTP/encrypted SQLite controls for AWS credential storage.

Run in the cached application image with --network none, read-only source and
a private TMPDIR. The ordinary operator runner performs actual startup,
encryption, transactions, catalog validation and cold reopen. There are no
mocked API/store successes, AWS calls, gate, native authority or signing claims.
An outer 300-second process bound is recommended; no test retries.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
import http.client
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_operator_demo_runtime as runtime
import test_operator_workspace_api as workspace


PREFIX = "/api/operator-demo/"
CREATE = "credentials/aws-sigv4"
REPLACE = CREATE + "/replace"
TYPE = "aws_sigv4_v1"
BODY_LIMIT = 32768
CONFLICT = {"detail": "operator catalog or policy changed; refresh before trying again"}
STORAGE = {"detail": "operator catalog storage unavailable; inspect saved status before retrying"}
INVALID = {"detail": "invalid operator catalog input or unsupported policy"}
CAPABILITY = {
    "schema": "catchplate.operatorAwsCredentials/v1", "connection_type": TYPE,
    "create_path": PREFIX + CREATE, "replace_path": PREFIX + REPLACE,
    "revoke_path": PREFIX + "credentials/revoke",
    "credential_kinds": ["long_term", "session"],
    "signing_available": False, "automatic_renewal": False,
}
# Public AWS documentation examples and a fake companion token, never real keys.
ACCESS = "AKIAIOSFODNN7EXAMPLE"
SESSION_ACCESS = "ASIAIOSFODNN7EXAMPLE"
SECRET = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
TOKEN = "SYNTHETIC-AWS-SESSION-CANARY+/=fixture"


class OperatorCatalogAwsApiTests(unittest.TestCase):
    database = workspace.OperatorWorkspaceApiTests.database
    snapshot = workspace.OperatorWorkspaceApiTests.snapshot
    status = workspace.OperatorWorkspaceApiTests.status
    review = workspace.OperatorWorkspaceApiTests.review
    mutation = workspace.OperatorWorkspaceApiTests.mutation
    application = workspace.OperatorWorkspaceApiTests.application
    rule_body = workspace.OperatorWorkspaceApiTests.rule_body

    def setUp(self):
        runtime.OperatorDemoRuntimeTests.setUp(self)
        for key in tuple(self.environment):
            if key.startswith("AWS_") or key.upper() in {
                    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "BOTO_CONFIG"}:
                self.environment.pop(key)
        self.environment["CATCHPLATE_DECISION_GATE_BASE"] = "http://127.0.0.1:1"
        self.private_values = {ACCESS, SESSION_ACCESS, SECRET, TOKEN, self.provider_secret}
        self.expiry = (datetime.now(timezone.utc) + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.log_checks = 0

    def secretless(self, raw, where):
        if not isinstance(raw, bytes):
            raw = json.dumps(raw, sort_keys=True).encode()
        for secret in self.private_values:
            for representation in (secret.encode(), json.dumps(secret)[1:-1].encode()):
                if representation in raw:
                    self.fail("synthetic AWS material exposed in " + where)

    def request(self, *args, **kwargs):
        result = workspace.OperatorWorkspaceApiTests.request(self, *args, **kwargs)
        self.secretless(result[1], "HTTP response")
        self.secretless(result[2], "HTTP response headers")
        return result

    @contextmanager
    def runner(self):
        # Same real entrypoint/startup/termination bounds as the shared harness;
        # retain and inspect its actual output rather than mocking its logger.
        with tempfile.TemporaryFile(dir=self.directory) as log:
            process = subprocess.Popen([sys.executable, "-B", "-m", "catchplate.operator_demo_runner"],
                cwd=runtime.ROOT, env=self.environment, stdout=log, stderr=subprocess.STDOUT)
            failed = False
            try:
                deadline = time.monotonic() + 35
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        self.fail("operator runner exited before listening")
                    try:
                        status, _, _ = self.request("GET", "/healthz")
                    except (OSError, http.client.HTTPException):
                        time.sleep(0.1)
                        continue
                    self.assertEqual(status, 200)
                    break
                else:
                    self.fail("operator runner did not listen within 35 seconds")
                yield
            except BaseException:
                failed = True
                raise
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=7)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
                log.seek(0)
                output = log.read(2 * 1024**2 + 1)
                self.secretless(output, "runner log")
                self.assertLessEqual(len(output), 2 * 1024**2, "runner log exceeded test bound")
                self.log_checks += 1
                if failed:
                    text = output[-16000:].decode(errors="replace")
                    for value in sorted(self.private_values | {self.environment["CATCHPLATE_" + name]
                            for name in runtime.TOKEN_NAMES}, key=len, reverse=True):
                        text = text.replace(value, "[synthetic private value]")
                    print("Bounded AWS catalog runner diagnostics:\n" + text, file=sys.stderr)

    def tuple_body(self, *, session=False, **changes):
        value = {"credential_kind": "session" if session else "long_term",
            "access_key_id": SESSION_ACCESS if session else ACCESS,
            "secret_access_key": SECRET, "session_token": TOKEN if session else None,
            "expires_at": self.expiry if session else None}
        value.update(changes)
        for key in ("access_key_id", "secret_access_key", "session_token"):
            if isinstance(value[key], str) and len(value[key]) >= 16:
                self.private_values.add(value[key])
        return value

    def create_body(self, **changes):
        return {**self.review(), "name": "Synthetic AWS credential", **self.tuple_body(**changes)}

    def replace_body(self, identifier, generation, **changes):
        return {**self.review(), "id": identifier, "expected_credential_generation": generation,
            **self.tuple_body(**changes)}

    def authority(self):
        return self.snapshot(), (self.directory / "data" / "policy-bundle.json").read_bytes()

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

    def encrypted_row(self, identifier, generation):
        with closing(self.database()) as connection:
            columns = [row[1] for row in connection.execute("PRAGMA table_info(credentials)")]
            row = connection.execute("SELECT * FROM credentials WHERE id=?", (identifier,)).fetchone()
            high_water = connection.execute(
                "SELECT last_version FROM credential_generations WHERE credential_id=?", (identifier,)).fetchone()
        self.assertIsNotNone(row)
        result = dict(zip(columns, row))
        self.assertEqual(result["kind"], TYPE)
        self.assertEqual(result["credential_version"], generation)
        self.assertEqual(high_water, (generation,))
        self.assertEqual(result["encrypted_secret"], "envelope:v2")
        for field in ("encrypted_dek", "secret_nonce", "secret_ciphertext", "secret_kek_id"):
            self.assertIsInstance(result[field], str)
            self.assertTrue(result[field])
        self.secretless(result, "plaintext credential columns")
        return result

    def public_credential(self, value, *, kind, generation, expiry=None, replaced=False, revoked=False):
        required = {"id", "name", "created_at", "status", "version", "auth_type", "header_name",
            "active_rule_count", "credential_generation", "connection_type", "provider_id",
            "credential_kind", "expires_at", "expired", "signing_available"}
        self.assertEqual(set(value), required | ({"key_replaced_at"} if replaced else set())
                         | ({"revoked_at"} if revoked else set()))
        self.assertEqual(str(uuid.UUID(value["id"])), value["id"])
        self.assertEqual(value["auth_type"], TYPE)
        self.assertEqual(value["connection_type"], TYPE)
        self.assertEqual(value["provider_id"], "aws")
        self.assertIsNone(value["header_name"])
        self.assertIs(type(value["active_rule_count"]), int)
        self.assertEqual(value["active_rule_count"], 0)
        self.assertEqual(value["credential_kind"], kind)
        if generation is not None:
            self.assertIs(type(value["credential_generation"]), int)
        self.assertEqual(value["credential_generation"], generation)
        self.assertEqual(value["expires_at"], expiry)
        self.assertIs(value["expired"], False)
        self.assertIs(value["signing_available"], False)
        self.assertEqual(value["status"], "revoked" if revoked else "active")
        self.secretless(value, "public credential")

    def private_database(self):
        self.secretless(self.snapshot(), "plaintext SQL/audit/catalog rows")
        # Check actual private database files as well as live row projections.
        # A small overlap also catches a canary crossing a read boundary.
        overlap = 2 * max(len(value.encode()) for value in self.private_values) + 16
        for name in ("catchplate.sqlite3", "catchplate.sqlite3-wal", "catchplate.sqlite3-shm"):
            path = self.directory / "data" / name
            if not path.exists():
                continue
            consumed, previous = 0, b""
            with path.open("rb") as stream:
                while chunk := stream.read(1024**2):
                    consumed += len(chunk)
                    self.assertLessEqual(consumed, 64 * 1024**2, "private database fixture exceeded bound")
                    self.secretless(previous + chunk, "SQLite file bytes")
                    previous = (previous + chunk)[-overlap:]

    def test_http_auth_origin_methods_media_bounds_and_closed_dtos(self):
        with self.runner():
            create = self.create_body()
            replace = self.replace_body(str(uuid.uuid4()), 1)
            before = self.authority()
            for route, body in ((CREATE, create), (REPLACE, replace)):
                duplicate = (b'{"access_key_id":' + json.dumps(body["access_key_id"]).encode()
                             + b"," + json.dumps(body).encode()[1:])
                cases = [
                    ({"auth": False}, body, 401),
                    ({"headers": [("X-Catchplate-Admin-Token", "synthetic-wrong")]}, body, 401),
                    ({"origin": None}, body, 403),
                    ({"origin": "https://foreign.example.com"}, body, 403),
                    ({"origin": self.origin + "/"}, body, 403),
                    ({"headers": [("Origin", self.origin)]}, body, 403),
                    ({"headers": [("Content-Type", None)]}, body, 415),
                    ({"headers": [("Content-Type", "application/json")]}, body, 415),
                    ({"headers": [("Content-Type", None), ("Content-Type", "text/plain")]}, body, 415),
                    ({"headers": [("Content-Encoding", "gzip")]}, body, 415),
                    ({}, b"{", 422), ({}, b"\xff", 422), ({}, [], 422),
                    ({}, duplicate, 422),
                    ({}, {**body, "unexpected": SECRET}, 422),
                    ({}, {**body, "expected_revision": True}, 422),
                    ({}, {**body, "expected_revision": 1.0}, 422),
                    ({}, {**body, "expected_policy_hash": "sha256:" + "A" * 64}, 422),
                    ({}, b" " * (BODY_LIMIT + 1), 413),
                ]
                if route == CREATE:
                    cases += [({}, {**body, "id": str(uuid.uuid4())}, 422)]
                else:
                    cases += [({}, {**body, "name": "not a rename"}, 422)]
                    cases += [({}, {**body, "expected_credential_generation": value}, 422)
                              for value in (True, 1.0, 0, -1, "1")]
                for index, (options, payload, code) in enumerate(cases):
                    with self.subTest(route=route, case=index):
                        self.failure(route, payload, code, options=options)
                        self.assertEqual(self.authority(), before)
                self.failure(route + "?extra=1", body, 422)
                for method in ("GET", "PUT", "PATCH", "DELETE"):
                    code, _, _ = self.request(method, PREFIX + route, origin=self.origin)
                    self.assertEqual(code, 403)
                self.assertEqual(self.authority(), before)

    def test_whole_tuple_kinds_expiry_and_secret_grammar_refuse_without_writes(self):
        with self.runner():
            saved = self.mutation(CREATE, self.create_body())["credential"]
            reviewed = self.review()
            before = self.authority()
            invalid = [
                (False, {"credential_kind": "temporary"}),
                (False, {"credential_kind": True}),
                (False, {"access_key_id": SESSION_ACCESS}),
                (False, {"access_key_id": ACCESS.lower()}),
                (False, {"access_key_id": ACCESS + "0"}),
                (False, {"secret_access_key": "x" * 39}),
                (False, {"secret_access_key": "x" * 41}),
                (False, {"secret_access_key": "!" * 40}),
                (False, {"secret_access_key": None}),
                (False, {"session_token": TOKEN}),
                (False, {"expires_at": self.expiry}),
                (True, {"access_key_id": ACCESS}),
                (True, {"session_token": None}),
                (True, {"session_token": ""}),
                (True, {"session_token": "x" * 8193}),
                (True, {"session_token": "contains space"}),
                (True, {"session_token": "line\nbreak"}),
                (True, {"expires_at": None}),
                (True, {"expires_at": "1970-01-01T00:00:00Z"}),
                (True, {"expires_at": "2099-02-30T00:00:00Z"}),
                (True, {"expires_at": "2099-01-01T00:00:00+00:00"}),
                (True, {"expires_at": "2099-01-01T00:00:00.000Z"}),
                (True, {"expires_at": True}),
            ]
            for index, (session, changes) in enumerate(invalid):
                fields = self.tuple_body(session=session, **changes)
                for route, selector in ((CREATE, {"name": "Invalid AWS tuple"}),
                        (REPLACE, {"id": saved["id"], "expected_credential_generation": 1})):
                    with self.subTest(case=index, route=route):
                        self.failure(route, {**reviewed, **selector, **fields}, 422)
                        self.assertEqual(self.authority(), before)
            # There is no partial replacement operation: these missing required
            # key fields cannot mean "retain the previous encrypted value".
            for field in ("credential_kind", "access_key_id", "secret_access_key", "session_token", "expires_at"):
                for route, selector in ((CREATE, {"name": "Incomplete tuple"}),
                        (REPLACE, {"id": saved["id"], "expected_credential_generation": 1})):
                    body = {**reviewed, **selector, **self.tuple_body()}
                    del body[field]
                    self.failure(route, body, 422)
                    self.assertEqual(self.authority(), before)

    def test_encrypted_complete_tuple_replacement_and_cold_restart(self):
        with self.runner():
            initial = self.status()
            self.assertEqual(initial["capabilities"]["aws_credentials"], CAPABILITY)
            original_policy = self.authority()[1]
            create = self.create_body()
            first = self.mutation(CREATE, create)
            credential = first["credential"]
            identifier = credential["id"]
            self.assertEqual(first["revision"], create["expected_revision"] + 1)
            self.public_credential(credential, kind="long_term", generation=1)
            first_row = self.encrypted_row(identifier, 1)
            # Re-submitting the identical complete tuple is still an intentional
            # whole-generation replacement, not a secret equality/no-op probe.
            body = self.replace_body(identifier, 1)
            replaced = self.mutation(REPLACE, body, expected=200)
            self.assertEqual(replaced["revision"], body["expected_revision"] + 1)
            self.public_credential(replaced["credential"], kind="long_term", generation=2, replaced=True)
            receipt = replaced["key_replacement"]
            self.assertEqual(set(receipt), {"previous_credential_generation", "credential_generation",
                                           "cache_invalidation", "in_flight_requests"})
            for key in ("previous_credential_generation", "credential_generation"):
                self.assertIs(type(receipt[key]), int)
            self.assertEqual((receipt["previous_credential_generation"], receipt["credential_generation"]), (1, 2))
            self.assertIn(receipt["cache_invalidation"], {"local_completed", "local_unconfirmed"})
            self.assertEqual(receipt["in_flight_requests"], "not_recalled")
            second_row = self.encrypted_row(identifier, 2)
            self.assertNotEqual(first_row["secret_ciphertext"], second_row["secret_ciphertext"])
            self.assertNotEqual(first_row["secret_nonce"], second_row["secret_nonce"])
            body = self.replace_body(identifier, 2, session=True, secret_access_key="Z" * 40)
            third = self.mutation(REPLACE, body, expected=200)
            self.public_credential(third["credential"], kind="session", generation=3,
                                   expiry=self.expiry, replaced=True)
            third_row = self.encrypted_row(identifier, 3)
            self.assertNotEqual(second_row["secret_ciphertext"], third_row["secret_ciphertext"])
            self.assertEqual(third["credential"]["name"], credential["name"])
            # Worst-case escaped legal token exceeds the old 16 KiB body bound.
            max_token = '\\"' * 4096
            session = self.create_body(session=True, session_token=max_token)
            raw = json.dumps(session).encode()
            self.assertGreater(len(raw), 16384)
            self.assertLess(len(raw), BODY_LIMIT)
            session_result = self.mutation(CREATE, raw + b" " * (BODY_LIMIT - len(raw)))
            session_id = session_result["credential"]["id"]
            self.public_credential(session_result["credential"], kind="session", generation=1, expiry=self.expiry)
            self.encrypted_row(session_id, 1)
            current = self.status()
            self.assertEqual(current["access_rules"], [])
            self.assertEqual(current["applications"], [])
            self.assertEqual(current["policy"]["policy_hash"], initial["policy"]["policy_hash"])
            self.assertEqual(current["policy"]["sequence"], initial["policy"]["sequence"])
            self.assertEqual(current["policy"]["activation"], "pending")
            self.assertIsNone(current["policy"]["loaded_policy_hash"])
            self.assertEqual(self.authority()[1], original_policy)
            committed = self.authority()
            self.secretless(current, "fresh catalog")
        self.private_database()
        with self.runner():
            restarted = self.status()
            for field in ("revision", "policy", "credentials", "applications", "access_rules", "capabilities"):
                self.assertEqual(restarted[field], current[field])
            self.assertEqual(self.authority(), committed)
            self.assertEqual(self.encrypted_row(identifier, 3), third_row)
            self.encrypted_row(session_id, 1)
        self.assertEqual(self.log_checks, 2)
        self.private_database()

    def test_aws_has_no_generic_grant_or_static_key_replacement_and_revokes_locally(self):
        with self.runner():
            credential = self.mutation(CREATE, self.create_body())["credential"]
            generic = self.mutation("credentials", {**self.review(), "name": "Generic bearer",
                "auth_type": "bearer", "secret": self.provider_secret})["credential"]
            app = self.application()["application"]
            before = self.authority()
            self.failure("access-rules", self.rule_body(app["id"], credential["id"]), 422, exact=INVALID)
            self.assertEqual(self.authority(), before)
            self.failure("credentials/replace-key", {**self.review(), "id": credential["id"],
                "expected_credential_generation": 1, "secret": SECRET}, 409, exact=CONFLICT)
            self.assertEqual(self.authority(), before)
            self.failure(REPLACE, self.replace_body(generic["id"], 1), 409, exact=CONFLICT)
            self.assertEqual(self.authority(), before)
            self.failure("credentials", {**self.review(), "name": "Wrong generic constructor",
                "auth_type": TYPE, "secret": SECRET}, 422)
            self.assertEqual(self.authority(), before)
            revoked = self.mutation("credentials/revoke", {**self.review(), "id": credential["id"]}, expected=200)
            self.public_credential(revoked["credential"], kind="long_term", generation=None, revoked=True)
            with closing(self.database()) as connection:
                self.assertIsNone(connection.execute("SELECT id FROM credentials WHERE id=?", (credential["id"],)).fetchone())
            current = self.status()
            self.assertEqual(current["access_rules"], [])
            self.assertEqual(current["capabilities"]["aws_credentials"], CAPABILITY)
            committed = self.authority()
            self.failure(REPLACE, self.replace_body(credential["id"], 1), 409, exact=CONFLICT)
            self.assertEqual(self.authority(), committed)
        with self.runner():
            restarted = self.status()
            self.assertEqual(restarted["credentials"], current["credentials"])
            self.assertEqual(self.authority(), committed)
        self.private_database()

    def test_revision_policy_generation_cas_and_storage_rollback_are_exact(self):
        with self.runner():
            credential = self.mutation(CREATE, self.create_body())["credential"]
            create = self.create_body(session=True)
            replace = self.replace_body(credential["id"], 1, secret_access_key="Y" * 40)
            before = self.authority()
            for route, body in ((CREATE, create), (REPLACE, replace)):
                for wrong in ({"expected_revision": 1}, {"expected_policy_hash": "sha256:" + "0" * 64}):
                    self.failure(route, {**body, **wrong}, 409, exact=CONFLICT)
                    self.assertEqual(self.authority(), before)
            self.failure(REPLACE, {**replace, "expected_credential_generation": 2}, 409, exact=CONFLICT)
            self.assertEqual(self.authority(), before)
            self.failure(REPLACE, {**replace, "id": str(uuid.uuid4())}, 404,
                         exact={"detail": "operator catalog resource not found"})
            self.assertEqual(self.authority(), before)
            # An actual SQLite abort after mutation work must roll back the
            # encrypted tuple, catalog revision, generation and all audit rows.
            with closing(self.database()) as connection, connection:
                connection.execute("CREATE TRIGGER aws_http_abort AFTER INSERT ON audit_events "
                    "BEGIN SELECT RAISE(ABORT, 'private synthetic AWS storage canary'); END")
            try:
                for route, body in ((CREATE, create), (REPLACE, replace)):
                    self.failure(route, body, 503, exact=STORAGE)
                    self.assertEqual(self.authority(), before)
            finally:
                with closing(self.database()) as connection, connection:
                    connection.execute("DROP TRIGGER aws_http_abort")
            saved = self.mutation(REPLACE, replace, expected=200)
            self.assertEqual(saved["credential"]["credential_generation"], 2)
            committed = self.authority()
            # Fresh catalog CAS but stale expected generation is still refused.
            self.failure(REPLACE, {**replace, **self.review()}, 409, exact=CONFLICT)
            self.assertEqual(self.authority(), committed)
            self.encrypted_row(credential["id"], 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
