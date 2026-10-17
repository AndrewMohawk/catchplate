#!/usr/bin/env python3
"""Actual loopback HTTP checks for static-key replacement, not proxy acceptance.

Run once in the bounded network-none/read-only-source application test image.
Each group owns fresh SQLite/encryption state and a real operator server. The
restart control starts a new server process against the same synthetic data.
OAuth setup uses the existing synthetic verified-account fixture, not consent,
refresh, provider traffic, or a patched replacement/admission guard. No Rust
gate is present: local cache receipt fields do not prove remote invalidation.
"""
from __future__ import annotations

from contextlib import closing, contextmanager, redirect_stderr
import http.client
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import unittest
import uuid

import test_operator_catalog_google as google_tests
import test_operator_demo_persistence as common
import test_operator_workspace_api as workspace_api

ROOT = Path(__file__).resolve().parents[1]
REPLACE_PATH = workspace_api.PREFIX + "credentials/replace-key"
CONFLICT = {"detail": "operator catalog or policy changed; refresh before trying again"}


def worker(operation, payload):
    """Real decryption/setup in a cold process; stdout contains no secret data."""
    if operation == "seed-google":
        fixture = google_tests.Fixture()
        return {"id": fixture.record["id"]}
    if operation == "check-secret":
        _, db, _, _ = common.backend(initialize=False)
        credential = db.get_credential(payload["id"], include_secret=True)
        return {"matches": credential is not None and credential["secret"] == payload["secret"],
            "generation": credential["credential_version"] if credential is not None else None}
    raise ValueError("unknown key-replacement test worker")


class OperatorKeyReplacementApiTests(unittest.TestCase):
    # Reuse the server/SQLite helpers without inheriting its unrelated test_* methods.
    database = workspace_api.OperatorWorkspaceApiTests.database
    snapshot = workspace_api.OperatorWorkspaceApiTests.snapshot
    review = workspace_api.OperatorWorkspaceApiTests.review
    rule_body = workspace_api.OperatorWorkspaceApiTests.rule_body

    def setUp(self):
        workspace_api.OperatorWorkspaceApiTests.setUp(self)
        self.replacement_secret = self.provider_secret + "-replacement"
        self.sensitive = [self.provider_secret, self.replacement_secret, self.admin,
            google_tests.ACCESS_TOKEN, google_tests.REFRESH_TOKEN, google_tests.CLIENT_SECRET]

    @contextmanager
    def runner(self):
        # The shared harness already bounds and redacts service-token logs, but
        # knows neither this test's OAuth fixture nor its one-time app tokens.
        # Capture its failure diagnostics until all current sensitive values
        # have been removed; preserve the original exception and assertions.
        diagnostic = io.StringIO()
        try:
            with redirect_stderr(diagnostic):
                with workspace_api.OperatorWorkspaceApiTests.runner(self):
                    yield
        finally:
            redacted = diagnostic.getvalue()
            for value in sorted(set(self.sensitive), key=len, reverse=True):
                redacted = redacted.replace(value, "[synthetic test secret]")
            if redacted:
                sys.stderr.write(redacted)

    def request(self, method, path, *, body=None, auth=True, origin=None, headers=None):
        # Same physical HTTP seam as the existing suite, with fail-safe redaction
        # before any status assertion can include a returned body in diagnostics.
        values = [("Connection", "close")]
        if auth:
            values.append(("X-Catchplate-Admin-Token", self.admin))
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
            self.assertFalse(any(secret.encode() in content for secret in self.sensitive),
                "HTTP response exposed synthetic credential/token material")
            return response.status, content, dict(response.getheaders())
        finally:
            client.close()

    def status(self):
        code, raw, headers = self.request("GET", workspace_api.CATALOG)
        self.assertEqual(code, 200, "catalog HTTP status differs")
        self.assertEqual(headers.get("cache-control"), "no-store")
        return json.loads(raw)

    def mutation(self, route, body, expected=201):
        code, raw, headers = self.request("POST", workspace_api.PREFIX + route,
            body=body, origin=self.origin)
        self.assertEqual(code, expected, "mutation HTTP status differs: " + route)
        self.assertEqual(headers.get("cache-control"), "no-store")
        self.assertEqual(headers.get("pragma"), "no-cache")
        document = json.loads(raw)
        if isinstance(document, dict) and isinstance(document.get("client_token"), str):
            self.sensitive.append(document["client_token"])
        return document

    def credential(self, kind="bearer"):
        body = {**self.review(), "name": "HTTP replaceable " + kind,
            "auth_type": kind, "secret": self.provider_secret}
        if kind == "header":
            body["header_name"] = "X-Api-Key"
        return self.mutation("credentials", body)["credential"]

    def application(self, name):
        return self.mutation("applications", {**self.review(), "name": name,
            "token_lifetime_seconds": 3600})["application"]

    def public_credential(self, identifier):
        matches = [item for item in self.status()["credentials"] if item["id"] == identifier]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def replacement(self, credential, **changes):
        return {**self.review(), "id": credential["id"],
            "expected_credential_generation": credential["credential_generation"],
            "secret": self.replacement_secret, **changes}

    def core(self, identifier):
        with closing(self.database()) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute("SELECT * FROM credentials WHERE id=?", (identifier,)).fetchone()
            self.assertIsNotNone(row)
            return dict(row)

    def state(self):
        return self.snapshot(), (self.directory / "data" / "policy-bundle.json").read_bytes()

    def unchanged(self, before):
        # Never let unittest format ciphertexts, verifiers, or private rows.
        self.assertTrue(self.state() == before, "rejected HTTP operation changed persisted state")

    def child(self, operation, payload=None):
        environment = {**common._ENVIRONMENT, **self.environment}
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", operation],
            cwd=ROOT, env=environment, input=json.dumps(payload or {}), capture_output=True,
            text=True, timeout=60)
        self.assertEqual(result.returncode, 0, "synthetic backend worker failed; output intentionally withheld")
        try:
            return json.loads(result.stdout)
        except ValueError:
            self.fail("synthetic backend worker did not return bounded JSON")

    def assert_replaced(self, before, response):
        after = response["credential"]
        self.assertTrue(all(after[key] == before[key]
            for key in ("id", "name", "auth_type", "header_name", "created_at", "status")),
            "key replacement changed credential identity or injection metadata")
        self.assertEqual(after["version"], before["version"] + 1)
        self.assertEqual(after["credential_generation"], before["credential_generation"] + 1)
        self.assertIsInstance(after["key_replaced_at"], str)
        receipt = response["key_replacement"]
        self.assertEqual(set(receipt), {"previous_credential_generation", "credential_generation",
            "cache_invalidation", "in_flight_requests"})
        self.assertEqual(receipt["previous_credential_generation"], before["credential_generation"])
        self.assertEqual(receipt["credential_generation"], after["credential_generation"])
        self.assertIn(receipt["cache_invalidation"], {"local_completed", "local_unconfirmed"})
        self.assertEqual(receipt["in_flight_requests"], "not_recalled")
        return after

    def test_shared_bearer_replacement_keeps_identity_policy_bindings_and_survives_restart(self):
        with self.runner():
            self.assertEqual(self.status()["capabilities"]["static_key_replacement"], {
                "schema": "catchplate.operatorStaticKeyReplacement/v1",
                "path": REPLACE_PATH, "credential_types": ["bearer", "header"]})
            credential = self.credential()
            self.assertIs(type(credential["credential_generation"]), int)
            self.assertEqual(credential["credential_generation"], 1)
            self.assertNotIn("key_replaced_at", credential)
            for label in ("First shared key app", "Second shared key app"):
                app = self.application(label)
                self.mutation("access-rules", self.rule_body(app["id"], credential["id"]))
            before = self.status()
            original_core = self.core(credential["id"])
            policy_bytes = self.state()[1]
            payload = self.replacement(credential)
            response = self.mutation("credentials/replace-key", payload, expected=200)
            updated = self.assert_replaced(credential, response)
            self.assertEqual(response["revision"], payload["expected_revision"] + 1)
            self.assertTrue(response["policy"] == before["policy"], "replacement republished authority")
            current = self.status()
            self.assertTrue(current["applications"] == before["applications"] and
                current["access_rules"] == before["access_rules"], "shared application/rule bindings changed")
            self.assertEqual(updated["active_rule_count"], 2)
            self.assertEqual(current["credentials"], [updated])
            self.assertTrue(self.state()[1] == policy_bytes, "replacement changed signed policy bytes")
            saved_core = self.core(credential["id"])
            self.assertEqual(saved_core["credential_version"], 2)
            self.assertTrue(all(saved_core[key] == original_core[key]
                for key in ("id", "name", "kind", "metadata", "created_at", "lifecycle_status")),
                "core credential metadata changed")
            self.assertTrue(all(saved_core[key] for key in
                ("encrypted_dek", "secret_nonce", "secret_ciphertext", "secret_kek_id")))
            self.assertTrue(saved_core["secret_ciphertext"] != original_core["secret_ciphertext"],
                "replacement did not update encrypted storage")
            self.assertEqual(self.child("check-secret", {"id": credential["id"],
                "secret": self.replacement_secret}), {"matches": True, "generation": 2})
            with closing(self.database()) as connection:
                stored = "\n".join(connection.iterdump())
            self.assertFalse(any(secret in stored for secret in self.sensitive),
                "plaintext synthetic material appeared in SQLite")
            committed = self.state()
        with self.runner():
            restarted = self.status()
            self.assertEqual(restarted["credentials"], [updated])
            self.assertTrue(restarted["applications"] == current["applications"] and
                restarted["access_rules"] == current["access_rules"] and
                restarted["policy"] == current["policy"], "restart changed authority bindings")
            self.unchanged(committed)
            self.assertEqual(self.child("check-secret", {"id": credential["id"],
                "secret": self.replacement_secret}), {"matches": True, "generation": 2})

    def test_custom_header_replacement_preserves_target_without_creating_access(self):
        with self.runner():
            credential = self.credential("header")
            before = self.status()
            payload = self.replacement(credential)
            updated = self.assert_replaced(credential,
                self.mutation("credentials/replace-key", payload, expected=200))
            self.assertEqual(updated["header_name"], "X-Api-Key")
            current = self.status()
            self.assertEqual(current["applications"], [])
            self.assertEqual(current["access_rules"], [])
            self.assertTrue(current["policy"] == before["policy"], "unassigned replacement granted access")
            self.assertEqual(self.child("check-secret", {"id": credential["id"],
                "secret": self.replacement_secret}), {"matches": True, "generation": 2})

    def test_generation_revision_policy_unknown_and_revoked_fail_without_writes(self):
        with self.runner():
            credential = self.credential()
            first_payload = self.replacement(credential)
            credential = self.mutation("credentials/replace-key", first_payload, expected=200)["credential"]
            before = self.state()
            current = self.replacement(credential)
            cases = [("generation", {**current, "expected_credential_generation": 1}, 409, CONFLICT),
                ("revision", {**current, "expected_revision": first_payload["expected_revision"]}, 409, CONFLICT),
                ("policy", {**current, "expected_policy_hash": "sha256:" + "0" * 64}, 409, CONFLICT),
                ("unknown", {**current, "id": str(uuid.uuid4())}, 404,
                    {"detail": "operator catalog resource not found"})]
            for label, payload, expected, error in cases:
                with self.subTest(boundary=label):
                    self.assertEqual(self.mutation("credentials/replace-key", payload, expected=expected), error)
                    self.unchanged(before)
            self.mutation("credentials/revoke", {**self.review(), "id": credential["id"]}, expected=200)
            self.assertIsNone(self.public_credential(credential["id"])["credential_generation"])
            before = self.state()
            self.assertEqual(self.mutation("credentials/replace-key", {**self.review(),
                "id": credential["id"], "expected_credential_generation": 2,
                "secret": self.replacement_secret}, expected=409), CONFLICT)
            self.unchanged(before)

    def test_http_auth_origin_media_and_closed_dto_never_echo_secrets(self):
        with self.runner():
            credential = self.credential()
            payload = self.replacement(credential)
            before = self.state()
            cases = [
                ("missing-auth", {"auth": False}, payload, 401),
                ("wrong-auth", {"auth": False, "headers": [("X-Catchplate-Admin-Token", "synthetic-wrong")]}, payload, 401),
                ("missing-origin", {"origin": None}, payload, 403),
                ("wrong-origin", {"origin": "https://foreign.example.com"}, payload, 403),
                ("wrong-media", {"headers": [("Content-Type", None), ("Content-Type", "text/plain")]}, payload, 415),
                ("duplicate-media", {"headers": [("Content-Type", "application/json")]}, payload, 415),
                ("encoded", {"headers": [("Content-Encoding", "gzip")]}, payload, 415),
                ("extra-field", {}, {**payload, "unexpected": self.provider_secret}, 422),
                ("change-auth-type", {}, {**payload, "auth_type": "header"}, 422),
                ("change-target", {}, {**payload, "header_name": "X-Other-Key"}, 422),
                ("boolean-generation", {}, {**payload, "expected_credential_generation": True}, 422),
                ("empty-secret", {}, {**payload, "secret": ""}, 422),
                ("control-secret", {}, {**payload, "secret": self.provider_secret + "\n"}, 422),
                ("non-ascii-secret", {}, {**payload, "secret": self.provider_secret + "\u2603"}, 422),
                ("invalid-json", {}, b"{", 422),
                ("oversized", {}, b" " * 16385, 413),
            ]
            for label, options, body, expected in cases:
                with self.subTest(boundary=label):
                    code, raw, headers = self.request("POST", REPLACE_PATH, body=body,
                        **{"origin": self.origin, **options})
                    self.assertEqual(code, expected, "replacement HTTP boundary returned unexpected status")
                    self.assertEqual(set(json.loads(raw)), {"detail"})
                    self.assertEqual(headers.get("cache-control"), "no-store")
                    self.unchanged(before)

    def test_real_managed_oauth_record_refuses_static_key_replacement(self):
        self.origin = "https://control.example.com"
        secret_file = self.directory / "google-client-secret"
        secret_file.write_text(google_tests.CLIENT_SECRET + "\n", encoding="utf-8")
        secret_file.chmod(0o600)
        self.environment.update({"CATCHPLATE_OPERATOR_GOOGLE_PROFILE": "operator-google-v1",
            "CATCHPLATE_OPERATOR_DEMO_UPSTREAMS": '["https://api.example.com","https://gmail.googleapis.com"]',
            "CATCHPLATE_PUBLIC_URL": self.origin,
            "CATCHPLATE_GOOGLE_OAUTH_CLIENT_ID": "123-fixture.apps.googleusercontent.com",
            "CATCHPLATE_GOOGLE_OAUTH_REDIRECT_URI": self.origin + "/api/oauth/callback/google",
            "CATCHPLATE_GOOGLE_OAUTH_CLIENT_SECRET_FILE": str(secret_file)})
        identifier = self.child("seed-google")["id"]
        with self.runner():
            credential = self.public_credential(identifier)
            self.assertEqual(credential["auth_type"], "google_oauth")
            self.assertNotIn("credential_generation", credential)
            before = self.state()
            result = self.mutation("credentials/replace-key", {**self.review(), "id": identifier,
                "expected_credential_generation": 1, "secret": self.replacement_secret}, expected=409)
            self.assertEqual(result, CONFLICT)
            self.unchanged(before)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        try:
            print(json.dumps(worker(sys.argv[2], json.load(sys.stdin)), sort_keys=True))
        except Exception as error:
            print(json.dumps({"error_type": type(error).__name__}))
            raise SystemExit(1) from None
    else:
        unittest.main(verbosity=2)
