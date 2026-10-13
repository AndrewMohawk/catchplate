#!/usr/bin/env python3
"""Offline renewal integration: real HTTP, SQLite, Ed25519, signing and restart.

Run in the bounded application-test image with network none, read-only source
and disposable TMPDIR. Each group starts a real operator HTTP process. A
bounded loopback responder SIMULATES management health using the real saved
policy hash and the exact renewal descriptor; it is not a Rust decision gate.
The cold child verifies real signed policy/audit and Python identity matching.
Only its matcher clock is controlled, never a mutation or admission guard.
No provider, SDK, CONNECT continuity, real-time overlap or live claim is made.
"""
from __future__ import annotations

import base64
from contextlib import closing
from copy import deepcopy
from decimal import Decimal
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import secrets
import sqlite3
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import test_operator_demo_persistence as common
import test_operator_key_replacement_api as reusable
import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]
MACHINE = "/api/operator-demo/workloads/renew"
ENROLL = "/api/operator-demo/applications/renewal/enroll"
CANCEL = "/api/operator-demo/applications/renewal/cancel"
DOMAIN = b"serverware.workload-token-renewal/v1\x00POST /v1/workload/renew\x00"
DESCRIPTOR = {"schema": "serverware.proxyTokenRenewal/v1", "path": "/v1/workload/renew",
    "overlap_seconds": 300, "max_request_bytes": 4096, "max_response_bytes": 8192}
RECEIPT_KEYS = {"operation_id", "request_sha256", "application_id", "enrollment_id",
    "previous_generation", "token_generation", "token_sha256", "issued_at_epoch_ms",
    "rotated_at_epoch_ms", "expires_at_epoch_ms", "previous_accept_until_epoch_ms"}
RENEW_EVENT = "operator_catalog.application.token_renewed"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("ascii")


def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def cold_verify(payload):
    """No initialization or writes; actual signature, high-water and audit checks."""
    config, db, store, bundles = common.backend(initialize=False)
    signed = workspace.verify_signed(config, db, store, bundles)
    compiled = bundles.compile_policy_bundle(signed, verify_signature=True, validate_schema=True)
    results = []
    for item in payload.get("matches", []):
        token, app_id = item["token"], payload["application_id"]
        for authorization in ("Bearer " + token, "Basic " + base64.b64encode(
                (app_id + ":" + token).encode("ascii")).decode("ascii")):
            with patch.object(bundles.time, "time", return_value=Decimal(item["at"]) / 1000):
                principal = compiled.identify_principal("127.0.0.1", {"Proxy-Authorization": authorization})
            results.append((principal.id if principal else None) == item["principal"])
    with closing(db.connect()) as conn:
        events = [dict(row) for row in conn.execute(
            "SELECT event_type,actor_type,actor_id,event_json FROM audit_events ORDER BY rowid")]
    renewed = [row for row in events if row["event_type"] == RENEW_EVENT]
    if "receipt" in payload:
        receipt = payload["receipt"]
        joined = [row for row in renewed if json.loads(row["event_json"]).get("operation_id") == receipt["operation_id"]]
        assert len(joined) == 1
        event = json.loads(joined[0]["event_json"])
        assert joined[0]["actor_type"] == "agent" and joined[0]["actor_id"] == payload["principal_id"]
        assert event["resource_id"] == receipt["application_id"]
        assert event["enrollment_id"] == receipt["enrollment_id"]
        assert event["token_generation"] == receipt["token_generation"]
        assert event["token_expires_at_epoch_ms"] == receipt["expires_at_epoch_ms"]
        assert event["policy_hash"] == compiled.hash
    return {"signed_policy_and_audit_valid": True, "all_identity_checks": all(results),
        "identity_checks": len(results), "renewal_events": len(renewed)}


class OperatorWorkloadRenewalTests(unittest.TestCase):
    database = reusable.OperatorKeyReplacementApiTests.database
    snapshot = reusable.OperatorKeyReplacementApiTests.snapshot
    review = reusable.OperatorKeyReplacementApiTests.review
    rule_body = reusable.OperatorKeyReplacementApiTests.rule_body
    runner = reusable.OperatorKeyReplacementApiTests.runner
    request = reusable.OperatorKeyReplacementApiTests.request
    status = reusable.OperatorKeyReplacementApiTests.status
    mutation = reusable.OperatorKeyReplacementApiTests.mutation
    credential = reusable.OperatorKeyReplacementApiTests.credential
    state = reusable.OperatorKeyReplacementApiTests.state
    unchanged = reusable.OperatorKeyReplacementApiTests.unchanged

    def setUp(self):
        reusable.OperatorKeyReplacementApiTests.setUp(self)
        self.key = Ed25519PrivateKey.generate()
        self.public_key = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.sensitive.append(self.key.private_bytes(serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex())
        self.health_mode = "matching"
        self.fixed_hash = None
        self.health_requests = 0
        self.matching_health = 0
        owner = self

        class Health(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                owner.health_requests += 1
                if self.path != "/healthz" or owner.health_requests > 512:
                    self.send_error(503)
                    return
                try:
                    path = owner.directory / "data" / "serverware.sqlite3"
                    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=1)) as conn:
                        policy_hash = conn.execute("SELECT policy_hash FROM operator_demo_policy WHERE singleton=1").fetchone()[0]
                    descriptor = deepcopy(DESCRIPTOR)
                    if owner.health_mode == "wrong_descriptor":
                        descriptor["overlap_seconds"] = 301
                    elif owner.health_mode == "wrong_descriptor_type":
                        descriptor["max_request_bytes"] = "4096"
                    observed = owner.fixed_hash or policy_hash
                    if owner.health_mode == "stale_hash":
                        observed = "sha256:" + "0" * 64
                    body = canonical({"ok": True, "policy_hash": observed,
                        "operator_workload_renewal": descriptor})
                    if descriptor == DESCRIPTOR and observed == policy_hash:
                        owner.matching_health += 1
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(body)
                except (OSError, sqlite3.Error, TypeError):
                    self.send_error(503)

        class BoundedHTTPServer(HTTPServer):
            def get_request(self):
                connection, address = super().get_request()
                connection.settimeout(2)
                return connection, address

        self.health = BoundedHTTPServer(("127.0.0.1", 0), Health)
        self.health.timeout = 0.2
        self.health_stop = threading.Event()

        def serve():
            deadline = time.monotonic() + 180
            while not self.health_stop.is_set() and time.monotonic() < deadline:
                self.health.handle_request()

        self.health_thread = threading.Thread(target=serve, daemon=True)
        self.health_thread.start()
        self.environment["SERVERWARE_DECISION_GATE_BASE"] = "http://127.0.0.1:" + str(self.health.server_port)
        self.addCleanup(self.close_health)

    def close_health(self):
        self.health_stop.set()
        self.health_thread.join(timeout=3)
        self.health.server_close()
        self.assertFalse(self.health_thread.is_alive(), "simulated health thread did not close")

    def record(self, identifier):
        with closing(self.database()) as conn:
            cursor = conn.execute("SELECT * FROM operator_catalog_applications WHERE id=?", (identifier,))
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            stored = dict(zip((item[0] for item in cursor.description), row))
            data = json.loads(stored.pop("data_json"))
            self.assertTrue(type(data) is dict and not set(data).intersection(stored))
            return {**stored, **data}

    def application(self, name="Managed workload", *, basic=True):
        return self.mutation("applications", {**self.review(), "name": name,
            "token_lifetime_seconds": 3600,
            **({"proxy_authentication": "basic_and_bearer_v1"} if basic else {})})

    def seed(self):
        credential = self.credential()
        created = self.application()
        identifier = created["application"]["id"]
        self.mutation("access-rules", self.rule_body(identifier, credential["id"]))
        self.assertNotIn("client_renewal", self.record(identifier), "old apps were implicitly enrolled")
        return identifier, created["client_token"]

    def enroll(self, identifier, **changes):
        return self.mutation("applications/renewal/enroll", {**self.review(), "id": identifier,
            "public_key": self.public_key, "enrollment_lifetime_seconds": 86400,
            "token_lifetime_seconds": 3600, **changes}, expected=200)

    def signed_request(self, identifier, *, key=None, **changes):
        record = self.record(identifier)
        enrollment = record["client_renewal"]
        public = [item for item in self.status()["applications"] if item["id"] == identifier]
        self.assertEqual(len(public), 1)
        advertised = public[0]["client_renewal"]
        self.assertEqual(advertised["enrollment_id"], enrollment["enrollment_id"])
        now = time.time_ns() // 1_000_000
        candidate = secrets.token_urlsafe(32)
        self.sensitive.append(candidate)
        fields = {"schema": "serverware.workloadTokenRenewal/v1",
            # Use the saved public setup, like a real client. Deployment input
            # may contain :443, while the admitted proxy origin omits it.
            "audience": advertised["audience"],
            "application_id": identifier, "enrollment_id": enrollment["enrollment_id"],
            "expected_token_generation": record["token_version"], "operation_id": str(uuid.uuid4()),
            "issued_at_epoch_ms": now, "expires_at_epoch_ms": now + 60000,
            "token_sha256": digest(candidate.encode()),
            "token_expires_at_epoch_ms": min(now + enrollment["token_lifetime_seconds"] * 1000,
                enrollment["expires_at_epoch_ms"]), **changes}
        signature = (key or self.key).sign(DOMAIN + canonical(fields)).hex()
        return {**fields, "signature": signature}, candidate

    def machine(self, payload, expected=200, **options):
        code, raw, headers = self.request("POST", MACHINE, body=payload, auth=False, **options)
        document = json.loads(raw)
        detail = document.get("detail") if type(document) is dict else None
        reason = detail.get("code") if type(detail) is dict else None
        safe_reason = reason if (type(reason) is str and len(reason) <= 80 and reason.isascii()
            and reason.replace("_", "").isalnum()) else "no_fixed_error_code"
        self.assertEqual(code, expected, "machine renewal HTTP status differs: " + safe_reason)
        self.assertLessEqual(len(raw), 8192)
        self.assertEqual(headers.get("cache-control"), "no-store")
        return document

    def verify(self, identifier, matches=(), receipt=None):
        payload = {"application_id": identifier, "principal_id": self.record(identifier)["principal_id"],
            "matches": list(matches), **({"receipt": receipt} if receipt is not None else {})}
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--verify"],
            cwd=ROOT, env={**common._ENVIRONMENT, **self.environment}, input=canonical(payload),
            capture_output=True, timeout=60)
        self.assertEqual(result.returncode, 0, "cold signed-policy/audit check failed; private output withheld")
        self.assertLessEqual(len(result.stdout), 4096)
        checked = json.loads(result.stdout)
        self.assertTrue(checked["signed_policy_and_audit_valid"] and checked["all_identity_checks"])
        self.assertEqual(checked["identity_checks"], 2 * len(matches))
        return checked

    def test_http_renewal_preserves_permissions_and_signs_bounded_overlap(self):
        with self.runner():
            identifier, old = self.seed()
            sibling = self.application("Unenrolled sibling", basic=False)["application"]["id"]
            self.enroll(identifier)
            before, original = self.state(), self.record(identifier)
            reviewed = self.review()
            sibling_before = self.record(sibling)
            payload, candidate = self.signed_request(identifier)
            self.assertEqual(payload["audience"], "https://proxy.example.com/v1/workload/renew")
            response = self.machine(payload)
            receipt, saved = response["operation"], self.record(identifier)
            self.assertEqual(set(response), {"operation", "application", "revision", "policy"})
            self.assertEqual(set(receipt), RECEIPT_KEYS)
            self.assertEqual(receipt["request_sha256"], digest(DOMAIN + canonical(
                {key: value for key, value in payload.items() if key != "signature"})))
            self.assertEqual(receipt["token_generation"], original["token_version"] + 1)
            self.assertEqual(receipt["previous_generation"], original["token_version"])
            self.assertEqual(receipt["token_sha256"], digest(candidate.encode()))
            self.assertEqual(receipt["expires_at_epoch_ms"], payload["token_expires_at_epoch_ms"])
            cutoff = min(original["token_expires_at_epoch_ms"], receipt["rotated_at_epoch_ms"] + 300000)
            self.assertEqual(receipt["previous_accept_until_epoch_ms"], cutoff)
            self.assertEqual(saved["client_renewal"]["last_operation"], receipt)
            self.assertEqual(saved["client_renewal"]["expires_at_epoch_ms"], original["client_renewal"]["expires_at_epoch_ms"])
            self.assertEqual(response["revision"], reviewed["expected_revision"] + 1)
            self.assertEqual(saved["version"], original["version"] + 1)
            changed = {"version", "token_sha256", "token_version", "token_rotated_at",
                "token_expires_at_epoch_ms", "client_renewal"}
            self.assertTrue({key: value for key, value in saved.items() if key not in changed}
                == {key: value for key, value in original.items() if key not in changed},
                "renewal changed application identity or restrictions")
            self.assertTrue(self.record(sibling) == sibling_before, "renewal changed a sibling application")
            after = self.state()
            for table in ("credentials", "credential_generations", "operator_catalog_credentials", "operator_catalog_rules"):
                self.assertTrue(after[0][table] == before[0][table], "renewal changed provider or permission authority")
            self.assertNotEqual(after[1], before[1])
            old_policy, new_policy = json.loads(before[1]), json.loads(after[1])
            self.assertTrue(old_policy["routes"] == new_policy["routes"] and
                old_policy["credentials"] == new_policy["credentials"], "renewal changed signed permission authority")
            self.assertEqual(new_policy["metadata"]["sequence"], old_policy["metadata"]["sequence"] + 1)
            self.assertEqual(response["policy"]["activation"], "active")
            self.assertEqual(response["policy"]["loaded_policy_hash"], response["policy"]["policy_hash"])
            self.assertGreater(self.matching_health, 0, "simulated descriptor/hash was never joined")
            principal = original["principal_id"]
            checks = [{"token": old, "at": cutoff - 1, "principal": principal},
                {"token": old, "at": cutoff, "principal": None},
                {"token": candidate, "at": cutoff, "principal": principal},
                {"token": candidate, "at": receipt["expires_at_epoch_ms"], "principal": None}]
            self.assertEqual(self.verify(identifier, checks, receipt)["renewal_events"], 1)
            with closing(self.database()) as conn:
                dumped = "\n".join(conn.iterdump())
            self.assertFalse(any(value in dumped for value in self.sensitive), "plaintext synthetic secret persisted")

    def test_exact_operation_recovers_after_restart_and_expiry_without_writes(self):
        with self.runner():
            identifier, _ = self.seed()
            self.enroll(identifier)
            payload, _ = self.signed_request(identifier, expires_at_epoch_ms=time.time_ns() // 1_000_000 + 3000)
            committed = self.machine(payload)["operation"]
            before = self.state()
        self.health_mode = "wrong_descriptor"
        with self.runner():
            remaining = (payload["expires_at_epoch_ms"] - time.time_ns() // 1_000_000) / 1000
            if remaining > 0:
                time.sleep(min(remaining + 0.01, 3.1))
            self.assertGreaterEqual(time.time_ns() // 1_000_000, payload["expires_at_epoch_ms"])
            response = self.machine(payload)
            self.assertEqual(response["operation"], committed)
            self.assertEqual(response["policy"]["activation"], "pending")
            self.unchanged(before)
            self.assertEqual(self.verify(identifier, receipt=committed)["renewal_events"], 1)

    def test_proof_generation_and_simulated_gate_readiness_fail_closed(self):
        with self.runner():
            identifier, _ = self.seed()
            for mode in ("stale_hash", "wrong_descriptor", "wrong_descriptor_type"):
                self.health_mode = mode
                before = self.state()
                code, _, _ = self.request("POST", ENROLL, auth=True, origin=self.origin,
                    body={**self.review(), "id": identifier, "public_key": self.public_key})
                self.assertEqual(code, 409)
                self.unchanged(before)
            self.health_mode = "matching"
            self.enroll(identifier)
            now = time.time_ns() // 1_000_000
            cases = [({"audience": "https://other.example.com/v1/workload/renew"}, 401),
                ({"audience": self.environment["SERVERWARE_OPERATOR_DEMO_PROXY_URL"] + "/v1/workload/renew"}, 401),
                ({"enrollment_id": str(uuid.uuid4())}, 409),
                ({"application_id": str(uuid.uuid4())}, 404),
                ({"expected_token_generation": 2}, 409),
                ({"issued_at_epoch_ms": now - 60000, "expires_at_epoch_ms": now - 1}, 401),
                ({"issued_at_epoch_ms": now + 60000, "expires_at_epoch_ms": now + 61000}, 401),
                ({"token_expires_at_epoch_ms": now + 9999999}, 401)]
            before = self.state()
            for changes, expected in cases:
                payload, _ = self.signed_request(identifier, **changes)
                self.machine(payload, expected)
                self.unchanged(before)
            payload, _ = self.signed_request(identifier, key=Ed25519PrivateKey.generate())
            self.machine(payload, 401)
            self.unchanged(before)
            for mode in ("stale_hash", "wrong_descriptor", "wrong_descriptor_type"):
                self.health_mode = mode
                payload, _ = self.signed_request(identifier)
                self.machine(payload, 409)
                self.unchanged(before)
            self.health_mode = "matching"
            payload, _ = self.signed_request(identifier)
            self.machine(payload)
            before = self.state()
            conflicting, _ = self.signed_request(identifier, operation_id=payload["operation_id"])
            self.machine(conflicting, 409)
            next_request, _ = self.signed_request(identifier)
            self.machine(next_request, 409)
            self.unchanged(before)

    def test_http_machine_and_administrator_boundaries(self):
        with self.runner():
            identifier, _ = self.seed()
            enrollment = {**self.review(), "id": identifier, "public_key": self.public_key}
            before = self.state()
            for options, expected in (({"auth": False, "origin": self.origin}, 401),
                    ({"origin": "https://foreign.example.com"}, 403), ({}, 403)):
                code, _, _ = self.request("POST", ENROLL, body=enrollment, **options)
                self.assertEqual(code, expected)
                self.unchanged(before)
            self.enroll(identifier)
            payload, _ = self.signed_request(identifier)
            before = self.state()
            for header in ("Authorization", "Proxy-Authorization", "Cookie", "Origin",
                    "X-Serverware-Admin-Token", "X-Serverware-Bootstrap-Token", "X-Serverware-Data-Plane-Token",
                    "Remote-User", "Remote-Groups", "Remote-Email", "Remote-Name"):
                self.machine(payload, 401, headers=[(header, "synthetic-forbidden")])
                self.unchanged(before)
            for raw in (b'{"schema":"one","schema":"two"}', canonical({**payload, "extra": True}),
                    canonical({**payload, "expected_token_generation": True}), b"[]"):
                self.machine(raw, 422)
                self.unchanged(before)
            for headers in ([('Content-Type', None), ('Content-Type', 'text/plain')],
                    [('Content-Type', 'application/json')], [('Content-Encoding', 'gzip')]):
                self.machine(payload, 400, headers=headers)
                self.unchanged(before)
            self.machine(b" " * 4097, 413)
            for path in (MACHINE + "?extra=1", MACHINE.replace("renew", "%72enew")):
                code, _, _ = self.request("POST", path, body=payload, auth=False)
                self.assertEqual(code, 400)
            self.unchanged(before)
            self.machine(payload)  # Positive proof-authenticated call, without administrator headers.

    def test_manual_lifecycle_invalidates_enrollment_and_old_overlap(self):
        with self.runner():
            credential = self.credential()
            for action in ("cancel", "rotate", "revoke", "replace_enrollment"):
                created = self.application(action)
                identifier, old = created["application"]["id"], created["client_token"]
                self.mutation("access-rules", self.rule_body(identifier, credential["id"]))
                self.enroll(identifier)
                payload, candidate = self.signed_request(identifier)
                receipt = self.machine(payload)["operation"]
                original = self.record(identifier)
                if action == "replace_enrollment":
                    self.enroll(identifier)
                    self.assertNotEqual(self.record(identifier)["client_renewal"]["enrollment_id"], payload["enrollment_id"])
                else:
                    path = {"cancel": "applications/renewal/cancel", "rotate": "applications/rotate-token",
                        "revoke": "applications/revoke"}[action]
                    self.mutation(path, {**self.review(), "id": identifier,
                        **({"token_lifetime_seconds": 3600} if action == "rotate" else {})}, expected=200)
                    self.assertNotIn("client_renewal", self.record(identifier))
                after = self.record(identifier)
                before = self.state()
                self.machine(payload, 409)
                self.unchanged(before)
                self.assertEqual(after["principal_id"], original["principal_id"])
                current_allowed = action in {"cancel", "replace_enrollment"}
                checks = [{"token": candidate, "at": receipt["rotated_at_epoch_ms"] + 1,
                    "principal": original["principal_id"] if current_allowed else None},
                    {"token": old, "at": receipt["rotated_at_epoch_ms"] + 1, "principal": None}]
                self.verify(identifier, checks)

    def test_audit_rollback_and_committed_pending_receipt(self):
        with self.runner():
            identifier, _ = self.seed()
            self.enroll(identifier)
            with closing(self.database()) as conn, conn:
                conn.execute("CREATE TRIGGER renewal_test_abort BEFORE INSERT ON audit_events "
                    "WHEN NEW.event_type='operator_catalog.application.token_renewed' "
                    "BEGIN SELECT RAISE(ABORT,'synthetic renewal audit failure'); END")
            before = self.state()
            payload, _ = self.signed_request(identifier)
            self.machine(payload, 503)
            self.unchanged(before)
            with closing(self.database()) as conn, conn:
                conn.execute("DROP TRIGGER renewal_test_abort")
            self.fixed_hash = self.review()["expected_policy_hash"]
            payload, _ = self.signed_request(identifier)
            committed = self.machine(payload)
            self.assertEqual(committed["policy"]["activation"], "pending")
            self.assertNotEqual(committed["policy"]["policy_hash"], committed["policy"]["loaded_policy_hash"])
            before = self.state()
            replay = self.machine(payload)
            self.assertEqual(replay["operation"], committed["operation"])
            self.unchanged(before)
            self.fixed_hash = None
            recovered = self.machine(payload)
            self.assertEqual(recovered["operation"], committed["operation"])
            self.assertEqual(recovered["policy"]["activation"], "active")
            self.unchanged(before)
            self.assertEqual(self.verify(identifier, receipt=committed["operation"])["renewal_events"], 1)


if __name__ == "__main__":
    if sys.argv[1:] == ["--verify"]:
        try:
            print(json.dumps(cold_verify(json.loads(sys.stdin.buffer.read(32769)))))
        except BaseException:
            sys.stderr.write("cold renewal verification failed; private details withheld\n")
            raise SystemExit(1) from None
    else:
        unittest.main()
