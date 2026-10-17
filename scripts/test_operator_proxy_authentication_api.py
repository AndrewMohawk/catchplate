#!/usr/bin/env python3
"""Actual bounded loopback HTTP tests; not Basic proxy/client acceptance.

Reuses the real operator runner and secret-silent HTTP helpers, not its tests.
Each group has fresh encrypted SQLite state. Restart means a new app process;
there is no gate, provider, native authority, or outbound proxy request here.
"""
from __future__ import annotations

from contextlib import closing
import json
import unittest
import uuid

import test_operator_key_replacement_api as helpers
import test_operator_proxy_authentication as contract

ROUTE = "applications/proxy-authentication"
CONFLICT = {"detail": "operator catalog or policy changed; refresh before trying again"}


class OperatorProxyAuthenticationApiTests(unittest.TestCase):
    setUp = helpers.OperatorKeyReplacementApiTests.setUp
    runner = helpers.OperatorKeyReplacementApiTests.runner
    request = helpers.OperatorKeyReplacementApiTests.request
    status = helpers.OperatorKeyReplacementApiTests.status
    mutation = helpers.OperatorKeyReplacementApiTests.mutation
    database = helpers.OperatorKeyReplacementApiTests.database
    snapshot = helpers.OperatorKeyReplacementApiTests.snapshot
    review = helpers.OperatorKeyReplacementApiTests.review
    rule_body = helpers.OperatorKeyReplacementApiTests.rule_body
    credential = helpers.OperatorKeyReplacementApiTests.credential
    state = helpers.OperatorKeyReplacementApiTests.state
    unchanged = helpers.OperatorKeyReplacementApiTests.unchanged

    def application(self, name="HTTP proxy transport", **extra):
        return self.mutation("applications", {**self.review(), "name": name,
            "token_lifetime_seconds": 3600, **extra})

    def record(self, identifier):
        with closing(self.database()) as conn:
            cursor = conn.execute("SELECT * FROM operator_catalog_applications WHERE id=?", (identifier,))
            row = cursor.fetchone()
            columns = [item[0] for item in cursor.description]
        self.assertIsNotNone(row)
        stored = dict(zip(columns, row))
        data = json.loads(stored.pop("data_json"))
        self.assertIsInstance(data, dict)
        self.assertFalse(set(stored) & set(data), "catalog metadata overlaps storage columns")
        return {**stored, **data}

    def payload(self, identifier, mode=contract.MODE, **changes):
        return {**self.review(), "id": identifier, "proxy_authentication": mode, **changes}

    def assert_mode_change(self, before, response, mode):
        self.assertNotIn("client_token", response)
        self.assertEqual(response["application"]["proxy_authentication"], mode)
        after = self.record(before["id"])
        self.assertTrue(after == {**before, "proxy_authentication": mode, "version": before["version"] + 1},
            "transport change altered token verifier, expiry, identity or unrelated metadata")
        self.assertEqual(response["policy"]["activation"], "pending")
        self.assertIsNone(response["policy"]["loaded_policy_hash"])
        return after

    def test_assigned_change_survives_cold_restart_and_disable_preserves_all_assignments(self):
        with self.runner():
            self.assertEqual(self.status()["capabilities"]["application_proxy_authentication"], contract.CAPABILITY)
            credential = self.credential()
            first = self.application("Changed HTTP app")["application"]
            sibling = self.application("Unchanged HTTP app")["application"]
            rules = [self.mutation("access-rules", self.rule_body(app["id"], credential["id"]))["access_rule"]
                for app in (first, sibling)]
            before_status = self.status()
            before = self.record(first["id"])
            self.assertNotIn("proxy_authentication", before)
            payload = self.payload(first["id"])
            result = self.mutation(ROUTE, payload, expected=200)
            enabled = self.assert_mode_change(before, result, contract.MODE)
            self.assertEqual(result["revision"], payload["expected_revision"] + 1)
            self.assertEqual(result["affected_rule_ids"], [rules[0]["id"]])
            self.assertNotEqual(result["policy"]["policy_hash"], payload["expected_policy_hash"])
            self.assertEqual(result["policy"]["sequence"], before_status["policy"]["sequence"] + 1)
            current = self.status()
            self.assertTrue(current["credentials"] == before_status["credentials"] and
                current["access_rules"] == before_status["access_rules"], "shared assignments changed")
            self.assertTrue(current["applications"][1] == before_status["applications"][1], "sibling app changed")
            policy = json.loads(self.state()[1])
            auth = next(item["proxyAuthorization"] for item in policy["principals"]
                if item["id"] == first["principal_id"])
            self.assertTrue(auth == {"scheme": "Bearer", "tokenId": first["id"],
                "tokenSha256": before["token_sha256"], "expiresAtEpochMs": before["token_expires_at_epoch_ms"],
                "basicTransport": {"username": first["id"]}}, "signed transport binding differs")
            committed = self.state()
        with self.runner():
            self.unchanged(committed)
            self.assertTrue(self.record(first["id"]) == enabled, "cold restart rewrote the opt-in record")
            restarted = self.status()
            self.assertTrue(restarted["applications"] == current["applications"], "cold restart changed public apps")
            payload = self.payload(first["id"], "bearer")
            disabled = self.mutation(ROUTE, payload, expected=200)
            self.assert_mode_change(enabled, disabled, "bearer")
            self.assertEqual(disabled["affected_rule_ids"], [rules[0]["id"]])
            self.assertEqual(disabled["revision"], payload["expected_revision"] + 1)
            self.assertTrue(self.status()["access_rules"] == current["access_rules"], "disable altered assignments")
            policy = json.loads(self.state()[1])
            self.assertTrue(all("basicTransport" not in item["proxyAuthorization"] for item in policy["principals"]))
            with closing(self.database()) as conn:
                events = [json.loads(row[0]) for row in conn.execute(
                    "SELECT event_json FROM audit_events WHERE event_type=? ORDER BY rowid", (contract.EVENT,))]
            self.assertEqual(len(events), 2)
            self.assertEqual([(event["previous_proxy_authentication"], event["proxy_authentication"])
                for event in events], [("bearer", contract.MODE), (contract.MODE, "bearer")])
            self.assertTrue(all(event["affected_rule_ids"] == [rules[0]["id"]] for event in events))

    def test_unassigned_create_optin_and_rotation_do_not_grant_access_or_reset_mode(self):
        with self.runner():
            baseline = self.state()[1]
            default = self.application("Default HTTP app")
            explicit = self.application("Explicit HTTP app", proxy_authentication=contract.MODE)
            self.assertEqual(default["application"]["proxy_authentication"], "bearer")
            self.assertNotIn("proxy_authentication", self.record(default["application"]["id"]))
            self.assertEqual(explicit["application"]["proxy_authentication"], contract.MODE)
            identifier = default["application"]["id"]
            before = self.record(identifier)
            result = self.mutation(ROUTE, self.payload(identifier), expected=200)
            enabled = self.assert_mode_change(before, result, contract.MODE)
            self.assertNotIn("affected_rule_ids", result)
            self.assertTrue(self.state()[1] == baseline, "unassigned opt-in published access")
            rotated = self.mutation("applications/rotate-token", {**self.review(), "id": identifier,
                "token_lifetime_seconds": 7200}, expected=200)
            self.assertTrue(rotated["client_token"] != default["client_token"], "explicit rotation reused token")
            self.assertEqual(rotated["application"]["proxy_authentication"], contract.MODE)
            retained = self.record(identifier)
            self.assertEqual(retained["token_version"], enabled["token_version"] + 1)
            self.assertTrue(retained["token_sha256"] != enabled["token_sha256"], "rotation retained old verifier")
            self.assertEqual(self.status()["access_rules"], [])
            self.assertTrue(self.state()[1] == baseline, "unassigned rotation granted access")
            disabled = self.mutation(ROUTE, self.payload(identifier, "bearer"), expected=200)
            self.assert_mode_change(retained, disabled, "bearer")
            self.assertTrue(self.state()[1] == baseline)

    def test_actual_http_auth_origin_strict_json_cas_and_storage_errors_fail_closed(self):
        with self.runner():
            app = self.application()["application"]
            credential = self.credential()
            self.mutation("access-rules", self.rule_body(app["id"], credential["id"]))
            payload, before = self.payload(app["id"]), self.state()
            duplicate = json.dumps(payload).encode()[:-1] + b',"proxy_authentication":"basic_and_bearer_v1"}'
            missing = {key: value for key, value in payload.items() if key != "proxy_authentication"}
            cases = [
                ({"auth": False}, payload, 401),
                ({"headers": [("X-Catchplate-Admin-Token", "synthetic-wrong")]}, payload, 401),
                ({"origin": None}, payload, 403),
                ({"origin": "https://foreign.example.com"}, payload, 403),
                ({"headers": [("Origin", self.origin)]}, payload, 403),
                ({"headers": [("Content-Type", "application/json")]}, payload, 415),
                ({"headers": [("Content-Type", None), ("Content-Type", "text/plain")]}, payload, 415),
                ({"headers": [("Content-Encoding", "gzip")]}, payload, 415),
                ({}, b"{", 422), ({}, b"\xff", 422), ({}, [], 422), ({}, duplicate, 422),
                ({}, missing, 422), ({}, {**payload, "proxy_authentication": None}, 422),
                ({}, {**payload, "proxy_authentication": "basic"}, 422),
                ({}, {**payload, "proxy_authentication": True}, 422),
                ({}, {**payload, "expected_revision": True}, 422),
                ({}, {**payload, "secret": self.provider_secret}, 422),
                ({}, b" " * 2049, 413),
            ]
            for index, (options, body, expected) in enumerate(cases):
                with self.subTest(case=index):
                    code, raw, headers = self.request("POST", contract.PATH, body=body,
                        **{"origin": self.origin, **options})
                    self.assertEqual(code, expected, "HTTP guard status differs")
                    self.assertEqual(set(json.loads(raw)), {"detail"})
                    self.assertEqual(headers.get("cache-control"), "no-store")
                    self.unchanged(before)
            for change, code in (({"expected_revision": 1}, 409),
                    ({"expected_policy_hash": "sha256:" + "0" * 64}, 409),
                    ({"proxy_authentication": "bearer"}, 409), ({"id": str(uuid.uuid4())}, 404)):
                error = self.mutation(ROUTE, {**payload, **change}, expected=code)
                self.assertEqual(error, CONFLICT if code == 409 else {"detail": "operator catalog resource not found"})
                self.unchanged(before)
            code, _, _ = self.request("POST", contract.PATH + "?extra=1", body=payload, origin=self.origin)
            self.assertEqual(code, 422)
            code, _, _ = self.request("GET", contract.PATH)
            self.assertEqual(code, 403)
            for mode in (None, "basic", True):
                self.mutation("applications", {**self.review(), "name": "Invalid mode", "token_lifetime_seconds": 3600,
                    "proxy_authentication": mode}, expected=422)
                self.unchanged(before)
            with closing(self.database()) as conn, conn:
                conn.execute("CREATE TRIGGER proxy_auth_http_abort BEFORE INSERT ON audit_events "
                    "BEGIN SELECT RAISE(ABORT, 'synthetic private proxy authentication refusal'); END")
            try:
                self.assertEqual(self.mutation(ROUTE, payload, expected=503), {
                    "detail": "operator catalog storage unavailable; inspect saved status before retrying"})
                self.unchanged(before)
            finally:
                with closing(self.database()) as conn, conn:
                    conn.execute("DROP TRIGGER proxy_auth_http_abort")
            encoded = json.dumps(payload).encode()
            result = self.mutation(ROUTE, encoded + b" " * (2048 - len(encoded)), expected=200)
            self.assertEqual(result["application"]["proxy_authentication"], contract.MODE)
            committed = self.state()
            self.assertEqual(self.mutation(ROUTE, payload, expected=409), CONFLICT)
            self.unchanged(committed)
            self.mutation("applications/revoke", {**self.review(), "id": app["id"]}, expected=200)
            revoked = self.state()
            self.assertEqual(self.mutation(ROUTE, self.payload(app["id"], "bearer"), expected=409), CONFLICT)
            self.unchanged(revoked)


if __name__ == "__main__":
    unittest.main(verbosity=2)
