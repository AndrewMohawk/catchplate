#!/usr/bin/env python3
"""Offline refresh orchestration, not connected custody or provider proof.

Real protocol/metadata validation and capture correlation run against explicit
transaction/store/transport doubles. No socket, SQLite, keys or app startup is
used; the separate connected lifecycle suite owns those integration claims.
"""
from contextlib import contextmanager
from copy import deepcopy
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import serverware
from serverware import db, oauth, operator_publication as publication
from serverware import operator_provider_key as keys
from serverware import operator_x_admission as admission
from serverware import operator_x_configuration as configuration
from serverware import operator_x_oauth_profile as profiles
from serverware import operator_x_oauth_protocol as protocol
from serverware import operator_x_refresh as refresh
from serverware import operator_x_transport as transport
from serverware import operator_catalog_x_oauth as catalog


def no_external_effects(event, _args):
    if event in {"socket.connect", "socket.getaddrinfo", "socket.bind"} or event.startswith("sqlite3."):
        raise AssertionError("refresh component tests forbid external effects")


sys.addaudithook(no_external_effects)
ID = "22ea63d6-013c-435e-88ee-b52075397709"
WORK = "e4c8e794-5cd5-4adb-8d28-5a3474198619"
OWNER = "4e378b3d-c178-4b90-8f27-4810675f3eee"
CONFIGURATION = "aa2b22ca-7af6-4270-9b86-d99acee70f80"
INTENT = "d52c8bf5-209f-477e-8093-a442a9764c91"
CANARY = "synthetic-private-refresh-canary"
WALL_MS = 1_900_000_000_000
PRINCIPAL = "operator-app.synthetic"
ROUTE = "operator.synthetic"
POLICY = "sha256:" + "a" * 64
LEASE_BINDING = {"principal_id": PRINCIPAL, "route_id": ROUTE, "credential_id": ID, "policy_hash": POLICY}


def raw(value):
    return json.dumps(value, separators=(",", ":")).encode()


class RefreshTests(unittest.TestCase):
    def setUp(self):
        self.events, self.captures, self.deadlines = [], [], []
        self.clock, self.locked, self.transaction = 100.0, False, False
        self.used, self.interrupted, self.complete = False, False, True
        self.late, self.adopt_error, self.hold_error = False, False, False
        self.subject = "123"
        self.catalog_allowed, self.policy_hash = True, POLICY
        self.token_body = raw({"access_token": CANARY + "-access", "refresh_token": CANARY + "-new",
            "token_type": "bearer", "expires_in": 7200, "scope": " ".join(profiles.SCOPES)})
        self.profile = profiles.build_profile(client_id="synthetic-client", public_origin="https://operator.example.com")
        self.binding = {"operation_id": CONFIGURATION, "owner_id": OWNER, "config_version": 1,
            "profile_binding_digest": self.profile.binding_digest,
            "public_profile": profiles.public_record(self.profile)}
        self.metadata = {"oauth": True, "provider": "x.oauth2", "provider_id": "x",
            "oauth_client_id": self.profile.client_id, "x_app_id": self.profile.client_id,
            "provider_subject": "123", "provider_account": "@synthetic", "provider_identity_verified": True,
            "scopes": list(profiles.SCOPES), "refreshable": True, "injection_field": "access_token",
            "expires_at_epoch_ms": WALL_MS - 1,
            "operator_x_account": {"schema": "serverware.operatorXAccountBinding/v1",
                "owner_id": OWNER, "configuration_operation_id": CONFIGURATION,
                "config_version": 1, "profile_binding_digest": self.profile.binding_digest, "intent_id": INTENT}}
        self.credential = {"id": ID, "kind": "oauth2", "credential_version": 1,
            "lifecycle_status": "active", "metadata": self.metadata}
        self.selection = SimpleNamespace(record=self.binding, profile=self.profile,
            client_secret=CANARY + "-client", key_pin=object())

        class Connection:
            def execute(inner, sql):
                if sql == "SELECT policy_hash FROM operator_demo_policy WHERE singleton=1":
                    self.assertTrue(self.locked and self.transaction)
                    self.events.append("current-policy")
                    return SimpleNamespace(fetchone=lambda: (self.policy_hash,))
                self.assertEqual(sql, "BEGIN IMMEDIATE")
                self.assertTrue(self.locked)
                self.transaction = True
                self.events.append("begin")

            def commit(inner):
                self.assertTrue(self.transaction)
                self.events.append("commit")
                self.transaction = False

        @contextmanager
        def connection():
            try:
                yield Connection()
            finally:
                self.transaction = False
                self.events.append("connection-exit")

        @contextmanager
        def exclusive():
            self.assertFalse(self.locked)
            self.locked = True
            try:
                yield
            finally:
                self.locked = False
                self.events.append("unlock")

        @contextmanager
        def selected(*_args):
            self.assertTrue(self.transaction)
            self.events.append("open-private-selection")
            try:
                yield self.selection
            finally:
                self.events.append("close-private-selection")

        def claim(_conn, *, credential_id, expected_version, lease_binding):
            self.assertEqual((credential_id, expected_version), (ID, 1))
            self.assertEqual(lease_binding, LEASE_BINDING)
            self.assertTrue(self.locked and self.transaction)
            self.assertLess(self.events.index("authorize"), self.events.index("open-private-selection"))
            if self.used:
                raise ValueError(CANARY)
            self.used = True
            self.events.append("claim-refresh")
            return {"work_id": WORK, "selection": deepcopy(self.binding), "credential_id": ID,
                "generation": 1, "metadata": deepcopy(self.metadata), "lease_binding": deepcopy(lease_binding),
                "secret": json.dumps({"token_type": "bearer", "refresh_token": CANARY + "-old"})}

        def claim_contact(_conn, work_id, *, request, deadline):
            self.assertEqual(work_id, WORK)
            self.assertTrue(self.locked and self.transaction)
            self.events.append("claim-" + request.phase)
            self.deadlines.append(deadline)

        def capture(_conn, work_id, value):
            self.assertEqual(work_id, WORK)
            self.assertTrue(self.locked and self.transaction)
            self.events.append("capture-" + value.request.phase)
            self.captures.append(value)

        def adopt(_conn, work_id, *, token, identity):
            self.assertEqual(work_id, WORK)
            self.assertTrue(self.locked and self.transaction)
            self.assertIs(type(token), protocol.AcceptedToken)
            self.assertIs(type(identity), protocol.AcceptedIdentity)
            self.assertEqual([item.request.phase for item in self.captures], ["refresh", "identity"])
            self.events.append("adopt")
            if self.adopt_error:
                raise ValueError(CANARY)
            result = deepcopy(self.credential)
            result["credential_version"] = 2
            result["metadata"]["expires_at_epoch_ms"] = WALL_MS + 7_200_000
            return result

        def hold(*_args, **kwargs):
            self.assertEqual(kwargs, {"reason": "refresh_failed"})
            self.events.append("hold")
            if self.hold_error:
                raise ValueError(CANARY)

        self.store = SimpleNamespace(current=lambda *_: {"credential": deepcopy(self.credential),
            "metadata": deepcopy(self.metadata), "selection": deepcopy(self.binding)},
            claim_refresh=claim, claim_contact=claim_contact, capture=capture, adopt_refresh=adopt, hold=hold)

        def send(request, *, work_id, deadline):
            self.assertFalse(self.locked or self.transaction)
            self.assertEqual(self.events[-3:], ["commit", "connection-exit", "unlock"])
            self.events.append("send-" + request.phase)
            self.deadlines.append(deadline)
            body = self.token_body if request.phase == "refresh" else raw({"data": {
                "id": self.subject, "name": "Synthetic", "username": "synthetic"}})
            captured = transport._capture(request, work_id, deadline, 200,
                (("Content-Type", "application/json"),), body, b"synthetic-wire:" + body, self.complete)
            if self.late:
                self.clock = 111.0
            if self.interrupted:
                raise transport.TransportInterrupted(captured)
            return captured

        def check_connection(*_args):
            self.assertTrue(self.locked and self.transaction)

        def authorize(_conn, **kwargs):
            self.assertTrue(self.locked and self.transaction)
            self.assertEqual(kwargs, {"principal_id": PRINCIPAL, "route_id": ROUTE,
                "credential_id": ID, "core_credential": self.credential, "profile": self.profile})
            self.events.append("authorize")
            if not self.catalog_allowed:
                raise ValueError("synthetic revoked application or rule")

        for replacement in (patch.object(serverware, "operator_x_account_store", self.store, create=True),
                patch.object(db, "metadata_connection", connection),
                patch.object(publication, "exclusive", exclusive),
                patch.object(publication, "assert_not_held", lambda: self.assertFalse(self.locked)),
                patch.object(admission, "require_runtime", return_value=object()),
                patch.object(admission, "check_connection", check_connection),
                patch.object(catalog, "require_lease_binding", authorize),
                patch.object(configuration, "retained_public_binding", return_value=self.binding),
                patch.object(configuration, "_retained_selection", selected),
                patch.object(keys, "check_pin", return_value=None),
                patch.object(refresh.time, "monotonic", lambda: self.clock),
                patch.object(refresh.time, "time_ns", return_value=WALL_MS * 1_000_000),
                patch.object(transport, "send", send)):
            replacement.start()
            self.addCleanup(replacement.stop)

    def run_refresh(self, version=1, deadline=110.0, **pins):
        arguments = {"principal_id": PRINCIPAL, "route_id": ROUTE, "policy_hash": POLICY, "deadline": deadline}
        arguments.update(pins)
        return refresh.prepare_for_lease(ID, version, **arguments)

    def refused(self, **kwargs):
        with self.assertRaises(refresh.RefreshUnavailable) as caught:
            self.run_refresh(**kwargs)
        self.assertEqual(str(caught.exception), refresh._ERROR)
        self.assertNotIn(CANARY, repr(caught.exception))

    def test_marker_presence_blocks_global_and_google_fallback(self):
        for marker in (None, {}, "malformed", {"schema": "wrong"}):
            metadata = {"operator_x_account": marker}
            self.assertTrue(refresh.selected({"metadata": metadata}))
            with patch.object(oauth, "provider_for", side_effect=AssertionError("global provider resolved")):
                with self.assertRaisesRegex(oauth.OAuthError, "requires its retained account owner"):
                    oauth.refresh_access_token(provider_id="x", token_secret={}, metadata=metadata)
        self.assertFalse(refresh.selected({"metadata": {"oauth": True, "provider_id": "x"}}))

    def test_healthy_and_advanced_generation_are_metadata_only(self):
        for advanced in (False, True):
            self.credential["credential_version"] = 2 if advanced else 1
            self.metadata["expires_at_epoch_ms"] = WALL_MS - 1 if advanced else WALL_MS + 61_000
            result = self.run_refresh()
            self.assertEqual(result, self.credential)
            self.assertNotIn("open-private-selection", self.events)
            self.assertFalse(self.used)
            self.assertEqual(self.captures, [])

    def test_current_catalog_and_policy_are_required_before_all_return_or_refresh_paths(self):
        for path in ("refresh", "healthy", "advanced"):
            for denial in ("catalog", "policy", "principal", "route"):
                with self.subTest(path=path, denial=denial):
                    self.events.clear()
                    self.credential["credential_version"] = 2 if path == "advanced" else 1
                    self.metadata["expires_at_epoch_ms"] = WALL_MS + 61_000 if path == "healthy" else WALL_MS - 1
                    self.catalog_allowed = denial != "catalog"
                    self.policy_hash = "sha256:" + "b" * 64 if denial == "policy" else POLICY
                    pins = {denial + "_id": "wrong-scope"} if denial in ("principal", "route") else {}
                    self.refused(**pins)
                    self.assertFalse(self.used)
                    self.assertNotIn("open-private-selection", self.events)
                    self.assertNotIn("claim-refresh", self.events)
                    self.assertEqual(self.captures, [])

    def test_malformed_caller_pins_refuse_before_storage(self):
        for field in ("principal_id", "route_id", "policy_hash"):
            for value in (None, True, "", "x" * 513):
                self.events.clear()
                self.refused(**{field: value})
                self.assertEqual(self.events, [])
        for value in ("a" * 64, "sha256:" + "A" * 64, "sha256:" + "g" * 64):
            self.refused(policy_hash=value)
        self.assertFalse(self.used)

    def test_success_exact_one_shot_order_original_deadline_and_no_secrets(self):
        result = self.run_refresh()
        important = [item for item in self.events if item.startswith(("claim-", "send-", "capture-")) or item == "adopt"]
        self.assertEqual(important, ["claim-refresh", "claim-refresh", "send-refresh", "capture-refresh",
            "claim-identity", "send-identity", "capture-identity", "adopt"])
        self.assertTrue(all(item is self.deadlines[0] and item.expires_at == 110.0 for item in self.deadlines))
        self.assertEqual(result["credential_version"], 2)
        self.assertEqual(set(result), {"id", "kind", "credential_version", "lifecycle_status", "metadata"})
        self.assertNotIn(CANARY, json.dumps(result))
        self.assertNotIn("hold", self.events)

    def test_incomplete_valid_json_is_retained_without_classification(self):
        self.complete = False
        with patch.object(protocol, "classify_token_response", side_effect=AssertionError("incomplete codec")):
            self.refused()
        self.assertEqual(len(self.captures), 1)
        self.assertIn(CANARY.encode(), self.captures[0].body)
        self.assertLess(self.events.index("capture-refresh"), self.events.index("hold"))
        self.assertNotIn("send-identity", self.events)

    def test_late_and_interrupted_responses_are_retained_before_hold(self):
        for mode in ("late", "interrupted"):
            with self.subTest(mode=mode):
                self.events.clear()
                self.used, self.clock = False, 100.0
                self.late, self.interrupted = mode == "late", mode == "interrupted"
                self.refused()
                self.assertLess(self.events.index("capture-refresh"), self.events.index("hold"))
                self.assertNotIn("send-identity", self.events)

    def test_uncertain_missing_rotated_token_and_mixed_error_never_replay(self):
        values = [raw({"access_token": CANARY, "token_type": "bearer", "expires_in": 7200,
                    "scope": " ".join(profiles.SCOPES)}),
            raw({"error": "invalid_grant", "refresh_token": CANARY}),
            b'{"access_token":"first","access_token":"second"}']
        for body in values:
            self.events.clear()
            self.used = False
            self.token_body = body
            self.refused()
            self.assertEqual(self.events.count("send-refresh"), 1)
            self.assertNotIn("send-identity", self.events)
            self.assertEqual(self.captures[-1].body, body)
            self.refused()
            self.assertEqual(self.events.count("send-refresh"), 1)

    def test_subject_drift_or_losing_adoption_retains_both_without_replay(self):
        for mismatch in (True, False):
            self.events.clear()
            self.captures.clear()
            self.used = False
            self.subject, self.adopt_error = ("456", False) if mismatch else ("123", True)
            self.refused()
            self.assertEqual(len(self.captures), 2)
            self.assertEqual(self.events.count("send-refresh"), 1)
            self.assertEqual(self.events.count("send-identity"), 1)
            self.assertEqual("adopt" in self.events, not mismatch)
            self.assertIn("hold", self.events)
            self.assertEqual(self.credential["credential_version"], 1)

    def test_hold_write_failure_preserves_claim_and_fixed_refusal(self):
        self.complete, self.hold_error = False, True
        self.refused()
        self.refused()
        self.assertTrue(self.used)
        self.assertEqual(self.events.count("send-refresh"), 1)

    def test_expired_invalid_deadline_or_generation_never_claims(self):
        for value in (100.0, 99.0, float("inf"), float("nan"), True, "110"):
            self.refused(deadline=value)
        for version in (True, 0, 2):
            self.refused(version=version)
        self.assertFalse(self.used)
        self.assertEqual(self.captures, [])

    def test_configuration_pin_and_malformed_metadata_refuse_before_contact(self):
        with patch.object(keys, "check_pin", side_effect=ValueError(CANARY)):
            self.refused()
        self.assertTrue(self.used)
        self.assertIn("hold", self.events)
        self.assertEqual(self.captures, [])
        self.used = False
        self.metadata["operator_x_account"] = None
        self.refused()
        self.assertFalse(self.used)


if __name__ == "__main__":
    unittest.main()
