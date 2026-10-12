#!/usr/bin/env python3
"""Closed proof construction/refusal controls with explicit owner doubles.

No signatures, live nonce storage or connected ASGI acceptance are claimed.
The real metadata validator and hash construction run; the separate joined
lifecycle tests must establish actual owner, catalog and signing admission.
"""
import base64
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import serverware
from serverware import db, operator_demo, oauth_application_owner as owner
from serverware import control_plane_credential_currentness as currentness
from serverware import control_plane_custody_startup as custody
from serverware import operator_x_admission as admission
from serverware import operator_x_configuration as configuration
from serverware import operator_x_oauth_profile as profiles
from serverware import operator_catalog_x_oauth as catalog
from serverware.operator_catalog_schema import CatalogIntegrityError
from serverware import operator_x_lease_reconciliation as proof


def no_external_effects(event, _args):
    if event in {"socket.connect", "socket.getaddrinfo", "socket.bind"} or event.startswith("sqlite3."):
        raise AssertionError("reconciliation component tests forbid external effects")


sys.addaudithook(no_external_effects)
ID = "22ea63d6-013c-435e-88ee-b52075397709"
OP = "e4c8e794-5cd5-4adb-8d28-5a3474198619"
SHA = "sha256:" + "a" * 64
UNCONTROLLED = {"controlled": False, "issuanceKind": None, "requestAuthority": None,
    "requestAuthoritySha256": None, "releaseAuthorization": None}
KEYS = {"apiVersion", "capability", "profileBindingSha256", "outcome", "reason", "purpose",
    "requestBodySha256", "requestBindingSha256", "policyHash", "scope", "dataPlaneBinaryDigest",
    "recipientKeyId", "recipientNonceSha256", "expectedCredentialVersion", "expectedMetadataSha256",
    "observedCredentialVersion", "observedMetadataSha256", "issuedAtEpochMs", "expiresAtEpochMs"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value).encode()).hexdigest()


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.profile = profiles.build_profile(client_id="synthetic-client", public_origin="https://operator.example.com")
        self.binding = {"operation_id": OP, "owner_id": ID, "config_version": 1,
            "profile_binding_digest": self.profile.binding_digest, "public_profile": profiles.public_record(self.profile)}
        metadata = {"oauth": True, "provider": "x.oauth2", "provider_id": "x",
            "oauth_client_id": self.profile.client_id, "x_app_id": self.profile.client_id,
            "provider_subject": "123", "provider_account": "@synthetic", "provider_identity_verified": True,
            "scopes": list(profiles.SCOPES), "refreshable": True, "injection_field": "access_token",
            "expires_at_epoch_ms": 1_900_000_000_000,
            "operator_x_account": {"schema": "serverware.operatorXAccountBinding/v1", "owner_id": ID,
                "configuration_operation_id": OP, "config_version": 1,
                "profile_binding_digest": self.profile.binding_digest, "intent_id": OP}}
        self.committed = {"id": ID, "kind": "oauth2", "credential_version": 2,
            "lifecycle_status": "active", "metadata": metadata}
        self.prepared = deepcopy(self.committed)
        nonce = b"N" * 32
        self.nonce = base64.urlsafe_b64encode(nonce).rstrip(b"=").decode()
        self.nonce_digest = "sha256:" + hashlib.sha256(nonce).hexdigest()
        self.payload = SimpleNamespace(api_version="serverware.credentialLeaseRequest/v3",
            purpose="dispatchSecret", request_authority=None, release_authorization=None,
            model_fields_set=set(), data_plane_binary_digest=SHA, recipient_nonce=self.nonce,
            credential_id=ID, expected_credential_version=1, expected_metadata_sha256=SHA,
            policy_hash=SHA, route_id="operator.synthetic", principal_id="app.synthetic",
            recipient_key_id=SHA, max_ttl_seconds=30)
        self.request = SimpleNamespace(scope={})
        self.original = {"recipientPublicKey": "synthetic-public", "extraBoundField": "retained"}
        self.signature_inputs = ("POST", "/api/data-plane/credential-leases", "", self.nonce, True, False)
        self.snapshot = SimpleNamespace(hash=SHA)
        self.public = {"provider_id": "x", "provider_subject": "123", "scopes": list(profiles.SCOPES)}
        self.application = SimpleNamespace(EXPECTED_DATA_PLANE_BINARY_DIGEST=SHA,
            _request_signature_inputs=lambda _: self.signature_inputs,
            _CREDENTIAL_LEASE_ORIGINAL_SCOPE_KEY="synthetic-original",
            _original_data_plane_request=lambda *_: self.original,
            _canonical_json=canonical, _credential_lease_request_binding_sha256=lambda _: SHA,
            _decode_unpadded_base64url=lambda *_args, **_kwargs: nonce,
            get_policy_snapshot=lambda: self.snapshot,
            _assert_credential_lease_route_binding=lambda *_: {"id": ID},
            _active_route_by_id=lambda *_args, **_kwargs: {"id": self.payload.route_id},
            _assert_credential_lease_release_authorization=lambda *_args, **_kwargs: UNCONTROLLED,
            _assert_credential_policy_binding=lambda *_: self.events.append("credential-policy"),
            _assert_credential_injection_binding=lambda *_: self.events.append("injection"),
            _assert_route_credential_binding=lambda *_: self.events.append("route"),
            _credential_lease_public_metadata=lambda _: self.public,
            _credential_lease_metadata_sha256=digest)

        @contextmanager
        def connection():
            self.events.append("read-open")
            yield SimpleNamespace(execute=lambda sql: self.assertEqual(sql, "BEGIN"))
            self.events.append("read-close")

        @contextmanager
        def generation(credential_id):
            self.assertEqual(credential_id, ID)
            self.events.append("generation-open")
            yield self.committed
            self.events.append("generation-close")

        def join(_conn, **kwargs):
            self.assertEqual(kwargs, {"principal_id": self.payload.principal_id,
                "route_id": self.payload.route_id, "credential_id": ID,
                "core_credential": self.committed, "profile": self.profile})
            self.events.append("catalog-join")

        self.patches = {}
        for name, replacement in {
                "app": patch.object(serverware, "app", self.application, create=True),
                "active": patch.object(operator_demo, "active", return_value=True),
                "enabled": patch.object(admission, "enabled", return_value=True),
                "runtime": patch.object(admission, "require_runtime", return_value=object()),
                "connection-check": patch.object(admission, "check_connection", return_value=None),
                "owner": patch.object(owner, "require_started", return_value=None),
                "currentness": patch.object(currentness, "selected", return_value=False),
                "broker": patch.object(custody, "credential_broker_selected", return_value=False),
                "connection": patch.object(db, "metadata_connection", connection),
                "generation": patch.object(db, "credential_generation_snapshot", generation),
                "nonce": patch.object(db, "credential_lease_nonce_reserved", return_value=True),
                "binding": patch.object(configuration, "retained_public_binding", return_value=self.binding),
                "join": patch.object(catalog, "require_lease_binding", join),
                "clock": patch.object(proof.time, "time_ns", return_value=1_900_000_000_000_000_000),
        }.items():
            self.patches[name] = replacement.start()
            self.addCleanup(replacement.stop)

    def call(self, **changes):
        arguments = {"prepared_credential": self.prepared,
            "prepared_metadata_sha256": digest(self.public), "request_binding_sha256": SHA,
            "recipient_nonce_sha256": self.nonce_digest, "dispatch_authority": deepcopy(UNCONTROLLED),
            "claimed_release_authorization": None, "profile": "legacy", "wrapped": False,
            "broker": False, "refresh_opening": None, "currentness_opening": None}
        arguments.update(changes)
        return proof.pre_encryption_generation_conflict(self.request, self.payload, **arguments)

    def test_exact_closed_x_proof_original_body_and_bounded_expiry(self):
        value = json.loads(self.call())
        self.assertEqual(set(value), KEYS)
        self.assertEqual(value["capability"], "operator-x-oauth-v1")
        self.assertEqual(value["profileBindingSha256"], self.profile.binding_digest)
        self.assertEqual(value["requestBodySha256"], digest(self.original))
        self.assertEqual(value["recipientNonceSha256"], self.nonce_digest)
        self.assertEqual(value["observedCredentialVersion"], 2)
        self.assertEqual(value["expectedCredentialVersion"], 1)
        self.assertEqual(value["expiresAtEpochMs"] - value["issuedAtEpochMs"], 5000)
        self.assertEqual(self.events.count("catalog-join"), 1)
        self.assertEqual(self.events.count("generation-open"), 1)
        self.assertEqual(self.events.count("read-open"), self.events.count("read-close"))
        self.assertNotIn("secret", canonical(value).lower().replace("nosecretenvelopeissued", "").replace("dispatchsecret", ""))

    def test_no_native_controlled_wrapped_currentness_or_claimed_openings(self):
        for key, value in (("profile", "native-v1"), ("wrapped", True), ("broker", True),
                ("refresh_opening", {}), ("currentness_opening", {}),
                ("claimed_release_authorization", {}), ("dispatch_authority", {"controlled": True})):
            self.assertIsNone(self.call(**{key: value}))
        self.assertEqual(self.events, [])
        for key in ("request_authority", "release_authorization"):
            self.payload.model_fields_set = {key}
            self.assertIsNone(self.call())

    def test_wrong_provider_marker_or_malformed_metadata_cannot_borrow_google(self):
        self.prepared["metadata"]["provider_id"] = "google"
        self.assertIsNone(self.call())
        self.prepared["metadata"]["provider_id"] = "x"
        self.prepared["metadata"].pop("operator_x_account")
        self.assertIsNone(self.call())
        self.prepared["metadata"]["operator_x_account"] = None
        with self.assertRaises(CatalogIntegrityError):
            self.call()

    def test_exact_runtime_binary_request_binding_nonce_and_policy(self):
        for name, denied in (("active", False), ("enabled", False), ("owner", object()),
                ("currentness", True), ("broker", True), ("nonce", False)):
            original = self.patches[name].return_value
            self.patches[name].return_value = denied
            self.assertIsNone(self.call(), name)
            self.patches[name].return_value = original
        for name in ("prepared_metadata_sha256", "request_binding_sha256", "recipient_nonce_sha256"):
            self.assertIsNone(self.call(**{name: "sha256:" + "b" * 64}))
        self.application.EXPECTED_DATA_PLANE_BINARY_DIGEST = "sha256:" + "b" * 64
        self.assertIsNone(self.call())
        self.application.EXPECTED_DATA_PLANE_BINARY_DIGEST = SHA
        self.snapshot.hash = "sha256:" + "b" * 64
        self.assertIsNone(self.call())

    def test_exact_http_request_and_positive_strict_generation(self):
        original = self.signature_inputs
        for index, value in ((0, "GET"), (1, "/other"), (2, "extra=1"), (3, "other"), (5, True)):
            self.signature_inputs = tuple(value if offset == index else old for offset, old in enumerate(original))
            self.assertIsNone(self.call())
        self.signature_inputs = original
        for generation in (None, True, 1, 3, 1 << 64):
            self.committed["credential_version"] = generation
            self.assertIsNone(self.call())
        self.committed["credential_version"] = 2
        self.payload.expected_credential_version = True
        self.assertIsNone(self.call())

    def test_configuration_and_catalog_drift_never_emit_proof(self):
        different = deepcopy(self.binding)
        different["owner_id"] = OP
        for changes in ([self.binding, different], [self.binding, self.binding, different]):
            self.patches["binding"].side_effect = changes
            self.assertIsNone(self.call())
        self.patches["binding"].side_effect = None
        with patch.object(catalog, "require_lease_binding", side_effect=ValueError("fixed refusal")):
            with self.assertRaises(ValueError):
                self.call()


if __name__ == "__main__":
    unittest.main()
