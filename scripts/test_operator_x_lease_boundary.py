#!/usr/bin/env python3
"""Source-selected lease handler controls, not signed HTTP/owner acceptance.

The unchanged app handler, X-selection wrapper, body-budget function and token
projection run here, with explicit synthetic admission/DB/audit dependencies.
Envelope encryption is the actual production X25519/HKDF/AESGCM function and
the successful control is independently decrypted. No provider, SQLite, key
custody, signature admission, gate or durable publication is established.
"""
from __future__ import annotations

import ast
import asyncio
import base64
from contextlib import ExitStack, contextmanager
from copy import deepcopy
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def no_external_effects(event, _arguments):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo", "subprocess.Popen", "os.system"} or event.startswith("sqlite3."):
        raise AssertionError("lease boundary tests forbid external effects")


sys.addaudithook(no_external_effects)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from starlette.exceptions import HTTPException
from starlette.responses import Response
import serverware
from serverware import credential_lease_profiles

ID = "11111111-2222-4333-8444-555555555555"
POLICY = "sha256:" + "a" * 64
BINARY = "sha256:" + "b" * 64
DEADLINE_KEY = "serverware.operator-x-lease-deadline"
ACCESS = "synthetic-x-lease-access-canary"
REFRESH = "synthetic-x-private-refresh-canary"
UNCONTROLLED = {"controlled": False, "issuanceKind": None, "requestAuthority": None,
    "requestAuthoritySha256": None, "releaseAuthorization": None}
APP_TREE = ast.parse((ROOT / "serverware/app.py").read_text())


def selected_functions(tree, names, namespace, filename):
    nodes = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names]
    if {node.name for node in nodes} != set(names):
        raise AssertionError("production function roster changed")
    module = ast.Module(body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0), *nodes], type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), filename, "exec"), namespace)
    return namespace


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value).encode()).hexdigest()


def encoded(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decoded(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


CRYPTO = selected_functions(ast.parse((ROOT / "serverware/crypto.py").read_text()),
    {"encrypt_credential_lease_envelope", "canonical_json_bytes", "_b64e"},
    {"X25519PublicKey": X25519PublicKey, "X25519PrivateKey": X25519PrivateKey,
        "AESGCM": AESGCM, "HKDF": HKDF, "hashes": hashes, "serialization": serialization,
        "os": os, "json": json, "hashlib": hashlib, "base64": base64}, "serverware/crypto.py")
X_SELECTED = selected_functions(ast.parse((ROOT / "serverware/operator_x_refresh.py").read_text()),
    {"selected"}, {}, "serverware/operator_x_refresh.py")["selected"]


class NativeWrapper:
    pass


class Fixture:
    """Successful admission seams are doubles, never a production authority."""
    def __init__(self, provider="x", purpose="dispatchSecret", *, audit_advance=0.0):
        self.now = 100.0
        self.events = []
        self.audit_advance = audit_advance
        self.locked = False
        self.private = X25519PrivateKey.generate()
        public = self.private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.nonce = b"N" * 32
        metadata = {} if provider == "ordinary" else {"oauth": True, "provider_id": provider,
            "expires_at_epoch_ms": 4_102_444_800_000}
        if provider == "x":
            metadata["operator_x_account"] = {"synthetic": "marker detection only"}
        self.credential = {"id": ID, "credential_version": 7, "lifecycle_status": "active",
            "kind": "bearer" if provider == "ordinary" else "oauth2", "metadata": metadata,
            "secret": ACCESS if provider == "ordinary" else canonical({"access_token": ACCESS, "refresh_token": REFRESH})}
        self.public = {key: deepcopy(value) for key, value in self.credential.items() if key != "secret"}
        self.payload = SimpleNamespace(api_version="serverware.credentialLeaseRequest/v3", purpose=purpose,
            principal_id="app.synthetic", route_id="operator.synthetic", credential_id=ID,
            expected_credential_version=7 if purpose == "dispatchSecret" else None,
            expected_metadata_sha256=digest(metadata) if purpose == "dispatchSecret" else None,
            policy_hash=POLICY, data_plane_binary_digest=BINARY, recipient_public_key=encoded(public),
            recipient_key_id="sha256:" + hashlib.sha256(public).hexdigest(), recipient_nonce=encoded(self.nonce),
            recipient_attestation=None, max_ttl_seconds=5, request_authority=None, release_authorization=None)
        self.request = SimpleNamespace(scope={DEADLINE_KEY: (self.payload, 110.0)})
        self.snapshot = SimpleNamespace(hash=POLICY)
        self.route = SimpleNamespace(id=self.payload.route_id, adapter_type="x.post.v1", constraints=[])
        self.credential_policy = SimpleNamespace(injection={"type": "bearer", "header": "Authorization", "field": "access_token"})
        self.prepare = Mock(side_effect=self._prepare)
        self.runtime_read = Mock(return_value=deepcopy(self.credential))
        self.binding = Mock(side_effect=self._binding)
        self.connection = SimpleNamespace(execute=Mock(), close=Mock())
        self.db = SimpleNamespace(get_credential=Mock(return_value=self.public),
            credential_lease_nonce_reserved=Mock(return_value=False), reserve_credential_lease_nonce=Mock(return_value="reserved"),
            credential_generation_snapshot=self._snapshot, credential_lease_snapshot=self._snapshot,
            credential_ciphertext_snapshot=self._snapshot, connect=Mock(return_value=self.connection))
        self.modules = {
            "control_plane_credential_currentness": SimpleNamespace(selected=lambda: False),
            "control_plane_custody_startup": SimpleNamespace(credential_broker_selected=lambda: False),
            "oauth_application_owner": SimpleNamespace(require_started=lambda: None),
            "operator_github_app": SimpleNamespace(selected=lambda _: False),
            "operator_x_refresh": SimpleNamespace(selected=X_SELECTED, prepare_for_lease=self.prepare),
            "operator_catalog_x_oauth": SimpleNamespace(require_lease_binding=self.binding),
            "aws_credential_boundary": SimpleNamespace(credential_selected=lambda _: False),
        }
        self.responses = Mock(side_effect=Response)
        self.encrypt = Mock(side_effect=self._encrypt)
        self.audit = Mock(side_effect=self._audit)
        self.ns = {"app": SimpleNamespace(post=lambda _path: lambda function: function), "Depends": lambda _: None,
            "NativeCurrentCredentialLeaseRequest": NativeWrapper, "CredentialLeaseWireRequest": object(),
            "HTTPException": HTTPException, "Response": self.responses, "json": json, "re": re,
            "base64": base64, "hashlib": hashlib, "hmac": hmac, "time": SimpleNamespace(
                monotonic=lambda: self.now, time_ns=lambda: 1_900_000_000_000_000_000),
            "db": self.db, "runtime": SimpleNamespace(get_control_plane_credential=self.runtime_read),
            "lease_profiles": credential_lease_profiles, "EXPECTED_DATA_PLANE_BINARY_DIGEST": BINARY,
            "SECRET_LEASE_TTL_SECONDS": 5, "OAUTH_REFRESH_SKEW_SECONDS": 60,
            "OAuthError": ValueError,
            "_OPERATOR_X_LEASE_DEADLINE_SCOPE_KEY": DEADLINE_KEY,
            "_CREDENTIAL_LEASE_ORIGINAL_SCOPE_KEY": "synthetic-original",
            "_CREDENTIAL_LEASE_REQUEST_MAX_BYTES": 65536, "DATA_PLANE_CREDENTIAL_LEASE_TOKEN": "synthetic-token",
            "_CREDENTIAL_LEASE_PLAINTEXT_MAX_BYTES": 4 * 1024 * 1024, "_CREDENTIAL_LEASE_RESPONSE_MAX_BYTES": 8 * 1024 * 1024,
            "_credential_lease_audit_lock": threading.Lock(), "_credential_lease_audit_last": {},
            "get_policy_snapshot": lambda: self.snapshot, "require_application_metadata": Mock(),
            "_assert_credential_lease_route_binding": Mock(return_value=self.credential_policy),
            "_active_route_by_id": Mock(return_value=self.route),
            "_assert_credential_lease_release_authorization": Mock(return_value=deepcopy(UNCONTROLLED)),
            "_credential_lease_request_binding_sha256": Mock(return_value=POLICY),
            "_verify_credential_lease_recipient_attestation": Mock(),
            "_claim_credential_lease_release_authorization": Mock(return_value=None),
            "_assert_credential_policy_binding": Mock(), "_assert_credential_injection_binding": Mock(),
            "_assert_route_credential_binding": Mock(), "_credential_lease_public_metadata": lambda value: deepcopy(value["metadata"]),
            "_credential_lease_metadata_sha256": digest, "_should_record_credential_lease_issuance": Mock(return_value="audit-key"),
            "_record_credential_lease_audit": self.audit, "encrypt_credential_lease_envelope": self.encrypt}
        selected_functions(APP_TREE, {"_canonical_json", "_decode_unpadded_base64url", "_bounded_credential_lease_request",
            "_credential_for_lease", "_credential_secret_for_lease", "data_plane_credential_leases"}, self.ns, "serverware/app.py")

    def _prepare(self, credential_id, expected_version, *, principal_id, route_id, policy_hash, deadline):
        self.events.append("prepare")
        assert (credential_id, expected_version, principal_id, route_id, policy_hash, deadline) == (
            ID, 7, self.payload.principal_id, self.payload.route_id, self.payload.policy_hash, 110.0)
        assert not self.locked
        return deepcopy(self.public)

    @contextmanager
    def _snapshot(self, identifier):
        assert identifier == ID and not self.locked
        self.locked = True
        self.events.append("snapshot-enter")
        try:
            yield deepcopy(self.credential)
        finally:
            self.events.append("snapshot-exit")
            self.locked = False

    def _binding(self, connection, **pins):
        assert self.locked and connection is self.connection
        assert pins == {"principal_id": self.payload.principal_id, "route_id": self.payload.route_id,
            "credential_id": ID, "core_credential": self.credential}
        self.events.append("binding")

    def _encrypt(self, **values):
        assert self.locked
        self.events.append("encrypt")
        return CRYPTO["encrypt_credential_lease_envelope"](**values)

    def _audit(self, outcome, _payload, **_fields):
        assert not self.locked
        self.events.append("audit-" + outcome)
        if outcome == "issued":
            self.now += self.audit_advance

    @contextmanager
    def installed(self):
        with ExitStack() as stack:
            stack.enter_context(patch.dict(sys.modules, {"serverware." + key: value for key, value in self.modules.items()}))
            for key, value in self.modules.items():
                stack.enter_context(patch.object(serverware, key, value, create=True))
            yield

    def call(self):
        with self.installed():
            return self.ns["data_plane_credential_leases"](self.request, self.payload)

    def decrypt(self, response):
        envelope = json.loads(response.body)
        aad = {key: value for key, value in envelope.items() if key not in {
            "serverEphemeralPublicKey", "aeadNonce", "ciphertext", "ciphertextSha256"}}
        ciphertext = decoded(envelope["ciphertext"])
        assert envelope["ciphertextSha256"] == "sha256:" + hashlib.sha256(ciphertext).hexdigest()
        shared = self.private.exchange(X25519PublicKey.from_public_bytes(decoded(envelope["serverEphemeralPublicKey"])))
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=self.nonce,
            info=b"serverware:credential-lease-envelope:v2\0" + hashlib.sha256(canonical(aad).encode()).digest()).derive(shared)
        return json.loads(AESGCM(key).decrypt(decoded(envelope["aeadNonce"]), ciphertext, canonical(aad).encode()))


class LeaseBoundaryTests(unittest.TestCase):
    def test_late_audit_expiry_refuses_x_dispatch_and_metadata_envelopes(self):
        for purpose in ("dispatchSecret", "generationMetadata"):
            with self.subTest(purpose=purpose):
                f = Fixture(purpose=purpose, audit_advance=10.0)
                with self.assertRaises(HTTPException) as raised:
                    f.call()
                self.assertEqual((raised.exception.status_code, raised.exception.detail),
                    (409, "X account lease deadline expired before output"))
                self.assertEqual(f.events[-3:], ["encrypt", "snapshot-exit", "audit-issued"])
                self.assertEqual(f.encrypt.call_count, 1)
                f.responses.assert_not_called()
                self.assertEqual(f.db.reserve_credential_lease_nonce.call_count, 1)
                self.assertNotIn(ACCESS, str(raised.exception))

    def test_actual_handler_forwards_authenticated_pins_and_keeps_access_token_only(self):
        f = Fixture()
        response = f.call()
        self.assertEqual(response.status_code, 200)
        f.prepare.assert_called_once_with(ID, 7, principal_id=f.payload.principal_id,
            route_id=f.payload.route_id, policy_hash=POLICY, deadline=110.0)
        self.assertEqual(f.events, ["prepare", "snapshot-enter", "binding", "encrypt", "snapshot-exit", "audit-issued"])
        f.runtime_read.assert_not_called()
        self.assertEqual(json.loads(f.decrypt(response)["credentials"][0]["secret"]), {"access_token": ACCESS})
        self.assertNotIn(REFRESH.encode(), response.body)
        self.assertEqual(f.request.scope[DEADLINE_KEY], (f.payload, 110.0))

    def test_x_metadata_lease_does_not_refresh_or_include_secret(self):
        f = Fixture(purpose="generationMetadata")
        response = f.call()
        f.prepare.assert_not_called()
        self.assertNotIn("secret", f.decrypt(response)["credentials"][0])
        self.assertEqual(f.binding.call_count, 1)

    def test_google_and_ordinary_legacy_paths_do_not_acquire_x_deadline_rule(self):
        for provider in ("google", "ordinary"):
            with self.subTest(provider=provider):
                f = Fixture(provider=provider, audit_advance=10.0)
                response = f.call()
                self.assertEqual(response.status_code, 200)
                f.prepare.assert_not_called()
                f.binding.assert_not_called()
                self.assertEqual(f.runtime_read.call_count, 1)
                secret = f.decrypt(response)["credentials"][0]["secret"]
                if provider == "google":
                    self.assertEqual(json.loads(secret), {"access_token": ACCESS})
                else:
                    self.assertEqual(secret, ACCESS)

    def test_marked_x_cannot_fall_through_or_reflect_prepare_error(self):
        f = Fixture()
        with f.installed():
            with self.assertRaises(HTTPException) as denied:
                f.ns["_credential_for_lease"](ID)
            self.assertEqual(denied.exception.status_code, 409)
            f.prepare.assert_not_called()
            f.prepare.side_effect = RuntimeError(REFRESH)
            with self.assertRaises(HTTPException) as failed:
                f.ns["_credential_for_lease"](ID, allow_x=True, expected_version=7,
                    principal_id=f.payload.principal_id, route_id=f.payload.route_id,
                    policy_hash=POLICY, deadline=110.0)
            self.assertEqual((failed.exception.status_code, failed.exception.detail),
                (503, "X account refresh is unavailable; inspect retained status"))
            self.assertIsNone(failed.exception.__cause__)
            self.assertNotIn(REFRESH, str(failed.exception))
            f.runtime_read.assert_not_called()

    def test_final_locked_binding_failure_precedes_encryption(self):
        f = Fixture()
        f.binding.side_effect = ValueError("synthetic changed account/configuration/rule")
        with self.assertRaises(HTTPException) as raised:
            f.call()
        self.assertEqual((raised.exception.status_code, raised.exception.detail), (409, "X account lease binding unavailable"))
        f.encrypt.assert_not_called()
        f.responses.assert_not_called()
        self.assertEqual(f.events[-1], "audit-rejected")

    def test_original_budget_is_stamped_before_body_and_bound_to_actual_payload(self):
        f = Fixture()
        async def consume(request, **_options):
            self.assertIs(request, f.request)
            f.now = 107.0
            return SimpleNamespace(root=f.payload)
        f.ns["_bounded_exact_data_plane_model"] = AsyncMock(side_effect=consume)
        f.request.scope.clear()
        actual = asyncio.run(f.ns["_bounded_credential_lease_request"](f.request))
        self.assertIs(actual, f.payload)
        self.assertEqual(f.request.scope[DEADLINE_KEY], (actual, 110.0))
        f.ns["_bounded_exact_data_plane_model"].assert_awaited_once()
        f.request.scope[DEADLINE_KEY] = (deepcopy(actual), 110.0)
        f.payload.purpose = "generationMetadata"
        with self.assertRaises(HTTPException) as raised:
            f.call()
        self.assertEqual(raised.exception.detail, "X account lease admission or deadline unavailable")
        f.encrypt.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
