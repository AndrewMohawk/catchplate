#!/usr/bin/env python3
"""Offline wire/encryption/auth controls, not durable-owner or AWS acceptance.

Uses the real codec, SigV4 signer and recipient encryption; owner/DB are inert
doubles. App token/nonce admission is extracted unchanged, without startup or
host configuration. No provider, credential files, sockets or database opens.
"""
from __future__ import annotations

import ast
import asyncio
import base64
from contextlib import contextmanager, ExitStack
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import sys
import time
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def offline(event, _args):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo", "subprocess.Popen"} or event.startswith("sqlite3."):
        raise AssertionError("ECR signing API checks forbid external effects")


sys.addaudithook(offline)
import catchplate
from fastapi import HTTPException, Request
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from catchplate import operator_ecr_signing_api as api
from catchplate.response_identity import validate_response_nonce

PUBLICATION = "12345678-1234-4234-8234-123456789abc"
CHILD = "87654321-1234-4234-8234-123456789abc"
H = "sha256:" + "1" * 64
TOKEN = "public-inert-data-plane-token"
NONCE = base64.urlsafe_b64encode(b"N" * 32).rstrip(b"=").decode()
SECRET = "A" * 40
ACCESS = "AKIA" + "S" * 16
BODY = b'{"registryId":"123456789012","repositoryName":"fixture"}'


@contextmanager
def modules(**values):
    with ExitStack() as stack:
        for name, value in values.items():
            stack.enter_context(patch.dict(sys.modules, {"catchplate." + name: value}))
            stack.enter_context(patch.object(catchplate, name, value, create=True))
        yield


def app_double():
    tree = ast.parse((ROOT / "catchplate/app.py").read_text())
    names = {"_require_data_plane_token", "_require_currentness_response_context", "_request_signature_inputs"}
    selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    assert len(selected) == len(names)
    module = ModuleType("catchplate.app")
    module.__dict__.update(HTTPException=HTTPException, hmac=hmac, validate_response_nonce=validate_response_nonce,
        DATA_PLANE_INSTANCE_ID="inert-test-gate", EXPECTED_DATA_PLANE_BINARY_DIGEST=H)
    unit = ast.Module(body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0), *selected], type_ignores=[])
    exec(compile(ast.fix_missing_locations(unit), str(ROOT / "catchplate/app.py"), "exec"), module.__dict__)

    async def blocking(slots, function, *args):
        async with slots:
            return function(*args)
    module._run_bounded_blocking = blocking
    return module


class Owner:
    def __init__(self):
        self.events = []
        self.in_transaction = False
        self.committed = False
        self.fail_commit = False
        self.conn = object()
        self.binding = {"principal_id": "agent:λ", "route_id": "operator.ecr", "credential_id": "aws-fixture",
            "credential_generation": 3, "policy_hash": H, "scope": {"region": "us-east-1"}}
        self.value = {"id": PUBLICATION, **self.binding, "expires_at_epoch_ms": time.time_ns() // 1_000_000 + 60000,
            "status": "active", "revision": 4}

    def require_client(self, principal, publication):
        assert principal == self.binding["principal_id"] and publication == PUBLICATION
        self.events.append("context")
        return deepcopy(self.value)

    def reserve(self, publication, **kwargs):
        assert publication == PUBLICATION
        self.events.append("reserve")
        self.pins = {key: kwargs[key] for key in ("principal_id", "route_id", "credential_id",
            "credential_generation", "policy_hash", "request_binding_sha256")}
        self.pins["publication_id"] = publication
        self.retained = SimpleNamespace(publication_id=publication, child_id=kwargs["child_id"],
            action=kwargs["action"], body=kwargs["body"], request_sha256=api._sha(kwargs["body"]),
            request_binding_sha256=kwargs["request_binding_sha256"], binding=deepcopy(self.binding),
            deadline=SimpleNamespace(unix_seconds=self.value["expires_at_epoch_ms"] // 1000,
                monotonic_ns=time.monotonic_ns() + 60_000_000_000))
        self.value["child"] = {"id": kwargs["child_id"], "action": kwargs["action"], "status": "reserved",
            "request_sha256": self.retained.request_sha256, "request_binding_sha256": kwargs["request_binding_sha256"],
            "response_sha256": None}
        return self.retained

    @contextmanager
    def signing_transaction(self, child, **pins):
        assert child == CHILD and pins == self.pins
        self.in_transaction = True
        self.events.append("begin")
        try:
            yield self.conn, self.retained
            self.events.append("commit")
            if self.fail_commit:
                raise RuntimeError("PRIVATE-COMMIT-CANARY")
            self.committed = True
            self.value["child"]["status"] = "possible_send"
        finally:
            self.in_transaction = False

    def finish(self, child, *, status, body, **pins):
        assert child == CHILD and pins == self.pins and self.committed
        self.events.append("finish")
        if status == 200:
            self.value["child"].update(status="acknowledged", response_sha256=api._sha(body))
        else:
            self.value["status"] = "uncertain"
        self.value["revision"] += 1
        return deepcopy(self.value)

    def fail(self, child, *, before_send, **pins):
        assert child == CHILD and pins == self.pins
        self.events.append(("fail", before_send))
        self.value["status"] = "uncertain" if self.committed or not before_send else "failed"
        return deepcopy(self.value)


class SigningApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = app_double()
        cls.config = SimpleNamespace(DATA_PLANE_CREDENTIAL_LEASE_TOKEN=TOKEN,
            MASTER_KEY_PATH=Path("/never-read"), MASTER_KEY_UNSEAL_COMMAND="", RELEASE_CHANNEL="test",
            ensure_data_dirs=lambda: (_ for _ in ()).throw(AssertionError("no host directories")))
        with modules(config=cls.config):
            from catchplate import crypto
        cls.crypto = crypto

    def setUp(self):
        self.owner = Owner()
        self.recipient = X25519PrivateKey.generate()
        raw = self.recipient.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.wire = {"apiVersion": api.RESERVE_VERSION, "publicationId": PUBLICATION, "childId": CHILD,
            "principalId": "agent:λ", "routeId": "operator.ecr", "credentialId": "aws-fixture",
            "expectedCredentialVersion": 3, "policyHash": H, "dataPlaneBinaryDigest": H,
            "action": "InitiateLayerUpload", "bodyBase64": base64.b64encode(BODY).decode(), "bodySha256": api._sha(BODY),
            "recipientPublicKey": base64.urlsafe_b64encode(raw).rstrip(b"=").decode(), "recipientKeyId": api._sha(raw),
            "recipientNonce": NONCE, "maxTtlSeconds": 5}
        db = SimpleNamespace(open_operator_ecr_credentials=self.open_credentials)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(modules(app=self.app, config=self.config, db=db, crypto=self.crypto,
            operator_ecr_publications=self.owner, operator_demo=SimpleNamespace(active=lambda: True)))

    def open_credentials(self, conn, identifier, *, expected_version):
        self.assertIs(conn, self.owner.conn)
        self.assertTrue(self.owner.in_transaction)
        self.assertEqual((identifier, expected_version), ("aws-fixture", 3))
        self.owner.events.append("open")
        return api.signing.Credentials(kind="long_term", access_key_id=ACCESS, secret_access_key=SECRET)

    def decrypt(self, envelope):
        fields = {"serverEphemeralPublicKey", "aeadNonce", "ciphertext", "ciphertextSha256"}
        aad = {key: value for key, value in envelope.items() if key not in fields}
        decode = lambda value: base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        ciphertext = decode(envelope["ciphertext"])
        self.assertEqual(api._sha(ciphertext), envelope["ciphertextSha256"])
        shared = self.recipient.exchange(X25519PublicKey.from_public_bytes(decode(envelope["serverEphemeralPublicKey"])))
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=decode(NONCE),
            info=b"catchplate:credential-lease-envelope:v2\0" + hashlib.sha256(api.canonical(aad)).digest()).derive(shared)
        return json.loads(AESGCM(key).decrypt(decode(envelope["aeadNonce"]), ciphertext, api.canonical(aad)))

    def finish_wire(self, outcome="response", status=200):
        value = {key: self.wire[key] for key in api._COMMON | {"childId", "expectedCredentialVersion"}}
        value.update(apiVersion=api.FINISH_VERSION, requestBindingSha256=api._sha(api.canonical(self.wire)), outcome=outcome)
        if outcome == "response":
            value.update(statusCode=status, responseBodyBase64=base64.b64encode(b'{"ok":true}').decode())
        return value

    def test_real_encrypted_signed_request_and_commit_precede_release(self):
        result = api.reserve(self.wire, NONCE)
        self.assertEqual(self.owner.events, ["reserve", "begin", "open", "commit"])
        self.assertTrue(self.owner.committed)
        aad_fields = {"apiVersion", "requestBindingSha256", "publicationId", "childId", "principalId", "routeId",
            "credentialId", "credentialVersion", "policyHash", "dataPlaneBinaryDigest", "recipientKeyId", "recipientNonce",
            "issuedAtEpochMs", "expiresAtEpochMs", "publicationExpiresAtEpochMs"}
        self.assertEqual(set(result), aad_fields | {"serverEphemeralPublicKey", "aeadNonce", "ciphertext", "ciphertextSha256"})
        self.assertEqual(result["requestBindingSha256"], api._sha(api.canonical(self.wire)))
        self.assertEqual(result["apiVersion"], api.ENVELOPE_VERSION)
        self.assertLessEqual(result["expiresAtEpochMs"] - result["issuedAtEpochMs"], 5000)
        plain = self.decrypt(result)
        self.assertEqual(set(plain), {"apiVersion", "method", "scheme", "authority", "path", "query", "bodySha256", "bodyLength", "headers"})
        self.assertEqual((plain["method"], plain["authority"], plain["path"], plain["query"]),
            ("POST", "api.ecr.us-east-1.amazonaws.com", "/", ""))
        self.assertEqual((plain["bodySha256"], plain["bodyLength"]), (api._sha(BODY), len(BODY)))
        self.assertIn("Credential=" + ACCESS, plain["headers"]["authorization"])
        self.assertEqual(plain["headers"]["accept"], "*/*")
        self.assertIn("SignedHeaders=accept;", plain["headers"]["authorization"])
        self.assertTrue(all(key == key.lower() for key in plain["headers"]))
        for text in (SECRET, ACCESS, BODY.decode()):
            self.assertNotIn(text, json.dumps(result))
        self.assertNotIn(SECRET, json.dumps(plain))
        corrupted = {**result, "routeId": "other"}
        with self.assertRaises(Exception):
            self.decrypt(corrupted)

    def test_bad_wire_never_reserves_or_opens(self):
        for change in ({"extra": True}, {"bodySha256": H}, {"bodyBase64": "YQ==\n"},
                {"recipientKeyId": H}, {"recipientPublicKey": "A" * 42 + "B"}, {"recipientNonce": "A" * 43},
                {"maxTtlSeconds": True}, {"maxTtlSeconds": 6}, {"expectedCredentialVersion": True},
                {"childId": PUBLICATION.upper()}, {"dataPlaneBinaryDigest": "sha256:" + "2" * 64},
                {"action": "GetAuthorizationToken"}):
            with self.subTest(change=next(iter(change))), self.assertRaises(Exception):
                api.reserve({**self.wire, **change}, NONCE)
            self.assertEqual(self.owner.events, [])

    def test_session_token_is_only_inside_recipient_envelope(self):
        token = "public-inert-session-token-canary"
        expiry = datetime.fromtimestamp(time.time() + 120, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        def session_credentials(conn, identifier, *, expected_version):
            self.open_credentials(conn, identifier, expected_version=expected_version)
            return api.signing.Credentials(kind="session", access_key_id="ASIA" + "T" * 16,
                secret_access_key=SECRET, session_token=token, expires_at=expiry)
        with patch.object(catchplate.db, "open_operator_ecr_credentials", side_effect=session_credentials):
            result = api.reserve(self.wire, NONCE)
        self.assertNotIn(token, json.dumps(result))
        plain = self.decrypt(result)
        self.assertEqual(plain["headers"]["x-amz-security-token"], token)
        self.assertIn("x-amz-security-token", plain["headers"]["authorization"])

    def test_retained_scope_or_request_change_never_opens_credentials(self):
        original = self.owner.reserve
        def altered(publication, **kwargs):
            result = original(publication, **kwargs)
            result.binding["route_id"] = "other"
            return result
        with patch.object(self.owner, "reserve", side_effect=altered):
            with self.assertRaises(api.SigningUnavailable):
                api.reserve(self.wire, NONCE)
        self.assertNotIn("open", self.owner.events)
        self.assertIn(("fail", True), self.owner.events)

    def test_encrypt_or_commit_failure_never_returns_envelope(self):
        with patch.object(self.crypto, "encrypt_credential_lease_envelope", side_effect=RuntimeError("PRIVATE-CANARY")):
            with self.assertRaises(api.SigningUnavailable) as caught:
                api.reserve(self.wire, NONCE)
        self.assertNotIn("CANARY", str(caught.exception))
        self.assertIn(("fail", True), self.owner.events)
        self.assertFalse(self.owner.committed)
        self.owner.events.clear()
        self.owner.fail_commit = True
        with self.assertRaises(api.SigningUnavailable):
            api.reserve(self.wire, NONCE)
        self.assertIn("commit", self.owner.events)
        self.assertIn(("fail", True), self.owner.events)

    def test_context_current_binding_and_finish_receipts(self):
        context = {key: self.wire[key] for key in api._COMMON}
        context["apiVersion"] = api.CONTEXT_VERSION
        value = api.context(context)
        self.assertEqual(set(value), api._COMMON | {"credentialVersion", "expiresAtEpochMs"})
        self.assertEqual(value["credentialVersion"], 3)
        api.reserve(self.wire, NONCE)
        result = api.finish(self.finish_wire())
        self.assertTrue(result["acknowledged"])
        self.assertTrue(result["responseReleaseAllowed"])
        self.assertEqual(result["responseBodySha256"], api._sha(b'{"ok":true}'))
        self.assertEqual(result["requestBodySha256"], api._sha(BODY))
        self.assertEqual(set(result), {"apiVersion", "publicationId", "childId", "requestBindingSha256", "principalId",
            "routeId", "credentialId", "credentialVersion", "policyHash", "requestBodySha256", "responseBodySha256",
            "status", "revision", "acknowledged", "responseReleaseAllowed"})

    def test_unknown_and_provider_error_never_acknowledged(self):
        for outcome, status in (("unknown", 200), ("response", 400)):
            with self.subTest(outcome=outcome):
                api.reserve(self.wire, NONCE)
                result = api.finish(self.finish_wire(outcome, status))
                self.assertFalse(result["acknowledged"])
                self.assertFalse(result["responseReleaseAllowed"])
                self.assertEqual(result["status"], "uncertain")
                if outcome == "unknown":
                    self.assertIsNone(result["responseBodySha256"])
        wire = self.finish_wire("unknown")
        wire["responseBodyBase64"] = ""
        with self.assertRaises(api.SigningUnavailable):
            api.finish(wire)

    def test_changed_authority_retains_valid_ack_but_terminal_parent(self):
        original = self.owner.finish
        for parent_status in ("failed", "published"):
            with self.subTest(parent_status=parent_status):
                api.reserve(self.wire, NONCE)
                def changed(child, **kwargs):
                    value = original(child, **kwargs)
                    value.update(status=parent_status, terminal_reason="authority_changed_after_send")
                    return value
                with patch.object(self.owner, "finish", side_effect=changed):
                    result = api.finish(self.finish_wire())
                self.assertTrue(result["acknowledged"])
                self.assertFalse(result["responseReleaseAllowed"])
                self.assertEqual(result["status"], parent_status)
                self.assertEqual(result["responseBodySha256"], api._sha(b'{"ok":true}'))

    def test_wrong_publication_is_bound_before_finish_mutation(self):
        api.reserve(self.wire, NONCE)
        wire = self.finish_wire()
        wire["publicationId"] = "11111111-1111-4111-8111-111111111111"
        with self.assertRaises(AssertionError):
            api.finish(wire)
        self.assertNotIn("finish", self.owner.events)

    def test_strict_parser_and_error_body_limit(self):
        raw = api.canonical(self.wire)
        for invalid in (b"[]", b"{}{}", b'{"apiVersion":1,"apiVersion":2}', b'{"x":1.0}', b'{"x":NaN}'):
            with self.subTest(invalid=invalid), self.assertRaises(HTTPException) as caught:
                api._execute(invalid, api.MAX_RESERVE_BYTES, api.reserve, NONCE)
            self.assertEqual(caught.exception.status_code, 422)
        api.reserve(self.wire, NONCE)
        wire = self.finish_wire(status=400)
        wire["responseBodyBase64"] = base64.b64encode(b"x" * (api.MAX_ERROR_BYTES + 1)).decode()
        with self.assertRaises(api.SigningUnavailable):
            api.finish(wire)
        self.assertNotIn("finish", self.owner.events)
        self.assertLess(len(raw), api.MAX_RESERVE_BYTES)

    def request(self, *, path=api.RESERVE_PATH, raw_path=None, token=TOKEN, nonce=NONCE, headers=(), body=None):
        reads = []
        async def receive():
            reads.append(True)
            return {"type": "http.request", "body": api.canonical(self.wire) if body is None else body, "more_body": False}
        values = [(b"content-type", b"application/json"), *headers]
        if token is not None:
            values.append((b"x-catchplate-data-plane-token", token.encode()))
        if nonce is not None:
            values.append((b"x-catchplate-response-nonce", nonce.encode()))
        return Request({"type": "http", "method": "POST", "scheme": "https", "path": path,
            "raw_path": path.encode() if raw_path is None else raw_path, "query_string": b"", "headers": values}, receive), reads

    def test_auth_nonce_exact_path_and_framing_refuse_before_body(self):
        cases = ({"token": None}, {"token": "wrong"}, {"nonce": None}, {"nonce": "bad"},
            {"raw_path": b"/api/data-plane/ecr-publications/%72eserve"},
            {"headers": [(b"x-catchplate-data-plane-token", TOKEN.encode())]},
            {"headers": [(b"content-length", str(api.MAX_RESERVE_BYTES + 1).encode())]},
            {"headers": [(b"content-length", b"2"), (b"transfer-encoding", b"chunked")]},
            {"headers": [(b"content-encoding", b"gzip")]})
        for options in cases:
            with self.subTest(options=options):
                request, reads = self.request(**options)
                with self.assertRaises(HTTPException):
                    asyncio.run(api.reserve_request(request))
                self.assertEqual(reads, [])
                self.assertEqual(self.owner.events, [])

    def test_router_response_and_fixed_refusal_do_not_leak(self):
        request, reads = self.request()
        response = asyncio.run(api.reserve_request(request))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(reads)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.decrypt(json.loads(response.body))
        request, _ = self.request(body=b'{"secret":"PRIVATE-CANARY"}')
        with self.assertRaises(HTTPException) as caught:
            asyncio.run(api.reserve_request(request))
        self.assertEqual(caught.exception.detail, "ECR signing request unavailable")
        self.assertNotIn("CANARY", str(caught.exception))
        self.assertEqual(api._WORKERS._value, 2)
        self.assertEqual(api._BODIES._value, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
