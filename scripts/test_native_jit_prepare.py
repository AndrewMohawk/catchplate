#!/usr/bin/env python3
"""Actual no-lifespan ASGI preparation, not native admission or DB acceptance.

Route/policy and credential-generation read sources are explicitly synthetic;
their real consumers, canonical review, durable claims, facade defaults,
compound projection, middleware and Ed25519 response signer are exercised.
Synthetic keys are provisioned in disposable files, never admitted NSM keys.
No startup, socket server, custody sealing, maintenance, writer or reserve runs.
"""
from __future__ import annotations

import asyncio
import argparse
import base64
import copy
from contextlib import ExitStack, nullcontext
from dataclasses import replace
import functools
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
PATH = "/api/data-plane/release-authorizations/native-jit-prepare"
TOKEN = "synthetic-preparation-service-token"
ACTOR = "spiffe://synthetic.invalid/decision-gate"
PRINCIPAL, ROUTE, CREDENTIAL = "agent:synthetic", "route:synthetic", "credential:synthetic"
POLICY = "sha256:" + "2" * 64
ATTEMPT = "sha256:" + "3" * 64
OTHER = "sha256:" + "4" * 64
NONCE = base64.urlsafe_b64encode(bytes([121]) * 32).rstrip(b"=")
_guard_active = False
_violations: list[str] = []
_fixture_output: Path | None = None


def audit_guard(event, arguments):
    external = event.startswith("sqlite3.") or event in {
        "socket.connect", "socket.bind", "socket.getaddrinfo", "subprocess.Popen",
        "os.system", "os.exec", "os.posix_spawn"}
    mutation = event in {"os.mkdir", "os.remove", "os.rmdir", "os.rename", "os.link",
        "os.symlink", "os.chmod", "os.chown", "os.truncate", "os.utime"}
    if event == "open":
        _path, mode, flags = arguments
        mutation = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
        mutation |= isinstance(mode, str) and any(c in mode for c in "wax+")
    if external or (_guard_active and mutation):
        _violations.append(event)
        raise AssertionError("preparation fixture forbids external or mutation effects")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("ascii")


def sha(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def approver_policy():
    return {"schema": "serverware.jitApproverPolicy/v1", "requiredRoles": ["approver"],
        "roleMatch": "any", "allowedApproverIds": ["oidc:alpha", "oidc:beta"],
        "allowAnyApproverId": False, "requireWebAuthn": True, "threshold": 2,
        "credentialPolicy": {"allowedCredentialRecordIds": [],
            "allowedAuthenticatorClasses": ["hardware", "yubikey"], "allowedAaguids": [],
            "requireAttestationTrusted": True, "requiredTrustBundleDigest": None,
            "minimumTrustBundleSequence": None, "rpId": "synthetic.invalid",
            "origins": ["https://synthetic.invalid"], "requireUserPresence": True,
            "requireUserVerification": True, "counterPolicy": "strict-or-zero",
            "maxAssertionAgeSeconds": 30}}


def key_material(constraint):
    return {"constraint": constraint, "principal": PRINCIPAL, "credential": CREDENTIAL,
        "credentialVersion": 7, "route": ROUTE, "operation": "test.write"}


def quota_claim():
    return {"counter_key": sha(canonical(key_material("fixed:test"))),
        "constraint_id": "fixed:test", "operation": "test.write", "window_kind": "fixed",
        "window_seconds": 60, "max_count": 10}


def durable_claim():
    return {"type": "slidingWindowLimit", "constraint_id": "sliding:test",
        "budget_key": sha(canonical(key_material("sliding:test"))), "principal_id": PRINCIPAL,
        "route_id": ROUTE, "credential_id": CREDENTIAL, "credential_version": 7,
        "policy_hash": POLICY, "operation": "test.write", "window_semantics": "sliding",
        "measure": "operationCount", "reservation_mode": "atomicReserveCommitRelease",
        "on_overflow": "deny", "unit_field": "operations", "units": 1,
        "window_seconds": 60, "max_units": 10}


def payload():
    operation = {"operation": "test.write", "label": "caf\u00e9"}
    original = {"v": 1, "principal": PRINCIPAL, "client_ip": "192.0.2.123",
        "route_id": ROUTE, "credential_ref": CREDENTIAL, "credential_version": "7",
        "policy_hash": POLICY, "operation": operation,
        "request": {"method": "POST", "scheme": "https", "authority": "synthetic.invalid",
            "path": "/resource", "query": [["label", "caf\u00e9"], ["token", "synthetic-private-query"]],
            "headers": {"host": "synthetic.invalid"}, "body_sha256": sha(b"synthetic body")}}
    claims = [durable_claim()]
    return {"apiVersion": "serverware.nativeReleaseAuthorizationPrepare/v2",
        "attemptId": ATTEMPT, "flowId": ATTEMPT, "principalId": PRINCIPAL, "routeId": ROUTE,
        "credentialRef": CREDENTIAL, "credentialVersion": 7, "policyHash": POLICY,
        "requestDigest": sha(canonical(original)),
        "operationDigest": sha(canonical({k: v for k, v in original.items() if k not in {"v", "client_ip"}})),
        "operationContext": operation, "canonicalRequest": original,
        "durablePolicy": {"actorId": ACTOR, "claimDigest": sha(canonical(claims)), "claims": claims}}


def raw_parent(value):
    """Independent full original marshaled facade roster, including defaults."""
    url = "https://synthetic.invalid/resource?label=caf%C3%A9&token=redacted"
    return {"attempt_id": ATTEMPT, "flow_id": ATTEMPT, "principal_id": PRINCIPAL,
        "route_id": ROUTE, "credential_id": CREDENTIAL, "credential_version": 7,
        "policy_hash": POLICY, "request_digest": value["requestDigest"],
        "operation_digest": value["operationDigest"], "operation_context": value["operationContext"],
        "shared_quotas": [quota_claim()], "require_jit_grant": True,
        "reservation_ttl_seconds": 15, "durable_policy_binding": value["durablePolicy"],
        "jit_approval_request": {"method": "POST", "url": url,
            "canonical_request": value["canonicalRequest"], "redacted_display": {
                "method": "POST", "url": url, "route_id": ROUTE, "principal": PRINCIPAL,
                "body_sha256": sha(b"synthetic body")}, "pending_ttl_seconds": 300,
            "grant_ttl_seconds": 30, "grant_max_uses": 1},
        "now_epoch_ms": None, "actor_id": ACTOR, "authority_policy_hash": POLICY,
        "authority_route_id": ROUTE,
        "required_approver_roles": {"$authorityType": "set", "items": ["approver"]},
        "allowed_approver_ids": {"$authorityType": "set", "items": ["oidc:alpha", "oidc:beta"]},
        "require_approver_webauthn": True, "approval_threshold": 2,
        "approver_credential_policy": approver_policy()["credentialPolicy"],
        "native_profile": True, "policy_aware_profile": False,
        "expected_approver_policy_sha256": sha(canonical(approver_policy()))}


class PreparationASGITests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.import_stack = ExitStack()
        cls.addClassCleanup(cls.import_stack.close)
        root = Path(cls.import_stack.enter_context(tempfile.TemporaryDirectory(prefix="native-jit-prepare-")))
        environment = {k: v for k, v in os.environ.items() if not k.startswith("SERVERWARE_")}
        environment.update(SERVERWARE_PROCESS_MODE="serverware-control-plane",
            SERVERWARE_RELEASE_CHANNEL="dev", SERVERWARE_DATA_DIR=str(root),
            SERVERWARE_WEBAUTHN_RP_ID="synthetic.invalid", SERVERWARE_WEBAUTHN_ORIGIN="https://synthetic.invalid")
        cls.import_stack.enter_context(patch.dict(os.environ, environment, clear=True))
        from serverware import app, attestation, policy_bundle, response_identity, native_release_jit_preparation
        from scripts import test_authority_release_private_request as oracle
        cls.app, cls.attestation, cls.policy, cls.identity = app, attestation, policy_bundle, response_identity
        cls.preparation, cls.oracle = native_release_jit_preparation, oracle

    async def asyncSetUp(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix="native-jit-keys-")))
        self.key = Ed25519PrivateKey.from_private_bytes(bytes([113]) * 32)
        public = self.key.public_key()
        self.key_id = sha(public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
        private = self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        pem = public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.files = {"private.pem": (private, 0o600), "public.pem": (pem, 0o644),
            "key-id": ((self.key_id + "\n").encode(), 0o644), "policy.pem": (pem, 0o644)}
        self.provision()
        for owner, name, value in (
            (self.identity, "RESPONSE_SIGNING_KEY_PATH", self.root / "private.pem"),
            (self.identity, "RESPONSE_SIGNING_PUBLIC_KEY_PATH", self.root / "public.pem"),
            (self.identity, "RESPONSE_SIGNING_PUBLIC_KEY_ID_PATH", self.root / "key-id"),
            (self.policy, "POLICY_SIGNING_PUBLIC_KEY_PATH", self.root / "policy.pem"),
            (self.app, "DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN", TOKEN),
            (self.app, "DATA_PLANE_INSTANCE_ID", ACTOR),
            (self.app, "RELEASE_AUTHORIZATION_RESERVATION_TTL_SECONDS", 15),
            (self.app.db, "WEBAUTHN_RP_ID", "synthetic.invalid"),
            (self.app.db, "WEBAUTHN_ORIGIN", "https://synthetic.invalid"),
            # Configuration-only same-DSN admission; no PG connection exists.
            (self.app.db, "METADATA_STORE_BACKEND", "postgres"),
            (self.app.db, "METADATA_STORE_POSTGRES_DSN", "postgresql:///synthetic_prepare?host=/nonexistent"),
            (self.app.db.grants, "GRANT_STORE_BACKEND", "postgres"),
            (self.app.db.grants, "GRANT_STORE_POSTGRES_DSN", "postgresql:///synthetic_prepare?host=/nonexistent"),
            (self.identity, "time", SimpleNamespace(time=lambda: 1_800_000_000.25))):
            self.stack.enter_context(patch.object(owner, name, value))
        self.stack.enter_context(patch.object(self.attestation.platform, "platform", return_value="synthetic-platform"))
        self.stack.enter_context(patch.object(self.app, "attestation_artifact_digests", return_value={
            "provenance_digest": None, "image_signatures_digest": None, "source_tree_digest": None}))
        for name, count in (("_SIGNED_RESPONSE_WORKER_SLOTS", 4), ("_SIGNED_RESPONSE_BUFFER_SLOTS", 16)):
            self.stack.enter_context(patch.object(self.app, name, asyncio.BoundedSemaphore(count)))
        key = {"scope": ["principal", "credential", "credentialVersion", "route", "operation"], "operationFields": []}
        constraints = ({"type": "rateLimit", "id": "fixed:test", "store": "shared", "phase": "request",
                "windowSeconds": 60, "max": 10, "key": key},
            {"type": "slidingWindowLimit", "id": "sliding:test", "store": "shared",
                "windowSemantics": "sliding", "measure": "operationCount",
                "reservationMode": "atomicReserveCommitRelease", "onOverflow": "deny",
                "windowSeconds": 60, "max": 10, "key": key})
        self.route = self.policy.RoutePolicy(ROUTE, (PRINCIPAL,), "synthetic.invalid", 443, "https",
            frozenset({"POST"}), ("/resource",), (re.compile(r"^/resource$"),), CREDENTIAL, "generic.http",
            {"request": {"allowedHeaders": [], "requiredHeaders": {}}}, constraints=constraints,
            jit={"required": True, "pendingTtlSeconds": 300, "ttlSeconds": 30, "maxUses": 1,
                "approvers": {"users": ["oidc:beta", "oidc:alpha"], "quorum": 2,
                    "authn": {"maxAssertionAgeSeconds": 30}}})
        self.snapshot = self.policy.PolicySnapshot({}, POLICY, {PRINCIPAL: self.policy.PrincipalPolicy(PRINCIPAL)},
            {CREDENTIAL: self.policy.CredentialPolicy(CREDENTIAL, injection={"type": "bearer", "header": "Authorization"})}, (self.route,))
        self.lookup = self.stack.enter_context(patch.object(self.app, "get_policy_snapshot", side_effect=lambda: self.snapshot))
        self.generation = self.stack.enter_context(patch.object(self.app.db, "credential_generation_snapshot",
            side_effect=lambda _identifier: nullcontext({"credential_version": 7})))
        self.forbidden = []
        def forbid(name, original):
            @functools.wraps(original)
            def fail(*_args, **_kwargs):
                self.forbidden.append(name)
                raise AssertionError("preparation contacted forbidden writer")
            return fail
        for owner, names in ((self.app, ("_release_authorization_maintenance",)),
            (self.app.db, ("connect", "reserve_release_authorization", "reserve_release_authorization_v2",
                "reconcile_release_authorizations", "drain_release_authorization_audit_outbox",
                "drain_metadata_audit_outbox", "record_audit_event", "record_audit_event_batch",
                "dispatch_policy_authority_operation")),
            (self.identity, ("ensure_data_dirs", "_load_response_key", "_publish_response_identity", "_retire_legacy_response_key")),
            (self.policy, ("_load_policy_private_key",))):
            for name in names:
                self.stack.enter_context(patch.object(owner, name, forbid(name, getattr(owner, name))))
        self.assertEqual(len(inspect.signature(self.app.db.reserve_release_authorization_v2).parameters), 27)
        self.manifest = self.attestation.runtime_manifest(read_only=True)
        self.assertEqual(self.manifest["policy_signing_key_id"], self.key_id)
        self.manifest_digest = sha(canonical({"apiVersion": "serverware.runtimeManifestDigest/v2", "manifest": self.manifest}))
        self.addCleanup(lambda: self.assertEqual(self.forbidden, []))

    def provision(self):
        for name, (body, mode) in self.files.items():
            path = self.root / name
            path.write_bytes(body)
            path.chmod(mode)

    async def request(self, value=None, *, body=None, token=TOKEN, nonce=NONCE, query=b"", method="POST",
                      extra_headers=(), length=True, messages=None):
        global _guard_active
        body = canonical(payload() if value is None else value) if body is None else body
        messages = [] if messages is None else messages
        headers = [(b"host", b"synthetic.invalid"), (b"content-type", b"application/json")]
        if length: headers.append((b"content-length", str(len(body)).encode()))
        if token is not None: headers.append((b"x-serverware-data-plane-token", token.encode()))
        if nonce is not None: headers.append((b"x-serverware-response-nonce", nonce))
        scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1",
            "scheme": "https", "method": method, "path": PATH, "raw_path": PATH.encode(), "root_path": "",
            "query_string": query, "server": ("synthetic.invalid", 443), "client": ("127.0.0.1", 30001),
            "headers": headers + list(extra_headers)}
        received, complete = False, asyncio.Event()
        self.body_reads = 0
        async def receive():
            nonlocal received
            if not received:
                received = True
                self.body_reads += 1
                return {"type": "http.request", "body": body, "more_body": False}
            await complete.wait()
            return {"type": "http.disconnect"}
        async def send(message):
            messages.append(dict(message))
            if message["type"] == "http.response.body" and not message.get("more_body", False): complete.set()
        before = len(_violations)
        _guard_active = True
        try:
            await asyncio.wait_for(self.app.app(scope, receive, send), 5)
        finally:
            _guard_active = False
            complete.set()
            self.assertEqual(_violations[before:], [])
            self.assertEqual(self.forbidden, [])
        return messages

    def response(self, messages, *, signed=True, nonce=NONCE, query=b"", method="POST"):
        starts = [row for row in messages if row["type"] == "http.response.start"]
        self.assertEqual(len(starts), 1)
        status = starts[0]["status"]
        raw_headers = starts[0]["headers"]
        headers = {k.decode().lower(): v.decode() for k, v in raw_headers}
        self.assertEqual(len(headers), len(raw_headers))
        body = b"".join(row.get("body", b"") for row in messages if row["type"] == "http.response.body")
        self.assertNotIn(TOKEN.encode(), body)
        self.assertEqual(headers["cache-control"], "no-store")
        if signed:
            raw = decode(headers["x-serverware-response-statement-b64"])
            statement = json.loads(raw)
            self.assertEqual(raw, canonical(statement))
            unsigned = sorted((k.lower(), v) for k, v in raw_headers if not k.lower().startswith(b"x-serverware-response-"))
            items = [{"name": k.decode("ascii"), "value_b64": b64(v)} for k, v in unsigned]
            self.assertEqual(statement, {"version": "serverware.responseSignature/v3", "issued_at_ms": 1_800_000_000_250,
                "request": {"method": method, "path": PATH, "query_sha256": sha(query)},
                "status_code": status, "body_sha256": sha(body), "response_headers_sha256": sha(canonical(items)),
                "response_header_count": len(items), "nonce": nonce.decode(), "response_signing_key_id": self.key_id,
                "context": {"runtime_manifest_digest": self.manifest_digest, "policy_bundle_digest": POLICY if status == 200 else None,
                    "provenance_digest": None, "image_signatures_digest": None, "source_tree_digest": None}})
            self.assertEqual(headers["x-serverware-response-key-id"], self.key_id)
            self.assertEqual(headers["x-serverware-response-body-sha256"], sha(body))
            self.assertEqual(headers["x-serverware-response-statement-sha256"], sha(raw))
            self.key.public_key().verify(decode(headers["x-serverware-response-signature"].removeprefix("ed25519:")), raw)
        else:
            self.assertFalse(any(k.startswith("x-serverware-response-") for k in headers))
        return status, json.loads(body), body

    async def test_exact_originals_actual_asgi_signature_and_no_effects(self):
        value = payload()
        status, result, body = self.response(await self.request(value))
        self.assertEqual(status, 200)
        envelope = self.oracle.expected_envelope(raw_parent(value))
        self.assertEqual(len(raw_parent(value)), 27)
        expected = {"apiVersion": "serverware.nativeReleaseJitPreparation/v1", "principalId": PRINCIPAL,
            "routeId": ROUTE, "policyHash": POLICY, "requestDigest": value["requestDigest"],
            "operationDigest": value["operationDigest"], "approverPolicy": approver_policy(),
            "approverPolicySha256": sha(canonical(approver_policy())), "runtimeInput": canonical(envelope).decode(),
            "parentRequest": canonical(self.oracle.native_request_oracle("release.reserve", envelope["arguments"])).decode(),
            "childRequest": canonical(self.oracle.native_request_oracle("jit.request", envelope["arguments"]["jit_approval_request"])).decode()}
        self.assertEqual(set(result), set(expected))
        self.assertEqual(body, canonical(expected))
        self.assertLessEqual(len(body), 512 * 1024)
        for name in ("runtimeInput", "parentRequest", "childRequest"):
            self.assertIs(type(result[name]), str)
            self.assertEqual(result[name].encode(), canonical(json.loads(result[name])))
        self.assertIn(b"\\u00e9", body)
        self.generation.assert_called_once_with(CREDENTIAL)
        self.assertEqual(self.response(await self.request(body=json.dumps(value, indent=2, ensure_ascii=False).encode()))[2], body)
        if _fixture_output is not None:
            # Explicit root-owned generation only, after actual signer and all
            # independent original/response assertions. No token/key/proof export.
            fixture = {"schema": "serverware.nativeReleaseJitPreparationFixture/v1", "request": value,
                "actorId": ACTOR, "responseBody": body.decode("ascii"), "route": {
                    "id": self.route.id, "principals": list(self.route.principals),
                    "host": self.route.host, "port": self.route.port, "scheme": self.route.scheme,
                    "methods": sorted(self.route.methods), "pathTemplates": list(self.route.path_templates),
                    "credentialRef": self.route.credential_ref, "adapterType": self.route.adapter_type,
                    "adapterConfig": self.route.adapter_config, "jit": self.route.jit,
                    "constraints": list(self.route.constraints)}}
            descriptor = os.open(_fixture_output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(canonical(fixture) + b"\n")

    async def test_authentication_before_bounded_body_or_credential_reads(self):
        for token in (None, "wrong"):
            with self.subTest(token_present=token is not None):
                self.assertEqual(self.response(await self.request(body=b"not JSON", token=token))[0], 401)
                self.assertEqual(self.body_reads, 0)
        with patch.object(self.app, "DATA_PLANE_INSTANCE_ID", ""):
            self.assertEqual(self.response(await self.request())[0], 503)
        self.generation.assert_not_called()
        self.lookup.assert_not_called()

    async def test_actual_topology_guard_before_any_metadata_read(self):
        for metadata, grants, metadata_dsn, grants_dsn in (
            ("sqlite", "postgres", "same", "same"), ("postgres", "sqlite", "same", "same"),
            ("postgres", "postgres", "left", "right"), ("postgres", "postgres", "", "")):
            with self.subTest(metadata=metadata, grants=grants, matching=metadata_dsn == grants_dsn), \
                    patch.object(self.app.db, "METADATA_STORE_BACKEND", metadata), \
                    patch.object(self.app.db, "METADATA_STORE_POSTGRES_DSN", metadata_dsn), \
                    patch.object(self.app.db.grants, "GRANT_STORE_BACKEND", grants), \
                    patch.object(self.app.db.grants, "GRANT_STORE_POSTGRES_DSN", grants_dsn):
                # Manifest truth follows actual selected config, including refusals.
                manifest = self.attestation.runtime_manifest(read_only=True)
                self.manifest_digest = sha(canonical({"apiVersion": "serverware.runtimeManifestDigest/v2", "manifest": manifest}))
                status, result, _ = self.response(await self.request())
                self.assertEqual((status, result), (503, {"detail": "native JIT metadata authority is unavailable"}))
                self.assertEqual(self.response(await self.request(token="wrong"))[0], 401)
                self.lookup.assert_not_called()
                self.generation.assert_not_called()

    async def test_exact_profile_jit_and_durable_gates(self):
        for version, status in (("serverware.nativeReleaseAuthorizationPrepare/v1", 409),
            ("serverware.policyAwareReleaseAuthorizationPrepare/v2", 422),
            ("serverware.releaseAuthorizationPrepare/v2", 422),
            ("serverware.nativeReleaseAuthorizationReserve/v2", 422)):
            value = payload(); value["apiVersion"] = version
            if version.endswith("/v1"): value.pop("durablePolicy")
            with self.subTest(version=version): self.assertEqual(self.response(await self.request(value))[0], status)
        self.snapshot = replace(self.snapshot, routes=(replace(self.route, jit={"required": False}),))
        self.assertEqual(self.response(await self.request())[0], 409)
        self.snapshot = replace(self.snapshot, routes=(replace(self.route, constraints=()),))
        self.assertEqual(self.response(await self.request())[0], 409)

    async def test_authoritative_identity_generation_and_policy_substitutions(self):
        for field, changed in (("principalId", "agent:other"), ("routeId", "route:other"),
            ("credentialRef", "credential:other"), ("credentialVersion", 8), ("policyHash", OTHER)):
            value = payload(); value[field] = changed
            with self.subTest(field=field): self.assertEqual(self.response(await self.request(value))[0], 409)
        for current in (None, {}, {"credential_version": True}, {"credential_version": 8}):
            with self.subTest(current=current), patch.object(self.app.db, "credential_generation_snapshot", side_effect=lambda _: nullcontext(current)):
                self.assertEqual(self.response(await self.request())[0], 409)

    async def test_real_durable_claim_actor_values_digest_and_closed_fields(self):
        value = payload(); value["durablePolicy"]["actorId"] = "different-authenticated-instance"
        self.assertEqual(self.response(await self.request(value))[0], 403)
        for field, changed in (("units", 2), ("max_units", 11), ("credential_version", 8), ("budget_key", OTHER)):
            value = payload(); value["durablePolicy"]["claims"][0][field] = changed
            value["durablePolicy"]["claimDigest"] = sha(canonical(value["durablePolicy"]["claims"]))
            with self.subTest(field=field): self.assertEqual(self.response(await self.request(value))[0], 409)
        for change in (lambda v: v.pop("durablePolicy"),
            lambda v: v["durablePolicy"].update(claimDigest=OTHER),
            lambda v: v["durablePolicy"].update(extra=True)):
            value = payload(); change(value)
            self.assertEqual(self.response(await self.request(value))[0], 422)

    async def test_canonical_target_header_shape_and_digest_refusals(self):
        for field, changed in (("method", "DELETE"), ("scheme", "http"), ("authority", "other.invalid"),
            ("path", "/other"), ("headers", {"host": "other.invalid"}),
            ("body_sha256", OTHER), ("extra", True)):
            value = payload(); value["canonicalRequest"]["request"][field] = changed
            with self.subTest(field=field): self.assertEqual(self.response(await self.request(value))[0], 409)
        for field in ("requestDigest", "operationDigest"):
            value = payload(); value[field] = OTHER
            self.assertEqual(self.response(await self.request(value))[0], 409)
        for changed in (True, 0, 3):
            value = payload(); value["canonicalRequest"]["v"] = changed
            self.assertEqual(self.response(await self.request(value))[0], 409)

    async def test_closed_parser_duplicate_nonfinite_and_original_byte_limits(self):
        for body in (canonical({**payload(), "unknown": True}), b'{"apiVersion":1,"apiVersion":2}',
            canonical(payload()).replace(b'"credentialVersion":7', b'"credentialVersion":NaN'), b"[]"):
            self.assertEqual(self.response(await self.request(body=body))[0], 422)
        self.assertEqual(self.app._RELEASE_AUTHORIZATION_REQUEST_MAX_BYTES, 512 * 1024)
        for length in (True, False):
            self.assertEqual(self.response(await self.request(body=b" " * (512 * 1024 + 1), length=length))[0], 413)
        self.assertEqual(self.preparation.MAX_RESPONSE_BYTES, 512 * 1024)
        _, _, body = self.response(await self.request())
        with patch.object(self.preparation, "MAX_RESPONSE_BYTES", len(body) - 1):
            self.assertEqual(self.response(await self.request())[0], 413)

    async def test_exact_nonce_method_and_query_binding(self):
        self.assertEqual(self.response(await self.request(nonce=None), signed=False)[0], 400)
        for kwargs in ({"nonce": b"bad"}, {"extra_headers": ((b"x-serverware-response-nonce", NONCE),)}):
            self.assertEqual(self.response(await self.request(**kwargs), signed=False)[0], 400)
        self.assertEqual(self.response(await self.request(query=b"unexpected=1"), query=b"unexpected=1")[0], 400)
        self.assertEqual(self.response(await self.request(method="GET"), method="GET")[0], 405)

    async def test_signature_cannot_be_reused_for_substituted_response_or_context(self):
        from cryptography.exceptions import InvalidSignature
        messages = await self.request()
        self.response(messages)
        headers = {name.lower(): value for name, value in next(
            row["headers"] for row in messages if row["type"] == "http.response.start")}
        raw = decode(headers[b"x-serverware-response-statement-b64"].decode())
        signature = decode(headers[b"x-serverware-response-signature"].decode().split(":", 1)[1])
        for field, changed in (("nonce", b64(bytes([122]) * 32)), ("status_code", 201),
            ("body_sha256", OTHER), ("response_headers_sha256", OTHER), ("response_header_count", 0),
            ("request", {"method": "POST", "path": PATH + "/other", "query_sha256": sha(b"")}),
            ("context", {"policy_bundle_digest": OTHER})):
            with self.subTest(field=field):
                statement = json.loads(raw); statement[field] = changed
                with self.assertRaises(InvalidSignature): self.key.public_key().verify(signature, canonical(statement))
        with self.assertRaises(InvalidSignature): self.key.public_key().verify(signature[:-1] + bytes([signature[-1] ^ 1]), raw)

    async def test_cold_or_corrupt_signer_refuses_before_any_response_without_writes(self):
        for filename in self.files:
            for bad in (None, b"invalid synthetic key material"):
                with self.subTest(filename=filename, missing=bad is None):
                    self.provision()
                    path = self.root / filename
                    if bad is None: path.unlink()
                    else: path.write_bytes(bad)
                    before = {p.name: (p.read_bytes(), p.stat().st_mode) for p in self.root.iterdir()}
                    messages = []
                    with self.assertRaises((self.identity.ResponseIdentityPublicationError, self.policy.PolicyBundleError)):
                        await self.request(messages=messages)
                    self.assertEqual(messages, [])
                    self.assertEqual({p.name: (p.read_bytes(), p.stat().st_mode) for p in self.root.iterdir()}, before)
        self.provision()

    async def test_mismatched_provisioned_key_and_publication_configuration_refuse(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        other = Ed25519PrivateKey.from_private_bytes(bytes([114]) * 32).public_key()
        for filename, changed in (("public.pem", other.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)),
            ("key-id", (OTHER + "\n").encode())):
            self.provision(); (self.root / filename).write_bytes(changed)
            with self.assertRaises(self.identity.ResponseIdentityPublicationError): await self.request()
        self.provision()
        with patch.object(self.identity, "RESPONSE_SIGNING_PUBLIC_KEY_ID_PATH", None):
            with self.assertRaises(self.identity.ResponseIdentityPublicationError): await self.request()

    async def test_shared_reserve_builder_preserves_legacy_jit_durable_and_profile_arguments(self):
        value = payload()
        model = self.app.DataPlaneReleaseAuthorizationPrepare.model_validate(value)
        original = raw_parent(value)
        approval = original["jit_approval_request"]
        review = ("POST", approval["url"], approval["canonical_request"], approval["redacted_display"])
        policy, approvers = self.app.db.release_approver_policy_for_route(self.route.jit, require_jit_grant=True)
        self.assertEqual(policy, approver_policy())
        self.assertEqual(approvers, {"required_approver_roles": {"approver"}, "allowed_approver_ids": {"oidc:alpha", "oidc:beta"},
            "require_approver_webauthn": True, "approval_threshold": 2, "approver_credential_policy": policy["credentialPolicy"]})
        for jit, durable, native, aware in ((False, None, False, False), (True, None, False, False),
            (True, value["durablePolicy"], True, False), (True, value["durablePolicy"], False, True)):
            with self.subTest(jit=jit, durable=durable is not None, native=native, aware=aware):
                digest = sha(canonical(policy)) if native or aware else None
                arguments = self.app._release_authorization_reserve_arguments(model, authenticated_actor_id=ACTOR,
                    route=self.route, shared_quotas=[quota_claim()], require_jit_grant=jit, approval_review=review,
                    durable_policy=durable, approver_arguments=approvers, native=native, policy_aware=aware,
                    expected_approver_policy_sha256=digest)
                expected = {k: copy.deepcopy(v) for k, v in original.items() if k not in {"now_epoch_ms", "durable_policy_binding"} | set(approvers)}
                expected.update(require_jit_grant=jit, jit_approval_request=copy.deepcopy(approval) if jit else None,
                    native_profile=native, policy_aware_profile=aware, expected_approver_policy_sha256=digest)
                if jit: expected.update(copy.deepcopy(approvers))
                if durable is not None: expected["durable_policy_binding"] = copy.deepcopy(durable)
                self.assertEqual(arguments, expected)
        route = replace(self.route, jit={**self.route.jit, "pendingTtlSeconds": 0, "ttlSeconds": 9999, "maxUses": 0})
        arguments = self.app._release_authorization_reserve_arguments(model, authenticated_actor_id=ACTOR,
            route=route, shared_quotas=[], require_jit_grant=True, approval_review=review,
            durable_policy=None, approver_arguments=approvers, native=False, policy_aware=False,
            expected_approver_policy_sha256=None)
        self.assertEqual({k: arguments["jit_approval_request"][k] for k in ("pending_ttl_seconds", "grant_ttl_seconds", "grant_max_uses")},
            {"pending_ttl_seconds": 1, "grant_ttl_seconds": 3600, "grant_max_uses": 1})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--fixture-output", type=Path)
    options, remaining = parser.parse_known_args()
    _fixture_output = options.fixture_output
    sys.dont_write_bytecode = True
    sys.addaudithook(audit_guard)
    unittest.main(argv=[sys.argv[0], *remaining], verbosity=2)
