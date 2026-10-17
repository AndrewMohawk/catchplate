#!/usr/bin/env python3
"""Actual bounded ASGI submission and signature, not native/SQL acceptance.

Reuses the preparation suite's explicit synthetic policy/generation readers and
real HTTP middleware/Ed25519 signer. Synthetic encrypted originals are genuine
local AES-GCM/Ed25519 fixtures; the final authority runtime is an explicit stub.
This suite neither substitutes a custody verdict nor runs the native verifier,
planner, SQL writer, provider, startup, or live deployment.
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import test_native_jit_prepare as preparation_fixture

PATH = "/api/data-plane/release-authorizations/native-jit-submit"
canonical = preparation_fixture.canonical
sha = preparation_fixture.sha


class SubmissionHTTPTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        preparation_fixture.PreparationASGITests.setUpClass.__func__(cls)
        from scripts import test_authority_native_jit_review_custody as cryptographic_fixture
        from catchplate import native_release_jit_submission
        cls.crypto = cryptographic_fixture
        cls.submission = native_release_jit_submission
        cls.pki = cryptographic_fixture.SyntheticNitro()

    async def asyncSetUp(self):
        await preparation_fixture.PreparationASGITests.asyncSetUp(self)
        self.stack.enter_context(patch.object(preparation_fixture, "PATH", PATH))
        self.stack.enter_context(patch.object(self.submission, "time", SimpleNamespace(
            monotonic_ns=time.monotonic_ns, time_ns=lambda: self.crypto.NOW + self.crypto.SECOND)))
        self.fixture = self.crypto.Fixture(self.pki)
        self.original = self.wire()
        self.expected_result = self.pending_result()
        # The only admitted effect boundary is explicitly stubbed. Every
        # legacy reserve, maintenance, audit, connection and provider remains
        # guarded by the original no-effects fixture.
        self.runtime = self.stack.enter_context(patch.object(self.app.db,
            "dispatch_policy_authority_operation", side_effect=lambda *_args, **_kwargs:
                copy.deepcopy(self.expected_result)))

    provision = preparation_fixture.PreparationASGITests.provision
    response = preparation_fixture.PreparationASGITests.response

    async def request(self, value=None, **kwargs):
        return await preparation_fixture.PreparationASGITests.request(
            self, self.original if value is None else value, **kwargs)

    def wire(self, raw=None):
        fixture = self.fixture
        if raw is not None:
            fixture = self.crypto.Fixture(self.pki)
            fixture.runtime = self.crypto.private.prepare(raw)
            fixture.parent = self.oracle.native_request_oracle("release.reserve", fixture.runtime["arguments"])
            fixture.child = self.oracle.native_request_oracle("jit.request", fixture.runtime["arguments"]["jit_approval_request"])
            fixture.scope.update(publicRequest=fixture.child, parentRequestSha256=sha(canonical(fixture.parent)))
            fixture.scope["documentExpiresAtEpochNs"] = self.crypto.NOW + min(
                raw["jit_approval_request"]["pending_ttl_seconds"], 300) * self.crypto.SECOND
            fixture.pair = self.crypto.material.seal_release_pair(fixture.scope,
                fixture.runtime["privateDocuments"], key_id=self.crypto.KEY_ID,
                kek=self.crypto.AESGCM(self.crypto.KEY), now_epoch_ns=self.crypto.NOW)
            fixture.statement.update(requestDigest=fixture.child["requestDigest"], operationId=fixture.child["operationId"],
                publicRequestSha256=sha(canonical(fixture.child)), pairSha256=sha(canonical(fixture.pair)),
                parentRequestSha256=sha(canonical(fixture.parent)), parentRequestDigest=fixture.parent["requestDigest"],
                parentOperationId=fixture.parent["operationId"], documentExpiresAtEpochNs=fixture.scope["documentExpiresAtEpochNs"])
            fixture.proof = fixture.sign_proof()
        return {"schema": "catchplate.nativeJitPendingSubmission/v1",
            "runtimeOriginal": canonical(fixture.runtime).decode("ascii"),
            "parentOriginal": canonical(fixture.parent).decode("ascii"),
            "childOriginal": canonical(fixture.child).decode("ascii"),
            "pairOriginal": canonical(fixture.pair).decode("ascii"),
            "evidenceOriginal": canonical(fixture.proof).decode("ascii")}

    def pending_result(self):
        raw = preparation_fixture.raw_parent(preparation_fixture.payload())
        identity = {"schema": "catchplate.policyAuthorityDeterministicIdentity/v1", "operation": "jit.request",
            "requestDigest": self.fixture.child["requestDigest"], "purpose": "jit-approval-request"}
        digits = list(hashlib.sha256(canonical(identity)).hexdigest()[:32])
        digits[12] = "5"; digits[16] = format((int(digits[16], 16) & 3) | 8, "x")
        compact = "".join(digits)
        approval_id = "-".join((compact[:8], compact[8:12], compact[12:16], compact[16:20], compact[20:]))
        binding = {name: raw[name] for name in ("attempt_id", "flow_id", "principal_id", "route_id", "credential_id",
            "credential_version", "policy_hash", "request_digest", "operation_digest", "operation_context", "require_jit_grant")}
        binding.update(api_version="catchplate.nativeReleaseAuthorizationBinding/v2",
            durable_policy=raw["durable_policy_binding"], approver_policy=preparation_fixture.approver_policy(),
            shared_quotas=raw["shared_quotas"])
        return {"authorized": False, "state": "denied", "reason": "jit_grant_unavailable",
            "attempt_id": preparation_fixture.ATTEMPT, "binding_digest": sha(canonical(binding)),
            "binding_api_version": "catchplate.nativeReleaseAuthorizationBinding/v2", "idempotent_replay": False,
            "grant_id": None, "approval_request_id": approval_id, "approval_status": "pending", "approval_created": True,
            "approval_expires_at": (datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(
                microseconds=self.fixture.scope["documentExpiresAtEpochNs"] // 1000)).isoformat(),
            "reservation_expires_at_epoch_ms": None, "dispatch_started_at_epoch_ms": None,
            "dispatch_expires_at_epoch_ms": None, "completion_outcome": None, "retry_after_seconds": 3,
            "quotas": [], "release_authorization_store_backend": "postgres", "release_authorization_store_ha": True,
            "durable_policy": {"state": "denied", "attempt_id": preparation_fixture.ATTEMPT,
                "claim_digest": raw["durable_policy_binding"]["claimDigest"], "actor_id": preparation_fixture.ACTOR,
                "reservation_id": None, "reservation_deadline_at_epoch_ms": None, "dispatch_deadline_at_epoch_ms": None,
                "response_evidence_digest": None, "failure_reason": None, "response_body_sha256": None, "uncertainty": None}}

    async def test_actual_asgi_signed_pending_response_and_one_exact_dispatch(self):
        started = time.monotonic_ns()
        status, response, body = self.response(await self.request())
        self.assertEqual(status, 200)
        self.assertEqual((response["apiVersion"], response["authorized"], response["state"], response["reason"]),
            ("catchplate.nativeReleaseAuthorizationResponse/v2", False, "denied", "jit_grant_unavailable"))
        self.assertEqual((response["approvalRequestId"], response["approvalStatus"], response["approvalCreated"]),
            (self.expected_result["approval_request_id"], "pending", True))
        self.assertEqual(response["approvalExpiresAt"], self.expected_result["approval_expires_at"])
        self.assertEqual(response["durablePolicy"]["state"], "denied")
        self.assertIsNone(response["durablePolicy"]["reservationId"])
        self.assertEqual(response["quotas"], [])
        self.runtime.assert_called_once()
        args, kwargs = self.runtime.call_args
        self.assertEqual(args, ("release.reserve", self.original))
        self.assertEqual(set(kwargs), {"deadline_ns"})
        self.assertGreater(kwargs["deadline_ns"], started)
        self.assertLessEqual(kwargs["deadline_ns"], time.monotonic_ns() + 29 * self.crypto.SECOND)
        for secret in (b"synthetic-private-query", b"runtimeOriginal", b"privateDocuments", b"pairOriginal"):
            self.assertNotIn(secret, body)

    async def test_token_authentication_precedes_body_policy_and_generation(self):
        for token in (None, "incorrect"):
            self.assertEqual(self.response(await self.request(body=b"private invalid body", token=token))[0], 401)
            self.assertEqual(self.body_reads, 0)
        with patch.object(self.app, "DATA_PLANE_INSTANCE_ID", ""):
            self.assertEqual(self.response(await self.request())[0], 503)
            self.assertEqual(self.body_reads, 0)
        self.lookup.assert_not_called(); self.generation.assert_not_called(); self.runtime.assert_not_called()

    async def test_nonce_query_and_method_precede_body_and_state(self):
        for nonce in (None, b"invalid"):
            self.assertEqual(self.response(await self.request(nonce=nonce), signed=False)[0], 400)
            self.assertEqual(self.body_reads, 0)
        self.assertEqual(self.response(await self.request(extra_headers=((b"x-catchplate-response-nonce", preparation_fixture.NONCE),)), signed=False)[0], 400)
        self.assertEqual(self.response(await self.request(query=b"unexpected=1"), query=b"unexpected=1")[0], 400)
        self.assertEqual(self.body_reads, 0)
        self.assertEqual(self.response(await self.request(method="GET"), method="GET")[0], 405)
        self.assertEqual(self.body_reads, 0)
        self.lookup.assert_not_called(); self.generation.assert_not_called(); self.runtime.assert_not_called()

    async def test_actual_native_postgres_topology_precedes_body(self):
        for metadata, grant, left, right in (("sqlite", "postgres", "same", "same"),
            ("postgres", "sqlite", "same", "same"), ("postgres", "postgres", "left", "right"),
            ("postgres", "postgres", "", "")):
            with self.subTest(metadata=metadata, grant=grant), \
                    patch.object(self.app.db, "METADATA_STORE_BACKEND", metadata), \
                    patch.object(self.app.db.grants, "GRANT_STORE_BACKEND", grant), \
                    patch.object(self.app.db, "METADATA_STORE_POSTGRES_DSN", left), \
                    patch.object(self.app.db.grants, "GRANT_STORE_POSTGRES_DSN", right):
                manifest = self.attestation.runtime_manifest(read_only=True)
                self.manifest_digest = sha(canonical({"apiVersion": "catchplate.runtimeManifestDigest/v2", "manifest": manifest}))
                self.assertEqual(self.response(await self.request())[0], 503)
                self.assertEqual(self.body_reads, 0)
        self.lookup.assert_not_called(); self.generation.assert_not_called(); self.runtime.assert_not_called()

    async def test_closed_json_originals_and_redacted_errors(self):
        values = [{**self.original, "extra": "synthetic-private-query"},
            {**self.original, "schema": "other"}, {**self.original, "runtimeOriginal": {}},
            {**self.original, "runtimeOriginal": self.original["runtimeOriginal"] + " "},
            {**self.original, "runtimeOriginal": "é"}, []]
        bodies = [canonical(value) for value in values] + [b'{"schema":1,"schema":2}', b'{"schema":NaN}', b"not JSON"]
        for body in bodies:
            status, result, raw = self.response(await self.request(body=body))
            self.assertEqual((status, result), (422, {"detail": self.submission.ERROR}))
            self.assertNotIn(b"synthetic-private-query", raw)
        self.lookup.assert_not_called(); self.generation.assert_not_called(); self.runtime.assert_not_called()

    async def test_wire_limit_and_content_length_before_allocation(self):
        self.assertEqual(self.submission.MAX_REQUEST_BYTES, 4 * 1024 * 1024)
        oversized = b" " * (self.submission.MAX_REQUEST_BYTES + 1)
        self.assertEqual(self.response(await self.request(body=oversized))[0], 413)
        self.assertEqual(self.body_reads, 0)
        self.assertEqual(self.response(await self.request(body=oversized, length=False))[0], 413)
        self.assertEqual(self.body_reads, 1)
        for length in (b"-1", b"invalid", b"0001"):
            self.assertEqual(self.response(await self.request(length=False,
                extra_headers=((b"content-length", length),)))[0], 400)
            self.assertEqual(self.body_reads, 0)
        self.assertEqual(self.response(await self.request(extra_headers=((b"content-length", b"1"),)))[0], 400)
        self.assertEqual(self.body_reads, 0)
        self.lookup.assert_not_called(); self.runtime.assert_not_called()

    async def test_current_policy_route_and_approver_configuration_are_rejoined(self):
        from dataclasses import replace
        original = self.snapshot
        for changed in (replace(original, hash=preparation_fixture.OTHER),
            replace(original, routes=()), replace(original, routes=(replace(self.route, jit={"required": False}),)),
            replace(original, routes=(replace(self.route, constraints=()),)),
            replace(original, routes=(replace(self.route, jit={**self.route.jit, "pendingTtlSeconds": 299}),))):
            self.snapshot = changed
            self.assertEqual(self.response(await self.request())[0], 409)
        self.snapshot = original
        self.runtime.assert_not_called()

    async def test_current_credential_generation_is_rejoined(self):
        from contextlib import nullcontext
        for value in (None, {}, {"credential_version": True}, {"credential_version": 8}):
            with patch.object(self.app.db, "credential_generation_snapshot", return_value=nullcontext(value)):
                self.assertEqual(self.response(await self.request())[0], 409)
        self.runtime.assert_not_called()

    async def test_authenticated_actor_cannot_be_supplied_by_runtime_original(self):
        raw = preparation_fixture.raw_parent(preparation_fixture.payload())
        raw["actor_id"] = "spiffe://synthetic.invalid/other"
        self.assertEqual(self.response(await self.request(self.wire(raw)))[0], 409)
        raw["durable_policy_binding"]["actorId"] = raw["actor_id"]
        self.assertEqual(self.response(await self.request(self.wire(raw)))[0], 403)
        self.runtime.assert_not_called()

    async def test_durable_claim_values_are_not_self_authorizing(self):
        raw = preparation_fixture.raw_parent(preparation_fixture.payload())
        raw["durable_policy_binding"]["claims"][0]["units"] = 2
        raw["durable_policy_binding"]["claimDigest"] = sha(canonical(raw["durable_policy_binding"]["claims"]))
        self.assertEqual(self.response(await self.request(self.wire(raw)))[0], 409)
        self.runtime.assert_not_called()

    async def test_actual_facade_defaults_and_shared_quotas_are_rederived(self):
        for field, changed in (("reservation_ttl_seconds", 16), ("shared_quotas", []), ("now_epoch_ms", 123)):
            raw = preparation_fixture.raw_parent(preparation_fixture.payload()); raw[field] = changed
            self.assertEqual(self.response(await self.request(self.wire(raw)))[0], 409)
        self.runtime.assert_not_called()

    async def test_private_canonical_request_and_three_literal_originals_rejoin(self):
        raw = preparation_fixture.raw_parent(preparation_fixture.payload())
        raw["jit_approval_request"]["canonical_request"]["request"]["path"] = "/other-private-path"
        self.assertEqual(self.response(await self.request(self.wire(raw)))[0], 409)
        for name in ("parentOriginal", "childOriginal", "pairOriginal", "evidenceOriginal"):
            value = {**self.original, name: "{}"}
            status, _result, body = self.response(await self.request(value))
            self.assertEqual(status, 409)
            self.assertNotIn(b"other-private-path", body)
        self.runtime.assert_not_called()

    async def test_runtime_failure_is_sanitized_not_retried_or_fallen_back(self):
        self.runtime.side_effect = RuntimeError("synthetic-private-query: uncertain commit")
        status, result, _ = self.response(await self.request())
        self.assertEqual((status, result), (503, {"detail": self.submission.ERROR}))
        self.runtime.assert_called_once()

    async def test_authorized_reserved_dispatched_or_wrong_approval_result_refuses(self):
        baseline = copy.deepcopy(self.expected_result)
        for field, changed in (("authorized", True), ("state", "reserved"), ("grant_id", "grant"),
            ("approval_request_id", "other"), ("approval_status", "approved"),
            ("reservation_expires_at_epoch_ms", 1), ("dispatch_started_at_epoch_ms", 1),
            ("dispatch_expires_at_epoch_ms", 1), ("completion_outcome", "success"),
            ("quotas", [{"count": 1}]), ("release_authorization_store_backend", "sqlite")):
            self.expected_result = {**baseline, field: changed}
            self.assertEqual(self.response(await self.request())[0], 503)

    async def test_binding_expiry_and_durable_result_must_match_original(self):
        baseline = copy.deepcopy(self.expected_result)
        for field, changed in (("binding_api_version", "wrong"), ("binding_digest", preparation_fixture.OTHER),
            ("approval_expires_at", "2099-01-01T00:00:00+00:00"), ("retry_after_seconds", 4)):
            self.expected_result = {**baseline, field: changed}
            self.assertEqual(self.response(await self.request())[0], 503)
        for field, changed in (("state", "reserved"), ("actor_id", "different"),
            ("claim_digest", preparation_fixture.OTHER), ("reservation_id", "reservation"),
            ("reservation_deadline_at_epoch_ms", 1), ("dispatch_deadline_at_epoch_ms", 1),
            ("response_evidence_digest", preparation_fixture.OTHER), ("response_body_sha256", preparation_fixture.OTHER),
            ("failure_reason", "unexpected"), ("uncertainty", True)):
            self.expected_result = copy.deepcopy(baseline)
            self.expected_result["durable_policy"][field] = changed
            self.assertEqual(self.response(await self.request())[0], 503)

    async def test_original_deadline_clipping_and_expired_seal_refuse(self):
        start = time.monotonic_ns()
        earlier = start + self.crypto.SECOND
        self.assertEqual(self.submission.clipped_deadline(self.original, deadline_ns=earlier), earlier)
        with patch.object(self.submission, "time", SimpleNamespace(monotonic_ns=time.monotonic_ns,
                time_ns=lambda: self.crypto.NOW + 30 * self.crypto.SECOND)):
            self.assertEqual(self.response(await self.request())[0], 409)
        self.lookup.assert_not_called(); self.runtime.assert_not_called()

    async def test_body_timeout_refuses_before_authority_reads(self):
        with patch.object(self.submission, "BODY_TIMEOUT_SECONDS", 0):
            self.assertEqual(self.response(await self.request())[0], 408)
        self.lookup.assert_not_called(); self.generation.assert_not_called(); self.runtime.assert_not_called()

    async def test_expired_http_owner_cannot_dispatch(self):
        with patch.object(self.submission, "REQUEST_TIMEOUT_NS", 0):
            self.assertEqual(self.response(await self.request())[0], 422)
        self.assertEqual(self.body_reads, 0)
        self.lookup.assert_not_called(); self.generation.assert_not_called(); self.runtime.assert_not_called()


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    sys.addaudithook(preparation_fixture.audit_guard)
    unittest.main(verbosity=2)
