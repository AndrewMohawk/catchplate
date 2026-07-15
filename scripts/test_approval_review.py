#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def exercise_python_release_lifecycle_contracts(runtime, canonical_json) -> None:
    now_ms = int(time.time() * 1000)
    attempt_id = "attempt:exact-lifecycle"
    binding_digest = "sha256:" + "a" * 64
    grant_id = "grant:exact-lifecycle"
    approval_request_id = "approval:exact-lifecycle"
    reserved = {
        "authorized": True,
        "state": "reserved",
        "reason": "reserved",
        "attempt_id": attempt_id,
        "binding_digest": binding_digest,
        "idempotent_replay": False,
        "grant_id": grant_id,
        "approval_request_id": approval_request_id,
        "approval_status": None,
        "approval_expires_at": None,
        "approval_created": None,
        "reservation_expires_at_epoch_ms": now_ms + 60_000,
        "dispatch_started_at_epoch_ms": None,
        "dispatch_expires_at_epoch_ms": None,
        "completion_outcome": None,
        "retry_after_seconds": 0,
        "quotas": [],
        "store": {"backend": "postgres", "ha": True},
    }
    runtime.validate_reserve_release_authorization_response(
        reserved,
        attempt_id=attempt_id,
        require_jit_grant=True,
    )

    def expect_rejected(call, label: str) -> None:
        try:
            call()
        except runtime.ReleaseAuthorizationClientError:
            return
        raise AssertionError(f"Python lifecycle validator accepted {label}")

    expect_rejected(
        lambda: runtime.validate_reserve_release_authorization_response(
            {**reserved, "binding_digest": "sha256:" + "A" * 64},
            attempt_id=attempt_id,
            require_jit_grant=True,
        ),
        "an uppercase SHA-256 binding",
    )
    expect_rejected(
        lambda: runtime.validate_reserve_release_authorization_response(
            {**reserved, "grant_id": "grant:other"},
            attempt_id=attempt_id,
            require_jit_grant=False,
        ),
        "a non-JIT reserve carrying grant identity",
    )

    dispatching = {
        **reserved,
        "state": "dispatching",
        "reason": "dispatching",
        "idempotent_replay": True,
        "dispatch_started_at_epoch_ms": now_ms,
        "dispatch_expires_at_epoch_ms": now_ms + 30_000,
    }
    runtime.validate_dispatch_release_authorization_response(
        dispatching,
        attempt_id=attempt_id,
        binding_digest=binding_digest,
        grant_id=grant_id,
        approval_request_id=approval_request_id,
        now_epoch_ms=now_ms,
    )
    for label, changes in (
        ("an expired dispatch", {"dispatch_expires_at_epoch_ms": now_ms}),
        ("an unauthorized dispatch", {"authorized": False}),
        (
            "a completed dispatch",
            {"state": "committed", "reason": "committed", "completion_outcome": "forwarded"},
        ),
        ("a dispatch with the wrong grant", {"grant_id": "grant:other"}),
    ):
        expect_rejected(
            lambda changes=changes: runtime.validate_dispatch_release_authorization_response(
                {**dispatching, **changes},
                attempt_id=attempt_id,
                binding_digest=binding_digest,
                grant_id=grant_id,
                approval_request_id=approval_request_id,
                now_epoch_ms=now_ms,
            ),
            label,
        )

    committed = {
        **dispatching,
        "state": "committed",
        "reason": "forwarded",
        "idempotent_replay": False,
        "completion_outcome": "forwarded",
    }
    runtime.validate_complete_release_authorization_response(
        committed,
        attempt_id=attempt_id,
        binding_digest=binding_digest,
        outcome="forwarded",
        grant_id=grant_id,
        approval_request_id=approval_request_id,
    )
    expect_rejected(
        lambda: runtime.validate_complete_release_authorization_response(
            {**committed, "authorized": False},
            attempt_id=attempt_id,
            binding_digest=binding_digest,
            outcome="forwarded",
            grant_id=grant_id,
            approval_request_id=approval_request_id,
        ),
        "an authorized/state completion contradiction",
    )
    replayed_forwarded = {
        **committed,
        "reason": "committed",
        "idempotent_replay": True,
    }
    runtime.validate_complete_release_authorization_response(
        replayed_forwarded,
        attempt_id=attempt_id,
        binding_digest=binding_digest,
        outcome="unknown",
        grant_id=grant_id,
        approval_request_id=approval_request_id,
    )
    expect_rejected(
        lambda: runtime.validate_complete_release_authorization_response(
            {**replayed_forwarded, "idempotent_replay": False, "reason": "forwarded"},
            attempt_id=attempt_id,
            binding_digest=binding_digest,
            outcome="unknown",
            grant_id=grant_id,
            approval_request_id=approval_request_id,
        ),
        "a non-replay forwarded result for unknown completion",
    )

    with patch.dict(
        os.environ,
        {
            "SERVERWARE_RELEASE_CHANNEL": "prod",
            "SERVERWARE_CONTROL_PLANE_RELEASE_AUTHORIZATION_BASE_URL": (
                "http://control-plane.test/api/data-plane/release-authorizations"
            ),
        },
        clear=False,
    ):
        expect_rejected(
            runtime._release_authorization_base_url,
            "a plaintext production release-authority URL",
        )

    canonical_request = {"request": {"method": "POST"}, "operation": {}}
    request_digest = "sha256:" + hashlib.sha256(
        canonical_json(canonical_request).encode("utf-8")
    ).hexdigest()
    with (
        patch.dict(
            os.environ,
            {"SERVERWARE_RELEASE_CHANNEL": "prod"},
            clear=False,
        ),
        patch.object(runtime, "atomic_release_authorization_enabled", return_value=True),
        patch.object(runtime, "_release_authorization_base_url", return_value=""),
        patch.object(runtime.db, "reserve_release_authorization") as reserve_db,
        patch.object(runtime.db, "dispatch_release_authorization") as dispatch_db,
        patch.object(runtime.db, "complete_release_authorization") as complete_db,
    ):
        fallback_calls = (
            lambda: runtime.reserve_release_authorization(
                attempt_id=attempt_id,
                flow_id=attempt_id,
                principal_id="agent:test",
                route_id="route:test",
                credential_ref="credential:test",
                credential_version=1,
                policy_hash="sha256:" + "b" * 64,
                request_digest=request_digest,
                operation_digest=None,
                operation_context={},
                canonical_request=canonical_request,
                shared_quotas=[],
                require_jit_grant=True,
            ),
            lambda: runtime.dispatch_release_authorization(
                attempt_id=attempt_id,
                binding_digest=binding_digest,
                grant_id=grant_id,
                approval_request_id=approval_request_id,
            ),
            lambda: runtime.complete_release_authorization(
                attempt_id=attempt_id,
                binding_digest=binding_digest,
                outcome="forwarded",
                grant_id=grant_id,
                approval_request_id=approval_request_id,
            ),
        )
        for action, fallback_call in zip(("reserve", "dispatch", "complete"), fallback_calls):
            expect_rejected(
                fallback_call,
                f"production direct database fallback for {action}",
            )
        reserve_db.assert_not_called()
        dispatch_db.assert_not_called()
        complete_db.assert_not_called()

    with patch.dict(
        os.environ,
        {"SERVERWARE_RELEASE_CHANNEL": "development"},
        clear=False,
    ):
        runtime._require_development_release_authorization_fallback()


def exercise_python_atomic_reserve_contract(runtime, canonical_json) -> None:
    canonical_request = {
        "v": 1,
        "principal": "agent:demo",
        "client_ip": "127.0.0.1",
        "route_id": "demo.npm.publish.jit",
        "credential_ref": "cred-demo-bearer",
        "credential_version": "2",
        "policy_hash": "sha256:" + "a" * 64,
        "request": {
            "method": "PUT",
            "scheme": "https",
            "authority": "registry.npmjs.org",
            "path": "/@scope%2fpkg",
            "query": [],
            "headers": {"host": "registry.npmjs.org"},
            "body_sha256": "sha256:" + "b" * 64,
        },
        "operation": {
            "operation": "npm.publish",
            "packageName": "@scope/pkg",
            "packageVersion": "1.2.3",
        },
    }
    request_digest = "sha256:" + hashlib.sha256(
        canonical_json(canonical_request).encode("utf-8")
    ).hexdigest()
    approval_expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    response = {
        "apiVersion": "serverware.releaseAuthorization/v1",
        "ok": True,
        "authorized": False,
        "state": "denied",
        "reason": "jit_grant_unavailable",
        "attemptId": "attempt:python-proxy",
        "bindingDigest": "sha256:" + "c" * 64,
        "idempotentReplay": False,
        "grantId": None,
        "approvalRequestId": "approval:python-proxy",
        "approvalStatus": "pending",
        "approvalExpiresAt": approval_expires_at,
        "approvalCreated": True,
        "reservationExpiresAtEpochMs": None,
        "dispatchStartedAtEpochMs": None,
        "dispatchExpiresAtEpochMs": None,
        "completionOutcome": None,
        "retryAfterSeconds": 3,
        "quotas": [],
        "store": {"backend": "postgres", "ha": True},
    }
    captured: list[dict] = []

    def request_bytes(request, **_kwargs):
        captured.append(json.loads(request.data.decode("utf-8")))
        return SimpleNamespace(body=json.dumps(response).encode("utf-8"))

    with (
        patch.object(runtime, "atomic_release_authorization_enabled", return_value=True),
        patch.object(
            runtime,
            "_release_authorization_base_url",
            return_value="https://control-plane.test/api/data-plane/release-authorizations",
        ),
        patch.object(runtime, "_release_authorization_token", return_value="test-token"),
        patch.object(runtime, "_release_authorization_ssl_context", return_value=None),
        patch.object(runtime, "request_bytes", side_effect=request_bytes),
    ):
        result = runtime.reserve_release_authorization(
            attempt_id="attempt:python-proxy",
            flow_id="attempt:python-proxy",
            principal_id="agent:demo",
            route_id="demo.npm.publish.jit",
            credential_ref="cred-demo-bearer",
            credential_version=2,
            policy_hash=canonical_request["policy_hash"],
            request_digest=request_digest,
            operation_digest="sha256:" + "d" * 64,
            operation_context=dict(canonical_request["operation"]),
            canonical_request=canonical_request,
            shared_quotas=[],
            require_jit_grant=True,
        )
    if len(captured) != 1:
        raise AssertionError(f"Python reserve did not make exactly one request: {captured}")
    payload = captured[0]
    if payload.get("canonicalRequest") != canonical_request:
        raise AssertionError(f"Python reserve changed the canonical request: {payload}")
    if payload.get("requestDigest") != request_digest:
        raise AssertionError(f"Python reserve changed the canonical digest: {payload}")
    if payload.get("operationContext") != canonical_request["operation"]:
        raise AssertionError(f"Python reserve changed operation context: {payload}")
    if any(field in payload for field in ("redactedDisplay", "method", "url")):
        raise AssertionError(f"Python reserve supplied backend-derived display fields: {payload}")
    if (
        result.get("approval_request_id") != "approval:python-proxy"
        or result.get("approval_status") != "pending"
        or result.get("approval_expires_at") != approval_expires_at
        or result.get("approval_created") is not True
        or result.get("retry_after_seconds") != 3
    ):
        raise AssertionError(f"Python reserve dropped approval retry context: {result}")

    incomplete = dict(response)
    incomplete.pop("approvalCreated")
    try:
        runtime._normalized_release_authorization_response(
            incomplete,
            attempt_id="attempt:python-proxy",
        )
    except runtime.ReleaseAuthorizationClientError:
        pass
    else:
        raise AssertionError("Python reserve accepted an incomplete JIT approval response")

    reused = dict(response)
    reused["approvalCreated"] = False
    normalized_reuse = runtime._normalized_release_authorization_response(
        reused,
        attempt_id="attempt:python-proxy",
    )
    if normalized_reuse.get("approval_created") is not False:
        raise AssertionError(
            f"Python reserve lost idempotent approval reuse state: {normalized_reuse}"
        )

    oversized = {"value": "x" * (65 * 1024)}
    oversized_digest = "sha256:" + hashlib.sha256(
        canonical_json(oversized).encode("utf-8")
    ).hexdigest()
    with (
        patch.object(runtime, "atomic_release_authorization_enabled", return_value=True),
        patch.object(runtime, "_release_authorization_base_url", return_value="https://control-plane.test"),
        patch.object(runtime, "_release_authorization_http_post") as post,
    ):
        try:
            runtime.reserve_release_authorization(
                attempt_id="attempt:oversized",
                flow_id="attempt:oversized",
                principal_id="agent:demo",
                route_id="demo.npm.publish.jit",
                credential_ref="cred-demo-bearer",
                credential_version=2,
                policy_hash="sha256:" + "a" * 64,
                request_digest=oversized_digest,
                operation_digest="sha256:" + "d" * 64,
                operation_context={},
                canonical_request=oversized,
                shared_quotas=[],
                require_jit_grant=True,
            )
        except runtime.ReleaseAuthorizationClientError:
            pass
        else:
            raise AssertionError("Python reserve accepted an oversized canonical request")
        post.assert_not_called()


def make_approval(db, snapshot, *, digest_suffix: str, redacted_display: dict, canonical_request: dict):
    return db.ensure_jit_approval_request(
        route_id="demo.npm.publish.jit",
        method="PUT",
        url="https://registry.npmjs.org/@scope%2fpkg",
        principal_id="agent:demo",
        credential_id="cred-demo-bearer",
        credential_version=2,
        policy_hash=snapshot.hash,
        request_digest="sha256:" + digest_suffix * 64,
        operation_digest="sha256:" + digest_suffix.upper() * 64,
        canonical_request=canonical_request,
        redacted_display=redacted_display,
        pending_ttl_seconds=300,
        grant_ttl_seconds=30,
        grant_max_uses=1,
    )


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["SERVERWARE_DATA_DIR"] = tmp
        os.environ["SERVERWARE_METADATA_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_AUDIT_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_GRANT_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_KEY_RELEASE_REQUIRED"] = "0"
        os.environ["SERVERWARE_PUBLIC_URL"] = "http://localhost:3000"
        os.environ["SERVERWARE_DEV_AUTHENTICATOR"] = "1"
        os.environ.pop("SERVERWARE_METADATA_STORE_POSTGRES_DSN", None)
        os.environ.pop("SERVERWARE_AUDIT_STORE_POSTGRES_DSN", None)
        os.environ.pop("SERVERWARE_GRANT_STORE_POSTGRES_DSN", None)

        from serverware import app as app_module
        from serverware import db, policy_bundle, runtime, webauthn
        from serverware.auth import AdminIdentity

        exercise_python_release_lifecycle_contracts(
            runtime,
            policy_bundle.canonical_json,
        )
        exercise_python_atomic_reserve_contract(runtime, policy_bundle.canonical_json)
        db.init_db()
        webauthn.create_dev_credential("user:demo", "Approval review test authenticator")
        snapshot = policy_bundle.write_policy_bundle(policy_bundle.demo_policy_bundle("cred-demo-bearer"))
        db.upsert_route_with_id(
            "demo.npm.publish.jit",
            {
                "name": "Demo NPM publish JIT",
                "enabled": True,
                "match_host": "registry.npmjs.org",
                "match_path_prefix": "/",
                "credential_id": None,
                "injection": {"type": "bearer"},
                "policies": [{"type": "approval", "scope": "request_digest"}],
            },
        )
        previous = make_approval(
            db,
            snapshot,
            digest_suffix="c",
            redacted_display={"package": "@scope/pkg", "version": "1.2.2"},
            canonical_request={"principal": "agent:demo", "operation": {"packageName": "@scope/pkg", "packageVersion": "1.2.2"}},
        )
        db.deny_request(previous["id"], note="prior package failed review", actor_id="user:demo")

        current = make_approval(
            db,
            snapshot,
            digest_suffix="d",
            redacted_display={
                "package": "@scope/pkg",
                "version": "1.2.3",
                "secretToken": "top-secret-value",
            },
            canonical_request={
                "principal": "agent:demo",
                "client_ip": "10.20.0.8",
                "proxy_authorization_hash": "sha256:" + "9" * 64,
                "request": {
                    "method": "PUT",
                    "body_sha256": "sha256:" + "4" * 64,
                    "headers": {"authorization": "Bearer top-secret-value"},
                },
                "operation": {
                    "type": "npm.publish",
                    "packageName": "@scope/pkg",
                    "packageVersion": "1.2.3",
                    "tarballIntegrity": "sha512-demo",
                    "authorization": "Bearer top-secret-value",
                },
            },
        )
        review = app_module.approval_review(
            current["id"],
            identity=AdminIdentity("user:demo", frozenset({"approver"}), "admin-token-header"),
        )
        if review["principal_id"] != "agent:demo" or review["route_id"] != "demo.npm.publish.jit":
            raise AssertionError(f"approval review missing principal/route context: {review}")
        if review["source_identity"].get("client_ip") != "10.20.0.8":
            raise AssertionError(f"approval review missing source identity: {review}")
        if review["body_hash"] != "sha256:" + "4" * 64:
            raise AssertionError(f"approval review missing body hash: {review}")
        if review["normalized_operation_fields"].get("packageName") != "@scope/pkg":
            raise AssertionError(f"approval review missing operation fields: {review}")
        if review["normalized_operation_fields"].get("authorization") != "[redacted]":
            raise AssertionError(f"approval review did not redact sensitive operation fields: {review}")
        if review["redacted_payload_summary"].get("secretToken") != "[redacted]":
            raise AssertionError(f"approval review did not redact sensitive display fields: {review}")
        if "prior package failed review" not in json.dumps(review["previous_similar_approvals"], sort_keys=True):
            raise AssertionError(f"approval review missing previous similar approvals: {review}")
        if review["retry_semantics"].get("agent_receives_secret_or_token") is not False:
            raise AssertionError(f"approval review retry semantics are unsafe: {review}")
        for expected_flag in ("credential_version_bound", "policy_hash_current", "webauthn_required", "one_use_grant"):
            if expected_flag not in review["risk_flags"]:
                raise AssertionError(f"approval review missing risk flag {expected_flag}: {review}")
        if "top-secret-value" in json.dumps(review, sort_keys=True):
            raise AssertionError(f"approval review leaked a secret value: {review}")
        receipt = review.get("review_receipt") or {}
        if not receipt.get("id") or not receipt.get("expires_at"):
            raise AssertionError(f"approval review did not issue a bounded receipt: {review}")
        if not str(review.get("review_digest") or "").startswith("sha256:"):
            raise AssertionError(f"approval review did not bind its document digest: {review}")
        active_receipt = db.get_active_approval_review_receipt(
            receipt["id"],
            approval_request_id=current["id"],
            reviewer_id="user:demo",
        )
        if active_receipt is None or active_receipt["review_digest"] != review["review_digest"]:
            raise AssertionError("server-side approval review receipt binding is missing")
        if db.get_active_approval_review_receipt(
            receipt["id"],
            approval_request_id=current["id"],
            reviewer_id="user:other",
        ) is not None:
            raise AssertionError("approval review receipt was transferable to another approver")
        options = app_module.approval_webauthn_options(
            current["id"],
            app_module.ApprovalWebAuthnOptionsRequest(
                reviewReceiptId=receipt["id"]
            ),
            AdminIdentity("user:demo", frozenset({"approver"}), "admin-token-header"),
        )
        challenge_payload = options["serverware"]["payload"]
        if (
            challenge_payload.get("review_receipt_id") != receipt["id"]
            or challenge_payload.get("review_digest") != review["review_digest"]
            or challenge_payload.get("type") != "serverware.approval.reviewed"
        ):
            raise AssertionError(
                f"WebAuthn challenge did not bind the review receipt: {challenge_payload}"
            )

        receipt_test = make_approval(
            db,
            snapshot,
            digest_suffix="e",
            redacted_display={"package": "@scope/pkg", "version": "1.2.4"},
            canonical_request={
                "principal": "agent:demo",
                "operation": {
                    "packageName": "@scope/pkg",
                    "packageVersion": "1.2.4",
                },
            },
        )
        receipt_test_review = app_module.approval_review(
            receipt_test["id"],
            identity=AdminIdentity(
                "user:demo", frozenset({"approver"}), "admin-token-header"
            ),
        )
        receipt_test_token = receipt_test_review["review_receipt"]
        approved = db.approve_request(
            receipt_test["id"],
            actor_id="user:demo",
            authn={"method": "test-reviewed-approval"},
            review_receipt_id=receipt_test_token["id"],
            review_digest=receipt_test_review["review_digest"],
            require_review_receipt=True,
        )
        if approved is None or approved["status"] != "approved":
            raise AssertionError("review receipt was not consumed with approval")
        if db.get_active_approval_review_receipt(
            receipt_test_token["id"],
            approval_request_id=receipt_test["id"],
            reviewer_id="user:demo",
        ) is not None:
            raise AssertionError("approval review receipt remained reusable")

        changed_bundle = policy_bundle.demo_policy_bundle("cred-demo-bearer")
        changed_bundle["metadata"]["sequence"] = 2
        policy_bundle.write_policy_bundle(changed_bundle)
        stale_review = app_module.approval_review(
            current["id"],
            identity=AdminIdentity("user:demo", frozenset({"approver"}), "admin-token-header"),
        )
        if "policy_hash_not_current" not in stale_review["risk_flags"]:
            raise AssertionError(f"stale approval review did not flag policy change: {stale_review}")
        try:
            app_module.approve(
                current["id"],
                ttl_seconds=30,
                payload=app_module.ApprovalApprove(
                    reviewReceiptId=receipt["id"]
                ),
                identity=AdminIdentity("user:demo", frozenset({"approver"}), "admin-token-header"),
            )
        except app_module.HTTPException as exc:
            if exc.status_code != 409 or "policy changed" not in str(exc.detail):
                raise AssertionError(f"stale approval failed with the wrong error: {exc.detail}") from exc
        else:
            raise AssertionError("stale approval was accepted after the active policy changed")

    print(json.dumps({"approval_review": "pass", "ok": True}, sort_keys=True))


if __name__ == "__main__":
    main()
