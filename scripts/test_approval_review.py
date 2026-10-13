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
    window_start_ms = now_ms - 5_000
    quota_claim = {
        "counter_key": "sha256:" + "1" * 64,
        "constraint_id": "quota:exact-lifecycle",
        "operation": "npm.publish",
        "window_kind": "fixed",
        "window_seconds": 120,
        "max_count": 2,
    }
    reserved_quota = {
        "counter_key": quota_claim["counter_key"],
        "constraint_id": quota_claim["constraint_id"],
        "operation": quota_claim["operation"],
        "window_kind": "fixed",
        "window_seconds": 120,
        "calendar_window": None,
        "window_start_epoch_ms": window_start_ms,
        "window_end_epoch_ms": window_start_ms + 120_000,
        "max": 2,
        "count": 1,
        "remaining": 1,
        "reservation_state": "reserved",
    }
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
        "quotas": [reserved_quota],
        "store": {"backend": "postgres", "ha": True},
    }
    runtime.validate_reserve_release_authorization_response(
        reserved,
        attempt_id=attempt_id,
        require_jit_grant=True,
        expected_binding_digest=binding_digest,
        expected_shared_quotas=[quota_claim],
        now_epoch_ms=now_ms,
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
            expected_binding_digest=binding_digest,
            expected_shared_quotas=[quota_claim],
            now_epoch_ms=now_ms,
        ),
        "an uppercase SHA-256 binding",
    )
    expect_rejected(
        lambda: runtime.validate_reserve_release_authorization_response(
            {**reserved, "grant_id": "grant:other"},
            attempt_id=attempt_id,
            require_jit_grant=False,
            expected_binding_digest=binding_digest,
            expected_shared_quotas=[quota_claim],
            now_epoch_ms=now_ms,
        ),
        "a non-JIT reserve carrying grant identity",
    )
    expect_rejected(
        lambda: runtime.validate_reserve_release_authorization_response(
            reserved,
            attempt_id=attempt_id,
            require_jit_grant=True,
            expected_binding_digest="sha256:" + "b" * 64,
            expected_shared_quotas=[quota_claim],
            now_epoch_ms=now_ms,
        ),
        "a substituted reserve binding digest",
    )
    expect_rejected(
        lambda: runtime.validate_reserve_release_authorization_response(
            reserved,
            attempt_id=attempt_id,
            require_jit_grant=True,
            expected_binding_digest=binding_digest,
            expected_shared_quotas=[{**quota_claim, "max_count": 1}],
            now_epoch_ms=now_ms,
        ),
        "a substituted reserve quota claim",
    )
    expect_rejected(
        lambda: runtime.validate_reserve_release_authorization_response(
            {
                **reserved,
                "reservation_expires_at_epoch_ms": reserved_quota[
                    "window_end_epoch_ms"
                ]
                + 1,
            },
            attempt_id=attempt_id,
            require_jit_grant=True,
            expected_binding_digest=binding_digest,
            expected_shared_quotas=[quota_claim],
            now_epoch_ms=now_ms,
        ),
        "a fixed reservation expiry beyond its quota boundary",
    )
    expect_rejected(
        lambda: runtime._normalized_release_authorization_quota(
            {**reserved_quota, "count": 3, "remaining": 0},
            camel_case=False,
        ),
        "a quota count above its maximum",
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
        previous_lifecycle=reserved,
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
                previous_lifecycle=reserved,
                now_epoch_ms=now_ms,
            ),
            label,
        )

    substituted_dispatch_quota = {
        **dispatching,
        "quotas": [{**reserved_quota, "count": 2, "remaining": 0}],
    }
    expect_rejected(
        lambda: runtime.validate_dispatch_release_authorization_response(
            substituted_dispatch_quota,
            attempt_id=attempt_id,
            binding_digest=binding_digest,
            grant_id=grant_id,
            approval_request_id=approval_request_id,
            previous_lifecycle=reserved,
            now_epoch_ms=now_ms,
        ),
        "a substituted dispatch quota snapshot",
    )
    expect_rejected(
        lambda: runtime.validate_dispatch_release_authorization_response(
            {
                **dispatching,
                "reservation_expires_at_epoch_ms": now_ms + 59_999,
            },
            attempt_id=attempt_id,
            binding_digest=binding_digest,
            grant_id=grant_id,
            approval_request_id=approval_request_id,
            previous_lifecycle=reserved,
            now_epoch_ms=now_ms,
        ),
        "a substituted dispatch reservation expiry",
    )
    boundary_quota = {
        **reserved_quota,
        "window_start_epoch_ms": now_ms - 120_000,
        "window_end_epoch_ms": now_ms,
    }
    boundary_reserve = {**reserved, "quotas": [boundary_quota]}
    expect_rejected(
        lambda: runtime.validate_dispatch_release_authorization_response(
            {**dispatching, "quotas": [boundary_quota]},
            attempt_id=attempt_id,
            binding_digest=binding_digest,
            grant_id=grant_id,
            approval_request_id=approval_request_id,
            previous_lifecycle=boundary_reserve,
            now_epoch_ms=now_ms,
        ),
        "a dispatch at the quota window end",
    )

    committed = {
        **dispatching,
        "state": "committed",
        "reason": "forwarded",
        "idempotent_replay": False,
        "completion_outcome": "forwarded",
        "quotas": [{**reserved_quota, "reservation_state": "committed"}],
    }
    runtime.validate_complete_release_authorization_response(
        committed,
        attempt_id=attempt_id,
        binding_digest=binding_digest,
        outcome="forwarded",
        grant_id=grant_id,
        approval_request_id=approval_request_id,
        previous_lifecycle=dispatching,
    )
    expect_rejected(
        lambda: runtime.validate_complete_release_authorization_response(
            {**committed, "authorized": False},
            attempt_id=attempt_id,
            binding_digest=binding_digest,
            outcome="forwarded",
            grant_id=grant_id,
            approval_request_id=approval_request_id,
            previous_lifecycle=dispatching,
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
        previous_lifecycle=dispatching,
    )
    expect_rejected(
        lambda: runtime.validate_complete_release_authorization_response(
            {**replayed_forwarded, "idempotent_replay": False, "reason": "forwarded"},
            attempt_id=attempt_id,
            binding_digest=binding_digest,
            outcome="unknown",
            grant_id=grant_id,
            approval_request_id=approval_request_id,
            previous_lifecycle=dispatching,
        ),
        "a non-replay forwarded result for unknown completion",
    )
    expect_rejected(
        lambda: runtime.validate_complete_release_authorization_response(
            {
                **committed,
                "quotas": [{**reserved_quota, "reservation_state": "committed"}],
                "reservation_expires_at_epoch_ms": now_ms + 59_999,
            },
            attempt_id=attempt_id,
            binding_digest=binding_digest,
            outcome="forwarded",
            grant_id=grant_id,
            approval_request_id=approval_request_id,
            previous_lifecycle=dispatching,
        ),
        "a substituted completion reservation expiry",
    )
    expect_rejected(
        lambda: runtime.validate_complete_release_authorization_response(
            {
                **committed,
                "quotas": [{**reserved_quota, "reservation_state": "reserved"}],
            },
            attempt_id=attempt_id,
            binding_digest=binding_digest,
            outcome="forwarded",
            grant_id=grant_id,
            approval_request_id=approval_request_id,
            previous_lifecycle=dispatching,
        ),
        "an invalid completion quota reservation state",
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

    canonical_request = {
        "v": 1,
        "principal": "agent:test",
        "client_ip": None,
        "route_id": "route:test",
        "credential_ref": "credential:test",
        "credential_version": "1",
        "policy_hash": "sha256:" + "b" * 64,
        "request": {
            "method": "POST",
            "scheme": "https",
            "authority": "upstream.invalid",
            "path": "/resource",
            "query": [],
            "headers": {"host": "upstream.invalid"},
            "body_sha256": "sha256:" + hashlib.sha256(b"").hexdigest(),
        },
        "operation": {"operation": "test.write"},
    }
    request_digest = "sha256:" + hashlib.sha256(
        canonical_json(canonical_request).encode("utf-8")
    ).hexdigest()
    operation_digest = "sha256:" + hashlib.sha256(
        canonical_json(
            {
                key: canonical_request[key]
                for key in (
                    "principal",
                    "route_id",
                    "credential_ref",
                    "credential_version",
                    "policy_hash",
                    "request",
                    "operation",
                )
            }
        ).encode("utf-8")
    ).hexdigest()
    expected_reserve = runtime.expected_release_authorization_identity(
        attempt_id=attempt_id,
        flow_id=attempt_id,
        principal_id="agent:test",
        route_id="route:test",
        credential_ref="credential:test",
        credential_version=1,
        policy_hash="sha256:" + "b" * 64,
        request_digest=request_digest,
        operation_digest=operation_digest,
        operation_context=dict(canonical_request["operation"]),
        shared_quotas=[],
        require_jit_grant=True,
    )
    reserve_guard = runtime.ReleaseAuthorizationGuard(expected_reserve)
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
            lambda: runtime.reserve_expected_release_authorization(
                guard=reserve_guard,
                operation_context=dict(canonical_request["operation"]),
                canonical_request=canonical_request,
                shared_quotas=[],
            ),
            lambda: runtime.dispatch_release_authorization(
                attempt_id=attempt_id,
                binding_digest=binding_digest,
                grant_id=grant_id,
                approval_request_id=approval_request_id,
                previous_lifecycle=reserved,
            ),
            lambda: runtime.complete_release_authorization(
                attempt_id=attempt_id,
                binding_digest=binding_digest,
                outcome="forwarded",
                grant_id=grant_id,
                approval_request_id=approval_request_id,
                previous_lifecycle=dispatching,
            ),
        )
        for action, fallback_call in zip(("reserve", "dispatch", "complete"), fallback_calls):
            expect_rejected(
                fallback_call,
                f"production direct database fallback for {action}",
            )
        expect_rejected(
            lambda: runtime.complete_release_authorization(
                attempt_id=attempt_id,
                binding_digest=binding_digest,
                outcome="not_forwarded",
                grant_id=grant_id,
                approval_request_id=approval_request_id,
                previous_lifecycle=reserved,
            ),
            "untyped not_forwarded completion without a retained guard",
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
        "v": 2,
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
            "discard_headers": ["npm-session"],
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
    expected_reserve = runtime.expected_release_authorization_identity(
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
        shared_quotas=[],
        require_jit_grant=True,
    )
    expected_binding_digest = expected_reserve.binding_digest
    reserve_guard = runtime.ReleaseAuthorizationGuard(expected_reserve)
    approval_expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    response = {
        "apiVersion": "serverware.releaseAuthorization/v1",
        "ok": True,
        "authorized": False,
        "state": "denied",
        "reason": "jit_grant_unavailable",
        "attemptId": "attempt:python-proxy",
        "bindingDigest": expected_binding_digest,
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

    def request_json_bytes(request, **_kwargs):
        captured.append(json.loads(request.data.decode("utf-8")))
        return SimpleNamespace(value=response)

    with (
        patch.object(runtime, "atomic_release_authorization_enabled", return_value=True),
        patch.object(
            runtime,
            "_release_authorization_base_url",
            return_value="https://control-plane.test/api/data-plane/release-authorizations",
        ),
        patch.object(runtime, "_release_authorization_token", return_value="test-token"),
        patch.object(runtime, "_release_authorization_ssl_context", return_value=None),
        patch.object(
            runtime,
            "request_json_bytes",
            side_effect=request_json_bytes,
        ),
    ):
        result = runtime.reserve_expected_release_authorization(
            guard=reserve_guard,
            operation_context=dict(canonical_request["operation"]),
            canonical_request=canonical_request,
            shared_quotas=[],
        )
        if reserve_guard.phase != "denied":
            raise AssertionError(
                "validated reserve denial did not disarm the caller-owned guard"
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
    oversized_expected = runtime.expected_release_authorization_identity(
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
        shared_quotas=[],
        require_jit_grant=True,
    )
    oversized_guard = runtime.ReleaseAuthorizationGuard(oversized_expected)
    oversized_cleanups: list[Any] = []

    def cancel_oversized(expected: Any) -> dict[str, Any]:
        oversized_cleanups.append(expected)
        return {
            "authorized": False,
            "state": "absent",
            "reason": "reservation_absent",
            "attempt_id": expected.attempt_id,
            "binding_digest": expected.binding_digest,
            "idempotent_replay": True,
            "grant_id": None,
            "approval_request_id": None,
            "approval_status": None,
            "approval_expires_at": None,
            "approval_created": None,
            "reservation_expires_at_epoch_ms": None,
            "dispatch_started_at_epoch_ms": None,
            "dispatch_expires_at_epoch_ms": None,
            "completion_outcome": None,
            "retry_after_seconds": 0,
            "quotas": [],
        }

    with (
        patch.object(runtime, "atomic_release_authorization_enabled", return_value=True),
        patch.object(runtime, "_release_authorization_base_url", return_value="https://control-plane.test"),
        patch.object(runtime, "_release_authorization_http_post") as post,
        patch.object(
            runtime,
            "cancel_expected_release_authorization",
            side_effect=cancel_oversized,
        ),
    ):
        try:
            runtime.reserve_expected_release_authorization(
                guard=oversized_guard,
                operation_context={},
                canonical_request=oversized,
                shared_quotas=[],
            )
        except runtime.ReleaseAuthorizationClientError:
            pass
        else:
            raise AssertionError("Python reserve accepted an oversized canonical request")
        post.assert_not_called()
    if oversized_cleanups != [oversized_expected]:
        raise AssertionError(
            "oversized reserve did not terminalize its exact expected identity"
        )


def make_approval(
    db,
    snapshot,
    *,
    digest_suffix: str,
    redacted_display: dict,
    canonical_request: dict,
    route_id: str = "demo.npm.publish.jit",
):
    return db.ensure_jit_approval_request(
        route_id=route_id,
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


def approval_review_receipt_count(db, approval_id: str) -> int:
    with db.connect() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS count FROM approval_review_receipts "
            "WHERE approval_request_id = ?",
            (approval_id,),
        ).fetchone()
    return int(row["count"] if row else 0)


def expect_http_error(call, *, status_code: int, detail: str, label: str) -> None:
    try:
        call()
    except Exception as exc:
        if (
            getattr(exc, "status_code", None) != status_code
            or detail not in str(getattr(exc, "detail", ""))
        ):
            raise AssertionError(f"{label} failed with the wrong error: {exc}") from exc
        return
    raise AssertionError(f"{label} was unexpectedly allowed")


def exercise_grant_publish_acknowledgement_binding(runtime) -> None:
    approval = {
        "id": "approval:ack-binding",
        "status": "approved",
        "principal_id": "agent:demo",
        "route_id": "demo.npm.publish.jit",
        "credential_id": "cred-demo-bearer",
        "credential_version": 2,
        "policy_hash": "sha256:" + "a" * 64,
        "request_digest": "sha256:" + "b" * 64,
        "operation_digest": "sha256:" + "c" * 64,
        "grant_max_uses": 1,
        "grant_ttl_seconds": 30,
    }
    acknowledgement = {
        "ok": True,
        "grant_id": "approval:approval:ack-binding",
        "approval_id": "approval:ack-binding",
        "policy_hash": approval["policy_hash"],
    }

    def publish(response: dict) -> dict:
        with (
            patch.object(runtime, "DECISION_GATE_BASE", "https://gate.test"),
            patch.object(
                runtime,
                "request_bytes",
                return_value=SimpleNamespace(body=json.dumps(response).encode("utf-8")),
            ),
        ):
            return runtime.publish_decision_gate_grant(approval)

    accepted = publish(acknowledgement)
    if accepted.get("ok") is not True or accepted.get("error") is not None:
        raise AssertionError(f"matching grant acknowledgement was rejected: {accepted}")
    for field in ("grant_id", "approval_id", "policy_hash"):
        mismatched = dict(acknowledgement)
        mismatched[field] = "sha256:" + "d" * 64
        rejected = publish(mismatched)
        if rejected.get("ok") is not False or field not in str(rejected.get("error")):
            raise AssertionError(
                f"mismatched {field} grant acknowledgement was accepted: {rejected}"
            )


def exercise_pending_approval_restart_migration(db, snapshot) -> None:
    url = "https://registry.npmjs.org/@scope%2frestart-test"
    approval = db.ensure_jit_approval_request(
        route_id="demo.npm.publish.jit",
        method="PUT",
        url=url,
        principal_id="agent:restart-test",
        credential_id="cred-demo-bearer",
        credential_version=2,
        policy_hash=snapshot.hash,
        request_digest="sha256:" + "e" * 64,
        operation_digest="sha256:" + "f" * 64,
        canonical_request={"operation": {"packageName": "@scope/restart-test"}},
        redacted_display={"url": url, "package": "@scope/restart-test"},
        pending_ttl_seconds=300,
        grant_ttl_seconds=30,
        grant_max_uses=1,
    )
    key_args = {
        "route_id": approval["route_id"],
        "method": approval["method"],
        "principal_id": approval["principal_id"],
        "credential_id": approval["credential_id"],
        "credential_version": approval["credential_version"],
        "policy_hash": approval["policy_hash"],
        "request_digest": approval["request_digest"],
        "operation_digest": approval["operation_digest"],
        "grant_ttl_seconds": approval["grant_ttl_seconds"],
        "grant_max_uses": approval["grant_max_uses"],
    }
    expected_key = db._pending_approval_key(
        **key_args, url=db._approval_url_commitment(url)
    )
    legacy_key = db._pending_approval_key(**key_args, url=url)
    if approval.get("pending_key") != expected_key or legacy_key == expected_key:
        raise AssertionError(f"new pending approval key is not restart-stable: {approval}")
    db.init_db()

    with db.connect() as conn:
        conn.execute(
            "UPDATE approval_requests SET pending_key = ? WHERE id = ?",
            (legacy_key, approval["id"]),
        )
    db.init_db()
    migrated = db.get_approval_request(approval["id"])
    if migrated is None or migrated.get("pending_key") != expected_key:
        raise AssertionError(f"legacy pending approval key was not migrated: {migrated}")

    tampered_key = "sha256:" + "0" * 64
    with db.connect() as conn:
        conn.execute(
            "UPDATE approval_requests SET pending_key = ? WHERE id = ?",
            (tampered_key, approval["id"]),
        )
    try:
        db.init_db()
    except db.MetadataStoreError as exc:
        if "non-deterministic immutable key" not in str(exc):
            raise AssertionError(f"tampered pending key failed unclearly: {exc}") from exc
    else:
        raise AssertionError("tampered pending approval key was accepted")
    with db.connect() as conn:
        conn.execute(
            "UPDATE approval_requests SET pending_key = ? WHERE id = ?",
            (expected_key, approval["id"]),
        )
    db.init_db()


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

        exercise_grant_publish_acknowledgement_binding(runtime)
        from serverware.auth import AdminIdentity

        exercise_python_release_lifecycle_contracts(
            runtime,
            policy_bundle.canonical_json,
        )
        exercise_python_atomic_reserve_contract(runtime, policy_bundle.canonical_json)
        db.init_db()
        webauthn.create_dev_credential("user:demo", "Approval review test authenticator")
        snapshot = policy_bundle.write_policy_bundle(policy_bundle.demo_policy_bundle("cred-demo-bearer"))
        db.advance_policy_high_water(
            policy_id=snapshot.raw["metadata"]["id"],
            sequence=snapshot.raw["metadata"]["sequence"],
            rollback_epoch=snapshot.raw["metadata"]["rollbackEpoch"],
            policy_hash=snapshot.hash,
        )
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
        exercise_pending_approval_restart_migration(db, snapshot)
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
        approver_identity = AdminIdentity(
            "user:demo", frozenset({"approver"}), "admin-token-header"
        )
        admin_identity = AdminIdentity(
            "user:demo",
            frozenset(
                {
                    "admin",
                    "approver",
                    "auditor",
                    "credential_owner",
                    "policy_author",
                    "policy_publisher",
                }
            ),
            "admin-token-header",
        )
        with patch.object(
            db,
            "_decrypt_approval_json",
            side_effect=AssertionError("approval collection attempted to decrypt review material"),
        ):
            public_collection = db.list_approvals(limit=100)
            public_api_collection = app_module.approvals(
                status=None, _=approver_identity
            )
            bootstrap_document = app_module.bootstrap(admin_identity)
        public_surfaces = json.dumps(
            {
                "db": public_collection,
                "api": public_api_collection,
                "bootstrap": bootstrap_document.get("approvals"),
            },
            sort_keys=True,
        )
        for forbidden in (
            "top-secret-value",
            "canonical_request",
            "redacted_display",
            "approval_authn",
        ):
            if forbidden in public_surfaces:
                raise AssertionError(
                    f"approval collection surface disclosed {forbidden}: {public_surfaces}"
                )
        if app_module.approval_index(current["id"]) != app_module.UI_HTML:
            raise AssertionError("approval deep link did not serve the operator portal")
        try:
            app_module.approval_index("invalid/approval")
        except app_module.HTTPException as exc:
            if exc.status_code != 404:
                raise AssertionError(
                    f"invalid approval deep link returned {exc.status_code}"
                ) from exc
        else:
            raise AssertionError("approval deep link accepted an invalid path identifier")
        receipts_before_denied_reviews = approval_review_receipt_count(db, current["id"])
        for label, denied_identity, detail in (
            (
                "unrelated global approver review",
                AdminIdentity(
                    "user:unrelated",
                    frozenset({"approver"}),
                    "admin-token-header",
                ),
                "not an allowed approver for this route",
            ),
            (
                "auditor-only review",
                AdminIdentity(
                    "user:demo",
                    frozenset({"auditor"}),
                    "admin-token-header",
                ),
                "required role: approver",
            ),
        ):
            with patch.object(
                db,
                "_decrypt_approval_json",
                side_effect=AssertionError(
                    f"{label} reached encrypted approval review material"
                ),
            ):
                expect_http_error(
                    lambda denied_identity=denied_identity: app_module.approval_review(
                        current["id"], identity=denied_identity
                    ),
                    status_code=403,
                    detail=detail,
                    label=label,
                )
        if (
            approval_review_receipt_count(db, current["id"])
            != receipts_before_denied_reviews
        ):
            raise AssertionError("denied approval reviews issued a review receipt")

        missing_route_id = "demo.npm.removed.jit"
        db.upsert_route_with_id(
            missing_route_id,
            {
                "name": "Removed NPM publish JIT route",
                "enabled": True,
                "match_host": "registry.npmjs.org",
                "match_path_prefix": "/",
                "credential_id": None,
                "injection": {"type": "bearer"},
                "policies": [{"type": "approval", "scope": "request_digest"}],
            },
        )
        missing_route = make_approval(
            db,
            snapshot,
            digest_suffix="6",
            redacted_display={"package": "@scope/removed"},
            canonical_request={
                "principal": "agent:demo",
                "operation": {"packageName": "@scope/removed"},
            },
            route_id=missing_route_id,
        )
        with patch.object(
            db,
            "_decrypt_approval_json",
            side_effect=AssertionError(
                "missing-route review reached encrypted approval review material"
            ),
        ):
            expect_http_error(
                lambda: app_module.approval_review(
                    missing_route["id"], identity=approver_identity
                ),
                status_code=409,
                detail="approval route is not in the active policy",
                label="missing-route approval review",
            )
        if approval_review_receipt_count(db, missing_route["id"]) != 0:
            raise AssertionError("missing-route approval review issued a receipt")

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
        if (
            approval_review_receipt_count(db, current["id"])
            != receipts_before_denied_reviews + 1
        ):
            raise AssertionError("authorized approval review did not issue exactly one receipt")
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

        denial_test = make_approval(
            db,
            snapshot,
            digest_suffix="f",
            redacted_display={
                "package": "@scope/pkg-denied",
                "version": "1.0.0",
                "secretToken": "top-secret-value",
            },
            canonical_request={
                "principal": "agent:demo",
                "operation": {
                    "packageName": "@scope/pkg-denied",
                    "authorization": "Bearer top-secret-value",
                },
            },
        )
        denied = app_module.deny(
            denial_test["id"],
            payload=app_module.ApprovalDeny(reason="operator rejected request"),
            identity=approver_identity,
        )
        denied_json = json.dumps(denied, sort_keys=True)
        for forbidden in (
            "top-secret-value",
            "canonical_request",
            "redacted_display",
            "approval_authn",
        ):
            if forbidden in denied_json:
                raise AssertionError(
                    f"approval decision surface disclosed {forbidden}: {denied_json}"
                )
        terminal_receipts = approval_review_receipt_count(db, denial_test["id"])
        with patch.object(
            db,
            "_decrypt_approval_json",
            side_effect=AssertionError(
                "unrelated terminal review reached retained encrypted review material"
            ),
        ):
            unrelated_terminal_review = app_module.approval_review(
                denial_test["id"],
                identity=AdminIdentity(
                    "user:unrelated",
                    frozenset({"approver"}),
                    "admin-token-header",
                ),
            )
        if approval_review_receipt_count(db, denial_test["id"]) != terminal_receipts:
            raise AssertionError("denied terminal review issued a review receipt")
        if unrelated_terminal_review != app_module.approval_review(
            denial_test["id"], identity=approver_identity
        ):
            raise AssertionError(
                "terminal approval summary varied by globally authorized approver"
            )
        denied_collection_summary = next(
            item
            for item in db.list_approvals(limit=100)
            if item["id"] == denial_test["id"]
        )
        terminal_review_json = json.dumps(unrelated_terminal_review, sort_keys=True)
        if unrelated_terminal_review != {
            **denied_collection_summary,
            "review_detail_available": False,
            "review_receipt": None,
        } or any(
            forbidden in terminal_review_json
            for forbidden in (
                "top-secret-value",
                "canonical_request",
                "redacted_display",
                "source_identity",
                "normalized_operation_fields",
                "previous_similar_approvals",
            )
        ):
            raise AssertionError(
                f"terminal approval review was not collection-safe: {unrelated_terminal_review}"
            )
        audit_documents = json.dumps(
            {
                "list": app_module.audit_events(limit=500, _=admin_identity),
                "search": db.search_audit_events(
                    limit=500,
                    scan_limit=5000,
                    approval_id=denial_test["id"],
                ),
                "export": db.export_audit_events_jsonl(
                    limit=500,
                    scan_limit=5000,
                    approval_id=denial_test["id"],
                ),
            },
            sort_keys=True,
        )
        for forbidden in (
            "top-secret-value",
            "canonical_request",
            "redacted_display",
        ):
            if forbidden in audit_documents:
                raise AssertionError(
                    f"approval audit surface disclosed {forbidden}: {audit_documents}"
                )

        approval_success_test = make_approval(
            db,
            snapshot,
            digest_suffix="a",
            redacted_display={"package": "@scope/pkg-approved", "version": "1.0.0"},
            canonical_request={
                "principal": "agent:demo",
                "operation": {"packageName": "@scope/pkg-approved"},
            },
        )
        approval_success_review = app_module.approval_review(
            approval_success_test["id"], identity=approver_identity
        )
        with (
            patch.object(app_module, "_webauthn_required", return_value=False),
            patch.object(
                runtime,
                "publish_decision_gate_grant",
                return_value={
                    "enabled": True,
                    "ok": True,
                    "response": {"secret": "top-secret-value"},
                    "payload": {"secret": "top-secret-value"},
                },
            ),
        ):
            approved_api = app_module.approve(
                approval_success_test["id"],
                ttl_seconds=30,
                payload=app_module.ApprovalApprove(
                    reviewReceiptId=approval_success_review["review_receipt"]["id"]
                ),
                identity=approver_identity,
            )
        approved_documents = json.dumps(
            {
                "response": approved_api,
                "audit": db.search_audit_events(
                    limit=500,
                    scan_limit=5000,
                    approval_id=approval_success_test["id"],
                ),
            },
            sort_keys=True,
        )
        if "top-secret-value" in approved_documents or '"response"' in json.dumps(
            approved_api, sort_keys=True
        ):
            raise AssertionError(
                f"approval publish surface disclosed a raw gate response: {approved_documents}"
            )
        with patch.object(
            db,
            "_decrypt_approval_json",
            side_effect=AssertionError(
                "approved review reached retained encrypted review material"
            ),
        ):
            approved_terminal_review = app_module.approval_review(
                approval_success_test["id"],
                identity=AdminIdentity(
                    "user:unrelated",
                    frozenset({"approver"}),
                    "admin-token-header",
                ),
            )
        if (
            approved_terminal_review["status"] != "approved"
            or approved_terminal_review["review_detail_available"] is not False
            or approved_terminal_review["review_receipt"] is not None
        ):
            raise AssertionError(
                f"approved terminal review was not collection-safe: {approved_terminal_review}"
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
        sibling_receipt = db.issue_approval_review_receipt(
            approval_request_id=receipt_test["id"],
            reviewer_id="user:other",
            review_digest=receipt_test_review["review_digest"],
        )
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
        if db.get_active_approval_review_receipt(
            sibling_receipt["id"],
            approval_request_id=receipt_test["id"],
            reviewer_id="user:other",
        ) is not None:
            raise AssertionError("terminal approval left a sibling review receipt active")
        with db.connect() as conn:
            sibling_row = conn.execute(
                "SELECT used_at FROM approval_review_receipts WHERE id = ?",
                (sibling_receipt["id"],),
            ).fetchone()
        if sibling_row is None or sibling_row["used_at"] is None:
            raise AssertionError("terminal approval did not invalidate sibling receipts")

        receipt_audit_failure = make_approval(
            db,
            snapshot,
            digest_suffix="b",
            redacted_display={"package": "@scope/audit-failure"},
            canonical_request={
                "principal": "agent:demo",
                "operation": {"packageName": "@scope/audit-failure"},
            },
        )
        original_append_audit_event = db.append_audit_event

        def reject_review_audit(*_args, **_kwargs):
            raise db.AuditStoreError("injected review receipt audit failure")

        with patch.object(db, "append_audit_event", side_effect=reject_review_audit):
            try:
                db.issue_approval_review_receipt(
                    approval_request_id=receipt_audit_failure["id"],
                    reviewer_id="user:demo",
                    review_digest="sha256:" + "7" * 64,
                )
            except db.AuditStoreError:
                pass
            else:
                raise AssertionError("review receipt committed without its audit event")
        db.append_audit_event = original_append_audit_event
        with db.connect() as conn:
            leaked_receipts = conn.execute(
                "SELECT COUNT(*) AS count FROM approval_review_receipts "
                "WHERE approval_request_id = ?",
                (receipt_audit_failure["id"],),
            ).fetchone()["count"]
        if int(leaked_receipts) != 0:
            raise AssertionError("review receipt survived an audit append rollback")

        lock_expiry = make_approval(
            db,
            snapshot,
            digest_suffix="8",
            redacted_display={"package": "@scope/lock-expiry"},
            canonical_request={
                "principal": "agent:demo",
                "operation": {"packageName": "@scope/lock-expiry"},
            },
        )
        with db.connect() as conn:
            conn.execute(
                "UPDATE approval_requests SET expires_at = ? WHERE id = ?",
                (
                    (datetime.now(timezone.utc) + timedelta(milliseconds=50)).isoformat(),
                    lock_expiry["id"],
                ),
            )
        original_lock = db._lock_pending_approval_creation

        def delayed_lock(conn):
            original_lock(conn)
            time.sleep(0.1)

        with patch.object(db, "_lock_pending_approval_creation", side_effect=delayed_lock):
            expired_approval = db.approve_request(
                lock_expiry["id"],
                actor_id="user:demo",
            )
        if expired_approval is not None:
            raise AssertionError("approval used a timestamp captured before lock acquisition")
        if db.get_approval_request(lock_expiry["id"])["status"] != "pending":
            raise AssertionError("expired approval changed state after waiting for its lock")
        expired_receipts = approval_review_receipt_count(db, lock_expiry["id"])
        with patch.object(
            db,
            "_decrypt_approval_json",
            side_effect=AssertionError(
                "expired review reached retained encrypted review material"
            ),
        ):
            expired_review = app_module.approval_review(
                lock_expiry["id"],
                identity=AdminIdentity(
                    "user:unrelated",
                    frozenset({"approver"}),
                    "admin-token-header",
                ),
            )
        if (
            expired_review["review_detail_available"] is not False
            or expired_review["review_receipt"] is not None
            or approval_review_receipt_count(db, lock_expiry["id"])
            != expired_receipts
        ):
            raise AssertionError(
                f"expired approval review was not collection-safe: {expired_review}"
            )

        missing_policy_receipts = approval_review_receipt_count(db, current["id"])
        with (
            patch.object(app_module, "get_policy_snapshot", return_value=None),
            patch.object(
                db,
                "_decrypt_approval_json",
                side_effect=AssertionError(
                    "missing-policy review reached encrypted approval review material"
                ),
            ),
        ):
            expect_http_error(
                lambda: app_module.approval_review(
                    current["id"], identity=approver_identity
                ),
                status_code=503,
                detail="policy bundle missing",
                label="missing-policy approval review",
            )
        if approval_review_receipt_count(db, current["id"]) != missing_policy_receipts:
            raise AssertionError("missing-policy approval review issued a receipt")

        changed_bundle = policy_bundle.demo_policy_bundle("cred-demo-bearer")
        changed_bundle["metadata"]["sequence"] = 2
        policy_bundle.write_policy_bundle(changed_bundle)
        stale_policy_receipts = approval_review_receipt_count(db, current["id"])
        with patch.object(
            db,
            "_decrypt_approval_json",
            side_effect=AssertionError(
                "stale-policy review reached encrypted approval review material"
            ),
        ):
            expect_http_error(
                lambda: app_module.approval_review(
                    current["id"], identity=approver_identity
                ),
                status_code=409,
                detail="policy changed",
                label="stale-policy approval review",
            )
        if approval_review_receipt_count(db, current["id"]) != stale_policy_receipts:
            raise AssertionError("stale-policy approval review issued a receipt")
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
