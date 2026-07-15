#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException
from pydantic import ValidationError
from starlette.requests import Request


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

INSTANCE_ID = "spiffe://test.serverware/decision-gate/internal-auth"
TOKENS = {
    "SERVERWARE_DATA_PLANE_CREDENTIAL_LEASE_TOKEN": "credential-lease-test-token",
    "SERVERWARE_DATA_PLANE_AUDIT_TOKEN": "audit-ingest-test-token",
    "SERVERWARE_DATA_PLANE_GRANT_CONSUME_TOKEN": "grant-consume-test-token",
    "SERVERWARE_DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN": "rate-limit-consume-test-token",
    "SERVERWARE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN": "release-authorization-test-token",
    "SERVERWARE_DATA_PLANE_MANAGEMENT_TOKEN": "rust-management-test-token",
}


def expect_http_error(call, status_code: int) -> str:
    try:
        call()
    except HTTPException as exc:
        if exc.status_code != status_code:
            raise AssertionError(f"expected HTTP {status_code}, got {exc.status_code}: {exc.detail}") from exc
        detail = str(exc.detail)
        for token in TOKENS.values():
            if token in detail:
                raise AssertionError("service-auth failure disclosed a token")
        return detail
    raise AssertionError(f"expected HTTP {status_code}")


async def bounded_lease_with_token(token: str):
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": b"{}", "more_body": False}

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/data-plane/credential-leases",
            "headers": [(b"x-serverware-data-plane-token", token.encode("ascii"))],
        },
        receive,
    )
    return await app_module._bounded_credential_lease_request(request)


def expect_model_rejects_actor(model, payload: dict) -> None:
    for actor_field in ("actor_id", "actorId"):
        try:
            model.model_validate({**payload, actor_field: "spiffe://forged.example/workload"})
        except ValidationError as exc:
            if not any(error.get("type") == "extra_forbidden" for error in exc.errors()):
                raise AssertionError(f"forged {actor_field} failed for the wrong reason: {exc}") from exc
        else:
            raise AssertionError(f"model accepted forged {actor_field}")


def production_validation(environment: dict[str, str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            sys.executable,
            "-c",
            "from serverware.config import validate_internal_service_auth; validate_internal_service_auth()",
        ],
        cwd=ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def assert_production_validation() -> None:
    production_tokens = {
        name: f"{index:02d}-scope-token-ABCDEFGHIJKLMNOPQRSTUVWXYZ-0123456789"
        for index, name in enumerate(TOKENS, start=1)
    }
    base = os.environ.copy()
    base.update(production_tokens)
    base["SERVERWARE_RELEASE_CHANNEL"] = "prod"
    base["SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED"] = "1"
    base["SERVERWARE_DATA_PLANE_INSTANCE_ID"] = "spiffe://prod.serverware/decision-gate/instance-01"
    passed = production_validation(base)
    if passed.returncode != 0:
        raise AssertionError(passed.stderr.decode("utf-8", errors="replace"))

    cases = []
    missing = dict(base)
    missing.pop("SERVERWARE_DATA_PLANE_GRANT_CONSUME_TOKEN")
    cases.append((missing, "SERVERWARE_DATA_PLANE_GRANT_CONSUME_TOKEN", None))
    weak = dict(base)
    weak["SERVERWARE_DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN"] = "x" * 32
    cases.append((weak, "high-entropy", "x" * 32))
    equal = dict(base)
    duplicate = equal["SERVERWARE_DATA_PLANE_AUDIT_TOKEN"]
    equal["SERVERWARE_DATA_PLANE_CREDENTIAL_LEASE_TOKEN"] = duplicate
    cases.append((equal, "distinct internal service credentials", duplicate))

    for environment, expected, secret in cases:
        result = production_validation(environment)
        detail = result.stderr.decode("utf-8", errors="replace") + result.stdout.decode("utf-8", errors="replace")
        if result.returncode == 0 or expected not in detail:
            raise AssertionError(f"production service-auth validation did not fail closed: {detail}")
        if secret and secret in detail:
            raise AssertionError("production service-auth validation disclosed a token")


def main() -> None:
    db.init_db()
    audit_payload = {
        "event_type": "data_plane.test.internal_auth",
        "event": {"marker": "server-derived-actor"},
    }
    rate_payload = {
        "counterKey": "sha256:" + "a" * 64,
        "principalId": "agent:test",
        "routeId": "route:test",
        "credentialRef": "credential:test",
        "credentialVersion": 1,
        "policyHash": "sha256:" + "b" * 64,
        "constraintId": "quota:test",
        "operation": "test.read",
        "operationContext": {"operation": "test.read"},
        "max": 1,
        "windowSeconds": 60,
    }
    release_payload = {
        "apiVersion": "serverware.releaseAuthorizationReserve/v1",
        "attemptId": "attempt:test",
        "flowId": "flow:test",
        "principalId": "agent:test",
        "routeId": "route:test",
        "credentialRef": "credential:test",
        "credentialVersion": 1,
        "policyHash": "sha256:" + "b" * 64,
        "requestDigest": "sha256:" + "c" * 64,
        "operationDigest": "sha256:" + "d" * 64,
        "operationContext": {"operation": "test.write"},
    }
    expect_model_rejects_actor(DataPlaneAuditEvent, audit_payload)
    expect_model_rejects_actor(DataPlaneRateLimitConsume, rate_payload)
    expect_model_rejects_actor(DataPlaneReleaseAuthorizationReserve, release_payload)
    for forbidden in ("counterKey", "constraintId", "max", "windowSeconds"):
        try:
            DataPlaneReleaseAuthorizationReserve.model_validate(
                {**release_payload, forbidden: 1}
            )
        except ValidationError as exc:
            if not any(error.get("type") == "extra_forbidden" for error in exc.errors()):
                raise AssertionError(
                    f"release reserve rejected {forbidden} for the wrong reason: {exc}"
                ) from exc
        else:
            raise AssertionError(
                f"release reserve accepted caller-controlled {forbidden}"
            )

    batch = DataPlaneAuditBatch(events=[DataPlaneAuditEvent.model_validate(audit_payload)])
    expect_http_error(
        lambda: data_plane_audit(batch, TOKENS["SERVERWARE_DATA_PLANE_CREDENTIAL_LEASE_TOKEN"]),
        401,
    )
    expect_http_error(
        lambda: data_plane_grant_consume(
            DataPlaneGrantConsume.model_validate(
                {
                    "principalId": "agent:test",
                    "routeId": "route:test",
                    "credentialRef": "credential:test",
                    "credentialVersion": 1,
                    "policyHash": "sha256:" + "b" * 64,
                    "requestDigest": "sha256:" + "c" * 64,
                    "operationDigest": "sha256:" + "d" * 64,
                    "flowId": "flow:test",
                }
            ),
            TOKENS["SERVERWARE_DATA_PLANE_AUDIT_TOKEN"],
        ),
        401,
    )
    expect_http_error(
        lambda: data_plane_rate_limit_consume(
            DataPlaneRateLimitConsume.model_validate(rate_payload),
            TOKENS["SERVERWARE_DATA_PLANE_GRANT_CONSUME_TOKEN"],
        ),
        401,
    )
    expect_http_error(
        lambda: data_plane_release_authorization_reserve(
            DataPlaneReleaseAuthorizationReserve.model_validate(release_payload),
            TOKENS["SERVERWARE_DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN"],
        ),
        401,
    )
    transition_digest = "sha256:" + "e" * 64
    expect_http_error(
        lambda: data_plane_release_authorization_dispatch(
            DataPlaneReleaseAuthorizationDispatch.model_validate(
                {
                    "apiVersion": "serverware.releaseAuthorizationDispatch/v1",
                    "attemptId": "attempt:test",
                    "bindingDigest": transition_digest,
                }
            ),
            TOKENS["SERVERWARE_DATA_PLANE_GRANT_CONSUME_TOKEN"],
        ),
        401,
    )
    expect_http_error(
        lambda: data_plane_release_authorization_complete(
            DataPlaneReleaseAuthorizationComplete.model_validate(
                {
                    "apiVersion": "serverware.releaseAuthorizationComplete/v1",
                    "attemptId": "attempt:test",
                    "bindingDigest": transition_digest,
                    "outcome": "unknown",
                }
            ),
            TOKENS["SERVERWARE_DATA_PLANE_AUDIT_TOKEN"],
        ),
        401,
    )
    try:
        asyncio.run(bounded_lease_with_token(TOKENS["SERVERWARE_DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN"]))
    except HTTPException as exc:
        if exc.status_code != 401 or any(token in str(exc.detail) for token in TOKENS.values()):
            raise AssertionError(f"credential-lease wrong-scope rejection was unsafe: {exc.detail}") from exc
    else:
        raise AssertionError("credential-lease endpoint accepted a wrong-scope token")

    accepted = data_plane_audit(batch, TOKENS["SERVERWARE_DATA_PLANE_AUDIT_TOKEN"])
    if accepted != {"ok": True, "accepted": 1}:
        raise AssertionError(f"audit ingestion failed: {accepted}")
    stored = next(item for item in db.list_audit_events() if item["event_type"] == audit_payload["event_type"])
    if stored.get("actor_type") != "data-plane" or stored.get("actor_id") != INSTANCE_ID:
        raise AssertionError(f"audit actor was not derived from authenticated configuration: {stored}")

    route = SimpleNamespace(
        id="route:test",
        principals=("agent:test",),
        scheme="https",
        host="upstream.invalid",
        port=443,
        methods=frozenset({"POST"}),
        match_path=lambda path: {} if path == "/resource" else None,
        credential_ref="credential:test",
        constraints=(
            {
                "id": "quota:principal",
                "type": "rateLimit",
                "store": "shared",
                "max": 3,
                "windowSeconds": 60,
                "key": {
                    "scope": ["principal", "credential", "route", "operation"]
                },
            },
            {
                "id": "quota:account",
                "type": "rateLimit",
                "store": "shared",
                "max": 1,
                "windowSeconds": 3600,
                "key": {
                    "scope": ["route"],
                    "operationFields": ["account"],
                },
            },
        ),
        jit={
            "required": True,
            "maxUses": 1,
            "consumeOn": "forwardStart",
            "binding": {"type": "operationDigest"},
        },
    )
    snapshot = SimpleNamespace(
        hash=release_payload["policyHash"], routes=(route,)
    )
    captured: dict[str, object] = {}

    def reserve_release(**kwargs):
        captured.update(kwargs)
        return {
            "authorized": True,
            "state": "reserved",
            "reason": "reserved",
            "attempt_id": kwargs["attempt_id"],
            "binding_digest": "sha256:" + "e" * 64,
            "idempotent_replay": False,
            "grant_id": "grant:test",
            "approval_request_id": "approval:test",
            "reservation_expires_at_epoch_ms": 123456,
            "dispatch_started_at_epoch_ms": None,
            "dispatch_expires_at_epoch_ms": None,
            "completion_outcome": None,
            "quotas": [],
            "release_authorization_store_backend": "sqlite",
            "release_authorization_store_ha": False,
        }

    release_payload["operationContext"]["account"] = "acct:test"
    canonical_request = {
        "v": 1,
        "principal": release_payload["principalId"],
        "client_ip": "192.0.2.10",
        "route_id": release_payload["routeId"],
        "credential_ref": release_payload["credentialRef"],
        "credential_version": str(release_payload["credentialVersion"]),
        "policy_hash": release_payload["policyHash"],
        "request": {
            "method": "POST",
            "scheme": "https",
            "authority": "upstream.invalid",
            "path": "/resource",
            "query": [],
            "headers": {"host": "upstream.invalid"},
            "body_sha256": "sha256:" + hashlib.sha256(b"").hexdigest(),
        },
        "operation": dict(release_payload["operationContext"]),
    }

    def digest(value: dict) -> str:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(encoded).hexdigest()

    release_payload["canonicalRequest"] = canonical_request
    release_payload["requestDigest"] = digest(canonical_request)
    release_payload["operationDigest"] = digest(
        {
            "principal": canonical_request["principal"],
            "route_id": canonical_request["route_id"],
            "credential_ref": canonical_request["credential_ref"],
            "credential_version": canonical_request["credential_version"],
            "policy_hash": canonical_request["policy_hash"],
            "request": canonical_request["request"],
            "operation": canonical_request["operation"],
        }
    )
    with (
        patch.object(app_module, "get_policy_snapshot", return_value=snapshot),
        patch.object(app_module.db, "get_credential", return_value={"credential_version": 1}),
        patch.object(app_module.db, "reserve_release_authorization", side_effect=reserve_release),
        patch.object(app_module, "_release_authorization_maintenance"),
    ):
        release_response = data_plane_release_authorization_reserve(
            DataPlaneReleaseAuthorizationReserve.model_validate(release_payload),
            TOKENS["SERVERWARE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN"],
        )
    derived_quotas = captured.get("shared_quotas")
    if not isinstance(derived_quotas, list) or {
        (item.get("constraint_id"), item.get("max_count"), item.get("window_seconds"))
        for item in derived_quotas
    } != {("quota:principal", 3, 60), ("quota:account", 1, 3600)}:
        raise AssertionError(
            f"reserve endpoint did not derive every shared claim from policy: {captured}"
        )
    if not all(str(item.get("counter_key", "")).startswith("sha256:") for item in derived_quotas):
        raise AssertionError(f"reserve endpoint did not derive counter keys: {derived_quotas}")
    if release_response != {
        "apiVersion": "serverware.releaseAuthorization/v1",
        "ok": True,
        "authorized": True,
        "state": "reserved",
        "reason": "reserved",
        "attemptId": "attempt:test",
        "bindingDigest": "sha256:" + "e" * 64,
        "idempotentReplay": False,
        "grantId": "grant:test",
        "approvalRequestId": "approval:test",
        "reservationExpiresAtEpochMs": 123456,
        "dispatchStartedAtEpochMs": None,
        "dispatchExpiresAtEpochMs": None,
        "completionOutcome": None,
        "retryAfterSeconds": 0,
        "quotas": [],
        "store": {"backend": "sqlite", "ha": False},
    }:
        raise AssertionError(f"release reserve response contract changed: {release_response}")

    with (
        patch.object(app_module, "ATOMIC_RELEASE_AUTHORIZATION_ENABLED", True),
        patch.object(app_module, "RELEASE_CHANNEL", "production"),
    ):
        expect_http_error(
            lambda: data_plane_grant_consume(
                DataPlaneGrantConsume.model_validate(
                    {
                        "principalId": "agent:test",
                        "routeId": "route:test",
                        "credentialRef": "credential:test",
                        "credentialVersion": 1,
                        "policyHash": "sha256:" + "b" * 64,
                        "requestDigest": "sha256:" + "c" * 64,
                        "flowId": "flow:test",
                    }
                ),
                TOKENS["SERVERWARE_DATA_PLANE_GRANT_CONSUME_TOKEN"],
            ),
            409,
        )
        expect_http_error(
            lambda: data_plane_rate_limit_consume(
                DataPlaneRateLimitConsume.model_validate(rate_payload),
                TOKENS["SERVERWARE_DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN"],
            ),
            409,
        )

    assert_production_validation()
    print("internal service-auth trust-boundary tests passed")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["SERVERWARE_DATA_DIR"] = tmp
        os.environ["SERVERWARE_RELEASE_CHANNEL"] = "test"
        os.environ["SERVERWARE_DATA_PLANE_INSTANCE_ID"] = INSTANCE_ID
        os.environ.update(TOKENS)
        os.environ["SERVERWARE_METADATA_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_AUDIT_STORE_BACKEND"] = "sqlite"
        os.environ["SERVERWARE_GRANT_STORE_BACKEND"] = "sqlite"
        from serverware import db
        from serverware import app as app_module
        from serverware.app import (
            DataPlaneAuditBatch,
            DataPlaneAuditEvent,
            DataPlaneGrantConsume,
            DataPlaneRateLimitConsume,
            DataPlaneReleaseAuthorizationComplete,
            DataPlaneReleaseAuthorizationDispatch,
            DataPlaneReleaseAuthorizationReserve,
            data_plane_audit,
            data_plane_grant_consume,
            data_plane_rate_limit_consume,
            data_plane_release_authorization_complete,
            data_plane_release_authorization_dispatch,
            data_plane_release_authorization_reserve,
        )

        main()
