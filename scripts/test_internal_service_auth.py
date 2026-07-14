#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import tempfile
from pathlib import Path

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
    expect_model_rejects_actor(DataPlaneAuditEvent, audit_payload)
    expect_model_rejects_actor(DataPlaneRateLimitConsume, rate_payload)

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
            data_plane_audit,
            data_plane_grant_consume,
            data_plane_rate_limit_consume,
        )

        main()
