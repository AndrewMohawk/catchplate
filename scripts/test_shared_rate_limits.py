#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

tmpdir = tempfile.TemporaryDirectory()
os.environ["SERVERWARE_DATA_DIR"] = tmpdir.name
os.environ["SERVERWARE_DATA_PLANE_AUDIT_TOKEN"] = "test-data-plane-token"
os.environ["SERVERWARE_METADATA_STORE_BACKEND"] = "sqlite"
os.environ["SERVERWARE_AUDIT_STORE_BACKEND"] = "sqlite"
os.environ["SERVERWARE_GRANT_STORE_BACKEND"] = "sqlite"
for name in (
    "SERVERWARE_METADATA_STORE_POSTGRES_DSN",
    "SERVERWARE_AUDIT_STORE_POSTGRES_DSN",
    "SERVERWARE_GRANT_STORE_POSTGRES_DSN",
):
    os.environ.pop(name, None)

from serverware import db
from serverware.constraints import evaluate_request_constraints, reset_local_constraint_state

try:
    from fastapi import HTTPException

    from serverware import app as app_module
    from serverware.app import DataPlaneRateLimitConsume, data_plane_rate_limit_consume
except ModuleNotFoundError as exc:
    if exc.name != "fastapi":
        raise
    DataPlaneRateLimitConsume = None
    data_plane_rate_limit_consume = None
    app_module = None


class Request:
    method = "POST"
    pretty_url = "https://api.example.test/2/tweets"
    headers = {"content-type": "application/json"}
    raw_content = json.dumps({"text": "ship it"}).encode("utf-8")


def decision_for(route: SimpleNamespace, *, consume: bool):
    return evaluate_request_constraints(
        SimpleNamespace(request=Request()),
        route,
        principal_id="agent:quota-test",
        credential_ref=route.credential_ref,
        credential_version=7,
        operation_fields={"operation": "tweets.write"},
        consume_rate_limits=consume,
        policy_hash="sha256:" + "b" * 64,
        rate_limits_only=True,
    )


def main() -> None:
    db.init_db()
    counter_key = "sha256:" + "a" * 64
    base = {
        "counter_key": counter_key,
        "principal_id": "agent:quota-test",
        "route_id": "route.shared-quota",
        "credential_id": "cred-x",
        "credential_version": 7,
        "policy_hash": "sha256:" + "b" * 64,
        "constraint_id": "one-tweet-per-day",
        "operation": "tweets.write",
        "window_seconds": 60,
        "max_count": 2,
        "consume": True,
        "now_epoch_ms": 1_000_000,
    }
    first = db.consume_rate_limit(**base)
    second = db.consume_rate_limit(**base)
    third = db.consume_rate_limit(**base)
    assert first["allowed"] is True and first["remaining"] == 1, first
    assert second["allowed"] is True and second["remaining"] == 0, second
    assert third["allowed"] is False and third["retry_after_seconds"] > 0, third

    reset = db.consume_rate_limit(**{**base, "now_epoch_ms": 1_061_000})
    assert reset["allowed"] is True and reset["count"] == 1, reset

    precheck_base = {
        **base,
        "counter_key": "sha256:" + "e" * 64,
        "max_count": 1,
        "now_epoch_ms": 2_000_000,
    }
    assert db.consume_rate_limit(**precheck_base)["allowed"] is True
    precheck = db.consume_rate_limit(**{**precheck_base, "consume": False, "now_epoch_ms": 2_061_000})
    assert precheck["allowed"] is True and precheck["consumed"] is False and precheck["count"] == 0, precheck
    after_precheck = db.consume_rate_limit(**{**precheck_base, "now_epoch_ms": 2_090_000})
    assert after_precheck["allowed"] is True and after_precheck["window_start_epoch_ms"] == 2_090_000, after_precheck
    still_limited = db.consume_rate_limit(**{**precheck_base, "now_epoch_ms": 2_121_000})
    assert still_limited["allowed"] is False, still_limited

    endpoint_checked = False
    if DataPlaneRateLimitConsume is not None and data_plane_rate_limit_consume is not None:
        policy_hash = "sha256:" + "d" * 64
        api_constraint = {
            "id": "api-one-call",
            "type": "rateLimit",
            "max": 1,
            "windowSeconds": 60,
            "store": "shared",
            "key": {
                "scope": ["principal", "credential", "credentialVersion", "route", "operation"],
                "operationFields": ["tenant"],
            },
        }
        api_route = SimpleNamespace(
            id="route.api-quota",
            principals=("agent:quota-test",),
            credential_ref="cred-x",
            constraints=(api_constraint,),
        )
        snapshot = SimpleNamespace(hash=policy_hash, routes=(api_route,))
        operation_context = {"operation": "tweets.write", "tenant": "tenant-a"}
        counter_key = app_module._rate_limit_counter_key(
            constraint=api_constraint,
            route_id=api_route.id,
            principal_id="agent:quota-test",
            credential_ref=api_route.credential_ref,
            credential_version=7,
            operation_context=operation_context,
        )
        payload = DataPlaneRateLimitConsume.model_validate(
            {
                "counterKey": counter_key,
                "principalId": "agent:quota-test",
                "routeId": "route.api-quota",
                "credentialRef": "cred-x",
                "credentialVersion": 7,
                "policyHash": policy_hash,
                "constraintId": "api-one-call",
                "operation": "tweets.write",
                "operationContext": operation_context,
                "max": 1,
                "windowSeconds": 60,
                "consume": True,
                "actorId": "decision-gate-rs",
            }
        )
        original_snapshot = app_module.get_policy_snapshot
        original_get_credential = db.get_credential
        app_module.get_policy_snapshot = lambda: snapshot
        db.get_credential = lambda credential_id, include_secret=False: (
            {"id": credential_id, "credential_version": 7} if credential_id == "cred-x" else None
        )
        try:
            api_first = data_plane_rate_limit_consume(payload, x_serverware_data_plane_token="test-data-plane-token")
            api_second = data_plane_rate_limit_consume(payload, x_serverware_data_plane_token="test-data-plane-token")
            assert api_first["ok"] is True and api_first["allowed"] is True, api_first
            assert api_second["ok"] is True and api_second["allowed"] is False, api_second
            tampered = payload.model_copy(update={"max_count": 999})
            try:
                data_plane_rate_limit_consume(
                    tampered,
                    x_serverware_data_plane_token="test-data-plane-token",
                )
            except HTTPException as exc:
                assert exc.status_code == 409 and "parameters" in str(exc.detail), exc
            else:
                raise AssertionError("shared rate-limit endpoint accepted caller-controlled quota parameters")
        finally:
            app_module.get_policy_snapshot = original_snapshot
            db.get_credential = original_get_credential
        endpoint_checked = True

    route = SimpleNamespace(
        id="route.constraint-quota",
        credential_ref="cred-x",
        constraints=[
            {
                "id": "constraint-one-use",
                "type": "rateLimit",
                "max": 1,
                "windowSeconds": 60,
                "store": "shared",
                "key": {"scope": ["principal", "credential", "route", "operation", "credentialVersion"]},
            }
        ],
    )
    reset_local_constraint_state()
    assert decision_for(route, consume=False).allowed
    assert decision_for(route, consume=True).allowed
    denied = decision_for(route, consume=True)
    assert not denied.allowed, denied
    assert denied.payload["error"] == "credential_rate_limit_exceeded", denied.payload
    assert denied.payload["store"] == "shared", denied.payload

    print(f"shared rate-limit tests passed; endpoint_checked={endpoint_checked}")


if __name__ == "__main__":
    try:
        main()
    finally:
        tmpdir.cleanup()
