#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from contextlib import nullcontext
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


def audit_event_id(marker: int) -> str:
    return f"sha256:{marker:064x}"


def audit_event(marker: int, event_type: str, event: dict) -> dict:
    return {
        "eventId": audit_event_id(marker),
        "eventType": event_type,
        "event": event,
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


async def bounded_lease_payload(payload: dict, token: str):
    sent = False
    body = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

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


async def bounded_lease_with_token(token: str):
    return await bounded_lease_payload({}, token)


async def asgi_json_post(
    path: str,
    payload: dict,
    token: str,
) -> tuple[int, bytes]:
    body = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    sent = False
    status_code = 0
    response_body = bytearray()

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        nonlocal status_code
        if message["type"] == "http.response.start":
            status_code = int(message["status"])
        elif message["type"] == "http.response.body":
            response_body.extend(message.get("body", b""))

    await app_module.app(
        {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": b"",
            "root_path": "",
            "headers": [
                (b"host", b"testserver"),
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"x-serverware-data-plane-token", token.encode("ascii")),
                (
                    b"x-serverware-response-nonce",
                    b"alias-closure-wire-response",
                ),
            ],
            "client": ("127.0.0.1", 43127),
            "server": ("testserver", 80),
        },
        receive,
        send,
    )
    return status_code, bytes(response_body)


def conflicting_alias_value(value):
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    if isinstance(value, str):
        return value + "-conflict"
    if isinstance(value, list):
        return [*value, {"conflict": True}]
    if isinstance(value, dict):
        return {**value, "conflict": True}
    return "conflict"


def expect_alias_only_wire(model, payload: dict, *, label: str) -> None:
    model.model_validate(payload)
    for field_name, field in model.model_fields.items():
        alias = field.alias
        if not isinstance(alias, str) or alias == field_name or alias not in payload:
            continue
        snake_only = json.loads(json.dumps(payload))
        snake_only[field_name] = snake_only.pop(alias)
        alias_and_snake = json.loads(json.dumps(payload))
        alias_and_snake[field_name] = conflicting_alias_value(
            alias_and_snake[alias]
        )
        for variant, shape in (
            (snake_only, "snake_case"),
            (alias_and_snake, "alias+snake conflict"),
        ):
            try:
                model.model_validate(variant)
            except ValidationError as exc:
                if not any(
                    error.get("type") == "extra_forbidden"
                    and tuple(error.get("loc") or ()) == (field_name,)
                    for error in exc.errors()
                ):
                    raise AssertionError(
                        f"{label} rejected {shape} {field_name} for the "
                        f"wrong reason: {exc}"
                    ) from exc
            else:
                raise AssertionError(
                    f"{label} accepted {shape} spelling for {field_name}"
                )


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


def audit_retry_regressions() -> None:
    """Exercise the legacy HTTP receiver and real SQLite transactions, not a mock store."""
    token = TOKENS["SERVERWARE_DATA_PLANE_AUDIT_TOKEN"]

    def request_body(events: list[dict]) -> bytes:
        return json.dumps({"events": events}, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def ingest(body: bytes, request_token: str = token) -> dict:
        sent = False

        async def receive():
            nonlocal sent
            if sent:
                return {"type": "http.disconnect"}
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}

        request = Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/api/data-plane/audit",
                "query_string": b"",
                "headers": [(b"content-type", b"application/json")],
            },
            receive,
        )
        return asyncio.run(app_module.data_plane_audit(request, request_token))

    def snapshot() -> list[dict]:
        with db.connect() as conn:
            return [dict(row) for row in conn.execute("SELECT * FROM audit_events ORDER BY rowid")]

    def expected_ack(body: bytes, count: int) -> dict:
        # These are route-body assertions; middleware signature verification is separate.
        return {
            "apiVersion": "serverware.dataPlaneAuditAck/v1",
            "ok": True,
            "accepted": count,
            "batchDigest": "sha256:" + hashlib.sha256(body).hexdigest(),
            "instanceId": INSTANCE_ID,
        }

    first = audit_event(100, "data_plane.test.retry_batch.first", {"marker": "first"})
    second = audit_event(101, "data_plane.test.retry_batch.second", {"marker": "second"})
    third = audit_event(102, "data_plane.test.retry_batch.third", {"marker": "third"})
    fourth = audit_event(103, "data_plane.test.retry_batch.fourth", {"marker": "fourth"})
    original_body = request_body([first, second])
    initial = snapshot()
    expect_http_error(lambda: ingest(b"not-json"), 422)
    expect_http_error(
        lambda: ingest(original_body, TOKENS["SERVERWARE_DATA_PLANE_CREDENTIAL_LEASE_TOKEN"]),
        401,
    )
    assert snapshot() == initial, "invalid body or wrong-scope token appended audit history"

    with patch.object(db, "iso_now", return_value="2026-01-01T00:00:00+00:00"):
        first_ack = ingest(original_body)
    assert first_ack == expected_ack(original_body, 2), "initial ACK did not bind both events and exact body"
    committed = snapshot()
    assert len(committed) == len(initial) + 2, "initial batch did not append exactly two rows"
    for row, event in zip(committed[-2:], [first, second], strict=True):
        assert row["id"] == db._data_plane_audit_row_id(INSTANCE_ID, event["eventId"])
        assert row["event_type"] == event["eventType"]
        assert row["actor_type"] == "data-plane" and row["actor_id"] == INSTANCE_ID
        assert json.loads(row["event_json"]) == event["event"]

    # The first response is treated as lost after commit; preserve the original batch.
    with patch.object(db, "iso_now", return_value="2026-01-01T00:00:01+00:00"):
        replay_ack = ingest(original_body)
    assert replay_ack == first_ack, "lost-ACK whole-batch replay was not acknowledged"
    assert snapshot() == committed, "whole-batch replay changed immutable rows, timestamps, or head"

    expect_http_error(lambda: ingest(request_body([first, third])), 409)
    assert snapshot() == committed, "mixed existing/new batch appended its fresh suffix"
    changed = {**second, "event": {"marker": "changed"}}
    expect_http_error(lambda: ingest(request_body([first, changed])), 409)
    assert snapshot() == committed, "changed existing event body mutated immutable history"
    expect_http_error(lambda: ingest(request_body([third, third])), 400)
    assert snapshot() == committed, "duplicate event IDs appended audit history"
    assert ingest(original_body) == first_ack, "rejected batches poisoned an exact retry"
    assert snapshot() == committed, "retry after rejection changed audit history"

    fresh_body = request_body([third, fourth])
    with patch.object(db, "iso_now", return_value="2026-01-01T00:00:02+00:00"):
        fresh_ack = ingest(fresh_body)
    assert fresh_ack == expected_ack(fresh_body, 2), "separate fresh batch was not acknowledged"
    complete = snapshot()
    assert complete[:-2] == committed and len(complete) == len(initial) + 4
    assert complete[-2]["prev_event_hash"] == committed[-1]["event_hash"]
    assert complete[-1]["prev_event_hash"] == complete[-2]["event_hash"]
    assert [row["id"] for row in complete[-2:]] == [
        db._data_plane_audit_row_id(INSTANCE_ID, event["eventId"])
        for event in [third, fourth]
    ]
    assert ingest(original_body) == first_ack, "older committed batch stopped being replayable"
    assert ingest(fresh_body) == fresh_ack, "fresh batch stopped being replayable"
    assert snapshot() == complete, "replay after a fresh batch changed the chain head"
    verification = db.verify_audit_chain()
    assert verification["ok"] and verification["complete"], "final audit chain did not verify"
    assert verification["count"] == len(complete) and verification["head"] == complete[-1]["event_hash"]
    print(
        "audit receiver retry regressions passed: 11 route requests, 4 appended rows, "
        "4 immutable replays, 5 rejected requests, exact-body ACKs, complete verified chain"
    )


def initialize_audit_retry_fixture() -> None:
    """Minimal temporary SQLite schema; no full application bootstrap or external stores."""
    with db.connect() as conn:
        conn.executescript(
            """
            CREATE TABLE audit_events (
                id TEXT PRIMARY KEY, event_type TEXT NOT NULL,
                actor_type TEXT NOT NULL, actor_id TEXT, event_json TEXT NOT NULL,
                encrypted_canonical_event_json TEXT, storage_format_version INTEGER,
                prev_event_hash TEXT, event_hash TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE serverware_store_migrations (
                migration TEXT PRIMARY KEY, version INTEGER NOT NULL
            );
            """
        )


def main() -> None:
    db.init_db()
    audit_retry_regressions()
    rust_source = (
        ROOT / "data-plane" / "decision-gate-rs" / "src" / "main.rs"
    ).read_text(encoding="utf-8")
    rust_source = rust_source.rsplit("\n#[cfg(test)]\nmod tests {", maxsplit=1)[0]
    rust_event_types = set(
        re.findall(
            r'"(data_plane\.[A-Za-z0-9_.-]+)"',
            rust_source,
        )
    )
    rust_event_types.discard("data_plane.test")
    if rust_event_types != set(app_module._PRODUCTION_DATA_PLANE_AUDIT_EVENT_TYPES):
        raise AssertionError(
            "production audit allowlist differs from Rust event types: "
            f"missing={sorted(rust_event_types - set(app_module._PRODUCTION_DATA_PLANE_AUDIT_EVENT_TYPES))} "
            f"extra={sorted(set(app_module._PRODUCTION_DATA_PLANE_AUDIT_EVENT_TYPES) - rust_event_types)}"
        )
    audit_payload = audit_event(
        1,
        "data_plane.test.internal_auth",
        {"marker": "server-derived-actor"},
    )
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

    def digest(value: object) -> str:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(encoded).hexdigest()

    release_canonical_request = {
        "v": 1,
        "principal": "agent:test",
        "client_ip": "192.0.2.10",
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
    release_payload = {
        "apiVersion": "serverware.releaseAuthorizationReserve/v1",
        "attemptId": "attempt:test",
        "flowId": "attempt:test",
        "principalId": "agent:test",
        "routeId": "route:test",
        "credentialRef": "credential:test",
        "credentialVersion": 1,
        "policyHash": "sha256:" + "b" * 64,
        "requestDigest": digest(release_canonical_request),
        "operationDigest": digest(
            {
                key: release_canonical_request[key]
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
        ),
        "operationContext": {"operation": "test.write"},
        "canonicalRequest": release_canonical_request,
    }
    durable_claim = {
        "type": "weightedBudget",
        "constraint_id": "weighted:test",
        "budget_key": "sha256:" + "1" * 64,
        "principal_id": "agent:test",
        "route_id": "route:test",
        "credential_id": "credential:test",
        "credential_version": 1,
        "policy_hash": release_payload["policyHash"],
        "operation": "test.write",
        "window_semantics": "sliding",
        "measure": "weightedCanonicalInteger",
        "reservation_mode": "atomicReserveCommitRelease",
        "on_overflow": "deny",
        "unit_field": "request-unit:requestValue:units",
        "units": 7,
        "window_seconds": 60,
        "max_units": 100,
    }
    durable_claims = [durable_claim]
    release_v2_payload = {
        **json.loads(json.dumps(release_payload)),
        "apiVersion": "serverware.releaseAuthorizationReserve/v2",
        "attemptId": "sha256:" + "8" * 64,
        "flowId": "sha256:" + "8" * 64,
        "durablePolicy": {
            "actorId": INSTANCE_ID,
            "claimDigest": digest(durable_claims),
            "claims": durable_claims,
        },
    }
    DataPlaneReleaseAuthorizationReserve.model_validate(release_v2_payload)
    for invalid_v2 in (
        {**release_v2_payload, "apiVersion": "serverware.releaseAuthorizationReserve/v1"},
        {**release_payload, "durablePolicy": None},
        {
            key: value
            for key, value in release_v2_payload.items()
            if key != "durablePolicy"
        },
        {
            **release_v2_payload,
            "durablePolicy": {
                **release_v2_payload["durablePolicy"],
                "unknown": True,
            },
        },
        {
            **release_v2_payload,
            "durablePolicy": {
                key: value
                for key, value in release_v2_payload["durablePolicy"].items()
                if key != "claimDigest"
            },
        },
        {
            **release_v2_payload,
            "durablePolicy": {
                **release_v2_payload["durablePolicy"],
                "claimDigest": "sha256:" + "f" * 64,
            },
        },
    ):
        try:
            DataPlaneReleaseAuthorizationReserve.model_validate(invalid_v2)
        except ValidationError:
            pass
        else:
            raise AssertionError(
                f"release v2 reserve accepted a mixed or open body: {invalid_v2}"
            )

    operation_scoped_route = SimpleNamespace(
        constraints=(
            {
                "type": "traversalBudget",
                "operations": ["test.read"],
            },
        )
    )
    if app_module._release_authorization_durable_claims(
        DataPlaneReleaseAuthorizationReserve.model_validate(release_payload),
        operation_scoped_route,
        authenticated_actor_id=INSTANCE_ID,
    ) is not None:
        raise AssertionError(
            "operation-excluded traversal unexpectedly produced durable authority"
        )
    app_module._assert_release_authorization_v2_reserve_result(
        {"authorized": False, "reason": "durable_policy_denied"}
    )
    denial_detail = expect_http_error(
        lambda: app_module._assert_release_authorization_v2_reserve_result(
            {"authorized": False, "reason": "active_policy_changed"}
        ),
        409,
    )
    if "release_authorization_v2_denial_unrepresentable" not in denial_detail:
        raise AssertionError("unrepresentable v2 denial was not typed")

    durable_transition = {
        "actorId": INSTANCE_ID,
        "attemptId": release_v2_payload["attemptId"],
        "claimDigest": digest(durable_claims),
        "reservationId": "sha256:" + "2" * 64,
    }
    dispatch_v2_payload = {
        "apiVersion": "serverware.releaseAuthorizationDispatch/v2",
        "attemptId": release_v2_payload["attemptId"],
        "bindingDigest": "sha256:" + "3" * 64,
        "durablePolicy": {
            **durable_transition,
            "dispatchDeadlineAtEpochMs": 4_102_444_800_000,
        },
    }
    DataPlaneReleaseAuthorizationDispatch.model_validate(dispatch_v2_payload)
    response_evidence = [
        {
            "constraint_id": "traversal:test",
            "lineage_digest": "sha256:" + "4" * 64,
            "request_cursor_digest": None,
            "response_digest": "sha256:" + "5" * 64,
            "next_cursor_digest": "sha256:" + "6" * 64,
            "record_count": 1,
            "decoded_bytes": 128,
            "validation": "passed",
        }
    ]
    complete_v2_payload = {
        "apiVersion": "serverware.releaseAuthorizationComplete/v2",
        "attemptId": release_v2_payload["attemptId"],
        "bindingDigest": dispatch_v2_payload["bindingDigest"],
        "outcome": "forwarded",
        "durablePolicy": {
            **durable_transition,
            "dispatchDeadlineAtEpochMs": dispatch_v2_payload[
                "durablePolicy"
            ]["dispatchDeadlineAtEpochMs"],
            "responseEvidence": response_evidence,
            "responseEvidenceDigest": digest(response_evidence),
            "responseBodySha256": "sha256:" + "5" * 64,
        },
    }
    DataPlaneReleaseAuthorizationComplete.model_validate(complete_v2_payload)
    DataPlaneReleaseAuthorizationComplete.model_validate(
        {
            "apiVersion": "serverware.releaseAuthorizationComplete/v2",
            "attemptId": release_v2_payload["attemptId"],
            "bindingDigest": dispatch_v2_payload["bindingDigest"],
            "outcome": "not_forwarded",
            "durablePolicy": durable_transition,
        }
    )
    indeterminate_evidence = [
        {
            "constraint_id": "traversal:test",
            "lineage_digest": "sha256:" + "4" * 64,
            "request_cursor_digest": None,
            "outcome": "indeterminate",
            "reason": "provider_outcome_or_response_validation_uncertain",
            "response_body_sha256": "sha256:" + "7" * 64,
        }
    ]
    unknown_v2_payload = {
        "apiVersion": "serverware.releaseAuthorizationComplete/v2",
        "attemptId": release_v2_payload["attemptId"],
        "bindingDigest": dispatch_v2_payload["bindingDigest"],
        "outcome": "unknown",
        "durablePolicy": {
            **durable_transition,
            "dispatchDeadlineAtEpochMs": dispatch_v2_payload[
                "durablePolicy"
            ]["dispatchDeadlineAtEpochMs"],
            "responseEvidence": indeterminate_evidence,
            "responseEvidenceDigest": digest(indeterminate_evidence),
            "failureReason": (
                "provider_outcome_or_response_validation_uncertain"
            ),
            "responseBodySha256": "sha256:" + "7" * 64,
            "uncertainty": "charged_fail_closed",
        },
    }
    DataPlaneReleaseAuthorizationComplete.model_validate(unknown_v2_payload)
    credential_quota_claim = {
        "counterKey": "sha256:" + "9" * 64,
        "constraintId": "quota:credential-lease-v4",
        "operation": "gmail.message.list",
        "windowKind": "fixed",
        "windowSeconds": 60,
        "windowStartEpochMs": 4_102_444_740_000,
        "windowEndEpochMs": 4_102_444_800_000,
        "max": 1,
        "count": 1,
        "remaining": 0,
        "reservationState": "reserved",
    }
    credential_request_attempt_id = "sha256:" + "a" * 64
    credential_request_binding_digest = "sha256:" + "b" * 64
    credential_request_reservation_id = db.release_reservation_id(
        credential_request_attempt_id,
        credential_request_binding_digest,
    )
    credential_request_authority = {
        "apiVersion": "serverware.credentialLeaseRequestAuthority/v1",
        "attemptId": credential_request_attempt_id,
        "reservationId": credential_request_reservation_id,
        "bindingDigest": credential_request_binding_digest,
        "requestDigest": "sha256:" + "c" * 64,
        "operationDigest": "sha256:" + "d" * 64,
        "operationContext": {
            "account": "acct:test",
            "operation": "gmail.message.list",
        },
        "reservationExpiresAtEpochMs": 4_102_444_800_000,
    }
    credential_durable_claim = {
        "reservationId": "sha256:" + "e" * 64,
        "actorId": INSTANCE_ID,
        "claimDigest": "sha256:" + "f" * 64,
        "reservationDeadlineAtEpochMs": 4_102_444_800_000,
        "releaseBindingDigest": credential_request_binding_digest,
    }
    credential_release_authorization = {
        "apiVersion": (
            "serverware.credentialLeaseReleaseAuthorization/v2"
        ),
        "kind": "atomicReservation",
        "state": "reserved",
        "attemptId": credential_request_attempt_id,
        "reservationId": credential_request_reservation_id,
        "bindingDigest": credential_request_binding_digest,
        "principalId": "agent:test",
        "routeId": "route:test",
        "credentialId": "credential:test",
        "credentialVersion": 1,
        "policyHash": "sha256:" + "1" * 64,
        "requestDigest": credential_request_authority["requestDigest"],
        "operationDigest": credential_request_authority[
            "operationDigest"
        ],
        "quotaClaims": [credential_quota_claim],
        "durablePolicy": credential_durable_claim,
        "grantId": None,
        "approvalRequestId": None,
        "reservationExpiresAtEpochMs": 4_102_444_800_000,
    }
    credential_request_v4 = {
        "apiVersion": "serverware.credentialLeaseRequest/v4",
        "purpose": "dispatchSecret",
        "principalId": "agent:test",
        "routeId": "route:test",
        "credentialId": "credential:test",
        "expectedCredentialVersion": 1,
        "expectedMetadataSha256": "sha256:" + "2" * 64,
        "requestAuthority": credential_request_authority,
        "releaseAuthorization": credential_release_authorization,
        "recipientPublicKey": "A" * 43,
        "recipientKeyId": "sha256:" + "3" * 64,
        "recipientNonce": "B" * 43,
        "policyHash": "sha256:" + "1" * 64,
        "dataPlaneBinaryDigest": "sha256:" + "4" * 64,
        "maxTtlSeconds": 5,
        "recipientAttestation": {"format": "test-only"},
    }
    for model, payload, label in (
        (
            app_module.CredentialLeaseReleaseQuotaClaim,
            credential_quota_claim,
            "credential lease quota claim",
        ),
        (
            app_module.CredentialLeaseDurablePolicyClaim,
            credential_durable_claim,
            "credential lease durable policy claim",
        ),
        (
            app_module.CredentialLeaseReleaseAuthorization,
            credential_release_authorization,
            "credential lease release authorization",
        ),
        (
            app_module.CredentialLeaseRequestAuthority,
            credential_request_authority,
            "credential lease request authority",
        ),
        (
            app_module.CredentialLeaseRequest,
            credential_request_v4,
            "credential lease request",
        ),
        (
            app_module.DataPlaneReleaseAuthorizationDurablePolicyReserve,
            release_v2_payload["durablePolicy"],
            "release durable reserve",
        ),
        (
            app_module.DataPlaneReleaseAuthorizationDurablePolicyTransition,
            unknown_v2_payload["durablePolicy"],
            "release durable transition",
        ),
        (
            DataPlaneReleaseAuthorizationReserve,
            release_v2_payload,
            "release reserve",
        ),
        (
            DataPlaneReleaseAuthorizationDispatch,
            dispatch_v2_payload,
            "release dispatch",
        ),
        (
            DataPlaneReleaseAuthorizationComplete,
            unknown_v2_payload,
            "release complete",
        ),
    ):
        expect_alias_only_wire(model, payload, label=label)

    calendar_quota_claim = {
        **credential_quota_claim,
        "windowKind": "utcDay",
        "windowSeconds": None,
    }
    app_module.CredentialLeaseReleaseQuotaClaim.model_validate(
        calendar_quota_claim
    )
    calendar_without_null = dict(calendar_quota_claim)
    calendar_without_null.pop("windowSeconds")
    try:
        app_module.CredentialLeaseReleaseQuotaClaim.model_validate(
            calendar_without_null
        )
    except ValidationError:
        pass
    else:
        raise AssertionError(
            "calendar credential quota accepted an omitted windowSeconds"
        )

    def nested_alias_variant(
        path: tuple[str, ...],
        snake_name: str,
        *,
        replace_alias: bool,
    ) -> dict:
        variant = json.loads(json.dumps(credential_request_v4))
        target = variant
        for part in path[:-1]:
            target = target[part]
            if isinstance(target, list):
                target = target[0]
        alias = path[-1]
        value = target[alias]
        if replace_alias:
            target.pop(alias)
            target[snake_name] = value
        else:
            target[snake_name] = conflicting_alias_value(value)
        return variant

    lease_wire_alias_cases = [
        (
            {**credential_request_v4, "api_version": "conflict"},
            "root alias conflict",
        )
    ]
    for path, snake_name, label in (
        (
            ("requestAuthority", "attemptId"),
            "attempt_id",
            "nested request authority",
        ),
        (
            ("releaseAuthorization", "bindingDigest"),
            "binding_digest",
            "nested release authorization",
        ),
        (
            ("releaseAuthorization", "quotaClaims", "counterKey"),
            "counter_key",
            "nested quota claim",
        ),
        (
            ("releaseAuthorization", "durablePolicy", "actorId"),
            "actor_id",
            "nested durable policy",
        ),
    ):
        lease_wire_alias_cases.extend(
            [
                (
                    nested_alias_variant(
                        path,
                        snake_name,
                        replace_alias=True,
                    ),
                    f"{label} snake-only",
                ),
                (
                    nested_alias_variant(
                        path,
                        snake_name,
                        replace_alias=False,
                    ),
                    f"{label} alias conflict",
                ),
            ]
        )
    with patch.object(
        app_module.db,
        "release_credential_request_authority_snapshot",
        side_effect=AssertionError(
            "invalid alias wire reached credential authority DB mutation"
        ),
    ) as authority_probe:
        for invalid_wire, label in lease_wire_alias_cases:
            try:
                asyncio.run(
                    bounded_lease_payload(
                        invalid_wire,
                        TOKENS[
                            "SERVERWARE_DATA_PLANE_CREDENTIAL_LEASE_TOKEN"
                        ],
                    )
                )
            except HTTPException as exc:
                if exc.status_code != 422:
                    raise AssertionError(
                        f"{label} returned HTTP {exc.status_code}: {exc.detail}"
                    ) from exc
            else:
                raise AssertionError(f"{label} did not return HTTP 422")
        if authority_probe.called:
            raise AssertionError(
                "alias-invalid credential lease reached authority storage"
            )

    release_wire_alias_cases = [
        (
            "/api/data-plane/release-authorizations/reserve",
            {
                **release_v2_payload,
                "api_version": (
                    "serverware.releaseAuthorizationReserve/v1"
                ),
            },
            "release reserve root alias conflict",
        ),
        (
            "/api/data-plane/release-authorizations/reserve",
            {
                **release_v2_payload,
                "durablePolicy": {
                    **release_v2_payload["durablePolicy"],
                    "actor_id": "spiffe://forged.example/decision-gate",
                },
            },
            "release durable reserve nested alias conflict",
        ),
        (
            "/api/data-plane/release-authorizations/reserve",
            {
                **release_v2_payload,
                "operationContext": {
                    "operation": "gmail.message.list",
                    "historyId": -1,
                },
            },
            "release reserve negative operation integer",
        ),
        (
            "/api/data-plane/release-authorizations/reserve",
            {
                **release_v2_payload,
                "operationContext": {
                    "operation": "gmail.message.list",
                    "confidence": 0.5,
                },
            },
            "release reserve floating operation value",
        ),
        (
            "/api/data-plane/release-authorizations/reserve",
            {
                **release_v2_payload,
                "operationContext": {
                    "operation": "gmail.message.list",
                    "historyId": 18_446_744_073_709_551_616,
                },
            },
            "release reserve oversized operation integer",
        ),
        (
            "/api/data-plane/release-authorizations/dispatch",
            {
                **dispatch_v2_payload,
                "binding_digest": "sha256:" + "0" * 64,
            },
            "release dispatch root alias conflict",
        ),
        (
            "/api/data-plane/release-authorizations/dispatch",
            {
                **dispatch_v2_payload,
                "durablePolicy": {
                    **dispatch_v2_payload["durablePolicy"],
                    "attempt_id": "sha256:" + "0" * 64,
                },
            },
            "release durable dispatch nested alias conflict",
        ),
        (
            "/api/data-plane/release-authorizations/complete",
            {
                **unknown_v2_payload,
                "attempt_id": "sha256:" + "0" * 64,
            },
            "release complete root alias conflict",
        ),
        (
            "/api/data-plane/release-authorizations/complete",
            {
                **unknown_v2_payload,
                "durablePolicy": {
                    **unknown_v2_payload["durablePolicy"],
                    "response_evidence_digest": "sha256:" + "0" * 64,
                },
            },
            "release durable completion nested alias conflict",
        ),
    ]
    mutation_failure = AssertionError(
        "alias-invalid release wire reached a DB mutation"
    )
    with (
        patch.object(
            app_module,
            "_release_authorization_maintenance",
            side_effect=mutation_failure,
        ) as maintenance_probe,
        patch.object(
            app_module.db,
            "reserve_release_authorization",
            side_effect=mutation_failure,
        ) as reserve_v1_probe,
        patch.object(
            app_module.db,
            "reserve_release_authorization_v2",
            side_effect=mutation_failure,
        ) as reserve_v2_probe,
        patch.object(
            app_module.db,
            "dispatch_release_authorization",
            side_effect=mutation_failure,
        ) as dispatch_v1_probe,
        patch.object(
            app_module.db,
            "dispatch_release_authorization_v2",
            side_effect=mutation_failure,
        ) as dispatch_v2_probe,
        patch.object(
            app_module.db,
            "complete_release_authorization",
            side_effect=mutation_failure,
        ) as complete_v1_probe,
        patch.object(
            app_module.db,
            "complete_release_authorization_v2",
            side_effect=mutation_failure,
        ) as complete_v2_probe,
    ):
        for path, invalid_wire, label in release_wire_alias_cases:
            status_code, response_body = asyncio.run(
                asgi_json_post(
                    path,
                    invalid_wire,
                    TOKENS[
                        "SERVERWARE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN"
                    ],
                )
            )
            if (
                status_code != 422
                or (
                    "alias" in label
                    and b"extra_forbidden" not in response_body
                )
            ):
                raise AssertionError(
                    f"{label} did not fail with pre-mutation HTTP 422: "
                    f"{status_code} {response_body!r}"
                )
        if any(
            probe.called
            for probe in (
                maintenance_probe,
                reserve_v1_probe,
                reserve_v2_probe,
                dispatch_v1_probe,
                dispatch_v2_probe,
                complete_v1_probe,
                complete_v2_probe,
            )
        ):
            raise AssertionError(
                "alias-invalid release wire reached release state mutation"
            )
    dispatch_uncertain_payload = json.loads(
        json.dumps(unknown_v2_payload)
    )
    dispatch_uncertain_payload["durablePolicy"].pop(
        "dispatchDeadlineAtEpochMs"
    )
    DataPlaneReleaseAuthorizationComplete.model_validate(
        dispatch_uncertain_payload
    )
    for model, invalid in (
        (
            DataPlaneReleaseAuthorizationDispatch,
            {
                **dispatch_v2_payload,
                "apiVersion": "serverware.releaseAuthorizationDispatch/v1",
            },
        ),
        (
            DataPlaneReleaseAuthorizationDispatch,
            {
                "apiVersion": "serverware.releaseAuthorizationDispatch/v1",
                "attemptId": "attempt:test",
                "bindingDigest": "sha256:" + "3" * 64,
                "durablePolicy": None,
            },
        ),
        (
            DataPlaneReleaseAuthorizationDispatch,
            {
                **dispatch_v2_payload,
                "durablePolicy": {
                    **dispatch_v2_payload["durablePolicy"],
                    "responseEvidence": [],
                },
            },
        ),
        (
            DataPlaneReleaseAuthorizationComplete,
            {
                **complete_v2_payload,
                "apiVersion": "serverware.releaseAuthorizationComplete/v1",
            },
        ),
        (
            DataPlaneReleaseAuthorizationComplete,
            {
                "apiVersion": "serverware.releaseAuthorizationComplete/v1",
                "attemptId": "attempt:test",
                "bindingDigest": "sha256:" + "3" * 64,
                "outcome": "unknown",
                "durablePolicy": None,
            },
        ),
        (
            DataPlaneReleaseAuthorizationComplete,
            {
                **complete_v2_payload,
                "durablePolicy": {
                    **complete_v2_payload["durablePolicy"],
                    "uncertainty": "charged_fail_closed",
                },
            },
        ),
        (
            DataPlaneReleaseAuthorizationDispatch,
            {
                **dispatch_v2_payload,
                "durablePolicy": {
                    **dispatch_v2_payload["durablePolicy"],
                    "dispatchDeadlineAtEpochMs": None,
                },
            },
        ),
        (
            DataPlaneReleaseAuthorizationComplete,
            {
                **unknown_v2_payload,
                "durablePolicy": {
                    **unknown_v2_payload["durablePolicy"],
                    "dispatchDeadlineAtEpochMs": None,
                },
            },
        ),
    ):
        try:
            model.model_validate(invalid)
        except ValidationError:
            pass
        else:
            raise AssertionError(
                f"release v2 transition accepted a mixed or extra body: {invalid}"
            )
    expect_model_rejects_actor(DataPlaneAuditEvent, audit_payload)
    expect_model_rejects_actor(DataPlaneRateLimitConsume, rate_payload)
    expect_model_rejects_actor(DataPlaneReleaseAuthorizationReserve, release_payload)
    for required_field in (
        "credentialRef",
        "operationDigest",
        "operationContext",
        "canonicalRequest",
    ):
        missing_required = json.loads(json.dumps(release_payload))
        missing_required.pop(required_field)
        try:
            DataPlaneReleaseAuthorizationReserve.model_validate(missing_required)
        except ValidationError as exc:
            if not any(
                error.get("type") == "missing"
                and tuple(error.get("loc") or ()) == (required_field,)
                for error in exc.errors()
            ):
                raise AssertionError(
                    f"release reserve rejected missing {required_field} for the wrong reason: {exc}"
                ) from exc
        else:
            raise AssertionError(
                f"release reserve accepted missing mandatory {required_field}"
            )
    for forbidden in (
        "counterKey",
        "constraintId",
        "max",
        "windowSeconds",
        "calendarWindow",
        "windowStartEpochMs",
        "windowEndEpochMs",
    ):
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

    for invalid_event_id in (
        "sha256:" + "A" * 64,
        "sha256:" + "a" * 63,
        "sha512:" + "a" * 64,
    ):
        try:
            DataPlaneAuditEvent.model_validate(
                {**audit_payload, "eventId": invalid_event_id}
            )
        except ValidationError:
            pass
        else:
            raise AssertionError(
                f"audit model accepted invalid event ID {invalid_event_id!r}"
            )
    try:
        DataPlaneAuditEvent.model_validate(
            {
                "eventType": audit_payload["eventType"],
                "event": audit_payload["event"],
            }
        )
    except ValidationError:
        pass
    else:
        raise AssertionError("audit model accepted a missing production event ID")

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
    exact_body = json.dumps(
        {"events": [audit_payload]},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    body_sent = False

    async def receive_audit_body():
        nonlocal body_sent
        if body_sent:
            return {"type": "http.disconnect"}
        body_sent = True
        return {"type": "http.request", "body": exact_body, "more_body": False}

    audit_request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/data-plane/audit",
            "query_string": b"",
            "headers": [],
        },
        receive_audit_body,
    )
    signed_ack = asyncio.run(
        app_module.data_plane_audit(
            audit_request,
            TOKENS["SERVERWARE_DATA_PLANE_AUDIT_TOKEN"],
        )
    )
    expected_digest = "sha256:" + hashlib.sha256(exact_body).hexdigest()
    if signed_ack != {
        "apiVersion": "serverware.dataPlaneAuditAck/v1",
        "ok": True,
        "accepted": 1,
        "batchDigest": expected_digest,
        "instanceId": INSTANCE_ID,
    }:
        raise AssertionError(f"audit acknowledgement did not bind request bytes: {signed_ack}")
    replayed = data_plane_audit(
        batch, TOKENS["SERVERWARE_DATA_PLANE_AUDIT_TOKEN"]
    )
    if replayed != {"ok": True, "accepted": 1}:
        raise AssertionError(f"lost-ACK audit replay failed: {replayed}")
    matching = [
        item
        for item in db.list_audit_events()
        if item["event_type"] == audit_payload["eventType"]
    ]
    if len(matching) != 1:
        raise AssertionError(
            f"lost-ACK retry created duplicate immutable rows: {matching}"
        )
    stored = matching[0]
    if stored.get("actor_type") != "data-plane" or stored.get("actor_id") != INSTANCE_ID:
        raise AssertionError(f"audit actor was not derived from authenticated configuration: {stored}")
    expected_row_id = db._data_plane_audit_row_id(
        INSTANCE_ID, audit_payload["eventId"]
    )
    if stored.get("id") != expected_row_id:
        raise AssertionError(
            f"audit row ID was not instance/event derived: {stored.get('id')}"
        )

    duplicate_id_batch = DataPlaneAuditBatch.model_validate(
        {
            "events": [
                audit_event(2, "data_plane.test.duplicate.first", {"marker": 1}),
                audit_event(2, "data_plane.test.duplicate.second", {"marker": 2}),
            ]
        }
    )
    expect_http_error(
        lambda: data_plane_audit(
            duplicate_id_batch, TOKENS["SERVERWARE_DATA_PLANE_AUDIT_TOKEN"]
        ),
        400,
    )

    replay_seed = DataPlaneAuditBatch.model_validate(
        {
            "events": [
                audit_event(10, "data_plane.test.retry.first", {"marker": "first"}),
                audit_event(11, "data_plane.test.retry.second", {"marker": "second"}),
            ]
        }
    )
    data_plane_audit(replay_seed, TOKENS["SERVERWARE_DATA_PLANE_AUDIT_TOKEN"])
    partial_replay = DataPlaneAuditBatch.model_validate(
        {
            "events": [
                audit_event(10, "data_plane.test.retry.first", {"marker": "first"}),
                audit_event(12, "data_plane.test.retry.third", {"marker": "third"}),
            ]
        }
    )
    expect_http_error(
        lambda: data_plane_audit(
            partial_replay, TOKENS["SERVERWARE_DATA_PLANE_AUDIT_TOKEN"]
        ),
        409,
    )
    if any(
        item["event_type"] == "data_plane.test.retry.third"
        for item in db.list_audit_events()
    ):
        raise AssertionError("partial audit replay appended its new suffix")

    mismatched_replay = DataPlaneAuditBatch.model_validate(
        {
            "events": [
                audit_event(
                    10,
                    "data_plane.test.retry.first",
                    {"marker": "changed"},
                )
            ]
        }
    )
    expect_http_error(
        lambda: data_plane_audit(
            mismatched_replay, TOKENS["SERVERWARE_DATA_PLANE_AUDIT_TOKEN"]
        ),
        409,
    )
    secret_batch = DataPlaneAuditBatch.model_validate(
        {
            "events": [
                {
                    "eventId": audit_event_id(20),
                    "eventType": "data_plane.test.secret_rejection",
                    "event": {
                        "nested": {
                            "accessToken": "must-not-enter-the-audit-chain"
                        }
                    },
                }
            ]
        }
    )
    secret_error = expect_http_error(
        lambda: data_plane_audit(
            secret_batch, TOKENS["SERVERWARE_DATA_PLANE_AUDIT_TOKEN"]
        ),
        400,
    )
    if "nested.accessToken" not in secret_error:
        raise AssertionError(f"audit secret rejection omitted its safe field path: {secret_error}")
    with patch.object(app_module, "RELEASE_CHANNEL", "production"):
        expect_http_error(
            lambda: data_plane_audit(
                batch, TOKENS["SERVERWARE_DATA_PLANE_AUDIT_TOKEN"]
            ),
            400,
        )
        production_batch = DataPlaneAuditBatch.model_validate(
            {
                "events": [
                    {
                        "eventId": audit_event_id(21),
                        "eventType": "data_plane.policy.reloaded",
                        "event": {
                            "component": "serverware-decision-gate-rs",
                            "policy_hash": "sha256:" + "f" * 64,
                        },
                    }
                ]
            }
        )
        production_accepted = data_plane_audit(
            production_batch, TOKENS["SERVERWARE_DATA_PLANE_AUDIT_TOKEN"]
        )
    if production_accepted != {"ok": True, "accepted": 1}:
        raise AssertionError(
            f"production audit allowlist rejected a measured event: {production_accepted}"
        )

    route = SimpleNamespace(
        id="route:test",
        principals=("agent:test",),
        scheme="https",
        host="upstream.invalid",
        port=443,
        methods=frozenset({"POST"}),
        match_path=lambda path: {} if path == "/resource" else None,
        credential_ref="credential:test",
        adapter_config={"request": {"discardHeaders": []}},
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
                "calendarWindow": "utcDay",
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
        hash=release_payload["policyHash"],
        principals={
            "agent:test": SimpleNamespace(required_headers={}),
        },
        credentials={
            "credential:test": SimpleNamespace(injection={"type": "bearer"}),
        },
        routes=(route,),
    )
    durable_route = SimpleNamespace(
        **{
            **vars(route),
            "adapter_type": "generic.rest",
            "constraints": (
                {
                    "id": "weighted:test",
                    "type": "weightedBudget",
                    "store": "shared",
                    "windowSeconds": 60,
                    "windowSemantics": "sliding",
                    "measure": "weightedCanonicalInteger",
                    "reservationMode": "atomicReserveCommitRelease",
                    "onOverflow": "deny",
                    "max": 100,
                    "key": {
                        "scope": [
                            "principal",
                            "route",
                            "credential",
                            "credentialVersion",
                            "operation",
                        ]
                    },
                    "weight": {
                        "source": "requestValue",
                        "field": "units",
                        "representation": "canonicalNonNegativeInteger",
                        "unit": "request-unit",
                        "minimumPerOperation": 1,
                        "maximumPerOperation": 10,
                    },
                },
            ),
            "jit": {"required": False},
        }
    )
    durable_snapshot = SimpleNamespace(
        **{
            **vars(snapshot),
            "routes": (durable_route,),
        }
    )
    forged_actor_payload = json.loads(json.dumps(release_v2_payload))
    forged_actor_payload["durablePolicy"][
        "actorId"
    ] = "spiffe://forged.example/workload"
    with (
        patch.object(
            app_module, "get_policy_snapshot", return_value=durable_snapshot
        ),
        patch.object(
            app_module.db,
            "credential_generation_snapshot",
            return_value=nullcontext({"credential_version": 1}),
        ),
        patch.object(
            app_module.db,
            "reserve_release_authorization_v2",
            side_effect=AssertionError(
                "forged actor reached durable reservation mutation"
            ),
            create=True,
        ),
        patch.object(app_module, "_release_authorization_maintenance"),
    ):
        expect_http_error(
            lambda: data_plane_release_authorization_reserve(
                DataPlaneReleaseAuthorizationReserve.model_validate(
                    forged_actor_payload
                ),
                TOKENS[
                    "SERVERWARE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN"
                ],
            ),
            403,
        )
        expect_http_error(
            lambda: data_plane_release_authorization_reserve(
                DataPlaneReleaseAuthorizationReserve.model_validate(
                    release_payload
                ),
                TOKENS[
                    "SERVERWARE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN"
                ],
            ),
            409,
        )
    legitimate_v2_payload = json.loads(
        json.dumps(release_v2_payload)
    )
    legitimate_v2_payload["operationContext"] = {
        "operation": "test.write",
        "units": "7",
    }
    legitimate_v2_payload["canonicalRequest"]["operation"] = dict(
        legitimate_v2_payload["operationContext"]
    )
    legitimate_v2_payload["requestDigest"] = digest(
        legitimate_v2_payload["canonicalRequest"]
    )
    legitimate_v2_payload["operationDigest"] = digest(
        {
            key: legitimate_v2_payload["canonicalRequest"][key]
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
    )
    legitimate_claims = app_module.shared_durable_budget_claims(
        durable_route,
        principal_id=legitimate_v2_payload["principalId"],
        credential_ref=legitimate_v2_payload["credentialRef"],
        credential_version=legitimate_v2_payload[
            "credentialVersion"
        ],
        policy_hash=legitimate_v2_payload["policyHash"],
        operation_fields=legitimate_v2_payload[
            "operationContext"
        ],
    )
    legitimate_v2_payload["durablePolicy"] = {
        "actorId": INSTANCE_ID,
        "claimDigest": digest(legitimate_claims),
        "claims": legitimate_claims,
    }
    captured_v2: dict[str, object] = {}

    def reserve_release_v2(**kwargs):
        captured_v2.update(kwargs)
        durable = kwargs["durable_policy_binding"]
        return {
            "authorized": True,
            "state": "reserved",
            "reason": "reserved",
            "attempt_id": kwargs["attempt_id"],
            "binding_digest": "sha256:" + "9" * 64,
            "idempotent_replay": False,
            "grant_id": None,
            "approval_request_id": None,
            "reservation_expires_at_epoch_ms": 4_102_444_800_000,
            "dispatch_started_at_epoch_ms": None,
            "dispatch_expires_at_epoch_ms": None,
            "completion_outcome": None,
            "retry_after_seconds": 0,
            "quotas": [],
            "release_authorization_store_backend": "sqlite",
            "release_authorization_store_ha": False,
            "durable_policy": {
                "state": "reserved",
                "attempt_id": kwargs["attempt_id"],
                "claim_digest": durable["claimDigest"],
                "reservation_id": "sha256:" + "a" * 64,
                "actor_id": kwargs["actor_id"],
                "reservation_deadline_at_epoch_ms": (
                    4_102_444_800_000
                ),
                "dispatch_deadline_at_epoch_ms": None,
                "response_evidence_digest": None,
                "failure_reason": None,
                "response_body_sha256": None,
                "uncertainty": None,
            },
        }

    with (
        patch.object(
            app_module, "get_policy_snapshot", return_value=durable_snapshot
        ),
        patch.object(
            app_module.db,
            "credential_generation_snapshot",
            return_value=nullcontext({"credential_version": 1}),
        ),
        patch.object(
            app_module.db,
            "reserve_release_authorization_v2",
            side_effect=reserve_release_v2,
        ),
        patch.object(app_module, "_release_authorization_maintenance"),
    ):
        legitimate_response = (
            data_plane_release_authorization_reserve(
                DataPlaneReleaseAuthorizationReserve.model_validate(
                    legitimate_v2_payload
                ),
                TOKENS[
                    "SERVERWARE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN"
                ],
            )
        )
    if (
        legitimate_response["apiVersion"]
        != "serverware.releaseAuthorization/v2"
        or legitimate_response["durablePolicy"]["actorId"]
        != INSTANCE_ID
        or captured_v2.get("actor_id") != INSTANCE_ID
        or captured_v2.get("durable_policy_binding")
        != legitimate_v2_payload["durablePolicy"]
    ):
        raise AssertionError(
            "release v2 endpoint did not preserve its exact actor and durable binding"
        )

    forged_dispatch = json.loads(json.dumps(dispatch_v2_payload))
    forged_dispatch["durablePolicy"]["actorId"] = (
        "spiffe://forged.example/workload"
    )
    forged_completion = json.loads(json.dumps(unknown_v2_payload))
    forged_completion["durablePolicy"]["actorId"] = (
        "spiffe://forged.example/workload"
    )
    with (
        patch.object(
            app_module.db,
            "dispatch_release_authorization_v2",
            side_effect=AssertionError(
                "forged dispatch actor reached database mutation"
            ),
        ),
        patch.object(
            app_module.db,
            "complete_release_authorization_v2",
            side_effect=AssertionError(
                "forged completion actor reached database mutation"
            ),
        ),
    ):
        expect_http_error(
            lambda: data_plane_release_authorization_dispatch(
                DataPlaneReleaseAuthorizationDispatch.model_validate(
                    forged_dispatch
                ),
                TOKENS[
                    "SERVERWARE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN"
                ],
            ),
            403,
        )
        expect_http_error(
            lambda: data_plane_release_authorization_complete(
                DataPlaneReleaseAuthorizationComplete.model_validate(
                    forged_completion
                ),
                TOKENS[
                    "SERVERWARE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN"
                ],
            ),
            403,
        )
    captured_dispatch_v2: dict[str, object] = {}
    captured_complete_v2: dict[str, object] = {}

    def dispatch_release_v2(**kwargs):
        captured_dispatch_v2.update(kwargs)
        transition = kwargs["durable_policy_transition"]
        return {
            "authorized": True,
            "state": "dispatching",
            "reason": "dispatching",
            "attempt_id": kwargs["attempt_id"],
            "binding_digest": kwargs["binding_digest"],
            "idempotent_replay": False,
            "grant_id": None,
            "approval_request_id": None,
            "reservation_expires_at_epoch_ms": (
                4_102_444_800_000
            ),
            "dispatch_started_at_epoch_ms": 4_102_444_700_000,
            "dispatch_expires_at_epoch_ms": transition[
                "dispatchDeadlineAtEpochMs"
            ],
            "completion_outcome": None,
            "retry_after_seconds": 0,
            "quotas": [],
            "release_authorization_store_backend": "sqlite",
            "release_authorization_store_ha": False,
            "durable_policy": {
                "state": "dispatched",
                "attempt_id": kwargs["attempt_id"],
                "claim_digest": transition["claimDigest"],
                "reservation_id": transition["reservationId"],
                "actor_id": kwargs["actor_id"],
                "reservation_deadline_at_epoch_ms": (
                    4_102_444_800_000
                ),
                "dispatch_deadline_at_epoch_ms": transition[
                    "dispatchDeadlineAtEpochMs"
                ],
                "response_evidence_digest": None,
                "failure_reason": None,
                "response_body_sha256": None,
                "uncertainty": None,
            },
        }

    def complete_release_v2(**kwargs):
        captured_complete_v2.update(kwargs)
        transition = kwargs["durable_policy_transition"]
        return {
            "authorized": True,
            "state": "committed_indeterminate",
            "reason": "forward_outcome_indeterminate",
            "attempt_id": kwargs["attempt_id"],
            "binding_digest": kwargs["binding_digest"],
            "idempotent_replay": False,
            "grant_id": None,
            "approval_request_id": None,
            "reservation_expires_at_epoch_ms": (
                4_102_444_800_000
            ),
            "dispatch_started_at_epoch_ms": 4_102_444_700_000,
            "dispatch_expires_at_epoch_ms": 4_102_444_730_000,
            "completion_outcome": "unknown",
            "retry_after_seconds": 0,
            "quotas": [],
            "release_authorization_store_backend": "sqlite",
            "release_authorization_store_ha": False,
            "durable_policy": {
                "state": "indeterminate",
                "attempt_id": kwargs["attempt_id"],
                "claim_digest": transition["claimDigest"],
                "reservation_id": transition["reservationId"],
                "actor_id": kwargs["actor_id"],
                "reservation_deadline_at_epoch_ms": (
                    4_102_444_800_000
                ),
                "dispatch_deadline_at_epoch_ms": None,
                "response_evidence_digest": transition[
                    "responseEvidenceDigest"
                ],
                "failure_reason": transition["failureReason"],
                "response_body_sha256": transition[
                    "responseBodySha256"
                ],
                "uncertainty": transition["uncertainty"],
            },
        }

    with (
        patch.object(
            app_module.db,
            "dispatch_release_authorization_v2",
            side_effect=dispatch_release_v2,
        ),
        patch.object(
            app_module.db,
            "complete_release_authorization_v2",
            side_effect=complete_release_v2,
        ),
        patch.object(app_module, "_release_authorization_maintenance"),
    ):
        dispatch_response = data_plane_release_authorization_dispatch(
            DataPlaneReleaseAuthorizationDispatch.model_validate(
                dispatch_v2_payload
            ),
            TOKENS[
                "SERVERWARE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN"
            ],
        )
        uncertain_response = data_plane_release_authorization_complete(
            DataPlaneReleaseAuthorizationComplete.model_validate(
                dispatch_uncertain_payload
            ),
            TOKENS[
                "SERVERWARE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN"
            ],
        )
    if (
        dispatch_response["durablePolicy"]["state"] != "dispatched"
        or uncertain_response["durablePolicy"][
            "dispatchDeadlineAtEpochMs"
        ]
        is not None
        or captured_dispatch_v2.get("durable_policy_transition")
        != dispatch_v2_payload["durablePolicy"]
        or captured_complete_v2.get("durable_policy_transition")
        != dispatch_uncertain_payload["durablePolicy"]
    ):
        raise AssertionError(
            "release v2 transition endpoint changed its exact Rust-shaped binding"
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
        patch.object(
            app_module.db,
            "credential_generation_snapshot",
            return_value=nullcontext({"credential_version": 1}),
        ),
        patch.object(app_module.db, "reserve_release_authorization", side_effect=reserve_release),
        patch.object(app_module, "_release_authorization_maintenance"),
    ):
        release_response = data_plane_release_authorization_reserve(
            DataPlaneReleaseAuthorizationReserve.model_validate(release_payload),
            TOKENS["SERVERWARE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN"],
        )
    derived_quotas = captured.get("shared_quotas")
    if not isinstance(derived_quotas, list) or {
        (
            item.get("constraint_id"),
            item.get("max_count"),
            item.get("window_kind"),
            item.get("window_seconds"),
        )
        for item in derived_quotas
    } != {
        ("quota:principal", 3, "fixed", 60),
        ("quota:account", 1, "utcDay", None),
    }:
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

    invalid_wire_shapes = []
    v1_with_discard_field = json.loads(json.dumps(release_payload))
    v1_with_discard_field["canonicalRequest"]["request"]["discard_headers"] = []
    invalid_wire_shapes.append(v1_with_discard_field)
    v2_without_discard_field = json.loads(json.dumps(release_payload))
    v2_without_discard_field["canonicalRequest"]["v"] = 2
    invalid_wire_shapes.append(v2_without_discard_field)
    unknown_top_level_field = json.loads(json.dumps(release_payload))
    unknown_top_level_field["canonicalRequest"]["discard_headers"] = []
    invalid_wire_shapes.append(unknown_top_level_field)
    noncanonical_header_name = json.loads(json.dumps(release_payload))
    noncanonical_headers = noncanonical_header_name["canonicalRequest"]["request"][
        "headers"
    ]
    noncanonical_headers["Host"] = noncanonical_headers.pop("host")
    invalid_wire_shapes.append(noncanonical_header_name)
    mixed_v2_request_shape = json.loads(json.dumps(release_payload))
    mixed_v2_request_shape["canonicalRequest"]["v"] = 2
    mixed_v2_request_shape["canonicalRequest"]["request"]["discard_headers"] = [
        "x-client-retry"
    ]
    mixed_v2_request_shape["canonicalRequest"]["request"]["discardHeaders"] = [
        "x-client-retry"
    ]
    invalid_wire_shapes.append(mixed_v2_request_shape)
    for invalid_discard_headers in (
        [],
        [1],
        ["z-retry", "a-retry"],
        ["x-retry", "x-retry"],
    ):
        invalid_release_payload = json.loads(json.dumps(release_payload))
        invalid_release_payload["canonicalRequest"]["v"] = 2
        invalid_request = invalid_release_payload["canonicalRequest"]["request"]
        invalid_request["discard_headers"] = invalid_discard_headers
        invalid_wire_shapes.append(invalid_release_payload)
    for invalid_release_payload in invalid_wire_shapes:
        invalid_request = invalid_release_payload["canonicalRequest"]["request"]
        invalid_release_payload["requestDigest"] = digest(
            invalid_release_payload["canonicalRequest"]
        )
        invalid_release_payload["operationDigest"] = digest(
            {
                "principal": invalid_release_payload["canonicalRequest"]["principal"],
                "route_id": invalid_release_payload["canonicalRequest"]["route_id"],
                "credential_ref": invalid_release_payload["canonicalRequest"]["credential_ref"],
                "credential_version": invalid_release_payload["canonicalRequest"]["credential_version"],
                "policy_hash": invalid_release_payload["canonicalRequest"]["policy_hash"],
                "request": invalid_request,
                "operation": invalid_release_payload["canonicalRequest"]["operation"],
            }
        )
        with (
            patch.object(app_module, "get_policy_snapshot", return_value=snapshot),
            patch.object(
                app_module.db,
                "credential_generation_snapshot",
                return_value=nullcontext({"credential_version": 1}),
            ),
            patch.object(
                app_module,
                "_release_authorization_maintenance",
                side_effect=AssertionError(
                    "invalid canonical request reached reservation maintenance"
                ),
            ),
            patch.object(
                app_module.db,
                "reserve_release_authorization",
                side_effect=AssertionError(
                    "invalid canonical request reached reservation mutation"
                ),
            ),
        ):
            expect_http_error(
                lambda payload=invalid_release_payload: data_plane_release_authorization_reserve(
                    DataPlaneReleaseAuthorizationReserve.model_validate(payload),
                    TOKENS["SERVERWARE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN"],
                ),
                409,
            )

    retained_discard_payload = json.loads(json.dumps(release_payload))
    retained_discard_payload["canonicalRequest"]["v"] = 2
    retained_discard_request = retained_discard_payload["canonicalRequest"]["request"]
    retained_discard_request["discard_headers"] = ["x-client-retry"]
    retained_discard_request["headers"]["x-client-retry"] = "must-not-be-bound"
    retained_discard_payload["requestDigest"] = digest(
        retained_discard_payload["canonicalRequest"]
    )
    retained_discard_payload["operationDigest"] = digest(
        {
            "principal": retained_discard_payload["canonicalRequest"]["principal"],
            "route_id": retained_discard_payload["canonicalRequest"]["route_id"],
            "credential_ref": retained_discard_payload["canonicalRequest"]["credential_ref"],
            "credential_version": retained_discard_payload["canonicalRequest"]["credential_version"],
            "policy_hash": retained_discard_payload["canonicalRequest"]["policy_hash"],
            "request": retained_discard_request,
            "operation": retained_discard_payload["canonicalRequest"]["operation"],
        }
    )
    retained_route = SimpleNamespace(
        **{
            **vars(route),
            "adapter_config": {
                "request": {"discardHeaders": ["x-client-retry"]}
            },
        }
    )
    retained_snapshot = SimpleNamespace(
        hash=release_payload["policyHash"],
        principals={
            "agent:test": SimpleNamespace(required_headers={}),
        },
        credentials={
            "credential:test": SimpleNamespace(injection={"type": "bearer"}),
        },
        routes=(retained_route,),
    )
    valid_v2_payload = json.loads(json.dumps(retained_discard_payload))
    valid_v2_payload["canonicalRequest"]["request"]["headers"].pop(
        "x-client-retry", None
    )
    valid_v2_payload["requestDigest"] = digest(valid_v2_payload["canonicalRequest"])
    valid_v2_payload["operationDigest"] = digest(
        {
            "principal": valid_v2_payload["canonicalRequest"]["principal"],
            "route_id": valid_v2_payload["canonicalRequest"]["route_id"],
            "credential_ref": valid_v2_payload["canonicalRequest"]["credential_ref"],
            "credential_version": valid_v2_payload["canonicalRequest"][
                "credential_version"
            ],
            "policy_hash": valid_v2_payload["canonicalRequest"]["policy_hash"],
            "request": valid_v2_payload["canonicalRequest"]["request"],
            "operation": valid_v2_payload["canonicalRequest"]["operation"],
        }
    )
    with (
        patch.object(
            app_module,
            "get_policy_snapshot",
            return_value=retained_snapshot,
        ),
        patch.object(
            app_module.db,
            "credential_generation_snapshot",
            return_value=nullcontext({"credential_version": 1}),
        ),
        patch.object(
            app_module.db,
            "reserve_release_authorization",
            side_effect=reserve_release,
        ),
        patch.object(app_module, "_release_authorization_maintenance"),
    ):
        data_plane_release_authorization_reserve(
            DataPlaneReleaseAuthorizationReserve.model_validate(valid_v2_payload),
            TOKENS["SERVERWARE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN"],
        )

    with (
        patch.object(
            app_module,
            "get_policy_snapshot",
            return_value=retained_snapshot,
        ),
        patch.object(
            app_module.db,
            "credential_generation_snapshot",
            return_value=nullcontext({"credential_version": 1}),
        ),
        patch.object(app_module, "_release_authorization_maintenance"),
    ):
        expect_http_error(
            lambda: data_plane_release_authorization_reserve(
                DataPlaneReleaseAuthorizationReserve.model_validate(
                    release_payload
                ),
                TOKENS["SERVERWARE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN"],
            ),
            409,
        )

    for retained_name in (
        "x-client-retry",
        "X-Client-Retry",
        "x_client_retry",
    ):
        alias_payload = json.loads(json.dumps(retained_discard_payload))
        alias_request = alias_payload["canonicalRequest"]["request"]
        alias_request["headers"].pop("x-client-retry")
        alias_request["headers"][retained_name] = "must-not-be-bound"
        alias_payload["requestDigest"] = digest(alias_payload["canonicalRequest"])
        alias_payload["operationDigest"] = digest(
            {
                "principal": alias_payload["canonicalRequest"]["principal"],
                "route_id": alias_payload["canonicalRequest"]["route_id"],
                "credential_ref": alias_payload["canonicalRequest"]["credential_ref"],
                "credential_version": alias_payload["canonicalRequest"]["credential_version"],
                "policy_hash": alias_payload["canonicalRequest"]["policy_hash"],
                "request": alias_request,
                "operation": alias_payload["canonicalRequest"]["operation"],
            }
        )
        with (
            patch.object(
                app_module,
                "get_policy_snapshot",
                return_value=retained_snapshot,
            ),
            patch.object(
                app_module.db,
                "credential_generation_snapshot",
                return_value=nullcontext({"credential_version": 1}),
            ),
            patch.object(app_module, "_release_authorization_maintenance"),
        ):
            expect_http_error(
                lambda payload=alias_payload: data_plane_release_authorization_reserve(
                    DataPlaneReleaseAuthorizationReserve.model_validate(payload),
                    TOKENS["SERVERWARE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN"],
                ),
                409,
            )

    corrupt_policy_payload = json.loads(json.dumps(release_payload))
    corrupt_policy_payload["canonicalRequest"]["v"] = 2
    corrupt_policy_request = corrupt_policy_payload["canonicalRequest"]["request"]
    corrupt_policy_request["discard_headers"] = ["authorization"]
    corrupt_policy_payload["requestDigest"] = digest(
        corrupt_policy_payload["canonicalRequest"]
    )
    corrupt_policy_payload["operationDigest"] = digest(
        {
            "principal": corrupt_policy_payload["canonicalRequest"]["principal"],
            "route_id": corrupt_policy_payload["canonicalRequest"]["route_id"],
            "credential_ref": corrupt_policy_payload["canonicalRequest"]["credential_ref"],
            "credential_version": corrupt_policy_payload["canonicalRequest"]["credential_version"],
            "policy_hash": corrupt_policy_payload["canonicalRequest"]["policy_hash"],
            "request": corrupt_policy_request,
            "operation": corrupt_policy_payload["canonicalRequest"]["operation"],
        }
    )
    corrupt_policy_route = SimpleNamespace(
        **{
            **vars(route),
            "adapter_config": {
                "request": {"discardHeaders": ["authorization"]}
            },
        }
    )
    corrupt_policy_snapshot = SimpleNamespace(
        hash=release_payload["policyHash"],
        principals={
            "agent:test": SimpleNamespace(required_headers={}),
        },
        credentials={
            "credential:test": SimpleNamespace(injection={"type": "bearer"}),
        },
        routes=(corrupt_policy_route,),
    )
    with (
        patch.object(
            app_module,
            "get_policy_snapshot",
            return_value=corrupt_policy_snapshot,
        ),
        patch.object(
            app_module.db,
            "credential_generation_snapshot",
            return_value=nullcontext({"credential_version": 1}),
        ),
        patch.object(app_module, "_release_authorization_maintenance"),
    ):
        expect_http_error(
            lambda: data_plane_release_authorization_reserve(
                DataPlaneReleaseAuthorizationReserve.model_validate(
                    corrupt_policy_payload
                ),
                TOKENS["SERVERWARE_DATA_PLANE_RELEASE_AUTHORIZATION_TOKEN"],
            ),
            409,
        )

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
    if sys.argv[1:] not in ([], ["--audit-retry-only"]):
        raise SystemExit("usage: test_internal_service_auth.py [--audit-retry-only]")
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["SERVERWARE_DATA_DIR"] = tmp
        os.environ["SERVERWARE_RELEASE_CHANNEL"] = "test"
        os.environ["SERVERWARE_PROCESS_MODE"] = "serverware-control-plane"
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
            _ingest_data_plane_audit as data_plane_audit,
            data_plane_grant_consume,
            data_plane_rate_limit_consume,
            data_plane_release_authorization_complete,
            data_plane_release_authorization_dispatch,
            data_plane_release_authorization_reserve,
        )

        if sys.argv[1:] == ["--audit-retry-only"]:
            initialize_audit_retry_fixture()
            audit_retry_regressions()
        else:
            main()
