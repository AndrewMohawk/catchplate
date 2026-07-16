#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

tmpdir = tempfile.TemporaryDirectory()
os.environ["SERVERWARE_DATA_DIR"] = tmpdir.name
os.environ["SERVERWARE_DATA_PLANE_INSTANCE_ID"] = "spiffe://test.serverware/decision-gate/rate-limit"
os.environ["SERVERWARE_DATA_PLANE_RATE_LIMIT_CONSUME_TOKEN"] = "test-rate-limit-token"
os.environ["SERVERWARE_METADATA_STORE_BACKEND"] = "sqlite"
os.environ["SERVERWARE_AUDIT_STORE_BACKEND"] = "sqlite"
os.environ["SERVERWARE_GRANT_STORE_BACKEND"] = "sqlite"
os.environ["SERVERWARE_KEY_RELEASE_REQUIRED"] = "0"
for name in (
    "SERVERWARE_METADATA_STORE_POSTGRES_DSN",
    "SERVERWARE_AUDIT_STORE_POSTGRES_DSN",
    "SERVERWARE_GRANT_STORE_POSTGRES_DSN",
):
    os.environ.pop(name, None)

legacy_db_path = Path(tmpdir.name) / "serverware.sqlite3"
with sqlite3.connect(legacy_db_path) as legacy_conn:
    legacy_conn.execute(
        """
        CREATE TABLE rate_limit_counters (
            counter_key TEXT PRIMARY KEY,
            principal_id TEXT,
            route_id TEXT,
            credential_id TEXT,
            credential_version INTEGER,
            policy_hash TEXT,
            constraint_id TEXT,
            operation TEXT,
            encrypted_operation TEXT,
            operation_storage_version BIGINT,
            window_start_epoch_ms BIGINT NOT NULL,
            window_seconds INTEGER NOT NULL,
            max_count INTEGER NOT NULL,
            count INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    legacy_conn.execute(
        "INSERT INTO rate_limit_counters VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "sha256:" + "f" * 64,
            "agent:legacy",
            "route.legacy",
            "",
            0,
            "sha256:" + "0" * 64,
            "legacy-fixed",
            None,
            None,
            None,
            10_000,
            60,
            2,
            1,
            "1970-01-01T00:00:10+00:00",
            "1970-01-01T00:00:10+00:00",
        ),
    )
    legacy_conn.executescript(
        """
        CREATE TABLE release_authorization_attempts (
            attempt_id TEXT PRIMARY KEY,
            binding_digest TEXT NOT NULL,
            binding_json TEXT NOT NULL,
            flow_id TEXT NOT NULL,
            state TEXT NOT NULL,
            principal_id TEXT NOT NULL,
            route_id TEXT NOT NULL,
            credential_id TEXT NOT NULL,
            credential_version BIGINT NOT NULL,
            policy_hash TEXT NOT NULL,
            request_digest TEXT NOT NULL,
            operation_digest TEXT,
            operation_context_json TEXT NOT NULL,
            grant_id TEXT,
            approval_request_id TEXT,
            reservation_expires_at_epoch_ms BIGINT NOT NULL,
            dispatch_started_at_epoch_ms BIGINT,
            dispatch_expires_at_epoch_ms BIGINT,
            completion_outcome TEXT,
            completed_at_epoch_ms BIGINT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE release_authorization_quota_reservations (
            attempt_id TEXT NOT NULL,
            counter_key TEXT NOT NULL,
            constraint_id TEXT NOT NULL,
            operation TEXT,
            encrypted_operation TEXT,
            operation_storage_version BIGINT,
            window_start_epoch_ms BIGINT NOT NULL,
            window_seconds INTEGER NOT NULL,
            max_count INTEGER NOT NULL,
            count_after INTEGER NOT NULL,
            reservation_state TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (attempt_id, counter_key)
        );
        """
    )
    legacy_conn.execute(
        """
        INSERT INTO release_authorization_attempts (
            attempt_id, binding_digest, binding_json, flow_id, state,
            principal_id, route_id, credential_id, credential_version,
            policy_hash, request_digest, operation_context_json,
            reservation_expires_at_epoch_ms, created_at, updated_at
        ) VALUES (?, ?, ?, ?, 'reserved', ?, ?, '', 0, ?, ?, '{}', ?, ?, ?)
        """,
        (
            "attempt:legacy-fixed",
            "sha256:" + "1" * 64,
            "{}",
            "flow:legacy-fixed",
            "agent:legacy",
            "route.legacy",
            "sha256:" + "0" * 64,
            "sha256:" + "2" * 64,
            100_000,
            "1970-01-01T00:00:10+00:00",
            "1970-01-01T00:00:10+00:00",
        ),
    )
    legacy_conn.execute(
        """
        INSERT INTO release_authorization_quota_reservations (
            attempt_id, counter_key, constraint_id, window_start_epoch_ms,
            window_seconds, max_count, count_after, reservation_state,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'reserved', ?, ?)
        """,
        (
            "attempt:legacy-fixed",
            "sha256:" + "f" * 64,
            "legacy-fixed",
            10_000,
            60,
            2,
            1,
            "1970-01-01T00:00:10+00:00",
            "1970-01-01T00:00:10+00:00",
        ),
    )

from serverware import db
from serverware.constraints import (
    evaluate_request_constraints,
    reset_local_constraint_state,
    shared_rate_limit_claims,
)

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


def decision_for(
    route: SimpleNamespace,
    *,
    consume: bool,
    skip_shared_rate_limits: bool = False,
):
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
        skip_shared_rate_limits=skip_shared_rate_limits,
    )


def epoch_ms(value: str) -> int:
    return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000)


def calendar_base(counter_suffix: str, calendar_window: str, now_epoch_ms: int) -> dict:
    return {
        "counter_key": "sha256:" + counter_suffix * 64,
        "principal_id": "agent:calendar-test",
        "route_id": f"route.calendar-{counter_suffix}",
        "credential_id": "",
        "credential_version": 0,
        "policy_hash": "sha256:" + "c" * 64,
        "constraint_id": f"calendar-{counter_suffix}",
        "operation": None,
        "calendar_window": calendar_window,
        "max_count": 1,
        "consume": True,
        "now_epoch_ms": now_epoch_ms,
        "audit": False,
    }


def main() -> None:
    db.init_db()
    with db.connect() as conn:
        migrated = conn.execute(
            "SELECT window_kind, window_start_epoch_ms, window_end_epoch_ms "
            "FROM rate_limit_counters WHERE counter_key = ?",
            ("sha256:" + "f" * 64,),
        ).fetchone()
    assert migrated["window_kind"] == "fixed", dict(migrated)
    assert int(migrated["window_start_epoch_ms"]) == 10_000, dict(migrated)
    assert int(migrated["window_end_epoch_ms"]) == 70_000, dict(migrated)
    with db.connect() as conn:
        migrated_reservation = conn.execute(
            "SELECT window_kind, window_start_epoch_ms, window_end_epoch_ms "
            "FROM release_authorization_quota_reservations "
            "WHERE attempt_id = ? AND counter_key = ?",
            ("attempt:legacy-fixed", "sha256:" + "f" * 64),
        ).fetchone()
    assert migrated_reservation["window_kind"] == "fixed", dict(
        migrated_reservation
    )
    assert int(migrated_reservation["window_start_epoch_ms"]) == 10_000, dict(
        migrated_reservation
    )
    assert int(migrated_reservation["window_end_epoch_ms"]) == 70_000, dict(
        migrated_reservation
    )
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

    boundary_cases = (
        (
            "1",
            "utcDay",
            "2024-02-29T00:00:00Z",
            "2024-03-01T00:00:00Z",
        ),
        (
            "2",
            "utcIsoWeek",
            "2024-12-30T00:00:00Z",
            "2025-01-06T00:00:00Z",
        ),
        (
            "3",
            "utcMonth",
            "2024-02-01T00:00:00Z",
            "2024-03-01T00:00:00Z",
        ),
        (
            "4",
            "utcMonth",
            "2024-12-01T00:00:00Z",
            "2025-01-01T00:00:00Z",
        ),
    )
    for suffix, kind, start_text, end_text in boundary_cases:
        start_ms = epoch_ms(start_text)
        end_ms = epoch_ms(end_text)
        calendar = calendar_base(suffix, kind, start_ms + 1234)
        preview = db.consume_rate_limit(**{**calendar, "consume": False})
        assert preview["allowed"] and not preview["consumed"], preview
        assert preview["window_start_epoch_ms"] == start_ms, preview
        assert preview["window_end_epoch_ms"] == end_ms, preview
        assert preview["window_kind"] == kind, preview
        consumed = db.consume_rate_limit(**calendar)
        assert consumed["allowed"] and consumed["count"] == 1, consumed
        denied = db.consume_rate_limit(
            **{**calendar, "now_epoch_ms": end_ms - 1}
        )
        assert not denied["allowed"] and denied["retry_after_seconds"] == 1, denied
        reset_calendar = db.consume_rate_limit(
            **{**calendar, "now_epoch_ms": end_ms}
        )
        assert reset_calendar["allowed"] and reset_calendar["count"] == 1, reset_calendar
        assert reset_calendar["window_start_epoch_ms"] == end_ms, reset_calendar

    rollback = calendar_base("5", "utcDay", epoch_ms("2025-03-09T12:00:00Z"))
    assert db.consume_rate_limit(**rollback)["allowed"]
    try:
        db.consume_rate_limit(
            **{**rollback, "now_epoch_ms": epoch_ms("2025-03-08T23:59:59.999Z")}
        )
    except db.RateLimitStoreError as exc:
        assert "clock moved" in str(exc), exc
    else:
        raise AssertionError("calendar quota accepted a clock rollback")
    with db.connect() as conn:
        rollback_row = conn.execute(
            "SELECT count, window_kind FROM rate_limit_counters WHERE counter_key = ?",
            (rollback["counter_key"],),
        ).fetchone()
    assert int(rollback_row["count"]) == 1 and rollback_row["window_kind"] == "utcDay"

    transition_key = "sha256:" + "6" * 64
    transition_fixed = {
        **base,
        "counter_key": transition_key,
        "operation": None,
        "window_seconds": 60,
        "max_count": 2,
        "now_epoch_ms": epoch_ms("2025-01-15T12:00:00Z"),
        "audit": False,
    }
    assert db.consume_rate_limit(**transition_fixed)["allowed"]
    transition_calendar = {
        **transition_fixed,
        "window_seconds": None,
        "calendar_window": "utcMonth",
    }
    try:
        db.consume_rate_limit(**transition_calendar)
    except db.RateLimitStoreError as exc:
        assert "cannot change window kind" in str(exc), exc
    else:
        raise AssertionError("live fixed quota transitioned to a calendar window")
    transitioned = db.consume_rate_limit(
        **{
            **transition_calendar,
            "now_epoch_ms": transition_fixed["now_epoch_ms"] + 60_000,
        }
    )
    assert transitioned["allowed"] and transitioned["window_kind"] == "utcMonth", transitioned

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
        calendar_constraint = {
            **api_constraint,
            "id": "api-daily-call",
            "calendarWindow": "utcDay",
        }
        calendar_constraint.pop("windowSeconds")
        calendar_route = SimpleNamespace(
            id="route.api-calendar-quota",
            principals=("agent:quota-test",),
            credential_ref="cred-x",
            constraints=(calendar_constraint,),
        )
        snapshot = SimpleNamespace(
            hash=policy_hash, routes=(api_route, calendar_route)
        )
        operation_context = {"operation": "tweets.write", "tenant": "tenant-a"}
        counter_key = app_module._rate_limit_counter_key(
            constraint=api_constraint,
            route_id=api_route.id,
            principal_id="agent:quota-test",
            credential_ref=api_route.credential_ref,
            credential_version=7,
            operation_context=operation_context,
        )
        claims = shared_rate_limit_claims(
            api_route,
            principal_id="agent:quota-test",
            credential_ref=api_route.credential_ref,
            credential_version=7,
            operation_fields=operation_context,
        )
        assert len(claims) == 1 and claims[0]["counter_key"] == counter_key, claims
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
            }
        )
        original_snapshot = app_module.get_policy_snapshot
        original_get_credential = db.get_credential
        app_module.get_policy_snapshot = lambda: snapshot
        db.get_credential = lambda credential_id, include_secret=False: (
            {"id": credential_id, "credential_version": 7} if credential_id == "cred-x" else None
        )
        try:
            api_first = data_plane_rate_limit_consume(payload, x_serverware_data_plane_token="test-rate-limit-token")
            api_second = data_plane_rate_limit_consume(payload, x_serverware_data_plane_token="test-rate-limit-token")
            assert api_first["ok"] is True and api_first["allowed"] is True, api_first
            assert api_second["ok"] is True and api_second["allowed"] is False, api_second
            tampered = payload.model_copy(update={"max_count": 999})
            try:
                data_plane_rate_limit_consume(
                    tampered,
                    x_serverware_data_plane_token="test-rate-limit-token",
                )
            except HTTPException as exc:
                assert exc.status_code == 409 and "parameters" in str(exc.detail), exc
            else:
                raise AssertionError("shared rate-limit endpoint accepted caller-controlled quota parameters")

            calendar_counter_key = app_module._rate_limit_counter_key(
                constraint=calendar_constraint,
                route_id=calendar_route.id,
                principal_id="agent:quota-test",
                credential_ref=calendar_route.credential_ref,
                credential_version=7,
                operation_context=operation_context,
            )
            stable_fixed_key = app_module._rate_limit_counter_key(
                constraint=api_constraint,
                route_id=api_route.id,
                principal_id="agent:quota-test",
                credential_ref=api_route.credential_ref,
                credential_version=7,
                operation_context=operation_context,
            )
            stable_calendar_key = app_module._rate_limit_counter_key(
                constraint={
                    **api_constraint,
                    "calendarWindow": "utcDay",
                    "windowSeconds": None,
                },
                route_id=api_route.id,
                principal_id="agent:quota-test",
                credential_ref=api_route.credential_ref,
                credential_version=7,
                operation_context=operation_context,
            )
            assert stable_fixed_key == stable_calendar_key
            calendar_payload = DataPlaneRateLimitConsume.model_validate(
                {
                    "counterKey": calendar_counter_key,
                    "principalId": "agent:quota-test",
                    "routeId": calendar_route.id,
                    "credentialRef": "cred-x",
                    "credentialVersion": 7,
                    "policyHash": policy_hash,
                    "constraintId": calendar_constraint["id"],
                    "operation": "tweets.write",
                    "operationContext": operation_context,
                    "max": 1,
                    "calendarWindow": "utcDay",
                    "consume": False,
                }
            )
            calendar_preview = data_plane_rate_limit_consume(
                calendar_payload,
                x_serverware_data_plane_token="test-rate-limit-token",
            )
            assert calendar_preview["window_kind"] == "utcDay", calendar_preview
            assert calendar_preview["window_seconds"] is None, calendar_preview
            wrong_calendar = calendar_payload.model_copy(
                update={"calendar_window": "utcMonth"}
            )
            try:
                data_plane_rate_limit_consume(
                    wrong_calendar,
                    x_serverware_data_plane_token="test-rate-limit-token",
                )
            except HTTPException as exc:
                assert exc.status_code == 409, exc
            else:
                raise AssertionError(
                    "shared rate-limit endpoint trusted a caller calendar descriptor"
                )
            try:
                DataPlaneRateLimitConsume.model_validate(
                    {
                        **calendar_payload.model_dump(by_alias=True),
                        "windowStartEpochMs": 0,
                    }
                )
            except Exception:
                pass
            else:
                raise AssertionError(
                    "shared rate-limit API accepted a caller-computed boundary"
                )
            base_calendar_payload = calendar_payload.model_dump(
                by_alias=True,
                exclude_none=True,
            )
            for label, changes in (
                ("both descriptors", {"windowSeconds": 60}),
                (
                    "neither descriptor",
                    {"calendarWindow": None},
                ),
                ("fractional maximum", {"max": 1.5}),
            ):
                try:
                    DataPlaneRateLimitConsume.model_validate(
                        {**base_calendar_payload, **changes}
                    )
                except Exception:
                    pass
                else:
                    raise AssertionError(
                        f"shared rate-limit API accepted {label}"
                    )
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

    with patch.object(
        db,
        "consume_rate_limit",
        side_effect=AssertionError("atomic mode called the legacy shared quota endpoint"),
    ):
        assert decision_for(
            route,
            consume=False,
            skip_shared_rate_limits=True,
        ).allowed
        assert decision_for(
            route,
            consume=True,
            skip_shared_rate_limits=True,
        ).allowed

    invalid_local_calendar = SimpleNamespace(
        id="route.invalid-local-calendar",
        credential_ref="cred-x",
        constraints=[
            {
                "id": "invalid-local-calendar",
                "type": "rateLimit",
                "max": 1,
                "calendarWindow": "utcDay",
                "store": "local",
            }
        ],
    )
    local_denial = decision_for(invalid_local_calendar, consume=True)
    assert not local_denial.allowed, local_denial
    assert local_denial.payload["error"] == "constraint_invalid_rate_limit_store"

    fractional_local = SimpleNamespace(
        id="route.invalid-fractional-limit",
        credential_ref="cred-x",
        constraints=[
            {
                "id": "invalid-fractional-limit",
                "type": "rateLimit",
                "max": 1.5,
                "windowSeconds": 60,
                "store": "local",
            }
        ],
    )
    fractional_denial = decision_for(fractional_local, consume=True)
    assert not fractional_denial.allowed, fractional_denial
    assert fractional_denial.payload["error"] == "constraint_invalid_rate_limit"

    print(f"shared rate-limit tests passed; endpoint_checked={endpoint_checked}")


if __name__ == "__main__":
    try:
        main()
    finally:
        tmpdir.cleanup()
