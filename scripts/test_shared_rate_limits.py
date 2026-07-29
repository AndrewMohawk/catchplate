#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any
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
    shared_durable_budget_claims,
    shared_rate_limit_claims,
    traversal_budget_claims,
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


def digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def durable_budget_base(
    *,
    reservation_id: str,
    budget_key: str,
    request_digest: str,
    operation_digest: str,
    units: int,
    now_epoch_ms: int,
    max_units: int = 2,
    unit_field: str = "operations",
) -> dict:
    return {
        "reservation_id": reservation_id,
        "budget_key": budget_key,
        "principal_id": "agent:durable-budget",
        "route_id": "route.durable-budget",
        "credential_id": "cred-durable",
        "credential_version": 4,
        "policy_hash": digest("policy:durable-budget"),
        "constraint_id": "durable-budget",
        "operation_digest": operation_digest,
        "request_digest": request_digest,
        "unit_field": unit_field,
        "units": units,
        "window_seconds": 60,
        "max_units": max_units,
        "reservation_ttl_seconds": 30,
        "now_epoch_ms": now_epoch_ms,
    }


def exercise_durable_budgets() -> None:
    budget_key = digest("budget:sliding-operations")
    first = durable_budget_base(
        reservation_id="budget-reservation:first",
        budget_key=budget_key,
        request_digest=digest("request:first"),
        operation_digest=digest("operation:send-a"),
        units=1,
        now_epoch_ms=1_000,
    )
    reserved_first = db.reserve_durable_budget(**first)
    assert reserved_first["allowed"] and reserved_first["total_units"] == 1
    replayed_first = db.reserve_durable_budget(**first)
    assert replayed_first["idempotent_replay"] is True
    dispatched_first = db.mark_durable_budget_dispatched(
        reservation_id=first["reservation_id"],
        budget_key=budget_key,
        request_digest=first["request_digest"],
        operation_digest=first["operation_digest"],
        now_epoch_ms=1_001,
    )
    assert dispatched_first["state"] == "dispatched"
    committed_first = db.commit_durable_budget_reservation(
        reservation_id=first["reservation_id"],
        budget_key=budget_key,
        request_digest=first["request_digest"],
        operation_digest=first["operation_digest"],
        now_epoch_ms=1_002,
    )
    assert committed_first["state"] == "committed"
    replayed_commit = db.commit_durable_budget_reservation(
        reservation_id=first["reservation_id"],
        budget_key=budget_key,
        request_digest=first["request_digest"],
        operation_digest=first["operation_digest"],
        now_epoch_ms=1_003,
    )
    assert replayed_commit["idempotent_replay"] is True

    second = durable_budget_base(
        reservation_id="budget-reservation:second",
        budget_key=budget_key,
        request_digest=digest("request:second"),
        operation_digest=digest("operation:send-b"),
        units=1,
        now_epoch_ms=2_000,
    )
    assert db.reserve_durable_budget(**second)["allowed"]
    third = durable_budget_base(
        reservation_id="budget-reservation:third",
        budget_key=budget_key,
        request_digest=digest("request:third"),
        operation_digest=digest("operation:send-c"),
        units=1,
        now_epoch_ms=2_001,
    )
    denied_third = db.reserve_durable_budget(**third)
    assert not denied_third["allowed"]
    assert denied_third["reason"] == "sliding_budget_exceeded"
    cancelled_second = db.cancel_durable_budget_reservation(
        reservation_id=second["reservation_id"],
        budget_key=budget_key,
        request_digest=second["request_digest"],
        operation_digest=second["operation_digest"],
        now_epoch_ms=2_002,
    )
    assert cancelled_second["state"] == "cancelled"
    assert db.reserve_durable_budget(**{**third, "now_epoch_ms": 2_003})["allowed"]
    db.commit_durable_budget_reservation(
        reservation_id=third["reservation_id"],
        budget_key=budget_key,
        request_digest=third["request_digest"],
        operation_digest=third["operation_digest"],
        now_epoch_ms=2_004,
    )

    exact_boundary = durable_budget_base(
        reservation_id="budget-reservation:boundary",
        budget_key=budget_key,
        request_digest=digest("request:boundary"),
        operation_digest=digest("operation:boundary"),
        units=1,
        now_epoch_ms=61_001,
    )
    boundary_result = db.reserve_durable_budget(**exact_boundary)
    assert boundary_result["allowed"], boundary_result
    assert boundary_result["total_units"] == 2, boundary_result

    try:
        db.reserve_durable_budget(
            **{
                **exact_boundary,
                "reservation_id": first["reservation_id"],
                "request_digest": digest("request:tampered"),
                "now_epoch_ms": 61_002,
            }
        )
    except db.DurableBudgetStoreError as exc:
        assert "different evidence" in str(exc), exc
    else:
        raise AssertionError("durable budget accepted reservation-id rebinding")

    try:
        db.reserve_durable_budget(
            **{
                **exact_boundary,
                "reservation_id": "budget-reservation:clock-rollback",
                "request_digest": digest("request:clock-rollback"),
                "now_epoch_ms": 61_000,
            }
        )
    except db.DurableBudgetStoreError as exc:
        assert "clock moved" in str(exc), exc
    else:
        raise AssertionError("durable budget accepted clock regression")

    weighted_key = digest("budget:weighted-cents")
    weighted_first = durable_budget_base(
        reservation_id="weighted:first",
        budget_key=weighted_key,
        request_digest=digest("weighted-request:first"),
        operation_digest=digest("weighted-operation:create"),
        units=60,
        now_epoch_ms=100_000,
        max_units=100,
        unit_field="cents:operationField:amount",
    )
    assert db.reserve_durable_budget(**weighted_first)["allowed"]
    db.commit_durable_budget_reservation(
        reservation_id=weighted_first["reservation_id"],
        budget_key=weighted_key,
        request_digest=weighted_first["request_digest"],
        operation_digest=weighted_first["operation_digest"],
        now_epoch_ms=100_001,
    )
    weighted_overflow = durable_budget_base(
        reservation_id="weighted:overflow",
        budget_key=weighted_key,
        request_digest=digest("weighted-request:overflow"),
        operation_digest=digest("weighted-operation:update"),
        units=50,
        now_epoch_ms=100_002,
        max_units=100,
        unit_field="cents:operationField:amount",
    )
    denied_weight = db.reserve_durable_budget(**weighted_overflow)
    assert not denied_weight["allowed"] and denied_weight["remaining_units"] == 40
    weighted_exact = {
        **weighted_overflow,
        "reservation_id": "weighted:exact",
        "request_digest": digest("weighted-request:exact"),
        "units": 40,
        "now_epoch_ms": 100_003,
    }
    assert db.reserve_durable_budget(**weighted_exact)["allowed"]

    concurrent_key = digest("budget:concurrent")
    concurrent_results: list[dict] = []
    concurrent_errors: list[BaseException] = []
    concurrent_lock = threading.Lock()
    concurrent_barrier = threading.Barrier(2)

    def reserve_concurrently(index: int) -> None:
        try:
            concurrent_barrier.wait()
            result = db.reserve_durable_budget(
                **durable_budget_base(
                    reservation_id=f"concurrent:{index}",
                    budget_key=concurrent_key,
                    request_digest=digest(f"concurrent-request:{index}"),
                    operation_digest=digest(f"concurrent-operation:{index}"),
                    units=1,
                    now_epoch_ms=200_000,
                    max_units=1,
                )
            )
            with concurrent_lock:
                concurrent_results.append(result)
        except BaseException as exc:
            with concurrent_lock:
                concurrent_errors.append(exc)

    concurrent_threads = [
        threading.Thread(target=reserve_concurrently, args=(index,))
        for index in range(2)
    ]
    for thread in concurrent_threads:
        thread.start()
    for thread in concurrent_threads:
        thread.join(timeout=10)
        assert not thread.is_alive(), "concurrent budget reservation did not terminate"
    assert not concurrent_errors, concurrent_errors
    assert sum(1 for result in concurrent_results if result["allowed"]) == 1
    assert sum(1 for result in concurrent_results if not result["allowed"]) == 1

    sliding_constraint = {
        "id": "five-sends",
        "type": "slidingWindowLimit",
        "store": "shared",
        "windowSeconds": 3600,
        "max": 5,
        "windowSemantics": "sliding",
        "measure": "operationCount",
        "reservationMode": "atomicReserveCommitRelease",
        "onOverflow": "deny",
        "key": {"scope": ["principal", "credential", "route"]},
    }
    weighted_constraint = {
        **sliding_constraint,
        "id": "daily-spend",
        "type": "weightedBudget",
        "max": 100_000,
        "windowSeconds": 86_400,
        "measure": "weightedCanonicalInteger",
        "weight": {
            "source": "operationField",
            "field": "amount",
            "representation": "canonicalNonNegativeInteger",
            "unit": "cents",
            "minimumPerOperation": 1,
            "maximumPerOperation": 50_000,
        },
    }
    route = SimpleNamespace(
        id="route.claims",
        credential_ref="cred-durable",
        constraints=(sliding_constraint, weighted_constraint),
    )
    claims = shared_durable_budget_claims(
        route,
        principal_id="agent:durable-budget",
        credential_ref=route.credential_ref,
        credential_version=4,
        policy_hash=digest("policy:durable-claims"),
        operation_fields={"operation": "payments.create", "amount": "2500"},
    )
    assert [claim["window_semantics"] for claim in claims] == [
        "sliding",
        "sliding",
    ]
    assert [claim["type"] for claim in claims] == [
        "slidingWindowLimit",
        "weightedBudget",
    ]
    assert claims[0]["units"] == 1 and claims[0]["unit_field"] == "operations"
    assert claims[1]["units"] == 2500
    assert claims[1]["unit_field"] == "cents:operationField:amount"
    runtime_route = SimpleNamespace(
        id="route.runtime-sliding",
        credential_ref="cred-durable",
        constraints=(
            {
                **sliding_constraint,
                "id": "runtime-one-send",
                "max": 1,
            },
        ),
    )
    runtime_flow = SimpleNamespace(
        id="flow:runtime-sliding:first",
        metadata={
            "serverware_request_digest": digest("runtime-request:first"),
            "serverware_operation_digest": digest("runtime-operation:first"),
        },
        request=Request(),
    )
    runtime_allowed = evaluate_request_constraints(
        runtime_flow,
        runtime_route,
        principal_id="agent:durable-budget",
        credential_ref=runtime_route.credential_ref,
        credential_version=4,
        operation_fields={"operation": "messages.send"},
        consume_rate_limits=True,
        policy_hash=digest("policy:runtime-sliding"),
        rate_limits_only=True,
    )
    assert runtime_allowed.allowed, runtime_allowed
    runtime_denied = evaluate_request_constraints(
        SimpleNamespace(
            id="flow:runtime-sliding:second",
            metadata={
                "serverware_request_digest": digest("runtime-request:second"),
                "serverware_operation_digest": digest("runtime-operation:second"),
            },
            request=Request(),
        ),
        runtime_route,
        principal_id="agent:durable-budget",
        credential_ref=runtime_route.credential_ref,
        credential_version=4,
        operation_fields={"operation": "messages.send"},
        consume_rate_limits=True,
        policy_hash=digest("policy:runtime-sliding"),
        rate_limits_only=True,
    )
    assert not runtime_denied.allowed
    assert runtime_denied.payload["error"] == "credential_durable_budget_exceeded"
    try:
        shared_durable_budget_claims(
            route,
            principal_id="agent:durable-budget",
            credential_ref=route.credential_ref,
            credential_version=4,
            policy_hash=digest("policy:durable-claims"),
            operation_fields={"operation": "payments.create", "amount": "02500"},
        )
    except ValueError as exc:
        assert "noncanonical" in str(exc), exc
    else:
        raise AssertionError("weighted budget accepted a noncanonical integer")


def traversal_identity(**overrides) -> dict:
    base = {
        "chain_key": digest("traversal:chain-a"),
        "lineage_digest": digest("traversal:lineage-a"),
        "principal_id": "agent:traversal",
        "route_id": "route.search",
        "credential_id": "cred-search",
        "credential_version": 3,
        "policy_hash": digest("policy:traversal"),
        "constraint_id": "search-traversal",
        "max_pages": 3,
        "max_records": 5,
        "max_bytes": 500,
        "lifetime_seconds": 300,
        "reservation_ttl_seconds": 30,
    }
    return {**base, **overrides}


def exercise_traversal_budgets() -> None:
    identity = traversal_identity()
    root = db.reserve_traversal_page(
        **identity,
        reservation_id="traversal:root",
        request_digest=digest("traversal-request:root"),
        request_cursor_digest=None,
        now_epoch_ms=1_000_000,
    )
    assert root["allowed"] and root["page_number"] == 1
    root_replay = db.reserve_traversal_page(
        **identity,
        reservation_id="traversal:root-replay",
        request_digest=digest("traversal-request:root-replay"),
        request_cursor_digest=None,
        now_epoch_ms=1_000_001,
    )
    assert not root_replay["allowed"] and root_replay["reason"] == "root_request_replayed"
    db.mark_traversal_page_dispatched(
        reservation_id="traversal:root",
        chain_key=identity["chain_key"],
        request_digest=digest("traversal-request:root"),
        now_epoch_ms=1_000_002,
    )
    cursor_one = digest("provider-cursor:one")
    completed_root = db.complete_traversal_page(
        reservation_id="traversal:root",
        chain_key=identity["chain_key"],
        request_digest=digest("traversal-request:root"),
        response_digest=digest("traversal-response:root"),
        response_records=2,
        response_bytes=100,
        next_cursor_digest=cursor_one,
        now_epoch_ms=1_000_003,
    )
    assert completed_root["allowed"] and completed_root["record_count"] == 2

    foreign = traversal_identity(
        chain_key=digest("traversal:chain-foreign"),
        lineage_digest=digest("traversal:lineage-foreign"),
        principal_id="agent:other",
    )
    cross_lineage = db.reserve_traversal_page(
        **foreign,
        reservation_id="traversal:cross-lineage",
        request_digest=digest("traversal-request:cross-lineage"),
        request_cursor_digest=cursor_one,
        now_epoch_ms=1_000_004,
    )
    assert not cross_lineage["allowed"]
    assert cross_lineage["reason"] == "cursor_cross_lineage"

    page_two_request = digest("traversal-request:page-two")
    page_two = db.reserve_traversal_page(
        **identity,
        reservation_id="traversal:page-two",
        request_digest=page_two_request,
        request_cursor_digest=cursor_one,
        now_epoch_ms=1_000_005,
    )
    assert page_two["allowed"] and page_two["page_number"] == 2
    fork = db.reserve_traversal_page(
        **identity,
        reservation_id="traversal:fork",
        request_digest=digest("traversal-request:fork"),
        request_cursor_digest=cursor_one,
        now_epoch_ms=1_000_006,
    )
    assert not fork["allowed"] and fork["reason"] == "cursor_replayed_or_expired"
    cancelled = db.terminate_traversal_page(
        reservation_id="traversal:page-two",
        chain_key=identity["chain_key"],
        request_digest=page_two_request,
        outcome="not_forwarded",
        now_epoch_ms=1_000_007,
    )
    assert cancelled["reservation_state"] == "cancelled"

    page_two_retry = db.reserve_traversal_page(
        **identity,
        reservation_id="traversal:page-two-retry",
        request_digest=digest("traversal-request:page-two-retry"),
        request_cursor_digest=cursor_one,
        now_epoch_ms=1_000_008,
    )
    assert page_two_retry["allowed"] and page_two_retry["page_number"] == 2
    db.mark_traversal_page_dispatched(
        reservation_id="traversal:page-two-retry",
        chain_key=identity["chain_key"],
        request_digest=digest("traversal-request:page-two-retry"),
        now_epoch_ms=1_000_009,
    )
    cursor_two = digest("provider-cursor:two")
    completed_two = db.complete_traversal_page(
        reservation_id="traversal:page-two-retry",
        chain_key=identity["chain_key"],
        request_digest=digest("traversal-request:page-two-retry"),
        response_digest=digest("traversal-response:page-two"),
        response_records=2,
        response_bytes=200,
        next_cursor_digest=cursor_two,
        now_epoch_ms=1_000_010,
    )
    assert completed_two["record_count"] == 4
    consumed_replay = db.reserve_traversal_page(
        **identity,
        reservation_id="traversal:consumed-replay",
        request_digest=digest("traversal-request:consumed-replay"),
        request_cursor_digest=cursor_one,
        now_epoch_ms=1_000_011,
    )
    assert not consumed_replay["allowed"]
    assert consumed_replay["reason"] == "cursor_replayed_or_expired"

    page_three = db.reserve_traversal_page(
        **identity,
        reservation_id="traversal:page-three",
        request_digest=digest("traversal-request:page-three"),
        request_cursor_digest=cursor_two,
        now_epoch_ms=1_000_012,
    )
    assert page_three["allowed"] and page_three["page_number"] == 3
    db.mark_traversal_page_dispatched(
        reservation_id="traversal:page-three",
        chain_key=identity["chain_key"],
        request_digest=digest("traversal-request:page-three"),
        now_epoch_ms=1_000_013,
    )
    record_overflow = db.complete_traversal_page(
        reservation_id="traversal:page-three",
        chain_key=identity["chain_key"],
        request_digest=digest("traversal-request:page-three"),
        response_digest=digest("traversal-response:page-three"),
        response_records=2,
        response_bytes=100,
        next_cursor_digest=digest("provider-cursor:three"),
        now_epoch_ms=1_000_014,
    )
    assert not record_overflow["allowed"]
    assert record_overflow["reason"] == "traversal_record_budget_exceeded"
    assert record_overflow["chain_state"] == "exhausted"

    byte_identity = traversal_identity(
        chain_key=digest("traversal:chain-bytes"),
        lineage_digest=digest("traversal:lineage-bytes"),
        max_bytes=50,
    )
    db.reserve_traversal_page(
        **byte_identity,
        reservation_id="traversal:bytes-root",
        request_digest=digest("traversal-request:bytes-root"),
        request_cursor_digest=None,
        now_epoch_ms=2_000_000,
    )
    db.mark_traversal_page_dispatched(
        reservation_id="traversal:bytes-root",
        chain_key=byte_identity["chain_key"],
        request_digest=digest("traversal-request:bytes-root"),
        now_epoch_ms=2_000_001,
    )
    byte_overflow = db.complete_traversal_page(
        reservation_id="traversal:bytes-root",
        chain_key=byte_identity["chain_key"],
        request_digest=digest("traversal-request:bytes-root"),
        response_digest=digest("traversal-response:bytes-root"),
        response_records=1,
        response_bytes=51,
        next_cursor_digest=digest("provider-cursor:bytes"),
        now_epoch_ms=2_000_002,
    )
    assert not byte_overflow["allowed"]
    assert byte_overflow["reason"] == "traversal_byte_budget_exceeded"

    unknown_identity = traversal_identity(
        chain_key=digest("traversal:chain-unknown"),
        lineage_digest=digest("traversal:lineage-unknown"),
    )
    db.reserve_traversal_page(
        **unknown_identity,
        reservation_id="traversal:unknown-root",
        request_digest=digest("traversal-request:unknown-root"),
        request_cursor_digest=None,
        now_epoch_ms=3_000_000,
    )
    db.mark_traversal_page_dispatched(
        reservation_id="traversal:unknown-root",
        chain_key=unknown_identity["chain_key"],
        request_digest=digest("traversal-request:unknown-root"),
        now_epoch_ms=3_000_001,
    )
    unknown = db.terminate_traversal_page(
        reservation_id="traversal:unknown-root",
        chain_key=unknown_identity["chain_key"],
        request_digest=digest("traversal-request:unknown-root"),
        outcome="indeterminate",
        now_epoch_ms=3_000_002,
    )
    assert unknown["chain_state"] == "poisoned"
    poisoned_retry = db.reserve_traversal_page(
        **unknown_identity,
        reservation_id="traversal:unknown-retry",
        request_digest=digest("traversal-request:unknown-retry"),
        request_cursor_digest=None,
        now_epoch_ms=3_000_003,
    )
    assert not poisoned_retry["allowed"]
    assert poisoned_retry["reason"] == "traversal_poisoned"

    identity_replay = traversal_identity(
        chain_key=digest("traversal:chain-identity-replay"),
        lineage_digest=digest("traversal:lineage-identity-replay"),
    )
    identity_replay_request = {
        **identity_replay,
        "reservation_id": "traversal:identity-replay",
        "request_digest": digest("traversal-request:identity-replay"),
        "request_cursor_digest": None,
        "now_epoch_ms": 4_000_000,
    }
    assert db.reserve_traversal_page(**identity_replay_request)["allowed"]
    try:
        db.reserve_traversal_page(
            **{
                **identity_replay_request,
                "principal_id": "agent:identity-rebound",
                "now_epoch_ms": 4_000_001,
            }
        )
    except db.TraversalBudgetStoreError as exc:
        assert "different policy dimensions" in str(exc), exc
    else:
        raise AssertionError("traversal replay accepted a rebound principal")

    lifetime_identity = traversal_identity(
        chain_key=digest("traversal:chain-lifetime"),
        lineage_digest=digest("traversal:lineage-lifetime"),
        lifetime_seconds=1,
    )
    lifetime_request_digest = digest("traversal-request:lifetime")
    db.reserve_traversal_page(
        **lifetime_identity,
        reservation_id="traversal:lifetime",
        request_digest=lifetime_request_digest,
        request_cursor_digest=None,
        now_epoch_ms=5_000_000,
    )
    db.mark_traversal_page_dispatched(
        reservation_id="traversal:lifetime",
        chain_key=lifetime_identity["chain_key"],
        request_digest=lifetime_request_digest,
        now_epoch_ms=5_000_001,
    )
    lifetime_denial = db.complete_traversal_page(
        reservation_id="traversal:lifetime",
        chain_key=lifetime_identity["chain_key"],
        request_digest=lifetime_request_digest,
        response_digest=digest("traversal-response:lifetime"),
        response_records=1,
        response_bytes=1,
        next_cursor_digest=None,
        now_epoch_ms=5_001_000,
    )
    assert not lifetime_denial["allowed"]
    assert lifetime_denial["reason"] == "traversal_lifetime_expired"
    assert lifetime_denial["chain_state"] == "expired"

    traversal_constraint = {
        "id": "typed-traversal",
        "type": "traversalBudget",
        "operations": ["search.read"],
        "traversal": {
            "store": "shared",
            "phases": ["request", "response"],
            "cursor": {
                "requestSource": "query",
                "requestField": "next_token",
                "responseField": "meta.next_token",
                "digest": "sha256",
                "firstPageMayOmit": True,
            },
            "lineage": {
                "scope": ["principal", "route", "credential", "credentialVersion"],
                "queryFields": ["query", "max_results"],
                "queryDigest": "sha256",
            },
            "limits": {
                "maxPages": 3,
                "maxLifetimeSeconds": 300,
                "maxRecords": 300,
                "maxDecodedBytes": 196608,
            },
            "accounting": {
                "recordCountField": "meta.result_count",
                "byteSource": "validatedDecodedResponseBytes",
                "commit": "atomicAfterResponseValidation",
            },
            "onReplay": "deny",
            "onCrossLineage": "deny",
            "onMissingEvidence": "deny",
        },
    }
    route = SimpleNamespace(
        id="route.typed-traversal",
        credential_ref="cred-search",
        constraints=(traversal_constraint,),
    )
    typed_claim = traversal_budget_claims(
        route,
        principal_id="agent:traversal",
        credential_ref=route.credential_ref,
        credential_version=3,
        policy_hash=digest("policy:typed-traversal"),
        operation_fields={"operation": "search.read"},
        canonical_query_fields={"query": "from:example", "max_results": 100},
        request_cursor_values={"next_token": "raw-provider-cursor"},
    )[0]
    assert typed_claim["request_cursor_digest"] == digest("raw-provider-cursor")
    assert "raw-provider-cursor" not in json.dumps(typed_claim, sort_keys=True)
    changed_query_claim = traversal_budget_claims(
        route,
        principal_id="agent:traversal",
        credential_ref=route.credential_ref,
        credential_version=3,
        policy_hash=digest("policy:typed-traversal"),
        operation_fields={"operation": "search.read"},
        canonical_query_fields={"query": "from:other", "max_results": 100},
        request_cursor_values={"next_token": "raw-provider-cursor"},
    )[0]
    assert changed_query_claim["chain_key"] != typed_claim["chain_key"]
    try:
        traversal_budget_claims(
            route,
            principal_id="agent:traversal",
            credential_ref=route.credential_ref,
            credential_version=3,
            policy_hash=digest("policy:typed-traversal"),
            operation_fields={"operation": "search.read"},
            canonical_query_fields={
                "query": "from:example",
                "max_results": 100,
                "unbound": "unsafe",
            },
            request_cursor_values={},
        )
    except ValueError as exc:
        assert "lineage contract" in str(exc), exc
    else:
        raise AssertionError("traversal accepted unbound query evidence")
    malformed_traversal = {
        **traversal_constraint,
        "traversal": {
            **traversal_constraint["traversal"],
            "onReplay": "allow",
        },
    }
    try:
        traversal_budget_claims(
            SimpleNamespace(
                id="route.malformed-traversal",
                credential_ref="cred-search",
                constraints=(malformed_traversal,),
            ),
            principal_id="agent:traversal",
            credential_ref="cred-search",
            credential_version=3,
            policy_hash=digest("policy:malformed-traversal"),
            operation_fields={"operation": "search.read"},
            canonical_query_fields={"query": "from:example", "max_results": 100},
            request_cursor_values={},
        )
    except ValueError as exc:
        assert "contract" in str(exc), exc
    else:
        raise AssertionError("traversal accepted a non-denying replay contract")


def policy_claim_digest(claims: Any) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(
            claims, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
    ).hexdigest()


def exercise_atomic_policy_state_bundles() -> None:
    actor_id = "spiffe://test.serverware/decision-gate/rate-limit"

    def release_binding(suffix: str) -> str:
        return digest(f"bundle-release-binding:{suffix}")

    def bundle_claims(
        suffix: str,
        *,
        budget_max: int = 10,
        include_traversal: bool = True,
    ) -> tuple[str, str, str, list[dict]]:
        policy_hash = digest(f"bundle-policy:{suffix}")
        budget_constraint = {
            "id": f"bundle-budget-{suffix}",
            "type": "slidingWindowLimit",
            "store": "shared",
            "windowSeconds": 3600,
            "max": budget_max,
            "windowSemantics": "sliding",
            "measure": "operationCount",
            "reservationMode": "atomicReserveCommitRelease",
            "onOverflow": "deny",
            "key": {
                "scope": ["principal", "credential", "route"],
            },
        }
        traversal_constraint = {
            "id": f"bundle-traversal-{suffix}",
            "type": "traversalBudget",
            "operations": ["search.read"],
            "traversal": {
                "store": "shared",
                "phases": ["request", "response"],
                "cursor": {
                    "requestSource": "query",
                    "requestField": "next_token",
                    "responseField": "meta.next_token",
                    "digest": "sha256",
                    "firstPageMayOmit": True,
                },
                "lineage": {
                    "scope": [
                        "principal",
                        "route",
                        "credential",
                        "credentialVersion",
                    ],
                    "queryFields": ["max_results", "query"],
                    "queryDigest": "sha256",
                },
                "limits": {
                    "maxPages": 3,
                    "maxLifetimeSeconds": 300,
                    "maxRecords": 30,
                    "maxDecodedBytes": 65536,
                },
                "accounting": {
                    "recordCountField": "data",
                    "byteSource": "validatedDecodedResponseBytes",
                    "commit": "atomicAfterResponseValidation",
                },
                "onReplay": "deny",
                "onCrossLineage": "deny",
                "onMissingEvidence": "deny",
            },
        }
        route = SimpleNamespace(
            id=f"route.bundle.{suffix}",
            credential_ref="cred-bundle",
            constraints=(
                (budget_constraint, traversal_constraint)
                if include_traversal
                else (budget_constraint,)
            ),
        )
        operation = {"operation": "search.read"}
        claims = shared_durable_budget_claims(
            route,
            principal_id="agent:bundle",
            credential_ref=route.credential_ref,
            credential_version=5,
            policy_hash=policy_hash,
            operation_fields=operation,
        )
        if include_traversal:
            claims.extend(
                traversal_budget_claims(
                    route,
                    principal_id="agent:bundle",
                    credential_ref=route.credential_ref,
                    credential_version=5,
                    policy_hash=policy_hash,
                    operation_fields=operation,
                    canonical_query_fields={
                        "max_results": "10",
                        "query": f"from:{suffix}",
                    },
                    request_cursor_values={},
                )
            )
        return (
            policy_hash,
            digest(f"bundle-request:{suffix}"),
            digest(f"bundle-operation:{suffix}"),
            claims,
        )

    def ensure_reserved_release(
        suffix: str,
        material: tuple[str, str, str, list[dict]],
    ) -> None:
        claim = material[3][0]
        now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        timestamp = datetime.fromtimestamp(
            now_ms / 1000, timezone.utc
        ).isoformat()
        with db.connect() as conn:
            conn.execute(
                """
                INSERT INTO release_authorization_attempts (
                    attempt_id, binding_digest, binding_json, flow_id,
                    state, principal_id, route_id, credential_id,
                    credential_version, policy_hash, request_digest,
                    operation_digest, operation_context_json, grant_id,
                    approval_request_id,
                    reservation_expires_at_epoch_ms,
                    dispatch_started_at_epoch_ms,
                    dispatch_expires_at_epoch_ms, completion_outcome,
                    completed_at_epoch_ms, created_at, updated_at
                )
                VALUES (?, ?, '{}', ?, 'reserved', ?, ?, ?, ?, ?, ?, ?,
                        '{}', NULL, NULL, ?, NULL, NULL, NULL, NULL, ?, ?)
                ON CONFLICT (attempt_id) DO NOTHING
                """,
                (
                    f"attempt:bundle:{suffix}",
                    release_binding(suffix),
                    f"flow:bundle:{suffix}",
                    claim["principal_id"],
                    claim["route_id"],
                    claim["credential_id"],
                    claim["credential_version"],
                    material[0],
                    material[1],
                    material[2],
                    now_ms + 240_000,
                    timestamp,
                    timestamp,
                ),
            )

    def reserve(
        suffix: str,
        claims_material: tuple[str, str, str, list[dict]],
    ) -> dict:
        policy_hash, request_digest, operation_digest, claims = (
            claims_material
        )
        ensure_reserved_release(suffix, claims_material)
        return db.reserve_policy_state_bundle(
            attempt_id=f"attempt:bundle:{suffix}",
            policy_hash=policy_hash,
            request_digest=request_digest,
            operation_digest=operation_digest,
            release_binding_digest=release_binding(suffix),
            claims=claims,
            claim_digest=policy_claim_digest(claims),
            actor_id=actor_id,
        )

    successful = bundle_claims("success")
    reserved = reserve("success", successful)
    assert reserved["state"] == "reserved", reserved
    assert reserve("success", successful)["state"] == "reserved"
    def dispatch(
        reservation: dict,
        *,
        deadline_at_epoch_ms: int | None = None,
    ) -> dict:
        deadline = deadline_at_epoch_ms or (
            int(datetime.now(timezone.utc).timestamp() * 1000) + 30_000
        )
        dispatch_started_at = min(
            int(datetime.now(timezone.utc).timestamp() * 1000),
            deadline - 1,
        )
        dispatch_timestamp = datetime.fromtimestamp(
            dispatch_started_at / 1000, timezone.utc
        ).isoformat()
        with db.connect() as conn:
            conn.execute(
                "UPDATE release_authorization_attempts "
                "SET state = 'dispatching', "
                "dispatch_started_at_epoch_ms = ?, "
                "dispatch_expires_at_epoch_ms = ?, "
                "completion_outcome = NULL, completed_at_epoch_ms = NULL, "
                "updated_at = ? "
                "WHERE attempt_id = ? AND state = 'reserved'",
                (
                    dispatch_started_at,
                    deadline,
                    dispatch_timestamp,
                    reservation["attempt_id"],
                ),
            )
        result = db.dispatch_policy_state_bundle(
            reservation_id=reservation["reservation_id"],
            attempt_id=reservation["attempt_id"],
            claim_digest=reservation["claim_digest"],
            actor_id=actor_id,
            dispatch_deadline_at_epoch_ms=deadline,
        )
        completed_at = min(
            int(datetime.now(timezone.utc).timestamp() * 1000),
            deadline - 1,
        )
        completed_timestamp = datetime.fromtimestamp(
            completed_at / 1000, timezone.utc
        ).isoformat()
        with db.connect() as conn:
            conn.execute(
                "UPDATE release_authorization_attempts "
                "SET state = 'committed', completion_outcome = 'forwarded', "
                "completed_at_epoch_ms = ?, updated_at = ? "
                "WHERE attempt_id = ? AND state = 'dispatching'",
                (
                    completed_at,
                    completed_timestamp,
                    reservation["attempt_id"],
                ),
            )
        return result

    success_deadline = (
        int(datetime.now(timezone.utc).timestamp() * 1000) + 30_000
    )
    dispatched = dispatch(
        reserved, deadline_at_epoch_ms=success_deadline
    )
    assert dispatched["state"] == "dispatched", dispatched
    assert (
        dispatch(
            reserved, deadline_at_epoch_ms=success_deadline
        )["state"]
        == "dispatched"
    )
    traversal_claim = next(
        claim for claim in successful[3] if claim["type"] == "traversalBudget"
    )
    success_evidence = [
        {
            "constraint_id": traversal_claim["constraint_id"],
            "lineage_digest": traversal_claim["lineage_digest"],
            "request_cursor_digest": None,
            "response_digest": digest("bundle-response:success"),
            "next_cursor_digest": digest("bundle-cursor:success"),
            "record_count": 2,
            "decoded_bytes": 100,
            "validation": "passed",
        }
    ]
    completed = db.complete_policy_state_bundle(
        reservation_id=reserved["reservation_id"],
        attempt_id=reserved["attempt_id"],
        claim_digest=reserved["claim_digest"],
        actor_id=actor_id,
        response_evidence=success_evidence,
    )
    assert completed["state"] == "committed", completed
    assert (
        db.complete_policy_state_bundle(
            reservation_id=reserved["reservation_id"],
            attempt_id=reserved["attempt_id"],
            claim_digest=reserved["claim_digest"],
            actor_id=actor_id,
            response_evidence=success_evidence,
        )["state"]
        == "committed"
    )

    abort_material = bundle_claims("abort")
    abort_reserved = reserve("abort", abort_material)
    aborted = db.abort_policy_state_bundle(
        reservation_id=abort_reserved["reservation_id"],
        attempt_id=abort_reserved["attempt_id"],
        claim_digest=abort_reserved["claim_digest"],
        actor_id=actor_id,
    )
    assert aborted["state"] == "aborted", aborted
    assert (
        db.abort_policy_state_bundle(
            reservation_id=abort_reserved["reservation_id"],
            attempt_id=abort_reserved["attempt_id"],
            claim_digest=abort_reserved["claim_digest"],
            actor_id=actor_id,
        )["state"]
        == "aborted"
    )

    capacity_material = bundle_claims(
        "capacity", budget_max=1, include_traversal=False
    )
    capacity_reserved = reserve("capacity", capacity_material)
    dispatch(capacity_reserved)
    db.complete_policy_state_bundle(
        reservation_id=capacity_reserved["reservation_id"],
        attempt_id=capacity_reserved["attempt_id"],
        claim_digest=capacity_reserved["claim_digest"],
        actor_id=actor_id,
        response_evidence=[],
    )
    rollback_claim = {
        **capacity_material[3][0],
        "constraint_id": "bundle-budget-capacity-rollback",
        "budget_key": digest("bundle-budget:capacity-rollback"),
    }
    denied_claims = [rollback_claim, capacity_material[3][0]]
    denied_attempt = "attempt:bundle:capacity-denied"
    denied_request_digest = digest("bundle-request:capacity-denied")
    denied_operation_digest = digest("bundle-operation:capacity-denied")
    ensure_reserved_release(
        "capacity-denied",
        (
            capacity_material[0],
            denied_request_digest,
            denied_operation_digest,
            denied_claims,
        ),
    )
    denied = db.reserve_policy_state_bundle(
        attempt_id=denied_attempt,
        policy_hash=capacity_material[0],
        request_digest=denied_request_digest,
        operation_digest=denied_operation_digest,
        release_binding_digest=release_binding("capacity-denied"),
        claims=denied_claims,
        claim_digest=policy_claim_digest(denied_claims),
        actor_id=actor_id,
    )
    assert denied["state"] == "denied", denied
    with db.connect() as conn:
        rollback_definition = conn.execute(
            "SELECT budget_key FROM durable_budget_definitions "
            "WHERE budget_key = ?",
            (rollback_claim["budget_key"],),
        ).fetchone()
        denied_bundle = conn.execute(
            "SELECT reservation_id FROM policy_state_bundles "
            "WHERE attempt_id = ?",
            (denied_attempt,),
        ).fetchone()
    assert rollback_definition is None
    assert denied_bundle is None

    partial_material = bundle_claims(
        "partial-dispatch", include_traversal=False
    )
    second_budget = {
        **partial_material[3][0],
        "constraint_id": "bundle-budget-partial-dispatch-second",
        "budget_key": digest("bundle-budget:partial-dispatch-second"),
    }
    partial_material[3].append(second_budget)
    partial_reserved = reserve("partial-dispatch", partial_material)
    second_child_id = db._policy_state_child_reservation_id(
        partial_reserved["reservation_id"], 1, second_budget
    )
    first_child_id = db._policy_state_child_reservation_id(
        partial_reserved["reservation_id"], 0, partial_material[3][0]
    )
    with db.connect() as conn:
        conn.execute(
            "UPDATE durable_budget_events SET state = 'cancelled' "
            "WHERE reservation_id = ?",
            (second_child_id,),
        )
    try:
        dispatch(partial_reserved)
    except db.PolicyStateBundleStoreError:
        pass
    else:
        raise AssertionError(
            "bundle dispatch accepted a partial child transition"
        )
    with db.connect() as conn:
        first_state = conn.execute(
            "SELECT state FROM durable_budget_events "
            "WHERE reservation_id = ?",
            (first_child_id,),
        ).fetchone()["state"]
        bundle_state = conn.execute(
            "SELECT state FROM policy_state_bundles "
            "WHERE reservation_id = ?",
            (partial_reserved["reservation_id"],),
        ).fetchone()["state"]
    assert first_state == "reserved"
    assert bundle_state == "reserved"

    indeterminate_material = bundle_claims("indeterminate")
    indeterminate_reserved = reserve(
        "indeterminate", indeterminate_material
    )
    dispatch(indeterminate_reserved)
    indeterminate_traversal = next(
        claim
        for claim in indeterminate_material[3]
        if claim["type"] == "traversalBudget"
    )
    failure_evidence = [
        {
            "constraint_id": indeterminate_traversal["constraint_id"],
            "lineage_digest": indeterminate_traversal["lineage_digest"],
            "request_cursor_digest": None,
            "outcome": "indeterminate",
            "reason": "provider_transport_error",
            "response_body_sha256": digest(""),
        }
    ]
    failed = db.fail_policy_state_bundle(
        reservation_id=indeterminate_reserved["reservation_id"],
        attempt_id=indeterminate_reserved["attempt_id"],
        claim_digest=indeterminate_reserved["claim_digest"],
        actor_id=actor_id,
        failure_reason="provider_transport_error",
        response_body_sha256=digest(""),
        traversal_evidence=failure_evidence,
    )
    assert failed["state"] == "indeterminate", failed
    assert (
        db.fail_policy_state_bundle(
            reservation_id=indeterminate_reserved["reservation_id"],
            attempt_id=indeterminate_reserved["attempt_id"],
            claim_digest=indeterminate_reserved["claim_digest"],
            actor_id=actor_id,
            failure_reason="provider_transport_error",
            response_body_sha256=digest(""),
            traversal_evidence=failure_evidence,
        )["state"]
        == "indeterminate"
    )
    with db.connect() as conn:
        charged = conn.execute(
            "SELECT state FROM durable_budget_events "
            "WHERE reservation_id = ?",
            (
                db._policy_state_child_reservation_id(
                    indeterminate_reserved["reservation_id"],
                    0,
                    indeterminate_material[3][0],
                ),
            ),
        ).fetchone()["state"]
        poisoned = conn.execute(
            "SELECT state FROM traversal_budget_chains "
            "WHERE chain_key = ?",
            (indeterminate_traversal["chain_key"],),
        ).fetchone()["state"]
    assert charged == "committed"
    assert poisoned == "poisoned"

    lock_material = bundle_claims(
        "lock-order", include_traversal=False
    )
    captured_lock_sets: list[tuple[str, ...]] = []
    original_lock_resources = db._lock_release_resources

    def capture_lock_resources(conn, resources):
        captured_lock_sets.append(tuple(sorted(set(resources))))
        return original_lock_resources(conn, resources)

    with patch.object(
        db, "_lock_release_resources", capture_lock_resources
    ):
        lock_reserved = reserve("lock-order", lock_material)
        db.abort_policy_state_bundle(
            reservation_id=lock_reserved["reservation_id"],
            attempt_id=lock_reserved["attempt_id"],
            claim_digest=lock_reserved["claim_digest"],
            actor_id=actor_id,
        )
    expected_lock_set = tuple(
        sorted(
            db._policy_state_resources(
                lock_reserved["reservation_id"],
                lock_reserved["attempt_id"],
                lock_material[3],
            )
        )
    )
    assert captured_lock_sets == [expected_lock_set, expected_lock_set]

    cursor_token = "abort-rowcount-cursor"
    cursor_material = bundle_claims("abort-rowcount")
    cursor_root = reserve("abort-rowcount-root", cursor_material)
    dispatch(cursor_root)
    cursor_claim = next(
        claim
        for claim in cursor_material[3]
        if claim["type"] == "traversalBudget"
    )
    db.complete_policy_state_bundle(
        reservation_id=cursor_root["reservation_id"],
        attempt_id=cursor_root["attempt_id"],
        claim_digest=cursor_root["claim_digest"],
        actor_id=actor_id,
        response_evidence=[
            {
                "constraint_id": cursor_claim["constraint_id"],
                "lineage_digest": cursor_claim["lineage_digest"],
                "request_cursor_digest": None,
                "response_digest": digest("abort-rowcount-response"),
                "next_cursor_digest": digest(cursor_token),
                "record_count": 1,
                "decoded_bytes": 10,
                "validation": "passed",
            }
        ],
    )
    continuation_claims = json.loads(json.dumps(cursor_material[3]))
    continuation_traversal = next(
        claim
        for claim in continuation_claims
        if claim["type"] == "traversalBudget"
    )
    continuation_traversal["request_cursor_digest"] = digest(cursor_token)
    continuation_material = (
        cursor_material[0],
        digest("abort-rowcount-continuation-request"),
        digest("abort-rowcount-continuation-operation"),
        continuation_claims,
    )
    continuation = reserve(
        "abort-rowcount-continuation", continuation_material
    )
    with db.connect() as conn:
        conn.execute(
            "UPDATE traversal_budget_cursors SET reserved_by = ? "
            "WHERE cursor_digest = ?",
            ("corrupt-reservation-owner", digest(cursor_token)),
        )
    try:
        db.abort_policy_state_bundle(
            reservation_id=continuation["reservation_id"],
            attempt_id=continuation["attempt_id"],
            claim_digest=continuation["claim_digest"],
            actor_id=actor_id,
        )
    except db.PolicyStateBundleStoreError as exc:
        assert "lost its reserved cursor" in str(exc), exc
    else:
        raise AssertionError(
            "bundle abort ignored a cursor-restore rowcount mismatch"
        )
    with db.connect() as conn:
        abort_integrity_bundle = conn.execute(
            "SELECT state FROM policy_state_bundles "
            "WHERE reservation_id = ?",
            (continuation["reservation_id"],),
        ).fetchone()
        abort_integrity_page = conn.execute(
            "SELECT state FROM traversal_budget_page_reservations "
            "WHERE reservation_id = ?",
            (
                db._policy_state_child_reservation_id(
                    continuation["reservation_id"],
                    1,
                    continuation_traversal,
                ),
            ),
        ).fetchone()
    assert abort_integrity_bundle["state"] == "reserved"
    assert abort_integrity_page["state"] == "reserved"

    def insert_release_outcome(
        suffix: str,
        material: tuple[str, str, str, list[dict]],
        *,
        state: str,
        completion_outcome: str,
        binding_digest: str | None = None,
        completed_at_epoch_ms: int,
    ) -> None:
        timestamp = datetime.fromtimestamp(
            completed_at_epoch_ms / 1000, timezone.utc
        ).isoformat()
        with db.connect() as conn:
            updated = conn.execute(
                "UPDATE release_authorization_attempts "
                "SET binding_digest = ?, state = ?, completion_outcome = ?, "
                "completed_at_epoch_ms = ?, updated_at = ? "
                "WHERE attempt_id = ?",
                (
                    binding_digest or release_binding(suffix),
                    state,
                    completion_outcome,
                    completed_at_epoch_ms,
                    timestamp,
                    f"attempt:bundle:{suffix}",
                ),
            )
            assert updated.rowcount == 1

    def recovery_fixture(
        suffix: str,
        *,
        release_state: str,
        completion_outcome: str,
        expected_bundle_state: str,
        mismatched_binding: bool = False,
    ) -> tuple[dict, tuple[str, str, str, list[dict]], int]:
        material = bundle_claims(suffix)
        reservation = reserve(suffix, material)
        deadline = (
            int(datetime.now(timezone.utc).timestamp() * 1000) + 30_000
        )
        dispatch(
            reservation, deadline_at_epoch_ms=deadline
        )
        budget_child_id = db._policy_state_child_reservation_id(
            reservation["reservation_id"], 0, material[3][0]
        )
        with db.connect() as conn:
            dispatch_time = int(
                conn.execute(
                    "SELECT occurred_at_epoch_ms "
                    "FROM durable_budget_events WHERE reservation_id = ?",
                    (budget_child_id,),
                ).fetchone()["occurred_at_epoch_ms"]
            )
        insert_release_outcome(
            suffix,
            material,
            state=release_state,
            completion_outcome=completion_outcome,
            binding_digest=(
                digest(f"mismatched-release-binding:{suffix}")
                if mismatched_binding
                else None
            ),
            completed_at_epoch_ms=(
                deadline - 1
                if release_state == "committed"
                and completion_outcome == "forwarded"
                else deadline
            ),
        )
        reconciled = db.reconcile_policy_state_bundles(
            limit=1,
            now_epoch_ms=deadline,
        )
        assert reconciled["processed"] == 1, reconciled
        with db.connect() as conn:
            bundle = conn.execute(
                "SELECT state, terminal_reason FROM policy_state_bundles "
                "WHERE reservation_id = ?",
                (reservation["reservation_id"],),
            ).fetchone()
            budget = conn.execute(
                "SELECT state, occurred_at_epoch_ms "
                "FROM durable_budget_events WHERE reservation_id = ?",
                (budget_child_id,),
            ).fetchone()
        assert bundle["state"] == expected_bundle_state, dict(bundle)
        if expected_bundle_state == "indeterminate":
            assert budget["state"] == "committed", dict(budget)
            assert int(budget["occurred_at_epoch_ms"]) == dispatch_time
        else:
            assert budget["state"] == "cancelled", dict(budget)
        return reservation, material, deadline

    forwarded, forwarded_material, _ = recovery_fixture(
        "recovery-forwarded",
        release_state="committed",
        completion_outcome="forwarded",
        expected_bundle_state="indeterminate",
    )
    forwarded_traversal = next(
        claim
        for claim in forwarded_material[3]
        if claim["type"] == "traversalBudget"
    )
    forwarded_reason = "durable_dispatch_deadline_forwarded"
    assert db.fail_policy_state_bundle(
        reservation_id=forwarded["reservation_id"],
        attempt_id=forwarded["attempt_id"],
        claim_digest=forwarded["claim_digest"],
        actor_id=actor_id,
        failure_reason=forwarded_reason,
        response_body_sha256=digest(""),
        traversal_evidence=[
            {
                "constraint_id": forwarded_traversal["constraint_id"],
                "lineage_digest": forwarded_traversal["lineage_digest"],
                "request_cursor_digest": None,
                "outcome": "indeterminate",
                "reason": forwarded_reason,
                "response_body_sha256": digest(""),
            }
        ],
    )["state"] == "indeterminate"
    recovery_fixture(
        "recovery-unknown",
        release_state="committed_indeterminate",
        completion_outcome="unknown",
        expected_bundle_state="indeterminate",
    )
    recovery_fixture(
        "recovery-not-forwarded",
        release_state="cancelled",
        completion_outcome="not_forwarded",
        expected_bundle_state="indeterminate",
    )
    recovery_fixture(
        "recovery-binding-mismatch",
        release_state="cancelled",
        completion_outcome="not_forwarded",
        expected_bundle_state="indeterminate",
        mismatched_binding=True,
    )

    def completion_evidence(
        material: tuple[str, str, str, list[dict]],
        suffix: str,
    ) -> list[dict]:
        traversal = next(
            claim
            for claim in material[3]
            if claim["type"] == "traversalBudget"
        )
        return [
            {
                "constraint_id": traversal["constraint_id"],
                "lineage_digest": traversal["lineage_digest"],
                "request_cursor_digest": traversal[
                    "request_cursor_digest"
                ],
                "response_digest": digest(f"bundle-response:{suffix}"),
                "next_cursor_digest": digest(f"bundle-cursor:{suffix}"),
                "record_count": 1,
                "decoded_bytes": 10,
                "validation": "passed",
            }
        ]

    expired_material = bundle_claims("complete-after-deadline")
    expired_reservation = reserve(
        "complete-after-deadline", expired_material
    )
    expired_deadline = (
        int(datetime.now(timezone.utc).timestamp() * 1000) + 30_000
    )
    dispatch(
        expired_reservation,
        deadline_at_epoch_ms=expired_deadline,
    )
    expired_traversal = next(
        claim
        for claim in expired_material[3]
        if claim["type"] == "traversalBudget"
    )
    expired_next_cursor = digest("bundle-cursor:complete-after-deadline")
    expired_page_id = db._policy_state_child_reservation_id(
        expired_reservation["reservation_id"],
        expired_material[3].index(expired_traversal),
        expired_traversal,
    )
    with patch.object(
        db,
        "_rate_limit_transaction_now_epoch_ms",
        return_value=expired_deadline,
    ):
        expired_completion = db.complete_policy_state_bundle(
            reservation_id=expired_reservation["reservation_id"],
            attempt_id=expired_reservation["attempt_id"],
            claim_digest=expired_reservation["claim_digest"],
            actor_id=actor_id,
            response_evidence=completion_evidence(
                expired_material, "complete-after-deadline"
            ),
        )
    assert expired_completion["state"] == "indeterminate"
    assert (
        expired_completion["reason"]
        == "durable_dispatch_deadline_forwarded"
    )
    with db.connect() as conn:
        expired_chain = conn.execute(
            "SELECT state FROM traversal_budget_chains WHERE chain_key = ?",
            (expired_traversal["chain_key"],),
        ).fetchone()
        expired_cursor = conn.execute(
            "SELECT state FROM traversal_budget_cursors "
            "WHERE cursor_digest = ?",
            (expired_next_cursor,),
        ).fetchone()
        expired_page = conn.execute(
            "SELECT state, next_cursor_digest "
            "FROM traversal_budget_page_reservations "
            "WHERE reservation_id = ?",
            (expired_page_id,),
        ).fetchone()
    assert expired_chain["state"] == "poisoned"
    assert expired_cursor is None
    assert expired_page["state"] == "indeterminate"
    assert expired_page["next_cursor_digest"] is None

    for suffix, release_change, expected_reason in (
        (
            "complete-release-not-forwarded",
            (
                "state = 'cancelled', "
                "completion_outcome = 'not_forwarded'"
            ),
            "durable_dispatch_deadline_release_indeterminate",
        ),
        (
            "complete-release-binding-mismatch",
            "binding_digest = '" + digest("mismatched-completion") + "'",
            "durable_dispatch_deadline_binding_mismatch",
        ),
    ):
        material = bundle_claims(suffix)
        reservation = reserve(suffix, material)
        deadline = (
            int(datetime.now(timezone.utc).timestamp() * 1000) + 30_000
        )
        dispatch(reservation, deadline_at_epoch_ms=deadline)
        completed_at = int(
            datetime.now(timezone.utc).timestamp() * 1000
        )
        with db.connect() as conn:
            conn.execute(
                "UPDATE release_authorization_attempts SET "
                + release_change
                + ", completed_at_epoch_ms = ? WHERE attempt_id = ?",
                (completed_at, reservation["attempt_id"]),
            )
        result = db.complete_policy_state_bundle(
            reservation_id=reservation["reservation_id"],
            attempt_id=reservation["attempt_id"],
            claim_digest=reservation["claim_digest"],
            actor_id=actor_id,
            response_evidence=completion_evidence(material, suffix),
        )
        assert result["state"] == "indeterminate", result
        assert result["reason"] == expected_reason, result

    race_material = bundle_claims("complete-reconcile-race")
    race_reservation = reserve("complete-reconcile-race", race_material)
    race_deadline = (
        int(datetime.now(timezone.utc).timestamp() * 1000) + 30_000
    )
    dispatch(race_reservation, deadline_at_epoch_ms=race_deadline)
    race_barrier = threading.Barrier(2)
    race_results: list[dict] = []
    race_errors: list[BaseException] = []

    def complete_at_deadline() -> None:
        try:
            race_barrier.wait()
            race_results.append(
                db.complete_policy_state_bundle(
                    reservation_id=race_reservation["reservation_id"],
                    attempt_id=race_reservation["attempt_id"],
                    claim_digest=race_reservation["claim_digest"],
                    actor_id=actor_id,
                    response_evidence=completion_evidence(
                        race_material, "complete-reconcile-race"
                    ),
                )
            )
        except BaseException as exc:
            race_errors.append(exc)

    def reconcile_at_deadline() -> None:
        try:
            race_barrier.wait()
            race_results.append(
                db.reconcile_policy_state_bundles(
                    limit=1,
                    now_epoch_ms=race_deadline,
                )
            )
        except BaseException as exc:
            race_errors.append(exc)

    with patch.object(
        db,
        "_rate_limit_transaction_now_epoch_ms",
        return_value=race_deadline,
    ):
        race_threads = [
            threading.Thread(target=complete_at_deadline),
            threading.Thread(target=reconcile_at_deadline),
        ]
        for thread in race_threads:
            thread.start()
        for thread in race_threads:
            thread.join()
    assert not race_errors, race_errors
    replay = db.complete_policy_state_bundle(
        reservation_id=race_reservation["reservation_id"],
        attempt_id=race_reservation["attempt_id"],
        claim_digest=race_reservation["claim_digest"],
        actor_id=actor_id,
        response_evidence=completion_evidence(
            race_material, "complete-reconcile-race"
        ),
    )
    assert replay["state"] == "indeterminate", (race_results, replay)
    assert replay["reason"] == "idempotent_replay", replay
    with db.connect() as conn:
        race_bundle = conn.execute(
            "SELECT state, terminal_reason FROM policy_state_bundles "
            "WHERE reservation_id = ?",
            (race_reservation["reservation_id"],),
        ).fetchone()
    assert race_bundle["state"] == "indeterminate"
    assert (
        race_bundle["terminal_reason"]
        == "durable_dispatch_deadline_forwarded"
    )

    class FakePostgresCursor:
        def __init__(self, rows: list[dict]):
            self.rows = rows

        def fetchall(self) -> list[dict]:
            return self.rows

    candidate_sql: list[str] = []
    candidate_params: list[tuple] = []
    fake_postgres = db.PostgresMetadataConnection(None)
    later_candidate = {
        "reservation_id": digest("later-unlocked-candidate"),
        "attempt_id": "attempt:later-unlocked-candidate",
        "claim_digest": digest("later-unlocked-claims"),
    }

    def fake_candidate_execute(sql: str, params=None):
        candidate_sql.append(sql)
        candidate_params.append(params)
        return FakePostgresCursor([later_candidate])

    fake_postgres.execute = fake_candidate_execute
    selected = db._policy_state_stale_candidate_rows(
        fake_postgres,
        now_ms=race_deadline,
        limit=2,
        skip_locked=True,
    )
    assert selected == [later_candidate]
    assert "FOR UPDATE SKIP LOCKED" in candidate_sql[0]
    assert "reservation_id ASC" in candidate_sql[0]
    assert candidate_params[0] == (race_deadline, race_deadline, 2)

    class RetryablePostgresConflict(Exception):
        sqlstate = "55P03"

    for sqlstate in ("40001", "40P01", "55P03"):
        conflict = RetryablePostgresConflict()
        conflict.sqlstate = sqlstate
        assert db._policy_state_retryable_postgres_conflict(conflict)
    for sqlstate in ("23505", "57014"):
        systemic = RetryablePostgresConflict()
        systemic.sqlstate = sqlstate
        assert not db._policy_state_retryable_postgres_conflict(systemic)

    class FakePostgresContext(db.PostgresMetadataConnection):
        def __init__(self):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, sql: str, params=None):
            return FakePostgresCursor([])

    oldest_locked = {
        "reservation_id": digest("oldest-locked-candidate"),
        "attempt_id": "attempt:oldest-locked-candidate",
        "claim_digest": digest("oldest-locked-claims"),
    }
    transition_order: list[str] = []

    def reconcile_candidate(conn, *, preview, now_ms):
        transition_order.append(preview["reservation_id"])
        if preview == oldest_locked:
            raise RetryablePostgresConflict()
        return "indeterminate"

    with (
        patch.object(db, "metadata_uses_postgres", return_value=True),
        patch.object(db, "connect", side_effect=FakePostgresContext),
        patch.object(
            db,
            "_rate_limit_transaction_now_epoch_ms",
            return_value=race_deadline,
        ),
        patch.object(
            db,
            "_policy_state_stale_candidate_rows",
            return_value=[oldest_locked, later_candidate],
        ),
        patch.object(
            db,
            "_reconcile_policy_state_bundle_on_connection",
            side_effect=reconcile_candidate,
        ),
    ):
        locked_oldest_result = db.reconcile_policy_state_bundles(
            limit=2,
            now_epoch_ms=race_deadline,
        )
    assert transition_order == [
        oldest_locked["reservation_id"],
        later_candidate["reservation_id"],
    ]
    assert locked_oldest_result["processed"] == 1
    assert locked_oldest_result["reservation_ids"] == [
        later_candidate["reservation_id"]
    ]


def exercise_release_authorization_v2_coordinator() -> None:
    actor_id = (
        "spiffe://test.serverware/decision-gate/release-authority-v2"
    )

    def case(suffix: str) -> dict[str, Any]:
        policy_hash = digest(f"release-v2-policy:{suffix}")
        route = SimpleNamespace(
            id=f"route.release-v2.{suffix}",
            credential_ref="cred-release-v2",
            constraints=(
                {
                    "id": f"release-v2-budget-{suffix}",
                    "type": "slidingWindowLimit",
                    "store": "shared",
                    "windowSeconds": 3600,
                    "max": 10,
                    "windowSemantics": "sliding",
                    "measure": "operationCount",
                    "reservationMode": "atomicReserveCommitRelease",
                    "onOverflow": "deny",
                    "key": {
                        "scope": [
                            "principal",
                            "credential",
                            "route",
                        ]
                    },
                },
                {
                    "id": f"release-v2-traversal-{suffix}",
                    "type": "traversalBudget",
                    "operations": ["search.read"],
                    "traversal": {
                        "store": "shared",
                        "phases": ["request", "response"],
                        "cursor": {
                            "requestSource": "query",
                            "requestField": "next_token",
                            "responseField": "meta.next_token",
                            "digest": "sha256",
                            "firstPageMayOmit": True,
                        },
                        "lineage": {
                            "scope": [
                                "principal",
                                "route",
                                "credential",
                                "credentialVersion",
                            ],
                            "queryFields": ["max_results", "query"],
                            "queryDigest": "sha256",
                        },
                        "limits": {
                            "maxPages": 3,
                            "maxLifetimeSeconds": 300,
                            "maxRecords": 30,
                            "maxDecodedBytes": 65536,
                        },
                        "accounting": {
                            "recordCountField": "data",
                            "byteSource": (
                                "validatedDecodedResponseBytes"
                            ),
                            "commit": (
                                "atomicAfterResponseValidation"
                            ),
                        },
                        "onReplay": "deny",
                        "onCrossLineage": "deny",
                        "onMissingEvidence": "deny",
                    },
                },
            ),
        )
        operation = {"operation": "search.read"}
        claims = shared_durable_budget_claims(
            route,
            principal_id="agent:release-v2",
            credential_ref=route.credential_ref,
            credential_version=7,
            policy_hash=policy_hash,
            operation_fields=operation,
        )
        claims.extend(
            traversal_budget_claims(
                route,
                principal_id="agent:release-v2",
                credential_ref=route.credential_ref,
                credential_version=7,
                policy_hash=policy_hash,
                operation_fields=operation,
                canonical_query_fields={
                    "max_results": "10",
                    "query": f"from:{suffix}",
                },
                request_cursor_values={},
            )
        )
        attempt_id = digest(f"release-v2-attempt:{suffix}")
        request_digest = digest(f"release-v2-request:{suffix}")
        operation_digest = digest(
            f"release-v2-operation:{suffix}"
        )
        quota = {
            "counter_key": digest(f"release-v2-quota:{suffix}"),
            "constraint_id": f"release-v2-quota-{suffix}",
            "operation": "search.read",
            "window_kind": "fixed",
            "window_seconds": 60,
            "max_count": 10,
        }
        claim_digest = policy_claim_digest(claims)
        durable_policy = {
            "actorId": actor_id,
            "claimDigest": claim_digest,
            "claims": claims,
        }
        binding = {
            "api_version": (
                "serverware.releaseAuthorizationBinding/v2"
            ),
            "attempt_id": attempt_id,
            "flow_id": attempt_id,
            "principal_id": "agent:release-v2",
            "route_id": route.id,
            "credential_id": route.credential_ref,
            "credential_version": 7,
            "policy_hash": policy_hash,
            "request_digest": request_digest,
            "operation_digest": operation_digest,
            "operation_context": operation,
            "require_jit_grant": False,
            "shared_quotas": [quota],
            "durable_policy": durable_policy,
        }
        return {
            "attempt_id": attempt_id,
            "route": route,
            "policy_hash": policy_hash,
            "request_digest": request_digest,
            "operation_digest": operation_digest,
            "operation": operation,
            "quota": quota,
            "claims": claims,
            "claim_digest": claim_digest,
            "durable_policy": durable_policy,
            "binding_digest": policy_claim_digest(binding),
        }

    def reserve(material: dict[str, Any]) -> dict[str, Any]:
        return db.reserve_release_authorization_v2(
            attempt_id=material["attempt_id"],
            flow_id=material["attempt_id"],
            principal_id="agent:release-v2",
            route_id=material["route"].id,
            credential_id=material["route"].credential_ref,
            credential_version=7,
            policy_hash=material["policy_hash"],
            request_digest=material["request_digest"],
            operation_digest=material["operation_digest"],
            operation_context=material["operation"],
            shared_quotas=[material["quota"]],
            require_jit_grant=False,
            reservation_ttl_seconds=60,
            durable_policy_binding=material["durable_policy"],
            actor_id=actor_id,
        )

    def transition(
        material: dict[str, Any],
        reserved: dict[str, Any],
        *,
        deadline: int,
    ) -> dict[str, Any]:
        durable = reserved["durable_policy"]
        return {
            "actorId": actor_id,
            "attemptId": material["attempt_id"],
            "claimDigest": material["claim_digest"],
            "reservationId": durable["reservation_id"],
            "dispatchDeadlineAtEpochMs": deadline,
        }

    def expect_conflict(call) -> None:
        try:
            call()
        except (
            db.ReleaseAuthorizationError,
            db.PolicyStateBundleStoreError,
        ):
            pass
        else:
            raise AssertionError(
                "release authority v2 accepted substituted state"
            )

    with (
        patch.object(
            db,
            "_validate_release_credential_authority",
            return_value=None,
        ),
        patch.object(
            db,
            "_revalidate_release_policy_authority",
            return_value=True,
        ),
    ):
        committed = case("committed")
        committed_reserve = reserve(committed)
        assert committed_reserve["binding_digest"] == committed[
            "binding_digest"
        ]
        assert committed_reserve["durable_policy"]["state"] == "reserved"
        committed_replay = reserve(committed)
        assert committed_replay["idempotent_replay"] is True
        assert committed_replay["durable_policy"] == committed_reserve[
            "durable_policy"
        ]
        expect_conflict(
            lambda: db.dispatch_release_authorization(
                attempt_id=committed["attempt_id"],
                binding_digest=committed["binding_digest"],
                dispatch_ttl_seconds=30,
                actor_id=actor_id,
            )
        )
        expect_conflict(
            lambda: db.complete_release_authorization(
                attempt_id=committed["attempt_id"],
                binding_digest=committed["binding_digest"],
                outcome="unknown",
                actor_id=actor_id,
            )
        )
        expect_conflict(
            lambda: db.cancel_release_authorization_if_present(
                attempt_id=committed["attempt_id"],
                binding_digest=committed["binding_digest"],
                actor_id=actor_id,
            )
        )

        quota_substitution = {
            **committed,
            "quota": {
                **committed["quota"],
                "max_count": 11,
            },
        }
        expect_conflict(lambda: reserve(quota_substitution))
        traversal_substitution = case("committed-substituted")
        traversal_substitution.update(
            {
                "attempt_id": committed["attempt_id"],
                "route": committed["route"],
                "policy_hash": committed["policy_hash"],
                "request_digest": committed["request_digest"],
                "operation_digest": committed["operation_digest"],
                "quota": committed["quota"],
            }
        )
        expect_conflict(lambda: reserve(traversal_substitution))

        dispatch_deadline = int(time.time() * 1000) + 30_000
        committed_transition = transition(
            committed,
            committed_reserve,
            deadline=dispatch_deadline,
        )
        for field, value in (
            ("actorId", "spiffe://forged.invalid/actor"),
            ("claimDigest", digest("substituted-claim")),
            ("reservationId", digest("substituted-reservation")),
            (
                "dispatchDeadlineAtEpochMs",
                dispatch_deadline + 1,
            ),
        ):
            substituted = {
                **committed_transition,
                field: value,
            }
            expect_conflict(
                lambda substituted=substituted: (
                    db.dispatch_release_authorization_v2(
                        attempt_id=committed["attempt_id"],
                        binding_digest=committed[
                            "binding_digest"
                        ],
                        actor_id=actor_id,
                        durable_policy_transition=substituted,
                    )
                )
            )
        dispatched = db.dispatch_release_authorization_v2(
            attempt_id=committed["attempt_id"],
            binding_digest=committed["binding_digest"],
            actor_id=actor_id,
            durable_policy_transition=committed_transition,
        )
        assert dispatched["durable_policy"]["state"] == "dispatched"
        dispatch_replay = db.dispatch_release_authorization_v2(
            attempt_id=committed["attempt_id"],
            binding_digest=committed["binding_digest"],
            actor_id=actor_id,
            durable_policy_transition=committed_transition,
        )
        assert dispatch_replay["idempotent_replay"] is True
        assert dispatch_replay["durable_policy"] == dispatched[
            "durable_policy"
        ]
        expect_conflict(
            lambda: db.complete_release_authorization_v2(
                attempt_id=committed["attempt_id"],
                binding_digest=committed["binding_digest"],
                outcome="not_forwarded",
                actor_id=actor_id,
                durable_policy_transition={
                    key: committed_transition[key]
                    for key in (
                        "actorId",
                        "attemptId",
                        "claimDigest",
                        "reservationId",
                    )
                },
            )
        )

        traversal_claim = committed["claims"][1]
        response_digest = digest("release-v2-response:committed")
        evidence = [
            {
                "constraint_id": traversal_claim["constraint_id"],
                "lineage_digest": traversal_claim["lineage_digest"],
                "request_cursor_digest": traversal_claim[
                    "request_cursor_digest"
                ],
                "response_digest": response_digest,
                "next_cursor_digest": digest(
                    "release-v2-next:committed"
                ),
                "record_count": 1,
                "decoded_bytes": 128,
                "validation": "passed",
            }
        ]
        forwarded_transition = {
            **committed_transition,
            "responseEvidence": evidence,
            "responseEvidenceDigest": policy_claim_digest(evidence),
            "responseBodySha256": response_digest,
        }
        completed = db.complete_release_authorization_v2(
            attempt_id=committed["attempt_id"],
            binding_digest=committed["binding_digest"],
            outcome="forwarded",
            actor_id=actor_id,
            durable_policy_transition=forwarded_transition,
        )
        assert completed["durable_policy"]["state"] == "committed"
        completed_replay = db.complete_release_authorization_v2(
            attempt_id=committed["attempt_id"],
            binding_digest=committed["binding_digest"],
            outcome="forwarded",
            actor_id=actor_id,
            durable_policy_transition=forwarded_transition,
        )
        assert completed_replay["idempotent_replay"] is True
        assert completed_replay["durable_policy"] == completed[
            "durable_policy"
        ]

        denied = case("denied")
        denied_reserve = reserve(denied)
        denied_deadline = int(time.time() * 1000) + 30_000
        denied_transition = transition(
            denied,
            denied_reserve,
            deadline=denied_deadline,
        )
        db.dispatch_release_authorization_v2(
            attempt_id=denied["attempt_id"],
            binding_digest=denied["binding_digest"],
            actor_id=actor_id,
            durable_policy_transition=denied_transition,
        )
        denied_claim = denied["claims"][1]
        denied_response_digest = digest(
            "release-v2-response:denied"
        )
        denied_evidence = [
            {
                "constraint_id": denied_claim["constraint_id"],
                "lineage_digest": denied_claim["lineage_digest"],
                "request_cursor_digest": denied_claim[
                    "request_cursor_digest"
                ],
                "response_digest": denied_response_digest,
                "next_cursor_digest": None,
                "record_count": 31,
                "decoded_bytes": 128,
                "validation": "passed",
            }
        ]
        denied_result = db.complete_release_authorization_v2(
            attempt_id=denied["attempt_id"],
            binding_digest=denied["binding_digest"],
            outcome="forwarded",
            actor_id=actor_id,
            durable_policy_transition={
                **denied_transition,
                "responseEvidence": denied_evidence,
                "responseEvidenceDigest": policy_claim_digest(
                    denied_evidence
                ),
                "responseBodySha256": denied_response_digest,
            },
        )
        assert denied_result["durable_policy"]["state"] == "denied"

        aborted = case("aborted")
        aborted_reserve = reserve(aborted)
        aborted_transition = transition(
            aborted,
            aborted_reserve,
            deadline=int(time.time() * 1000) + 30_000,
        )
        aborted_identity = {
            key: aborted_transition[key]
            for key in (
                "actorId",
                "attemptId",
                "claimDigest",
                "reservationId",
            )
        }
        aborted_result = db.complete_release_authorization_v2(
            attempt_id=aborted["attempt_id"],
            binding_digest=aborted["binding_digest"],
            outcome="not_forwarded",
            actor_id=actor_id,
            durable_policy_transition=aborted_identity,
        )
        assert aborted_result["durable_policy"]["state"] == "aborted"
        assert db.complete_release_authorization_v2(
            attempt_id=aborted["attempt_id"],
            binding_digest=aborted["binding_digest"],
            outcome="not_forwarded",
            actor_id=actor_id,
            durable_policy_transition=aborted_identity,
        )["idempotent_replay"] is True

        uncertain = case("indeterminate")
        uncertain_reserve = reserve(uncertain)
        uncertain_deadline = int(time.time() * 1000) + 30_000
        uncertain_transition = transition(
            uncertain,
            uncertain_reserve,
            deadline=uncertain_deadline,
        )
        db.dispatch_release_authorization_v2(
            attempt_id=uncertain["attempt_id"],
            binding_digest=uncertain["binding_digest"],
            actor_id=actor_id,
            durable_policy_transition=uncertain_transition,
        )
        uncertain_claim = uncertain["claims"][1]
        uncertain_response_digest = digest(
            "release-v2-response:uncertain"
        )
        uncertainty_reason = (
            "provider_outcome_or_response_validation_uncertain"
        )
        uncertainty_evidence = [
            {
                "constraint_id": uncertain_claim["constraint_id"],
                "lineage_digest": uncertain_claim["lineage_digest"],
                "request_cursor_digest": uncertain_claim[
                    "request_cursor_digest"
                ],
                "outcome": "indeterminate",
                "reason": uncertainty_reason,
                "response_body_sha256": uncertain_response_digest,
            }
        ]
        uncertain_identity = {
            key: uncertain_transition[key]
            for key in (
                "actorId",
                "attemptId",
                "claimDigest",
                "reservationId",
            )
        }
        unknown_transition = {
            **uncertain_identity,
            "responseEvidence": uncertainty_evidence,
            "responseEvidenceDigest": policy_claim_digest(
                uncertainty_evidence
            ),
            "failureReason": uncertainty_reason,
            "responseBodySha256": uncertain_response_digest,
            "uncertainty": "charged_fail_closed",
        }
        indeterminate = db.complete_release_authorization_v2(
            attempt_id=uncertain["attempt_id"],
            binding_digest=uncertain["binding_digest"],
            outcome="unknown",
            actor_id=actor_id,
            durable_policy_transition=unknown_transition,
        )
        assert indeterminate["durable_policy"]["state"] == (
            "indeterminate"
        )
        assert indeterminate["durable_policy"][
            "dispatch_deadline_at_epoch_ms"
        ] is None
        indeterminate_replay = db.complete_release_authorization_v2(
            attempt_id=uncertain["attempt_id"],
            binding_digest=uncertain["binding_digest"],
            outcome="unknown",
            actor_id=actor_id,
            durable_policy_transition=unknown_transition,
        )
        assert indeterminate_replay["idempotent_replay"] is True
        assert indeterminate_replay["durable_policy"] == indeterminate[
            "durable_policy"
        ]
        expect_conflict(
            lambda: db.complete_release_authorization_v2(
                attempt_id=uncertain["attempt_id"],
                binding_digest=uncertain["binding_digest"],
                outcome="unknown",
                actor_id=actor_id,
                durable_policy_transition={
                    **unknown_transition,
                    "dispatchDeadlineAtEpochMs": uncertain_deadline,
                },
            )
        )

        reconciled_case = case("reconciled-indeterminate")
        reconciled_reserve = reserve(reconciled_case)
        reconciled_deadline = int(time.time() * 1000) + 30_000
        reconciled_transition = transition(
            reconciled_case,
            reconciled_reserve,
            deadline=reconciled_deadline,
        )
        db.dispatch_release_authorization_v2(
            attempt_id=reconciled_case["attempt_id"],
            binding_digest=reconciled_case["binding_digest"],
            actor_id=actor_id,
            durable_policy_transition=reconciled_transition,
        )
        reconciliation = db.reconcile_release_authorizations(
            now_epoch_ms=reconciled_deadline,
            actor_id=actor_id,
        )
        assert reconciled_case["attempt_id"] in reconciliation["attempt_ids"]
        reconciled_claim = reconciled_case["claims"][1]
        reconciled_body_digest = db._POLICY_STATE_EMPTY_RESPONSE_DIGEST
        reconciled_evidence = [
            {
                "constraint_id": reconciled_claim["constraint_id"],
                "lineage_digest": reconciled_claim["lineage_digest"],
                "request_cursor_digest": reconciled_claim[
                    "request_cursor_digest"
                ],
                "outcome": "indeterminate",
                "reason": uncertainty_reason,
                "response_body_sha256": reconciled_body_digest,
            }
        ]
        reconciled_unknown = {
            key: reconciled_transition[key]
            for key in (
                "actorId",
                "attemptId",
                "claimDigest",
                "reservationId",
            )
        }
        reconciled_unknown.update(
            {
                "responseEvidence": reconciled_evidence,
                "responseEvidenceDigest": policy_claim_digest(
                    reconciled_evidence
                ),
                "failureReason": uncertainty_reason,
                "responseBodySha256": reconciled_body_digest,
                "uncertainty": "charged_fail_closed",
            }
        )
        reconciled_replay = db.complete_release_authorization_v2(
            attempt_id=reconciled_case["attempt_id"],
            binding_digest=reconciled_case["binding_digest"],
            outcome="unknown",
            actor_id=actor_id,
            durable_policy_transition=reconciled_unknown,
        )
        assert reconciled_replay["idempotent_replay"] is True
        assert reconciled_replay["durable_policy"][
            "dispatch_deadline_at_epoch_ms"
        ] is None
        expect_conflict(
            lambda: db.complete_release_authorization_v2(
                attempt_id=reconciled_case["attempt_id"],
                binding_digest=reconciled_case["binding_digest"],
                outcome="unknown",
                actor_id=actor_id,
                durable_policy_transition={
                    **reconciled_unknown,
                    "dispatchDeadlineAtEpochMs": reconciled_deadline,
                },
            )
        )


def main() -> None:
    db.init_db()
    with db.connect() as conn:
        policy_state_columns = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(policy_state_bundles)"
            ).fetchall()
        }
        migrated = conn.execute(
            "SELECT window_kind, window_start_epoch_ms, window_end_epoch_ms "
            "FROM rate_limit_counters WHERE counter_key = ?",
            ("sha256:" + "f" * 64,),
        ).fetchone()
    assert {
        "release_binding_digest",
        "dispatch_started_at_epoch_ms",
        "dispatch_deadline_at_epoch_ms",
    }.issubset(policy_state_columns)
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
    exercise_durable_budgets()
    exercise_traversal_budgets()
    exercise_atomic_policy_state_bundles()
    exercise_release_authorization_v2_coordinator()
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
