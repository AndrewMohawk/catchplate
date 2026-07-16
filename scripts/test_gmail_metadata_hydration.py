#!/usr/bin/env python3
from __future__ import annotations

import json
import hashlib
import sys
import time
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from urllib.parse import parse_qsl, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

try:
    import mitmproxy  # noqa: F401
except ModuleNotFoundError:
    mitmproxy_module = types.ModuleType("mitmproxy")
    http_module = types.ModuleType("mitmproxy.http")
    connection_module = types.ModuleType("mitmproxy.connection")
    tls_module = types.ModuleType("mitmproxy.tls")
    http_module.HTTPFlow = object
    http_module.Response = SimpleNamespace(make=lambda status, body, headers: Response(body, status))
    connection_module.Client = object
    connection_module.ConnectionState = SimpleNamespace(CLOSED="closed")
    tls_module.ClientHelloData = object
    mitmproxy_module.http = http_module
    mitmproxy_module.connection = connection_module
    mitmproxy_module.tls = tls_module
    sys.modules["mitmproxy"] = mitmproxy_module
    sys.modules["mitmproxy.http"] = http_module
    sys.modules["mitmproxy.connection"] = connection_module
    sys.modules["mitmproxy.tls"] = tls_module

from serverware import http_client
from serverware import adapters, mitm_addon, policy_engine
from serverware.policy_bundle import CredentialPolicy
from serverware.policies import PolicyDecision


def epoch_ms_days_ago(days: int) -> str:
    return str(int((datetime.now(timezone.utc) - timedelta(days=days)).timestamp() * 1000))


class Request:
    def __init__(self, url: str, headers: dict[str, str] | None = None) -> None:
        self.method = "GET"
        self.pretty_url = url
        self.headers = dict(headers or {})
        self.query = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
        self.raw_content = b""


class Response:
    def __init__(self, payload: object, status_code: int = 200) -> None:
        self.status_code = status_code
        self.headers = {"content-type": "application/json"}
        self.raw_content = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.stream = False

    @property
    def content(self) -> bytes:
        return self.raw_content

    @content.setter
    def content(self, value: bytes) -> None:
        self.raw_content = value

    def get_text(self, strict: bool = False) -> str:
        return self.raw_content.decode("utf-8", errors="strict" if strict else "replace")

    def set_text(self, value: str) -> None:
        self.raw_content = value.encode("utf-8")


def gmail_route(*, allowed_fields: list[str] | None = None, max_messages: int = 10) -> SimpleNamespace:
    return SimpleNamespace(
        id="gmail.real.metadata",
        principals=("agent:test",),
        host="gmail.googleapis.com",
        port=444,
        scheme="https",
        credential_ref="credential:gmail",
        adapter_type="gmail.v1",
        constraints=(),
        jit={"required": True},
        adapter_config={
            "maxAgeDays": 30,
            "maxResults": max_messages,
            "cacheTtlSeconds": 1800,
            "response": {
                "validateInternalDate": True,
                "validateListByMetadataFetch": True,
                "metadataFetch": {
                    "maxMessages": max_messages,
                    "perRequestTimeoutMs": 250,
                    "totalTimeoutMs": 1000,
                    "maxBodyBytes": 4096,
                },
                "maxBodyBytes": 65536,
                "allowedFields": allowed_fields
                if allowed_fields is not None
                else ["id", "threadId", "snippet", "internalDate"],
                "allowedHeaders": [],
            },
        },
    )


def gmail_credential_policy() -> CredentialPolicy:
    return CredentialPolicy(
        id="credential:gmail",
        provider="google",
        provider_subject="subject:test",
        scopes=("https://www.googleapis.com/auth/gmail.readonly",),
        injection={
            "type": "bearer",
            "header": "Authorization",
            "prefix": "Bearer ",
            "field": "access_token",
        },
    )


def gmail_flow(payload: object, *, route: SimpleNamespace | None = None) -> SimpleNamespace:
    active_route = route or gmail_route()
    url = (
        "https://gmail.googleapis.com:444/gmail/v1/users/"
        "user%2Btag%40example.com/messages"
    )
    item = SimpleNamespace(
        request=Request(url, {"Authorization": "Bearer stable-token"}),
        response=Response(payload),
        metadata={},
        client_conn=SimpleNamespace(peername=("127.0.0.1", 12345)),
    )
    item.metadata.update(
        {
            "serverware_route": active_route,
            "serverware_params": {"user": "user%2Btag%40example.com"},
            "serverware_route_id": active_route.id,
            "serverware_principal_id": "agent:test",
            "serverware_policy_hash": "sha256:" + "1" * 64,
            "serverware_credential_id": active_route.credential_ref,
            "serverware_credential_version": 7,
            "serverware_request_digest": "sha256:" + "2" * 64,
            "serverware_operation_digest": "sha256:" + "3" * 64,
            "serverware_operation": {"operation": "gmail.messages.list"},
            "serverware_release_attempt_id": "attempt:gmail-parent",
            "serverware_release_binding_digest": "sha256:" + "4" * 64,
            "serverware_release_state": "dispatching",
            "serverware_release_grant_id": "grant:gmail-parent",
            "serverware_release_approval_request_id": "approval:gmail-parent",
            "serverware_release_dispatch_expires_at_epoch_ms": int(time.time() * 1000)
            + 10_000,
            "serverware_credential_policy": gmail_credential_policy(),
        }
    )
    item.metadata["serverware_credential_lease_binding"] = credential_lease().binding
    return item


def credential(token: str = "fresh-token", version: int = 7) -> dict[str, object]:
    return {
        "kind": "oauth2",
        "credential_version": version,
        "secret": json.dumps({"access_token": token}),
    }


def credential_lease(
    token: str = "stable-token",
    version: int = 7,
    *,
    expires_at_monotonic: float | None = None,
) -> policy_engine.runtime.BoundCredentialLease:
    loaded = credential(token, version)
    secret = str(loaded["secret"])
    return policy_engine.runtime.BoundCredentialLease(
        credential=loaded,
        binding=policy_engine.runtime.CredentialLeaseBinding(
            credential_id="credential:gmail",
            credential_version=version,
            secret_fingerprint="sha256:" + hashlib.sha256(secret.encode("utf-8")).hexdigest(),
            expires_at_monotonic=(
                time.monotonic() + 10
                if expires_at_monotonic is None
                else expires_at_monotonic
            ),
        ),
    )


class GmailMetadataHydrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.audit_records: list[tuple[str, dict[str, object]]] = []

    def record_audit(self, event_type: str, event: dict[str, object], *args, **kwargs):
        self.audit_records.append((event_type, event))
        return {"event_type": event_type}

    def common_patches(self):
        return (
            patch.object(adapters.db, "record_audit_event", side_effect=self.record_audit),
            patch.object(policy_engine.runtime, "log_request"),
        )

    def test_runtime_bound_lease_rejects_same_generation_secret_change(self) -> None:
        loaded = credential("stable-token")
        expires_at = time.monotonic() + 5
        cache_key = ("credential:gmail", 7)
        with policy_engine.runtime._credential_lock:
            previous_cache = dict(policy_engine.runtime._credential_cache)
            policy_engine.runtime._credential_cache.clear()
            policy_engine.runtime._credential_cache[cache_key] = (expires_at, loaded)
        try:
            with patch.object(policy_engine.runtime, "get_credential", return_value=loaded):
                bound = policy_engine.runtime.get_bound_credential_lease("credential:gmail")
            self.assertIsNotNone(bound)
            assert bound is not None
            self.assertEqual(bound.binding.credential_version, 7)
            self.assertEqual(bound.binding.expires_at_monotonic, expires_at)

            with patch.object(
                policy_engine.runtime,
                "get_credential",
                return_value=credential("changed-without-version"),
            ):
                self.assertIsNone(
                    policy_engine.runtime.get_bound_credential_lease("credential:gmail")
                )
        finally:
            with policy_engine.runtime._credential_lock:
                policy_engine.runtime._credential_cache.clear()
                policy_engine.runtime._credential_cache.update(previous_cache)

    def test_dispatch_lifecycle_retains_child_expiry(self) -> None:
        flow = gmail_flow({"messages": []})
        now_ms = int(time.time() * 1000)
        flow.metadata["serverware_release_authorization"] = {
            "attempt_id": "attempt:gmail-dispatch",
            "binding_digest": "sha256:" + "8" * 64,
            "state": "reserved",
            "dispatch_attempted": False,
            "reservation_expires_at_epoch_ms": now_ms + 10_000,
        }
        dispatch_response = {
            "authorized": True,
            "state": "dispatching",
            "reason": "dispatching",
            "attempt_id": "attempt:gmail-dispatch",
            "binding_digest": "sha256:" + "8" * 64,
            "idempotent_replay": False,
            "grant_id": None,
            "approval_request_id": None,
            "approval_status": None,
            "approval_expires_at": None,
            "approval_created": None,
            "reservation_expires_at_epoch_ms": now_ms + 10_000,
            "dispatch_started_at_epoch_ms": now_ms,
            "dispatch_expires_at_epoch_ms": now_ms + 5_000,
            "completion_outcome": None,
            "retry_after_seconds": 0,
        }
        with patch.object(
            policy_engine.runtime,
            "dispatch_release_authorization",
            return_value=dispatch_response,
        ):
            decision = policy_engine.dispatch_release_authorization(flow)
        self.assertTrue(decision.allowed, decision)
        self.assertEqual(
            flow.metadata["serverware_release_dispatch_expires_at_epoch_ms"],
            now_ms + 5_000,
        )
        self.assertEqual(
            flow.metadata["serverware_release_authorization"][
                "dispatch_expires_at_epoch_ms"
            ],
            now_ms + 5_000,
        )

    def test_hydrates_in_order_with_reacquired_auth_and_concrete_transport(self) -> None:
        flow = gmail_flow(
            {
                "messages": [
                    {"id": "m/1", "threadId": "thread-1"},
                    {"id": "already-recent", "internalDate": epoch_ms_days_ago(1)},
                    {"id": "m 2", "snippet": "parent-value"},
                ]
            }
        )
        child_payloads = iter(
            (
                {"id": "m/1", "internalDate": epoch_ms_days_ago(1), "ignored": "secret-one"},
                {"id": "m 2", "internalDate": epoch_ms_days_ago(2), "ignored": "secret-two"},
            )
        )
        cache = Mock()
        with self.common_patches()[0], self.common_patches()[1], patch.object(
            policy_engine.runtime, "get_bound_credential_lease", return_value=credential_lease()
        ) as get_credential_mock, patch.object(
            adapters.http_client, "request_json", side_effect=lambda *args, **kwargs: next(child_payloads)
        ) as request_json, patch.object(
            policy_engine.runtime, "cache_gmail_message_ids", cache
        ):
            prepared = policy_engine.prepare_response(flow)
            self.assertTrue(prepared.allowed, prepared)
            decision = policy_engine.evaluate_response(flow)

        self.assertTrue(decision.allowed, decision)
        self.assertEqual(get_credential_mock.call_count, 2)
        self.assertEqual(request_json.call_count, 2)
        first, second = request_json.call_args_list
        self.assertEqual(
            first.args[0],
            "https://gmail.googleapis.com:444/gmail/v1/users/"
            "user%2Btag%40example.com/messages/m%2F1?format=metadata&fields=id,internalDate",
        )
        self.assertEqual(
            second.args[0],
            "https://gmail.googleapis.com:444/gmail/v1/users/"
            "user%2Btag%40example.com/messages/m%202?format=metadata&fields=id,internalDate",
        )
        self.assertEqual(
            first.kwargs["headers"],
            {"Authorization": "Bearer stable-token"},
        )
        self.assertEqual(
            second.kwargs["headers"],
            {"Authorization": "Bearer stable-token"},
        )
        for call in request_json.call_args_list:
            self.assertEqual(call.kwargs["expected_statuses"], (200,))
            self.assertEqual(call.kwargs["expected_content_types"], ("application/json",))
            self.assertTrue(call.kwargs["require_https"])
            self.assertIsInstance(call.kwargs["deadline"], http_client.HttpDeadline)
        self.assertLessEqual(
            max(call.kwargs["deadline"].expires_at for call in request_json.call_args_list),
            flow.metadata["serverware_credential_lease_binding"].expires_at_monotonic,
        )
        self.assertEqual(flow.request.headers["Authorization"], "Bearer stable-token")

        released = json.loads(flow.response.get_text())
        self.assertEqual(
            [item["id"] for item in released["messages"]],
            ["m/1", "already-recent", "m 2"],
        )
        self.assertNotIn("ignored", released["messages"][0])
        self.assertEqual(released["messages"][2]["snippet"], "parent-value")
        cache.assert_called_once()
        self.assertEqual(cache.call_args.args[1], ["m/1", "already-recent", "m 2"])
        self.assertEqual(
            [event_type for event_type, _ in self.audit_records],
            [
                "data_plane.gmail.metadata_fanout.started",
                "data_plane.gmail.metadata_fanout.completed",
            ],
        )
        completed = self.audit_records[-1][1]
        self.assertEqual(completed["planned_count"], 2)
        self.assertEqual(completed["attempted_count"], 2)
        self.assertEqual(completed["hydrated_count"], 2)
        self.assertEqual(completed["binding_digest"], "sha256:" + "4" * 64)
        serialized_audit = json.dumps(self.audit_records, sort_keys=True)
        for sensitive in (
            "m/1",
            "m 2",
            "already-recent",
            "user+tag@example.com",
            "stable-token",
            "secret-one",
            "gmail.googleapis.com",
        ):
            self.assertNotIn(sensitive, serialized_audit)

    def test_transport_and_malformed_children_drop_without_reordering_survivors(self) -> None:
        ids = ["status-404", "status-429", "status-500", "timeout", "missing", "good"]
        flow = gmail_flow({"messages": [{"id": value} for value in ids]})
        results = iter(
            (
                http_client.HttpClientError("HTTP response status 404 is not allowed"),
                http_client.HttpClientError("HTTP response status 429 is not allowed"),
                http_client.HttpClientError("HTTP response status 500 is not allowed"),
                http_client.HttpClientError("HTTP request deadline exceeded"),
                {"id": "missing"},
                {"id": "good", "internalDate": epoch_ms_days_ago(1)},
            )
        )

        def request_json(*args, **kwargs):
            result = next(results)
            if isinstance(result, Exception):
                raise result
            return result

        with patch.object(adapters.db, "record_audit_event", side_effect=self.record_audit), patch.object(
            policy_engine.runtime, "log_request"
        ), patch.object(
            policy_engine.runtime,
            "get_bound_credential_lease",
            return_value=credential_lease(),
        ), patch.object(
            adapters.http_client, "request_json", side_effect=request_json
        ), patch.object(policy_engine.runtime, "cache_gmail_message_ids") as cache:
            prepared = policy_engine.prepare_response(flow)
            self.assertTrue(prepared.allowed, prepared)
            decision = policy_engine.evaluate_response(flow)

        self.assertTrue(decision.allowed, decision)
        released = json.loads(flow.response.get_text())
        self.assertEqual([item["id"] for item in released["messages"]], ["good"])
        self.assertEqual(cache.call_args.args[1], ["good"])
        completed = self.audit_records[-1][1]
        self.assertEqual(completed["planned_count"], 6)
        self.assertEqual(completed["attempted_count"], 6)
        self.assertEqual(completed["hydrated_count"], 1)
        self.assertEqual(completed["dropped_count"], 5)

    def test_duplicate_and_explicit_old_ids_deny_without_disclosure_or_fanout(self) -> None:
        cases = (
            (
                {
                    "messages": [
                        {"id": "dup-sensitive-value"},
                        {"id": "dup-sensitive-value"},
                    ]
                },
                "gmail_metadata_fetch_duplicate_id",
            ),
            (
                {"messages": [{"id": "old-sensitive-id", "internalDate": epoch_ms_days_ago(45)}]},
                "gmail_response_too_old",
            ),
            (
                {"messages": [{"id": "fractional-date", "internalDate": 1_800_000_000_000.5}]},
                "gmail_response_invalid_internal_date",
            ),
        )
        for payload, expected_error in cases:
            with self.subTest(expected_error=expected_error):
                flow = gmail_flow(payload)
                self.audit_records.clear()
                with patch.object(
                    adapters.db, "record_audit_event", side_effect=self.record_audit
                ), patch.object(policy_engine.runtime, "log_request"), patch.object(
                    adapters.http_client, "request_json"
                ) as request_json:
                    decision = policy_engine.prepare_response(flow)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.payload["error"], expected_error)
                for sensitive in ("dup-sensitive-value", "old-sensitive-id"):
                    self.assertNotIn(sensitive, json.dumps(decision.payload, sort_keys=True))
                request_json.assert_not_called()
                self.assertEqual(self.audit_records, [])

    def test_audit_failures_and_version_changes_fail_closed(self) -> None:
        start_failure = gmail_flow({"messages": [{"id": "start-audit-id"}]})
        with patch.object(adapters.db, "record_audit_event", side_effect=RuntimeError("down")), patch.object(
            policy_engine.runtime, "log_request"
        ), patch.object(adapters.http_client, "request_json") as request_json:
            decision = policy_engine.prepare_response(start_failure)
        self.assertEqual(decision.payload["error"], "gmail_metadata_fetch_start_audit_unavailable")
        request_json.assert_not_called()

        completion_failure = gmail_flow({"messages": [{"id": "completion-audit-id"}]})
        audit_calls = 0

        def fail_completion(*args, **kwargs):
            nonlocal audit_calls
            audit_calls += 1
            if audit_calls == 2:
                raise RuntimeError("down")
            return {"ok": True}

        with patch.object(adapters.db, "record_audit_event", side_effect=fail_completion), patch.object(
            policy_engine.runtime, "log_request"
        ), patch.object(
            policy_engine.runtime,
            "get_bound_credential_lease",
            return_value=credential_lease(),
        ), patch.object(
            adapters.http_client,
            "request_json",
            return_value={"id": "completion-audit-id", "internalDate": epoch_ms_days_ago(1)},
        ):
            decision = policy_engine.prepare_response(completion_failure)
        self.assertEqual(decision.payload["error"], "gmail_metadata_fetch_completion_audit_unavailable")

        changed = gmail_flow({"messages": [{"id": "changed-version-id"}]})
        self.audit_records.clear()
        with patch.object(adapters.db, "record_audit_event", side_effect=self.record_audit), patch.object(
            policy_engine.runtime, "log_request"
        ), patch.object(
            policy_engine.runtime,
            "get_bound_credential_lease",
            return_value=credential_lease(version=8),
        ), patch.object(
            adapters.http_client, "request_json"
        ) as request_json:
            decision = policy_engine.prepare_response(changed)
        self.assertEqual(decision.payload["error"], "gmail_metadata_fetch_credential_authority_changed")
        request_json.assert_not_called()
        self.assertEqual(self.audit_records[-1][1]["outcome"], "blocked")

    def test_old_hydrated_date_blocks_and_audits_without_id(self) -> None:
        sensitive_id = "old-hydrated-sensitive-id"
        flow = gmail_flow({"messages": [{"id": sensitive_id}]})
        with patch.object(adapters.db, "record_audit_event", side_effect=self.record_audit), patch.object(
            policy_engine.runtime, "log_request"
        ), patch.object(
            policy_engine.runtime,
            "get_bound_credential_lease",
            return_value=credential_lease(),
        ), patch.object(
            adapters.http_client,
            "request_json",
            return_value={"id": sensitive_id, "internalDate": epoch_ms_days_ago(45)},
        ):
            decision = policy_engine.prepare_response(flow)
        self.assertEqual(decision.payload["error"], "gmail_response_too_old")
        self.assertNotIn(sensitive_id, json.dumps(decision.payload, sort_keys=True))
        self.assertNotIn(sensitive_id, json.dumps(self.audit_records, sort_keys=True))
        self.assertEqual(self.audit_records[-1][1]["blocked_count"], 1)

    def test_proof_nonce_denied_and_cache_waits_for_all_guards_and_emission(self) -> None:
        route = gmail_route()
        for header in ("x-serverware-proof-nonce", "x-serverware-stream-proof-nonce"):
            with self.subTest(header=header):
                proof_flow = gmail_flow({"messages": []}, route=route)
                proof_flow.request.headers[header] = "nonce"
                decision = adapters.get_adapter("gmail.v1").validate_request(
                    proof_flow, route, {"user": "user%2Btag%40example.com"}
                )
                self.assertEqual(
                    decision.payload["error"],
                    "gmail_metadata_fetch_response_proof_unsupported",
                )

        reflected = gmail_flow(
            {"messages": [{"id": "reflected-id", "snippet": "stable-token"}]},
            route=route,
        )
        with patch.object(adapters.db, "record_audit_event", side_effect=self.record_audit), patch.object(
            policy_engine.runtime, "log_request"
        ), patch.object(
            policy_engine.runtime,
            "get_bound_credential_lease",
            return_value=credential_lease(),
        ), patch.object(
            adapters.http_client,
            "request_json",
            return_value={"id": "reflected-id", "internalDate": epoch_ms_days_ago(1)},
        ), patch.object(policy_engine.runtime, "cache_gmail_message_ids") as cache:
            self.assertTrue(policy_engine.prepare_response(reflected).allowed)
            decision = policy_engine.evaluate_response(reflected)
        self.assertEqual(decision.payload["error"], "response_credential_reflection")
        cache.assert_not_called()

    def test_child_fetches_cannot_outlive_or_change_parent_authority(self) -> None:
        cases = (
            (
                "expired-dispatch",
                lambda flow: flow.metadata.__setitem__(
                    "serverware_release_dispatch_expires_at_epoch_ms",
                    int(time.time() * 1000) - 1,
                ),
                credential_lease(),
                "gmail_metadata_fetch_release_authority_expired",
            ),
            (
                "missing-dispatch-expiry",
                lambda flow: flow.metadata.pop(
                    "serverware_release_dispatch_expires_at_epoch_ms"
                ),
                credential_lease(),
                "gmail_metadata_fetch_release_authority_expired",
            ),
            (
                "expired-parent-lease",
                lambda flow: flow.metadata.__setitem__(
                    "serverware_credential_lease_binding",
                    credential_lease(expires_at_monotonic=time.monotonic() - 1).binding,
                ),
                credential_lease(),
                "gmail_metadata_fetch_credential_authority_changed",
            ),
            (
                "same-version-secret-change",
                lambda flow: None,
                credential_lease(token="changed-without-version"),
                "gmail_metadata_fetch_credential_authority_changed",
            ),
            (
                "generation-change",
                lambda flow: None,
                credential_lease(version=8),
                "gmail_metadata_fetch_credential_authority_changed",
            ),
        )
        for name, mutate, child_lease, expected_error in cases:
            with self.subTest(name=name):
                flow = gmail_flow({"messages": [{"id": "authority-bound"}]})
                mutate(flow)
                self.audit_records.clear()
                with patch.object(
                    adapters.db, "record_audit_event", side_effect=self.record_audit
                ), patch.object(policy_engine.runtime, "log_request"), patch.object(
                    policy_engine.runtime,
                    "get_bound_credential_lease",
                    return_value=child_lease,
                ), patch.object(adapters.http_client, "request_json") as request_json:
                    decision = policy_engine.prepare_response(flow)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.payload["error"], expected_error)
                request_json.assert_not_called()

    def test_child_deadline_is_capped_by_parent_lease(self) -> None:
        route = gmail_route(max_messages=1)
        route.adapter_config["response"]["metadataFetch"].update(
            {"perRequestTimeoutMs": 3000, "totalTimeoutMs": 5000}
        )
        flow = gmail_flow({"messages": [{"id": "lease-capped"}]}, route=route)
        parent_expires_at = time.monotonic() + 0.600
        flow.metadata["serverware_credential_lease_binding"] = credential_lease(
            expires_at_monotonic=parent_expires_at
        ).binding
        flow.metadata["serverware_release_dispatch_expires_at_epoch_ms"] = (
            int(time.time() * 1000) + 2_000
        )
        with patch.object(
            adapters.db, "record_audit_event", side_effect=self.record_audit
        ), patch.object(policy_engine.runtime, "log_request"), patch.object(
            policy_engine.runtime,
            "get_bound_credential_lease",
            return_value=credential_lease(expires_at_monotonic=time.monotonic() + 5),
        ), patch.object(
            adapters.http_client,
            "request_json",
            return_value={"id": "lease-capped", "internalDate": epoch_ms_days_ago(1)},
        ) as request_json:
            decision = policy_engine.prepare_response(flow)
        self.assertTrue(decision.allowed, decision)
        self.assertLessEqual(request_json.call_args.kwargs["deadline"].expires_at, parent_expires_at)
        self.assertLess(request_json.call_args.kwargs["timeout"], 1.0)

    def test_metadata_fetch_runtime_contract_is_exact_and_bounded(self) -> None:
        mutations = (
            lambda route: route.adapter_config["response"]["metadataFetch"].__setitem__(
                "unexpected", True
            ),
            lambda route: route.adapter_config["response"]["metadataFetch"].__setitem__(
                "maxMessages", 33
            ),
            lambda route: route.adapter_config["response"]["metadataFetch"].__setitem__(
                "perRequestTimeoutMs", 3001
            ),
            lambda route: route.adapter_config["response"]["metadataFetch"].__setitem__(
                "totalTimeoutMs", 10001
            ),
            lambda route: route.adapter_config["response"]["metadataFetch"].__setitem__(
                "maxBodyBytes", 8193
            ),
            lambda route: route.adapter_config["response"]["metadataFetch"].update(
                {"perRequestTimeoutMs": 1001, "totalTimeoutMs": 1000}
            ),
            lambda route: route.adapter_config.__setitem__("maxResults", 5),
            lambda route: route.adapter_config["response"].__setitem__(
                "allowedFields", ["internalDate"]
            ),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                route = gmail_route(max_messages=10)
                mutate(route)
                flow = gmail_flow({"messages": [{"id": "contract-id"}]}, route=route)
                with patch.object(adapters.db, "record_audit_event") as audit, patch.object(
                    policy_engine.runtime, "log_request"
                ), patch.object(adapters.http_client, "request_json") as request_json:
                    decision = policy_engine.prepare_response(flow)
                self.assertFalse(decision.allowed)
                self.assertEqual(decision.payload["error"], "gmail_metadata_fetch_config_invalid")
                audit.assert_not_called()
                request_json.assert_not_called()

    def test_parent_release_completes_between_hydration_and_response_guards(self) -> None:
        addon = object.__new__(mitm_addon.ServerwareAddon)
        flow = gmail_flow({"messages": []})
        events: list[str] = []

        def prepare(_flow):
            events.append("prepare")
            return PolicyDecision(True)

        def complete(_flow, outcome):
            self.assertEqual(outcome, "forwarded")
            events.append("complete")
            return PolicyDecision(True)

        def evaluate(_flow):
            events.append("evaluate")
            return PolicyDecision(True)

        with patch.object(mitm_addon, "prepare_response", side_effect=prepare), patch.object(
            mitm_addon, "complete_release_authorization", side_effect=complete
        ), patch.object(mitm_addon, "evaluate_response", side_effect=evaluate):
            addon.response(flow)
        self.assertEqual(events, ["prepare", "complete", "evaluate"])


if __name__ == "__main__":
    unittest.main()
