#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import statistics
import time
import urllib.error
import urllib.request
from typing import Any


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round((pct / 100.0) * (len(ordered) - 1))))
    return ordered[index]


def request_json(
    url: str,
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    method: str | None = None,
) -> dict[str, Any]:
    data = None if payload is None else json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    if payload is not None:
        request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read())


def bootstrap(base: str, admin_token: str) -> tuple[int, dict[str, str]]:
    data = request_json(f"{base.rstrip('/')}/api/bootstrap", headers={"X-Serverware-Admin-Token": admin_token})
    credential = next(item for item in data["credentials"] if item["id"] == "cred-demo-bearer")
    metadata = {str(k): str(v) for k, v in (credential.get("metadata") or {}).items()}
    return int(credential["credential_version"]), metadata


def update_demo_credential(base: str, admin_token: str, secret: str, metadata: dict[str, str]) -> int:
    data = request_json(
        f"{base.rstrip('/')}/api/credentials/cred-demo-bearer",
        payload={"secret": secret, "metadata": metadata},
        headers={"X-Serverware-Admin-Token": admin_token},
        method="PUT",
    )
    return int(data["credential_version"])


def decide(base: str, payload: dict[str, Any]) -> dict[str, Any]:
    return request_json(f"{base.rstrip('/')}/v1/decide", payload)


def create_grant(base: str, payload: dict[str, Any]) -> dict[str, Any]:
    return request_json(f"{base.rstrip('/')}/v1/grants", payload)


def assert_decision(name: str, decision: dict[str, Any], action: str, error: str | None = None) -> None:
    if decision.get("action") != action:
        raise AssertionError(f"{name}: expected action {action}, got {decision}")
    if error and (decision.get("payload") or {}).get("error") != error:
        raise AssertionError(f"{name}: expected error {error}, got {decision}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark the Rust Serverware data-plane decision gate.")
    parser.add_argument("--gate", default=os.getenv("DECISION_GATE_BASE", "http://localhost:9090"))
    parser.add_argument("--serverware", default=os.getenv("BASE", "http://localhost:3000"))
    parser.add_argument("--admin-token", default=os.getenv("SERVERWARE_ADMIN_TOKEN", "dev-admin-token"))
    parser.add_argument("--requests", type=int, default=1000)
    parser.add_argument("--warmup", type=int, default=100)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    credential_version, metadata = bootstrap(args.serverware, args.admin_token)
    base_payload: dict[str, Any] = {
        "clientIp": "127.0.0.1",
        "method": "GET",
        "url": "https://demo-upstream:8443/echo",
        "headers": {"X-Serverware-Agent": "demo-agent"},
        "credentialMetadata": {"cred-demo-bearer": {"x_app_id": "caller-spoofed-app"}},
    }

    if args.self_test:
        health = request_json(f"{args.gate.rstrip('/')}/healthz")
        shared_jit_store = health.get("jit_grant_store") == "shared"
        if health.get("credential_leases", 0) < 1:
            raise AssertionError(f"Rust gate did not load broker credential leases: {health}")
        echo = decide(args.gate, base_payload)
        assert_decision("echo allow", echo, "allow")
        injection = echo.get("injection") or {}
        if injection.get("secret_available") is not True or "demo-token-from-vault" in json.dumps(injection):
            raise AssertionError(f"decision must prove secret lease presence without returning the secret: {echo}")
        proxy_auth_payload = {
            **base_payload,
            "headers": {
                "X-Serverware-Agent": "demo-token-agent",
                "Proxy-Authorization": "Bearer demo-agent-proxy-token",
            },
        }
        assert_decision("proxy auth principal allow", decide(args.gate, proxy_auth_payload), "allow")
        assert_decision(
            "proxy auth missing token denies",
            decide(args.gate, {**proxy_auth_payload, "headers": {"X-Serverware-Agent": "demo-token-agent"}}),
            "deny",
            "client_principal_denied",
        )
        assert_decision(
            "proxy auth bad token denies",
            decide(
                args.gate,
                {
                    **proxy_auth_payload,
                    "headers": {
                        "X-Serverware-Agent": "demo-token-agent",
                        "Proxy-Authorization": "Bearer wrong-token",
                    },
                },
            ),
            "deny",
            "client_principal_denied",
        )
        assert_decision(
            "source-bound proxy auth principal allow",
            decide(
                args.gate,
                {
                    **base_payload,
                    "headers": {
                        "X-Serverware-Agent": "demo-bound-agent",
                        "Proxy-Authorization": "Bearer demo-bound-proxy-token",
                    },
                },
            ),
            "allow",
        )
        assert_decision(
            "source-bound proxy auth wrong source denies",
            decide(
                args.gate,
                {
                    **base_payload,
                    "clientIp": "198.51.100.42",
                    "headers": {
                        "X-Serverware-Agent": "demo-bound-agent",
                        "Proxy-Authorization": "Bearer demo-bound-proxy-token",
                    },
                },
            ),
            "deny",
            "client_principal_denied",
        )
        assert_decision(
            "unknown route",
            decide(args.gate, {**base_payload, "url": "https://demo-upstream:8443/not-allowed"}),
            "deny",
            "unknown_route_denied",
        )
        gmail_rewrite = decide(
            args.gate,
            {
                **base_payload,
                "url": "https://demo-upstream:8443/gmail/v1/users/me/messages?q=newer_than%3A3650d&maxResults=500",
            },
        )
        assert_decision("gmail weak query rewrite", gmail_rewrite, "allow")
        rewrite_query = ((gmail_rewrite.get("rewrite") or {}).get("query") or {})
        if rewrite_query.get("q") != "newer_than:30d" or int(rewrite_query.get("maxResults", 0)) != 10:
            raise AssertionError(f"gmail weak query was not tightened by policy: {gmail_rewrite}")
        assert_decision(
            "gmail unproven direct read",
            decide(args.gate, {**base_payload, "url": "https://demo-upstream:8443/gmail/v1/users/me/messages/pending-message-1"}),
            "deny",
            "gmail_message_age_not_proven",
        )
        assert_decision(
            "x write missing body denied",
            decide(args.gate, {**base_payload, "method": "POST", "url": "https://demo-upstream:8443/2/tweets"}),
            "deny",
            "json_body_missing",
        )
        assert_decision(
            "npm publish missing fields",
            decide(
                args.gate,
                {
                    **base_payload,
                    "method": "PUT",
                    "url": "https://demo-upstream:8443/npm/demo-package",
                    "headers": {"X-Serverware-Agent": "demo-agent", "Content-Type": "application/json"},
                    "body": json.dumps({"name": "demo-package", "version": "1.2.3"}),
                },
            ),
            "deny",
            "npm_publish_missing_fields",
        )
        npm_publish_payload = {
            **base_payload,
            "method": "PUT",
            "url": "https://demo-upstream:8443/npm/demo-package",
            "headers": {"X-Serverware-Agent": "demo-agent", "Content-Type": "application/json"},
            "body": json.dumps({"name": "demo-package", "version": "1.2.3", "tarball_integrity": "sha512-demo"}),
        }
        npm_jit = decide(args.gate, npm_publish_payload)
        assert_decision("npm publish requires jit", npm_jit, "jit_required")
        grant = create_grant(
            args.gate,
            {
                "grantId": "selftest-npm-publish",
                "approvalId": "approval-selftest",
                "principalId": npm_jit["principal_id"],
                "routeId": npm_jit["route_id"],
                "credentialRef": npm_jit["credential_ref"],
                "credentialVersion": npm_jit["credential_version"],
                "policyHash": npm_jit["policy_hash"],
                "requestDigest": npm_jit["request_digest"],
                "operationDigest": npm_jit["operation_digest"],
                "maxUses": 1,
                "ttlSeconds": 30,
            },
        )
        if grant.get("ok") is not True:
            raise AssertionError(f"grant create failed: {grant}")
        npm_allowed = decide(args.gate, npm_publish_payload)
        if shared_jit_store:
            assert_decision("local grant cache is ignored when shared JIT store is enabled", npm_allowed, "jit_required")
            if (npm_allowed.get("jit") or {}).get("grant_store") != "shared":
                raise AssertionError(f"expected shared JIT grant store decision: {npm_allowed}")
        else:
            assert_decision("npm publish grant consumed", npm_allowed, "allow")
            jit = npm_allowed.get("jit") or {}
            if jit.get("grant_consumed") is not True or jit.get("grant_id") != "selftest-npm-publish":
                raise AssertionError(f"grant was not consumed atomically: {npm_allowed}")
            assert_decision("npm publish grant cannot be reused", decide(args.gate, npm_publish_payload), "jit_required")

        stale_jit = decide(args.gate, npm_publish_payload)
        if not shared_jit_store:
            stale_grant = create_grant(
                args.gate,
                {
                    "grantId": "selftest-stale-after-rotation",
                    "approvalId": "approval-selftest-stale",
                    "principalId": stale_jit["principal_id"],
                    "routeId": stale_jit["route_id"],
                    "credentialRef": stale_jit["credential_ref"],
                    "credentialVersion": stale_jit["credential_version"],
                    "policyHash": stale_jit["policy_hash"],
                    "requestDigest": stale_jit["request_digest"],
                    "operationDigest": stale_jit["operation_digest"],
                    "maxUses": 1,
                    "ttlSeconds": 30,
                },
            )
            if stale_grant.get("ok") is not True:
                raise AssertionError(f"stale grant setup failed: {stale_grant}")
        rotated_version = update_demo_credential(
            args.serverware,
            args.admin_token,
            f"rotated-for-rust-gate-{int(time.time())}",
            metadata,
        )
        stale_version_payload = {
            **base_payload,
            "credentialVersions": {"cred-demo-bearer": credential_version},
        }
        for _ in range(40):
            rotated_decision = decide(args.gate, stale_version_payload)
            if rotated_decision.get("credential_version") == rotated_version:
                break
            time.sleep(0.1)
        else:
            raise AssertionError(f"Rust gate did not observe rotated credential generation {rotated_version}")
        if rotated_decision["action"] != "allow":
            raise AssertionError(f"echo route should still allow after rotation: {rotated_decision}")
        stale_npm_payload = {
            **npm_publish_payload,
            "credentialVersions": {"cred-demo-bearer": credential_version},
        }
        stale_after_rotation = decide(args.gate, stale_npm_payload)
        assert_decision("stale JIT grant cannot survive credential rotation", stale_after_rotation, "jit_required")
        if stale_after_rotation.get("credential_version") != rotated_version:
            raise AssertionError(f"decision did not use broker credential version: {stale_after_rotation}")
        credential_version = rotated_version

    latencies_ms: list[float] = []
    for index in range(args.warmup + args.requests):
        start = time.perf_counter()
        decision = decide(args.gate, base_payload)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        if decision.get("action") != "allow" or decision.get("route_id") != "demo.echo":
            raise SystemExit(f"unexpected decision: {decision}")
        if index >= args.warmup:
            latencies_ms.append(elapsed_ms)

    result = {
        "candidate": "rust-decision-gate",
        "url": f"{args.gate.rstrip('/')}/v1/decide",
        "requests": args.requests,
        "warmup": args.warmup,
        "p50_ms": round(statistics.median(latencies_ms), 3),
        "p95_ms": round(percentile(latencies_ms, 95), 3),
        "p99_ms": round(percentile(latencies_ms, 99), 3),
        "min_ms": round(min(latencies_ms), 3),
        "max_ms": round(max(latencies_ms), 3),
        "mean_ms": round(statistics.mean(latencies_ms), 3),
        "credential_version": credential_version,
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except urllib.error.URLError as exc:
        raise SystemExit(f"decision gate benchmark failed: {exc}") from exc
