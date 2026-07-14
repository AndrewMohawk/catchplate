#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import socket
import statistics
import time
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit


MANAGEMENT_TOKEN = os.getenv("SERVERWARE_DATA_PLANE_AUDIT_TOKEN", "").strip() or "dev-data-plane-audit-token"
MANAGEMENT_HEADERS = {"X-Serverware-Data-Plane-Token": MANAGEMENT_TOKEN}
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


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


def request_head_only(
    base: str,
    target: str,
    headers: dict[str, str] | None = None,
    *,
    method: str = "POST",
    content_length: int = 1048576,
) -> tuple[int, dict[str, Any]]:
    parsed = urlsplit(base)
    if parsed.scheme != "http" or not parsed.hostname:
        raise AssertionError(f"head-only listener probe requires an http URL: {base}")
    port = parsed.port or 80
    if target.startswith("/"):
        target = f"{parsed.path.rstrip('/')}{target}"
    lines = [
        f"{method} {target} HTTP/1.1",
        f"Host: {parsed.hostname}:{port}",
        "Content-Type: application/json",
        f"Content-Length: {content_length}",
        "Connection: close",
    ]
    lines.extend(f"{name}: {value}" for name, value in (headers or {}).items())
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")
    with socket.create_connection((parsed.hostname, port), timeout=3) as sock:
        sock.settimeout(3)
        sock.sendall(raw)
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
    head, separator, body = response.partition(b"\r\n\r\n")
    if not separator:
        raise AssertionError(f"listener did not reject from request headers: {response!r}")
    status = int(head.split(b" ", 2)[1])
    return status, json.loads(body)


def bootstrap(base: str, admin_token: str) -> tuple[int, dict[str, Any]]:
    data = request_json(f"{base.rstrip('/')}/api/bootstrap", headers={"X-Serverware-Admin-Token": admin_token})
    credential = next(item for item in data["credentials"] if item["id"] == "cred-demo-bearer")
    metadata = dict(credential.get("metadata") or {})
    return int(credential["credential_version"]), metadata


def update_demo_credential(base: str, admin_token: str, secret: str, metadata: dict[str, Any]) -> int:
    data = request_json(
        f"{base.rstrip('/')}/api/credentials/cred-demo-bearer",
        payload={"secret": secret, "metadata": metadata},
        headers={"X-Serverware-Admin-Token": admin_token},
        method="PUT",
    )
    return int(data["credential_version"])


def decide(base: str, payload: dict[str, Any]) -> dict[str, Any]:
    return request_json(f"{base.rstrip('/')}/v1/decide", payload, headers=MANAGEMENT_HEADERS)


def create_grant(base: str, payload: dict[str, Any]) -> dict[str, Any]:
    return request_json(f"{base.rstrip('/')}/v1/grants", payload, headers=MANAGEMENT_HEADERS)


def measured_attestation(base: str) -> dict[str, str]:
    nonce = secrets.token_urlsafe(24)
    attestation = request_json(f"{base.rstrip('/')}/attestation?nonce={nonce}")
    if attestation.get("nonce") != nonce:
        raise AssertionError("decision-gate attestation did not echo the benchmark nonce")
    fields = {
        "data_plane_binary_digest": attestation.get("data_plane_binary_digest"),
        "policy_hash": attestation.get("policy_bundle_digest"),
        "runtime_manifest_digest": attestation.get("runtime_manifest_digest"),
    }
    for name, value in fields.items():
        if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
            raise AssertionError(f"decision-gate attestation has invalid {name}: {value!r}")
    runtime_manifest = attestation.get("runtime_manifest")
    if not isinstance(runtime_manifest, dict):
        raise AssertionError("decision-gate attestation is missing its runtime manifest")
    if runtime_manifest.get("binary_digest") != fields["data_plane_binary_digest"]:
        raise AssertionError("decision-gate runtime manifest does not bind the attested binary digest")
    if runtime_manifest.get("policy_hash") != fields["policy_hash"]:
        raise AssertionError("decision-gate runtime manifest does not bind the attested policy hash")
    return {**fields, "nonce": nonce}


def assert_decision(name: str, decision: dict[str, Any], action: str, error: str | None = None) -> None:
    if decision.get("action") != action:
        raise AssertionError(f"{name}: expected action {action}, got {decision}")
    if error and (decision.get("payload") or {}).get("error") != error:
        raise AssertionError(f"{name}: expected error {error}, got {decision}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark the Rust Serverware data-plane decision gate.")
    parser.add_argument("--gate", default=os.getenv("DECISION_GATE_BASE", "http://localhost:9091"))
    parser.add_argument("--proxy", default=os.getenv("PROXY", "http://localhost:8080"))
    parser.add_argument("--serverware", default=os.getenv("BASE", "http://localhost:3000"))
    parser.add_argument("--admin-token", default=os.getenv("SERVERWARE_ADMIN_TOKEN", "dev-admin-token"))
    parser.add_argument("--requests", type=int, default=1000)
    parser.add_argument("--warmup", type=int, default=100)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    credential_version, metadata = bootstrap(args.serverware, args.admin_token)
    attestation_before = measured_attestation(args.gate)
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
        for path in ("/v1/decide", "/v1/grants"):
            status, denial = request_head_only(args.gate, path)
            if status != 401 or denial.get("error") != "management_auth_required":
                raise AssertionError(f"unexpected unauthenticated management denial for {path}: {status} {denial}")
            status, denial = request_head_only(
                args.gate,
                path,
                {"X-Serverware-Data-Plane-Token": "incorrect-management-token"},
            )
            if status != 401 or denial.get("error") != "management_auth_required":
                raise AssertionError(f"unexpected wrong-token management denial for {path}: {status} {denial}")
            status, denial = request_head_only(args.proxy, path, MANAGEMENT_HEADERS)
            if status != 404 or denial.get("error") != "not_found":
                raise AssertionError(f"unexpected public-listener denial for {path}: {status} {denial}")
        for method, target in (
            ("CONNECT", "demo-upstream:8443"),
            ("GET", "https://demo-upstream:8443/echo"),
        ):
            status, denial = request_head_only(
                args.gate,
                target,
                MANAGEMENT_HEADERS,
                method=method,
            )
            if status != 404 or denial.get("error") != "not_found":
                raise AssertionError(
                    f"management listener accepted proxy traffic {method} {target}: {status} {denial}"
                )
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
        x_missing_body = decide(
            args.gate,
            {**base_payload, "method": "POST", "url": "https://demo-upstream:8443/2/tweets"},
        )
        x_missing_body_error = (x_missing_body.get("payload") or {}).get("error")
        if x_missing_body.get("action") != "deny" or x_missing_body_error not in {
            "json_body_missing",
            "credential_rate_limit_exceeded",
        }:
            raise AssertionError(f"x write missing body was not denied: {x_missing_body}")
        assert_decision(
            "npm publish missing fields",
            decide(
                args.gate,
                {
                    **base_payload,
                    "method": "PUT",
                    "url": "https://demo-upstream:8443/npm/demo-package",
                    "headers": {"X-Serverware-Agent": "demo-agent", "Content-Type": "application/json"},
                    "body": json.dumps(
                        {
                            "name": "demo-package",
                            "dist-tags": {"latest": "1.2.3"},
                            "versions": {"1.2.3": {"version": "1.2.3", "dist": {}}},
                        }
                    ),
                },
            ),
            "deny",
            "npm_publish_attachment_missing",
        )
        npm_publish_payload = {
            **base_payload,
            "method": "PUT",
            "url": "https://demo-upstream:8443/npm/demo-package",
            "headers": {"X-Serverware-Agent": "demo-agent", "Content-Type": "application/json"},
            "body": json.dumps(
                {
                    "name": "demo-package",
                    "dist-tags": {"latest": "1.2.3"},
                    "versions": {
                        "1.2.3": {
                            "version": "1.2.3",
                            "dist": {"integrity": "sha512-demo"},
                        }
                    },
                }
            ),
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
        # The scoped recipient-bound lease has a five-second maximum TTL, so
        # rotation must become authoritative after that bounded cache window.
        for _ in range(80):
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
        for _ in range(80):
            stale_after_rotation = decide(args.gate, stale_npm_payload)
            if stale_after_rotation.get("credential_version") == rotated_version:
                break
            time.sleep(0.1)
        else:
            raise AssertionError(
                f"NPM route lease did not observe rotated credential generation {rotated_version}"
            )
        assert_decision("stale JIT grant cannot survive credential rotation", stale_after_rotation, "jit_required")
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

    attestation_after = measured_attestation(args.gate)
    for field in ("data_plane_binary_digest", "policy_hash", "runtime_manifest_digest"):
        if attestation_after[field] != attestation_before[field]:
            raise AssertionError(f"decision-gate {field} changed during the benchmark")

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
        "data_plane_binary_digest": attestation_before["data_plane_binary_digest"],
        "policy_hash": attestation_before["policy_hash"],
        "runtime_manifest_digest": attestation_before["runtime_manifest_digest"],
        "attestation_nonce_before": attestation_before["nonce"],
        "attestation_nonce_after": attestation_after["nonce"],
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except urllib.error.URLError as exc:
        raise SystemExit(f"decision gate benchmark failed: {exc}") from exc
