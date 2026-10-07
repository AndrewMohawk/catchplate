#!/usr/bin/env python3
"""Exercise the isolated synthetic sandbox's real Rust HTTPS proxy and audit API.

Run inside a bounded client on the sandbox-only network. This is engineering
acceptance, never hardware, native-pilot, or production acceptance. No requests
are made until the control plane explicitly identifies the synthetic profile.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import time
from typing import Any
from urllib.parse import urlencode, urlsplit
import uuid


MAX_BODY = 2 * 1024 * 1024
UPSTREAM = "demo-upstream"
AUTHORITY = f"{UPSTREAM}:8443"


def require(condition: bool, label: str) -> None:
    if not condition:
        raise RuntimeError(label)


def token_file(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 4096,
                "admin token must be a bounded regular file")
        require(stat.S_IMODE(info.st_mode) in {0o400, 0o440, 0o600, 0o640},
                "admin token file permissions are too broad")
        payload = os.read(descriptor, 4097)
        require(len(payload) == info.st_size, "admin token changed during read")
    finally:
        os.close(descriptor)
    value = payload.decode("ascii").rstrip("\r\n")
    require(bool(value) and value == value.strip() and not any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ), "admin token has invalid framing")
    return value


def response_json(response: http.client.HTTPResponse) -> tuple[int, Any]:
    body = response.read(MAX_BODY + 1)
    require(len(body) <= MAX_BODY, "response exceeds the acceptance body bound")
    return response.status, json.loads(body)


class SandboxCheck:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.run_id = f"sandbox-check-{uuid.uuid4().hex}"
        self.client_secret = f"synthetic-client-secret-{uuid.uuid4().hex}"
        self.admin_token: str | None = None
        self.ca = ssl.create_default_context(cafile=str(args.ca_file))
        self.upstream_ca = ssl.create_default_context(cafile=str(args.upstream_ca_file))
        self.results: list[str] = []
        self.deadline = time.monotonic() + 45
        self.control = urlsplit(args.control_base)
        require(self.control.scheme == "http" and self.control.hostname in {
            "serverware", "localhost", "127.0.0.1", "::1"
        } and self.control.path in {"", "/"} and not any((
            self.control.query, self.control.fragment, self.control.username,
            self.control.password,
        )), "control-base must be the direct local sandbox service")
        require(args.proxy_host in {"decision-gate-rs", "localhost", "127.0.0.1", "::1"},
                "proxy-host must be the direct local sandbox service")

    def timeout(self) -> float:
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, "sandbox acceptance exceeded its 45-second deadline")
        return min(3.0, remaining)

    def control_json(self, path: str, *, authenticated: bool = False) -> Any:
        headers = {}
        if authenticated:
            require(self.admin_token is not None, "admin token is not loaded")
            headers["X-Serverware-Admin-Token"] = self.admin_token
        connection = http.client.HTTPConnection(
            self.control.hostname, self.control.port or 80, timeout=self.timeout())
        try:
            connection.request("GET", path, headers=headers)
            status, document = response_json(connection.getresponse())
            require(status == 200, f"control API {path.split('?')[0]} returned HTTP {status}")
            return document
        finally:
            connection.close()

    def preflight(self) -> dict[str, Any]:
        profile = self.control_json("/api/sandbox/status")
        expected = {
            "schema": "serverware.developmentSandbox/v1",
            "mode": "synthetic-development", "syntheticOnly": True,
            "productionReady": False, "hardwareVerified": False,
            "persistent": True, "allowedUpstreams": [UPSTREAM],
            "commissioningRequired": False,
        }
        require(isinstance(profile, dict) and all(
            type(profile.get(key)) is type(value) and profile.get(key) == value
            for key, value in expected.items()
        ), "target is not the isolated synthetic development sandbox")
        connection = http.client.HTTPConnection(
            self.args.proxy_host, self.args.management_port, timeout=self.timeout())
        try:
            connection.request("GET", "/healthz")
            status, health = response_json(connection.getresponse())
        finally:
            connection.close()
        require(status == 200 and health.get("ok") is True, "Rust gate is not healthy")
        require(health.get("policy_shadow_serving_ready") is True
                and health.get("policy_shadow", {}).get("mode") == "synthetic-development"
                and health.get("policy_shadow", {}).get("enabled") is False
                and health.get("policy_shadow", {}).get("readiness") is False,
                "Rust gate has not selected the explicit uncommissioned sandbox profile")
        require(health.get("data_plane_binary_digest") == self.args.expected_binary_sha256,
                "Rust runtime does not match the selected build")
        require(health.get("policy_trust_root_source") == "attested-control-plane",
                "Rust gate is missing the local signed control-plane trust binding")
        require(health.get("connect_mitm_interceptor") is True, "CONNECT TLS is unavailable")
        require(health.get("release_authorization", {}).get("enabled") is False,
                "sandbox check requires the explicitly selected non-atomic development flow")
        require(health.get("audit", {}).get("enabled") is True,
                "Rust gate has no real audit delivery")
        self.admin_token = token_file(self.args.admin_token_file)
        self.results.append("synthetic_profile_and_exact_rust_build")
        return health

    def upstream_count(self, method: str) -> int:
        connection = http.client.HTTPSConnection(
            UPSTREAM, 8443, context=self.upstream_ca, timeout=self.timeout())
        try:
            connection.request("GET", "/_test/request-count?" + urlencode({
                "method": method, "path": "/echo", "run_id": self.run_id,
            }))
            status, payload = response_json(connection.getresponse())
            require(status == 200 and type(payload.get("count")) is int,
                    "synthetic upstream counter is unavailable")
            return payload["count"]
        finally:
            connection.close()

    def tunnel(self, *, agent: str | None = "demo-agent",
               proxy_authorization: str | None = None, port: int = 8443,
               expected_status: int = 200) -> socket.socket | None:
        raw = socket.create_connection((self.args.proxy_host, self.args.proxy_port), timeout=self.timeout())
        try:
            headers = [f"CONNECT {UPSTREAM}:{port} HTTP/1.1", f"Host: {UPSTREAM}:{port}"]
            if agent:
                headers.append(f"X-Serverware-Agent: {agent}")
            if proxy_authorization:
                headers.append(f"Proxy-Authorization: {proxy_authorization}")
            raw.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii"))
            head = bytearray()
            while not head.endswith(b"\r\n\r\n"):
                raw.settimeout(self.timeout())
                chunk = raw.recv(1)
                require(bool(chunk), "CONNECT closed before its response headers")
                head.extend(chunk)
                require(len(head) <= 16384, "CONNECT response headers exceed bound")
            status = int(head.split(b" ", 2)[1])
            require(status == expected_status,
                    f"CONNECT expected HTTP {expected_status}, received {status}")
            if status != 200:
                raw.close()
                return None
            return raw
        except BaseException:
            raw.close()
            raise

    def request(self, path: str, *, method: str = "GET", body: bytes = b"",
                sensitive_headers: bool = False,
                authorization_collision: bool = False) -> tuple[int, Any]:
        raw = self.tunnel()
        require(raw is not None, "CONNECT did not open a tunnel")
        with raw:
            raw.settimeout(self.timeout())
            with self.ca.wrap_socket(raw, server_hostname=UPSTREAM) as tls:
                headers = [f"{method} {path} HTTP/1.1", f"Host: {AUTHORITY}",
                           "X-Serverware-Agent: demo-agent", "Connection: close",
                           f"User-Agent: serverware-test-run/{self.run_id}"]
                if body:
                    headers.extend(["Content-Type: application/json", f"Content-Length: {len(body)}"])
                if sensitive_headers:
                    headers.extend([f"Cookie: sandbox={self.client_secret}",
                                    f"X-Serverware-Data-Plane-Token: {self.client_secret}"])
                if authorization_collision:
                    headers.append(f"Authorization: Bearer {self.client_secret}")
                tls.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + body)
                response = http.client.HTTPResponse(tls)
                response.begin()
                status, payload = response_json(response)
                serialized = json.dumps(payload)
                require(self.client_secret not in serialized and "demo-token-from-vault" not in serialized,
                        "a synthetic credential escaped response filtering")
                return status, payload

    def audit(self) -> list[dict[str, Any]]:
        events = self.control_json("/api/audit?limit=500", authenticated=True)
        require(isinstance(events, list), "audit API did not return stored events")
        return events

    def run(self) -> dict[str, Any]:
        health = self.preflight()
        before_ids = {event["id"] for event in self.audit()}
        require(all(self.upstream_count(method) == 0 for method in ("GET", "POST", "DELETE")),
                "fresh acceptance run unexpectedly has upstream traffic")
        self.tunnel(agent=None, expected_status=403)
        self.tunnel(agent="demo-token-agent", proxy_authorization="Bearer invalid-synthetic-token",
                    expected_status=403)
        self.tunnel(port=9443, expected_status=403)
        self.results.append("connect_identity_and_destination_denials")

        status, payload = self.request("/echo", authorization_collision=True)
        require(status == 403 and payload.get("reason") == "credential_injection_header_collision"
                and self.upstream_count("GET") == 0,
                "caller credential collision was not denied before upstream dispatch")
        self.results.append("caller_credential_collision_denied_without_dispatch")

        status, payload = self.request("/echo", sensitive_headers=True)
        require(status == 200 and payload.get("authorization_present") is True
                and payload.get("authorization_scheme") == "Bearer"
                and payload.get("credential_marker") == "initial"
                and payload.get("query", {}).get("_data_plane_token_seen") is False,
                "real credential injection or internal-header removal failed")
        require(not ({"authorization", "authorization_sha256", "proxy_authorization",
                      "serverware_agent", "cookie", "x_api_key"} & payload.keys()),
                "upstream credential fields escaped response redaction")
        self.results.append("connect_tls_credential_injection_and_header_redaction")

        status, _ = self.request("/not-allowed")
        require(status == 403, "unknown path was not denied")
        status, _ = self.request("/echo", method="DELETE")
        require(status == 403, "unapproved method was not denied")
        require(self.upstream_count("GET") == 1 and self.upstream_count("DELETE") == 0,
                "denied requests reached the synthetic echo upstream")
        self.results.append("route_denials_without_upstream_dispatch")

        status, payload = self.request("/echo?reflectCredential=1")
        require(status == 502 and payload == {"error": "response_credential_reflection"},
                "reflected synthetic credential was not blocked")
        self.results.append("credential_reflection_blocked")

        marker_body = json.dumps({"audit_marker": self.run_id}, separators=(",", ":"),
                                 sort_keys=True).encode("ascii")
        body_digest = "sha256:" + hashlib.sha256(marker_body).hexdigest()
        status, _ = self.request("/echo", method="POST", body=marker_body)
        require(status == 200, "audited POST did not traverse the real proxy")

        nested = {
            "requestId": self.run_id,
            "profile": {"email": "sandbox@example.test", "secret": self.client_secret,
                        "settings": {"theme": "dark", "token": self.client_secret}},
            "items": [{"id": 1, "secret": self.client_secret,
                       "details": {"safe": "kept", "secret": self.client_secret}}],
            "audit": {"trace": self.run_id, "privateToken": self.client_secret},
            "secret": self.client_secret,
        }
        status, payload = self.request("/json-nested-redact", method="POST",
                                       body=json.dumps(nested, separators=(",", ":")).encode("ascii"))
        require(status == 200 and payload == {
            "requestId": self.run_id,
            "profile": {"email": "sandbox@example.test", "settings": {"theme": "dark"}},
            "items": [{"id": 1, "details": {"safe": "kept"}}],
            "audit": {"trace": self.run_id}, "sawSecret": False,
            "authorization_present": False, "authorization_scheme": None,
        }, "nested request and response redaction did not preserve the exact safe projection")
        self.results.append("bidirectional_nested_json_redaction")

        deadline = min(self.deadline, time.monotonic() + 15)
        while True:
            events = [event for event in self.audit() if event["id"] not in before_ids]
            encoded = json.dumps(events)
            require(self.client_secret not in encoded and "demo-token-from-vault" not in encoded
                    and self.admin_token not in encoded, "stored audit leaked synthetic credential material")
            correlated = {event.get("event_type") for event in events
                          if event.get("event", {}).get("body_sha256") == body_digest}
            reflection = any(event.get("event_type") == "data_plane.response.blocked"
                             and event.get("event", {}).get("response_validation", {}).get("error")
                             == "response_credential_reflection" for event in events)
            if {"data_plane.credential.release_started", "data_plane.response.released"} <= correlated and reflection:
                break
            require(time.monotonic() < deadline, "correlated real audit receipts did not arrive")
            time.sleep(0.5)
        self.results.append("stored_correlated_audit_without_credential_material")
        require(self.upstream_count("GET") == 2 and self.upstream_count("POST") == 1
                and self.upstream_count("DELETE") == 0,
                "upstream dispatch counts differ from the accepted requests")
        return {"ok": True, "schema": "serverware.developmentSandboxCheck/v1",
                "mode": "synthetic-development", "productionReady": False,
                "hardwareVerified": False, "checks": self.results,
                "dataPlaneBinaryDigest": health["data_plane_binary_digest"],
                "policyHash": health["policy_hash"], "auditRequestBodySha256": body_digest}


def run_checks(*, expected_binary_sha256: str,
               control_base: str = "http://serverware:3000",
               proxy_host: str = "decision-gate-rs", proxy_port: int = 9090,
               management_port: int = 9091,
               ca_file: str | Path = "/data/mitmproxy/mitmproxy-ca-cert.pem",
               upstream_ca_file: str | Path = "/demo-upstream/ca.pem",
               admin_token_file: str | Path = "/run/secrets/serverware/admin.token") -> dict[str, Any]:
    """Run the fixed internal engineering flow; return only sanitized results.

    Callers must not accept these configuration arguments from browser input.
    The application also owns its single-in-flight concurrency admission.
    """
    try:
        require(isinstance(expected_binary_sha256, str)
                and re.fullmatch(r"sha256:[a-f0-9]{64}", expected_binary_sha256) is not None,
                "expected binary SHA-256 must be an exact lowercase digest")
        require(all(type(value) is int and 1 <= value <= 65535
                    for value in (proxy_port, management_port)), "proxy ports must be valid")
        args = argparse.Namespace(
            expected_binary_sha256=expected_binary_sha256,
            control_base=control_base, proxy_host=proxy_host, proxy_port=proxy_port,
            management_port=management_port, ca_file=Path(ca_file),
            upstream_ca_file=Path(upstream_ca_file), admin_token_file=Path(admin_token_file),
        )
        return SandboxCheck(args).run()
    except Exception as error:
        # No server response body, token, request header, or secret is returned.
        label = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        return {"ok": False, "error": label, "mode": "synthetic-development"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control-base", default="http://serverware:3000")
    parser.add_argument("--proxy-host", default="decision-gate-rs")
    parser.add_argument("--proxy-port", type=int, default=9090)
    parser.add_argument("--management-port", type=int, default=9091)
    parser.add_argument("--ca-file", type=Path, default=Path("/data/mitmproxy/mitmproxy-ca-cert.pem"))
    parser.add_argument("--upstream-ca-file", type=Path, default=Path("/demo-upstream/ca.pem"))
    parser.add_argument("--admin-token-file", type=Path, default=Path("/run/secrets/serverware/admin.token"))
    parser.add_argument("--expected-binary-sha256", required=True)
    args = parser.parse_args()
    result = run_checks(**vars(args))
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
