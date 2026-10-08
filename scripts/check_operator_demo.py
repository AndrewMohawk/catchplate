#!/usr/bin/env python3
"""Accept an explicitly supplied PRIVATE operator-demo stack using real traffic.

Creates one durable connection with a random synthetic credential. Requires
private control/management/proxy endpoints, actual CA certificates and the admin
token FILE. Never uses a real provider or a live sandbox/pilot. The HTTP proxy
leg is reported separately from a verified HTTPS edge; neither proves public DNS
or production/native custody. Run in the isolated fixture network, or supply its
private IP with --upstream-address while retaining demo-upstream TLS identity.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import io
import ipaddress
import json
from pathlib import Path
import re
import secrets
import signal
import socket
import ssl
import time
from typing import Any, Callable
from urllib.parse import urlencode, urlsplit
import uuid

try:
    from scripts.check_development_sandbox import token_file
except ModuleNotFoundError:
    from check_development_sandbox import token_file


MAX_BODY = 2 * 1024 * 1024
UPSTREAM = "demo-upstream"
AUTHORITY = UPSTREAM + ":8443"
SHA256 = re.compile(r"sha256:[a-f0-9]{64}\Z")
PRIVATE_NETS = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128", "fc00::/7"))


class CheckFailure(RuntimeError):
    """Only static, locally authored messages may be exposed to the caller."""


def require(condition: bool, label: str) -> None:
    if not condition:
        raise CheckFailure(label)


def private_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
        return any(address in network for network in PRIVATE_NETS)
    except ValueError:
        return False


class Endpoint:
    """Resolve once, reject non-private results, then connect only to pinned IPs."""

    def __init__(self, value: str, *, address: str | None = None):
        parsed = urlsplit(value)
        require(parsed.scheme in {"http", "https"} and bool(parsed.hostname)
                and parsed.path in {"", "/"} and not any((parsed.query, parsed.fragment,
                parsed.username, parsed.password)), "endpoint must be an explicit HTTP(S) origin")
        self.host, self.scheme = parsed.hostname, parsed.scheme
        self.port = parsed.port or (443 if self.scheme == "https" else 80)
        require(1 <= self.port <= 65535, "endpoint port is invalid")
        if address is not None:
            addresses = {address}
        else:
            addresses = {item[4][0] for item in socket.getaddrinfo(
                self.host, self.port, type=socket.SOCK_STREAM)}
        require(bool(addresses) and all(private_address(item) for item in addresses),
                "every endpoint address must be private or loopback")
        self.address = sorted(addresses)[0]

    def connect(self, timeout: float, context: ssl.SSLContext | None = None) -> socket.socket:
        raw = socket.create_connection((self.address, self.port), timeout=timeout)
        try:
            if self.scheme == "https":
                require(context is not None, "HTTPS endpoint requires its supplied CA")
                return context.wrap_socket(raw, server_hostname=self.host)
            return raw
        except BaseException:
            raw.close()
            raise


class TunnelTLS(io.RawIOBase):
    """Origin TLS over either a plain CONNECT socket or a TLS proxy socket."""

    def __init__(self, raw: socket.socket, context: ssl.SSLContext,
                 timeout: Callable[[], float]):
        super().__init__()
        self.raw, self.timeout = raw, timeout
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.tls = context.wrap_bio(self.incoming, self.outgoing, server_hostname=UPSTREAM)
        self._perform(self.tls.do_handshake)

    def _flush(self) -> None:
        while self.outgoing.pending:
            self.raw.settimeout(self.timeout())
            self.raw.sendall(self.outgoing.read())

    def _perform(self, operation):
        while True:
            try:
                result = operation()
                self._flush()
                return result
            except ssl.SSLWantReadError:
                self._flush()
                self.raw.settimeout(self.timeout())
                chunk = self.raw.recv(16384)
                if chunk:
                    self.incoming.write(chunk)
                else:
                    self.incoming.write_eof()
            except ssl.SSLWantWriteError:
                self._flush()

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        try:
            data = self._perform(lambda: self.tls.read(len(buffer)))
        except ssl.SSLZeroReturnError:
            return 0
        buffer[:len(data)] = data
        return len(data)

    def sendall(self, data: bytes) -> None:
        while data:
            written = self._perform(lambda: self.tls.write(data))
            data = data[written:]

    def makefile(self, mode: str):
        require(mode == "rb", "unexpected HTTP response stream mode")
        return io.BufferedReader(self)

    def close(self) -> None:
        self.raw.close()
        super().close()


class OperatorDemoCheck:
    def __init__(self, args: argparse.Namespace):
        self.args, self.results = args, []
        self.deadline = time.monotonic() + args.timeout_seconds
        self.run_id = "operator-check-" + uuid.uuid4().hex
        self.credential = "synthetic-operator-" + secrets.token_urlsafe(32)
        self.wrong_token = "invalid-synthetic-" + secrets.token_urlsafe(32)
        self.admin_token, self.client_token = None, None
        self.policy_hash, self.connection = None, None
        self.control = Endpoint(args.control_base)
        self.management = Endpoint(args.management_base)
        self.proxy = Endpoint(args.proxy_url)
        self.upstream = Endpoint("https://" + AUTHORITY, address=args.upstream_address)
        self.ca = ssl.create_default_context(cafile=str(args.ca_file))
        self.upstream_ca = ssl.create_default_context(cafile=str(args.upstream_ca_file))
        self.control_ca = self._optional_ca(args.control_ca_file, self.control)
        self.management_ca = self._optional_ca(args.management_ca_file, self.management)
        self.proxy_ca = self._optional_ca(args.proxy_ca_file, self.proxy)
        origin = urlsplit(args.operator_origin)
        require(origin.scheme == "https" and bool(origin.hostname) and origin.path in {"", "/"}
                and not any((origin.query, origin.fragment, origin.username, origin.password)),
                "operator-origin must be the configured HTTPS browser origin")

    @staticmethod
    def _optional_ca(path: Path | None, endpoint: Endpoint):
        require(endpoint.scheme != "https" or path is not None,
                "HTTPS control, management and proxy endpoints each require an explicit CA file")
        return ssl.create_default_context(cafile=str(path)) if path is not None else None

    def timeout(self) -> float:
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, "operator acceptance exceeded its deadline")
        return min(4.0, remaining)

    def clean(self, content: bytes, *, allow_client_token: bool = False) -> None:
        values = (self.credential, self.admin_token, self.wrong_token,
                  None if allow_client_token else self.client_token)
        require(all(value is None or value.encode("ascii") not in content for value in values),
                "credential material escaped into a response or durable audit")

    def response(self, response: http.client.HTTPResponse, *, allow_client_token=False):
        body = response.read(MAX_BODY + 1)
        require(len(body) <= MAX_BODY, "response exceeds the acceptance body bound")
        self.clean(str(response.getheaders()).encode("utf-8"))
        self.clean(body, allow_client_token=allow_client_token)
        document = json.loads(body)
        self.clean(json.dumps(document).encode("utf-8"), allow_client_token=allow_client_token)
        return response.status, document

    def json_request(self, endpoint: Endpoint, path: str, *, context=None,
                     method="GET", payload=None, authenticated=False, creation=False):
        headers = {"Connection": "close"}
        if authenticated:
            require(self.admin_token is not None, "admin token is not loaded")
            headers["X-Serverware-Admin-Token"] = self.admin_token
        body = None
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("ascii")
            headers.update({"Content-Type": "application/json", "Origin": self.args.operator_origin.rstrip("/")})
        connection = http.client.HTTPConnection(endpoint.host, endpoint.port, timeout=self.timeout())
        connection.connect = lambda: setattr(connection, "sock", endpoint.connect(self.timeout(), context))
        try:
            connection.request(method, path, body=body, headers=headers)
            return self.response(connection.getresponse(), allow_client_token=creation)
        finally:
            connection.close()

    def control_json(self, path: str, **kwargs):
        status, payload = self.json_request(self.control, path, context=self.control_ca, **kwargs)
        require(status == 200, "operator control API returned an unexpected HTTP status")
        return payload

    def health(self):
        status, health = self.json_request(self.management, "/healthz", context=self.management_ca)
        require(status == 200 and isinstance(health, dict) and health.get("ok") is True,
                "Rust gate is not healthy")
        shadow = health.get("policy_shadow", {})
        require(health.get("policy_shadow_serving_ready") is True
                and shadow.get("mode") == "operator-demo" and shadow.get("enabled") is False
                and shadow.get("readiness") is False and shadow.get("production_custody_bound") is False,
                "Rust gate is not the explicit uncommissioned operator demo")
        require(health.get("data_plane_binary_digest") == self.args.expected_binary_sha256,
                "Rust runtime does not match the selected build")
        require(health.get("policy_trust_root_source") == "attested-control-plane"
                and bool(health.get("policy_signing_key_id")), "Rust signed-policy trust binding is unavailable")
        require(health.get("connect_mitm_interceptor") is True
                and health.get("audit", {}).get("enabled") is True
                and health.get("release_authorization", {}).get("enabled") is False,
                "operator TLS, audit or non-production release configuration differs")
        return health

    def profile(self):
        profile = self.control_json("/api/operator-demo/status", authenticated=True)
        expected = {"schema": "serverware.operatorDemo/v1", "mode": "operator-development",
                    "syntheticOnly": False, "productionReady": False, "hardwareVerified": False,
                    "allowed_upstreams": ["https://" + AUTHORITY]}
        require(isinstance(profile, dict) and all(type(profile.get(key)) is type(value)
                and profile.get(key) == value for key, value in expected.items()),
                "target is not a fixture-only isolated operator-demo profile")
        return profile

    def upstream_count(self, method: str, path: str = "/echo") -> int:
        status, payload = self.json_request(self.upstream, "/_test/request-count?" + urlencode({
            "method": method, "path": path, "run_id": self.run_id}), context=self.upstream_ca)
        require(status == 200 and isinstance(payload, dict) and type(payload.get("count")) is int,
                "real private fixture counter is unavailable")
        return payload["count"]

    def tunnel(self, token: str | None, *, expected_status=200):
        raw = self.proxy.connect(self.timeout(), self.proxy_ca)
        try:
            headers = [f"CONNECT {AUTHORITY} HTTP/1.1", f"Host: {AUTHORITY}"]
            if token is not None:
                headers.append("Proxy-Authorization: Bearer " + token)
            raw.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii"))
            head = bytearray()
            while not head.endswith(b"\r\n\r\n"):
                raw.settimeout(self.timeout())
                chunk = raw.recv(1)
                require(bool(chunk), "CONNECT closed before its response headers")
                head.extend(chunk)
                require(len(head) <= 16384, "CONNECT response headers exceed bound")
            self.clean(bytes(head))
            require(int(head.split(b" ", 2)[1]) == expected_status,
                    "CONNECT authentication returned an unexpected status")
            if expected_status != 200:
                raw.close()
                return None
            return raw
        except BaseException:
            raw.close()
            raise

    def request(self, path: str, *, method="GET", body=b""):
        raw = self.tunnel(self.client_token)
        try:
            with TunnelTLS(raw, self.ca, self.timeout) as tls:
                headers = [f"{method} {path} HTTP/1.1", f"Host: {AUTHORITY}", "Connection: close",
                           f"User-Agent: serverware-test-run/{self.run_id}", "Accept: application/json"]
                if body:
                    headers += ["Content-Type: application/json", f"Content-Length: {len(body)}"]
                tls.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + body)
                response = http.client.HTTPResponse(tls)
                try:
                    response.begin()
                    return self.response(response)
                finally:
                    response.close()
        finally:
            raw.close()

    def create_connection(self):
        result = self.control_json("/api/operator-demo/connections", method="POST", authenticated=True,
            creation=True, payload={"name": self.run_id, "upstream_url": "https://" + AUTHORITY + "/echo",
                "methods": ["GET", "POST"], "auth_type": "bearer", "secret": self.credential,
                "request_fields": ["audit_marker"], "response_fields": ["method", "path", "query",
                    "authorization_present", "authorization_scheme", "authorization_matches_expected",
                    "proxy_authorization_seen"],
                "query_keys": ["expectedAuthorizationSha256", "reflectCredential"],
                "allowed_headers": ["accept", "user-agent", "content-type"]})
        self.client_token = result.get("client_token")
        require(isinstance(self.client_token, str) and re.fullmatch(r"[A-Za-z0-9_-]{32,128}", self.client_token)
                is not None, "connection creation did not return a bounded one-time proxy token")
        self.clean(json.dumps({key: value for key, value in result.items() if key != "client_token"}).encode("utf-8"))
        self.policy_hash, self.connection = result.get("policy_hash"), result.get("connection")
        require(isinstance(self.policy_hash, str) and SHA256.fullmatch(self.policy_hash) is not None
                and isinstance(self.connection, dict) and self.connection.get("name") == self.run_id
                and self.connection.get("principal_id") == "agent:operator-demo:" + self.connection.get("id", ""),
                "connection metadata or committed signed-policy hash is invalid")
        self.results.append("credential_entry_and_one_time_proxy_token")

    def wait_loaded(self):
        while True:
            profile, health = self.profile(), self.health()
            active = next((row for row in profile.get("connections", [])
                           if row.get("id") == self.connection["id"]), None)
            if (profile.get("active_policy_hash") == self.policy_hash == profile.get("loaded_policy_hash")
                    == health.get("policy_hash") == health.get("policy_shadow", {}).get("operator_policy_sha256")
                    and active is not None and active.get("activation") == "active"):
                break
            time.sleep(min(0.4, self.timeout()))
        self.results.append("committed_signed_policy_loaded_by_exact_rust_build")

    def audit(self):
        events = self.control_json("/api/audit?limit=500", authenticated=True)
        require(isinstance(events, list) and all(isinstance(item, dict) for item in events),
                "audit API did not return persisted events")
        return events

    def verify_audit(self, body_digest: str):
        while True:
            events = self.audit()
            correlated = [row for row in events if row.get("event", {}).get("principal_id") == self.connection["principal_id"]
                and row.get("event", {}).get("route_id") == "operator." + self.connection["id"]
                and row.get("event", {}).get("policy_hash") == self.policy_hash]
            post = {row.get("event_type"): row for row in correlated
                    if row.get("event", {}).get("body_sha256") == body_digest}
            reflection = [row for row in correlated if row.get("event_type") == "data_plane.response.blocked"
                          and row.get("event", {}).get("response_validation", {}).get("error")
                          == "response_credential_reflection"]
            created = [row for row in events if row.get("event_type") == "operator_demo.connection.created"
                       and row.get("event", {}).get("connection_id") == self.connection["id"]
                       and row.get("event", {}).get("policy_hash") == self.policy_hash]
            needed = {"data_plane.credential.release_started", "data_plane.response.released"}
            if needed <= post.keys() and reflection and created:
                retained = {row["id"] for row in [*(post[key] for key in needed), reflection[0], created[0]]}
                break
            time.sleep(min(0.4, self.timeout()))
        require(retained <= {row["id"] for row in self.audit()}, "audit receipts did not survive a fresh database read")
        chain = self.control_json("/api/audit/verify?limit=1000", authenticated=True)
        require(chain.get("ok") is True and chain.get("complete") is True and chain.get("backend") == "sqlite",
                "durable operator audit chain verification failed or was incomplete")
        self.results.append("durable_correlated_audit_and_verified_chain_without_secrets")
        return sorted(retained)

    def run(self):
        self.health()  # Refuse other profiles before reading or transmitting the admin token.
        self.admin_token = token_file(self.args.admin_token_file)
        self.profile()
        self.results.append("private_fixture_only_operator_profile")
        require(all(self.upstream_count(method) == 0 for method in ("GET", "POST", "DELETE")),
                "fresh acceptance run already has fixture traffic")
        self.create_connection()
        self.wait_loaded()
        self.tunnel(None, expected_status=403)
        self.tunnel(self.wrong_token, expected_status=403)
        require(self.upstream_count("GET") == 0, "unauthenticated CONNECT reached the fixture")
        self.results.append("missing_and_wrong_proxy_tokens_denied")
        digest = "sha256:" + hashlib.sha256(("Bearer " + self.credential).encode("ascii")).hexdigest()
        path = "/echo?" + urlencode({"expectedAuthorizationSha256": digest})
        status, payload = self.request(path)
        require(status == 200 and payload.get("authorization_present") is True
                and payload.get("authorization_scheme") == "Bearer"
                and payload.get("authorization_matches_expected") is True
                and payload.get("proxy_authorization_seen") is False,
                "exact credential injection or proxy token removal failed")
        require(digest not in json.dumps(payload), "fixture returned credential-derived proof input")
        status, payload = self.request("/echo?" + urlencode({"expectedAuthorizationSha256": "sha256:" + "0" * 64}))
        require(status == 200 and payload.get("authorization_matches_expected") is False,
                "credential comparison negative control failed")
        self.results.append("verified_origin_tls_exact_injection_and_proxy_token_absent_upstream")
        status, _ = self.request("/echo", method="DELETE")
        require(status == 403 and self.upstream_count("DELETE") == 0, "unapproved method reached the fixture")
        status, _ = self.request("/not-allowed")
        require(status == 403 and self.upstream_count("GET", "/not-allowed") == 0,
                "unapproved path reached the fixture")
        require(self.upstream_count("GET") == 2, "denied traffic changed the fixture count")
        self.results.append("wrong_method_and_path_denied_without_dispatch")
        status, payload = self.request("/echo?reflectCredential=1")
        require(status == 502 and payload == {"error": "response_credential_reflection"},
                "credential reflection was not blocked")
        self.results.append("credential_reflection_blocked")
        body = json.dumps({"audit_marker": self.run_id}, separators=(",", ":"), sort_keys=True).encode("ascii")
        body_digest = "sha256:" + hashlib.sha256(body).hexdigest()
        status, payload = self.request(path, method="POST", body=body)
        require(status == 200 and payload.get("authorization_matches_expected") is True
                and payload.get("proxy_authorization_seen") is False, "audited POST failed credential verification")
        audit_ids = self.verify_audit(body_digest)
        require(self.upstream_count("GET") == 3 and self.upstream_count("POST") == 1
                and self.upstream_count("DELETE") == 0, "final fixture dispatch counts differ")
        return {"ok": True, "schema": "serverware.operatorDemoCheck/v1", "mode": "operator-development",
                "productionReady": False, "hardwareVerified": False, "publicDnsVerified": False,
                "proxyTransport": "verified-private-https-edge" if self.proxy.scheme == "https" else "private-http-connect-leg",
                "originTlsVerified": True, "checks": self.results, "runId": self.run_id,
                "connectionId": self.connection["id"], "policyHash": self.policy_hash,
                "dataPlaneBinaryDigest": self.args.expected_binary_sha256,
                "auditRequestBodySha256": body_digest, "durableAuditEventIds": audit_ids}


def run_checks(args: argparse.Namespace) -> dict[str, Any]:
    check = None
    try:
        require(isinstance(args.expected_binary_sha256, str) and SHA256.fullmatch(args.expected_binary_sha256)
                is not None, "expected binary digest must be an exact lowercase SHA-256")
        require(type(args.timeout_seconds) is int and 10 <= args.timeout_seconds <= 180,
                "acceptance timeout must be between 10 and 180 seconds")
        check = OperatorDemoCheck(args)
        return check.run()
    except Exception as error:
        # Never emit server body, request data, token, TLS error details or traceback.
        return {"ok": False, "mode": "operator-development", "error": str(error) if isinstance(error, CheckFailure)
                else type(error).__name__, "checks": list(check.results) if check else []}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("control-base", "management-base", "proxy-url", "operator-origin", "expected-binary-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("ca-file", "upstream-ca-file", "admin-token-file"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("proxy-ca-file", "control-ca-file", "management-ca-file"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--upstream-address", help="private fixture IP, preserving demo-upstream TLS hostname")
    parser.add_argument("--timeout-seconds", type=int, default=90)
    args = parser.parse_args()

    def expired(_signum, _frame):
        raise CheckFailure("operator acceptance exceeded its process deadline")

    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, min(max(args.timeout_seconds, 1), 180))
    try:
        result = run_checks(args)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
