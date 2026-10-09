"""Synthetic Google on its real hostnames, reachable only in a network-none fixture.

This module changes no provider URLs, policy, refresh skew, TLS verifier or gate.
The inherited simulator owns real PKCE/code/client/grant checks; this adapter adds
closed host/path routing and actual monotonic access-token expiry. No provider
token or token digest is returned by observations. Never run on the host.
"""
from __future__ import annotations

import argparse
import http.server
import json
from pathlib import Path
import re
import select
import signal
import socket
import socketserver
import ssl
import threading
import time
from urllib.parse import parse_qs, urlsplit

from scripts.oauth_provider_simulator import OAuthProviderSimulator


GOOGLE_IP = "93.184.216.34"
GOOGLE_HOSTS = ("accounts.google.com", "oauth2.googleapis.com",
                "openidconnect.googleapis.com", "gmail.googleapis.com")
CONTROL_HOST = "serverware-demo.example.com"
CONTROL_ORIGIN = "https://" + CONTROL_HOST
AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
IDENTITY_URL = "https://openidconnect.googleapis.com/v1/userinfo"
GMAIL_PATH = "/gmail/v1/users/me/messages"
OBSERVATIONS_PATH = "/__test__/observations"
CLIENT_ID = "serverware-fixture.apps.googleusercontent.com"
CLIENT_SECRET = "synthetic-google-client-secret-fixture-only"
INITIAL_TTL_SECONDS = 90
REFRESH_TTL_SECONDS = 300
TOKEN_PATTERN = rb"oauth-sim-(?:access|refresh)-google-[0-9]{6}-material"
GMAIL_RESPONSE_BODY = json.dumps({"messages": [
    {"id": "gmail-recent-1", "threadId": "gmail-thread-1"},
    {"id": "gmail-recent-2", "threadId": "gmail-thread-2"}],
    "resultSizeEstimate": 2}, sort_keys=True, separators=(",", ":")).encode("ascii")
MARKER = {"schema": "serverware.privateOperatorGoogleFixture/v1",
          "syntheticOnly": True, "networkMode": "none", "googleAddress": GOOGLE_IP}
PKI = Path("/fixture-google")


def require(condition, message="isolated Google fixture refused"):
    if not condition:
        raise ValueError(message)


def assert_isolated_network(*, attached=True):
    """Actual namespace observations, not an environment-variable assertion."""
    require({path.name for path in Path("/sys/class/net").iterdir()} == {"lo"})
    routes = Path("/proc/net/route").read_text(encoding="ascii").splitlines()[1:]
    require(all(len(row.split()) >= 8 and row.split()[0] == "lo"
                and row.split()[1] != "00000000" for row in routes))
    ipv6 = Path("/proc/net/ipv6_route").read_text(encoding="ascii").splitlines()
    require(all(row.split()[-1] == "lo" for row in ipv6 if row.strip()))
    require(Path("/proc/sys/net/ipv4/ip_nonlocal_bind").read_text().strip() == "0")
    if attached:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind((GOOGLE_IP, 0))
        for hostname in GOOGLE_HOSTS:
            addresses = {item[4][0] for item in socket.getaddrinfo(
                hostname, 443, socket.AF_INET, socket.SOCK_STREAM)}
            require(addresses == {GOOGLE_IP})
        require({item[4][0] for item in socket.getaddrinfo(
            CONTROL_HOST, 443, socket.AF_INET, socket.SOCK_STREAM)} == {"127.0.0.1"})


class _BoundedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = 8

    def __init__(self, address, handler, context):
        self._slots = threading.BoundedSemaphore(8)
        self._context = context
        super().__init__(address, handler)

    def get_request(self):
        raw, address = super().get_request()
        raw.settimeout(5)
        try:
            return self._context.wrap_socket(raw, server_side=True), address
        except BaseException:
            raw.close()
            raise

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def handle_error(self, request, client_address):
        # Never print request, callback-code or token material on fixture errors.
        return


class GoogleFixture(OAuthProviderSimulator):
    GOOGLE_CLIENT_ID = CLIENT_ID
    GOOGLE_CLIENT_SECRET = CLIENT_SECRET
    _CLIENTS = {"google": (CLIENT_ID, CLIENT_SECRET)}
    _ALLOWED_SCOPES = {"google": frozenset(("email", "openid",
        "https://www.googleapis.com/auth/gmail.readonly"))}

    def __init__(self, work_dir=PKI):
        super().__init__(work_dir, host=GOOGLE_IP, port=443,
            redirect_base_url=CONTROL_ORIGIN,
            authorization_token_ttl_seconds=INITIAL_TTL_SECONDS,
            refresh_token_ttl_seconds=REFRESH_TTL_SECONDS)
        self._expiry = {}
        self._request_generation = threading.local()
        self._initial_expiry_epoch_ms = None
        self._initial_expiry_monotonic = None
        self.ca_cert_path = self.work_dir / "ca.pem"
        self.server_cert_path = self.work_dir / "server.pem"
        self.server_key_path = self.work_dir / "server-key.pem"

    def _issue_tokens_locked(self, provider, grant_id, scopes, *, grant_type):
        require(provider == "google" and len(self._expiry) < 8)
        result = super()._issue_tokens_locked(provider, grant_id, scopes, grant_type=grant_type)
        ttl = result["expires_in"]
        epoch_ms = time.time_ns() // 1_000_000 + ttl * 1000
        monotonic = time.monotonic() + ttl
        self._expiry[result["access_token"]] = (monotonic, epoch_ms, self._token_counter)
        if grant_type == "authorization_code":
            require(self._initial_expiry_epoch_ms is None)
            self._initial_expiry_epoch_ms = epoch_ms
            self._initial_expiry_monotonic = monotonic
        return result

    def _expire(self):
        now = time.monotonic()
        with self._lock:
            for token, (deadline, _, _) in self._expiry.items():
                if now >= deadline:
                    self._access_tokens[token].active = False

    def _authorized_grant(self, handler, **kwargs):
        self._expire()
        values = handler.headers.get_all("Authorization", [])
        if len(values) != 1:
            self._send_json(handler, 401, {"error": "invalid_token"})
            return None
        token = values[0].removeprefix("Bearer ")
        with self._lock:
            self._request_generation.value = self._expiry.get(token, (None, None, None))[2]
        try:
            return super()._authorized_grant(handler, **kwargs)
        finally:
            self._request_generation.value = None

    def _identity(self, handler, provider):
        self._expire()
        if len(handler.headers.get_all("Authorization", [])) != 1:
            self._send_json(handler, 401, {"error": "invalid_token"})
            return
        super()._identity(handler, provider)

    def _record_locked(self, provider, event_type, **details):
        details["timestamp_epoch_ms"] = time.time_ns() // 1_000_000
        if event_type == "resource_authorized":
            generation = self._request_generation.value
            require(type(generation) is int and generation > 0)
            details["token_generation"] = generation
        super()._record_locked(provider, event_type, **details)

    def observations(self):
        self._expire()
        with self._lock:
            result = super().observations()
            result.update(schema="serverware.privateGoogleObservations/v1",
                initialAccessExpiresAtEpochMs=self._initial_expiry_epoch_ms,
                initialAccessExpired=(self._initial_expiry_monotonic is not None
                    and time.monotonic() >= self._initial_expiry_monotonic))
            self.assert_no_token_values(json.dumps(result))
            return result

    def note_arrival(self, handler):
        # Count BEFORE auth/method/header parsing so a denied upstream arrival
        # cannot masquerade as a gate-side no-dispatch result.
        if handler.path.split("?", 1)[0] == GMAIL_PATH:
            with self._lock:
                self._counts["google"]["resource_attempts"] += 1
                self._record_locked("google", "resource_received")

    def _admit(self, handler):
        if not self._request_headers_are_bounded(handler):
            return None
        hosts = handler.headers.get_all("Host", [])
        if len(hosts) != 1 or hosts[0] not in set(GOOGLE_HOSTS) | {host + ":443" for host in GOOGLE_HOSTS}:
            self._send_json(handler, 400, {"error": "fixture_host_refused"})
            return None
        if (not handler.path.startswith("/") or handler.path.startswith("//")
                or handler.headers.get_all("Transfer-Encoding", [])
                or handler.headers.get_all("Proxy-Authorization", [])):
            self._send_json(handler, 400, {"error": "fixture_request_refused"})
            return None
        self._expire()
        return hosts[0].removesuffix(":443"), urlsplit(handler.path)

    def _handle_get(self, handler):
        admitted = self._admit(handler)
        if admitted is None:
            return
        host, parsed = admitted
        if handler.headers.get_all("Content-Length", []) not in ([], ["0"]):
            self._send_json(handler, 400, {"error": "fixture_request_refused"})
        elif host == "accounts.google.com" and parsed.path == "/o/oauth2/v2/auth":
            with self._lock:
                require(self._code_counter < 2)
            self._authorize(handler, "google", parsed.query)
        elif host == "openidconnect.googleapis.com" and parsed.path == "/v1/userinfo" and not parsed.query:
            self._identity(handler, "google")
        elif host == "gmail.googleapis.com" and parsed.path == OBSERVATIONS_PATH and not parsed.query:
            self._send_json(handler, 200, self.observations())
        elif host == "gmail.googleapis.com" and parsed.path == GMAIL_PATH and not parsed.query:
            self._gmail_resource(handler, parsed)
        else:
            self._send_json(handler, 404, {"error": "fixture_route_refused"})

    def _authorize(self, handler, provider, query):
        try:
            params = parse_qs(
                query, keep_blank_values=True, strict_parsing=True, max_num_fields=24)
        except ValueError:
            self._send_json(handler, 400, {"error": "invalid_request"})
            return
        scope = self._one(params, "scope")
        if scope is None or set(scope.split(" ")) != self._ALLOWED_SCOPES["google"]:
            self._send_json(handler, 400, {"error": "invalid_scope"})
            return
        super()._authorize(handler, provider, query)

    def _handle_post(self, handler):
        admitted = self._admit(handler)
        if admitted is None:
            return
        host, parsed = admitted
        if host != "oauth2.googleapis.com" or parsed.query or parsed.path not in {"/token", "/revoke"}:
            self._send_json(handler, 404, {"error": "fixture_route_refused"})
            return
        lengths = handler.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or re.fullmatch(r"[0-9]{1,5}", lengths[0]) is None:
            self._send_json(handler, 400, {"error": "fixture_request_refused"})
            return
        form = self._read_form(handler)
        if form is not None:
            (self._token if parsed.path == "/token" else self._revoke)(handler, "google", form)

    def start(self):
        assert_isolated_network()
        require(self._server is None)
        fixture = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def do_GET(self):
                fixture.note_arrival(self)
                fixture._handle_get(self)
            def do_POST(self):
                fixture.note_arrival(self)
                fixture._handle_post(self)
            def _unsupported(self):
                fixture.note_arrival(self)
                fixture._send_json(self, 405, {"error": "fixture_method_refused"})
            do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_HEAD = _unsupported
            def log_message(self, *args):
                return

        self._server = _BoundedServer((GOOGLE_IP, 443), Handler, server_context(self.work_dir))
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self


def server_context(directory):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(directory / "server.pem"), str(directory / "server-key.pem"))
    return context


class _ControlFront(socketserver.BaseRequestHandler):
    """Fixture TLS termination only: unmodified HTTP bytes to the real runner."""
    def handle(self):
        deadline, remaining = time.monotonic() + 10, 4 * 1024 * 1024
        with socket.create_connection(("127.0.0.1", 3000), timeout=3) as upstream:
            peers = {self.request: upstream, upstream: self.request}
            while remaining > 0:
                timeout = min(3, deadline - time.monotonic())
                if timeout <= 0:
                    return
                ready = [self.request] if self.request.pending() else select.select(list(peers), [], [], timeout)[0]
                if not ready:
                    continue
                for source in ready:
                    source.settimeout(timeout)
                    data = source.recv(min(16384, remaining))
                    if not data:
                        return
                    remaining -= len(data)
                    peers[source].settimeout(timeout)
                    peers[source].sendall(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lifetime-seconds", type=int, default=240)
    args = parser.parse_args()
    require(120 <= args.lifetime_seconds <= 300)
    assert_isolated_network()
    stopped = threading.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: stopped.set())
    fixture = GoogleFixture()
    front = _BoundedServer(("127.0.0.1", 443), _ControlFront, server_context(PKI))
    thread = threading.Thread(target=front.serve_forever, daemon=True)
    try:
        fixture.start()
        thread.start()
        print("Isolated synthetic Google fixture ready; no provider values emitted.", flush=True)
        stopped.wait(args.lifetime_seconds)
    finally:
        fixture.close()
        if thread.is_alive():
            front.shutdown()
        front.server_close()
        thread.join(timeout=6) if thread.ident else None


if __name__ == "__main__":
    main()
