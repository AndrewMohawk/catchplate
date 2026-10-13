"""Local-only, one-attempt managed-X provider for stock posting clients.

Runtime admits only the fixed network-none namespace. No production endpoint,
clock, refresh skew or provider policy is rewritten. Private OAuth material is
memory-only; the durable observations contain counts and public commitments.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import http.server
import json
import os
from pathlib import Path
import re
import secrets
import signal
import ssl
import stat
import threading
import time
from urllib.parse import parse_qsl, urlencode, urlsplit

from scripts import operator_x_post_fixture_network as network
from scripts import operator_x_post_profiles as profiles

CLIENT_ID = "serverware-x-post-fixture-client"
CLIENT_SECRET = "synthetic-x-post-fixture-client-secret"
SUBJECT, USERNAME = "18446744073709551001", "operator_x"
SCOPES = ("offline.access", "tweet.read", "tweet.write", "users.read")
INITIAL_TTL_SECONDS, REFRESH_TTL_SECONDS = 120, 600
TOKEN_PATTERN = rb"synthetic-x-post-(?:access|refresh)-g[12]-[A-Za-z0-9_-]{43}"
AUTHORIZATION_URL = "https://x.com/i/oauth2/authorize"
CALLBACK_URL = network.CONTROL_ORIGIN + "/api/oauth/callback/x"
OBSERVATIONS_PATH = "/__test__/observations"
PKI = Path("/x")
MAX_CONTACTS, MAX_OBSERVATIONS, MAX_BODY = 64, 128, 32768
POST_KEYS = frozenset(("ordinal", "client", "case", "generation", "requestBodySha256",
    "requestBodyBytes", "requestHeaders", "timestampEpochMs", "responseBodySha256",
    "responseBytes", "status", "postId", "providerCredentialMatched", "proxyAuthorizationPresent"))
QUOTA_OBSERVATION_SCHEMA = "serverware.privateXQuotaProvider/v1"


def require(condition):
    if not condition:
        raise ValueError("private managed X fixture refused")


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("ascii")


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def response_body(ordinal, *, reflected_token=None):
    require(type(ordinal) is int and 1 <= ordinal <= 7)
    value = {"data": {"id": str(9000000000000000000 + ordinal),
        "text": profiles.TEXT if reflected_token is None else profiles.REFLECTION_TEXT}}
    if reflected_token is not None:
        require(type(reflected_token) is str and re.fullmatch(TOKEN_PATTERN, reflected_token.encode()))
        value["unselected"] = {"credential": reflected_token}
    return encoded(value)


def headers(fields):
    require(type(fields) in (list, tuple) and len(fields) <= 24)
    result = {}
    for name, value in fields:
        require(type(name) is str and type(value) is str and name.isascii() and value.isascii()
            and re.fullmatch(r"[A-Za-z0-9-]{1,64}", name) and len(value) <= 2048
            and not any(ord(char) < 32 or ord(char) == 127 for char in value))
        name = name.lower()
        require(name not in result)
        result[name] = value
    require("proxy-authorization" not in result and "transfer-encoding" not in result
        and "cookie" not in result)
    if "connection" in result:
        require(result["connection"].lower() in ("close", "keep-alive"))
    return result


def form(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_BODY)
    pairs = parse_qsl(raw.decode("ascii"), keep_blank_values=True, strict_parsing=True,
        max_num_fields=8, encoding="utf-8", errors="strict")
    require(len(pairs) == len(dict(pairs)))
    return dict(pairs)


class State:
    """Fixed synthetic state; injected clocks are only an inert unit-test seam."""

    def __init__(self, *, directory=None, wall=time.time, monotonic=time.monotonic):
        self._wall, self._monotonic, self._directory = wall, monotonic, directory
        self._start_wall, self._start_mono = wall(), monotonic()
        self._last_wall, self._last_mono = self._start_wall, self._start_mono
        self._deadline = self._start_mono + network.KEEPER_SECONDS
        self._lock = threading.RLock()
        self._counts = dict.fromkeys(("total", "authorize", "code", "refresh", "identity", "revoke", "posts", "rejected"), 0)
        self._codes, self._tokens, self._posts, self._revocations = {}, {}, [], []
        self._generations, self._identity_generations = [], set()
        self._initial_issued = self._initial_expires = self._initial_mono_expires = None
        self._refresh_after_expiry, self._overflowed, self._observations = False, False, 0
        self._terminal = "running"
        if directory is not None:
            info = directory.lstat()
            require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
                and info.st_uid == info.st_gid == os.geteuid() == 10001)
            network._write(directory / "run.claim", b"private managed X one-shot\n")
            require(not (directory / "observations.json").exists())
            self._persist()

    def _now(self):
        wall, mono = self._wall(), self._monotonic()
        require(wall >= self._last_wall and mono >= self._last_mono)
        self._last_wall, self._last_mono = wall, mono
        require(self._terminal == "running" and mono < self._deadline
            and wall < self._start_wall + network.KEEPER_SECONDS)
        return int(wall * 1000), mono

    def _expired(self, wall_ms, mono):
        return self._initial_expires is not None and wall_ms >= self._initial_expires and mono >= self._initial_mono_expires

    def _view(self):
        return {"schema": profiles.OBSERVATION_SCHEMA, "syntheticOnly": True,
            "terminal": self._terminal, "counts": dict(self._counts),
            "initialAccessIssuedAtEpochMs": self._initial_issued,
            "initialAccessExpiresAtEpochMs": self._initial_expires,
            "initialAccessExpired": self._expired(int(self._wall() * 1000), self._monotonic()),
            "refreshAfterInitialExpiry": self._refresh_after_expiry,
            "tokenLifetimes": {"initial": INITIAL_TTL_SECONDS, "refreshed": REFRESH_TTL_SECONDS},
            "issuedGenerations": list(self._generations), "posts": list(self._posts),
            "revocations": list(self._revocations),
            "cleanupComplete": bool(self._tokens) and all(value["revoked"] for value in self._tokens.values()),
            "overflowed": self._overflowed}

    def _persist(self):
        if self._directory is None:
            return
        target, stage = self._directory / "observations.json", self._directory / "observations.next"
        if target.exists() or target.is_symlink():
            info = target.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid())
        network._write(stage, encoded(self._view()), 0o600)
        os.replace(stage, target)
        descriptor = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def observations(self):
        with self._lock:
            self._now()
            self._observations += 1
            require(self._observations <= MAX_OBSERVATIONS)
            return json.loads(encoded(self._view()))

    def stop(self, terminal):
        require(terminal in ("stopped", "expired", "failed"))
        with self._lock:
            self._terminal = terminal
            self._persist()

    def refused_arrival(self):
        with self._lock:
            self._counts["total"] += 1
            self._counts["rejected"] += 1
            self._overflowed |= self._counts["total"] > MAX_CONTACTS
            self._persist()

    def request(self, method, target, fields, raw=b""):
        with self._lock:
            self._counts["total"] += 1
            try:
                wall, mono = self._now()
                self._overflowed |= self._counts["total"] > MAX_CONTACTS
                require(not self._overflowed and type(raw) is bytes and len(raw) <= MAX_BODY)
                values = headers(fields)
                kind, status, extra, body = self._dispatch(method, target, values, raw, wall, mono)
                self._counts[kind] += 1
            except (ValueError, UnicodeError, TypeError):
                self._counts["rejected"] += 1
                status, extra, body = 400, (), encoded({"error": "private_fixture_refused"})
            try:
                self._persist()  # Persist every provider effect/refusal BEFORE replying.
            except BaseException:
                self._terminal = "failed"
                raise
            return status, extra, body

    def _basic(self, values, raw):
        expected = "Basic " + base64.b64encode((CLIENT_ID + ":" + CLIENT_SECRET).encode()).decode()
        require(hmac.compare_digest(values.get("authorization", ""), expected)
            and values.get("host") == "api.x.com"
            and values.get("content-type") == "application/x-www-form-urlencoded"
            and values.get("accept") == "application/json"
            and values.get("content-length") == str(len(raw))
            and set(values) <= {"host", "authorization", "content-type", "accept", "content-length", "connection"})

    def _access(self, values, wall, mono):
        auth = values.get("authorization", "")
        require(auth.startswith("Bearer "))
        token = auth[7:]
        value = self._tokens.get(token)
        require(value is not None and value["hint"] == "access_token" and not value["revoked"]
            and wall < value["expires"] and mono < value["mono_expires"])
        return token, value

    def _issue(self, generation, ttl, wall, mono):
        require(self._generations == ([] if generation == 1 else [1]))
        access, refresh = ("synthetic-x-post-" + kind + "-g" + str(generation) + "-" + secrets.token_urlsafe(32)
            for kind in ("access", "refresh"))
        for token, hint in ((access, "access_token"), (refresh, "refresh_token")):
            self._tokens[token] = {"hint": hint, "generation": generation, "revoked": False,
                "used": False, "expires": wall + ttl * 1000, "mono_expires": mono + ttl}
        self._generations.append(generation)
        if generation == 1:
            self._initial_issued, self._initial_expires = wall, wall + ttl * 1000
            self._initial_mono_expires = mono + ttl
        return encoded({"access_token": access, "refresh_token": refresh, "token_type": "bearer",
            "expires_in": ttl, "scope": " ".join(SCOPES)})

    def _authorization_allowed(self):
        return not self._codes

    def _identity_key(self, value):
        return value["generation"]

    def _post_selection(self, ordinal):
        require(ordinal <= 7)
        return (profiles.CLIENTS[(ordinal - 1) % 3] if ordinal <= 6 else "node",
            "success" if ordinal <= 6 else "reflection", 1 if ordinal <= 3 else 2)

    def _public_family(self, value):
        return {}

    def _dispatch(self, method, target, values, raw, wall, mono):
        if method == "GET" and target.startswith("/i/oauth2/authorize?"):
            require(self._authorization_allowed() and not raw and values.get("host") == "x.com"
                and set(values) <= {"host", "connection", "user-agent", "accept", "accept-encoding"}
                and values.get("accept-encoding", "identity") == "identity")
            uri = urlsplit(target)
            require(uri.path == "/i/oauth2/authorize" and not uri.fragment)
            args = form(uri.query.encode("ascii"))
            require(set(args) == {"response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method"}
                and args["response_type"] == "code" and args["client_id"] == CLIENT_ID
                and args["redirect_uri"] == CALLBACK_URL and args["scope"] == " ".join(SCOPES)
                and args["code_challenge_method"] == "S256"
                and re.fullmatch(r"[A-Za-z0-9_-]{43}", args["code_challenge"])
                and re.fullmatch(r"[A-Za-z0-9_-]{43}", args["state"]))
            code = secrets.token_urlsafe(32)
            self._codes[code] = {"challenge": args["code_challenge"], "used": False,
                "expires": wall + 60000, "mono_expires": mono + 60}
            return "authorize", 302, (("Location", CALLBACK_URL + "?" + urlencode({"code": code, "state": args["state"]})),), b""
        require(values.get("host") == "api.x.com")
        if method == "POST" and target == "/2/oauth2/token":
            self._basic(values, raw)
            args = form(raw)
            if args.get("grant_type") == "authorization_code":
                require(set(args) == {"grant_type", "code", "redirect_uri", "code_verifier"})
                value = self._codes.get(args["code"])
                require(value is not None and not value["used"])
                value["used"] = True
                require(wall < value["expires"] and mono < value["mono_expires"]
                    and args["redirect_uri"] == CALLBACK_URL
                    and re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", args["code_verifier"])
                    and hmac.compare_digest(base64.urlsafe_b64encode(hashlib.sha256(args["code_verifier"].encode()).digest()).rstrip(b"=").decode(), value["challenge"]))
                return "code", 200, (), self._issue(1, INITIAL_TTL_SECONDS, wall, mono)
            require(set(args) == {"grant_type", "refresh_token"} and args["grant_type"] == "refresh_token")
            value = self._tokens.get(args["refresh_token"])
            require(value is not None and value["hint"] == "refresh_token" and value["generation"] == 1
                and not value["used"] and not value["revoked"])
            value["used"] = True
            self._refresh_after_expiry = self._expired(wall, mono)
            return "refresh", 200, (), self._issue(2, REFRESH_TTL_SECONDS, wall, mono)
        if method == "GET" and target == "/2/users/me":
            require(not raw and values.get("accept") == "application/json"
                and set(values) <= {"host", "authorization", "accept", "connection"})
            _, value = self._access(values, wall, mono)
            identity = self._identity_key(value)
            require(identity not in self._identity_generations)
            self._identity_generations.add(identity)
            return "identity", 200, (), encoded({"data": {"id": SUBJECT, "name": "Synthetic local X account", "username": USERNAME}})
        if method == "POST" and target == "/2/oauth2/revoke":
            self._basic(values, raw)
            args = form(raw)
            require(set(args) == {"token", "token_type_hint"})
            value = self._tokens.get(args["token"])
            require(value is not None and value["hint"] == args["token_type_hint"] and not value["revoked"])
            value["revoked"] = True
            self._revocations.append({"generation": value["generation"], "tokenTypeHint": value["hint"],
                "originalClientVerified": True, **self._public_family(value)})
            return "revoke", 200, (), encoded({"revoked": True})
        require(method == "POST" and target == profiles.TARGET and len(self._posts) < 7)
        token, value = self._access(values, wall, mono)
        ordinal = len(self._posts) + 1
        client, case, generation = self._post_selection(ordinal)
        public_headers = {name: item for name, item in values.items() if name not in ("authorization", "connection")}
        require(value["generation"] == generation and self._identity_key(value) in self._identity_generations
            and public_headers == profiles.provider_headers(client, case) and raw == profiles.post_body(client, case))
        body = response_body(ordinal, reflected_token=token if case == "reflection" else None)
        self._posts.append({"ordinal": ordinal, "client": client, "case": case, "generation": generation,
            "requestBodySha256": sha(raw), "requestBodyBytes": len(raw), "requestHeaders": public_headers,
            "timestampEpochMs": wall, "responseBodySha256": sha(body), "responseBytes": len(body),
            "status": 201, "postId": str(9000000000000000000 + ordinal),
            "providerCredentialMatched": True, "proxyAuthorizationPresent": False, **self._public_family(value)})
        return "posts", 201, (), body


class QuotaState(State):
    """Closed two-consent lane, separate from the original SDK provider.

    Four posts only. A new token family for the same subject is issued only
    after the first family is revoked; original expiry/lifetime never resets.
    """

    def __init__(self, **kwargs):
        self._families = []
        super().__init__(**kwargs)

    def _view(self):
        value = super()._view()
        value["schema"] = QUOTA_OBSERVATION_SCHEMA
        del value["issuedGenerations"]
        value["issuedTokenFamilies"] = list(self._families)
        return value

    def _authorization_allowed(self):
        return not self._codes or (len(self._codes) == 1 and len(self._posts) == 4
            and self._families == [{"alias": 1, "generation": 1}, {"alias": 1, "generation": 2}]
            and all(value["revoked"] for value in self._tokens.values()))

    def _identity_key(self, value):
        return value["alias"], value["generation"]

    def _public_family(self, value):
        return {"alias": value["alias"]}

    def _post_selection(self, ordinal):
        require(ordinal <= 4)
        return profiles.CLIENTS[(ordinal - 1) % 3], "success", 1 if ordinal <= 3 else 2

    def _issue(self, generation, ttl, wall, mono):
        expected = ((1, 1), (1, 2), (2, 1))
        require(len(self._families) < len(expected))
        alias, selected = expected[len(self._families)]
        require(generation == selected and len(self._codes) == alias
            and ttl == (INITIAL_TTL_SECONDS if generation == 1 else REFRESH_TTL_SECONDS))
        if generation == 2:
            require(self._refresh_after_expiry and self._expired(wall, mono) and len(self._posts) == 3)
        if alias == 2:
            require(len(self._posts) == 4 and all(value["revoked"] for value in self._tokens.values()))
        access, refresh = ("synthetic-x-quota-a" + str(alias) + "-" + kind + "-g" + str(generation)
            + "-" + secrets.token_urlsafe(32) for kind in ("access", "refresh"))
        for token, hint in ((access, "access_token"), (refresh, "refresh_token")):
            self._tokens[token] = {"hint": hint, "alias": alias, "generation": generation,
                "revoked": False, "used": False, "expires": wall + ttl * 1000, "mono_expires": mono + ttl}
        self._families.append({"alias": alias, "generation": generation})
        if alias == generation == 1:
            self._initial_issued, self._initial_expires = wall, wall + ttl * 1000
            self._initial_mono_expires = mono + ttl
        return encoded({"access_token": access, "refresh_token": refresh, "token_type": "bearer",
            "expires_in": ttl, "scope": " ".join(SCOPES)})


class FaultState(State):
    """One consent and zero post arrivals for each fresh claim-ACK fault lane."""

    def _view(self):
        value = super()._view()
        value["schema"] = "serverware.privateXQuotaFaultProvider/v1"
        return value

    def _issue(self, generation, ttl, wall, mono):
        require(generation == 1 and ttl == INITIAL_TTL_SECONDS)
        return super()._issue(generation, ttl, wall, mono)

    def _post_selection(self, ordinal):
        raise ValueError("private fault provider must not receive a post")


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        return

    def send(self, status, body, extra=()):
        self.close_connection = True
        self.send_response_only(status)
        for name, value in (("Content-Type", "application/json"), ("Content-Length", str(len(body))),
                ("Cache-Control", "no-store"), ("Connection", "close"), *extra):
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def send_error(self, code, message=None, explain=None):
        self.server.state.refused_arrival()
        self.send(400, encoded({"error": "private_fixture_refused"}))

    def handle_expect_100(self):
        self.send_error(400)
        return False

    def handle_request(self):
        try:
            fields = list(self.headers.raw_items())
            values = headers(fields)
            if self.command == "GET" and self.path == OBSERVATIONS_PATH:
                require(values.get("host") == "api.x.com" and "content-length" not in values)
                self.send(200, encoded(self.server.state.observations()))
                return
            length = values.get("content-length", "0")
            require(re.fullmatch(r"0|[1-9][0-9]{0,4}", length) and int(length) <= MAX_BODY)
            raw = self.rfile.read(int(length))
            require(len(raw) == int(length))
        except (ValueError, OSError):
            self.send_error(400)
            return
        status, extra, body = self.server.state.request(self.command, self.path, fields, raw)
        self.send(status, body, extra)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_HEAD = handle_request


def setup(*, fault_gate=False):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    root = Path("/upstream-data/x")
    require(os.geteuid() == os.getegid() == 10001 and not root.exists() and not root.is_symlink()
        and root.parent.stat().st_uid == 10001)
    network.assert_isolated_network(attached=False)
    require(json.loads(Path("/private-fixture.json").read_bytes()) == {
        "schema": "serverware.privateOperatorAuditFixture/v1", "syntheticOnly": True})
    now = datetime.now(timezone.utc)
    key, leaf_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Private managed X posting fixture CA")])
    ca = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), True).sign(key, hashes.SHA256()))
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "api.x.com")]))
        .issuer_name(subject).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host) for host in (*network.PROVIDER_HOSTS, network.CONTROL_HOST)]), False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False).sign(key, hashes.SHA256()))
    root.mkdir(mode=0o700)
    for name, data, mode in (("ca.pem", ca.public_bytes(serialization.Encoding.PEM), 0o444),
            ("cert.pem", leaf.public_bytes(serialization.Encoding.PEM), 0o444),
            ("key.pem", leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()), 0o400)):
        network._write(root / name, data, mode)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    network.prepare_network_files(fault_gate=fault_gate)
    print('{"ok":true,"syntheticOnly":true,"providerContact":false}', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--setup", action="store_true")
    parser.add_argument("--lifetime-seconds", type=int, default=network.KEEPER_SECONDS)
    parser.add_argument("--profile", choices=("sdk", "quota", "fault"), default="sdk")
    args = parser.parse_args()
    os.umask(0o077)
    require(args.lifetime_seconds == network.KEEPER_SECONDS)
    if args.setup:
        signal.alarm(30)
        setup(fault_gate=args.profile == "fault")
        return
    from scripts.operator_google_fixture import _BoundedServer, _ControlFront
    require(os.geteuid() == os.getegid() == 10001)
    network.assert_isolated_network()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(["http/1.1"])
    context.load_cert_chain(str(PKI / "cert.pem"), str(PKI / "key.pem"))
    selected = {"sdk": State, "quota": QuotaState, "fault": FaultState}[args.profile]
    state, stopped = selected(directory=PKI), threading.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: stopped.set())
    servers, threads = [], []
    terminal = "failed"
    try:
        for address, handler in (((network.FIXTURE_IP, 443), Handler), ((network.LOOPBACK, 443), _ControlFront)):
            server = _BoundedServer(address, handler, context)
            server.state = state
            servers.append(server)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            threads.append(thread)
            thread.start()
        print('{"ready":true,"syntheticOnly":true,"controlHeaderRewriting":false}', flush=True)
        terminal = "stopped" if stopped.wait(max(0, state._deadline - time.monotonic())) else "expired"
    finally:
        for server in servers:
            server.shutdown(); server.server_close()
        for thread in threads:
            thread.join(timeout=6)
        state.stop(terminal)


if __name__ == "__main__":
    main()
