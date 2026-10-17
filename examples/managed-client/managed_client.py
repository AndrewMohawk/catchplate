"""Standalone Linux workload token manager. No Catchplate server imports.

The private directory is a single-writer credential store, not a hardware vault.
Only exact journaled operations may be retried after an uncertain outcome.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import fcntl
import hashlib
import http.client
import json
import logging
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SCHEMA = "catchplate.workloadTokenRenewal/v1"
SETUP_SCHEMA = "catchplate.managedClientSetup/v1"
STATE_SCHEMA = "catchplate.managedClientState/v1"
PUBLIC_PATH = "/v1/workload/renew"
DOMAIN = b"catchplate.workload-token-renewal/v1\x00POST /v1/workload/renew\x00"
MAX_INTEGER = 9_007_199_254_740_991
MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, MAX_STATE_BYTES = 4096, 8192, 32768
REQUEST_LIFETIME_MS, CLOCK_SKEW_MS, OVERLAP_MS = 60_000, 5000, 300_000
HTTP_TIMEOUT_SECONDS = 15
RENEW_MARGIN_MS = 600_000
SETUP_FIELDS = frozenset({"schema", "application_id", "enrollment_id", "audience",
    "public_key_fingerprint", "token_generation", "token_expires_at_epoch_ms",
    "enrollment_expires_at_epoch_ms", "token_lifetime_seconds", "overlap_seconds"})
REQUEST_FIELDS = frozenset({"schema", "audience", "application_id", "enrollment_id",
    "expected_token_generation", "operation_id", "issued_at_epoch_ms", "expires_at_epoch_ms",
    "token_sha256", "token_expires_at_epoch_ms", "signature"})
RECEIPT_FIELDS = frozenset({"operation_id", "request_sha256", "application_id",
    "enrollment_id", "previous_generation", "token_generation", "token_sha256",
    "issued_at_epoch_ms", "rotated_at_epoch_ms", "expires_at_epoch_ms",
    "previous_accept_until_epoch_ms"})
CURRENT_FIELDS = frozenset({"token", "generation", "expires_at_epoch_ms", "pool_refresh_by_epoch_ms"})
STATE_FIELDS = frozenset({"schema", "setup", "current", "pending", "last_receipt",
    "last_clock_ms", "last_revision", "last_policy_sequence"})


class ClientError(RuntimeError):
    """Fixed public error; never attach a token, response or request body."""


class RenewalUnavailable(ClientError):
    pass


def _require(condition):
    if not condition:
        raise ClientError("Managed client state or renewal contract refused")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("ascii")


def _pairs(items):
    result = {}
    for key, value in items:
        _require(key not in result)
        result[key] = value
    return result


def _json(raw, maximum):
    try:
        _require(type(raw) is bytes and 0 < len(raw) <= maximum)
        return json.loads(raw, object_pairs_hook=_pairs,
            parse_constant=lambda _: _require(False))
    except (ValueError, UnicodeError, RecursionError, TypeError):
        raise ClientError("Managed client JSON refused") from None


def _integer(value, minimum=1, maximum=MAX_INTEGER):
    _require(type(value) is int and minimum <= value <= maximum)
    return value


def _identifier(value):
    try:
        _require(type(value) is str and str(uuid.UUID(value)) == value)
    except (ValueError, AttributeError):
        raise ClientError("Managed client identifier refused") from None


def _digest(value):
    _require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None)


def sha256(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _token(value):
    _require(type(value) is str and 1 <= len(value) <= 8192
        and all(33 <= ord(char) <= 126 for char in value))
    return value


def _audience(value):
    try:
        _require(type(value) is str and 1 <= len(value) <= 512 and value.isascii()
            and not any(ord(char) < 33 or char == "\\" for char in value))
        parsed = urlsplit(value)
        _require(parsed.scheme == "https" and parsed.hostname and parsed.username is None
            and parsed.password is None and parsed.path == PUBLIC_PATH
            and "?" not in value and "#" not in value
            and (parsed.port is None or 1 <= parsed.port <= 65535))
        return parsed
    except ValueError:
        raise ClientError("Managed client HTTPS audience refused") from None


def signing_bytes(request):
    return DOMAIN + canonical({key: value for key, value in request.items() if key != "signature"})


def _file_stat(info):
    _require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
        and info.st_uid == os.getuid() and info.st_nlink == 1)


def _read_fd(fd, maximum):
    _file_stat(os.fstat(fd))
    raw = bytearray()
    while len(raw) <= maximum:
        chunk = os.read(fd, min(4096, maximum + 1 - len(raw)))
        if not chunk:
            break
        raw.extend(chunk)
    _require(0 < len(raw) <= maximum)
    return bytes(raw)


def _private_file(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        return _read_fd(fd, maximum)
    finally:
        os.close(fd)


@dataclass(frozen=True)
class TokenLease:
    token: str = field(repr=False)
    generation: int
    expires_at_epoch_ms: int
    pool_refresh_by_epoch_ms: int


class ManagedClient:
    """Hold one process-wide file lock for the worker lifetime.

    Call lease before each bounded provider operation and at least every 60 s.
    A generation change requires replacing the SDK/client connection pool.
    Nothing here retries or submits a provider operation.
    """

    def __init__(self, directory, *, transport=None, clock_ms=None):
        self._directory_fd = self._lock_fd = None
        self._pid = os.getpid()
        self._thread = threading.get_ident()
        self._clock = clock_ms or (lambda: time.time_ns() // 1_000_000)
        self._transport = transport or https_post
        self._last_now = 0
        self._state = None
        self._poisoned = False
        path = Path(directory).absolute()
        try:
            for parent in (*reversed(path.parents), path):
                if parent.exists() or parent.is_symlink():
                    _require(not parent.is_symlink())
            path.mkdir(mode=0o700, exist_ok=True)
            self._directory_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            info = os.fstat(self._directory_fd)
            _require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
            self._lock_fd = os.open("lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600, dir_fd=self._directory_fd)
            _file_stat(os.fstat(self._lock_fd))
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._state = self._read("state.json", optional=True)
            if self._state is not None:
                self._state = _json(self._state, MAX_STATE_BYTES)
                self._validate_state()
        except Exception:
            self.close()
            raise ClientError("Managed client private directory unavailable") from None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        _require(os.getpid() == self._pid and threading.get_ident() == self._thread)
        for name in ("_lock_fd", "_directory_fd"):
            fd = getattr(self, name, None)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)

    def _check(self):
        _require(os.getpid() == self._pid and threading.get_ident() == self._thread
            and self._lock_fd is not None and not self._poisoned)

    def _now(self):
        self._check()
        now = _integer(self._clock())
        _require(now >= self._last_now)
        self._last_now = now
        return now

    def _read(self, name, *, optional=False):
        self._check()
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self._directory_fd)
        except FileNotFoundError:
            if optional:
                return None
            raise ClientError("Managed client key unavailable") from None
        try:
            return _read_fd(fd, MAX_STATE_BYTES)
        finally:
            os.close(fd)

    def _write(self, name, raw):
        self._check()
        _require(type(raw) is bytes and 0 < len(raw) <= MAX_STATE_BYTES)
        temporary = ".pending-" + str(uuid.uuid4())
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600, dir_fd=self._directory_fd)
        try:
            offset = 0
            while offset < len(raw):
                offset += os.write(fd, raw[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, name, src_dir_fd=self._directory_fd, dst_dir_fd=self._directory_fd)
        os.fsync(self._directory_fd)

    def _save(self, value):
        # Set in-memory state only after replace AND directory fsync succeed.
        try:
            self._write("state.json", canonical(value))
        except Exception:
            # Replacement may have occurred even if its directory fsync failed.
            # This owner cannot safely continue with either in-memory version.
            self._poisoned = True
            raise ClientError("Managed client persistence uncertain; close and reopen the private journal") from None
        self._state = value

    def _key(self):
        raw = self._read("ed25519.key")
        _require(len(raw) == 32)
        return Ed25519PrivateKey.from_private_bytes(raw)

    def initialize(self):
        """Return only the public enrollment key; never rotate an existing key."""
        if self._read("ed25519.key", optional=True) is None:
            _require(self._state is None)
            key = Ed25519PrivateKey.generate()
            try:
                self._write("ed25519.key", key.private_bytes(serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw, serialization.NoEncryption()))
            except Exception:
                self._poisoned = True
                raise ClientError("Managed client key persistence uncertain; close and reopen") from None
        try:
            # A prior process may have stopped after replacement but before the
            # directory sync. Do not advertise enrollment until this succeeds.
            os.fsync(self._directory_fd)
        except Exception:
            self._poisoned = True
            raise ClientError("Managed client key persistence uncertain; close and reopen") from None
        return self._key().public_key().public_bytes(serialization.Encoding.Raw,
            serialization.PublicFormat.Raw).hex()

    def _validate_setup(self, setup):
        _require(type(setup) is dict and set(setup) == SETUP_FIELDS and setup["schema"] == SETUP_SCHEMA)
        for name in ("application_id", "enrollment_id"):
            _identifier(setup[name])
        _audience(setup["audience"])
        _digest(setup["public_key_fingerprint"])
        public = self._key().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        _require(setup["public_key_fingerprint"] == sha256(public))
        for name in ("token_generation", "token_expires_at_epoch_ms", "enrollment_expires_at_epoch_ms"):
            _integer(setup[name])
        _integer(setup["token_lifetime_seconds"], 3600, 86400)
        _require(type(setup["overlap_seconds"]) is int and setup["overlap_seconds"] == 300
            and setup["token_expires_at_epoch_ms"] <= setup["enrollment_expires_at_epoch_ms"])

    def configure(self, setup, token_file):
        _require(self._state is None)
        setup = _json(canonical(setup), MAX_RESPONSE_BYTES)
        self._validate_setup(setup)
        now = self._now()
        _require(now < setup["enrollment_expires_at_epoch_ms"])
        raw = _private_file(token_file, 8193)
        if raw.endswith(b"\n"):
            raw = raw[:-1]
        token = _token(raw.decode("ascii"))
        self._save({"schema": STATE_SCHEMA, "setup": setup,
            "current": {"token": token, "generation": setup["token_generation"],
                "expires_at_epoch_ms": setup["token_expires_at_epoch_ms"],
                "pool_refresh_by_epoch_ms": setup["token_expires_at_epoch_ms"]},
            "pending": None, "last_receipt": None, "last_clock_ms": now,
            "last_revision": 0, "last_policy_sequence": 0})

    def _pending_request(self):
        state, pending = self._state, self._state["pending"]
        _require(type(pending) is dict and set(pending) == {"candidate_token", "request_original"})
        candidate = _token(pending["candidate_token"])
        _require(type(pending["request_original"]) is str)
        raw = pending["request_original"].encode("ascii")
        request = _json(raw, MAX_REQUEST_BYTES)
        _require(type(request) is dict and set(request) == REQUEST_FIELDS and canonical(request) == raw
            and request["schema"] == SCHEMA)
        for name in ("application_id", "enrollment_id", "audience"):
            _require(request[name] == state["setup"][name])
        _identifier(request["operation_id"])
        for name in ("expected_token_generation", "issued_at_epoch_ms", "expires_at_epoch_ms", "token_expires_at_epoch_ms"):
            _integer(request[name])
        _require(request["expected_token_generation"] == state["current"]["generation"]
            and request["expires_at_epoch_ms"] - request["issued_at_epoch_ms"] == REQUEST_LIFETIME_MS
            and request["token_sha256"] == sha256(candidate.encode("ascii"))
            and request["token_expires_at_epoch_ms"] == min(state["setup"]["enrollment_expires_at_epoch_ms"],
                request["issued_at_epoch_ms"] + state["setup"]["token_lifetime_seconds"] * 1000)
            and request["token_expires_at_epoch_ms"] > request["issued_at_epoch_ms"]
            and type(request["signature"]) is str
            and re.fullmatch(r"[0-9a-f]{128}", request["signature"]) is not None)
        try:
            self._key().public_key().verify(bytes.fromhex(request["signature"]), signing_bytes(request))
        except Exception:
            raise ClientError("Managed client journal signature refused") from None
        return request, raw

    def _validate_state(self):
        value = self._state
        _require(type(value) is dict and set(value) == STATE_FIELDS and value["schema"] == STATE_SCHEMA)
        self._validate_setup(value["setup"])
        current = value["current"]
        _require(type(current) is dict and set(current) == CURRENT_FIELDS)
        _token(current["token"])
        for name in CURRENT_FIELDS - {"token"}:
            _integer(current[name])
        _require(current["generation"] >= value["setup"]["token_generation"]
            and current["pool_refresh_by_epoch_ms"] <= current["expires_at_epoch_ms"]
            <= value["setup"]["enrollment_expires_at_epoch_ms"])
        self._last_now = _integer(value["last_clock_ms"])
        for name in ("last_revision", "last_policy_sequence"):
            _integer(value[name], 0)
        if value["last_receipt"] is not None:
            _require(type(value["last_receipt"]) is dict and set(value["last_receipt"]) == RECEIPT_FIELDS)
            receipt = value["last_receipt"]
            _require(receipt["token_generation"] == current["generation"]
                and receipt["token_sha256"] == sha256(current["token"].encode("ascii"))
                and receipt["expires_at_epoch_ms"] == current["expires_at_epoch_ms"])
        if value["pending"] is not None:
            self._pending_request()
        self._now()

    def _prepare(self, now):
        state, setup = self._state, self._state["setup"]
        _require(now < setup["enrollment_expires_at_epoch_ms"])
        last = state["last_receipt"]
        if last is not None and last["previous_accept_until_epoch_ms"] is not None and now < last["previous_accept_until_epoch_ms"]:
            raise RenewalUnavailable("Previous token overlap is still active")
        candidate = secrets.token_urlsafe(32)
        request = {"schema": SCHEMA, "audience": setup["audience"],
            "application_id": setup["application_id"], "enrollment_id": setup["enrollment_id"],
            "expected_token_generation": state["current"]["generation"], "operation_id": str(uuid.uuid4()),
            "issued_at_epoch_ms": now, "expires_at_epoch_ms": now + REQUEST_LIFETIME_MS,
            "token_sha256": sha256(candidate.encode("ascii")),
            "token_expires_at_epoch_ms": min(now + setup["token_lifetime_seconds"] * 1000,
                setup["enrollment_expires_at_epoch_ms"])}
        _require(request["expected_token_generation"] < MAX_INTEGER)
        request["signature"] = self._key().sign(signing_bytes(request)).hex()
        raw = canonical(request)
        _require(len(raw) <= MAX_REQUEST_BYTES)
        self._save({**state, "last_clock_ms": now, "pending": {
            "candidate_token": candidate, "request_original": raw.decode("ascii")}})

    def _validate_response(self, raw, request, now):
        value = _json(raw, MAX_RESPONSE_BYTES)
        _require(type(value) is dict and set(value) == {"operation", "application", "revision", "policy"})
        receipt, app, policy = value["operation"], value["application"], value["policy"]
        _require(type(receipt) is dict and set(receipt) == RECEIPT_FIELDS)
        expected = {"operation_id": request["operation_id"], "request_sha256": sha256(signing_bytes(request)),
            "application_id": request["application_id"], "enrollment_id": request["enrollment_id"],
            "previous_generation": request["expected_token_generation"],
            "token_generation": request["expected_token_generation"] + 1, "token_sha256": request["token_sha256"],
            "issued_at_epoch_ms": request["issued_at_epoch_ms"], "expires_at_epoch_ms": request["token_expires_at_epoch_ms"]}
        _require(all(type(receipt[key]) is type(item) and receipt[key] == item for key, item in expected.items()))
        rotation = _integer(receipt["rotated_at_epoch_ms"])
        previous_expiry = self._state["current"]["expires_at_epoch_ms"]
        cutoff = receipt["previous_accept_until_epoch_ms"]
        _require(request["issued_at_epoch_ms"] - CLOCK_SKEW_MS <= rotation < request["expires_at_epoch_ms"]
            and rotation <= now + CLOCK_SKEW_MS
            and now < receipt["expires_at_epoch_ms"])
        if previous_expiry <= rotation:
            _require(cutoff is None)
        else:
            _require(_integer(cutoff) == min(previous_expiry, rotation + OVERLAP_MS))
        required = {"id", "name", "created_at", "status", "version", "principal_id", "proxy_authentication",
            "token_generation", "token_expires_at_epoch_ms", "token_status", "access_status", "active_rule_count", "client_renewal"}
        _require(type(app) is dict and required <= set(app) <= required | {"token_rotated_at", "revoked_at"}
            and app["id"] == request["application_id"] and app["status"] == "active"
            and app["principal_id"] == "agent:operator-demo:" + request["application_id"]
            and type(app["token_generation"]) is int and app["token_generation"] == receipt["token_generation"]
            and type(app["token_expires_at_epoch_ms"]) is int and app["token_expires_at_epoch_ms"] == receipt["expires_at_epoch_ms"]
            and app["token_status"] == "valid" and app["proxy_authentication"] in {"bearer", "basic_and_bearer_v1"}
            and app["access_status"] in {"active", "pending", "unassigned"})
        _integer(app["version"])
        _integer(app["active_rule_count"], 0)
        _require(all(type(app[name]) is str and 0 < len(app[name]) <= 512 for name in ("name", "created_at")))
        setup = self._state["setup"]
        enrollment = {"version": 1, "enrollment_id": setup["enrollment_id"],
            "expires_at_epoch_ms": setup["enrollment_expires_at_epoch_ms"],
            "public_key_fingerprint": setup["public_key_fingerprint"],
            "token_lifetime_seconds": setup["token_lifetime_seconds"], "overlap_seconds": 300,
            "audience": setup["audience"], "status": "active"}
        _require(type(app["client_renewal"]) is dict and canonical(app["client_renewal"]) == canonical(enrollment)
            and now < setup["enrollment_expires_at_epoch_ms"])
        _integer(value["revision"], max(1, self._state["last_revision"]))
        _require(type(policy) is dict and set(policy) == {"policy_hash", "sequence", "loaded_policy_hash", "activation"})
        _digest(policy["policy_hash"])
        _integer(policy["sequence"], max(1, self._state["last_policy_sequence"]))
        if policy["activation"] != "active" or policy["loaded_policy_hash"] != policy["policy_hash"]:
            raise RenewalUnavailable("Renewal is retained but matching current policy is not active")
        if app["access_status"] != "active" or app["active_rule_count"] < 1:
            raise RenewalUnavailable("Renewal is retained but the application has no active permission")
        return value

    def renew(self):
        _require(self._state is not None)
        now = self._now()
        if self._state["pending"] is None:
            self._prepare(now)
        request, raw = self._pending_request()
        try:
            response = self._transport(self._state["setup"]["audience"], raw)
            now = self._now()
            result = self._validate_response(response, request, now)
        except Exception:
            raise RenewalUnavailable("Renewal unavailable; exact private journal retained for recovery") from None
        receipt = result["operation"]
        current = {"token": self._state["pending"]["candidate_token"],
            "generation": receipt["token_generation"], "expires_at_epoch_ms": receipt["expires_at_epoch_ms"],
            # No previous slot means an immediate pool handoff, not a new
            # overlap or permission to retain a previously expired connection.
            "pool_refresh_by_epoch_ms": min(receipt["previous_accept_until_epoch_ms"]
                if receipt["previous_accept_until_epoch_ms"] is not None else receipt["rotated_at_epoch_ms"],
                receipt["expires_at_epoch_ms"])}
        self._save({**self._state, "current": current, "pending": None, "last_receipt": receipt,
            "last_clock_ms": now, "last_revision": result["revision"], "last_policy_sequence": result["policy"]["sequence"]})
        return TokenLease(**current)

    def lease(self):
        _require(self._state is not None)
        now = self._now()
        if self._state["pending"] is not None or self._state["last_receipt"] is None or (
                self._state["current"]["expires_at_epoch_ms"] < self._state["setup"]["enrollment_expires_at_epoch_ms"]
                and now >= self._state["current"]["expires_at_epoch_ms"] - RENEW_MARGIN_MS):
            try:
                return self.renew()
            except RenewalUnavailable:
                pass
        now, current = self._now(), self._state["current"]
        cutoff = current["expires_at_epoch_ms"]
        if self._state["pending"] is not None:
            request, _ = self._pending_request()
            # The server may already have rotated even when no response arrived.
            cutoff = min(cutoff, request["issued_at_epoch_ms"] - CLOCK_SKEW_MS + OVERLAP_MS)
        if now >= min(cutoff, self._state["setup"]["enrollment_expires_at_epoch_ms"]):
            raise RenewalUnavailable("No safely usable token; recover the retained operation or re-enroll")
        return TokenLease(**{**current, "expires_at_epoch_ms": cutoff,
            "pool_refresh_by_epoch_ms": min(current["pool_refresh_by_epoch_ms"], cutoff)})

    def status(self):
        _require(self._state is not None)
        now = self._now()
        current = self._state["current"]
        return {"application_id": self._state["setup"]["application_id"],
            "enrollment_id": self._state["setup"]["enrollment_id"], "token_generation": current["generation"],
            "token_expires_at_epoch_ms": current["expires_at_epoch_ms"],
            "enrollment_expires_at_epoch_ms": self._state["setup"]["enrollment_expires_at_epoch_ms"],
            "recovery_pending": self._state["pending"] is not None, "expired": now >= current["expires_at_epoch_ms"]}

    @property
    def application_id(self):
        _require(self._state is not None)
        return self._state["setup"]["application_id"]

    @property
    def proxy_origin(self):
        _require(self._state is not None)
        return self._state["setup"]["audience"][:-len(PUBLIC_PATH)]


def _https_exchange(audience, body):
    """Child only: stdlib HTTPS uses system trust and no ambient proxy/cookies."""
    parsed = _audience(audience)
    _require(type(body) is bytes and 0 < len(body) <= MAX_REQUEST_BYTES)
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443,
        timeout=5, context=ssl.create_default_context())
    try:
        connection.request("POST", PUBLIC_PATH, body=body,
            headers={"Content-Type": "application/json", "Accept": "application/json", "Connection": "close"})
        response = connection.getresponse()
        content_types = response.headers.get_all("Content-Type", [])
        lengths = response.headers.get_all("Content-Length", [])
        _require(response.status == 200 and len(content_types) == 1
            and content_types[0].split(";", 1)[0].strip().lower() == "application/json"
            and len(lengths) <= 1 and (not lengths or lengths[0].isdigit()
                and 0 < int(lengths[0]) <= MAX_RESPONSE_BYTES))
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        _require(0 < len(raw) <= MAX_RESPONSE_BYTES and (not lengths or len(raw) == int(lengths[0])))
        return raw
    finally:
        connection.close()


def https_post(audience, body):
    """Finite process boundary also bounds DNS and slow/trickling responses."""
    _audience(audience)
    _require(type(body) is bytes and 0 < len(body) <= MAX_REQUEST_BYTES)
    input_bytes = canonical({"audience": audience, "body": body.decode("ascii")})
    process = subprocess.Popen([sys.executable, "-I", "-B", str(Path(__file__).resolve()), "_http"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env={}, close_fds=True)
    try:
        output, _ = process.communicate(input=input_bytes, timeout=HTTP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        raise RenewalUnavailable("Renewal HTTPS deadline exceeded; outcome is unknown") from None
    _require(process.returncode == 0 and 0 < len(output) <= MAX_RESPONSE_BYTES)
    return output


def main(argv=None):
    logging.disable(logging.CRITICAL)
    if argv is None and sys.argv[1:] == ["_http"]:
        try:
            value = _json(sys.stdin.buffer.read(8193), 8192)
            _require(type(value) is dict and set(value) == {"audience", "body"} and type(value["body"]) is str)
            sys.stdout.buffer.write(_https_exchange(value["audience"], value["body"].encode("ascii")))
            return 0
        except Exception:
            return 1
    parser = argparse.ArgumentParser(description="Private single-writer managed workload client")
    parser.add_argument("--state-dir", required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="Generate or display only the public enrollment key")
    configure = sub.add_parser("configure", help="Import public enrollment setup and a private token file")
    configure.add_argument("--setup-file", required=True)
    configure.add_argument("--token-file", required=True)
    sub.add_parser("renew", help="Renew once, or recover the exact journaled operation")
    sub.add_parser("status", help="Display public local status without networking")
    args = parser.parse_args(argv)
    try:
        with ManagedClient(args.state_dir) as manager:
            if args.command == "init":
                print(manager.initialize())
            else:
                if args.command == "configure":
                    with open(args.setup_file, "rb") as stream:
                        setup = _json(stream.read(MAX_RESPONSE_BYTES + 1), MAX_RESPONSE_BYTES)
                    manager.configure(setup, args.token_file)
                elif args.command == "renew":
                    manager.renew()
                print(canonical(manager.status()).decode("ascii"))
        return 0
    except Exception:
        print("Managed client unavailable. Check private file permissions, enrollment and retained recovery state.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
