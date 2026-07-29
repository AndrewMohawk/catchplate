#!/usr/bin/env python3
"""Non-production durable live-witness reference service.

Python's sqlite3 API opens a database by pathname and cannot close the
lstat/open pathname substitution race. The SQLite backend in this file is
therefore explicitly non-production even when it uses WAL, FULL synchronous
writes, checkpoint verification, and complete history validation. It never
claims secure inode pinning or production rollback resistance.

A production deployment must replace this backend with an independently
administered, linearizable external CAS witness whose authenticated protocol,
store identity, store key, witness key, current-head selection, and monotonic
floor behavior match this closed contract. That service must protect its keys
in a KMS/HSM and issue ``externallyWitnessedRollbackProtected`` state. This
program deliberately refuses to claim that assurance.

The service receives its descriptor and all RPC/signer channels through
retained file descriptors. Store and witness identities and public keys come
only from a separate immutable release-signed trust-config FD, never from the
mutable descriptor. It never accepts a private key, signer command, or shell
command. Production-shaped signer channels are authenticated Unix sockets; the
signer protocol binds every response to a per-launch channel nonce, monotonic
RPC sequence, exact signer identity, key, domain, and message, and every
returned Ed25519 signature is verified locally before use.

The launcher must independently measurement-pin the expected release-root and
trust-config SHA-256 command-line values and retain the corresponding immutable
FDs. Accepting caller-selected values would make the release signature
self-asserted and is not a production trust boundary.
"""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import json
import os
import re
import secrets
import select
import socket
import sqlite3
import stat
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol


U64_MAX = 18_446_744_073_709_551_615
MAX_SQLITE_HISTORY_ROWS = 1_000_000
MAX_FRAME_BYTES = 1_048_576
MAX_TTL_SECONDS = 300
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 4096
MAX_SIGNER_RPC_TIMEOUT_MILLISECONDS = 30_000
MAX_SERVICE_CHALLENGE_FRAME_BYTES = 16 * 1024
MAX_SERVICE_EXECUTABLE_BYTES = 256 * 1024 * 1024

DESCRIPTOR_VERSION = "serverware.attestationWitnessServiceDescriptor/v2"
STORE_IDENTITY_VERSION = "serverware.attestationWitnessStoreIdentity/v2"
ADVANCE_REQUEST_VERSION = "serverware.attestationWitnessAdvanceRequest/v1"
CURRENT_REQUEST_VERSION = "serverware.attestationWitnessCurrentRequest/v2"
ADVANCE_RESPONSE_VERSION = "serverware.attestationWitnessAdvanceResponse/v1"
CURRENT_RESPONSE_VERSION = "serverware.attestationWitnessCurrentResponse/v2"
ERROR_RESPONSE_VERSION = "serverware.attestationWitnessServiceError/v1"
SERVICE_CHALLENGE_VERSION = (
    "serverware.publicAttestationServiceChannelChallenge/v1"
)
SERVICE_CHALLENGE_RESPONSE_VERSION = (
    "serverware.publicAttestationServiceChannelChallengeResponse/v1"
)
SERVICE_PROTOCOL_VERSION = "serverware.attestationWitnessService/v2"
INVOCATION_BINDING_VERSION = (
    "serverware.attestationWitnessInvocationBinding/v1"
)
LIVE_WITNESS_HEAD_VERSION = "serverware.liveWitnessHead/v1"
PROTECTED_STATE_VERSION = "serverware.protectedLiveWitnessState/v2"
CAS_RECEIPT_VERSION = "serverware.liveWitnessCasReceipt/v1"
SIGNER_REQUEST_VERSION = "serverware.attestationSignerRequest/v2"
SIGNER_RESPONSE_VERSION = "serverware.attestationSignerResponse/v2"
SIGNER_IDENTITY_VERSION = "serverware.attestationSignerServiceIdentity/v1"
IMMUTABLE_TRUST_ENVELOPE_VERSION = (
    "serverware.attestationWitnessImmutableTrustConfigEnvelope/v1"
)
IMMUTABLE_TRUST_CONFIG_VERSION = (
    "serverware.attestationWitnessImmutableTrustConfig/v1"
)

LIVE_WITNESS_DOMAIN = (
    b"serverware.liveWitnessHead/v1\x00Ed25519\x00"
)
PROTECTED_STATE_DOMAIN = (
    b"serverware.protectedLiveWitnessState/v2\x00Ed25519\x00"
)
SIGNER_PROTOCOL_DOMAIN = (
    b"serverware.attestationSignerRequest/v2\x00"
)
IMMUTABLE_TRUST_CONFIG_DOMAIN = (
    b"serverware.attestationWitnessImmutableTrustConfigEnvelope/v1"
    b"\x00Ed25519\x00"
)
CHECKPOINT_DOMAIN = b"serverware:live-witness-checkpoint:v1:"
HEAD_DOMAIN = b"serverware:live-witness-head-chain:v1:"
CONTINUITY_DOMAIN = b"serverware:live-witness-continuity:v1:"

SHA256_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
IDENTIFIER_RE = re.compile(
    r"\A[a-z0-9][a-z0-9._:/-]{1,126}[a-z0-9]\Z"
)
BASE64URL_32_RE = re.compile(r"\A[A-Za-z0-9_-]{43}\Z")
BASE64URL_64_RE = re.compile(r"\A[A-Za-z0-9_-]{86}\Z")
CGROUP_COMPONENT_RE = re.compile(r"\A[A-Za-z0-9._+@=-]+\Z")


class WitnessServiceError(ValueError):
    pass


class ClientFrameError(WitnessServiceError):
    pass


class ClientRequestError(WitnessServiceError):
    pass


class FatalWitnessServiceError(RuntimeError):
    pass


class Signer(Protocol):
    @property
    def key_id(self) -> str:
        ...

    def sign(self, *, domain: bytes, message: bytes) -> bytes:
        ...

    def verify(
        self,
        *,
        domain: bytes,
        message: bytes,
        signature: bytes,
    ) -> None:
        ...

    @property
    def public_key_spki_der(self) -> bytes:
        ...


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def canonical_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decode_base64url(
    value: Any,
    *,
    expected_bytes: int,
    label: str,
) -> bytes:
    if not isinstance(value, str):
        raise WitnessServiceError(f"{label} must be base64url text")
    expected_chars = (expected_bytes * 8 + 5) // 6
    if len(value) != expected_chars or re.fullmatch(
        r"[A-Za-z0-9_-]+", value
    ) is None:
        raise WitnessServiceError(f"{label} has the wrong base64url shape")
    try:
        decoded = base64.urlsafe_b64decode(
            value + "=" * ((4 - len(value) % 4) % 4)
        )
    except ValueError as exc:
        raise WitnessServiceError(f"{label} is invalid base64url") from exc
    if (
        len(decoded) != expected_bytes
        or canonical_base64url(decoded) != value
    ):
        raise WitnessServiceError(f"{label} is not canonical base64url")
    return decoded


def _reject_constant(value: str) -> None:
    raise WitnessServiceError(f"non-finite JSON number is forbidden: {value}")


def _closed_object(
    value: Any,
    expected: set[str],
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise WitnessServiceError(f"{label} is not a closed object")
    return value


def _pairs_object(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise WitnessServiceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _require_raw_json_depth(raw: bytes, *, label: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in {0x5B, 0x7B}:
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise WitnessServiceError(
                    f"{label} exceeds the JSON depth bound"
                )
        elif byte in {0x5D, 0x7D}:
            depth -= 1
            if depth < 0:
                raise WitnessServiceError(
                    f"{label} has unbalanced JSON delimiters"
                )


def parse_canonical_json(raw: bytes, *, label: str) -> dict[str, Any]:
    if not raw or len(raw) > MAX_FRAME_BYTES:
        raise WitnessServiceError(f"{label} size is invalid")
    _require_raw_json_depth(raw, label=label)
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_pairs_object,
            parse_constant=_reject_constant,
        )
    except (RecursionError, UnicodeDecodeError, ValueError) as exc:
        raise WitnessServiceError(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise WitnessServiceError(f"{label} is not canonical JSON")
    nodes = 0
    pending: list[tuple[Any, int]] = [(value, 1)]
    while pending:
        current, depth = pending.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise WitnessServiceError(f"{label} exceeds the JSON node bound")
        if depth > MAX_JSON_DEPTH:
            raise WitnessServiceError(f"{label} exceeds the JSON depth bound")
        if isinstance(current, dict):
            pending.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            pending.extend((item, depth + 1) for item in current)
    return value


def require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise WitnessServiceError(f"{label} is not a sha256 digest")
    return value


def require_u64(
    value: Any,
    label: str,
    *,
    minimum: int = 0,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= U64_MAX
    ):
        raise WitnessServiceError(f"{label} is not a bounded unsigned integer")
    return value


def require_identifier(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or IDENTIFIER_RE.fullmatch(value) is None
    ):
        raise WitnessServiceError(f"{label} is not a canonical identifier")
    return value


def require_absolute_normal_path(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or "\x00" in value
        or not value.startswith("/")
        or value == "/"
        or value.endswith("/")
        or "//" in value
        or os.path.normpath(value) != value
    ):
        raise WitnessServiceError(f"{label} is not a normalized absolute path")
    components = value.split("/")[1:]
    if any(component in {"", ".", ".."} for component in components):
        raise WitnessServiceError(f"{label} contains a forbidden component")
    return value


def validate_store_identity(value: Any) -> dict[str, Any]:
    identity = _closed_object(
        value,
        {
            "apiVersion",
            "assurance",
            "deploymentId",
            "serviceId",
            "storageBackend",
        },
        "witness store identity",
    )
    if identity["apiVersion"] != STORE_IDENTITY_VERSION:
        raise WitnessServiceError("witness store identity version is invalid")
    assurance = identity["assurance"]
    if assurance not in {
        "nonProductionFixture",
        "nonProductionSqliteReference",
        "externallyWitnessedRollbackProtected",
    }:
        raise WitnessServiceError("witness store assurance is invalid")
    require_identifier(identity["deploymentId"], "store deployment id")
    require_identifier(identity["serviceId"], "store service id")
    expected_backend = {
        "nonProductionFixture": "fixture-sqlite",
        "nonProductionSqliteReference": "sqlite-wal-full-sync",
        "externallyWitnessedRollbackProtected":
        "external-linearizable-cas",
    }[assurance]
    if identity["storageBackend"] != expected_backend:
        raise WitnessServiceError(
            "witness store assurance and backend disagree"
        )
    return identity


def validate_peer_credentials(value: Any, label: str) -> dict[str, int]:
    peer = _closed_object(value, {"gid", "pid", "uid"}, label)
    return {
        "gid": require_u64(peer["gid"], f"{label} gid"),
        "pid": require_u64(peer["pid"], f"{label} pid", minimum=1),
        "uid": require_u64(peer["uid"], f"{label} uid"),
    }


def authenticate_unix_channel_fd(
    fd: int,
    *,
    direction: str,
    expected_peer: Mapping[str, Any],
    socket_type: str,
    label: str,
    repeatable_control_frames: bool = False,
) -> None:
    if direction not in {"read", "write"}:
        raise FatalWitnessServiceError(f"{label} direction is invalid")
    expected_socket_type = {
        "unix-seqpacket": socket.SOCK_SEQPACKET,
        "unix-stream": socket.SOCK_STREAM,
    }.get(socket_type)
    if expected_socket_type is None:
        raise FatalWitnessServiceError(f"{label} socket type is invalid")
    expected = validate_peer_credentials(expected_peer, f"{label} peer")
    if not hasattr(socket, "SO_PEERCRED"):
        raise FatalWitnessServiceError(
            f"{label} requires Linux SO_PEERCRED authentication"
        )
    duplicated = os.dup(fd)
    channel: socket.socket | None = None
    try:
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        channel = socket.socket(fileno=duplicated)
        if channel.family != socket.AF_UNIX:
            raise FatalWitnessServiceError(f"{label} is not an AF_UNIX socket")
        actual_type = channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
        if actual_type != expected_socket_type:
            raise FatalWitnessServiceError(f"{label} socket type changed")
        channel.getpeername()
        raw_peer = channel.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            struct.calcsize("3i"),
        )
        pid, uid, gid = struct.unpack("3i", raw_peer)
        if {"pid": pid, "uid": uid, "gid": gid} != expected:
            raise FatalWitnessServiceError(
                f"{label} Unix peer credentials changed"
            )
        if repeatable_control_frames:
            if (flags & os.O_ACCMODE) != os.O_RDWR:
                raise FatalWitnessServiceError(
                    f"{label} must be read-write for launcher challenges"
                )
        elif direction == "read":
            channel.shutdown(socket.SHUT_WR)
        else:
            channel.shutdown(socket.SHUT_RD)
    except OSError as exc:
        raise FatalWitnessServiceError(
            f"{label} Unix channel authentication failed"
        ) from exc
    finally:
        if channel is not None:
            channel.close()
        else:
            os.close(duplicated)


class BoundedJsonLineFd:
    def __init__(
        self,
        fd: int,
        *,
        max_bytes: int,
        recoverable_frames: bool = False,
        packet_mode: bool = False,
        socket_timeout_seconds: float | None = None,
    ) -> None:
        if (
            isinstance(fd, bool)
            or not isinstance(fd, int)
            or fd < 3
        ):
            raise WitnessServiceError("service channel fd is invalid")
        if not 1 <= max_bytes <= MAX_FRAME_BYTES:
            raise WitnessServiceError("service channel bound is invalid")
        os.fstat(fd)
        self._fd = fd
        self._max_bytes = max_bytes
        self._recoverable_frames = recoverable_frames
        self._packet_socket = (
            socket.socket(fileno=os.dup(fd)) if packet_mode else None
        )
        if (
            self._packet_socket is not None
            and socket_timeout_seconds is not None
        ):
            self._packet_socket.settimeout(socket_timeout_seconds)
        self._buffer = bytearray()

    @property
    def has_buffered_data(self) -> bool:
        return bool(self._buffer)

    def close(self) -> None:
        if self._packet_socket is not None:
            self._packet_socket.close()
            self._packet_socket = None

    def _frame_error(self, message: str) -> WitnessServiceError:
        if self._recoverable_frames:
            return ClientFrameError(message)
        return WitnessServiceError(message)

    def _discard_oversized_frame(self, *, label: str) -> None:
        self._buffer.clear()
        while True:
            chunk = os.read(self._fd, 65536)
            if not chunk:
                raise self._frame_error(
                    f"{label} ended while discarding an oversized frame"
                )
            newline = chunk.find(b"\n")
            if newline >= 0:
                self._buffer.extend(chunk[newline + 1:])
                raise self._frame_error(f"{label} exceeds its size bound")

    def read(self, *, label: str) -> dict[str, Any] | None:
        if self._packet_socket is not None:
            try:
                raw_frame, _, flags, _ = self._packet_socket.recvmsg(
                    self._max_bytes + 2
                )
            except OSError as exc:
                raise self._frame_error(f"{label} receive failed") from exc
            if not raw_frame:
                return None
            if (
                flags & getattr(socket, "MSG_TRUNC", 0)
                or len(raw_frame) > self._max_bytes + 1
            ):
                raise self._frame_error(f"{label} exceeds its size bound")
            if (
                not raw_frame.endswith(b"\n")
                or b"\n" in raw_frame[:-1]
            ):
                raise self._frame_error(
                    f"{label} is not one canonical JSON packet"
                )
            try:
                return parse_canonical_json(
                    raw_frame[:-1], label=label
                )
            except WitnessServiceError as exc:
                raise self._frame_error(str(exc)) from exc
        while True:
            newline = self._buffer.find(b"\n")
            if newline >= 0:
                if newline > self._max_bytes:
                    del self._buffer[: newline + 1]
                    raise self._frame_error(
                        f"{label} exceeds its size bound"
                    )
                raw = bytes(self._buffer[:newline])
                del self._buffer[: newline + 1]
                try:
                    return parse_canonical_json(raw, label=label)
                except WitnessServiceError as exc:
                    raise self._frame_error(str(exc)) from exc
            if len(self._buffer) > self._max_bytes:
                self._discard_oversized_frame(label=label)
            chunk = os.read(self._fd, min(65536, self._max_bytes + 2))
            if not chunk:
                if self._buffer:
                    raise self._frame_error(
                        f"{label} ended without a line terminator"
                    )
                return None
            self._buffer.extend(chunk)

    def write(self, value: Mapping[str, Any]) -> None:
        raw = canonical_json_bytes(value) + b"\n"
        if len(raw) > self._max_bytes + 1:
            raise WitnessServiceError("service response exceeds its size bound")
        if self._packet_socket is not None:
            try:
                written = self._packet_socket.send(raw)
            except OSError as exc:
                raise WitnessServiceError(
                    "service response packet failed"
                ) from exc
            if written != len(raw):
                raise WitnessServiceError(
                    "service response packet was not atomic"
                )
            return
        offset = 0
        while offset < len(raw):
            written = os.write(self._fd, raw[offset:])
            if written <= 0:
                raise WitnessServiceError("service response channel closed")
            offset += written


def _live_service_executable_sha256() -> str:
    try:
        descriptor = os.open(
            "/proc/self/exe",
            os.O_RDONLY | os.O_CLOEXEC,
        )
    except OSError as exc:
        raise FatalWitnessServiceError(
            "live service executable is unavailable"
        ) from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) & 0o111 == 0
            or before.st_size < 1
            or before.st_size > MAX_SERVICE_EXECUTABLE_BYTES
        ):
            raise FatalWitnessServiceError(
                "live service executable identity is invalid"
            )
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_SERVICE_EXECUTABLE_BYTES:
                raise FatalWitnessServiceError(
                    "live service executable exceeds its size bound"
                )
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (
            total != before.st_size
            or after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or after.st_size != before.st_size
        ):
            raise FatalWitnessServiceError(
                "live service executable changed while hashing"
            )
        return "sha256:" + digest.hexdigest()
    except OSError as exc:
        raise FatalWitnessServiceError(
            "live service executable measurement failed"
        ) from exc
    finally:
        os.close(descriptor)


def _live_service_cgroup_path() -> str:
    try:
        descriptor = os.open(
            "/proc/self/cgroup",
            os.O_RDONLY | os.O_CLOEXEC,
        )
        try:
            materialized = bytearray()
            while len(materialized) <= 4096:
                chunk = os.read(
                    descriptor,
                    4097 - len(materialized),
                )
                if not chunk:
                    break
                materialized.extend(chunk)
            raw = bytes(materialized)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise FatalWitnessServiceError(
            "live service cgroup membership is unavailable"
        ) from exc
    if len(raw) > 4096:
        raise FatalWitnessServiceError(
            "live service cgroup membership exceeds its bound"
        )
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise FatalWitnessServiceError(
            "live service cgroup membership is not ASCII"
        ) from exc
    if len(lines) != 1 or not lines[0].startswith("0::"):
        raise FatalWitnessServiceError(
            "service does not have one cgroup-v2 membership"
        )
    try:
        membership = require_absolute_normal_path(
            lines[0][3:],
            "live service cgroup membership",
        )
    except WitnessServiceError as exc:
        raise FatalWitnessServiceError(
            "live service cgroup membership is not normalized"
        ) from exc
    if any(
        CGROUP_COMPONENT_RE.fullmatch(component) is None
        for component in membership.split("/")[1:]
    ):
        raise FatalWitnessServiceError(
            "live service cgroup membership has an invalid component"
        )
    return membership


def _service_challenge_response(
    request: Mapping[str, Any],
    *,
    direction: str,
    role: str,
) -> dict[str, Any]:
    try:
        challenge = _closed_object(
            request,
            {
                "apiVersion",
                "challengeBase64url",
                "direction",
                "protocol",
                "role",
            },
            f"{role} service channel challenge",
        )
        if (
            len(canonical_json_bytes(challenge))
            > MAX_SERVICE_CHALLENGE_FRAME_BYTES
            or challenge["apiVersion"] != SERVICE_CHALLENGE_VERSION
            or challenge["direction"] != direction
            or challenge["protocol"] != SERVICE_PROTOCOL_VERSION
            or challenge["role"] != role
        ):
            raise WitnessServiceError(
                f"{role} service channel challenge crossed its contract"
            )
        decode_base64url(
            challenge["challengeBase64url"],
            expected_bytes=32,
            label=f"{role} service channel challenge",
        )
    except WitnessServiceError as exc:
        raise FatalWitnessServiceError(
            f"{role} service channel challenge is invalid"
        ) from exc
    return {
        "apiVersion": SERVICE_CHALLENGE_RESPONSE_VERSION,
        "challengeBase64url": challenge["challengeBase64url"],
        "direction": direction,
        "peerCgroupPath": _live_service_cgroup_path(),
        "peerExecutableSha256": _live_service_executable_sha256(),
        "protocol": SERVICE_PROTOCOL_VERSION,
        "role": role,
    }


def _load_ed25519_public_key(der: bytes, label: str) -> Any:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )

        key = serialization.load_der_public_key(der)
    except Exception as exc:
        raise FatalWitnessServiceError(
            f"{label} is not a valid DER public key"
        ) from exc
    if not isinstance(key, Ed25519PublicKey):
        raise FatalWitnessServiceError(f"{label} is not Ed25519")
    return key


def validate_signer_identity(value: Any, label: str) -> dict[str, Any]:
    identity = _closed_object(
        value,
        {
            "apiVersion",
            "deploymentId",
            "keySpkiSha256",
            "role",
            "serviceId",
        },
        label,
    )
    if identity["apiVersion"] != SIGNER_IDENTITY_VERSION:
        raise WitnessServiceError(f"{label} version is invalid")
    require_identifier(identity["deploymentId"], f"{label} deployment id")
    require_identifier(identity["serviceId"], f"{label} service id")
    require_sha256(identity["keySpkiSha256"], f"{label} key")
    if identity["role"] not in {"liveWitness", "witnessStore"}:
        raise WitnessServiceError(f"{label} role is invalid")
    return identity


class FdSigner:
    is_non_production_fixture = False

    def __init__(
        self,
        *,
        request_fd: int,
        response_fd: int,
        key_id: str,
        public_key_spki_der: bytes,
        signer_identity: Mapping[str, Any],
        expected_peer: Mapping[str, Any],
        socket_type: str,
        rpc_timeout_milliseconds: int,
        max_frame_bytes: int = 131072,
    ) -> None:
        self._key_id = require_sha256(key_id, "signer key id")
        if (
            not isinstance(public_key_spki_der, bytes)
            or len(public_key_spki_der) != 44
            or sha256_bytes(public_key_spki_der) != self._key_id
        ):
            raise FatalWitnessServiceError(
                "signer public key does not match its immutable pin"
            )
        self._public_key_spki_der = public_key_spki_der
        self._public_key = _load_ed25519_public_key(
            public_key_spki_der, "signer public key"
        )
        self._identity = validate_signer_identity(
            signer_identity, "signer identity"
        )
        if self._identity["keySpkiSha256"] != self._key_id:
            raise FatalWitnessServiceError(
                "signer identity and public key disagree"
            )
        self._identity_sha256 = sha256_json(self._identity)
        timeout_milliseconds = require_u64(
            rpc_timeout_milliseconds,
            "signer RPC timeout milliseconds",
            minimum=1,
        )
        if timeout_milliseconds > MAX_SIGNER_RPC_TIMEOUT_MILLISECONDS:
            raise FatalWitnessServiceError(
                "signer RPC timeout exceeds its bound"
            )
        timeout_seconds = timeout_milliseconds / 1000
        authenticate_unix_channel_fd(
            request_fd,
            direction="write",
            expected_peer=expected_peer,
            socket_type=socket_type,
            label="signer request channel",
        )
        authenticate_unix_channel_fd(
            response_fd,
            direction="read",
            expected_peer=expected_peer,
            socket_type=socket_type,
            label="signer response channel",
        )
        self._requests = BoundedJsonLineFd(
            request_fd,
            max_bytes=max_frame_bytes,
            packet_mode=(socket_type == "unix-seqpacket"),
            socket_timeout_seconds=timeout_seconds,
        )
        self._responses = BoundedJsonLineFd(
            response_fd,
            max_bytes=max_frame_bytes,
            packet_mode=(socket_type == "unix-seqpacket"),
            socket_timeout_seconds=timeout_seconds,
        )
        self._channel_nonce = canonical_base64url(secrets.token_bytes(32))
        self._rpc_sequence = 0

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def public_key_spki_der(self) -> bytes:
        return self._public_key_spki_der

    def sign(self, *, domain: bytes, message: bytes) -> bytes:
        self._rpc_sequence = require_u64(
            self._rpc_sequence + 1,
            "signer RPC sequence",
            minimum=1,
        )
        request = {
            "apiVersion": SIGNER_REQUEST_VERSION,
            "channelNonceBase64url": self._channel_nonce,
            "domainBase64url": canonical_base64url(domain),
            "messageBase64url": canonical_base64url(message),
            "messageSha256": sha256_bytes(message),
            "rpcSequence": self._rpc_sequence,
            "signerIdentitySha256": self._identity_sha256,
            "signingKeyId": self._key_id,
        }
        request_sha256 = sha256_bytes(
            SIGNER_PROTOCOL_DOMAIN + canonical_json_bytes(request)
        )
        try:
            self._requests.write(request)
            response = self._responses.read(label="signer response")
        except (OSError, WitnessServiceError) as exc:
            raise FatalWitnessServiceError("signer RPC failed") from exc
        if response is None:
            raise FatalWitnessServiceError("signer response channel closed")
        try:
            response = _closed_object(
                response,
                {
                    "apiVersion",
                    "channelNonceBase64url",
                    "requestSha256",
                    "rpcSequence",
                    "signatureBase64url",
                    "signerIdentitySha256",
                    "signingKeyId",
                },
                "signer response",
            )
        except WitnessServiceError as exc:
            raise FatalWitnessServiceError(
                "signer returned a malformed response"
            ) from exc
        try:
            response_sequence = require_u64(
                response["rpcSequence"],
                "signer response RPC sequence",
                minimum=1,
            )
        except WitnessServiceError as exc:
            raise FatalWitnessServiceError(
                "signer response RPC sequence is malformed"
            ) from exc
        if (
            response["apiVersion"] != SIGNER_RESPONSE_VERSION
            or response["channelNonceBase64url"] != self._channel_nonce
            or response["requestSha256"] != request_sha256
            or response_sequence != self._rpc_sequence
            or response["signerIdentitySha256"] != self._identity_sha256
            or response["signingKeyId"] != self._key_id
        ):
            raise FatalWitnessServiceError(
                "signer response binding is invalid"
            )
        if (
            not isinstance(response["signatureBase64url"], str)
            or BASE64URL_64_RE.fullmatch(
                response["signatureBase64url"]
            ) is None
        ):
            raise FatalWitnessServiceError(
                "signer response signature is invalid"
            )
        try:
            signature = decode_base64url(
                response["signatureBase64url"],
                expected_bytes=64,
                label="signer response signature",
            )
        except WitnessServiceError as exc:
            raise FatalWitnessServiceError(
                "signer response signature is malformed"
            ) from exc
        self.verify(domain=domain, message=message, signature=signature)
        return signature

    def verify(
        self,
        *,
        domain: bytes,
        message: bytes,
        signature: bytes,
    ) -> None:
        try:
            self._public_key.verify(signature, domain + message)
        except Exception as exc:
            raise FatalWitnessServiceError(
                "signer returned an invalid Ed25519 signature"
            ) from exc

    def close(self) -> None:
        self._requests.close()
        self._responses.close()


class FixtureEd25519Signer:
    """Explicitly non-production signer for source fixtures only."""

    is_non_production_fixture = True

    def __init__(self, private_key: Any, *, non_production: bool) -> None:
        if non_production is not True:
            raise WitnessServiceError(
                "fixture signer requires explicit non-production acknowledgement"
            )
        from cryptography.hazmat.primitives import serialization

        der = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self._public_key_spki_der = der
        self._key_id = sha256_bytes(der)

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def public_key_spki_der(self) -> bytes:
        return self._public_key_spki_der

    def sign(self, *, domain: bytes, message: bytes) -> bytes:
        return self._private_key.sign(domain + message)

    def verify(
        self,
        *,
        domain: bytes,
        message: bytes,
        signature: bytes,
    ) -> None:
        try:
            self._public_key.verify(signature, domain + message)
        except Exception as exc:
            raise FatalWitnessServiceError(
                "fixture signer returned an invalid signature"
            ) from exc


def signed_envelope(
    *,
    api_version: str,
    domain: bytes,
    payload: Mapping[str, Any],
    signer: Signer,
) -> dict[str, Any]:
    payload_document = dict(payload)
    payload_sha256 = sha256_json(payload_document)
    message = canonical_json_bytes(
        {
            "payload": payload_document,
            "payloadSha256": payload_sha256,
        }
    )
    signature = signer.sign(domain=domain, message=message)
    if len(signature) != 64:
        raise FatalWitnessServiceError(
            "signer returned a non-Ed25519 signature"
        )
    signer.verify(domain=domain, message=message, signature=signature)
    return {
        "apiVersion": api_version,
        "payload": payload_document,
        "payloadSha256": payload_sha256,
        "signature": canonical_base64url(signature),
        "signingKeyId": signer.key_id,
    }


@dataclass(frozen=True)
class StoredCheckpoint:
    ordinal: int
    release_identity_sha256: str
    generation: int
    rollback_epoch: int
    sequence: int
    tree_size: int
    event_sha256: str
    checkpoint_sha256: str
    head_sha256: str
    previous_continuity_sha256: str | None
    continuity_sha256: str
    transaction_id_base64url: str
    idempotency_key_base64url: str
    request_sha256: str
    committed_at_unix: int
    cas_receipt: dict[str, Any]

    def prior_document(self) -> dict[str, Any]:
        return {
            "checkpointSha256": self.checkpoint_sha256,
            "generation": self.generation,
            "headSha256": self.head_sha256,
            "releaseIdentitySha256": self.release_identity_sha256,
            "rollbackEpoch": self.rollback_epoch,
            "sequence": self.sequence,
            "treeSize": self.tree_size,
        }


class DurableWitnessStore:
    def __init__(
        self,
        *,
        database_path: str,
        store_identity: Mapping[str, Any],
        expected_store_identity_sha256: str,
        expected_store_key_spki_sha256: str,
        expected_store_signing_public_key_spki_der_base64url: str,
        witness_signer: Signer,
        store_signer: Signer,
        allow_create: bool,
        expected_witness_key_spki_sha256: str | None = None,
        expected_witness_signing_public_key_spki_der_base64url: str | None = None,
        max_history_rows: int = 100000,
        live_head_ttl_seconds: int = 30,
        protected_state_ttl_seconds: int = 30,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._database_path = require_absolute_normal_path(
            database_path, "witness database path"
        )
        self._identity = validate_store_identity(dict(store_identity))
        self._assurance = self._identity["assurance"]
        if self._assurance == "externallyWitnessedRollbackProtected":
            raise WitnessServiceError(
                "production requires the external linearizable CAS witness; "
                "the Python SQLite reference cannot claim production assurance"
            )
        if self._assurance == "nonProductionFixture" and allow_create is not True:
            raise WitnessServiceError("fixture SQLite must be explicitly creatable")
        if self._assurance == "nonProductionSqliteReference" and allow_create:
            raise WitnessServiceError(
                "the non-production SQLite reference must be pre-created"
            )
        self._identity_sha256 = sha256_json(self._identity)
        if (
            self._identity_sha256
            != require_sha256(
                expected_store_identity_sha256,
                "expected witness store identity",
            )
        ):
            raise WitnessServiceError("witness store identity pin mismatch")
        self._store_signer = store_signer
        self._witness_signer = witness_signer
        if (
            getattr(store_signer, "is_non_production_fixture", False)
            or getattr(
                witness_signer, "is_non_production_fixture", False
            )
        ) and self._assurance != "nonProductionFixture":
            raise WitnessServiceError(
                "fixture signing keys cannot issue non-fixture witness state"
            )
        self._store_key_id = require_sha256(
            expected_store_key_spki_sha256,
            "expected witness store key",
        )
        store_public_key_der = decode_base64url(
            expected_store_signing_public_key_spki_der_base64url,
            expected_bytes=44,
            label="witness store signing public key SPKI",
        )
        if sha256_bytes(store_public_key_der) != self._store_key_id:
            raise WitnessServiceError(
                "witness store public key and key digest disagree"
            )
        if self._store_signer.key_id != self._store_key_id:
            raise WitnessServiceError("witness store signer pin mismatch")
        if expected_witness_key_spki_sha256 is None:
            if self._assurance != "nonProductionFixture":
                raise WitnessServiceError(
                    "non-fixture witness key pin is required"
                )
            expected_witness_key_spki_sha256 = sha256_bytes(
                witness_signer.public_key_spki_der
            )
        self._witness_key_id = require_sha256(
            expected_witness_key_spki_sha256,
            "expected witness signing key",
        )
        if expected_witness_signing_public_key_spki_der_base64url is None:
            if self._assurance != "nonProductionFixture":
                raise WitnessServiceError(
                    "non-fixture witness public key is required"
                )
            witness_public_key_der = witness_signer.public_key_spki_der
        else:
            witness_public_key_der = decode_base64url(
                expected_witness_signing_public_key_spki_der_base64url,
                expected_bytes=44,
                label="witness signing public key SPKI",
            )
        if sha256_bytes(witness_public_key_der) != self._witness_key_id:
            raise WitnessServiceError(
                "witness public key and key digest disagree"
            )
        if (
            self._witness_signer.key_id != self._witness_key_id
            or self._witness_signer.public_key_spki_der
            != witness_public_key_der
        ):
            raise WitnessServiceError("witness signer pin mismatch")
        if (
            self._store_signer.public_key_spki_der != store_public_key_der
            or self._witness_key_id == self._store_key_id
            or witness_public_key_der == store_public_key_der
        ):
            raise WitnessServiceError(
                "live witness and witness-store keys must be distinct"
            )
        self._max_history_rows = require_u64(
            max_history_rows,
            "maximum witness history rows",
            minimum=1,
        )
        if self._max_history_rows > MAX_SQLITE_HISTORY_ROWS:
            raise WitnessServiceError("witness history bound is too large")
        self._live_ttl = require_u64(
            live_head_ttl_seconds,
            "live witness ttl",
            minimum=1,
        )
        self._state_ttl = require_u64(
            protected_state_ttl_seconds,
            "protected witness state ttl",
            minimum=1,
        )
        if (
            self._live_ttl > MAX_TTL_SECONDS
            or self._state_ttl > MAX_TTL_SECONDS
        ):
            raise WitnessServiceError("witness ttl exceeds the service maximum")
        self._clock = clock or (lambda: int(time.time()))
        self._prepare_non_production_database_path(allow_create=allow_create)
        self._connection = sqlite3.connect(
            self._database_path,
            timeout=5.0,
            isolation_level=None,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute("PRAGMA wal_autocheckpoint=1")
        self._connection.execute("PRAGMA busy_timeout=5000")
        self._connection.execute("PRAGMA trusted_schema=OFF")
        self._connection.execute("PRAGMA secure_delete=ON")
        self._require_sqlite_configuration()
        self._initialize_schema()
        self._checkpoint_and_require()
        self._verified_history: list[StoredCheckpoint] = []
        self._load_history()

    @property
    def store_identity_sha256(self) -> str:
        return self._identity_sha256

    @property
    def store_key_spki_sha256(self) -> str:
        return self._store_key_id

    def close(self) -> None:
        try:
            self._connection.close()
        finally:
            for signer in (self._store_signer, self._witness_signer):
                close = getattr(signer, "close", None)
                if callable(close):
                    close()

    def _prepare_non_production_database_path(
        self,
        *,
        allow_create: bool,
    ) -> None:
        path = Path(self._database_path)
        parent = path.parent
        parent_stat = os.lstat(parent)
        if (
            not stat.S_ISDIR(parent_stat.st_mode)
            or parent_stat.st_uid != os.geteuid()
            or parent_stat.st_mode & 0o022
        ):
            raise WitnessServiceError("witness database parent is not a directory")
        if stat.S_ISLNK(parent_stat.st_mode):
            raise WitnessServiceError("witness database parent cannot be a symlink")
        if not path.exists():
            if not allow_create:
                raise WitnessServiceError("pinned witness database is missing")
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            fd = os.open(self._database_path, flags, 0o600)
            os.close(fd)
            directory_fd = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        file_stat = os.lstat(self._database_path)
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or stat.S_ISLNK(file_stat.st_mode)
            or file_stat.st_uid != os.geteuid()
            or file_stat.st_mode & 0o077
        ):
            raise WitnessServiceError(
                "witness database must be a private regular file"
            )

    def _read_pragma_scalar(self, pragma: str) -> Any:
        row = self._connection.execute(f"PRAGMA {pragma}").fetchone()
        if row is None or len(row) != 1:
            raise FatalWitnessServiceError(
                f"SQLite PRAGMA {pragma} did not return one value"
            )
        return row[0]

    def _require_sqlite_configuration(self) -> None:
        expected = {
            "busy_timeout": 5000,
            "foreign_keys": 1,
            "journal_mode": "wal",
            "secure_delete": 1,
            "synchronous": 2,
            "trusted_schema": 0,
            "wal_autocheckpoint": 1,
        }
        for pragma, expected_value in expected.items():
            actual = self._read_pragma_scalar(pragma)
            if isinstance(actual, str):
                actual = actual.lower()
            if actual != expected_value:
                raise FatalWitnessServiceError(
                    f"SQLite PRAGMA {pragma} is not enforced"
                )

    def _checkpoint_and_require(self) -> None:
        row = self._connection.execute("PRAGMA wal_checkpoint(FULL)").fetchone()
        if row is None or len(row) != 3:
            raise FatalWitnessServiceError(
                "SQLite WAL checkpoint returned an invalid result"
            )
        busy, log_frames, checkpointed_frames = row
        for value in row:
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise FatalWitnessServiceError(
                    "SQLite WAL checkpoint returned invalid counters"
                )
        if busy != 0 or checkpointed_frames != log_frames:
            raise FatalWitnessServiceError(
                "SQLite WAL checkpoint did not fully complete"
            )
        self._require_sqlite_configuration()

    def _initialize_schema(self) -> None:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS witness_metadata (
                    key TEXT PRIMARY KEY NOT NULL,
                    value TEXT NOT NULL
                ) STRICT
                """
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS witness_transitions (
                    ordinal INTEGER PRIMARY KEY,
                    release_identity_sha256 TEXT NOT NULL,
                    generation_decimal TEXT NOT NULL,
                    rollback_epoch_decimal TEXT NOT NULL,
                    sequence_decimal TEXT NOT NULL,
                    tree_size_decimal TEXT NOT NULL,
                    event_sha256 TEXT NOT NULL,
                    checkpoint_sha256 TEXT NOT NULL UNIQUE,
                    head_sha256 TEXT NOT NULL UNIQUE,
                    previous_continuity_sha256 TEXT,
                    continuity_sha256 TEXT NOT NULL UNIQUE,
                    transaction_id_base64url TEXT NOT NULL UNIQUE,
                    idempotency_key_base64url TEXT NOT NULL UNIQUE,
                    request_sha256 TEXT NOT NULL,
                    committed_at_unix_decimal TEXT NOT NULL,
                    cas_receipt_json BLOB NOT NULL
                ) STRICT
                """
            )
            metadata = {
                "schemaVersion": "1",
                "witnessStoreIdentitySha256": self._identity_sha256,
                "witnessStoreKeySpkiSha256": self._store_key_id,
                "witnessSigningKeyId": self._witness_signer.key_id,
            }
            for key, value in metadata.items():
                existing = self._connection.execute(
                    "SELECT value FROM witness_metadata WHERE key = ?",
                    (key,),
                ).fetchone()
                if existing is None:
                    self._connection.execute(
                        "INSERT INTO witness_metadata(key, value) VALUES (?, ?)",
                        (key, value),
                    )
                elif existing["value"] != value:
                    raise WitnessServiceError(
                        f"witness database metadata changed: {key}"
                    )
            self._connection.execute("COMMIT")
        except Exception:
            self._connection.execute("ROLLBACK")
            raise

    @staticmethod
    def _row_to_checkpoint(row: sqlite3.Row) -> StoredCheckpoint:
        receipt_raw = bytes(row["cas_receipt_json"])
        receipt = parse_canonical_json(
            receipt_raw, label="stored witness CAS receipt"
        )
        return StoredCheckpoint(
            ordinal=require_u64(row["ordinal"], "stored witness ordinal", minimum=1),
            release_identity_sha256=require_sha256(
                row["release_identity_sha256"],
                "stored release identity",
            ),
            generation=require_u64(
                int(row["generation_decimal"]),
                "stored witness generation",
                minimum=1,
            ),
            rollback_epoch=require_u64(
                int(row["rollback_epoch_decimal"]),
                "stored witness rollback epoch",
            ),
            sequence=require_u64(
                int(row["sequence_decimal"]),
                "stored witness sequence",
                minimum=1,
            ),
            tree_size=require_u64(
                int(row["tree_size_decimal"]),
                "stored witness tree size",
                minimum=1,
            ),
            event_sha256=require_sha256(
                row["event_sha256"], "stored witness event"
            ),
            checkpoint_sha256=require_sha256(
                row["checkpoint_sha256"], "stored witness checkpoint"
            ),
            head_sha256=require_sha256(
                row["head_sha256"], "stored witness head"
            ),
            previous_continuity_sha256=(
                None
                if row["previous_continuity_sha256"] is None
                else require_sha256(
                    row["previous_continuity_sha256"],
                    "stored previous witness continuity",
                )
            ),
            continuity_sha256=require_sha256(
                row["continuity_sha256"], "stored witness continuity"
            ),
            transaction_id_base64url=row["transaction_id_base64url"],
            idempotency_key_base64url=row["idempotency_key_base64url"],
            request_sha256=require_sha256(
                row["request_sha256"], "stored witness request"
            ),
            committed_at_unix=require_u64(
                int(row["committed_at_unix_decimal"]),
                "stored witness commit time",
                minimum=1,
            ),
            cas_receipt=receipt,
        )

    def _load_history(self) -> list[StoredCheckpoint]:
        count_row = self._connection.execute(
            """
            SELECT COUNT(*) AS count, MAX(ordinal) AS maximum
            FROM witness_transitions
            """
        ).fetchone()
        if count_row is None:
            raise WitnessServiceError("witness history metadata is missing")
        count = require_u64(count_row["count"], "witness history count")
        maximum = (
            0
            if count_row["maximum"] is None
            else require_u64(
                count_row["maximum"],
                "witness maximum ordinal",
                minimum=1,
            )
        )
        if (
            count != maximum
            or count > self._max_history_rows
            or count < len(self._verified_history)
        ):
            raise WitnessServiceError("witness history exceeds its bound")
        if self._verified_history:
            last = self._verified_history[-1]
            unchanged_row = self._connection.execute(
                "SELECT * FROM witness_transitions WHERE ordinal = ?",
                (last.ordinal,),
            ).fetchone()
            if (
                unchanged_row is None
                or self._row_to_checkpoint(unchanged_row) != last
            ):
                raise WitnessServiceError(
                    "previously verified witness history changed"
                )
        rows = self._connection.execute(
            """
            SELECT * FROM witness_transitions
            WHERE ordinal > ?
            ORDER BY ordinal ASC
            """,
            (len(self._verified_history),),
        ).fetchall()
        for row in rows:
            current = self._row_to_checkpoint(row)
            previous = (
                None
                if not self._verified_history
                else self._verified_history[-1]
            )
            self._verify_transition(
                previous=previous,
                current=current,
                expected_ordinal=len(self._verified_history) + 1,
            )
            self._verified_history.append(current)
        if len(self._verified_history) != count:
            raise WitnessServiceError("witness history changed during validation")
        return list(self._verified_history)

    def _checkpoint_document(
        self,
        *,
        previous: StoredCheckpoint | None,
        release_identity_sha256: str,
        generation: int,
        rollback_epoch: int,
        sequence: int,
        tree_size: int,
        event_sha256: str,
        idempotency_key_base64url: str,
    ) -> dict[str, Any]:
        return {
            "apiVersion": "serverware.liveWitnessCheckpoint/v1",
            "eventSha256": event_sha256,
            "generation": generation,
            "idempotencyKeySha256": sha256_bytes(
                decode_base64url(
                    idempotency_key_base64url,
                    expected_bytes=32,
                    label="witness idempotency key",
                )
            ),
            "previousHeadSha256": (
                None if previous is None else previous.head_sha256
            ),
            "releaseIdentitySha256": release_identity_sha256,
            "rollbackEpoch": rollback_epoch,
            "sequence": sequence,
            "treeSize": tree_size,
            "witnessStoreIdentitySha256": self._identity_sha256,
        }

    def _continuity_document(
        self,
        *,
        checkpoint_sha256: str,
        head_sha256: str,
        previous_continuity_sha256: str | None,
        release_identity_sha256: str,
        generation: int,
        rollback_epoch: int,
        sequence: int,
        tree_size: int,
    ) -> dict[str, Any]:
        return {
            "apiVersion": "serverware.liveWitnessContinuity/v1",
            "checkpointSha256": checkpoint_sha256,
            "generation": generation,
            "headSha256": head_sha256,
            "previousRollbackContinuityCommitmentSha256":
            previous_continuity_sha256,
            "releaseIdentitySha256": release_identity_sha256,
            "rollbackEpoch": rollback_epoch,
            "sequence": sequence,
            "treeSize": tree_size,
            "witnessStoreIdentitySha256": self._identity_sha256,
            "witnessStoreKeySpkiSha256": self._store_key_id,
        }

    def _verify_history(
        self, checkpoints: list[StoredCheckpoint]
    ) -> None:
        previous: StoredCheckpoint | None = None
        for expected_ordinal, current in enumerate(checkpoints, start=1):
            self._verify_transition(
                previous=previous,
                current=current,
                expected_ordinal=expected_ordinal,
            )
            previous = current

    def _verify_transition(
        self,
        *,
        previous: StoredCheckpoint | None,
        current: StoredCheckpoint,
        expected_ordinal: int,
    ) -> None:
        if current.ordinal != expected_ordinal:
            raise WitnessServiceError("witness history has an ordinal gap")
        if current.sequence != expected_ordinal:
            raise WitnessServiceError("witness history has a sequence gap")
        if (
            current.previous_continuity_sha256
            != (
                None if previous is None else previous.continuity_sha256
            )
        ):
            raise WitnessServiceError("witness continuity predecessor changed")
        if previous is not None:
            self._validate_monotonic_coordinates(
                previous=previous,
                release_identity_sha256=current.release_identity_sha256,
                generation=current.generation,
                rollback_epoch=current.rollback_epoch,
                tree_size=current.tree_size,
            )
        checkpoint = self._checkpoint_document(
            previous=previous,
            release_identity_sha256=current.release_identity_sha256,
            generation=current.generation,
            rollback_epoch=current.rollback_epoch,
            sequence=current.sequence,
            tree_size=current.tree_size,
            event_sha256=current.event_sha256,
            idempotency_key_base64url=(
                current.idempotency_key_base64url
            ),
        )
        checkpoint_sha256 = sha256_bytes(
            CHECKPOINT_DOMAIN + canonical_json_bytes(checkpoint)
        )
        head_sha256 = sha256_bytes(
            HEAD_DOMAIN
            + canonical_json_bytes(
                {
                    "checkpointSha256": checkpoint_sha256,
                    "previousHeadSha256": (
                        None if previous is None else previous.head_sha256
                    ),
                }
            )
        )
        continuity_sha256 = sha256_bytes(
            CONTINUITY_DOMAIN
            + canonical_json_bytes(
                self._continuity_document(
                    checkpoint_sha256=checkpoint_sha256,
                    head_sha256=head_sha256,
                    previous_continuity_sha256=(
                        current.previous_continuity_sha256
                    ),
                    release_identity_sha256=(
                        current.release_identity_sha256
                    ),
                    generation=current.generation,
                    rollback_epoch=current.rollback_epoch,
                    sequence=current.sequence,
                    tree_size=current.tree_size,
                )
            )
        )
        if (
            checkpoint_sha256 != current.checkpoint_sha256
            or head_sha256 != current.head_sha256
            or continuity_sha256 != current.continuity_sha256
        ):
            raise WitnessServiceError("witness history digest changed")
        self._validate_cas_receipt(current)

    def _validate_cas_receipt(self, current: StoredCheckpoint) -> None:
        receipt = _closed_object(
            current.cas_receipt,
            {
                "apiVersion",
                "checkpointSha256",
                "committedAtUnix",
                "committedRollbackContinuityCommitmentSha256",
                "generation",
                "previousRollbackContinuityCommitmentSha256",
                "releaseIdentitySha256",
                "sequence",
                "witnessStoreIdentitySha256",
                "transactionIdBase64url",
            },
            "stored witness CAS receipt",
        )
        expected = {
            "apiVersion": CAS_RECEIPT_VERSION,
            "checkpointSha256": current.checkpoint_sha256,
            "committedAtUnix": current.committed_at_unix,
            "committedRollbackContinuityCommitmentSha256":
            current.continuity_sha256,
            "generation": current.generation,
            "previousRollbackContinuityCommitmentSha256":
            current.previous_continuity_sha256,
            "releaseIdentitySha256": current.release_identity_sha256,
            "sequence": current.sequence,
            "witnessStoreIdentitySha256": self._identity_sha256,
            "transactionIdBase64url":
            current.transaction_id_base64url,
        }
        if receipt != expected:
            raise WitnessServiceError("stored witness CAS receipt changed")
        decode_base64url(
            current.transaction_id_base64url,
            expected_bytes=32,
            label="witness transaction id",
        )

    @staticmethod
    def _validate_monotonic_coordinates(
        *,
        previous: StoredCheckpoint,
        release_identity_sha256: str,
        generation: int,
        rollback_epoch: int,
        tree_size: int,
    ) -> None:
        if tree_size < previous.tree_size:
            raise WitnessServiceError("witness tree size regressed")
        same_release = (
            release_identity_sha256 == previous.release_identity_sha256
        )
        if same_release:
            if (
                generation != previous.generation
                or rollback_epoch != previous.rollback_epoch
            ):
                raise WitnessServiceError(
                    "stable release coordinates changed without a new identity"
                )
            return
        if (
            rollback_epoch < previous.rollback_epoch
            or (
                rollback_epoch == previous.rollback_epoch
                and generation <= previous.generation
            )
        ):
            raise WitnessServiceError("witness release coordinates regressed")

    @staticmethod
    def _parse_advance_request(
        request: Mapping[str, Any],
    ) -> dict[str, Any]:
        try:
            document = _closed_object(
                dict(request),
                {
                    "apiVersion",
                    "eventSha256",
                    "expectedPreviousRollbackContinuityCommitmentSha256",
                    "generation",
                    "idempotencyKeyBase64url",
                    "releaseIdentitySha256",
                    "rollbackEpoch",
                    "treeSize",
                },
                "witness advance request",
            )
            if document["apiVersion"] != ADVANCE_REQUEST_VERSION:
                raise WitnessServiceError(
                    "witness advance request version is invalid"
                )
            require_sha256(
                document["releaseIdentitySha256"],
                "witness release identity",
            )
            require_sha256(document["eventSha256"], "witness event")
            require_u64(
                document["generation"],
                "witness generation",
                minimum=1,
            )
            require_u64(
                document["rollbackEpoch"], "witness rollback epoch"
            )
            require_u64(
                document["treeSize"],
                "witness tree size",
                minimum=1,
            )
            decode_base64url(
                document["idempotencyKeyBase64url"],
                expected_bytes=32,
                label="witness idempotency key",
            )
            expected_previous = document[
                "expectedPreviousRollbackContinuityCommitmentSha256"
            ]
            if expected_previous is not None:
                require_sha256(
                    expected_previous,
                    "expected previous witness continuity",
                )
            return document
        except WitnessServiceError as exc:
            raise ClientRequestError(
                "witness advance request is invalid"
            ) from exc

    @staticmethod
    def _parse_current_request(
        request: Mapping[str, Any],
    ) -> dict[str, Any]:
        try:
            document = _closed_object(
                dict(request),
                {
                    "apiVersion",
                    "minimumReleaseIdentitySha256",
                    "minimumRollbackContinuityCommitmentSha256",
                    "producerEphemeralKeySpkiSha256",
                    "producerInvocationSha256",
                    "producerRequestSha256",
                    "tlsBindingSha256",
                    "verifierChallengeBase64url",
                },
                "current witness request",
            )
            if document["apiVersion"] != CURRENT_REQUEST_VERSION:
                raise WitnessServiceError(
                    "current witness request version is invalid"
                )
            for field in (
                "minimumReleaseIdentitySha256",
                "minimumRollbackContinuityCommitmentSha256",
                "producerEphemeralKeySpkiSha256",
                "producerInvocationSha256",
                "producerRequestSha256",
                "tlsBindingSha256",
            ):
                require_sha256(document[field], f"current request {field}")
            decode_base64url(
                document["verifierChallengeBase64url"],
                expected_bytes=32,
                label="current request verifier challenge",
            )
            return document
        except WitnessServiceError as exc:
            raise ClientRequestError(
                "current witness request is invalid"
            ) from exc

    def advance(self, request: Mapping[str, Any]) -> dict[str, Any]:
        request_document = self._parse_advance_request(request)
        release_identity_sha256 = request_document[
            "releaseIdentitySha256"
        ]
        event_sha256 = request_document["eventSha256"]
        generation = request_document["generation"]
        rollback_epoch = request_document["rollbackEpoch"]
        tree_size = request_document["treeSize"]
        idempotency_key = request_document["idempotencyKeyBase64url"]
        expected_previous = request_document[
            "expectedPreviousRollbackContinuityCommitmentSha256"
        ]
        request_sha256 = sha256_json(request_document)
        now = require_u64(
            self._clock(), "witness service clock", minimum=1
        )
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            history = self._load_history()
            existing_row = self._connection.execute(
                """
                SELECT * FROM witness_transitions
                WHERE idempotency_key_base64url = ?
                """,
                (idempotency_key,),
            ).fetchone()
            if existing_row is not None:
                existing = self._row_to_checkpoint(existing_row)
                if existing.request_sha256 != request_sha256:
                    raise ClientRequestError(
                        "witness idempotency key crossed requests"
                    )
                if (
                    existing.ordinal > len(history)
                    or history[existing.ordinal - 1] != existing
                ):
                    raise WitnessServiceError(
                        "idempotent witness transition was not verified"
                    )
                self._connection.execute("COMMIT")
                self._checkpoint_and_require()
                return self._advance_response(existing)
            previous = history[-1] if history else None
            actual_previous = (
                None if previous is None else previous.continuity_sha256
            )
            if expected_previous != actual_previous:
                raise ClientRequestError(
                    "witness CAS predecessor mismatch"
                )
            if previous is not None:
                self._validate_monotonic_coordinates(
                    previous=previous,
                    release_identity_sha256=release_identity_sha256,
                    generation=generation,
                    rollback_epoch=rollback_epoch,
                    tree_size=tree_size,
                )
            sequence = 1 if previous is None else previous.sequence + 1
            require_u64(sequence, "next witness sequence", minimum=1)
            checkpoint_document = self._checkpoint_document(
                previous=previous,
                release_identity_sha256=release_identity_sha256,
                generation=generation,
                rollback_epoch=rollback_epoch,
                sequence=sequence,
                tree_size=tree_size,
                event_sha256=event_sha256,
                idempotency_key_base64url=idempotency_key,
            )
            checkpoint_sha256 = sha256_bytes(
                CHECKPOINT_DOMAIN + canonical_json_bytes(checkpoint_document)
            )
            head_sha256 = sha256_bytes(
                HEAD_DOMAIN
                + canonical_json_bytes(
                    {
                        "checkpointSha256": checkpoint_sha256,
                        "previousHeadSha256": (
                            None if previous is None else previous.head_sha256
                        ),
                    }
                )
            )
            continuity_sha256 = sha256_bytes(
                CONTINUITY_DOMAIN
                + canonical_json_bytes(
                    self._continuity_document(
                        checkpoint_sha256=checkpoint_sha256,
                        head_sha256=head_sha256,
                        previous_continuity_sha256=actual_previous,
                        release_identity_sha256=release_identity_sha256,
                        generation=generation,
                        rollback_epoch=rollback_epoch,
                        sequence=sequence,
                        tree_size=tree_size,
                    )
                )
            )
            transaction_id = canonical_base64url(secrets.token_bytes(32))
            receipt = {
                "apiVersion": CAS_RECEIPT_VERSION,
                "checkpointSha256": checkpoint_sha256,
                "committedAtUnix": now,
                "committedRollbackContinuityCommitmentSha256":
                continuity_sha256,
                "generation": generation,
                "previousRollbackContinuityCommitmentSha256":
                actual_previous,
                "releaseIdentitySha256": release_identity_sha256,
                "sequence": sequence,
                "witnessStoreIdentitySha256": self._identity_sha256,
                "transactionIdBase64url": transaction_id,
            }
            cursor = self._connection.execute(
                """
                INSERT INTO witness_transitions(
                    release_identity_sha256,
                    generation_decimal,
                    rollback_epoch_decimal,
                    sequence_decimal,
                    tree_size_decimal,
                    event_sha256,
                    checkpoint_sha256,
                    head_sha256,
                    previous_continuity_sha256,
                    continuity_sha256,
                    transaction_id_base64url,
                    idempotency_key_base64url,
                    request_sha256,
                    committed_at_unix_decimal,
                    cas_receipt_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    release_identity_sha256,
                    str(generation),
                    str(rollback_epoch),
                    str(sequence),
                    str(tree_size),
                    event_sha256,
                    checkpoint_sha256,
                    head_sha256,
                    actual_previous,
                    continuity_sha256,
                    transaction_id,
                    idempotency_key,
                    request_sha256,
                    str(now),
                    canonical_json_bytes(receipt),
                ),
            )
            row = self._connection.execute(
                "SELECT * FROM witness_transitions WHERE ordinal = ?",
                (cursor.lastrowid,),
            ).fetchone()
            if row is None:
                raise WitnessServiceError("witness transition commit vanished")
            current = self._row_to_checkpoint(row)
            self._connection.execute("COMMIT")
        except Exception:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise
        self._checkpoint_and_require()
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            history = self._load_history()
            if (
                current.ordinal > len(history)
                or history[current.ordinal - 1] != current
            ):
                raise FatalWitnessServiceError(
                    "committed witness transition did not survive checkpoint"
                )
            self._connection.execute("COMMIT")
        except Exception:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise
        return self._advance_response(current)

    def current(self, request: Mapping[str, Any]) -> dict[str, Any]:
        request_document = self._parse_current_request(request)
        current_request_sha256 = sha256_json(request_document)
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            history = self._load_history()
            if not history:
                raise ClientRequestError(
                    "witness store has no current head"
                )
            floor = next(
                (
                    checkpoint
                    for checkpoint in history
                    if checkpoint.continuity_sha256
                    == request_document[
                        "minimumRollbackContinuityCommitmentSha256"
                    ]
                ),
                None,
            )
            if floor is None:
                raise ClientRequestError(
                    "current witness continuity floor is not in the "
                    "authoritative history"
                )
            if (
                floor.release_identity_sha256
                != request_document["minimumReleaseIdentitySha256"]
            ):
                raise ClientRequestError(
                    "current witness release floor does not match its "
                    "continuity floor"
                )
            current = history[-1]
            if floor.ordinal > current.ordinal:
                raise FatalWitnessServiceError(
                    "current witness floor is newer than the selected head"
                )
            now = require_u64(
                self._clock(), "witness service clock", minimum=1
            )
            response = self._issue_current(
                current,
                now=now,
                request=request_document,
                current_request_sha256=current_request_sha256,
            )
            self._connection.execute("COMMIT")
        except Exception:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise
        return response

    def _advance_response(
        self, current: StoredCheckpoint
    ) -> dict[str, Any]:
        return {
            "apiVersion": ADVANCE_RESPONSE_VERSION,
            "checkpointCasReceipt": current.cas_receipt,
            "rollbackContinuityCommitmentSha256":
            current.continuity_sha256,
            "witnessStoreIdentitySha256": self._identity_sha256,
            "witnessStoreKeySpkiSha256": self._store_key_id,
        }

    def _previous_for(
        self, current: StoredCheckpoint
    ) -> StoredCheckpoint | None:
        if current.ordinal == 1:
            return None
        row = self._connection.execute(
            "SELECT * FROM witness_transitions WHERE ordinal = ?",
            (current.ordinal - 1,),
        ).fetchone()
        if row is None:
            raise WitnessServiceError("witness predecessor is missing")
        return self._row_to_checkpoint(row)

    def _issue_current(
        self,
        current: StoredCheckpoint,
        *,
        now: int,
        request: Mapping[str, Any],
        current_request_sha256: str,
    ) -> dict[str, Any]:
        previous = self._previous_for(current)
        invocation_binding = {
            "apiVersion": INVOCATION_BINDING_VERSION,
            "currentRequestSha256": require_sha256(
                current_request_sha256,
                "current witness request digest",
            ),
            "producerEphemeralKeySpkiSha256":
            request["producerEphemeralKeySpkiSha256"],
            "producerInvocationSha256":
            request["producerInvocationSha256"],
            "producerRequestSha256": request["producerRequestSha256"],
            "tlsBindingSha256": request["tlsBindingSha256"],
            "verifierChallengeBase64url":
            request["verifierChallengeBase64url"],
        }
        live_payload = {
            "expiresAtUnix": now + self._live_ttl,
            "generation": current.generation,
            "headSha256": current.head_sha256,
            "invocationBinding": invocation_binding,
            "issuedAtUnix": now,
            "releaseIdentitySha256": current.release_identity_sha256,
            "rollbackEpoch": current.rollback_epoch,
            "sequence": current.sequence,
            "treeSize": current.tree_size,
        }
        require_u64(
            live_payload["expiresAtUnix"],
            "live witness expiration",
            minimum=1,
        )
        live_head = signed_envelope(
            api_version=LIVE_WITNESS_HEAD_VERSION,
            domain=LIVE_WITNESS_DOMAIN,
            payload=live_payload,
            signer=self._witness_signer,
        )
        current_document = current.prior_document()
        current_document["liveWitnessHeadPayloadSha256"] = live_head[
            "payloadSha256"
        ]
        protected_payload = {
            "checkpointCasReceipt": current.cas_receipt,
            "current": current_document,
            "expiresAtUnix": now + self._state_ttl,
            "invocationBinding": invocation_binding,
            "issuedAtUnix": now,
            "previous": (
                None if previous is None else previous.prior_document()
            ),
            "releaseIdentitySha256":
            current.release_identity_sha256,
            "rollbackContinuityCommitmentSha256":
            current.continuity_sha256,
            "storeAssurance": self._assurance,
            "witnessSigningKeyId": self._witness_signer.key_id,
            "witnessStoreIdentity": self._identity,
            "witnessStoreIdentitySha256": self._identity_sha256,
            "witnessStoreKeySpkiSha256": self._store_key_id,
        }
        require_u64(
            protected_payload["expiresAtUnix"],
            "protected witness expiration",
            minimum=1,
        )
        protected_state = signed_envelope(
            api_version=PROTECTED_STATE_VERSION,
            domain=PROTECTED_STATE_DOMAIN,
            payload=protected_payload,
            signer=self._store_signer,
        )
        if (
            live_head["payload"]["invocationBinding"]
            != protected_state["payload"]["invocationBinding"]
            or protected_state["payload"]["storeAssurance"]
            != protected_state["payload"]["witnessStoreIdentity"]["assurance"]
            or protected_state["payload"]["witnessStoreIdentitySha256"]
            != sha256_json(
                protected_state["payload"]["witnessStoreIdentity"]
            )
            or protected_state["payload"]["witnessStoreKeySpkiSha256"]
            != protected_state["signingKeyId"]
            or protected_state["payload"]["witnessSigningKeyId"]
            != live_head["signingKeyId"]
            or protected_state["payload"]["releaseIdentitySha256"]
            != current.release_identity_sha256
            or protected_state["payload"]["current"][
                "releaseIdentitySha256"
            ] != current.release_identity_sha256
        ):
            raise FatalWitnessServiceError(
                "signed witness envelope semantic equality failed"
            )
        return {
            "apiVersion": CURRENT_RESPONSE_VERSION,
            "checkpointCasReceipt": current.cas_receipt,
            "currentRequestSha256": current_request_sha256,
            "invocationBinding": invocation_binding,
            "liveWitnessHead": live_head,
            "protectedLiveWitnessState": protected_state,
            "rollbackContinuityCommitmentSha256":
            current.continuity_sha256,
            "witnessStoreIdentitySha256": self._identity_sha256,
            "witnessStoreKeySpkiSha256": self._store_key_id,
        }


def _validate_database_descriptor(
    value: Any,
) -> dict[str, Any]:
    database = _closed_object(
        value,
        {
            "allowCreate",
            "path",
            "pathnameSecurity",
        },
        "witness database descriptor",
    )
    if not isinstance(database["allowCreate"], bool):
        raise WitnessServiceError("database allowCreate must be boolean")
    require_absolute_normal_path(database["path"], "witness database path")
    if (
        database["pathnameSecurity"]
        != "nonProductionPythonSqlitePathname"
    ):
        raise WitnessServiceError(
            "SQLite descriptor must acknowledge pathname TOCTOU"
        )
    return database


def _validate_signer_descriptor(
    value: Any, label: str
) -> dict[str, Any]:
    signer = _closed_object(
        value,
        {"requestFd", "responseFd"},
        label,
    )
    for field in ("requestFd", "responseFd"):
        require_u64(signer[field], f"{label} {field}", minimum=3)
    return signer


def _read_immutable_snapshot_fd(
    fd: int,
    *,
    expected_bytes: int | None,
    max_bytes: int,
    label: str,
) -> bytes:
    if isinstance(fd, bool) or not isinstance(fd, int) or fd < 3:
        raise FatalWitnessServiceError(f"{label} fd is invalid")
    try:
        file_stat_before = os.fstat(fd)
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    except OSError as exc:
        raise FatalWitnessServiceError(f"{label} fd is unavailable") from exc
    if not stat.S_ISREG(file_stat_before.st_mode):
        raise FatalWitnessServiceError(
            f"{label} must be a retained regular-file or sealed-memfd snapshot"
        )
    access_mode = flags & os.O_ACCMODE
    sealed = False
    if hasattr(fcntl, "F_GET_SEALS"):
        try:
            seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
            required_seals = (
                getattr(fcntl, "F_SEAL_GROW", 0)
                | getattr(fcntl, "F_SEAL_SEAL", 0)
                | getattr(fcntl, "F_SEAL_SHRINK", 0)
                | getattr(fcntl, "F_SEAL_WRITE", 0)
            )
            sealed = (
                required_seals != 0
                and seals & required_seals == required_seals
            )
        except OSError:
            sealed = False
    if access_mode != os.O_RDONLY and not sealed:
        raise FatalWitnessServiceError(
            f"{label} must be read-only or fully sealed"
        )
    size = file_stat_before.st_size
    if size < 1 or size > max_bytes:
        raise FatalWitnessServiceError(f"{label} size is invalid")
    if expected_bytes is not None and size != expected_bytes:
        raise FatalWitnessServiceError(f"{label} length is invalid")
    try:
        raw = os.pread(fd, size, 0)
        file_stat_after = os.fstat(fd)
    except OSError as exc:
        raise FatalWitnessServiceError(f"{label} read failed") from exc
    if (
        len(raw) != size
        or file_stat_after.st_size != size
        or file_stat_after.st_dev != file_stat_before.st_dev
        or file_stat_after.st_ino != file_stat_before.st_ino
    ):
        raise FatalWitnessServiceError(
            f"{label} changed while materializing its signed snapshot"
        )
    return raw


def _validate_trusted_signer(
    value: Any,
    *,
    expected_role: str,
    label: str,
) -> dict[str, Any]:
    signer = _closed_object(
        value,
        {
            "identity",
            "keySpkiSha256",
            "peerCredentials",
            "publicKeySpkiDerBase64url",
        },
        label,
    )
    identity = validate_signer_identity(
        signer["identity"], f"{label} identity"
    )
    if identity["role"] != expected_role:
        raise WitnessServiceError(f"{label} role is invalid")
    key_id = require_sha256(
        signer["keySpkiSha256"], f"{label} key"
    )
    public_key_der = decode_base64url(
        signer["publicKeySpkiDerBase64url"],
        expected_bytes=44,
        label=f"{label} public key SPKI",
    )
    if (
        sha256_bytes(public_key_der) != key_id
        or identity["keySpkiSha256"] != key_id
    ):
        raise WitnessServiceError(f"{label} key pins disagree")
    _load_ed25519_public_key(public_key_der, f"{label} public key")
    validate_peer_credentials(
        signer["peerCredentials"], f"{label} peer credentials"
    )
    return signer


def load_immutable_trust_config(
    *,
    config_fd: int,
    release_root_spki_fd: int,
    expected_config_sha256: str,
    expected_release_root_spki_sha256: str,
) -> dict[str, Any]:
    expected_config_id = require_sha256(
        expected_config_sha256,
        "expected immutable witness trust config",
    )
    expected_root_id = require_sha256(
        expected_release_root_spki_sha256,
        "expected release root key",
    )
    release_root_der = _read_immutable_snapshot_fd(
        release_root_spki_fd,
        expected_bytes=44,
        max_bytes=44,
        label="release root SPKI",
    )
    if sha256_bytes(release_root_der) != expected_root_id:
        raise FatalWitnessServiceError("release root SPKI pin mismatch")
    release_root_key = _load_ed25519_public_key(
        release_root_der, "release root SPKI"
    )
    raw_config = _read_immutable_snapshot_fd(
        config_fd,
        expected_bytes=None,
        max_bytes=262144,
        label="immutable witness trust config",
    )
    if sha256_bytes(raw_config) != expected_config_id:
        raise FatalWitnessServiceError(
            "immutable witness trust config pin mismatch"
        )
    try:
        envelope = parse_canonical_json(
            raw_config, label="immutable witness trust config"
        )
        envelope = _closed_object(
            envelope,
            {
                "apiVersion",
                "payload",
                "payloadSha256",
                "signature",
                "signingKeyId",
            },
            "immutable witness trust config envelope",
        )
        if envelope["apiVersion"] != IMMUTABLE_TRUST_ENVELOPE_VERSION:
            raise WitnessServiceError(
                "immutable witness trust envelope version is invalid"
            )
        payload = _closed_object(
            envelope["payload"],
            {
                "apiVersion",
                "releaseIdentitySha256",
                "servicePeerCredentials",
                "signerRpcTimeoutMilliseconds",
                "signerSocketType",
                "storeIdentity",
                "storeSigner",
                "witnessSigner",
                "witnessStoreIdentitySha256",
            },
            "immutable witness trust config payload",
        )
        if payload["apiVersion"] != IMMUTABLE_TRUST_CONFIG_VERSION:
            raise WitnessServiceError(
                "immutable witness trust config version is invalid"
            )
        require_sha256(
            payload["releaseIdentitySha256"],
            "immutable witness release identity",
        )
        validate_peer_credentials(
            payload["servicePeerCredentials"],
            "immutable witness service peer",
        )
        if payload["signerSocketType"] != "unix-seqpacket":
            raise WitnessServiceError(
                "witness RPC requires bounded AF_UNIX SOCK_SEQPACKET frames"
            )
        signer_rpc_timeout = require_u64(
            payload["signerRpcTimeoutMilliseconds"],
            "immutable witness signer RPC timeout",
            minimum=1,
        )
        if signer_rpc_timeout > MAX_SIGNER_RPC_TIMEOUT_MILLISECONDS:
            raise WitnessServiceError(
                "immutable witness signer RPC timeout exceeds its bound"
            )
        store_identity = validate_store_identity(
            payload["storeIdentity"]
        )
        identity_sha256 = require_sha256(
            payload["witnessStoreIdentitySha256"],
            "immutable witness store identity",
        )
        if sha256_json(store_identity) != identity_sha256:
            raise WitnessServiceError(
                "immutable witness store identity pin mismatch"
            )
        store_signer = _validate_trusted_signer(
            payload["storeSigner"],
            expected_role="witnessStore",
            label="immutable witness store signer",
        )
        witness_signer = _validate_trusted_signer(
            payload["witnessSigner"],
            expected_role="liveWitness",
            label="immutable live witness signer",
        )
        if (
            store_signer["keySpkiSha256"]
            == witness_signer["keySpkiSha256"]
            or store_signer["publicKeySpkiDerBase64url"]
            == witness_signer["publicKeySpkiDerBase64url"]
            or sha256_json(store_signer["identity"])
            == sha256_json(witness_signer["identity"])
        ):
            raise WitnessServiceError(
                "immutable witness and store signer roots are not distinct"
            )
        payload_sha256 = require_sha256(
            envelope["payloadSha256"],
            "immutable witness trust payload",
        )
        if payload_sha256 != sha256_json(payload):
            raise WitnessServiceError(
                "immutable witness trust payload digest is invalid"
            )
        if envelope["signingKeyId"] != expected_root_id:
            raise WitnessServiceError(
                "immutable witness trust root is not independently pinned"
            )
        signature = decode_base64url(
            envelope["signature"],
            expected_bytes=64,
            label="immutable witness trust signature",
        )
        message = canonical_json_bytes(
            {"payload": payload, "payloadSha256": payload_sha256}
        )
        release_root_key.verify(
            signature, IMMUTABLE_TRUST_CONFIG_DOMAIN + message
        )
    except FatalWitnessServiceError:
        raise
    except Exception as exc:
        raise FatalWitnessServiceError(
            "immutable release-signed witness trust config is invalid"
        ) from exc
    return payload


def load_descriptor(fd: int) -> dict[str, Any]:
    channel = BoundedJsonLineFd(fd, max_bytes=262144)
    descriptor = channel.read(label="witness service descriptor")
    if descriptor is None:
        raise WitnessServiceError("witness service descriptor is missing")
    descriptor = _closed_object(
        descriptor,
        {
            "apiVersion",
            "database",
            "liveWitnessHeadTtlSeconds",
            "maxHistoryRows",
            "maxRequestBytes",
            "maxResponseBytes",
            "protectedStateTtlSeconds",
            "requestFd",
            "responseFd",
            "storeSigner",
            "witnessSigner",
        },
        "witness service descriptor",
    )
    if descriptor["apiVersion"] != DESCRIPTOR_VERSION:
        raise WitnessServiceError("witness service descriptor version is invalid")
    _validate_database_descriptor(descriptor["database"])
    _validate_signer_descriptor(descriptor["storeSigner"], "store signer")
    _validate_signer_descriptor(
        descriptor["witnessSigner"], "witness signer"
    )
    for field in (
        "maxHistoryRows",
        "maxRequestBytes",
        "maxResponseBytes",
        "liveWitnessHeadTtlSeconds",
        "protectedStateTtlSeconds",
    ):
        require_u64(descriptor[field], field, minimum=1)
    for field in ("requestFd", "responseFd"):
        require_u64(descriptor[field], field, minimum=3)
    channel_fds = {
        descriptor["requestFd"],
        descriptor["responseFd"],
        descriptor["storeSigner"]["requestFd"],
        descriptor["storeSigner"]["responseFd"],
        descriptor["witnessSigner"]["requestFd"],
        descriptor["witnessSigner"]["responseFd"],
    }
    if len(channel_fds) != 6:
        raise WitnessServiceError(
            "witness service and signer channels must use distinct FDs"
        )
    return descriptor


def serve(
    descriptor: Mapping[str, Any],
    immutable_trust: Mapping[str, Any],
) -> None:
    database = descriptor["database"]
    store_signer_descriptor = descriptor["storeSigner"]
    witness_signer_descriptor = descriptor["witnessSigner"]
    store_signer_trust = immutable_trust["storeSigner"]
    witness_signer_trust = immutable_trust["witnessSigner"]
    socket_type = immutable_trust["signerSocketType"]
    signer_rpc_timeout = immutable_trust[
        "signerRpcTimeoutMilliseconds"
    ]
    service_peer = immutable_trust["servicePeerCredentials"]
    authenticate_unix_channel_fd(
        descriptor["requestFd"],
        direction="read",
        expected_peer=service_peer,
        socket_type=socket_type,
        label="witness service request channel",
        repeatable_control_frames=True,
    )
    authenticate_unix_channel_fd(
        descriptor["responseFd"],
        direction="write",
        expected_peer=service_peer,
        socket_type=socket_type,
        label="witness service response channel",
        repeatable_control_frames=True,
    )
    store = DurableWitnessStore(
        database_path=database["path"],
        store_identity=immutable_trust["storeIdentity"],
        expected_store_identity_sha256=immutable_trust[
            "witnessStoreIdentitySha256"
        ],
        expected_store_key_spki_sha256=store_signer_trust[
            "keySpkiSha256"
        ],
        expected_store_signing_public_key_spki_der_base64url=(
            store_signer_trust["publicKeySpkiDerBase64url"]
        ),
        expected_witness_key_spki_sha256=witness_signer_trust[
            "keySpkiSha256"
        ],
        expected_witness_signing_public_key_spki_der_base64url=(
            witness_signer_trust["publicKeySpkiDerBase64url"]
        ),
        witness_signer=FdSigner(
            request_fd=witness_signer_descriptor["requestFd"],
            response_fd=witness_signer_descriptor["responseFd"],
            key_id=witness_signer_trust["keySpkiSha256"],
            public_key_spki_der=decode_base64url(
                witness_signer_trust["publicKeySpkiDerBase64url"],
                expected_bytes=44,
                label="immutable witness signer public key",
            ),
            signer_identity=witness_signer_trust["identity"],
            expected_peer=witness_signer_trust["peerCredentials"],
            socket_type=socket_type,
            rpc_timeout_milliseconds=signer_rpc_timeout,
        ),
        store_signer=FdSigner(
            request_fd=store_signer_descriptor["requestFd"],
            response_fd=store_signer_descriptor["responseFd"],
            key_id=store_signer_trust["keySpkiSha256"],
            public_key_spki_der=decode_base64url(
                store_signer_trust["publicKeySpkiDerBase64url"],
                expected_bytes=44,
                label="immutable store signer public key",
            ),
            signer_identity=store_signer_trust["identity"],
            expected_peer=store_signer_trust["peerCredentials"],
            socket_type=socket_type,
            rpc_timeout_milliseconds=signer_rpc_timeout,
        ),
        allow_create=database["allowCreate"],
        max_history_rows=descriptor["maxHistoryRows"],
        live_head_ttl_seconds=descriptor["liveWitnessHeadTtlSeconds"],
        protected_state_ttl_seconds=descriptor[
            "protectedStateTtlSeconds"
        ],
    )
    requests = BoundedJsonLineFd(
        descriptor["requestFd"],
        max_bytes=descriptor["maxRequestBytes"],
        recoverable_frames=True,
        packet_mode=(socket_type == "unix-seqpacket"),
    )
    responses = BoundedJsonLineFd(
        descriptor["responseFd"],
        max_bytes=descriptor["maxResponseBytes"],
        packet_mode=(socket_type == "unix-seqpacket"),
    )
    # Both sockets stay bidirectional only for repeatable launcher admission.
    # Normal witness traffic retains request-in/response-out directionality.
    poller = select.poll()
    event_mask = (
        select.POLLIN
        | select.POLLHUP
        | select.POLLERR
        | select.POLLNVAL
    )
    poller.register(descriptor["requestFd"], event_mask)
    poller.register(descriptor["responseFd"], event_mask)
    response_control_open = True
    try:
        while True:
            request_ready = requests.has_buffered_data
            response_ready = (
                response_control_open and responses.has_buffered_data
            )
            if not request_ready and not response_ready:
                for ready_fd, events in poller.poll():
                    if events & (select.POLLERR | select.POLLNVAL):
                        raise FatalWitnessServiceError(
                            "witness service channel became invalid"
                        )
                    if not events & (select.POLLIN | select.POLLHUP):
                        continue
                    if ready_fd == descriptor["responseFd"]:
                        response_ready = response_control_open
                    elif ready_fd == descriptor["requestFd"]:
                        request_ready = True
                    else:
                        raise FatalWitnessServiceError(
                            "witness poll returned an unknown descriptor"
                        )
            if response_ready:
                try:
                    control = responses.read(
                        label="witness response-channel challenge"
                    )
                except WitnessServiceError as exc:
                    raise FatalWitnessServiceError(
                        "witness response-channel challenge is malformed"
                    ) from exc
                if control is None:
                    response_control_open = False
                    poller.unregister(descriptor["responseFd"])
                else:
                    responses.write(
                        _service_challenge_response(
                            control,
                            direction="service-to-producer",
                            role="witnessResponse",
                        )
                    )
                continue
            if not request_ready:
                continue
            try:
                request = requests.read(label="witness service request")
            except ClientFrameError:
                responses.write(
                    {
                        "apiVersion": ERROR_RESPONSE_VERSION,
                        "errorCode": "invalidFrame",
                        "requestSha256": None,
                        "retryable": False,
                    }
                )
                continue
            if request is None:
                return
            if request.get("apiVersion") == SERVICE_CHALLENGE_VERSION:
                requests.write(
                    _service_challenge_response(
                        request,
                        direction="producer-to-service",
                        role="witnessRequest",
                    )
                )
                continue
            request_sha256 = sha256_json(request)
            try:
                if request.get("apiVersion") == ADVANCE_REQUEST_VERSION:
                    response = store.advance(request)
                elif request.get("apiVersion") == CURRENT_REQUEST_VERSION:
                    response = store.current(request)
                else:
                    raise ClientRequestError(
                        "unknown witness service request version"
                    )
            except ClientRequestError:
                responses.write(
                    {
                        "apiVersion": ERROR_RESPONSE_VERSION,
                        "errorCode": "requestRejected",
                        "requestSha256": request_sha256,
                        "retryable": False,
                    }
                )
                continue
            responses.write(response)
    finally:
        try:
            requests.close()
            responses.close()
        finally:
            store.close()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Serve non-production SQLite attestation witness CAS requests"
        )
    )
    parser.add_argument("--descriptor-fd", required=True, type=int)
    parser.add_argument(
        "--immutable-trust-config-fd", required=True, type=int
    )
    parser.add_argument(
        "--release-root-spki-fd", required=True, type=int
    )
    parser.add_argument(
        "--expected-release-root-spki-sha256", required=True
    )
    parser.add_argument(
        "--expected-immutable-trust-config-sha256", required=True
    )
    args = parser.parse_args()
    retained_control_fds = {
        args.descriptor_fd,
        args.immutable_trust_config_fd,
        args.release_root_spki_fd,
    }
    if len(retained_control_fds) != 3:
        raise FatalWitnessServiceError(
            "descriptor, trust config, and release root require distinct FDs"
        )
    immutable_trust = load_immutable_trust_config(
        config_fd=args.immutable_trust_config_fd,
        release_root_spki_fd=args.release_root_spki_fd,
        expected_config_sha256=(
            args.expected_immutable_trust_config_sha256
        ),
        expected_release_root_spki_sha256=(
            args.expected_release_root_spki_sha256
        ),
    )
    descriptor = load_descriptor(args.descriptor_fd)
    data_fds = {
        descriptor["requestFd"],
        descriptor["responseFd"],
        descriptor["storeSigner"]["requestFd"],
        descriptor["storeSigner"]["responseFd"],
        descriptor["witnessSigner"]["requestFd"],
        descriptor["witnessSigner"]["responseFd"],
    }
    if retained_control_fds & data_fds:
        raise FatalWitnessServiceError(
            "control snapshots and RPC channels require distinct FDs"
        )
    serve(descriptor, immutable_trust)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
