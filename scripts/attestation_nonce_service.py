#!/usr/bin/env python3
"""Restart-durable one-use nonce reference service.

This process is deliberately not a production nonce authority. Its SQLite
backend is useful for source fixtures and single-host reference deployments,
but pathname-based SQLite opening cannot exclude namespace, mount, symlink, or
snapshot rollback races. The service therefore accepts only identities with
``productionEligible: false`` and refuses any production assurance label.

A production deployment must replace this process with an independently
administered, linearizable external CAS service. That service must retain every
tombstone for the full replay horizon, protect its signing key in a KMS/HSM,
publish the same signed receipt contract, resist storage and administrative
rollback, and atomically consume the final verifier-issued challenge. A receipt
from this reference service always says that final verifier challenge
consumption is required and has not happened. It is not final replay
authorization.

The reference service still enforces the important protocol properties:

* ``oneUse: true`` is emitted only after the SQLite transaction commits and an
  exact WAL checkpoint succeeds.
* Every consumption has a 32-byte transaction id, contiguous u64 sequence, and
  signed receipt plus a domain-separated authority high-water hash chain.
* The signed receipt binds the exact canonical consume request, nonce, request
  body, TLS channel, expiration, store identity, producer invocation,
  producer ephemeral key, fresh producer channel challenge, and the digest of
  an external verifier-state current-head authorization.
* The store signing SPKI and key id come only from a separately retained,
  immutable release-config FD and are checked against independently supplied
  release pins.
* The signer uses two distinct connected Unix sockets. Their type, access mode,
  peer uid/gid/pid, and common peer are checked before a service-generated
  per-launch channel nonce is authenticated.
* Every signer response is locally Ed25519-verified over the exact requested
  domain and message. A prior response cannot satisfy a new operation,
  channel launch, producer invocation, or producer channel challenge.
* Restart validation checks the effective SQLite PRAGMAs, performs an exact WAL
  checkpoint and integrity check, and validates every tombstone, signature,
  contiguous sequence, receipt link, and authority high-water link.

The reference service does not validate or consume the external current-head
authorization and cannot issue the required verifier-state CAS commit receipt.
Those are independent production-authority responsibilities. Their digest
binding here prevents substitution but does not make SQLite production-safe.

Malformed client frames receive a closed error and do not stop the shared
service. Database, signer, framing-output, and invariant failures terminate the
service so a supervisor can investigate rather than continue from uncertain
state.
"""

from __future__ import annotations

import argparse
import base64
import binascii
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
from pathlib import Path
from typing import Any, Callable, Mapping


U64_MAX = 18_446_744_073_709_551_615
PID_MAX = 2_147_483_647
MAX_FRAME_BYTES = 1_048_576
MAX_TTL_SECONDS = 300
MAX_RECORDS = 10_000_000
MAX_JSON_DEPTH = 16
MAX_JSON_CONTAINER_ITEMS = 256
MAX_JSON_NODES = 4096
MAX_JSON_STRING_BYTES = 262_144
MAX_SERVICE_CHALLENGE_FRAME_BYTES = 16 * 1024
MAX_SERVICE_EXECUTABLE_BYTES = 256 * 1024 * 1024
FD_OPERATION_TIMEOUT_SECONDS = 30.0

DESCRIPTOR_VERSION = "serverware.attestationNonceServiceDescriptor/v2"
IMMUTABLE_CONFIG_VERSION = (
    "serverware.signedAttestationNonceImmutableReleaseConfig/v1"
)
IMMUTABLE_CONFIG_PAYLOAD_VERSION = (
    "serverware.attestationNonceImmutableReleaseConfigPayload/v1"
)
STORE_IDENTITY_VERSION = "serverware.attestationNonceStoreIdentity/v2"
NONCE_AUTHORITY_ASSURANCE_VERSION = (
    "serverware.nonceAuthorityAssurance/v1"
)
NONCE_AUTHORITY_STATE_VERSION = "serverware.nonceAuthorityState/v1"
NONCE_AUTHORITY_HIGH_WATER_INPUT_VERSION = (
    "serverware.nonceAuthorityHighWaterCommitment/v1"
)
RESERVE_REQUEST_VERSION = "serverware.attestationNonceReserveRequest/v2"
RESERVE_RESPONSE_VERSION = "serverware.attestationNonceReserveResponse/v2"
CONSUME_REQUEST_VERSION = "serverware.attestationNonceConsumeRequest/v3"
CONSUME_ONCE_REQUEST_VERSION = (
    "serverware.attestationNonceConsumeOnceRequest/v3"
)
CONSUMPTION_VERSION = "serverware.publicAttestationNonceConsumption/v1"
RECEIPT_PAYLOAD_VERSION = (
    "serverware.attestationNonceConsumptionReceiptPayload/v2"
)
SIGNED_RECEIPT_VERSION = (
    "serverware.signedAttestationNonceConsumptionReceipt/v2"
)
CONSUME_RESPONSE_VERSION = "serverware.attestationNonceConsumeResponse/v2"
STATUS_REQUEST_VERSION = (
    "serverware.attestationNonceTransactionStatusRequest/v1"
)
STATUS_RESPONSE_VERSION = (
    "serverware.attestationNonceTransactionStatusResponse/v1"
)
STATUS_EVIDENCE_VERSION = (
    "serverware.attestationNonceTransactionStatusEvidence/v1"
)
SIGNED_STATUS_EVIDENCE_VERSION = (
    "serverware.signedAttestationNonceTransactionStatusEvidence/v1"
)
ERROR_RESPONSE_VERSION = "serverware.attestationNonceServiceError/v1"
SERVICE_CHALLENGE_VERSION = (
    "serverware.publicAttestationServiceChannelChallenge/v1"
)
SERVICE_CHALLENGE_RESPONSE_VERSION = (
    "serverware.publicAttestationServiceChannelChallengeResponse/v1"
)
SERVICE_PROTOCOL_VERSION = "serverware.attestationNonceService/v2"

SIGNER_REQUEST_VERSION = "serverware.attestationNonceSignerRequest/v2"
SIGNER_RESPONSE_VERSION = "serverware.attestationNonceSignerResponse/v2"
SIGNER_CHANNEL_OPEN_VERSION = (
    "serverware.attestationNonceSignerChannelOpen/v1"
)
SIGNER_CHANNEL_POLICY_VERSION = (
    "serverware.attestationNonceSignerChannelPolicy/v1"
)
SIGNER_CHANNEL_BINDING_VERSION = (
    "serverware.attestationNonceSignerChannelBinding/v1"
)

NONCE_RECEIPT_DOMAIN = (
    b"serverware.attestationNonceConsumptionReceipt/v2\x00Ed25519\x00"
)
NONCE_STATUS_EVIDENCE_DOMAIN = (
    b"serverware.attestationNonceTransactionStatusEvidence/v1\x00"
    b"Ed25519\x00"
)
SIGNER_PROTOCOL_DOMAIN = (
    b"serverware.attestationNonceSignerRequest/v2\x00"
)
SIGNER_CHANNEL_OPEN_DOMAIN = (
    b"serverware.attestationNonceSignerChannelOpen/v1\x00Ed25519\x00"
)
CONSUME_REQUEST_DIGEST_DOMAIN = (
    b"serverware.attestationNonceConsumeRequestDigest/v3\x00"
)
IMMUTABLE_CONFIG_DOMAIN = (
    b"serverware.attestationNonceImmutableReleaseConfig/v1\x00"
    b"Ed25519\x00"
)
NONCE_AUTHORITY_GENESIS_DOMAIN = (
    b"serverware.nonceAuthorityGenesisCommitment/v1\x00"
)
NONCE_AUTHORITY_HIGH_WATER_DOMAIN = (
    b"serverware.nonceAuthorityHighWaterCommitment/v1\x00"
)

SHA256_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
IDENTIFIER_RE = re.compile(
    r"\A[a-z0-9][a-z0-9._:/-]{1,126}[a-z0-9]\Z"
)
CGROUP_COMPONENT_RE = re.compile(r"\A[A-Za-z0-9._+@=-]+\Z")


class NonceServiceError(ValueError):
    """Base class for closed protocol and invariant failures."""


class NonceRequestError(NonceServiceError):
    """A request-local failure that may be returned without stopping service."""

    def __init__(self, error_code: str) -> None:
        if error_code not in {
            "capacityExceeded",
            "invalidRequest",
            "replayRejected",
        }:
            raise ValueError("invalid nonce request error code")
        super().__init__(error_code)
        self.error_code = error_code


class NonceFrameError(NonceRequestError):
    """A malformed or over-bound client frame."""

    def __init__(self) -> None:
        super().__init__("invalidRequest")


class NonceChannelDeadlineError(NonceServiceError):
    """A bounded retained-FD operation exhausted its shared deadline."""


class NonceInvariantError(RuntimeError):
    """A database, signer, or channel failure that must stop the service."""


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
        raise NonceServiceError(f"{label} must be base64url text")
    expected_chars = (expected_bytes * 8 + 5) // 6
    if (
        len(value) != expected_chars
        or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None
    ):
        raise NonceServiceError(f"{label} has the wrong base64url shape")
    try:
        decoded = base64.urlsafe_b64decode(
            value + "=" * ((4 - len(value) % 4) % 4)
        )
    except (ValueError, binascii.Error) as exc:
        raise NonceServiceError(f"{label} is invalid base64url") from exc
    if (
        len(decoded) != expected_bytes
        or canonical_base64url(decoded) != value
    ):
        raise NonceServiceError(f"{label} is not canonical base64url")
    return decoded


def closed_object(
    value: Any,
    expected: set[str],
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise NonceServiceError(f"{label} is not a closed object")
    return value


def require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise NonceServiceError(f"{label} is not a sha256 digest")
    return value


def require_u64(
    value: Any,
    label: str,
    *,
    minimum: int = 0,
    maximum: int = U64_MAX,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise NonceServiceError(f"{label} is not a bounded unsigned integer")
    return value


def require_identifier(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or IDENTIFIER_RE.fullmatch(value) is None
    ):
        raise NonceServiceError(f"{label} is not a canonical identifier")
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
        raise NonceServiceError(f"{label} is not a normalized absolute path")
    components = value.split("/")[1:]
    if any(component in {"", ".", ".."} for component in components):
        raise NonceServiceError(f"{label} contains a forbidden component")
    return value


def _pairs_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _parse_json_u64(value: str) -> int:
    parsed = int(value, 10)
    if parsed < 0 or parsed > U64_MAX:
        raise ValueError("JSON integer is outside u64")
    return parsed


def _reject_json_number(value: str) -> None:
    raise ValueError(f"forbidden JSON number: {value}")


def _validate_json_tree(
    value: Any,
    *,
    depth: int,
    node_count: list[int],
) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ValueError("JSON nesting depth exceeds its bound")
    node_count[0] += 1
    if node_count[0] > MAX_JSON_NODES:
        raise ValueError("JSON node count exceeds its bound")
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, str):
        if len(value.encode("utf-8")) > MAX_JSON_STRING_BYTES:
            raise ValueError("JSON string exceeds its bound")
        return
    if isinstance(value, list):
        if len(value) > MAX_JSON_CONTAINER_ITEMS:
            raise ValueError("JSON array exceeds its item bound")
        for item in value:
            _validate_json_tree(
                item,
                depth=depth + 1,
                node_count=node_count,
            )
        return
    if isinstance(value, dict):
        if len(value) > MAX_JSON_CONTAINER_ITEMS:
            raise ValueError("JSON object exceeds its item bound")
        for key, item in value.items():
            if (
                not isinstance(key, str)
                or len(key.encode("utf-8")) > MAX_JSON_STRING_BYTES
            ):
                raise ValueError("JSON object key is invalid")
            _validate_json_tree(
                item,
                depth=depth + 1,
                node_count=node_count,
            )
        return
    raise ValueError("JSON value type is forbidden")


def parse_canonical_json(
    raw: bytes,
    *,
    label: str,
    max_bytes: int = MAX_FRAME_BYTES,
) -> dict[str, Any]:
    if not raw or len(raw) > max_bytes:
        raise NonceFrameError()
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_pairs_object,
            parse_int=_parse_json_u64,
            parse_float=_reject_json_number,
            parse_constant=_reject_json_number,
        )
        _validate_json_tree(value, depth=0, node_count=[0])
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise NonceFrameError() from exc
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw:
        raise NonceFrameError()
    return value


class BoundedCanonicalJsonLineFd:
    """A bounded canonical-JSON line channel with frame-level recovery."""

    def __init__(self, fd: int, *, max_bytes: int) -> None:
        self._fd = require_u64(
            fd,
            "service channel fd",
            minimum=3,
            maximum=PID_MAX,
        )
        if not 1 <= max_bytes <= MAX_FRAME_BYTES:
            raise NonceInvariantError("service channel bound is invalid")
        try:
            os.fstat(self._fd)
        except OSError as exc:
            raise NonceInvariantError("service channel fd is unavailable") from exc
        self._max_bytes = max_bytes
        self._buffer = bytearray()
        self._discarding_oversize_frame = False
        try:
            os.set_blocking(self._fd, False)
        except OSError as exc:
            raise NonceInvariantError(
                "service channel could not be made nonblocking"
            ) from exc

    @property
    def has_buffered_data(self) -> bool:
        return bool(self._buffer) or self._discarding_oversize_frame

    def _wait(
        self,
        *,
        event: int,
        deadline: float,
        label: str,
    ) -> None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise NonceChannelDeadlineError(
                f"{label} exhausted its shared deadline"
            )
        poller = select.poll()
        poller.register(
            self._fd,
            event
            | select.POLLERR
            | select.POLLHUP
            | select.POLLNVAL,
        )
        events = poller.poll(max(1, int(remaining * 1000)))
        if not events:
            raise NonceChannelDeadlineError(
                f"{label} exhausted its shared deadline"
            )
        returned = events[0][1]
        if (
            returned & (select.POLLERR | select.POLLNVAL)
            or event == select.POLLOUT
            and returned & select.POLLHUP
        ):
            raise NonceInvariantError(f"{label} channel failed")
        if not (
            returned & event
            or event == select.POLLIN
            and returned & select.POLLHUP
        ):
            raise NonceInvariantError(
                f"{label} channel returned an invalid poll event"
            )

    def read(
        self,
        *,
        label: str,
        deadline: float,
    ) -> dict[str, Any] | None:
        while True:
            if self._discarding_oversize_frame:
                try:
                    self._wait(
                        event=select.POLLIN,
                        deadline=deadline,
                        label=label,
                    )
                    chunk = os.read(self._fd, 65536)
                except BlockingIOError:
                    continue
                except NonceChannelDeadlineError:
                    self._buffer.clear()
                    self._discarding_oversize_frame = False
                    raise
                except OSError as exc:
                    raise NonceInvariantError(
                        f"{label} channel read failed"
                    ) from exc
                if not chunk:
                    self._discarding_oversize_frame = False
                    raise NonceFrameError()
                newline = chunk.find(b"\n")
                if newline < 0:
                    continue
                self._buffer.extend(chunk[newline + 1 :])
                self._discarding_oversize_frame = False
                raise NonceFrameError()

            newline = self._buffer.find(b"\n")
            if newline >= 0:
                raw = bytes(self._buffer[:newline])
                del self._buffer[: newline + 1]
                if len(raw) > self._max_bytes:
                    raise NonceFrameError()
                return parse_canonical_json(
                    raw,
                    label=label,
                    max_bytes=self._max_bytes,
                )

            if len(self._buffer) > self._max_bytes:
                self._buffer.clear()
                self._discarding_oversize_frame = True
                continue

            try:
                self._wait(
                    event=select.POLLIN,
                    deadline=deadline,
                    label=label,
                )
                chunk = os.read(
                    self._fd,
                    min(65536, self._max_bytes + 2),
                )
            except BlockingIOError:
                continue
            except NonceChannelDeadlineError:
                self._buffer.clear()
                self._discarding_oversize_frame = False
                raise
            except OSError as exc:
                raise NonceInvariantError(
                    f"{label} channel read failed"
                ) from exc
            if not chunk:
                if self._buffer:
                    self._buffer.clear()
                    raise NonceFrameError()
                return None
            self._buffer.extend(chunk)

    def write(
        self,
        value: Mapping[str, Any],
        *,
        deadline: float,
        label: str,
    ) -> None:
        raw = canonical_json_bytes(dict(value)) + b"\n"
        if len(raw) > self._max_bytes:
            raise NonceInvariantError(
                "service response exceeds its size bound"
            )
        offset = 0
        while offset < len(raw):
            try:
                self._wait(
                    event=select.POLLOUT,
                    deadline=deadline,
                    label=label,
                )
                written = os.write(self._fd, raw[offset:])
            except BlockingIOError:
                continue
            except OSError as exc:
                raise NonceInvariantError(
                    "service response channel write failed"
                ) from exc
            if written <= 0:
                raise NonceInvariantError(
                    "service response channel closed"
                )
            offset += written


def _inspect_service_channel_fd(
    fd: int,
    *,
    label: str,
) -> tuple[int, int, int]:
    try:
        metadata = os.fstat(fd)
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    except OSError as exc:
        raise NonceInvariantError(
            f"{label} fd inspection failed"
        ) from exc
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or (flags & os.O_ACCMODE) != os.O_RDWR
    ):
        raise NonceInvariantError(
            f"{label} must be a read-write Unix socket"
        )
    if not hasattr(socket, "SO_PEERCRED"):
        raise NonceInvariantError(
            f"{label} requires Linux SO_PEERCRED"
        )
    duplicate = os.dup(fd)
    channel: socket.socket | None = None
    try:
        channel = socket.socket(fileno=duplicate)
        duplicate = -1
        if (
            channel.family != socket.AF_UNIX
            or channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
            != socket.SOCK_STREAM
        ):
            raise NonceInvariantError(
                f"{label} is not an AF_UNIX SOCK_STREAM socket"
            )
        channel.getpeername()
        raw_peer = channel.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            struct.calcsize("3i"),
        )
    except OSError as exc:
        raise NonceInvariantError(
            f"{label} peer authentication failed"
        ) from exc
    finally:
        if channel is not None:
            channel.close()
        elif duplicate >= 0:
            os.close(duplicate)
    peer_pid, peer_uid, peer_gid = struct.unpack("3i", raw_peer)
    if peer_pid < 1 or peer_uid < 0 or peer_gid < 0:
        raise NonceInvariantError(
            f"{label} peer credentials are invalid"
        )
    return peer_pid, peer_uid, peer_gid


def _live_service_executable_sha256() -> str:
    try:
        descriptor = os.open(
            "/proc/self/exe",
            os.O_RDONLY | os.O_CLOEXEC,
        )
    except OSError as exc:
        raise NonceInvariantError(
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
            raise NonceInvariantError(
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
                raise NonceInvariantError(
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
            raise NonceInvariantError(
                "live service executable changed while hashing"
            )
        return "sha256:" + digest.hexdigest()
    except OSError as exc:
        raise NonceInvariantError(
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
        raise NonceInvariantError(
            "live service cgroup membership is unavailable"
        ) from exc
    if len(raw) > 4096:
        raise NonceInvariantError(
            "live service cgroup membership exceeds its bound"
        )
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise NonceInvariantError(
            "live service cgroup membership is not ASCII"
        ) from exc
    if len(lines) != 1 or not lines[0].startswith("0::"):
        raise NonceInvariantError(
            "service does not have one cgroup-v2 membership"
        )
    try:
        membership = require_absolute_normal_path(
            lines[0][3:],
            "live service cgroup membership",
        )
    except NonceServiceError as exc:
        raise NonceInvariantError(
            "live service cgroup membership is not normalized"
        ) from exc
    if any(
        CGROUP_COMPONENT_RE.fullmatch(component) is None
        for component in membership.split("/")[1:]
    ):
        raise NonceInvariantError(
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
        challenge = closed_object(
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
            raise NonceServiceError(
                f"{role} service channel challenge crossed its contract"
            )
        decode_base64url(
            challenge["challengeBase64url"],
            expected_bytes=32,
            label=f"{role} service channel challenge",
        )
    except NonceServiceError as exc:
        raise NonceInvariantError(
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


def validate_nonce_store_identity(value: Any) -> dict[str, Any]:
    identity = closed_object(
        value,
        {
            "apiVersion",
            "assurance",
            "deploymentId",
            "productionEligible",
            "referenceOnly",
            "serviceId",
            "storageBackend",
        },
        "nonce store identity",
    )
    if identity["apiVersion"] != STORE_IDENTITY_VERSION:
        raise NonceServiceError("nonce store identity version is invalid")
    assurance = identity["assurance"]
    expected_backends = {
        "nonProductionFixture": "fixture-sqlite",
        "nonProductionDurableReference":
        "sqlite-full-sync-reference-only",
    }
    if assurance not in expected_backends:
        raise NonceServiceError(
            "local SQLite cannot claim production nonce assurance"
        )
    if (
        identity["productionEligible"] is not False
        or identity["referenceOnly"] is not True
    ):
        raise NonceServiceError(
            "local SQLite identity must be explicitly reference-only"
        )
    require_identifier(identity["deploymentId"], "nonce deployment id")
    require_identifier(identity["serviceId"], "nonce service id")
    if identity["storageBackend"] != expected_backends[assurance]:
        raise NonceServiceError(
            "nonce store assurance and backend disagree"
        )
    return identity


def reference_nonce_authority_assurance(
    identity: Mapping[str, Any],
    *,
    identity_sha256: str,
) -> dict[str, Any]:
    assurance_level = identity["assurance"]
    if assurance_level not in {
        "nonProductionFixture",
        "nonProductionDurableReference",
    }:
        raise NonceInvariantError(
            "SQLite reference authority received a production assurance label"
        )
    return {
        "apiVersion": NONCE_AUTHORITY_ASSURANCE_VERSION,
        "administrativeDomainSha256": sha256_json(
            {
                "apiVersion":
                "serverware.referenceNonceAuthorityAdministrativeDomain/v1",
                "deploymentId": identity["deploymentId"],
                "serviceId": identity["serviceId"],
            }
        ),
        "assuranceEvidenceSha256": None,
        "assuranceEvidenceType": "none",
        "assuranceLevel": assurance_level,
        "authorityEpoch": 1,
        "authorityGeneration": 1,
        "authorityIdentitySha256": require_sha256(
            identity_sha256,
            "reference nonce authority identity",
        ),
        "backendClass": "nonProductionSqlite",
        "productionEligible": False,
        "rollbackProtection": {
            "administrativeRollbackResistance": False,
            "backendAttestationRequired": False,
            "exactSuccessorRequired": True,
            "freshVerifierChallengeRequired": True,
            "keyProtection": "retainedFdReference",
            "mechanism": "none",
            "stateCommitment": "localHashChain",
            "verifierStateStoreClass": "nonProductionCallerFile",
        },
    }


def nonce_authority_genesis_commitment(
    assurance_sha256: str,
) -> str:
    return sha256_bytes(
        NONCE_AUTHORITY_GENESIS_DOMAIN
        + canonical_json_bytes(
            {
                "assuranceSha256": require_sha256(
                    assurance_sha256,
                    "nonce authority assurance",
                ),
            }
        )
    )


def nonce_authority_high_water_commitment(
    *,
    assurance_sha256: str,
    authority_epoch: int,
    authority_generation: int,
    nonce_consumption_sha256: str,
    nonce_verifier_state_authorization_sha256: str,
    previous_high_water_commitment_sha256: str,
    previous_receipt_sha256: str | None,
    sequence: int,
    transaction_id_base64url: str,
) -> str:
    checked_sequence = require_u64(
        sequence,
        "nonce authority high-water sequence",
        minimum=1,
    )
    if checked_sequence == 1:
        if previous_receipt_sha256 is not None:
            raise NonceServiceError(
                "first nonce authority state has a receipt predecessor"
            )
    else:
        require_sha256(
            previous_receipt_sha256,
            "nonce authority receipt predecessor",
        )
    decode_base64url(
        transaction_id_base64url,
        expected_bytes=32,
        label="nonce authority transaction id",
    )
    commitment_input = {
        "apiVersion": NONCE_AUTHORITY_HIGH_WATER_INPUT_VERSION,
        "assuranceSha256": require_sha256(
            assurance_sha256,
            "nonce authority assurance",
        ),
        "authorityEpoch": require_u64(
            authority_epoch,
            "nonce authority epoch",
            minimum=1,
        ),
        "authorityGeneration": require_u64(
            authority_generation,
            "nonce authority generation",
            minimum=1,
        ),
        "nonceConsumptionSha256": require_sha256(
            nonce_consumption_sha256,
            "nonce authority consumption",
        ),
        "nonceVerifierStateAuthorizationSha256": require_sha256(
            nonce_verifier_state_authorization_sha256,
            "nonce verifier-state authorization",
        ),
        "previousHighWaterCommitmentSha256": require_sha256(
            previous_high_water_commitment_sha256,
            "previous nonce authority high-water commitment",
        ),
        "previousReceiptSha256": previous_receipt_sha256,
        "sequence": checked_sequence,
        "transactionIdBase64url": transaction_id_base64url,
    }
    return sha256_bytes(
        NONCE_AUTHORITY_HIGH_WATER_DOMAIN
        + canonical_json_bytes(commitment_input)
    )


def _validate_sorted_unique_sha256_array(
    value: Any,
    *,
    label: str,
) -> list[str]:
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= 32
    ):
        raise NonceServiceError(f"{label} must be a bounded array")
    validated = [
        require_sha256(item, f"{label} item") for item in value
    ]
    if validated != sorted(validated) or len(set(validated)) != len(validated):
        raise NonceServiceError(
            f"{label} must be unique and canonically ordered"
        )
    return validated


def _load_canonical_ed25519_public_key(
    spki_der: bytes,
    *,
    label: str,
) -> Any:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )

        public_key = serialization.load_der_public_key(spki_der)
        if not isinstance(public_key, Ed25519PublicKey):
            raise NonceServiceError(
                f"{label} is not an Ed25519 public key"
            )
        canonical_der = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except NonceServiceError:
        raise
    except Exception as exc:
        raise NonceServiceError(
            f"{label} could not be loaded"
        ) from exc
    if canonical_der != spki_der:
        raise NonceServiceError(
            f"{label} is not canonical DER"
        )
    return public_key


def validate_global_attestation_key_role_separation(
    role_key_ids: Mapping[str, Any],
) -> dict[str, str]:
    if not role_key_ids:
        raise NonceServiceError(
            "global nonce role registry is empty"
        )
    normalized = {
        name: require_sha256(
            value,
            f"global nonce {name} role",
        )
        for name, value in role_key_ids.items()
    }
    collisions: dict[str, list[str]] = {}
    for name, key_id in normalized.items():
        collisions.setdefault(key_id, []).append(name)
    duplicate_roles = sorted(
        sorted(names)
        for names in collisions.values()
        if len(names) > 1
    )
    if duplicate_roles:
        raise NonceServiceError(
            "global nonce key roles collide: "
            f"{duplicate_roles!r}"
        )
    return normalized


def validate_immutable_release_config(
    value: Any,
    *,
    expected_config_sha256: str,
    expected_release_identity_sha256: str,
    expected_release_signing_key_id: str,
    expected_release_signing_key_spki_base64url: str,
    expected_release_signing_key_spki_sha256: str,
    expected_signing_key_id: str,
    expected_signing_key_spki_sha256: str,
) -> dict[str, Any]:
    envelope = closed_object(
        value,
        {
            "apiVersion",
            "payload",
            "payloadSha256",
            "releaseSignatureBase64url",
            "releaseSigningKeyId",
            "releaseSigningKeySpkiSha256",
        },
        "signed nonce immutable release config",
    )
    if envelope["apiVersion"] != IMMUTABLE_CONFIG_VERSION:
        raise NonceServiceError(
            "signed nonce immutable config version is invalid"
        )
    if sha256_json(envelope) != require_sha256(
        expected_config_sha256,
        "expected nonce immutable config",
    ):
        raise NonceServiceError(
            "nonce immutable release config pin mismatch"
        )
    release_spki_der = decode_base64url(
        expected_release_signing_key_spki_base64url,
        expected_bytes=44,
        label="independently expected release signing SPKI",
    )
    release_spki_sha256 = require_sha256(
        expected_release_signing_key_spki_sha256,
        "expected release signing SPKI digest",
    )
    release_key_id = require_sha256(
        expected_release_signing_key_id,
        "expected release signing key id",
    )
    if (
        release_spki_sha256 != sha256_bytes(release_spki_der)
        or release_key_id != release_spki_sha256
        or envelope["releaseSigningKeyId"] != release_key_id
        or envelope["releaseSigningKeySpkiSha256"]
        != release_spki_sha256
    ):
        raise NonceServiceError(
            "nonce immutable config release root pin mismatch"
        )
    payload_sha256 = require_sha256(
        envelope["payloadSha256"],
        "nonce immutable config payload digest",
    )
    if payload_sha256 != sha256_json(envelope["payload"]):
        raise NonceServiceError(
            "nonce immutable config payload digest mismatch"
        )
    signature = decode_base64url(
        envelope["releaseSignatureBase64url"],
        expected_bytes=64,
        label="nonce immutable config release signature",
    )
    release_public_key = _load_canonical_ed25519_public_key(
        release_spki_der,
        label="nonce immutable config release signing SPKI",
    )
    signed_message = canonical_json_bytes(
        {
            "payload": envelope["payload"],
            "payloadSha256": payload_sha256,
        }
    )
    try:
        release_public_key.verify(
            signature,
            IMMUTABLE_CONFIG_DOMAIN + signed_message,
        )
    except Exception as exc:
        raise NonceServiceError(
            "nonce immutable config release signature is invalid"
        ) from exc

    config = closed_object(
        envelope["payload"],
        {
            "apiVersion",
            "nonceStoreIdentitySha256",
            "nonceStoreSigningKey",
            "prohibitedSigningKeyIds",
            "releaseIdentitySha256",
            "signerChannelPolicy",
        },
        "nonce immutable release config payload",
    )
    if config["apiVersion"] != IMMUTABLE_CONFIG_PAYLOAD_VERSION:
        raise NonceServiceError(
            "nonce immutable release config payload version is invalid"
        )
    release_identity = require_sha256(
        config["releaseIdentitySha256"],
        "nonce release identity",
    )
    if release_identity != require_sha256(
        expected_release_identity_sha256,
        "expected release identity",
    ):
        raise NonceServiceError("nonce release identity pin mismatch")
    require_sha256(
        config["nonceStoreIdentitySha256"],
        "immutable nonce store identity",
    )

    signing_key = closed_object(
        config["nonceStoreSigningKey"],
        {
            "algorithm",
            "keyId",
            "spkiBase64url",
            "spkiSha256",
        },
        "nonce store signing key",
    )
    if signing_key["algorithm"] != "Ed25519":
        raise NonceServiceError(
            "nonce store signing algorithm must be Ed25519"
        )
    spki_der = decode_base64url(
        signing_key["spkiBase64url"],
        expected_bytes=44,
        label="nonce store signing key SPKI",
    )
    spki_sha256 = require_sha256(
        signing_key["spkiSha256"],
        "nonce store signing key SPKI digest",
    )
    if spki_sha256 != sha256_bytes(spki_der):
        raise NonceServiceError(
            "nonce store signing SPKI digest mismatch"
        )
    if spki_sha256 != require_sha256(
        expected_signing_key_spki_sha256,
        "expected nonce store signing SPKI",
    ):
        raise NonceServiceError(
            "nonce store signing SPKI independent pin mismatch"
        )
    key_id = require_sha256(
        signing_key["keyId"],
        "nonce store signing key id",
    )
    if (
        key_id != spki_sha256
        or key_id
        != require_sha256(
            expected_signing_key_id,
            "expected nonce store signing key id",
        )
    ):
        raise NonceServiceError(
            "nonce store signing key id pin mismatch"
        )

    prohibited = _validate_sorted_unique_sha256_array(
        config["prohibitedSigningKeyIds"],
        label="prohibited nonce signing key ids",
    )
    if key_id in prohibited or release_key_id not in prohibited:
        raise NonceServiceError(
            "nonce store signing key is not custody-distinct"
        )
    validate_global_attestation_key_role_separation(
        {
            "nonceReceipt": key_id,
            "release": release_key_id,
            **{
                f"prohibitedRolePin:{index}": value
                for index, value in enumerate(prohibited)
                if value != release_key_id
            },
        }
    )

    policy = closed_object(
        config["signerChannelPolicy"],
        {
            "apiVersion",
            "expectedPeerGid",
            "expectedPeerUid",
            "fdAccessMode",
            "fdFamily",
            "fdSocketType",
            "requireDistinctFds",
            "requireSamePeerPid",
        },
        "nonce signer channel policy",
    )
    if (
        policy["apiVersion"] != SIGNER_CHANNEL_POLICY_VERSION
        or policy["fdAccessMode"] != "readWrite"
        or policy["fdFamily"] != "AF_UNIX"
        or policy["fdSocketType"] != "SOCK_STREAM"
        or policy["requireDistinctFds"] is not True
        or policy["requireSamePeerPid"] is not True
    ):
        raise NonceServiceError(
            "nonce signer channel policy is not the closed production profile"
        )
    require_u64(
        policy["expectedPeerUid"],
        "expected signer peer uid",
        maximum=0xFFFFFFFF,
    )
    require_u64(
        policy["expectedPeerGid"],
        "expected signer peer gid",
        maximum=0xFFFFFFFF,
    )
    return config


def _inspect_signer_socket(
    fd: int,
    *,
    label: str,
    expected_peer_pid: int,
    expected_peer_uid: int,
    expected_peer_gid: int,
) -> dict[str, Any]:
    checked_fd = require_u64(
        fd,
        f"{label} fd",
        minimum=3,
        maximum=PID_MAX,
    )
    try:
        fd_stat = os.fstat(checked_fd)
        flags = fcntl.fcntl(checked_fd, fcntl.F_GETFL)
    except OSError as exc:
        raise NonceInvariantError(
            f"{label} fd inspection failed"
        ) from exc
    if not stat.S_ISSOCK(fd_stat.st_mode):
        raise NonceInvariantError(f"{label} fd is not a socket")
    if flags & os.O_ACCMODE != os.O_RDWR:
        raise NonceInvariantError(f"{label} fd is not read-write")
    if not hasattr(socket, "SO_PEERCRED"):
        raise NonceInvariantError(
            "SO_PEERCRED is required for the nonce signer channel"
        )

    duplicate_fd = os.dup(checked_fd)
    peer_socket = socket.socket(fileno=duplicate_fd)
    try:
        if peer_socket.family != socket.AF_UNIX:
            raise NonceInvariantError(
                f"{label} fd is not an AF_UNIX socket"
            )
        socket_type = peer_socket.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_TYPE,
        )
        if socket_type != socket.SOCK_STREAM:
            raise NonceInvariantError(
                f"{label} fd is not a SOCK_STREAM socket"
            )
        peer_socket.getpeername()
        peer_credentials = peer_socket.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_PEERCRED,
            struct.calcsize("3i"),
        )
    except OSError as exc:
        raise NonceInvariantError(
            f"{label} peer authentication failed"
        ) from exc
    finally:
        peer_socket.close()

    peer_pid, peer_uid, peer_gid = struct.unpack("3i", peer_credentials)
    if (
        peer_pid != expected_peer_pid
        or peer_uid != expected_peer_uid
        or peer_gid != expected_peer_gid
    ):
        raise NonceInvariantError(
            f"{label} peer credentials do not match the launch contract"
        )
    return {
        "accessMode": "readWrite",
        "family": "AF_UNIX",
        "peerGid": peer_gid,
        "peerPid": peer_pid,
        "peerUid": peer_uid,
        "socketType": "SOCK_STREAM",
    }


class AuthenticatedFdEd25519Signer:
    """Retained-FD signer with peer, launch, request, and signature binding."""

    def __init__(
        self,
        *,
        request_fd: int,
        response_fd: int,
        expected_peer_pid: int,
        immutable_config: Mapping[str, Any],
        immutable_config_sha256: str,
        max_frame_bytes: int,
    ) -> None:
        if request_fd == response_fd:
            raise NonceInvariantError(
                "nonce signer request and response FDs must be distinct"
            )
        policy = immutable_config["signerChannelPolicy"]
        expected_uid = require_u64(
            policy["expectedPeerUid"],
            "signer peer uid",
            maximum=0xFFFFFFFF,
        )
        expected_gid = require_u64(
            policy["expectedPeerGid"],
            "signer peer gid",
            maximum=0xFFFFFFFF,
        )
        expected_pid = require_u64(
            expected_peer_pid,
            "signer peer pid",
            minimum=1,
            maximum=PID_MAX,
        )
        request_socket = _inspect_signer_socket(
            request_fd,
            label="nonce signer request",
            expected_peer_pid=expected_pid,
            expected_peer_uid=expected_uid,
            expected_peer_gid=expected_gid,
        )
        response_socket = _inspect_signer_socket(
            response_fd,
            label="nonce signer response",
            expected_peer_pid=expected_pid,
            expected_peer_uid=expected_uid,
            expected_peer_gid=expected_gid,
        )
        if (
            request_socket["peerPid"] != response_socket["peerPid"]
            or request_socket["peerUid"] != response_socket["peerUid"]
            or request_socket["peerGid"] != response_socket["peerGid"]
        ):
            raise NonceInvariantError(
                "nonce signer channels do not share one authenticated peer"
            )

        signing_key = immutable_config["nonceStoreSigningKey"]
        self._key_id = signing_key["keyId"]
        self._spki_sha256 = signing_key["spkiSha256"]
        self._spki_der = decode_base64url(
            signing_key["spkiBase64url"],
            expected_bytes=44,
            label="nonce signing SPKI",
        )
        self._public_key = self._load_public_key(self._spki_der)
        self._requests = BoundedCanonicalJsonLineFd(
            request_fd,
            max_bytes=max_frame_bytes,
        )
        self._responses = BoundedCanonicalJsonLineFd(
            response_fd,
            max_bytes=max_frame_bytes,
        )
        self._operation_deadline: float | None = None
        self._channel_nonce = canonical_base64url(
            secrets.token_bytes(32)
        )
        channel_binding = {
            "apiVersion": SIGNER_CHANNEL_BINDING_VERSION,
            "channelNonceBase64url": self._channel_nonce,
            "immutableConfigSha256": require_sha256(
                immutable_config_sha256,
                "nonce immutable config digest",
            ),
            "releaseIdentitySha256": immutable_config[
                "releaseIdentitySha256"
            ],
            "requestSocket": request_socket,
            "responseSocket": response_socket,
            "signingKeyId": self._key_id,
            "signingKeySpkiSha256": self._spki_sha256,
        }
        self._channel_binding_sha256 = sha256_json(channel_binding)
        self._authenticate_channel(channel_binding)

    @staticmethod
    def _load_public_key(spki_der: bytes) -> Any:
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )

            public_key = serialization.load_der_public_key(spki_der)
            if not isinstance(public_key, Ed25519PublicKey):
                raise NonceInvariantError(
                    "nonce signer SPKI is not an Ed25519 public key"
                )
            canonical_der = public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        except NonceInvariantError:
            raise
        except Exception as exc:
            raise NonceInvariantError(
                "nonce signer SPKI could not be loaded"
            ) from exc
        if canonical_der != spki_der:
            raise NonceInvariantError(
                "nonce signer SPKI is not canonical DER"
            )
        return public_key

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def spki_sha256(self) -> str:
        return self._spki_sha256

    @property
    def channel_binding_sha256(self) -> str:
        return self._channel_binding_sha256

    def begin_operation(self, deadline: float) -> None:
        if (
            self._operation_deadline is not None
            or deadline <= time.monotonic()
        ):
            raise NonceInvariantError(
                "nonce signer operation deadline is invalid"
            )
        self._operation_deadline = deadline

    def end_operation(self) -> None:
        self._operation_deadline = None

    def _authenticate_channel(
        self,
        channel_binding: Mapping[str, Any],
    ) -> None:
        message = canonical_json_bytes(
            {
                "apiVersion": SIGNER_CHANNEL_OPEN_VERSION,
                "channelBinding": dict(channel_binding),
                "channelBindingSha256": self._channel_binding_sha256,
            }
        )
        self._exchange_signature(
            domain=SIGNER_CHANNEL_OPEN_DOMAIN,
            message=message,
        )

    def _verify_signature(
        self,
        *,
        signature: bytes,
        domain: bytes,
        message: bytes,
    ) -> None:
        try:
            self._public_key.verify(signature, domain + message)
        except Exception as exc:
            raise NonceInvariantError(
                "nonce signer response signature verification failed"
            ) from exc

    def _exchange_signature(
        self,
        *,
        domain: bytes,
        message: bytes,
    ) -> bytes:
        deadline = self._operation_deadline
        if deadline is None:
            deadline = (
                time.monotonic() + FD_OPERATION_TIMEOUT_SECONDS
            )
        operation_id = canonical_base64url(secrets.token_bytes(32))
        request = {
            "apiVersion": SIGNER_REQUEST_VERSION,
            "channelNonceBase64url": self._channel_nonce,
            "domainBase64url": canonical_base64url(domain),
            "messageBase64url": canonical_base64url(message),
            "messageSha256": sha256_bytes(message),
            "operationIdBase64url": operation_id,
            "signingKeyId": self._key_id,
            "signingKeySpkiSha256": self._spki_sha256,
        }
        request_sha256 = sha256_bytes(
            SIGNER_PROTOCOL_DOMAIN + canonical_json_bytes(request)
        )
        self._requests.write(
            request,
            deadline=deadline,
            label="nonce signer request",
        )
        try:
            response = self._responses.read(
                label="nonce signer response",
                deadline=deadline,
            )
        except (NonceChannelDeadlineError, NonceFrameError) as exc:
            raise NonceInvariantError(
                "nonce signer did not return one complete frame before the shared deadline"
            ) from exc
        if response is None:
            raise NonceInvariantError(
                "nonce signer response channel closed"
            )
        try:
            response = closed_object(
                response,
                {
                    "apiVersion",
                    "channelNonceBase64url",
                    "operationIdBase64url",
                    "requestSha256",
                    "signatureBase64url",
                    "signingKeyId",
                    "signingKeySpkiSha256",
                },
                "nonce signer response",
            )
            if (
                response["apiVersion"] != SIGNER_RESPONSE_VERSION
                or response["channelNonceBase64url"]
                != self._channel_nonce
                or response["operationIdBase64url"] != operation_id
                or response["requestSha256"] != request_sha256
                or response["signingKeyId"] != self._key_id
                or response["signingKeySpkiSha256"]
                != self._spki_sha256
            ):
                raise NonceServiceError(
                    "nonce signer response binding mismatch"
                )
            signature = decode_base64url(
                response["signatureBase64url"],
                expected_bytes=64,
                label="nonce signer signature",
            )
        except NonceServiceError as exc:
            raise NonceInvariantError(
                "nonce signer returned an invalid response"
            ) from exc
        self._verify_signature(
            signature=signature,
            domain=domain,
            message=message,
        )
        return signature

    def sign(self, *, domain: bytes, message: bytes) -> bytes:
        return self._exchange_signature(domain=domain, message=message)

    def verify(
        self,
        *,
        signature: bytes,
        domain: bytes,
        message: bytes,
    ) -> None:
        self._verify_signature(
            signature=signature,
            domain=domain,
            message=message,
        )


def signed_receipt_envelope(
    *,
    payload: Mapping[str, Any],
    signer: AuthenticatedFdEd25519Signer,
) -> dict[str, Any]:
    payload_document = dict(payload)
    payload_sha256 = sha256_json(payload_document)
    message = canonical_json_bytes(
        {
            "payload": payload_document,
            "payloadSha256": payload_sha256,
        }
    )
    signature = signer.sign(
        domain=NONCE_RECEIPT_DOMAIN,
        message=message,
    )
    if len(signature) != 64:
        raise NonceInvariantError(
            "nonce signer returned a non-Ed25519 signature"
        )
    return {
        "apiVersion": SIGNED_RECEIPT_VERSION,
        "payload": payload_document,
        "payloadSha256": payload_sha256,
        "signatureAlgorithm": "Ed25519",
        "signatureBase64url": canonical_base64url(signature),
        "signingKeyId": signer.key_id,
        "signingKeySpkiSha256": signer.spki_sha256,
    }


def signed_status_evidence_envelope(
    *,
    payload: Mapping[str, Any],
    signer: AuthenticatedFdEd25519Signer,
) -> dict[str, Any]:
    payload_document = dict(payload)
    payload_sha256 = sha256_json(payload_document)
    message = canonical_json_bytes(
        {
            "payload": payload_document,
            "payloadSha256": payload_sha256,
        }
    )
    signature = signer.sign(
        domain=NONCE_STATUS_EVIDENCE_DOMAIN,
        message=message,
    )
    if len(signature) != 64:
        raise NonceInvariantError(
            "nonce signer returned an invalid status signature"
        )
    return {
        "apiVersion": SIGNED_STATUS_EVIDENCE_VERSION,
        "payload": payload_document,
        "payloadSha256": payload_sha256,
        "signatureAlgorithm": "Ed25519",
        "signatureBase64url": canonical_base64url(signature),
        "signingKeyId": signer.key_id,
        "signingKeySpkiSha256": signer.spki_sha256,
    }


def validate_signed_receipt_envelope(
    value: Any,
    *,
    signer: AuthenticatedFdEd25519Signer,
) -> dict[str, Any]:
    envelope = closed_object(
        value,
        {
            "apiVersion",
            "payload",
            "payloadSha256",
            "signatureAlgorithm",
            "signatureBase64url",
            "signingKeyId",
            "signingKeySpkiSha256",
        },
        "signed nonce consumption receipt",
    )
    if (
        envelope["apiVersion"] != SIGNED_RECEIPT_VERSION
        or envelope["signatureAlgorithm"] != "Ed25519"
        or envelope["signingKeyId"] != signer.key_id
        or envelope["signingKeySpkiSha256"] != signer.spki_sha256
    ):
        raise NonceServiceError(
            "signed nonce receipt key binding is invalid"
        )
    payload_sha256 = require_sha256(
        envelope["payloadSha256"],
        "signed nonce receipt payload digest",
    )
    if payload_sha256 != sha256_json(envelope["payload"]):
        raise NonceServiceError(
            "signed nonce receipt payload digest mismatch"
        )
    signature = decode_base64url(
        envelope["signatureBase64url"],
        expected_bytes=64,
        label="signed nonce receipt signature",
    )
    message = canonical_json_bytes(
        {
            "payload": envelope["payload"],
            "payloadSha256": payload_sha256,
        }
    )
    signer.verify(
        signature=signature,
        domain=NONCE_RECEIPT_DOMAIN,
        message=message,
    )
    return envelope


def _canonical_decimal(
    value: Any,
    label: str,
    *,
    minimum: int = 0,
) -> int:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"0|[1-9][0-9]{0,19}", value) is None
    ):
        raise NonceServiceError(f"{label} is not canonical decimal text")
    parsed = int(value, 10)
    return require_u64(parsed, label, minimum=minimum)


def _sequence_decimal(value: int) -> str:
    return f"{require_u64(value, 'nonce sequence', minimum=1):020d}"


class DurableNonceStore:
    """SQLite reference implementation; never production eligible."""

    def __init__(
        self,
        *,
        database_path: str,
        store_identity: Mapping[str, Any],
        expected_store_identity_sha256: str,
        allow_create: bool,
        signer: AuthenticatedFdEd25519Signer,
        release_identity_sha256: str,
        max_records: int = 1_000_000,
        max_ttl_seconds: int = 60,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self._database_path = require_absolute_normal_path(
            database_path,
            "nonce database path",
        )
        self._identity = validate_nonce_store_identity(
            dict(store_identity)
        )
        self._identity_sha256 = sha256_json(self._identity)
        if self._identity_sha256 != require_sha256(
            expected_store_identity_sha256,
            "expected nonce store identity",
        ):
            raise NonceInvariantError(
                "nonce store identity pin mismatch"
            )
        self._authority_assurance = (
            reference_nonce_authority_assurance(
                self._identity,
                identity_sha256=self._identity_sha256,
            )
        )
        self._authority_assurance_sha256 = sha256_json(
            self._authority_assurance
        )
        self._authority_epoch = require_u64(
            self._authority_assurance["authorityEpoch"],
            "nonce authority epoch",
            minimum=1,
        )
        self._authority_generation = require_u64(
            self._authority_assurance["authorityGeneration"],
            "nonce authority generation",
            minimum=1,
        )
        self._authority_genesis_commitment_sha256 = (
            nonce_authority_genesis_commitment(
                self._authority_assurance_sha256
            )
        )
        self._signer = signer
        self._release_identity_sha256 = require_sha256(
            release_identity_sha256,
            "nonce release identity",
        )
        self._max_records = require_u64(
            max_records,
            "maximum nonce records",
            minimum=1,
        )
        if self._max_records > MAX_RECORDS:
            raise NonceInvariantError(
                "nonce record bound is too large"
            )
        self._max_ttl = require_u64(
            max_ttl_seconds,
            "maximum nonce ttl",
            minimum=1,
        )
        if self._max_ttl > MAX_TTL_SECONDS:
            raise NonceInvariantError(
                "nonce ttl exceeds the service maximum"
            )
        self._clock = clock or (lambda: int(time.time()))
        self._last_observed_unix = 0
        self._prepare_reference_database_file(
            allow_create=allow_create
        )
        try:
            self._connection = sqlite3.connect(
                self._database_path,
                timeout=5.0,
                isolation_level=None,
            )
        except sqlite3.Error as exc:
            raise NonceInvariantError(
                "nonce reference database could not be opened"
            ) from exc
        self._connection.row_factory = sqlite3.Row
        self._configure_and_verify_pragmas()
        self._checkpoint_wal()
        self._verify_sqlite_integrity()
        self._initialize_schema()
        self._verify_sqlite_integrity()
        self._validate_database(full_scan=True)

    @property
    def store_identity_sha256(self) -> str:
        return self._identity_sha256

    def close(self) -> None:
        try:
            self._connection.close()
        except sqlite3.Error as exc:
            raise NonceInvariantError(
                "nonce reference database close failed"
            ) from exc

    def _prepare_reference_database_file(
        self,
        *,
        allow_create: bool,
    ) -> None:
        if not isinstance(allow_create, bool):
            raise NonceInvariantError(
                "nonce database allowCreate must be boolean"
            )
        assurance = self._identity["assurance"]
        if assurance == "nonProductionFixture" and allow_create is not True:
            raise NonceInvariantError(
                "fixture SQLite must be explicitly creatable"
            )
        if (
            assurance == "nonProductionDurableReference"
            and allow_create
        ):
            raise NonceInvariantError(
                "durable reference SQLite must be pre-created"
            )

        path = Path(self._database_path)
        parent = path.parent
        try:
            parent_stat = os.lstat(parent)
        except OSError as exc:
            raise NonceInvariantError(
                "nonce database parent is unavailable"
            ) from exc
        if (
            not stat.S_ISDIR(parent_stat.st_mode)
            or stat.S_ISLNK(parent_stat.st_mode)
            or parent_stat.st_uid != os.geteuid()
            or parent_stat.st_mode & 0o022
        ):
            raise NonceInvariantError(
                "nonce database parent must be a private real directory"
            )
        if not path.exists():
            if not allow_create:
                raise NonceInvariantError(
                    "nonce reference database is missing"
                )
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            try:
                fd = os.open(self._database_path, flags, 0o600)
                os.close(fd)
                directory_fd = os.open(parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError as exc:
                raise NonceInvariantError(
                    "nonce reference database creation failed"
                ) from exc
        try:
            file_stat = os.lstat(self._database_path)
        except OSError as exc:
            raise NonceInvariantError(
                "nonce reference database is unavailable"
            ) from exc
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or stat.S_ISLNK(file_stat.st_mode)
            or file_stat.st_uid != os.geteuid()
            or file_stat.st_mode & 0o077
        ):
            raise NonceInvariantError(
                "nonce reference database must be a private regular file"
            )
        # These checks are hygiene only. They intentionally do not claim that
        # SQLite opened this lstat result or that the path is rollback-safe.

    def _pragma_scalar(self, statement: str, label: str) -> Any:
        try:
            row = self._connection.execute(statement).fetchone()
        except sqlite3.Error as exc:
            raise NonceInvariantError(
                f"nonce SQLite {label} query failed"
            ) from exc
        if row is None or len(row) != 1:
            raise NonceInvariantError(
                f"nonce SQLite {label} result is invalid"
            )
        return row[0]

    def _configure_and_verify_pragmas(self) -> None:
        statements = (
            "PRAGMA foreign_keys=ON",
            "PRAGMA journal_mode=WAL",
            "PRAGMA synchronous=FULL",
            "PRAGMA wal_autocheckpoint=1",
            "PRAGMA busy_timeout=5000",
            "PRAGMA trusted_schema=OFF",
        )
        try:
            for statement in statements:
                self._connection.execute(statement)
        except sqlite3.Error as exc:
            raise NonceInvariantError(
                "nonce SQLite PRAGMA configuration failed"
            ) from exc
        effective = {
            "foreign_keys": self._pragma_scalar(
                "PRAGMA foreign_keys",
                "foreign_keys",
            ),
            "journal_mode": self._pragma_scalar(
                "PRAGMA journal_mode",
                "journal_mode",
            ),
            "synchronous": self._pragma_scalar(
                "PRAGMA synchronous",
                "synchronous",
            ),
            "wal_autocheckpoint": self._pragma_scalar(
                "PRAGMA wal_autocheckpoint",
                "wal_autocheckpoint",
            ),
            "busy_timeout": self._pragma_scalar(
                "PRAGMA busy_timeout",
                "busy_timeout",
            ),
            "trusted_schema": self._pragma_scalar(
                "PRAGMA trusted_schema",
                "trusted_schema",
            ),
        }
        expected = {
            "foreign_keys": 1,
            "journal_mode": "wal",
            "synchronous": 2,
            "wal_autocheckpoint": 1,
            "busy_timeout": 5000,
            "trusted_schema": 0,
        }
        if effective != expected:
            raise NonceInvariantError(
                "nonce SQLite effective PRAGMAs do not match the contract"
            )

    def _checkpoint_wal(self) -> None:
        try:
            rows = self._connection.execute(
                "PRAGMA wal_checkpoint(FULL)"
            ).fetchall()
        except sqlite3.Error as exc:
            raise NonceInvariantError(
                "nonce SQLite WAL checkpoint failed"
            ) from exc
        if len(rows) != 1 or len(rows[0]) != 3:
            raise NonceInvariantError(
                "nonce SQLite WAL checkpoint result is invalid"
            )
        busy, log_frames, checkpointed_frames = rows[0]
        try:
            checked_busy = require_u64(
                busy,
                "nonce WAL busy result",
            )
            checked_log = require_u64(
                log_frames,
                "nonce WAL frame count",
            )
            checked_checkpointed = require_u64(
                checkpointed_frames,
                "nonce WAL checkpointed frame count",
            )
        except NonceServiceError as exc:
            raise NonceInvariantError(
                "nonce SQLite WAL checkpoint values are invalid"
            ) from exc
        if checked_busy != 0 or checked_log != checked_checkpointed:
            raise NonceInvariantError(
                "nonce SQLite WAL checkpoint was not exact"
            )

    def _verify_sqlite_integrity(self) -> None:
        try:
            integrity_rows = self._connection.execute(
                "PRAGMA integrity_check"
            ).fetchall()
            foreign_key_rows = self._connection.execute(
                "PRAGMA foreign_key_check"
            ).fetchall()
        except sqlite3.Error as exc:
            raise NonceInvariantError(
                "nonce SQLite integrity query failed"
            ) from exc
        if (
            len(integrity_rows) != 1
            or len(integrity_rows[0]) != 1
            or integrity_rows[0][0] != "ok"
            or foreign_key_rows
        ):
            raise NonceInvariantError(
                "nonce SQLite integrity validation failed"
            )

    def _initialize_schema(self) -> None:
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS nonce_metadata (
                    key TEXT PRIMARY KEY NOT NULL,
                    value TEXT NOT NULL
                ) STRICT
                """
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS nonce_records (
                    nonce_sha256 TEXT PRIMARY KEY NOT NULL,
                    request_body_sha256 TEXT NOT NULL,
                    tls_binding_sha256 TEXT NOT NULL,
                    producer_invocation_sha256 TEXT NOT NULL,
                    producer_ephemeral_key_sha256 TEXT NOT NULL,
                    producer_channel_challenge_base64url TEXT NOT NULL UNIQUE,
                    verifier_state_authorization_sha256 TEXT NOT NULL,
                    state TEXT NOT NULL
                        CHECK(state IN ('reserved', 'consumed', 'blocked')),
                    reservation_id_base64url TEXT UNIQUE,
                    reserved_at_unix_decimal TEXT NOT NULL,
                    expires_at_unix_decimal TEXT NOT NULL,
                    consumed_at_unix_decimal TEXT,
                    sequence_decimal TEXT UNIQUE,
                    transaction_id_base64url TEXT UNIQUE,
                    consume_request_sha256 TEXT UNIQUE,
                    authority_high_water_commitment_sha256 TEXT UNIQUE,
                    previous_authority_high_water_commitment_sha256 TEXT,
                    previous_receipt_sha256 TEXT,
                    receipt_sha256 TEXT UNIQUE,
                    receipt_json BLOB
                ) STRICT
                """
            )
            self._connection.execute(
                """
                CREATE INDEX IF NOT EXISTS nonce_consumed_sequence
                ON nonce_records(sequence_decimal)
                WHERE state = 'consumed'
                """
            )
            initial_metadata = {
                "authorityEpoch": str(self._authority_epoch),
                "authorityGeneration": str(
                    self._authority_generation
                ),
                "lastAuthorityHighWaterCommitmentSha256":
                self._authority_genesis_commitment_sha256,
                "lastReceiptSha256": "",
                "nextSequence": "1",
                "nonceAuthorityAssuranceSha256":
                self._authority_assurance_sha256,
                "nonceStoreIdentitySha256": self._identity_sha256,
                "releaseIdentitySha256": self._release_identity_sha256,
                "schemaVersion": "5",
                "sequenceExhausted": "false",
                "signingKeyId": self._signer.key_id,
                "signingKeySpkiSha256": self._signer.spki_sha256,
            }
            for key, value in initial_metadata.items():
                existing = self._connection.execute(
                    "SELECT value FROM nonce_metadata WHERE key = ?",
                    (key,),
                ).fetchone()
                if existing is None:
                    self._connection.execute(
                        """
                        INSERT INTO nonce_metadata(key, value)
                        VALUES (?, ?)
                        """,
                        (key, value),
                    )
                elif (
                    key not in {
                        "lastAuthorityHighWaterCommitmentSha256",
                        "lastReceiptSha256",
                        "nextSequence",
                        "sequenceExhausted",
                    }
                    and existing["value"] != value
                ):
                    raise NonceInvariantError(
                        f"nonce database metadata changed: {key}"
                    )
            self._validate_database(full_scan=True)
            self._connection.execute("COMMIT")
        except Exception:
            if self._connection.in_transaction:
                self._connection.execute("ROLLBACK")
            raise
        self._checkpoint_wal()

    def _read_metadata(self) -> dict[str, str]:
        try:
            rows = self._connection.execute(
                "SELECT key, value FROM nonce_metadata ORDER BY key"
            ).fetchall()
        except sqlite3.Error as exc:
            raise NonceInvariantError(
                "nonce metadata read failed"
            ) from exc
        metadata = {row["key"]: row["value"] for row in rows}
        expected_keys = {
            "authorityEpoch",
            "authorityGeneration",
            "lastAuthorityHighWaterCommitmentSha256",
            "lastReceiptSha256",
            "nextSequence",
            "nonceAuthorityAssuranceSha256",
            "nonceStoreIdentitySha256",
            "releaseIdentitySha256",
            "schemaVersion",
            "sequenceExhausted",
            "signingKeyId",
            "signingKeySpkiSha256",
        }
        if set(metadata) != expected_keys or len(metadata) != len(rows):
            raise NonceInvariantError(
                "nonce database metadata is not closed"
            )
        static_expected = {
            "authorityEpoch": str(self._authority_epoch),
            "authorityGeneration": str(self._authority_generation),
            "nonceAuthorityAssuranceSha256":
            self._authority_assurance_sha256,
            "nonceStoreIdentitySha256": self._identity_sha256,
            "releaseIdentitySha256": self._release_identity_sha256,
            "schemaVersion": "5",
            "signingKeyId": self._signer.key_id,
            "signingKeySpkiSha256": self._signer.spki_sha256,
        }
        for key, expected in static_expected.items():
            if metadata[key] != expected:
                raise NonceInvariantError(
                    f"nonce database metadata changed: {key}"
                )
        if metadata["sequenceExhausted"] not in {"false", "true"}:
            raise NonceInvariantError(
                "nonce sequence terminal marker is invalid"
            )
        return metadata

    def _validate_consumption(
        self,
        value: Any,
        *,
        expected_nonce_sha256: str,
        expected_request_body_sha256: str,
        expected_tls_binding_sha256: str,
        expected_consumed_at_unix: int,
        expected_sequence: int,
    ) -> dict[str, Any]:
        consumption = closed_object(
            value,
            {
                "apiVersion",
                "consumedAtUnix",
                "nonceSha256",
                "oneUse",
                "requestBodySha256",
                "sequence",
                "storeIdentitySha256",
                "tlsBindingSha256",
            },
            "nonce consumption",
        )
        if (
            consumption["apiVersion"] != CONSUMPTION_VERSION
            or consumption["oneUse"] is not True
            or consumption["nonceSha256"] != expected_nonce_sha256
            or consumption["requestBodySha256"]
            != expected_request_body_sha256
            or consumption["tlsBindingSha256"]
            != expected_tls_binding_sha256
            or consumption["storeIdentitySha256"]
            != self._identity_sha256
            or require_u64(
                consumption["consumedAtUnix"],
                "nonce consumed time",
                minimum=1,
            )
            != expected_consumed_at_unix
            or require_u64(
                consumption["sequence"],
                "nonce consumption sequence",
                minimum=1,
            )
            != expected_sequence
        ):
            raise NonceServiceError(
                "stored nonce consumption changed"
            )
        return consumption

    def _validate_nonce_authority_state(
        self,
        value: Any,
        *,
        expected_sequence: int,
        expected_previous_high_water_commitment_sha256: str,
        expected_previous_receipt_sha256: str | None,
        nonce_consumption_sha256: str,
        nonce_verifier_state_authorization_sha256: str,
        transaction_id_base64url: str,
    ) -> dict[str, Any]:
        state = closed_object(
            value,
            {
                "apiVersion",
                "assuranceSha256",
                "authorityEpoch",
                "authorityGeneration",
                "highWaterCommitmentSha256",
                "highWaterSequence",
                "previousHighWaterCommitmentSha256",
            },
            "nonce authority state",
        )
        expected_commitment = nonce_authority_high_water_commitment(
            assurance_sha256=self._authority_assurance_sha256,
            authority_epoch=self._authority_epoch,
            authority_generation=self._authority_generation,
            nonce_consumption_sha256=nonce_consumption_sha256,
            nonce_verifier_state_authorization_sha256=(
                nonce_verifier_state_authorization_sha256
            ),
            previous_high_water_commitment_sha256=(
                expected_previous_high_water_commitment_sha256
            ),
            previous_receipt_sha256=(
                expected_previous_receipt_sha256
            ),
            sequence=expected_sequence,
            transaction_id_base64url=transaction_id_base64url,
        )
        if (
            state["apiVersion"] != NONCE_AUTHORITY_STATE_VERSION
            or state["assuranceSha256"]
            != self._authority_assurance_sha256
            or require_u64(
                state["authorityEpoch"],
                "nonce authority state epoch",
                minimum=1,
            )
            != self._authority_epoch
            or require_u64(
                state["authorityGeneration"],
                "nonce authority state generation",
                minimum=1,
            )
            != self._authority_generation
            or require_u64(
                state["highWaterSequence"],
                "nonce authority state high-water sequence",
                minimum=1,
            )
            != expected_sequence
            or state["previousHighWaterCommitmentSha256"]
            != expected_previous_high_water_commitment_sha256
            or state["highWaterCommitmentSha256"]
            != expected_commitment
        ):
            raise NonceServiceError(
                "nonce authority state changed or crossed its commitment"
            )
        return state

    def _validate_receipt_payload(
        self,
        value: Any,
        *,
        row: sqlite3.Row,
        expected_sequence: int,
        expected_previous_receipt_sha256: str | None,
        expected_previous_high_water_commitment_sha256: str,
    ) -> dict[str, Any]:
        payload = closed_object(
            value,
            {
                "apiVersion",
                "consumeRequestSha256",
                "consumedAtUnix",
                "expiresAtUnix",
                "finalExternalVerifierChallengeConsumed",
                "finalExternalVerifierChallengeConsumptionRequired",
                "nonceAuthorityAssuranceSha256",
                "nonceAuthorityState",
                "nonceAuthorityStateSha256",
                "nonceAuthorityVerifierStateAuthorizationSha256",
                "nonceConsumption",
                "nonceConsumptionSha256",
                "nonceSha256",
                "previousReceiptSha256",
                "producerChannelChallengeBase64url",
                "producerEphemeralKeySha256",
                "producerInvocationSha256",
                "receiptIssuedAtUnix",
                "requestBodySha256",
                "sequence",
                "signerChannelBindingSha256",
                "storeIdentitySha256",
                "tlsBindingSha256",
                "transactionIdBase64url",
            },
            "nonce consumption receipt payload",
        )
        if payload["apiVersion"] != RECEIPT_PAYLOAD_VERSION:
            raise NonceServiceError(
                "nonce receipt payload version is invalid"
            )
        sequence = require_u64(
            payload["sequence"],
            "nonce receipt sequence",
            minimum=1,
        )
        consumed_at = require_u64(
            payload["consumedAtUnix"],
            "nonce receipt consumed time",
            minimum=1,
        )
        issued_at = require_u64(
            payload["receiptIssuedAtUnix"],
            "nonce receipt issue time",
            minimum=1,
        )
        expires_at = require_u64(
            payload["expiresAtUnix"],
            "nonce receipt expiration",
            minimum=1,
        )
        transaction_id = payload["transactionIdBase64url"]
        decode_base64url(
            transaction_id,
            expected_bytes=32,
            label="nonce receipt transaction id",
        )
        channel_challenge = payload[
            "producerChannelChallengeBase64url"
        ]
        decode_base64url(
            channel_challenge,
            expected_bytes=32,
            label="producer channel challenge",
        )
        consumption = self._validate_consumption(
            payload["nonceConsumption"],
            expected_nonce_sha256=row["nonce_sha256"],
            expected_request_body_sha256=row[
                "request_body_sha256"
            ],
            expected_tls_binding_sha256=row[
                "tls_binding_sha256"
            ],
            expected_consumed_at_unix=consumed_at,
            expected_sequence=sequence,
        )
        nonce_consumption_sha256 = sha256_json(consumption)
        authority_state = self._validate_nonce_authority_state(
            payload["nonceAuthorityState"],
            expected_sequence=sequence,
            expected_previous_high_water_commitment_sha256=(
                expected_previous_high_water_commitment_sha256
            ),
            expected_previous_receipt_sha256=(
                expected_previous_receipt_sha256
            ),
            nonce_consumption_sha256=nonce_consumption_sha256,
            nonce_verifier_state_authorization_sha256=payload[
                "nonceAuthorityVerifierStateAuthorizationSha256"
            ],
            transaction_id_base64url=transaction_id,
        )
        if (
            sequence != expected_sequence
            or consumed_at != _canonical_decimal(
                row["consumed_at_unix_decimal"],
                "stored consumed time",
                minimum=1,
            )
            or issued_at != consumed_at
            or expires_at != _canonical_decimal(
                row["expires_at_unix_decimal"],
                "stored nonce expiration",
                minimum=1,
            )
            or payload["consumeRequestSha256"]
            != row["consume_request_sha256"]
            or payload["nonceSha256"] != row["nonce_sha256"]
            or payload["requestBodySha256"]
            != row["request_body_sha256"]
            or payload["tlsBindingSha256"]
            != row["tls_binding_sha256"]
            or payload["producerInvocationSha256"]
            != row["producer_invocation_sha256"]
            or payload["producerEphemeralKeySha256"]
            != row["producer_ephemeral_key_sha256"]
            or channel_challenge
            != row["producer_channel_challenge_base64url"]
            or transaction_id != row["transaction_id_base64url"]
            or payload["storeIdentitySha256"]
            != self._identity_sha256
            or payload["nonceAuthorityAssuranceSha256"]
            != self._authority_assurance_sha256
            or payload["nonceAuthorityStateSha256"]
            != sha256_json(authority_state)
            or payload[
                "nonceAuthorityVerifierStateAuthorizationSha256"
            ]
            != row["verifier_state_authorization_sha256"]
            or payload["previousReceiptSha256"]
            != expected_previous_receipt_sha256
            or payload[
                "finalExternalVerifierChallengeConsumptionRequired"
            ]
            is not True
            or payload["finalExternalVerifierChallengeConsumed"]
            is not False
            or payload["nonceConsumptionSha256"]
            != nonce_consumption_sha256
        ):
            raise NonceServiceError(
                "stored nonce receipt binding changed"
            )
        require_sha256(
            payload["consumeRequestSha256"],
            "nonce consume request digest",
        )
        require_sha256(
            payload["producerInvocationSha256"],
            "producer invocation digest",
        )
        require_sha256(
            payload["producerEphemeralKeySha256"],
            "producer ephemeral key digest",
        )
        require_sha256(
            payload["signerChannelBindingSha256"],
            "signer channel binding digest",
        )
        require_sha256(
            payload["nonceAuthorityAssuranceSha256"],
            "nonce authority assurance digest",
        )
        require_sha256(
            payload["nonceAuthorityStateSha256"],
            "nonce authority state digest",
        )
        require_sha256(
            payload[
                "nonceAuthorityVerifierStateAuthorizationSha256"
            ],
            "nonce authority verifier-state authorization digest",
        )
        if expected_previous_receipt_sha256 is not None:
            require_sha256(
                payload["previousReceiptSha256"],
                "previous nonce receipt digest",
            )
        return payload

    def _validate_stored_receipt(
        self,
        row: sqlite3.Row,
        *,
        expected_sequence: int,
        expected_previous_receipt_sha256: str | None,
        expected_previous_high_water_commitment_sha256: str,
    ) -> dict[str, Any]:
        if row["state"] != "consumed":
            raise NonceInvariantError(
                "non-consumed row appeared in receipt sequence"
            )
        if row["sequence_decimal"] != _sequence_decimal(
            expected_sequence
        ):
            raise NonceInvariantError(
                "nonce consumption sequence has a gap"
            )
        if row["receipt_json"] is None:
            raise NonceInvariantError(
                "consumed nonce receipt is missing"
            )
        try:
            receipt = parse_canonical_json(
                bytes(row["receipt_json"]),
                label="stored nonce receipt",
            )
            envelope = validate_signed_receipt_envelope(
                receipt,
                signer=self._signer,
            )
            payload = self._validate_receipt_payload(
                envelope["payload"],
                row=row,
                expected_sequence=expected_sequence,
                expected_previous_receipt_sha256=(
                    expected_previous_receipt_sha256
                ),
                expected_previous_high_water_commitment_sha256=(
                    expected_previous_high_water_commitment_sha256
                ),
            )
        except (NonceServiceError, NonceFrameError) as exc:
            raise NonceInvariantError(
                "stored nonce receipt validation failed"
            ) from exc
        receipt_sha256 = sha256_json(envelope)
        if receipt_sha256 != row["receipt_sha256"]:
            raise NonceInvariantError(
                "stored nonce receipt digest changed"
            )
        if (
            row["previous_receipt_sha256"]
            != expected_previous_receipt_sha256
        ):
            raise NonceInvariantError(
                "stored nonce receipt hash chain changed"
            )
        authority_state = payload["nonceAuthorityState"]
        high_water_commitment_sha256 = authority_state[
            "highWaterCommitmentSha256"
        ]
        if (
            row["authority_high_water_commitment_sha256"]
            != high_water_commitment_sha256
            or row[
                "previous_authority_high_water_commitment_sha256"
            ]
            != expected_previous_high_water_commitment_sha256
        ):
            raise NonceInvariantError(
                "stored nonce authority commitment chain changed"
            )
        return {
            "document": envelope,
            "highWaterCommitmentSha256":
            high_water_commitment_sha256,
            "payload": payload,
            "receiptSha256": receipt_sha256,
        }

    def _validate_reserved_row(self, row: sqlite3.Row) -> None:
        if row["state"] != "reserved":
            raise NonceInvariantError(
                "invalid row appeared in reserved set"
            )
        required_null = {
            "authority_high_water_commitment_sha256",
            "consume_request_sha256",
            "consumed_at_unix_decimal",
            "previous_authority_high_water_commitment_sha256",
            "previous_receipt_sha256",
            "receipt_json",
            "receipt_sha256",
            "sequence_decimal",
            "transaction_id_base64url",
        }
        if any(row[field] is not None for field in required_null):
            raise NonceInvariantError(
                "reserved nonce has consumption fields"
            )
        if row["reservation_id_base64url"] is None:
            raise NonceInvariantError(
                "reserved nonce is missing its reservation id"
            )
        decode_base64url(
            row["reservation_id_base64url"],
            expected_bytes=32,
            label="stored nonce reservation id",
        )
        _canonical_decimal(
            row["reserved_at_unix_decimal"],
            "stored nonce reservation time",
            minimum=1,
        )
        _canonical_decimal(
            row["expires_at_unix_decimal"],
            "stored nonce expiration",
            minimum=1,
        )
        require_sha256(row["nonce_sha256"], "stored nonce digest")
        require_sha256(
            row["request_body_sha256"],
            "stored request body digest",
        )
        require_sha256(
            row["tls_binding_sha256"],
            "stored TLS binding digest",
        )
        require_sha256(
            row["producer_invocation_sha256"],
            "stored producer invocation digest",
        )
        require_sha256(
            row["producer_ephemeral_key_sha256"],
            "stored producer ephemeral key digest",
        )
        require_sha256(
            row["verifier_state_authorization_sha256"],
            "stored nonce verifier-state authorization digest",
        )
        decode_base64url(
            row["producer_channel_challenge_base64url"],
            expected_bytes=32,
            label="stored producer channel challenge",
        )

    def _validate_blocked_row(self, row: sqlite3.Row) -> None:
        if row["state"] != "blocked":
            raise NonceInvariantError(
                "invalid row appeared in blocked set"
            )
        required_null = {
            "authority_high_water_commitment_sha256",
            "consumed_at_unix_decimal",
            "previous_authority_high_water_commitment_sha256",
            "previous_receipt_sha256",
            "receipt_json",
            "receipt_sha256",
            "sequence_decimal",
        }
        if (
            any(row[field] is not None for field in required_null)
            or row["reservation_id_base64url"] is not None
            or row["consume_request_sha256"] is None
            or row["transaction_id_base64url"] is None
        ):
            raise NonceInvariantError(
                "blocked nonce tombstone has mutable consumption fields"
            )
        decode_base64url(
            row["transaction_id_base64url"],
            expected_bytes=32,
            label="blocked nonce transaction",
        )
        require_sha256(
            row["consume_request_sha256"],
            "blocked consume request",
        )
        for field in (
            "nonce_sha256",
            "request_body_sha256",
            "tls_binding_sha256",
            "producer_invocation_sha256",
            "producer_ephemeral_key_sha256",
            "verifier_state_authorization_sha256",
        ):
            require_sha256(
                row[field],
                f"blocked nonce {field}",
            )
        decode_base64url(
            row["producer_channel_challenge_base64url"],
            expected_bytes=32,
            label="blocked producer channel challenge",
        )
        _canonical_decimal(
            row["reserved_at_unix_decimal"],
            "blocked nonce tombstone time",
            minimum=1,
        )
        _canonical_decimal(
            row["expires_at_unix_decimal"],
            "blocked nonce expiration",
            minimum=1,
        )

    def _validate_database(self, *, full_scan: bool) -> None:
        metadata = self._read_metadata()
        next_sequence = _canonical_decimal(
            metadata["nextSequence"],
            "next nonce sequence",
            minimum=1,
        )
        sequence_exhausted = metadata["sequenceExhausted"] == "true"
        try:
            count_row = self._connection.execute(
                "SELECT COUNT(*) AS count FROM nonce_records"
            ).fetchone()
            consumed_count_row = self._connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM nonce_records
                WHERE state = 'consumed'
                """
            ).fetchone()
        except sqlite3.Error as exc:
            raise NonceInvariantError(
                "nonce database count query failed"
            ) from exc
        if count_row is None or consumed_count_row is None:
            raise NonceInvariantError(
                "nonce database count result is missing"
            )
        count = require_u64(
            count_row["count"],
            "nonce record count",
        )
        consumed_count = require_u64(
            consumed_count_row["count"],
            "nonce consumed record count",
        )
        if count > self._max_records:
            raise NonceInvariantError(
                "nonce record count exceeds its bound"
            )
        expected_consumed_count = (
            next_sequence
            if sequence_exhausted
            else next_sequence - 1
        )
        if (
            sequence_exhausted
            and next_sequence != U64_MAX
        ) or consumed_count != expected_consumed_count:
            raise NonceInvariantError(
                "nonce sequence metadata is not contiguous"
            )

        if full_scan:
            try:
                reserved_rows = self._connection.execute(
                    """
                    SELECT * FROM nonce_records
                    WHERE state = 'reserved'
                    ORDER BY nonce_sha256
                    """
                ).fetchall()
                consumed_rows = self._connection.execute(
                    """
                    SELECT * FROM nonce_records
                    WHERE state = 'consumed'
                    ORDER BY sequence_decimal
                    """
                ).fetchall()
                blocked_rows = self._connection.execute(
                    """
                    SELECT * FROM nonce_records
                    WHERE state = 'blocked'
                    ORDER BY nonce_sha256
                    """
                ).fetchall()
            except sqlite3.Error as exc:
                raise NonceInvariantError(
                    "nonce full validation query failed"
                ) from exc
            for row in reserved_rows:
                self._validate_reserved_row(row)
            for row in blocked_rows:
                self._validate_blocked_row(row)
            previous_receipt_sha256: str | None = None
            previous_high_water_commitment_sha256 = (
                self._authority_genesis_commitment_sha256
            )
            for sequence, row in enumerate(consumed_rows, start=1):
                validated = self._validate_stored_receipt(
                    row,
                    expected_sequence=sequence,
                    expected_previous_receipt_sha256=(
                        previous_receipt_sha256
                    ),
                    expected_previous_high_water_commitment_sha256=(
                        previous_high_water_commitment_sha256
                    ),
                )
                previous_receipt_sha256 = validated["receiptSha256"]
                previous_high_water_commitment_sha256 = validated[
                    "highWaterCommitmentSha256"
                ]
            expected_last = previous_receipt_sha256 or ""
            expected_last_high_water = (
                previous_high_water_commitment_sha256
            )
        elif consumed_count:
            try:
                last_row = self._connection.execute(
                    """
                    SELECT * FROM nonce_records
                    WHERE state = 'consumed'
                    ORDER BY sequence_decimal DESC
                    LIMIT 1
                    """
                ).fetchone()
            except sqlite3.Error as exc:
                raise NonceInvariantError(
                    "nonce tail validation query failed"
                ) from exc
            if last_row is None:
                raise NonceInvariantError(
                    "nonce receipt tail is missing"
                )
            expected_previous = last_row[
                "previous_receipt_sha256"
            ]
            if consumed_count == 1 and expected_previous is not None:
                raise NonceInvariantError(
                    "first nonce receipt has a predecessor"
                )
            if expected_previous is not None:
                require_sha256(
                    expected_previous,
                    "nonce tail predecessor",
                )
            expected_previous_high_water = last_row[
                "previous_authority_high_water_commitment_sha256"
            ]
            require_sha256(
                expected_previous_high_water,
                "nonce authority tail predecessor",
            )
            validated = self._validate_stored_receipt(
                last_row,
                expected_sequence=consumed_count,
                expected_previous_receipt_sha256=expected_previous,
                expected_previous_high_water_commitment_sha256=(
                    expected_previous_high_water
                ),
            )
            expected_last = validated["receiptSha256"]
            expected_last_high_water = validated[
                "highWaterCommitmentSha256"
            ]
        else:
            expected_last = ""
            expected_last_high_water = (
                self._authority_genesis_commitment_sha256
            )
        if metadata["lastReceiptSha256"] != expected_last:
            raise NonceInvariantError(
                "nonce receipt head metadata changed"
            )
        if (
            metadata["lastAuthorityHighWaterCommitmentSha256"]
            != expected_last_high_water
        ):
            raise NonceInvariantError(
                "nonce authority high-water metadata changed"
            )

    def _validate_window(self, expires_at_unix: Any, now: int) -> int:
        expires = require_u64(
            expires_at_unix,
            "nonce expiration",
            minimum=1,
        )
        if (
            now > U64_MAX - self._max_ttl
            or not now < expires <= now + self._max_ttl
        ):
            raise NonceServiceError(
                "nonce expiration is stale or overlong"
            )
        return expires

    @staticmethod
    def _validate_bindings(
        request: Mapping[str, Any],
    ) -> dict[str, str]:
        channel_challenge = request[
            "producerChannelChallengeBase64url"
        ]
        decode_base64url(
            channel_challenge,
            expected_bytes=32,
            label="producer channel challenge",
        )
        return {
            "nonceSha256": require_sha256(
                request["nonceSha256"],
                "nonce digest",
            ),
            "nonceAuthorityVerifierStateAuthorizationSha256":
            require_sha256(
                request[
                    "nonceAuthorityVerifierStateAuthorizationSha256"
                ],
                "nonce verifier-state authorization digest",
            ),
            "producerChannelChallengeBase64url":
            channel_challenge,
            "producerEphemeralKeySha256": require_sha256(
                request["producerEphemeralKeySha256"],
                "producer ephemeral key digest",
            ),
            "producerInvocationSha256": require_sha256(
                request["producerInvocationSha256"],
                "producer invocation digest",
            ),
            "requestBodySha256": require_sha256(
                request["requestBodySha256"],
                "request body digest",
            ),
            "tlsBindingSha256": require_sha256(
                request["tlsBindingSha256"],
                "TLS binding digest",
            ),
        }

    @staticmethod
    def _consume_request_sha256(
        request_document: Mapping[str, Any],
    ) -> str:
        return sha256_bytes(
            CONSUME_REQUEST_DIGEST_DOMAIN
            + canonical_json_bytes(dict(request_document))
        )

    def _now(self) -> int:
        try:
            observed = require_u64(
                self._clock(),
                "nonce service clock",
                minimum=1,
            )
            if observed < self._last_observed_unix:
                raise NonceServiceError(
                    "nonce service clock rolled backward"
                )
            self._last_observed_unix = observed
            return observed
        except NonceServiceError as exc:
            raise NonceInvariantError(
                "nonce service clock is invalid"
            ) from exc

    def _begin_immediate(self) -> None:
        try:
            self._connection.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as exc:
            raise NonceInvariantError(
                "nonce SQLite transaction could not begin"
            ) from exc

    def _rollback(self) -> None:
        if self._connection.in_transaction:
            try:
                self._connection.execute("ROLLBACK")
            except sqlite3.Error as exc:
                raise NonceInvariantError(
                    "nonce SQLite rollback failed"
                ) from exc

    def _commit_and_checkpoint(self) -> None:
        try:
            self._connection.execute("COMMIT")
        except sqlite3.Error as exc:
            raise NonceInvariantError(
                "nonce SQLite commit failed"
            ) from exc
        self._checkpoint_wal()

    def reserve(self, request: Mapping[str, Any]) -> dict[str, Any]:
        try:
            request_document = closed_object(
                dict(request),
                {
                    "apiVersion",
                    "expiresAtUnix",
                    "nonceAuthorityVerifierStateAuthorizationSha256",
                    "nonceSha256",
                    "producerChannelChallengeBase64url",
                    "producerEphemeralKeySha256",
                    "producerInvocationSha256",
                    "requestBodySha256",
                    "tlsBindingSha256",
                },
                "nonce reservation request",
            )
            if request_document["apiVersion"] != RESERVE_REQUEST_VERSION:
                raise NonceServiceError(
                    "nonce reservation version is invalid"
                )
            bindings = self._validate_bindings(request_document)
            now = self._now()
            expires = self._validate_window(
                request_document["expiresAtUnix"],
                now,
            )
        except NonceInvariantError:
            raise
        except NonceServiceError as exc:
            raise NonceRequestError("invalidRequest") from exc

        reservation_id = canonical_base64url(secrets.token_bytes(32))
        self._begin_immediate()
        try:
            self._validate_database(full_scan=False)
            if self._read_metadata()["sequenceExhausted"] == "true":
                raise NonceRequestError("capacityExceeded")
            count = self._connection.execute(
                "SELECT COUNT(*) AS count FROM nonce_records"
            ).fetchone()["count"]
            if count >= self._max_records:
                raise NonceRequestError("capacityExceeded")
            self._connection.execute(
                """
                INSERT INTO nonce_records(
                    nonce_sha256,
                    request_body_sha256,
                    tls_binding_sha256,
                    producer_invocation_sha256,
                    producer_ephemeral_key_sha256,
                    producer_channel_challenge_base64url,
                    verifier_state_authorization_sha256,
                    state,
                    reservation_id_base64url,
                    reserved_at_unix_decimal,
                    expires_at_unix_decimal
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'reserved', ?, ?, ?)
                """,
                (
                    bindings["nonceSha256"],
                    bindings["requestBodySha256"],
                    bindings["tlsBindingSha256"],
                    bindings["producerInvocationSha256"],
                    bindings["producerEphemeralKeySha256"],
                    bindings[
                        "producerChannelChallengeBase64url"
                    ],
                    bindings[
                        "nonceAuthorityVerifierStateAuthorizationSha256"
                    ],
                    reservation_id,
                    str(now),
                    str(expires),
                ),
            )
            self._commit_and_checkpoint()
        except sqlite3.IntegrityError as exc:
            self._rollback()
            raise NonceRequestError("replayRejected") from exc
        except NonceRequestError:
            self._rollback()
            raise
        except Exception:
            self._rollback()
            raise
        return {
            "apiVersion": RESERVE_RESPONSE_VERSION,
            "expiresAtUnix": expires,
            "nonceAuthorityAssurance":
            self._authority_assurance,
            "nonceAuthorityAssuranceSha256":
            self._authority_assurance_sha256,
            "nonceSha256": bindings["nonceSha256"],
            "producerChannelChallengeBase64url": bindings[
                "producerChannelChallengeBase64url"
            ],
            "producerInvocationSha256": bindings[
                "producerInvocationSha256"
            ],
            "reservationIdBase64url": reservation_id,
            "reservedAtUnix": now,
            "storeIdentitySha256": self._identity_sha256,
        }

    def consume(self, request: Mapping[str, Any]) -> dict[str, Any]:
        try:
            request_document = closed_object(
                dict(request),
                {
                    "apiVersion",
                    "nonceAuthorityVerifierStateAuthorizationSha256",
                    "nonceSha256",
                    "producerChannelChallengeBase64url",
                    "producerEphemeralKeySha256",
                    "producerInvocationSha256",
                    "requestBodySha256",
                    "reservationIdBase64url",
                    "tlsBindingSha256",
                    "transactionIdBase64url",
                },
                "nonce consumption request",
            )
            if request_document["apiVersion"] != CONSUME_REQUEST_VERSION:
                raise NonceServiceError(
                    "nonce consumption version is invalid"
                )
            reservation_id = request_document[
                "reservationIdBase64url"
            ]
            decode_base64url(
                reservation_id,
                expected_bytes=32,
                label="nonce reservation id",
            )
            bindings = self._validate_bindings(request_document)
            transaction_id = request_document[
                "transactionIdBase64url"
            ]
            decode_base64url(
                transaction_id,
                expected_bytes=32,
                label="nonce transaction id",
            )
            consume_request_sha256 = self._consume_request_sha256(
                request_document
            )
            now = self._now()
        except NonceInvariantError:
            raise
        except NonceServiceError as exc:
            raise NonceRequestError("invalidRequest") from exc

        self._begin_immediate()
        try:
            self._validate_database(full_scan=False)
            row = self._connection.execute(
                """
                SELECT * FROM nonce_records
                WHERE nonce_sha256 = ?
                """,
                (bindings["nonceSha256"],),
            ).fetchone()
            if row is not None and row["state"] == "consumed":
                result = self._recover_exact_consumption(
                    row=row,
                    bindings=bindings,
                    consume_request_sha256=consume_request_sha256,
                    transaction_id_base64url=transaction_id,
                )
                self._connection.execute("COMMIT")
                return self._consumption_response(result)
            if (
                row is None
                or row["state"] != "reserved"
                or row["reservation_id_base64url"] != reservation_id
                or row["request_body_sha256"]
                != bindings["requestBodySha256"]
                or row["tls_binding_sha256"]
                != bindings["tlsBindingSha256"]
                or row["producer_invocation_sha256"]
                != bindings["producerInvocationSha256"]
                or row["producer_ephemeral_key_sha256"]
                != bindings["producerEphemeralKeySha256"]
                or row["producer_channel_challenge_base64url"]
                != bindings[
                    "producerChannelChallengeBase64url"
                ]
                or row["verifier_state_authorization_sha256"]
                != bindings[
                    "nonceAuthorityVerifierStateAuthorizationSha256"
                ]
                or now
                >= _canonical_decimal(
                    row["expires_at_unix_decimal"],
                    "stored nonce expiration",
                    minimum=1,
                )
            ):
                raise NonceRequestError("replayRejected")
            result = self._commit_consumption(
                row=row,
                bindings=bindings,
                consume_request_sha256=consume_request_sha256,
                consumed_at_unix=now,
                transaction_id_base64url=transaction_id,
            )
            self._commit_and_checkpoint()
        except NonceRequestError:
            self._rollback()
            raise
        except Exception:
            self._rollback()
            raise
        return self._consumption_response(result)

    def consume_once(self, request: Mapping[str, Any]) -> dict[str, Any]:
        try:
            request_document = closed_object(
                dict(request),
                {
                    "apiVersion",
                    "expiresAtUnix",
                    "nonceAuthorityVerifierStateAuthorizationSha256",
                    "nonceSha256",
                    "producerChannelChallengeBase64url",
                    "producerEphemeralKeySha256",
                    "producerInvocationSha256",
                    "requestBodySha256",
                    "tlsBindingSha256",
                    "transactionIdBase64url",
                },
                "atomic nonce consumption request",
            )
            if (
                request_document["apiVersion"]
                != CONSUME_ONCE_REQUEST_VERSION
            ):
                raise NonceServiceError(
                    "atomic nonce consumption version is invalid"
                )
            bindings = self._validate_bindings(request_document)
            transaction_id = request_document[
                "transactionIdBase64url"
            ]
            decode_base64url(
                transaction_id,
                expected_bytes=32,
                label="atomic nonce transaction id",
            )
            consume_request_sha256 = self._consume_request_sha256(
                request_document
            )
            now = self._now()
            expires = self._validate_window(
                request_document["expiresAtUnix"],
                now,
            )
        except NonceInvariantError:
            raise
        except NonceServiceError as exc:
            raise NonceRequestError("invalidRequest") from exc

        self._begin_immediate()
        try:
            self._validate_database(full_scan=False)
            existing = self._connection.execute(
                """
                SELECT * FROM nonce_records
                WHERE nonce_sha256 = ?
                   OR transaction_id_base64url = ?
                   OR consume_request_sha256 = ?
                """,
                (
                    bindings["nonceSha256"],
                    transaction_id,
                    consume_request_sha256,
                ),
            ).fetchall()
            if existing:
                if len(existing) != 1:
                    raise NonceInvariantError(
                        "nonce idempotency indexes crossed different records"
                    )
                result = self._recover_exact_consumption(
                    row=existing[0],
                    bindings=bindings,
                    consume_request_sha256=consume_request_sha256,
                    transaction_id_base64url=transaction_id,
                )
                self._connection.execute("COMMIT")
                return self._consumption_response(result)
            if self._read_metadata()["sequenceExhausted"] == "true":
                raise NonceRequestError("capacityExceeded")
            count = self._connection.execute(
                "SELECT COUNT(*) AS count FROM nonce_records"
            ).fetchone()["count"]
            if count >= self._max_records:
                raise NonceRequestError("capacityExceeded")
            self._connection.execute(
                """
                INSERT INTO nonce_records(
                    nonce_sha256,
                    request_body_sha256,
                    tls_binding_sha256,
                    producer_invocation_sha256,
                    producer_ephemeral_key_sha256,
                    producer_channel_challenge_base64url,
                    verifier_state_authorization_sha256,
                    state,
                    reserved_at_unix_decimal,
                    expires_at_unix_decimal
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'reserved', ?, ?)
                """,
                (
                    bindings["nonceSha256"],
                    bindings["requestBodySha256"],
                    bindings["tlsBindingSha256"],
                    bindings["producerInvocationSha256"],
                    bindings["producerEphemeralKeySha256"],
                    bindings[
                        "producerChannelChallengeBase64url"
                    ],
                    bindings[
                        "nonceAuthorityVerifierStateAuthorizationSha256"
                    ],
                    str(now),
                    str(expires),
                ),
            )
            row = self._connection.execute(
                """
                SELECT * FROM nonce_records
                WHERE nonce_sha256 = ?
                """,
                (bindings["nonceSha256"],),
            ).fetchone()
            if row is None:
                raise NonceInvariantError(
                    "atomic nonce reservation disappeared"
                )
            result = self._commit_consumption(
                row=row,
                bindings=bindings,
                consume_request_sha256=consume_request_sha256,
                consumed_at_unix=now,
                transaction_id_base64url=transaction_id,
            )
            self._commit_and_checkpoint()
        except sqlite3.IntegrityError as exc:
            self._rollback()
            raise NonceRequestError("replayRejected") from exc
        except NonceRequestError:
            self._rollback()
            raise
        except Exception:
            self._rollback()
            raise
        return self._consumption_response(result)

    def transaction_status(
        self,
        request: Mapping[str, Any],
    ) -> dict[str, Any]:
        try:
            request_document = closed_object(
                dict(request),
                {
                    "apiVersion",
                    "consumeRequest",
                    "preparedOperationSha256",
                    "recoveryKeySha256",
                    "requestBindingSha256",
                    "requestOperation",
                },
                "nonce transaction-status request",
            )
            if request_document["apiVersion"] != STATUS_REQUEST_VERSION:
                raise NonceServiceError(
                    "nonce status request version is invalid"
                )
            request_operation = request_document["requestOperation"]
            if request_operation not in {
                "recoverExact",
                "proveNeverConsumedAndBlock",
            }:
                raise NonceServiceError(
                    "nonce status operation is invalid"
                )
            consume_request = closed_object(
                request_document["consumeRequest"],
                {
                    "apiVersion",
                    "expiresAtUnix",
                    "nonceAuthorityVerifierStateAuthorizationSha256",
                    "nonceSha256",
                    "producerChannelChallengeBase64url",
                    "producerEphemeralKeySha256",
                    "producerInvocationSha256",
                    "requestBodySha256",
                    "tlsBindingSha256",
                    "transactionIdBase64url",
                },
                "status-bound nonce consume request",
            )
            if (
                consume_request["apiVersion"]
                != CONSUME_ONCE_REQUEST_VERSION
            ):
                raise NonceServiceError(
                    "status-bound consume request version is invalid"
                )
            bindings = self._validate_bindings(consume_request)
            transaction_id = consume_request[
                "transactionIdBase64url"
            ]
            decode_base64url(
                transaction_id,
                expected_bytes=32,
                label="status nonce transaction id",
            )
            consume_request_sha256 = self._consume_request_sha256(
                consume_request
            )
            prepared_operation_sha256 = require_sha256(
                request_document["preparedOperationSha256"],
                "status prepared operation",
            )
            recovery_key_sha256 = require_sha256(
                request_document["recoveryKeySha256"],
                "status recovery key",
            )
            request_binding_sha256 = require_sha256(
                request_document["requestBindingSha256"],
                "status request binding",
            )
            now = self._now()
        except NonceInvariantError:
            raise
        except NonceServiceError as exc:
            raise NonceRequestError("invalidRequest") from exc

        self._begin_immediate()
        try:
            self._validate_database(full_scan=False)
            matches = self._connection.execute(
                """
                SELECT * FROM nonce_records
                WHERE nonce_sha256=?
                   OR transaction_id_base64url=?
                   OR consume_request_sha256=?
                """,
                (
                    bindings["nonceSha256"],
                    transaction_id,
                    consume_request_sha256,
                ),
            ).fetchall()
            if len(matches) > 1:
                raise NonceInvariantError(
                    "nonce status indexes identify different records"
                )
            row = matches[0] if matches else None
            receipt: dict[str, Any] | None = None
            status = "notObserved"
            never_consumable = False
            if row is not None and row["state"] == "consumed":
                retained = self._recover_exact_consumption(
                    row=row,
                    bindings=bindings,
                    consume_request_sha256=consume_request_sha256,
                    transaction_id_base64url=transaction_id,
                )
                receipt = retained["receipt"]
                status = "consumed"
            elif row is not None and row["state"] == "blocked":
                self._validate_blocked_row(row)
                if (
                    row["nonce_sha256"] != bindings["nonceSha256"]
                    or row["request_body_sha256"]
                    != bindings["requestBodySha256"]
                    or row["tls_binding_sha256"]
                    != bindings["tlsBindingSha256"]
                    or row["producer_invocation_sha256"]
                    != bindings["producerInvocationSha256"]
                    or row["producer_ephemeral_key_sha256"]
                    != bindings["producerEphemeralKeySha256"]
                    or row[
                        "producer_channel_challenge_base64url"
                    ]
                    != bindings[
                        "producerChannelChallengeBase64url"
                    ]
                    or row[
                        "verifier_state_authorization_sha256"
                    ]
                    != bindings[
                        "nonceAuthorityVerifierStateAuthorizationSha256"
                    ]
                    or row["transaction_id_base64url"]
                    != transaction_id
                    or row["consume_request_sha256"]
                    != consume_request_sha256
                ):
                    raise NonceRequestError("replayRejected")
                status = "neverConsumed"
                never_consumable = True
            elif request_operation == "proveNeverConsumedAndBlock":
                if row is not None and row["state"] != "reserved":
                    raise NonceRequestError("replayRejected")
                if row is None:
                    self._connection.execute(
                        """
                        INSERT INTO nonce_records(
                            nonce_sha256,request_body_sha256,
                            tls_binding_sha256,
                            producer_invocation_sha256,
                            producer_ephemeral_key_sha256,
                            producer_channel_challenge_base64url,
                            verifier_state_authorization_sha256,
                            state,reserved_at_unix_decimal,
                            expires_at_unix_decimal,
                            transaction_id_base64url,
                            consume_request_sha256
                        ) VALUES(?,?,?,?,?,?,?,'blocked',?,?,?,?)
                        """,
                        (
                            bindings["nonceSha256"],
                            bindings["requestBodySha256"],
                            bindings["tlsBindingSha256"],
                            bindings["producerInvocationSha256"],
                            bindings["producerEphemeralKeySha256"],
                            bindings[
                                "producerChannelChallengeBase64url"
                            ],
                            bindings[
                                "nonceAuthorityVerifierStateAuthorizationSha256"
                            ],
                            str(now),
                            str(
                                require_u64(
                                    consume_request["expiresAtUnix"],
                                    "blocked nonce expiry",
                                    minimum=1,
                                )
                            ),
                            transaction_id,
                            consume_request_sha256,
                        ),
                    )
                else:
                    if (
                        row["nonce_sha256"] != bindings["nonceSha256"]
                        or row["request_body_sha256"]
                        != bindings["requestBodySha256"]
                        or row["tls_binding_sha256"]
                        != bindings["tlsBindingSha256"]
                        or row["producer_invocation_sha256"]
                        != bindings["producerInvocationSha256"]
                        or row["producer_ephemeral_key_sha256"]
                        != bindings["producerEphemeralKeySha256"]
                        or row[
                            "producer_channel_challenge_base64url"
                        ]
                        != bindings[
                            "producerChannelChallengeBase64url"
                        ]
                        or row[
                            "verifier_state_authorization_sha256"
                        ]
                        != bindings[
                            "nonceAuthorityVerifierStateAuthorizationSha256"
                        ]
                    ):
                        raise NonceRequestError("replayRejected")
                    updated = self._connection.execute(
                        """
                        UPDATE nonce_records
                        SET state='blocked',
                            reservation_id_base64url=NULL,
                            transaction_id_base64url=?,
                            consume_request_sha256=?
                        WHERE nonce_sha256=? AND state='reserved'
                        """,
                        (
                            transaction_id,
                            consume_request_sha256,
                            bindings["nonceSha256"],
                        ),
                    )
                    if updated.rowcount != 1:
                        raise NonceInvariantError(
                            "nonce tombstone did not replace one reservation"
                        )
                status = "neverConsumed"
                never_consumable = True
            self._commit_and_checkpoint()
        except sqlite3.IntegrityError as exc:
            self._rollback()
            raise NonceRequestError("replayRejected") from exc
        except Exception:
            self._rollback()
            raise
        receipt_sha256 = (
            None if receipt is None else sha256_json(receipt)
        )
        evidence_payload = {
            "apiVersion": STATUS_EVIDENCE_VERSION,
            "consumeRequestSha256": consume_request_sha256,
            "evidenceIssuedAtUnix": now,
            "neverConsumable": never_consumable,
            "nonceAuthorityVerifierStateAuthorizationSha256":
            bindings[
                "nonceAuthorityVerifierStateAuthorizationSha256"
            ],
            "nonceConsumptionReceiptSha256": receipt_sha256,
            "nonceSha256": bindings["nonceSha256"],
            "preparedOperationSha256":
            prepared_operation_sha256,
            "recoveryKeySha256": recovery_key_sha256,
            "requestBindingSha256": request_binding_sha256,
            "requestOperation": request_operation,
            "status": status,
            "transactionIdBase64url": transaction_id,
        }
        evidence = signed_status_evidence_envelope(
            payload=evidence_payload,
            signer=self._signer,
        )
        return {
            "apiVersion": STATUS_RESPONSE_VERSION,
            "nonceAuthorityAssurance":
            self._authority_assurance,
            "nonceAuthorityAssuranceSha256":
            self._authority_assurance_sha256,
            "nonceConsumptionReceipt": receipt,
            "nonceStatusEvidence": evidence,
            "nonceStatusEvidenceSha256": sha256_json(evidence),
            "status": status,
            "storeIdentitySha256": self._identity_sha256,
        }

    def _commit_consumption(
        self,
        *,
        row: sqlite3.Row,
        bindings: Mapping[str, str],
        consume_request_sha256: str,
        consumed_at_unix: int,
        transaction_id_base64url: str,
    ) -> dict[str, Any]:
        metadata = self._read_metadata()
        sequence = _canonical_decimal(
            metadata["nextSequence"],
            "next nonce sequence",
            minimum=1,
        )
        if metadata["sequenceExhausted"] == "true":
            raise NonceRequestError("capacityExceeded")
        terminal_sequence = sequence == U64_MAX
        next_sequence = (
            sequence
            if terminal_sequence
            else require_u64(
                sequence + 1,
                "advanced nonce sequence",
                minimum=1,
            )
        )
        next_sequence_exhausted = (
            "true" if terminal_sequence else "false"
        )
        previous_receipt_sha256 = (
            metadata["lastReceiptSha256"] or None
        )
        if previous_receipt_sha256 is not None:
            require_sha256(
                previous_receipt_sha256,
                "previous nonce receipt digest",
            )
        previous_high_water_commitment_sha256 = require_sha256(
            metadata["lastAuthorityHighWaterCommitmentSha256"],
            "previous nonce authority high-water commitment",
        )
        expires_at_unix = _canonical_decimal(
            row["expires_at_unix_decimal"],
            "stored nonce expiration",
            minimum=1,
        )
        transaction_id = transaction_id_base64url
        decode_base64url(
            transaction_id,
            expected_bytes=32,
            label="committed nonce transaction id",
        )
        consumption = {
            "apiVersion": CONSUMPTION_VERSION,
            "consumedAtUnix": consumed_at_unix,
            "nonceSha256": bindings["nonceSha256"],
            "oneUse": True,
            "requestBodySha256": bindings["requestBodySha256"],
            "sequence": sequence,
            "storeIdentitySha256": self._identity_sha256,
            "tlsBindingSha256": bindings["tlsBindingSha256"],
        }
        nonce_consumption_sha256 = sha256_json(consumption)
        high_water_commitment_sha256 = (
            nonce_authority_high_water_commitment(
                assurance_sha256=(
                    self._authority_assurance_sha256
                ),
                authority_epoch=self._authority_epoch,
                authority_generation=self._authority_generation,
                nonce_consumption_sha256=(
                    nonce_consumption_sha256
                ),
                nonce_verifier_state_authorization_sha256=(
                    bindings[
                        "nonceAuthorityVerifierStateAuthorizationSha256"
                    ]
                ),
                previous_high_water_commitment_sha256=(
                    previous_high_water_commitment_sha256
                ),
                previous_receipt_sha256=(
                    previous_receipt_sha256
                ),
                sequence=sequence,
                transaction_id_base64url=transaction_id,
            )
        )
        authority_state = {
            "apiVersion": NONCE_AUTHORITY_STATE_VERSION,
            "assuranceSha256":
            self._authority_assurance_sha256,
            "authorityEpoch": self._authority_epoch,
            "authorityGeneration": self._authority_generation,
            "highWaterCommitmentSha256":
            high_water_commitment_sha256,
            "highWaterSequence": sequence,
            "previousHighWaterCommitmentSha256":
            previous_high_water_commitment_sha256,
        }
        payload = {
            "apiVersion": RECEIPT_PAYLOAD_VERSION,
            "consumeRequestSha256": consume_request_sha256,
            "consumedAtUnix": consumed_at_unix,
            "expiresAtUnix": expires_at_unix,
            "finalExternalVerifierChallengeConsumed": False,
            "finalExternalVerifierChallengeConsumptionRequired": True,
            "nonceAuthorityAssuranceSha256":
            self._authority_assurance_sha256,
            "nonceAuthorityState": authority_state,
            "nonceAuthorityStateSha256":
            sha256_json(authority_state),
            "nonceAuthorityVerifierStateAuthorizationSha256":
            bindings[
                "nonceAuthorityVerifierStateAuthorizationSha256"
            ],
            "nonceConsumption": consumption,
            "nonceConsumptionSha256": nonce_consumption_sha256,
            "nonceSha256": bindings["nonceSha256"],
            "previousReceiptSha256": previous_receipt_sha256,
            "producerChannelChallengeBase64url": bindings[
                "producerChannelChallengeBase64url"
            ],
            "producerEphemeralKeySha256": bindings[
                "producerEphemeralKeySha256"
            ],
            "producerInvocationSha256": bindings[
                "producerInvocationSha256"
            ],
            "receiptIssuedAtUnix": consumed_at_unix,
            "requestBodySha256": bindings["requestBodySha256"],
            "sequence": sequence,
            "signerChannelBindingSha256":
            self._signer.channel_binding_sha256,
            "storeIdentitySha256": self._identity_sha256,
            "tlsBindingSha256": bindings["tlsBindingSha256"],
            "transactionIdBase64url": transaction_id,
        }
        receipt = signed_receipt_envelope(
            payload=payload,
            signer=self._signer,
        )
        receipt_sha256 = sha256_json(receipt)
        try:
            updated = self._connection.execute(
                """
                UPDATE nonce_records
                SET state = 'consumed',
                    consumed_at_unix_decimal = ?,
                    sequence_decimal = ?,
                    transaction_id_base64url = ?,
                    consume_request_sha256 = ?,
                    authority_high_water_commitment_sha256 = ?,
                    previous_authority_high_water_commitment_sha256 = ?,
                    previous_receipt_sha256 = ?,
                    receipt_sha256 = ?,
                    receipt_json = ?
                WHERE nonce_sha256 = ? AND state = 'reserved'
                """,
                (
                    str(consumed_at_unix),
                    _sequence_decimal(sequence),
                    transaction_id,
                    consume_request_sha256,
                    high_water_commitment_sha256,
                    previous_high_water_commitment_sha256,
                    previous_receipt_sha256,
                    receipt_sha256,
                    canonical_json_bytes(receipt),
                    bindings["nonceSha256"],
                ),
            )
            if updated.rowcount != 1:
                raise NonceRequestError("replayRejected")
            next_update = self._connection.execute(
                """
                UPDATE nonce_metadata
                SET value = ?
                WHERE key = 'nextSequence' AND value = ?
                """,
                (str(next_sequence), str(sequence)),
            )
            exhaustion_update = self._connection.execute(
                """
                UPDATE nonce_metadata
                SET value = ?
                WHERE key = 'sequenceExhausted' AND value = 'false'
                """,
                (next_sequence_exhausted,),
            )
            head_update = self._connection.execute(
                """
                UPDATE nonce_metadata
                SET value = ?
                WHERE key = 'lastReceiptSha256' AND value = ?
                """,
                (
                    receipt_sha256,
                    previous_receipt_sha256 or "",
                ),
            )
            authority_head_update = self._connection.execute(
                """
                UPDATE nonce_metadata
                SET value = ?
                WHERE key = 'lastAuthorityHighWaterCommitmentSha256'
                    AND value = ?
                """,
                (
                    high_water_commitment_sha256,
                    previous_high_water_commitment_sha256,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise NonceRequestError("replayRejected") from exc
        except sqlite3.Error as exc:
            raise NonceInvariantError(
                "nonce consumption update failed"
            ) from exc
        if (
            next_update.rowcount != 1
            or exhaustion_update.rowcount != 1
            or head_update.rowcount != 1
            or authority_head_update.rowcount != 1
        ):
            raise NonceInvariantError(
                "nonce sequence terminal marker, receipt, or authority head CAS failed"
            )
        return {
            "consumption": consumption,
            "receipt": receipt,
            "receiptSha256": receipt_sha256,
        }

    def _recover_exact_consumption(
        self,
        *,
        row: sqlite3.Row,
        bindings: Mapping[str, str],
        consume_request_sha256: str,
        transaction_id_base64url: str,
    ) -> dict[str, Any]:
        if (
            row["state"] != "consumed"
            or row["consume_request_sha256"] != consume_request_sha256
            or row["transaction_id_base64url"]
            != transaction_id_base64url
            or row["nonce_sha256"] != bindings["nonceSha256"]
            or row["request_body_sha256"]
            != bindings["requestBodySha256"]
            or row["tls_binding_sha256"]
            != bindings["tlsBindingSha256"]
            or row["producer_invocation_sha256"]
            != bindings["producerInvocationSha256"]
            or row["producer_ephemeral_key_sha256"]
            != bindings["producerEphemeralKeySha256"]
            or row["producer_channel_challenge_base64url"]
            != bindings["producerChannelChallengeBase64url"]
            or row["verifier_state_authorization_sha256"]
            != bindings[
                "nonceAuthorityVerifierStateAuthorizationSha256"
            ]
            or row["receipt_json"] is None
            or row["receipt_sha256"] is None
            or row["sequence_decimal"] is None
        ):
            raise NonceRequestError("replayRejected")
        retained = self._validate_stored_receipt(
            row,
            expected_sequence=_canonical_decimal(
                row["sequence_decimal"],
                "retained nonce sequence",
                minimum=1,
            ),
            expected_previous_receipt_sha256=(
                row["previous_receipt_sha256"]
            ),
            expected_previous_high_water_commitment_sha256=(
                row[
                    "previous_authority_high_water_commitment_sha256"
                ]
            ),
        )
        payload = retained["payload"]
        if (
            payload["consumeRequestSha256"]
            != consume_request_sha256
            or payload["transactionIdBase64url"]
            != transaction_id_base64url
        ):
            raise NonceRequestError("replayRejected")
        return {
            "consumption": payload["nonceConsumption"],
            "receipt": retained["document"],
            "receiptSha256": retained["receiptSha256"],
        }

    def _consumption_response(
        self,
        result: Mapping[str, Any],
    ) -> dict[str, Any]:
        consumption = result["consumption"]
        receipt = result["receipt"]
        return {
            "apiVersion": CONSUME_RESPONSE_VERSION,
            "nonceAuthorityAssurance":
            self._authority_assurance,
            "nonceAuthorityAssuranceSha256":
            self._authority_assurance_sha256,
            "nonceConsumption": consumption,
            "nonceConsumptionReceipt": receipt,
            "nonceConsumptionReceiptSha256": result[
                "receiptSha256"
            ],
            "nonceConsumptionSha256": sha256_json(consumption),
            "nonceStoreIdentitySha256": self._identity_sha256,
        }


def _validate_database_descriptor(value: Any) -> dict[str, Any]:
    database = closed_object(
        value,
        {
            "allowCreate",
            "path",
        },
        "nonce database descriptor",
    )
    if not isinstance(database["allowCreate"], bool):
        raise NonceServiceError(
            "nonce database allowCreate must be boolean"
        )
    require_absolute_normal_path(
        database["path"],
        "nonce database path",
    )
    return database


def load_single_fd_document(
    fd: int,
    *,
    label: str,
    max_bytes: int = 262_144,
) -> dict[str, Any]:
    channel = BoundedCanonicalJsonLineFd(fd, max_bytes=max_bytes)
    try:
        document = channel.read(
            label=label,
            deadline=(
                time.monotonic() + FD_OPERATION_TIMEOUT_SECONDS
            ),
        )
    except (NonceChannelDeadlineError, NonceFrameError) as exc:
        raise NonceInvariantError(f"{label} is malformed") from exc
    if document is None:
        raise NonceInvariantError(f"{label} is missing")
    if channel.has_buffered_data:
        raise NonceInvariantError(
            f"{label} has buffered trailing data"
        )
    return document


def load_descriptor(fd: int) -> dict[str, Any]:
    descriptor = load_single_fd_document(
        fd,
        label="nonce service descriptor",
    )
    try:
        descriptor = closed_object(
            descriptor,
            {
                "apiVersion",
                "database",
                "expectedSignerPeerPid",
                "maxRecords",
                "maxRequestBytes",
                "maxResponseBytes",
                "maxSignerFrameBytes",
                "maxTtlSeconds",
                "nonceStoreIdentity",
                "nonceStoreIdentitySha256",
                "releaseIdentitySha256",
                "requestFd",
                "responseFd",
                "signerRequestFd",
                "signerResponseFd",
            },
            "nonce service descriptor",
        )
        if descriptor["apiVersion"] != DESCRIPTOR_VERSION:
            raise NonceServiceError(
                "nonce service descriptor version is invalid"
            )
        _validate_database_descriptor(descriptor["database"])
        validate_nonce_store_identity(
            descriptor["nonceStoreIdentity"]
        )
        require_sha256(
            descriptor["nonceStoreIdentitySha256"],
            "descriptor nonce store identity",
        )
        require_sha256(
            descriptor["releaseIdentitySha256"],
            "descriptor release identity",
        )
        for field in (
            "maxRecords",
            "maxRequestBytes",
            "maxResponseBytes",
            "maxSignerFrameBytes",
            "maxTtlSeconds",
        ):
            require_u64(descriptor[field], field, minimum=1)
        if descriptor["maxRecords"] > MAX_RECORDS:
            raise NonceServiceError(
                "descriptor nonce record bound is too large"
            )
        if descriptor["maxTtlSeconds"] > MAX_TTL_SECONDS:
            raise NonceServiceError(
                "descriptor nonce ttl bound is too large"
            )
        for field in (
            "maxRequestBytes",
            "maxResponseBytes",
            "maxSignerFrameBytes",
        ):
            if descriptor[field] > MAX_FRAME_BYTES:
                raise NonceServiceError(
                    f"descriptor {field} exceeds the frame maximum"
                )
        if descriptor["maxResponseBytes"] < 512:
            raise NonceServiceError(
                "descriptor response frame bound is too small"
            )
        fd_fields = (
            "requestFd",
            "responseFd",
            "signerRequestFd",
            "signerResponseFd",
        )
        fds = [
            require_u64(
                descriptor[field],
                field,
                minimum=3,
                maximum=PID_MAX,
            )
            for field in fd_fields
        ]
        if len(set(fds)) != len(fds):
            raise NonceServiceError(
                "all nonce service retained FDs must be distinct"
            )
        require_u64(
            descriptor["expectedSignerPeerPid"],
            "expected signer peer pid",
            minimum=1,
            maximum=PID_MAX,
        )
    except NonceServiceError as exc:
        raise NonceInvariantError(
            "nonce service descriptor is invalid"
        ) from exc
    return descriptor


def load_immutable_release_config(
    fd: int,
    *,
    expected_config_sha256: str,
    expected_release_identity_sha256: str,
    expected_release_signing_key_id: str,
    expected_release_signing_key_spki_base64url: str,
    expected_release_signing_key_spki_sha256: str,
    expected_signing_key_id: str,
    expected_signing_key_spki_sha256: str,
) -> dict[str, Any]:
    config = load_single_fd_document(
        fd,
        label="nonce immutable release config",
    )
    try:
        return validate_immutable_release_config(
            config,
            expected_config_sha256=expected_config_sha256,
            expected_release_identity_sha256=(
                expected_release_identity_sha256
            ),
            expected_release_signing_key_id=(
                expected_release_signing_key_id
            ),
            expected_release_signing_key_spki_base64url=(
                expected_release_signing_key_spki_base64url
            ),
            expected_release_signing_key_spki_sha256=(
                expected_release_signing_key_spki_sha256
            ),
            expected_signing_key_id=expected_signing_key_id,
            expected_signing_key_spki_sha256=(
                expected_signing_key_spki_sha256
            ),
        )
    except NonceServiceError as exc:
        raise NonceInvariantError(
            "nonce immutable release config is invalid"
        ) from exc


def _closed_error_response(
    *,
    error_code: str,
    request_sha256: str | None,
) -> dict[str, Any]:
    if error_code not in {
        "capacityExceeded",
        "invalidRequest",
        "replayRejected",
    }:
        raise NonceInvariantError(
            "nonce error response code is invalid"
        )
    if request_sha256 is not None:
        require_sha256(
            request_sha256,
            "failed nonce request digest",
        )
    return {
        "apiVersion": ERROR_RESPONSE_VERSION,
        "errorCode": error_code,
        "requestSha256": request_sha256,
        "retryable": False,
    }


def serve(
    descriptor: Mapping[str, Any],
    *,
    immutable_config: Mapping[str, Any],
    immutable_config_sha256: str,
) -> None:
    if (
        descriptor["releaseIdentitySha256"]
        != immutable_config["releaseIdentitySha256"]
        or descriptor["nonceStoreIdentitySha256"]
        != immutable_config["nonceStoreIdentitySha256"]
    ):
        raise NonceInvariantError(
            "nonce descriptor and immutable release config pins differ"
        )
    store_identity = descriptor["nonceStoreIdentity"]
    if sha256_json(store_identity) != descriptor[
        "nonceStoreIdentitySha256"
    ]:
        raise NonceInvariantError(
            "nonce descriptor store identity digest mismatch"
        )
    request_peer = _inspect_service_channel_fd(
        descriptor["requestFd"],
        label="nonce request channel",
    )
    response_peer = _inspect_service_channel_fd(
        descriptor["responseFd"],
        label="nonce response channel",
    )
    if request_peer != response_peer:
        raise NonceInvariantError(
            "nonce request and response channels terminate at different peers"
        )

    signer = AuthenticatedFdEd25519Signer(
        request_fd=descriptor["signerRequestFd"],
        response_fd=descriptor["signerResponseFd"],
        expected_peer_pid=descriptor["expectedSignerPeerPid"],
        immutable_config=immutable_config,
        immutable_config_sha256=immutable_config_sha256,
        max_frame_bytes=descriptor["maxSignerFrameBytes"],
    )
    database = descriptor["database"]
    store = DurableNonceStore(
        database_path=database["path"],
        store_identity=store_identity,
        expected_store_identity_sha256=descriptor[
            "nonceStoreIdentitySha256"
        ],
        allow_create=database["allowCreate"],
        signer=signer,
        release_identity_sha256=descriptor[
            "releaseIdentitySha256"
        ],
        max_records=descriptor["maxRecords"],
        max_ttl_seconds=descriptor["maxTtlSeconds"],
    )
    requests = BoundedCanonicalJsonLineFd(
        descriptor["requestFd"],
        max_bytes=descriptor["maxRequestBytes"],
    )
    responses = BoundedCanonicalJsonLineFd(
        descriptor["responseFd"],
        max_bytes=descriptor["maxResponseBytes"],
    )
    # Both sockets stay bidirectional only for repeatable launcher admission.
    # Normal nonce traffic retains request-in/response-out directionality.
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
                        raise NonceInvariantError(
                            "nonce service channel became invalid"
                        )
                    if not events & (select.POLLIN | select.POLLHUP):
                        continue
                    if ready_fd == descriptor["responseFd"]:
                        response_ready = response_control_open
                    elif ready_fd == descriptor["requestFd"]:
                        request_ready = True
                    else:
                        raise NonceInvariantError(
                            "nonce poll returned an unknown descriptor"
                        )
            if response_ready:
                operation_deadline = (
                    time.monotonic()
                    + FD_OPERATION_TIMEOUT_SECONDS
                )
                try:
                    control = responses.read(
                        label="nonce response-channel challenge",
                        deadline=operation_deadline,
                    )
                except NonceChannelDeadlineError:
                    continue
                except NonceFrameError as exc:
                    raise NonceInvariantError(
                        "nonce response-channel challenge is malformed"
                    ) from exc
                if control is None:
                    response_control_open = False
                    poller.unregister(descriptor["responseFd"])
                else:
                    try:
                        responses.write(
                            _service_challenge_response(
                                control,
                                direction="service-to-producer",
                                role="nonceResponse",
                            ),
                            deadline=operation_deadline,
                            label=(
                                "nonce response-channel challenge "
                                "response"
                            ),
                        )
                    except NonceChannelDeadlineError:
                        continue
                continue
            if not request_ready:
                continue
            operation_deadline = (
                time.monotonic() + FD_OPERATION_TIMEOUT_SECONDS
            )
            try:
                request = requests.read(
                    label="nonce service request",
                    deadline=operation_deadline,
                )
            except NonceChannelDeadlineError:
                continue
            except NonceFrameError:
                try:
                    responses.write(
                        _closed_error_response(
                            error_code="invalidRequest",
                            request_sha256=None,
                        ),
                        deadline=operation_deadline,
                        label="invalid nonce request response",
                    )
                except NonceChannelDeadlineError:
                    pass
                continue
            if request is None:
                return
            if request.get("apiVersion") == SERVICE_CHALLENGE_VERSION:
                try:
                    requests.write(
                        _service_challenge_response(
                            request,
                            direction="producer-to-service",
                            role="nonceRequest",
                        ),
                        deadline=operation_deadline,
                        label=(
                            "nonce request-channel challenge "
                            "response"
                        ),
                    )
                except NonceChannelDeadlineError:
                    pass
                continue
            request_sha256 = sha256_json(request)
            signer.begin_operation(operation_deadline)
            try:
                api_version = request.get("apiVersion")
                if api_version == RESERVE_REQUEST_VERSION:
                    response = store.reserve(request)
                elif api_version == CONSUME_REQUEST_VERSION:
                    response = store.consume(request)
                elif api_version == CONSUME_ONCE_REQUEST_VERSION:
                    response = store.consume_once(request)
                elif api_version == STATUS_REQUEST_VERSION:
                    response = store.transaction_status(request)
                else:
                    raise NonceRequestError("invalidRequest")
            except NonceRequestError as exc:
                response = _closed_error_response(
                    error_code=exc.error_code,
                    request_sha256=request_sha256,
                )
            finally:
                signer.end_operation()
            try:
                responses.write(
                    response,
                    deadline=operation_deadline,
                    label="nonce service response",
                )
            except NonceChannelDeadlineError:
                continue
    finally:
        store.close()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Serve the non-production SQLite attestation nonce reference"
        )
    )
    parser.add_argument("--descriptor-fd", required=True, type=int)
    parser.add_argument(
        "--immutable-release-config-fd",
        required=True,
        type=int,
    )
    parser.add_argument(
        "--expected-immutable-release-config-sha256",
        required=True,
    )
    parser.add_argument(
        "--expected-release-identity-sha256",
        required=True,
    )
    parser.add_argument(
        "--expected-release-signing-key-id",
        required=True,
    )
    parser.add_argument(
        "--expected-release-signing-key-spki-base64url",
        required=True,
    )
    parser.add_argument(
        "--expected-release-signing-key-spki-sha256",
        required=True,
    )
    parser.add_argument(
        "--expected-nonce-store-signing-key-id",
        required=True,
    )
    parser.add_argument(
        "--expected-nonce-store-signing-key-spki-sha256",
        required=True,
    )
    args = parser.parse_args()

    expected_config_sha256 = require_sha256(
        args.expected_immutable_release_config_sha256,
        "expected nonce immutable release config",
    )
    expected_release_identity_sha256 = require_sha256(
        args.expected_release_identity_sha256,
        "expected nonce release identity",
    )
    expected_release_signing_key_id = require_sha256(
        args.expected_release_signing_key_id,
        "expected release signing key id",
    )
    expected_release_signing_key_spki_base64url = (
        args.expected_release_signing_key_spki_base64url
    )
    decode_base64url(
        expected_release_signing_key_spki_base64url,
        expected_bytes=44,
        label="expected release signing SPKI",
    )
    expected_release_signing_key_spki_sha256 = require_sha256(
        args.expected_release_signing_key_spki_sha256,
        "expected release signing SPKI digest",
    )
    expected_signing_key_id = require_sha256(
        args.expected_nonce_store_signing_key_id,
        "expected nonce signing key id",
    )
    expected_signing_key_spki_sha256 = require_sha256(
        args.expected_nonce_store_signing_key_spki_sha256,
        "expected nonce signing SPKI",
    )
    immutable_config = load_immutable_release_config(
        args.immutable_release_config_fd,
        expected_config_sha256=expected_config_sha256,
        expected_release_identity_sha256=(
            expected_release_identity_sha256
        ),
        expected_release_signing_key_id=(
            expected_release_signing_key_id
        ),
        expected_release_signing_key_spki_base64url=(
            expected_release_signing_key_spki_base64url
        ),
        expected_release_signing_key_spki_sha256=(
            expected_release_signing_key_spki_sha256
        ),
        expected_signing_key_id=expected_signing_key_id,
        expected_signing_key_spki_sha256=(
            expected_signing_key_spki_sha256
        ),
    )
    descriptor = load_descriptor(args.descriptor_fd)
    if descriptor["releaseIdentitySha256"] != (
        expected_release_identity_sha256
    ):
        raise NonceInvariantError(
            "descriptor release identity is not independently pinned"
        )
    serve(
        descriptor,
        immutable_config=immutable_config,
        immutable_config_sha256=expected_config_sha256,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
