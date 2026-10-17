#!/usr/bin/env python3
from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import hmac
import ipaddress
import json
import os
import select
import socket
import sqlite3
import ssl
import stat
import sys
import threading
import time
from urllib.parse import urlsplit
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Callable, Mapping

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(_SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIRECTORY))

import launch_authorization as protocol  # noqa: E402


REGISTRY_API_VERSION = "catchplate.launchAuthorityReleaseRegistry/v2"
REGISTRY_KIND = "ProductionLaunchAuthorityReleaseRegistry"
AUTHORIZATION_PATH = "/v1/launch-authorizations"
REQUEST_CONTENT_TYPE = "application/catchplate.launch-authorization-request+json"
RESPONSE_CONTENT_TYPE = "application/catchplate.launch-authorization+json"
MAX_REQUEST_BYTES = 16 * 1024
MAX_REGISTRY_BYTES = 8 * 1024 * 1024
MAX_REGISTRY_ENTRIES = 4096
MAX_KEY_BYTES = 16 * 1024
MAX_TLS_MATERIAL_BYTES = 1024 * 1024
MAX_WITNESS_RESPONSE_BYTES = 64 * 1024
MAX_WITNESS_RESPONSE_HEADER_BYTES = 16 * 1024
MAX_WITNESS_RESPONSE_HEADER_COUNT = 32
MAX_WITNESS_RESPONSE_LINE_BYTES = 4096
WITNESS_REQUEST_CONTENT_TYPE = (
    "application/catchplate.launch-authority-witness-transition-request+json"
)
WITNESS_RESPONSE_CONTENT_TYPE = (
    "application/catchplate.launch-authority-witness-transition+json"
)
REGISTRY_OBSERVATION_REQUEST_CONTENT_TYPE = (
    "application/catchplate.launch-authority-registry-observation-request+json"
)
REGISTRY_OBSERVATION_RESPONSE_CONTENT_TYPE = (
    "application/catchplate.launch-authority-registry-observation+json"
)
DEFAULT_VALIDITY_SECONDS = 30
DEFAULT_CONNECTION_DEADLINE_SECONDS = 5.0
DEFAULT_HANDSHAKE_DEADLINE_SECONDS = 2.0
DEFAULT_MAX_HANDSHAKES = 32
DEFAULT_MAX_HANDSHAKES_PER_IP = 2
DEFAULT_MAX_ISSUANCE_WORKERS = 16
DEFAULT_MAX_ISSUANCE_WORKERS_PER_IP = 4
LEDGER_SCHEMA_VERSION = 7
EXTERNAL_ANTI_ROLLBACK_REQUIREMENT = (
    "The native launcher is trusted-host readiness only. Every readiness authorization "
    "requires an online, independently signed, exact predecessor/successor transition "
    "from an external monotonic witness; local registry and ledger files never establish "
    "rollback resistance by themselves."
)
NETWORK_ADMISSION_BOUNDARY = (
    "Source CIDR admission uses the direct TCP peer address and is defense in depth; "
    "production must also enforce equivalent upstream firewall/routing policy and "
    "must not place an address-rewriting proxy in front of the authority."
)
TRUST_CONFIGURATION_LIFECYCLE = (
    "Launch trust is an in-memory startup snapshot; on-disk changes are not "
    "dynamically observed and overlapping listeners or in-process reload are "
    "forbidden. To rotate trust, stop accepting traffic, drain active requests, "
    "restart with the original retained authority and witness trust to recover and "
    "terminalize every nonterminal issuance, stop that process, then start one "
    "replacement listener with the rotated configuration."
)
_LISTENER_LEASE_GUARD = threading.Lock()
_PROCESS_LISTENER_LEASES: dict[int, Path] = {}

_REGISTRY_FIELDS = frozenset({"apiVersion", "kind", "generation", "releases"})
_ENTRY_BINDING_FIELDS = (
    "deploymentAudience",
    "deploymentIdentitySha256",
    "releaseSequence",
    "rollbackEpoch",
    "manifestSha256",
    "nonceRollbackAssuranceContractSha256",
    "nonceRollbackAssurancePinsSha256",
    "releaseProvenanceSha256",
    "provenanceDigest",
    "sourceTreeDigest",
    "launcherSha256",
    "reproducibleBuildVerificationSha256",
    "authorizationScope",
    "freshnessAuthority",
    "launchAuthorityWitnessKeyId",
    "launchAuthorityWitnessIdentitySha256",
    "launchAuthorityWitnessAdministrativeDomainSha256",
    "launchAuthorityWitnessStoreAssuranceSha256",
)
_CONTENT_TUPLE_FIELDS = (
    "manifestSha256",
    "nonceRollbackAssuranceContractSha256",
    "nonceRollbackAssurancePinsSha256",
    "releaseProvenanceSha256",
    "provenanceDigest",
    "sourceTreeDigest",
    "launcherSha256",
    "reproducibleBuildVerificationSha256",
    "authorizationScope",
    "freshnessAuthority",
    "launchAuthorityWitnessKeyId",
    "launchAuthorityWitnessIdentitySha256",
    "launchAuthorityWitnessAdministrativeDomainSha256",
    "launchAuthorityWitnessStoreAssuranceSha256",
)
_RELAY_CERTIFICATE_FIELD = "relayClientCertificateSha256"
_ENTRY_FIELDS = frozenset(
    (*_ENTRY_BINDING_FIELDS, _RELAY_CERTIFICATE_FIELD, "enabled", "revoked")
)


class AuthorityConfigurationError(ValueError):
    pass


class AuthorityWitnessExchangeError(AuthorityConfigurationError):
    def __init__(
        self,
        message: str,
        *,
        phase: str,
        outcome_unknown: bool,
    ) -> None:
        super().__init__(message)
        self.phase = phase
        self.outcome_unknown = outcome_unknown


class AuthorityError(ValueError):
    def __init__(self, code: str, message: str, *, http_status: int) -> None:
        super().__init__(message)
        self.code = code
        self.http_status = http_status


class AuthorityOperationAborted(AuthorityConfigurationError):
    def __init__(
        self,
        reason: str,
        phase: str,
        *,
        outcome_unknown: bool = False,
    ) -> None:
        super().__init__(f"authority operation stopped during {phase}: {reason}")
        self.reason = reason
        self.phase = phase
        self.outcome_unknown = outcome_unknown


class AuthorityOperationContext:
    """Cooperative cancellation for one ingress-bounded issuance operation."""

    def __init__(self, deadline: float) -> None:
        if isinstance(deadline, bool) or not isinstance(deadline, float):
            raise AuthorityConfigurationError(
                "authority operation deadline must be a monotonic float"
            )
        self.deadline = deadline
        self._cancelled = threading.Event()
        self._lock = threading.Lock()
        self._reason: str | None = None
        self._abort_callbacks: dict[int, Callable[[], None]] = {}
        self._next_callback_id = 1

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    @property
    def reason(self) -> str:
        with self._lock:
            return self._reason or "operation_cancelled"

    def remaining_seconds(self, phase: str) -> float:
        if self._cancelled.is_set():
            raise AuthorityOperationAborted(self.reason, phase)
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            self.cancel("deadline_expired")
            raise AuthorityOperationAborted("deadline_expired", phase)
        if self._cancelled.is_set():
            raise AuthorityOperationAborted(self.reason, phase)
        return remaining

    def assert_active(
        self,
        phase: str,
        *,
        outcome_unknown: bool = False,
    ) -> None:
        try:
            self.remaining_seconds(phase)
        except AuthorityOperationAborted as exc:
            if outcome_unknown and not exc.outcome_unknown:
                raise AuthorityOperationAborted(
                    exc.reason,
                    phase,
                    outcome_unknown=True,
                ) from exc
            raise

    def checkpoint(self, phase: str) -> None:
        try:
            self.assert_active(phase)
        except AuthorityOperationAborted as exc:
            code = (
                "AUTHORITY_OPERATION_DEADLINE_EXPIRED"
                if exc.reason == "deadline_expired"
                else "AUTHORITY_CLIENT_DISCONNECTED"
            )
            raise AuthorityError(
                code,
                "authority operation stopped before mutable work could continue",
                http_status=408,
            ) from exc

    def cancel(self, reason: str) -> None:
        callbacks: tuple[Callable[[], None], ...] = ()
        with self._lock:
            if self._cancelled.is_set():
                return
            self._reason = reason
            self._cancelled.set()
            callbacks = tuple(self._abort_callbacks.values())
        for callback in callbacks:
            try:
                callback()
            except Exception:
                pass

    def register_abort(self, callback: Callable[[], None]) -> int | None:
        invoke_now = False
        callback_id: int | None = None
        with self._lock:
            if self._cancelled.is_set():
                invoke_now = True
            else:
                callback_id = self._next_callback_id
                self._next_callback_id += 1
                self._abort_callbacks[callback_id] = callback
        if invoke_now:
            try:
                callback()
            except Exception:
                pass
        return callback_id

    def unregister_abort(self, callback_id: int | None) -> None:
        if callback_id is None:
            return
        with self._lock:
            self._abort_callbacks.pop(callback_id, None)


def _sha256_domain(domain: bytes, value: Any) -> str:
    return (
        "sha256:"
        + hashlib.sha256(domain + protocol.canonical_json_bytes(value)).hexdigest()
    )


def _exact_object(value: Any, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AuthorityConfigurationError(f"{label} must be an object")
    if any(type(key) is not str for key in value):
        raise AuthorityConfigurationError(f"{label} contains a non-string key")
    actual = set(value)
    missing = sorted(fields - actual)
    unknown = sorted(actual - fields)
    if missing:
        raise AuthorityConfigurationError(f"{label} is missing fields: {missing}")
    if unknown:
        raise AuthorityConfigurationError(f"{label} contains unknown fields: {unknown}")
    return value


def _parse_strict_json(raw: bytes, *, label: str, max_bytes: int) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > max_bytes:
        raise AuthorityConfigurationError(
            f"{label} byte length is outside the accepted bound"
        )
    if raw.startswith(b"\xef\xbb\xbf"):
        raise AuthorityConfigurationError(f"{label} must not contain a UTF-8 BOM")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise AuthorityConfigurationError(f"{label} must be strict UTF-8 JSON") from exc

    def parse_integer(value: str) -> int:
        parsed = int(value, 10)
        if abs(parsed) > protocol.MAX_SAFE_INTEGER:
            raise AuthorityConfigurationError(f"{label} contains an unsafe integer")
        return parsed

    def reject_float(_: str) -> float:
        raise AuthorityConfigurationError(
            f"{label} must not contain floating-point values"
        )

    def reject_constant(_: str) -> object:
        raise AuthorityConfigurationError(f"{label} must not contain non-finite values")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        parsed: dict[str, Any] = {}
        for key, value in pairs:
            if key in parsed:
                raise AuthorityConfigurationError(
                    f"{label} contains duplicate object key: {key}"
                )
            parsed[key] = value
        return parsed

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=reject_duplicates,
            parse_int=parse_integer,
            parse_float=reject_float,
            parse_constant=reject_constant,
        )
    except AuthorityConfigurationError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise AuthorityConfigurationError(f"{label} is invalid JSON") from exc
    if not isinstance(parsed, dict):
        raise AuthorityConfigurationError(f"{label} must be a JSON object")
    try:
        protocol.canonical_json_bytes(parsed)
    except protocol.LaunchAuthorizationError as exc:
        raise AuthorityConfigurationError(
            f"{label} contains invalid JSON values"
        ) from exc
    return parsed


def _stable_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _validate_trusted_ancestors(path: Path, *, label: str) -> None:
    candidate = Path(path.anchor)
    for component in path.parts[1:-1]:
        candidate /= component
        try:
            metadata = os.lstat(candidate)
        except OSError as exc:
            raise AuthorityConfigurationError(
                f"cannot inspect {label} ancestor: {candidate}"
            ) from exc
        if not stat.S_ISDIR(metadata.st_mode):
            raise AuthorityConfigurationError(
                f"{label} ancestor must be a real directory: {candidate}"
            )
        mode = stat.S_IMODE(metadata.st_mode)
        root_sticky_directory = (
            metadata.st_uid == 0 and bool(mode & stat.S_ISVTX) and bool(mode & 0o022)
        )
        if metadata.st_uid not in {0, os.geteuid()} or (
            mode & 0o022 and not root_sticky_directory
        ):
            raise AuthorityConfigurationError(
                f"{label} ancestor is not trusted: {candidate}"
            )


def _read_stable_regular_file(
    path: Path,
    *,
    label: str,
    max_bytes: int,
    owner_only: bool,
) -> bytes:
    path = Path(path)
    if not path.is_absolute():
        raise AuthorityConfigurationError(f"{label} path must be absolute")
    _validate_trusted_ancestors(path, label=label)
    try:
        before_path = os.lstat(path)
    except OSError as exc:
        raise AuthorityConfigurationError(f"cannot inspect {label}: {path}") from exc
    if not stat.S_ISREG(before_path.st_mode):
        raise AuthorityConfigurationError(f"{label} must be a regular non-symlink file")
    if before_path.st_nlink != 1:
        raise AuthorityConfigurationError(
            f"{label} must have exactly one filesystem link"
        )
    mode = stat.S_IMODE(before_path.st_mode)
    if before_path.st_uid not in {0, os.geteuid()}:
        raise AuthorityConfigurationError(f"{label} must have a trusted owner")
    if owner_only:
        if before_path.st_uid != os.geteuid():
            raise AuthorityConfigurationError(
                f"{label} must be owned by the authority user"
            )
        if mode not in {0o400, 0o600}:
            raise AuthorityConfigurationError(f"{label} mode must be 0400 or 0600")
    elif mode & 0o022:
        raise AuthorityConfigurationError(f"{label} must not be group/world writable")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AuthorityConfigurationError(
            f"cannot open {label} securely: {path}"
        ) from exc
    try:
        before = os.fstat(descriptor)
        if _stable_identity(before) != _stable_identity(before_path):
            raise AuthorityConfigurationError(f"{label} changed before it was read")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise AuthorityConfigurationError(f"{label} exceeds {max_bytes} bytes")
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    current = os.stat(path, follow_symlinks=False)
    if _stable_identity(before) != _stable_identity(after) or _stable_identity(
        after
    ) != _stable_identity(current):
        raise AuthorityConfigurationError(f"{label} changed while it was read")
    _validate_trusted_ancestors(path, label=label)
    return b"".join(chunks)


def _require_sha256_digest(value: Any, *, label: str) -> str:
    if not (
        type(value) is str
        and value.startswith("sha256:")
        and len(value) == 71
        and all(character in "0123456789abcdef" for character in value[7:])
    ):
        raise AuthorityConfigurationError(f"{label} must be sha256:<64 lowercase hex>")
    return value


def der_certificate_sha256(certificate_der: bytes) -> str:
    if type(certificate_der) is not bytes or not certificate_der:
        raise AuthorityConfigurationError("peer certificate DER bytes are invalid")
    return "sha256:" + hashlib.sha256(certificate_der).hexdigest()


def _request_binding(request: Mapping[str, Any]) -> dict[str, Any]:
    return {field: request[field] for field in _ENTRY_BINDING_FIELDS}


def _content_tuple(binding: Mapping[str, Any]) -> dict[str, Any]:
    return {field: binding[field] for field in _CONTENT_TUPLE_FIELDS}


def _authorization_id(request_sha256: str, witness_challenge: str) -> str:
    return hashlib.sha256(
        b"catchplate.launchAuthorityAuthorizationId/v2\0"
        + request_sha256.encode("ascii")
        + b"\0"
        + witness_challenge.encode("ascii")
    ).hexdigest()


def _witness_operation_sha256(
    request: Mapping[str, Any],
    *,
    request_sha256: str,
    authorization_id: str,
    registry_generation: int,
    registry_sha256: str,
    authority_key_id: str,
) -> str:
    return _sha256_domain(
        b"catchplate.launchAuthorityWitnessOperation/v2\0",
        {
            "authorizationId": authorization_id,
            "authorizationScope": request["authorizationScope"],
            "authorityKeyId": authority_key_id,
            "challenge": request["launchAuthorityWitnessChallenge"],
            "deploymentAudience": request["deploymentAudience"],
            "deploymentIdentitySha256": request["deploymentIdentitySha256"],
            "globalRoleRegistrySha256": request["globalRoleRegistrySha256"],
            "globalRoleRegistryPinsSha256": request[
                "globalRoleRegistryPinsSha256"
            ],
            "launchAttemptJournalDomain": request[
                "launchAttemptJournalDomain"
            ],
            "launchAttemptRecoveryIdentitySha256": request[
                "launchAttemptRecoveryIdentitySha256"
            ],
            "operation": protocol.WITNESS_OPERATION,
            "operationId": request["launcherNonce"],
            "registryGeneration": registry_generation,
            "registrySha256": registry_sha256,
            "releaseSequence": request["releaseSequence"],
            "requestSha256": request_sha256,
            "rollbackEpoch": request["rollbackEpoch"],
            "storeAssuranceSha256": request[
                "launchAuthorityWitnessStoreAssuranceSha256"
            ],
            "witnessAdministrativeDomainSha256": request[
                "launchAuthorityWitnessAdministrativeDomainSha256"
            ],
            "witnessIdentitySha256": request[
                "launchAuthorityWitnessIdentitySha256"
            ],
            "witnessKeyId": request["launchAuthorityWitnessKeyId"],
        },
    )


@dataclass(frozen=True, slots=True)
class ReleaseEntry:
    binding: Mapping[str, Any]
    enabled: bool
    revoked: bool
    binding_sha256: str
    content_tuple_sha256: str
    relay_client_certificate_sha256: str

    @classmethod
    def from_document(cls, value: Any, *, index: int) -> ReleaseEntry:
        entry = _exact_object(value, _ENTRY_FIELDS, f"release registry entry {index}")
        if type(entry["enabled"]) is not bool or type(entry["revoked"]) is not bool:
            raise AuthorityConfigurationError(
                f"release registry entry {index} status fields must be booleans"
            )
        relay_client_certificate_sha256 = _require_sha256_digest(
            entry[_RELAY_CERTIFICATE_FIELD],
            label=(f"release registry entry {index} relay client certificate digest"),
        )
        binding = {field: entry[field] for field in _ENTRY_BINDING_FIELDS}
        synthetic_roles = {
            role: (
                "sha256:"
                + hashlib.sha256(
                    ("synthetic-" + role).encode("ascii")
                ).hexdigest()
            )
            for role in protocol.GLOBAL_ROLE_REGISTRY_REQUIRED_ROLES
        }
        synthetic_roles["launchAuthorityWitness"] = binding[
            "launchAuthorityWitnessKeyId"
        ]
        synthetic_global_role_registry = (
            protocol.build_launch_global_role_registry(synthetic_roles)
        )
        synthetic_request = {
            "apiVersion": protocol.REQUEST_API_VERSION,
            "kind": protocol.REQUEST_KIND,
            "launcherNonce": "0" * 64,
            "bootIdSha256": "sha256:" + "0" * 64,
            "launchAuthorityWitnessChallenge": "0" * 64,
            "globalRoleRegistry": synthetic_global_role_registry,
            "globalRoleRegistrySha256": (
                protocol.launch_global_role_registry_sha256(
                    synthetic_global_role_registry
                )
            ),
            "globalRoleRegistryPinsSha256": "sha256:" + "1" * 64,
            "launchAttemptJournalDomain": (
                protocol.LAUNCH_ATTEMPT_JOURNAL_DOMAIN
            ),
            **binding,
        }
        synthetic_request["launchAttemptRecoveryIdentitySha256"] = (
            protocol.launch_attempt_recovery_identity_sha256(
                synthetic_request
            )
        )
        try:
            protocol.validate_launch_authorization_request(synthetic_request)
        except protocol.LaunchAuthorizationError as exc:
            raise AuthorityConfigurationError(
                f"release registry entry {index} has invalid bindings: {exc}"
            ) from exc
        return cls(
            binding=binding,
            enabled=entry["enabled"],
            revoked=entry["revoked"],
            binding_sha256=_sha256_domain(
                b"catchplate.launchAuthorityRegistryBinding/v2\0", binding
            ),
            content_tuple_sha256=_sha256_domain(
                b"catchplate.launchAuthorityReleaseTuple/v2\0",
                _content_tuple(binding),
            ),
            relay_client_certificate_sha256=relay_client_certificate_sha256,
        )


@dataclass(frozen=True, slots=True)
class ReleaseRegistry:
    generation: int
    registry_sha256: str
    entries: Mapping[str, ReleaseEntry]

    @classmethod
    def from_bytes(cls, raw: bytes) -> ReleaseRegistry:
        document = _parse_strict_json(
            raw, label="release registry", max_bytes=MAX_REGISTRY_BYTES
        )
        registry = _exact_object(document, _REGISTRY_FIELDS, "release registry")
        if not hmac.compare_digest(protocol.canonical_json_bytes(document), raw):
            raise AuthorityConfigurationError(
                "release registry must use canonical compact sorted ASCII JSON bytes"
            )
        if registry["apiVersion"] != REGISTRY_API_VERSION:
            raise AuthorityConfigurationError("release registry apiVersion is invalid")
        if registry["kind"] != REGISTRY_KIND:
            raise AuthorityConfigurationError("release registry kind is invalid")
        generation = registry["generation"]
        if (
            type(generation) is not int
            or not 1 <= generation <= protocol.MAX_SAFE_INTEGER
        ):
            raise AuthorityConfigurationError(
                "release registry generation must be a positive safe integer"
            )
        releases = registry["releases"]
        if (
            not isinstance(releases, list)
            or not releases
            or len(releases) > MAX_REGISTRY_ENTRIES
        ):
            raise AuthorityConfigurationError(
                f"release registry must contain 1 to {MAX_REGISTRY_ENTRIES} entries"
            )
        entries: dict[str, ReleaseEntry] = {}
        for index, value in enumerate(releases):
            entry = ReleaseEntry.from_document(value, index=index)
            if entry.binding_sha256 in entries:
                raise AuthorityConfigurationError(
                    f"release registry contains duplicate binding at entry {index}"
                )
            entries[entry.binding_sha256] = entry
        return cls(
            generation=generation,
            registry_sha256="sha256:" + hashlib.sha256(raw).hexdigest(),
            entries=entries,
        )

    @classmethod
    def from_path(cls, path: Path) -> ReleaseRegistry:
        return cls.from_bytes(
            _read_stable_regular_file(
                Path(path),
                label="release registry",
                max_bytes=MAX_REGISTRY_BYTES,
                owner_only=False,
            )
        )

    def lookup(
        self, request: Mapping[str, Any], *, peer_certificate_sha256: str
    ) -> ReleaseEntry:
        binding = _request_binding(request)
        binding_sha256 = _sha256_domain(
            b"catchplate.launchAuthorityRegistryBinding/v2\0", binding
        )
        entry = self.entries.get(binding_sha256)
        if entry is None:
            raise AuthorityError(
                "UNKNOWN_RELEASE",
                "launch request does not match a pre-enrolled release",
                http_status=403,
            )
        if not hmac.compare_digest(
            entry.relay_client_certificate_sha256, peer_certificate_sha256
        ):
            raise AuthorityError(
                "RELAY_CLIENT_CERTIFICATE_MISMATCH",
                "release is not enrolled for the authenticated relay certificate",
                http_status=403,
            )
        if entry.revoked:
            raise AuthorityError(
                "RELEASE_REVOKED", "pre-enrolled release is revoked", http_status=403
            )
        if not entry.enabled:
            raise AuthorityError(
                "RELEASE_DISABLED", "pre-enrolled release is disabled", http_status=403
            )
        return entry


@dataclass(frozen=True, slots=True)
class AuthoritySigningKey:
    private_key: Ed25519PrivateKey
    key_id: str


@dataclass(frozen=True, slots=True)
class AuthorityTrustSnapshot:
    authority_key_id: str
    authority_public_key_spki_der: bytes
    witness_signing_key_id: str
    witness_signing_public_key_spki_der: bytes
    witness_identity_sha256: str
    witness_administrative_domain_sha256: str
    witness_store_assurance_sha256: str
    witness_store_assurance_key_id: str
    witness_tls_spki_sha256: str
    global_role_registry_sha256: str
    global_role_registry_pins_sha256: str


def load_authority_signing_key(
    path: Path, *, expected_key_id: str
) -> AuthoritySigningKey:
    if not (
        type(expected_key_id) is str
        and expected_key_id.startswith("sha256:")
        and len(expected_key_id) == 71
        and all(character in "0123456789abcdef" for character in expected_key_id[7:])
    ):
        raise AuthorityConfigurationError(
            "configured authority key ID must be sha256:<64 lowercase hex>"
        )
    raw = _read_stable_regular_file(
        Path(path),
        label="authority private key",
        max_bytes=MAX_KEY_BYTES,
        owner_only=True,
    )
    try:
        if raw.startswith(b"-----BEGIN PRIVATE KEY-----\n"):
            loaded = serialization.load_pem_private_key(raw, password=None)
        else:
            loaded = serialization.load_der_private_key(raw, password=None)
    except (TypeError, ValueError) as exc:
        raise AuthorityConfigurationError(
            "authority private key must be unencrypted PKCS8"
        ) from exc
    if not isinstance(loaded, Ed25519PrivateKey):
        raise AuthorityConfigurationError("authority private key must be Ed25519")
    encoding = (
        serialization.Encoding.PEM
        if raw.startswith(b"-----BEGIN PRIVATE KEY-----\n")
        else serialization.Encoding.DER
    )
    canonical_pkcs8 = loaded.private_bytes(
        encoding,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    if not hmac.compare_digest(raw, canonical_pkcs8):
        raise AuthorityConfigurationError(
            "authority private key must use canonical unencrypted PKCS8 bytes"
        )
    spki = loaded.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    actual_key_id = protocol.spki_key_id(spki)
    if not hmac.compare_digest(actual_key_id, expected_key_id):
        raise AuthorityConfigurationError(
            "authority private key does not match the configured key ID"
        )
    return AuthoritySigningKey(private_key=loaded, key_id=actual_key_id)


_WITNESS_HTTP_TOKEN_BYTES = frozenset(
    b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)
_WITNESS_HTTP_ALLOWED_RESPONSE_HEADERS = frozenset(
    {
        "connection",
        "content-length",
        "content-type",
        "date",
        "server",
    }
)


def _parse_witness_http_response_head(
    raw_head: bytes,
    *,
    expected_content_type: str,
) -> int:
    if (
        type(raw_head) is not bytes
        or not raw_head.endswith(b"\r\n\r\n")
        or len(raw_head) > MAX_WITNESS_RESPONSE_HEADER_BYTES
    ):
        raise AuthorityConfigurationError(
            "monotonic witness response headers are malformed or oversized"
        )
    lines = raw_head[:-4].split(b"\r\n")
    if not lines or len(lines) - 1 > MAX_WITNESS_RESPONSE_HEADER_COUNT:
        raise AuthorityConfigurationError(
            "monotonic witness response header count is invalid"
        )
    status_line = lines[0]
    status_parts = status_line.split(b" ", 2)
    if (
        len(status_line) > MAX_WITNESS_RESPONSE_LINE_BYTES
        or len(status_parts) != 3
        or status_parts[0] != b"HTTP/1.1"
        or len(status_parts[1]) != 3
        or not status_parts[1].isdigit()
        or not status_parts[2]
        or len(status_parts[2]) > 128
        or any(byte < 0x20 or byte > 0x7E for byte in status_parts[2])
    ):
        raise AuthorityConfigurationError(
            "monotonic witness returned an invalid HTTP/1.1 status line"
        )
    if status_parts[1] != b"200":
        raise AuthorityConfigurationError(
            "monotonic witness rejected the exact transition"
        )

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if (
            not line
            or len(line) > MAX_WITNESS_RESPONSE_LINE_BYTES
            or line[:1] in {b" ", b"\t"}
        ):
            raise AuthorityConfigurationError(
                "monotonic witness returned an invalid HTTP/1.1 header line"
            )
        raw_name, separator, raw_value = line.partition(b":")
        if (
            separator != b":"
            or not raw_name
            or any(byte not in _WITNESS_HTTP_TOKEN_BYTES for byte in raw_name)
            or not raw_value.startswith(b" ")
        ):
            raise AuthorityConfigurationError(
                "monotonic witness returned an invalid HTTP/1.1 header"
            )
        value_bytes = raw_value[1:]
        if (
            not value_bytes
            or value_bytes != value_bytes.strip(b" ")
            or any(byte < 0x20 or byte > 0x7E for byte in value_bytes)
        ):
            raise AuthorityConfigurationError(
                "monotonic witness returned a non-canonical HTTP/1.1 header value"
            )
        name = raw_name.decode("ascii").lower()
        if name in headers:
            raise AuthorityConfigurationError(
                "monotonic witness returned a duplicate HTTP/1.1 header"
            )
        if name in {"transfer-encoding", "content-encoding"}:
            raise AuthorityConfigurationError(
                "monotonic witness response encoding is forbidden"
            )
        if name not in _WITNESS_HTTP_ALLOWED_RESPONSE_HEADERS:
            raise AuthorityConfigurationError(
                "monotonic witness returned an unsupported HTTP/1.1 header"
            )
        headers[name] = value_bytes.decode("ascii")

    if headers.get("connection", "").lower() != "close":
        raise AuthorityConfigurationError(
            "monotonic witness response must require connection close"
        )
    if headers.get("content-type") != expected_content_type:
        raise AuthorityConfigurationError(
            "monotonic witness returned an unexpected content type"
        )
    raw_length = headers.get("content-length")
    if (
        raw_length is None
        or not raw_length.isdigit()
        or len(raw_length) > len(str(MAX_WITNESS_RESPONSE_BYTES))
        or str(int(raw_length)) != raw_length
        or not 1 <= int(raw_length) <= MAX_WITNESS_RESPONSE_BYTES
    ):
        raise AuthorityConfigurationError(
            "monotonic witness response length is invalid"
        )
    return int(raw_length)


class LiteralIpv4TlsTransport:
    """Deadline-bounded TLS transport that cannot enter hostname resolution."""

    def __init__(
        self,
        address: str,
        port: int,
        *,
        context: ssl.SSLContext,
        remaining_seconds: Callable[[str], float],
    ) -> None:
        try:
            numeric_address = ipaddress.ip_address(address)
        except ValueError as exc:
            raise AuthorityConfigurationError(
                "monotonic witness transport address must be a canonical literal IPv4 address"
            ) from exc
        if (
            not isinstance(numeric_address, ipaddress.IPv4Address)
            or str(numeric_address) != address
            or type(port) is not int
            or not 1 <= port <= 65535
        ):
            raise AuthorityConfigurationError(
                "monotonic witness transport requires canonical literal IPv4 and a valid TCP port"
            )
        self._literal_address = str(numeric_address)
        self.port = port
        self._context = context
        self._remaining_seconds = remaining_seconds
        self._socket_lock = threading.Lock()
        self._socket: socket.socket | ssl.SSLSocket | None = None
        self._closed = False

    def _install_socket(self, candidate: socket.socket | ssl.SSLSocket) -> None:
        with self._socket_lock:
            if self._closed:
                try:
                    candidate.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                candidate.close()
                raise OSError("monotonic witness transport was cancelled")
            self._socket = candidate

    def _current_socket(self) -> socket.socket | ssl.SSLSocket:
        with self._socket_lock:
            current = self._socket
            if self._closed or current is None:
                raise OSError("monotonic witness transport is closed")
            return current

    def abort(self) -> None:
        with self._socket_lock:
            self._closed = True
            current = self._socket
            self._socket = None
            if current is None:
                return
            try:
                current.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                current.close()
            except OSError:
                pass

    def close(self) -> None:
        self.abort()

    def _wait(
        self,
        current: socket.socket | ssl.SSLSocket,
        *,
        readable: bool,
        writable: bool,
        phase: str,
    ) -> None:
        while True:
            timeout = self._remaining_seconds(phase)
            try:
                ready_read, ready_write, exceptional = select.select(
                    [current] if readable else [],
                    [current] if writable else [],
                    [current],
                    timeout,
                )
            except InterruptedError:
                continue
            if exceptional:
                raise OSError("monotonic witness transport became exceptional")
            if (readable and ready_read) or (writable and ready_write):
                return
            raise TimeoutError(f"{phase} exceeded the absolute deadline")

    def connect(self) -> ssl.SSLSocket:
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_socket.set_inheritable(False)
        raw_socket.setblocking(False)
        self._install_socket(raw_socket)
        connect_result = raw_socket.connect_ex(
            (self._literal_address, self.port)
        )
        if connect_result not in {
            0,
            errno.EINPROGRESS,
            errno.EWOULDBLOCK,
            errno.EALREADY,
            errno.EINTR,
        }:
            raise OSError(
                connect_result,
                "monotonic witness literal-IP TCP connection failed",
            )
        if connect_result != 0:
            self._wait(
                raw_socket,
                readable=False,
                writable=True,
                phase="witness literal-IP TCP connection",
            )
            socket_error = raw_socket.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if socket_error != 0:
                raise OSError(
                    socket_error,
                    "monotonic witness literal-IP TCP connection failed",
                )

        self._remaining_seconds("witness TLS socket wrapping")
        with self._socket_lock:
            if self._closed or self._socket is not raw_socket:
                raise OSError("monotonic witness transport was cancelled")
            tls_socket = self._context.wrap_socket(
                raw_socket,
                server_hostname=self._literal_address,
                do_handshake_on_connect=False,
                suppress_ragged_eofs=False,
            )
            tls_socket.setblocking(False)
            self._socket = tls_socket
        while True:
            self._remaining_seconds("witness TLS handshake")
            try:
                tls_socket.do_handshake()
                return tls_socket
            except ssl.SSLWantReadError:
                self._wait(
                    tls_socket,
                    readable=True,
                    writable=False,
                    phase="witness TLS handshake",
                )
            except ssl.SSLWantWriteError:
                self._wait(
                    tls_socket,
                    readable=False,
                    writable=True,
                    phase="witness TLS handshake",
                )

    def send_all(self, data: bytes, *, phase: str) -> None:
        current = self._current_socket()
        if not isinstance(current, ssl.SSLSocket):
            raise OSError("monotonic witness TLS socket is not established")
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            self._remaining_seconds(phase)
            try:
                sent = current.send(view[offset:])
            except ssl.SSLWantReadError:
                self._wait(
                    current,
                    readable=True,
                    writable=False,
                    phase=phase,
                )
                continue
            except ssl.SSLWantWriteError:
                self._wait(
                    current,
                    readable=False,
                    writable=True,
                    phase=phase,
                )
                continue
            if sent <= 0:
                raise OSError("monotonic witness request send made no progress")
            offset += sent

    def receive_some(self, maximum: int, *, phase: str) -> bytes:
        if not 1 <= maximum <= MAX_WITNESS_RESPONSE_HEADER_BYTES:
            raise AuthorityConfigurationError(
                "monotonic witness receive bound is invalid"
            )
        current = self._current_socket()
        if not isinstance(current, ssl.SSLSocket):
            raise OSError("monotonic witness TLS socket is not established")
        while True:
            self._remaining_seconds(phase)
            try:
                return current.recv(maximum)
            except ssl.SSLZeroReturnError:
                return b""
            except ssl.SSLWantReadError:
                self._wait(
                    current,
                    readable=True,
                    writable=False,
                    phase=phase,
                )
            except ssl.SSLWantWriteError:
                self._wait(
                    current,
                    readable=False,
                    writable=True,
                    phase=phase,
                )

    def complete_tls_close(self) -> None:
        current = self._current_socket()
        if not isinstance(current, ssl.SSLSocket):
            raise OSError("monotonic witness TLS socket is not established")
        while True:
            self._remaining_seconds("witness TLS close confirmation")
            try:
                unwrapped = current.unwrap()
            except ssl.SSLWantReadError:
                self._wait(
                    current,
                    readable=True,
                    writable=False,
                    phase="witness TLS close confirmation",
                )
                continue
            except ssl.SSLWantWriteError:
                self._wait(
                    current,
                    readable=False,
                    writable=True,
                    phase="witness TLS close confirmation",
                )
                continue
            unwrapped.setblocking(False)
            with self._socket_lock:
                if self._closed or self._socket is not current:
                    try:
                        unwrapped.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    unwrapped.close()
                    raise OSError(
                        "monotonic witness transport was cancelled during TLS close"
                    )
                self._socket = unwrapped
            return

    def receive_http_response(self, *, expected_content_type: str) -> bytes:
        buffered = bytearray()
        header_end = -1
        while header_end < 0:
            if len(buffered) >= MAX_WITNESS_RESPONSE_HEADER_BYTES:
                raise AuthorityConfigurationError(
                    "monotonic witness response headers exceed the byte limit"
                )
            received = self.receive_some(
                min(
                    4096,
                    MAX_WITNESS_RESPONSE_HEADER_BYTES - len(buffered),
                ),
                phase="witness HTTP/1.1 response headers",
            )
            if not received:
                raise AuthorityConfigurationError(
                    "monotonic witness closed before complete response headers"
                )
            buffered.extend(received)
            marker = buffered.find(b"\r\n\r\n")
            if marker >= 0:
                header_end = marker + 4

        content_length = _parse_witness_http_response_head(
            bytes(buffered[:header_end]),
            expected_content_type=expected_content_type,
        )
        body = bytearray(buffered[header_end:])
        if len(body) > content_length:
            raise AuthorityConfigurationError(
                "monotonic witness appended bytes after the declared response body"
            )
        while len(body) < content_length:
            received = self.receive_some(
                min(4096, content_length - len(body)),
                phase="witness HTTP/1.1 response body",
            )
            if not received:
                raise AuthorityConfigurationError(
                    "monotonic witness closed before the declared response body"
                )
            body.extend(received)

        trailing = self.receive_some(
            1,
            phase="witness HTTP/1.1 response TLS close",
        )
        if trailing:
            raise AuthorityConfigurationError(
                "monotonic witness appended bytes after the declared response body"
            )
        self.complete_tls_close()
        return bytes(body)


class LaunchAuthorityMonotonicWitnessClient:
    """Online external witness client for exact readiness state transitions.

    The witness is deliberately outside the local ledger/registry failure domain.
    Its signed transition is a readiness authorization prerequisite, not TEE proof.
    """

    def __init__(
        self,
        *,
        url: str,
        ca_certificate: Path,
        client_certificate: Path,
        client_private_key: Path,
        expected_tls_spki_sha256: str,
        signing_public_key: Path,
        expected_signing_key_id: str,
        witness_identity_sha256: str,
        administrative_domain_sha256: str,
        store_assurance_sha256: str,
        store_assurance_key_id: str,
        timeout_seconds: float = 1.0,
    ) -> None:
        parsed = urlsplit(url)
        try:
            parsed_port = parsed.port
            numeric_address = ipaddress.ip_address(parsed.hostname or "")
        except ValueError as exc:
            raise AuthorityConfigurationError(
                "monotonic witness URL authority must be a canonical literal IPv4 address"
            ) from exc
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or not isinstance(numeric_address, ipaddress.IPv4Address)
            or str(numeric_address) != parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path != "/v1/launch-authority-transitions"
        ):
            raise AuthorityConfigurationError(
                "monotonic witness URL must be an exact HTTPS canonical-literal-IPv4 "
                "/v1/launch-authority-transitions endpoint"
            )
        effective_port = 443 if parsed_port is None else parsed_port
        if not 1 <= effective_port <= 65535:
            raise AuthorityConfigurationError(
                "monotonic witness URL port is outside the valid TCP range"
            )
        canonical_authority = (
            parsed.hostname
            if effective_port == 443
            else f"{parsed.hostname}:{effective_port}"
        )
        canonical_url = (
            f"https://{canonical_authority}/v1/launch-authority-transitions"
        )
        if parsed.netloc != canonical_authority or url != canonical_url:
            raise AuthorityConfigurationError(
                "monotonic witness URL is not canonical"
            )
        if type(timeout_seconds) not in {int, float} or not 0.05 <= timeout_seconds <= 30:
            raise AuthorityConfigurationError(
                "monotonic witness timeout must be between 0.05 and 30 seconds"
            )
        self.url = url
        self.host = str(numeric_address)
        self.port = effective_port
        self.path = parsed.path
        self.registry_observation_path = (
            "/v1/launch-authority-registry-observations"
        )
        self.expected_tls_spki_sha256 = _require_sha256_digest(
            expected_tls_spki_sha256, label="monotonic witness TLS SPKI digest"
        )
        self.witness_identity_sha256 = _require_sha256_digest(
            witness_identity_sha256, label="monotonic witness identity digest"
        )
        self.administrative_domain_sha256 = _require_sha256_digest(
            administrative_domain_sha256,
            label="monotonic witness administrative-domain digest",
        )
        self.store_assurance_sha256 = _require_sha256_digest(
            store_assurance_sha256,
            label="monotonic witness store-assurance digest",
        )
        self.store_assurance_key_id = _require_sha256_digest(
            store_assurance_key_id,
            label="monotonic witness store-assurance signing key ID",
        )
        self.timeout_seconds = float(timeout_seconds)

        signing_key_bytes = _read_stable_regular_file(
            signing_public_key,
            label="monotonic witness signing public key",
            max_bytes=MAX_KEY_BYTES,
            owner_only=False,
        )
        try:
            loaded_signing_key = serialization.load_pem_public_key(signing_key_bytes)
        except (TypeError, ValueError) as exc:
            raise AuthorityConfigurationError(
                "monotonic witness signing public key must be canonical Ed25519 PEM"
            ) from exc
        canonical_signing_key = loaded_signing_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if not hmac.compare_digest(signing_key_bytes, canonical_signing_key):
            raise AuthorityConfigurationError(
                "monotonic witness signing public key PEM is not canonical"
            )
        self.signing_public_key_spki_der = loaded_signing_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        try:
            self.signing_key_id = protocol.spki_key_id(
                self.signing_public_key_spki_der
            )
        except protocol.LaunchAuthorizationError as exc:
            raise AuthorityConfigurationError(
                "monotonic witness signing public key must be Ed25519"
            ) from exc
        if not hmac.compare_digest(self.signing_key_id, expected_signing_key_id):
            raise AuthorityConfigurationError(
                "monotonic witness signing key does not match its independent pin"
            )

        ca_bytes = _read_stable_regular_file(
            ca_certificate,
            label="monotonic witness CA certificate",
            max_bytes=MAX_TLS_MATERIAL_BYTES,
            owner_only=False,
        )
        client_certificate_bytes = _read_stable_regular_file(
            client_certificate,
            label="monotonic witness client certificate",
            max_bytes=MAX_TLS_MATERIAL_BYTES,
            owner_only=False,
        )
        client_private_key_bytes = _read_stable_regular_file(
            client_private_key,
            label="monotonic witness client private key",
            max_bytes=MAX_TLS_MATERIAL_BYTES,
            owner_only=True,
        )
        self.context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.context.maximum_version = ssl.TLSVersion.TLSv1_3
        self.context.check_hostname = True
        try:
            ca_data: str | bytes = ca_bytes.decode("ascii")
        except UnicodeDecodeError:
            ca_data = ca_bytes
        self.context.load_verify_locations(cadata=ca_data)
        self.context.load_cert_chain(
            certfile=str(client_certificate), keyfile=str(client_private_key)
        )
        for path, label, expected, owner_only in (
            (ca_certificate, "monotonic witness CA certificate", ca_bytes, False),
            (
                client_certificate,
                "monotonic witness client certificate",
                client_certificate_bytes,
                False,
            ),
            (
                client_private_key,
                "monotonic witness client private key",
                client_private_key_bytes,
                True,
            ),
        ):
            current = _read_stable_regular_file(
                path,
                label=label,
                max_bytes=MAX_TLS_MATERIAL_BYTES,
                owner_only=owner_only,
            )
            if not hmac.compare_digest(current, expected):
                raise AuthorityConfigurationError(
                    f"{label} changed while the witness TLS context was created"
                )

    def _post_json(
        self,
        request: Mapping[str, Any],
        *,
        path: str,
        request_content_type: str,
        response_content_type: str,
        operation_context: AuthorityOperationContext,
    ) -> bytes:
        body = protocol.canonical_json_bytes(dict(request))
        operation_context.assert_active("witness connection setup")
        local_deadline = min(
            operation_context.deadline,
            time.monotonic() + self.timeout_seconds,
        )
        def remaining_seconds(phase: str) -> float:
            return min(
                _remaining_deadline_seconds(local_deadline),
                operation_context.remaining_seconds(phase),
            )

        transport = LiteralIpv4TlsTransport(
            self.host,
            self.port,
            context=self.context,
            remaining_seconds=remaining_seconds,
        )
        request_may_have_been_dispatched = False
        abort_callback_id = operation_context.register_abort(transport.abort)
        try:
            operation_context.assert_active("witness connection")
            tls_socket = transport.connect()
            operation_context.assert_active("witness TLS identity verification")
            peer_certificate = tls_socket.getpeercert(binary_form=True)
            if not peer_certificate:
                raise AuthorityConfigurationError(
                    "monotonic witness did not present a peer certificate"
                )
            peer_key = x509.load_der_x509_certificate(
                peer_certificate
            ).public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            peer_spki_sha256 = "sha256:" + hashlib.sha256(peer_key).hexdigest()
            if not hmac.compare_digest(
                peer_spki_sha256, self.expected_tls_spki_sha256
            ):
                raise AuthorityConfigurationError(
                    "monotonic witness TLS SPKI does not match its independent pin"
                )
            authority = (
                self.host
                if self.port == 443
                else f"{self.host}:{self.port}"
            )
            request_head = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {authority}\r\n"
                f"Accept: {response_content_type}\r\n"
                f"Content-Type: {request_content_type}\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode("ascii")
            operation_context.assert_active("witness request dispatch")
            request_may_have_been_dispatched = True
            transport.send_all(
                request_head + body,
                phase="witness HTTP/1.1 request dispatch",
            )
            operation_context.assert_active(
                "witness response wait",
                outcome_unknown=True,
            )
            raw = transport.receive_http_response(
                expected_content_type=response_content_type,
            )
            operation_context.assert_active(
                "witness response completion",
                outcome_unknown=True,
            )
            return raw
        except AuthorityOperationAborted as exc:
            if request_may_have_been_dispatched and not exc.outcome_unknown:
                raise AuthorityOperationAborted(
                    exc.reason,
                    exc.phase,
                    outcome_unknown=True,
                ) from exc
            raise
        except AuthorityWitnessExchangeError as exc:
            if request_may_have_been_dispatched and not exc.outcome_unknown:
                raise AuthorityWitnessExchangeError(
                    "online monotonic witness exchange outcome is unknown after "
                    "request dispatch",
                    phase=exc.phase,
                    outcome_unknown=True,
                ) from exc
            raise
        except Exception as exc:
            if operation_context.cancelled:
                raise AuthorityOperationAborted(
                    operation_context.reason,
                    "witness transport",
                    outcome_unknown=request_may_have_been_dispatched,
                ) from exc
            if request_may_have_been_dispatched:
                raise AuthorityWitnessExchangeError(
                    "online monotonic witness exchange outcome is unknown after "
                    "request dispatch",
                    phase="witness exchange",
                    outcome_unknown=True,
                ) from exc
            raise AuthorityWitnessExchangeError(
                "online monotonic witness exchange failed before request dispatch",
                phase="witness exchange",
                outcome_unknown=False,
            ) from exc
        finally:
            operation_context.unregister_abort(abort_callback_id)
            transport.close()

    def observe_registry_head(
        self,
        request: Mapping[str, Any],
        *,
        operation_context: AuthorityOperationContext,
    ) -> dict[str, Any]:
        validated_request = protocol.validate_registry_observation_request(request)
        try:
            raw = self._post_json(
                validated_request,
                path=self.registry_observation_path,
                request_content_type=REGISTRY_OBSERVATION_REQUEST_CONTENT_TYPE,
                response_content_type=REGISTRY_OBSERVATION_RESPONSE_CONTENT_TYPE,
                operation_context=operation_context,
            )
            operation_context.assert_active(
                "registry witness response verification",
                outcome_unknown=True,
            )
            return protocol.verify_registry_observation(
                protocol.require_canonical_json_bytes(
                    raw, label="launch-authority registry observation"
                ),
                witness_public_key_spki_der=self.signing_public_key_spki_der,
                expected_witness_key_id=self.signing_key_id,
                expected_request=validated_request,
            )
        except (AuthorityWitnessExchangeError, AuthorityOperationAborted):
            raise
        except Exception as exc:
            raise AuthorityWitnessExchangeError(
                "registry witness response verification failed after request dispatch",
                phase="registry witness response verification",
                outcome_unknown=True,
            ) from exc

    def authorize_transition(
        self,
        request: Mapping[str, Any],
        *,
        operation_context: AuthorityOperationContext,
    ) -> dict[str, Any]:
        validated_request = protocol.validate_launch_authority_witness_request(
            request
        )
        try:
            raw = self._post_json(
                validated_request,
                path=self.path,
                request_content_type=WITNESS_REQUEST_CONTENT_TYPE,
                response_content_type=WITNESS_RESPONSE_CONTENT_TYPE,
                operation_context=operation_context,
            )
            operation_context.assert_active(
                "witness transition response verification",
                outcome_unknown=True,
            )
            witness = protocol.validate_launch_authority_witness(
                protocol.require_canonical_json_bytes(
                    raw, label="launch-authority witness transition"
                )
            )
            operation_context.assert_active(
                "witness transition response verification completion",
                outcome_unknown=True,
            )
            return witness
        except (AuthorityWitnessExchangeError, AuthorityOperationAborted):
            raise
        except Exception as exc:
            raise AuthorityWitnessExchangeError(
                "witness transition response verification failed after request dispatch",
                phase="witness transition response verification",
                outcome_unknown=True,
            ) from exc

    def recover_transition(
        self,
        request: Mapping[str, Any],
        *,
        operation_context: AuthorityOperationContext,
    ) -> dict[str, Any]:
        """Recover one exact idempotent witness operation using the same wire request."""

        return self.authorize_transition(
            request,
            operation_context=operation_context,
        )


@dataclass(slots=True)
class LedgerSession:
    ledger: LaunchAuthorityLedger
    connection: sqlite3.Connection
    inode_identity: tuple[int, int]

    def assert_path_identity(self) -> None:
        current = self.ledger._validate_existing_file()
        if (current.st_dev, current.st_ino) != self.inode_identity:
            raise AuthorityConfigurationError(
                "authority ledger pathname was replaced during the operation"
            )


class LaunchAuthorityLedger:
    """Durable local state that still requires an external rollback witness.

    File ownership and SQLite integrity can reject deletion and malformed state, but
    cannot distinguish the current database from a correctly restored old snapshot.
    Deployments must externally checkpoint a monotonic representation of this state.
    """

    _SCHEMA_STATEMENTS = (
        """
        CREATE TABLE authorizations (
            launcher_nonce TEXT PRIMARY KEY,
            request_sha256 TEXT NOT NULL,
            request_bytes BLOB NOT NULL,
            envelope_bytes BLOB NOT NULL,
            authorization_id TEXT NOT NULL UNIQUE,
            deployment_audience TEXT NOT NULL,
            deployment_identity_sha256 TEXT NOT NULL,
            release_sequence INTEGER NOT NULL,
            rollback_epoch INTEGER NOT NULL,
            nonce_rollback_assurance_contract_sha256 TEXT NOT NULL,
            nonce_rollback_assurance_pins_sha256 TEXT NOT NULL,
            binding_sha256 TEXT NOT NULL,
            content_tuple_sha256 TEXT NOT NULL,
            relay_client_certificate_sha256 TEXT NOT NULL,
            witness_transition_sha256 TEXT NOT NULL,
            witness_checkpoint_sequence INTEGER NOT NULL,
            witness_predecessor_state_sha256 TEXT NOT NULL,
            witness_successor_state_sha256 TEXT NOT NULL,
            issued_at_unix_seconds INTEGER NOT NULL,
            expires_at_unix_seconds INTEGER NOT NULL
        ) STRICT
        """,
        """
        CREATE TABLE deployment_high_water (
            deployment_audience TEXT NOT NULL,
            deployment_identity_sha256 TEXT NOT NULL,
            release_sequence INTEGER NOT NULL,
            rollback_epoch INTEGER NOT NULL,
            nonce_rollback_assurance_contract_sha256 TEXT NOT NULL,
            nonce_rollback_assurance_pins_sha256 TEXT NOT NULL,
            witness_operation_sha256 TEXT NOT NULL,
            witness_challenge TEXT NOT NULL,
            binding_sha256 TEXT NOT NULL,
            content_tuple_sha256 TEXT NOT NULL,
            PRIMARY KEY (deployment_audience, deployment_identity_sha256)
        ) STRICT
        """,
        """
        CREATE TABLE seen_release_tuples (
            deployment_audience TEXT NOT NULL,
            deployment_identity_sha256 TEXT NOT NULL,
            content_tuple_sha256 TEXT NOT NULL,
            nonce_rollback_assurance_contract_sha256 TEXT NOT NULL,
            nonce_rollback_assurance_pins_sha256 TEXT NOT NULL,
            first_release_sequence INTEGER NOT NULL,
            last_release_sequence INTEGER NOT NULL,
            max_rollback_epoch INTEGER NOT NULL,
            PRIMARY KEY (
                deployment_audience,
                deployment_identity_sha256,
                content_tuple_sha256
            )
        ) STRICT
        """,
        """
        CREATE TABLE registry_state (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            generation INTEGER NOT NULL,
            registry_sha256 TEXT NOT NULL
        ) STRICT
        """,
        """
        CREATE TABLE revoked_release_bindings (
            binding_sha256 TEXT PRIMARY KEY,
            first_revoked_generation INTEGER NOT NULL
        ) STRICT
        """,
        """
        CREATE TABLE issuance_operations (
            operation_id TEXT PRIMARY KEY,
            state TEXT NOT NULL CHECK (
                state IN ('prepared', 'finalized', 'terminal')
            ),
            nonterminal_slot INTEGER UNIQUE,
            request_sha256 TEXT NOT NULL,
            request_bytes BLOB NOT NULL,
            authorization_id TEXT NOT NULL UNIQUE,
            relay_client_certificate_sha256 TEXT NOT NULL,
            registry_generation INTEGER NOT NULL,
            registry_sha256 TEXT NOT NULL,
            registry_bytes BLOB NOT NULL,
            binding_sha256 TEXT NOT NULL,
            content_tuple_sha256 TEXT NOT NULL,
            global_role_registry_sha256 TEXT NOT NULL,
            witness_operation_sha256 TEXT NOT NULL,
            witness_request_bytes BLOB NOT NULL,
            witness_predecessor_state_sha256 TEXT NOT NULL,
            witness_successor_state_sha256 TEXT NOT NULL,
            issued_at_unix_seconds INTEGER NOT NULL,
            expires_at_unix_seconds INTEGER NOT NULL,
            witness_transition_bytes BLOB,
            envelope_bytes BLOB,
            terminal_registry_generation INTEGER,
            terminal_registry_sha256 TEXT,
            terminal_observed_at_unix_seconds INTEGER,
            CHECK (
                (
                    state = 'prepared'
                    AND nonterminal_slot = 1
                    AND witness_transition_bytes IS NULL
                    AND envelope_bytes IS NULL
                    AND terminal_registry_generation IS NULL
                    AND terminal_registry_sha256 IS NULL
                    AND terminal_observed_at_unix_seconds IS NULL
                )
                OR
                (
                    state = 'finalized'
                    AND nonterminal_slot = 1
                    AND witness_transition_bytes IS NOT NULL
                    AND envelope_bytes IS NOT NULL
                    AND terminal_registry_generation IS NULL
                    AND terminal_registry_sha256 IS NULL
                    AND terminal_observed_at_unix_seconds IS NULL
                )
                OR
                (
                    state = 'terminal'
                    AND nonterminal_slot IS NULL
                    AND witness_transition_bytes IS NOT NULL
                    AND envelope_bytes IS NOT NULL
                    AND terminal_registry_generation IS NOT NULL
                    AND terminal_registry_sha256 IS NOT NULL
                    AND terminal_observed_at_unix_seconds IS NOT NULL
                )
            )
        ) STRICT
        """,
    )

    def __init__(
        self,
        path: Path,
        *,
        initialize: bool = False,
        busy_timeout_seconds: float = 5.0,
    ) -> None:
        self.path = Path(path)
        self.busy_timeout_seconds = busy_timeout_seconds
        self._created_identity: tuple[int, int] | None = None
        try:
            self._prepare_path(initialize=initialize)
            self._open_or_initialize(initialize=initialize)
        except Exception as exc:
            if initialize and self._created_identity is not None:
                try:
                    self._cleanup_failed_initialization()
                except OSError as cleanup_exc:
                    raise AuthorityConfigurationError(
                        "authority ledger initialization failed and cleanup was not "
                        "completed"
                    ) from cleanup_exc
            if isinstance(exc, AuthorityConfigurationError):
                raise
            if isinstance(exc, (sqlite3.Error, OSError)):
                raise AuthorityConfigurationError(
                    "authority ledger setup failed closed"
                ) from exc
            raise

    def _prepare_path(self, *, initialize: bool) -> None:
        if not self.path.is_absolute():
            raise AuthorityConfigurationError("ledger path must be absolute")
        _validate_trusted_ancestors(self.path, label="authority ledger")
        try:
            parent = os.lstat(self.path.parent)
        except OSError as exc:
            raise AuthorityConfigurationError(
                "ledger parent directory is unavailable"
            ) from exc
        if not stat.S_ISDIR(parent.st_mode):
            raise AuthorityConfigurationError("ledger parent must be a directory")
        if (
            parent.st_uid not in {0, os.geteuid()}
            or stat.S_IMODE(parent.st_mode) & 0o022
        ):
            raise AuthorityConfigurationError(
                "ledger parent must be trusted and not group/world writable"
            )
        try:
            metadata = os.lstat(self.path)
        except FileNotFoundError:
            if not initialize:
                raise AuthorityConfigurationError(
                    "authority ledger is missing; initialize it explicitly once with "
                    "--initialize-ledger"
                ) from None
            flags = (
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                descriptor = os.open(self.path, flags, 0o600)
            except OSError as exc:
                raise AuthorityConfigurationError(
                    "could not create authority ledger"
                ) from exc
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            metadata = os.lstat(self.path)
            self._created_identity = (metadata.st_dev, metadata.st_ino)
            self._fsync_parent_directory()
        else:
            if initialize:
                raise AuthorityConfigurationError(
                    "authority ledger already exists; initialization is one-time"
                )
        self._validate_ledger_metadata(metadata)

    @staticmethod
    def _validate_ledger_metadata(metadata: os.stat_result) -> None:
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise AuthorityConfigurationError(
                "ledger must be an owner-only regular non-symlink file"
            )

    def _fsync_parent_directory(self) -> None:
        flags = (
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
        )
        descriptor = os.open(self.path.parent, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _cleanup_failed_initialization(self) -> None:
        try:
            current = os.lstat(self.path)
        except FileNotFoundError:
            current = None
        if current is not None:
            if (current.st_dev, current.st_ino) != self._created_identity:
                raise OSError(
                    "refusing to clean up a replaced authority ledger pathname"
                )
            os.unlink(self.path)
        for suffix in ("-wal", "-shm"):
            try:
                os.unlink(str(self.path) + suffix)
            except FileNotFoundError:
                pass
        self._fsync_parent_directory()

    def _validate_existing_file(self) -> os.stat_result:
        _validate_trusted_ancestors(self.path, label="authority ledger")
        try:
            metadata = os.lstat(self.path)
        except FileNotFoundError:
            raise AuthorityConfigurationError(
                "authority ledger disappeared; refusing to recreate it"
            ) from None
        except OSError as exc:
            raise AuthorityConfigurationError(
                "authority ledger pathname could not be inspected"
            ) from exc
        self._validate_ledger_metadata(metadata)
        return metadata

    def connect(self) -> sqlite3.Connection:
        before = self._validate_existing_file()
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                self.path.as_uri() + "?mode=rw",
                uri=True,
                timeout=self.busy_timeout_seconds,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(
                f"PRAGMA busy_timeout={int(self.busy_timeout_seconds * 1000)}"
            )
            after = self._validate_existing_file()
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise AuthorityConfigurationError(
                    "authority ledger pathname changed while it was opened"
                )
            return connection
        except AuthorityConfigurationError:
            if connection is not None:
                try:
                    connection.close()
                except sqlite3.Error as exc:
                    raise AuthorityConfigurationError(
                        "authority ledger open failed and SQLite cleanup failed"
                    ) from exc
            raise
        except sqlite3.Error as exc:
            if connection is not None:
                try:
                    connection.close()
                except sqlite3.Error:
                    pass
            raise AuthorityConfigurationError(
                "authority ledger could not be opened and configured"
            ) from exc

    def open_session(self) -> LedgerSession:
        connection = self.connect()
        metadata = self._validate_existing_file()
        return LedgerSession(
            ledger=self,
            connection=connection,
            inode_identity=(metadata.st_dev, metadata.st_ino),
        )

    def acquire_listener_lease(self) -> int:
        lease_path = self.path.with_name(self.path.name + ".listener.lock")
        _validate_trusted_ancestors(lease_path, label="authority listener lease")
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor: int | None = None
        try:
            with _LISTENER_LEASE_GUARD:
                if lease_path in _PROCESS_LISTENER_LEASES.values():
                    raise AuthorityConfigurationError(
                        "another launch-authority listener owns this ledger; "
                        + TRUST_CONFIGURATION_LIFECYCLE
                    )
                descriptor = os.open(lease_path, flags, 0o600)
                os.fchmod(descriptor, 0o600)
                metadata = os.fstat(descriptor)
                current = os.stat(lease_path, follow_symlinks=False)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    raise AuthorityConfigurationError(
                        "authority listener lease must be a single-link regular file"
                    )
                if (
                    metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                ):
                    raise AuthorityConfigurationError(
                        "authority listener lease must be owned by the authority user "
                        "with mode 0600"
                    )
                if _stable_identity(metadata) != _stable_identity(current):
                    raise AuthorityConfigurationError(
                        "authority listener lease pathname changed while it was opened"
                    )
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    raise AuthorityConfigurationError(
                        "another launch-authority listener owns this ledger; "
                        + TRUST_CONFIGURATION_LIFECYCLE
                    ) from exc
                _PROCESS_LISTENER_LEASES[descriptor] = lease_path
            return descriptor
        except Exception:
            if descriptor is not None:
                os.close(descriptor)
            raise

    @staticmethod
    def release_listener_lease(descriptor: int) -> None:
        with _LISTENER_LEASE_GUARD:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                try:
                    os.close(descriptor)
                finally:
                    _PROCESS_LISTENER_LEASES.pop(descriptor, None)

    def _create_schema(self, connection: sqlite3.Connection) -> None:
        for statement in self._SCHEMA_STATEMENTS:
            connection.execute(statement)

    def _open_or_initialize(self, *, initialize: bool) -> None:
        session = self.open_session()
        connection = session.connection
        failure: Exception | None = None
        try:
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if not initialize:
                if version != LEDGER_SCHEMA_VERSION:
                    raise AuthorityConfigurationError(
                        "authority ledger is not initialized at the required schema "
                        f"version {LEDGER_SCHEMA_VERSION}"
                    )
                mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
                if str(mode).lower() != "wal":
                    raise AuthorityConfigurationError(
                        "authority ledger requires SQLite WAL mode"
                    )
                check = connection.execute("PRAGMA quick_check(1)").fetchone()[0]
                if check != "ok":
                    raise AuthorityConfigurationError(
                        "authority ledger failed SQLite integrity validation"
                    )
                session.assert_path_identity()
            else:
                if version != 0:
                    raise AuthorityConfigurationError(
                        "new authority ledger has unexpected existing schema state"
                    )
                mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
                if str(mode).lower() != "wal":
                    raise AuthorityConfigurationError(
                        "authority ledger requires SQLite WAL mode"
                    )
                connection.execute("BEGIN IMMEDIATE")
                self._create_schema(connection)
                connection.execute(f"PRAGMA user_version={LEDGER_SCHEMA_VERSION}")
                session.assert_path_identity()
                connection.commit()
                session.assert_path_identity()
        except Exception as exc:
            failure = exc
            try:
                connection.rollback()
            except sqlite3.Error as rollback_exc:
                failure = AuthorityConfigurationError(
                    "authority ledger setup failed and rollback failed"
                )
                failure.__cause__ = rollback_exc
        try:
            connection.close()
        except sqlite3.Error as close_exc:
            if failure is None:
                failure = AuthorityConfigurationError(
                    "authority ledger setup failed while closing SQLite"
                )
                failure.__cause__ = close_exc
        if failure is not None:
            if isinstance(failure, AuthorityConfigurationError):
                raise failure
            if isinstance(failure, (sqlite3.Error, OSError)):
                raise AuthorityConfigurationError(
                    "authority ledger setup failed closed"
                ) from failure
            raise failure

    def counts(self) -> dict[str, int]:
        connection = self.connect()
        try:
            return {
                table: int(
                    connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                )
                for table in (
                    "authorizations",
                    "deployment_high_water",
                    "seen_release_tuples",
                    "registry_state",
                    "revoked_release_bindings",
                    "issuance_operations",
                )
            }
        except sqlite3.Error as exc:
            raise AuthorityConfigurationError(
                "authority ledger counts could not be read"
            ) from exc
        finally:
            connection.close()

    def registry_generation(self) -> int | None:
        connection = self.connect()
        try:
            row = connection.execute(
                "SELECT generation FROM registry_state WHERE singleton = 1"
            ).fetchone()
            return None if row is None else int(row["generation"])
        except sqlite3.Error as exc:
            raise AuthorityConfigurationError(
                "authority registry generation could not be read"
            ) from exc
        finally:
            connection.close()


def _authority_state_sha256(connection: sqlite3.Connection) -> str:
    def rows(query: str) -> list[dict[str, Any]]:
        return [dict(row) for row in connection.execute(query).fetchall()]

    state = {
        "apiVersion": "catchplate.launchAuthorityState/v1",
        "ledgerSchemaVersion": LEDGER_SCHEMA_VERSION,
        "registryState": rows(
            """
            SELECT generation, registry_sha256
            FROM registry_state ORDER BY singleton
            """
        ),
        "deploymentHighWater": rows(
            """
            SELECT deployment_audience, deployment_identity_sha256,
                   release_sequence, rollback_epoch,
                   nonce_rollback_assurance_contract_sha256,
                   nonce_rollback_assurance_pins_sha256,
                   witness_operation_sha256, witness_challenge,
                   binding_sha256, content_tuple_sha256
            FROM deployment_high_water
            ORDER BY deployment_audience, deployment_identity_sha256
            """
        ),
        "seenReleaseTuples": rows(
            """
            SELECT deployment_audience, deployment_identity_sha256,
                   content_tuple_sha256,
                   nonce_rollback_assurance_contract_sha256,
                   nonce_rollback_assurance_pins_sha256,
                   first_release_sequence, last_release_sequence,
                   max_rollback_epoch
            FROM seen_release_tuples
            ORDER BY deployment_audience, deployment_identity_sha256,
                     content_tuple_sha256
            """
        ),
        "revokedReleaseBindings": rows(
            """
            SELECT binding_sha256, first_revoked_generation
            FROM revoked_release_bindings
            ORDER BY binding_sha256
            """
        ),
    }
    return _sha256_domain(b"catchplate.launchAuthorityState/v1\0", state)


class LaunchAuthority:
    def __init__(
        self,
        *,
        registry_path: Path,
        ledger: LaunchAuthorityLedger,
        signing_key: AuthoritySigningKey,
        monotonic_witness: LaunchAuthorityMonotonicWitnessClient,
        expected_global_role_registry_sha256: str,
        expected_global_role_registry_pins_sha256: str,
        validity_seconds: int = DEFAULT_VALIDITY_SECONDS,
    ) -> None:
        if type(validity_seconds) is not int or not 1 <= validity_seconds <= 30:
            raise AuthorityConfigurationError(
                "authorization validity must be 1 to 30 seconds"
            )
        self.registry_path = Path(registry_path)
        ReleaseRegistry.from_path(self.registry_path)
        self.ledger = ledger
        self.signing_key = signing_key
        required_witness_attributes = (
            "signing_public_key_spki_der",
            "signing_key_id",
            "witness_identity_sha256",
            "administrative_domain_sha256",
            "store_assurance_sha256",
            "store_assurance_key_id",
            "expected_tls_spki_sha256",
            "observe_registry_head",
            "authorize_transition",
            "recover_transition",
        )
        if any(
            not hasattr(monotonic_witness, attribute)
            for attribute in required_witness_attributes
        ):
            raise AuthorityConfigurationError(
                "an online independently pinned monotonic witness is required"
            )
        if hmac.compare_digest(
            monotonic_witness.signing_key_id, signing_key.key_id
        ):
            raise AuthorityConfigurationError(
                "launch authority and monotonic witness signing keys must be distinct"
            )
        self.monotonic_witness = monotonic_witness
        self.expected_global_role_registry_sha256 = _require_sha256_digest(
            expected_global_role_registry_sha256,
            label="expected launch global role registry digest",
        )
        self.expected_global_role_registry_pins_sha256 = _require_sha256_digest(
            expected_global_role_registry_pins_sha256,
            label="expected launch global role registry pins-file digest",
        )
        self.validity_seconds = validity_seconds
        self.trust_snapshot = self._capture_trust_snapshot()
        if hmac.compare_digest(
            self.trust_snapshot.witness_signing_key_id,
            self.trust_snapshot.authority_key_id,
        ):
            raise AuthorityConfigurationError(
                "launch authority and monotonic witness signing keys must be distinct"
            )
        self._assert_nonterminal_recovery_configuration()

    def _capture_trust_snapshot(self) -> AuthorityTrustSnapshot:
        try:
            authority_public_key_spki_der = (
                self.signing_key.private_key.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            witness_public_key_spki_der = bytes(
                self.monotonic_witness.signing_public_key_spki_der
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise AuthorityConfigurationError(
                "authority and witness signing keys must expose immutable Ed25519 "
                "startup material"
            ) from exc
        authority_key_id = _require_sha256_digest(
            self.signing_key.key_id,
            label="authority signing key ID",
        )
        witness_key_id = _require_sha256_digest(
            self.monotonic_witness.signing_key_id,
            label="witness signing key ID",
        )
        if not hmac.compare_digest(
            protocol.spki_key_id(authority_public_key_spki_der),
            authority_key_id,
        ):
            raise AuthorityConfigurationError(
                "authority signing key ID does not match its startup public key"
            )
        if not hmac.compare_digest(
            protocol.spki_key_id(witness_public_key_spki_der),
            witness_key_id,
        ):
            raise AuthorityConfigurationError(
                "witness signing key ID does not match its startup public key"
            )
        return AuthorityTrustSnapshot(
            authority_key_id=authority_key_id,
            authority_public_key_spki_der=authority_public_key_spki_der,
            witness_signing_key_id=witness_key_id,
            witness_signing_public_key_spki_der=witness_public_key_spki_der,
            witness_identity_sha256=_require_sha256_digest(
                self.monotonic_witness.witness_identity_sha256,
                label="witness identity digest",
            ),
            witness_administrative_domain_sha256=_require_sha256_digest(
                self.monotonic_witness.administrative_domain_sha256,
                label="witness administrative-domain digest",
            ),
            witness_store_assurance_sha256=_require_sha256_digest(
                self.monotonic_witness.store_assurance_sha256,
                label="witness store-assurance digest",
            ),
            witness_store_assurance_key_id=_require_sha256_digest(
                self.monotonic_witness.store_assurance_key_id,
                label="witness store-assurance signing key ID",
            ),
            witness_tls_spki_sha256=_require_sha256_digest(
                self.monotonic_witness.expected_tls_spki_sha256,
                label="witness TLS SPKI digest",
            ),
            global_role_registry_sha256=self.expected_global_role_registry_sha256,
            global_role_registry_pins_sha256=(
                self.expected_global_role_registry_pins_sha256
            ),
        )

    def _runtime_trust_snapshot_mismatches(self) -> tuple[str, ...]:
        try:
            current = self._capture_trust_snapshot()
        except AuthorityConfigurationError:
            return ("TRUST_SNAPSHOT_INVALID",)
        mismatches: list[str] = []
        for field in AuthorityTrustSnapshot.__dataclass_fields__:
            if not hmac.compare_digest(
                getattr(current, field),
                getattr(self.trust_snapshot, field),
            ):
                mismatches.append(field)
        return tuple(mismatches)

    def _assert_runtime_trust_snapshot(self) -> None:
        if self._runtime_trust_snapshot_mismatches():
            raise AuthorityError(
                "TRUST_SNAPSHOT_CHANGED",
                "process-lifetime launch trust changed after startup; "
                + TRUST_CONFIGURATION_LIFECYCLE,
                http_status=503,
            )

    def _assert_listener_startup_trust_snapshot(self) -> None:
        if self._runtime_trust_snapshot_mismatches():
            raise AuthorityConfigurationError(
                "launch trust changed between configuration and listener startup; "
                + TRUST_CONFIGURATION_LIFECYCLE
            )

    def _snapshot_trust_mismatches(
        self, request: Mapping[str, Any]
    ) -> tuple[str, ...]:
        registry = protocol.validate_launch_global_role_registry(
            request["globalRoleRegistry"]
        )
        snapshot = self.trust_snapshot
        comparisons = (
            (
                "WITNESS_KEY_MISMATCH",
                request["launchAuthorityWitnessKeyId"],
                snapshot.witness_signing_key_id,
            ),
            (
                "WITNESS_IDENTITY_MISMATCH",
                request["launchAuthorityWitnessIdentitySha256"],
                snapshot.witness_identity_sha256,
            ),
            (
                "WITNESS_ADMINISTRATIVE_DOMAIN_MISMATCH",
                request[
                    "launchAuthorityWitnessAdministrativeDomainSha256"
                ],
                snapshot.witness_administrative_domain_sha256,
            ),
            (
                "WITNESS_STORE_ASSURANCE_MISMATCH",
                request["launchAuthorityWitnessStoreAssuranceSha256"],
                snapshot.witness_store_assurance_sha256,
            ),
            (
                "GLOBAL_ROLE_REGISTRY_MISMATCH",
                request["globalRoleRegistrySha256"],
                snapshot.global_role_registry_sha256,
            ),
            (
                "GLOBAL_ROLE_REGISTRY_PINS_MISMATCH",
                request["globalRoleRegistryPinsSha256"],
                snapshot.global_role_registry_pins_sha256,
            ),
        )
        mismatches = [
            code
            for code, supplied, expected in comparisons
            if not hmac.compare_digest(supplied, expected)
        ]
        roles = registry["roles"]
        expected_roles = {
            "launchAuthority": snapshot.authority_key_id,
            "launchAuthorityWitness": snapshot.witness_signing_key_id,
            "launchAuthorityWitnessStoreAssurance": (
                snapshot.witness_store_assurance_key_id
            ),
            "launchAuthorityWitnessTls": snapshot.witness_tls_spki_sha256,
        }
        for role, expected in expected_roles.items():
            if not hmac.compare_digest(roles[role], expected):
                mismatches.append(f"GLOBAL_ROLE_BINDING_MISMATCH:{role}")
        return tuple(mismatches)

    def _assert_nonterminal_recovery_configuration(self) -> None:
        session: LedgerSession | None = None
        connection: sqlite3.Connection | None = None
        failure: Exception | None = None
        try:
            session = self.ledger.open_session()
            connection = session.connection
            connection.execute("BEGIN IMMEDIATE")
            operations = connection.execute(
                """
                SELECT operation_id, request_bytes, witness_request_bytes
                FROM issuance_operations
                WHERE state IN ('prepared', 'finalized')
                """
            ).fetchall()
            if len(operations) > 1:
                raise AuthorityConfigurationError(
                    "authority ledger contains multiple nonterminal issuance operations"
                )
            if operations:
                operation = operations[0]
                request = protocol.validate_launch_authorization_request(
                    protocol.require_canonical_json_bytes(
                        bytes(operation["request_bytes"]),
                        label="durable nonterminal launch request",
                    )
                )
                witness_request = protocol.validate_launch_authority_witness_request(
                    protocol.require_canonical_json_bytes(
                        bytes(operation["witness_request_bytes"]),
                        label="durable nonterminal witness request",
                    )
                )
                mismatches = list(self._snapshot_trust_mismatches(request))
                if not hmac.compare_digest(
                    witness_request["authorityKeyId"],
                    self.trust_snapshot.authority_key_id,
                ):
                    mismatches.append("AUTHORITY_KEY_MISMATCH")
                if not hmac.compare_digest(
                    witness_request["witnessKeyId"],
                    self.trust_snapshot.witness_signing_key_id,
                ):
                    mismatches.append("WITNESS_RECOVERY_KEY_MISMATCH")
                if mismatches:
                    raise AuthorityConfigurationError(
                        "startup trust rotation is forbidden while issuance "
                        f"{operation['operation_id']} is nonterminal "
                        f"({', '.join(mismatches)}); "
                        + TRUST_CONFIGURATION_LIFECYCLE
                    )
            self._commit_with_identity(session)
        except Exception as exc:
            failure = exc
            if connection is not None:
                try:
                    connection.rollback()
                except sqlite3.Error as rollback_exc:
                    failure = AuthorityConfigurationError(
                        "nonterminal startup check failed and rollback failed"
                    )
                    failure.__cause__ = rollback_exc
        if connection is not None:
            try:
                connection.close()
            except sqlite3.Error as close_exc:
                if failure is None:
                    failure = AuthorityConfigurationError(
                        "nonterminal startup check could not close the ledger"
                    )
                    failure.__cause__ = close_exc
        if failure is not None:
            if isinstance(failure, AuthorityConfigurationError):
                raise failure
            raise AuthorityConfigurationError(
                "nonterminal startup trust check failed; "
                + TRUST_CONFIGURATION_LIFECYCLE
            ) from failure

    def _current_trust_mismatches(
        self, request: Mapping[str, Any]
    ) -> tuple[str, ...]:
        return self._snapshot_trust_mismatches(request)

    @staticmethod
    def _raise_current_trust_mismatch(mismatches: tuple[str, ...]) -> None:
        code = mismatches[0].partition(":")[0]
        raise AuthorityError(
            code,
            "launch request does not match the independently pinned trust configuration",
            http_status=403,
        )

    @staticmethod
    def _assert_exact_operation(
        operation: Mapping[str, Any],
        *,
        raw_request: bytes,
        request_sha256: str,
        peer_certificate_sha256: str,
    ) -> None:
        if not hmac.compare_digest(
            operation["relay_client_certificate_sha256"],
            peer_certificate_sha256,
        ):
            raise AuthorityError(
                "RELAY_CLIENT_CERTIFICATE_MISMATCH",
                "issuance operation belongs to a different relay certificate",
                http_status=403,
            )
        if not (
            hmac.compare_digest(operation["request_sha256"], request_sha256)
            and hmac.compare_digest(bytes(operation["request_bytes"]), raw_request)
        ):
            raise AuthorityError(
                "NONCE_COLLISION",
                "launcher nonce is bound to a different durable issuance operation",
                http_status=409,
            )

    def _observe_registry_head(
        self,
        request: Mapping[str, Any],
        registry: ReleaseRegistry,
        *,
        operation_context: AuthorityOperationContext,
    ) -> None:
        operation_context.checkpoint("registry witness contact")
        self.monotonic_witness.observe_registry_head(
            {
                "apiVersion": protocol.REGISTRY_OBSERVATION_REQUEST_API_VERSION,
                "kind": protocol.REGISTRY_OBSERVATION_REQUEST_KIND,
                "operation": protocol.REGISTRY_OBSERVATION_OPERATION,
                "operationId": request["launcherNonce"],
                "challenge": request["launchAuthorityWitnessChallenge"],
                "authorityKeyId": self.signing_key.key_id,
                "witnessKeyId": request["launchAuthorityWitnessKeyId"],
                "witnessIdentitySha256": request[
                    "launchAuthorityWitnessIdentitySha256"
                ],
                "witnessAdministrativeDomainSha256": request[
                    "launchAuthorityWitnessAdministrativeDomainSha256"
                ],
                "storeAssuranceSha256": request[
                    "launchAuthorityWitnessStoreAssuranceSha256"
                ],
                "registryGeneration": registry.generation,
                "registrySha256": registry.registry_sha256,
            },
            operation_context=operation_context,
        )
        operation_context.assert_active(
            "registry witness completion",
            outcome_unknown=True,
        )

    def _witness_request_for(
        self,
        request: Mapping[str, Any],
        *,
        request_sha256: str,
        authorization_id: str,
        registry_generation: int,
        registry_sha256: str,
        predecessor_state_sha256: str,
        successor_state_sha256: str,
        issued_at_unix_seconds: int,
        expires_at_unix_seconds: int,
    ) -> dict[str, Any]:
        return protocol.validate_launch_authority_witness_request(
            {
                "apiVersion": protocol.WITNESS_REQUEST_API_VERSION,
                "kind": protocol.WITNESS_REQUEST_KIND,
                "operation": protocol.WITNESS_OPERATION,
                "operationId": request["launcherNonce"],
                "authorizationId": authorization_id,
                "requestSha256": request_sha256,
                "challenge": request["launchAuthorityWitnessChallenge"],
                "issuedAtUnixSeconds": issued_at_unix_seconds,
                "expiresAtUnixSeconds": expires_at_unix_seconds,
                "authorityKeyId": self.signing_key.key_id,
                "witnessKeyId": request["launchAuthorityWitnessKeyId"],
                "witnessIdentitySha256": request[
                    "launchAuthorityWitnessIdentitySha256"
                ],
                "witnessAdministrativeDomainSha256": request[
                    "launchAuthorityWitnessAdministrativeDomainSha256"
                ],
                "storeAssuranceSha256": request[
                    "launchAuthorityWitnessStoreAssuranceSha256"
                ],
                "registryGeneration": registry_generation,
                "registrySha256": registry_sha256,
                "predecessorStateSha256": predecessor_state_sha256,
                "successorStateSha256": successor_state_sha256,
                "deploymentAudience": request["deploymentAudience"],
                "deploymentIdentitySha256": request[
                    "deploymentIdentitySha256"
                ],
                "releaseSequence": request["releaseSequence"],
                "rollbackEpoch": request["rollbackEpoch"],
                "authorizationScope": request["authorizationScope"],
            }
        )

    def issue(
        self,
        raw_request: bytes,
        *,
        peer_certificate_sha256: str,
        now_unix_seconds: int | None = None,
        operation_context: AuthorityOperationContext | None = None,
    ) -> bytes:
        if operation_context is None:
            operation_context = AuthorityOperationContext(
                time.monotonic() + DEFAULT_CONNECTION_DEADLINE_SECONDS
            )
        operation_context.checkpoint("issuance start")
        self._assert_runtime_trust_snapshot()
        if type(raw_request) is not bytes or len(raw_request) > MAX_REQUEST_BYTES:
            raise AuthorityError(
                "INVALID_REQUEST", "launch request frame is invalid", http_status=400
            )
        try:
            _require_sha256_digest(
                peer_certificate_sha256,
                label="authenticated relay certificate digest",
            )
            request = protocol.validate_launch_authorization_request(
                protocol.require_canonical_json_bytes(
                    raw_request, label="launch authorization request"
                )
            )
            request_sha256 = protocol.launch_authorization_request_sha256(request)
        except AuthorityConfigurationError as exc:
            raise AuthorityError(
                "CLIENT_CERTIFICATE_IDENTITY_INVALID",
                "authenticated relay certificate identity is invalid",
                http_status=403,
            ) from exc
        except protocol.LaunchAuthorizationError as exc:
            raise AuthorityError(
                "INVALID_REQUEST",
                "launch request is not strict canonical JSON",
                http_status=400,
            ) from exc

        def sample_wall_time() -> int:
            sampled = (
                int(time.time())
                if now_unix_seconds is None
                else now_unix_seconds
            )
            if (
                type(sampled) is not int
                or not 1
                <= sampled
                <= protocol.MAX_SAFE_INTEGER - self.validity_seconds
            ):
                raise AuthorityError(
                    "INVALID_TIME",
                    "authority clock is invalid",
                    http_status=500,
                )
            return sampled

        now = sample_wall_time()

        persisted_operation: dict[str, Any] | None = None
        operation_context.checkpoint("durable operation inspection")
        probe_interrupt_id: int | None = None
        try:
            probe_session = self.ledger.open_session()
            probe_connection = probe_session.connection
            probe_interrupt_id = operation_context.register_abort(
                probe_connection.interrupt
            )
        except AuthorityConfigurationError as exc:
            raise AuthorityError(
                "LEDGER_UNAVAILABLE",
                "authority ledger is unavailable",
                http_status=503,
            ) from exc
        try:
            operation_context.checkpoint(
                "durable operation inspection transaction"
            )
            probe_connection.execute("BEGIN IMMEDIATE")
            active = probe_connection.execute(
                """
                SELECT * FROM issuance_operations
                WHERE state IN ('prepared', 'finalized')
                """
            ).fetchone()
            operation = probe_connection.execute(
                """
                SELECT * FROM issuance_operations WHERE operation_id = ?
                """,
                (request["launcherNonce"],),
            ).fetchone()
            if active is not None and (
                operation is None
                or active["operation_id"] != operation["operation_id"]
            ):
                raise AuthorityError(
                    "ISSUANCE_IN_PROGRESS",
                    "another durable issuance operation must be recovered first",
                    http_status=409,
                )
            if operation is not None:
                self._assert_exact_operation(
                    operation,
                    raw_request=raw_request,
                    request_sha256=request_sha256,
                    peer_certificate_sha256=peer_certificate_sha256,
                )
                persisted_operation = dict(operation)
            self._commit_with_identity(
                probe_session,
                operation_context=operation_context,
                phase="durable operation inspection",
            )
        except AuthorityError:
            probe_connection.rollback()
            raise
        except (AuthorityConfigurationError, sqlite3.Error) as exc:
            probe_connection.rollback()
            raise AuthorityError(
                "LEDGER_UNAVAILABLE",
                "authority could not inspect durable issuance state",
                http_status=503,
            ) from exc
        finally:
            operation_context.unregister_abort(probe_interrupt_id)
            probe_connection.close()

        current_trust_mismatches = self._current_trust_mismatches(request)
        if persisted_operation is None and current_trust_mismatches:
            self._raise_current_trust_mismatch(current_trust_mismatches)

        if persisted_operation is None:
            try:
                observed_registry_bytes = _read_stable_regular_file(
                    self.registry_path,
                    label="release registry",
                    max_bytes=MAX_REGISTRY_BYTES,
                    owner_only=False,
                )
                observed_registry = ReleaseRegistry.from_bytes(
                    observed_registry_bytes
                )
            except AuthorityConfigurationError as exc:
                raise AuthorityError(
                    "REGISTRY_UNAVAILABLE",
                    "current release registry is unavailable or invalid",
                    http_status=503,
                ) from exc
            try:
                self._observe_registry_head(
                    request,
                    observed_registry,
                    operation_context=operation_context,
                )
            except AuthorityOperationAborted as exc:
                raise AuthorityError(
                    "AUTHORITY_OPERATION_RECOVERY_PENDING",
                    "registry witness outcome may be unknown; retry the identical request",
                    http_status=503,
                ) from exc
            except AuthorityWitnessExchangeError as exc:
                if exc.outcome_unknown:
                    raise AuthorityError(
                        "AUTHORITY_OPERATION_RECOVERY_PENDING",
                        "registry witness outcome is unknown; retry the identical request",
                        http_status=503,
                    ) from exc
                raise AuthorityError(
                    "REGISTRY_WITNESS_UNAVAILABLE",
                    "external witness did not receive the registry observation",
                    http_status=503,
                ) from exc
            except (
                AuthorityConfigurationError,
                protocol.LaunchAuthorizationError,
            ) as exc:
                raise AuthorityError(
                    "REGISTRY_WITNESS_UNAVAILABLE",
                    "external witness did not confirm the current registry head",
                    http_status=503,
                ) from exc
        else:
            try:
                observed_registry_bytes = bytes(
                    persisted_operation["registry_bytes"]
                )
                observed_registry = ReleaseRegistry.from_bytes(
                    observed_registry_bytes
                )
            except (TypeError, AuthorityConfigurationError) as exc:
                raise AuthorityError(
                    "PREPARED_OPERATION_TAMPERED",
                    "durable issuance registry bytes are not exactly recoverable",
                    http_status=503,
                ) from exc

        operation_id = request["launcherNonce"]
        authorization_id = _authorization_id(
            request_sha256, request["launchAuthorityWitnessChallenge"]
        )
        newly_prepared = False
        operation_context.checkpoint("durable issuance preparation")
        preparation_interrupt_id: int | None = None
        try:
            session = self.ledger.open_session()
            connection = session.connection
            preparation_interrupt_id = operation_context.register_abort(
                connection.interrupt
            )
        except AuthorityConfigurationError as exc:
            raise AuthorityError(
                "LEDGER_UNAVAILABLE",
                "authority ledger is unavailable",
                http_status=503,
            ) from exc
        try:
            operation_context.checkpoint(
                "durable issuance preparation transaction"
            )
            connection.execute("BEGIN IMMEDIATE")
            active = connection.execute(
                """
                SELECT * FROM issuance_operations
                WHERE state IN ('prepared', 'finalized')
                """
            ).fetchone()
            operation = connection.execute(
                """
                SELECT * FROM issuance_operations WHERE operation_id = ?
                """,
                (operation_id,),
            ).fetchone()
            if active is not None and (
                operation is None
                or active["operation_id"] != operation["operation_id"]
            ):
                raise AuthorityError(
                    "ISSUANCE_IN_PROGRESS",
                    "another durable issuance operation must be recovered first",
                    http_status=409,
                )
            if operation is not None:
                self._assert_exact_operation(
                    operation,
                    raw_request=raw_request,
                    request_sha256=request_sha256,
                    peer_certificate_sha256=peer_certificate_sha256,
                )
                prepared = dict(operation)
            else:
                entry = observed_registry.lookup(
                    request, peer_certificate_sha256=peer_certificate_sha256
                )
                predecessor_state_sha256 = _authority_state_sha256(connection)
                witness_operation_sha256 = _witness_operation_sha256(
                    request,
                    request_sha256=request_sha256,
                    authorization_id=authorization_id,
                    registry_generation=observed_registry.generation,
                    registry_sha256=observed_registry.registry_sha256,
                    authority_key_id=self.signing_key.key_id,
                )
                connection.execute("SAVEPOINT staged_issuance")
                try:
                    operation_context.checkpoint(
                        "staged issuance state calculation"
                    )
                    self._record_registry_state(connection, observed_registry)
                    self._enforce_high_water(connection, request, entry)
                    self._persist_high_water(
                        connection,
                        request,
                        entry,
                        witness_operation_sha256=witness_operation_sha256,
                    )
                    operation_context.checkpoint(
                        "staged issuance state calculation completion"
                    )
                    successor_state_sha256 = _authority_state_sha256(connection)
                finally:
                    connection.execute("ROLLBACK TO staged_issuance")
                    connection.execute("RELEASE staged_issuance")
                if hmac.compare_digest(
                    predecessor_state_sha256, successor_state_sha256
                ):
                    raise AuthorityError(
                        "WITNESS_IDENTITY_TRANSITION",
                        "readiness authorization did not advance witness-bound state",
                        http_status=409,
                    )
                witness_request = self._witness_request_for(
                    request,
                    request_sha256=request_sha256,
                    authorization_id=authorization_id,
                    registry_generation=observed_registry.generation,
                    registry_sha256=observed_registry.registry_sha256,
                    predecessor_state_sha256=predecessor_state_sha256,
                    successor_state_sha256=successor_state_sha256,
                    issued_at_unix_seconds=now,
                    expires_at_unix_seconds=now + self.validity_seconds,
                )
                witness_request_bytes = protocol.canonical_json_bytes(
                    witness_request
                )
                operation_context.checkpoint(
                    "durable issuance operation insert"
                )
                connection.execute(
                    """
                    INSERT INTO issuance_operations (
                        operation_id, state, nonterminal_slot,
                        request_sha256, request_bytes,
                        authorization_id, relay_client_certificate_sha256,
                        registry_generation, registry_sha256, registry_bytes,
                        binding_sha256, content_tuple_sha256,
                        global_role_registry_sha256, witness_operation_sha256,
                        witness_request_bytes,
                        witness_predecessor_state_sha256,
                        witness_successor_state_sha256,
                        issued_at_unix_seconds, expires_at_unix_seconds,
                        witness_transition_bytes, envelope_bytes
                    ) VALUES (
                        ?, 'prepared', 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, NULL, NULL
                    )
                    """,
                    (
                        operation_id,
                        request_sha256,
                        raw_request,
                        authorization_id,
                        peer_certificate_sha256,
                        observed_registry.generation,
                        observed_registry.registry_sha256,
                        observed_registry_bytes,
                        entry.binding_sha256,
                        entry.content_tuple_sha256,
                        request["globalRoleRegistrySha256"],
                        witness_operation_sha256,
                        witness_request_bytes,
                        predecessor_state_sha256,
                        successor_state_sha256,
                        now,
                        now + self.validity_seconds,
                    ),
                )
                prepared = dict(
                    connection.execute(
                        """
                        SELECT * FROM issuance_operations WHERE operation_id = ?
                        """,
                        (operation_id,),
                    ).fetchone()
                )
                newly_prepared = True
            self._commit_with_identity(
                session,
                operation_context=operation_context,
                phase="durable issuance preparation",
            )
        except AuthorityError:
            connection.rollback()
            raise
        except (AuthorityConfigurationError, sqlite3.Error) as exc:
            connection.rollback()
            raise AuthorityError(
                "LEDGER_UNAVAILABLE",
                "authority could not durably prepare issuance",
                http_status=503,
            ) from exc
        finally:
            operation_context.unregister_abort(preparation_interrupt_id)
            connection.close()

        try:
            witness_request = (
                protocol.validate_launch_authority_witness_request(
                    protocol.require_canonical_json_bytes(
                        bytes(prepared["witness_request_bytes"]),
                        label="durable witness request",
                    )
                )
            )
            expected_witness_request = self._witness_request_for(
                request,
                request_sha256=request_sha256,
                authorization_id=prepared["authorization_id"],
                registry_generation=prepared["registry_generation"],
                registry_sha256=prepared["registry_sha256"],
                predecessor_state_sha256=prepared[
                    "witness_predecessor_state_sha256"
                ],
                successor_state_sha256=prepared[
                    "witness_successor_state_sha256"
                ],
                issued_at_unix_seconds=prepared["issued_at_unix_seconds"],
                expires_at_unix_seconds=prepared["expires_at_unix_seconds"],
            )
            expected_witness_operation_sha256 = _witness_operation_sha256(
                request,
                request_sha256=request_sha256,
                authorization_id=prepared["authorization_id"],
                registry_generation=prepared["registry_generation"],
                registry_sha256=prepared["registry_sha256"],
                authority_key_id=self.signing_key.key_id,
            )
            operation_matches = (
                hmac.compare_digest(
                    protocol.canonical_json_bytes(witness_request),
                    protocol.canonical_json_bytes(expected_witness_request),
                )
                and hmac.compare_digest(
                    prepared["witness_operation_sha256"],
                    expected_witness_operation_sha256,
                )
                and hmac.compare_digest(
                    prepared["global_role_registry_sha256"],
                    request["globalRoleRegistrySha256"],
                )
            )
        except (KeyError, TypeError, protocol.LaunchAuthorizationError) as exc:
            raise AuthorityError(
                "PREPARED_OPERATION_TAMPERED",
                "durable issuance operation is not exactly recoverable",
                http_status=503,
            ) from exc
        if not operation_matches:
            raise AuthorityError(
                "PREPARED_OPERATION_TAMPERED",
                "durable issuance operation changed its exact recovery binding",
                http_status=503,
            )
        if prepared["state"] in {"finalized", "terminal"}:
            operation_context.checkpoint("durable witness recovery read")
            try:
                monotonic_witness = protocol.require_canonical_json_bytes(
                    bytes(prepared["witness_transition_bytes"]),
                    label="durable witness transition",
                )
            except (TypeError, protocol.LaunchAuthorizationError) as exc:
                raise AuthorityError(
                    "FINALIZED_OPERATION_TAMPERED",
                    "finalized issuance lost its exact witness transition",
                    http_status=503,
                ) from exc
        elif newly_prepared:
            operation_context.checkpoint("witness transition dispatch")
            try:
                monotonic_witness = self.monotonic_witness.authorize_transition(
                    witness_request,
                    operation_context=operation_context,
                )
            except AuthorityOperationAborted as exc:
                raise AuthorityError(
                    "MONOTONIC_WITNESS_RECOVERY_PENDING",
                    "exact witness outcome may be unknown; retry the identical request",
                    http_status=503,
                ) from exc
            except AuthorityConfigurationError:
                operation_context.checkpoint("witness transition recovery")
                try:
                    monotonic_witness = self.monotonic_witness.recover_transition(
                        witness_request,
                        operation_context=operation_context,
                    )
                except AuthorityOperationAborted as exc:
                    raise AuthorityError(
                        "MONOTONIC_WITNESS_RECOVERY_PENDING",
                        "exact witness outcome may be unknown; retry the identical request",
                        http_status=503,
                    ) from exc
                except AuthorityConfigurationError as exc:
                    raise AuthorityError(
                        "MONOTONIC_WITNESS_RECOVERY_PENDING",
                        "exact witness outcome is unknown; retry the identical request",
                        http_status=503,
                    ) from exc
        else:
            operation_context.checkpoint("witness transition recovery")
            try:
                monotonic_witness = self.monotonic_witness.recover_transition(
                    witness_request,
                    operation_context=operation_context,
                )
            except AuthorityOperationAborted as exc:
                raise AuthorityError(
                    "MONOTONIC_WITNESS_RECOVERY_PENDING",
                    "durable issuance still requires exact witness recovery",
                    http_status=503,
                ) from exc
            except AuthorityConfigurationError as exc:
                raise AuthorityError(
                    "MONOTONIC_WITNESS_RECOVERY_PENDING",
                    "durable issuance requires exact witness recovery",
                    http_status=503,
                ) from exc
        operation_context.checkpoint("witness transition verification")
        try:
            monotonic_witness = protocol.verify_launch_authority_witness(
                monotonic_witness,
                witness_public_key_spki_der=(
                    self.monotonic_witness.signing_public_key_spki_der
                ),
                expected_witness_key_id=self.monotonic_witness.signing_key_id,
                expected_request=request,
                expected_authorization_id=prepared["authorization_id"],
                expected_authority_key_id=self.signing_key.key_id,
                expected_registry_generation=prepared["registry_generation"],
                expected_registry_sha256=prepared["registry_sha256"],
                expected_predecessor_state_sha256=prepared[
                    "witness_predecessor_state_sha256"
                ],
                expected_successor_state_sha256=prepared[
                    "witness_successor_state_sha256"
                ],
                expected_issued_at_unix_seconds=prepared[
                    "issued_at_unix_seconds"
                ],
                expected_expires_at_unix_seconds=prepared[
                    "expires_at_unix_seconds"
                ],
            )
        except protocol.LaunchAuthorizationError as exc:
            raise AuthorityError(
                "MONOTONIC_WITNESS_INVALID",
                "recovered witness result does not match the durable operation",
                http_status=503,
            ) from exc
        witness_transition_bytes = protocol.canonical_json_bytes(monotonic_witness)

        operation_context.checkpoint("authority finalization")
        finalization_interrupt_id: int | None = None
        try:
            final_session = self.ledger.open_session()
            final_connection = final_session.connection
            finalization_interrupt_id = operation_context.register_abort(
                final_connection.interrupt
            )
        except AuthorityConfigurationError as exc:
            raise AuthorityError(
                "LEDGER_UNAVAILABLE",
                "authority ledger is unavailable during finalization",
                http_status=503,
            ) from exc
        try:
            operation_context.checkpoint("authority finalization transaction")
            final_connection.execute("BEGIN IMMEDIATE")
            current = final_connection.execute(
                """
                SELECT * FROM issuance_operations WHERE operation_id = ?
                """,
                (operation_id,),
            ).fetchone()
            if current is None:
                raise AuthorityError(
                    "ISSUANCE_OPERATION_LOST",
                    "durable issuance operation disappeared",
                    http_status=503,
                )
            self._assert_exact_operation(
                current,
                raw_request=raw_request,
                request_sha256=request_sha256,
                peer_certificate_sha256=peer_certificate_sha256,
            )
            if current["state"] in {"finalized", "terminal"}:
                if not hmac.compare_digest(
                    bytes(current["witness_transition_bytes"]),
                    witness_transition_bytes,
                ):
                    raise AuthorityError(
                        "WITNESS_RECOVERY_MISMATCH",
                        "recovered witness result changed after local finalization",
                        http_status=503,
                    )
                response_bytes = bytes(current["envelope_bytes"])
            else:
                if not hmac.compare_digest(
                    _authority_state_sha256(final_connection),
                    current["witness_predecessor_state_sha256"],
                ):
                    raise AuthorityError(
                        "PREPARED_STATE_DIVERGED",
                        "local authority state changed before exact finalization",
                        http_status=503,
                    )
                prepared_registry = ReleaseRegistry.from_bytes(
                    bytes(current["registry_bytes"])
                )
                if not (
                    prepared_registry.generation == current["registry_generation"]
                    and hmac.compare_digest(
                        prepared_registry.registry_sha256,
                        current["registry_sha256"],
                    )
                ):
                    raise AuthorityError(
                        "PREPARED_REGISTRY_INVALID",
                        "prepared registry bytes changed their durable binding",
                        http_status=503,
                    )
                entry = prepared_registry.lookup(
                    request, peer_certificate_sha256=peer_certificate_sha256
                )
                if not (
                    hmac.compare_digest(entry.binding_sha256, current["binding_sha256"])
                    and hmac.compare_digest(
                        entry.content_tuple_sha256,
                        current["content_tuple_sha256"],
                    )
                ):
                    raise AuthorityError(
                        "PREPARED_RELEASE_MISMATCH",
                        "prepared release binding changed during recovery",
                        http_status=503,
                    )
                operation_context.checkpoint(
                    "witnessed authority state mutation"
                )
                self._record_registry_state(final_connection, prepared_registry)
                self._enforce_high_water(final_connection, request, entry)
                self._persist_high_water(
                    final_connection,
                    request,
                    entry,
                    witness_operation_sha256=current[
                        "witness_operation_sha256"
                    ],
                )
                operation_context.checkpoint(
                    "witnessed authority state mutation completion"
                )
                if not hmac.compare_digest(
                    _authority_state_sha256(final_connection),
                    current["witness_successor_state_sha256"],
                ):
                    raise AuthorityError(
                        "PREPARED_SUCCESSOR_MISMATCH",
                        "local finalization does not match the witnessed successor",
                        http_status=503,
                    )
                operation_context.checkpoint("authority signature generation")
                envelope = protocol.sign_launch_authorization(
                    request,
                    private_key=self.signing_key.private_key,
                    authorization_id=current["authorization_id"],
                    issued_at_unix_seconds=current["issued_at_unix_seconds"],
                    expires_at_unix_seconds=current["expires_at_unix_seconds"],
                    monotonic_witness=monotonic_witness,
                )
                operation_context.checkpoint(
                    "authority signature persistence"
                )
                response_bytes = protocol.canonical_json_bytes(envelope)
                witness_transition_sha256 = (
                    "sha256:" + hashlib.sha256(witness_transition_bytes).hexdigest()
                )
                operation_context.checkpoint(
                    "authorization record insert"
                )
                final_connection.execute(
                    """
                    INSERT INTO authorizations (
                        launcher_nonce, request_sha256, request_bytes, envelope_bytes,
                        authorization_id, deployment_audience,
                        deployment_identity_sha256, release_sequence, rollback_epoch,
                        nonce_rollback_assurance_contract_sha256,
                        nonce_rollback_assurance_pins_sha256,
                        binding_sha256, content_tuple_sha256,
                        relay_client_certificate_sha256,
                        witness_transition_sha256,
                        witness_checkpoint_sequence,
                        witness_predecessor_state_sha256,
                        witness_successor_state_sha256,
                        issued_at_unix_seconds, expires_at_unix_seconds
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        operation_id,
                        request_sha256,
                        raw_request,
                        response_bytes,
                        current["authorization_id"],
                        request["deploymentAudience"],
                        request["deploymentIdentitySha256"],
                        request["releaseSequence"],
                        request["rollbackEpoch"],
                        request["nonceRollbackAssuranceContractSha256"],
                        request["nonceRollbackAssurancePinsSha256"],
                        entry.binding_sha256,
                        entry.content_tuple_sha256,
                        peer_certificate_sha256,
                        witness_transition_sha256,
                        monotonic_witness["statement"]["checkpointSequence"],
                        current["witness_predecessor_state_sha256"],
                        current["witness_successor_state_sha256"],
                        current["issued_at_unix_seconds"],
                        current["expires_at_unix_seconds"],
                    ),
                )
                operation_context.checkpoint(
                    "authority finalized operation update"
                )
                final_connection.execute(
                    """
                    UPDATE issuance_operations
                    SET state = 'finalized',
                        witness_transition_bytes = ?,
                        envelope_bytes = ?
                    WHERE operation_id = ? AND state = 'prepared'
                    """,
                    (witness_transition_bytes, response_bytes, operation_id),
                )
            self._commit_with_identity(
                final_session,
                operation_context=operation_context,
                phase="authority finalization",
            )
        except AuthorityError:
            final_connection.rollback()
            raise
        except (
            AuthorityConfigurationError,
            protocol.LaunchAuthorizationError,
            sqlite3.Error,
        ) as exc:
            final_connection.rollback()
            raise AuthorityError(
                "AUTHORITY_FINALIZATION_FAILED",
                "authority could not finalize the exact witnessed operation",
                http_status=503,
            ) from exc
        finally:
            operation_context.unregister_abort(finalization_interrupt_id)
            final_connection.close()

        operation_context.checkpoint("finalized authorization verification")
        signing_public_key_spki_der = (
            self.signing_key.private_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        try:
            protocol.verify_launch_authorization_with_witness_for_recovery(
                response_bytes,
                authority_public_key_spki_der=signing_public_key_spki_der,
                expected_request=request,
                expected_authority_key_id=self.signing_key.key_id,
                witness_public_key_spki_der=(
                    self.monotonic_witness.signing_public_key_spki_der
                ),
                expected_witness_key_id=request[
                    "launchAuthorityWitnessKeyId"
                ],
                expected_registry_generation=prepared[
                    "registry_generation"
                ],
                expected_registry_sha256=prepared["registry_sha256"],
                expected_predecessor_state_sha256=prepared[
                    "witness_predecessor_state_sha256"
                ],
                expected_successor_state_sha256=prepared[
                    "witness_successor_state_sha256"
                ],
            )
        except protocol.LaunchAuthorizationError as exc:
            raise AuthorityError(
                "FINALIZED_AUTHORIZATION_INVALID",
                "durable authorization failed authenticity verification",
                http_status=503,
            ) from exc
        operation_context.checkpoint("terminal registry observation")
        try:
            terminal_registry = ReleaseRegistry.from_path(self.registry_path)
            self._observe_registry_head(
                request,
                terminal_registry,
                operation_context=operation_context,
            )
        except AuthorityOperationAborted as exc:
            raise AuthorityError(
                "AUTHORITY_TERMINAL_RECOVERY_PENDING",
                "terminal registry witness outcome may be unknown; "
                "retry the identical request",
                http_status=503,
            ) from exc
        except AuthorityWitnessExchangeError as exc:
            if exc.outcome_unknown:
                raise AuthorityError(
                    "AUTHORITY_TERMINAL_RECOVERY_PENDING",
                    "terminal registry witness outcome is unknown; "
                    "retry the identical request",
                    http_status=503,
                ) from exc
            raise AuthorityError(
                "TERMINAL_REGISTRY_WITNESS_UNAVAILABLE",
                "authorization was finalized but registry observation was not dispatched",
                http_status=503,
            ) from exc
        except (
            AuthorityConfigurationError,
            protocol.LaunchAuthorizationError,
        ) as exc:
            raise AuthorityError(
                "TERMINAL_REGISTRY_WITNESS_UNAVAILABLE",
                "authorization was finalized but current registry head is unconfirmed",
                http_status=503,
            ) from exc
        registry_changed = (
            terminal_registry.generation != prepared["registry_generation"]
            or not hmac.compare_digest(
                terminal_registry.registry_sha256, prepared["registry_sha256"]
            )
        )
        registry_freshness_now = sample_wall_time()
        if (
            registry_changed
            and registry_freshness_now < prepared["expires_at_unix_seconds"]
        ):
            raise AuthorityError(
                "REGISTRY_CHANGED_DURING_ISSUANCE",
                "fresh recovered authorization is blocked by newer release policy",
                http_status=409,
            )
        operation_context.checkpoint("authority terminalization")
        terminal_interrupt_id: int | None = None
        try:
            terminal_session = self.ledger.open_session()
            terminal_connection = terminal_session.connection
            terminal_interrupt_id = operation_context.register_abort(
                terminal_connection.interrupt
            )
        except AuthorityConfigurationError as exc:
            raise AuthorityError(
                "LEDGER_UNAVAILABLE",
                "authority ledger is unavailable during terminal recovery",
                http_status=503,
            ) from exc
        try:
            operation_context.checkpoint("authority terminalization transaction")
            terminal_connection.execute("BEGIN IMMEDIATE")
            terminal_operation = terminal_connection.execute(
                """
                SELECT * FROM issuance_operations WHERE operation_id = ?
                """,
                (operation_id,),
            ).fetchone()
            if terminal_operation is None:
                raise AuthorityError(
                    "ISSUANCE_OPERATION_LOST",
                    "finalized issuance operation disappeared",
                    http_status=503,
                )
            self._assert_exact_operation(
                terminal_operation,
                raw_request=raw_request,
                request_sha256=request_sha256,
                peer_certificate_sha256=peer_certificate_sha256,
            )
            if terminal_operation["state"] == "finalized":
                operation_context.checkpoint(
                    "authority terminal state update"
                )
                terminal_observed_at_unix_seconds = sample_wall_time()
                terminal_connection.execute(
                    """
                    UPDATE issuance_operations
                    SET state = 'terminal',
                        nonterminal_slot = NULL,
                        terminal_registry_generation = ?,
                        terminal_registry_sha256 = ?,
                        terminal_observed_at_unix_seconds = ?
                    WHERE operation_id = ? AND state = 'finalized'
                    """,
                    (
                        terminal_registry.generation,
                        terminal_registry.registry_sha256,
                        terminal_observed_at_unix_seconds,
                        operation_id,
                    ),
                )
            elif terminal_operation["state"] != "terminal":
                raise AuthorityError(
                    "ISSUANCE_NOT_FINALIZED",
                    "issuance operation cannot enter terminal state",
                    http_status=503,
                )
            self._commit_with_identity(
                terminal_session,
                operation_context=operation_context,
                phase="authority terminalization",
            )
        except AuthorityError:
            terminal_connection.rollback()
            raise
        except (AuthorityConfigurationError, sqlite3.Error) as exc:
            terminal_connection.rollback()
            raise AuthorityError(
                "AUTHORITY_TERMINALIZATION_FAILED",
                "authority could not persist terminal registry observation",
                http_status=503,
            ) from exc
        finally:
            operation_context.unregister_abort(terminal_interrupt_id)
            terminal_connection.close()
        operation_context.checkpoint("terminal authorization return")
        self._assert_runtime_trust_snapshot()
        return_trust_mismatches = self._snapshot_trust_mismatches(request)
        return_freshness_now = sample_wall_time()
        if (
            return_trust_mismatches
            and return_freshness_now < prepared["expires_at_unix_seconds"]
        ):
            raise AuthorityError(
                "TRUST_CONFIGURATION_CHANGED_DURING_ISSUANCE",
                "fresh recovered authorization is blocked by changed trust pins",
                http_status=409,
            )
        # An expired envelope is still the authenticated terminal saga result. The
        # launch verifier rejects its freshness; a recovery verifier may authenticate
        # it only to clear the exact prior attempt before creating another one. If
        # policy changed, the terminal artifact is withheld until expiry.
        return response_bytes

    @staticmethod
    def _commit_with_identity(
        session: LedgerSession,
        *,
        operation_context: AuthorityOperationContext | None = None,
        phase: str = "authority ledger",
    ) -> None:
        if operation_context is not None:
            operation_context.checkpoint(f"{phase} pre-commit")
        session.assert_path_identity()
        if operation_context is not None:
            operation_context.checkpoint(f"{phase} commit admission")
        try:
            session.connection.commit()
        except sqlite3.Error as exc:
            if operation_context is not None and operation_context.cancelled:
                raise AuthorityError(
                    "AUTHORITY_COMMIT_OUTCOME_UNKNOWN",
                    "ledger commit outcome is unknown; retry the identical request",
                    http_status=503,
                ) from exc
            raise
        session.assert_path_identity()
        if operation_context is not None:
            try:
                operation_context.checkpoint(f"{phase} post-commit")
            except AuthorityError as exc:
                # SQLite commit is atomic, but cancellation racing an entered commit
                # cannot prove whether the acknowledgement or commit won. The
                # persisted operation identity makes the identical retry recover it.
                raise AuthorityError(
                    "AUTHORITY_COMMIT_OUTCOME_UNKNOWN",
                    "ledger commit outcome is unknown; retry the identical request",
                    http_status=503,
                ) from exc

    @staticmethod
    def _record_registry_state(
        connection: sqlite3.Connection, registry: ReleaseRegistry
    ) -> bool:
        current = connection.execute(
            "SELECT generation, registry_sha256 FROM registry_state WHERE singleton = 1"
        ).fetchone()
        if current is not None and registry.generation < current["generation"]:
            raise AuthorityError(
                "REGISTRY_GENERATION_ROLLBACK",
                "release registry generation is below the durable high-water",
                http_status=503,
            )
        if current is not None and registry.generation == current["generation"]:
            if not hmac.compare_digest(
                registry.registry_sha256, current["registry_sha256"]
            ):
                raise AuthorityError(
                    "REGISTRY_GENERATION_CONFLICT",
                    "release registry changed without increasing its generation",
                    http_status=503,
                )
        sticky_revocations = {
            row["binding_sha256"]
            for row in connection.execute(
                "SELECT binding_sha256 FROM revoked_release_bindings"
            ).fetchall()
        }
        for entry in registry.entries.values():
            if entry.binding_sha256 in sticky_revocations and not entry.revoked:
                raise AuthorityError(
                    "REGISTRY_REVOKED_BINDING_RESURRECTION",
                    "a durably revoked release binding cannot be re-enabled",
                    http_status=503,
                )

        changed_before = connection.total_changes
        if current is None:
            connection.execute(
                """
                INSERT INTO registry_state (singleton, generation, registry_sha256)
                VALUES (1, ?, ?)
                """,
                (registry.generation, registry.registry_sha256),
            )
        elif registry.generation > current["generation"]:
            connection.execute(
                """
                UPDATE registry_state SET generation = ?, registry_sha256 = ?
                WHERE singleton = 1
                """,
                (registry.generation, registry.registry_sha256),
            )
        for entry in registry.entries.values():
            if entry.revoked:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO revoked_release_bindings (
                        binding_sha256, first_revoked_generation
                    ) VALUES (?, ?)
                    """,
                    (entry.binding_sha256, registry.generation),
                )
        return connection.total_changes > changed_before

    @staticmethod
    def _enforce_high_water(
        connection: sqlite3.Connection,
        request: Mapping[str, Any],
        entry: ReleaseEntry,
    ) -> None:
        current = connection.execute(
            """
            SELECT release_sequence, rollback_epoch, binding_sha256,
                   content_tuple_sha256,
                   nonce_rollback_assurance_contract_sha256,
                   nonce_rollback_assurance_pins_sha256
            FROM deployment_high_water
            WHERE deployment_audience = ? AND deployment_identity_sha256 = ?
            """,
            (request["deploymentAudience"], request["deploymentIdentitySha256"]),
        ).fetchone()
        if current is None:
            return
        sequence = request["releaseSequence"]
        epoch = request["rollbackEpoch"]
        if sequence < current["release_sequence"]:
            raise AuthorityError(
                "SEQUENCE_ROLLBACK",
                "release sequence is below the deployment high-water",
                http_status=409,
            )
        if epoch < current["rollback_epoch"]:
            raise AuthorityError(
                "ROLLBACK_EPOCH_ROLLBACK",
                "rollback epoch is below the deployment high-water",
                http_status=409,
            )
        if sequence == current["release_sequence"]:
            if not (
                hmac.compare_digest(entry.binding_sha256, current["binding_sha256"])
                and hmac.compare_digest(
                    request["nonceRollbackAssuranceContractSha256"],
                    current["nonce_rollback_assurance_contract_sha256"],
                )
                and hmac.compare_digest(
                    request["nonceRollbackAssurancePinsSha256"],
                    current["nonce_rollback_assurance_pins_sha256"],
                )
            ):
                raise AuthorityError(
                    "SEQUENCE_TUPLE_MISMATCH",
                    "equal release sequence requires the exact accepted release tuple",
                    http_status=409,
                )
            return
        if not hmac.compare_digest(
            entry.content_tuple_sha256, current["content_tuple_sha256"]
        ):
            seen = connection.execute(
                """
                SELECT 1 FROM seen_release_tuples
                WHERE deployment_audience = ?
                  AND deployment_identity_sha256 = ?
                  AND content_tuple_sha256 = ?
                """,
                (
                    request["deploymentAudience"],
                    request["deploymentIdentitySha256"],
                    entry.content_tuple_sha256,
                ),
            ).fetchone()
            if seen is not None and epoch <= current["rollback_epoch"]:
                raise AuthorityError(
                    "ROLLBACK_EPOCH_REQUIRED",
                    "returning to a previously seen release requires a higher rollback epoch",
                    http_status=409,
                )

    @staticmethod
    def _persist_high_water(
        connection: sqlite3.Connection,
        request: Mapping[str, Any],
        entry: ReleaseEntry,
        *,
        witness_operation_sha256: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO deployment_high_water (
                deployment_audience, deployment_identity_sha256,
                release_sequence, rollback_epoch,
                nonce_rollback_assurance_contract_sha256,
                nonce_rollback_assurance_pins_sha256,
                witness_operation_sha256, witness_challenge, binding_sha256,
                content_tuple_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (deployment_audience, deployment_identity_sha256)
            DO UPDATE SET
                release_sequence = excluded.release_sequence,
                rollback_epoch = excluded.rollback_epoch,
                nonce_rollback_assurance_contract_sha256 =
                    excluded.nonce_rollback_assurance_contract_sha256,
                nonce_rollback_assurance_pins_sha256 =
                    excluded.nonce_rollback_assurance_pins_sha256,
                witness_operation_sha256 =
                    excluded.witness_operation_sha256,
                witness_challenge = excluded.witness_challenge,
                binding_sha256 = excluded.binding_sha256,
                content_tuple_sha256 = excluded.content_tuple_sha256
            """,
            (
                request["deploymentAudience"],
                request["deploymentIdentitySha256"],
                request["releaseSequence"],
                request["rollbackEpoch"],
                request["nonceRollbackAssuranceContractSha256"],
                request["nonceRollbackAssurancePinsSha256"],
                witness_operation_sha256,
                request["launchAuthorityWitnessChallenge"],
                entry.binding_sha256,
                entry.content_tuple_sha256,
            ),
        )
        connection.execute(
            """
            INSERT INTO seen_release_tuples (
                deployment_audience, deployment_identity_sha256,
                content_tuple_sha256,
                nonce_rollback_assurance_contract_sha256,
                nonce_rollback_assurance_pins_sha256, first_release_sequence,
                last_release_sequence, max_rollback_epoch
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (
                deployment_audience, deployment_identity_sha256,
                content_tuple_sha256
            ) DO UPDATE SET
                nonce_rollback_assurance_contract_sha256 =
                    excluded.nonce_rollback_assurance_contract_sha256,
                nonce_rollback_assurance_pins_sha256 =
                    excluded.nonce_rollback_assurance_pins_sha256,
                last_release_sequence = MAX(
                    seen_release_tuples.last_release_sequence,
                    excluded.last_release_sequence
                ),
                max_rollback_epoch = MAX(
                    seen_release_tuples.max_rollback_epoch,
                    excluded.max_rollback_epoch
                )
            """,
            (
                request["deploymentAudience"],
                request["deploymentIdentitySha256"],
                entry.content_tuple_sha256,
                request["nonceRollbackAssuranceContractSha256"],
                request["nonceRollbackAssurancePinsSha256"],
                request["releaseSequence"],
                request["releaseSequence"],
                request["rollbackEpoch"],
            ),
        )


def _remaining_deadline_seconds(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("authority connection deadline expired")
    return remaining


def _tls_handshake_before_deadline(
    raw_socket: socket.socket,
    context: ssl.SSLContext,
    deadline: float,
) -> ssl.SSLSocket:
    tls_socket = context.wrap_socket(
        raw_socket,
        server_side=True,
        do_handshake_on_connect=False,
    )
    tls_socket.setblocking(False)
    try:
        while True:
            try:
                tls_socket.do_handshake()
                break
            except ssl.SSLWantReadError:
                readable, _, _ = select.select(
                    [tls_socket], [], [], _remaining_deadline_seconds(deadline)
                )
                if not readable:
                    raise TimeoutError("authority TLS handshake deadline expired")
            except ssl.SSLWantWriteError:
                _, writable, _ = select.select(
                    [], [tls_socket], [], _remaining_deadline_seconds(deadline)
                )
                if not writable:
                    raise TimeoutError("authority TLS handshake deadline expired")
        tls_socket.setblocking(True)
        tls_socket.settimeout(_remaining_deadline_seconds(deadline))
        return tls_socket
    except Exception:
        tls_socket.close()
        raise


AllowedSourceNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def validate_allowed_source_cidrs(values: object) -> tuple[AllowedSourceNetwork, ...]:
    if not isinstance(values, (list, tuple)) or not 1 <= len(values) <= 64:
        raise AuthorityConfigurationError(
            "1 through 64 explicit source CIDRs are required"
        )
    networks: list[AllowedSourceNetwork] = []
    for raw in values:
        if type(raw) is not str or not raw or raw.strip() != raw:
            raise AuthorityConfigurationError(
                "allowed source CIDRs must be canonical strings"
            )
        try:
            network = ipaddress.ip_network(raw, strict=True)
        except ValueError as exc:
            raise AuthorityConfigurationError(
                f"allowed source CIDR is invalid: {raw!r}"
            ) from exc
        if str(network) != raw:
            raise AuthorityConfigurationError(
                f"allowed source CIDR is not canonical: {raw!r}"
            )
        if any(
            network.version == existing.version and network.overlaps(existing)
            for existing in networks
        ):
            raise AuthorityConfigurationError(
                f"allowed source CIDR overlaps another configured network: {raw}"
            )
        networks.append(network)
    return tuple(networks)


class LaunchAuthorityHTTPServer(HTTPServer):
    allow_reuse_address = True
    request_queue_size = 32

    def __init__(
        self,
        address: tuple[str, int],
        authority: LaunchAuthority,
        *,
        tls_context: ssl.SSLContext,
        allowed_source_cidrs: object,
        max_handshakes: int,
        max_handshakes_per_ip: int,
        max_issuance_workers: int,
        max_issuance_workers_per_ip: int,
        handshake_deadline_seconds: float,
        connection_deadline_seconds: float,
        listener_lease_descriptor: int,
    ) -> None:
        integer_limits = (
            ("handshake limit", max_handshakes, 256),
            ("per-IP handshake limit", max_handshakes_per_ip, max_handshakes),
            ("issuance worker limit", max_issuance_workers, 256),
            (
                "per-IP issuance worker limit",
                max_issuance_workers_per_ip,
                max_issuance_workers,
            ),
        )
        for label, value, maximum in integer_limits:
            if type(value) is not int or not 1 <= value <= maximum:
                raise AuthorityConfigurationError(
                    f"authority {label} must be between 1 and {maximum}"
                )
        if (
            isinstance(connection_deadline_seconds, bool)
            or not isinstance(connection_deadline_seconds, (int, float))
            or not 0.05 <= float(connection_deadline_seconds) <= 30.0
        ):
            raise AuthorityConfigurationError(
                "authority connection deadline must be between 0.05 and 30 seconds"
            )
        if (
            isinstance(handshake_deadline_seconds, bool)
            or not isinstance(handshake_deadline_seconds, (int, float))
            or not 0.05
            <= float(handshake_deadline_seconds)
            <= float(connection_deadline_seconds)
        ):
            raise AuthorityConfigurationError(
                "authority handshake deadline must be at least 0.05 seconds and "
                "must not exceed the connection deadline"
            )
        self.authority = authority
        self.tls_context = tls_context
        self.allowed_source_networks = validate_allowed_source_cidrs(
            allowed_source_cidrs
        )
        self.max_handshakes = max_handshakes
        self.max_handshakes_per_ip = max_handshakes_per_ip
        self.max_issuance_workers = max_issuance_workers
        self.max_issuance_workers_per_ip = max_issuance_workers_per_ip
        self.handshake_deadline_seconds = float(handshake_deadline_seconds)
        self.connection_deadline_seconds = float(connection_deadline_seconds)
        self._handshake_slots = threading.BoundedSemaphore(max_handshakes)
        self._issuance_slots = threading.BoundedSemaphore(max_issuance_workers)
        self._worker_state = threading.local()
        self._admission_lock = threading.Lock()
        self._handshakes_by_ip: dict[str, int] = {}
        self._issuance_by_ip: dict[str, int] = {}
        self.active_handshakes = 0
        self.peak_handshakes = 0
        self.active_issuance_workers = 0
        self.peak_issuance_workers = 0
        self.rejected_source_count = 0
        self._listener_lease_descriptor: int | None = None
        super().__init__(address, LaunchAuthorityRequestHandler)
        self._listener_lease_descriptor = listener_lease_descriptor

    def server_close(self) -> None:
        try:
            super().server_close()
        finally:
            descriptor = self._listener_lease_descriptor
            self._listener_lease_descriptor = None
            if descriptor is not None:
                self.authority.ledger.release_listener_lease(descriptor)

    def process_request(
        self, request: socket.socket, client_address: tuple[str, int]
    ) -> None:
        try:
            source = ipaddress.ip_address(client_address[0])
        except ValueError:
            self.shutdown_request(request)
            return
        if isinstance(source, ipaddress.IPv6Address) and source.ipv4_mapped is not None:
            source = source.ipv4_mapped
        if not any(source in network for network in self.allowed_source_networks):
            with self._admission_lock:
                self.rejected_source_count += 1
            self.shutdown_request(request)
            return
        source_text = str(source)
        if not self._acquire_handshake(source_text):
            self.shutdown_request(request)
            return
        worker = threading.Thread(
            target=self._process_request_worker,
            args=(request, client_address, source_text),
            name="launch-authority-handshake",
            daemon=True,
        )
        try:
            worker.start()
        except Exception:
            self._release_handshake(source_text)
            self.shutdown_request(request)
            raise

    def _acquire_handshake(self, source: str) -> bool:
        if not self._handshake_slots.acquire(blocking=False):
            return False
        with self._admission_lock:
            current = self._handshakes_by_ip.get(source, 0)
            if current >= self.max_handshakes_per_ip:
                self._handshake_slots.release()
                return False
            self._handshakes_by_ip[source] = current + 1
            self.active_handshakes += 1
            self.peak_handshakes = max(self.peak_handshakes, self.active_handshakes)
        return True

    def _release_handshake(self, source: str) -> None:
        with self._admission_lock:
            current = self._handshakes_by_ip[source]
            if current == 1:
                del self._handshakes_by_ip[source]
            else:
                self._handshakes_by_ip[source] = current - 1
            self.active_handshakes -= 1
        self._handshake_slots.release()

    def _acquire_issuance(self, source: str) -> bool:
        if not self._issuance_slots.acquire(blocking=False):
            return False
        with self._admission_lock:
            current = self._issuance_by_ip.get(source, 0)
            if current >= self.max_issuance_workers_per_ip:
                self._issuance_slots.release()
                return False
            self._issuance_by_ip[source] = current + 1
            self.active_issuance_workers += 1
            self.peak_issuance_workers = max(
                self.peak_issuance_workers, self.active_issuance_workers
            )
        return True

    def _release_issuance(self, source: str) -> None:
        with self._admission_lock:
            current = self._issuance_by_ip[source]
            if current == 1:
                del self._issuance_by_ip[source]
            else:
                self._issuance_by_ip[source] = current - 1
            self.active_issuance_workers -= 1
        self._issuance_slots.release()

    def _process_request_worker(
        self,
        raw_socket: socket.socket,
        client_address: tuple[str, int],
        source: str,
    ) -> None:
        deadline = time.monotonic() + self.connection_deadline_seconds
        operation_context = AuthorityOperationContext(deadline)
        handshake_deadline = min(
            deadline, time.monotonic() + self.handshake_deadline_seconds
        )
        connection: socket.socket = raw_socket
        deadline_timer: threading.Timer | None = None
        deadline_timer_started = False
        client_abort_callback_id: int | None = None
        handshake_admitted = True
        issuance_admitted = False
        try:
            connection = _tls_handshake_before_deadline(
                raw_socket, self.tls_context, handshake_deadline
            )
            self._release_handshake(source)
            handshake_admitted = False
            if not self._acquire_issuance(source):
                return
            issuance_admitted = True

            def expire_connection() -> None:
                operation_context.cancel("deadline_expired")

            def abort_connection() -> None:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

            client_abort_callback_id = operation_context.register_abort(
                abort_connection
            )
            deadline_timer = threading.Timer(
                _remaining_deadline_seconds(deadline), expire_connection
            )
            deadline_timer.daemon = True
            deadline_timer.start()
            deadline_timer_started = True
            self._worker_state.operation_context = operation_context
            self.finish_request(connection, client_address)
        except (OSError, ssl.SSLError, TimeoutError):
            pass
        except Exception:
            self.handle_error(connection, client_address)
        finally:
            if deadline_timer is not None:
                deadline_timer.cancel()
                if deadline_timer_started:
                    deadline_timer.join()
            operation_context.unregister_abort(client_abort_callback_id)
            if hasattr(self._worker_state, "operation_context"):
                del self._worker_state.operation_context
            self.shutdown_request(connection)
            if handshake_admitted:
                self._release_handshake(source)
            if issuance_admitted:
                self._release_issuance(source)

    def current_operation_context(self) -> AuthorityOperationContext:
        operation_context = getattr(
            self._worker_state, "operation_context", None
        )
        if not isinstance(operation_context, AuthorityOperationContext):
            raise RuntimeError("authority request is outside a bounded worker")
        return operation_context

    def start_disconnect_monitor(
        self,
        connection: socket.socket,
    ) -> tuple[threading.Event, threading.Thread]:
        operation_context = self.current_operation_context()
        stop = threading.Event()

        def watch() -> None:
            while not stop.is_set() and not operation_context.cancelled:
                try:
                    timeout = min(
                        0.1,
                        operation_context.remaining_seconds(
                            "client disconnect monitor"
                        ),
                    )
                    pending = getattr(connection, "pending", None)
                    has_pending_tls_data = (
                        pending is not None and pending() > 0
                    )
                    readable = (
                        [connection]
                        if has_pending_tls_data
                        else select.select([connection], [], [], timeout)[0]
                    )
                except (OSError, ValueError, AuthorityOperationAborted):
                    if not stop.is_set():
                        operation_context.cancel("client_disconnected")
                    return
                if stop.is_set():
                    return
                if not readable:
                    continue
                try:
                    connection.settimeout(
                        min(
                            0.1,
                            operation_context.remaining_seconds(
                                "client disconnect confirmation"
                            ),
                        )
                    )
                    extra = connection.recv(1)
                except (BlockingIOError, ssl.SSLWantReadError, socket.timeout):
                    continue
                except (OSError, ValueError, AuthorityOperationAborted):
                    if not stop.is_set():
                        operation_context.cancel("client_disconnected")
                    return
                if stop.is_set():
                    return
                operation_context.cancel(
                    "client_disconnected"
                    if not extra
                    else "unexpected_client_data"
                )
                return

        monitor = threading.Thread(
            target=watch,
            name="launch-authority-disconnect-monitor",
            daemon=True,
        )
        monitor.start()
        return stop, monitor

    @staticmethod
    def stop_disconnect_monitor(
        monitor: tuple[threading.Event, threading.Thread],
    ) -> None:
        stop, worker = monitor
        stop.set()
        # The watcher uses bounded select/recv intervals. Joining it completely
        # prevents an old watcher from consuming bytes or racing response writes.
        worker.join()


class LaunchAuthorityRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "CatchplateLaunchAuthority/1"
    sys_version = ""
    rbufsize = 0

    def setup(self) -> None:
        super().setup()
        self._set_deadline_timeout()

    @property
    def authority_server(self) -> LaunchAuthorityHTTPServer:
        if not isinstance(self.server, LaunchAuthorityHTTPServer):
            raise RuntimeError(
                "launch authority handler is attached to the wrong server"
            )
        return self.server

    def log_message(self, format: str, *args: object) -> None:
        sys.stderr.write("launch-authority-http: " + (format % args) + "\n")

    def handle_expect_100(self) -> bool:
        self._send_error(417, "EXPECTATION_REJECTED")
        return False

    def do_POST(self) -> None:  # noqa: N802
        self._set_deadline_timeout()
        if self.path != AUTHORIZATION_PATH:
            self._send_error(404, "NOT_FOUND")
            return
        if self.request_version != "HTTP/1.1":
            self._send_error(400, "HTTP_VERSION_INVALID")
            return
        get_peer_certificate = getattr(self.connection, "getpeercert", None)
        peer = (
            get_peer_certificate(binary_form=True)
            if get_peer_certificate is not None
            else None
        )
        if not peer:
            self._send_error(403, "CLIENT_CERTIFICATE_REQUIRED")
            return
        if self.headers.get_all("Transfer-Encoding"):
            self._send_error(400, "TRANSFER_ENCODING_FORBIDDEN")
            return
        if self.headers.get_all("Content-Encoding"):
            self._send_error(400, "CONTENT_ENCODING_FORBIDDEN")
            return
        content_types = self.headers.get_all("Content-Type") or []
        if content_types != [REQUEST_CONTENT_TYPE]:
            self._send_error(415, "CONTENT_TYPE_INVALID")
            return
        lengths = self.headers.get_all("Content-Length") or []
        if (
            len(lengths) != 1
            or not lengths[0].isdigit()
            or len(lengths[0]) > 5
            or str(int(lengths[0])) != lengths[0]
        ):
            self._send_error(411, "CONTENT_LENGTH_INVALID")
            return
        length = int(lengths[0])
        if not 1 <= length <= MAX_REQUEST_BYTES:
            self._send_error(413, "REQUEST_TOO_LARGE")
            return
        try:
            chunks: list[bytes] = []
            remaining = length
            while remaining:
                self._set_deadline_timeout()
                chunk = self.rfile.read(remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            body = b"".join(chunks)
        except (OSError, TimeoutError):
            self._send_error(408, "REQUEST_TIMEOUT")
            return
        if len(body) != length:
            self._send_error(400, "REQUEST_TRUNCATED")
            return
        self._set_deadline_timeout()
        disconnect_monitor = self.authority_server.start_disconnect_monitor(
            self.connection
        )
        authority_error: AuthorityError | None = None
        try:
            response = self.authority_server.authority.issue(
                body,
                peer_certificate_sha256=der_certificate_sha256(peer),
                operation_context=(
                    self.authority_server.current_operation_context()
                ),
            )
        except AuthorityError as exc:
            authority_error = exc
        finally:
            self.authority_server.stop_disconnect_monitor(
                disconnect_monitor
            )
        if authority_error is not None:
            self._send_error(
                authority_error.http_status,
                authority_error.code,
            )
            return
        self._set_deadline_timeout()
        self._send_bytes(200, RESPONSE_CONTENT_TYPE, response)

    def do_GET(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_PUT(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_DELETE(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_PATCH(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def _method_not_allowed(self) -> None:
        self._set_deadline_timeout()
        self.send_response(405)
        self.send_header("Allow", "POST")
        body = protocol.canonical_json_bytes({"code": "METHOD_NOT_ALLOWED"})
        self.send_header("Content-Type", RESPONSE_CONTENT_TYPE)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _send_error(self, status: int, code: str) -> None:
        self._send_bytes(
            status,
            RESPONSE_CONTENT_TYPE,
            protocol.canonical_json_bytes({"code": code}),
        )

    def _send_bytes(self, status: int, content_type: str, body: bytes) -> None:
        self._set_deadline_timeout()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        self.close_connection = True

    def _set_deadline_timeout(self) -> None:
        self.connection.settimeout(
            self.authority_server.current_operation_context().remaining_seconds(
                "client connection I/O"
            )
        )


def create_https_server(
    address: tuple[str, int],
    *,
    authority: LaunchAuthority,
    server_certificate: Path,
    server_private_key: Path,
    client_ca_certificate: Path,
    allowed_source_cidrs: object,
    max_handshakes: int = DEFAULT_MAX_HANDSHAKES,
    max_handshakes_per_ip: int = DEFAULT_MAX_HANDSHAKES_PER_IP,
    max_issuance_workers: int = DEFAULT_MAX_ISSUANCE_WORKERS,
    max_issuance_workers_per_ip: int = DEFAULT_MAX_ISSUANCE_WORKERS_PER_IP,
    handshake_deadline_seconds: float = DEFAULT_HANDSHAKE_DEADLINE_SECONDS,
    connection_deadline_seconds: float = DEFAULT_CONNECTION_DEADLINE_SECONDS,
) -> LaunchAuthorityHTTPServer:
    server_certificate = Path(server_certificate)
    server_private_key = Path(server_private_key)
    client_ca_certificate = Path(client_ca_certificate)
    certificate_bytes = _read_stable_regular_file(
        server_certificate,
        label="authority TLS server certificate",
        max_bytes=MAX_TLS_MATERIAL_BYTES,
        owner_only=False,
    )
    private_key_bytes = _read_stable_regular_file(
        server_private_key,
        label="authority TLS server private key",
        max_bytes=MAX_TLS_MATERIAL_BYTES,
        owner_only=True,
    )
    client_ca_bytes = _read_stable_regular_file(
        client_ca_certificate,
        label="authority TLS client CA certificate",
        max_bytes=MAX_TLS_MATERIAL_BYTES,
        owner_only=False,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(str(server_certificate), str(server_private_key))
    try:
        client_ca_data: str | bytes = client_ca_bytes.decode("ascii")
    except UnicodeDecodeError:
        client_ca_data = client_ca_bytes
    context.load_verify_locations(cadata=client_ca_data)
    for path, label, expected, owner_only in (
        (
            server_certificate,
            "authority TLS server certificate",
            certificate_bytes,
            False,
        ),
        (
            server_private_key,
            "authority TLS server private key",
            private_key_bytes,
            True,
        ),
        (
            client_ca_certificate,
            "authority TLS client CA certificate",
            client_ca_bytes,
            False,
        ),
    ):
        current = _read_stable_regular_file(
            path,
            label=label,
            max_bytes=MAX_TLS_MATERIAL_BYTES,
            owner_only=owner_only,
        )
        if not hmac.compare_digest(current, expected):
            raise AuthorityConfigurationError(
                f"{label} changed while the TLS context was created"
            )
    authority._assert_listener_startup_trust_snapshot()
    listener_lease_descriptor = authority.ledger.acquire_listener_lease()
    try:
        return LaunchAuthorityHTTPServer(
            address,
            authority,
            tls_context=context,
            allowed_source_cidrs=allowed_source_cidrs,
            max_handshakes=max_handshakes,
            max_handshakes_per_ip=max_handshakes_per_ip,
            max_issuance_workers=max_issuance_workers,
            max_issuance_workers_per_ip=max_issuance_workers_per_ip,
            handshake_deadline_seconds=handshake_deadline_seconds,
            connection_deadline_seconds=connection_deadline_seconds,
            listener_lease_descriptor=listener_lease_descriptor,
        )
    except Exception:
        authority.ledger.release_listener_lease(
            listener_lease_descriptor
        )
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Catchplate off-host launch authority",
        epilog=(EXTERNAL_ANTI_ROLLBACK_REQUIREMENT + " " + NETWORK_ADMISSION_BOUNDARY),
    )
    parser.add_argument(
        "--initialize-ledger",
        metavar="PATH",
        type=Path,
        help="create one new ledger and exit; never use this for normal service start",
    )
    parser.add_argument("--listen-host")
    parser.add_argument("--listen-port", type=int)
    parser.add_argument("--ledger", type=Path)
    parser.add_argument("--release-registry", type=Path)
    parser.add_argument("--authority-private-key", type=Path)
    parser.add_argument("--expected-authority-key-id")
    parser.add_argument("--expected-global-role-registry-sha256")
    parser.add_argument("--expected-global-role-registry-pins-sha256")
    parser.add_argument("--server-certificate", type=Path)
    parser.add_argument("--server-private-key", type=Path)
    parser.add_argument("--client-ca-certificate", type=Path)
    parser.add_argument("--monotonic-witness-url")
    parser.add_argument("--monotonic-witness-ca-certificate", type=Path)
    parser.add_argument("--monotonic-witness-client-certificate", type=Path)
    parser.add_argument("--monotonic-witness-client-private-key", type=Path)
    parser.add_argument("--monotonic-witness-expected-tls-spki-sha256")
    parser.add_argument("--monotonic-witness-signing-public-key", type=Path)
    parser.add_argument("--monotonic-witness-expected-signing-key-id")
    parser.add_argument("--monotonic-witness-identity-sha256")
    parser.add_argument("--monotonic-witness-administrative-domain-sha256")
    parser.add_argument("--monotonic-witness-store-assurance-sha256")
    parser.add_argument("--monotonic-witness-store-assurance-key-id")
    parser.add_argument(
        "--allowed-source-cidr",
        action="append",
        help="repeat for each canonical direct-peer IPv4 or IPv6 network",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    parser = build_parser()
    args = parser.parse_args(argv)
    service_arguments = {
        "--listen-host": args.listen_host,
        "--listen-port": args.listen_port,
        "--ledger": args.ledger,
        "--release-registry": args.release_registry,
        "--authority-private-key": args.authority_private_key,
        "--expected-authority-key-id": args.expected_authority_key_id,
        "--expected-global-role-registry-sha256": (
            args.expected_global_role_registry_sha256
        ),
        "--expected-global-role-registry-pins-sha256": (
            args.expected_global_role_registry_pins_sha256
        ),
        "--server-certificate": args.server_certificate,
        "--server-private-key": args.server_private_key,
        "--client-ca-certificate": args.client_ca_certificate,
        "--monotonic-witness-url": args.monotonic_witness_url,
        "--monotonic-witness-ca-certificate": (
            args.monotonic_witness_ca_certificate
        ),
        "--monotonic-witness-client-certificate": (
            args.monotonic_witness_client_certificate
        ),
        "--monotonic-witness-client-private-key": (
            args.monotonic_witness_client_private_key
        ),
        "--monotonic-witness-expected-tls-spki-sha256": (
            args.monotonic_witness_expected_tls_spki_sha256
        ),
        "--monotonic-witness-signing-public-key": (
            args.monotonic_witness_signing_public_key
        ),
        "--monotonic-witness-expected-signing-key-id": (
            args.monotonic_witness_expected_signing_key_id
        ),
        "--monotonic-witness-identity-sha256": (
            args.monotonic_witness_identity_sha256
        ),
        "--monotonic-witness-administrative-domain-sha256": (
            args.monotonic_witness_administrative_domain_sha256
        ),
        "--monotonic-witness-store-assurance-sha256": (
            args.monotonic_witness_store_assurance_sha256
        ),
        "--monotonic-witness-store-assurance-key-id": (
            args.monotonic_witness_store_assurance_key_id
        ),
        "--allowed-source-cidr": args.allowed_source_cidr,
    }
    if args.initialize_ledger is not None:
        supplied = sorted(name for name, value in service_arguments.items() if value)
        if supplied:
            parser.error(
                "--initialize-ledger is a one-time standalone operation and cannot be "
                "combined with service arguments"
            )
        try:
            LaunchAuthorityLedger(args.initialize_ledger, initialize=True)
        except AuthorityConfigurationError as exc:
            sys.stderr.write(f"launch-authority: ledger initialization failed: {exc}\n")
            return 2
        sys.stdout.write(
            f"initialized launch-authority ledger: {args.initialize_ledger}\n"
        )
        return 0
    missing = sorted(name for name, value in service_arguments.items() if value is None)
    if missing:
        parser.error("normal service mode requires " + ", ".join(missing))
    if not 1 <= args.listen_port <= 65535:
        raise SystemExit("--listen-port must be between 1 and 65535")
    try:
        signing_key = load_authority_signing_key(
            args.authority_private_key,
            expected_key_id=args.expected_authority_key_id,
        )
        authority = LaunchAuthority(
            registry_path=args.release_registry,
            ledger=LaunchAuthorityLedger(args.ledger),
            signing_key=signing_key,
            monotonic_witness=LaunchAuthorityMonotonicWitnessClient(
                url=args.monotonic_witness_url,
                ca_certificate=args.monotonic_witness_ca_certificate,
                client_certificate=args.monotonic_witness_client_certificate,
                client_private_key=args.monotonic_witness_client_private_key,
                expected_tls_spki_sha256=(
                    args.monotonic_witness_expected_tls_spki_sha256
                ),
                signing_public_key=args.monotonic_witness_signing_public_key,
                expected_signing_key_id=(
                    args.monotonic_witness_expected_signing_key_id
                ),
                witness_identity_sha256=(
                    args.monotonic_witness_identity_sha256
                ),
                administrative_domain_sha256=(
                    args.monotonic_witness_administrative_domain_sha256
                ),
                store_assurance_sha256=(
                    args.monotonic_witness_store_assurance_sha256
                ),
                store_assurance_key_id=(
                    args.monotonic_witness_store_assurance_key_id
                ),
            ),
            expected_global_role_registry_sha256=(
                args.expected_global_role_registry_sha256
            ),
            expected_global_role_registry_pins_sha256=(
                args.expected_global_role_registry_pins_sha256
            ),
        )
        server = create_https_server(
            (args.listen_host, args.listen_port),
            authority=authority,
            server_certificate=args.server_certificate,
            server_private_key=args.server_private_key,
            client_ca_certificate=args.client_ca_certificate,
            allowed_source_cidrs=args.allowed_source_cidr,
        )
    except (AuthorityConfigurationError, OSError, ssl.SSLError) as exc:
        sys.stderr.write(f"launch-authority: configuration failed: {exc}\n")
        return 2
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
