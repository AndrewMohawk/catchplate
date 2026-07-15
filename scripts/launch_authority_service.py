#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import select
import secrets
import socket
import sqlite3
import ssl
import stat
import sys
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(_SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIRECTORY))

import launch_authorization as protocol  # noqa: E402


REGISTRY_API_VERSION = "serverware.launchAuthorityReleaseRegistry/v1"
REGISTRY_KIND = "ProductionLaunchAuthorityReleaseRegistry"
AUTHORIZATION_PATH = "/v1/launch-authorizations"
REQUEST_CONTENT_TYPE = "application/serverware.launch-authorization-request+json"
RESPONSE_CONTENT_TYPE = "application/serverware.launch-authorization+json"
MAX_REQUEST_BYTES = 16 * 1024
MAX_REGISTRY_BYTES = 8 * 1024 * 1024
MAX_REGISTRY_ENTRIES = 4096
MAX_KEY_BYTES = 16 * 1024
MAX_TLS_MATERIAL_BYTES = 1024 * 1024
DEFAULT_VALIDITY_SECONDS = 30
DEFAULT_CONNECTION_DEADLINE_SECONDS = 5.0
DEFAULT_HANDSHAKE_DEADLINE_SECONDS = 2.0
DEFAULT_MAX_HANDSHAKES = 32
DEFAULT_MAX_HANDSHAKES_PER_IP = 2
DEFAULT_MAX_ISSUANCE_WORKERS = 16
DEFAULT_MAX_ISSUANCE_WORKERS_PER_IP = 4
LEDGER_SCHEMA_VERSION = 4
EXTERNAL_ANTI_ROLLBACK_REQUIREMENT = (
    "A correctly matched restore of an older SQLite ledger and older registry cannot "
    "be detected locally; production must compare ledger state with an external "
    "monotonic anti-rollback checkpoint."
)
NETWORK_ADMISSION_BOUNDARY = (
    "Source CIDR admission uses the direct TCP peer address and is defense in depth; "
    "production must also enforce equivalent upstream firewall/routing policy and "
    "must not place an address-rewriting proxy in front of the authority."
)

_REGISTRY_FIELDS = frozenset({"apiVersion", "kind", "generation", "releases"})
_ENTRY_BINDING_FIELDS = (
    "deploymentAudience",
    "deploymentIdentitySha256",
    "releaseSequence",
    "rollbackEpoch",
    "manifestSha256",
    "releaseProvenanceSha256",
    "provenanceDigest",
    "sourceTreeDigest",
    "launcherSha256",
    "reproducibleBuildVerificationSha256",
)
_CONTENT_TUPLE_FIELDS = (
    "manifestSha256",
    "releaseProvenanceSha256",
    "provenanceDigest",
    "sourceTreeDigest",
    "launcherSha256",
    "reproducibleBuildVerificationSha256",
)
_RELAY_CERTIFICATE_FIELD = "relayClientCertificateSha256"
_ENTRY_FIELDS = frozenset(
    (*_ENTRY_BINDING_FIELDS, _RELAY_CERTIFICATE_FIELD, "enabled", "revoked")
)


class AuthorityConfigurationError(ValueError):
    pass


class AuthorityError(ValueError):
    def __init__(self, code: str, message: str, *, http_status: int) -> None:
        super().__init__(message)
        self.code = code
        self.http_status = http_status


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
        synthetic_request = {
            "apiVersion": protocol.REQUEST_API_VERSION,
            "kind": protocol.REQUEST_KIND,
            "launcherNonce": "0" * 64,
            "bootIdSha256": "sha256:" + "0" * 64,
            **binding,
        }
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
                b"serverware.launchAuthorityRegistryBinding/v1\0", binding
            ),
            content_tuple_sha256=_sha256_domain(
                b"serverware.launchAuthorityReleaseTuple/v1\0",
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
            b"serverware.launchAuthorityRegistryBinding/v1\0", binding
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
            binding_sha256 TEXT NOT NULL,
            content_tuple_sha256 TEXT NOT NULL,
            relay_client_certificate_sha256 TEXT NOT NULL,
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


class LaunchAuthority:
    def __init__(
        self,
        *,
        registry_path: Path,
        ledger: LaunchAuthorityLedger,
        signing_key: AuthoritySigningKey,
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
        self.validity_seconds = validity_seconds

    def issue(
        self,
        raw_request: bytes,
        *,
        peer_certificate_sha256: str,
        now_unix_seconds: int | None = None,
    ) -> bytes:
        if type(raw_request) is not bytes or len(raw_request) > MAX_REQUEST_BYTES:
            raise AuthorityError(
                "INVALID_REQUEST", "launch request frame is invalid", http_status=400
            )
        try:
            _require_sha256_digest(
                peer_certificate_sha256, label="authenticated relay certificate digest"
            )
        except AuthorityConfigurationError as exc:
            raise AuthorityError(
                "CLIENT_CERTIFICATE_IDENTITY_INVALID",
                "authenticated relay certificate identity is invalid",
                http_status=403,
            ) from exc
        try:
            request = protocol.validate_launch_authorization_request(
                protocol.require_canonical_json_bytes(
                    raw_request, label="launch authorization request"
                )
            )
            request_sha256 = protocol.launch_authorization_request_sha256(request)
        except protocol.LaunchAuthorizationError as exc:
            raise AuthorityError(
                "INVALID_REQUEST",
                "launch request is not strict canonical JSON",
                http_status=400,
            ) from exc
        now = int(time.time()) if now_unix_seconds is None else now_unix_seconds
        if (
            type(now) is not int
            or not 1 <= now <= protocol.MAX_SAFE_INTEGER - self.validity_seconds
        ):
            raise AuthorityError(
                "INVALID_TIME", "authority clock is invalid", http_status=500
            )

        try:
            session = self.ledger.open_session()
        except AuthorityConfigurationError as exc:
            raise AuthorityError(
                "LEDGER_UNAVAILABLE",
                "authority ledger is unavailable",
                http_status=503,
            ) from exc
        connection = session.connection
        registry_state_changed = False
        response_bytes: bytes | None = None
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                registry = ReleaseRegistry.from_path(self.registry_path)
            except AuthorityConfigurationError as exc:
                raise AuthorityError(
                    "REGISTRY_UNAVAILABLE",
                    "release registry could not be reloaded safely",
                    http_status=503,
                ) from exc
            registry_state_changed = self._record_registry_state(connection, registry)
            existing = connection.execute(
                """
                SELECT request_sha256, request_bytes, envelope_bytes,
                       relay_client_certificate_sha256
                FROM authorizations WHERE launcher_nonce = ?
                """,
                (request["launcherNonce"],),
            ).fetchone()
            entry = registry.lookup(
                request, peer_certificate_sha256=peer_certificate_sha256
            )
            self._enforce_high_water(connection, request, entry)
            if existing is not None:
                if not hmac.compare_digest(
                    existing["relay_client_certificate_sha256"],
                    peer_certificate_sha256,
                ):
                    raise AuthorityError(
                        "RELAY_CLIENT_CERTIFICATE_MISMATCH",
                        "nonce is bound to a different authenticated relay certificate",
                        http_status=403,
                    )
                if not (
                    hmac.compare_digest(existing["request_sha256"], request_sha256)
                    and hmac.compare_digest(
                        bytes(existing["request_bytes"]), raw_request
                    )
                ):
                    raise AuthorityError(
                        "NONCE_COLLISION",
                        "launcher nonce was already used for a different request",
                        http_status=409,
                    )
                response_bytes = bytes(existing["envelope_bytes"])
            else:
                authorization_id = secrets.token_hex(32)
                envelope = protocol.sign_launch_authorization(
                    request,
                    private_key=self.signing_key.private_key,
                    authorization_id=authorization_id,
                    issued_at_unix_seconds=now,
                    expires_at_unix_seconds=now + self.validity_seconds,
                )
                response_bytes = protocol.canonical_json_bytes(envelope)
                connection.execute(
                    """
                    INSERT INTO authorizations (
                        launcher_nonce, request_sha256, request_bytes, envelope_bytes,
                        authorization_id, deployment_audience,
                        deployment_identity_sha256, release_sequence, rollback_epoch,
                        binding_sha256, content_tuple_sha256,
                        relay_client_certificate_sha256,
                        issued_at_unix_seconds, expires_at_unix_seconds
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        request["launcherNonce"],
                        request_sha256,
                        raw_request,
                        response_bytes,
                        authorization_id,
                        request["deploymentAudience"],
                        request["deploymentIdentitySha256"],
                        request["releaseSequence"],
                        request["rollbackEpoch"],
                        entry.binding_sha256,
                        entry.content_tuple_sha256,
                        peer_certificate_sha256,
                        now,
                        now + self.validity_seconds,
                    ),
                )
                self._persist_high_water(connection, request, entry)
            self._commit_with_identity(session)
        except AuthorityError:
            if registry_state_changed:
                try:
                    self._commit_with_identity(session)
                except (AuthorityConfigurationError, sqlite3.Error) as exc:
                    raise AuthorityError(
                        "LEDGER_UNAVAILABLE",
                        "authority ledger changed while registry state was persisted",
                        http_status=503,
                    ) from exc
            else:
                try:
                    connection.rollback()
                except sqlite3.Error as exc:
                    raise AuthorityError(
                        "LEDGER_UNAVAILABLE",
                        "authority ledger rollback failed",
                        http_status=503,
                    ) from exc
            raise
        except AuthorityConfigurationError as exc:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise AuthorityError(
                "LEDGER_UNAVAILABLE",
                "authority ledger pathname changed during issuance",
                http_status=503,
            ) from exc
        except (sqlite3.Error, protocol.LaunchAuthorizationError) as exc:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise AuthorityError(
                "AUTHORITY_FAILURE",
                "launch authority could not persist issuance",
                http_status=503,
            ) from exc
        finally:
            try:
                connection.close()
            except sqlite3.Error:
                response_bytes = None
        if response_bytes is None:
            raise AuthorityError(
                "LEDGER_UNAVAILABLE",
                "authority ledger did not release a durable authorization",
                http_status=503,
            )
        return response_bytes

    @staticmethod
    def _commit_with_identity(session: LedgerSession) -> None:
        session.assert_path_identity()
        session.connection.commit()
        session.assert_path_identity()

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
                   content_tuple_sha256
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
            if not hmac.compare_digest(entry.binding_sha256, current["binding_sha256"]):
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
    ) -> None:
        connection.execute(
            """
            INSERT INTO deployment_high_water (
                deployment_audience, deployment_identity_sha256,
                release_sequence, rollback_epoch, binding_sha256,
                content_tuple_sha256
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (deployment_audience, deployment_identity_sha256)
            DO UPDATE SET
                release_sequence = excluded.release_sequence,
                rollback_epoch = excluded.rollback_epoch,
                binding_sha256 = excluded.binding_sha256,
                content_tuple_sha256 = excluded.content_tuple_sha256
            """,
            (
                request["deploymentAudience"],
                request["deploymentIdentitySha256"],
                request["releaseSequence"],
                request["rollbackEpoch"],
                entry.binding_sha256,
                entry.content_tuple_sha256,
            ),
        )
        connection.execute(
            """
            INSERT INTO seen_release_tuples (
                deployment_audience, deployment_identity_sha256,
                content_tuple_sha256, first_release_sequence,
                last_release_sequence, max_rollback_epoch
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (
                deployment_audience, deployment_identity_sha256,
                content_tuple_sha256
            ) DO UPDATE SET
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
        super().__init__(address, LaunchAuthorityRequestHandler)

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
        handshake_deadline = min(
            deadline, time.monotonic() + self.handshake_deadline_seconds
        )
        connection: socket.socket = raw_socket
        deadline_timer: threading.Timer | None = None
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
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

            deadline_timer = threading.Timer(
                _remaining_deadline_seconds(deadline), expire_connection
            )
            deadline_timer.daemon = True
            deadline_timer.start()
            self._worker_state.deadline = deadline
            self.finish_request(connection, client_address)
        except (OSError, ssl.SSLError, TimeoutError):
            pass
        except Exception:
            self.handle_error(connection, client_address)
        finally:
            if deadline_timer is not None:
                deadline_timer.cancel()
            if hasattr(self._worker_state, "deadline"):
                del self._worker_state.deadline
            self.shutdown_request(connection)
            if handshake_admitted:
                self._release_handshake(source)
            if issuance_admitted:
                self._release_issuance(source)

    def current_connection_deadline(self) -> float:
        deadline = getattr(self._worker_state, "deadline", None)
        if not isinstance(deadline, float):
            raise RuntimeError("authority request is outside a bounded worker")
        return deadline


class LaunchAuthorityRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ServerwareLaunchAuthority/1"
    sys_version = ""

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
            self._set_deadline_timeout()
            body = self.rfile.read(length)
        except (OSError, TimeoutError):
            self._send_error(408, "REQUEST_TIMEOUT")
            return
        if len(body) != length:
            self._send_error(400, "REQUEST_TRUNCATED")
            return
        self._set_deadline_timeout()
        try:
            response = self.authority_server.authority.issue(
                body,
                peer_certificate_sha256=der_certificate_sha256(peer),
            )
        except AuthorityError as exc:
            self._send_error(exc.http_status, exc.code)
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
            _remaining_deadline_seconds(
                self.authority_server.current_connection_deadline()
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
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Serverware off-host launch authority",
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
    parser.add_argument("--server-certificate", type=Path)
    parser.add_argument("--server-private-key", type=Path)
    parser.add_argument("--client-ca-certificate", type=Path)
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
        "--server-certificate": args.server_certificate,
        "--server-private-key": args.server_private_key,
        "--client-ca-certificate": args.client_ca_certificate,
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
