from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import stat
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from serverware.config import (
    DATA_DIR,
    PRODUCTION_IMAGE,
    RESPONSE_SIGNING_KEY_PATH,
    RESPONSE_SIGNING_PUBLIC_KEY_ID_PATH,
    RESPONSE_SIGNING_PUBLIC_KEY_PATH,
    ensure_data_dirs,
)


class ResponseIdentityPublicationError(RuntimeError):
    pass


_PUBLICATION_LOCK = threading.Lock()
_MAX_RESPONSE_SIGNING_KEY_BYTES = 64 * 1024
_PUBLICATION_REVALIDATE_SECONDS = 1.0
_PUBLICATION_LOCK_TIMEOUT_SECONDS = 1.0
_PUBLICATION_CACHE: tuple[str, str, bytes, bytes, float] | None = None


@dataclass
class _PendingPublication:
    path: Path
    content: bytes
    parent_fd: int
    parent_identity: tuple[int, int]
    target_snapshot: tuple[int, ...] | None
    temporary_name: str
    temporary_identity: tuple[int, int]
    committed: bool = False


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _read_stable_key_file(
    path: Path,
    *,
    label: str,
    max_bytes: int,
    allowed_modes: set[int],
    expected_uid: int | None,
) -> bytes:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise ResponseIdentityPublicationError(
            f"{label} requires no-follow file operations"
        )
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | no_follow
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
    except OSError as exc:
        raise ResponseIdentityPublicationError(
            f"{label} must be a readable non-symlink file"
        ) from exc
    try:
        opened = os.fstat(descriptor)
        mode = stat.S_IMODE(opened.st_mode)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise ResponseIdentityPublicationError(
                f"{label} must be a single-link regular file"
            )
        if mode not in allowed_modes:
            expected = " or ".join(f"{value:04o}" for value in sorted(allowed_modes))
            raise ResponseIdentityPublicationError(
                f"{label} must use mode {expected}"
            )
        if expected_uid is not None and opened.st_uid != expected_uid:
            raise ResponseIdentityPublicationError(
                f"{label} must be owned by UID {expected_uid}"
            )
        if not 1 <= opened.st_size <= max_bytes:
            raise ResponseIdentityPublicationError(
                f"{label} must contain between 1 and {max_bytes} bytes"
            )
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        completed = os.fstat(descriptor)
    except OSError as exc:
        raise ResponseIdentityPublicationError(
            f"{label} could not be read safely"
        ) from exc
    finally:
        os.close(descriptor)
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if identity(opened) != identity(completed) or len(payload) != opened.st_size:
        raise ResponseIdentityPublicationError(f"{label} changed while being read")
    return payload


def _load_response_key_file(
    path: Path, *, expected_uid: int
) -> Ed25519PrivateKey:
    payload = _read_stable_key_file(
        path,
        label="response signing private key",
        max_bytes=_MAX_RESPONSE_SIGNING_KEY_BYTES,
        allowed_modes={0o400, 0o600},
        expected_uid=expected_uid,
    )
    try:
        key = serialization.load_pem_private_key(payload, password=None)
    except (TypeError, ValueError) as exc:
        raise ResponseIdentityPublicationError(
            "response signing private key must be unencrypted PKCS8 PEM"
        ) from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ResponseIdentityPublicationError(
            "response signing private key must be Ed25519"
        )
    return key


def validate_response_signing_key_custody(
    private_path: Path,
    public_path: Path,
    key_id_path: Path,
    *,
    expected_private_uid: int | None = None,
) -> str:
    expected_private_uid = (
        os.geteuid() if expected_private_uid is None else expected_private_uid
    )
    private_key = _load_response_key_file(
        private_path, expected_uid=expected_private_uid
    )
    public_pem = _read_stable_key_file(
        public_path,
        label="response signing public key",
        max_bytes=_MAX_RESPONSE_SIGNING_KEY_BYTES,
        allowed_modes={0o444, 0o644},
        expected_uid=None,
    )
    key_id_bytes = _read_stable_key_file(
        key_id_path,
        label="response signing key ID",
        max_bytes=80,
        allowed_modes={0o444, 0o644},
        expected_uid=None,
    )
    public_key = private_key.public_key()
    expected_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    expected_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    expected_key_id = sha256_prefixed(expected_der)
    if public_pem != expected_pem:
        raise ResponseIdentityPublicationError(
            "response signing public key does not match the private key"
        )
    if key_id_bytes != (expected_key_id + "\n").encode("ascii"):
        raise ResponseIdentityPublicationError(
            "response signing key ID does not match the private key"
        )
    return expected_key_id


def _load_response_key() -> Ed25519PrivateKey:
    ensure_data_dirs()
    try:
        return _load_response_key_file(
            RESPONSE_SIGNING_KEY_PATH, expected_uid=os.geteuid()
        )
    except ResponseIdentityPublicationError:
        if RESPONSE_SIGNING_KEY_PATH.is_symlink() or RESPONSE_SIGNING_KEY_PATH.exists():
            raise
    if PRODUCTION_IMAGE:
        raise ResponseIdentityPublicationError(
            "production response signing private key must be provisioned"
        )
    key = Ed25519PrivateKey.generate()
    encoded = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise ResponseIdentityPublicationError(
            "response signing private-key creation requires no-follow file operations"
        )
    try:
        descriptor = os.open(
            RESPONSE_SIGNING_KEY_PATH,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | no_follow
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
    except FileExistsError:
        return _load_response_key_file(
            RESPONSE_SIGNING_KEY_PATH, expected_uid=os.geteuid()
        )
    except OSError as exc:
        raise ResponseIdentityPublicationError(
            "response signing private key could not be created safely"
        ) from exc
    try:
        written = 0
        while written < len(encoded):
            written += os.write(descriptor, encoded[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return _load_response_key_file(
        RESPONSE_SIGNING_KEY_PATH, expected_uid=os.geteuid()
    )


def _require_secure_open_flags() -> tuple[int, int]:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory is None:
        raise ResponseIdentityPublicationError(
            "response identity publication requires no-follow directory operations"
        )
    return no_follow, directory


def _validate_parent_descriptor(descriptor: int) -> os.stat_result:
    directory_stat = os.fstat(descriptor)
    mode = stat.S_IMODE(directory_stat.st_mode)
    if not stat.S_ISDIR(directory_stat.st_mode):
        raise ResponseIdentityPublicationError(
            "response identity publication parent must be a directory"
        )
    if (
        directory_stat.st_uid != os.getuid()
        or mode & 0o022
        or mode & 0o700 != 0o700
        or mode & 0o011 != 0o011
    ):
        raise ResponseIdentityPublicationError(
            "response identity publication parent must be owner-controlled and cross-UID traversable"
        )
    return directory_stat


def _open_secure_parent(path: Path, *, create: bool) -> tuple[int, tuple[int, int]]:
    if not path.is_absolute() or not path.name or ".." in path.parts:
        raise ResponseIdentityPublicationError(
            "response identity publication paths must be normalized absolute file paths"
        )
    no_follow, directory = _require_secure_open_flags()
    flags = os.O_RDONLY | directory | no_follow | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open("/", flags)
    try:
        for component in path.parent.parts[1:]:
            try:
                next_descriptor = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, 0o755, dir_fd=descriptor)
                    os.fsync(descriptor)
                except FileExistsError:
                    pass
                next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        directory_stat = _validate_parent_descriptor(descriptor)
        return descriptor, (directory_stat.st_dev, directory_stat.st_ino)
    except ResponseIdentityPublicationError:
        os.close(descriptor)
        raise
    except OSError as exc:
        os.close(descriptor)
        raise ResponseIdentityPublicationError(
            "response identity publication parent is unsafe or unavailable"
        ) from exc


def _target_snapshot(parent_fd: int, name: str) -> tuple[int, ...] | None:
    try:
        target_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ResponseIdentityPublicationError(
            "response identity publication target could not be inspected"
        ) from exc
    mode = stat.S_IMODE(target_stat.st_mode)
    if (
        not stat.S_ISREG(target_stat.st_mode)
        or target_stat.st_uid != os.getuid()
        or target_stat.st_nlink != 1
        or mode & ~0o644
    ):
        raise ResponseIdentityPublicationError(
            "response identity publication target must be an owner-controlled regular file"
        )
    return (
        target_stat.st_dev,
        target_stat.st_ino,
        target_stat.st_mode,
        target_stat.st_uid,
        target_stat.st_nlink,
        target_stat.st_size,
        target_stat.st_mtime_ns,
        target_stat.st_ctime_ns,
    )


def _target_content_matches(path: Path, expected: bytes) -> bool:
    parent_fd, _parent_identity = _open_secure_parent(path, create=True)
    descriptor: int | None = None
    try:
        snapshot = _target_snapshot(parent_fd, path.name)
        if snapshot is None:
            return False
        no_follow, _directory = _require_secure_open_flags()
        descriptor = os.open(
            path.name,
            os.O_RDONLY
            | no_follow
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=parent_fd,
        )
        before = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != snapshot:
            raise ResponseIdentityPublicationError(
                "response identity publication target changed before comparison"
            )
        if stat.S_IMODE(before.st_mode) != 0o644:
            return False
        payload = bytearray()
        while len(payload) <= len(expected):
            chunk = os.read(descriptor, len(expected) + 1 - len(payload))
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ResponseIdentityPublicationError(
                "response identity publication target changed during comparison"
            )
        if _target_snapshot(parent_fd, path.name) != snapshot:
            raise ResponseIdentityPublicationError(
                "response identity publication pathname changed during comparison"
            )
        return bytes(payload) == expected
    except ResponseIdentityPublicationError:
        raise
    except OSError as exc:
        raise ResponseIdentityPublicationError(
            "response identity publication target could not be compared safely"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)


def _acquire_publication_process_lock(path: Path) -> int:
    descriptor, identity = _open_secure_parent(path, create=True)
    reopened_fd: int | None = None
    try:
        deadline = time.monotonic() + _PUBLICATION_LOCK_TIMEOUT_SECONDS
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError as exc:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ResponseIdentityPublicationError(
                        "response identity publication process lock timed out"
                    ) from exc
                time.sleep(min(0.01, remaining))
        current = _validate_parent_descriptor(descriptor)
        reopened_fd, reopened_identity = _open_secure_parent(path, create=False)
        if (
            (current.st_dev, current.st_ino) != identity
            or reopened_identity != identity
        ):
            raise ResponseIdentityPublicationError(
                "response identity publication lock directory changed"
            )
        return descriptor
    except ResponseIdentityPublicationError:
        os.close(descriptor)
        raise
    except OSError as exc:
        os.close(descriptor)
        raise ResponseIdentityPublicationError(
            "response identity publication process lock failed"
        ) from exc
    finally:
        if reopened_fd is not None:
            os.close(reopened_fd)


def _verify_parent_mapping(pending: _PendingPublication) -> None:
    current_stat = _validate_parent_descriptor(pending.parent_fd)
    if (current_stat.st_dev, current_stat.st_ino) != pending.parent_identity:
        raise ResponseIdentityPublicationError(
            "response identity publication parent changed during publication"
        )
    reopened_fd: int | None = None
    try:
        reopened_fd, reopened_identity = _open_secure_parent(pending.path, create=False)
        if reopened_identity != pending.parent_identity:
            raise ResponseIdentityPublicationError(
                "response identity publication parent path changed during publication"
            )
    except OSError as exc:
        raise ResponseIdentityPublicationError(
            "response identity publication parent path changed during publication"
        ) from exc
    finally:
        if reopened_fd is not None:
            os.close(reopened_fd)


def _prepare_publication(path: Path, content: bytes) -> _PendingPublication:
    parent_fd, parent_identity = _open_secure_parent(path, create=True)
    temporary_name = f".serverware-response-{uuid.uuid4().hex}.tmp"
    temporary_fd: int | None = None
    try:
        target_snapshot = _target_snapshot(parent_fd, path.name)
        no_follow, _directory = _require_secure_open_flags()
        temporary_fd = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | no_follow
            | getattr(os, "O_CLOEXEC", 0),
            0o644,
            dir_fd=parent_fd,
        )
        os.fchmod(temporary_fd, 0o644)
        temporary_stat = os.fstat(temporary_fd)
        if (
            not stat.S_ISREG(temporary_stat.st_mode)
            or temporary_stat.st_uid != os.getuid()
            or temporary_stat.st_nlink != 1
            or stat.S_IMODE(temporary_stat.st_mode) & ~0o644
        ):
            raise ResponseIdentityPublicationError(
                "response identity publication temporary file is unsafe"
            )
        offset = 0
        while offset < len(content):
            written = os.write(temporary_fd, content[offset:])
            if written <= 0:
                raise OSError("short response identity publication write")
            offset += written
        os.fsync(temporary_fd)
        temporary_stat = os.fstat(temporary_fd)
        temporary_identity = (temporary_stat.st_dev, temporary_stat.st_ino)
        os.close(temporary_fd)
        temporary_fd = None
        return _PendingPublication(
            path=path,
            content=content,
            parent_fd=parent_fd,
            parent_identity=parent_identity,
            target_snapshot=target_snapshot,
            temporary_name=temporary_name,
            temporary_identity=temporary_identity,
        )
    except ResponseIdentityPublicationError:
        if temporary_fd is not None:
            os.close(temporary_fd)
        try:
            os.unlink(temporary_name, dir_fd=parent_fd)
        except OSError:
            pass
        os.close(parent_fd)
        raise
    except OSError as exc:
        if temporary_fd is not None:
            os.close(temporary_fd)
        try:
            os.unlink(temporary_name, dir_fd=parent_fd)
        except OSError:
            pass
        os.close(parent_fd)
        raise ResponseIdentityPublicationError(
            "response identity publication could not be staged"
        ) from exc


def _read_published_content(pending: _PendingPublication) -> bytes:
    no_follow, _directory = _require_secure_open_flags()
    descriptor: int | None = None
    try:
        descriptor = os.open(
            pending.path.name,
            os.O_RDONLY
            | no_follow
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=pending.parent_fd,
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & ~0o644
            or (before.st_dev, before.st_ino) != pending.temporary_identity
        ):
            raise ResponseIdentityPublicationError(
                "response identity publication target changed after replacement"
            )
        payload = bytearray()
        while len(payload) <= len(pending.content):
            chunk = os.read(descriptor, len(pending.content) + 1 - len(payload))
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ResponseIdentityPublicationError(
                "response identity publication target changed while it was verified"
            )
        return bytes(payload)
    except ResponseIdentityPublicationError:
        raise
    except OSError as exc:
        raise ResponseIdentityPublicationError(
            "response identity publication target could not be verified"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _commit_publication(pending: _PendingPublication) -> None:
    _verify_parent_mapping(pending)
    if _target_snapshot(pending.parent_fd, pending.path.name) != pending.target_snapshot:
        raise ResponseIdentityPublicationError(
            "response identity publication target changed before replacement"
        )
    try:
        os.replace(
            pending.temporary_name,
            pending.path.name,
            src_dir_fd=pending.parent_fd,
            dst_dir_fd=pending.parent_fd,
        )
        pending.committed = True
        os.fsync(pending.parent_fd)
    except OSError as exc:
        raise ResponseIdentityPublicationError(
            "response identity publication replacement failed"
        ) from exc
    if _read_published_content(pending) != pending.content:
        raise ResponseIdentityPublicationError(
            "response identity publication produced unexpected bytes"
        )
    _verify_parent_mapping(pending)


def _cleanup_publication(pending: _PendingPublication) -> None:
    if not pending.committed:
        try:
            os.unlink(pending.temporary_name, dir_fd=pending.parent_fd)
        except OSError:
            pass
    os.close(pending.parent_fd)


def _normalized_absolute_path(path: Path) -> str:
    return os.path.normpath(os.path.abspath(os.fspath(path)))


def _configured_publication_paths() -> tuple[Path, Path] | None:
    public_path = RESPONSE_SIGNING_PUBLIC_KEY_PATH
    key_id_path = RESPONSE_SIGNING_PUBLIC_KEY_ID_PATH
    if public_path is None and key_id_path is None:
        return None
    if public_path is None or key_id_path is None:
        raise ResponseIdentityPublicationError(
            "response signing public-key PEM and ID paths must be configured together"
        )
    if any(
        not path.is_absolute() or not path.name or ".." in path.parts
        for path in (public_path, key_id_path)
    ):
        raise ResponseIdentityPublicationError(
            "response identity publication paths must be normalized absolute file paths"
        )
    output_paths = tuple(
        _normalized_absolute_path(path) for path in (public_path, key_id_path)
    )
    private_path = _normalized_absolute_path(RESPONSE_SIGNING_KEY_PATH)
    casefolded_outputs = {path.casefold() for path in output_paths}
    try:
        real_outputs = {os.path.realpath(path) for path in output_paths}
        private_real_path = os.path.realpath(private_path)
    except OSError as exc:
        raise ResponseIdentityPublicationError(
            "response identity publication paths could not be resolved safely"
        ) from exc
    if (
        len(casefolded_outputs) != 2
        or private_path.casefold() in casefolded_outputs
        or len(real_outputs) != 2
        or private_real_path in real_outputs
    ):
        raise ResponseIdentityPublicationError(
            "response identity publication paths must be dedicated and distinct"
        )
    return public_path, key_id_path


def _publish_response_identity(public_pem: bytes, key_id: str) -> None:
    global _PUBLICATION_CACHE

    configured_paths = _configured_publication_paths()
    if configured_paths is None:
        return
    public_path, key_id_path = configured_paths
    key_id_bytes = key_id.encode("ascii") + b"\n"
    cache_identity = (
        _normalized_absolute_path(public_path),
        _normalized_absolute_path(key_id_path),
        public_pem,
        key_id_bytes,
    )
    cached = _PUBLICATION_CACHE
    if (
        cached is not None
        and cached[:4] == cache_identity
        and time.monotonic() < cached[4]
    ):
        return

    pending: list[_PendingPublication] = []
    if not _PUBLICATION_LOCK.acquire(timeout=_PUBLICATION_LOCK_TIMEOUT_SECONDS):
        raise ResponseIdentityPublicationError(
            "response identity publication thread lock timed out"
        )
    try:
        cached = _PUBLICATION_CACHE
        if (
            cached is not None
            and cached[:4] == cache_identity
            and time.monotonic() < cached[4]
        ):
            return
        _PUBLICATION_CACHE = None
        process_lock_fd = _acquire_publication_process_lock(public_path)
        cleanup_error: Exception | None = None
        try:
            already_current = (
                _target_content_matches(public_path, public_pem)
                and _target_content_matches(key_id_path, key_id_bytes)
                and _target_content_matches(public_path, public_pem)
                and _target_content_matches(key_id_path, key_id_bytes)
            )
            if not already_current:
                pending.append(_prepare_publication(public_path, public_pem))
                pending.append(_prepare_publication(key_id_path, key_id_bytes))
                for publication in pending:
                    _verify_parent_mapping(publication)
                    if (
                        _target_snapshot(publication.parent_fd, publication.path.name)
                        != publication.target_snapshot
                    ):
                        raise ResponseIdentityPublicationError(
                            "response identity publication target changed while files were staged"
                        )
                for publication in pending:
                    _commit_publication(publication)
        finally:
            for publication in pending:
                try:
                    _cleanup_publication(publication)
                except Exception as exc:
                    if cleanup_error is None:
                        cleanup_error = exc
            try:
                fcntl.flock(process_lock_fd, fcntl.LOCK_UN)
            except Exception as exc:
                if cleanup_error is None:
                    cleanup_error = exc
            finally:
                try:
                    os.close(process_lock_fd)
                except Exception as exc:
                    if cleanup_error is None:
                        cleanup_error = exc
            if cleanup_error is not None:
                raise cleanup_error
        _PUBLICATION_CACHE = (*cache_identity, time.monotonic() + _PUBLICATION_REVALIDATE_SECONDS)
    finally:
        _PUBLICATION_LOCK.release()


def _retire_legacy_response_key() -> None:
    legacy_path = DATA_DIR / "response-signing-ed25519.pem"
    if os.path.abspath(legacy_path) == os.path.abspath(RESPONSE_SIGNING_KEY_PATH):
        return
    try:
        legacy_path.unlink(missing_ok=True)
    except OSError as exc:
        raise ResponseIdentityPublicationError(
            "legacy response signing key could not be retired"
        ) from exc


def response_public_key_info() -> dict[str, str]:
    _configured_publication_paths()
    public_key = _load_response_key().public_key()
    pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_id = sha256_prefixed(der)
    _publish_response_identity(pem, key_id)
    _retire_legacy_response_key()
    return {"pem": pem.decode("ascii"), "spki_sha256": key_id}


def response_statement(
    *,
    method: str,
    path: str,
    query: str,
    status_code: int,
    body: bytes,
    nonce: str | None,
    context: dict[str, Any],
) -> dict[str, Any]:
    key_info = response_public_key_info()
    return {
        "version": "serverware.responseSignature/v1",
        "issued_at_ms": int(time.time() * 1000),
        "request": {
            "method": method.upper(),
            "path": path,
            "query": query,
        },
        "status_code": status_code,
        "body_sha256": sha256_prefixed(body),
        "nonce": nonce,
        "response_signing_key_id": key_info["spki_sha256"],
        "context": context,
    }


def sign_statement(statement: dict[str, Any]) -> str:
    key = _load_response_key()
    return "ed25519:" + b64e(key.sign(canonical_json(statement).encode("utf-8")))


def response_signature_headers(statement: dict[str, Any]) -> dict[str, str]:
    encoded_statement = b64e(canonical_json(statement).encode("utf-8"))
    signature = sign_statement(statement)
    return {
        "X-Serverware-Response-Key-Id": str(statement["response_signing_key_id"]),
        "X-Serverware-Response-Body-SHA256": str(statement["body_sha256"]),
        "X-Serverware-Response-Statement-SHA256": sha256_prefixed(canonical_json(statement).encode("utf-8")),
        "X-Serverware-Response-Statement-B64": encoded_statement,
        "X-Serverware-Response-Signature": signature,
    }
