"""Application-only provider key, independent of runtime configuration imports.

The setup owner supplies full development admission and proves absence of managed
setup/audit history before initialize_first. A missing file is not that proof.
Only explicit first Prepare may create/recover a key; readers never initialize.
The deployment owner must verify that this separate directory is not gate-shared.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import stat
import uuid

FILENAME = "provider-key.json"
SCHEMA = "serverware.operatorProviderKey/v1"
KEY_SOURCE = "operator-provider-key-v1"
_ERROR = "operator provider key unavailable"
_MAX_RECORD = 512


class ProviderKeyError(RuntimeError):
    """Fixed failure; never contains paths, key bytes or record contents."""


def _require(value):
    if not value:
        raise ProviderKeyError(_ERROR)


def _environment():
    return tuple(sorted((name, value) for name, value in os.environ.items()
        if name.startswith("SERVERWARE_") and name != "SERVERWARE_CONTROL_PLANE_STARTUP_VALIDATED_PID"))


def _process():
    return os.getpid(), os.geteuid(), os.getegid()


def _path(value):
    _require(isinstance(value, (str, Path)))
    result = Path(value)
    _require(result.is_absolute() and result != Path("/") and ".." not in result.parts
        and str(result) == str(value) and not any(ord(char) < 33 for char in str(result)))
    return result


def _uuid(value):
    return type(value) is str and str(uuid.UUID(value)) == value


def _directory_identity(info):
    _require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
        and stat.S_IMODE(info.st_mode) == 0o700)
    return info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode


def _file_identity(info):
    _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
        and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
        and 1 <= info.st_size <= _MAX_RECORD)
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


@contextmanager
def _open_directory(path):
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_DIRECTORY
    descriptor = os.open("/", flags)
    try:
        for part in path.parts[1:]:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        _directory_identity(os.fstat(descriptor))
        yield descriptor
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class DirectoryAdmission:
    """Internal filesystem admission, not development/HTTP/activation authority."""
    path: Path = field(repr=False)
    data_directory: Path = field(repr=False)
    process: tuple[int, int, int]
    environment: tuple[tuple[str, str], ...] = field(repr=False)
    directory_identity: tuple[int, ...] = field(repr=False)
    data_identity: tuple[int, ...] = field(repr=False)


@dataclass(frozen=True)
class KeyAdmission:
    owner_id: str
    material: bytes = field(repr=False)
    directory: DirectoryAdmission = field(repr=False)
    identity: tuple[int, ...] = field(repr=False)
    digest: bytes = field(repr=False)
    descriptor: int = field(repr=False)


def _check_directory(admission, descriptor):
    _require(type(admission) is DirectoryAdmission and admission.process == _process()
        and admission.environment == _environment())
    with _open_directory(admission.path) as current, _open_directory(admission.data_directory) as data:
        _require(_directory_identity(os.fstat(current)) == admission.directory_identity
            and _directory_identity(os.fstat(descriptor)) == admission.directory_identity
            and _directory_identity(os.fstat(data)) == admission.data_identity)
    # Bounded listing: no other key, temp file or unrelated custody is adopted.
    with os.scandir(descriptor) as entries:
        for index, entry in enumerate(entries):
            _require(index == 0 and entry.name == FILENAME)


def admit_directory(path: str | Path, *, data_directory: str | Path) -> DirectoryAdmission:
    """Pin existing, separate private directories; never create directories/files."""
    try:
        path, data = _path(path), _path(data_directory)
        _require(not path.is_relative_to(data) and not data.is_relative_to(path))
        environment, process = _environment(), _process()
        with _open_directory(path) as descriptor, _open_directory(data) as data_fd:
            identity, data_identity = (_directory_identity(os.fstat(descriptor)),
                _directory_identity(os.fstat(data_fd)))
            _require(identity[:2] != data_identity[:2])
            result = DirectoryAdmission(path, data, process, environment, identity, data_identity)
            _check_directory(result, descriptor)
            return result
    except (OSError, ValueError, TypeError, RuntimeError):
        raise ProviderKeyError(_ERROR) from None


def _canonical(record):
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"


def _read(descriptor):
    before = _file_identity(os.fstat(descriptor))
    raw = os.pread(descriptor, _MAX_RECORD + 1, 0)
    _require(len(raw) == before[6] and _file_identity(os.fstat(descriptor)) == before)
    record = json.loads(raw)
    _require(type(record) is dict and set(record) == {"schema", "owner_id", "key"}
        and record["schema"] == SCHEMA and _uuid(record["owner_id"]) and type(record["key"]) is str)
    material = base64.b64decode(record["key"], validate=True)
    _require(len(material) == 32 and base64.b64encode(material).decode("ascii") == record["key"]
        and _canonical(record) == raw)
    return record["owner_id"], material, before, hashlib.sha256(raw).digest()


def _pin(admission, directory, owner_id=None):
    descriptor = os.open(FILENAME, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        dir_fd=directory)
    try:
        found_owner, material, identity, digest = _read(descriptor)
        _require(owner_id is None or found_owner == owner_id)
        result = KeyAdmission(found_owner, material, admission, identity, digest, descriptor)
        _check_pin(result, directory)
        descriptor = None  # Lifetime pin; close_pin is explicit cleanup, never replacement.
        return result
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _check_pin(admission, directory):
    _require(type(admission) is KeyAdmission and type(admission.descriptor) is int
        and admission.descriptor >= 0 and _uuid(admission.owner_id)
        and type(admission.material) is bytes and len(admission.material) == 32)
    _check_directory(admission.directory, directory)
    owner, material, identity, digest = _read(admission.descriptor)
    _require(owner == admission.owner_id and identity == admission.identity
        and hmac.compare_digest(material, admission.material) and hmac.compare_digest(digest, admission.digest)
        and _file_identity(os.stat(FILENAME, dir_fd=directory, follow_symlinks=False)) == identity)
    _check_directory(admission.directory, directory)


def read_existing_pinned(admission: DirectoryAdmission, owner_id: str) -> KeyAdmission:
    """Read only this exact owner; absent/malformed retained state never initializes."""
    try:
        _require(type(admission) is DirectoryAdmission and _uuid(owner_id))
        with _open_directory(admission.path) as directory:
            _check_directory(admission, directory)
            return _pin(admission, directory, owner_id)
    except (OSError, ValueError, TypeError, RuntimeError):
        raise ProviderKeyError(_ERROR) from None


def check_pin(admission: KeyAdmission) -> None:
    """Recheck process/environment, both paths and the retained key inode/content."""
    try:
        _require(type(admission) is KeyAdmission and type(admission.directory) is DirectoryAdmission)
        with _open_directory(admission.directory.path) as directory:
            _check_pin(admission, directory)
    except (OSError, ValueError, TypeError, RuntimeError):
        raise ProviderKeyError(_ERROR) from None


def close_pin(admission: KeyAdmission) -> None:
    """Release this admission's descriptor; closed admissions cannot be reused."""
    _require(type(admission) is KeyAdmission and type(admission.descriptor) is int
        and admission.descriptor >= -1)
    descriptor = admission.descriptor
    if descriptor >= 0:
        object.__setattr__(admission, "descriptor", -1)
        try:
            os.close(descriptor)
        except OSError:
            raise ProviderKeyError(_ERROR) from None


def initialize_first(admission: DirectoryAdmission, conn: sqlite3.Connection, *,
        no_retained_provider_state: bool) -> KeyAdmission:
    """Explicit Prepare only: durable no-overwrite creation or valid orphan reuse.

    Caller must first strictly prove no managed setup/audit history in its real
    BEGIN IMMEDIATE transaction. This module additionally refuses any retained
    provider-custody namespace. A failed DB commit may leave a valid orphan key;
    only another explicit first Prepare with the same proof may reuse it.
    """
    return _initialize_first(admission, conn, no_retained_provider_state=no_retained_provider_state,
        x_configuration=False)


def initialize_first_x(admission: DirectoryAdmission, conn: sqlite3.Connection, *,
        no_retained_provider_state: bool) -> KeyAdmission:
    """First X save only, with its separate application-only key directory.

    The X configuration owner proves its complete history/audit/custody absence
    before calling. Google custody may coexist in the database, but the caller
    must admit a different, non-nested key directory. Readers never call this.
    """
    return _initialize_first(admission, conn, no_retained_provider_state=no_retained_provider_state,
        x_configuration=True)


def _initialize_first(admission, conn, *, no_retained_provider_state, x_configuration):
    try:
        _require(type(admission) is DirectoryAdmission and no_retained_provider_state is True
            and isinstance(conn, sqlite3.Connection) and conn.in_transaction)
        from serverware.operator_publication import assert_held
        assert_held()
        _require(conn.execute("PRAGMA query_only").fetchone()[0] == 0
            and conn.execute("PRAGMA read_uncommitted").fetchone()[0] == 0)
        if x_configuration:
            for schema in ("main.sqlite_master", "sqlite_temp_master"):
                _require(conn.execute("SELECT 1 FROM " + schema + " WHERE "
                    "lower(name) GLOB 'operator_x_provider_custody*' OR "
                    "lower(tbl_name) GLOB 'operator_x_provider_custody*' OR "
                    "lower(name) GLOB 'operator_x_configuration*' OR "
                    "lower(tbl_name) GLOB 'operator_x_configuration*' LIMIT 1").fetchone() is None)
        else:
            _require(conn.execute("SELECT 1 FROM sqlite_master WHERE lower(name) GLOB 'operator_provider_custody*' "
                "OR lower(tbl_name) GLOB 'operator_provider_custody*' LIMIT 1").fetchone() is None)
        with _open_directory(admission.path) as directory:
            _check_directory(admission, directory)
            # Only the absent open permits creation; read/validation failures do not.
            try:
                os.stat(FILENAME, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                raw = _canonical({"schema": SCHEMA, "owner_id": str(uuid.uuid4()),
                    "key": base64.b64encode(os.urandom(32)).decode("ascii")})
                handle = os.open(FILENAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600, dir_fd=directory)
                try:
                    offset = 0
                    while offset < len(raw):
                        written = os.write(handle, raw[offset:])
                        _require(written > 0)
                        offset += written
                    _file_identity(os.fstat(handle))
                    os.fsync(handle)
                finally:
                    os.close(handle)
                os.fsync(directory)
            result = _pin(admission, directory)
            try:
                # A valid orphan may follow a failed durability call, not only a
                # failed SQLite commit. Explicit retry must complete durability.
                os.fsync(result.descriptor)
                os.fsync(directory)
                _check_pin(result, directory)
                return result
            except BaseException:
                close_pin(result)
                raise
    except (OSError, ValueError, TypeError, RuntimeError, sqlite3.Error):
        raise ProviderKeyError(_ERROR) from None
