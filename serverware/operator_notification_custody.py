"""Notification-only custody in a separately mounted, application-private directory.

No configured imports, URL logging, key regeneration or Google/master-key reuse.
The store owns admission and the publication transaction. Only explicit first
Save may call initialize(); all other callers read an existing closed record.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import stat
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FILENAME = "notification-key.json"
SCHEMA = "serverware.operatorNotificationKey/v1"
_ERROR = "operator notification custody unavailable"


class CustodyError(RuntimeError):
    """Fixed, non-secret filesystem or authenticated-ciphertext failure."""


def _require(condition):
    if not condition:
        raise CustodyError(_ERROR)


def _uuid(value):
    return type(value) is str and str(uuid.UUID(value)) == value


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


@dataclass(frozen=True)
class Key:
    owner_id: str
    material: bytes = field(repr=False)


def _identity(info, *, directory=False):
    _require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600))
    _require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
    return info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink


@contextmanager
def _directory(path: Path):
    from serverware.development_sandbox import _open_directory
    _require(type(path) is Path or isinstance(path, Path))
    _require(path.is_absolute() and path != Path("/") and ".." not in path.parts)
    descriptor = _open_directory(path)
    try:
        before = _identity(os.fstat(descriptor), directory=True)
        _require(set(os.listdir(descriptor)) <= {FILENAME})
        yield descriptor
        check = _open_directory(path)
        try:
            _require(_identity(os.fstat(check), directory=True) == before
                and _identity(os.fstat(descriptor), directory=True) == before)
        finally:
            os.close(check)
    finally:
        os.close(descriptor)


def _read(descriptor):
    handle = os.open(FILENAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=descriptor)
    try:
        before = os.fstat(handle)
        identity = _identity(before)
        _require(1 <= before.st_size <= 512)
        raw = os.read(handle, 513)
        record = json.loads(raw)
        _require(type(record) is dict and set(record) == {"schema", "owner_id", "key"}
            and record["schema"] == SCHEMA and _uuid(record["owner_id"]) and type(record["key"]) is str)
        material = base64.b64decode(record["key"], validate=True)
        _require(len(material) == 32 and base64.b64encode(material).decode("ascii") == record["key"]
            and _canonical(record) + b"\n" == raw)
        for after in (os.fstat(handle), os.stat(FILENAME, dir_fd=descriptor, follow_symlinks=False)):
            _require(_identity(after) == identity and after.st_size == before.st_size
                and after.st_mtime_ns == before.st_mtime_ns and after.st_ctime_ns == before.st_ctime_ns)
        return Key(record["owner_id"], material)
    finally:
        os.close(handle)


def read(path: Path, owner_id: str) -> Key:
    """Never creates storage or adopts a different retained owner."""
    try:
        _require(_uuid(owner_id))
        with _directory(path) as descriptor:
            result = _read(descriptor)
            _require(result.owner_id == owner_id)
            return result
    except (OSError, ValueError, TypeError, RuntimeError):
        raise CustodyError(_ERROR) from None


def initialize(path: Path, *, no_retained_notification_state: bool) -> Key:
    """Explicit-Save only; durable no-overwrite creation or exact orphan recovery.

The caller must prove no notification schema *and* no notification audit history
inside its existing publication/SQLite transaction. A valid orphan can be left
by a failed first database commit. An invalid/partial record is never repaired.
"""
    try:
        from serverware.operator_publication import assert_held
        assert_held()
        _require(no_retained_notification_state is True)
        with _directory(path) as descriptor:
            try:
                return _read(descriptor)
            except FileNotFoundError:
                pass
            result = Key(str(uuid.uuid4()), os.urandom(32))
            raw = _canonical({"schema": SCHEMA, "owner_id": result.owner_id,
                "key": base64.b64encode(result.material).decode("ascii")}) + b"\n"
            handle = os.open(FILENAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600, dir_fd=descriptor)
            try:
                _identity(os.fstat(handle))
                offset = 0
                while offset < len(raw):
                    written = os.write(handle, raw[offset:])
                    _require(written > 0)
                    offset += written
                os.fsync(handle)
            finally:
                os.close(handle)
            os.fsync(descriptor)
            retained = _read(descriptor)
            _require(retained == result)
            return retained
    except (OSError, ValueError, TypeError, RuntimeError):
        raise CustodyError(_ERROR) from None


def _aad(key, slot, revision):
    _require(type(key) is Key and _uuid(key.owner_id) and type(key.material) is bytes and len(key.material) == 32
        and slot in {"action_required.slack", "action_required.webhook", "audit_log.slack", "audit_log.webhook"}
        and type(revision) is int and revision > 0)
    return _canonical({"schema": "serverware.operatorNotificationURL/v1", "owner_id": key.owner_id,
        "slot": slot, "adapter": slot.split(".")[1], "revision": revision})


def seal(key: Key, slot: str, revision: int, url: str) -> tuple[bytes, bytes]:
    try:
        _require(type(url) is str and 1 <= len(url.encode("utf-8")) <= 4096)
        nonce = os.urandom(12)
        return nonce, AESGCM(key.material).encrypt(nonce, url.encode("utf-8"), _aad(key, slot, revision))
    except (ValueError, TypeError, RuntimeError):
        raise CustodyError(_ERROR) from None


def unseal(key: Key, slot: str, revision: int, nonce: bytes, ciphertext: bytes) -> str:
    from cryptography.exceptions import InvalidTag
    try:
        _require(type(nonce) is bytes and len(nonce) == 12 and type(ciphertext) is bytes
            and 17 <= len(ciphertext) <= 4112)
        return AESGCM(key.material).decrypt(nonce, ciphertext, _aad(key, slot, revision)).decode("utf-8")
    except (ValueError, TypeError, RuntimeError, InvalidTag):
        raise CustodyError(_ERROR) from None
