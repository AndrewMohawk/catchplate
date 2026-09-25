"""Cold, PID-bound ownership of the configured control-plane custody client.

The runner initializes this owner before application, database or server imports
open descriptors. Runtime trust admission therefore sees the exact inherited
config and directory descriptors, before the real journal opens a private one.
This module neither provisions a directory nor substitutes a PID environment
marker for the actual owner. Failure, shutdown and fork never trigger a retry.

Importing this module performs no authority admission. Unconfigured development
may opt out without importing the client or application configuration; the
release-channel default and development names match serverware.config. Explicit
custody FD/PATH mentions, including empty values, always require strict admission.
"""
from __future__ import annotations

import fcntl
import json
import os
import stat
import threading


SCHEMA = "serverware.controlPlaneCustodyStartup/v1"
CONFIG_FD_ENVIRONMENT = "SERVERWARE_CONTROL_PLANE_CUSTODY_CONFIG_FD"
MAX_CONFIG_BYTES = 16384
_PREFIX = "SERVERWARE_CONTROL_PLANE_CUSTODY_"
_DEVELOPMENT = frozenset({"dev", "development", "local", "test"})
_FIELDS = frozenset({"schema", "sourceRevision", "configurationDigest", "directoryFd",
    "device", "inode", "uid", "gid", "quotaBytes", "maximumRecords"})
_PID = os.getpid()
_LOCK = threading.RLock()
_state = "new"
_namespace = None
_owner = None


class CustodyStartupError(RuntimeError):
    pass


def _require_pid():
    # Check before acquiring a possibly inherited lock after fork.
    if os.getpid() != _PID:
        raise CustodyStartupError("forked process cannot use the parent custody startup owner")


def _environment():
    release = os.environ.get("SERVERWARE_RELEASE_CHANNEL", "dev").strip().lower()
    settings = tuple(sorted((name, value) for name, value in os.environ.items()
        if name.startswith(_PREFIX) and name.endswith(("_FD", "_PATH"))))
    return release, settings


def _development(namespace):
    return namespace[0] in _DEVELOPMENT and not namespace[1]


def _descriptor(namespace):
    settings = namespace[1]
    if len(settings) != 1 or settings[0][0] != CONFIG_FD_ENVIRONMENT:
        raise CustodyStartupError("custody startup requires only its fixed configuration FD; paths are forbidden")
    value = settings[0][1]
    if (type(value) is not str or not 2 <= len(value) <= 4
            or not value.isascii() or not value.isdecimal()):
        raise CustodyStartupError("custody configuration FD is not canonical decimal")
    descriptor = int(value)
    if not 32 <= descriptor <= 1023 or str(descriptor) != value:
        raise CustodyStartupError("custody configuration FD is outside its inherited range")
    return descriptor


def _identity(descriptor):
    metadata = os.fstat(descriptor)
    seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
    target = os.readlink("/proc/self/fd/" + str(descriptor))
    required = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_nlink != 0
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not 2 <= metadata.st_size <= MAX_CONFIG_BYTES
            or seals & required != required
            or not target.startswith("/memfd:") or not target.endswith(" (deleted)")):
        raise CustodyStartupError("custody configuration is not bounded root-owned sealed memfd material")
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
        metadata.st_gid, metadata.st_nlink, metadata.st_size,
        metadata.st_mtime_ns, metadata.st_ctime_ns, seals, target)


def _read_original(descriptor):
    before = _identity(descriptor)
    size = before[6]
    value = bytearray()
    while len(value) < size:
        chunk = os.pread(descriptor, min(4096, size - len(value)), len(value))
        if not chunk:
            raise CustodyStartupError("custody configuration was truncated")
        value.extend(chunk)
    if os.pread(descriptor, 1, size) or _identity(descriptor) != before:
        raise CustodyStartupError("custody configuration descriptor changed while reading")
    return bytes(value), before


def _pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise CustodyStartupError("custody configuration has a duplicate member")
        value[key] = item
    return value


def _constant(_value):
    raise CustodyStartupError("custody configuration contains a non-JSON constant")


def _manifest(original, descriptor, *, source_revision, journal):
    try:
        value = json.loads(original.decode("ascii"), object_pairs_hook=_pairs, parse_constant=_constant)
        if type(value) is not dict or set(value) != _FIELDS:
            raise CustodyStartupError("custody startup configuration is not closed")
        if value["schema"] != SCHEMA or value["sourceRevision"] != source_revision:
            raise CustodyStartupError("custody startup schema or source is unsupported")
        digest = value["configurationDigest"]
        if (type(digest) is not str or len(digest) != 71 or not digest.startswith("sha256:")
                or any(character not in "0123456789abcdef" for character in digest[7:])):
            raise CustodyStartupError("custody startup configuration identity is not canonical SHA-256")
        for name, minimum, maximum in (
            ("directoryFd", 32, 1023), ("device", 0, 2**64 - 1), ("inode", 1, 2**64 - 1),
            ("uid", 0, 2**32 - 2), ("gid", 0, 2**32 - 2),
            ("quotaBytes", 1, journal.MAX_QUOTA_BYTES), ("maximumRecords", 1, journal.MAX_RECORDS),
        ):
            journal._integer(value[name], minimum=minimum, maximum=maximum, label="custody " + name)
        if value["directoryFd"] == descriptor:
            raise CustodyStartupError("custody configuration and directory descriptors must differ")
        if (value["uid"], value["gid"]) != (os.geteuid(), os.getegid()):
            raise CustodyStartupError("custody journal differs from the actual control-plane owner")
        canonical = json.dumps(value, ensure_ascii=True, allow_nan=False,
            separators=(",", ":"), sort_keys=True).encode("ascii")
        if canonical != original:
            raise CustodyStartupError("custody startup configuration bytes are not canonical")
        return (digest, value["directoryFd"], value["device"], value["inode"],
            value["uid"], value["gid"], value["quotaBytes"], value["maximumRecords"])
    except (KeyError, TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise CustodyStartupError("custody startup configuration is invalid") from exc


def initialize_from_environment():
    """Admit once before other startup opens FDs; never retry failed admission."""
    global _state, _namespace, _owner
    _require_pid()
    with _LOCK:
        if _state in ("started", "disabled"):
            return require_started()
        if _state != "new":
            raise CustodyStartupError("custody startup cannot be repeated after failure or shutdown")
        namespace = _environment()
        _namespace, _state = namespace, "initializing"
        candidate = None
        try:
            if _development(namespace):
                _state = "disabled"
                return None
            descriptor = _descriptor(namespace)
            original, identity = _read_original(descriptor)
            # Keep authority imports beyond the genuine development opt-out.
            from serverware import authority_contract as authority
            from serverware import control_plane_custody_client as client
            from serverware import control_plane_custody_journal as journal

            held = _manifest(original, descriptor, source_revision=authority.SOURCE_REVISION, journal=journal)
            if _environment() != namespace or _identity(descriptor) != identity:
                raise CustodyStartupError("custody startup inputs changed before admission")
            candidate = client.ControlPlaneCustodyClient.from_environment(directory_fd=held[1],
                expected_device=held[2], expected_inode=held[3], expected_uid=held[4], expected_gid=held[5],
                quota_bytes=held[6], maximum_records=held[7])
            binding = client._snapshot(candidate)
            if (binding.configuration_digest != held[0] or _environment() != namespace
                    or _identity(descriptor) != identity):
                raise CustodyStartupError("custody startup differs from its admitted runtime scope")
            _owner, _state = candidate, "started"
            return candidate
        except BaseException:
            _owner, _state = None, "failed"
            if candidate is not None:
                try:
                    client.ControlPlaneCustodyClient.close(candidate)
                except BaseException:
                    pass
            raise


def require_started():
    """Return the real owner, or opt-out only for unconfigured development."""
    _require_pid()
    with _LOCK:
        namespace = _environment()
        if _state == "new" and _development(namespace):
            # Direct development ASGI/library imports need no authority owner.
            # This does not initialize, change lifecycle state or open any FD.
            return None
        if _state not in ("started", "disabled"):
            raise CustodyStartupError("custody must be admitted by cold startup before use")
        if namespace != _namespace:
            raise CustodyStartupError("custody startup environment differs from its admitted namespace")
        if _state == "disabled":
            if not _development(namespace) or _owner is not None:
                raise CustodyStartupError("custody development opt-out is inconsistent")
            return None
        from serverware import control_plane_custody_client as client

        owner = _owner
        binding = client._snapshot(owner)
        client._receipt_now(binding)
        return owner


def close():
    """Close only this PID's owner; shutdown never permits reinitialization."""
    global _state, _owner
    _require_pid()
    with _LOCK:
        if _state == "closed":
            return
        if _state == "initializing":
            raise CustodyStartupError("custody startup cannot close during admission")
        owner = _owner
        _owner, _state = None, "closed"
        if owner is not None:
            from serverware import control_plane_custody_client as client

            client.ControlPlaneCustodyClient.close(owner)
