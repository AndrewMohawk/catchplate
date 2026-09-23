"""Witness journal file I/O, without launch, registry or protocol authority.

The descriptor is borrowed, not owned. The caller must retain its singleton
flock on the exact trusted, preprovisioned directory and validate its signed
binding, record names, canonical records, signatures, chain and quotas. Recovery
is a one-shot validated scan followed by a directory durability barrier. A
failed recovery or publication I/O attempt permanently poisons this handle;
only a fresh handle and complete validated reload can regain readiness. Invalid
publication arguments fail before I/O without poisoning. Directory timestamps
are supplemental change detection, not exclusion of hostile writers or an
independent anti-rollback anchor.
"""
from __future__ import annotations

import ctypes
import errno
import os
import re
import stat
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager


class JournalError(RuntimeError):
    pass


class JournalConflict(JournalError):
    pass


_LIBC = ctypes.CDLL(None, use_errno=True)
_RENAMEAT2 = getattr(_LIBC, "renameat2", None)
if _RENAMEAT2 is not None:
    _RENAMEAT2.argtypes = (
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
        ctypes.c_uint,
    )
    _RENAMEAT2.restype = ctypes.c_int
_RENAME_NOREPLACE = 1


def _rename_noreplace(
    directory_descriptor: int, temporary_name: str, record_name: str,
) -> None:
    if _RENAMEAT2 is None:
        raise JournalError("witness requires libc renameat2")
    result = _RENAMEAT2(
        directory_descriptor, temporary_name.encode("ascii"),
        directory_descriptor, record_name.encode("ascii"), _RENAME_NOREPLACE,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        if error_number == errno.EEXIST:
            raise JournalConflict("witness state record already exists")
        raise JournalError(f"witness renameat2 failed with errno {error_number}")


def _basename(value: str) -> None:
    if (type(value) is not str or not 1 <= len(value) <= 255
            or value in {".", ".."}
            or re.fullmatch(r"[A-Za-z0-9_.-]+", value) is None):
        raise JournalError("witness journal name is not a bounded ASCII basename")


class WitnessJournalIO:
    def __init__(self, directory_descriptor: int, *, maximum_record_bytes: int) -> None:
        if type(directory_descriptor) is not int or directory_descriptor < 0:
            raise JournalError("witness journal directory descriptor is invalid")
        if type(maximum_record_bytes) is not int or maximum_record_bytes < 1:
            raise JournalError("witness journal record byte bound is invalid")
        metadata = os.fstat(directory_descriptor)
        if not stat.S_ISDIR(metadata.st_mode):
            raise JournalError("witness journal descriptor is not a directory")
        self.directory_descriptor = directory_descriptor
        self.maximum_record_bytes = maximum_record_bytes
        self.lock = threading.RLock()
        self._directory_identity = (metadata.st_dev, metadata.st_ino)
        self._state = "unrecovered"

    def poison(self) -> None:
        with self.lock:
            self._state = "poisoned"

    def require_ready(self) -> None:
        with self.lock:
            if self._state != "ready":
                raise JournalError("witness journal requires a fresh validated reload")

    @contextmanager
    def ready(self) -> Iterator[None]:
        """Serialize a readiness-checked operation, including exact replay."""
        with self.lock:
            self.require_ready()
            yield

    def recover(
        self, validated_scan: Callable[[], tuple[int, int, int, int]],
    ) -> tuple[int, int, int, int]:
        """Return the exact validated (device, inode, mtime_ns, ctime_ns)."""
        with self.lock:
            if self._state != "unrecovered":
                raise JournalError("witness journal recovery is not available on this handle")
            self._state = "recovering"
            try:
                validated_stamp = validated_scan()
                if self._state != "recovering":
                    raise JournalError("witness journal recovery handle was poisoned")
                if (type(validated_stamp) is not tuple or len(validated_stamp) != 4
                        or any(type(value) is not int for value in validated_stamp)):
                    raise JournalError("witness journal validated directory stamp is invalid")
                # The scan may remove abandoned temporary files. Its existing
                # chain/metadata checks run before this unconditional barrier;
                # do not require the pre-cleanup directory timestamps here.
                before = os.fstat(self.directory_descriptor)
                if (not stat.S_ISDIR(before.st_mode)
                        or (before.st_dev, before.st_ino) != self._directory_identity
                        or (before.st_dev, before.st_ino, before.st_mtime_ns,
                            before.st_ctime_ns) != validated_stamp):
                    raise JournalError("witness journal directory identity changed")
                os.fsync(self.directory_descriptor)
                after = os.fstat(self.directory_descriptor)
                if (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns) != (
                        after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns):
                    raise JournalError("witness journal directory changed during recovery barrier")
                if self._state != "recovering":
                    raise JournalError("witness journal recovery handle was poisoned")
            except BaseException:
                self.poison()
                raise
            self._state = "ready"
            return validated_stamp

    def publish(self, temporary_name: str, record_name: str, canonical_record: bytes) -> None:
        with self.ready():
            _basename(temporary_name)
            _basename(record_name)
            if temporary_name == record_name:
                raise JournalError("witness temporary and published names must differ")
            if (type(canonical_record) is not bytes
                    or not 1 <= len(canonical_record) <= self.maximum_record_bytes):
                raise JournalError("witness journal record bytes exceed their bound")
            descriptor = None
            published = False
            try:
                try:
                    descriptor = os.open(
                        temporary_name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                        0o600, dir_fd=self.directory_descriptor,
                    )
                    offset = 0
                    while offset < len(canonical_record):
                        written = os.write(descriptor, canonical_record[offset:])
                        if written <= 0:
                            raise JournalError("witness state record write was incomplete")
                        offset += written
                    os.fchmod(descriptor, 0o400)
                    os.fsync(descriptor)
                    _rename_noreplace(self.directory_descriptor, temporary_name, record_name)
                    published = True
                    os.fsync(self.directory_descriptor)
                finally:
                    if descriptor is not None:
                        os.close(descriptor)
                        if not published:
                            try:
                                os.unlink(temporary_name, dir_fd=self.directory_descriptor)
                                os.fsync(self.directory_descriptor)
                            except FileNotFoundError:
                                pass
            except BaseException:
                # A visible published record is never removed. Even when the
                # exception happened before publication, no request may reuse
                # this handle's in-memory view without a complete fresh scan.
                self.poison()
                raise
