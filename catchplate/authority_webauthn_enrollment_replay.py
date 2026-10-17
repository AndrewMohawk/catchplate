"""Durable local one-attempt ledger for admitted enrollment authorizations.

The signer owns one independently provisioned private directory for its entire
key lifetime, across configuration and source generations. This module neither
provisions that directory nor authenticates a grant. Its caller must genuinely
admit the original grant and source exchange, then consume the verified grant
identity before invoking the evidence signer. A consumed identity never becomes
usable again, even when signing fails or its outcome is unknown.

The borrowed directory descriptor is reopened as an independent open-file
description with a singleton flock. Cold recovery validates every immutable
marker and completes file and directory durability barriers before use. Unknown
or temporary files fail closed; published markers are never removed. An
ambiguous publication poisons the owner. Filesystem durability relies on fsync;
these local files, timestamps and flock are not hostile-host anti-rollback.
An independently protected deployment and stable signer-wide directory binding
remain mandatory external prerequisites, not authority granted by this store.
"""
from __future__ import annotations

import fcntl
import os
import stat

from catchplate.authority_witness_journal import WitnessJournalIO


MAX_RECORDS = 4096
_MARKER_MAGIC = b"SWENR001"
_MARKER_BYTES = 40
_PREFIX = "attempted-"
_HEX = frozenset("0123456789abcdef")


class EnrollmentReplayError(RuntimeError):
    pass


def _integer(value, minimum, maximum, label):
    if type(value) is not int or not minimum <= value <= maximum:
        raise EnrollmentReplayError(label + " is not a bounded exact integer")


def _digest(value):
    if (type(value) is not str or len(value) != 71 or not value.startswith("sha256:")
            or any(character not in _HEX for character in value[7:])):
        raise EnrollmentReplayError("enrollment authorization identity is not canonical SHA-256")
    return value


def _identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid,
        metadata.st_mode, metadata.st_nlink, metadata.st_size,
        metadata.st_mtime_ns, metadata.st_ctime_ns)


class EnrollmentReplayStore:
    """One PID-bound, thread-serialized, append-only signer attempt owner."""

    __slots__ = ("_pid", "_binding", "_maximum_records", "_closed", "_consumed",
        "_directory_fd", "_directory_stamp", "_io")

    def __init__(self, *, directory_fd, expected_device, expected_inode,
            expected_uid, expected_gid, maximum_records):
        for value, minimum, maximum, label in (
            (directory_fd, 0, 2**31 - 1, "directory descriptor"),
            (expected_device, 0, 2**64 - 1, "directory device"),
            (expected_inode, 1, 2**64 - 1, "directory inode"),
            (expected_uid, 0, 2**32 - 2, "directory owner UID"),
            (expected_gid, 0, 2**32 - 2, "directory owner GID"),
            (maximum_records, 1, MAX_RECORDS, "enrollment replay record limit"),
        ):
            _integer(value, minimum, maximum, label)
        self._pid = os.getpid()
        self._binding = (expected_device, expected_inode, expected_uid, expected_gid)
        self._maximum_records = maximum_records
        self._closed = False
        self._consumed = set()
        self._directory_fd = None
        self._directory_stamp = None
        self._io = None
        if (os.geteuid(), os.getegid()) != self._binding[2:]:
            raise EnrollmentReplayError("enrollment replay writer differs from its provisioned owner")
        self._directory_metadata(directory_fd)
        try:
            # dup() would share the caller's open-file description and flock;
            # openat('.') instead owns a distinct lease without closing it.
            self._directory_fd = os.open(".",
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_fd)
            self._directory_metadata(self._directory_fd)
            fcntl.flock(self._directory_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._io = WitnessJournalIO(self._directory_fd,
                maximum_record_bytes=_MARKER_BYTES)
            self._directory_stamp = self._io.recover(self._recover)
        except BaseException:
            self._closed = True
            if self._io is not None:
                self._io.poison()
            if self._directory_fd is not None:
                try:
                    os.close(self._directory_fd)
                except OSError:
                    pass
            raise

    def _directory_metadata(self, descriptor):
        metadata = os.fstat(descriptor)
        if (not stat.S_ISDIR(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o700 or metadata.st_nlink < 1
                or (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid)
                    != self._binding):
            raise EnrollmentReplayError("enrollment replay directory differs from its private pinned identity")
        return metadata

    def _stamp(self):
        metadata = self._directory_metadata(self._directory_fd)
        return (metadata.st_dev, metadata.st_ino, metadata.st_mtime_ns, metadata.st_ctime_ns)

    def _require_process(self):
        # Check before locking: a fork can inherit an unavailable thread lock.
        if os.getpid() != self._pid:
            raise EnrollmentReplayError("forked process cannot use the enrollment replay owner")
        if self._closed:
            raise EnrollmentReplayError("enrollment replay owner is closed")
        if (os.geteuid(), os.getegid()) != self._binding[2:]:
            raise EnrollmentReplayError("enrollment replay writer identity changed")

    def _require_ready(self):
        self._require_process()
        self._io.require_ready()
        try:
            if self._stamp() != self._directory_stamp:
                raise EnrollmentReplayError("enrollment replay directory changed outside its owner")
        except BaseException:
            self._io.poison()
            raise

    def _read_marker(self, name, digest, *, synchronize=False):
        descriptor = os.open(name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=self._directory_fd)
        try:
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o400
                    or before.st_nlink != 1 or before.st_dev != self._binding[0]
                    or (before.st_uid, before.st_gid) != self._binding[2:]
                    or before.st_size != _MARKER_BYTES):
                raise EnrollmentReplayError("enrollment replay marker is not exact immutable material")
            encoded = bytearray()
            while len(encoded) < _MARKER_BYTES:
                chunk = os.read(descriptor, _MARKER_BYTES - len(encoded))
                if not chunk:
                    raise EnrollmentReplayError("enrollment replay marker was truncated")
                encoded.extend(chunk)
            if os.read(descriptor, 1):
                raise EnrollmentReplayError("enrollment replay marker grew while reading")
            if bytes(encoded) != _MARKER_MAGIC + bytes.fromhex(digest[7:]):
                raise EnrollmentReplayError("enrollment replay marker differs from its named authorization")
            if synchronize:
                os.fsync(descriptor)
            if _identity(before) != _identity(os.fstat(descriptor)):
                raise EnrollmentReplayError("enrollment replay marker changed while reading")
        finally:
            os.close(descriptor)

    def _recover(self):
        before = self._stamp()
        consumed = set()
        count = 0
        with os.scandir(self._directory_fd) as entries:
            for entry in entries:
                count += 1
                if count > self._maximum_records:
                    raise EnrollmentReplayError("enrollment replay record limit exceeded")
                name = entry.name
                suffix = name[len(_PREFIX):]
                if (not name.startswith(_PREFIX) or len(suffix) != 64
                        or any(character not in _HEX for character in suffix)):
                    raise EnrollmentReplayError("enrollment replay contains an unknown or temporary file")
                digest = "sha256:" + suffix
                if digest in consumed:
                    raise EnrollmentReplayError("enrollment replay contains a repeated identity")
                self._read_marker(name, digest, synchronize=True)
                consumed.add(digest)
        if self._stamp() != before:
            raise EnrollmentReplayError("enrollment replay directory changed during recovery")
        self._consumed = consumed
        return before

    def consume(self, authorization_digest):
        """Durably spend one admitted grant identity before any evidence signing.

        A duplicate is always an error, never an idempotent success. Failures
        supply no retry or rollback authority, and never remove a marker.
        """
        digest = _digest(authorization_digest)
        self._require_process()
        with self._io.ready():
            self._require_ready()
            if digest in self._consumed:
                raise EnrollmentReplayError("enrollment authorization already has an attempt")
            if len(self._consumed) >= self._maximum_records:
                raise EnrollmentReplayError("enrollment replay capacity is exhausted")
            name = _PREFIX + digest[7:]
            encoded = _MARKER_MAGIC + bytes.fromhex(digest[7:])
            try:
                self._io.publish(".tmp-" + name, name, encoded)
                self._read_marker(name, digest)
                self._consumed.add(digest)
                self._directory_stamp = self._stamp()
                self._require_ready()
            except BaseException:
                self._io.poison()
                raise

    def close(self):
        if os.getpid() != self._pid:
            raise EnrollmentReplayError("forked process cannot close the enrollment replay owner")
        if self._closed:
            return
        with self._io.lock:
            if not self._closed:
                self._closed = True
                self._io.poison()
                # Closing only our private description releases the flock.
                # Never unlock or close the caller's borrowed descriptor.
                os.close(self._directory_fd)
