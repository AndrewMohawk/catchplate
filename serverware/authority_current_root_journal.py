"""Bounded opaque durable storage for the fixed current-root service owner.

An independently provisioned directory binding and the owning service's fixed
replay validator are prerequisites. This module does not parse canonical JSON,
verify signatures, reduce protocol state or establish a latest trusted head.
After complete recovery the service must still compare its separately admitted
exact checkpoint and poison this owner on a mismatch. A directory, file hash,
timestamp or successful callback is not an anti-rollback or authority token.

Construction opens a private description of the borrowed directory and takes
its own singleton lease. It creates no directory or genesis. Recovery is one
bounded scan followed by actual file/directory durability barriers. Unknown or
temporary entries fail closed without recovery cleanup. Published records are
never removed, rewritten or retried. Capacity for a completion record must be
reserved by the source-fixed protocol owner before accepting a pending change.
"""
from __future__ import annotations

from dataclasses import dataclass
import fcntl
import hashlib
import os
import stat

from serverware.authority_witness_journal import WitnessJournalIO


MAX_RECORDS = 1024
MAX_RECORD_BYTES = 1024 * 1024
_READ_CHUNK = 64 * 1024
_HEX = frozenset("0123456789abcdef")


class CurrentRootJournalError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CurrentRootRecord:
    """Actual local file metadata only, never a signed receipt or trusted head."""

    sequence: int
    digest: str
    byte_count: int


def _integer(value, minimum, maximum, label):
    if type(value) is not int or not minimum <= value <= maximum:
        raise CurrentRootJournalError(label + " is not a bounded exact integer")


def _identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid,
        metadata.st_mode, metadata.st_nlink, metadata.st_size,
        metadata.st_mtime_ns, metadata.st_ctime_ns)


def _name(record):
    return f"{record.sequence:020d}-" + record.digest[7:]


def _parse_name(name):
    if (type(name) is not str or len(name) != 85 or name[20] != "-"
            or any(character not in "0123456789" for character in name[:20])
            or any(character not in _HEX for character in name[21:])):
        raise CurrentRootJournalError("current-root journal contains an unknown or temporary entry")
    sequence = int(name[:20])
    if not 1 <= sequence <= MAX_RECORDS:
        raise CurrentRootJournalError("current-root journal sequence exceeds its source bound")
    return sequence, "sha256:" + name[21:]


class CurrentRootJournal:
    """One PID-bound, thread-serialized, append-only private file owner."""

    __slots__ = ("_pid", "_binding", "_maximum_records", "_closed", "_state",
        "_directory_fd", "_directory_stamp", "_io", "_records", "_identities")

    def __init__(self, *, directory_fd, expected_device, expected_inode,
            expected_uid, expected_gid, maximum_records, _current=None):
        if _current is not None and not callable(_current):
            raise CurrentRootJournalError("current-root original guard is not callable")
        check = (lambda: None) if _current is None else _current
        check()
        for value, minimum, maximum, label in (
            (directory_fd, 0, 2**31 - 1, "directory descriptor"),
            (expected_device, 0, 2**64 - 1, "directory device"),
            (expected_inode, 1, 2**64 - 1, "directory inode"),
            (expected_uid, 1, 2**32 - 2, "nonroot directory owner UID"),
            (expected_gid, 0, 2**32 - 2, "directory owner GID"),
            (maximum_records, 2, MAX_RECORDS, "current-root journal record limit"),
        ):
            _integer(value, minimum, maximum, label)
        self._pid = os.getpid()
        self._binding = (expected_device, expected_inode, expected_uid, expected_gid)
        self._maximum_records = maximum_records
        self._closed, self._state = False, "unrecovered"
        self._directory_fd = self._directory_stamp = self._io = None
        self._records, self._identities = (), ()
        if (os.geteuid(), os.getegid()) != self._binding[2:]:
            raise CurrentRootJournalError("current-root journal process differs from its provisioned owner")
        self._directory_metadata(directory_fd)
        check()
        try:
            # dup() shares flock state. Reopening '.' owns an independent open
            # description anchored to the actual borrowed, validated directory.
            self._directory_fd = os.open(".",
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_fd)
            check()
            self._directory_metadata(self._directory_fd)
            check()
            fcntl.flock(self._directory_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            check()
            self._io = WitnessJournalIO(self._directory_fd,
                maximum_record_bytes=MAX_RECORD_BYTES)
            self._directory_stamp = self._stamp()
            check()
        except BaseException:
            self._closed, self._state = True, "poisoned"
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
            raise CurrentRootJournalError("current-root directory differs from its private pinned identity")
        return metadata

    def _stamp(self):
        metadata = self._directory_metadata(self._directory_fd)
        return (metadata.st_dev, metadata.st_ino, metadata.st_mtime_ns, metadata.st_ctime_ns)

    def _require_process(self):
        # Reject fork reuse before any possibly inherited thread lock.
        if os.getpid() != self._pid:
            raise CurrentRootJournalError("forked process cannot use the current-root journal")
        if self._closed:
            raise CurrentRootJournalError("current-root journal is closed")
        if (os.geteuid(), os.getegid()) != self._binding[2:]:
            self.poison()
            raise CurrentRootJournalError("current-root journal process identity changed")

    def _require_ready(self):
        self._require_process()
        self._io.require_ready()
        try:
            if self._state != "ready" or self._stamp() != self._directory_stamp:
                raise CurrentRootJournalError("current-root directory changed outside its owner")
            # Directory timestamps alone do not cover in-place file changes.
            # Check the bounded complete inventory as well: a concurrent added
            # entry must not be adopted when our own publication updates it.
            count = 0
            with os.scandir(self._directory_fd) as entries:
                for entry in entries:
                    count += 1
                    if count > len(self._records):
                        raise CurrentRootJournalError("current-root journal acquired an unknown entry")
                    sequence, digest = _parse_name(entry.name)
                    if sequence > len(self._records) or digest != self._records[sequence - 1].digest:
                        raise CurrentRootJournalError("current-root journal inventory changed outside its owner")
                    actual = os.stat(entry.name, dir_fd=self._directory_fd, follow_symlinks=False)
                    if _identity(actual) != self._identities[sequence - 1]:
                        raise CurrentRootJournalError("current-root record identity changed outside its owner")
            if count != len(self._records):
                raise CurrentRootJournalError("current-root journal lost a retained record")
            if self._stamp() != self._directory_stamp:
                raise CurrentRootJournalError("current-root directory changed during continuity checks")
        except BaseException:
            self.poison()
            raise

    def _read_record(self, name, sequence, digest, *, synchronize=False, work=None,
            _current=None, _maximum_record_bytes=MAX_RECORD_BYTES):
        if _current is not None and not callable(_current):
            raise CurrentRootJournalError("current-root read requires its original guard")
        _integer(_maximum_record_bytes, 1, MAX_RECORD_BYTES, "current-root tightened record cap")
        check = (lambda: None) if _current is None else _current
        check()
        descriptor = os.open(name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=self._directory_fd)
        try:
            check()
            before = os.fstat(descriptor)
            check()
            if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o400
                    or before.st_nlink != 1 or before.st_dev != self._binding[0]
                    or (before.st_uid, before.st_gid) != self._binding[2:]
                    or not 1 <= before.st_size <= _maximum_record_bytes):
                raise CurrentRootJournalError("current-root record is not bounded immutable private material")
            def read_original():
                check()
                encoded = bytearray(before.st_size)
                offset = 0
                while offset < before.st_size:
                    check()
                    chunk = os.read(descriptor, min(_READ_CHUNK, before.st_size - offset))
                    check()
                    if not chunk:
                        raise CurrentRootJournalError("current-root record was truncated")
                    encoded[offset:offset + len(chunk)] = chunk
                    offset += len(chunk)
                    del chunk
                check()
                if os.read(descriptor, 1):
                    raise CurrentRootJournalError("current-root record grew while reading")
                check()
                original = bytes(encoded)
                check()
                if "sha256:" + hashlib.sha256(original).hexdigest() != digest:
                    raise CurrentRootJournalError("current-root record differs from its named raw digest")
                check()
                if synchronize:
                    os.fsync(descriptor)
                    check()
                identity = _identity(before)
                if (identity != _identity(os.fstat(descriptor))
                        or identity != _identity(os.stat(name, dir_fd=self._directory_fd,
                            follow_symlinks=False))):
                    raise CurrentRootJournalError("current-root record changed during its stable read")
                check()
                return original, CurrentRootRecord(sequence, digest, len(original)), identity

            if work is None:
                result = read_original()
            else:
                from serverware import authority_revocation_capability_production as production

                # Charge before allocation. A supplied ancestor may itself
                # meter work, so only the old guard-free read uses _callback.
                work.charge(hashes=1, input_bytes=3 * before.st_size + 1)
                result = (production._callback(work, read_original) if _current is None
                    else read_original())
        finally:
            os.close(descriptor)
        check()
        return result

    def recover(self, validate_record, *, work=None, _current=None,
            _maximum_record_bytes=MAX_RECORD_BYTES):
        """Replay once via the owning service's fixed validator, then fsync.

        The callback receives (sequence, original_bytes) in contiguous order.
        It must verify canonical protocol/signatures and deterministic state,
        raising on failure. It is cold service code, never a request callback.
        Even complete recovery does not admit the latest semantic checkpoint.
        """
        if _current is not None and not callable(_current):
            raise CurrentRootJournalError("current-root recovery requires its original guard")
        _integer(_maximum_record_bytes, 1, MAX_RECORD_BYTES, "current-root tightened recovery cap")
        check = (lambda: None) if _current is None else _current
        check()
        self._require_process()
        if work is not None:
            from serverware.authority_query_read_work import _ValidationWork

            if type(work) is not _ValidationWork:
                raise CurrentRootJournalError("current-root recovery requires its actual inherited work")
        if not callable(validate_record):
            raise CurrentRootJournalError("current-root recovery requires the fixed service validator")
        with self._io.lock:
            self._require_process()
            if self._state != "unrecovered":
                raise CurrentRootJournalError("current-root recovery is one-shot on this owner")
            self._state = "recovering"
            recovered, identities = [], []

            def scan():
                check()
                before = self._stamp()
                check()
                if before != self._directory_stamp:
                    raise CurrentRootJournalError("current-root directory changed before recovery")
                names = []
                with os.scandir(self._directory_fd) as entries:
                    for entry in entries:
                        check()
                        if len(names) >= self._maximum_records:
                            raise CurrentRootJournalError("current-root journal exceeds its record limit")
                        sequence, digest = _parse_name(entry.name)
                        names.append((sequence, digest, entry.name))
                names.sort()
                for position, (sequence, digest, name) in enumerate(names, start=1):
                    check()
                    if sequence != position:
                        raise CurrentRootJournalError("current-root journal has a missing or repeated sequence")
                    original, record, identity = self._read_record(name, sequence, digest,
                        synchronize=True, work=work, _current=_current,
                        _maximum_record_bytes=_maximum_record_bytes)
                    validate_record(sequence, original)
                    check()
                    self._require_process()
                    if (self._state != "recovering" or self._stamp() != before
                            or _identity(os.stat(name, dir_fd=self._directory_fd,
                                follow_symlinks=False)) != identity):
                        raise CurrentRootJournalError("current-root journal changed during protocol replay")
                    recovered.append(record)
                    identities.append(identity)
                if self._stamp() != before:
                    raise CurrentRootJournalError("current-root directory changed during recovery")
                check()
                return before

            try:
                stamp = self._io.recover(scan)
                self._records, self._identities = tuple(recovered), tuple(identities)
                self._directory_stamp, self._state = stamp, "ready"
                self._require_ready()
                check()
                return self._records
            except BaseException:
                self.poison()
                raise

    def append(self, raw_bytes):
        """Publish the next opaque original once; semantic admission is upstream.

        No protocol callback, implicit genesis, capacity reservation or retry
        occurs here. Publication ambiguity permanently poisons this handle.
        """
        original = raw_bytes
        if type(original) is not bytes or not 1 <= len(original) <= MAX_RECORD_BYTES:
            raise CurrentRootJournalError("current-root original exceeds its immutable byte bound")
        self._require_process()
        with self._io.ready():
            self._require_ready()
            if len(self._records) >= self._maximum_records:
                raise CurrentRootJournalError("current-root journal capacity is exhausted")
            sequence = len(self._records) + 1
            digest = "sha256:" + hashlib.sha256(original).hexdigest()
            record = CurrentRootRecord(sequence, digest, len(original))
            name = _name(record)
            try:
                self._io.publish(".tmp-" + name, name, original)
                observed, metadata, identity = self._read_record(name, sequence, digest)
                if observed != original or metadata != record:
                    raise CurrentRootJournalError("published current-root original changed")
                self._records += (record,)
                self._identities += (identity,)
                self._directory_stamp = self._stamp()
                self._require_ready()
                return record
            except BaseException:
                self.poison()
                raise

    @property
    def records(self):
        self._require_process()
        with self._io.ready():
            self._require_ready()
            return self._records

    @property
    def count(self):
        return len(self.records)

    @property
    def maximum_records(self):
        self._require_process()
        return self._maximum_records

    def poison(self):
        """Prevent use after the service rejects protocol/checkpoint admission."""
        if os.getpid() != self._pid:
            raise CurrentRootJournalError("forked process cannot poison the parent journal")
        if self._closed:
            return
        with self._io.lock:
            self._state = "poisoned"
            self._io.poison()

    def close(self):
        if os.getpid() != self._pid:
            raise CurrentRootJournalError("forked process cannot close the parent journal")
        if self._closed:
            return
        with self._io.lock:
            if not self._closed:
                self._closed, self._state = True, "closed"
                self._io.poison()
                # Only our independent description is closed. Never unlock or
                # close the supplied borrowed FD or delete published records.
                os.close(self._directory_fd)

    def __enter__(self):
        self._require_process()
        with self._io.ready():
            self._require_ready()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False
