"""Caller-owned originals, one attempt and unsigned readback observations.

This library is not a measured authority role, provisioner, network client or
receipt verifier. Its caller supplies an independently provisioned private
directory. Local content identity and an ATTEMPTED marker establish neither a
remote commit nor permission to send or retry. Published records are never
removed. Recovery rejects unknown and temporary files rather than guessing
whether an interrupted publication may safely be discarded.
An OBSERVED marker records only first successful readback metadata; it is
neither terminal business state nor authority to bypass fresh verification.
Registration execution-grant records are a separate retention-only family;
they never admit attempted or observed markers or legacy forwarding.

The private directory open-file description owns the singleton flock. The
supplied descriptor remains borrowed; use after fork is rejected. Filesystem
durability depends on the provisioned filesystem honoring fsync. The lease and
directory timestamps do not provide an independent anti-rollback anchor or
exclude an independently privileged writer.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import fcntl
import os
import stat

from serverware import control_plane_custody_records as records
from serverware import control_plane_custody_observations as observations
from serverware import control_plane_registration_execution_records as execution_records
from serverware.authority_witness_journal import WitnessJournalIO


MAX_QUOTA_BYTES = 8 * 1024**3
MAX_RECORDS = 4096
_ATTEMPT_MAGIC = b"SWCPA001"
_ATTEMPT_BYTES = 40
_OBSERVATION_RESERVE = observations.MAX_OBSERVATION_BYTES
_HEX = frozenset("0123456789abcdef")
_READ_CHUNK = 1024 * 1024
_MAX_RECORD_BYTES = max(records.MAX_RECORD_BYTES, execution_records.MAX_RECORD_BYTES)


class CustodyJournalError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class JournalEntry:
    """Metadata only; neither history admission nor a delivery receipt."""

    digest: str
    family: str
    selector: str
    source_revision: str
    prepared_bytes: int
    attempted: bool
    observed: bool = False


def _integer(value, *, minimum, maximum, label):
    if type(value) is not int or not minimum <= value <= maximum:
        raise CustodyJournalError(label + " is not a bounded exact integer")


def _digest(value):
    if (type(value) is not str or len(value) != 71 or not value.startswith("sha256:")
            or any(character not in _HEX for character in value[7:])):
        raise CustodyJournalError("local prepared digest is not canonical SHA-256")
    return value


def _name(kind, digest):
    return kind + "-" + digest[7:]


def _identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid,
        metadata.st_mode, metadata.st_nlink, metadata.st_size,
        metadata.st_mtime_ns, metadata.st_ctime_ns)


def _decode_prepared(encoded):
    """Dispatch only the two fixed original-record formats, never a plugin."""
    if type(encoded) is not bytes:
        raise CustodyJournalError("prepared record is not immutable bytes")
    if encoded[:8] == records.PREPARED_RECORD_MAGIC:
        return records.decode_prepared(encoded)
    if encoded[:8] == execution_records.PREPARED_RECORD_MAGIC:
        return execution_records.decode_prepared(encoded)
    raise CustodyJournalError("prepared record version is unsupported")


class CustodyJournal:
    """One PID-bound, explicitly provisioned, append-only local journal.

    Construction completes the only recovery scan before making the owner
    available. Quota reserves forty attempt bytes and the maximum observation
    frame for each legacy prepared record still missing those markers.
    Retention-only execution grants reserve no marker bytes. Preparation cannot
    consume another record's marker capacity. At most three times maximum_records
    published files are admitted; old records are never rewritten or removed.
    """

    def __init__(self, *, directory_fd, expected_device, expected_inode,
            expected_uid, expected_gid, quota_bytes, maximum_records):
        for value, minimum, maximum, label in (
            (directory_fd, 0, 2**31 - 1, "directory descriptor"),
            (expected_device, 0, 2**64 - 1, "directory device"),
            (expected_inode, 1, 2**64 - 1, "directory inode"),
            (expected_uid, 0, 2**32 - 2, "directory owner UID"),
            (expected_gid, 0, 2**32 - 2, "directory owner GID"),
            (quota_bytes, 1, MAX_QUOTA_BYTES, "journal quota"),
            (maximum_records, 1, MAX_RECORDS, "journal record limit"),
        ):
            _integer(value, minimum=minimum, maximum=maximum, label=label)
        self._pid = os.getpid()
        self._binding = (expected_device, expected_inode, expected_uid, expected_gid)
        self._quota, self._maximum_records = quota_bytes, maximum_records
        self._closed = False
        self._entries = {}
        self._file_identities = {}
        self._used_bytes = 0
        self._reserved_bytes = 0
        self._directory_stamp = None
        self._io = None
        self._directory_fd = None
        if (os.geteuid(), os.getegid()) != (expected_uid, expected_gid):
            raise CustodyJournalError("journal writer identity differs from its provisioned owner")
        self._directory_metadata(directory_fd)
        try:
            # Unlike dup(), this acquires an independent open-file description
            # and cannot share a successful flock with another journal owner.
            self._directory_fd = os.open(".",
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_fd)
            self._directory_metadata(self._directory_fd)
            fcntl.flock(self._directory_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._io = WitnessJournalIO(self._directory_fd,
                maximum_record_bytes=_MAX_RECORD_BYTES)
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
                or stat.S_IMODE(metadata.st_mode) != 0o700
                or (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid)
                    != self._binding):
            raise CustodyJournalError("journal directory differs from its private pinned identity")
        return metadata

    def _stamp(self):
        metadata = self._directory_metadata(self._directory_fd)
        return (metadata.st_dev, metadata.st_ino, metadata.st_mtime_ns, metadata.st_ctime_ns)

    def _require_process(self):
        if os.getpid() != self._pid:
            raise CustodyJournalError("journal cannot be used or closed by a forked process")
        if self._closed:
            raise CustodyJournalError("journal is closed")

    def _require_ready(self):
        self._require_process()
        self._io.require_ready()
        try:
            if self._stamp() != self._directory_stamp:
                raise CustodyJournalError("journal directory changed outside its owner")
        except BaseException:
            self._io.poison()
            raise

    def _read_file(self, name, *, maximum_bytes, synchronize=False):
        descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=self._directory_fd)
        try:
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o400
                    or before.st_nlink != 1 or before.st_dev != self._binding[0]
                    or (before.st_uid, before.st_gid) != self._binding[2:]
                    or not 1 <= before.st_size <= maximum_bytes):
                raise CustodyJournalError("journal record is not bounded private immutable material")
            encoded = bytearray()
            while len(encoded) < before.st_size:
                chunk = os.read(descriptor, min(_READ_CHUNK, before.st_size - len(encoded)))
                if not chunk:
                    raise CustodyJournalError("journal record was truncated")
                encoded.extend(chunk)
            if os.read(descriptor, 1):
                raise CustodyJournalError("journal record grew while reading")
            if synchronize:
                os.fsync(descriptor)
            after = os.fstat(descriptor)
            if _identity(before) != _identity(after):
                raise CustodyJournalError("journal record identity changed while reading")
            return bytes(encoded), _identity(after)
        finally:
            os.close(descriptor)

    def _recover(self):
        before = self._stamp()
        prepared = {}
        attempted = set()
        observed = set()
        count = 0
        with os.scandir(self._directory_fd) as entries:
            for entry in entries:
                count += 1
                if count > 3 * self._maximum_records:
                    raise CustodyJournalError("journal physical file limit exceeded")
                name = entry.name
                if name.startswith("prepared-"):
                    kind = "prepared"
                elif name.startswith("attempted-"):
                    kind = "attempted"
                else:
                    kind = "observed"
                prefix = kind + "-"
                suffix = name[len(prefix):]
                if (not name.startswith(prefix) or len(suffix) != 64
                        or any(character not in _HEX for character in suffix)):
                    raise CustodyJournalError("journal contains an unknown or temporary file")
                digest = "sha256:" + suffix
                maximum = (_MAX_RECORD_BYTES if kind == "prepared" else
                    _ATTEMPT_BYTES if kind == "attempted" else observations.MAX_OBSERVATION_BYTES)
                encoded, identity = self._read_file(name,
                    maximum_bytes=min(maximum, self._quota - self._used_bytes), synchronize=True)
                self._used_bytes += len(encoded)
                self._file_identities[name] = identity
                if kind == "prepared":
                    record = _decode_prepared(encoded)
                    if record.digest != digest or digest in prepared:
                        raise CustodyJournalError("prepared filename differs from its original content")
                    prepared[digest] = JournalEntry(digest, record.family, record.selector,
                        record.source_revision, len(encoded), False)
                    if len(prepared) > self._maximum_records:
                        raise CustodyJournalError("journal prepared record limit exceeded")
                elif kind == "attempted":
                    if encoded != _ATTEMPT_MAGIC + bytes.fromhex(suffix) or digest in attempted:
                        raise CustodyJournalError("journal attempt marker is not exact")
                    attempted.add(digest)
                else:
                    observation = observations.decode_observation(encoded)
                    if observation.local_digest != digest or digest in observed:
                        raise CustodyJournalError("journal observation does not match its local record")
                    observed.add(digest)
        if not attempted <= prepared.keys():
            raise CustodyJournalError("journal attempt marker has no prepared original")
        retention_only = {digest for digest, entry in prepared.items()
            if entry.family == execution_records.FAMILY}
        if (attempted | observed) & retention_only:
            raise CustodyJournalError("retention-only grant record cannot have delivery markers")
        if not observed <= attempted:
            raise CustodyJournalError("journal observation has no prepared and attempted original")
        marker_records = len(prepared) - len(retention_only)
        self._reserved_bytes = ((marker_records - len(attempted)) * _ATTEMPT_BYTES
            + (marker_records - len(observed)) * _OBSERVATION_RESERVE)
        if self._used_bytes + self._reserved_bytes > self._quota:
            raise CustodyJournalError("journal has insufficient reserved marker capacity")
        self._entries = {digest: replace(entry, attempted=digest in attempted, observed=digest in observed)
            for digest, entry in prepared.items()}
        if self._stamp() != before:
            raise CustodyJournalError("journal directory changed during recovery")
        return before

    def _load(self, digest):
        info = self._entries.get(digest)
        if info is None:
            raise CustodyJournalError("local prepared record is absent")
        name = _name("prepared", digest)
        encoded, identity = self._read_file(name, maximum_bytes=info.prepared_bytes)
        record = _decode_prepared(encoded)
        if (identity != self._file_identities[name] or record.digest != digest
                or (record.family, record.selector, record.source_revision)
                    != (info.family, info.selector, info.source_revision)):
            raise CustodyJournalError("prepared record changed after admitted recovery")
        if info.family == execution_records.FAMILY and (info.attempted or info.observed):
            raise CustodyJournalError("retention-only grant record cannot have delivery markers")
        if info.attempted:
            marker_name = _name("attempted", digest)
            marker, marker_identity = self._read_file(marker_name, maximum_bytes=_ATTEMPT_BYTES)
            if (marker != _ATTEMPT_MAGIC + bytes.fromhex(digest[7:])
                    or marker_identity != self._file_identities[marker_name]):
                raise CustodyJournalError("attempt marker changed after admitted recovery")
        if info.observed:
            if not info.attempted:
                raise CustodyJournalError("observed local record has no attempt")
            self._read_observation(digest)
        return record, encoded

    def _read_observation(self, digest):
        name = _name("observed", digest)
        encoded, identity = self._read_file(name, maximum_bytes=observations.MAX_OBSERVATION_BYTES)
        observation = observations.decode_observation(encoded)
        if identity != self._file_identities[name] or observation.local_digest != digest:
            raise CustodyJournalError("observation changed after admitted recovery")
        return observation, encoded

    def _publish(self, kind, digest, encoded):
        name = _name(kind, digest)
        temporary = ".tmp-" + name
        self._io.publish(temporary, name, encoded)
        stored, identity = self._read_file(name, maximum_bytes=len(encoded))
        if stored != encoded:
            raise CustodyJournalError("published journal bytes differ from the original")
        self._file_identities[name] = identity
        self._directory_stamp = self._stamp()

    def _append(self, digest, encoded):
        if digest in self._entries:
            try:
                _, original = self._load(digest)
                if original != encoded:
                    raise CustodyJournalError("duplicate preparation changed exact originals")
                self._require_ready()
                return digest
            except BaseException:
                self._io.poison()
                raise
        record = _decode_prepared(encoded)
        marker_reserve = (0 if record.family == execution_records.FAMILY else
            _ATTEMPT_BYTES + _OBSERVATION_RESERVE)
        if (len(self._entries) >= self._maximum_records
                or len(encoded) + marker_reserve
                    > self._quota - self._used_bytes - self._reserved_bytes):
            raise CustodyJournalError("journal preparation capacity is exhausted")
        try:
            self._publish("prepared", digest, encoded)
            self._used_bytes += len(encoded)
            self._reserved_bytes += marker_reserve
            self._entries[digest] = JournalEntry(digest, record.family, record.selector,
                record.source_revision, len(encoded), False)
            self._require_ready()
            return digest
        except BaseException:
            self._io.poison()
            raise

    def append_evidence(self, purpose, originals):
        self._require_process()
        with self._io.ready():
            self._require_ready()
            return self._append(*records.encode_evidence(purpose, originals))

    def append_transition(self, operation, originals):
        self._require_process()
        with self._io.ready():
            self._require_ready()
            return self._append(*records.encode_transition(operation, originals))

    def append_registration_execution_grant(self, originals):
        """Durably retain original raw10, without forwarding or execution authority."""
        self._require_process()
        with self._io.ready():
            self._require_ready()
            return self._append(*execution_records.encode(originals))

    def load(self, localdigest):
        digest = _digest(localdigest)
        self._require_process()
        with self._io.ready():
            self._require_ready()
            if digest not in self._entries:
                raise CustodyJournalError("local prepared record is absent")
            try:
                record, _ = self._load(digest)
                self._require_ready()
                return record
            except BaseException:
                self._io.poison()
                raise

    def claim_attempt(self, localdigest):
        digest = _digest(localdigest)
        self._require_process()
        with self._io.ready():
            self._require_ready()
            entry = self._entries.get(digest)
            if entry is None:
                raise CustodyJournalError("cannot attempt an absent local record")
            if entry.family == execution_records.FAMILY:
                raise CustodyJournalError("retention-only grant record cannot be attempted")
            if entry.attempted:
                raise CustodyJournalError("local record already has an attempt; repeat delivery is forbidden")
            try:
                self._load(digest)
                self._require_ready()
                self._publish("attempted", digest, _ATTEMPT_MAGIC + bytes.fromhex(digest[7:]))
                self._used_bytes += _ATTEMPT_BYTES
                self._reserved_bytes -= _ATTEMPT_BYTES
                self._entries[digest] = replace(entry, attempted=True)
                self._require_ready()
            except BaseException:
                self._io.poison()
                raise

    def record_observation(self, localdigest, *, retained_record_digest,
            retained_at_epoch_ns, configuration_digest):
        """Durably retain one exact successful-read observation, not authority."""
        # The codec holds all exact immutable scalars, including current source,
        # before the first filesystem/lease callback in this operation.
        observation, encoded = observations.encode_observation(localdigest,
            retained_record_digest=retained_record_digest,
            retained_at_epoch_ns=retained_at_epoch_ns, configuration_digest=configuration_digest)
        digest = observation.local_digest
        self._require_process()
        with self._io.ready():
            self._require_ready()
            entry = self._entries.get(digest)
            if entry is not None and entry.family == execution_records.FAMILY:
                raise CustodyJournalError("retention-only grant record cannot have an observation")
            if entry is None or not entry.attempted:
                raise CustodyJournalError("readback observation requires a prepared and attempted record")
            try:
                self._load(digest)
                if entry.observed:
                    previous, original = self._read_observation(digest)
                    if original != encoded:
                        raise CustodyJournalError("first readback observation cannot change its exact metadata")
                    self._require_ready()
                    return previous
                if (self._reserved_bytes < _OBSERVATION_RESERVE
                        or len(encoded) > _OBSERVATION_RESERVE):
                    raise CustodyJournalError("journal observation reservation is inconsistent")
                self._require_ready()
                self._publish("observed", digest, encoded)
                self._used_bytes += len(encoded)
                self._reserved_bytes -= _OBSERVATION_RESERVE
                self._entries[digest] = replace(entry, observed=True)
                self._require_ready()
                return observation
            except BaseException:
                self._io.poison()
                raise

    def load_observation(self, localdigest):
        """Return first local readback metadata, or None, never remote absence."""
        digest = _digest(localdigest)
        self._require_process()
        with self._io.ready():
            self._require_ready()
            entry = self._entries.get(digest)
            if entry is None:
                raise CustodyJournalError("local prepared record is absent")
            try:
                # This validates prepared content and any attempt/observation
                # identities. A missing local marker is not a failed lookup.
                self._load(digest)
                observation = self._read_observation(digest)[0] if entry.observed else None
                self._require_ready()
                return observation
            except BaseException:
                self._io.poison()
                raise

    def inventory(self):
        """Return bounded metadata, never all original byte records."""
        self._require_process()
        with self._io.ready():
            self._require_ready()
            return tuple(self._entries[digest] for digest in sorted(self._entries))

    def close(self):
        if os.getpid() != self._pid:
            raise CustodyJournalError("forked process cannot close the parent journal owner")
        if self._closed:
            return
        with self._io.lock:
            if not self._closed:
                self._closed = True
                self._io.poison()
                # Closing the sole private open-file description releases its
                # lease; never explicitly unlock the caller's borrowed FD.
                os.close(self._directory_fd)

    def __enter__(self):
        self._require_process()
        with self._io.ready():
            self._require_ready()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False
