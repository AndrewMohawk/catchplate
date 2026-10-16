"""Private, bounded durable uploads for ordinary host-trusted ECR publications.

The publication owner, not this module, authorizes a current client and performs
its status/CAS checks before each call. Paths are server configuration plus an
opaque canonical UUID; uploaded bytes never choose paths. Each stage is new and
retained, including failures. There is deliberately no automatic deletion or
reuse. Four retained stages bound blob storage to four GiB, plus bounded image
manifests/metadata. The caller owns HTTP deadlines and bounded request reads.

This emits the existing ecrArtifactStage/v1 format, but a marker is not proof of
content. Finalization and every later capture verify the actual durable streams
through ecr_image_custody.capture, returning process-owned sealed bytes. Nothing
here authorizes, signs, dispatches, extracts, decompresses or fetches an image.
"""
from __future__ import annotations

from contextlib import ExitStack
import fcntl
from functools import wraps
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading
import uuid

from . import ecr_artifact_staging as staging
from . import ecr_image_artifact as artifact
from . import ecr_image_custody as custody


MAX_STAGES = 4
MAX_PART_BYTES = 4 * 1024 * 1024
ROOT_ENVIRONMENT_VARIABLE = "SERVERWARE_ECR_ARTIFACT_ROOT"
_CHUNK = artifact.READ_CHUNK_BYTES
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_NEW = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


class ArtifactStoreError(ValueError):
    """Fixed redacted diagnostic; any partial stage is retained for inspection."""

    def __init__(self, *, completion_uncertain=False):
        self.completion_uncertain = bool(completion_uncertain)
        super().__init__("ECR artifact completion uncertain; preserve stage"
            if completion_uncertain else "ECR artifact unavailable; preserve stage")


def _require(value):
    if not value:
        raise ArtifactStoreError()


def _safe(function):
    @wraps(function)
    def invoke(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except ArtifactStoreError:
            raise
        except Exception:
            raise ArtifactStoreError() from None
    return invoke


def _identifier(value):
    _require(type(value) is str and len(value) == 36 and str(uuid.UUID(value)) == value)
    return value


def _digest(value):
    _require(type(value) is str and _DIGEST.fullmatch(value) is not None)
    return value


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False).encode("utf-8")


def _hash(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _directory_identity(info, *, private=False):
    _require(stat.S_ISDIR(info.st_mode))
    if private:
        _require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700)
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def _file_identity(info, *, links=1):
    _require(stat.S_ISREG(info.st_mode) and info.st_nlink == links
        and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600)
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class _Access:
    """Held, rechecked ancestor and stage identities; no pathname following."""

    def __init__(self, store, stage_id=None):
        self.stack, self.directories = ExitStack(), []
        self.owner = os.getpid(), os.geteuid(), os.getegid()
        try:
            descriptor = self.directory(None, "/")
            for part in store._root.parts[1:]:
                descriptor = self.directory(descriptor, part)
            self.root = descriptor
            identity = _directory_identity(os.fstat(descriptor), private=True)
            _require(store._identity is None or store._identity == identity)
            self.stage = None
            if stage_id is not None:
                self.stage = self.directory(self.root, _identifier(stage_id), private=True)
                fcntl.flock(self.stage, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.check()
        except BaseException:
            self.stack.close()
            raise

    def directory(self, parent, name, *, private=False):
        descriptor = os.open(name, _DIRECTORY, dir_fd=parent)
        self.stack.callback(os.close, descriptor)
        identity = _directory_identity(os.fstat(descriptor), private=private)
        self.directories.append((descriptor, parent, name, identity, private))
        return descriptor

    def check(self):
        _require(self.owner == (os.getpid(), os.geteuid(), os.getegid()))
        for descriptor, parent, name, identity, private in self.directories:
            _require(_directory_identity(os.fstat(descriptor), private=private) == identity)
            if parent is not None:
                _require(_directory_identity(os.stat(name, dir_fd=parent,
                    follow_symlinks=False), private=private) == identity)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stack.close()


class _Reader:
    def __init__(self, access, directory, name, *, limit, size=None):
        self.access, self.directory, self.name = access, directory, name
        self.fd = os.open(name, _READ, dir_fd=directory)
        access.stack.callback(os.close, self.fd)
        info = os.fstat(self.fd)
        self.identity = _file_identity(info)
        self.size, self.offset, self.calls = info.st_size, 0, 0
        _require(1 <= self.size <= limit and (size is None or self.size == size))
        self.check()

    def check(self):
        self.access.check()
        _require(_file_identity(os.fstat(self.fd)) == self.identity
            and _file_identity(os.stat(self.name, dir_fd=self.directory,
                follow_symlinks=False)) == self.identity)

    def read(self, amount):
        _require(type(amount) is int and 1 <= amount <= _CHUNK
            and self.calls < artifact.MAX_READ_CALLS_PER_BLOB)
        self.check()
        raw = os.pread(self.fd, min(amount, self.size - self.offset + 1), self.offset)
        self.calls += 1
        self.offset += len(raw)
        _require(self.offset <= self.size)
        self.check()
        return raw


def _read_all(reader):
    result = bytearray()
    while True:
        raw = reader.read(_CHUNK)
        if not raw:
            _require(reader.offset == reader.size)
            return bytes(result)
        result.extend(raw)


def _absent(directory, name):
    try:
        os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise ArtifactStoreError()


def _roster(directory, expected):
    seen = set()
    with os.scandir(directory) as entries:
        for entry in entries:
            _require(entry.name in expected and entry.name not in seen)
            seen.add(entry.name)
    _require(seen == expected)


def _write_all(fd, raw):
    # Bounded input is split to the verifier's normal one-MiB I/O budget.
    calls = offset = 0
    while offset < len(raw):
        _require(calls < 8192)
        written = os.write(fd, memoryview(raw)[offset:offset + _CHUNK])
        _require(type(written) is int and 0 < written <= min(_CHUNK, len(raw) - offset))
        offset += written
        calls += 1


def _publish(access, directory, pending, final, fd):
    """Atomic no-replace publication, then removal of only our matching alias."""
    access.check()
    identity = _file_identity(os.fstat(fd))
    _require(_file_identity(os.stat(pending, dir_fd=directory,
        follow_symlinks=False)) == identity)
    os.link(pending, final, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
    # Linking changes ctime. Both names must refer to this owned inode and have
    # precisely two links before the temporary alias can be removed.
    current = _file_identity(os.fstat(fd), links=2)
    _require(current[:7] == identity[:7])
    for name in (pending, final):
        _require(_file_identity(os.stat(name, dir_fd=directory,
            follow_symlinks=False), links=2) == current)
    access.check()
    os.fsync(directory)
    os.unlink(pending, dir_fd=directory)
    _require(_file_identity(os.stat(final, dir_fd=directory,
        follow_symlinks=False)) == _file_identity(os.fstat(fd)))
    os.fsync(directory)
    access.check()


def _write_atomic(access, directory, final, raw):
    pending = final.removesuffix(".json") + ".pending"
    _absent(directory, final)
    fd = os.open(pending, _NEW, 0o600, dir_fd=directory)
    try:
        os.fchmod(fd, 0o600)
        _file_identity(os.fstat(fd))
        _write_all(fd, raw)
        _require(os.fstat(fd).st_size == len(raw))
        os.fsync(fd)
        _publish(access, directory, pending, final, fd)
    finally:
        os.close(fd)


def _description(access):
    raw = _read_all(_Reader(access, access.stage, "manifest.json",
        limit=artifact.MAX_MANIFEST_BYTES))
    return artifact.parse_manifest(raw)


def _capture(access, description):
    blobs = access.directory(access.stage, "blobs", private=True)
    _roster(blobs, {blob.digest[7:] for blob in description.blobs})
    readers = {blob.digest: _Reader(access, blobs, blob.digest[7:],
        limit=artifact.MAX_BLOB_BYTES, size=blob.size) for blob in description.blobs}
    sealed = custody.capture(description.manifest_bytes, readers)
    try:
        for reader in readers.values():
            reader.check()
        access.check()
        return sealed
    except BaseException:
        sealed.close()
        raise


def _marker(image):
    return {"schema": staging.SCHEMA, "artifactSha256": image.commitment_sha256,
        "manifestDigest": image.manifest.digest, "unsigned": True}


class ArtifactStore:
    """Dedicated existing private root; no path comes from an HTTP caller.

    ``max_stages`` is deliberately at most four and counts every retained UUID,
    including failed/completed stages, across process restarts. Admission does
    not reserve server RAM; callers must bound concurrent sealed captures and
    close every returned SealedImage when its active publication ends.
    """

    @_safe
    def __init__(self, root, *, max_stages=MAX_STAGES):
        _require(isinstance(root, (str, Path)))
        raw, path = str(root), Path(root)
        _require(path.is_absolute() and 1 < len(raw) <= 4096 and raw == str(path)
            and raw == os.path.normpath(raw) and not raw.startswith("//")
            and ".." not in path.parts and len(path.parts) <= 128
            and not any(ord(character) < 32 for character in raw))
        _require(type(max_stages) is int and 1 <= max_stages <= MAX_STAGES)
        self._root, self._identity, self._max_stages = path, None, max_stages
        self._lock, self._owner = threading.RLock(), (os.getpid(), os.geteuid(), os.getegid())
        with _Access(self) as access:
            self._identity = _directory_identity(os.fstat(access.root), private=True)

    def __repr__(self):
        return "ArtifactStore(<server-owned private artifact root>)"

    def _check(self):
        # Check before locking so forked children cannot wait on inherited locks.
        _require(self._owner == (os.getpid(), os.geteuid(), os.getegid()))

    @_safe
    def begin(self, stage_id=None):
        """Create a fresh stage, optionally using an owner-generated UUID."""
        self._check()
        stage_id = str(uuid.uuid4()) if stage_id is None else _identifier(stage_id)
        with self._lock, _Access(self) as access:
            fcntl.flock(access.root, fcntl.LOCK_EX | fcntl.LOCK_NB)
            count = 0
            with os.scandir(access.root) as entries:
                for entry in entries:
                    _identifier(entry.name)
                    _directory_identity(entry.stat(follow_symlinks=False), private=True)
                    count += 1
                    _require(count < self._max_stages)
            access.check()
            os.mkdir(stage_id, 0o700, dir_fd=access.root)
            stage = access.directory(access.root, stage_id, private=True)
            os.mkdir("blobs", 0o700, dir_fd=stage)
            blobs = access.directory(stage, "blobs", private=True)
            os.fsync(blobs)
            os.fsync(stage)
            os.fsync(access.root)
            access.check()
            return stage_id

    @_safe
    def write_manifest(self, stage_id, manifest_bytes):
        """Commit one original manifest; validate its entire declared roster first."""
        self._check()
        description = artifact.parse_manifest(manifest_bytes)
        with self._lock, _Access(self, stage_id) as access:
            _roster(access.stage, {"blobs"})
            blobs = access.directory(access.stage, "blobs", private=True)
            _roster(blobs, set())
            _write_atomic(access, access.stage, "manifest.json", manifest_bytes)
            stored = _description(access)
            _require(stored.manifest_bytes == manifest_bytes)
            return description

    @_safe
    def describe(self, stage_id):
        """Return parsed declarations, not proof of blob verification or approval."""
        self._check()
        with self._lock, _Access(self, stage_id) as access:
            return _description(access)

    @_safe
    def append_part(self, stage_id, digest, offset, raw):
        """Append exactly the next <=4MiB part; final bytes require the full hash.

        A lost acknowledgement can be reconciled using summary(). A repeated or
        reordered offset is refused, never silently overwritten or appended.
        An unsuccessful write can leave a partial file; it is never removed.
        """
        self._check()
        _digest(digest)
        _require(type(offset) is int and offset >= 0 and type(raw) is bytes
            and 1 <= len(raw) <= MAX_PART_BYTES)
        with self._lock, _Access(self, stage_id) as access:
            _roster(access.stage, {"blobs", "manifest.json"})
            description = _description(access)
            declared = next((blob for blob in description.blobs if blob.digest == digest), None)
            _require(declared is not None and offset + len(raw) <= declared.size)
            blobs = access.directory(access.stage, "blobs", private=True)
            final, pending = digest[7:], digest[7:] + ".pending"
            _absent(blobs, final)
            flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            if offset == 0:
                flags |= os.O_CREAT | os.O_EXCL
            fd = os.open(pending, flags, 0o600, dir_fd=blobs)
            try:
                if offset == 0:
                    os.fchmod(fd, 0o600)
                info = os.fstat(fd)
                identity = _file_identity(info)
                _require(info.st_size == offset and _file_identity(os.stat(pending,
                    dir_fd=blobs, follow_symlinks=False)) == identity)
                access.check()
                _require(os.lseek(fd, offset, os.SEEK_SET) == offset)
                _write_all(fd, raw)
                _require(os.fstat(fd).st_size == offset + len(raw))
                os.fsync(fd)
                os.fsync(blobs)
                _require(_file_identity(os.stat(pending, dir_fd=blobs,
                    follow_symlinks=False)) == _file_identity(os.fstat(fd)))
                access.check()
                complete = offset + len(raw) == declared.size
                if complete:
                    reader = _Reader(access, blobs, pending,
                        limit=artifact.MAX_BLOB_BYTES, size=declared.size)
                    hasher = hashlib.sha256()
                    while True:
                        chunk = reader.read(_CHUNK)
                        if not chunk:
                            break
                        hasher.update(chunk)
                    _require("sha256:" + hasher.hexdigest() == digest)
                    _publish(access, blobs, pending, final, fd)
                return {"digest": digest, "size": declared.size,
                    "uploaded_bytes": offset + len(raw), "complete": complete}
            finally:
                os.close(fd)

    @_safe
    def summary(self, stage_id):
        """Return bounded upload progress. This is not verified image content."""
        self._check()
        with self._lock, _Access(self, stage_id) as access:
            description = _description(access)
            blobs = access.directory(access.stage, "blobs", private=True)
            allowed = {name for blob in description.blobs
                for name in (blob.digest[7:], blob.digest[7:] + ".pending")}
            observed = {}
            with os.scandir(blobs) as entries:
                for entry in entries:
                    _require(entry.name in allowed)
                    info = entry.stat(follow_symlinks=False)
                    _file_identity(info)
                    observed[entry.name] = info.st_size
            rows = []
            for blob in description.blobs:
                name = blob.digest[7:]
                complete = name in observed
                _require(not (complete and name + ".pending" in observed))
                uploaded = observed.get(name, observed.get(name + ".pending", 0))
                _require(0 <= uploaded <= blob.size and (not complete or uploaded == blob.size))
                rows.append({"digest": blob.digest, "size": blob.size,
                    "uploaded_bytes": uploaded, "complete": complete})
            access.check()
            return {"manifest_digest": description.manifest.digest,
                "manifest_size": description.manifest.size,
                "total_blob_bytes": description.total_blob_bytes, "blobs": rows}

    @_safe
    def finalize(self, stage_id):
        """Verify every byte, durably publish the standard marker, return custody."""
        self._check()
        sealed, marker_started = None, False
        try:
            with self._lock, _Access(self, stage_id) as access:
                _roster(access.stage, {"blobs", "manifest.json"})
                description = _description(access)
                sealed = _capture(access, description)
                image = sealed.image
                encoded = _canonical(image.commitment())
                _require(_hash(encoded) == image.commitment_sha256)
                _write_atomic(access, access.stage, "artifact.json", encoded)
                marker_started = True
                _write_atomic(access, access.stage, "stage.json", _canonical(_marker(image)))
                _roster(access.stage, {"blobs", "manifest.json", "artifact.json", "stage.json"})
                _require(_read_all(_Reader(access, access.stage, "artifact.json",
                    limit=artifact.MAX_MANIFEST_BYTES)) == encoded)
                _require(_read_all(_Reader(access, access.stage, "stage.json", limit=4096))
                    == _canonical(_marker(image)))
                os.fsync(access.stage)
                os.fsync(access.root)
                access.check()
                result, sealed = sealed, None
                return result
        except Exception:
            raise ArtifactStoreError(completion_uncertain=marker_started) from None
        finally:
            if sealed is not None:
                sealed.close()

    @_safe
    def recapture(self, stage_id):
        """Reverify durable content after restart; never accept a marker alone."""
        self._check()
        sealed = None
        try:
            with self._lock, _Access(self, stage_id) as access:
                _roster(access.stage, {"blobs", "manifest.json", "artifact.json", "stage.json"})
                description = _description(access)
                artifact_reader = _Reader(access, access.stage, "artifact.json",
                    limit=artifact.MAX_MANIFEST_BYTES)
                marker_reader = _Reader(access, access.stage, "stage.json", limit=4096)
                stored_artifact, stored_marker = _read_all(artifact_reader), _read_all(marker_reader)
                sealed = _capture(access, description)
                image = sealed.image
                _require(stored_artifact == _canonical(image.commitment())
                    and stored_marker == _canonical(_marker(image)))
                artifact_reader.check()
                marker_reader.check()
                access.check()
                result, sealed = sealed, None
                return result
        finally:
            if sealed is not None:
                sealed.close()


@_safe
def configured_store():
    """Open the explicit server root; never create it or use a fallback path."""
    root = os.environ.get(ROOT_ENVIRONMENT_VARIABLE)
    _require(type(root) is str and bool(root))
    return ArtifactStore(root)


def configuration_ready():
    """Read-only root configuration check, not free capacity or publication readiness."""
    try:
        configured_store()
        return True
    except ArtifactStoreError:
        return False
