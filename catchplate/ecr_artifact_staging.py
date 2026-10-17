"""Unsigned, local preparation of one exact OCI/Docker image artifact.

Only caller-selected digest paths under an OCI blob directory are read. A new
private destination is mandatory; failures preserve it for inspection and never
overwrite, resume or reuse it. The complete, synced marker is published last by
an atomic no-replace link. Failure once publication starts is explicitly
uncertain. Only our matching pending marker link is removed after publication.

This is not approval, immutable custody, a signature, native authority or AWS
acceptance. Files remain owned by the preparer and must be verified again by any
future consumer. There are no keys, environment configuration or network calls.
"""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from catchplate import ecr_image_artifact as image


SCHEMA = "catchplate.ecrArtifactStage/v1"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CHUNK = 1024 * 1024
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class ArtifactStagingError(ValueError):
    """Fixed diagnostic; never includes paths, bytes or underlying exceptions."""

    def __init__(self, *, completion_uncertain: bool = False):
        self.completion_uncertain = completion_uncertain
        super().__init__("ECR artifact stage completion uncertain; preserve destination"
            if completion_uncertain else "ECR artifact staging unavailable; preserve destination")


def _require(value):
    if not value:
        raise ArtifactStagingError()


def _path(value):
    _require(isinstance(value, (str, Path)))
    raw = str(value)
    result = Path(raw)
    _require(1 < len(raw) <= 4096 and result.is_absolute() and raw == str(result)
        and raw == os.path.normpath(raw) and not raw.startswith("//")
        and ".." not in result.parts and len(result.parts) <= 128
        and not any(ord(character) < 32 for character in raw))
    return result


def _directory_identity(info):
    _require(stat.S_ISDIR(info.st_mode))
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def _file_identity(info, *, private):
    _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
    if private:
        _require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600)
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class _Custody:
    """Held directory/name identities for this one call, not an authority cache."""

    def __init__(self, stack):
        self.stack, self.directories = stack, []
        self.process = os.getpid(), os.geteuid(), os.getegid()

    def check(self):
        _require(self.process == (os.getpid(), os.geteuid(), os.getegid()))
        for descriptor, parent, name, identity in self.directories:
            _require(_directory_identity(os.fstat(descriptor)) == identity)
            if parent is not None:
                _require(_directory_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity)

    def directory(self, parent, name):
        descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
        self.stack.callback(os.close, descriptor)
        identity = _directory_identity(os.fstat(descriptor))
        self.directories.append((descriptor, parent, name, identity))
        self.check()
        return descriptor

    def path(self, path):
        descriptor = self.directory(None, "/")
        chain = [os.fstat(descriptor)]
        for part in path.parts[1:]:
            descriptor = self.directory(descriptor, part)
            chain.append(os.fstat(descriptor))
        return descriptor, chain

    def new_directory(self, parent, name):
        self.check()
        os.mkdir(name, 0o700, dir_fd=parent)
        descriptor = self.directory(parent, name)
        info = os.fstat(descriptor)
        _require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700)
        return descriptor


class _Reader:
    """Read-only bounded BinaryIO seam, with fresh held/name checks per read."""

    def __init__(self, custody, directory, name, *, limit, size=None, private=False):
        self.custody, self.directory, self.name, self.private = custody, directory, name, private
        self.descriptor = os.open(name, _READ_FLAGS, dir_fd=directory)
        custody.stack.callback(os.close, self.descriptor)
        info = os.fstat(self.descriptor)
        self.identity = _file_identity(info, private=private)
        _require(1 <= info.st_size <= limit and (size is None or info.st_size == size))
        self.size, self.offset, self.calls, self.eof = info.st_size, 0, 0, False
        self.check()

    def check(self):
        self.custody.check()
        _require(_file_identity(os.fstat(self.descriptor), private=self.private) == self.identity
            and _file_identity(os.stat(self.name, dir_fd=self.directory, follow_symlinks=False),
                private=self.private) == self.identity)

    def read(self, size):
        _require(type(size) is int and 1 <= size <= _CHUNK and self.calls < image.MAX_READ_CALLS_PER_BLOB)
        self.check()
        self.calls += 1
        raw = os.pread(self.descriptor, min(size, self.size - self.offset + 1), self.offset)
        self.offset += len(raw)
        _require(self.offset <= self.size)
        if not raw:
            _require(self.offset == self.size)
            self.eof = True
        self.check()
        return raw


def _chunks(reader):
    while True:
        raw = reader.read(_CHUNK)
        if not raw:
            return
        yield raw


def _read_all(reader):
    return b"".join(_chunks(reader))


def _write_new(custody, directory, name, chunks, *, size, digest):
    custody.check()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open(name, flags, 0o600, dir_fd=directory)
    try:
        os.fchmod(descriptor, 0o600)
        created = os.fstat(descriptor)
        _file_identity(created, private=True)
        count, actual = 0, hashlib.sha256()
        for raw in chunks:
            _require(type(raw) is bytes and 0 < len(raw) <= _CHUNK)
            custody.check()
            count += len(raw)
            _require(count <= size)
            actual.update(raw)
            remaining = memoryview(raw)
            while remaining:
                written = os.write(descriptor, remaining)
                _require(type(written) is int and 0 < written <= len(remaining))
                remaining = remaining[written:]
        _require(count == size and "sha256:" + actual.hexdigest() == digest)
        os.fsync(descriptor)
        current = os.fstat(descriptor)
        _file_identity(current, private=True)
        _require((current.st_dev, current.st_ino, current.st_size) == (created.st_dev, created.st_ino, size)
            and _file_identity(os.stat(name, dir_fd=directory, follow_symlinks=False), private=True)
                == _file_identity(current, private=True))
        custody.check()
    finally:
        os.close(descriptor)


def _bytes_chunks(raw):
    for offset in range(0, len(raw), _CHUNK):
        yield raw[offset:offset + _CHUNK]


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha256(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _roster(directory, expected):
    seen = set()
    with os.scandir(directory) as entries:
        for entry in entries:
            _require(entry.name in expected and entry.name not in seen)
            seen.add(entry.name)
    _require(seen == expected)


def _marker_aliases(directory, identity):
    for name in ("stage.pending", "stage.json"):
        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
        _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 2
            and (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                info.st_size, info.st_mtime_ns) == identity[:5] + identity[6:8])


def stage_artifact(source_directory, destination_directory, manifest_digest):
    """Create one new unsigned stage; never adopt or repair an existing stage.

    ``source_directory`` contains ``blobs/sha256/<digest hex>``. Unselected OCI
    blobs are not read. The destination's existing parent must be private 0700
    and owned by this effective UID. Both paths must be canonical and absolute.
    The returned closed marker binds exact manifest bytes and the verifier's
    public commitment; it does not permit a push or establish immutable custody.
    """
    marker_started = False
    try:
        source, destination = _path(source_directory), _path(destination_directory)
        _require(type(manifest_digest) is str and _DIGEST.fullmatch(manifest_digest) is not None)
        _require(source != destination and source not in destination.parents and destination not in source.parents)
        with ExitStack() as stack:
            custody = _Custody(stack)
            source_fd, _ = custody.path(source)
            parent_fd, parent_chain = custody.path(destination.parent)
            parent_info = os.fstat(parent_fd)
            _require(parent_info.st_uid == os.geteuid() and stat.S_IMODE(parent_info.st_mode) == 0o700)
            source_info = os.fstat(source_fd)
            _require(all((row.st_dev, row.st_ino) != (source_info.st_dev, source_info.st_ino) for row in parent_chain))
            # Refuse an existing destination before reading the selected blobs.
            try:
                os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ArtifactStagingError()
            source_blob_root = custody.directory(source_fd, "blobs")
            source_blobs = custody.directory(source_blob_root, "sha256")
            selected_directories = {(os.fstat(fd).st_dev, os.fstat(fd).st_ino)
                for fd in (source_fd, source_blob_root, source_blobs)}
            _require(all((row.st_dev, row.st_ino) not in selected_directories for row in parent_chain))
            manifest_reader = _Reader(custody, source_blobs, manifest_digest[7:], limit=image.MAX_MANIFEST_BYTES)
            manifest = _read_all(manifest_reader)
            _require(_sha256(manifest) == manifest_digest)
            description = image.parse_manifest(manifest)
            _require(description.manifest.digest == manifest_digest)
            stage_fd = custody.new_directory(parent_fd, destination.name)
            blobs_fd = custody.new_directory(stage_fd, "blobs")
            os.fsync(parent_fd)
            _write_new(custody, stage_fd, "manifest.json", _bytes_chunks(manifest),
                size=len(manifest), digest=manifest_digest)
            for blob in description.blobs:
                reader = _Reader(custody, source_blobs, blob.digest[7:], limit=image.MAX_BLOB_BYTES, size=blob.size)
                _write_new(custody, blobs_fd, blob.digest[7:], _chunks(reader), size=blob.size, digest=blob.digest)
            # Independent readback uses only newly opened, owned destination FDs.
            copied_manifest_reader = _Reader(custody, stage_fd, "manifest.json",
                limit=image.MAX_MANIFEST_BYTES, size=len(manifest), private=True)
            copied_manifest = _read_all(copied_manifest_reader)
            _require(copied_manifest == manifest)
            readers = {blob.digest: _Reader(custody, blobs_fd, blob.digest[7:],
                limit=image.MAX_BLOB_BYTES, size=blob.size, private=True) for blob in description.blobs}
            verified = image.verify_image(copied_manifest, readers)
            _require(all(reader.eof and reader.offset == reader.size for reader in readers.values()))
            artifact = _encoded(verified.commitment())
            _require(1 <= len(artifact) <= image.MAX_MANIFEST_BYTES
                and _sha256(artifact) == verified.commitment_sha256)
            _write_new(custody, stage_fd, "artifact.json", _bytes_chunks(artifact),
                size=len(artifact), digest=verified.commitment_sha256)
            artifact_reader = _Reader(custody, stage_fd, "artifact.json", limit=image.MAX_MANIFEST_BYTES,
                size=len(artifact), private=True)
            _require(_read_all(artifact_reader) == artifact)
            _roster(blobs_fd, {blob.digest[7:] for blob in description.blobs})
            _roster(stage_fd, {"blobs", "manifest.json", "artifact.json"})
            for reader in (copied_manifest_reader, artifact_reader, *readers.values()):
                reader.check()
            custody.check()
            os.fsync(blobs_fd)
            os.fsync(stage_fd)
            os.fsync(parent_fd)
            marker = {"schema": SCHEMA, "artifactSha256": verified.commitment_sha256,
                "manifestDigest": manifest_digest, "unsigned": True}
            encoded_marker = _encoded(marker)
            _write_new(custody, stage_fd, "stage.pending", _bytes_chunks(encoded_marker),
                size=len(encoded_marker), digest=_sha256(encoded_marker))
            pending_reader = _Reader(custody, stage_fd, "stage.pending", limit=4096,
                size=len(encoded_marker), private=True)
            _require(_read_all(pending_reader) == encoded_marker)
            _roster(stage_fd, {"blobs", "manifest.json", "artifact.json", "stage.pending"})
            for reader in (copied_manifest_reader, artifact_reader, pending_reader, *readers.values()):
                reader.check()
            os.fsync(stage_fd)
            for reader in (copied_manifest_reader, artifact_reader, pending_reader, *readers.values()):
                reader.check()
            # Atomic EEXIST refusal: a stage.json can never expose partial JSON.
            marker_started = True
            os.link("stage.pending", "stage.json", src_dir_fd=stage_fd, dst_dir_fd=stage_fd,
                follow_symlinks=False)
            pending_identity = pending_reader.identity
            _marker_aliases(stage_fd, pending_identity)
            custody.check()
            os.fsync(stage_fd)
            # This is the only removal: our exact newly-created pending alias.
            _marker_aliases(stage_fd, pending_identity)
            os.unlink("stage.pending", dir_fd=stage_fd)
            _require(_read_all(_Reader(custody, stage_fd, "stage.json", limit=4096,
                size=len(encoded_marker), private=True)) == encoded_marker)
            _roster(stage_fd, {"blobs", "manifest.json", "artifact.json", "stage.json"})
            os.fsync(stage_fd)
            _roster(blobs_fd, {blob.digest[7:] for blob in description.blobs})
            for reader in (copied_manifest_reader, artifact_reader, *readers.values()):
                reader.check()
            custody.check()
            return marker
    except Exception:
        raise ArtifactStagingError(completion_uncertain=marker_started) from None
