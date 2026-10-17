"""Process-local custody of actually verified image bytes in sealed Linux memfds.

The existing image verifier observes the same bytes copied into owned memfds;
all are write/grow/shrink/seal sealed before a handle is returned. Readers are
borrowed and never retained or closed. Caller-controlled blocking/cancellation
and publication authorization remain outside this component. This is neither
durable storage nor native/hostile-root authority, and no filesystem paths,
credentials, network requests or publication markers are used.

Linux sealing semantics: https://man7.org/linux/man-pages/man2/F_GET_SEALS.2const.html
"""
from __future__ import annotations

from dataclasses import dataclass
import fcntl
import os
import stat
import threading
from typing import BinaryIO

from . import ecr_image_artifact as artifact


MAX_RANGE_BYTES = 10 * 1024 * 1024
MAX_WRITE_CALLS_PER_BLOB = 8192
MAX_RANGE_READ_CALLS = 8192
_SEALS = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
_TOKEN = object()


class CustodyError(ValueError):
    def __init__(self):
        super().__init__("ECR image custody unavailable")


def _require(condition):
    if not condition:
        raise CustodyError()


def _owner():
    return os.getpid(), os.getuid(), os.geteuid()


def _identity(fd):
    value = os.fstat(fd)
    _require(stat.S_ISREG(value.st_mode))
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
        value.st_gid, value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


@dataclass(frozen=True, slots=True, repr=False)
class _HeldBlob:
    fd: int
    size: int
    identity: tuple


def _check_blob(blob):
    _require(_identity(blob.fd) == blob.identity and blob.identity[6] == blob.size)
    _require(fcntl.fcntl(blob.fd, fcntl.F_GET_SEALS) & _SEALS == _SEALS)
    _require(fcntl.fcntl(blob.fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC != 0)


def _close_fds(fds):
    # No retry: retrying a failed close could close a descriptor reused by
    # another thread. Attempt every owned descriptor even after cancellation.
    for fd in fds:
        try:
            os.close(fd)
        except BaseException:
            pass


class _CopyReader:
    __slots__ = ("read_source", "fd", "remaining", "writes", "owner")

    def __init__(self, read_source, fd, size, owner):
        self.read_source, self.fd, self.remaining = read_source, fd, size
        self.writes, self.owner = 0, owner

    def read(self, amount):
        _require(_owner() == self.owner)
        _require(type(amount) is int and 1 <= amount <= artifact.READ_CHUNK_BYTES)
        chunk = self.read_source(amount)
        # Inspect the untrusted result BEFORE allocating a view or copying it.
        _require(type(chunk) is bytes and len(chunk) <= amount and len(chunk) <= self.remaining)
        _require(_owner() == self.owner)
        view, offset = memoryview(chunk), 0
        while offset < len(chunk):
            _require(self.writes < MAX_WRITE_CALLS_PER_BLOB)
            written = os.write(self.fd, view[offset:])
            self.writes += 1
            _require(type(written) is int and 0 < written <= len(chunk) - offset)
            offset += written
        self.remaining -= len(chunk)
        return chunk


class SealedImage:
    """Owned finite-lifetime content, not a publication or approval capability."""
    __slots__ = ("_image", "_blobs", "_owner", "_lock", "_closed")

    def __init__(self, token=None, *, image=None, blobs=None, owner=None):
        _require(token is _TOKEN)
        self._image, self._blobs, self._owner = image, blobs, owner
        self._lock, self._closed = threading.RLock(), False

    def __repr__(self):
        return "SealedImage(<process-local sealed content>)"

    def _check(self):
        _require(type(self) is SealedImage and not self._closed and _owner() == self._owner)

    @property
    def image(self) -> artifact.VerifiedImage:
        try:
            self._check()  # Before lock: never wait on an inherited locked lock.
            with self._lock:
                self._check()
                return self._image
        except Exception:
            raise CustodyError() from None

    def read_blob(self, digest: str, offset: int, length: int) -> bytes:
        """Read a bounded range from the held sealed inode, including empty ranges."""
        try:
            self._check()
            _require(type(digest) is str and type(offset) is int and type(length) is int)
            _require(offset >= 0 and 0 <= length <= MAX_RANGE_BYTES)
            with self._lock:
                self._check()
                blob = self._blobs.get(digest)
                _require(blob is not None and offset <= blob.size and length <= blob.size - offset)
                _check_blob(blob)
                result, calls = bytearray(), 0
                while len(result) < length:
                    _require(calls < MAX_RANGE_READ_CALLS)
                    amount = min(artifact.READ_CHUNK_BYTES, length - len(result))
                    chunk = os.pread(blob.fd, amount, offset + len(result))
                    calls += 1
                    _require(type(chunk) is bytes and 0 < len(chunk) <= amount)
                    result.extend(chunk)
                _check_blob(blob)
                self._check()
                return bytes(result)
        except Exception:
            raise CustodyError() from None

    def _close(self):
        if not self._closed:
            self._closed = True
            blobs, self._blobs = self._blobs, {}
            _close_fds(blob.fd for blob in blobs.values())

    def close(self):
        # Child cleanup only closes inherited copies; never acquire a lock
        # inherited from another thread. Child reads remain forbidden.
        if os.getpid() != self._owner[0]:
            self._close()
        else:
            with self._lock:
                self._close()

    def __enter__(self):
        self.image
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False


def capture(manifest_bytes: bytes, readers: dict[str, BinaryIO]) -> SealedImage:
    """Verify and seal actual streams; all partial memfds close on any failure.

    Ordinary failures are redacted. BaseException cancellation propagates after
    cleanup. Positive short writes are supported within a fixed per-blob budget.
    The returned handle retains neither source readers nor their callbacks.
    """
    owned = []
    try:
        owner = _owner()
        description = artifact.parse_manifest(manifest_bytes)
        _require(type(readers) is dict and len(readers) == len(description.blobs))
        supplied = tuple(readers.items())
        _require(all(type(key) is str for key, _ in supplied))
        sources = {key: getattr(reader, "read") for key, reader in supplied}
        _require(set(sources) == {blob.digest for blob in description.blobs}
            and all(callable(read) for read in sources.values()))
        copies = {}
        for blob in description.blobs:
            fd = os.memfd_create("catchplate-ecr-image", os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
            owned.append(fd)
            copies[blob.digest] = _CopyReader(sources[blob.digest], fd, blob.size, owner)
        image = artifact.verify_image(manifest_bytes, copies)
        _require(_owner() == owner)
        held = {}
        for blob in image.blobs:
            copy = copies[blob.digest]
            _require(copy.remaining == 0 and os.fstat(copy.fd).st_size == blob.size)
            fcntl.fcntl(copy.fd, fcntl.F_ADD_SEALS, _SEALS)
            value = _HeldBlob(copy.fd, blob.size, _identity(copy.fd))
            _require(value.identity[3] == owner[2])
            _check_blob(value)
            held[blob.digest] = value
        _require(_owner() == owner)
        result = SealedImage(_TOKEN, image=image, blobs=held, owner=owner)
        owned.clear()  # Ownership transfers only after every blob is sealed.
        return result
    except Exception:
        raise CustodyError() from None
    finally:
        _close_fds(owned)
