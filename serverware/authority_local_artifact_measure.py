"""Measure an already frozen local source tree, without issuing authority.

No flags are set here. A read-only mount or actual immutable inode flags must
already protect every object. A successful scan is not closure/rootfs analysis,
provenance, installation, or hostile-root protection.

Only kernel-enforced ext4 fs-verity content identities may reuse a process-local
content digest. This is not an eager disk scrub: later reads still fail with EIO
if their data violates the enforced digest. Metadata, roster and caller checks
remain fresh, and no authority or session receipt is cached.

An independently pinned content catalog can explicitly supply the same
content-only relation inside a PID/thread-owned scope. Its claims never seed
the observed LRU and do not persist after that scope exits.
"""
from __future__ import annotations

import array
from collections import OrderedDict
import ctypes
import errno
import fcntl
import hashlib
import os
from pathlib import PurePosixPath
import stat
import struct
import sys
import threading

from serverware import authority_artifact_spec as spec
from serverware import authority_local_content_catalog as _catalog

pinned_content_catalog = _catalog.pinned_content_catalog

FS_IOC_GETFLAGS = 0x80086601
FS_IOC_GETVERSION = 0x80087601
FS_IMMUTABLE_FL = 0x10
FS_IOC_MEASURE_VERITY = 0xC0046686
FIELDS = frozenset({"path", "kind", "mode", "uid", "gid"})
_FILE_DIGEST_CACHE_LIMIT = min(32768, spec.MAX_BUNDLE_FILES)
_FILE_DIGEST_CACHE = OrderedDict()
_FILE_DIGEST_CACHE_LOCK = threading.Lock()
_FILE_DIGEST_CACHE_PID = os.getpid()


class _Statfs(ctypes.Structure):
    # Linux x86_64 libc statfs ABI, not an inferred mount/path name.
    _fields_ = [("f_type", ctypes.c_long), ("f_bsize", ctypes.c_long),
                ("f_blocks", ctypes.c_ulong), ("f_bfree", ctypes.c_ulong),
                ("f_bavail", ctypes.c_ulong), ("f_files", ctypes.c_ulong),
                ("f_ffree", ctypes.c_ulong), ("f_fsid", ctypes.c_int * 2),
                ("f_namelen", ctypes.c_long), ("f_frsize", ctypes.c_long),
                ("f_flags", ctypes.c_long), ("f_spare", ctypes.c_long * 4)]


_LIBC = ctypes.CDLL(None, use_errno=True)
_FSTATFS = _LIBC.fstatfs
_FSTATFS.argtypes = (ctypes.c_int, ctypes.POINTER(_Statfs))
_FSTATFS.restype = ctypes.c_int


def _require(value):
    if not value:
        raise ValueError("local artifact source measurement refused")


def _ext4_verity_cache_eligible(fd):
    # Other ABIs retain the original full-read path. On this admitted ABI an
    # actual syscall failure refuses; it is not mistaken for absent verity.
    if sys.platform != "linux" or os.uname().machine != "x86_64":
        return False
    _require(ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_long) == 8
             and ctypes.sizeof(_Statfs) == 120)
    info = _Statfs()
    result = _FSTATFS(fd, ctypes.byref(info))
    if result == -1:
        raise OSError(ctypes.get_errno(), "local artifact filesystem measurement refused")
    _require(result == 0)
    # FUSE may emulate MEASURE_VERITY but cannot supply ext4's kernel statfs
    # type. Read-only mounts and immutable inode flags never admit this cache.
    return info.f_type == 0xEF53


def _fsverity_digest(fd):
    buffer = bytearray(struct.pack("=HH64s", 0, 64, bytes(64)))
    try:
        result = fcntl.ioctl(fd, FS_IOC_MEASURE_VERITY, buffer, True)
    except OSError as error:
        if error.errno in (errno.ENODATA, errno.ENOTTY, errno.EOPNOTSUPP):
            return None
        raise
    _require(type(result) is int and result == 0 and len(buffer) == 68)
    algorithm, size, digest = struct.unpack("=HH64s", buffer)
    if algorithm == 2 and size == 64:
        # Valid SHA-512 verity remains measurable by the original byte-read
        # path; only SHA-256 verity is admitted to this optimization.
        return None
    _require(algorithm == 1 and size == 32)
    return digest[:32]


def _file_cache_key(fd, size):
    if not _ext4_verity_cache_eligible(fd):
        return None
    verity = _fsverity_digest(fd)
    return None if verity is None else (verity, size)


def _reset_file_digest_cache():
    global _FILE_DIGEST_CACHE, _FILE_DIGEST_CACHE_LOCK, _FILE_DIGEST_CACHE_PID
    _FILE_DIGEST_CACHE = OrderedDict()
    _FILE_DIGEST_CACHE_LOCK = threading.Lock()
    _FILE_DIGEST_CACHE_PID = os.getpid()


os.register_at_fork(after_in_child=_reset_file_digest_cache)


def _cache_lookup(key):
    # Check before taking a possibly inherited lock. Forked children must not
    # reuse the parent's memo, even though every lookup remeasures the FD.
    if os.getpid() != _FILE_DIGEST_CACHE_PID:
        _reset_file_digest_cache()
    with _FILE_DIGEST_CACHE_LOCK:
        value = _FILE_DIGEST_CACHE.get(key)
        if value is not None:
            _FILE_DIGEST_CACHE.move_to_end(key)
        return value


def _cache_remember(key, digest):
    if os.getpid() != _FILE_DIGEST_CACHE_PID:
        _reset_file_digest_cache()
    with _FILE_DIGEST_CACHE_LOCK:
        previous = _FILE_DIGEST_CACHE.get(key)
        _require(previous is None or previous == digest)
        _FILE_DIGEST_CACHE[key] = digest
        _FILE_DIGEST_CACHE.move_to_end(key)
        while len(_FILE_DIGEST_CACHE) > _FILE_DIGEST_CACHE_LIMIT:
            _FILE_DIGEST_CACHE.popitem(last=False)


def _content_lookup(key):
    token, selected = _catalog._capture(key)
    observed = None if key is None else _cache_lookup(key)
    _require(selected is None or observed is None or selected == observed)
    return token, observed if observed is not None else selected, observed is None and selected is not None


def _content_complete(key, digest, token, catalog_only):
    # Run after the caller's final custody/deadline check. A callback cannot
    # remove or replace an activation while retaining its cached result.
    _catalog._check(token)
    if key is not None:
        observed = _cache_lookup(key)
        _require(observed is None or observed == digest)
        if not catalog_only:
            _cache_remember(key, digest)


def _digest_owned_file(fd, *, maximum, read=None, check):
    """Content-only measurement of a caller-owned FD, never a claimed digest.

    ``check`` must freshly validate that owner's custody/lifetime and path.
    If supplied, ``read`` must return the actual FD bytes using the owner's
    existing guarded reader. Otherwise misses stream in at most 1MiB chunks,
    checking the caller before each read. Neither callback nor descriptor is
    retained. Hits reuse only the ext4-enforced content identity.
    """
    _require(type(fd) is int and fd >= 3 and type(maximum) is int
             and 0 < maximum <= spec.MAX_FILE_BYTES and (read is None or callable(read))
             and callable(check))
    check()
    before = os.fstat(fd)
    _require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= maximum)
    cache_key = _file_cache_key(fd, before.st_size)
    token, content_digest, catalog_only = _content_lookup(cache_key)
    if content_digest is None:
        if read is None:
            digest = hashlib.sha256()
            offset = 0
            while offset < before.st_size:
                check()
                raw = os.pread(fd, min(1024 * 1024, before.st_size - offset), offset)
                _require(bool(raw))
                digest.update(raw)
                offset += len(raw)
            content_digest = digest.hexdigest()
        else:
            raw = read()
            _require(type(raw) is bytes and len(raw) == before.st_size)
            content_digest = hashlib.sha256(raw).hexdigest()
            del raw
    _require(not os.pread(fd, 1, before.st_size))
    _require(_file_cache_key(fd, before.st_size) == cache_key)
    _require(_identity(os.fstat(fd)) == _identity(before))
    check()
    _content_complete(cache_key, content_digest, token, catalog_only)
    return "sha256:" + content_digest


def observe_catalog_entry(fd, *, check):
    """Observe a sealed original for an offline content catalog, never seed it.

    The producer supplies current named-FD custody in ``check``. An existing
    actually observed memo entry may be reused, but an active pinned catalog
    is forbidden; cold content is read through the original guarded helper.
    """
    _require(type(fd) is int and fd >= 3 and callable(check))
    _catalog._require_inactive()

    def guarded():
        _catalog._require_inactive()
        check()
        _catalog._require_inactive()

    guarded()
    before = os.fstat(fd)
    _require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= spec.MAX_FILE_BYTES)
    key = _file_cache_key(fd, before.st_size)
    _require(key is not None)
    digest = _digest_owned_file(fd, maximum=spec.MAX_FILE_BYTES, check=guarded)
    _require(_file_cache_key(fd, before.st_size) == key
             and _identity(os.fstat(fd)) == _identity(before))
    guarded()
    return dict(fsVerityDigest="sha256:" + key[0].hex(), size=before.st_size, sha256=digest)


def _ioctl_number(fd, request):
    result = array.array("l", [0])
    _require(result.itemsize == 8)
    fcntl.ioctl(fd, request, result, True)
    return result[0]


def _frozen(fd):
    if not os.fstatvfs(fd).f_flag & os.ST_RDONLY:
        _require(_ioctl_number(fd, FS_IOC_GETFLAGS) & FS_IMMUTABLE_FL)


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _named_root(runtime_path):
    _require(isinstance(runtime_path, str) and runtime_path.isascii()
             and runtime_path.startswith("/") and runtime_path != "/"
             and str(PurePosixPath(runtime_path)) == runtime_path
             and all(part not in (".", "..") for part in runtime_path.split("/")[1:]))
    current = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in runtime_path.split("/")[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                              dir_fd=current)
            os.close(current)
            current = next_fd
        return current
    except BaseException:
        os.close(current)
        raise


def root_identity(root_fd, runtime_path):
    """Actual root identity; refuse unavailable/zero inode generation."""
    _require(type(root_fd) is int and root_fd >= 3)
    info = os.fstat(root_fd)
    _require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
             and not stat.S_IMODE(info.st_mode) & 0o022)
    _frozen(root_fd)
    named = _named_root(runtime_path)
    try:
        _require(_identity(os.fstat(named)) == _identity(info))
    finally:
        os.close(named)
    with open(f"/proc/self/fdinfo/{root_fd}", "rt", encoding="ascii") as stream:
        text = stream.read(16385)
    _require(len(text) <= 16384)
    mounts = [line.split(":", 1)[1].strip() for line in text.splitlines() if line.startswith("mnt_id:")]
    _require(len(mounts) == 1 and mounts[0].isdigit() and int(mounts[0]) > 0)
    generation = _ioctl_number(root_fd, FS_IOC_GETVERSION)
    _require(generation > 0)
    return dict(runtimePath=runtime_path, device=info.st_dev, inode=info.st_ino,
                generation=generation, mountId=int(mounts[0]), mode=stat.S_IMODE(info.st_mode),
                uid=info.st_uid, gid=info.st_gid)


def _enumerate(root_fd, paths, *, check):
    """Bound work by the selected roster, rejecting the first extra entry."""
    directories = {""}
    for path in paths:
        parts = path.split("/")
        _require(len(parts) <= 64)
        directories.update("/".join(parts[:index]) for index in range(1, len(parts)))
    _require(not set(paths) & directories and len(directories) <= spec.MAX_BUNDLE_FILES)
    found = set()
    visited = set()

    def visit(fd, prefix):
        check()
        info = os.fstat(fd)
        _require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                 and not stat.S_IMODE(info.st_mode) & 0o022)
        _frozen(fd)
        before = _identity(info)
        visited.add(prefix)
        with os.scandir(fd) as entries:
            for entry in entries:
                check()
                name = prefix + "/" + entry.name if prefix else entry.name
                _require(name in paths or name in directories)
                flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
                if name in directories:
                    flags |= os.O_DIRECTORY
                child = os.open(entry.name, flags, dir_fd=fd)
                try:
                    child_info = os.fstat(child)
                    if name in directories:
                        visit(child, name)
                    else:
                        _require(stat.S_ISREG(child_info.st_mode) and child_info.st_nlink == 1
                                 and child_info.st_uid == child_info.st_gid == 0
                                 and not stat.S_IMODE(child_info.st_mode) & 0o022)
                        _frozen(child)
                        found.add(name)
                finally:
                    os.close(child)
        _require(_identity(os.fstat(fd)) == before)

    visit(root_fd, "")
    _require(found == set(paths) and visited == directories)


def measure_file(root_fd, entry, *, check):
    """Nofollow/nonblocking, chunk-checked real file measurement."""
    _require(isinstance(entry, dict) and set(entry) == FIELDS)
    path = spec._require_relative_path(entry["path"], name="source path")
    current = os.dup(root_fd)
    try:
        for part in path.split("/")[:-1]:
            check()
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                              dir_fd=current)
            os.close(current)
            current = next_fd
        check()
        descriptor = os.open(path.split("/")[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW,
                             dir_fd=current)
    finally:
        os.close(current)
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and 0 <= before.st_size <= spec.MAX_FILE_BYTES
                 and stat.S_IMODE(before.st_mode) == entry["mode"]
                 and before.st_uid == entry["uid"] and before.st_gid == entry["gid"])
        cache_key = _file_cache_key(descriptor, before.st_size)
        token, content_digest, catalog_only = _content_lookup(cache_key)
        if content_digest is None:
            digest = hashlib.sha256()
            offset = 0
            while offset < before.st_size:
                check()
                raw = os.pread(descriptor, min(1024 * 1024, before.st_size - offset), offset)
                _require(bool(raw))
                digest.update(raw)
                offset += len(raw)
            content_digest = digest.hexdigest()
        else:
            offset = before.st_size
        _require(not os.pread(descriptor, 1, offset))
        _require(_file_cache_key(descriptor, before.st_size) == cache_key)
        _require(_identity(os.fstat(descriptor)) == _identity(before))
        result = dict(entry, size=before.st_size, sha256="sha256:" + content_digest)
        spec._validate_file_entry(result)
        # Preserve the original pre-open/per-chunk callback cadence and make
        # the terminal check later: after every measurement/validation step,
        # before any cache population or successful return.
        check()
        _content_complete(cache_key, content_digest, token, catalog_only)
        return result
    finally:
        os.close(descriptor)


def measure_tree(root_fd, file_inputs, *, runtime_path, check):
    """Measure exact metadata-selected files from a genuinely frozen root FD."""
    _require(callable(check) and isinstance(file_inputs, (list, tuple))
             and 0 < len(file_inputs) <= spec.MAX_BUNDLE_FILES)
    paths = []
    for entry in file_inputs:
        _require(isinstance(entry, dict) and set(entry) == FIELDS)
        paths.append(spec._require_relative_path(entry["path"], name="source path"))
    _require(paths == sorted(set(paths)))
    check()
    before = root_identity(root_fd, runtime_path)
    _enumerate(root_fd, set(paths), check=check)
    files = []
    total = 0
    for entry in file_inputs:
        check()
        measured = measure_file(root_fd, entry, check=check)
        total += measured["size"]
        _require(total <= spec.MAX_TOTAL_BUNDLE_BYTES)
        files.append(measured)
    _enumerate(root_fd, set(paths), check=check)
    _require(before == root_identity(root_fd, runtime_path))
    check()
    return dict(rootIdentity=before, files=files, totalBytes=total,
                treeDigest=spec.domain_digest(spec.SOURCE_TREE_DIGEST_DOMAIN, spec.canonical_json_bytes(files)),
                enumeratedTreeDigest=spec.domain_digest("serverware.authorityEnumeratedTree/v1",
                                                       spec.canonical_json_bytes(files)))
