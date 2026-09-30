"""Bounded Linux originals for the explicit software five-service launcher."""
import fcntl
import os
import select
import stat
import time

from serverware import custody_generation_grants as g
from serverware import native_shadow_nitro_originals as native

p = g.p
FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
SEALS = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE


def clock():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
        info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def structural(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def read(fd, maximum):
    before = identity(os.fstat(fd))
    p.require(stat.S_ISREG(before[2]) and 0 < before[6] <= maximum)
    raw, offset = [], 0
    while offset < before[6]:
        part = os.pread(fd, min(65536, before[6] - offset), offset)
        p.require(bool(part)); raw.append(part); offset += len(part)
    p.require(identity(os.fstat(fd)) == before)
    return b"".join(raw)


def directory(path, uid=0):
    p.require(type(path) is str and path.startswith("/") and path.isascii()
        and all(part not in {"", ".", ".."} for part in path.split("/")[1:]))
    fd = os.open("/", FLAGS | os.O_DIRECTORY)
    try:
        for part in path.split("/")[1:]:
            info = os.fstat(fd)
            p.require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, uid) and info.st_mode & 0o022 == 0)
            child = os.open(part, FLAGS | os.O_DIRECTORY, dir_fd=fd)
            os.close(fd); fd = child
        info = os.fstat(fd)
        p.require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, uid) and info.st_mode & 0o022 == 0)
        return fd
    except BaseException:
        os.close(fd); raise


class Original:
    def __init__(self, path, maximum, *, uid=0, gid=0, mode=0o400, sha=None):
        parent, leaf = path.rsplit("/", 1)
        root = directory(parent, uid)
        try:
            self.fd = os.open(leaf, FLAGS, dir_fd=root)
        finally:
            os.close(root)
        try:
            self.path, self.maximum = path, maximum
            self.expected = identity(os.fstat(self.fd))
            info = os.fstat(self.fd)
            p.require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_gid == gid
                and stat.S_IMODE(info.st_mode) == mode and info.st_nlink == 1 and 0 < info.st_size <= maximum)
            self.sha = sha
            if sha is not None:
                p.require(p.sha(self.read()) == p.digest(sha))
        except BaseException:
            os.close(self.fd); self.fd = -1; raise

    def check(self):
        p.require(self.fd >= 0 and identity(os.fstat(self.fd)) == self.expected and not os.get_inheritable(self.fd))

    def read(self):
        self.check(); raw = read(self.fd, self.maximum); self.check()
        if self.sha is not None:
            p.require(p.sha(raw) == self.sha)
        return raw

    def close(self):
        if self.fd >= 0:
            os.close(self.fd); self.fd = -1


def publish(path, raw):
    """Exclusive public original publication. Never repair or overwrite."""
    p.require(type(raw) is bytes and 0 < len(raw) <= 65536)
    parent, leaf = path.rsplit("/", 1)
    root = directory(parent)
    fd = -1
    try:
        fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400, dir_fd=root)
        os.fchown(fd, 0, 0); os.fchmod(fd, 0o400)
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:]); p.require(count > 0); offset += count
        os.fsync(fd); os.fsync(root)
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(root)
    return Original(path, len(raw), sha=p.sha(raw))


def process(pid):
    fd = os.open(f"/proc/{pid}/stat", FLAGS)
    try:
        raw = os.read(fd, 16385); p.require(0 < len(raw) <= 16384)
    finally:
        os.close(fd)
    tail = raw.rsplit(b") ", 1)[1].split()
    p.require(len(tail) >= 20 and tail[0] not in (b"Z", b"X"))
    return int(tail[1]), int(tail[19])


def live(pidfd, pid, start, parent):
    poll = select.poll(); poll.register(pidfd, select.POLLIN)
    p.require(not poll.poll(0) and process(pid) == (parent, start))
    fd = os.open(f"/proc/self/fdinfo/{pidfd}", FLAGS)
    try:
        raw = os.read(fd, 4097); p.require(len(raw) <= 4096)
    finally:
        os.close(fd)
    entries = [line[4:].strip() for line in raw.splitlines() if line.startswith(b"Pid:")]
    p.require(entries == [str(pid).encode("ascii")])


def names(fd):
    # A fresh OFD is required: repeated scandir on a dup shares readdir offset.
    fresh = os.open(".", FLAGS | os.O_DIRECTORY, dir_fd=fd)
    try:
        p.require(structural(os.fstat(fresh)) == structural(os.fstat(fd)))
        with os.scandir(fresh) as entries:
            result = []
            for entry in entries:
                p.require(len(result) < 128); result.append(entry.name)
        return tuple(sorted(result))
    finally:
        os.close(fresh)


def activation(name, target, fd):
    info = os.fstat(fd)
    return dict(name=name, fd=target, device=info.st_dev, inode=info.st_ino,
        mode=info.st_mode, uid=info.st_uid, gid=info.st_gid)


def directory_identity(fd):
    info = os.fstat(fd)
    p.require(stat.S_ISDIR(info.st_mode))
    original = os.open(f"/proc/self/fdinfo/{fd}", FLAGS)
    try:
        raw = os.read(original, 4097); p.require(len(raw) <= 4096)
    finally:
        os.close(original)
    values = [line.split(b":", 1)[1].strip() for line in raw.splitlines() if line.startswith(b"mnt_id:")]
    p.require(len(values) == 1 and values[0].isdigit())
    return dict(mountId=int(values[0]), deviceMajor=os.major(info.st_dev), deviceMinor=os.minor(info.st_dev),
        inode=info.st_ino, uid=info.st_uid, gid=info.st_gid, mode=info.st_mode)
