"""Publish an independently approved, observation-bound cold rendezvous pair.

This installer issues no approval and acquires no peer or process capability.
Three independently pinned root-protected originals are required. It creates
only the two fixed names, input first and approval last, without replacement,
parent creation, rollback or retry. Filesystem stalls require an external
watchdog; byte counts and all completed operations retain the original caps.
"""
from __future__ import annotations

import copy
import os
import stat
import threading
import time

from catchplate import native_pilot_approval_install as publication
from catchplate import native_pilot_genesis_parent_control_io as io
from catchplate import native_pilot_genesis_rendezvous_profile as profile
from catchplate import native_shadow_nitro_originals as originals
from catchplate.native_shadow_proof_cohort_control import _Original

p = profile.p
MAX_REQUEST, MAX_INPUT, MAX_APPROVAL = profile.MAX_REQUEST, profile.MAX_INPUT, profile.MAX_APPROVAL
_PATHS = (profile.INPUT_PATH, profile.APPROVAL_PATH)
_ROOTS = ("/", "/etc", "/etc/catchplate", "/etc/catchplate/native-genesis-authority")
_TOKEN, _USED = object(), False


def prepare_input(request_raw, input_raw, approval_raw, *, request_sha256, input_sha256,
                  approval_sha256, boot, now_boottime_ns, now_unix_ns):
    """Public association checks only; neither installation nor approval provenance."""
    for raw, maximum, digest in ((request_raw, MAX_REQUEST, request_sha256),
            (input_raw, MAX_INPUT, input_sha256), (approval_raw, MAX_APPROVAL, approval_sha256)):
        p.require(type(raw) is bytes and 0 < len(raw) <= maximum and p.sha(raw) == p.digest(digest))
    request = profile.verify_request(request_raw)
    selected = profile.execution(input_raw, request_raw, boot=boot, now_boottime_ns=now_boottime_ns,
        now_unix_ns=now_unix_ns)
    profile.approval(approval_raw, request_raw=request_raw, input_sha256=input_sha256)
    return dict(deadline=min(p.ns(request["deadlineBoottimeNs"]),
            p.ns(selected["window"]["lifetimeDeadlineBoottimeNs"]) - profile.wire.RESERVE),
        epochLimit=request["expiresAtUnixNanos"],
        reply=profile.reply_value(request_raw, input_sha256=input_sha256, approval_sha256=approval_sha256))


class InstallationError(ValueError):
    def __init__(self, owner):
        super().__init__("cold rendezvous installation refused; partial files and actual owner retained")
        self.owner = owner


class GenesisRendezvousInstallation(publication._Pair):
    """Reuse the real protected-parent writer checks, never the legacy planner."""

    def __init__(self, token):
        p.require(token is _TOKEN)
        super().__init__("", None)
        self._paths = _ROOTS
        self._publication_paths = _PATHS
        self._start, self._wall = originals._start(), time.time_ns()
        self._sources, self._reply = [], None
        self._expiry = None
        self._failed = self._closed = self._close_attempted = self._close_uncertain = False

    @classmethod
    def install(cls, *, request_fd, request_sha256, input_fd, input_sha256, approval_fd, approval_sha256):
        global _USED
        p.require(cls is GenesisRendezvousInstallation and not _USED)
        _USED = True  # Refused acquisition/publication cannot be retried in this process.
        owner = cls(_TOKEN)
        try:
            owner._clock()
            descriptors = (request_fd, input_fd, approval_fd)
            p.require(all(type(fd) is int and 3 <= fd < (1 << 31) for fd in descriptors)
                and len(set(descriptors)) == 3)
            for fd, maximum, digest in ((request_fd, MAX_REQUEST, request_sha256),
                    (input_fd, MAX_INPUT, input_sha256), (approval_fd, MAX_APPROVAL, approval_sha256)):
                with io.owning():
                    source = io.PublicInput(fd, maximum, digest)
                    owner._sources.append(source)
                if len(owner._sources) == 1:
                    ticket = profile.verify_request(source.raw)
                    owner._deadline = p.ns(ticket["deadlineBoottimeNs"])
                    owner._expiry = ticket["expiresAtUnixNanos"]
                owner._clock()
            p.require(len({source.identity[:2] for source in owner._sources}) == 3)
            owner._clock()
            prepared = prepare_input(*(source.raw for source in owner._sources),
                request_sha256=request_sha256, input_sha256=input_sha256, approval_sha256=approval_sha256,
                boot=owner._boot, now_boottime_ns=owner._previous, now_unix_ns=owner._wall)
            p.require(prepared["deadline"] <= owner._deadline and prepared["epochLimit"] == owner._expiry)
            owner._deadline = prepared["deadline"]
            owner._clock()
            owner.open()  # Actual protected ancestry retained by the existing publisher.
            root = owner._roots[_ROOTS[-1]][0]
            for path in _PATHS:
                owner.check()
                try:
                    os.stat(path.rsplit("/", 1)[1], dir_fd=root, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise ValueError("cold rendezvous destination exists")
            owner._publish(profile.INPUT_PATH, owner._sources[1].raw, MAX_INPUT, input_sha256)
            owner._publish(profile.APPROVAL_PATH, owner._sources[2].raw, MAX_APPROVAL, approval_sha256)
            owner.check()
            owner._reply = prepared["reply"]
            owner._clock()
            return owner
        except BaseException as error:
            owner._failed = True
            raise InstallationError(owner) from error

    def _origin(self):
        publication.io._process()
        p.require(not self._closed and os.getpid() == self._pid and originals._start() == self._start
            and originals._boot() == self._boot and threading.current_thread() is threading.main_thread()
            and len(os.listdir("/proc/self/task")) == 1)

    def _clock(self):
        self._origin()
        now, wall = originals._clock(), time.time_ns()
        p.require(self._previous <= now and self._wall <= wall
            and (self._deadline is None or now < self._deadline)
            and (self._expiry is None or wall < self._expiry))
        self._previous, self._wall = now, wall

    def check(self):
        p.require(not self._failed and not self._close_attempted and self._deadline is not None)
        self._clock()
        for source in self._sources:
            source.check()
        super().check()  # Exact retained FD/name/ancestor identities and literal readback.
        self._clock()

    def _publish(self, path, raw, maximum, digest):
        # The same exclusive publisher protection, with a sticky close fence:
        # a close error must not be relabeled known cleanup on a later call.
        p.require(path in self._publication_paths and path == self._publication_paths[len(self._files)])
        self.check()
        parent, name = self._roots[_ROOTS[-1]][0], path.rsplit("/", 1)[1]
        with io.owning():
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o400, dir_fd=parent)
            self._pending.append(fd)
        info = os.fstat(fd)
        p.require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
            and info.st_nlink == 1 and info.st_size == 0)
        os.fchmod(fd, 0o400)
        offset = 0
        while offset < len(raw):
            self.check()
            part = raw[offset:offset + 4096]
            count = os.pwrite(fd, part, offset)
            p.require(0 < count <= len(part))
            offset += count
            self.check()
        os.fsync(fd); self.check()
        p.require(os.pread(fd, maximum + 1, 0) == raw)
        written = os.fstat(fd)
        p.require(stat.S_IMODE(written.st_mode) == 0o400 and written.st_uid == written.st_gid == 0
            and written.st_nlink == 1 and written.st_size == len(raw)
            and publication.publication._file_identity(written)
            == publication.publication._file_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)))
        with io.owning():
            original = _Original(path, maximum, digest, mode=0o400)
            self._files.append(original)
        p.require(original.raw == raw and publication.publication._file_identity(os.fstat(original.fd))
            == publication.publication._file_identity(written))
        with io.owning():
            self._pending.remove(fd)
            self._close_uncertain = True
            os.close(fd)
            self._close_uncertain = False
        os.fsync(parent)
        self.check()

    def reply(self):
        p.require(self._reply is not None)
        self.check()
        result = copy.deepcopy(self._reply)
        self._clock()
        return result

    @property
    def deadline_boottime_ns(self):
        return self._deadline

    def close(self):
        if self._closed:
            return
        try:
            self._origin()  # Cleanup is not new admission and may follow expiry.
            p.require(not self._close_attempted and not self._close_uncertain)
            self._close_attempted = True
            with io.owning():
                for original in self._files:
                    while original.fds:
                        os.close(original.fds.pop())
                self._files.clear()
                while self._pending:
                    os.close(self._pending.pop())
                while self._roots:
                    os.close(self._roots.popitem()[1][0])
                while self._sources:
                    source = self._sources.pop()
                    source.close()
                self._closed = True
        except BaseException as error:
            self._close_uncertain = True
            raise InstallationError(self) from error
