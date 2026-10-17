"""Fixed-eight operator file service over the real protected approval channel.

The independently admitted operator publishes complete Input3 then Approval2
under the retained root0700 directory. This service only exposes evidence,
validates and forwards those literal originals. No currentness, approval or
signature is generated. Same-host root permissions are not organizational
independence. Existing/partial files remain on failure; no retry or removal.
"""
from __future__ import annotations

import os
import select
import stat
import threading
import time

from scripts import native_pilot_runtime_artifacts as artifacts
from scripts.authority import native_pilot_authority_io as public_io
from catchplate import native_pilot_current_head_decision_service_profile as profile
from catchplate import native_pilot_genesis_parent_control_io as ownership
from catchplate import native_pilot_publication as publication
from catchplate import native_shadow_nitro_originals as originals
from catchplate.native_pilot_genesis_authority import _SelfRuntime
from catchplate.native_pilot_lifecycle import _Protected
from catchplate.native_pilot_current_head_state import AtomicPublisher
from catchplate.native_pilot_supervisor_approval_channel import ApprovalPeer

p = profile.p
_TOKEN, _USED, _LIVE = object(), False, None
_ROOTS = ("/", "/etc", "/etc/catchplate", profile.DIRECTORY)
_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
MAX_BYTES = 512 * 1024 * 1024


class CurrentHeadDecisionServiceError(ValueError):
    def __init__(self, owner):
        super().__init__("current-head decision service refused; actual owner retained")
        self.owner = owner


class CurrentHeadDecisionService:
    def __init__(self, token):
        p.require(token is _TOKEN)
        self._pid, self._start, self._boot = os.getpid(), originals._start(), originals._boot()
        self._last, self._wall = originals._clock(), time.time_ns()
        self._sources, self._handles, self._files, self._roots = [], [], [], {}
        self._runtime = self._peer = self._prepared = self._active = self._atomic = None
        self._allowed, self._bytes = set(), 0
        self._failed = self._closed = self._closing = self._running = self._used = False
        self.stage, self.decisions = "opening", 0

    def _handle(self, fd):
        row = [fd, None]
        self._handles.append(row)
        info = os.fstat(fd)
        row[1] = info.st_dev, info.st_ino
        return row

    def _drop(self, row):
        p.require(row[0] is not None and (os.fstat(row[0]).st_dev, os.fstat(row[0]).st_ino) == row[1])
        with ownership.owning():
            fd, row[0] = row[0], None
            os.close(fd)
            self._handles.remove(row)

    @classmethod
    def open(cls, *, supervisor_inventory_fd, supervisor_inventory_sha256,
             configuration_fd, configuration_sha256, approval_socket_fd):
        global _USED, _LIVE
        p.require(cls is CurrentHeadDecisionService and not _USED and _LIVE is None)
        _USED = True
        owner = cls(_TOKEN); _LIVE = owner
        try:
            public_io._process()
            fds = (supervisor_inventory_fd, configuration_fd, approval_socket_fd)
            p.require(all(type(fd) is int and 3 <= fd < (1 << 31) for fd in fds) and len(set(fds)) == 3)
            inventory = _Protected(owner._sources, supervisor_inventory_fd, artifacts.MAX_MANIFEST_BYTES,
                supervisor_inventory_sha256)
            configuration = _Protected(owner._sources, configuration_fd, profile.MAX_CONFIGURATION, configuration_sha256)
            p.require(inventory.identity[:2] != configuration.identity[:2])
            owner._runtime = _SelfRuntime()
            owner._runtime.admit(inventory.fd, inventory.digest)
            owner._prepared = profile.configuration(configuration.raw, inventory_sha256=inventory.digest,
                boot=owner._boot, now_boottime_ns=originals._clock(), now_unix_ns=time.time_ns())
            for path in _ROOTS:
                with ownership.owning():
                    parent, name = path.rsplit("/", 1)
                    fd = os.open(path, _FLAGS | os.O_DIRECTORY) if path == "/" else os.open(name,
                        _FLAGS | os.O_DIRECTORY, dir_fd=owner._roots[parent or "/"][0][0])
                    row = owner._handle(fd)
                    owner._roots[path] = row, publication._structural(os.fstat(fd))
                publication._protected(os.fstat(fd))
            leaf = os.fstat(owner._roots[profile.DIRECTORY][0][0])
            pin = owner._prepared["value"]["directory"]
            p.require(stat.S_IMODE(leaf.st_mode) == 0o700 and (leaf.st_dev, leaf.st_ino) == (pin["device"], pin["inode"]))
            owner._scan()  # Exact empty task directory before any publication.
            with ownership.owning():
                try:
                    owner._atomic = AtomicPublisher.open(directory=pin, check=owner.check)
                except BaseException as error:
                    if getattr(error, "owner", None) is not None:
                        p.require(type(error.owner) is AtomicPublisher)
                        owner._atomic = error.owner
                    raise
            peer = owner._prepared["value"]["providerPeer"]
            with ownership.owning():
                try:
                    owner._peer = ApprovalPeer.open_current_heads(approval_socket_fd,
                        **{"peer_" + name: peer[name] for name in ("pid", "uid", "gid")},
                        deadline_boottime_ns=owner._prepared["deadline"],
                        expires_at_unix_ns=owner._prepared["epochLimit"], check=owner.check, evidence=True)
                except BaseException as error:
                    if getattr(error, "owner", None) is not None: owner._peer = error.owner
                    raise
            p.require(owner._peer.peer_identity() == peer)
            owner.check(full=True)
            return owner
        except BaseException as error:
            owner._failed = True
            raise CurrentHeadDecisionServiceError(owner) from error

    def _origin(self):
        p.require(type(self) is CurrentHeadDecisionService and _LIVE is self and not self._closed
            and (self._pid, self._start, self._boot) == (os.getpid(), originals._start(), originals._boot())
            and threading.current_thread() is threading.main_thread()
            and os.getresuid() == os.getresgid() == (0, 0, 0))

    def _scan(self):
        names = set()
        with os.scandir(self._roots[profile.DIRECTORY][0][0]) as entries:
            for entry in entries:
                p.require(len(names) < 32 and entry.name in self._allowed)
                names.add(entry.name)
        return names

    def check(self, *, full=False):
        self._origin()
        p.require(not self._failed and not self._closing and self._prepared is not None)
        for held in self._sources: (held.check if full else held.check_identity)()
        self._runtime.check()
        for path, (row, expected) in self._roots.items():
            fd = row[0]
            parent, name = path.rsplit("/", 1)
            named = os.stat(path, follow_symlinks=False) if path == "/" else os.stat(name,
                dir_fd=self._roots[parent or "/"][0][0], follow_symlinks=False)
            actual = os.fstat(fd)
            publication._protected(actual)
            p.require(not os.get_inheritable(fd) and publication._structural(actual) == expected == publication._structural(named))
        for item in self._files:
            fd, name, maximum, identity, raw = item
            p.require(public_io._input(fd, maximum) == identity == originals._identity(os.stat(name,
                dir_fd=self._roots[profile.DIRECTORY][0][0], follow_symlinks=False)))
            if full: p.require(public_io.read_public(fd, maximum) == raw)
        now, wall = originals._clock(), time.time_ns()
        caps = self._prepared
        deadline, expiry = caps["deadline"], caps["epochLimit"]
        if self._active is not None:
            deadline, expiry = min(deadline, self._active["deadline"]), min(expiry, self._active["epochLimit"])
        p.require(self._last <= now < deadline and self._wall <= wall < expiry)
        self._last, self._wall = now, wall

    def _read(self, name, maximum):
        self.check()
        with ownership.owning():
            fd = os.open(name, _FLAGS, dir_fd=self._roots[profile.DIRECTORY][0][0])
            self._handle(fd)
        identity = public_io._input(fd, maximum)
        raw = public_io.read_public(fd, maximum)
        p.require(self._bytes + len(raw) <= MAX_BYTES)
        self._files.append((fd, name, maximum, identity, raw)); self._bytes += len(raw)
        self.check(full=True)
        return fd, raw

    def _publish(self, name, raw):
        self.check()
        p.require(type(raw) is bytes and 0 < len(raw) <= 32 * 1024 * 1024 and name not in self._allowed)
        # A waiting worker treats the final name as readiness. Publish only
        # complete, fsynced, read-back bytes through atomic no-overwrite link.
        self._atomic.publish(name, raw)
        self._allowed.add(name)
        _, actual = self._read(name, len(raw))
        p.require(actual == raw)
        self.check()

    def run(self):
        try:
            self.check(full=True); p.require(not self._used and not self._running)
            self._used = self._running = True
            for job in profile.intake.JOB_NAMES:
                self.stage = job
                received = self._peer.receive_current_head(deadline_boottime_ns=self._prepared["deadline"],
                    expires_at_unix_ns=self._prepared["epochLimit"], check=self.check)
                p.fields(received, ("pending", "evidenceOriginal"))
                pending, evidence = received["pending"], received["evidenceOriginal"].encode("ascii")
                p.require(pending["job"] == job)
                profile.channel.current_head_evidence(pending, evidence)
                self._active = profile.intake.pending_bounds(pending)
                names = profile.filenames(job)
                self._scan()
                # Publish the actual AuthorityJobRequest2 literal, not a
                # second JSON encoding of request plus observation strings.
                self._publish(names["request"], pending["requestOriginal"].encode("ascii"))
                self._publish(names["evidence"], evidence)
                self._allowed.update((names["input"], names["approval"]))
                while not {names["input"], names["approval"]} <= self._scan():
                    self._peer.check(); self.check()
                    select.select([], [], [], 0.01)
                    self.check()
                input_fd, input_raw = self._read(names["input"], profile.intake.MAX_INPUT)
                approval_fd, approval_raw = self._read(names["approval"], profile.intake.MAX_APPROVAL)
                caps = profile.require_pair(pending, evidence, input_raw, approval_raw,
                    boot=self._boot, now_boottime_ns=self._last, now_unix_ns=self._wall)
                self._active = {name: min(self._active[name], caps[name]) for name in ("deadline", "epochLimit")}
                self.check(full=True)
                self._peer.respond_current_head(input_fd=input_fd, input_sha256=p.sha(input_raw),
                    approval_fd=approval_fd, approval_sha256=p.sha(approval_raw))
                self.decisions += 1
                self.check(full=True)
                if self.decisions < len(profile.intake.JOB_NAMES): self._active = None
            self._runtime.check(installed=True); self.check(full=True)
            self.stage = "eight-independent-pairs-delivered"
        except BaseException as error:
            self._failed = True
            raise CurrentHeadDecisionServiceError(self) from error
        finally:
            self._running = False

    def close(self):
        if self._closed: return
        try:
            self._origin(); p.require(not self._running and not self._closing)
            self._closing = True
            with ownership.owning():
                if self._peer is not None: self._peer.close()
                if self._atomic is not None: self._atomic.close()
                while self._handles: self._drop(self._handles[-1])
                for held in reversed(self._sources): held.close()
                if self._runtime is not None: self._runtime.close()
                self._closed = True
        except BaseException as error:
            self._failed = True
            raise CurrentHeadDecisionServiceError(self) from error
