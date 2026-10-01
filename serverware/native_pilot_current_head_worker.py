"""Fixed-eight fresh-head worker under independently supplied live-state policy.

Historical evidence is not freshness. Every decision rereads the independently
controlled current state under its actual shared lock and requires the exact
policy-pinned baseline. The lock spans durable consume receipt and atomic,
no-overwrite input-first/approval-last publication. This process has no signing
key, state updater, checkpoint constructor, retry or rollback path.
"""
from __future__ import annotations

import os
import select
import stat
import threading
import time

from scripts import native_pilot_runtime_artifacts as artifacts
from scripts.authority import native_pilot_authority_io as public_io
from serverware import native_pilot_current_head_decision_service_profile as delivery
from serverware import native_pilot_current_head_worker_profile as profile
from serverware import native_pilot_genesis_parent_control_io as ownership
from serverware import native_pilot_publication as publication
from serverware import native_shadow_nitro_originals as originals
from serverware.native_pilot_current_head_state import StateStore
from serverware.native_pilot_genesis_authority import _SelfRuntime
from serverware.native_pilot_lifecycle import _Protected

p = delivery.p
_TOKEN, _USED, _LIVE = object(), False, None
_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
_ROOTS = ("/", "/etc", "/etc/serverware", delivery.DIRECTORY)
MAX_RETAINED_BYTES = 512 * 1024 * 1024
_FILENAMES = frozenset(name for job in delivery.intake.JOB_NAMES for name in delivery.filenames(job).values())


class CurrentHeadWorkerError(ValueError):
    def __init__(self, owner):
        super().__init__("fresh current-head worker refused; actual resources retained; no retry")
        self.owner = owner


class CurrentHeadWorker:
    def __init__(self, token):
        p.require(token is _TOKEN)
        self._pid, self._start, self._boot = os.getpid(), originals._start(), originals._boot()
        self._last, self._wall = originals._clock(), time.time_ns()
        self._runtime = self._state = self._prepared = self._active = None
        self._sources, self._handles, self._files, self._roots = [], [], {}, {}
        self._first_conductor, self._bytes = None, 0
        self._failed = self._closed = self._closing = self._running = self._used = False
        self.stage, self.decisions = "opening", 0

    @classmethod
    def open(cls, *, supervisor_inventory_fd, supervisor_inventory_sha256, policy_fd, policy_sha256):
        global _USED, _LIVE
        p.require(cls is CurrentHeadWorker and not _USED and _LIVE is None)
        _USED = True
        owner = cls(_TOKEN); _LIVE = owner
        try:
            owner._origin()
            p.require(type(supervisor_inventory_fd) is int and type(policy_fd) is int
                and 3 <= supervisor_inventory_fd < (1 << 31) and 3 <= policy_fd < (1 << 31)
                and supervisor_inventory_fd != policy_fd)
            inventory = _Protected(owner._sources, supervisor_inventory_fd, artifacts.MAX_MANIFEST_BYTES,
                supervisor_inventory_sha256)
            policy = _Protected(owner._sources, policy_fd, profile.MAX_POLICY, policy_sha256)
            p.require(inventory.identity[:2] != policy.identity[:2])
            owner._runtime = _SelfRuntime()  # Retain partial installed-runtime admission.
            owner._runtime.admit(inventory.fd, inventory.digest)
            owner._prepared = profile.prepare(policy.raw, inventory_sha256=inventory.digest,
                boot=owner._boot, now_boottime_ns=originals._clock(), now_unix_ns=time.time_ns())
            for path in _ROOTS:
                with ownership.owning():
                    parent, name = path.rsplit("/", 1)
                    fd = os.open(path, _FLAGS | os.O_DIRECTORY) if path == "/" else os.open(name,
                        _FLAGS | os.O_DIRECTORY, dir_fd=owner._roots[parent or "/"][0][0])
                    row = owner._handle(fd)
                    owner._roots[path] = row, publication._structural(os.fstat(fd))
                publication._protected(os.fstat(fd))
            info = os.fstat(owner._roots[delivery.DIRECTORY][0][0])
            directory = owner._prepared["value"]["decisionDirectory"]
            p.require(stat.S_IMODE(info.st_mode) == 0o700
                and (info.st_dev, info.st_ino) == (directory["device"], directory["inode"]))
            owner._scan()
            # A fresh worker never resumes previously committed/partial pairs.
            for job in delivery.intake.JOB_NAMES: owner._require_absent(delivery.filenames(job))
            with ownership.owning():
                try:
                    owner._state = StateStore.open(directory=owner._prepared["value"]["stateDirectory"], check=owner.check)
                except BaseException as error:
                    if getattr(error, "owner", None) is not None:
                        p.require(type(error.owner) is StateStore)
                        owner._state = error.owner
                    raise
            owner.check(full=True)
            return owner
        except BaseException as error:
            owner._failed = True
            raise CurrentHeadWorkerError(owner) from error

    def _origin(self):
        public_io._process()
        p.require(type(self) is CurrentHeadWorker and _LIVE is self and not self._closed
            and (self._pid, self._start, self._boot) == (os.getpid(), originals._start(), originals._boot())
            and threading.current_thread() is threading.main_thread())

    def _handle(self, fd):
        row = [fd, None]
        self._handles.append(row)
        row[1] = originals._identity(os.fstat(fd))[:2]
        return row

    def _scan(self):
        names = set()
        with os.scandir(self._roots[delivery.DIRECTORY][0][0]) as entries:
            for entry in entries:
                p.require(len(names) < len(_FILENAMES) and entry.name in _FILENAMES)
                names.add(entry.name)
        return names

    def _require_absent(self, names):
        directory = self._roots[delivery.DIRECTORY][0][0]
        for suffix in ("input", "approval"):
            try: os.stat(names[suffix], dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError: continue
            raise ValueError("current-head pair already exists; no retry or replacement")

    def check(self, *, full=False):
        """StateStore callback: no recursive StateStore.check or lock acquisition."""
        self._origin()
        p.require(not self._failed and not self._closing and self._prepared is not None)
        for held in self._sources: (held.check if full else held.check_identity)()
        self._runtime.check()
        for path, (row, expected) in self._roots.items():
            parent, name = path.rsplit("/", 1)
            actual = os.fstat(row[0]); publication._protected(actual)
            named = os.stat(path, follow_symlinks=False) if path == "/" else os.stat(name,
                dir_fd=self._roots[parent or "/"][0][0], follow_symlinks=False)
            p.require(not os.get_inheritable(row[0])
                and publication._structural(actual) == expected == publication._structural(named))
        for name, (row, maximum, identity, raw) in self._files.items():
            p.require(public_io._input(row[0], maximum) == identity == originals._identity(os.stat(name,
                dir_fd=self._roots[delivery.DIRECTORY][0][0], follow_symlinks=False)))
            if full: p.require(public_io.read_public(row[0], maximum) == raw)
        now, wall = originals._clock(), time.time_ns()
        deadline, expiry = self._prepared["deadline"], self._prepared["epochLimit"]
        if self._active is not None:
            deadline, expiry = min(deadline, self._active["deadline"]), min(expiry, self._active["epochLimit"])
        p.require(self._last <= now < deadline and self._wall <= wall < expiry)
        self._last, self._wall = now, wall

    def _clocks(self):
        self.check()
        return dict(boot=self._boot, now_boottime_ns=self._last, now_unix_ns=self._wall)

    def _read(self, name, maximum):
        self.check(); p.require(name in _FILENAMES and name not in self._files)
        with ownership.owning():
            fd = os.open(name, _FLAGS, dir_fd=self._roots[delivery.DIRECTORY][0][0])
            row = self._handle(fd)
        identity = public_io._input(fd, maximum)
        p.require(self._bytes + identity[6] <= MAX_RETAINED_BYTES)
        raw = public_io.read_public(fd, maximum)
        self._files[name] = row, maximum, identity, raw
        self._bytes += len(raw)
        self.check(full=True)
        return raw

    def _wait_name(self, name):
        while name not in self._scan():
            self.check()
            caps = self._prepared if self._active is None else self._active
            delay = min(0.01, (caps["deadline"] - self._last) / 1e9, (caps["epochLimit"] - self._wall) / 1e9)
            p.require(delay > 0); select.select([], [], [], delay)
            self.check()

    def run(self):
        try:
            self.check(full=True); p.require(not self._used and not self._running)
            self._used = self._running = True
            for index, job in enumerate(delivery.intake.JOB_NAMES):
                p.require(self.decisions == index)
                self.stage = job
                names = delivery.filenames(job)
                self._require_absent(names)
                self._wait_name(names["request"])
                request = self._read(names["request"], delivery.channel.MAX_REQUEST)
                # Narrow the wait as soon as the actual outer request exists;
                # complete evidence/state authority is checked below, never
                # inferred from this deadline-only early projection.
                ticket = p.fields(p.document(request, delivery.channel.MAX_REQUEST), delivery.intake.profile.REQUEST_FIELDS)
                p.require(ticket["apiVersion"] == delivery.intake.profile.API and ticket["job"] == job)
                self._active = dict(deadline=min(self._prepared["deadline"], p.ns(ticket["deadlineBoottimeNs"])),
                    epochLimit=min(self._prepared["epochLimit"], p.ns(ticket["expiresAtUnixNanos"])))
                self.check()
                self._wait_name(names["evidence"])
                evidence = self._read(names["evidence"], delivery.channel.heads.MAX_OBSERVED)
                bounds = profile.bounds(request, evidence, index=index, first_conductor_raw=self._first_conductor)
                self._active = {name: min(self._active[name], bounds[name]) for name in ("deadline", "epochLimit")}
                self.check(full=True)
                # No state authority is inferred from the evidence. The real
                # shared lock prevents its independently controlled writer
                # from changing this named snapshot through durable approval.
                state = self._state.acquire_shared()
                prepared = profile.compose(request, evidence, state, self._prepared, index=index,
                    first_conductor_raw=self._first_conductor, **self._clocks())
                p.require(prepared["conductorOriginal"] == bounds["conductorOriginal"])
                self._active = {name: min(self._active[name], prepared[name]) for name in ("deadline", "epochLimit")}
                added = sum(len(prepared[name]) for name in ("inputOriginal", "approvalOriginal", "receiptOriginal"))
                p.require(self._bytes + added <= MAX_RETAINED_BYTES)
                self._require_absent(names)
                self.check(full=True); self._state.check()
                # The durable receipt consumes this exact request even if a
                # later publication fails. There is no rollback or second try.
                self._state.consume(job, prepared["receiptOriginal"])
                self.check(full=True); self._state.check()
                self._state.publish_pair(job, prepared["inputOriginal"], prepared["approvalOriginal"],
                    directory=self._prepared["value"]["decisionDirectory"])
                self.check(full=True); self._state.check()
                self._state.release()
                self._bytes += added
                self._first_conductor = bytes(prepared["conductorOriginal"])
                self.decisions += 1
                self.check(full=True)
                if self.decisions < len(delivery.intake.JOB_NAMES): self._active = None
            self._runtime.check(installed=True); self.check(full=True)
            self.stage = "eight-authoritative-state-decisions-published"
        except BaseException as error:
            self._failed = True
            raise CurrentHeadWorkerError(self) from error
        finally:
            self._running = False

    def close(self):
        global _LIVE
        if self._closed: return
        try:
            self._origin(); p.require(not self._running and not self._closing)
            self._closing = True
            # Cleanup grants no new decision time and leaves every published
            # consume record/pair in place. StateStore owns ambiguous writes.
            with ownership.owning():
                if self._state is not None: self._state.close()
                while self._handles:
                    row = self._handles[-1]
                    p.require(row[0] is not None and originals._identity(os.fstat(row[0]))[:2] == row[1])
                    fd, row[0] = row[0], None
                    os.close(fd); self._handles.pop()
                for held in self._sources: held.close()
                if self._runtime is not None: self._runtime.close()
                self._closed = True; _LIVE = None
        except BaseException as error:
            self._failed = True
            raise CurrentHeadWorkerError(self) from error
