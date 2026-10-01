"""Actual protected live-state locks, CAS publication and one-use receipts.

The independently approved initial state is authority, not a history-derived
claim. Cooperating readers and writers use the same retained lock inode. This
is delegated same-host root administration, not protection from hostile root
or whole-directory rollback. No checkpoint key, signature or state is invented.
All final public names become visible only after complete durable writes.
Filesystem stalls require the caller's independently operated watchdog.
"""
from __future__ import annotations

import ctypes
import fcntl
import os
import select
import stat
import threading
import time

from serverware import native_pilot_current_head_worker_profile as profile
from serverware import native_pilot_genesis_parent_control_io as ownership
from serverware import native_pilot_publication as publication

p = profile.p
_READ = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
_TOKEN = object()
_LIBC = ctypes.CDLL(None, use_errno=True)
_LIBC.linkat.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int)
_LIBC.linkat.restype = ctypes.c_int
_LIBC.fstatfs.argtypes = (ctypes.c_int, ctypes.c_void_p)
_LIBC.fstatfs.restype = ctypes.c_int


class StateStoreError(ValueError):
    def __init__(self, owner):
        super().__init__("current-head state/publication refused; actual partial owner retained")
        self.owner = owner


class CurrentHeadStatePublisherError(StateStoreError):
    pass


class _Directory:
    """Retained filesystem mechanism only; callback supplies authority/clocks."""
    def __init__(self, token, check):
        p.require(token is _TOKEN and callable(check))
        self._pid, self._outer = os.getpid(), check
        self._handles, self._roots, self._files = [], {}, {}
        self._attempted = set()
        self._closed = self._closing = self._uncertain = self._failed = False
        self._path = None
        self._proc, self._proc_start = {}, None

    def _origin(self):
        p.require(not self._closed and self._pid == os.getpid()
            and threading.current_thread() is threading.main_thread()
            and os.getresuid() == os.getresgid() == (0, 0, 0))

    def _hold(self, fd):
        row = [fd, None]
        self._handles.append(row)  # Before the first fallible metadata read.
        info = os.fstat(fd); row[1] = info.st_dev, info.st_ino
        return row

    def _drop(self, row):
        p.require(row in self._handles and row[0] is not None
            and (os.fstat(row[0]).st_dev, os.fstat(row[0]).st_ino) == row[1])
        with ownership.owning():
            fd, row[0] = row[0], None
            self._uncertain = True
            os.close(fd)
            self._uncertain = False
            self._handles.remove(row)

    def _open(self, path, pin):
        self._origin(); self._outer()
        from serverware import native_pilot_startup_profile as startup
        p.require(path in (profile.STATE_DIRECTORY, profile.DECISION_DIRECTORY, startup.DIRECTORY))
        if pin is not None: profile._directory(pin)
        self._open_proc()
        self._path = path
        for name in ("/", "/etc", "/etc/serverware", path):
            with ownership.owning():
                parent, leaf = name.rsplit("/", 1)
                fd = os.open(name, _READ | os.O_DIRECTORY) if name == "/" else os.open(leaf,
                    _READ | os.O_DIRECTORY, dir_fd=self._roots[parent or "/"][0][0])
                row = self._hold(fd)
                self._roots[name] = row, publication._structural(os.fstat(fd))
            publication._protected(os.fstat(fd))
        info = os.fstat(self.fd)
        p.require(stat.S_IMODE(info.st_mode) == 0o700
            and (pin is None or (info.st_dev, info.st_ino) == (pin["device"], pin["inode"])))
        self.check()

    @property
    def fd(self):
        return self._roots[self._path][0][0]

    def _process_start(self):
        raw = os.pread(self._proc["stat"][0], 4097, 0)
        p.require(0 < len(raw) <= 4096)
        prefix, tail = raw.rsplit(b") ", 1)
        p.require(prefix.split(b" ", 1)[0] == str(self._pid).encode("ascii"))
        return p.integer(int(tail.split()[19]))

    def _open_proc(self):
        # Resolve our own actual PID once on genuine procfs, then hold its FD
        # directory. The caller never supplies a pathname, PID or proc handle.
        with ownership.owning():
            self._proc["root"] = self._hold(os.open("/proc", _READ | os.O_DIRECTORY))
        root = self._proc["root"][0]
        buffer = ctypes.create_string_buffer(256)
        p.require(_LIBC.fstatfs(root, ctypes.byref(buffer)) == 0
            and ctypes.c_long.from_buffer(buffer).value & 0xffffffff == 0x9fa0
            and os.readlink("self", dir_fd=root) == str(self._pid))
        with ownership.owning():
            self._proc["pid"] = self._hold(os.open(str(self._pid), _READ | os.O_DIRECTORY, dir_fd=root))
            self._proc["fd"] = self._hold(os.open("fd", _READ | os.O_DIRECTORY, dir_fd=self._proc["pid"][0]))
            self._proc["stat"] = self._hold(os.open("stat", _READ, dir_fd=self._proc["pid"][0]))
        self._proc_start = self._process_start()
        self._check_proc()

    def _check_proc(self):
        if not self._proc: return
        for name, row in self._proc.items():
            actual = os.fstat(row[0])
            if name == "root": named = os.stat("/proc", follow_symlinks=False)
            else:
                parent, leaf = ("root", str(self._pid)) if name == "pid" else ("pid", name)
                named = os.stat(leaf, dir_fd=self._proc[parent][0], follow_symlinks=False)
            p.require(not os.get_inheritable(row[0]) and (actual.st_dev, actual.st_ino) == row[1]
                == (named.st_dev, named.st_ino) and (stat.S_ISREG(actual.st_mode) if name == "stat"
                else stat.S_ISDIR(actual.st_mode)))
        p.require(self._pid == os.getpid() and self._process_start() == self._proc_start
            and os.readlink("self", dir_fd=self._proc["root"][0]) == str(self._pid))
        # Prove this proc directory addresses this process's actual FD table,
        # not a numerically matching descriptor in another process/namespace.
        row = self._proc["fd"]
        link = os.stat(str(row[0]), dir_fd=row[0], follow_symlinks=True)
        p.require((link.st_dev, link.st_ino) == row[1])

    def _retained(self):
        self._check_proc()
        for path, (row, expected) in self._roots.items():
            parent, leaf = path.rsplit("/", 1)
            named = os.stat(path, follow_symlinks=False) if path == "/" else os.stat(leaf,
                dir_fd=self._roots[parent or "/"][0][0], follow_symlinks=False)
            actual = os.fstat(row[0]); publication._protected(actual)
            p.require(not os.get_inheritable(row[0]) and publication._structural(actual)
                == expected == publication._structural(named))
        for name, (row, identity, raw) in self._files.items():
            p.require(not os.get_inheritable(row[0]) and publication._file_identity(os.fstat(row[0]))
                == identity == publication._file_identity(os.stat(name, dir_fd=self.fd, follow_symlinks=False)))

    def check(self):
        self._origin()
        p.require(not self._failed and not self._closing and not self._uncertain)
        self._outer(); self._retained(); self._outer()

    def _read(self, name, maximum):
        self.check()
        with ownership.owning():
            row = self._hold(os.open(name, _READ, dir_fd=self.fd))
        info = os.fstat(row[0])
        p.require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o400 and info.st_nlink == 1
            and 0 < info.st_size <= maximum)
        raw = os.pread(row[0], maximum + 1, 0)
        p.require(len(raw) == info.st_size and publication._file_identity(os.fstat(row[0]))
            == publication._file_identity(info))
        self._files[name] = row, publication._file_identity(info), raw
        self.check()
        return raw

    def _absent(self, name):
        try: os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError: return
        raise ValueError("current-head publication name already exists")

    def _publish(self, name, raw, maximum):
        self.check()
        p.require(type(name) is str and name and "/" not in name and name not in self._attempted
            and type(raw) is bytes and 0 < len(raw) <= maximum)
        self._attempted.add(name); self._absent(name)
        # No named staging file can race the independent receiver's scanner.
        with ownership.owning():
            row = self._hold(os.open(".", os.O_TMPFILE | os.O_RDWR | os.O_CLOEXEC,
                0o400, dir_fd=self.fd))
        info = os.fstat(row[0])
        p.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 0 and info.st_size == 0
            and info.st_uid == info.st_gid == 0)
        os.fchmod(row[0], 0o400)
        offset = 0
        while offset < len(raw):
            self.check()
            count = os.pwrite(row[0], raw[offset:offset + 65536], offset)
            p.require(0 < count <= min(65536, len(raw) - offset)); offset += count
        os.fsync(row[0]); self.check()
        p.require(os.pread(row[0], len(raw) + 1, 0) == raw)
        with ownership.owning():
            self._check_proc()
            source = str(row[0]).encode("ascii")
            linked = os.stat(source, dir_fd=self._proc["fd"][0], follow_symlinks=True)
            p.require(publication._file_identity(linked) == publication._file_identity(os.fstat(row[0]))
                and (linked.st_dev, linked.st_ino) == row[1] and linked.st_nlink == 0)
            # Following this validated kernel proc magic link does not require
            # AT_EMPTY_PATH's initial-namespace CAP_DAC_READ_SEARCH. This is the
            # only publication primitive, not an error-dependent fallback.
            if _LIBC.linkat(self._proc["fd"][0], source, self.fd, name.encode("ascii"), 0x400) != 0:
                code = ctypes.get_errno(); raise OSError(code, os.strerror(code))
        written = publication._file_identity(os.fstat(row[0]))
        p.require(written[5:7] == (1, len(raw)))
        os.fsync(self.fd); self.check()
        p.require(self._read(name, maximum) == raw and self._files[name][1] == written)
        self._drop(row); self.check()

    def close(self):
        if self._closed: return
        try:
            self._origin(); p.require(not self._closing and not self._uncertain)
            self._closing = True
            # No clock or peer/source callback: expiration is not new work.
            with ownership.owning():
                while self._handles: self._drop(self._handles[-1])
                self._closed = True
        except BaseException as error:
            self._uncertain = True
            raise StateStoreError(self) from error


class AtomicPublisher(_Directory):
    """Source-fixed public files only; bytes never imply approval provenance."""
    @classmethod
    def open(cls, *, directory, check):
        p.require(cls is AtomicPublisher)
        owner = cls(_TOKEN, check)
        try:
            owner._open(profile.DECISION_DIRECTORY, directory)
            return owner
        except BaseException as error:
            owner._failed = True
            raise StateStoreError(owner) from error

    def publish(self, name, raw):
        try:
            limits = {file: (profile.intake.MAX_APPROVAL if suffix == "approval" else
                profile.MAX_EVIDENCE if suffix == "evidence" else profile.MAX_REQUEST if suffix == "request"
                else profile.intake.MAX_INPUT) for job in profile.JOB_NAMES
                for suffix, file in profile.delivery.filenames(job).items()}
            p.require(name in limits)
            self._publish(name, raw, limits[name])
        except BaseException as error:
            self._failed = True
            raise StateStoreError(self) from error


class StartupAtomicPublisher(_Directory):
    """Only the eight fixed startup public names; no admission is authored."""
    @classmethod
    def open(cls, *, directory, check):
        from serverware import native_pilot_startup_profile as startup
        p.require(cls is StartupAtomicPublisher)
        owner = cls(_TOKEN, check)
        try:
            owner._open(startup.DIRECTORY, directory)
            owner.names()
            return owner
        except BaseException as error:
            owner._failed = True
            raise StateStoreError(owner) from error

    @staticmethod
    def _limits():
        from serverware import native_pilot_startup_profile as startup
        return {startup.OBSERVATION_NAME: startup.MAX_OBSERVATION,
            startup.ADMISSION_NAME: startup.MAX_ADMISSION,
            **{startup.SOURCE_FILENAMES[name]: maximum for name, maximum in startup.SOURCE_LIMITS.items()}}

    def names(self):
        self.check()
        names, limits = set(), self._limits()
        with os.scandir(self.fd) as entries:
            for entry in entries:
                p.require(len(names) < len(limits) and entry.name in limits)
                names.add(entry.name)
        self.check()
        return names

    def preflight_inputs(self):
        from serverware import native_pilot_startup_profile as startup
        self.names()
        for name in (*startup.SOURCE_FILENAMES.values(), startup.ADMISSION_NAME): self._absent(name)
        self.check()

    def observation_original(self):
        from serverware import native_pilot_startup_profile as startup
        p.require(startup.OBSERVATION_NAME not in self._files)
        return self._read(startup.OBSERVATION_NAME, startup.MAX_OBSERVATION)

    def publish(self, name, raw):
        try:
            limits = self._limits()
            p.require(name in limits)
            self._publish(name, raw, limits[name])
        except BaseException as error:
            self._failed = True
            raise StateStoreError(self) from error


class StateStore(_Directory):
    def __init__(self, token, check):
        super().__init__(token, check)
        self._lock = None
        self._locked = None
        self._snapshot = None
        self._consumed = {}
        self._publisher = None
        self._initializing = False
        self._update_original = None
        self._update_attempted = False
        self._worker_published = False

    @classmethod
    def open(cls, *, directory, check):
        p.require(cls is StateStore)
        owner = cls(_TOKEN, check)
        try:
            owner._open(profile.STATE_DIRECTORY, directory)
            owner._open_lock(create=False)
            owner.check()
            return owner
        except BaseException as error:
            owner._failed = True
            raise StateStoreError(owner) from error

    def _open_lock(self, *, create):
        flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        if create: flags |= os.O_CREAT | os.O_EXCL
        with ownership.owning():
            self._lock = self._hold(os.open(profile.LOCK_NAME, flags, 0o600, dir_fd=self.fd))
        if create: os.fchmod(self._lock[0], 0o600)
        info = os.fstat(self._lock[0])
        p.require(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and info.st_size == 0)
        if create: os.fsync(self._lock[0]); os.fsync(self.fd)

    @classmethod
    def open_update(cls, *, authorization_raw, check):
        """Actual fixed store acquisition; caller owns independent authorization."""
        p.require(cls is StateStore)
        owner = cls(_TOKEN, check)
        try:
            value = p.fields(p.document(authorization_raw, profile.MAX_UPDATE), profile.UPDATE_FIELDS)
            p.require(value["apiVersion"] == profile.UPDATE_API and p.canonical(value) == authorization_raw)
            profile.state(value["nextStateOriginal"].encode("ascii"))
            owner._update_original = authorization_raw
            owner._initializing = value["expectedStateSha256"] is None
            owner._open(profile.STATE_DIRECTORY, value["directory"])
            if owner._initializing:
                profile.update(authorization_raw, None)
                p.require(not os.listdir(owner.fd))
            owner._open_lock(create=owner._initializing)
            return owner
        except BaseException as error:
            owner._failed = True
            raise StateStoreError(owner) from error

    def apply_update(self):
        try:
            self.check(); p.require(self._update_original is not None and not self._update_attempted)
            self._update_attempted = True
            # The constructor is retained under the caller's signal mask;
            # wait only here, after that short ownership handoff has ended.
            self._acquire(True)
            if self._initializing: p.require(os.listdir(self.fd) == [profile.LOCK_NAME])
            return self._update(self._update_original)
        except BaseException as error:
            self._failed = True
            raise StateStoreError(self) from error

    def _state_check(self):
        super().check()
        if self._lock is not None:
            info = os.fstat(self._lock[0])
            p.require((info.st_dev, info.st_ino) == self._lock[1]
                and publication._file_identity(info) == publication._file_identity(os.stat(profile.LOCK_NAME,
                    dir_fd=self.fd, follow_symlinks=False)) and stat.S_ISREG(info.st_mode)
                and info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_nlink == 1 and info.st_size == 0 and not os.get_inheritable(self._lock[0]))
        if profile.STATE_NAME in self._files:
            row, _, raw = self._files[profile.STATE_NAME]
            p.require(os.pread(row[0], len(raw) + 1, 0) == raw)
        self._outer()

    def check(self):
        self._state_check()
        if self._publisher is not None: self._publisher.check()
        self._outer()

    def _acquire(self, exclusive):
        self.check(); p.require(self._lock is not None and self._locked is None)
        mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        while True:
            self.check()
            try:
                with ownership.owning():
                    fcntl.flock(self._lock[0], mode | fcntl.LOCK_NB)
                    self._locked = mode
                break
            except BlockingIOError:
                select.select([], [], [], 0.01)
        self.check()

    def acquire_shared(self):
        try:
            self._acquire(False)
            p.require(self._snapshot is None)
            self._snapshot = self._read(profile.STATE_NAME, profile.MAX_STATE)
            profile.state(self._snapshot); self.check()
            return self._snapshot
        except BaseException as error:
            self._failed = True
            raise StateStoreError(self) from error

    def consume(self, job, receipt_raw):
        try:
            self.check(); p.require(self._locked == fcntl.LOCK_SH and self._snapshot is not None)
            row = profile.receipt(receipt_raw); current = profile.state(self._snapshot)
            p.require(row["job"] == job and job not in self._consumed
                and row["stateSha256"] == p.sha(self._snapshot) and row["stateGeneration"] == current["generation"])
            self._publish(job + ".receipt.json", receipt_raw, profile.MAX_RECEIPT)
            self._consumed[job] = row
            self.check()
        except BaseException as error:
            self._failed = True
            raise StateStoreError(self) from error

    def publish_pair(self, job, input_raw, approval_raw, *, directory):
        try:
            self.check(); p.require(self._locked == fcntl.LOCK_SH and job in self._consumed)
            receipt = self._consumed[job]
            p.require(receipt["inputSha256"] == p.sha(input_raw) and receipt["approvalSha256"] == p.sha(approval_raw))
            if self._publisher is None:
                with ownership.owning():
                    try: self._publisher = AtomicPublisher.open(directory=directory, check=self._state_check)
                    except StateStoreError as error:
                        self._publisher = error.owner
                        raise
            pin = os.fstat(self._publisher.fd)
            p.require((pin.st_dev, pin.st_ino) == (directory["device"], directory["inode"]))
            names = profile.delivery.filenames(job)
            self._publisher._absent(names["input"]); self._publisher._absent(names["approval"])
            self._publisher.publish(names["input"], input_raw); self.check()
            self._publisher.publish(names["approval"], approval_raw); self.check()
        except BaseException as error:
            self._failed = True
            raise StateStoreError(self) from error

    def publish_worker_inputs(self, supervisor_inventory_raw, worker_policy_raw):
        """Explicit gen1 initializer only; inventory first, fixed policy last."""
        from serverware import native_pilot_initial_state_profile as initial
        from serverware import native_shadow_nitro_originals as originals
        from scripts import native_pilot_runtime_artifacts as artifacts
        try:
            self.check()
            p.require(self._initializing and self._update_attempted and self._locked == fcntl.LOCK_EX
                and not self._worker_published and profile.STATE_NAME in self._files)
            current_raw = self._files[profile.STATE_NAME][2]
            current = profile.state(current_raw)
            boot, now, wall = originals._boot(), originals._clock(), time.time_ns()
            profile._live(current, boot, now, wall)
            initial.lifecycle._inventory(supervisor_inventory_raw, "supervisor")
            prepared = profile.prepare(worker_policy_raw, inventory_sha256=p.sha(supervisor_inventory_raw),
                boot=boot, now_boottime_ns=now, now_unix_ns=wall)
            value, info = prepared["value"], os.fstat(self.fd)
            p.require(value["initialStateSha256"] == p.sha(current_raw)
                and value["initialStateGeneration"] == current["generation"] == 1
                and value["stateDirectory"] == dict(device=info.st_dev, inode=info.st_ino)
                and all(value[name] == current[name] for name in (*profile.BOOT, *profile.CLOCKS)))
            self._absent(initial.INVENTORY_NAME); self._absent(initial.POLICY_NAME)
            self._publish(initial.INVENTORY_NAME, supervisor_inventory_raw, artifacts.MAX_MANIFEST_BYTES)
            self._publish(initial.POLICY_NAME, worker_policy_raw, profile.MAX_POLICY)
            self.check()
            after, epoch = originals._clock(), time.time_ns()
            p.require(now <= after and wall <= epoch)
            profile._live(current, originals._boot(), after, epoch)
            self._worker_published = True
        except BaseException as error:
            self._failed = True
            raise StateStoreError(self) from error

    def check_retained(self):
        """Committed initialization source custody, not renewed publication time."""
        self._origin()
        p.require(self._worker_published and not self._failed and not self._closing and not self._uncertain)
        self._retained()
        p.require(profile.STATE_NAME in self._files)
        row, _, raw = self._files[profile.STATE_NAME]
        p.require(os.pread(row[0], len(raw) + 1, 0) == raw)
        if self._lock is not None:
            actual = os.fstat(self._lock[0])
            p.require((actual.st_dev, actual.st_ino) == self._lock[1]
                and publication._file_identity(actual) == publication._file_identity(os.stat(
                    profile.LOCK_NAME, dir_fd=self.fd, follow_symlinks=False)))
        self._origin()

    def worker_inputs(self):
        """Borrow actual retained readonly public handles, never create authority."""
        from serverware import native_pilot_initial_state_profile as initial
        self.check_retained()
        result = {}
        for purpose, name in (("supervisor_inventory", initial.INVENTORY_NAME), ("policy", initial.POLICY_NAME)):
            row, _, raw = self._files[name]
            p.require(fcntl.fcntl(row[0], fcntl.F_GETFL) & (os.O_ACCMODE | os.O_PATH) == os.O_RDONLY)
            p.require(os.pread(row[0], len(raw) + 1, 0) == raw)
            result[purpose + "_fd"], result[purpose + "_sha256"] = row[0], p.sha(raw)
        self.check_retained()
        return result

    def release(self, *, retain_current=False):
        try:
            self.check(); p.require(self._locked is not None and type(retain_current) is bool
                and (not retain_current or self._worker_published))
            if profile.STATE_NAME in self._files and not retain_current:
                row, _, _ = self._files.pop(profile.STATE_NAME)
                self._drop(row)
            self._snapshot = None
            with ownership.owning():
                fcntl.flock(self._lock[0], fcntl.LOCK_UN)
                self._locked = None
            self.check()
        except BaseException as error:
            self._failed = True
            raise StateStoreError(self) from error

    def close(self):
        if self._closed: return
        if self._publisher is not None:
            try: self._publisher.close()
            except BaseException as error:
                self._uncertain = True
                raise StateStoreError(self) from error
        super().close()  # Closing the actual lock FD releases any held flock.

    def _update(self, authorization_raw):
        """Only the actual protected publisher invokes this one-shot mutation."""
        self.check(); p.require(self._locked == fcntl.LOCK_EX)
        current_raw = None if self._initializing else self._read(profile.STATE_NAME, profile.MAX_STATE)
        next_raw = profile.update(authorization_raw, current_raw)
        number = profile.state(next_raw)["generation"]
        audit, staged = "update-%020d.json" % number, "state-%020d.pending" % number
        self._absent(audit); self._absent(staged)
        self._publish(audit, authorization_raw, profile.MAX_UPDATE)
        if self._initializing:
            self._publish(profile.STATE_NAME, next_raw, profile.MAX_STATE)
        else:
            self._publish(staged, next_raw, profile.MAX_STATE)
            self.check()  # Exact retained old named state immediately before replace.
            old = self._files.pop(profile.STATE_NAME)
            replacement = self._files.pop(staged)
            with ownership.owning():
                # Explicit approved CAS is the only replacement operation.
                os.replace(staged, profile.STATE_NAME, src_dir_fd=self.fd, dst_dir_fd=self.fd)
                self._files[profile.STATE_NAME] = replacement
            # Rename changes inode ctime on some filesystems; capture only the
            # same held inode after the explicit rename and exact readback.
            held = replacement[0]
            p.require(os.pread(held[0], len(next_raw) + 1, 0) == next_raw)
            self._files[profile.STATE_NAME] = held, publication._file_identity(os.fstat(held[0])), next_raw
            self._drop(old[0])
            os.fsync(self.fd); self.check()
        self.check()
        return next_raw


class CurrentHeadStatePublisher:
    def __init__(self, token):
        p.require(token is _TOKEN)
        from serverware import native_shadow_nitro_originals as originals
        self._pid, self._start, self._boot = os.getpid(), originals._start(), originals._boot()
        self._last, self._wall = originals._clock(), time.time_ns()
        self._sources = []
        self._runtime = self._store = self._next = self._authorization = None
        self._used = self._closed = self._closing = self._failed = False
        self.stage = "opening"

    @classmethod
    def open(cls, *, supervisor_inventory_fd, supervisor_inventory_sha256, authorization_fd, authorization_sha256):
        from scripts import native_pilot_runtime_artifacts as artifacts
        from scripts.authority import native_pilot_authority_io as public_io
        from serverware.native_pilot_genesis_authority import _SelfRuntime
        from serverware.native_pilot_lifecycle import _Protected
        p.require(cls is CurrentHeadStatePublisher)
        owner = cls(_TOKEN)
        try:
            public_io._process()
            p.require(all(type(fd) is int and 3 <= fd < (1 << 31) for fd in
                (supervisor_inventory_fd, authorization_fd)) and supervisor_inventory_fd != authorization_fd)
            inventory = _Protected(owner._sources, supervisor_inventory_fd, artifacts.MAX_MANIFEST_BYTES,
                supervisor_inventory_sha256)
            authorization = _Protected(owner._sources, authorization_fd, profile.MAX_UPDATE, authorization_sha256)
            p.require(inventory.identity[:2] != authorization.identity[:2])
            value = p.fields(p.document(authorization.raw, profile.MAX_UPDATE), profile.UPDATE_FIELDS)
            owner._authorization = authorization.raw
            owner._next = profile.state(value["nextStateOriginal"].encode("ascii"))
            owner.check()
            owner._runtime = _SelfRuntime(); owner._runtime.admit(inventory.fd, inventory.digest)
            owner.check()
            owner.stage = "prepared"
            owner.check()
            return owner
        except BaseException as error:
            owner._failed = True
            raise CurrentHeadStatePublisherError(owner) from error

    def check(self):
        from serverware import native_shadow_nitro_originals as originals
        p.require(not self._closed and not self._closing and not self._failed
            and (self._pid, self._start, self._boot) == (os.getpid(), originals._start(), originals._boot())
            and threading.current_thread() is threading.main_thread()
            and os.getresuid() == os.getresgid() == (0, 0, 0))
        for source in self._sources: source.check()
        if self._runtime is not None: self._runtime.check()
        now, wall = originals._clock(), time.time_ns()
        p.require(self._last <= now and self._wall <= wall)
        if self._next is not None: profile._live(self._next, self._boot, now, wall)
        self._last, self._wall = now, wall

    def run(self):
        try:
            self.check(); p.require(not self._used); self._used = True
            value = p.document(self._authorization, profile.MAX_UPDATE)
            initialize = value["expectedStateSha256"] is None
            self.stage = "initializing" if initialize else "updating"
            with ownership.owning():
                try: self._store = StateStore.open_update(authorization_raw=self._authorization, check=self.check)
                except StateStoreError as error:
                    self._store = error.owner
                    raise
            self._store.apply_update()
            self._store.release()
            self._runtime.check(installed=True); self.check()
            self.stage = "state-published"
        except BaseException as error:
            self._failed = True
            raise CurrentHeadStatePublisherError(self) from error

    def close(self):
        if self._closed: return
        try:
            p.require(not self._closing and self._pid == os.getpid()
                and threading.current_thread() is threading.main_thread())
            self._closing = True
            with ownership.owning():
                if self._store is not None: self._store.close()
                if self._runtime is not None: self._runtime.close()
                for source in reversed(self._sources): source.close()
                self._closed = True
        except BaseException as error:
            raise CurrentHeadStatePublisherError(self) from error
