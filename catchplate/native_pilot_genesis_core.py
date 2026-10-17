"""Retain the actual cold immutable core before its native owners retire.

Only a completed, still-held GenesisCoordinatorAssembly can acquire this
capability. Its JSON observation is not an owner constructor. Transfer is a
one-shot custody handoff, not operational adoption or policy readiness.
"""
from __future__ import annotations

import fcntl
import os
import stat
import threading
import time

from catchplate import custody_generation_grants as g
from catchplate import custody_generation_originals as o
from catchplate import native_pilot_genesis_core_profile as wire
from catchplate import native_pilot_genesis_ordinary_authority as authority
from catchplate import native_pilot_genesis_parent_control_io as io
from catchplate import native_shadow_nitro_originals as originals
from catchplate import native_shadow_retrieval_store as verity

p = g.p
_TOKEN, _LIVE, _USED = object(), None, False
RETRIEVAL, PUBLICATION = "publicationGenesisRetrieval", "publicationGenesis"
NAMES = tuple(sorted(("genesis.json", "ledger.lock", wire.FILENAME,
    "prepared-00000000000000000001.json", "stored-00000000000000000001.json",
    "head-00000000000000000001.json")))


class CoreError(ValueError):
    def __init__(self, owner, *, cleanup_unknown=False):
        super().__init__("cold core refused; actual descriptors retained; no retry")
        self.owner, self.cleanup_unknown = owner, cleanup_unknown


def _metadata(info):
    return dict(zip(wire.FILE_FIELDS, o.identity(info)))


class ColdCore:
    def __init__(self, token, assembly):
        p.require(token is _TOKEN)
        self._assembly = assembly
        self._pid, self._start, self._boot = os.getpid(), originals._start(), originals._boot()
        self._last, self._wall = originals._clock(), time.time_ns()
        self._fds, self._sources, self._siblings = [], [], []
        self._directory = self._fd = self._directory_identity = self._identity = None
        self._bundle = self._observation = self._proof = None
        self._deadline = self._expiry = self._floor = self._issued = None
        self._closed = self._failed = self._transfer_attempted = self._transferred = self._close_attempted = False
        self._channel = None

    @classmethod
    def acquire(cls, *, assembly):
        from catchplate.native_pilot_genesis_coordinator_control import GenesisCoordinatorAssembly
        global _LIVE, _USED
        p.require(cls is ColdCore and type(assembly) is GenesisCoordinatorAssembly and _LIVE is None and not _USED)
        assembly._check()
        parent = assembly._coordinator
        p.require(not assembly._failed and assembly._result is not None and parent._result == assembly._result
            and parent._reaped and parent._terminal_result == (os.CLD_EXITED, 0))
        owner = cls(_TOKEN, assembly)
        _LIVE, _USED = owner, True
        try:
            owner._acquire()
            assembly._check()  # Acquisition remains inside original work/reserve bounds.
            owner.check()
            return owner
        except BaseException as error:
            owner._failed = True
            raise CoreError(owner) from error

    def _retain(self, fd, raw, maximum):
        with io.owning():
            held = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 64)
            self._fds.append(held)
        row = (held, o.identity(os.fstat(held)), bytes(raw), maximum)
        self._sources.append(row)
        p.require(o.read(held, maximum) == raw and o.identity(os.fstat(held)) == row[1])
        return held

    def _acquire(self):
        assembly = self._assembly
        endpoints, ordinary = assembly._endpoints, assembly._ordinary
        resources = endpoints._resources
        p.require(resources is not None and resources.genesis is not None and not resources.closed)
        self._bundle = bytes(assembly._result)
        scope = g.document(assembly._runtime, g.MAX_BYTES)["scope"]
        payloads, grant_shas = {}, {}
        for role in authority.initial.ROLES:
            row = ordinary._resources.roles[role]
            raw = authority.verify_grant(row["grant_raw"], item=ordinary._roles[role]["checked"])
            self._retain(row["grant"], raw, authority.MAX_GRANT)
            payloads[role], grant_shas[role] = g.document(raw, authority.MAX_GRANT)["payload"], p.sha(raw)
        native_raw = {}
        for role in (PUBLICATION, RETRIEVAL):
            original = endpoints._launch_sources[role]["grant"]
            original.check()
            self._retain(original.fd, original.raw, g.MAX_BYTES)
            native_raw[role] = bytes(original.raw)
        genesis_fd, _, genesis_raw = resources.genesis
        self._retain(genesis_fd, genesis_raw, 65536)
        self._proof = wire.verify(self._bundle, scope=scope, native_grant_raw=native_raw[PUBLICATION],
            retrieval_grant_raw=native_raw[RETRIEVAL], ordinary_payloads=payloads,
            ordinary_grant_sha256=grant_shas, retrieval_guest=endpoints._deliveries[RETRIEVAL]["context"]["guest"],
            genesis_raw=genesis_raw, now_boottime_ns=originals._clock(), now_unix_ns=time.time_ns())
        self._issued = scope["issuedAtBoottimeNanos"]
        self._deadline = min(scope["expiresAtBoottimeNanos"], self._proof["storedPayload"]["originalDeadlineBoottimeNanos"],
            assembly._lifetime, endpoints._lifetime, assembly._coordinator._lifetime)
        self._floor = max(self._proof["epochFloor"], assembly._epoch_floor)
        self._expiry = min(self._proof["epochLimit"], assembly._epoch_limit)
        source = resources.roles[RETRIEVAL]["directories"]["ledger-spool-store"]
        with io.owning():
            self._directory = fcntl.fcntl(source, fcntl.F_DUPFD_CLOEXEC, 64)
            self._fds.append(self._directory)
        self._directory_identity = o.structural(os.fstat(self._directory))
        p.require(self._directory_identity == o.structural(os.fstat(source)) and o.names(self._directory) == NAMES)
        for name, expected in (("genesis.json", genesis_raw),
                ("prepared-00000000000000000001.json", self._proof["prepared"]),
                ("stored-00000000000000000001.json", self._proof["stored"]),
                ("head-00000000000000000001.json", self._proof["head"]), (wire.FILENAME, self._proof["core"])):
            self._clock()
            with io.owning():
                fd = os.open(name, o.FLAGS, dir_fd=self._directory)
                self._fds.append(fd)
            info = os.fstat(fd)
            self._siblings.append((name, fd, o.identity(info), expected))
            guest = self._proof["storedPayload"]["guest"]
            p.require(info.st_mode == stat.S_IFREG | 0o400 and info.st_nlink == 1
                and info.st_uid == guest["uid"] and info.st_gid == guest["gid"]
                and o.read(fd, wire.MAX_CORE) == expected)
            if name == wire.FILENAME:
                self._fd, self._identity = fd, _metadata(info)
        stored = self._proof["storedPayload"]
        self._observation = g.canonical({"apiVersion": wire.API, **assembly._pins(),
            "bundleSha256": p.sha(self._bundle), "scopeSha256": p.sha(g.canonical(scope)),
            "commissioningIdSha256": scope["commissioningIdSha256"],
            "endpointPreparationSha256": p.sha(endpoints._preparation), "endpointResourcesSha256": p.sha(resources.raw),
            "retrievalDeliverySha256": stored["guest"]["deliverySha256"],
            "nativeGrantSha256": p.sha(native_raw[PUBLICATION]), "retrievalGrantSha256": p.sha(native_raw[RETRIEVAL]),
            "coreSha256": stored["coreSha256"], "objectSha256": stored["objectSha256"], "fsveritySha256": stored["fsveritySha256"],
            "filename": wire.FILENAME, "directory": dict(zip(wire.DIRECTORY_FIELDS, self._directory_identity)),
            "file": self._identity, "issuedAtBoottimeNs": str(self._issued), "deadlineBoottimeNs": str(self._deadline),
            "issuedAtUnixNanos": self._floor, "expiresAtUnixNanos": self._expiry})
        wire.observation(self._observation, self._bundle)

    def _origin(self):
        p.require(_LIVE is self and not self._closed and os.getpid() == self._pid and originals._start() == self._start
            and originals._boot() == self._boot and threading.current_thread() is threading.main_thread()
            and len(os.listdir("/proc/self/task")) == 1 and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))

    def _clock(self):
        self._origin()
        now, wall = originals._clock(), time.time_ns()
        p.require(self._issued <= self._last <= now < self._deadline and self._floor <= self._wall <= wall < self._expiry)
        self._last, self._wall = now, wall

    def check(self):
        self._clock()
        p.require(not self._failed and self._observation is not None)
        p.require(o.structural(os.fstat(self._directory)) == self._directory_identity
            and not os.get_inheritable(self._directory) and o.names(self._directory) == NAMES)
        for fd, identity, raw, maximum in self._sources:
            p.require(not os.get_inheritable(fd) and o.identity(os.fstat(fd)) == identity
                and o.read(fd, maximum) == raw and o.identity(os.fstat(fd)) == identity)
        for name, fd, identity, raw in self._siblings:
            p.require(not os.get_inheritable(fd) and fcntl.fcntl(fd, fcntl.F_GETFL) & (os.O_ACCMODE | os.O_PATH) == os.O_RDONLY
                and o.identity(os.fstat(fd)) == identity == o.identity(os.stat(name, dir_fd=self._directory, follow_symlinks=False))
                and o.read(fd, wire.MAX_CORE) == raw and o.identity(os.fstat(fd)) == identity)
        wire.verify_file_metadata(_metadata(os.fstat(self._fd)), self._identity)
        p.require(verity._measure(self._fd) == self._proof["storedPayload"]["fsveritySha256"]
            and o.read(self._fd, wire.MAX_CORE) == self._proof["core"])
        wire.verify_file_metadata(_metadata(os.fstat(self._fd)), self._identity)
        p.require(verity._measure(self._fd) == self._proof["storedPayload"]["fsveritySha256"]
            and o.identity(os.stat(wire.FILENAME, dir_fd=self._directory, follow_symlinks=False)) == tuple(self._identity[name] for name in wire.FILE_FIELDS)
            and o.structural(os.fstat(self._directory)) == self._directory_identity)
        self._clock()

    @property
    def transferred(self):
        return self._transferred

    @property
    def deadline_boottime_ns(self):
        return self._deadline

    @property
    def expires_at_unix_ns(self):
        return self._expiry

    def observation_original(self):
        self.check()
        return bytes(self._observation)

    def _retired(self):
        assembly = self._assembly
        p.require(assembly._closed and all(owner._closed for owner in
            (assembly._coordinator, assembly._endpoints, assembly._ordinary)))

    def transfer(self, channel):
        from catchplate.native_pilot_genesis_core_channel import GenesisCoreChannel
        try:
            self.check(); self._retired()
            p.require(type(channel) is GenesisCoreChannel and not self._transfer_attempted)
            self._channel, self._transfer_attempted = channel, True
            channel._send_core(self._fd, self._observation, self._bundle, self.check)
            self._transferred = True  # Exact authenticated ACK, not merely positive send.
            self.check()
        except BaseException as error:
            self._failed = True
            raise CoreError(self, cleanup_unknown=True) from error

    def close(self):
        if self._closed:
            return
        try:
            self._origin(); self._retired()
            p.require(not self._close_attempted)
            p.require(not self._transfer_attempted or self._channel.custody_known)
            # Closing known local custody does not renew an expired admission.
            with io.owning():
                self._close_attempted = True
                while self._fds:
                    fd = self._fds.pop()
                    os.close(fd)
                self._closed = True
        except BaseException as error:
            raise CoreError(self, cleanup_unknown=True) from error
