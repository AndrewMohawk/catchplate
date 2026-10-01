"""One-shot peer-preparation exports from the three actual retained owners.

No caller-supplied PID, FD map, clock, or observation can construct an owner.
General resource checks survive exec; only initial capture/export requires the
original preparation phase. Final socket inspectors remain the admission path.
"""
from __future__ import annotations

import os
import select
import threading

from serverware import custody_generation_grants as g
from serverware import custody_generation_originals as o
from serverware import native_pilot_peer_preparation as wire
from serverware import native_pilot_peer_resources as resources

p = wire.p
_TOKEN = object()


def _kind(owner):
    from serverware.custody_generation_launch import FiveServiceLaunch
    from serverware.native_shadow_proof_cohort_control import ParkedProofCohort
    from serverware.native_shadow_driver_bootstrap import DriverBootstrap
    kinds = {FiveServiceLaunch: "ordinary-services", ParkedProofCohort: "native-endpoints", DriverBootstrap: "gate"}
    p.require(type(owner) in kinds)
    return kinds[type(owner)]


def _source(owner, kind):
    owner.check()
    p.require(not owner._attempted and threading.current_thread() is threading.main_thread())
    rows = []
    api = wire.API
    if kind == "ordinary-services":
        p.require(tuple(owner._children) == g.ROLES and not owner._stop.is_set()
            and all(item["phase"] == "parked" and not item["reaped"] for item in owner._children.values()))
        source = owner._originals[0].read()
        config_sha, issued, invocation = p.sha(source), owner._issued, owner._invocation
        for role in g.ROLES:
            child = owner._children[role]
            configuration, cold, executable = owner._configurations[role]
            p.require(g.configuration(configuration.read(), configuration.sha, role) == cold)
            executable.check()
            info = os.fstat(executable.fd)
            expected = dict(device=info.st_dev, inode=info.st_ino, length=info.st_size, sha256=executable.sha)
            rows.append((role, child["pidfd"], child["pid"], child["start"], owner._pid, executable.fd, expected))
    elif kind == "native-endpoints":
        roles = wire.ADOPTED_NATIVE_ROLES if owner.adoption_selected() else wire.NATIVE_ROLES
        api = wire.ADOPTED_API if owner.adoption_selected() else wire.API
        p.require(owner._external_driver is not None and tuple(owner._roles) == roles
            and len(owner._parked) == len(roles))
        source = owner.original_bytes()
        config_sha = p.sha(owner._config_original.raw)
        issued, invocation = p.ns(owner._window["issuedAtBoottimeNs"]), owner._window["invocationId"]
        for role, (pidfd, pid, start) in zip(owner._roles, owner._parked, strict=True):
            row = owner._observed[role]
            p.require((pid, start) == (row["processId"], row["startTimeTicks"]))
            rows.append((role, pidfd, pid, start, owner._child_pid, None, row["executable"]))
    else:
        p.require(owner._gate_binding is not None and owner._gate_pidfd is not None
            and type(owner._gate_binding_raw) is bytes)
        source = owner._gate_binding_raw
        p.require(p.document(source, 8192) == owner._gate_binding)
        config_sha = owner._config_sha
        issued, invocation = p.ns(owner._window["issuedAtBoottimeNs"]), owner._window["invocationId"]
        binding = owner._gate_binding["binding"]
        pid, start = binding["gateProcessId"], binding["gateStartTimeTicks"]
        parent, current_start = o.process(pid)
        p.require(current_start == start)
        rows.append(("gate", owner._gate_pidfd, pid, start, parent, None,
            {"sha256": owner._config["lifecycle"]["gate"]["executableSha256"]}))
    metadata = dict(apiVersion=api, profile=wire.PROFILE, ownerKind=kind,
        phase="executing-gate" if kind == "gate" else "parked-pre-exec",
        configurationSha256=config_sha, sourceOriginalSha256=p.sha(source),
        bootIdBase64url=owner._boot[0], timeNamespaceDevice=owner._boot[1], timeNamespaceInode=owner._boot[2],
        issuedAtBoottimeNs=str(issued), startupDeadlineBoottimeNs=str(owner._startup),
        lifetimeDeadlineBoottimeNs=str(owner._lifetime), invocationId=invocation)
    return metadata, rows


class _Preparation:
    def __init__(self, token, owner, kind):
        p.require(token is _TOKEN)
        self.owner, self.kind = owner, kind
        self.peers, self.raw, self.metadata = {}, None, None
        self.failed = self.closed = False
        self.lock = threading.RLock()
        self.pid, self.start, self.boot = os.getpid(), o.native._start(), o.native._boot()
        self.observed = self.previous = o.clock()

    def _origin(self):
        p.require(not self.closed and not self.failed and os.getpid() == self.pid
            and o.native._start() == self.start and o.native._boot() == self.boot
            and self.boot == self.owner._boot and os.getresuid() == (0, 0, 0)
            and os.getresgid() == (0, 0, 0) and os.uname().machine == "x86_64")
        now = o.clock()
        p.require(self.observed <= self.previous <= now < self.owner._lifetime)
        self.previous = now

    def _startup(self):
        self._origin()
        p.require(o.clock() < self.owner._startup)

    def capture(self):
        with self.lock:
            p.require(self.raw is None and not self.peers)
            self.metadata, rows = _source(self.owner, self.kind)
            p.require(p.ns(self.metadata["issuedAtBoottimeNs"]) <= self.observed)
            for role, pidfd, pid, start, parent, executable, expected in rows:
                self._startup()
                peer = resources._Peer(resources._TOKEN, pidfd=pidfd, pid=pid, start=start,
                    parent=parent, executable_fd=executable, expected=expected, kind=self.kind, check=self._startup)
                self.peers[role] = peer
            value = dict(self.metadata, observedAtBoottimeNs=str(self.observed),
                peers={role: peer.value for role, peer in self.peers.items()})
            self.raw = g.canonical(value)
            wire.shape(self.raw)
            return self.original()

    def check_resources(self):
        # This path is called by actual owner checks, including the ordinary
        # watcher after release. It does not demand parked state or recurse
        # into that owner's check, and never refreshes the captured original.
        with self.lock:
            try:
                self._origin()
                for peer in self.peers.values():
                    peer.check()
                self._origin()
            except BaseException:
                self.failed = True
                raise

    def original(self):
        with self.lock:
            try:
                p.require(self.raw is not None)
                self._startup()
                metadata, rows = _source(self.owner, self.kind)
                p.require(metadata == self.metadata and tuple(self.peers) == tuple(row[0] for row in rows))
                for role, pidfd, pid, start, parent, _, expected in rows:
                    held = self.peers[role]
                    info = os.fstat(pidfd)
                    p.require((pid, start, parent) == (held.pid, held.start, held.parent)
                        and (info.st_dev, info.st_ino) == held.pidfd_identity)
                    target = held.value["targetExecutable"]
                    p.require(target == expected if self.kind != "gate" else target["sha256"] == expected["sha256"])
                self.check_resources(); self._startup()
                return bytes(self.raw)
            except BaseException:
                self.failed = True
                raise

    def close(self):
        # Actual owner close calls only after its existing reap/terminal proof.
        # Independently keep each duplicate PIDFD until it is terminal too.
        with self.lock:
            if self.closed:
                return
            p.require(os.getpid() == self.pid and threading.current_thread() is threading.main_thread())
            for peer in self.peers.values():
                poll = select.poll(); poll.register(peer.pidfd, select.POLLIN)
                p.require(bool(poll.poll(0)))
            for peer in self.peers.values():
                peer.close()
            self.closed = True


def original(owner, *, profile):
    """No serialized constructor: dispatch only these exact genuine owners."""
    p.require(profile == wire.PROFILE)
    kind = _kind(owner)
    owner.check()
    try:
        if not owner._peer_preparation_attempted:
            p.require(threading.current_thread() is threading.main_thread() and not owner._attempted)
            owner._peer_preparation_attempted = True
            retained = _Preparation(_TOKEN, owner, kind)
            owner._peer_preparation = retained
            return retained.capture()
        p.require(owner._peer_preparation is not None)
        return owner._peer_preparation.original()
    except BaseException:
        if owner._peer_preparation is not None:
            owner._peer_preparation.failed = True
        raise
