"""Actual cold coordinator assembly, not an owner reconstructed from JSON.

Only the three original retained owners can construct this one-shot owner.
Four unconnected sockets and four listener directories are passed to their
existing coordinator; its result socket pair remains entirely native-owned.
"""
from __future__ import annotations

import copy
import os
import threading
import time

from catchplate import custody_generation_grants as g
from catchplate import native_pilot_genesis_coordinator_assembly as wire
from catchplate import native_pilot_genesis_coordinator_resources as resources
from catchplate import native_pilot_genesis_parent_control_io as io
from catchplate import native_pilot_peer_resources as peer_resources
from catchplate import native_shadow_nitro_originals as originals
from catchplate.native_shadow_proof_cohort_control import _terminal

p = g.p
_TOKEN, _LIVE, _USED = object(), None, False
RESERVE = 250_000_000


class AssemblyError(ValueError):
    def __init__(self, owner, *, cleanup_unknown=False):
        super().__init__("cold coordinator assembly refused; " +
            ("cleanup unknown; all retained owners remain reachable" if cleanup_unknown else "actual owners retained"))
        self.owner, self.cleanup_unknown = owner, cleanup_unknown


class GenesisCoordinatorAssembly:
    def __init__(self, token, coordinator, ordinary, endpoints):
        p.require(token is _TOKEN)
        self._coordinator, self._ordinary, self._endpoints = coordinator, ordinary, endpoints
        self._pid, self._start, self._boot = os.getpid(), originals._start(), originals._boot()
        self._last = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        self._window = copy.deepcopy(coordinator._window)
        self._startup, self._lifetime = (p.ns(self._window[name]) for name in ("startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"))
        self._deadline = self._lifetime - RESERVE
        self._epoch_floor = self._epoch_limit = None
        self._resources = self._observation = self._approval = self._runtime = self._result = None
        self._peers, self._owned_peers, self._inputs = {}, [], []
        self._failed = self._closed = self._close_attempted = self._assemble_attempted = self._release_attempted = self._finish_attempted = False
        self._released = False

    @classmethod
    def prepare(cls, *, coordinator, ordinary, endpoints):
        from catchplate.native_pilot_genesis_parent_control import ParkedGenesisController
        from catchplate.native_pilot_genesis_ordinary_control import GenesisOrdinaryControl
        from catchplate.native_pilot_genesis_endpoint_control import GenesisEndpointControl
        global _LIVE, _USED
        p.require(cls is GenesisCoordinatorAssembly and _LIVE is None and not _USED
            and type(coordinator) is ParkedGenesisController and type(ordinary) is GenesisOrdinaryControl
            and type(endpoints) is GenesisEndpointControl and ordinary._coordinator is coordinator and endpoints._coordinator is coordinator)
        io.public_io._process()
        coordinator.observation_original(); ordinary._check(startup=True); endpoints._check(startup=True)
        p.require(endpoints._preparation is not None and endpoints._resources is not None)
        owner = cls(_TOKEN, coordinator, ordinary, endpoints)
        _LIVE, _USED = owner, True
        try:
            for item in (ordinary, endpoints):
                p.require(g.canonical({name: item._window[name] for name in wire.endpoints.WINDOW})
                    == g.canonical({name: owner._window[name] for name in wire.endpoints.WINDOW}))
            for role in wire.runtime.ROLES:
                child, item = ordinary._children[role], ordinary._roles[role]
                target = {name: item["target"][name] for name in ("device", "inode", "length", "sha256")}
                with io.owning():
                    peer = peer_resources._Peer(peer_resources._TOKEN, pidfd=child["pidfd"], pid=child["pid"], start=child["start"],
                        parent=ordinary._pid, executable_fd=item["executable"].fd, expected=target,
                        kind="ordinary-services", check=lambda: owner._clock(startup=True))
                    owner._owned_peers.append(peer); owner._peers[role] = peer
            for role in wire.endpoints.ROLES:
                owner._peers[role] = endpoints._peers[role]
            actual = coordinator.controller_observation()
            with io.owning():
                # The low-level executing-process branch reads this actual
                # retained native controller's /proc/exe, not a gate DTO or
                # arbitrary supplied PID. No gate authority is constructed.
                peer = peer_resources._Peer(peer_resources._TOKEN, pidfd=coordinator._pidfd,
                    pid=actual["processId"], start=actual["startTimeTicks"], parent=coordinator._pid,
                    executable_fd=None, expected=actual["executable"], kind="gate", check=lambda: owner._clock(startup=True))
                owner._owned_peers.append(peer); owner._peers["resultPeer"] = peer
            p.require(peer.value["targetExecutable"] == actual["executable"])
            resources.Resources.prepare(owner)
            activation = owner._resources.activation + copy.deepcopy(coordinator._observed["resultActivation"])
            value = {"apiVersion": wire.OBSERVATION, **owner._pins(),
                "window": {name: owner._window[name] for name in wire.endpoints.WINDOW},
                "observedAtBoottimeNs": str(owner._clock(startup=True)),
                "peers": {role: owner._peers[role].value for role in wire.ROLES}, "activation": activation}
            owner._observation = g.canonical(value); wire.observation(owner._observation)
            owner._check(startup=True)
            return owner
        except BaseException as error:
            owner._failed = True
            raise AssemblyError(owner) from error

    def _pins(self):
        return dict(parentConfigurationSha256=p.sha(self._coordinator._configuration.raw),
            parentPrecreationSha256=p.sha(self._coordinator._precreation.raw),
            ordinaryConfigurationSha256=p.sha(self._ordinary._configuration.raw),
            endpointConfigurationSha256=p.sha(self._endpoints._configuration.raw))

    def _origin(self):
        p.require(_LIVE is self and not self._closed and os.getpid() == self._pid and originals._start() == self._start
            and originals._boot() == self._boot and threading.current_thread() is threading.main_thread()
            and len(os.listdir("/proc/self/task")) == 1 and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))

    def _clock(self, *, startup=False, cleanup=False):
        self._origin()
        now = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        ceiling = self._lifetime if cleanup else min(self._startup, self._deadline) if startup else self._deadline
        p.require(p.ns(self._window["issuedAtBoottimeNs"]) <= self._last <= now < ceiling)
        if not cleanup and self._epoch_limit is not None:
            p.require(self._epoch_floor <= time.time_ns() < self._epoch_limit)
        self._last = now
        return now

    def _check(self, *, startup=False, resources=True):
        self._clock(startup=startup)
        self._ordinary._check(startup=startup)
        self._endpoints._check(startup=startup)
        coordinator = self._coordinator
        coordinator._origin(); coordinator._check_sources()
        if startup:
            coordinator.observation_original()
        elif not coordinator._reaped:
            # Normal native completion can precede the caller's finish poll.
            # Only finish() may authenticate output and consume the real reap.
            coordinator._controller(terminal=True)
        for role, peer in self._peers.items():
            if role == "resultPeer" and self._release_attempted and _terminal(peer.pidfd):
                continue
            peer.check()
        for original in self._inputs:
            original.check_identity()
        if resources and self._resources is not None:
            self._resources.check()
        self._clock(startup=startup)

    def observation_original(self):
        self._check(startup=True)
        p.require(self._observation is not None and not self._release_attempted and not self._failed)
        return bytes(self._observation)

    def assemble(self, *, approval_fd, approval_sha256):
        try:
            self._check(startup=True)
            p.require(not self._assemble_attempted and not self._failed and self._ordinary._released and self._endpoints._released)
            self._assemble_attempted = True
            with io.owning():
                original = io.PublicInput(approval_fd, 65536, approval_sha256)
                self._inputs.append(original); self._approval = original
            ordinary_records, native_records = {}, {}
            for role in wire.runtime.ROLES:
                item = self._ordinary._roles[role]["checked"]
                ordinary_records[role] = {"runtimeOriginal": item["runtime_raw"].decode("ascii"),
                    "historyOriginal": item["history_raw"].decode("ascii"),
                    "grantOriginal": self._ordinary._resources.roles[role]["grant_raw"].decode("ascii"),
                    "guest": copy.deepcopy(item["guest"])}
            for role in wire.endpoints.ROLES:
                held = self._endpoints._launch_sources[role]["grant"]
                held.check()
                native_records[role] = {"grantOriginal": held.raw.decode("ascii"),
                    "guest": copy.deepcopy(self._endpoints._deliveries[role]["context"]["guest"])}
            result = wire.build(approval_raw=original.raw, observation_raw=self._observation,
                ordinary_records=ordinary_records, native_records=native_records, cold=self._coordinator._context["cold"],
                coordinator=self._coordinator._observed, boot=self._boot,
                now_boottime_ns=self._clock(startup=True), now_unix_ns=time.time_ns())
            self._deadline = min(self._deadline, result["runtimeDeadline"] - RESERVE, self._endpoints._deadline)
            self._epoch_floor, self._epoch_limit = result["epochFloor"], result["epochLimit"]
            self._runtime = result["runtimeOriginal"]
            self._check(startup=True)
            return bytes(self._runtime)
        except BaseException as error:
            self._failed = True
            raise AssemblyError(self) from error

    def runtime_original(self):
        self._check(startup=True)
        p.require(self._runtime is not None and not self._release_attempted and not self._failed)
        return bytes(self._runtime)

    def activation_original(self):
        self._check(startup=True)
        p.require(not self._release_attempted and not self._failed)
        return g.canonical(wire.observation(self._observation)["activation"])

    def release(self, *, release_fd, release_sha256):
        try:
            self._check(startup=True)
            p.require(self._runtime is not None and not self._release_attempted and not self._failed)
            self._release_attempted = True
            descriptors = self._resources.borrowed_fds()
            # A positive send may be followed by cancellation; retain the
            # possible connection state before handing descriptors to native.
            self._resources.released = True
            self._coordinator._release_with_runtime(release_fd=release_fd, release_sha256=release_sha256,
                activation_fds=descriptors, expected_runtime=self._runtime, check=self._release_check)
            self._released = True
            self._check()
            self._clock(startup=True)
        except BaseException as error:
            self._failed = True
            raise AssemblyError(self) from error

    def _release_check(self):
        # Parent has already consumed the release attempt. Do not invoke its
        # parked-observation export API; retain the original startup ceiling.
        self._check()
        self._clock(startup=True)

    def _running_check(self):
        self._ordinary.poll()  # Actual notices, not inferred readiness.
        self._check()

    def finish(self):
        try:
            p.require(self._released and not self._finish_attempted and not self._failed)
            self._finish_attempted = True
            self._running_check()
            raw = self._coordinator._finish_checked(self._running_check)
            p.require(self._coordinator._reaped and self._coordinator._runtime.raw == self._runtime)
            self._check()
            self._result = bytes(raw)
            return bytes(raw)  # Coordinator completion only, not all-owner retirement.
        except BaseException as error:
            self._failed = True
            raise AssemblyError(self) from error

    def close(self):
        if self._closed:
            return {"status": "closed"}
        self._origin()
        p.require(not self._close_attempted)
        self._close_attempted = True
        failures = []
        for owner in (self._coordinator, self._endpoints, self._ordinary):
            if owner._closed:
                continue
            try:
                self._clock(cleanup=True)
                owner.close()
            except BaseException as error:
                failures.append(error)
        # Each owner must establish its own retirement. In particular ordinary
        # cleanup requires the native helper notice and the direct-child reap;
        # a completed coordinator Bundle cannot stand in for either of them.
        if failures:
            raise AssemblyError(self, cleanup_unknown=True) from failures[0]
        try:
            self._clock(cleanup=True)
            if self._resources is not None:
                self._resources.close_after_coordinator()
            with io.owning():
                while self._owned_peers:
                    self._owned_peers[-1].close(); self._owned_peers.pop()
                while self._inputs:
                    self._inputs[-1].close(); self._inputs.pop()
                self._clock(cleanup=True)
                self._closed = True
            return {"status": "closed", "coordinatorCompleted": self._result is not None}
        except BaseException as error:
            raise AssemblyError(self, cleanup_unknown=True) from error
