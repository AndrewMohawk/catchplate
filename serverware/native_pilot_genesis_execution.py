"""One independently approved cold commissioning graph with real retained owners.

The fixed catalogue, complete public inputs and separately pinned approvals
authorize each step. Observations never authorize signatures. No caller DTO
can replace a process owner, no key is generated, and failed work is not
retried. A returned Bundle requires native completion AND actual cleanup.
The explicit v2 mode additionally transfers the genuine retained fs-verity
core after cleanup. Acknowledged custody is not operational adoption authority.
"""
from __future__ import annotations

import copy
import fcntl
import os
import select
import threading
import time

from scripts.authority import native_pilot_authority_io as key_io
from serverware import custody_generation_grants as g
from serverware import native_pilot_genesis_execution_protocol as wire
from serverware import native_pilot_genesis_jobs as jobs
from serverware import native_pilot_genesis_launch_install as launch_install
from serverware import native_pilot_genesis_parent_control_io as io
from serverware import native_pilot_genesis_publication as publication
from serverware import native_shadow_nitro_originals as originals
from serverware.native_pilot_genesis_coordinator_control import GenesisCoordinatorAssembly
from serverware.native_pilot_genesis_endpoint_control import GenesisEndpointControl
from serverware.native_pilot_genesis_ordinary_control import GenesisOrdinaryControl
from serverware.native_pilot_genesis_parent_control import ParkedGenesisController

p = g.p
MAX_RETAINED_BYTES = 128 * 1024 * 1024
_TOKEN, _LIVE, _USED = object(), None, False


class GenesisExecutionError(ValueError):
    def __init__(self, owner, *, cleanup_unknown=False):
        super().__init__("cold commissioning refused; " + ("cleanup unknown; all capabilities retained"
            if cleanup_unknown else "actual partial owners retained; no retry"))
        self.owner, self.cleanup_unknown = owner, cleanup_unknown


class GenesisExecution:
    def __init__(self, token):
        p.require(token is _TOKEN)
        self._pid, self._start, self._boot = os.getpid(), originals._start(), originals._boot()
        self._last, self._wall = originals._clock(), time.time_ns()
        self._configuration = self._window = None
        self._startup = self._lifetime = self._deadline = self._epoch_limit = None
        self._parent = self._ordinary = self._endpoints = self._assembly = None
        self._core = self._core_channel = None
        self._handoff_listener = None
        self._handoff = self._handoff_attempted = False
        self._handoff_peer = None
        self._jobs = jobs.JOBS
        self._held, self._keys, self._public_fds, self._installers = [], {}, {}, []
        self._prior, self._input_sources, self._observations, self._delta = {}, {}, {}, {}
        self._bytes = self._index = 0
        self._ticket = self._ticket_value = self._previous = self._bundle = None
        self._failed = self._closed = self._keys_attempted = self._keys_ready = False
        self._close_attempted = self._cleanup_attempted = self._owners_retired = False

    @classmethod
    def open(cls, configuration_fd, configuration_sha256, *, handoff=False):
        global _LIVE, _USED
        p.require(cls is GenesisExecution and not _USED and _LIVE is None and type(handoff) is bool)
        key_io._process()
        p.require(threading.current_thread() is threading.main_thread() and len(os.listdir("/proc/self/task")) == 1)
        owner = cls(_TOKEN)
        _LIVE, _USED = owner, True
        try:
            owner._handoff, owner._jobs = handoff, jobs.catalogue(handoff=handoff)
            source = owner._input(configuration_fd, configuration_sha256, 4096)
            selected = wire.configuration(source.raw, boot=owner._boot,
                now_boottime_ns=owner._last, now_unix_ns=owner._wall, handoff=handoff)
            owner._handoff_peer = copy.deepcopy(selected.get("coreHandoff"))
            owner._configuration, owner._window = source, copy.deepcopy(selected["window"])
            owner._startup, owner._lifetime = (p.ns(owner._window[name]) for name in
                ("startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"))
            owner._deadline = owner._lifetime - wire.RESERVE
            owner._epoch_limit = selected["expiresAtUnixNanos"]
            owner._check()
            return owner
        except BaseException as error:
            owner._failed = True
            raise GenesisExecutionError(owner) from error

    def _origin(self):
        p.require(_LIVE is self and not self._closed and os.getpid() == self._pid
            and originals._start() == self._start and originals._boot() == self._boot
            and threading.current_thread() is threading.main_thread() and len(os.listdir("/proc/self/task")) == 1
            and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))

    def _selected(self):
        p.require(self._index < len(self._jobs))
        return self._jobs[self._index]

    def _ceiling(self):
        name = self._jobs[self._index].name if self._index < len(self._jobs) else "cleanup"
        ceiling = (self._lifetime if name in ("cleanup", "handoff-cold-core") else self._deadline
            if name in ("coordinator-finish", "acquire-cold-core") else min(self._startup, self._deadline))
        return min(ceiling, self._core.deadline_boottime_ns) if self._core is not None else ceiling

    def prepare_handoff(self, fd):
        """Retain the separately approved real peer before private key intake."""
        from serverware.native_pilot_genesis_core_channel import GenesisCoreChannel
        self._check()
        p.require(self._handoff and not self._handoff_attempted and not self._keys_attempted)
        self._handoff_attempted = True
        try:
            peer = self._handoff_peer
            self._acquire("_core_channel", lambda: GenesisCoreChannel.open(fd=fd,
                peer_pid=peer["peerPid"], peer_uid=peer["peerUid"], peer_gid=peer["peerGid"],
                deadline_boottime_ns=self._lifetime, expires_at_unix_ns=self._epoch_limit))
            self._check()
        except BaseException as error:
            self._failed = True
            raise GenesisExecutionError(self) from error

    def prepare_handoff_listener(self, listener):
        """Accept one actual recipient after independent observed-PID approval."""
        from serverware.native_pilot_genesis_handoff_listener import CoreHandoffListener
        self._check()
        p.require(type(listener) is CoreHandoffListener and self._handoff
            and not self._handoff_attempted and not self._keys_attempted)
        self._handoff_attempted = True
        self._handoff_listener = listener  # Retain before any accepting work.
        try:
            selected = listener.require_execution(self._configuration.raw)
            p.require(selected["coreHandoff"] == self._handoff_peer)
            # Listener retains the same actual channel even if cancellation
            # arrives before this assignment; no descriptor DTO reconstructs it.
            self._core_channel = listener.accept(self._configuration.raw, self._check)
            self._check()
        except BaseException as error:
            self._failed = True
            raise GenesisExecutionError(self) from error

    def _clock(self, *, cleanup=False):
        self._origin()
        now, wall = originals._clock(), time.time_ns()
        p.require(self._last <= now and self._wall <= wall)
        if self._window is not None:
            p.require(p.ns(self._window["issuedAtBoottimeNs"]) <= now < (self._lifetime if cleanup else self._ceiling()))
            if not cleanup:
                p.require(wall < self._epoch_limit)
        self._last, self._wall = now, wall
        return now

    def _input(self, fd, digest, maximum):
        p.require(self._bytes < MAX_RETAINED_BYTES)
        with io.owning():
            source = io.PublicInput(fd, min(maximum, MAX_RETAINED_BYTES - self._bytes), digest)
            self._held.append(source)
            self._bytes += len(source.raw)
        return source

    def prepare_keys(self, declared):
        self._check()
        p.require(not self._failed and not self._keys_attempted and self._index == 0)
        p.require(not self._handoff or self._core_channel is not None)
        self._keys_attempted = True
        try:
            p.fields(declared, jobs.KEY_PURPOSES)
            for purpose in jobs.KEY_PURPOSES:
                fd = declared[purpose]
                identity = key_io._input(fd, 32, private=True)
                p.require(identity[6] == 32)
                with io.owning():
                    held = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 128)
                    self._keys[purpose] = (held, identity)
                p.require(key_io._input(held, 32, private=True) == identity)
            # These supplied capabilities are transferred, not borrowed. A
            # single seed FD may serve distinct independently checked purposes.
            for fd in set(declared.values()):
                with io.owning():
                    os.close(fd)
            self._keys_ready = True
            self._check()
        except BaseException as error:
            self._failed = True
            raise GenesisExecutionError(self) from error

    def _key(self, purpose):
        p.require(self._failed and self._keys_ready and purpose == self._selected().key)
        self._check()
        fd, identity = self._keys[purpose]
        p.require(key_io._input(fd, 32, private=True) == identity)
        result = key_io.signing_key(fd)
        p.require(key_io._input(fd, 32, private=True) == identity)
        self._clock()
        return result

    def _owners_check(self):
        if self._owners_retired:
            return
        if self._assembly is not None:
            self._assembly._check()
            return
        for owner in (self._ordinary, self._endpoints):
            if owner is not None and not owner._closed:
                owner._check()
        owner = self._parent
        if owner is not None and not owner._closed:
            owner._origin(); owner._check_sources()
            if owner._started and not owner._reaped:
                owner._controller(terminal=owner._release_attempted)

    def _installation_guard(self):
        # Deliberately excludes installer.check(): it calls this during real
        # writes, so recursively checking installers would recurse forever.
        self._clock()
        for original in self._held:
            original.check_identity()
        self._owners_check()
        if self._handoff_listener is not None:
            self._handoff_listener.check()
        if self._core_channel is not None:
            self._core_channel.check()
        if self._core is not None:
            self._core.check()
        self._clock()

    def _check(self, *, full=False):
        try:
            self._installation_guard()
            if full:
                for original in self._held:
                    original.check()
            for installer in self._installers:
                installer.check_retained()
            self._clock()
        except BaseException:
            self._failed = True
            raise

    def has_job(self):
        p.require(not self._failed and self._keys_ready and not self._closed)
        self._check()
        return self._index < len(self._jobs)

    def job_request(self):
        p.require(self.has_job())
        if self._ticket is None:
            self._ticket_value, self._ticket = wire.request(sequence=self._index + 1,
                job=self._selected().name, deadline=self._ceiling(), observation=self._delta, previous=self._previous,
                handoff=self._handoff)
        self._clock()
        return copy.deepcopy(self._ticket_value)

    def _observe(self, name, raw):
        p.require((name in jobs.OBSERVATIONS or (self._handoff and name == "core.observation"))
            and type(raw) is bytes and 0 < len(raw) <= wire.MAX_REQUEST)
        if name in self._observations:
            p.require(self._observations[name] == raw)
            return
        p.require(self._bytes + len(raw) <= MAX_RETAINED_BYTES)
        self._observations[name] = raw; self._delta[name] = raw
        self._bytes += len(raw)

    def _public_fd(self, name, raw):
        """Sealed public result transport, never an approval or private seed."""
        if name in self._public_fds:
            fd, identity, previous = self._public_fds[name]
            p.require(previous == raw and key_io._input(fd, len(raw)) == identity)
            return fd
        p.require(type(raw) is bytes and 0 < len(raw) <= wire.MAX_REQUEST
            and self._bytes + len(raw) <= MAX_RETAINED_BYTES)
        with io.owning():
            fd = os.memfd_create("serverware-genesis-public", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            self._public_fds[name] = (fd, None, raw)
            self._bytes += len(raw)
        offset = 0
        while offset < len(raw):
            self._clock()
            count = os.pwrite(fd, raw[offset:offset + 65536], offset)
            p.require(count > 0); offset += count
        os.fchmod(fd, 0o400)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, key_io.SEALS)
        identity = key_io._input(fd, len(raw))
        p.require(key_io.read_public(fd, len(raw)) == raw)
        self._public_fds[name] = (fd, identity, raw)
        self._clock()
        return fd

    def _record(self, name):
        return wire.preceding(self._prior, name)

    def _result_fd(self, name):
        raw = self._record(name)["result"]
        return self._public_fd(name, raw), p.sha(raw)

    def _acquire(self, field, call):
        # Constructors retain their own partial state in typed exceptions;
        # the mask also closes the successful return-to-field handoff gap.
        with io.owning():
            try:
                value = call()
                setattr(self, field, value)
                return value
            except BaseException as error:
                if getattr(error, "owner", None) is not None:
                    setattr(self, field, error.owner)
                raise

    def _install(self, call):
        with io.owning():
            try:
                owner = call()
                self._installers.append(owner)
                return owner
            except BaseException as error:
                if getattr(error, "owner", None) is not None:
                    self._installers.append(error.owner)
                raise

    def _await_ordinary_constructed(self):
        # Both notices are authenticated by the retained ordinary owner. Do
        # not expose the lifetime-valid finish request with queued startup
        # notices that could become inadmissible while awaiting its approval.
        p.require(self._selected().name == "coordinator-release" and self._assembly._released)
        while True:
            self._installation_guard()
            complete = self._ordinary.constructed()
            now = self._clock()  # Still this release job's original startup.
            if complete:
                return
            watched = [descriptor for child in self._ordinary._children.values()
                for descriptor in (child["channel"], child["pidfd"])]
            select.select(watched, [], [], min(0.01, (self._ceiling() - now) / 1_000_000_000))
            self._clock()

    def _perform_owner(self, selected, source):
        name, role = selected.name, selected.role
        if name == "parent-start":
            owner = self._acquire("_parent", lambda: ParkedGenesisController.prepare(
                control_fd=source.fd, control_sha256=p.sha(source.raw)))
            wire.require_window(owner._window, self._window)
            p.require(owner._precreation.raw == self._record("parent-precreation")["result"])
            approved = jobs.parent.input_document(self._record("parent-precreation")["input"])
            p.require(approved["configurationOriginal"].encode("ascii") == owner._configuration.raw
                and approved["deliveryConfigurationOriginal"].encode("ascii") == owner._cold.raw)
            owner.start()
            for key, raw in (("configuration", owner._configuration.raw), ("cold", owner._cold.raw),
                    ("precreation", owner._precreation.raw), ("observation", owner.observation_original()),
                    ("peer", owner.peer_preparation_original())):
                self._observe("parent." + key, raw)
        elif name == "ordinary-prepare":
            owner = self._acquire("_ordinary", lambda: GenesisOrdinaryControl.prepare(coordinator=self._parent,
                control_fd=source.fd, control_sha256=p.sha(source.raw)))
            wire.require_window(owner._window, self._window)
            for key, raw in (("configuration", owner._configuration.raw), ("preparation", owner.preparation_original()),
                    ("resources", owner.resources_original())):
                self._observe("ordinary." + key, raw)
            for item in jobs.ORDINARY:
                self._observe("ordinary.activation." + item, g.canonical(owner.activation(item)))
                self._observe("ordinary.runtime-inputs." + item, g.canonical(owner.runtime_inputs(item)))
        elif name == "endpoints-prepare":
            owner = self._acquire("_endpoints", lambda: GenesisEndpointControl.prepare(coordinator=self._parent,
                control_fd=source.fd, control_sha256=p.sha(source.raw)))
            wire.require_window(owner._window, self._window)
            owner.start(); owner.prepare_resources()
            for key, raw in (("configuration", owner._configuration.raw), ("preparation", owner.preparation_original()),
                    ("resources", owner._resources.original())):
                self._observe("endpoints." + key, raw)
            for item in jobs.NATIVE[:2]:
                self._observe("endpoints.activation." + item, g.canonical(owner._resources.roles[item]["activation"]))
        elif name == "initialize-retrieval-store":
            expected = g.document(self._record("cold-binding")["result"], g.MAX_BYTES)["proofScopeOriginal"].encode("ascii")
            p.require(source.raw == expected)
            raw = self._endpoints._resources.initialize_store(proof_scope_fd=source.fd, proof_scope_sha256=p.sha(source.raw))
            self._observe("endpoints.store", raw)
            return raw
        elif name.startswith("install-launch-"):
            wire.native_install(source.raw, role, self._prior)
            owner = self._install(lambda: launch_install.prepare(role, source.fd, p.sha(source.raw)))
            return g.canonical(owner.install())
        elif name == "coordinator-assemble":
            raw = self._assembly.assemble(approval_fd=source.fd, approval_sha256=p.sha(source.raw))
            self._deadline = min(self._deadline, self._assembly._deadline)
            self._epoch_limit = min(self._epoch_limit, self._assembly._epoch_limit)
            self._observe("coordinator.runtime", raw)
            return raw
        else:
            wire.owner_action(source.raw, name)
            return self._action(selected)
        return g.canonical({"apiVersion": "serverware.nativePilotGenesisOwnerResult/v1", "action": name,
            "observationSha256": {key: p.sha(raw) for key, raw in self._delta.items()}})

    def _action(self, selected):
        name, role = selected.name, selected.role
        if name == "install-precreation" or name.startswith("install-ordinary-"):
            owner = self._install(lambda: publication.GenesisPublicInstallation.install(job_name=name,
                prior=self._prior, observations=self._observations, check=self._installation_guard))
            return g.canonical(owner.result())
        if name.startswith("admit-delivery-"):
            key = "native-delivery-" + role
            source = self._input_sources[key]
            fd, digest = self._result_fd(key)
            self._endpoints.admit_delivery(role, input_fd=source.fd, input_sha256=p.sha(source.raw),
                delivery_fd=fd, delivery_sha256=digest)
        elif name == "endpoints-release":
            fd, digest = self._result_fd("endpoint-release")
            self._endpoints.release(release_fd=fd, release_sha256=digest)
            self._deadline = min(self._deadline, self._endpoints._deadline)
        elif name == "ordinary-release":
            rows = {}
            for item in jobs.ORDINARY:
                installed = g.document(self._record("install-ordinary-" + item)["result"], 65536)
                fd, digest = self._result_fd("ordinary-grant-" + item)
                rows[item] = {"launch": installed["launchPin"], "grant": {"fd": fd, "sha256": digest}}
            self._ordinary.release(inputs=rows)
        elif name == "coordinator-prepare":
            owner = self._acquire("_assembly", lambda: GenesisCoordinatorAssembly.prepare(
                coordinator=self._parent, ordinary=self._ordinary, endpoints=self._endpoints))
            self._observe("coordinator.observation", owner.observation_original())
            self._observe("coordinator.activation", owner.activation_original())
        elif name == "coordinator-release":
            fd, digest = self._result_fd("parent-release")
            self._assembly.release(release_fd=fd, release_sha256=digest)
            self._deadline = min(self._deadline, self._assembly._deadline, self._parent._deadline)
            self._await_ordinary_constructed()
        elif name == "coordinator-finish":
            self._bundle = self._assembly.finish()
            return self._bundle
        elif name == "acquire-cold-core":
            from serverware.native_pilot_genesis_core import ColdCore
            p.require(self._handoff and self._bundle is not None and not self._owners_retired)
            owner = self._acquire("_core", lambda: ColdCore.acquire(assembly=self._assembly))
            self._epoch_limit = min(self._epoch_limit, owner.expires_at_unix_ns)
            raw = owner.observation_original()
            self._observe("core.observation", raw)
            return raw
        elif name == "cleanup":
            self._cleanup_owners()
            return g.canonical({"status": "closed", "coordinatorCompleted": self._bundle is not None})
        elif name == "handoff-cold-core":
            p.require(self._handoff and self._owners_retired and self._core is not None)
            # Earlier approved producer inputs may have tightened this graph's
            # UNIX cap since the channel was acquired. Keep that ceiling inside
            # the actual send/ACK wait, not merely in a post-transfer check.
            self._core_channel.constrain(deadline_boottime_ns=self._ceiling(),
                expires_at_unix_ns=self._epoch_limit)
            self._core.transfer(self._core_channel)
            p.require(self._core.transferred)
            return g.canonical({"status": "cold-core-custody-acknowledged", "bundleSha256": p.sha(self._bundle),
                "observationSha256": p.sha(self._core.observation_original()), "operationalAdoptionVerified": False})
        else:
            raise ValueError("fixed cold owner action refused")
        return g.canonical({"apiVersion": "serverware.nativePilotGenesisOwnerResult/v1", "action": name,
            "observationSha256": {key: p.sha(raw) for key, raw in self._delta.items()}})

    def execute(self, *, input_fd, input_sha256, approval_fd, approval_sha256):
        p.require(not self._failed and self._keys_ready and self._ticket is not None)
        self._check(full=True)
        selected = self._selected()
        self._failed = True  # Only definite full completion clears the fence.
        try:
            approval = self._input(approval_fd, approval_sha256, 8192)
            wire.approval(approval.raw, request_raw=self._ticket, input_sha256=input_sha256)
            source = self._input(input_fd, input_sha256, selected.maximum)
            self._input_sources[selected.name] = source
            self._delta = {}
            self._clock()
            if selected.family == "owner":
                result = self._perform_owner(selected, source)
            else:
                if selected.name == "parent-precreation":
                    value = jobs.parent.input_document(source.raw)
                    wire.require_window(g.document(value["payloadOriginal"].encode("ascii"), 32768), self._window)
                prepared = jobs.run(selected.name, input_original=source.raw, prior=self._prior,
                    observations=self._observations, key_loader=self._key)
                result = prepared["result"]
                if prepared["deadline"] is not None:
                    p.require(self._clock() < prepared["deadline"])
                if prepared["epochLimit"] is not None:
                    self._epoch_limit = min(self._epoch_limit, prepared["epochLimit"])
                if selected.name == "parent-precreation":
                    wire.require_window(g.document(result, 32768)["payload"], self._window)
            p.require(type(result) is bytes and 0 < len(result) <= wire.MAX_REQUEST
                and self._bytes + len(result) <= MAX_RETAINED_BYTES)
            self._bytes += len(result)
            self._prior[selected.name] = {"input": source.raw, "result": result}
            self._previous = dict(job=selected.name, resultOriginal=result.decode("ascii"), resultSha256=p.sha(result))
            self._check(full=True)
            # Changing the index can relax startup only after the exact
            # successful coordinator release. Its own final check was still
            # within startup, not the next job's longer lifetime interval.
            self._index += 1
            self._ticket = self._ticket_value = None
            self._failed = False
        except BaseException as error:
            raise GenesisExecutionError(self, cleanup_unknown=getattr(error, "cleanup_unknown", False)) from error

    def _cleanup_owners(self):
        if self._owners_retired:
            return
        p.require(not self._cleanup_attempted)
        self._cleanup_attempted = True
        if all(owner is None for owner in (self._parent, self._ordinary, self._endpoints, self._assembly)):
            # Expired admission cannot manufacture a child that never existed.
            # This grants no operation time, signature or installation retry.
            self._origin()
            self._owners_retired = True
            return
        failures = []
        owners = (self._assembly,) if self._assembly is not None else (self._parent, self._endpoints, self._ordinary)
        for owner in owners:
            if owner is None or owner._closed:
                continue
            try:
                self._clock(cleanup=True)
                owner.close()
                p.require(owner._closed)
            except BaseException as error:
                failures.append(error)
        if failures:
            raise GenesisExecutionError(self, cleanup_unknown=True) from failures[0]
        self._clock(cleanup=True)
        self._owners_retired = True

    def finish(self):
        p.require(not self._failed and self._index == len(self._jobs) and self._owners_retired
            and self._bundle is not None and self._assembly._result == self._bundle and self._parent._reaped)
        p.require(not self._handoff or (self._core is not None and self._core.transferred))
        self._check(full=True)
        return bytes(self._bundle)

    def final_result(self):
        """Copy the actual completed last job, never derive success from input."""
        p.require(type(self) is GenesisExecution and self._handoff)
        self.finish()  # Actual transfer, retired owners and retained originals.
        last = self._jobs[-1]
        p.require(last.name == "handoff-cold-core")
        row = p.fields(self._prior[last.name], ("input", "result"))
        wire.owner_action(row["input"], last.name)
        previous = p.fields(self._previous, ("job", "resultOriginal", "resultSha256"))
        p.require(previous["job"] == last.name and previous["resultOriginal"].encode("ascii") == row["result"]
            and previous["resultSha256"] == p.sha(row["result"]))
        result = copy.deepcopy(previous)
        result["inputSha256"] = p.sha(row["input"])
        self._check(full=True)
        return result

    def close(self):
        if self._closed:
            return {"status": "closed", "coordinatorCompleted": self._bundle is not None}
        self._origin()
        p.require(not self._close_attempted)
        self._close_attempted = True
        try:
            self._cleanup_owners()
            if self._core is not None:
                self._core.close()
            if self._core_channel is not None:
                self._core_channel.close()
            if self._handoff_listener is not None:
                self._handoff_listener.close()
            with io.owning():
                while self._installers:
                    self._installers[-1].close(); self._installers.pop()
                while self._public_fds:
                    name = next(reversed(self._public_fds))
                    fd = self._public_fds.pop(name)[0]
                    os.close(fd)
                while self._keys:
                    name = next(reversed(self._keys))
                    fd = self._keys.pop(name)[0]
                    os.close(fd)
                while self._held:
                    self._held[-1].close(); self._held.pop()
                self._closed = True
            return {"status": "closed", "coordinatorCompleted": self._bundle is not None}
        except BaseException as error:
            raise GenesisExecutionError(self, cleanup_unknown=True) from error
