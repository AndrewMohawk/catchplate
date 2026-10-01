"""Single-thread retained owner of the actual two cold native endpoints.

Public originals are observations, never owner reconstruction. This owner
executes only the pinned fixed controller, retains both real descendant
PIDFDs, and never signs a release, invents grants or claims endpoint readiness.
"""
from __future__ import annotations

import os
import select
import signal
import threading
import time

from serverware import custody_generation_grants as g
from serverware import native_pilot_genesis_endpoint_profile as wire
from serverware import native_pilot_genesis_endpoint_process as process
from serverware import native_pilot_genesis_parent_authority as authority
from serverware import native_pilot_genesis_parent_control_io as io
from serverware import native_pilot_peer_resources as peers
from serverware import native_shadow_nitro_originals as originals
from serverware.native_shadow_proof_cohort_control import _Original, _process, _terminal

p = g.p
CONFIGURATION = "/etc/serverware/native-publication-genesis-endpoints.json"
_TOKEN, _LIVE, _USED = object(), None, False
RESERVE = 250_000_000


def control(raw):
    value = p.fields(g.document(raw, 4096), ("apiVersion", "controllerExecutableSha256", "configurationSha256"))
    p.require(value["apiVersion"] == wire.CONTROL_API)
    p.digest(value["controllerExecutableSha256"]); p.digest(value["configurationSha256"])
    return value


def release_original(raw, *, configuration_raw, observation_raw):
    config, observed = wire.configuration(configuration_raw), wire.observation(observation_raw)
    value = p.fields(g.document(raw, wire.MAX_WIRE), ("apiVersion", "payload", "signatureBase64url"))
    payload = p.fields(value["payload"], ("configurationSha256", "parentConfigurationSha256", "parentPrecreationSha256",
        "observationSha256", "invocationId", "signingKeyId", "services"))
    p.require(value["apiVersion"] == wire.RELEASE_API and payload["configurationSha256"] == p.sha(configuration_raw)
        and payload["observationSha256"] == p.sha(observation_raw)
        and payload["invocationId"] == observed["invocationId"]
        and payload["signingKeyId"] == config["releaseAuthority"]["keyId"])
    for name in ("parentConfigurationSha256", "parentPrecreationSha256"):
        p.require(payload[name] == config[name] == observed[name])
    for role, row in p.fields(payload["services"], wire.ROLES).items():
        p.fields(row, ("launch", "image"))
        g.c9._pin(row["launch"]); g.c9._pin(row["image"])
        p.require(g.canonical(row["image"]) == g.canonical(config["services"][role]["image"]))
    key = authority._authority(config["releaseAuthority"])
    key.verify(p.decoded(value["signatureBase64url"], size=64),
        b"serverware.signedEnvelope/v1\0" + wire.RELEASE_DOMAIN.encode("ascii")
        + b"\0serverware.canonicalJson/ascii-integer-v1\0" + g.canonical(payload))
    return payload


class EndpointControlError(ValueError):
    def __init__(self, owner, *, cleanup_unknown=False):
        super().__init__("cold endpoint owner refused; " + ("cleanup unknown, owner retained" if cleanup_unknown else "owner retained"))
        self.owner, self.cleanup_unknown = owner, cleanup_unknown


class GenesisEndpointControl:
    def __init__(self, token, coordinator):
        p.require(token is _TOKEN)
        self._coordinator = coordinator
        self._pid, self._start, self._boot = os.getpid(), originals._start(), originals._boot()
        self._last = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        self._inputs, self._named, self._images = [], [], []
        self._peers, self._cold, self._deliveries = {}, {}, {}
        self._process = self._resources = self._observation = self._preparation = None
        self._started = self._failed = self._closed = self._released = self._release_attempted = self._close_attempted = False
        self._release_raw = None

    @classmethod
    def prepare(cls, *, coordinator, control_fd, control_sha256):
        from serverware.native_pilot_genesis_parent_control import ParkedGenesisController
        global _LIVE, _USED
        p.require(cls is GenesisEndpointControl and type(coordinator) is ParkedGenesisController and _LIVE is None and not _USED)
        io.public_io._process()
        p.require(len(os.listdir("/proc/self/task")) == 1 and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL)
        observed = coordinator.observation_original()
        owner = cls(_TOKEN, coordinator)
        _LIVE, _USED = owner, True
        try:
            approved = owner._input(control_fd, 4096, control_sha256)
            selected = control(approved.raw)
            owner._control_raw = approved.raw
            owner._configuration = owner._open(CONFIGURATION, wire.MAX_WIRE, selected["configurationSha256"])
            owner._config = wire.configuration(owner._configuration.raw)
            p.require(owner._config["parentConfigurationSha256"] == p.sha(coordinator._configuration.raw)
                and owner._config["parentPrecreationSha256"] == p.sha(coordinator._precreation.raw))
            owner._parent_observation = bytes(observed)
            inherited = authority.validate_precreation(coordinator._precreation.raw,
                configuration_raw=coordinator._configuration.raw, delivery_configuration_raw=coordinator._cold.raw,
                boot=owner._boot, now_boottime_ns=owner._last)
            owner._parent_cold, owner._window = inherited["cold"], inherited["window"]
            owner._startup, owner._lifetime = (p.ns(owner._window[name]) for name in
                ("startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"))
            owner._deadline = owner._lifetime - RESERVE
            forbidden = {inherited["configuration"][name]["publicKeyBase64url"] for name in ("precreationAuthority", "releaseAuthority")}
            forbidden.add(inherited["cold"]["authority"]["publicKeyBase64url"])
            release_key = owner._config["releaseAuthority"]["publicKeyBase64url"]
            p.require(release_key not in forbidden)
            uids, gids = {owner._parent_cold["uid"]}, {owner._parent_cold["gid"]}
            for role in wire.ROLES:
                pin = owner._config["services"][role]["deliveryConfiguration"]
                original = owner._open(pin["path"], 65536, pin["sha256"])
                cold = g.c9.configuration(original.raw, pin["sha256"])
                p.require(cold["serviceRole"] == "production-bridge" and cold["uid"] not in uids and cold["gid"] not in gids
                    and cold["authority"]["publicKeyBase64url"] != release_key)
                owner._cold[role] = cold; uids.add(cold["uid"]); gids.add(cold["gid"])
            executable = owner._open(process.EXECUTABLE, io.MAX_EXECUTABLE, selected["controllerExecutableSha256"], 0o555)
            owner._process = process.Process(executable)
            owner._process.seal()
            owner._check(startup=True)
            return owner
        except BaseException as error:
            owner._failed = True
            raise EndpointControlError(owner) from error

    def _input(self, fd, maximum, digest):
        with io.owning():
            value = io.PublicInput(fd, maximum, digest); self._inputs.append(value)
        return value

    def _open(self, path, maximum, digest, mode=0o400):
        with io.owning():
            value = _Original(path, maximum, digest, mode); self._named.append(value)
        return value

    def _origin(self):
        p.require(_LIVE is self and not self._closed and os.getpid() == self._pid and originals._start() == self._start
            and originals._boot() == self._boot and threading.current_thread() is threading.main_thread()
            and len(os.listdir("/proc/self/task")) == 1 and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))

    def _clock(self, *, startup=False, cleanup=False):
        self._origin()
        now = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        deadline = self._lifetime if cleanup else min(self._deadline, self._startup) if startup else self._deadline
        p.require(self._last <= now < deadline and p.ns(self._window["issuedAtBoottimeNs"]) <= now)
        self._last = now
        return now

    def _check(self, *, startup=False, resources=True):
        self._clock(startup=startup)
        for original in self._inputs:
            original.check_identity()
        for original in self._named:
            io.original_identity(original)
        for image in self._images:
            image.check_identity()
        if self._process is not None and self._process.pid is not None:
            self._process.check()
        for peer in self._peers.values():
            peer.check()
        if resources and self._resources is not None:
            self._resources.check()
        if startup:
            p.require(self._coordinator.observation_original() == self._parent_observation)
        self._clock(startup=startup)

    def start(self):
        try:
            self._check(startup=True)
            p.require(not self._started and not self._failed)
            self._started = True
            self._process.spawn()
            self._process.send(self._control_raw, [], lambda: self._clock(startup=True))
            while True:
                self._check(startup=True)
                packet = self._process.receive(2)
                if packet is not None:
                    break
                select.select([self._process.socket, self._process.pidfd], [], [], 0.001)
            raw, rights = packet
            observed = wire.observation(raw)
            p.require(observed["configurationSha256"] == p.sha(self._configuration.raw)
                and observed["parentConfigurationSha256"] == self._config["parentConfigurationSha256"]
                and observed["parentPrecreationSha256"] == self._config["parentPrecreationSha256"]
                and observed["invocationId"] == self._window["invocationId"])
            self._observation = bytes(raw)
            for role, fd in zip(wire.ROLES, rights, strict=True):
                row = observed["services"][role]
                info = os.fstat(fd)
                p.require(io.pidfd_pid(fd) == row["processId"] and not _terminal(fd)
                    and _process(row["processId"]) == (self._process.pid, row["startTimeTicks"])
                    and (info.st_dev, info.st_ino) == (row["pidfdDevice"], row["pidfdInode"])
                    and row["executable"]["sha256"] == self._config["services"][role]["executableSha256"])
                with io.owning():
                    self._peers[role] = peers._Peer(peers._TOKEN, pidfd=fd, pid=row["processId"], start=row["startTimeTicks"],
                        parent=self._process.pid, executable_fd=None, expected=row["executable"], kind="native-endpoints",
                        check=lambda: self._clock(startup=True))
            value = {"apiVersion": wire.PREPARATION_API, "configurationSha256": p.sha(self._configuration.raw),
                "parentConfigurationSha256": self._config["parentConfigurationSha256"],
                "parentPrecreationSha256": self._config["parentPrecreationSha256"],
                "observationOriginal": raw.decode("ascii"), **{name: self._window[name] for name in wire.WINDOW},
                "observedAtBoottimeNs": str(self._clock(startup=True)),
                "services": {role: self._peers[role].value for role in wire.ROLES}}
            self._preparation = g.canonical(value); wire.preparation(self._preparation)
            self._check(startup=True)
            return bytes(self._preparation)
        except BaseException as error:
            self._failed = True
            raise EndpointControlError(self) from error

    def preparation_original(self):
        self._check(startup=True)
        p.require(self._preparation is not None and not self._released and not self._failed)
        return bytes(self._preparation)

    def prepare_resources(self):
        from serverware.native_pilot_genesis_endpoint_resources import Resources
        try:
            self.preparation_original()
            p.require(self._resources is None)
            return Resources.prepare(self)
        except BaseException as error:
            self._failed = True
            raise EndpointControlError(self) from error

    def admit_delivery(self, role, *, input_fd, input_sha256, delivery_fd, delivery_sha256):
        from serverware import native_pilot_genesis_delivery_authority as delivery
        try:
            self._check(startup=True)
            p.require(role in wire.ROLES and role not in self._deliveries and not self._release_attempted and not self._failed)
            source = self._input(input_fd, delivery.MAX_INPUT, input_sha256)
            signed = self._input(delivery_fd, 65536, delivery_sha256)
            value = delivery.input_document(source.raw)
            p.require(value["ownerConfigurationOriginal"].encode("ascii") == self._configuration.raw
                and value["preparationOriginal"].encode("ascii") == self._preparation
                and value["resourcesOriginal"].encode("ascii") == self._resources.raw)
            parent = self._coordinator
            expected = (parent._configuration.raw, parent._cold.raw, parent._precreation.raw, self._parent_observation)
            p.require(tuple(value["parentOriginals"][name].encode("ascii") for name in delivery.PARENTS) == expected)
            context = delivery.verified_delivery(role, source.raw, signed.raw, boot=self._boot, now_boottime_ns=self._clock(startup=True))
            self._deliveries[role] = {"context": context, "raw": signed.raw, "input": source.raw}
            self._check(startup=True)
            return bytes(signed.raw)
        except BaseException as error:
            self._failed = True
            raise EndpointControlError(self) from error

    def _status(self, suffix):
        return {"apiVersion": "serverware.nativePublicationGenesisEndpoints" + suffix + "/v1",
            "configurationSha256": p.sha(self._configuration.raw), "observationSha256": p.sha(self._observation),
            "releaseSha256": None if self._release_raw is None else p.sha(self._release_raw)}

    def release(self, *, release_fd, release_sha256):
        from serverware import native_pilot_genesis_coordinator_peer as coordinator_peer
        try:
            self._check(startup=True)
            p.require(not self._release_attempted and not self._failed and set(self._deliveries) == set(wire.ROLES)
                and self._resources.genesis is not None)
            self._release_attempted = True
            original = self._input(release_fd, wire.MAX_WIRE, release_sha256)
            self._release_raw = original.raw
            payload = release_original(original.raw, configuration_raw=self._configuration.raw, observation_raw=self._observation)
            for role in wire.ROLES:
                pins = payload["services"][role]
                launch = self._open(pins["launch"]["path"], wire.MAX_WIRE, pins["launch"]["sha256"])
                selected = g.document(launch.raw, wire.MAX_WIRE)
                key = "retrieval" if role == wire.ROLES[0] else "publication"
                api = "serverware.nativeShadowPublicationGenesis" + ("Retrieval" if role == wire.ROLES[0] else "") + "GuestLaunch/v1"
                p.fields(selected, ("apiVersion", "keyAdmission", key))
                p.require(selected["apiVersion"] == api)
                admission = selected["keyAdmission"]
                p.require(g.canonical(admission["deliveryConfiguration"]) == g.canonical(self._config["services"][role]["deliveryConfiguration"])
                    and admission["delivery"]["sha256"] == p.sha(self._deliveries[role]["raw"]))
                c9 = self._open(admission["delivery"]["path"], 65536, admission["delivery"]["sha256"])
                p.require(c9.raw == self._deliveries[role]["raw"])
                grant_pin = selected[key]; g.c9._pin(grant_pin)
                grant = self._open(grant_pin["path"], 4 * 1024 * 1024 if key == "publication" else 65536, grant_pin["sha256"])
                grant_value = g.document(grant.raw, 4 * 1024 * 1024)
                scope = grant_value["payload"]["scope"]
                parent = self._coordinator
                coordinator_peer.expected_peer(parent.peer_preparation_original(), approved=grant_value["payload"]["expectedPeer"],
                    observation_raw=parent.observation_original(), configuration_raw=parent._configuration.raw,
                    precreation_raw=parent._precreation.raw, delivery_configuration_raw=parent._cold.raw,
                    boot=self._boot, now_boottime_ns=self._clock(startup=True))
                now = self._clock(startup=True)
                p.require(p.integer(scope["issuedAtBoottimeNanos"], maximum=p.MAX_U64) <= now
                    < p.integer(scope["expiresAtBoottimeNanos"], maximum=p.MAX_U64))
                self._deadline = min(self._deadline, scope["expiresAtBoottimeNanos"] - RESERVE)
                with io.owning():
                    self._images.append(io.ImageOriginal(pins["image"]["path"], pins["image"]["sha256"]))
            self._check(startup=True)
            rights = [fd for role in wire.ROLES for _, fd in self._resources.roles[role]["descriptors"]]
            # The native gate may have released one child before failing the
            # second, including if cancellation lands after a positive send.
            # Never retain the pre-release empty-directory assumption.
            self._resources.released = True
            self._process.send(original.raw, rights, lambda: self._check(startup=True))
            while True:
                self._check()
                packet = self._process.receive(0)
                if packet is not None:
                    p.require(packet[0] == g.canonical(self._status("Released")))
                    self._released = True
                    self._check()
                    return None
                select.select([self._process.socket, self._process.pidfd], [], [], 0.001)
        except BaseException as error:
            self._failed = True
            raise EndpointControlError(self) from error

    def poll(self):
        self._check()
        p.require(self._released and not self._failed and not self._close_attempted)
        return {"status": "released", "ready": False}  # No service-admission observation is fabricated.

    def close(self):
        if self._closed:
            return {"status": "closed"}
        self._origin()
        p.require(not self._close_attempted)
        self._close_attempted = True
        try:
            successful = False
            if self._process is not None and self._process.pid is not None and not self._process.reaped:
                if not self._failed and self._observation is not None:
                    self._process.send(g.canonical(self._status("Stop")), [], lambda: self._clock(cleanup=True))
                    while True:
                        self._clock(cleanup=True)
                        packet = self._process.receive(0, terminal=True)
                        if packet is not None:
                            p.require(packet[0] == g.canonical(self._status("Stopped")))
                            successful = True; break
                        self._process.check(terminal=True)
                        select.select([self._process.socket, self._process.pidfd], [], [], 0.001)
                self._process.retire(lambda: self._clock(cleanup=True),
                    self._process.child_rights + [peer.pidfd for peer in self._peers.values()], successful=successful)
            with io.owning():
                for peer in self._peers.values():
                    peer.close()
                if self._resources is not None:
                    self._resources.close_after_reap()
                if self._process is not None:
                    self._process.close_after_reap()
                for original in [*self._inputs, *self._named, *self._images]:
                    original.close()
                self._closed = True
            return {"status": "closed", "released": self._released}
        except BaseException as error:
            raise EndpointControlError(self, cleanup_unknown=True) from error
