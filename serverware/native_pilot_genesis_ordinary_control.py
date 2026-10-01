"""Retained two-service cold preparation and one-shot inspected C9 release.

Only actual owned children/resources produce observations. This owner signs
nothing, has no parent watcher thread, and preserves the coordinator's original
signed window. A listening notice is not constructed readiness. Retirement
requires a request-bound native helper-reap notice and consuming same-service
PIDFD wait; neither alone is cleanup proof. An error service result can retire
resources without implying any successful business operation.
"""
from __future__ import annotations

import array
import copy
import fcntl
import os
import select
import signal
import socket
import stat
import threading

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware import custody_generation_grants as g
from serverware import custody_generation_measurements as measurements
from serverware import custody_generation_originals as o
from serverware import native_pilot_genesis_parent_authority as parent_authority
from serverware import native_pilot_genesis_parent_control_io as io
from serverware import native_pilot_genesis_ordinary_control_process as process
from serverware import native_pilot_genesis_ordinary_resources as resources
from serverware import native_pilot_genesis_ordinary_retirement as retirement
from serverware.native_shadow_proof_cohort_control import _Original

p = g.p
ROLES = resources.ROLES
CONFIGURATION = "/etc/serverware/custody-genesis-two.json"
CONTROL_API = "serverware.custodyGenesisTwoServiceControl/v1"
LAUNCH_API = "serverware.custodyGenesisTwoServiceLaunch/v1"
PREPARATION_API = "serverware.custodyGenesisTwoServicePreparation/v1"
LAUNCH_FIELDS = ("apiVersion", "bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode",
    "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId", "services")
_TOKEN, _LIVE, _USED = object(), None, False


def _control(raw):
    value = p.fields(g.document(raw, 4096), ("apiVersion", "launchConfigurationSha256",
        "parentConfigurationSha256", "parentPrecreationSha256"))
    p.require(value["apiVersion"] == CONTROL_API)
    for name in ("launchConfigurationSha256", "parentConfigurationSha256", "parentPrecreationSha256"):
        p.digest(value[name])
    return value


def _launch(raw, window):
    value = p.fields(g.document(raw, 65536), LAUNCH_FIELDS)
    p.require(value["apiVersion"] == LAUNCH_API)
    for name in LAUNCH_FIELDS[1:-1]:
        p.require(type(value[name]) is type(window[name]) and value[name] == window[name])
    p.fields(value["services"], ROLES)
    for row in value["services"].values():
        p.fields(row, ("executableSha256", "deliveryConfiguration"))
        p.digest(row["executableSha256"])
        g.c9._pin(row["deliveryConfiguration"])
    return value


def _native_launch(raw, role):
    p.require(role in ROLES)
    value = p.fields(g.document(raw, 32768), ("apiVersion", "deliveryConfiguration", "delivery",
        "peerInspectionCredential"))
    p.require(value["apiVersion"] == "serverware.custodyOrdinaryServiceGuestLaunch/v7"
        and value["peerInspectionCredential"] == "peer-inspection-policy")
    g.c9._pin(value["deliveryConfiguration"])
    g.c9._pin(value["delivery"])
    return value


class GenesisOrdinaryError(ValueError):
    def __init__(self, owner, *, cleanup_unknown=False):
        super().__init__("cold ordinary services refused; " +
            ("cleanup unknown, actual owner retained" if cleanup_unknown else "actual owner retained for cleanup"))
        self.owner, self.cleanup_unknown = owner, cleanup_unknown


class GenesisOrdinaryControl:
    def __init__(self, token, coordinator):
        p.require(token is _TOKEN)
        self._coordinator = coordinator
        self._pid, self._start, self._boot = os.getpid(), o.native._start(), o.native._boot()
        self._last = o.clock()
        self._originals, self._role_originals, self._inputs, self._received = [], [], [], []
        self._roles, self._children = {}, {}
        self._resources = self._preparation = self._preparation_value = None
        self._closed = self._failed = self._release_attempted = self._released = self._close_attempted = False
        self._native_may_run = False

    @classmethod
    def prepare(cls, *, coordinator, control_fd, control_sha256):
        from serverware.native_pilot_genesis_parent_control import ParkedGenesisController, CONFIGURATION as PARENT, PRECREATION
        global _LIVE, _USED
        p.require(cls is GenesisOrdinaryControl and _LIVE is None and not _USED
            and type(coordinator) is ParkedGenesisController)
        io.public_io._process()
        p.require(len(os.listdir("/proc/self/task")) == 1 and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL)
        observation = coordinator.observation_original()
        owner = cls(_TOKEN, coordinator)
        _LIVE, _USED = owner, True
        try:
            control = _control(owner._input(control_fd, 4096, control_sha256).raw)
            config = owner._open(PARENT, 32768, control["parentConfigurationSha256"])
            precreation = owner._open(PRECREATION, 32768, control["parentPrecreationSha256"])
            p.require(config.raw == coordinator._configuration.raw and precreation.raw == coordinator._precreation.raw)
            pin = g.document(config.raw, 32768)["deliveryConfiguration"]
            g.c9._pin(pin)
            cold = owner._open(pin["path"], 65536, pin["sha256"])
            owner._parent_configuration, owner._parent_precreation, owner._parent_cold = config, precreation, cold
            context = parent_authority.validate_precreation(precreation.raw, configuration_raw=config.raw,
                delivery_configuration_raw=cold.raw, boot=owner._boot, now_boottime_ns=owner._last)
            parent_authority.validate_observation(observation, configuration_raw=config.raw,
                precreation_raw=precreation.raw, context=context)
            owner._coordinator_cold_value = context["cold"]
            owner._window = context["window"]
            owner._issued, owner._startup, owner._lifetime = (p.ns(owner._window[name]) for name in
                ("issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"))
            owner._invocation = owner._window["invocationId"]
            owner._release_deadline, owner._release_not_before = context["deadline"], owner._issued
            owner._configuration = owner._open(CONFIGURATION, 65536, control["launchConfigurationSha256"])
            owner._launch = _launch(owner._configuration.raw, owner._window)
            uids, gids, inodes = {context["cold"]["uid"]}, {context["cold"]["gid"]}, set()
            # Complete independently pinned executable/config inventory first.
            for role in ROLES:
                spec = owner._launch["services"][role]
                pin = spec["deliveryConfiguration"]
                original = owner._open(pin["path"], 65536, pin["sha256"])
                selected = g.configuration(original.raw, pin["sha256"], role)
                p.require(selected["uid"] not in uids and selected["gid"] not in gids)
                uids.add(selected["uid"])
                gids.add(selected["gid"])
                executable = owner._open("/usr/local/bin/serverware-policy-custody-" + role,
                    io.MAX_EXECUTABLE, spec["executableSha256"], 0o755)
                io.require_static_elf(executable.raw)
                info = os.fstat(executable.fd)
                p.require((info.st_dev, info.st_ino) not in inodes)
                inodes.add((info.st_dev, info.st_ino))
                target = dict(device=info.st_dev, inode=info.st_ino, length=info.st_size,
                    sha256=spec["executableSha256"], imaSha256=measurements._ima(executable.fd),
                    fsVeritySha256=measurements._verity(executable.fd))
                owner._roles[role] = dict(configuration=original, cold=selected, executable=executable, target=target)
            for role in ROLES:
                owner._spawn(role)
            owner._check(startup=True)
            resources.GenesisOrdinaryResources._prepare(owner)
            owner.preparation_original()
            owner.resources_original()
            return owner
        except BaseException as error:
            owner._failed = True
            raise GenesisOrdinaryError(owner) from error

    def _input(self, fd, maximum, digest):
        with io.owning():
            item = io.PublicInput(fd, maximum, digest)
            self._inputs.append(item)
        return item

    def _open(self, path, maximum, digest, mode=0o400):
        with io.owning():
            item = _Original(path, maximum, digest, mode)
            self._originals.append(item)
        return item

    def _role_open(self, path, maximum, role, *, digest=None):
        cold = self._roles[role]["cold"]
        with io.owning():
            item = o.Original(path, maximum, uid=cold["uid"], gid=cold["gid"], sha=digest)
            self._role_originals.append(item)
        return item

    def _origin(self):
        p.require(not self._closed and threading.current_thread() is threading.main_thread()
            and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0)
            and os.getpid() == self._pid and o.native._start() == self._start and o.native._boot() == self._boot)

    def _clock(self, *, startup):
        self._origin()
        now = o.clock()
        p.require(self._issued <= self._last <= now < (self._startup if startup else self._lifetime))
        self._last = now
        return now

    def _sources(self):
        for original in self._originals:
            io.original_identity(original)
        for item in self._inputs:
            item.check_identity()
        for item in self._role_originals:
            item.check()
            parent, name = item.path.rsplit("/", 1)
            fd = o.directory(parent, item.expected[3])
            try:
                p.require(o.identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) == item.expected)
            finally:
                os.close(fd)

    def _check(self, *, startup=False, resources=True):
        p.require(not self._failed)
        before_constructed = startup or any(item["phase"] != "constructed" for item in self._children.values())
        self._clock(startup=before_constructed)
        self._sources()
        for item in self._children.values():
            p.require(item["pidfd"] is not None and not item["reaped"])
            p.require(o.structural(os.fstat(item["pidfd"])) == item["pidfd_identity"]
                and o.structural(os.fstat(item["channel"].fileno())) == item["channel_identity"])
            o.live(item["pidfd"], item["pid"], item["start"], self._pid)
        if resources and self._resources is not None:
            self._resources.check()
        self._clock(startup=before_constructed)

    def _release_clock(self):
        now = self._clock(startup=True)
        p.require(self._release_not_before <= now < self._release_deadline)
        return now

    def _spawn(self, role):
        self._clock(startup=True)
        p.require(len(os.listdir("/proc/self/task")) == 1)
        item = dict(pid=None, pidfd=None, start=None, channel=None, phase="parked", reaped=False,
            stop_raw=None, stop_sent=False, terminal=None, reap_result=None, forced=False)
        self._children[role] = item
        child = None
        try:
            with io.owning():
                parent, child = socket.socketpair(socket.AF_UNIX,
                    socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK)
                item["channel"] = parent
                item["channel_identity"] = o.structural(os.fstat(parent.fileno()))
                for value in (parent, child):
                    value.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                pid = os.fork()
                if pid == 0:
                    process.park(child, self._roles[role]["executable"].fd, self._pid, role, self._startup)
                    os._exit(1)
                item["pid"] = pid
                item["pidfd"] = os.pidfd_open(pid, 0)
                item["pidfd_identity"] = o.structural(os.fstat(item["pidfd"]))
                item["start"] = o.process(pid)[1]
            child.close()
            child = None
            while True:
                self._clock(startup=True)
                o.live(item["pidfd"], pid, item["start"], self._pid)
                packet = process.packet(parent, 0, self._received)
                if packet is not None:
                    raw, _, credentials = packet
                    p.require(raw == process.PARKED and credentials == (pid, 0, 0))
                    return
                select.select([parent, item["pidfd"]], [], [], 0.01)
        finally:
            if child is not None:
                child.close()

    def preparation_original(self):
        self._check(startup=True)
        p.require(not self._release_attempted and tuple(self._children) == ROLES)
        self._coordinator.observation_original()
        services = {}
        for role in ROLES:
            item, child = self._roles[role], self._children[role]
            target = item["target"]
            p.require(measurements._ima(item["executable"].fd) == target["imaSha256"]
                and measurements._verity(item["executable"].fd) == target["fsVeritySha256"])
            services[role] = dict(configurationSha256=p.sha(item["configuration"].raw),
                plannedUid=item["cold"]["uid"], plannedGid=item["cold"]["gid"],
                processId=child["pid"], startTimeTicks=child["start"],
                pidfdStat=measurements._pidfd(child["pidfd"]), targetExecutable=dict(target))
        value = {"apiVersion": PREPARATION_API, "phase": "parked-pre-exec",
            "configurationSha256": p.sha(self._configuration.raw), **{name: self._window[name]
                for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode", "issuedAtBoottimeNs",
                    "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId")}, "services": services}
        raw = g.canonical(value)
        p.require(len(raw) <= 65536)
        if self._preparation is None:
            self._preparation, self._preparation_value = raw, value
        p.require(raw == self._preparation)
        self._check(startup=True)
        return raw

    def resources_original(self):
        preparation = self.preparation_original()
        raw = self._resources.original(preparation)
        self._check(startup=True)
        return raw

    def activation(self, role):
        self._check(startup=True)
        p.require(role in ROLES and not self._release_attempted)
        return copy.deepcopy(self._resources.roles[role]["activation"])

    def runtime_inputs(self, role):
        self._check(startup=True)
        p.require(role in ROLES and not self._release_attempted)
        row = self._resources.roles[role]
        return dict(listenerSocketPath=row["path"], activationDirectoryIdentities=copy.deepcopy(row["directory_identities"]))

    def release(self, *, inputs):
        """One exact two-role release, after all actual public input validation.

        Each row is {launch:{path,sha256},grant:{fd,sha256}}. Caller-installed
        launch/C9/runtime/credentials are retained originals, never templates.
        Native entry independently authenticates all grant/history/key facts.
        """
        from serverware import native_pilot_genesis_ordinary_authority as authority
        from serverware import native_pilot_genesis_ordinary_initial_authority as initial_authority
        from serverware import native_pilot_genesis_ordinary_initial_profile as initial
        from serverware import native_pilot_genesis_coordinator_peer as coordinator_peer
        try:
            self._check(startup=True)
            p.require(not self._release_attempted)
            self._release_attempted = True  # Failure consumes the only attempt.
            p.fields(inputs, ROLES)
            grants = {}
            for role in ROLES:
                row = p.fields(inputs[role], ("launch", "grant"))
                g.c9._pin(row["launch"])
                p.require(row["launch"]["path"] == "/etc/serverware/custody-" + role + "-guest.json")
                launch = self._open(row["launch"]["path"], 32768, row["launch"]["sha256"])
                selected = _native_launch(launch.raw, role)
                item = self._roles[role]
                p.require(selected["deliveryConfiguration"] == self._launch["services"][role]["deliveryConfiguration"])
                delivery = self._open(selected["delivery"]["path"], 65536, selected["delivery"]["sha256"])
                envelope = p.fields(g.document(delivery.raw, 65536), ("apiVersion", "payload", "signatureBase64url"))
                p.require(envelope["apiVersion"] == "serverware.policyCustodyGuestDelivery/v1")
                payload = p.fields(envelope["payload"], g.c9.FIELDS)
                # Authenticate selected C9 before following its runtime or
                # credential paths, including unopened private key originals.
                Ed25519PublicKey.from_public_bytes(p.decoded(item["cold"]["authority"]["publicKeyBase64url"], size=32)).verify(
                    p.decoded(envelope["signatureBase64url"], size=64), g.c9.DOMAIN + g.canonical(payload))
                p.require(payload["configurationSha256"] == p.sha(item["configuration"].raw)
                    and payload["authorityKeyId"] == item["cold"]["authority"]["keyId"]
                    and all(payload[name] == item["cold"][name] for name in ("serviceRole", "uid", "gid")))
                p.require(all(payload[name] == self._window[name] for name in ("bootIdBase64url", "timeNamespaceDevice",
                    "timeNamespaceInode", "issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId")))
                p.require(type(payload["credentials"]) is list and 1 <= len(payload["credentials"]) <= 64)
                runtime_pin = payload["runtimeConfig"]
                g.c9._pin(runtime_pin)
                # Native C9 admits its public runtime as root:root 0400;
                # only credential originals belong to the final service role.
                runtime = self._open(runtime_pin["path"], g.MAX_BYTES, runtime_pin["sha256"])
                originals, total = {}, 0
                for credential in payload["credentials"]:
                    p.fields(credential, ("name", "original", "length", "signing"))
                    g.c9._pin(credential["original"])
                    maximum = p.integer(credential["length"], maximum=g.MAX_BYTES)
                    total += maximum
                    p.require(total <= 16 * 1024 * 1024)
                    p.require(credential["name"] not in originals)
                    # Private seeds remain unread; the native owner verifies
                    # their signed hash, assigned key and actual possession.
                    original = self._role_open(credential["original"]["path"], maximum, role)
                    p.require(original.expected[6] == maximum)
                    originals[credential["name"]] = original
                history_raw = originals["authority-history"].read()
                runtime_raw = runtime.raw
                checked = authority.verify_delivery(signed_raw=delivery.raw,
                    configuration_raw=item["configuration"].raw, runtime_raw=runtime_raw,
                    history_raw=history_raw, activation=self._resources.roles[role]["activation"],
                    boot=self._boot, now_boottime_ns=self._clock(startup=True))
                history_value = g.document(history_raw, g.MAX_BYTES)
                checkpoint = history_value["initialCheckpoint"]["payload"]
                self._release_deadline = min(self._release_deadline,
                    checkpoint["validUntilBoottime"]["absoluteBoottimeNanos"])
                self._release_not_before = max(self._release_not_before,
                    checkpoint["validFromBoottime"]["absoluteBoottimeNanos"])
                self._release_clock()
                history_identity = checked["history"]["firstRetainedEpoch"]["retainedEpoch"]["endpointProcessIdentity"]
                source = initial_authority.source_context(parent_configuration_raw=self._parent_configuration.raw,
                    parent_delivery_configuration_raw=self._parent_cold.raw, parent_precreation_raw=self._parent_precreation.raw,
                    parent_observation_raw=self._coordinator.observation_original(), launch_raw=self._configuration.raw,
                    preparation_raw=self._preparation, resources_raw=self._resources.raw, configuration_raw=item["configuration"].raw,
                    role=role, endpoint_role=history_identity["endpointRole"], boot=self._boot,
                    now_boottime_ns=self._clock(startup=True))
                initial.same(source["identity"], history_identity)
                state = history_value["initialState"]
                p.require(state["preparationSha256"] == p.sha(self._preparation)
                    and state["resourcesSha256"] == p.sha(self._resources.raw)
                    and state["launchSha256"] == p.sha(self._configuration.raw))
                p.require(all(payload[name] == self._window[name] for name in ("issuedAtBoottimeNs",
                    "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId")))
                header = checked["header"]
                actual = self.runtime_inputs_for_release(role)
                p.require(header["listenerSocketPath"] == actual["listenerSocketPath"]
                    and header["activationDirectoryIdentities"] == actual["activationDirectoryIdentities"])
                coordinator_peer.expected_peer(self._coordinator.peer_preparation_original(), approved=header["expectedPeer"],
                    observation_raw=self._coordinator.observation_original(), configuration_raw=self._parent_configuration.raw,
                    precreation_raw=self._parent_precreation.raw, delivery_configuration_raw=self._parent_cold.raw,
                    boot=self._boot, now_boottime_ns=self._clock(startup=True))
                policy_raw = originals["peer-inspection-policy"].read()
                expected_policy = {"apiVersion": "serverware.custodyOrdinaryPeerInspection/v1",
                    "purpose": "ordinary-service-peer-inspection", "runtimeConfigurationSha256": runtime_pin["sha256"],
                    "serviceRole": role, "uid": item["cold"]["uid"], "gid": item["cold"]["gid"],
                    "startupDeadlineBoottimeNs": str(self._startup), "lifetimeDeadlineBoottimeNs": str(self._lifetime)}
                metadata = next(value for value in payload["credentials"] if value["name"] == "peer-inspection-policy")
                p.require(metadata["signing"] is None and metadata["length"] <= 4096
                    and p.sha(policy_raw) == metadata["original"]["sha256"]
                    and g.document(policy_raw, 4096) == expected_policy)
                grant = p.fields(row["grant"], ("fd", "sha256"))
                raw = self._input(grant["fd"], resources.MAX_GRANT, grant["sha256"]).raw
                authority.verify_grant(raw, item=checked)
                scope = g.document(raw, resources.MAX_GRANT)["payload"]["scope"]
                self._release_deadline = min(self._release_deadline, scope["expiresAtBoottimeNanos"])
                self._release_not_before = max(self._release_not_before, scope["issuedAtBoottimeNanos"])
                self._release_clock()
                grants[role] = raw
                item.update(launch=launch, delivery=delivery, checked=checked)
            first, second = (g.document(grants[role], resources.MAX_GRANT)["payload"] for role in ROLES)
            for name in ("scope", "native", "retrieval", "durableAuthorityEpoch", "durablePublicKeyBase64url",
                    "currentAuthorityEpoch", "currentPublicKeyBase64url"):
                initial.same(first[name], second[name])
            self._resources.seal(grants)
            self._check(startup=True)
            self._release_clock()
            self._resources.released = True
            self._native_may_run = True
            for role in ROLES:
                child, item = self._children[role], self._roles[role]
                child["phase"] = "released"
                child["notice"] = dict(apiVersion="serverware.policyCustodyGuestStartup/v1",
                    deliverySha256=p.sha(item["delivery"].raw), serviceRole=role,
                    invocationId=self._invocation, phase="constructed")
                fds = array.array("i", [item["launch"].fd,
                    *(fd for _, fd in self._resources.roles[role]["descriptors"])])
                self._check(startup=True)
                self._release_clock()
                p.require(child["channel"].sendmsg([process.RELEASE], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)]) == len(process.RELEASE))
            self._released = True
        except BaseException as error:
            self._failed = True
            raise GenesisOrdinaryError(self) from error

    def runtime_inputs_for_release(self, role):
        self._check(startup=True)
        row = self._resources.roles[role]
        return dict(listenerSocketPath=row["path"], activationDirectoryIdentities=row["directory_identities"])

    def poll(self):
        try:
            self._check()
            p.require(self._released)
            for role, child in self._children.items():
                packet = process.packet(child["channel"], 0, self._received)
                if packet is None:
                    continue
                raw, _, credentials = packet
                cold = self._roles[role]["cold"]
                p.require(credentials == (child["pid"], cold["uid"], cold["gid"]))
                expected = dict(child["notice"])
                if child["phase"] == "released":
                    expected.update(apiVersion="serverware.custodyOrdinaryListening/v1", phase="final-role-listening")
                    next_phase = "listening"
                else:
                    p.require(child["phase"] == "listening")
                    next_phase = "constructed"
                p.require(g.document(raw, 4096) == expected)
                child["phase"] = next_phase
            self._check()
            return {role: item["phase"] for role, item in self._children.items()}
        except BaseException as error:
            self._failed = True
            raise GenesisOrdinaryError(self) from error

    def listening(self):
        return all(value in ("listening", "constructed") for value in self.poll().values())

    def constructed(self):
        return all(value == "constructed" for value in self.poll().values())

    def _retained_child(self, item):
        """Same unreaped child, including a zombie with its final packet queued.

        This uses the already retained PIDFD plus packet SCM_CREDENTIALS, not
        per-packet SCM_PIDFD. An unreaped direct child's PID cannot be reused.
        """
        p.require(item["pidfd"] is not None and not item["reaped"]
            and o.structural(os.fstat(item["pidfd"])) == item["pidfd_identity"]
            and io.pidfd_pid(item["pidfd"]) == item["pid"])
        channel = item["channel"]
        p.require(o.structural(os.fstat(channel.fileno())) == item["channel_identity"]
            and channel.family == socket.AF_UNIX and channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_SEQPACKET
            and channel.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 1
            and fcntl.fcntl(channel.fileno(), fcntl.F_GETFL) & os.O_NONBLOCK)
        fd = os.open("/proc/" + str(item["pid"]) + "/stat", o.FLAGS)
        try:
            raw = os.read(fd, 16385)
            p.require(0 < len(raw) <= 16384)
        finally:
            os.close(fd)
        tail = raw.rsplit(b") ", 1)[1].split()
        p.require(len(tail) >= 20 and int(tail[1]) == self._pid and int(tail[19]) == item["start"])

    def _retirement_check(self):
        self._clock(startup=False)
        self._sources()
        for item in self._children.values():
            if not item["reaped"]:
                self._retained_child(item)
        if self._resources is not None:
            self._resources.check()
        return self._clock(startup=False)

    def _stop_services(self):
        p.require(not self._failed and self._released and tuple(self._children) == ROLES
            and all(item["phase"] == "constructed" for item in self._children.values()))
        self._retirement_check()
        for role, item in self._children.items():
            p.require(item["stop_raw"] is None and not item["forced"])
            raw = retirement.stop_original(delivery_sha256=p.sha(self._roles[role]["delivery"].raw),
                role=role, invocation=self._invocation, deadline=self._lifetime)
            self._retained_child(item)
            with io.owning():
                # Even a failed/uncertain send consumes this attempt. No retry
                # or new deadline is authorized by a writable channel.
                item["stop_raw"], item["stop_sent_at"] = raw, self._clock(startup=False)
                count = item["channel"].send(raw)
                item["stop_sent"] = count == len(raw)
                p.require(item["stop_sent"])
            self._retirement_check()

    def _reap_services(self):
        while True:
            self._retirement_check()
            for role, item in self._children.items():
                if item["reaped"]:
                    continue
                self._retained_child(item)
                if item["terminal"] is None:
                    packet = process.packet(item["channel"], 0, self._received)
                    if packet is None:
                        continue
                    raw, _, credentials = packet
                    cold = self._roles[role]["cold"]
                    p.require(item["stop_sent"] and credentials == (item["pid"], cold["uid"], cold["gid"]))
                    self._retained_child(item)
                    now = self._clock(startup=False)
                    item["terminal"] = retirement.terminal(raw, stop_raw=item["stop_raw"],
                        stop_sent_at=item["stop_sent_at"], now=now, service_pid=item["pid"])
                    item["terminal_raw"] = raw
                self._retained_child(item)
                self._clock(startup=False)
                with io.owning():
                    result = os.waitid(os.P_PIDFD, item["pidfd"], os.WEXITED | os.WNOHANG)
                    if result is not None:
                        # Retain consumed kernel evidence before restoring the
                        # signal mask, even if status validation will refuse.
                        item["reap_result"], item["reaped"] = result, True
                if result is not None:
                    retirement.require_reap(result, pid=item["pid"], uid=self._roles[role]["cold"]["uid"],
                        status=item["terminal"]["serviceExitStatus"])
                    item["retired"] = True
                self._clock(startup=False)
            if all(item.get("retired") is True for item in self._children.values()):
                self._retirement_check()
                return
            pending = [item for item in self._children.values() if not item["reaped"]]
            now = self._clock(startup=False)
            select.select([fd for item in pending for fd in (item["channel"], item["pidfd"])], [], [],
                min(0.01, (self._lifetime - now) / 1_000_000_000))

    def _abort_children(self):
        """Bounded safety stop only. It can never certify helper retirement."""
        for item in self._children.values():
            try:
                self._clock(startup=False)
                if item["pid"] is None or item["reaped"]:
                    continue
                if item["pidfd"] is None:
                    # Actual fork return only; no numeric-PID signal fallback.
                    p.require(o.structural(os.fstat(item["channel"].fileno())) == item["channel_identity"])
                    item["channel"].shutdown(socket.SHUT_RDWR)
                else:
                    self._retained_child(item)
                    with io.owning():
                        item["forced"] = True
                        try:
                            signal.pidfd_send_signal(item["pidfd"], signal.SIGKILL)
                        except ProcessLookupError:
                            pass
            except BaseException:
                pass
        while any(item["pid"] is not None and not item["reaped"] for item in self._children.values()):
            try:
                self._clock(startup=False)
                for item in self._children.values():
                    if item["pid"] is None or item["reaped"]:
                        continue
                    with io.owning():
                        if item["pidfd"] is None:
                            pid, status = os.waitpid(item["pid"], os.WNOHANG)
                            if pid == item["pid"]:
                                item["reap_result"], item["reaped"] = (pid, status), True
                        else:
                            self._retained_child(item)
                            result = os.waitid(os.P_PIDFD, item["pidfd"], os.WEXITED | os.WNOHANG)
                            if result is not None:
                                item["reap_result"], item["reaped"] = result, True
                now = self._clock(startup=False)
                pending = [item for item in self._children.values() if item["pid"] is not None and not item["reaped"]]
                if not pending:
                    return
                select.select([item["pidfd"] for item in pending if item["pidfd"] is not None], [], [],
                    min(0.001, (self._lifetime - now) / 1_000_000_000))
            except BaseException:
                return

    def close(self):
        global _LIVE
        if self._closed:
            return
        self._origin()
        p.require(not self._close_attempted)
        self._close_attempted = True
        try:
            if self._native_may_run:
                self._stop_services()
                self._reap_services()
                self._retirement_check()
            else:
                # No release can have reached exec or created a native helper.
                # Actual parked-child reap is sufficient only in this branch.
                self._abort_children()
                p.require(all(item["pid"] is None or item["reaped"] for item in self._children.values()))
                if self._children:
                    self._clock(startup=False)
            with io.owning():
                self._native_may_run = False
                if self._resources is not None:
                    self._resources.close_after_reap()
                for item in self._children.values():
                    if item["channel"] is not None:
                        item["channel"].close()
                    if item["pidfd"] is not None:
                        os.close(item["pidfd"])
                        item["pidfd"] = None
                while self._received:
                    os.close(self._received[-1])
                    self._received.pop()
                for item in reversed(self._role_originals):
                    item.close()
                for item in reversed(self._originals):
                    item.close()
                for item in self._inputs:
                    item.close()
                if self._children:
                    self._clock(startup=False)
                self._closed = True
                _LIVE = None
        except BaseException as error:
            self._failed = True
            self._abort_children()
            raise GenesisOrdinaryError(self, cleanup_unknown=True) from error
