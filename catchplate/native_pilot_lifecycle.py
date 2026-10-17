"""Staged, retained cold-to-adopted commissioning ownership.

This module neither composes nor approves operator decisions. Literal requests
come from real children; separately protected inputs and approvals go through
the fixed installer child's EOF/exit/reap gate. The existing adopted supervisor
is started before rendezvous, but its first blocking step waits for actual cold
completion. No owner can be supplied in a JSON document or constructor argument.
"""
from __future__ import annotations

import contextlib
import copy
import fcntl
import os
import select
import threading
import time

from scripts import native_pilot_runtime_artifacts as artifacts
from scripts.authority import native_pilot_authority_io as public_io
from catchplate import native_pilot_adopted_intake as intake
from catchplate import native_pilot_genesis_authority_channel as cold_channel
from catchplate import native_pilot_genesis_job_install as job_install
from catchplate import native_pilot_genesis_jobs as jobs
from catchplate import native_pilot_genesis_parent_control_io as ownership
from catchplate import native_pilot_genesis_rendezvous_install as rendezvous_install
from catchplate import native_pilot_genesis_rendezvous_profile as rendezvous
from catchplate import native_pilot_measured_configuration as measured
from catchplate import native_shadow_nitro_originals as originals
from catchplate import native_shadow_proof_cohort_control as mechanics
from catchplate.native_pilot_adopted_supervisor import AdoptedCommissioningSupervisor, SUPPORTED_JOBS
from catchplate.native_pilot_adopted_supervisor_policy import AdoptedSupervisorPolicy, MAX_POLICY, shape as policy_shape
from catchplate.native_pilot_genesis_installer_process import GenesisInstallerProcess, SealedRequest
from catchplate.native_pilot_genesis_process import GenesisAuthorityProcess
from catchplate.native_pilot_supervisor_process import AuthorityCoordinatorProcess

p = rendezvous.p
_TOKEN, _USED, _LIVE = object(), False, None
_COLD_JOBS = jobs.catalogue(handoff=True)
_KNOWN_ADOPTED = ("not-started", "stopped-cleanup-complete", "failed-cleanup-complete")
_EDGES = {("prepared", "start"): "sender", ("sender", "attach_adopted"): "adopted-waiting",
    ("adopted-waiting", "receive_rendezvous"): "rendezvous",
    ("rendezvous", "submit_rendezvous"): "cold-ready", ("cold-ready", "cold_step"): "cold-pending",
    ("cold-pending", "cold_submit"): "cold-ready", ("cold-ready", "finish_cold"): "cold-finished",
    ("cold-finished", "adopted_step"): "adopted-pending", ("adopted-ready", "adopted_step"): "adopted-pending",
    ("adopted-pending", "adopted_submit"): "adopted-ready",
    ("adopted-ready", "finish_adopted"): "adopted-finished"}


def _next(stage, operation):
    """Ordering only, not evidence that an operation occurred."""
    p.require(type(stage) is str and type(operation) is str and (stage, operation) in _EDGES)
    return _EDGES[stage, operation]


def _sender_join(raw, configuration_raw, identity):
    configuration = rendezvous._configuration(configuration_raw)
    sender = rendezvous._document(raw, rendezvous.MAX_SENDER, rendezvous.SENDER_REQUEST_FIELDS)
    observed_raw = rendezvous._original(sender["listenerOriginal"], rendezvous.MAX_SENDER)
    observed = rendezvous._document(observed_raw, rendezvous.MAX_SENDER, rendezvous.SENDER_FIELDS)
    p.require(sender["apiVersion"] == rendezvous.SENDER_REQUEST_API
        and type(sender["sequence"]) is int and sender["sequence"] == 0
        and sender["configurationSha256"] == p.sha(configuration_raw)
        and sender["listenerSha256"] == p.sha(observed_raw)
        and sender["deadlineBoottimeNs"] == configuration["window"]["startupDeadlineBoottimeNs"]
        and type(sender["expiresAtUnixNanos"]) is int
        and sender["expiresAtUnixNanos"] == configuration["expiresAtUnixNanos"]
        and observed["apiVersion"] == rendezvous.SENDER_API and observed["endpoint"] == rendezvous.ENDPOINT
        and observed["configurationSha256"] == sender["configurationSha256"])
    for name in rendezvous.wire.endpoints.WINDOW[:3]:
        p.require(type(observed[name]) is type(configuration["window"][name])
            and observed[name] == configuration["window"][name])
    rendezvous._socket(observed["socket"], named=True)
    p.integer(observed["processId"], minimum=2, maximum=(1 << 31) - 1)
    p.integer(observed["processStartTimeTicks"], maximum=p.MAX_I64)
    p.require(identity["pid"] == observed["processId"] and identity["startTimeTicks"] == observed["processStartTimeTicks"]
        and identity["uid"] == identity["gid"] == 0)
    return {"pid": observed["processId"], "uid": 0, "gid": 0,
        "startTimeTicks": observed["processStartTimeTicks"]}


def _late_join(sender_raw, listener_raw, identity, intake_raw, *, boot, now_boottime_ns, now_unix_ns):
    """Intersect independent originals; never issue a replacement window."""
    sender = _sender_join(sender_raw, listener_raw, identity)
    cold = rendezvous._configuration(listener_raw)
    adopted = intake.validate_configuration(intake_raw, boot=boot,
        now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    p.require(adopted["sender"] == sender
        and tuple(cold["window"][name] for name in rendezvous.wire.endpoints.WINDOW[:3]) == boot)
    issued = max(p.ns(cold["window"]["issuedAtBoottimeNs"]), p.ns(adopted["issuedAtBoottimeNs"]))
    startup = min(p.ns(cold["window"]["startupDeadlineBoottimeNs"]), p.ns(adopted["startupDeadlineBoottimeNs"]))
    lifetime = min(p.ns(cold["window"]["lifetimeDeadlineBoottimeNs"]), p.ns(adopted["lifetimeDeadlineBoottimeNs"]))
    expiry = min(cold["expiresAtUnixNanos"], adopted["expiresAtUnixNanos"])
    p.require(issued <= now_boottime_ns < min(startup, lifetime - rendezvous.wire.RESERVE)
        and now_unix_ns < expiry)
    return dict(startup=startup, deadline=lifetime, epochLimit=expiry)


def _rendezvous_join(raw, sender_raw, listener_raw):
    ticket = rendezvous.verify_request(raw)
    p.require(ticket["senderRequestOriginal"].encode("ascii") == sender_raw
        and ticket["configurationOriginal"].encode("ascii") == listener_raw)
    return p.document(ticket["receiverOriginal"].encode("ascii"), rendezvous.MAX_RECEIVER)["receiver"]


def _receiver_process(fd, expected, parent_pid, boot):
    """Actual retained PIDFD/parent/credentials joins, never receiver approval."""
    p.require(type(fd) is int and fd >= 3 and not os.get_inheritable(fd)
        and not select.select([fd], [], [], 0)[0]
        and mechanics._pidfd_pid(fd) == expected["pid"]
        and mechanics._process(expected["pid"]) == (parent_pid, expected["startTimeTicks"]))
    namespace = os.stat("/proc/" + str(expected["pid"]) + "/ns/time")
    p.require((namespace.st_dev, namespace.st_ino) == boot[1:])
    with open("/proc/" + str(expected["pid"]) + "/status", "rt", encoding="ascii") as stream:
        status = stream.read(16385)
    p.require(len(status) <= 16384)
    for label, key in (("Uid:", "uid"), ("Gid:", "gid")):
        rows = [line.split()[1:] for line in status.splitlines() if line.startswith(label)]
        p.require(len(rows) == 1 and len(rows[0]) == 4
            and all(number.isascii() and number.isdecimal() and int(number) == expected[key] for number in rows[0]))
    p.require(not select.select([fd], [], [], 0)[0] and mechanics._pidfd_pid(fd) == expected["pid"]
        and mechanics._process(expected["pid"]) == (parent_pid, expected["startTimeTicks"])
        and originals._boot() == boot)
    namespace = os.stat("/proc/" + str(expected["pid"]) + "/ns/time")
    p.require((namespace.st_dev, namespace.st_ino) == boot[1:])


class LifecycleError(ValueError):
    def __init__(self, owner):
        super().__init__("connected commissioning refused; actual lifecycle owner retained")
        self.owner = owner


class _Protected:
    def __init__(self, retained, fd, maximum, digest):
        self.fd, self._uncertain = None, False
        self.maximum, self.digest = maximum, p.digest(digest)
        retained.append(self)
        with ownership.owning():
            self.identity = public_io._input(fd, maximum)
            self.fd = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 128)
        self.raw = public_io.read_public(self.fd, maximum)
        p.require(public_io.read_public(fd, maximum) == self.raw)
        self.check()

    def check_identity(self):
        p.require(not self._uncertain and self.fd is not None and not os.get_inheritable(self.fd)
            and public_io._input(self.fd, self.maximum) == self.identity)

    def check(self):
        self.check_identity()
        p.require(public_io.read_public(self.fd, self.maximum) == self.raw and p.sha(self.raw) == self.digest)
        self.check_identity()

    def close(self):
        p.require(not self._uncertain)
        if self.fd is None:
            return
        self.check_identity()
        try:
            with ownership.owning():
                self._uncertain = True
                fd, self.fd = self.fd, None
                os.close(fd)
                self._uncertain = False
        except BaseException:
            self._uncertain = True
            raise


class CommissioningLifecycle:
    def __init__(self, token):
        p.require(token is _TOKEN)
        self._pid, self._start, self._boot = os.getpid(), originals._start(), originals._boot()
        self._last, self._wall = originals._clock(), time.time_ns()
        self._sources, self._errors = [], []
        self._cold = self._process = self._supervisor = self._policy = self._recipe = None
        self._installer = self._sealed = self._execution = self._inventory = None
        self._sender = self._pending = self._bundle = self._adopted_result = None
        self._receiver = self._receiver_fd = self._receiver_identity = None
        self._deadline = self._startup = self._expiry = None
        self._cold_index = self._adopted_index = 0
        self._approval_bytes = 0
        self._stage = "prepared"
        self._active = self._failed = self._closed = self._close_attempted = self._receiver_close_uncertain = False

    def _acquire(self, slot, factory, **kwargs):
        # Constructors' partial real owners become reachable before signals
        # unmask. Neither caller-supplied owners nor JSON success are accepted.
        with ownership.owning():
            try:
                value = factory(**kwargs)
            except BaseException as error:
                if getattr(error, "owner", None) is not None:
                    setattr(self, slot, error.owner)
                raise
            setattr(self, slot, value)
        return value

    @classmethod
    def prepare(cls, *, supervisor_inventory_fd, supervisor_inventory_sha256,
                listener_configuration_fd, listener_configuration_sha256, authority_key_fds):
        global _USED, _LIVE
        p.require(cls is CommissioningLifecycle and not _USED and _LIVE is None)
        _USED = True
        owner = cls(_TOKEN)
        _LIVE = owner
        try:
            public_io._process()
            owner._inventory = _Protected(owner._sources, supervisor_inventory_fd,
                artifacts.MAX_MANIFEST_BYTES, supervisor_inventory_sha256)
            owner._listener = _Protected(owner._sources, listener_configuration_fd,
                rendezvous.MAX_CONFIGURATION, listener_configuration_sha256)
            owner._distinct()
            configuration = rendezvous._configuration(owner._listener.raw)
            owner._startup = p.ns(configuration["window"]["startupDeadlineBoottimeNs"])
            owner._deadline = p.ns(configuration["window"]["lifetimeDeadlineBoottimeNs"])
            owner._expiry = configuration["expiresAtUnixNanos"]
            owner._acquire("_cold", GenesisAuthorityProcess.prepare,
                supervisor_inventory_fd=owner._inventory.fd, supervisor_inventory_sha256=owner._inventory.digest,
                listener_configuration_fd=owner._listener.fd, listener_configuration_sha256=owner._listener.digest,
                authority_key_fds=authority_key_fds)
            p.require(owner._cold.listener_configuration_original() == owner._listener.raw)
            owner._check(full=True)
            return owner
        except BaseException as error:
            owner._failed = True
            raise LifecycleError(owner) from error

    def _origin(self):
        p.require(type(self) is CommissioningLifecycle and _LIVE is self and not self._closed
            and (self._pid, self._start, self._boot) == (os.getpid(), originals._start(), originals._boot())
            and threading.current_thread() is threading.main_thread()
            and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))

    def _distinct(self):
        p.require(len({item.identity[:2] for item in self._sources}) == len(self._sources))

    def _clock(self, deadline=None, expiry=None):
        now, wall = originals._clock(), time.time_ns()
        p.require(self._last <= now < min(self._deadline, self._deadline if deadline is None else deadline)
            and self._wall <= wall < min(self._expiry, self._expiry if expiry is None else expiry))
        self._last, self._wall = now, wall

    def _check_receiver(self, *, live):
        if self._receiver_fd is None:
            return
        p.require(not self._receiver_close_uncertain
            and public_io._identity(os.fstat(self._receiver_fd)) == self._receiver_identity
            and not os.get_inheritable(self._receiver_fd))
        if live:
            p.require(type(self._process) is AuthorityCoordinatorProcess)
            _receiver_process(self._receiver_fd, self._receiver, self._process._child.pid, self._boot)

    def _check(self, *, full=False, deadline=None, expiry=None):
        self._origin()
        p.require(not self._failed and not self._close_attempted)
        for original in self._sources:
            (original.check if full else original.check_identity)()
        if self._cold is not None:
            if self._cold.finished:
                self._cold.check_retained(full=full)
            else:
                self._cold.check_waiting()
        if self._process is not None and not self._process._closed:
            if self._supervisor is not None and self._supervisor._pending is not None:
                self._process.check_request(self._supervisor._pending)
            elif self._process._started and self._process._channel._index == 0:
                self._process.check_waiting()
            else:
                self._process._capabilities()
            self._expiry = min(self._expiry, self._process._epoch_limit)
            if self._policy is not None:
                self._policy.check(self._process if self._policy._bound else None)
        self._check_receiver(live=self._process is not None and not self._process._closed
            and self._adopted_index < len(SUPPORTED_JOBS))
        self._clock(deadline, expiry)  # After actual identity and retained I/O.

    def check_waiting(self):
        """Keep genuine current owners without receiving or advancing a job."""
        try:
            self._check()
        except BaseException as error:
            self._failed = True
            raise LifecycleError(self) from error

    def approval_context(self):
        """Return checked public transport context, never authority or renewal.

        The lifetime ceiling bounds the one inherited approval connection.
        Each exchange uses the current wait ceiling and still calls
        check_waiting during I/O. Copies of these values cannot construct a
        process owner, approve an input, or keep a later wait current.
        """
        try:
            self._check()
            p.require(not self._active)
            self._listener.check()
            lifetime, expiry = self._deadline, self._expiry
            if self._cold._core_deadline is not None:
                lifetime = min(lifetime, self._cold._core_deadline)
            if self._cold._core_expiry is not None:
                expiry = min(expiry, self._cold._core_expiry)
            wait = lifetime
            if not self._cold.finished:
                wait = min(wait, self._cold._upper())
            if self._process is not None and not self._process._closed:
                expiry = min(expiry, self._process._epoch_limit)
                if self._supervisor is not None and self._supervisor._pending is not None:
                    wait = min(wait, self._supervisor._pending.deadline_boottime_ns)
                elif self._process._started and self._process._channel._index < len(self._process._order):
                    # Match the actual process.receive bound without reading
                    # its pipe or advancing its selected catalogue.
                    phase = self._process._order[self._process._channel._index][0]
                    upper = self._process._lifetime - self._process._reserve if phase in (
                        "generation-origin", "shutdown") else self._process._startup
                    wait = min(wait, upper)
            result = {"stage": self._stage,
                "listenerConfigurationOriginal": self._listener.raw.decode("ascii"),
                "startupDeadlineBoottimeNs": min(self._startup, lifetime),
                "deadlineBoottimeNs": lifetime, "waitDeadlineBoottimeNs": wait,
                "expiresAtUnixNanos": expiry}
            self._check(deadline=wait, expiry=expiry)  # Sample after all retained source/identity I/O.
            return result
        except BaseException as error:
            self._failed = True
            raise LifecycleError(self) from error

    @contextlib.contextmanager
    def _operation(self, name):
        try:
            self._check(full=True)
            target = _next(self._stage, name)
            p.require(not self._active)
            self._active = True
            yield
            self._check(full=True)
            self._stage = target
        except BaseException as error:
            self._failed = True
            raise LifecycleError(self) from error
        finally:
            self._active = False

    def start(self):
        with self._operation("start"):
            with ownership.owning():
                self._sender = self._cold.start()
            _sender_join(self._sender.raw, self._listener.raw, self._cold.identity())
        return self._sender.raw

    def attach_adopted(self, *, policy_fd, policy_sha256, recipe_fd, recipe_sha256,
                       intake_configuration_fd, intake_configuration_sha256,
                       conductor_inventory_fd, conductor_inventory_sha256,
                       authority_inventory_fd, authority_inventory_sha256, authority_key_fds):
        with self._operation("attach_adopted"):
            sources = {}
            for name, fd, digest, maximum in (
                ("policy", policy_fd, policy_sha256, MAX_POLICY),
                ("recipe", recipe_fd, recipe_sha256, measured.MAX_RECIPE),
                ("intake", intake_configuration_fd, intake_configuration_sha256, intake.MAX_CONFIGURATION),
                ("conductor", conductor_inventory_fd, conductor_inventory_sha256, artifacts.MAX_MANIFEST_BYTES),
                ("authority", authority_inventory_fd, authority_inventory_sha256, artifacts.MAX_MANIFEST_BYTES)):
                sources[name] = _Protected(self._sources, fd, maximum, digest)
            self._distinct()
            limits = _late_join(self._sender.raw, self._listener.raw, self._cold.identity(), sources["intake"].raw,
                boot=self._boot, now_boottime_ns=originals._clock(), now_unix_ns=time.time_ns())
            policy = policy_shape(sources["policy"].raw)
            source = artifacts._source(p.document(self._inventory.raw, artifacts.MAX_MANIFEST_BYTES)["source"])
            p.require(policy["source"] == source
                and policy["intakeConfigurationOriginal"].encode("ascii") == sources["intake"].raw
                and policy["intakeConfigurationSha256"] == sources["intake"].digest
                and policy["measuredRecipeSha256"] == sources["recipe"].digest)
            for role in ("conductor", "authority"):
                p.require(artifacts._source(p.document(sources[role].raw, artifacts.MAX_MANIFEST_BYTES)["source"]) == source
                    and policy[role + "InventorySha256"] == sources[role].digest)
            self._startup, self._deadline, self._expiry = limits["startup"], limits["deadline"], limits["epochLimit"]
            self._acquire("_policy", AdoptedSupervisorPolicy.open,
                policy_fd=sources["policy"].fd, policy_sha256=sources["policy"].digest)
            self._acquire("_recipe", measured.MeasuredConfigurationRecipe.open,
                recipe_fd=sources["recipe"].fd, recipe_sha256=sources["recipe"].digest)
            # Public originals and actual cold identity are joined before the
            # real process reads any selected adopted private signing key.
            self._check(full=True, deadline=self._startup)
            self._acquire("_process", AuthorityCoordinatorProcess.prepare_adopted,
                conductor_inventory_fd=sources["conductor"].fd, conductor_inventory_sha256=sources["conductor"].digest,
                authority_inventory_fd=sources["authority"].fd, authority_inventory_sha256=sources["authority"].digest,
                authority_key_fds=authority_key_fds, intake_configuration_fd=sources["intake"].fd,
                intake_configuration_sha256=sources["intake"].digest)
            self._acquire("_supervisor", AdoptedCommissioningSupervisor.prepare,
                policy=self._policy, process=self._process, measured_recipe=self._recipe)
            self._startup = min(self._startup, self._process._startup)
            self._deadline = min(self._deadline, self._process._lifetime)
            self._expiry = min(self._expiry, self._process._epoch_limit)
            self._check(full=True, deadline=self._startup)
            self._supervisor.start()  # Deliberately no blocking step/receive.

    def receive_rendezvous(self):
        with self._operation("receive_rendezvous"):
            with ownership.owning():
                self._pending = self._cold.receive_rendezvous()
            self._receiver = _rendezvous_join(self._pending.raw, self._sender.raw, self._listener.raw)
            self._process.check_waiting()
            with ownership.owning():
                self._receiver_fd = os.pidfd_open(self._receiver["pid"], 0)
                os.set_inheritable(self._receiver_fd, False)
                self._receiver_identity = public_io._identity(os.fstat(self._receiver_fd))
            self._check_receiver(live=True)
        return self._pending.raw

    def _install(self, kind, input_fd, input_sha256, approval_fd, approval_sha256):
        p.require(self._installer is None and self._sealed is None and self._pending is not None)
        request_raw = self._pending.raw
        maximum = rendezvous.MAX_INPUT if kind == "rendezvous" else _COLD_JOBS[self._cold_index].maximum
        inp = _Protected(self._sources, input_fd, maximum, input_sha256)
        approval = _Protected(self._sources, approval_fd, 8192, approval_sha256)
        self._distinct()
        self._approval_bytes += len(inp.raw) + len(approval.raw)
        p.require(self._approval_bytes <= cold_channel.MAX_RETAINED)
        clocks = dict(boot=self._boot, now_boottime_ns=originals._clock(), now_unix_ns=time.time_ns())
        pins = dict(request_sha256=p.sha(request_raw), input_sha256=inp.digest, approval_sha256=approval.digest)
        if kind == "rendezvous":
            prepared = rendezvous_install.prepare_input(request_raw, inp.raw, approval.raw, **pins, **clocks)
            self._execution = inp
        else:
            p.require(self._cold.configuration_original() == self._execution.raw)
            prepared = job_install.prepare_input(request_raw, inp.raw, approval.raw, self._execution.raw,
                configuration_sha256=self._execution.digest, **pins, **clocks)
        self._acquire("_sealed", SealedRequest.open, raw=request_raw)
        arguments = dict(kind=kind, supervisor_inventory_fd=self._inventory.fd,
            supervisor_inventory_sha256=self._inventory.digest, request_fd=self._sealed.fd,
            request_sha256=self._sealed.digest, input_fd=inp.fd, input_sha256=inp.digest,
            approval_fd=approval.fd, approval_sha256=approval.digest)
        if kind == "job":
            arguments.update(configuration_fd=self._execution.fd, configuration_sha256=self._execution.digest)
        self._acquire("_installer", GenesisInstallerProcess.prepare, **arguments)
        self._sealed.check()
        sealed_identity = public_io._input(self._sealed.fd, jobs.MAX_OUTPUT)

        def current():
            p.require(public_io._input(self._sealed.fd, jobs.MAX_OUTPUT) == sealed_identity)
            self._check(deadline=prepared["deadline"], expiry=prepared["epochLimit"])

        current()
        reply = self._installer.run(check=current)
        p.require(type(reply) is bytes and reply == p.canonical(prepared["reply"]))
        inp.check(); approval.check(); self._sealed.check(); current()
        # Only a genuine successful installer can reach its known cleanup.
        # The reply is not forwarded if either local descriptor close is unsure.
        with ownership.owning():
            self._installer.close(cancel=False)
            self._installer = None
            self._sealed.close()
            self._sealed = None
        self._check(deadline=prepared["deadline"], expiry=prepared["epochLimit"])
        return reply

    def submit_rendezvous(self, *, input_fd, input_sha256, approval_fd, approval_sha256):
        with self._operation("submit_rendezvous"):
            reply = self._install("rendezvous", input_fd, input_sha256, approval_fd, approval_sha256)
            self._check_receiver(live=True)
            with ownership.owning():
                self._cold.reply_rendezvous(reply)
                p.require(self._cold.configuration_original() == self._execution.raw)
                self._pending = None

    def cold_step(self):
        with self._operation("cold_step"):
            p.require(self._cold_index < len(_COLD_JOBS) and self._pending is None)
            with ownership.owning():
                self._pending = self._cold.receive_job()
            p.require(self._pending.sequence == self._cold_index + 1
                and self._pending.job == _COLD_JOBS[self._cold_index].name)
        return {"status": "awaiting-independent-cold-job-approval", "job": self._pending.job,
            "sequence": self._pending.sequence, "requestOriginal": self._pending.raw.decode("ascii"),
            "requestSha256": p.sha(self._pending.raw)}

    def cold_submit(self, *, input_fd, input_sha256, approval_fd, approval_sha256):
        with self._operation("cold_submit"):
            reply = self._install("job", input_fd, input_sha256, approval_fd, approval_sha256)
            cold_channel.reply(reply, self._pending.raw)
            with ownership.owning():
                self._cold.reply_job(reply)
                self._cold_index += 1
                self._pending = None

    def finish_cold(self):
        with self._operation("finish_cold"):
            p.require(self._cold_index == len(_COLD_JOBS) and self._pending is None)
            with ownership.owning():
                self._bundle = self._cold.finish()
            p.require(type(self._bundle) is bytes and self._cold.finished)
            if self._cold._core_deadline is not None:
                self._deadline = min(self._deadline, self._cold._core_deadline)
            if self._cold._core_expiry is not None:
                self._expiry = min(self._expiry, self._cold._core_expiry)
        return self._bundle  # Custody/cleanup evidence, never operational readiness.

    def adopted_step(self):
        with self._operation("adopted_step"):
            p.require(self._cold.finished and self._bundle is not None and self._adopted_index < len(SUPPORTED_JOBS))
            result = self._supervisor.step()
            p.require((result["phase"], result["job"]) == SUPPORTED_JOBS[self._adopted_index]
                and result["sequence"] == self._adopted_index + 1)
        return result

    def adopted_submit(self, *, input_fd, input_sha256, approval_fd, approval_sha256):
        with self._operation("adopted_submit"):
            with ownership.owning():
                result = self._supervisor.submit(input_fd=input_fd, input_sha256=input_sha256,
                    approval_fd=approval_fd, approval_sha256=approval_sha256)
                self._adopted_index += 1
        return result

    def finish_adopted(self):
        with self._operation("finish_adopted"):
            p.require(self._adopted_index == len(SUPPORTED_JOBS))
            self._process.wait_interactive()
            with ownership.owning():
                self._adopted_result = self._supervisor.close(cancel=False)
            p.require(self._adopted_result["status"] == "stopped-cleanup-complete" and self._process._closed)
        return copy.deepcopy(self._adopted_result)

    def completion_original(self, stage):
        """Actual child result after verified exit, not overall CLI cleanup.

        Public source capabilities stay retained until close. These bytes may
        complete an independent transcript but confer no execution authority.
        """
        try:
            self._check(full=True)
            p.require(not self._active and stage in ("cold", "adopted"))
            if stage == "cold":
                p.require(self._stage == "cold-finished" and self._bundle is not None)
                owner = self._cold
            else:
                p.require(self._stage == "adopted-finished" and self._adopted_result is not None)
                owner = self._process
            raw = owner.completion_original()
            p.require(type(raw) is bytes)
            self._check(full=True)
            # Sample the terminal's potentially tighter caps after all of the
            # lifecycle's retained-file checks, not merely before that I/O.
            p.require(owner.completion_original() == raw)
            return raw
        except BaseException as error:
            self._failed = True
            raise LifecycleError(self) from error

    def close(self, *, cancel=False):
        global _LIVE
        if self._closed:
            return copy.deepcopy(self._result)
        self._origin()
        p.require(type(cancel) is bool and not self._active and not self._close_attempted)
        self._close_attempted = True
        failures = []
        # Each real owner is attempted once. One uncertainty does not hide the
        # other owner from cancellation; public sources/PIDFD stay retained.
        if self._installer is not None:
            try:
                self._installer.close(cancel=cancel)
            except BaseException as error:
                failures.append(error)
        if self._cold is not None:
            try:
                result = self._cold.close(cancel=cancel)
                p.require(result["status"] == "closed")
            except BaseException as error:
                failures.append(error)
        if self._process is not None and not self._process._closed:
            try:
                result = self._supervisor.close(cancel=cancel) if self._supervisor is not None else self._process.close(cancel=cancel)
                p.require(result["status"] in _KNOWN_ADOPTED and self._process._closed)
                self._adopted_result = result
            except BaseException as error:
                failures.append(error)
        if failures:
            self._errors.extend(failures)
            self._failed = True
            raise LifecycleError(self) from failures[0]
        try:
            if self._policy is not None:
                self._policy.close()
            if self._recipe is not None:
                self._recipe.close()
            if self._sealed is not None:
                self._sealed.close()
            if self._receiver_fd is not None:
                self._check_receiver(live=False)
                p.require(self._process is not None and self._process._closed
                    and select.select([self._receiver_fd], [], [], 0)[0])
                with ownership.owning():
                    self._receiver_close_uncertain = True
                    fd, self._receiver_fd = self._receiver_fd, None
                    os.close(fd)
                    self._receiver_close_uncertain = False
            while self._sources:
                with ownership.owning():
                    self._sources[-1].close()
                    self._sources.pop()
            self._result = {"status": "closed", "completed": self._stage == "adopted-finished",
                "pilotAcceptanceVerified": False, "productionReleaseEligible": False}
            self._closed, _LIVE = True, None
            return copy.deepcopy(self._result)
        except BaseException as error:
            self._errors.append(error)
            self._failed = True
            raise LifecycleError(self) from error
