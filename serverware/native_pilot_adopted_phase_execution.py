"""Actual selected adopted phase execution over the retained conductor.

Endpoint originals are published from authenticated prior inputs only after
independent job approval. Adoption requires the real pinned native validator;
neither this executor nor an observation stands in for independent approval,
received-core custody, or service readiness.
"""
from __future__ import annotations

import copy
import fcntl
import os
import time

from serverware import native_pilot_phase_execution as base
from serverware import native_pilot_adopted_phase_profile as profile
from serverware import native_pilot_adopted_publication as public_profile
from serverware import native_pilot_adopted_ordinary_install as ordinary_install
from serverware import native_pilot_adopted_endpoint_publication as endpoint_publication
from serverware import native_pilot_genesis_parent_control_io as owning
from serverware.native_pilot_publication_adoption_authority import AdoptionAuthority, AdoptionAuthorityError

p, io = base.p, base.io
_FAMILIES = frozenset(("driver", "cohort", "precreation", "ordinary-initial", "helper-initial",
    "ordinary-installation", "ordinary-delivery", "ordinary-generation", "ordinary-dispatch", "ordinary-head",
    "ordinary-cleanup", "ordinary-current", "ordinary-publication", "adoption", "endpoint-inputs", "delivery",
    "native-key", "native", "generation-install", "native-launch-authorization", "launch", "service-material",
    "current-head", "bridge-runtime", "bridge-authorization", "scope", "phase-two-public", "origin", "stop"))


def require_complete_coverage():
    """Fixed executable coverage, called before a child or private key read."""
    p.require(tuple(profile.JOBS) == base.STAGES and len(profile.BY_NAME) == sum(map(len, profile.JOBS.values())))
    for name, (_, job) in profile.BY_NAME.items():
        p.require(job.family in _FAMILIES)
        if job.family == "native-key": p.require(name in profile.KEY_INFO)
        elif job.family == "native-launch-authorization": p.require(name in profile.AUTH_INFO)
        elif job.family == "bridge-authorization": p.require(name in base.BRIDGE_AUTHORIZATION_JOB_INFO)
        elif job.family == "current-head": p.require(name in base.CURRENT_HEAD_JOB_INFO)
        elif job.family == "ordinary-initial": p.require(name in base.INITIAL_JOB_INFO)
        elif job.family == "helper-initial": p.require(name in base.HELPER_INITIAL_JOB_INFO)
        elif job.family in ("delivery", "launch"): p.require(job.role in (*profile.ENDPOINTS, "bridge"))
        elif job.family == "native": p.require(job.role in profile.NATIVE_ENDPOINT)
        elif job.family.startswith("ordinary-") and job.family != "ordinary-installation":
            p.require(job.role in base.generation.ROLES)
        elif job.family == "driver": p.require(job.role in ("bootstrap", "constructed"))
        elif job.family == "cohort": p.require(job.role in ("precreation", "release"))
    p.require(set(profile.KEY_PURPOSES) == {job.key for _, job in profile.BY_NAME.values() if job.key is not None})


class AdoptedPhaseExecution(base.PhaseExecution):
    @classmethod
    def open(cls, process):
        p.require(cls is AdoptedPhaseExecution and not base._USED and base._LIVE is None
            and type(process) is base.ConductorProcess)
        process._origin()
        p.require(not process._started and process.adoption_selected())
        require_complete_coverage()
        base._USED = True
        owner = cls(base._TOKEN, process)
        base._LIVE = owner
        return owner

    def __init__(self, token, process):
        super().__init__(token, process)
        self._adopted = True
        self._jobs, self._key_purposes = profile.JOBS, profile.KEY_PURPOSES
        self._approval_root = profile.APPROVAL_ROOT
        self._request_api, self._reply_api, self._approval_api = profile.API, profile.REPLY_API, profile.APPROVAL_API
        self._prior = {}
        self._ordinary_install = self._adoption_owner = None
        self._endpoint_publication = None
        self._public_fds = []
        self._prepared = None
        self._final_stop = self._final_stop_expiry = None
        self._job_deadline = self._job_expiry = None
        self._last_boot, self._last_wall = base.originals._clock(), time.time_ns()
        self._close_attempted = False

    def _during(self):
        """Original checks during the already consumed/fenced job attempt."""
        p.require(base._LIVE is self and not self._closed and os.getpid() == self._pid
            and base.originals._boot() == self._boot)
        self._process._origin()
        for original in self._held: original.check()
        if self._ordinary_install is not None: self._ordinary_install.check_retained()
        if self._endpoint_publication is not None: self._endpoint_publication.check()
        if self._publisher is not None: self._publisher.check()
        if self._public is not None: self._public.check()
        for fd, identity, raw in self._public_fds:
            if identity is not None:
                p.require(io._input(fd, len(raw)) == identity)
        if self._request is not None:
            self._process._io_check(self._request.deadline_boottime_ns)
        now, wall = base.originals._clock(), time.time_ns()
        p.require(self._last_boot <= now and self._last_wall <= wall)
        self._last_boot, self._last_wall = now, wall
        if self._request is not None:
            p.require(wall < self._request.expires_at_unix_ns)
        if self._job_deadline is not None: p.require(now < self._job_deadline)
        if self._job_expiry is not None: p.require(wall < self._job_expiry)

    def _check(self, *, pending=False):
        super()._check(pending=pending)
        self._during()

    def begin(self, request):
        # A completed startup job cannot renew a later phase's admission. The
        # phase's genuine Request2 and each new producer supply its own cap.
        self._job_deadline = self._job_expiry = None
        super().begin(request)
        p.require(p.document(request.raw, profile.MAX_FRAME)["apiVersion"] == "serverware.nativePilotOperatorRequest/v2")

    def _bind(self, job, value):
        self._during()
        self._prepared = profile.prepare_input(job.name, self._inputs[job.name], phase=self._request.phase,
            prior=self._prior, observations=self._observations, boot=self._boot,
            now_boottime_ns=base.originals._clock(), now_unix_ns=time.time_ns())
        self._job_deadline, self._job_expiry = self._prepared["deadline"], self._prepared["epochLimit"]
        self._during()

    def execute(self, reply):
        try:
            super().execute(reply)
            self._prior[self._previous["job"]] = {"input": self._inputs[self._previous["job"]],
                "result": copy.deepcopy(self._previous["result"])}
            if self._previous["job"] == "stop":
                p.require(self._previous["phase"] == "shutdown" and self._final_stop is None)
                actual = p.canonical(self._previous["result"])
                p.require(actual == p.canonical(self._installations["stop"]))
                self._final_stop = {"finalResult": {"job": "stop", "inputSha256": p.sha(self._inputs["stop"]),
                    "resultOriginal": actual.decode("ascii"), "resultSha256": p.sha(actual)},
                    "deadlineBoottimeNs": str(self._request.deadline_boottime_ns),
                    "expiresAtUnixNanos": str(self._request.expires_at_unix_ns)}
                self._final_stop_expiry = min(self._request.expires_at_unix_ns,
                    self._job_expiry if self._job_expiry is not None else self._request.expires_at_unix_ns)
            self._during()
        except BaseException:
            self._failed = True
            raise

    def final_result(self):
        """Actual last result only after this executor's conductor is retired."""
        p.require(base._LIVE is self and not self._closed and not self._failed and not self._close_attempted
            and os.getpid() == self._pid and base.originals._boot() == self._boot
            and self._process._closed and self._process._result["status"] == "stopped-cleanup-complete"
            and self._phase_index == len(base.STAGES) and self._request is None and self._final_stop is not None)
        for original in self._held: original.check()
        result = copy.deepcopy(self._final_stop)
        p.require(result["finalResult"]["inputSha256"] == p.sha(self._inputs["stop"])
            and result["finalResult"]["resultOriginal"].encode("ascii") == p.canonical(self._previous["result"])
            == p.canonical(self._installations["stop"]))
        now, wall = base.originals._clock(), time.time_ns()
        p.require(self._last_boot <= now < p.ns(result["deadlineBoottimeNs"])
            and self._last_wall <= wall < self._final_stop_expiry)
        self._last_boot, self._last_wall = now, wall
        return result

    def _public_fd(self, raw):
        p.require(type(raw) is bytes and 0 < len(raw) <= profile.MAX_FRAME
            and self._bytes + len(raw) <= base.MAX_RETAINED_BYTES)
        with owning.owning():
            fd = os.memfd_create("serverware-adopted-public-original", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            index = len(self._public_fds)
            self._public_fds.append((fd, None, raw))
            self._bytes += len(raw)
        offset = 0
        while offset < len(raw):
            self._during()
            count = os.pwrite(fd, raw[offset:offset + 65536], offset)
            p.require(count > 0); offset += count
        os.fchmod(fd, 0o400)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, io.SEALS)
        identity = io._input(fd, len(raw))
        p.require(io.read_public(fd, len(raw)) == raw)
        self._public_fds[index] = (fd, identity, raw)
        self._during()
        return fd

    def _adoption(self, job, value):
        # These are sealed copies of separately approved public originals, not
        # signing approval or a fabricated native validation response.
        control, native = (profile._raw(value[name]) for name in ("controlOriginal", "validationInputOriginal"))
        control_fd, input_fd = self._public_fd(control), self._public_fd(native)
        try:
            with owning.owning():
                self._adoption_owner = AdoptionAuthority.prepare(control_fd=control_fd, control_sha256=p.sha(control),
                    input_fd=input_fd, input_sha256=p.sha(native))
        except AdoptionAuthorityError as error:
            self._adoption_owner = error.owner
            raise
        self._during()
        self._adoption_owner.validate()  # Actual native output, successful exit, consuming PIDFD reap.
        self._during()
        fd, identity = self._keys[job.key]
        p.require(io._input(fd, 32, private=True) == identity)
        signed = self._adoption_owner.sign(key_fd=fd)
        p.require(io._input(fd, 32, private=True) == identity)
        self._during()
        self._adoption_owner.close()  # The actual validator is already reaped.
        return signed

    def _signed(self, job, signed):
        p.require(type(signed) is bytes)
        self._outputs[job.name] = signed
        self._bytes += len(signed)
        p.require(self._bytes <= base.MAX_RETAINED_BYTES)
        result = {"original": signed.decode("ascii"), "sha256": p.sha(signed)}
        if job.purpose is not None:
            self._during()
            if job.purpose in public_profile.DESTINATIONS:
                publish = self._publisher.publish_adopted_ordinary
            elif job.purpose in base.launch_install.ADOPTED_DESTINATIONS:
                publish = self._publisher.publish_adopted
            else:
                publish = self._publisher.publish
            pin = publish(purpose=job.purpose, raw=signed, expected_sha256=p.sha(signed))
            self._pins[job.name] = pin
            result["pin"] = pin
        self._during()
        return result

    def _perform(self, job, raw, value, key):
        family, signed = job.family, None
        if family == "driver": signed = base.driver_authority.sign(job.role, raw, key, adopted=True)
        elif family == "cohort": signed = profile.cohort_authority.sign(job.role, input_original=raw, signing_key=key)[0]
        elif family == "adoption":
            p.require(key is None)
            signed = self._adoption(job, value)
        elif family == "delivery":
            signed = (base.delivery_authority.sign(raw, key) if job.role == "bridge"
                else profile.commands.execute(job.role, "delivery", raw, signing_key=key))
        elif family == "native-key":
            role, operation = profile.KEY_INFO[job.name]
            signed = profile.commands.execute(role, operation, raw, signing_key=key)
        elif family == "native-launch-authorization":
            role, operation = profile.AUTH_INFO[job.name]
            signed = profile.commands.execute(role, "verifier" if operation == "verifier-transport" else operation,
                raw, signing_key=key)
        elif family in ("native", "generation-install"):
            op = "generationInstall" if family == "generation-install" else job.role
            role = "generationInstall" if op == "generationInstall" else profile.NATIVE_ENDPOINT[op]
            signed = profile.commands.execute(role, "companion-grant" if op == "commitRequest" else "grant", raw, signing_key=key)
        elif family in ("ordinary-initial", "helper-initial"):
            _, operation = (base.INITIAL_JOB_INFO if family == "ordinary-initial" else base.HELPER_INITIAL_JOB_INFO)[job.name]
            signed = (base.initial_authority.assemble(input_original=raw, adopted=True)[0] if operation == "assemble"
                else base.initial_authority.sign(operation, input_original=raw, signing_key=key, adopted=True)[0])
        elif family == "ordinary-publication":
            signed = profile.publication.sign(job.role, input_original=raw, signing_key=key)[0]
        elif family in ("ordinary-delivery", "ordinary-generation", "ordinary-dispatch", "ordinary-head", "ordinary-cleanup", "ordinary-current"):
            signed = base.service_authority.sign(operation=family.removeprefix("ordinary-"), role=job.role,
                input_original=raw, signing_key=key, adopted=True)[0]
        elif family == "current-head":
            signed = base.current_head_authority.sign(input_original=raw, signing_key=key, adopted=True)[0]
        elif family == "bridge-authorization":
            operation = base.BRIDGE_AUTHORIZATION_JOB_INFO[job.name]
            signed = (base.closure_authority.sign(input_original=raw, signing_key=key)[0] if operation == "closure"
                else base.bridge_authority.sign(operation, raw, key)[0])
        elif family == "scope": signed = base.scope_authority.sign(raw, key, adopted=True)
        if signed is not None:
            return self._signed(job, signed)
        p.require(key is None)
        if family == "precreation": result = base.precreation_install.install_adopted(raw, expected_sha256=p.sha(raw))
        elif family == "ordinary-installation":
            try:
                with owning.owning():
                    self._ordinary_install = ordinary_install.install(input_original=raw, expected_sha256=p.sha(raw), check=self._during)
            except ordinary_install.InstallationError as error:
                self._ordinary_install = error.owner
                raise
            result = self._ordinary_install.result()
        elif family == "launch":
            install = base.launch_install.install_adopted_bridge if job.role == "bridge" else base.launch_install.install_adopted
            result = install(raw, expected_sha256=p.sha(raw))
        elif family == "bridge-runtime": result = base.bridge_install.install(raw, expected_sha256=p.sha(raw))
        elif family == "service-material":
            result = base.service_material.install_adopted(raw, expected_sha256=p.sha(raw))
            self._material = copy.deepcopy(result["material"])
        elif family == "endpoint-inputs":
            p.require(self._endpoint_publication is None)
            # execute() has already retained and authenticated this job's exact
            # independent Approval2 and input. Retain before any acquisition.
            self._endpoint_publication = endpoint_publication._Publication(self._publisher, self._public)
            self._endpoint_publication.publish(value, prior=self._prior,
                observations=self._observations, check=self._during)
            self._endpoint_inputs = copy.deepcopy(value)
            result = {"publicPinsOpened": True}
        elif family == "phase-two-public":
            selected = base.phase_two.prepare_input(raw, adopted=True)
            pin = self._publisher.publish_adopted_ordinary(purpose=base.phase_two.PURPOSE,
                raw=selected, expected_sha256=p.sha(selected))
            p.require(self._public.read(pin, maximum=base.bridge_runtime.MAX_BRIDGE_INPUT) == selected)
            self._public_bundle_pin = pin
            result = {"pin": pin}
        else:
            p.require(family in ("origin", "stop"))
            result = dict(value)
        self._installations[job.name] = result
        self._during()
        return result

    def complete(self):
        self._check(pending=True)
        p.require(not self.has_job() and self._ticket is None)
        phase = self._request.phase
        if phase == "endpoint-deliveries":
            reply = {"endpointDeliveries": {role: self._pins["native-delivery-" + role] for role in profile.COMPOSITE}}
        elif phase == "service-originals":
            reply = {"ordinaryDeliveries": {role: self._pins["ordinary-delivery-" + role] for role in base.generation.ROLES},
                "ordinaryGrants": {role: self._pins["ordinary-generation-" + role] for role in base.generation.ROLES},
                "dispatchGrants": {role: self._pins["ordinary-dispatch-" + role] for role in base.commitment.ROLES},
                "dispatchNativeGrant": self._pins["native-service-commitRequest"],
                "spoolGrants": {role: self._pins["ordinary-" + name] for name, role in
                    zip(("head", "cleanup", "current"), base.spool.EFFECT_ROLES, strict=True)},
                "nativeSpoolGrants": {name: self._pins["native-service-" + name] for name in base.spool.EFFECT_NATIVE},
                "publicationGrants": {role: self._pins["ordinary-publication-" + role] for role in profile.PUBLICATION_ROLES},
                "nativePublicationGrant": self._pins["native-service-publication"],
                "endpointLaunches": {role: self._installations["install-launch-" + role]["launch"] for role in profile.ENDPOINTS},
                **self._material}
        else:
            return super().complete()
        self._failed = True
        self._process.reply(self._request, copy.deepcopy(reply))
        self._request = None
        self._phase_index += 1
        self._failed = False

    def close(self):
        if self._closed: return
        p.require(not self._close_attempted and self._process._closed
            and self._process._result["status"] in ("not-started", "stopped-cleanup-complete", "failed-cleanup-complete"))
        self._close_attempted = True
        if self._endpoint_publication is not None: self._endpoint_publication.close()
        if self._adoption_owner is not None: self._adoption_owner.close()
        if self._ordinary_install is not None: self._ordinary_install.close()
        with owning.owning():
            while self._public_fds:
                fd, _, _ = self._public_fds.pop()
                os.close(fd)
        super().close()
