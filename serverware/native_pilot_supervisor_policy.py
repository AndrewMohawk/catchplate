"""Independent one-attempt commissioning policy and first bootstrap decision.

The protected complete policy and its digest are independently provisioned.
Neither a supplied digest, file mode, valid request nor this parser establishes
that approval provenance. This owner delegates only the initial bootstrap and
the separate two fixed precreation decisions, not all sixty authority jobs.
Explicit policy v2 additionally pins a retained measured recipe/v2 and allows
its one actual post-bootstrap derivation; it does not approve endpoint jobs.

Only the actual AuthorityCoordinatorProcess and its current opaque JobRequest
can enter bootstrap(). No signing, publication, process launch, arbitrary
template, generated history, deadline renewal or live-owner DTO is supported.
"""
from __future__ import annotations

import copy
import fcntl
import os

from scripts import native_pilot_runtime_artifacts as artifact
from scripts.authority import native_pilot_authority_io as io
from serverware import native_pilot_bootstrap_install as installation
from serverware import native_pilot_driver_authority as driver_authority
from serverware import native_pilot_scope_authority as scope
from serverware import native_pilot_window_authority as window_authority
from serverware import native_shadow_driver_bootstrap as driver
from serverware import native_shadow_nitro_originals as originals
from serverware.native_pilot_phase_execution import KEY_PURPOSES, MAX_APPROVAL

p = driver.p
MAX_POLICY = 4 * 1024 * 1024
POLICY_API = "serverware.nativePilotSupervisorCommissioningPolicy/v1"
PURPOSE = "initial-driver-bootstrap-and-endpoint-precreation"
FIELDS = ("apiVersion", "purpose", "source", "conductorInventorySha256", "authorityInventorySha256",
    "bootstrapOriginals", "keyBindings", "precreation")
MEASURED_POLICY_API = "serverware.nativePilotSupervisorCommissioningPolicy/v2"
MEASURED_PURPOSE = "initial-driver-bootstrap-precreation-and-measured-configuration"
MEASURED_FIELDS = FIELDS + ("measuredRecipeSha256",)
BOOTSTRAP_FIELDS = ("control", "configuration", "window", "deliveryConfiguration")
_TOKEN = object()
_USED = False
_LIVE = None


def _same(first, second):
    p.require(p.canonical(first) == p.canonical(second))


def _bootstrap_originals(value):
    supplied = p.fields(value, BOOTSTRAP_FIELDS)
    limits = (4096, 65536, 32768, 65536)
    raw = {name: scope._original(supplied[name], maximum)[0]
        for name, maximum in zip(BOOTSTRAP_FIELDS, limits, strict=True)}
    config = window_authority.validate_configuration(raw["configuration"])
    cold = window_authority.validate_delivery(config, raw["deliveryConfiguration"])
    control = installation.shape("driver-bootstrap-control", raw["control"])
    signed = installation.shape("driver-bootstrap-window", raw["window"])
    p.require(control["configurationSha256"] == p.sha(raw["configuration"])
        and control["windowSha256"] == p.sha(raw["window"]))
    window = signed["payload"]
    driver._key(config["bootstrapAuthority"]).verify(p.decoded(signed["signatureBase64url"], size=64),
        driver.WINDOW_DOMAIN + p.canonical(window))
    window_authority.validate_window(window, raw["configuration"], config,
        boot=originals._boot(), now=originals._clock())
    return raw, control, config, cold, window


class SupervisorPolicy:
    """Retained independent policy, bound once to an actual coordinator owner."""

    def __init__(self, token):
        p.require(token is _TOKEN)
        self._pid, self._start, self._boot = os.getpid(), originals._start(), originals._boot()
        self._fd = self._identity = self._raw = self._digest = self._value = None
        self._process = self._bindings = self._bootstrap = self._control = self._config = self._window = None
        self._last = originals._clock()
        self._failed = self._closed = self._bind_attempted = self._bootstrap_attempted = False
        self._bootstrap_input = None
        self._recipe = None
        self._recipe_attempted = self._measured_attempted = False

    @classmethod
    def open(cls, *, policy_fd: int, policy_sha256: str):
        global _USED, _LIVE
        p.require(cls is SupervisorPolicy and not _USED and _LIVE is None)
        _USED = True
        owner = cls(_TOKEN)
        _LIVE = owner
        try:
            identity = io._input(policy_fd, MAX_POLICY)
            owner._fd = fcntl.fcntl(policy_fd, fcntl.F_DUPFD_CLOEXEC, 3)
            owner._identity = identity
            p.require(io._input(owner._fd, MAX_POLICY) == identity)
            owner._raw = io.read_public(owner._fd, MAX_POLICY)
            owner._digest = p.digest(policy_sha256)
            p.require(p.sha(owner._raw) == owner._digest)
            value = p.document(owner._raw, MAX_POLICY)
            p.require(type(value) is dict and value.get("apiVersion") in (POLICY_API, MEASURED_POLICY_API))
            measured = value["apiVersion"] == MEASURED_POLICY_API
            p.fields(value, MEASURED_FIELDS if measured else FIELDS)
            p.require(value["purpose"] == (MEASURED_PURPOSE if measured else PURPOSE))
            if measured:
                p.digest(value["measuredRecipeSha256"])
            p.fields(value["source"], artifact.SOURCE_FIELDS)
            source = artifact._source(value["source"])
            for field in ("conductorInventorySha256", "authorityInventorySha256"):
                p.digest(value[field])
            keys = p.fields(value["keyBindings"], KEY_PURPOSES)
            for digest in keys.values():
                p.digest(digest)
            raw, control, config, cold, window = _bootstrap_originals(value["bootstrapOriginals"])
            # These public bindings select the existing purpose authorities,
            # not just whichever private capabilities happen to be supplied.
            admission_key = p.sha(p.decoded(config["lifecycle"]["constructedAdmissionAuthority"]["publicKeyBase64url"], size=32))
            p.require(keys["driver-bootstrap"] == keys["driver-constructed"] == admission_key
                and keys["driver-scope"] == config["phaseTwoAuthority"]["keyId"])
            from serverware.native_pilot_supervisor_precreation import validate_policy
            precreation = validate_policy(value["precreation"], bootstrap_configuration=config)
            _same(precreation["authority"], cold["authority"])
            p.require(keys["cohort-precreation"] == keys["cohort-release"] == precreation["authority"]["keyId"])
            owner._value = copy.deepcopy(value)
            owner._value["precreation"] = precreation
            owner._bootstrap, owner._control, owner._config, owner._window = raw, control, config, window
            owner._bindings = {"apiVersion": "serverware.nativePilotSupervisorBindings/v1",
                "conductorInventorySha256": value["conductorInventorySha256"],
                "authorityInventorySha256": value["authorityInventorySha256"],
                "source": source, "keyBindings": dict(keys)}
            owner.check()
            return owner
        except BaseException:
            owner._failed = True
            if owner._fd is not None:
                os.close(owner._fd)
            owner._closed = True
            _LIVE = None
            raise

    def check(self, process=None):
        p.require(type(self) is SupervisorPolicy and _LIVE is self and not self._closed and not self._failed
            and (self._pid, self._start, self._boot) == (os.getpid(), originals._start(), originals._boot()))
        p.require(io._input(self._fd, MAX_POLICY) == self._identity
            and io.read_public(self._fd, MAX_POLICY) == self._raw and p.sha(self._raw) == self._digest)
        now = originals._clock()
        p.require(self._last <= now < p.ns(self._window["lifetimeDeadlineBoottimeNs"]))
        self._last = now
        if process is not None:
            from serverware.native_pilot_supervisor_process import AuthorityCoordinatorProcess
            p.require(type(process) is AuthorityCoordinatorProcess and process is self._process)
        if self._process is not None:
            p.require(not self._process._closed)
            _same(self._process.policy_bindings(), self._bindings)
            if not self._process._started:
                window_authority.validate_window(self._window, self._bootstrap["configuration"], self._config,
                    boot=self._boot, now=now)

    def retain_measured_recipe(self, recipe):
        """Retain only the source-selected real recipe before process setup.

        Legacy policy forbids a recipe. v2 requires the already independently
        approved original pin, not future process-dependent configuration data.
        """
        from serverware.native_pilot_measured_configuration import MeasuredConfigurationRecipe
        self.check()
        p.require(not self._recipe_attempted and not self._bind_attempted and self._process is None)
        self._recipe_attempted = True
        try:
            if self._value["apiVersion"] == POLICY_API:
                p.require(recipe is None)
                return
            p.require(type(recipe) is MeasuredConfigurationRecipe)
            self._recipe = recipe  # Keep even a failed admission until close.
            recipe.require_original(self._value["measuredRecipeSha256"])
            self.check()
        except BaseException:
            self._failed = True
            raise

    def bind(self, process):
        from serverware.native_pilot_supervisor_process import AuthorityCoordinatorProcess
        self.check()
        p.require(not self._bind_attempted)
        self._bind_attempted = True
        try:
            p.require(type(process) is AuthorityCoordinatorProcess and not process._started)
            self._process = process  # Retain even when the binding subsequently fails.
            _same(process.policy_bindings(), self._bindings)
            retained = p.fields(process.bootstrap_originals(), BOOTSTRAP_FIELDS)
            p.require(all(type(retained[name]) is bytes and retained[name] == raw
                for name, raw in self._bootstrap.items()))
            if self._value["apiVersion"] == MEASURED_POLICY_API:
                p.require(self._recipe_attempted and self._recipe is not None)
                self._recipe.require_original(self._value["measuredRecipeSha256"])
                self._recipe.bind(process)
            self.check(process)
        except BaseException:
            self._failed = True
            raise

    def derive_measured(self, *, process, request):
        """Derive once at the genuine pending cohort-precreation request only."""
        self.check(process)
        if self._value["apiVersion"] == POLICY_API:
            return None
        p.require(not self._measured_attempted and self._recipe is not None)
        self._measured_attempted = True
        try:
            process.check_request(request)
            self._recipe.require_original(self._value["measuredRecipeSha256"])
            value = self._recipe.derive(process=process, request=request)
            self.check(process)
            process.check_request(request)
            return value
        except BaseException:
            self._failed = True
            raise

    def measured_configuration(self, *, process, request) -> dict:
        """Checked retained result for a fixed downstream startup composer.

        This returns derived public data, not permission to approve a new job.
        The actual pending request and original startup allowance are required.
        """
        self.check(process)
        p.require(self._value["apiVersion"] == MEASURED_POLICY_API
            and self._recipe is not None and self._measured_attempted)
        value = self._recipe.result(process=process, request=request)
        self.check(process)
        process.check_request(request)
        return value

    def precreation(self):
        self.check()
        return copy.deepcopy(self._value["precreation"])

    def bootstrap_originals(self):
        self.check()
        return dict(self._bootstrap)

    def bootstrap_input_original(self):
        self.check()
        p.require(self._bootstrap_input is not None)
        return self._bootstrap_input

    def bootstrap(self, process, request) -> tuple[bytes, bytes]:
        """Decide one complete initial input and approval8; never install/sign."""
        from serverware.native_pilot_supervisor_process import AuthorityCoordinatorProcess, JobRequest
        self.check(process)
        p.require(not self._bootstrap_attempted)
        self._bootstrap_attempted = True
        try:
            p.require(type(process) is AuthorityCoordinatorProcess and type(request) is JobRequest)
            process.check_request(request)
            ticket = p.fields(p.document(request.raw, 32 * 1024 * 1024 - 1), ("apiVersion", "sequence",
                "conductorSequence", "conductorRequestSha256", "phase", "jobIndex", "job",
                "deadlineBoottimeNs", "conductorRequest", "previousResult"))
            _same(ticket, request.value)
            p.require(ticket["apiVersion"] == "serverware.nativePilotAuthorityJobRequest/v1"
                and p.integer(ticket["sequence"], maximum=1) == p.integer(ticket["conductorSequence"], maximum=1)
                == p.integer(ticket["jobIndex"], maximum=1) == 1
                and ticket["phase"] == "bootstrap-admission" and ticket["job"] == "driver-bootstrap"
                and ticket["previousResult"] is None
                and ticket["deadlineBoottimeNs"] == self._window["startupDeadlineBoottimeNs"])
            conductor = p.fields(ticket["conductorRequest"], ("apiVersion", "sequence", "phase", "payload", "deadlineBoottimeNs"))
            p.require(conductor["apiVersion"] == "serverware.nativePilotOperatorRequest/v1"
                and p.integer(conductor["sequence"], maximum=1) == 1
                and conductor["phase"] == ticket["phase"] and conductor["deadlineBoottimeNs"] == ticket["deadlineBoottimeNs"]
                and p.sha(p.canonical(conductor)) == p.digest(ticket["conductorRequestSha256"]))
            payload = p.fields(conductor["payload"], ("bootstrapObservationOriginal", "admissionPayloadOriginal"))
            retained = p.fields(process.bootstrap_originals(), BOOTSTRAP_FIELDS)
            p.require(all(type(retained[name]) is bytes and retained[name] == raw for name, raw in self._bootstrap.items()))
            now = originals._clock()
            window_authority.validate_window(self._window, self._bootstrap["configuration"], self._config,
                boot=self._boot, now=now)
            observed_raw, _ = scope._original(payload["bootstrapObservationOriginal"], 65536)
            admission_raw, admitted = scope._original(payload["admissionPayloadOriginal"], 8192)
            selected = self._config["lifecycle"]["constructedAdmissionAuthority"]
            driver_authority._bootstrap(admitted, observed_raw, self._control, self._window, selected)
            observed = driver_authority._observation(observed_raw, self._control, self._config, self._window, now)
            p.require(admitted["parent"]["processId"] != observed["processId"])
            live, wall = scope._live(self._window, admitted)
            p.require(now <= live)
            p.freshness(admitted["issuedAtUnixNanos"], admitted["expiresAtUnixNanos"], wall, 30_000_000_000)
            value = {"apiVersion": "serverware.nativePilotDriverAuthorityInput/v1", "operation": "bootstrap",
                **{name + "Original": raw.decode("ascii") for name, raw in self._bootstrap.items()},
                "payloadOriginal": admission_raw.decode("ascii"), "observationOriginal": observed_raw.decode("ascii")}
            input_raw = p.canonical(value)
            p.fields(p.document(input_raw, driver_authority.MAX_INPUT), driver_authority.INPUT_FIELDS + ("observationOriginal",))
            approval_raw = p.canonical({"apiVersion": "serverware.nativePilotAuthorityJobApproval/v1",
                **{name: ticket[name] for name in ("conductorSequence", "conductorRequestSha256", "phase",
                    "jobIndex", "job", "deadlineBoottimeNs")}, "inputSha256": p.sha(input_raw)})
            p.require(len(approval_raw) <= MAX_APPROVAL)
            process.check_request(request)
            self.check(process)
            scope._live(self._window, admitted, live, wall)
            self._bootstrap_input = input_raw
            return input_raw, approval_raw
        except BaseException:
            self._failed = True
            raise

    def close(self):
        """Release only this public policy after actual process cleanup proof."""
        global _LIVE
        if self._closed:
            return
        p.require(type(self) is SupervisorPolicy and _LIVE is self
            and (self._pid, self._start, self._boot) == (os.getpid(), originals._start(), originals._boot()))
        if self._process is not None:
            from serverware.native_pilot_supervisor_process import AuthorityCoordinatorProcess
            p.require(type(self._process) is AuthorityCoordinatorProcess and self._process._closed
                and self._process._result["status"] in ("not-started", "stopped-cleanup-complete", "failed-cleanup-complete"))
        if self._recipe is not None:
            self._recipe.close()
        os.close(self._fd)
        self._closed = True
        _LIVE = None
