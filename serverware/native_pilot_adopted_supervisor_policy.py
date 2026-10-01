"""Independent selected policy for externally approved adopted commissioning.

This retains public policy/intake/recipe originals. It does not turn public
validation into approval and contains no fallback to legacy supervisor scopes.
Every dynamic job still requires its own protected independent Approval2.
"""
from __future__ import annotations

import copy
import fcntl
import os
import time

from scripts import native_pilot_runtime_artifacts as artifacts
from scripts.authority import native_pilot_authority_io as io
from serverware import native_pilot_adopted_intake as intake
from serverware import native_pilot_adopted_phase_profile as profile
from serverware import native_pilot_genesis_parent_control_io as ownership
from serverware import native_pilot_interactive as interactive
from serverware import native_pilot_supervisor_policy as legacy
from serverware import native_shadow_nitro_originals as originals

p = profile.p
API = "serverware.nativePilotAdoptedSupervisorPolicy/v1"
PURPOSE = "independently-approved-adopted-native-commissioning"
INTERACTIVE_API = "serverware.nativePilotAdoptedSupervisorPolicy/v2"
INTERACTIVE_PURPOSE = "independently-approved-adopted-native-commissioning-through-bounded-interactive-shutdown"
MAX_POLICY = 4 * 1024 * 1024
FIELDS = ("apiVersion", "purpose", "source", "conductorInventorySha256", "authorityInventorySha256",
    "catalogueSha256", "bootstrapOriginals", "keyBindings", "measuredRecipeSha256",
    "intakeConfigurationOriginal", "intakeConfigurationSha256")
_TOKEN, _USED, _LIVE = object(), False, None


def catalogue_original():
    return p.canonical({"apiVersion": "serverware.nativePilotAdoptedSupervisorCatalogue/v1",
        "phases": [{"phase": phase, "jobs": [{"name": job.name, "family": job.family,
            "role": job.role, "maximum": job.maximum, "purpose": job.purpose, "key": job.key}
            for job in jobs]} for phase, jobs in profile.JOBS.items()], "keyPurposes": list(profile.KEY_PURPOSES)})


def shape(raw):
    value = p.document(raw, MAX_POLICY)
    p.require(type(value) is dict)
    selected = value.get("apiVersion") == INTERACTIVE_API
    p.fields(value, FIELDS + (("interactive",) if selected else ()))
    p.require(value["apiVersion"] == (INTERACTIVE_API if selected else API)
        and value["purpose"] == (INTERACTIVE_PURPOSE if selected else PURPOSE)
        and value["catalogueSha256"] == p.sha(catalogue_original()))
    artifacts._source(p.fields(value["source"], artifacts.SOURCE_FIELDS))
    for field in ("conductorInventorySha256", "authorityInventorySha256", "measuredRecipeSha256",
            "intakeConfigurationSha256"):
        p.digest(value[field])
    p.fields(value["keyBindings"], profile.KEY_PURPOSES)
    for digest in value["keyBindings"].values():
        p.digest(digest)
    p.fields(value["bootstrapOriginals"], legacy.BOOTSTRAP_FIELDS)
    text = value["intakeConfigurationOriginal"]
    p.require(type(text) is str and text.isascii() and 0 < len(text) <= intake.MAX_CONFIGURATION
        and p.sha(text.encode("ascii")) == value["intakeConfigurationSha256"])
    if selected:
        interactive.validate_policy(value["interactive"])
    return copy.deepcopy(value)


def require_shutdown(value, action, *, origin_handoff, deadline_boottime_ns,
        expires_at_unix_ns, now_boottime_ns, now_unix_ns):
    """Join an independently supplied action to the retained policy selection.

    This pure check grants no authority. The caller owns the protected policy,
    actual request and separately approved action; the phase validator also
    clips the interval to the authenticated service/cohort predecessor bounds.
    """
    selected = value["apiVersion"] == INTERACTIVE_API
    p.require(value["apiVersion"] == (INTERACTIVE_API if selected else API)
        and value["purpose"] == (INTERACTIVE_PURPOSE if selected else PURPOSE))
    p.require(type(action) is dict)
    if action.get("action") == "stop":
        p.fields(action, ("action",))
        return copy.deepcopy(action)
    p.require(selected)
    policy = interactive.validate_policy(value["interactive"])
    checked = interactive.validate_action(action, origin_handoff=origin_handoff)
    p.require(all(checked[name] == policy[name] for name in interactive.FIELDS[1:]))
    stop, expiry = checked["stopAtBoottimeNanos"], checked["expiresAtUnixNanos"]
    p.require(now_boottime_ns < stop < p.integer(deadline_boottime_ns, maximum=p.MAX_U64)
        and now_unix_ns < expiry <= p.integer(expires_at_unix_ns)
        and stop - now_boottime_ns < expiry - now_unix_ns)
    return checked


class PolicyError(ValueError):
    def __init__(self, owner):
        super().__init__("adopted supervisor policy refused; retained owner requires cleanup")
        self.owner = owner


class AdoptedSupervisorPolicy:
    def __init__(self, token):
        p.require(token is _TOKEN)
        self._pid, self._start, self._boot = os.getpid(), originals._start(), originals._boot()
        self._last, self._wall = originals._clock(), time.time_ns()
        self._fd = self._identity = self._raw = self._sha = self._value = None
        self._process = self._recipe = self._window = self._bootstrap = self._intake = None
        self._failed = self._closed = self._bound = self._recipe_attempted = self._derived = False

    @classmethod
    def open(cls, *, policy_fd, policy_sha256):
        global _USED, _LIVE
        p.require(cls is AdoptedSupervisorPolicy and not _USED and _LIVE is None)
        _USED = True
        owner = cls(_TOKEN)
        _LIVE = owner
        try:
            io._process()
            with ownership.owning():
                identity = io._input(policy_fd, MAX_POLICY)
                owner._fd = fcntl.fcntl(policy_fd, fcntl.F_DUPFD_CLOEXEC, 3)
                owner._identity = identity
            p.require(io._input(owner._fd, MAX_POLICY) == identity)
            owner._raw, owner._sha = io.read_public(owner._fd, MAX_POLICY), p.digest(policy_sha256)
            p.require(p.sha(owner._raw) == owner._sha)
            owner._value = value = shape(owner._raw)
            owner._bootstrap, _, config, cold, owner._window = legacy._bootstrap_originals(value["bootstrapOriginals"])
            owner._intake_raw = value["intakeConfigurationOriginal"].encode("ascii")
            owner._intake = intake.validate_configuration(owner._intake_raw, boot=owner._boot,
                now_boottime_ns=originals._clock(), now_unix_ns=time.time_ns())
            for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode"):
                p.require(owner._intake[name] == owner._window[name])
            owner._deadline = min(p.ns(owner._intake["lifetimeDeadlineBoottimeNs"]),
                p.ns(owner._window["lifetimeDeadlineBoottimeNs"]))
            owner._startup = min(p.ns(owner._intake["startupDeadlineBoottimeNs"]),
                p.ns(owner._window["startupDeadlineBoottimeNs"]))
            p.require(originals._clock() < min(owner._startup, owner._deadline - 250_000_000))
            owner._interactive_deadline = owner._deadline - max(interactive.COHORT_REAP_RESERVE_NS,
                p.integer(config["lifecycle"]["cleanupReserveNanos"], minimum=1_000_000, maximum=5_000_000_000))
            if value["apiVersion"] == INTERACTIVE_API:
                interval = value["interactive"]
                now, wall = originals._clock(), time.time_ns()
                p.require(now < interval["stopAtBoottimeNanos"] < owner._interactive_deadline
                    and wall < interval["expiresAtUnixNanos"] <= owner._intake["expiresAtUnixNanos"]
                    and interval["stopAtBoottimeNanos"] - now < interval["expiresAtUnixNanos"] - wall)
            selected = config["lifecycle"]["constructedAdmissionAuthority"]
            keys = value["keyBindings"]
            p.require(keys["driver-bootstrap"] == keys["driver-constructed"]
                == p.sha(p.decoded(selected["publicKeyBase64url"], size=32))
                and keys["driver-scope"] == config["phaseTwoAuthority"]["keyId"])
            owner._bindings = {"apiVersion": "serverware.nativePilotSupervisorBindings/v2",
                **{name: copy.deepcopy(value[name]) for name in ("source", "conductorInventorySha256",
                    "authorityInventorySha256", "keyBindings", "intakeConfigurationSha256")}}
            owner.check()
            return owner
        except BaseException as error:
            owner._failed = True
            raise PolicyError(owner) from error

    def _origin(self):
        p.require(type(self) is AdoptedSupervisorPolicy and _LIVE is self and not self._closed
            and (self._pid, self._start, self._boot) == (os.getpid(), originals._start(), originals._boot()))

    def check(self, process=None):
        self._origin()
        p.require(not self._failed and io._input(self._fd, MAX_POLICY) == self._identity
            and io.read_public(self._fd, MAX_POLICY) == self._raw
            and io._input(self._fd, MAX_POLICY) == self._identity and p.sha(self._raw) == self._sha)
        if process is not None:
            p.require(process is self._process)
        if self._process is not None:
            p.require(self._process.adoption_selected() and not self._process._closed
                and self._process.policy_bindings() == self._bindings
                and self._process.intake_configuration_original() == self._intake_raw)
        # Sample after all retained-original and process identity I/O.
        now, epoch = originals._clock(), time.time_ns()
        p.require(self._last <= now < self._deadline
            and self._wall <= epoch < self._intake["expiresAtUnixNanos"])
        self._last, self._wall = now, epoch

    def retain_measured_recipe(self, recipe):
        from serverware.native_pilot_measured_configuration import MeasuredConfigurationRecipe
        self.check()
        p.require(not self._recipe_attempted and not self._bound and type(recipe) is MeasuredConfigurationRecipe)
        self._recipe_attempted = True
        self._recipe = recipe
        recipe.require_original(self._value["measuredRecipeSha256"], adopted=True)
        self.check()

    def bind(self, process):
        from serverware.native_pilot_supervisor_process import AuthorityCoordinatorProcess
        self.check()
        p.require(not self._bound and type(process) is AuthorityCoordinatorProcess and process.adoption_selected()
            and not process._started and self._recipe_attempted and self._recipe is not None)
        self._bound, self._process = True, process
        p.require(process.policy_bindings() == self._bindings
            and process.bootstrap_originals() == self._bootstrap
            and process.intake_configuration_original() == self._intake_raw)
        self._recipe.bind(process)
        self.check(process)

    def require_final_scope(self, process):
        self.check(process)
        p.require(self._bound and self._recipe is not None)
        self._recipe.require_original(self._value["measuredRecipeSha256"], adopted=True)
        p.require(self._value["catalogueSha256"] == p.sha(catalogue_original()))
        self.check(process)

    def derive_measured(self, *, process, request):
        self.check(process)
        p.require(not self._derived)
        self._derived = True
        result = self._recipe.derive(process=process, request=request)
        self.check(process)
        return result

    def observation(self, *, process, request):
        self.check(process); process.check_request(request)
        from serverware.native_pilot_measured_configuration import RESULT_PHASES
        measured = recipe = None
        if self._derived and request.phase in RESULT_PHASES:
            measured = self._recipe.result(process=process, request=request, adopted=True)
            recipe = self._recipe.public_originals(process=process, request=request, adopted=True)
        value = {"apiVersion": "serverware.nativePilotAdoptedSupervisorObservation/v1",
            "policySha256": self._sha, "catalogueSha256": self._value["catalogueSha256"],
            "intakeConfigurationSha256": self._value["intakeConfigurationSha256"],
            "conductorRequestOriginal": p.canonical(process.conductor_request(request.phase)).decode("ascii"),
            "measuredConfiguration": measured, "recipeOriginals": recipe}
        self.check(process); process.check_request(request)
        return p.canonical(value)

    def require_input(self, raw, *, process, request):
        """Join selected assignment-bearing inputs to this actual Recipe3.

        This is an additional policy pin check, not recursive JSON admission;
        the fixed producer still authenticates the complete input afterwards.
        """
        self.check(process); process.check_request(request)
        job = profile.BY_NAME[request.job][1]
        if job.family == "stop":
            action = p.document(raw, job.maximum)
            observed = process.conductor_request(request.phase)["payload"]
            require_shutdown(self._value, action, origin_handoff=observed["originHandoff"],
                deadline_boottime_ns=min(request.deadline_boottime_ns, self._interactive_deadline),
                expires_at_unix_ns=min(p.ns(request.value["expiresAtUnixNanos"]), self._intake["expiresAtUnixNanos"]),
                now_boottime_ns=originals._clock(), now_unix_ns=time.time_ns())
            self.check(process); process.check_request(request)
            return
        selected = job.family in ("native-key", "adoption", "endpoint-inputs") or (
            job.family == "bridge-authorization" and job.role in ("role-keys", "admission"))
        # The bridge catalogue stores its operation in a separate exact map.
        if job.family == "bridge-authorization":
            selected = profile.legacy.BRIDGE_AUTHORIZATION_JOB_INFO[job.name] in ("role-keys", "admission")
        if not selected:
            return
        p.require(self._derived)
        measured = self._recipe.result(process=process, request=request, adopted=True)
        recipe = self._recipe.public_originals(process=process, request=request, adopted=True)
        value = p.document(raw, job.maximum)
        if job.family in ("native-key", "bridge-authorization"):
            p.require(value["recipeOriginals"] == recipe and value["measured"] == measured)
        elif job.family == "adoption":
            from serverware import native_pilot_publication_adoption_profile as adoption
            native = p.fields(p.document(adoption.original(value["validationInputOriginal"], adoption.MAX_INPUT),
                adoption.MAX_INPUT), adoption.INPUT_FIELDS)
            for field, original in (("currentAssignmentOriginal", "assignmentOriginal"),
                    ("currentTrustOriginal", "trustOriginal"), ("currentTrustSha256", "trustSha256"),
                    ("currentClosureSetOriginal", "closureSetOriginal")):
                p.require(native[field] == recipe[original])
            p.require(native["currentConfigurationBindingSha256"] == measured["configurationBindingSha256"]
                and native["currentProofScopeOriginal"] == measured["proofScopeOriginal"])
        else:
            p.require(value["production"] == measured["production"]
                and value["proofScope"]["sha256"] == p.sha(measured["proofScopeOriginal"].encode("ascii"))
                and value["assignment"]["sha256"] == p.sha(recipe["assignmentOriginal"].encode("ascii")))
        self.check(process); process.check_request(request)

    def close(self):
        global _LIVE
        if self._closed:
            return
        self._origin()
        if self._process is not None:
            p.require(self._process._closed and self._process._result["status"] in
                ("not-started", "stopped-cleanup-complete", "failed-cleanup-complete"))
        if self._recipe is not None:
            self._recipe.close()
        with ownership.owning():
            fd, self._fd = self._fd, None
            if fd is not None:
                os.close(fd)
            self._closed, _LIVE = True, None
