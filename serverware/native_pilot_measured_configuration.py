"""Actual-owner derivation of explicitly versioned native configuration binding.

The independently approved root-protected recipe is retained before spawn.
Only the real coordinator's bootstrap observation supplies process-dependent
values. Legacy v1 preserves its single bridge closure; recipe v2 additionally
authenticates the complete closure set under assignment v2. It emits unsigned derived data,
never a receipt, object store, authorization, native admission or readiness.
Explicit recipe v3 selects the twelve-member adopted set. Its native binding,
proof scope and derived data remain v2; the independently approved recipe
original, not a guessed process or changed runtime tag, selects that set.
"""
from __future__ import annotations

import copy
import fcntl
import os
import time

from scripts import native_pilot_runtime_artifacts as artifact
from scripts.authority import native_pilot_authority_io as io
from serverware import authority_policy_canary_native_opening as opening
from serverware import native_pilot_assignment as assignments
from serverware import native_pilot_closure_authority as closure
from serverware import native_pilot_closure_set as closure_set
from serverware import native_pilot_delivery_authority as c9
from serverware import native_pilot_driver_authority as driver_authority
from serverware import native_pilot_launch_publication as launch
from serverware import native_pilot_publication as publication
from serverware import native_pilot_scope_authority as scope
from serverware import native_shadow_constructed_driver as admission
from serverware import native_shadow_driver_bootstrap as driver
from serverware import native_shadow_nitro_originals as originals
from serverware import native_shadow_retrieval_artifacts as retrieval

p = driver.p
MAX_RECIPE = 8 * 1024 * 1024
LEGACY_API = "serverware.nativePilotMeasuredConfigurationRecipe/v1"
SET_API = "serverware.nativePilotMeasuredConfigurationRecipe/v2"
ADOPTED_API = "serverware.nativePilotMeasuredConfigurationRecipe/v3"
FIELDS = ("apiVersion", "source", "conductorInventorySha256", "authorityInventorySha256",
    "bootstrapOriginals", "assignmentOriginal", "trustOriginal", "trustSha256",
    "closureManifestOriginal", "production")
SET_FIELDS = FIELDS + ("closureSetOriginal",)
RESULT_PHASES = ("endpoint-precreation", "endpoint-inputs", "endpoint-deliveries", "service-originals",
    "bridge-runtime", "bridge-delivery", "release", "constructed-admission")
PRODUCTION_FIELDS = scope.PRODUCTION_FIELDS[:-1]
OPERATIONS = (
    "recover-current-state", "verify-checkpoint-successor", "verify-current-checkpoint-head", "verify-observation-evidence",
    "prepare-generation-publication", "commit-generation-publication", "abort-generation-publication", "begin-ingress",
    "reserve-spool-append", "append-spool-event", "compact-spool", "commit-request", "append-active-effect-barrier",
    "commit-active-effect", "reconcile-active-effect", "append-terminal", "consume-and-publish-activation",
)
_TOKEN = object()
_USED = False
_LIVE = None


def _production(value):
    p.fields(value, PRODUCTION_FIELDS)
    for name in PRODUCTION_FIELDS[:4]:
        p.digest(value[name])
    p.integer(value["maximumRpcNanos"], minimum=250_000_000, maximum=1_000_000_000)
    p.integer(value["cleanupReserveNanos"], maximum=5_000_000_000)
    p.integer(value["maximumInFlightCalls"], maximum=64)
    p.integer(value["maximumAsyncDurabilityNanos"], maximum=value["maximumRpcNanos"])


def _assignment(value, now):
    """Authenticate existing assignment/key material against independently pinned trust."""
    trust_raw, _ = scope._original(value["trustOriginal"], 1024 * 1024)
    p.require(p.sha(trust_raw) == p.digest(value["trustSha256"]))
    trust = launch.shape("native-bridge-trust", trust_raw)
    p.freshness(trust["issuedAtUnixNanos"], trust["expiresAtUnixNanos"], now)
    checkpoint = trust["checkpoint"]
    p.digest(checkpoint["checkpointId"]); p.digest(checkpoint["revocationRootSha256"])
    p.integer(checkpoint["revocationGeneration"], minimum=0, maximum=p.MAX_U64)
    p.require(p.integer(checkpoint["asOfUnixNanos"]) <= now < checkpoint["asOfUnixNanos"] + 300_000_000_000)
    assignment_key = launch._key(trust["assignmentKey"], now)
    launch._key(trust["timeKey"], now)
    material = {trust["assignmentKey"]["publicKeyBase64url"], trust["timeKey"]["publicKeyBase64url"]}
    p.require(len(material) == 2)
    keys = {}
    for row in trust["roleKeys"]:
        role, key = row["role"], row["key"]
        p.require(type(role) is str and role.isascii() and 1 <= len(role) <= 128
            and role not in keys and key["publicKeyBase64url"] not in material)
        launch._key(key, now)
        material.add(key["publicKeyBase64url"]); keys[role] = key
    p.require(set(p.ROLES).issubset(keys))
    raw, _ = scope._original(value["assignmentOriginal"], 4 * 1024 * 1024)
    envelope = launch.shape("native-bridge-assignment", raw)
    p.require(value["apiVersion"] in (LEGACY_API, SET_API, ADOPTED_API))
    selected = 1 if value["apiVersion"] == LEGACY_API else 2
    p.require(assignments.version(envelope) == selected)
    assignment = opening.assignment_payload(envelope["payload"], version=selected)
    p.require(envelope["signingKeyId"] == trust["assignmentKey"]["keyId"]
        and envelope["signingKeySpkiSha256"] == trust["assignmentKey"]["keySpkiSha256"])
    assignment_key.verify(p.decoded(envelope["signature"], size=64),
        p.preimage(assignments.domain(envelope), assignment))
    p.freshness(assignment["issuedAtUnixNanos"], assignment["expiresAtUnixNanos"], now)
    p.digest(assignment["assignmentId"])
    p.integer(assignment["assignmentRevision"], maximum=p.MAX_U64)
    _, key_root = opening._keys(assignment)
    bindings = {}
    for role in p.ROLES:
        rows = [row for row in assignment["authorityKeyIndependence"]["bindings"]
            if row["role"] == role and row["scopeSha256"] == assignment["assignmentId"]]
        p.require(len(rows) == 1)
        row, key = rows[0], keys[role]
        p.require(row["keyId"] == key["keyId"] and row["keySpkiSha256"] == key["keySpkiSha256"])
        public = {name: row[name] for name in ("role", "keyId", "keySpkiSha256", "keyMaterialSha256")}
        p.public_key(public | {"publicKeyBase64url": key["publicKeyBase64url"]})
        bindings[role] = public
    p.require(p.key_root([bindings[role] for role in p.ROLES]) == key_root)
    return envelope, bindings, key_root


def _closure_set(value, envelope, manifest):
    """Authenticate common roots without changing the measured bridge leaf."""
    text = value["closureSetOriginal"]
    p.require(type(text) is str and text.isascii() and 0 < len(text) <= closure_set.MAX_BYTES)
    raw = text.encode("ascii")
    p.require(value["apiVersion"] in (SET_API, ADOPTED_API))
    set_api = closure_set.PUBLICATION_API if value["apiVersion"] == ADOPTED_API else closure_set.API
    selected = closure_set.validate(raw, api_version=set_api)
    binding = assignments.closure_binding(envelope, raw, "bridge", set_api_version=set_api)
    p.require(p.canonical(selected["members"][-1]["manifest"]) == p.canonical(manifest)
        and binding["manifestSha256"] == manifest["manifestSha256"])
    return envelope["payload"]["nativeClosureSet"]


def _phase(process, phase):
    adopted = process.adoption_selected()
    value = p.fields(process.conductor_request(phase),
        ("apiVersion", "sequence", "phase", "payload", "deadlineBoottimeNs")
        + (("expiresAtUnixNanos",) if adopted else ()))
    p.require(value["apiVersion"] == "serverware.nativePilotOperatorRequest/v" + ("2" if adopted else "1")
        and value["phase"] == phase)
    if adopted:
        p.require(time.time_ns() < p.ns(value["expiresAtUnixNanos"]))
    p.ns(value["deadlineBoottimeNs"])
    return value


def derive_configuration(*, envelope, keys, key_root, manifest, observed,
                         production, window, recipe_sha, successor):
    """Pure native hash recipe over already authenticated public originals.

    This is data derivation, not recipe approval, a live observation or an owner.
    The retained recipe and bridge issuer each authenticate their own inputs.
    """
    p.require(type(successor) is bool)
    p.digest(recipe_sha)
    _production(production)
    assignment = envelope["payload"]
    authority = assignment["custodyAuthority"]
    binding = {"assignmentId": assignment["assignmentId"], "assignmentPayloadSha256": envelope["payloadSha256"],
        "assignmentRevision": assignment["assignmentRevision"], "authorityId": authority["authorityId"],
        "storageRealmSha256": authority["storageRealmSha256"], "retrievalNamespaceSha256": authority["retrievalNamespaceSha256"],
        "authorityKeyIndependenceSha256": assignment["authorityKeyIndependence"]["independenceRootSha256"],
        "attestationMode": authority["attestationMode"],
        "supervisorInstanceSha256": p.sha(window["invocationId"].encode("ascii")),
        "supervisorBootIdSha256": p.sha(p.decoded(window["bootIdBase64url"], size=16)),
        "executionClosureManifestSha256": manifest["manifestSha256"],
        "structurallyVerifiedSeccompPolicySha256": manifest["seccompPolicy"]["structurallyVerifiedPolicySha256"],
        "workerExecutableSha256": manifest["workerExecutableSha256"], **production,
        "operationCoverageRootSha256": p.framed(b"serverware.policyShadowCustodyOperationCoverage/v1", (p.canonical(OPERATIONS),)),
        "kernelRetainedDriverIdentitySha256": observed["driver"]["identitySha256"],
        "assertedCustodyKeySetRootSha256": key_root}
    p.require(len(binding) == 24)
    version = "2" if successor else "1"
    if successor:
        binding["nativeClosureSet"] = copy.deepcopy(assignment["nativeClosureSet"])
        p.require(len(binding) == 25)
    binding_raw = p.canonical(binding)
    binding_sha = p.framed(("serverware.policyShadowProductionCustodyConfiguration/v" + version).encode("ascii"), (binding_raw,))
    proof_values = (assignment["assignmentId"], envelope["payloadSha256"], assignment["assignmentRevision"],
        authority["authorityId"], authority["storageRealmSha256"], authority["retrievalNamespaceSha256"],
        assignment["authorityKeyIndependence"]["independenceRootSha256"], binding_sha, key_root,
        manifest["manifestSha256"], manifest["seccompPolicy"]["structurallyVerifiedPolicySha256"])
    proof = dict(zip(retrieval.SCOPE_VALUES, proof_values, strict=True))
    if successor:
        roots = assignment["nativeClosureSet"]
        proof["api_version"] = retrieval.SCOPE_SET_API
        proof.update(zip(retrieval.SCOPE_SET_VALUES, (roots["setRootSha256"], roots["seccompSetRootSha256"]), strict=True))
        proof_values += (roots["setRootSha256"], roots["seccompSetRootSha256"])
    proof["store_response_authority"] = {name: keys["custody-store-response"][source] for name, source in
        (("role", "role"), ("key_id", "keyId"), ("key_spki_sha256", "keySpkiSha256"), ("key_material_sha256", "keyMaterialSha256"))}
    proof["retrieval_response_authority"] = {name: keys["custody-retrieval-response"][source] for name, source in
        (("role", "role"), ("key_id", "keyId"), ("key_spki_sha256", "keySpkiSha256"), ("key_material_sha256", "keyMaterialSha256"))}
    proof["binding_sha256"] = p.framed(("serverware.policyShadowProductionCustodyProofScope/v" + version).encode("ascii"),
        (p.canonical(proof_values),))
    proof_raw = p.canonical(proof)
    retrieval.scope_original(proof_raw)
    if successor:
        retrieval.require_assignment_scope(proof, p.canonical(assignment))
    return {"apiVersion": "serverware.nativePilotMeasuredConfiguration/v" + version, "recipeSha256": recipe_sha,
        "configurationBindingOriginal": binding_raw.decode("ascii"), "configurationBindingSha256": binding_sha,
        "proofScopeOriginal": proof_raw.decode("ascii"),
        "production": {**production, "expectedConfigurationBindingSha256": binding_sha}}


class RecipeError(ValueError):
    def __init__(self, owner):
        super().__init__("measured recipe cleanup unknown; actual owner retained")
        self.owner = owner


class MeasuredConfigurationRecipe:
    """One retained independently approved recipe, one actual prebound process."""

    def __init__(self, token):
        p.require(token is _TOKEN)
        self._pid, self._start, self._boot = os.getpid(), originals._start(), originals._boot()
        self._fd = self._identity = self._raw = self._sha = self._value = None
        self._bootstrap = self._control = self._config = self._window = self._source = None
        self._process = self._result = None
        self._derived_sequence = self._derived_phase_sha256 = None
        self._last, self._wall = originals._clock(), time.time_ns()
        self._failed = self._closed = self._bind_attempted = self._derive_attempted = False
        self._close_uncertain = False

    @classmethod
    def open(cls, *, recipe_fd: int, recipe_sha256: str):
        global _USED, _LIVE
        p.require(cls is MeasuredConfigurationRecipe and not _USED and _LIVE is None)
        _USED = True
        io._process()
        owner = cls(_TOKEN)
        _LIVE = owner
        try:
            owner._identity = io._input(recipe_fd, MAX_RECIPE)
            owner._fd = fcntl.fcntl(recipe_fd, fcntl.F_DUPFD_CLOEXEC, 3)
            p.require(io._input(owner._fd, MAX_RECIPE) == owner._identity)
            owner._raw = io.read_public(owner._fd, MAX_RECIPE)
            owner._sha = p.digest(recipe_sha256)
            p.require(p.sha(owner._raw) == owner._sha)
            value = p.document(owner._raw, MAX_RECIPE)
            p.require(type(value) is dict and value.get("apiVersion") in (LEGACY_API, SET_API, ADOPTED_API))
            successor = value["apiVersion"] != LEGACY_API
            p.fields(value, SET_FIELDS if successor else FIELDS)
            owner._source = artifact._source(p.fields(value["source"], artifact.SOURCE_FIELDS))
            for name in ("conductorInventorySha256", "authorityInventorySha256"):
                p.digest(value[name])
            from serverware.native_pilot_supervisor_policy import _bootstrap_originals
            raw, control, config, _, window = _bootstrap_originals(value["bootstrapOriginals"])
            _production(value["production"])
            envelope, _, _ = _assignment(value, time.time_ns())
            manifest_raw, manifest = scope._original(value["closureManifestOriginal"], closure.MAX_BYTES)
            p.fields(manifest, closure.MANIFEST_FIELDS)
            p.require(manifest["apiVersion"] == "serverware.nativeCustodyExecutionClosure/v2"
                and manifest["profile"] == closure.PROFILE and len(manifest_raw) <= closure.MAX_BYTES)
            if successor:
                _closure_set(value, envelope, manifest)
            owner._value = copy.deepcopy(value)
            owner._bootstrap, owner._control, owner._config, owner._window = raw, control, config, window
            owner.check()
            return owner
        except BaseException:
            owner._failed = True
            try:
                owner._retire_descriptor()
            except BaseException as error:
                raise RecipeError(owner) from error
            owner._closed = True
            _LIVE = None
            raise

    def check(self):
        p.require(type(self) is MeasuredConfigurationRecipe and _LIVE is self
            and not self._closed and not self._failed
            and (self._pid, self._start, self._boot) == (os.getpid(), originals._start(), originals._boot()))
        p.require(io._input(self._fd, MAX_RECIPE) == self._identity
            and io.read_public(self._fd, MAX_RECIPE) == self._raw and p.sha(self._raw) == self._sha)
        now, wall = c9._live(self._window, self._last), time.time_ns()
        p.require(self._wall <= wall)
        self._last, self._wall = now, wall
        _assignment(self._value, wall)
        if self._process is not None:
            bindings = self._process.policy_bindings()
            c9._same(bindings["source"], self._source)
            for name in ("conductorInventorySha256", "authorityInventorySha256"):
                p.require(bindings[name] == self._value[name])
            retained = self._process.bootstrap_originals()
            p.fields(retained, tuple(self._bootstrap))
            p.require(all(retained[name] == raw for name, raw in self._bootstrap.items()))

    def bind(self, process):
        from serverware.native_pilot_supervisor_process import AuthorityCoordinatorProcess
        self.check()
        p.require(not self._bind_attempted)
        self._bind_attempted = True
        try:
            p.require(type(process) is AuthorityCoordinatorProcess and not process._started)
            p.require(process.adoption_selected() == (self._value["apiVersion"] == ADOPTED_API))
            self._process = process
            self.check()
        except BaseException:
            self._failed = True
            raise

    def require_original(self, expected_sha256: str, *, adopted=False):
        """Check the actual v2 original against a separately admitted policy pin.

        The calling policy owns approval of this digest. This method neither
        selects that policy nor infers approval from a self-computed hash.
        """
        self.check()
        p.require(type(adopted) is bool and self._value["apiVersion"] == (ADOPTED_API if adopted else SET_API)
            and self._sha == p.digest(expected_sha256))

    def derive(self, *, process, request) -> dict:
        """Return the selected hash/proof-scope after the real bootstrap result."""
        from serverware.native_pilot_supervisor_process import AuthorityCoordinatorProcess, JobRequest
        self.check()
        p.require(not self._derive_attempted)
        self._derive_attempted = True
        try:
            p.require(type(process) is AuthorityCoordinatorProcess and process is self._process
                and type(request) is JobRequest and request.phase == "endpoint-precreation"
                and request.job_index == 1 and request.job == "cohort-precreation")
            process.check_request(request)
            early = _phase(process, "bootstrap-admission")
            p.fields(early["payload"], ("bootstrapObservationOriginal", "admissionPayloadOriginal"))
            current = _phase(process, "endpoint-precreation")
            p.fields(current["payload"], ("bootstrapObservationOriginal", "bootstrapAdmissionOriginal", "gateBindingOriginal"))
            p.require(early["deadlineBoottimeNs"] == current["deadlineBoottimeNs"]
                and request.deadline_boottime_ns == p.ns(current["deadlineBoottimeNs"])
                and p.sha(p.canonical(current)) == request.value["conductorRequestSha256"])
            if self._value["apiVersion"] == ADOPTED_API:
                # The real receiver can narrow this original driver interval;
                # it may never replace or extend the signed window itself.
                p.require(request.deadline_boottime_ns <= p.ns(self._window["startupDeadlineBoottimeNs"])
                    and early["expiresAtUnixNanos"] == current["expiresAtUnixNanos"])
            else:
                p.require(current["deadlineBoottimeNs"] == self._window["startupDeadlineBoottimeNs"])
            observed_raw, _ = scope._original(early["payload"]["bootstrapObservationOriginal"], 65536)
            p.require(current["payload"]["bootstrapObservationOriginal"] == observed_raw.decode("ascii"))
            observed = driver_authority._observation(observed_raw, self._control, self._config, self._window, originals._clock())
            expected_input = p.canonical({"apiVersion": "serverware.nativePilotDriverAuthorityInput/v1", "operation": "bootstrap",
                **{name + "Original": raw.decode("ascii") for name, raw in self._bootstrap.items()},
                "observationOriginal": observed_raw.decode("ascii"), "payloadOriginal": early["payload"]["admissionPayloadOriginal"]})
            p.require(process.approved_input_original("bootstrap-admission", "driver-bootstrap") == expected_input
                and process.approved_input_sha256("bootstrap-admission", "driver-bootstrap") == p.sha(expected_input))
            prior = p.fields(process.prior_result("bootstrap-admission", "driver-bootstrap"), ("original", "sha256", "pin"))
            signed_raw, signed = scope._original(prior["original"], 8192)
            p.require(p.sha(signed_raw) == p.digest(prior["sha256"])
                and current["payload"]["bootstrapAdmissionOriginal"] == prior["original"])
            c9._same(prior["pin"], {"path": publication.DESTINATIONS["driver-bootstrap-admission"], "sha256": p.sha(signed_raw)})
            p.fields(signed, ("payload", "signature"))
            payload_raw, _ = scope._original(early["payload"]["admissionPayloadOriginal"], 8192)
            p.require(p.canonical(signed["payload"]) == payload_raw)
            authority = self._config["lifecycle"]["constructedAdmissionAuthority"]
            admission.authority(authority).verify(p.decoded(signed["signature"], size=64),
                p.preimage(admission.BOOTSTRAP_DOMAIN, signed["payload"]))
            driver_authority._bootstrap(signed["payload"], observed_raw, self._control, self._window, authority)
            p.freshness(signed["payload"]["issuedAtUnixNanos"], signed["payload"]["expiresAtUnixNanos"], time.time_ns(), 30_000_000_000)
            envelope, keys, key_root = _assignment(self._value, time.time_ns())
            manifest = closure._manifest({"manifestOriginal": self._value["closureManifestOriginal"]},
                self._config, observed, envelope["payload"])
            if self._value["apiVersion"] != LEGACY_API:
                _closure_set(self._value, envelope, manifest)
            result = self._derive(envelope, keys, key_root, manifest, observed)
            self.check()
            process.check_request(request)
            p.freshness(signed["payload"]["issuedAtUnixNanos"], signed["payload"]["expiresAtUnixNanos"], time.time_ns(), 30_000_000_000)
            self._result = result
            self._derived_sequence = request.sequence
            self._derived_phase_sha256 = p.sha(p.canonical(current))
            return copy.deepcopy(result)
        except BaseException:
            self._failed = True
            raise

    def result(self, *, process, request, adopted=False) -> dict:
        """Read the once-derived v2 data for the same actual pending startup job.

        No result is recreated, and no new window is opened. This accessor is
        deliberately unavailable for lifetime/cleanup phases after startup.
        """
        from serverware.native_pilot_supervisor_process import AuthorityCoordinatorProcess, JobRequest
        self.check()
        p.require(type(adopted) is bool and type(process) is AuthorityCoordinatorProcess and process is self._process
            and type(request) is JobRequest and self._result is not None
            and self._value["apiVersion"] == (ADOPTED_API if adopted else SET_API)
            and request.phase in RESULT_PHASES and request.sequence >= self._derived_sequence
            and request.deadline_boottime_ns <= p.ns(self._window["startupDeadlineBoottimeNs"]))
        process.check_request(request)
        p.require(p.sha(p.canonical(_phase(process, "endpoint-precreation"))) == self._derived_phase_sha256)
        value = copy.deepcopy(self._result)
        self.check()
        process.check_request(request)
        return value

    def public_originals(self, *, process, request, adopted=False) -> dict:
        """Return four literal v2 originals under the existing result guards.

        The same retained recipe, actual pending request, original startup
        window, assignment signature and trust currentness are rechecked. This
        neither changes the six-field result nor admits a caller-provided DTO.
        """
        self.result(process=process, request=request, adopted=adopted)
        value = {name: self._value[name] for name in
            ("assignmentOriginal", "trustOriginal", "trustSha256", "closureSetOriginal")}
        self.check()
        process.check_request(request)
        return value

    def _derive(self, envelope, keys, key_root, manifest, observed):
        return derive_configuration(envelope=envelope, keys=keys, key_root=key_root,
            manifest=manifest, observed=observed, production=self._value["production"],
            window=self._window, recipe_sha=self._sha,
            successor=self._value["apiVersion"] != LEGACY_API)

    def close(self):
        """Release only this public descriptor after the actual bound owner retires."""
        global _LIVE
        if self._closed:
            return
        if self._close_uncertain:
            raise RecipeError(self)
        p.require(_LIVE is self and not self._closed
            and (self._pid, self._start, self._boot) == (os.getpid(), originals._start(), originals._boot()))
        if self._process is not None:
            p.require(self._process._closed and self._process._result["status"] in
                ("not-started", "stopped-cleanup-complete", "failed-cleanup-complete"))
        try:
            self._retire_descriptor()
        except BaseException as error:
            raise RecipeError(self) from error
        self._closed = True
        _LIVE = None

    def _retire_descriptor(self):
        # A close error cannot leave a recycled descriptor available for retry.
        from serverware import native_pilot_genesis_parent_control_io as ownership
        p.require(not self._close_uncertain)
        try:
            with ownership.owning():
                fd, self._fd = self._fd, None
                if fd is not None:
                    self._close_uncertain = True
                    os.close(fd)
                    self._close_uncertain = False
        except BaseException:
            self._close_uncertain = True
            raise
