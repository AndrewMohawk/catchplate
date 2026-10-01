"""Independent one-attempt commissioning policy and first bootstrap decision.

The protected complete policy and its digest are independently provisioned.
Neither a supplied digest, file mode, valid request nor this parser establishes
that approval provenance. This owner delegates only the initial bootstrap and
the separate two fixed precreation decisions, not the entire job graph.
Explicit policy v2 additionally pins a retained measured recipe/v2 and allows
its one actual post-bootstrap derivation; it does not approve endpoint jobs.
Explicit v3 additionally delegates the fixed fresh-ledger endpoint preparation
and first three C9 deliveries from that same retained recipe and actual owner.
It does not delegate the remaining service, bridge, release or lifetime jobs.
Explicit v4 additionally delegates the fixed five-step initial-history ceremony
for each ordinary role. It does not approve subsequent ordinary C9 or runtime
composition. Legacy policies retain their old key field set and cannot bind
the expanded coordinator's capability inventory.
Explicit v5 additionally delegates five ordinary runtime/public-input and C9
delivery decisions. It does not authorize subsequent generation or release.
Explicit v6 additionally delegates five ordinary generation grants within one
independently selected installation interval; later native/release jobs remain
outside its scope.
Explicit v7 additionally delegates the remaining seven native C9 deliveries;
it does not authorize subsequent native grants, launches or release jobs.
Explicit v8 adds two ordered key/admission authorizations per native endpoint.
Legacy capability inventories remain closed; downstream grants are separate.
Explicit v9 delegates eleven native operational grants with authenticated
ordinary histories and independently selected verifier/fresh-input settings.
It retains v8's 77 selectors and does not authorize subsequent launches.
Explicit v10 delegates two ordinary dispatch grants and Head/Cleanup/Current
under each role's independently approved history root. Its selected starting
heads are initialization inputs, not receipts; launch jobs remain separate.
Explicit v11 delegates the 31 late closure, encrypted-delivery and verifier
authorizations required before endpoint launch, including CommitRequest's
separate HMAC assignment. It adds 31 fixed supervisor capabilities; legacy
42/57/77-selector policies remain closed and cannot bind the expanded owner.
Explicit v12 delegates the ten endpoint launch bundles using actual earlier
authorizations and separately approved clock-bootstrap settings. It retains
108 signing selectors; service material, bridge and release remain separate.
Explicit v13 delegates exclusive publication of the four existing fresh
Persistence/GenerationInstall material originals. It introduces no signer or
journal-initialization authority; bridge and release remain separate.
Explicit v14 adds three supplemental helper initial-history ceremonies under
its existing approved root/checkpoint/service keys. Their exact outputs enter
the four-role runtime; they do not approve currentness, launch or cleanup.
Explicit v15 permits protected late intake for eight actual current-head
requests. The independent authority still supplies each complete input and
approval after request acquisition; static policy never decides currentness.
Explicit v16 additionally delegates the bridge runtime/outgoing installation
from those actual signed heads, measured peers and authenticated service grants.
It neither provisions bridge credentials nor authorizes subsequent release.
Explicit v17 adds seven bridge delivery, authorization and launch decisions
with five new supervisor capabilities. Legacy v11-v16 policies retain exactly
108 selectors. Actual credentials remain independently provisioned, and
release, origin and lifetime decisions remain separate.
Explicit v18 delegates those last six source-fixed decisions and an exclusive
phase-two publication. It retains v17's 113 capabilities and adds only original
image pins and static verifier/assignment-trust selections. It or explicit v19
is required before the full supervisor can start; graph coverage alone grants
no authority. V19 selects the completed-invocation persistence grant and the
v12 bridge/v8 launch through versioned inner policies, retaining all 113 keys.

Only the actual AuthorityCoordinatorProcess and its current opaque JobRequest
can enter bootstrap(). No signing, publication, process launch, arbitrary
template, generated history, deadline renewal or live-owner DTO is supported.
"""
from __future__ import annotations

import copy
import fcntl
import json
import os
import time

from scripts import native_pilot_runtime_artifacts as artifact
from scripts.authority import native_pilot_authority_io as io
from serverware import custody_generation_grants as generation
from serverware import native_pilot_bootstrap_install as installation
from serverware import native_pilot_driver_authority as driver_authority
from serverware import native_pilot_scope_authority as scope
from serverware import native_pilot_window_authority as window_authority
from serverware import native_shadow_driver_bootstrap as driver
from serverware import native_shadow_nitro_originals as originals
from serverware.native_pilot_phase_execution import (
    JOBS, KEY_AUTHORIZATION_JOBS, LAUNCH_AUTHORIZATION_JOBS, BRIDGE_AUTHORIZATION_JOBS, KEY_PURPOSES, MAX_APPROVAL)

p = driver.p
MAX_POLICY = 4 * 1024 * 1024
POLICY_API = "serverware.nativePilotSupervisorCommissioningPolicy/v1"
PURPOSE = "initial-driver-bootstrap-and-endpoint-precreation"
FIELDS = ("apiVersion", "purpose", "source", "conductorInventorySha256", "authorityInventorySha256",
    "bootstrapOriginals", "keyBindings", "precreation")
MEASURED_POLICY_API = "serverware.nativePilotSupervisorCommissioningPolicy/v2"
MEASURED_PURPOSE = "initial-driver-bootstrap-precreation-and-measured-configuration"
MEASURED_FIELDS = FIELDS + ("measuredRecipeSha256",)
ENDPOINT_POLICY_API = "serverware.nativePilotSupervisorCommissioningPolicy/v3"
ENDPOINT_PURPOSE = "initial-driver-bootstrap-precreation-and-endpoint-commissioning"
ENDPOINT_FIELDS = MEASURED_FIELDS + ("endpointPreparation", "endpointDeliveries")
INITIAL_POLICY_API = "serverware.nativePilotSupervisorCommissioningPolicy/v4"
INITIAL_PURPOSE = "initial-driver-bootstrap-precreation-endpoints-and-ordinary-initial-history"
INITIAL_FIELDS = ENDPOINT_FIELDS + ("ordinaryInitialHistories",)
DELIVERY_POLICY_API = "serverware.nativePilotSupervisorCommissioningPolicy/v5"
DELIVERY_PURPOSE = "initial-driver-bootstrap-precreation-endpoints-and-ordinary-deliveries"
DELIVERY_FIELDS = INITIAL_FIELDS + ("ordinaryDeliveriesOriginal",)
GENERATION_POLICY_API = "serverware.nativePilotSupervisorCommissioningPolicy/v6"
GENERATION_PURPOSE = "initial-driver-bootstrap-precreation-endpoints-and-ordinary-generations"
GENERATION_FIELDS = DELIVERY_FIELDS + ("ordinaryGenerationsOriginal",)
NATIVE_DELIVERY_POLICY_API = "serverware.nativePilotSupervisorCommissioningPolicy/v7"
NATIVE_DELIVERY_PURPOSE = "initial-driver-bootstrap-precreation-endpoints-ordinary-generations-and-native-deliveries"
NATIVE_DELIVERY_FIELDS = GENERATION_FIELDS + ("nativeDeliveriesOriginal",)
KEY_AUTHORIZATION_POLICY_API = "serverware.nativePilotSupervisorCommissioningPolicy/v8"
KEY_AUTHORIZATION_PURPOSE = "initial-driver-bootstrap-precreation-endpoints-generations-and-native-key-authorizations"
KEY_AUTHORIZATION_FIELDS = NATIVE_DELIVERY_FIELDS + ("nativeKeyAuthorizationsOriginal",)
NATIVE_SERVICE_POLICY_API = "serverware.nativePilotSupervisorCommissioningPolicy/v9"
NATIVE_SERVICE_PURPOSE = "initial-driver-bootstrap-precreation-endpoints-generations-and-native-services"
NATIVE_SERVICE_FIELDS = KEY_AUTHORIZATION_FIELDS + ("nativeServicesOriginal",)
ORDINARY_TRANSITION_POLICY_API = "serverware.nativePilotSupervisorCommissioningPolicy/v10"
ORDINARY_TRANSITION_PURPOSE = "initial-driver-bootstrap-precreation-endpoints-generations-and-ordinary-transitions"
ORDINARY_TRANSITION_FIELDS = NATIVE_SERVICE_FIELDS + ("ordinaryTransitionsOriginal",)
LAUNCH_AUTHORIZATION_POLICY_API = "serverware.nativePilotSupervisorCommissioningPolicy/v11"
LAUNCH_AUTHORIZATION_PURPOSE = "initial-driver-bootstrap-precreation-endpoints-generations-and-native-launch-authorizations"
LAUNCH_AUTHORIZATION_FIELDS = ORDINARY_TRANSITION_FIELDS + ("nativeLaunchAuthorizationsOriginal",)
ENDPOINT_LAUNCH_POLICY_API = "serverware.nativePilotSupervisorCommissioningPolicy/v12"
ENDPOINT_LAUNCH_PURPOSE = "initial-driver-bootstrap-precreation-endpoints-generations-and-endpoint-launches"
ENDPOINT_LAUNCH_FIELDS = LAUNCH_AUTHORIZATION_FIELDS + ("endpointLaunchesOriginal",)
SERVICE_MATERIAL_POLICY_API = "serverware.nativePilotSupervisorCommissioningPolicy/v13"
SERVICE_MATERIAL_PURPOSE = "initial-driver-bootstrap-precreation-endpoints-generations-and-service-material"
SERVICE_MATERIAL_FIELDS = ENDPOINT_LAUNCH_FIELDS + ("serviceMaterialOriginal",)
HELPER_INITIAL_POLICY_API = "serverware.nativePilotSupervisorCommissioningPolicy/v14"
HELPER_INITIAL_PURPOSE = "initial-driver-bootstrap-precreation-endpoints-generations-and-helper-histories"
HELPER_INITIAL_FIELDS = SERVICE_MATERIAL_FIELDS + ("helperInitialHistoriesOriginal",)
CURRENT_HEAD_POLICY_API = "serverware.nativePilotSupervisorCommissioningPolicy/v15"
CURRENT_HEAD_PURPOSE = "initial-driver-bootstrap-precreation-endpoints-generations-and-current-head-intake"
CURRENT_HEAD_FIELDS = HELPER_INITIAL_FIELDS + ("currentHeadIntakeOriginal",)
BRIDGE_RUNTIME_POLICY_API = "serverware.nativePilotSupervisorCommissioningPolicy/v16"
BRIDGE_RUNTIME_PURPOSE = "initial-driver-bootstrap-precreation-endpoints-generations-and-bridge-runtime"
BRIDGE_RUNTIME_FIELDS = CURRENT_HEAD_FIELDS + ("bridgeRuntimeOriginal",)
BRIDGE_COMMISSIONING_POLICY_API = "serverware.nativePilotSupervisorCommissioningPolicy/v17"
BRIDGE_COMMISSIONING_PURPOSE = "initial-driver-bootstrap-precreation-endpoints-generations-and-bridge-commissioning"
BRIDGE_COMMISSIONING_FIELDS = BRIDGE_RUNTIME_FIELDS + ("bridgeCommissioningOriginal",)
CONTINUATION_POLICY_API = "serverware.nativePilotSupervisorCommissioningPolicy/v18"
CONTINUATION_PURPOSE = "initial-driver-bootstrap-through-controlled-shutdown"
CONTINUATION_FIELDS = BRIDGE_COMMISSIONING_FIELDS + ("continuationOriginal",)
NATIVE_TERMINAL_POLICY_API = "serverware.nativePilotSupervisorCommissioningPolicy/v19"
NATIVE_TERMINAL_PURPOSE = "initial-driver-bootstrap-through-native-completed-invocation-shutdown"
NATIVE_TERMINAL_FIELDS = CONTINUATION_FIELDS
CONTINUATION_POLICY_APIS = (CONTINUATION_POLICY_API, NATIVE_TERMINAL_POLICY_API)
BRIDGE_COMMISSIONING_POLICY_APIS = (BRIDGE_COMMISSIONING_POLICY_API,) + CONTINUATION_POLICY_APIS
BRIDGE_RUNTIME_POLICY_APIS = (BRIDGE_RUNTIME_POLICY_API,) + BRIDGE_COMMISSIONING_POLICY_APIS
CURRENT_HEAD_POLICY_APIS = (CURRENT_HEAD_POLICY_API,) + BRIDGE_RUNTIME_POLICY_APIS
HELPER_INITIAL_POLICY_APIS = (HELPER_INITIAL_POLICY_API,) + CURRENT_HEAD_POLICY_APIS
SERVICE_MATERIAL_POLICY_APIS = (SERVICE_MATERIAL_POLICY_API,) + HELPER_INITIAL_POLICY_APIS
ENDPOINT_LAUNCH_POLICY_APIS = (ENDPOINT_LAUNCH_POLICY_API,) + SERVICE_MATERIAL_POLICY_APIS
LAUNCH_AUTHORIZATION_POLICY_APIS = (LAUNCH_AUTHORIZATION_POLICY_API,) + ENDPOINT_LAUNCH_POLICY_APIS
ORDINARY_TRANSITION_POLICY_APIS = (ORDINARY_TRANSITION_POLICY_API,) + LAUNCH_AUTHORIZATION_POLICY_APIS
NATIVE_SERVICE_POLICY_APIS = (NATIVE_SERVICE_POLICY_API,) + ORDINARY_TRANSITION_POLICY_APIS
KEY_AUTHORIZATION_POLICY_APIS = (KEY_AUTHORIZATION_POLICY_API,) + NATIVE_SERVICE_POLICY_APIS
NATIVE_DELIVERY_POLICY_APIS = (NATIVE_DELIVERY_POLICY_API,) + KEY_AUTHORIZATION_POLICY_APIS
NATIVE_SERVICE_JOBS = tuple(job for job in JOBS["service-originals"]
    if job.family in ("native", "generation-install"))
GENERATION_POLICY_APIS = (GENERATION_POLICY_API,) + NATIVE_DELIVERY_POLICY_APIS
DELIVERY_POLICY_APIS = (DELIVERY_POLICY_API,) + GENERATION_POLICY_APIS
INITIAL_POLICY_APIS = (INITIAL_POLICY_API,) + DELIVERY_POLICY_APIS
ENDPOINT_POLICY_APIS = (ENDPOINT_POLICY_API,) + INITIAL_POLICY_APIS
MEASURED_POLICY_APIS = (MEASURED_POLICY_API,) + ENDPOINT_POLICY_APIS
LAUNCH_KEY_PURPOSES = tuple(name for name in KEY_PURPOSES
    if name not in {job.key for job in BRIDGE_AUTHORIZATION_JOBS})
NATIVE_KEY_PURPOSES = tuple(name for name in LAUNCH_KEY_PURPOSES
    if name not in {job.key for job in LAUNCH_AUTHORIZATION_JOBS})
INITIAL_KEY_PURPOSES = tuple(name for name in NATIVE_KEY_PURPOSES
    if name not in {job.key for job in KEY_AUTHORIZATION_JOBS})
LEGACY_KEY_PURPOSES = tuple(name for name in INITIAL_KEY_PURPOSES if not name.startswith("ordinary-initial-"))
BOOTSTRAP_FIELDS = ("control", "configuration", "window", "deliveryConfiguration")
_TOKEN = object()
_USED = False
_LIVE = None


def _same(first, second):
    p.require(p.canonical(first) == p.canonical(second))


def _policy_document(raw):
    """Keep legacy JSON bounds; widen only v4+ initial-history counters."""
    p.require(type(raw) is bytes and 0 < len(raw) <= MAX_POLICY)
    value = json.loads(raw.decode("ascii"), object_pairs_hook=p._pairs,
        parse_float=p._reject, parse_constant=p._reject)
    p.require(type(value) is dict)
    if value.get("apiVersion") not in INITIAL_POLICY_APIS:
        p.require(p.canonical(value) == raw)
        return value
    from serverware import native_pilot_supervisor_initial_history as ordinary
    fragment = p.fields(value["ordinaryInitialHistories"], ("apiVersion", "services"))
    p.require(fragment["apiVersion"] == ordinary.POLICY_API)
    rows = p.fields(fragment["services"], generation.ROLES)
    projected = copy.deepcopy(value)
    for role in generation.ROLES:
        row = p.fields(rows[role], ordinary.ROLE_FIELDS)
        for name in ordinary.GENERATIONS + ("revocationGenerationHighWater",):
            p.integer(row[name], maximum=p.MAX_U64)
            projected["ordinaryInitialHistories"]["services"][role][name] = 0
    # Projection changes no container or field: the original depth/node caps
    # and i64 restriction still cover every other value, including unknowns.
    p.canonical(projected)
    p.require(generation.canonical(value) == raw)
    return value


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
        self._ordinary_deliveries = None
        self._ordinary_generations = None
        self._native_deliveries = None
        self._native_key_authorizations = None
        self._native_services = None
        self._ordinary_transitions = None
        self._launch_authorizations = None
        self._endpoint_launches = None
        self._service_material = None
        self._helper_initial = None
        self._current_head_intake = None
        self._bridge_runtime = None
        self._bridge_commissioning = None
        self._continuation = None
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
            value = _policy_document(owner._raw)
            p.require(type(value) is dict and value.get("apiVersion") in
                (POLICY_API,) + MEASURED_POLICY_APIS)
            native_terminal = value["apiVersion"] == NATIVE_TERMINAL_POLICY_API
            continuation = value["apiVersion"] in CONTINUATION_POLICY_APIS
            bridge_commissioning = value["apiVersion"] in BRIDGE_COMMISSIONING_POLICY_APIS
            bridge_runtime = value["apiVersion"] in BRIDGE_RUNTIME_POLICY_APIS
            current_head_intake = value["apiVersion"] in CURRENT_HEAD_POLICY_APIS
            helper_initial = value["apiVersion"] in HELPER_INITIAL_POLICY_APIS
            service_material = value["apiVersion"] in SERVICE_MATERIAL_POLICY_APIS
            endpoint_launch = value["apiVersion"] in ENDPOINT_LAUNCH_POLICY_APIS
            launch_authorization = value["apiVersion"] in LAUNCH_AUTHORIZATION_POLICY_APIS
            ordinary_transition = value["apiVersion"] in ORDINARY_TRANSITION_POLICY_APIS
            native_service = value["apiVersion"] in NATIVE_SERVICE_POLICY_APIS
            key_authorization = value["apiVersion"] in KEY_AUTHORIZATION_POLICY_APIS
            native_delivery = value["apiVersion"] in NATIVE_DELIVERY_POLICY_APIS
            ordinary_generation = value["apiVersion"] in GENERATION_POLICY_APIS
            ordinary_delivery = value["apiVersion"] in DELIVERY_POLICY_APIS
            initial = value["apiVersion"] in INITIAL_POLICY_APIS
            endpoint = value["apiVersion"] in ENDPOINT_POLICY_APIS
            measured = value["apiVersion"] in MEASURED_POLICY_APIS
            p.fields(value, CONTINUATION_FIELDS if continuation else BRIDGE_COMMISSIONING_FIELDS if bridge_commissioning else BRIDGE_RUNTIME_FIELDS if bridge_runtime else CURRENT_HEAD_FIELDS if current_head_intake else HELPER_INITIAL_FIELDS if helper_initial else SERVICE_MATERIAL_FIELDS if service_material else ENDPOINT_LAUNCH_FIELDS if endpoint_launch else LAUNCH_AUTHORIZATION_FIELDS if launch_authorization else ORDINARY_TRANSITION_FIELDS if ordinary_transition else NATIVE_SERVICE_FIELDS if native_service else KEY_AUTHORIZATION_FIELDS if key_authorization else NATIVE_DELIVERY_FIELDS if native_delivery else GENERATION_FIELDS if ordinary_generation else DELIVERY_FIELDS if ordinary_delivery else INITIAL_FIELDS if initial else
                ENDPOINT_FIELDS if endpoint else MEASURED_FIELDS if measured else FIELDS)
            p.require(value["purpose"] == (NATIVE_TERMINAL_PURPOSE if native_terminal else CONTINUATION_PURPOSE if continuation else BRIDGE_COMMISSIONING_PURPOSE if bridge_commissioning else BRIDGE_RUNTIME_PURPOSE if bridge_runtime else CURRENT_HEAD_PURPOSE if current_head_intake else HELPER_INITIAL_PURPOSE if helper_initial else SERVICE_MATERIAL_PURPOSE if service_material else ENDPOINT_LAUNCH_PURPOSE if endpoint_launch else LAUNCH_AUTHORIZATION_PURPOSE if launch_authorization else ORDINARY_TRANSITION_PURPOSE if ordinary_transition else NATIVE_SERVICE_PURPOSE if native_service else KEY_AUTHORIZATION_PURPOSE if key_authorization else NATIVE_DELIVERY_PURPOSE if native_delivery else GENERATION_PURPOSE if ordinary_generation else DELIVERY_PURPOSE if ordinary_delivery else INITIAL_PURPOSE if initial else
                ENDPOINT_PURPOSE if endpoint else MEASURED_PURPOSE if measured else PURPOSE))
            if measured:
                p.digest(value["measuredRecipeSha256"])
            p.fields(value["source"], artifact.SOURCE_FIELDS)
            source = artifact._source(value["source"])
            for field in ("conductorInventorySha256", "authorityInventorySha256"):
                p.digest(value[field])
            keys = p.fields(value["keyBindings"], KEY_PURPOSES if bridge_commissioning else LAUNCH_KEY_PURPOSES if launch_authorization else NATIVE_KEY_PURPOSES if key_authorization
                else INITIAL_KEY_PURPOSES if initial else LEGACY_KEY_PURPOSES)
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
            if endpoint:
                from serverware import native_pilot_supervisor_endpoint_policy as preparation
                from serverware import native_pilot_supervisor_endpoint_deliveries as deliveries
                from serverware import native_shadow_guest_delivery as delivery
                endpoint_preparation = preparation.validate_policy(value["endpointPreparation"])
                endpoint_deliveries = deliveries.validate_policy(value["endpointDeliveries"],
                    native_cold_originals=precreation["nativeColdOriginals"])
                for role in ("retrieval", "persistence", "trustedTime"):
                    cold_raw, _ = scope._original(precreation["nativeColdOriginals"][role], 65536)
                    endpoint_cold = delivery.configuration(cold_raw, p.sha(cold_raw))
                    p.require(keys["native-delivery-" + role] == endpoint_cold["authority"]["keyId"])
            if initial:
                from serverware import native_pilot_supervisor_initial_history as ordinary
                ordinary_initial = ordinary.validate_policy(value["ordinaryInitialHistories"],
                    ordinary_cold_originals=precreation["ordinaryColdOriginals"], driver_configuration=config)
                for role, fragment in ordinary_initial["services"].items():
                    for name, public in fragment["authorities"].items():
                        # validate_policy has verified canonical Ed25519 SPKI.
                        # Capability bindings hash raw public material, not an
                        # independently selected key ID or the SPKI bytes.
                        raw_key = p.decoded(public["publicKeySpkiBase64"], size=44)[-32:]
                        p.require(keys["ordinary-initial-" + name + "-" + role] == p.sha(raw_key))
            if ordinary_delivery:
                from serverware import native_pilot_ordinary_runtime_profile as runtime
                policy_text = value["ordinaryDeliveriesOriginal"]
                p.require(type(policy_text) is str and policy_text.isascii())
                policy_fragment = generation.document(policy_text.encode("ascii"), MAX_POLICY)
                ordinary_deliveries = runtime.validate_policy(policy_fragment,
                    ordinary_cold_originals=precreation["ordinaryColdOriginals"], initial_policy=ordinary_initial)
                for role in generation.ROLES:
                    cold_raw = precreation["ordinaryColdOriginals"][role].encode("ascii")
                    service_cold = generation.configuration(cold_raw, p.sha(cold_raw), role)
                    p.require(keys["ordinary-delivery-" + role] == service_cold["authority"]["keyId"])
            if ordinary_generation:
                from serverware import native_pilot_ordinary_generation_profile as grants
                policy_text = value["ordinaryGenerationsOriginal"]
                p.require(type(policy_text) is str and policy_text.isascii())
                ordinary_generations = grants.validate_policy(generation.document(policy_text.encode("ascii"), MAX_POLICY))
                for role in generation.ROLES:
                    root = ordinary_initial["services"][role]["authorities"]["root"]
                    p.require(keys["ordinary-generation-" + role]
                        == p.sha(p.decoded(root["publicKeySpkiBase64"], size=44)[-32:]))
            if helper_initial:
                from serverware import native_pilot_supervisor_helper_initial_profile as helper
                policy_text = value["helperInitialHistoriesOriginal"]
                p.require(type(policy_text) is str and policy_text.isascii()
                    and ordinary_deliveries["apiVersion"] == "serverware.nativePilotOrdinaryRuntimePolicy/v2")
                helper_initial_policy = helper.validate_policy(
                    generation.document(policy_text.encode("ascii"), helper.MAX_POLICY), initial_policy=ordinary_initial)
            if current_head_intake:
                from serverware import native_pilot_supervisor_current_head_profile as current_heads
                policy_text = value["currentHeadIntakeOriginal"]
                p.require(type(policy_text) is str and policy_text.isascii())
                current_head_policy = current_heads.validate_policy(
                    p.document(policy_text.encode("ascii"), current_heads.MAX_POLICY))
            if bridge_runtime:
                from serverware import native_pilot_bridge_runtime_policy as bridge_policy
                policy_text = value["bridgeRuntimeOriginal"]
                p.require(type(policy_text) is str and policy_text.isascii())
                bridge_runtime_policy = bridge_policy.validate_policy(
                    generation.document(policy_text.encode("ascii"), bridge_policy.MAX_POLICY))
                p.require(bridge_runtime_policy["apiVersion"] == (bridge_policy.TERMINAL_API if native_terminal else bridge_policy.API))
            if bridge_commissioning:
                from serverware import native_pilot_bridge_commissioning_policy as bridge_policy
                policy_text = value["bridgeCommissioningOriginal"]
                p.require(type(policy_text) is str and policy_text.isascii())
                bridge_commissioning_policy = bridge_policy.validate_policy(
                    generation.document(policy_text.encode("ascii"), bridge_policy.MAX_POLICY),
                    bootstrap_configuration=config, cold_original=raw["deliveryConfiguration"],
                    runtime_policy=bridge_runtime_policy)
                p.require(keys["native-delivery-bridge"] == cold["authority"]["keyId"])
            if continuation:
                from serverware import native_pilot_supervisor_continuation_policy as continuation_policy
                policy_text = value["continuationOriginal"]
                p.require(type(policy_text) is str and policy_text.isascii())
                continuation_fragment = continuation_policy.validate_policy(
                    generation.document(policy_text.encode("ascii"), continuation_policy.MAX_POLICY))
            if native_delivery:
                from serverware import native_pilot_native_delivery_profile as native
                policy_text = value["nativeDeliveriesOriginal"]
                p.require(type(policy_text) is str and policy_text.isascii())
                native_deliveries = native.validate_policy(
                    p.document(policy_text.encode("ascii"), MAX_POLICY),
                    native_cold_originals=precreation["nativeColdOriginals"])
                for role in native.ROLES:
                    cold_raw = precreation["nativeColdOriginals"][role].encode("ascii")
                    native_cold = delivery.configuration(cold_raw, p.sha(cold_raw))
                    p.require(keys["native-delivery-" + role] == native_cold["authority"]["keyId"])
            if key_authorization:
                from serverware import native_pilot_key_profile as key_profile
                policy_text = value["nativeKeyAuthorizationsOriginal"]
                p.require(type(policy_text) is str and policy_text.isascii())
                native_key_authorizations = key_profile.validate_policy(
                    p.document(policy_text.encode("ascii"), MAX_POLICY))
            if native_service:
                from serverware import native_pilot_native_service_profile as services
                policy_text = value["nativeServicesOriginal"]
                p.require(type(policy_text) is str and policy_text.isascii())
                native_services = services.validate_policy(
                    generation.document(policy_text.encode("ascii"), MAX_POLICY))
                p.require(native_services["apiVersion"] == (services.COMPLETED_API if native_terminal else services.API))
            if ordinary_transition:
                from serverware import native_pilot_ordinary_transition_profile as transitions
                policy_text = value["ordinaryTransitionsOriginal"]
                p.require(type(policy_text) is str and policy_text.isascii())
                ordinary_transitions = transitions.validate_policy(
                    generation.document(policy_text.encode("ascii"), MAX_POLICY))
                for operation, role in transitions.JOBS:
                    job_name = "ordinary-" + operation + ("-" + role if operation == "dispatch" else "")
                    root = ordinary_initial["services"][role]["authorities"]["root"]
                    p.require(keys[job_name]
                        == p.sha(p.decoded(root["publicKeySpkiBase64"], size=44)[-32:]))
            if launch_authorization:
                from serverware import native_pilot_launch_authorization_profile as authorizations
                policy_text = value["nativeLaunchAuthorizationsOriginal"]
                p.require(type(policy_text) is str and policy_text.isascii())
                launch_authorizations = authorizations.validate_policy(
                    p.document(policy_text.encode("ascii"), MAX_POLICY))
            if endpoint_launch:
                from serverware import native_pilot_endpoint_launch_profile as launches
                policy_text = value["endpointLaunchesOriginal"]
                p.require(type(policy_text) is str and policy_text.isascii())
                endpoint_launches = launches.validate_policy(
                    p.document(policy_text.encode("ascii"), MAX_POLICY))
                _same(endpoint_launches["endpoints"]["trustedTime"], native_services["trustedTime"])
            if service_material:
                from serverware import native_pilot_service_material as material
                policy_text = value["serviceMaterialOriginal"]
                p.require(type(policy_text) is str and policy_text.isascii())
                service_material_policy = material.validate_policy(
                    p.document(policy_text.encode("ascii"), MAX_POLICY))
            owner._value = copy.deepcopy(value)
            owner._value["precreation"] = precreation
            if endpoint:
                owner._value["endpointPreparation"] = endpoint_preparation
                owner._value["endpointDeliveries"] = endpoint_deliveries
            if initial:
                owner._value["ordinaryInitialHistories"] = ordinary_initial
            if ordinary_delivery:
                owner._ordinary_deliveries = ordinary_deliveries
            if ordinary_generation:
                owner._ordinary_generations = ordinary_generations
            if native_delivery:
                owner._native_deliveries = native_deliveries
            if key_authorization:
                owner._native_key_authorizations = native_key_authorizations
            if native_service:
                owner._native_services = native_services
            if ordinary_transition:
                owner._ordinary_transitions = ordinary_transitions
            if launch_authorization:
                owner._launch_authorizations = launch_authorizations
            if endpoint_launch:
                owner._endpoint_launches = endpoint_launches
            if service_material:
                owner._service_material = service_material_policy
            if helper_initial:
                owner._helper_initial = helper_initial_policy
            if current_head_intake:
                owner._current_head_intake = current_head_policy
            if bridge_runtime:
                owner._bridge_runtime = bridge_runtime_policy
            if bridge_commissioning:
                owner._bridge_commissioning = bridge_commissioning_policy
            if continuation:
                owner._continuation = continuation_fragment
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

        Legacy policy forbids a recipe. v2+ require the already independently
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
            if self._value["apiVersion"] in MEASURED_POLICY_APIS:
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
        p.require(self._value["apiVersion"] in MEASURED_POLICY_APIS
            and self._recipe is not None and self._measured_attempted)
        value = self._recipe.result(process=process, request=request)
        self.check(process)
        process.check_request(request)
        return value

    def endpoint_policy(self) -> dict:
        """Return the admitted static v3 preparation fragment, not live facts."""
        self.check()
        p.require(self._value["apiVersion"] in ENDPOINT_POLICY_APIS)
        return copy.deepcopy(self._value["endpointPreparation"])

    def endpoint_deliveries(self) -> dict:
        """Return the three independently selected C9 public input fragments."""
        self.check()
        p.require(self._value["apiVersion"] in ENDPOINT_POLICY_APIS)
        return copy.deepcopy(self._value["endpointDeliveries"])

    def endpoint_recipe_originals(self, *, process, request) -> dict:
        """Read only the same retained recipe's authenticated public originals."""
        self.check(process)
        p.require(self._value["apiVersion"] in ENDPOINT_POLICY_APIS
            and self._recipe is not None and self._measured_attempted)
        self._recipe.require_original(self._value["measuredRecipeSha256"])
        value = self._recipe.public_originals(process=process, request=request)
        self.check(process)
        process.check_request(request)
        return value

    def ordinary_initial_policy(self, *, process, request) -> dict:
        """Only v4+ delegate initial history; the fragment is not a result."""
        self.check(process)
        process.check_request(request)
        p.require(self._value["apiVersion"] in INITIAL_POLICY_APIS)
        return copy.deepcopy(self._value["ordinaryInitialHistories"])

    def ordinary_delivery_policy(self, *, process, request) -> dict:
        """Only v5+ delegate ordinary public-input installation and C9 decisions."""
        self.check(process)
        process.check_request(request)
        p.require(self._value["apiVersion"] in DELIVERY_POLICY_APIS)
        return copy.deepcopy(self._ordinary_deliveries)

    def helper_initial_policy(self, *, process, request) -> dict | None:
        """Only explicit v14 supplies supplementary roles; never infer them."""
        self.check(process)
        process.check_request(request)
        if self._value["apiVersion"] not in HELPER_INITIAL_POLICY_APIS:
            return None
        p.require(self._helper_initial is not None)
        return copy.deepcopy(self._helper_initial)

    def current_head_policy(self, *, process, request) -> dict:
        """Permit only late intake; never approve a request's currentness."""
        self.check(process)
        process.check_request(request)
        p.require(self._value["apiVersion"] in CURRENT_HEAD_POLICY_APIS
            and self._current_head_intake is not None)
        return copy.deepcopy(self._current_head_intake)

    def bridge_runtime_policy(self, *, process, request) -> dict:
        """V16+ delegate composition, never release or credential provisioning."""
        self.check(process)
        process.check_request(request)
        p.require(self._value["apiVersion"] in BRIDGE_RUNTIME_POLICY_APIS
            and self._bridge_runtime is not None)
        return copy.deepcopy(self._bridge_runtime)

    def bridge_commissioning_policy(self, *, process, request) -> dict:
        """Only v17+ delegate the seven fixed bridge decisions."""
        self.check(process)
        process.check_request(request)
        p.require(self._value["apiVersion"] in BRIDGE_COMMISSIONING_POLICY_APIS
            and self._bridge_commissioning is not None)
        return copy.deepcopy(self._bridge_commissioning)

    def require_bridge_keys(self, recipe_originals, *, process, request):
        """Bind five capabilities to the genuine runtime owner's retained recipe."""
        from serverware import native_pilot_measured_configuration as measured
        from serverware import native_pilot_native_delivery_profile as native
        self.check(process)
        process.check_request(request)
        p.require(self._value["apiVersion"] in BRIDGE_COMMISSIONING_POLICY_APIS
            and (request.phase, request.job, request.job_index)
                == ("bridge-delivery", "native-delivery-bridge", 1))
        p.fields(recipe_originals, native.RECIPE_FIELDS)
        _, bindings, _ = measured._assignment(
            {"apiVersion": "serverware.nativePilotMeasuredConfigurationRecipe/v2", **recipe_originals}, time.time_ns())
        _, trust = scope._original(recipe_originals["trustOriginal"], 1024 * 1024)
        selected = [row["key"] for row in trust["roleKeys"]
            if row["role"] == "custody-supervisor-capability"]
        p.require(len(selected) == 1 and selected[0]["keyId"]
            == bindings["custody-supervisor-capability"]["keyId"])
        digest = p.sha(p.decoded(selected[0]["publicKeyBase64url"], size=32))
        p.require(all(self._value["keyBindings"][job.key] == digest for job in BRIDGE_AUTHORIZATION_JOBS)
            and digest != self._value["keyBindings"]["native-delivery-bridge"])
        self.check(process)
        process.check_request(request)

    def require_final_scope(self, process):
        """Old policies cannot enter a full run merely because coverage grew."""
        self.check(process)
        p.require(self._value["apiVersion"] in CONTINUATION_POLICY_APIS and self._continuation is not None)

    def continuation_policy(self, *, process, request) -> dict:
        self.require_final_scope(process)
        process.check_request(request)
        return copy.deepcopy(self._continuation)

    def ordinary_generation_policy(self, *, process, request) -> dict:
        """Only v6+ delegate the five fixed ordinary generation decisions."""
        self.check(process)
        process.check_request(request)
        p.require(self._value["apiVersion"] in GENERATION_POLICY_APIS)
        return copy.deepcopy(self._ordinary_generations)

    def native_delivery_policy(self, *, process, request) -> dict:
        """Only v7+ delegate the remaining seven fixed native C9 decisions."""
        self.check(process)
        process.check_request(request)
        p.require(self._value["apiVersion"] in NATIVE_DELIVERY_POLICY_APIS)
        return copy.deepcopy(self._native_deliveries)

    def native_key_authorization_policy(self, *, process, request) -> dict:
        """V8+: match every key capability to the actual signed recipe key."""
        self.check(process)
        process.check_request(request)
        p.require(self._value["apiVersion"] in KEY_AUTHORIZATION_POLICY_APIS)
        self._require_native_signers(process, request, KEY_AUTHORIZATION_JOBS)
        return copy.deepcopy(self._native_key_authorizations)

    def native_service_policy(self, *, process, request) -> dict:
        """V9+: eleven grants under the assignment's supervisor authority."""
        self.check(process)
        process.check_request(request)
        p.require(self._value["apiVersion"] in NATIVE_SERVICE_POLICY_APIS)
        self._require_native_signers(process, request, NATIVE_SERVICE_JOBS)
        return copy.deepcopy(self._native_services)

    def ordinary_transition_policy(self, *, process, request) -> dict:
        """V10+ delegate the five root-authorized ordinary transitions."""
        self.check(process)
        process.check_request(request)
        p.require(self._value["apiVersion"] in ORDINARY_TRANSITION_POLICY_APIS)
        return copy.deepcopy(self._ordinary_transitions)

    def launch_authorization_policy(self, *, process, request) -> dict:
        """V11+ delegate the 31 supervisor-authorized late launch inputs."""
        self.check(process)
        process.check_request(request)
        p.require(self._value["apiVersion"] in LAUNCH_AUTHORIZATION_POLICY_APIS)
        self._require_native_signers(process, request, LAUNCH_AUTHORIZATION_JOBS)
        return copy.deepcopy(self._launch_authorizations)

    def endpoint_launch_policy(self, *, process, request) -> dict:
        """V12+ delegate ten fixed launch bundles, not bridge or release."""
        self.check(process)
        process.check_request(request)
        p.require(self._value["apiVersion"] in ENDPOINT_LAUNCH_POLICY_APIS)
        return copy.deepcopy(self._endpoint_launches)

    def service_material_policy(self, *, process, request) -> dict:
        """V13+ delegate exact fresh public material, not journal writes."""
        self.check(process)
        process.check_request(request)
        p.require(self._value["apiVersion"] in SERVICE_MATERIAL_POLICY_APIS)
        return copy.deepcopy(self._service_material)

    def _require_native_signers(self, process, request, jobs):
        """Check source-selected purposes against independent assignment trust."""
        from serverware import native_pilot_measured_configuration as measured
        self.check(process)
        process.check_request(request)
        recipe = {"apiVersion": "serverware.nativePilotMeasuredConfigurationRecipe/v2",
            **self.endpoint_recipe_originals(process=process, request=request)}
        _, bindings, _ = measured._assignment(recipe, time.time_ns())
        # The retained recipe's signed assignment and independently pinned
        # trust select this key, not a caller-authored result or C9 authority.
        trust_raw, _ = scope._original(recipe["trustOriginal"], 1024 * 1024)
        trust = p.document(trust_raw, 1024 * 1024)
        selected = [row["key"] for row in trust["roleKeys"]
            if row["role"] == "custody-supervisor-capability"]
        p.require(len(selected) == 1 and selected[0]["keyId"]
            == bindings["custody-supervisor-capability"]["keyId"])
        digest = p.sha(p.decoded(selected[0]["publicKeyBase64url"], size=32))
        p.require(all(self._value["keyBindings"][job.key] == digest for job in jobs))
        self.check(process)
        process.check_request(request)

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
            if self._value["apiVersion"] in CONTINUATION_POLICY_APIS:
                from serverware import native_pilot_supervisor_continuation as continuation
                continuation.close(self._process)
            if self._value["apiVersion"] in BRIDGE_COMMISSIONING_POLICY_APIS:
                from serverware import native_pilot_supervisor_bridge_commissioning as bridge_commissioning
                bridge_commissioning.close(self._process)
            if self._value["apiVersion"] in BRIDGE_RUNTIME_POLICY_APIS:
                from serverware import native_pilot_supervisor_bridge_runtime as bridge_runtime
                bridge_runtime.close(self._process)
            if self._value["apiVersion"] in CURRENT_HEAD_POLICY_APIS:
                from serverware import native_pilot_supervisor_current_heads as current_heads
                current_heads.close(self._process)
            if self._value["apiVersion"] in SERVICE_MATERIAL_POLICY_APIS:
                from serverware import native_pilot_supervisor_service_material as service_material
                service_material.close(self._process)
            if self._value["apiVersion"] in ENDPOINT_LAUNCH_POLICY_APIS:
                from serverware import native_pilot_supervisor_endpoint_launches as endpoint_launches
                endpoint_launches.close(self._process)
            if self._value["apiVersion"] in LAUNCH_AUTHORIZATION_POLICY_APIS:
                from serverware import native_pilot_supervisor_launch_authorizations as launch_authorizations
                launch_authorizations.close(self._process)
            if self._value["apiVersion"] in ORDINARY_TRANSITION_POLICY_APIS:
                from serverware import native_pilot_supervisor_ordinary_transitions as ordinary_transitions
                ordinary_transitions.close(self._process)
            if self._value["apiVersion"] in NATIVE_SERVICE_POLICY_APIS:
                from serverware import native_pilot_supervisor_native_services as native_services
                native_services.close(self._process)
            if self._value["apiVersion"] in KEY_AUTHORIZATION_POLICY_APIS:
                from serverware import native_pilot_supervisor_key_authorizations as key_authorizations
                key_authorizations.close(self._process)
            if self._value["apiVersion"] in NATIVE_DELIVERY_POLICY_APIS:
                from serverware import native_pilot_supervisor_native_deliveries as native_deliveries
                native_deliveries.close(self._process)
            if self._value["apiVersion"] in GENERATION_POLICY_APIS:
                from serverware import native_pilot_supervisor_ordinary_generations as ordinary_generations
                ordinary_generations.close(self._process)
            if self._value["apiVersion"] in DELIVERY_POLICY_APIS:
                from serverware import native_pilot_supervisor_ordinary_deliveries as ordinary_deliveries
                ordinary_deliveries.close(self._process)
            if self._value["apiVersion"] in INITIAL_POLICY_APIS:
                from serverware import native_pilot_supervisor_initial_history as ordinary
                ordinary.close(self._process)
            if self._value["apiVersion"] in ENDPOINT_POLICY_APIS:
                from serverware import native_pilot_supervisor_endpoint_inputs as endpoint_inputs
                # Close partial publication/directory owners only after genuine
                # process cleanup. Failure retains this policy and its recipe.
                endpoint_inputs.close(self._process)
        if self._recipe is not None:
            self._recipe.close()
        os.close(self._fd)
        self._closed = True
        _LIVE = None
