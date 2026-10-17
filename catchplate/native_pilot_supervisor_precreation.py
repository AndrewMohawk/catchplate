"""Closed composition for two genuine endpoint-precreation authority jobs.

Independent policy supplies authorities, executable pins, complete cold inputs
and an already provisioned cleanup journal/genesis binding. Only fixed pins,
hashes and the original admitted window are composed from those inputs and the
actual process-owned requests/results. There are no templates, replacements,
signers, filesystem writes, fabricated observations or renewed timestamps here.
The independent supervisor spine alone approves/publishes the resulting input.
"""
from __future__ import annotations

import copy
import time

from catchplate import custody_generation_grants as generation
from catchplate import native_pilot_delivery_authority as c9
from catchplate import native_pilot_driver_authority as driver_authority
from catchplate import native_pilot_precreation_install as installation
from catchplate import native_pilot_publication as publication
from catchplate import native_pilot_scope_authority as scope
from catchplate import native_pilot_window_authority as window_authority
from catchplate import native_shadow_constructed_driver as admission
from catchplate import native_shadow_driver_bootstrap as driver
from catchplate import native_shadow_guest_delivery as delivery
from catchplate import native_shadow_nitro_originals as originals
from catchplate import native_shadow_proof_cohort_assignment as cohort
from catchplate import native_shadow_proof_cohort_cleanup as cleanup

p = delivery.p
FIELDS = ("apiVersion", "authority", "endpointExecutableSha256", "cohortExecutableSha256",
    "cleanup", "nativeColdOriginals", "ordinaryColdOriginals", "ordinaryExecutableSha256")
_JOBS = ("cohort-precreation", "install-precreation")
_ATTEMPTED = set()


def validate_policy(fragment, *, bootstrap_configuration: dict) -> dict:
    """Pure exact-eight-field policy validation, not an approval or live owner.

    The independent SupervisorPolicy calls this before admitting its protected
    original. Cleanup identity/genesis must already be independently provisioned;
    this function neither creates them nor proves their current filesystem state.
    """
    p.fields(fragment, FIELDS)
    p.require(fragment["apiVersion"] == "catchplate.nativePilotSupervisorPrecreationPolicy/v1")
    driver._key(fragment["authority"])
    p.digest(fragment["endpointExecutableSha256"])
    p.digest(fragment["cohortExecutableSha256"])
    cleanup.configuration({"apiVersion": "catchplate.nativeShadowProofCohortConfiguration/v7",
        "authority": fragment["authority"], "cleanup": fragment["cleanup"]})
    native = p.fields(fragment["nativeColdOriginals"], cohort.ENDPOINT_ROLES)
    ordinary = p.fields(fragment["ordinaryColdOriginals"], generation.ROLES)
    executables = p.fields(fragment["ordinaryExecutableSha256"], generation.ROLES)
    native_uids, native_gids = {bootstrap_configuration["uid"]}, {bootstrap_configuration["gid"]}
    for role in cohort.ENDPOINT_ROLES:
        raw, _ = scope._original(native[role], 65536)
        cold = delivery.configuration(raw, p.sha(raw))
        c9._same(cold["authority"], fragment["authority"])
        p.require(cold["uid"] not in native_uids and cold["gid"] not in native_gids)
        native_uids.add(cold["uid"]); native_gids.add(cold["gid"])
    ordinary_uids, ordinary_gids = set(), set()
    for role in generation.ROLES:
        raw, _ = scope._original(ordinary[role], 65536)
        cold = generation.configuration(raw, p.sha(raw), role)
        p.digest(executables[role])
        p.require(cold["uid"] not in ordinary_uids and cold["gid"] not in ordinary_gids)
        ordinary_uids.add(cold["uid"]); ordinary_gids.add(cold["gid"])
    return copy.deepcopy(fragment)


def _phase(process, phase):
    value = p.fields(process.conductor_request(phase),
        ("apiVersion", "sequence", "phase", "payload", "deadlineBoottimeNs"))
    p.require(value["apiVersion"] == "catchplate.nativePilotOperatorRequest/v1" and value["phase"] == phase)
    p.ns(value["deadlineBoottimeNs"])
    return value


def _bootstrap(policy, process, request):
    approved = p.fields(policy.bootstrap_originals(), ("control", "configuration", "window", "deliveryConfiguration"))
    retained = p.fields(process.bootstrap_originals(), tuple(approved))
    p.require(all(type(raw) is bytes and raw == retained[name] for name, raw in approved.items()))
    control = p.fields(p.document(approved["control"], 4096),
        ("apiVersion", "supervisorExecutableSha256", "configurationSha256", "windowSha256"))
    p.require(control["apiVersion"] == "catchplate.nativeShadowDriverBootstrapControl/v1")
    p.digest(control["supervisorExecutableSha256"])
    p.require(control["configurationSha256"] == p.sha(approved["configuration"])
        and control["windowSha256"] == p.sha(approved["window"]))
    config = window_authority.validate_configuration(approved["configuration"])
    cold = window_authority.validate_delivery(config, approved["deliveryConfiguration"])
    signed_window = p.fields(p.document(approved["window"], 32768), ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed_window["apiVersion"] == "catchplate.nativeShadowDriverBootstrapWindow/v1")
    window = signed_window["payload"]
    driver._key(config["bootstrapAuthority"]).verify(p.decoded(signed_window["signatureBase64url"], size=64),
        driver.WINDOW_DOMAIN + p.canonical(window))
    window_authority.validate_window(window, approved["configuration"], config,
        boot=originals._boot(), now=originals._clock())
    p.require(request.deadline_boottime_ns == p.ns(window["startupDeadlineBoottimeNs"]))
    early = _phase(process, "bootstrap-admission")
    p.fields(early["payload"], ("bootstrapObservationOriginal", "admissionPayloadOriginal"))
    current = _phase(process, "endpoint-precreation")
    p.fields(current["payload"], ("bootstrapObservationOriginal", "bootstrapAdmissionOriginal", "gateBindingOriginal"))
    p.require(early["deadlineBoottimeNs"] == current["deadlineBoottimeNs"] == window["startupDeadlineBoottimeNs"]
        and p.sha(p.canonical(current)) == request.value["conductorRequestSha256"])
    observed_raw, _ = scope._original(early["payload"]["bootstrapObservationOriginal"], 65536)
    p.require(current["payload"]["bootstrapObservationOriginal"] == observed_raw.decode("ascii"))
    driver_authority._observation(observed_raw, control, config, window, originals._clock())
    # This exact input was produced by the admitted policy, installed and sent
    # for the prior real request, not merely an earlier caller-supplied digest.
    input_raw = policy.bootstrap_input_original()
    expected_input = {"apiVersion": "catchplate.nativePilotDriverAuthorityInput/v1", "operation": "bootstrap",
        **{name + "Original": raw.decode("ascii") for name, raw in approved.items()},
        "observationOriginal": observed_raw.decode("ascii"), "payloadOriginal": early["payload"]["admissionPayloadOriginal"]}
    p.require(type(input_raw) is bytes and input_raw == p.canonical(expected_input)
        and p.sha(input_raw) == process.approved_input_sha256("bootstrap-admission", "driver-bootstrap"))
    result = p.fields(process.prior_result("bootstrap-admission", "driver-bootstrap"), ("original", "sha256", "pin"))
    signed_raw, signed = scope._original(result["original"], 8192)
    p.require(p.sha(signed_raw) == p.digest(result["sha256"])
        and current["payload"]["bootstrapAdmissionOriginal"] == result["original"])
    c9._same(result["pin"], {"path": publication.DESTINATIONS["driver-bootstrap-admission"], "sha256": p.sha(signed_raw)})
    p.fields(signed, ("payload", "signature"))
    payload_raw, _ = scope._original(early["payload"]["admissionPayloadOriginal"], 8192)
    p.require(p.canonical(signed["payload"]) == payload_raw)
    selected = config["lifecycle"]["constructedAdmissionAuthority"]
    authority = admission.authority(selected)
    authority.verify(p.decoded(signed["signature"], size=64), p.preimage(admission.BOOTSTRAP_DOMAIN, signed["payload"]))
    driver_authority._bootstrap(signed["payload"], observed_raw, control, window, selected)
    p.freshness(signed["payload"]["issuedAtUnixNanos"], signed["payload"]["expiresAtUnixNanos"],
        time.time_ns(), 30_000_000_000)
    _gate(current["payload"]["gateBindingOriginal"], control, config, window, observed_raw, signed["payload"])
    return approved, control, config, cold, window, observed_raw, signed["payload"]


def _gate(raw_text, control, config, window, observed_raw, bootstrap):
    _, notice = scope._original(raw_text, 8192)
    p.fields(notice, ("apiVersion", "configurationSha256", "windowSha256", "bootstrapObservationSha256",
        "gateExecutableSha256", "binding"))
    p.require(notice["apiVersion"] == "catchplate.nativeShadowDriverGateBound/v1"
        and notice["configurationSha256"] == control["configurationSha256"]
        and notice["windowSha256"] == control["windowSha256"]
        and notice["bootstrapObservationSha256"] == p.sha(observed_raw))
    gate = config["lifecycle"]["gate"]
    p.require(notice["gateExecutableSha256"] == gate["executableSha256"])
    binding = p.fields(notice["binding"], ("apiVersion", "preparedSha256", "gateProcessId", "gateStartTimeTicks",
        "uid", "gid", "observedAtBoottimeNs"))
    p.require(binding["apiVersion"] == "catchplate.nativeShadowDriverLifecycleBound/v1")
    p.integer(binding["gateProcessId"], minimum=2, maximum=(1 << 31) - 1)
    p.integer(binding["gateStartTimeTicks"], maximum=p.MAX_U64)
    c9._same([binding["uid"], binding["gid"]], [gate["uid"], gate["gid"]])
    p.require(p.ns(window["issuedAtBoottimeNs"]) <= p.ns(binding["observedAtBoottimeNs"])
        <= originals._clock() < p.ns(window["startupDeadlineBoottimeNs"]))
    # Exact existing PreparedOriginal transcript from driver_lifecycle.rs. This
    # hash joins a genuine notice to signed prior fields; it creates no notice.
    prepared = {"apiVersion": "catchplate.nativeShadowDriverLifecyclePrepared/v1",
        **{name: bootstrap[name] for name in ("configurationSha256", "windowSha256", "parent",
            "parentExecutableSha256", "pidNamespaceSha256", "lifetimeDeadlineBoottimeNs")}}
    p.require(p.digest(binding["preparedSha256"]) == p.sha(p.canonical(prepared)))


def _configuration(fragment, control, observed_raw):
    config = {"apiVersion": "catchplate.nativeShadowProofCohortConfiguration/v7",
        "authority": fragment["authority"], "executableSha256": fragment["endpointExecutableSha256"],
        "cleanup": fragment["cleanup"], "externalDriver": {
            "configurationSha256": control["configurationSha256"], "windowSha256": control["windowSha256"],
            "observationSha256": p.sha(observed_raw), "supervisorExecutableSha256": control["supervisorExecutableSha256"]}}
    for role in cohort.ENDPOINT_ROLES:
        raw, _ = scope._original(fragment["nativeColdOriginals"][role], 65536)
        config[role + "Configuration"] = {"path": publication.DESTINATIONS["native-cold-" + role], "sha256": p.sha(raw)}
    raw = p.canonical(config)
    cohort.configuration(raw)
    return raw, config


def _signing_input(fragment, config_raw, config, window):
    payload = {"configurationSha256": p.sha(config_raw), "authorityKeyId": config["authority"]["keyId"],
        **{name: window[name] for name in c9.WINDOW_FIELDS}}
    cohort._window(payload, config, p.sha(config_raw), originals._boot(), originals._clock())
    value = {"apiVersion": "catchplate.nativePilotCohortAuthorityInput/v1", "operation": "precreation",
        "configurationOriginal": config_raw.decode("ascii"), "configurationSha256": p.sha(config_raw),
        "coldOriginals": fragment["nativeColdOriginals"], "payloadOriginal": p.canonical(payload).decode("ascii")}
    raw = p.canonical(value)
    p.require(len(raw) <= 2 * 1024 * 1024)
    return raw, payload


def compose(policy, *, process, request) -> bytes:
    """Compose only the two fixed jobs from admitted owners; output is not approval."""
    from catchplate.native_pilot_supervisor_policy import SupervisorPolicy
    from catchplate.native_pilot_supervisor_process import AuthorityCoordinatorProcess, JobRequest

    p.require(type(policy) is SupervisorPolicy and type(process) is AuthorityCoordinatorProcess and type(request) is JobRequest)
    policy.check(process); process.check_request(request)
    p.require(request.phase == "endpoint-precreation" and request.job in _JOBS
        and request.job_index == _JOBS.index(request.job) + 1)
    attempt = (id(process), request.sequence)
    p.require(attempt not in _ATTEMPTED and len(_ATTEMPTED) < 2)
    _ATTEMPTED.add(attempt)  # Refusal never grants an in-process composition retry.
    approved, control, driver_config, cold, window, observed_raw, bootstrap = _bootstrap(policy, process, request)
    fragment = validate_policy(policy.precreation(), bootstrap_configuration=driver_config)
    c9._same(fragment["authority"], cold["authority"])
    config_raw, config = _configuration(fragment, control, observed_raw)
    signing_raw, expected_payload = _signing_input(fragment, config_raw, config, window)
    if request.job == "cohort-precreation":
        result = signing_raw
    else:
        p.require(p.sha(signing_raw) == process.approved_input_sha256("endpoint-precreation", "cohort-precreation"))
        prior = p.fields(process.prior_result("endpoint-precreation", "cohort-precreation"), ("original", "sha256"))
        precreation_raw, signed = scope._original(prior["original"], cohort.MAX_BYTES)
        p.require(p.sha(precreation_raw) == p.digest(prior["sha256"]))
        p.fields(signed, ("apiVersion", "payload", "signatureBase64url"))
        p.require(signed["apiVersion"] == "catchplate.nativeShadowProofCohortPrecreation/v1")
        c9._same(signed["payload"], expected_payload)
        driver._key(config["authority"]).verify(p.decoded(signed["signatureBase64url"], size=64),
            cohort.PRECREATE_DOMAIN + p.canonical(signed["payload"]))
        control_value = {"apiVersion": "catchplate.nativeShadowProofCohortControl/v1",
            "cohortExecutableSha256": fragment["cohortExecutableSha256"],
            "configurationSha256": p.sha(config_raw), "precreationSha256": p.sha(precreation_raw)}
        ordinary = {"apiVersion": "catchplate.custodyFiveServiceLaunch/v6",
            **{name: window[name] for name in c9.WINDOW_FIELDS if name != "issuedAtBoottimeNs"}, "services": {}}
        for role in generation.ROLES:
            cold_raw, _ = scope._original(fragment["ordinaryColdOriginals"][role], 65536)
            ordinary["services"][role] = {"executableSha256": fragment["ordinaryExecutableSha256"][role],
                "deliveryConfiguration": {"path": publication.DESTINATIONS["ordinary-cold-" + role], "sha256": p.sha(cold_raw)}}
        result = p.canonical({"apiVersion": "catchplate.nativePilotPrecreationBundle/v1",
            "driverConfigurationOriginal": approved["configuration"].decode("ascii"),
            "driverWindowOriginal": approved["window"].decode("ascii"), "driverObservationOriginal": observed_raw.decode("ascii"),
            "cohortConfigurationOriginal": config_raw.decode("ascii"), "cohortPrecreationOriginal": precreation_raw.decode("ascii"),
            "cohortControlOriginal": p.canonical(control_value).decode("ascii"), "ordinaryLaunchOriginal": p.canonical(ordinary).decode("ascii"),
            "nativeColdOriginals": fragment["nativeColdOriginals"], "ordinaryColdOriginals": fragment["ordinaryColdOriginals"]})
        # Reuse the actual installer's complete public/signature preparation.
        # _prepare performs no publication or resource creation.
        installation._prepare(result, p.sha(result))
    p.freshness(bootstrap["issuedAtUnixNanos"], bootstrap["expiresAtUnixNanos"], time.time_ns(), 30_000_000_000)
    c9._live(window)
    policy.check(process); process.check_request(request)
    return result
