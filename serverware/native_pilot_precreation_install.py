"""Publish one approved fixed pilot precreation bundle, control original last.

This checks original-byte, signature and public observation associations only.
It does not reconstruct a DriverBootstrap, attest a process, install binaries,
create a journal/key, or acknowledge launch. Actual retained owners still admit
all live state. An external supervisor must bound filesystem stalls. On any
failure, partial files remain; there is no rollback, replacement or retry.
"""
from __future__ import annotations

import time

from serverware import custody_generation_grants as generation
from serverware import native_pilot_delivery_authority as native_delivery
from serverware import native_pilot_publication as publication
from serverware import native_pilot_scope_authority as scope
from serverware import native_shadow_constructed_driver as admission
from serverware import native_shadow_driver_bootstrap as driver
from serverware import native_shadow_guest_delivery as delivery
from serverware import native_shadow_nitro_originals as originals
from serverware import native_shadow_proof_cohort_assignment as cohort

p = delivery.p
MAX_INPUT = 4 * 1024 * 1024
FIELDS = ("apiVersion", "driverConfigurationOriginal", "driverWindowOriginal", "driverObservationOriginal",
    "cohortConfigurationOriginal", "cohortPrecreationOriginal", "cohortControlOriginal", "ordinaryLaunchOriginal",
    "nativeColdOriginals", "ordinaryColdOriginals")
_USED = False


def _same(first, second):
    p.require(p.canonical(first) == p.canonical(second))


def _pin(purpose, pin, raw):
    delivery._pin(pin)
    p.require(pin["path"] == publication.DESTINATIONS[purpose] and pin["sha256"] == p.sha(raw))


def _driver(config_raw, window_raw, observed_raw):
    config = p.fields(p.document(config_raw, 65536), ("apiVersion", "bootstrapAuthority", "phaseTwoAuthority",
        "deliveryConfiguration", "uid", "gid", "image", "continuation", "lifecycle"))
    p.require(config["apiVersion"] == "serverware.nativeShadowDriverBootstrapConfiguration/v4")
    for field in ("uid", "gid"):
        p.integer(config[field], maximum=(1 << 32) - 2)
        p.require(config[field] not in {64988, 64989, 64990, 65534})
    delivery._pin(config["deliveryConfiguration"])
    bootstrap_key = driver._key(config["bootstrapAuthority"])
    driver._key(config["phaseTwoAuthority"])
    p.require(config["bootstrapAuthority"] != config["phaseTwoAuthority"])
    continuation = p.fields(config["continuation"], ("apiVersion", "keyTransport"))
    p.require(continuation["apiVersion"] == "serverware.nativeShadowDriverContinuationPreparation/v3")
    lifecycle = p.fields(config["lifecycle"], ("apiVersion", "gate", "cleanupReserveNanos", "constructedAdmissionAuthority"))
    p.require(lifecycle["apiVersion"] == "serverware.nativeShadowDriverLifecyclePolicy/v3")
    gate = p.fields(lifecycle["gate"], ("uid", "gid", "executableSha256"))
    p.require(p.integer(gate["uid"]) == 65534 and p.integer(gate["gid"]) == 65534)
    p.digest(gate["executableSha256"])
    admission.authority(lifecycle["constructedAdmissionAuthority"])
    p.require(lifecycle["constructedAdmissionAuthority"]["publicKeyBase64url"] not in
        (config["bootstrapAuthority"]["publicKeyBase64url"], config["phaseTwoAuthority"]["publicKeyBase64url"]))
    reserve = p.integer(lifecycle["cleanupReserveNanos"], minimum=1_000_000, maximum=5_000_000_000)
    signed = p.fields(p.document(window_raw, 32768), ("apiVersion", "payload", "signatureBase64url"))
    window = p.fields(signed["payload"], scope.WINDOW_FIELDS)
    p.require(signed["apiVersion"] == "serverware.nativeShadowDriverBootstrapWindow/v1"
        and window["configurationSha256"] == p.sha(config_raw)
        and window["signingKeyId"] == config["bootstrapAuthority"]["keyId"])
    bootstrap_key.verify(p.decoded(signed["signatureBase64url"], size=64), driver.WINDOW_DOMAIN + p.canonical(window))
    now = native_delivery._live(window)
    p.require(p.ns(window["startupDeadlineBoottimeNs"]) < p.ns(window["lifetimeDeadlineBoottimeNs"]) - reserve)
    observed = p.fields(p.document(observed_raw, 65536), ("apiVersion", "configurationSha256", "windowSha256",
        "invocationId", "processId", "uid", "gid", "cgroupOriginalSha256", "root", "seccompFilterCount", "descriptors", "driver"))
    p.require(observed["apiVersion"] == "serverware.nativeShadowDriverObservation/v1"
        and observed["configurationSha256"] == p.sha(config_raw) and observed["windowSha256"] == p.sha(window_raw)
        and observed["invocationId"] == window["invocationId"])
    _same([observed["uid"], observed["gid"]], [config["uid"], config["gid"]])
    p.integer(observed["processId"], minimum=2, maximum=(1 << 31) - 1)
    identity = p.fields(observed["driver"], scope.DRIVER_FIELDS)
    for name in scope.DRIVER_FIELDS:
        if name.endswith("Sha256"):
            p.digest(identity[name])
        else:
            p.integer(identity[name], maximum=p.MAX_U64)
    p.require(identity["identitySha256"] == p.framed(b"serverware.policyShadowCustodyKernelDriverIdentity/v1",
        (p.canonical([identity[name] for name in scope.DRIVER_FIELDS[:-1]]),))
        and identity["driverExecutableSha256"] == config["image"]["executableSha256"]
        and identity["supervisorBootIdSha256"] == p.sha(p.decoded(window["bootIdBase64url"], size=16))
        and p.ns(window["issuedAtBoottimeNs"]) <= identity["verifiedAtBoottimeNanos"] <= now)
    return config, window


def _check(window, ordinary, previous=0):
    now = native_delivery._live(window, previous)
    _same(list(originals._boot()), [ordinary[name] for name in native_delivery.WINDOW_FIELDS[:3]])
    startup, lifetime = (p.ns(ordinary[name]) for name in ("startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"))
    p.require(now < startup <= lifetime and startup - now <= 30_000_000_000)
    return now


def _prepare(raw, expected_sha256):
    p.require(type(raw) is bytes and 0 < len(raw) <= MAX_INPUT
        and p.sha(raw) == p.digest(expected_sha256))
    value = p.fields(p.document(raw, MAX_INPUT), FIELDS)
    p.require(value["apiVersion"] == "serverware.nativePilotPrecreationBundle/v1")
    config_raw, _ = scope._original(value["driverConfigurationOriginal"], 65536)
    window_raw, _ = scope._original(value["driverWindowOriginal"], 32768)
    observed_raw, _ = scope._original(value["driverObservationOriginal"], 65536)
    driver_config, window = _driver(config_raw, window_raw, observed_raw)
    cohort_raw, _ = scope._original(value["cohortConfigurationOriginal"], cohort.MAX_BYTES)
    config = cohort.configuration(cohort_raw)
    p.require(cohort.endpoint_driver_selected(config))
    selected = config["externalDriver"]
    p.require(selected["configurationSha256"] == p.sha(config_raw)
        and selected["windowSha256"] == p.sha(window_raw)
        and selected["observationSha256"] == p.sha(observed_raw))
    # supervisorExecutableSha256 is an independently approved pin, not derived
    # from child executable bytes. The real EndpointDriver verifies it later.
    precreation_raw, precreation = scope._original(value["cohortPrecreationOriginal"], cohort.MAX_BYTES)
    p.fields(precreation, ("apiVersion", "payload", "signatureBase64url"))
    p.require(precreation["apiVersion"] == "serverware.nativeShadowProofCohortPrecreation/v1")
    created = p.fields(precreation["payload"], cohort.WINDOW_FIELDS)
    cohort._window(created, config, p.sha(cohort_raw), originals._boot(), time.clock_gettime_ns(time.CLOCK_BOOTTIME))
    driver._key(config["authority"]).verify(p.decoded(precreation["signatureBase64url"], size=64),
        cohort.PRECREATE_DOMAIN + p.canonical(created))
    for name in native_delivery.WINDOW_FIELDS:
        _same(created[name], window[name])
    control_raw, control = scope._original(value["cohortControlOriginal"], 4096)
    p.fields(control, ("apiVersion", "cohortExecutableSha256", "configurationSha256", "precreationSha256"))
    p.require(control["apiVersion"] == "serverware.nativeShadowProofCohortControl/v1"
        and control["configurationSha256"] == p.sha(cohort_raw) and control["precreationSha256"] == p.sha(precreation_raw))
    p.digest(control["cohortExecutableSha256"])
    launch_raw, ordinary = scope._original(value["ordinaryLaunchOriginal"], 65536)
    p.fields(ordinary, ("apiVersion", "bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode",
        "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId", "services"))
    p.require(ordinary["apiVersion"] == "serverware.custodyFiveServiceLaunch/v6")
    for name in ("timeNamespaceDevice", "timeNamespaceInode"):
        p.integer(ordinary[name], maximum=p.MAX_U64)
    cohort._invocation(ordinary["invocationId"])
    _check(window, ordinary)
    services = p.fields(ordinary["services"], generation.ROLES)
    native_cold = p.fields(value["nativeColdOriginals"], cohort.ENDPOINT_ROLES)
    ordinary_cold = p.fields(value["ordinaryColdOriginals"], generation.ROLES)
    planned, native_uids, native_gids = [], set(), set()
    for role in cohort.ENDPOINT_ROLES:
        original, _ = scope._original(native_cold[role], 65536)
        purpose = "native-cold-" + role
        _pin(purpose, config[role + "Configuration"], original)
        cold = delivery.configuration(original, p.sha(original))
        _same(cold["authority"], config["authority"])
        p.require(cold["uid"] not in native_uids and cold["gid"] not in native_gids
            and cold["uid"] != driver_config["uid"] and cold["gid"] != driver_config["gid"])
        native_uids.add(cold["uid"]); native_gids.add(cold["gid"])
        planned.append((purpose, original))
    ordinary_uids, ordinary_gids = set(), set()
    for role in generation.ROLES:
        spec = p.fields(services[role], ("executableSha256", "deliveryConfiguration"))
        p.digest(spec["executableSha256"])
        original, _ = scope._original(ordinary_cold[role], 65536)
        purpose = "ordinary-cold-" + role
        _pin(purpose, spec["deliveryConfiguration"], original)
        cold = generation.configuration(original, p.sha(original), role)
        p.require(cold["uid"] not in ordinary_uids and cold["gid"] not in ordinary_gids)
        ordinary_uids.add(cold["uid"]); ordinary_gids.add(cold["gid"])
        planned.append((purpose, original))
    planned += [("cohort-configuration", cohort_raw), ("cohort-precreation", precreation_raw),
        ("ordinary-launch", launch_raw), ("cohort-control", control_raw)]
    p.require(len(planned) == 19 and len({purpose for purpose, _ in planned}) == 19)
    # Run every publisher shape check before the first file creation as well.
    for purpose, original in planned:
        p.require(purpose in publication.DESTINATIONS and len(original) <= publication.LIMITS[purpose])
        publication._shape(purpose, original)
    _check(window, ordinary)
    return tuple(planned), window, ordinary


def install(bundle_original: bytes, *, expected_sha256: str) -> dict:
    """Publish exact originals once; returned pins are observations, not launch."""
    global _USED
    p.require(not _USED)
    _USED = True  # Refusal or partial publication never enables an in-process retry.
    planned, window, ordinary = _prepare(bundle_original, expected_sha256)
    publisher = publication.PublicPublisher.open()
    try:
        publisher.require_absent(tuple(purpose for purpose, _ in planned))
        previous = _check(window, ordinary)
        pins = {}
        for purpose, raw in planned:
            previous = _check(window, ordinary, previous)
            pins[purpose] = publisher.publish(purpose=purpose, raw=raw, expected_sha256=p.sha(raw))
            previous = _check(window, ordinary, previous)
        publisher.check()
        deadline = min(p.ns(window["startupDeadlineBoottimeNs"]), p.ns(ordinary["startupDeadlineBoottimeNs"]))
        return {"apiVersion": "serverware.nativePilotPrecreationPublication/v1", "bundleSha256": expected_sha256,
            "startupDeadlineBoottimeNs": str(deadline), "pins": pins}
    finally:
        publisher.close()  # Descriptor cleanup only; published/partial files remain.
