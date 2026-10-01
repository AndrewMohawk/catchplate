"""Purpose-fixed PhaseScope/v4 producer from independently approved originals.

The protected input and matching phase-two key must be provisioned and approved
by their independent authority. This producer verifies their byte associations;
it neither discovers processes nor reconstructs a DriverBootstrap owner. Native
admission still checks real descriptors, service signatures and currentness.
"""
from __future__ import annotations

import re
import stat
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from serverware import custody_generation_grants as generation
from serverware import native_shadow_constructed_driver as admission
from serverware import native_shadow_driver_bootstrap as driver
from serverware import native_shadow_guest_delivery as delivery
from serverware import native_shadow_nitro_originals as originals
from serverware import native_shadow_nitro_profile as p
from serverware import native_pilot_bridge_runtime as bridge_runtime

MAX_INPUT = 4 * 1024 * 1024
MAX_BRIDGE_INPUT = bridge_runtime.MAX_BRIDGE_INPUT
MAX_SCOPE = 32768
DOMAIN = b"serverware.nativeShadowDriverScope.signature/v4\0"
INPUT_FIELDS = ("apiVersion", "configurationOriginal", "windowOriginal", "observationOriginal",
    "operationOriginal", "publicBundleOriginal", "deliveryConfigurationOriginal", "launchOriginal",
    "bootstrapAdmissionOriginal")
WINDOW_FIELDS = ("configurationSha256", "signingKeyId", "bootIdBase64url", "timeNamespaceDevice",
    "timeNamespaceInode", "issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId")
DRIVER_FIELDS = ("driverInstanceSha256", "driverExecutableSha256", "supervisorBootIdSha256",
    "processStartTimeTicks", "pidfdInode", "cgroupId", "cgroupMountId", "cgroupInode",
    "retainedDescriptorManifestSha256", "verifiedAtBoottimeNanos", "identitySha256")
PRODUCTION_FIELDS = ("signerBackendSha256", "persistenceBackendSha256", "retrievalBackendSha256",
    "dispatcherProtocolSetSha256", "maximumRpcNanos", "cleanupReserveNanos", "maximumInFlightCalls",
    "maximumAsyncDurabilityNanos", "expectedConfigurationBindingSha256")
BOOTSTRAP_FIELDS = ("apiVersion", "purpose", "configurationSha256", "windowSha256",
    "bootstrapObservationOriginal", "parent", "parentExecutableSha256", "pidNamespaceSha256",
    "issuedAtUnixNanos", "expiresAtUnixNanos", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs",
    "signingKeyId", "signingKeySpkiSha256")


def _original(value, maximum):
    p.require(type(value) is str and value.isascii() and 0 < len(value) <= maximum)
    raw = value.encode("ascii")
    return raw, p.document(raw, maximum)


def _generation_original(value):
    """The existing ordinary grant codec admits u64, under its fixed 64KiB cap."""
    p.require(type(value) is str and value.isascii() and 0 < len(value) <= 65536)
    raw = value.encode("ascii")
    return raw, generation.document(raw, 65536)


def _same(first, second):
    p.require(p.canonical(first) == p.canonical(second))


def _live(window, bootstrap, previous_boot=0, previous_wall=0):
    boot = originals._boot()
    p.require(boot == (window["bootIdBase64url"], window["timeNamespaceDevice"], window["timeNamespaceInode"]))
    now, wall = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
    p.require(previous_boot <= now and previous_wall <= wall
        and p.ns(window["issuedAtBoottimeNs"]) <= now < p.ns(window["startupDeadlineBoottimeNs"]))
    p.freshness(bootstrap["issuedAtUnixNanos"], bootstrap["expiresAtUnixNanos"], wall)
    return now, wall


def _at(window, bootstrap, *, boot, now_boottime_ns, now_unix_ns):
    """Explicit-clock counterpart of _live; no owner or clock is created."""
    p.require(boot == (window["bootIdBase64url"], window["timeNamespaceDevice"], window["timeNamespaceInode"]))
    p.integer(now_boottime_ns, minimum=0, maximum=p.MAX_U64)
    p.integer(now_unix_ns, minimum=0)
    p.require(p.ns(window["issuedAtBoottimeNs"]) <= now_boottime_ns
        < p.ns(window["startupDeadlineBoottimeNs"]))
    p.freshness(bootstrap["issuedAtUnixNanos"], bootstrap["expiresAtUnixNanos"], now_unix_ns)
    return now_boottime_ns, now_unix_ns


def _operation(operation, launch, c9, raw_files):
    p.fields(operation, ("apiVersion", "launch", "descriptors", "production"))
    p.require(operation["apiVersion"] == "serverware.nativeShadowDriverOperation/v1")
    delivery._pin(operation["launch"])
    p.require(operation["launch"]["sha256"] == p.sha(raw_files["launch"]))
    production = p.fields(operation["production"], PRODUCTION_FIELDS)
    for field in PRODUCTION_FIELDS[:4] + PRODUCTION_FIELDS[-1:]:
        p.digest(production[field])
    p.require(250_000_000 <= p.integer(production["maximumRpcNanos"]) <= 1_000_000_000
        and p.integer(production["cleanupReserveNanos"]) <= 5_000_000_000
        and p.integer(production["maximumInFlightCalls"]) <= 64
        and p.integer(production["maximumAsyncDurabilityNanos"]) <= production["maximumRpcNanos"])
    records = operation["descriptors"]
    p.require(type(records) is list and 1 <= len(records) <= 94)
    names, identities, by_name = [], set(), {}
    for record in records:
        p.fields(record, ("name", "device", "inode", "mode", "uid", "gid", "length"))
        name = record["name"]
        p.require(type(name) is str and name.isascii() and 1 <= len(name) <= 256
            and all(32 < ord(character) < 127 for character in name))
        for field in ("device", "inode", "length"):
            p.integer(record[field], minimum=1 if field == "inode" else 0, maximum=p.MAX_U64)
        for field in ("mode", "uid", "gid"):
            p.integer(record[field], minimum=0, maximum=(1 << 32) - 1)
        identity = record["device"], record["inode"]
        p.require(identity not in identities)
        identities.add(identity); names.append(name); by_name[name] = record
    p.require(names == sorted(set(names)))
    expected = {"launch", "c9-configuration", "c9-delivery", "c9-runtime", "trust", "time", "assignment",
        "closure", "keys", "encrypted", "admission", "verifier", "time-grant"}
    for name, raw in raw_files.items():
        record = by_name[name]
        p.require(stat.S_ISREG(record["mode"]) and stat.S_IMODE(record["mode"]) == 0o400
            and record["uid"] == record["gid"] == 0 and record["length"] == len(raw))
    credentials = c9["credentials"]
    p.require(type(credentials) is list and 1 <= len(credentials) <= 64)
    total = 0
    for credential in credentials:
        p.fields(credential, ("name", "original", "length", "signing"))
        name = credential["name"]
        p.require(type(name) is str and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name) is not None)
        name = "credential:" + name
        p.require(name not in expected); expected.add(name)
        delivery._pin(credential["original"])
        total += p.integer(credential["length"], maximum=4 * 1024 * 1024)
        record = by_name[name]
        p.require(stat.S_ISREG(record["mode"]) and record["length"] == credential["length"]
            and (record["uid"], record["gid"]) == (c9["uid"], c9["gid"]))
    p.require(total <= 16 * 1024 * 1024)
    activation = c9["activation"]
    p.require(type(activation) is list and 1 <= len(activation) <= 64)
    for fd, entry in enumerate(activation, 6):
        p.fields(entry, ("name", "fd", "device", "inode", "mode", "uid", "gid"))
        name = entry["name"]
        p.require(type(name) is str and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name) is not None
            and type(entry["fd"]) is int and entry["fd"] == fd)
        name = "activation:" + name
        p.require(name not in expected); expected.add(name)
        record = by_name[name]
        _same({key: record[key] for key in ("device", "inode", "mode", "uid", "gid")},
              {key: entry[key] for key in ("device", "inode", "mode", "uid", "gid")})
        p.require(stat.S_IFMT(record["mode"]) in (stat.S_IFSOCK, stat.S_IFDIR))
    p.require(set(names) == expected)
    for name in ("deliveryConfiguration", "delivery", "trust", "timeBootstrap", "assignment", "closure",
                 "keys", "encryptedKeys", "admission", "verifierTransport"):
        delivery._pin(launch["keyAdmission"][name])
    delivery._pin(launch["trustedTime"])


def prepare_input(input_original: bytes, *, boot, now_boottime_ns, now_unix_ns) -> dict:
    """Derive the unchanged Scope/v4 from complete public originals only.

    Explicit clocks and supplied observations are checked data, not provenance,
    permission to release, a process owner or proof of native admission.
    """
    value = p.fields(p.document(input_original, MAX_BRIDGE_INPUT), INPUT_FIELDS)
    p.require(value["apiVersion"] == "serverware.nativePilotScopeSigningInput/v1")
    config_raw, config = _original(value["configurationOriginal"], 65536)
    window_raw, signed_window = _original(value["windowOriginal"], 32768)
    observation_raw, observation = _original(value["observationOriginal"], 65536)
    operation_raw, operation = _original(value["operationOriginal"], 65536)
    bundle_raw, bundle = _original(value["publicBundleOriginal"], MAX_BRIDGE_INPUT)
    runtime_raw, runtime = bridge_runtime.original(bundle["runtimeOriginal"])
    p.require(bridge_runtime.version(runtime) in (10, 11, 12) or (len(input_original) <= MAX_INPUT and len(bundle_raw) <= 1024 * 1024))
    cold_raw, _ = _original(value["deliveryConfigurationOriginal"], 65536)
    launch_raw, launch = _original(value["launchOriginal"], 32768)
    _, signed_bootstrap = _original(value["bootstrapAdmissionOriginal"], 8192)
    p.fields(config, ("apiVersion", "bootstrapAuthority", "phaseTwoAuthority", "deliveryConfiguration",
        "uid", "gid", "image", "continuation", "lifecycle"))
    p.require(config["apiVersion"] == "serverware.nativeShadowDriverBootstrapConfiguration/v4")
    bootstrap_key, phase_key = driver._key(config["bootstrapAuthority"]), driver._key(config["phaseTwoAuthority"])
    p.require(config["bootstrapAuthority"]["keyId"] != config["phaseTwoAuthority"]["keyId"])
    delivery._pin(config["deliveryConfiguration"])
    cold = delivery.configuration(cold_raw, config["deliveryConfiguration"]["sha256"])
    _same([config["uid"], config["gid"]], [cold["uid"], cold["gid"]])
    lifecycle = p.fields(config["lifecycle"], ("apiVersion", "gate", "cleanupReserveNanos", "constructedAdmissionAuthority"))
    p.require(lifecycle["apiVersion"] == "serverware.nativeShadowDriverLifecyclePolicy/v3")
    admission_key = admission.authority(lifecycle["constructedAdmissionAuthority"])
    p.require(lifecycle["constructedAdmissionAuthority"]["publicKeyBase64url"] not in
        (config["bootstrapAuthority"]["publicKeyBase64url"], config["phaseTwoAuthority"]["publicKeyBase64url"]))
    p.fields(signed_window, ("apiVersion", "payload", "signatureBase64url"))
    window = p.fields(signed_window["payload"], WINDOW_FIELDS)
    p.require(signed_window["apiVersion"] == "serverware.nativeShadowDriverBootstrapWindow/v1"
        and window["configurationSha256"] == p.sha(config_raw)
        and window["signingKeyId"] == config["bootstrapAuthority"]["keyId"])
    bootstrap_key.verify(p.decoded(signed_window["signatureBase64url"], size=64), driver.WINDOW_DOMAIN + p.canonical(window))
    issued, startup, lifetime = (p.ns(window[name]) for name in
        ("issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"))
    p.require(issued < startup <= lifetime and startup - issued <= 30_000_000_000
        and startup < lifetime - p.integer(lifecycle["cleanupReserveNanos"], minimum=1_000_000, maximum=5_000_000_000)
        and type(window["invocationId"]) is str and re.fullmatch(r"[0-9a-f]{32}", window["invocationId"])
        and window["invocationId"] != "0" * 32)
    p.fields(signed_bootstrap, ("payload", "signature"))
    early = p.fields(signed_bootstrap["payload"], BOOTSTRAP_FIELDS)
    admission_key.verify(p.decoded(signed_bootstrap["signature"], size=64), p.preimage(admission.BOOTSTRAP_DOMAIN, early))
    p.require(early["apiVersion"] == "serverware.nativeShadowBootstrapDriverAdmission/v1"
        and early["purpose"] == "native-driver-bootstrap-admission"
        and early["configurationSha256"] == p.sha(config_raw) and early["windowSha256"] == p.sha(window_raw)
        and early["bootstrapObservationOriginal"] == value["observationOriginal"]
        and early["signingKeyId"] == lifecycle["constructedAdmissionAuthority"]["keyId"]
        and early["signingKeySpkiSha256"] == lifecycle["constructedAdmissionAuthority"]["keySpkiSha256"]
        and early["expiresAtUnixNanos"] - early["issuedAtUnixNanos"] <= 30_000_000_000)
    for name in ("startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"):
        p.require(early[name] == window[name])
    now, _ = _at(window, early, boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    p.fields(observation, ("apiVersion", "configurationSha256", "windowSha256", "invocationId", "processId",
        "uid", "gid", "cgroupOriginalSha256", "root", "seccompFilterCount", "descriptors", "driver"))
    p.require(observation["apiVersion"] == "serverware.nativeShadowDriverObservation/v1"
        and observation["configurationSha256"] == p.sha(config_raw) and observation["windowSha256"] == p.sha(window_raw)
        and observation["invocationId"] == window["invocationId"])
    _same([observation["uid"], observation["gid"]], [cold["uid"], cold["gid"]])
    identity = p.fields(observation["driver"], DRIVER_FIELDS)
    for name in DRIVER_FIELDS:
        if name.endswith("Sha256"):
            p.digest(identity[name])
        else:
            p.integer(identity[name], maximum=p.MAX_U64)
    p.require(identity["identitySha256"] == p.framed(b"serverware.policyShadowCustodyKernelDriverIdentity/v1",
        (p.canonical([identity[name] for name in DRIVER_FIELDS[:-1]]),))
        and identity["driverExecutableSha256"] == config["image"]["executableSha256"]
        and identity["supervisorBootIdSha256"] == p.sha(p.decoded(window["bootIdBase64url"], size=16))
        and issued <= identity["verifiedAtBoottimeNanos"] <= now < startup)
    p.fields(bundle, ("runtimeOriginal", "deliveryOriginal", "generationOriginals"))
    p.require(bridge_runtime.version(runtime) in (9, 10, 11, 12))
    delivery_raw, signed_delivery = _original(bundle["deliveryOriginal"], 65536)
    p.fields(signed_delivery, ("apiVersion", "payload", "signatureBase64url"))
    c9 = p.fields(signed_delivery["payload"], delivery.FIELDS)
    driver._key(cold["authority"]).verify(p.decoded(signed_delivery["signatureBase64url"], size=64),
        delivery.DOMAIN + p.canonical(c9))
    p.require(signed_delivery["apiVersion"] == "serverware.policyCustodyGuestDelivery/v1"
        and c9["configurationSha256"] == config["deliveryConfiguration"]["sha256"]
        and c9["authorityKeyId"] == cold["authority"]["keyId"])
    for name in ("serviceRole", "uid", "gid"):
        _same(c9[name], cold[name])
    for name in WINDOW_FIELDS[2:]:
        _same(c9[name], window[name])
    delivery._pin(c9["runtimeConfig"])
    p.require(c9["runtimeConfig"]["sha256"] == p.sha(runtime_raw))
    p.fields(launch, ("apiVersion", "keyAdmission", "trustedTime"))
    p.require(launch["apiVersion"] == bridge_runtime.launch_for_runtime(runtime_raw))
    inner = p.fields(launch["keyAdmission"], ("apiVersion", "deliveryConfiguration", "delivery", "trust", "timeBootstrap",
        "assignment", "closure", "keys", "encryptedKeys", "admission", "verifierTransport"))
    p.require(inner["apiVersion"] == "serverware.nativeShadowGuestLaunch/v1"
        and inner["delivery"]["sha256"] == p.sha(delivery_raw))
    _same(inner["deliveryConfiguration"], config["deliveryConfiguration"])
    _operation(operation, launch, c9, {"launch": launch_raw, "c9-configuration": cold_raw,
        "c9-delivery": delivery_raw, "c9-runtime": runtime_raw})
    grants = p.fields(bundle["generationOriginals"], driver.ROLES)
    grant_pins = {role: p.sha(_generation_original(grants[role])[0]) for role in driver.ROLES}
    # As in PhaseTwo::retain, these are exact retained public originals, not
    # a replacement for each service's history/signature/currentness checks.
    scope = {"apiVersion": "serverware.nativeShadowDriverScope/v4", "configurationSha256": p.sha(config_raw),
        "windowSha256": p.sha(window_raw), "observationSha256": p.sha(observation_raw),
        "kernelDriverIdentitySha256": identity["identitySha256"], "invocationId": window["invocationId"],
        "startupDeadlineBoottimeNs": window["startupDeadlineBoottimeNs"],
        "lifetimeDeadlineBoottimeNs": window["lifetimeDeadlineBoottimeNs"],
        "originals": {"runtimeSha256": p.sha(runtime_raw), "deliverySha256": p.sha(delivery_raw), "generationGrants": grant_pins},
        "publicBundleSha256": p.sha(bundle_raw), "signingKeyId": config["phaseTwoAuthority"]["keyId"], "operation": operation}
    p.require(p.canonical(operation) == operation_raw)
    message = DOMAIN + p.canonical(scope)
    p.require(len(p.canonical({"payload": scope, "signatureBase64url": ""})) + 86 <= MAX_SCOPE)
    return {"payload": scope, "key": phase_key, "window": window, "bootstrap": early,
        "deadline": startup, "epochLimit": early["expiresAtUnixNanos"], "message": message}


def checked_result(input_original, result, *, boot, now_boottime_ns, now_unix_ns) -> bytes:
    context = prepare_input(input_original, boot=boot,
        now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    p.fields(result, ("original", "sha256"))
    raw, signed = _original(result["original"], MAX_SCOPE)
    p.fields(signed, ("payload", "signatureBase64url"))
    p.require(p.sha(raw) == p.digest(result["sha256"]))
    _same(signed["payload"], context["payload"])
    context["key"].verify(p.decoded(signed["signatureBase64url"], size=64), context["message"])
    return raw


def sign(input_original: bytes, signing_key: Ed25519PrivateKey) -> bytes:
    """Sign only the derived existing Scope/v4 under actual pre/post clocks."""
    p.require(isinstance(signing_key, Ed25519PrivateKey))
    boot, now, wall = originals._boot(), originals._clock(), time.time_ns()
    context = prepare_input(input_original, boot=boot, now_boottime_ns=now, now_unix_ns=wall)
    public = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    expected = context["key"].public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(public == expected)
    now, wall = _live(context["window"], context["bootstrap"], now, wall)
    message = context["message"]
    signature = signing_key.sign(message)
    context["key"].verify(signature, message)
    result = p.canonical({"payload": context["payload"], "signatureBase64url": p.encoded(signature)})
    p.require(len(result) <= MAX_SCOPE)
    _live(context["window"], context["bootstrap"], now, wall)
    return result
