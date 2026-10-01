"""Fixed pilot C9 delivery signatures from independently approved public originals.

The authority must approve the complete protected input and supply its existing
key. Observations are data from the retained operator, not process/FD authority
created by this producer. Native admission still checks actual descriptors,
service grants, assigned keys and lifetime. No resource or runtime is generated.
"""
from __future__ import annotations

import json
import os
import re
import stat
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from serverware import native_pilot_scope_authority as scope
from serverware import native_pilot_bridge_runtime as bridge_runtime
from serverware import native_shadow_driver_bootstrap as driver
from serverware import native_shadow_driver_outgoing as outgoing
from serverware import native_shadow_guest_delivery as delivery
from serverware import native_shadow_nitro_originals as originals
from serverware import native_shadow_proof_cohort_assignment as cohort

p = delivery.p
MAX_INPUT = 1024 * 1024
MAX_BRIDGE_INPUT = bridge_runtime.MAX_BRIDGE_INPUT
MAX_DELIVERY = delivery.MAX_DELIVERY
INPUT_FIELDS = ("apiVersion", "role", "configurationOriginal", "ownerConfigurationOriginal",
    "windowOriginal", "observationOriginal", "runtimeOriginal", "payloadOriginal", "activationOriginal")
WINDOW_FIELDS = ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode", "issuedAtBoottimeNs",
    "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId")
ACTIVATION_FIELDS = ("name", "fd", "device", "inode", "mode", "uid", "gid")
# Ordered exactly as the real endpoint resource owners expose FD6 onward.
ENDPOINTS = {
    "retrieval": (("retrieval-listener", stat.S_IFSOCK), ("retrieval-objects", stat.S_IFDIR),
        ("ledger-spool-store", stat.S_IFDIR), ("ledger-spool-lock", stat.S_IFREG)),
    "persistence": (("persistence-listener", stat.S_IFSOCK), ("persistence-journal", stat.S_IFDIR),
        ("persistence-lock", stat.S_IFREG)),
    "trustedTime": (("trusted-time-listener", stat.S_IFSOCK),),
    "generationInstall": (("shadow-generation-install-listener", stat.S_IFSOCK),
        ("generation-install-journal", stat.S_IFDIR)),
    "commitRequest": (("commit-request-listener", stat.S_IFSOCK),),
    "ingressAdmission": (("ingress-admission-listener", stat.S_IFSOCK),),
    "terminalAppend": (("terminal-append-listener", stat.S_IFSOCK),),
    "dispatchBarrier": (("dispatch-barrier-listener", stat.S_IFSOCK),),
    "activeEffectBarrier": (("active-effect-barrier-listener", stat.S_IFSOCK),),
    "activeEffectCommit": (("active-effect-commit-listener", stat.S_IFSOCK),),
}


def _same(first, second):
    p.require(p.canonical(first) == p.canonical(second))


def _original(value, maximum, *, array=False):
    p.require(type(value) is str and value.isascii() and 0 < len(value) <= maximum)
    raw = value.encode("ascii")
    if not array:
        return raw, p.document(raw, maximum)
    # p.document deliberately accepts objects only; use its same duplicate,
    # integer and canonical rules for the existing public activation array.
    parsed = json.loads(raw.decode("ascii"), object_pairs_hook=p._pairs,
        parse_float=p._reject, parse_constant=p._reject)
    p.require(type(parsed) is list and p.canonical(parsed) == raw)
    return raw, parsed


def _live(window, previous=0):
    return window_at(window, boot=originals._boot(),
        now=time.clock_gettime_ns(time.CLOCK_BOOTTIME), previous=previous)


def window_at(window, *, boot, now, previous=0):
    """Pure unchanged window checks; supplied clocks do not establish ownership."""
    _same(list(boot), [window[name] for name in WINDOW_FIELDS[:3]])
    p.require(p.decoded(window["bootIdBase64url"], size=16) != bytes(16))
    for name in WINDOW_FIELDS[1:3]:
        p.integer(window[name], maximum=p.MAX_U64)
    issued, startup, lifetime = (p.ns(window[name]) for name in WINDOW_FIELDS[3:6])
    p.integer(now, maximum=p.MAX_U64)
    p.require(previous <= now and issued <= now < startup <= lifetime
        and startup - issued <= 30_000_000_000 and now + 250_000_000 < lifetime)
    cohort._invocation(window["invocationId"])
    return now


def _endpoint_owner(role, cold, cold_raw, config_raw, window_raw, signed, observed):
    now = _live(p.fields(signed, ("apiVersion", "payload", "signatureBase64url"))["payload"])
    return endpoint_owner(role, cold, cold_raw, config_raw, window_raw, signed, observed,
        boot=originals._boot(), now=now)


def endpoint_owner(role, cold, cold_raw, config_raw, window_raw, signed, observed, *, boot, now):
    """Pure original/signature checks; actual callers retain provenance and time."""
    p.require(role in ENDPOINTS)
    config = cohort.configuration(config_raw)
    p.require(cohort.endpoint_driver_selected(config) and tuple(ENDPOINTS) == cohort.ENDPOINT_ROLES)
    _same(config["authority"], cold["authority"])
    pin = config[role + "Configuration"]
    delivery._pin(pin)
    p.require(pin["sha256"] == p.sha(cold_raw))
    p.fields(signed, ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed["apiVersion"] == "serverware.nativeShadowProofCohortPrecreation/v1")
    window = p.fields(signed["payload"], cohort.WINDOW_FIELDS)
    public = driver._key(config["authority"])
    public.verify(p.decoded(signed["signatureBase64url"], size=64),
        cohort.PRECREATE_DOMAIN + p.canonical(window))
    cohort._window(window, config, p.sha(config_raw), boot, now)
    p.fields(observed, cohort.originals_fields(config))
    p.require(observed["apiVersion"] == "serverware.nativeShadowProofCohortOriginals/v6"
        and observed["configurationSha256"] == p.sha(config_raw)
        and observed["precreationSha256"] == p.sha(window_raw)
        and observed["invocationId"] == window["invocationId"])
    cohort.external_driver_sha256(config, observed)
    processes, executables = set(), set()
    for name in cohort.ENDPOINT_ROLES:
        child = p.fields(observed[name], ("processId", "startTimeTicks", "executable"))
        pid = p.integer(child["processId"], minimum=2, maximum=(1 << 31) - 1)
        p.integer(child["startTimeTicks"], maximum=p.MAX_U64)
        exe = p.fields(child["executable"], ("device", "inode", "length", "sha256"))
        p.integer(exe["device"], maximum=p.MAX_U64)
        p.integer(exe["inode"], maximum=p.MAX_U64)
        p.integer(exe["length"], maximum=64 * 1024 * 1024)
        identity = exe["device"], exe["inode"]
        p.require(p.digest(exe["sha256"]) == config["executableSha256"]
            and pid not in processes and identity not in executables)
        processes.add(pid); executables.add(identity)
    return window


def _bridge_owner(cold, cold_raw, config_raw, window_raw, signed, observed):
    return bridge_owner(cold, cold_raw, config_raw, window_raw, signed, observed,
        boot=originals._boot(), now=time.clock_gettime_ns(time.CLOCK_BOOTTIME))


def bridge_owner(cold, cold_raw, config_raw, window_raw, signed, observed, *, boot, now):
    """Pure original/signature checks; the live wrapper supplies actual clocks."""
    config = p.fields(p.document(config_raw, 65536), ("apiVersion", "bootstrapAuthority", "phaseTwoAuthority",
        "deliveryConfiguration", "uid", "gid", "image", "continuation", "lifecycle"))
    p.require(config["apiVersion"] == "serverware.nativeShadowDriverBootstrapConfiguration/v4")
    delivery._pin(config["deliveryConfiguration"])
    p.require(config["deliveryConfiguration"]["sha256"] == p.sha(cold_raw))
    _same([config["uid"], config["gid"]], [cold["uid"], cold["gid"]])
    lifecycle = p.fields(config["lifecycle"], ("apiVersion", "gate", "cleanupReserveNanos", "constructedAdmissionAuthority"))
    p.require(lifecycle["apiVersion"] == "serverware.nativeShadowDriverLifecyclePolicy/v3")
    p.fields(signed, ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed["apiVersion"] == "serverware.nativeShadowDriverBootstrapWindow/v1")
    window = p.fields(signed["payload"], scope.WINDOW_FIELDS)
    p.require(window["configurationSha256"] == p.sha(config_raw)
        and window["signingKeyId"] == config["bootstrapAuthority"]["keyId"])
    driver._key(config["bootstrapAuthority"]).verify(p.decoded(signed["signatureBase64url"], size=64),
        driver.WINDOW_DOMAIN + p.canonical(window))
    window_at(window, boot=boot, now=now)
    p.require(p.ns(window["startupDeadlineBoottimeNs"]) < p.ns(window["lifetimeDeadlineBoottimeNs"])
        - p.integer(lifecycle["cleanupReserveNanos"], minimum=1_000_000, maximum=5_000_000_000))
    p.fields(observed, ("apiVersion", "configurationSha256", "windowSha256", "invocationId", "processId",
        "uid", "gid", "cgroupOriginalSha256", "root", "seccompFilterCount", "descriptors", "driver"))
    p.require(observed["apiVersion"] == "serverware.nativeShadowDriverObservation/v1"
        and observed["configurationSha256"] == p.sha(config_raw) and observed["windowSha256"] == p.sha(window_raw)
        and observed["invocationId"] == window["invocationId"])
    _same([observed["uid"], observed["gid"]], [cold["uid"], cold["gid"]])
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
    return window


def _bridge_inventory(runtime_raw, cold):
    p.require(bridge_runtime.runtime_version(runtime_raw) in (9, 10, 11, 12))
    runtime, other, native = outgoing._selection(runtime_raw, bridge_runtime.launch_for_runtime(runtime_raw), cold["uid"])
    p.require(runtime["listenerSocketPath"] == "/run/serverware-native-pilot-bridge/listener.sock"
        and len(other) == 9 and len(native) == 10)
    inventory = {"production-listener": stat.S_IFSOCK, "production-journal": stat.S_IFDIR,
        "generation-origin": stat.S_IFSOCK}
    for ordinal, (name, _) in enumerate(other):
        inventory[name] = stat.S_IFSOCK
        inventory[outgoing._DIRECTORY_PREFIX + str(ordinal)] = stat.S_IFDIR
    selected = [(entry, outgoing._PROOFS[entry["endpointKind"]]) for entry in runtime["proofEndpoints"]]
    selected += [(entry, outgoing._NATIVE_SIGNERS[entry["signerRole"]])
        for entry in runtime["parentSignerEndpoints"] if entry["signerRole"] in outgoing._NATIVE_SIGNERS]
    p.require(len(selected) == 10 and {entry["activationFdName"] for entry, _ in selected} == native)
    for entry, (_, directory) in selected:
        p.require(entry["activationFdName"] not in inventory and directory not in inventory)
        inventory[entry["activationFdName"]] = stat.S_IFSOCK
        inventory[directory] = stat.S_IFDIR
    p.require(len(inventory) == 41)
    return tuple(sorted(inventory.items())), runtime


def _activation(records, expected):
    p.require(type(records) is list and len(records) == len(expected))
    identities = set()
    for fd, (entry, (name, kind)) in enumerate(zip(records, expected, strict=True), 6):
        p.fields(entry, ACTIVATION_FIELDS)
        p.require(entry["name"] == name and p.integer(entry["fd"]) == fd)
        p.integer(entry["device"], minimum=0, maximum=p.MAX_U64)
        p.integer(entry["inode"], maximum=p.MAX_U64)
        for field in ("mode", "uid", "gid"):
            p.integer(entry[field], minimum=0, maximum=(1 << 32) - 1)
        identity = entry["device"], entry["inode"]
        p.require(stat.S_IFMT(entry["mode"]) == kind and identity not in identities)
        identities.add(identity)


def _credentials(entries, authority):
    # Preserve the existing C9 public grammar and signer separation. Credential
    # pins are approved references; no secret original enters this public input.
    p.require(type(entries) is list and 1 <= len(entries) <= 64)
    names, total = set(), 0
    for entry in entries:
        p.fields(entry, ("name", "original", "length", "signing"))
        name = entry["name"]
        p.require(type(name) is str and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name) and name not in names)
        names.add(name); delivery._pin(entry["original"])
        total += p.integer(entry["length"], maximum=4 * 1024 * 1024)
        if entry["signing"] is not None:
            assigned = p.fields(entry["signing"], ("publicKeyBase64url", "keyId"))
            public = p.decoded(assigned["publicKeyBase64url"], size=32)
            p.digest(assigned["keyId"])
            p.require(entry["length"] == 32 and public != bytes(32)
                and assigned["publicKeyBase64url"] != authority["publicKeyBase64url"]
                and assigned["keyId"] != authority["keyId"])
            Ed25519PublicKey.from_public_bytes(public)
    p.require(total <= 16 * 1024 * 1024)


def input_document(input_original: bytes) -> dict:
    """Version-selected input bounds only; not original/signature admission."""
    value = p.fields(p.document(input_original, MAX_BRIDGE_INPUT), INPUT_FIELDS)
    role = value["role"]
    p.require(value["apiVersion"] == "serverware.nativePilotDeliverySigningInput/v1"
        and type(role) is str and role in (*ENDPOINTS, "bridge"))
    successor = role == "bridge" and bridge_runtime.version(bridge_runtime.original(value["runtimeOriginal"])[1]) in (10, 11, 12)
    p.require(successor or len(input_original) <= MAX_INPUT)
    return value


def sign(input_original: bytes, signing_key: Ed25519PrivateKey) -> bytes:
    """Sign one fixed native delivery, never a supplied role or FD extension."""
    value = input_document(input_original)
    role = value["role"]
    cold_raw, _ = _original(value["configurationOriginal"], 65536)
    cold = delivery.configuration(cold_raw, p.sha(cold_raw))
    config_raw, _ = _original(value["ownerConfigurationOriginal"], 65536 if role == "bridge" else cohort.MAX_BYTES)
    window_raw, signed_window = _original(value["windowOriginal"], 32768)
    _, observed = _original(value["observationOriginal"], 65536 if role == "bridge" else cohort.MAX_BYTES)
    runtime_raw, _ = (bridge_runtime.original(value["runtimeOriginal"]) if role == "bridge"
        else _original(value["runtimeOriginal"], 65536))
    payload_raw, payload = _original(value["payloadOriginal"], MAX_DELIVERY)
    _, activation = _original(value["activationOriginal"], 32768, array=True)
    p.fields(payload, delivery.FIELDS)
    p.require(isinstance(signing_key, Ed25519PrivateKey))
    public = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(p.encoded(public) == cold["authority"]["publicKeyBase64url"])
    if role == "bridge":
        window = _bridge_owner(cold, cold_raw, config_raw, window_raw, signed_window, observed)
        expected, runtime = _bridge_inventory(runtime_raw, cold)
    else:
        window = _endpoint_owner(role, cold, cold_raw, config_raw, window_raw, signed_window, observed)
        expected, runtime = ENDPOINTS[role], None
    p.require(payload["configurationSha256"] == p.sha(cold_raw)
        and payload["authorityKeyId"] == cold["authority"]["keyId"])
    for name in ("serviceRole", "uid", "gid"):
        _same(payload[name], cold[name])
    for name in WINDOW_FIELDS:
        _same(payload[name], window[name])
    delivery._pin(payload["runtimeConfig"])
    p.require(payload["runtimeConfig"]["sha256"] == p.sha(runtime_raw))
    _same(payload["activation"], activation)
    _activation(activation, expected)
    _credentials(payload["credentials"], cold["authority"])
    if runtime is not None:
        journal = next(entry for entry in activation if entry["name"] == "production-journal")
        identity = p.fields(runtime["journalDirectoryIdentity"],
            ("mountId", "deviceMajor", "deviceMinor", "inode", "uid", "gid", "mode"))
        p.integer(identity["mountId"], maximum=p.MAX_U64)
        _same({name: identity[name] for name in ("inode", "uid", "gid", "mode")},
            {name: journal[name] for name in ("inode", "uid", "gid", "mode")})
        _same([identity["deviceMajor"], identity["deviceMinor"]], [os.major(journal["device"]), os.minor(journal["device"])])
        p.require(stat.S_IMODE(journal["mode"]) == 0o700)
        _same([journal["uid"], journal["gid"]], [cold["uid"], cold["gid"]])
    before = _live(window)
    message = delivery.DOMAIN + payload_raw
    signature = signing_key.sign(message)
    signing_key.public_key().verify(signature, message)
    result = p.canonical({"apiVersion": "serverware.policyCustodyGuestDelivery/v1",
        "payload": payload, "signatureBase64url": p.encoded(signature)})
    p.require(len(result) <= MAX_DELIVERY)
    delivery._delivery_guest(payload, result)
    _live(window, before)
    return result
