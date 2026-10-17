"""Fixed cold-parent signatures over separately approved literal originals.

Pure validation is not approval or proof of a live parked process. The release
operator must independently admit the observation from the retained controller.
Native admission retains the actual PIDFD, image, C9, runtime and closure trust
checks. These helpers neither open payload paths nor create those capabilities.
"""
from __future__ import annotations

import os
import re
import stat

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from catchplate import custody_generation_grants as g
from catchplate import native_pilot_closure_set as sets
from catchplate import native_shadow_guest_delivery as delivery
from catchplate import native_shadow_nitro_originals as originals
from catchplate import native_shadow_nitro_profile as p

INPUT_API = "catchplate.nativePilotGenesisParentAuthorityInput/v1"
CONFIGURATION_API = "catchplate.nativePublicationGenesisParent/v1"
PRECREATION_API = "catchplate.nativePublicationGenesisPrecreation/v1"
OBSERVATION_API = "catchplate.nativePublicationGenesisParentObservation/v1"
RELEASE_API = "catchplate.nativePublicationGenesisParentRelease/v1"
PRECREATION_DOMAIN = "catchplate.nativePublicationGenesisPrecreation.signature/v1"
RELEASE_DOMAIN = "catchplate.nativePublicationGenesisParentRelease.signature/v1"
OPERATIONS = ("precreation", "release")
MAX_INPUT = 8 * 1024 * 1024
MAX_OUTPUT = MAX_WIRE = 32768
MAX_COLD = 65536
MAX_CLOSURE = 1024 * 1024
MAX_EXECUTABLE = 64 * 1024 * 1024
REAP_RESERVE_NS = 250_000_000
INPUT_FIELDS = ("apiVersion", "operation", "configurationOriginal", "deliveryConfigurationOriginal", "payloadOriginal")
RELEASE_INPUT_FIELDS = ("precreationOriginal", "observationOriginal", "launchOriginal", "closureOriginal")
WINDOW_FIELDS = ("configurationSha256", "authorityKeyId", "bootIdBase64url", "timeNamespaceDevice",
    "timeNamespaceInode", "issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId")
RELEASE_FIELDS = ("configurationSha256", "precreationSha256", "observationSha256", "invocationId", "launch", "image", "signingKeyId")
LAUNCH_PINS = ("deliveryConfiguration", "delivery", "trust", "timeBootstrap", "assignment", "closure", "keys",
    "encryptedKeys", "admission", "verifierTransport")
ASSIGNMENT_FIELDS = ("apiVersion", "purpose", "profile", "assignmentId", "assignmentPayloadSha256",
    "assignmentRevision", "manifestSha256", "guest", "trustCheckpointId", "revocationGeneration",
    "revocationRootSha256", "issuedAtUnixNanos", "expiresAtUnixNanos", "signingKeyId", "signingKeySpkiSha256",
    "guestRole", "setRootSha256", "seccompSetRootSha256", "leafSha256")


def signature_preimage(domain, payload):
    p.require(domain in (PRECREATION_DOMAIN, RELEASE_DOMAIN))
    # Exact policy_shadow::signature_preimage, preserving native u64 integers.
    return (b"catchplate.signedEnvelope/v1\0" + domain.encode("ascii")
        + b"\0catchplate.canonicalJson/ascii-integer-v1\0" + g.canonical(payload))


def _original(text, maximum):
    p.require(type(text) is str and text.isascii())
    raw = text.encode("ascii")
    return raw, g.document(raw, maximum)


def _uint(value, *, minimum=0, maximum=p.MAX_U64):
    return p.integer(value, minimum=minimum, maximum=maximum)


def _authority(value):
    p.fields(value, ("publicKeyBase64url", "keyId"))
    raw = p.decoded(value["publicKeyBase64url"], size=32)
    p.require(raw != bytes(32) and value["keyId"] == p.sha(raw))
    return Ed25519PublicKey.from_public_bytes(raw)


def _invocation(value):
    p.require(type(value) is str and re.fullmatch(r"[0-9a-f]{32}", value) and value != "0" * 32)


def validate_configuration(configuration_raw, delivery_configuration_raw):
    config = p.fields(g.document(configuration_raw, MAX_WIRE), ("apiVersion", "precreationAuthority",
        "releaseAuthority", "executableSha256", "deliveryConfiguration"))
    p.require(config["apiVersion"] == CONFIGURATION_API)
    _authority(config["precreationAuthority"]); _authority(config["releaseAuthority"])
    p.require(config["precreationAuthority"]["publicKeyBase64url"] != config["releaseAuthority"]["publicKeyBase64url"]
        and p.digest(config["executableSha256"]) != p.sha(b""))
    delivery._pin(config["deliveryConfiguration"])
    cold = delivery.configuration(delivery_configuration_raw, config["deliveryConfiguration"]["sha256"])
    return config, cold


def _window(payload, configuration_raw, config, *, boot, now_boottime_ns):
    p.fields(payload, WINDOW_FIELDS)
    p.require(payload["configurationSha256"] == p.sha(configuration_raw)
        and payload["authorityKeyId"] == config["precreationAuthority"]["keyId"])
    p.require(p.decoded(payload["bootIdBase64url"], size=16) != bytes(16))
    for name in ("timeNamespaceDevice", "timeNamespaceInode"):
        _uint(payload[name], minimum=0 if name == "timeNamespaceDevice" else 1)
    p.require((payload["bootIdBase64url"], payload["timeNamespaceDevice"], payload["timeNamespaceInode"]) == boot)
    _invocation(payload["invocationId"])
    issued, startup, lifetime = (p.ns(payload[name]) for name in
        ("issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"))
    now = _uint(now_boottime_ns, minimum=1)
    p.require(issued <= now < startup <= lifetime and startup - issued <= 30_000_000_000
        and now + REAP_RESERVE_NS < lifetime)
    return min(startup, lifetime - REAP_RESERVE_NS)


def validate_precreation(precreation_raw, *, configuration_raw, delivery_configuration_raw, boot, now_boottime_ns):
    config, cold = validate_configuration(configuration_raw, delivery_configuration_raw)
    signed = p.fields(g.document(precreation_raw, MAX_WIRE), ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed["apiVersion"] == PRECREATION_API)
    deadline = _window(signed["payload"], configuration_raw, config, boot=boot, now_boottime_ns=now_boottime_ns)
    _authority(config["precreationAuthority"]).verify(p.decoded(signed["signatureBase64url"], size=64),
        signature_preimage(PRECREATION_DOMAIN, signed["payload"]))
    return {"configuration": config, "cold": cold, "window": signed["payload"], "deadline": deadline}


def validate_observation(observation_raw, *, configuration_raw, precreation_raw, context):
    """Check literal associations only; the actual controller supplies provenance."""
    p.fields(context, ("configuration", "cold", "window", "deadline"))
    value = p.fields(g.document(observation_raw, MAX_WIRE), ("apiVersion", "configurationSha256", "precreationSha256",
        "invocationId", "processId", "startTimeTicks", "pidfdDevice", "pidfdInode", "executable", "resultActivation"))
    p.require(value["apiVersion"] == OBSERVATION_API and value["configurationSha256"] == p.sha(configuration_raw)
        and value["precreationSha256"] == p.sha(precreation_raw)
        and value["invocationId"] == context["window"]["invocationId"])
    _uint(value["processId"], minimum=2, maximum=(1 << 31) - 1)
    _uint(value["startTimeTicks"], minimum=1)
    _uint(value["pidfdDevice"]); _uint(value["pidfdInode"], minimum=1)
    executable = p.fields(value["executable"], ("device", "inode", "length", "sha256"))
    _uint(executable["device"], minimum=1); _uint(executable["inode"], minimum=1)
    _uint(executable["length"], minimum=1, maximum=MAX_EXECUTABLE)
    p.require(executable["sha256"] == context["configuration"]["executableSha256"])
    rows = value["resultActivation"]
    p.require(type(rows) is list and len(rows) == 2)
    identities = set()
    for fd, name, row in zip((14, 15), ("publication-genesis-result", "publication-genesis-result-parent"), rows, strict=True):
        p.fields(row, ("name", "fd", "device", "inode", "mode", "uid", "gid"))
        p.require(row["name"] == name and type(row["fd"]) is int and row["fd"] == fd)
        _uint(row["device"]); _uint(row["inode"], minimum=1)
        _uint(row["mode"], maximum=(1 << 32) - 1)
        p.require(stat.S_IFMT(row["mode"]) == stat.S_IFSOCK)
        for field in ("uid", "gid"):
            _uint(row[field], maximum=0)
        identities.add((row["device"], row["inode"]))
    p.require(len(identities) == 2)
    return value


def _launch_image(launch_raw, closure_raw, context):
    """Closed public image joins, not a substitute for native closure admission."""
    launch = p.fields(g.document(launch_raw, MAX_WIRE), ("apiVersion", "keyAdmission"))
    p.require(launch["apiVersion"] == "catchplate.nativeShadowPublicationGenesisCoordinatorGuestLaunch/v2")
    inner = p.fields(launch["keyAdmission"], ("apiVersion",) + LAUNCH_PINS)
    p.require(inner["apiVersion"] == "catchplate.nativeShadowGuestLaunch/v1")
    for name in LAUNCH_PINS:
        delivery._pin(inner[name])
    p.require(inner["deliveryConfiguration"] == context["configuration"]["deliveryConfiguration"]
        and inner["closure"]["sha256"] == p.sha(closure_raw)
        and inner["verifierTransport"]["path"] ==
            "/etc/catchplate/native-pilot-inputs/native-publicationGenesisCoordinator-verifier.json")
    closure = p.fields(g.document(closure_raw, MAX_CLOSURE), ("apiVersion", "manifest", "closureSet", "authorization"))
    p.require(closure["apiVersion"] == "catchplate.nativeCustodyClosure/v6")
    selected = sets.validate(g.canonical(closure["closureSet"]), api_version=sets.GENESIS_BOOTSTRAP_API)
    role = "publicationGenesisCoordinator"
    manifest = selected["members"][-1]["manifest"]
    p.require(closure["manifest"] == manifest
        and manifest["workerExecutableSha256"] == context["configuration"]["executableSha256"])
    authorization = p.fields(closure["authorization"], ("payload", "signature"))
    p.decoded(authorization["signature"], size=64)
    assigned = p.fields(authorization["payload"], ASSIGNMENT_FIELDS)
    p.require(assigned["apiVersion"] == "catchplate.nativeCustodyClosureAssignment/v6"
        and assigned["purpose"] == "shadow-custody-closure-set-member"
        and assigned["profile"] == "native-publication-genesis-closure-set-v2" and assigned["guestRole"] == role)
    leaf = sets.leaf_binding(selected, role, api_version=sets.GENESIS_BOOTSTRAP_API)
    for name in ("setRootSha256", "seccompSetRootSha256", "leafSha256", "manifestSha256"):
        p.require(assigned[name] == leaf[name])
    for name in ("assignmentId", "assignmentPayloadSha256", "trustCheckpointId", "revocationRootSha256",
            "signingKeyId", "signingKeySpkiSha256"):
        p.digest(assigned[name])
    _uint(assigned["assignmentRevision"], minimum=1); _uint(assigned["revocationGeneration"])
    p.integer(assigned["issuedAtUnixNanos"]); p.integer(assigned["expiresAtUnixNanos"])
    p.require(assigned["issuedAtUnixNanos"] < assigned["expiresAtUnixNanos"])
    guest = p.fields(assigned["guest"], p.GUEST_FIELDS)
    for name in ("configurationSha256", "deliverySha256", "runtimeConfigurationSha256"):
        p.digest(guest[name])
    for name in ("uid", "gid"):
        _uint(guest[name], minimum=1, maximum=(1 << 32) - 2)
    for name in ("timeNamespaceDevice", "timeNamespaceInode"):
        _uint(guest[name], minimum=0 if name == "timeNamespaceDevice" else 1)
    p.require(guest["configurationSha256"] == inner["deliveryConfiguration"]["sha256"]
        and guest["deliverySha256"] == inner["delivery"]["sha256"]
        and guest["runtimeConfigurationSha256"] != manifest["runtimeConfigurationSha256"]
        and all(guest[name] == context["cold"][name] for name in ("serviceRole", "uid", "gid"))
        and all(guest[name] == context["window"][name] for name in WINDOW_FIELDS[2:]))
    return manifest["imageSha256"]


def _release(payload, *, configuration_raw, delivery_configuration_raw, precreation_raw, observation_raw,
             launch_raw, closure_raw, boot, now_boottime_ns):
    context = validate_precreation(precreation_raw, configuration_raw=configuration_raw,
        delivery_configuration_raw=delivery_configuration_raw, boot=boot, now_boottime_ns=now_boottime_ns)
    validate_observation(observation_raw, configuration_raw=configuration_raw, precreation_raw=precreation_raw, context=context)
    image_sha = _launch_image(launch_raw, closure_raw, context)
    p.fields(payload, RELEASE_FIELDS)
    delivery._pin(payload["launch"]); delivery._pin(payload["image"])
    p.require(payload["configurationSha256"] == p.sha(configuration_raw)
        and payload["precreationSha256"] == p.sha(precreation_raw)
        and payload["observationSha256"] == p.sha(observation_raw)
        and payload["invocationId"] == context["window"]["invocationId"]
        and payload["signingKeyId"] == context["configuration"]["releaseAuthority"]["keyId"]
        and payload["launch"]["sha256"] == p.sha(launch_raw) and payload["image"]["sha256"] == image_sha)
    return context


def validate_release(release_raw, *, configuration_raw, delivery_configuration_raw, precreation_raw,
                     observation_raw, launch_raw, closure_raw, boot, now_boottime_ns):
    signed = p.fields(g.document(release_raw, MAX_WIRE), ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed["apiVersion"] == RELEASE_API)
    context = _release(signed["payload"], configuration_raw=configuration_raw, delivery_configuration_raw=delivery_configuration_raw,
        precreation_raw=precreation_raw, observation_raw=observation_raw, launch_raw=launch_raw, closure_raw=closure_raw,
        boot=boot, now_boottime_ns=now_boottime_ns)
    _authority(context["configuration"]["releaseAuthority"]).verify(p.decoded(signed["signatureBase64url"], size=64),
        signature_preimage(RELEASE_DOMAIN, signed["payload"]))
    return context


def input_document(raw):
    # This outer envelope contains ONLY strings, so p's integer ceiling cannot
    # narrow embedded native u64 originals. Each nested document has its own cap.
    value = p.document(raw, MAX_INPUT)
    p.require(value.get("apiVersion") == INPUT_API and value.get("operation") in OPERATIONS)
    p.fields(value, INPUT_FIELDS + (RELEASE_INPUT_FIELDS if value["operation"] == "release" else ()))
    for name in value:
        p.require(type(value[name]) is str and value[name].isascii())
    return value


def prepare_input(raw, *, boot, now_boottime_ns):
    value = input_document(raw)
    config_raw, _ = _original(value["configurationOriginal"], MAX_WIRE)
    cold_raw, _ = _original(value["deliveryConfigurationOriginal"], MAX_COLD)
    _, payload = _original(value["payloadOriginal"], MAX_WIRE)
    config, cold = validate_configuration(config_raw, cold_raw)
    if value["operation"] == "precreation":
        deadline = _window(payload, config_raw, config, boot=boot, now_boottime_ns=now_boottime_ns)
        context = {"configuration": config, "cold": cold, "window": payload, "deadline": deadline}
        authority, domain, api = config["precreationAuthority"], PRECREATION_DOMAIN, PRECREATION_API
    else:
        rows = {name: _original(value[name], MAX_CLOSURE if name == "closureOriginal" else MAX_WIRE)[0]
            for name in RELEASE_INPUT_FIELDS}
        context = _release(payload, configuration_raw=config_raw, delivery_configuration_raw=cold_raw,
            precreation_raw=rows["precreationOriginal"], observation_raw=rows["observationOriginal"],
            launch_raw=rows["launchOriginal"], closure_raw=rows["closureOriginal"], boot=boot, now_boottime_ns=now_boottime_ns)
        authority, domain, api = config["releaseAuthority"], RELEASE_DOMAIN, RELEASE_API
    return {"payload": payload, "authority": authority, "window": context["window"],
        "deadline": context["deadline"], "domain": domain, "apiVersion": api}


def checked_result(raw, result, *, boot, now_boottime_ns):
    prepared = prepare_input(raw, boot=boot, now_boottime_ns=now_boottime_ns)
    p.fields(result, ("original", "sha256"))
    output, signed = _original(result["original"], MAX_OUTPUT)
    p.fields(signed, ("apiVersion", "payload", "signatureBase64url"))
    p.require(result["sha256"] == p.sha(output) and signed["apiVersion"] == prepared["apiVersion"]
        and g.canonical(signed["payload"]) == g.canonical(prepared["payload"]))
    _authority(prepared["authority"]).verify(p.decoded(signed["signatureBase64url"], size=64),
        signature_preimage(prepared["domain"], signed["payload"]))
    return output


def sign(*, input_original, signing_key):
    """One supplied key, one signature, real original-domain clock brackets."""
    p.require(type(input_original) is bytes and isinstance(signing_key, Ed25519PrivateKey))
    pid, start, boot = os.getpid(), originals._start(), originals._boot()
    now = originals._clock()
    prepared = prepare_input(input_original, boot=boot, now_boottime_ns=now)
    public = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(public == p.decoded(prepared["authority"]["publicKeyBase64url"], size=32))

    def check(previous):
        p.require(os.getpid() == pid and originals._start() == start and originals._boot() == boot)
        current = originals._clock()
        p.require(previous <= current < prepared["deadline"])
        return current

    before = check(now)
    message = signature_preimage(prepared["domain"], prepared["payload"])
    signature = signing_key.sign(message)
    _authority(prepared["authority"]).verify(signature, message)
    output = g.canonical({"apiVersion": prepared["apiVersion"], "payload": prepared["payload"],
        "signatureBase64url": p.encoded(signature)})
    p.require(len(output) <= MAX_OUTPUT)
    after = check(before)
    checked_result(input_original, {"original": output.decode("ascii"), "sha256": p.sha(output)}, boot=boot, now_boottime_ns=after)
    check(after)
    return output, prepared["deadline"]
