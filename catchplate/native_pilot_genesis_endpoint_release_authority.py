"""One fixed cold endpoint-parent release over independently approved originals.

The two closure signatures, assignment, C9 sources and original intervals are
authenticated here. Launch pins for encrypted keys, native grants and verifier
transport are not authentication of those files: the actual native release
must admit them and retain the real PIDFDs, descriptors and measured images.
This public-data producer opens no paths and creates no process or key owner.
"""
from __future__ import annotations

import os
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from catchplate import custody_generation_grants as g
from catchplate import native_pilot_genesis_closure_authority as closure
from catchplate import native_pilot_genesis_delivery_authority as delivery
from catchplate import native_pilot_genesis_endpoint_profile as endpoints
from catchplate import native_pilot_genesis_key_authority as signer
from catchplate import native_pilot_genesis_key_profile as keys
from catchplate import native_pilot_genesis_parent_authority as parent
from catchplate import native_shadow_nitro_originals as originals

p = g.p
API = "catchplate.nativePilotGenesisEndpointReleaseAuthorityInput/v1"
RELEASE_API, DOMAIN = endpoints.RELEASE_API, endpoints.RELEASE_DOMAIN
ROLES = endpoints.ROLES
MAX_INPUT = 16 * 1024 * 1024
MAX_OUTPUT = endpoints.MAX_WIRE
FIELDS = ("apiVersion", "parentOriginals", "configurationOriginal", "preparationOriginal", "resourcesOriginal", "services")
SERVICE_FIELDS = ("launch", "launchOriginal", "closureInputOriginal", "closureOriginal")
PAYLOAD_FIELDS = ("configurationSha256", "parentConfigurationSha256", "parentPrecreationSha256",
    "observationSha256", "invocationId", "signingKeyId", "services")
LAUNCHES = {
    ROLES[0]: ("catchplate.nativeShadowPublicationGenesisRetrievalGuestLaunch/v1", "retrieval"),
    ROLES[1]: ("catchplate.nativeShadowPublicationGenesisGuestLaunch/v1", "publication"),
}


def signature_preimage(payload):
    return (b"catchplate.signedEnvelope/v1\0" + DOMAIN.encode("ascii")
        + b"\0catchplate.canonicalJson/ascii-integer-v1\0" + g.canonical(payload))


def input_document(raw):
    # Only literal-original strings and pin fields live in this outer envelope.
    value = p.fields(p.document(raw, MAX_INPUT), FIELDS)
    p.require(value["apiVersion"] == API)
    p.fields(value["parentOriginals"], delivery.PARENTS)
    for row in p.fields(value["services"], ROLES).values():
        p.fields(row, SERVICE_FIELDS)
        g.c9._pin(row["launch"])
    return value


def _service(role, row, value, source_raws, *, boot, now_boottime_ns, now_unix_ns):
    input_raw = keys.original(row["closureInputOriginal"], closure.MAX_INPUT)
    closure_raw = keys.original(row["closureOriginal"], closure.MAX_OUTPUT)
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    closure.checked_result(role, input_raw, {"original": row["closureOriginal"], "sha256": p.sha(closure_raw)}, **clocks)
    checked = closure.prepare_input(role, input_raw, **clocks)
    source = checked["source"]
    observed = source["delivery"]
    keys.same(observed["parentOriginals"], value["parentOriginals"])
    for field, name in (("owner_configuration_raw", "configurationOriginal"),
            ("preparation_raw", "preparationOriginal"), ("resources_raw", "resourcesOriginal")):
        p.require(observed[field] == source_raws[name])

    launch_raw = keys.original(row["launchOriginal"], MAX_OUTPUT)
    api, native_field = LAUNCHES[role]
    launch = p.fields(g.document(launch_raw, MAX_OUTPUT), ("apiVersion", "keyAdmission", native_field))
    p.require(launch["apiVersion"] == api and row["launch"]["sha256"] == p.sha(launch_raw))
    g.c9._pin(launch[native_field])
    inner = p.fields(launch["keyAdmission"], ("apiVersion", *parent.LAUNCH_PINS))
    p.require(inner["apiVersion"] == "catchplate.nativeShadowGuestLaunch/v1")
    for field in parent.LAUNCH_PINS:
        g.c9._pin(inner[field])
    configured = endpoints.configuration(source_raws["configurationOriginal"])["services"][role]
    keys.same(inner["deliveryConfiguration"], configured["deliveryConfiguration"])
    p.require(inner["delivery"]["sha256"] == p.sha(source["deliveryOriginal"])
        and inner["closure"]["sha256"] == p.sha(closure_raw)
        and checked["manifest"]["imageSha256"] == configured["image"]["sha256"]
        and checked["manifest"]["workerExecutableSha256"] == configured["executableSha256"]
        and inner["verifierTransport"]["path"] == "/etc/catchplate/native-pilot-inputs/native-" + role + "-verifier.json")
    approved = keys.binding.input_document(source["coldBindingInputOriginal"])
    p.require(inner["trust"]["sha256"] == p.sha(approved["trustOriginal"].encode("ascii"))
        and inner["assignment"]["sha256"] == p.sha(approved["assignmentOriginal"].encode("ascii")))
    return checked, {"launch": row["launch"], "image": configured["image"]}


def prepare_input(raw, *, boot, now_boottime_ns, now_unix_ns):
    value = input_document(raw)
    source_raws = {name: keys.original(value[name], endpoints.MAX_WIRE if name == "configurationOriginal" else 65536)
        for name in ("configurationOriginal", "preparationOriginal", "resourcesOriginal")}
    parents = {name: keys.original(value["parentOriginals"][name], 65536) for name in delivery.PARENTS}
    held = endpoints.context(configuration_raw=source_raws["configurationOriginal"],
        preparation_raw=source_raws["preparationOriginal"], resources_raw=source_raws["resourcesOriginal"],
        parent_configuration_raw=parents[delivery.PARENTS[0]], parent_delivery_configuration_raw=parents[delivery.PARENTS[1]],
        parent_precreation_raw=parents[delivery.PARENTS[2]], parent_observation_raw=parents[delivery.PARENTS[3]],
        boot=boot, now_boottime_ns=now_boottime_ns)
    contexts, services = [], {}
    for role in ROLES:
        checked, pins = _service(role, value["services"][role], value, source_raws,
            boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
        contexts.append(checked); services[role] = pins
    p.require(contexts[0]["source"]["coldBindingInputOriginal"] == contexts[1]["source"]["coldBindingInputOriginal"])
    authority = held["configuration"]["releaseAuthority"]
    payload = {"configurationSha256": p.sha(source_raws["configurationOriginal"]),
        "parentConfigurationSha256": p.sha(parents[delivery.PARENTS[0]]),
        "parentPrecreationSha256": p.sha(parents[delivery.PARENTS[2]]),
        "observationSha256": p.sha(held["preparation"]["observationOriginal"].encode("ascii")),
        "invocationId": held["window"]["invocationId"], "signingKeyId": authority["keyId"], "services": services}
    p.fields(payload, PAYLOAD_FIELDS)
    deadline = min(held["deadline"], *(context["deadline"] for context in contexts))
    epoch_limit = min(context["epochLimit"] for context in contexts)
    p.require(now_boottime_ns < deadline and now_unix_ns < epoch_limit and len(g.canonical(payload)) + 256 <= MAX_OUTPUT)
    return {"payload": payload, "authority": authority, "window": held["window"], "deadline": deadline,
        "epochLimit": epoch_limit, "apiVersion": RELEASE_API, "domain": DOMAIN}


def checked_result(input_raw, result, *, boot, now_boottime_ns, now_unix_ns):
    checked = prepare_input(input_raw, boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    p.fields(result, ("original", "sha256"))
    raw = keys.original(result["original"], MAX_OUTPUT)
    signed = p.fields(g.document(raw, MAX_OUTPUT), ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed["apiVersion"] == RELEASE_API and result["sha256"] == p.sha(raw))
    keys.same(signed["payload"], checked["payload"])
    parent._authority(checked["authority"]).verify(p.decoded(signed["signatureBase64url"], size=64),
        signature_preimage(signed["payload"]))
    return raw


def sign(*, input_original, signing_key):
    p.require(isinstance(signing_key, Ed25519PrivateKey))
    owner = os.getpid(), originals._start(), originals._boot()
    now, wall = originals._clock(), time.time_ns()
    checked = prepare_input(input_original, boot=owner[2], now_boottime_ns=now, now_unix_ns=wall)
    public = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(p.encoded(public) == checked["authority"]["publicKeyBase64url"])
    before, epoch = signer.current(checked, owner, now, wall)
    message = signature_preimage(checked["payload"])
    signature = signing_key.sign(message)
    parent._authority(checked["authority"]).verify(signature, message)
    raw = g.canonical({"apiVersion": RELEASE_API, "payload": checked["payload"], "signatureBase64url": p.encoded(signature)})
    p.require(len(raw) <= MAX_OUTPUT)
    after, later = signer.current(checked, owner, before, epoch)
    checked_result(input_original, {"original": raw.decode("ascii"), "sha256": p.sha(raw)},
        boot=owner[2], now_boottime_ns=after, now_unix_ns=later)
    signer.current(checked, owner, after, later)
    return raw, checked["deadline"]
