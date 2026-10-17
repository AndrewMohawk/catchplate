"""Cold-only C9 signatures from complete independently approved originals.

The endpoint owner supplies actual observations and retained resources. This
public-data adapter checks their source associations, not their provenance or
liveness. The coordinator uses its separately retained parent observation.
Neither path creates credentials, grants service authority, opens input pins,
or substitutes for native image, descriptor and key admission.
"""
from __future__ import annotations

import copy
import json
import os
import stat
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from catchplate import custody_generation_grants as g
from catchplate import native_pilot_delivery_authority as wire
from catchplate import native_pilot_genesis_endpoint_profile as endpoints
from catchplate import native_pilot_genesis_parent_authority as parent
from catchplate import native_shadow_nitro_originals as originals

p = g.p
API = "catchplate.nativePilotGenesisDeliveryAuthorityInput/v1"
ROLES = (*endpoints.ROLES, "publicationGenesisCoordinator")
MAX_INPUT = 16 * 1024 * 1024
MAX_OUTPUT = 65536
PARENTS = ("parentConfigurationOriginal", "parentDeliveryConfigurationOriginal",
    "parentPrecreationOriginal", "parentObservationOriginal")
FIELDS = ("apiVersion", "role", "parentOriginals", "configurationOriginal", "runtimeOriginal",
    "payloadOriginal", "activationOriginal", "image")
ENDPOINT_FIELDS = ("ownerConfigurationOriginal", "preparationOriginal", "resourcesOriginal")


def original(value, maximum):
    p.require(type(value) is str and value.isascii() and 0 < len(value) <= maximum)
    return value.encode("ascii")


def same(left, right):
    p.require(g.canonical(left) == g.canonical(right))


def input_document(raw):
    # Outer numbers are absent; embedded native originals use the full-u64 codec.
    value = p.document(raw, MAX_INPUT)
    p.require(value.get("apiVersion") == API and value.get("role") in ROLES)
    p.fields(value, FIELDS + (ENDPOINT_FIELDS if value["role"] in endpoints.ROLES else ()))
    p.fields(value["parentOriginals"], PARENTS)
    g.c9._pin(value["image"])
    return value


def _activation(raw):
    p.require(len(raw) <= 32768)
    value = json.loads(raw.decode("ascii"), object_pairs_hook=p._pairs,
        parse_float=p._reject, parse_constant=p._reject)
    p.require(type(value) is list and g.canonical(value) == raw)
    return value


def _parent(value, *, boot, now_boottime_ns):
    sources = {name: original(value["parentOriginals"][name], 65536) for name in PARENTS}
    args = dict(configuration_raw=sources[PARENTS[0]], delivery_configuration_raw=sources[PARENTS[1]])
    inherited = parent.validate_precreation(sources[PARENTS[2]], **args,
        boot=boot, now_boottime_ns=now_boottime_ns)
    observed = parent.validate_observation(sources[PARENTS[3]], configuration_raw=args["configuration_raw"],
        precreation_raw=sources[PARENTS[2]], context=inherited)
    return sources, inherited, observed


def prepare_input(role, raw, *, boot, now_boottime_ns):
    value = input_document(raw)
    p.require(role in ROLES and value["role"] == role)
    sources, inherited, coordinator = _parent(value, boot=boot, now_boottime_ns=now_boottime_ns)
    cold_raw = original(value["configurationOriginal"], MAX_OUTPUT)
    cold = g.c9.configuration(cold_raw, p.sha(cold_raw))
    runtime_raw = original(value["runtimeOriginal"], g.MAX_BYTES)
    payload_raw = original(value["payloadOriginal"], MAX_OUTPUT)
    payload = p.fields(g.document(payload_raw, MAX_OUTPUT), g.c9.FIELDS)
    activation = _activation(original(value["activationOriginal"], 32768))
    forbidden = {inherited["configuration"][field]["publicKeyBase64url"]
        for field in ("precreationAuthority", "releaseAuthority")}
    deadline, extra = inherited["deadline"], {}
    if role in endpoints.ROLES:
        owner_raw = original(value["ownerConfigurationOriginal"], endpoints.MAX_WIRE)
        preparation_raw = original(value["preparationOriginal"], 65536)
        resources_raw = original(value["resourcesOriginal"], 65536)
        held = endpoints.context(configuration_raw=owner_raw, preparation_raw=preparation_raw,
            resources_raw=resources_raw, parent_configuration_raw=sources[PARENTS[0]],
            parent_delivery_configuration_raw=sources[PARENTS[1]], parent_precreation_raw=sources[PARENTS[2]],
            parent_observation_raw=sources[PARENTS[3]], boot=boot, now_boottime_ns=now_boottime_ns)
        selected = held["configuration"]["services"][role]
        p.require(selected["deliveryConfiguration"]["sha256"] == p.sha(cold_raw))
        same(selected["image"], value["image"])
        forbidden.add(held["configuration"]["releaseAuthority"]["publicKeyBase64url"])
        forbidden.add(inherited["cold"]["authority"]["publicKeyBase64url"])
        p.require(cold["uid"] != inherited["cold"]["uid"] and cold["gid"] != inherited["cold"]["gid"])
        observed = endpoints.observation(held["preparation"]["observationOriginal"].encode("ascii"))["services"][role]
        same(activation, held["resources"]["services"][role]["activation"])
        for entry in activation:
            expected_ids = (0, 0) if entry["fd"] == 6 else (cold["uid"], cold["gid"])
            p.require((entry["uid"], entry["gid"]) == expected_ids)
        same(g.document(runtime_raw, 65536), {"apiVersion": "catchplate.nativePilotEndpointRuntime/v1", "role": role})
        extra = dict(resources_raw=resources_raw, preparation_raw=preparation_raw,
            owner_configuration_raw=owner_raw, preparation=held["preparation"])
    else:
        # The static image contains BootstrapRuntime/v1, never this late Runtime/v2.
        p.require(cold_raw == sources[PARENTS[1]])
        from catchplate import native_pilot_genesis_coordinator_runtime as runtime
        late = runtime.validate(runtime_raw, window=inherited["window"], coordinator=coordinator,
            cold=cold, boot=boot, now_boottime_ns=now_boottime_ns)
        wire._activation(activation, runtime.ACTIVATION)
        same(activation[-2:], coordinator["resultActivation"])
        deadline = min(deadline, late["deadline"])
        observed = {name: coordinator[name] for name in ("processId", "startTimeTicks", "pidfdDevice",
            "pidfdInode", "executable", "resultActivation")}
    p.require(cold["authority"]["publicKeyBase64url"] not in forbidden)
    p.require(payload["configurationSha256"] == p.sha(cold_raw)
        and payload["authorityKeyId"] == cold["authority"]["keyId"])
    for name in ("serviceRole", "uid", "gid"):
        same(payload[name], cold[name])
    for name in endpoints.WINDOW:
        same(payload[name], inherited["window"][name])
    same(payload["activation"], activation)
    g.c9._pin(payload["runtimeConfig"])
    p.require(payload["runtimeConfig"]["sha256"] == p.sha(runtime_raw))
    wire._credentials(payload["credentials"], cold["authority"])
    paths = [entry["original"]["path"] for entry in payload["credentials"]]
    p.require(len(set(paths)) == len(paths) and payload["runtimeConfig"]["path"] not in paths)
    p.require(len(payload_raw) + 256 <= MAX_OUTPUT and now_boottime_ns < deadline)
    return dict(payload=payload, message=g.c9.DOMAIN + payload_raw, key=parent._authority(cold["authority"]),
        window=inherited["window"], observed=observed, runtime_raw=runtime_raw, cold=cold, deadline=deadline,
        parentOriginals=copy.deepcopy(value["parentOriginals"]), executable_sha256=observed["executable"]["sha256"],
        image_sha256=value["image"]["sha256"], **extra)


def verified_delivery(role, input_raw, signed_raw, *, boot, now_boottime_ns):
    context = prepare_input(role, input_raw, boot=boot, now_boottime_ns=now_boottime_ns)
    signed = p.fields(g.document(signed_raw, MAX_OUTPUT), ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed["apiVersion"] == "catchplate.policyCustodyGuestDelivery/v1")
    same(signed["payload"], context["payload"])
    context["key"].verify(p.decoded(signed["signatureBase64url"], size=64), context["message"])
    payload = context["payload"]
    guest = {name: payload[name] for name in p.GUEST_FIELDS if name not in
        ("deliverySha256", "runtimeConfigurationSha256")}
    guest.update(deliverySha256=p.sha(signed_raw), runtimeConfigurationSha256=payload["runtimeConfig"]["sha256"])
    # All scalar checks come from the signed parent window and cold config.
    # Do not narrow valid native u64 namespaces through the old p.guest codec.
    p.fields(guest, p.GUEST_FIELDS)
    return {**context, "guest": guest}


def checked_result(role, input_raw, result, *, boot, now_boottime_ns):
    p.fields(result, ("original", "sha256"))
    raw = original(result["original"], MAX_OUTPUT)
    p.require(p.sha(raw) == result["sha256"])
    verified_delivery(role, input_raw, raw, boot=boot, now_boottime_ns=now_boottime_ns)
    return raw


def sign(role, *, input_original, signing_key):
    pid, boot = os.getpid(), originals._boot()
    before = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    context = prepare_input(role, input_original, boot=boot, now_boottime_ns=before)
    p.require(isinstance(signing_key, Ed25519PrivateKey))
    public = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(p.encoded(public) == context["cold"]["authority"]["publicKeyBase64url"])
    raw = g.canonical({"apiVersion": "catchplate.policyCustodyGuestDelivery/v1", "payload": context["payload"],
        "signatureBase64url": p.encoded(signing_key.sign(context["message"]))})
    context["key"].verify(p.decoded(g.document(raw, MAX_OUTPUT)["signatureBase64url"], size=64), context["message"])
    after = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    p.require(os.getpid() == pid and originals._boot() == boot and before <= after < context["deadline"])
    return raw, context["deadline"]
