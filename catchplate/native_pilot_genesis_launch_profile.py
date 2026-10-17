"""Unsigned cold launch bundles from complete authenticated public originals.

No file is installed, no ciphertext or authority is manufactured, and no guest,
KMS or verifier admission is claimed. Independently approved destination pins
must match the exact included bytes; native receivers still own actual files,
images, descriptors, trusted time and key import. Only the explicit cold set/v2
and late coordinator Runtime/v2 paths are accepted, never hot launch fallbacks.
"""
from __future__ import annotations

import copy
import os
import time

from catchplate import custody_generation_grants as g
from catchplate import native_pilot_genesis_closure_authority as closure
from catchplate import native_pilot_genesis_key_profile as keys
from catchplate import native_pilot_genesis_native_service_authority as services
from catchplate import native_pilot_publication_cold_binding as binding
from catchplate import native_shadow_nitro_originals as originals

p = g.p
API = "catchplate.nativePilotGenesisLaunchInput/v1"
RESULT_API = "catchplate.nativePilotGenesisLaunchBundle/v1"
ROLES = keys.ROLES
MAX_INPUT, MAX_OUTPUT = 32 * 1024 * 1024, 16 * 1024 * 1024
PAIR_FIELDS = services.PAIR_FIELDS
CLOCK_FIELDS = ("parentPort", "maximumBracketNanos", "timestampErrorNanos", "maximumClockRateErrorPpm")
AUTHORIZATIONS = ("closure", "encrypted-delivery", "verifier-transport")
COMPONENTS = ("deliveryConfiguration", "delivery", "runtime", "trust", "timeBootstrap", "assignment",
    "closure", "keys", "encryptedKeys", "admission", "verifierTransport", "encryptedInventory")
INNER = ("deliveryConfiguration", "delivery", "trust", "timeBootstrap", "assignment", "closure",
    "keys", "encryptedKeys", "admission", "verifierTransport")
SELECTORS = {
    "publicationGenesisRetrieval": ("catchplate.nativeShadowPublicationGenesisRetrievalGuestLaunch/v1", "retrieval"),
    "publicationGenesis": ("catchplate.nativeShadowPublicationGenesisGuestLaunch/v1", "publication"),
    "publicationGenesisCoordinator": ("catchplate.nativeShadowPublicationGenesisCoordinatorGuestLaunch/v2", None),
}
FIELDS = ("apiVersion", "role", "pairContext", "authorizations", "timeBootstrap", "pins", "serviceContexts")


def _original(value, maximum):
    return keys.original(value, maximum)


def _result(raw):
    return {"original": raw.decode("ascii"), "sha256": p.sha(raw)}


def _clock_settings(value):
    p.fields(value, CLOCK_FIELDS)
    p.integer(value["parentPort"], minimum=1024, maximum=(1 << 32) - 2)
    p.require(p.ns(value["maximumBracketNanos"]) <= 1_000_000_000)
    p.integer(value["timestampErrorNanos"], minimum=0, maximum=1_000_000_000)
    p.integer(value["maximumClockRateErrorPpm"], minimum=0, maximum=10000)


def input_document(raw):
    # Native u64 values remain inside literal originals and use their own codec.
    value = p.fields(p.document(raw, MAX_INPUT), FIELDS)
    p.require(value["apiVersion"] == API and value["role"] in ROLES)
    p.fields(value["pairContext"], PAIR_FIELDS)
    for row in p.fields(value["authorizations"], AUTHORIZATIONS).values():
        p.fields(row, ("inputOriginal", "authorizationOriginal"))
    operation = SELECTORS[value["role"]][1]
    for row in p.fields(value["serviceContexts"], (operation,) if operation else services.OPERATIONS).values():
        p.fields(row, ("inputOriginal", "grantOriginal"))
    _clock_settings(value["timeBootstrap"])
    pins = p.fields(value["pins"], (*COMPONENTS, "launch") + (("serviceGrant",) if operation else ()))
    for pin in pins.values(): g.c9._pin(pin)
    paths = [pin["path"] for pin in pins.values()]
    p.require(len(set(paths)) == len(paths))
    return value


def _pair(value, role, clocks):
    row = value["pairContext"]
    raw = {name: _original(row[name], keys.MAX_INPUT if "Input" in name else keys.MAX_OUTPUT) for name in PAIR_FIELDS}
    pair = keys.admitted_pair(role, *(raw[name] for name in PAIR_FIELDS), **clocks)
    first = keys.input_document(raw["roleKeyInputOriginal"])
    return pair, first, raw


def _authorizations(value, role, first, clocks):
    from catchplate import native_pilot_genesis_encrypted_authority as encrypted
    from catchplate import native_pilot_genesis_verifier_authority as verifier
    modules = dict(zip(AUTHORIZATIONS, (closure, encrypted, verifier), strict=True))
    contexts, output, inputs = {}, {}, {}
    for name, module in modules.items():
        row = value["authorizations"][name]
        input_raw = _original(row["inputOriginal"], module.MAX_INPUT)
        raw = _original(row["authorizationOriginal"], module.MAX_OUTPUT)
        supplied = p.document(input_raw, module.MAX_INPUT)
        if name == "closure":
            for field in keys.SOURCE_FIELDS: p.require(supplied[field] == first[field])
        else:
            for field in PAIR_FIELDS: p.require(supplied[field] == value["pairContext"][field])
        contexts[name] = module.prepare_input(role, input_raw, **clocks)
        output[name] = module.checked_result(role, input_raw, _result(raw), **clocks)
        inputs[name] = supplied
    p.require(value["pins"]["verifierTransport"]["path"] == verifier.PATHS[role])
    return contexts, output, inputs


def _service_contexts(value, role, pair, first, clocks):
    checked = {}
    for operation, row in value["serviceContexts"].items():
        input_raw = _original(row["inputOriginal"], services.MAX_INPUT)
        raw = _original(row["grantOriginal"], services.MAX_OUTPUT[operation])
        supplied = services.input_document(input_raw)
        p.require(supplied["coldBindingInputOriginal"] == first["coldBindingInputOriginal"]
            and supplied["coldBindingInputSha256"] == first["coldBindingInputSha256"])
        parents = pair["source"]["delivery"]["parentOriginals"]
        for field in services.PARENT_FIELDS: p.require(supplied["ordinary"]["source"][field] == parents[field])
        if role != ROLES[-1]:
            keys.same(supplied["endpointPairs"][role], value["pairContext"])
        prepared = services.prepare_input(operation, input_raw, **clocks)
        services.checked_result(operation, input_raw, _result(raw), **clocks)
        checked[operation] = dict(input=supplied, raw=raw, prepared=prepared)
    if role == ROLES[-1]:
        native, retrieval = (checked[name] for name in services.OPERATIONS)
        p.require(retrieval["input"]["nativePublicationOriginal"].encode("ascii") == native["raw"])
        for field in ("ordinary", "coordinatorPeerPreparationOriginal", "expectedPeer", "endpointPairs"):
            keys.same(native["input"][field], retrieval["input"][field])
        runtime = g.document(pair["source"]["delivery"]["runtime_raw"], g.MAX_BYTES)
        for field in ("durableGrantOriginal", "currentGrantOriginal"):
            grant = g.document(runtime[field].encode("ascii"), 256 * 1024)["payload"]
            for source, operation in (("native", "publication"), ("retrieval", "retrieval")):
                assigned_role = services.LOCAL_ROLES[services.ENDPOINTS[services.OPERATIONS.index(operation)]]
                assigned = next(row for row in pair["authorityKeys"] if row["role"] == assigned_role)
                keys.same(grant[source], {**{name: assigned[name] for name in
                    ("role", "keyId", "keySpkiSha256", "publicKeyBase64url")}, "grantSha256": p.sha(checked[operation]["raw"])})
                native_payload = checked[operation]["prepared"]["payload"]
                for prefix, native_name in (("durable", "durableAuthority"), ("current", "currentAuthority")):
                    keys.same(grant[prefix + "AuthorityEpoch"], native_payload[native_name]["epoch"])
                    p.require(grant[prefix + "PublicKeyBase64url"] == native_payload[native_name]["publicKeyBase64url"])
        for operation, kind in (("publication", "publication-reconciliation"), ("retrieval", "retrieval")):
            current = checked[operation]
            payload = current["prepared"]["payload"]
            # Root-signed ordinary grants and native grants all select the same
            # authentic epochs/keys and literal cold commissioning scope.
            keys.same(payload["scope"], runtime["scope"])
            for member in runtime["histories"]:
                ordinary_runtime = g.document(member["runtimeOriginal"].encode("ascii"), g.MAX_BYTES)
                keys.same(ordinary_runtime["runtime"]["expectedPeer"], payload["expectedPeer"])
            endpoint_role = services.ENDPOINTS[services.OPERATIONS.index(operation)]
            native_pair = current["input"]["endpointPairs"][endpoint_role]
            key_input = keys.input_document(native_pair["roleKeyInputOriginal"].encode("ascii"))
            delivered = keys.delivery.verified_delivery(endpoint_role, key_input["deliveryInputOriginal"].encode("ascii"),
                key_input["deliveryOriginal"].encode("ascii"), boot=clocks["boot"], now_boottime_ns=clocks["now_boottime_ns"])
            endpoint = next(row["expectedPeer"] for row in runtime["nativeEndpoints"] if row["kind"] == kind)
            guest, observed = delivered["guest"], delivered["observed"]
            p.require(endpoint["uid"] == guest["uid"] and endpoint["gid"] == guest["gid"]
                and endpoint["pid"] == observed["processId"] and endpoint["startTimeTicks"] == observed["startTimeTicks"])
            for name in ("device", "inode", "length", "sha256"):
                p.require(endpoint["executable" + name[0].upper() + name[1:]] == observed["executable"][name])
            cgroup = delivered["preparation"]["services"][endpoint_role]["cgroup"]
            for target, source in (("cgroupPathSha256", "pathSha256"), ("cgroupMountId", "mountId"), ("cgroupInode", "inode")):
                p.require(endpoint[target] == cgroup[source])
    return checked


def prepare_input(role, raw, *, boot, now_boottime_ns, now_unix_ns):
    value = input_document(raw)
    p.require(value["role"] == role and role in ROLES)
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    pair, first, pair_raw = _pair(value, role, clocks)
    contexts, signed, auth_inputs = _authorizations(value, role, first, clocks)
    service = _service_contexts(value, role, pair, first, clocks)
    source = pair["source"]
    supplied = keys.delivery.input_document(source["deliveryInputOriginal"])
    approved = binding.input_document(source["coldBindingInputOriginal"])
    trust_raw = _original(approved["trustOriginal"], 1024 * 1024)
    trust = g.document(trust_raw, 1024 * 1024)
    guest = pair["expectedScope"]["guest"]
    clock_raw = g.canonical({"apiVersion": "catchplate.nativeShadowGuestTimeBootstrap/v1", "guest": guest,
        "signingKeyId": trust["timeKey"]["keyId"], **value["timeBootstrap"]})
    public = {"deliveryConfiguration": supplied["configurationOriginal"].encode("ascii"),
        "delivery": source["deliveryOriginal"], "runtime": source["delivery"]["runtime_raw"],
        "trust": trust_raw, "timeBootstrap": clock_raw, "assignment": approved["assignmentOriginal"].encode("ascii"),
        "closure": signed["closure"], "keys": g.canonical({"apiVersion": "catchplate.nativeShadowRoleKeys/v2",
            "authorization": pair["authorization"]}), "encryptedKeys": signed["encrypted-delivery"],
        "admission": pair_raw["admissionOriginal"], "verifierTransport": signed["verifier-transport"],
        "encryptedInventory": _original(auth_inputs["encrypted-delivery"]["encryptedInventoryOriginal"], 32768)}
    pins = value["pins"]
    if role == ROLES[-1]:
        parent = g.document(supplied["parentOriginals"]["parentConfigurationOriginal"].encode("ascii"), 65536)
        cold_pin = parent["deliveryConfiguration"]
    else:
        owner = g.document(supplied["ownerConfigurationOriginal"].encode("ascii"), 32768)
        cold_pin = owner["services"][role]["deliveryConfiguration"]
    keys.same(pins["deliveryConfiguration"], cold_pin)
    payload = source["delivery"]["payload"]
    keys.same(pins["runtime"], payload["runtimeConfig"])
    ciphertext = [row for row in payload["credentials"] if row["name"] == "shadow-encrypted-role-inventory"]
    p.require(len(ciphertext) == 1)
    keys.same(pins["encryptedInventory"], ciphertext[0]["original"])
    # A launch destination cannot replace any other retained C9 credential.
    forbidden = {row["original"]["path"] for row in payload["credentials"]
        if row["name"] != "shadow-encrypted-role-inventory"}
    p.require(not forbidden.intersection(pin["path"] for pin in pins.values()))
    selector, operation = SELECTORS[role]
    if operation: public["serviceGrant"] = service[operation]["raw"]
    for name, original in public.items(): p.require(pins[name]["sha256"] == p.sha(original))
    launch = {"apiVersion": selector, "keyAdmission": {"apiVersion": "catchplate.nativeShadowGuestLaunch/v1",
        **{name: copy.deepcopy(pins[name]) for name in INNER}}}
    if operation: launch[operation] = copy.deepcopy(pins["serviceGrant"])
    launch_raw = g.canonical(launch)
    p.require(len(launch_raw) <= 32768 and pins["launch"]["sha256"] == p.sha(launch_raw))
    bounded = [pair, *contexts.values(), *(row["prepared"] for row in service.values())]
    deadline, epoch_limit = min(row["deadline"] for row in bounded), min(row["epochLimit"] for row in bounded)
    issued = max(pair[name]["payload"]["issuedAtUnixNanos"] for name in ("authorization", "admissionAuthorization"))
    issued = max(issued, *(row["payload"]["issuedAtUnixNanos"] for row in contexts.values()),
        *(row["prepared"]["payload"]["authorization"]["issuedAtUnixNanos"] for row in service.values()))
    p.require(issued <= now_unix_ns < epoch_limit and now_boottime_ns < deadline)
    bundle = {"apiVersion": RESULT_API, "role": role, "inputSha256": p.sha(raw),
        "launchOriginal": launch_raw.decode("ascii"), "launchSha256": p.sha(launch_raw), "launchPin": pins["launch"],
        "originals": {name: {"pin": pins[name], "original": original.decode("ascii")} for name, original in public.items()},
        "windowOriginal": g.canonical(source["delivery"]["window"]).decode("ascii"),
        "deadlineBoottimeNs": str(deadline), "issuedAtUnixNanos": issued, "expiresAtUnixNanos": epoch_limit}
    bundle_raw = p.canonical(bundle)
    p.require(len(bundle_raw) <= MAX_OUTPUT)
    return {"bundleOriginal": bundle_raw, "launchOriginal": launch_raw, "deadline": deadline, "epochLimit": epoch_limit}


def assemble(role, *, input_original):
    """Actual-clock keyless assembly; never installation or native admission."""
    owner = os.getpid(), originals._start(), originals._boot()
    before, wall = originals._clock(), time.time_ns()
    prepared = prepare_input(role, input_original, boot=owner[2], now_boottime_ns=before, now_unix_ns=wall)
    p.require((os.getpid(), originals._start(), originals._boot()) == owner)
    now, epoch = originals._clock(), time.time_ns()
    p.require(before <= now < prepared["deadline"] and wall <= epoch < prepared["epochLimit"])
    return prepared["bundleOriginal"], prepared["deadline"]
