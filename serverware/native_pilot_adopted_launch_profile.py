"""Keyless adopted endpoint launch bundles from exact authenticated issuers.

This is public assembly, not installation, release, attestation or a live owner.
All authorization inputs remain literal and version-selected. The native grant
is a prior output; no C9 or key assignment contains a future service-grant hash.
"""
from __future__ import annotations

import time

from serverware import native_pilot_adopted_service_authority as service
from serverware import native_pilot_adopted_delivery as adopted_c9
from serverware import native_pilot_delivery_authority as c9
from serverware import native_pilot_key_profile as keys
from serverware import native_pilot_launch_authorization_profile as late
from serverware import native_pilot_launch_publication as launch
from serverware import native_shadow_nitro_originals as host

p = keys.p
API = "serverware.nativePilotAdoptedLaunchInput/v1"
BUNDLE_API = "serverware.nativePilotLaunchBundle/v2"
ROLES = ("retrieval", "persistence", "publicationReconciliation")
OPERATIONS = {"retrieval": "retrieval", "persistence": "persistence", "publicationReconciliation": "publication"}
FIELDS = ("apiVersion", "role", "pair", "authorizations", "serviceInputOriginal", "serviceGrantOriginal", "timeBootstrap")
AUTHORIZATIONS = ("closure", "encrypted-delivery", "verifier-transport")
MAX_INPUT = 32 * 1024 * 1024


def input_document(role, raw):
    value = p.fields(p.document(raw, MAX_INPUT), FIELDS)
    p.require(value["apiVersion"] == API and role in ROLES and value["role"] == role)
    p.fields(value["pair"], late.PAIR_FIELDS)
    p.fields(value["authorizations"], AUTHORIZATIONS)
    for row in value["authorizations"].values(): p.fields(row, ("inputOriginal", "original"))
    return value


def prepare_input(role, input_original, *, boot, now_boottime_ns, now_unix_ns):
    value = input_document(role, input_original)
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    pair_raw = {name: service.original(text, keys.MAX_INPUT if "Input" in name else keys.MAX_OUTPUT)[0]
        for name, text in value["pair"].items()}
    pair = keys.admitted_adopted_pair(role, pair_raw["roleKeyInputOriginal"], pair_raw["roleKeyOriginal"],
        pair_raw["admissionInputOriginal"], pair_raw["admissionOriginal"], **clocks)
    first = p.document(pair_raw["roleKeyInputOriginal"], keys.MAX_INPUT)
    delivered_input, delivered = service.original(first["deliveryInputOriginal"], adopted_c9.MAX_INPUT)
    delivered_raw, _ = service.original(first["deliveryOriginal"], 65536)
    endpoint = c9.verify_adopted_delivery(delivered_input, delivered_raw, boot=boot,
        now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    p.require(endpoint["role"] == role and endpoint["guest"] == pair["expectedScope"]["guest"])
    source_raw, source = service.original(value["serviceInputOriginal"], service.MAX_INPUT)
    operation = OPERATIONS[role]
    prepared = service.prepare_input(operation, source_raw, **clocks)
    grant_raw, _ = service.original(value["serviceGrantOriginal"], service.PROFILES[operation][3])
    signed = service.grant_original(operation, grant_raw)
    p.require(signed["payload"] == prepared["payload"]
        and source["deliveryInputOriginal"] == first["deliveryInputOriginal"]
        and source["deliveryOriginal"] == first["deliveryOriginal"])
    p.public_key(prepared["supervisor"]).verify(p.decoded(signed["signature"], size=64),
        p.preimage(prepared["domain"], signed["payload"]))
    _, config = service.original(source["configurationOriginal"], p.MAX_CONFIG)
    for name in ("authorization", "admissionAuthorization", "expectedScope", "authorityKeys", "trustCheckpoint"):
        p.require(config[name] == pair[name])
    _, validation = service.original(source["adoptionValidationInputOriginal"], service.MAX_INPUT)
    recipe = first["recipeOriginals"]
    for target, field in (("trustOriginal", "currentTrustOriginal"), ("assignmentOriginal", "currentAssignmentOriginal"),
            ("closureSetOriginal", "currentClosureSetOriginal")):
        p.require(recipe[target] == validation[field])
    p.require(recipe["trustSha256"] == validation["currentTrustSha256"])
    deadline, epoch_limit = prepared["deadline"], prepared["epochLimit"]
    authenticated = {}
    for name, row in value["authorizations"].items():
        raw, original_input = service.original(row["inputOriginal"], MAX_INPUT)
        result_raw, _ = service.original(row["original"], 1024 * 1024)
        context = late.prepare_adopted_input(name, role, raw, **clocks)
        result = late.checked_adopted_result(name, role, raw,
            {"original": row["original"], "sha256": p.sha(result_raw)}, **clocks)
        p.require(result == result_raw)
        if name == "closure":
            p.require(original_input["deliveryInputOriginal"] == first["deliveryInputOriginal"]
                and original_input["deliveryOriginal"] == first["deliveryOriginal"]
                and original_input["trustOriginal"] == recipe["trustOriginal"]
                and original_input["assignmentOriginal"] == recipe["assignmentOriginal"]
                and original_input["closureSetOriginal"] == recipe["closureSetOriginal"])
        else:
            for field in late.PAIR_FIELDS: p.require(original_input[field] == value["pair"][field])
        deadline = min(deadline, context["deadline"]); epoch_limit = min(epoch_limit, context["epochLimit"])
        authenticated[name] = result_raw
    _, trust = service.original(recipe["trustOriginal"], 1024 * 1024)
    timing = p.fields(value["timeBootstrap"], ("parentPort", "maximumBracketNanos", "timestampErrorNanos", "maximumClockRateErrorPpm"))
    clock_raw = p.canonical({"apiVersion": "serverware.nativeShadowGuestTimeBootstrap/v1", "guest": endpoint["guest"],
        "signingKeyId": trust["timeKey"]["keyId"], **timing})
    launch.shape_adopted("native-" + role + "-time-bootstrap", clock_raw)
    originals = {"trust": recipe["trustOriginal"].encode("ascii"), "timeBootstrap": clock_raw,
        "assignment": recipe["assignmentOriginal"].encode("ascii"), "closure": authenticated["closure"],
        "keys": p.canonical({"apiVersion": "serverware.nativeShadowRoleKeys/v2", "authorization": pair["authorization"]}),
        "encryptedKeys": authenticated["encrypted-delivery"], "admission": pair_raw["admissionOriginal"],
        "verifierTransport": authenticated["verifier-transport"]}
    paths = launch.ADOPTED_DESTINATIONS
    inner = {"apiVersion": "serverware.nativeShadowGuestLaunch/v1",
        "deliveryConfiguration": {"path": paths["native-cold-" + role], "sha256": p.sha(endpoint["configuration_raw"])},
        "delivery": {"path": paths["native-delivery-" + role], "sha256": p.sha(delivered_raw)}}
    files = {"native-runtime-" + role: endpoint["runtime_raw"]}
    for name, (suffix, _) in launch.COMPONENTS.items():
        purpose = "native-" + role + "-" + suffix
        launch.shape_adopted(purpose, originals[name])
        files[purpose] = originals[name]
        inner[name] = {"path": paths[purpose], "sha256": p.sha(originals[name])}
    p.require(endpoint["payload"]["runtimeConfig"] == {"path": paths["native-runtime-" + role], "sha256": p.sha(endpoint["runtime_raw"])})
    encrypted = p.document(authenticated["encrypted-delivery"], 65536)["authorization"]["payload"]["transport"]
    inventory = [row for row in endpoint["payload"]["credentials"] if row["name"] == "shadow-encrypted-role-inventory"]
    p.require(len(inventory) == 1 and inventory[0]["signing"] is None and 0 < inventory[0]["length"] <= 32768
        and inventory[0]["original"]["sha256"] == encrypted["encryptedInventorySha256"]
        and all(not row["name"].startswith("shadow-key-custody-") for row in endpoint["payload"]["credentials"]))
    grant_pin = {"path": paths["native-service-" + operation], "sha256": p.sha(grant_raw)}
    api, field, _ = launch.ADOPTED_LAUNCHES[role]
    launch_raw = p.canonical({"apiVersion": "serverware." + api, "keyAdmission": inner, field: grant_pin})
    launch.shape_adopted("native-launch-" + role, launch_raw)
    files["native-launch-" + role] = launch_raw
    pins = {purpose: {"path": paths[purpose], "sha256": p.sha(raw)} for purpose, raw in files.items()}
    p.require(len({pin["path"] for pin in pins.values()}) == len(pins))
    bundle = p.canonical({"apiVersion": BUNDLE_API, "role": role,
        "ownerConfigurationSha256": p.sha(endpoint["owner_configuration_raw"]),
        "windowSha256": p.sha(delivered["windowOriginal"].encode("ascii")), "observationOriginal": delivered["observationOriginal"],
        "keyAdmission": inner, "runtimeOriginal": delivered["runtimeOriginal"],
        "originals": {name: raw.decode("ascii") for name, raw in originals.items()}, "serviceGrant": grant_pin})
    p.require(len(bundle) <= launch.MAX_INPUT and now_boottime_ns < deadline and now_unix_ns < epoch_limit)
    return {"role": role, "bundleOriginal": bundle, "prepared": files, "pins": pins, "launch": pins["native-launch-" + role],
        "window": endpoint["window"], "deadline": deadline, "epochLimit": epoch_limit,
        "prerequisites": (("owner", endpoint["owner_configuration_raw"]), ("window", delivered["windowOriginal"].encode("ascii")),
            ("configuration", endpoint["configuration_raw"]), ("delivery", delivered_raw), ("grant", grant_raw))}


def assemble(role, *, input_original):
    boot, before, wall = host._boot(), host._clock(), time.time_ns()
    context = prepare_input(role, input_original, boot=boot, now_boottime_ns=before, now_unix_ns=wall)
    p.require(host._boot() == boot)
    after, epoch = host._clock(), time.time_ns()
    p.require(before <= after < context["deadline"] and wall <= epoch < context["epochLimit"])
    return context["bundleOriginal"], context["deadline"]


def checked_result(role, input_raw, result, **clocks):
    context = prepare_input(role, input_raw, **clocks)
    p.fields(result, ("original", "sha256"))
    p.require(result == {"original": context["bundleOriginal"].decode("ascii"), "sha256": p.sha(context["bundleOriginal"])})
    return context["bundleOriginal"]
