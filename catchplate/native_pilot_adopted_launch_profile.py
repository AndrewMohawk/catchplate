"""Keyless adopted endpoint launch bundles from exact authenticated issuers.

This is public assembly, not installation, release, attestation or a live owner.
All authorization inputs remain literal and version-selected. The native grant
is a prior output; no C9 or key assignment contains a future service-grant hash.
"""
from __future__ import annotations

import time

from catchplate import native_pilot_adopted_service_authority as service
from catchplate import native_pilot_adopted_delivery as adopted_c9
from catchplate import native_pilot_delivery_authority as c9
from catchplate import native_pilot_encrypted_authority as encrypted_authority
from catchplate import native_pilot_generation_install_authority as generation
from catchplate import native_pilot_key_profile as keys
from catchplate import native_pilot_launch_authorization_profile as late
from catchplate import native_pilot_launch_publication as launch
from catchplate import native_pilot_native_service_authority as native
from catchplate import native_pilot_native_service_profile as services
from catchplate import native_shadow_nitro_originals as host

p = keys.p
API = "catchplate.nativePilotAdoptedLaunchInput/v1"
ALL_API = "catchplate.nativePilotAdoptedLaunchInput/v2"
BUNDLE_API = "catchplate.nativePilotLaunchBundle/v2"
ROLES = ("retrieval", "persistence", "publicationReconciliation")
ALL_ROLES = keys.ADOPTED_ROLES
OPERATIONS = {role: role for role in ALL_ROLES} | {"publicationReconciliation": "publication",
    "commitRequest": "ledger", "ingressAdmission": "ingress", "terminalAppend": "terminal"}
FIELDS = ("apiVersion", "role", "pair", "authorizations", "serviceInputOriginal", "serviceGrantOriginal", "timeBootstrap")
AUTHORIZATIONS = ("closure", "encrypted-delivery", "verifier-transport")
MAX_INPUT = 32 * 1024 * 1024


def input_document(role, raw):
    value = p.document(raw, MAX_INPUT)
    all_roles = value.get("apiVersion") == ALL_API
    p.fields(value, FIELDS + (("companionInputOriginal", "companionGrantOriginal") if all_roles and role == "commitRequest" else ()))
    p.require(value["apiVersion"] == (ALL_API if all_roles else API)
        and role in (ALL_ROLES if all_roles else ROLES) and value["role"] == role)
    p.fields(value["pair"], late.PAIR_FIELDS)
    p.fields(value["authorizations"], AUTHORIZATIONS + (("request-commitment",) if role == "commitRequest" else ()))
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
    prepared = services.prepare_adopted_input(operation, source_raw, **clocks)
    maximum = service.PROFILES[operation][3] if operation in service.PROFILES else native.MAX_OUTPUT
    grant_raw, _ = service.original(value["serviceGrantOriginal"], maximum)
    signed = generation.grant_original(grant_raw) if role == "generationInstall" else native.grant_original(operation, grant_raw)
    delivery_field = "coordinatorDeliveryOriginal" if role == "generationInstall" else "deliveryOriginal"
    configuration_field = "nativeConfigurationOriginal" if role == "generationInstall" else "configurationOriginal"
    p.require(signed["payload"] == prepared["payload"]
        and source["deliveryInputOriginal"] == first["deliveryInputOriginal"]
        and source[delivery_field] == first["deliveryOriginal"])
    p.public_key(prepared["supervisor"]).verify(p.decoded(signed["signature"], size=64),
        p.preimage(prepared["domain"], signed["payload"]))
    _, config = service.original(source[configuration_field], p.MAX_CONFIG)
    for name in ("authorization", "admissionAuthorization", "expectedScope", "authorityKeys", "trustCheckpoint"):
        p.require(config[name] == pair[name])
    recipe = first["recipeOriginals"]
    if role in ROLES:
        _, validation = service.original(source["adoptionValidationInputOriginal"], service.MAX_INPUT)
        for target, field in (("trustOriginal", "currentTrustOriginal"), ("assignmentOriginal", "currentAssignmentOriginal"),
                ("closureSetOriginal", "currentClosureSetOriginal")):
            p.require(recipe[target] == validation[field])
        p.require(recipe["trustSha256"] == validation["currentTrustSha256"])
    else:
        p.require(source["pair"] == value["pair"])
    deadline, epoch_limit = prepared["deadline"], prepared["epochLimit"]
    authenticated = {}
    for name, row in value["authorizations"].items():
        raw, original_input = service.original(row["inputOriginal"], MAX_INPUT)
        result_raw, _ = service.original(row["original"], 1024 * 1024)
        packet = {"original": row["original"], "sha256": p.sha(result_raw)}
        if name == "request-commitment":
            p.require(role == "commitRequest" and original_input["apiVersion"] == encrypted_authority.ADOPTED_API)
            context = encrypted_authority.prepare_input(name, role, raw, **clocks)
            result = encrypted_authority.checked_result(name, role, raw, packet, **clocks)
        else:
            context = late.prepare_adopted_input(name, role, raw, **clocks)
            result = late.checked_adopted_result(name, role, raw, packet, **clocks)
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
    clock_raw = p.canonical({"apiVersion": "catchplate.nativeShadowGuestTimeBootstrap/v1", "guest": endpoint["guest"],
        "signingKeyId": trust["timeKey"]["keyId"], **timing})
    launch.shape_adopted("native-" + role + "-time-bootstrap", clock_raw)
    if role == "trustedTime":
        p.require(source["bootstrapOriginal"].encode("ascii") == clock_raw
            and signed["payload"]["clockBootstrapSha256"] == p.sha(clock_raw))
    companion = None
    if role == "commitRequest":
        companion_input, companion_source = service.original(value["companionInputOriginal"], native.MAX_INPUT)
        companion, _ = service.original(value["companionGrantOriginal"], native.MAX_OUTPUT)
        companion_prepared = services.prepare_adopted_input("commitRequest", companion_input, **clocks)
        services.checked_adopted_result("commitRequest", companion_input,
            {"original": value["companionGrantOriginal"], "sha256": p.sha(companion)}, **clocks)
        p.require(companion_source["pair"] == value["pair"]
            and companion_source["deliveryInputOriginal"] == first["deliveryInputOriginal"]
            and companion_source["deliveryOriginal"] == first["deliveryOriginal"]
            and source["companionOriginal"] == value["companionGrantOriginal"]
            and source["companionPin"] == {"path": launch.ADOPTED_DESTINATIONS["native-service-commitRequest"], "sha256": p.sha(companion)})
        encrypted_value = p.document(authenticated["encrypted-delivery"], 65536)
        p.require(p.canonical(encrypted_value["requestCommitment"]) == authenticated["request-commitment"])
        deadline = min(deadline, companion_prepared["deadline"])
        epoch_limit = min(epoch_limit, companion_prepared["epochLimit"])
    originals = {"trust": recipe["trustOriginal"].encode("ascii"), "timeBootstrap": clock_raw,
        "assignment": recipe["assignmentOriginal"].encode("ascii"), "closure": authenticated["closure"],
        "keys": p.canonical({"apiVersion": "catchplate.nativeShadowRoleKeys/v2", "authorization": pair["authorization"]}),
        "encryptedKeys": authenticated["encrypted-delivery"], "admission": pair_raw["admissionOriginal"],
        "verifierTransport": authenticated["verifier-transport"]}
    paths = launch.ADOPTED_DESTINATIONS
    inner = {"apiVersion": "catchplate.nativeShadowGuestLaunch/v1",
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
    grant_purpose = "native-generation-install-grant" if role == "generationInstall" else "native-service-" + operation
    grant_pin = {"path": paths[grant_purpose], "sha256": p.sha(grant_raw)}
    api, field, _ = launch.ADOPTED_LAUNCHES[role]
    launch_raw = p.canonical({"apiVersion": "catchplate." + api, "keyAdmission": inner, field: grant_pin})
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
            ("configuration", endpoint["configuration_raw"]), ("delivery", delivered_raw), ("grant", grant_raw))
            + ((("companion", companion),) if companion is not None else ())}


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
