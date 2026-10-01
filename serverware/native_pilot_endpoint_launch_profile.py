"""Pure ten-endpoint launch composition from authenticated retained originals.

The caller supplies the real owner's prior inputs and outputs. These functions
verify public signatures and exact byte associations, not owner provenance,
installed files, encrypted secrets, hardware attestation or native readiness.
Only independently selected time-bootstrap settings are composed. TrustedTime
retains its earlier unsigned bootstrap original bound by the signed grant.
"""
from __future__ import annotations

import copy

from serverware import native_pilot_delivery_authority as c9
from serverware import native_pilot_key_profile as keys
from serverware import native_pilot_launch_authorization_profile as late
from serverware import native_pilot_launch_publication as launch
from serverware import native_pilot_native_service_profile as services

p = keys.p
API = "serverware.nativePilotEndpointLaunchPolicy/v1"
ROLES = keys.ROLES
CLOCK_FIELDS = ("parentPort", "maximumBracketNanos", "timestampErrorNanos", "maximumClockRateErrorPpm")
SERVICE_OPERATIONS = {role: launch.LAUNCHES[role][2] or "generationInstall" for role in ROLES}
MAX_POLICY = 16384
MAX_INPUT = launch.MAX_INPUT


def validate_policy(fragment):
    p.fields(fragment, ("apiVersion", "endpoints"))
    p.require(fragment["apiVersion"] == API and len(p.canonical(fragment)) <= MAX_POLICY)
    for row in p.fields(fragment["endpoints"], ROLES).values():
        p.fields(row, CLOCK_FIELDS)
        p.integer(row["parentPort"], minimum=1024, maximum=(1 << 32) - 2)
        p.require(p.ns(row["maximumBracketNanos"]) <= 1_000_000_000)
        p.integer(row["timestampErrorNanos"], minimum=0, maximum=1_000_000_000)
        p.integer(row["maximumClockRateErrorPpm"], minimum=0, maximum=10000)
    return copy.deepcopy(fragment)


def _bytes(raw, maximum):
    p.require(type(raw) is bytes and 0 < len(raw) <= maximum)
    p.document(raw, maximum)
    return raw


def _same(first, second):
    p.require(p.canonical(first) == p.canonical(second))


def _pair(role, pair_context, clocks):
    p.fields(pair_context, late.PAIR_FIELDS)
    raw = {name: c9._original(pair_context[name], keys.MAX_INPUT if "Input" in name else keys.MAX_OUTPUT)[0]
        for name in late.PAIR_FIELDS}
    admitted = keys.admitted_pair(role, raw["roleKeyInputOriginal"], raw["roleKeyOriginal"],
        raw["admissionInputOriginal"], raw["admissionOriginal"], **clocks)
    first = p.document(raw["roleKeyInputOriginal"], keys.MAX_INPUT)
    delivery_input, delivery = c9._original(first["deliveryInputOriginal"], c9.MAX_INPUT)
    delivery_raw, _ = c9._original(first["deliveryOriginal"], keys.MAX_OUTPUT)
    return {"pair": admitted, "first": first, "delivery": delivery,
        "delivery_input": delivery_input, "delivery_raw": delivery_raw}


def _service(role, context, service_context, clocks):
    p.fields(service_context, ("inputOriginal", "grantOriginal", "commitRequestOriginal"))
    input_raw = _bytes(service_context["inputOriginal"], services.MAX_INPUT)
    grant_raw = _bytes(service_context["grantOriginal"], services.MAX_OUTPUT)
    operation = SERVICE_OPERATIONS[role]
    services.checked_result(operation, input_raw,
        {"original": grant_raw.decode("ascii"), "sha256": p.sha(grant_raw)}, **clocks)
    value = p.document(input_raw, services.MAX_INPUT)
    generation = role == "generationInstall"
    native_name = "nativeConfigurationOriginal" if generation else "configurationOriginal"
    _, native = c9._original(value[native_name], p.MAX_CONFIG)
    for name, expected in context["pair"].items():
        _same(native[name], expected)
    delivered = context["delivery"]
    joins = {"cohortConfigurationOriginal": "ownerConfigurationOriginal", "precreationOriginal": "windowOriginal",
        "observationOriginal": "observationOriginal",
        "coordinatorConfigurationOriginal" if generation else "coldConfigurationOriginal": "configurationOriginal",
        "coordinatorRuntimeOriginal" if generation else "runtimeOriginal": "runtimeOriginal"}
    for target, source in joins.items():
        p.require(value[target] == delivered[source])
    p.require(value["coordinatorDeliveryOriginal" if generation else "deliveryOriginal"]
        == context["first"]["deliveryOriginal"])
    companion = service_context["commitRequestOriginal"]
    if role == "commitRequest":
        _bytes(companion, services.MAX_OUTPUT)
        p.require(value["companionOriginal"].encode("ascii") == companion)
    else:
        p.require(companion is None)
    return value


def _authorizations(role, context, pair_context, authorizations, clocks):
    operations = tuple(operation for operation, selected in late.JOBS if selected == role)
    p.fields(authorizations, operations)
    output = {}
    for operation in operations:
        item = p.fields(authorizations[operation], ("inputOriginal", "authorizationOriginal"))
        input_raw = _bytes(item["inputOriginal"], keys.MAX_INPUT)
        raw = _bytes(item["authorizationOriginal"], launch.MAX_INPUT)
        value = p.document(input_raw, keys.MAX_INPUT)
        if operation == "closure":
            delivered, recipe = context["delivery"], context["first"]["recipeOriginals"]
            for target, source in (("configurationOriginal", "ownerConfigurationOriginal"),
                    ("windowOriginal", "windowOriginal"), ("observationOriginal", "observationOriginal"),
                    ("deliveryConfigurationOriginal", "configurationOriginal"), ("runtimeOriginal", "runtimeOriginal")):
                p.require(value[target] == delivered[source])
            p.require(value["deliveryOriginal"] == context["first"]["deliveryOriginal"])
            for name in ("trustOriginal", "trustSha256", "assignmentOriginal", "closureSetOriginal"):
                p.require(value[name] == recipe[name])
        else:
            for name in late.PAIR_FIELDS:
                p.require(value[name] == pair_context[name])
            if operation == "encrypted-delivery" and role == "commitRequest":
                p.require(value["requestCommitmentOriginal"].encode("ascii") == output["request-commitment"])
        output[operation] = late.checked_result(operation, role, input_raw,
            {"original": raw.decode("ascii"), "sha256": p.sha(raw)}, **clocks)
    return output


def _bundle(role, row, context, authorizations, service_context, service_input):
    """Deterministic public projection; callers must authenticate context first."""
    first, delivered = context["first"], context["delivery"]
    recipe, guest = first["recipeOriginals"], context["pair"]["expectedScope"]["guest"]
    _, trust = c9._original(recipe["trustOriginal"], 1024 * 1024)
    if role == "trustedTime":
        clock_raw, clock = c9._original(service_input["bootstrapOriginal"], 65536)
        _same({name: clock[name] for name in CLOCK_FIELDS}, row)
        p.require(clock["signingKeyId"] == trust["timeKey"]["keyId"])
        _same(clock["guest"], guest)
    else:
        clock_raw = p.canonical({"apiVersion": "serverware.nativeShadowGuestTimeBootstrap/v1",
            "guest": guest, "signingKeyId": trust["timeKey"]["keyId"], **row})
    originals = {"trust": recipe["trustOriginal"], "timeBootstrap": clock_raw.decode("ascii"),
        "assignment": recipe["assignmentOriginal"], "closure": authorizations["closure"].decode("ascii"),
        "keys": p.canonical({"apiVersion": "serverware.nativeShadowRoleKeys/v2",
            "authorization": context["pair"]["authorization"]}).decode("ascii"),
        "encryptedKeys": authorizations["encrypted-delivery"].decode("ascii"),
        "admission": p.canonical(context["pair"]["admissionAuthorization"]).decode("ascii"),
        "verifierTransport": authorizations["verifier-transport"].decode("ascii")}
    inner = {"apiVersion": "serverware.nativeShadowGuestLaunch/v1",
        "deliveryConfiguration": {"path": launch.publication.DESTINATIONS["native-cold-" + role],
            "sha256": p.sha(delivered["configurationOriginal"].encode("ascii"))},
        "delivery": {"path": launch.publication.DESTINATIONS["native-delivery-" + role],
            "sha256": p.sha(context["delivery_raw"])}}
    for name, (suffix, _) in launch.COMPONENTS.items():
        inner[name] = {"path": launch.DESTINATIONS["native-" + role + "-" + suffix],
            "sha256": p.sha(originals[name].encode("ascii"))}
    return p.canonical({"apiVersion": "serverware.nativePilotLaunchBundle/v1", "role": role,
        "ownerConfigurationSha256": p.sha(delivered["ownerConfigurationOriginal"].encode("ascii")),
        "windowSha256": p.sha(delivered["windowOriginal"].encode("ascii")),
        "observationOriginal": delivered["observationOriginal"], "keyAdmission": inner,
        "runtimeOriginal": delivered["runtimeOriginal"], "originals": originals,
        "serviceGrant": {"path": launch.publication.DESTINATIONS[launch._grant_purpose(role)],
            "sha256": p.sha(service_context["grantOriginal"])}})


def _options(context, service_context, clocks):
    return dict(delivery_input_original=context["delivery_input"], delivery_original=context["delivery_raw"],
        service_grant_original=service_context["grantOriginal"],
        commit_request_original=service_context["commitRequestOriginal"], **clocks)


def build(role, *, fragment, pair_context, authorizations, service_context,
          boot, now_boottime_ns, now_unix_ns) -> bytes:
    p.require(role in ROLES)
    selected = validate_policy(fragment)["endpoints"][role]
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    context = _pair(role, pair_context, clocks)
    service_input = _service(role, context, service_context, clocks)
    output = _authorizations(role, context, pair_context, authorizations, clocks)
    raw = _bundle(role, selected, context, output, service_context, service_input)
    p.require(len(raw) <= MAX_INPUT)
    prepared = launch.prepare_endpoint_bundle(raw, **_options(context, service_context, clocks))
    p.require(prepared["role"] == role)
    return raw


def checked_result(role, input_raw, result, *, pair_context, service_context,
                   boot, now_boottime_ns, now_unix_ns):
    """Validate reported public pins, never a claim that installation occurred."""
    p.require(role in ROLES)
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    context = _pair(role, pair_context, clocks)
    _service(role, context, service_context, clocks)
    p.require(p.document(input_raw, MAX_INPUT)["role"] == role)
    return launch.checked_endpoint_result(input_raw, result, **_options(context, service_context, clocks))
