"""Compose the fixed bridge launch from actual five authorizations and time grant.

The bridge is the TrustedTime endpoint's client, not that endpoint's guest.
Both complete authority inputs are authenticated without merging their original
invocations or windows. Independent policy supplies only the unsigned bridge
clock settings. No publication, verifier, ciphertext or live owner is created.
"""
from __future__ import annotations

import copy
import os
import time

from catchplate import native_pilot_bridge_authorization_profile as profile
from catchplate import native_pilot_bridge_launch_publication as publication
from catchplate import native_pilot_bridge_runtime as runtime
from catchplate import native_pilot_launch_publication as launch
from catchplate import native_pilot_native_service_profile as services
from catchplate import native_shadow_key_admission_profile as admission
from catchplate import native_shadow_nitro_originals as originals

p = profile.p
MAX_INPUT = launch.MAX_INPUT
ADOPTED_INPUT_API = "catchplate.nativePilotAdoptedBridgeLaunchInput/v1"
ADOPTED_INPUT_FIELDS = ("apiVersion", "fragment", "controlOriginal", "deliveryInputOriginal", "deliveryOriginal",
    "recipeOriginals", "measured", "authorizations", "serviceContext")
MAX_ADOPTED_INPUT = 32 * 1024 * 1024


def _service(service_context, *, pair, source, clocks, adopted=False):
    p.fields(service_context, ("inputOriginal", "grantOriginal"))
    input_raw = profile._bytes(service_context["inputOriginal"], services.MAX_INPUT)
    grant_raw = profile._bytes(service_context["grantOriginal"], 65536)
    prepared = (services.prepare_adopted_input if adopted else services.prepare_input)("trustedTime", input_raw, **clocks)
    (services.checked_adopted_result if adopted else services.checked_result)("trustedTime", input_raw, profile._result(grant_raw), **clocks)
    value = p.document(input_raw, services.MAX_INPUT)
    _, config = profile.keys.c9._original(value["configurationOriginal"], p.MAX_CONFIG)
    admitted, keys = admission.authorization(config, clocks["now_unix_ns"])
    scope = pair["expectedScope"]
    for name in ("assignmentId", "assignmentPayloadSha256", "assignmentRevision", "fullKeySetRootSha256"):
        p.require(admitted[name] == scope[name])
    profile.keys.c9._same(keys, pair["authorityKeys"])
    profile.keys.c9._same(config["trustCheckpoint"], pair["trustCheckpoint"])
    _, operational = runtime.original(source["runtimeOriginal"])
    peer = prepared["payload"]["expectedPeer"]
    p.require(peer["processIdentitySha256"] == operational["expectedDriverProcessIdentitySha256"]
        and peer["configurationGenerationSha256"] == operational["expectedDriverConfigurationGenerationSha256"])
    # Different guest and invocation are intentional. Only the actual boot/time
    # namespace and simultaneous original validity are shared with the bridge.
    for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode"):
        p.require(prepared["payload"]["guest"][name] == scope["guest"][name])
    return prepared


def _bundle(fragment, *, source, recipe_originals, pair, authorization_originals, service_grant_raw):
    """Deterministic public projection after authentication by prepare.

    This internal function alone makes no signature or provenance claim.
    Complete build has no option to bypass the actual authority checks.
    """
    p.fields(authorization_originals, profile.OPERATIONS)
    _, trust = profile.keys.c9._original(recipe_originals["trustOriginal"], 1024 * 1024)
    _, config = profile.keys.c9._original(source["ownerConfigurationOriginal"], 65536)
    clock = {"apiVersion": "catchplate.nativeShadowGuestTimeBootstrap/v1",
        "guest": pair["expectedScope"]["guest"], "signingKeyId": trust["timeKey"]["keyId"],
        **fragment["timeBootstrap"]}
    originals = {"trust": recipe_originals["trustOriginal"], "assignment": recipe_originals["assignmentOriginal"],
        "timeBootstrap": p.canonical(clock).decode("ascii"),
        "closure": authorization_originals["closure"].decode("ascii"),
        "keys": p.canonical({"apiVersion": "catchplate.nativeShadowRoleKeys/v2",
            "authorization": p.document(authorization_originals["role-keys"], profile.keys.MAX_OUTPUT)}).decode("ascii"),
        "admission": authorization_originals["admission"].decode("ascii"),
        "encryptedKeys": authorization_originals["encrypted-delivery"].decode("ascii"),
        "verifierTransport": authorization_originals["verifier-transport"].decode("ascii")}
    inner = {"apiVersion": "catchplate.nativeShadowGuestLaunch/v1",
        "deliveryConfiguration": copy.deepcopy(config["deliveryConfiguration"]),
        "delivery": {"path": launch.publication.DESTINATIONS["native-delivery-bridge"],
            "sha256": pair["expectedScope"]["guest"]["deliverySha256"]}}
    for name, (suffix, _) in launch.COMPONENTS.items():
        inner[name] = {"path": launch.DESTINATIONS["native-bridge-" + suffix],
            "sha256": p.sha(originals[name].encode("ascii"))}
    return p.canonical({"apiVersion": "catchplate.nativePilotLaunchBundle/v3" if fragment["apiVersion"] == profile.policy.ADOPTED_API
        else "catchplate.nativePilotLaunchBundle/v1", "role": "bridge",
        "ownerConfigurationSha256": p.sha(source["ownerConfigurationOriginal"].encode("ascii")),
        "windowSha256": p.sha(source["windowOriginal"].encode("ascii")),
        "observationOriginal": source["observationOriginal"], "runtimeOriginal": source["runtimeOriginal"],
        "keyAdmission": inner, "originals": originals, "serviceGrant": {
            "path": launch.publication.DESTINATIONS["native-service-trustedTime"], "sha256": p.sha(service_grant_raw)}})


def prepare(*, fragment, control_original, delivery_input_raw, delivery_raw, recipe_originals, measured,
            authorizations: dict, service_context, boot, now_boottime_ns, now_unix_ns):
    # The public parameter name is the retained operation map, not an owner.
    common = dict(fragment=fragment, control_original=control_original, delivery_input_raw=delivery_input_raw,
        delivery_raw=delivery_raw, recipe_originals=recipe_originals, measured=measured)
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    selected, source, records, contexts = profile._chain(profile.OPERATIONS, authorizations,
        common=common, clocks=clocks)
    window, deadline, epoch = profile._bounds(contexts, clocks)
    pair_context = profile._pair_context(records)
    adopted = selected["apiVersion"] == profile.policy.ADOPTED_API
    pair = profile.keys.admitted_pair(*(pair_context[name].encode("ascii") for name in profile.PAIR_FIELDS),
        adopted=adopted, **clocks)
    service = _service(service_context, pair=pair, source=source, clocks=clocks, adopted=adopted)
    raw = _bundle(selected, source=source, recipe_originals=recipe_originals, pair=pair,
        authorization_originals={name: row["authorizationOriginal"] for name, row in records.items()},
        service_grant_raw=service_context["grantOriginal"])
    profile._bytes(raw, MAX_INPUT)
    checked = publication.prepare_bridge_bundle(raw, pair_context=pair_context,
        service_grant_original=service_context["grantOriginal"], **clocks)
    profile.keys.c9._same(window, checked["window"])
    deadline = min(deadline, service["deadline"], checked["deadline"])
    epoch = min(epoch, service["epochLimit"], checked["epochLimit"])
    p.require(now_boottime_ns < deadline and now_unix_ns < epoch)
    return {"bundleOriginal": raw, "window": window, "deadline": deadline, "epochLimit": epoch}


def build(**kwargs):
    return prepare(**kwargs)["bundleOriginal"]


def checked_result(bundle_raw, result, **kwargs):
    prepared = prepare(**kwargs)
    p.require(type(bundle_raw) is bytes and bundle_raw == prepared["bundleOriginal"])
    return publication.checked_bridge_result(bundle_raw, result,
        pair_context=profile._pair_context(kwargs["authorizations"]),
        service_grant_original=kwargs["service_context"]["grantOriginal"],
        **{name: kwargs[name] for name in ("boot", "now_boottime_ns", "now_unix_ns")})


def input_document(raw):
    """Complete approved source input, never a caller-supplied success record."""
    value = p.fields(p.document(raw, MAX_ADOPTED_INPUT), ADOPTED_INPUT_FIELDS)
    p.require(value["apiVersion"] == ADOPTED_INPUT_API
        and value["fragment"]["apiVersion"] == profile.policy.ADOPTED_API)
    for row in p.fields(value["authorizations"], profile.OPERATIONS).values():
        p.fields(row, ("inputOriginal", "authorizationOriginal"))
    p.fields(value["serviceContext"], ("inputOriginal", "grantOriginal"))
    return value


def prepare_input(input_original, *, boot, now_boottime_ns, now_unix_ns):
    """Explicit adopted assembly, authenticating the full graph before output."""
    value = input_document(input_original)
    def original(text, maximum): return profile.keys.c9._original(text, maximum)[0]
    records = {operation: {name: original(text, profile.MAX_INPUT if name == "inputOriginal" else profile.MAX_OUTPUT)
        for name, text in row.items()} for operation, row in value["authorizations"].items()}
    service = {name: original(text, services.MAX_INPUT if name == "inputOriginal" else 65536)
        for name, text in value["serviceContext"].items()}
    common = dict(fragment=value["fragment"], control_original=original(value["controlOriginal"], 4096),
        delivery_input_raw=original(value["deliveryInputOriginal"], profile.keys.c9.MAX_BRIDGE_INPUT),
        delivery_raw=original(value["deliveryOriginal"], profile.keys.delivery.MAX_DELIVERY),
        recipe_originals=value["recipeOriginals"], measured=value["measured"],
        authorizations=records, service_context=service)
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    prepared = prepare(**common, **clocks)
    checked = publication.prepare_bridge_bundle(prepared["bundleOriginal"],
        pair_context=profile._pair_context(records), service_grant_original=service["grantOriginal"], **clocks)
    source = profile.keys.c9.input_document(common["delivery_input_raw"])
    prerequisites = [("control", common["control_original"]),
        *((name, original(source[field], maximum)) for name, field, maximum in (
            ("owner", "ownerConfigurationOriginal", 65536), ("window", "windowOriginal", 32768),
            ("configuration", "configurationOriginal", 65536), ("runtime", "runtimeOriginal", 4 * 1024 * 1024))),
        ("delivery", common["delivery_raw"]), ("grant", service["grantOriginal"])]
    return {**checked, **prepared, "prerequisites": tuple(prerequisites)}


def assemble(*, input_original):
    """Keyless deterministic public bundle only; never install or release."""
    owner = (os.getpid(), originals._start(), originals._boot())
    before, wall = originals._clock(), time.time_ns()
    prepared = prepare_input(input_original, boot=owner[2], now_boottime_ns=before, now_unix_ns=wall)
    p.require(owner == (os.getpid(), originals._start(), originals._boot()))
    now, epoch = originals._clock(), time.time_ns()
    p.require(before <= now < prepared["deadline"] and wall <= epoch < prepared["epochLimit"])
    return prepared["bundleOriginal"], prepared["deadline"]
