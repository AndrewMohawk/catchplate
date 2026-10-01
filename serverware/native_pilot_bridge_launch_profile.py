"""Compose the fixed bridge launch from actual five authorizations and time grant.

The bridge is the TrustedTime endpoint's client, not that endpoint's guest.
Both complete authority inputs are authenticated without merging their original
invocations or windows. Independent policy supplies only the unsigned bridge
clock settings. No publication, verifier, ciphertext or live owner is created.
"""
from __future__ import annotations

import copy

from serverware import native_pilot_bridge_authorization_profile as profile
from serverware import native_pilot_bridge_launch_publication as publication
from serverware import native_pilot_bridge_runtime as runtime
from serverware import native_pilot_launch_publication as launch
from serverware import native_pilot_native_service_profile as services
from serverware import native_shadow_key_admission_profile as admission

p = profile.p
MAX_INPUT = launch.MAX_INPUT


def _service(service_context, *, pair, source, clocks):
    p.fields(service_context, ("inputOriginal", "grantOriginal"))
    input_raw = profile._bytes(service_context["inputOriginal"], services.MAX_INPUT)
    grant_raw = profile._bytes(service_context["grantOriginal"], 65536)
    prepared = services.prepare_input("trustedTime", input_raw, **clocks)
    services.checked_result("trustedTime", input_raw, profile._result(grant_raw), **clocks)
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
    clock = {"apiVersion": "serverware.nativeShadowGuestTimeBootstrap/v1",
        "guest": pair["expectedScope"]["guest"], "signingKeyId": trust["timeKey"]["keyId"],
        **fragment["timeBootstrap"]}
    originals = {"trust": recipe_originals["trustOriginal"], "assignment": recipe_originals["assignmentOriginal"],
        "timeBootstrap": p.canonical(clock).decode("ascii"),
        "closure": authorization_originals["closure"].decode("ascii"),
        "keys": p.canonical({"apiVersion": "serverware.nativeShadowRoleKeys/v2",
            "authorization": p.document(authorization_originals["role-keys"], profile.keys.MAX_OUTPUT)}).decode("ascii"),
        "admission": authorization_originals["admission"].decode("ascii"),
        "encryptedKeys": authorization_originals["encrypted-delivery"].decode("ascii"),
        "verifierTransport": authorization_originals["verifier-transport"].decode("ascii")}
    inner = {"apiVersion": "serverware.nativeShadowGuestLaunch/v1",
        "deliveryConfiguration": copy.deepcopy(config["deliveryConfiguration"]),
        "delivery": {"path": launch.publication.DESTINATIONS["native-delivery-bridge"],
            "sha256": pair["expectedScope"]["guest"]["deliverySha256"]}}
    for name, (suffix, _) in launch.COMPONENTS.items():
        inner[name] = {"path": launch.DESTINATIONS["native-bridge-" + suffix],
            "sha256": p.sha(originals[name].encode("ascii"))}
    return p.canonical({"apiVersion": "serverware.nativePilotLaunchBundle/v1", "role": "bridge",
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
    pair = profile.keys.admitted_pair(*(pair_context[name].encode("ascii") for name in profile.PAIR_FIELDS), **clocks)
    service = _service(service_context, pair=pair, source=source, clocks=clocks)
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
