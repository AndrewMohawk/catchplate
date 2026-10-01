"""Selected constructed-admission candidate from retained public predecessors.

The independent continuation policy supplies verifier settings and its pinned
assignment public key. All scope, launch, C9, key, closure and exported driver
originals remain literal prior inputs/results or actual phase observations.
This pure projection neither signs nor claims a process, verifier or admission.
"""
from __future__ import annotations

import copy

from cryptography.hazmat.primitives import serialization
from serverware import native_pilot_adopted_phase_profile as profile
from serverware import native_pilot_bridge_key_profile as keys
from serverware import native_pilot_bridge_launch_profile as launch
from serverware import native_pilot_bridge_launch_publication as publication
from serverware import native_pilot_continuation_profile as continuation

p, authority = profile.p, continuation.authority
JOB = "driver-constructed"


def selection_fields(selected):
    p.require(type(selected) is profile.legacy._Job and selected is profile.BY_NAME[JOB][1])
    return ("continuationPolicy",)


def _text(raw):
    p.require(type(raw) is bytes and raw.isascii())
    return raw.decode("ascii")


def _bootstrap(prior):
    value = profile._input(prior, "driver-bootstrap")
    return {name: value[name + "Original"] for name in ("control", "configuration", "window", "deliveryConfiguration")}


def _verifier(fragment, prior, supervisor_observation, bootstrap, clocks):
    """Authenticate the explicit adopted pair before deriving verifier v3."""
    first = profile._input(prior, "native-role-keys-bridge")
    pair_context = profile._pair(prior, "bridge")
    pair = keys.admitted_adopted_pair(*(text.encode("ascii") for text in pair_context.values()), **clocks)
    p.require(first["controlOriginal"] == bootstrap["control"]
        and first["recipeOriginals"] == supervisor_observation["recipeOriginals"]
        and first["measured"] == supervisor_observation["measuredConfiguration"]
        and first["deliveryInputOriginal"].encode("ascii") == prior["native-delivery-bridge"]["input"]
        and first["deliveryOriginal"].encode("ascii") == profile._output(prior, "native-delivery-bridge"))
    delivered = keys.c9.input_document(prior["native-delivery-bridge"]["input"])
    for field, name in (("ownerConfigurationOriginal", "configuration"),
            ("configurationOriginal", "deliveryConfiguration"), ("windowOriginal", "window")):
        p.require(delivered[field] == bootstrap[name])
    settings = fragment["verifierSettings"]
    continuation.services._verifier(settings, now=clocks["now_unix_ns"])
    guest = pair["expectedScope"]["guest"]
    p.require(settings["uid"] != guest["uid"] and settings["gid"] != guest["gid"])
    operation = {name: guest[name] for name in
        ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode", "issuedAtBoottimeNs")}
    operation["deadlineBoottimeNs"] = guest["startupDeadlineBoottimeNs"]
    raw = p.canonical({"apiVersion": "serverware.nativeShadowNitroVerifierConfiguration/v3",
        **copy.deepcopy(settings), "operation": operation, **pair})
    p.require(len(raw) <= p.MAX_CONFIG)
    authority.bridge.authorization(p.document(raw, p.MAX_CONFIG), clocks["now_unix_ns"])
    _, trust = authority._original(first["recipeOriginals"]["trustOriginal"], 1024 * 1024)
    assignment_key = continuation.key_live(trust["assignmentKey"], clocks["now_unix_ns"])
    p.require(continuation._pem(fragment).public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        == assignment_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    return raw, pair_context


def _launch(prior, pair_context, supervisor_observation, bootstrap, clocks):
    """Authenticate the installed bundle and every literal issuer predecessor."""
    row = prior["install-launch-bridge"]
    value = launch.input_document(row["input"])
    p.require(value["controlOriginal"] == bootstrap["control"]
        and value["deliveryInputOriginal"].encode("ascii") == prior["native-delivery-bridge"]["input"]
        and value["deliveryOriginal"].encode("ascii") == profile._output(prior, "native-delivery-bridge")
        and value["recipeOriginals"] == supervisor_observation["recipeOriginals"]
        and value["measured"] == supervisor_observation["measuredConfiguration"])
    names = {operation: name for name, operation in profile.legacy.BRIDGE_AUTHORIZATION_JOB_INFO.items()}
    for operation, entry in value["authorizations"].items():
        name = names[operation]
        p.require(entry["inputOriginal"].encode("ascii") == prior[name]["input"]
            and entry["authorizationOriginal"].encode("ascii") == profile._output(prior, name))
    service = value["serviceContext"]
    p.require(service["inputOriginal"].encode("ascii") == prior["native-service-trustedTime"]["input"]
        and service["grantOriginal"].encode("ascii") == profile._output(prior, "native-service-trustedTime"))
    prepared = launch.prepare_input(row["input"], **clocks)
    publication.checked_bridge_result(prepared["bundleOriginal"], row["result"], pair_context=pair_context,
        service_grant_original=service["grantOriginal"].encode("ascii"), **clocks)
    return prepared


def _exported(observed, *, scope_input, scope_raw, bootstrap_raw, recipe, bundle):
    """Exact byte association only; the final issuer authenticates evidence."""
    p.fields(observed, continuation.OBSERVATION_FIELDS)
    p.require(observed["bootstrapAdmissionOriginal"].encode("ascii") == bootstrap_raw)
    _, exported = authority._original(observed["publicAdmissionOriginal"], 8 * 1024 * 1024)
    p.fields(exported, authority.admission.PUBLIC)
    p.require(exported["apiVersion"] == "serverware.nativeShadowDriverPublicAdmission/v1"
        and exported["phaseScopeOriginal"].encode("ascii") == scope_raw
        and exported["phaseBundleOriginal"] == scope_input["publicBundleOriginal"]
        and exported["bootstrapObservationOriginal"] == scope_input["observationOriginal"]
        and exported["assignmentOriginal"] == recipe["assignmentOriginal"])
    for name, component in (("closureOriginal", "closure"), ("keyConfigurationOriginal", "keys"),
            ("admissionAuthorizationOriginal", "admission")):
        p.require(exported[name] == bundle["originals"][component])


def compose(selected, selection, *, prior, observations, supervisor_observation,
            boot, now_boottime_ns, now_unix_ns):
    p.fields(selection, selection_fields(selected))
    fragment = continuation.validate_policy(selection["continuationPolicy"])
    clocks = dict(boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    observed = observations["constructed-admission"]
    p.fields(observed, continuation.OBSERVATION_FIELDS)
    bootstrap = _bootstrap(prior)
    bootstrap_raw = profile._output(prior, "driver-bootstrap")
    authority.checked_result("bootstrap", prior["driver-bootstrap"]["input"],
        {"original": _text(bootstrap_raw), "sha256": p.sha(bootstrap_raw)}, **clocks, adopted=True)
    scope_input = profile._input(prior, "driver-scope")
    scope_raw = profile._output(prior, "driver-scope")
    continuation.scope_authority.checked_result(prior["driver-scope"]["input"],
        {"original": _text(scope_raw), "sha256": p.sha(scope_raw)}, **clocks, adopted=True)
    for name in ("configuration", "window", "deliveryConfiguration"):
        p.require(scope_input[name + "Original"] == bootstrap[name])
    p.require(scope_input["bootstrapAdmissionOriginal"].encode("ascii") == bootstrap_raw
        and scope_input["observationOriginal"] == profile._input(prior, "driver-bootstrap")["observationOriginal"])
    verifier_raw, pair_context = _verifier(fragment, prior, supervisor_observation, bootstrap, clocks)
    prepared = _launch(prior, pair_context, supervisor_observation, bootstrap, clocks)
    p.require(scope_input["launchOriginal"].encode("ascii") == prepared["prepared"]["native-launch-bridge"])
    bundle = p.document(prepared["bundleOriginal"], launch.MAX_INPUT)
    _exported(observed, scope_input=scope_input, scope_raw=scope_raw, bootstrap_raw=bootstrap_raw,
        recipe=supervisor_observation["recipeOriginals"], bundle=bundle)
    value = {"apiVersion": "serverware.nativePilotDriverAuthorityInput/v1", "operation": "constructed",
        **{name + "Original": text for name, text in bootstrap.items()}, **copy.deepcopy(observed),
        "launchOriginal": scope_input["launchOriginal"], "verifierConfigurationOriginal": _text(verifier_raw),
        "verifierConfigurationSha256": p.sha(verifier_raw),
        **{name: fragment[name] for name in ("assignmentPublicKeyOriginal", "assignmentPublicKeySha256")}}
    raw = p.canonical(value)
    p.require(0 < len(raw) <= selected.maximum)
    checked = authority.prepare_input("constructed", raw, **clocks, adopted=True)
    p.require(now_boottime_ns < min(checked["deadline"], prepared["deadline"])
        and now_unix_ns < min(checked["epochLimit"], prepared["epochLimit"]))
    return raw
