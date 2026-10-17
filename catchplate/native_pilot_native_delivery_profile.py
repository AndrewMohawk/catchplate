"""Pure C9 inputs for the seven remaining source-fixed native endpoints.

The retained supervisor supplies independently admitted policy and the actual
earlier originals, observations, boot identity and clock samples. This module
authenticates their public bindings, not kernel provenance or approval. It
never creates resources, signs, publishes, opens credentials or renews time.
The earlier three-role endpoint-delivery policy remains a separate contract.
"""
from __future__ import annotations

import copy

from catchplate import native_pilot_assignment as assignments
from catchplate import native_pilot_closure_set as closure_set
from catchplate import native_pilot_delivery_authority as c9
from catchplate import native_pilot_launch_publication as launch
from catchplate import native_pilot_measured_configuration as measured_profile
from catchplate import native_pilot_publication as publication
from catchplate import native_pilot_scope_authority as scope
from catchplate import native_shadow_driver_bootstrap as driver
from catchplate import native_shadow_guest_delivery as delivery
from catchplate import native_shadow_proof_cohort_assignment as cohort
from catchplate import native_shadow_retrieval_artifacts as retrieval

p = delivery.p
ROLES = ("generationInstall", "commitRequest", "ingressAdmission", "terminalAppend",
    "dispatchBarrier", "activeEffectBarrier", "activeEffectCommit")
FIELDS = ("runtimeOriginal", "runtimeConfig", "credentials")
MAX_POLICY = 1024 * 1024
RECIPE_FIELDS = ("assignmentOriginal", "trustOriginal", "trustSha256", "closureSetOriginal")
MEASURED_FIELDS = ("apiVersion", "recipeSha256", "configurationBindingOriginal",
    "configurationBindingSha256", "proofScopeOriginal", "production")


def _row(role, value, cold):
    p.require(role in ROLES)
    p.fields(value, FIELDS)
    raw, _ = scope._original(value["runtimeOriginal"], 65536)
    purpose = "native-runtime-" + role
    launch.shape(purpose, raw)
    delivery._pin(value["runtimeConfig"])
    c9._same(value["runtimeConfig"], {"path": publication.DESTINATIONS[purpose], "sha256": p.sha(raw)})
    c9._credentials(value["credentials"], cold["authority"])
    return raw


def validate_policy(fragment, *, native_cold_originals) -> dict:
    """Closed seven-role policy; no credential read or authority from metadata."""
    p.fields(fragment, ROLES)
    p.fields(native_cold_originals, cohort.ENDPOINT_ROLES)
    for role in ROLES:
        raw, _ = scope._original(native_cold_originals[role], 65536)
        cold = delivery.configuration(raw, p.sha(raw))
        _row(role, fragment[role], cold)
    p.require(len(p.canonical(fragment)) <= MAX_POLICY)
    return copy.deepcopy(fragment)


def require_runtime_bindings(role, *, runtime_raw, measured, recipe_originals, now_unix_ns):
    """Authenticate a role leaf under the independently pinned recipe trust.

    Callers obtain these exact originals and the measured result from their
    retained recipe owner. Supplied dictionaries alone cannot establish that
    association or authorize the independent trust pin selected here.
    """
    p.require(role in ROLES)
    launch.shape("native-runtime-" + role, runtime_raw)
    p.fields(recipe_originals, RECIPE_FIELDS); p.fields(measured, MEASURED_FIELDS)
    p.require(measured["apiVersion"] == "catchplate.nativePilotMeasuredConfiguration/v2")
    p.digest(measured["recipeSha256"]); p.integer(now_unix_ns)
    recipe = {"apiVersion": "catchplate.nativePilotMeasuredConfigurationRecipe/v2", **recipe_originals}
    envelope, _, key_root = measured_profile._assignment(recipe, now_unix_ns)
    assignment = envelope["payload"]
    text = recipe_originals["closureSetOriginal"]
    p.require(type(text) is str and text.isascii() and 0 < len(text) <= closure_set.MAX_BYTES)
    set_raw = text.encode("ascii")
    member = assignments.closure_binding(envelope, set_raw, role)
    selected = closure_set.validate(set_raw)
    manifest = selected["members"][closure_set.ROLES.index(role)]["manifest"]
    p.require(manifest["manifestSha256"] == member["manifestSha256"]
        and manifest["runtimeConfigurationSha256"] == p.sha(runtime_raw))

    proof_raw, _ = scope._original(measured["proofScopeOriginal"], 16384)
    proof = retrieval.scope_original(proof_raw)
    retrieval.require_assignment_scope(proof, p.canonical(assignment))
    binding_raw, binding = scope._original(measured["configurationBindingOriginal"], 65536)
    p.require(p.framed(b"catchplate.policyShadowProductionCustodyConfiguration/v2", (binding_raw,))
        == measured["configurationBindingSha256"] == proof["production_configuration_binding_sha256"]
        and binding["assignmentId"] == assignment["assignmentId"]
        and binding["assignmentPayloadSha256"] == envelope["payloadSha256"]
        and binding["assignmentRevision"] == assignment["assignmentRevision"]
        and binding["assertedCustodyKeySetRootSha256"] == key_root
        and binding["nativeClosureSet"] == assignment["nativeClosureSet"]
        and binding["executionClosureManifestSha256"] == proof["execution_closure_manifest_sha256"]
        and binding["structurallyVerifiedSeccompPolicySha256"] == proof["structurally_verified_seccomp_policy_sha256"])
    production = p.fields(measured["production"], scope.PRODUCTION_FIELDS)
    measured_profile._production({name: production[name] for name in measured_profile.PRODUCTION_FIELDS})
    p.require(production["expectedConfigurationBindingSha256"] == measured["configurationBindingSha256"])
    for name in measured_profile.PRODUCTION_FIELDS:
        c9._same(binding[name], production[name])


def _context(role, configuration_raw, owner_configuration_raw, window_raw, observation_raw, *, boot, now):
    p.require(role in ROLES)
    cold = delivery.configuration(configuration_raw, p.sha(configuration_raw))
    signed = p.document(window_raw, 32768)
    observed = p.document(observation_raw, cohort.MAX_BYTES)
    window = c9.endpoint_owner(role, cold, configuration_raw, owner_configuration_raw,
        window_raw, signed, observed, boot=boot, now=now)
    config = cohort.configuration(owner_configuration_raw)
    c9._same(config[role + "Configuration"],
        {"path": publication.DESTINATIONS["native-cold-" + role], "sha256": p.sha(configuration_raw)})
    return cold, window


def _payload(cold, configuration_raw, window, selected, activation, role):
    c9._activation(activation, c9.ENDPOINTS[role])
    value = {"configurationSha256": p.sha(configuration_raw), "authorityKeyId": cold["authority"]["keyId"],
        **{name: cold[name] for name in ("serviceRole", "uid", "gid")},
        **{name: window[name] for name in c9.WINDOW_FIELDS},
        "runtimeConfig": selected["runtimeConfig"], "credentials": selected["credentials"], "activation": activation}
    p.fields(value, delivery.FIELDS)
    raw = p.canonical(value)
    p.require(len(raw) <= delivery.MAX_DELIVERY)
    return raw


def build(role, *, fragment, configuration_raw, owner_configuration_raw, window_raw, observation_raw,
          activation, measured, recipe_originals, boot, now_boottime_ns, now_unix_ns) -> bytes:
    """Compose one existing input9 from complete approved and actual originals."""
    p.require(role in ROLES)
    p.fields(fragment, ROLES)
    cold, window = _context(role, configuration_raw, owner_configuration_raw, window_raw,
        observation_raw, boot=boot, now=now_boottime_ns)
    selected = fragment[role]
    runtime_raw = _row(role, selected, cold)
    require_runtime_bindings(role, runtime_raw=runtime_raw, measured=measured,
        recipe_originals=recipe_originals, now_unix_ns=now_unix_ns)
    payload_raw = _payload(cold, configuration_raw, window, selected, activation, role)
    activation_raw = p.canonical(activation)
    p.require(len(activation_raw) <= 32768)
    value = {"apiVersion": "catchplate.nativePilotDeliverySigningInput/v1", "role": role,
        "configurationOriginal": configuration_raw.decode("ascii"),
        "ownerConfigurationOriginal": owner_configuration_raw.decode("ascii"),
        "windowOriginal": window_raw.decode("ascii"), "observationOriginal": observation_raw.decode("ascii"),
        "runtimeOriginal": runtime_raw.decode("ascii"), "payloadOriginal": payload_raw.decode("ascii"),
        "activationOriginal": activation_raw.decode("ascii")}
    p.fields(value, c9.INPUT_FIELDS)
    raw = p.canonical(value)
    p.require(len(raw) <= c9.MAX_INPUT)
    return raw


def checked_result(role, input_raw, result) -> bytes:
    """Verify the exact prior input and fixed C9 output, not current ownership.

    The caller rechecks its real owners and original clock window around this
    pure check. Using the signed original's issued time here is only a static
    consistency check; it does not establish currentness or renew any deadline.
    """
    p.require(role in ROLES)
    value = p.fields(p.document(input_raw, c9.MAX_INPUT), c9.INPUT_FIELDS)
    p.require(value["apiVersion"] == "catchplate.nativePilotDeliverySigningInput/v1" and value["role"] == role)
    cold_raw, _ = scope._original(value["configurationOriginal"], 65536)
    config_raw, _ = scope._original(value["ownerConfigurationOriginal"], cohort.MAX_BYTES)
    window_raw, signed_window = scope._original(value["windowOriginal"], 32768)
    observation_raw, _ = scope._original(value["observationOriginal"], cohort.MAX_BYTES)
    window = p.fields(signed_window["payload"], cohort.WINDOW_FIELDS)
    boot = tuple(window[name] for name in c9.WINDOW_FIELDS[:3])
    cold, window = _context(role, cold_raw, config_raw, window_raw, observation_raw,
        boot=boot, now=p.ns(window["issuedAtBoottimeNs"]))
    payload_raw, payload = scope._original(value["payloadOriginal"], delivery.MAX_DELIVERY)
    p.fields(payload, delivery.FIELDS)
    selected = {"runtimeOriginal": value["runtimeOriginal"],
        "runtimeConfig": payload["runtimeConfig"], "credentials": payload["credentials"]}
    _row(role, selected, cold)
    _, activation = c9._original(value["activationOriginal"], 32768, array=True)
    p.require(payload_raw == _payload(cold, cold_raw, window, selected, activation, role))
    p.fields(result, ("original", "sha256", "pin"))
    raw, signed = scope._original(result["original"], delivery.MAX_DELIVERY)
    p.require(p.sha(raw) == p.digest(result["sha256"]))
    c9._same(result["pin"], {"path": publication.DESTINATIONS["native-delivery-" + role], "sha256": p.sha(raw)})
    p.fields(signed, ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed["apiVersion"] == "catchplate.policyCustodyGuestDelivery/v1"
        and p.canonical(signed["payload"]) == payload_raw)
    driver._key(cold["authority"]).verify(p.decoded(signed["signatureBase64url"], size=64), delivery.DOMAIN + payload_raw)
    delivery._delivery_guest(signed["payload"], raw)
    return raw


def build_adopted(role, *, configuration_raw, owner_configuration_raw, window_raw, observation_raw,
                  runtime_raw, payload_raw, activation, boot, now_boottime_ns, now_unix_ns,
                  core_observation_raw=None, core_bundle_raw=None):
    """Complete independently approved v8 input; no legacy profile widening."""
    from catchplate import custody_generation_grants as g
    from catchplate import native_pilot_adopted_delivery as adopted
    p.require(role in adopted.ROLES and (core_observation_raw is not None) == (role == "retrieval")
        and (core_bundle_raw is not None) == (role == "retrieval"))
    value = dict(apiVersion=adopted.API, role=role, configurationOriginal=configuration_raw.decode("ascii"),
        ownerConfigurationOriginal=owner_configuration_raw.decode("ascii"), windowOriginal=window_raw.decode("ascii"),
        observationOriginal=observation_raw.decode("ascii"), runtimeOriginal=runtime_raw.decode("ascii"),
        payloadOriginal=payload_raw.decode("ascii"), activationOriginal=g.canonical(activation).decode("ascii"))
    if role == "retrieval":
        value.update(coreObservationOriginal=core_observation_raw.decode("ascii"), coreBundleOriginal=core_bundle_raw.decode("ascii"))
    raw = g.canonical(value)
    adopted.prepare_input(raw, boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    return raw


def checked_adopted_result(input_raw, signed_original, *, boot, now_boottime_ns, now_unix_ns):
    return c9.verify_adopted_delivery(input_raw, signed_original, boot=boot,
        now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
