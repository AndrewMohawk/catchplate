"""Complete bridge C9 metadata from the actual retained runtime installation.

This pure layer binds approved metadata to literal public history bytes,
authenticated assignment keys and original bootstrap ciphertext transport.
It never reads or provisions a credential. The previous genuine owner supplies
authenticated histories/runtime and installation provenance; native admission
still reads and verifies the actual independently provisioned credentials.
"""
from __future__ import annotations

import copy
import os
import stat

from serverware import custody_generation_grants as generation
from serverware import native_pilot_assignment as assignment
from serverware import native_pilot_bridge_commissioning_policy as policy
from serverware import native_pilot_bridge_install as install
from serverware import native_pilot_bridge_runtime as runtime_profile
from serverware import native_pilot_bridge_runtime_profile as runtime_builder
from serverware import native_pilot_closure_authority as closure
from serverware import native_pilot_closure_set as closure_set
from serverware import native_pilot_delivery_authority as c9
from serverware import native_pilot_measured_configuration as measured_profile
from serverware import native_pilot_native_delivery_profile as native
from serverware import native_pilot_publication as publication
from serverware import native_pilot_scope_authority as scope
from serverware import native_shadow_driver_bootstrap as driver
from serverware import native_shadow_driver_outgoing as outgoing
from serverware import native_shadow_guest_delivery as delivery

p = c9.p
MAX_INPUT = c9.MAX_BRIDGE_INPUT
AUTHORITY_KEY_ROLES = {role: "custody-" + role for role in outgoing._SIGNERS} | {
    "retrieval": "custody-retrieval-response", "persistence": "custody-store-response",
    "trusted-time": "custody-trusted-time-response", "generation-install-envelope": "custody-result-envelope"}


def _same(first, second):
    p.require(generation.canonical(first) == generation.canonical(second))


def _installed(bundle_raw, result, bootstrap, *, boot, now, adopted=False):
    bundle = p.fields(p.document(bundle_raw, install.MAX_BRIDGE_INPUT), install.FIELDS)
    p.require(type(adopted) is bool and bundle["apiVersion"] == (runtime_builder.ADOPTED_API if adopted else runtime_builder.API)
        and bundle["driverControlSha256"] == p.sha(bootstrap["control"]))
    observation_raw, _ = c9._original(bundle["driverObservationOriginal"], 65536)
    config, cold, window, observed = runtime_builder._bootstrap(bootstrap, observation_raw, boot=boot, now=now)
    raw, runtime = runtime_profile.original(bundle["runtimeOriginal"])
    p.require(runtime_profile.version(runtime) in ((14,) if adopted else (11, 12)))
    install.shape("bridge-runtime", raw)
    selected_raw, _ = c9._original(bundle["outgoingOriginal"], 8192)
    selected = install.shape("bridge-outgoing", selected_raw)
    _same(selected, {"apiVersion": "serverware.nativeShadowDriverOutgoingInputs/v1",
        "driverConfigurationSha256": p.sha(bootstrap["configuration"]),
        "driverWindowSha256": p.sha(bootstrap["window"]), "driverObservationSha256": p.sha(observation_raw),
        "invocationId": window["invocationId"], "deliveryConfiguration": config["deliveryConfiguration"],
        "runtime": {"path": install.RUNTIME_DESTINATION, "sha256": p.sha(raw)},
        "bridgeLaunchVersion": runtime_profile.launch_for_runtime(raw)})
    expected = {"apiVersion": "serverware.nativePilotBridgeRuntimeInstallation/v2" if adopted else "serverware.nativePilotBridgeRuntimeInstallation/v1",
        "bundleSha256": p.sha(bundle_raw), "configurationSha256": p.sha(bootstrap["configuration"]),
        "windowSha256": p.sha(bootstrap["window"]), "observationSha256": p.sha(observation_raw),
        "invocationId": window["invocationId"], "startupDeadlineBoottimeNs": window["startupDeadlineBoottimeNs"],
        "lifetimeDeadlineBoottimeNs": window["lifetimeDeadlineBoottimeNs"],
        "pins": {purpose: {"path": publication.DESTINATIONS[purpose], "sha256": p.sha(value)}
            for purpose, value in (("bridge-runtime", raw), ("bridge-outgoing", selected_raw))}}
    p.fields(result, tuple(expected)); _same(result, expected)
    return config, cold, window, observed, observation_raw, raw, runtime


def _assignment(recipe, measured, config, observed, window, now, *, adopted=False):
    p.fields(recipe, native.RECIPE_FIELDS); p.fields(measured, native.MEASURED_FIELDS)
    envelope, bindings, key_root = measured_profile._assignment(
        {"apiVersion": measured_profile.ADOPTED_API if adopted else measured_profile.SET_API, **recipe}, now)
    p.require(assignment.version(envelope) == 2)
    set_raw, _ = c9._original(recipe["closureSetOriginal"], closure_set.MAX_BYTES)
    set_api = closure_set.PUBLICATION_API if adopted else closure_set.API
    assignment.closure_binding(envelope, set_raw, "bridge", set_api_version=set_api)
    manifest = closure_set.validate(set_raw, api_version=set_api)["members"][-1]["manifest"]
    closure._manifest({"manifestOriginal": p.canonical(manifest).decode("ascii")},
        config, observed, envelope["payload"])
    production = p.fields(measured["production"], scope.PRODUCTION_FIELDS)
    derived = measured_profile.derive_configuration(envelope=envelope, keys=bindings, key_root=key_root,
        manifest=manifest, observed=observed, production={name: production[name]
            for name in measured_profile.PRODUCTION_FIELDS}, window=window,
        recipe_sha=measured["recipeSha256"], successor=True)
    _same(derived, measured)
    _, trust = c9._original(recipe["trustOriginal"], 1024 * 1024)
    public = {row["role"]: row["key"] for row in trust["roleKeys"]}
    keys = {role: bindings[role] | {"publicKeyBase64url": public[role]["publicKeyBase64url"]} for role in p.ROLES}
    for value in keys.values():
        p.public_key(value)
    expiry = min(trust["expiresAtUnixNanos"], envelope["payload"]["expiresAtUnixNanos"],
        trust["checkpoint"]["asOfUnixNanos"] + 300_000_000_000,
        *(value["notAfterUnixNanos"] for value in (trust["assignmentKey"], trust["timeKey"], *public.values())))
    p.require(now < expiry)
    return keys, expiry


def _metadata(credentials, runtime, history_originals, keys):
    """Exact public-file byte pins; supplied data alone is not provenance."""
    rows = {row["name"]: row for row in credentials}
    p.fields(history_originals, generation.ROLES)
    names, seen = {policy.CIPHERTEXT}, set()
    for item in runtime["histories"]:
        role, name = item["serviceRole"], item["manifestCredential"]
        p.require(role in history_originals and role not in seen and name not in names and name in rows)
        names.add(name); seen.add(role)
        raw = history_originals[role]
        p.require(type(raw) is bytes and 0 < len(raw) <= generation.MAX_BYTES)
        generation.document(raw, generation.MAX_BYTES)
        if runtime_profile.version(runtime) in (12, 14):
            p.require(runtime["ordinaryInitialHistories"][role]["historyOriginal"].encode("ascii") == raw)
        row = rows[name]
        p.require(row["original"]["sha256"] == p.sha(raw) and row["length"] == len(raw) and row["signing"] is None)
    p.require(seen == set(generation.ROLES))
    for discriminator, endpoints in (("signerRole", runtime["parentSignerEndpoints"]),
            ("endpointKind", runtime["proofEndpoints"])):
        for endpoint in endpoints:
            name = endpoint["authorityBindingCredential"]
            p.require(name not in names and name in rows)
            names.add(name)
            key = keys[AUTHORITY_KEY_ROLES[endpoint[discriminator]]]
            p.public_key(key)
            p.require(endpoint["authorityKeyId"] == key["keyId"]
                and endpoint["authorityKeySpkiSha256"] == key["keySpkiSha256"])
            public = p.decoded(key["publicKeyBase64url"], size=32)
            row = rows[name]
            p.require(row["length"] == 32 and row["original"]["sha256"] == p.sha(public) and row["signing"] is None)
    p.require(len(names) == 20 and set(rows) == names)


def prepare(*, fragment, runtime_bundle_raw, runtime_result, bootstrap_originals, activation,
            recipe_originals, measured, history_originals, boot, now_boottime_ns, now_unix_ns):
    runtime_builder._size((fragment, runtime_bundle_raw, runtime_result, bootstrap_originals, activation,
        recipe_originals, measured, history_originals))
    p.fields(fragment, policy.FIELDS)
    adopted = fragment["apiVersion"] == policy.ADOPTED_API
    config, cold, window, observed, observation_raw, runtime_raw, runtime = _installed(
        runtime_bundle_raw, runtime_result, bootstrap_originals, boot=boot, now=now_boottime_ns, adopted=adopted)
    selected = policy.validate_policy(fragment, bootstrap_configuration=config,
        cold_original=bootstrap_originals["deliveryConfiguration"])
    keys, expiry = _assignment(recipe_originals, measured, config, observed, window, now_unix_ns, adopted=adopted)
    _metadata(selected["deliveryCredentials"], runtime, history_originals, keys)
    expected, _ = c9._bridge_inventory(runtime_raw, cold, adopted=adopted)
    c9._activation(activation, expected)
    journal = next(row for row in activation if row["name"] == "production-journal")
    identity = runtime["journalDirectoryIdentity"]
    _same({name: identity[name] for name in ("inode", "uid", "gid", "mode")},
        {name: journal[name] for name in ("inode", "uid", "gid", "mode")})
    _same([identity["deviceMajor"], identity["deviceMinor"]],
        [os.major(journal["device"]), os.minor(journal["device"])])
    p.require(stat.S_IMODE(journal["mode"]) == 0o700
        and (journal["uid"], journal["gid"]) == (cold["uid"], cold["gid"]))
    payload = {"configurationSha256": p.sha(bootstrap_originals["deliveryConfiguration"]),
        "authorityKeyId": cold["authority"]["keyId"], **{name: cold[name] for name in ("serviceRole", "uid", "gid")},
        **{name: window[name] for name in c9.WINDOW_FIELDS},
        "runtimeConfig": runtime_result["pins"]["bridge-runtime"],
        "credentials": selected["deliveryCredentials"], "activation": copy.deepcopy(activation)}
    p.fields(payload, delivery.FIELDS)
    payload_raw, activation_raw = p.canonical(payload), p.canonical(activation)
    p.require(len(payload_raw) <= delivery.MAX_DELIVERY and len(activation_raw) <= 32768)
    value = {"apiVersion": "serverware.nativePilotDeliverySigningInput/v3" if adopted else "serverware.nativePilotDeliverySigningInput/v1", "role": "bridge",
        "configurationOriginal": bootstrap_originals["deliveryConfiguration"].decode("ascii"),
        "ownerConfigurationOriginal": bootstrap_originals["configuration"].decode("ascii"),
        "windowOriginal": bootstrap_originals["window"].decode("ascii"),
        "observationOriginal": observation_raw.decode("ascii"), "runtimeOriginal": runtime_raw.decode("ascii"),
        "payloadOriginal": payload_raw.decode("ascii"), "activationOriginal": activation_raw.decode("ascii")}
    raw = p.canonical(value)
    c9.input_document(raw)
    return {"inputOriginal": raw, "window": copy.deepcopy(window),
        "deadline": p.ns(window["startupDeadlineBoottimeNs"]), "epochLimit": expiry}


def build(**kwargs):
    return prepare(**kwargs)["inputOriginal"]


def checked_result(input_raw, result, **kwargs):
    prepared = prepare(**kwargs)
    p.require(type(input_raw) is bytes and input_raw == prepared["inputOriginal"])
    value = c9.input_document(input_raw)
    payload_raw, _ = c9._original(value["payloadOriginal"], delivery.MAX_DELIVERY)
    cold_raw = kwargs["bootstrap_originals"]["deliveryConfiguration"]
    cold = delivery.configuration(cold_raw, p.sha(cold_raw))
    p.fields(result, ("original", "sha256", "pin"))
    raw, signed = c9._original(result["original"], delivery.MAX_DELIVERY)
    p.fields(signed, ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed["apiVersion"] == "serverware.policyCustodyGuestDelivery/v1"
        and p.sha(raw) == p.digest(result["sha256"]) and p.canonical(signed["payload"]) == payload_raw)
    _same(result["pin"], {"path": publication.DESTINATIONS["native-delivery-bridge"], "sha256": p.sha(raw)})
    driver._key(cold["authority"]).verify(p.decoded(signed["signatureBase64url"], size=64), delivery.DOMAIN + payload_raw)
    delivery._delivery_guest(signed["payload"], raw)
    return raw


def prepare_signing_input(input_raw, *, boot, now_boottime_ns):
    """Full public C9Input3 checks before the fixed C9 key can be read.

    This is the C9 authority's original contract, not measured assignment or
    runtime-business admission. Those require the subsequent bridge issuers.
    """
    value = c9.input_document(input_raw)
    p.require(value["apiVersion"] == "serverware.nativePilotDeliverySigningInput/v3" and value["role"] == "bridge")
    cold_raw, _ = c9._original(value["configurationOriginal"], 65536)
    cold = delivery.configuration(cold_raw, p.sha(cold_raw))
    config_raw, _ = c9._original(value["ownerConfigurationOriginal"], 65536)
    window_raw, signed_window = c9._original(value["windowOriginal"], 32768)
    _, observed = c9._original(value["observationOriginal"], 65536)
    runtime_raw, runtime = runtime_profile.original(value["runtimeOriginal"])
    payload_raw, payload = c9._original(value["payloadOriginal"], delivery.MAX_DELIVERY)
    _, activation = c9._original(value["activationOriginal"], 32768, array=True)
    p.fields(payload, delivery.FIELDS)
    window = c9.bridge_owner(cold, cold_raw, config_raw, window_raw, signed_window, observed,
        boot=boot, now=now_boottime_ns)
    expected, _ = c9._bridge_inventory(runtime_raw, cold, adopted=True)
    p.require(payload["configurationSha256"] == p.sha(cold_raw)
        and payload["authorityKeyId"] == cold["authority"]["keyId"])
    for name in ("serviceRole", "uid", "gid"): _same(payload[name], cold[name])
    for name in c9.WINDOW_FIELDS: _same(payload[name], window[name])
    _same(payload["runtimeConfig"], {"path": install.RUNTIME_DESTINATION, "sha256": p.sha(runtime_raw)})
    _same(payload["activation"], activation)
    c9._activation(activation, expected); c9._credentials(payload["credentials"], cold["authority"])
    journal = next(row for row in activation if row["name"] == "production-journal")
    identity = p.fields(runtime["journalDirectoryIdentity"],
        ("mountId", "deviceMajor", "deviceMinor", "inode", "uid", "gid", "mode"))
    p.integer(identity["mountId"], maximum=p.MAX_U64)
    _same({name: identity[name] for name in ("inode", "uid", "gid", "mode")},
        {name: journal[name] for name in ("inode", "uid", "gid", "mode")})
    _same([identity["deviceMajor"], identity["deviceMinor"]], [os.major(journal["device"]), os.minor(journal["device"])])
    p.require(stat.S_IMODE(journal["mode"]) == 0o700 and (journal["uid"], journal["gid"]) == (cold["uid"], cold["gid"]))
    p.require(payload_raw == p.canonical(payload))  # Native signed-i64 codec before key access.
    return {"window": window, "deadline": p.ns(window["startupDeadlineBoottimeNs"]), "epochLimit": None}
