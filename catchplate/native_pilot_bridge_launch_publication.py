"""Pure bridge launch joins using actual signed public originals.

The supplied pair carries the original bootstrap control, complete C9 input,
signed C9, approved recipe and measured production binding. It is verified as
data, never reconstructed as a live owner or independent approval. The caller
retains provenance and selects the complete bundle, including time settings.
No credential, runtime file, verifier service, KMS or publication is accessed.
"""
from __future__ import annotations

from catchplate import native_pilot_bridge_authority as authority
from catchplate import native_pilot_bridge_key_profile as keys
from catchplate import native_pilot_launch_publication as launch

p = launch.p


def prepare_bridge_bundle(bundle_original: bytes, *, pair_context, service_grant_original: bytes,
        boot, now_boottime_ns, now_unix_ns) -> dict:
    """Return checked fixed public bytes/pins, not installation or admission."""
    value = p.fields(p.document(bundle_original, launch.MAX_INPUT), launch.FIELDS)
    adopted = value["apiVersion"] == "catchplate.nativePilotLaunchBundle/v3"
    p.require(value["apiVersion"] in ("catchplate.nativePilotLaunchBundle/v1", "catchplate.nativePilotLaunchBundle/v3")
        and value["role"] == "bridge")
    p.fields(pair_context, authority.PAIR_FIELDS)
    raw = {name: launch.c9._original(pair_context[name],
        keys.MAX_INPUT if name.endswith("InputOriginal") else keys.MAX_OUTPUT)[0]
        for name in authority.PAIR_FIELDS}
    pair = keys.admitted_pair(*(raw[name] for name in authority.PAIR_FIELDS),
        boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns, adopted=adopted)
    contexts = [keys.prepare_input(operation, raw[name], boot=boot, now_boottime_ns=now_boottime_ns,
        now_unix_ns=now_unix_ns) for operation, name in (("role-keys", "roleKeyInputOriginal"), ("admission", "admissionInputOriginal"))]
    first = p.document(raw["roleKeyInputOriginal"], keys.MAX_INPUT)
    delivered_raw, _ = launch.c9._original(first["deliveryInputOriginal"], launch.c9.MAX_BRIDGE_INPUT)
    delivered = launch.c9.input_document(delivered_raw)
    delivery_raw, signed = launch.c9._original(first["deliveryOriginal"], launch.delivery.MAX_DELIVERY)
    config_raw, config = launch.c9._original(delivered["ownerConfigurationOriginal"], 65536)
    window_raw, signed_window = launch.c9._original(delivered["windowOriginal"], 32768)
    _, observed = launch.c9._original(delivered["observationOriginal"], 65536)
    cold_raw, _ = launch.c9._original(delivered["configurationOriginal"], 65536)
    runtime_raw, _ = launch.bridge_runtime.original(delivered["runtimeOriginal"])
    window = signed_window["payload"]  # Authenticated by admitted_pair's actual C9/control join.
    launch.c9.window_at(window, boot=boot, now=now_boottime_ns)
    p.require(p.digest(value["ownerConfigurationSha256"]) == p.sha(config_raw)
        and p.digest(value["windowSha256"]) == p.sha(window_raw))
    for name in ("observationOriginal", "runtimeOriginal"):
        p.require(value[name] == delivered[name])
    inner = value["keyAdmission"]
    launch._inner(inner, "bridge")
    launch.c9._same(inner["deliveryConfiguration"], config["deliveryConfiguration"])
    p.require(inner["deliveryConfiguration"]["sha256"] == p.sha(cold_raw))
    launch.c9._same(inner["delivery"], {
        "path": launch.publication.DESTINATIONS["native-delivery-bridge"], "sha256": p.sha(delivery_raw)})

    # Signed but unrelated public originals are not interchangeable. In
    # particular the bridge admission must carry the rederived production
    # binding, not merely a valid supervisor signature over a supplied digest.
    originals = p.fields(value["originals"], launch.COMPONENTS)
    recipe = first["recipeOriginals"]
    for name in ("trust", "assignment"):
        p.require(originals[name] == recipe[name + "Original"])
    p.require(originals["keys"] == p.canonical({"apiVersion": "catchplate.nativeShadowRoleKeys/v2",
        "authorization": pair["authorization"]}).decode("ascii"))
    p.require(originals["admission"] == raw["admissionOriginal"].decode("ascii"))
    closure_raw, _ = launch.c9._original(originals["closure"], launch.COMPONENTS["closure"][1])
    closure = (launch.shape_adopted_bridge if adopted else launch.shape)("native-bridge-closure", closure_raw)
    p.require(closure["apiVersion"] == ("catchplate.nativeCustodyClosure/v5" if adopted else "catchplate.nativeCustodyClosure/v3")
        and p.canonical(closure["closureSet"]).decode("ascii") == recipe["closureSetOriginal"])
    prepared, pins, expiry = launch._prepare_public(value, payload=signed["payload"],
        guest=pair["expectedScope"]["guest"], runtime_raw=runtime_raw, grant_raw=service_grant_original,
        companion_raw=None, observed=observed, config=config, now=now_unix_ns, adopted_bridge=adopted)
    expiry = min(expiry, *(context["epochLimit"] for context in contexts))
    p.require(now_unix_ns < expiry)
    return {"role": "bridge", "window": window, "deadline": p.ns(window["startupDeadlineBoottimeNs"]),
        "epochLimit": expiry, "prepared": prepared, "pins": pins, "launch": pins["native-launch-bridge"]}


def checked_bridge_result(bundle_original: bytes, result, *, pair_context, service_grant_original: bytes,
        boot, now_boottime_ns, now_unix_ns) -> dict:
    """Check the exact reported result; actual publication provenance is external."""
    context = prepare_bridge_bundle(bundle_original, pair_context=pair_context,
        service_grant_original=service_grant_original, boot=boot,
        now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    expected = launch._installation_result("bridge", p.sha(bundle_original), context["window"], context["pins"])
    if p.document(bundle_original, launch.MAX_INPUT)["apiVersion"] == "catchplate.nativePilotLaunchBundle/v3":
        expected["apiVersion"] = "catchplate.nativePilotLaunchInstallation/v3"
    p.fields(result, tuple(expected))
    launch.c9._same(result, expected)
    return p.document(p.canonical(result), 32768)
