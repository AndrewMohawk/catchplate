"""Explicit adopted-cohort C9 public recipe; never a received-FD capability.

Only Config/v8 and its literal observed eleven children are accepted. The
independent signer approves complete inputs. Actual C9/kernel admission and
the retained owner still prove descriptors; this module does not create them.
"""
from __future__ import annotations

import json
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from catchplate import custody_generation_grants as g
from catchplate import native_pilot_delivery_authority as base
from catchplate import native_pilot_genesis_core_profile as core
from catchplate import native_shadow_guest_delivery as delivery

p = g.p
API = "catchplate.nativePilotDeliverySigningInput/v2"
MAX_INPUT = g.MAX_BYTES
ROLES = tuple(base.ENDPOINTS) + ("publicationReconciliation",)
CORE_FIELDS = ("coreObservationOriginal", "coreBundleOriginal")


def _original(text, maximum, *, array=False):
    p.require(type(text) is str and text.isascii() and 0 < len(text) <= maximum)
    raw = text.encode("ascii")
    if not array:
        return raw, g.document(raw, maximum)
    value = json.loads(text, object_pairs_hook=p._pairs, parse_float=p._reject, parse_constant=p._reject)
    p.require(type(value) is list and g.canonical(value) == raw)
    return raw, value


def inventory(role):
    p.require(role in ROLES)
    if role == "retrieval":
        import stat
        return base.ENDPOINTS[role] + (("publication-genesis-core", stat.S_IFREG),)
    if role == "publicationReconciliation":
        import stat
        return (("publication-reconciliation-listener", stat.S_IFSOCK),)
    return base.ENDPOINTS[role]


def require_retrieval_inventory(records, cold, observation_raw, bundle_raw):
    """The prior cold UID exception is exactly the authenticated fifth row."""
    import stat
    base._activation(records, inventory("retrieval"))
    for row, mode, uid, gid in ((records[0], stat.S_IFSOCK | 0o777, 0, 0),
            (records[1], stat.S_IFDIR | 0o555, 0, 0),
            (records[2], stat.S_IFDIR | 0o700, cold["uid"], cold["gid"]),
            (records[3], stat.S_IFREG | 0o600, cold["uid"], cold["gid"])):
        p.require(row["mode"] == mode and row["uid"] == uid and row["gid"] == gid)
    return delivery.require_adopted_core_activation(records, observation_raw, bundle_raw)


def prepare_input(raw, *, boot, now_boottime_ns, now_unix_ns=None):
    value = g.document(raw, MAX_INPUT)
    role = value.get("role")
    p.require(value.get("apiVersion") == API and role in ROLES)
    p.fields(value, base.INPUT_FIELDS + (CORE_FIELDS if role == "retrieval" else ()))
    cold_raw, _ = _original(value["configurationOriginal"], 65536)
    cold = delivery.configuration(cold_raw, p.sha(cold_raw))
    configuration_raw, _ = _original(value["ownerConfigurationOriginal"], base.cohort.MAX_BYTES)
    config = base.cohort.configuration(configuration_raw)
    p.require(config["apiVersion"] == "catchplate.nativeShadowProofCohortConfiguration/v8"
        and base.cohort.roles(config) == ROLES and config[role + "Configuration"]["sha256"] == p.sha(cold_raw)
        and g.canonical(config["authority"]) == g.canonical(cold["authority"]))
    window_raw, signed_window = _original(value["windowOriginal"], 32768)
    p.fields(signed_window, ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed_window["apiVersion"] == "catchplate.nativeShadowProofCohortPrecreation/v1")
    window = p.fields(signed_window["payload"], base.cohort.WINDOW_FIELDS)
    base.driver._key(config["authority"]).verify(p.decoded(signed_window["signatureBase64url"], size=64),
        base.cohort.PRECREATE_DOMAIN + g.canonical(window))
    base.cohort._window(window, config, p.sha(configuration_raw), boot, now_boottime_ns)
    _, observed = _original(value["observationOriginal"], base.cohort.MAX_BYTES)
    p.fields(observed, base.cohort.originals_fields(config))
    p.require(observed["apiVersion"] == "catchplate.nativeShadowProofCohortOriginals/v7"
        and observed["configurationSha256"] == p.sha(configuration_raw) and observed["precreationSha256"] == p.sha(window_raw)
        and observed["invocationId"] == window["invocationId"])
    base.cohort.external_driver_sha256(config, observed)
    processes, executables = set(), set()
    for name in ROLES:
        child = p.fields(observed[name], ("processId", "startTimeTicks", "executable"))
        pid = p.integer(child["processId"], minimum=2, maximum=(1 << 31) - 1)
        p.integer(child["startTimeTicks"], maximum=p.MAX_U64)
        exe = p.fields(child["executable"], ("device", "inode", "length", "sha256"))
        p.integer(exe["device"], minimum=0, maximum=p.MAX_U64); p.integer(exe["inode"], maximum=p.MAX_U64)
        p.integer(exe["length"], maximum=64 * 1024 * 1024)
        identity = exe["device"], exe["inode"]
        p.require(p.digest(exe["sha256"]) == config["executableSha256"] and pid not in processes and identity not in executables)
        processes.add(pid); executables.add(identity)
    runtime_raw, runtime = _original(value["runtimeOriginal"], 65536)
    p.fields(runtime, ("apiVersion", "role"))
    p.require(runtime == {"apiVersion": "catchplate.nativePilotEndpointRuntime/v1", "role": role})
    payload_raw, payload = _original(value["payloadOriginal"], delivery.MAX_DELIVERY)
    p.fields(payload, delivery.FIELDS)
    _, activation = _original(value["activationOriginal"], 32768, array=True)
    p.require(payload["configurationSha256"] == p.sha(cold_raw) and payload["authorityKeyId"] == cold["authority"]["keyId"])
    for name in ("serviceRole", "uid", "gid"):
        p.require(type(payload[name]) is type(cold[name]) and payload[name] == cold[name])
    for name in base.WINDOW_FIELDS:
        p.require(type(payload[name]) is type(window[name]) and payload[name] == window[name])
    delivery._pin(payload["runtimeConfig"])
    p.require(payload["runtimeConfig"]["sha256"] == p.sha(runtime_raw) and g.canonical(payload["activation"]) == g.canonical(activation))
    base._activation(activation, inventory(role)); base._credentials(payload["credentials"], cold["authority"])
    result = dict(role=role, cold=cold, payload=payload, window=window, observed=observed, configuration_raw=cold_raw,
        owner_configuration_raw=configuration_raw, runtime_raw=runtime_raw, payload_raw=payload_raw, guest=None)
    if role == "retrieval":
        observation_raw, _ = _original(value["coreObservationOriginal"], core.MAX_OBSERVATION)
        bundle_raw, bundle = _original(value["coreBundleOriginal"], core.MAX_BUNDLE)
        observed_core = require_retrieval_inventory(activation, cold, observation_raw, bundle_raw)
        scope = bundle["completion"]["prepared"]["core"]["genesis"]["scope"]
        p.require(tuple(scope[name] for name in ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode")) == tuple(boot)
            and p.ns(payload["lifetimeDeadlineBoottimeNs"]) <= p.ns(observed_core["deadlineBoottimeNs"]))
        wall = time.time_ns() if now_unix_ns is None else now_unix_ns
        p.require(p.ns(observed_core["issuedAtBoottimeNs"]) <= now_boottime_ns < p.ns(observed_core["deadlineBoottimeNs"])
            and observed_core["issuedAtUnixNanos"] <= wall < observed_core["expiresAtUnixNanos"])
        result.update(core_observation_raw=observation_raw, core_bundle_raw=bundle_raw, core_observation=observed_core)
    return result


def verify_delivery(input_raw, signed_raw, *, boot, now_boottime_ns, now_unix_ns=None):
    context = prepare_input(input_raw, boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    signed = p.fields(g.document(signed_raw, delivery.MAX_DELIVERY), ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed["apiVersion"] == "catchplate.policyCustodyGuestDelivery/v1"
        and g.canonical(signed["payload"]) == context["payload_raw"])
    base.driver._key(context["cold"]["authority"]).verify(p.decoded(signed["signatureBase64url"], size=64),
        delivery.DOMAIN + context["payload_raw"])
    context.update(guest=delivery.adopted_delivery_guest(signed["payload"], signed_raw), delivery_raw=signed_raw)
    return context


def sign(input_raw, key):
    from catchplate import native_shadow_nitro_originals as originals
    import os
    owner = os.getpid(), originals._start(), originals._boot()
    now, wall = originals._clock(), time.time_ns()
    context = prepare_input(input_raw, boot=owner[2], now_boottime_ns=now, now_unix_ns=wall)
    p.require(isinstance(key, Ed25519PrivateKey) and p.encoded(key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)) == context["cold"]["authority"]["publicKeyBase64url"])
    message = delivery.DOMAIN + context["payload_raw"]
    signature = key.sign(message); key.public_key().verify(signature, message)
    raw = g.canonical(dict(apiVersion="catchplate.policyCustodyGuestDelivery/v1", payload=context["payload"], signatureBase64url=p.encoded(signature)))
    p.require(owner == (os.getpid(), originals._start(), originals._boot()))
    later, epoch = originals._clock(), time.time_ns()
    p.require(now <= later and wall <= epoch)
    verify_delivery(input_raw, raw, boot=owner[2], now_boottime_ns=later, now_unix_ns=epoch)
    config = base.cohort.configuration(context["owner_configuration_raw"])
    p.require(owner == (os.getpid(), originals._start(), originals._boot()))
    final, final_epoch = originals._clock(), time.time_ns()
    p.require(later <= final and epoch <= final_epoch)
    base.cohort._window(context["window"], config, p.sha(context["owner_configuration_raw"]), owner[2], final)
    if context["role"] == "retrieval":
        p.require(final < p.ns(context["core_observation"]["deadlineBoottimeNs"])
            and final_epoch < context["core_observation"]["expiresAtUnixNanos"])
    return raw
