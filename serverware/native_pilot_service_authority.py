"""Independent fixed-five service authoring from complete approved originals.

No GenerationInputs, descriptor owner, history, peer or authority is invented.
The operator approves the complete input and supplies an existing matching key.
Delivery/generation/dispatch use their existing byte producers. Head/Cleanup/
Current reproduce the existing public joins without calling a live memfd writer.
Full history currentness, native admission and real resource identity remain
with the receiving services; a checked public bundle is not a live owner.
"""
from __future__ import annotations

import re
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from serverware import custody_generation_grants as g
from serverware import custody_commitment_inputs as commitment
from serverware import custody_spool_inputs as spool
from serverware import native_shadow_commitment_artifacts as dispatch
from serverware import native_shadow_spool_artifacts as artifacts
from serverware import native_shadow_nitro_originals as originals
from serverware import native_shadow_retrieval_artifacts as retrieval
from serverware.native_shadow_time_profile import key_live

p = g.p
MAX_INPUT_BYTES = 32 * 1024 * 1024
OPERATIONS = ("delivery", "generation", "dispatch", "head", "cleanup", "current")
ROLES = g.ROLES
HEAD_FIELDS = spool.HEAD + ("completion", "effects")
CLEANUP_FIELDS = CURRENT_FIELDS = spool.CURRENT
_COMMON = ("apiVersion", "operation", "serviceRole", "launchOriginal", "payloadOriginal")
_SERVICE = ("configurationOriginal", "configurationSha256", "deliveryOriginal", "runtimeOriginal", "historyOriginal")
_DRS, _CLEANUP, _, _CURRENT, _ = ROLES
_SPOOL = {
    "head": (_DRS, "nativeSpoolHeadGrant", "3", "native-shared-spool-head", "spoolHead", "spool-head", HEAD_FIELDS),
    "cleanup": (_CLEANUP, "nativeActiveEffectCleanupGrant", "1", "native-active-effect-cleanup", "spoolCleanup", "active-effect-cleanup", CLEANUP_FIELDS),
    "current": (_CURRENT, "nativeSpoolCurrentGrant", "3", "native-spool-current-signature", "spoolCurrent", "spool-current", CURRENT_FIELDS),
}


def _original(value, maximum):
    p.require(type(value) is str and value.isascii())
    raw = value.encode("ascii")
    g.document(raw, maximum)
    return raw


def _public(key):
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _flags(role):
    effects = role in spool.EFFECT_ROLES
    return dict(commitment=role in commitment.ROLES, spool=effects, effects=effects)


def _launch(raw, boot, now):
    value = p.fields(g.document(raw, 65536), ("apiVersion", "bootIdBase64url", "timeNamespaceDevice",
        "timeNamespaceInode", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId", "services"))
    p.require(value["apiVersion"] == "serverware.custodyFiveServiceLaunch/v6"
        and (value["bootIdBase64url"], value["timeNamespaceDevice"], value["timeNamespaceInode"]) == boot
        and type(value["invocationId"]) is str and re.fullmatch(r"[0-9a-f]{32}", value["invocationId"])
        and value["invocationId"] != "0" * 32)
    startup, lifetime = p.ns(value["startupDeadlineBoottimeNs"]), p.ns(value["lifetimeDeadlineBoottimeNs"])
    p.require(now < startup <= lifetime and startup - now <= 30_000_000_000)
    for spec in p.fields(value["services"], ROLES).values():
        p.fields(spec, ("executableSha256", "deliveryConfiguration"))
        p.digest(spec["executableSha256"])
        g.c9._pin(spec["deliveryConfiguration"])
    return value, startup, lifetime


def _cold(value, role, launch):
    raw = _original(value["configurationOriginal"], 65536)
    digest = p.digest(value["configurationSha256"])
    p.require(digest == launch["services"][role]["deliveryConfiguration"]["sha256"])
    return raw, digest, g.configuration(raw, digest, role)


def _runtime(raw, role):
    header = g.document(raw, g.MAX_BYTES)["runtime"]
    effects = role in spool.EFFECT_ROLES
    p.require(header["apiVersion"] == "serverware.policyCustodyServiceRuntimeConfig/v" + ("8" if effects else "5")
        and header["generationAdmission"] == {"grantFdName": "generation-grant"}
        and (header.get("dispatchAdmission") == {"grantFdName": "dispatch-grant"}
             if role in commitment.ROLES else header.get("dispatchAdmission") is None))
    expected = {_DRS: ("spoolHead", "spool-head"), _CLEANUP: ("spoolCleanup", "active-effect-cleanup"),
                _CURRENT: ("spoolCurrent", "spool-current")}.get(role)
    for field in ("spoolHead", "spoolCleanup", "spoolCurrent"):
        p.require(header.get(field) == ({"grantFdName": expected[1] + "-grant"}
                  if expected is not None and field == expected[0] else None))
        if effects and field != expected[0]:
            p.require(field not in header)
    return header


def _service(value, role, launch, boot, startup, lifetime, now, *, granted):
    p.fields(value, _SERVICE + (("generationGrantOriginal",) if granted else ()))
    cold_raw, cold_sha, cold = _cold(value, role, launch)
    delivery_raw = _original(value["deliveryOriginal"], 65536)
    envelope = p.fields(g.document(delivery_raw, 65536), ("apiVersion", "payload", "signatureBase64url"))
    payload = envelope["payload"]
    _, guest = g._admit_delivery(signed_raw=delivery_raw, cold_raw=cold_raw, cold_sha=cold_sha, role=role,
        activation=payload["activation"], boot=boot, startup=startup, lifetime=lifetime, now=now, **_flags(role))
    p.require(guest["invocationId"] == launch["invocationId"])
    runtime_raw = _original(value["runtimeOriginal"], g.MAX_BYTES)
    history_raw = _original(value["historyOriginal"], g.MAX_BYTES)
    header = _runtime(runtime_raw, role)
    p.require(p.sha(runtime_raw) == guest["runtimeConfigurationSha256"])
    item = dict(cold=cold, guest=guest, runtime_raw=runtime_raw, history_raw=history_raw,
                delivery_raw=delivery_raw, header=header)
    if granted:
        item["grant_raw"] = _original(value["generationGrantOriginal"], 65536)
        _, item["root"] = g._admit_grant(signed_raw=item["grant_raw"], guest=guest,
            runtime_raw=runtime_raw, history_raw=history_raw, delivery_raw=delivery_raw, now=now, **_flags(role))
        item["generation"] = g.document(item["grant_raw"], 65536)["payload"]
    return item


def _scope(scope, item, now):
    generation = item["generation"]
    commitment._scope_join(scope, generation["scope"])
    p.require(p.ns(item["guest"]["issuedAtBoottimeNs"]) <= generation["issuedAtBoottimeNanos"]
        <= scope["issuedAtBoottimeNanos"] <= now < scope["expiresAtBoottimeNanos"]
        <= generation["expiresAtBoottimeNanos"] <= p.ns(item["guest"]["lifetimeDeadlineBoottimeNs"]))


def _spool_payload(operation, raw, item):
    role, stem, version, purpose, field, prefix, fields = _SPOOL[operation]
    value = p.fields(g.document(raw, 65536 if operation == "head" else 131072), fields)
    root, semantic = spool._root(item)
    p.require(value["apiVersion"] == "serverware." + stem + "/v" + version
        and value["purpose"] == purpose and item["guest"]["serviceRole"] == role
        and value["guest"] == item["guest"]
        and value["runtimeConfigurationSha256"] == p.sha(item["runtime_raw"])
        and value["authorityHistoryManifestSha256"] == semantic
        and _public(root) == _public(item["root"])
        and p.digest(value["initialTransitionHeadSha256"]) != p.sha(b"")
        and item["header"][field] == {"grantFdName": prefix + "-grant"})
    return value


def _message(operation, raw):
    _, stem, version, *_ = _SPOOL[operation]
    domain = ("serverware." + stem + ".signature/v" + version).encode("ascii")
    return b"serverware-signature-v1\0" + len(domain).to_bytes(8, "big") + domain + len(raw).to_bytes(8, "big") + raw


def _signed_spool(operation, raw, item):
    envelope = p.fields(g.document(raw, 65536 if operation == "head" else 131072),
                        ("payload", "signatureBase64url"))
    payload_raw = g.canonical(envelope["payload"])
    value = _spool_payload(operation, payload_raw, item)
    item["root"].verify(p.decoded(envelope["signatureBase64url"], size=64), _message(operation, payload_raw))
    return value


def _head(value, services, native, now, epoch):
    item = services[_DRS]
    scope = p.fields(value["scope"], spool.SCOPE)
    for field in spool.SCOPE:
        if field in ("assignmentRevision", "issuedAtBoottimeNanos", "expiresAtBoottimeNanos"):
            p.integer(scope[field], maximum=p.MAX_U64)
        else:
            p.digest(scope[field])
    _scope(scope, item, now)
    _scope(scope, services[_CLEANUP], now)
    completion = p.fields(value["completion"], ("terminal", "regularAppendCapacity"))
    p.integer(completion["regularAppendCapacity"], maximum=32)
    effects = p.fields(value["effects"], spool.EFFECTS)
    spool._epoch_key(effects["cleanupAuthorityEpoch"], _CLEANUP,
                     effects["cleanupPublicKeyBase64url"], services[_CLEANUP])
    p.require(p.digest(effects["cleanupInitialTransitionHeadSha256"]) != p.sha(b""))
    proof_raw = _original(value["proofScopeOriginal"], 16384)
    proof = retrieval.scope_original(proof_raw)
    p.require(p.sha(proof_raw) == scope["proofScopeSha256"]
        and proof["production_configuration_binding_sha256"] == scope["productionConfigurationBindingSha256"]
        and proof["retrieval_namespace_sha256"] == scope["retrievalNamespaceSha256"]
        and proof["assignment_payload_sha256"] == scope["assignmentPayloadSha256"]
        and proof["assignment_revision"] == scope["assignmentRevision"])
    keys = [_public(key_live(value["originVerifier"], epoch)), p.decoded(effects["cleanupPublicKeyBase64url"], size=32)]
    for name, (role, api) in spool.EFFECT_NATIVE.items():
        selected = completion["terminal"] if name == "terminal" else effects[name] if name in spool.EFFECT_KEYS else value[name]
        p.fields(selected, ("role", "keyId", "keySpkiSha256", "publicKeyBase64url", "grantSha256"))
        public = p.decoded(selected["publicKeyBase64url"], size=32)
        p.require(public != bytes(32) and selected["role"] == role
            and p.digest(selected["keyId"]) != p.sha(b"")
            and selected["grantSha256"] == p.sha(native[name])
            and selected["keySpkiSha256"] == p.sha(bytes.fromhex("302a300506032b6570032100") + public))
        keys.append(public)
        signed = p.fields(g.document(native[name], 65536), ("payload", "signature"))
        payload = signed["payload"]
        p.decoded(signed["signature"], size=64)
        p.require(payload["apiVersion"] == api and payload["assignmentPayloadSha256"] == scope["assignmentPayloadSha256"]
            and payload["expectedPeer"] == item["header"]["expectedPeer"]
            and payload["spoolScope" if name == "retrieval" else "scope"] == scope)
        if name != "retrieval":
            p.require(payload["proofScopeOriginal"] == value["proofScopeOriginal"]
                      and payload["originVerifier"] == value["originVerifier"])
        if name in spool.EFFECT_KEYS:
            p.require(payload["commitRequest"] is None)
    p.require(len(set(keys)) == len(keys) and _public(item["root"]) not in keys)
    signing = g.document(item["delivery_raw"], 65536)["payload"]["credentials"]
    p.require(all(p.decoded(entry["signing"]["publicKeyBase64url"], size=32) not in keys
                  for entry in signing if entry["signing"] is not None))
    retrieved = g.document(native["retrieval"], 65536)["payload"]
    p.require(p.decoded(retrieved["proofScopeOriginalBase64url"], maximum=16384) == proof_raw
        and retrieved["ingress"] == value["ingress"] and retrieved["ledger"] == value["ledger"]
        and retrieved["terminal"] == completion["terminal"]
        and p.fields(retrieved["effects"], spool.EFFECT_KEYS) == {name: effects[name] for name in spool.EFFECT_KEYS})
    # Native signatures/quotes and their complete current admission remain the
    # native receivers' responsibility. This root approves these exact pinned
    # native originals; shape alone is never reported as native verification.
    return scope


def _followup(operation, value, item, head, head_raw, services, now, cleanup=None):
    p.require(value["headGrantOriginal"] == head_raw.decode("ascii"))
    scope = head["scope"]
    _scope(scope, item, now)
    spool._epoch_key(value["durableAuthorityEpoch"], _DRS, value["durablePublicKeyBase64url"], services[_DRS])
    if operation == "cleanup":
        p.require(value["initialTransitionHeadSha256"] == head["effects"]["cleanupInitialTransitionHeadSha256"])
    else:
        p.require(cleanup is not None and value["durableAuthorityEpoch"] == cleanup["durableAuthorityEpoch"]
                  and value["durablePublicKeyBase64url"] == cleanup["durablePublicKeyBase64url"])
    return scope


def sign(*, operation, role, input_original, signing_key):
    """Return (existing signed original, original output deadline), no new wire.

    Common input fields: apiVersion nativePilotServiceAuthorityInput/v1,
    operation, serviceRole, launchOriginal, payloadOriginal. Delivery adds
    configurationOriginal/configurationSha256/runtimeOriginal/activation.
    Other operations use services: a closed map of the required ordinary roles.
    Each service has configurationOriginal/configurationSha256/deliveryOriginal/
    runtimeOriginal/historyOriginal, plus generationGrantOriginal except when
    signing generation itself. Dispatch adds nativeGrantOriginal and native
    configurationOriginal/Sha256. Spool operations add nativeOriginals exact7;
    Cleanup/Current add headGrantOriginal, and Current adds cleanupGrantOriginal.
    All Original values are literal canonical ASCII strings, not summaries.
    """
    p.require(operation in OPERATIONS and role in ROLES and isinstance(signing_key, Ed25519PrivateKey))
    extra = ("configurationOriginal", "configurationSha256", "runtimeOriginal", "activation") if operation == "delivery" else ("services",)
    if operation == "dispatch":
        p.require(role in commitment.ROLES)
        extra += ("nativeGrantOriginal", "nativeConfigurationOriginal", "nativeConfigurationSha256")
    elif operation in _SPOOL:
        p.require(role == _SPOOL[operation][0])
        extra += ("nativeOriginals",)
        if operation != "head":
            extra += ("headGrantOriginal",)
        if operation == "current":
            extra += ("cleanupGrantOriginal",)
    value = p.fields(p.document(input_original, MAX_INPUT_BYTES), _COMMON + extra)
    p.require(value["apiVersion"] == "serverware.nativePilotServiceAuthorityInput/v1"
        and value["operation"] == operation and value["serviceRole"] == role)
    launch_raw = _original(value["launchOriginal"], 65536)
    boot, now = originals._boot(), originals._clock()
    launch, startup, lifetime = _launch(launch_raw, boot, now)
    payload_raw = _original(value["payloadOriginal"], 131072 if operation in ("cleanup", "current") else 65536)
    deadline = startup
    if operation == "delivery":
        cold_raw, cold_sha, _ = _cold(value, role, launch)
        payload = g.document(payload_raw, 65536)
        runtime_raw = _original(value["runtimeOriginal"], g.MAX_BYTES)
        _runtime(runtime_raw, role)
        p.require(payload["invocationId"] == launch["invocationId"]
                  and payload["runtimeConfig"]["sha256"] == p.sha(runtime_raw))
        producer = spool.sign_effects_delivery if role in spool.EFFECT_ROLES else g.sign_delivery
        signed, _ = producer(cold_raw=cold_raw, cold_sha=cold_sha, role=role, payload_raw=payload_raw,
            activation=value["activation"], boot=boot, startup=startup, lifetime=lifetime, now=now, signing_key=signing_key)
    else:
        selected = ((_DRS, _CLEANUP, _CURRENT) if operation == "current" else (_DRS, _CLEANUP)) if operation in _SPOOL else (role,)
        supplied = p.fields(value["services"], selected)
        services = {name: _service(supplied[name], name, launch, boot, startup, lifetime, now,
                                  granted=operation != "generation") for name in selected}
        p.require(len({item["cold"]["uid"] for item in services.values()}) == len(services)
                  and len({item["cold"]["gid"] for item in services.values()}) == len(services))
        item = services[role]
        if operation == "generation":
            producer = spool.sign_effects_generation_grant if role in spool.EFFECT_ROLES else g.sign_grant
            signed = producer(payload_raw=payload_raw, guest=item["guest"], runtime_raw=item["runtime_raw"],
                history_raw=item["history_raw"], delivery_raw=item["delivery_raw"], signing_key=signing_key, now=now)
            deadline = min(deadline, g.document(payload_raw, 65536)["expiresAtBoottimeNanos"])
        elif operation == "dispatch":
            payload = p.fields(g.document(payload_raw, 65536), dispatch.SERVICE_FIELDS)
            p.require(payload["guest"] == item["guest"] and payload["serviceRole"] == role)
            _scope(payload["scope"], item, now)
            native_raw = _original(value["nativeGrantOriginal"], 65536)
            p.require(g.document(native_raw, 65536)["payload"]["expectedPeer"] == item["header"]["expectedPeer"])
            signed = artifacts.sign_effects_transition_grant(payload_original=payload_raw, native_grant_original=native_raw,
                runtime_original=item["runtime_raw"], history_original=item["history_raw"], delivery_original=item["delivery_raw"],
                signing_key=signing_key, now=now,
                native_configuration_original=_original(value["nativeConfigurationOriginal"], p.MAX_CONFIG),
                native_configuration_sha256=p.digest(value["nativeConfigurationSha256"]), native_now=time.time_ns())
            deadline = min(deadline, payload["scope"]["expiresAtBoottimeNanos"])
        else:
            native = {name: _original(raw, 65536) for name, raw in p.fields(value["nativeOriginals"], spool.EFFECT_NATIVE).items()}
            payload = _spool_payload(operation, payload_raw, item)
            p.require(_public(signing_key.public_key()) == _public(item["root"]))
            if operation == "head":
                scope = _head(payload, services, native, now, time.time_ns())
            else:
                head_raw = _original(value["headGrantOriginal"], 65536)
                head = _signed_spool("head", head_raw, services[_DRS])
                _head(head, services, native, now, time.time_ns())
                cleanup = None
                if operation == "current":
                    cleanup_raw = _original(value["cleanupGrantOriginal"], 131072)
                    cleanup = _signed_spool("cleanup", cleanup_raw, services[_CLEANUP])
                    _followup("cleanup", cleanup, services[_CLEANUP], head, head_raw, services, now)
                scope = _followup(operation, payload, item, head, head_raw, services, now, cleanup)
            deadline = min(deadline, scope["expiresAtBoottimeNanos"])
            message = _message(operation, payload_raw)
            signature = signing_key.sign(message)
            signing_key.public_key().verify(signature, message)
            signed = g.canonical({"payload": payload, "signatureBase64url": p.encoded(signature)})
    p.require(len(signed) <= (131072 if operation in ("cleanup", "current") else 65536)
        and originals._boot() == boot and now <= originals._clock() < deadline)
    _launch(launch_raw, boot, originals._clock())
    return signed, deadline
