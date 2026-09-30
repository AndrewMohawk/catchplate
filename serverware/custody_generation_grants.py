"""Purpose-fixed public five-service grants. No key generation or native proof.

Existing independently supplied C9/history-root keys authorize exact originals.
The actual service still verifies the complete authority history and all local
state; these offline data helpers never assert that a service is installed.
"""
import json
import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from serverware import native_shadow_nitro_profile as p
from serverware import native_shadow_guest_delivery as c9

ROLES = ("durable-recovery-store", "cleanup-authorization-consumer", "recovery-target-provider",
    "current-signature-authority", "bounded-cleanup-helper")
BUSINESS = {ROLES[0]: ("listener", "journal"), ROLES[1]: ("listener", "state", "journal"),
    ROLES[2]: ("listener", "journal"), ROLES[3]: ("listener",), ROLES[4]: ("listener", "journal")}
SCOPE = ("previousConfigurationBindingSha256", "successorConfigurationBindingSha256", "dispatchManifestSha256",
    "kernelDriverIdentitySha256", "retainedDescriptorSetSha256", "driverGenerationReceiptSha256", "assignmentId",
    "assignmentPayloadSha256", "assignmentRevision", "operationCoverageRootSha256", "fiveServiceProtocolSetSha256",
    "envelopeAuthorityKeyId", "envelopeAuthorityKeySpkiSha256", "trustedTimeCheckpointSha256",
    "trustedTimeRevocationGeneration", "trustedTimeRevocationRootSha256", "installationIssuedAtUnixNanos",
    "installationExpiresAtUnixNanos")
GRANT = ("apiVersion", "purpose", "serviceRole", "guest", "runtimeConfigurationSha256",
    "authorityHistoryManifestSha256", "scope", "issuedAtBoottimeNanos", "expiresAtBoottimeNanos")
HISTORY = ("apiVersion", "authorityRole", "rootAuthority", "retention", "firstRetainedEpoch",
    "adjacentTransitions", "compactionAnchors", "replayTombstones", "manifestSha256")
DOMAIN = b"serverware.custodyServiceGenerationGrant.signature/v1"
MAX_BYTES = 4 * 1024 * 1024


def canonical(value):
    # Rust's canonical integral JSON supports both i64 and u64, never binary64
    # rounding. Preserve ASCII DEL exactly; retain fixed bounded work.
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop(); count += 1
        p.require(depth <= 32 and count <= 65536)
        if type(item) is dict:
            p.require(all(type(key) is str and key.isascii() for key in item))
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) in (list, tuple):
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            p.require(item.isascii())
        elif type(item) is int:
            p.require(-(1 << 63) <= item <= (1 << 64) - 1)
        else:
            p.require(item is None or type(item) is bool)
    raw = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    p.require(len(raw) <= MAX_BYTES)
    return raw


def document(raw, bound):
    p.require(type(raw) is bytes and 0 < len(raw) <= bound <= MAX_BYTES)
    value = json.loads(raw.decode("ascii"), object_pairs_hook=p._pairs, parse_float=p._reject, parse_constant=p._reject)
    p.require(type(value) is dict and canonical(value) == raw)
    return value


def configuration(raw, expected_sha, role):
    value = p.fields(document(raw, 65536), ("apiVersion", "authority", "serviceRole", "uid", "gid"))
    p.require(role in ROLES and p.sha(raw) == p.digest(expected_sha))
    p.require(value["apiVersion"] == "serverware.policyCustodyGuestConfiguration/v1" and value["serviceRole"] == role)
    for field in ("uid", "gid"):
        p.integer(value[field], maximum=(1 << 32) - 2)
        p.require(value[field] not in {64988, 64989, 64990, 65534})
    key = p.fields(value["authority"], ("publicKeyBase64url", "keyId"))
    public = p.decoded(key["publicKeyBase64url"], size=32)
    p.require(public != bytes(32) and key["keyId"] == p.sha(public))
    Ed25519PublicKey.from_public_bytes(public)
    return value


def sign_delivery(*, cold_raw, cold_sha, role, payload_raw, activation, boot, startup, lifetime, now, signing_key):
    cold = configuration(cold_raw, cold_sha, role)
    payload = p.fields(document(payload_raw, 65536), c9.FIELDS)
    p.require(payload["configurationSha256"] == cold_sha and payload["authorityKeyId"] == cold["authority"]["keyId"]
        and all(payload[field] == cold[field] for field in ("serviceRole", "uid", "gid"))
        and payload["activation"] == activation
        and tuple(item["name"] for item in activation) == BUSINESS[role] + ("generation-journal", "generation-grant"))
    for index, entry in enumerate(activation, 6):
        p.fields(entry, ("name", "fd", "device", "inode", "mode", "uid", "gid"))
        p.require(entry["fd"] == index)
    p.require((payload["bootIdBase64url"], payload["timeNamespaceDevice"], payload["timeNamespaceInode"]) == boot
        and p.ns(payload["startupDeadlineBoottimeNs"]) == startup
        and p.ns(payload["lifetimeDeadlineBoottimeNs"]) == lifetime
        and p.ns(payload["issuedAtBoottimeNs"]) <= now < startup <= lifetime
        and startup - p.ns(payload["issuedAtBoottimeNs"]) <= 30_000_000_000)
    c9._pin(payload["runtimeConfig"])
    credentials, names, total = payload["credentials"], set(), 0
    p.require(type(credentials) is list and 1 <= len(credentials) <= 64)
    for credential in credentials:
        p.fields(credential, ("name", "original", "length", "signing"))
        name = credential["name"]
        p.require(type(name) is str and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name)
            and name not in names and name != "generation-grant")
        names.add(name); c9._pin(credential["original"])
        total += p.integer(credential["length"], maximum=MAX_BYTES)
        if credential["signing"] is not None:
            key = p.fields(credential["signing"], ("publicKeyBase64url", "keyId"))
            raw = p.decoded(key["publicKeyBase64url"], size=32); p.digest(key["keyId"])
            p.require(credential["length"] == 32 and raw != bytes(32)
                and key["publicKeyBase64url"] != cold["authority"]["publicKeyBase64url"]
                and key["keyId"] != cold["authority"]["keyId"])
    p.require(total <= 16 * 1024 * 1024 and isinstance(signing_key, Ed25519PrivateKey))
    public = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(p.encoded(public) == cold["authority"]["publicKeyBase64url"])
    signature = signing_key.sign(c9.DOMAIN + payload_raw)
    signing_key.public_key().verify(signature, c9.DOMAIN + payload_raw)
    result = canonical({"apiVersion": "serverware.policyCustodyGuestDelivery/v1", "payload": payload,
        "signatureBase64url": p.encoded(signature)})
    p.require(len(result) <= 65536)
    guest = {field: payload[field] for field in p.GUEST_FIELDS if field not in {"deliverySha256", "runtimeConfigurationSha256"}}
    guest.update(deliverySha256=p.sha(result), runtimeConfigurationSha256=payload["runtimeConfig"]["sha256"])
    p.guest(guest)
    return result, guest


def sign_grant(*, payload_raw, guest, runtime_raw, history_raw, delivery_raw, signing_key, now):
    payload = p.fields(document(payload_raw, 65536), GRANT)
    runtime = document(runtime_raw, MAX_BYTES)["runtime"]
    history = p.fields(document(history_raw, MAX_BYTES), HISTORY)
    delivery = document(delivery_raw, 65536)["payload"]
    p.guest(guest)
    scope = p.fields(payload["scope"], SCOPE)
    role = guest["serviceRole"]
    p.require(role in ROLES and payload["apiVersion"] == "serverware.custodyServiceGenerationGrant/v1"
        and payload["purpose"] == "cold-service-generation-admission" and payload["serviceRole"] == role
        and payload["guest"] == guest and p.sha(delivery_raw) == guest["deliverySha256"]
        and p.sha(runtime_raw) == guest["runtimeConfigurationSha256"] == payload["runtimeConfigurationSha256"])
    p.require(runtime["apiVersion"] == "serverware.policyCustodyServiceRuntimeConfig/v5"
        and runtime["generationAdmission"] == {"grantFdName": "generation-grant"})
    p.require(history["apiVersion"] == "serverware.policyCustodyAuthorityHistory/v3"
        and history["authorityRole"] == {"authorityKind": "isolated-service", "role": role})
    semantic = p.framed(b"serverware.policyCustodyAuthorityHistoryManifest/v3",
        (canonical([history[field] for field in HISTORY[:-1]]),))
    p.require(history["manifestSha256"] == semantic == runtime["authorityHistoryManifestSha256"]
        == payload["authorityHistoryManifestSha256"])
    selected = [entry for entry in delivery["credentials"] if entry["name"] == runtime["authorityHistoryManifestCredential"]]
    p.require(len(selected) == 1 and selected[0]["original"]["sha256"] == p.sha(history_raw)
        and selected[0]["length"] == len(history_raw) and selected[0]["signing"] is None)
    root = p.fields(history["rootAuthority"], ("keyId", "keySpkiSha256", "publicKeySpkiBase64"))
    p.require(isinstance(signing_key, Ed25519PrivateKey))
    spki = signing_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    p.require(p.encoded(spki) == root["publicKeySpkiBase64"] and p.sha(spki) == root["keySpkiSha256"]
        == runtime["authorityHistoryRootKeySpkiSha256"] and p.digest(root["keyId"]) == runtime["authorityHistoryRootKeyId"])
    p.require(p.encoded(signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        not in [entry["signing"]["publicKeyBase64url"] for entry in delivery["credentials"] if entry["signing"] is not None])
    for field in SCOPE:
        value = scope[field]
        if field == "previousConfigurationBindingSha256" and value is None:
            continue
        if field in ("assignmentRevision", "trustedTimeRevocationGeneration", "installationIssuedAtUnixNanos", "installationExpiresAtUnixNanos"):
            p.integer(value, maximum=(1 << 63) - 1 if field.startswith("installation") else (1 << 64) - 1)
        else:
            p.digest(value)
    p.require(scope["installationIssuedAtUnixNanos"] < scope["installationExpiresAtUnixNanos"]
        and scope["fiveServiceProtocolSetSha256"] == runtime["productionDispatchProtocolSetSha256"])
    issued = p.integer(payload["issuedAtBoottimeNanos"], maximum=(1 << 64) - 1)
    expires = p.integer(payload["expiresAtBoottimeNanos"], maximum=(1 << 64) - 1)
    p.require(p.ns(guest["issuedAtBoottimeNs"]) <= issued <= now < expires <= p.ns(guest["lifetimeDeadlineBoottimeNs"]))
    message = b"serverware-signature-v1\0" + len(DOMAIN).to_bytes(8, "big") + DOMAIN + len(payload_raw).to_bytes(8, "big") + payload_raw
    signature = signing_key.sign(message)
    signing_key.public_key().verify(signature, message)
    raw = canonical({"payload": payload, "signatureBase64url": p.encoded(signature)})
    p.require(len(raw) <= 65536)
    return raw
