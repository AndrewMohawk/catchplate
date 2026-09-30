"""Closed C9 retrieval-delivery authoring, not native admission or key creation."""
from __future__ import annotations

import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from serverware import native_shadow_nitro_profile as p

MAX_DELIVERY = 65536
DOMAIN = b"serverware.policyCustodyGuestDelivery.signature/v1\0"
FIELDS = ("configurationSha256", "authorityKeyId", "serviceRole", "uid", "gid", "bootIdBase64url",
    "timeNamespaceDevice", "timeNamespaceInode", "issuedAtBoottimeNs", "startupDeadlineBoottimeNs",
    "lifetimeDeadlineBoottimeNs", "invocationId", "runtimeConfig", "credentials", "activation")


def configuration(raw, expected_sha256):
    value = p.fields(p.document(raw, MAX_DELIVERY), ("apiVersion", "authority", "serviceRole", "uid", "gid"))
    p.require(p.sha(raw) == p.digest(expected_sha256)
        and value["apiVersion"] == "serverware.policyCustodyGuestConfiguration/v1"
        and value["serviceRole"] == "production-bridge")
    for name in ("uid", "gid"):
        p.integer(value[name], maximum=(1 << 32) - 2)
        p.require(value[name] not in {64988, 64989, 64990, 65534})
    authority = p.fields(value["authority"], ("publicKeyBase64url", "keyId"))
    raw_key = p.decoded(authority["publicKeyBase64url"], size=32)
    p.require(raw_key != bytes(32) and authority["keyId"] == p.sha(raw_key))
    Ed25519PublicKey.from_public_bytes(raw_key)
    return value


def _pin(value):
    p.fields(value, ("path", "sha256"))
    path = value["path"]
    p.require(type(path) is str and path.isascii() and path.startswith("/") and 1 < len(path) <= 4096
        and "\0" not in path and all(part not in {"", ".", ".."} for part in path.split("/")[1:]))
    p.digest(value["sha256"])


def sign_retrieval_delivery(*, configuration_raw, configuration_sha256, payload_raw, signing_key,
                            activation, boot, startup_deadline, now):
    """Sign exact approved bytes; observed activation arguments are data only.

    The actual retained activation owner supplies these observations. Native
    admission independently verifies every original descriptor and credential.
    This function by itself does not assert that any runtime owner exists.
    """
    cold = configuration(configuration_raw, configuration_sha256)
    payload = p.fields(p.document(payload_raw, MAX_DELIVERY), FIELDS)
    p.require(payload["configurationSha256"] == configuration_sha256
        and payload["authorityKeyId"] == cold["authority"]["keyId"]
        and all(payload[name] == cold[name] for name in ("serviceRole", "uid", "gid")))
    _pin(payload["runtimeConfig"])
    p.require(p.decoded(payload["bootIdBase64url"], size=16) != bytes(16))
    p.integer(payload["timeNamespaceDevice"]); p.integer(payload["timeNamespaceInode"])
    p.require(type(payload["invocationId"]) is str and re.fullmatch(r"[0-9a-f]{32}", payload["invocationId"])
        and payload["invocationId"] != "0" * 32)
    issued, startup, lifetime = (p.ns(payload[name]) for name in
        ("issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"))
    p.require(issued <= now < startup <= lifetime and startup == startup_deadline
        and startup - issued <= 30_000_000_000
        and (payload["bootIdBase64url"], payload["timeNamespaceDevice"], payload["timeNamespaceInode"]) == boot)
    p.require(type(activation) is list and len(activation) == 2 and payload["activation"] == activation)
    for index, (entry, name) in enumerate(zip(activation, ("retrieval-listener", "retrieval-objects")), 6):
        p.fields(entry, ("name", "fd", "device", "inode", "mode", "uid", "gid"))
        p.require(entry["name"] == name and entry["fd"] == index)
        p.integer(entry["device"], minimum=0); p.integer(entry["inode"])
        p.integer(entry["mode"], maximum=(1 << 32) - 1)
        for field in ("uid", "gid"):
            p.integer(entry[field], minimum=0, maximum=(1 << 32) - 1)
    credentials = payload["credentials"]
    p.require(type(credentials) is list and 1 <= len(credentials) <= 64)
    names, total = set(), 0
    for entry in credentials:
        p.fields(entry, ("name", "original", "length", "signing"))
        name = entry["name"]
        p.require(type(name) is str and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name) and name not in names)
        names.add(name)
        _pin(entry["original"])
        total += p.integer(entry["length"], maximum=4 * 1024 * 1024)
        if entry["signing"] is not None:
            assigned = p.fields(entry["signing"], ("publicKeyBase64url", "keyId"))
            public = p.decoded(assigned["publicKeyBase64url"], size=32)
            p.digest(assigned["keyId"])
            p.require(entry["length"] == 32 and public != bytes(32)
                and assigned["publicKeyBase64url"] != cold["authority"]["publicKeyBase64url"]
                and assigned["keyId"] != cold["authority"]["keyId"])
            Ed25519PublicKey.from_public_bytes(public)
    p.require(total <= 16 * 1024 * 1024 and isinstance(signing_key, Ed25519PrivateKey))
    actual = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(p.encoded(actual) == cold["authority"]["publicKeyBase64url"])
    signature = signing_key.sign(DOMAIN + payload_raw)
    signing_key.public_key().verify(signature, DOMAIN + payload_raw)
    result = p.canonical({"apiVersion": "serverware.policyCustodyGuestDelivery/v1",
        "payload": payload, "signatureBase64url": p.encoded(signature)})
    p.require(len(result) <= MAX_DELIVERY)
    guest = {name: payload[name] for name in p.GUEST_FIELDS if name not in
        {"deliverySha256", "runtimeConfigurationSha256"}}
    guest.update(deliverySha256=p.sha(result), runtimeConfigurationSha256=payload["runtimeConfig"]["sha256"])
    p.guest(guest)
    return result
