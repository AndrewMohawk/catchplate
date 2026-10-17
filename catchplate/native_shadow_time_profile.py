"""Closed public time-issuer grammar; these values are not signing authority."""
from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from catchplate import native_shadow_nitro_profile as p

MAX_FRAME = 65536
CONFIG_NAME = "native-shadow-guest-time-issuer.json"
CHALLENGE_TAG = b"SWNGTC1\0"
EVIDENCE_TAG = b"SWNGTE1\0"
ANCHOR_TAG = b"SWNGTA2\0"
CHALLENGE_DOMAIN = "catchplate.nativeShadowGuestTimeChallenge.signature/v1"
SAMPLE_DOMAIN = "catchplate.nativeShadowGuestTimeSample.signature/v1"
ANCHOR_DOMAIN = "catchplate.nativeShadowGuestTimeAnchor.signature/v2"
AUTH_DOMAIN = "catchplate.nativeShadowGuestTimeIssuerAuthorization.signature/v1"
EVIDENCE_PREFIX = b"catchplate/native-shadow-guest-time-evidence/v1\0"
KEY_FIELDS = ("keyId", "keySpkiSha256", "publicKeyBase64url", "notBeforeUnixNanos", "notAfterUnixNanos")
CONFIG_FIELDS = ("apiVersion", "uid", "gid", "operation", "issuerAuthorityKey", "timeKey",
    "guestAuthorityPublicKeyBase64url", "guestConfigurationOriginalBase64url", "guestDeliveryOriginalBase64url",
    "nitro", "collateralRevocation", "transport", "maximumBracketNanos", "timestampErrorNanos",
    "maximumClockRateErrorPpm", "maximumAnchorAgeNanos", "authorization")
CHALLENGE_FIELDS = ("apiVersion", "purpose", "guest", "nonceBase64url", "issuedAtUnixNanos",
    "expiresAtUnixNanos", "maximumBracketNanos", "timestampErrorNanos", "maximumClockRateErrorPpm", "signingKeyId")
STATEMENT_FIELDS = ("apiVersion", "purpose", "guest", "challengeSha256", "beforeBoottimeNs", "publicKeyBase64url")
EVIDENCE_FIELDS = ("apiVersion", "statement", "afterBoottimeNs", "attestationDocumentBase64url", "signature")
ANCHOR_FIELDS = ("apiVersion", "purpose", "guest", "challengeSha256", "evidenceSha256", "quoteSha256",
    "anchorBoottimeNs", "earliestUnixNanos", "latestUnixNanos", "expiresAtUnixNanos",
    "maximumClockRateErrorPpm", "signingKeyId")


def public_key(value):
    p.fields(value, KEY_FIELDS)
    raw = p.decoded(value["publicKeyBase64url"], size=32)
    p.require(raw != bytes(32))
    key = Ed25519PublicKey.from_public_bytes(raw)
    spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    p.require(p.sha(spki) == p.digest(value["keyId"]) == p.digest(value["keySpkiSha256"]))
    p.require(p.integer(value["notBeforeUnixNanos"]) < p.integer(value["notAfterUnixNanos"]))
    return key


def key_live(value, now):
    key = public_key(value)
    p.require(value["notBeforeUnixNanos"] <= now < value["notAfterUnixNanos"])
    return key


def authorization(config, now):
    p.fields(config, CONFIG_FIELDS)
    p.require(config["apiVersion"] == "catchplate.nativeShadowGuestTimeIssuerConfiguration/v1")
    authority = key_live(config["issuerAuthorityKey"], now)
    key_live(config["timeKey"], now)
    p.require(config["issuerAuthorityKey"]["publicKeyBase64url"] != config["timeKey"]["publicKeyBase64url"]
        and config["guestAuthorityPublicKeyBase64url"] not in (
            config["issuerAuthorityKey"]["publicKeyBase64url"], config["timeKey"]["publicKeyBase64url"]))
    p.decoded(config["guestAuthorityPublicKeyBase64url"], size=32)
    p.require(p.ns(config["maximumBracketNanos"]) <= 1_000_000_000)
    p.integer(config["timestampErrorNanos"], minimum=0, maximum=1_000_000_000)
    p.integer(config["maximumClockRateErrorPpm"], minimum=0, maximum=10000)
    p.integer(config["maximumAnchorAgeNanos"], maximum=300_000_000_000)
    envelope = p.fields(config["authorization"], ("payload", "signature"))
    payload = p.fields(envelope["payload"], ("apiVersion", "purpose", "configurationSha256",
        "issuedAtUnixNanos", "expiresAtUnixNanos", "signingKeyId"))
    p.require(payload["apiVersion"] == "catchplate.nativeShadowGuestTimeIssuerAuthorization/v1"
        and payload["purpose"] == "native-shadow-guest-time-issuance"
        and payload["signingKeyId"] == config["issuerAuthorityKey"]["keyId"]
        and payload["configurationSha256"] == p.sha(p.canonical({name: value for name, value in config.items()
            if name != "authorization"})))
    p.freshness(payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"], now, 300_000_000_000)
    p.require(payload["expiresAtUnixNanos"] - payload["issuedAtUnixNanos"] <= 300_000_000_000)
    authority.verify(p.decoded(envelope["signature"], size=64), p.preimage(AUTH_DOMAIN, payload))
    return payload


def guest_originals(config):
    """Authenticate originals against the issuer's independent C9 root, not a DTO."""
    raw = p.decoded(config["guestConfigurationOriginalBase64url"], maximum=MAX_FRAME)
    cold = p.document(raw, MAX_FRAME)
    p.fields(cold, ("apiVersion", "authority", "serviceRole", "uid", "gid"))
    p.require(cold["apiVersion"] == "catchplate.policyCustodyGuestConfiguration/v1")
    authority = p.fields(cold["authority"], ("publicKeyBase64url", "keyId"))
    public = p.decoded(config["guestAuthorityPublicKeyBase64url"], size=32)
    p.require(public != bytes(32) and authority["publicKeyBase64url"] == config["guestAuthorityPublicKeyBase64url"]
        and authority["keyId"] == p.sha(public))
    delivery_raw = p.decoded(config["guestDeliveryOriginalBase64url"], maximum=MAX_FRAME)
    wire = p.document(delivery_raw, MAX_FRAME)
    p.fields(wire, ("apiVersion", "payload", "signatureBase64url"))
    p.require(wire["apiVersion"] == "catchplate.policyCustodyGuestDelivery/v1")
    payload = p.fields(wire["payload"], ("configurationSha256", "authorityKeyId", "serviceRole", "uid", "gid",
        "bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode", "issuedAtBoottimeNs",
        "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId", "runtimeConfig", "credentials", "activation"))
    Ed25519PublicKey.from_public_bytes(public).verify(p.decoded(wire["signatureBase64url"], size=64),
        b"catchplate.policyCustodyGuestDelivery.signature/v1\0" + p.canonical(payload))
    p.require(payload["configurationSha256"] == p.sha(raw) and payload["authorityKeyId"] == authority["keyId"]
        and all(payload[name] == cold[name] for name in ("serviceRole", "uid", "gid")))
    runtime = p.fields(payload["runtimeConfig"], ("path", "sha256"))
    p.digest(runtime["sha256"])
    p.require(type(runtime["path"]) is str and runtime["path"].startswith("/") and len(runtime["path"]) <= 4096)
    guest = {name: payload[name] for name in p.GUEST_FIELDS if name not in
        {"deliverySha256", "runtimeConfigurationSha256"}}
    guest.update(deliverySha256=p.sha(delivery_raw), runtimeConfigurationSha256=runtime["sha256"])
    p.guest(guest)
    p.require(p.ns(guest["startupDeadlineBoottimeNs"]) - p.ns(guest["issuedAtBoottimeNs"]) <= 30_000_000_000)
    credentials = payload["credentials"]
    p.require(type(credentials) is list and 1 <= len(credentials) <= 64)
    names, total = set(), 0
    for item in credentials:
        p.fields(item, ("name", "original", "length", "signing"))
        p.require(type(item["name"]) is str and 1 <= len(item["name"]) <= 255 and item["name"] not in names)
        names.add(item["name"])
        pin = p.fields(item["original"], ("path", "sha256"))
        p.digest(pin["sha256"])
        p.require(type(pin["path"]) is str and pin["path"].startswith("/") and len(pin["path"]) <= 4096)
        total += p.integer(item["length"], maximum=4 * 1024 * 1024)
        if item["signing"] is not None:
            signing = p.fields(item["signing"], ("publicKeyBase64url", "keyId"))
            p.decoded(signing["publicKeyBase64url"], size=32); p.digest(signing["keyId"])
            p.require(signing["publicKeyBase64url"] not in (config["timeKey"]["publicKeyBase64url"],
                config["issuerAuthorityKey"]["publicKeyBase64url"], config["guestAuthorityPublicKeyBase64url"]))
    p.require(total <= 16 * 1024 * 1024 and type(payload["activation"]) is list
        and 1 <= len(payload["activation"]) <= 64)
    activation_names = set()
    for index, item in enumerate(payload["activation"]):
        p.fields(item, ("name", "fd", "device", "inode", "mode", "uid", "gid"))
        p.require(type(item["name"]) is str and 1 <= len(item["name"]) <= 255 and item["name"] not in activation_names)
        activation_names.add(item["name"])
        p.require(p.integer(item["fd"], minimum=6, maximum=69) == index + 6)
        p.integer(item["device"], minimum=0); p.integer(item["inode"])
        p.integer(item["mode"], maximum=(1 << 32) - 1)
        p.integer(item["uid"], minimum=0, maximum=(1 << 32) - 2)
        p.integer(item["gid"], minimum=0, maximum=(1 << 32) - 2)
    # This validates the signature/scope, not the foreign process or its FDs.
    # Genuine measured guest code must join those actual C9 owners itself.
    return guest


def drift(elapsed, ppm):
    return (elapsed * ppm + 999999) // 1000000
