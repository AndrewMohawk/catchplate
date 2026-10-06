"""Closed C9 retrieval/activation delivery authoring, not native admission or key creation."""
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
SPOOL_RETRIEVAL_NAMES = ("retrieval-listener", "retrieval-objects", "ledger-spool-store", "ledger-spool-lock")
ADOPTED_RETRIEVAL_NAMES = SPOOL_RETRIEVAL_NAMES + ("publication-genesis-core",)


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
    return _sign_delivery(configuration_raw=configuration_raw, configuration_sha256=configuration_sha256,
        payload_raw=payload_raw, signing_key=signing_key, activation=activation, boot=boot,
        startup_deadline=startup_deadline, now=now, names=("retrieval-listener", "retrieval-objects"))


def sign_activation_delivery(*, configuration_raw, configuration_sha256, payload_raw, signing_key,
                             activation, boot, startup_deadline, now):
    return _sign_delivery(configuration_raw=configuration_raw, configuration_sha256=configuration_sha256,
        payload_raw=payload_raw, signing_key=signing_key, activation=activation, boot=boot,
        startup_deadline=startup_deadline, now=now, names=("activation-channel", "activation-journal"))


def sign_persistence_delivery(*, configuration_raw, configuration_sha256, payload_raw, signing_key,
                              activation, boot, startup_deadline, now):
    """Explicit v2 persistence activation: transfer the already held lock too."""
    return _sign_delivery(configuration_raw=configuration_raw, configuration_sha256=configuration_sha256,
        payload_raw=payload_raw, signing_key=signing_key, activation=activation, boot=boot,
        startup_deadline=startup_deadline, now=now,
        names=("persistence-listener", "persistence-journal", "persistence-lock"))


def _validate_delivery_payload(*, configuration_raw, configuration_sha256, payload_raw,
                               activation, boot, startup_deadline, now, names, adopted_core=None):
    """Shared public checks; only retained callers supply actual resource facts."""
    cold, payload = _validate_delivery_payload_fields(configuration_raw=configuration_raw,
        configuration_sha256=configuration_sha256, payload_raw=payload_raw, activation=activation,
        boot=boot, startup_deadline=startup_deadline, names=names, adopted_core=adopted_core)
    p.require(p.ns(payload["issuedAtBoottimeNs"]) <= now < p.ns(payload["startupDeadlineBoottimeNs"]))
    return cold, payload


def _validate_delivery_payload_fields(*, configuration_raw, configuration_sha256, payload_raw,
                                      activation, boot, startup_deadline, names, adopted_core=None):
    """Original syntax and interval relationships; no current clock assertion."""
    adopted = names == ADOPTED_RETRIEVAL_NAMES
    p.require((adopted and adopted_core is not None) or (adopted_core is None and names in
        (("retrieval-listener", "retrieval-objects"), ("activation-channel", "activation-journal"),
        ("persistence-listener", "persistence-journal", "persistence-lock"), SPOOL_RETRIEVAL_NAMES)))
    if adopted:
        require_adopted_core_activation(activation, *adopted_core)
    from serverware import custody_generation_grants as g
    codec = g if adopted else p
    cold = configuration(configuration_raw, configuration_sha256)
    payload = p.fields(codec.document(payload_raw, MAX_DELIVERY), FIELDS)
    p.require(payload["configurationSha256"] == configuration_sha256
        and payload["authorityKeyId"] == cold["authority"]["keyId"]
        and all(payload[name] == cold[name] for name in ("serviceRole", "uid", "gid")))
    _pin(payload["runtimeConfig"])
    p.require(p.decoded(payload["bootIdBase64url"], size=16) != bytes(16))
    p.integer(payload["timeNamespaceDevice"], minimum=0 if adopted else 1, maximum=p.MAX_U64 if adopted else p.MAX_I64)
    p.integer(payload["timeNamespaceInode"], maximum=p.MAX_U64 if adopted else p.MAX_I64)
    p.require(type(payload["invocationId"]) is str and re.fullmatch(r"[0-9a-f]{32}", payload["invocationId"])
        and payload["invocationId"] != "0" * 32)
    issued, startup, lifetime = (p.ns(payload[name]) for name in
        ("issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"))
    p.require(issued < startup <= lifetime and startup == startup_deadline
        and startup - issued <= 30_000_000_000
        and (payload["bootIdBase64url"], payload["timeNamespaceDevice"], payload["timeNamespaceInode"]) == boot)
    p.require(type(activation) is list and len(activation) == len(names) and payload["activation"] == activation)
    for index, (entry, name) in enumerate(zip(activation, names), 6):
        p.fields(entry, ("name", "fd", "device", "inode", "mode", "uid", "gid"))
        p.require(entry["name"] == name and entry["fd"] == index)
        p.integer(entry["device"], minimum=0, maximum=p.MAX_U64 if adopted else p.MAX_I64)
        p.integer(entry["inode"], maximum=p.MAX_U64 if adopted else p.MAX_I64)
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
    p.require(total <= 16 * 1024 * 1024)
    return cold, payload


def _delivery_guest(payload, raw):
    guest = {name: payload[name] for name in p.GUEST_FIELDS if name not in
        {"deliverySha256", "runtimeConfigurationSha256"}}
    guest.update(deliverySha256=p.sha(raw), runtimeConfigurationSha256=payload["runtimeConfig"]["sha256"])
    p.guest(guest)
    return guest


def verify_persistence_delivery(*, configuration_raw, configuration_sha256, signed_delivery_original,
                                activation, boot, startup_deadline, now):
    """Verify an independent original for the fixed held-lock v2 inventory.

    Never re-sign or re-encode the returned original. This public validator is
    not a resource owner; PersistenceInputs must bracket it with its live checks.
    """
    signed = p.fields(p.document(signed_delivery_original, MAX_DELIVERY),
        ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed["apiVersion"] == "serverware.policyCustodyGuestDelivery/v1")
    payload_raw = p.canonical(signed["payload"])
    cold, payload = _validate_delivery_payload(configuration_raw=configuration_raw,
        configuration_sha256=configuration_sha256, payload_raw=payload_raw,
        activation=activation, boot=boot, startup_deadline=startup_deadline, now=now,
        names=("persistence-listener", "persistence-journal", "persistence-lock"))
    public = Ed25519PublicKey.from_public_bytes(p.decoded(cold["authority"]["publicKeyBase64url"], size=32))
    public.verify(p.decoded(signed["signatureBase64url"], size=64), DOMAIN + payload_raw)
    _delivery_guest(payload, signed_delivery_original)
    return signed_delivery_original


def require_adopted_core_activation(activation, observation_raw, bundle_raw):
    """Public association only; the real retained received owner supplies FD10."""
    from serverware import native_pilot_genesis_core_profile as core
    observed = core.observation(observation_raw, bundle_raw)
    p.require(type(activation) is list and len(activation) == 5)
    entry = p.fields(activation[4], ("name", "fd", "device", "inode", "mode", "uid", "gid"))
    p.require(entry["name"] == "publication-genesis-core" and type(entry["fd"]) is int and entry["fd"] == 10
        and all(type(entry[name]) is int and entry[name] == observed["file"][name]
            for name in ("device", "inode", "mode", "uid", "gid")))
    return observed


def verify_adopted_retrieval_delivery(*, configuration_raw, configuration_sha256, signed_delivery_original,
                                    activation, boot, startup_deadline, now, core_observation_raw, core_bundle_raw):
    """Explicit full5 original, separate from both legacy inventories."""
    from serverware import custody_generation_grants as g
    signed = p.fields(g.document(signed_delivery_original, MAX_DELIVERY), ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed["apiVersion"] == "serverware.policyCustodyGuestDelivery/v1")
    payload_raw = g.canonical(signed["payload"])
    cold, payload = _validate_delivery_payload(configuration_raw=configuration_raw, configuration_sha256=configuration_sha256,
        payload_raw=payload_raw, activation=activation, boot=boot, startup_deadline=startup_deadline, now=now,
        names=ADOPTED_RETRIEVAL_NAMES, adopted_core=(core_observation_raw, core_bundle_raw))
    from serverware.native_pilot_adopted_delivery import require_retrieval_inventory
    require_retrieval_inventory(activation, cold, core_observation_raw, core_bundle_raw)
    public = Ed25519PublicKey.from_public_bytes(p.decoded(cold["authority"]["publicKeyBase64url"], size=32))
    public.verify(p.decoded(signed["signatureBase64url"], size=64), DOMAIN + payload_raw)
    adopted_delivery_guest(payload, signed_delivery_original)
    return signed_delivery_original


def adopted_delivery_guest(payload, raw):
    """Same closed native guest fields, preserving the native u64 namespace."""
    guest = {name: payload[name] for name in p.GUEST_FIELDS if name not in {"deliverySha256", "runtimeConfigurationSha256"}}
    guest.update(deliverySha256=p.sha(raw), runtimeConfigurationSha256=payload["runtimeConfig"]["sha256"])
    p.fields(guest, p.GUEST_FIELDS)
    for name in ("configurationSha256", "deliverySha256", "runtimeConfigurationSha256"): p.digest(guest[name])
    p.require(guest["serviceRole"] == "production-bridge")
    for name in ("uid", "gid"):
        p.integer(guest[name], maximum=(1 << 32) - 2); p.require(guest[name] not in {64988, 64989, 64990, 65534})
    p.require(p.decoded(guest["bootIdBase64url"], size=16) != bytes(16))
    p.integer(guest["timeNamespaceDevice"], minimum=0, maximum=p.MAX_U64); p.integer(guest["timeNamespaceInode"], maximum=p.MAX_U64)
    p.require(p.ns(guest["issuedAtBoottimeNs"]) < p.ns(guest["startupDeadlineBoottimeNs"]) <= p.ns(guest["lifetimeDeadlineBoottimeNs"])
        and type(guest["invocationId"]) is str and re.fullmatch(r"[0-9a-f]{32}", guest["invocationId"]) and guest["invocationId"] != "0" * 32)
    return guest


def verify_spool_retrieval_delivery(*, configuration_raw, configuration_sha256, signed_delivery_original,
                                   activation, boot, startup_deadline, now):
    """Verify the fixed four-FD original; no private signer or resource creation.

    The retained Retrieval/Spool owners choose this profile and supply actual
    metadata. The two-FD retrieval producer remains a separate closed API.
    """
    signed = p.fields(p.document(signed_delivery_original, MAX_DELIVERY),
        ("apiVersion", "payload", "signatureBase64url"))
    p.require(signed["apiVersion"] == "serverware.policyCustodyGuestDelivery/v1")
    payload_raw = p.canonical(signed["payload"])
    cold, payload = _validate_delivery_payload(configuration_raw=configuration_raw,
        configuration_sha256=configuration_sha256, payload_raw=payload_raw,
        activation=activation, boot=boot, startup_deadline=startup_deadline, now=now,
        names=SPOOL_RETRIEVAL_NAMES)
    p.require(p.canonical(payload["activation"]) == p.canonical(activation))
    public = Ed25519PublicKey.from_public_bytes(p.decoded(cold["authority"]["publicKeyBase64url"], size=32))
    public.verify(p.decoded(signed["signatureBase64url"], size=64), DOMAIN + payload_raw)
    _delivery_guest(payload, signed_delivery_original)
    return signed_delivery_original


def _sign_delivery(*, configuration_raw, configuration_sha256, payload_raw, signing_key,
                   activation, boot, startup_deadline, now, names):
    """Sign exact approved bytes; observed activation arguments are data only.

    The actual retained activation owner supplies these observations. Native
    admission independently verifies every original descriptor and credential.
    This function by itself does not assert that any runtime owner exists.
    """
    cold, payload = _validate_delivery_payload(configuration_raw=configuration_raw,
        configuration_sha256=configuration_sha256, payload_raw=payload_raw,
        activation=activation, boot=boot, startup_deadline=startup_deadline, now=now, names=names)
    return _sign_validated_delivery(cold, payload, payload_raw, signing_key)


def validate_activation_delivery_sample_anchored(*, configuration_raw, configuration_sha256,
        payload_raw, activation, boot, observed_at_boottime_ns):
    """Validate an explicitly approved interval anchored to an original sample.

    The sample is public acquisition data, NOT a fresh same-domain clock. No
    host clock is consulted or substituted. Delayed issuance cannot rebase the
    interval: the actual enclave receiver still refuses an expired delivery.
    """
    sample = p.integer(observed_at_boottime_ns, maximum=p.MAX_U64)
    payload = p.fields(p.document(payload_raw, MAX_DELIVERY), FIELDS)
    p.require(p.ns(payload["issuedAtBoottimeNs"]) == sample)
    return _validate_delivery_payload_fields(configuration_raw=configuration_raw,
        configuration_sha256=configuration_sha256, payload_raw=payload_raw,
        activation=activation, boot=boot, startup_deadline=p.ns(payload["startupDeadlineBoottimeNs"]),
        names=("activation-channel", "activation-journal"))


def sign_activation_delivery_sample_anchored(*, configuration_raw, configuration_sha256,
        payload_raw, signing_key, activation, boot, observed_at_boottime_ns):
    """Sign exact approved sample-anchored bytes, never a currentness proof."""
    cold, payload = validate_activation_delivery_sample_anchored(configuration_raw=configuration_raw,
        configuration_sha256=configuration_sha256, payload_raw=payload_raw, activation=activation,
        boot=boot, observed_at_boottime_ns=observed_at_boottime_ns)
    return _sign_validated_delivery(cold, payload, payload_raw, signing_key)


def _sign_validated_delivery(cold, payload, payload_raw, signing_key):
    p.require(isinstance(signing_key, Ed25519PrivateKey))
    actual = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(p.encoded(actual) == cold["authority"]["publicKeyBase64url"])
    signature = signing_key.sign(DOMAIN + payload_raw)
    signing_key.public_key().verify(signature, DOMAIN + payload_raw)
    result = p.canonical({"apiVersion": "serverware.policyCustodyGuestDelivery/v1",
        "payload": payload, "signatureBase64url": p.encoded(signature)})
    p.require(len(result) <= MAX_DELIVERY)
    _delivery_guest(payload, result)
    return result
