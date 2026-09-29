"""Offline purpose-fixed guest-delivery signing, not runtime admission.

The operator independently chooses the configuration, current guest boot/window
and original file inventory. This producer neither observes that guest nor
verifies its generation/TEE evidence; the real Rust consumer still does so.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ENVELOPE = "serverware.responseV2.guestCredentialDelivery/v1"
AUTHORITY = "serverware.responseV2.guestDeliveryAuthority/v1"
DOMAIN = b"serverware.responseV2.guestCredentialDelivery.signature/v1\0"
MAX_CONFIG = 256 * 1024
MAX_DELIVERY = 64 * 1024
MAX_WINDOW_NS = 600_000_000_000
MAX_U64 = (1 << 64) - 1
MAX_SAFE_INTEGER = (1 << 53) - 1
ROLES = frozenset({"custody-router", "state-authority", "credential-transport",
    "policy-proof-verifier", "immutable-artifact-ledger", "release-attestor-publisher",
    "cleanup-watchdog"})


def require(value):
    if not value:
        raise ValueError("guest credential delivery signing refused")


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _hash(value):
    require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value))
    return value


def encoded(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decoded(value, size):
    require(type(value) is str and len(value) == (4 * size + 2) // 3)
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    require(len(raw) == size and encoded(raw) == value)
    return raw


def canonical(value):
    # This payload contains no floating-point numbers. UTF-8, sorted object
    # keys and compact separators match the existing custody Rust codec.
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _pairs(items):
    result = {}
    for key, value in items:
        require(key not in result)
        result[key] = value
    return result


def _reject(_value):
    raise ValueError("guest credential delivery contains an unsupported number")


class _ConfigurationNumber(str):
    """Keep unrelated configuration number spelling; never serialize it."""


def document(raw, maximum, *, payload=False):
    require(type(raw) is bytes and 1 <= len(raw) <= maximum)
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
        parse_float=_reject if payload else _ConfigurationNumber, parse_constant=_reject)
    require(type(value) is dict)
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        require(depth <= 64 and count <= 32768)
        if type(item) is dict:
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
    if payload:
        require(canonical(value) == raw)
    # Do not reconstruct configuration JSON: hash its complete original bytes.
    # The Rust consumer repeats full canonical/configuration/signature admission.
    return value


def _fields(value, names):
    require(type(value) is dict and set(value) == set(names))


def _path(value):
    require(type(value) is str and value.startswith("/") and "\0" not in value
        and 1 < len(value.encode("utf-8")) <= 4096
        and all(part not in {"", ".", ".."} for part in value.split("/")[1:]))
    return value


def _pin(value, originals, *, secret=False):
    _fields(value, ("path", "sha256"))
    path, sha = _path(value["path"]), _hash(value["sha256"])
    if path in originals:
        old_hash, old_secret = originals[path]
        require(not secret and not old_secret and old_hash == sha)
    originals[path] = (sha, secret)


def _ns(value):
    require(type(value) is str and re.fullmatch(r"[1-9][0-9]{0,19}", value))
    result = int(value)
    require(1 <= result <= MAX_U64)
    return result


def sign_delivery(configuration_original, payload_original, signing_seed,
                  generation_root, expected_configuration_sha256):
    """Sign independently approved originals; do not choose a boot or deadline."""
    require(type(signing_seed) is bytes and len(signing_seed) == 32
        and type(generation_root) is bytes and len(generation_root) == 32)
    configuration = document(configuration_original, MAX_CONFIG)
    payload = document(payload_original, MAX_DELIVERY, payload=True)
    require(configuration.get("apiVersion") == "serverware.responseObservationV2CustodyConfig/v1")
    authority = configuration.get("guestDeliveryAuthority")
    _fields(authority, ("apiVersion", "publicKeyBase64url", "keyId"))
    require(authority["apiVersion"] == AUTHORITY)
    key = Ed25519PrivateKey.from_private_bytes(signing_seed)
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    require(decoded(authority["publicKeyBase64url"], 32) == public
        and authority["keyId"] == digest(public) and generation_root != public)
    _fields(payload, ("configurationSha256", "authorityKeyId", "generationId", "generation",
        "serviceRole", "bootId", "issuedAtBoottimeNs", "deadlineBoottimeNs", "credentials"))
    require(payload["configurationSha256"] == _hash(expected_configuration_sha256)
        == digest(configuration_original) and payload["authorityKeyId"] == authority["keyId"]
        and type(payload["serviceRole"]) is str and payload["serviceRole"] in ROLES
        and type(payload["bootId"]) is str
        and re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", payload["bootId"])
        and type(payload["generation"]) is int and 1 <= payload["generation"] <= MAX_SAFE_INTEGER
        and type(payload["generationId"]) is str and 1 <= len(payload["generationId"].encode("utf-8")) <= 256)
    issued, deadline = _ns(payload["issuedAtBoottimeNs"]), _ns(payload["deadlineBoottimeNs"])
    require(0 < deadline - issued <= MAX_WINDOW_NS)

    topology = configuration.get("custodyTopology")
    require(type(topology) is dict and topology.get("attestationMode") == "tee-hardware"
        and topology.get("hardwareProof") is True
        and type(configuration.get("teeHardwareGenerationVerifier")) is dict
        and type(topology.get("generation")) is int
        and topology["generation"] == payload["generation"]
        and topology.get("generationId") == payload["generationId"])
    processes = topology.get("processes")
    require(type(processes) is list and len(processes) == len(ROLES))
    roles, selected = set(), None
    for process in processes:
        require(type(process) is dict and type(process.get("serviceRole")) is str
            and process["serviceRole"] in ROLES and process["serviceRole"] not in roles)
        roles.add(process["serviceRole"])
        role_keys = process.get("roleKeys")
        require(type(role_keys) is list and 1 <= len(role_keys) <= 64)
        for descriptor in role_keys:
            require(type(descriptor) is dict and _hash(descriptor.get("keyId")) != authority["keyId"])
        if process["serviceRole"] == payload["serviceRole"]:
            selected = process
    require(roles == ROLES and selected is not None)

    credentials = payload["credentials"]
    _fields(credentials, ("generationManifest", "trustAnchorPublicKey", "bootstrapManifests", "roleKeys"))
    originals = {}
    _pin(credentials["generationManifest"], originals)
    _pin(credentials["trustAnchorPublicKey"], originals)
    require(credentials["trustAnchorPublicKey"]["sha256"] == digest(generation_root))
    bootstrap = credentials["bootstrapManifests"]
    if payload["serviceRole"] == "state-authority":
        _fields(bootstrap, ("topologyManifest", "roleManifest", "keyManifest"))
        for pin in bootstrap.values():
            _pin(pin, originals)
    else:
        require(bootstrap is None)
    expected = {}
    for descriptor in selected["roleKeys"]:
        logical = descriptor.get("logicalRole")
        require(type(logical) is str and 1 <= len(logical) <= 256 and logical not in expected)
        require(descriptor["keyId"] == _hash(descriptor.get("publicKeySha256")))
        _path(descriptor.get("publicKeyPath"))
        _path(descriptor.get("secretKeyPath"))
        expected[logical] = descriptor
    delivered = credentials["roleKeys"]
    require(type(delivered) is list and len(delivered) == len(expected))
    seen = set()
    for material in delivered:
        _fields(material, ("logicalRole", "publicKey", "secretKey"))
        logical = material["logicalRole"]
        require(type(logical) is str and logical in expected and logical not in seen)
        seen.add(logical)
        _pin(material["publicKey"], originals)
        _pin(material["secretKey"], originals, secret=True)
        descriptor = expected[logical]
        require(material["publicKey"]["path"] == descriptor["publicKeyPath"]
            and material["secretKey"]["path"] == descriptor["secretKeyPath"]
            and material["publicKey"]["sha256"] == descriptor["publicKeySha256"])
    require(seen == set(expected))
    signature = key.sign(DOMAIN + canonical(payload))
    result = canonical({"apiVersion": ENVELOPE, "payload": payload,
                        "signatureBase64url": encoded(signature)})
    require(len(result) <= MAX_DELIVERY)
    return result
