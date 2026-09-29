"""Closed public grammar for the independent native shadow Nitro verifier.

This module is not a custody owner, a signing API, or a verification verdict.
Its canonical bytes exactly follow the existing Rust ASCII/integer profile.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAX_I64 = (1 << 63) - 1
MAX_U64 = (1 << 64) - 1
MAX_CONFIG = 512 * 1024
MAX_REQUEST = 128 * 1024
MAX_RESULT = 32 * 1024
DAY_NS = 86_400_000_000_000
ROLES = (
    "custody-ingress-admission", "custody-unavailable-ingress", "custody-dispatch-barrier",
    "custody-terminal-append", "custody-ledger-append", "custody-spool-compaction",
    "custody-active-effect-barrier", "custody-active-effect-commit",
    "custody-publication-reconciliation", "custody-activation-publication",
    "custody-result-envelope", "custody-store-response", "custody-signer-response",
    "custody-retrieval-response", "custody-trusted-time-response", "custody-provider-response",
    "custody-attestation-verifier", "custody-supervisor-capability",
)
ASSIGNMENT_DOMAIN = "serverware.nativeShadowRoleKeyAssignment.signature/v1"
POSSESSION_DOMAIN = "serverware.nativeShadowRoleKeyPossession.signature/v1"
RESULT_DOMAIN = "serverware.policyShadowCustodyAttestationVerifier/v1"
EVIDENCE_PREFIX = b"serverware/native-shadow-role-key-evidence/v1\0"
CONFIG_FIELDS = frozenset(("apiVersion", "uid", "gid", "operation", "authorization", "expectedStatement",
    "authorityKeys", "trustCheckpoint", "nitro", "collateralRevocation", "expectedAttestation", "maximumResultAgeNanos"))
AUTH_FIELDS = frozenset(("apiVersion", "profile", "purpose", "assignmentId", "assignmentPayloadSha256",
    "assignmentRevision", "executionClosureManifestSha256", "guest", "fullKeySetRootSha256", "localRoles",
    "challengeBase64url", "trustCheckpointId", "revocationGeneration", "revocationRootSha256",
    "issuedAtUnixNanos", "expiresAtUnixNanos", "signingKeyId", "signingKeySpkiSha256"))
STATEMENT_FIELDS = frozenset(("apiVersion", "purpose", "assignmentId", "assignmentPayloadSha256", "assignmentRevision",
    "keyAuthorizationSha256", "guest", "productionConfigurationBindingSha256", "executionClosureManifestSha256",
    "structurallyVerifiedSeccompPolicySha256", "workerExecutableSha256", "fullKeySetRootSha256", "localKeySetRootSha256",
    "localKeys", "challengeBase64url"))
GUEST_FIELDS = frozenset(("configurationSha256", "deliverySha256", "runtimeConfigurationSha256", "serviceRole", "uid", "gid",
    "bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode", "issuedAtBoottimeNs", "startupDeadlineBoottimeNs",
    "lifetimeDeadlineBoottimeNs", "invocationId"))
PUBLIC_KEY_FIELDS = frozenset(("role", "keyId", "keySpkiSha256", "keyMaterialSha256", "publicKeyBase64url"))
EVIDENCE_FIELDS = frozenset(("apiVersion", "statement", "possession", "attestationDocumentBase64url", "userDataBase64url",
    "publicKeyBase64url", "nonceBase64url"))
RESULT_FIELDS = (
    "platform", "quoteSha256", "endorsementEvidenceSha256", "endorsementRootSha256", "collateralPolicySha256",
    "revocationSourceSha256", "collateralRevocationGeneration", "collateralRevocationRootSha256", "measurementSha256",
    "productionConfigurationBindingSha256", "workerExecutableSha256", "executionClosureManifestSha256",
    "structurallyVerifiedSeccompPolicySha256", "quoteBoundCustodyKeySetRootSha256", "verifiedAtUnixNanos", "expiresAtUnixNanos",
    "trustCheckpointId", "trustRevocationGeneration", "trustRevocationRootSha256", "signingKeyId", "signingKeySpkiSha256", "signature",
)


def require(value):
    if not value:
        raise ValueError("native shadow Nitro verification refused")


def fields(value, names):
    require(type(value) is dict and set(value) == set(names))
    return value


def integer(value, minimum=1, maximum=MAX_I64):
    require(type(value) is int and minimum <= value <= maximum)
    return value


def ns(value):
    require(type(value) is str and re.fullmatch(r"[1-9][0-9]{0,19}", value))
    return integer(int(value), maximum=MAX_U64)


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def digest(value):
    require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value)
        and value != "sha256:" + "0" * 64)
    return value


def raw_digest(value):
    return bytes.fromhex(digest(value)[7:])


def encoded(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decoded(value, *, size=None, maximum=12 * 1024):
    require(type(value) is str and 1 <= len(value) <= (maximum * 4 + 2) // 3
        and re.fullmatch(r"[A-Za-z0-9_-]+", value))
    raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    require(encoded(raw) == value and 1 <= len(raw) <= maximum and (size is None or len(raw) == size))
    return raw


def _pairs(items):
    value = {}
    for name, child in items:
        require(name not in value)
        value[name] = child
    return value


def _reject(_):
    raise ValueError("native shadow profile forbids floating-point numbers")


def canonical(value):
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        require(depth <= 32 and count <= 16384)
        if type(item) is dict:
            require(all(type(key) is str and key.isascii() for key in item))
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) in (tuple, list):
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            require(item.isascii())
        elif type(item) is int:
            integer(item, minimum=-(1 << 63))
        else:
            require(item is None or type(item) is bool)
    # ensure_ascii=False preserves ASCII DEL exactly like the Rust codec.
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")


def document(raw, maximum):
    require(type(raw) is bytes and 1 <= len(raw) <= maximum)
    value = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs, parse_float=_reject, parse_constant=_reject)
    require(type(value) is dict and canonical(value) == raw)
    return value


def preimage(domain, payload):
    return b"serverware.signedEnvelope/v1\0" + domain.encode("ascii") + b"\0serverware.canonicalJson/ascii-integer-v1\0" + canonical(payload)


def framed(domain, parts):
    return sha(domain + b"\0" + b"".join(len(part).to_bytes(8, "big") + part for part in parts))


def public_key(value):
    fields(value, PUBLIC_KEY_FIELDS)
    require(value["role"] in ROLES)
    for name in ("keyId", "keySpkiSha256", "keyMaterialSha256"):
        digest(value[name])
    raw = decoded(value["publicKeyBase64url"], size=32)
    require(raw != bytes(32))
    key = Ed25519PublicKey.from_public_bytes(raw)
    spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    require(sha(spki) == value["keySpkiSha256"]
        and framed(b"serverware.policyAuthorityPublicKeyMaterial/v1", (b"ed25519", spki)) == value["keyMaterialSha256"])
    return key


def key_root(values):
    level = []
    for index, value in enumerate(values, 1):
        leaf = framed(b"serverware.policyShadowCustodyAssertedKey/v1", (canonical([
            value["role"], value["keyId"], value["keySpkiSha256"], value["keyMaterialSha256"]]),))
        level.append(hashlib.sha256(b"serverware.policyShadowMerkleLeaf/v1\0" + index.to_bytes(8, "big") + raw_digest(leaf)).digest())
    require(bool(level))
    while len(level) > 1:
        level = [level[index] if index + 1 == len(level) else hashlib.sha256(
            b"serverware.policyShadowMerkleNode/v1\x01" + level[index] + level[index + 1]).digest()
            for index in range(0, len(level), 2)]
    return "sha256:" + level[0].hex()


def freshness(issued, expires, now, maximum_age=DAY_NS):
    integer(issued); integer(expires); integer(now)
    require(issued <= now < expires and now - issued <= maximum_age)


def guest(value):
    fields(value, GUEST_FIELDS)
    for name in ("configurationSha256", "deliverySha256", "runtimeConfigurationSha256"):
        digest(value[name])
    require(value["serviceRole"] in {"durable-recovery-store", "cleanup-authorization-consumer", "recovery-target-provider",
        "current-signature-authority", "bounded-cleanup-helper", "production-bridge"})
    for name in ("uid", "gid"):
        integer(value[name], maximum=(1 << 32) - 2)
        require(value[name] not in {64988, 64989, 64990, 65534})
    require(decoded(value["bootIdBase64url"], size=16) != bytes(16))
    integer(value["timeNamespaceDevice"]); integer(value["timeNamespaceInode"])
    require(ns(value["issuedAtBoottimeNs"]) < ns(value["startupDeadlineBoottimeNs"]) <= ns(value["lifetimeDeadlineBoottimeNs"]))
    require(type(value["invocationId"]) is str and re.fullmatch(r"[0-9a-f]{32}", value["invocationId"])
        and value["invocationId"] != "0" * 32)


def authorization(config, now):
    fields(config, CONFIG_FIELDS)
    require(config["apiVersion"] == "serverware.nativeShadowNitroVerifierConfiguration/v1")
    auth = fields(config["authorization"], ("payload", "signature"))
    p = fields(auth["payload"], AUTH_FIELDS)
    s = fields(config["expectedStatement"], STATEMENT_FIELDS)
    checkpoint = fields(config["trustCheckpoint"], ("checkpointId", "asOfUnixNanos", "revocationGeneration", "revocationRootSha256"))
    require(p["apiVersion"] == "serverware.nativeShadowRoleKeyAssignment/v1"
        and p["profile"] == "preassigned-final-role-originals-v1" and p["purpose"] == "shadow-role-key-possession"
        and s["apiVersion"] == "serverware.nativeShadowRoleKeyStatement/v1" and s["purpose"] == "local-key-possession")
    guest(p["guest"]); guest(s["guest"])
    require(canonical(s["guest"]) == canonical(p["guest"]))
    for name in ("assignmentId", "assignmentPayloadSha256", "executionClosureManifestSha256", "fullKeySetRootSha256"):
        require(digest(p[name]) == digest(s[name]))
    require(integer(p["assignmentRevision"]) == integer(s["assignmentRevision"]))
    require(s["keyAuthorizationSha256"] == sha(canonical(auth)))
    for name in ("productionConfigurationBindingSha256", "structurallyVerifiedSeccompPolicySha256", "workerExecutableSha256", "localKeySetRootSha256"):
        digest(s[name])
    require(s["challengeBase64url"] == p["challengeBase64url"]
        and decoded(p["challengeBase64url"], size=32) != bytes(32))
    freshness(p["issuedAtUnixNanos"], p["expiresAtUnixNanos"], now)
    require(integer(checkpoint["asOfUnixNanos"]) <= now <= checkpoint["asOfUnixNanos"] + 300_000_000_000
        and p["trustCheckpointId"] == digest(checkpoint["checkpointId"])
        and integer(p["revocationGeneration"]) == integer(checkpoint["revocationGeneration"])
        and p["revocationRootSha256"] == digest(checkpoint["revocationRootSha256"]))
    keys = config["authorityKeys"]
    require(type(keys) is list and len(keys) == 18)
    for index, item in enumerate(keys):
        public_key(item)
        require(item["role"] == ROLES[index])
    for name in ("keyId", "keySpkiSha256", "keyMaterialSha256"):
        require(len({item[name] for item in keys}) == 18)
    require(key_root(keys) == p["fullKeySetRootSha256"])
    roles = p["localRoles"]
    require(type(roles) is list and 1 <= len(roles) <= 16 and all(role in ROLES[:16] for role in roles)
        and roles == sorted(set(roles), key=ROLES.index))
    local = [keys[ROLES.index(role)] for role in roles]
    require(s["localKeys"] == local and key_root(local) == s["localKeySetRootSha256"])
    supervisor = keys[-1]
    require(p["signingKeyId"] == supervisor["keyId"] and p["signingKeySpkiSha256"] == supervisor["keySpkiSha256"])
    public_key(supervisor).verify(decoded(auth["signature"], size=64), preimage(ASSIGNMENT_DOMAIN, p))
    integer(config["maximumResultAgeNanos"], maximum=30_000_000_000)
    return s, keys


def result_payload(result):
    # This is EXACTLY CustodyTeeAttestationVerifierResultWire::canonical_payload,
    # not a new verifier-success signature family.
    fields(result, RESULT_FIELDS[:-1])
    return ["serverware.policyShadowCustodyTeeAttestationResult/v1",
        [result[name] for name in RESULT_FIELDS[:9]], [result[name] for name in RESULT_FIELDS[9:21]]]
