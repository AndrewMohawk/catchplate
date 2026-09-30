"""Explicit signed assignment v2; no reinterpretation of legacy bridge pins.

The fixed issuer consumes an independently approved canonical input exact5:
apiVersion=serverware.nativePilotAssignmentAuthorityInput/v1, trustOriginal,
trustSha256, payloadOriginal, closureSetOriginal. Originals are literal ASCII,
not paths. The complete selected payload includes all legacy native fields and
the required nativeClosureSet roots. Nothing invents or extends its timestamps,
fleet, policy, identities, provenance or authority. Existing independently
provisioned trust selects the matching assignment signing key. Public structural
checks and signatures are not native runtime/trusted-time/provenance acceptance.
Generic DB admission remains v1; this is the explicit native-only successor.
"""
from __future__ import annotations

import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from serverware import authority_policy_canary_native_opening as opening
from serverware import native_pilot_closure_set as closure_set
from serverware import native_shadow_nitro_profile as p

DOMAINS = {1: "serverware.policyShadowAssignment/v1", 2: "serverware.policyShadowAssignment/v2"}
MAX_BYTES = 4 * 1024 * 1024
MAX_INPUT = 8 * 1024 * 1024
FIELDS = ("apiVersion", "kind", "canonicalProfile", "signatureDomain", "payload", "payloadSha256",
    "signatureAlgorithm", "signingKeyId", "signingKeySpkiSha256", "signature")
INPUT_FIELDS = ("apiVersion", "trustOriginal", "trustSha256", "payloadOriginal", "closureSetOriginal")
NATIVE_FIELDS = ("assignmentId", "canaryId", "assignmentRevision", "generationEpoch", "minimumGenerationTombstoneEpoch",
    "policyIdentity", "expectedLoadedSnapshots", "responseValidationObligations", "responseValidationObligationsRootSha256",
    "fleet", "custodyAuthority", "authorityKeyIndependence", "observationWindow", "readinessThresholds",
    "issuedAtUnixNanos", "expiresAtUnixNanos")


def version(envelope: dict) -> int:
    p.require(type(envelope) is dict and type(envelope.get("apiVersion")) is str)
    selected = [number for number, api in DOMAINS.items() if envelope["apiVersion"] == api]
    p.require(len(selected) == 1)
    return selected[0]


def shape(envelope: dict) -> dict:
    """Closed native envelope grammar/hash only; the caller verifies its key."""
    p.fields(envelope, FIELDS)
    selected = version(envelope)
    payload = opening.assignment_payload(envelope["payload"], version=selected)
    p.fields(payload, NATIVE_FIELDS + (("nativeClosureSet",) if selected == 2 else ()))
    p.require(envelope["signatureDomain"] == DOMAINS[selected]
        and envelope["kind"] == "PolicyShadowAssignment"
        and envelope["canonicalProfile"] == "serverware.canonicalJson/ascii-integer-v1"
        and envelope["signatureAlgorithm"] == "Ed25519"
        and p.digest(envelope["payloadSha256"]) == p.sha(p.canonical(payload)))
    p.digest(envelope["signingKeyId"]); p.digest(envelope["signingKeySpkiSha256"])
    p.decoded(envelope["signature"], size=64)
    return envelope


def domain(envelope: dict) -> str:
    """Return only an explicit API-matched, shape-checked signature domain."""
    return shape(envelope)["signatureDomain"]


def closure_binding(envelope: dict, set_original: bytes, role: str) -> dict:
    """Join an authenticated v2 assignment to a static member, not live custody."""
    shape(envelope)
    p.require(version(envelope) == 2)
    payload = envelope["payload"]
    pins = payload["nativeClosureSet"]
    selected = closure_set.require_binding(set_original, expected_set_root=pins["setRootSha256"],
        expected_seccomp_set_root=pins["seccompSetRootSha256"])
    bridge = closure_set.leaf_binding(selected, "bridge")
    p.require(bridge["manifestSha256"] == payload["custodyAuthority"]["executionClosureManifestSha256"]
        and bridge["structurallyVerifiedPolicySha256"]
        == payload["custodyAuthority"]["structurallyVerifiedSeccompPolicySha256"])
    return closure_set.leaf_binding(selected, role)


def _original(text, maximum):
    p.require(type(text) is str and text.isascii() and 0 < len(text) <= maximum)
    raw = text.encode("ascii")
    return raw, p.document(raw, maximum)


def sign(*, input_original: bytes, signing_key) -> bytes:
    """Sign only the complete approved native v2 payload with its cold key."""
    # Local import avoids publication -> assignment -> publication cycles.
    from serverware import native_pilot_launch_publication as launch
    p.require(isinstance(signing_key, Ed25519PrivateKey))
    value = p.fields(p.document(input_original, MAX_INPUT), INPUT_FIELDS)
    p.require(value["apiVersion"] == "serverware.nativePilotAssignmentAuthorityInput/v1")
    trust_raw, _ = _original(value["trustOriginal"], 1024 * 1024)
    p.require(p.sha(trust_raw) == p.digest(value["trustSha256"]))
    trust = launch.shape("native-bridge-trust", trust_raw)
    payload_raw, payload = _original(value["payloadOriginal"], MAX_BYTES)
    opening.assignment_payload(payload, version=2)
    p.fields(payload, NATIVE_FIELDS + ("nativeClosureSet",))
    for name in ("assignmentId", "canaryId", "responseValidationObligationsRootSha256"):
        p.digest(payload[name])
    for name in ("assignmentRevision", "generationEpoch", "minimumGenerationTombstoneEpoch"):
        p.integer(payload[name])
    p.require(payload["minimumGenerationTombstoneEpoch"] <= payload["generationEpoch"])
    # The issuer preserves all supplied legacy payload bytes. Their operational
    # fleet/policy/threshold semantics remain the full native receiver's checks.
    opening._keys(payload, "custody-supervisor-capability")
    set_raw, _ = _original(value["closureSetOriginal"], 1024 * 1024)
    selected = closure_set.require_binding(set_raw,
        expected_set_root=payload["nativeClosureSet"]["setRootSha256"],
        expected_seccomp_set_root=payload["nativeClosureSet"]["seccompSetRootSha256"])
    bridge = closure_set.leaf_binding(selected, "bridge")
    p.require(bridge["manifestSha256"] == payload["custodyAuthority"]["executionClosureManifestSha256"]
        and bridge["structurallyVerifiedPolicySha256"]
        == payload["custodyAuthority"]["structurallyVerifiedSeccompPolicySha256"])
    now = time.time_ns()
    p.freshness(payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"], now)
    p.freshness(trust["issuedAtUnixNanos"], trust["expiresAtUnixNanos"], now)
    checkpoint = p.fields(trust["checkpoint"], ("checkpointId", "asOfUnixNanos", "revocationGeneration", "revocationRootSha256"))
    p.digest(checkpoint["checkpointId"]); p.digest(checkpoint["revocationRootSha256"])
    p.integer(checkpoint["revocationGeneration"], minimum=0, maximum=p.MAX_U64)
    p.require(p.integer(checkpoint["asOfUnixNanos"]) <= now < checkpoint["asOfUnixNanos"] + 300_000_000_000)
    authority = trust["assignmentKey"]
    public = launch._key(authority, now)
    launch._key(trust["timeKey"], now)
    actual = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(p.encoded(actual) == authority["publicKeyBase64url"])
    materials = {authority["publicKeyBase64url"], trust["timeKey"]["publicKeyBase64url"]}
    p.require(len(materials) == 2)
    keys = {}
    for row in trust["roleKeys"]:
        name, key = row["role"], row["key"]
        p.require(type(name) is str and name not in keys and key["publicKeyBase64url"] not in materials)
        launch._key(key, now); materials.add(key["publicKeyBase64url"]); keys[name] = key
    p.require(set(p.ROLES).issubset(keys))
    for role in p.ROLES:
        matches = [row for row in payload["authorityKeyIndependence"]["bindings"]
            if row["role"] == role and row["scopeSha256"] == payload["assignmentId"]]
        p.require(len(matches) == 1)
        row, key = matches[0], keys[role]
        p.require(row["keyId"] == key["keyId"] and row["keySpkiSha256"] == key["keySpkiSha256"])
        p.public_key({name: row[name] for name in ("role", "keyId", "keySpkiSha256", "keyMaterialSha256")}
            | {"publicKeyBase64url": key["publicKeyBase64url"]})
    floor = max(trust["issuedAtUnixNanos"], authority["notBeforeUnixNanos"])
    ceiling = min(trust["expiresAtUnixNanos"], authority["notAfterUnixNanos"])
    p.require(floor <= payload["issuedAtUnixNanos"] < payload["expiresAtUnixNanos"] <= ceiling)
    message = p.preimage(DOMAINS[2], payload)
    result = {"apiVersion": DOMAINS[2], "kind": "PolicyShadowAssignment",
        "canonicalProfile": "serverware.canonicalJson/ascii-integer-v1", "signatureDomain": DOMAINS[2],
        "payload": payload, "payloadSha256": p.sha(payload_raw), "signatureAlgorithm": "Ed25519",
        "signingKeyId": authority["keyId"], "signingKeySpkiSha256": authority["keySpkiSha256"],
        "signature": ""}
    # Signature encoding is exactly 86 ASCII bytes; reject an oversized full
    # envelope before using the signing capability, without fabricating a signature.
    p.require(len(p.canonical(result)) + 86 <= MAX_BYTES)
    signature = signing_key.sign(message)
    public.verify(signature, message)
    result["signature"] = p.encoded(signature)
    raw = p.canonical(shape(result))
    p.require(len(raw) <= MAX_BYTES)
    after = time.time_ns()
    p.require(now <= after < checkpoint["asOfUnixNanos"] + 300_000_000_000)
    p.freshness(payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"], after)
    p.freshness(trust["issuedAtUnixNanos"], trust["expiresAtUnixNanos"], after)
    return raw
