"""Offline, purpose-fixed issuer for the portal's existing Assignment/v1.

The authority operator independently approves the complete original input and
provisions its matching key. This module creates neither approval nor keys,
enrollment, current-head evidence, attestation verification or database effects.
It does not convert native Assignment/v2 or remove its closure commitments.
"""
from __future__ import annotations

import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from serverware import authority_policy_canary_native_opening as opening
from serverware import native_shadow_nitro_profile as p
from serverware.policy_shadow_assignment_fields import NATIVE_FIELDS

API = "serverware.policyShadowAssignmentAuthorityInput/v1"
DOMAIN = "serverware.policyShadowAssignment/v1"
MAX_INPUT = 32 * 1024 * 1024
MAX_ORIGINAL = 1024 * 1024
MAX_RECORD = 8 * 1024 * 1024
MAX_OUTPUT = 8 * 1024 * 1024
INPUT_FIELDS = ("apiVersion", "payloadOriginal", "recordOriginal", "authority")
AUTHORITY_FIELDS = ("evidenceKind", "signatureDomain", "publicKeyBase64url", "signingKeyId", "signingKeySpkiSha256")
DERIVED_FIELDS = frozenset((
    "assignment_envelope_digest", "assignment_payload_digest", "assignment_envelope_json",
    "assignment_payload_json", "signature_algorithm", "signing_key_id", "signature", "signature_digest",
))


def _original(text, maximum):
    p.require(type(text) is str and text.isascii() and 0 < len(text) <= maximum)
    raw = text.encode("ascii")
    return raw, p.document(raw, maximum)


def _event(record, payload_original, envelope, *, envelope_digest, signature_digest):
    return {"kind": "assignment", "record": {**record,
        "assignment_envelope_digest": envelope_digest,
        "assignment_payload_digest": envelope["payloadSha256"],
        "assignment_envelope_json": p.canonical(envelope).decode("ascii"),
        "assignment_payload_json": payload_original,
        "signature_algorithm": "Ed25519", "signing_key_id": envelope["signingKeyId"],
        "signature": envelope["signature"], "signature_digest": signature_digest}}


def prepare_input(input_original: bytes, *, now_epoch_ns: int) -> dict:
    """Validate approved originals without reading a private key or opening SQL."""
    from serverware import db

    value = p.fields(p.document(input_original, MAX_INPUT), INPUT_FIELDS)
    p.require(value["apiVersion"] == API)
    authority = p.fields(value["authority"], AUTHORITY_FIELDS)
    p.require(authority["evidenceKind"] == "canary_assignment" and authority["signatureDomain"] == DOMAIN)
    public_raw = p.decoded(authority["publicKeyBase64url"], size=32)
    public = Ed25519PublicKey.from_public_bytes(public_raw)
    spki = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    key_id = p.sha(spki)
    p.require(p.digest(authority["signingKeyId"]) == p.digest(authority["signingKeySpkiSha256"]) == key_id)

    payload_raw, payload = _original(value["payloadOriginal"], MAX_ORIGINAL)
    record_raw, record = _original(value["recordOriginal"], MAX_RECORD)
    # Admit precisely the existing native-bearing v1 shape, not legacy fields
    # derived by deleting v2 commitments. Every supplied payload byte is kept.
    opening.assignment_payload(payload, version=1)
    p.fields(payload, NATIVE_FIELDS)
    opening._keys(payload)
    for name in ("assignmentId", "canaryId", "responseValidationObligationsRootSha256"):
        p.digest(payload[name])
    for name in ("assignmentRevision", "generationEpoch", "minimumGenerationTombstoneEpoch"):
        p.integer(payload[name])
    p.require(payload["minimumGenerationTombstoneEpoch"] <= payload["generationEpoch"])
    p.require(all(key_id not in (row["keyId"], row["keySpkiSha256"])
        for row in payload["authorityKeyIndependence"]["bindings"]))

    fields = tuple(name for name in db._POLICY_CANARY_ASSIGNMENT_FIELDS if name not in DERIVED_FIELDS)
    record = db._candidate_authority_record("approved assignment projection", record, fields)
    # These are the consumer's pure encodings/contract checks, not staging or
    # a claim that the referenced artifact, keys or TEE evidence are admitted.
    db._candidate_authority_json("approved assignment payload", value["payloadOriginal"], p.sha(payload_raw))
    db._candidate_authority_json("approved assignment projection", value["recordOriginal"], p.sha(record_raw), maximum=MAX_RECORD)
    for name in fields:
        if name.endswith(("_digest", "_hash")):
            db._candidate_authority_digest(name, record[name])
    for name in ("assignment_id", "fleet_id"):
        db._candidate_authority_digest(name, record[name])
    for name in ("candidate_policy_sequence", "candidate_rollback_epoch", "predecessor_policy_sequence",
            "predecessor_rollback_epoch", "assignment_revision", "generation_epoch", "minimum_generation_tombstone_epoch",
            "membership_revision", "expected_instance_count", "minimum_evaluation_count"):
        db._candidate_authority_int(name, record[name], minimum=1)
    for name in ("created_at_epoch_ns", "issued_at_epoch_ns", "expires_at_epoch_ns"):
        db._candidate_authority_int(name, record[name])
    for name, maximum in (("canary_id", 256), ("policy_id", 256), ("created_by", 1024)):
        db._candidate_authority_text(name, record[name], maximum=maximum)
    db._policy_shadow_assert_direct_record_binding(
        evidence_kind="canary_assignment", payload=payload, record_binding=record)
    members = db._validate_policy_assignment_contract(record)
    now = p.integer(now_epoch_ns)
    issued, expires = payload["issuedAtUnixNanos"], payload["expiresAtUnixNanos"]
    p.require(record["created_at_epoch_ns"] == issued and issued <= now < expires)
    for member in members:
        for role in member["roles"]:
            p.require(role["key_id"] != key_id
                and role["not_before_epoch_ns"] <= issued < expires <= role["not_after_epoch_ns"])

    envelope = {"apiVersion": DOMAIN, "kind": "PolicyShadowAssignment",
        "canonicalProfile": "serverware.canonicalJson/ascii-integer-v1", "signatureDomain": DOMAIN,
        "payload": payload, "payloadSha256": p.sha(payload_raw), "signatureAlgorithm": "Ed25519",
        "signingKeyId": key_id, "signingKeySpkiSha256": key_id, "signature": ""}
    p.require(len(p.canonical(envelope)) + 86 <= MAX_ORIGINAL)
    # Exact future encoded lengths: the signature occurs in the envelope JSON
    # and record; the two digest slots each become 71 ASCII bytes. These empty
    # preflight slots are never emitted or accepted as signatures/digests.
    unsigned = _event(record, value["payloadOriginal"], envelope, envelope_digest="", signature_digest="")
    p.require(len(p.canonical(unsigned)) + 2 * 86 + 2 * 71 <= MAX_OUTPUT)
    return {"value": value, "record": record, "envelope": envelope, "public": public,
        "publicRaw": public_raw, "message": p.preimage(DOMAIN, payload), "expiresAtEpochNs": expires}


def sign(*, input_original: bytes, signing_key, check=None) -> bytes:
    """Emit one existing assignment event, never install, send or approve it."""
    p.require(isinstance(signing_key, Ed25519PrivateKey) and (check is None or callable(check)))
    before_boot, before = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
    prepared = prepare_input(input_original, now_epoch_ns=before)
    expires = prepared["expiresAtEpochNs"]
    deadline = before_boot + expires - before
    previous_boot, previous_wall = before_boot, before

    def current():
        nonlocal previous_boot, previous_wall
        if check is not None:
            check()
        now_boot, now_wall = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
        p.require(previous_boot <= now_boot < deadline and previous_wall <= now_wall < expires)
        previous_boot, previous_wall = now_boot, now_wall

    current()
    actual = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    p.require(actual == prepared["publicRaw"])
    current()  # Public validation/key matching cannot consume the signing interval.
    signature = signing_key.sign(prepared["message"])
    current()
    prepared["public"].verify(signature, prepared["message"])
    current()
    envelope = {**prepared["envelope"], "signature": p.encoded(signature)}
    envelope_raw = p.canonical(envelope)
    event = _event(prepared["record"], prepared["value"]["payloadOriginal"], envelope,
        envelope_digest=p.sha(envelope_raw), signature_digest=p.sha(signature))
    raw = p.canonical(event)
    p.require(len(raw) <= MAX_OUTPUT)
    current()
    return raw
