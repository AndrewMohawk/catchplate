"""Purpose-fixed offline producer for the independently operated compiler key.

It signs a complete analysis; it cannot generate keys, contact the control
plane, bypass current key enrollment, or authorize native delivery by itself.
"""
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from serverware import authority_policy_canary as p
from serverware import authority_policy_canary_native_opening as opening
from serverware import authority_policy_canary_native_pilot as pilot

SCHEMA = "serverware.nativePilotInventoryPublication/v1"
DOMAIN = "serverware.policyAuthorityAnalysis/v1"


def _message(domain, payload):
    from serverware import db
    return b"\0".join((db._POLICY_AUTHORITY_SIGNATURE_FRAME, domain.encode("ascii"),
        db._POLICY_AUTHORITY_CANONICAL_PROFILE.encode("ascii"), p.canonical(payload)))


def produce(value, *, compiler_key, assignment_public_key, now_epoch_ns):
    from serverware import db
    p.require(type(value) is dict and set(value) == {"apiVersion", "assignmentEnvelope", "analysisPayload", "recordBinding"}
        and value["apiVersion"] == SCHEMA and isinstance(compiler_key, Ed25519PrivateKey)
        and isinstance(assignment_public_key, Ed25519PublicKey))
    envelope = value["assignmentEnvelope"]
    p.require(type(envelope) is dict and set(envelope) == {"apiVersion", "kind", "canonicalProfile", "signatureDomain",
        "payload", "payloadSha256", "signatureAlgorithm", "signingKeyId", "signingKeySpkiSha256", "signature"})
    assignment = opening.assignment_payload(envelope["payload"])
    domain = db._POLICY_AUTHORITY_EVIDENCE_DOMAINS["canary_assignment"]
    spki = p.sha256(assignment_public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
    p.require(envelope["apiVersion"] == envelope["signatureDomain"] == domain and envelope["kind"] == "PolicyShadowAssignment"
        and envelope["canonicalProfile"] == db._POLICY_AUTHORITY_CANONICAL_PROFILE and envelope["signatureAlgorithm"] == "Ed25519"
        and envelope["signingKeyId"] == envelope["signingKeySpkiSha256"] == spki
        and envelope["payloadSha256"] == p.sha256(p.canonical(assignment)))
    signature = db._candidate_authority_b64url("assignment signature", envelope["signature"], expected_bytes=64)
    assignment_public_key.verify(signature, _message(domain, assignment))
    payload = value["analysisPayload"]
    p.require(type(payload) is dict and set(payload) == db._POLICY_SHADOW_DIRECT_PAYLOAD_FIELDS["compiler_analysis"])
    pilot.validate(payload["pilotRestrictions"])
    p.require(payload["authorityAnalysis"] == {"mode": "approved-expansion", "expansionCells": payload["pilotRestrictions"]["cells"],
        "approvalMode": payload["authorityAnalysis"].get("approvalMode")}
        and payload["authorityAnalysis"]["approvalMode"] in {"single-person-hardware-webauthn", "two-person-hardware-webauthn"})
    p.epoch(now_epoch_ns)
    for source in (assignment, payload):
        p.epoch(source["issuedAtUnixNanos"]); p.epoch(source["expiresAtUnixNanos"])
    p.require(assignment["issuedAtUnixNanos"] <= payload["issuedAtUnixNanos"] <= now_epoch_ns
        < payload["expiresAtUnixNanos"] <= assignment["expiresAtUnixNanos"]
        and payload["assignmentSha256"] == p.sha256(p.canonical(envelope))
        and payload["assignmentPayloadSha256"] == envelope["payloadSha256"]
        and payload["assignmentRevision"] == assignment["assignmentRevision"]
        and payload["canaryId"] == assignment["canaryId"]
        and payload["policyIdentity"] == assignment["policyIdentity"]
        and payload["expectedLoadedSnapshots"] == assignment["expectedLoadedSnapshots"]
        and payload["responseValidationObligationsRootSha256"] == assignment["responseValidationObligationsRootSha256"])
    public = compiler_key.public_key()
    identity = p.sha256(public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
    pilot.compiler_key(assignment, identity, public)
    binding = value["recordBinding"]
    excluded = {"analysis_envelope_json", "analysis_envelope_digest", "analysis_payload_json", "analysis_payload_digest",
        "signature_algorithm", "signing_key_id", "signature", "signature_digest", "actor_id"}
    p.require(type(binding) is dict and set(binding) == set(db._POLICY_COMPILER_AUTHORITY_ANALYSIS_FIELDS) - excluded)
    db._policy_shadow_assert_direct_record_binding(evidence_kind="compiler_analysis", payload=payload, record_binding=binding)
    p.require(binding["analysis_mode"] == "approved-expansion" and binding["approval_mode"] == payload["authorityAnalysis"]["approvalMode"]
        and binding["required_approval_quorum"] == (2 if binding["approval_mode"] == "two-person-hardware-webauthn" else 1))
    signed = compiler_key.sign(_message(DOMAIN, payload))
    encoded = base64.urlsafe_b64encode(signed).rstrip(b"=").decode("ascii")
    original = {"apiVersion": DOMAIN, "kind": "PolicyAuthorityAnalysis", "canonicalProfile": db._POLICY_AUTHORITY_CANONICAL_PROFILE,
        "signatureDomain": DOMAIN, "payload": payload, "payloadSha256": p.sha256(p.canonical(payload)),
        "signatureAlgorithm": "Ed25519", "signingKeyId": identity, "signingKeySpkiSha256": identity, "signature": encoded}
    record = {**binding, "analysis_envelope_json": p.canonical(original).decode("ascii"), "analysis_envelope_digest": p.sha256(p.canonical(original)),
        "analysis_payload_json": p.canonical(payload).decode("ascii"), "analysis_payload_digest": original["payloadSha256"],
        "signature_algorithm": "Ed25519", "signing_key_id": identity, "signature": encoded, "signature_digest": p.sha256(signed), "actor_id": identity}
    p.require(set(record) == set(db._POLICY_COMPILER_AUTHORITY_ANALYSIS_FIELDS) and len(p.canonical(record)) <= 512 * 1024)
    return {"kind": "compiler-analysis", "record": record}
