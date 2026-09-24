"""Original-byte signatures for successor WebAuthn evidence claims.

These private mechanics authenticate the two fixed evidence purposes against
independently supplied key, identity, claim and time expectations. They do not
admit those expectations, authorize a registration or installation, or register
a transition. In particular, signing an arbitrary claims object does not prove
that installation or attestation occurred. Actual purpose-specific composers
must derive the claims from their real operations before calling the signer.

The complete original envelope has an acyclic identity: neither its signature
nor its resulting evidence digest occurs in the signed claims. Callers must
preserve that property in their purpose-specific schemas. Verification returns
no authority token. All work uses the original allowance; no clock, database,
key lookup, registry bypass, or legacy receipt interpretation is introduced.
"""
from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from serverware import authority_contract as authority
from serverware import authority_revocation_writer_acknowledgment as keys


plan, capability, production = keys.plan, keys.capability, keys.production
capture, wire = keys.capture, keys.wire
SCHEMA = "serverware.policyAuthorityWebAuthnEvidence/v1"
SIGNATURE_DOMAIN = "serverware.policyAuthorityWebAuthnEvidenceSignature/v1"
IDENTITY_DOMAIN = "serverware.policyAuthorityWebAuthnEvidenceIdentity/v1"
MAX_EVIDENCE_BYTES = authority.MAX_REQUEST_BYTES
MAX_EVIDENCE_NODES = 4096
MAX_EVIDENCE_DEPTH = 16
_CLAIM_SCHEMAS = {
    "registration-attestation": "serverware.policyAuthorityWebAuthnRegistrationAttestation/v2",
    "trust-installation": "serverware.policyAuthorityWebAuthnTrustInstallation/v2",
}
_IDENTITY_FIELDS = frozenset({"sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest"})
_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "signerIdentity", "signerSpkiDigest",
    "issuedAtEpochNs", "expiresAtEpochNs", "claims", "signatureBase64Url"})


class WebAuthnEvidenceError(ValueError):
    pass


class _Capture(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_EVIDENCE_DEPTH or self.nodes >= MAX_EVIDENCE_NODES:
            raise WebAuthnEvidenceError("WebAuthn evidence exceeds its local structure bounds")
        result = super().visit(value, depth, ancestors)
        if self.nodes > MAX_EVIDENCE_NODES:
            raise WebAuthnEvidenceError("WebAuthn evidence exceeds its node bound")
        return result


def _identity(value):
    plan.contract._object(value, _IDENTITY_FIELDS, "WebAuthn evidence signer identity")
    for field in _IDENTITY_FIELDS:
        plan.contract._digest(value[field])


def _claims(value, purpose):
    if type(purpose) is not str or purpose not in _CLAIM_SCHEMAS:
        raise WebAuthnEvidenceError("WebAuthn evidence purpose is not supported")
    if type(value) is not dict:
        raise WebAuthnEvidenceError("WebAuthn evidence claims are not an exact object")
    plan.contract._literal(value.get("schema"), _CLAIM_SCHEMAS[purpose])
    # The fixed consumer owns the complete purpose-specific field set. This
    # shared layer checks the domain and whole-graph equality, not semantics.


def _shape(envelope):
    plan.contract._object(envelope, _FIELDS, "WebAuthn evidence envelope")
    plan.contract._literal(envelope["schema"], SCHEMA)
    plan.contract._literal(envelope["sourceRevision"], authority.SOURCE_REVISION)
    _claims(envelope["claims"], envelope["purpose"])
    _identity(envelope["signerIdentity"])
    plan.contract._digest(envelope["signerSpkiDigest"])
    for field in ("issuedAtEpochNs", "expiresAtEpochNs"):
        plan.contract._integer(envelope[field], minimum=1)
    lifetime = envelope["expiresAtEpochNs"] - envelope["issuedAtEpochNs"]
    if not 0 < lifetime <= authority.VERIFIER_RESPONSE_MAX_AGE_NS:
        raise WebAuthnEvidenceError("WebAuthn evidence validity interval is outside source bounds")
    plan.contract._base64url(envelope["signatureBase64Url"], signature=True)


def _fresh(envelope, now_epoch_ns, maximum_age_ns, maximum_clock_skew_ns):
    plan.contract._integer(now_epoch_ns, minimum=1)
    plan.contract._integer(maximum_age_ns, authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    plan.contract._integer(maximum_clock_skew_ns, authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    issued, expires = envelope["issuedAtEpochNs"], envelope["expiresAtEpochNs"]
    if (issued > now_epoch_ns + maximum_clock_skew_ns
            or now_epoch_ns - issued > maximum_age_ns or now_epoch_ns >= expires
            or expires - issued > maximum_age_ns):
        raise WebAuthnEvidenceError("WebAuthn evidence is outside independently configured freshness")


def _decode_on_work(envelope_bytes, work):
    """Decode canonical original data only; this is not authentication."""
    ledger = capture._SharedLedger(work)
    envelope = wire._decode_object(envelope_bytes, work=work,
        maximum_bytes=MAX_EVIDENCE_BYTES, maximum_nodes=MAX_EVIDENCE_NODES,
        maximum_depth=MAX_EVIDENCE_DEPTH)
    _shape(envelope)
    capability._canonical(envelope_bytes, envelope, ledger, MAX_EVIDENCE_BYTES, MAX_EVIDENCE_NODES)
    return envelope


def _evidence_digest_on_work(envelope_bytes, work):
    """Commit original bytes without granting their claims any authority."""
    capture._SharedLedger(work)
    if type(envelope_bytes) is not bytes or not 2 <= len(envelope_bytes) <= MAX_EVIDENCE_BYTES:
        raise WebAuthnEvidenceError("WebAuthn evidence identity requires bounded original bytes")
    return plan._frame(IDENTITY_DOMAIN, (envelope_bytes,), work)


def _produce_on_work(*, purpose, claims, private_key, public_key, signer_identity,
        signer_spki_digest, issued_at_epoch_ns, expires_at_epoch_ns, work):
    """Sign owned claims; semantic production and signer admission are external."""
    try:
        ledger = capture._SharedLedger(work)
        _claims(claims, purpose)
        _identity(signer_identity)
        if not isinstance(private_key, Ed25519PrivateKey):
            raise WebAuthnEvidenceError("WebAuthn evidence signer is not Ed25519")
        unsigned = _Capture(ledger, maximum_bytes=MAX_EVIDENCE_BYTES).visit({
            "schema": SCHEMA, "sourceRevision": authority.SOURCE_REVISION, "purpose": purpose,
            "signerIdentity": signer_identity, "signerSpkiDigest": signer_spki_digest,
            "issuedAtEpochNs": issued_at_epoch_ns, "expiresAtEpochNs": expires_at_epoch_ns,
            "claims": claims})
        placeholder = {**unsigned, "signatureBase64Url": "A" * 86}
        _shape(placeholder)
        keys._public_binding(public_key, signer_spki_digest, work)
        keys._pair_on_work(private_key, public_key, work)
        unsigned_bytes = capability._wire(unsigned, ledger, MAX_EVIDENCE_BYTES, MAX_EVIDENCE_NODES)
        message = plan._ascii(plan._frame(SIGNATURE_DOMAIN, (unsigned_bytes,), work), work)
        final_size, final_nodes = work.measure(placeholder)
        if final_size > MAX_EVIDENCE_BYTES or final_nodes > MAX_EVIDENCE_NODES:
            raise WebAuthnEvidenceError("WebAuthn evidence signed output exceeds its bound")
        unsigned_size, unsigned_nodes = work.measure(unsigned)
        # Reserve the actual post-callback encoder/comparison and final output
        # before signing. Native Ed25519 internals keep their existing exclusion.
        work.charge(input_bytes=3 * unsigned_size + final_size + production._SIGNATURE_TRANSPORT_BYTES,
            json_nodes=unsigned_nodes + final_nodes)
        signature = production._sign_and_verify(private_key, public_key, message, work)
        if plan.core.canonical_bytes(unsigned) != unsigned_bytes:
            raise WebAuthnEvidenceError("WebAuthn evidence claims changed during signing")
        encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        plan.contract._base64url(encoded, signature=True)
        original = plan.core.canonical_bytes({**unsigned, "signatureBase64Url": encoded})
        if len(original) != final_size:
            raise WebAuthnEvidenceError("WebAuthn evidence final output changed")
        return original
    except keys._FAILURES as exc:
        if isinstance(exc, WebAuthnEvidenceError):
            raise
        raise WebAuthnEvidenceError("WebAuthn evidence signing failed") from exc


def _verify_on_work(*, envelope_bytes, purpose, expected_claims, public_key,
        expected_signer_identity, expected_signer_spki_digest, now_epoch_ns,
        maximum_age_ns, maximum_clock_skew_ns, work):
    """Actually verify original bytes and complete independent claims; no token."""
    try:
        ledger = capture._SharedLedger(work)
        _claims(expected_claims, purpose)
        _identity(expected_signer_identity)
        plan.contract._digest(expected_signer_spki_digest)
        expected = _Capture(ledger, maximum_bytes=MAX_EVIDENCE_BYTES).visit({
            "claims": expected_claims, "signerIdentity": expected_signer_identity})
        envelope = _decode_on_work(envelope_bytes, work)
        _fresh(envelope, now_epoch_ns, maximum_age_ns, maximum_clock_skew_ns)
        work.prepare_copy(envelope)
        unsigned = envelope.copy()
        encoded_signature = unsigned.pop("signatureBase64Url")
        unsigned_bytes = capability._wire(unsigned, ledger, MAX_EVIDENCE_BYTES, MAX_EVIDENCE_NODES)
        keys._public_binding(public_key, expected_signer_spki_digest, work)
        capability._signature(public_key, encoded_signature, SIGNATURE_DOMAIN, unsigned_bytes, ledger)
        capability._canonical(unsigned_bytes, unsigned, ledger, MAX_EVIDENCE_BYTES, MAX_EVIDENCE_NODES)
        capability._canonical(envelope_bytes, envelope, ledger, MAX_EVIDENCE_BYTES, MAX_EVIDENCE_NODES)
        plan._same((unsigned["purpose"], unsigned["signerSpkiDigest"], unsigned["signerIdentity"], unsigned["claims"]),
            (purpose, expected_signer_spki_digest, expected["signerIdentity"], expected["claims"]), work,
            "WebAuthn evidence differs from independently pinned purpose, signer or claims")
    except keys._FAILURES as exc:
        if isinstance(exc, WebAuthnEvidenceError):
            raise
        raise WebAuthnEvidenceError("WebAuthn evidence verification failed") from exc
