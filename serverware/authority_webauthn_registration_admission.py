"""Genuine original registration verification before a proposed v2 row effect.

The caller independently admits the ceremony, complete trust-root snapshot,
challenge/authorization/predecessor rows, signer pins, fresh check time and
selected evidence descriptor. This worker does not authenticate SQL selection,
root currentness, enrollment permission or the descriptor's absence proof.
It invokes the real shared registration cryptography itself, derives the
expected claims and verifies the original evidence; no claims or successful
verification result is accepted as input.

The historical context time determines the signed issuance and challenge- /
OIDC-clipped expiry. Fresh receipt verification uses a separate supplied time;
neither instant is sampled or substituted here. Native cryptographic internals
retain the shared core's explicit bounded boundary. All source-visible work
uses the original meter without an added allowance.

The returned selected/proposed-row pair is ordinary planning data. None means
only an exact unused verified duplicate, never consumed evidence or permission
to skip verification. There is no signer, SQL, durable admission, root update,
ACL change, operation registration or execution in this module.
"""
from __future__ import annotations

from serverware import authority_webauthn_registration_production as production


registration, evidence = production.registration, production.evidence


class WebAuthnRegistrationAdmissionError(ValueError):
    pass


def _admit_on_work(*, envelope_bytes, selected_evidence,
        client_data_json, attestation_object, credential_id, transports,
        scope, verification_context, challenge_row, expected_authorization,
        high_water_row, published_row, oidc_session_row, sibling_challenge_ids,
        public_key, expected_signer_identity, expected_signer_spki_digest,
        now_epoch_ns, maximum_age_ns, maximum_clock_skew_ns, work):
    """Return (owned selected evidence, actual verified row or exact-duplicate None)."""
    ledger = evidence.capture._SharedLedger(work)
    if type(envelope_bytes) is not bytes or not 2 <= len(envelope_bytes) <= evidence.MAX_EVIDENCE_BYTES:
        raise WebAuthnRegistrationAdmissionError("registration admission requires the bounded original envelope")
    if not isinstance(public_key, evidence.keys.Ed25519PublicKey):
        raise WebAuthnRegistrationAdmissionError("registration admission requires its pinned Ed25519 public key")
    # Exact immutable pins and fresh check time are held before any native or
    # key callback. No subsequent read consults a caller-owned pin container.
    evidence.plan.contract._digest(expected_signer_spki_digest)
    evidence.plan.contract._integer(now_epoch_ns, minimum=1)
    evidence.plan.contract._integer(maximum_age_ns, production.authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    evidence.plan.contract._integer(maximum_clock_skew_ns, production.authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    owned = evidence.capture._JSONCapture(ledger).visit({
        "selected": selected_evidence, "identity": expected_signer_identity})
    selected, identity = owned["selected"], owned["identity"]
    evidence._identity(identity)
    evidence.plan.contract._object(selected, evidence.capture._SELECTED_FIELDS, "registration evidence selection")
    evidence.plan.contract._literal(selected["table"], evidence.EVIDENCE_TABLE)
    evidence.plan.contract._object(selected["key"], frozenset({"evidence_digest"}), "registration evidence primary key")
    evidence.plan.contract._digest(selected["key"]["evidence_digest"])
    evidence.plan.contract._digest(selected["keyDigest"])
    if (selected["contractSelector"] is not None or type(selected["present"]) is not bool
            or selected["present"] and type(selected["row"]) is not dict
            or not selected["present"] and selected["row"] is not None):
        raise WebAuthnRegistrationAdmissionError("registration evidence selection has no exact presence/row shape")
    # The shared worker first owns every remaining ceremony, root and semantic
    # input, then performs the actual parser/attestation verification. It is
    # called here, not supplied as a successful observation by another caller.
    claims, _, identity, issued_ns, expires_ns = production._claims_on_work(
        client_data_json=client_data_json, attestation_object=attestation_object,
        credential_id=credential_id, transports=transports, scope=scope,
        verification_context=verification_context, challenge_row=challenge_row,
        expected_authorization=expected_authorization, high_water_row=high_water_row,
        published_row=published_row, oidc_session_row=oidc_session_row,
        sibling_challenge_ids=sibling_challenge_ids, signer_identity=identity,
        maximum_age_ns=maximum_age_ns, work=work)
    # Decoding alone is not authentication. Bind the actual original's timing
    # to the genuine historical derivation before verifying the full original
    # at the separately held fresh receipt time. Do not retime expired evidence.
    envelope = evidence._decode_on_work(envelope_bytes, work)
    registration._same((envelope["issuedAtEpochNs"], envelope["expiresAtEpochNs"]),
        (issued_ns, expires_ns), work, "registration evidence historical issuance or clipped expiry changed")
    verified_row = evidence._verified_row_on_work(envelope_bytes=envelope_bytes,
        purpose="registration-attestation", expected_claims=claims, public_key=public_key,
        expected_signer_identity=identity, expected_signer_spki_digest=expected_signer_spki_digest,
        now_epoch_ns=now_epoch_ns, maximum_age_ns=maximum_age_ns,
        maximum_clock_skew_ns=maximum_clock_skew_ns, work=work)
    # Only the just-derived and genuinely verified row reaches the mechanical
    # absent/identical/conflicting-row comparison; it confers no persistence.
    return evidence._admission_effect_on_work(selected, verified_row, work)
