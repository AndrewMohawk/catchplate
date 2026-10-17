"""Fixed original-byte installation evidence admission, without persistence.

The caller independently admits the physical installed/read-back originals,
committed stage and current publication/high-water rows, target, installer pins,
original observation time and fresh admission time. Supplied bytes or selected
row descriptors do not establish those authorities. This worker recomputes the
actual completion claims and genuinely verifies the original signed envelope;
it accepts no expected-claims graph, verified row or successful-proof DTO.

The original observation instant binds the signed issuance and configured
lifetime exactly. Fresh verification never retimes the installation or signed
original. The returned selected/row pair is only an ordinary proposed effect;
None denotes an identical unused verified row, not consumed or revoked evidence.
There is no SQL, filesystem access, clock, configuration lookup, durable write,
execution or registry admission here. A real owner must still authenticate the
selected row/current roots and atomically persist any proposed row. All actual
source-visible capture, decoding, comparison and verification uses the original
work allowance; native parser/crypto resource exclusions remain unchanged.
"""
from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from catchplate import authority_transition_webauthn_completion as completion


authority, evidence = completion.authority, completion.evidence


class WebAuthnInstallationAdmissionError(ValueError):
    pass


def _admit_on_work(*, installation_envelope_bytes, installed_bundle_bytes,
        installed_state_bytes, publication_row, high_water_row,
        expected_committed_stage, installation_target_digest, observed_at,
        now_epoch_ns, selected_evidence, installer_public_key,
        expected_installer_identity, expected_installer_spki_digest,
        maximum_age_ns, maximum_clock_skew_ns, work):
    """Return owned selected evidence and its verified insertion row or None."""
    ledger = evidence.capture._SharedLedger(work)
    for raw, maximum in (
            (installation_envelope_bytes, evidence.MAX_EVIDENCE_BYTES),
            (installed_bundle_bytes, completion.bundle_core.MAX_INSTALLATION_BYTES),
            (installed_state_bytes, completion.bundle_core.MAX_STATE_BYTES)):
        if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
            raise WebAuthnInstallationAdmissionError("installation admission requires bounded original bytes")
    if not isinstance(installer_public_key, Ed25519PublicKey):
        raise WebAuthnInstallationAdmissionError("installation admission requires the configured Ed25519 key")
    observed_ns = completion._now(observed_at)
    completion._integer(now_epoch_ns, "fresh installation admission time", 1)
    evidence.plan.contract._integer(maximum_age_ns, authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    evidence.plan.contract._integer(maximum_clock_skew_ns, authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    expires_ns = observed_ns + maximum_age_ns
    completion._integer(expires_ns, "original installation evidence expiry", 1)
    evidence.plan.contract._digest(installation_target_digest)
    evidence.plan.contract._digest(expected_installer_spki_digest)
    owned = evidence.capture._JSONCapture(ledger).visit({
        "publication": publication_row, "highWater": high_water_row,
        "stage": expected_committed_stage, "selected": selected_evidence,
        "identity": expected_installer_identity, "target": installation_target_digest,
        "signerSpkiDigest": expected_installer_spki_digest,
        "observedEpochNs": observed_ns, "expiresEpochNs": expires_ns,
        "nowEpochNs": now_epoch_ns, "maximumAgeNs": maximum_age_ns,
        "maximumClockSkewNs": maximum_clock_skew_ns})
    evidence._identity(owned["identity"])
    selected = owned["selected"]
    completion._object(selected, evidence.capture._SELECTED_FIELDS, "selected installation evidence")
    completion._object(selected["key"], frozenset({"evidence_digest"}), "installation evidence key")
    evidence.plan.contract._digest(selected["key"]["evidence_digest"])
    evidence.plan.contract._digest(selected["keyDigest"])
    if (selected["table"] != evidence.EVIDENCE_TABLE or selected["contractSelector"] is not None
            or type(selected["present"]) is not bool
            or (selected["present"] and type(selected["row"]) is not dict)
            or (not selected["present"] and selected["row"] is not None)):
        raise WebAuthnInstallationAdmissionError("installation evidence selection has an invalid table or row")
    claims, _, _, _, _, _ = completion._installation_claims_on_work(
        installed_bundle_bytes=installed_bundle_bytes, installed_state_bytes=installed_state_bytes,
        publication_row=owned["publication"], high_water_row=owned["highWater"],
        expected_committed_stage=owned["stage"], installation_target_digest=owned["target"],
        observed_at=observed_at, work=work)
    # This extra real canonical decode binds the original observation/lifetime;
    # it is data only and never substitutes for the subsequent signature check.
    envelope = evidence._decode_on_work(installation_envelope_bytes, work)
    completion._same((envelope["issuedAtEpochNs"], envelope["expiresAtEpochNs"]),
        (owned["observedEpochNs"], owned["expiresEpochNs"]), work,
        "installation evidence changed its original observation or configured lifetime")
    verified = evidence._verified_row_on_work(
        envelope_bytes=installation_envelope_bytes, purpose="trust-installation",
        expected_claims=claims, public_key=installer_public_key,
        expected_signer_identity=owned["identity"], expected_signer_spki_digest=owned["signerSpkiDigest"],
        now_epoch_ns=owned["nowEpochNs"], maximum_age_ns=owned["maximumAgeNs"],
        maximum_clock_skew_ns=owned["maximumClockSkewNs"], work=work)
    return evidence._admission_effect_on_work(selected, verified, work)
