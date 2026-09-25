"""Shared held-policy joins for evidence-admission plan verification/custody.

An exact immutable tuple holds one source operation, independently admitted
public keys, identity triples, configuration and purpose-policy pins. This
module validates that shape and owns independent historical expectations before
real key/SPKI callbacks. It does not enroll keys, admit configuration or history,
or accept a successful verifier carrier. The returned eighteen-field dictionary
is ordinary owned data; genuine original-byte/proof/semantic replay must follow.

No DSN, SQL, registry activation, clock sample, signer, retry, callback parameter
or new allowance is introduced. Both actual key checks and every variable
capture/comparison spend the original caller's work.
"""
from __future__ import annotations

from serverware import authority_revocation_root_reader as reader
from serverware import authority_webauthn_evidence_plan as plan


evidence = plan.evidence
_IDENTITY_FIELDS = ("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")
_REGISTRATION = "webauthn.registration.evidence.admit"


class WebAuthnEvidencePlanAdmissionError(ValueError):
    pass


def _validate_pins(pins):
    """Return the same exact tuple13 after callback-free fixed-pin checks."""
    if type(pins) is not tuple or len(pins) != 13:
        raise WebAuthnEvidencePlanAdmissionError("evidence plan pins are not an exact thirteen-tuple")
    (operation, planner_key, planner_identity, planner_spki, evidence_key,
        evidence_identity, evidence_spki, configuration_digest, age, skew,
        rp_id, origin, target) = pins
    if type(operation) is not str or operation not in plan.contract.OPERATIONS:
        raise WebAuthnEvidencePlanAdmissionError("evidence plan operation is not source fixed")
    if (not isinstance(planner_key, plan.Ed25519PublicKey)
            or not isinstance(evidence_key, plan.Ed25519PublicKey)):
        raise WebAuthnEvidencePlanAdmissionError("evidence plan requires real Ed25519 public keys")
    shape = evidence.plan.contract
    for identity in (planner_identity, evidence_identity):
        if type(identity) is not tuple or len(identity) != 3:
            raise WebAuthnEvidencePlanAdmissionError("evidence plan identity is not an exact triple")
        for digest in identity:
            shape._digest(digest)
    for digest in (planner_spki, evidence_spki, configuration_digest):
        shape._digest(digest)
    shape._integer(age, evidence.authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    shape._integer(skew, evidence.authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    if operation == _REGISTRATION:
        reader._bounded_text(rp_id, 4096)
        reader._bounded_text(origin, 8192)
        if target is not None:
            raise WebAuthnEvidencePlanAdmissionError("registration custody cannot use an installation target")
    else:
        shape._digest(target)
        if rp_id is not None or origin is not None:
            raise WebAuthnEvidencePlanAdmissionError("installation custody cannot use a registration RP")
    return pins


def _capture_expectations_on_work(pins, expectations, work):
    """Own and join independent18 before actual public-key binding callbacks."""
    pins = _validate_pins(pins)
    ledger = evidence.capture._SharedLedger(work)
    evidence.plan.contract._object(expectations, plan._EXPECTATION_FIELDS,
        "independent configured evidence plan expectations")
    owned = evidence.capture._JSONCapture(ledger).visit(expectations)
    plan._validate_expectations(owned, pins[0])
    # Join to independently held configuration, never to values adopted from
    # the envelope or stored context. Both ages remain the one measured policy
    # age, with no per-call expansion or historical clock substitution.
    evidence.plan._same((owned["configurationDigest"], owned["plannerIdentity"],
            owned["plannerSpkiDigest"], owned["evidenceIdentity"], owned["evidenceSpkiDigest"],
            owned["maximumPlanAgeNs"], owned["maximumEvidenceAgeNs"],
            owned["maximumClockSkewNs"], owned["rpId"], owned["origin"],
            owned["installationTargetDigest"]),
        (pins[7], dict(zip(_IDENTITY_FIELDS, pins[2])), pins[3],
            dict(zip(_IDENTITY_FIELDS, pins[5])), pins[6], pins[8], pins[8],
            pins[9], pins[10], pins[11], pins[12]),
        work, "evidence plan expectations differ from held configuration")
    # Callers hold their raw originals/digest before invoking this helper.
    # All variable expectations are detached before either native key callback.
    evidence.keys._public_binding(pins[1], pins[3], work)
    evidence.keys._public_binding(pins[4], pins[6], work)
    return owned
