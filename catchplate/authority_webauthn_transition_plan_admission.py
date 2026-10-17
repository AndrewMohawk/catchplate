"""Held configuration joins for three genuine successor plan verifiers.

The exact immutable pins are independently admitted configuration, not values
enrolled from a received plan or context. All five independent expectation
fields are owned and joined before actual key/SPKI callbacks. Request, roots,
historical times, stage capability and committed-stage history remain separate
invocation admission obligations. Returned expectations are ordinary owned
data; genuine original-byte, primary/count and semantic replay must follow.

There is no database, private signer, clock, registry mutation, proof token or
replacement work allowance here.
"""
from __future__ import annotations

from catchplate import authority_webauthn_transition_plan as plan


evidence, shape = plan.evidence, plan.contract.shape
_IDENTITY_FIELDS = ("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")
_REGISTRATION = plan.proof.registration.OPERATION
_STAGE = plan.proof.stage.OPERATION
_COMPLETION = plan.proof.completion.OPERATION
_POLICY_LENGTHS = {_REGISTRATION: 7, _STAGE: 9, _COMPLETION: 6}


class WebAuthnTransitionPlanAdmissionError(ValueError):
    pass


def _identity(values):
    if type(values) is not tuple or len(values) != 3:
        raise WebAuthnTransitionPlanAdmissionError("transition plan identity is not an exact immutable triple")
    for digest in values:
        shape._digest(digest)


def _validate_pins(pins):
    """Validate the same exact tuple7 without native or key callbacks."""
    if type(pins) is not tuple or len(pins) != 7:
        raise WebAuthnTransitionPlanAdmissionError("transition plan pins are not an exact seven-tuple")
    operation, planner_key, planner_identity, planner_spki, operation_key, configuration_digest, policy = pins
    if type(operation) is not str or operation not in _POLICY_LENGTHS:
        raise WebAuthnTransitionPlanAdmissionError("transition plan operation is not source fixed")
    if (not isinstance(planner_key, plan.Ed25519PublicKey)
            or not isinstance(operation_key, plan.Ed25519PublicKey)):
        raise WebAuthnTransitionPlanAdmissionError("transition plan requires actual Ed25519 public keys")
    _identity(planner_identity)
    for digest in (planner_spki, configuration_digest):
        shape._digest(digest)
    if type(policy) is not tuple or len(policy) != _POLICY_LENGTHS[operation]:
        raise WebAuthnTransitionPlanAdmissionError("transition plan policy is not its exact purpose tuple")
    age, skew, plan_age, identity, spki = policy[:5]
    for maximum in (age, plan_age):
        shape._integer(maximum, plan.contract.authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    shape._integer(skew, plan.contract.authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    _identity(identity)
    shape._digest(spki)
    if operation == _REGISTRATION:
        for value, maximum in zip(policy[5:], (4096, 8192)):
            shape._text(value, maximum)
            if "\x00" in value:
                raise WebAuthnTransitionPlanAdmissionError("registration policy text contains NUL")
    elif operation == _STAGE:
        shape._digest(policy[5])
        if any(type(value) is not bool for value in policy[6:]):
            raise WebAuthnTransitionPlanAdmissionError("trust-stage policy flags are not exact booleans")
    else:
        shape._digest(policy[5])
    return pins


def _capture_expectations_on_work(pins, expectations, work):
    """Own independent5 and bind configured policy before both key callbacks."""
    pins = _validate_pins(pins)
    ledger = evidence.capture._SharedLedger(work)
    shape._object(expectations, plan.contract.EXPECTATION_FIELDS,
        "independent configured transition plan expectations")
    owned = evidence.capture._JSONCapture(ledger).visit(expectations)
    operation = plan.contract._validate_expectations(owned)
    policy, configured = owned["proofExpectations"]["policy"], pins[6]
    evidence.plan._same((operation, owned["configurationDigest"], owned["plannerIdentity"],
            owned["plannerSpkiDigest"], owned["maximumPlanAgeNs"],
            policy["maximumAgeNs"], policy["maximumClockSkewNs"]),
        (pins[0], pins[5], dict(zip(_IDENTITY_FIELDS, pins[2])), pins[3],
            configured[2], configured[0], configured[1]),
        work, "transition plan expectations differ from held configuration")
    identity = dict(zip(_IDENTITY_FIELDS, configured[3]))
    if operation == _REGISTRATION:
        actual = (policy["signerIdentity"], policy["signerSpkiDigest"], policy["rpId"], policy["origin"])
        expected = (identity, configured[4], configured[5], configured[6])
    elif operation == _STAGE:
        actual = (policy["verifierIdentity"], policy["candidateSigningKeyId"],
            policy["developmentEnabled"], policy["requireApproval"], policy["requireApproverWebauthn"])
        expected = (identity, configured[5], configured[6], configured[7], configured[8])
    else:
        actual = (policy["installerIdentity"], policy["installerSpkiDigest"], policy["installationTargetDigest"])
        expected = (identity, configured[4], configured[5])
    evidence.plan._same(actual, expected, work,
        "transition plan operation policy differs from held configuration")
    # The caller holds every raw original before invoking this helper. Both
    # keys are independently configured; even the stage verifier key, whose
    # SPKI is not a proof-policy field, must match its actual admitted SPKI.
    evidence.keys._public_binding(pins[1], pins[3], work)
    evidence.keys._public_binding(pins[4], configured[4], work)
    return owned
