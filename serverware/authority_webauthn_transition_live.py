"""Genuine live raw-four replay under an authenticated successor request.

The caller first authenticates the dedicated response control over the request
control and every returned original. Only then may this worker decode the plan
context. Its cutoff is a bounded planner observation, not an independent
database-clock observation. Every other expectation is reconstructed from the
held signed request and configured pins before genuine signature/proof/semantic
replay. The existing verifier returns nothing. A separate source-owned live
history admission returns those reconstructed expectations only after the same
real replay; it accepts no successful-proof carrier. This history records its
live origin, not current roots or execution authority. The original request
window is never renewed. There is no SQL, custody, retry or new allowance.
"""
from __future__ import annotations

from serverware import authority_webauthn_transition_plan_admission as admission
from serverware import authority_webauthn_transition_plan_verifier as verifier
from serverware import authority_webauthn_transition_request as request_wire


plan, evidence = admission.plan, admission.evidence
clock, wire = request_wire.clock, request_wire.wire


class WebAuthnTransitionLiveError(ValueError):
    pass


def _expectations(context, cutoff, pins):
    """Use only cutoff as a claimed observation; derive all other pins anew."""
    configured = pins[6]
    identity = dict(zip(admission._IDENTITY_FIELDS, configured[3]))
    policy = {"nowEpochNs": context["nowEpochNs"], "deadlineEpochNs": context["deadlineEpochNs"],
        "maximumAgeNs": configured[0], "maximumClockSkewNs": configured[1]}
    if pins[0] == admission._REGISTRATION:
        policy.update({"signerIdentity": identity, "signerSpkiDigest": configured[4],
            "rpId": configured[5], "origin": configured[6]})
    elif pins[0] == admission._STAGE:
        policy.update({"verifierIdentity": identity, "candidateSigningKeyId": configured[5],
            "developmentEnabled": configured[6], "requireApproval": configured[7],
            "requireApproverWebauthn": configured[8], "capabilityId": context["invocation"]["capabilityId"]})
    else:
        policy.update({"installerIdentity": identity, "installerSpkiDigest": configured[4],
            "installationTargetDigest": configured[5], "committedStage": context["invocation"]["committedStage"]})
    proof = {name: context[name] for name in ("request", "businessBeforeRoots",
        "authorizationBeforeRoots", "countedBeforeHeads", "inputsDigest")}
    proof.update({"databaseCutoffUs": cutoff, "policy": policy})
    return {"proofExpectations": proof, "configurationDigest": pins[5],
        "plannerIdentity": dict(zip(admission._IDENTITY_FIELDS, pins[2])),
        "plannerSpkiDigest": pins[3], "maximumPlanAgeNs": configured[2]}


def _cutoff(expected, timing, pins, now):
    cutoff = expected["proofExpectations"]["databaseCutoffUs"] * 1000
    policy = expected["proofExpectations"]["policy"]
    skew = pins[6][1]
    if (abs(cutoff - policy["nowEpochNs"]) > skew
            or cutoff < timing["issuedAtEpochNs"] - skew or cutoff > now + skew
            or cutoff >= timing["expiresAtEpochNs"]):
        raise WebAuthnTransitionLiveError("planner cutoff exceeds the original live request bounds")


def _verify_live_on_work(*, envelope_bytes, proof_bytes, inputs_bytes, context_bytes,
        request_context, request_issued_at_epoch_ns, request_expires_at_epoch_ns,
        request_window, pins, maximum_control_age_ns, work):
    """Replay authenticated raw4, without adopting planner history authority."""
    _admit_history_on_work(envelope_bytes=envelope_bytes, proof_bytes=proof_bytes,
        inputs_bytes=inputs_bytes, context_bytes=context_bytes, request_context=request_context,
        request_issued_at_epoch_ns=request_issued_at_epoch_ns,
        request_expires_at_epoch_ns=request_expires_at_epoch_ns, request_window=request_window,
        pins=pins, maximum_control_age_ns=maximum_control_age_ns, work=work)


def _admit_history_on_work(*, envelope_bytes, proof_bytes, inputs_bytes, context_bytes,
        request_context, request_issued_at_epoch_ns, request_expires_at_epoch_ns,
        request_window, pins, maximum_control_age_ns, work):
    """Admit derived live history after actual response authentication and replay.

    The fixed exchange authenticates the original request and response before
    calling this worker. Only databaseCutoffUs comes from that authenticated
    response; it remains a bounded planner observation. Request, roots, inputs,
    original invocation/time and policy/key pins come from that live exchange's
    held request and measured configuration, never a copied stored context.
    """
    ledger = evidence.capture._SharedLedger(work)
    originals = envelope_bytes, proof_bytes, inputs_bytes, context_bytes
    for raw in originals:
        if type(raw) is not bytes or not 2 <= len(raw) <= plan.contract.MAX_BYTES:
            raise WebAuthnTransitionLiveError("live transition response requires bounded original bytes")
    if sum(len(raw) for raw in originals) > plan.contract.MAX_BYTES:
        raise WebAuthnTransitionLiveError("live transition originals exceed the aggregate bound")
    held = admission._validate_pins(pins)
    window = clock._validate(request_window)
    timing = {"issuedAtEpochNs": request_issued_at_epoch_ns,
        "expiresAtEpochNs": request_expires_at_epoch_ns}
    wire._time_pins(timing, maximum_control_age_ns, held[6][1])
    if clock._deadline_epoch_ns(window) > timing["expiresAtEpochNs"]:
        raise WebAuthnTransitionLiveError("request window exceeds its original signed expiry")
    plan.contract.shape._object(request_context, request_wire._CONTEXT_FIELDS,
        "authenticated successor request context")
    owned = evidence.capture._JSONCapture(ledger,
        maximum_bytes=request_wire.MAX_CONTEXT_BYTES).visit(request_context)
    request_wire._context_shape(owned, held[0])
    if (timing["expiresAtEpochNs"] > owned["deadlineEpochNs"]
            or abs(timing["issuedAtEpochNs"] - owned["nowEpochNs"]) > held[6][1]):
        raise WebAuthnTransitionLiveError("request timing differs from its original invocation")
    # The response control has already bound these exact raw bytes. No caller
    # graph or key handle is read after this point to establish authority.
    claimed = plan.context._decode_on_work(originals[3], work=work)
    expected = _expectations(owned, claimed["proofExpectations"]["databaseCutoffUs"], held)
    plan.contract._validate_expectations(expected)
    evidence.plan._same(claimed, expected, work,
        "successor response context differs from the authenticated request or configured policy")
    now = wire._fresh_on_work(timing, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=held[6][1], work=work)
    _cutoff(expected, timing, held, now)
    owner = verifier.TransitionPlanVerifier(pins=held)
    verified = verifier.TransitionPlanVerifier.verify(owner, envelope_bytes=originals[0],
        proof_bytes=originals[1], inputs_bytes=originals[2], context_bytes=originals[3],
        expectations=expected, work=work)
    # Read only the genuinely verified original envelope. The signature and
    # full proof replay above are not replaced by this timing projection.
    envelope = evidence.wire._decode_object(verified.envelope_bytes, work=work,
        maximum_bytes=plan.contract.MAX_BYTES, maximum_nodes=plan.contract.MAX_NODES,
        maximum_depth=plan.contract.MAX_DEPTH)
    plan.contract.validate_envelope_shape(envelope)
    evidence.capability._canonical(verified.envelope_bytes, envelope, ledger,
        plan.contract.MAX_BYTES, plan.contract.MAX_NODES)
    payload = envelope["payload"]
    now = wire._fresh_on_work(timing, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=held[6][1], work=work)
    _cutoff(expected, timing, held, now)
    if (payload["issuedAtEpochNs"] < timing["issuedAtEpochNs"] - held[6][1]
            or payload["expiresAtEpochNs"] > timing["expiresAtEpochNs"]):
        raise WebAuthnTransitionLiveError("signed plan exceeds the original request lifetime")
    plan._fresh(payload, expected, now)
    # Rejoin after all native verifier/key callbacks, then return only the
    # privately reconstructed ordinary graph. This is not a proof token.
    encoded = plan.context._encode_on_work(expectations=expected, work=work)
    work.charge(input_bytes=len(encoded) + len(originals[3]))
    if encoded != originals[3]:
        raise WebAuthnTransitionLiveError("admitted live history changed during genuine replay")
    now = wire._fresh_on_work(timing, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=held[6][1], work=work)
    _cutoff(expected, timing, held, now)
    plan._fresh(payload, expected, now)
    return expected
