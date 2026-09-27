"""Admit original planning history only after the signed exchange is verified.

The fixed caller first authenticates the original verifier request and planner
response, including every raw3 byte commitment. Request context, original
request/response times and independently admitted pins retain that mandatory
provenance. This worker accepts no prior successful replay as a substitute.

Only three bounded signed planner observations supply historical time fields.
They are not independently trusted database-clock facts or current roots. Real
original signature, proof, input-semantic and root replay runs once on the
existing work. Current processing uses only the caller's original live window;
historical request or plan expiry creates no renewed execution authority.
"""
from __future__ import annotations

import time

from serverware import authority_webauthn_evidence_plan_admission as admission
from serverware import authority_webauthn_evidence_plan_request as request_wire
from serverware import authority_webauthn_evidence_plan_verifier as verifier


retention = verifier.retention
plan, evidence = retention.plan, retention.evidence
clock, wire = request_wire.clock, request_wire.wire


class WebAuthnEvidencePlanHistoryError(ValueError):
    pass


def _observations(history, request_context, request_timing, response_timing, pins, now):
    """Compare authenticated historical times without making them a clock."""
    issued, deadline = history["nowEpochNs"], history["deadlineEpochNs"]
    cutoff_ns = history["databaseCutoffUs"] * 1000
    request_issued, request_expires = request_timing
    response_issued, response_expires = response_timing
    age, skew = pins[8], pins[9]
    expires = min(deadline, issued + age)
    if (response_expires != request_expires
            or not deadline <= request_expires <= request_context["deadlineEpochNs"]
            or response_issued < request_issued - skew
            or issued < request_issued - skew or cutoff_ns < request_issued - skew
            or issued > response_issued + skew or cutoff_ns > response_issued + skew
            or response_issued >= expires or cutoff_ns >= expires
            or abs(cutoff_ns - issued) > skew
            or max(request_issued, response_issued, issued, cutoff_ns) > now + skew):
        raise WebAuthnEvidencePlanHistoryError("planner observations exceed their original signed exchange bounds")


def _admit_history_on_work(*, envelope_bytes, inputs_bytes, evaluation_context_bytes,
        request_context, request_issued_at_epoch_ns, request_expires_at_epoch_ns,
        response_issued_at_epoch_ns, response_expires_at_epoch_ns, live_window,
        pins, maximum_control_age_ns, work, transport_deadline_ns=None):
    """Return ordinary history after genuine raw3 replay, never live authority.

    The current processing window is supplied independently of the historical
    exchange. Original request and response signatures/commitments must have
    been verified in this same composition before this private continuation.
    """
    ledger = evidence.capture._SharedLedger(work)
    originals = envelope_bytes, inputs_bytes, evaluation_context_bytes
    for raw, maximum in zip(originals, (plan.contract.MAX_BYTES,
            plan.inputs_wire.MAX_BYTES, retention.context_wire.MAX_BYTES)):
        if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
            raise WebAuthnEvidencePlanHistoryError("historical evidence response requires bounded original bytes")
    if sum(len(raw) for raw in originals) + 2 > request_wire.authority.MAX_RESULT_BYTES:
        raise WebAuthnEvidencePlanHistoryError("historical evidence response exceeds its aggregate bound")
    held_pins = admission._validate_pins(pins)
    window = clock._validate(live_window)
    request_timing = wire._time_pins({"issuedAtEpochNs": request_issued_at_epoch_ns,
        "expiresAtEpochNs": request_expires_at_epoch_ns}, maximum_control_age_ns, held_pins[9])
    response_timing = wire._time_pins({"issuedAtEpochNs": response_issued_at_epoch_ns,
        "expiresAtEpochNs": response_expires_at_epoch_ns}, maximum_control_age_ns, held_pins[9])
    inherited = transport_deadline_ns
    if inherited is not None:
        evidence.plan.contract._integer(inherited, minimum=1)
    bound = window[4] if inherited is None else min(window[4], inherited)
    evidence.plan.contract._object(request_context, request_wire._CONTEXT_FIELDS,
        "authenticated historical evidence request context")
    owned_request = evidence.capture._JSONCapture(ledger,
        maximum_bytes=request_wire.MAX_CONTEXT_BYTES).visit(request_context)
    request_wire._context_shape(owned_request, held_pins[0])
    # Every caller graph, original byte reference, key handle and time scalar
    # is held before the first native decoder, key or clock callback.
    last_epoch, last_monotonic = window[0], window[2]

    def current():
        nonlocal last_epoch, last_monotonic
        now = clock._check_on_work(window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        evidence.plan.contract._integer(monotonic, minimum=1)
        if now < last_epoch or monotonic < last_monotonic or monotonic >= bound:
            raise WebAuthnEvidencePlanHistoryError("historical evidence processing expired or its clocks reversed")
        last_epoch, last_monotonic = now, monotonic
        return now

    current()
    decoded = retention.context_wire._decode_on_work(originals[2], work=work)
    observations = decoded["databaseCutoffUs"], decoded["nowEpochNs"], decoded["deadlineEpochNs"]
    # Never adopt the returned context's roots, request or identity/policy pins.
    # Only these three original planner observations enter derived history.
    derived = {"request": owned_request["request"],
        "businessBeforeRoots": owned_request["businessBeforeRoots"],
        "authorizationBeforeRoots": owned_request["authorizationBeforeRoots"],
        "inputsDigest": owned_request["inputsDigest"],
        "configurationDigest": held_pins[7],
        "plannerIdentity": dict(zip(admission._IDENTITY_FIELDS, held_pins[2])),
        "plannerSpkiDigest": held_pins[3],
        "evidenceIdentity": dict(zip(admission._IDENTITY_FIELDS, held_pins[5])),
        "evidenceSpkiDigest": held_pins[6],
        "databaseCutoffUs": observations[0], "nowEpochNs": observations[1],
        "deadlineEpochNs": observations[2], "maximumPlanAgeNs": held_pins[8],
        "maximumEvidenceAgeNs": held_pins[8], "maximumClockSkewNs": held_pins[9],
        "rpId": held_pins[10], "origin": held_pins[11], "installationTargetDigest": held_pins[12]}
    history = evidence.capture._JSONCapture(ledger,
        maximum_bytes=retention.context_wire.MAX_BYTES).visit(derived)
    plan._validate_expectations(history, held_pins[0])
    _observations(history, owned_request, request_timing, response_timing, held_pins, current())
    canonical_history = retention.context_wire._encode_on_work(expectations=history, work=work)
    work.charge(input_bytes=len(canonical_history) + len(originals[2]))
    if canonical_history != originals[2]:
        raise WebAuthnEvidencePlanHistoryError("derived historical expectations differ from the authenticated original context")

    # The real fixed verifier repeats signature, primary-proof, original input
    # semantics and root effects; a prior success carrier cannot skip it.
    owner = verifier.EvidencePlanVerifier(pins=held_pins)
    retained = verifier.EvidencePlanVerifier.verify(owner, envelope_bytes=originals[0],
        inputs_bytes=originals[1], evaluation_context_bytes=originals[2],
        expectations=history, work=work)
    original_payload = retained.verification.payload_bytes
    payload = evidence.wire._decode_object(original_payload, work=work,
        maximum_bytes=plan.contract.MAX_BYTES, maximum_nodes=plan.contract.MAX_NODES,
        maximum_depth=plan.contract.MAX_DEPTH)
    plan.contract.validate_payload_shape(payload)
    evidence.capability._canonical(original_payload, payload, ledger,
        plan.contract.MAX_BYTES, plan.contract.MAX_NODES)
    evidence.plan._same((payload["issuedAtEpochNs"], payload["expiresAtEpochNs"],
            payload["databaseCutoffUs"]),
        (history["nowEpochNs"], min(history["deadlineEpochNs"],
            history["nowEpochNs"] + held_pins[8]), history["databaseCutoffUs"]), work,
        "signed evidence plan times differ from its original historical observations")
    _observations(history, owned_request, request_timing, response_timing, held_pins, current())
    return history
