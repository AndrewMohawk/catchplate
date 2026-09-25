"""Live response replay against an authenticated evidence-planning request.

The caller obtains the three originals from the actual configured producer or
authenticates the dedicated planner response control binding those originals
and the original request control before calling this worker. Request context,
role pins and the unchanged request clock window require their real upstream
admission; no successful-response carrier is accepted instead of raw bytes.

The returned evaluation context supplies claimed planner observations, not
independently established historical cutoff or time authority. Its request,
roots and input commitment must equal the authenticated request, its policy
must equal held configuration, and its times must fit the original live window.
Genuine plan signature, membership, query, original-input semantics and root
effects are then replayed on the same work. Success returns no proof token,
history, execution permission, custody assertion or renewed clock allowance.
"""
from __future__ import annotations

from serverware import authority_webauthn_evidence_plan_admission as admission
from serverware import authority_webauthn_evidence_plan_request as request_wire
from serverware import authority_webauthn_evidence_plan_verifier as verifier


retention = verifier.retention
plan, evidence = retention.plan, retention.evidence
clock, wire = request_wire.clock, request_wire.wire


class WebAuthnEvidencePlanLiveError(ValueError):
    pass


def _observations(claimed, request_context, timing, pins, now):
    """Bound planner-observed scalars without promoting them to history."""
    issued, deadline = claimed["nowEpochNs"], claimed["deadlineEpochNs"]
    cutoff_ns = claimed["databaseCutoffUs"] * 1000
    request_issued, request_expires = timing["issuedAtEpochNs"], timing["expiresAtEpochNs"]
    age, skew = pins[8], pins[9]
    expires = min(deadline, issued + age)
    if (not deadline <= request_expires <= request_context["deadlineEpochNs"]
            or issued < request_issued - skew or cutoff_ns < request_issued - skew
            or issued > now + skew or cutoff_ns > now + skew
            or now - issued > age or now >= expires
            or cutoff_ns >= expires or abs(cutoff_ns - issued) > skew):
        raise WebAuthnEvidencePlanLiveError("planner observations exceed the original live request bounds")


def _verify_live_on_work(*, envelope_bytes, inputs_bytes, evaluation_context_bytes,
        request_context, request_issued_at_epoch_ns, request_expires_at_epoch_ns,
        request_window, pins, maximum_control_age_ns, work):
    """Genuinely replay a live raw3 response; establish no historical authority."""
    ledger = evidence.capture._SharedLedger(work)
    originals = envelope_bytes, inputs_bytes, evaluation_context_bytes
    for raw, maximum in zip(originals, (plan.contract.MAX_BYTES,
            plan.inputs_wire.MAX_BYTES, retention.context_wire.MAX_BYTES)):
        if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
            raise WebAuthnEvidencePlanLiveError("live evidence response requires bounded original bytes")
    held_pins = admission._validate_pins(pins)
    window = clock._validate(request_window)
    timing = {"issuedAtEpochNs": request_issued_at_epoch_ns,
        "expiresAtEpochNs": request_expires_at_epoch_ns}
    wire._time_pins(timing, maximum_control_age_ns, held_pins[9])
    if clock._deadline_epoch_ns(window) > timing["expiresAtEpochNs"]:
        raise WebAuthnEvidencePlanLiveError("live evidence request window exceeds its signed expiry")
    evidence.plan.contract._object(request_context, request_wire._CONTEXT_FIELDS,
        "authenticated live evidence request context")
    owned_request = evidence.capture._JSONCapture(ledger,
        maximum_bytes=request_wire.MAX_CONTEXT_BYTES).visit(request_context)
    request_wire._context_shape(owned_request, held_pins[0])
    # All caller graphs, exact raw-byte references, key handles and immutable
    # time pins are held before decoding or any native key/clock callback.
    decoded = retention.context_wire._decode_on_work(originals[2], work=work)
    claimed = admission._capture_expectations_on_work(held_pins, decoded, work)
    for name in ("request", "businessBeforeRoots", "authorizationBeforeRoots", "inputsDigest"):
        evidence.plan._same(claimed[name], owned_request[name], work,
            "live evidence response differs from authenticated request " + name)
    now = wire._fresh_on_work(timing, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=held_pins[9], work=work)
    _observations(claimed, owned_request, timing, held_pins, now)

    # This fixed owner performs the real raw3 replay. The context is used only
    # as a bounded claim under the live request, never exported as independently
    # admitted history or accepted as a substitute for signature/proof work.
    owner = verifier.EvidencePlanVerifier(pins=held_pins)
    retained = verifier.EvidencePlanVerifier.verify(owner, envelope_bytes=originals[0],
        inputs_bytes=originals[1], evaluation_context_bytes=originals[2],
        expectations=claimed, work=work)
    original_payload = retained.verification.payload_bytes
    payload = evidence.wire._decode_object(original_payload, work=work,
        maximum_bytes=plan.contract.MAX_BYTES, maximum_nodes=plan.contract.MAX_NODES,
        maximum_depth=plan.contract.MAX_DEPTH)
    plan.contract.validate_payload_shape(payload)
    evidence.capability._canonical(original_payload, payload, ledger,
        plan.contract.MAX_BYTES, plan.contract.MAX_NODES)
    evidence.plan._same((payload["issuedAtEpochNs"], payload["expiresAtEpochNs"],
            payload["databaseCutoffUs"]),
        (claimed["nowEpochNs"], min(claimed["deadlineEpochNs"],
            claimed["nowEpochNs"] + held_pins[8]), claimed["databaseCutoffUs"]), work,
        "signed evidence plan times differ from its claimed live observations")
    now = wire._fresh_on_work(timing, window=window, maximum_age_ns=maximum_control_age_ns,
        maximum_clock_skew_ns=held_pins[9], work=work)
    _observations(claimed, owned_request, timing, held_pins, now)
    plan._fresh(payload, claimed, now)
