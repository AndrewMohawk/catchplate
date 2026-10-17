"""Genuine original planner-response verification for historical inspection.

This separate path authenticates the same canonical signed response and exact
request/raw3 commitments as the live verifier. Expiry may be historical; its
original interval, request relationship and nonfuture issue are still checked.
The caller has genuinely verified the original request and independently
admitted pins in the same call. Neither caller timing data nor this result is a
permission token. No old issue time supplies a clock or a new live window.

Only the caller's existing processing window/work and inherited monotonic
deadline bound this inspection. There is no signing, I/O, callback argument,
request dispatch, SQL, new allowance or change to the live response verifier.
"""
from __future__ import annotations

from dataclasses import dataclass
import time

from catchplate import authority_webauthn_evidence_plan_response as response_wire


evidence, wire, clock = response_wire.evidence, response_wire.wire, response_wire.clock
plan, retention, admission = response_wire.plan, response_wire.retention, response_wire.admission


class HistoricalEvidencePlanResponseError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _HistoricalPlanResponse:
    """Authenticated original times only, not live/executable plan metadata."""

    issued_at_epoch_ns: int
    expires_at_epoch_ns: int


def _verify_on_work(*, control_bytes, request_control_bytes, envelope_bytes, inputs_bytes,
        evaluation_context_bytes, pins, generation_sequence, generation_digest,
        verifier_public_key, request_issued_at_epoch_ns, request_expires_at_epoch_ns,
        live_window, maximum_control_age_ns, work, transport_deadline_ns=None):
    ledger = evidence.capture._SharedLedger(work)
    originals = response_wire._originals(request_control_bytes, envelope_bytes,
        inputs_bytes, evaluation_context_bytes)
    if (type(control_bytes) is not bytes or not 2 <= len(control_bytes) <= response_wire.MAX_CONTROL_BYTES
            or len(control_bytes) + sum(len(raw) for raw in originals[1:])
                > response_wire.MAX_RESPONSE_BYTES):
        raise HistoricalEvidencePlanResponseError("historical planning response exceeds its original byte bounds")
    original = control_bytes
    held_pins = admission._validate_pins(pins)
    scope = wire._pins(held_pins[7], generation_sequence, generation_digest, held_pins[0])
    planner_key, verifier_key = held_pins[1], verifier_public_key
    if not isinstance(verifier_key, plan.Ed25519PublicKey):
        raise HistoricalEvidencePlanResponseError("historical planning response requires the actual verifier key")
    maximum_age, skew = maximum_control_age_ns, held_pins[9]
    request_timing = {"issuedAtEpochNs": request_issued_at_epoch_ns,
        "expiresAtEpochNs": request_expires_at_epoch_ns}
    request_issued, request_expires = wire._time_pins(request_timing, maximum_age, skew)
    window = clock._validate(live_window)
    inherited = transport_deadline_ns
    if inherited is not None:
        evidence.plan.contract._integer(inherited, minimum=1)
    bound = window[4] if inherited is None else min(window[4], inherited)
    last_epoch, last_monotonic = window[0], window[2]

    def current():
        nonlocal last_epoch, last_monotonic
        now = clock._check_on_work(window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        evidence.plan.contract._integer(monotonic, minimum=1)
        if now < last_epoch or monotonic < last_monotonic or monotonic >= bound:
            raise HistoricalEvidencePlanResponseError("historical response processing expired or its clocks reversed")
        last_epoch, last_monotonic = now, monotonic
        return now

    if request_issued > current() + skew:
        raise HistoricalEvidencePlanResponseError("historical planning request issue is in the future")
    value, signature, unsigned_wire = response_wire._read_control(original, work)
    issued, expires = wire._time_pins({"issuedAtEpochNs": value["issuedAtEpochNs"],
        "expiresAtEpochNs": value["expiresAtEpochNs"]}, maximum_age, skew)
    actual_scope = (value["configurationDigest"], value["generationSequence"],
        value["generationDigest"], value["operation"])
    expected_body = tuple((value[name + "BytesDigest"], value[name + "ByteCount"])
        for name in response_wire._BODY_NAMES)
    evidence.plan._same(expires, request_expires, work,
        "historical planning response changed its original request expiry")
    if issued < request_issued - skew:
        raise HistoricalEvidencePlanResponseError("historical planning response predates its original request")
    if issued > current() + skew:
        raise HistoricalEvidencePlanResponseError("historical planning response issue is in the future")

    evidence.keys._public_binding(planner_key, held_pins[3], work)
    evidence.capability._signature(planner_key, signature, response_wire.SCHEMA, unsigned_wire, ledger)
    evidence.capability._canonical(original, value, ledger,
        response_wire.MAX_CONTROL_BYTES, response_wire.MAX_CONTROL_NODES)
    evidence.plan._same(actual_scope, scope, work,
        "historical planning response differs from independent configuration, generation or operation")
    wire._distinct_keys(planner_key, verifier_key, work)
    current()
    actual_body = tuple((retention._bytes_digest(raw, work), len(raw)) for raw in originals)
    evidence.plan._same(actual_body, expected_body, work,
        "historical planning response differs from original request or produced bytes")
    # The original interval stays historical. Only the independently supplied
    # processing window must be live; there is deliberately no now < expires,
    # response-age freshness, window reopening or synthesized historical clock.
    now = current()
    if request_issued > now + skew or issued > now + skew:
        raise HistoricalEvidencePlanResponseError("historical planning issue time is in the future")
    return _HistoricalPlanResponse(issued, expires)
