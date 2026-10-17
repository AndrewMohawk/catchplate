"""Authenticate original evidence-planning requests as historical data only.

The existing live request verifier is unchanged. This separate path verifies
the genuine signature, independent configuration/generation/key scope, complete
original body commitments and typed request identities without pretending that
an expired request is live. Its original signed interval must still fit the
independently configured age, source bounds and authenticated context deadline.

The caller supplies an already opened CURRENT processing window and the same
cumulative work allowance. Neither an old issue time nor an invented window is
used as the current clock. No currentness, execution permission, planner result,
renewed grant, transport, signing, SQL or replacement work owner is returned.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from catchplate import authority_webauthn_evidence_plan_request as request_wire


evidence, authority, clock = request_wire.evidence, request_wire.authority, request_wire.clock


class HistoricalEvidencePlanRequestError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _HistoricalPlanRequest:
    """Owned historical observations, never accepted as live authority."""

    context: dict
    issued_at_epoch_ns: int
    expires_at_epoch_ns: int


def _verify_on_work(*, control_bytes, context_bytes, inputs_bytes, pins,
        generation_sequence, generation_digest, verifier_public_key,
        maximum_control_age_ns, live_window, work, transport_deadline_ns=None):
    """Authenticate exact original raw3 under a caller-owned processing bound.

    The caller independently admits pins, generation and verifier key. This
    result authenticates request observations only; full original response,
    plan, evidence and grant replay remain separate mandatory joins.
    """
    ledger = evidence.capture._SharedLedger(work)
    original, original_context, original_inputs = request_wire._raw3(
        control_bytes, context_bytes, inputs_bytes)
    held_pins = request_wire.admission._validate_pins(pins)
    scope = request_wire.wire._pins(held_pins[7], generation_sequence,
        generation_digest, held_pins[0])
    public_key, planner_key = verifier_public_key, held_pins[1]
    if not isinstance(public_key, request_wire.plan.Ed25519PublicKey):
        raise HistoricalEvidencePlanRequestError("historical planning verifier is not Ed25519")
    shape = evidence.plan.contract
    shape._integer(maximum_control_age_ns, authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    maximum_age, skew = maximum_control_age_ns, held_pins[9]
    window = clock._validate(live_window)
    if transport_deadline_ns is not None:
        shape._integer(transport_deadline_ns, minimum=1)
    bound = window[4] if transport_deadline_ns is None else min(window[4], transport_deadline_ns)
    last_epoch, last_monotonic = window[0], window[2]
    original_issued = None

    def live():
        nonlocal last_epoch, last_monotonic
        now = clock._check_on_work(window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if (now < last_epoch or monotonic < last_monotonic or monotonic >= bound
                or original_issued is not None and original_issued > now + skew):
            raise HistoricalEvidencePlanRequestError(
                "historical planning processing expired, reversed or encountered future issuance")
        last_epoch, last_monotonic = now, monotonic
        return now

    live()
    value, signature, unsigned_wire = request_wire._read_control(original, work)
    issued, expires = request_wire.wire._time_pins(
        {"issuedAtEpochNs": value["issuedAtEpochNs"], "expiresAtEpochNs": value["expiresAtEpochNs"]},
        maximum_age, skew)
    # Hold all signed scalar commitments before any real key callback. No body
    # is parsed, and no copied timing value is authority for this processing.
    body_commitment = (value["contextBytesDigest"], value["contextByteCount"],
        value["inputsBytesDigest"], value["inputsByteCount"])
    signed_scope = (value["configurationDigest"], value["generationSequence"],
        value["generationDigest"], value["operation"])
    evidence.capability._signature(public_key, signature, request_wire.SCHEMA, unsigned_wire, ledger)
    evidence.capability._canonical(original, value, ledger,
        request_wire.MAX_CONTROL_BYTES, request_wire.MAX_CONTROL_NODES)
    evidence.plan._same(signed_scope, scope, work,
        "historical planning request differs from independent configuration, generation or operation")
    request_wire.wire._distinct_keys(planner_key, public_key, work)
    original_issued = issued
    live()
    evidence.plan._same((request_wire.retention._bytes_digest(original_context, work), len(original_context),
            request_wire.retention._bytes_digest(original_inputs, work), len(original_inputs)),
        body_commitment, work,
        "historical planning request differs from its complete original-byte commitments")
    live()
    # Both original bodies are authenticated before the first context decode.
    # Root observations are authenticated request content, not a live DB head.
    decoded = evidence.wire._decode_object(original_context, work=work,
        maximum_bytes=request_wire.MAX_CONTEXT_BYTES, maximum_nodes=request_wire.MAX_CONTEXT_NODES,
        maximum_depth=request_wire.MAX_CONTEXT_DEPTH)
    owned = evidence.capture._JSONCapture(ledger,
        maximum_bytes=request_wire.MAX_CONTEXT_BYTES).visit(decoded)
    request_wire._context_shape(owned, scope[3])
    evidence.capability._canonical(original_context, owned, ledger,
        request_wire.MAX_CONTEXT_BYTES, request_wire.MAX_CONTEXT_NODES)
    evidence.plan._same(request_wire.inputs_wire._digest_on_work(original_inputs, work),
        owned["inputsDigest"], work,
        "historical planning context differs from its original input identity")
    request_wire._request_commitments(owned, work)
    if expires > owned["deadlineEpochNs"]:
        raise HistoricalEvidencePlanRequestError(
            "historical planning control exceeds its original context deadline")
    # Expiry is an ORIGINAL observation, not a cutoff for the independently
    # current processing window. Never call a live verifier at issuedAtEpochNs.
    live()
    evidence.capability._canonical(original, value, ledger,
        request_wire.MAX_CONTROL_BYTES, request_wire.MAX_CONTROL_NODES)
    evidence.capability._canonical(original_context, owned, ledger,
        request_wire.MAX_CONTEXT_BYTES, request_wire.MAX_CONTEXT_NODES)
    return _HistoricalPlanRequest(owned, issued, expires)
