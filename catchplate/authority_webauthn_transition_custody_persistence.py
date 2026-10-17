"""Authenticated retain-only composition for successor-transition originals.

The actual configured owner supplies held database and public-key policy. Both
original controls and every detached body are genuinely replayed before the
registry-gated database connection. Only their authenticated historical bytes
are decoded, and they still undergo the real configured expectation joins.
No successful-verification object is accepted as authority instead of bytes.

A private fixed store operation checks the original nonrenewable windows and
readback identity/raw4 inside the real outer transaction, then checks the same
windows after normal commit and connection close. A late rejection cannot
undo a commit or authorize retry. There is no execution, reservation, signed
durability receipt, arbitrary operation hook or replacement work allowance.
"""
from __future__ import annotations

from catchplate import authority_webauthn_transition_custody_relay as relay
from catchplate import authority_webauthn_transition_custody_transport as transport
from catchplate import authority_webauthn_transition_custody_wire as wire
from catchplate import authority_webauthn_transition_persistence as persistence


evidence, store, writer = wire.evidence, persistence.store, persistence.writer
_RESULT_FIELDS = frozenset({"envelope_bytes", "proof_bytes", "inputs_bytes", "context_bytes",
    "retained_record_digest", "retained_at_epoch_ns"})


class WebAuthnTransitionCustodyPersistenceError(ValueError):
    pass


def _fresh_controls_on_work(*, intent_window, relay_window, intent_times, relay_times,
        maximum_control_age_ns, maximum_clock_skew_ns, work):
    """Check only ordinary held timing pins; this does not authenticate bytes."""
    now = None
    for window, times in ((intent_window, intent_times), (relay_window, relay_times)):
        if type(times) is not tuple or len(times) != 2:
            raise WebAuthnTransitionCustodyPersistenceError("transition custody timing pair is not exact")
        now = wire._fresh_on_work({"issuedAtEpochNs": times[0], "expiresAtEpochNs": times[1]},
            window=window, maximum_age_ns=maximum_control_age_ns,
            maximum_clock_skew_ns=maximum_clock_skew_ns, work=work)
    return now


def _persist_authenticated_record(*, connection, work, envelope_bytes, proof_bytes,
        inputs_bytes, context_bytes, expectations, planner_public_key, operation_public_key,
        retained_record_digest, intent_window, relay_window, intent_times, relay_times,
        maximum_control_age_ns, maximum_clock_skew_ns):
    """One fixed actual store operation, not a request-selected callback."""
    timing = {"intent_window": intent_window, "relay_window": relay_window,
        "intent_times": intent_times, "relay_times": relay_times,
        "maximum_control_age_ns": maximum_control_age_ns,
        "maximum_clock_skew_ns": maximum_clock_skew_ns}
    originals = wire.retention._raw4(envelope_bytes, proof_bytes, inputs_bytes, context_bytes)
    _fresh_controls_on_work(**timing, work=work)
    result = store.persist_webauthn_transition_plan_record(envelope_bytes=originals[0],
        proof_bytes=originals[1], inputs_bytes=originals[2], context_bytes=originals[3],
        expectations=expectations, planner_public_key=planner_public_key,
        operation_public_key=operation_public_key, connection=connection, work=work)
    evidence.plan.contract._object(result, _RESULT_FIELDS, "transition custody store readback")
    returned = wire.retention._raw4(result["envelope_bytes"], result["proof_bytes"],
        result["inputs_bytes"], result["context_bytes"])
    digest, retained_at = result["retained_record_digest"], result["retained_at_epoch_ns"]
    evidence.plan.contract._digest(digest)
    evidence.plan.contract._integer(retained_at, minimum=1)
    evidence.plan._same(digest, retained_record_digest, work,
        "transition custody readback differs from the authenticated record identity")
    for original, actual in zip(originals, returned):
        work.charge(input_bytes=len(original) + len(actual))
        if original != actual:
            raise WebAuthnTransitionCustodyPersistenceError("transition custody readback changed an original body")
    # The actual store already genuinely replayed raw4 and matched every
    # immutable persisted field. Do not spend a third full proof replay here.
    now = _fresh_controls_on_work(**timing, work=work)
    if retained_at > now + maximum_clock_skew_ns:
        raise WebAuthnTransitionCustodyPersistenceError("transition custody readback has a future retention time")
    # These checks still run inside the caller-owned outer transaction. Its
    # nested store savepoint did not commit or release a custody observation.
    return {"envelope_bytes": returned[0], "proof_bytes": returned[1],
        "inputs_bytes": returned[2], "context_bytes": returned[3],
        "retained_record_digest": digest, "retained_at_epoch_ns": retained_at}


def _persist_on_configuration(owner, *, intent_bytes, relay_bytes, envelope_bytes,
        proof_bytes, inputs_bytes, context_bytes, historical_expectations_bytes,
        generation_sequence, generation_digest, verifier_public_key, maximum_control_age_ns, work):
    """Authenticate raw7 and return only after actual outer commit and close."""
    evidence.capture._SharedLedger(work)
    configured = persistence._snapshot(owner)
    pins = configured[3:]
    originals = transport._validate_originals(intent_bytes=intent_bytes, relay_bytes=relay_bytes,
        envelope_bytes=envelope_bytes, proof_bytes=proof_bytes, inputs_bytes=inputs_bytes,
        context_bytes=context_bytes, historical_expectations_bytes=historical_expectations_bytes)
    public_key = verifier_public_key
    scope = wire._pins(pins[5], generation_sequence, generation_digest, pins[0])
    evidence.plan.contract._integer(maximum_control_age_ns,
        wire.authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    skew = pins[6][1]
    verified = relay._verify_on_work(intent_bytes=originals[0], relay_bytes=originals[1],
        envelope_bytes=originals[2], proof_bytes=originals[3], inputs_bytes=originals[4],
        context_bytes=originals[5], historical_expectations_bytes=originals[6], pins=pins,
        generation_sequence=scope[1], generation_digest=scope[2], verifier_public_key=public_key,
        maximum_control_age_ns=maximum_control_age_ns, work=work)
    record_digest = verified.retained_record_digest
    timing = {"intent_window": verified.intent_window, "relay_window": verified.relay_window,
        "intent_times": verified.intent_times, "relay_times": verified.relay_times,
        "maximum_control_age_ns": maximum_control_age_ns, "maximum_clock_skew_ns": skew}
    # Authentication bound this original history; no graph from the verifier's
    # ordinary result replaces actual canonical decoding and configured joins.
    historical = wire.retention.context_wire._decode_on_work(originals[6], work=work)
    owned = persistence.admission._capture_expectations_on_work(pins, historical, work)
    _fresh_controls_on_work(**timing, work=work)
    from catchplate import db
    import psycopg
    from psycopg.rows import dict_row

    if configured[2][0] != db._METADATA_STORE_AUTHORITY_PLANNER_WRITER_ROLE:
        raise WebAuthnTransitionCustodyPersistenceError("transition writer role differs from the actual database contract")
    arguments = {"envelope_bytes": originals[2], "proof_bytes": originals[3],
        "inputs_bytes": originals[4], "context_bytes": originals[5],
        "retained_record_digest": record_digest, **timing}
    fixed = {"expectations": owned, "planner_public_key": pins[1], "operation_public_key": pins[4]}
    _fresh_controls_on_work(**timing, work=work)
    connection = persistence._connect(configured, work, psycopg, dict_row)
    result = writer._run_on_connection(connection, database_identity=configured[2], work=work,
        operation=_persist_authenticated_record, arguments=arguments, expectations=fixed)
    # Outer exit and closed-handle checks have completed. Expiry here is an
    # uncertain outcome, never a claim that a possible commit was rolled back.
    _fresh_controls_on_work(**timing, work=work)
    return result
