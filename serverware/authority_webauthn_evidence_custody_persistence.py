"""Fixed authenticated retain composition for the configured evidence writer.

The caller must independently admit the exact configuration, generation and
verifier key. Original signed controls and all detached bodies are genuinely
verified before the registry-gated database import or connection. A received
successful-verification carrier can never replace that work. Historical
expectations are decoded only after their signed byte commitments authenticate.

The actual writer owner retains the outer transaction and connection; this
fixed operation checks both original control windows around real persistence,
inside that transaction, and again after normal close. Post-commit expiry or
transport failure cannot undo a commit and is an uncertain outcome, not a
rollback receipt. No automatic retry, signed acknowledgment, new database
privilege, execution capability, reservation, transport or registry activation
is provided here. Every replay uses the same original work allowance.
"""
from __future__ import annotations

from serverware import authority_webauthn_evidence_custody_relay as relay
from serverware import authority_webauthn_evidence_custody_wire as wire
from serverware import authority_webauthn_evidence_plan_persistence as persistence


evidence, store, writer = wire.evidence, persistence.store, persistence.writer


class WebAuthnEvidenceCustodyPersistenceError(ValueError):
    pass


def _fresh_controls_on_work(*, intent_window, relay_window, intent_times,
        relay_times, maximum_control_age_ns, maximum_clock_skew_ns, work):
    """Check held times; these ordinary scalars do not authenticate a control."""
    for window, times in ((intent_window, intent_times), (relay_window, relay_times)):
        if type(times) is not tuple or len(times) != 2:
            raise WebAuthnEvidenceCustodyPersistenceError("evidence custody timing pair is not exact")
        wire._fresh_on_work({"issuedAtEpochNs": times[0], "expiresAtEpochNs": times[1]},
            window=window, maximum_age_ns=maximum_control_age_ns,
            maximum_clock_skew_ns=maximum_clock_skew_ns, work=work)


def _persist_authenticated_record(*, connection, work, envelope_bytes,
        inputs_bytes, evaluation_context_bytes, expectations, planner_public_key,
        evidence_public_key, retained_record_digest, intent_window, relay_window,
        intent_times, relay_times, maximum_control_age_ns, maximum_clock_skew_ns):
    """Private fixed operation, never selected or supplied by request data."""
    timing = {"intent_window": intent_window, "relay_window": relay_window,
        "intent_times": intent_times, "relay_times": relay_times,
        "maximum_control_age_ns": maximum_control_age_ns,
        "maximum_clock_skew_ns": maximum_clock_skew_ns}
    _fresh_controls_on_work(**timing, work=work)
    result = store.persist_webauthn_evidence_plan_record(envelope_bytes=envelope_bytes,
        inputs_bytes=inputs_bytes, evaluation_context_bytes=evaluation_context_bytes,
        expectations=expectations, planner_public_key=planner_public_key,
        evidence_public_key=evidence_public_key, connection=connection, work=work)
    evidence.plan._same(result["retained_record_digest"], retained_record_digest, work,
        "evidence custody persisted record differs from its authenticated original controls")
    # A failure here aborts the still-owned outer transaction. The store's
    # nested savepoint is not a commit and cannot release a custody response.
    _fresh_controls_on_work(**timing, work=work)
    return result


def _persist_on_configuration(configuration, *, intent_bytes, relay_bytes,
        envelope_bytes, inputs_bytes, evaluation_context_bytes,
        historical_expectations_bytes, generation_sequence, generation_digest,
        verifier_public_key, maximum_control_age_ns, work):
    """Authenticate originals, retain them, and return only after normal close.

    The exact configuration is the existing measured-writer mapper's tuple,
    not network-supplied configuration or an authentication token. This private
    seam does not establish provenance for an arbitrarily constructed tuple.
    """
    evidence.capture._SharedLedger(work)
    configured = persistence._configuration(configuration)
    pins = configured[3:]
    originals = wire._raw4(envelope_bytes, inputs_bytes, evaluation_context_bytes,
        historical_expectations_bytes)
    controls = intent_bytes, relay_bytes
    if any(type(raw) is not bytes or not 2 <= len(raw) <= wire.MAX_CONTROL_BYTES for raw in controls):
        raise WebAuthnEvidenceCustodyPersistenceError("evidence custody controls are not bounded originals")
    public_key = verifier_public_key
    scope = wire._pins(pins[7], generation_sequence, generation_digest, pins[0])
    evidence.plan.contract._integer(maximum_control_age_ns,
        wire.authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    maximum_clock_skew_ns = pins[9]
    verified = relay._verify_on_work(intent_bytes=controls[0], relay_bytes=controls[1],
        envelope_bytes=originals[0], inputs_bytes=originals[1],
        evaluation_context_bytes=originals[2], historical_expectations_bytes=originals[3],
        pins=pins, generation_sequence=scope[1], generation_digest=scope[2],
        verifier_public_key=public_key, maximum_control_age_ns=maximum_control_age_ns, work=work)
    record_digest = verified.retained_record_digest
    timing = {"intent_window": verified.intent_window, "relay_window": verified.relay_window,
        "intent_times": verified.intent_times, "relay_times": verified.relay_times,
        "maximum_control_age_ns": maximum_control_age_ns,
        "maximum_clock_skew_ns": maximum_clock_skew_ns}
    # Decode the original authenticated history anew. The receiver never
    # adopts an expectations graph from a successful-verification carrier.
    historical = wire.retention.context_wire._decode_on_work(originals[3], work=work)
    owned = persistence._capture(configured, historical, work)
    _fresh_controls_on_work(**timing, work=work)
    # Preserve the actual facade's startup/registry gate before any socket.
    from serverware import db
    import psycopg
    from psycopg.rows import dict_row

    if configured[2][0] != db._METADATA_STORE_AUTHORITY_PLANNER_WRITER_ROLE:
        raise WebAuthnEvidenceCustodyPersistenceError("evidence custody writer role differs from the database contract")
    arguments = {"envelope_bytes": originals[0], "inputs_bytes": originals[1],
        "evaluation_context_bytes": originals[2], "retained_record_digest": record_digest,
        **timing}
    fixed = {"expectations": owned, "planner_public_key": pins[1], "evidence_public_key": pins[4]}
    _fresh_controls_on_work(**timing, work=work)
    connection = persistence._connect(configured, work, psycopg, dict_row)
    result = writer._run_on_connection(connection, database_identity=configured[2],
        work=work, operation=_persist_authenticated_record, arguments=arguments, expectations=fixed)
    # The real outer exit/close has completed. A late rejection here must not
    # be misrepresented as proof of rollback or permission for an automatic retry.
    _fresh_controls_on_work(**timing, work=work)
    return result
