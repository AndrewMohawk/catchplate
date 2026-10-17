"""Separate configured verifier requests for planner relay and forwarding.

The actual verifier service supplies admitted configuration and launch pins.
This component does not manufacture that provenance or accept successful proof
observations. Relay preparation authenticates originals before requesting a
signature, then authenticates the returned original relay. Forwarding is an
explicit separate operation over retained originals: genuine local plan replay
derives independent ACK expectations before a potentially committing socket.

No operation retries, regenerates signatures, opens a database, or chooses a
key from a response. A returned original ACK is a pinned custody statement,
not current execution authority, historical recovery, or a durability proof.
Failure after forwarding does not imply rollback or absence of writer custody.
"""
from __future__ import annotations

import time

from catchplate import authority_contract as authority
from catchplate import authority_revocation_configuration as configuration
from catchplate import authority_revocation_planning_client as planning_client
from catchplate import authority_revocation_planner_custody_transport as transport
from catchplate import authority_revocation_verifier as verifier
from catchplate import authority_revocation_writer_ack_expectation as expectation
from catchplate import authority_revocation_writer_acknowledgment as acknowledgment
from catchplate import authority_revocation_writer_commitment as commitment


_IDENTITY_FIELDS = ("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")
_AGE_FIELDS = ("maximum_assertion_age_ns", "maximum_plan_age_ns", "maximum_clock_skew_ns")


class RevocationPlannerCustodyClientError(ValueError):
    pass


def _configured(payload, configuration_digest, generation, runtime_role_identities, work):
    """Own full configuration and hold all endpoint/key pins before callbacks."""
    ledger = commitment.capture._SharedLedger(work)
    commitment.plan.contract._digest(configuration_digest)
    if type(payload) is not dict:
        raise RevocationPlannerCustodyClientError("planner custody configuration is not an exact object")
    owned = configuration._ConfigurationCapture(
        ledger, maximum_bytes=authority.MAX_REQUEST_BYTES).visit(payload)
    # This is the real measured verifier -> planner endpoint and the same
    # enabled-operation admission as detached planning, not a wider peer route.
    path, peer_uid, peer_gid, timeout, age = planning_client._endpoint(owned, work)
    roles = owned["roles"]
    writer = roles["planner-writer"]
    if type(writer) is not dict:
        raise RevocationPlannerCustodyClientError("planner custody writer role is not an exact object")
    commitment.plan.contract._literal(writer["processMode"], "policy-authority-planner-writer")
    commitment.plan.contract._integer(writer["maximumInternalAgeNs"], minimum=1)
    age = min(age, writer["maximumInternalAgeNs"])
    writer_key_bytes = writer["responseSigningPublicKeyBase64Url"]
    if type(writer_key_bytes) is not str or len(writer_key_bytes) != 43:
        raise RevocationPlannerCustodyClientError("planner custody writer key is not bounded raw32 transport")
    writer_pin = writer["responseSigningSpkiDigest"]
    commitment.plan.contract._digest(writer_pin)
    other_pins = tuple(roles[name]["responseSigningSpkiDigest"]
        for name in ("verifier", "planner", "issuer", "executor"))
    for pin in other_pins:
        commitment.plan.contract._digest(pin)
    if writer_pin in other_pins:
        raise RevocationPlannerCustodyClientError("planner custody writer response key reuses another role pin")
    owner = verifier._verifier_from_configuration_on_work(payload=owned,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, work=work)
    fixed = owner._snapshot_configuration()
    return fixed, (path, peer_uid, peer_gid, timeout), age, writer_key_bytes, writer_pin


def _clocks(work):
    monotonic = configuration.production._callback(work, time.monotonic_ns)
    epoch = configuration.production._callback(work, time.time_ns)
    return epoch, monotonic


def _fresh_now(pins, age, skew, work):
    epoch, monotonic = _clocks(work)
    commitment._check_freshness_pins(pins, now_epoch_ns=epoch,
        now_monotonic_ns=monotonic, maximum_age_ns=age, maximum_clock_skew_ns=skew)


def _request_relay_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities,
        intent_bytes, envelope_bytes, evaluation_context_bytes,
        historical_expectations_bytes, work):
    """Return one authenticated original relay without forwarding any custody."""
    try:
        commitment.capture._SharedLedger(work)
        commitment._raw(intent_bytes, commitment.MAX_CONTROL_BYTES)
        commitment._body_bounds(envelope_bytes, evaluation_context_bytes, historical_expectations_bytes)
        transport._validate_relay_lengths((len(intent_bytes), len(envelope_bytes),
            len(evaluation_context_bytes), len(historical_expectations_bytes)))
        fixed, endpoint, age, _, _ = _configured(payload, configuration_digest, generation, runtime_role_identities, work)
        path, peer_uid, peer_gid, timeout = endpoint
        epoch, monotonic = _clocks(work)
        _, history, pins = commitment._verify_intent_on_work(
            intent_bytes=intent_bytes, envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes,
            historical_expectations_bytes=historical_expectations_bytes,
            planner_public_key=fixed[0], verifier_public_key=fixed[1],
            expected_configuration_digest=fixed[7], expected_generation_sequence=fixed[8],
            expected_generation_digest=fixed[9], now_epoch_ns=epoch, now_monotonic_ns=monotonic,
            maximum_age_ns=age, maximum_clock_skew_ns=fixed[6], work=work)
        commitment.plan._same(tuple(history[name] for name in _AGE_FIELDS),
            (fixed[4], fixed[5], fixed[6]), work,
            "planner relay history differs from independently configured policy")
        # Authentication can consume real time. These are the original signed
        # issuance/deadline scalars, not history retimed to the next socket.
        _fresh_now(pins, age, fixed[6], work)
        relay_bytes = configuration.production._callback(work, lambda: transport._request_relay(
            path, intent_bytes=intent_bytes, envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes,
            historical_expectations_bytes=historical_expectations_bytes,
            timeout_seconds=timeout, expected_peer_uid=peer_uid, expected_peer_gid=peer_gid))
        commitment._raw(relay_bytes, commitment.MAX_CONTROL_BYTES)
        epoch, monotonic = _clocks(work)
        received = commitment._verify_commitments_on_work(intent_bytes=intent_bytes,
            relay_bytes=relay_bytes, envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes,
            historical_expectations_bytes=historical_expectations_bytes,
            planner_public_key=fixed[0], verifier_public_key=fixed[1],
            expected_configuration_digest=fixed[7], expected_generation_sequence=fixed[8],
            expected_generation_digest=fixed[9], now_epoch_ns=epoch, now_monotonic_ns=monotonic,
            maximum_age_ns=age, maximum_clock_skew_ns=fixed[6], work=work)
        pins = (received.intent_envelope["issuedAtEpochNs"], received.intent_envelope["issuedMonotonicNs"],
            received.relay_envelope["issuedAtEpochNs"], received.relay_envelope["issuedMonotonicNs"],
            received.expectations["deadline_epoch_ns"], received.expectations["deadline_monotonic_ns"])
        commitment.plan._same(tuple(received.expectations[name] for name in _AGE_FIELDS),
            (fixed[4], fixed[5], fixed[6]), work,
            "planner relay response history differs from independently configured policy")
        _fresh_now(pins, age, fixed[6], work)
        return relay_bytes
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, RevocationPlannerCustodyClientError):
            raise
        raise RevocationPlannerCustodyClientError("configured planner relay request failed") from exc


def _forward_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities,
        intent_bytes, relay_bytes, envelope_bytes, evaluation_context_bytes,
        historical_expectations_bytes, work):
    """Explicitly forward fixed originals and authenticate the writer's ACK.

    The expected scalar request is derived through real authentication and
    retained-plan replay before any socket. The response cannot supply expected
    fields, keys or policy. Only ACK verification follows the potentially
    committing exchange; an exception makes no claim that custody rolled back.
    """
    try:
        commitment.capture._SharedLedger(work)
        commitment._raw(intent_bytes, commitment.MAX_CONTROL_BYTES)
        commitment._raw(relay_bytes, commitment.MAX_CONTROL_BYTES)
        commitment._body_bounds(envelope_bytes, evaluation_context_bytes, historical_expectations_bytes)
        transport._validate_forward_lengths((len(intent_bytes), len(relay_bytes), len(envelope_bytes),
            len(evaluation_context_bytes), len(historical_expectations_bytes)))
        fixed, endpoint, age, writer_key_bytes, writer_pin = _configured(
            payload, configuration_digest, generation, runtime_role_identities, work)
        path, peer_uid, peer_gid, timeout = endpoint
        writer_public_key = configuration._key(writer_key_bytes, work, expected_spki=writer_pin)
        epoch, monotonic = _clocks(work)
        request_fields, pins = expectation._expected_ack_request_and_freshness_on_work(
            intent_bytes=intent_bytes, relay_bytes=relay_bytes, envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes,
            historical_expectations_bytes=historical_expectations_bytes,
            planner_public_key=fixed[0], verifier_public_key=fixed[1],
            expected_planner_identity=dict(zip(_IDENTITY_FIELDS, fixed[2])),
            expected_verifier_identity=dict(zip(_IDENTITY_FIELDS, fixed[3])),
            expected_configuration_digest=fixed[7], expected_generation_sequence=fixed[8],
            expected_generation_digest=fixed[9], now_epoch_ns=epoch, now_monotonic_ns=monotonic,
            maximum_age_ns=age, maximum_clock_skew_ns=fixed[6],
            maximum_assertion_age_ns=fixed[4], maximum_plan_age_ns=fixed[5], work=work)
        _fresh_now(pins, age, fixed[6], work)
        acknowledgment_bytes = configuration.production._callback(work, lambda: transport._forward_originals(
            path, intent_bytes=intent_bytes, relay_bytes=relay_bytes, envelope_bytes=envelope_bytes,
            evaluation_context_bytes=evaluation_context_bytes,
            historical_expectations_bytes=historical_expectations_bytes,
            timeout_seconds=timeout, expected_peer_uid=peer_uid, expected_peer_gid=peer_gid))
        acknowledgment._verify_on_work(acknowledgment_bytes=acknowledgment_bytes,
            request_fields=request_fields, writer_public_key=writer_public_key,
            expected_writer_spki_digest=writer_pin, work=work)
        return acknowledgment_bytes
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, RevocationPlannerCustodyClientError):
            raise
        raise RevocationPlannerCustodyClientError("configured planner custody forwarding failed") from exc
