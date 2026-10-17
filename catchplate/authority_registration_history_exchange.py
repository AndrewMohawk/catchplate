"""Genuine historical planning/caller/grant exchange admission from originals.

No reservation or completion need exist. The actual signed exchange and caller
authorization are authenticated; full original plan replay joins every grant
claim to the complete before-vector and derived after-vector. A signed grant
or vector hash alone cannot supply this admission. Independent configuration,
keys and enrollments remain caller prerequisites, not response-appointed pins.

This is private historical inspection, never current permission or a successful
carrier input API. The caller's processing window/work remain unchanged; no
old timestamp supplies a clock and no execution interval is revived. There is
no signing, SQL, transport, persistence, retry or present-caller admission here.
"""
from __future__ import annotations

from dataclasses import dataclass
import time

from catchplate import authority_registration_execution_exchange as exchange
from catchplate import authority_registration_reservation_transport as reservation_wire
from catchplate import authority_webauthn_evidence_plan_request_history as request_history
from catchplate import authority_webauthn_evidence_plan_response_history as response_history
from catchplate import authority_webauthn_evidence_plan_history as plan_history


authorization, grants, evidence, clock = (
    exchange.authorization, exchange.grants, exchange.evidence, exchange.clock)
current_root = grants.authorization


class RegistrationHistoryExchangeError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _HistoricalRegistrationExchange:
    """Same-call facts only; no verifier accepts this instead of originals."""

    request_digest: str
    operation_id: str
    authorization_digest: str
    database_id: str
    generation_digest: str
    expectations: dict
    planner_public_key: object
    evidence_public_key: object


def _verify_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, originals, authorization_enrollment_bytes,
        grant_enrollment_bytes, current_root_enrollment_bytes, root_public_key,
        live_window, work, transport_deadline_ns=None):
    ledger = evidence.capture._SharedLedger(work)
    held = reservation_wire._originals(originals, response=False)
    caller_enrollment = current_root._original(authorization_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "historical exchange caller enrollment")
    grant_enrollment = current_root._original(grant_enrollment_bytes,
        grants.MAX_ENROLLMENT_BYTES, "historical exchange grant enrollment")
    current_enrollment = current_root._original(current_root_enrollment_bytes,
        current_root.MAX_ENROLLMENT_BYTES, "historical exchange current-root enrollment")
    if sum(len(raw) for raw in (*held, caller_enrollment, grant_enrollment,
            current_enrollment)) > exchange.MAX_ORIGINAL_BYTES:
        raise RegistrationHistoryExchangeError("historical exchange originals exceed their complete bound")
    shape = current_root.shape
    shape._digest(configuration_digest)
    digest, root = configuration_digest, root_public_key
    current_root._public(root)
    window = clock._validate(live_window)
    inherited = transport_deadline_ns
    if inherited is not None:
        shape._integer(inherited, minimum=1)
    bound = window[4] if inherited is None else min(window[4], inherited)
    if type(payload) is not dict or type(generation) is not dict:
        raise RegistrationHistoryExchangeError("historical exchange configuration is not exact data")
    shape._bounded_object(generation, 24, "historical exchange launch context")
    owned_payload = exchange.measured._ConfigurationCapture(ledger,
        maximum_bytes=exchange.wire.authority.MAX_REQUEST_BYTES).visit(payload)
    owned_generation = evidence.capture._JSONCapture(ledger).visit(
        {name: generation[name] for name in exchange.measured._GENERATION_FIELDS})
    owned_runtime = evidence.capture._JSONCapture(ledger,
        maximum_bytes=8192).visit(runtime_role_identities)
    last_epoch, last_monotonic = window[0], window[2]

    def current():
        nonlocal last_epoch, last_monotonic
        now = clock._check_on_work(window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if now < last_epoch or monotonic < last_monotonic or monotonic >= bound:
            raise RegistrationHistoryExchangeError("historical exchange processing expired or its clocks reversed")
        last_epoch, last_monotonic = now, monotonic
        return now

    current()
    configured = exchange.configuration._capture_on_work(purpose="registration",
        payload=owned_payload, configuration_digest=digest, generation=owned_generation,
        runtime_role_identities=owned_runtime, work=work)
    current()
    request = request_history._verify_on_work(control_bytes=held[1],
        context_bytes=held[2], inputs_bytes=held[3], pins=configured.pins,
        generation_sequence=configured.generation_sequence,
        generation_digest=configured.generation_digest, verifier_public_key=configured.verifier_public_key,
        maximum_control_age_ns=configured.maximum_control_age_ns,
        live_window=window, work=work, transport_deadline_ns=bound)
    current()
    response = response_history._verify_on_work(control_bytes=held[4],
        request_control_bytes=held[1], envelope_bytes=held[5], inputs_bytes=held[6],
        evaluation_context_bytes=held[7], pins=configured.pins,
        generation_sequence=configured.generation_sequence,
        generation_digest=configured.generation_digest, verifier_public_key=configured.verifier_public_key,
        request_issued_at_epoch_ns=request.issued_at_epoch_ns,
        request_expires_at_epoch_ns=request.expires_at_epoch_ns,
        maximum_control_age_ns=configured.maximum_control_age_ns,
        live_window=window, work=work, transport_deadline_ns=bound)
    work.charge(input_bytes=len(held[3]) + len(held[6]))
    if held[3] != held[6]:
        raise RegistrationHistoryExchangeError("historical planning response changed the original inputs")
    current()
    history = plan_history._admit_history_on_work(envelope_bytes=held[5],
        inputs_bytes=held[6], evaluation_context_bytes=held[7], request_context=request.context,
        request_issued_at_epoch_ns=request.issued_at_epoch_ns,
        request_expires_at_epoch_ns=request.expires_at_epoch_ns,
        response_issued_at_epoch_ns=response.issued_at_epoch_ns,
        response_expires_at_epoch_ns=response.expires_at_epoch_ns,
        pins=configured.pins, maximum_control_age_ns=configured.maximum_control_age_ns,
        live_window=window, work=work, transport_deadline_ns=bound)
    current()
    authorized = authorization._verify_historical_on_work(authorization_bytes=held[0],
        authorization_enrollment_bytes=caller_enrollment,
        current_root_enrollment_bytes=current_enrollment, grant_enrollment_bytes=grant_enrollment,
        root_public_key=root, configuration_digest=digest,
        planner_public_key=configured.pins[1], evidence_public_key=configured.pins[4],
        live_window=window, work=work, transport_deadline_ns=bound)
    current()
    evidence.plan._same(authorized.generation_digest, configured.generation_digest, work,
        "historical caller enrollment differs from the independently configured generation")
    for name, expected in (("operation", authorization.OPERATION),
            ("requestDigest", authorized.request_digest), ("operationId", authorized.operation_id)):
        evidence.plan._same(request.context["request"][name], expected, work,
            "historical planning request differs from original caller authorization")

    # This is the complete-vector replay path, not just history admission or a
    # before-vector hash. It verifies original plan semantics, joins every
    # affected predecessor, derives the complete after-vector and checks delta.
    replayed = grants.replay._replay_on_work(operation=authorization.OPERATION,
        originals=held[5:8], expectations=history, planner_public_key=configured.pins[1],
        operation_public_key=configured.pins[4], before_vector_bytes=held[8], work=work)
    expected_claims = grants._replay_claims(replayed, work)
    current()
    grant, _grant_digest = grants._verify_historical_control_on_work(grant_bytes=held[9],
        grant_enrollment_bytes=grant_enrollment, current_root_enrollment_bytes=current_enrollment,
        root_public_key=root, planner_public_key=configured.pins[1], operation_public_key=configured.pins[4],
        expected_authorization_digest=authorized.authorization_digest, work=work)
    for name, expected in expected_claims.items():
        evidence.plan._same(grant[name], expected, work,
            "historical grant differs from genuine complete plan replay " + name)
    for name, expected in (("operation", authorization.OPERATION),
            ("requestDigest", authorized.request_digest), ("operationId", authorized.operation_id),
            ("databaseId", authorized.database_id), ("generationDigest", configured.generation_digest),
            ("currentRootEnrollmentDigest", authorized.current_root_enrollment_digest),
            ("grantEnrollmentDigest", authorized.grant_enrollment_digest)):
        evidence.plan._same(grant[name], expected, work,
            "historical grant differs from independent caller and planning scope")
    if (grant["issuedAtEpochNs"] < authorized.issued_at_epoch_ns
            or grant["expiresAtEpochNs"] > min(authorized.expires_at_epoch_ns,
                request.expires_at_epoch_ns, response.expires_at_epoch_ns)):
        raise RegistrationHistoryExchangeError("historical grant escapes its original authority interval")
    current()
    return _HistoricalRegistrationExchange(authorized.request_digest, authorized.operation_id,
        authorized.authorization_digest, authorized.database_id, configured.generation_digest,
        history, configured.pins[1], configured.pins[4])
