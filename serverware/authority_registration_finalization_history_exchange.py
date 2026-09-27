"""Historical finalization authorization, custody raw7 and full-vector grant replay.

The actual finalization mapper admits independently configured transition keys;
evidence-admission controls cannot enter this path. Complete original verifier
intent commitments precede detached history parsing. Real transition proof and
complete-vector replay then join every original execution-grant claim.

Expired originals remain history only. The supplied current processing window,
work and inherited deadline are never reopened. No signing, SQL, transport,
storage, present-caller permission or live-currentness authority is provided.
"""
from __future__ import annotations

from dataclasses import dataclass
import time

from serverware import authority_registration_finalization_authorization as caller
from serverware import authority_webauthn_transition_custody_actions as custody
from serverware import authority_registration_finalization_reservation_transport as reservation_wire


grants, authorization, shape = caller.grants, caller.authorization, caller.shape
evidence, wire = custody.evidence, custody.wire
clock, measured = wire.clock, custody.configuration.configuration
OPERATION = caller.OPERATION
MAX_ORIGINAL_BYTES = grants.replay.MAX_ORIGINAL_BYTES


class RegistrationFinalizationHistoryError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _HistoricalFinalizationExchange:
    """Owned same-call facts; never accepted as an original-admission token."""

    request_digest: str
    operation_id: str
    authorization_digest: str
    database_id: str
    generation_digest: str
    expectations: dict
    planner_public_key: object
    operation_public_key: object
    raw4: tuple[bytes, ...]
    request: dict
    inputs_bytes: bytes


def _verify_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, originals, authorization_enrollment_bytes,
        grant_enrollment_bytes, current_root_enrollment_bytes, root_public_key,
        live_window, work, transport_deadline_ns=None):
    """Admit raw10=(authorization, custody raw7, before-vector, grant).

    This is the same independently admitted configuration/generation cohort.
    Received history cannot appoint an archive, old key or trust root.
    """
    ledger = evidence.capture._SharedLedger(work)
    held = reservation_wire._originals(originals, response=False)
    raw4, before = grants.replay._originals(OPERATION, held[3:7], held[8])
    caller_enrollment = authorization._original(authorization_enrollment_bytes,
        caller.MAX_ENROLLMENT_BYTES, "historical finalization caller enrollment")
    grant_enrollment = authorization._original(grant_enrollment_bytes,
        grants.MAX_ENROLLMENT_BYTES, "historical finalization grant enrollment")
    current_enrollment = authorization._original(current_root_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "historical finalization current-root enrollment")
    if sum(len(raw) for raw in (*held, caller_enrollment, grant_enrollment,
            current_enrollment)) > MAX_ORIGINAL_BYTES:
        raise RegistrationFinalizationHistoryError("historical finalization originals exceed their complete bound")
    digest, root = configuration_digest, root_public_key
    shape._digest(digest)
    authorization._public(root)
    window = clock._validate(live_window)
    inherited = transport_deadline_ns
    if inherited is not None:
        shape._integer(inherited, minimum=1)
    bound = window[4] if inherited is None else min(window[4], inherited)
    if type(payload) is not dict or type(generation) is not dict:
        raise RegistrationFinalizationHistoryError("historical finalization configuration is not exact data")
    shape._bounded_object(generation, 24, "historical finalization launch context")
    owned_payload = measured._ConfigurationCapture(ledger,
        maximum_bytes=wire.authority.MAX_REQUEST_BYTES).visit(payload)
    owned_generation = evidence.capture._JSONCapture(ledger).visit(
        {name: generation[name] for name in measured._GENERATION_FIELDS})
    owned_runtime = evidence.capture._JSONCapture(ledger,
        maximum_bytes=8192).visit(runtime_role_identities)
    last_epoch, last_monotonic = window[0], window[2]

    def current():
        nonlocal last_epoch, last_monotonic
        now = clock._check_on_work(window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if now < last_epoch or monotonic < last_monotonic or monotonic >= bound:
            raise RegistrationFinalizationHistoryError("historical finalization processing expired or clocks reversed")
        last_epoch, last_monotonic = now, monotonic
        return now

    current()
    configured = custody.configuration._capture_on_work(operation=OPERATION,
        payload=owned_payload, configuration_digest=digest, generation=owned_generation,
        runtime_role_identities=owned_runtime, work=work)
    current()
    authorized = caller._verify_historical_on_work(authorization_bytes=held[0],
        authorization_enrollment_bytes=caller_enrollment,
        current_root_enrollment_bytes=current_enrollment, grant_enrollment_bytes=grant_enrollment,
        root_public_key=root, configuration_digest=digest,
        planner_public_key=configured.pins[1], evidence_public_key=configured.pins[4],
        live_window=window, work=work, transport_deadline_ns=bound)
    if authorized.last_epoch_ns < last_epoch or authorized.last_monotonic_ns < last_monotonic:
        raise RegistrationFinalizationHistoryError("historical finalization authorization reversed processing clocks")
    last_epoch, last_monotonic = authorized.last_epoch_ns, authorized.last_monotonic_ns
    evidence.plan._same(authorized.generation_digest, configured.generation_digest, work,
        "historical finalization caller differs from the configured generation")
    pins = custody.relay._hold_on_work((held[1], held[2]), held[3:8], configured.pins,
        configured.generation_sequence, configured.generation_digest,
        configured.verifier_public_key, configured.maximum_control_age_ns, work)
    planner, operation_key, skew = pins[1], pins[4], pins[6][1]
    current()

    # These actual wire primitives authenticate signatures and complete body
    # commitments without opening the LIVE custody verifier's control windows.
    intent, signature, unsigned = wire._read_control(held[1], relay=False, work=work)
    intent_times = intent["issuedAtEpochNs"], intent["expiresAtEpochNs"]
    record_digest = intent["retainedRecordDigest"]
    signed_bodies = {name: intent[name] for name in custody.intent._BODY_FIELDS}
    wire._signature(signature, unsigned, relay=False,
        public_key=configured.verifier_public_key, work=work)
    evidence.capability._canonical(held[1], intent, ledger,
        wire.MAX_CONTROL_BYTES, wire.MAX_CONTROL_NODES)
    wire._bind_control(intent, configuration_digest=digest,
        generation_sequence=configured.generation_sequence, generation_digest=configured.generation_digest,
        operation=OPERATION, work=work)
    actual_bodies = wire._body_commitments_on_work(envelope_bytes=held[3], proof_bytes=held[4],
        inputs_bytes=held[5], context_bytes=held[6], historical_expectations_bytes=held[7], work=work)
    evidence.plan._same(actual_bodies, signed_bodies, work,
        "historical finalization intent differs from complete original raw5")
    current()
    relay, signature, unsigned = wire._read_control(held[2], relay=True, work=work)
    relay_times = relay["issuedAtEpochNs"], relay["expiresAtEpochNs"]
    wire._signature(signature, unsigned, relay=True, public_key=planner, work=work)
    evidence.capability._canonical(held[2], relay, ledger,
        wire.MAX_CONTROL_BYTES, wire.MAX_CONTROL_NODES)
    wire._bind_control(relay, configuration_digest=digest,
        generation_sequence=configured.generation_sequence, generation_digest=configured.generation_digest,
        operation=OPERATION, work=work)
    evidence.plan._same((wire.retention._bytes_digest(held[1], work), len(held[1])),
        (relay["intentBytesDigest"], relay["intentByteCount"]), work,
        "historical finalization relay differs from original intent")
    evidence.plan._same(relay["retainedRecordDigest"], record_digest, work,
        "historical finalization controls name different records")
    for issued, expires in (intent_times, relay_times):
        wire._time_pins({"issuedAtEpochNs": issued, "expiresAtEpochNs": expires},
            configured.maximum_control_age_ns, skew)
        if issued > current() + skew:
            raise RegistrationFinalizationHistoryError("historical finalization custody is future-issued")
    if relay_times[1] > intent_times[1] or relay_times[0] < intent_times[0] - skew:
        raise RegistrationFinalizationHistoryError("historical finalization relay widens or predates its intent")

    # Only now parse the history committed by the genuine verifier signature.
    # Independent configured pins still constrain its keys, RP/origin and policy.
    historical = custody.intent.context_wire._decode_on_work(held[7], work=work)
    expected = custody.intent.admission._capture_expectations_on_work(pins, historical, work)
    current()
    replayed = grants.replay._replay_on_work(operation=OPERATION, originals=raw4,
        expectations=expected, planner_public_key=planner, operation_public_key=operation_key,
        before_vector_bytes=before, work=work)
    current()
    evidence.plan._same(replayed.retained_record_digest, record_digest, work,
        "historical finalization custody differs from actual complete-vector replay")
    request = replayed.request
    request_digest = authorization.commitment._typed_request_digest(request, work=work)
    operation_id = evidence.plan._frame("serverware.policyAuthorityOperation/v2",
        (OPERATION.encode("ascii"), request_digest.encode("ascii")), work)
    for actual, value in ((request["operation"], OPERATION),
            (request["requestDigest"], request_digest), (request["operationId"], operation_id),
            (request_digest, authorized.request_digest), (operation_id, authorized.operation_id)):
        evidence.plan._same(actual, value, work,
            "historical finalization typed request differs from original caller authority")
    plan_issued, plan_expires = replayed.original_interval
    if plan_issued < authorized.issued_at_epoch_ns or plan_expires > authorized.expires_at_epoch_ns:
        raise RegistrationFinalizationHistoryError("historical finalization plan escapes its prior authorization")
    policy = expected["proofExpectations"]["policy"]
    if plan_issued > current() + skew:
        raise RegistrationFinalizationHistoryError("historical finalization plan is future-issued")
    for issued, expires in (intent_times, relay_times):
        # Original interval containment, not a live verifier invoked with a
        # substituted now=issued. Full plan replay already checked its original
        # policy/cutoff relations; no old instant is a processing clock here.
        if (expires > plan_expires or expires > policy["deadlineEpochNs"]
                or plan_issued > issued + skew
                or expires - 1 - plan_issued > expected["maximumPlanAgeNs"]):
            raise RegistrationFinalizationHistoryError("historical custody escapes the original plan interval")
    expected_claims = grants._replay_claims(replayed, work)
    current()
    grant, _grant_digest = grants._verify_historical_control_on_work(grant_bytes=held[9],
        grant_enrollment_bytes=grant_enrollment, current_root_enrollment_bytes=current_enrollment,
        root_public_key=root, planner_public_key=planner, operation_public_key=operation_key,
        expected_authorization_digest=authorized.authorization_digest, work=work)
    for name, value in expected_claims.items():
        evidence.plan._same(grant[name], value, work,
            "historical finalization grant differs from genuine complete replay " + name)
    for name, value in (("operation", OPERATION), ("requestDigest", request_digest),
            ("operationId", operation_id), ("databaseId", authorized.database_id),
            ("generationDigest", configured.generation_digest),
            ("currentRootEnrollmentDigest", authorized.current_root_enrollment_digest),
            ("grantEnrollmentDigest", authorized.grant_enrollment_digest)):
        evidence.plan._same(grant[name], value, work,
            "historical finalization grant differs from independent original scope " + name)
    if (grant["issuedAtEpochNs"] < authorized.issued_at_epoch_ns
            or grant["expiresAtEpochNs"] > min(authorized.expires_at_epoch_ns, plan_expires,
                policy["deadlineEpochNs"], intent_times[1], relay_times[1])
            or grant["issuedAtEpochNs"] > current() + skew):
        raise RegistrationFinalizationHistoryError("historical finalization grant escapes original authority intervals")
    # Recheck owned control graphs after downstream native replay/key callbacks.
    evidence.capability._canonical(held[1], intent, ledger,
        wire.MAX_CONTROL_BYTES, wire.MAX_CONTROL_NODES)
    evidence.capability._canonical(held[2], relay, ledger,
        wire.MAX_CONTROL_BYTES, wire.MAX_CONTROL_NODES)
    current()
    return _HistoricalFinalizationExchange(request_digest, operation_id,
        authorized.authorization_digest, authorized.database_id, configured.generation_digest,
        expected, planner, operation_key, raw4, request, raw4[2])
