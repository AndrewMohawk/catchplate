"""Same-call original admission and claims for consume-only execution grants.

Only raw originals, independent expectations and the actual receiving owner
enter this path. Private projections connect one invocation; no service accepts
them instead of signatures or proof replay. The shared work, original clock
opening and inherited deadline are never replaced or enlarged.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from serverware import authority_oidc_session_activation_delivery_execution_authorization as caller
from serverware import authority_oidc_session_activation_delivery_execution_custody as custody
from serverware import authority_oidc_session_activation_delivery_execution_grant as wire
from serverware import authority_successor_execution_window as processing


authorization, capture, plan, shape = caller.authorization, caller.capture, caller.plan, caller.shape
evidence, clock, enrollments = caller.evidence, caller.clock, caller.enrollments
_OWNER = custody.OidcSessionActivationDeliveryExecutionCustody
_RESULT_DOMAIN = "serverware.policyAuthorityControlledWriterResult/v2"


class DeliveryExecutionGrantAdmissionError(ValueError):
    pass


def _fail(message):
    raise DeliveryExecutionGrantAdmissionError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Held:
    inputs: object
    authorization_bytes: bytes
    receiving_custody: object
    custody_configuration: object
    extra_originals: tuple
    original_bytes: int
    required_consumer_role: str


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Admitted:
    held: _Held
    enrollment: object
    authorization: object
    bindings: dict
    window: tuple
    deadline_ns: int
    live: object


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Replay:
    admitted: _Admitted
    claims: dict
    replayed: object
    valid_until_epoch_ns: int
    window: tuple
    deadline_ns: int
    live: object


def _hold_on_work(*, authorization_bytes, authorization_enrollment_bytes,
        current_root_enrollment_bytes, grant_enrollment_bytes, root_public_key,
        configuration_digest, planner_public_key, operation_public_key, originals,
        expectations, before_vector_bytes, receiving_custody, live_window,
        transport_deadline_ns, work, extra_originals=(), required_consumer_role="grant"):
    capture._SharedLedger(work)
    custody.bootstrap._profile(required_consumer_role)
    original = authorization._original(authorization_bytes, caller.MAX_AUTHORIZATION_BYTES,
        "consume grant caller authorization")
    if type(extra_originals) is not tuple or len(extra_originals) > 4:
        _fail("consume admission permits only a grant and fixed reserve/snapshot/ACK originals")
    extras = tuple(authorization._original(raw,
        wire.MAX_GRANT_BYTES if position == 0 else wire.MAX_ORIGINAL_BYTES,
        "consume admission extra original") for position, raw in enumerate(extra_originals))
    if type(originals) is not tuple or len(originals) != 2:
        _fail("consume grant requires its exact original plan and ciphertext pair")
    signed = authorization._original(originals[0], caller.contract.MAX_BYTES, "consume plan")
    encrypted = caller.bundle._bounded_frame(originals[1])
    before = authorization._original(before_vector_bytes, caller.vector.MAX_BYTES, "consume before vector")
    caller_raw = authorization._original(authorization_enrollment_bytes,
        caller.MAX_ENROLLMENT_BYTES, "consume caller enrollment")
    current_raw = authorization._original(current_root_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "consume current-root enrollment")
    grant_raw = authorization._original(grant_enrollment_bytes,
        enrollments.MAX_ENROLLMENT_BYTES, "consume grant enrollment")
    root, planner, operation_key, config = (
        root_public_key, planner_public_key, operation_public_key, configuration_digest)
    for key in (root, planner, operation_key):
        authorization._public(key)
    shape._digest(config)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    bound = min(window[4], transport_deadline_ns)
    owner = receiving_custody
    if type(owner) is not _OWNER:
        _fail("consume grant requires the actual dedicated receiving custodian")
    configured = _OWNER._snapshot_configuration(owner)
    _OWNER.require_consumer_role_on_work(owner, consumer_role=required_consumer_role, work=work)
    receiver_originals = (configured.custody_bytes, configured.planner_bootstrap_bytes,
        configured.planner_history_custody_bytes, configured.receiving_history_custody_bytes)
    total = sum(len(raw) for raw in (original, *extras, signed, encrypted, before,
        caller_raw, current_raw, grant_raw, *receiver_originals))
    if total > wire.MAX_ORIGINAL_BYTES:
        _fail("consume grant admission originals exceed the fixed aggregate bound")
    # Hold the optional grant/raw3, every receiving original and configuration/key
    # reference before the caller's typed graph capture can hash or call out.
    work.charge(input_bytes=sum(map(len, (*extras, *receiver_originals))))
    inputs = caller._capture_on_work(originals=(signed, encrypted), expectations=expectations,
        before_vector_bytes=before, authorization_enrollment_bytes=caller_raw,
        current_root_enrollment_bytes=current_raw, grant_enrollment_bytes=grant_raw,
        root_public_key=root, configuration_digest=config, planner_public_key=planner,
        operation_public_key=operation_key, live_window=window, transport_deadline_ns=bound,
        work=work, extra_originals=(original,))
    if _OWNER._snapshot_configuration(owner) is not configured:
        _fail("consume receiving configuration changed during input capture")
    return _Held(inputs, original, owner, configured, extras, total, required_consumer_role)


def _frames(originals, work):
    result = []
    for position, original in enumerate(originals):
        work.charge(hashes=1, input_bytes=len(original))
        result.append({"position": position,
            "bytesDigest": "sha256:" + hashlib.sha256(original).hexdigest(), "byteCount": len(original)})
    work.prepare_copy(result)
    return result


def _admit_on_work(held, work):
    """Authenticate actual caller/root originals, not a caller's success DTO."""
    capture._SharedLedger(work)
    if type(held) is not _Held or type(held.inputs) is not caller._Inputs:
        _fail("consume grant inputs were not held by the fixed path")
    inputs, owner, configured = held.inputs, held.receiving_custody, held.custody_configuration
    if _OWNER._snapshot_configuration(owner) is not configured:
        _fail("consume receiving configuration changed before admission")
    _OWNER.require_consumer_role_on_work(owner, consumer_role=held.required_consumer_role, work=work)
    control = caller._verify_held_on_work(inputs, held.authorization_bytes, work)
    control.live()
    enrolled = enrollments._admit_enrollment_on_work(grant_enrollment_bytes=inputs.grant_enrollment,
        current_root_enrollment_bytes=inputs.current_enrollment, root_public_key=inputs.root, work=work)
    # The dedicated grant enrollment already excludes root/state roles; keep
    # the consume planner and operation purposes separate as well.
    caller.primitives._separate(enrolled.authorizer_public_key,
        (inputs.planner, inputs.operation_key), work)
    _OWNER.bind_context_on_work(owner, root_public_key=inputs.root,
        current_root_enrollment_bytes=inputs.current_enrollment, work=work)
    policy = enrolled.payload
    window = processing._narrow(control.window,
        deadline_epoch_ns=min(control.expires_at_epoch_ns, configured.attestation_interval[1]),
        maximum_lifetime_ns=min(policy["maximumGrantAgeNs"], configured.maximum_age_ns),
        maximum_clock_skew_ns=min(policy["maximumClockSkewNs"], configured.maximum_clock_skew_ns))
    bound = min(control.deadline_ns, inputs.deadline_ns, window[4],
        configured.opening_sample[0] + configured.attestation_interval[1] - configured.opening_sample[1])
    last_epoch, last_monotonic = control.last_epoch_ns, control.last_monotonic_ns

    def live():
        nonlocal last_epoch, last_monotonic
        if _OWNER._snapshot_configuration(owner) is not configured:
            _fail("consume receiving configuration changed after caller admission")
        first, first_mono = control.live()
        middle = clock._check_on_work(window, work=work)
        now, mono = control.live()
        if (first < last_epoch or first_mono < last_monotonic
                or not first <= middle <= now or mono < first_mono
                or mono >= bound or now >= window[3]):
            _fail("consume grant admission expired or clocks reversed")
        if _OWNER._snapshot_configuration(owner) is not configured:
            _fail("consume receiving lifecycle changed during currentness check")
        last_epoch, last_monotonic = now, mono
        return now, mono

    live()
    bindings = {"schema": wire.GRANT_PAYLOAD_SCHEMA,
        "sourceRevision": wire.authority.SOURCE_REVISION,
        "grantEnrollmentDigest": enrolled.enrollment_digest,
        "currentRootEnrollmentDigest": policy["currentRootEnrollmentDigest"],
        "configurationDigest": inputs.configuration_digest,
        "databaseId": policy["databaseId"], "generationDigest": policy["generationDigest"],
        "authorizerMeasurementDigest": policy["authorizer"]["measurementDigest"],
        "operation": wire.OPERATION, "requestDigest": control.request_digest,
        "operationId": control.operation_id, "requestAuthorizationDigest": control.authorization_digest,
        "journalDigest": control.journal_digest, "retainedRecordDigest": control.retained_record_digest,
        "planDigest": control.plan_digest, "beforeVectorDigest": control.before_vector_digest,
        "originalFrames": _frames(inputs.originals, work)}
    owned = wire._Capture(capture._SharedLedger(work), maximum_bytes=wire.MAX_GRANT_BYTES).visit(bindings)
    live()
    return _Admitted(held, enrolled, control, owned, window, bound, live)


def _check_control_on_work(payload, admitted, work):
    """Check signed static commitments and actual freshness before decryption."""
    if type(admitted) is not _Admitted:
        _fail("consume grant admission is not the same-call fixed result")
    wire._shape(payload)
    for name, value in admitted.bindings.items():
        plan._same(payload[name], value, work, "consume grant independent control " + name)
    policy = admitted.enrollment.payload
    if payload["expiresAtEpochNs"] > min(admitted.authorization.expires_at_epoch_ns, admitted.window[3]):
        _fail("consume grant outlives its caller or inherited processing window")
    now, _mono = admitted.live()
    evidence._fresh(payload, now, policy["maximumGrantAgeNs"], admitted.window[6])
    return now


def _replay_on_work(admitted, work):
    """Call genuine independent receiving replay exactly once for this path."""
    if type(admitted) is not _Admitted:
        _fail("consume grant replay requires its same-call admitted originals")
    held, control = admitted.held, admitted.authorization
    inputs = held.inputs
    _OWNER.require_consumer_role_on_work(held.receiving_custody,
        consumer_role=held.required_consumer_role, work=work)
    admitted.live()
    actual = _OWNER.replay_on_work(held.receiving_custody,
        envelope_bytes=inputs.originals[0], encrypted_originals_bytes=inputs.originals[1],
        expectations=inputs.expectations, before_vector_bytes=inputs.before,
        live_window=admitted.window, transport_deadline_ns=admitted.deadline_ns, work=work)
    if type(actual) is not custody.replay._ReplayedDelivery:
        _fail("consume grant original replay returned another result type")
    admitted.live()
    custody.replay._narrowed(admitted.window, actual.live_window, admitted.deadline_ns, actual.deadline_ns)
    shape._literal(actual.operation, wire.OPERATION)
    plan._same(actual.request, inputs.expectations["request"], work, "consume grant actual replay request")
    for actual_value, expected, label in ((actual.plan_digest, control.plan_digest, "plan"),
            (actual.retained_record_digest, control.retained_record_digest, "retained record"),
            (actual.before_vector_digest, control.before_vector_digest, "before vector")):
        plan._same(actual_value, expected, work, "consume grant replay " + label)
    custody.replay._bytes_equal(actual.before_vector_bytes, inputs.before, work, "grant before vector")
    if type(actual.originals) is not tuple or len(actual.originals) != 2:
        _fail("consume grant replay lost its original plan/ciphertext pair")
    for original, expected in zip(actual.originals, inputs.originals):
        custody.replay._bytes_equal(original, expected, work, "grant plan/ciphertext")
    issued, expires = actual.original_interval
    if not issued <= control.issued_at_epoch_ns < control.expires_at_epoch_ns <= expires:
        _fail("consume grant caller control escapes the replayed original lifetime")
    policy = admitted.enrollment.payload
    valid_until = min(expires, control.expires_at_epoch_ns, actual.valid_until_epoch_ns,
        admitted.window[3], actual.live_window[3], issued + policy["maximumGrantAgeNs"])
    window = processing._narrow(actual.live_window, deadline_epoch_ns=valid_until,
        maximum_lifetime_ns=policy["maximumGrantAgeNs"], maximum_clock_skew_ns=admitted.window[6])
    bound = min(admitted.deadline_ns, actual.deadline_ns, window[4])
    valid_until = min(valid_until, window[3])
    last_epoch, last_monotonic = admitted.live()

    def live():
        nonlocal last_epoch, last_monotonic
        first, first_mono = admitted.live()
        replayed_now = actual.live()
        sampled = clock._check_on_work(window, work=work)
        now, mono = admitted.live()
        if (first < last_epoch or first_mono < last_monotonic
                or not first <= replayed_now <= sampled <= now
                or mono < first_mono or mono >= bound or now >= valid_until):
            _fail("consume grant original replay expired or clocks reversed")
        last_epoch, last_monotonic = now, mono
        return now, mono

    live()
    claims = {"operation": actual.operation, "requestDigest": actual.request["requestDigest"],
        "operationId": actual.request["operationId"], "retainedRecordDigest": actual.retained_record_digest,
        "planDigest": actual.plan_digest, "beforeVectorDigest": actual.before_vector_digest,
        "afterVectorDigest": actual.after_vector_digest,
        "resultDigest": evidence.plan._json_digest(_RESULT_DOMAIN, actual.result, capture._SharedLedger(work)),
        # These descriptors were hashed from the held bytes and those exact
        # bytes were just compared with the genuine replay's original pair.
        "originalFrames": admitted.bindings["originalFrames"],
        "originalIssuedAtEpochNs": issued, "originalExpiresAtEpochNs": expires}
    owned = wire._Capture(capture._SharedLedger(work), maximum_bytes=wire.MAX_GRANT_BYTES).visit(claims)
    live()
    return _Replay(admitted, owned, actual, valid_until, window, bound, live)


def _check_claims_on_work(payload, replayed, work):
    """Join genuine replay facts without invoking proof replay a second time."""
    if type(replayed) is not _Replay:
        _fail("consume grant claims are not from the same-call original replay")
    _check_control_on_work(payload, replayed.admitted, work)
    for name, value in replayed.claims.items():
        plan._same(payload[name], value, work, "consume grant genuine original replay " + name)
    if payload["expiresAtEpochNs"] > replayed.valid_until_epoch_ns:
        _fail("consume grant exceeds the independently replayed remaining lifetime")
    now, _mono = replayed.live()
    if now >= payload["expiresAtEpochNs"]:
        _fail("consume grant expired while joining original claims")
    return now
