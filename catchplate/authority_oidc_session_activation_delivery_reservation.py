"""Original-based consume reserve production and receipt admission.

One actual consume-grant verification replays the private originals once. The
signed reserve, distinct computation snapshot and ACK never stand in for that
replay or for an independently held current pending checkpoint. No I/O, SQL,
automatic resend, replacement signature or historical renewal is provided.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_current_root_authorization as current_root
from catchplate import authority_oidc_session_activation_delivery_computation as computation
from catchplate import authority_oidc_session_activation_delivery_execution_custody as custody
from catchplate import authority_oidc_session_activation_delivery_execution_grant_verification as grants
from catchplate import authority_oidc_session_activation_delivery_reservation_records as records
from catchplate import authority_successor_execution_window as windows


OPERATION = computation.OPERATION
plan = current_root.plan


class OidcSessionActivationDeliveryReservationError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _VerifiedReservation:
    """Same-call continuation only; no original-input API accepts this object."""

    originals: tuple
    material: object
    request: dict
    request_digest: str
    receipt: dict | None
    receipt_digest: str | None
    snapshot: dict
    replayed: object
    window: tuple
    deadline_ns: int
    live: object


def _fail(message):
    raise OidcSessionActivationDeliveryReservationError(message)


def _response_originals(values, *, allow_pending=False):
    if type(values) not in (tuple, list) or len(values) != 3:
        _fail("consume reservation requires exact original reserve/snapshot/ACK raw3")
    request = current_root._original(values[0], records.MAX_REQUEST_BYTES, "consume reserve")
    snapshot = current_root._original(values[1], records.MAX_SNAPSHOT_BYTES, "consume snapshot")
    receipt = (None if allow_pending and values[2] is None else
        current_root._original(values[2], records.MAX_RECEIPT_BYTES, "consume reserve ACK"))
    return request, snapshot, receipt


def _hold_originals(originals, before_vector_bytes, authorization_bytes, grant_bytes,
        authorization_enrollment_bytes, grant_enrollment_bytes,
        current_root_enrollment_bytes, receiving_custody):
    """Hold exact immutable originals before any graph/hash/clock callbacks."""
    caller = grants.admission.caller
    if type(originals) is not tuple or len(originals) != 2:
        _fail("consume reservation requires exact plan/ciphertext raw2")
    pair = (current_root._original(originals[0], caller.contract.MAX_BYTES, "consume plan"),
        caller.bundle._bounded_frame(originals[1]))
    before = current_root._original(before_vector_bytes, caller.vector.MAX_BYTES, "consume before vector")
    authorization = current_root._original(authorization_bytes, caller.MAX_AUTHORIZATION_BYTES,
        "consume caller authorization")
    grant = current_root._original(grant_bytes, grants.wire.MAX_GRANT_BYTES, "consume grant")
    caller_enrollment = current_root._original(authorization_enrollment_bytes,
        caller.MAX_ENROLLMENT_BYTES, "consume caller enrollment")
    grant_enrollment = current_root._original(grant_enrollment_bytes,
        grants.admission.enrollments.MAX_ENROLLMENT_BYTES, "consume grant enrollment")
    enrollment = current_root._original(current_root_enrollment_bytes,
        current_root.MAX_ENROLLMENT_BYTES, "consume current-root enrollment")
    if type(receiving_custody) is not custody.OidcSessionActivationDeliveryExecutionCustody:
        _fail("consume reservation requires the actual purpose-specific receiving owner")
    configured = custody.OidcSessionActivationDeliveryExecutionCustody._snapshot_configuration(receiving_custody)
    total = sum(map(len, (*pair, before, authorization, grant, caller_enrollment,
        grant_enrollment, enrollment, configured.custody_bytes, configured.planner_bootstrap_bytes,
        configured.planner_history_custody_bytes, configured.receiving_history_custody_bytes)))
    if total > grants.wire.MAX_ORIGINAL_BYTES:
        _fail("consume reservation originals exceed the source aggregate")
    return pair, before, authorization, grant, caller_enrollment, grant_enrollment, enrollment, total


def _same_bytes(actual, expected, work, label):
    work.charge(input_bytes=len(actual) + len(expected))
    if actual != expected:
        _fail(label)


def _reserve_guard(verified, material, request, work):
    policy = material.payload
    window = windows._narrow(verified.window, deadline_epoch_ns=request["expiresAtEpochNs"],
        maximum_lifetime_ns=policy["maxControlAgeNs"], maximum_clock_skew_ns=policy["maxClockSkewNs"])
    bound = min(verified.deadline_ns, window[4])

    def live():
        first = verified.live()
        now = windows.clock._check_on_work(window, work=work)
        last = verified.live()
        if (not first[0] <= now <= last[0] or first[1] > last[1]
                or last[1] >= bound or last[0] >= window[3]):
            _fail("consume reserve original allowance expired or clocks reversed")
        current_root._fresh(request, material, last[0])
        return last

    live()
    return window, bound, live


def _produce_on_work(*, originals, expectations, before_vector_bytes, authorization_bytes,
        grant_bytes, authorization_enrollment_bytes, grant_enrollment_bytes,
        current_root_enrollment_bytes, root_public_key, planner_public_key,
        operation_public_key, configuration_digest, computation_private_key,
        expected_predecessor_sequence, expected_predecessor_head_digest, expected_fence,
        receiving_custody, live_window, transport_deadline_ns, work):
    """Produce a fresh signed reserve/snapshot pair, not a state reservation."""
    signer = computation_private_key
    current_root._private(signer)
    sequence, head, fence = records._predecessor_scope(expected_predecessor_sequence,
        expected_predecessor_head_digest, expected_fence)
    pair, before, authorization, grant, caller_raw, grant_raw, enrollment, total = _hold_originals(
        originals, before_vector_bytes, authorization_bytes, grant_bytes,
        authorization_enrollment_bytes, grant_enrollment_bytes,
        current_root_enrollment_bytes, receiving_custody)
    # Reserve all possible response originals before replay/signing. This
    # conservative cap also leaves room for the subsequently received ACK.
    if total + records.MAX_REQUEST_BYTES + records.MAX_SNAPSHOT_BYTES + records.MAX_RECEIPT_BYTES > grants.wire.MAX_ORIGINAL_BYTES:
        _fail("consume reserve exchange exceeds the source aggregate")
    full = grants._verify_full_on_work(grant_bytes=grant, authorization_bytes=authorization,
        authorization_enrollment_bytes=caller_raw, current_root_enrollment_bytes=enrollment,
        grant_enrollment_bytes=grant_raw, root_public_key=root_public_key,
        configuration_digest=configuration_digest, planner_public_key=planner_public_key,
        operation_public_key=operation_public_key, originals=pair, expectations=expectations,
        before_vector_bytes=before, receiving_custody=receiving_custody,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work,
        required_consumer_role="reserve")
    verified = full.verified
    verified.live()
    produced = computation._sign_replayed_on_work(replayed=full.replayed, verified=verified,
        enrollment_bytes=enrollment, root_public_key=root_public_key,
        computation_private_key=signer, predecessor_sequence=sequence,
        predecessor_head_digest=head, fence=fence, work=work)
    material, request, _digest = current_root._verify_request_on_work(
        request_bytes=produced.request_bytes, enrollment_bytes=enrollment,
        root_public_key=root_public_key, now_epoch_ns=verified.live()[0], work=work)
    _window, _bound, live = _reserve_guard(verified, material, request, work)
    live()
    return produced


def _verify_full_on_work(*, originals, expectations, before_vector_bytes, authorization_bytes,
        grant_bytes, response_originals, authorization_enrollment_bytes, grant_enrollment_bytes,
        current_root_enrollment_bytes, root_public_key, planner_public_key,
        operation_public_key, configuration_digest, expected_predecessor_sequence,
        expected_predecessor_head_digest, expected_fence, receiving_custody,
        live_window, transport_deadline_ns, work, required_consumer_role="reserve"):
    """Authenticate raw3 and replay once for reserve or independent SQL admission.

    An absent ACK is allowed only for retained-request verification; callers
    requiring pending admission must demand the original ACK independently.
    """
    if type(required_consumer_role) is not str or required_consumer_role not in ("reserve", "sql-issuer"):
        _fail("consume reservation receiver purpose is not source fixed")
    returned = _response_originals(response_originals, allow_pending=True)
    sequence, head, fence = records._predecessor_scope(expected_predecessor_sequence,
        expected_predecessor_head_digest, expected_fence)
    pair, before, authorization, grant, caller_raw, grant_raw, enrollment, total = _hold_originals(
        originals, before_vector_bytes, authorization_bytes, grant_bytes,
        authorization_enrollment_bytes, grant_enrollment_bytes,
        current_root_enrollment_bytes, receiving_custody)
    extras = tuple(raw for raw in returned if raw is not None)
    if total + sum(map(len, extras)) > grants.wire.MAX_ORIGINAL_BYTES:
        _fail("consume reserve response exceeds the source original aggregate")
    full = grants._verify_full_on_work(grant_bytes=grant, authorization_bytes=authorization,
        authorization_enrollment_bytes=caller_raw, current_root_enrollment_bytes=enrollment,
        grant_enrollment_bytes=grant_raw, root_public_key=root_public_key,
        configuration_digest=configuration_digest, planner_public_key=planner_public_key,
        operation_public_key=operation_public_key, originals=pair, expectations=expectations,
        before_vector_bytes=before, receiving_custody=receiving_custody,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work,
        required_consumer_role=required_consumer_role, extra_originals=extras)
    verified, replayed = full.verified, full.replayed
    material, request, request_digest = current_root._verify_request_on_work(
        request_bytes=returned[0], enrollment_bytes=enrollment,
        root_public_key=root_public_key, now_epoch_ns=verified.live()[0], work=work)
    for field, expected in (("action", "reserve"), ("operation", OPERATION),
            ("requestDigest", verified.payload["requestDigest"]),
            ("operationId", verified.payload["operationId"]),
            ("capabilityDigest", verified.grant_digest), ("predecessorSequence", sequence),
            ("predecessorHeadDigest", head), ("fence", fence)):
        plan._same(request[field], expected, work, "consume reserve independent original " + field)
    plan._same(material.enrollment_digest, verified.payload["currentRootEnrollmentDigest"], work,
        "consume reserve and grant current-root enrollment")
    if (request["issuedAtEpochNs"] != verified.payload["issuedAtEpochNs"]
            or request["issuedAtEpochNs"] != replayed.original_interval[0]
            or request["expiresAtEpochNs"] > min(verified.valid_until_epoch_ns,
                verified.payload["expiresAtEpochNs"], replayed.original_interval[1])):
        _fail("consume reserve renews or retimes original authority")
    window, bound, live = _reserve_guard(verified, material, request, work)
    actual_before = current_root.vector._encode_on_work(request["beforeVector"], work=work)
    actual_after = current_root.vector._encode_on_work(request["afterVector"], work=work)
    _same_bytes(actual_before, before, work, "consume reserve differs from independent before vector")
    _same_bytes(actual_before, replayed.before_vector_bytes, work, "consume reserve before differs from replay")
    _same_bytes(actual_after, replayed.after_vector_bytes, work, "consume reserve after differs from replay")
    snapshot = computation._snapshot(replayed, material, verified.grant_digest, work)
    expected_snapshot = computation._snapshot_wire(snapshot, work)
    _same_bytes(returned[1], expected_snapshot, work, "consume snapshot differs from actual replay")
    live()
    _request, retained_digest, receipt, receipt_digest = records._verify_on_work(
        request_bytes=returned[0], snapshot_bytes=returned[1], receipt_bytes=returned[2],
        enrollment_bytes=enrollment, root_public_key=root_public_key,
        expected_predecessor_sequence=sequence, expected_predecessor_head_digest=head,
        expected_fence=fence, work=work)
    plan._same(retained_digest, request_digest, work, "consume ACK differs from original live reserve")
    if returned[2] is not None and receipt is None:
        _fail("consume response has no genuine original state ACK")
    live()
    result = _VerifiedReservation(returned, material, request, request_digest, receipt, receipt_digest,
        snapshot, replayed, window, bound, live)
    live()
    return result


def _verify_retained_on_work(*, originals, expectations, before_vector_bytes, authorization_bytes,
        grant_bytes, response_originals, authorization_enrollment_bytes, grant_enrollment_bytes,
        current_root_enrollment_bytes, root_public_key, planner_public_key,
        operation_public_key, configuration_digest, expected_predecessor_sequence,
        expected_predecessor_head_digest, expected_fence, receiving_custody,
        live_window, transport_deadline_ns, work):
    """Return unchanged raw3 after live replay; absent ACK is not currentness."""
    verified = _verify_full_on_work(originals=originals, expectations=expectations,
        before_vector_bytes=before_vector_bytes, authorization_bytes=authorization_bytes,
        grant_bytes=grant_bytes, response_originals=response_originals,
        authorization_enrollment_bytes=authorization_enrollment_bytes,
        grant_enrollment_bytes=grant_enrollment_bytes, current_root_enrollment_bytes=current_root_enrollment_bytes,
        root_public_key=root_public_key, planner_public_key=planner_public_key,
        operation_public_key=operation_public_key, configuration_digest=configuration_digest,
        expected_predecessor_sequence=expected_predecessor_sequence,
        expected_predecessor_head_digest=expected_predecessor_head_digest, expected_fence=expected_fence,
        receiving_custody=receiving_custody, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work, required_consumer_role="reserve")
    verified.live()
    return verified.originals


def _verify_response_on_work(*, originals, expectations, before_vector_bytes, authorization_bytes,
        grant_bytes, response_originals, authorization_enrollment_bytes, grant_enrollment_bytes,
        current_root_enrollment_bytes, root_public_key, planner_public_key,
        operation_public_key, configuration_digest, expected_predecessor_sequence,
        expected_predecessor_head_digest, expected_fence, receiving_custody,
        live_window, transport_deadline_ns, work):
    """Return the actual authenticated ACK originals, not a current pending pin."""
    returned = _response_originals(response_originals)
    return _verify_retained_on_work(originals=originals, expectations=expectations,
        before_vector_bytes=before_vector_bytes, authorization_bytes=authorization_bytes,
        grant_bytes=grant_bytes, response_originals=returned,
        authorization_enrollment_bytes=authorization_enrollment_bytes,
        grant_enrollment_bytes=grant_enrollment_bytes, current_root_enrollment_bytes=current_root_enrollment_bytes,
        root_public_key=root_public_key, planner_public_key=planner_public_key,
        operation_public_key=operation_public_key, configuration_digest=configuration_digest,
        expected_predecessor_sequence=expected_predecessor_sequence,
        expected_predecessor_head_digest=expected_predecessor_head_digest, expected_fence=expected_fence,
        receiving_custody=receiving_custody, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work)
