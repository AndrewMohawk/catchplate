"""Authenticate returned reservation originals for one fixed registration grant.

The caller supplies the original raw10 authorization/planning/grant exchange,
independently admitted configuration/enrollments and predecessor/head/fence.
The response is only reserve-request, computation-snapshot and state-ack bytes.
Neither transport framing nor a signed historical receipt makes them current.

Actual planning and caller-purpose verification precede one genuine full grant
and plan/vector replay. Live computation-request admission and exact snapshot
reconstruction then join the original state acknowledgment to the independent
predecessor. Historical record verification supplements, never replaces, that
live gate. All work and clock checks retain the caller's original bounds.

Only the unchanged raw3 is returned: no candidate, successful-verification
carrier, execution packet, latest-state claim, SQL permission or completion.
This module performs no signing, transport, storage, retry or clock injection.
Historical retrieval is a separate operation and cannot use this live path.
"""
from __future__ import annotations

import time

from serverware import authority_current_root_authorization as current_root
from serverware import authority_current_root_computation as computation
from serverware import authority_registration_execution_exchange as exchange
from serverware import authority_registration_reservation_records as records
from serverware import authority_registration_reservation_transport as transport


authorization, grants, evidence, clock = (
    exchange.authorization, exchange.grants, exchange.evidence, exchange.clock)


class RegistrationReservationResponseError(ValueError):
    pass


def _same_original(actual, expected, work, label):
    work.charge(input_bytes=len(actual) + len(expected))
    if actual != expected:
        raise RegistrationReservationResponseError(label)


def _verify_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, originals, response_originals,
        authorization_enrollment_bytes, grant_enrollment_bytes, current_root_enrollment_bytes,
        root_public_key, expected_predecessor_sequence, expected_predecessor_head_digest,
        expected_fence, deadline_epoch_ns, transport_deadline_ns, work):
    """Return original raw3 only after actual live, original-bound verification.

    ``originals`` is authorization + planning request3 + planning response4 +
    complete before-vector + grant. ``response_originals`` is reserve request,
    snapshot, state acknowledgment. No expected scope is copied from them.
    The supplied monotonic deadline is mandatory and never renewed.
    """
    evidence.capture._SharedLedger(work)
    held = transport._originals(originals, response=False)
    returned = transport._originals(response_originals, response=True)
    caller_enrollment = current_root._original(authorization_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "registration caller enrollment")
    grant_enrollment = current_root._original(grant_enrollment_bytes,
        grants.MAX_ENROLLMENT_BYTES, "registration grant enrollment")
    current_enrollment = current_root._original(current_root_enrollment_bytes,
        current_root.MAX_ENROLLMENT_BYTES, "registration current-root enrollment")
    if sum(len(raw) for raw in (*held, *returned, caller_enrollment,
            grant_enrollment, current_enrollment)) > exchange.MAX_ORIGINAL_BYTES:
        raise RegistrationReservationResponseError("reservation response originals exceed the complete source bound")
    sequence, predecessor, fence = records._predecessor_scope(expected_predecessor_sequence,
        expected_predecessor_head_digest, expected_fence)
    shape = current_root.shape
    shape._integer(deadline_epoch_ns, minimum=1)
    shape._integer(transport_deadline_ns, minimum=1)
    inherited = transport_deadline_ns
    # Every returned byte and independent scalar is held before the shared
    # gate captures caller graphs and begins actual key/clock callbacks.
    admitted = exchange._admit_on_configuration(payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, request_originals=held[1:4],
        response_originals=held[4:8], before_vector_bytes=held[8], authorization_bytes=held[0],
        authorization_enrollment_bytes=caller_enrollment, grant_enrollment_bytes=grant_enrollment,
        current_root_enrollment_bytes=current_enrollment, root_public_key=root_public_key,
        deadline_epoch_ns=deadline_epoch_ns, transport_deadline_ns=inherited, work=work,
        _returned_grant_bytes=held[9])
    admitted.live()
    authorized = authorization._verify_on_work(authorization_bytes=admitted.authorization,
        authorization_enrollment_bytes=admitted.authorization_enrollment,
        current_root_enrollment_bytes=admitted.current_enrollment,
        grant_enrollment_bytes=admitted.grant_enrollment, root_public_key=admitted.root,
        configuration_digest=admitted.configuration_digest,
        planner_public_key=admitted.configured.pins[1], evidence_public_key=admitted.configured.pins[4],
        deadline_epoch_ns=admitted.deadline_epoch_ns, work=work,
        transport_deadline_ns=admitted.deadline_ns)
    deadline = min(admitted.deadline_epoch_ns, authorized.expires_at_epoch_ns, authorized.window[3])
    bound = min(inherited, admitted.deadline_ns, authorized.deadline_ns)
    last_epoch, last_monotonic = authorized.last_epoch_ns, authorized.last_monotonic_ns
    reserve_payload, reserve_material = None, None

    def live():
        nonlocal last_epoch, last_monotonic
        exchange_now = admitted.live()
        now = clock._check_on_work(authorized.window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if (now < exchange_now or now < last_epoch or monotonic < last_monotonic
                or monotonic >= bound or now >= deadline):
            raise RegistrationReservationResponseError("reservation response expired or its original clocks reversed")
        if reserve_payload is not None:
            current_root._fresh(reserve_payload, reserve_material, now)
        last_epoch, last_monotonic = now, monotonic
        return now

    verified = grants._verify_on_work(grant_bytes=held[9],
        grant_enrollment_bytes=admitted.grant_enrollment,
        current_root_enrollment_bytes=admitted.current_enrollment, root_public_key=admitted.root,
        operation=authorization.OPERATION, originals=admitted.originals, expectations=admitted.history,
        planner_public_key=admitted.configured.pins[1], operation_public_key=admitted.configured.pins[4],
        before_vector_bytes=admitted.before, expected_authorization_digest=authorized.authorization_digest,
        now_epoch_ns=live(), work=work)
    for name, expected in (("operation", authorization.OPERATION),
            ("requestDigest", authorized.request_digest), ("operationId", authorized.operation_id)):
        evidence.plan._same(verified.replayed.request[name], expected, work,
            "reservation grant differs from the original authorized request")
    grant_issued, grant_expires = verified.payload["issuedAtEpochNs"], verified.payload["expiresAtEpochNs"]
    if grant_issued < authorized.issued_at_epoch_ns or grant_expires > deadline:
        raise RegistrationReservationResponseError("reservation grant escapes its original authorization interval")
    deadline = min(deadline, grant_expires)
    bound = min(bound, authorized.window[1] + deadline - authorized.window[0])
    live()

    material, request, request_digest = current_root._verify_request_on_work(
        request_bytes=returned[0], enrollment_bytes=admitted.current_enrollment,
        root_public_key=admitted.root, now_epoch_ns=live(), work=work)
    if request["action"] != "reserve" or request["operation"] != authorization.OPERATION:
        raise RegistrationReservationResponseError("reservation response is not the fixed registration reserve")
    for name, expected in (("operation", authorization.OPERATION),
            ("requestDigest", authorized.request_digest), ("operationId", authorized.operation_id),
            ("capabilityDigest", verified.grant_digest), ("predecessorSequence", sequence),
            ("predecessorHeadDigest", predecessor), ("fence", fence)):
        evidence.plan._same(request[name], expected, work,
            "reservation request differs from original independent scope")
    evidence.plan._same(material.payload["generationDigest"], admitted.configured.generation_digest,
        work, "reservation enrollment differs from the configured planning generation")
    evidence.plan._same(material.enrollment_digest, verified.payload["currentRootEnrollmentDigest"],
        work, "reservation computation and original grant enrollment differ")
    if (request["issuedAtEpochNs"] != grant_issued
            or request["issuedAtEpochNs"] != verified.replayed.original_interval[0]
            or request["expiresAtEpochNs"] > min(deadline, verified.replayed.original_interval[1])):
        raise RegistrationReservationResponseError("reservation renewed or retimed its original authority interval")
    reserve_material, reserve_payload = material, request
    deadline = min(deadline, request["expiresAtEpochNs"])
    bound = min(bound, authorized.window[1] + deadline - authorized.window[0])
    live()

    before_bytes = current_root.vector._encode_on_work(request["beforeVector"], work=work)
    after_bytes = current_root.vector._encode_on_work(request["afterVector"], work=work)
    _same_original(before_bytes, admitted.before, work,
        "reservation before-vector differs from the original raw10 request")
    _same_original(before_bytes, verified.replayed.before_vector_bytes, work,
        "reservation before-vector differs from genuine grant replay")
    _same_original(after_bytes, verified.replayed.after_vector_bytes, work,
        "reservation after-vector differs from genuine grant replay")
    snapshot = computation._snapshot(verified.replayed, material, verified.grant_digest, work)
    snapshot_bytes = computation._snapshot_wire(snapshot, work)
    _same_original(returned[1], snapshot_bytes, work,
        "reservation snapshot differs from actual original grant and plan replay")
    live()
    # This existing original verifier authenticates the state ack, its exact
    # request/pending digest, predecessor+1, head, fence, scope and vector
    # digests. Its historical verification is ADDITIONAL to the live signed
    # request gate above, and never produces independently latest-state input.
    _request, retained_request_digest, receipt, _receipt_digest = records._verify_on_work(
        request_bytes=returned[0], snapshot_bytes=returned[1], receipt_bytes=returned[2],
        enrollment_bytes=admitted.current_enrollment, root_public_key=admitted.root,
        expected_predecessor_sequence=sequence, expected_predecessor_head_digest=predecessor,
        expected_fence=fence, work=work)
    evidence.plan._same(retained_request_digest, request_digest, work,
        "reservation state acknowledgment differs from the live original request")
    if receipt is None:
        raise RegistrationReservationResponseError("reservation response has no original state acknowledgment")
    live()
    return returned
