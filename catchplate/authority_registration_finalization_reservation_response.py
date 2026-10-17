"""Live admission of returned finalization reserve/snapshot/ack originals.

Raw10 retains the dedicated authorization, custody raw7, complete before-vector
and original grant. Independent configuration/root/enrollments and predecessor
scope precede one genuine complete finalization grant/plan replay. The live
computation signature, exact reconstructed snapshot and original state receipt
must all join that same replay. No received head becomes an expected head.

Only unchanged raw3 returns. Historical receipt verification supplements the
live request gate; it cannot revive stale authority or establish latest state.
No signing key, callback, successful result input, new window/work, transport,
storage, retry, SQL permission or completed credential/session is provided.
"""
from __future__ import annotations

import time

from catchplate import authority_current_root_authorization as current_root
from catchplate import authority_current_root_computation as computation
from catchplate import authority_registration_finalization_execution_admission as admission
from catchplate import authority_registration_finalization_reservation_records as records
from catchplate import authority_registration_finalization_reservation_transport as transport


evidence, clock, grants = admission.evidence, admission.clock, admission.grants
OPERATION = admission.OPERATION


class RegistrationFinalizationReservationResponseError(ValueError):
    pass


def _same_original(actual, expected, work, label):
    work.charge(input_bytes=len(actual) + len(expected))
    if actual != expected:
        raise RegistrationFinalizationReservationResponseError(label)


def _verify_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, originals, response_originals,
        authorization_enrollment_bytes, grant_enrollment_bytes, current_root_enrollment_bytes,
        root_public_key, expected_predecessor_sequence, expected_predecessor_head_digest,
        expected_fence, live_window, transport_deadline_ns, work):
    """Return exact raw3 after genuine live original joins, never latest-head admission."""
    evidence.capture._SharedLedger(work)
    held = transport._originals(originals, response=False)
    returned = transport._originals(response_originals, response=True)
    caller_enrollment = current_root._original(authorization_enrollment_bytes,
        admission.caller.MAX_ENROLLMENT_BYTES, "finalization caller enrollment")
    grant_enrollment = current_root._original(grant_enrollment_bytes,
        grants.MAX_ENROLLMENT_BYTES, "finalization grant enrollment")
    current_enrollment = current_root._original(current_root_enrollment_bytes,
        current_root.MAX_ENROLLMENT_BYTES, "finalization current-root enrollment")
    if sum(len(raw) for raw in (*held, *returned, caller_enrollment,
            grant_enrollment, current_enrollment)) > grants.replay.MAX_ORIGINAL_BYTES:
        raise RegistrationFinalizationReservationResponseError(
            "finalization reservation originals exceed their complete aggregate bound")
    sequence, predecessor, fence = records._predecessor_scope(expected_predecessor_sequence,
        expected_predecessor_head_digest, expected_fence)
    shape = current_root.shape
    shape._integer(transport_deadline_ns, minimum=1)
    inherited = transport_deadline_ns
    window = clock._validate(live_window)
    # Hold every original and independent immutable scope before the real
    # admission captures mutable configuration and invokes key/clock work.
    admitted = admission._admit_on_configuration(payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, originals=held[1:8],
        before_vector_bytes=held[8], authorization_bytes=held[0], grant_bytes=held[9],
        authorization_enrollment_bytes=caller_enrollment, grant_enrollment_bytes=grant_enrollment,
        current_root_enrollment_bytes=current_enrollment, root_public_key=root_public_key,
        live_window=window, work=work, transport_deadline_ns=inherited)
    verified, authorized = admitted.verified_grant, admitted.authorized
    window = admitted.window
    deadline = admitted.deadline_epoch_ns
    bound = min(inherited, admitted.deadline_ns)
    last_epoch, last_monotonic = window[0], window[2]
    reserve_payload, reserve_material = None, None

    def live():
        nonlocal last_epoch, last_monotonic
        now = admitted.live()
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if (now < last_epoch or monotonic < last_monotonic
                or now >= deadline or monotonic >= bound):
            raise RegistrationFinalizationReservationResponseError(
                "finalization reservation response expired or its clocks reversed")
        if reserve_payload is not None:
            current_root._fresh(reserve_payload, reserve_material, now)
        last_epoch, last_monotonic = now, monotonic
        return now

    # These are facts from the actual full replay above, not a second input
    # carrier or a plan interpreted at a manufactured historical instant.
    for name, expected in (("operation", OPERATION), ("requestDigest", authorized.request_digest),
            ("operationId", authorized.operation_id)):
        evidence.plan._same(verified.replayed.request[name], expected, work,
            "finalization reservation replay differs from its authorized request")
    grant_issued, grant_expires = verified.payload["issuedAtEpochNs"], verified.payload["expiresAtEpochNs"]
    live()
    material, request, request_digest = current_root._verify_request_on_work(
        request_bytes=returned[0], enrollment_bytes=admitted.current_enrollment,
        root_public_key=admitted.root, now_epoch_ns=live(), work=work)
    if request["action"] != "reserve" or request["operation"] != OPERATION:
        raise RegistrationFinalizationReservationResponseError(
            "finalization response is not its fixed reserve operation")
    for name, expected in (("operation", OPERATION), ("requestDigest", authorized.request_digest),
            ("operationId", authorized.operation_id), ("capabilityDigest", verified.grant_digest),
            ("predecessorSequence", sequence), ("predecessorHeadDigest", predecessor), ("fence", fence)):
        evidence.plan._same(request[name], expected, work,
            "finalization reservation differs from independently admitted original scope")
    evidence.plan._same(material.payload["generationDigest"], admitted.configured.generation_digest,
        work, "finalization computation differs from configured planning generation")
    evidence.plan._same(material.enrollment_digest, verified.payload["currentRootEnrollmentDigest"],
        work, "finalization computation and original grant enrollments differ")
    if (request["issuedAtEpochNs"] != grant_issued
            or request["issuedAtEpochNs"] != verified.replayed.original_interval[0]
            or request["expiresAtEpochNs"] > min(deadline, grant_expires, verified.replayed.original_interval[1])):
        raise RegistrationFinalizationReservationResponseError(
            "finalization reservation renewed or retimed its original authority")
    reserve_material, reserve_payload = material, request
    deadline = min(deadline, request["expiresAtEpochNs"])
    bound = min(bound, window[1] + deadline - window[0])
    live()

    before_bytes = current_root.vector._encode_on_work(request["beforeVector"], work=work)
    after_bytes = current_root.vector._encode_on_work(request["afterVector"], work=work)
    _same_original(before_bytes, admitted.before, work,
        "finalization reservation before-vector differs from original raw10")
    _same_original(before_bytes, verified.replayed.before_vector_bytes, work,
        "finalization reservation before-vector differs from actual grant replay")
    _same_original(after_bytes, verified.replayed.after_vector_bytes, work,
        "finalization reservation after-vector differs from actual grant replay")
    snapshot = computation._snapshot(verified.replayed, material, verified.grant_digest, work)
    expected_snapshot = computation._snapshot_wire(snapshot, work)
    _same_original(returned[1], expected_snapshot, work,
        "finalization reservation snapshot differs from actual original replay")
    live()
    # Historical admission authenticates the exact ack/request/pending digest,
    # predecessor+1, head, fence, scope and vectors. It is ADDITIONAL to the live
    # signature/interval gate and supplies no independently current head.
    _request, retained_digest, receipt, _receipt_digest = records._verify_on_work(
        request_bytes=returned[0], snapshot_bytes=returned[1], receipt_bytes=returned[2],
        enrollment_bytes=admitted.current_enrollment, root_public_key=admitted.root,
        expected_predecessor_sequence=sequence, expected_predecessor_head_digest=predecessor,
        expected_fence=fence, work=work)
    evidence.plan._same(retained_digest, request_digest, work,
        "finalization state acknowledgment differs from the live original request")
    if receipt is None:
        raise RegistrationFinalizationReservationResponseError(
            "finalization reservation has no original state acknowledgment")
    live()
    return returned
