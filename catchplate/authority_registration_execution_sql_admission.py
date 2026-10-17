"""Original-input registration admission before the actual protected SQL owner.

Cold callers independently supply configuration/root/enrollment provenance and
the CURRENT pending sequence/head/fence. A returned reserve acknowledgment,
snapshot or historical journal cannot enroll those expected current inputs.
This private bridge authenticates the original planning exchange, caller
permission and grant control, then joins their exact request/interval scope
and the complete canonical before-vector. It creates no SQL owner or work.

The genuine SuccessorExecutionIssuer must still perform the full original
plan/pending/grant replay once before packet custody. Returned same-call data
is never accepted as an incoming verification token. No database, transport,
signing, reservation, attempt claim, completion or clock fallback occurs here;
both original verification brackets continue without renewing their lifetime.
"""
from __future__ import annotations

from dataclasses import dataclass
import time

from catchplate import authority_registration_execution_exchange as exchange
from catchplate import authority_registration_reservation_transport as transport


authorization, grants, evidence, clock = (
    exchange.authorization, exchange.grants, exchange.evidence, exchange.clock)
current_root = grants.authorization


class RegistrationExecutionSqlAdmissionError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _AdmittedSqlInputs:
    """Private same-call inputs only; no public entrypoint accepts this type."""

    issue_arguments: dict
    live_window: tuple
    deadline_ns: int
    live: object


def _admit_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, originals, reservation_originals,
        authorization_enrollment_bytes, grant_enrollment_bytes, current_root_enrollment_bytes,
        root_public_key, expected_pending_sequence, expected_pending_head_digest,
        expected_fence, deadline_epoch_ns, transport_deadline_ns, work):
    """Prepare exact issuer arguments from originals, never a successful carrier.

    ``originals`` is authorization + planning request3 + response4 + complete
    before-vector + grant. ``reservation_originals`` is request/snapshot/ack.
    Their complete inventory and independent pending scalars are held before
    any native callback. Full pending and plan admission remains with issuer.
    """
    evidence.capture._SharedLedger(work)
    held = transport._originals(originals, response=False)
    reserved = transport._originals(reservation_originals, response=True)
    caller_enrollment = current_root._original(authorization_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "registration SQL caller enrollment")
    grant_enrollment = current_root._original(grant_enrollment_bytes,
        grants.MAX_ENROLLMENT_BYTES, "registration SQL grant enrollment")
    current_enrollment = current_root._original(current_root_enrollment_bytes,
        current_root.MAX_ENROLLMENT_BYTES, "registration SQL current-root enrollment")
    if sum(len(raw) for raw in (*held, *reserved, caller_enrollment,
            grant_enrollment, current_enrollment)) > exchange.MAX_ORIGINAL_BYTES:
        raise RegistrationExecutionSqlAdmissionError("registration SQL originals exceed the complete source bound")
    shape = current_root.shape
    shape._integer(expected_pending_sequence, current_root.MAX_RECORDS, minimum=1)
    shape._digest(expected_pending_head_digest)
    shape._integer(expected_fence, minimum=1)
    shape._integer(deadline_epoch_ns, minimum=1)
    shape._integer(transport_deadline_ns, minimum=1)
    sequence, head, fence = expected_pending_sequence, expected_pending_head_digest, expected_fence
    deadline, inherited, root = deadline_epoch_ns, transport_deadline_ns, root_public_key
    # This genuine shared gate detaches all configuration graphs before key
    # callbacks and authenticates request/response controls and history inputs.
    admitted = exchange._admit_on_configuration(payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, request_originals=held[1:4],
        response_originals=held[4:8], before_vector_bytes=held[8], authorization_bytes=held[0],
        authorization_enrollment_bytes=caller_enrollment, grant_enrollment_bytes=grant_enrollment,
        current_root_enrollment_bytes=current_enrollment, root_public_key=root,
        deadline_epoch_ns=deadline, transport_deadline_ns=inherited, work=work,
        _returned_grant_bytes=held[9])
    admitted.live()
    authorized = authorization._verify_on_work(authorization_bytes=admitted.authorization,
        authorization_enrollment_bytes=admitted.authorization_enrollment,
        current_root_enrollment_bytes=admitted.current_enrollment,
        grant_enrollment_bytes=admitted.grant_enrollment, root_public_key=admitted.root,
        configuration_digest=admitted.configuration_digest,
        planner_public_key=admitted.configured.pins[1], evidence_public_key=admitted.configured.pins[4],
        deadline_epoch_ns=admitted.deadline_epoch_ns, transport_deadline_ns=admitted.deadline_ns, work=work)
    authorization_expiry = min(admitted.deadline_epoch_ns, authorized.expires_at_epoch_ns)
    deadline = min(authorization_expiry, authorized.window[3])
    bound = min(inherited, admitted.deadline_ns, authorized.deadline_ns)
    last_epoch, last_monotonic = authorized.last_epoch_ns, authorized.last_monotonic_ns

    def live():
        nonlocal last_epoch, last_monotonic
        exchange_now = admitted.live()
        now = clock._check_on_work(authorized.window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if (now < exchange_now or now < last_epoch or monotonic < last_monotonic
                or monotonic >= bound or now >= deadline):
            raise RegistrationExecutionSqlAdmissionError("registration SQL admission expired or its clocks reversed")
        last_epoch, last_monotonic = now, monotonic
        return now

    live()
    current = current_root._admit_enrollment_on_work(enrollment_bytes=admitted.current_enrollment,
        root_public_key=admitted.root, work=work)
    evidence.plan._same(current.payload["generationDigest"], admitted.configured.generation_digest,
        work, "registration SQL enrollment differs from the actual configured generation")
    if sequence > current.payload["maxRecords"]:
        raise RegistrationExecutionSqlAdmissionError("independent pending sequence exceeds enrolled capacity")
    control, _grant_digest = grants._verify_control_on_work(grant_bytes=held[9],
        grant_enrollment_bytes=admitted.grant_enrollment,
        current_root_enrollment_bytes=admitted.current_enrollment, root_public_key=admitted.root,
        planner_public_key=admitted.configured.pins[1], operation_public_key=admitted.configured.pins[4],
        expected_authorization_digest=authorized.authorization_digest,
        now_epoch_ns=live(), work=work)
    for name, expected in (("operation", authorization.OPERATION),
            ("requestDigest", authorized.request_digest), ("operationId", authorized.operation_id),
            ("currentRootEnrollmentDigest", current.enrollment_digest),
            ("databaseId", current.payload["databaseId"]),
            ("generationDigest", admitted.configured.generation_digest)):
        evidence.plan._same(control[name], expected, work,
            "registration SQL grant differs from original authorization or enrolled scope")
    issued, expires = control["issuedAtEpochNs"], control["expiresAtEpochNs"]
    if issued < authorized.issued_at_epoch_ns or expires > authorization_expiry:
        raise RegistrationExecutionSqlAdmissionError("registration SQL grant escapes its original authorization interval")
    # The genuine control shape also binds issue/expiry to the original plan
    # interval. Retain the authorization's actual opening bracket, only clip.
    deadline = min(deadline, expires)
    window = clock._validate((authorized.window[0], authorized.window[1], authorized.window[2],
        deadline, authorized.window[1] + deadline - authorized.window[0],
        authorized.window[5], authorized.window[6]))
    bound = min(bound, window[4])
    live()
    # The issuer receives no separate raw10 before-vector argument. Therefore
    # bind these exact canonical source-validated bytes to the signed grant now;
    # actual issuer replay subsequently joins that grant to the pending vectors.
    before_digest = current_root.vector._digest_on_work(admitted.before, work=work)
    evidence.plan._same(before_digest, control["beforeVectorDigest"], work,
        "registration SQL before-vector differs from its original signed grant")
    live()
    arguments = {
        "operation": authorization.OPERATION,
        "originals": admitted.originals,
        "expectations": admitted.history,
        "planner_public_key": admitted.configured.pins[1],
        "operation_public_key": admitted.configured.pins[4],
        "enrollment_bytes": admitted.current_enrollment,
        "root_public_key": admitted.root,
        "reserve_request_bytes": reserved[0],
        "reserve_receipt_bytes": reserved[2],
        "snapshot_bytes": reserved[1],
        "grant_bytes": held[9],
        "grant_enrollment_bytes": admitted.grant_enrollment,
        "expected_authorization_digest": authorized.authorization_digest,
        "expected_database_id": current.payload["databaseId"],
        "expected_generation_digest": admitted.configured.generation_digest,
        "expected_pending_sequence": sequence,
        "expected_pending_head_digest": head,
        "expected_fence": fence,
    }
    live()
    return _AdmittedSqlInputs(arguments, window, bound, live)
