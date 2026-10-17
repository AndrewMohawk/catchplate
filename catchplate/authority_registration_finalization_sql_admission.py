"""Original-only finalization admission before the actual protected SQL owner.

The caller independently admits configuration, root/enrollments and the CURRENT
pending sequence/head/fence. This bridge authenticates dedicated finalization
raw10 and reserve raw3, reconstructs the exact snapshot and full vectors from
the same genuine plan replay, and joins the original state receipt to those
independent pending pins. A receipt never supplies expected current authority.

Only private same-call original issuer arguments and their unchanged live
guard return. The real SuccessorExecutionIssuer must still admit its original
inputs before protected packet custody. No public entrypoint accepts this
record as proof. There is no SQL, signing, transport, attempt claim, completion,
new work/window, historical expiry exception or credential/session success.
"""
from __future__ import annotations

from dataclasses import dataclass
import time

from catchplate import authority_current_root_authorization as current_root
from catchplate import authority_current_root_computation as computation
from catchplate import authority_current_root_execution_admission as pending
from catchplate import authority_registration_finalization_execution_admission as admission
from catchplate import authority_registration_finalization_reservation_transport as transport


authorization, grants, evidence, clock = admission.caller, admission.grants, admission.evidence, admission.clock
OPERATION = admission.OPERATION


class RegistrationFinalizationSqlAdmissionError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _AdmittedSqlInputs:
    """This call's derived inputs only; never an accepted authority carrier."""

    issue_arguments: dict
    live_window: tuple
    deadline_ns: int
    live: object
    marker_expectation: dict


def _same_original(actual, expected, work, label):
    work.charge(input_bytes=len(actual) + len(expected))
    if actual != expected:
        raise RegistrationFinalizationSqlAdmissionError(label)


def _admit_on_configuration(*, payload, configuration_digest, generation,
        runtime_role_identities, originals, reservation_originals,
        authorization_enrollment_bytes, grant_enrollment_bytes, current_root_enrollment_bytes,
        root_public_key, expected_pending_sequence, expected_pending_head_digest,
        expected_fence, live_window, transport_deadline_ns, work):
    """Join original raw10/raw3 to independently held current pending scope.

    Raw10 is finalization authorization, custody raw7, complete before-vector
    and grant. Raw3 is reserve request, snapshot and state acknowledgment. All
    immutable originals and expected scalars are held before native callbacks;
    actual admission owns the supplied configuration graphs before key work.
    """
    evidence.capture._SharedLedger(work)
    held = transport._originals(originals, response=False)
    reserved = transport._originals(reservation_originals, response=True)
    caller_enrollment = current_root._original(authorization_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "finalization SQL caller enrollment")
    grant_enrollment = current_root._original(grant_enrollment_bytes,
        grants.MAX_ENROLLMENT_BYTES, "finalization SQL grant enrollment")
    current_enrollment = current_root._original(current_root_enrollment_bytes,
        current_root.MAX_ENROLLMENT_BYTES, "finalization SQL current-root enrollment")
    if sum(len(raw) for raw in (*held, *reserved, caller_enrollment,
            grant_enrollment, current_enrollment)) > grants.replay.MAX_ORIGINAL_BYTES:
        raise RegistrationFinalizationSqlAdmissionError("finalization SQL originals exceed their complete source bound")
    shape = current_root.shape
    shape._integer(expected_pending_sequence, current_root.MAX_RECORDS, minimum=1)
    shape._digest(expected_pending_head_digest)
    shape._integer(expected_fence, minimum=1)
    shape._integer(transport_deadline_ns, minimum=1)
    sequence, head, fence = expected_pending_sequence, expected_pending_head_digest, expected_fence
    root, inherited = root_public_key, transport_deadline_ns
    window = clock._validate(live_window)
    admitted = admission._admit_on_configuration(payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        runtime_role_identities=runtime_role_identities, originals=held[1:8],
        authorization_bytes=held[0], before_vector_bytes=held[8], grant_bytes=held[9],
        authorization_enrollment_bytes=caller_enrollment, grant_enrollment_bytes=grant_enrollment,
        current_root_enrollment_bytes=current_enrollment, root_public_key=root,
        live_window=window, transport_deadline_ns=inherited, work=work)
    verified, authorized = admitted.verified_grant, admitted.authorized
    replayed = verified.replayed
    window, deadline = admitted.window, admitted.deadline_epoch_ns
    bound = min(inherited, admitted.deadline_ns, window[4])
    last_epoch, last_monotonic = window[0], window[2]
    reserve_material, reserve_payload = None, None

    def live():
        nonlocal last_epoch, last_monotonic
        admitted_now = admitted.live()
        now = clock._check_on_work(window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if (now < admitted_now or now < last_epoch or monotonic < last_monotonic
                or now >= deadline or monotonic >= bound):
            raise RegistrationFinalizationSqlAdmissionError("finalization SQL admission expired or its clocks reversed")
        if reserve_payload is not None:
            current_root._fresh(reserve_payload, reserve_material, now)
        last_epoch, last_monotonic = now, monotonic
        return now

    live()
    material, request, request_digest = current_root._verify_request_on_work(
        request_bytes=reserved[0], enrollment_bytes=admitted.current_enrollment,
        root_public_key=admitted.root, now_epoch_ns=live(), work=work)
    if request["action"] != "reserve" or request["operation"] != OPERATION:
        raise RegistrationFinalizationSqlAdmissionError("finalization SQL requires its original fixed-operation reserve")
    for name, expected in (("operation", OPERATION), ("requestDigest", authorized.request_digest),
            ("operationId", authorized.operation_id), ("capabilityDigest", verified.grant_digest)):
        evidence.plan._same(request[name], expected, work,
            "finalization SQL reserve differs from genuine authorization or grant " + name)
    for name in ("operation", "requestDigest", "operationId"):
        evidence.plan._same(request[name], replayed.request[name], work,
            "finalization SQL reserve differs from its actual typed plan request")
    for actual, expected in ((material.enrollment_digest, verified.payload["currentRootEnrollmentDigest"]),
            (material.enrollment_digest, authorized.current_root_enrollment_digest),
            (material.payload["databaseId"], authorized.database_id),
            (material.payload["generationDigest"], admitted.configured.generation_digest)):
        evidence.plan._same(actual, expected, work,
            "finalization SQL differs from its actual enrollment and configuration")
    if (request["issuedAtEpochNs"] != verified.payload["issuedAtEpochNs"]
            or request["issuedAtEpochNs"] != replayed.original_interval[0]
            or request["expiresAtEpochNs"] > min(deadline, verified.payload["expiresAtEpochNs"],
                replayed.original_interval[1])):
        raise RegistrationFinalizationSqlAdmissionError("finalization SQL reserve retimes or renews original authority")
    reserve_material, reserve_payload = material, request
    deadline = min(deadline, request["expiresAtEpochNs"])
    window = clock._validate((window[0], window[1], window[2], deadline,
        min(window[4], window[1] + deadline - window[0]), window[5], window[6]))
    bound = min(bound, window[4])
    live()
    receipt = current_root._verify_receipt_on_work(receipt_bytes=reserved[2],
        enrollment_bytes=admitted.current_enrollment, root_public_key=admitted.root, work=work)
    receipt_digest = current_root._receipt_digest_on_work(reserved[2], work)
    # Reuse the actual pending consumer's complete scalar/ancestry/capacity
    # join. Only the independently supplied sequence/head/fence enter scope;
    # neither request nor acknowledgment fills or advances those expected pins.
    scope = pending._scope(expected_database_id=material.payload["databaseId"],
        expected_generation_digest=admitted.configured.generation_digest,
        expected_pending_sequence=sequence, expected_pending_head_digest=head,
        expected_fence=fence, live_window=window, transport_deadline_ns=bound)
    pending._pending(material, request, request_digest, receipt, receipt_digest, scope, work)
    live()
    before = current_root.vector._encode_on_work(request["beforeVector"], work=work)
    after = current_root.vector._encode_on_work(request["afterVector"], work=work)
    _same_original(before, admitted.before, work,
        "finalization SQL reserve before-vector differs from original raw10")
    _same_original(before, replayed.before_vector_bytes, work,
        "finalization SQL reserve before-vector differs from actual grant replay")
    _same_original(after, replayed.after_vector_bytes, work,
        "finalization SQL reserve after-vector differs from actual grant replay")
    for name, expected in (("beforeVectorDigest", replayed.before_vector_digest),
            ("afterVectorDigest", replayed.after_vector_digest)):
        evidence.plan._same(receipt[name], expected, work,
            "finalization SQL receipt differs from the actual complete vector " + name)
        evidence.plan._same(verified.payload[name], expected, work,
            "finalization SQL grant differs from the actual complete vector " + name)
    snapshot = computation._snapshot(replayed, material, verified.grant_digest, work)
    snapshot_bytes = computation._snapshot_wire(snapshot, work)
    _same_original(snapshot_bytes, reserved[1], work,
        "finalization SQL snapshot differs from its actual original plan replay")
    snapshot_digest = computation._snapshot_digest_on_work(reserved[1], work=work)
    evidence.plan._same(snapshot_digest, request["snapshotDigest"], work,
        "finalization SQL reserve does not commit its actual snapshot original")
    marker_expectation = pending._marker(material, request, request_digest,
        receipt, receipt_digest, snapshot, work)
    live()
    arguments = {"operation": OPERATION, "originals": admitted.raw4,
        "expectations": admitted.history, "planner_public_key": admitted.configured.pins[1],
        "operation_public_key": admitted.configured.pins[4],
        "enrollment_bytes": admitted.current_enrollment, "root_public_key": admitted.root,
        "reserve_request_bytes": reserved[0], "reserve_receipt_bytes": reserved[2],
        "snapshot_bytes": reserved[1], "grant_bytes": admitted.grant,
        "grant_enrollment_bytes": admitted.grant_enrollment,
        "expected_authorization_digest": authorized.authorization_digest,
        "expected_database_id": material.payload["databaseId"],
        "expected_generation_digest": admitted.configured.generation_digest,
        "expected_pending_sequence": sequence, "expected_pending_head_digest": head,
        "expected_fence": fence}
    live()
    return _AdmittedSqlInputs(arguments, window, bound, live, marker_expectation)
