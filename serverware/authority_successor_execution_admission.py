"""Original grant plus genuine pending/plan admission for six successors.

The pre-decision grant's original signed identity is the capability digest in
the later reserve. The grant cannot depend on that pending decision or on the
computation snapshot containing its own identity. Distinct authorizer and
computation measurement identities are deliberately not equated.

This composition genuinely replays the original plan once, authenticates the
original pending controls, then verifies the purpose-enrolled original grant
and joins every claim to the same-call computation. No successful candidate,
grant verification carrier or caller-derived mutation is accepted as input.

The owning service must independently admit request authorization, historical
policy/key provenance, current pending state and the original live window.
This source component provides no cold owner, SQL function permission, durable
capability custody, one-use execution, postcommit receipt or retry authority.
"""
from __future__ import annotations

import time

from serverware import authority_current_root_authorization as authorization
from serverware import authority_current_root_computation as computation
from serverware import authority_current_root_execution_admission as pending
from serverware import authority_successor_execution_grant as grants
from serverware import authority_webauthn_evidence as evidence
from serverware import authority_webauthn_evidence_plan_clock as clock


_SNAPSHOT_JOINS = (
    "sourceRevision", "databaseId", "generationDigest", "operation", "requestDigest",
    "operationId", "retainedRecordDigest", "planDigest", "beforeVectorDigest",
    "afterVectorDigest", "resultDigest", "originalFrames", "originalIssuedAtEpochNs",
    "originalExpiresAtEpochNs", "signedSnapshotDigest", "signedCapabilityId",
)


class SuccessorExecutionAdmissionError(ValueError):
    pass


def _admit_on_work(*, operation, originals, expectations, planner_public_key,
        operation_public_key, enrollment_bytes, root_public_key,
        reserve_request_bytes, reserve_receipt_bytes, snapshot_bytes,
        grant_bytes, grant_enrollment_bytes, expected_authorization_digest,
        expected_database_id, expected_generation_digest, expected_pending_sequence,
        expected_pending_head_digest, expected_fence, live_window, work,
        transport_deadline_ns=None, activation_custody=None, native_review_owner=None,
        native_review_frames=None, session_token_original=None):
    """Derive an execution candidate from all genuine originals on one work.

    Request authorization and the exact pending head/fence are independent
    expected inputs, never adopted from a returned grant, snapshot or receipt.
    All plan proof/semantic work occurs in the actual pending admission once.
    Later scalar/digest joins do not rerun that heavy proof computation.
    """
    evidence.capture._SharedLedger(work)
    held_custody = activation_custody
    if type(operation) is str and operation == pending.replay.ACTIVATION_OPERATION:
        authorization.shape._integer(transport_deadline_ns, minimum=1)
    held_grant = authorization._original(grant_bytes, grants.MAX_GRANT_BYTES,
        "successor execution grant")
    held_grant_enrollment = authorization._original(grant_enrollment_bytes,
        grants.MAX_ENROLLMENT_BYTES, "successor execution grant enrollment")
    held_enrollment = authorization._original(enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "current-root enrollment")
    held_pending = pending._originals(operation, originals, held_enrollment,
        reserve_request_bytes, reserve_receipt_bytes, snapshot_bytes)
    if sum(len(raw) for raw in (*held_pending[0], *held_pending[1:],
            held_grant, held_grant_enrollment)) > pending.replay.MAX_ORIGINAL_BYTES:
        raise SuccessorExecutionAdmissionError("successor execution originals exceed the aggregate byte bound")
    shape = authorization.shape
    shape._digest(expected_authorization_digest)
    held_authorization = expected_authorization_digest
    held_root, held_planner, held_operation = root_public_key, planner_public_key, operation_public_key
    window = clock._validate(live_window)
    inherited = transport_deadline_ns
    if inherited is not None:
        shape._integer(inherited, minimum=1)
    bound = window[4] if inherited is None else min(window[4], inherited)
    # Own all mutable historical expectations in the actual pending consumer
    # before any grant-key/clock callback can affect the later plan replay.
    candidate = pending._admit_on_work(operation=operation, originals=held_pending[0],
        expectations=expectations, planner_public_key=held_planner,
        operation_public_key=held_operation, enrollment_bytes=held_enrollment,
        root_public_key=held_root, reserve_request_bytes=held_pending[2],
        reserve_receipt_bytes=held_pending[3], snapshot_bytes=held_pending[4],
        expected_database_id=expected_database_id, expected_generation_digest=expected_generation_digest,
        expected_pending_sequence=expected_pending_sequence,
        expected_pending_head_digest=expected_pending_head_digest, expected_fence=expected_fence,
        live_window=window, work=work, transport_deadline_ns=inherited,
        activation_custody=held_custody, native_review_owner=native_review_owner,
        native_review_frames=native_review_frames, session_token_original=session_token_original)

    def live():
        now = clock._check_on_work(window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        if monotonic >= bound or now >= candidate.original_interval[1]:
            raise SuccessorExecutionAdmissionError("successor execution original admission window expired")
        return now

    verified_now = live()
    grant, grant_digest = grants._verify_control_on_work(grant_bytes=held_grant,
        grant_enrollment_bytes=held_grant_enrollment,
        current_root_enrollment_bytes=held_enrollment, root_public_key=held_root,
        planner_public_key=held_planner, operation_public_key=held_operation,
        expected_authorization_digest=held_authorization, now_epoch_ns=verified_now, work=work)
    snapshot = computation._decode_snapshot_on_work(candidate.snapshot_bytes, work=work)
    evidence.plan._same(grant_digest, candidate.marker["capability_digest"], work,
        "successor pending decision differs from the original execution grant")
    evidence.plan._same(grant["currentRootEnrollmentDigest"], snapshot["enrollmentDigest"], work,
        "successor grant current-root enrollment differs from genuine computation")
    for field in _SNAPSHOT_JOINS:
        evidence.plan._same(grant[field], snapshot[field], work,
            "successor grant differs from genuine computation " + field)
    issued, expires = candidate.original_interval
    if issued != grant["issuedAtEpochNs"] or expires > grant["expiresAtEpochNs"]:
        raise SuccessorExecutionAdmissionError("successor reserve extends or retimes original execution authority")
    finished_now = live()
    # Grant admission already checked its enrolled skew/age at verified_now.
    # A nondecreasing final sample below its unchanged expiry preserves those
    # checks without a second heavy replay or renewing the original interval.
    if finished_now < verified_now or finished_now >= grant["expiresAtEpochNs"]:
        raise SuccessorExecutionAdmissionError("successor grant clock regressed or original grant expired")
    return candidate
