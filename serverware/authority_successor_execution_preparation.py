"""Original predecision grant and plan into one signed reserve computation.

The actual purpose-specific grant verifier authenticates independently pinned
root/authorizer enrollment, request-authorization commitment and original plan
effects once. Its genuine same-call replay feeds the fixed computation signing
suffix; no successful proof/candidate is accepted from a caller and no second
heavy plan replay is substituted. The capabilityDigest is derived only from
the complete original grant, before any reserve exists, avoiding a self-cycle.

All caller history, original bytes, scope and key references are held before
real clock/key callbacks. One original local window bounds the whole operation;
both inherited absolute deadlines and original grant expiry only shorten it.
Grant freshness is checked at a genuine processing instant by its real verifier. Later
epoch samples cannot go backward and must remain below the original expiry:
this preserves the enrolled age/future-issue bounds without exposing policy or
repeating signatures. Supplied original plan issue time is never rewritten.

This produces reserve-request/snapshot bytes, not a durable pending decision,
SQL execution, commit, completion, latest-state claim or retry permission.
Independent request-policy provenance, cold owners and currentness admission
remain caller prerequisites. No IO, new allowance or authority fallback exists.
"""
from __future__ import annotations

import time

from serverware import authority_contract as authority
from serverware import authority_current_root_authorization as authorization
from serverware import authority_current_root_computation as computation
from serverware import authority_current_root_plan_replay as replay
from serverware import authority_successor_execution_grant as grants
from serverware import authority_successor_execution_window as execution_window
from serverware import authority_webauthn_evidence as evidence
from serverware import authority_webauthn_evidence_plan_clock as clock


class SuccessorExecutionPreparationError(ValueError):
    pass


def _produce_reserve_on_work(*, operation, originals, expectations, planner_public_key,
        operation_public_key, before_vector_bytes, enrollment_bytes, root_public_key,
        computation_private_key, grant_bytes, grant_enrollment_bytes, expected_authorization_digest,
        predecessor_sequence, predecessor_head_digest, fence, deadline_epoch_ns, work,
        transport_deadline_ns=None, live_window=None, activation_custody=None):
    """Authenticate an original grant/plan once and derive a nonrenewing reserve.

    There is deliberately no caller capability-digest or successful replay
    parameter. Existing original history/key provenance remains mandatory.
    The return is the actual ``CurrentRootComputation`` original byte pair.
    """
    evidence.capture._SharedLedger(work)
    held_operation = operation
    held_custody = activation_custody
    if type(held_operation) is str and held_operation == replay.ACTIVATION_OPERATION:
        if live_window is None:
            raise SuccessorExecutionPreparationError("activation reserve requires its original supplied window")
        authorization.shape._integer(transport_deadline_ns, minimum=1)
    held_window = None if live_window is None else execution_window._narrow(live_window,
        deadline_epoch_ns=deadline_epoch_ns, maximum_lifetime_ns=authority.VERIFIER_RESPONSE_MAX_AGE_NS,
        maximum_clock_skew_ns=authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    held_originals, held_before = replay._originals(held_operation, originals, before_vector_bytes)
    held_enrollment = authorization._original(enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "authorized reserve current-root enrollment")
    held_grant = authorization._original(grant_bytes, grants.MAX_GRANT_BYTES, "original execution grant")
    held_grant_enrollment = authorization._original(grant_enrollment_bytes,
        grants.MAX_ENROLLMENT_BYTES, "original execution grant enrollment")
    if (sum(len(raw) for raw in held_originals) + len(held_before) + len(held_enrollment)
            + len(held_grant) + len(held_grant_enrollment) > replay.MAX_ORIGINAL_BYTES):
        raise SuccessorExecutionPreparationError("authorized reserve originals exceed the existing aggregate bound")
    held_root, held_signer = root_public_key, computation_private_key
    planner_key, operation_key = planner_public_key, operation_public_key
    authorization._public(held_root)
    authorization._private(held_signer)
    shape = authorization.shape
    shape._digest(expected_authorization_digest)
    shape._digest(predecessor_head_digest)
    shape._integer(predecessor_sequence, authorization.MAX_RECORDS)
    shape._integer(fence, minimum=1)
    shape._integer(deadline_epoch_ns, minimum=1)
    if transport_deadline_ns is not None:
        shape._integer(transport_deadline_ns, minimum=1)
    held_scope = (expected_authorization_digest, predecessor_sequence, predecessor_head_digest,
        fence, deadline_epoch_ns, transport_deadline_ns)
    # This real family helper owns every JSON history graph and preserves the
    # exact UTC revocation datetime before clocks or any external key callback.
    owned = replay._expectations(held_operation, expectations, planner_key, operation_key, work)
    authorization_digest, sequence, predecessor, held_fence, deadline, inherited = held_scope
    window = held_window if held_window is not None else clock._open_on_work(deadline_epoch_ns=deadline,
        maximum_lifetime_ns=authority.VERIFIER_RESPONSE_MAX_AGE_NS,
        maximum_clock_skew_ns=authority.VERIFIER_MAX_CLOCK_SKEW_NS, work=work)
    bound = window[4] if inherited is None else min(window[4], inherited)
    verification_now = window[0]
    last_epoch = verification_now
    last_monotonic = window[2]

    def live(grant=None):
        nonlocal last_epoch, last_monotonic
        now = clock._check_on_work(window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if monotonic >= bound or now < last_epoch or monotonic < last_monotonic:
            raise SuccessorExecutionPreparationError("authorized reserve original window expired or clock reversed")
        if grant is not None and now >= grant["expiresAtEpochNs"]:
            raise SuccessorExecutionPreparationError("authorized reserve original grant expired")
        last_epoch, last_monotonic = now, monotonic
        return now

    checked_now = live()
    if held_window is not None:
        verification_now = checked_now
    # The fixed full verifier authenticates control/enrollment and performs one
    # genuine raw plan replay. This is not a caller-constructed result carrier.
    verified = grants._verify_on_work(grant_bytes=held_grant,
        grant_enrollment_bytes=held_grant_enrollment, current_root_enrollment_bytes=held_enrollment,
        root_public_key=held_root, operation=held_operation, originals=held_originals,
        expectations=owned, planner_public_key=planner_key, operation_public_key=operation_key,
        before_vector_bytes=held_before, expected_authorization_digest=authorization_digest,
        now_epoch_ns=verification_now, work=work, activation_custody=held_custody,
        live_window=window, transport_deadline_ns=bound)
    grant_digest, grant, replayed = verified.grant_digest, verified.payload, verified.replayed
    live(grant)
    # Do not reopen this outer bracket. The unchanged original monotonic bound
    # is shortened using the original opening epoch, not a fresh sampled now.
    effective_deadline = min(deadline, window[3], grant["expiresAtEpochNs"])
    bound = min(bound, window[1] + effective_deadline - window[0])
    live(grant)
    produced = computation._sign_replayed_on_work(replayed=replayed,
        enrollment_bytes=held_enrollment, root_public_key=held_root,
        computation_private_key=held_signer, capability_digest=grant_digest,
        predecessor_sequence=sequence, predecessor_head_digest=predecessor, fence=held_fence,
        deadline_epoch_ns=effective_deadline, transport_deadline_ns=bound, work=work,
        live_window=window)
    live(grant)
    return produced
