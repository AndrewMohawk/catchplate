"""Verify finalization completion originals, not unsigned SQL observations.

The original finalization plan/grant/reservation, independent historical keys
and pending scope are held before callbacks. Actual completion-only plan replay
derives the marker; enrolled completion and state signatures then bind returned
originals to that exact scope. Neither a received ID nor a supplied successful
verification object can replace those checks.

No SQL, transport, signing, storage, clock-window opening or retry occurs here.
Authenticated historical statements are not a live off-host head or permission
to activate an OIDC session. The wire has no packet ID; this verifier makes no
packet-identity claim. Caller ownership/purpose and retention remain separate.
"""
from __future__ import annotations

from dataclasses import dataclass
import time

from serverware import authority_registration_completion_response as shared
from serverware import authority_registration_finalization_completion_transport as transport


completion, records = shared.completion, shared.records
authorization, pending, grants = shared.authorization, shared.pending, shared.grants
evidence, clock = shared.evidence, shared.clock
OPERATION = "webauthn.registration.finalize"
MAX_ORIGINAL_BYTES = pending.replay.MAX_ORIGINAL_BYTES


class FinalizationCompletionResponseError(ValueError):
    pass


class FinalizationCompletionUncertainError(FinalizationCompletionResponseError):
    """No authenticated completion or retry permission is established."""


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _VerifiedCompletionResponse:
    """Private original observations; never accepted as an incoming proof."""

    completion_request_bytes: bytes
    state_receipt_bytes: bytes
    completion_request_digest: str
    state_receipt_digest: str


def _verify_on_work(*, response_originals, plan_originals,
        reserve_request_bytes, reserve_receipt_bytes, snapshot_bytes,
        enrollment_bytes, grant_bytes, grant_enrollment_bytes,
        expectations, planner_public_key, operation_public_key, root_public_key,
        expected_authorization_digest, expected_database_id, expected_generation_digest,
        expected_pending_sequence, expected_pending_head_digest, expected_fence,
        live_window, work, transport_deadline_ns=None):
    """Authenticate complete original signatures/replay under one held window.

    Historical completion expiry is not refreshed. Original plan expectations,
    caller authorization digest and pending scope must already have independent
    provenance; caller-authorization and retained ownership admission are not
    synthesized here. The result is not a successful-admission input token.
    """
    evidence.capture._SharedLedger(work)
    returned = transport._originals(response_originals, response=True)
    held = pending._originals(OPERATION, plan_originals, enrollment_bytes,
        reserve_request_bytes, reserve_receipt_bytes, snapshot_bytes)
    originals, enrollment, reserve, reserve_receipt, snapshot = held
    grant = authorization._original(grant_bytes, grants.MAX_GRANT_BYTES,
        "finalization completion grant")
    grant_enrollment = authorization._original(grant_enrollment_bytes,
        grants.MAX_ENROLLMENT_BYTES, "finalization completion grant enrollment")
    if sum(len(raw) for raw in (*originals, *held[1:], grant,
            grant_enrollment, *returned)) > MAX_ORIGINAL_BYTES:
        raise FinalizationCompletionResponseError("finalization completion originals exceed the aggregate source bound")
    root, planner, operation_key = root_public_key, planner_public_key, operation_public_key
    authorization._public(root)
    authorization.shape._digest(expected_authorization_digest)
    authorization_digest = expected_authorization_digest
    scope = pending._scope(expected_database_id=expected_database_id,
        expected_generation_digest=expected_generation_digest,
        expected_pending_sequence=expected_pending_sequence,
        expected_pending_head_digest=expected_pending_head_digest,
        expected_fence=expected_fence, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns)
    expected = pending.replay._expectations(OPERATION, expectations, planner, operation_key, work)
    database_id, generation, sequence, head, fence, window, inherited = scope
    if returned[0] == b"uncertain":
        raise FinalizationCompletionUncertainError("finalization completion outcome is not established")
    work.charge(input_bytes=len(returned[1]))
    returned_identity = returned[1].decode("ascii")
    bound = window[4] if inherited is None else min(window[4], inherited)
    last_epoch, last_monotonic = window[0], window[2]

    def live():
        nonlocal last_epoch, last_monotonic
        now = clock._check_on_work(window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        authorization.shape._integer(monotonic, minimum=1)
        if monotonic >= bound or now < last_epoch or monotonic < last_monotonic:
            raise FinalizationCompletionResponseError("finalization completion response expired or clocks reversed")
        last_epoch, last_monotonic = now, monotonic

    live()
    candidate = pending._admit_for_completion_on_work(operation=OPERATION,
        originals=originals, expectations=expected, planner_public_key=planner,
        operation_public_key=operation_key, enrollment_bytes=enrollment, root_public_key=root,
        reserve_request_bytes=reserve, reserve_receipt_bytes=reserve_receipt,
        snapshot_bytes=snapshot, expected_database_id=database_id,
        expected_generation_digest=generation, expected_pending_sequence=sequence,
        expected_pending_head_digest=head, expected_fence=fence,
        live_window=window, work=work, transport_deadline_ns=bound)
    live()
    completion._verify_grant_on_work(candidate=candidate, grant_raw=grant,
        grant_enrollment=grant_enrollment, enrollment=enrollment, root_public_key=root,
        planner_public_key=planner, operation_public_key=operation_key,
        authorization_digest=authorization_digest, work=work)
    live()
    acknowledged = records._verify_ack_on_work(request_bytes=returned[2],
        receipt_bytes=returned[3], enrollment_bytes=enrollment, root_public_key=root,
        expected_pending_sequence=sequence, expected_pending_head_digest=head, work=work)
    live()
    evidence.plan._same(returned_identity, acknowledged.request_digest, work,
        "finalization completion response ID differs from its framed original request")
    request = acknowledged.request_payload
    evidence.plan._same(request["action"], "complete", work,
        "finalization completion response is not the complete action")
    # These columns and producer semantics are operation-neutral. The actual
    # finalization candidate above supplies every expected value; no evidence
    # verifier or externally supplied candidate is used as finalization scope.
    for field, column in shared._REQUEST_MARKER_JOINS:
        evidence.plan._same(request[field], candidate.marker[column], work,
            "finalization completion control differs from genuine marker " + field)
    live()
    shared._observation_on_work(request, candidate, work)
    live()
    return _VerifiedCompletionResponse(returned[2], returned[3],
        acknowledged.request_digest, acknowledged.receipt_digest)
