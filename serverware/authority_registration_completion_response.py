"""Authenticate returned registration completion originals on existing work.

Independent original plan/grant/reserve scope, actual keys and the caller's
unchanged live window precede every native callback. Genuine historical plan
replay derives the marker; the enrolled completion and state signatures then
bind the returned original observation to that exact scope. No received head,
candidate, successful-result carrier or packet locator supplies authority.

This module performs no SQL, transport, signing, storage, clock-window opening
or retry. Authenticated historical key statements do not prove independent
database truth, latest-state currentness or credential finalization. The wire
does not contain a packet ID and this verifier makes no packet-ID claim.
"""
from __future__ import annotations

from dataclasses import dataclass
import time

from serverware import authority_current_root_completion as completion
from serverware import authority_current_root_delivery_records as records
from serverware import authority_registration_completion_transport as transport


authorization, pending, grants = completion.authorization, completion.pending, completion.grants
evidence, clock, vector = completion.evidence, completion.clock, completion.vector
OPERATION = "webauthn.registration.evidence.admit"
MAX_ORIGINAL_BYTES = pending.replay.MAX_ORIGINAL_BYTES
_OBSERVATION_FIELDS = frozenset({"schema", "sourceRevision", "marker",
    "afterVectorDigest", "observedAtEpochNs"})
_REQUEST_MARKER_JOINS = (
    ("operation", "operation"), ("databaseId", "database_id"),
    ("generationDigest", "generation_digest"), ("enrollmentDigest", "enrollment_digest"),
    ("pendingRequestDigest", "pending_request_digest"),
    ("pendingDecisionDigest", "pending_decision_digest"), ("fence", "fence"),
    ("snapshotDigest", "snapshot_digest"), ("resultDigest", "result_digest"),
    ("beforeVectorDigest", "before_vector_digest"), ("afterVectorDigest", "after_vector_digest"),
)


class RegistrationCompletionResponseError(ValueError):
    pass


class RegistrationCompletionUncertainError(RegistrationCompletionResponseError):
    """Uncertainty only; carries no request, receipt, identity or retry grant."""


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _VerifiedCompletionResponse:
    """Ordinary original observations; no admission API accepts this object."""

    completion_request_bytes: bytes
    state_receipt_bytes: bytes
    completion_request_digest: str
    state_receipt_digest: str


def _observation_on_work(request, candidate, work):
    raw = authorization.transport._decode(request["writerReceiptBase64Url"],
        request["writerReceiptByteCount"], completion.MAX_OBSERVATION_BYTES, work)
    document = authorization.wire._decode_object(raw, work=work,
        maximum_bytes=completion.MAX_OBSERVATION_BYTES,
        maximum_nodes=completion.MAX_OBSERVATION_NODES, maximum_depth=3)
    shape = authorization.shape
    shape._object(document, _OBSERVATION_FIELDS, "registration completion observation")
    shape._literal(document["schema"], completion.OBSERVATION_SCHEMA)
    shape._literal(document["sourceRevision"], authorization.authority.SOURCE_REVISION)
    shape._object(document["marker"], frozenset(pending._MARKER_COLUMNS),
        "registration completion observation marker")
    evidence.plan._same(document["marker"], candidate.marker, work,
        "registration completion observation differs from genuine marker replay")
    # Derive the digest from the genuine full after-vector, not a response claim.
    after_digest = vector._digest_on_work(candidate.after_vector_bytes, work=work)
    for actual in (candidate.marker["after_vector_digest"], request["afterVectorDigest"],
            document["afterVectorDigest"]):
        evidence.plan._same(actual, after_digest, work,
            "registration completion observation differs from the full after-vector")
    observed_at = document["observedAtEpochNs"]
    shape._integer(observed_at, minimum=1)
    if not request["issuedAtEpochNs"] <= observed_at < request["expiresAtEpochNs"]:
        raise RegistrationCompletionResponseError("registration observation escapes the original completion interval")
    # Use the actual producer's encoding, including its exact source revision
    # and marker, to reject noncanonical or alternate observation semantics.
    expected = completion._observation_bytes(candidate.marker, after_digest, observed_at, work)
    work.charge(input_bytes=len(raw) + len(expected))
    if raw != expected:
        raise RegistrationCompletionResponseError("registration completion observation is not the exact canonical original")


def _verify_on_work(*, response_originals, plan_originals,
        reserve_request_bytes, reserve_receipt_bytes, snapshot_bytes,
        enrollment_bytes, grant_bytes, grant_enrollment_bytes,
        expectations, planner_public_key, evidence_public_key, root_public_key,
        expected_authorization_digest, expected_database_id, expected_generation_digest,
        expected_pending_sequence, expected_pending_head_digest, expected_fence,
        live_window, work, transport_deadline_ns=None):
    """Return only authenticated original completion/ack bytes and identities.

    All original bounds, the complete aggregate and independent scope are held
    before detaching historical expectations and sampling clocks or keys. The
    supplied original window is never opened again, clipped upward or renewed.
    Signed historical completion expiry need not be current; it supplies no
    fresh action-time or latest-head authority.
    """
    evidence.capture._SharedLedger(work)
    returned = transport._originals(response_originals, response=True)
    held = pending._originals(OPERATION, plan_originals, enrollment_bytes,
        reserve_request_bytes, reserve_receipt_bytes, snapshot_bytes)
    originals, enrollment, reserve, reserve_receipt, snapshot = held
    grant = authorization._original(grant_bytes, grants.MAX_GRANT_BYTES,
        "registration completion grant")
    grant_enrollment = authorization._original(grant_enrollment_bytes,
        grants.MAX_ENROLLMENT_BYTES, "registration completion grant enrollment")
    if sum(len(raw) for raw in (*originals, *held[1:], grant,
            grant_enrollment, *returned)) > MAX_ORIGINAL_BYTES:
        raise RegistrationCompletionResponseError("registration completion originals exceed the aggregate source bound")
    root, planner, operation_key = root_public_key, planner_public_key, evidence_public_key
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
        raise RegistrationCompletionUncertainError("registration completion outcome is not established")
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
            raise RegistrationCompletionResponseError("registration completion response expired or its clocks reversed")
        last_epoch, last_monotonic = now, monotonic
        return now

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
        "registration completion response identity differs from the original framed request")
    request = acknowledged.request_payload
    evidence.plan._same(request["action"], "complete", work,
        "registration completion response is not the complete action")
    for field, column in _REQUEST_MARKER_JOINS:
        evidence.plan._same(request[field], candidate.marker[column], work,
            "registration completion control differs from genuine marker " + field)
    live()
    # The genuine control verifier above already authenticated these exact
    # embedded bytes/hash. This adds their fixed producer semantics, not a
    # separate database observation or an unsigned-observation trust token.
    _observation_on_work(request, candidate, work)
    live()
    return _VerifiedCompletionResponse(returned[2], returned[3],
        acknowledged.request_digest, acknowledged.receipt_digest)
