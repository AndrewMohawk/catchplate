"""Join original maintenance grant/pending controls to genuine streamed effects.

Every control is an original signed byte string. Exact independently admitted
database/generation/pending-head/fence and request authorization remain required
inputs. The sole entrypoint authenticates those originals, then actually replays
the raw maintenance pages once while tentatively retaining same-call effects.
It never accepts an execution header, mutation list or successful proof DTO.

Only a later protected issuer may seal the completed output. A retained prefix,
returned digest, ordinary result object or signed grant is not SQL permission.
That issuer must retain its genuine role/configuration/transaction custody and
must not publish a header after any error. No clock, connection, work allowance,
current checkpoint, commit, retry or root enrollment is created here.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_challenge_computation as computation
from catchplate import authority_challenge_execution_grant as grants
from catchplate import authority_challenge_execution_stream as streams
from catchplate import authority_current_root_execution_admission as pending


authorization, plan, vector = pending.authorization, streams.plan, streams.current_root.vector
OPERATION = grants.OPERATION


class ChallengeExecutionAdmissionError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _PreparedMaintenanceStream:
    """Ordinary same-call output; no public executor accepts this carrier."""

    stream_header_bytes: bytes
    stream_digest: str
    pending_decision_digest: str
    grant_digest: str
    marker: dict
    before_vector_bytes: bytes
    after_vector_bytes: bytes
    original_interval: tuple
    result: object
    originals: tuple
    controls: tuple
    original_deadline_ns: int
    last_epoch_ns: int
    last_monotonic_ns: int


def _require(value):
    if not value:
        raise ChallengeExecutionAdmissionError("maintenance stream differs from its original pending authority")


def _same_bytes(actual, expected, work):
    _require(type(actual) is bytes and type(expected) is bytes)
    work.charge(input_bytes=len(actual) + len(expected))
    _require(actual == expected)


def _prepare_on_work(*, originals, expectations, planner_public_key,
        enrollment_bytes, root_public_key, reserve_request_bytes, reserve_receipt_bytes,
        snapshot_bytes, grant_bytes, grant_enrollment_bytes, expected_authorization_digest,
        expected_database_id, expected_generation_digest, expected_pending_sequence,
        expected_pending_head_digest, expected_fence, live_window,
        read_original, check, retain_effect, work):
    """Authenticate fixed controls, replay raw pages once, then close all joins."""
    _require(callable(read_original) and callable(check) and callable(retain_effect))
    plan.evidence.capture._SharedLedger(work)
    _require(type(originals) is tuple and len(originals) == 3)
    for raw, maximum in zip(originals, grants.FRAME_MAXIMA, strict=True):
        authorization._original(raw, maximum, "maintenance execution original")
    enrollment = authorization._original(enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "maintenance current-root enrollment")
    reserve = authorization._original(reserve_request_bytes,
        authorization.MAX_BYTES, "maintenance original reserve")
    receipt_raw = authorization._original(reserve_receipt_bytes,
        pending.MAX_RECEIPT_BYTES, "maintenance original pending receipt")
    snapshot_raw = authorization._original(snapshot_bytes,
        pending.computation.MAX_SNAPSHOT_BYTES, "maintenance original computation")
    grant_raw = authorization._original(grant_bytes, grants.MAX_GRANT_BYTES, "maintenance grant")
    delegation = authorization._original(grant_enrollment_bytes,
        grants.MAX_ENROLLMENT_BYTES, "maintenance authorizer enrollment")
    controls = (enrollment, delegation, grant_raw, reserve, receipt_raw, snapshot_raw)
    _require(sum(len(raw) for raw in (*originals, *controls)) <= authorization.authority.MAX_RESULT_BYTES)
    authorization._public(root_public_key)
    authorization._public(planner_public_key)
    authorization.shape._digest(expected_authorization_digest)
    # Mutable expectations and fixed scope are owned before the first clock,
    # key, raw-page, or tentative-retention callback.
    expected = plan._expectations(expectations, work)
    _require(expected["context"]["operation"] == OPERATION)
    plan._request(originals[1], expected["context"], work)
    scope = pending._scope(expected_database_id=expected_database_id,
        expected_generation_digest=expected_generation_digest,
        expected_pending_sequence=expected_pending_sequence,
        expected_pending_head_digest=expected_pending_head_digest, expected_fence=expected_fence,
        live_window=live_window, transport_deadline_ns=expected["context"]["originalDeadlineNs"])
    live = grants._Live(scope[5], scope[6])
    initial_now = live.sample(work)
    material, request, request_digest = authorization._verify_request_on_work(
        request_bytes=reserve, enrollment_bytes=enrollment, root_public_key=root_public_key,
        now_epoch_ns=initial_now, work=work)
    _require(request["action"] == "reserve" and request["operation"] == OPERATION)
    receipt = authorization._verify_receipt_on_work(receipt_bytes=receipt_raw,
        enrollment_bytes=enrollment, root_public_key=root_public_key, work=work)
    receipt_digest = authorization._receipt_digest_on_work(receipt_raw, work)
    pending._pending(material, request, request_digest, receipt, receipt_digest, scope, work)
    grant, grant_digest = grants._verify_control_on_work(grant_bytes=grant_raw,
        grant_enrollment_bytes=delegation, current_root_enrollment_bytes=enrollment,
        root_public_key=root_public_key, planner_public_key=planner_public_key,
        expected_authorization_digest=expected_authorization_digest, live_window=scope[5], work=work)
    for actual, wanted in ((request["capabilityDigest"], grant_digest),
            (grant["currentRootEnrollmentDigest"], material.enrollment_digest),
            (grant["databaseId"], scope[0]), (grant["generationDigest"], scope[1])):
        plan._same(actual, wanted, work)
    # Unlike older aggregate families, this source successor preserves exactly
    # one original interval through parent, predecision grant and reservation.
    interval = request["issuedAtEpochNs"], request["expiresAtEpochNs"]
    plan._same(interval, (grant["issuedAtEpochNs"], grant["expiresAtEpochNs"]), work)
    before = vector._encode_on_work(request["beforeVector"], work=work)

    def current(stage=None):
        selected_work = work if stage is None else stage.work
        if stage is not None:
            _require(type(stage) is streams.compound._Stage)
            stage.check()
        now = live.sample(selected_work)
        authorization._fresh(request, material, now)
        _require(now >= initial_now and now < grant["expiresAtEpochNs"])
        return now

    def checked(stage):
        current(stage)
        _require(check(stage) is None)
        current(stage)

    def retain(ordinal, raw, descriptor, stage):
        current(stage)
        _require(retain_effect(ordinal, raw, descriptor, stage) is None)
        current(stage)

    current()
    # The callback gets only actual engine effects. An error in any later
    # signature/snapshot/vector/header join leaves that prefix unsealed.
    derived = streams.derive_stream(envelope_bytes=originals[0], request_bytes=originals[1],
        manifest_bytes=originals[2], expectations=expected, planner_public_key=planner_public_key,
        before_vector_bytes=before, read_original=read_original, check=checked,
        retain_effect=retain, work=work)
    _require(type(derived) is streams.DerivedExecutionStream)
    observed = derived.observation
    _require(type(observed) is streams.current_root.MaintenanceVectorObservation)
    current()
    plan._same(interval, observed.original_interval, work)
    for name in ("operation", "requestDigest", "operationId"):
        plan._same(request[name], expected["context"][name], work)
    actual_snapshot = computation._snapshot_on_work(observed=observed, originals=originals,
        expected=expected, material=material, capability_digest=grant_digest, work=work)
    actual_snapshot_bytes = pending.computation._snapshot_wire(actual_snapshot, work)
    _same_bytes(actual_snapshot_bytes, snapshot_raw, work)
    snapshot_digest = pending.computation._snapshot_digest_on_work(snapshot_raw, work=work)
    plan._same(snapshot_digest, request["snapshotDigest"], work)
    after = vector._encode_on_work(request["afterVector"], work=work)
    _same_bytes(before, observed.before_vector_bytes, work)
    _same_bytes(after, observed.after_vector_bytes, work)
    for name, digest in (("beforeVectorDigest", observed.before_vector_digest),
            ("afterVectorDigest", observed.after_vector_digest)):
        plan._same(receipt[name], digest, work)
    # This same invocation's genuine replay, not a supplied successful carrier,
    # determines every maintenance grant claim including raw3 byte identities.
    actual_claims = grants._claims(observed, originals, expected, work)
    for name, value in actual_claims.items():
        plan._same(grant[name], value, work)
    marker = pending._marker(material, request, request_digest, receipt, receipt_digest,
        actual_snapshot, work)
    result = plan.evidence.capture._JSONCapture(plan.evidence.capture._SharedLedger(work)).visit(observed.result)
    final_now = current()
    return _PreparedMaintenanceStream(derived.header_bytes, derived.header_digest,
        receipt_digest, grant_digest, marker, before, after, interval, result, originals, controls,
        expected["context"]["originalDeadlineNs"], final_now, live.last_monotonic)
