"""Original reserve/receipt/plan admission into ordinary execution candidates.

The caller independently admits root/planner/operation keys, historical plan
expectations and the exact database/generation/pending checkpoint/fence. An
actual unchanged live window is supplied by that caller; this module samples
real clocks against it and never opens or renews a window.

Original root enrollment, computation reserve and state receipt signatures are
verified here. All six original plan families undergo genuine semantic/proof
replay, complete vector reconstruction and exact computation-snapshot replay.
Only those actual selected rows, ordered mutations, result and work units are
returned, with the source's exact eighteen-column commit-marker expectation.

This is not request-policy authorization, execution-capability admission,
independent latest-state admission, SQL permission or proof of commit. In
particular, the reserve capabilityDigest is a distinct original scope digest,
not the revocation capabilityId. A future fixed executor must separately admit
the actual purpose-specific grant and current pending authority, compare real
database state, apply the exact effects and retain postcommit evidence. No
successful-result carrier is accepted as an input; no SQL or allowance exists
here, and returned data grants no retry or authority.

A separate historical completion entrypoint shares original replay but never
returns selected rows or mutations. Its fresh local observation window cannot
renew the expired reserve; actual marker/root observation remains mandatory.
"""
from __future__ import annotations

from dataclasses import dataclass
import time

from serverware import authority_contract as authority
from serverware import authority_current_root_authorization as authorization
from serverware import authority_current_root_computation as computation
from serverware import authority_current_root_plan_replay as replay
from serverware import authority_current_root_vector as vector
from serverware import authority_webauthn_evidence as evidence
from serverware import authority_webauthn_evidence_plan_clock as clock


MAX_RECEIPT_BYTES = 16 * 1024
_MARKER_COLUMNS = (
    "pending_decision_digest", "source_revision", "database_id", "enrollment_digest",
    "generation_digest", "pending_request_digest", "pending_sequence", "predecessor_sequence",
    "predecessor_head_digest", "fence", "operation", "request_digest", "operation_id",
    "capability_digest", "snapshot_digest", "before_vector_digest", "after_vector_digest", "result_digest",
)


class CurrentRootExecutionAdmissionError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ExecutionCandidate:
    """Same-call owned computation data, not an accepted execution grant."""

    operation: str
    request: dict
    selected_rows: tuple
    mutations: tuple
    result: object
    before_vector_bytes: bytes
    after_vector_bytes: bytes
    marker: dict
    original_interval: tuple[int, int]
    reserve_request_bytes: bytes
    reserve_receipt_bytes: bytes
    snapshot_bytes: bytes
    work_units: int


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _PendingCompletion:
    """Historical same-call scope only; deliberately no executable mutations."""

    operation: str
    marker: dict
    after_vector_bytes: bytes
    reserve_request_bytes: bytes
    reserve_receipt_bytes: bytes
    snapshot_bytes: bytes
    original_interval: tuple[int, int]


def _originals(operation, originals, enrollment_bytes, reserve_request_bytes,
        reserve_receipt_bytes, snapshot_bytes):
    authorization.delta._source(operation)
    count = (2 if operation == replay.REVOCATION_OPERATION else
        3 if operation in replay.EVIDENCE_OPERATIONS else 4)
    if (type(originals) is not tuple or len(originals) != count
            or any(type(raw) is not bytes or not 2 <= len(raw) <= replay.MAX_ORIGINAL_BYTES
                for raw in originals)):
        raise CurrentRootExecutionAdmissionError("execution admission needs the fixed original plan tuple")
    enrollment = authorization._original(enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "execution enrollment")
    request = authorization._original(reserve_request_bytes,
        authorization.MAX_BYTES, "execution reserve request")
    receipt = authorization._original(reserve_receipt_bytes, MAX_RECEIPT_BYTES, "execution reserve receipt")
    snapshot = authorization._original(snapshot_bytes, computation.MAX_SNAPSHOT_BYTES, "execution snapshot")
    if sum(len(raw) for raw in (*originals, enrollment, request, receipt, snapshot)) > replay.MAX_ORIGINAL_BYTES:
        raise CurrentRootExecutionAdmissionError("execution originals exceed the existing aggregate byte bound")
    return originals, enrollment, request, receipt, snapshot


def _scope(*, expected_database_id, expected_generation_digest, expected_pending_sequence,
        expected_pending_head_digest, expected_fence, live_window, transport_deadline_ns):
    shape = authorization.shape
    authorization._token(expected_database_id)
    shape._digest(expected_generation_digest)
    shape._integer(expected_pending_sequence, authorization.MAX_RECORDS, minimum=1)
    shape._digest(expected_pending_head_digest)
    shape._integer(expected_fence, minimum=1)
    held_window = clock._validate(live_window)
    if transport_deadline_ns is not None:
        shape._integer(transport_deadline_ns, minimum=1)
    return (expected_database_id, expected_generation_digest, expected_pending_sequence,
        expected_pending_head_digest, expected_fence, held_window, transport_deadline_ns)


def _live(window, inherited, work):
    now = clock._check_on_work(window, work=work)
    if inherited is not None:
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        authorization.shape._integer(monotonic, minimum=1)
        if monotonic >= min(window[4], inherited):
            raise CurrentRootExecutionAdmissionError("execution admission inherited deadline expired")
    return now


def _pending(material, request, request_digest, receipt, receipt_digest, scope, work):
    database_id, generation_digest, sequence, head_digest, fence, _window, _inherited = scope
    expected = (
        (request["action"], "reserve"), (receipt["action"], "reserve"),
        (material.payload["databaseId"], database_id),
        (material.payload["generationDigest"], generation_digest),
        (receipt_digest, head_digest), (receipt["sequence"], sequence),
        (receipt["sequence"], request["predecessorSequence"] + 1),
        (receipt["previousHeadDigest"], request["predecessorHeadDigest"]),
        (receipt["requestDigest"], request_digest), (receipt["pendingRequestDigest"], request_digest),
        (receipt["fence"], fence), (request["fence"], fence),
        (receipt["enrollmentDigest"], material.enrollment_digest),
        (receipt["databaseId"], database_id), (receipt["generationDigest"], generation_digest),
        (receipt["issuedAtEpochNs"], request["issuedAtEpochNs"]),
        (receipt["expiresAtEpochNs"], request["expiresAtEpochNs"]),
    )
    for actual, wanted in expected:
        evidence.plan._same(actual, wanted, work, "execution reserve differs from exact pending scope")
    if sequence >= material.payload["maxRecords"]:
        raise CurrentRootExecutionAdmissionError("execution pending decision has no reserved completion capacity")


def _marker(material, request, request_digest, receipt, receipt_digest, snapshot, work):
    if authority.CURRENT_ROOT_COMMIT_MARKER_COLUMNS != _MARKER_COLUMNS:
        raise CurrentRootExecutionAdmissionError("execution marker differs from the exact source storage contract")
    marker = {
        "pending_decision_digest": receipt_digest, "source_revision": authority.SOURCE_REVISION,
        "database_id": material.payload["databaseId"], "enrollment_digest": material.enrollment_digest,
        "generation_digest": material.payload["generationDigest"], "pending_request_digest": request_digest,
        "pending_sequence": receipt["sequence"], "predecessor_sequence": request["predecessorSequence"],
        "predecessor_head_digest": request["predecessorHeadDigest"], "fence": request["fence"],
        "operation": request["operation"], "request_digest": request["requestDigest"],
        "operation_id": request["operationId"], "capability_digest": request["capabilityDigest"],
        "snapshot_digest": request["snapshotDigest"], "before_vector_digest": snapshot["beforeVectorDigest"],
        "after_vector_digest": snapshot["afterVectorDigest"], "result_digest": snapshot["resultDigest"],
    }
    if tuple(marker) != _MARKER_COLUMNS:
        raise CurrentRootExecutionAdmissionError("execution marker lost its exact source column order")
    return evidence.capture._JSONCapture(evidence.capture._SharedLedger(work)).visit(marker)


def _derive_on_work(*, operation, originals, expectations, planner_public_key,
        operation_public_key, enrollment_bytes, root_public_key, reserve_request_bytes,
        reserve_receipt_bytes, snapshot_bytes, expected_database_id, expected_generation_digest,
        expected_pending_sequence, expected_pending_head_digest, expected_fence,
        live_window, work, transport_deadline_ns, historical_controls):
    """Fixed replay shared by separate live-execution/historical-completion paths.

    ``original_interval`` in the candidate is the effective ORIGINAL RESERVE
    issue/expiry, exactly equal to the state receipt. The original plan's own
    distinct interval remains unchanged inside the verified computation snapshot.
    Neither interval is rewritten or extended. The caller must keep checking
    its same window and original grant around actual downstream execution.
    """
    if type(historical_controls) is not bool:
        raise CurrentRootExecutionAdmissionError("pending admission purpose is not source-selected")
    evidence.capture._SharedLedger(work)
    held_operation = operation
    held = _originals(held_operation, originals, enrollment_bytes,
        reserve_request_bytes, reserve_receipt_bytes, snapshot_bytes)
    plan_originals, enrollment, reserve, receipt_original, snapshot_original = held
    held_root, planner_key, operation_key = root_public_key, planner_public_key, operation_public_key
    authorization._public(held_root)
    scope = _scope(expected_database_id=expected_database_id,
        expected_generation_digest=expected_generation_digest,
        expected_pending_sequence=expected_pending_sequence,
        expected_pending_head_digest=expected_pending_head_digest, expected_fence=expected_fence,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns)
    # All caller JSON is detached before the first actual clock/key callback.
    # This uses the fixed family capture, including revocation's held exact UTC
    # instant, and never derives independent expectations from returned bytes.
    expected = replay._expectations(held_operation, expectations, planner_key, operation_key, work)
    window, inherited = scope[5:]
    initial_now = _live(window, inherited, work)
    if historical_controls:
        material, request, request_digest = authorization._verify_historical_request_on_work(
            request_bytes=reserve, enrollment_bytes=enrollment, root_public_key=held_root, work=work)
    else:
        material, request, request_digest = authorization._verify_request_on_work(
            request_bytes=reserve, enrollment_bytes=enrollment, root_public_key=held_root,
            now_epoch_ns=initial_now, work=work)
    if request["action"] != "reserve":
        raise CurrentRootExecutionAdmissionError("execution admission accepts only an original reserve")
    receipt = authorization._verify_receipt_on_work(receipt_bytes=receipt_original,
        enrollment_bytes=enrollment, root_public_key=held_root, work=work)
    receipt_digest = authorization._receipt_digest_on_work(receipt_original, work)
    _pending(material, request, request_digest, receipt, receipt_digest, scope, work)
    evidence.plan._same(request["operation"], held_operation, work, "execution operation differs from reserve")
    now = _live(window, inherited, work)
    if not historical_controls:
        authorization._fresh(request, material, now)
    before_bytes = vector._encode_on_work(request["beforeVector"], work=work)
    replayed = replay._replay_on_work(operation=held_operation, originals=plan_originals,
        expectations=expected, planner_public_key=planner_key, operation_public_key=operation_key,
        before_vector_bytes=before_bytes, work=work)
    for field in ("operation", "requestDigest", "operationId"):
        evidence.plan._same(request[field], replayed.request[field], work,
            "execution reserve differs from actual typed plan request")
    # The computation producer preserves the plan's original issue instant and
    # may only shorten expiry. A historical state receipt cannot renew either.
    if (request["issuedAtEpochNs"] != replayed.original_interval[0]
            or request["expiresAtEpochNs"] > replayed.original_interval[1]):
        raise CurrentRootExecutionAdmissionError("execution reserve renewed its original plan interval")
    expected_snapshot = computation._snapshot(replayed, material, request["capabilityDigest"], work)
    actual_snapshot_bytes = computation._snapshot_wire(expected_snapshot, work)
    work.charge(input_bytes=len(actual_snapshot_bytes) + len(snapshot_original))
    if actual_snapshot_bytes != snapshot_original:
        raise CurrentRootExecutionAdmissionError("execution snapshot differs from genuine original plan replay")
    snapshot_digest = computation._snapshot_digest_on_work(snapshot_original, work=work)
    evidence.plan._same(snapshot_digest, request["snapshotDigest"], work,
        "execution reserve does not commit its actual computation snapshot")
    after_bytes = vector._encode_on_work(request["afterVector"], work=work)
    work.charge(input_bytes=len(before_bytes) + len(replayed.before_vector_bytes)
        + len(after_bytes) + len(replayed.after_vector_bytes))
    if before_bytes != replayed.before_vector_bytes or after_bytes != replayed.after_vector_bytes:
        raise CurrentRootExecutionAdmissionError("execution vectors differ from actual plan effects")
    for field, actual in (("beforeVectorDigest", replayed.before_vector_digest),
            ("afterVectorDigest", replayed.after_vector_digest)):
        evidence.plan._same(receipt[field], actual, work,
            "execution state receipt differs from actual complete vectors")
    marker = _marker(material, request, request_digest, receipt, receipt_digest, expected_snapshot, work)
    now = _live(window, inherited, work)
    if historical_controls:
        return _PendingCompletion(held_operation, marker, replayed.after_vector_bytes,
            reserve, receipt_original, snapshot_original,
            (request["issuedAtEpochNs"], request["expiresAtEpochNs"]))
    authorization._fresh(request, material, now)
    return _ExecutionCandidate(held_operation, replayed.request, replayed.selected_rows,
        replayed.mutations, replayed.result, replayed.before_vector_bytes, replayed.after_vector_bytes,
        marker, (request["issuedAtEpochNs"], request["expiresAtEpochNs"]), reserve,
        receipt_original, snapshot_original, replayed.work_units)


def _admit_on_work(*, operation, originals, expectations, planner_public_key,
        operation_public_key, enrollment_bytes, root_public_key, reserve_request_bytes,
        reserve_receipt_bytes, snapshot_bytes, expected_database_id, expected_generation_digest,
        expected_pending_sequence, expected_pending_head_digest, expected_fence,
        live_window, work, transport_deadline_ns=None):
    """Live original controls plus genuine replay; no execution authority alone."""
    return _derive_on_work(operation=operation, originals=originals, expectations=expectations,
        planner_public_key=planner_public_key, operation_public_key=operation_public_key,
        enrollment_bytes=enrollment_bytes, root_public_key=root_public_key,
        reserve_request_bytes=reserve_request_bytes, reserve_receipt_bytes=reserve_receipt_bytes,
        snapshot_bytes=snapshot_bytes, expected_database_id=expected_database_id,
        expected_generation_digest=expected_generation_digest,
        expected_pending_sequence=expected_pending_sequence,
        expected_pending_head_digest=expected_pending_head_digest, expected_fence=expected_fence,
        live_window=live_window, work=work, transport_deadline_ns=transport_deadline_ns,
        historical_controls=False)


def _admit_for_completion_on_work(*, operation, originals, expectations, planner_public_key,
        operation_public_key, enrollment_bytes, root_public_key, reserve_request_bytes,
        reserve_receipt_bytes, snapshot_bytes, expected_database_id, expected_generation_digest,
        expected_pending_sequence, expected_pending_head_digest, expected_fence,
        live_window, work, transport_deadline_ns=None):
    """Historical pending scope for actual postcommit observation, never execution.

    This still verifies every original signature, original interval, exact
    independently current pending checkpoint, and genuine original plan. The
    caller's fresh completion window is checked throughout; expired execution
    authority is not renewed. No selected rows or mutations are returned.
    """
    return _derive_on_work(operation=operation, originals=originals, expectations=expectations,
        planner_public_key=planner_public_key, operation_public_key=operation_public_key,
        enrollment_bytes=enrollment_bytes, root_public_key=root_public_key,
        reserve_request_bytes=reserve_request_bytes, reserve_receipt_bytes=reserve_receipt_bytes,
        snapshot_bytes=snapshot_bytes, expected_database_id=expected_database_id,
        expected_generation_digest=expected_generation_digest,
        expected_pending_sequence=expected_pending_sequence,
        expected_pending_head_digest=expected_pending_head_digest, expected_fence=expected_fence,
        live_window=live_window, work=work, transport_deadline_ns=transport_deadline_ns,
        historical_controls=True)
