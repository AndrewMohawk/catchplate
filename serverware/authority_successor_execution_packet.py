"""Closed original-retaining custody packets from genuine successor admission.

The sole entrypoint accepts original plans/controls and independently admitted
scope, keys and historical expectations. It performs the actual successor
admission once, then serializes only that invocation's derived effects. No
entrypoint accepts a supplied candidate, packet or successful verification DTO.

Canonical bytes retain the original reserve interval and all original controls
needed for separate historical completion. Encoded history is not independent
trust enrollment. The packet and its identity are ordinary data: only a fixed
protected issuer/consumer lifecycle can give their custody execution meaning.
This codec adds no database access, clock window, allowance, signature, current
checkpoint admission or retry authority. Its caller must continue the original
live checks after serialization and before any protected database operation.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from serverware import authority_contract as authority
from serverware import authority_current_root_authorization as authorization
from serverware import authority_current_root_execution_admission as pending
from serverware import authority_current_root_vector as vector
from serverware import authority_successor_execution_admission as successor
from serverware import authority_successor_execution_grant as grants
from serverware.authority_query_read_work import MAX_JSON_DEPTH, MAX_JSON_NODES


SCHEMA = "serverware.policyAuthoritySuccessorExecutionPacket/v1"
IDENTITY_DOMAIN = "serverware.policyAuthoritySuccessorExecutionPacketIdentity/v1"
MAX_BYTES = authority.MAX_RESULT_BYTES
MAX_NODES, MAX_DEPTH = MAX_JSON_NODES, MAX_JSON_DEPTH
PACKET_FIELDS = frozenset({"schema", "sourceRevision", "authorizationDigest", "operation",
    "requestDigest", "operationId", "issuedAtEpochNs", "expiresAtEpochNs", "selectedRows",
    "mutations", "workUnits", "result", "beforeVector", "afterVector", "marker", "originals"})
ORIGINAL_FIELDS = frozenset({"currentRootEnrollment", "grantEnrollment", "grant",
    "reserveRequest", "reserveReceipt", "computationSnapshot", "plan"})
_CONTROL_MAXIMA = (
    ("currentRootEnrollment", authorization.MAX_ENROLLMENT_BYTES),
    ("grantEnrollment", grants.MAX_ENROLLMENT_BYTES),
    ("grant", grants.MAX_GRANT_BYTES),
    ("reserveRequest", authorization.MAX_BYTES),
    ("reserveReceipt", pending.MAX_RECEIPT_BYTES),
    ("computationSnapshot", pending.computation.MAX_SNAPSHOT_BYTES),
)


class SuccessorExecutionPacketError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _PreparedCustody:
    """Ordinary same-call output, not a token accepted by an execution API."""

    packet_bytes: bytes
    packet_digest: str
    pending_decision_digest: str
    issued_at_epoch_ns: int
    expires_at_epoch_ns: int


def _raw_frame(raw, maximum, work):
    original = authorization._original(raw, maximum, "successor packet original")
    work.charge(hashes=1, input_bytes=len(original))
    digest = "sha256:" + hashlib.sha256(original).hexdigest()
    # This genuine shared codec reserves the raw/padded/base64/ASCII work before
    # creating the immutable original-byte representation.
    encoded = authorization.transport._encode(original, work)
    return {"base64Url": encoded, "bytesDigest": digest, "byteCount": len(original)}


def _component(value, maximum_bytes, maximum_nodes, work):
    size, nodes = work.measure(value)
    if size > maximum_bytes or nodes > maximum_nodes:
        raise SuccessorExecutionPacketError("successor packet component exceeds its source bound")


def _encode_candidate_on_work(candidate, authorization_digest, plan_originals, controls, work):
    """Private suffix reached only by this invocation's actual admission below."""
    if type(candidate) is not pending._ExecutionCandidate:
        raise SuccessorExecutionPacketError("successor packet requires its same-call actual candidate")
    operation = candidate.operation
    spec = authority.operation_spec(operation)
    if (type(candidate.selected_rows) is not tuple
            or len(candidate.selected_rows) > spec["maximumQueryRows"]
            or type(candidate.mutations) is not tuple
            or len(candidate.mutations) > spec["maximumMutations"]):
        raise SuccessorExecutionPacketError("successor packet effects exceed the actual operation inventory")
    work_units = candidate.work_units
    authorization.shape._integer(work_units, spec["maximumWorkUnits"], minimum=1)
    request_digest, operation_id = candidate.request["requestDigest"], candidate.request["operationId"]
    issued, expires = candidate.original_interval
    before_original, after_original = candidate.before_vector_bytes, candidate.after_vector_bytes
    # All mutable replay outputs are detached before serialization/native hash
    # work. Mutation order and genuine capacity effects remain exactly intact.
    work.prepare_copy(candidate.selected_rows)
    work.prepare_copy(candidate.mutations)
    owned = vector.capture._JSONCapture(vector.capture._SharedLedger(work),
        maximum_bytes=MAX_BYTES).visit({"selectedRows": list(candidate.selected_rows),
            "mutations": list(candidate.mutations), "result": candidate.result,
            "marker": candidate.marker})
    vector._closed(owned["marker"], frozenset(authority.CURRENT_ROOT_COMMIT_MARKER_COLUMNS),
        "successor packet marker")
    for name, expected in (("operation", operation), ("request_digest", request_digest),
            ("operation_id", operation_id)):
        vector.framing._same(owned["marker"][name], expected, work,
            "successor packet marker differs from the actual candidate")
    _component(owned["selectedRows"], authority.MAX_PLAN_SELECTED_BYTES, MAX_NODES, work)
    _component(owned["mutations"], authority.MAX_RESULT_BYTES, MAX_NODES, work)
    _component(owned["result"], authority.MAX_RESULT_BYTES, MAX_NODES, work)
    _component(owned["marker"], 4096, 64, work)
    before = vector._decode_on_work(before_original, work=work)
    after = vector._decode_on_work(after_original, work=work)
    originals = {name: _raw_frame(raw, maximum, work)
        for (name, maximum), raw in zip(_CONTROL_MAXIMA, controls)}
    # The actual family replay already checked each plan frame's own source
    # cap and the fixed raw2/raw3/raw4 order, not just this aggregate ceiling.
    originals["plan"] = [_raw_frame(raw, pending.replay.MAX_ORIGINAL_BYTES, work)
        for raw in plan_originals]
    vector._closed(originals, ORIGINAL_FIELDS, "successor packet original inventory")
    packet = {"schema": SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
        "authorizationDigest": authorization_digest, "operation": operation,
        "requestDigest": request_digest, "operationId": operation_id,
        "issuedAtEpochNs": issued, "expiresAtEpochNs": expires,
        "selectedRows": owned["selectedRows"], "mutations": owned["mutations"],
        "workUnits": work_units, "result": owned["result"],
        "beforeVector": before, "afterVector": after, "marker": owned["marker"],
        "originals": originals}
    vector._closed(packet, PACKET_FIELDS, "successor execution packet")
    # The real encoder measures/charges ASCII canonical bytes and every node
    # under the original work's depth ceiling before allocating output. The
    # whole packet (including base64 originals) has the existing 64 MiB cap;
    # individual caps never promise it will fit the remaining shared allowance.
    encoded = vector.encoding._bounded_wire(packet, vector.capture._SharedLedger(work),
        maximum_bytes=MAX_BYTES, maximum_nodes=MAX_NODES)
    identity = vector.framing._frame(IDENTITY_DOMAIN, (encoded,), work)
    return _PreparedCustody(encoded, identity, owned["marker"]["pending_decision_digest"], issued, expires)


def _prepare_on_work(*, operation, originals, expectations, planner_public_key,
        operation_public_key, enrollment_bytes, root_public_key,
        reserve_request_bytes, reserve_receipt_bytes, snapshot_bytes,
        grant_bytes, grant_enrollment_bytes, expected_authorization_digest,
        expected_database_id, expected_generation_digest, expected_pending_sequence,
        expected_pending_head_digest, expected_fence, live_window, work,
        transport_deadline_ns=None, activation_custody=None):
    """Admit genuine originals once, then encode their closed custody packet."""
    vector.capture._SharedLedger(work)
    held_custody = activation_custody
    if type(operation) is str and operation == pending.replay.ACTIVATION_OPERATION:
        authorization.shape._integer(transport_deadline_ns, minimum=1)
    held = pending._originals(operation, originals, enrollment_bytes,
        reserve_request_bytes, reserve_receipt_bytes, snapshot_bytes)
    plan_originals, enrollment, reserve, receipt, snapshot = held
    grant = authorization._original(grant_bytes, grants.MAX_GRANT_BYTES, "execution packet grant")
    grant_enrollment = authorization._original(grant_enrollment_bytes,
        grants.MAX_ENROLLMENT_BYTES, "execution packet grant enrollment")
    controls = (enrollment, grant_enrollment, grant, reserve, receipt, snapshot)
    if sum(len(raw) for raw in (*plan_originals, *controls)) > MAX_BYTES:
        raise SuccessorExecutionPacketError("successor packet originals exceed the aggregate source bound")
    held_operation, held_authorization = operation, expected_authorization_digest
    authorization.shape._digest(held_authorization)
    root_key, planner_key, operation_key = root_public_key, planner_public_key, operation_public_key
    authorization._public(root_key)
    scope = pending._scope(expected_database_id=expected_database_id,
        expected_generation_digest=expected_generation_digest,
        expected_pending_sequence=expected_pending_sequence,
        expected_pending_head_digest=expected_pending_head_digest, expected_fence=expected_fence,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns)
    # Own independent history and every original/scope before the first native
    # clock/key callback in actual admission. No returned plan supplies history.
    expected = pending.replay._expectations(held_operation, expectations,
        planner_key, operation_key, work)
    candidate = successor._admit_on_work(operation=held_operation, originals=plan_originals,
        expectations=expected, planner_public_key=planner_key, operation_public_key=operation_key,
        enrollment_bytes=enrollment, root_public_key=root_key, reserve_request_bytes=reserve,
        reserve_receipt_bytes=receipt, snapshot_bytes=snapshot, grant_bytes=grant,
        grant_enrollment_bytes=grant_enrollment, expected_authorization_digest=held_authorization,
        expected_database_id=scope[0], expected_generation_digest=scope[1],
        expected_pending_sequence=scope[2], expected_pending_head_digest=scope[3],
        expected_fence=scope[4], live_window=scope[5], transport_deadline_ns=scope[6], work=work,
        activation_custody=held_custody)
    return _encode_candidate_on_work(candidate, held_authorization, plan_originals, controls, work)
