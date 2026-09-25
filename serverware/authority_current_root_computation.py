"""Genuine plan replay into a purpose-specific current-root reserve control.

This producer verifies the original plan family itself; no replay/result carrier
is accepted. Its new computation snapshot commits exact plan originals, actual
kernel result and complete before/after vectors without exporting selected rows.
It is NOT the existing revocation Snapshot/v4 or an execution capability.

The caller must independently admit planner/operation/root keys and historical
expectations. The capability digest is a scope commitment, not proof of original
capability admission. Existing signed revocation capability ID and snapshot are
preserved distinctly. The eventual executor still needs actual capability and
pending-decision admission, maintained SQL effects and postcommit assurance.

The enrolled computation key signs only after genuine replay. The root decision
owner must separately join the exact predecessor and full current vector. No
SQL, transport, retry, currentness service or replacement work is provided.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import time

from serverware import authority_contract as authority
from serverware import authority_current_root_authorization as authorization
from serverware import authority_current_root_plan_replay as replay
from serverware import authority_current_root_vector as vector
from serverware import authority_request_commitment as commitment
from serverware import authority_webauthn_evidence as evidence
from serverware import authority_webauthn_evidence_plan_clock as clock


SNAPSHOT_SCHEMA = "serverware.policyAuthorityCurrentRootComputationSnapshot/v1"
SNAPSHOT_DOMAIN = "serverware.policyAuthorityCurrentRootComputationSnapshotIdentity/v1"
MAX_SNAPSHOT_BYTES, MAX_SNAPSHOT_NODES = 16 * 1024, 512
_SNAPSHOT_FIELDS = frozenset({"schema", "sourceRevision", "enrollmentDigest",
    "databaseId", "generationDigest", "producerMeasurementDigest", "operation",
    "requestDigest", "operationId", "capabilityDigest", "retainedRecordDigest",
    "planDigest", "beforeVectorDigest", "afterVectorDigest", "resultDigest",
    "originalFrames", "originalIssuedAtEpochNs", "originalExpiresAtEpochNs",
    "signedSnapshotDigest", "signedCapabilityId"})
_DIGEST_FIELDS = ("enrollmentDigest", "generationDigest", "producerMeasurementDigest",
    "requestDigest", "operationId", "capabilityDigest", "retainedRecordDigest",
    "planDigest", "beforeVectorDigest", "afterVectorDigest", "resultDigest")
_FRAME_FIELDS = frozenset({"position", "bytesDigest", "byteCount"})


class CurrentRootComputationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class CurrentRootComputation:
    """Original output bytes only, not an accepted proof or execution token."""

    request_bytes: bytes
    snapshot_bytes: bytes


def _snapshot_shape(document):
    shape = authorization.shape
    shape._object(document, _SNAPSHOT_FIELDS, "current-root computation snapshot")
    shape._literal(document["schema"], SNAPSHOT_SCHEMA)
    shape._literal(document["sourceRevision"], authority.SOURCE_REVISION)
    authorization._token(document["databaseId"])
    authorization.delta._source(document["operation"])
    for name in _DIGEST_FIELDS:
        shape._digest(document[name])
    issued, expires = document["originalIssuedAtEpochNs"], document["originalExpiresAtEpochNs"]
    shape._integer(issued, minimum=1)
    shape._integer(expires, minimum=1)
    if expires <= issued:
        raise CurrentRootComputationError("computation snapshot original interval is empty")
    revocation = document["operation"] == replay.REVOCATION_OPERATION
    for name in ("signedSnapshotDigest", "signedCapabilityId"):
        if revocation:
            shape._digest(document[name])
        elif document[name] is not None:
            raise CurrentRootComputationError("computation snapshot invented another plan family's authority")
    expected_count = 2 if revocation else 3 if document["operation"] in replay.EVIDENCE_OPERATIONS else 4
    frames = document["originalFrames"]
    if type(frames) is not list or len(frames) != expected_count:
        raise CurrentRootComputationError("computation snapshot original inventory differs from its plan family")
    for position, frame in enumerate(frames):
        shape._object(frame, _FRAME_FIELDS, "computation snapshot original")
        shape._integer(frame["position"], expected_count - 1)
        if frame["position"] != position:
            raise CurrentRootComputationError("computation snapshot original order differs")
        shape._digest(frame["bytesDigest"])
        shape._integer(frame["byteCount"], authority.MAX_RESULT_BYTES, minimum=2)


def _snapshot_wire(document, work):
    _snapshot_shape(document)
    return vector.encoding._bounded_wire(document, vector.capture._SharedLedger(work),
        maximum_bytes=MAX_SNAPSHOT_BYTES, maximum_nodes=MAX_SNAPSHOT_NODES)


def _decode_snapshot_on_work(snapshot_bytes, *, work):
    """Decode canonical computation data; signature/currentness are separate."""
    authorization._original(snapshot_bytes, MAX_SNAPSHOT_BYTES, "computation snapshot")
    document = vector.wire._decode_object(snapshot_bytes, work=work,
        maximum_bytes=MAX_SNAPSHOT_BYTES, maximum_nodes=MAX_SNAPSHOT_NODES, maximum_depth=4)
    canonical = _snapshot_wire(document, work)
    work.charge(input_bytes=len(snapshot_bytes) + len(canonical))
    if snapshot_bytes != canonical:
        raise CurrentRootComputationError("computation snapshot is not canonical")
    return document


def _snapshot_digest_on_work(snapshot_bytes, *, work):
    _decode_snapshot_on_work(snapshot_bytes, work=work)
    return evidence.plan._frame(SNAPSHOT_DOMAIN, (snapshot_bytes,), work)


def _snapshot(replayed, material, capability_digest, work):
    # Only the result of this invocation's actual original replay reaches here.
    request_digest = commitment._typed_request_digest(replayed.request, work=work)
    evidence.plan._same(request_digest, replayed.request["requestDigest"], work,
        "computation request differs from its actual typed commitment")
    frames = []
    for position, raw in enumerate(replayed.originals):
        work.charge(hashes=1, input_bytes=len(raw))
        frames.append({"position": position, "bytesDigest": "sha256:" + hashlib.sha256(raw).hexdigest(),
            "byteCount": len(raw)})
    result_digest = evidence.plan._json_digest("serverware.policyAuthorityControlledWriterResult/v2",
        replayed.result, evidence.capture._SharedLedger(work))
    return {"schema": SNAPSHOT_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
        "enrollmentDigest": material.enrollment_digest,
        "databaseId": material.payload["databaseId"], "generationDigest": material.payload["generationDigest"],
        "producerMeasurementDigest": material.payload["computation"]["measurementDigest"],
        "operation": replayed.operation, "requestDigest": request_digest,
        "operationId": replayed.request["operationId"], "capabilityDigest": capability_digest,
        "retainedRecordDigest": replayed.retained_record_digest, "planDigest": replayed.plan_digest,
        "beforeVectorDigest": replayed.before_vector_digest, "afterVectorDigest": replayed.after_vector_digest,
        "resultDigest": result_digest, "originalFrames": frames,
        "originalIssuedAtEpochNs": replayed.original_interval[0],
        "originalExpiresAtEpochNs": replayed.original_interval[1],
        "signedSnapshotDigest": replayed.signed_snapshot_digest,
        "signedCapabilityId": replayed.signed_capability_id}


def _produce_reserve_on_work(*, operation, originals, expectations, planner_public_key,
        operation_public_key, before_vector_bytes, enrollment_bytes, root_public_key,
        computation_private_key, capability_digest, predecessor_sequence,
        predecessor_head_digest, fence, deadline_epoch_ns, work, transport_deadline_ns=None):
    """Replay genuine originals and sign one nonrenewing reserve control.

    A fresh request requires live original history. No new control can extend
    the original signed interval, supplied absolute deadline or inherited local
    monotonic deadline. This function neither reserves nor executes anything.
    """
    evidence.capture._SharedLedger(work)
    # Hold immutable scope and actual keys before any replay/clock/key callback.
    held_enrollment = authorization._original(enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "current-root enrollment")
    held_root, held_signer = root_public_key, computation_private_key
    authorization._public(held_root)
    authorization._private(held_signer)
    shape = authorization.shape
    shape._digest(capability_digest)
    shape._digest(predecessor_head_digest)
    shape._integer(predecessor_sequence, authorization.MAX_RECORDS)
    shape._integer(fence, minimum=1)
    shape._integer(deadline_epoch_ns, minimum=1)
    if transport_deadline_ns is not None:
        shape._integer(transport_deadline_ns, minimum=1)
    held_scope = (capability_digest, predecessor_sequence, predecessor_head_digest,
        fence, deadline_epoch_ns, transport_deadline_ns)
    # This actual family verifier owns all mutable expectations before its first
    # callback. Enrollment callbacks therefore cannot substitute plan history.
    replayed = replay._replay_on_work(operation=operation, originals=originals,
        expectations=expectations, planner_public_key=planner_public_key,
        operation_public_key=operation_public_key, before_vector_bytes=before_vector_bytes, work=work)
    material = authorization._admit_enrollment_on_work(enrollment_bytes=held_enrollment,
        root_public_key=held_root, work=work)
    policy = material.payload
    capability_digest, predecessor_sequence, predecessor_head_digest, fence, deadline, inherited = held_scope
    issued, original_expires = replayed.original_interval
    window = clock._open_on_work(deadline_epoch_ns=min(deadline, original_expires,
        issued + policy["maxControlAgeNs"]), maximum_lifetime_ns=policy["maxControlAgeNs"],
        maximum_clock_skew_ns=policy["maxClockSkewNs"], work=work)
    expires = window[3]
    bound = window[4] if inherited is None else min(window[4], inherited)
    interval = {"issuedAtEpochNs": issued, "expiresAtEpochNs": expires}

    def live():
        now = clock._check_on_work(window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        if monotonic >= bound:
            raise CurrentRootComputationError("computation reserve inherited deadline expired")
        evidence._fresh(interval, now, policy["maxControlAgeNs"], policy["maxClockSkewNs"])
        return now

    live()
    snapshot = _snapshot(replayed, material, capability_digest, work)
    snapshot_bytes = _snapshot_wire(snapshot, work)
    snapshot_digest = _snapshot_digest_on_work(snapshot_bytes, work=work)
    before = vector._decode_on_work(replayed.before_vector_bytes, work=work)
    after = vector._decode_on_work(replayed.after_vector_bytes, work=work)
    payload = {"schema": authorization.REQUEST_PAYLOAD_SCHEMA,
        **{name: snapshot[name] for name in ("sourceRevision", "enrollmentDigest", "databaseId",
            "generationDigest", "producerMeasurementDigest", "operation", "requestDigest", "operationId",
            "capabilityDigest")},
        "action": "reserve", "snapshotDigest": snapshot_digest,
        "predecessorSequence": predecessor_sequence, "predecessorHeadDigest": predecessor_head_digest,
        "fence": fence, "beforeVector": before, "afterVector": after, **interval}
    request_bytes = authorization._produce_request_on_work(payload=payload,
        enrollment_bytes=held_enrollment, root_public_key=held_root,
        producer_private_key=held_signer, now_epoch_ns=live(), work=work)
    live()
    return CurrentRootComputation(request_bytes, snapshot_bytes)
