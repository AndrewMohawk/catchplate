"""Consume-only computation originals, derived from genuine same-call replay.

The private signing suffix is called only by original-based reservation below;
no successful replay carrier is an accepted public authority input. The distinct
snapshot does not widen the generic computation or execution inventories.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from serverware import authority_contract as authority
from serverware import authority_current_root_authorization as authorization
from serverware import authority_current_root_vector as vector
from serverware import authority_oidc_session_activation_delivery_execution_grant as grant
from serverware import authority_request_commitment as commitment
from serverware import authority_successor_execution_window as windows


OPERATION = "oidc.session.activation-delivery.consume"
SNAPSHOT_SCHEMA = "serverware.oidcSessionActivationDeliveryComputationSnapshot/v1"
SNAPSHOT_DOMAIN = "serverware.oidcSessionActivationDeliveryComputationSnapshotIdentity/v1"
MAX_SNAPSHOT_BYTES, MAX_SNAPSHOT_NODES = 16 * 1024, 512
_FIELDS = frozenset({"schema", "sourceRevision", "enrollmentDigest", "databaseId",
    "generationDigest", "producerMeasurementDigest", "operation", "requestDigest",
    "operationId", "capabilityDigest", "retainedRecordDigest", "planDigest",
    "beforeVectorDigest", "afterVectorDigest", "resultDigest", "originalFrames",
    "originalIssuedAtEpochNs", "originalExpiresAtEpochNs"})
_DIGEST_FIELDS = ("enrollmentDigest", "generationDigest", "producerMeasurementDigest",
    "requestDigest", "operationId", "capabilityDigest", "retainedRecordDigest",
    "planDigest", "beforeVectorDigest", "afterVectorDigest", "resultDigest")
_FRAME_FIELDS = frozenset({"position", "bytesDigest", "byteCount"})


class DeliveryComputationError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class DeliveryComputation:
    request_bytes: bytes
    snapshot_bytes: bytes


def _snapshot_shape(document):
    shape = authorization.shape
    shape._object(document, _FIELDS, "consume computation snapshot")
    shape._literal(document["schema"], SNAPSHOT_SCHEMA)
    shape._literal(document["sourceRevision"], authority.SOURCE_REVISION)
    shape._literal(document["operation"], OPERATION)
    authorization._token(document["databaseId"])
    for name in _DIGEST_FIELDS:
        shape._digest(document[name])
    issued, expires = document["originalIssuedAtEpochNs"], document["originalExpiresAtEpochNs"]
    shape._integer(issued, minimum=1)
    shape._integer(expires, minimum=1)
    if expires <= issued:
        raise DeliveryComputationError("consume computation original interval is empty")
    frames = document["originalFrames"]
    if type(frames) is not list or len(frames) != 2:
        raise DeliveryComputationError("consume computation requires exact plan/ciphertext raw2")
    total = 0
    for position, (frame, maximum) in enumerate(zip(frames, grant.FRAME_MAXIMA)):
        shape._object(frame, _FRAME_FIELDS, "consume computation original")
        shape._integer(frame["position"], 1)
        if frame["position"] != position:
            raise DeliveryComputationError("consume computation original order differs")
        shape._digest(frame["bytesDigest"])
        shape._integer(frame["byteCount"], maximum, minimum=2)
        total += frame["byteCount"]
    if total > authority.MAX_RESULT_BYTES:
        raise DeliveryComputationError("consume computation original aggregate exceeds source bound")


def _snapshot_wire(document, work):
    _snapshot_shape(document)
    return vector.encoding._bounded_wire(document, vector.capture._SharedLedger(work),
        maximum_bytes=MAX_SNAPSHOT_BYTES, maximum_nodes=MAX_SNAPSHOT_NODES)


def _decode_snapshot_on_work(snapshot_bytes, *, work):
    original = authorization._original(snapshot_bytes, MAX_SNAPSHOT_BYTES, "consume computation snapshot")
    document = vector.wire._decode_object(original, work=work,
        maximum_bytes=MAX_SNAPSHOT_BYTES, maximum_nodes=MAX_SNAPSHOT_NODES, maximum_depth=4)
    canonical = _snapshot_wire(document, work)
    work.charge(input_bytes=len(original) + len(canonical))
    if original != canonical:
        raise DeliveryComputationError("consume computation snapshot is not canonical")
    return document


def _snapshot_digest_on_work(snapshot_bytes, *, work):
    _decode_snapshot_on_work(snapshot_bytes, work=work)
    return authorization.plan._frame(SNAPSHOT_DOMAIN, (snapshot_bytes,), work)


def _snapshot(replayed, material, grant_digest, work):
    """Neutral projection of this call's actual consume replay, not admission."""
    if replayed.operation != OPERATION:
        raise DeliveryComputationError("consume computation cannot project another operation")
    request_digest = commitment._typed_request_digest(replayed.request, work=work)
    authorization.plan._same(request_digest, replayed.request["requestDigest"], work,
        "consume computation actual request commitment")
    frames = []
    for position, raw in enumerate(replayed.originals):
        work.charge(hashes=1, input_bytes=len(raw))
        frames.append({"position": position, "bytesDigest": "sha256:" + hashlib.sha256(raw).hexdigest(),
            "byteCount": len(raw)})
    result_digest = authorization.plan._json_digest("serverware.policyAuthorityControlledWriterResult/v2",
        replayed.result, authorization.capture._SharedLedger(work))
    return {"schema": SNAPSHOT_SCHEMA, "sourceRevision": authority.SOURCE_REVISION,
        "enrollmentDigest": material.enrollment_digest,
        "databaseId": material.payload["databaseId"], "generationDigest": material.payload["generationDigest"],
        "producerMeasurementDigest": material.payload["computation"]["measurementDigest"],
        "operation": OPERATION, "requestDigest": request_digest,
        "operationId": replayed.request["operationId"], "capabilityDigest": grant_digest,
        "retainedRecordDigest": replayed.retained_record_digest, "planDigest": replayed.plan_digest,
        "beforeVectorDigest": replayed.before_vector_digest, "afterVectorDigest": replayed.after_vector_digest,
        "resultDigest": result_digest, "originalFrames": frames,
        "originalIssuedAtEpochNs": replayed.original_interval[0],
        "originalExpiresAtEpochNs": replayed.original_interval[1]}


def _sign_replayed_on_work(*, replayed, verified, enrollment_bytes, root_public_key,
        computation_private_key, predecessor_sequence, predecessor_head_digest, fence, work):
    """Private continuation of reservation's actual original grant verification."""
    held_enrollment = authorization._original(enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "consume computation enrollment")
    root, signer = root_public_key, computation_private_key
    authorization._public(root)
    authorization._private(signer)
    authorization.shape._integer(predecessor_sequence, authorization.MAX_RECORDS - 2)
    authorization.shape._digest(predecessor_head_digest)
    authorization.shape._integer(fence, minimum=1)
    verified.live()
    material = authorization._admit_enrollment_on_work(enrollment_bytes=held_enrollment,
        root_public_key=root, work=work)
    verified.live()
    authorization.plan._same(material.enrollment_digest, verified.payload["currentRootEnrollmentDigest"],
        work, "consume reserve actual grant/root enrollment")
    policy = material.payload
    if predecessor_sequence + 2 > policy["maxRecords"]:
        raise DeliveryComputationError("consume reserve leaves no enrolled completion capacity")
    issued, original_expiry = replayed.original_interval
    authorization.plan._same(issued, verified.payload["issuedAtEpochNs"], work,
        "consume reserve cannot retime original grant issuance")
    ceiling = min(verified.valid_until_epoch_ns, original_expiry,
        issued + policy["maxControlAgeNs"])
    window = windows._narrow(verified.window, deadline_epoch_ns=ceiling,
        maximum_lifetime_ns=policy["maxControlAgeNs"], maximum_clock_skew_ns=policy["maxClockSkewNs"])
    bound = min(verified.deadline_ns, window[4])
    interval = {"issuedAtEpochNs": issued, "expiresAtEpochNs": window[3]}

    def live():
        first = verified.live()
        now = windows.clock._check_on_work(window, work=work)
        last = verified.live()
        if not first[0] <= now <= last[0] or first[1] > last[1] or last[1] >= bound:
            raise DeliveryComputationError("consume computation original allowance expired or reversed")
        authorization._fresh(interval, material, last[0])
        return last[0]

    live()
    snapshot = _snapshot(replayed, material, verified.grant_digest, work)
    snapshot_bytes = _snapshot_wire(snapshot, work)
    snapshot_digest = authorization.plan._frame(SNAPSHOT_DOMAIN, (snapshot_bytes,), work)
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
        enrollment_bytes=held_enrollment, root_public_key=root,
        producer_private_key=signer, now_epoch_ns=live(), work=work)
    live()
    return DeliveryComputation(request_bytes, snapshot_bytes)
