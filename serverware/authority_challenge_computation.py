"""Maintenance raw replay into an original-interval current-root reserve.

The caller independently admits the planner/current roots and maintenance
grant. The latter's digest is only a scope commitment here, not grant proof.
This producer authenticates the actual parent and replays every raw page once,
then uses the real enrolled computation signer and reserve-control producer.
It accepts no successful replay DTO and reserves/executes nothing itself.

No clock opening, connection, retry, generic replay widening or new allowance
occurs here. The exact parent interval is preserved; the retained receiver
window and original context deadline only narrow actual processing time.
"""
from __future__ import annotations

import hashlib
import time

from serverware import authority_challenge_current_root as current_root
from serverware import authority_current_root_computation as computation


authorization, vector = computation.authorization, computation.vector
evidence, clock = computation.evidence, computation.clock
plan = current_root.plan
OPERATION = "webauthn.challenge.maintain"
ORIGINAL_RECORD_DOMAIN = "serverware.policyAuthorityChallengeMaintenanceOriginalRecord/v1"
RESULT_DOMAIN = "serverware.policyAuthorityControlledWriterResult/v2"
FRAME_MAXIMA = (plan.MAX_PARENT_BYTES, plan.requests.MAX_REQUEST_BYTES, plan.manifests.MAX_MANIFEST_BYTES)


class ChallengeComputationError(ValueError):
    pass


def _require(value):
    if not value:
        raise ChallengeComputationError("maintenance computation differs from its original replay and scope")


def _originals(originals):
    _require(type(originals) is tuple and len(originals) == 3)
    for raw, maximum in zip(originals, FRAME_MAXIMA, strict=True):
        authorization._original(raw, maximum, "maintenance computation original")
    _require(sum(map(len, originals)) <= computation.authority.MAX_RESULT_BYTES)
    return originals


def _same_bytes(left, right, work):
    _require(type(left) is bytes and type(right) is bytes)
    work.charge(input_bytes=len(left) + len(right))
    _require(left == right)


def _snapshot_on_work(*, observed, originals, expected, material, capability_digest, work):
    """Private graph suffix after this invocation's actual complete replay.

    C's execution composition may share this suffix only after its own genuine
    raw replay. Neither this graph nor an observation is an authority input to
    the public producer. The record digest commits all ordered raw3 bytes, not
    a manifest alias, and legacy signed-capability/snapshot fields stay null.
    """
    evidence.capture._SharedLedger(work)
    _require(type(observed) is current_root.MaintenanceVectorObservation
        and type(observed.replay) is plan.VerifiedMaintenancePlan
        and type(material) is authorization._EnrollmentMaterial)
    originals = _originals(originals)
    authorization.shape._digest(capability_digest)
    selected = plan._expectations(expected, work)
    authorization.shape._literal(selected["context"]["operation"], OPERATION)
    request = plan._request(originals[1], selected["context"], work)
    for raw, retained in zip(originals, (observed.replay.envelope_bytes,
            observed.replay.request_bytes, observed.replay.manifest_bytes), strict=True):
        _same_bytes(raw, retained, work)
    plan._same(observed.plan_digest, evidence.plan._frame(plan.IDENTITY_DOMAIN, (originals[0],), work), work)
    plan._same(observed.manifest_digest, evidence.plan._frame(plan.MANIFEST_DOMAIN, (originals[2],), work), work)
    frames = []
    for position, raw in enumerate(originals):
        work.charge(hashes=1, input_bytes=len(raw))
        frames.append({"position": position, "bytesDigest": "sha256:" + hashlib.sha256(raw).hexdigest(),
            "byteCount": len(raw)})
    snapshot = {"schema": computation.SNAPSHOT_SCHEMA, "sourceRevision": computation.authority.SOURCE_REVISION,
        "enrollmentDigest": material.enrollment_digest,
        "databaseId": material.payload["databaseId"], "generationDigest": material.payload["generationDigest"],
        "producerMeasurementDigest": material.payload["computation"]["measurementDigest"],
        "operation": OPERATION, "requestDigest": request["requestDigest"], "operationId": request["operationId"],
        "capabilityDigest": capability_digest,
        "retainedRecordDigest": evidence.plan._frame(ORIGINAL_RECORD_DOMAIN, originals, work),
        "planDigest": observed.plan_digest, "beforeVectorDigest": observed.before_vector_digest,
        "afterVectorDigest": observed.after_vector_digest,
        "resultDigest": evidence.plan._json_digest(RESULT_DOMAIN, observed.result,
            evidence.capture._SharedLedger(work)), "originalFrames": frames,
        "originalIssuedAtEpochNs": observed.original_interval[0],
        "originalExpiresAtEpochNs": observed.original_interval[1],
        "signedSnapshotDigest": None, "signedCapabilityId": None}
    computation._snapshot_shape(snapshot)
    return snapshot


class _Live:
    """Invocation-local native checks, never a returned liveness verdict."""

    def __init__(self, window, deadline, interval):
        self.window = clock._validate(window)
        authorization.shape._integer(deadline, minimum=1)
        _require(type(interval) is tuple and len(interval) == 2)
        self.bound = min(self.window[4], deadline)
        self.interval = {"issuedAtEpochNs": interval[0], "expiresAtEpochNs": interval[1]}
        authorization._interval(self.interval, computation.authority.VERIFIER_RESPONSE_MAX_AGE_NS)
        self.policy = None
        self.last_epoch, self.last_monotonic = self.window[0], self.window[2]

    def enroll(self, policy):
        self.policy = (policy["maxControlAgeNs"], policy["maxClockSkewNs"])
        authorization._interval(self.interval, self.policy[0])
        self.window = computation.execution_window._narrow(self.window,
            deadline_epoch_ns=self.window[3], maximum_lifetime_ns=self.policy[0],
            maximum_clock_skew_ns=self.policy[1])
        self.bound = min(self.bound, self.window[4])

    def sample(self, work):
        now = clock._check_on_work(self.window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        authorization.shape._integer(monotonic, minimum=1)
        _require(self.last_epoch <= now and self.last_monotonic <= monotonic < self.bound)
        if self.policy is not None:
            evidence._fresh(self.interval, now, *self.policy)
        self.last_epoch, self.last_monotonic = now, monotonic
        return now


def produce_reserve(*, originals, expectations, planner_public_key, before_vector_bytes,
        enrollment_bytes, root_public_key, computation_private_key, capability_digest,
        predecessor_sequence, predecessor_head_digest, fence, live_window, read_original, check, work):
    """Produce actual signed reserve/snapshot bytes after one genuine raw replay."""
    evidence.capture._SharedLedger(work)
    originals = _originals(originals)
    before_raw = authorization._original(before_vector_bytes, vector.MAX_BYTES, "complete before vector")
    enrollment_raw = authorization._original(enrollment_bytes, authorization.MAX_ENROLLMENT_BYTES,
        "current-root enrollment")
    authorization._public(root_public_key)
    authorization._public(planner_public_key)
    authorization._private(computation_private_key)
    _require(callable(read_original) and callable(check))
    shape = authorization.shape
    shape._digest(capability_digest)
    shape._digest(predecessor_head_digest)
    shape._integer(predecessor_sequence, authorization.MAX_RECORDS)
    shape._integer(fence, minimum=1)
    scope = capability_digest, predecessor_sequence, predecessor_head_digest, fence
    expected = plan._expectations(expectations, work)
    shape._literal(expected["context"]["operation"], OPERATION)
    plan._request(originals[1], expected["context"], work)
    # This early untrusted interval can only constrain processing. Signature
    # and full semantic admission occur in the genuine replay below.
    parent = evidence.wire._decode_object(originals[0], work=work,
        maximum_bytes=plan.MAX_PARENT_BYTES, maximum_nodes=plan.MAX_PARENT_NODES,
        maximum_depth=plan.MAX_PARENT_DEPTH)
    shape._object(parent, frozenset({"schema", "payload", "signatureBase64Url"}), "maintenance parent")
    shape._literal(parent["schema"], plan.ENVELOPE_SCHEMA)
    plan._payload_shape(parent["payload"])
    interval = parent["payload"]["issuedAtEpochNs"], parent["payload"]["expiresAtEpochNs"]
    live = _Live(live_window, expected["context"]["originalDeadlineNs"], interval)
    live.sample(work)
    material = authorization._admit_enrollment_on_work(enrollment_bytes=enrollment_raw,
        root_public_key=root_public_key, work=work)
    # Fail before expensive replay if the protected signer is not the actual
    # root-enrolled computation key. The producer repeats this join at signing.
    evidence.keys._pair_on_work(computation_private_key, material.computation_public_key, work)
    live.enroll(material.payload)
    live.sample(work)

    def checked(stage):
        _require(type(stage) is current_root.compound._Stage)
        stage.check()
        live.sample(stage.work)
        _require(check(stage) is None)
        stage.check()
        live.sample(stage.work)

    observed = current_root.replay_to_complete_vector(envelope_bytes=originals[0],
        request_bytes=originals[1], manifest_bytes=originals[2], expectations=expected,
        planner_public_key=planner_public_key, before_vector_bytes=before_raw,
        read_original=read_original, check=checked, work=work)
    live.sample(work)
    _require(type(observed) is current_root.MaintenanceVectorObservation)
    plan._same(observed.original_interval, interval, work)
    snapshot = _snapshot_on_work(observed=observed, originals=originals, expected=expected,
        material=material, capability_digest=scope[0], work=work)
    snapshot_bytes = computation._snapshot_wire(snapshot, work)
    snapshot_digest = computation._snapshot_digest_on_work(snapshot_bytes, work=work)
    before = vector._decode_on_work(observed.before_vector_bytes, work=work)
    after = vector._decode_on_work(observed.after_vector_bytes, work=work)
    payload = {"schema": authorization.REQUEST_PAYLOAD_SCHEMA,
        **{name: snapshot[name] for name in ("sourceRevision", "enrollmentDigest", "databaseId",
            "generationDigest", "producerMeasurementDigest", "operation", "requestDigest", "operationId",
            "capabilityDigest")}, "action": "reserve", "snapshotDigest": snapshot_digest,
        "predecessorSequence": scope[1], "predecessorHeadDigest": scope[2], "fence": scope[3],
        "beforeVector": before, "afterVector": after,
        "issuedAtEpochNs": interval[0], "expiresAtEpochNs": interval[1]}
    request_bytes = authorization._produce_request_on_work(payload=payload,
        enrollment_bytes=enrollment_raw, root_public_key=root_public_key,
        producer_private_key=computation_private_key, now_epoch_ns=live.sample(work), work=work)
    live.sample(work)
    return computation.CurrentRootComputation(request_bytes, snapshot_bytes)
