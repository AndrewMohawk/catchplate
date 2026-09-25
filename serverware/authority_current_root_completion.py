"""Actual read-only postcommit observation into an enrolled completion control.

Every original reserve, state receipt, plan and pre-decision execution grant is
authenticated here. Historical verification does not revive expired execution
authority: the only database operation is a fixed read-only marker/full-root
observation. Its exact current pending checkpoint and original request-policy
authorization must be admitted independently, never copied from a response.

The genuine configured reader closes its physical connection normally before
the observation is joined to the same-call replay. Only then can the enrolled
completion key sign a fresh complete control containing the canonical observed
marker record. The inner record is not independently signed proof; the actual
complete-control signature covers its exact original bytes and purpose.

No supplied candidate, successful observation, caller SQL/opener, publisher,
new allowance or mutation is accepted. Missing/ambiguous markers, changed roots
and timeout fail without releasing a pending fence or authorizing re-execution.
Database authenticity, cold key custody/measurement and currentness remain
independent prerequisites; a matching restored database is not antirollback
proof. Delivery to the durable state owner is still a separate operation.

The retained-custody entrypoint decodes original packet bytes, authenticates
all original controls and replays the plan once against independent history
and scope. Stored effects are compared by their genuine same-call digest and
never returned as executable data. Its caller's existing retrieval window is
retained through observation/signing; no new completion window is opened.
"""
from __future__ import annotations

import hashlib
import time

from serverware import authority_current_root_authorization as authorization
from serverware import authority_current_root_commit_reader as reader
from serverware import authority_current_root_computation as computation
from serverware import authority_current_root_execution_admission as pending
from serverware import authority_current_root_vector as vector
from serverware import authority_successor_execution_admission as execution
from serverware import authority_successor_execution_grant as grants
from serverware import authority_webauthn_evidence as evidence
from serverware import authority_webauthn_evidence_plan_clock as clock


OBSERVATION_SCHEMA = "serverware.policyAuthorityCurrentRootCommitObservation/v1"
MAX_OBSERVATION_BYTES, MAX_OBSERVATION_NODES = 16 * 1024, 256


class CurrentRootCompletionError(ValueError):
    pass


def _observation_bytes(marker, after_digest, observed_at, work):
    """Encode only this invocation's real matched observation, not a proof API."""
    document = {"schema": OBSERVATION_SCHEMA,
        "sourceRevision": authorization.authority.SOURCE_REVISION, "marker": marker,
        "afterVectorDigest": after_digest, "observedAtEpochNs": observed_at}
    return vector.encoding._bounded_wire(document, evidence.capture._SharedLedger(work),
        maximum_bytes=MAX_OBSERVATION_BYTES, maximum_nodes=MAX_OBSERVATION_NODES)


def _verify_grant_on_work(*, candidate, grant_raw, grant_enrollment, enrollment,
        root_public_key, planner_public_key, operation_public_key, authorization_digest, work):
    """Private join to this call's real historical pending replay, never a token API."""
    grant, grant_digest = grants._verify_historical_control_on_work(grant_bytes=grant_raw,
        grant_enrollment_bytes=grant_enrollment, current_root_enrollment_bytes=enrollment,
        root_public_key=root_public_key, planner_public_key=planner_public_key,
        operation_public_key=operation_public_key,
        expected_authorization_digest=authorization_digest, work=work)
    snapshot = computation._decode_snapshot_on_work(candidate.snapshot_bytes, work=work)
    evidence.plan._same(grant_digest, candidate.marker["capability_digest"], work,
        "completion pending capability differs from the original grant")
    evidence.plan._same(grant["currentRootEnrollmentDigest"], snapshot["enrollmentDigest"], work,
        "completion grant enrollment differs from genuine computation")
    for field in execution._SNAPSHOT_JOINS:
        evidence.plan._same(grant[field], snapshot[field], work,
            "completion grant differs from genuine computation " + field)
    if (candidate.original_interval[0] != grant["issuedAtEpochNs"]
            or candidate.original_interval[1] > grant["expiresAtEpochNs"]):
        raise CurrentRootCompletionError("completion reserve retimed or extended original execution authority")


def _read_and_sign_on_work(*, candidate, configuration, enrollment, root_public_key,
        completion_private_key, pins, window, bound, not_before_epoch_ns, work,
        not_before_monotonic_ns=None):
    """Fixed suffix reached only by this module's genuine original admissions."""
    last_epoch = not_before_epoch_ns
    last_monotonic = window[2] if not_before_monotonic_ns is None else not_before_monotonic_ns

    def live():
        nonlocal last_epoch, last_monotonic
        now = clock._check_on_work(window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        authorization.shape._integer(monotonic, minimum=1)
        if monotonic >= bound or now < last_epoch or monotonic < last_monotonic:
            raise CurrentRootCompletionError("completion original local deadline expired or clock reversed")
        last_epoch, last_monotonic = now, monotonic
        return now

    live()
    # This fixed real reader uses a fresh physical read-only connection. Its
    # snapshot cannot see an uncommitted marker from an executor transaction.
    marker, after_bytes = reader._read_on_configuration(configuration,
        pending_decision_digest=candidate.marker["pending_decision_digest"],
        live_window=window, transport_deadline_ns=bound, work=work)
    observed_at = live()
    evidence.plan._same(marker, candidate.marker, work,
        "committed marker differs from the genuine original pending plan")
    work.charge(input_bytes=len(after_bytes) + len(candidate.after_vector_bytes))
    if after_bytes != candidate.after_vector_bytes:
        raise CurrentRootCompletionError("committed complete roots differ from the genuine planned result")
    after_digest = vector._digest_on_work(after_bytes, work=work)
    evidence.plan._same(after_digest, marker["after_vector_digest"], work,
        "committed complete root digest differs from the immutable marker")
    observation = _observation_bytes(marker, after_digest, observed_at, work)
    work.charge(hashes=1, input_bytes=len(observation))
    observation_digest = "sha256:" + hashlib.sha256(observation).hexdigest()
    payload = {"schema": authorization.REQUEST_PAYLOAD_SCHEMA,
        "sourceRevision": authorization.authority.SOURCE_REVISION, "action": "complete",
        "enrollmentDigest": pins[0], "databaseId": pins[1], "generationDigest": pins[2],
        "producerMeasurementDigest": pins[3], "issuedAtEpochNs": window[0], "expiresAtEpochNs": window[3],
        "operation": candidate.operation, "pendingRequestDigest": marker["pending_request_digest"],
        "pendingDecisionDigest": marker["pending_decision_digest"], "fence": marker["fence"],
        "writerReceiptBase64Url": authorization.transport._encode(observation, work),
        "writerReceiptBytesDigest": observation_digest, "writerReceiptByteCount": len(observation),
        "snapshotDigest": marker["snapshot_digest"], "resultDigest": marker["result_digest"],
        "beforeVectorDigest": marker["before_vector_digest"], "afterVectorDigest": after_digest}
    request = authorization._produce_request_on_work(payload=payload,
        enrollment_bytes=enrollment, root_public_key=root_public_key,
        producer_private_key=completion_private_key, now_epoch_ns=live(), work=work)
    live()
    return request


def _produce_complete_on_work(*, operation, originals, expectations, planner_public_key,
        operation_public_key, enrollment_bytes, root_public_key, completion_private_key,
        reserve_request_bytes, reserve_receipt_bytes, snapshot_bytes,
        grant_bytes, grant_enrollment_bytes, expected_authorization_digest,
        expected_database_id, expected_generation_digest, expected_pending_sequence,
        expected_pending_head_digest, expected_fence, commit_reader, deadline_epoch_ns,
        work, transport_deadline_ns=None):
    """Return an original signed completion after actual committed-state reads.

    A new completion window can attest a committed transition after the original
    execution grant expired. It cannot execute that transition or extend the
    original grant/reserve intervals. The caller still owns delivery, durable
    acknowledgment and uncertainty handling under the exact pending checkpoint.
    """
    evidence.capture._SharedLedger(work)
    shape = authorization.shape
    held = pending._originals(operation, originals, enrollment_bytes,
        reserve_request_bytes, reserve_receipt_bytes, snapshot_bytes)
    plan_originals, enrollment, reserve, receipt, snapshot_original = held
    grant_raw = authorization._original(grant_bytes, grants.MAX_GRANT_BYTES, "completion grant")
    grant_enrollment = authorization._original(grant_enrollment_bytes,
        grants.MAX_ENROLLMENT_BYTES, "completion grant enrollment")
    if sum(len(raw) for raw in (*plan_originals, *held[1:], grant_raw,
            grant_enrollment)) > pending.replay.MAX_ORIGINAL_BYTES:
        raise CurrentRootCompletionError("completion originals exceed the existing aggregate bound")
    held_root, held_signer = root_public_key, completion_private_key
    planner_key, operation_key = planner_public_key, operation_public_key
    authorization._public(held_root)
    authorization._private(held_signer)
    shape._digest(expected_authorization_digest)
    authorization._token(expected_database_id)
    shape._digest(expected_generation_digest)
    shape._integer(expected_pending_sequence, authorization.MAX_RECORDS, minimum=1)
    shape._digest(expected_pending_head_digest)
    shape._integer(expected_fence, minimum=1)
    shape._integer(deadline_epoch_ns, minimum=1)
    if transport_deadline_ns is not None:
        shape._integer(transport_deadline_ns, minimum=1)
    held_scope = (expected_authorization_digest, expected_database_id,
        expected_generation_digest, expected_pending_sequence,
        expected_pending_head_digest, expected_fence, deadline_epoch_ns, transport_deadline_ns)
    # Exact owner/configuration and all mutable history are held before native
    # key, clock or driver callbacks. No instance read override is invoked.
    configuration = reader.CurrentRootCommitReader._snapshot_configuration(commit_reader)
    expected = pending.replay._expectations(operation, expectations, planner_key, operation_key, work)
    authorization_digest, database_id, generation, sequence, head, fence, deadline, inherited = held_scope
    window = clock._open_on_work(deadline_epoch_ns=deadline,
        maximum_lifetime_ns=authorization.authority.VERIFIER_RESPONSE_MAX_AGE_NS,
        maximum_clock_skew_ns=authorization.authority.VERIFIER_MAX_CLOCK_SKEW_NS, work=work)
    bound = window[4] if inherited is None else min(window[4], inherited)
    last_epoch = window[0]

    def live():
        nonlocal last_epoch
        now = clock._check_on_work(window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if monotonic >= bound or now < last_epoch:
            raise CurrentRootCompletionError("completion original local deadline expired or clock reversed")
        last_epoch = now
        return now

    live()
    material = authorization._admit_enrollment_on_work(enrollment_bytes=enrollment,
        root_public_key=held_root, work=work)
    policy = material.payload
    pins = (material.enrollment_digest, policy["databaseId"], policy["generationDigest"],
        policy["completion"]["measurementDigest"], policy["maxControlAgeNs"], policy["maxClockSkewNs"])
    # Clip the original opening bracket; no second clock window is opened.
    expires = min(window[3], window[0] + pins[4])
    window = clock._validate((window[0], window[1], window[2], expires,
        window[1] + expires - window[0], pins[4], pins[5]))
    bound = min(bound, window[4])
    live()
    candidate = pending._admit_for_completion_on_work(operation=operation,
        originals=plan_originals, expectations=expected, planner_public_key=planner_key,
        operation_public_key=operation_key, enrollment_bytes=enrollment, root_public_key=held_root,
        reserve_request_bytes=reserve, reserve_receipt_bytes=receipt, snapshot_bytes=snapshot_original,
        expected_database_id=database_id, expected_generation_digest=generation,
        expected_pending_sequence=sequence, expected_pending_head_digest=head, expected_fence=fence,
        live_window=window, work=work, transport_deadline_ns=bound)
    live()
    _verify_grant_on_work(candidate=candidate, grant_raw=grant_raw,
        grant_enrollment=grant_enrollment, enrollment=enrollment, root_public_key=held_root,
        planner_public_key=planner_key, operation_public_key=operation_key,
        authorization_digest=authorization_digest, work=work)
    live()
    return _read_and_sign_on_work(candidate=candidate, configuration=configuration,
        enrollment=enrollment, root_public_key=held_root, completion_private_key=held_signer,
        pins=pins, window=window, bound=bound, not_before_epoch_ns=last_epoch, work=work)


def _match_custody_on_work(*, payload, candidate, actual_effects_digest,
        operation, authorization_digest, work):
    """Compare stored packet claims to this invocation's actual original replay."""
    from serverware import authority_successor_execution_recovery_packet as recovery

    for actual, expected in (
        (payload["operation"], operation), (payload["operation"], candidate.operation),
        (payload["authorizationDigest"], authorization_digest),
        (payload["requestDigest"], candidate.marker["request_digest"]),
        (payload["operationId"], candidate.marker["operation_id"]),
        (payload["issuedAtEpochNs"], candidate.original_interval[0]),
        (payload["expiresAtEpochNs"], candidate.original_interval[1]),
        (payload["marker"], candidate.marker),
    ):
        evidence.plan._same(actual, expected, work,
            "retained custody differs from genuinely admitted original scope")
    before_bytes = vector._encode_on_work(payload["beforeVector"], work=work)
    after_bytes = vector._encode_on_work(payload["afterVector"], work=work)
    # These bytes were genuinely validated and encoded immediately above; do
    # not substitute a packet-claimed digest for either complete vector.
    for name, original in (("before_vector_digest", before_bytes),
            ("after_vector_digest", after_bytes)):
        digest = vector.framing._frame(vector.IDENTITY_DOMAIN, (original,), work)
        evidence.plan._same(digest, candidate.marker[name], work,
            "retained custody complete vector differs from actual original replay")
    work.charge(input_bytes=len(after_bytes) + len(candidate.after_vector_bytes))
    if after_bytes != candidate.after_vector_bytes:
        raise CurrentRootCompletionError("retained custody after vector differs from actual original replay")
    result_digest = evidence.plan._json_digest("serverware.policyAuthorityControlledWriterResult/v2",
        payload["result"], evidence.capture._SharedLedger(work))
    evidence.plan._same(result_digest, candidate.marker["result_digest"], work,
        "retained custody result differs from actual original replay")
    stored_effects_digest = recovery._effects_digest_on_work(selected_rows=payload["selectedRows"],
        mutations=payload["mutations"], result=payload["result"],
        work_units=payload["workUnits"], work=work)
    evidence.plan._same(stored_effects_digest, actual_effects_digest, work,
        "retained custody effects differ from genuine same-call replay")


def _produce_from_custody_on_work(*, packet_bytes, expected_packet_digest, operation,
        expectations, planner_public_key, operation_public_key, root_public_key,
        completion_private_key, expected_authorization_digest, expected_database_id,
        expected_generation_digest, expected_pending_sequence, expected_pending_head_digest,
        expected_fence, commit_reader, live_window, work, transport_deadline_ns=None):
    """Authenticate retained originals once, observe real commit, sign completion.

    Packet bytes are data, not an admitted candidate. Root/history/key/request
    authority and the exact still-current pending checkpoint are independent
    inputs. Expired grant/reserve originals are verified historically only;
    this path cannot execute their effects or renew execution authority.
    The provided retrieval window retains its original clock bracket and can
    only be shortened by enrolled completion policy, never reopened here.
    """
    from serverware import authority_successor_execution_recovery_packet as recovery

    evidence.capture._SharedLedger(work)
    original = authorization._original(packet_bytes, recovery.MAX_BYTES, "completion custody packet")
    shape = authorization.shape
    shape._digest(expected_packet_digest)
    shape._digest(expected_authorization_digest)
    held_packet_digest, authorization_digest = expected_packet_digest, expected_authorization_digest
    held_operation = operation
    authorization.delta._source(held_operation)
    held_root, held_signer = root_public_key, completion_private_key
    planner_key, operation_key = planner_public_key, operation_public_key
    authorization._public(held_root)
    authorization._private(held_signer)
    scope = pending._scope(expected_database_id=expected_database_id,
        expected_generation_digest=expected_generation_digest,
        expected_pending_sequence=expected_pending_sequence,
        expected_pending_head_digest=expected_pending_head_digest, expected_fence=expected_fence,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns)
    # Own every independent input before packet hashing, native clocks/keys or
    # database callbacks. No scope/key/history is adopted from retained bytes.
    configuration = reader.CurrentRootCommitReader._snapshot_configuration(commit_reader)
    expected = pending.replay._expectations(held_operation, expectations, planner_key, operation_key, work)
    database_id, generation, sequence, head, fence, window, inherited = scope
    bound = window[4] if inherited is None else min(window[4], inherited)
    last_epoch, last_monotonic = window[0], window[2]

    def live():
        nonlocal last_epoch, last_monotonic
        now = clock._check_on_work(window, work=work)
        monotonic = evidence.production._callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if monotonic >= bound or now < last_epoch or monotonic < last_monotonic:
            raise CurrentRootCompletionError("custody completion original window expired or clock reversed")
        last_epoch, last_monotonic = now, monotonic
        return now

    live()
    retained = recovery._decode_on_work(original, expected_packet_digest=held_packet_digest,
        expected_pending_decision_digest=head, work=work)
    live()
    material = authorization._admit_enrollment_on_work(enrollment_bytes=retained.enrollment_bytes,
        root_public_key=held_root, work=work)
    policy = material.payload
    pins = (material.enrollment_digest, policy["databaseId"], policy["generationDigest"],
        policy["completion"]["measurementDigest"], policy["maxControlAgeNs"], policy["maxClockSkewNs"])
    # Preserve the supplied origin, lifetime and skew; enrollment may only
    # shorten them. The packet's expired execution interval is never retimed.
    lifetime, skew = min(window[5], pins[4]), min(window[6], pins[5])
    expires = min(window[3], window[0] + lifetime)
    window = clock._validate((window[0], window[1], window[2], expires,
        window[1] + expires - window[0], lifetime, skew))
    bound = min(bound, window[4])
    live()
    candidate, effects_digest = pending._admit_for_custody_completion_on_work(
        operation=held_operation, originals=retained.originals, expectations=expected,
        planner_public_key=planner_key, operation_public_key=operation_key,
        enrollment_bytes=retained.enrollment_bytes, root_public_key=held_root,
        reserve_request_bytes=retained.reserve_request_bytes,
        reserve_receipt_bytes=retained.reserve_receipt_bytes, snapshot_bytes=retained.snapshot_bytes,
        expected_database_id=database_id, expected_generation_digest=generation,
        expected_pending_sequence=sequence, expected_pending_head_digest=head, expected_fence=fence,
        live_window=window, work=work, transport_deadline_ns=bound)
    live()
    _verify_grant_on_work(candidate=candidate, grant_raw=retained.grant_bytes,
        grant_enrollment=retained.grant_enrollment_bytes, enrollment=retained.enrollment_bytes,
        root_public_key=held_root, planner_public_key=planner_key, operation_public_key=operation_key,
        authorization_digest=authorization_digest, work=work)
    live()
    _match_custody_on_work(payload=retained.payload, candidate=candidate,
        actual_effects_digest=effects_digest, operation=held_operation,
        authorization_digest=authorization_digest, work=work)
    live()
    return _read_and_sign_on_work(candidate=candidate, configuration=configuration,
        enrollment=retained.enrollment_bytes, root_public_key=held_root,
        completion_private_key=held_signer, pins=pins, window=window, bound=bound,
        not_before_epoch_ns=last_epoch, not_before_monotonic_ns=last_monotonic, work=work)
