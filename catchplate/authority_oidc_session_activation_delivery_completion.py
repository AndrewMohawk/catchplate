"""Original consume custody -> genuine historical replay -> signed completion.

This dedicated path requires the independent historical custody owner, actual
caller/enrollment originals, independently pinned pending scope and the fixed
read-only commit reader. No candidate or successful observation is accepted.
Expired original execution intervals are data, never current clock samples.
The supplied current allowance covers decoding, replay, observation and signing.

This module neither executes SQL mutations nor publishes a completion. Its
caller must durably retain the first exact control before state delivery. Cold
completion signing-key/readers and state-peer installation remain separate.
The existing generic consume completion rejection is unchanged.
"""
from __future__ import annotations

import hashlib

from catchplate import authority_current_root_completion as common
from catchplate import authority_oidc_session_activation_delivery_completion_admission as admission
from catchplate import authority_oidc_session_activation_delivery_execution_authorization as caller
from catchplate import authority_oidc_session_activation_delivery_execution_enrollment as enrollments
from catchplate import authority_oidc_session_activation_delivery_execution_expectations as expectations_wire
from catchplate import oidc_session_activation_delivery as delivery
from catchplate import authority_oidc_session_activation_delivery_completion_custody as custody
from catchplate import authority_oidc_session_activation_delivery_recovery_packet as packets
from catchplate import authority_successor_execution_window as processing_window


authorization, evidence, clock = common.authorization, common.evidence, common.clock
reader, vector = common.reader, common.vector
OPERATION = admission.OPERATION


class DeliveryCompletionError(ValueError):
    pass


def _produce_from_custody_on_work(*, packet_bytes, expected_packet_digest,
        expectations, planner_public_key, operation_public_key, root_public_key,
        completion_private_key, authorization_bytes, authorization_enrollment_bytes,
        grant_enrollment_bytes, current_root_enrollment_bytes, configuration_digest,
        expected_authorization_digest, expected_database_id, expected_generation_digest,
        expected_pending_sequence, expected_pending_head_digest, expected_fence,
        historical_custody, commit_reader, live_window, transport_deadline_ns, work):
    """Sign only after actual original replay and a normally closed commit read."""
    evidence.capture._SharedLedger(work)
    raw_packet = authorization._original(packet_bytes, packets.MAX_BYTES, "consume custody packet")
    caller_raw = authorization._original(authorization_bytes,
        caller.MAX_AUTHORIZATION_BYTES, "consume historical caller")
    caller_enrollment = authorization._original(authorization_enrollment_bytes,
        caller.MAX_ENROLLMENT_BYTES, "consume historical caller enrollment")
    grant_enrollment = authorization._original(grant_enrollment_bytes,
        enrollments.MAX_ENROLLMENT_BYTES, "consume historical grant enrollment")
    state_enrollment = authorization._original(current_root_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "consume independent state enrollment")
    if sum(map(len, (raw_packet, caller_raw, caller_enrollment, grant_enrollment,
            state_enrollment))) > packets.MAX_BYTES:
        raise DeliveryCompletionError("consume completion originals exceed their aggregate bound")
    root, signer, planner, operation_key = (
        root_public_key, completion_private_key, planner_public_key, operation_public_key)
    for key in (root, planner, operation_key):
        authorization._public(key)
    authorization._private(signer)
    packet_digest, authorization_digest, config_digest = (
        expected_packet_digest, expected_authorization_digest, configuration_digest)
    for digest in (packet_digest, authorization_digest, config_digest):
        authorization.shape._digest(digest)
    scope = common.pending._scope(expected_database_id=expected_database_id,
        expected_generation_digest=expected_generation_digest,
        expected_pending_sequence=expected_pending_sequence,
        expected_pending_head_digest=expected_pending_head_digest, expected_fence=expected_fence,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns)
    authorization.shape._integer(transport_deadline_ns, minimum=1)
    database_id, generation, sequence, head, fence, window, inherited = scope
    if type(historical_custody) is not custody.OidcSessionActivationDeliveryCompletionCustody:
        raise DeliveryCompletionError("consume completion requires its actual historical custody owner")
    owner = historical_custody
    configured = reader.CurrentRootCommitReader._snapshot_configuration(commit_reader)
    expected = expectations_wire._capture_on_work(expectations, work=work)
    bound = min(window[4], inherited)
    # Every external mutable graph and immutable original is held before the
    # first native key/clock callback. A returned admission is never an input.
    custody.OidcSessionActivationDeliveryCompletionCustody.require_completion_on_work(owner, work=work)
    custody.OidcSessionActivationDeliveryCompletionCustody.bind_context_on_work(owner,
        root_public_key=root, current_root_enrollment_bytes=state_enrollment, work=work)
    window, bound = custody.OidcSessionActivationDeliveryCompletionCustody.processing_bounds_on_work(owner,
        live_window=window, transport_deadline_ns=bound, work=work)
    owner_live = custody.OidcSessionActivationDeliveryCompletionCustody.check_on_work(owner,
        live_window=window, transport_deadline_ns=bound, work=work)
    _window, processing = delivery._window(window, bound, work)
    processing_guards = [processing]
    admitted = None

    def current():
        samples = [owner_live()]
        if admitted is not None:
            samples.append(admitted.live())
        samples.extend(guard() for guard in processing_guards)
        if any(later < earlier for earlier, later in zip(samples, samples[1:])):
            raise DeliveryCompletionError("consume completion clocks reversed across admission")
        if reader.CurrentRootCommitReader._snapshot_configuration(commit_reader) != configured:
            raise DeliveryCompletionError("consume completion reader configuration changed")
        return samples[-1]

    current()
    retained = packets._decode_on_work(raw_packet, expected_packet_digest=packet_digest,
        expected_pending_decision_digest=head, work=work)
    current()
    for actual, independent, label in (
            (retained.enrollment_bytes, state_enrollment, "state enrollment"),
            (retained.grant_enrollment_bytes, grant_enrollment, "grant enrollment"),
            (retained.authorization_enrollment_bytes, caller_enrollment, "caller enrollment"),
            (retained.authorization_bytes, caller_raw, "caller authorization")):
        work.charge(input_bytes=len(actual) + len(independent))
        if actual != independent:
            raise DeliveryCompletionError("consume retained " + label + " differs from its independent original")
    material = authorization._admit_enrollment_on_work(enrollment_bytes=state_enrollment,
        root_public_key=root, work=work)
    policy = material.payload
    for actual, independent in ((policy["databaseId"], database_id),
            (policy["generationDigest"], generation)):
        evidence.plan._same(actual, independent, work, "consume completion independent state scope")
    authorization.keys._pair_on_work(signer, material.completion_public_key, work)
    window = processing_window._narrow(window, deadline_epoch_ns=window[3],
        maximum_lifetime_ns=policy["maxControlAgeNs"], maximum_clock_skew_ns=policy["maxClockSkewNs"])
    bound = min(bound, window[4])
    _window, narrowed_processing = delivery._window(window, bound, work)
    # Retain the first guard's sticky clock history when adding a tighter one.
    processing_guards.append(narrowed_processing)
    current()
    admitted = admission._admit_on_work(originals=retained.originals, expectations=expected,
        planner_public_key=planner, operation_public_key=operation_key,
        enrollment_bytes=state_enrollment, root_public_key=root,
        reserve_request_bytes=retained.reserve_request_bytes,
        reserve_receipt_bytes=retained.reserve_receipt_bytes, snapshot_bytes=retained.snapshot_bytes,
        expected_database_id=database_id, expected_generation_digest=generation,
        expected_pending_sequence=sequence, expected_pending_head_digest=head, expected_fence=fence,
        authorization_bytes=caller_raw, authorization_enrollment_bytes=caller_enrollment,
        grant_bytes=retained.grant_bytes, grant_enrollment_bytes=grant_enrollment,
        configuration_digest=config_digest, historical_custody=owner,
        live_window=window, transport_deadline_ns=bound, work=work)
    if type(admitted) is not admission._AdmittedCompletion:
        raise DeliveryCompletionError("consume completion requires its actual same-call historical admission")
    current()
    evidence.plan._same(admitted.authorization_digest, authorization_digest, work,
        "consume completion independently expected caller authorization")
    candidate = admitted.candidate
    common._match_custody_on_work(payload=retained.payload, candidate=candidate,
        actual_effects_digest=admitted.effects_digest, operation=OPERATION,
        authorization_digest=authorization_digest, work=work)
    current()
    # The real fixed reader returns only after normal cursor/connection close.
    # No write-capable opener or supplied marker can reach this suffix.
    marker, after_bytes = reader._read_on_configuration(configured,
        pending_decision_digest=head, live_window=window, transport_deadline_ns=bound, work=work)
    observed_at = current()
    evidence.plan._same(marker, candidate.marker, work,
        "consume committed marker differs from genuine historical admission")
    work.charge(input_bytes=len(after_bytes) + len(candidate.after_vector_bytes))
    if after_bytes != candidate.after_vector_bytes:
        raise DeliveryCompletionError("consume committed vector differs from genuine historical replay")
    after_digest = vector._digest_on_work(after_bytes, work=work)
    evidence.plan._same(after_digest, marker["after_vector_digest"], work,
        "consume committed vector differs from immutable marker")
    observation = common._observation_bytes(marker, after_digest, observed_at, work)
    work.charge(hashes=1, input_bytes=len(observation))
    observation_digest = "sha256:" + hashlib.sha256(observation).hexdigest()
    current()
    payload = {"schema": authorization.REQUEST_PAYLOAD_SCHEMA,
        "sourceRevision": authorization.authority.SOURCE_REVISION, "action": "complete",
        "enrollmentDigest": material.enrollment_digest, "databaseId": database_id,
        "generationDigest": generation, "producerMeasurementDigest": policy["completion"]["measurementDigest"],
        "issuedAtEpochNs": window[0], "expiresAtEpochNs": window[3], "operation": OPERATION,
        "pendingRequestDigest": marker["pending_request_digest"],
        "pendingDecisionDigest": marker["pending_decision_digest"], "fence": marker["fence"],
        "writerReceiptBase64Url": authorization.transport._encode(observation, work),
        "writerReceiptBytesDigest": observation_digest, "writerReceiptByteCount": len(observation),
        "snapshotDigest": marker["snapshot_digest"], "resultDigest": marker["result_digest"],
        "beforeVectorDigest": marker["before_vector_digest"], "afterVectorDigest": after_digest}
    original = authorization._produce_request_on_work(payload=payload,
        enrollment_bytes=state_enrollment, root_public_key=root, producer_private_key=signer,
        now_epoch_ns=current(), work=work)
    current()
    return original
