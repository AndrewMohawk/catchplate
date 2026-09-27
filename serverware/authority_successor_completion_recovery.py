"""Restricted custody read -> original completion -> durable exact delivery.

All historical keys, authorization and the exact pending checkpoint are
independent inputs. Actual configured owners are required; there is no supplied
packet, accepted-proof carrier, database opener or caller signing callback.
The caller's deadline and one original work allowance cover the entire flow.

The delivery owner is locked across lookup, read, production, retention and
exchange. An existing completion is authenticated and joined to the independently
pinned custody packet, then reused unchanged: no replacement signature, expiry
renewal or SQL execution is possible. Only absent local custody permits genuine
historical plan replay, committed-state readback and a newly signed completion.
That original is durably enqueued before transport, and the original state ack
is durably retained before return. Failure may leave either durable record.

An expired never-accepted retained completion remains unresolved; this API
cannot clear it or sign another. Missing custody/markers and late failures do
not prove noncommit. Cold role/key/config/catalog/checkpoint provenance, service
admission and independent latest-state authority remain external requirements.
Lock, database, signing, disk and socket work are not a hard native watchdog.
"""
from __future__ import annotations

from dataclasses import dataclass
import time

from serverware import authority_current_root_authorization as authorization
from serverware import authority_current_root_commit_reader as committed
from serverware import authority_current_root_completion as completion
from serverware import authority_current_root_delivery as delivery_store
from serverware import authority_current_root_delivery_records as delivery_records
from serverware import authority_current_root_execution_admission as pending
from serverware import authority_current_root_transport as transport
from serverware import authority_successor_execution_owner as custody
from serverware import authority_successor_execution_recovery_packet as packets
from serverware import authority_webauthn_evidence as evidence
from serverware import authority_webauthn_evidence_plan_clock as clock


class SuccessorCompletionRecoveryError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class SuccessorCompletionRecoveryResult:
    """Exact original state receipt retained durably, not a fresh state lease."""

    request_digest: str
    receipt_bytes: bytes
    reused_original: bool


def _reuse_on_work(original, retained_identity, recovered, *, operation, root_public_key,
        authorization_digest, database_id, generation, sequence, head, fence, work):
    """Authenticate the retained complete control, never generate another one.

    This branch does not replay the plan again or claim an executable recovered
    packet. It uses its independently pinned packet identity and an authentic
    original completion assertion already in durable local custody.
    """
    payload, marker = recovered.payload, recovered.payload["marker"]
    for actual, expected in ((payload["operation"], operation),
            (payload["authorizationDigest"], authorization_digest),
            (marker["database_id"], database_id), (marker["generation_digest"], generation),
            (marker["pending_sequence"], sequence), (marker["pending_decision_digest"], head),
            (marker["fence"], fence)):
        authorization.plan._same(actual, expected, work, "retained completion custody differs from independent scope")
    verified = delivery_records._verify_request_on_work(request_bytes=original,
        enrollment_bytes=recovered.enrollment_bytes, root_public_key=root_public_key,
        expected_pending_sequence=sequence, expected_pending_head_digest=head, work=work)
    authorization.plan._same(verified.request_digest, retained_identity, work,
        "recovered completion original identity differs from retained delivery")
    bindings = {"enrollmentDigest": "enrollment_digest", "databaseId": "database_id",
        "generationDigest": "generation_digest", "operation": "operation",
        "pendingRequestDigest": "pending_request_digest",
        "pendingDecisionDigest": "pending_decision_digest", "fence": "fence",
        "snapshotDigest": "snapshot_digest", "resultDigest": "result_digest",
        "beforeVectorDigest": "before_vector_digest", "afterVectorDigest": "after_vector_digest"}
    for request_field, marker_field in bindings.items():
        authorization.plan._same(verified.payload[request_field], marker[marker_field], work,
            "retained completion differs from the original custody marker")
    return retained_identity


def recover_and_deliver(*, custody_reader, commit_reader, delivery, client,
        operation, packet_digest, expectations, planner_public_key, operation_public_key,
        root_public_key, completion_private_key, expected_authorization_digest,
        expected_database_id, expected_generation_digest, expected_pending_sequence,
        expected_pending_head_digest, expected_fence, deadline_epoch_ns, work,
        transport_deadline_ns=None):
    """Recover one independently scoped completion without any execution retry.

    A caller may repeat this operation after uncertainty. It can redeliver only
    the unchanged retained complete control; it never invokes a SQL executor or
    clears attempt/pending state. This is not expired-unaccepted replacement or
    authorization to reconstruct lost independently admitted history.
    """
    evidence.capture._SharedLedger(work)
    if type(delivery) is not delivery_store.CurrentRootCompletionDelivery:
        raise SuccessorCompletionRecoveryError("completion recovery requires its actual durable delivery owner")
    read_config = custody.SuccessorExecutionRecoveryReader._snapshot_configuration(custody_reader)
    commit_config = committed.CurrentRootCommitReader._snapshot_configuration(commit_reader)
    transport_config = transport.CurrentRootDecisionClient._snapshot_configuration(client)
    held_operation, held_packet = operation, packet_digest
    held_root, held_signer = root_public_key, completion_private_key
    planner_key, operation_key = planner_public_key, operation_public_key
    authorization._public(held_root)
    authorization._private(held_signer)
    for value in (held_packet, expected_authorization_digest, expected_generation_digest,
            expected_pending_head_digest):
        authorization.shape._digest(value)
    authorization._token(expected_database_id)
    authorization.shape._integer(expected_pending_sequence, authorization.MAX_RECORDS, minimum=1)
    authorization.shape._integer(expected_fence, minimum=1)
    authorization.shape._integer(deadline_epoch_ns, minimum=1)
    if transport_deadline_ns is not None:
        authorization.shape._integer(transport_deadline_ns, minimum=1)
    authorization_digest, database_id, generation, sequence, head, fence, deadline, inherited = (
        expected_authorization_digest, expected_database_id, expected_generation_digest,
        expected_pending_sequence, expected_pending_head_digest, expected_fence,
        deadline_epoch_ns, transport_deadline_ns)
    # Detach independent mutable history before any clock, key or DB callback.
    expected = pending.replay._expectations(held_operation, expectations, planner_key, operation_key, work)
    for index in (6, 7):
        evidence.plan._same(read_config[index], commit_config[index], work,
            "completion readers differ from the same independent query or catalog pin")
    # Equal pins constrain both real observations, but cannot establish that
    # distinct role/TLS connections reach the same independently admitted DB.
    with delivery_store.CurrentRootCompletionDelivery._recovery_scope(delivery):
        window = clock._open_on_work(deadline_epoch_ns=deadline,
            maximum_lifetime_ns=authorization.authority.VERIFIER_RESPONSE_MAX_AGE_NS,
            maximum_clock_skew_ns=authorization.authority.VERIFIER_MAX_CLOCK_SKEW_NS, work=work)
        bound = window[4] if inherited is None else min(window[4], inherited)
        last_epoch, last_monotonic = window[0], window[2]

        def live():
            nonlocal last_epoch, last_monotonic
            now = clock._check_on_work(window, work=work)
            monotonic = evidence.production._callback(work, time.monotonic_ns)
            authorization.shape._integer(monotonic, minimum=1)
            if now < last_epoch or monotonic < last_monotonic or monotonic >= bound:
                raise SuccessorCompletionRecoveryError("completion recovery original deadline expired or clock reversed")
            last_epoch, last_monotonic = now, monotonic
            if (custody.SuccessorExecutionRecoveryReader._snapshot_configuration(custody_reader) != read_config
                    or committed.CurrentRootCommitReader._snapshot_configuration(commit_reader) != commit_config
                    or transport.CurrentRootDecisionClient._snapshot_configuration(client) != transport_config):
                raise SuccessorCompletionRecoveryError("completion recovery configured owners changed")

        live()
        retained = delivery_store.CurrentRootCompletionDelivery._original_for_pending_on_work(delivery,
            expected_pending_sequence=sequence, expected_pending_head_digest=head, work=work)
        raw_packet = custody._read_on_configuration(read_config, pending_decision_digest=head,
            packet_digest=held_packet, live_window=window, work=work, transport_deadline_ns=bound)
        live()
        if retained is not None:
            identity, original = retained
            recovered = packets._decode_on_work(raw_packet, expected_packet_digest=held_packet,
                expected_pending_decision_digest=head, work=work)
            identity = _reuse_on_work(original, identity, recovered, operation=held_operation,
                root_public_key=held_root, authorization_digest=authorization_digest,
                database_id=database_id, generation=generation, sequence=sequence, head=head, fence=fence, work=work)
        else:
            original = completion._produce_from_custody_on_work(packet_bytes=raw_packet,
                expected_packet_digest=held_packet, operation=held_operation, expectations=expected,
                planner_public_key=planner_key, operation_public_key=operation_key,
                root_public_key=held_root, completion_private_key=held_signer,
                expected_authorization_digest=authorization_digest, expected_database_id=database_id,
                expected_generation_digest=generation, expected_pending_sequence=sequence,
                expected_pending_head_digest=head, expected_fence=fence, commit_reader=commit_reader,
                live_window=window, work=work, transport_deadline_ns=bound)
            live()
            identity = delivery_store.CurrentRootCompletionDelivery.enqueue(delivery, original,
                expected_pending_sequence=sequence, expected_pending_head_digest=head,
                live_window=window, work=work, transport_deadline_ns=bound)
        live()
        receipt = delivery_store.CurrentRootCompletionDelivery.deliver(delivery, identity,
            client=client, live_window=window, work=work, transport_deadline_ns=bound)
        live()
        return SuccessorCompletionRecoveryResult(identity, receipt, retained is not None)
