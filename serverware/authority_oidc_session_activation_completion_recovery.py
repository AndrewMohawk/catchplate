"""Dedicated activation completion retention, delivery and no-repeat recovery.

Actual separately configured custody/commit readers and historical key owner
are mandatory. A first completion genuinely replays originals and observes the
immutable commit before signing. It is durably retained before transmission.
An existing original is never replaced: a fresh signed state lookup recovers
its exact acknowledgment or permits only the unchanged original to be sent.
Ambiguous/changed state fails closed without clearing custody or repeating SQL.

This is a private composition, not an installed cold service or public action.
Independent signing-key/reader/journal/TLS/state-peer provenance and fresh public
permission remain required. No token is released and no current session claim
is made. The caller supplies one real current processing window and allowance.
"""
from __future__ import annotations

from serverware import authority_current_root_delivery as delivery_store
from serverware import authority_current_root_transport as transport
from serverware import authority_oidc_session_activation_completion as completion
from serverware import authority_successor_completion_recovery as common
from serverware import authority_successor_execution_owner as packet_store


authorization, evidence, clock = completion.authorization, completion.evidence, completion.clock
custody, history, packets = completion.custody, completion.history, completion.packets
OPERATION = completion.OPERATION


class ActivationCompletionRecoveryError(RuntimeError):
    pass


def recover_and_deliver(*, custody_reader, commit_reader, delivery, client,
        historical_custody, packet_digest, expectations, planner_public_key,
        operation_public_key, root_public_key, completion_private_key,
        authorization_bytes, authorization_enrollment_bytes, grant_enrollment_bytes,
        current_root_enrollment_bytes, configuration_digest, expected_authorization_digest,
        expected_database_id, expected_generation_digest, expected_pending_sequence,
        expected_pending_head_digest, expected_fence, live_window, transport_deadline_ns, work):
    """Return a durably retained original acknowledgment, never execution authority.

    A retained original is authenticated and looked up before any unchanged
    redelivery. Each call performs at most one complete exchange. Uncertainty
    preserves the exact original; another call cannot sign its replacement.
    """
    evidence.capture._SharedLedger(work)
    if type(delivery) is not delivery_store.CurrentRootCompletionDelivery:
        raise ActivationCompletionRecoveryError("activation recovery requires the actual completion delivery owner")
    if type(historical_custody) is not custody.OidcSessionActivationHistoryCustody:
        raise ActivationCompletionRecoveryError("activation recovery requires the actual historical custody owner")
    owner = historical_custody
    read_config = packet_store.SuccessorExecutionRecoveryReader._snapshot_configuration(custody_reader)
    commit_config = completion.reader.CurrentRootCommitReader._snapshot_configuration(commit_reader)
    transport_config = transport.CurrentRootDecisionClient._snapshot_configuration(client)
    caller_raw = authorization._original(authorization_bytes,
        completion.caller.MAX_AUTHORIZATION_BYTES, "activation recovery caller")
    caller_enrollment = authorization._original(authorization_enrollment_bytes,
        completion.caller.MAX_ENROLLMENT_BYTES, "activation recovery caller enrollment")
    grant_enrollment = authorization._original(grant_enrollment_bytes,
        completion.common.grants.MAX_ENROLLMENT_BYTES, "activation recovery grant enrollment")
    state_enrollment = authorization._original(current_root_enrollment_bytes,
        authorization.MAX_ENROLLMENT_BYTES, "activation recovery independent state enrollment")
    if sum(map(len, (caller_raw, caller_enrollment, grant_enrollment,
            state_enrollment))) > history.MAX_ORIGINAL_BYTES:
        raise ActivationCompletionRecoveryError("activation recovery originals exceed their aggregate bound")
    root, signer, planner, operation_key = (
        root_public_key, completion_private_key, planner_public_key, operation_public_key)
    for key in (root, planner, operation_key):
        authorization._public(key)
    authorization._private(signer)
    held_packet, authorization_digest, config_digest = (
        packet_digest, expected_authorization_digest, configuration_digest)
    for digest in (held_packet, authorization_digest, config_digest):
        authorization.shape._digest(digest)
    scope = completion.common.pending._scope(expected_database_id=expected_database_id,
        expected_generation_digest=expected_generation_digest,
        expected_pending_sequence=expected_pending_sequence,
        expected_pending_head_digest=expected_pending_head_digest, expected_fence=expected_fence,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns)
    authorization.shape._integer(transport_deadline_ns, minimum=1)
    database_id, generation, sequence, head, fence, window, inherited = scope
    expected = completion.common.pending.replay._expectations(OPERATION,
        expectations, planner, operation_key, work)
    bound = min(window[4], inherited)
    # All independent input graphs and owner configurations are held before
    # native clocks, key operations, protected reads or journal access.
    custody.OidcSessionActivationHistoryCustody.bind_context_on_work(owner,
        root_public_key=root, current_root_enrollment_bytes=state_enrollment, work=work)
    window, bound = custody.OidcSessionActivationHistoryCustody.processing_bounds_on_work(owner,
        live_window=window, transport_deadline_ns=bound, work=work)
    owner_live = custody.OidcSessionActivationHistoryCustody.check_on_work(owner,
        live_window=window, transport_deadline_ns=bound, work=work)
    _window, processing = history.delivery._window(window, bound, work)
    processing_guards = [processing]

    def live():
        samples = [owner_live()]
        samples.extend(guard() for guard in processing_guards)
        if any(later < earlier for earlier, later in zip(samples, samples[1:])):
            raise ActivationCompletionRecoveryError("activation recovery clocks reversed across custody")
        if (packet_store.SuccessorExecutionRecoveryReader._snapshot_configuration(custody_reader) != read_config
                or completion.reader.CurrentRootCommitReader._snapshot_configuration(commit_reader) != commit_config
                or transport.CurrentRootDecisionClient._snapshot_configuration(client) != transport_config):
            raise ActivationCompletionRecoveryError("activation recovery configured reader or transport changed")
        return samples[-1]

    live()
    for index in (6, 7):
        evidence.plan._same(read_config[index], commit_config[index], work,
            "activation recovery readers differ in independent query/catalog pins")
    # Equal query/catalog pins do not establish database identity or freshness.
    # Those are independently admitted cold configuration obligations.
    material = authorization._admit_enrollment_on_work(enrollment_bytes=state_enrollment,
        root_public_key=root, work=work)
    for actual, expected_value in ((material.payload["databaseId"], database_id),
            (material.payload["generationDigest"], generation)):
        evidence.plan._same(actual, expected_value, work, "activation recovery independent state scope")
    authorization.keys._pair_on_work(signer, material.completion_public_key, work)
    window = completion.processing_window._narrow(window, deadline_epoch_ns=window[3],
        maximum_lifetime_ns=material.payload["maxControlAgeNs"],
        maximum_clock_skew_ns=material.payload["maxClockSkewNs"])
    bound = min(bound, window[4])
    _window, narrowed_processing = history.delivery._window(window, bound, work)
    # Narrowing adds a guard; it cannot discard prior sticky clock samples.
    processing_guards.append(narrowed_processing)
    live()
    with delivery_store.CurrentRootCompletionDelivery._recovery_scope(delivery):
        live()
        # The actual delivery owner must use the same independent root and
        # exact enrollment, including on the retained-original recovery branch.
        delivery_enrollment = authorization._original(delivery._enrollment_bytes,
            authorization.MAX_ENROLLMENT_BYTES, "activation delivery enrollment")
        delivery_root = delivery._root_public_key
        authorization._public(delivery_root)
        work.charge(input_bytes=len(delivery_enrollment) + len(state_enrollment))
        if delivery_enrollment != state_enrollment:
            raise ActivationCompletionRecoveryError("activation delivery enrollment differs from independent history")
        evidence.plan._same(authorization.keys._spki_on_work(delivery_root, work),
            authorization.keys._spki_on_work(root, work), work, "activation delivery independent root")

        def current():
            now = live()
            delivery_store.CurrentRootCompletionDelivery._require_ready(delivery)
            if (delivery._enrollment_bytes is not delivery_enrollment
                    or delivery._root_public_key is not delivery_root):
                raise ActivationCompletionRecoveryError("activation delivery authority changed during recovery")
            return now

        current()
        retained = delivery_store.CurrentRootCompletionDelivery._original_for_pending_on_work(delivery,
            expected_pending_sequence=sequence, expected_pending_head_digest=head, work=work)
        raw_packet = packet_store._read_on_configuration(read_config,
            pending_decision_digest=head, packet_digest=held_packet,
            live_window=window, transport_deadline_ns=bound, work=work)
        current()
        if sum(map(len, (raw_packet, caller_raw, caller_enrollment,
                grant_enrollment, state_enrollment))) > packets.MAX_BYTES:
            raise ActivationCompletionRecoveryError("activation recovered originals exceed their aggregate bound")
        if retained is None:
            original = completion._produce_from_custody_on_work(packet_bytes=raw_packet,
                expected_packet_digest=held_packet, expectations=expected,
                planner_public_key=planner, operation_public_key=operation_key,
                root_public_key=root, completion_private_key=signer,
                authorization_bytes=caller_raw, authorization_enrollment_bytes=caller_enrollment,
                grant_enrollment_bytes=grant_enrollment, current_root_enrollment_bytes=state_enrollment,
                configuration_digest=config_digest, expected_authorization_digest=authorization_digest,
                expected_database_id=database_id, expected_generation_digest=generation,
                expected_pending_sequence=sequence, expected_pending_head_digest=head, expected_fence=fence,
                historical_custody=owner, commit_reader=commit_reader,
                live_window=window, transport_deadline_ns=bound, work=work)
            current()
            identity = delivery_store.CurrentRootCompletionDelivery.enqueue(delivery, original,
                expected_pending_sequence=sequence, expected_pending_head_digest=head,
                live_window=window, transport_deadline_ns=bound, work=work)
            current()
        else:
            identity, original = retained
            recovered = packets._decode_on_work(raw_packet, expected_packet_digest=held_packet,
                expected_pending_decision_digest=head, work=work)
            for actual, independent in ((recovered.enrollment_bytes, state_enrollment),
                    (recovered.grant_enrollment_bytes, grant_enrollment)):
                work.charge(input_bytes=len(actual) + len(independent))
                if actual != independent:
                    raise ActivationCompletionRecoveryError("activation retained enrollment differs from independent history")
            identity = common._reuse_on_work(original, identity, recovered, operation=OPERATION,
                root_public_key=root, authorization_digest=authorization_digest,
                database_id=database_id, generation=generation, sequence=sequence,
                head=head, fence=fence, work=work)
            current()
            observed = delivery_store.CurrentRootCompletionDelivery.reconcile(delivery, identity,
                client=client, live_window=window, transport_deadline_ns=bound, work=work)
            current()
            if type(observed) is not delivery_store.CurrentRootDeliveryReconciliation:
                raise ActivationCompletionRecoveryError("activation recovery requires its actual state lookup")
            if observed.status == "acknowledged":
                if type(observed.receipt_bytes) is not bytes:
                    raise ActivationCompletionRecoveryError("activation acknowledgment lacks its exact original")
                current()
                return common.SuccessorCompletionRecoveryResult(identity, observed.receipt_bytes, True)
            if observed.status != "pendingUnaccepted":
                raise ActivationCompletionRecoveryError("activation completion remains unresolved at changed state")
            # An authenticated notRecorded observation is not database noncommit
            # or permission to replace this original. Only exact redelivery follows.
        current()
        receipt = delivery_store.CurrentRootCompletionDelivery.deliver(delivery, identity,
            client=client, live_window=window, transport_deadline_ns=bound, work=work)
        current()
        return common.SuccessorCompletionRecoveryResult(identity, receipt, retained is not None)
