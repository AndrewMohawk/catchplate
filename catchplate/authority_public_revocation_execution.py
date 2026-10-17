"""Public-v5 composition of the genuine successor execution owners.

Every phase replays original caller, preparation and plan material. The public
aggregate is never converted into nullable v4 assertion evidence. Existing v4
retention SQL is not called. Issuance uses the actual protected successor
issuer; execution uses its independently durable attempt owner before SQL.
Completion uses the separate restricted readers and original delivery journal.
An exception, timeout or missing acknowledgment never establishes noncommit.
"""
from __future__ import annotations

from catchplate import authority_public_revocation_preparation as preparation
from catchplate import authority_public_revocation_transport as wire
from catchplate import authority_successor_execution_grant_production as grant_production
from catchplate import authority_successor_execution_preparation as computation
from catchplate import authority_successor_execution_packet as packets
from catchplate import authority_successor_execution_owner as owners
from catchplate import authority_successor_completion_recovery as recovery
from catchplate import authority_current_root_delivery as deliveries
from catchplate import authority_current_root_delivery_records as delivery_records


caller, clock = preparation.caller, preparation.clock
OPERATION = preparation.aggregate.OPERATION


def _scope(process, raw, kind, window, bound, work, *, historical=False):
    from catchplate import authority_public_revocation_terminal as terminal
    raw = wire.originals(kind, raw)
    owner = terminal.require_started(process)
    owner.check(work=work)
    owner.require_originals(raw[:3], work=work)
    observed = preparation.verify_prepared(payload=owner.configuration_payload,
        configuration_digest=owner.configuration_digest, generation=owner.generation,
        runtime_role_identities=owner.runtime_role_identities, root_public_key=owner.root,
        originals=raw[:5], prepared=raw[5:11], live_window=window,
        transport_deadline_ns=bound, work=work, historical=historical)
    owner.check(work=work)
    return owner, observed


def _grant_arguments(observed, raw, root, window, bound, work):
    return dict(operation=OPERATION, originals=raw[5:7], expectations=observed.expectations,
        planner_public_key=observed.planner, operation_public_key=observed.verifier,
        before_vector_bytes=raw[7], current_root_enrollment_bytes=raw[0],
        grant_enrollment_bytes=raw[1], root_public_key=root,
        expected_authorization_digest=observed.authorization.authorization_digest,
        deadline_epoch_ns=min(window[3], observed.authorization.expires_at_epoch_ns),
        live_window=window, transport_deadline_ns=bound, work=work)


def grant_on_process(process, *, raw, live_window, transport_deadline_ns, work):
    window = clock._validate(live_window)
    bound = min(window[4], transport_deadline_ns)
    owner, observed = _scope(process, raw, "grant", window, bound, work)
    owner.require_role("issuer")
    produced = grant_production._produce_on_work(**_grant_arguments(observed, raw, owner.root,
        window, bound, work), authorizer_private_key=owner.signer)
    owner.check(work=work)
    preparation._current(window, bound, work)
    return (produced,)


def compute_on_process(process, *, raw, live_window, transport_deadline_ns, work):
    window = clock._validate(live_window)
    bound = min(window[4], transport_deadline_ns)
    owner, observed = _scope(process, raw, "compute", window, bound, work)
    owner.require_role("verifier")
    produced = computation._produce_reserve_on_work(operation=OPERATION, originals=raw[5:7],
        expectations=observed.expectations, planner_public_key=observed.planner,
        operation_public_key=observed.verifier, before_vector_bytes=raw[7], enrollment_bytes=raw[0],
        root_public_key=owner.root, computation_private_key=owner.signer,
        grant_bytes=raw[11], grant_enrollment_bytes=raw[1],
        expected_authorization_digest=observed.authorization.authorization_digest,
        predecessor_sequence=observed.head["sequence"], predecessor_head_digest=observed.head["headDigest"],
        fence=observed.head["fence"] + 1,
        deadline_epoch_ns=min(window[3], observed.authorization.expires_at_epoch_ns),
        live_window=window, transport_deadline_ns=bound, work=work)
    owner.check(work=work)
    preparation._current(window, bound, work)
    return produced.request_bytes, produced.snapshot_bytes


def _reserved(observed, raw, root, window, bound, work, *, receipt, historical=False):
    authorization = caller.authorization
    if historical:
        material, request, digest = authorization._verify_historical_request_on_work(
            request_bytes=raw[12], enrollment_bytes=raw[0], root_public_key=root, work=work)
    else:
        now, _mono = preparation._current(window, bound, work)
        material, request, digest = authorization._verify_request_on_work(request_bytes=raw[12],
            enrollment_bytes=raw[0], root_public_key=root, now_epoch_ns=now, work=work)
    for field, expected in (("action", "reserve"), ("operation", OPERATION),
            ("requestDigest", observed.authorization.request_digest),
            ("operationId", observed.authorization.operation_id),
            ("predecessorSequence", observed.head["sequence"]),
            ("predecessorHeadDigest", observed.head["headDigest"]), ("fence", observed.head["fence"] + 1)):
        caller.plan._same(request[field], expected, work, "public revocation reserve original " + field)
    if receipt:
        original = authorization._verify_receipt_on_work(receipt_bytes=raw[14],
            enrollment_bytes=raw[0], root_public_key=root, work=work)
        pending = authorization._receipt_digest_on_work(raw[14], work)
        for actual, expected in ((original["action"], "reserve"),
                (original["sequence"], observed.head["sequence"] + 1),
                (original["previousHeadDigest"], observed.head["headDigest"]),
                (original["requestDigest"], digest), (original["pendingRequestDigest"], digest),
                (original["fence"], observed.head["fence"] + 1)):
            caller.plan._same(actual, expected, work, "public revocation actual state acknowledgment differs")
        return pending, original["sequence"]
    # Genuine grant replay and exact snapshot reproduction precede the state
    # effect. A signed reserve from an enrolled key is not sufficient alone.
    now, _mono = preparation._current(window, bound, work)
    verified = caller.grants._verify_on_work(grant_bytes=raw[11], grant_enrollment_bytes=raw[1],
        current_root_enrollment_bytes=raw[0], root_public_key=root, operation=OPERATION,
        originals=raw[5:7], expectations=observed.expectations, planner_public_key=observed.planner,
        operation_public_key=observed.verifier, before_vector_bytes=raw[7],
        expected_authorization_digest=observed.authorization.authorization_digest,
        now_epoch_ns=now, work=work)
    snapshot = computation.computation._snapshot(verified.replayed, material, verified.grant_digest, work)
    expected_snapshot = computation.computation._snapshot_wire(snapshot, work)
    caller.plan._same(raw[13], expected_snapshot, work, "public revocation computation snapshot differs")
    for field, expected in (("capabilityDigest", verified.grant_digest),
            ("issuedAtEpochNs", verified.replayed.original_interval[0]),
            ("snapshotDigest", computation.computation._snapshot_digest_on_work(expected_snapshot, work=work))):
        caller.plan._same(request[field], expected, work, "public revocation reserve differs from actual grant replay")
    for field, expected in (("beforeVector", verified.replayed.before_vector_bytes),
            ("afterVector", verified.replayed.after_vector_bytes)):
        caller.plan._same(authorization.vector._encode_on_work(request[field], work=work), expected,
            work, "public revocation reserve vector differs from genuine replay")
    if request["expiresAtEpochNs"] > min(verified.payload["expiresAtEpochNs"], observed.authorization.expires_at_epoch_ns):
        raise preparation.aggregate.PublicRevocationError("public revocation reserve renews its original authority")
    return digest, None


def reserve_on_process(process, *, raw, live_window, transport_deadline_ns, work):
    window = clock._validate(live_window)
    bound = min(window[4], transport_deadline_ns)
    owner, observed = _scope(process, raw, "reserve", window, bound, work)
    owner.require_role("issuer")
    _reserved(observed, raw, owner.root, window, bound, work, receipt=False)
    owner.check(work=work)
    preparation._current(window, bound, work)
    receipt = owner.state.exchange(action="reserve", request_bytes=raw[12], deadline_ns=bound)
    owner.check(work=work)
    _reserved(observed, (*raw, receipt), owner.root, window, bound, work, receipt=True)
    return (receipt,)


def _packet_arguments(observed, raw, root, window, bound, work):
    pending, sequence = _reserved(observed, raw, root, window, bound, work, receipt=True)
    return dict(operation=OPERATION, originals=raw[5:7], expectations=observed.expectations,
        planner_public_key=observed.planner, operation_public_key=observed.verifier,
        enrollment_bytes=raw[0], root_public_key=root, reserve_request_bytes=raw[12],
        reserve_receipt_bytes=raw[14], snapshot_bytes=raw[13], grant_bytes=raw[11], grant_enrollment_bytes=raw[1],
        expected_authorization_digest=observed.authorization.authorization_digest,
        expected_database_id=observed.authorization.database_id,
        expected_generation_digest=observed.authorization.generation_digest,
        expected_pending_sequence=sequence, expected_pending_head_digest=pending,
        expected_fence=observed.head["fence"] + 1, live_window=window, transport_deadline_ns=bound, work=work)


def packet_locators(*, configuration, originals, prepared, grant, reserved,
        live_window, transport_deadline_ns, work):
    """Derive locators BEFORE contact by genuine replay, never from a SQL ACK."""
    raw = wire.originals("issue", (*originals, *prepared, grant, *reserved))
    observed = preparation.verify_prepared(**configuration, originals=originals, prepared=prepared,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work)
    packet = packets._prepare_on_work(**_packet_arguments(observed, raw, configuration["root_public_key"],
        live_window, transport_deadline_ns, work))
    return packet.pending_decision_digest.encode("ascii"), packet.packet_digest.encode("ascii")


def issue_on_process(process, *, raw, live_window, transport_deadline_ns, work):
    window = clock._validate(live_window)
    bound = min(window[4], transport_deadline_ns)
    owner, observed = _scope(process, raw, "issue", window, bound, work)
    owner.require_role("issuer")
    result = owners.SuccessorExecutionIssuer.issue(owner.issuer,
        **_packet_arguments(observed, raw, owner.root, window, bound, work))
    owner.check(work=work)
    preparation._current(window, bound, work)
    return result.pending_decision_digest.encode("ascii"), result.packet_digest.encode("ascii")


def execute_on_process(process, *, raw, live_window, transport_deadline_ns, work):
    window = clock._validate(live_window)
    bound = min(window[4], transport_deadline_ns)
    owner, observed = _scope(process, raw, "execute", window, bound, work)
    owner.require_role("executor")
    expected = packets._prepare_on_work(**_packet_arguments(observed, raw, owner.root, window, bound, work))
    pending, packet = expected.pending_decision_digest, expected.packet_digest
    caller.plan._same(raw[15:17], (pending.encode("ascii"), packet.encode("ascii")), work,
        "public revocation executor identifiers differ from original replay")
    owner.check(work=work)
    preparation._current(window, bound, work)
    try:
        result = owners.SuccessorExecutionExecutor.execute(owner.executor,
            pending_decision_digest=pending, packet_digest=packet, live_window=window,
            work=work, transport_deadline_ns=bound)
    except Exception:
        # The separate actual attempt may be durable even when SQL never
        # connected. Nothing in this unsigned response grants a retry.
        return b"uncertain", raw[15], raw[16], b""
    owner.check(work=work)
    preparation._current(window, bound, work)
    return b"observed-commit", raw[15], raw[16], result.marker_bytes


def complete_on_process(process, *, kind, raw, live_window, transport_deadline_ns, work):
    """Read actual committed state and deliver its exact completion, never SQL."""
    from catchplate import authority_public_revocation_recovery_authorization as read_authority
    if kind not in ("complete", "recover"):
        raise preparation.aggregate.PublicRevocationError("public revocation completion purpose is not fixed")
    window = clock._validate(live_window)
    bound = min(window[4], transport_deadline_ns)
    owner, observed = _scope(process, raw, kind, window, bound, work, historical=True)
    owner.require_role("executor")
    pending, sequence = _reserved(observed, raw, owner.root, window, bound, work,
        receipt=True, historical=True)
    try:
        actual_pending, packet = (item.decode("ascii") for item in raw[15:17])
    except UnicodeError as exc:
        raise preparation.aggregate.PublicRevocationError("public recovery locators are not ASCII") from exc
    caller.shape._digest(packet)
    caller.plan._same(actual_pending, pending, work, "public recovery pending original differs")
    enrollment = caller._admit_enrollment_on_work(authorization_enrollment_bytes=raw[2],
        current_root_enrollment_bytes=raw[0], grant_enrollment_bytes=raw[1], root_public_key=owner.root,
        configuration_digest=owner.configuration_digest,
        planner_public_key=observed.planner, evidence_public_key=observed.verifier, work=work)
    read_authority.verify(raw[17], enrollment=enrollment,
        configuration_digest=owner.configuration_digest,
        request_authorization_digest=observed.authorization.authorization_digest,
        pending_decision_digest=pending, packet_digest=packet,
        original_actor_id=observed.request["arguments"]["actor_id"], live_window=window,
        transport_deadline_ns=bound, work=work)
    owner.check(work=work)
    completed = recovery.recover_and_deliver(custody_reader=owner.recovery_reader,
        commit_reader=owner.commit_reader, delivery=owner.delivery, client=owner.state,
        operation=OPERATION, packet_digest=packet, expectations=observed.expectations,
        planner_public_key=observed.planner, operation_public_key=observed.verifier,
        root_public_key=owner.root, completion_private_key=owner.signer,
        expected_authorization_digest=observed.authorization.authorization_digest,
        expected_database_id=observed.authorization.database_id,
        expected_generation_digest=observed.authorization.generation_digest,
        expected_pending_sequence=sequence, expected_pending_head_digest=pending,
        expected_fence=observed.head["fence"] + 1,
        deadline_epoch_ns=window[3], live_window=window, transport_deadline_ns=bound, work=work)
    owner.check(work=work)
    retained = deliveries.CurrentRootCompletionDelivery._original_for_pending_on_work(owner.delivery,
        expected_pending_sequence=sequence, expected_pending_head_digest=pending, work=work)
    if retained is None or retained[0] != completed.request_digest:
        raise preparation.aggregate.PublicRevocationError("public completion lost its actual retained control")
    packet_raw = owners.SuccessorExecutionRecoveryReader.read(owner.recovery_reader,
        pending_decision_digest=pending, packet_digest=packet, live_window=window,
        transport_deadline_ns=bound, work=work)
    returned = (retained[1], completed.receipt_bytes, packet_raw)
    owner.check(work=work)
    verify_completion(configuration=owner.configuration_arguments(), raw=raw[:17],
        returned=returned, live_window=window, transport_deadline_ns=bound, work=work)
    owner.check(work=work)
    return returned


def verify_completion(*, configuration, raw, returned, live_window, transport_deadline_ns, work):
    """Authenticate terminal originals and return the genuinely replayed result.

    This receiver signs nothing and opens no writer. Expired original effects
    are historical inputs only; a completion receipt cannot authorize another
    reservation, execution or reactivation of a revoked credential/session.
    """
    from catchplate import authority_current_root_completion as completion
    from catchplate import authority_current_root_execution_admission as pending_admission
    from catchplate import authority_successor_execution_recovery_packet as recovery_packet

    raw = wire.originals("execute", raw)
    returned = wire.originals("complete", returned, response=True)
    window = clock._validate(live_window)
    bound = min(window[4], transport_deadline_ns)
    observed = preparation.verify_prepared(**configuration, originals=raw[:5], prepared=raw[5:11],
        live_window=window, transport_deadline_ns=bound, work=work, historical=True)
    root = configuration["root_public_key"]
    pending, sequence = _reserved(observed, raw, root, window, bound, work, receipt=True, historical=True)
    try:
        actual_pending, packet_id = (item.decode("ascii") for item in raw[15:17])
    except UnicodeError as exc:
        raise preparation.aggregate.PublicRevocationError("public terminal locators are not ASCII") from exc
    caller.shape._digest(packet_id)
    caller.plan._same(actual_pending, pending, work, "public terminal names another exact pending decision")
    packet = recovery_packet._decode_on_work(returned[2], expected_packet_digest=packet_id,
        expected_pending_decision_digest=pending, work=work)
    for actual, expected in ((packet.enrollment_bytes, raw[0]), (packet.grant_enrollment_bytes, raw[1]),
            (packet.grant_bytes, raw[11]), (packet.originals, raw[5:7]),
            (packet.reserve_request_bytes, raw[12]), (packet.snapshot_bytes, raw[13]),
            (packet.reserve_receipt_bytes, raw[14])):
        caller.plan._same(actual, expected, work, "public terminal packet changed a retained original")
    candidate, effects = pending_admission._admit_for_custody_completion_on_work(operation=OPERATION,
        originals=packet.originals, expectations=observed.expectations,
        planner_public_key=observed.planner, operation_public_key=observed.verifier,
        enrollment_bytes=raw[0], root_public_key=root, reserve_request_bytes=raw[12],
        reserve_receipt_bytes=raw[14], snapshot_bytes=raw[13],
        expected_database_id=observed.authorization.database_id,
        expected_generation_digest=observed.authorization.generation_digest,
        expected_pending_sequence=sequence, expected_pending_head_digest=pending,
        expected_fence=observed.head["fence"] + 1, live_window=window,
        transport_deadline_ns=bound, work=work)
    completion._verify_grant_on_work(candidate=candidate, grant_raw=raw[11], grant_enrollment=raw[1],
        enrollment=raw[0], root_public_key=root, planner_public_key=observed.planner,
        operation_public_key=observed.verifier,
        authorization_digest=observed.authorization.authorization_digest, work=work)
    completion._match_custody_on_work(payload=packet.payload, candidate=candidate,
        actual_effects_digest=effects, operation=OPERATION,
        authorization_digest=observed.authorization.authorization_digest, work=work)
    verified = delivery_records._verify_ack_on_work(request_bytes=returned[0], receipt_bytes=returned[1],
        enrollment_bytes=raw[0], root_public_key=root,
        expected_pending_sequence=sequence, expected_pending_head_digest=pending, work=work)
    for field, marker_field in (("enrollmentDigest", "enrollment_digest"), ("databaseId", "database_id"),
            ("generationDigest", "generation_digest"), ("operation", "operation"),
            ("pendingRequestDigest", "pending_request_digest"), ("pendingDecisionDigest", "pending_decision_digest"),
            ("fence", "fence"), ("snapshotDigest", "snapshot_digest"), ("resultDigest", "result_digest"),
            ("beforeVectorDigest", "before_vector_digest"), ("afterVectorDigest", "after_vector_digest")):
        caller.plan._same(verified.request_payload[field], candidate.marker[marker_field], work,
            "public completion differs from genuine committed-original scope " + field)
    preparation._current(window, bound, work)
    return observed.replayed.result
