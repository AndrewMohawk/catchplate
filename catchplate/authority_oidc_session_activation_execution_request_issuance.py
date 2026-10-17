"""Root-owned execution bootstrap production from actual request originals.

All observations are local intermediate outputs. Callers supply raw originals,
independent protected resource projections, root custody and their existing
work/window. A signed role bootstrap does not itself prove current SQL state.
"""
from __future__ import annotations

import hashlib
import secrets

from catchplate import authority_oidc_session_activation_request_issuance as request
from catchplate import control_plane_oidc_session_activation_request_dispatch as predecessors
from catchplate import oidc_session_activation_execution_authorizer_bootstrap as grant_role
from catchplate import oidc_session_activation_execution_reserver_bootstrap as reserve_role
from catchplate import oidc_session_activation_execution_sql_bootstrap as sql_role
from catchplate import oidc_session_activation_completion_bootstrap as completion_role

policy, state, plan = request.policy, request.authorization, request.plan


def _digest(raw, work):
    work.charge(hashes=1, input_bytes=len(raw))
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _original(raw, domain, work):
    wrapped = request._wrapped(raw, work)
    wrapped["identityDigest"] = plan._frame(domain, (raw,), work)
    return wrapped


def _admit(policy_bytes, originals, root, window, bound, work, continuity):
    raw = request._verify_planning_on_work(policy_bytes=policy_bytes, request_bytes=originals[0],
        originals=originals, root_public_key=root, live_window=window,
        transport_deadline_ns=bound, work=work, _continuity=continuity)
    admitted = policy._verify_on_work(policy_bytes=policy_bytes, root_public_key=root,
        live_window=window, transport_deadline_ns=bound, work=work, _continuity=continuity)
    asked = request._verify_request(raw[0], admitted, work, admitted.live)
    issued, expires = asked["issuedAtEpochNs"], asked["expiresAtEpochNs"]
    processing = request.planner._processing(window, min(bound, window[1] + expires - window[0]),
        work, _continuity=continuity)

    def current():
        first = admitted.live()
        now = processing()
        if now < first or not issued <= now < expires:
            raise ValueError("execution issuance exhausted the original signed request")
        return now

    current()
    planned = request.planner._verify_on_work(bootstrap_bytes=raw[3], root_public_key=root,
        live_window=window, transport_deadline_ns=bound, work=work)
    current()
    enrollment = planned.state_enrollment_bytes
    enrolled = state._admit_enrollment_on_work(enrollment_bytes=enrollment, root_public_key=root, work=work)
    context = plan._frame(request.REQUEST_IDENTITY_DOMAIN, (raw[0],), work)
    predecessor = predecessors._predecessor_on_work(query_bytes=raw[1], observation_bytes=raw[2],
        enrollment_bytes=enrollment, root_public_key=root, expected_context_digest=context,
        before_vector_bytes=planned.complete_root_vector_bytes, now_epoch_ns=current(), work=work)
    current()
    return raw, admitted, planned, enrolled, predecessor, (issued, expires), current


def _base(module, admitted, planned, enrolled, interval, projection, work):
    resource = policy._capture(projection, work)
    wrapped = {}
    for name, raw, domain in (
            ("currentRootEnrollment", planned.state_enrollment_bytes, state.ENROLLMENT_IDENTITY_DOMAIN),
            ("grantEnrollment", admitted.grant_enrollment, module.grants.ENROLLMENT_IDENTITY_DOMAIN),
            ("authorizationEnrollment", admitted.authorization_enrollment, module.caller.ENROLLMENT_IDENTITY_DOMAIN)):
        wrapped[name] = _original(raw, domain, work)
    payload = dict(schema=module.PAYLOAD_SCHEMA, sourceRevision=policy.authority.SOURCE_REVISION,
        role=module.ROLE, operation=module.OPERATION, configurationDigest=planned.configuration_digest,
        generationDigest=planned.generation["digest"], runtimeClosureDigest=planned.runtime_closure_digest,
        databaseId=enrolled.payload["databaseId"], issuedAtEpochNs=interval[0], expiresAtEpochNs=interval[1],
        trustMode="trusted-host-local", launch=resource["launch"], **wrapped,
        **{name: False for name in module._FALSE_FIELDS})
    return payload, resource


def _custody(payload, original, receiver, work):
    payload["receivingCustody"] = dict(byteCount=len(original), bytesDigest=_digest(original, work))
    payload["receiverIdentity"] = receiver


def _produce_initial_on_work(*, policy_bytes, planning_originals, projections,
        root_private_key, root_public_key, live_window, transport_deadline_ns, work, _continuity):
    """Genuine authorizer/reserver originals, before any app grant request."""
    if type(projections) is not dict or set(projections) != {"activation-authorizer", "activation-reserver"}:
        raise ValueError("execution issuance needs exact independently owned initial resources")
    projections = policy._capture(projections, work)
    raw, admitted, planned, enrolled, predecessor, interval, current = _admit(policy_bytes,
        planning_originals, root_public_key, live_window, transport_deadline_ns, work, _continuity)
    result = []
    for role, module, custody_index, consumer in (
            ("activation-authorizer", grant_role, 4, "grant"),
            ("activation-reserver", reserve_role, 5, "reserve")):
        payload, resource = _base(module, admitted, planned, enrolled, interval, projections[role], work)
        plan._same(resource["receiverIdentity"], admitted.payload["receiverIdentities"][consumer],
            work, "execution issuance independently retained receiver")
        _custody(payload, raw[custody_index], admitted.payload["receiverIdentities"][consumer], work)
        if module is grant_role:
            grant = module.grants._admit_enrollment_on_work(grant_enrollment_bytes=admitted.grant_enrollment,
                current_root_enrollment_bytes=planned.state_enrollment_bytes, root_public_key=root_public_key, work=work)
            producer = grant.payload["authorizer"]
            payload.update(authorizerSpkiDigest=producer["spkiDigest"],
                authorizerMeasurementDigest=producer["measurementDigest"])
        else:
            producer = enrolled.payload["computation"]
            payload.update(computationSpkiDigest=producer["spkiDigest"],
                computationMeasurementDigest=producer["measurementDigest"],
                statePredecessor=dict(sequence=predecessor[0], headDigest=predecessor[1], nextFence=predecessor[2]),
                reservationCheckpoint=resource["checkpoint"], stateEndpoint=resource["stateEndpoint"])
        current()
        bootstrap = module._produce_on_work(payload=payload, custody_bytes=raw[custody_index],
            root_private_key=root_private_key, root_public_key=root_public_key, work=work,
            live_window=live_window, transport_deadline_ns=transport_deadline_ns)
        current()
        result.append((role, (bootstrap, raw[custody_index])))
    current()
    return tuple(result)


def _pending_on_work(raw8, admitted, planned, enrolled, predecessor, root, window, bound, work, current):
    """Public signatures/ancestry plus fresh actual nonce-bound pending head."""
    from catchplate import authority_oidc_session_activation_sql_transport as wire
    from catchplate import authority_oidc_session_activation_execution_authorization as caller
    from catchplate import authority_oidc_session_activation_reservation_records as records
    raw = wire._originals(raw8, response=False)
    expected = caller.expectations_wire._capture_on_work(caller.authorization.wire._decode_object(raw[3],
        work=work, maximum_bytes=caller.expectations_wire.MAX_BYTES,
        maximum_nodes=caller.expectations_wire.MAX_NODES, maximum_depth=12), work=work)
    canonical = caller.expectations_wire.registration._wire(expected, work)
    work.charge(input_bytes=len(raw[3]) + len(canonical))
    if raw[3] != canonical:
        raise ValueError("execution issuance expectations are not exact canonical originals")
    held = caller._capture_on_work(authorization_enrollment_bytes=admitted.authorization_enrollment,
        current_root_enrollment_bytes=planned.state_enrollment_bytes,
        grant_enrollment_bytes=admitted.grant_enrollment, root_public_key=root,
        planner_public_key=planned.planner_public_key, operation_public_key=root,
        configuration_digest=planned.configuration_digest, originals=raw[1:3], expectations=expected,
        before_vector_bytes=planned.complete_root_vector_bytes, live_window=window,
        transport_deadline_ns=bound, work=work, extra_originals=(raw[0],))
    authorized = caller._verify_held_on_work(held, raw[0], work, current=caller._clock(held, work))
    current()
    grant, grant_digest = caller.grants._verify_control_on_work(grant_bytes=raw[4],
        grant_enrollment_bytes=admitted.grant_enrollment,
        current_root_enrollment_bytes=planned.state_enrollment_bytes, root_public_key=root,
        planner_public_key=planned.planner_public_key, operation_public_key=root,
        expected_authorization_digest=authorized.authorization_digest, now_epoch_ns=current(), work=work)
    for field, wanted in (("operation", caller.OPERATION), ("requestDigest", authorized.request_digest),
            ("operationId", authorized.operation_id), ("planDigest", authorized.plan_digest),
            ("retainedRecordDigest", authorized.retained_record_digest),
            ("beforeVectorDigest", authorized.before_vector_digest)):
        plan._same(grant[field], wanted, work, "execution issuance exact grant " + field)
    frames = [dict(position=position, byteCount=len(original), bytesDigest=_digest(original, work))
        for position, original in enumerate(held.originals)]
    plan._same(grant["originalFrames"], frames, work, "execution issuance exact grant original frames")
    if not (grant["issuedAtEpochNs"] <= authorized.issued_at_epoch_ns
            < authorized.expires_at_epoch_ns <= grant["originalExpiresAtEpochNs"]
            and grant["expiresAtEpochNs"] <= authorized.expires_at_epoch_ns):
        raise ValueError("execution issuance grant renews original caller permission")
    reserve, reserve_digest, receipt, receipt_digest = records._verify_on_work(
        request_bytes=raw[5], snapshot_bytes=raw[6], receipt_bytes=raw[7],
        enrollment_bytes=planned.state_enrollment_bytes, root_public_key=root,
        expected_predecessor_sequence=predecessor[0], expected_predecessor_head_digest=predecessor[1],
        expected_fence=predecessor[2], work=work)
    if receipt is None or receipt_digest is None:
        raise ValueError("execution issuance requires the actual signed reserve acknowledgment")
    for field, wanted in (("capabilityDigest", grant_digest), ("requestDigest", authorized.request_digest),
            ("operationId", authorized.operation_id), ("databaseId", enrolled.payload["databaseId"]),
            ("generationDigest", enrolled.payload["generationDigest"])):
        plan._same(reserve[field], wanted, work, "execution issuance exact original reserve " + field)
    before = state.vector._encode_on_work(reserve["beforeVector"], work=work)
    after = state.vector._encode_on_work(reserve["afterVector"], work=work)
    for field, vector in (("beforeVectorDigest", before), ("afterVectorDigest", after)):
        plan._same(state.vector._digest_on_work(vector, work=work), grant[field], work,
            "execution issuance original reserve/grant vector")
    work.charge(input_bytes=len(before) + len(planned.complete_root_vector_bytes))
    if before != planned.complete_root_vector_bytes:
        raise ValueError("execution issuance reserve differs from the root-admitted before vector")
    context = plan._frame("catchplate.oidcSessionActivationExecutionPendingQuery/v1", raw, work)
    work.charge(input_bytes=96)
    nonce = policy.production._callback(work, lambda: secrets.token_hex(32))
    query = request.head._encode_query_on_work(enrollment_digest=enrolled.enrollment_digest,
        context_digest=context, expected_vector_digest=grant["beforeVectorDigest"], challenge=nonce, work=work)
    work.charge(input_bytes=2 * len(query) + 2 * request.head.MAX_BYTES + 32)
    current()
    observed = policy.production._callback(work, lambda: request.state_transport._head_on_configuration(
        request.planner._state_endpoint(admitted.payload["plannerResources"]["stateEndpoint"]),
        query_bytes=query, deadline_ns=bound))
    current()
    actual = request.head._verify_on_work(observation_bytes=observed, query_bytes=query,
        enrollment_bytes=planned.state_enrollment_bytes, root_public_key=root,
        now_epoch_ns=current(), work=work)
    for field, wanted in (("sequence", predecessor[0] + 1), ("headDigest", receipt_digest),
            ("fence", predecessor[2]), ("pendingRequestDigest", reserve_digest),
            ("pendingDecisionDigest", receipt_digest)):
        plan._same(actual[field], wanted, work, "execution issuance actual pending head " + field)
    interval = reserve["issuedAtEpochNs"], min(reserve["expiresAtEpochNs"], grant["expiresAtEpochNs"])

    def live():
        now = current()
        if not interval[0] <= now < min(interval[1], actual["expiresAtEpochNs"]):
            raise ValueError("execution issuance pending head or original request expired")
        return now

    live()
    return raw, expected, authorized.authorization_digest, dict(sequence=actual["sequence"],
        headDigest=actual["headDigest"], fence=actual["fence"]), interval, live


def _produce_sql_on_work(*, policy_bytes, planning_originals, request_originals, projection,
        root_private_key, root_public_key, live_window, transport_deadline_ns, work, _continuity):
    projection = policy._capture(projection, work)
    raw, admitted, planned, enrolled, predecessor, _interval, current = _admit(policy_bytes,
        planning_originals, root_public_key, live_window, transport_deadline_ns, work, _continuity)
    _request, _expected, _authorization, pending, interval, live = _pending_on_work(request_originals,
        admitted, planned, enrolled, predecessor, root_public_key, live_window,
        transport_deadline_ns, work, current)
    payload, resource = _base(sql_role, admitted, planned, enrolled, interval, projection, work)
    plan._same(resource["receiverIdentity"], admitted.payload["receiverIdentities"]["sql-issuer"],
        work, "execution SQL issuance independently retained receiver")
    _custody(payload, raw[6], admitted.payload["receiverIdentities"]["sql-issuer"], work)
    payload.update(statePredecessor=dict(sequence=predecessor[0], headDigest=predecessor[1], nextFence=predecessor[2]),
        currentPending=pending, attemptCheckpoint=resource["checkpoint"])
    for name in ("databaseEndpoint", "sqlRoles", "queryManifestDigest", "structureManifestDigest", "tlsFiles"):
        payload[name] = resource[name]
    live()
    result = sql_role._produce_on_work(payload=payload, custody_bytes=raw[6],
        root_private_key=root_private_key, root_public_key=root_public_key, work=work,
        live_window=live_window, transport_deadline_ns=transport_deadline_ns)
    live()
    return result, raw[6]


def _produce_completion_on_work(*, policy_bytes, planning_originals, request_originals,
        sql_response_originals, projection, root_private_key, root_public_key,
        live_window, transport_deadline_ns, work, _continuity):
    """Bind a real SQL-returned locator, never treat its outcome as a verdict.

    The completion worker must still independently read the exact protected
    packet and normally closed commit evidence. No completed effects, token or
    state transition is derived from the unsigned SQL outcome here.
    """
    from catchplate import authority_oidc_session_activation_sql_transport as wire
    from catchplate import oidc_session_activation_history_custody_bootstrap as history
    projection = policy._capture(projection, work)
    raw, admitted, planned, enrolled, predecessor, _interval, current = _admit(policy_bytes,
        planning_originals, root_public_key, live_window, transport_deadline_ns, work, _continuity)
    actual, expected, authorization_digest, pending, interval, live = _pending_on_work(request_originals,
        admitted, planned, enrolled, predecessor, root_public_key, live_window,
        transport_deadline_ns, work, current)
    outcome = wire._originals(sql_response_originals, response=True)
    if len(outcome[1]) != 71 or len(outcome[2]) != 71:
        raise ValueError("completion issuance lacks an actual native SQL custody locator")
    work.charge(input_bytes=142)
    pending_digest, packet_digest = outcome[1].decode("ascii"), outcome[2].decode("ascii")
    policy.shape._digest(packet_digest)
    plan._same(pending_digest, pending["headDigest"], work,
        "completion locator differs from the fresh same-request pending head")
    payload, resource = _base(completion_role, admitted, planned, enrolled, interval, projection, work)
    receiver = resource["receiverIdentity"]
    custody_payload = dict(schema=history.PAYLOAD_SCHEMA, sourceRevision=policy.authority.SOURCE_REVISION,
        operation=history.OPERATION, consumerRole=history.CONSUMER_ROLE, processMode=history.PROCESS_MODE,
        serviceUid=history.SERVICE_UID, serviceGid=history.SERVICE_GID, receiverIdentity=receiver,
        configurationDigest=planned.configuration_digest, generationDigest=planned.generation["digest"],
        runtimeClosureDigest=planned.runtime_closure_digest,
        bundleKeyDigest=admitted.payload["plannerResources"]["bundleKeyDigest"],
        deliveryKeyDigest=admitted.payload["plannerResources"]["deliveryKeyDigest"],
        plannerBootstrap=request._wrapped(raw[3], work), issuedAtEpochNs=interval[0],
        expiresAtEpochNs=interval[1], trustMode="trusted-host-local",
        **{name: False for name in history._FALSE_FIELDS})
    live()
    historical = history._produce_on_work(payload=custody_payload, root_private_key=root_private_key,
        root_public_key=root_public_key, work=work, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns)
    live()
    producer = enrolled.payload["completion"]
    payload.update(historicalCustody=request._wrapped(historical, work), receiverIdentity=receiver,
        authorization=_original(actual[0], completion_role.caller.REQUEST_IDENTITY_DOMAIN, work),
        completionSpkiDigest=producer["spkiDigest"], completionMeasurementDigest=producer["measurementDigest"],
        currentPending=pending, completionCheckpoint=resource["checkpoint"], stateEndpoint=resource["stateEndpoint"],
        packetDigest=packet_digest, authorizationDigest=authorization_digest, replayExpectations=expected)
    for name in ("databaseEndpoint", "sqlRoles", "queryManifestDigest", "structureManifestDigest", "tlsFiles"):
        payload[name] = resource[name]
    result = completion_role._produce_on_work(payload=payload, root_private_key=root_private_key,
        root_public_key=root_public_key, work=work, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns)
    live()
    return result
