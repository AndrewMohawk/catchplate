"""Issue fixed consume worker originals from the actual admitted request pair.

This root-owned continuation authenticates public originals and queries the
actual state service. It does not replace the workers' private replay, native
SQL admission, protected packet readback or completion acknowledgment.
"""
from __future__ import annotations

import hashlib
import secrets

from catchplate import authority_oidc_session_activation_request_issuance as request
from catchplate import authority_oidc_session_activation_delivery_execution_authorization as caller
from catchplate import authority_oidc_session_activation_delivery_execution_grant as grant_wire
from catchplate import authority_oidc_session_activation_delivery_execution_grant_admission as grant_admission
from catchplate import authority_oidc_session_activation_delivery_reservation_records as records
from catchplate import authority_oidc_session_activation_delivery_sql_transport as wire
from catchplate import control_plane_oidc_session_activation_request_dispatch as predecessors
from catchplate import oidc_session_activation_consume_input_delivery_admission as delivery
from catchplate import oidc_session_activation_delivery_execution_authorizer_bootstrap as grant_role
from catchplate import oidc_session_activation_delivery_execution_reserver_bootstrap as reserve_role
from catchplate import oidc_session_activation_delivery_execution_sql_bootstrap as sql_role
from catchplate import oidc_session_activation_delivery_completion_bootstrap as completion_role
from catchplate import oidc_session_activation_delivery_completion_custody_bootstrap as completion_custody

state, plan, shape = request.authorization, request.plan, request.shape
receiving, history = grant_role.receiving, grant_role.history_bootstrap


def _detached(raw, work):
    work.charge(hashes=1, input_bytes=len(raw))
    return {"byteCount": len(raw), "bytesDigest": "sha256:" + hashlib.sha256(raw).hexdigest()}


class _Request:
    """Private same-call owner; public functions only accept raw originals."""

    def __init__(self, policy_bytes, planning_originals, activation_planner_bytes,
            grant_enrollment_bytes, authorization_enrollment_bytes, root_private_key,
            root_public_key, live_window, transport_deadline_ns, work, continuity):
        if type(planning_originals) is not tuple or len(planning_originals) != 2:
            raise ValueError("consume execution issuance requires the actual planner/history raw2")
        self.grant_raw = state._original(grant_enrollment_bytes,
            grant_role.grants.MAX_ENROLLMENT_BYTES, "consume grant enrollment")
        self.caller_raw = state._original(authorization_enrollment_bytes,
            caller.MAX_ENROLLMENT_BYTES, "consume caller enrollment")
        self.private, self.root, self.work = root_private_key, root_public_key, work
        work.charge(input_bytes=128 * 1024 + len(self.grant_raw) + len(self.caller_raw), json_nodes=4096)
        self.admitted = delivery._verify_on_work(planner_bootstrap_bytes=planning_originals[0],
            history_custody_bytes=planning_originals[1], issuer_policy_bytes=policy_bytes,
            activation_planner_bootstrap_bytes=activation_planner_bytes, root_public_key=self.root,
            live_window=live_window, transport_deadline_ns=transport_deadline_ns, work=work,
            _continuity=continuity)
        policy = self.admitted.issuer_policy_material
        if (policy.request_bound is not True or policy.payload["schema"] != delivery.issuer.V3_PAYLOAD_SCHEMA
                or policy.bridge is not None or policy.activation_predecessor is not None):
            raise ValueError("consume request issuance requires the explicit same-root resource-only v3 policy")
        self.planned = self.admitted.planner_material
        self.raw = (self.admitted.planner_bootstrap_bytes, self.admitted.history_custody_bytes)
        self.window, self.bound = self.admitted.live_window, self.admitted.deadline_ns
        self.interval = self.planned.attestation_interval
        self.live()
        self.enrolled = state._admit_enrollment_on_work(
            enrollment_bytes=self.planned.state_enrollment_bytes, root_public_key=self.root, work=work)
        self.grant = grant_role.grants._admit_enrollment_on_work(grant_enrollment_bytes=self.grant_raw,
            current_root_enrollment_bytes=self.planned.state_enrollment_bytes,
            root_public_key=self.root, work=work)
        self.caller = caller._admit_enrollment_on_work(authorization_enrollment_bytes=self.caller_raw,
            current_root_enrollment_bytes=self.planned.state_enrollment_bytes,
            grant_enrollment_bytes=self.grant_raw, root_public_key=self.root,
            configuration_digest=self.planned.payload["configurationDigest"],
            planner_public_key=self.planned.planner_public_key, operation_public_key=self.root, work=work)
        self.live()

    def live(self):
        now = self.admitted.live()
        if not self.interval[0] <= now < self.interval[1]:
            raise ValueError("consume issuance exhausted its original planner interval")
        return now

    def observe(self, context, current):
        """One genuine nonce-bound state observation, never an incoming head."""
        work, planned = self.work, self.planned
        current()
        work.charge(input_bytes=96)
        nonce = request.production._callback(work, lambda: secrets.token_hex(32))
        query = request.head._encode_query_on_work(enrollment_digest=self.enrolled.enrollment_digest,
            context_digest=context, expected_vector_digest=planned.complete_root_vector_digest,
            challenge=nonce, work=work)
        work.charge(input_bytes=2 * len(query) + 2 * request.head.MAX_BYTES + 32)
        current()
        original = request.production._callback(work,
            lambda: request.state_transport._head_on_configuration(planned.state_endpoint,
                query_bytes=query, deadline_ns=self.bound))
        current()
        observed = request.head._verify_on_work(observation_bytes=original, query_bytes=query,
            enrollment_bytes=planned.state_enrollment_bytes, root_public_key=self.root,
            now_epoch_ns=current(), work=work)
        plan._same(observed["vectorDigest"], planned.complete_root_vector_digest, work,
            "consume issuance actual state differs from the admitted before vector")
        current()
        return query, original, observed

    def base(self, module, interval, resource):
        work, configured = self.work, self.planned.payload
        originals = {}
        for name, raw, domain in (
                ("currentRootEnrollment", self.planned.state_enrollment_bytes, state.ENROLLMENT_IDENTITY_DOMAIN),
                ("grantEnrollment", self.grant_raw, grant_role.grants.ENROLLMENT_IDENTITY_DOMAIN),
                ("authorizationEnrollment", self.caller_raw, caller.ENROLLMENT_IDENTITY_DOMAIN)):
            originals[name] = request._wrapped(raw, work, domain)
        return dict(schema=module.PAYLOAD_SCHEMA, sourceRevision=request.policy.authority.SOURCE_REVISION,
            role=module.ROLE, operation=module.OPERATION, configurationDigest=configured["configurationDigest"],
            generationDigest=configured["generation"]["digest"], runtimeClosureDigest=configured["runtimeClosureDigest"],
            databaseId=self.enrolled.payload["databaseId"], issuedAtEpochNs=interval[0], expiresAtEpochNs=interval[1],
            trustMode="trusted-host-local", launch=resource["launch"], **originals,
            **{name: False for name in module._FALSE_FIELDS})

    def custody(self, purpose, interval, receiver, current):
        """Produce genuine purpose-specific history and detached receiving custody."""
        work, planned = self.work, self.planned
        if purpose == "completion":
            module, profile = completion_custody, (completion_custody.PAYLOAD_SCHEMA,
                completion_custody.PROCESS_MODE, completion_custody.SERVICE_UID,
                completion_custody.SERVICE_GID, history.CONSUME_COMPLETION_CONSUMER_ROLE)
            produce = completion_custody._produce_on_work
            produce_history = history._produce_consume_completion_on_work
            consumer = completion_custody.CONSUMER_ROLE
        else:
            module = receiving
            _schema, payload_schema, mode, uid, gid, history_role = receiving._profile(purpose)
            profile = payload_schema, mode, uid, gid, history_role
            consumer = purpose
            produce, produce_history = {
                "grant": (receiving._produce_on_work, history._produce_consume_grant_on_work),
                "reserve": (receiving._produce_reserve_on_work, history._produce_consume_reserve_on_work),
                "sql-issuer": (receiving._produce_sql_issuer_on_work, history._produce_consume_sql_issuer_on_work),
            }[purpose]
        payload_schema, mode, uid, gid, history_role = profile
        _schema, history_schema, operation, role, history_mode, history_uid, history_gid = history._purpose_profile(history_role)
        nested = planned.history_material
        historical_payload = dict(schema=history_schema, sourceRevision=request.policy.authority.SOURCE_REVISION,
            operation=operation, consumerRole=role, processMode=history_mode,
            serviceUid=history_uid, serviceGid=history_gid, receiverIdentity=receiver,
            configurationDigest=nested.planner.configuration_digest,
            generationDigest=nested.planner.generation["digest"], runtimeClosureDigest=nested.planner.runtime_closure_digest,
            bundleKeyDigest=nested.bundle_key_digest, deliveryKeyDigest=nested.delivery_key_digest,
            plannerBootstrap=request._wrapped(nested.planner.bootstrap_bytes, work),
            consumeRequest=request._wrapped(planned.consume_request_bytes, work),
            issuedAtEpochNs=interval[0], expiresAtEpochNs=interval[1], trustMode="trusted-host-local",
            **{name: False for name in history._FALSE_FIELDS})
        current()
        historical = produce_history(payload=historical_payload, root_private_key=self.private,
            root_public_key=self.root, live_window=self.window, transport_deadline_ns=self.bound, work=work)
        current()
        configured = planned.payload
        payload = dict(schema=payload_schema, sourceRevision=request.policy.authority.SOURCE_REVISION,
            operation=module.OPERATION, consumerRole=consumer, processMode=mode, serviceUid=uid, serviceGid=gid,
            receiverIdentity=receiver, configurationDigest=configured["configurationDigest"],
            generationDigest=configured["generation"]["digest"], runtimeClosureDigest=configured["runtimeClosureDigest"],
            executionBundleKeyDigest=planned.execution_bundle_key_digest,
            historicalBundleKeyDigest=nested.bundle_key_digest, deliveryKeyDigest=nested.delivery_key_digest,
            plannerBootstrap=_detached(self.raw[0], work), plannerHistoryCustody=_detached(self.raw[1], work),
            receivingHistoryCustody=_detached(historical, work), consumeRequest=_detached(planned.consume_request_bytes, work),
            issuedAtEpochNs=interval[0], expiresAtEpochNs=interval[1], trustMode="trusted-host-local",
            **{name: False for name in module._FALSE_FIELDS})
        current()
        custody = produce(payload=payload, planner_bootstrap_bytes=self.raw[0],
            planner_history_custody_bytes=self.raw[1], receiving_history_custody_bytes=historical,
            root_private_key=self.private, root_public_key=self.root, live_window=self.window,
            transport_deadline_ns=self.bound, work=work)
        current()
        return custody, self.raw[0], self.raw[1], historical

    def role(self, module, payload, originals, current):
        for (name, _maximum), raw in zip(module._DETACHED_LIMITS, originals):
            payload[name] = _detached(raw, self.work)
        current()
        bootstrap = module._produce_on_work(payload=payload, custody_bytes=originals[0],
            planner_bootstrap_bytes=originals[1], planner_history_custody_bytes=originals[2],
            receiving_history_custody_bytes=originals[3], root_private_key=self.private,
            root_public_key=self.root, live_window=self.window, transport_deadline_ns=self.bound, work=self.work)
        current()
        return (bootstrap, *originals)


def _produce_initial_on_work(*, policy_bytes, planning_originals, activation_planner_bytes,
        grant_enrollment_bytes, authorization_enrollment_bytes, projections, root_private_key,
        root_public_key, live_window, transport_deadline_ns, work, _continuity):
    if type(projections) is not dict or set(projections) != {"consume-authorizer", "consume-reserver"}:
        raise ValueError("consume issuance needs its exact independently retained initial resources")
    resources = request.policy._capture(projections, work)
    held = _Request(policy_bytes, planning_originals, activation_planner_bytes, grant_enrollment_bytes,
        authorization_enrollment_bytes, root_private_key, root_public_key, live_window,
        transport_deadline_ns, work, _continuity)
    context = plan._frame("catchplate.oidcSessionActivationConsumeIssuanceHead/v1", held.raw, work)
    query, observed, head = held.observe(context, held.live)
    predecessor = predecessors._predecessor_on_work(query_bytes=query, observation_bytes=observed,
        enrollment_bytes=held.planned.state_enrollment_bytes, root_public_key=root_public_key,
        expected_context_digest=context, before_vector_bytes=held.planned.complete_root_vector_bytes,
        now_epoch_ns=held.live(), work=work)
    # The root-admitted pair contains the actual activation reserve scope;
    # only its immediately following COMPLETE can be this consume predecessor.
    scope = held.planned.payload["activationScope"]
    plan._same((predecessor[0], predecessor[2]),
        (scope["pendingSequence"] + 1, scope["fence"] + 1), work,
        "consume issuance actual head follows its exact activation completion")

    def current():
        now = held.live()
        if now >= head["expiresAtEpochNs"]:
            raise ValueError("consume issuance original state observation expired")
        return now

    result = []
    for role, module, purpose in (("consume-authorizer", grant_role, "grant"),
            ("consume-reserver", reserve_role, "reserve")):
        resource = resources[role]
        payload = held.base(module, held.interval, resource)
        payload["receiverIdentity"] = resource["receiverIdentity"]
        if purpose == "grant":
            key = held.grant.payload["authorizer"]
            payload.update(authorizerSpkiDigest=key["spkiDigest"], authorizerMeasurementDigest=key["measurementDigest"])
        else:
            key = held.enrolled.payload["computation"]
            payload.update(computationSpkiDigest=key["spkiDigest"], computationMeasurementDigest=key["measurementDigest"],
                statePredecessor=dict(sequence=predecessor[0], headDigest=predecessor[1], nextFence=predecessor[2]),
                reservationCheckpoint=resource["checkpoint"], stateEndpoint=resource["stateEndpoint"])
        originals = held.custody(purpose, held.interval, resource["receiverIdentity"], current)
        result.append((role, held.role(module, payload, originals, current)))
    current()
    return tuple(result)


def _pending(held, request_originals):
    """Authenticate public raw8 controls; private proof replay remains native."""
    work, planned = held.work, held.planned
    raw = wire._originals(request_originals, response=False)
    expected = caller.expectations_wire._capture_on_work(state.wire._decode_object(raw[3], work=work,
        maximum_bytes=caller.expectations_wire.MAX_BYTES, maximum_nodes=caller.expectations_wire.MAX_NODES,
        maximum_depth=12), work=work)
    canonical = caller.expectations_wire.registration._wire(expected, work)
    work.charge(input_bytes=len(raw[3]) + len(canonical))
    if raw[3] != canonical:
        raise ValueError("consume execution expectations are not canonical originals")
    captured = caller._capture_on_work(originals=raw[1:3], expectations=expected,
        before_vector_bytes=planned.complete_root_vector_bytes, authorization_enrollment_bytes=held.caller_raw,
        current_root_enrollment_bytes=planned.state_enrollment_bytes, grant_enrollment_bytes=held.grant_raw,
        root_public_key=held.root, configuration_digest=planned.payload["configurationDigest"],
        planner_public_key=planned.planner_public_key, operation_public_key=held.root,
        live_window=held.window, transport_deadline_ns=held.bound, work=work, extra_originals=(raw[0],))
    authorized = caller._verify_held_on_work(captured, raw[0], work)
    held.live()
    grant, grant_digest = grant_wire._verify_signature_on_work(raw[4], held.grant.authorizer_public_key, work)
    bindings = dict(grantEnrollmentDigest=held.grant.enrollment_digest,
        currentRootEnrollmentDigest=held.enrolled.enrollment_digest,
        configurationDigest=planned.payload["configurationDigest"], databaseId=held.enrolled.payload["databaseId"],
        generationDigest=held.enrolled.payload["generationDigest"],
        authorizerMeasurementDigest=held.grant.payload["authorizer"]["measurementDigest"],
        requestDigest=authorized.request_digest, operationId=authorized.operation_id,
        requestAuthorizationDigest=authorized.authorization_digest, journalDigest=authorized.journal_digest,
        retainedRecordDigest=authorized.retained_record_digest, planDigest=authorized.plan_digest,
        beforeVectorDigest=authorized.before_vector_digest, originalFrames=grant_admission._frames(raw[1:3], work))
    for field, wanted in bindings.items():
        plan._same(grant[field], wanted, work, "consume issuance signed grant " + field)
    # Derive predecessor from the real signed reserve, not a new idle query
    # (the state is already pending at this stage).
    _enrolled, signed, signed_digest = state._verify_request_on_work(request_bytes=raw[5],
        enrollment_bytes=planned.state_enrollment_bytes, root_public_key=held.root,
        now_epoch_ns=held.live(), work=work)
    predecessor = records._predecessor_scope(signed["predecessorSequence"],
        signed["predecessorHeadDigest"], signed["fence"])
    scope = planned.payload["activationScope"]
    plan._same((predecessor[0], predecessor[2]),
        (scope["pendingSequence"] + 1, scope["fence"] + 1), work,
        "consume issuance signed reserve follows the actual activation scope")
    reserve, reserve_digest, receipt, receipt_digest = records._verify_on_work(request_bytes=raw[5],
        snapshot_bytes=raw[6], receipt_bytes=raw[7], enrollment_bytes=planned.state_enrollment_bytes,
        root_public_key=held.root, expected_predecessor_sequence=predecessor[0],
        expected_predecessor_head_digest=predecessor[1], expected_fence=predecessor[2], work=work)
    if receipt is None or receipt_digest is None:
        raise ValueError("consume issuance needs an actual post-activation reserve acknowledgment")
    plan._same(reserve_digest, signed_digest, work, "consume issuance exact reserve original")
    for field, wanted in (("capabilityDigest", grant_digest), ("requestDigest", authorized.request_digest),
            ("operationId", authorized.operation_id), ("databaseId", held.enrolled.payload["databaseId"]),
            ("generationDigest", held.enrolled.payload["generationDigest"])):
        plan._same(reserve[field], wanted, work, "consume issuance exact reserve " + field)
    for name in ("beforeVector", "afterVector"):
        vector = state.vector._encode_on_work(reserve[name], work=work)
        plan._same(state.vector._digest_on_work(vector, work=work), grant[name + "Digest"], work,
            "consume issuance reserve and grant vectors")
        if name == "beforeVector":
            receiving._same_bytes(vector, planned.complete_root_vector_bytes, work,
                "consume issuance independently admitted before vector")
    interval = reserve["issuedAtEpochNs"], min(reserve["expiresAtEpochNs"], grant["expiresAtEpochNs"])
    if (interval[0] != grant["issuedAtEpochNs"]
            or not held.interval[0] <= interval[0] < interval[1] <= held.interval[1]
            or grant["expiresAtEpochNs"] > authorized.expires_at_epoch_ns):
        raise ValueError("consume issuance reserve/grant extends its original authority")

    def current():
        first = held.live()
        now, _mono = authorized.live()
        if now < first or not interval[0] <= now < interval[1]:
            raise ValueError("consume issuance original request expired or reversed")
        caller.evidence._fresh(grant, now, held.grant.payload["maximumGrantAgeNs"], held.window[6])
        return now

    context = plan._frame("catchplate.oidcSessionActivationConsumePendingQuery/v1", raw, work)
    _query, _original, observed = held.observe(context, current)
    for field, wanted in (("sequence", predecessor[0] + 1), ("headDigest", receipt_digest),
            ("fence", predecessor[2]), ("pendingRequestDigest", reserve_digest),
            ("pendingDecisionDigest", receipt_digest)):
        plan._same(observed[field], wanted, work, "consume issuance actual pending head " + field)

    def live():
        now = current()
        if now >= observed["expiresAtEpochNs"]:
            raise ValueError("consume issuance original pending observation expired")
        return now

    live()
    return raw, expected, authorized.authorization_digest, predecessor, dict(sequence=observed["sequence"],
        headDigest=observed["headDigest"], fence=observed["fence"]), interval, live


def _produce_sql_on_work(*, policy_bytes, planning_originals, activation_planner_bytes,
        grant_enrollment_bytes, authorization_enrollment_bytes, request_originals, projection,
        root_private_key, root_public_key, live_window, transport_deadline_ns, work, _continuity):
    resource = request.policy._capture(projection, work)
    raw = wire._originals(request_originals, response=False)
    held = _Request(policy_bytes, planning_originals, activation_planner_bytes, grant_enrollment_bytes,
        authorization_enrollment_bytes, root_private_key, root_public_key, live_window,
        transport_deadline_ns, work, _continuity)
    _raw, _expected, _authorization, predecessor, pending, interval, current = _pending(held, raw)
    payload = held.base(sql_role, interval, resource)
    payload.update(receiverIdentity=resource["receiverIdentity"], beforeVectorDigest=held.planned.complete_root_vector_digest,
        statePredecessor=dict(sequence=predecessor[0], headDigest=predecessor[1], nextFence=predecessor[2]),
        currentPending=pending, attemptCheckpoint=resource["checkpoint"])
    for name in ("databaseEndpoint", "sqlRoles", "queryManifestDigest", "structureManifestDigest", "tlsFiles"):
        payload[name] = resource[name]
    originals = held.custody("sql-issuer", interval, resource["receiverIdentity"], current)
    return held.role(sql_role, payload, originals, current)


def _produce_completion_on_work(*, policy_bytes, planning_originals, activation_planner_bytes,
        grant_enrollment_bytes, authorization_enrollment_bytes, request_originals, result_originals,
        projection, root_private_key, root_public_key, live_window, transport_deadline_ns, work, _continuity):
    resource = request.policy._capture(projection, work)
    raw = wire._originals(request_originals, response=False)
    outcome = wire._originals(result_originals, response=True)
    held = _Request(policy_bytes, planning_originals, activation_planner_bytes, grant_enrollment_bytes,
        authorization_enrollment_bytes, root_private_key, root_public_key, live_window,
        transport_deadline_ns, work, _continuity)
    actual, expected, authorization_digest, _predecessor, pending, interval, current = _pending(held, raw)
    if len(outcome[1]) != 71 or len(outcome[2]) != 71:
        raise ValueError("consume completion lacks an actual SQL packet locator")
    work.charge(input_bytes=142)
    pending_digest, packet_digest = outcome[1].decode("ascii"), outcome[2].decode("ascii")
    shape._digest(packet_digest)
    plan._same(pending_digest, pending["headDigest"], work, "consume completion actual pending locator")
    payload = held.base(completion_role, interval, resource)
    originals = held.custody("completion", interval, resource["receiverIdentity"], current)
    for (name, _maximum), original in zip(completion_role._CUSTODY_LIMITS, originals):
        payload[name] = request._wrapped(original, work)
    key = held.enrolled.payload["completion"]
    payload.update(receiverIdentity=resource["receiverIdentity"],
        authorization=request._wrapped(actual[0], work, caller.REQUEST_IDENTITY_DOMAIN),
        completionSpkiDigest=key["spkiDigest"], completionMeasurementDigest=key["measurementDigest"],
        currentPending=pending, completionCheckpoint=resource["checkpoint"], stateEndpoint=resource["stateEndpoint"],
        packetDigest=packet_digest, authorizationDigest=authorization_digest, replayExpectations=expected)
    for name in ("databaseEndpoint", "sqlRoles", "queryManifestDigest", "structureManifestDigest", "tlsFiles"):
        payload[name] = resource[name]
    current()
    # The locator is not a result verdict: the genuine worker still reads the
    # exact protected packet and normally closed SQL commit before completion.
    result = completion_role._produce_on_work(payload=payload, root_private_key=root_private_key,
        root_public_key=root_public_key, work=work, live_window=held.window,
        transport_deadline_ns=held.bound)
    current()
    return result
