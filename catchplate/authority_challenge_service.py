"""Fixed maintenance callers on the real measured service role boundary.

These private methods do not dispatch requests or admit a current root. They
join the actual root-verified configuration, active generation, original role
descriptor and planner signer before constructing their specific source owner.
No incoming parent chooses keys, DSNs, policy, custody callbacks or role
credentials. The private live callers use actual page transport and genuine
native production/replay. Their independently supplied roots/context still
need the surrounding current-root owner; these calls grant no execution or
request authority and do not enable a public operation.
"""
from __future__ import annotations

from catchplate import authority_challenge_configuration as mapping
from catchplate import authority_challenge_page_service as pages
from catchplate import authority_webauthn_transition_service as measured


plan = mapping.plan
_OPERATION = "webauthn.challenge.maintain"


def _producer_on_work(process, *, operation, work):
    mapping._require(type(operation) is str and operation in mapping._OPERATIONS)
    owned, digest, generation, dsn, private, runtime = measured._measured_context_on_work(
        process, role="planner", signing=True,
        read_descriptor="CATCHPLATE_POLICY_AUTHORITY_PLANNER_READ_POSTGRES_DSN", work=work)
    return mapping._producer_from_configuration_on_work(operation=operation,
        payload=owned, configuration_digest=digest, generation=generation,
        runtime_role_identities=runtime, read_dsn=dsn, planner_private_key=private, work=work)


def _verifier_on_work(process, *, operation, work):
    mapping._require(type(operation) is str and operation in mapping._OPERATIONS)
    owned, digest, generation, _dsn, _private, runtime = measured._measured_context_on_work(
        process, role="verifier", signing=False, read_descriptor=None, work=work)
    return mapping._verifier_from_configuration_on_work(operation=operation,
        payload=owned, configuration_digest=digest, generation=generation,
        runtime_role_identities=runtime, work=work)


def _anchors(primary_root, index_heads, work):
    """Own exact scalar anchors before protected-descriptor/key callbacks."""
    maintenance = plan.maintenance
    mapping._require(type(work) is plan._ValidationWork
        and type(primary_root) is maintenance.primary.PrimaryRoot
        and type(index_heads) is tuple and len(index_heads) == len(plan.manifests.WRITE_IDS)
        and all(type(head) is maintenance.CapturedIndexHead
            and type(head.index_root) is maintenance.CountedNode for head in index_heads))
    # Reserve fixed containers before creating the scalar projection; the
    # genuine ownership traversal then accounts every retained scalar byte.
    work.charge(json_nodes=16 + 12 * len(index_heads))
    owned = maintenance._owned((primary_root.json_projection(),
        tuple(maintenance.head_wire(head) for head in index_heads)), work)
    work.charge(hashes=maintenance.contract.TREE_DEPTH + 1, json_nodes=5)
    root = maintenance._root(owned[0])
    values = owned[1]
    mapping._require(tuple(value["indexId"] for value in values) == plan.manifests.WRITE_IDS)
    heads = []
    for identity, value in zip(plan.manifests.WRITE_IDS, values, strict=True):
        work.charge(hashes=maintenance.projection.PROFILE_HASH_WORK, json_nodes=10)
        heads.append(maintenance._head(value, maintenance.projection.profile_for(identity), root, work))
    work.charge(json_nodes=1 + len(heads))
    return root, tuple(heads)


def _same_planner(caller, *, configuration_digest, planner_spki_digest, work):
    pages._PageCaller._live(caller, work)
    configured = caller._configured
    plan._same((configured.configuration_digest, configured.planner_spki_digest),
        (configuration_digest, planner_spki_digest), work)


def _original_interval(envelope_bytes, work):
    """An untrusted interval only narrows processing before real verification."""
    envelope = plan.evidence.wire._decode_object(envelope_bytes, work=work,
        maximum_bytes=plan.MAX_PARENT_BYTES, maximum_nodes=plan.MAX_PARENT_NODES,
        maximum_depth=plan.MAX_PARENT_DEPTH)
    plan._object(envelope, frozenset({"schema", "payload", "signatureBase64Url"}))
    mapping._require(envelope["schema"] == plan.ENVELOPE_SCHEMA)
    plan._payload_shape(envelope["payload"])
    work.charge(json_nodes=5)
    return {name: envelope["payload"][name] for name in ("issuedAtEpochNs", "expiresAtEpochNs")}


def _live_original(interval, expected, window, work):
    # Original policy now is an anchor, not the current verification time.
    # A narrower receiving window does not rewrite the original interval;
    # its actual epoch sample must still lie within that signed interval.
    plan._fresh(interval, expected, plan.clock._check_on_work(window, work=work))


def _produce_on_work(process, *, request_bytes, primary_root, index_heads,
        live_window, original_deadline_ns, check, work):
    """Real two-pass planner plus actual immutable writer-page retention.

    No retention callback is admitted from the request or caller. The native
    planner matches these owned anchors against its original SQL snapshot;
    the external check retains the upstream current-root/request ownership.
    """
    mapping._require(type(work) is plan._ValidationWork and callable(check))
    request = plan.requests.capture_request(request_bytes, work=work)
    mapping._require(request["operation"] == _OPERATION)
    root, heads = _anchors(primary_root, index_heads, work)
    window = plan.clock._validate(live_window)
    plan.evidence.plan.contract._integer(original_deadline_ns, minimum=1)
    mapping._require(original_deadline_ns <= window[4])
    caller = pages._caller_on_work(process, live_window=window, work=work)
    mapping._require(caller._configured.local_role == "planner")
    producer = _producer_on_work(process, operation=_OPERATION, work=work)
    from catchplate.authority_challenge_planning import MaintenancePlanner

    mapping._require(type(producer) is MaintenancePlanner)
    configured = producer._configured
    _same_planner(caller, configuration_digest=configured[8],
        planner_spki_digest=configured[7], work=work)

    def current():
        pages._PageCaller._live(caller, work)
        mapping._require(plan.evidence.production._callback(work, check) is None)
        pages._PageCaller._live(caller, work)

    current()
    result = MaintenancePlanner.produce(producer, request_bytes=request_bytes,
        primary_root=root, index_heads=heads, live_window=window,
        original_deadline_ns=original_deadline_ns,
        retain_page=lambda *arguments: pages._PageCaller.retain(caller, *arguments),
        check=current, work=work)
    current()
    mapping._require(type(result) is plan.ProducedMaintenancePlan and producer._configured is configured)
    return result


def _verify_vector_on_work(process, *, envelope_bytes, request_bytes, manifest_bytes,
        context, before_vector_bytes, now_epoch_ns, deadline_epoch_ns,
        live_window, check, work):
    """Replay actual retained pages through the configured verifier and vector.

    Context, the complete before vector and original policy interval are
    independently admitted inputs, not adopted from the parent. The receiving
    live window may be narrower and does not replace that original interval.
    No mutation/effect or raw-reader override is exposed here; protected
    execution owns its separate tentative SQL path.
    """
    from catchplate import authority_challenge_current_root as current_root

    mapping._require(type(work) is plan._ValidationWork and callable(check))
    for raw, maximum in ((envelope_bytes, plan.MAX_PARENT_BYTES),
            (request_bytes, plan.evidence.authority.MAX_REQUEST_BYTES),
            (manifest_bytes, plan.manifests.MAX_MANIFEST_BYTES),
            (before_vector_bytes, current_root.vector.MAX_BYTES)):
        mapping._require(type(raw) is bytes and 2 <= len(raw) <= maximum)
    for value in (now_epoch_ns, deadline_epoch_ns):
        plan.evidence.plan.contract._integer(value, minimum=1)
    mapping._require(now_epoch_ns < deadline_epoch_ns)
    owned = plan.manifests._context(context, work)
    mapping._require(owned["operation"] == _OPERATION)
    interval = _original_interval(envelope_bytes, work)
    window = plan.clock._validate(live_window)
    caller = pages._caller_on_work(process, live_window=window, work=work)
    mapping._require(caller._configured.local_role == "verifier")
    verifier = _verifier_on_work(process, operation=_OPERATION, work=work)
    mapping._require(type(verifier) is mapping.MaintenanceVerifier)
    pins = verifier._pins
    _same_planner(caller, configuration_digest=pins[4], planner_spki_digest=pins[3], work=work)
    _expected_pins, expected = mapping.MaintenanceVerifier._expectations(verifier,
        context=owned, now_epoch_ns=now_epoch_ns, deadline_epoch_ns=deadline_epoch_ns, work=work)
    mapping._require(_expected_pins is pins)
    reader = pages._PageCaller.reader(caller, context=owned, work=work)

    def current(stage):
        mapping._require(type(stage) is current_root.compound._Stage)
        stage.check()
        pages._PageCaller._live(caller, stage.work)
        _live_original(interval, expected, window, stage.work)
        mapping._require(plan.evidence.production._callback(stage.work, lambda: check(stage)) is None)
        pages._PageCaller._live(caller, stage.work)
        _live_original(interval, expected, window, stage.work)
        stage.check()

    _live_original(interval, expected, window, work)
    result = mapping.MaintenanceVerifier.verify_vector(verifier,
        envelope_bytes=envelope_bytes, request_bytes=request_bytes, manifest_bytes=manifest_bytes,
        context=owned, now_epoch_ns=now_epoch_ns, deadline_epoch_ns=deadline_epoch_ns,
        before_vector_bytes=before_vector_bytes, read_original=reader, check=current, work=work)
    pages._PageCaller._live(caller, work)
    _live_original(interval, expected, window, work)
    mapping._require(verifier._pins is pins and type(result) is current_root.MaintenanceVectorObservation)
    plan._same(result.original_interval,
        (interval["issuedAtEpochNs"], interval["expiresAtEpochNs"]), work)
    return result
