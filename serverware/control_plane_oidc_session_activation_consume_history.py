"""Independent retained-consume authority, never borrowed activation authority.

Untrusted locators select exactly one already admitted current/archive scope.
Genuine caller and plan signatures precede original-interval/cohort selection.
No key, successful material, execution permission or processing clock is posted.
"""
from __future__ import annotations

from dataclasses import dataclass
import time

from serverware import authority_oidc_session_activation_consume_input_production as bookkeeping
from serverware import authority_oidc_session_activation_delivery_execution_authorization as caller
from serverware import control_plane_oidc_session_activation_history as history


bootstrap, archive, registration = history.bootstrap, history.archive, history.registration
evidence, contract = caller.evidence, caller.contract
MAX_ORIGINAL_BYTES = contract.MAX_ORIGINAL_BYTES
_FIELDS = ("configuration_payload", "configuration_digest", "generation", "runtime_role_identities",
    "root_public_key", "consume_execution", "completion_recovery", "authority_interval")


class ConsumeHistoryError(ValueError):
    pass


def _fail(message):
    raise ConsumeHistoryError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _SelectedConsumeHistory:
    """Same-call original-derived scope; not an incoming authority carrier."""

    configuration_payload: dict
    configuration_digest: str
    generation: dict
    runtime_role_identities: dict
    root_public_key: object
    consume_execution: object
    completion_recovery: object
    authority_interval: tuple
    live: object
    window: tuple
    deadline_ns: int


def _candidate_sizes(consumed, planned):
    if (type(consumed) is not bootstrap.consume._ConsumeExecutionMaterial
            or type(planned) is not bootstrap.planning._PlanningMaterial):
        _fail("consume history lacks its actual cold original inventory")
    originals = (consumed.authorization_enrollment_bytes, consumed.current_root_enrollment_bytes,
        consumed.grant_enrollment_bytes)
    maxima = (caller.MAX_ENROLLMENT_BYTES, caller.authorization.MAX_ENROLLMENT_BYTES,
        caller.enrollments.MAX_ENROLLMENT_BYTES)
    if any(type(raw) is not bytes or not 2 <= len(raw) <= maximum
            for raw, maximum in zip(originals, maxima)):
        _fail("consume history cold enrollment originals exceed their bounds")
    original = planned.planner_bootstrap_bytes
    if type(original) is not bytes or not 2 <= len(original) <= bootstrap.planning.planner.MAX_BYTES:
        _fail("consume history configuration capture has no bounded original")
    return sum(map(len, originals)), len(original)


def _capture_reservation_on_owner(owner):
    """Extra decoder/thaw/seal footprints, not already-held parent/archive bytes.

    Each genuinely admitted activation planner contains its exact configuration,
    generation and runtime graphs. Its immutable wire length bounds their fresh
    selected copies without traversing or copying the archive before body one.
    """
    parent, material = history._cold_on_owner(owner)
    candidates = []
    if parent.consume_execution is not None:
        candidates.append(_candidate_sizes(parent.consume_execution, parent.activation_planning))
    if material is not None:
        if type(material.scopes) is not tuple or not 1 <= len(material.scopes) <= archive.MAX_ENTRIES + 1:
            _fail("consume history cold scope inventory changed")
        for scope in material.scopes:
            if type(scope) is not bootstrap._ActivationHistoryScope:
                _fail("consume history cold scope type changed")
            candidates.append(_candidate_sizes(scope.consume_execution, scope.activation_planning))
    if not candidates:
        _fail("consume history has no independently configured authority")
    reserved = (8 * (max(value[0] for value in candidates) + max(value[1] for value in candidates)
        + caller.MAX_AUTHORIZATION_BYTES + contract.MAX_BYTES) + 128 * 1024)
    if reserved >= MAX_ORIGINAL_BYTES:
        _fail("consume history extra captures exhaust the original aggregate ceiling")
    return reserved


def _select(owner, payload, work):
    parent, material = history._cold_on_owner(owner)
    wanted = tuple(payload[name] for name in (
        "configurationDigest", "generationDigest", "authorizationEnrollmentDigest"))
    for value in wanted:
        caller.shape._digest(value)
    current = parent.consume_execution
    is_current = (type(current) is bootstrap.consume._ConsumeExecutionMaterial
        and wanted == (parent.configuration_digest, parent.generation["digest"],
            current.authorization_enrollment_digest))
    if is_current:
        # Explicit current classification is allowed with an unrelated old
        # archive. An overlapping cold selector is ambiguous, never fallback.
        if material is not None:
            for scope in bootstrap._scopes(material, work):
                if wanted == (scope.configuration_digest, scope.generation_digest,
                        scope.consume_execution.authorization_enrollment_digest):
                    _fail("consume locator ambiguously selects current and archived authority")
        return parent, material, None
    if material is None:
        _fail("consume locator does not select the independently current authority")
    selected = bootstrap._lookup_consume_on_work(material, configuration_digest=wanted[0],
        generation_digest=wanted[1], authorization_enrollment_digest=wanted[2], work=work)
    return parent, material, selected


def _result(owner, selected, snapshot, originals, lifetime, work):
    parent, material = history._cold_on_owner(owner)
    binding, custody = owner._binding, owner._custody
    if selected is None:
        generation = evidence.capture._JSONCapture(evidence.capture._SharedLedger(work)).visit(
            {name: parent.generation[name] for name in history.configured.configuration._GENERATION_FIELDS})
        values = (parent.configuration_payload, parent.configuration_digest, generation,
            parent.runtime_role_identities, binding.runtime_root_public_key,
            parent.consume_execution, parent.completion_recovery, binding.attestation_interval)
    else:
        values = (snapshot.payload, snapshot.configuration_digest, snapshot.generation,
            snapshot.runtime_role_identities, selected.root_public_key, selected.consume_execution,
            selected.completion_recovery, (snapshot.valid_from_epoch_ns, snapshot.valid_until_epoch_ns))
    graphs = values[0], values[2], values[3]
    pins = tuple(registration._graph_bytes(value, work) for value in graphs)
    current_lanes = parent.activation_execution, parent.activation_planning, parent.consume_execution, parent.completion_recovery
    selected_lanes = (None if selected is None else
        (selected.activation_execution, selected.activation_planning, selected.consume_execution, selected.completion_recovery))
    result = None

    def live():
        now = lifetime.current()
        if (type(result) is not _SelectedConsumeHistory or result.live is not live
                or owner._material is not parent or owner._binding is not binding or owner._custody is not custody
                or parent.activation_history is not material
                or any(actual is not held for actual, held in zip((parent.activation_execution,
                    parent.activation_planning, parent.consume_execution, parent.completion_recovery), current_lanes))
                or any(getattr(result, name) is not value for name, value in zip(_FIELDS, values))
                or result.window is not lifetime.window or result.deadline_ns != lifetime.bound
                or (selected is not None and (not any(selected is scope for scope in material.scopes)
                    or any(actual is not held for actual, held in zip((selected.activation_execution,
                        selected.activation_planning, selected.consume_execution, selected.completion_recovery), selected_lanes))))
                or type(originals) is not tuple or len(originals) != 2
                or any(type(raw) is not bytes for raw in originals)):
            _fail("consume history selected authority changed or outlived its owner")
        for graph, pin in zip(graphs, pins):
            actual = registration._graph_bytes(graph, work)
            work.charge(input_bytes=len(actual) + len(pin))
            if actual != pin:
                _fail("consume history selected configuration changed")
        later = lifetime.current()
        if later < now:
            _fail("consume history selected clocks reversed")
        return later

    result = _SelectedConsumeHistory(*values, live, lifetime.window, lifetime.bound)
    live()
    return result


def _scope_on_owner(owner, *, authorization_bytes, plan_bytes, window, bound, work, current):
    """Authenticate one independently selected consume caller and signed plan."""
    evidence.capture._SharedLedger(work)
    _capture_reservation_on_owner(owner)
    authorization = caller.authorization._original(authorization_bytes,
        caller.MAX_AUTHORIZATION_BYTES, "historical consume caller original")
    original_plan = caller.authorization._original(plan_bytes, contract.MAX_BYTES,
        "historical consume signed plan original")
    originals = authorization, original_plan
    work.charge(input_bytes=sum(map(len, originals)))
    window, bound, inherited, _cold_bytes = history._lifetime_on_owner(owner,
        window=window, bound=bound, work=work, current=current)

    def ancestor(epoch, monotonic):
        now = inherited()
        sampled = caller.production._callback(work, time.monotonic_ns)
        if type(now) is not int or type(sampled) is not int or now < epoch or sampled < monotonic:
            _fail("consume history original processing clocks reversed")
        return now, sampled

    lifetime = bookkeeping._Lifetime(window, bound, work, ancestor)
    lifetime.current()
    envelope = caller._read(authorization, enrollment=False, work=work)
    payload = envelope["payload"]
    parent, material, selected = _select(owner, payload, work)
    policy = parent.consume_execution if selected is None else selected.consume_execution
    activation = parent.activation_execution if selected is None else selected.activation_execution
    completion = parent.completion_recovery if selected is None else selected.completion_recovery
    root = owner._binding.runtime_root_public_key if selected is None else selected.root_public_key
    configuration = parent.configuration_digest if selected is None else selected.configuration_digest
    generation = parent.generation["digest"] if selected is None else selected.generation_digest
    if (type(policy) is not bootstrap.consume._ConsumeExecutionMaterial
            or type(activation) is not bootstrap.activation._ActivationExecutionMaterial
            or type(completion) is not bootstrap.completion._CompletionRecoveryMaterial
            or type(completion.consume) is not bootstrap.completion._CompletionRecoveryScope
            or activation.consume_planner_public_key is None
            or activation.consume_planner_measurement_digest is None):
        _fail("consume history lacks independently admitted original planner/completion authority")
    enrolled = caller._admit_enrollment_on_work(
        authorization_enrollment_bytes=policy.authorization_enrollment_bytes,
        current_root_enrollment_bytes=policy.current_root_enrollment_bytes,
        grant_enrollment_bytes=policy.grant_enrollment_bytes, root_public_key=root,
        configuration_digest=configuration, planner_public_key=policy.planner_public_key,
        operation_public_key=policy.operation_public_key, work=work)
    lifetime.narrow(lifetime.window[3], min(policy.maximum_age_ns, enrolled.payload["maximumAgeNs"]),
        min(policy.maximum_clock_skew_ns, enrolled.payload["maximumClockSkewNs"]))
    caller.primitives._signature(envelope, enrolled.caller_public_key, caller.MAX_AUTHORIZATION_BYTES, work)
    caller.plan._same(caller.plan._frame(caller.REQUEST_IDENTITY_DOMAIN, (authorization,), work),
        completion.consume.authorization_digest, work, "historical consume independently pinned caller original")
    for name in caller._SCOPE_FIELDS:
        caller.plan._same(payload[name], enrolled.payload[name], work, "historical consume caller " + name)
    for actual, expected, label in ((payload["authorizationEnrollmentDigest"], enrolled.enrollment_digest, "enrollment"),
            (enrolled.enrollment_digest, policy.authorization_enrollment_digest, "cold enrollment"),
            (payload["callerMeasurementDigest"], enrolled.payload["callerKey"]["measurementDigest"], "caller measurement"),
            (payload["generationDigest"], generation, "generation")):
        caller.plan._same(actual, expected, work, "historical consume " + label)
    caller.authorization._interval(payload, enrolled.payload["maximumAgeNs"])
    lifetime.current()
    signed = contract._decode_on_work(original_plan, envelope=True, work=work)
    planned = signed["payload"]
    evidence.keys._public_binding(policy.planner_public_key, planned["plannerSpkiDigest"], work)
    caller.plan._same(evidence.keys._spki_on_work(activation.consume_planner_public_key, work),
        planned["plannerSpkiDigest"], work, "historical consume independently configured planner")
    caller.plan._same(planned["plannerIdentity"]["measurementDigest"],
        activation.consume_planner_measurement_digest, work, "historical consume planner measurement")
    unsigned = contract._encode_on_work(planned, work=work)
    evidence.capability._signature(policy.planner_public_key, signed["signatureBase64Url"],
        contract.SIGNATURE_DOMAIN, unsigned, evidence.capture._SharedLedger(work))
    for field in ("requestDigest", "operationId", "configurationDigest"):
        caller.plan._same(payload[field], planned[field], work, "historical consume exact plan " + field)
    caller.plan._same(payload["planDigest"], evidence.plan._frame(contract.IDENTITY_DOMAIN, (original_plan,), work),
        work, "historical consume caller exact signed plan")
    now = lifetime.current()
    if (planned["issuedAtEpochNs"] > now + lifetime.window[6]
            or payload["issuedAtEpochNs"] > now + lifetime.window[6]
            or not planned["issuedAtEpochNs"] <= payload["issuedAtEpochNs"]
                < payload["expiresAtEpochNs"] <= planned["expiresAtEpochNs"]):
        _fail("historical consume caller/plan intervals escape their original authority")
    snapshot = None
    if selected is None:
        interval = owner._binding.attestation_interval
        for original in (payload, planned):
            if not interval[0] <= original["issuedAtEpochNs"] < original["expiresAtEpochNs"] <= interval[1]:
                _fail("current consume originals escape the independently admitted original interval")
    else:
        captured = archive._capture_on_work(material.archive, work=work)
        snapshot = archive._lookup_on_work(captured, configuration_digest=configuration,
            planner_attestation_receipt_digest=selected.planner_attestation_receipt_digest,
            evaluation_epoch_ns=planned["issuedAtEpochNs"], work=work)
        if bootstrap._scope_on_work(material, snapshot=snapshot, work=work) is not selected:
            _fail("consume caller and authenticated plan select another cold archive scope")
        registration._interval(snapshot, payload["issuedAtEpochNs"], payload["expiresAtEpochNs"])
        registration._interval(snapshot, planned["issuedAtEpochNs"], planned["expiresAtEpochNs"])
    caller.primitives._unchanged(authorization, envelope, caller.MAX_AUTHORIZATION_BYTES, work)
    evidence.capability._canonical(original_plan, signed, evidence.capture._SharedLedger(work),
        contract.MAX_BYTES, contract.MAX_NODES)
    lifetime.current()
    return _result(owner, selected, snapshot, originals, lifetime, work)
