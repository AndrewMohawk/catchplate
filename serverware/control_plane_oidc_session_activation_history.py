"""Original-only activation history selection from one actual cold archive.

Locators select only already admitted scope. Genuine caller/plan or intent
signatures precede final selection; none supplies current execution permission.
Original expiry stays historical and unsupported source revisions fail closed.
"""
from __future__ import annotations

from dataclasses import dataclass
import time

from serverware import authority_oidc_session_activation_release_intent as intent
from serverware import control_plane_oidc_session_activation_history_bootstrap as bootstrap
from serverware import control_plane_oidc_session_activation_planning as planning
from serverware import control_plane_oidc_session_activation_release_intent_bootstrap as intent_configured
from serverware import control_plane_registration_history as registration


caller, planner, configured = planning.caller, planning.planner, planning.configured
archive, evidence, clock = registration.archive, registration.evidence, caller.clock
MAX_ORIGINAL_BYTES = evidence.authority.MAX_RESULT_BYTES
_COLD_FIELDS = ("registration_history", "finalization_history", "activation_history")


class ActivationHistoryError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _SelectedActivationHistory:
    """Source-owned observations; no effect API accepts this as authority."""

    configuration_payload: dict
    configuration_digest: str
    generation: dict
    runtime_role_identities: dict
    root_public_key: object
    activation_execution: object
    activation_planning: object
    consume_execution: object
    release_intent: object
    planner_attestation_interval: tuple
    live: object


def _cold_on_owner(owner):
    if type(owner) is not planning.execution.startup._EnrollmentOwner:
        raise ActivationHistoryError("activation history requires the actual cold owner")
    parent = owner._material
    if parent is None or owner._binding is None or owner._custody is None:
        raise ActivationHistoryError("activation history has no cold parent")
    material = parent.activation_history
    if material is not None and (
            type(material) is not bootstrap._ActivationHistoryMaterial
            or material.registration_history is not parent.registration_history
            or material.finalization_history is not parent.finalization_history
            or parent.registration_history is None
            or material.archive is not parent.registration_history.archive):
        raise ActivationHistoryError("activation history changed its actual shared archive")
    return parent, material


def _cold_originals(owner):
    parent, material = _cold_on_owner(owner)
    originals = []
    for name in _COLD_FIELDS:
        value = getattr(parent, name)
        if value is not None:
            raw = value.original_bytes
            if type(raw) is not bytes or not 2 <= len(raw) <= bootstrap.MAX_BYTES:
                raise ActivationHistoryError("historical cold original exceeds its fixed bound")
            if not any(raw is previous for previous in originals):
                originals.append(raw)
    if material is None:
        # These are fixed source-known current lanes, not arbitrary traversal
        # of parent objects or serialization of any private key.
        planning_scope = parent.activation_planning
        if planning_scope is not None:
            originals.append(planning_scope.planner_bootstrap_bytes)
        for lane in (parent.activation_execution, parent.consume_execution):
            if lane is not None:
                originals.extend((lane.authorization_enrollment_bytes,
                    lane.current_root_enrollment_bytes, lane.grant_enrollment_bytes))
        if parent.release_intent is not None:
            originals.extend((parent.release_intent.enrollment_bytes, parent.release_intent.expected_scope_bytes))
    if any(type(raw) is not bytes or not 2 <= len(raw) <= evidence.authority.MAX_REQUEST_BYTES
            for raw in originals):
        raise ActivationHistoryError("activation history cold original inventory exceeds its source limits")
    return tuple(originals)


def _capture_reservation_on_owner(owner):
    """Known held/capture bytes; excludes parent8 and upstream additional bytes."""
    size = sum(map(len, _cold_originals(owner)))
    reservation = 8 * size + 2 * evidence.authority.MAX_REQUEST_BYTES + 64 * 1024
    if reservation >= MAX_ORIGINAL_BYTES:
        raise ActivationHistoryError("activation history cold captures exhaust the original capacity")
    return size, reservation


def _lifetime_on_owner(owner, *, window, bound, work, current):
    """Cold-only ancestor; the caller must not feed a selected child into it."""
    parent, material = _cold_on_owner(owner)
    binding, custody = owner._binding, owner._custody
    histories = tuple(getattr(parent, name) for name in _COLD_FIELDS)
    active = tuple(value for value in histories if value is not None)
    window = clock._validate(window)
    caller.shape._integer(bound, minimum=1)
    deadline = min((window[3], *(value.valid_until_epoch_ns for value in active)))
    window = clock._validate((*window[:3], deadline, window[1] + deadline - window[0], window[5], window[6]))
    bound = min(bound, window[4])
    last_epoch, last_monotonic = window[0], window[2]
    original_bytes = sum(map(len, _cold_originals(owner)))

    def continuity():
        nonlocal last_epoch, last_monotonic
        first = current()
        caller.shape._integer(first, minimum=1)
        if (owner._material is not parent or owner._binding is not binding or owner._custody is not custody
                or any(getattr(parent, name) is not value for name, value in zip(_COLD_FIELDS, histories))
                or parent.activation_history is not material):
            raise ActivationHistoryError("activation historical cold references changed")
        now = clock._check_on_work(window, work=work)
        mono = caller.production._callback(work, time.monotonic_ns)
        caller.shape._integer(mono, minimum=1)
        if (first < last_epoch or now < first or mono < last_monotonic or mono >= bound
                or any(not value.valid_from_epoch_ns <= now < value.valid_until_epoch_ns for value in active)):
            raise ActivationHistoryError("activation historical processing expired or reversed")
        last_epoch, last_monotonic = now, mono
        return now

    continuity()
    return window, bound, continuity, original_bytes


def _common(owner, selected, snapshot, work):
    parent, _material = _cold_on_owner(owner)
    if selected is None:
        generation = evidence.capture._JSONCapture(evidence.capture._SharedLedger(work)).visit(
            {name: parent.generation[name] for name in configured.configuration._GENERATION_FIELDS})
        return (parent.configuration_payload, parent.configuration_digest, generation,
            parent.runtime_role_identities, owner._binding.runtime_root_public_key,
            parent.activation_execution, parent.activation_planning, parent.consume_execution,
            parent.release_intent, owner._binding.attestation_interval)
    return (snapshot.payload, snapshot.configuration_digest, snapshot.generation,
        snapshot.runtime_role_identities, selected.root_public_key, selected.activation_execution,
        selected.activation_planning, selected.consume_execution, selected.release_intent,
        selected.planner_attestation_interval)


def _result_on_owner(owner, selected, snapshot, *, originals, work, current):
    parent, material = _cold_on_owner(owner)
    binding, custody = owner._binding, owner._custody
    values = _common(owner, selected, snapshot, work)
    graphs = values[0], values[2], values[3]
    pins = tuple(registration._graph_bytes(value, work) for value in graphs)
    # Current-mode lanes are source-owned too; replacing any lane invalidates
    # an already selected original just as replacing archived material does.
    lanes = parent.activation_execution, parent.activation_planning, parent.consume_execution, parent.release_intent
    result = None

    def live():
        now = current()
        if (type(result) is not _SelectedActivationHistory or result.live is not live
                or owner._material is not parent or owner._binding is not binding or owner._custody is not custody
                or parent.activation_history is not material
                or any(actual is not prior for actual, prior in zip((parent.activation_execution,
                    parent.activation_planning, parent.consume_execution, parent.release_intent), lanes))
                or any(getattr(result, name) is not value for name, value in zip((
                    "configuration_payload", "configuration_digest", "generation", "runtime_role_identities",
                    "root_public_key", "activation_execution", "activation_planning", "consume_execution",
                    "release_intent", "planner_attestation_interval"), values))
                or type(originals) is not tuple or any(type(raw) is not bytes for raw in originals)):
            raise ActivationHistoryError("activation historical selected scope changed")
        for graph, pin in zip(graphs, pins):
            actual = registration._graph_bytes(graph, work)
            work.charge(input_bytes=len(actual) + len(pin))
            if actual != pin:
                raise ActivationHistoryError("activation historical selected configuration changed")
        later = current()
        if type(now) is not int or type(later) is not int or later < now:
            raise ActivationHistoryError("activation historical selected clocks reversed")
        return later

    result = _SelectedActivationHistory(*values, live)
    live()
    return result


def _prepared_scope_on_owner(owner, *, originals, window, bound, work, current):
    """Authenticate raw5 caller and plan before final archive cohort selection."""
    parent, material = _cold_on_owner(owner)
    if type(originals) is not tuple or len(originals) != 5 or any(type(raw) is not bytes for raw in originals):
        raise ActivationHistoryError("activation history requires exact prepared raw5")
    current()
    envelope = caller._read(originals[0], enrollment=False, work=work)
    payload = envelope["payload"]
    selected = (None if material is None else bootstrap._lookup_execution_on_work(material,
        configuration_digest=payload["configurationDigest"], generation_digest=payload["generationDigest"],
        authorization_enrollment_digest=payload["authorizationEnrollmentDigest"], work=work))
    policy = parent.activation_execution if selected is None else selected.activation_execution
    root = owner._binding.runtime_root_public_key if selected is None else selected.root_public_key
    digest = parent.configuration_digest if selected is None else selected.configuration_digest
    enrolled = caller._admit_enrollment_on_work(
        authorization_enrollment_bytes=policy.authorization_enrollment_bytes,
        current_root_enrollment_bytes=policy.current_root_enrollment_bytes,
        grant_enrollment_bytes=policy.grant_enrollment_bytes, root_public_key=root,
        configuration_digest=digest, planner_public_key=policy.planner_public_key,
        operation_public_key=policy.operation_public_key, work=work)
    current()
    caller.primitives._signature(envelope, enrolled.caller_public_key, caller.MAX_AUTHORIZATION_BYTES, work)
    for name in caller._SCOPE_FIELDS:
        caller.plan._same(payload[name], enrolled.payload[name], work, "historical activation caller " + name)
    caller.plan._same(payload["authorizationEnrollmentDigest"], enrolled.enrollment_digest, work,
        "historical activation exact caller enrollment")
    caller.plan._same(payload["callerMeasurementDigest"], enrolled.payload["callerKey"]["measurementDigest"],
        work, "historical activation caller measurement")
    caller.authorization._interval(payload, enrolled.payload["maximumAgeNs"])
    if payload["issuedAtEpochNs"] > current() + enrolled.payload["maximumClockSkewNs"]:
        raise ActivationHistoryError("historical activation caller is future issued")
    contract = caller.history.contract
    plan_envelope = contract._decode_on_work(originals[1], envelope=True, work=work)
    planned = plan_envelope["payload"]
    encoded = contract._encode_on_work(planned, work=work)
    evidence.keys._public_binding(policy.planner_public_key, enrolled.payload["plannerSpkiDigest"], work)
    evidence.capability._signature(policy.planner_public_key, plan_envelope["signatureBase64Url"],
        contract.SIGNATURE_DOMAIN, encoded, evidence.capture._SharedLedger(work))
    plan_digest = evidence.plan._frame(contract.IDENTITY_DOMAIN, (originals[1],), work)
    caller.plan._same(payload["planDigest"], plan_digest, work, "historical caller's exact signed plan")
    caller.plan._same(planned["configurationDigest"], digest, work, "historical signed plan configuration")
    evidence.capability._canonical(originals[1], plan_envelope, evidence.capture._SharedLedger(work),
        contract.MAX_BYTES, contract.MAX_NODES)
    snapshot = None
    if material is not None:
        captured = archive._capture_on_work(material.archive, work=work)
        snapshot = archive._lookup_on_work(captured, configuration_digest=planned["configurationDigest"],
            planner_attestation_receipt_digest=planned["plannerIdentity"]["attestationReceiptDigest"],
            evaluation_epoch_ns=planned["issuedAtEpochNs"], work=work)
        if bootstrap._scope_on_work(material, snapshot=snapshot, work=work) is not selected:
            raise ActivationHistoryError("activation caller and authenticated planner select different scopes")
        registration._interval(snapshot, payload["issuedAtEpochNs"], payload["expiresAtEpochNs"])
        registration._interval(snapshot, planned["issuedAtEpochNs"], planned["expiresAtEpochNs"])
    current()
    return _result_on_owner(owner, selected, snapshot, originals=originals, work=work, current=current)


def _intent_scope_on_owner(owner, *, intent_bytes, window, bound, work, current):
    """Unique root-enrolled intent lookup, genuine original signature, no target DTO."""
    parent, material = _cold_on_owner(owner)
    current()
    envelope = intent.contract._read(intent_bytes, work)
    payload = envelope["payload"]
    selected = (None if material is None else bootstrap._lookup_intent_on_work(material,
        configuration_digest=payload["configurationDigest"], generation_digest=payload["generationDigest"],
        enrollment_digest=payload["enrollmentDigest"], work=work))
    policy = parent.release_intent if selected is None else selected.release_intent
    root = owner._binding.runtime_root_public_key if selected is None else selected.root_public_key
    if type(policy) is not intent_configured._ReleaseIntentMaterial:
        raise ActivationHistoryError("historical release intent lacks independently admitted original scope")
    scope = intent_configured._scope_on_work(policy.expected_scope_bytes, work)
    enrolled = intent.enrollments._admit_on_work(enrollment_bytes=policy.enrollment_bytes,
        root_public_key=root, expected_scope=scope, forbidden_public_keys=policy.forbidden_public_keys, work=work)
    current()
    intent.contract._signature(envelope, enrolled.caller_public_key, work)
    for name in intent.SCOPE_FIELDS:
        intent.plan._same(payload[name], scope[name], work, "historical intent original scope " + name)
    intent.plan._same(payload["enrollmentDigest"], enrolled.enrollment_digest, work,
        "historical intent actual enrolled original")
    intent.plan._same(enrolled.enrollment_digest, policy.enrollment_digest, work,
        "historical intent cold enrollment locator")
    intent.plan._same(payload["callerMeasurementDigest"], enrolled.payload["callerKey"]["measurementDigest"],
        work, "historical intent caller measurement")
    intent.plan._same(intent.enrollments.keys._spki_on_work(enrolled.caller_public_key, work),
        intent.enrollments.keys._spki_on_work(policy.caller_public_key, work), work,
        "historical intent independently held caller key")
    intent.authorization._interval(payload, enrolled.payload["maximumAgeNs"])
    if payload["issuedAtEpochNs"] > current() + enrolled.payload["maximumClockSkewNs"]:
        raise ActivationHistoryError("historical intent is future issued")
    snapshot = None
    if material is not None:
        captured = archive._capture_on_work(material.archive, work=work)
        snapshot = archive._lookup_on_work(captured, configuration_digest=selected.configuration_digest,
            planner_attestation_receipt_digest=selected.planner_attestation_receipt_digest,
            evaluation_epoch_ns=payload["issuedAtEpochNs"], work=work)
        if bootstrap._scope_on_work(material, snapshot=snapshot, work=work) is not selected:
            raise ActivationHistoryError("historical intent selected another cold scope")
        registration._interval(snapshot, payload["issuedAtEpochNs"], payload["expiresAtEpochNs"])
    current()
    return _result_on_owner(owner, selected, snapshot, originals=(intent_bytes,), work=work, current=current)
