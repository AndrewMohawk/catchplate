"""Public consume-input endpoint and original policy in signed parent v13.

Cold admission authenticates the inner policy signature and static original
joins only. It creates no processing window and supplies no live issuer-policy
admission; the actual request must re-admit originals under its held allowance.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_oidc_session_activation_consume_input_transport as transport
from serverware import control_plane_oidc_session_activation_execution_bootstrap as execution
from serverware import control_plane_oidc_session_activation_planning_bootstrap as planning
from serverware import control_plane_oidc_session_activation_consume_execution_bootstrap as consume
from serverware import control_plane_oidc_session_activation_history_bootstrap as historical
from serverware import oidc_session_activation_consume_input_issuer_policy as issuer


SCHEMA = "serverware.controlPlaneOidcSessionActivationConsumeInputAcquisition/v1"
V2_SCHEMA = "serverware.controlPlaneOidcSessionActivationConsumeInputAcquisition/v2"
SOCKET_PATH = transport.LISTENER_PATH
V1_MAX_BYTES = 128 * 1024
MAX_BYTES, MAX_NODES, MAX_DEPTH = 4 * 1024 * 1024, 64, 4
shape, capture, plan = issuer.shape, issuer.capture, issuer.plan
_FIELDS = frozenset({"schema", "endpoint", "issuerPolicy"})
_ENDPOINT_FIELDS = frozenset({"path", "timeoutSeconds", "peerUid", "peerGid"})
_ORIGINAL_FIELDS = frozenset({"base64Url", "byteCount"})


class OidcSessionActivationConsumeInputAcquisitionBootstrapError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationConsumeInputAcquisitionBootstrapError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ConsumeInputAcquisitionMaterial:
    """Original cold configuration, not present permission or a live result."""

    endpoint: tuple
    issuer_policy_bytes: bytes
    historical_scope: object | None = None
    bridge_interval: tuple | None = None


class _Capture(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            _fail("consume input acquisition exceeds its shape bound")
        owned = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            _fail("consume input acquisition exceeds its node bound")
        return owned


def _endpoint(value):
    shape._object(value, _ENDPOINT_FIELDS, "consume input acquisition endpoint")
    shape._literal(value["path"], SOCKET_PATH)
    shape._integer(value["timeoutSeconds"], 30, minimum=1)
    for name in ("peerUid", "peerGid"):
        shape._integer(value[name], 2**32 - 2)
    try:
        return transport._endpoint((value["path"], value["timeoutSeconds"],
            value["peerUid"], value["peerGid"]))
    except transport.AuthorityTransportError as exc:
        raise OidcSessionActivationConsumeInputAcquisitionBootstrapError(
            "consume input acquisition endpoint differs from its fixed listener") from exc


def _shape(value):
    if value is None:
        return
    shape._object(value, _FIELDS, "control-plane consume input acquisition")
    if type(value["schema"]) is not str or value["schema"] not in (SCHEMA, V2_SCHEMA):
        _fail("consume input acquisition requires an explicit supported version")
    _endpoint(value["endpoint"])
    original = value["issuerPolicy"]
    shape._object(original, _ORIGINAL_FIELDS, "consume input issuer policy original")
    maximum = issuer.V1_MAX_BYTES if value["schema"] == SCHEMA else issuer.MAX_BYTES
    shape._integer(original["byteCount"], maximum, minimum=2)
    issuer.authorization.transport._transport_shape(
        original["base64Url"], original["byteCount"], maximum)


def _state_original(planner_original, work):
    """Compare data from the exact planner already admitted by parent v7."""
    planner = issuer.activation
    envelope = planner.codec._decode(planner_original, work)
    shape._object(envelope, planner._ENVELOPE_FIELDS, "parent activation planner original")
    shape._literal(envelope["schema"], planner.SCHEMA)
    shape._object(envelope["payload"], planner._PAYLOAD_FIELDS, "parent activation planner payload")
    planner.codec._canonical(planner_original, envelope, work)
    original = envelope["payload"]["stateEnrollment"]
    shape._object(original, planner._ORIGINAL_FIELDS, "parent activation state enrollment")
    return issuer.authorization.transport._decode(original["base64Url"], original["byteCount"],
        issuer.authorization.MAX_ENROLLMENT_BYTES, work)


def _admit_on_work(*, consume_input_acquisition, activation_planning,
        activation_execution, runtime_root_public_key, work):
    """Authenticate static originals without a fresh cold/request allowance."""
    try:
        ledger = capture._SharedLedger(work)
        _shape(consume_input_acquisition)
        if consume_input_acquisition is None:
            return None
        shape._literal(consume_input_acquisition["schema"], SCHEMA)
        held_planning, held_execution, root = (
            activation_planning, activation_execution, runtime_root_public_key)
        if (type(held_planning) is not planning._PlanningMaterial
                or type(held_execution) is not execution._ActivationExecutionMaterial
                or held_execution.consume_planner_endpoint is None
                or held_execution.consume_planner_public_key is None
                or held_execution.consume_planner_measurement_digest is None
                or held_execution.reservation_predecessor is None):
            _fail("consume input acquisition requires actual planning and consume-capable execution")
        # Hold every original/key reference before signature or key callbacks.
        planner_original = issuer.authorization._original(held_planning.planner_bootstrap_bytes,
            issuer.MAX_ACTIVATION_PLANNER_BOOTSTRAP_BYTES, "actual parent activation planner")
        state_original = issuer.authorization._original(held_execution.current_root_enrollment_bytes,
            issuer.authorization.MAX_ENROLLMENT_BYTES, "actual parent state enrollment")
        consume_key = held_execution.consume_planner_public_key
        measurement = held_execution.consume_planner_measurement_digest
        predecessor = held_execution.reservation_predecessor
        owned = _Capture(ledger, maximum_bytes=V1_MAX_BYTES).visit(consume_input_acquisition)
        _shape(owned)
        wrapped = owned["issuerPolicy"]
        original = issuer.authorization.transport._decode(
            wrapped["base64Url"], wrapped["byteCount"], issuer.MAX_BYTES, work)
        endpoint = _endpoint(owned["endpoint"])
        issuer.authorization._public(root)
        issuer.authorization._public(consume_key)
        shape._digest(measurement)
        expected_predecessor = issuer.reservation._predecessor_scope(*predecessor)
        envelope = issuer._read(original, work)
        shape._literal(envelope["schema"], issuer.SCHEMA)
        issuer._signature(envelope, root, work)
        issuer._canonical(original, envelope, work)
        payload = envelope["payload"]
        plan._same(payload["activationPlannerBootstrapDigest"],
            issuer._activation_planner_bootstrap_digest_on_work(planner_original, work), work,
            "consume input issuer differs from the exact parent activation planner")
        selected = payload["consumePlanner"]["planner"]
        selected_key = issuer.activation.configuration._key(selected["publicKeyBase64Url"], work,
            expected_spki=selected["spkiDigest"])
        plan._same(issuer.keys._spki_on_work(selected_key, work),
            issuer.keys._spki_on_work(consume_key, work), work,
            "consume input issuer differs from the actual parent consume planner key")
        plan._same(selected["identity"]["measurementDigest"], measurement, work,
            "consume input issuer differs from the actual parent consume planner measurement")
        declared = payload["activationPredecessor"]
        plan._same(issuer.reservation._predecessor_scope(
            declared["sequence"], declared["headDigest"], declared["fence"]),
            expected_predecessor, work, "consume input issuer differs from the parent activation predecessor")
        actual_state = _state_original(planner_original, work)
        work.charge(input_bytes=len(actual_state) + len(state_original))
        if actual_state != state_original:
            _fail("consume input issuer and actual execution require the same original state enrollment")
        issuer._canonical(original, envelope, work)
        if (held_planning.planner_bootstrap_bytes is not planner_original
                or held_execution.current_root_enrollment_bytes is not state_original
                or held_execution.consume_planner_public_key is not consume_key
                or held_execution.consume_planner_measurement_digest != measurement
                or held_execution.reservation_predecessor is not predecessor):
            _fail("consume input acquisition replaced its actual parent pins")
        return _ConsumeInputAcquisitionMaterial(endpoint, original)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, OidcSessionActivationConsumeInputAcquisitionBootstrapError):
            raise
        raise OidcSessionActivationConsumeInputAcquisitionBootstrapError(
            "consume input acquisition cold configuration failed") from exc


def _admit_historical_on_work(*, consume_input_acquisition, activation_history,
        activation_planning, activation_execution, consume_execution,
        runtime_root_public_key, live_window, transport_deadline_ns, work):
    """Join current signed issuance to one genuinely archived activation scope.

    This is cold source configuration, not authorization to run a consume call.
    The original bridge and old planner must be verified again on request work.
    """
    ledger = capture._SharedLedger(work)
    _shape(consume_input_acquisition)
    shape._literal(consume_input_acquisition["schema"], V2_SCHEMA)
    if (type(activation_history) is not historical._ActivationHistoryMaterial
            or type(activation_planning) is not planning._PlanningMaterial
            or type(activation_execution) is not execution._ActivationExecutionMaterial
            or type(consume_execution) is not consume._ConsumeExecutionMaterial):
        _fail("historical consume acquisition requires actual archive and current execution lanes")
    window, bound, current, continuity = historical._processing(
        activation_history, live_window, transport_deadline_ns, work)
    owned = _Capture(ledger, maximum_bytes=MAX_BYTES).visit(consume_input_acquisition)
    _shape(owned)
    wrapped = owned["issuerPolicy"]
    original = issuer.authorization.transport._decode(
        wrapped["base64Url"], wrapped["byteCount"], issuer.MAX_BYTES, work)
    root = runtime_root_public_key
    issuer.authorization._public(root)
    current()
    envelope = issuer._read(original, work)
    shape._literal(envelope["schema"], issuer.V2_SCHEMA)
    issuer._signature(envelope, root, work)
    current()
    evidence = envelope["payload"]["activationEvidence"]
    selected = None
    for candidate in activation_history.scopes:
        work.charge(input_bytes=4 * 71, json_nodes=1)
        if (candidate.configuration_digest, candidate.planner_attestation_receipt_digest) == (
                evidence["configurationDigest"], evidence["plannerAttestationReceiptDigest"]):
            if selected is not None:
                _fail("historical consume activation selector is ambiguous")
            selected = candidate
    if selected is None:
        _fail("historical consume activation is absent from the admitted archive")
    for actual, expected, label in (
            (evidence["generationDigest"], selected.generation_digest, "generation"),
            ((evidence["validFromEpochNs"], evidence["validUntilEpochNs"]),
                (selected.valid_from_epoch_ns, selected.valid_until_epoch_ns), "original interval"),
            (evidence["rootSpkiDigest"], issuer.keys._spki_on_work(selected.root_public_key, work), "old root")):
        plan._same(actual, expected, work, "historical consume archived " + label)
    prior = selected.activation_execution
    enrolled = execution.caller._admit_enrollment_on_work(
        authorization_enrollment_bytes=prior.authorization_enrollment_bytes,
        current_root_enrollment_bytes=prior.current_root_enrollment_bytes,
        grant_enrollment_bytes=prior.grant_enrollment_bytes, root_public_key=selected.root_public_key,
        configuration_digest=selected.configuration_digest, planner_public_key=prior.planner_public_key,
        operation_public_key=prior.operation_public_key, work=work)
    for actual, expected in ((evidence["authorizationEnrollmentDigest"], enrolled.enrollment_digest),
            (evidence["grantEnrollmentDigest"], enrolled.payload["grantEnrollmentDigest"]),
            (evidence["stateEnrollmentDigest"], enrolled.payload["currentRootEnrollmentDigest"])):
        plan._same(actual, expected, work, "historical consume exact archived enrollment")
    current()
    material = issuer._verify_on_work(policy_bytes=original,
        activation_planner_bootstrap_bytes=selected.activation_planning.planner_bootstrap_bytes,
        root_public_key=root, live_window=window, transport_deadline_ns=bound,
        work=work, _continuity=continuity)
    if type(material) is not issuer._IssuerPolicyMaterial or material.bridge is None:
        _fail("historical consume requires genuine versioned bridge admission")
    actual = material.current_planner.bootstrap_bytes
    expected = activation_planning.planner_bootstrap_bytes
    work.charge(input_bytes=len(actual) + len(expected))
    if actual != expected:
        _fail("historical consume current context differs from actual parent planning")
    actual = material.current_planner.state_enrollment_bytes
    expected = consume_execution.current_root_enrollment_bytes
    work.charge(input_bytes=len(actual) + len(expected))
    if actual != expected:
        _fail("historical consume output state differs from current consume execution")
    for key in (consume_execution.planner_public_key, activation_execution.consume_planner_public_key):
        plan._same(issuer.keys._spki_on_work(material.consume_planner_public_key, work),
            issuer.keys._spki_on_work(key, work), work, "historical consume current planner key")
    plan._same(material.consume_planner["planner"]["identity"]["measurementDigest"],
        activation_execution.consume_planner_measurement_digest, work,
        "historical consume current planner measurement")
    plan._same(material.activation_predecessor, prior.reservation_predecessor, work,
        "historical consume exact original activation predecessor")
    plan._same(issuer.keys._spki_on_work(material.historical_root_public_key, work),
        issuer.keys._spki_on_work(selected.root_public_key, work), work,
        "historical consume independently archived verification root")
    issuer._canonical(original, envelope, work)
    material.live()
    current()
    return _ConsumeInputAcquisitionMaterial(_endpoint(owned["endpoint"]), original, selected,
        (material.payload["issuedAtEpochNs"], material.payload["expiresAtEpochNs"]))
