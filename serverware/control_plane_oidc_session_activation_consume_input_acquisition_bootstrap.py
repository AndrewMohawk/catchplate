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
from serverware import oidc_session_activation_consume_input_issuer_policy as issuer


SCHEMA = "serverware.controlPlaneOidcSessionActivationConsumeInputAcquisition/v1"
SOCKET_PATH = transport.LISTENER_PATH
MAX_BYTES, MAX_NODES, MAX_DEPTH = 128 * 1024, 64, 4
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
    shape._literal(value["schema"], SCHEMA)
    _endpoint(value["endpoint"])
    original = value["issuerPolicy"]
    shape._object(original, _ORIGINAL_FIELDS, "consume input issuer policy original")
    shape._integer(original["byteCount"], issuer.MAX_BYTES, minimum=2)
    issuer.authorization.transport._transport_shape(
        original["base64Url"], original["byteCount"], issuer.MAX_BYTES)


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
        owned = _Capture(ledger, maximum_bytes=MAX_BYTES).visit(consume_input_acquisition)
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
