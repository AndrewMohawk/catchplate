"""Explicit public completion-recovery pins inside signed parent v16.

These cold expectations enable no socket or recovery effect by themselves.
Original historical admission and fresh actor authority remain mandatory in
the separate recovery caller; no expired execution authority is renewed here.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import control_plane_oidc_session_activation_execution_bootstrap as activation
from serverware import control_plane_oidc_session_activation_consume_execution_bootstrap as consume
from serverware import authority_oidc_session_activation_completion_dispatch_transport as activation_transport
from serverware import authority_oidc_session_activation_delivery_completion_release_transport as consume_transport


SCHEMA = "serverware.controlPlaneOidcSessionActivationCompletionRecovery/v1"
ACTIVATION_SCHEMA = "serverware.controlPlaneOidcSessionActivationCompletionRecoveryScope/v1"
CONSUME_SCHEMA = "serverware.controlPlaneOidcSessionActivationConsumeCompletionRecoveryScope/v1"
MAX_BYTES, MAX_NODES, MAX_DEPTH = 16 * 1024, 128, 4
shape, capture, plan = activation.shape, activation.capture, activation.plan
_FIELDS = frozenset({"schema", "activation", "consume"})
_LANE_FIELDS = frozenset({"schema", "endpoint", "packetDigest", "authorizationDigest", "currentPending"})
_ENDPOINT_FIELDS = frozenset({"socketPath", "requestTimeoutSeconds", "listenerUid", "listenerGid"})
_PENDING_FIELDS = frozenset({"sequence", "headDigest", "fence"})


class OidcSessionActivationCompletionRecoveryBootstrapError(ValueError):
    pass


def _fail(message):
    raise OidcSessionActivationCompletionRecoveryBootstrapError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _CompletionRecoveryScope:
    """Immutable independently signed expectations, not an admitted outcome."""

    endpoint: tuple
    packet_digest: str
    authorization_digest: str
    current_pending: tuple


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _CompletionRecoveryMaterial:
    activation: _CompletionRecoveryScope | None
    consume: _CompletionRecoveryScope | None


class _Capture(capture._JSONCapture):
    def visit(self, value, depth=0, ancestors=frozenset()):
        if depth > MAX_DEPTH or self.nodes >= MAX_NODES:
            _fail("completion recovery configuration exceeds its structure bound")
        owned = super().visit(value, depth, ancestors)
        if self.nodes > MAX_NODES:
            _fail("completion recovery configuration exceeds its node bound")
        return owned


def _endpoint(value, transport):
    shape._object(value, _ENDPOINT_FIELDS, "completion recovery endpoint")
    return transport._endpoint((value["socketPath"], value["requestTimeoutSeconds"],
        value["listenerUid"], value["listenerGid"]))


def _pending(value):
    shape._object(value, _PENDING_FIELDS, "completion recovery independent pending scope")
    shape._integer(value["sequence"], activation.caller.authorization.MAX_RECORDS, minimum=1)
    shape._digest(value["headDigest"])
    shape._integer(value["fence"], minimum=1)
    return value["sequence"], value["headDigest"], value["fence"]


def _shape(value):
    if value is None:
        return
    shape._object(value, _FIELDS, "control-plane completion recovery")
    shape._literal(value["schema"], SCHEMA)
    if value["activation"] is None and value["consume"] is None:
        _fail("completion recovery requires at least one explicit role")
    for name, schema, transport in (("activation", ACTIVATION_SCHEMA, activation_transport),
            ("consume", CONSUME_SCHEMA, consume_transport)):
        lane = value[name]
        if lane is None:
            continue
        shape._object(lane, _LANE_FIELDS, "completion recovery fixed " + name + " role")
        shape._literal(lane["schema"], schema)
        _endpoint(lane["endpoint"], transport)
        shape._digest(lane["packetDigest"])
        shape._digest(lane["authorizationDigest"])
        _pending(lane["currentPending"])


def _lane_on_work(value, material, *, expected_type, caller, transport,
        root, configuration_digest, generation_digest, work):
    if value is None:
        return None
    if (type(material) is not expected_type or material.completion_endpoint is None
            or type(material.reservation_predecessor) is not tuple
            or len(material.reservation_predecessor) != 3):
        _fail("completion recovery requires the actual configured execution and predecessor")
    endpoint, pending = _endpoint(value["endpoint"], transport), _pending(value["currentPending"])
    for actual, expected in zip(endpoint, material.completion_endpoint):
        plan._same(actual, expected, work, "completion recovery exact parent endpoint")
    plan._same(pending[0], material.reservation_predecessor[0] + 1, work,
        "completion recovery independent pending sequence")
    plan._same(pending[2], material.reservation_predecessor[2], work,
        "completion recovery independent pending fence")
    # Re-admit the actual root-signed public originals. The source-selected
    # parent material supplies only the already configured key/scope inputs;
    # it cannot replace these genuine enrollment and purpose checks.
    admitted = caller._admit_enrollment_on_work(
        authorization_enrollment_bytes=material.authorization_enrollment_bytes,
        current_root_enrollment_bytes=material.current_root_enrollment_bytes,
        grant_enrollment_bytes=material.grant_enrollment_bytes, root_public_key=root,
        configuration_digest=configuration_digest, planner_public_key=material.planner_public_key,
        operation_public_key=material.operation_public_key, work=work)
    for actual, expected, label in (
            (admitted.enrollment_digest, material.authorization_enrollment_digest, "caller enrollment"),
            (admitted.payload["generationDigest"], generation_digest, "parent generation"),
            (admitted.payload["callerId"], material.caller_id, "caller identity"),
            (admitted.payload["callerKey"]["measurementDigest"], material.caller_measurement_digest,
                "caller measurement"),
            (caller.keys._spki_on_work(admitted.caller_public_key, work),
                caller.keys._spki_on_work(material.caller_public_key, work), "caller public key")):
        plan._same(actual, expected, work, "completion recovery " + label)
    return _CompletionRecoveryScope(endpoint, value["packetDigest"],
        value["authorizationDigest"], pending)


def _admit_on_work(*, completion_recovery, activation_execution, consume_execution,
        runtime_root_public_key, configuration_digest, generation_digest, work):
    """Called only by genuine signed-parent admission; opens no live authority."""
    try:
        ledger = capture._SharedLedger(work)
        _shape(completion_recovery)
        if completion_recovery is None:
            return None
        root = runtime_root_public_key
        activation.caller.authorization._public(root)
        shape._digest(configuration_digest)
        shape._digest(generation_digest)
        owned = _Capture(ledger, maximum_bytes=MAX_BYTES).visit(completion_recovery)
        _shape(owned)
        if owned["consume"] is not None:
            if (type(consume_execution) is not consume._ConsumeExecutionMaterial
                    or consume_execution.release_hints is not True
                    or type(activation_execution) is not activation._ActivationExecutionMaterial):
                _fail("consume completion recovery requires the explicit hints-v3 parent lane")
            actual, expected = (consume_execution.current_root_enrollment_bytes,
                activation_execution.current_root_enrollment_bytes)
            work.charge(input_bytes=len(actual) + len(expected))
            if actual != expected:
                _fail("consume recovery differs from the parent's current-root original")
        first = _lane_on_work(owned["activation"], activation_execution,
            expected_type=activation._ActivationExecutionMaterial, caller=activation.caller,
            transport=activation_transport, root=root, configuration_digest=configuration_digest,
            generation_digest=generation_digest, work=work)
        second = _lane_on_work(owned["consume"], consume_execution,
            expected_type=consume._ConsumeExecutionMaterial, caller=consume.caller,
            transport=consume_transport, root=root, configuration_digest=configuration_digest,
            generation_digest=generation_digest, work=work)
        return _CompletionRecoveryMaterial(first, second)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, OidcSessionActivationCompletionRecoveryBootstrapError):
            raise
        raise OidcSessionActivationCompletionRecoveryBootstrapError(
            "completion recovery cold configuration failed") from exc
