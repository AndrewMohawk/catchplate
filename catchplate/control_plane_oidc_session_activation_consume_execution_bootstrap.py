"""Dedicated consume caller enrollment inside explicit control-plane v8.

Only original enrollments and the actual parent's independently configured
keys are admitted. This cold mapping supplies no present permission, plan,
private replay, socket request or renewed processing allowance.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_oidc_session_activation_delivery_execution_authorization as caller
from catchplate import authority_oidc_session_activation_delivery_reservation_records as reservation_records
from catchplate import control_plane_oidc_session_activation_execution_bootstrap as activation
from catchplate import control_plane_oidc_session_activation_planning_bootstrap as planning


SCHEMA = "catchplate.controlPlaneOidcSessionActivationConsumeExecution/v1"
V2_SCHEMA = "catchplate.controlPlaneOidcSessionActivationConsumeExecution/v2"
V3_SCHEMA = "catchplate.controlPlaneOidcSessionActivationConsumeExecution/v3"
V4_SCHEMA = "catchplate.controlPlaneOidcSessionActivationConsumeExecution/v4"
V5_SCHEMA = "catchplate.controlPlaneOidcSessionActivationConsumeExecution/v5"
CALLER_KEY_FD = 206
AUTHORIZER_SOCKET_PATH = "/run/catchplate/oidc-session-activation-delivery-execution/authorizer.sock"
RESERVATION_SOCKET_PATH = "/run/catchplate/oidc-session-activation-delivery-execution/reserver.sock"
SQL_SOCKET_PATH = "/run/catchplate/oidc-session-activation-delivery-execution/sql.sock"
COMPLETION_SOCKET_PATH = "/run/catchplate/oidc-session-activation-delivery-execution/completion.sock"
_FIELDS = frozenset({"schema", "callerPrivateKeyFd", "grantEnrollment",
    "authorizationEnrollment", "authorizerEndpoint"})
_V2_FIELDS = _FIELDS | frozenset({"reservationEndpoint", "reservationPredecessor", "sqlEndpoint"})
_V3_FIELDS = _V2_FIELDS | frozenset({"completionEndpoint"})
_V5_FIELDS = _V3_FIELDS - frozenset({"reservationPredecessor"})
_PREDECESSOR_FIELDS = frozenset({"sequence", "headDigest", "nextFence"})
_ORIGINAL_FIELDS = frozenset({"base64Url", "byteCount"})
_ORIGINAL_LIMITS = (("grantEnrollment", caller.enrollments.MAX_ENROLLMENT_BYTES),
    ("authorizationEnrollment", caller.MAX_ENROLLMENT_BYTES))
_ENDPOINT_FIELDS = frozenset({"socketPath", "requestTimeoutSeconds", "listenerUid", "listenerGid"})
configuration = activation.configuration
shape, capture, plan = caller.shape, caller.capture, caller.plan


class OidcSessionActivationConsumeExecutionBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ConsumeExecutionMaterial:
    caller_private_key_fd: int
    caller_public_key: object
    planner_public_key: object
    operation_public_key: object
    current_root_enrollment_bytes: bytes
    grant_enrollment_bytes: bytes
    authorization_enrollment_bytes: bytes
    authorization_enrollment_digest: str
    caller_id: str
    caller_measurement_digest: str
    maximum_age_ns: int
    maximum_clock_skew_ns: int
    authorizer_endpoint: tuple
    reservation_endpoint: tuple | None = None
    reservation_predecessor: tuple | None = None
    sql_endpoint: tuple | None = None
    completion_endpoint: tuple | None = None
    release_hints: bool = False
    # Output metadata for the explicit resource-only version, not permission
    # to consume a caller-selected future predecessor or reservation.
    request_bound: bool = False


def _endpoint(value, *, _path=AUTHORIZER_SOCKET_PATH):
    if type(_path) is not str or _path not in (AUTHORIZER_SOCKET_PATH, RESERVATION_SOCKET_PATH,
            SQL_SOCKET_PATH, COMPLETION_SOCKET_PATH):
        raise OidcSessionActivationConsumeExecutionBootstrapError("consume endpoint profile is not source fixed")
    shape._object(value, _ENDPOINT_FIELDS, "consume caller endpoint")
    shape._literal(value["socketPath"], _path)
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for name in ("listenerUid", "listenerGid"):
        shape._integer(value[name], 2**32 - 2)
        if value[name] != 0:
            raise OidcSessionActivationConsumeExecutionBootstrapError(
                "consume listener must be the fixed root peer")
    return value["socketPath"], value["requestTimeoutSeconds"], 0, 0


def _predecessor(value):
    shape._object(value, _PREDECESSOR_FIELDS, "independent consume reservation predecessor")
    selected = reservation_records._predecessor_scope(
        value["sequence"], value["headDigest"], value["nextFence"])
    if selected[0] == 0 and selected[2] != 1:
        raise OidcSessionActivationConsumeExecutionBootstrapError("consume genesis requires fence one")
    return selected


def _shape(value):
    if value is None:
        return
    if (type(value) is not dict or type(value.get("schema")) is not str
            or value["schema"] not in (SCHEMA, V2_SCHEMA, V3_SCHEMA, V4_SCHEMA, V5_SCHEMA)):
        raise OidcSessionActivationConsumeExecutionBootstrapError("consume caller purpose version differs")
    fields = (_V5_FIELDS if value["schema"] == V5_SCHEMA else _V3_FIELDS
        if value["schema"] in (V3_SCHEMA, V4_SCHEMA) else _V2_FIELDS if value["schema"] == V2_SCHEMA else _FIELDS)
    shape._object(value, fields,
        "control-plane consume caller purpose")
    shape._integer(value["callerPrivateKeyFd"], 1023, minimum=32)
    if value["callerPrivateKeyFd"] != CALLER_KEY_FD:
        raise OidcSessionActivationConsumeExecutionBootstrapError(
            "consume caller descriptor is not the dedicated fixed slot")
    for name, maximum in _ORIGINAL_LIMITS:
        original = value[name]
        shape._object(original, _ORIGINAL_FIELDS, "consume caller enrollment original")
        shape._integer(original["byteCount"], maximum, minimum=2)
        caller.authorization.transport._transport_shape(
            original["base64Url"], original["byteCount"], maximum)
    _endpoint(value["authorizerEndpoint"])
    if value["schema"] in (V2_SCHEMA, V3_SCHEMA, V4_SCHEMA, V5_SCHEMA):
        _endpoint(value["reservationEndpoint"], _path=RESERVATION_SOCKET_PATH)
        _endpoint(value["sqlEndpoint"], _path=SQL_SOCKET_PATH)
        if value["schema"] != V5_SCHEMA:
            _predecessor(value["reservationPredecessor"])
    if value["schema"] in (V3_SCHEMA, V4_SCHEMA, V5_SCHEMA):
        _endpoint(value["completionEndpoint"], _path=COMPLETION_SOCKET_PATH)


def _request_policy_on_work(*, planned, parent, configured, launch, runtime,
        digest, root, work, live_window, transport_deadline_ns):
    """Reverify genuine static originals, never substitute a future planner.

    Shared by the two explicit resource-only cold versions. None/None is cold
    policy freshness; a supplied processing pair retains its actual original
    bounds. Neither branch manufactures a request vector, nonce or state head.
    """
    from catchplate import control_plane_oidc_session_activation_request_issuance_bootstrap as requested

    if (type(planned) is not requested._RequestPlanningMaterial
            or type(parent) is not activation._ActivationExecutionMaterial
            or (live_window is None) != (transport_deadline_ns is None)):
        raise OidcSessionActivationConsumeExecutionBootstrapError(
            "resource-only consume requires genuine request planning and complete original bounds")
    requested.transport._endpoint(planned.issuance_endpoint)
    endpoint = planned.planner_endpoint
    if type(endpoint) is not tuple or len(endpoint) != 4:
        raise OidcSessionActivationConsumeExecutionBootstrapError("request planner endpoint is not exact")
    # Fixed endpoint projection and the nine bounded original/key/cohort joins;
    # all actual policy decoding, cryptography and comparisons charge separately.
    work.charge(input_bytes=8192, json_nodes=256)
    endpoint = planning._endpoint(dict(zip(("socketPath", "requestTimeoutSeconds", "listenerUid", "listenerGid"), endpoint)))
    admitted = requested.policy._verify_on_work(policy_bytes=planned.policy_bytes,
        root_public_key=root, live_window=live_window,
        transport_deadline_ns=transport_deadline_ns, work=work)
    configured_policy, generation_policy, runtime_policy, public, current_raw, _pin, _reader = admitted.resource_facts
    for actual, expected in ((configured_policy, configured), (generation_policy, launch),
            (runtime_policy, runtime)):
        planning._same_configuration(actual, expected, work, "resource-only parent configuration cohort")
    plan._same(admitted.payload["plannerResources"]["configurationDigest"], digest,
        work, "resource-only parent configuration identity")
    for actual, expected in ((current_raw, parent.current_root_enrollment_bytes),
            (admitted.authorization_enrollment, parent.authorization_enrollment_bytes),
            (admitted.grant_enrollment, parent.grant_enrollment_bytes)):
        work.charge(input_bytes=len(actual) + len(expected))
        if actual != expected:
            raise OidcSessionActivationConsumeExecutionBootstrapError(
                "resource-only planning changed an actual parent enrollment")
    for actual, expected in ((public, parent.planner_public_key),
            (admitted.caller.caller_public_key, parent.caller_public_key),
            (root, parent.operation_public_key)):
        plan._same(requested.policy.keys._spki_on_work(actual, work),
            requested.policy.keys._spki_on_work(expected, work), work,
            "resource-only planning changed an actual parent purpose key")
    if endpoint[1] > admitted.payload["plannerResources"]["launch"]["requestTimeoutSeconds"]:
        raise OidcSessionActivationConsumeExecutionBootstrapError("request planner endpoint widens its original timeout")
    admitted.live()
    return admitted


def _admit_on_work(*, consume_execution, configuration_payload, configuration_digest,
        generation, runtime_role_identities, runtime_root_public_key,
        activation_execution, activation_planning, issuer_public_key,
        execution_caller_public_key, finalization_caller_public_key, work,
        live_window=None, transport_deadline_ns=None):
    """Compose genuine cold original admission; no carrier grants permission."""
    try:
        ledger = capture._SharedLedger(work)
        root, digest = runtime_root_public_key, configuration_digest
        parent, planned = activation_execution, activation_planning
        other_keys = issuer_public_key, execution_caller_public_key, finalization_caller_public_key
        _shape(consume_execution)
        if consume_execution is None:
            return None
        if (live_window is None) != (transport_deadline_ns is None):
            raise OidcSessionActivationConsumeExecutionBootstrapError("consume requires the complete original processing pair")
        processing = (None if live_window is None else
            planning.planner._processing(live_window, transport_deadline_ns, work))
        if processing is not None:
            processing()
        request_bound = consume_execution["schema"] == V5_SCHEMA
        planning_type = planning._PlanningMaterial
        if request_bound:
            from catchplate import control_plane_oidc_session_activation_request_issuance_bootstrap as requested
            planning_type = requested._RequestPlanningMaterial
        if (type(parent) is not activation._ActivationExecutionMaterial
                or type(planned) is not planning_type
                or parent.consume_planner_public_key is None
                or parent.consume_planner_endpoint is None
                or parent.consume_planner_measurement_digest is None):
            raise OidcSessionActivationConsumeExecutionBootstrapError(
                "consume caller requires actual activation v4 and enabled planning")
        planner_key, current_raw = parent.consume_planner_public_key, parent.current_root_enrollment_bytes
        other_keys = (*other_keys, parent.caller_public_key, parent.planner_public_key, planner_key)
        caller.authorization._public(root)
        caller.authorization._public(planner_key)
        caller.authorization._original(current_raw, caller.authorization.MAX_ENROLLMENT_BYTES,
            "actual activation current-root enrollment")
        shape._digest(digest)
        shape._bounded_object(generation, 24, "consume caller parent generation")
        owned = configuration._ConfigurationCapture(ledger,
            maximum_bytes=configuration.authority.MAX_REQUEST_BYTES).visit({
                "consume": consume_execution, "configuration": configuration_payload,
                "generation": {name: generation[name] for name in configuration._GENERATION_FIELDS},
                "runtime": runtime_role_identities})
        value = owned["consume"]
        _shape(value)
        configured, launch = configuration._capture_configuration_on_work(
            payload=owned["configuration"], configuration_digest=digest,
            generation=owned["generation"], work=work)
        identities = configuration._capture_runtime_role_identities_on_work(
            runtime_role_identities=owned["runtime"], owned_payload=configured,
            configuration_digest=digest, launch=launch, work=work)
        resources = None
        if request_bound:
            resources = _request_policy_on_work(planned=planned, parent=parent,
                configured=configured, launch=launch, runtime=identities, digest=digest,
                root=root, work=work, live_window=live_window, transport_deadline_ns=transport_deadline_ns)
        grant_raw, caller_raw = tuple(caller.authorization.transport._decode(
            value[name]["base64Url"], value[name]["byteCount"], maximum, work)
            for name, maximum in _ORIGINAL_LIMITS)
        admitted = caller._admit_enrollment_on_work(authorization_enrollment_bytes=caller_raw,
            current_root_enrollment_bytes=current_raw, grant_enrollment_bytes=grant_raw,
            root_public_key=root, configuration_digest=digest, planner_public_key=planner_key,
            operation_public_key=root, work=work)
        policy = admitted.payload
        plan._same(policy["generationDigest"], launch["digest"], work,
            "consume caller differs from the actual parent generation")
        forbidden = activation._purpose_pins(configured, root, other_keys, work)
        pin = policy["callerKey"]["spkiDigest"]
        work.prepare_scan(forbidden)
        for other in forbidden:
            work.prepare_comparison(pin, other)
            if pin == other:
                raise OidcSessionActivationConsumeExecutionBootstrapError(
                    "consume caller key reuses another independently configured purpose")
        reservation_endpoint = reservation_predecessor = sql_endpoint = completion_endpoint = None
        if value["schema"] in (V2_SCHEMA, V3_SCHEMA, V4_SCHEMA, V5_SCHEMA):
            current = caller.authorization._admit_enrollment_on_work(
                enrollment_bytes=current_raw, root_public_key=root, work=work)
            for actual, expected in (
                    (current.enrollment_digest, policy["currentRootEnrollmentDigest"]),
                    (current.payload["generationDigest"], launch["digest"]),
                    (current.payload["databaseId"], policy["databaseId"])):
                plan._same(actual, expected, work, "consume predecessor original enrollment")
            if not request_bound:
                reservation_predecessor = _predecessor(value["reservationPredecessor"])
                sequence, head, fence = reservation_predecessor
                if sequence + 2 > current.payload["maxRecords"]:
                    raise OidcSessionActivationConsumeExecutionBootstrapError(
                        "consume predecessor lacks enrolled reserve and completion capacity")
                if sequence == 0:
                    plan._same(head, current.enrollment_digest, work, "consume independent genesis head")
            reservation_endpoint = _endpoint(value["reservationEndpoint"], _path=RESERVATION_SOCKET_PATH)
            sql_endpoint = _endpoint(value["sqlEndpoint"], _path=SQL_SOCKET_PATH)
        if value["schema"] in (V3_SCHEMA, V4_SCHEMA, V5_SCHEMA):
            completion_endpoint = _endpoint(value["completionEndpoint"], _path=COMPLETION_SOCKET_PATH)
        result = _ConsumeExecutionMaterial(CALLER_KEY_FD, admitted.caller_public_key, planner_key, root,
            current_raw, grant_raw, caller_raw, admitted.enrollment_digest, policy["callerId"],
            policy["callerKey"]["measurementDigest"], policy["maximumAgeNs"],
            policy["maximumClockSkewNs"], _endpoint(value["authorizerEndpoint"]),
            reservation_endpoint, reservation_predecessor, sql_endpoint, completion_endpoint,
            value["schema"] in (V4_SCHEMA, V5_SCHEMA), request_bound)
        if processing is not None:
            processing()
        if resources is not None:
            resources.live()
        return result
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, OidcSessionActivationConsumeExecutionBootstrapError):
            raise
        raise OidcSessionActivationConsumeExecutionBootstrapError(
            "consume caller cold original admission failed") from exc
