"""Dedicated activation caller custody inside explicit root-signed parent v6.

The actual three enrollment originals are authenticated on the parent's work.
This cold mapping supplies no present-user permission or fresh plan authority.
It opens no descriptor, socket, clock or private key and admits no successful
carrier in place of originals. The operation key is the actual runtime root.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_oidc_session_activation_execution_authorization as caller
from serverware import authority_revocation_configuration as configuration
from serverware import oidc_session_activation_planner_bootstrap as planner_bootstrap


SCHEMA = "serverware.controlPlaneOidcSessionActivationExecution/v1"
V2_SCHEMA = "serverware.controlPlaneOidcSessionActivationExecution/v2"
CALLER_KEY_FD = 205
AUTHORIZER_SOCKET_PATH = "/run/serverware/oidc-session-activation-execution/authorizer.sock"
RESERVER_SOCKET_PATH = "/run/serverware/oidc-session-activation-execution/reserver.sock"
SQL_SOCKET_PATH = "/run/serverware/oidc-session-activation-execution/sql.sock"
_FIELDS = frozenset({"schema", "activationCallerPrivateKeyFd", "plannerKey",
    "currentRootEnrollment", "grantEnrollment", "authorizationEnrollment", "authorizerEndpoint"})
_V2_FIELDS = _FIELDS | frozenset({"reserverEndpoint", "sqlEndpoint", "statePredecessor"})
_PLANNER_FIELDS = frozenset({"publicKeyBase64Url", "spkiDigest"})
_ORIGINAL_FIELDS = frozenset({"base64Url", "byteCount"})
_ORIGINAL_LIMITS = (("currentRootEnrollment", caller.authorization.MAX_ENROLLMENT_BYTES),
    ("grantEnrollment", caller.grants.MAX_ENROLLMENT_BYTES),
    ("authorizationEnrollment", caller.MAX_ENROLLMENT_BYTES))
_ENDPOINT_FIELDS = frozenset({"socketPath", "requestTimeoutSeconds", "listenerUid", "listenerGid"})
shape, capture, plan = caller.shape, caller.capture, caller.plan


class OidcSessionActivationExecutionBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ActivationExecutionMaterial:
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


def _endpoint(value, *, _path=AUTHORIZER_SOCKET_PATH):
    if type(_path) is not str or _path not in (
            AUTHORIZER_SOCKET_PATH, RESERVER_SOCKET_PATH, SQL_SOCKET_PATH):
        raise OidcSessionActivationExecutionBootstrapError("activation endpoint profile is not source fixed")
    shape._object(value, _ENDPOINT_FIELDS, "activation caller endpoint")
    shape._literal(value["socketPath"], _path)
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for name in ("listenerUid", "listenerGid"):
        shape._integer(value[name], 2**32 - 2)
        if value[name] != 0:
            raise OidcSessionActivationExecutionBootstrapError(
                "activation listener differs from its fixed root peer")
    return value["socketPath"], value["requestTimeoutSeconds"], 0, 0


def _shape(value):
    if value is None:
        return
    if (type(value) is not dict or type(value.get("schema")) is not str
            or value["schema"] not in (SCHEMA, V2_SCHEMA)):
        raise OidcSessionActivationExecutionBootstrapError("activation execution purpose version differs")
    shape._object(value, _V2_FIELDS if value["schema"] == V2_SCHEMA else _FIELDS,
        "control-plane activation execution purpose")
    shape._integer(value["activationCallerPrivateKeyFd"], 1023, minimum=32)
    if value["activationCallerPrivateKeyFd"] != CALLER_KEY_FD:
        raise OidcSessionActivationExecutionBootstrapError("activation caller FD is not source fixed")
    selected = value["plannerKey"]
    shape._object(selected, _PLANNER_FIELDS, "dedicated activation planner public key")
    caller.authorization.transport._transport_shape(selected["publicKeyBase64Url"], 32, 32)
    shape._digest(selected["spkiDigest"])
    for name, maximum in _ORIGINAL_LIMITS:
        original = value[name]
        shape._object(original, _ORIGINAL_FIELDS, "activation caller enrollment original")
        caller.authorization.transport._transport_shape(
            original["base64Url"], original["byteCount"], maximum)
    _endpoint(value["authorizerEndpoint"])
    if value["schema"] == V2_SCHEMA:
        _endpoint(value["reserverEndpoint"], _path=RESERVER_SOCKET_PATH)
        _endpoint(value["sqlEndpoint"], _path=SQL_SOCKET_PATH)
        predecessor = value["statePredecessor"]
        shape._object(predecessor, frozenset({"sequence", "headDigest", "nextFence"}),
            "independent activation reservation predecessor")
        shape._integer(predecessor["sequence"], caller.authorization.MAX_RECORDS)
        shape._digest(predecessor["headDigest"])
        shape._integer(predecessor["nextFence"], minimum=1)
        if predecessor["sequence"] == 0 and predecessor["nextFence"] != 1:
            raise OidcSessionActivationExecutionBootstrapError("activation genesis requires fence one")


def _purpose_pins(configured, root, other_keys, work):
    """Actual configured and retained purposes, not caller-selected exclusions."""
    pins = [caller.keys._spki_on_work(root, work)]
    roles = configured["roles"]
    shape._object(roles, frozenset(configuration._ROLE_NAMES), "activation caller configured roles")
    for name in configuration._ROLE_NAMES:
        role = roles[name]
        shape._digest(role["responseSigningSpkiDigest"])
        pins.append(role["responseSigningSpkiDigest"])
        if name in ("verifier", "planner"):
            shape._digest(role["signingSpkiDigest"])
            configuration._key(role["signingPublicKeyBase64Url"], work,
                expected_spki=role["signingSpkiDigest"])
            pins.append(role["signingSpkiDigest"])
    planner_bootstrap.enabled._require_enabled_operation(roles["planner"], caller.OPERATION, work)
    for module, slots in ((planner_bootstrap.evidence_policy, ("registration", "installation")),
            (planner_bootstrap.transition_policy, ("registration", "stage", "completion"))):
        value = configured.get(module.FIELD)
        if value is not None:
            policy, _keys = module._validate_policy_on_work(value,
                webauthn=configured["webauthn"], work=work)
            pins.extend(policy[name]["signingSpkiDigest"] for name in slots if policy[name] is not None)
    module = planner_bootstrap.enrollment_policy
    value = configured.get(module.FIELD)
    if value is not None:
        policy, _key = module._validate_policy_on_work(value, payload=configured, work=work)
        pins.append(policy["signingSpkiDigest"])
    for key in other_keys:
        if key is not None:
            caller.authorization._public(key)
            pins.append(caller.keys._spki_on_work(key, work))
    return tuple(pins)


def _admit_on_work(*, activation_execution, configuration_payload, configuration_digest,
        generation, runtime_role_identities, runtime_root_public_key, issuer_public_key,
        execution_caller_public_key, finalization_caller_public_key, work):
    """Authenticate original caller scope; never infer present-user authority."""
    try:
        ledger = capture._SharedLedger(work)
        root, digest = runtime_root_public_key, configuration_digest
        other_keys = issuer_public_key, execution_caller_public_key, finalization_caller_public_key
        _shape(activation_execution)
        if activation_execution is None:
            return None
        caller.authorization._public(root)
        shape._digest(digest)
        shape._bounded_object(generation, 24, "activation caller launch context")
        owned = configuration._ConfigurationCapture(ledger,
            maximum_bytes=configuration.authority.MAX_REQUEST_BYTES).visit({
                "activation": activation_execution, "configuration": configuration_payload,
                "generation": {name: generation[name] for name in configuration._GENERATION_FIELDS},
                "runtime": runtime_role_identities})
        value = owned["activation"]
        _shape(value)
        configured, launch = configuration._capture_configuration_on_work(
            payload=owned["configuration"], configuration_digest=digest,
            generation=owned["generation"], work=work)
        configuration._capture_runtime_role_identities_on_work(
            runtime_role_identities=owned["runtime"], owned_payload=configured,
            configuration_digest=digest, launch=launch, work=work)
        selected = value["plannerKey"]
        planner = configuration._key(selected["publicKeyBase64Url"], work,
            expected_spki=selected["spkiDigest"])
        current_raw, grant_raw, caller_raw = tuple(caller.authorization.transport._decode(
            value[name]["base64Url"], value[name]["byteCount"], maximum, work)
            for name, maximum in _ORIGINAL_LIMITS)
        admitted = caller._admit_enrollment_on_work(authorization_enrollment_bytes=caller_raw,
            current_root_enrollment_bytes=current_raw, grant_enrollment_bytes=grant_raw,
            root_public_key=root, configuration_digest=digest, planner_public_key=planner,
            operation_public_key=root, work=work)
        policy = admitted.payload
        plan._same(policy["generationDigest"], launch["digest"], work,
            "activation caller enrollment differs from its actual parent generation")
        forbidden = _purpose_pins(configured, root, other_keys, work)
        work.prepare_scan(forbidden)
        for pin in (selected["spkiDigest"], policy["callerKey"]["spkiDigest"]):
            for other in forbidden:
                work.prepare_comparison(pin, other)
                if pin == other:
                    raise OidcSessionActivationExecutionBootstrapError(
                        "activation caller or planner key reuses another configured purpose")
        reservation_endpoint = reservation_predecessor = sql_endpoint = None
        if value["schema"] == V2_SCHEMA:
            current = caller.authorization._admit_enrollment_on_work(
                enrollment_bytes=current_raw, root_public_key=root, work=work)
            for actual, expected in (
                    (current.enrollment_digest, policy["currentRootEnrollmentDigest"]),
                    (current.payload["generationDigest"], launch["digest"]),
                    (current.payload["databaseId"], policy["databaseId"])):
                plan._same(actual, expected, work,
                    "activation predecessor differs from its actual original enrollment")
            predecessor = value["statePredecessor"]
            if predecessor["sequence"] + 2 > current.payload["maxRecords"]:
                raise OidcSessionActivationExecutionBootstrapError(
                    "activation predecessor lacks enrolled reserve and completion capacity")
            if predecessor["sequence"] == 0:
                plan._same(predecessor["headDigest"], current.enrollment_digest, work,
                    "activation independent genesis head differs")
            reservation_endpoint = _endpoint(value["reserverEndpoint"], _path=RESERVER_SOCKET_PATH)
            reservation_predecessor = (predecessor["sequence"], predecessor["headDigest"],
                predecessor["nextFence"])
            sql_endpoint = _endpoint(value["sqlEndpoint"], _path=SQL_SOCKET_PATH)
        return _ActivationExecutionMaterial(CALLER_KEY_FD, admitted.caller_public_key, planner, root,
            current_raw, grant_raw, caller_raw, admitted.enrollment_digest, policy["callerId"],
            policy["callerKey"]["measurementDigest"], policy["maximumAgeNs"],
            policy["maximumClockSkewNs"], _endpoint(value["authorizerEndpoint"]),
            reservation_endpoint, reservation_predecessor, sql_endpoint)
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, OidcSessionActivationExecutionBootstrapError):
            raise
        raise OidcSessionActivationExecutionBootstrapError("activation caller cold admission failed") from exc
