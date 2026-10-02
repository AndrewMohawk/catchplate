"""Closed opt-in caller-key scope for the v3 control-plane cold bootstrap.

The parent authenticates the complete original v3 envelope under its already
admitted runtime root. This module additionally authenticates all three actual
enrollment originals and joins their caller/configuration/generation/key scope.
The exact nested v1 profile remains authorizer-only. Opt-in nested v2 also pins
the separate reserver endpoint and one independent state predecessor/fence;
neither is inferred from an acknowledgment or recovered journal observation.
Nested v3 additionally pins SQL/completion endpoints, the same operation's
independent current pending scope and completion packet identity. No response
advances those cold pins or automatically promotes an older profile.
It does not deliver descriptors, read private keys, authenticate an actor,
issue permission or open a transport. Returned material is owned data only.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_registration_execution_authorization as caller
from serverware import authority_revocation_configuration as configuration
from serverware import authority_webauthn_enrollment_policy as enrollment_policy
from serverware import authority_webauthn_evidence_policy as evidence_policy


SCHEMA = "serverware.controlPlaneRegistrationExecution/v1"
V2_SCHEMA = "serverware.controlPlaneRegistrationExecution/v2"
V3_SCHEMA = "serverware.controlPlaneRegistrationExecution/v3"
LOCAL_SCHEMA = "serverware.controlPlaneRegistrationExecution/v4"
CALLER_KEY_FD = 203
AUTHORIZER_SOCKET_PATH = "/run/serverware/registration-execution/authorizer.sock"
RESERVER_SOCKET_PATH = "/run/serverware/registration-execution/reserver.sock"
SQL_SOCKET_PATH = "/run/serverware/registration-execution/sql.sock"
COMPLETION_SOCKET_PATH = "/run/serverware/registration-execution/completion.sock"
_FIELDS = frozenset({"schema", "executionCallerPrivateKeyFd", "currentRootEnrollment",
    "grantEnrollment", "authorizationEnrollment", "authorizerEndpoint"})
_V2_FIELDS = _FIELDS | frozenset({"reserverEndpoint", "statePredecessor"})
_V3_FIELDS = _V2_FIELDS | frozenset({"sqlEndpoint", "completionEndpoint",
    "currentPending", "completionPacketDigest"})
_LOCAL_FIELDS = _FIELDS | frozenset({"reserverEndpoint", "sqlEndpoint", "completionEndpoint", "contextDirectory"})
_ORIGINAL_FIELDS = frozenset({"base64Url", "byteCount"})
_ENDPOINT_FIELDS = frozenset({"socketPath", "requestTimeoutSeconds", "listenerUid", "listenerGid"})
_ORIGINAL_LIMITS = (("currentRootEnrollment", caller.authorization.MAX_ENROLLMENT_BYTES),
    ("grantEnrollment", caller.grants.MAX_ENROLLMENT_BYTES),
    ("authorizationEnrollment", caller.MAX_ENROLLMENT_BYTES))
shape, capture, plan = caller.shape, caller.capture, caller.plan


class RegistrationExecutionBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ExecutionMaterial:
    caller_private_key_fd: int
    caller_public_key: object
    current_root_enrollment_bytes: bytes
    grant_enrollment_bytes: bytes
    authorization_enrollment_bytes: bytes
    authorizer_endpoint: tuple
    reservation_endpoint: tuple | None = None
    reservation_predecessor: tuple | None = None
    sql_endpoint: tuple | None = None
    completion_endpoint: tuple | None = None
    current_pending: tuple | None = None
    completion_packet_digest: str | None = None
    context_directory: tuple | None = None


def _endpoint(value):
    shape._object(value, _ENDPOINT_FIELDS, "registration execution authorizer endpoint")
    shape._literal(value["socketPath"], AUTHORIZER_SOCKET_PATH)
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for name in ("listenerUid", "listenerGid"):
        shape._integer(value[name], 2**32 - 2)
        if value[name] != 0:
            raise RegistrationExecutionBootstrapError("authorizer listener must retain the fixed root peer identity")
    # This pins the system manager's listen() identity, not the accepting child.
    return value["socketPath"], value["requestTimeoutSeconds"], 0, 0


def _shape(value):
    if value is None:
        return
    if type(value) is not dict:
        raise RegistrationExecutionBootstrapError("control-plane registration execution scope is not an exact object")
    version = value.get("schema")
    if type(version) is not str or version not in (SCHEMA, V2_SCHEMA, V3_SCHEMA, LOCAL_SCHEMA):
        raise RegistrationExecutionBootstrapError("control-plane registration execution profile is unsupported")
    fields = _LOCAL_FIELDS if version == LOCAL_SCHEMA else _FIELDS if version == SCHEMA else _V2_FIELDS if version == V2_SCHEMA else _V3_FIELDS
    shape._object(value, fields,
        "control-plane registration execution scope")
    shape._integer(value["executionCallerPrivateKeyFd"], 1023, minimum=32)
    if value["executionCallerPrivateKeyFd"] != CALLER_KEY_FD:
        raise RegistrationExecutionBootstrapError("registration execution caller key FD is not source fixed")
    for name, maximum in _ORIGINAL_LIMITS:
        original = value[name]
        shape._object(original, _ORIGINAL_FIELDS, "registration execution enrollment original")
        caller.authorization.transport._transport_shape(
            original["base64Url"], original["byteCount"], maximum)
    _endpoint(value["authorizerEndpoint"])
    if version == LOCAL_SCHEMA:
        from serverware import authority_local_registration_context as contexts
        contexts.directory(value["contextDirectory"])
        _reserver_endpoint(value["reserverEndpoint"])
        _handoff_endpoint(value["sqlEndpoint"], SQL_SOCKET_PATH)
        _handoff_endpoint(value["completionEndpoint"], COMPLETION_SOCKET_PATH)
    if version in (V2_SCHEMA, V3_SCHEMA):
        _reserver_endpoint(value["reserverEndpoint"])
        predecessor = value["statePredecessor"]
        shape._object(predecessor, frozenset({"sequence", "headDigest", "nextFence"}),
            "independent registration reservation predecessor")
        shape._integer(predecessor["sequence"], caller.authorization.MAX_RECORDS)
        shape._digest(predecessor["headDigest"])
        shape._integer(predecessor["nextFence"], minimum=1)
        if predecessor["sequence"] == 0 and predecessor["nextFence"] != 1:
            raise RegistrationExecutionBootstrapError("genesis reservation predecessor requires fence one")
    if version == V3_SCHEMA:
        _handoff_endpoint(value["sqlEndpoint"], SQL_SOCKET_PATH)
        _handoff_endpoint(value["completionEndpoint"], COMPLETION_SOCKET_PATH)
        pending = value["currentPending"]
        shape._object(pending, frozenset({"sequence", "headDigest", "fence"}),
            "independent registration execution current pending scope")
        shape._integer(pending["sequence"], caller.authorization.MAX_RECORDS, minimum=1)
        shape._digest(pending["headDigest"])
        shape._integer(pending["fence"], minimum=1)
        shape._digest(value["completionPacketDigest"])
        if (pending["sequence"] != predecessor["sequence"] + 1
                or pending["fence"] != predecessor["nextFence"]):
            raise RegistrationExecutionBootstrapError("execution pending scope is not this cold reservation's successor")


def _reserver_endpoint(value):
    shape._object(value, _ENDPOINT_FIELDS, "registration execution reserver endpoint")
    shape._literal(value["socketPath"], RESERVER_SOCKET_PATH)
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for name in ("listenerUid", "listenerGid"):
        shape._integer(value[name], 2**32 - 2)
        if value[name] != 0:
            raise RegistrationExecutionBootstrapError("reserver listener must retain the fixed root peer identity")
    # The peer is the root socket activator, not the accepting UID 65514 child.
    return value["socketPath"], value["requestTimeoutSeconds"], 0, 0


def _handoff_endpoint(value, path):
    if path not in (SQL_SOCKET_PATH, COMPLETION_SOCKET_PATH):
        raise RegistrationExecutionBootstrapError("registration handoff endpoint purpose is not source fixed")
    shape._object(value, _ENDPOINT_FIELDS, "registration SQL/completion handoff endpoint")
    shape._literal(value["socketPath"], path)
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for name in ("listenerUid", "listenerGid"):
        shape._integer(value[name], 2**32 - 2)
        if value[name] != 0:
            raise RegistrationExecutionBootstrapError("handoff listener must retain the fixed root peer identity")
    # Pin the root manager's activated listener, not an asserted service UID.
    return value["socketPath"], value["requestTimeoutSeconds"], 0, 0


def _admit_on_work(*, registration_execution, configuration_payload,
        configuration_digest, generation, runtime_role_identities,
        runtime_root_public_key, issuer_public_key, work):
    """Authenticate actual original enrollments on the parent's existing work."""
    try:
        ledger = capture._SharedLedger(work)
        _shape(registration_execution)
        if registration_execution is None:
            return None
        root, issuer, digest = runtime_root_public_key, issuer_public_key, configuration_digest
        caller.authorization._public(root)
        caller.authorization._public(issuer)
        shape._digest(digest)
        shape._bounded_object(generation, 24, "execution caller launch context")
        # Own all mutable graphs before any genuine key/hash callback.
        owned = configuration._ConfigurationCapture(ledger,
            maximum_bytes=caller.grants.authority.MAX_REQUEST_BYTES).visit({
                "execution": registration_execution, "configuration": configuration_payload,
                "generation": {name: generation[name] for name in configuration._GENERATION_FIELDS},
                "runtime": runtime_role_identities})
        value, configured = owned["execution"], owned["configuration"]
        _shape(value)
        mapped = enrollment_policy._capture_on_work(payload=configured,
            configuration_digest=digest, generation=owned["generation"],
            runtime_role_identities=owned["runtime"], work=work)
        plan._same(caller.keys._spki_on_work(issuer, work), mapped.policy["signingSpkiDigest"],
            work, "execution caller bootstrap differs from the actual enrollment issuer key")
        purposes, evidence_keys = evidence_policy._validate_policy_on_work(
            configured.get(evidence_policy.FIELD), webauthn=configured["webauthn"], work=work)
        if purposes["registration"] is None:
            raise RegistrationExecutionBootstrapError("registration evidence purpose is disabled")
        roles = configured["roles"]
        shape._object(roles, frozenset(configuration._ROLE_NAMES), "execution caller configured roles")
        planner = configuration._key(roles["planner"]["signingPublicKeyBase64Url"], work,
            expected_spki=roles["planner"]["signingSpkiDigest"])
        originals = tuple(caller.authorization.transport._decode(
            value[name]["base64Url"], value[name]["byteCount"], maximum, work)
            for name, maximum in _ORIGINAL_LIMITS)
        current_raw, grant_raw, authorization_raw = originals
        admitted = caller._admit_enrollment_on_work(authorization_enrollment_bytes=authorization_raw,
            current_root_enrollment_bytes=current_raw, grant_enrollment_bytes=grant_raw,
            root_public_key=root, configuration_digest=digest, planner_public_key=planner,
            evidence_public_key=evidence_keys["registration"], work=work)
        plan._same(admitted.payload["generationDigest"], mapped.generation_digest, work,
            "execution caller enrollment generation differs from actual configuration")
        caller_pin = admitted.payload["callerKey"]["spkiDigest"]
        forbidden = [mapped.policy["signingSpkiDigest"]]
        for name in configuration._ROLE_NAMES:
            role = roles[name]
            shape._digest(role["responseSigningSpkiDigest"])
            forbidden.append(role["responseSigningSpkiDigest"])
            if name in ("verifier", "planner"):
                shape._digest(role["signingSpkiDigest"])
                forbidden.append(role["signingSpkiDigest"])
        for name in ("registration", "installation"):
            if purposes[name] is not None:
                forbidden.append(purposes[name]["signingSpkiDigest"])
        transitions = configured.get(enrollment_policy.transition_policy.FIELD)
        if transitions is not None:
            for name in ("registration", "stage", "completion"):
                if transitions[name] is not None:
                    forbidden.append(transitions[name]["signingSpkiDigest"])
        work.prepare_scan(forbidden)
        for pin in forbidden:
            work.prepare_comparison(caller_pin, pin)
            if caller_pin == pin:
                raise RegistrationExecutionBootstrapError("execution caller key reuses another configured purpose")
        reservation_endpoint = reservation_predecessor = None
        sql_endpoint = completion_endpoint = current_pending = completion_packet_digest = None
        if value["schema"] in (V2_SCHEMA, V3_SCHEMA):
            # Read capacity only from genuine admission of this same original
            # enrollment. The parent's root signature, not these data fields,
            # is the prerequisite for selecting an independent predecessor.
            current = caller.authorization._admit_enrollment_on_work(enrollment_bytes=current_raw,
                root_public_key=root, work=work)
            plan._same(current.enrollment_digest, admitted.payload["currentRootEnrollmentDigest"], work,
                "reservation predecessor enrollment differs from actual caller enrollment")
            predecessor = value["statePredecessor"]
            if predecessor["sequence"] > current.payload["maxRecords"]:
                raise RegistrationExecutionBootstrapError("reservation predecessor exceeds enrolled capacity")
            if predecessor["sequence"] == 0:
                plan._same(predecessor["headDigest"], current.enrollment_digest, work,
                    "reservation independent genesis head differs")
            reservation_endpoint = _reserver_endpoint(value["reserverEndpoint"])
            reservation_predecessor = (predecessor["sequence"], predecessor["headDigest"],
                predecessor["nextFence"])
            if value["schema"] == V3_SCHEMA:
                pending = value["currentPending"]
                if pending["sequence"] >= current.payload["maxRecords"]:
                    raise RegistrationExecutionBootstrapError("execution pending scope has no enrolled completion capacity")
                # These are independently signed pins for ONE operation, not
                # observations adopted from its reservation response/journal.
                current_pending = (pending["sequence"], pending["headDigest"], pending["fence"])
                completion_packet_digest = value["completionPacketDigest"]
                sql_endpoint = _handoff_endpoint(value["sqlEndpoint"], SQL_SOCKET_PATH)
                completion_endpoint = _handoff_endpoint(value["completionEndpoint"], COMPLETION_SOCKET_PATH)
        context_directory = None
        if value["schema"] == LOCAL_SCHEMA:
            from serverware import authority_local_registration_context as contexts
            contexts._development()
            context_directory = contexts.directory(value["contextDirectory"])
            reservation_endpoint = _reserver_endpoint(value["reserverEndpoint"])
            sql_endpoint = _handoff_endpoint(value["sqlEndpoint"], SQL_SOCKET_PATH)
            completion_endpoint = _handoff_endpoint(value["completionEndpoint"], COMPLETION_SOCKET_PATH)
        return _ExecutionMaterial(CALLER_KEY_FD, admitted.caller_public_key, current_raw,
            grant_raw, authorization_raw, _endpoint(value["authorizerEndpoint"]),
            reservation_endpoint, reservation_predecessor, sql_endpoint, completion_endpoint,
            current_pending, completion_packet_digest, context_directory)
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, RegistrationExecutionBootstrapError):
            raise
        raise RegistrationExecutionBootstrapError("registration execution caller bootstrap admission failed") from exc
