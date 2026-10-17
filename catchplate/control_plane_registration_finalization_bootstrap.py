"""Explicit finalization-only caller scope inside root-signed parent v4.

The parent admits the complete original envelope and configuration. This
module then admits the three original enrollments for the dedicated finalization
purpose, its configured transition key and a separate caller public key. No
evidence-execution enrollment, key, endpoint or permission is substituted.
Returned material is private owned data, not present-caller authorization.
No key generation, descriptor access, transport or replacement work occurs here.
Nested v1 remains grant-only. Explicit nested v2 additionally pins one fixed
reserver endpoint and independent state predecessor, with no new descriptor.
Nested v3 adds independently root-signed current-pending scope and a fixed SQL
endpoint. These are cold configuration assertions, not an action-time witness.
Nested v4 additionally pins the completion endpoint, request packet locator and
original authorization identity within that same configured historical cohort.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_registration_finalization_authorization as caller
from catchplate import authority_revocation_configuration as configuration
from catchplate import authority_revocation_writer_acknowledgment as keys
from catchplate import authority_webauthn_enrollment_policy as enrollment_policy
from catchplate import authority_webauthn_transition_custody_configuration as transition


SCHEMA = "catchplate.controlPlaneRegistrationFinalization/v1"
V2_SCHEMA = "catchplate.controlPlaneRegistrationFinalization/v2"
V3_SCHEMA = "catchplate.controlPlaneRegistrationFinalization/v3"
V4_SCHEMA = "catchplate.controlPlaneRegistrationFinalization/v4"
LOCAL_SCHEMA = "catchplate.controlPlaneRegistrationFinalization/v5"
CALLER_KEY_FD = 204
AUTHORIZER_SOCKET_PATH = "/run/catchplate/registration-finalization-authorizer.sock"
RESERVER_SOCKET_PATH = "/run/catchplate/registration-finalization/reserver.sock"
SQL_SOCKET_PATH = "/run/catchplate/registration-finalization/sql.sock"
COMPLETION_SOCKET_PATH = "/run/catchplate/registration-finalization/completion.sock"
_FIELDS = frozenset({"schema", "finalizationCallerPrivateKeyFd", "currentRootEnrollment",
    "grantEnrollment", "authorizationEnrollment", "authorizerEndpoint"})
_V2_FIELDS = _FIELDS | frozenset({"reserverEndpoint", "statePredecessor"})
_V3_FIELDS = _V2_FIELDS | frozenset({"sqlEndpoint", "currentPending"})
_V4_FIELDS = _V3_FIELDS | frozenset({"completionEndpoint", "completionPacketDigest",
    "completionAuthorizationDigest"})
_LOCAL_FIELDS = _FIELDS | frozenset({"reserverEndpoint", "sqlEndpoint", "completionEndpoint", "contextDirectory"})
_ORIGINAL_FIELDS = frozenset({"base64Url", "byteCount"})
_ENDPOINT_FIELDS = frozenset({"socketPath", "requestTimeoutSeconds", "listenerUid", "listenerGid"})
_ORIGINAL_LIMITS = (("currentRootEnrollment", caller.authorization.MAX_ENROLLMENT_BYTES),
    ("grantEnrollment", caller.grants.MAX_ENROLLMENT_BYTES),
    ("authorizationEnrollment", caller.MAX_ENROLLMENT_BYTES))
shape, capture, plan = caller.shape, caller.capture, caller.plan


class RegistrationFinalizationBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _FinalizationMaterial:
    caller_private_key_fd: int
    caller_public_key: object
    current_root_enrollment_bytes: bytes
    grant_enrollment_bytes: bytes
    authorization_enrollment_bytes: bytes
    authorizer_endpoint: tuple
    reservation_endpoint: tuple | None = None
    reservation_predecessor: tuple | None = None
    sql_endpoint: tuple | None = None
    current_pending: tuple | None = None
    completion_endpoint: tuple | None = None
    completion_packet_digest: str | None = None
    completion_authorization_digest: str | None = None
    context_directory: tuple | None = None


def _endpoint(value, *, _path=AUTHORIZER_SOCKET_PATH):
    if type(_path) is not str or _path not in (AUTHORIZER_SOCKET_PATH, RESERVER_SOCKET_PATH,
            SQL_SOCKET_PATH, COMPLETION_SOCKET_PATH):
        raise RegistrationFinalizationBootstrapError("finalization endpoint profile is not source fixed")
    shape._object(value, _ENDPOINT_FIELDS, "registration finalization endpoint")
    shape._literal(value["socketPath"], _path)
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for name in ("listenerUid", "listenerGid"):
        shape._integer(value[name], 2**32 - 2)
        if value[name] != 0:
            raise RegistrationFinalizationBootstrapError("finalization listener must retain the fixed root peer")
    # The peer identifies the socket activator, not the later signing process.
    return value["socketPath"], value["requestTimeoutSeconds"], 0, 0


def _reserver_endpoint(value):
    return _endpoint(value, _path=RESERVER_SOCKET_PATH)


def _sql_endpoint(value):
    return _endpoint(value, _path=SQL_SOCKET_PATH)


def _completion_endpoint(value):
    return _endpoint(value, _path=COMPLETION_SOCKET_PATH)


def _shape(value):
    if value is None:
        return
    if (type(value) is not dict or type(value.get("schema")) is not str
            or value["schema"] not in (SCHEMA, V2_SCHEMA, V3_SCHEMA, V4_SCHEMA, LOCAL_SCHEMA)):
        raise RegistrationFinalizationBootstrapError("registration finalization scope version differs")
    shape._object(value, _LOCAL_FIELDS if value["schema"] == LOCAL_SCHEMA else _V4_FIELDS if value["schema"] == V4_SCHEMA else
        _V3_FIELDS if value["schema"] == V3_SCHEMA else
        _V2_FIELDS if value["schema"] == V2_SCHEMA else _FIELDS,
        "control-plane registration finalization scope")
    shape._integer(value["finalizationCallerPrivateKeyFd"], 1023, minimum=32)
    if value["finalizationCallerPrivateKeyFd"] != CALLER_KEY_FD:
        raise RegistrationFinalizationBootstrapError("finalization caller key FD is not source fixed")
    for name, maximum in _ORIGINAL_LIMITS:
        original = value[name]
        shape._object(original, _ORIGINAL_FIELDS, "registration finalization enrollment original")
        caller.authorization.transport._transport_shape(
            original["base64Url"], original["byteCount"], maximum)
    _endpoint(value["authorizerEndpoint"])
    if value["schema"] == LOCAL_SCHEMA:
        from catchplate import authority_local_registration_context as contexts
        contexts.directory(value["contextDirectory"])
        _reserver_endpoint(value["reserverEndpoint"])
        _sql_endpoint(value["sqlEndpoint"])
        _completion_endpoint(value["completionEndpoint"])
    if value["schema"] in (V2_SCHEMA, V3_SCHEMA, V4_SCHEMA):
        _reserver_endpoint(value["reserverEndpoint"])
        predecessor = value["statePredecessor"]
        shape._object(predecessor, frozenset({"sequence", "headDigest", "nextFence"}),
            "independent finalization reservation predecessor")
        shape._integer(predecessor["sequence"], caller.authorization.MAX_RECORDS)
        shape._digest(predecessor["headDigest"])
        shape._integer(predecessor["nextFence"], minimum=1)
        if predecessor["sequence"] == 0 and predecessor["nextFence"] != 1:
            raise RegistrationFinalizationBootstrapError("genesis finalization predecessor requires fence one")
    if value["schema"] in (V3_SCHEMA, V4_SCHEMA):
        _sql_endpoint(value["sqlEndpoint"])
        pending = value["currentPending"]
        shape._object(pending, frozenset({"sequence", "headDigest", "fence"}),
            "independent finalization current pending scope")
        shape._integer(pending["sequence"], caller.authorization.MAX_RECORDS, minimum=1)
        shape._digest(pending["headDigest"])
        shape._integer(pending["fence"], minimum=1)
        if (pending["sequence"] != predecessor["sequence"] + 1
                or pending["fence"] != predecessor["nextFence"]):
            raise RegistrationFinalizationBootstrapError(
                "finalization pending scope is not this cold predecessor's successor")
    if value["schema"] == V4_SCHEMA:
        _completion_endpoint(value["completionEndpoint"])
        shape._digest(value["completionPacketDigest"])
        shape._digest(value["completionAuthorizationDigest"])


def _admit_on_work(*, registration_finalization, configuration_payload,
        configuration_digest, generation, runtime_role_identities,
        runtime_root_public_key, issuer_public_key, execution_caller_public_key, work):
    """Authenticate finalization originals using only the parent's existing work."""
    try:
        ledger = capture._SharedLedger(work)
        _shape(registration_finalization)
        if registration_finalization is None:
            return None
        root, issuer, prior, digest = (runtime_root_public_key, issuer_public_key,
            execution_caller_public_key, configuration_digest)
        caller.authorization._public(root)
        caller.authorization._public(issuer)
        if prior is not None:
            caller.authorization._public(prior)
        shape._digest(digest)
        shape._bounded_object(generation, 24, "finalization caller launch context")
        # Detach every mutable graph before key/hash/native callbacks.
        owned = configuration._ConfigurationCapture(ledger,
            maximum_bytes=caller.grants.authority.MAX_REQUEST_BYTES).visit({
                "finalization": registration_finalization, "configuration": configuration_payload,
                "generation": {name: generation[name] for name in configuration._GENERATION_FIELDS},
                "runtime": runtime_role_identities})
        value, configured = owned["finalization"], owned["configuration"]
        _shape(value)
        mapped = enrollment_policy._capture_on_work(payload=configured,
            configuration_digest=digest, generation=owned["generation"],
            runtime_role_identities=owned["runtime"], work=work)
        plan._same(keys._spki_on_work(issuer, work), mapped.policy["signingSpkiDigest"],
            work, "finalization caller differs from the actual enrollment issuer")
        configured_transition = transition._capture_on_work(operation=caller.OPERATION,
            payload=configured, configuration_digest=digest, generation=owned["generation"],
            runtime_role_identities=owned["runtime"], work=work)
        current_raw, grant_raw, authorization_raw = tuple(caller.authorization.transport._decode(
            value[name]["base64Url"], value[name]["byteCount"], maximum, work)
            for name, maximum in _ORIGINAL_LIMITS)
        admitted = caller._admit_enrollment_on_work(authorization_enrollment_bytes=authorization_raw,
            current_root_enrollment_bytes=current_raw, grant_enrollment_bytes=grant_raw,
            root_public_key=root, configuration_digest=digest,
            planner_public_key=configured_transition.pins[1],
            evidence_public_key=configured_transition.pins[4], work=work)
        plan._same(admitted.payload["generationDigest"], mapped.generation_digest, work,
            "finalization caller enrollment differs from the actual configured generation")
        caller_pin = admitted.payload["callerKey"]["spkiDigest"]
        forbidden = [mapped.policy["signingSpkiDigest"]]
        if prior is not None:
            forbidden.append(keys._spki_on_work(prior, work))
        roles = configured["roles"]
        shape._object(roles, frozenset(configuration._ROLE_NAMES), "finalization caller configured roles")
        for name in configuration._ROLE_NAMES:
            role = roles[name]
            shape._digest(role["responseSigningSpkiDigest"])
            forbidden.append(role["responseSigningSpkiDigest"])
            if name in ("verifier", "planner"):
                shape._digest(role["signingSpkiDigest"])
                forbidden.append(role["signingSpkiDigest"])
        for field, names in ((enrollment_policy.evidence_policy.FIELD, ("registration", "installation")),
                (enrollment_policy.transition_policy.FIELD, ("registration", "stage", "completion"))):
            purposes = configured.get(field)
            if purposes is not None:
                for name in names:
                    if purposes[name] is not None:
                        shape._digest(purposes[name]["signingSpkiDigest"])
                        forbidden.append(purposes[name]["signingSpkiDigest"])
        work.prepare_scan(forbidden)
        for pin in forbidden:
            work.prepare_comparison(caller_pin, pin)
            if caller_pin == pin:
                raise RegistrationFinalizationBootstrapError("finalization caller key reuses another configured purpose")
        reservation_endpoint = reservation_predecessor = None
        sql_endpoint = current_pending = None
        completion_endpoint = completion_packet_digest = completion_authorization_digest = None
        if value["schema"] in (V2_SCHEMA, V3_SCHEMA, V4_SCHEMA):
            # Capacity and genesis come from actual admission of this same
            # original root enrollment, never from a received state receipt.
            current = caller.authorization._admit_enrollment_on_work(enrollment_bytes=current_raw,
                root_public_key=root, work=work)
            for actual, expected in (
                    (current.enrollment_digest, admitted.payload["currentRootEnrollmentDigest"]),
                    (current.payload["generationDigest"], mapped.generation_digest),
                    (current.payload["databaseId"], admitted.payload["databaseId"])):
                plan._same(actual, expected, work,
                    "finalization predecessor differs from actual configured enrollment")
            predecessor = value["statePredecessor"]
            if predecessor["sequence"] + 2 > current.payload["maxRecords"]:
                raise RegistrationFinalizationBootstrapError(
                    "finalization predecessor has no enrolled reserve and completion capacity")
            if predecessor["sequence"] == 0:
                plan._same(predecessor["headDigest"], current.enrollment_digest, work,
                    "finalization independent genesis head differs")
            reservation_endpoint = _reserver_endpoint(value["reserverEndpoint"])
            reservation_predecessor = (predecessor["sequence"], predecessor["headDigest"],
                predecessor["nextFence"])
            if value["schema"] in (V3_SCHEMA, V4_SCHEMA):
                pending = value["currentPending"]
                if pending["sequence"] >= current.payload["maxRecords"]:
                    raise RegistrationFinalizationBootstrapError(
                        "finalization pending scope has no enrolled completion capacity")
                # Supplied only by this authenticated original root bootstrap.
                # Neither a returned reserve receipt nor local retained bytes
                # can enroll, update or independently prove these current pins.
                sql_endpoint = _sql_endpoint(value["sqlEndpoint"])
                current_pending = (pending["sequence"], pending["headDigest"], pending["fence"])
                if value["schema"] == V4_SCHEMA:
                    # Independent root assertions, never populated from an
                    # unsigned SQL result or a returned completion carrier.
                    # The packet is a request locator, not a response claim.
                    completion_endpoint = _completion_endpoint(value["completionEndpoint"])
                    completion_packet_digest = value["completionPacketDigest"]
                    completion_authorization_digest = value["completionAuthorizationDigest"]
        context_directory = None
        if value["schema"] == LOCAL_SCHEMA:
            from catchplate import authority_local_registration_context as contexts
            contexts._development()
            context_directory = contexts.directory(value["contextDirectory"])
            reservation_endpoint = _reserver_endpoint(value["reserverEndpoint"])
            sql_endpoint = _sql_endpoint(value["sqlEndpoint"])
            completion_endpoint = _completion_endpoint(value["completionEndpoint"])
        return _FinalizationMaterial(CALLER_KEY_FD, admitted.caller_public_key,
            current_raw, grant_raw, authorization_raw, _endpoint(value["authorizerEndpoint"]),
            reservation_endpoint, reservation_predecessor, sql_endpoint, current_pending,
            completion_endpoint, completion_packet_digest, completion_authorization_digest, context_directory)
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, RegistrationFinalizationBootstrapError):
            raise
        raise RegistrationFinalizationBootstrapError("registration finalization caller bootstrap admission failed") from exc
