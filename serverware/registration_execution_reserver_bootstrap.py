"""Root-authenticated cold scope for the fixed registration reserve service.

The independent provisioner must establish configuration, runtime provenance,
purpose enrollments, the state predecessor and the separate local journal's
current checkpoint. Their root signature does not manufacture those facts.
The actual existing configuration mapper and original enrollment verifiers run
on the caller's one work allowance before any resource may be selected.

Only the enrolled computation private key belongs in this process; caller,
grant, completion, state and SQL keys do not. Returned material is ordinary
owned same-call data, not an admission token, currentness observation or one-use
permission. This module opens no descriptor, journal, listener or transport and
does not reserve, complete or execute anything. The trusted-host-local launch
interval and single independently supplied predecessor are never renewed.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature

from serverware import control_plane_enrollment_bootstrap as codec
from serverware import current_root_state_bootstrap as state_bootstrap
from serverware import registration_evidence_signer_bootstrap as signing
from serverware import authority_registration_execution_authorization as caller
from serverware import authority_webauthn_enrollment_policy as enrollment_policy
from serverware import authority_webauthn_evidence_policy as evidence_policy


authority, configuration = codec.authority, codec.configuration
capability, capture, plan = codec.capability, codec.capture, codec.plan
authorization, grants, shape = caller.authorization, caller.grants, caller.shape
ROLE = PROCESS_MODE = "registration-execution-reserver"
SERVICE_UID = SERVICE_GID = 65514
PEER_UID = PEER_GID = 65532
STATE_SERVICE_UID = STATE_SERVICE_GID = 65516
STATE_LISTENER_UID = STATE_LISTENER_GID = 0
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD, JOURNAL_FD = 198, 199, 200, 201, 202
INHERITED_DESCRIPTORS = (ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD, JOURNAL_FD)
LISTENER_PATH = "/run/serverware/registration-execution/reserver.sock"
STATE_SOCKET_PATH = "/run/serverware/current-root/state.sock"
MAX_BYTES = 4 * 1024 * 1024
MAX_RECEIPT_AGE_NS = 300 * 1_000_000_000
SCHEMA = "serverware.signedRegistrationExecutionReserverBootstrap/v1"
PAYLOAD_SCHEMA = "serverware.registrationExecutionReserverBootstrap/v1"
LAUNCH_SCHEMA = "serverware.registrationExecutionReserverLaunch/v1"
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
_ORIGINAL_FIELDS = frozenset({"base64Url", "byteCount", "bytesDigest", "identityDigest"})
_ORIGINAL_LIMITS = (("currentRootEnrollment", authorization.MAX_ENROLLMENT_BYTES),
    ("grantEnrollment", grants.MAX_ENROLLMENT_BYTES),
    ("authorizationEnrollment", caller.MAX_ENROLLMENT_BYTES))
_FALSE_FIELDS = ("hardwareBacked", "nativeStageZero", "hsmBackedKeys", "teeVerified",
    "externalWitnessVerified")
_PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "role", "configurationPayload",
    "configurationDigest", "generation", "runtimeRoleIdentities", "currentRootEnrollment",
    "grantEnrollment", "authorizationEnrollment", "databaseId", "generationDigest",
    "computationSpkiDigest", "computationMeasurementDigest", "runtimeClosureDigest",
    "statePredecessor", "reservationCheckpoint", "stateEndpoint", "issuedAtEpochNs",
    "expiresAtEpochNs", "trustMode", "launch", *_FALSE_FIELDS})
_LAUNCH_FIELDS = frozenset({"schema", "processMode", "serviceUid", "serviceGid", "peerUid",
    "peerGid", "rootPublicKeyFd", "bootstrapFd", "listenerFd", "signingKeyFd",
    "journalDirectoryFd", "inheritedFileDescriptors", "listenerPath", "requestTimeoutSeconds",
    "journalDirectoryDevice", "journalDirectoryInode", "journalMaximumRecords",
    "listenerSocketDevice", "listenerSocketInode", "listenerPathDevice", "listenerPathInode"})
_ENDPOINT_FIELDS = frozenset({"socketPath", "requestTimeoutSeconds", "serviceUid", "serviceGid",
    "listenerUid", "listenerGid"})


class RegistrationExecutionReserverBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _ReserverMaterial:
    configuration_payload: dict
    generation: dict
    runtime_role_identities: dict
    configuration_digest: str
    current_root_enrollment_bytes: bytes
    grant_enrollment_bytes: bytes
    authorization_enrollment_bytes: bytes
    planner_public_key: object
    evidence_public_key: object
    computation_public_key: object
    computation_spki_digest: str
    computation_measurement_digest: str
    database_id: str
    generation_digest: str
    enrollment_digest: str
    state_predecessor: tuple
    reservation_checkpoint: tuple
    state_endpoint: tuple
    attestation_interval: tuple
    opening_sample: tuple
    launch: dict


def _state_endpoint(value):
    shape._object(value, _ENDPOINT_FIELDS, "registration reserve state endpoint")
    shape._literal(value["socketPath"], STATE_SOCKET_PATH)
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for name, expected in (("serviceUid", STATE_SERVICE_UID), ("serviceGid", STATE_SERVICE_GID),
            ("listenerUid", STATE_LISTENER_UID), ("listenerGid", STATE_LISTENER_GID)):
        shape._integer(value[name], 2**32 - 2)
        if value[name] != expected:
            raise RegistrationExecutionReserverBootstrapError("state endpoint identity is not source fixed")
    # SO_PEERCRED pins the root manager that called listen(), not its UID 65516
    # accepting service. UID 65514 requires independently provisioned path ACLs;
    # neither this scope nor the client widens the state service's peer list.
    return value["socketPath"], value["requestTimeoutSeconds"], STATE_LISTENER_UID, STATE_LISTENER_GID


def _launch_shape(value, work):
    shape._object(value, _LAUNCH_FIELDS, "registration execution reserver launch")
    for name, expected in (("schema", LAUNCH_SCHEMA), ("processMode", PROCESS_MODE),
            ("listenerPath", LISTENER_PATH)):
        shape._literal(value[name], expected)
    for name, expected in (("serviceUid", SERVICE_UID), ("serviceGid", SERVICE_GID),
            ("peerUid", PEER_UID), ("peerGid", PEER_GID), ("rootPublicKeyFd", ROOT_FD),
            ("bootstrapFd", BOOTSTRAP_FD), ("listenerFd", LISTENER_FD),
            ("signingKeyFd", KEY_FD), ("journalDirectoryFd", JOURNAL_FD)):
        shape._integer(value[name], 2**32 - 2, minimum=1)
        if value[name] != expected:
            raise RegistrationExecutionReserverBootstrapError("reserver fixed launch scalar differs")
    descriptors = value["inheritedFileDescriptors"]
    shape._array(descriptors, len(INHERITED_DESCRIPTORS), "reserver inherited descriptors")
    for descriptor in descriptors:
        shape._integer(descriptor, 1023, minimum=3)
    plan._same(descriptors, list(INHERITED_DESCRIPTORS), work,
        "reserver inherited descriptor inventory differs")
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for name in ("journalDirectoryDevice", "listenerSocketDevice", "listenerPathDevice"):
        shape._integer(value[name], 2**64 - 1)
    for name in ("journalDirectoryInode", "listenerSocketInode", "listenerPathInode"):
        shape._integer(value[name], 2**64 - 1, minimum=1)
    shape._integer(value["journalMaximumRecords"], authorization.MAX_RECORDS, minimum=2)


def _payload_shape(payload, work):
    shape._object(payload, _PAYLOAD_FIELDS, "registration execution reserver bootstrap")
    for name, expected in (("schema", PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("role", ROLE), ("trustMode", "trusted-host-local")):
        shape._literal(payload[name], expected)
    for name in ("configurationDigest", "generationDigest", "computationSpkiDigest",
            "computationMeasurementDigest", "runtimeClosureDigest"):
        shape._digest(payload[name])
    authorization._token(payload["databaseId"])
    shape._object(payload["generation"], frozenset(configuration._GENERATION_FIELDS),
        "reserver generation")
    if type(payload["configurationPayload"]) is not dict or type(payload["runtimeRoleIdentities"]) is not dict:
        raise RegistrationExecutionReserverBootstrapError("reserver configuration and runtime are not exact data")
    for name, maximum in _ORIGINAL_LIMITS:
        record = payload[name]
        shape._object(record, _ORIGINAL_FIELDS, "reserver enrollment original")
        authorization.transport._transport_shape(record["base64Url"], record["byteCount"], maximum)
        shape._digest(record["bytesDigest"])
        shape._digest(record["identityDigest"])
    predecessor = payload["statePredecessor"]
    shape._object(predecessor, frozenset({"sequence", "headDigest", "nextFence"}),
        "independent state predecessor")
    shape._integer(predecessor["sequence"], authorization.MAX_RECORDS)
    shape._digest(predecessor["headDigest"])
    shape._integer(predecessor["nextFence"], minimum=1)
    if predecessor["sequence"] == 0 and predecessor["nextFence"] != 1:
        raise RegistrationExecutionReserverBootstrapError("genesis state predecessor requires fence one")
    checkpoint = payload["reservationCheckpoint"]
    shape._object(checkpoint, frozenset({"sequence", "headDigest"}), "independent reservation checkpoint")
    shape._integer(checkpoint["sequence"], authorization.MAX_RECORDS)
    shape._digest(checkpoint["headDigest"])
    _state_endpoint(payload["stateEndpoint"])
    for name in ("issuedAtEpochNs", "expiresAtEpochNs"):
        shape._integer(payload[name], minimum=1)
    if not 0 < payload["expiresAtEpochNs"] - payload["issuedAtEpochNs"] <= MAX_RECEIPT_AGE_NS:
        raise RegistrationExecutionReserverBootstrapError("reserver launch lifetime exceeds its source bound")
    if any(payload[name] is not False for name in _FALSE_FIELDS):
        raise RegistrationExecutionReserverBootstrapError("reserver bootstrap is not trusted-host-local assurance")
    _launch_shape(payload["launch"], work)


def _fresh(interval, work, opening=None):
    """Check the original bounded epoch/monotonic bracket without renewal."""
    try:
        return state_bootstrap._fresh(interval, work, opening=opening)
    except (TypeError, ValueError, OverflowError) as exc:
        raise RegistrationExecutionReserverBootstrapError("reserver original launch interval is not live") from exc


def _originals(payload, work):
    originals = []
    for name, maximum in _ORIGINAL_LIMITS:
        record = payload[name]
        raw = authorization.transport._decode(record["base64Url"], record["byteCount"], maximum, work)
        work.charge(hashes=1, input_bytes=len(raw))
        plan._same("sha256:" + hashlib.sha256(raw).hexdigest(), record["bytesDigest"], work,
            "reserver enrollment original bytes differ from their root pin")
        originals.append(raw)
    return tuple(originals)


def _material(payload, root_key, opening, work):
    configured, generation, runtime = (payload["configurationPayload"],
        payload["generation"], payload["runtimeRoleIdentities"])
    digest = payload["configurationDigest"]
    mapped = enrollment_policy._capture_on_work(payload=configured,
        configuration_digest=digest, generation=generation, runtime_role_identities=runtime, work=work)
    purposes, evidence_keys = evidence_policy._validate_policy_on_work(
        configured.get(evidence_policy.FIELD), webauthn=configured["webauthn"], work=work)
    if purposes["registration"] is None:
        raise RegistrationExecutionReserverBootstrapError("registration evidence purpose is disabled")
    roles = configured["roles"]
    shape._object(roles, frozenset(configuration._ROLE_NAMES), "reserver configured roles")
    forbidden = [caller.keys._spki_on_work(root_key, work), mapped.policy["signingSpkiDigest"]]
    for name in configuration._ROLE_NAMES:
        role = roles[name]
        shape._integer(role["serviceUid"], 2**32 - 2)
        if role["serviceUid"] == SERVICE_UID:
            raise RegistrationExecutionReserverBootstrapError("reserver UID is shared with a configured role")
        shape._digest(role["responseSigningSpkiDigest"])
        forbidden.append(role["responseSigningSpkiDigest"])
        if name in ("verifier", "planner"):
            shape._digest(role["signingSpkiDigest"])
            forbidden.append(role["signingSpkiDigest"])
    planner = configuration._key(roles["planner"]["signingPublicKeyBase64Url"], work,
        expected_spki=roles["planner"]["signingSpkiDigest"])
    evidence_key = evidence_keys["registration"]
    current_raw, grant_raw, caller_raw = _originals(payload, work)
    caller_material = caller._admit_enrollment_on_work(authorization_enrollment_bytes=caller_raw,
        current_root_enrollment_bytes=current_raw, grant_enrollment_bytes=grant_raw,
        root_public_key=root_key, configuration_digest=digest,
        planner_public_key=planner, evidence_public_key=evidence_key, work=work)
    current = authorization._admit_enrollment_on_work(enrollment_bytes=current_raw,
        root_public_key=root_key, work=work)
    grant = grants._admit_enrollment_on_work(grant_enrollment_bytes=grant_raw,
        current_root_enrollment_bytes=current_raw, root_public_key=root_key, work=work)
    enrolled, policy = caller_material.payload, current.payload
    computation = policy["computation"]
    for actual, expected in ((payload["currentRootEnrollment"]["identityDigest"], current.enrollment_digest),
            (payload["grantEnrollment"]["identityDigest"], grant.enrollment_digest),
            (payload["authorizationEnrollment"]["identityDigest"], caller_material.enrollment_digest),
            (payload["databaseId"], enrolled["databaseId"]),
            (payload["generationDigest"], enrolled["generationDigest"]),
            (payload["generationDigest"], mapped.generation_digest),
            (payload["computationSpkiDigest"], computation["spkiDigest"]),
            (payload["computationMeasurementDigest"], computation["measurementDigest"]),
            (payload["launch"]["journalMaximumRecords"], policy["maxRecords"])):
        plan._same(actual, expected, work, "reserver bootstrap differs from genuine configuration or enrollment")
    # The enrollment authenticates the distinct computation/completion/state
    # keys. Also exclude every other configured purpose and the actual root.
    forbidden.extend((enrolled["callerKey"]["spkiDigest"], grant.payload["authorizer"]["spkiDigest"]))
    for slot in ("registration", "installation"):
        if purposes[slot] is not None:
            forbidden.append(purposes[slot]["signingSpkiDigest"])
    transitions = configured.get(enrollment_policy.transition_policy.FIELD)
    if transitions is not None:
        for slot in ("registration", "stage", "completion"):
            if transitions[slot] is not None:
                forbidden.append(transitions[slot]["signingSpkiDigest"])
    work.prepare_scan(forbidden)
    for pin in forbidden:
        work.prepare_comparison(computation["spkiDigest"], pin)
        if computation["spkiDigest"] == pin:
            raise RegistrationExecutionReserverBootstrapError("computation key is shared with another configured purpose")
    predecessor, checkpoint = payload["statePredecessor"], payload["reservationCheckpoint"]
    for selected in (predecessor, checkpoint):
        if selected["sequence"] > policy["maxRecords"]:
            raise RegistrationExecutionReserverBootstrapError("independent checkpoint exceeds enrolled capacity")
        if selected["sequence"] == 0:
            plan._same(selected["headDigest"], current.enrollment_digest, work,
                "reserver independent genesis head differs")
    return _ReserverMaterial(configured, generation, runtime, digest, current_raw, grant_raw,
        caller_raw, planner, evidence_key, current.computation_public_key, computation["spkiDigest"],
        computation["measurementDigest"], enrolled["databaseId"], mapped.generation_digest,
        current.enrollment_digest, (predecessor["sequence"], predecessor["headDigest"], predecessor["nextFence"]),
        (checkpoint["sequence"], checkpoint["headDigest"]), _state_endpoint(payload["stateEndpoint"]),
        (payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]), opening, payload["launch"])


def _verify_on_work(*, bootstrap_bytes, root_public_key, work):
    """Authenticate exact root originals before any cold resource selection."""
    try:
        ledger = capture._SharedLedger(work)
        original = authorization._original(bootstrap_bytes, MAX_BYTES, "reserver bootstrap")
        root = root_public_key
        authorization._public(root)
        envelope = codec._decode(original, work)
        shape._object(envelope, _ENVELOPE_FIELDS, "reserver signed bootstrap")
        shape._literal(envelope["schema"], SCHEMA)
        shape._base64url(envelope["signatureBase64Url"], signature=True)
        if type(envelope["payload"]) is not dict:
            raise RegistrationExecutionReserverBootstrapError("reserver payload is not an exact object")
        codec._canonical(original, envelope, work)
        payload = envelope["payload"]
        unsigned = configuration._configuration_wire(payload, ledger)
        capability._signature(root, envelope["signatureBase64Url"], SCHEMA, unsigned, ledger)
        codec._canonical(original, envelope, work)
        _payload_shape(payload, work)
        interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
        opening = _fresh(interval, work)
        material = _material(payload, root, opening, work)
        _fresh(interval, work, opening=opening)
        codec._canonical(original, envelope, work)
        return material
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, RegistrationExecutionReserverBootstrapError):
            raise
        raise RegistrationExecutionReserverBootstrapError("reserver bootstrap admission failed") from exc


def _produce_on_work(*, payload, root_private_key, root_public_key, work):
    """Sign independently established original launch claims, not provenance."""
    try:
        ledger = capture._SharedLedger(work)
        private, public = root_private_key, root_public_key
        authorization._private(private)
        authorization._public(public)
        owned = configuration._ConfigurationCapture(ledger, maximum_bytes=MAX_BYTES).visit(payload)
        _payload_shape(owned, work)
        unsigned = configuration._configuration_wire(owned, ledger)
        interval = owned["issuedAtEpochNs"], owned["expiresAtEpochNs"]
        opening = _fresh(interval, work)
        _material(owned, public, opening, work)
        codec._canonical(unsigned, owned, work)
        _fresh(interval, work, opening=opening)
        original = signing._sign(owned, SCHEMA, MAX_BYTES, private, public, work)
        codec._canonical(unsigned, owned, work)
        _fresh(interval, work, opening=opening)
        return original
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, RegistrationExecutionReserverBootstrapError):
            raise
        raise RegistrationExecutionReserverBootstrapError("reserver bootstrap production failed") from exc
