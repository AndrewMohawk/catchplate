"""Root-authenticated cold scope for registration evidence completion only.

The root independently establishes configuration, runtime provenance, current
pending scope, historical replay expectations, packet/authorization identities,
database/TLS provenance and a separate completion-delivery journal checkpoint.
Signing those claims is not a live witness or proof that two connections reach
the same database. Original purpose enrollments and configured static replay
pins are genuinely admitted on the caller's unchanged work; no returned packet
or current clock supplies historical expectations.

Only the enrolled completion signing key and two fixed read-role TLS identities
belong in this process. Closed DSNs use one literal address and verified server
name with fixed TLS paths, no supplied DSN/password or credential-file fallback.
The cold launcher must retain its literal environment without PG* variables;
independent certificate-only database authentication remains a prerequisite.
Both readers require exact eight-field configurations carrying the same
independently signed structural-manifest pin. Neither has a seven-field or
optional-pin fallback; their distinct roles and TLS identities remain separate.

No descriptor, private key, TLS file, journal, network or database is opened.
Material is ordinary same-call data, not authority. The original <=300-second
trusted-host-local interval is never renewed, and no completion is signed here.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature

from catchplate import control_plane_enrollment_bootstrap as codec
from catchplate import current_root_state_bootstrap as state_bootstrap
from catchplate import registration_evidence_signer_bootstrap as signing
from catchplate import registration_execution_reserver_bootstrap as reserve_profile
from catchplate import registration_execution_sql_bootstrap as database_profile
from catchplate import authority_current_root_plan_replay as replay
from catchplate import authority_registration_execution_authorization as caller
from catchplate import authority_webauthn_enrollment_policy as enrollment_policy
from catchplate import authority_webauthn_evidence_policy as evidence_policy
from catchplate import authority_webauthn_evidence_plan_verifier_configuration as pins_configuration
from catchplate.authority_local_limits import LOCAL_SESSION_MAX_NS


authority, configuration = codec.authority, codec.configuration
capability, capture, plan = codec.capability, codec.capture, codec.plan
authorization, grants, shape = caller.authorization, caller.grants, caller.shape
ROLE = PROCESS_MODE = "registration-execution-completion"
OPERATION = "webauthn.registration.evidence.admit"
SERVICE_UID = SERVICE_GID = 65515
PEER_UID = PEER_GID = 65532
STATE_SERVICE_UID = STATE_SERVICE_GID = 65516
STATE_LISTENER_UID = STATE_LISTENER_GID = 0
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD, JOURNAL_FD = 198, 199, 200, 201, 202
INHERITED_DESCRIPTORS = (ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, KEY_FD, JOURNAL_FD)
LISTENER_PATH = "/run/catchplate/registration-execution/completion.sock"
STATE_SOCKET_PATH = "/run/catchplate/current-root/state.sock"
TLS_PATHS = {
    "ca": "/run/catchplate/registration-completion-tls/ca.pem",
    "custodyCertificate": "/run/catchplate/registration-completion-tls/custody.crt",
    "custodyKey": "/run/catchplate/registration-completion-tls/custody.key",
    "commitCertificate": "/run/catchplate/registration-completion-tls/commit.crt",
    "commitKey": "/run/catchplate/registration-completion-tls/commit.key",
}
TLS_LIMITS = {name: (16 * 1024 if name in ("custodyKey", "commitKey") else 64 * 1024)
    for name in TLS_PATHS}
MIN_TLS_BYTES = 2
MAX_BYTES = 4 * 1024 * 1024
MAX_RECEIPT_AGE_NS = LOCAL_SESSION_MAX_NS
SCHEMA = "catchplate.signedRegistrationExecutionCompletionBootstrap/v1"
PAYLOAD_SCHEMA = "catchplate.registrationExecutionCompletionBootstrap/v1"
LAUNCH_SCHEMA = "catchplate.registrationExecutionCompletionLaunch/v1"
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
    "completionSpkiDigest", "completionMeasurementDigest", "runtimeClosureDigest",
    "currentPending", "completionCheckpoint", "stateEndpoint", "packetDigest",
    "authorizationDigest", "replayExpectations", "databaseEndpoint", "sqlRoles",
    "queryManifestDigest", "structureManifestDigest", "tlsFiles", "issuedAtEpochNs",
    "expiresAtEpochNs", "trustMode", "launch", *_FALSE_FIELDS})
_LAUNCH_FIELDS = frozenset({"schema", "processMode", "serviceUid", "serviceGid", "peerUid",
    "peerGid", "rootPublicKeyFd", "bootstrapFd", "listenerFd", "signingKeyFd",
    "journalDirectoryFd", "inheritedFileDescriptors", "listenerPath", "requestTimeoutSeconds",
    "journalDirectoryDevice", "journalDirectoryInode", "journalMaximumRecords",
    "listenerSocketDevice", "listenerSocketInode", "listenerPathDevice", "listenerPathInode"})
_SQL_ROLE_FIELDS = frozenset({"connectTimeoutSeconds", "clientDn", "clientSerial", "issuerDn"})


class RegistrationExecutionCompletionBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _CompletionMaterial:
    configuration_payload: dict
    generation: dict
    runtime_role_identities: dict
    configuration_digest: str
    current_root_enrollment_bytes: bytes
    grant_enrollment_bytes: bytes
    authorization_enrollment_bytes: bytes
    planner_public_key: object
    evidence_public_key: object
    completion_public_key: object
    completion_spki_digest: str
    completion_measurement_digest: str
    database_id: str
    generation_digest: str
    enrollment_digest: str
    runtime_closure_digest: str
    current_pending: tuple
    completion_checkpoint: tuple
    state_endpoint: tuple
    packet_digest: str
    authorization_digest: str
    expectations: dict
    custody_configuration: tuple
    commit_configuration: tuple
    tls_files: dict
    attestation_interval: tuple
    opening_sample: tuple
    launch: dict


def _database_configurations(payload, work):
    endpoint = payload["databaseEndpoint"]
    # Reuse the exact SQL profile's scalar-only grammar, not its worker
    # material, role selection or executable authority.
    database_profile._database_shape(endpoint)
    roles = payload["sqlRoles"]
    shape._object(roles, frozenset({"custody", "commit"}), "fixed completion read roles")
    result = []
    for name, role in (("custody", authority.SUCCESSOR_RECOVERY_ROLE),
            ("commit", authority.COMPLETION_READER_ROLE)):
        selected = roles[name]
        shape._object(selected, _SQL_ROLE_FIELDS, "fixed completion SQL identity")
        shape._integer(selected["connectTimeoutSeconds"], 300, minimum=2)
        for field in ("clientDn", "clientSerial", "issuerDn"):
            text = selected[field]
            if (type(text) is not str or not 1 <= len(text) <= 4096 or "\x00" in text
                    or work.prepare_utf8(text) > 4096):
                raise RegistrationExecutionCompletionBootstrapError("completion SQL TLS identity exceeds its bound")
        dsn = ("host=" + endpoint["host"] + " hostaddr=" + endpoint["hostaddr"]
            + " port=" + str(endpoint["port"]) + " dbname=" + endpoint["databaseName"]
            + " user=" + role + " sslmode=verify-full sslrootcert=" + TLS_PATHS["ca"]
            + " sslcert=" + TLS_PATHS[name + "Certificate"]
            + " sslkey=" + TLS_PATHS[name + "Key"]
            + " passfile=/dev/null gssencmode=disable")
        selected_configuration = (dsn, selected["connectTimeoutSeconds"], role, selected["clientDn"],
            selected["clientSerial"], selected["issuerDn"], payload["queryManifestDigest"],
            payload["structureManifestDigest"])
        result.append(selected_configuration)
    return tuple(result)


def _launch_shape(value, work):
    shape._object(value, _LAUNCH_FIELDS, "registration execution completion launch")
    for name, expected in (("schema", LAUNCH_SCHEMA), ("processMode", PROCESS_MODE),
            ("listenerPath", LISTENER_PATH)):
        shape._literal(value[name], expected)
    for name, expected in (("serviceUid", SERVICE_UID), ("serviceGid", SERVICE_GID),
            ("peerUid", PEER_UID), ("peerGid", PEER_GID), ("rootPublicKeyFd", ROOT_FD),
            ("bootstrapFd", BOOTSTRAP_FD), ("listenerFd", LISTENER_FD),
            ("signingKeyFd", KEY_FD), ("journalDirectoryFd", JOURNAL_FD)):
        shape._integer(value[name], 2**32 - 2, minimum=1)
        if value[name] != expected:
            raise RegistrationExecutionCompletionBootstrapError("completion fixed launch scalar differs")
    descriptors = value["inheritedFileDescriptors"]
    shape._array(descriptors, len(INHERITED_DESCRIPTORS), "completion inherited descriptors")
    for descriptor in descriptors:
        shape._integer(descriptor, 1023, minimum=3)
    plan._same(descriptors, list(INHERITED_DESCRIPTORS), work,
        "completion inherited descriptor inventory differs")
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for name in ("journalDirectoryDevice", "listenerSocketDevice", "listenerPathDevice"):
        shape._integer(value[name], 2**64 - 1)
    for name in ("journalDirectoryInode", "listenerSocketInode", "listenerPathInode"):
        shape._integer(value[name], 2**64 - 1, minimum=1)
    shape._integer(value["journalMaximumRecords"], authorization.MAX_RECORDS, minimum=2)


def _payload_shape(payload, work):
    shape._object(payload, _PAYLOAD_FIELDS, "registration execution completion bootstrap")
    for name, expected in (("schema", PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("role", ROLE), ("trustMode", "trusted-host-local")):
        shape._literal(payload[name], expected)
    for name in ("configurationDigest", "generationDigest", "completionSpkiDigest",
            "completionMeasurementDigest", "runtimeClosureDigest", "packetDigest",
            "authorizationDigest", "queryManifestDigest", "structureManifestDigest"):
        shape._digest(payload[name])
    authorization._token(payload["databaseId"])
    shape._object(payload["generation"], frozenset(configuration._GENERATION_FIELDS), "completion generation")
    if any(type(payload[name]) is not dict for name in
            ("configurationPayload", "runtimeRoleIdentities", "replayExpectations")):
        raise RegistrationExecutionCompletionBootstrapError("completion configuration and history are not exact data")
    for name, maximum in _ORIGINAL_LIMITS:
        record = payload[name]
        shape._object(record, _ORIGINAL_FIELDS, "completion enrollment original")
        authorization.transport._transport_shape(record["base64Url"], record["byteCount"], maximum)
        shape._digest(record["bytesDigest"])
        shape._digest(record["identityDigest"])
    pending = payload["currentPending"]
    shape._object(pending, frozenset({"sequence", "headDigest", "fence"}), "independent completion pending scope")
    shape._integer(pending["sequence"], authorization.MAX_RECORDS, minimum=1)
    shape._digest(pending["headDigest"])
    shape._integer(pending["fence"], minimum=1)
    checkpoint = payload["completionCheckpoint"]
    shape._object(checkpoint, frozenset({"sequence", "headDigest"}), "independent completion checkpoint")
    shape._integer(checkpoint["sequence"], authorization.MAX_RECORDS)
    shape._digest(checkpoint["headDigest"])
    # Exact existing state-service/activated-listener identity; no peer widening.
    reserve_profile._state_endpoint(payload["stateEndpoint"])
    _database_configurations(payload, work)
    shape._object(payload["tlsFiles"], frozenset(TLS_PATHS), "completion fixed TLS originals")
    for name, maximum in TLS_LIMITS.items():
        record = payload["tlsFiles"][name]
        shape._object(record, frozenset({"byteCount", "bytesDigest"}), "completion TLS original pin")
        shape._integer(record["byteCount"], maximum, minimum=MIN_TLS_BYTES)
        shape._digest(record["bytesDigest"])
    for name in ("issuedAtEpochNs", "expiresAtEpochNs"):
        shape._integer(payload[name], minimum=1)
    if not 0 < payload["expiresAtEpochNs"] - payload["issuedAtEpochNs"] <= MAX_RECEIPT_AGE_NS:
        raise RegistrationExecutionCompletionBootstrapError("completion launch lifetime exceeds its source bound")
    if any(payload[name] is not False for name in _FALSE_FIELDS):
        raise RegistrationExecutionCompletionBootstrapError("completion bootstrap is not trusted-host-local assurance")
    _launch_shape(payload["launch"], work)


def _fresh(interval, work, opening=None):
    """Check the original bounded epoch/monotonic bracket without renewal."""
    try:
        return state_bootstrap._fresh(interval, work, opening=opening)
    except (TypeError, ValueError, OverflowError) as exc:
        raise RegistrationExecutionCompletionBootstrapError("completion original launch interval is not live") from exc


def _originals(payload, work):
    originals = []
    for name, maximum in _ORIGINAL_LIMITS:
        record = payload[name]
        raw = authorization.transport._decode(record["base64Url"], record["byteCount"], maximum, work)
        work.charge(hashes=1, input_bytes=len(raw))
        plan._same("sha256:" + hashlib.sha256(raw).hexdigest(), record["bytesDigest"], work,
            "completion enrollment original bytes differ from their root pin")
        originals.append(raw)
    return tuple(originals)


def _material(payload, root_key, opening, work):
    configured, generation, runtime = (payload["configurationPayload"],
        payload["generation"], payload["runtimeRoleIdentities"])
    digest = payload["configurationDigest"]
    mapped = enrollment_policy._capture_on_work(payload=configured,
        configuration_digest=digest, generation=generation, runtime_role_identities=runtime, work=work)
    # This invocation has genuinely admitted the complete configuration and
    # runtime. Reuse the real fixed registration pin mapper, with no read owner
    # or fabricated successful verifier carrier to obtain static policy pins.
    pins = pins_configuration._pins_from_owned_configuration_on_work(purpose="registration",
        owned_payload=configured, owned_runtime_identities=runtime, configuration_digest=digest, work=work)
    plan._same(pins[0], OPERATION, work, "completion replay operation is not registration evidence")
    planner, evidence_key = pins[1], pins[4]
    expected = replay._expectations(OPERATION, payload["replayExpectations"], planner, evidence_key, work)
    expected = pins_configuration.admission._capture_expectations_on_work(pins, expected, work)
    roles = configured["roles"]
    shape._object(roles, frozenset(configuration._ROLE_NAMES), "completion configured roles")
    forbidden = [mapped.policy["signingSpkiDigest"]]
    for name in configuration._ROLE_NAMES:
        role = roles[name]
        shape._integer(role["serviceUid"], 2**32 - 2)
        if role["serviceUid"] == SERVICE_UID:
            raise RegistrationExecutionCompletionBootstrapError("completion UID is shared with a configured role")
        shape._digest(role["responseSigningSpkiDigest"])
        forbidden.append(role["responseSigningSpkiDigest"])
        if name in ("verifier", "planner"):
            shape._digest(role["signingSpkiDigest"])
            forbidden.append(role["signingSpkiDigest"])
    purposes = configured[evidence_policy.FIELD]
    for name in ("registration", "installation"):
        if purposes[name] is not None:
            forbidden.append(purposes[name]["signingSpkiDigest"])
    transitions = configured.get(enrollment_policy.transition_policy.FIELD)
    if transitions is not None:
        for name in ("registration", "stage", "completion"):
            if transitions[name] is not None:
                forbidden.append(transitions[name]["signingSpkiDigest"])
    current_raw, grant_raw, caller_raw = _originals(payload, work)
    admitted = caller._admit_enrollment_on_work(authorization_enrollment_bytes=caller_raw,
        current_root_enrollment_bytes=current_raw, grant_enrollment_bytes=grant_raw,
        root_public_key=root_key, configuration_digest=digest,
        planner_public_key=planner, evidence_public_key=evidence_key, work=work)
    current = authorization._admit_enrollment_on_work(enrollment_bytes=current_raw,
        root_public_key=root_key, work=work)
    grant = grants._admit_enrollment_on_work(grant_enrollment_bytes=grant_raw,
        current_root_enrollment_bytes=current_raw, root_public_key=root_key, work=work)
    enrolled, policy = admitted.payload, current.payload
    completion = policy["completion"]
    for actual, pinned in ((payload["currentRootEnrollment"]["identityDigest"], current.enrollment_digest),
            (payload["grantEnrollment"]["identityDigest"], grant.enrollment_digest),
            (payload["authorizationEnrollment"]["identityDigest"], admitted.enrollment_digest),
            (payload["databaseId"], enrolled["databaseId"]),
            (payload["generationDigest"], enrolled["generationDigest"]),
            (payload["generationDigest"], mapped.generation_digest),
            (payload["queryManifestDigest"], configured["queryManifestDigest"]),
            (payload["completionSpkiDigest"], completion["spkiDigest"]),
            (payload["completionMeasurementDigest"], completion["measurementDigest"]),
            (payload["launch"]["journalMaximumRecords"], policy["maxRecords"])):
        plan._same(actual, pinned, work, "completion bootstrap differs from genuine configuration or enrollment")
    # Actual caller admission already excludes root/current-root/grant keys.
    # Retain the separate configured-purpose exclusion for that caller too.
    work.prepare_scan(forbidden)
    for pin in forbidden:
        work.prepare_comparison(enrolled["callerKey"]["spkiDigest"], pin)
        if enrolled["callerKey"]["spkiDigest"] == pin:
            raise RegistrationExecutionCompletionBootstrapError("completion caller key reuses another purpose")
    forbidden.extend((caller.keys._spki_on_work(root_key, work),
        enrolled["callerKey"]["spkiDigest"], grant.payload["authorizer"]["spkiDigest"]))
    work.prepare_scan(forbidden)
    for pin in forbidden:
        work.prepare_comparison(completion["spkiDigest"], pin)
        if completion["spkiDigest"] == pin:
            raise RegistrationExecutionCompletionBootstrapError("completion key reuses another configured purpose")
    pending, checkpoint = payload["currentPending"], payload["completionCheckpoint"]
    if pending["sequence"] >= policy["maxRecords"] or checkpoint["sequence"] > policy["maxRecords"]:
        raise RegistrationExecutionCompletionBootstrapError("completion pending or checkpoint exceeds enrolled capacity")
    if checkpoint["sequence"] == 0:
        plan._same(checkpoint["headDigest"], current.enrollment_digest, work,
            "completion independent journal genesis differs")
    custody_config, commit_config = _database_configurations(payload, work)
    return _CompletionMaterial(configured, generation, runtime, digest, current_raw, grant_raw,
        caller_raw, planner, evidence_key, current.completion_public_key, completion["spkiDigest"],
        completion["measurementDigest"], enrolled["databaseId"], mapped.generation_digest,
        current.enrollment_digest, payload["runtimeClosureDigest"],
        (pending["sequence"], pending["headDigest"], pending["fence"]),
        (checkpoint["sequence"], checkpoint["headDigest"]), reserve_profile._state_endpoint(payload["stateEndpoint"]),
        payload["packetDigest"], payload["authorizationDigest"], expected, custody_config, commit_config,
        payload["tlsFiles"], (payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]), opening, payload["launch"])


def _verify_on_work(*, bootstrap_bytes, root_public_key, work):
    """Authenticate exact root originals before any cold resource selection."""
    try:
        ledger = capture._SharedLedger(work)
        original = authorization._original(bootstrap_bytes, MAX_BYTES, "completion bootstrap")
        root = root_public_key
        authorization._public(root)
        envelope = codec._decode(original, work)
        shape._object(envelope, _ENVELOPE_FIELDS, "completion signed bootstrap")
        shape._literal(envelope["schema"], SCHEMA)
        shape._base64url(envelope["signatureBase64Url"], signature=True)
        if type(envelope["payload"]) is not dict:
            raise RegistrationExecutionCompletionBootstrapError("completion payload is not an exact object")
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
        if isinstance(exc, RegistrationExecutionCompletionBootstrapError):
            raise
        raise RegistrationExecutionCompletionBootstrapError("completion bootstrap admission failed") from exc


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
        if isinstance(exc, RegistrationExecutionCompletionBootstrapError):
            raise
        raise RegistrationExecutionCompletionBootstrapError("completion bootstrap production failed") from exc
