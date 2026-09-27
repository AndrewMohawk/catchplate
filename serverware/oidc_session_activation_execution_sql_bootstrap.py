"""Independent root-original admission for the activation SQL worker.

The role launch, receiving custody and embedded planner are distinct genuine
originals. Their signatures authenticate independently supplied configuration,
predecessor, current pending and attempt-checkpoint claims; they do not observe
currentness or prove that two TLS identities reach the same database. The
actual issuer and executor must still use the genuine catalog-bound owners.

This process receives no signing key. Only the two admitted AES originals and
fixed issuer/executor TLS files belong here. No key values, supplied DSN,
password, database connection, filesystem read or successful admission token
is accepted or created by this module. Original work/windows never renew.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from cryptography.exceptions import InvalidSignature

from serverware import authority_oidc_session_activation_execution_authorization as caller
from serverware import authority_successor_execution_attempts as attempts
from serverware import oidc_session_activation_execution_custody_bootstrap as receiving
# Pure closed scalar grammar only: this selects no other role, TLS path,
# configuration, original, key or successful admission result.
from serverware.registration_execution_sql_bootstrap import _database_shape


planner_bootstrap = receiving.planner_bootstrap
authority, configuration = planner_bootstrap.authority, planner_bootstrap.configuration
codec, signing = planner_bootstrap.codec, planner_bootstrap.signing
capability, capture, plan = planner_bootstrap.capability, planner_bootstrap.capture, planner_bootstrap.plan
authorization, grants, shape, clock = caller.authorization, caller.grants, caller.shape, caller.clock
production = configuration.production
ROLE = PROCESS_MODE = receiving.CONSUMERS["sql-issuer"][0]
OPERATION = "oidc.session.activate"
SERVICE_UID = SERVICE_GID = 65504
PEER_UID = PEER_GID = 65532
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, CUSTODY_FD, BUNDLE_KEY_FD, DELIVERY_KEY_FD, JOURNAL_FD = range(198, 205)
INHERITED_DESCRIPTORS = (ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, CUSTODY_FD,
    BUNDLE_KEY_FD, DELIVERY_KEY_FD, JOURNAL_FD)
LISTENER_PATH = "/run/serverware/oidc-session-activation-execution/sql.sock"
LISTENER_NAME = "serverware-oidc-session-activation-execution-sql"
JOURNAL_PATH = "/var/lib/serverware/oidc-session-activation-execution-sql-attempts"
TLS_PATHS = {
    "ca": "/run/serverware/oidc-session-activation-execution-sql-tls/ca.pem",
    "issuerCertificate": "/run/serverware/oidc-session-activation-execution-sql-tls/issuer.crt",
    "issuerKey": "/run/serverware/oidc-session-activation-execution-sql-tls/issuer.key",
    "executorCertificate": "/run/serverware/oidc-session-activation-execution-sql-tls/executor.crt",
    "executorKey": "/run/serverware/oidc-session-activation-execution-sql-tls/executor.key",
}
TLS_LIMITS = {name: (16 * 1024 if name in ("issuerKey", "executorKey") else 64 * 1024)
    for name in TLS_PATHS}
MIN_TLS_BYTES = 2
MAX_BYTES = MAX_ROLE_BYTES = 4 * 1024 * 1024
MAX_CUSTODY_BYTES = receiving.MAX_BYTES
MAX_RECEIPT_AGE_NS = planner_bootstrap.MAX_RECEIPT_AGE_NS
SCHEMA = "serverware.signedOidcSessionActivationExecutionSqlBootstrap/v1"
PAYLOAD_SCHEMA = "serverware.oidcSessionActivationExecutionSqlBootstrap/v1"
LAUNCH_SCHEMA = "serverware.oidcSessionActivationExecutionSqlLaunch/v1"
_FALSE_FIELDS = receiving._FALSE_FIELDS
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
_CUSTODY_FIELDS = frozenset({"byteCount", "bytesDigest"})
_ORIGINAL_FIELDS = frozenset({"base64Url", "byteCount", "bytesDigest", "identityDigest"})
_ORIGINAL_LIMITS = (("currentRootEnrollment", authorization.MAX_ENROLLMENT_BYTES),
    ("grantEnrollment", grants.MAX_ENROLLMENT_BYTES),
    ("authorizationEnrollment", caller.MAX_ENROLLMENT_BYTES))
_PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "role", "operation", "receivingCustody",
    "receiverIdentity", "configurationDigest", "generationDigest", "runtimeClosureDigest", "databaseId",
    "currentRootEnrollment", "grantEnrollment", "authorizationEnrollment", "statePredecessor",
    "currentPending", "attemptCheckpoint", "databaseEndpoint", "sqlRoles", "queryManifestDigest",
    "structureManifestDigest", "tlsFiles", "issuedAtEpochNs", "expiresAtEpochNs", "trustMode",
    "launch", *_FALSE_FIELDS})
_LAUNCH_FIELDS = frozenset({"schema", "processMode", "serviceUid", "serviceGid", "peerUid", "peerGid",
    "rootPublicKeyFd", "bootstrapFd", "listenerFd", "custodyFd", "bundleKeyFd", "deliveryKeyFd",
    "inheritedFileDescriptors", "listenerPath", "requestTimeoutSeconds", "listenerSocketDevice",
    "listenerSocketInode", "listenerPathDevice", "listenerPathInode", "journalDirectoryFd",
    "journalDirectoryPath", "journalDirectoryDevice", "journalDirectoryInode", "journalMaximumRecords"})
_SQL_ROLE_FIELDS = frozenset({"connectTimeoutSeconds", "clientDn", "clientSerial", "issuerDn"})


class OidcSessionActivationExecutionSqlBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _SqlMaterial:
    """Owned same-call facts, never an accepted SQL admission capability."""

    bootstrap_bytes: bytes
    custody_bytes: bytes
    custody_material: receiving._CustodyMaterial
    receiver_identity: dict
    configuration_payload: dict
    generation: dict
    runtime_role_identities: dict
    configuration_digest: str
    runtime_closure_digest: str
    current_root_enrollment_bytes: bytes
    grant_enrollment_bytes: bytes
    authorization_enrollment_bytes: bytes
    planner_public_key: object
    operation_public_key: object
    database_id: str
    generation_digest: str
    enrollment_digest: str
    maximum_authorization_age_ns: int
    maximum_authorization_clock_skew_ns: int
    state_predecessor: tuple
    current_pending: tuple
    attempt_checkpoint: tuple
    issuer_configuration: tuple
    executor_configuration: tuple
    tls_files: dict
    attestation_interval: tuple
    opening_sample: tuple
    launch: dict


def _fail(message):
    raise OidcSessionActivationExecutionSqlBootstrapError(message)


def _database_configurations(payload, work):
    endpoint = payload["databaseEndpoint"]
    _database_shape(endpoint)
    roles = payload["sqlRoles"]
    shape._object(roles, frozenset({"issuer", "executor"}), "activation fixed SQL roles")
    result = []
    for name, role in (("issuer", authority.SUCCESSOR_ISSUER_ROLE),
            ("executor", authority.SUCCESSOR_EXECUTOR_ROLE)):
        selected = roles[name]
        shape._object(selected, _SQL_ROLE_FIELDS, "activation SQL TLS identity")
        shape._integer(selected["connectTimeoutSeconds"], 300, minimum=2)
        for field in ("clientDn", "clientSerial", "issuerDn"):
            text = selected[field]
            if (type(text) is not str or not 1 <= len(text) <= 4096 or "\x00" in text
                    or work.prepare_utf8(text) > 4096):
                _fail("activation SQL TLS identity exceeds its exact text bound")
        # All interpolation is fixed source or closed scalar grammar. There is
        # no supplied DSN, URI, list, service file, password or path fallback.
        dsn = ("host=" + endpoint["host"] + " hostaddr=" + endpoint["hostaddr"]
            + " port=" + str(endpoint["port"]) + " dbname=" + endpoint["databaseName"]
            + " user=" + role + " sslmode=verify-full sslrootcert=" + TLS_PATHS["ca"]
            + " sslcert=" + TLS_PATHS[name + "Certificate"]
            + " sslkey=" + TLS_PATHS[name + "Key"]
            + " passfile=/dev/null gssencmode=disable")
        result.append((dsn, selected["connectTimeoutSeconds"], role, selected["clientDn"],
            selected["clientSerial"], selected["issuerDn"], payload["queryManifestDigest"],
            payload["structureManifestDigest"]))
    return tuple(result)


def _launch_shape(value, work):
    shape._object(value, _LAUNCH_FIELDS, "activation execution SQL launch")
    for field, expected in (("schema", LAUNCH_SCHEMA), ("processMode", PROCESS_MODE),
            ("listenerPath", LISTENER_PATH), ("journalDirectoryPath", JOURNAL_PATH)):
        shape._literal(value[field], expected)
    for field, expected in (("serviceUid", SERVICE_UID), ("serviceGid", SERVICE_GID),
            ("peerUid", PEER_UID), ("peerGid", PEER_GID), ("rootPublicKeyFd", ROOT_FD),
            ("bootstrapFd", BOOTSTRAP_FD), ("listenerFd", LISTENER_FD), ("custodyFd", CUSTODY_FD),
            ("bundleKeyFd", BUNDLE_KEY_FD), ("deliveryKeyFd", DELIVERY_KEY_FD),
            ("journalDirectoryFd", JOURNAL_FD)):
        shape._integer(value[field], 2**32 - 2, minimum=1)
        if value[field] != expected:
            _fail("activation SQL fixed launch scalar differs")
    descriptors = value["inheritedFileDescriptors"]
    shape._array(descriptors, len(INHERITED_DESCRIPTORS), "activation SQL descriptors")
    for descriptor in descriptors:
        shape._integer(descriptor, 1023, minimum=3)
    plan._same(descriptors, list(INHERITED_DESCRIPTORS), work, "activation SQL exact descriptor inventory")
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for field in ("listenerSocketDevice", "listenerPathDevice", "journalDirectoryDevice"):
        shape._integer(value[field], 2**64 - 1)
    for field in ("listenerSocketInode", "listenerPathInode", "journalDirectoryInode"):
        shape._integer(value[field], 2**64 - 1, minimum=1)
    shape._integer(value["journalMaximumRecords"], authorization.MAX_RECORDS, minimum=2)


def _payload_shape(payload, work):
    shape._object(payload, _PAYLOAD_FIELDS, "activation execution SQL payload")
    for field, expected in (("schema", PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("role", ROLE), ("operation", OPERATION), ("trustMode", "trusted-host-local")):
        shape._literal(payload[field], expected)
    shape.validate_identity_shape(payload["receiverIdentity"])
    for field in ("configurationDigest", "generationDigest", "runtimeClosureDigest",
            "queryManifestDigest", "structureManifestDigest"):
        shape._digest(payload[field])
    authorization._token(payload["databaseId"])
    custody = payload["receivingCustody"]
    shape._object(custody, _CUSTODY_FIELDS, "activation external SQL receiving original")
    shape._integer(custody["byteCount"], MAX_CUSTODY_BYTES, minimum=2)
    shape._digest(custody["bytesDigest"])
    for name, maximum in _ORIGINAL_LIMITS:
        record = payload[name]
        shape._object(record, _ORIGINAL_FIELDS, "activation SQL enrollment original")
        authorization.transport._transport_shape(record["base64Url"], record["byteCount"], maximum)
        shape._integer(record["byteCount"], maximum, minimum=2)
        shape._digest(record["bytesDigest"])
        shape._digest(record["identityDigest"])
    predecessor, pending, checkpoint = (payload["statePredecessor"], payload["currentPending"],
        payload["attemptCheckpoint"])
    shape._object(predecessor, frozenset({"sequence", "headDigest", "nextFence"}),
        "independent activation SQL predecessor")
    shape._object(pending, frozenset({"sequence", "headDigest", "fence"}),
        "independent activation SQL current pending")
    shape._object(checkpoint, frozenset({"sequence", "headDigest"}),
        "independent activation SQL attempt checkpoint")
    for selected in (predecessor, checkpoint):
        shape._integer(selected["sequence"], authorization.MAX_RECORDS)
        shape._digest(selected["headDigest"])
    shape._integer(predecessor["nextFence"], minimum=1)
    shape._integer(pending["sequence"], authorization.MAX_RECORDS, minimum=1)
    shape._digest(pending["headDigest"])
    shape._integer(pending["fence"], minimum=1)
    if predecessor["sequence"] == 0 and predecessor["nextFence"] != 1:
        _fail("activation SQL genesis predecessor requires fence one")
    if (pending["sequence"] != predecessor["sequence"] + 1
            or pending["fence"] != predecessor["nextFence"]):
        _fail("activation SQL independent pending and predecessor scopes disagree")
    _database_configurations(payload, work)
    shape._object(payload["tlsFiles"], frozenset(TLS_PATHS), "activation fixed SQL TLS originals")
    for name, maximum in TLS_LIMITS.items():
        record = payload["tlsFiles"][name]
        shape._object(record, frozenset({"byteCount", "bytesDigest"}), "activation SQL TLS original pin")
        shape._integer(record["byteCount"], maximum, minimum=MIN_TLS_BYTES)
        shape._digest(record["bytesDigest"])
    for field in ("issuedAtEpochNs", "expiresAtEpochNs"):
        shape._integer(payload[field], minimum=1)
    if not 0 < payload["expiresAtEpochNs"] - payload["issuedAtEpochNs"] <= MAX_RECEIPT_AGE_NS:
        _fail("activation SQL lifetime exceeds its original launch ceiling")
    if any(payload[field] is not False for field in _FALSE_FIELDS):
        _fail("activation SQL claims unsupported hardware or witness assurance")
    _launch_shape(payload["launch"], work)


def _fresh(interval, work, opening=None):
    return planner_bootstrap._fresh(interval, work, opening=opening)


def _digest(raw, work):
    work.charge(hashes=1, input_bytes=len(raw))
    return production._callback(work, lambda: "sha256:" + hashlib.sha256(raw).hexdigest())


def _originals(payload, work, current):
    originals = []
    for name, maximum in _ORIGINAL_LIMITS:
        current()
        record = payload[name]
        raw = authorization.transport._decode(record["base64Url"], record["byteCount"], maximum, work)
        plan._same(_digest(raw, work), record["bytesDigest"], work, "activation SQL enrollment original digest")
        current()
        originals.append(raw)
    return tuple(originals)


def _configured_scope(configured, caller_spki, work):
    roles = configured["roles"]
    shape._object(roles, frozenset(configuration._ROLE_NAMES), "activation SQL configured roles")
    forbidden = []
    for name in configuration._ROLE_NAMES:
        role = roles[name]
        for field in ("serviceUid", "serviceGid"):
            shape._integer(role[field], 2**32 - 2)
            if role[field] == SERVICE_UID:
                _fail("activation SQL identity is shared with a configured role")
        forbidden.append(role["responseSigningSpkiDigest"])
        if name in ("verifier", "planner"):
            forbidden.append(role["signingSpkiDigest"])
    for policy_module, slots in ((planner_bootstrap.evidence_policy, ("registration", "installation")),
            (planner_bootstrap.transition_policy, ("registration", "stage", "completion"))):
        value = configured.get(policy_module.FIELD)
        if value is not None:
            policy, _public_keys = policy_module._validate_policy_on_work(value,
                webauthn=configured["webauthn"], work=work)
            forbidden.extend(policy[name]["signingSpkiDigest"] for name in slots if policy[name] is not None)
    value = configured.get(planner_bootstrap.enrollment_policy.FIELD)
    if value is not None:
        policy, _public_key = planner_bootstrap.enrollment_policy._validate_policy_on_work(
            value, payload=configured, work=work)
        forbidden.append(policy["signingSpkiDigest"])
    work.prepare_scan(forbidden)
    for pin in forbidden:
        shape._digest(pin)
        work.prepare_comparison(caller_spki, pin)
        if caller_spki == pin:
            _fail("activation SQL caller key is shared with another configured purpose")


def _admit_payload(payload, custody_bytes, root, window, deadline, work, current):
    record = payload["receivingCustody"]
    if len(custody_bytes) != record["byteCount"]:
        _fail("activation SQL receiving original byte count differs from the role launch")
    if len(custody_bytes) + sum(payload[name]["byteCount"] for name, _ in _ORIGINAL_LIMITS) + MAX_BYTES > authority.MAX_RESULT_BYTES:
        _fail("activation SQL original inventory exceeds its aggregate ceiling")
    current()
    plan._same(_digest(custody_bytes, work), record["bytesDigest"], work, "activation SQL receiving original digest")
    custody = receiving._verify_on_work(custody_bytes=custody_bytes, root_public_key=root,
        expected_consumer_role="sql-issuer", work=work, live_window=window, transport_deadline_ns=deadline)
    current()
    admitted = custody.planner
    for actual, expected in ((payload["receiverIdentity"], custody.receiver_identity),
            (payload["configurationDigest"], admitted.configuration_digest),
            (payload["generationDigest"], admitted.generation["digest"]),
            (payload["runtimeClosureDigest"], admitted.runtime_closure_digest),
            (payload["queryManifestDigest"], admitted.configuration_payload["queryManifestDigest"])):
        plan._same(actual, expected, work, "activation SQL differs from genuine receiving scope")
    if not custody.attestation_interval[0] <= payload["issuedAtEpochNs"] < payload["expiresAtEpochNs"] <= custody.attestation_interval[1]:
        _fail("activation SQL interval escapes its original receiving interval")

    def live():
        current()
        _fresh(custody.attestation_interval, work, opening=custody.opening_sample)
        _fresh(admitted.attestation_interval, work, opening=admitted.opening_sample)
        return current()

    live()
    current_raw, grant_raw, caller_raw = _originals(payload, work, live)
    work.charge(input_bytes=len(current_raw) + len(admitted.state_enrollment_bytes))
    if current_raw != admitted.state_enrollment_bytes:
        _fail("activation SQL state enrollment differs from its original planner scope")
    enrolled = caller._admit_enrollment_on_work(authorization_enrollment_bytes=caller_raw,
        current_root_enrollment_bytes=current_raw, grant_enrollment_bytes=grant_raw,
        root_public_key=root, configuration_digest=admitted.configuration_digest,
        planner_public_key=admitted.planner_public_key, operation_public_key=root, work=work)
    live()
    current_material = authorization._admit_enrollment_on_work(enrollment_bytes=current_raw,
        root_public_key=root, work=work)
    live()
    grant = grants._admit_enrollment_on_work(grant_enrollment_bytes=grant_raw,
        current_root_enrollment_bytes=current_raw, root_public_key=root, work=work)
    live()
    policy, caller_policy = current_material.payload, enrolled.payload
    for actual, expected in ((payload["currentRootEnrollment"]["identityDigest"], admitted.state_enrollment_digest),
            (payload["currentRootEnrollment"]["identityDigest"], current_material.enrollment_digest),
            (payload["currentRootEnrollment"]["identityDigest"], caller_policy["currentRootEnrollmentDigest"]),
            (payload["grantEnrollment"]["identityDigest"], grant.enrollment_digest),
            (payload["authorizationEnrollment"]["identityDigest"], enrolled.enrollment_digest),
            (payload["databaseId"], caller_policy["databaseId"]),
            (payload["generationDigest"], caller_policy["generationDigest"])):
        plan._same(actual, expected, work, "activation SQL differs from genuine purpose enrollment")
    # No computation/authorizer measurement is relabeled as a SQL identity.
    # The independent root signs this SQL identity in both original role and
    # custody statements; local signatures do not measure its runtime.
    _configured_scope(admitted.configuration_payload, caller_policy["callerKey"]["spkiDigest"], work)
    predecessor, pending, checkpoint = (payload["statePredecessor"], payload["currentPending"],
        payload["attemptCheckpoint"])
    maximum = payload["launch"]["journalMaximumRecords"]
    if (maximum > policy["maxRecords"] or pending["sequence"] >= policy["maxRecords"]
            or checkpoint["sequence"] > maximum):
        _fail("activation SQL independent pending or attempt scope exceeds enrolled capacity")
    if predecessor["sequence"] == 0:
        plan._same(predecessor["headDigest"], current_material.enrollment_digest, work,
            "activation SQL independent predecessor genesis differs")
    if checkpoint["sequence"] == 0:
        plan._same(checkpoint["headDigest"], attempts._genesis_on_work(payload["structureManifestDigest"], work),
            work, "activation SQL attempt checkpoint differs from genuine source-catalog genesis")
    configurations = _database_configurations(payload, work)
    live()
    return custody, current_raw, grant_raw, caller_raw, enrolled, current_material, configurations, live


def _verify_on_work(*, bootstrap_bytes, custody_bytes, root_public_key, work,
        live_window=None, transport_deadline_ns=None):
    """Authenticate exact originals before selecting any SQL or key resources."""
    try:
        original = authorization._original(bootstrap_bytes, MAX_BYTES, "activation SQL bootstrap")
        custody_original = authorization._original(custody_bytes, MAX_CUSTODY_BYTES, "activation receiving custody")
        root = root_public_key
        authorization._public(root)
        window = None if live_window is None else clock._validate(live_window)
        deadline = transport_deadline_ns
        inherited = planner_bootstrap._processing(window, deadline, work)
        inherited()
        envelope = codec._decode(original, work)
        shape._object(envelope, _ENVELOPE_FIELDS, "signed activation SQL bootstrap")
        shape._literal(envelope["schema"], SCHEMA)
        shape._base64url(envelope["signatureBase64Url"], signature=True)
        if type(envelope["payload"]) is not dict:
            _fail("activation SQL payload is not an exact object")
        codec._canonical(original, envelope, work)
        payload = envelope["payload"]
        unsigned = configuration._configuration_wire(payload, capture._SharedLedger(work))
        inherited()
        capability._signature(root, envelope["signatureBase64Url"], SCHEMA, unsigned, capture._SharedLedger(work))
        inherited()
        codec._canonical(original, envelope, work)
        _payload_shape(payload, work)
        interval = payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]
        opening = _fresh(interval, work)
        current = planner_bootstrap._launch_guard(interval, opening, inherited, work)
        custody, current_raw, grant_raw, caller_raw, enrolled, current_material, configurations, live = _admit_payload(
            payload, custody_original, root, window, deadline, work, current)
        admitted = custody.planner
        predecessor, pending, checkpoint = (payload["statePredecessor"], payload["currentPending"],
            payload["attemptCheckpoint"])
        material = _SqlMaterial(bootstrap_bytes=original, custody_bytes=custody_original,
            custody_material=custody, receiver_identity=payload["receiverIdentity"],
            configuration_payload=admitted.configuration_payload, generation=admitted.generation,
            runtime_role_identities=admitted.runtime_role_identities,
            configuration_digest=admitted.configuration_digest, runtime_closure_digest=admitted.runtime_closure_digest,
            current_root_enrollment_bytes=current_raw, grant_enrollment_bytes=grant_raw,
            authorization_enrollment_bytes=caller_raw, planner_public_key=admitted.planner_public_key,
            operation_public_key=root, database_id=payload["databaseId"], generation_digest=payload["generationDigest"],
            enrollment_digest=current_material.enrollment_digest,
            maximum_authorization_age_ns=enrolled.payload["maximumAgeNs"],
            maximum_authorization_clock_skew_ns=enrolled.payload["maximumClockSkewNs"],
            state_predecessor=(predecessor["sequence"], predecessor["headDigest"], predecessor["nextFence"]),
            current_pending=(pending["sequence"], pending["headDigest"], pending["fence"]),
            attempt_checkpoint=(checkpoint["sequence"], checkpoint["headDigest"]),
            issuer_configuration=configurations[0], executor_configuration=configurations[1],
            tls_files=payload["tlsFiles"], attestation_interval=interval, opening_sample=opening, launch=payload["launch"])
        codec._canonical(original, envelope, work)
        live()
        return material
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, OidcSessionActivationExecutionSqlBootstrapError):
            raise
        raise OidcSessionActivationExecutionSqlBootstrapError("activation SQL bootstrap admission failed") from exc


def _produce_on_work(*, payload, custody_bytes, root_private_key, root_public_key, work,
        live_window=None, transport_deadline_ns=None):
    """Sign independently established scope; never infer currentness from ACKs."""
    try:
        custody_original = authorization._original(custody_bytes, MAX_CUSTODY_BYTES, "activation receiving custody")
        private, root = root_private_key, root_public_key
        authorization._private(private)
        authorization._public(root)
        owned = configuration._ConfigurationCapture(capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(payload)
        window = None if live_window is None else clock._validate(live_window)
        deadline = transport_deadline_ns
        inherited = planner_bootstrap._processing(window, deadline, work)
        inherited()
        _payload_shape(owned, work)
        interval = owned["issuedAtEpochNs"], owned["expiresAtEpochNs"]
        opening = _fresh(interval, work)
        current = planner_bootstrap._launch_guard(interval, opening, inherited, work)
        *_facts, live = _admit_payload(owned, custody_original, root, window, deadline, work, current)
        unsigned = configuration._configuration_wire(owned, capture._SharedLedger(work))
        live()
        original = signing._sign(owned, SCHEMA, MAX_BYTES, private, root, work)
        codec._canonical(unsigned, owned, work)
        live()
        return original
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, OidcSessionActivationExecutionSqlBootstrapError):
            raise
        raise OidcSessionActivationExecutionSqlBootstrapError("activation SQL bootstrap production failed") from exc
