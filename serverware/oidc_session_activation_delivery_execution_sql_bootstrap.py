"""Independent root-original resource admission for a future consume SQL worker.

The closed role original binds current pending/predecessor and local attempt
checkpoints independently, never from a response ACK. It authenticates the
separate SQL-issuer receiving purpose and its actual planner/history originals.
It opens no keys, files or database, supplies no consume SQL implementation and
accepts no successful material as authority. Original allowances never renew.
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature

from serverware import authority_successor_execution_attempts as attempts
from serverware import oidc_session_activation_delivery_execution_authorizer_bootstrap as primitives
# Closed scalar grammar only; no registration role, DSN, key or admission path.
from serverware.registration_execution_sql_bootstrap import _database_shape


receiving, caller, grants = primitives.receiving, primitives.caller, primitives.grants
shared, planner_bootstrap = primitives.shared, primitives.planner_bootstrap
authority, configuration = primitives.authority, primitives.configuration
codec, signing = primitives.codec, primitives.signing
authorization, capability, capture = primitives.authorization, primitives.capability, primitives.capture
plan, shape, clock, keys = primitives.plan, primitives.shape, primitives.clock, primitives.keys
ROLE = PROCESS_MODE = receiving.SQL_ISSUER_PROCESS_MODE
OPERATION = caller.OPERATION
SERVICE_UID = SERVICE_GID = 65498
PEER_UID = PEER_GID = 65532
(ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, CUSTODY_FD, PLANNER_BOOTSTRAP_FD,
    PLANNER_HISTORY_CUSTODY_FD, RECEIVING_HISTORY_CUSTODY_FD, EXECUTION_BUNDLE_KEY_FD,
    HISTORICAL_BUNDLE_KEY_FD, DELIVERY_KEY_FD, JOURNAL_FD) = range(198, 209)
INHERITED_DESCRIPTORS = (ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, CUSTODY_FD,
    PLANNER_BOOTSTRAP_FD, PLANNER_HISTORY_CUSTODY_FD, RECEIVING_HISTORY_CUSTODY_FD,
    EXECUTION_BUNDLE_KEY_FD, HISTORICAL_BUNDLE_KEY_FD, DELIVERY_KEY_FD, JOURNAL_FD)
LISTENER_PATH = "/run/serverware/oidc-session-activation-delivery-execution/sql.sock"
LISTENER_NAME = "serverware-oidc-session-activation-delivery-execution-sql"
JOURNAL_PATH = "/var/lib/serverware/oidc-session-activation-delivery-execution-sql-attempts"
TLS_PATHS = {
    "ca": "/run/serverware/oidc-session-activation-delivery-execution-sql-tls/ca.pem",
    "issuerCertificate": "/run/serverware/oidc-session-activation-delivery-execution-sql-tls/issuer.crt",
    "issuerKey": "/run/serverware/oidc-session-activation-delivery-execution-sql-tls/issuer.key",
    "executorCertificate": "/run/serverware/oidc-session-activation-delivery-execution-sql-tls/executor.crt",
    "executorKey": "/run/serverware/oidc-session-activation-delivery-execution-sql-tls/executor.key",
}
TLS_LIMITS = {name: (16 * 1024 if name in ("issuerKey", "executorKey") else 64 * 1024)
    for name in TLS_PATHS}
MIN_TLS_BYTES = 2
MAX_BYTES = MAX_ROLE_BYTES = primitives.MAX_ROLE_BYTES
MAX_CUSTODY_BYTES = primitives.MAX_CUSTODY_BYTES
MAX_PLANNER_BOOTSTRAP_BYTES = primitives.MAX_PLANNER_BOOTSTRAP_BYTES
MAX_PLANNER_HISTORY_CUSTODY_BYTES = primitives.MAX_PLANNER_HISTORY_CUSTODY_BYTES
MAX_RECEIVING_HISTORY_CUSTODY_BYTES = primitives.MAX_RECEIVING_HISTORY_CUSTODY_BYTES
MAX_RECEIPT_AGE_NS = primitives.MAX_RECEIPT_AGE_NS
SCHEMA = "serverware.signedOidcSessionActivationDeliveryExecutionSqlBootstrap/v1"
PAYLOAD_SCHEMA = "serverware.oidcSessionActivationDeliveryExecutionSqlBootstrap/v1"
LAUNCH_SCHEMA = "serverware.oidcSessionActivationDeliveryExecutionSqlLaunch/v1"
_FALSE_FIELDS = receiving._FALSE_FIELDS
_ENVELOPE_FIELDS = frozenset({"schema", "payload", "signatureBase64Url"})
_DETACHED_FIELDS, _DETACHED_LIMITS = primitives._DETACHED_FIELDS, primitives._DETACHED_LIMITS
_ORIGINAL_FIELDS, _ORIGINAL_LIMITS = primitives._ORIGINAL_FIELDS, primitives._ORIGINAL_LIMITS
_PAYLOAD_FIELDS = frozenset({"schema", "sourceRevision", "role", "operation",
    "receivingCustody", "plannerBootstrap", "plannerHistoryCustody", "receivingHistoryCustody",
    "receiverIdentity", "configurationDigest", "generationDigest", "runtimeClosureDigest", "databaseId",
    "currentRootEnrollment", "grantEnrollment", "authorizationEnrollment", "beforeVectorDigest",
    "statePredecessor", "currentPending", "attemptCheckpoint", "databaseEndpoint", "sqlRoles",
    "queryManifestDigest", "structureManifestDigest", "tlsFiles", "issuedAtEpochNs", "expiresAtEpochNs",
    "trustMode", "launch", *_FALSE_FIELDS})
_FD_FIELDS = (("rootPublicKeyFd", ROOT_FD), ("bootstrapFd", BOOTSTRAP_FD),
    ("listenerFd", LISTENER_FD), ("custodyFd", CUSTODY_FD),
    ("plannerBootstrapFd", PLANNER_BOOTSTRAP_FD),
    ("plannerHistoryCustodyFd", PLANNER_HISTORY_CUSTODY_FD),
    ("receivingHistoryCustodyFd", RECEIVING_HISTORY_CUSTODY_FD),
    ("executionBundleKeyFd", EXECUTION_BUNDLE_KEY_FD),
    ("historicalBundleKeyFd", HISTORICAL_BUNDLE_KEY_FD),
    ("deliveryKeyFd", DELIVERY_KEY_FD), ("journalDirectoryFd", JOURNAL_FD))
_LAUNCH_FIELDS = frozenset({"schema", "processMode", "serviceUid", "serviceGid", "peerUid", "peerGid",
    *(name for name, _ in _FD_FIELDS), "inheritedFileDescriptors", "listenerPath", "requestTimeoutSeconds",
    "listenerSocketDevice", "listenerSocketInode", "listenerPathDevice", "listenerPathInode",
    "journalDirectoryPath", "journalDirectoryDevice", "journalDirectoryInode", "journalMaximumRecords"})
_SQL_ROLE_FIELDS = frozenset({"connectTimeoutSeconds", "clientDn", "clientSerial", "issuerDn"})
_construction_on_work = primitives._construction_on_work
_processing, _fresh = primitives._processing, primitives._fresh
_detached, _digest, _originals = primitives._detached, primitives._digest, primitives._originals


class OidcSessionActivationDeliveryExecutionSqlBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _SqlMaterial:
    """Owned resource facts; no API accepts this output as SQL authority."""

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
    before_vector_bytes: bytes
    before_vector_digest: str
    state_predecessor: tuple
    current_pending: tuple
    attempt_checkpoint: tuple
    issuer_configuration: tuple
    executor_configuration: tuple
    tls_files: dict
    attestation_interval: tuple
    opening_sample: tuple
    launch: dict
    planner_bootstrap_bytes: bytes
    planner_history_custody_bytes: bytes
    receiving_history_custody_bytes: bytes


def _fail(message):
    raise OidcSessionActivationDeliveryExecutionSqlBootstrapError(message)


def _database_configurations(payload, work):
    endpoint, roles = payload["databaseEndpoint"], payload["sqlRoles"]
    _database_shape(endpoint)
    shape._object(roles, frozenset({"issuer", "executor"}), "consume fixed SQL roles")
    result = []
    for name, role in (("issuer", authority.SUCCESSOR_ISSUER_ROLE),
            ("executor", authority.SUCCESSOR_EXECUTOR_ROLE)):
        selected = roles[name]
        shape._object(selected, _SQL_ROLE_FIELDS, "consume SQL TLS identity")
        shape._integer(selected["connectTimeoutSeconds"], 300, minimum=2)
        for field in ("clientDn", "clientSerial", "issuerDn"):
            text = selected[field]
            if (type(text) is not str or not 1 <= len(text) <= 4096 or "\x00" in text
                    or work.prepare_utf8(text) > 4096):
                _fail("consume SQL TLS identity exceeds its exact text bound")
        # Only fixed literals and closed endpoint scalars enter this DSN. It
        # pins a future resource; it does not add consume to generic SQL.
        dsn = ("host=" + endpoint["host"] + " hostaddr=" + endpoint["hostaddr"]
            + " port=" + str(endpoint["port"]) + " dbname=" + endpoint["databaseName"]
            + " user=" + role + " sslmode=verify-full sslrootcert=" + TLS_PATHS["ca"]
            + " sslcert=" + TLS_PATHS[name + "Certificate"]
            + " sslkey=" + TLS_PATHS[name + "Key"]
            + " passfile=/dev/null gssencmode=disable")
        result.append((dsn, selected["connectTimeoutSeconds"], role, selected["clientDn"],
            selected["clientSerial"], selected["issuerDn"], payload["queryManifestDigest"],
            payload["structureManifestDigest"]))
    issuer, executor = roles["issuer"], roles["executor"]
    left = (issuer["clientDn"], issuer["clientSerial"], issuer["issuerDn"])
    right = (executor["clientDn"], executor["clientSerial"], executor["issuerDn"])
    work.prepare_comparison(left, right)
    if left == right:
        _fail("consume issuer and executor must have distinct root-pinned TLS identities")
    return tuple(result)


def _launch_shape(value, work):
    shape._object(value, _LAUNCH_FIELDS, "consume execution SQL launch")
    for field, expected in (("schema", LAUNCH_SCHEMA), ("processMode", PROCESS_MODE),
            ("listenerPath", LISTENER_PATH), ("journalDirectoryPath", JOURNAL_PATH)):
        shape._literal(value[field], expected)
    for field, expected in (("serviceUid", SERVICE_UID), ("serviceGid", SERVICE_GID),
            ("peerUid", PEER_UID), ("peerGid", PEER_GID), *_FD_FIELDS):
        shape._integer(value[field], 2**32 - 2, minimum=1)
        if value[field] != expected:
            _fail("consume SQL fixed launch scalar differs")
    descriptors = value["inheritedFileDescriptors"]
    shape._array(descriptors, len(INHERITED_DESCRIPTORS), "consume SQL descriptors")
    for descriptor in descriptors:
        shape._integer(descriptor, 1023, minimum=3)
    work.prepare_copy(INHERITED_DESCRIPTORS)
    plan._same(descriptors, list(INHERITED_DESCRIPTORS), work, "consume SQL exact descriptor inventory")
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for field in ("listenerSocketDevice", "listenerPathDevice", "journalDirectoryDevice"):
        shape._integer(value[field], 2**64 - 1)
    for field in ("listenerSocketInode", "listenerPathInode", "journalDirectoryInode"):
        shape._integer(value[field], 2**64 - 1, minimum=1)
    shape._integer(value["journalMaximumRecords"], attempts.storage.MAX_RECORDS, minimum=2)


def _payload_shape(payload, work):
    shape._object(payload, _PAYLOAD_FIELDS, "consume execution SQL payload")
    for field, expected in (("schema", PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("role", ROLE), ("operation", OPERATION), ("trustMode", "trusted-host-local")):
        shape._literal(payload[field], expected)
    shape.validate_identity_shape(payload["receiverIdentity"])
    for field in ("configurationDigest", "generationDigest", "runtimeClosureDigest",
            "beforeVectorDigest", "queryManifestDigest", "structureManifestDigest"):
        shape._digest(payload[field])
    authorization._token(payload["databaseId"])
    for name, maximum in _DETACHED_LIMITS:
        record = payload[name]
        shape._object(record, _DETACHED_FIELDS, "consume SQL detached original")
        shape._integer(record["byteCount"], maximum, minimum=2)
        shape._digest(record["bytesDigest"])
    for name, maximum in _ORIGINAL_LIMITS:
        record = payload[name]
        shape._object(record, _ORIGINAL_FIELDS, "consume SQL enrollment original")
        authorization.transport._transport_shape(record["base64Url"], record["byteCount"], maximum)
        shape._integer(record["byteCount"], maximum, minimum=2)
        shape._digest(record["bytesDigest"])
        shape._digest(record["identityDigest"])
    predecessor, pending, checkpoint = payload["statePredecessor"], payload["currentPending"], payload["attemptCheckpoint"]
    shape._object(predecessor, frozenset({"sequence", "headDigest", "nextFence"}), "independent consume predecessor")
    shape._object(pending, frozenset({"sequence", "headDigest", "fence"}), "independent consume current pending")
    shape._object(checkpoint, frozenset({"sequence", "headDigest"}), "independent consume attempt checkpoint")
    for selected in (predecessor, checkpoint):
        shape._integer(selected["sequence"], authorization.MAX_RECORDS)
        shape._digest(selected["headDigest"])
    shape._integer(predecessor["nextFence"], minimum=1)
    shape._integer(pending["sequence"], authorization.MAX_RECORDS, minimum=1)
    shape._digest(pending["headDigest"])
    shape._integer(pending["fence"], minimum=1)
    if predecessor["sequence"] == 0 and predecessor["nextFence"] != 1:
        _fail("consume SQL genesis predecessor requires fence one")
    if pending["sequence"] != predecessor["sequence"] + 1 or pending["fence"] != predecessor["nextFence"]:
        _fail("consume SQL independent pending and predecessor scopes disagree")
    _database_configurations(payload, work)
    shape._object(payload["tlsFiles"], frozenset(TLS_PATHS), "consume fixed SQL TLS originals")
    for name, maximum in TLS_LIMITS.items():
        record = payload["tlsFiles"][name]
        shape._object(record, _DETACHED_FIELDS, "consume SQL TLS original pin")
        shape._integer(record["byteCount"], maximum, minimum=MIN_TLS_BYTES)
        shape._digest(record["bytesDigest"])
    for suffix in ("Certificate", "Key"):
        left, right = (payload["tlsFiles"][role + suffix]["bytesDigest"] for role in ("issuer", "executor"))
        work.prepare_comparison(left, right)
        if left == right:
            _fail("consume issuer and executor TLS material purposes coincide")
    for field in ("issuedAtEpochNs", "expiresAtEpochNs"):
        shape._integer(payload[field], minimum=1)
    if not 0 < payload["expiresAtEpochNs"] - payload["issuedAtEpochNs"] <= MAX_RECEIPT_AGE_NS:
        _fail("consume SQL lifetime exceeds its original launch ceiling")
    if any(payload[field] is not False for field in _FALSE_FIELDS):
        _fail("consume SQL claims unsupported hardware or witness assurance")
    _launch_shape(payload["launch"], work)


def _configured_scope(configured, purpose_pins, work):
    roles = configured["roles"]
    shape._object(roles, frozenset(configuration._ROLE_NAMES), "consume SQL configured roles")
    forbidden = []
    for name in configuration._ROLE_NAMES:
        role = roles[name]
        for field in ("serviceUid", "serviceGid"):
            shape._integer(role[field], 2**32 - 2)
            if role[field] == SERVICE_UID:
                _fail("consume SQL identity is shared with a configured role")
        forbidden.append(role["responseSigningSpkiDigest"])
        if name in ("verifier", "planner"):
            forbidden.append(role["signingSpkiDigest"])
    for policy_module, slots in ((shared.evidence_policy, ("registration", "installation")),
            (shared.transition_policy, ("registration", "stage", "completion"))):
        value = configured.get(policy_module.FIELD)
        if value is not None:
            policy, _public_keys = policy_module._validate_policy_on_work(value,
                webauthn=configured["webauthn"], work=work)
            forbidden.extend(policy[name]["signingSpkiDigest"] for name in slots if policy[name] is not None)
    value = configured.get(shared.enrollment_policy.FIELD)
    if value is not None:
        policy, _public_key = shared.enrollment_policy._validate_policy_on_work(value, payload=configured, work=work)
        forbidden.append(policy["signingSpkiDigest"])
    work.prepare_scan(forbidden)
    for expected in purpose_pins:
        shape._digest(expected)
        for pin in forbidden:
            shape._digest(pin)
            work.prepare_comparison(expected, pin)
            if expected == pin:
                _fail("consume SQL caller/grant key is shared with another configured purpose")


def _admit_payload(payload, originals, root, window, bound, work, current):
    if MAX_BYTES + sum(len(raw) for raw in originals) + sum(
            payload[name]["byteCount"] for name, _ in _ORIGINAL_LIMITS) > receiving.MAX_ORIGINALS_BYTES:
        _fail("consume SQL original inventory exceeds its aggregate ceiling")
    for (name, _maximum), original in zip(_DETACHED_LIMITS, originals):
        current()
        record = payload[name]
        if len(original) != record["byteCount"]:
            _fail("consume SQL detached original byte count differs")
        plan._same(_digest(original, work), record["bytesDigest"], work, "consume SQL detached original digest")
        current()
    custody_raw, planner_raw, planning_raw, receiving_raw = originals
    custody = receiving._verify_sql_issuer_on_work(custody_bytes=custody_raw, planner_bootstrap_bytes=planner_raw,
        planner_history_custody_bytes=planning_raw, receiving_history_custody_bytes=receiving_raw,
        root_public_key=root, live_window=window, transport_deadline_ns=bound, work=work)
    current()
    for field, expected in (("consumerRole", receiving.SQL_ISSUER_CONSUMER_ROLE),
            ("processMode", PROCESS_MODE), ("serviceUid", SERVICE_UID), ("serviceGid", SERVICE_GID)):
        plan._same(custody.payload[field], expected, work, "consume SQL receiving purpose differs")
    admitted, configured = custody.planner, custody.planner.payload
    live = current
    for material in (custody, admitted, admitted.history_material, custody.history):
        if not material.attestation_interval[0] <= payload["issuedAtEpochNs"] < payload["expiresAtEpochNs"] <= material.attestation_interval[1]:
            _fail("consume SQL interval escapes an original current nested launch")
        live = shared._launch_guard(material.attestation_interval, material.opening_sample, live, work)
    live()
    for actual, expected in ((payload["receiverIdentity"], custody.receiver_identity),
            (payload["configurationDigest"], configured["configurationDigest"]),
            (payload["generationDigest"], configured["generation"]["digest"]),
            (payload["runtimeClosureDigest"], configured["runtimeClosureDigest"]),
            (payload["databaseId"], configured["databaseId"]),
            (payload["beforeVectorDigest"], admitted.complete_root_vector_digest),
            (payload["queryManifestDigest"], configured["configurationPayload"]["queryManifestDigest"])):
        plan._same(actual, expected, work, "consume SQL differs from genuine receiving scope")
    current_raw, grant_raw, caller_raw = _originals(payload, work, live)
    work.charge(input_bytes=len(current_raw) + len(admitted.state_enrollment_bytes))
    if current_raw != admitted.state_enrollment_bytes:
        _fail("consume SQL state enrollment differs from its original planner scope")
    enrolled = caller._admit_enrollment_on_work(authorization_enrollment_bytes=caller_raw,
        current_root_enrollment_bytes=current_raw, grant_enrollment_bytes=grant_raw,
        root_public_key=root, configuration_digest=payload["configurationDigest"],
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
        plan._same(actual, expected, work, "consume SQL differs from genuine purpose enrollment")
    _configured_scope(configured["configurationPayload"],
        (caller_policy["callerKey"]["spkiDigest"], grant.payload["authorizer"]["spkiDigest"]), work)
    predecessor, pending, checkpoint = payload["statePredecessor"], payload["currentPending"], payload["attemptCheckpoint"]
    maximum = payload["launch"]["journalMaximumRecords"]
    if maximum > policy["maxRecords"] or pending["sequence"] >= policy["maxRecords"] or checkpoint["sequence"] >= maximum:
        _fail("consume SQL scope has no enrolled completion or local attempt capacity")
    if predecessor["sequence"] == 0:
        plan._same(predecessor["headDigest"], current_material.enrollment_digest, work,
            "consume SQL independent predecessor genesis differs")
    if checkpoint["sequence"] == 0:
        plan._same(checkpoint["headDigest"], attempts._genesis_on_work(payload["structureManifestDigest"], work),
            work, "consume SQL attempt checkpoint differs from source/catalog genesis")
    launch = payload["launch"]
    directory = (launch["journalDirectoryDevice"], launch["journalDirectoryInode"])
    for previous in (configured["launch"], custody.history.planner.launch):
        if directory in ((previous["journalDirectoryDevice"], previous["journalDirectoryInode"]),
                (previous["executionStoreDirectoryDevice"], previous["executionStoreDirectoryInode"])):
            _fail("consume SQL attempt journal reuses an original or ciphertext-export directory")
    configurations = _database_configurations(payload, work)
    live()
    return custody, current_raw, grant_raw, caller_raw, enrolled, current_material, configurations, live


def _verify_on_work(*, bootstrap_bytes, custody_bytes, planner_bootstrap_bytes,
        planner_history_custody_bytes, receiving_history_custody_bytes, root_public_key, work,
        live_window=None, transport_deadline_ns=None):
    """Authenticate raw role/receiving originals before selecting resources."""
    try:
        original = authorization._original(bootstrap_bytes, MAX_BYTES, "consume SQL bootstrap")
        originals = _detached(custody_bytes, planner_bootstrap_bytes,
            planner_history_custody_bytes, receiving_history_custody_bytes)
        receiving._intake_reservation((16 * 1024, len(original), *map(len, originals)))
        root = root_public_key
        authorization._public(root)
        window, bound, inherited = _processing(live_window, transport_deadline_ns, work)
        inherited()
        envelope = codec._decode(original, work)
        shape._object(envelope, _ENVELOPE_FIELDS, "signed consume SQL bootstrap")
        shape._literal(envelope["schema"], SCHEMA)
        shape._base64url(envelope["signatureBase64Url"], signature=True)
        if type(envelope["payload"]) is not dict:
            _fail("consume SQL payload is not an exact object")
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
        current = shared._launch_guard(interval, opening, inherited, work)
        custody, current_raw, grant_raw, caller_raw, enrolled, current_material, configurations, live = _admit_payload(
            payload, originals, root, window, bound, work, current)
        admitted, configured = custody.planner, custody.planner.payload
        predecessor, pending, checkpoint = payload["statePredecessor"], payload["currentPending"], payload["attemptCheckpoint"]
        material = _SqlMaterial(bootstrap_bytes=original, custody_bytes=originals[0], custody_material=custody,
            receiver_identity=payload["receiverIdentity"], configuration_payload=configured["configurationPayload"],
            generation=configured["generation"], runtime_role_identities=configured["runtimeRoleIdentities"],
            configuration_digest=payload["configurationDigest"], runtime_closure_digest=payload["runtimeClosureDigest"],
            current_root_enrollment_bytes=current_raw, grant_enrollment_bytes=grant_raw,
            authorization_enrollment_bytes=caller_raw, planner_public_key=admitted.planner_public_key,
            operation_public_key=root, database_id=payload["databaseId"], generation_digest=payload["generationDigest"],
            enrollment_digest=current_material.enrollment_digest,
            maximum_authorization_age_ns=enrolled.payload["maximumAgeNs"],
            maximum_authorization_clock_skew_ns=enrolled.payload["maximumClockSkewNs"],
            before_vector_bytes=admitted.complete_root_vector_bytes, before_vector_digest=admitted.complete_root_vector_digest,
            state_predecessor=(predecessor["sequence"], predecessor["headDigest"], predecessor["nextFence"]),
            current_pending=(pending["sequence"], pending["headDigest"], pending["fence"]),
            attempt_checkpoint=(checkpoint["sequence"], checkpoint["headDigest"]),
            issuer_configuration=configurations[0], executor_configuration=configurations[1], tls_files=payload["tlsFiles"],
            attestation_interval=interval, opening_sample=opening, launch=payload["launch"],
            planner_bootstrap_bytes=originals[1], planner_history_custody_bytes=originals[2],
            receiving_history_custody_bytes=originals[3])
        codec._canonical(original, envelope, work)
        live()
        return material
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, OidcSessionActivationDeliveryExecutionSqlBootstrapError):
            raise
        raise OidcSessionActivationDeliveryExecutionSqlBootstrapError("consume SQL bootstrap admission failed") from exc


def _produce_on_work(*, payload, custody_bytes, planner_bootstrap_bytes, planner_history_custody_bytes,
        receiving_history_custody_bytes, root_private_key, root_public_key, work,
        live_window=None, transport_deadline_ns=None):
    """Sign independently established scope; never infer pending pins from ACKs."""
    try:
        originals = _detached(custody_bytes, planner_bootstrap_bytes,
            planner_history_custody_bytes, receiving_history_custody_bytes)
        private, root = root_private_key, root_public_key
        authorization._private(private)
        authorization._public(root)
        owned = configuration._ConfigurationCapture(capture._SharedLedger(work), maximum_bytes=MAX_BYTES).visit(payload)
        window, bound, inherited = _processing(live_window, transport_deadline_ns, work)
        inherited()
        _payload_shape(owned, work)
        interval = owned["issuedAtEpochNs"], owned["expiresAtEpochNs"]
        opening = _fresh(interval, work)
        current = shared._launch_guard(interval, opening, inherited, work)
        *_facts, live = _admit_payload(owned, originals, root, window, bound, work, current)
        unsigned = configuration._configuration_wire(owned, capture._SharedLedger(work))
        live()
        original = signing._sign(owned, SCHEMA, MAX_BYTES, private, root, work)
        codec._canonical(unsigned, owned, work)
        live()
        checked = codec._decode(original, work)
        shape._object(checked, _ENVELOPE_FIELDS, "signed consume SQL output")
        shape._literal(checked["schema"], SCHEMA)
        shape._base64url(checked["signatureBase64Url"], signature=True)
        _payload_shape(checked["payload"], work)
        plan._same(checked["payload"], owned, work, "consume SQL output payload changed")
        codec._canonical(original, checked, work)
        live()
        return original
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError, InvalidSignature) as exc:
        if isinstance(exc, OidcSessionActivationDeliveryExecutionSqlBootstrapError):
            raise
        raise OidcSessionActivationDeliveryExecutionSqlBootstrapError("consume SQL bootstrap production failed") from exc
