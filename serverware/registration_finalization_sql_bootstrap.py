"""Root-authenticated cold scope for the fixed finalization SQL worker.

Configuration, runtime provenance, the current pending head, database/TLS
identity and the separate attempt journal checkpoint are independent root
assertions. Their signature neither observes currentness nor establishes that
two credentials reach the same database. Genuine configuration and original
purpose-enrollment admission still run on the caller's unchanged work.
The fixed finalization transition mapper supplies the actual planner and
operation-key pins; evidence-admission purpose authority is never substituted.

Only two fixed-purpose database TLS identities belong in this process: no
caller, grant, computation, completion or state signing key is delivered. The
closed connection strings select one literal address, verified server name,
database, role and fixed TLS files. The cold launcher must supply its literal
environment without PG* settings; unset libpq parameters can otherwise use
environment defaults. Independently provisioned PostgreSQL certificate-only
authentication remains necessary. No password or caller-selected DSN is input.

This module reads no TLS file, opens no connection or journal, and performs no
SQL, reservation or completion. Material is ordinary same-call data, not an
admission token. The original trusted-host-local launch interval never renews.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature

from serverware import control_plane_enrollment_bootstrap as codec
from serverware import current_root_state_bootstrap as state_bootstrap
from serverware import registration_evidence_signer_bootstrap as signing
from serverware import authority_registration_finalization_authorization as caller
from serverware import authority_successor_execution_attempts as attempts
from serverware import authority_webauthn_transition_custody_configuration as custody_configuration
# This helper validates only its explicit closed endpoint scalars. It selects
# no purpose, key, path, role, environment, signed material or admission result.
from serverware.registration_execution_sql_bootstrap import _database_shape
from serverware import authority_webauthn_enrollment_policy as enrollment_policy
from serverware import authority_webauthn_evidence_policy as evidence_policy
from serverware.authority_local_limits import LOCAL_SESSION_MAX_NS


authority, configuration = codec.authority, codec.configuration
capability, capture, plan = codec.capability, codec.capture, codec.plan
authorization, grants, shape = caller.authorization, caller.grants, caller.shape
ROLE = PROCESS_MODE = "registration-finalization-sql"
SERVICE_UID = SERVICE_GID = 65509
PEER_UID = PEER_GID = 65532
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, JOURNAL_FD = 198, 199, 200, 201
INHERITED_DESCRIPTORS = (ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, JOURNAL_FD)
LISTENER_PATH = "/run/serverware/registration-finalization/sql.sock"
TLS_PATHS = {
    "ca": "/run/serverware/registration-finalization-sql-tls/ca.pem",
    "issuerCertificate": "/run/serverware/registration-finalization-sql-tls/issuer.crt",
    "issuerKey": "/run/serverware/registration-finalization-sql-tls/issuer.key",
    "executorCertificate": "/run/serverware/registration-finalization-sql-tls/executor.crt",
    "executorKey": "/run/serverware/registration-finalization-sql-tls/executor.key",
}
TLS_LIMITS = {name: (16 * 1024 if name in ("issuerKey", "executorKey") else 64 * 1024)
    for name in TLS_PATHS}
MIN_TLS_BYTES = 2
MAX_BYTES = 4 * 1024 * 1024
MAX_RECEIPT_AGE_NS = LOCAL_SESSION_MAX_NS
SCHEMA = "serverware.signedRegistrationFinalizationSqlBootstrap/v1"
PAYLOAD_SCHEMA = "serverware.registrationFinalizationSqlBootstrap/v1"
LAUNCH_SCHEMA = "serverware.registrationFinalizationSqlLaunch/v1"
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
    "runtimeClosureDigest", "currentPending", "attemptCheckpoint", "databaseEndpoint",
    "sqlRoles", "queryManifestDigest", "structureManifestDigest", "tlsFiles",
    "issuedAtEpochNs", "expiresAtEpochNs", "trustMode", "launch", *_FALSE_FIELDS})
_LAUNCH_FIELDS = frozenset({"schema", "processMode", "serviceUid", "serviceGid", "peerUid",
    "peerGid", "rootPublicKeyFd", "bootstrapFd", "listenerFd", "journalDirectoryFd",
    "inheritedFileDescriptors", "listenerPath", "requestTimeoutSeconds",
    "journalDirectoryDevice", "journalDirectoryInode", "journalMaximumRecords",
    "listenerSocketDevice", "listenerSocketInode", "listenerPathDevice", "listenerPathInode"})
_SQL_ROLE_FIELDS = frozenset({"connectTimeoutSeconds", "clientDn", "clientSerial", "issuerDn"})


class RegistrationFinalizationSqlBootstrapError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _SqlMaterial:
    configuration_payload: dict
    generation: dict
    runtime_role_identities: dict
    configuration_digest: str
    current_root_enrollment_bytes: bytes
    grant_enrollment_bytes: bytes
    authorization_enrollment_bytes: bytes
    planner_public_key: object
    operation_public_key: object
    database_id: str
    generation_digest: str
    enrollment_digest: str
    runtime_closure_digest: str
    current_pending: tuple
    attempt_checkpoint: tuple
    issuer_configuration: tuple
    executor_configuration: tuple
    tls_files: dict
    attestation_interval: tuple
    opening_sample: tuple
    launch: dict


def _database_configurations(payload, work):
    endpoint = payload["databaseEndpoint"]
    _database_shape(endpoint)
    roles = payload["sqlRoles"]
    shape._object(roles, frozenset({"issuer", "executor"}), "fixed SQL roles")
    result = []
    for name, role in (("issuer", authority.SUCCESSOR_ISSUER_ROLE),
            ("executor", authority.SUCCESSOR_EXECUTOR_ROLE)):
        selected = roles[name]
        shape._object(selected, _SQL_ROLE_FIELDS, "fixed SQL role identity")
        shape._integer(selected["connectTimeoutSeconds"], 300, minimum=2)
        for field in ("clientDn", "clientSerial", "issuerDn"):
            text = selected[field]
            if (type(text) is not str or not 1 <= len(text) <= 4096 or "\x00" in text
                    or work.prepare_utf8(text) > 4096):
                raise RegistrationFinalizationSqlBootstrapError("SQL TLS identity exceeds its exact text bound")
        # All interpolated values are source-fixed or scalar-validated above:
        # no quoting, lists, URI expansion, service file, DNS or supplied DSN.
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
    shape._object(value, _LAUNCH_FIELDS, "registration finalization SQL launch")
    for name, expected in (("schema", LAUNCH_SCHEMA), ("processMode", PROCESS_MODE),
            ("listenerPath", LISTENER_PATH)):
        shape._literal(value[name], expected)
    for name, expected in (("serviceUid", SERVICE_UID), ("serviceGid", SERVICE_GID),
            ("peerUid", PEER_UID), ("peerGid", PEER_GID), ("rootPublicKeyFd", ROOT_FD),
            ("bootstrapFd", BOOTSTRAP_FD), ("listenerFd", LISTENER_FD),
            ("journalDirectoryFd", JOURNAL_FD)):
        shape._integer(value[name], 2**32 - 2, minimum=1)
        if value[name] != expected:
            raise RegistrationFinalizationSqlBootstrapError("SQL fixed launch scalar differs")
    descriptors = value["inheritedFileDescriptors"]
    shape._array(descriptors, len(INHERITED_DESCRIPTORS), "SQL inherited descriptors")
    for descriptor in descriptors:
        shape._integer(descriptor, 1023, minimum=3)
    plan._same(descriptors, list(INHERITED_DESCRIPTORS), work, "SQL descriptor inventory differs")
    shape._integer(value["requestTimeoutSeconds"], 30, minimum=1)
    for name in ("journalDirectoryDevice", "listenerSocketDevice", "listenerPathDevice"):
        shape._integer(value[name], 2**64 - 1)
    for name in ("journalDirectoryInode", "listenerSocketInode", "listenerPathInode"):
        shape._integer(value[name], 2**64 - 1, minimum=1)
    shape._integer(value["journalMaximumRecords"], authorization.MAX_RECORDS, minimum=2)


def _payload_shape(payload, work):
    shape._object(payload, _PAYLOAD_FIELDS, "registration finalization SQL bootstrap")
    for name, expected in (("schema", PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("role", ROLE), ("trustMode", "trusted-host-local")):
        shape._literal(payload[name], expected)
    for name in ("configurationDigest", "generationDigest", "runtimeClosureDigest",
            "queryManifestDigest", "structureManifestDigest"):
        shape._digest(payload[name])
    authorization._token(payload["databaseId"])
    shape._object(payload["generation"], frozenset(configuration._GENERATION_FIELDS), "SQL generation")
    if type(payload["configurationPayload"]) is not dict or type(payload["runtimeRoleIdentities"]) is not dict:
        raise RegistrationFinalizationSqlBootstrapError("SQL configuration and runtime are not exact data")
    for name, maximum in _ORIGINAL_LIMITS:
        record = payload[name]
        shape._object(record, _ORIGINAL_FIELDS, "SQL enrollment original")
        authorization.transport._transport_shape(record["base64Url"], record["byteCount"], maximum)
        shape._digest(record["bytesDigest"])
        shape._digest(record["identityDigest"])
    pending = payload["currentPending"]
    shape._object(pending, frozenset({"sequence", "headDigest", "fence"}), "independent SQL pending scope")
    shape._integer(pending["sequence"], authorization.MAX_RECORDS, minimum=1)
    shape._digest(pending["headDigest"])
    shape._integer(pending["fence"], minimum=1)
    checkpoint = payload["attemptCheckpoint"]
    shape._object(checkpoint, frozenset({"sequence", "headDigest"}), "independent SQL attempt checkpoint")
    shape._integer(checkpoint["sequence"], authorization.MAX_RECORDS)
    shape._digest(checkpoint["headDigest"])
    _database_configurations(payload, work)
    shape._object(payload["tlsFiles"], frozenset(TLS_PATHS), "SQL fixed TLS originals")
    for name, maximum in TLS_LIMITS.items():
        record = payload["tlsFiles"][name]
        shape._object(record, frozenset({"byteCount", "bytesDigest"}), "SQL TLS original pin")
        shape._integer(record["byteCount"], maximum, minimum=MIN_TLS_BYTES)
        shape._digest(record["bytesDigest"])
    for name in ("issuedAtEpochNs", "expiresAtEpochNs"):
        shape._integer(payload[name], minimum=1)
    if not 0 < payload["expiresAtEpochNs"] - payload["issuedAtEpochNs"] <= MAX_RECEIPT_AGE_NS:
        raise RegistrationFinalizationSqlBootstrapError("SQL launch lifetime exceeds its source bound")
    if any(payload[name] is not False for name in _FALSE_FIELDS):
        raise RegistrationFinalizationSqlBootstrapError("SQL bootstrap is not trusted-host-local assurance")
    _launch_shape(payload["launch"], work)


def _fresh(interval, work, opening=None):
    """Check the original bounded epoch/monotonic bracket without renewal."""
    try:
        return state_bootstrap._fresh(interval, work, opening=opening)
    except (TypeError, ValueError, OverflowError) as exc:
        raise RegistrationFinalizationSqlBootstrapError("SQL original launch interval is not live") from exc


def _originals(payload, work):
    originals = []
    for name, maximum in _ORIGINAL_LIMITS:
        record = payload[name]
        raw = authorization.transport._decode(record["base64Url"], record["byteCount"], maximum, work)
        work.charge(hashes=1, input_bytes=len(raw))
        plan._same("sha256:" + hashlib.sha256(raw).hexdigest(), record["bytesDigest"], work,
            "SQL enrollment original bytes differ from their root pin")
        originals.append(raw)
    return tuple(originals)


def _material(payload, root_key, opening, work):
    configured, generation, runtime = (payload["configurationPayload"],
        payload["generation"], payload["runtimeRoleIdentities"])
    digest = payload["configurationDigest"]
    mapped = custody_configuration._capture_on_work(operation=caller.OPERATION,
        payload=configured, configuration_digest=digest, generation=generation,
        runtime_role_identities=runtime, work=work)
    roles = configured["roles"]
    shape._object(roles, frozenset(configuration._ROLE_NAMES), "SQL configured roles")
    forbidden = []
    for name in configuration._ROLE_NAMES:
        role = roles[name]
        shape._integer(role["serviceUid"], 2**32 - 2)
        shape._integer(role["serviceGid"], 2**32 - 2)
        if role["serviceUid"] == SERVICE_UID or role["serviceGid"] == SERVICE_GID:
            raise RegistrationFinalizationSqlBootstrapError("SQL worker identity is shared with a configured role")
        shape._digest(role["responseSigningSpkiDigest"])
        forbidden.append(role["responseSigningSpkiDigest"])
        if name in ("verifier", "planner"):
            shape._digest(role["signingSpkiDigest"])
            forbidden.append(role["signingSpkiDigest"])
    planner, operation_key = mapped.pins[1], mapped.pins[4]
    current_raw, grant_raw, caller_raw = _originals(payload, work)
    admitted = caller._admit_enrollment_on_work(authorization_enrollment_bytes=caller_raw,
        current_root_enrollment_bytes=current_raw, grant_enrollment_bytes=grant_raw,
        root_public_key=root_key, configuration_digest=digest,
        planner_public_key=planner, evidence_public_key=operation_key, work=work)
    current = authorization._admit_enrollment_on_work(enrollment_bytes=current_raw,
        root_public_key=root_key, work=work)
    grant = grants._admit_enrollment_on_work(grant_enrollment_bytes=grant_raw,
        current_root_enrollment_bytes=current_raw, root_public_key=root_key, work=work)
    enrolled, policy = admitted.payload, current.payload
    for actual, expected in ((payload["currentRootEnrollment"]["identityDigest"], current.enrollment_digest),
            (payload["grantEnrollment"]["identityDigest"], grant.enrollment_digest),
            (payload["authorizationEnrollment"]["identityDigest"], admitted.enrollment_digest),
            (payload["databaseId"], enrolled["databaseId"]),
            (payload["generationDigest"], enrolled["generationDigest"]),
            (payload["generationDigest"], mapped.generation_digest),
            (payload["queryManifestDigest"], configured["queryManifestDigest"])):
        plan._same(actual, expected, work, "SQL bootstrap differs from genuine configuration or enrollment")
    # The genuine finalization caller verifier already excludes the actual
    # root/current-root/grant/planner/operation keys. Also reject reuse of
    # optional enrollment/evidence and every configured transition purpose.
    # Their absence is not an evidence-purpose fallback or admission shortcut.
    issuer_policy = configured.get(enrollment_policy.FIELD)
    if issuer_policy is not None:
        issuer, _issuer_key = enrollment_policy._validate_policy_on_work(
            issuer_policy, payload=configured, work=work)
        forbidden.append(issuer["signingSpkiDigest"])
    evidence_purposes = configured.get(evidence_policy.FIELD)
    if evidence_purposes is not None:
        purposes, _evidence_keys = evidence_policy._validate_policy_on_work(
            evidence_purposes, webauthn=configured["webauthn"], work=work)
        for name in ("registration", "installation"):
            if purposes[name] is not None:
                forbidden.append(purposes[name]["signingSpkiDigest"])
    transitions = configured.get(enrollment_policy.transition_policy.FIELD)
    if transitions is not None:
        for name in ("registration", "stage", "completion"):
            if transitions[name] is not None:
                forbidden.append(transitions[name]["signingSpkiDigest"])
    work.prepare_scan(forbidden)
    caller_pin = enrolled["callerKey"]["spkiDigest"]
    for pin in forbidden:
        work.prepare_comparison(caller_pin, pin)
        if caller_pin == pin:
            raise RegistrationFinalizationSqlBootstrapError("SQL caller key reuses another configured purpose")
    pending, checkpoint = payload["currentPending"], payload["attemptCheckpoint"]
    maximum = payload["launch"]["journalMaximumRecords"]
    if (maximum > policy["maxRecords"] or pending["sequence"] >= policy["maxRecords"]
            or checkpoint["sequence"] > maximum):
        raise RegistrationFinalizationSqlBootstrapError("SQL pending or attempt scope exceeds independent capacity")
    if checkpoint["sequence"] == 0:
        plan._same(checkpoint["headDigest"],
            attempts._genesis_on_work(payload["structureManifestDigest"], work), work,
            "SQL attempt checkpoint differs from genuine source-catalog genesis")
    issuer_config, executor_config = _database_configurations(payload, work)
    return _SqlMaterial(configured, generation, runtime, digest, current_raw, grant_raw,
        caller_raw, planner, operation_key, enrolled["databaseId"], mapped.generation_digest,
        current.enrollment_digest, payload["runtimeClosureDigest"],
        (pending["sequence"], pending["headDigest"], pending["fence"]),
        (checkpoint["sequence"], checkpoint["headDigest"]), issuer_config, executor_config,
        payload["tlsFiles"], (payload["issuedAtEpochNs"], payload["expiresAtEpochNs"]),
        opening, payload["launch"])


def _verify_on_work(*, bootstrap_bytes, root_public_key, work):
    """Authenticate exact root originals before any cold resource selection."""
    try:
        ledger = capture._SharedLedger(work)
        original = authorization._original(bootstrap_bytes, MAX_BYTES, "SQL bootstrap")
        root = root_public_key
        authorization._public(root)
        envelope = codec._decode(original, work)
        shape._object(envelope, _ENVELOPE_FIELDS, "SQL signed bootstrap")
        shape._literal(envelope["schema"], SCHEMA)
        shape._base64url(envelope["signatureBase64Url"], signature=True)
        if type(envelope["payload"]) is not dict:
            raise RegistrationFinalizationSqlBootstrapError("SQL payload is not an exact object")
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
        if isinstance(exc, RegistrationFinalizationSqlBootstrapError):
            raise
        raise RegistrationFinalizationSqlBootstrapError("SQL bootstrap admission failed") from exc


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
        if isinstance(exc, RegistrationFinalizationSqlBootstrapError):
            raise
        raise RegistrationFinalizationSqlBootstrapError("SQL bootstrap production failed") from exc
