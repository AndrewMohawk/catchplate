"""Root-authenticated cold scope for the fixed registration SQL worker.

Configuration, runtime provenance, the current pending head, database/TLS
identity and the separate attempt journal checkpoint are independent root
assertions. Their signature neither observes currentness nor establishes that
two credentials reach the same database. Genuine configuration and original
purpose-enrollment admission still run on the caller's unchanged work.

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
import ipaddress
import re
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature

from serverware import control_plane_enrollment_bootstrap as codec
from serverware import current_root_state_bootstrap as state_bootstrap
from serverware import registration_evidence_signer_bootstrap as signing
from serverware import authority_registration_execution_authorization as caller
from serverware import authority_successor_execution_attempts as attempts
from serverware import authority_webauthn_enrollment_policy as enrollment_policy
from serverware import authority_webauthn_evidence_policy as evidence_policy


authority, configuration = codec.authority, codec.configuration
capability, capture, plan = codec.capability, codec.capture, codec.plan
authorization, grants, shape = caller.authorization, caller.grants, caller.shape
ROLE = PROCESS_MODE = "registration-execution-sql"
SERVICE_UID = SERVICE_GID = 65512
PEER_UID = PEER_GID = 65532
ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, JOURNAL_FD = 198, 199, 200, 201
INHERITED_DESCRIPTORS = (ROOT_FD, BOOTSTRAP_FD, LISTENER_FD, JOURNAL_FD)
LISTENER_PATH = "/run/serverware/registration-execution/sql.sock"
TLS_PATHS = {
    "ca": "/run/serverware/registration-sql-tls/ca.pem",
    "issuerCertificate": "/run/serverware/registration-sql-tls/issuer.crt",
    "issuerKey": "/run/serverware/registration-sql-tls/issuer.key",
    "executorCertificate": "/run/serverware/registration-sql-tls/executor.crt",
    "executorKey": "/run/serverware/registration-sql-tls/executor.key",
}
TLS_LIMITS = {name: (16 * 1024 if name in ("issuerKey", "executorKey") else 64 * 1024)
    for name in TLS_PATHS}
MIN_TLS_BYTES = 2
MAX_BYTES = 4 * 1024 * 1024
MAX_RECEIPT_AGE_NS = 300 * 1_000_000_000
SCHEMA = "serverware.signedRegistrationExecutionSqlBootstrap/v1"
PAYLOAD_SCHEMA = "serverware.registrationExecutionSqlBootstrap/v1"
LAUNCH_SCHEMA = "serverware.registrationExecutionSqlLaunch/v1"
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
_DATABASE_FIELDS = frozenset({"host", "hostaddr", "port", "databaseName"})
_SQL_ROLE_FIELDS = frozenset({"connectTimeoutSeconds", "clientDn", "clientSerial", "issuerDn"})
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.ASCII)
_DATABASE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}\Z", re.ASCII)


class RegistrationExecutionSqlBootstrapError(ValueError):
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
    evidence_public_key: object
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


def _address(value):
    if type(value) is not str or not 1 <= len(value) <= 45 or not value.isascii() or "%" in value:
        raise RegistrationExecutionSqlBootstrapError("SQL hostaddr is not one bounded literal address")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise RegistrationExecutionSqlBootstrapError("SQL hostaddr is not a literal address") from exc
    unwrapped = address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) else None
    checked = address if unwrapped is None else unwrapped
    if (str(address) != value or address.is_unspecified or address.is_multicast
            or checked.is_unspecified or checked.is_multicast
            or checked == ipaddress.IPv4Address("255.255.255.255")):
        raise RegistrationExecutionSqlBootstrapError("SQL address is not canonical concrete unicast")
    return address


def _database_shape(value):
    shape._object(value, _DATABASE_FIELDS, "fixed SQL database endpoint")
    host = value["host"]
    if type(host) is not str or not 1 <= len(host) <= 253 or not host.isascii():
        raise RegistrationExecutionSqlBootstrapError("SQL server name is not bounded ASCII")
    if ":" in host or re.fullmatch(r"[0-9.]+", host, re.ASCII) is not None:
        _address(host)
    elif any(_DNS_LABEL.fullmatch(label) is None for label in host.split(".")):
        raise RegistrationExecutionSqlBootstrapError("SQL server name is not canonical lowercase DNS")
    _address(value["hostaddr"])
    shape._integer(value["port"], 65535, minimum=1)
    name = value["databaseName"]
    if type(name) is not str or _DATABASE_NAME.fullmatch(name) is None:
        raise RegistrationExecutionSqlBootstrapError("SQL database name is outside the closed identifier profile")


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
                raise RegistrationExecutionSqlBootstrapError("SQL TLS identity exceeds its exact text bound")
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
    shape._object(value, _LAUNCH_FIELDS, "registration execution SQL launch")
    for name, expected in (("schema", LAUNCH_SCHEMA), ("processMode", PROCESS_MODE),
            ("listenerPath", LISTENER_PATH)):
        shape._literal(value[name], expected)
    for name, expected in (("serviceUid", SERVICE_UID), ("serviceGid", SERVICE_GID),
            ("peerUid", PEER_UID), ("peerGid", PEER_GID), ("rootPublicKeyFd", ROOT_FD),
            ("bootstrapFd", BOOTSTRAP_FD), ("listenerFd", LISTENER_FD),
            ("journalDirectoryFd", JOURNAL_FD)):
        shape._integer(value[name], 2**32 - 2, minimum=1)
        if value[name] != expected:
            raise RegistrationExecutionSqlBootstrapError("SQL fixed launch scalar differs")
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
    shape._object(payload, _PAYLOAD_FIELDS, "registration execution SQL bootstrap")
    for name, expected in (("schema", PAYLOAD_SCHEMA), ("sourceRevision", authority.SOURCE_REVISION),
            ("role", ROLE), ("trustMode", "trusted-host-local")):
        shape._literal(payload[name], expected)
    for name in ("configurationDigest", "generationDigest", "runtimeClosureDigest",
            "queryManifestDigest", "structureManifestDigest"):
        shape._digest(payload[name])
    authorization._token(payload["databaseId"])
    shape._object(payload["generation"], frozenset(configuration._GENERATION_FIELDS), "SQL generation")
    if type(payload["configurationPayload"]) is not dict or type(payload["runtimeRoleIdentities"]) is not dict:
        raise RegistrationExecutionSqlBootstrapError("SQL configuration and runtime are not exact data")
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
        raise RegistrationExecutionSqlBootstrapError("SQL launch lifetime exceeds its source bound")
    if any(payload[name] is not False for name in _FALSE_FIELDS):
        raise RegistrationExecutionSqlBootstrapError("SQL bootstrap is not trusted-host-local assurance")
    _launch_shape(payload["launch"], work)


def _fresh(interval, work, opening=None):
    """Check the original bounded epoch/monotonic bracket without renewal."""
    try:
        return state_bootstrap._fresh(interval, work, opening=opening)
    except (TypeError, ValueError, OverflowError) as exc:
        raise RegistrationExecutionSqlBootstrapError("SQL original launch interval is not live") from exc


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
    mapped = enrollment_policy._capture_on_work(payload=configured,
        configuration_digest=digest, generation=generation, runtime_role_identities=runtime, work=work)
    purposes, evidence_keys = evidence_policy._validate_policy_on_work(
        configured.get(evidence_policy.FIELD), webauthn=configured["webauthn"], work=work)
    if purposes["registration"] is None:
        raise RegistrationExecutionSqlBootstrapError("registration evidence purpose is disabled")
    roles = configured["roles"]
    shape._object(roles, frozenset(configuration._ROLE_NAMES), "SQL configured roles")
    forbidden = [mapped.policy["signingSpkiDigest"]]
    for name in configuration._ROLE_NAMES:
        role = roles[name]
        shape._integer(role["serviceUid"], 2**32 - 2)
        if role["serviceUid"] == SERVICE_UID:
            raise RegistrationExecutionSqlBootstrapError("SQL worker UID is shared with a configured role")
        shape._digest(role["responseSigningSpkiDigest"])
        forbidden.append(role["responseSigningSpkiDigest"])
        if name in ("verifier", "planner"):
            shape._digest(role["signingSpkiDigest"])
            forbidden.append(role["signingSpkiDigest"])
    planner = configuration._key(roles["planner"]["signingPublicKeyBase64Url"], work,
        expected_spki=roles["planner"]["signingSpkiDigest"])
    evidence_key = evidence_keys["registration"]
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
    for actual, expected in ((payload["currentRootEnrollment"]["identityDigest"], current.enrollment_digest),
            (payload["grantEnrollment"]["identityDigest"], grant.enrollment_digest),
            (payload["authorizationEnrollment"]["identityDigest"], admitted.enrollment_digest),
            (payload["databaseId"], enrolled["databaseId"]),
            (payload["generationDigest"], enrolled["generationDigest"]),
            (payload["generationDigest"], mapped.generation_digest),
            (payload["queryManifestDigest"], configured["queryManifestDigest"])):
        plan._same(actual, expected, work, "SQL bootstrap differs from genuine configuration or enrollment")
    # The actual caller verifier excludes root/current-root/grant/planner and
    # registration-evidence keys. Exclude the remaining configured purposes too.
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
            raise RegistrationExecutionSqlBootstrapError("SQL caller key reuses another configured purpose")
    pending, checkpoint = payload["currentPending"], payload["attemptCheckpoint"]
    maximum = payload["launch"]["journalMaximumRecords"]
    if (maximum > policy["maxRecords"] or pending["sequence"] >= policy["maxRecords"]
            or checkpoint["sequence"] > maximum):
        raise RegistrationExecutionSqlBootstrapError("SQL pending or attempt scope exceeds independent capacity")
    if checkpoint["sequence"] == 0:
        plan._same(checkpoint["headDigest"],
            attempts._genesis_on_work(payload["structureManifestDigest"], work), work,
            "SQL attempt checkpoint differs from genuine source-catalog genesis")
    issuer_config, executor_config = _database_configurations(payload, work)
    return _SqlMaterial(configured, generation, runtime, digest, current_raw, grant_raw,
        caller_raw, planner, evidence_key, enrolled["databaseId"], mapped.generation_digest,
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
            raise RegistrationExecutionSqlBootstrapError("SQL payload is not an exact object")
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
        if isinstance(exc, RegistrationExecutionSqlBootstrapError):
            raise
        raise RegistrationExecutionSqlBootstrapError("SQL bootstrap admission failed") from exc


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
        if isinstance(exc, RegistrationExecutionSqlBootstrapError):
            raise
        raise RegistrationExecutionSqlBootstrapError("SQL bootstrap production failed") from exc
