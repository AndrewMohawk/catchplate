"""One locally committed initialization candidate, never installation authority.

This storage prerequisite requires an independently supplied, already installed
enrollment. It has no enrollment, reset, generation handover, signing, anchor or
APPLIED operation. A committed local row is NOT a rollback-resistant decision.
Observed schema/ACL/session admission assumes trusted administrator stability;
physical separation, trusted enrollment, external latest head and purpose-specific
decision/materialization services remain required.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, fields, replace
from typing import Any

import psycopg
from psycopg import sql
from psycopg.pq import TransactionStatus
from psycopg.rows import dict_row

from serverware import authority_audit_capacity as capacity
from serverware import authority_audit_initialization_admission as admission
from serverware import authority_audit_initialization_postgres as reader
from serverware import authority_audit_initialization_signatures as signatures
from serverware import authority_transition_core as core
from serverware.authority_radix_mutation import PrimaryRoot
from serverware.authority_store.audit_initialization_store_sql import (
    CANDIDATES, ENROLLMENTS, MAX_ENROLLMENT_BYTES, MAX_RECORD_BYTES,
)
from serverware.authority_store import initialization_store_access as access
from serverware.authority_store import initialization_store_structure as structure


ENROLLMENT_SCHEMA = "serverware.metadataAuditInitializationStoreEnrollment/v1"
REQUEST_SCHEMA = "serverware.metadataAuditInitializationStoreRequest/v1"
CANDIDATE_SCHEMA = "serverware.metadataAuditInitializationStoredCandidate/v1"
LOCAL_STATE = "RECORDED_UNANCHORED"
_STATIC_BINDINGS = (
    "database_identity_digest", "database_generation_digest", "source_contract_digest",
    "schema_contract_digest", "initializer_measurement_digest", "initialization_ancestry_digest",
)


class LocalInitializationStoreError(ValueError):
    pass


class LocalInitializationConflict(LocalInitializationStoreError):
    pass


class LocalInitializationOutcomeUnknown(LocalInitializationStoreError):
    """Commit may have happened; use fresh exact lookup, never reset/reinsert."""


def _digest(value: Any) -> None:
    if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        raise LocalInitializationStoreError("local initialization digest is invalid")


def _integer(value: Any, minimum: int, maximum: int = capacity.MAX_INTEGER) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise LocalInitializationStoreError("local initialization integer is invalid")


def _canonical(value: Any, maximum: int = MAX_RECORD_BYTES) -> bytes:
    try:
        raw = capacity.canonical_audit_json(value)
    except (capacity.AuditCapacityError, ValueError, RecursionError) as exc:
        raise LocalInitializationStoreError("local initialization JSON is invalid") from exc
    if not 1 <= len(raw) <= maximum:
        raise LocalInitializationStoreError("local initialization document exceeds its byte bound")
    return raw


def _document(raw: bytes, maximum: int = MAX_RECORD_BYTES) -> dict[str, Any]:
    if type(raw) is not bytes or not 1 <= len(raw) <= maximum:
        raise LocalInitializationStoreError("local initialization stored bytes are invalid")
    try:
        value = json.loads(raw)
        if type(value) is not dict or _canonical(value, maximum) != raw:
            raise LocalInitializationStoreError("local initialization stored document is not canonical")
        return value
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise LocalInitializationStoreError("local initialization stored document is invalid") from exc


def _copy(kind, value):
    if type(value) is not kind:
        raise LocalInitializationStoreError("local initialization input has the wrong type")
    try:
        return kind(**{field.name: getattr(value, field.name) for field in fields(kind)})
    except (AttributeError, TypeError, ValueError) as exc:
        raise LocalInitializationStoreError("local initialization input is incomplete or invalid") from exc


def _trust(value: admission.AuditInitializationTrust) -> admission.AuditInitializationTrust:
    copied = _copy(admission.AuditInitializationTrust, value)
    return replace(copied,
        checkpoint_signer=_copy(signatures.InitializationSignerPin, copied.checkpoint_signer),
        authorization_signer=_copy(signatures.InitializationSignerPin, copied.authorization_signer))


def _trust_document(trust: admission.AuditInitializationTrust) -> dict[str, Any]:
    def pin(value):
        return {"role": value.role, "publicKeyDerHex": value.public_key_der.hex(),
            "authorityIdentityDigest": value.authority_identity_digest,
            "measurementDigest": value.measurement_digest,
            "attestationReceiptDigest": value.attestation_receipt_digest}
    return {"checkpointSigner": pin(trust.checkpoint_signer),
        "authorizationSigner": pin(trust.authorization_signer), "policyDigest": trust.policy_digest,
        "notBeforeEpochNs": trust.not_before_epoch_ns, "notAfterEpochNs": trust.not_after_epoch_ns,
        "maximumLifetimeNs": trust.maximum_lifetime_ns}


@dataclass(frozen=True, slots=True)
class LocalInitializationEnrollment:
    """Pinned local-store input representation, not authenticated enrollment."""

    database_identity_digest: str
    database_generation_digest: str
    generation_sequence: int
    generation_predecessor_digest: str | None
    backend_incarnation_digest: str
    source_contract_digest: str
    schema_contract_digest: str
    initializer_measurement_digest: str
    initialization_ancestry_digest: str
    trust: admission.AuditInitializationTrust

    def __post_init__(self) -> None:
        for name in (*_STATIC_BINDINGS, "backend_incarnation_digest"):
            _digest(getattr(self, name))
        _integer(self.generation_sequence, 1)
        if self.generation_sequence == 1:
            if self.generation_predecessor_digest is not None:
                raise LocalInitializationStoreError("first local enrollment generation has a predecessor")
        else:
            _digest(self.generation_predecessor_digest)
        object.__setattr__(self, "trust", _trust(self.trust))
        _canonical(self.json_projection(), MAX_ENROLLMENT_BYTES)

    def json_projection(self) -> dict[str, Any]:
        return {"schema": ENROLLMENT_SCHEMA, "databaseIdentityDigest": self.database_identity_digest,
            "databaseGenerationDigest": self.database_generation_digest,
            "generationSequence": self.generation_sequence,
            "generationPredecessorDigest": self.generation_predecessor_digest,
            "backendIncarnationDigest": self.backend_incarnation_digest,
            "counterIdentity": capacity.AGGREGATE_ID, "sourceContractDigest": self.source_contract_digest,
            "schemaContractDigest": self.schema_contract_digest,
            "initializerMeasurementDigest": self.initializer_measurement_digest,
            "initializationAncestryDigest": self.initialization_ancestry_digest,
            "trust": _trust_document(self.trust)}

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical(self.json_projection(), MAX_ENROLLMENT_BYTES)

    @property
    def digest(self) -> str:
        return core.framed_digest(ENROLLMENT_SCHEMA, self.canonical_bytes)


@dataclass(frozen=True, slots=True)
class StoreReadLimits:
    statement_timeout_ms: int
    lock_timeout_ms: int
    total_timeout_ms: int

    def __post_init__(self) -> None:
        for field in fields(self):
            _integer(getattr(self, field.name), 1, 86_400_000)


@dataclass(frozen=True, slots=True)
class StoredInitializationCandidate:
    """Immutable historical representation; construction verifies no authority."""

    canonical_bytes: bytes

    def __post_init__(self) -> None:
        value = _document(self.canonical_bytes)
        if (set(value) != {"schema", "state", "databaseIdentityDigest", "enrollmentDigest",
                "requestDigest", "predecessorHeadDigest", "localSequence", "request", "evidence",
                "installationPermitted"}
                or value["schema"] != CANDIDATE_SCHEMA or value["state"] != LOCAL_STATE
                or value["installationPermitted"] is not False
                or type(value["localSequence"]) is not int or value["localSequence"] != 1):
            raise LocalInitializationStoreError("local candidate representation is invalid")
        for name in ("databaseIdentityDigest", "enrollmentDigest", "requestDigest", "predecessorHeadDigest"):
            _digest(value[name])
        if (type(value["request"]) is not dict or type(value["evidence"]) is not dict
                or value["predecessorHeadDigest"] != value["enrollmentDigest"]):
            raise LocalInitializationStoreError("local candidate representation linkage is invalid")

    def json_projection(self) -> dict[str, Any]:
        return _document(self.canonical_bytes)

    @property
    def digest(self) -> str:
        return core.framed_digest(CANDIDATE_SCHEMA, self.canonical_bytes)


def _request(enrollment: LocalInitializationEnrollment, checkpoint: bytes, authorization: bytes) -> dict[str, Any]:
    # Bounds/type only, NOT signature admission. Historical lookup has no clock
    # and must not require fresh authority or unchanged metadata population.
    signatures.envelope_digest(checkpoint, role="checkpoint")
    signatures.envelope_digest(authorization, role="authorization")
    return {"schema": REQUEST_SCHEMA, "enrollmentDigest": enrollment.digest,
            "checkpointHex": checkpoint.hex(), "authorizationHex": authorization.hex()}


def _request_digest(request: dict[str, Any]) -> str:
    return core.framed_digest(REQUEST_SCHEMA, _canonical(request))


def _candidate(enrollment, request, evidence) -> StoredInitializationCandidate:
    return StoredInitializationCandidate(_canonical({"schema": CANDIDATE_SCHEMA,
        "state": LOCAL_STATE, "databaseIdentityDigest": enrollment.database_identity_digest,
        "enrollmentDigest": enrollment.digest, "requestDigest": _request_digest(request),
        "predecessorHeadDigest": enrollment.digest, "localSequence": 1,
        "request": request, "evidence": evidence.json_projection(), "installationPermitted": False}))


def _retained_evidence(enrollment, request, evidence) -> None:
    """Check archival v1 links, never re-admit history against current source.

    Original signer pins and signed bytes are retained cryptographic facts.
    Source revision, original verification time and preparation are historical
    data; no fresh policy, root/currentness, proof stream or expiry is admitted.
    """
    try:
        checkpoint_bytes = bytes.fromhex(request["checkpointHex"])
        authorization_bytes = bytes.fromhex(request["authorizationHex"])
        checkpoint = signatures.verify_initialization_envelope(checkpoint_bytes,
            role="checkpoint", pin=enrollment.trust.checkpoint_signer)
        authorization = signatures.verify_initialization_envelope(authorization_bytes,
            role="authorization", pin=enrollment.trust.authorization_signer)
        preparation = evidence["preparation"]
        verified_at = evidence["verifiedAtEpochNs"]
        _integer(verified_at, 0)
        if (type(preparation) is not dict
                or preparation["schema"] != "serverware.metadataAuditCapacityInitializationPreparation/v1"
                or preparation["installationPermitted"] is not False):
            raise LocalInitializationStoreError("local initialization retained preparation is invalid")
        preparation_digest = core.framed_digest(preparation["schema"], _canonical(preparation))
        checkpoint_digest = signatures.envelope_digest(checkpoint_bytes, role="checkpoint")
        expected = {"schema": "serverware.metadataAuditInitializationEvidence/v1",
            "checkpoint": checkpoint, "checkpointEnvelopeDigest": checkpoint_digest,
            "authorization": authorization,
            "authorizationEnvelopeDigest": signatures.envelope_digest(authorization_bytes, role="authorization"),
            "preparation": preparation, "preparationDigest": preparation_digest,
            "verifiedAtEpochNs": verified_at, "verificationBoundary": "pinned-signatures-and-local-recomputation",
            "installationPermitted": False}
        payload = authorization["payload"]
        checkpoint_payload = checkpoint["payload"]
        enrolled = enrollment.json_projection()
        if (_canonical(expected) != _canonical(evidence)
                or _canonical(checkpoint_payload["binding"]) != _canonical(payload["binding"])
                or any(payload["binding"][name] != enrolled[name] for name in (
                    "databaseIdentityDigest", "databaseGenerationDigest", "sourceContractDigest",
                    "schemaContractDigest", "initializerMeasurementDigest", "initializationAncestryDigest"))
                or checkpoint_payload["trustPolicyDigest"] != enrollment.trust.policy_digest
                or payload["trustPolicyDigest"] != enrollment.trust.policy_digest
                or checkpoint_payload["sourceRevision"] != preparation["sourceRevision"]
                or payload["sourceRevision"] != preparation["sourceRevision"]
                or checkpoint_payload["preparationProfile"] != preparation["profile"]
                or payload["preparationProfile"] != preparation["profile"]
                or payload["checkpointEnvelopeDigest"] != checkpoint_digest
                or payload["preparationDigest"] != preparation_digest
                or payload["counterRowDigest"] != preparation["counterRowDigest"]
                or _canonical(payload["afterRoots"]) != _canonical(preparation["afterRoots"])
                or _canonical(checkpoint_payload["beforeRoots"]) != _canonical(preparation["beforeRoots"])):
            raise LocalInitializationStoreError("local initialization retained evidence differs")
    except (KeyError, TypeError, ValueError) as exc:
        raise LocalInitializationStoreError("local initialization retained evidence is invalid") from exc


class _Session:
    def __init__(self, cursor, limits: StoreReadLimits, started: int):
        self.cursor, self.limits = cursor, limits
        self.deadline = started + limits.total_timeout_ms * 1_000_000

    def remaining_ms(self) -> int:
        remaining = self.deadline - time.monotonic_ns()
        if remaining <= 0:
            raise LocalInitializationStoreError("local initialization store exceeded its deadline")
        return max(1, (remaining + 999_999) // 1_000_000)

    def arm(self) -> None:
        remaining = self.remaining_ms()
        # SET, unlike a SELECT set_config call, does not establish the first
        # serializable snapshot before the initial relation locks. Identifiers
        # are source-owned and every literal is escaped by psycopg, never SQL
        # supplied by a request. Each command still needs the outer watchdog.
        settings = (("statement_timeout", str(min(remaining, self.limits.statement_timeout_ms)) + "ms"),
            ("lock_timeout", str(min(remaining, self.limits.lock_timeout_ms)) + "ms"),
            ("synchronous_commit", "on"), ("row_security", "off"), ("search_path", "pg_catalog"))
        for name, value in settings:
            self.cursor.execute(sql.SQL("SET LOCAL {} = {}").format(sql.Identifier(name), sql.Literal(value)))
            self.remaining_ms()

    def run(self, statement, parameters=None):
        self.arm()
        self.cursor.execute(statement, parameters)
        self.remaining_ms()
        return self.cursor


def _namespace(value: str) -> str:
    if type(value) is not str or re.fullmatch(r"[a-z][a-z0-9_]{0,62}", value) is None:
        raise LocalInitializationStoreError("local initialization store namespace is invalid")
    return value


def _operation(connection, limits, started, identity, callback):
    # A transaction context on INTRANS is only a savepoint. Never accept one.
    if (not isinstance(connection, psycopg.Connection) or connection.closed or connection.autocommit
            or connection.info.transaction_status != TransactionStatus.IDLE
            or not 160000 <= connection.info.server_version < 170000):
        raise LocalInitializationStoreError("local initialization store requires an idle PostgreSQL 16 connection")
    session = _Session(None, limits, started)
    session.remaining_ms()  # No transaction is started after an already expired preflight.
    committing = False
    try:
        with connection.transaction():
            with connection.cursor(row_factory=dict_row) as cursor:
                cursor.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ WRITE")
                session.cursor = cursor
                # SELECT privileges suffice. These locks precede the first
                # SELECT, but do not freeze GRANT/REVOKE or all privileged DDL.
                # Trusted administrator stability remains an explicit premise.
                session.run(sql.SQL("LOCK TABLE ONLY {}, ONLY {} IN ACCESS SHARE MODE").format(
                    sql.Identifier(identity.namespace, ENROLLMENTS), sql.Identifier(identity.namespace, CANDIDATES)))
                context = session.run(
                    "SELECT pg_catalog.current_setting('transaction_isolation') AS isolation, "
                    "pg_catalog.current_setting('transaction_read_only') AS read_only, "
                    "pg_catalog.getdatabaseencoding() AS encoding, "
                    "pg_catalog.current_setting('client_encoding') AS client_encoding, "
                    "pg_catalog.current_setting('fsync') AS fsync, "
                    "pg_catalog.current_setting('full_page_writes') AS full_page_writes, "
                    "pg_catalog.current_setting('synchronous_commit') AS synchronous_commit, "
                    "pg_catalog.pg_is_in_recovery() AS recovery").fetchone()
                expected = {"isolation": "serializable", "read_only": "off", "encoding": "UTF8",
                    "client_encoding": "UTF8", "fsync": "on", "full_page_writes": "on",
                    "synchronous_commit": "on", "recovery": False}
                if context is None or _canonical(context) != _canonical(expected):
                    raise LocalInitializationStoreError("local initialization store session is not admitted")
                access.admit_store_access(session, identity)
                structure.admit_store_structure(session, identity)
                result = callback(session)
                session.arm()  # Remaining deadline and local synchronous COMMIT policy.
            committing = True
        if connection.info.transaction_status != TransactionStatus.IDLE:
            raise LocalInitializationStoreError("local initialization store transaction did not finish")
        return result
    except BaseException as exc:
        # Do not reuse a handle after a failed transaction/uncertain acknowledgement.
        # Closing cannot retract a COMMIT that may already have happened.
        try:
            connection.close()
        except BaseException:
            pass
        if committing:
            raise LocalInitializationOutcomeUnknown(
                "local initialization commit outcome is unknown; use fresh exact lookup") from exc
        raise


def _existing(session, namespace, enrollment, request):
    rows = session.run(sql.SQL(
        "SELECT CASE WHEN pg_catalog.octet_length(enrollment_digest)=71 THEN enrollment_digest END AS enrollment_digest, "
        "head_sequence, CASE WHEN pg_catalog.octet_length(head_digest)=71 THEN head_digest END AS head_digest, "
        "CASE WHEN pg_catalog.octet_length(enrollment_bytes)<=%s THEN enrollment_bytes END AS enrollment_bytes "
        "FROM {} WHERE database_identity_digest=%s LIMIT 2 FOR UPDATE"
    ).format(sql.Identifier(namespace, ENROLLMENTS)),
        (MAX_ENROLLMENT_BYTES, enrollment.database_identity_digest)).fetchmany(2)
    if len(rows) != 1:
        raise LocalInitializationStoreError("local initialization enrollment is missing or duplicated")
    head = rows[0]
    if (head["enrollment_digest"] != enrollment.digest
            or type(head["enrollment_bytes"]) is not bytes or head["enrollment_bytes"] != enrollment.canonical_bytes
            or type(head["head_sequence"]) is not int or head["head_sequence"] not in (0, 1)):
        raise LocalInitializationStoreError("local initialization enrollment differs from its pin")
    _digest(head["head_digest"])
    records = session.run(sql.SQL(
        "SELECT CASE WHEN pg_catalog.octet_length(enrollment_digest)=71 THEN enrollment_digest END AS enrollment_digest, "
        "CASE WHEN pg_catalog.octet_length(request_digest)=71 THEN request_digest END AS request_digest, "
        "CASE WHEN pg_catalog.octet_length(candidate_digest)=71 THEN candidate_digest END AS candidate_digest, "
        "CASE WHEN pg_catalog.octet_length(candidate_bytes)<=%s THEN candidate_bytes END AS candidate_bytes "
        "FROM {} WHERE database_identity_digest=%s LIMIT 2"
    ).format(sql.Identifier(namespace, CANDIDATES)),
        (MAX_RECORD_BYTES, enrollment.database_identity_digest)).fetchmany(2)
    if head["head_sequence"] == 0:
        if records or head["head_digest"] != enrollment.digest:
            raise LocalInitializationStoreError("local initialization unused head is inconsistent")
        return None
    if len(records) != 1:
        raise LocalInitializationStoreError("local initialization recorded head lacks its candidate")
    row = records[0]
    candidate = StoredInitializationCandidate(row["candidate_bytes"])
    document = candidate.json_projection()
    stored_request = document["request"]
    if (row["enrollment_digest"] != enrollment.digest or document["enrollmentDigest"] != enrollment.digest
            or document["databaseIdentityDigest"] != enrollment.database_identity_digest
            or row["candidate_digest"] != candidate.digest or head["head_digest"] != candidate.digest
            or row["request_digest"] != _request_digest(stored_request)
            or document["requestDigest"] != row["request_digest"]):
        raise LocalInitializationStoreError("local initialization candidate and head commitments differ")
    if _canonical(stored_request) != _canonical(request):
        raise LocalInitializationConflict("local initialization enrollment already has a different candidate")
    _retained_evidence(enrollment, request, document["evidence"])
    session.remaining_ms()
    return candidate


def lookup_exact_local_initialization_candidate(
    store_connection: psycopg.Connection, checkpoint_bytes: bytes, authorization_bytes: bytes, *,
    enrollment: LocalInitializationEnrollment, store_limits: StoreReadLimits,
    store_identity: access.InitializationStoreDatabaseIdentity,
    namespace: str = "serverware_initialization",
) -> StoredInitializationCandidate | None:
    """Read exact retained local history without fresh signatures or metadata.

    None means only that the present pinned enrollment is locally unused, never
    fresh installation authority. Missing/crossed/inconsistent state denies.
    The dedicated idle store transaction is completed before returning; after
    transaction failure its connection is closed. No automatic retry occurs.
    """
    started = time.monotonic_ns()
    accepted = _copy(LocalInitializationEnrollment, enrollment)
    limits = _copy(StoreReadLimits, store_limits)
    namespace = _namespace(namespace)
    identity = _copy(access.InitializationStoreDatabaseIdentity, store_identity)
    if (identity.namespace != namespace
            or identity.backend_incarnation_digest != accepted.backend_incarnation_digest):
        raise LocalInitializationStoreError("local initialization database identity differs from enrollment")
    request = _request(accepted, checkpoint_bytes, authorization_bytes)
    return _operation(store_connection, limits, started, identity,
        lambda session: _existing(session, namespace, accepted, request))


def record_local_initialization_candidate(
    store_connection: psycopg.Connection, metadata_connection: psycopg.Connection,
    checkpoint_bytes: bytes, authorization_bytes: bytes, *, enrollment: LocalInitializationEnrollment,
    trust: admission.AuditInitializationTrust, expectation: admission.AuditInitializationExpectation,
    now_epoch_ns: int, expected_outbox_root: PrimaryRoot, expected_aggregate_root: PrimaryRoot,
    read_limits: reader.AuditInitializationReadLimits, store_limits: StoreReadLimits,
    store_identity: access.InitializationStoreDatabaseIdentity,
    namespace: str = "serverware_initialization", metadata_namespace: str = "serverware_metadata",
) -> StoredInitializationCandidate:
    """Commit one local candidate from real signed PostgreSQL verification.

    Fresh intent is preflighted before store SQL. Exact historical lookup after
    expiry uses the separate lookup function. An already retained exact request
    returns its original candidate without re-reading evolving metadata. A NEW
    candidate always invokes the actual signed database verifier, never accepts
    a caller-constructed Evidence object. Metadata transaction ownership stays
    with its caller; this function neither commits nor rolls it back.

    Store transaction acknowledgement establishes conditional LOCAL persistence
    only. This is not COMMIT_DECIDED, APPLIED, an anchor or permission to install.
    Observed catalog admission requires trusted administrator stability and is
    not an independent rollback/identity proof. An outer watchdog is required.
    After an ambiguous commit, keep writers fenced and use exact
    lookup on a fresh connection; never infer noncommit from local absence.
    """
    started = time.monotonic_ns()
    accepted = _copy(LocalInitializationEnrollment, enrollment)
    limits = _copy(StoreReadLimits, store_limits)
    reads = _copy(reader.AuditInitializationReadLimits, read_limits)
    accepted_trust, expected = admission.snapshot_audit_initialization_context(trust, expectation)
    outbox, aggregate = _copy(PrimaryRoot, expected_outbox_root), _copy(PrimaryRoot, expected_aggregate_root)
    namespace = _namespace(namespace)
    metadata_namespace = _namespace(metadata_namespace)
    identity = _copy(access.InitializationStoreDatabaseIdentity, store_identity)
    if (identity.namespace != namespace
            or identity.backend_incarnation_digest != accepted.backend_incarnation_digest):
        raise LocalInitializationStoreError("local initialization database identity differs from enrollment")
    if store_connection is metadata_connection:
        raise LocalInitializationStoreError("local initialization store and metadata connections must differ")
    if (accepted_trust != accepted.trust
            or any(getattr(expected, name) != getattr(accepted, name) for name in _STATIC_BINDINGS)):
        raise LocalInitializationStoreError("local initialization intent differs from pinned enrollment")
    admission.validate_audit_initialization_intent(checkpoint_bytes, authorization_bytes,
        trust=accepted_trust, expectation=expected, now_epoch_ns=now_epoch_ns,
        outbox_root=outbox, aggregate_root=aggregate)
    request = _request(accepted, checkpoint_bytes, authorization_bytes)

    def record(session):
        retained = _existing(session, namespace, accepted, request)
        if retained is not None:
            return retained
        bounded_reads = replace(reads, total_timeout_ms=min(reads.total_timeout_ms, session.remaining_ms()))
        evidence = reader.verify_audit_initialization_evidence_from_postgres(
            metadata_connection, checkpoint_bytes, authorization_bytes, trust=accepted_trust,
            expectation=expected, now_epoch_ns=now_epoch_ns, expected_outbox_root=outbox,
            expected_aggregate_root=aggregate, limits=bounded_reads, namespace=metadata_namespace)
        candidate = _candidate(accepted, request, evidence)
        session.run(sql.SQL(
            "INSERT INTO {} (database_identity_digest,enrollment_digest,request_digest,candidate_digest,candidate_bytes) "
            "VALUES (%s,%s,%s,%s,%s)"
        ).format(sql.Identifier(namespace, CANDIDATES)), (accepted.database_identity_digest,
            accepted.digest, _request_digest(request), candidate.digest, candidate.canonical_bytes))
        updated = session.run(sql.SQL(
            "UPDATE {} SET head_sequence=1,head_digest=%s "
            "WHERE database_identity_digest=%s AND enrollment_digest=%s AND head_sequence=0 AND head_digest=%s"
        ).format(sql.Identifier(namespace, ENROLLMENTS)),
            (candidate.digest, accepted.database_identity_digest, accepted.digest, accepted.digest))
        if updated.rowcount != 1:
            raise LocalInitializationConflict("local initialization head compare-and-swap failed")
        # Read back the real stored bytes/head inside the same transaction.
        if _existing(session, namespace, accepted, request) != candidate:
            raise LocalInitializationStoreError("local initialization candidate readback differs")
        return candidate

    return _operation(store_connection, limits, started, identity, record)
