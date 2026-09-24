"""Private read-only observed planning, without writer credentials or custody.

The constructor and ownership boundary are inert. Actual planner/program and
driver imports occur only at the genuine read transaction boundary, preserving
the existing registry/startup gate. This owner never opens a writer, accepts a
successful proof token or persists a result. Independently admitted request,
roots, reservation, key/identity and historical clock provenance remain caller
and measured-service prerequisites.

One actual read body is shared with the existing combined coordinator. Variable
graphs and real production use the supplied remaining work. Metadata/source
admission, driver calls and fixed configuration scaffolding retain their own
bounds, not a whole-process H/B/N claim. Observed connection identity/status
cannot detect a hostile driver that commits and begins another transaction.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from serverware import authority_contract as authority
from serverware import authority_query_reads
from serverware import authority_revocation_observed as observed
from serverware import authority_revocation_retention as retention
from serverware import authority_revocation_root_reader as reader


_IDENTITY_FIELDS = ("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")
_CONFIGURED_CONTEXT = frozenset({"expectedPlannerIdentity", "expectedVerifierIdentity",
    "maximumAssertionAgeNs", "maximumPlanAgeNs", "maximumClockSkewNs"})
_CALL_CONTEXT = retention.production._CONTEXT_FIELDS - _CONFIGURED_CONTEXT - {"expectedBefore"}


class RevocationPlanningError(ValueError):
    pass


def _validate_read_configuration(configuration):
    # The shared body preserves the old coordinator's timeout-one admission.
    # Only the new independently configured owner requires libpq's real minimum.
    if type(configuration) is not tuple or len(configuration) != 4:
        raise RevocationPlanningError("observed planner read configuration is not an exact four-tuple")
    dsn, timeout, identity, private_key = configuration
    if (type(dsn) is not str or not 1 <= len(dsn) <= 65536
            or type(timeout) is not int or not 1 <= timeout <= 300
            or type(identity) is not tuple or len(identity) != 7
            or any(type(value) is not str or not 1 <= len(value) <= 4096
                   or "\x00" in value for value in identity[:4])
            or not isinstance(private_key, Ed25519PrivateKey)):
        raise RevocationPlanningError("observed planner read configuration is invalid")
    for digest in identity[4:]:
        retention.plan.contract._digest(digest)


def _validate_configuration(configuration):
    if type(configuration) is not tuple or len(configuration) != 10:
        raise RevocationPlanningError("observed planner configuration is not an exact ten-tuple")
    _validate_read_configuration(configuration[:4])
    if configuration[1] < 2:
        raise RevocationPlanningError("observed planner connection timeout is below libpq's minimum")
    if any(not isinstance(key, Ed25519PublicKey) for key in configuration[4:6]):
        raise RevocationPlanningError("observed planner requires pinned Ed25519 public keys")
    identity = configuration[6]
    if type(identity) is not tuple or len(identity) != 3:
        raise RevocationPlanningError("observed planner verifier identity is not an exact triple")
    for digest in identity:
        retention.plan.contract._digest(digest)
    for value in configuration[7:9]:
        retention.plan.contract._integer(value, minimum=1)
    retention.plan.contract._integer(configuration[9])
    if (configuration[8] > authority.VERIFIER_RESPONSE_MAX_AGE_NS
            or configuration[9] != authority.VERIFIER_MAX_CLOCK_SKEW_NS):
        raise RevocationPlanningError("observed planner historical policy differs from source bounds")


def _capture_planning_inputs(configuration, *, request, evidence, context, root_inventory, work):
    """Own the caller's nine fields and full inventory before any callback."""
    _validate_configuration(configuration)
    retention.capture._SharedLedger(work)
    if type(request) is not dict or type(evidence) is not dict:
        raise RevocationPlanningError("observed planner request and evidence are not exact objects")
    retention.plan.contract._object(context, _CALL_CONTEXT, "observed planner caller context")
    owned = authority_query_reads._CopyBudget(work).copy({
        "request": request, "evidence": evidence, "context": context})
    inventory = observed._capture_root_inventory(root_inventory, work=work)
    actual_context = {**owned["context"],
        "expectedPlannerIdentity": dict(zip(_IDENTITY_FIELDS, configuration[2][4:])),
        "expectedVerifierIdentity": dict(zip(_IDENTITY_FIELDS, configuration[6])),
        "maximumAssertionAgeNs": configuration[7], "maximumPlanAgeNs": configuration[8],
        "maximumClockSkewNs": configuration[9]}
    retention.plan.contract._request(owned["request"])
    observed._validate_partial_context(actual_context, work)
    return owned, actual_context, inventory


class _ReadResult:
    """Pin the returned result and cursor while guarding actual fetch getters."""

    __slots__ = ("_result", "_cursor", "_identity")

    def __init__(self, result, cursor):
        self._result, self._cursor = result, cursor
        self._identity = result, cursor

    def _call(self, method, *args):
        identity = self._identity
        if type(identity) is not tuple or len(identity) != 2:
            raise reader.roots.RevocationRootReadError("observed planner result binding is invalid")
        result, cursor = identity
        if self._result is not result or self._cursor is not cursor:
            raise reader.roots.RevocationRootReadError("observed planner result binding changed")
        value = cursor._call(lambda: getattr(result, method)(*args))
        if self._identity is not identity or self._result is not result or self._cursor is not cursor:
            raise reader.roots.RevocationRootReadError("observed planner result binding changed")
        return value

    def fetchone(self):
        return self._call("fetchone")

    def fetchall(self):
        return self._call("fetchall")

    def fetchmany(self, size):
        return self._call("fetchmany", size)


class _ReadCursor:
    """Require the already-entered planner transaction around every driver call."""

    __slots__ = ("_cursor", "_connection", "_raw", "_work", "_identity")

    def __init__(self, cursor, connection, raw_identity, work):
        self._cursor, self._connection, self._raw, self._work = cursor, connection, raw_identity, work
        self._identity = cursor, connection, raw_identity, work

    def _require(self, identity):
        if (self._identity is not identity or any(actual is not expected for actual, expected in zip(
                (self._cursor, self._connection, self._raw, self._work), identity))):
            raise reader.roots.RevocationRootReadError("observed planner cursor binding changed")

    def _call(self, callback):
        identity = self._identity
        if type(identity) is not tuple or len(identity) != 4:
            raise reader.roots.RevocationRootReadError("observed planner cursor binding is invalid")
        _, connection, raw, work = identity

        def invoke():
            self._require(identity)
            reader.roots._callback(work, reader._require_connection, connection, raw, 2)
            self._require(identity)
            value = callback()
            self._require(identity)
            reader.roots._callback(work, reader._require_connection, connection, raw, 2)
            self._require(identity)
            return value

        return reader.roots._callback(work, invoke)

    def execute(self, sql, parameters=None):
        arguments = (sql,) if parameters is None else (sql, parameters)
        cursor = self._cursor
        return _ReadResult(self._call(lambda: cursor.execute(*arguments)), self)


@dataclass(frozen=True, slots=True)
class _ProducedObservedPlanBytes:
    """Original output and independent history, not persistence or authority."""

    envelope_bytes: bytes
    evaluation_context_bytes: bytes
    database_now: datetime
    expected_context: dict


def _produce_on_read_configuration(read_configuration, *, planner_public_key, verifier_public_key,
                                   owned, actual_context, work, root_inventory=None):
    """One genuine read body shared by the old coordinator and read-only owner.

    All input/configuration ownership precedes this boundary. Lazy imports
    preserve the real planner registry gate. Role/TLS and manifest admission
    remain the actual planner checks; no new PG-major/session-role/ACL claim
    is inferred from setting the transaction's read-only mode.
    """
    _validate_read_configuration(read_configuration)
    retention.capture._SharedLedger(work)
    if (not isinstance(planner_public_key, Ed25519PublicKey)
            or not isinstance(verifier_public_key, Ed25519PublicKey)):
        raise RevocationPlanningError("observed planner public keys are not Ed25519")
    read_dsn, timeout, identity, private_key = read_configuration
    from serverware import authority_planner as planner
    import psycopg
    from psycopg.rows import dict_row

    database_identity = planner.PlannerIdentity(*identity)
    operation = planner.authority_transition_webauthn.OPERATION
    kernel = planner.authority_transition_webauthn.WebAuthnCredentialRevokeKernel()
    program = planner.TypedTransitionPlanningProgram(operation=operation, handler=kernel.handler, kernel=kernel)
    trace = planner.PlannerTrace(operation=operation, _complete_queries=True)
    connection = reader._connect(work, lambda: psycopg.connect(read_dsn,
        row_factory=dict_row, connect_timeout=timeout, options="-c search_path=pg_catalog"))
    try:
        raw = reader.roots._callback(work, reader._connection_identity, connection, 0)
        with reader._context(connection, work) as active_connection:
            if active_connection is not connection:
                raise reader.roots.RevocationRootReadError("observed planner connection context changed its handle")
            reader.roots._callback(work, reader._require_connection, connection, raw, 0)
            transaction = reader.roots._callback(work, lambda: connection.transaction())
            reader.roots._callback(work, reader._require_connection, connection, raw, 0)
            with reader._context(transaction, work):
                reader.roots._callback(work, reader._require_connection, connection, raw, 2)
                cursor = reader.roots._callback(work, lambda: connection.cursor())
                reader.roots._callback(work, reader._require_connection, connection, raw, 2)
                with reader._context(cursor, work) as active:
                    if active is not cursor:
                        raise reader.roots.RevocationRootReadError("observed planner cursor context changed its handle")
                    guarded = _ReadCursor(active, connection, raw, work)
                    guarded.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY DEFERRABLE")
                    planner._validate_database_identity(guarded, database_identity)
                    manifest, _ = planner._load_manifest(guarded, operation=operation, trace=trace)
                    authorization = planner._load_authorization_manifest(guarded, operation=operation, trace=trace)
                    if root_inventory is None:
                        produced = program._produce_revocation_plan(guarded,
                            request=owned["request"], evidence=owned["evidence"], context=actual_context,
                            manifest=manifest + authorization, verifier_public_key=verifier_public_key,
                            planner_private_key=private_key, planner_public_key=planner_public_key,
                            query_work=work, trace=trace)
                        expected_context = None
                    else:
                        produced = program._produce_observed_revocation_plan(guarded,
                            request=owned["request"], evidence=owned["evidence"],
                            context=actual_context, root_inventory=root_inventory,
                            manifest=manifest + authorization, verifier_public_key=verifier_public_key,
                            planner_private_key=private_key, planner_public_key=planner_public_key,
                            query_work=work, trace=trace)
                        expected_context = authority_query_reads._CopyBudget(work).copy(produced.expected_context)
                        retention.production._validate_context(expected_context, work)
                        retention.plan.semantics._canonical_equal(
                            {name: expected_context[name] for name in actual_context}, actual_context,
                            work=work, label="observed producer changed independent context pins")
                    envelope_bytes = produced.signed.envelope_bytes
                    context_bytes = produced.evaluation_context_bytes
                    database_now = produced.database_now
                    if type(envelope_bytes) is not bytes or type(context_bytes) is not bytes:
                        raise ValueError("revocation producer lost original immutable bytes")
                    retention.plan._verification_types(planner_public_key, verifier_public_key, database_now)
                    reader.roots._callback(work, reader._require_connection, connection, raw, 2)
                reader.roots._callback(work, reader._require_connection, connection, raw, 2)
            reader.roots._callback(work, reader._require_connection, connection, raw, 0)
        if reader.roots._callback(work, lambda: connection.closed) is not True:
            raise reader.roots.RevocationRootReadError("observed planner connection was not closed")
        return envelope_bytes, context_bytes, database_now, expected_context
    except BaseException:
        reader._close_after_failure(connection)
        raise


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class RevocationObservedPlanner:
    """Read-only configured producer; no writer owner or successful DTO input."""

    _configuration: tuple

    def __init__(self, *, read_dsn, connect_timeout_seconds, database_identity,
                 planner_private_key, planner_public_key, verifier_public_key,
                 expected_verifier_identity, maximum_assertion_age_ns,
                 maximum_plan_age_ns, maximum_clock_skew_ns):
        retention.plan.contract.validate_identity_shape(expected_verifier_identity)
        configuration = (read_dsn, connect_timeout_seconds, database_identity, planner_private_key,
            planner_public_key, verifier_public_key,
            tuple(expected_verifier_identity[name] for name in _IDENTITY_FIELDS),
            maximum_assertion_age_ns, maximum_plan_age_ns, maximum_clock_skew_ns)
        _validate_configuration(configuration)
        object.__setattr__(self, "_configuration", configuration)

    def _snapshot_configuration(self):
        if type(self) is not RevocationObservedPlanner:
            raise RevocationPlanningError("observed planner requires its exact configured owner")
        configuration = self._configuration
        _validate_configuration(configuration)
        return configuration

    def produce_observed(self, *, request, evidence, context, root_inventory, work):
        configuration = self._snapshot_configuration()
        owned, actual_context, inventory = _capture_planning_inputs(configuration,
            request=request, evidence=evidence, context=context, root_inventory=root_inventory, work=work)
        envelope, context_bytes, database_now, expected_context = _produce_on_read_configuration(
            configuration[:4], planner_public_key=configuration[4], verifier_public_key=configuration[5],
            owned=owned, actual_context=actual_context, work=work, root_inventory=inventory)
        return _ProducedObservedPlanBytes(envelope, context_bytes, database_now, expected_context)
