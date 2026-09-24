"""Private configured read-owner to original-byte revocation persistence.

This is not a public service or registry admission. Independently admitted keys,
identities, roots, clocks and reservation are still prerequisites. Actual source
manifest/identity admission, SQL and driver work retain their separate bounds;
they are not claimed as shared H/B/N work. All variable invocation graphs and
genuine production/replay use one remaining work object, never a new allowance.
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from serverware import authority_query_reads
from serverware import authority_revocation_persistence as persistence_module
from serverware import authority_revocation_retention as retention


_IDENTITY_ATTRIBUTES = (
    "database_role", "tls_client_dn", "tls_client_serial", "tls_issuer_dn",
    "session_identity_digest", "measurement_digest", "attestation_receipt_digest",
)
_CALL_CONTEXT = retention.production._CONTEXT_FIELDS - {
    "expectedPlannerIdentity", "expectedVerifierIdentity"}


def _validate_read_configuration(configuration):
    dsn, timeout, identity, private_key, persistence = configuration
    if (type(dsn) is not str or not 1 <= len(dsn) <= 65536
            or type(timeout) is not int or not 1 <= timeout <= 300
            or type(identity) is not tuple or len(identity) != 7
            or any(type(value) is not str or not 1 <= len(value) <= 4096
                   or "\x00" in value for value in identity[:4])
            or not isinstance(private_key, Ed25519PrivateKey)
            or type(persistence) is not persistence_module.RevocationPlannerPersistence):
        raise ValueError("revocation read-owner configuration is invalid")
    for value in identity[4:]:
        retention.plan.contract._digest(value)


class _ReadResult:
    """The actual driver's bounded fetches cannot change invocation work."""

    __slots__ = ("_result", "_work")

    def __init__(self, result, work):
        self._result, self._work = result, work

    def fetchone(self):
        return persistence_module.store._callback(self._work, self._result.fetchone)

    def fetchall(self):
        return persistence_module.store._callback(self._work, self._result.fetchall)

    def fetchmany(self, size):
        return persistence_module.store._callback(self._work, self._result.fetchmany, size)


class _ReadCursor:
    __slots__ = ("_cursor", "_work")

    def __init__(self, cursor, work):
        self._cursor, self._work = cursor, work

    def execute(self, sql, parameters=None):
        arguments = (sql,) if parameters is None else (sql, parameters)
        result = persistence_module.store._callback(self._work, self._cursor.execute, *arguments)
        return _ReadResult(result, self._work)


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class RevocationPlanningCoordinator:
    """Own the actual read transaction and only then open the separate writer.

    Configuration is fixed bounded data, validated again per invocation and
    captured before callbacks. An immutable tuple pins all six persistence
    settings across the read phase; frozen dataclasses alone are not custody.
    No request may supply replacement keys, identities, manifests or traces.
    """

    read_dsn: str
    connect_timeout_seconds: int
    _database_identity: tuple[str, ...]
    planner_private_key: Ed25519PrivateKey
    persistence: persistence_module.RevocationPlannerPersistence

    def __init__(self, *, read_dsn, database_identity, connect_timeout_seconds,
                 planner_private_key, persistence):
        # Lazy import deliberately preserves the real registry/startup gate.
        from serverware import authority_planner as planner

        if type(database_identity) is not planner.PlannerIdentity:
            raise ValueError("revocation read owner requires the exact planner identity type")
        identity = tuple(getattr(database_identity, name) for name in _IDENTITY_ATTRIBUTES)
        _validate_read_configuration((read_dsn, connect_timeout_seconds, identity,
                                      planner_private_key, persistence))
        for name, value in (
            ("read_dsn", read_dsn), ("connect_timeout_seconds", connect_timeout_seconds),
            ("_database_identity", identity), ("planner_private_key", planner_private_key),
            ("persistence", persistence),
        ):
            object.__setattr__(self, name, value)

    def _snapshot_configuration(self):
        if type(self) is not RevocationPlanningCoordinator:
            raise ValueError("revocation read owner requires an exact configuration type")
        configuration = (self.read_dsn, self.connect_timeout_seconds,
                         self._database_identity, self.planner_private_key, self.persistence)
        _validate_read_configuration(configuration)
        return configuration

    def produce_and_persist(self, *, request, evidence, context, planned_at_epoch_ns, work):
        retained, _ = self.produce_and_persist_with_cutoff(
            request=request, evidence=evidence, context=context,
            planned_at_epoch_ns=planned_at_epoch_ns, work=work)
        return retained

    def produce_and_persist_with_cutoff(self, *, request, evidence, context,
                                       planned_at_epoch_ns, work):
        """Return original custody plus the actual acquisition's database instant.

        This local immutable instant is not a current-clock attestation or an
        authenticated cross-role invocation. Callers must retain independent
        request/context expectations; the stored context cannot supply them.
        """
        read_dsn, timeout, identity, private_key, persistence = self._snapshot_configuration()
        configured = persistence._snapshot_configuration()
        if identity[4:] != configured[4]:
            raise ValueError("revocation read identity differs from the configured planner pin")
        if (type(request) is not dict or type(evidence) is not dict or type(context) is not dict
                or len(context) != len(_CALL_CONTEXT)
                or any(type(name) is not str or len(name) > 64 for name in context)
                or set(context) != _CALL_CONTEXT
                or type(planned_at_epoch_ns) is not int
                or not 1 <= planned_at_epoch_ns <= 2**63 - 1):
            raise ValueError("revocation read-owner inputs are not closed")
        retention.capture._SharedLedger(work)
        owned = authority_query_reads._CopyBudget(work).copy({
            "request": request, "evidence": evidence, "context": context})
        actual_context = {**owned["context"],
            "expectedPlannerIdentity": dict(zip(persistence_module._IDENTITY_FIELDS, configured[4])),
            "expectedVerifierIdentity": dict(zip(persistence_module._IDENTITY_FIELDS, configured[5]))}
        retention.production._validate_context(actual_context, work)
        if not actual_context["reservedAtEpochNs"] <= planned_at_epoch_ns < actual_context["deadlineEpochNs"]:
            raise ValueError("revocation planned timestamp is outside its reservation")

        from serverware import authority_planner as planner
        import psycopg
        from psycopg.rows import dict_row

        database_identity = planner.PlannerIdentity(*identity)
        operation = planner.authority_transition_webauthn.OPERATION
        kernel = planner.authority_transition_webauthn.WebAuthnCredentialRevokeKernel()
        program = planner.TypedTransitionPlanningProgram(
            operation=operation, handler=kernel.handler, kernel=kernel)
        trace = planner.PlannerTrace(operation=operation, _complete_queries=True)
        store = persistence_module.store
        connection = persistence_module._connect(work, lambda: psycopg.connect(read_dsn,
            row_factory=dict_row, connect_timeout=timeout, options="-c search_path=pg_catalog"))
        with store._context(connection, work):
            transaction = store._callback(work, connection.transaction)
            with store._context(transaction, work):
                cursor = store._callback(work, connection.cursor)
                with store._context(cursor, work) as active:
                    guarded = _ReadCursor(active, work)
                    guarded.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY DEFERRABLE")
                    planner._validate_database_identity(guarded, database_identity)
                    manifest, _ = planner._load_manifest(guarded, operation=operation, trace=trace)
                    authorization = planner._load_authorization_manifest(
                        guarded, operation=operation, trace=trace)
                    # These are actual source-validated DB manifests, not
                    # caller-supplied successful-validation/trace tokens.
                    produced = program._produce_revocation_plan(guarded,
                        request=owned["request"], evidence=owned["evidence"],
                        context=actual_context, manifest=manifest + authorization,
                        verifier_public_key=configured[3], planner_private_key=private_key,
                        planner_public_key=configured[2], query_work=work, trace=trace)
                    # Capture immutable originals before any read exit callback.
                    # Never recover external expectations from the signed output.
                    envelope_bytes = produced.signed.envelope_bytes
                    context_bytes = produced.evaluation_context_bytes
                    database_now = produced.database_now
                    if type(envelope_bytes) is not bytes or type(context_bytes) is not bytes:
                        raise ValueError("revocation producer lost original immutable bytes")
                    retention.plan._verification_types(configured[2], configured[3], database_now)

        # No writer connection can open until all three read scopes have exited
        # successfully. Any body/cleanup/meter failure above skips this suffix.
        expectations = {argument: owned["context"][name]
                        for name, argument in retention._CONTEXT_PAIRS if name in _CALL_CONTEXT}
        expectations.update(expected_request=owned["request"], database_now=database_now)
        retained = persistence_module._run_on_configuration(configured,
            store.persist_revocation_planner_record,
            {"envelope_bytes": envelope_bytes, "evaluation_context_bytes": context_bytes,
             "planned_at_epoch_ns": planned_at_epoch_ns}, expectations, work)
        return retained, database_now
