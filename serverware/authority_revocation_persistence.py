"""Configured PostgreSQL coordinator for original revocation retention.

Separate from the closed legacy v3 coordinator and public service routes.
Configuration pins keys and identities; requests cannot replace those pins.
Persistence/read still genuinely verify original bytes with independent request,
historical clock and root expectations. Nothing here activates v4 execution.
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware import authority_revocation_retention as retention
from serverware.authority_store import revocation_retention as store


_CONFIGURED = frozenset({"planner_public_key", "verifier_public_key",
                        "expected_planner_identity", "expected_verifier_identity"})
_CALL_INPUTS = retention.wire._EXPECTATIONS - _CONFIGURED
_IDENTITY_FIELDS = ("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")


def _validate_configuration(configuration):
    """Admit fixed local custody, not key enrollment or a verification token."""
    if type(configuration) is not tuple or len(configuration) != 6:
        raise ValueError("revocation persistence configuration is not an exact six-tuple")
    dsn, timeout, planner_key, verifier_key, planner_identity, verifier_identity = configuration
    if (type(dsn) is not str or not 1 <= len(dsn) <= 65536
            or type(timeout) is not int or not 1 <= timeout <= 300
            or not isinstance(planner_key, Ed25519PublicKey)
            or not isinstance(verifier_key, Ed25519PublicKey)):
        raise ValueError("revocation persistence configuration is invalid")
    for identity in (planner_identity, verifier_identity):
        if type(identity) is not tuple or len(identity) != 3:
            raise ValueError("revocation persistence identity is not an exact triple")
        for digest in identity:
            retention.plan.contract._digest(digest)


def _inputs_from_configuration(configuration, expectations, work):
    _validate_configuration(configuration)
    if len(expectations) != len(_CALL_INPUTS) or set(expectations) != _CALL_INPUTS:
        raise ValueError("revocation persistence requires exactly fifteen external expectations")
    _, _, planner_key, verifier_key, planner_identity, verifier_identity = configuration
    pins = {"planner_public_key": planner_key, "verifier_public_key": verifier_key,
        "expected_planner_identity": dict(zip(_IDENTITY_FIELDS, planner_identity)),
        "expected_verifier_identity": dict(zip(_IDENTITY_FIELDS, verifier_identity))}
    return store._owned_expectations({**expectations, **pins}, work)


def _connect(work, opener):
    """Close a returned connection if its post-open work guard rejects it.

    Cleanup must still run with corrupted work and cannot suppress the original
    failure. An opener that raises before returning provides no handle to own.
    This does not broaden the separate context manager's entry guarantees.
    """
    connection = None

    def open_connection():
        nonlocal connection
        connection = opener()
        return connection

    try:
        return store._callback(work, open_connection)
    except BaseException:
        if connection is not None:
            try:
                connection.close()
            except BaseException:
                pass
        raise


def _run_on_configuration(configuration, operation, arguments, expectations, work):
    # The private combined read/write owner passes the same locally captured
    # tuple across both phases. Never recapture mutable coordinator slots here.
    owned = _inputs_from_configuration(configuration, expectations, work)
    dsn, timeout = configuration[:2]
    import psycopg
    from psycopg.rows import dict_row
    from serverware import db

    connection = _connect(work, lambda: psycopg.connect(dsn,
        row_factory=dict_row, connect_timeout=timeout, options="-c search_path=pg_catalog"))
    with store._context(connection, work):
        transaction = store._callback(work, connection.transaction)
        with store._context(transaction, work):
            cursor = store._callback(work, connection.cursor)
            with store._context(cursor, work) as active:
                store._callback(work, active.execute,
                    "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ WRITE NOT DEFERRABLE")
            result = operation(connection=db.PostgresMetadataConnection(connection),
                work=work, **arguments, **owned)
    return result


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class RevocationPlannerPersistence:
    """Independently configured keys, not keys enrolled by a retained record.

    Fixed bounded configuration is revalidated and captured once per invocation,
    outside JSON work. Each call owns its fifteen external inputs before any
    connection callback. The private six-tuple pins key handles, not mutable
    internals of arbitrary key implementations or independent provenance.
    Driver/transaction work is excluded from H/B/N but cannot alter the meter.
    This opens its own SERIALIZABLE writer transaction and commits only after
    the real store has completed; nested store rollback uses a real savepoint.
    """

    persistence_dsn: str
    connect_timeout_seconds: int
    planner_public_key: Ed25519PublicKey
    verifier_public_key: Ed25519PublicKey
    _planner_identity: tuple[str, str, str]
    _verifier_identity: tuple[str, str, str]

    def __init__(self, *, persistence_dsn, connect_timeout_seconds,
                 planner_public_key, verifier_public_key,
                 expected_planner_identity, expected_verifier_identity):
        if (type(persistence_dsn) is not str or not 1 <= len(persistence_dsn) <= 65536
                or type(connect_timeout_seconds) is not int or not 1 <= connect_timeout_seconds <= 300
                or not isinstance(planner_public_key, Ed25519PublicKey)
                or not isinstance(verifier_public_key, Ed25519PublicKey)):
            raise ValueError("revocation persistence configuration is invalid")
        retention.plan.contract.validate_identity_shape(expected_planner_identity)
        retention.plan.contract.validate_identity_shape(expected_verifier_identity)
        for name, value in (
            ("persistence_dsn", persistence_dsn), ("connect_timeout_seconds", connect_timeout_seconds),
            ("planner_public_key", planner_public_key), ("verifier_public_key", verifier_public_key),
            ("_planner_identity", tuple(expected_planner_identity[name] for name in _IDENTITY_FIELDS)),
            ("_verifier_identity", tuple(expected_verifier_identity[name] for name in _IDENTITY_FIELDS)),
        ):
            object.__setattr__(self, name, value)

    def _snapshot_configuration(self):
        if type(self) is not RevocationPlannerPersistence:
            raise ValueError("revocation persistence requires its exact configured owner")
        configuration = (self.persistence_dsn, self.connect_timeout_seconds,
            self.planner_public_key, self.verifier_public_key,
            self._planner_identity, self._verifier_identity)
        _validate_configuration(configuration)
        return configuration

    def _inputs(self, expectations, work):
        return _inputs_from_configuration(self._snapshot_configuration(), expectations, work)

    def _run(self, operation, arguments, expectations, work):
        return _run_on_configuration(self._snapshot_configuration(), operation, arguments, expectations, work)

    def persist(self, *, envelope_bytes, evaluation_context_bytes, planned_at_epoch_ns,
                work, **expectations):
        if type(envelope_bytes) is not bytes or type(evaluation_context_bytes) is not bytes:
            raise ValueError("revocation persistence accepts only original immutable bytes")
        if type(planned_at_epoch_ns) is not int or not 1 <= planned_at_epoch_ns <= 2**63 - 1:
            raise ValueError("revocation planned timestamp is not a positive int64")
        return self._run(store.persist_revocation_planner_record,
            {"envelope_bytes": envelope_bytes, "evaluation_context_bytes": evaluation_context_bytes,
             "planned_at_epoch_ns": planned_at_epoch_ns}, expectations, work)

    def read(self, *, planner_transaction_id, work, **expectations):
        retention.plan.contract._digest(planner_transaction_id)
        return self._run(store.read_revocation_planner_record,
            {"planner_transaction_id": planner_transaction_id}, expectations, work)

    def reserve_execution(self, *, envelope_id, planner_transaction_id, work, **expectations):
        """Genuine replay and private reservation share one writer transaction.

        This returns reserved data, not a capability or terminal receipt. It
        does not compose a separately committed historical read with a write.
        """
        from serverware.authority_store import revocation_execution

        retention.plan.contract._digest(envelope_id)
        retention.plan.contract._digest(planner_transaction_id)
        return self._run(revocation_execution.reserve_revocation_execution_envelope,
            {"envelope_id": envelope_id, "planner_transaction_id": planner_transaction_id},
            expectations, work)
