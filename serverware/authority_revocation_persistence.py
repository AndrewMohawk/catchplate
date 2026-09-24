"""Configured PostgreSQL coordinator for original revocation retention.

Separate from the legacy v3 coordinator and public service routes.
Configuration pins keys and identities; requests cannot replace those pins.
Persistence/read still genuinely verify original bytes with independent request,
historical clock and root expectations. Nothing here activates v4 execution.
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from serverware import authority_revocation_retention as retention
from serverware import authority_revocation_writer_connection as writer_connection
from serverware.authority_store import revocation_retention as store


_CONFIGURED = frozenset({"planner_public_key", "verifier_public_key",
                        "expected_planner_identity", "expected_verifier_identity"})
_CALL_INPUTS = retention.wire._EXPECTATIONS - _CONFIGURED
_IDENTITY_FIELDS = ("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")


def _validate_configuration(configuration):
    """Admit fixed local custody, not key enrollment or a verification token."""
    if type(configuration) is not tuple or len(configuration) != 7:
        raise ValueError("revocation persistence configuration is not an exact seven-tuple")
    dsn, timeout, planner_key, verifier_key, planner_identity, verifier_identity, database_identity = configuration
    if (type(dsn) is not str or not 1 <= len(dsn) <= 65536
            or any(character in dsn for character in ("\x00", "\n", "\r"))
            or type(timeout) is not int or not 2 <= timeout <= 300
            or not isinstance(planner_key, Ed25519PublicKey)
            or not isinstance(verifier_key, Ed25519PublicKey)):
        raise ValueError("revocation persistence configuration is invalid")
    try:
        if len(dsn.encode("utf-8")) > 65536:
            raise ValueError("revocation persistence DSN exceeds its byte bound")
    except UnicodeError as exc:
        raise ValueError("revocation persistence DSN is not Unicode") from exc
    for identity in (planner_identity, verifier_identity):
        if type(identity) is not tuple or len(identity) != 3:
            raise ValueError("revocation persistence identity is not an exact triple")
        for digest in identity:
            retention.plan.contract._digest(digest)
    writer_connection._validate_database_identity(database_identity)


def _inputs_from_configuration(configuration, expectations, work):
    _validate_configuration(configuration)
    if len(expectations) != len(_CALL_INPUTS) or set(expectations) != _CALL_INPUTS:
        raise ValueError("revocation persistence requires exactly fifteen external expectations")
    _, _, planner_key, verifier_key, planner_identity, verifier_identity = configuration[:6]
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
    # Preserve the actual facade/registry import gate before opening a socket.
    from serverware import db

    if configuration[6][0] != db._METADATA_STORE_AUTHORITY_PLANNER_WRITER_ROLE:
        raise ValueError("revocation writer role differs from the actual database contract")
    connection = _connect(work, lambda: psycopg.connect(dsn,
        row_factory=dict_row, connect_timeout=timeout, autocommit=False,
        options="-c search_path=pg_catalog"))
    return writer_connection._run_on_connection(connection,
        database_identity=configuration[6], work=work, operation=operation,
        arguments=arguments, expectations=owned)


def _retain_and_reserve_in_common(*, envelope_bytes, evaluation_context_bytes,
        planned_at_epoch_ns, envelope_id, planner_transaction_id, connection, raw, work,
        **expectations):
    """Two genuine replays inside the fixed caller's existing common scope.

    This helper opens no transaction and accepts no replacement operation.
    The first receipt never supplies reservation authority. Only after both
    calls may their ordinary outputs supply immutable custody linkage data.
    """
    from serverware.authority_store import revocation_execution

    store._callback(work, revocation_execution._same_connection, connection, raw)
    retained_receipt = store.persist_revocation_planner_record(
        envelope_bytes=envelope_bytes, evaluation_context_bytes=evaluation_context_bytes,
        planned_at_epoch_ns=planned_at_epoch_ns, connection=connection, work=work,
        **expectations)
    store._callback(work, revocation_execution._same_connection, connection, raw)
    execution_reservation = revocation_execution.reserve_revocation_execution_envelope(
        envelope_id=envelope_id, planner_transaction_id=planner_transaction_id,
        connection=connection, work=work, **expectations)
    store._callback(work, revocation_execution._same_connection, connection, raw)
    return retained_receipt, execution_reservation


def _persist_and_reserve_on_connection(*, envelope_bytes, evaluation_context_bytes,
        planned_at_epoch_ns, envelope_id, planner_transaction_id, connection, work,
        **expectations):
    """One real savepoint contains both original-byte custody operations.

    The configured runner owns every expectation before this private operation
    receives the actual facade. Each existing store still genuinely replays
    independently on the same work. The first receipt is output only: no field
    from it supplies the reservation's identity, bytes, clock or expectations.
    The common savepoint also protects a caller that catches either store's
    failure inside its still-open outer transaction. A rejection after that
    savepoint has released still relies on the configured outer owner's abort;
    a post-exit guard cannot undo the completed release. No failure is suppressed.
    """
    from serverware.authority_store import revocation_execution

    store._callback(work, store._transaction_connection, connection)
    raw = store._callback(work, store._require_planner_writer, connection)
    with store._context(store._callback(work, raw.transaction), work):
        result = _retain_and_reserve_in_common(
            envelope_bytes=envelope_bytes, evaluation_context_bytes=evaluation_context_bytes,
            planned_at_epoch_ns=planned_at_epoch_ns, envelope_id=envelope_id,
            planner_transaction_id=planner_transaction_id, connection=connection, raw=raw,
            work=work, **expectations)
    store._callback(work, revocation_execution._same_connection, connection, raw)
    return result


def _atomic_arguments_on_work(*, envelope_bytes,
        evaluation_context_bytes, planned_at_epoch_ns, envelope_id,
        planner_transaction_id, work, **expectations):
    """Shared original-byte bounds and charged independent-ID comparison.

    Return only fixed argument scaffolding, never admission or proof success.
    Both configured entries validate their held tuple before this preflight;
    their one real runner still owns the full external expectations afterward.
    """
    for raw, maximum in ((envelope_bytes, retention.plan.contract.MAX_PAYLOAD_BYTES),
                         (evaluation_context_bytes, retention.MAX_CONTEXT_BYTES)):
        if type(raw) is not bytes or not 2 <= len(raw) <= maximum:
            raise ValueError("atomic revocation custody requires source-bounded original bytes")
    if type(planned_at_epoch_ns) is not int or not 1 <= planned_at_epoch_ns <= 2**63 - 1:
        raise ValueError("atomic revocation planned timestamp is not a positive int64")
    retention.plan.contract._digest(envelope_id)
    retention.plan.contract._digest(planner_transaction_id)
    if (len(expectations) != len(_CALL_INPUTS)
            or any(type(name) is not str for name in expectations)
            or set(expectations) != _CALL_INPUTS):
        raise ValueError("atomic revocation custody requires exactly fifteen external expectations")
    expected_planner_transaction_id = expectations["expected_planner_transaction_id"]
    retention.plan.contract._digest(expected_planner_transaction_id)
    retention.capture._SharedLedger(work)
    retention.plan._same(planner_transaction_id, expected_planner_transaction_id, work,
        "atomic revocation planner transaction differs from its independent expectation")
    return {"envelope_bytes": envelope_bytes, "evaluation_context_bytes": evaluation_context_bytes,
        "planned_at_epoch_ns": planned_at_epoch_ns, "envelope_id": envelope_id,
        "planner_transaction_id": planner_transaction_id}


def _persist_and_reserve_on_configuration(configuration, *, envelope_bytes,
        evaluation_context_bytes, planned_at_epoch_ns, envelope_id,
        planner_transaction_id, work, **expectations):
    """Use one held configuration for the unchanged original atomic API."""
    _validate_configuration(configuration)
    arguments = _atomic_arguments_on_work(envelope_bytes=envelope_bytes,
        evaluation_context_bytes=evaluation_context_bytes, planned_at_epoch_ns=planned_at_epoch_ns,
        envelope_id=envelope_id, planner_transaction_id=planner_transaction_id,
        work=work, **expectations)
    return _run_on_configuration(configuration, _persist_and_reserve_on_connection,
        arguments, expectations, work)


def _persist_and_reserve_request_on_connection(*, intent_bytes, relay_bytes,
        historical_expectations_bytes, configuration_digest, generation_sequence,
        generation_digest, envelope_bytes, evaluation_context_bytes, planned_at_epoch_ns,
        envelope_id, planner_transaction_id, writer_private_key, writer_public_key,
        writer_response_spki_digest, connection, work, **expectations):
    """Exact request custody and both real replays share one common scope.

    Upstream fixed composition supplies genuinely authenticated originals and
    measured policy; this operation does not accept a successful-receiver DTO
    or claim to authenticate its ordinary local inputs independently. Existing
    rows are byte-compared before replay but never replace either replay. Only
    actual replay outputs supply final record/key links, not operation authority.
    The ACK is signed or verified only after that complete request readback.
    This private result remains inside the configured owner until outer and
    connection exits complete normally; exit uncertainty returns no ACK.
    """
    from serverware.authority_store import revocation_execution
    from serverware.authority_store import revocation_writer_request as request_store
    from serverware.authority_store import revocation_writer_acknowledgment as ack_store

    store._callback(work, store._transaction_connection, connection)
    raw = store._callback(work, store._require_planner_writer, connection)
    prefix = request_store._prefix_on_work(intent_bytes=intent_bytes, relay_bytes=relay_bytes,
        historical_expectations_bytes=historical_expectations_bytes,
        configuration_digest=configuration_digest, generation_sequence=generation_sequence,
        generation_digest=generation_digest, planned_at_epoch_ns=planned_at_epoch_ns,
        envelope_id=envelope_id, planner_transaction_id=planner_transaction_id, work=work)
    with store._context(store._callback(work, raw.transaction), work):
        store._callback(work, revocation_execution._same_connection, connection, raw)
        with store._context(store._callback(work, raw.cursor), work) as cursor:
            store._callback(work, revocation_execution._same_connection, connection, raw)
            existing = request_store._lookup(cursor, prefix, work)
            store._callback(work, revocation_execution._same_connection, connection, raw)
        store._callback(work, revocation_execution._same_connection, connection, raw)
        retained_receipt, execution_reservation = _retain_and_reserve_in_common(
            envelope_bytes=envelope_bytes, evaluation_context_bytes=evaluation_context_bytes,
            planned_at_epoch_ns=planned_at_epoch_ns, envelope_id=envelope_id,
            planner_transaction_id=planner_transaction_id, connection=connection, raw=raw,
            work=work, **expectations)
        with store._context(store._callback(work, raw.cursor), work) as cursor:
            store._callback(work, revocation_execution._same_connection, connection, raw)
            request_row = request_store._persist(cursor, prefix, retained_receipt, execution_reservation,
                work, insert=existing is None)
            store._callback(work, revocation_execution._same_connection, connection, raw)
            acknowledgment_bytes = ack_store._persist(cursor, request_row,
                writer_private_key=writer_private_key, writer_public_key=writer_public_key,
                writer_response_spki_digest=writer_response_spki_digest, work=work)
            store._callback(work, revocation_execution._same_connection, connection, raw)
        store._callback(work, revocation_execution._same_connection, connection, raw)
    store._callback(work, revocation_execution._same_connection, connection, raw)
    return retained_receipt, execution_reservation, acknowledgment_bytes


def _persist_and_reserve_request_on_configuration(configuration, *, intent_bytes,
        relay_bytes, historical_expectations_bytes, configuration_digest,
        generation_sequence, generation_digest, envelope_bytes, evaluation_context_bytes,
        planned_at_epoch_ns, envelope_id, planner_transaction_id, writer_private_key,
        writer_public_key, writer_response_spki_digest, work, **expectations):
    """Fixed authenticated composition suffix; no caller operation or opener.

    Original raw controls and independently held scalar pins are mandatory.
    These checks own no mutable control graph and manufacture no authentication.
    The actual service receiver and measured-policy check must precede this
    private call, and the real runner preserves registry/database admission.
    """
    from serverware import authority_revocation_writer_commitment as commitment

    _validate_configuration(configuration)
    arguments = _atomic_arguments_on_work(envelope_bytes=envelope_bytes,
        evaluation_context_bytes=evaluation_context_bytes, planned_at_epoch_ns=planned_at_epoch_ns,
        envelope_id=envelope_id, planner_transaction_id=planner_transaction_id,
        work=work, **expectations)
    commitment._raw(intent_bytes, commitment.MAX_CONTROL_BYTES)
    commitment._raw(relay_bytes, commitment.MAX_CONTROL_BYTES)
    commitment._raw(historical_expectations_bytes, commitment.MAX_HISTORY_BYTES)
    commitment._pins(configuration_digest, generation_sequence, generation_digest)
    commitment.plan.contract._digest(writer_response_spki_digest)
    if (not isinstance(writer_private_key, Ed25519PrivateKey)
            or not isinstance(writer_public_key, Ed25519PublicKey)):
        raise ValueError("revocation writer custody requires held Ed25519 response keys")
    # Fixed immutable argument scaffold; the runner captures all mutable
    # external expectations before its first database callback, as before.
    arguments.update(intent_bytes=intent_bytes, relay_bytes=relay_bytes,
        historical_expectations_bytes=historical_expectations_bytes,
        configuration_digest=configuration_digest, generation_sequence=generation_sequence,
        generation_digest=generation_digest, writer_private_key=writer_private_key,
        writer_public_key=writer_public_key, writer_response_spki_digest=writer_response_spki_digest)
    return _run_on_configuration(configuration, _persist_and_reserve_request_on_connection,
        arguments, expectations, work)


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class RevocationPlannerPersistence:
    """Independently configured keys, not keys enrolled by a retained record.

    Fixed bounded configuration is revalidated and captured once per invocation,
    outside JSON work. Each call owns its fifteen external inputs before any
    connection callback. The private seven-tuple pins key handles, not mutable
    internals of arbitrary key implementations or independent provenance.
    Its mandatory writer role/TLS identity is independent of the signed plan's
    planner/verifier identities. Connection admission checks the actual driver
    observations; configured strings alone do not enroll a database or CA.
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
    _database_identity: tuple[str, str, str, str]

    def __init__(self, *, persistence_dsn, connect_timeout_seconds,
                 planner_public_key, verifier_public_key,
                 expected_planner_identity, expected_verifier_identity,
                 writer_database_identity):
        retention.plan.contract.validate_identity_shape(expected_planner_identity)
        retention.plan.contract.validate_identity_shape(expected_verifier_identity)
        configuration = (persistence_dsn, connect_timeout_seconds,
            planner_public_key, verifier_public_key,
            tuple(expected_planner_identity[name] for name in _IDENTITY_FIELDS),
            tuple(expected_verifier_identity[name] for name in _IDENTITY_FIELDS),
            writer_database_identity)
        _validate_configuration(configuration)
        for name, value in (
            ("persistence_dsn", configuration[0]), ("connect_timeout_seconds", configuration[1]),
            ("planner_public_key", configuration[2]), ("verifier_public_key", configuration[3]),
            ("_planner_identity", configuration[4]), ("_verifier_identity", configuration[5]),
            ("_database_identity", configuration[6]),
        ):
            object.__setattr__(self, name, value)

    def _snapshot_configuration(self):
        if type(self) is not RevocationPlannerPersistence:
            raise ValueError("revocation persistence requires its exact configured owner")
        configuration = (self.persistence_dsn, self.connect_timeout_seconds,
            self.planner_public_key, self.verifier_public_key,
            self._planner_identity, self._verifier_identity, self._database_identity)
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

    def persist_and_reserve_execution(self, *, envelope_bytes, evaluation_context_bytes,
            planned_at_epoch_ns, envelope_id, planner_transaction_id, work, **expectations):
        """Retain and reserve atomically, without accepting a proof-result token.

        Immutable originals and independent identifiers are checked before the
        one configured runner owns the fifteen external expectations and opens
        its writer connection. The canonical ID join debits existing work;
        both actual replay costs remain separate. No timestamp is refreshed:
        retries preserve the original stored planned timestamp and bytes under
        the existing store rules, while reservation still checks live deadlines.
        The ordinary result pair is returned only after common/outer scopes and
        connection exit; a post-commit failure cannot promise rollback.
        """
        configuration = self._snapshot_configuration()
        return _persist_and_reserve_on_configuration(configuration,
            envelope_bytes=envelope_bytes, evaluation_context_bytes=evaluation_context_bytes,
            planned_at_epoch_ns=planned_at_epoch_ns, envelope_id=envelope_id,
            planner_transaction_id=planner_transaction_id, work=work, **expectations)

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
