"""Configured custody of four original successor-transition plan records.

The inert owner holds one writer endpoint and one operation's independently
admitted public-key/configuration policy. Each call owns its independent five
expectations before key or connection callbacks. Current configuration and
copied stored context cannot enroll historical key, request, root or invocation
authority. The fixed store must genuinely replay every original on the same
work, even for an identical retry or historical read.

The real writer connection owner admits PostgreSQL 16, SERIALIZABLE/TLS/role
and exact ACLs, then owns the outer transaction and closed connection. Results
escape only after their normal exits. Persistence retains original absolute
deadlines; historical reads sample no new clock. An uncertain outer exit is
not rollback proof. There is no signer, automatic retry, public operation hook,
business execution or replacement work allowance.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_revocation_root_reader as reader
from serverware import authority_revocation_writer_connection as writer
from serverware import authority_webauthn_transition_plan_admission as admission
from serverware import authority_webauthn_transition_retention as retention
from serverware.authority_store import webauthn_transition_retention as store


evidence = admission.evidence


class WebAuthnTransitionPersistenceError(ValueError):
    pass


def _configuration(values):
    """Validate the exact immutable database3 + independently admitted pins7."""
    if type(values) is not tuple or len(values) != 10:
        raise WebAuthnTransitionPersistenceError("transition persistence configuration is not exact")
    dsn, timeout, database = values[:3]
    reader._bounded_text(dsn, 65536)
    if "\n" in dsn or "\r" in dsn or type(timeout) is not int or not 2 <= timeout <= 300:
        raise WebAuthnTransitionPersistenceError("transition persistence connection settings are invalid")
    writer._validate_database_identity(database)
    admission._validate_pins(values[3:])
    return values


def _snapshot(owner):
    if type(owner) is not TransitionPlanPersistence:
        raise WebAuthnTransitionPersistenceError("transition persistence owner type changed")
    return _configuration(owner._configured)


def _connect(configured, work, psycopg, dict_row):
    connection = None

    def open_connection():
        nonlocal connection
        connection = psycopg.connect(configured[0], row_factory=dict_row,
            connect_timeout=configured[1], autocommit=False, options="-c search_path=pg_catalog")
        return connection

    try:
        # Lookup and call are inside the real finally-preserving work guard.
        # Retain cleanup custody even if the returned callback poisons work.
        return evidence.production._callback(work, open_connection)
    except BaseException:
        if connection is not None:
            reader._close_after_failure(connection)
        raise


def _run(configured, arguments, expectations, *, persist, work):
    # Preserve the actual facade's normal registry/startup gate before sockets.
    from serverware import db
    import psycopg
    from psycopg.rows import dict_row

    if configured[2][0] != db._METADATA_STORE_AUTHORITY_PLANNER_WRITER_ROLE:
        raise WebAuthnTransitionPersistenceError("transition writer role differs from the actual database contract")
    fixed_operation = (store.persist_webauthn_transition_plan_record if persist
        else store.read_webauthn_transition_plan_record)
    pins = configured[3:]
    fixed = {"expectations": expectations, "planner_public_key": pins[1],
        "operation_public_key": pins[4]}
    connection = _connect(configured, work, psycopg, dict_row)
    return writer._run_on_connection(connection, database_identity=configured[2],
        work=work, operation=fixed_operation, arguments=arguments, expectations=fixed)


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class TransitionPlanPersistence:
    """One source-fixed operation, protected writer endpoint and public pins."""

    _configured: tuple

    def __init__(self, *, writer_dsn, connect_timeout_seconds, database_identity, pins):
        held = admission._validate_pins(pins)
        values = (writer_dsn, connect_timeout_seconds, database_identity, *held)
        object.__setattr__(self, "_configured", _configuration(values))

    def persist(self, *, envelope_bytes, proof_bytes, inputs_bytes, context_bytes,
            expectations, work):
        """Genuinely replay/retain raw4, returning after normal outer commit."""
        configured = _snapshot(self)
        originals = retention._raw4(envelope_bytes, proof_bytes, inputs_bytes, context_bytes)
        arguments = {"envelope_bytes": originals[0], "proof_bytes": originals[1],
            "inputs_bytes": originals[2], "context_bytes": originals[3]}
        owned = admission._capture_expectations_on_work(configured[3:], expectations, work)
        return _run(configured, arguments, owned, persist=True, work=work)

    def read(self, *, retained_record_digest, expectations, work):
        """Replay historical custody without renewed time or absent-success."""
        configured = _snapshot(self)
        evidence.plan.contract._digest(retained_record_digest)
        arguments = {"retained_record_digest": retained_record_digest}
        owned = admission._capture_expectations_on_work(configured[3:], expectations, work)
        return _run(configured, arguments, owned, persist=False, work=work)
