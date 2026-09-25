"""Configured PostgreSQL custody owner for evidence-admission plan originals.

Construction is inert. One immutable configuration holds the writer endpoint,
database identity, fixed operation and independently admitted public-key,
identity, configuration and purpose-policy pins. Calls cannot substitute keys,
DSNs, clocks or successful verification carriers. Historical request, roots,
input commitment and evaluation times still need independent admission; a
current configuration or copied stored context does not establish that history.

The fixed store genuinely replays raw3 on the same work before publishing any
result. Persistence checks live original deadlines without retiming the signed
plan; a historical read samples no current clock. The actual writer owner
admits PostgreSQL/TLS/ACL and owns the outer transaction and connection through
normal exit. Returned observations are local custody results, not signed
durability receipts, business execution, reservation or registry activation.
An error or uncertain outer exit does not establish that nothing committed.
There is no automatic retry, signing, new allowance or caller operation hook.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_revocation_root_reader as reader
from serverware import authority_revocation_writer_connection as writer
from serverware import authority_webauthn_evidence_plan_admission as admission
from serverware.authority_store import webauthn_evidence_retention as store


plan, evidence = admission.plan, admission.evidence
_IDENTITY_FIELDS = admission._IDENTITY_FIELDS


class WebAuthnEvidencePlanPersistenceError(ValueError):
    pass


def _configuration(values):
    """Check fixed exact scalars and real key types without key callbacks."""
    if type(values) is not tuple or len(values) != 16:
        raise WebAuthnEvidencePlanPersistenceError("evidence persistence configuration is not exact")
    dsn, timeout, database = values[:3]
    reader._bounded_text(dsn, 65536)
    if "\n" in dsn or "\r" in dsn or type(timeout) is not int or not 2 <= timeout <= 300:
        raise WebAuthnEvidencePlanPersistenceError("evidence persistence connection settings are invalid")
    writer._validate_database_identity(database)
    admission._validate_pins(values[3:])
    return values


def _snapshot(owner):
    if type(owner) is not EvidencePlanPersistence:
        raise WebAuthnEvidencePlanPersistenceError("evidence persistence owner type changed")
    return _configuration(owner._configured)


def _capture(configured, expectations, work):
    return admission._capture_expectations_on_work(configured[3:], expectations, work)


def _connect(configured, work, psycopg, dict_row):
    connection = None

    def open_connection():
        nonlocal connection
        connection = psycopg.connect(configured[0], row_factory=dict_row,
            connect_timeout=configured[1], autocommit=False, options="-c search_path=pg_catalog")
        return connection

    try:
        # Method lookup and invocation stay within the finally-preserving
        # callback guard. A returned handle is closed even if that guard fails.
        return evidence.production._callback(work, open_connection)
    except BaseException:
        if connection is not None:
            reader._close_after_failure(connection)
        raise


def _run(configured, arguments, owned, *, persist, work):
    # The genuine facade's unchanged registry/startup gate precedes any socket.
    from serverware import db
    import psycopg
    from psycopg.rows import dict_row

    if configured[2][0] != db._METADATA_STORE_AUTHORITY_PLANNER_WRITER_ROLE:
        raise WebAuthnEvidencePlanPersistenceError("evidence writer role differs from the actual database contract")
    operation = (store.persist_webauthn_evidence_plan_record if persist
        else store.read_webauthn_evidence_plan_record)
    fixed = {"expectations": owned, "planner_public_key": configured[4],
        "evidence_public_key": configured[7]}
    connection = _connect(configured, work, psycopg, dict_row)
    # This real owner releases no result until the outer transaction and
    # connection have normally exited and the closed handle has been checked.
    return writer._run_on_connection(connection, database_identity=configured[2],
        work=work, operation=operation, arguments=arguments, expectations=fixed)


@dataclass(frozen=True, slots=True, init=False, repr=False, eq=False)
class EvidencePlanPersistence:
    """Hold one purpose's writer endpoint and independent historical key pins."""

    _configured: tuple

    def __init__(self, *, writer_dsn, connect_timeout_seconds, database_identity, operation,
            planner_public_key, expected_planner_identity, expected_planner_spki_digest,
            evidence_public_key, expected_evidence_identity, expected_evidence_spki_digest,
            configuration_digest, maximum_age_ns, maximum_clock_skew_ns,
            rp_id=None, origin=None, installation_target_digest=None):
        evidence._identity(expected_planner_identity)
        evidence._identity(expected_evidence_identity)
        configured = _configuration((writer_dsn, connect_timeout_seconds, database_identity,
            operation, planner_public_key,
            tuple(expected_planner_identity[name] for name in _IDENTITY_FIELDS),
            expected_planner_spki_digest, evidence_public_key,
            tuple(expected_evidence_identity[name] for name in _IDENTITY_FIELDS),
            expected_evidence_spki_digest, configuration_digest, maximum_age_ns,
            maximum_clock_skew_ns, rp_id, origin, installation_target_digest))
        object.__setattr__(self, "_configured", configured)

    def persist(self, *, envelope_bytes, inputs_bytes, evaluation_context_bytes, expectations, work):
        """Retain exact originals; normal outer exit precedes the local result.

        This fixed store performs live deadline checks as well as genuine
        historical replay. A failure after commit is not a rollback receipt.
        """
        configured = _snapshot(self)
        originals = store._raw3(envelope_bytes, inputs_bytes, evaluation_context_bytes)
        arguments = {"envelope_bytes": originals[0], "inputs_bytes": originals[1],
            "evaluation_context_bytes": originals[2]}
        owned = _capture(configured, expectations, work)
        return _run(configured, arguments, owned, persist=True, work=work)

    def read(self, *, retained_record_digest, expectations, work):
        """Genuinely replay historical custody without refreshing its authority.

        Missing or conflicting custody raises; it never proves that an earlier
        uncertain operation did not commit. There is no current clock here.
        """
        configured = _snapshot(self)
        evidence.plan.contract._digest(retained_record_digest)
        arguments = {"retained_record_digest": retained_record_digest}
        owned = _capture(configured, expectations, work)
        return _run(configured, arguments, owned, persist=False, work=work)
