"""Current configured read-only owner for immutable custody originals.

The actual writer service supplies its admitted measured payload, active
generation and held writer DSN. Those inputs are owned and genuinely joined
before any driver callback. Current connection admission does not enroll the
keys, configuration or generation found in historical custody rows.

One real SERIALIZABLE READ ONLY DEFERRABLE transaction admits PostgreSQL 16,
the exact current/session writer role, configured TLS identity, non-elevation
and the unchanged source-owned writer privilege inventory before fixed SELECTs.
Only owned immutable originals survive normal cursor, transaction and connection
exit. They are not signature/proof evidence, a current execution authorization,
or a claim that missing custody means no prior commit.

Configuration capture and the actual row/codec/hash work spend the existing
allowance. Fixed metadata queries and native driver internals keep their bounded
exclusions. No signer, writer mutation, new allowance, retry or repair exists
here. The real database/registry import gate remains before socket creation.
"""
from __future__ import annotations

import math

from catchplate import authority_revocation_configuration as configuration
from catchplate import authority_revocation_custody_read_transport as transport
from catchplate import authority_revocation_plan as plan
from catchplate import authority_revocation_root_reader as reader
from catchplate import authority_revocation_writer_connection as writer
from catchplate.authority_store import revocation_custody_read as store
from catchplate.authority_store.planner_writer_sql import planner_writer_privilege_check


_SET_TRANSACTION = "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY DEFERRABLE"


class RevocationCustodyReadError(ValueError):
    pass


def _capture_read_configuration(*, payload, configuration_digest, generation,
        persistence_dsn, work):
    """Hold a fixed read tuple from full current configuration/launch capture."""
    owned, _launch = configuration._capture_configuration_on_work(payload=payload,
        configuration_digest=configuration_digest, generation=generation, work=work)
    roles = owned["roles"]
    if type(roles) is not dict or type(roles["planner-writer"]) is not dict:
        raise RevocationCustodyReadError("custody reader writer role is not an exact object")
    role = roles["planner-writer"]
    plan.contract._literal(role["processMode"], "policy-authority-planner-writer")
    reader._bounded_text(persistence_dsn, 65536)
    if "\n" in persistence_dsn or "\r" in persistence_dsn:
        raise RevocationCustodyReadError("custody reader DSN is not one bounded descriptor value")
    timeout = role["databaseConnectTimeoutSeconds"]
    if (type(timeout) not in (int, float) or not math.isfinite(timeout)
            or not 2 <= timeout <= 300):
        raise RevocationCustodyReadError("custody reader timeout is outside libpq's bounded interval")
    identity = (role["databaseRole"], role["tlsClientDn"],
        role["tlsClientSerial"], role["tlsIssuerDn"])
    writer._validate_database_identity(identity)
    manifest = owned["queryManifestDigest"]
    plan._same(manifest, plan._QUERY_MANIFEST_DIGEST, work,
        "custody reader configuration differs from the source query manifest")
    fixed = (persistence_dsn, int(timeout), *identity, manifest)
    reader._validate_configuration(fixed)
    return fixed


def _read_originals_on_configuration(*, payload, configuration_digest, generation,
        persistence_dsn, execution_envelope_id, planner_transaction_id, work):
    """Read raw6 selected by independently held IDs, never infer absence.

    The current active writer configuration admits this read connection only.
    The fixed store checks immutable row links, codecs and hashes; independent
    cryptographic and historical-policy validation must still follow at the
    caller. Missing, partial or conflicting rows raise without a success value.
    Cleanup preserves the first failure, including after meter poisoning.
    Observed raw-handle/status continuity cannot detect a hostile driver's
    hidden transaction replacement; no post-exit guard reverses completed I/O.
    """
    configuration.capability.capture._SharedLedger(work)
    plan.contract._digest(execution_envelope_id)
    plan.contract._digest(planner_transaction_id)
    fixed = _capture_read_configuration(payload=payload,
        configuration_digest=configuration_digest, generation=generation,
        persistence_dsn=persistence_dsn, work=work)
    # Actual imports remain at the owning path. Do not bypass the database's
    # transitive registry/startup gate merely because these are SELECTs.
    from catchplate import db
    import psycopg
    from psycopg.rows import dict_row

    if fixed[2] != db._METADATA_STORE_AUTHORITY_PLANNER_WRITER_ROLE:
        raise RevocationCustodyReadError("custody reader role differs from the actual database contract")
    connection = reader._connect(work, lambda: psycopg.connect(fixed[0],
        row_factory=dict_row, connect_timeout=fixed[1], autocommit=False,
        options="-c search_path=pg_catalog"))
    try:
        original = reader.roots._callback(work, reader._connection_identity, connection, 0)
        with reader._context(connection, work) as active:
            if active is not connection:
                raise RevocationCustodyReadError("custody reader connection context replaced its handle")
            reader.roots._callback(work, reader._require_connection, connection, original, 0)
            transaction = reader.roots._callback(work, lambda: connection.transaction())
            reader.roots._callback(work, reader._require_connection, connection, original, 0)
            with reader._context(transaction, work) as entered:
                if entered is not transaction:
                    raise RevocationCustodyReadError("custody reader transaction context replaced its handle")
                reader.roots._callback(work, reader._require_connection, connection, original, 2)
                guarded = writer._Connection(connection, original, work)
                with guarded.cursor() as cursor:
                    cursor.execute(_SET_TRANSACTION)
                    reader._admit_identity(cursor.execute(reader._IDENTITY_SQL).fetchone(), fixed)
                    if cursor.execute(*planner_writer_privilege_check(
                            role=fixed[2], namespace="catchplate_metadata")).fetchone() is not None:
                        raise RevocationCustodyReadError("custody reader writer privileges are not source exact")
                    originals = store._read_originals(cursor,
                        execution_envelope_id=execution_envelope_id,
                        planner_transaction_id=planner_transaction_id, work=work)
                    if (type(originals) is not tuple or len(originals) != 6
                            or any(type(raw) is not bytes for raw in originals)):
                        raise RevocationCustodyReadError("custody reader lost six immutable originals")
                    transport._validate_response_lengths(tuple(len(raw) for raw in originals))
                guarded._call(lambda: None)
            reader.roots._callback(work, reader._require_connection, connection, original, 0)
        if reader.roots._callback(work, lambda: connection.closed) is not True:
            raise RevocationCustodyReadError("custody reader connection was not closed")
        return originals
    except BaseException:
        reader._close_after_failure(connection)
        raise
