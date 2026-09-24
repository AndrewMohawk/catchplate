"""Private PostgreSQL persistence of original signed revocation-v4 records.

Every write and replay accepts raw bytes and independent verifier expectations,
never a successful-verification DTO. The actual verifier runs once per call on
the supplied work. SQL, driver CPU and fixed column/parameter scaffolding are
not JSON work; variable JSON encodings, codecs and comparisons are prepaid.
No function commits the caller transaction or grants execution/currentness.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from itertools import chain

from serverware import authority_complete_query_batch as batch
from serverware import authority_contract
from serverware import authority_revocation_retention as retention
from serverware.authority_query_read_work import _ValidationWork
from serverware.authority_store.planner_connection import (
    _db_value, _require_fresh_deadline, _require_planner_writer,
    _require_postgres_connection,
)


_PARENT = "serverware_metadata.policy_authority_planner_transactions"
_SIDECAR = "serverware_metadata.policy_authority_revocation_retained_plans"
_RESERVATION_FIELDS = (
    "planner_transaction_id", "operation", "operation_id", "request_digest",
    "capability_id", "operation_contract_digest", "query_manifest_digest",
    "selected_business_rows_json", "selected_business_rows_digest",
    "mutation_plan_json", "mutation_plan_digest", "work_units",
    "authority_root_set_before_digest", "planner_session_identity_digest",
    "planner_measurement_digest", "planner_attestation_receipt_digest",
    "deadline_monotonic_ns", "deadline_epoch_ns", "fence",
    "reserved_at_epoch_ns", "source_revision", "plan_protocol",
)
_PLANNED_FIELDS = (
    "authorization_projection_digest", "authority_snapshot_digest",
    "exact_plan_base64url", "exact_plan_bytes_digest", "exact_plan_byte_count",
    "retained_record_digest",
)
_PARENT_FIELDS = _RESERVATION_FIELDS + _PLANNED_FIELDS + ("status", "planned_at_epoch_ns")
_RECORD_FIELDS = (
    "planner_transaction_id", "plan_protocol", "exact_envelope_base64url",
    "exact_envelope_bytes_digest", "exact_envelope_byte_count",
    "evaluation_context_base64url", "evaluation_context_bytes_digest",
    "evaluation_context_byte_count", "planner_key_digest", "verifier_key_digest",
    "retained_record_digest", "source_revision",
)
_SELECT_PARENT = ("SELECT " + ", ".join(_PARENT_FIELDS) + " FROM " + _PARENT
                  + " WHERE planner_transaction_id = %s FOR UPDATE")
_SELECT_RECORD = ("SELECT " + ", ".join(_RECORD_FIELDS) + " FROM " + _SIDECAR
                  + " WHERE planner_transaction_id = %s")
_INSERT_PARENT = ("INSERT INTO " + _PARENT + " (" + ", ".join(_RESERVATION_FIELDS)
    + ", status) VALUES (" + ", ".join(("%s",) * len(_RESERVATION_FIELDS))
    + ", 'reserved') ON CONFLICT (planner_transaction_id) DO NOTHING")
_INSERT_RECORD = ("INSERT INTO " + _SIDECAR + " (" + ", ".join(_RECORD_FIELDS)
    + ") VALUES (" + ", ".join(("%s",) * len(_RECORD_FIELDS))
    + ") ON CONFLICT (planner_transaction_id) DO NOTHING")
_COMPLETE_PARENT = ("UPDATE " + _PARENT + " SET status = 'planned', "
    + ", ".join(name + " = %s" for name in _PLANNED_FIELDS)
    + ", planned_at_epoch_ns = %s WHERE planner_transaction_id = %s "
    + "AND status = 'reserved' AND plan_protocol = 'revocation-v4' "
    + "AND retained_record_digest IS NULL")


def _error(message):
    return _db_value("MetadataStoreError")(message)


def _callback(work, callback, *args, **kwargs):
    """Driver/clock callbacks may not replace, refund or spend this work."""
    batch._SharedLedger(work)
    limits, metrics = work.limits, work.metrics
    values = (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
    result = callback(*args, **kwargs)
    batch._SharedLedger(work)
    if (work.limits is not limits or work.metrics != metrics
            or (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes) != values):
        raise _error("revocation persistence callback changed its shared work")
    return result


@contextmanager
def _context(manager, work):
    """Guard successful context callbacks; always clean up a failed scope.

    Failure cleanup cannot be gated on valid counters: even corrupt work must
    roll back/close its actual manager. Cleanup cannot suppress or replace the
    first failure and never repairs or refunds the ledger.
    """
    entered = False

    def enter():
        nonlocal entered
        value = manager.__enter__()
        entered = True
        return value

    try:
        value = _callback(work, enter)
        yield value
    except BaseException as exc:
        if entered:
            try:
                manager.__exit__(type(exc), exc, exc.__traceback__)
            except BaseException:
                pass
        raise
    else:
        exited = False

        def leave():
            nonlocal exited
            exited = True
            return manager.__exit__(None, None, None)

        try:
            _callback(work, leave)
        except BaseException as exc:
            if not exited:
                try:
                    manager.__exit__(type(exc), exc, exc.__traceback__)
                except BaseException:
                    pass
            raise


def _read(cursor, sql, parameters, work):
    result = _callback(work, cursor.execute, sql, parameters)
    return _callback(work, result.fetchone)


def _owned_row(row, fields, work):
    if (type(row) is not dict or len(row) != len(fields)
            or any(name not in row for name in fields)
            or any(type(value) not in (str, int, type(None)) for value in row.values())):
        raise _error("revocation retained SQL row is not closed scalar data")
    for name, value in row.items():
        maximum = (4 * ((retention.plan.contract.MAX_PAYLOAD_BYTES + 2) // 3)
                   if name.endswith("base64url") else authority_contract.MAX_RESULT_BYTES
                   if name.endswith("_json") else 128)
        if (type(value) is str and len(value) > maximum
                or type(value) is int and not 0 <= value <= 2**63 - 1):
            raise _error("revocation retained SQL scalar exceeds its source bound")
    work.prepare_copy(row)
    return row.copy()


def _owned_expectations(expectations, work):
    if (len(expectations) != len(retention.wire._EXPECTATIONS)
            or set(expectations) != retention.wire._EXPECTATIONS):
        raise ValueError("revocation retained replay expectations are not closed")
    pins = {name: expectations[name] for name in (
        "planner_public_key", "verifier_public_key", "database_now")}
    retention.plan._verification_types(pins["planner_public_key"],
        pins["verifier_public_key"], pins["database_now"])
    owned = batch._JSONCapture(batch._SharedLedger(work)).visit(
        {name: value for name, value in expectations.items() if name not in pins}, depth=0)
    # Fixed nineteen-field call scaffolding; the variable graphs are captured
    # above before the first driver callback, and actual replay captures again.
    return {**owned, **pins}


def _match(row, expected, work):
    # Each operand is prepared at its actual comparison site. Exact scalar
    # types prevent bool/int or equal-valued int/float aliases from passing.
    for name, value in expected.items():
        actual = row[name]
        work.prepare_comparison(actual, value)
        if type(actual) is not type(value) or actual != value:
            raise _error("revocation retained identity or exact bytes conflict")


def _encode(raw, work):
    padded = 4 * ((len(raw) + 2) // 3)
    length = padded - ((3 - len(raw) % 3) % 3)
    # Real input scan, padded output, URL translation, strip, ASCII decode.
    work.charge(input_bytes=len(raw) + 3 * padded + length)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _decode(value, count, maximum, work):
    if (type(count) is not int or not 2 <= count <= maximum
            or type(value) is not str or len(value) != (4 * count + 2) // 3):
        raise _error("revocation retained base64 or byte count is outside its bound")
    length = len(value)
    padded = length + (-length % 4)
    decoded = 3 * (padded // 4)
    reencoded = 4 * ((decoded + 2) // 3)
    # Conservative full alphabet+padding/ASCII/translation/decode and actual
    # canonical roundtrip reservation, before any codec allocation; no refund.
    work.charge(input_bytes=2 * length + 4 * padded + 2 * decoded + 5 * reencoded)
    if any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
           for character in value):
        raise _error("revocation retained base64 alphabet is invalid")
    raw = base64.b64decode(value + "=" * (-length % 4), altchars=b"-_", validate=True)
    if (len(raw) != count
            or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value):
        raise _error("revocation retained base64 is not canonical")
    return raw


def _json_text(value, maximum, work):
    size, _ = work.prepare_encoding(value)
    if size > maximum:
        raise _error("revocation retained reservation JSON exceeds its source bound")
    work.charge(input_bytes=size)
    return retention.plan.core.canonical_bytes(value).decode("ascii")


def _bindings(record, work):
    payload, context = record.payload, record.context
    plan, identity = payload["measuredPlan"], payload["plannerIdentity"]
    reservation = {
        "planner_transaction_id": plan["plannerTransactionId"],
        "operation": plan["operation"], "operation_id": plan["operationId"],
        "request_digest": plan["requestDigest"], "capability_id": plan["capabilityId"],
        "operation_contract_digest": plan["operationContractDigest"],
        "query_manifest_digest": plan["queryManifestDigest"],
        "selected_business_rows_json": _json_text(payload["selectedBusinessRows"],
            authority_contract.MAX_PLAN_SELECTED_BYTES, work),
        "selected_business_rows_digest": plan["selectedBusinessRowsDigest"],
        "mutation_plan_json": _json_text(payload["mutationPlan"],
            authority_contract.MAX_RESULT_BYTES, work),
        "mutation_plan_digest": plan["mutationPlanDigest"], "work_units": plan["workUnits"],
        "authority_root_set_before_digest": plan["authorityRootSetBeforeDigest"],
        "planner_session_identity_digest": identity["sessionIdentityDigest"],
        "planner_measurement_digest": identity["measurementDigest"],
        "planner_attestation_receipt_digest": identity["attestationReceiptDigest"],
        "deadline_monotonic_ns": context["deadlineMonotonicNs"],
        "deadline_epoch_ns": context["deadlineEpochNs"], "fence": context["expectedFence"],
        "reserved_at_epoch_ns": context["reservedAtEpochNs"],
        "source_revision": authority_contract.SOURCE_REVISION,
        "plan_protocol": retention.PLAN_PROTOCOL,
    }
    planned = {
        "authorization_projection_digest": plan["authorizationProjectionDigest"],
        "authority_snapshot_digest": plan["authoritySnapshotDigest"],
        # Deliberately the canonical payload, not the signed envelope.
        "exact_plan_base64url": _encode(record.payload_bytes, work),
        "exact_plan_bytes_digest": record.payload_digest,
        "exact_plan_byte_count": len(record.payload_bytes),
        "retained_record_digest": record.record_digest,
    }
    sidecar = {
        "planner_transaction_id": plan["plannerTransactionId"],
        "plan_protocol": retention.PLAN_PROTOCOL,
        "exact_envelope_base64url": _encode(record.envelope_bytes, work),
        "exact_envelope_bytes_digest": record.envelope_digest,
        "exact_envelope_byte_count": len(record.envelope_bytes),
        "evaluation_context_base64url": _encode(record.context_bytes, work),
        "evaluation_context_bytes_digest": record.context_digest,
        "evaluation_context_byte_count": len(record.context_bytes),
        "planner_key_digest": record.planner_key_digest,
        "verifier_key_digest": record.verifier_key_digest,
        "retained_record_digest": record.record_digest,
        "source_revision": authority_contract.SOURCE_REVISION,
    }
    return reservation, planned, sidecar


def _fresh(reservation):
    _require_fresh_deadline(deadline_monotonic_ns=reservation["deadline_monotonic_ns"],
        deadline_epoch_ns=reservation["deadline_epoch_ns"],
        reserved_at_epoch_ns=reservation["reserved_at_epoch_ns"])


def _planned_time(value, reservation):
    if (type(value) is not int or not reservation["reserved_at_epoch_ns"]
            <= value < reservation["deadline_epoch_ns"]):
        raise _error("revocation planned timestamp is outside its reservation interval")


def _parameters(document, fields, work, extra=()):
    # Conservative full document preparation before the real value tuple.
    work.prepare_copy(document)
    return tuple(chain((document[name] for name in fields), extra))


def _receipt(record, row):
    return {
        "schema": "serverware.policyAuthorityRevocationRetainedReceipt/v1",
        "planProtocol": retention.PLAN_PROTOCOL,
        "plannerTransactionId": record.header["plannerTransactionId"],
        "operationId": record.header["operationId"], "requestDigest": record.header["requestDigest"],
        "capabilityId": record.header["capabilityId"],
        "retainedRecordDigest": record.record_digest,
        "envelopeDigest": record.envelope_digest, "contextDigest": record.context_digest,
        "plannerKeyDigest": record.planner_key_digest, "verifierKeyDigest": record.verifier_key_digest,
        "exactEnvelopeBytes": record.envelope_bytes, "evaluationContextBytes": record.context_bytes,
        "plannedAtEpochNs": row["planned_at_epoch_ns"],
    }


def _transaction_connection(connection):
    _require_postgres_connection(connection)
    if connection.in_transaction is not True:
        raise _error("revocation retained persistence requires an existing caller transaction")
    return connection


def persist_revocation_planner_record(*, envelope_bytes: bytes, evaluation_context_bytes: bytes,
        planned_at_epoch_ns: int, connection, work: _ValidationWork, **expectations) -> dict:
    """Verify original bytes, then atomically reserve/insert/complete a v4 row.

    The savepoint rolls this operation back on a caught failure; the outer
    transaction remains caller-owned. Identical retries never update an old
    planned timestamp or replace a signature, context, key or payload.
    """
    _transaction_connection(connection)
    if type(planned_at_epoch_ns) is not int or not 1 <= planned_at_epoch_ns <= 2**63 - 1:
        raise ValueError("revocation planned timestamp is not an exact positive int64")
    record = retention._verify_record_on_work(envelope_bytes=envelope_bytes,
        evaluation_context_bytes=evaluation_context_bytes, work=work, **expectations)
    reservation, planned, sidecar = _bindings(record, work)
    _planned_time(planned_at_epoch_ns, reservation)
    reservation_parameters = _parameters(reservation, _RESERVATION_FIELDS, work)
    sidecar_parameters = _parameters(sidecar, _RECORD_FIELDS, work)
    completion_parameters = _parameters(planned, _PLANNED_FIELDS, work,
        (planned_at_epoch_ns, reservation["planner_transaction_id"]))
    raw = _callback(work, _require_planner_writer, connection)
    identity = (reservation["planner_transaction_id"],)
    with _context(_callback(work, raw.transaction), work):
        with _context(_callback(work, raw.cursor), work) as cursor:
            _callback(work, _fresh, reservation)
            _callback(work, cursor.execute, _INSERT_PARENT, reservation_parameters)
            row = _owned_row(_read(cursor, _SELECT_PARENT, identity, work), _PARENT_FIELDS, work)
            _match(row, reservation, work)
            if row["status"] == "reserved":
                _match(row, {name: None for name in _PLANNED_FIELDS}, work)
                if row["planned_at_epoch_ns"] is not None:
                    raise _error("revocation reserved row has a planned timestamp")
                _callback(work, cursor.execute, _INSERT_RECORD, sidecar_parameters)
                stored = _owned_row(_read(cursor, _SELECT_RECORD, identity, work), _RECORD_FIELDS, work)
                _match(stored, sidecar, work)
                _callback(work, _fresh, reservation)
                updated = _callback(work, cursor.execute, _COMPLETE_PARENT, completion_parameters)
                if updated.rowcount != 1:
                    raise _error("revocation planner completion CAS failed")
                row = _owned_row(_read(cursor, _SELECT_PARENT, identity, work), _PARENT_FIELDS, work)
                _match(row, reservation, work)
                if row["status"] != "planned" or row["planned_at_epoch_ns"] != planned_at_epoch_ns:
                    raise _error("revocation planner completion status or timestamp changed")
            elif row["status"] in {"planned", "consumed"}:
                stored = _owned_row(_read(cursor, _SELECT_RECORD, identity, work), _RECORD_FIELDS, work)
                _match(stored, sidecar, work)
            else:
                raise _error("revocation retention cannot replace a failed or unknown lifecycle")
            _match(row, planned, work)
            _planned_time(row["planned_at_epoch_ns"], reservation)
    return _receipt(record, row)


def read_revocation_planner_record(*, planner_transaction_id: str, connection,
        work: _ValidationWork, **expectations) -> dict | None:
    """Replay original bytes with independent historical expectations.

    A differently tagged or incomplete existing parent is a denial, never a
    not-found signal that could trigger recomputation or re-signing. Historical
    clocks are deliberately not refreshed and no execution is authorized.
    """
    _transaction_connection(connection)
    batch._SharedLedger(work)
    retention.plan.contract._digest(planner_transaction_id)
    expectations = _owned_expectations(expectations, work)
    work.prepare_comparison(planner_transaction_id, expectations["expected_planner_transaction_id"])
    if planner_transaction_id != expectations["expected_planner_transaction_id"]:
        raise ValueError("revocation retained replay transaction binding differs")
    raw = _callback(work, _require_planner_writer, connection)
    identity = (planner_transaction_id,)
    with _context(_callback(work, raw.cursor), work) as cursor:
        row = _read(cursor, _SELECT_PARENT, identity, work)
        if row is None:
            return None
        row = _owned_row(row, _PARENT_FIELDS, work)
        if (row["plan_protocol"] != retention.PLAN_PROTOCOL
                or row["status"] not in {"planned", "consumed"}
                or type(row["retained_record_digest"]) is not str):
            raise _error("revocation retained replay is not durably planned v4")
        stored = _owned_row(_read(cursor, _SELECT_RECORD, identity, work), _RECORD_FIELDS, work)
    envelope = _decode(stored["exact_envelope_base64url"], stored["exact_envelope_byte_count"],
        retention.plan.contract.MAX_PAYLOAD_BYTES, work)
    context = _decode(stored["evaluation_context_base64url"], stored["evaluation_context_byte_count"],
        retention.MAX_CONTEXT_BYTES, work)
    record = retention._verify_record_on_work(envelope_bytes=envelope,
        evaluation_context_bytes=context, work=work, **expectations)
    reservation, planned, sidecar = _bindings(record, work)
    _match(row, reservation, work)
    _match(row, planned, work)
    _match(stored, sidecar, work)
    _planned_time(row["planned_at_epoch_ns"], reservation)
    return _receipt(record, row)
