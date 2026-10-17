"""Private same-transaction reservation after genuine retained-v4 replay.

The successor request binds the original retained record and mixed transition.
It is data in the existing execution-envelope table, not a capability, current
root proof or execution receipt. No existing v3 service or executor admits it.
Envelope rows are mutable HEAD rows: every retry/use must compare the exact
locked parent/record/row, not assume a foreign key or immutable envelope guard.
"""
from __future__ import annotations

from catchplate import authority_contract as authority
from catchplate import authority_revocation_retention as retention
from catchplate.authority_query_read_work import _ValidationWork
from catchplate.authority_store import revocation_retention as store


REQUEST_SCHEMA = "catchplate.policyAuthorityRevocationExecutionRequest/v1"
_TABLE = "catchplate_metadata.policy_authority_execution_envelopes"
_RESERVATION_FIELDS = (
    "envelope_id", "parent_envelope_id", "purpose", "operation", "operation_id",
    "request_digest", "capability_id", "planner_transaction_id",
    "authorization_projection_digest", "operation_contract_digest",
    "exact_request_base64url", "exact_request_bytes_digest", "exact_request_byte_count",
    "deadline_monotonic_ns", "deadline_epoch_ns", "fence", "status",
    "reserved_at_epoch_ns", "source_revision",
)
_TERMINAL_FIELDS = (
    "exact_response_base64url", "exact_response_bytes_digest", "exact_response_byte_count",
    "result_digest", "terminal_receipt_json", "terminal_receipt_digest",
    "failure_code", "failure_digest", "terminal_at_epoch_ns",
)
_FIELDS = _RESERVATION_FIELDS + _TERMINAL_FIELDS
_INSERT = ("INSERT INTO " + _TABLE + " (" + ", ".join(_RESERVATION_FIELDS)
    + ") VALUES (" + ", ".join(("%s",) * len(_RESERVATION_FIELDS))
    + ") ON CONFLICT (envelope_id) DO NOTHING")
_SELECT = ("SELECT " + ", ".join(_FIELDS) + " FROM " + _TABLE
    + " WHERE envelope_id = %s FOR UPDATE")


def _expected_reservation(envelope_id, record, parent, work):
    # These are the actual owned verifier outputs, not caller-provided JSON.
    # Fixed field scaffolding is excluded; variable encoding/hash/codec work
    # is prepaid on the invocation's existing meter. Wrapper overhead counts
    # against the same 4 MiB exact-request bound as the existing table.
    request = {
        "schema": REQUEST_SCHEMA, "planProtocol": retention.PLAN_PROTOCOL,
        "retainedRecordDigest": record.record_digest,
        "rootTransitionDigest": record.payload["measuredPlan"]["rootTransitionDigest"],
        "typedRequest": record.payload["typedRequest"],
    }
    raw = retention.plan.retained._bounded_wire(request, store.batch._SharedLedger(work),
        maximum_bytes=authority.MAX_REQUEST_BYTES,
        maximum_nodes=retention.plan.contract.MAX_JSON_NODES)
    request_digest = retention._bytes_digest(raw, work)
    encoded = store._encode(raw, work)
    return {
        "envelope_id": envelope_id,
        "parent_envelope_id": parent["planner_transaction_id"], "purpose": "execute-v9",
        **{field: parent[field] for field in (
            "operation", "operation_id", "request_digest", "capability_id", "planner_transaction_id",
            "authorization_projection_digest", "operation_contract_digest",
            "deadline_monotonic_ns", "deadline_epoch_ns", "fence", "reserved_at_epoch_ns", "source_revision",
        )},
        "exact_request_base64url": encoded, "exact_request_bytes_digest": request_digest,
        "exact_request_byte_count": len(raw), "status": "reserved",
        **{field: None for field in _TERMINAL_FIELDS},
    }


def _owned_envelope(row, expected, work):
    # Bound returned scalar lengths by the independently reconstructed row
    # before copying. Terminal data is not accepted through this reserve API.
    if (type(row) is not dict or len(row) != len(_FIELDS)
            or any(type(name) is not str or len(name) > 128 for name in row)
            or set(row) != set(_FIELDS)
            or any(type(row[name]) is not type(value)
                   or type(value) is str and len(row[name]) > len(value)
                   for name, value in expected.items())):
        raise store._error("revocation execution reservation is not closed scalar data")
    work.prepare_copy(row)
    return row.copy()


def _same_connection(connection, raw):
    store._transaction_connection(connection)
    if store._require_postgres_connection(connection) is not raw:
        raise store._error("revocation execution connection changed during reservation")


def reserve_revocation_execution_envelope(*, envelope_id: str, planner_transaction_id: str,
        connection, work: _ValidationWork, **expectations) -> dict:
    """Reserve exact successor bytes after one real stored-record verification.

    Only a planned parent and a new or byte-identical reserved envelope are
    admitted. Current deadline/age/skew checks also apply to identical retries;
    historical reads remain separate and clock-free. A savepoint contains all
    replay and reservation work, without committing the caller transaction.
    Current authority roots, capability issuance/consumption, mutation and
    terminal/witness publication remain separate future consumer requirements.
    """
    store._transaction_connection(connection)
    retention.plan.contract._digest(envelope_id)
    retention.plan.contract._digest(planner_transaction_id)
    # Capture external mutable graphs before the first database callback. The
    # real read worker owns its inputs again at its own boundary; neither pass
    # grants a new work allowance or trusts the retained evaluation context.
    owned = store._owned_expectations(expectations, work)
    raw = store._callback(work, store._require_planner_writer, connection)
    with store._context(store._callback(work, raw.transaction), work):
        observed = store._read_revocation_record_on_work(
            planner_transaction_id=planner_transaction_id, connection=connection,
            work=work, _expected_raw=raw, expectations=owned)
        store._callback(work, _same_connection, connection, raw)
        if observed is None:
            raise store._error("revocation execution parent was not found")
        record, parent = observed
        if parent["status"] != "planned":
            raise store._error("revocation execution requires an unconsumed planned parent")
        expected = _expected_reservation(envelope_id, record, parent, work)
        parameters = store._parameters(expected, _RESERVATION_FIELDS, work)
        with store._context(store._callback(work, raw.cursor), work) as cursor:
            store._callback(work, store._fresh, parent)
            store._callback(work, _same_connection, connection, raw)
            store._callback(work, cursor.execute, _INSERT, parameters)
            row = _owned_envelope(store._read(cursor, _SELECT, (envelope_id,), work), expected, work)
            store._match(row, expected, work)
            store._callback(work, store._fresh, parent)
            store._callback(work, _same_connection, connection, raw)
        store._callback(work, _same_connection, connection, raw)
    return row
