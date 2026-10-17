"""SELECT-only recovery of original custody bytes, not authentication.

The owning configured reader admits the actual writer-role connection and
holds a read transaction before supplying its guarded cursor. Independently
held execution and planner IDs select one global intent identity. This module
owns bounded rows, checks immutable database links, and decodes/hash-checks the
original intent, relay, plan, context, history and ACK on the same caller work.

Rows do not enroll historical keys, configuration, generation or policy. The
returned ordinary bytes still require independent cryptographic verification
and genuine historical replay. Missing, partial or inconsistent custody is
unresolved; it never establishes rollback, permits re-signing, or repairs data.
No mutable execution status or terminal response is treated as custody evidence.
"""
from __future__ import annotations

from catchplate import authority_contract as authority
from catchplate import authority_revocation_writer_acknowledgment as acknowledgment
from catchplate import authority_revocation_writer_commitment as commitment
from catchplate.authority_store import revocation_retention as store


_REQUEST_FIELDS = authority.REVOCATION_WRITER_REQUEST_COLUMNS
_RETAINED_FIELDS = authority.REVOCATION_RETAINED_COLUMNS
_ACK_FIELDS = authority.REVOCATION_WRITER_ACK_COLUMNS
_NAMESPACE = "catchplate_metadata."
_SELECT_REQUEST = ("SELECT " + ", ".join("r." + name for name in _REQUEST_FIELDS)
    + " FROM " + _NAMESPACE + authority.REVOCATION_WRITER_REQUEST_TABLE + " AS r"
    + " INNER JOIN " + _NAMESPACE + "policy_authority_planner_transactions AS p"
    + " ON p.planner_transaction_id = r.planner_transaction_id"
    + " AND p.plan_protocol = r.plan_protocol"
    + " AND p.retained_record_digest = r.retained_record_digest"
    + " AND p.planned_at_epoch_ns = r.planned_at_epoch_ns"
    + " AND p.source_revision = r.source_revision"
    + " INNER JOIN " + _NAMESPACE + "policy_authority_execution_envelopes AS e"
    + " ON e.envelope_id = r.execution_envelope_id"
    + " AND e.planner_transaction_id = r.planner_transaction_id"
    + " AND e.parent_envelope_id = r.planner_transaction_id"
    + " AND e.source_revision = r.source_revision"
    + " WHERE r.intent_envelope_id = %s AND r.execution_envelope_id = %s"
    + " AND r.planner_transaction_id = %s")
_SELECT_RETAINED = ("SELECT " + ", ".join(_RETAINED_FIELDS)
    + " FROM " + _NAMESPACE + authority.REVOCATION_RETAINED_TABLE
    + " WHERE planner_transaction_id = %s")
_SELECT_ACK = ("SELECT " + ", ".join(_ACK_FIELDS)
    + " FROM " + _NAMESPACE + authority.REVOCATION_WRITER_ACK_TABLE
    + " WHERE intent_envelope_id = %s")

# Fixed source-owned transport columns, not caller-selected projection or SQL.
_REQUEST_BODIES = (
    ("exact_intent_base64url", "exact_intent_bytes_digest", "exact_intent_byte_count", commitment.MAX_CONTROL_BYTES),
    ("exact_relay_base64url", "exact_relay_bytes_digest", "exact_relay_byte_count", commitment.MAX_CONTROL_BYTES),
    ("historical_expectations_base64url", "historical_expectations_bytes_digest",
     "historical_expectations_byte_count", commitment.MAX_HISTORY_BYTES),
)
_RETAINED_BODIES = (
    ("exact_envelope_base64url", "exact_envelope_bytes_digest", "exact_envelope_byte_count",
     store.retention.plan.contract.MAX_PAYLOAD_BYTES),
    ("evaluation_context_base64url", "evaluation_context_bytes_digest", "evaluation_context_byte_count",
     store.retention.MAX_CONTEXT_BYTES),
)
_ACK_BODIES = (("exact_ack_base64url", "exact_ack_bytes_digest", "exact_ack_byte_count",
    acknowledgment.MAX_ACK_BYTES),)


class RevocationCustodyReadError(ValueError):
    pass


def _owned_row(row, fields, bodies, work):
    """Bound closed scalar data before copying or another driver callback."""
    if (type(row) is not dict or len(row) != len(fields)
            or any(type(name) is not str for name in row) or set(row) != set(fields)):
        raise RevocationCustodyReadError("revocation custody is missing or not a complete closed row")
    transport_fields = frozenset(name for body in bodies for name in (body[0], body[2]))
    for encoded_name, _digest_name, count_name, maximum in bodies:
        count, encoded = row[count_name], row[encoded_name]
        if (type(count) is not int or not 2 <= count <= maximum
                or type(encoded) is not str or len(encoded) != (4 * count + 2) // 3):
            raise RevocationCustodyReadError("revocation custody original-byte transport exceeds its source bound")
    for name in fields:
        value = row[name]
        if name in transport_fields:
            continue
        if name == "plan_protocol":
            commitment.plan.contract._literal(value, store.retention.PLAN_PROTOCOL)
        elif name == "source_revision":
            commitment.plan.contract._literal(value, authority.SOURCE_REVISION)
        elif name in ("generation_sequence", "planned_at_epoch_ns"):
            commitment.plan.contract._integer(value, minimum=1)
        else:
            commitment.plan.contract._digest(value)
    work.prepare_copy(row)
    return row.copy()


def _original(row, body, work):
    encoded_name, digest_name, count_name, maximum = body
    raw = store._decode(row[encoded_name], row[count_name], maximum, work)
    store._match(row, {digest_name: store.retention._bytes_digest(raw, work),
        count_name: len(raw)}, work)
    return raw


def _read_originals(cursor, *, execution_envelope_id, planner_transaction_id, work):
    """Return raw6 from one caller-held admitted read transaction.

    Order is intent, relay, plan, context, history, ACK. The three queries are
    fixed SELECTs with bound IDs and no row locks, mutation, status filtering
    or configurable operation. Every row is owned before the next callback.
    Three genuine stable-ID hashes, six genuine original-body hashes, exact
    comparisons, row copies and canonical codecs spend the original allowance.
    Local maxima do not promise that maximum bodies fit that cumulative budget.
    """
    commitment.capture._SharedLedger(work)
    commitment.plan.contract._digest(execution_envelope_id)
    commitment.plan.contract._digest(planner_transaction_id)
    intent_id = commitment._intent_id(execution_envelope_id, planner_transaction_id, work)
    relay_id = commitment._relay_id(intent_id, work)
    ack_id = acknowledgment._ack_id_on_work(intent_id, work)
    request = _owned_row(store._read(cursor, _SELECT_REQUEST,
        (intent_id, execution_envelope_id, planner_transaction_id), work),
        _REQUEST_FIELDS, _REQUEST_BODIES, work)
    store._match(request, {"intent_envelope_id": intent_id, "relay_envelope_id": relay_id,
        "execution_envelope_id": execution_envelope_id,
        "planner_transaction_id": planner_transaction_id}, work)
    retained = _owned_row(store._read(cursor, _SELECT_RETAINED, (planner_transaction_id,), work),
        _RETAINED_FIELDS, _RETAINED_BODIES, work)
    store._match(retained, {name: request[name] for name in (
        "planner_transaction_id", "plan_protocol", "retained_record_digest",
        "planner_key_digest", "verifier_key_digest", "source_revision")}, work)
    ack = _owned_row(store._read(cursor, _SELECT_ACK, (intent_id,), work),
        _ACK_FIELDS, _ACK_BODIES, work)
    store._match(ack, {"ack_envelope_id": ack_id, **{name: request[name] for name in (
        "intent_envelope_id", "configuration_digest", "generation_sequence",
        "generation_digest", "source_revision")}}, work)
    return (_original(request, _REQUEST_BODIES[0], work),
        _original(request, _REQUEST_BODIES[1], work),
        _original(retained, _RETAINED_BODIES[0], work),
        _original(retained, _RETAINED_BODIES[1], work),
        _original(request, _REQUEST_BODIES[2], work),
        _original(ack, _ACK_BODIES[0], work))
