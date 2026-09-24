"""Immutable custody of original writer controls, not signature admission.

The fixed service composition genuinely authenticates original intent, relay
and detached bodies and checks measured policy before its database runner.
These private helpers store bytes and links; constructing their ordinary rows
does not authenticate a caller, enroll keys, grant execution or supply an ACK.
The owning operation performs both genuine retained replays in the same common
savepoint and derives final links only from those actual local results.
"""
from __future__ import annotations

from serverware import authority_contract as authority
from serverware import authority_revocation_writer_commitment as commitment
from serverware.authority_store import revocation_retention as store


_TABLE = "serverware_metadata." + authority.REVOCATION_WRITER_REQUEST_TABLE
_FIELDS = authority.REVOCATION_WRITER_REQUEST_COLUMNS
_DERIVED = frozenset({"retained_record_digest", "planner_key_digest", "verifier_key_digest"})
_SELECT = ("SELECT " + ", ".join(_FIELDS) + " FROM " + _TABLE
    + " WHERE intent_envelope_id = %s")
_INSERT = ("INSERT INTO " + _TABLE + " (" + ", ".join(_FIELDS)
    + ") VALUES (" + ", ".join(("%s",) * len(_FIELDS))
    + ") ON CONFLICT (intent_envelope_id) DO NOTHING")


def _prefix_on_work(*, intent_bytes, relay_bytes, historical_expectations_bytes,
        configuration_digest, generation_sequence, generation_digest,
        planned_at_epoch_ns, envelope_id, planner_transaction_id, work):
    """Materialize nineteen custody fields from fixed original-byte inputs.

    This is not a second signature verifier or a successful-receiver input.
    Two actual stable-ID frames, three actual body hashes and three real codecs
    debit the original work. IDs deliberately exclude configuration/key epochs.
    Fixed column scaffolding is not variable JSON work; later SQL parameter and
    returned-row copies and comparisons are separately charged at their sites.
    """
    commitment.capture._SharedLedger(work)
    commitment._raw(intent_bytes, commitment.MAX_CONTROL_BYTES)
    commitment._raw(relay_bytes, commitment.MAX_CONTROL_BYTES)
    commitment._raw(historical_expectations_bytes, commitment.MAX_HISTORY_BYTES)
    commitment._pins(configuration_digest, generation_sequence, generation_digest)
    commitment.plan.contract._integer(planned_at_epoch_ns, minimum=1)
    commitment.plan.contract._digest(envelope_id)
    commitment.plan.contract._digest(planner_transaction_id)
    intent_id = commitment._intent_id(envelope_id, planner_transaction_id, work)
    relay_id = commitment._relay_id(intent_id, work)
    prefix = {"intent_envelope_id": intent_id, "relay_envelope_id": relay_id,
        "execution_envelope_id": envelope_id, "planner_transaction_id": planner_transaction_id,
        "plan_protocol": store.retention.PLAN_PROTOCOL,
        "configuration_digest": configuration_digest, "generation_sequence": generation_sequence,
        "generation_digest": generation_digest, "planned_at_epoch_ns": planned_at_epoch_ns,
        "source_revision": authority.SOURCE_REVISION}
    for name, raw in (("exact_intent", intent_bytes), ("exact_relay", relay_bytes),
                      ("historical_expectations", historical_expectations_bytes)):
        prefix[name + "_base64url"] = store._encode(raw, work)
        prefix[name + "_bytes_digest"] = store.retention._bytes_digest(raw, work)
        prefix[name + "_byte_count"] = len(raw)
    return prefix


def _owned_request(row, prefix, work):
    """Reject unbounded or nonclosed driver data before its real copy."""
    if (type(row) is not dict or len(row) != len(_FIELDS)
            or any(type(name) is not str for name in row) or set(row) != set(_FIELDS)):
        raise store._error("revocation writer request row is not a closed object")
    for name, value in row.items():
        if name in _DERIVED:
            commitment.plan.contract._digest(value)
        else:
            expected = prefix[name]
            if (type(value) is not type(expected)
                    or type(value) is str and len(value) > len(expected)
                    or type(value) is int and not 1 <= value <= 2**63 - 1):
                raise store._error("revocation writer request scalar exceeds its independent bound")
    work.prepare_copy(row)
    return row.copy()


def _lookup(cursor, prefix, work):
    row = store._read(cursor, _SELECT, (prefix["intent_envelope_id"],), work)
    if row is None:
        return None
    owned = _owned_request(row, prefix, work)
    store._match(owned, prefix, work)
    return owned


def _complete_on_work(prefix, receipt, reservation, work):
    """Link only freshly obtained replay outputs, never skip either replay.

    No public or configured entry accepts these ordinary objects. This fixed
    post-replay materializer does not authenticate them on its own. A legacy
    planned parent may attach only at the exact signed/stored planned time.
    """
    store._match(receipt, {"plannerTransactionId": prefix["planner_transaction_id"],
        "planProtocol": prefix["plan_protocol"], "plannedAtEpochNs": prefix["planned_at_epoch_ns"]}, work)
    store._match(reservation, {"envelope_id": prefix["execution_envelope_id"],
        "planner_transaction_id": prefix["planner_transaction_id"], "status": "reserved",
        "source_revision": prefix["source_revision"]}, work)
    derived = {"retained_record_digest": receipt["retainedRecordDigest"],
        "planner_key_digest": receipt["plannerKeyDigest"], "verifier_key_digest": receipt["verifierKeyDigest"]}
    for value in derived.values():
        commitment.plan.contract._digest(value)
    # Bounded fixed column scaffolding, like the existing retained-row builder.
    return {**prefix, **derived}


def _persist(cursor, prefix, receipt, reservation, work, *, insert):
    if type(insert) is not bool:
        raise ValueError("revocation writer request insertion mode is not exact")
    expected = _complete_on_work(prefix, receipt, reservation, work)
    if insert:
        parameters = store._parameters(expected, _FIELDS, work)
        store._callback(work, cursor.execute, _INSERT, parameters)
    # Even a previously observed row is read and matched completely after both
    # real replays. Concurrent conflicts cannot turn DO NOTHING into success.
    row = _owned_request(store._read(cursor, _SELECT,
        (prefix["intent_envelope_id"],), work), prefix, work)
    store._match(row, expected, work)
    return row
