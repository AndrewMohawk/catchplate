"""Immutable signed custody ACK child, never execution or commit authority.

Only the fixed authenticated writer suffix calls this after both genuine
replays and the complete original-request readback in the same common scope.
Ordinary dictionaries here are not accepted proof tokens. The outer owner must
finish both transaction and connection exits before any returned bytes escape.
Concurrent missing-child attempts may both sign; uniqueness guarantees one
durable child, not globally exactly-once signing. An observed existing child
is verified and returned byte-for-byte without signing again.
"""
from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from serverware import authority_contract as authority
from serverware import authority_revocation_writer_acknowledgment as acknowledgment
from serverware.authority_store import revocation_retention as store


_TABLE = "serverware_metadata." + authority.REVOCATION_WRITER_ACK_TABLE
_FIELDS = authority.REVOCATION_WRITER_ACK_COLUMNS
_BODY_FIELDS = frozenset({"exact_intent_base64url", "exact_relay_base64url",
                          "historical_expectations_base64url"})
_SELECT = ("SELECT " + ", ".join(_FIELDS) + " FROM " + _TABLE
    + " WHERE intent_envelope_id = %s")
_INSERT = ("INSERT INTO " + _TABLE + " (" + ", ".join(_FIELDS)
    + ") VALUES (" + ", ".join(("%s",) * len(_FIELDS))
    + ") ON CONFLICT (intent_envelope_id) DO NOTHING")


def _request_fields(request_row):
    # The caller has already owned and matched the actual request row. Fixed
    # scalar projection scaffolding does not copy its three potentially large
    # bodies. The crypto component separately bounds and owns these scalars
    # before key callbacks; this helper manufactures no replay authority.
    columns = authority.REVOCATION_WRITER_REQUEST_COLUMNS
    if (type(request_row) is not dict or len(request_row) != len(columns)
            or any(type(name) is not str for name in request_row)
            or set(request_row) != set(columns)):
        raise store._error("revocation writer ACK requires the complete request row")
    result = {name: request_row[name] for name in columns if name not in _BODY_FIELDS}
    for name, value in result.items():
        if name in {"generation_sequence", "planned_at_epoch_ns"} or name.endswith("_byte_count"):
            if type(value) is not int or not 1 <= value <= 2**63 - 1:
                raise store._error("revocation writer ACK request integer is not bounded")
        elif type(value) is not str or not 1 <= len(value) <= 128:
            raise store._error("revocation writer ACK request text is not bounded")
    return result


def _prefix_on_work(request_fields, writer_response_spki_digest, work):
    store.retention.capture._SharedLedger(work)
    store.retention.plan.contract._digest(writer_response_spki_digest)
    return {"ack_envelope_id": acknowledgment._ack_id_on_work(request_fields["intent_envelope_id"], work),
        "intent_envelope_id": request_fields["intent_envelope_id"],
        "configuration_digest": request_fields["configuration_digest"],
        "generation_sequence": request_fields["generation_sequence"],
        "generation_digest": request_fields["generation_digest"],
        "writer_response_spki_digest": writer_response_spki_digest,
        "source_revision": request_fields["source_revision"]}


def _owned_row(row, prefix, work):
    if (type(row) is not dict or len(row) != len(_FIELDS)
            or any(type(name) is not str for name in row) or set(row) != set(_FIELDS)):
        raise store._error("revocation writer ACK row is not a closed object")
    count, encoded = row["exact_ack_byte_count"], row["exact_ack_base64url"]
    if (type(count) is not int or not 2 <= count <= acknowledgment.MAX_ACK_BYTES
            or type(encoded) is not str or len(encoded) != (4 * count + 2) // 3):
        raise store._error("revocation writer ACK transport exceeds its bound")
    store.retention.plan.contract._digest(row["exact_ack_bytes_digest"])
    for name, expected in prefix.items():
        value = row[name]
        if (type(value) is not type(expected)
                or type(value) is str and len(value) > len(expected)
                or type(value) is int and not 1 <= value <= 2**63 - 1):
            raise store._error("revocation writer ACK scalar exceeds its independent bound")
    work.prepare_copy(row)
    return row.copy()


def _verify_row(row, prefix, request_fields, writer_public_key, work):
    owned = _owned_row(row, prefix, work)
    store._match(owned, prefix, work)
    raw = store._decode(owned["exact_ack_base64url"], owned["exact_ack_byte_count"],
        acknowledgment.MAX_ACK_BYTES, work)
    store._match(owned, {"exact_ack_bytes_digest": store.retention._bytes_digest(raw, work)}, work)
    acknowledgment._verify_on_work(acknowledgment_bytes=raw, request_fields=request_fields,
        writer_public_key=writer_public_key,
        expected_writer_spki_digest=prefix["writer_response_spki_digest"], work=work)
    return raw, owned


def _persist(cursor, request_row, *, writer_private_key, writer_public_key,
        writer_response_spki_digest, work):
    """Observe/verify or sign/insert/readback, with no independent transaction."""
    if (not isinstance(writer_private_key, Ed25519PrivateKey)
            or not isinstance(writer_public_key, Ed25519PublicKey)):
        raise ValueError("revocation writer ACK requires held Ed25519 key handles")
    request_fields = _request_fields(request_row)
    prefix = _prefix_on_work(request_fields, writer_response_spki_digest, work)
    existing = store._read(cursor, _SELECT, (prefix["intent_envelope_id"],), work)
    if existing is not None:
        raw, _ = _verify_row(existing, prefix, request_fields, writer_public_key, work)
        return raw
    raw = acknowledgment._sign_on_work(request_fields=request_fields,
        writer_private_key=writer_private_key, writer_public_key=writer_public_key,
        expected_writer_spki_digest=writer_response_spki_digest, work=work)
    expected = {**prefix, "exact_ack_base64url": store._encode(raw, work),
        "exact_ack_bytes_digest": store.retention._bytes_digest(raw, work),
        "exact_ack_byte_count": len(raw)}
    parameters = store._parameters(expected, _FIELDS, work)
    store._callback(work, cursor.execute, _INSERT, parameters)
    # DO NOTHING is not success: read, genuinely verify and compare all ten
    # stored columns, including exact bytes. Return the readback, never a
    # speculative signed buffer. Deferred conflicts still belong to the outer
    # transaction and must abort without a returned ACK.
    stored, owned = _verify_row(store._read(cursor, _SELECT,
        (prefix["intent_envelope_id"],), work), prefix, request_fields, writer_public_key, work)
    store._match(owned, expected, work)
    return stored
