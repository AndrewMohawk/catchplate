"""Lossless QueryRead transport for the two fixed evidence-admission plans.

These codecs own and reconstruct ordinary source observations, not proofs or
executable query declarations. Every exact-PK observation has one address,
including its absence placeholder. The genuine replay must still regenerate
the fixed query recipe and invoke authority_query_reads._validate_query_reads
against its actually proved selected rows. Embedded JSON stays opaque here.

All copying, ASCII conversion and constructor scans use the caller's existing
work. No SQL, registry, planner import, signature or new allowance is provided.
"""
from __future__ import annotations

from serverware import authority_complete_query_batch as capture
from serverware import authority_query_reads as reads
from serverware import authority_revocation_plan_contract as shape
from serverware import authority_revocation_read_write as mixed


_READ_FIELDS = frozenset({"queryId", "declaredQueryJson", "resolvedQueryJson",
    "addresses", "returnedRowCount"})
_ADDRESS_FIELDS = frozenset({"table", "keyJson", "keyDigest", "present"})


class WebAuthnEvidencePlanReadsError(ValueError):
    pass


def _maximum(maximum_rows, work):
    capture._SharedLedger(work)
    if type(maximum_rows) is not int or maximum_rows not in (3, 5):
        raise WebAuthnEvidencePlanReadsError("evidence query reads require a fixed source row ceiling")


def _shape(values, maximum_rows):
    if type(values) is not list or not 1 <= len(values) <= maximum_rows:
        raise WebAuthnEvidencePlanReadsError("evidence query read inventory is not a bounded exact list")
    for record in values:
        shape._object(record, _READ_FIELDS, "evidence query observation")
        shape._text(record["queryId"], reads.MAX_QUERY_ID_BYTES)
        for name in ("declaredQueryJson", "resolvedQueryJson"):
            shape._text(record[name], reads.MAX_BOOKKEEPING_BYTES, minimum=2)
        shape._integer(record["returnedRowCount"], 1)
        addresses = record["addresses"]
        if type(addresses) is not list or len(addresses) != 1:
            raise WebAuthnEvidencePlanReadsError("evidence PK observation requires exactly one address")
        address = addresses[0]
        shape._object(address, _ADDRESS_FIELDS, "evidence query address")
        shape._text(address["table"], 128)
        shape._text(address["keyJson"], reads.MAX_BOOKKEEPING_BYTES, minimum=2)
        shape._digest(address["keyDigest"])
        if type(address["present"]) is not bool:
            raise WebAuthnEvidencePlanReadsError("evidence query address presence is not an exact boolean")


def _encode_reads_on_work(query_reads, *, maximum_rows, work):
    """Return owned JSON records from actual immutable QueryRead observations."""
    _maximum(maximum_rows, work)
    if type(query_reads) is not tuple or not 1 <= len(query_reads) <= maximum_rows:
        raise WebAuthnEvidencePlanReadsError("evidence query observations are not a bounded exact tuple")
    # Admit the local inventories before the generic copier can walk them.
    # _copy_read then prepays the actual constructor scans and revalidates
    # every exact immutable scalar/byte field before any ASCII conversion.
    for record in query_reads:
        if (type(record) is not reads.QueryRead or type(record.addresses) is not tuple
                or len(record.addresses) != 1 or type(record.returned_row_count) is not int
                or not 0 <= record.returned_row_count <= 1):
            raise WebAuthnEvidencePlanReadsError("evidence PK observation has an invalid local shape")
    owned = tuple(reads._copy_read(record, work) for record in query_reads)
    raw_bytes = sum(len(record.declared_query_json) + len(record.resolved_query_json)
        + len(record.addresses[0].key_json) for record in owned)
    # Reserve all three real ASCII decodes per record before making any buffer.
    work.charge(input_bytes=raw_bytes)
    values = [{"queryId": record.query_id,
        "declaredQueryJson": record.declared_query_json.decode("ascii"),
        "resolvedQueryJson": record.resolved_query_json.decode("ascii"),
        "addresses": [{"table": record.addresses[0].table,
            "keyJson": record.addresses[0].key_json.decode("ascii"),
            "keyDigest": record.addresses[0].key_digest, "present": record.addresses[0].present}],
        "returnedRowCount": record.returned_row_count} for record in owned]
    _shape(values, maximum_rows)
    return capture._JSONCapture(capture._SharedLedger(work)).visit(values)


def _decode_reads_on_work(values, *, maximum_rows, work):
    """Reconstruct genuine records, without adopting their query meaning."""
    _maximum(maximum_rows, work)
    _shape(values, maximum_rows)
    owned = capture._JSONCapture(capture._SharedLedger(work)).visit(values)
    # This existing generic restoration body charges each strict ASCII encode
    # and calls the actual metered QueryRead/QueryReadAddress constructors.
    # It does not invoke the surrounding revocation-only proof machinery.
    return mixed._restore_reads(owned, work)
