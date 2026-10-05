"""Canonical raw JIT originals, not membership or operation authority.

Native chunk bytes come only from the actual source codec after consumption.
Proof and counted inputs retain their raw original fields; decoding checks
closed framing, not their truth against independently admitted roots. The
compound owner must bind phase order, source request, original clock and every
real proof/fold. Canonical frame bytes are not SQL scalar-transport metrics.
No context, manifest, clock, SQL, store, new work or success verdict exists here.
"""
from __future__ import annotations

import json

from serverware import authority_complete_query_batch as batch
from serverware import authority_complete_read_write as read_write
from serverware import authority_contract as contract
from serverware import authority_index_heads as heads
from serverware import authority_indexed_mutation as indexed
from serverware import authority_jit_primary_chunks as chunks
from serverware import authority_primary_contract as primary_contract
from serverware import authority_revocation_wire as wire
from serverware.authority_index_contract import CountedNode, IndexLeaf, OpaqueSubtree
from serverware.authority_query_read_work import MAX_JSON_NODES


OPERATION = chunks.OPERATION
INDEX_SCHEMA = "serverware.policyAuthorityJitIndexedOriginal/v1"
MAX_CHUNK_BYTES = 2 * chunks.CHUNK_BYTES + 256
MAX_PROOF_BYTES = 128 * 1024
MAX_INDEX_BYTES = 4 * 1024 * 1024
_PROOF_SCHEMA = "serverware.policyAuthorityRadixMultiproof/v3"
_PROOF_FIELDS = frozenset({"schema", "table", "key", "keyDigest", "present", "rowDigest",
    "leafDigest", "rootRevision", "rootDigest", "siblings", "proofDigest"})
_LEVEL_FIELDS = frozenset({"depth", "pathPrefix", "selectedNibble", "childDigests"})
_INDEX_FIELDS = frozenset({"schema", "indexId", "indexRevision", "rootDigest", "rootCount", "frontier"})
_LEAF_FIELDS = frozenset({"kind", "key", "primaryKeyDigest", "primaryRowDigest"})
_OPAQUE_FIELDS = frozenset({"kind", "prefix", "digest", "count"})
_HEX = frozenset("0123456789abcdef")


class JitOriginalFrameError(ValueError):
    pass


def _require(value):
    if not value:
        raise JitOriginalFrameError("JIT original frame is not canonical source-bounded raw evidence")


def _closed(value, fields):
    _require(type(value) is dict and len(value) == len(fields)
        and all(type(name) is str for name in value) and set(value) == fields)


def _integer(value, maximum, minimum=0):
    _require(type(value) is int and minimum <= value <= maximum)


def _hex(value, length):
    _require(type(value) is str and len(value) == length
        and all(character in _HEX for character in value))


def _digest(value):
    _require(type(value) is str and len(value) == 71 and value.startswith("sha256:"))
    _hex(value[7:], 64)


def _capture(value, maximum, work):
    return batch._JSONCapture(batch._SharedLedger(work), maximum_bytes=maximum).visit(value)


def _encode(value, maximum, work):
    batch._SharedLedger(work)
    size, _ = work.prepare_encoding(value)
    _require(2 <= size <= maximum)
    raw = json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
        separators=(",", ":")).encode("ascii")
    _require(len(raw) == size)
    return raw


def _decode(raw, maximum, work):
    """Reuse the genuine bounded lexer/parser hooks, including array roots."""
    batch._SharedLedger(work)
    _require(type(raw) is bytes and 2 <= len(raw) <= maximum)
    # All three closed source shapes are at most four semantic levels deep.
    # Eight admits those shapes without creating an input-sized token graph.
    nodes, hooks = wire._preflight(raw, work, maximum_nodes=MAX_JSON_NODES, maximum_depth=8)
    work.charge(input_bytes=3 * len(raw), json_nodes=nodes + hooks)
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=wire._unique_object,
            parse_int=wire._parse_integer, parse_float=wire._reject_number,
            parse_constant=wire._reject_number)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise JitOriginalFrameError("JIT original frame is not bounded ASCII JSON") from exc
    canonical = _encode(value, maximum, work)
    work.charge(input_bytes=len(canonical) + len(raw))
    _require(canonical == raw)
    return value


def _chunk_rows(rows, work):
    _require(type(rows) is list and len(rows) <= 1)
    work.prepare_scan(rows)
    if rows:
        record = rows[0]
        _closed(record, chunks._RECORD_FIELDS)
        total, ordinal, offset, raw = (record["total_bytes"], record["chunk_ordinal"],
            record["chunk_offset"], record["chunk_hex"])
        _integer(total, chunks.MAX_ROW_NATIVE_BYTES, 2)
        _integer(ordinal, chunks.MAX_ROW_DATA_CHUNKS - 1)
        _integer(offset, chunks.MAX_ROW_NATIVE_BYTES - 1)
        _require(offset == ordinal * chunks.CHUNK_BYTES and offset < total)
        _hex(raw, 2 * min(chunks.CHUNK_BYTES, total - offset))
    return rows


def encode_consumed_chunk(codec, *, work) -> bytes:
    """Reconstruct the last actual SQL record; no caller ordinal/size input."""
    batch._SharedLedger(work)
    _require(type(codec) is chunks.JitPrimaryRowChunks)
    codec._local()
    _require(codec._active is False and codec._finished is False
        and type(codec._chunks) is list and len(codec._chunks) <= chunks.MAX_ROW_DATA_CHUNKS
        and type(codec._complete) is bool)
    count, size, total = codec.data_chunks, codec.native_bytes, codec._total
    _integer(count, chunks.MAX_ROW_DATA_CHUNKS)
    _integer(size, chunks.MAX_ROW_NATIVE_BYTES)
    _integer(total, chunks.MAX_ROW_NATIVE_BYTES)
    work.charge(input_bytes=512 + 64 * len(codec._chunks), json_nodes=16 + len(codec._chunks))
    _require(count == len(codec._chunks)
        and all(type(value) is bytes for value in codec._chunks))
    if total == 0:
        _require(codec.complete is True and count == size == 0)
        rows = []
    else:
        _require(total >= 2 and count > 0 and size == sum(len(value) for value in codec._chunks)
            and codec.complete == (size == total)
            and all(len(value) == min(chunks.CHUNK_BYTES, total - ordinal * chunks.CHUNK_BYTES)
                for ordinal, value in enumerate(codec._chunks)))
        last = codec._chunks[-1]
        # Actual immutable byte scan plus the newly allocated lowercase hex.
        work.charge(input_bytes=3 * len(last), json_nodes=1)
        rows = [{"total_bytes": total, "chunk_ordinal": count - 1,
            "chunk_offset": (count - 1) * chunks.CHUNK_BYTES, "chunk_hex": last.hex()}]
    return _encode(_chunk_rows(rows, work), MAX_CHUNK_BYTES, work)


def decode_chunk(raw, *, work) -> list:
    """Return raw []/[record]; only the actual codec can consume its next slot."""
    return _chunk_rows(_decode(raw, MAX_CHUNK_BYTES, work), work)


def _proof(value, work):
    _closed(value, _PROOF_FIELDS)
    work.prepare_scan(value)
    contracts = primary_contract.primary_table_contracts(OPERATION)
    _require(len(contracts) == 8 and type(value["table"]) is str)
    selected = tuple(item for item in contracts if item.table == value["table"])
    _require(len(selected) == 1 and len(selected[0].key_columns) == 1)
    _closed(value["key"], frozenset(selected[0].key_columns))
    key_value = value["key"][selected[0].key_columns[0]]
    _require(type(key_value) is str and 1 <= len(key_value) <= 1024 and "\x00" not in key_value)
    _require(work.prepare_utf8(key_value) <= 1024)
    _require(type(value["schema"]) is str and value["schema"] == _PROOF_SCHEMA
        and type(value["present"]) is bool)
    for name in ("keyDigest", "leafDigest", "rootDigest", "proofDigest"):
        _digest(value[name])
    if value["present"]:
        _digest(value["rowDigest"])
    else:
        _require(value["rowDigest"] is None)
    _integer(value["rootRevision"], (1 << 63) - 1)
    _require(type(value["siblings"]) is list and len(value["siblings"]) == 64)
    for depth, level in enumerate(value["siblings"]):
        _closed(level, _LEVEL_FIELDS)
        _integer(level["depth"], 63)
        _require(level["depth"] == depth)
        _hex(level["pathPrefix"], depth)
        _hex(level["selectedNibble"], 1)
        _require(type(level["childDigests"]) is list and len(level["childDigests"]) == 16)
        for digest in level["childDigests"]:
            _digest(digest)
    return value


def encode_proof(proof, *, work) -> bytes:
    owned = _capture(proof, MAX_PROOF_BYTES, work)
    return _encode(_proof(owned, work), MAX_PROOF_BYTES, work)


def decode_proof(raw, *, work) -> dict:
    return _proof(_decode(raw, MAX_PROOF_BYTES, work), work)


def _index_ids():
    identities = heads._jit_receipt_ids()
    _require(type(identities) is tuple and len(identities) == 12)
    return identities


def _frontier_limit():
    # Existing source operation geometry; not an enlarged transport allowance
    # or a replacement for the pending same-call owner's actual target set.
    return read_write._source_sizes(contract.operation_spec(OPERATION))[2]


def _index(value, work):
    _closed(value, _INDEX_FIELDS)
    _require(type(value["schema"]) is str and value["schema"] == INDEX_SCHEMA
        and type(value["indexId"]) is str and value["indexId"] in _index_ids())
    _integer(value["indexRevision"], (1 << 63) - 1)
    _integer(value["rootCount"], (1 << 63) - 1)
    _digest(value["rootDigest"])
    _require(value["indexRevision"] != 0 or value["rootCount"] == 0)
    _require(type(value["frontier"]) is list and len(value["frontier"]) <= _frontier_limit())
    work.prepare_scan(value)
    work.charge(input_bytes=512, json_nodes=16)
    root = CountedNode(value["rootDigest"], value["rootCount"])
    frontier = []
    for record in value["frontier"]:
        _require(type(record) is dict and type(record.get("kind")) is str)
        if record["kind"] == "leaf":
            _closed(record, _LEAF_FIELDS)
            work.prepare_copy((record["key"], record["primaryKeyDigest"], record["primaryRowDigest"]))
            node = IndexLeaf(record["key"], record["primaryKeyDigest"], record["primaryRowDigest"])
        else:
            _closed(record, _OPAQUE_FIELDS)
            _require(record["kind"] == "opaque")
            work.prepare_copy((record["prefix"], record["digest"], record["count"]))
            node = OpaqueSubtree(record["prefix"], record["digest"], record["count"])
        work.charge(json_nodes=2)
        frontier.append(node)
    return indexed.IndexedMutationInput(value["indexId"], value["indexRevision"], root, tuple(frontier))


def encode_index(index_input, *, work) -> bytes:
    batch._SharedLedger(work)
    _require(type(index_input) is indexed.IndexedMutationInput
        and type(index_input.index_root) is CountedNode and type(index_input.frontier) is tuple
        and len(index_input.frontier) <= _frontier_limit())
    work.prepare_copy((index_input.index_id, index_input.index_revision,
        index_input.index_root.digest, index_input.index_root.count))
    work.charge(input_bytes=512, json_nodes=16)
    frontier = []
    for node in index_input.frontier:
        if type(node) is IndexLeaf:
            work.prepare_copy((node.key, node.primary_key_digest, node.primary_row_digest))
            record = {"kind": "leaf", "key": node.key,
                "primaryKeyDigest": node.primary_key_digest, "primaryRowDigest": node.primary_row_digest}
        elif type(node) is OpaqueSubtree:
            work.prepare_copy((node.prefix, node.digest, node.count))
            record = {"kind": "opaque", "prefix": node.prefix, "digest": node.digest, "count": node.count}
        else:
            raise JitOriginalFrameError("JIT counted original has an unknown raw record type")
        work.charge(json_nodes=10)
        frontier.append(record)
    value = {"schema": INDEX_SCHEMA, "indexId": index_input.index_id,
        "indexRevision": index_input.index_revision, "rootDigest": index_input.index_root.digest,
        "rootCount": index_input.index_root.count, "frontier": frontier}
    # These are only structural constructors. No profile hash, head match or
    # genuine fold is invoked, and this reconstructed observation is discarded.
    _index(value, work)
    return _encode(value, MAX_INDEX_BYTES, work)


def decode_index(raw, *, work) -> indexed.IndexedMutationInput:
    return _index(_decode(raw, MAX_INDEX_BYTES, work), work)
