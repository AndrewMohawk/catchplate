"""Seven source-ordered JIT rows, each authenticated before advancing.

This is a private compound component, not a clock or allowance allocator. The
parent supplies each actual child work meter, retains raw SQL/transport pages,
and owns native snapshot/source/current-root admission. No receipt key can be
chosen here: the completed seven-row context must next enter the genuine
three-stage ES256 computation before the eighth absence read is possible.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import os
import threading

from serverware import authority_jit_assertion_acquisition as source
from serverware import authority_jit_primary_chunks as chunks
from serverware import authority_primary_original_reader as primary_reader
from serverware.authority_query_read_work import _ValidationWork


MAX_PROOF_BYTES = 128 * 1024  # One fixed-depth v3 proof and a <=1024-byte source PK.
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class JitPrimaryRowsError(ValueError):
    pass


def _require(condition):
    if not condition:
        raise JitPrimaryRowsError("JIT primary rows lost their source order or original custody")


def _metrics(work):
    _require(type(work) is _ValidationWork)
    source.batch._SharedLedger(work)
    return work.hash_work, work.input_bytes, work.json_nodes


def _limits(work):
    return work.limits.max_hashes, work.limits.max_input_bytes, work.limits.max_json_nodes


def _pins(*values):
    _require(all(type(value) in (str, int, bool) or value is None for value in values))
    return tuple((type(value), value) for value in values)


def _digest(value, work):
    raw = work.wire(value)
    work.charge(hashes=1, input_bytes=len(raw))
    return len(raw), hashlib.sha256(raw).digest()


@dataclass(frozen=True, slots=True)
class _OriginalRows:
    """Same-call raw outputs, never an accepted authority/result input."""

    request: dict
    context: source.core.KernelContext
    business_before_roots: tuple
    authorization_before_roots: tuple
    before_proofs: tuple
    queries: tuple
    native_bytes: int
    data_chunks: int
    selected_bytes: int


class _JitPrimaryRows:
    def __init__(self, *, request, business_before_roots, authorization_before_roots,
            database_cutoff_us, work):
        _require(type(work) is _ValidationWork and type(request) is dict
            and type(business_before_roots) is tuple and len(business_before_roots) == 4
            and type(authorization_before_roots) is tuple and len(authorization_before_roots) == 4
            and type(database_cutoff_us) is int and 0 <= database_cutoff_us < 2**63)
        self._process = os.getpid(), threading.get_ident()
        self._failed = self._busy = self._closed = False
        self._meters, self._acquisition_meters = [], []
        self._anchors = self._pending_chunk_work = None
        self._proof_borrowed = False
        self._phase, self._slot = "capture", 0
        self._codec = self._codec_held = self._selection = self._selection_digest = None
        self._ack_chunks = self._ack_bytes = 0
        self._native_bytes = self._data_chunks = 0
        self._selected_bytes = 2
        self._rows, self._proofs, self._records, self._row_digests = [], [], [], []
        with self._step("capture", work):
            self._request = source.reads._CopyBudget(work).copy(request)
            source._request(self._request, work)
            source.receipt._arguments(self._request["arguments"])
            self._request_digest = _digest(self._request, work)
            self._queries = source.reads._snapshot_queries(source.OPERATION,
                source.receipt.queries(self._request["arguments"]), work=work)
            self._contracts = source.primary_contract.primary_table_contracts(source.OPERATION)
            _require(len(self._queries) == 7 and len(self._contracts) == 8)
            partitions = []
            for supplied, root_class in ((business_before_roots, "business"),
                    (authorization_before_roots, "authorization")):
                owned_roots = []
                for actual in supplied:
                    _require(type(actual) is primary_reader.primary.PrimaryRoot)
                    values = source.reads._CopyBudget(work).copy((actual.table, actual.root_revision,
                        actual.root_digest, actual.leaf_count))
                    work.charge(hashes=66, json_nodes=5)
                    owned_roots.append(primary_reader.primary.PrimaryRoot(*values))
                _require(tuple(item.table for item in owned_roots)
                    == tuple(item.table for item in self._contracts if item.root_class == root_class))
                partitions.append(tuple(owned_roots))
            self._business, self._authorization = partitions
            self._roots = tuple(sorted((*self._business, *self._authorization), key=lambda item: item.table))
            _require(tuple(item.table for item in self._roots)
                == tuple(item.table for item in self._contracts))
            try:
                self._now = _EPOCH + timedelta(microseconds=database_cutoff_us)
            except OverflowError as exc:
                raise JitPrimaryRowsError("JIT original cutoff is outside UTC datetime") from exc
            work.charge(input_bytes=32768, json_nodes=1024)
            self._anchors = self._anchor_pins()
            self._phase = "row-open"

    def _anchor_pins(self):
        queries = []
        for query in self._queries:
            _require(type(query) is source.core.BoundedQuery and type(query.absent_key) is dict
                and len(query.absent_key) == 1 and len(query.predicates) == len(query.order_by) == 1)
            queries.append((id(query), id(query.absent_key), id(query.predicates), id(query.order_by),
                tuple(_pins(key, value) for key, value in query.absent_key.items()),
                tuple((id(item), _pins(item.column, item.operator, item.value)) for item in query.predicates),
                tuple((id(item), _pins(item.column, item.descending)) for item in query.order_by),
                _pins(query.query_id, query.table, query.maximum_rows, query.work_units,
                    query.require_absence, query.proof_primitive, query.exact_page, query.page_size,
                    query.secondary_index_name, query.continuation_token_digest)))
        return (id(self._request), id(self._queries), id(self._contracts), id(self._roots), id(self._now),
            id(self._business), id(self._authorization),
            tuple(id(root) for root in (*self._business, *self._authorization)),
            self._request_digest, tuple(queries),
            tuple((id(root), _pins(root.table, root.root_revision, root.root_digest, root.leaf_count))
                for root in self._roots),
            tuple((id(item), id(item.key_columns), _pins(item.table, *item.key_columns,
                item.root_class, item.write_access)) for item in self._contracts))

    def _local(self):
        _require(type(self) is _JitPrimaryRows and not self._failed and not self._closed
            and self._process == (os.getpid(), threading.get_ident()))
        if self._anchors is not None:
            _require(self._anchor_pins() == self._anchors)
        for record in (*self._meters, *self._acquisition_meters):
            work, limits, maximum, previous = record
            current = _metrics(work)
            _require(work.limits is limits and _limits(work) == maximum
                and all(actual >= before for actual, before in zip(current, previous)))
            record[3] = current

    @contextmanager
    def _step(self, phase, work, *, chunk_ack=False):
        try:
            self._local()
            _require(not self._busy and self._phase == phase and type(work) is _ValidationWork
                and all(work is not item[0] for item in self._meters)
                and (self._pending_chunk_work is work if chunk_ack else self._pending_chunk_work is None)
                and (chunk_ack or all(work is not item[0] for item in self._acquisition_meters)))
            self._meters.append([work, work.limits, _limits(work), _metrics(work)])
            work.charge(input_bytes=16384, json_nodes=512)
            self._busy = True
            yield
            self._local()
        except BaseException:
            self._failed = True
            raise
        finally:
            self._busy = False

    @property
    def next_stage(self):
        self._local()
        return self._phase, self._slot

    def begin_row(self, work):
        with self._step("row-open", work):
            _require(self._slot < 7 and self._codec is None and self._selection is None)
            self._codec = chunks.JitPrimaryRowChunks(self._queries[self._slot], work=work)
            self._codec_held = self._codec
            self._ack_chunks = self._ack_bytes = 0
            self._proof_borrowed = False
            self._phase = "row-chunk"
            actual = self._codec
        return actual

    def _chunk_progress(self, work):
        codec = self._codec
        _require(type(codec) is chunks.JitPrimaryRowChunks and codec is self._codec_held)
        # A source physical reader has consumed exactly one chunk, or the
        # source replay method below has consumed exactly one retained page.
        count, size = codec.data_chunks, codec.native_bytes
        if count == 0:
            _require(self._ack_chunks == 0 and self._ack_bytes == 0
                and size == 0 and codec.complete is True)
        else:
            _require(count == self._ack_chunks + 1 and size > self._ack_bytes
                and size - self._ack_bytes <= chunks.CHUNK_BYTES)
        _require(self._data_chunks + count <= chunks.MAX_TOTAL_DATA_CHUNKS
            and self._native_bytes + size <= chunks.MAX_TOTAL_NATIVE_BYTES)
        work.charge(input_bytes=64, json_nodes=8)
        self._ack_chunks, self._ack_bytes = count, size
        if codec.complete:
            self._phase = "row-decode"

    def observe_acquired_chunk(self, work):
        """Join the actual reader's same codec; no caller count or length."""
        with self._step("row-chunk", work, chunk_ack=True):
            self._chunk_progress(work)
            self._pending_chunk_work = None

    @contextmanager
    def _acquisition_binding(self, *, kind, work):
        """Borrow only held source originals during one physical child stage.

        Chunk progress must be acknowledged immediately on this same meter.
        Proof acquisition leaves admission pending and can happen only once;
        the independently genuine admission needs a distinct original meter.
        The parent still owns all actual physical counters and the clock.
        """
        try:
            self._local()
            _require(type(kind) is str and kind in ("chunk", "proof") and not self._busy
                and self._pending_chunk_work is None and type(work) is _ValidationWork
                and all(work is not item[0] for item in (*self._meters, *self._acquisition_meters))
                and self._phase == ("row-chunk" if kind == "chunk" else "row-proof"))
            work.charge(input_bytes=32768, json_nodes=1024)
            self._acquisition_meters.append([work, work.limits, _limits(work), _metrics(work)])
            original = (self._phase, self._slot, self._codec, self._codec_held, self._selection,
                self._selection_digest, self._ack_chunks, self._ack_bytes, self._native_bytes,
                self._data_chunks, self._selected_bytes, self._rows, self._proofs,
                self._records, self._row_digests)
            lengths = tuple(len(value) for value in original[-4:])
            if kind == "chunk":
                _require(type(self._codec) is chunks.JitPrimaryRowChunks
                    and self._codec is self._codec_held and not self._codec.complete
                    and self._codec.data_chunks == self._ack_chunks
                    and self._codec.native_bytes == self._ack_bytes)
                borrowed = self._codec
            else:
                _require(not self._proof_borrowed and type(self._selection) is dict)
                root = next(item for item in self._roots if item.table == self._queries[self._slot].table)
                borrowed = self._selection, root
                self._proof_borrowed = True
            self._busy = True
            yield borrowed
            current = (self._phase, self._slot, self._codec, self._codec_held, self._selection,
                self._selection_digest, self._ack_chunks, self._ack_bytes, self._native_bytes,
                self._data_chunks, self._selected_bytes, self._rows, self._proofs,
                self._records, self._row_digests)
            _require(all(actual is held for actual, held in zip(current, original, strict=True))
                and tuple(len(value) for value in current[-4:]) == lengths)
            self._local()
            if kind == "chunk":
                self._pending_chunk_work = work
            else:
                _require(self._proof_borrowed is True)
        except BaseException:
            self._failed = True
            raise
        finally:
            self._busy = False

    def consume_chunk(self, rows, work):
        """Raw replay counterpart; no byte/hash descriptor can replace rows."""
        with self._step("row-chunk", work):
            _require(type(self._codec) is chunks.JitPrimaryRowChunks and self._codec is self._codec_held
                and self._codec.data_chunks == self._ack_chunks
                and self._codec.native_bytes == self._ack_bytes)
            self._codec.accept(rows, work=work)
            self._chunk_progress(work)

    def decode_row(self, work):
        with self._step("row-decode", work):
            codec, query = self._codec, self._queries[self._slot]
            _require(codec is self._codec_held and codec.complete and codec.data_chunks == self._ack_chunks
                and codec.native_bytes == self._ack_bytes)
            row = codec.finish(work=work)
            key = query.absent_key
            work.prepare_copy(key)
            key_bytes = work.wire(key)
            table_bytes = query.table.encode("ascii")
            domain = "serverware.policyAuthorityBusinessKey/v1"
            work.charge(hashes=1, input_bytes=len(domain) + 17 + len(table_bytes) + len(key_bytes), json_nodes=13)
            self._selection = dict(table=query.table, key=dict(key),
                keyDigest=source.core.framed_digest(domain, table_bytes, key_bytes),
                present=row is not None, row=row, contractSelector=None)
            self._selection_digest = _digest(self._selection, work)
            proposed = self._selected_bytes + self._selection_digest[0] + int(self._slot > 0)
            _require(proposed <= source.authority.MAX_REQUEST_BYTES)
            self._native_bytes += self._ack_bytes
            self._data_chunks += self._ack_chunks
            self._phase = "row-proof"
            # Only this raw original is exposed for the actual physical proof
            # reader. Its exact canonical digest is held before SQL callbacks.
            selected = self._selection
        return selected

    def admit_proof(self, before_proof, work):
        with self._step("row-proof", work):
            _require(type(before_proof) is dict and type(self._selection) is dict)
            _require(_digest(self._selection, work) == self._selection_digest)
            size, _ = work.measure(before_proof)
            _require(size <= MAX_PROOF_BYTES)
            proof = source.reads._CopyBudget(work).copy(before_proof)
            query = self._queries[self._slot]
            contract = next(item for item in self._contracts if item.table == query.table)
            root = next(item for item in self._roots if item.table == query.table)
            actual = primary_reader._membership(self._selection, proof, root, contract, work)
            _require(len(actual.selected_rows) == len(actual.before_proofs) == 1)
            selected, proof = actual.selected_rows[0], actual.before_proofs[0]
            source.reads._address(selected, source.reads._CopyBudget(work))
            work.prepare_comparison(selected["key"], query.absent_key)
            _require(selected["table"] == query.table and selected["key"] == query.absent_key)
            record = source.reads._capture_query_read(source.OPERATION, query, resolved_query=query,
                ordered_selected_rows=(selected,), returned_row_count=int(selected["present"]), work=work)
            _, checked = source.reads._validate_query_reads(source.OPERATION, queries=(query,),
                query_reads=(record,), selected_rows=(selected,), work=work)
            _require(len(checked) == 1)
            # Digest was made from the actual source-decoded row. The genuine
            # engine-owned copy must still be exactly that original.
            row_digest = _digest(selected, work)
            _require(row_digest == self._selection_digest)
            work.charge(input_bytes=64, json_nodes=12)
            self._rows.append(selected)
            self._proofs.append(proof)
            self._records.append(checked[0])
            self._row_digests.append(row_digest)
            self._selected_bytes += row_digest[0] + int(self._slot > 0)
            self._slot += 1
            self._codec = self._codec_held = self._selection = self._selection_digest = None
            self._phase = "finish" if self._slot == 7 else "row-open"

    def finish(self, work):
        with self._step("finish", work):
            _require(self._slot == 7 and len(self._rows) == len(self._proofs) == len(self._records) == 7
                and self._data_chunks <= chunks.MAX_TOTAL_DATA_CHUNKS
                and self._native_bytes <= chunks.MAX_TOTAL_NATIVE_BYTES)
            for row, expected in zip(self._rows, self._row_digests):
                _require(_digest(row, work) == expected)
            _require(_digest(self._request, work) == self._request_digest)
            size, _ = work.measure(tuple(self._rows))
            _require(size == self._selected_bytes <= source.authority.MAX_REQUEST_BYTES)
            _, records = source.reads._validate_query_reads(source.OPERATION, queries=self._queries,
                query_reads=tuple(self._records), selected_rows=tuple(self._rows), work=work)
            work.prepare_copy(self._rows)
            ordered = tuple(sorted(self._rows, key=lambda row: (row["table"], row["keyDigest"])))
            work.charge(input_bytes=512, json_nodes=32)
            context = source.core.KernelContext(source.OPERATION, self._request["arguments"],
                ordered, self._now, self._request["requestDigest"], query_reads=records)
            result = _OriginalRows(self._request, context, self._business, self._authorization, tuple(self._proofs),
                self._queries, self._native_bytes, self._data_chunks, self._selected_bytes)
        self._closed = True
        return result
