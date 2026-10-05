"""Join a genuine seven-row receipt computation to its eighth absence proof.

Private same-call composition only: no supplied receipt digest/result, clock,
work allocator, SQL, current-root admission or native snapshot is created here.
The parent supplies three distinct original child meters and retains actual
physical evidence. The later full transition independently recomputes ES256.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import os
import threading

from serverware import authority_jit_assertion_transition as semantics
from serverware import authority_jit_primary_rows as primary_rows
from serverware.authority_query_read_work import _ValidationWork


source = primary_rows.source
reads, core, primary_reader = source.reads, source.core, primary_rows.primary_reader
STAGES = ("capture", "admit", "finish")


class JitReceiptAbsenceError(ValueError):
    pass


def _require(value):
    if not value:
        raise JitReceiptAbsenceError("JIT receipt absence lost its original computation or proof")


def _meter(record):
    _require(type(record) is list and len(record) == 4)
    work, limits, maximum, previous = record
    current = primary_rows._metrics(work)
    _require(work.limits is limits and primary_rows._limits(work) == maximum
        and all(actual >= before for actual, before in zip(current, previous, strict=True)))
    return work, limits, maximum, current


def _closed_sources(rows, receipt):
    process = os.getpid(), threading.get_ident()
    _require(type(rows) is primary_rows._JitPrimaryRows
        and type(receipt) is semantics._JitAssertionReceipt)
    for owner in (rows, receipt):
        _require(owner._closed is True and owner._failed is False and owner._busy is False
            and owner._process == process)
    _require(rows._phase == "finish" and rows._slot == 7
        and len(rows._rows) == len(rows._proofs) == len(rows._records) == len(rows._row_digests) == 7
        and rows._codec is None and rows._selection is None and rows._pending_chunk_work is None
        and rows._anchor_pins() == rows._anchors
        and len(rows._meters) == 23 + rows._data_chunks + sum(not item["present"] for item in rows._rows))
    _require(receipt._phase == len(semantics.RECEIPT_STAGES) and len(receipt._meters) == 3
        and type(receipt._context) is core.KernelContext and type(receipt._receipt) is dict
        and receipt._mutations is None and receipt._selected is None and receipt._entries is None
        and receipt._originals is None
        and all(actual is held for actual, held in zip(receipt._state(), receipt._held, strict=True)))


@dataclass(frozen=True, slots=True)
class _ReceiptAbsenceOriginals:
    """Raw originals for the subsequent genuine full transition, not authority."""

    request: dict
    context: core.KernelContext
    business_before_roots: tuple
    authorization_before_roots: tuple
    before_proofs: tuple
    queries: tuple


class _JitReceiptAbsence:
    def __init__(self, *, rows, receipt_owner, work):
        _require(type(work) is _ValidationWork)
        # Reserve the bounded closed-source anchors and upstream-meter roster
        # before constructing either. The capture stage separately reserves
        # its own ordinary local checks and charges every full-graph walk.
        work.charge(input_bytes=65536, json_nodes=2048)
        self._process = os.getpid(), threading.get_ident()
        self._failed = self._busy = self._closed = False
        self._phase = 0
        self._meters, self._upstream_meters = [], []
        self._rows_owner, self._receipt_owner = rows, receipt_owner
        self._query = self._root = self._query_pin = None
        _closed_sources(rows, receipt_owner)
        # Native chunk work legitimately appears in both the acquisition and
        # acknowledgement inventories. Retain every record without inventing
        # another allowance, or requiring those two uses to be distinct.
        originals = (*rows._meters, *rows._acquisition_meters, *receipt_owner._meters)
        for record in originals:
            self._upstream_meters.append([record, *_meter(record)])
        with self._stage(0, work):
            _require(primary_rows._digest(rows._request, work) == rows._request_digest)
            self._request = reads._CopyBudget(work).copy(rows._request)
            context = receipt_owner._context
            _require(context.operation == source.OPERATION
                and context.request_digest == self._request["requestDigest"]
                and context.database_now == rows._now and len(context.selected_rows) == 7
                and len(context.query_reads) == 7)
            work.prepare_comparison(context.arguments, self._request["arguments"])
            _require(context.arguments == self._request["arguments"])
            by_table = {item["table"]: item for item in context.selected_rows}
            _require(len(by_table) == 7)
            for original, expected in zip(rows._rows, rows._row_digests, strict=True):
                _require(primary_rows._digest(original, work) == expected
                    and original["table"] in by_table
                    and primary_rows._digest(by_table[original["table"]], work) == expected)
            self._selected = reads._CopyBudget(work).copy(tuple(rows._rows))
            self._proofs = reads._CopyBudget(work).copy(tuple(rows._proofs))
            self._records = tuple(reads._copy_read(item, work) for item in rows._records)
            receipt_records = tuple(reads._copy_read(item, work) for item in context.query_reads)
            work.charge(input_bytes=sum(reads._read_size(item)
                for item in (*self._records, *receipt_records)), json_nodes=32)
            _require(self._records == receipt_records)
            self._queries = reads._snapshot_queries(source.OPERATION, rows._queries, work=work)
            reads._validate_query_reads(source.OPERATION, queries=self._queries,
                query_reads=self._records, selected_rows=tuple(self._selected), work=work)
            roots = []
            for actual in rows._roots:
                _require(type(actual) is primary_reader.primary.PrimaryRoot)
                values = reads._CopyBudget(work).copy((actual.table, actual.root_revision,
                    actual.root_digest, actual.leaf_count))
                work.charge(hashes=66, json_nodes=5)
                roots.append(primary_reader.primary.PrimaryRoot(*values))
            self._roots = tuple(roots)
            contracts = source.primary_contract.primary_table_contracts(source.OPERATION)
            _require(tuple(item.table for item in self._roots) == tuple(item.table for item in contracts))
            by_class = {item.table: item.root_class for item in contracts}
            self._business = tuple(item for item in self._roots if by_class[item.table] == "business")
            self._authorization = tuple(item for item in self._roots if by_class[item.table] == "authorization")
            _require(len(self._business) == len(self._authorization) == 4)
            self._contract = next(item for item in contracts if item.table == source.receipt.RECEIPT_TABLE)
            self._root = next(item for item in self._roots if item.table == self._contract.table)
            digest = receipt_owner._receipt["assertion_receipt_digest"]
            core.require_digest(digest, "genuinely computed JIT receipt")
            _require(receipt_owner._receipt["verified_at"] == context.database_now.isoformat())
            self._query = reads._snapshot_queries(source.OPERATION,
                (source.receipt.receipt_query(digest),), work=work)[0]
            self._query_pin = self._pins()
            self._now = rows._now
            self._absence = self._absence_proof = self._absence_record = None

    def _pins(self):
        query, root = self._query, self._root
        _require(type(query) is core.BoundedQuery and type(query.absent_key) is dict
            and len(query.absent_key) == len(query.predicates) == len(query.order_by) == 1
            and type(root) is primary_reader.primary.PrimaryRoot)
        return (id(query), id(query.absent_key), id(query.predicates), id(query.order_by),
            tuple(primary_rows._pins(key, value) for key, value in query.absent_key.items()),
            tuple((id(item), primary_rows._pins(item.column, item.operator, item.value))
                for item in query.predicates),
            tuple((id(item), primary_rows._pins(item.column, item.descending)) for item in query.order_by),
            primary_rows._pins(query.query_id, query.table, query.maximum_rows, query.work_units,
                query.require_absence, query.proof_primitive, query.exact_page, query.page_size,
                query.secondary_index_name, query.continuation_token_digest),
            id(root), primary_rows._pins(root.table, root.root_revision, root.root_digest, root.leaf_count))

    def _local(self):
        _require(type(self) is _JitReceiptAbsence and not self._failed and not self._closed
            and self._process == (os.getpid(), threading.get_ident()))
        _closed_sources(self._rows_owner, self._receipt_owner)
        if self._query_pin is not None:
            _require(self._pins() == self._query_pin)
        for held in self._upstream_meters:
            record, work, limits, maximum, previous = held
            current = _meter(record)
            _require(current[0] is work and current[1] is limits and current[2] == maximum
                and all(actual >= before for actual, before in zip(current[3], previous, strict=True)))
            held[4] = current[3]
        for record in self._meters:
            record[3] = _meter(record)[3]

    @contextmanager
    def _stage(self, ordinal, work):
        try:
            self._local()
            _require(self._phase == ordinal and not self._busy and type(work) is _ValidationWork
                and all(work is not item[0] for item in self._meters)
                and all(work is not item[1] for item in self._upstream_meters))
            self._meters.append([work, work.limits, primary_rows._limits(work), primary_rows._metrics(work)])
            # Fixed source anchors and bounded meter inventories, not full-row
            # canonical work (which is charged separately at its actual walks).
            work.charge(input_bytes=65536, json_nodes=2048)
            self._busy = True
            yield
            self._local()
            self._phase += 1
        except BaseException:
            self._failed = True
            raise
        finally:
            self._busy = False

    def query_inputs(self):
        """Raw fixed query/root for actual acquisition; never an absence claim."""
        try:
            self._local()
            _require(self._phase == 1 and not self._busy)
            return self._query, self._root
        except BaseException:
            self._failed = True
            raise

    def admit(self, *, selected_row, before_proof, work):
        with self._stage(1, work):
            _require(type(selected_row) is dict and set(selected_row) == reads._SELECTED_FIELDS
                and selected_row["table"] == self._query.table and selected_row["present"] is False
                and selected_row["row"] is None and selected_row["contractSelector"] is None)
            work.prepare_comparison(selected_row["key"], self._query.absent_key)
            _require(selected_row["key"] == self._query.absent_key)
            selected = reads._CopyBudget(work).copy(selected_row)
            proof = reads._CopyBudget(work).copy(before_proof)
            actual = primary_reader._membership(selected, proof, self._root, self._contract, work)
            _require(len(actual.selected_rows) == len(actual.before_proofs) == 1)
            selected, proof = actual.selected_rows[0], actual.before_proofs[0]
            record = reads._capture_query_read(source.OPERATION, self._query, resolved_query=self._query,
                ordered_selected_rows=(selected,), returned_row_count=0, work=work)
            _, checked = reads._validate_query_reads(source.OPERATION, queries=(self._query,),
                query_reads=(record,), selected_rows=(selected,), work=work)
            _require(len(checked) == 1)
            self._absence, self._absence_proof, self._absence_record = selected, proof, checked[0]

    def finish(self, work):
        with self._stage(2, work):
            _require(type(self._absence) is dict and type(self._absence_proof) is dict)
            work.charge(input_bytes=512, json_nodes=32)
            selected = (*self._selected, self._absence)
            size, _ = work.measure(selected)
            # All eight are non-framework selections (four business and four
            # authorization roots). The extra 8192 bytes are not their credit.
            _require(size <= source.authority.MAX_REQUEST_BYTES
                and size <= source.authority.MAX_PLAN_SELECTED_BYTES)
            queries = (*self._queries, self._query)
            _, records = reads._validate_query_reads(source.OPERATION, queries=queries,
                query_reads=(*self._records, self._absence_record), selected_rows=selected, work=work)
            work.prepare_copy(selected)
            selected = tuple(sorted(selected, key=lambda item: (item["table"], item["keyDigest"])))
            context = core.KernelContext(source.OPERATION, self._request["arguments"], selected,
                self._now, self._request["requestDigest"], query_reads=records)
            result = _ReceiptAbsenceOriginals(self._request, context, self._business, self._authorization,
                (*self._proofs, self._absence_proof), queries)
        self._closed = True
        return result
