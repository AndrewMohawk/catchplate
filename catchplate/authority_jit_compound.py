"""One fixed JIT original-acquisition or independent raw-replay pass.

Only the literal source call sites below create child work. Seven authentic
rows precede real ES256 and its derived eighth lookup; the full transition
then recomputes ES256, and three primary/twelve counted engines decide roots.
Every original ledger remains held and is checked for late spending. Raw
callbacks can transport bytes, never supply a receipt, mutation or verdict.

This is not native database/current-root admission, a signer, durable custody,
or the public producer. The native outer owner supplies its already admitted
cursor, trace, independent anchors, original deadline and continuity check.
Replay supplies the same independent inputs and raw retained bytes. Its caller
must compare the actual manifest with its independently admitted parent.
No generic work/physical ceiling is widened or renewed by a child. Aggregate
maxima bound this fixed algorithm, not RSS, PostgreSQL execution or CPU time.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import os
import threading
import time

from catchplate import authority_jit_assertion_acquisition as source
from catchplate import authority_jit_assertion_replay as original
from catchplate import authority_jit_assertion_transition as semantics
from catchplate import authority_jit_index_reader as index_reader
from catchplate import authority_jit_indexed_phases as indexed
from catchplate import authority_jit_original_frames as frames
from catchplate import authority_jit_primary_row_reader as row_reader
from catchplate import authority_jit_primary_rows as rows
from catchplate import authority_jit_receipt_absence as absence
from catchplate import authority_revocation_roots as callbacks
from catchplate.authority_index_contract import CountedNode, validate_counted_node
from catchplate.authority_query_read_work import (
    MAX_HASHES, MAX_INPUT_BYTES, MAX_JSON_NODES, QueryReadValidationLimits,
    QueryReadValidationMetrics, _ValidationWork,
)


OPERATION = source.OPERATION
CONTEXT_SCHEMA = "catchplate.policyAuthorityJitCompoundContext/v1"
MANIFEST_SCHEMA = "catchplate.policyAuthorityJitOriginalManifest/v1"
CONTEXT_DOMAIN = "catchplate.policyAuthorityJitCompoundContext/v1"
SEED_DOMAIN = "catchplate.policyAuthorityJitOriginalSeed/v1"
STEP_DOMAIN = "catchplate.policyAuthorityJitOriginalStep/v1"
MAX_CHUNK_STAGES = rows.chunks.MAX_TOTAL_DATA_CHUNKS + 7
MAX_ORIGINALS = MAX_CHUNK_STAGES + 8 + 12
MAX_STAGES = 1 + 7 * 4 + MAX_CHUNK_STAGES + 1 + 3 + 4 + 9 + indexed.STAGE_COUNT + 12 + 3
MAX_ACQUISITION_STAGES = MAX_ORIGINALS
MAX_ORIGINAL_BYTES = (rows.chunks.MAX_TOTAL_DATA_CHUNKS * frames.MAX_CHUNK_BYTES + 14
    + 8 * frames.MAX_PROOF_BYTES + 12 * frames.MAX_INDEX_BYTES)
_COUNTERS = ("hash_work", "input_bytes", "json_nodes")


class JitCompoundError(ValueError):
    pass


def _require(value):
    if not value:
        raise JitCompoundError("JIT pass lost its source schedule, original clock or work custody")


def schedule_binding():
    """Source description only; no supplied list or count can select stages."""
    return {"schema": "catchplate.policyAuthorityJitCompoundSchedule/v1",
        "sourceRevision": source.authority.SOURCE_REVISION, "operation": OPERATION,
        "initialRows": 7, "maximumDataChunks": rows.chunks.MAX_TOTAL_DATA_CHUNKS,
        "chunkBytes": rows.chunks.CHUNK_BYTES, "maximumChunksPerRow": rows.chunks.MAX_ROW_DATA_CHUNKS,
        "receiptStages": list(semantics.RECEIPT_STAGES), "absenceStages": list(absence.STAGES),
        "transitionStages": list(semantics.STAGES), "indexedStages": indexed.STAGE_COUNT,
        "writeIndexes": list(source.heads._jit_receipt_ids()), "maximumStages": MAX_STAGES,
        "maximumOriginals": MAX_ORIGINALS, "maximumOriginalBytes": MAX_ORIGINAL_BYTES,
        "stageLimits": {"hashes": MAX_HASHES, "inputBytes": MAX_INPUT_BYTES, "jsonNodes": MAX_JSON_NODES},
        "physicalLimits": {"sqlReads": source.reader.MAX_CUMULATIVE_SQL_READS,
            "parameterBytes": source.reader.MAX_PARAMETER_BYTES,
            "transportBytes": source.reader.MAX_TRANSPORT_BYTES}}


@dataclass(frozen=True, slots=True)
class PhysicalMetrics:
    sql_reads: int
    returned_rows: int
    parameter_bytes: int
    transport_bytes: int


@dataclass(frozen=True, slots=True)
class StageMetrics:
    name: str
    work: QueryReadValidationMetrics
    physical: PhysicalMetrics | None
    original_bytes: int


@dataclass(frozen=True, slots=True)
class JitPassObservation:
    """Output-only actual engines and raw-byte inventory, not admission."""

    context_bytes: bytes
    original_manifest_bytes: bytes
    transition: source.core.KernelTransition
    indexed_result: source.indexed.IndexedMutationResult
    stages: tuple[StageMetrics, ...]
    total_work: QueryReadValidationMetrics
    total_acquisition: PhysicalMetrics
    total_original_bytes: int


def _framed(domain, *raw, work):
    work.charge(hashes=1, input_bytes=len(domain) + 8 + sum(8 + len(value) for value in raw))
    return source.core.framed_digest(domain, *raw)


class _Stage:
    def __init__(self, invocation, name, physical):
        self._owner, self.name = invocation, name
        self.work = _ValidationWork(QueryReadValidationLimits())
        self._work, self._limits = self.work, self.work.limits
        self.reservation = source.reservations._MutationReservationGuard(self.work)
        self.acquisition = (source.reader._ReadAcquisitionBudget(invocation.cursor, invocation.trace,
            work=self.work) if physical else None)
        self._acquisition = self.acquisition
        self._acquisition_limits = None if self.acquisition is None else self.acquisition.limits
        self._reservation = self.reservation
        self._identity = (invocation, name, self.work, self._limits, self.acquisition,
            self._acquisition_limits, self.reservation)
        self._previous = (0,) * 7
        self.original_bytes = 0

    def _snapshot(self, *, seal=False):
        _require(type(self) is _Stage and all(actual is held for actual, held in zip(
            (self._owner, self.name, self.work, self._limits, self.acquisition,
                self._acquisition_limits, self.reservation), self._identity, strict=True))
            and type(self.original_bytes) is int and 0 <= self.original_bytes <= frames.MAX_INDEX_BYTES
            and self.work is self._work and type(self.work) is _ValidationWork
            and self.reservation is self._reservation and self.acquisition is self._acquisition
            and self.work.limits is self.reservation.current_limits())
        if seal:
            _require(self.work.limits is self._limits)
        source.batch._SharedLedger(self.work)
        _require((self._limits.max_hashes, self._limits.max_input_bytes, self._limits.max_json_nodes)
            == (MAX_HASHES, MAX_INPUT_BYTES, MAX_JSON_NODES))
        values = tuple(getattr(self.work, name) for name in _COUNTERS)
        maxima = (MAX_HASHES, MAX_INPUT_BYTES, MAX_JSON_NODES)
        if self.acquisition is None:
            values += (0,) * 4
            maxima += (0,) * 4
        else:
            physical = self.acquisition
            _require(type(physical) is source.reader._ReadAcquisitionBudget
                and physical.work is self.work and physical.cursor is self._owner.cursor
                and physical.trace is self._owner.trace and physical.limits is self._acquisition_limits
                and physical.limits == source.reader._ReadAcquisitionLimits() and not physical.failed)
            values += (physical.sql_reads, physical.returned_rows,
                physical.parameter_bytes, physical.transport_bytes)
            maxima += (source.reader.MAX_CUMULATIVE_SQL_READS,
                source.reader.MAX_CUMULATIVE_SQL_READS * source.reader.MAX_NODE_IDENTITIES,
                source.reader.MAX_PARAMETER_BYTES, source.reader.MAX_TRANSPORT_BYTES)
            if seal:
                physical.require_idle(self._owner.cursor, self._owner.trace, self.work)
                _require(not physical._read_phase_active and not physical._reading)
        _require(all(type(value) is int and previous <= value <= maximum
            for value, previous, maximum in zip(values, self._previous, maxima, strict=True)))
        self._previous = values
        return values

    def check(self):
        self._owner._check(self)


class _Invocation:
    """Private allocation owner used only by the fixed run_pass body below."""

    def __init__(self, cursor, trace, check, retain, read, deadline):
        _require(type(deadline) is int and 0 < deadline < 2**63 and callable(check)
            and ((cursor is not None and trace is not None and read is None)
                or (cursor is None and trace is None and callable(read) and retain is None))
            and (retain is None or callable(retain)))
        if cursor is not None:
            from catchplate.authority_planner_read import PlannerTrace
            _require(type(trace) is PlannerTrace and trace.operation == OPERATION
                and trace._jit_successor is True)
        self.cursor, self.trace, self._check_callback = cursor, trace, check
        self._retain, self._read, self._deadline = retain, read, deadline
        self._identity = cursor, trace, check, retain, read, deadline
        self._process = os.getpid(), threading.get_ident()
        self._failed = self._closed = self._callback_active = False
        self._active = None
        self._last_clock = 0
        self._sealed, self._records, self._descriptors = [], [], []
        self._totals, self._original_bytes = [0] * 7, 0
        self._seen = set()
        self._chain = self._context = None
        self._local()

    def _local(self):
        _require(not self._failed and not self._closed
            and self._process == (os.getpid(), threading.get_ident())
            and all(actual is held for actual, held in zip((self.cursor, self.trace,
                self._check_callback, self._retain, self._read, self._deadline), self._identity, strict=True)))
        actual = time.monotonic_ns()
        _require(type(actual) is int and self._last_clock <= actual < self._deadline)
        self._last_clock = actual
        for stage, values, raw_bytes in self._sealed:
            _require(stage._snapshot(seal=True) == values and stage.original_bytes == raw_bytes)

    def _check(self, stage):
        try:
            self._local()
            _require(stage is self._active and type(stage) is _Stage and not self._callback_active)
            before = stage._snapshot()
            original_bytes = stage.original_bytes
            self._callback_active = True
            try:
                value = callbacks._callback(stage.work, self._check_callback, stage)
            finally:
                self._callback_active = False
            _require(value is None and stage._snapshot() == before and stage.original_bytes == original_bytes)
            self._local()
        except BaseException:
            self._failed = True
            raise

    @contextmanager
    def _stage(self, name, *, acquire=False):
        try:
            self._local()
            _require(self._active is None and not self._callback_active and len(self._records) < MAX_STAGES)
            stage = _Stage(self, name, acquire and self.cursor is not None)
            self._active = stage
            # At most ten local scans examine <=138 compound ledgers. The
            # configured producer's neutral replay checks additionally scan
            # <=69 sealed production ledgers at most twenty times in a read
            # stage. Fixed metadata ceilings of 512/256 bytes and 32 nodes
            # per respective record total <=1,059,840 bytes/88,320 nodes;
            # the remainder covers bounded active/configuration scaffolding.
            # Reserve on this actual child BEFORE neutral callbacks, apart
            # from body/engine bytes. No sealed ledger receives a late debit.
            stage.work.charge(input_bytes=2 * 1024 * 1024, json_nodes=131072)
            stage.check()
            yield stage
            stage.check()
            values = stage._snapshot(seal=True)
            maxima = (MAX_STAGES * MAX_HASHES, MAX_STAGES * MAX_INPUT_BYTES,
                MAX_STAGES * MAX_JSON_NODES,
                MAX_ACQUISITION_STAGES * source.reader.MAX_CUMULATIVE_SQL_READS,
                MAX_ACQUISITION_STAGES * source.reader.MAX_CUMULATIVE_SQL_READS * source.reader.MAX_NODE_IDENTITIES,
                MAX_ACQUISITION_STAGES * source.reader.MAX_PARAMETER_BYTES,
                MAX_ACQUISITION_STAGES * source.reader.MAX_TRANSPORT_BYTES)
            _require(all(value <= maximum - total for value, maximum, total
                in zip(values, maxima, self._totals, strict=True)))
            self._totals = [total + value for total, value in zip(self._totals, values, strict=True)]
            physical = None if stage.acquisition is None else PhysicalMetrics(*values[3:])
            self._records.append(StageMetrics(name, stage.work.metrics, physical, stage.original_bytes))
            self._sealed.append((stage, values, stage.original_bytes))
        except BaseException:
            self._failed = True
            raise
        finally:
            self._active = None

    def _transport(self, stage, callback, *arguments):
        """A raw store may spend this child, never replace it or spend a sealed child."""
        stage.check()
        before = stage._snapshot(seal=True)
        original_bytes = stage.original_bytes
        self._callback_active = True
        try:
            result = callback(*arguments, stage.work)
        finally:
            self._callback_active = False
        after = stage._snapshot(seal=True)
        _require(stage.original_bytes == original_bytes
            and all(actual >= previous for actual, previous in zip(after, before, strict=True)))
        stage.check()
        return result

    def _receive(self, stage, kind, ordinal):
        _require(self._read is not None and stage.acquisition is None)
        raw = self._transport(stage, self._read, kind, ordinal)
        maximum = {"primary-chunk": frames.MAX_CHUNK_BYTES,
            "primary-proof": frames.MAX_PROOF_BYTES, "index-frontier": frames.MAX_INDEX_BYTES}[kind]
        _require(type(raw) is bytes and 2 <= len(raw) <= maximum)
        stage.work.charge(input_bytes=len(raw))
        return raw

    def _original(self, stage, kind, ordinal, raw):
        _require(type(raw) is bytes and 2 <= len(raw) <= frames.MAX_INDEX_BYTES
            and (kind, ordinal) not in self._seen and len(self._descriptors) < MAX_ORIGINALS
            and len(raw) <= MAX_ORIGINAL_BYTES - self._original_bytes)
        work = stage.work
        work.charge(hashes=1, input_bytes=len(raw) + 1024, json_nodes=32)
        descriptor = {"kind": kind, "ordinal": ordinal, "byteLength": len(raw),
            "digest": "sha256:" + hashlib.sha256(raw).hexdigest()}
        wire = work.wire(descriptor)
        self._chain = _framed(STEP_DOMAIN, self._chain.encode("ascii"), wire, work=work)
        if self._retain is not None:
            _require(self._transport(stage, self._retain, kind, ordinal, raw) is None)
        self._seen.add((kind, ordinal))
        self._descriptors.append(descriptor)
        self._original_bytes += len(raw)
        stage.original_bytes += len(raw)

    def _finish(self, transition, result, manifest):
        self._local()
        _require(self._active is None and len(self._records) <= MAX_STAGES
            and len(self._descriptors) <= MAX_ORIGINALS)
        self._closed = True
        return JitPassObservation(self._context, manifest, transition, result,
            tuple(self._records), QueryReadValidationMetrics(*self._totals[:3]),
            PhysicalMetrics(*self._totals[3:]), self._original_bytes)


def _heads(values, work):
    _require(type(values) is tuple and len(values) == 12)
    copied = []
    for value, identity in zip(values, source.heads._jit_receipt_ids(), strict=True):
        _require(type(value) is source.read_write.CompleteReadWriteHead and value.index_id == identity
            and type(value.index_revision) is int and 0 <= value.index_revision < 2**63)
        root = validate_counted_node(value.index_root)
        work.prepare_copy((identity, value.index_revision, root.digest, root.count))
        copied.append(source.read_write.CompleteReadWriteHead(identity, value.index_revision,
            CountedNode(root.digest, root.count)))
    return tuple(copied)


def _context(request, policy, business, authorization, heads, cutoff, deadline, work):
    # Fixed source-manifest generation and scalar roster construction are
    # reserved before the genuine helpers allocate their source documents.
    work.charge(input_bytes=1024 * 1024, json_nodes=32768)
    document, _spec = original._source_bindings(work)
    document.update(schema=CONTEXT_SCHEMA, requestDigest=request["requestDigest"],
        operationId=request["operationId"], assertionPolicy=policy, databaseCutoffUs=cutoff,
        originalDeadlineNs=deadline, businessBeforeRoots=[root.json_projection() for root in business],
        authorizationBeforeRoots=[root.json_projection() for root in authorization],
        countedBeforeHeads=[{"indexId": head.index_id,
            "indexRevision": head.index_revision, "rootDigest": head.index_root.digest,
            "leafCount": head.index_root.count} for head in heads], schedule=schedule_binding())
    return work.wire(document)


def _absent(query, work):
    _require(query.require_absence is True and query.table == source.receipt.RECEIPT_TABLE)
    work.prepare_copy(query.absent_key)
    key = dict(query.absent_key)
    digest = _framed("catchplate.policyAuthorityBusinessKey/v1",
        query.table.encode("ascii"), work.wire(key), work=work)
    work.charge(input_bytes=512, json_nodes=16)
    return {"table": query.table, "key": key, "keyDigest": digest,
        "present": False, "row": None, "contractSelector": None}


def run_pass(*, request, assertion_policy, business_before_roots, authorization_before_roots,
        counted_before_heads, database_cutoff_us, original_deadline_ns, cursor, trace, check,
        retain_original=None, read_original=None) -> JitPassObservation:
    """Execute the one source schedule; callbacks return only raw bytes/None."""
    invocation = _Invocation(cursor, trace, check, retain_original, read_original, original_deadline_ns)
    try:
        with invocation._stage("capture") as stage:
            work = stage.work
            policy = source.reads._CopyBudget(work).copy(assertion_policy)
            source._policy(policy)
            held_heads = _heads(counted_before_heads, work)
            primary = rows._JitPrimaryRows(request=request, business_before_roots=business_before_roots,
                authorization_before_roots=authorization_before_roots,
                database_cutoff_us=database_cutoff_us, work=work)
            invocation._context = _context(primary._request, policy, primary._business, primary._authorization, held_heads,
                database_cutoff_us, original_deadline_ns, work)
            context_digest = _framed(CONTEXT_DOMAIN, invocation._context, work=work)
            invocation._chain = _framed(SEED_DOMAIN, context_digest.encode("ascii"), work=work)
        for slot in range(7):
            _require(primary.next_stage == ("row-open", slot))
            with invocation._stage("row-open:" + str(slot)) as stage:
                codec = primary.begin_row(stage.work)
            page = 0
            while primary.next_stage == ("row-chunk", slot):
                _require(page < rows.chunks.MAX_ROW_DATA_CHUNKS)
                ordinal = slot * rows.chunks.MAX_ROW_DATA_CHUNKS + page
                with invocation._stage("row-chunk:" + str(ordinal), acquire=True) as stage:
                    if cursor is not None:
                        with stage.acquisition.read_phase(cursor, trace, stage.work):
                            row_reader.acquire_chunk(cursor, owner=primary, trace=trace,
                                work=stage.work, acquisition=stage.acquisition)
                        raw = frames.encode_consumed_chunk(codec, work=stage.work)
                    else:
                        raw = invocation._receive(stage, "primary-chunk", ordinal)
                        primary.consume_chunk(frames.decode_chunk(raw, work=stage.work), stage.work)
                    invocation._original(stage, "primary-chunk", ordinal, raw)
                page += 1
            _require(primary.next_stage == ("row-decode", slot))
            with invocation._stage("row-decode:" + str(slot)) as stage:
                primary.decode_row(stage.work)
            with invocation._stage("row-acquire-proof:" + str(slot), acquire=True) as stage:
                if cursor is not None:
                    with stage.acquisition.read_phase(cursor, trace, stage.work):
                        proof = row_reader.acquire_proof(cursor, owner=primary, trace=trace,
                            work=stage.work, acquisition=stage.acquisition)
                    raw = frames.encode_proof(proof, work=stage.work)
                else:
                    raw = invocation._receive(stage, "primary-proof", slot)
                    proof = frames.decode_proof(raw, work=stage.work)
                invocation._original(stage, "primary-proof", slot, raw)
            with invocation._stage("row-admit-proof:" + str(slot)) as stage:
                primary.admit_proof(proof, stage.work)
        with invocation._stage("rows-finish") as stage:
            first = primary.finish(stage.work)
        with invocation._stage("receipt-capture") as stage:
            prerequisite = semantics._JitAssertionReceipt(first.context, assertion_policy=policy, work=stage.work)
        with invocation._stage("receipt-actor") as stage:
            prerequisite.actor_policy(stage.work)
        with invocation._stage("receipt-derive") as stage:
            first_digest = prerequisite.receipt(stage.work)
        with invocation._stage("absence-capture") as stage:
            eighth = absence._JitReceiptAbsence(rows=primary, receipt_owner=prerequisite, work=stage.work)
        with invocation._stage("absence-acquire", acquire=True) as stage:
            query, root = eighth.query_inputs()
            if cursor is not None:
                # Only source metadata, not a caller manifest or alternate SQL.
                stage.work.prepare_copy((query.table, *query.absent_key))
                stage.work.charge(input_bytes=256, json_nodes=8)
                manifest = ({"table": query.table, "keyColumns": list(query.absent_key)},)
                stage.work.prepare_copy(manifest)
                with stage.acquisition.read_phase(cursor, trace, stage.work):
                    selected, proof = source.primary_reader.acquire_exact_primary(cursor, operation=OPERATION,
                        query=query, manifest=manifest, primary_root=root, trace=trace,
                        work=stage.work, acquisition=stage.acquisition)
                raw = frames.encode_proof(proof, work=stage.work)
            else:
                raw = invocation._receive(stage, "primary-proof", 7)
                proof = frames.decode_proof(raw, work=stage.work)
                selected = _absent(query, stage.work)
            invocation._original(stage, "primary-proof", 7, raw)
        with invocation._stage("absence-admit") as stage:
            eighth.admit(selected_row=selected, before_proof=proof, work=stage.work)
        with invocation._stage("absence-finish") as stage:
            complete = eighth.finish(stage.work)
        with invocation._stage("transition-capture") as stage:
            semantic = semantics._JitAssertionTransition(complete.context, assertion_policy=policy, work=stage.work)
        for method in ("actor_policy", "receipt", "base_mutations", "normalize_selected",
                "normalize_mutations", "validate_inventory", "expand_inline"):
            with invocation._stage("transition-" + method) as stage:
                value = getattr(semantic, method)(stage.work)
                _require(value == first_digest if method == "receipt" else value is None)
        with invocation._stage("transition-finish") as stage:
            transition = semantic.finish(stage.work)
        with invocation._stage("capacity") as stage:
            _require(type(transition) is source.core.KernelTransition and len(transition.mutations) == 3)
            stage.work.prepare_scan(transition.mutations)
            units = source.capacity.transition_work_units(operation=OPERATION,
                query_work_units=sum(query.work_units for query in complete.queries),
                kernel_work_units=transition.work_units, mutations=transition.mutations)
            source.capacity.validate_transition_work_units(OPERATION, units, transition.mutations)
        with invocation._stage("indexed-capture") as stage:
            indexes = indexed._JitIndexedPhases(business_before_roots=complete.business_before_roots,
                authorization_before_roots=complete.authorization_before_roots,
                counted_before_heads=held_heads, work=stage.work)
            stage.work.charge(input_bytes=8192, json_nodes=128)
            selected_by_table = {item["table"]: item for item in complete.context.selected_rows}
            proofs_by_table = {item["table"]: item for item in complete.before_proofs}
            mutations_by_table = {item["table"]: item for item in transition.mutations}
            _require(len(mutations_by_table) == 3 and set(mutations_by_table) == set(indexed.PRIMARY_TABLES))
        for table in indexed.PRIMARY_TABLES:
            with invocation._stage("primary-write:" + table) as stage:
                indexes.verify_primary(selected_row=selected_by_table[table],
                    before_proof=proofs_by_table[table], mutation=mutations_by_table[table], work=stage.work)
        with invocation._stage("primary-prepare") as stage:
            indexes.prepare_primary(stage.work)
        for ordinal, identity in enumerate(source.heads._jit_receipt_ids()):
            with invocation._stage("index-prepare:" + identity) as stage:
                prepared = indexes.prepare_index(stage.work)
                _require(prepared.index_id == identity)
            with invocation._stage("index-acquire:" + identity, acquire=True) as stage:
                if cursor is not None:
                    with stage.acquisition.read_phase(cursor, trace, stage.work):
                        raw_input = index_reader.acquire_index(cursor, owner=indexes, trace=trace,
                            work=stage.work, acquisition=stage.acquisition, reservation_guard=stage.reservation)
                    raw = frames.encode_index(raw_input, work=stage.work)
                else:
                    raw = invocation._receive(stage, "index-frontier", ordinal)
                    raw_input = frames.decode_index(raw, work=stage.work)
                invocation._original(stage, "index-frontier", ordinal, raw)
            with invocation._stage("index-fold:" + identity) as stage:
                indexes.fold_index(raw_input, work=stage.work)
        with invocation._stage("indexed-finish") as stage:
            evaluated = indexes.finish(stage.work)
        with invocation._stage("trace-close") as stage:
            if trace is not None:
                stage.work.prepare_scan(complete.context.selected_rows)
                stage.work.prepare_scan(transition.mutations)
                for mutation in transition.mutations:
                    stage.work.prepare_copy((mutation["table"], mutation["key"]))
                    trace.write(mutation["table"], mutation["key"])
                stage.work.prepare_copy(trace._entries)
                trace.close(selected_rows=complete.context.selected_rows, mutation_plan=transition.mutations)
        with invocation._stage("finish") as stage:
            _require(len(invocation._descriptors) == first.data_chunks
                + sum(not item["present"] for item in first.context.selected_rows) + 20)
            stage.work.charge(input_bytes=65536, json_nodes=2048)
            result = evaluated.result
            document = {"schema": MANIFEST_SCHEMA, "contextDigest": context_digest,
                "originalChainDigest": invocation._chain, "originalCount": len(invocation._descriptors),
                "originalBytes": invocation._original_bytes, "originals": invocation._descriptors,
                "businessAfterRoots": [root.json_projection() for root in result.primary.business_after_roots],
                "authorizationAfterRoots": [root.json_projection() for root in result.primary.authorization_after_roots],
                "countedAfterHeads": [{"indexId": head.index_id,
                    "indexRevision": head.index_revision, "rootDigest": head.index_root.digest,
                    "leafCount": head.index_root.count} for head in result.after_heads],
                "result": transition.result}
            manifest = stage.work.wire(document)
            _require(len(manifest) <= 128 * 1024)
        return invocation._finish(transition, result, manifest)
    except BaseException:
        invocation._failed = True
        raise
