"""Invocation-local complete-query acquisition for the real planner reader.

The caller owns one read-only MVCC transaction and its primary root capture.
This worker retains actual head/frontier observations, fetches exact full rows,
and replays genuine global primary membership and every range/row join in the
explicit revocation or registration family. Registration's ordinary/OIDC mode
is derived from the owned arguments; it is not a caller-selected role subset.
It is not independent root/time authority or a transport admission capability.
The public v3 planner does not construct or accept this worker: its complete
query gate remains closed until the coordinated successor protocol exists.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from serverware import authority_complete_query as complete
from serverware import authority_complete_query_batch as batch
from serverware import authority_contract
from serverware import authority_index_heads as heads
from serverware import authority_index_contract as counted
from serverware import authority_index_reader as reader
from serverware.authority_index_trace import PRIMARY_READ_PROFILE
from serverware import authority_query_reads as reads
from serverware.authority_query_read_work import _ValidationWork


class CompleteAcquisitionError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class CompleteAcquisitionEvidence:
    """Detached raw observations, not a successful verification capability.

    Nested wire dictionaries remain caller-mutable. Every retrieval owns fresh
    dictionaries and counted DTOs; no returned value aliases the collector.
    """

    cutoff_us: int
    heads: tuple[heads.CapturedIndexHead, ...]
    frontiers: tuple[batch.CompleteQueryFrontier, ...]
    business_before_roots: tuple[dict[str, Any], ...]
    authorization_before_roots: tuple[dict[str, Any], ...]
    before_proofs: tuple[dict[str, Any], ...]


def _query_value(query):
    return (query.operation, query.role, query.selector_items, query.maximum_rows)


class _CompleteQueryAcquisition:
    """Private sequential worker; every failure is terminal for this instance.

    Its work object is shared with observation bookkeeping and proof replay.
    Primary proof SQL, staged membership, trace serialization and process/driver
    allocation remain separately bounded; these totals are not whole-plan CPU.
    """

    def __init__(self, cursor: Any, *, operation: str, arguments: dict[str, Any],
                 cutoff_us: int, queries: tuple[complete.CompleteIndexQuery, ...],
                 business_before_roots: Any, authorization_before_roots: Any,
                 trace: Any, work: _ValidationWork,
                 acquisition: reader._ReadAcquisitionBudget | None = None,
                 include_write_heads: bool = False) -> None:
        self._failed = self._busy = False
        self._phase = "new"
        self._cursor, self._trace, self._work = cursor, trace, work
        self._identity = cursor, trace, work
        self._heads: tuple[heads.CapturedIndexHead, ...] = ()
        self._frontiers: list[batch.CompleteQueryFrontier] = []
        self._proofs: tuple[dict[str, Any], ...] = ()
        self._next = 0
        try:
            if (type(include_write_heads) is not bool
                    or type(operation) is not str or operation not in
                    (complete.OPERATION, complete.REGISTRATION_OPERATION)
                    or type(work) is not _ValidationWork
                    or type(queries) is not tuple or not 1 <= len(queries) <= len(
                        complete.ROLES if operation == complete.OPERATION else complete.REGISTRATION_ROLES)
                    or any(type(query) is not complete.CompleteIndexQuery for query in queries)
                    or any(type(getattr(query, "role", None)) is not str
                           or not 1 <= len(query.role) <= 128 for query in queries)):
                raise CompleteAcquisitionError("complete acquisition source inventory is invalid")
            self.operation = operation
            self._include_write_heads = include_write_heads
            copier = reads._CopyBudget(work)
            self._arguments = copier.copy(arguments)
            if type(self._arguments) is not dict:
                raise CompleteAcquisitionError("complete acquisition arguments are not an exact object")
            roles = complete.family_roles(operation, arguments=self._arguments)
            limits = complete.family_limits(operation, arguments=self._arguments)
            if (len(queries) != limits["query_count"] or len(queries) != len(roles)
                    or {query.role for query in queries} != set(roles)
                    or (operation == complete.REGISTRATION_OPERATION
                        and tuple(query.role for query in queries) != roles)
                    or len({query.index_id for query in queries}) != limits["head_count"]):
                raise CompleteAcquisitionError("complete acquisition role inventory differs from its actual family")
            self._business = copier.copy(business_before_roots)
            self._authorization = copier.copy(authorization_before_roots)
            self._cutoff = complete._cutoff(cutoff_us)
            self._queries = reads._snapshot_queries(operation, queries, work=work)
            for query in self._queries:
                expected = complete._bind_query(operation, query.role,
                    arguments=self._arguments, cutoff_us=self._cutoff, work=work)
                work.prepare_comparison(_query_value(query), _query_value(expected))
                if query != expected:
                    raise CompleteAcquisitionError("complete acquisition query differs from actual intent/time")
            if acquisition is None:
                acquisition = reader._ReadAcquisitionBudget(cursor, trace, work=work)
            elif type(acquisition) is not reader._ReadAcquisitionBudget:
                raise CompleteAcquisitionError("complete acquisition physical ledger type changed")
            acquisition.require_idle(cursor, trace, work)
            self._acquisition = acquisition
            self._physical_identity = acquisition
        except BaseException:
            self._failed = True
            self._phase = "failed"
            if type(acquisition) is reader._ReadAcquisitionBudget:
                acquisition.failed = True
            raise

    @contextmanager
    def _guard(self, phase: str):
        if (self._failed or self._busy or self._phase != phase
                or self._acquisition is not self._physical_identity
                or any(actual is not expected for actual, expected in
                       zip((self._acquisition.cursor, self._acquisition.trace,
                            self._acquisition.work), self._identity))
                or any(actual is not expected for actual, expected in
                       zip((self._cursor, self._trace, self._work), self._identity))):
            self._failed = True
            self._phase = "failed"
            self._physical_identity.failed = True
            raise CompleteAcquisitionError("complete acquisition lifecycle is not ready")
        self._busy = True
        try:
            yield
            self._require_running()
        except BaseException:
            self._failed = True
            self._phase = "failed"
            self._physical_identity.failed = True
            raise
        finally:
            self._busy = False

    def _require_running(self):
        if (self._failed or self._acquisition is not self._physical_identity
                or self._acquisition.failed
                or any(actual is not expected for actual, expected in
                       zip((self._acquisition.cursor, self._acquisition.trace,
                            self._acquisition.work), self._identity))
                or any(actual is not expected for actual, expected in
                       zip((self._cursor, self._trace, self._work), self._identity))):
            self._failed = True
            self._phase = "failed"
            self._physical_identity.failed = True
            raise CompleteAcquisitionError("complete acquisition was poisoned by a nested failure")

    def begin(self, cursor, *, operation, arguments, queries, trace, work) -> None:
        """Bind the actual mixed reader before its first business/proof SELECT."""
        with self._guard("new"):
            if (cursor is not self._cursor or trace is not self._trace or work is not self._work
                    or operation != self.operation):
                raise CompleteAcquisitionError("complete acquisition invocation identity changed")
            actual = tuple(query for query in queries if type(query) is complete.CompleteIndexQuery)
            expected_values = tuple(_query_value(query) for query in self._queries)
            actual_values = tuple(_query_value(query) for query in actual)
            work.prepare_comparison(actual_values, expected_values)
            actual_arguments = work.wire(arguments)
            expected_arguments = work.wire(self._arguments)
            work.charge(input_bytes=len(actual_arguments) + len(expected_arguments))
            if actual_values != expected_values or actual_arguments != expected_arguments:
                raise CompleteAcquisitionError("complete acquisition reader inputs changed")
            self._heads = heads.read_operation_index_heads(cursor, operation=operation,
                trace=trace, work=work, acquisition=self._acquisition,
                arguments=self._arguments, queries=self._queries,
                include_write_heads=self._include_write_heads)
            self._require_running()
            self._phase = "reading"

    def read_rows(self, query: complete.CompleteIndexQuery) -> tuple[dict[str, Any], ...]:
        """Use proved lookup IDs only for exact primary fetches, never predicates."""
        with self._guard("reading"):
            if self._next >= len(self._queries) or type(query) is not complete.CompleteIndexQuery:
                raise CompleteAcquisitionError("complete acquisition repeats or changes a role")
            expected = self._queries[self._next]
            self._work.prepare_comparison(_query_value(query), _query_value(expected))
            if query != expected:
                raise CompleteAcquisitionError("complete acquisition role order changed")
            query = expected
            head = next(item for item in self._heads if item.index_id == query.index_id)
            acquired = reader._read_complete_frontier(self._cursor, query=query,
                expected_root=head.index_root, index_revision=head.index_revision,
                trace=self._trace, work=self._work, acquisition=self._acquisition)
            self._require_running()
            rows = []
            with self._acquisition.scope(self._cursor, self._trace, self._work):
                for key_digest, primary_id in acquired.primary_ids:
                    # Fixed source table and key column, not caller SQL. The
                    # JSONB text bound is enforced by SQL before driver output;
                    # SQL evaluation/allocation itself remains outside this meter.
                    key = {"profile": PRIMARY_READ_PROFILE, "queryId": query.query_id,
                           "indexId": query.index_id, "primaryId": primary_id,
                           "primaryKeyDigest": key_digest, "limit": 2}
                    fetched = self._acquisition.read(query.table, key,
                        "SELECT CASE WHEN pg_catalog.octet_length(pg_catalog.to_jsonb(target)::pg_catalog.text) "
                        f"<= {reader.MAX_PRIMARY_ROW_BYTES} THEN pg_catalog.to_jsonb(target) "
                        "ELSE NULL END AS row_value "
                        f"FROM serverware_metadata.{query.table} AS target WHERE target.id = %s LIMIT %s",
                        (primary_id, 2), 1)
                    self._require_running()
                    if (len(fetched) != 1 or type(fetched[0]) is not dict or len(fetched[0]) != 1
                            or set(fetched[0]) != {"row_value"}
                            or type(fetched[0]["row_value"]) is not dict):
                        raise CompleteAcquisitionError("complete index member has no exact bounded primary row")
                    raw = fetched[0]["row_value"]
                    if type(raw.get("id")) is not str or raw["id"] != primary_id:
                        raise CompleteAcquisitionError("complete primary fetch returned a different key")
                    size, _ = self._work.prepare_encoding(raw)
                    if size > reader.MAX_PRIMARY_ROW_BYTES:
                        raise CompleteAcquisitionError("complete primary row exceeds its canonical retention bound")
                    wire = reads._wire(raw)
                    if len(wire) != size:
                        raise CompleteAcquisitionError("complete primary row encoding changed")
                    self._acquisition.charge_primary_row(wire)
                    row = reads._CopyBudget(self._work).copy(raw)
                    rows.append(row)
                self._acquisition.require_active()
            self._require_running()
            self._frontiers.append(batch.CompleteQueryFrontier(query.query_id, acquired.frontier))
            self._next += 1
            return tuple(rows)

    def finish_reads(self) -> None:
        with self._guard("reading"):
            if self._next != len(self._queries):
                raise CompleteAcquisitionError("complete acquisition did not enumerate every source role")
            self._phase = "proofs"

    def roots_for_proofs(self) -> tuple[dict[str, Any], ...]:
        with self._guard("proofs"):
            copier = reads._CopyBudget(self._work)
            return tuple(copier.copy(self._business)) + tuple(copier.copy(self._authorization))

    def retained_evidence(self) -> CompleteAcquisitionEvidence:
        """Copy the actual verified read evidence without proof SQL or replay.

        Source-value copies use the same real CopyBudget as input ownership.
        Fixed source-bounded tuple/list and DTO scaffolding is not a separate
        work unit. Counted constructors only recheck their bounded scalars;
        they neither hash profiles nor confer authority on the returned data.
        """
        with self._guard("complete"):
            copier = reads._CopyBudget(self._work)
            business = tuple(copier.copy(self._business))
            authorization = tuple(copier.copy(self._authorization))
            proofs = copier.copy(self._proofs)
            copied_heads = []
            for head in self._heads:
                values = copier.copy((head.index_id, head.table, head.counted_profile,
                    head.projection_digest, head.projection_manifest_digest,
                    head.index_revision, head.index_root.digest, head.index_root.count))
                copied_heads.append(heads.CapturedIndexHead(*values[:6],
                    counted.CountedNode(*values[6:])))
            copied_frontiers = []
            for proof in self._frontiers:
                query_id = copier.copy(proof.query_id)
                records = []
                for item in proof.frontier:
                    if type(item) is counted.IndexLeaf:
                        values = copier.copy((item.key, item.primary_key_digest,
                                              item.primary_row_digest))
                        records.append(counted.IndexLeaf(*values))
                    elif type(item) is counted.OpaqueSubtree:
                        values = copier.copy((item.prefix, item.digest, item.count))
                        records.append(counted.OpaqueSubtree(*values))
                    else:
                        raise CompleteAcquisitionError("retained complete frontier type changed")
                copied_frontiers.append(batch.CompleteQueryFrontier(query_id, tuple(records)))
            return CompleteAcquisitionEvidence(self._cutoff, tuple(copied_heads),
                tuple(copied_frontiers), business, authorization, proofs)

    def verify(self, *, selected_rows, before_proofs) -> batch.CompleteQueryBatchInputs:
        """Recompute raw global primary proofs and every genuine range/row join."""
        with self._guard("proofs"):
            read_ids = {query.index_id for query in self._queries}
            read_heads = tuple(batch.CompleteQueryHead(item.index_id, item.index_revision, item.index_root)
                               for item in self._heads if item.index_id in read_ids)
            actual = batch._verify_complete_query_batch(operation=self.operation,
                arguments=self._arguments, cutoff_us=self._cutoff, queries=self._queries,
                business_before_roots=self._business, authorization_before_roots=self._authorization,
                selected_rows=selected_rows, before_proofs=before_proofs,
                read_heads=read_heads, query_frontiers=tuple(self._frontiers), work=self._work)
            self._require_running()
            # The actual verifier owns this exact merged primary inventory.
            # Copy before exposing its mutable result to the caller, so later
            # result/input mutation cannot contaminate retained evidence.
            self._proofs = reads._CopyBudget(self._work).copy(actual.before_proofs)
            self._phase = "complete"
            return actual
