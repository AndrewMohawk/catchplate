"""Transaction-local primary proofs before deferred SQL parameter resolution.

Only newly referenced, previously observed rows are proved here. Other rows
remain unverified until the mandatory complete-plan input verifier; final delta
verification is also unchanged. Captured database roots are supplied context,
not independently current or authorized roots. No caller result, verifier
callback, alternate budget or persistent cache is accepted.
"""
from __future__ import annotations

import re
from contextlib import contextmanager
from dataclasses import dataclass, replace
from typing import Any

from serverware import authority_audit_capacity as capacity
from serverware import authority_contract, authority_query_reads, authority_radix_proof
from serverware.authority_primary_contract import primary_table_contracts
from serverware.authority_query_read_work import _ValidationWork
from serverware.authority_radix_mutation import (
    PrimaryRadixLimits, PrimaryRoot, evaluate_primary_radix_memberships,
)
from serverware.authority_transition_core import canonical_bytes


MAX_INPUT_BYTES = authority_contract.MAX_RESULT_BYTES
MAX_JSON_NODES = 1_000_000
MAX_STAMP_BYTES = authority_contract.MAX_RESULT_BYTES
MAX_STAMP_NODES = 1_000_000
MAX_JSON_DEPTH = 128
ROOT_HASH_ALLOWANCE = authority_contract.TREE_DEPTH + 2
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SELECTED_FIELDS = frozenset({"table", "key", "keyDigest", "present", "row", "contractSelector"})
_ROOT_FIELDS = frozenset({"table", "rootRevision", "rootDigest", "leafCount"})


class QueryStagingError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class StagedProofMetrics:
    stages: int = 0
    selected_rows: int = 0
    hash_work: int = ROOT_HASH_ALLOWANCE
    input_bytes: int = 0
    json_nodes: int = 0
    proof_vectors: int = 0
    proof_child_slots: int = 0
    stamp_bytes: int = 0
    stamp_nodes: int = 0


class StagedQueryProofs:
    """One private cursor/trace/root context with sticky failure and completion.

    For B source business slots, hash work is bounded by 66 + 136B: one cold
    root-capture allowance plus 66 per nonempty stage and 70 per distinct
    present source row. Stages cannot exceed distinct rows. Actual engine
    input bytes/nodes/vectors/slots are cumulative, not reset per stage.

    Immutable canonical stamps separately bound cache integrity checks. They
    reject mutation through returned row aliases before subsequent reuse, and
    their encoding work has its own cumulative byte/node limits. These limits
    do not claim process-memory isolation or account for the separate query
    bookkeeping, physical proof producer, or final complete-plan verification.
    An optional caller-owned QueryRead meter is reused for actual source
    snapshots/reference scans; its counters are not added to these proof/stamp
    metrics, and this collector never creates a replacement allowance.
    """

    def __init__(self, *, operation: str, business_before_roots: Any,
                 authorization_before_roots: Any,
                 query_work: _ValidationWork | None = None) -> None:
        self._phase = "active"
        self._busy = self._poisoned = False
        self._query_work = query_work
        self._usage = StagedProofMetrics()
        self._cursor = None
        self._trace = None
        self._query_ids: set[str] = set()
        self._rows: dict[tuple[str, str], dict[str, Any]] = {}
        self._proofs: dict[tuple[str, str], dict[str, Any]] = {}
        self._row_stamps: dict[tuple[str, str], bytes] = {}
        self._proof_stamps: dict[tuple[str, str], bytes] = {}
        self._completion_rows: tuple[dict[str, Any], ...] = ()
        self._completion_stamps: tuple[bytes, ...] = ()
        self._remaining: frozenset[tuple[str, str]] = frozenset()
        try:
            if query_work is not None and type(query_work) is not _ValidationWork:
                raise QueryStagingError("staging query work must be an exact shared meter")
            if type(operation) is not str or not 1 <= len(operation) <= 128:
                raise QueryStagingError("staging operation is not an exact string")
            self._operation = operation
            self._spec = authority_contract.operation_spec(operation)
            self._contracts = primary_table_contracts(operation)
            self._contract_by_table = {item.table: item for item in self._contracts}
            self._business_limit = self._spec["maximumBusinessQueryRows"]
            self._hash_limit = ROOT_HASH_ALLOWANCE + (authority_contract.TREE_DEPTH + 72) * self._business_limit
            self._business_roots = self._capture_roots(business_before_roots, "business")
            self._authorization_roots = self._capture_roots(authorization_before_roots, "authorization")
        except Exception as exc:
            self._phase = "failed"
            self._poisoned = True
            if isinstance(exc, QueryStagingError):
                raise
            raise QueryStagingError("staging source root context is invalid") from exc

    @property
    def metrics(self) -> StagedProofMetrics:
        # Even object.__setattr__ on an exposed frozen value cannot change the
        # collector's private counters.
        return replace(self._usage)

    def _capture_roots(self, values: Any, root_class: str) -> tuple[PrimaryRoot, ...]:
        expected = tuple(item.table for item in self._contracts if item.root_class == root_class)
        if type(values) not in (list, tuple) or len(values) != len(expected):
            raise QueryStagingError("staging root inventory differs from source classes")
        roots = []
        for table, value in zip(expected, values):
            if (type(value) is not dict or len(value) != len(_ROOT_FIELDS)
                    or set(value) != _ROOT_FIELDS or value["table"] != table):
                raise QueryStagingError("staging root descriptor is not exact and source ordered")
            roots.append(PrimaryRoot(value["table"], value["rootRevision"],
                                     value["rootDigest"], value["leafCount"]))
        return tuple(roots)

    @contextmanager
    def _guard(self, required: str):
        if self._poisoned or self._busy or self._phase != required:
            self._phase = "failed"
            self._poisoned = True
            raise QueryStagingError("staging collector is not ready for this phase")
        self._busy = True
        try:
            yield
            # A trace/cursor observer may catch a nested call's error. A
            # legitimate phase transition must never overwrite that failure.
            self._require_running()
        except BaseException as exc:
            self._phase = "failed"
            self._poisoned = True
            if isinstance(exc, QueryStagingError) or not isinstance(exc, Exception):
                raise
            raise QueryStagingError("staging acquisition or validation failed") from exc
        finally:
            self._busy = False

    def _require_running(self) -> None:
        if self._poisoned:
            self._phase = "failed"
            raise QueryStagingError("staging collector is not ready after a nested failure")

    def _require_query_work(self, work: _ValidationWork) -> None:
        """Pin the actual planner's non-None meter before starting its reader."""
        with self._guard("active"):
            if type(work) is not _ValidationWork or work is not self._query_work:
                raise QueryStagingError("staging query work identity changed")

    def _stamp(self, value: Any) -> bytes:
        """Count exact ASCII encoding before serialization, without row copies."""
        nodes = size = 0
        pending = [(value, 0, frozenset())]
        remaining_bytes = MAX_STAMP_BYTES - self._usage.stamp_bytes
        remaining_nodes = MAX_STAMP_NODES - self._usage.stamp_nodes
        while pending:
            item, depth, ancestors = pending.pop()
            nodes += 1
            if nodes > remaining_nodes or depth > MAX_JSON_DEPTH:
                raise QueryStagingError("staging cache stamp node budget exceeded")
            kind = type(item)
            if item is None:
                size += 4
            elif kind is bool:
                size += 4 if item else 5
            elif kind is int:
                if item.bit_length() > max(0, remaining_bytes - size) * 4:
                    raise QueryStagingError("staging cache stamp byte budget exceeded")
                size += len(str(item))
            elif kind is str:
                size += 2
                if len(item) > remaining_bytes - size:
                    raise QueryStagingError("staging cache stamp byte budget exceeded")
                for character in item:
                    scalar = ord(character)
                    if scalar == 0 or 0xD800 <= scalar <= 0xDFFF:
                        raise QueryStagingError("staging cache stamp is not lossless JSON")
                    size += (2 if character in '"\\\b\f\n\r\t' else
                             12 if scalar > 0xFFFF else
                             6 if scalar < 32 or scalar >= 127 else 1)
                    if size > remaining_bytes:
                        raise QueryStagingError("staging cache stamp byte budget exceeded")
            elif kind in (dict, list):
                if id(item) in ancestors:
                    raise QueryStagingError("staging cache stamp contains a cycle")
                width = 2 * len(item) if kind is dict else len(item)
                if width > remaining_nodes - nodes - len(pending):
                    raise QueryStagingError("staging cache stamp node budget exceeded")
                size += 2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0)
                branch = ancestors | {id(item)}
                if kind is dict:
                    if any(type(key) is not str for key in item):
                        raise QueryStagingError("staging cache stamp object key is not exact")
                    pending.extend((child, depth + 1, branch) for pair in item.items() for child in pair)
                else:
                    pending.extend((child, depth + 1, branch) for child in item)
            else:
                raise QueryStagingError("staging cache stamp is not lossless JSON")
            if size > remaining_bytes:
                raise QueryStagingError("staging cache stamp byte budget exceeded")
        self._usage = replace(self._usage, stamp_bytes=self._usage.stamp_bytes + size,
                              stamp_nodes=self._usage.stamp_nodes + nodes)
        encoded = canonical_bytes(value)
        if len(encoded) != size:
            raise QueryStagingError("staging cache stamp byte measurement changed")
        return encoded

    def _identity(self, selected: Any) -> tuple[str, str]:
        if (type(selected) is not dict or len(selected) != len(_SELECTED_FIELDS)
                or set(selected) != _SELECTED_FIELDS or type(selected["table"]) is not str
                or not 1 <= len(selected["table"]) <= 128
                or selected["table"] not in self._contract_by_table
                or type(selected["key"]) is not dict
                or len(selected["key"]) != len(self._contract_by_table[selected["table"]].key_columns)
                or any(type(column) is not str or not 1 <= len(column) <= 128 for column in selected["key"])
                or set(selected["key"]) != set(self._contract_by_table[selected["table"]].key_columns)
                or type(selected["keyDigest"]) is not str or len(selected["keyDigest"]) != 71
                or _DIGEST.fullmatch(selected["keyDigest"]) is None
                or type(selected["present"]) is not bool
                or (selected["present"] and type(selected["row"]) is not dict)
                or (not selected["present"] and selected["row"] is not None)
                or (selected["contractSelector"] is not None and type(selected["contractSelector"]) is not str)):
            raise QueryStagingError("staging selected wrapper is not source closed")
        return selected["table"], selected["keyDigest"]

    def _overlay(self, selected_rows: Any) -> tuple[dict[str, Any], ...]:
        if type(selected_rows) is not tuple or len(selected_rows) > self._spec["maximumQueryRows"]:
            raise QueryStagingError("staging global selected inventory exceeds its source bound")
        seen = set()
        result = []
        for row in selected_rows:
            address = self._identity(row)
            if address in seen:
                raise QueryStagingError("staging selected address is duplicated")
            seen.add(address)
            if address in self._rows:
                owned = self._rows[address]
                expected = self._row_stamps[address]
                if self._stamp(owned) != expected or (row is not owned and self._stamp(row) != expected):
                    raise QueryStagingError("staging previously verified row changed")
                row = owned
            result.append(row)
        if not set(self._rows) <= seen:
            raise QueryStagingError("staging previously verified row is missing")
        return tuple(result)

    def authenticate_references(self, cursor: Any, *, query: Any, query_reads: Any,
                                selected_rows: Any, trace: Any) -> tuple[dict[str, Any], ...]:
        """Replace referenced rows with actual verified owned snapshots.

        Other union rows are still unverified. The caller must resolve the
        deferred parameters only after this method returns successfully.
        """
        with self._guard("active"):
            if type(getattr(trace, "operation", None)) is not str or trace.operation != self._operation:
                raise QueryStagingError("staging trace operation changed")
            if self._cursor is None:
                if cursor is None:
                    raise QueryStagingError("staging cursor is absent")
                self._cursor, self._trace = cursor, trace
            elif cursor is not self._cursor or trace is not self._trace:
                raise QueryStagingError("staging cursor or trace identity changed")
            if self._query_work is None:
                owned_query, = authority_query_reads.snapshot_queries(self._operation, (query,))
            else:
                owned_query, = authority_query_reads._snapshot_queries(
                    self._operation, (query,), work=self._query_work,
                )
            self._require_running()
            if (owned_query.query_id in self._query_ids
                    or len(self._query_ids) >= self._spec["maximumQueryRows"]):
                raise QueryStagingError("staging query identity is repeated or exceeds its bound")
            self._query_ids.add(owned_query.query_id)
            union = self._overlay(selected_rows)
            if self._query_work is None:
                references = authority_query_reads.reference_source_rows(
                    self._operation, owned_query, prior_reads=query_reads, selected_rows=union,
                )
            else:
                references = authority_query_reads._reference_source_rows(
                    self._operation, owned_query, prior_reads=query_reads, selected_rows=union,
                    work=self._query_work,
                )
            self._require_running()
            fresh = tuple(row for row in references if self._identity(row) not in self._rows)
            if not fresh:
                return union
            if any(row["table"] == capacity.AGGREGATE_TABLE
                   and row["key"] == {"aggregate_id": capacity.AGGREGATE_ID} for row in fresh):
                raise QueryStagingError("staging cannot acquire the reserved global counter")
            count = len(fresh)
            depth, radix = authority_contract.TREE_DEPTH, authority_contract.TREE_RADIX
            reserve_hashes = depth + 2 + count * (depth + 6)
            if (self._usage.selected_rows + count > self._business_limit
                    or self._usage.stages + 1 > self._business_limit
                    or self._usage.hash_work + reserve_hashes > self._hash_limit):
                raise QueryStagingError("staging cumulative row, stage or hash budget exceeded")
            remaining_bytes = MAX_INPUT_BYTES - self._usage.input_bytes
            remaining_nodes = MAX_JSON_NODES - self._usage.json_nodes
            remaining_vectors = self._business_limit * depth - self._usage.proof_vectors
            remaining_slots = self._business_limit * depth * radix - self._usage.proof_child_slots
            if min(remaining_bytes, remaining_nodes) < 1 or remaining_vectors < count * depth or remaining_slots < count * depth * radix:
                raise QueryStagingError("staging cumulative input or vector budget exceeded")
            original_stamps = tuple(self._stamp(row) for row in fresh)
            self._require_running()
            # Reserve before any physical proof read or proof reconstruction.
            self._usage = replace(self._usage, stages=self._usage.stages + 1,
                                  selected_rows=self._usage.selected_rows + count,
                                  hash_work=self._usage.hash_work + reserve_hashes)
            proofs = authority_radix_proof.derive_multiproofs_batched(
                cursor, selected_rows=fresh,
                roots=tuple(root.json_projection() for root in self._business_roots + self._authorization_roots),
                trace=trace,
            )
            self._require_running()
            verified = evaluate_primary_radix_memberships(
                table_contracts=self._contracts, business_before_roots=self._business_roots,
                authorization_before_roots=self._authorization_roots, selected_rows=fresh, before_proofs=proofs,
                limits=PrimaryRadixLimits(
                    max_selected_rows=count, max_mutations=self._spec["maximumMutations"],
                    max_proof_vectors=remaining_vectors, max_proof_child_slots=remaining_slots,
                    max_hashes=reserve_hashes, max_input_bytes=remaining_bytes,
                    max_json_depth=MAX_JSON_DEPTH, max_json_nodes=remaining_nodes,
                ),
            )
            self._require_running()
            result = verified.result
            if (result.business_after_roots != self._business_roots
                    or result.authorization_after_roots != self._authorization_roots
                    or result.metrics.mutations or result.metrics.recomputed_ancestors):
                raise QueryStagingError("staging membership verification changed before roots")
            self._usage = replace(self._usage,
                hash_work=self._usage.hash_work - reserve_hashes + result.metrics.hash_work,
                input_bytes=self._usage.input_bytes + result.metrics.input_bytes,
                json_nodes=self._usage.json_nodes + result.metrics.json_nodes,
                proof_vectors=self._usage.proof_vectors + result.metrics.proof_vectors,
                proof_child_slots=self._usage.proof_child_slots + result.metrics.proof_child_slots)
            by_address = {(proof["table"], proof["keyDigest"]): proof for proof in verified.before_proofs}
            for row, original in zip(verified.selected_rows, original_stamps):
                address = self._identity(row)
                stamp = self._stamp(row)
                if stamp != original or row["present"] is not True:
                    raise QueryStagingError("staging source row changed during acquisition")
                proof = by_address[address]
                self._rows[address], self._row_stamps[address] = row, stamp
                self._proofs[address], self._proof_stamps[address] = proof, self._stamp(proof)
            return tuple(self._rows.get(self._identity(row), row) for row in union)

    def unproved_rows(self, selected_rows: Any) -> tuple[dict[str, Any], ...]:
        """Close acquisition and return only rows still needing physical proofs."""
        with self._guard("active"):
            rows = self._overlay(selected_rows)
            self._completion_rows = rows
            self._completion_stamps = tuple(self._stamp(row) for row in rows)
            remaining = tuple(row for row in rows if self._identity(row) not in self._rows)
            self._remaining = frozenset(self._identity(row) for row in remaining)
            self._phase = "completing"
            return remaining

    def merge_proofs(self, *, selected_rows: Any, remaining_proofs: Any) -> tuple[dict[str, Any], ...]:
        """Close once with exact coverage; the complete verifier must still run."""
        with self._guard("completing"):
            rows = self._overlay(selected_rows)
            if (len(rows) != len(self._completion_rows)
                    or tuple(self._stamp(row) for row in rows) != self._completion_stamps):
                raise QueryStagingError("staging completion selection changed")
            if type(remaining_proofs) is not tuple or len(remaining_proofs) != len(self._remaining):
                raise QueryStagingError("staging remaining proof inventory is not exact")
            merged = dict(self._proofs)
            for address, proof in self._proofs.items():
                if self._stamp(proof) != self._proof_stamps[address]:
                    raise QueryStagingError("staging cached proof changed")
            seen = set()
            for proof in remaining_proofs:
                if (type(proof) is not dict or type(proof.get("table")) is not str
                        or not 1 <= len(proof["table"]) <= 128 or proof["table"] not in self._contract_by_table
                        or type(proof.get("keyDigest")) is not str or len(proof["keyDigest"]) != 71
                        or _DIGEST.fullmatch(proof["keyDigest"]) is None):
                    raise QueryStagingError("staging remaining proof identity is not closed")
                address = (proof["table"], proof["keyDigest"])
                if address not in self._remaining or address in seen or address in merged:
                    raise QueryStagingError("staging remaining proof is missing, extra or duplicated")
                seen.add(address)
                merged[address] = proof
            if seen != self._remaining or set(merged) != {self._identity(row) for row in rows}:
                raise QueryStagingError("staging merged proofs do not cover the selected union")
            self._phase = "complete"
            return tuple(merged[address] for address in sorted(merged))
