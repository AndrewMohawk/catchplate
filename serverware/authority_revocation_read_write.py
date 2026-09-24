"""Bind the actual mixed revocation observations to genuine read/write proofs.

One privately owned raw graph and one cumulative work budget cover source
generation, retained observations, primary membership, all five complete joins
and indexed mutations. No successful component result is accepted as input.
Caller query JSON is never parsed into executable declarations.

This is proof computation over supplied context, not operation authorization:
request/signature authentication, trusted time, capacity admission, kernel
semantics, current roots, SQL and retained transport remain separate gates.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from serverware import authority_complete_query as complete
from serverware import authority_complete_query_batch as query_batch
from serverware import authority_complete_read_write as read_write
from serverware import authority_contract
from serverware import authority_index_join as join
from serverware import authority_indexed_mutation as indexed
from serverware import authority_query_reads as reads
from serverware import authority_radix_mutation as primary
from serverware import authority_transition_core as core
from serverware import authority_transition_webauthn as candidate
from serverware.authority_primary_contract import PRIMARY_KEY_COLUMNS
from serverware.authority_query_read_work import (
    QueryReadValidationLimits, QueryReadValidationMetrics, _ValidationWork,
)


# Target + five complete roles + at most 32 approval audits + credential audit
# + optional separate assertion credential + challenge + framework counter.
MAX_QUERY_READS = 1 + query_batch.QUERY_COUNT + complete.CASCADE_MAX + 1 + 2 + 1
_ASSERTION_FIELDS = frozenset({"credentialRecordId", "challengeId"})


class RevocationReadWriteError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class RevocationReadWriteMetrics:
    raw_decode_bytes: int
    ownership_bytes: int
    ownership_nodes: int
    generation: QueryReadValidationMetrics
    declaration_binding: QueryReadValidationMetrics
    observation_validation: QueryReadValidationMetrics
    point_binding: QueryReadValidationMetrics
    proof_work: QueryReadValidationMetrics
    complete_binding: QueryReadValidationMetrics
    total_hashes: int
    total_input_bytes: int
    total_json_nodes: int


@dataclass(frozen=True, slots=True)
class RevocationReadWriteInputs:
    operation: str
    arguments: dict[str, Any]
    cutoff_us: int
    request_digest: str
    assertion_binding: dict[str, str]
    query_program: tuple[core.Query, ...]
    query_reads: tuple[reads.QueryRead, ...]
    business_before_roots: tuple[primary.PrimaryRoot, ...]
    authorization_before_roots: tuple[primary.PrimaryRoot, ...]
    selected_rows: tuple[dict[str, Any], ...]
    before_proofs: tuple[dict[str, Any], ...]
    mutations: tuple[dict[str, Any], ...]
    queries: tuple[complete.CompleteIndexQuery, ...]
    before_heads: tuple[read_write.CompleteReadWriteHead, ...]
    after_heads: tuple[read_write.CompleteReadWriteHead, ...]
    query_frontiers: tuple[query_batch.CompleteQueryFrontier, ...]
    write_frontiers: tuple[read_write.CompleteWriteFrontier, ...]
    joined_reads: tuple[tuple[str, join.JoinedIndexObservation], ...]
    read_primary: primary.PrimaryRadixBatchResult
    write: indexed.IndexedMutationResult
    projection_manifest_digest: str
    metrics: RevocationReadWriteMetrics


class _Ledger:
    """Adapt the actual bounded work object to the genuine proof workers."""

    def __init__(self, limits: QueryReadValidationLimits) -> None:
        # Revalidates exact type/fields, including constructor-bypassed values.
        self.work = _ValidationWork(limits)

    @property
    def hashes(self):
        return self.work.hash_work

    @property
    def input_bytes(self):
        return self.work.input_bytes

    @property
    def json_nodes(self):
        return self.work.json_nodes

    def charge(self, *, hashes=0, input_bytes=0, json_nodes=0):
        self.work.charge(hashes=hashes, input_bytes=input_bytes, json_nodes=json_nodes)

    def remaining(self):
        values = (self.work.limits.max_hashes - self.hashes,
                  self.work.limits.max_input_bytes - self.input_bytes,
                  self.work.limits.max_json_nodes - self.json_nodes)
        if min(values) < 1:
            raise RevocationReadWriteError("revocation proof phase has no remaining work budget")
        return values


def _delta(before, after) -> QueryReadValidationMetrics:
    return QueryReadValidationMetrics(after.hash_work - before.hash_work,
        after.input_bytes - before.input_bytes, after.json_nodes - before.json_nodes)


def _payload_length(value) -> int:
    # No ASCII scan, decode, JSON parse or hash before the aggregate admission.
    if type(value) is not bytes or not 2 <= len(value) <= reads.MAX_BOOKKEEPING_BYTES:
        raise RevocationReadWriteError("revocation observation bytes are not bounded exact bytes")
    return len(value)


def _preflight(*, ledger, operation, request_digest, assertion_binding,
               query_reads, query_frontiers, write_frontiers) -> int:
    if type(operation) is not str or operation != complete.OPERATION:
        raise RevocationReadWriteError("revocation operation is not source admitted")
    if type(request_digest) is not str or len(request_digest) != 71:
        raise RevocationReadWriteError("revocation request digest has an invalid exact shape")
    if (type(assertion_binding) is not dict or len(assertion_binding) != 2
            or any(type(key) is not str for key in assertion_binding)
            or set(assertion_binding) != _ASSERTION_FIELDS
            or any(type(value) is not str or not 1 <= len(value) <= 1024
                   for value in assertion_binding.values())):
        raise RevocationReadWriteError("revocation assertion binding is not two bounded exact IDs")
    spec = authority_contract.operation_spec(operation)
    read_write._frontier_preflight(query_frontiers, write_frontiers,
                                  read_write._source_sizes(spec)[2])
    if type(query_reads) is not tuple or not 1 <= len(query_reads) <= MAX_QUERY_READS:
        raise RevocationReadWriteError("revocation observation count exceeds its source recipe")
    address_count = raw_bytes = 0
    for record in query_reads:
        if (type(record) is not reads.QueryRead
                or type(record.query_id) is not str or len(record.query_id) > reads.MAX_QUERY_ID_BYTES
                or type(record.addresses) is not tuple
                or type(record.returned_row_count) is not int
                or not 0 <= record.returned_row_count <= spec["maximumQueryRows"]):
            raise RevocationReadWriteError("revocation observation has an invalid raw shape")
        address_count += len(record.addresses)
        if address_count > spec["maximumQueryRows"]:
            raise RevocationReadWriteError("revocation observed address occurrences exceed their source bound")
        raw_bytes += _payload_length(record.declared_query_json) + _payload_length(record.resolved_query_json)
        for address in record.addresses:
            if (type(address) is not reads.QueryReadAddress
                    or type(address.table) is not str or not 1 <= len(address.table) <= 128
                    or type(address.key_digest) is not str or len(address.key_digest) != 71
                    or type(address.present) is not bool):
                raise RevocationReadWriteError("revocation address has an invalid raw shape")
            raw_bytes += _payload_length(address.key_json)
        if raw_bytes > ledger.work.limits.max_input_bytes - ledger.input_bytes:
            raise RevocationReadWriteError("revocation raw observation decoding exceeds remaining bytes")
    terminals = sum(len(item.frontier) for item in (*query_frontiers, *write_frontiers))
    # The existing 12-field document contributes at least 25 nodes. Three new
    # keys, digest, closed two-ID object and read list add 10. A five-field read
    # contributes 11; a four-field address and a frontier terminal each add 9.
    # This is a necessary combined lower bound, not an acceptance guarantee.
    minimum_nodes = 35 + 11 * len(query_reads) + 9 * (address_count + terminals)
    if minimum_nodes > ledger.work.limits.max_json_nodes - ledger.json_nodes:
        raise RevocationReadWriteError("revocation combined raw normalization exceeds remaining nodes")
    return raw_bytes


def _capture(*, ledger, request_digest, assertion_binding, query_reads, **inputs):
    raw_decode_bytes = _preflight(ledger=ledger, operation=inputs["operation"],
        request_digest=request_digest, assertion_binding=assertion_binding, query_reads=query_reads,
        query_frontiers=inputs["query_frontiers"], write_frontiers=inputs["write_frontiers"])
    # Reserve ALL decoding before the first buffer. Strict ASCII decode is the
    # validation pass; a separate uncharged isascii traversal is unnecessary.
    ledger.charge(input_bytes=raw_decode_bytes)
    raw_reads = [{"queryId": record.query_id,
        "declaredQueryJson": record.declared_query_json.decode("ascii"),
        "resolvedQueryJson": record.resolved_query_json.decode("ascii"),
        "addresses": [{"table": address.table, "keyJson": address.key_json.decode("ascii"),
            "keyDigest": address.key_digest, "present": address.present} for address in record.addresses],
        "returnedRowCount": record.returned_row_count} for record in query_reads]
    document = read_write._raw_document(**inputs)
    document.update(requestDigest=request_digest, assertionBinding=assertion_binding, queryReads=raw_reads)
    before = ledger.work.metrics
    owned = query_batch._JSONCapture(ledger).visit(document)
    captured = _delta(before, ledger.work.metrics)
    return owned, raw_decode_bytes, captured


def _ascii_bytes(value: str, work: _ValidationWork) -> bytes:
    # A privately captured string comes from typed inputs or retained replay.
    # The real strict encoder rejects non-ASCII replay text under this charge.
    work.charge(input_bytes=len(value))
    return value.encode("ascii")


def _restore_reads(values, work: _ValidationWork) -> tuple[reads.QueryRead, ...]:
    restored = []
    for record in values:
        addresses = tuple(reads._make_record(reads.QueryReadAddress, {
            "table": address["table"], "key_json": _ascii_bytes(address["keyJson"], work),
            "key_digest": address["keyDigest"], "present": address["present"],
        }, work) for address in record["addresses"])
        restored.append(reads._make_record(reads.QueryRead, {
            "query_id": record["queryId"],
            "declared_query_json": _ascii_bytes(record["declaredQueryJson"], work),
            "resolved_query_json": _ascii_bytes(record["resolvedQueryJson"], work),
            "addresses": addresses, "returned_row_count": record["returnedRowCount"],
        }, work))
    return tuple(restored)


def _bind_complete_declarations(raw, program, work: _ValidationWork) -> None:
    # Four raw fields suffice. contract_value/projection_digest would perform
    # unnecessary additional profile hashes and are deliberately not called.
    generated = [{"operation": query.operation, "role": query.role,
        "selectorItems": [list(pair) for pair in query.selector_items],
        "maximumRows": query.maximum_rows} for query in program
        if type(query) is complete.CompleteIndexQuery]
    work.prepare_comparison(raw, generated)
    if raw != generated:
        raise RevocationReadWriteError("revocation proof declarations differ from the ordered source recipe")


def _bind_point_keys(program, records, work: _ValidationWork) -> None:
    for query, record in zip(program, records):
        if type(query) is complete.CompleteIndexQuery:
            continue
        columns = PRIMARY_KEY_COLUMNS[query.table]
        if (type(query) is not core.BoundedQuery or query.maximum_rows != 1
                or query.proof_primitive != "primary-key-row"
                or type(query.absent_key) is not dict or set(query.absent_key) != set(columns)
                or len(query.predicates) != len(columns)
                or tuple(sorted(predicate.column for predicate in query.predicates)) != tuple(sorted(columns))
                or any(predicate.operator != "eq" or type(predicate.value) not in (str, int, bool)
                       for predicate in query.predicates)
                or tuple((order.column, order.descending) for order in query.order_by)
                    != tuple((column, False) for column in columns)):
            raise RevocationReadWriteError("revocation ordinary query is not an exact full-key source lookup")
        predicate_key = {predicate.column: predicate.value for predicate in query.predicates}
        work.prepare_comparison(predicate_key, query.absent_key)
        if predicate_key != query.absent_key or len(record.addresses) != 1:
            raise RevocationReadWriteError("revocation point observation lost its full source key")
        expected = work.wire(query.absent_key)
        address = record.addresses[0]
        work.charge(input_bytes=len(expected) + len(address.key_json))
        if (address.table != query.table or address.key_json != expected
                or record.returned_row_count != int(address.present)):
            raise RevocationReadWriteError("revocation point observation differs from its exact source key")


def _bind_complete_order(proved, records, work: _ValidationWork) -> None:
    by_query = {record.query_id: record for record in records}
    joined = dict(proved.joined_reads)
    for query in proved.queries:
        record = by_query[query.query_id]
        leaves = joined[query.query_id].leaves
        actual = {"queryId": record.query_id, "returnedRowCount": record.returned_row_count,
            "addresses": [[address.table, address.key_digest, address.present] for address in record.addresses]}
        expected = {"queryId": query.query_id, "returnedRowCount": len(leaves),
            "addresses": [[query.table, leaf.primary_key_digest, True] for leaf in leaves]}
        # Includes empty observations; complete order comes from actual joined
        # leaves, never from caller ordering or an independently returned token.
        work.prepare_comparison(actual, expected)
        if actual != expected:
            raise RevocationReadWriteError("revocation complete observation differs from genuine joined order")


def _verify(owned, ledger, raw_decode_bytes, capture) -> RevocationReadWriteInputs:
    """Run the genuine mixed phases on one already-owned private raw graph.

    An enclosing private composer supplies the same cumulative ledger. This
    worker neither captures caller inputs nor accepts a prior proof result.
    """
    operation = owned["operation"]
    # The no-audit recipe itself does not consume this field. Enforce its
    # canonical syntax unconditionally after complete raw ownership.
    core.require_digest(owned["requestDigest"], "revocation request digest")
    work = _ValidationWork(QueryReadValidationLimits(*ledger.remaining()))
    program = candidate._revocation_query_program(arguments=owned["arguments"],
        cutoff_us=owned["cutoffUs"], request_digest=owned["requestDigest"],
        evidence=owned["assertionBinding"], work=work)
    generation = before = work.metrics
    _bind_complete_declarations(owned["queries"], program, work)
    declaration_binding = _delta(before, work.metrics)
    before = work.metrics
    records = _restore_reads(owned["queryReads"], work)
    program, records = reads._validate_query_reads(operation, queries=program, query_reads=records,
        selected_rows=tuple(owned["selectedRows"]), work=work)
    observation_validation = _delta(before, work.metrics)
    before = work.metrics
    _bind_point_keys(program, records, work)
    point_binding = _delta(before, work.metrics)
    # Exactly one debit of this remaining-clamped work phase, before proof
    # workers request their limits. Failed phases abort; no retry or refund.
    ledger.charge(hashes=work.hash_work, input_bytes=work.input_bytes, json_nodes=work.json_nodes)
    before = ledger.work.metrics
    proved = read_write._verify(owned, ledger, capture.input_bytes, capture.json_nodes)
    proof_work = _delta(before, ledger.work.metrics)
    before = ledger.work.metrics
    # Charge the CURRENT outer ledger, not the now-stale pre-proof phase.
    _bind_complete_order(proved, records, ledger.work)
    complete_binding = _delta(before, ledger.work.metrics)
    return RevocationReadWriteInputs(
        operation=proved.operation, arguments=proved.arguments, cutoff_us=proved.cutoff_us,
        request_digest=owned["requestDigest"], assertion_binding=owned["assertionBinding"],
        query_program=program, query_reads=records,
        business_before_roots=proved.business_before_roots,
        authorization_before_roots=proved.authorization_before_roots,
        selected_rows=proved.selected_rows, before_proofs=proved.before_proofs,
        mutations=proved.mutations, queries=proved.queries,
        before_heads=proved.before_heads, after_heads=proved.after_heads,
        query_frontiers=proved.query_frontiers, write_frontiers=proved.write_frontiers,
        joined_reads=proved.joined_reads, read_primary=proved.read_primary, write=proved.write,
        projection_manifest_digest=proved.projection_manifest_digest,
        metrics=RevocationReadWriteMetrics(raw_decode_bytes, capture.input_bytes, capture.json_nodes,
            generation, declaration_binding, observation_validation, point_binding, proof_work,
            complete_binding, ledger.hashes, ledger.input_bytes, ledger.json_nodes),
    )


def verify_revocation_read_write_inputs(
    *, operation: str, arguments: dict[str, Any], cutoff_us: int,
    request_digest: str, assertion_binding: dict[str, str], query_reads: tuple[reads.QueryRead, ...],
    queries: tuple[complete.CompleteIndexQuery, ...],
    business_before_roots: Any, authorization_before_roots: Any,
    selected_rows: tuple[dict[str, Any], ...], before_proofs: tuple[dict[str, Any], ...],
    mutations: tuple[dict[str, Any], ...],
    counted_before_heads: tuple[read_write.CompleteReadWriteHead, ...],
    query_frontiers: tuple[query_batch.CompleteQueryFrontier, ...],
    write_frontiers: tuple[read_write.CompleteWriteFrontier, ...],
    limits: QueryReadValidationLimits | None = None,
) -> RevocationReadWriteInputs:
    """Recompute one owned mixed batch; limits may only lower source ceilings.

    Digest syntax and the two assertion IDs are context, not signatures. The
    full source counter slot is required even when absent; its initialized
    capacity and proposed mutation semantics are not admitted by this helper.
    No SQL, kernel, public composer reset or parser of retained query JSON runs.
    """
    try:
        ledger = _Ledger(QueryReadValidationLimits() if limits is None else limits)
        owned, raw_decode_bytes, capture = _capture(
            ledger=ledger, operation=operation, arguments=arguments, cutoff_us=cutoff_us,
            request_digest=request_digest, assertion_binding=assertion_binding, query_reads=query_reads,
            queries=queries, business_before_roots=business_before_roots,
            authorization_before_roots=authorization_before_roots, selected_rows=selected_rows,
            before_proofs=before_proofs, mutations=mutations, counted_before_heads=counted_before_heads,
            query_frontiers=query_frontiers, write_frontiers=write_frontiers,
        )
        return _verify(owned, ledger, raw_decode_bytes, capture)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError,
            core.TransitionKernelError) as exc:
        if isinstance(exc, RevocationReadWriteError):
            raise
        raise RevocationReadWriteError("revocation mixed read/write verification failed") from exc
