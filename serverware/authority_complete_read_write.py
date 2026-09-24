"""One source-bound complete-read and counted-write computation.

This composes the fixed revocation, registration or aggregate trust-stage
query family with genuine primary and counted write evaluation under one
private ledger. All caller evidence is owned before hashing; successful observations are not inputs.
Source mutation templates restrict the proposed write shapes, not their intent.

No kernel, audit-capacity admission, SQL, trusted clock, population genesis,
root currentness, Snapshot/witness protocol or operation authorization is
established. Returned owned JSON graphs are observations, not authority tokens.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from serverware import authority_audit_capacity as capacity
from serverware import authority_complete_query as complete
from serverware import authority_complete_query_batch as query_batch
from serverware import authority_contract
from serverware import authority_index_join as join
from serverware import authority_index_mutation as sparse
from serverware import authority_index_projection as projection
from serverware import authority_indexed_mutation as indexed
from serverware import authority_radix_mutation as primary
from serverware.authority_index_contract import (
    I64_MAX, KEY_NIBBLES, CountedNode, IndexLeaf, OpaqueSubtree, empty_node,
)
from serverware.authority_primary_contract import primary_table_contracts
from serverware.authority_transition_core import TransitionKernelError


MAX_TOTAL_HASHES = query_batch.MAX_TOTAL_HASHES
MAX_TOTAL_INPUT_BYTES = query_batch.MAX_TOTAL_INPUT_BYTES
MAX_TOTAL_JSON_NODES = query_batch.MAX_TOTAL_JSON_NODES
MAX_COUNTED_HEADS = len(projection.INDEX_IDS)
_MUTATION_FIELDS = frozenset({
    "templateId", "operation", "table", "key", "keyDigest", "expectedRow", "row",
})


class CompleteReadWriteError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class CompleteReadWriteHead:
    index_id: str
    index_revision: int
    index_root: CountedNode


@dataclass(frozen=True, slots=True)
class CompleteWriteFrontier:
    index_id: str
    frontier: tuple[IndexLeaf | OpaqueSubtree, ...]


@dataclass(frozen=True, slots=True)
class CompleteReadWriteMetrics:
    ownership_bytes: int
    ownership_nodes: int
    selected_envelope_bytes: int
    selected_envelope_nodes: int
    read_context_hashes: int
    read_primary: primary.PrimaryRadixMetrics
    queries: tuple[tuple[str, join.IndexJoinMetrics], ...]
    write_context_hashes: int
    write: indexed.IndexedMutationMetrics
    total_hashes: int
    total_input_bytes: int
    total_json_nodes: int


@dataclass(frozen=True, slots=True)
class CompleteReadWriteInputs:
    operation: str
    arguments: dict[str, Any]
    cutoff_us: int
    business_before_roots: tuple[primary.PrimaryRoot, ...]
    authorization_before_roots: tuple[primary.PrimaryRoot, ...]
    selected_rows: tuple[dict[str, Any], ...]
    before_proofs: tuple[dict[str, Any], ...]
    mutations: tuple[dict[str, Any], ...]
    queries: tuple[complete.CompleteIndexQuery, ...]
    before_heads: tuple[CompleteReadWriteHead, ...]
    after_heads: tuple[CompleteReadWriteHead, ...]
    query_frontiers: tuple[query_batch.CompleteQueryFrontier, ...]
    write_frontiers: tuple[CompleteWriteFrontier, ...]
    joined_reads: tuple[tuple[str, join.JoinedIndexObservation], ...]
    read_primary: primary.PrimaryRadixBatchResult
    write: indexed.IndexedMutationResult
    projection_manifest_digest: str
    metrics: CompleteReadWriteMetrics


def _source_sizes(spec: dict[str, Any]) -> tuple[int, int, int]:
    changes = 2 * min(spec["maximumMutations"], spec["maximumQueryRows"])
    opened = 1 + KEY_NIBBLES * changes
    return changes, opened, 16 * opened


def _frontier_preflight(query_frontiers, write_frontiers, maximum: int, *, family=None) -> None:
    """Reject necessarily over-budget normalization before building records.

    Each normalized terminal has a dict plus four keys and four scalar values:
    at least nine JSON nodes. This is a necessary whole-graph check, not a
    promise about interpreter allocation or acceptance at this isolated bound.
    """
    # The existing revocation composer also calls this bounded normalization
    # preflight before argument capture. Preserve its original six-role bound.
    # New family callers always supply a source-derived profile and the actual
    # proof verifier independently rebinds their complete inventory afterward.
    if family is None:
        family = {"query_count": query_batch.QUERY_COUNT,
                  "max_frontier_rows": complete.CASCADE_MAX}
    if (type(query_frontiers) is not tuple or len(query_frontiers) != family["query_count"]
            or type(write_frontiers) is not tuple or len(write_frontiers) > MAX_COUNTED_HEADS):
        raise CompleteReadWriteError("complete read/write frontier inventories are not bounded exact tuples")
    total = 0
    for inventory, expected, limit in (
        (query_frontiers, query_batch.CompleteQueryFrontier,
         query_batch.MAX_OUTSIDE_PREFIXES + family["max_frontier_rows"]),
        (write_frontiers, CompleteWriteFrontier, maximum),
    ):
        for item in inventory:
            if type(item) is not expected or type(item.frontier) is not tuple or len(item.frontier) > limit:
                raise CompleteReadWriteError("complete read/write frontier exceeds its source inventory")
            total += len(item.frontier)
            if total > MAX_TOTAL_JSON_NODES // 9:
                raise CompleteReadWriteError("complete read/write frontier normalization exceeds its node budget")


def _raw_records(frontier) -> list[dict[str, Any]]:
    records = []
    for item in frontier:
        if type(item) is IndexLeaf:
            records.append({"kind": "leaf", "key": item.key,
                            "primaryKeyDigest": item.primary_key_digest,
                            "primaryRowDigest": item.primary_row_digest})
        elif type(item) is OpaqueSubtree:
            records.append({"kind": "opaque", "prefix": item.prefix,
                            "digest": item.digest, "count": item.count})
        else:
            raise CompleteReadWriteError("complete read/write frontier has an unexpected record type")
    return records


def _raw_document(*, operation, arguments, cutoff_us, queries,
                  business_before_roots, authorization_before_roots, selected_rows,
                  before_proofs, mutations, counted_before_heads, query_frontiers,
                  write_frontiers):
    """Normalize without hashing; returned JSON still aliases caller values.

    An enclosing private composer may extend this document before its one
    ownership pass. Only the completed _JSONCapture copy may reach _verify.
    """
    # All preparation here is non-hashing. Even later-role/frontier/row graphs
    # must be detached before the first source/profile constructor can run.
    family = complete.family_limits(operation, arguments=arguments)
    spec = authority_contract.operation_spec(operation)
    if (type(mutations) is not tuple or len(mutations) > spec["maximumMutations"]
            or type(counted_before_heads) is not tuple
            or not family["head_count"] <= len(counted_before_heads) <= MAX_COUNTED_HEADS
            or type(queries) is not tuple or len(queries) != family["query_count"]
            or any(type(item) is not complete.CompleteIndexQuery for item in queries)):
        raise CompleteReadWriteError("complete read/write raw inventory exceeds its source bound")
    # The aggregate family cannot turn repeated per-credential ranges into
    # independent business allowances. The complete read phase will genuinely
    # rebind every declaration; this cheap check only rejects impossible raw
    # programs before constructing their potentially large frontier graph.
    maximum_rows = 0
    for query in queries:
        if (type(query.maximum_rows) is not int
                or not 1 <= query.maximum_rows <= family["max_frontier_rows"]):
            raise CompleteReadWriteError("complete read/write query ceiling exceeds its actual family")
        maximum_rows += query.maximum_rows
        if maximum_rows > spec["maximumBusinessQueryRows"]:
            raise CompleteReadWriteError("complete read/write aggregate query ceilings exceed the business allowance")
    _frontier_preflight(query_frontiers, write_frontiers, _source_sizes(spec)[2], family=family)
    raw_heads = []
    for head in counted_before_heads:
        if type(head) is not CompleteReadWriteHead or type(head.index_root) is not CountedNode:
            raise CompleteReadWriteError("complete read/write head has an unexpected exact type")
        if (type(head.index_id) is not str or not 1 <= len(head.index_id) <= 128
                or head.index_id not in projection.INDEX_IDS):
            raise CompleteReadWriteError("complete read/write head identity is not source admitted")
        raw_heads.append({"indexId": head.index_id, "indexRevision": head.index_revision,
                          "rootDigest": head.index_root.digest, "leafCount": head.index_root.count})
    # index_id is a hash-free source role property. Neither projection_digest
    # nor contract_value may be called while any input still aliases its caller.
    read_ids = {item.index_id for item in queries}
    read_heads = tuple(query_batch.CompleteQueryHead(
        item["indexId"], item["indexRevision"], CountedNode(item["rootDigest"], item["leafCount"]),
    ) for item in raw_heads if item["indexId"] in read_ids)
    document = query_batch._raw_document(
        operation=operation, arguments=arguments, cutoff_us=cutoff_us, queries=queries,
        business_before_roots=business_before_roots,
        authorization_before_roots=authorization_before_roots, selected_rows=selected_rows,
        before_proofs=before_proofs, read_heads=read_heads, query_frontiers=query_frontiers,
    )
    del document["readHeads"]
    document["countedBeforeHeads"] = raw_heads
    document["mutations"] = list(mutations)
    document["writeFrontiers"] = [
        {"indexId": item.index_id, "frontier": _raw_records(item.frontier)}
        for item in write_frontiers
    ]
    return document


def _capture(*, ledger, operation, arguments, cutoff_us, queries,
             business_before_roots, authorization_before_roots, selected_rows,
             before_proofs, mutations, counted_before_heads, query_frontiers,
             write_frontiers):
    document = _raw_document(
        operation=operation, arguments=arguments, cutoff_us=cutoff_us, queries=queries,
        business_before_roots=business_before_roots,
        authorization_before_roots=authorization_before_roots, selected_rows=selected_rows,
        before_proofs=before_proofs, mutations=mutations, counted_before_heads=counted_before_heads,
        query_frontiers=query_frontiers, write_frontiers=write_frontiers,
    )
    return query_batch._JSONCapture(ledger).visit(document)


def _address(item: dict[str, Any], contracts) -> tuple[tuple, tuple]:
    """Cheap typed-key/digest alias admission, without a new hash/JSON pass."""
    table, key, digest = item.get("table"), item.get("key"), item.get("keyDigest")
    if type(table) is not str or not 1 <= len(table) <= 128 or table not in contracts:
        raise CompleteReadWriteError("complete read/write row table is outside its source contract")
    columns = contracts[table].key_columns
    if (type(key) is not dict or len(key) != len(columns) or set(key) != set(columns)
            or any(type(key[column]) not in (str, int, bool) for column in columns)
            or type(digest) is not str or len(digest) != 71 or not digest.startswith("sha256:")
            or any(character not in "0123456789abcdef" for character in digest[7:])):
        raise CompleteReadWriteError("complete read/write row key or commitment is invalid")
    # bool and int are distinct canonical JSON keys despite Python equality.
    identity = (table, tuple((type(key[column]), key[column]) for column in columns))
    return identity, (table, digest)


def _admit_mutations(owned, contracts) -> tuple[str, ...]:
    operation = owned["operation"]
    spec = authority_contract.operation_spec(operation)
    by_table = {item.table: item for item in contracts}
    selected_keys, selected_addresses = {}, set()
    for item in owned["selectedRows"]:
        if (type(item) is not dict or len(item) != len(query_batch._SELECTED_FIELDS)
                or set(item) != query_batch._SELECTED_FIELDS
                or item["contractSelector"] is not None):
            raise CompleteReadWriteError("complete read/write global selection wrapper is invalid")
        identity, address = _address(item, by_table)
        if identity in selected_keys or address in selected_addresses:
            raise CompleteReadWriteError("complete read/write global selection has duplicate aliases")
        selected_keys[identity] = address
        selected_addresses.add(address)
    proof_addresses = set()
    for proof in owned["beforeProofs"]:
        if type(proof) is not dict:
            raise CompleteReadWriteError("complete read/write primary proof is not an object")
        table, digest = proof.get("table"), proof.get("keyDigest")
        if (type(table) is not str or not 1 <= len(table) <= 128
                or type(digest) is not str or len(digest) != 71):
            raise CompleteReadWriteError("complete read/write primary proof address is invalid")
        address = (table, digest)
        if address not in selected_addresses or address in proof_addresses:
            raise CompleteReadWriteError("complete read/write primary proofs have duplicate or unselected aliases")
        proof_addresses.add(address)
    if proof_addresses != selected_addresses:
        raise CompleteReadWriteError("complete read/write primary proofs omit a selected address")

    changes, addresses, tables = set(), set(), set()
    framework = business = 0
    for mutation in owned["mutations"]:
        if (type(mutation) is not dict or len(mutation) != len(_MUTATION_FIELDS)
                or set(mutation) != _MUTATION_FIELDS
                or type(mutation["templateId"]) is not str
                or not 1 <= len(mutation["templateId"]) <= 128
                or type(mutation["operation"]) is not str):
            raise CompleteReadWriteError("complete read/write mutation is not a closed source template")
        identity, address = _address(mutation, by_table)
        contract = by_table[mutation["table"]]
        template = authority_contract.mutation_template(operation, mutation["templateId"])
        if (not contract.write_access or contract.root_class != "business"
                or template["operation"] != operation
                or template["table"] != mutation["table"]
                or template["mutation"] != mutation["operation"]
                or template["predicate"] != "exact-primary-key-and-full-row-cas-v1"
                or type(template["cardinality"]) is not int or template["cardinality"] != 1):
            raise CompleteReadWriteError("complete read/write mutation differs from its source template")
        if (identity in changes or address in addresses
                or selected_keys.get(identity) != address):
            raise CompleteReadWriteError("complete read/write mutation is duplicated or unselected")
        old, new = mutation["expectedRow"], mutation["row"]
        if ((mutation["operation"] == "INSERT" and (old is not None or type(new) is not dict))
                or (mutation["operation"] == "UPDATE" and (type(old) is not dict or type(new) is not dict))
                or (mutation["operation"] == "DELETE" and (type(old) is not dict or new is not None))):
            raise CompleteReadWriteError("complete read/write mutation lifecycle is invalid")
        key = mutation["key"]
        is_framework = (mutation["table"] == capacity.AGGREGATE_TABLE
                        and len(key) == 1 and key.get("aggregate_id") == capacity.AGGREGATE_ID)
        framework += int(is_framework)
        business += int(not is_framework)
        changes.add(identity)
        addresses.add(address)
        tables.add(mutation["table"])
    if (framework > 1 or business > spec["maximumBusinessMutations"]
            or len(owned["mutations"]) > spec["maximumMutations"]):
        raise CompleteReadWriteError("complete read/write mutations exceed business or exact framework slots")
    # No separate mutation-byte envelope is invented. The whole ownership and
    # genuine writer traversals consume the same source 64 MiB shared ledger.
    return tuple(sorted(index_id for table in tables
                        for index_id in projection.index_ids_for_table(table)))


def _write_frontiers(values, expected_ids) -> tuple[CompleteWriteFrontier, ...]:
    if tuple(item["indexId"] for item in values) != expected_ids:
        raise CompleteReadWriteError("complete read/write frontier inventory is not the exact sorted write profile closure")
    result = []
    for item in values:
        records = []
        for raw in item["frontier"]:
            if raw["kind"] == "leaf":
                record = IndexLeaf(raw["key"], raw["primaryKeyDigest"], raw["primaryRowDigest"])
            else:
                record = OpaqueSubtree(raw["prefix"], raw["digest"], raw["count"])
            records.append(record)
        result.append(CompleteWriteFrontier(item["indexId"], tuple(records)))
    return tuple(result)


def _write_limits(spec, ledger) -> indexed.IndexedMutationLimits:
    hashes, input_bytes, nodes = ledger.remaining()
    maximum = spec["maximumQueryRows"]
    changes, opened, frontier_entries = _source_sizes(spec)
    return indexed.IndexedMutationLimits(
        primary=primary.PrimaryRadixLimits(
            max_selected_rows=maximum, max_mutations=spec["maximumMutations"],
            max_proof_vectors=authority_contract.TREE_DEPTH * maximum,
            max_proof_child_slots=authority_contract.TREE_DEPTH * authority_contract.TREE_RADIX * maximum,
            max_hashes=min(66 + 136 * maximum, hashes), max_input_bytes=input_bytes,
            max_json_depth=query_batch.MAX_JSON_DEPTH, max_json_nodes=nodes,
        ),
        index=sparse.IndexMutationLimits(
            max_changes=changes, max_frontier_entries=frontier_entries,
            max_opened_nodes=opened, max_hashes=min(2 * (16 * opened + changes), hashes),
            max_input_bytes=input_bytes,
        ),
        max_total_hashes=hashes, max_total_input_bytes=input_bytes,
    )


def _verify(owned, ledger, ownership_bytes, ownership_nodes) -> CompleteReadWriteInputs:
    operation = owned["operation"]
    contracts = primary_table_contracts(operation)
    write_ids = _admit_mutations(owned, contracts)
    # This private source-role lookup is hash-free. Actual declaration binding
    # and exact family closure still run inside the genuine read phase.
    read_ids = tuple(sorted({complete._role(operation, item["role"]).index_id
                             for item in owned["queries"]}))
    expected_union = tuple(sorted(set(read_ids) | set(write_ids)))
    if tuple(item["indexId"] for item in owned["countedBeforeHeads"]) != expected_union:
        raise CompleteReadWriteError("complete read/write heads are not the exact sorted read/write union")
    frontiers = _write_frontiers(owned["writeFrontiers"], write_ids)
    # Use one captured graph and one ledger, not the public query API. Its
    # temporary cumulative totals include this larger capture; they are NOT
    # exported as standalone query costs in the combined observation.
    read_document = dict(owned)
    read_document["readHeads"] = [item for item in owned["countedBeforeHeads"]
                                  if item["indexId"] in read_ids]
    reads = query_batch._verify(read_document, ledger, ownership_bytes, ownership_nodes)
    head_map = {item.index_id: CompleteReadWriteHead(
        item.index_id, item.index_revision, item.index_root) for item in reads.read_heads}
    extra_ids = set(expected_union) - set(read_ids)
    write_context_hashes = 2 * len(extra_ids)
    # Exactly one source profile and one canonical empty hash for each head
    # not already checked by the read phase. No new manifest or output digest.
    ledger.charge(hashes=write_context_hashes)
    primary_by_table = {item.table: item for item in
                        reads.business_before_roots + reads.authorization_before_roots}
    for raw in owned["countedBeforeHeads"]:
        if raw["indexId"] not in extra_ids:
            continue
        profile = projection.profile_for(raw["indexId"])
        root = CountedNode(raw["rootDigest"], raw["leafCount"])
        revision = raw["indexRevision"]
        empty = empty_node(profile, "")
        if (type(revision) is not int or not 0 <= revision <= I64_MAX
                or (revision == 0 and root.count != 0)
                or (root.count == 0) != (root.digest == empty.digest)
                or root.count > primary_by_table[profile.table].leaf_count):
            raise CompleteReadWriteError("complete read/write head revision, emptiness or primary population differs")
        head_map[profile.index_id] = CompleteReadWriteHead(profile.index_id, revision, root)
    before_heads = tuple(head_map[identity] for identity in expected_union)
    mutations = tuple(owned["mutations"])
    index_inputs = tuple(indexed.IndexedMutationInput(
        item.index_id, head_map[item.index_id].index_revision,
        head_map[item.index_id].index_root, item.frontier,
    ) for item in frontiers)
    write = indexed.evaluate_indexed_primary_batch(
        table_contracts=contracts, business_before_roots=reads.business_before_roots,
        authorization_before_roots=reads.authorization_before_roots,
        selected_rows=reads.selected_rows, before_proofs=reads.before_proofs,
        mutations=mutations, index_inputs=index_inputs,
        limits=_write_limits(authority_contract.operation_spec(operation), ledger),
    )
    ledger.charge(hashes=write.metrics.hashes, input_bytes=write.metrics.input_bytes,
                  json_nodes=write.metrics.primary.json_nodes)
    after_map = dict(head_map)
    for head in write.after_heads:
        after_map[head.index_id] = CompleteReadWriteHead(head.index_id, head.index_revision, head.index_root)
    after_heads = tuple(after_map[identity] for identity in expected_union)
    return CompleteReadWriteInputs(
        operation=operation, arguments=reads.arguments, cutoff_us=reads.cutoff_us,
        business_before_roots=reads.business_before_roots,
        authorization_before_roots=reads.authorization_before_roots,
        selected_rows=reads.selected_rows, before_proofs=reads.before_proofs,
        mutations=mutations, queries=reads.queries, before_heads=before_heads, after_heads=after_heads,
        query_frontiers=reads.query_frontiers, write_frontiers=frontiers,
        joined_reads=reads.joined_reads, read_primary=reads.primary, write=write,
        projection_manifest_digest=reads.projection_manifest_digest,
        metrics=CompleteReadWriteMetrics(
            ownership_bytes, ownership_nodes, reads.metrics.selected_envelope_bytes,
            reads.metrics.selected_envelope_nodes, reads.metrics.context_hashes,
            reads.metrics.primary, reads.metrics.queries, write_context_hashes, write.metrics,
            ledger.hashes, ledger.input_bytes, ledger.json_nodes,
        ),
    )


def verify_complete_read_write_batch(
    *, operation: str, arguments: dict[str, Any], cutoff_us: int,
    queries: tuple[complete.CompleteIndexQuery, ...],
    business_before_roots: Any, authorization_before_roots: Any,
    selected_rows: tuple[dict[str, Any], ...], before_proofs: tuple[dict[str, Any], ...],
    mutations: tuple[dict[str, Any], ...],
    counted_before_heads: tuple[CompleteReadWriteHead, ...],
    query_frontiers: tuple[query_batch.CompleteQueryFrontier, ...],
    write_frontiers: tuple[CompleteWriteFrontier, ...],
) -> CompleteReadWriteInputs:
    """Recompute raw complete reads and proposed writes under one source budget.

    The source admits at most 192 ordinary selections plus one exact optional
    framework address, and 136 ordinary mutations plus that exact address.
    Initialized counter state, audit deltas and authorized kernel intent remain
    outside this component. Every affected fixed write profile is required even
    when OLD and NEW are both nonmembers. Read-only after heads remain unchanged.

    The shared node count measures the normalized ownership graph, both selected
    envelope walks and every genuine primary traversal; bounded scalar context
    and counted-tree encoders do not become JSON nodes. Output has no new wire
    schema, digest, authority token or planner activation.
    """
    ledger = query_batch._Ledger()
    try:
        owned = _capture(
            ledger=ledger, operation=operation, arguments=arguments, cutoff_us=cutoff_us,
            queries=queries, business_before_roots=business_before_roots,
            authorization_before_roots=authorization_before_roots, selected_rows=selected_rows,
            before_proofs=before_proofs, mutations=mutations, counted_before_heads=counted_before_heads,
            query_frontiers=query_frontiers, write_frontiers=write_frontiers,
        )
        return _verify(owned, ledger, ledger.input_bytes, ledger.json_nodes)
    except (AttributeError, TypeError, ValueError, OverflowError, RecursionError,
            TransitionKernelError) as exc:
        if isinstance(exc, CompleteReadWriteError):
            raise
        raise CompleteReadWriteError("complete read/write raw evidence verification failed") from exc
