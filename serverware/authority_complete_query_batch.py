"""Source-bound complete-query verification, not operation authority.

Only the five explicit credential-revocation roles are admitted. Every raw
input is detached before any hashing constructor or verifier runs. One genuine
global primary membership evaluation owns the rows used by five genuine joins;
their repeated proof work is charged, including empty queries and shared heads.

The reader-sized frontier profile is intentionally narrower than the generic
range verifier: excessive outside subdivisions are rejected. No SQL, trusted
clock, index population/currentness, mixed QueryRead closure, kernel admission,
audit-capacity validation or Snapshot/witness authority is established here.
Returned owned dictionaries are observations, never accepted success tokens.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from serverware import authority_audit_capacity as capacity
from serverware import authority_complete_query as complete
from serverware import authority_contract
from serverware import authority_index_join as join
from serverware import authority_index_projection as projection
from serverware import authority_radix_mutation as primary
from serverware.authority_index_contract import (
    I64_MAX, KEY_NIBBLES, CountedNode, IndexLeaf, OpaqueSubtree, empty_node,
)
from serverware.authority_index_frontier import MAX_OUTSIDE_PREFIXES
from serverware.authority_index_range import IndexRangeLimits
from serverware.authority_primary_contract import primary_table_contracts
from serverware.authority_transition_core import TransitionKernelError, canonical_bytes


MAX_TOTAL_HASHES = 8_000_000
MAX_TOTAL_INPUT_BYTES = 64 * 1024 * 1024
MAX_TOTAL_JSON_NODES = 1_000_000
MAX_JSON_DEPTH = 128
QUERY_COUNT = 5
READ_HEAD_COUNT = 4
# Cold primary roots; five initial declarations and ten binding constructors;
# four profiles and four empty roots; five outer anchors; one source manifest.
# Each join separately charges its own complete conservative context allowance.
CONTEXT_HASH_ALLOWANCE = 66 + 5 + 10 + 4 + 4 + 5 + 1
_ROOT_FIELDS = frozenset({"table", "rootRevision", "rootDigest", "leafCount"})
_SELECTED_FIELDS = frozenset({"table", "key", "keyDigest", "present", "row", "contractSelector"})


class CompleteQueryBatchError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class CompleteQueryHead:
    index_id: str
    index_revision: int
    index_root: CountedNode


@dataclass(frozen=True, slots=True)
class CompleteQueryFrontier:
    query_id: str
    frontier: tuple[IndexLeaf | OpaqueSubtree, ...]


@dataclass(frozen=True, slots=True)
class CompleteQueryBatchMetrics:
    ownership_bytes: int
    ownership_nodes: int
    selected_envelope_bytes: int
    selected_envelope_nodes: int
    context_hashes: int
    primary: primary.PrimaryRadixMetrics
    queries: tuple[tuple[str, join.IndexJoinMetrics], ...]
    total_hashes: int
    total_input_bytes: int
    total_json_nodes: int


@dataclass(frozen=True, slots=True)
class CompleteQueryBatchInputs:
    operation: str
    arguments: dict[str, Any]
    cutoff_us: int
    business_before_roots: tuple[primary.PrimaryRoot, ...]
    authorization_before_roots: tuple[primary.PrimaryRoot, ...]
    selected_rows: tuple[dict[str, Any], ...]
    before_proofs: tuple[dict[str, Any], ...]
    queries: tuple[complete.CompleteIndexQuery, ...]
    read_heads: tuple[CompleteQueryHead, ...]
    query_frontiers: tuple[CompleteQueryFrontier, ...]
    joined_reads: tuple[tuple[str, join.JoinedIndexObservation], ...]
    primary: primary.PrimaryRadixBatchResult
    projection_manifest_digest: str
    metrics: CompleteQueryBatchMetrics


class _Ledger:
    """One private verification ledger; no externally supplied budget/token."""

    def __init__(self) -> None:
        self.hashes = self.input_bytes = self.json_nodes = 0

    def charge(self, *, hashes: int = 0, input_bytes: int = 0, json_nodes: int = 0) -> None:
        if (hashes < 0 or input_bytes < 0 or json_nodes < 0
                or hashes > MAX_TOTAL_HASHES - self.hashes
                or input_bytes > MAX_TOTAL_INPUT_BYTES - self.input_bytes
                or json_nodes > MAX_TOTAL_JSON_NODES - self.json_nodes):
            raise CompleteQueryBatchError("complete query batch exceeds its shared verification budget")
        self.hashes += hashes
        self.input_bytes += input_bytes
        self.json_nodes += json_nodes

    def remaining(self) -> tuple[int, int, int]:
        values = (MAX_TOTAL_HASHES - self.hashes, MAX_TOTAL_INPUT_BYTES - self.input_bytes,
                  MAX_TOTAL_JSON_NODES - self.json_nodes)
        if min(values) < 1:
            raise CompleteQueryBatchError("complete query batch has no remaining phase budget")
        return values


class _JSONCapture:
    """Exact compact ASCII JSON measurement and optional lossless ownership.

    Every container and scalar, including dictionary keys, is a node. Byte
    charges include punctuation and ASCII escapes before children are retained.
    This measures a normalized internal document, not received transport bytes
    or process allocation. Measurement-only envelope passes remain real work
    and are charged separately; they do not reuse the capture's byte allowance.
    """

    def __init__(self, ledger: _Ledger, *, maximum_bytes: int = MAX_TOTAL_INPUT_BYTES,
                 retain: bool = True) -> None:
        self.ledger, self.maximum_bytes, self.retain = ledger, maximum_bytes, retain
        self.bytes = self.nodes = 0

    def _bytes(self, amount: int) -> None:
        if amount > self.maximum_bytes - self.bytes:
            raise CompleteQueryBatchError("complete query JSON envelope exceeds its byte bound")
        self.ledger.charge(input_bytes=amount)
        self.bytes += amount

    def visit(self, value: Any, depth: int = 0,
              ancestors: frozenset[int] = frozenset()) -> Any:
        if depth > MAX_JSON_DEPTH:
            raise CompleteQueryBatchError("complete query JSON exceeds its depth bound")
        self.ledger.charge(json_nodes=1)
        self.nodes += 1
        kind = type(value)
        if value is None or kind is bool:
            self._bytes(4 if value is None or value is True else 5)
            return value if self.retain else None
        if kind is int:
            if value.bit_length() > 16384:
                raise CompleteQueryBatchError("complete query JSON integer exceeds its encoding bound")
            self._bytes(len(canonical_bytes(value)))
            return value if self.retain else None
        if kind is str:
            if len(value) > self.maximum_bytes - self.bytes:
                raise CompleteQueryBatchError("complete query JSON string exceeds its byte bound")
            size = 2
            for character in value:
                point = ord(character)
                if point == 0 or 0xD800 <= point <= 0xDFFF:
                    raise CompleteQueryBatchError("complete query JSON string is not lossless UTF-8")
                size += (2 if character in '"\\\b\f\n\r\t' else
                         12 if point > 0xFFFF else
                         6 if point < 32 or point >= 127 else 1)
                if size > self.maximum_bytes - self.bytes:
                    raise CompleteQueryBatchError("complete query JSON string exceeds its byte bound")
            self._bytes(size)
            return value if self.retain else None
        if kind not in (dict, list):
            raise CompleteQueryBatchError("complete query inputs require exact lossless JSON types")
        if id(value) in ancestors:
            raise CompleteQueryBatchError("complete query JSON is cyclic")
        minimum_nodes = len(value) * (2 if kind is dict else 1)
        if minimum_nodes > MAX_TOTAL_JSON_NODES - self.ledger.json_nodes:
            raise CompleteQueryBatchError("complete query JSON exceeds its node bound")
        self._bytes(2 + max(0, len(value) - 1) + (len(value) if kind is dict else 0))
        branch = ancestors | {id(value)}
        if kind is dict:
            owned = {} if self.retain else None
            for key, child in value.items():
                if type(key) is not str:
                    raise CompleteQueryBatchError("complete query JSON key is not an exact string")
                fresh_key = self.visit(key, depth + 1, branch)
                fresh_child = self.visit(child, depth + 1, branch)
                if self.retain:
                    owned[fresh_key] = fresh_child
            return owned
        owned = [] if self.retain else None
        for child in value:
            fresh = self.visit(child, depth + 1, branch)
            if self.retain:
                owned.append(fresh)
        return owned


def _raw_roots(values: Any) -> list[dict[str, Any]]:
    if type(values) not in (list, tuple) or len(values) > authority_contract.MAX_QUERY_PROOFS:
        raise CompleteQueryBatchError("complete query primary roots are not a bounded wire array")
    result = []
    for value in values:
        if (type(value) is not dict or len(value) != 4
                or any(type(key) is not str for key in value) or set(value) != _ROOT_FIELDS):
            raise CompleteQueryBatchError("complete query primary root descriptor is not closed")
        result.append(dict(value))
    return result


def _capture(*, ledger: _Ledger, operation, arguments, cutoff_us, queries,
             business_before_roots, authorization_before_roots, selected_rows,
             before_proofs, read_heads, query_frontiers) -> dict[str, Any]:
    """No constructor/profile/hash call may precede the completed JSON copy."""
    if type(operation) is not str or operation != complete.OPERATION:
        raise CompleteQueryBatchError("complete query batch operation is not source admitted")
    spec = authority_contract.operation_spec(operation)
    if (type(arguments) is not dict or len(arguments) > complete.MAX_ARGUMENT_FIELDS
            or type(cutoff_us) is not int or not -(2**63) <= cutoff_us <= I64_MAX
            or type(queries) is not tuple or len(queries) != QUERY_COUNT
            or type(read_heads) is not tuple or len(read_heads) != READ_HEAD_COUNT
            or type(query_frontiers) is not tuple or len(query_frontiers) != QUERY_COUNT
            or type(selected_rows) is not tuple or len(selected_rows) > spec["maximumQueryRows"]
            or type(before_proofs) is not tuple or len(before_proofs) != len(selected_rows)):
        raise CompleteQueryBatchError("complete query batch raw inventory exceeds its source bound")
    raw_queries = []
    for query in queries:
        if type(query) is not complete.CompleteIndexQuery:
            raise CompleteQueryBatchError("complete query batch requires exact source declarations")
        items = query.selector_items
        if (type(items) is not tuple or len(items) > 2
                or any(type(item) is not tuple or len(item) != 2 for item in items)):
            raise CompleteQueryBatchError("complete query raw selector inventory is invalid")
        raw_queries.append({"operation": query.operation, "role": query.role,
                            "selectorItems": [list(item) for item in items],
                            "maximumRows": query.maximum_rows})
    raw_heads = []
    for head in read_heads:
        if type(head) is not CompleteQueryHead or type(head.index_root) is not CountedNode:
            raise CompleteQueryBatchError("complete query read head has an unexpected exact type")
        raw_heads.append({"indexId": head.index_id, "indexRevision": head.index_revision,
                          "rootDigest": head.index_root.digest, "leafCount": head.index_root.count})
    raw_frontiers = []
    for proof in query_frontiers:
        if (type(proof) is not CompleteQueryFrontier or type(proof.frontier) is not tuple
                or len(proof.frontier) > MAX_OUTSIDE_PREFIXES + complete.CASCADE_MAX):
            raise CompleteQueryBatchError("complete query frontier exceeds its reader-sized inventory")
        records = []
        for item in proof.frontier:
            if type(item) is IndexLeaf:
                records.append({"kind": "leaf", "key": item.key,
                                "primaryKeyDigest": item.primary_key_digest,
                                "primaryRowDigest": item.primary_row_digest})
            elif type(item) is OpaqueSubtree:
                records.append({"kind": "opaque", "prefix": item.prefix,
                                "digest": item.digest, "count": item.count})
            else:
                raise CompleteQueryBatchError("complete query frontier record has an unexpected exact type")
        raw_frontiers.append({"queryId": proof.query_id, "frontier": records})
    document = {
        "operation": operation, "arguments": arguments, "cutoffUs": cutoff_us,
        "queries": raw_queries, "businessBeforeRoots": _raw_roots(business_before_roots),
        "authorizationBeforeRoots": _raw_roots(authorization_before_roots),
        "selectedRows": list(selected_rows), "beforeProofs": list(before_proofs),
        "readHeads": raw_heads, "queryFrontiers": raw_frontiers,
    }
    return _JSONCapture(ledger).visit(document)


def _selected_envelopes(owned: dict[str, Any], ledger: _Ledger) -> tuple[int, int]:
    selected = owned["selectedRows"]
    business, framework_count = [], 0
    for item in selected:
        if (type(item) is not dict or len(item) != len(_SELECTED_FIELDS)
                or set(item) != _SELECTED_FIELDS or item["contractSelector"] is not None):
            raise CompleteQueryBatchError("complete query global selection wrapper or selector tag is invalid")
        # Budget classification only. Actual key/digest/row membership follows
        # in the primary engine. A missing or absent counter is not initialized
        # or admitted by this query-only component.
        key = item["key"]
        framework = (item["table"] == capacity.AGGREGATE_TABLE
                     and type(key) is dict and len(key) == 1
                     and key.get("aggregate_id") == capacity.AGGREGATE_ID)
        if framework:
            framework_count += 1
        else:
            business.append(item)
    spec = authority_contract.operation_spec(owned["operation"])
    if (framework_count > 1 or len(business) > spec["maximumBusinessQueryRows"]
            or len(selected) > spec["maximumQueryRows"]):
        raise CompleteQueryBatchError("complete query selection exceeds its business or exact framework slots")
    start_bytes, start_nodes = ledger.input_bytes, ledger.json_nodes
    # These are two additional exact canonical-encoding measurement walks,
    # not free cached lengths and not full audit-capacity state validation.
    _JSONCapture(ledger, maximum_bytes=authority_contract.MAX_REQUEST_BYTES,
                 retain=False).visit(business)
    _JSONCapture(ledger, maximum_bytes=authority_contract.MAX_PLAN_SELECTED_BYTES,
                 retain=False).visit(selected)
    return ledger.input_bytes - start_bytes, ledger.json_nodes - start_nodes


def _roots(values: list[dict[str, Any]]) -> tuple[primary.PrimaryRoot, ...]:
    roots, previous = [], ""
    for item in values:
        root = primary.PrimaryRoot(item["table"], item["rootRevision"],
                                   item["rootDigest"], item["leafCount"])
        if root.table <= previous:
            raise CompleteQueryBatchError("complete query primary roots are not sorted and unique")
        roots.append(root)
        previous = root.table
    return tuple(roots)


def _frontiers(values: list[dict[str, Any]],
               queries: tuple[complete.CompleteIndexQuery, ...]) -> tuple[CompleteQueryFrontier, ...]:
    owned = []
    for value, query in zip(values, queries):
        if (value["queryId"] != query.query_id
                or len(value["frontier"]) > MAX_OUTSIDE_PREFIXES + query.maximum_rows):
            raise CompleteQueryBatchError("complete query frontier identity or reader-sized bound changed")
        records, leaves, outside = [], 0, 0
        for item in value["frontier"]:
            if item["kind"] == "leaf":
                record = IndexLeaf(item["key"], item["primaryKeyDigest"], item["primaryRowDigest"])
                leaves += 1
            else:
                record = OpaqueSubtree(item["prefix"], item["digest"], item["count"])
                outside += 1
            if leaves > query.maximum_rows or outside > MAX_OUTSIDE_PREFIXES:
                raise CompleteQueryBatchError("complete query frontier exceeds its leaf or complement bound")
            records.append(record)
        owned.append(CompleteQueryFrontier(query.query_id, tuple(records)))
    return tuple(owned)


def _primary_limits(spec: dict[str, Any], maximum_rows: int, ledger: _Ledger) -> primary.PrimaryRadixLimits:
    hashes, input_bytes, nodes = ledger.remaining()
    return primary.PrimaryRadixLimits(
        max_selected_rows=maximum_rows, max_mutations=spec["maximumMutations"],
        max_proof_vectors=authority_contract.TREE_DEPTH * maximum_rows,
        max_proof_child_slots=authority_contract.TREE_DEPTH * authority_contract.TREE_RADIX * maximum_rows,
        max_hashes=min(66 + 70 * maximum_rows, hashes), max_input_bytes=input_bytes,
        max_json_depth=MAX_JSON_DEPTH, max_json_nodes=nodes,
    )


def _verify(owned: dict[str, Any], ledger: _Ledger,
            ownership_bytes: int, ownership_nodes: int) -> CompleteQueryBatchInputs:
    envelope_bytes, envelope_nodes = _selected_envelopes(owned, ledger)
    if (len(owned["businessBeforeRoots"]) + len(owned["authorizationBeforeRoots"])
            > authority_contract.MAX_QUERY_PROOFS):
        raise CompleteQueryBatchError("complete query primary root classes exceed their source inventory")
    # The complete raw graph is already privately owned. Reserve every outer
    # source/constructor hash before the first one can occur, without cache
    # discounts. Do not add property/contract serializers without auditing this.
    ledger.charge(hashes=CONTEXT_HASH_ALLOWANCE)
    initial_queries = tuple(complete.CompleteIndexQuery(
        item["operation"], item["role"], tuple(tuple(pair) for pair in item["selectorItems"]),
        item["maximumRows"],
    ) for item in owned["queries"])
    queries = complete.validate_bindings(
        owned["operation"], initial_queries,
        arguments=owned["arguments"], cutoff_us=owned["cutoffUs"],
    )
    spec = authority_contract.operation_spec(owned["operation"])
    contracts = primary_table_contracts(owned["operation"])
    allowed = {contract.table for contract in contracts}
    if (complete.PROOF_PRIMITIVE not in spec["proofPrimitives"]
            or any(query.table not in allowed for query in queries)
            or sum(query.maximum_rows for query in queries) > spec["maximumBusinessQueryRows"]):
        raise CompleteQueryBatchError("complete query roles escaped their source operation contract")
    business = _roots(owned["businessBeforeRoots"])
    authorization = _roots(owned["authorizationBeforeRoots"])
    frontiers = _frontiers(owned["queryFrontiers"], queries)
    expected_ids = tuple(sorted({query.index_id for query in queries}))
    if (len(expected_ids) != READ_HEAD_COUNT
            or tuple(item["indexId"] for item in owned["readHeads"]) != expected_ids):
        raise CompleteQueryBatchError("complete query read heads are not the exact sorted source union")
    heads, profiles = [], {}
    for item in owned["readHeads"]:
        profile = projection.profile_for(item["indexId"])
        profiles[profile.index_id] = profile
        root = CountedNode(item["rootDigest"], item["leafCount"])
        revision = item["indexRevision"]
        empty = empty_node(profile, "")
        if (type(revision) is not int or not 0 <= revision <= I64_MAX
                or (revision == 0 and root.count != 0)
                or (root.count == 0) != (root.digest == empty.digest)):
            raise CompleteQueryBatchError("complete query read head revision or empty-root convention changed")
        heads.append(CompleteQueryHead(profile.index_id, revision, root))
    manifest_digest = projection.projection_manifest_digest()

    memberships = primary.evaluate_primary_radix_memberships(
        table_contracts=contracts, business_before_roots=business,
        authorization_before_roots=authorization,
        selected_rows=tuple(owned["selectedRows"]), before_proofs=tuple(owned["beforeProofs"]),
        limits=_primary_limits(spec, spec["maximumQueryRows"], ledger),
    )
    global_metrics = memberships.result.metrics
    ledger.charge(hashes=global_metrics.hash_work, input_bytes=global_metrics.input_bytes,
                  json_nodes=global_metrics.json_nodes)
    if (memberships.result.business_after_roots != business
            or memberships.result.authorization_after_roots != authorization
            or global_metrics.mutations != 0 or global_metrics.recomputed_ancestors != 0):
        raise CompleteQueryBatchError("complete query global membership evaluation changed before roots")
    primary_by_table = {root.table: root for root in business + authorization}
    head_by_id = {head.index_id: head for head in heads}
    for head in heads:
        root = primary_by_table[profiles[head.index_id].table]
        if head.index_root.count > root.leaf_count:
            raise CompleteQueryBatchError("complete query index count exceeds its primary population descriptor")
    # Every query subset comes solely from this actual engine's owned graph.
    # Caller-provided per-query rows, primary anchors or verification results
    # are never accepted. The genuine join verifies the leaf/row bijection.
    selected_by_address = {(item["table"], item["keyDigest"]): item for item in memberships.selected_rows}
    proofs_by_address = {(item["table"], item["keyDigest"]): item for item in memberships.before_proofs}
    joined_reads, shared = [], {}
    for query, proof in zip(queries, frontiers):
        addresses = tuple((query.table, item.primary_key_digest)
                          for item in proof.frontier if type(item) is IndexLeaf)
        if any(address not in selected_by_address or address not in proofs_by_address for address in addresses):
            raise CompleteQueryBatchError("complete query leaf has no matching global primary selection")
        head = head_by_id[query.index_id]
        anchor = join.IndexPrimaryAnchor(head.index_id, head.index_revision,
                                         head.index_root, primary_by_table[query.table])
        hashes, input_bytes, _ = ledger.remaining()
        maximum = query.maximum_rows
        opened = 1 + KEY_NIBBLES * maximum + 2 * KEY_NIBBLES
        limits = join.IndexJoinLimits(
            primary=_primary_limits(spec, maximum, ledger),
            index=IndexRangeLimits(
                max_entries=MAX_OUTSIDE_PREFIXES + maximum, max_leaves=maximum,
                max_opened_nodes=opened, max_hashes=min(16 * opened + maximum, hashes),
                max_input_bytes=min(4 * 1024 * 1024, input_bytes),
            ),
            max_total_hashes=min(join.MAX_TOTAL_HASHES, hashes),
            max_total_input_bytes=min(join.MAX_TOTAL_INPUT_BYTES, input_bytes),
        )
        observed = join.join_index_range(
            anchor=anchor, selector=query.selector(), frontier=proof.frontier,
            selected_rows=tuple(selected_by_address[address] for address in addresses),
            before_proofs=tuple(proofs_by_address[address] for address in addresses), limits=limits,
        )
        ledger.charge(hashes=observed.metrics.total_hashes,
                      input_bytes=observed.metrics.total_input_bytes,
                      json_nodes=observed.metrics.primary.json_nodes)
        group = shared.setdefault(query.shared_group, set())
        group.update((query.table, leaf.primary_key_digest) for leaf in observed.leaves)
        if len(group) > query.shared_maximum_rows:
            raise CompleteQueryBatchError("complete query shared distinct-primary union exceeds its source bound")
        joined_reads.append((query.query_id, observed))

    query_metrics = tuple((query_id, observed.metrics) for query_id, observed in joined_reads)
    return CompleteQueryBatchInputs(
        operation=owned["operation"], arguments=owned["arguments"], cutoff_us=owned["cutoffUs"],
        business_before_roots=business, authorization_before_roots=authorization,
        selected_rows=memberships.selected_rows, before_proofs=memberships.before_proofs,
        queries=queries, read_heads=tuple(heads), query_frontiers=frontiers,
        joined_reads=tuple(joined_reads), primary=memberships.result,
        projection_manifest_digest=manifest_digest,
        metrics=CompleteQueryBatchMetrics(
            ownership_bytes, ownership_nodes, envelope_bytes, envelope_nodes,
            CONTEXT_HASH_ALLOWANCE, global_metrics, query_metrics,
            ledger.hashes, ledger.input_bytes, ledger.json_nodes,
        ),
    )


def verify_complete_query_batch(
    *, operation: str, arguments: dict[str, Any], cutoff_us: int,
    queries: tuple[complete.CompleteIndexQuery, ...],
    business_before_roots: Any, authorization_before_roots: Any,
    selected_rows: tuple[dict[str, Any], ...], before_proofs: tuple[dict[str, Any], ...],
    read_heads: tuple[CompleteQueryHead, ...], query_frontiers: tuple[CompleteQueryFrontier, ...],
) -> CompleteQueryBatchInputs:
    """Reverify raw evidence under source limits, returning actual owned inputs.

    Root vectors are closed primary wire dictionaries in lists or tuples. All
    other inventories require the exact declared tuple/DTO types. The five
    query/frontier pairs retain supplied program order, while four heads are
    the sorted unique source union. One head is shared by both session roles.

    The optional exact framework-counter address earns only one extra selected
    slot; its initialized/present state is not validated here. Other point rows
    and absences may occur in the global union but gain no predicate-completeness
    claim. JSON-node totals measure ownership/envelope walks and each genuine
    primary engine traversal, not every bounded fixed-context serializer.
    """
    ledger = _Ledger()
    try:
        owned = _capture(
            ledger=ledger, operation=operation, arguments=arguments, cutoff_us=cutoff_us,
            queries=queries, business_before_roots=business_before_roots,
            authorization_before_roots=authorization_before_roots, selected_rows=selected_rows,
            before_proofs=before_proofs, read_heads=read_heads, query_frontiers=query_frontiers,
        )
        return _verify(owned, ledger, ledger.input_bytes, ledger.json_nodes)
    except (AttributeError, TypeError, ValueError, OverflowError, RecursionError,
            TransitionKernelError) as exc:
        if isinstance(exc, CompleteQueryBatchError):
            raise
        raise CompleteQueryBatchError("complete query batch raw evidence verification failed") from exc
