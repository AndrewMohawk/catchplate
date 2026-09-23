"""Closed write-effects-only counted transitions from the actual combined engine.

Before descriptors remain supplied evidence, not independent currentness or
authenticated population. This component neither carries complete-query/read
heads nor changes Snapshot/v3, the planner, SQL executor or writer admission.
Structural validation and a document digest do not verify proof inputs.
Derivation/recomputation always invokes the genuine combined engine once; no
public entrypoint accepts a caller-created successful result instead of inputs.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any

from serverware import authority_contract
from serverware import authority_index_contract as counted
from serverware import authority_index_mutation as sparse
from serverware import authority_index_projection as projection
from serverware import authority_indexed_mutation as indexed
from serverware import authority_radix_mutation as primary
from serverware import authority_root_transition as legacy
from serverware.authority_primary_contract import primary_table_contracts
from serverware.authority_transition_core import canonical_bytes, framed_digest


TRANSITION_SCHEMA = "serverware.policyAuthorityCountedRootTransition/v1"
TRANSITION_PROFILE = "serverware.policyAuthorityCountedRootTransitionProfile/v1"
TRANSITION_SCOPE = "write-effects-only"
MAX_DOCUMENT_BYTES = 256 * 1024
MAX_TOTAL_HASHES = indexed.MAX_TOTAL_HASHES
MAX_TOTAL_INPUT_BYTES = indexed.MAX_TOTAL_INPUT_BYTES
# One source context, reused for validation, derivation and assembly:
# cold primary descriptor ladder66 + eleven(profile1 + empty1) + manifest1
# + final document digest1. No cache discount and no repeated legacy derivation.
WRAPPER_HASH_ALLOWANCE = 66 + 2 * 11 + 1 + 1
TRANSITION_FIELDS = frozenset({
    "schema", "profile", "scope", "operation", "countedProfile", "projectionManifestDigest",
    "primaryTransition", "indexBeforeHeads", "indexAfterHeads", "metrics",
})
HEAD_FIELDS = frozenset({"indexId", "table", "projectionDigest", "indexRevision", "rootDigest", "leafCount"})
METRIC_FIELDS = frozenset({"indexes", "contextHashes", "projectionHashAllowance", "newRowHashes", "hashWork", "inputBytes"})
INDEX_METRIC_FIELDS = frozenset({
    "indexId", "changes", "frontierEntries", "openedNodes", "childSlots", "beforeHashes", "afterHashes", "inputBytes",
})
_WIRE_NODES = 20_000
_WIRE_DEPTH = 8


class CountedRootTransitionError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class CountedTransitionPackaging:
    wrapper_hash_allowance: int
    document_bytes: int
    total_hash_work: int
    total_input_bytes: int


@dataclass(frozen=True, slots=True)
class DerivedCountedRootTransition:
    """Immutable observation bytes plus the actual engine's primary result.

    Freely constructible data, never a verification capability. No verification
    API accepts this object. Projection returns a fresh graph on every call.
    """
    primary: primary.PrimaryRadixBatchResult
    canonical_bytes: bytes
    digest: str
    packaging: CountedTransitionPackaging

    def json_projection(self) -> dict[str, Any]:
        return json.loads(self.canonical_bytes)


def _object(value, fields, label):
    if (type(value) is not dict or len(value) != len(fields)
            or any(type(key) is not str or len(key) > 64 for key in value)
            or set(value) != fields):
        raise CountedRootTransitionError(f"counted transition {label} is not closed")


def _integer(value, maximum=counted.I64_MAX, *, minimum=0):
    if type(value) is not int or not minimum <= value <= maximum:
        raise CountedRootTransitionError("counted transition integer is not an exact bounded value")
    return value


def _scalar_text(value):
    if type(value) is not str or len(value) > 128 or not value.isascii():
        raise CountedRootTransitionError("counted transition text is not bounded ASCII")
    return value


def _raw_roots(value):
    """Copy scalar descriptors without hashing or constructing PrimaryRoot."""
    if type(value) not in (list, tuple) or len(value) > authority_contract.MAX_QUERY_PROOFS:
        raise CountedRootTransitionError("counted transition primary roots are not bounded arrays")
    result = []
    for raw in value:
        _object(raw, legacy.ROOT_FIELDS, "primary root")
        result.append({"table": _scalar_text(raw["table"]),
            "rootRevision": _integer(raw["rootRevision"]),
            "rootDigest": _scalar_text(raw["rootDigest"]), "leafCount": _integer(raw["leafCount"])})
    return result


def _wire_snapshot(value):
    """Detach the complete small closed-document candidate before any hash."""
    nodes = emitted = 0

    def charge(amount):
        nonlocal emitted
        if amount > MAX_DOCUMENT_BYTES - emitted:
            raise CountedRootTransitionError("counted transition document exceeds its canonical byte bound")
        emitted += amount

    def copy(item, depth):
        nonlocal nodes
        nodes += 1
        if nodes > _WIRE_NODES or depth > _WIRE_DEPTH:
            raise CountedRootTransitionError("counted transition document exceeds structural bounds")
        if type(item) is str:
            value = _scalar_text(item)
            charge(len(canonical_bytes(value)))
            return value
        if type(item) is int:
            value = _integer(item)
            charge(len(str(value)))
            return value
        if type(item) is list:
            if len(item) > authority_contract.MAX_QUERY_PROOFS:
                raise CountedRootTransitionError("counted transition document array exceeds its bound")
            charge(2 + max(0, len(item) - 1))
            return [copy(child, depth + 1) for child in item]
        if type(item) is dict:
            if (len(item) > 16 or any(type(key) is not str or len(key) > 64 for key in item)):
                raise CountedRootTransitionError("counted transition document object exceeds its bound")
            charge(2 + max(0, len(item) - 1) + len(item))
            return {copy(key, depth + 1): copy(child, depth + 1) for key, child in item.items()}
        raise CountedRootTransitionError("counted transition document contains an unexpected exact type")

    result = copy(value, 0)
    if len(canonical_bytes(result)) > MAX_DOCUMENT_BYTES:
        raise CountedRootTransitionError("counted transition document exceeds its canonical byte bound")
    return result


@dataclass(frozen=True, slots=True)
class _Context:
    operation: str
    spec: dict
    contracts: tuple
    profiles: dict
    empties: dict
    manifest: str


def _context(operation):
    _scalar_text(operation)
    try:
        spec = authority_contract.operation_spec(operation)
        contracts = primary_table_contracts(operation)
    except ValueError as exc:
        raise CountedRootTransitionError("counted transition operation is not source admitted") from exc
    if len(projection.INDEX_IDS) != 11:
        raise CountedRootTransitionError("counted transition source profile/hash inventory changed")
    profiles = {index_id: projection.profile_for(index_id) for index_id in projection.INDEX_IDS}
    empties = {index_id: counted.empty_node(profile, "").digest for index_id, profile in profiles.items()}
    return _Context(operation, spec, contracts, profiles, empties, projection.projection_manifest_digest())


def _root_classes(context, business, authorization):
    expected_business = tuple(item.table for item in context.contracts if item.root_class == "business")
    expected_authorization = tuple(item.table for item in context.contracts if item.root_class == "authorization")
    if (tuple(root.table for root in business) != expected_business
            or tuple(root.table for root in authorization) != expected_authorization):
        raise CountedRootTransitionError("counted transition primary inventory differs from the source operation")


def _heads(value, context):
    if type(value) is not list or len(value) > 11:
        raise CountedRootTransitionError("counted transition index heads are not a bounded array")
    result, previous = [], ""
    writable = {item.table for item in context.contracts if item.write_access}
    for raw in value:
        _object(raw, HEAD_FIELDS, "index head")
        identity = raw["indexId"]
        if type(identity) is not str or identity not in context.profiles or identity <= previous:
            raise CountedRootTransitionError("counted transition index heads are not source sorted and unique")
        profile = context.profiles[identity]
        if (raw["table"] != profile.table or profile.table not in writable
                or raw["projectionDigest"] != profile.projection_digest):
            raise CountedRootTransitionError("counted transition index head source profile changed")
        revision, count = _integer(raw["indexRevision"]), _integer(raw["leafCount"])
        try:
            root = counted.CountedNode(raw["rootDigest"], count)
        except counted.IndexRangeError as exc:
            raise CountedRootTransitionError("counted transition index root is invalid") from exc
        if ((count == 0) != (root.digest == context.empties[identity]) or revision == 0 and count != 0):
            raise CountedRootTransitionError("counted transition index empty convention changed")
        result.append(dict(raw))
        previous = identity
    expected = tuple(sorted(index_id for table in {item["table"] for item in result}
                            for index_id in projection.index_ids_for_table(table)))
    if tuple(item["indexId"] for item in result) != expected:
        raise CountedRootTransitionError("counted transition omitted a written table's fixed profile")
    return result


def _index_limits(context):
    # The source mutation ceiling can exceed its selected-row ceiling. The
    # actual primary engine requires distinct selected mutation addresses, so
    # at most min(those ceilings) can reach a counted profile.
    changes = 2 * min(context.spec["maximumMutations"], context.spec["maximumQueryRows"])
    opened = 1 + counted.KEY_NIBBLES * changes
    return sparse.IndexMutationLimits(max_changes=changes, max_frontier_entries=16 * opened,
        max_opened_nodes=opened, max_hashes=2 * (16 * opened + changes),
        max_input_bytes=MAX_TOTAL_INPUT_BYTES - MAX_DOCUMENT_BYTES)


def _metric_projection(result):
    return {"indexes": [{"indexId": identity, "changes": item.changes,
        "frontierEntries": item.frontier_entries, "openedNodes": item.opened_nodes,
        "childSlots": item.child_slots, "beforeHashes": item.before_hashes,
        "afterHashes": item.after_hashes, "inputBytes": item.input_bytes}
        for identity, item in result.metrics.indexes],
        "contextHashes": result.metrics.context_hashes,
        "projectionHashAllowance": result.metrics.projection_hash_allowance,
        "newRowHashes": result.metrics.new_row_hashes, "hashWork": result.metrics.hashes,
        "inputBytes": result.metrics.input_bytes}


def _validate_metrics(raw, context, primary_metrics, before_heads):
    _object(raw, METRIC_FIELDS, "metrics")
    entries = raw["indexes"]
    if type(entries) is not list or len(entries) != len(before_heads):
        raise CountedRootTransitionError("counted transition metric inventory differs")
    limits = _index_limits(context)
    index_hashes = index_bytes = 0
    # Exact combined scalar framing, apart from the low evaluators' own inputs.
    context_bytes = sum(8 + len(value) for value in (
        "serverware.policyAuthorityIndexedMutationInput/v1", str(len(entries))))
    copied = []
    for entry, head in zip(entries, before_heads):
        _object(entry, INDEX_METRIC_FIELDS, "index metrics")
        if entry["indexId"] != head["indexId"]:
            raise CountedRootTransitionError("counted transition metric identity changed")
        changes = _integer(entry["changes"], limits.max_changes)
        frontier = _integer(entry["frontierEntries"], limits.max_frontier_entries)
        opened = _integer(entry["openedNodes"], min(limits.max_opened_nodes, 1 + 160 * changes), minimum=1)
        if (_integer(entry["childSlots"], 32 * limits.max_opened_nodes) != 32 * opened
                or frontier > 16 * opened):
            raise CountedRootTransitionError("counted transition index slot accounting changed")
        index_hashes += _integer(entry["beforeHashes"], 16 * opened + changes, minimum=opened)
        index_hashes += _integer(entry["afterHashes"], 16 * opened + changes, minimum=opened)
        index_bytes += _integer(entry["inputBytes"], limits.max_input_bytes, minimum=1)
        context_bytes += sum(8 + len(value) for value in (head["indexId"], str(head["indexRevision"]),
            head["rootDigest"], str(head["leafCount"]), str(frontier)))
        copied.append(dict(entry))
    contexts = _integer(raw["contextHashes"], 11)
    projection_work = _integer(raw["projectionHashAllowance"], 12 * primary_metrics["mutations"])
    new_rows = _integer(raw["newRowHashes"], primary_metrics["mutations"])
    hashes = _integer(raw["hashWork"], MAX_TOTAL_HASHES - WRAPPER_HASH_ALLOWANCE)
    input_bytes = _integer(raw["inputBytes"], MAX_TOTAL_INPUT_BYTES - MAX_DOCUMENT_BYTES, minimum=1)
    if (contexts != len(before_heads) or projection_work % projection.ROW_HASH_WORK
            or hashes != primary_metrics["hashWork"] + index_hashes + contexts + projection_work + new_rows
            or input_bytes != primary_metrics["inputBytes"] + index_bytes + context_bytes):
        raise CountedRootTransitionError("counted transition combined metric accounting changed")
    return {"indexes": copied, "contextHashes": contexts, "projectionHashAllowance": projection_work,
            "newRowHashes": new_rows, "hashWork": hashes, "inputBytes": input_bytes}


def _validate_owned(value, context):
    _object(value, TRANSITION_FIELDS, "document")
    if (value["schema"] != TRANSITION_SCHEMA or value["profile"] != TRANSITION_PROFILE
            or value["scope"] != TRANSITION_SCOPE or value["operation"] != context.operation
            or value["countedProfile"] != counted.PROFILE or value["projectionManifestDigest"] != context.manifest):
        raise CountedRootTransitionError("counted transition source document profile changed")
    nested = value["primaryTransition"]
    _object(nested, legacy.TRANSITION_FIELDS, "primary transition")
    _object(nested["metrics"], frozenset(legacy.metric_bounds()), "primary metrics")
    for field in ("businessBeforeRoots", "authorizationBeforeRoots", "businessAfterRoots", "authorizationAfterRoots"):
        _raw_roots(nested[field])
    try:
        # Structural legacy validation only; no engine/derive call. Every
        # PrimaryRoot constructor consults the same cached depth0 empty ladder,
        # covered by this call's separately reserved cold66 wrapper allowance.
        nested = legacy.validate_primary_root_transition(nested)
    except primary.PrimaryRadixMutationError as exc:
        raise CountedRootTransitionError("counted transition primary document is invalid") from exc
    business = legacy._roots(nested["businessBeforeRoots"])
    authorization = legacy._roots(nested["authorizationBeforeRoots"])
    _root_classes(context, business, authorization)
    if (nested["metrics"]["selectedRows"] > context.spec["maximumQueryRows"]
            or nested["metrics"]["mutations"] > context.spec["maximumMutations"]
            or nested["metrics"]["hashWork"] > 66 + 136 * context.spec["maximumQueryRows"]
            or nested["metrics"]["inputBytes"] > MAX_TOTAL_INPUT_BYTES - MAX_DOCUMENT_BYTES):
        raise CountedRootTransitionError("counted transition primary metrics exceed the operation")
    before = _heads(value["indexBeforeHeads"], context)
    after = _heads(value["indexAfterHeads"], context)
    if tuple(item["indexId"] for item in before) != tuple(item["indexId"] for item in after):
        raise CountedRootTransitionError("counted transition changed index inventory")
    before_counts = {item["table"]: item["leafCount"] for item in nested["businessBeforeRoots"]}
    after_counts = {item["table"]: item["leafCount"] for item in nested["businessAfterRoots"]}
    for old, new in zip(before, after):
        delta = new["indexRevision"] - old["indexRevision"]
        if (not 0 <= delta <= nested["metrics"]["mutations"]
                or abs(new["leafCount"] - old["leafCount"]) > delta
                or (delta == 0 and (old["rootDigest"], old["leafCount"]) != (new["rootDigest"], new["leafCount"]))
                or old["leafCount"] > before_counts[old["table"]]
                or new["leafCount"] > after_counts[new["table"]]):
            raise CountedRootTransitionError("counted transition index delta or population descriptor changed")
    metrics = _validate_metrics(value["metrics"], context, nested["metrics"], before)
    return {"schema": TRANSITION_SCHEMA, "profile": TRANSITION_PROFILE, "scope": TRANSITION_SCOPE,
        "operation": context.operation, "countedProfile": counted.PROFILE,
        "projectionManifestDigest": context.manifest, "primaryTransition": nested,
        "indexBeforeHeads": before, "indexAfterHeads": after, "metrics": metrics}


def validate_counted_root_transition(value: Any) -> dict[str, Any]:
    """Validate/copy the closed wire shape, NOT proofs or operation authority."""
    owned = _wire_snapshot(value)
    _object(owned, TRANSITION_FIELDS, "document")
    return _validate_owned(owned, _context(owned["operation"]))


def counted_root_transition_digest(value: Any) -> str:
    """Digest a structurally valid document, NOT a successful proof result."""
    owned = _wire_snapshot(value)
    _object(owned, TRANSITION_FIELDS, "document")
    normalized = _validate_owned(owned, _context(owned["operation"]))
    return framed_digest(TRANSITION_SCHEMA, canonical_bytes(normalized))


def _derive(context, raw_business, raw_authorization, selected_rows, before_proofs, mutations, index_inputs):
    spec = context.spec
    for values in (selected_rows, before_proofs, mutations):
        if type(values) not in (list, tuple):
            raise CountedRootTransitionError("counted transition primary input is not an array")
    if (len(raw_business) + len(raw_authorization) > authority_contract.MAX_QUERY_PROOFS
            or len(selected_rows) > spec["maximumQueryRows"] or len(before_proofs) != len(selected_rows)
            or len(mutations) > spec["maximumMutations"]):
        raise CountedRootTransitionError("counted transition input inventory exceeds the operation")
    business, authorization = legacy._roots(raw_business), legacy._roots(raw_authorization)
    _root_classes(context, business, authorization)
    selected_limit = spec["maximumQueryRows"]
    primary_limits = primary.PrimaryRadixLimits(max_selected_rows=selected_limit,
        max_mutations=spec["maximumMutations"], max_proof_vectors=64 * selected_limit,
        max_proof_child_slots=1024 * selected_limit, max_hashes=66 + 136 * selected_limit,
        max_input_bytes=MAX_TOTAL_INPUT_BYTES - MAX_DOCUMENT_BYTES, max_json_depth=128, max_json_nodes=1_000_000)
    calculated = indexed.evaluate_indexed_primary_batch(table_contracts=context.contracts,
        business_before_roots=business, authorization_before_roots=authorization,
        selected_rows=tuple(selected_rows), before_proofs=tuple(before_proofs), mutations=tuple(mutations),
        index_inputs=index_inputs, limits=indexed.IndexedMutationLimits(primary=primary_limits,
            index=_index_limits(context), max_total_hashes=MAX_TOTAL_HASHES-WRAPPER_HASH_ALLOWANCE,
            max_total_input_bytes=MAX_TOTAL_INPUT_BYTES-MAX_DOCUMENT_BYTES))

    def heads(values):
        return [{"indexId": item.index_id, "table": context.profiles[item.index_id].table,
            "projectionDigest": context.profiles[item.index_id].projection_digest,
            "indexRevision": item.index_revision, "rootDigest": item.index_root.digest,
            "leafCount": item.index_root.count} for item in values]

    document = _validate_owned({"schema": TRANSITION_SCHEMA, "profile": TRANSITION_PROFILE,
        "scope": TRANSITION_SCOPE, "operation": context.operation, "countedProfile": counted.PROFILE,
        "projectionManifestDigest": context.manifest,
        "primaryTransition": {"schema": legacy.TRANSITION_SCHEMA, "profile": legacy.TRANSITION_PROFILE,
            "businessBeforeRoots": [item.json_projection() for item in business],
            "authorizationBeforeRoots": [item.json_projection() for item in authorization],
            **calculated.primary.json_projection()},
        "indexBeforeHeads": heads(calculated.before_heads), "indexAfterHeads": heads(calculated.after_heads),
        "metrics": _metric_projection(calculated)}, context)
    encoded = canonical_bytes(document)
    if len(encoded) > MAX_DOCUMENT_BYTES:
        raise CountedRootTransitionError("counted transition document exceeds its canonical byte reserve")
    packaging = CountedTransitionPackaging(WRAPPER_HASH_ALLOWANCE, len(encoded),
        calculated.metrics.hashes + WRAPPER_HASH_ALLOWANCE, calculated.metrics.input_bytes + len(encoded))
    if packaging.total_hash_work > MAX_TOTAL_HASHES or packaging.total_input_bytes > MAX_TOTAL_INPUT_BYTES:
        raise CountedRootTransitionError("counted transition packaging exceeds its reserved aggregate budget")
    return DerivedCountedRootTransition(calculated.primary, encoded,
        framed_digest(TRANSITION_SCHEMA, encoded), packaging)


def derive_counted_root_transition(*, operation: str, business_before_roots: Any, authorization_before_roots: Any,
                                  selected_rows: Any, before_proofs: Any, mutations: Any,
                                  index_inputs: tuple[indexed.IndexedMutationInput, ...]) -> DerivedCountedRootTransition:
    """Recompute one write-only transition from real original proof inputs."""
    # Both graphs are fully detached before profile/empty/manifest hashes or
    # any PrimaryRoot constructor can invoke a hashing boundary.
    business = _raw_roots(business_before_roots)
    authorization = _raw_roots(authorization_before_roots)
    context = _context(operation)
    try:
        return _derive(context, business, authorization, selected_rows, before_proofs, mutations, index_inputs)
    except (primary.PrimaryRadixMutationError, counted.IndexRangeError) as exc:
        raise CountedRootTransitionError("counted transition proof recomputation failed") from exc


def verify_counted_root_transition(*, operation: str, value: Any, selected_rows: Any, before_proofs: Any,
                                  mutations: Any, index_inputs: tuple[indexed.IndexedMutationInput, ...]) -> DerivedCountedRootTransition:
    """Snapshot the claim, genuinely recompute once, compare its entire wire."""
    owned = _wire_snapshot(value)
    _object(owned, TRANSITION_FIELDS, "document")
    context = _context(operation)
    normalized = _validate_owned(owned, context)
    expected_bytes = canonical_bytes(normalized)
    try:
        result = _derive(context, _raw_roots(normalized["primaryTransition"]["businessBeforeRoots"]),
            _raw_roots(normalized["primaryTransition"]["authorizationBeforeRoots"]),
            selected_rows, before_proofs, mutations, index_inputs)
    except (primary.PrimaryRadixMutationError, counted.IndexRangeError) as exc:
        raise CountedRootTransitionError("counted transition proof recomputation failed") from exc
    if result.canonical_bytes != expected_bytes:
        raise CountedRootTransitionError("counted transition differs from the recomputed complete write delta")
    return result
