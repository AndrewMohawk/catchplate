"""Bounded, pure primary-radix delta calculation relative to supplied heads.

This is neither a root-currentness check nor a predicate-completeness proof.
Callers must bind the complete before descriptors and measured table contracts
to their authority context. In particular, the tree hash does not authenticate
the descriptor's revision or leaf count. No database, clock, I/O or signing is
used here, and no verified-authority object is returned.

SQL tree hashes retain their length-prefixed domain/UTF-8 representation;
BusinessKey and proofDigest retain their distinct existing wire framing.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from serverware import authority_contract
from serverware import authority_radix_proof as radix
from serverware.authority_transition_core import canonical_bytes, framed_digest


_IDENTIFIER = re.compile(r"[a-z][a-z0-9_]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_I64_MAX = 2**63 - 1
_DEPTH = authority_contract.TREE_DEPTH
_RADIX = authority_contract.TREE_RADIX
_MAX_VECTORS = authority_contract.MAX_PLAN_QUERY_ROWS * _DEPTH
_MAX_CHILD_SLOTS = _MAX_VECTORS * _RADIX
# Conservative cold-cache allowance: empty_digest(0) hashes 65 nodes, and
# empty_digest(64) hashes one leaf. Cache hits do not reduce this charged work.
_EMPTY_HASH_WORK = _DEPTH + 2
_MAX_HASH_WORK = _EMPTY_HASH_WORK + authority_contract.MAX_PLAN_QUERY_ROWS * (2 * _DEPTH + 8)
_SELECTED_FIELDS = frozenset({"table", "key", "keyDigest", "present", "row", "contractSelector"})
_MUTATION_FIELDS = frozenset({"templateId", "operation", "table", "key", "keyDigest", "expectedRow", "row"})


class PrimaryRadixMutationError(ValueError):
    pass


def _identifier(value: Any, label: str) -> None:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise PrimaryRadixMutationError(f"{label} is not an exact identifier")


def _digest(value: Any, label: str) -> None:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise PrimaryRadixMutationError(f"{label} is not an exact digest")


def _counter(value: Any, label: str) -> None:
    if type(value) is not int or not 0 <= value <= _I64_MAX:
        raise PrimaryRadixMutationError(f"{label} is not an exact nonnegative int64")


@dataclass(frozen=True, slots=True)
class PrimaryTableContract:
    table: str
    key_columns: tuple[str, ...]
    write_access: bool
    root_class: str

    def __post_init__(self) -> None:
        _identifier(self.table, "table")
        if (type(self.key_columns) is not tuple or not self.key_columns
                or len(self.key_columns) > authority_contract.MAX_SELECTORS_PER_OPERATION
                or any(type(column) is not str for column in self.key_columns)
                or len(set(self.key_columns)) != len(self.key_columns)):
            raise PrimaryRadixMutationError("table key columns are not a nonempty unique tuple")
        for column in self.key_columns:
            _identifier(column, "key column")
        if (type(self.write_access) is not bool or type(self.root_class) is not str
                or self.root_class not in ("business", "authorization")):
            raise PrimaryRadixMutationError("table root class or write access is invalid")
        if self.root_class == "authorization" and self.write_access:
            raise PrimaryRadixMutationError("authorization root cannot grant mutation access")

    def json_projection(self) -> dict[str, Any]:
        return {"table": self.table, "keyColumns": list(self.key_columns),
                "writeAccess": self.write_access, "rootClass": self.root_class}


@dataclass(frozen=True, slots=True)
class PrimaryRoot:
    table: str
    root_revision: int
    root_digest: str
    leaf_count: int

    def __post_init__(self) -> None:
        _identifier(self.table, "root table")
        _counter(self.root_revision, "root revision")
        _counter(self.leaf_count, "root leaf count")
        _digest(self.root_digest, "root digest")
        empty = radix.empty_digest(0)
        if (self.leaf_count == 0) != (self.root_digest == empty):
            raise PrimaryRadixMutationError("root emptiness and leaf count disagree")
        if self.root_revision == 0 and self.leaf_count != 0:
            raise PrimaryRadixMutationError("zero root revision is not an empty genesis")

    def json_projection(self) -> dict[str, Any]:
        return {"table": self.table, "rootRevision": self.root_revision,
                "rootDigest": self.root_digest, "leafCount": self.leaf_count}


@dataclass(frozen=True, slots=True)
class PrimaryRadixLimits:
    """Explicit separate budget profile; never transition.work_units.

    Vectors count all 64 levels per supplied proof, including overlap. Child
    slots count all 16 entries, NOT the older 15-sibling MAX_PROOF_NODES model.
    hash_work conservatively charges cold empty hashes, proof authentication,
    path addressing, changed leaves and every recomputed union ancestor.
    """
    max_selected_rows: int
    max_mutations: int
    max_proof_vectors: int
    max_proof_child_slots: int
    max_hashes: int
    max_input_bytes: int
    max_json_depth: int
    max_json_nodes: int

    def __post_init__(self) -> None:
        bounds = (
            (self.max_selected_rows, authority_contract.MAX_PLAN_QUERY_ROWS),
            (self.max_mutations, authority_contract.MAX_PLAN_MUTATIONS),
            (self.max_proof_vectors, _MAX_VECTORS),
            (self.max_proof_child_slots, _MAX_CHILD_SLOTS),
            (self.max_hashes, _MAX_HASH_WORK),
            (self.max_input_bytes, authority_contract.MAX_RESULT_BYTES),
            (self.max_json_depth, 128), (self.max_json_nodes, 1_000_000),
        )
        if any(type(value) is not int or not 1 <= value <= maximum for value, maximum in bounds):
            raise PrimaryRadixMutationError("primary radix budget profile is invalid")


@dataclass(frozen=True, slots=True)
class PrimaryRadixMetrics:
    selected_rows: int
    mutations: int
    proof_vectors: int
    proof_child_slots: int
    recomputed_ancestors: int
    hash_work: int
    input_bytes: int
    json_nodes: int

    def __post_init__(self) -> None:
        for value in (self.selected_rows, self.mutations, self.proof_vectors, self.proof_child_slots,
                      self.recomputed_ancestors, self.hash_work, self.input_bytes, self.json_nodes):
            _counter(value, "primary radix metric")

    def json_projection(self) -> dict[str, int]:
        return {"selectedRows": self.selected_rows, "mutations": self.mutations,
                "proofVectors": self.proof_vectors, "proofChildSlots": self.proof_child_slots,
                "recomputedAncestors": self.recomputed_ancestors, "hashWork": self.hash_work,
                "inputBytes": self.input_bytes, "jsonNodes": self.json_nodes}


@dataclass(frozen=True, slots=True)
class PrimaryRadixBatchResult:
    business_after_roots: tuple[PrimaryRoot, ...]
    authorization_after_roots: tuple[PrimaryRoot, ...]
    metrics: PrimaryRadixMetrics

    def __post_init__(self) -> None:
        if (type(self.business_after_roots) is not tuple or type(self.authorization_after_roots) is not tuple
                or any(type(root) is not PrimaryRoot for root in self.business_after_roots + self.authorization_after_roots)
                or type(self.metrics) is not PrimaryRadixMetrics):
            raise PrimaryRadixMutationError("primary radix result must retain only frozen values")

    def json_projection(self) -> dict[str, Any]:
        return {"businessAfterRoots": [root.json_projection() for root in self.business_after_roots],
                "authorizationAfterRoots": [root.json_projection() for root in self.authorization_after_roots],
                "metrics": self.metrics.json_projection()}


class _Budget:
    def __init__(self, limits: PrimaryRadixLimits) -> None:
        self.limits = limits
        self.nodes = 0
        self.rough_bytes = 0
        self.hash_work = 0

    def charge_hashes(self, count: int) -> None:
        self.hash_work += count
        if self.hash_work > self.limits.max_hashes:
            raise PrimaryRadixMutationError("primary radix hash budget exceeded")

    def snapshot(self, value: Any, depth: int = 0, ancestors: frozenset[int] = frozenset()) -> Any:
        self.nodes += 1
        if self.nodes > self.limits.max_json_nodes or depth > self.limits.max_json_depth:
            raise PrimaryRadixMutationError("primary radix JSON structure budget exceeded")
        kind = type(value)
        if kind in (dict, list):
            if len(value) > self.limits.max_json_nodes - self.nodes:
                raise PrimaryRadixMutationError("primary radix JSON structure budget exceeded")
            if id(value) in ancestors:
                raise PrimaryRadixMutationError("primary radix JSON is cyclic")
            branch = ancestors | {id(value)}
            if kind is dict:
                copied = {}
                for key, child in value.items():
                    if type(key) is not str:
                        raise PrimaryRadixMutationError("primary radix JSON keys must be exact strings")
                    self.snapshot(key, depth + 1, branch)
                    copied[key] = self.snapshot(child, depth + 1, branch)
                return copied
            return [self.snapshot(child, depth + 1, branch) for child in value]
        if value is None or kind in (str, bool, int):
            remaining = self.limits.max_input_bytes - self.rough_bytes
            if ((kind is str and len(value) > remaining)
                    or (kind is int and value.bit_length() > remaining * 4)):
                raise PrimaryRadixMutationError("primary radix input byte budget exceeded")
            # Validate UTF-8 as well as wire JSON; lone surrogates have a wire
            # escape but cannot be represented by the SQL UTF-8 tree contract.
            encoded = radix.tree_json_bytes(value)
            self.rough_bytes += len(encoded)
            if self.rough_bytes > self.limits.max_input_bytes:
                raise PrimaryRadixMutationError("primary radix input byte budget exceeded")
            return value
        raise PrimaryRadixMutationError("primary radix JSON requires exact lossless scalar/container types")


def _key_bytes(value: Any, contract: PrimaryTableContract) -> bytes:
    if type(value) is not dict or set(value) != set(contract.key_columns):
        raise PrimaryRadixMutationError("primary radix key columns are not exact")
    if any(value[column] is None or type(value[column]) in (dict, list) for column in contract.key_columns):
        raise PrimaryRadixMutationError("primary radix primary key must contain nonnull scalar fields")
    return radix.tree_json_bytes(value)


def _row_has_key(row: Any, key_bytes: bytes, contract: PrimaryTableContract) -> None:
    if type(row) is not dict or any(column not in row for column in contract.key_columns):
        raise PrimaryRadixMutationError("primary radix row omits its original primary key")
    projected = {column: row[column] for column in contract.key_columns}
    if _key_bytes(projected, contract) != key_bytes:
        raise PrimaryRadixMutationError("primary radix original key changed")


def evaluate_primary_radix_batch(
    *,
    table_contracts: tuple[PrimaryTableContract, ...],
    business_before_roots: tuple[PrimaryRoot, ...],
    authorization_before_roots: tuple[PrimaryRoot, ...],
    selected_rows: tuple[dict[str, Any], ...],
    before_proofs: tuple[dict[str, Any], ...],
    mutations: tuple[dict[str, Any], ...],
    limits: PrimaryRadixLimits,
) -> PrimaryRadixBatchResult:
    """Calculate an exact final primary-root vector, or reject the entire batch.

    Mutation input order need not be the SQL sort order: distinct original keys
    commute for final roots/counts. No intermediate SQL root-revision history is
    returned or claimed. Duplicate same-key actions are always rejected.
    """
    if type(limits) is not PrimaryRadixLimits:
        raise PrimaryRadixMutationError("primary radix limits must be an exact frozen profile")
    sequences = (table_contracts, business_before_roots, authorization_before_roots,
                 selected_rows, before_proofs, mutations)
    if any(type(value) is not tuple for value in sequences):
        raise PrimaryRadixMutationError("primary radix inventories must be tuples")
    if (not table_contracts or len(table_contracts) > authority_contract.MAX_QUERY_PROOFS
            or len(business_before_roots) + len(authorization_before_roots) != len(table_contracts)
            or len(selected_rows) > limits.max_selected_rows
            or len(before_proofs) != len(selected_rows) or len(mutations) > limits.max_mutations):
        raise PrimaryRadixMutationError("primary radix inventory count is not closed or exceeds budget")
    if any(type(item) is not PrimaryTableContract for item in table_contracts):
        raise PrimaryRadixMutationError("primary radix table contract type is invalid")
    contracts = {item.table: item for item in table_contracts}
    if len(contracts) != len(table_contracts):
        raise PrimaryRadixMutationError("primary radix table contract is duplicated")
    heads = {}
    for root_class, inventory in (("business", business_before_roots), ("authorization", authorization_before_roots)):
        for root in inventory:
            if (type(root) is not PrimaryRoot or root.table in heads
                    or root.table not in contracts or contracts[root.table].root_class != root_class):
                raise PrimaryRadixMutationError("primary radix root inventory identity or class changed")
            heads[root.table] = root
    if set(heads) != set(contracts):
        raise PrimaryRadixMutationError("primary radix root inventory is not complete")
    vectors = len(before_proofs) * _DEPTH
    child_slots = vectors * _RADIX
    if vectors > limits.max_proof_vectors or child_slots > limits.max_proof_child_slots:
        raise PrimaryRadixMutationError("primary radix proof vector budget exceeded")
    budget = _Budget(limits)
    budget.charge_hashes(_EMPTY_HASH_WORK)
    try:
        snapshot = budget.snapshot({
            "contracts": [item.json_projection() for item in table_contracts],
            "businessRoots": [root.json_projection() for root in business_before_roots],
            "authorizationRoots": [root.json_projection() for root in authorization_before_roots],
            "selected": list(selected_rows), "proofs": list(before_proofs), "mutations": list(mutations),
        })
        input_bytes = len(canonical_bytes(snapshot))
    except (radix.RadixProofError, ValueError, TypeError, RecursionError, RuntimeError) as exc:
        if isinstance(exc, PrimaryRadixMutationError):
            raise
        raise PrimaryRadixMutationError("primary radix input snapshot is not lossless closed JSON") from exc
    if input_bytes > limits.max_input_bytes:
        raise PrimaryRadixMutationError("primary radix input byte budget exceeded")
    selected_by_address = {}
    key_bytes_by_address = {}
    present_counts = {table: 0 for table in heads}
    for selected in snapshot["selected"]:
        if (type(selected) is not dict or set(selected) != _SELECTED_FIELDS
                or type(selected.get("table")) is not str or selected["table"] not in contracts
                or type(selected.get("present")) is not bool
                or (selected["present"] and type(selected.get("row")) is not dict)
                or (not selected["present"] and selected.get("row") is not None)
                or (selected["contractSelector"] is not None and type(selected["contractSelector"]) is not str)):
            raise PrimaryRadixMutationError("primary radix selected row is not closed")
        contract = contracts[selected["table"]]
        key_bytes = _key_bytes(selected["key"], contract)
        _digest(selected["keyDigest"], "selected business key")
        address = (selected["table"], selected["keyDigest"])
        if address in selected_by_address:
            raise PrimaryRadixMutationError("primary radix selected address is duplicated")
        if selected["present"]:
            _row_has_key(selected["row"], key_bytes, contract)
            present_counts[contract.table] += 1
        selected_by_address[address] = selected
        key_bytes_by_address[address] = key_bytes
    if any(present_counts[table] > root.leaf_count for table, root in heads.items()):
        raise PrimaryRadixMutationError("primary radix proved membership exceeds root leaf count")
    before_vectors: dict[tuple[str, int, str], tuple[str, ...]] = {}
    paths = {}
    proof_addresses = set()
    tree_addresses = set()
    for proof in snapshot["proofs"]:
        if type(proof) is not dict or type(proof.get("table")) is not str:
            raise PrimaryRadixMutationError("primary radix proof identity is not closed")
        _digest(proof.get("keyDigest"), "proof business key")
        address = (proof["table"], proof["keyDigest"])
        selected = selected_by_address.get(address)
        if selected is None or address in proof_addresses:
            raise PrimaryRadixMutationError("primary radix proof address is missing, extra, or duplicated")
        root = heads[proof["table"]]
        if (type(proof.get("rootRevision")) is not int or proof["rootRevision"] != root.root_revision
                or proof.get("rootDigest") != root.root_digest
                or radix.tree_json_bytes(proof.get("key")) != key_bytes_by_address[address]):
            raise PrimaryRadixMutationError("primary radix proof differs from exact before descriptor or key")
        # proof digest + verifier's business/tree key, row/leaf and 64 node
        # hashes + our retained path address. Empty hash work is charged above.
        budget.charge_hashes(_DEPTH + 4 + (2 if selected["present"] else 0))
        expected_proof_digest = framed_digest(
            "serverware.policyAuthorityRadixMultiproof/v3",
            canonical_bytes({key: value for key, value in proof.items() if key != "proofDigest"}),
        )
        if proof.get("proofDigest") != expected_proof_digest:
            raise PrimaryRadixMutationError("primary radix proof digest changed")
        try:
            radix.reconstruct_multiproof_root(proof, selected=selected)
        except (radix.RadixProofError, ValueError, TypeError) as exc:
            raise PrimaryRadixMutationError("primary radix before proof reconstruction failed") from exc
        path = radix.authenticated_key_digest(proof["table"], selected["key"])[7:]
        if (proof["table"], path) in tree_addresses:
            raise PrimaryRadixMutationError("primary radix tree key identity collision")
        tree_addresses.add((proof["table"], path))
        paths[address] = path
        proof_addresses.add(address)
        for level in proof["siblings"]:
            node = (proof["table"], level["depth"], level["pathPrefix"])
            children = tuple(level["childDigests"])
            if node in before_vectors and before_vectors[node] != children:
                raise PrimaryRadixMutationError("primary radix shared before prefix is inconsistent")
            before_vectors[node] = children
    if proof_addresses != set(selected_by_address):
        raise PrimaryRadixMutationError("primary radix proofs do not exactly cover selected rows")
    changes = {}
    revision_deltas = {table: 0 for table in heads}
    count_deltas = {table: 0 for table in heads}
    for mutation in snapshot["mutations"]:
        if (type(mutation) is not dict or set(mutation) != _MUTATION_FIELDS
                or type(mutation.get("table")) is not str
                or type(mutation.get("templateId")) is not str or not mutation["templateId"]
                or mutation.get("operation") not in ("INSERT", "UPDATE", "DELETE")):
            raise PrimaryRadixMutationError("primary radix mutation is not closed")
        _digest(mutation["keyDigest"], "mutation business key")
        address = (mutation["table"], mutation["keyDigest"])
        selected = selected_by_address.get(address)
        if selected is None or address in changes:
            raise PrimaryRadixMutationError("primary radix mutation address is unselected or duplicated")
        contract = contracts[mutation["table"]]
        if not contract.write_access or contract.root_class != "business":
            raise PrimaryRadixMutationError("primary radix mutation table is not writable business state")
        key_bytes = _key_bytes(mutation["key"], contract)
        if key_bytes != key_bytes_by_address[address]:
            raise PrimaryRadixMutationError("primary radix mutation original key differs from selection")
        operation = mutation["operation"]
        old, new = mutation["expectedRow"], mutation["row"]
        if operation == "INSERT":
            if selected["present"] or old is not None or type(new) is not dict:
                raise PrimaryRadixMutationError("primary radix INSERT lifecycle is not exact")
            count_deltas[contract.table] += 1
        else:
            if (not selected["present"] or type(old) is not dict
                    or radix.tree_json_bytes(old) != radix.tree_json_bytes(selected["row"])):
                raise PrimaryRadixMutationError("primary radix old full-row CAS differs from selected row")
            if operation == "DELETE":
                if new is not None:
                    raise PrimaryRadixMutationError("primary radix DELETE requires explicit null after image")
                count_deltas[contract.table] -= 1
            elif type(new) is not dict:
                raise PrimaryRadixMutationError("primary radix UPDATE requires an object after image")
        if new is not None:
            _row_has_key(new, key_bytes, contract)
        revision_deltas[contract.table] += 1
        changes[address] = mutation
    for table, root in heads.items():
        _counter(root.root_revision + revision_deltas[table], "after root revision")
        _counter(root.leaf_count + count_deltas[table], "after root leaf count")
    # All before proofs and mutations have been checked. Never rewrite a proof
    # while another proof still needs authentication against the before root.
    overlay: dict[tuple[str, int, str], str] = {}
    ancestors = set()
    for address, mutation in changes.items():
        table, _ = address
        path = paths[address]
        new = mutation["row"]
        if new is None:
            leaf = radix.empty_digest(_DEPTH)
        else:
            budget.charge_hashes(2)
            row_digest = radix._tree_digest(
                "serverware.policyAuthorityAuthenticatedRow/v1", table.encode("utf-8"), radix.tree_json_bytes(new),
            )
            leaf = radix._tree_digest(
                "serverware.policyAuthorityAuthenticatedLeaf/v1", table.encode("utf-8"),
                ("sha256:" + path).encode("ascii"), key_bytes_by_address[address], row_digest.encode("ascii"),
            )
        overlay[(table, _DEPTH, path)] = leaf
        ancestors.update((table, depth, path[:depth]) for depth in range(_DEPTH))
    for table, depth, prefix in sorted(ancestors, key=lambda item: (-item[1], item[0], item[2])):
        node = (table, depth, prefix)
        original = before_vectors[node]
        children = [overlay.get((table, depth + 1, prefix + format(index, "x")), original[index])
                    for index in range(_RADIX)]
        budget.charge_hashes(1)
        overlay[node] = radix._tree_digest(
            "serverware.policyAuthorityAuthenticatedNode/v1", str(depth).encode("ascii"), radix.tree_json_bytes(children),
        )
    after = {
        table: PrimaryRoot(table, root.root_revision + revision_deltas[table],
                           overlay.get((table, 0, ""), root.root_digest), root.leaf_count + count_deltas[table])
        for table, root in heads.items()
    }
    return PrimaryRadixBatchResult(
        business_after_roots=tuple(after[table] for table in sorted(after) if contracts[table].root_class == "business"),
        authorization_after_roots=tuple(after[table] for table in sorted(after) if contracts[table].root_class == "authorization"),
        metrics=PrimaryRadixMetrics(len(selected_rows), len(mutations), vectors, child_slots,
                                   len(ancestors), budget.hash_work, input_bytes, budget.nodes),
    )
