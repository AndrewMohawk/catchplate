"""Bounded sparse counted-index changes, relative to a supplied before root.

This pure evaluator proves old membership/nonmembership on every changed path
and folds both root states with the real counted-index hashes. It does not
derive source projections, authenticate primary rows or a root/checkpoint,
maintain SQL storage, assign revisions, or authorize an operation. Inputs and
results are data, never reusable proof capabilities. No I/O or clock is used.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from serverware.authority_index_contract import (
    I64_MAX, KEY_NIBBLES, PROFILE, CountedNode, IndexLeaf, IndexProfile,
    IndexRangeError, OpaqueSubtree, branch_node, leaf_node,
    validate_counted_node, validate_leaf, validate_opaque_subtree, validate_profile,
)


MAX_CHANGES = 514
MAX_OPENED_NODES = 1 + KEY_NIBBLES * MAX_CHANGES
MAX_FRONTIER_ENTRIES = 16 * MAX_OPENED_NODES
MAX_HASHES = 2 * (16 * MAX_OPENED_NODES + MAX_CHANGES)
MAX_INPUT_BYTES = 64 * 1024 * 1024
_INPUT_DOMAIN = "serverware.policyAuthorityIndexMutationInput/v1"
_NIBBLES = "0123456789abcdef"
_KEY = re.compile(r"[0-9a-f]{160}\Z")


class IndexMutationError(IndexRangeError):
    pass


def _key(value: str) -> None:
    if type(value) is not str or len(value) != KEY_NIBBLES or _KEY.fullmatch(value) is None:
        raise IndexMutationError("index mutation key is not exact fixed-width lowercase hexadecimal")


def _leaf(value: IndexLeaf) -> IndexLeaf:
    try:
        return validate_leaf(value)
    except IndexRangeError as exc:
        raise IndexMutationError("index mutation leaf image is invalid") from exc


@dataclass(frozen=True, slots=True)
class IndexLeafChange:
    key: str
    before: IndexLeaf | None
    after: IndexLeaf | None

    def __post_init__(self) -> None:
        _key(self.key)
        if self.before is None and self.after is None:
            raise IndexMutationError("index mutation requires at least one leaf image")
        for name in ("before", "after"):
            value = getattr(self, name)
            if value is not None:
                owned = _leaf(value)
                if owned.key != self.key:
                    raise IndexMutationError("index mutation leaf image differs from its target key")
                object.__setattr__(self, name, owned)


@dataclass(frozen=True, slots=True)
class IndexMutationLimits:
    """One invocation's source ceilings; callers may tighten, never expand."""

    max_changes: int = MAX_CHANGES
    max_frontier_entries: int = MAX_FRONTIER_ENTRIES
    max_opened_nodes: int = MAX_OPENED_NODES
    max_hashes: int = MAX_HASHES
    max_input_bytes: int = MAX_INPUT_BYTES

    def __post_init__(self) -> None:
        for value, ceiling in (
            (self.max_changes, MAX_CHANGES), (self.max_frontier_entries, MAX_FRONTIER_ENTRIES),
            (self.max_opened_nodes, MAX_OPENED_NODES), (self.max_hashes, MAX_HASHES),
            (self.max_input_bytes, MAX_INPUT_BYTES),
        ):
            if type(value) is not int or not 1 <= value <= ceiling:
                raise IndexMutationError("index mutation limit is not an exact bounded source value")


@dataclass(frozen=True, slots=True)
class IndexMutationMetrics:
    changes: int
    frontier_entries: int
    opened_nodes: int
    child_slots: int
    before_hashes: int
    after_hashes: int
    input_bytes: int

    @property
    def hashes(self) -> int:
        return self.before_hashes + self.after_hashes


@dataclass(frozen=True, slots=True)
class IndexMutationResult:
    before_root: CountedNode
    after_root: CountedNode
    metrics: IndexMutationMetrics


@dataclass(frozen=True, slots=True)
class _IndexMutationOverlay:
    """Privately retained actual fold nodes, never a verification input."""

    result: IndexMutationResult
    nodes: dict[str, CountedNode | None]


def _limits(value: IndexMutationLimits) -> IndexMutationLimits:
    if type(value) is not IndexMutationLimits:
        raise IndexMutationError("index mutation limits have an unexpected exact type")
    try:
        return IndexMutationLimits(value.max_changes, value.max_frontier_entries,
                                   value.max_opened_nodes, value.max_hashes, value.max_input_bytes)
    except AttributeError as exc:
        raise IndexMutationError("index mutation limits are incomplete") from exc


def _change(value: IndexLeafChange) -> IndexLeafChange:
    if type(value) is not IndexLeafChange:
        raise IndexMutationError("index mutation change has an unexpected exact type")
    try:
        return IndexLeafChange(value.key, value.before, value.after)
    except AttributeError as exc:
        raise IndexMutationError("index mutation change is incomplete") from exc


class _Budget:
    def __init__(self, limits: IndexMutationLimits) -> None:
        self.limits, self.input_bytes = limits, 0

    def fields(self, *values: str) -> None:
        # Admitted scalars are exact bounded ASCII. This is closed scalar
        # framing, not JSON/network size or a caller's prior allocation bound.
        for value in values:
            size = 8 + len(value)
            if size > self.limits.max_input_bytes - self.input_bytes:
                raise IndexMutationError("index mutation framed input exceeds its byte budget")
            self.input_bytes += size


def _snapshots(changes, frontier, profile, root, budget):
    limits = budget.limits
    if type(changes) is not tuple or len(changes) > limits.max_changes:
        raise IndexMutationError("index mutation changes exceed their exact tuple bound")
    if type(frontier) is not tuple or len(frontier) > limits.max_frontier_entries:
        raise IndexMutationError("index mutation frontier exceeds its exact tuple bound")
    budget.fields(_INPUT_DOMAIN, PROFILE, profile.index_id, profile.table, profile.projection_digest,
                  str(KEY_NIBBLES), root.digest, str(root.count), str(len(changes)), str(len(frontier)))
    owned_changes = []
    targets = {}
    previous = None
    for raw in changes:
        change = _change(raw)
        if previous is not None and change.key <= previous:
            raise IndexMutationError("index mutation changes are not sorted and unique")
        budget.fields("change", change.key)
        for name, value in (("before", change.before), ("after", change.after)):
            if value is None:
                budget.fields(name + "-absent")
            else:
                budget.fields(name + "-leaf", value.key, value.primary_key_digest, value.primary_row_digest)
        owned_changes.append(change)
        targets[change.key] = change
        previous = change.key

    # Every targeted path is opened even when its before image is absent.
    # Cardinality is checked before retaining each new bounded prefix, and the
    # complete set is bounded before any sorting or hashing is performed.
    opened = {""}
    for change in owned_changes:
        for depth in range(KEY_NIBBLES):
            prefix = change.key[:depth]
            if prefix not in opened:
                if len(opened) >= limits.max_opened_nodes:
                    raise IndexMutationError("index mutation exceeds its opened-node budget")
                opened.add(prefix)

    owned_frontier = []
    matched = set()
    previous = None
    for raw in frontier:
        if type(raw) is IndexLeaf:
            record = _leaf(raw)
            path = record.key
            change = targets.get(path)
            if change is None or change.before is None or record != change.before:
                raise IndexMutationError("index mutation frontier leaf is not its exact before image")
            budget.fields("leaf", path, record.primary_key_digest, record.primary_row_digest)
            matched.add(path)
        elif type(raw) is OpaqueSubtree:
            try:
                record = validate_opaque_subtree(raw)
            except IndexRangeError as exc:
                raise IndexMutationError("index mutation opaque frontier record is invalid") from exc
            path = record.prefix
            if path in opened or path in targets or path[:-1] not in opened:
                raise IndexMutationError("index mutation opaque record is not an untouched immediate sibling")
            budget.fields("opaque", path, record.digest, str(record.count))
        else:
            raise IndexMutationError("index mutation frontier has an unexpected exact record type")
        if previous is not None and (path <= previous or path.startswith(previous)):
            raise IndexMutationError("index mutation frontier is not sorted, unique and prefix-free")
        owned_frontier.append(record)
        previous = path
    if matched != {change.key for change in owned_changes if change.before is not None}:
        raise IndexMutationError("index mutation frontier omitted a required before leaf")
    return tuple(owned_changes), tuple(owned_frontier), tuple(sorted(opened, key=lambda path: (-len(path), path)))


def _terminals(frontier, changes, *, after: bool):
    result = {record.key if type(record) is IndexLeaf else record.prefix: record for record in frontier}
    if after:
        for change in changes:
            if change.after is None:
                result.pop(change.key, None)
            else:
                result[change.key] = change.after
    return result


def _phase_work(terminals, opened) -> int:
    # Count/shape overflow and exact hash work for BOTH phases are admitted
    # before the first hash. Opaque counts are still untrusted commitments;
    # only the later genuine before fold can bind them to the supplied root.
    counts = {path: 1 if type(record) is IndexLeaf else record.count for path, record in terminals.items()}
    hashes = sum(type(record) is IndexLeaf for record in terminals.values())
    for prefix in opened:
        children = tuple(counts.pop(prefix + digit, 0) for digit in _NIBBLES)
        nonempty = sum(value > 0 for value in children)
        count = sum(children)
        capacity = min(I64_MAX, 1 << (4 * (KEY_NIBBLES - len(prefix))))
        if count > capacity:
            raise IndexMutationError("index mutation subtree count exceeds its fixed-key or int64 capacity")
        hashes += 1 if nonempty == 0 else 17 - nonempty
        if count:
            counts[prefix] = count
    return hashes


def _fold(profile, terminals, opened, *, retained=None) -> CountedNode:
    nodes = {path: leaf_node(profile, record) if type(record) is IndexLeaf
             else CountedNode(record.digest, record.count) for path, record in terminals.items()}
    if retained is not None:
        # Actual immutable node references, not another hash/JSON pass. Only
        # the private raw-input wrapper supplies this fresh internal map.
        retained.update(nodes)
    root = None
    for prefix in opened:
        children = tuple(nodes.pop(prefix + digit, None) for digit in _NIBBLES)
        node = branch_node(profile, prefix, children)
        if retained is not None:
            retained[prefix] = node if node.count else None
        # An opened absence branch has a real empty hash but is represented as
        # None in its parent, the counted contract's only empty-child spelling.
        if node.count:
            nodes[prefix] = node
        if prefix == "":
            root = node
    if root is None:
        raise IndexMutationError("index mutation did not reconstruct its root")
    return root


def _evaluate_index_mutations(
    *, profile: IndexProfile, before_root: CountedNode, changes: tuple[IndexLeafChange, ...],
    frontier: tuple[IndexLeaf | OpaqueSubtree, ...], limits: IndexMutationLimits,
    retain_nodes: bool,
) -> _IndexMutationOverlay:
    """Verify every old target path, then genuinely fold its changed tree.

    Untouched opaque records must be immediate children of opened ancestors,
    never targets, opened paths or the root. No changes still opens the root
    and allows only its positive depth-one children, then hashes both phases.
    Equal before/after leaves are allowed for explicit unchanged-row updates.
    Missing frontier siblings mean canonical emptiness, not proven absence on
    their own; the complete before digest AND count must match before success.
    """
    limits = _limits(limits)
    if type(retain_nodes) is not bool:
        raise IndexMutationError("index mutation private capture selection changed")
    try:
        profile = validate_profile(profile)
        before_root = validate_counted_node(before_root)
    except IndexRangeError as exc:
        raise IndexMutationError("index mutation profile or before root is invalid") from exc
    budget = _Budget(limits)
    changes, frontier, opened = _snapshots(changes, frontier, profile, before_root, budget)
    before = _terminals(frontier, changes, after=False)
    after = _terminals(frontier, changes, after=True)
    before_hashes, after_hashes = _phase_work(before, opened), _phase_work(after, opened)
    if before_hashes + after_hashes > limits.max_hashes:
        raise IndexMutationError("index mutation exceeds its combined hash budget")
    actual_before = _fold(profile, before, opened)
    if actual_before != before_root:
        raise IndexMutationError("index mutation reconstructed before root or count differs")
    retained = {} if retain_nodes else None
    actual_after = (_fold(profile, after, opened) if retained is None
                    else _fold(profile, after, opened, retained=retained))
    if retained is not None:
        for change in changes:
            if change.after is None:
                retained[change.key] = None
    result = IndexMutationResult(actual_before, actual_after, IndexMutationMetrics(
        changes=len(changes), frontier_entries=len(frontier), opened_nodes=len(opened),
        child_slots=2 * 16 * len(opened), before_hashes=before_hashes, after_hashes=after_hashes,
        input_bytes=budget.input_bytes,
    ))
    return _IndexMutationOverlay(result, {} if retained is None else retained)


def evaluate_index_mutations(*, profile: IndexProfile, before_root: CountedNode,
        changes: tuple[IndexLeafChange, ...], frontier: tuple[IndexLeaf | OpaqueSubtree, ...],
        limits: IndexMutationLimits) -> IndexMutationResult:
    """Preserve the public raw-input fold and its original result/limits."""
    return _evaluate_index_mutations(profile=profile, before_root=before_root,
        changes=changes, frontier=frontier, limits=limits, retain_nodes=False).result


def _evaluate_index_mutations_overlay(*, profile, before_root, changes, frontier, limits):
    """Reconstruct both roots from originals and retain the actual NEW nodes.

    These conditional producer observations never replace raw before proofs
    during later replay. No caller supplied node map or successful result is
    accepted, and the sole fold still admits every original limit and hash.
    """
    return _evaluate_index_mutations(profile=profile, before_root=before_root,
        changes=changes, frontier=frontier, limits=limits, retain_nodes=True)
