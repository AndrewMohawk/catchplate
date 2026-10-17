"""Bounded counted-index interval reconstruction, not query authority.

This pure component proves enumeration relative to a supplied index profile and
root. It does not authenticate that root, decode a SQL predicate, join primary
rows, establish maintained index population, or activate a transition kernel.
Its typed inputs are detached again before use; no caller-created result object
is accepted as prior verification. There is no JSON parser, database or I/O.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate.authority_index_contract import (
    PROFILE, EMPTY_DOMAIN, LEAF_DOMAIN, NODE_DOMAIN, KEY_NIBBLES,
    CountedNode, IndexLeaf, IndexProfile, IndexRangeError,
    KeyInterval, OpaqueSubtree, branch_node, leaf_node, validate_counted_node,
    validate_interval, validate_leaf, validate_opaque_subtree, validate_profile,
)
from catchplate.authority_query_read_work import _ValidationWork


_NIBBLES = "0123456789abcdef"
_TOP = 1 << (4 * KEY_NIBBLES)
_INPUT_DOMAIN = "catchplate.policyAuthorityIndexRangeInput/v1"


@dataclass(frozen=True, slots=True)
class IndexRangeLimits:
    """One invocation's budget; not a per-page or operation-level allowance."""

    max_entries: int = 8192
    max_leaves: int = 256
    max_opened_nodes: int = 65536
    max_hashes: int = 1048576
    max_input_bytes: int = 4194304

    def __post_init__(self) -> None:
        for value, ceiling in (
            (self.max_entries, 8192), (self.max_leaves, 256),
            (self.max_opened_nodes, 65536), (self.max_hashes, 1048576),
            (self.max_input_bytes, 4194304),
        ):
            if type(value) is not int or not 1 <= value <= ceiling:
                raise IndexRangeError("index range budget is not an exact bounded profile")


@dataclass(frozen=True, slots=True)
class IndexRangeMetrics:
    entries: int
    leaves: int
    opened_nodes: int
    child_slots: int
    hashes: int
    input_bytes: int


@dataclass(frozen=True, slots=True)
class IndexRangeObservation:
    """Relative reconstruction only; not a verified-authority capability."""

    profile: IndexProfile
    interval: KeyInterval
    leaves: tuple[IndexLeaf, ...]
    root: CountedNode
    metrics: IndexRangeMetrics


def _limits_snapshot(value: IndexRangeLimits) -> IndexRangeLimits:
    if type(value) is not IndexRangeLimits:
        raise IndexRangeError("index range limits have an unexpected exact type")
    try:
        return IndexRangeLimits(value.max_entries, value.max_leaves,
                                value.max_opened_nodes, value.max_hashes,
                                value.max_input_bytes)
    except AttributeError as exc:
        raise IndexRangeError("index range limits are incomplete") from exc


class _Budget:
    def __init__(self, limits: IndexRangeLimits, work: _ValidationWork | None = None) -> None:
        self.limits = limits
        self.work = work
        self.input_bytes = 0
        self.hashes = 0

    def fields(self, *values: str) -> None:
        # All values have already passed exact ASCII/size/type admission.
        # This measures one closed scalar framing, including each 8-byte length;
        # it is not a JSON transport-size or prior parser-allocation guarantee.
        for value in values:
            size = 8 + len(value)
            if size > self.limits.max_input_bytes - self.input_bytes:
                raise IndexRangeError("index range framed input exceeds its byte budget")
            if self.work is not None:
                self.work.charge(input_bytes=size)
            self.input_bytes += size

    def hash_work(self, amount: int) -> None:
        if amount > self.limits.max_hashes - self.hashes:
            raise IndexRangeError("index range reconstruction exceeds its hash budget")
        if self.work is not None:
            self.work.charge(hashes=amount)
        self.hashes += amount


def _prepare_hash_frames(profile: IndexProfile, domain: str, tail: tuple[str, ...],
                         work: _ValidationWork) -> None:
    """Reserve genuine counted-hash scalar encodings and length frames.

    Every value is already bounded ASCII. Each raw UTF-8 measurement/encoding
    costs 2U bytes and two scalar nodes; the actual length prefix costs eight
    bytes. This is declared encoding work, not allocator or SHA block work.
    """
    for value in (domain, PROFILE, profile.index_id, profile.table,
                  profile.projection_digest, str(KEY_NIBBLES), *tail):
        work.prepare_utf8(value)
        work.charge(input_bytes=8)


def _prepare_empty_work(profile: IndexProfile, prefix: str, work: _ValidationWork) -> None:
    """Prepare one actual empty_node call on an already admitted context."""
    if type(work) is not _ValidationWork:
        raise IndexRangeError("index range work has an unexpected exact type")
    work.charge(hashes=1)
    _prepare_hash_frames(profile, EMPTY_DOMAIN, (str(len(prefix)), prefix, "0"), work)


def _prepare_branch_encoding(profile: IndexProfile, prefix: str,
                             children: tuple[CountedNode | None, ...],
                             work: _ValidationWork) -> None:
    count = sum(child.count for child in children if child is not None)
    if not count:
        _prepare_hash_frames(profile, EMPTY_DOMAIN, (str(len(prefix)), prefix, "0"), work)
        return
    # The real branch constructor encodes each missing child's real digest
    # after computing it. Its exact canonical length is source-fixed at71;
    # measuring that length does not compute or substitute a digest.
    tail = [str(len(prefix)), prefix, str(count)]
    for ordinal, child in enumerate(children):
        if child is None:
            child_prefix = prefix + _NIBBLES[ordinal]
            _prepare_hash_frames(profile, EMPTY_DOMAIN,
                                 (str(len(child_prefix)), child_prefix, "0"), work)
            tail.extend(("0" * 71, "0"))
        else:
            tail.extend((child.digest, str(child.count)))
    _prepare_hash_frames(profile, NODE_DOMAIN, tuple(tail), work)


def _intersects(prefix: str, lower: int, upper: int) -> bool:
    if lower == upper:
        return False
    remaining_bits = 4 * (KEY_NIBBLES - len(prefix))
    start = int(prefix, 16) << remaining_bits
    return start < upper and lower < start + (1 << remaining_bits)


def _frontier_snapshot(
    frontier: tuple[IndexLeaf | OpaqueSubtree, ...],
    *, interval: KeyInterval, budget: _Budget,
) -> tuple[tuple[IndexLeaf | OpaqueSubtree, ...], tuple[IndexLeaf, ...]]:
    lower = int(interval.lower, 16)
    upper = _TOP if interval.upper is None else int(interval.upper, 16)
    snapshots: list[IndexLeaf | OpaqueSubtree] = []
    leaves: list[IndexLeaf] = []
    primary_keys: set[str] = set()
    previous: str | None = None
    for raw in frontier:
        if type(raw) is IndexLeaf:
            record = validate_leaf(raw)
            path = record.key
            if not lower <= int(path, 16) < upper:
                raise IndexRangeError("index range leaf lies outside the requested interval")
            if record.primary_key_digest in primary_keys:
                raise IndexRangeError("index range repeats a returned primary-key commitment")
            if len(leaves) >= budget.limits.max_leaves:
                raise IndexRangeError("index range exceeds its returned-leaf budget")
            budget.fields("leaf", record.key, record.primary_key_digest,
                          record.primary_row_digest)
            primary_keys.add(record.primary_key_digest)
            leaves.append(record)
        elif type(raw) is OpaqueSubtree:
            record = validate_opaque_subtree(raw)
            path = record.prefix
            if _intersects(path, lower, upper):
                raise IndexRangeError("nonempty opaque subtree intersects the requested interval")
            budget.fields("opaque", record.prefix, record.digest, str(record.count))
        else:
            raise IndexRangeError("index frontier entry has an unexpected exact type")
        # In lexical order a prefix and its descendants are adjacent. Checking
        # this before adding a record rejects duplicates and all overlap shapes.
        if previous is not None and (path <= previous or path.startswith(previous)):
            raise IndexRangeError("index frontier is not sorted, unique and prefix-free")
        previous = path
        snapshots.append(record)
    return tuple(snapshots), tuple(leaves)


def _open_prefixes(
    frontier: tuple[IndexLeaf | OpaqueSubtree, ...], limits: IndexRangeLimits,
) -> set[str]:
    # Even an empty interval opens the root. An opaque root could copy an
    # unverified count directly from a supplied descriptor without hashing it.
    opened = {""}
    for record in frontier:
        path = record.key if type(record) is IndexLeaf else record.prefix
        for depth in range(len(path)):
            prefix = path[:depth]
            if prefix not in opened:
                if len(opened) >= limits.max_opened_nodes:
                    raise IndexRangeError("index range exceeds its opened-node budget")
                opened.add(prefix)
    return opened


def _fold_frontier(
    *, profile: IndexProfile, frontier: tuple[IndexLeaf | OpaqueSubtree, ...],
    budget: _Budget,
) -> tuple[CountedNode, int]:
    """Fold an already detached/admitted frontier; not query admission.

    Enumeration and cardinality admit different terminal coverage, but use
    exactly the same counted hashes and cumulative work accounting. Callers
    must admit their interval semantics and compare the returned root.
    """
    opened = _open_prefixes(frontier, budget.limits)
    work = budget.work
    nodes: dict[str, CountedNode] = {}
    for record in frontier:
        if type(record) is IndexLeaf:
            budget.hash_work(1)
            if work is not None:
                _prepare_hash_frames(profile, LEAF_DOMAIN,
                                     (str(KEY_NIBBLES), record.key, "1",
                                      record.primary_key_digest, record.primary_row_digest), work)
            nodes[record.key] = leaf_node(profile, record)
        else:
            nodes[record.prefix] = CountedNode(record.digest, record.count)
    # Iterative bottom-up folding keeps stack depth independent of hostile
    # input. Each proper ancestor opens precisely sixteen positional slots.
    for prefix in sorted(opened, key=lambda value: (-len(value), value)):
        children = tuple(nodes.get(prefix + nibble) for nibble in _NIBBLES)
        nonempty = sum(child is not None for child in children)
        budget.hash_work(1 if nonempty == 0 else 17 - nonempty)
        if work is not None:
            _prepare_branch_encoding(profile, prefix, children, work)
        nodes[prefix] = branch_node(profile, prefix, children)
    return nodes[""], len(opened)


def reconstruct_complete_index_range(
    *, profile: IndexProfile, expected_root: CountedNode, interval: KeyInterval,
    frontier: tuple[IndexLeaf | OpaqueSubtree, ...], limits: IndexRangeLimits,
) -> IndexRangeObservation:
    """Reconstruct a complete half-open interval of fixed-width index keys.

    The sparse terminal frontier is sorted and prefix-free. Positive opaque
    subtrees are accepted only outside the requested interval. Every unlisted
    child is treated as the profile's canonical empty subtree, so omission of
    populated data changes the reconstructed root. The proof cannot assert its
    own interval or expected root, and no terminal/count claim bypasses hashing.

    Caller-owned profile/root authority, semantic projection and primary-row
    joins are deliberately absent from this result. Combining queries must
    charge their total work separately; this API does not authorize pagination.
    """
    return _reconstruct_complete_index_range(
        profile=profile, expected_root=expected_root, interval=interval,
        frontier=frontier, limits=limits, work=None,
    )


def _reconstruct_complete_index_range(
    *, profile: IndexProfile, expected_root: CountedNode, interval: KeyInterval,
    frontier: tuple[IndexLeaf | OpaqueSubtree, ...], limits: IndexRangeLimits,
    work: _ValidationWork | None = None,
) -> IndexRangeObservation:
    """Actual range body with optional caller-owned cumulative encoding work.

    Local observation metrics retain their historical scalar-input/hash scope.
    Shared work additionally spends repeated real hash-frame encodings; it is
    not a network, database, whole-process allocation or general CPU meter.
    """
    if work is not None and type(work) is not _ValidationWork:
        raise IndexRangeError("index range work has an unexpected exact type")
    limits = _limits_snapshot(limits)
    profile = validate_profile(profile)
    expected_root = validate_counted_node(expected_root)
    interval = validate_interval(interval)
    if type(frontier) is not tuple or len(frontier) > limits.max_entries:
        raise IndexRangeError("index range frontier is not a bounded exact tuple")
    budget = _Budget(limits, work)
    budget.fields(_INPUT_DOMAIN, PROFILE, profile.index_id, profile.table,
                  profile.projection_digest, str(KEY_NIBBLES),
                  expected_root.digest, str(expected_root.count), interval.lower,
                  "top" if interval.upper is None else interval.upper,
                  str(len(frontier)))
    frontier, leaves = _frontier_snapshot(frontier, interval=interval, budget=budget)
    root, opened = _fold_frontier(profile=profile, frontier=frontier, budget=budget)
    if root != expected_root:
        raise IndexRangeError("index range reconstructed root or count differs from its anchor")
    return IndexRangeObservation(
        profile=profile, interval=interval, leaves=leaves, root=root,
        metrics=IndexRangeMetrics(
            entries=len(frontier), leaves=len(leaves), opened_nodes=opened,
            child_slots=16 * opened, hashes=budget.hashes,
            input_bytes=budget.input_bytes,
        ),
    )
