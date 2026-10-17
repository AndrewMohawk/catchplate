"""Bounded interval cardinality relative to a supplied counted-index root.

Wholly covered opaque subtrees contribute their authenticated counts without
enumerating their leaves. A subtree crossing either interval boundary must be
opened. This is NOT primary-row evidence, a joined eligibility summary, root
currentness or query authority. In particular independent reference counts
cannot establish a set difference or cross-table reference exclusion.

All values are detached and revalidated before folding, and every hash/frame
uses the same budget machinery as enumeration. The population may exceed the
returned-leaf allowance without raising any proof or shared-work ceiling.
"""
from __future__ import annotations

from dataclasses import dataclass

from catchplate import authority_index_range as ranges
from catchplate.authority_index_contract import (
    PROFILE, KEY_NIBBLES, I64_MAX, CountedNode, IndexLeaf, IndexProfile,
    IndexRangeError, KeyInterval, OpaqueSubtree, validate_counted_node,
    validate_interval, validate_leaf, validate_opaque_subtree, validate_profile,
)
from catchplate.authority_query_read_work import _ValidationWork


_INPUT_DOMAIN = "catchplate.policyAuthorityIndexRangeCountInput/v1"
_TOP = 1 << (4 * KEY_NIBBLES)


@dataclass(frozen=True, slots=True)
class IndexRangeCountObservation:
    """Ordinary relative reconstruction data, never a verified capability."""

    profile: IndexProfile
    interval: KeyInterval
    count: int
    root: CountedNode
    metrics: ranges.IndexRangeMetrics


def _frontier_snapshot(frontier, *, interval, budget):
    lower = int(interval.lower, 16)
    upper = _TOP if interval.upper is None else int(interval.upper, 16)
    snapshots = []
    primary_keys = set()
    previous = None
    cardinality = leaves = 0
    for raw in frontier:
        if type(raw) is IndexLeaf:
            record = validate_leaf(raw)
            path = record.key
            if not lower <= int(path, 16) < upper:
                raise IndexRangeError("index count leaf lies outside the requested interval")
            if record.primary_key_digest in primary_keys:
                raise IndexRangeError("index count repeats a returned primary-key commitment")
            if leaves >= budget.limits.max_leaves:
                raise IndexRangeError("index count exceeds its explicit-leaf budget")
            budget.fields("leaf", record.key, record.primary_key_digest,
                          record.primary_row_digest)
            primary_keys.add(record.primary_key_digest)
            leaves += 1
            contribution = 1
        elif type(raw) is OpaqueSubtree:
            record = validate_opaque_subtree(raw)
            path = record.prefix
            remaining = 4 * (KEY_NIBBLES - len(path))
            start = int(path, 16) << remaining
            end = start + (1 << remaining)
            covered = lower <= start and end <= upper
            intersects = lower != upper and start < upper and lower < end
            if intersects and not covered:
                raise IndexRangeError("opaque index count subtree crosses an interval boundary")
            contribution = record.count if covered else 0
            budget.fields("opaque", record.prefix, record.digest, str(record.count))
        else:
            raise IndexRangeError("index count frontier entry has an unexpected exact type")
        if previous is not None and (path <= previous or path.startswith(previous)):
            raise IndexRangeError("index count frontier is not sorted, unique and prefix-free")
        if contribution > I64_MAX - cardinality:
            raise IndexRangeError("index interval count overflows int64")
        cardinality += contribution
        previous = path
        snapshots.append(record)
    return tuple(snapshots), cardinality, leaves


def reconstruct_index_range_count(
    *, profile: IndexProfile, expected_root: CountedNode, interval: KeyInterval,
    frontier: tuple[IndexLeaf | OpaqueSubtree, ...], limits: ranges.IndexRangeLimits,
) -> IndexRangeCountObservation:
    """Reconstruct the root and count keys in the caller's half-open interval.

    Omitted populated children change the reconstructed root. The root is
    always opened; no opaque root can merely echo its supplied count. The
    caller must separately authenticate the profile/root and source selector.
    """
    return _reconstruct_index_range_count(profile=profile, expected_root=expected_root,
        interval=interval, frontier=frontier, limits=limits, work=None)


def _reconstruct_index_range_count(
    *, profile: IndexProfile, expected_root: CountedNode, interval: KeyInterval,
    frontier: tuple[IndexLeaf | OpaqueSubtree, ...], limits: ranges.IndexRangeLimits,
    work: _ValidationWork | None = None,
) -> IndexRangeCountObservation:
    """Count on the caller's existing cumulative work, without a new allowance."""
    if work is not None and type(work) is not _ValidationWork:
        raise IndexRangeError("index count work has an unexpected exact type")
    limits = ranges._limits_snapshot(limits)
    profile = validate_profile(profile)
    expected_root = validate_counted_node(expected_root)
    interval = validate_interval(interval)
    if type(frontier) is not tuple or len(frontier) > limits.max_entries:
        raise IndexRangeError("index count frontier is not a bounded exact tuple")
    budget = ranges._Budget(limits, work)
    budget.fields(_INPUT_DOMAIN, PROFILE, profile.index_id, profile.table,
                  profile.projection_digest, str(KEY_NIBBLES),
                  expected_root.digest, str(expected_root.count), interval.lower,
                  "top" if interval.upper is None else interval.upper,
                  str(len(frontier)))
    frontier, count, leaves = _frontier_snapshot(frontier, interval=interval, budget=budget)
    root, opened = ranges._fold_frontier(profile=profile, frontier=frontier, budget=budget)
    if root != expected_root:
        raise IndexRangeError("index count reconstructed root or count differs from its anchor")
    return IndexRangeCountObservation(profile=profile, interval=interval, count=count, root=root,
        metrics=ranges.IndexRangeMetrics(entries=len(frontier), leaves=leaves,
            opened_nodes=opened, child_slots=16 * opened, hashes=budget.hashes,
            input_bytes=budget.input_bytes))
