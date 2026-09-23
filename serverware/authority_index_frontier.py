"""Canonical outside-range identities, not counted-index evidence.

This pure helper covers the complement of one supplied fixed-key interval. It
does not authenticate a selector, interval, population, root or SQL response.
A production caller must derive the interval from its source-owned query and
still reconstruct the actual frontier against its separately admitted root.
No I/O, hashing, recursive tree expansion or caller-selected budget is used.
"""
from __future__ import annotations

from serverware.authority_index_contract import (
    KEY_NIBBLES, IndexRangeError, KeyInterval, validate_interval,
)


MAX_OUTSIDE_PREFIXES = 2 * KEY_NIBBLES * 15
MAX_VISITED_SLOTS = 16 * (2 * KEY_NIBBLES - 1)
_NIBBLES = "0123456789abcdef"
_TOP = 1 << (4 * KEY_NIBBLES)
_ROOT_CHILD_WIDTH = _TOP // 16


def outside_prefixes(interval: KeyInterval) -> tuple[str, ...]:
    """Return the canonical non-root prefix cover outside ``[lower, upper)``.

    Every returned prefix is maximal subject to staying outside the interval
    and never being the root. The result is sorted, unique and prefix-free.
    An empty interval therefore returns all sixteen depth-one identities; the
    entire keyspace returns no identities. Missing SQL nodes at these addresses
    are only empty candidates, not authenticated absence or complete evidence.

    At most two boundary subtrees per depth can partially intersect a nonempty
    contiguous interval. Only these expand: sixteen root slots and at most
    thirty-two slots at each remaining depth, never the full key universe.
    """
    owned = validate_interval(interval)
    if owned.upper == owned.lower:
        return tuple(_NIBBLES)
    lower = int(owned.lower, 16)
    upper = _TOP if owned.upper is None else int(owned.upper, 16)
    if lower == 0 and upper == _TOP:
        return ()

    # Reverse push order makes the iterative depth-first traversal lexical.
    # Starting below the root enforces the reconstructor's no-opaque-root rule.
    pending = [(_NIBBLES[ordinal], ordinal * _ROOT_CHILD_WIDTH, _ROOT_CHILD_WIDTH)
               for ordinal in range(15, -1, -1)]
    result: list[str] = []
    visited = 0
    while pending:
        if visited >= MAX_VISITED_SLOTS:
            raise IndexRangeError("outside-prefix cover exceeds its fixed traversal bound")
        prefix, start, width = pending.pop()
        visited += 1
        end = start + width
        if end <= lower or start >= upper:
            if len(result) >= MAX_OUTSIDE_PREFIXES:
                raise IndexRangeError("outside-prefix cover exceeds its fixed identity bound")
            result.append(prefix)
        elif lower <= start and end <= upper:
            continue
        else:
            # Integer endpoints cannot partially intersect a one-key leaf.
            # Keep an explicit fail-closed guard if the structural source
            # contract ever changes; never recurse or emit a partial subtree.
            if len(prefix) >= KEY_NIBBLES or width < 16:
                raise IndexRangeError("outside-prefix boundary cannot be subdivided")
            child_width = width // 16
            pending.extend((prefix + _NIBBLES[ordinal], start + ordinal * child_width, child_width)
                           for ordinal in range(15, -1, -1))
    return tuple(result)
