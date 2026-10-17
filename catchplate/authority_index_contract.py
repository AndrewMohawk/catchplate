"""Pure counted-index values and hashes, relative to a supplied root.

The 160-nibble key is only a fixed-width structural contract. Its prospective
partition/order/primary-key decomposition does not establish a semantic codec,
selector, primary-row join, currentness, authorization or installed index.
These hashes are separate from every persisted primary-tree hash. No I/O,
clock, registry, cache or authority token is used here.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any


PROFILE = "catchplate.policyAuthorityCountedIndex/v1"
KEY_NIBBLES = 160
I64_MAX = 2**63 - 1
EMPTY_DOMAIN = "catchplate.policyAuthorityCountedIndexEmpty/v1"
LEAF_DOMAIN = "catchplate.policyAuthorityCountedIndexLeaf/v1"
NODE_DOMAIN = "catchplate.policyAuthorityCountedIndexNode/v1"
_IDENTIFIER = re.compile(r"[a-z][a-z0-9_]*\Z")
_HEX = re.compile(r"[0-9a-f]*\Z")
_NIBBLES = "0123456789abcdef"


class IndexRangeError(ValueError):
    pass


def _identifier(value: Any, label: str) -> None:
    if (type(value) is not str or not 1 <= len(value) <= 128
            or _IDENTIFIER.fullmatch(value) is None):
        raise IndexRangeError(f"{label} is not an exact ASCII identifier")


def _digest(value: Any, label: str) -> None:
    if (type(value) is not str or len(value) != 71
            or not value.startswith("sha256:")
            or _HEX.fullmatch(value[7:]) is None):
        raise IndexRangeError(f"{label} is not a canonical SHA-256 digest")


def _prefix(value: Any, *, minimum: int = 0, maximum: int = KEY_NIBBLES) -> None:
    if (type(value) is not str or not minimum <= len(value) <= maximum
            or _HEX.fullmatch(value) is None):
        raise IndexRangeError("index prefix is not bounded lowercase hexadecimal")


def _key(value: Any) -> None:
    _prefix(value, minimum=KEY_NIBBLES)


def _count(value: Any, *, minimum: int = 0) -> None:
    if type(value) is not int or not minimum <= value <= I64_MAX:
        raise IndexRangeError("index count is not an exact bounded int64")


def _subtree_capacity(depth: int) -> int:
    # Callers supply a validated prefix depth. Each complete fixed key has
    # exactly one leaf slot; this does not establish actual population.
    return min(I64_MAX, 1 << (4 * (KEY_NIBBLES - depth)))


@dataclass(frozen=True, slots=True)
class IndexProfile:
    index_id: str
    table: str
    projection_digest: str

    def __post_init__(self) -> None:
        _identifier(self.index_id, "index identity")
        _identifier(self.table, "index table")
        _digest(self.projection_digest, "index projection digest")


@dataclass(frozen=True, slots=True)
class CountedNode:
    digest: str
    count: int

    def __post_init__(self) -> None:
        _digest(self.digest, "index node digest")
        _count(self.count)


@dataclass(frozen=True, slots=True)
class IndexLeaf:
    key: str
    primary_key_digest: str
    primary_row_digest: str

    def __post_init__(self) -> None:
        _key(self.key)
        _digest(self.primary_key_digest, "index primary-key digest")
        _digest(self.primary_row_digest, "index primary-row digest")


@dataclass(frozen=True, slots=True)
class OpaqueSubtree:
    prefix: str
    digest: str
    count: int

    def __post_init__(self) -> None:
        # An opaque root would hide the entire query, including an empty one.
        _prefix(self.prefix, minimum=1)
        _digest(self.digest, "opaque index digest")
        _count(self.count, minimum=1)
        if self.count > _subtree_capacity(len(self.prefix)):
            raise IndexRangeError("opaque index count exceeds its fixed-key capacity")


@dataclass(frozen=True, slots=True)
class KeyInterval:
    """Half-open fixed-key interval; None is the exclusive top sentinel."""

    lower: str
    upper: str | None

    def __post_init__(self) -> None:
        _key(self.lower)
        if self.upper is not None:
            _key(self.upper)
            if self.upper < self.lower:
                raise IndexRangeError("index interval upper bound precedes its lower bound")


def _fields(value: Any, expected: type, names: tuple[str, ...]) -> tuple[Any, ...]:
    if type(value) is not expected:
        raise IndexRangeError("index value has an unexpected exact type")
    try:
        return tuple(getattr(value, name) for name in names)
    except AttributeError as exc:
        raise IndexRangeError("index value is incomplete") from exc


def validate_profile(value: IndexProfile) -> IndexProfile:
    """Return a fresh revalidated value, not a trusted projection authority."""
    return IndexProfile(*_fields(value, IndexProfile, (
        "index_id", "table", "projection_digest",
    )))


def validate_counted_node(value: CountedNode) -> CountedNode:
    return CountedNode(*_fields(value, CountedNode, ("digest", "count")))


def validate_leaf(value: IndexLeaf) -> IndexLeaf:
    return IndexLeaf(*_fields(value, IndexLeaf, (
        "key", "primary_key_digest", "primary_row_digest",
    )))


def validate_opaque_subtree(value: OpaqueSubtree) -> OpaqueSubtree:
    return OpaqueSubtree(*_fields(value, OpaqueSubtree, ("prefix", "digest", "count")))


def validate_interval(value: KeyInterval) -> KeyInterval:
    return KeyInterval(*_fields(value, KeyInterval, ("lower", "upper")))


def _profile_frames(profile: IndexProfile) -> tuple[bytes, ...]:
    return (
        PROFILE.encode("ascii"), profile.index_id.encode("ascii"),
        profile.table.encode("ascii"), profile.projection_digest.encode("ascii"),
        str(KEY_NIBBLES).encode("ascii"),
    )


def _hash(domain: str, profile: IndexProfile, *frames: bytes) -> str:
    # The domain is a frame too; this is NOT the primary proof domain-NUL format.
    digest = hashlib.sha256()
    for frame in (domain.encode("ascii"), *_profile_frames(profile), *frames):
        digest.update(len(frame).to_bytes(8, "big"))
        digest.update(frame)
    return "sha256:" + digest.hexdigest()


def empty_node(profile: IndexProfile, prefix: str) -> CountedNode:
    profile = validate_profile(profile)
    _prefix(prefix)
    return CountedNode(_hash(
        EMPTY_DOMAIN, profile, str(len(prefix)).encode("ascii"),
        prefix.encode("ascii"), b"0",
    ), 0)


def leaf_node(profile: IndexProfile, leaf: IndexLeaf) -> CountedNode:
    profile = validate_profile(profile)
    leaf = validate_leaf(leaf)
    return CountedNode(_hash(
        LEAF_DOMAIN, profile, str(KEY_NIBBLES).encode("ascii"),
        leaf.key.encode("ascii"), b"1", leaf.primary_key_digest.encode("ascii"),
        leaf.primary_row_digest.encode("ascii"),
    ), 1)


def branch_node(
    profile: IndexProfile,
    prefix: str,
    children: tuple[CountedNode | None, ...],
) -> CountedNode:
    profile = validate_profile(profile)
    _prefix(prefix, maximum=KEY_NIBBLES - 1)
    if type(children) is not tuple or len(children) != 16:
        raise IndexRangeError("index branch requires exactly sixteen child slots")
    # Validate and snapshot all explicit children, and reject overflow, before
    # computing even one hash. None is the only canonical empty-child spelling.
    checked: list[CountedNode | None] = []
    count = 0
    child_capacity = _subtree_capacity(len(prefix) + 1)
    for child in children:
        if child is None:
            checked.append(None)
            continue
        child = validate_counted_node(child)
        if child.count == 0:
            raise IndexRangeError("explicit zero-count index child is forbidden")
        if child.count > child_capacity:
            raise IndexRangeError("index child count exceeds its fixed-key capacity")
        if child.count > I64_MAX - count:
            raise IndexRangeError("index branch count overflows int64")
        count += child.count
        checked.append(child)
    if count == 0:
        # One hash, not a recursive expansion of empty descendants.
        return empty_node(profile, prefix)
    frames = [str(len(prefix)).encode("ascii"), prefix.encode("ascii"),
              str(count).encode("ascii")]
    for ordinal, child in enumerate(checked):
        if child is None:
            child = empty_node(profile, prefix + _NIBBLES[ordinal])
        frames.extend((child.digest.encode("ascii"), str(child.count).encode("ascii")))
    return CountedNode(_hash(NODE_DOMAIN, profile, *frames), count)
