"""Private cumulative work accounting for measured QueryRead validation.

Only standard-library imports are permitted here: transition_core itself uses
query_reads. Byte units are defined canonical/framed work, not Python allocation
or transport size. JSON nodes include dictionary keys and every repeated walk.
The public limits are ceilings, never caller-granted authority.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


MAX_HASHES = 8_000_000
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_JSON_NODES = 1_000_000
MAX_JSON_DEPTH = 128


class QueryReadWorkError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class QueryReadValidationLimits:
    max_hashes: int = MAX_HASHES
    max_input_bytes: int = MAX_INPUT_BYTES
    max_json_nodes: int = MAX_JSON_NODES

    def __post_init__(self) -> None:
        for value, maximum in ((self.max_hashes, MAX_HASHES),
                               (self.max_input_bytes, MAX_INPUT_BYTES),
                               (self.max_json_nodes, MAX_JSON_NODES)):
            if type(value) is not int or not 1 <= value <= maximum:
                raise QueryReadWorkError("query read work limit is not an exact positive source-bounded integer")


@dataclass(frozen=True, slots=True)
class QueryReadValidationMetrics:
    hash_work: int
    input_bytes: int
    json_nodes: int


class _ValidationWork:
    """One measured invocation; helpers never create replacement allowances."""

    def __init__(self, limits: QueryReadValidationLimits) -> None:
        if type(limits) is not QueryReadValidationLimits:
            raise QueryReadWorkError("query read work limits have an unexpected exact type")
        try:
            self.limits = QueryReadValidationLimits(
                limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
        except AttributeError as exc:
            raise QueryReadWorkError("query read work limits are incomplete") from exc
        self.hash_work = self.input_bytes = self.json_nodes = 0

    def charge(self, *, hashes: int = 0, input_bytes: int = 0, json_nodes: int = 0) -> None:
        if (any(type(value) is not int or value < 0 for value in (hashes, input_bytes, json_nodes))
                or hashes > self.limits.max_hashes - self.hash_work
                or input_bytes > self.limits.max_input_bytes - self.input_bytes
                or json_nodes > self.limits.max_json_nodes - self.json_nodes):
            raise QueryReadWorkError("query read validation exceeds its cumulative work budget")
        self.hash_work += hashes
        self.input_bytes += input_bytes
        self.json_nodes += json_nodes

    @property
    def metrics(self) -> QueryReadValidationMetrics:
        return QueryReadValidationMetrics(self.hash_work, self.input_bytes, self.json_nodes)

    def _measure(self, value: Any, *, ensure_ascii: bool, depth: int,
                 ancestors: frozenset[int]) -> None:
        if depth > MAX_JSON_DEPTH:
            raise QueryReadWorkError("query read encoding exceeds its source depth")
        self.charge(json_nodes=1)
        kind = type(value)
        if value is None or kind is bool:
            self.charge(input_bytes=4 if value is None or value is True else 5)
            return
        if kind is int:
            if value.bit_length() > 16384:
                raise QueryReadWorkError("query read encoding integer exceeds its source bound")
            self.charge(input_bytes=len(str(value)))
            return
        if kind is str:
            remaining = self.limits.max_input_bytes - self.input_bytes
            if len(value) + 2 > remaining:
                raise QueryReadWorkError("query read encoding string exceeds remaining work")
            size = 2
            for character in value:
                point = ord(character)
                if 0xD800 <= point <= 0xDFFF:
                    raise QueryReadWorkError("query read encoding contains a Unicode surrogate")
                size += (2 if character in '"\\\b\f\n\r\t' else
                         6 if point < 32 else
                         (12 if point > 0xFFFF else 6) if ensure_ascii and point >= 127 else
                         1 if point < 128 else 2 if point < 2048 else 3 if point < 65536 else 4)
                if size > remaining:
                    raise QueryReadWorkError("query read encoding string exceeds remaining work")
            self.charge(input_bytes=size)
            return
        if kind not in (dict, list, tuple) or id(value) in ancestors:
            raise QueryReadWorkError("query read encoding requires acyclic exact lossless JSON")
        minimum = len(value) * (2 if kind is dict else 1)
        if minimum > self.limits.max_json_nodes - self.json_nodes:
            raise QueryReadWorkError("query read encoding exceeds remaining structure work")
        self.charge(input_bytes=2 + max(0, len(value) - 1) + (len(value) if kind is dict else 0))
        branch = ancestors | {id(value)}
        if kind is dict:
            for key, child in value.items():
                if type(key) is not str:
                    raise QueryReadWorkError("query read encoding key is not an exact string")
                self._measure(key, ensure_ascii=ensure_ascii, depth=depth + 1, ancestors=branch)
                self._measure(child, ensure_ascii=ensure_ascii, depth=depth + 1, ancestors=branch)
        else:
            for child in value:
                self._measure(child, ensure_ascii=ensure_ascii, depth=depth + 1, ancestors=branch)

    def measure(self, value: Any, *, ensure_ascii: bool = True) -> tuple[int, int]:
        """Charge a real exact-size traversal without emitting a JSON buffer."""
        before_bytes, before_nodes = self.input_bytes, self.json_nodes
        self._measure(value, ensure_ascii=ensure_ascii, depth=0, ancestors=frozenset())
        return self.input_bytes - before_bytes, self.json_nodes - before_nodes

    def prepare_encoding(self, value: Any, *, ensure_ascii: bool = True,
                         shallow_copies: int = 0) -> tuple[int, int]:
        """Measure, then reserve encoding and any declared hidden dict copies.

        A hidden shallow copy is conservatively charged the full canonical
        key graph, not its interpreter allocation size. The actual caller must
        perform precisely the prepared constructor/encoding after this returns.
        """
        size, nodes = self.measure(value, ensure_ascii=ensure_ascii)
        self.charge(input_bytes=size * (1 + shallow_copies),
                    json_nodes=nodes * (1 + shallow_copies))
        return size, nodes

    def prepare_copy(self, value: Any) -> None:
        """Charge measurement plus one hidden canonical-sized shallow copy."""
        size, nodes = self.measure(value)
        self.charge(input_bytes=size, json_nodes=nodes)

    def wire(self, value: Any) -> bytes:
        size, _ = self.prepare_encoding(value)
        encoded = json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
                             separators=(",", ":")).encode("ascii")
        if len(encoded) != size:
            raise QueryReadWorkError("query read measured encoding changed during serialization")
        return encoded
