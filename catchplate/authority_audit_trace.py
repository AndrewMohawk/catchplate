"""Pure, source-owned planner trace accounting for global audit capacity.

Callers admit the closed entry/mutation shapes and operation permissions first.
This accounts their exact identities, not execution, row validity, proof hashes,
an authenticated initial count, delivery, or independently current roots.
"""
from __future__ import annotations

from typing import Any, Mapping

from catchplate import authority_audit_capacity
from catchplate import authority_contract
from catchplate import authority_radix_proof
from catchplate.authority_transition_core import canonical_bytes


MAX_TRACE_ENTRIES = 4096
# Scan, row, leaf, 64 child-vector reads, write, and only a source-declared
# newly added aggregate relation's root. Shared roots stay business charged.
MAX_AUDIT_CAPACITY_TRACE_ENTRIES = 69
MAX_PLAN_TRACE_ENTRIES = MAX_TRACE_ENTRIES + MAX_AUDIT_CAPACITY_TRACE_ENTRIES


class AuditTraceError(ValueError):
    pass


def audit_capacity_scan_key() -> dict[str, str]:
    return {"globalAuditCapacityQuery": authority_audit_capacity.AGGREGATE_ID}


class AuditTraceBudget:
    """Partition exact framework entries without enlarging business allowance.

    A global proof is one contiguous leaf-plus-64-node block. A different
    aggregate key may share its prefixes; those reads remain business charged.
    No input entry, key, or mutation is retained or changed.
    """

    def __init__(self, operation: str) -> None:
        spec = authority_contract.operation_spec(operation)
        self.participates = spec["globalAuditCapacity"]
        self.adds_root = spec["auditCapacityAddsAggregateRoot"]
        self.business_entries = 0
        self.framework_entries = 0
        self._seen: set[str] = set()
        self._next_proof_node: int | None = None
        self._markers: dict[bytes, str] = {}
        self._nodes: tuple[bytes, ...] = ()
        if not self.participates:
            return
        aggregate = authority_audit_capacity.AGGREGATE_TABLE
        key = {"aggregate_id": authority_audit_capacity.AGGREGATE_ID}
        tree_key_digest = authority_radix_proof.authenticated_key_digest(aggregate, key)
        path = tree_key_digest[7:]
        self._markers = {
            self._identity("read", aggregate, audit_capacity_scan_key()): "scan",
            self._identity("read", aggregate, key): "row",
            self._identity("write", aggregate, key): "write",
            self._identity("read", "policy_authority_authenticated_leaves", {
                "tableName": aggregate, "keyDigest": tree_key_digest,
            }): "leaf",
        }
        if self.adds_root:
            self._markers[self._identity(
                "read", "policy_authority_authenticated_table_roots", {"tableName": aggregate},
            )] = "root"
        self._nodes = tuple(
            self._identity("read", "policy_authority_authenticated_tree_nodes", {
                "tableName": aggregate, "depth": depth + 1, "pathPrefix": path[:depth],
            })
            for depth in range(authority_contract.TREE_DEPTH)
        )

    @staticmethod
    def _identity(access: str, table: str, key: Mapping[str, Any] | None) -> bytes:
        return canonical_bytes({"access": access, "table": table, "key": key})

    def append(self, entry: Mapping[str, Any]) -> None:
        # A batch entry represents exactly one bounded physical node SELECT.
        # Legacy singleton keys retain their decoder and reserved counter block;
        # a declared batch profile must satisfy the same source-owned shape and
        # limits used by the actual reader, and is always business charged.
        key = entry["key"]
        if (entry["access"] == "read"
                and entry["table"] == "policy_authority_authenticated_tree_nodes"
                and isinstance(key, Mapping) and "profile" in key):
            try:
                authority_radix_proof.validate_batch_trace_key(key)
            except authority_radix_proof.RadixProofError as exc:
                raise AuditTraceError("primary radix batch trace is not closed") from exc
        identity = self._identity(entry["access"], entry["table"], entry["key"])
        if self._next_proof_node is not None:
            depth = self._next_proof_node
            if identity != self._nodes[depth]:
                raise AuditTraceError("global audit capacity trace proof is not contiguous")
            marker = f"node:{depth}"
            self._next_proof_node = (
                None if depth + 1 == authority_contract.TREE_DEPTH else depth + 1
            )
        else:
            marker = self._markers.get(identity)
            if marker == "leaf":
                self._next_proof_node = 0
        if marker is None:
            self.business_entries += 1
        else:
            if marker in self._seen:
                raise AuditTraceError("global audit capacity trace identity is duplicated")
            self._seen.add(marker)
            self.framework_entries += 1
        framework_limit = (
            MAX_AUDIT_CAPACITY_TRACE_ENTRIES - 1 + int(self.adds_root)
            if self.participates else 0
        )
        if (self.business_entries > MAX_TRACE_ENTRIES
                or self.framework_entries > framework_limit):
            raise AuditTraceError("planner trace bound was exceeded")

    def close(self, mutations: tuple[dict[str, Any], ...] | list[dict[str, Any]]) -> None:
        if not self.participates:
            return
        required = {"scan", "row", "leaf"} | {
            f"node:{depth}" for depth in range(authority_contract.TREE_DEPTH)
        }
        if self.adds_root:
            required.add("root")
        if any(
            mutation["table"] == authority_audit_capacity.AGGREGATE_TABLE
            and mutation["key"] == {"aggregate_id": authority_audit_capacity.AGGREGATE_ID}
            for mutation in mutations
        ):
            required.add("write")
        if self._next_proof_node is not None or self._seen != required:
            raise AuditTraceError("global audit capacity trace is not exact")
