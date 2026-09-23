"""Streaming full-population observation relative to a supplied outbox root.

Distinct proved members whose number equals an independently accepted leaf
count establish completeness under collision resistance. The tree digest does
NOT authenticate that count, its revision, currentness, schema or database
identity. The caller must obtain and bind the whole descriptor independently.

This component has no database, clock, signer, writer fence, receipt issuer or
counter INSERT. Its observation is not an authorization object. It is one
prerequisite for a separately admitted offline initializer, not an initializer.
"""
from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from serverware import authority_audit_capacity as capacity
from serverware import authority_contract
from serverware import authority_radix_proof as radix
from serverware import authority_transition_core as core
from serverware.authority_primary_contract import PRIMARY_KEY_COLUMNS
from serverware.authority_radix_mutation import (
    PrimaryRadixLimits,
    PrimaryRadixMutationError,
    PrimaryRoot,
    PrimaryTableContract,
    evaluate_primary_radix_batch,
)


OBSERVATION_SCHEMA = "serverware.metadataAuditOutboxInventoryObservation/v1"
_MAX_INTEGER = 2**63 - 1
_MIN_INTEGER = -(2**63)
_TEXT_COLUMNS = frozenset({
    "id", "event_type", "actor_type", "event_json", "event_digest", "status", "created_at",
})
_NULLABLE_TEXT_COLUMNS = frozenset({
    "actor_id", "claim_id", "claimed_at", "audited_at", "audit_event_hash", "last_error",
})
_ROW_COLUMNS = _TEXT_COLUMNS | _NULLABLE_TEXT_COLUMNS | {"attempts", "storage_format_version"}
_SELECTED_COLUMNS = frozenset({"table", "key", "keyDigest", "present", "row", "contractSelector"})
_STATUSES = frozenset({"pending", "claimed", "audited"})
# One record/proof at a time; the total offline population may exceed ordinary
# selected-row limits. This is serialized input, not a peak-memory guarantee.
_RECORD_LIMITS = PrimaryRadixLimits(
    max_selected_rows=1,
    max_mutations=1,
    max_proof_vectors=authority_contract.TREE_DEPTH,
    max_proof_child_slots=authority_contract.TREE_DEPTH * authority_contract.TREE_RADIX,
    max_hashes=(authority_contract.TREE_DEPTH + 2) + (2 * authority_contract.TREE_DEPTH + 8),
    max_input_bytes=authority_contract.MAX_RESULT_BYTES,
    max_json_depth=128,
    max_json_nodes=1_000_000,
)
_TABLE_CONTRACT = PrimaryTableContract(
    table=capacity.OUTBOX_TABLE,
    key_columns=PRIMARY_KEY_COLUMNS[capacity.OUTBOX_TABLE],
    write_access=False,
    root_class="business",
)


class AuditInventoryError(ValueError):
    pass


def _root_copy(root: Any) -> PrimaryRoot:
    if type(root) is not PrimaryRoot or root.table != capacity.OUTBOX_TABLE:
        raise AuditInventoryError("audit inventory requires the exact outbox root descriptor")
    try:
        return PrimaryRoot(root.table, root.root_revision, root.root_digest, root.leaf_count)
    except PrimaryRadixMutationError as exc:
        raise AuditInventoryError("audit inventory root descriptor is invalid") from exc


@dataclass(frozen=True, slots=True)
class AuditInventoryObservation:
    """Self-consistent data only; direct construction confers no proof authority."""

    root: PrimaryRoot
    pending_count: int
    claimed_count: int
    audited_count: int

    def __post_init__(self) -> None:
        root = _root_copy(self.root)
        counts = (self.pending_count, self.claimed_count, self.audited_count)
        if (any(type(value) is not int or not 0 <= value <= _MAX_INTEGER for value in counts)
                or sum(counts) != root.leaf_count
                or self.pending_count + self.claimed_count > capacity.MAX_PENDING):
            raise AuditInventoryError("audit inventory counts are inconsistent or over capacity")
        object.__setattr__(self, "root", root)

    @property
    def outstanding_count(self) -> int:
        return self.pending_count + self.claimed_count

    def json_projection(self) -> dict[str, Any]:
        return {
            "schema": OBSERVATION_SCHEMA,
            "sourceRevision": authority_contract.SOURCE_REVISION,
            "root": self.root.json_projection(),
            "pendingCount": self.pending_count,
            "claimedCount": self.claimed_count,
            "auditedCount": self.audited_count,
            "outstandingCount": self.outstanding_count,
        }

    @property
    def digest(self) -> str:
        return core.framed_digest(OBSERVATION_SCHEMA, core.canonical_bytes(self.json_projection()))


def _owned_record(record: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    if type(record) is not dict or len(record) != 2 or set(record) != {"selectedRow", "proof"}:
        raise AuditInventoryError("audit inventory record is not closed")
    try:
        # Reject unsupported scalars, NUL, surrogates and over-bound graphs
        # before allocating a copy. Proof validation, ordering and counting all
        # use this same owned snapshot, never the caller's mutable row again.
        owned = json.loads(capacity.canonical_audit_json(record))
    except (capacity.AuditCapacityError, ValueError, RecursionError) as exc:
        raise AuditInventoryError("audit inventory record is not bounded lossless JSON") from exc
    selected, proof = owned["selectedRow"], owned["proof"]
    if (type(selected) is not dict or set(selected) != _SELECTED_COLUMNS
            or selected["table"] != capacity.OUTBOX_TABLE or selected["present"] is not True
            or selected["contractSelector"] is not None
            or type(selected["row"]) is not dict or set(selected["row"]) != _ROW_COLUMNS
            or type(proof) is not dict):
        raise AuditInventoryError("audit inventory must prove an exact present full row")
    row = selected["row"]
    if (any(type(row[name]) is not str for name in _TEXT_COLUMNS)
            or any(row[name] is not None and type(row[name]) is not str for name in _NULLABLE_TEXT_COLUMNS)
            or type(row["attempts"]) is not int or not _MIN_INTEGER <= row["attempts"] <= _MAX_INTEGER
            or (row["storage_format_version"] is not None
                and (type(row["storage_format_version"]) is not int
                     or not _MIN_INTEGER <= row["storage_format_version"] <= _MAX_INTEGER))
            or row["status"] not in _STATUSES
            or type(selected["key"]) is not dict or selected["key"] != {"id": row["id"]}):
        raise AuditInventoryError("audit inventory row differs from its SQL key/type/status profile")
    try:
        core.require_digest(row["event_digest"], "inventory event digest")
    except core.TransitionKernelError as exc:
        raise AuditInventoryError("audit inventory event digest is malformed") from exc
    # Historical text IDs, nullable storage versions and signed SQL BIGINTs
    # remain admissible. This does not impose today's fresh-event policy or
    # verify the event body, audit receipt, claim lease or delivery semantics.
    return selected, proof


def verify_audit_inventory(
    *, root: PrimaryRoot, records: Iterable[dict[str, Any]],
) -> AuditInventoryObservation:
    """Observe a complete stream, conditional on the supplied root authority.

    Records must be strictly ascending by persisted AuthenticatedKey/v1 digest,
    not textual id or BusinessKey/v1 digest. This proves uniqueness with only
    the preceding digest retained. An exact record count is necessary: root
    reconstruction alone says nothing about omitted leaves or leaf_count.

    Retained state is constant in population size; per-record wire/graph/hash
    budgets still apply. The owner of the offline job must enforce total CPU,
    byte, memory and deadline limits, including a producer that stalls between
    records. No successful prefix observation is returned on interruption.
    """
    expected = _root_copy(root)
    if isinstance(records, (str, bytes, bytearray, dict)):
        raise AuditInventoryError("audit inventory records must be a record stream")
    try:
        stream = iter(records)
    except TypeError as exc:
        raise AuditInventoryError("audit inventory records must be iterable") from exc
    counts = {status: 0 for status in _STATUSES}
    count = 0
    previous_key = ""
    for record in stream:
        # Fetch one beyond the advertised total to detect an extra record,
        # but do not copy, hash or admit it. Do not silently accept a prefix.
        if count >= expected.leaf_count:
            raise AuditInventoryError("audit inventory contains extra members")
        selected, proof = _owned_record(record)
        try:
            evaluation = evaluate_primary_radix_batch(
                table_contracts=(_TABLE_CONTRACT,),
                business_before_roots=(expected,), authorization_before_roots=(),
                selected_rows=(selected,), before_proofs=(proof,), mutations=(),
                limits=_RECORD_LIMITS,
            )
            tree_key = radix.authenticated_key_digest(capacity.OUTBOX_TABLE, selected["key"])
        except (PrimaryRadixMutationError, radix.RadixProofError, core.TransitionKernelError) as exc:
            raise AuditInventoryError("audit inventory membership proof is invalid") from exc
        if evaluation.business_after_roots != (expected,) or evaluation.authorization_after_roots:
            raise AuditInventoryError("audit inventory read-only proof changed its root")
        if tree_key <= previous_key:
            raise AuditInventoryError("audit inventory keys are duplicated or not in tree order")
        previous_key = tree_key
        counts[selected["row"]["status"]] += 1
        count += 1
        if counts["pending"] + counts["claimed"] > capacity.MAX_PENDING:
            raise AuditInventoryError("audit inventory outstanding population exceeds capacity")
    if count != expected.leaf_count:
        raise AuditInventoryError("audit inventory omits members from its supplied descriptor")
    return AuditInventoryObservation(expected, counts["pending"], counts["claimed"], counts["audited"])
