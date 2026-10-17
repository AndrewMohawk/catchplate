"""Deterministic offline preparation, never audit-counter installation authority.

Reverify a complete outbox stream and exact aggregate-key nonmembership, then
calculate the compact initial row and its prospective primary-root transition.
No database, clock, signer, writer exclusion, runtime template or receipt is
provided here. Accepted current roots/generation/schema, aggregate cardinality,
one-use initialization ancestry and an atomic installer remain prerequisites.
"""
from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from catchplate import authority_audit_capacity as capacity
from catchplate import authority_contract
from catchplate import authority_transition_core as core
from catchplate.authority_audit_inventory import AuditInventoryError, verify_audit_inventory
from catchplate.authority_primary_contract import PRIMARY_KEY_COLUMNS
from catchplate.authority_radix_mutation import (
    PrimaryRadixLimits,
    PrimaryRadixMutationError,
    PrimaryRoot,
    PrimaryTableContract,
    evaluate_primary_radix_batch,
)


SCHEMA = "catchplate.metadataAuditCapacityInitializationPreparation/v1"
PROFILE = "catchplate.metadataAuditCapacityInitializationProfile/v1"
# This is a mathematical evaluator label, NOT an admitted runtime template.
INSERT_TEMPLATE = "catchplate.metadataAuditCapacityInitializationInsert/v1"
INITIAL_ROW_DOMAIN = "catchplate.metadataAuditCapacityInitialRow/v1"
_DOCUMENT_FIELDS = frozenset({
    "schema", "profile", "sourceRevision", "initializationPolicy",
    "initializedAtEpochNs", "inventory", "inventoryDigest", "tableContracts",
    "beforeRoots", "afterRoots", "aggregateAbsence", "counterRow",
    "counterRowDigest", "prospectiveMutation", "radixMetrics", "installationPermitted",
})
_SELECTED_FIELDS = frozenset({
    "table", "key", "keyDigest", "present", "row", "contractSelector",
})
_LIMITS = PrimaryRadixLimits(
    max_selected_rows=1, max_mutations=1,
    max_proof_vectors=authority_contract.TREE_DEPTH,
    max_proof_child_slots=authority_contract.TREE_DEPTH * authority_contract.TREE_RADIX,
    max_hashes=(authority_contract.TREE_DEPTH + 2) + (2 * authority_contract.TREE_DEPTH + 8),
    max_input_bytes=authority_contract.MAX_RESULT_BYTES,
    max_json_depth=128, max_json_nodes=1_000_000,
)
_TABLE_CONTRACTS = tuple(sorted((
    PrimaryTableContract(capacity.OUTBOX_TABLE, PRIMARY_KEY_COLUMNS[capacity.OUTBOX_TABLE], False, "business"),
    PrimaryTableContract(capacity.AGGREGATE_TABLE, PRIMARY_KEY_COLUMNS[capacity.AGGREGATE_TABLE], True, "business"),
), key=lambda contract: contract.table))


class AuditCapacityInitializationError(ValueError):
    pass


def _policy() -> dict[str, Any]:
    return {
        "initialCounterRevision": 1,
        "initialNextSequence": 0,
        "sequenceBasis": "fresh-pending-inserts-after-initialization",
        "timestampBasis": "explicit-input-not-time-authority",
    }


def _canonical(value: Any) -> bytes:
    try:
        return capacity.canonical_audit_json(value)
    except (capacity.AuditCapacityError, ValueError, RecursionError) as exc:
        raise AuditCapacityInitializationError("audit initialization input is not bounded lossless JSON") from exc


def _time(value: Any) -> None:
    if type(value) is not int or not 0 <= value <= capacity.MAX_INTEGER:
        raise AuditCapacityInitializationError("audit initialization time is not an exact nonnegative int64")


@dataclass(frozen=True, slots=True)
class AuditCapacityInitializationPreparation:
    """Immutable serialization, not a verification token or installation permit.

    Direct construction checks only the bounded canonical outer envelope. It
    does not reverify nested proofs or relationships. A consumer needing that
    computation must call prepare_audit_capacity_initialization on the actual
    proof stream; it must never accept this object's type as authority.
    """

    _document: bytes

    def __post_init__(self) -> None:
        if (type(self._document) is not bytes
                or not 1 <= len(self._document) <= authority_contract.MAX_RESULT_BYTES):
            raise AuditCapacityInitializationError("audit initialization document is not bounded bytes")
        try:
            document = json.loads(self._document)
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise AuditCapacityInitializationError("audit initialization document is not JSON") from exc
        if (type(document) is not dict or set(document) != _DOCUMENT_FIELDS
                or document["schema"] != SCHEMA or document["profile"] != PROFILE
                or document["sourceRevision"] != authority_contract.SOURCE_REVISION
                or document["installationPermitted"] is not False
                or _canonical(document["initializationPolicy"]) != _canonical(_policy())
                or _canonical(document) != self._document):
            raise AuditCapacityInitializationError("audit initialization document envelope changed")
        _time(document["initializedAtEpochNs"])

    @property
    def canonical_bytes(self) -> bytes:
        return self._document

    def json_projection(self) -> dict[str, Any]:
        return json.loads(self._document)

    @property
    def digest(self) -> str:
        return core.framed_digest(SCHEMA, self._document)


def _root(root: Any, table: str) -> PrimaryRoot:
    if type(root) is not PrimaryRoot or root.table != table:
        raise AuditCapacityInitializationError("audit initialization root has the wrong table or type")
    try:
        return PrimaryRoot(root.table, root.root_revision, root.root_digest, root.leaf_count)
    except PrimaryRadixMutationError as exc:
        raise AuditCapacityInitializationError("audit initialization root descriptor is invalid") from exc


def _absence(record: Any) -> dict[str, Any]:
    if type(record) is not dict or set(record) != {"selectedRow", "proof"}:
        raise AuditCapacityInitializationError("audit initialization absence record is not closed")
    owned = json.loads(_canonical(record))
    selected, proof = owned["selectedRow"], owned["proof"]
    key = {"aggregate_id": capacity.AGGREGATE_ID}
    if (type(selected) is not dict or set(selected) != _SELECTED_FIELDS
            or selected["table"] != capacity.AGGREGATE_TABLE
            or type(selected["key"]) is not dict or selected["key"] != key
            or selected["present"] is not False or selected["row"] is not None
            or selected["contractSelector"] is not None or type(proof) is not dict
            or selected["keyDigest"] != core.framed_digest(
                "catchplate.policyAuthorityBusinessKey/v1",
                capacity.AGGREGATE_TABLE.encode("ascii"), _canonical(key))):
        raise AuditCapacityInitializationError("audit initialization requires exact global-key absence")
    return owned


def _initial_row(outstanding: int, timestamp: int) -> dict[str, Any]:
    # outstanding comes only from the internally verified complete inventory.
    # Retained terminal history is not lifetime insertion history. Start the
    # NEW counter's post-initialization insertion sequence at zero, not a guess
    # derived from old counters, the live count or an unrelated tree revision.
    row = {
        "aggregate_id": capacity.AGGREGATE_ID,
        "aggregate_kind": capacity.AGGREGATE_KIND,
        "partition_digest": capacity.PARTITION_DIGEST,
        "revision": 1, "live_count": outstanding, "active_count": outstanding,
        "capacity_limit": capacity.MAX_PENDING,
        "reserved_units_json": "{}", "committed_units_json": "{}",
        "next_sequence": 0, "minimum_expiry_epoch_ns": None,
        "expiry_index_root_digest": capacity.EMPTY_EXPIRY_DIGEST,
        "work_page_id": None, "updated_at_epoch_ns": timestamp,
        "source_revision": authority_contract.SOURCE_REVISION,
    }
    state = _canonical(capacity._state(row))
    row.update(state_json=state.decode("ascii"), state_digest=core.framed_digest(capacity.STATE_DOMAIN, state))
    if len(_canonical(row)) > capacity.MAX_COUNTER_BYTES:
        raise AuditCapacityInitializationError("audit initialization counter row exceeds its bound")
    return row


def prepare_audit_capacity_initialization(
    *, outbox_root: PrimaryRoot, outbox_records: Iterable[dict[str, Any]],
    aggregate_root: PrimaryRoot, aggregate_absence: dict[str, Any],
    initialized_at_epoch_ns: int,
) -> AuditCapacityInitializationPreparation:
    """Prepare exact bytes/root arithmetic relative to supplied descriptors.

    Full outbox reconstruction derives its count. One aggregate absence proof
    cannot derive aggregate cardinality: its before count/revision and their
    +1 successors remain conditional on independent descriptor acceptance.
    Even correct current absence cannot authorize resetting a deleted counter.
    The explicit timestamp is bound as data, not independently trusted time.
    """
    _time(initialized_at_epoch_ns)
    outbox_before = _root(outbox_root, capacity.OUTBOX_TABLE)
    aggregate_before = _root(aggregate_root, capacity.AGGREGATE_TABLE)
    if (aggregate_before.root_revision == capacity.MAX_INTEGER
            or aggregate_before.leaf_count == capacity.MAX_INTEGER):
        raise AuditCapacityInitializationError("audit initialization aggregate successor would overflow")
    # Own this snapshot BEFORE invoking a caller's potentially reusable stream.
    # No later read of caller-owned absence data may enter the calculation.
    absence = _absence(aggregate_absence)
    try:
        inventory = verify_audit_inventory(root=outbox_before, records=outbox_records)
    except AuditInventoryError as exc:
        raise AuditCapacityInitializationError("audit initialization outbox inventory is invalid") from exc
    row = _initial_row(inventory.outstanding_count, initialized_at_epoch_ns)
    selected = absence["selectedRow"]
    mutation = {
        "templateId": INSERT_TEMPLATE, "operation": "INSERT",
        "table": capacity.AGGREGATE_TABLE, "key": dict(selected["key"]),
        "keyDigest": selected["keyDigest"], "expectedRow": None, "row": row,
    }
    before_roots = tuple(sorted((outbox_before, aggregate_before), key=lambda root: root.table))
    try:
        evaluation = evaluate_primary_radix_batch(
            table_contracts=_TABLE_CONTRACTS,
            business_before_roots=before_roots, authorization_before_roots=(),
            selected_rows=(selected,), before_proofs=(absence["proof"],),
            mutations=(mutation,), limits=_LIMITS,
        )
    except PrimaryRadixMutationError as exc:
        raise AuditCapacityInitializationError("audit initialization absence or insertion proof is invalid") from exc
    after_roots = evaluation.business_after_roots
    if (evaluation.authorization_after_roots
            or len(after_roots) != 2
            or next((root for root in after_roots if root.table == capacity.OUTBOX_TABLE), None) != outbox_before):
        raise AuditCapacityInitializationError("audit initialization changed the outbox root closure")
    document = {
        "schema": SCHEMA, "profile": PROFILE,
        "sourceRevision": authority_contract.SOURCE_REVISION,
        "initializationPolicy": _policy(),
        "initializedAtEpochNs": initialized_at_epoch_ns,
        "inventory": inventory.json_projection(), "inventoryDigest": inventory.digest,
        "tableContracts": [contract.json_projection() for contract in _TABLE_CONTRACTS],
        "beforeRoots": [root.json_projection() for root in before_roots],
        "afterRoots": [root.json_projection() for root in after_roots],
        "aggregateAbsence": absence, "counterRow": row,
        # Unlike state_digest, this commitment includes time/source revision.
        "counterRowDigest": core.framed_digest(INITIAL_ROW_DOMAIN, _canonical(row)),
        "prospectiveMutation": mutation, "radixMetrics": evaluation.metrics.json_projection(),
        "installationPermitted": False,
    }
    return AuditCapacityInitializationPreparation(_canonical(document))
