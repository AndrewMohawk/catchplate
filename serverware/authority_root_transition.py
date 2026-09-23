"""Closed, bounded primary-root transition wire profile and recomputation.

Before heads are supplied evidence, not an independent currentness authority.
Physical key columns and per-operation dependency classes come from measured
source, never a key shape inferred from a selected row or mutable DB metadata.
The separate work profile below does not replace transition workUnits limits.
"""
from __future__ import annotations

from typing import Any

from serverware import authority_contract
from serverware.authority_radix_mutation import (
    PrimaryRadixLimits,
    PrimaryRadixMutationError,
    PrimaryRoot,
    evaluate_primary_radix_batch,
)
from serverware.authority_transition_core import canonical_bytes, framed_digest


TRANSITION_SCHEMA = "serverware.policyAuthorityPrimaryRootTransition/v1"
TRANSITION_PROFILE = "serverware.policyAuthorityPrimaryRootTransitionProfile/v2"
TRANSITION_FIELDS = frozenset({
    "schema", "profile", "businessBeforeRoots", "authorizationBeforeRoots",
    "businessAfterRoots", "authorizationAfterRoots", "metrics",
})
ROOT_FIELDS = frozenset({"table", "rootRevision", "rootDigest", "leafCount"})


def metric_bounds() -> dict[str, int]:
    """Return a fresh source-owned profile, shared with the SQL renderer."""
    depth = authority_contract.TREE_DEPTH
    proofs = authority_contract.MAX_PLAN_QUERY_ROWS
    return {
        "selectedRows": proofs,
        "mutations": authority_contract.MAX_PLAN_MUTATIONS,
        "proofVectors": proofs * depth,
        "proofChildSlots": proofs * depth * authority_contract.TREE_RADIX,
        "recomputedAncestors": authority_contract.MAX_PLAN_MUTATIONS * depth,
        "hashWork": depth + 2 + proofs * (2 * depth + 8),
        "inputBytes": authority_contract.MAX_RESULT_BYTES,
        "jsonNodes": 1_000_000,
    }


def _roots(value: Any) -> tuple[PrimaryRoot, ...]:
    if type(value) is not list or len(value) > authority_contract.MAX_QUERY_PROOFS:
        raise PrimaryRadixMutationError("primary root vector is not a bounded array")
    roots = []
    previous = ""
    for entry in value:
        if type(entry) is not dict or set(entry) != ROOT_FIELDS:
            raise PrimaryRadixMutationError("primary root descriptor is not closed")
        root = PrimaryRoot(entry["table"], entry["rootRevision"],
                           entry["rootDigest"], entry["leafCount"])
        if root.table <= previous:
            raise PrimaryRadixMutationError("primary root vector is not sorted and unique")
        previous = root.table
        roots.append(root)
    return tuple(roots)


def validate_primary_root_transition(value: Any) -> dict[str, Any]:
    """Validate the wire profile only; callers must ALSO recompute the delta."""
    if (type(value) is not dict or set(value) != TRANSITION_FIELDS
            or type(value["schema"]) is not str or value["schema"] != TRANSITION_SCHEMA
            or type(value["profile"]) is not str or value["profile"] != TRANSITION_PROFILE):
        raise PrimaryRadixMutationError("primary root transition profile is not closed")
    vectors = {field: _roots(value[field]) for field in (
        "businessBeforeRoots", "authorizationBeforeRoots",
        "businessAfterRoots", "authorizationAfterRoots",
    )}
    business = vectors["businessBeforeRoots"]
    authorization = vectors["authorizationBeforeRoots"]
    if (not business or len(business) + len(authorization) > authority_contract.MAX_QUERY_PROOFS
            or {root.table for root in business} & {root.table for root in authorization}):
        raise PrimaryRadixMutationError("primary root classes overlap or exceed inventory bounds")
    for before_name, after_name in (("businessBeforeRoots", "businessAfterRoots"),
                                    ("authorizationBeforeRoots", "authorizationAfterRoots")):
        before, after = vectors[before_name], vectors[after_name]
        if tuple(root.table for root in before) != tuple(root.table for root in after):
            raise PrimaryRadixMutationError("primary root transition changed table inventory")
        if any(new.root_revision < old.root_revision for old, new in zip(before, after)):
            raise PrimaryRadixMutationError("primary root transition rolled revision backward")
    if authorization != vectors["authorizationAfterRoots"]:
        raise PrimaryRadixMutationError("primary root transition changed read-only authorization roots")
    metrics = value["metrics"]
    bounds = metric_bounds()
    if (type(metrics) is not dict or set(metrics) != set(bounds)
            or any(type(metrics[name]) is not int or not 0 <= metrics[name] <= bound
                   for name, bound in bounds.items())):
        raise PrimaryRadixMutationError("primary root transition metrics are not bounded integers")
    depth = authority_contract.TREE_DEPTH
    if (metrics["mutations"] > metrics["selectedRows"]
            or metrics["proofVectors"] != metrics["selectedRows"] * depth
            or metrics["proofChildSlots"] != metrics["proofVectors"] * authority_contract.TREE_RADIX
            or metrics["recomputedAncestors"] > metrics["mutations"] * depth
            or metrics["hashWork"] < depth + 2
            or metrics["inputBytes"] < 1 or metrics["jsonNodes"] < 1):
        raise PrimaryRadixMutationError("primary root transition metric relationships changed")
    return {
        "schema": TRANSITION_SCHEMA, "profile": TRANSITION_PROFILE,
        **{field: [root.json_projection() for root in roots] for field, roots in vectors.items()},
        "metrics": dict(metrics),
    }


def primary_root_transition_digest(value: Any) -> str:
    return framed_digest(TRANSITION_SCHEMA, canonical_bytes(validate_primary_root_transition(value)))


def derive_authorization_sources(*, operation: str, selected_rows: Any) -> list[dict[str, Any]]:
    """Project actual proof-selected authorization rows, never table-head rows.

    This is called only alongside full proof/root recomputation. Every declared
    authorization relation needs at least one exact selection; absent query
    coverage is an error, not permission to fabricate a source selector.
    """
    from serverware.authority_primary_contract import primary_table_contracts

    contracts = {entry.table: entry for entry in primary_table_contracts(operation)
                 if entry.root_class == "authorization"}
    if type(selected_rows) not in (list, tuple) or len(selected_rows) > authority_contract.MAX_PLAN_QUERY_ROWS:
        raise PrimaryRadixMutationError("authorization source selections are not bounded")
    result = []
    seen = set()
    tables = set()
    for selected in selected_rows:
        if type(selected) is not dict or type(selected.get("table")) is not str:
            raise PrimaryRadixMutationError("authorization source selection is invalid")
        table = selected["table"]
        if table not in contracts:
            continue
        key, row, present = selected.get("key"), selected.get("row"), selected.get("present")
        if (type(key) is not dict or set(key) != set(contracts[table].key_columns)
                or type(present) is not bool or (present and type(row) is not dict)
                or (not present and row is not None)):
            raise PrimaryRadixMutationError("authorization source key or presence is not exact")
        address = (table, canonical_bytes(key))
        if address in seen or len(result) >= 64:
            raise PrimaryRadixMutationError("authorization source identity is duplicated or exceeds store bound")
        seen.add(address)
        tables.add(table)
        result.append({
            "table": table, "selector": dict(key), "present": present, "row": row,
            "rowDigest": framed_digest(
                "serverware.policyAuthorityAuthorizationRow/v1", table.encode("ascii"),
                canonical_bytes(key), b"present" if present else b"absent", canonical_bytes(row),
            ),
        })
    if tables != set(contracts):
        raise PrimaryRadixMutationError("authorization source selections do not cover declared relations")
    result.sort(key=lambda entry: (entry["table"], canonical_bytes(entry["selector"])))
    return result


def derive_primary_root_transition(
    *, operation: str, business_before_roots: Any, authorization_before_roots: Any,
    selected_rows: Any, before_proofs: Any, mutations: Any,
) -> dict[str, Any]:
    from serverware.authority_primary_contract import primary_table_contracts

    spec = authority_contract.operation_spec(operation)
    bounds = metric_bounds()
    for inventory in (business_before_roots, authorization_before_roots,
                      selected_rows, before_proofs, mutations):
        if type(inventory) not in (list, tuple):
            raise PrimaryRadixMutationError("primary root transition inventory is not an array")
    # Reject before copying potentially oversized caller inventories.
    if (len(business_before_roots) + len(authorization_before_roots) > authority_contract.MAX_QUERY_PROOFS
            or len(selected_rows) > spec["maximumQueryRows"]
            or len(before_proofs) != len(selected_rows)
            or len(mutations) > spec["maximumMutations"]):
        raise PrimaryRadixMutationError("primary root transition inventory exceeds operation bounds")
    business = _roots(list(business_before_roots))
    authorization = _roots(list(authorization_before_roots))
    result = evaluate_primary_radix_batch(
        table_contracts=primary_table_contracts(operation),
        business_before_roots=business, authorization_before_roots=authorization,
        selected_rows=tuple(selected_rows), before_proofs=tuple(before_proofs), mutations=tuple(mutations),
        limits=PrimaryRadixLimits(
            max_selected_rows=spec["maximumQueryRows"], max_mutations=spec["maximumMutations"],
            max_proof_vectors=bounds["proofVectors"], max_proof_child_slots=bounds["proofChildSlots"],
            max_hashes=bounds["hashWork"], max_input_bytes=bounds["inputBytes"],
            max_json_depth=128, max_json_nodes=bounds["jsonNodes"],
        ),
    )
    return validate_primary_root_transition({
        "schema": TRANSITION_SCHEMA, "profile": TRANSITION_PROFILE,
        "businessBeforeRoots": [root.json_projection() for root in business],
        "authorizationBeforeRoots": [root.json_projection() for root in authorization],
        **result.json_projection(),
    })


def verify_primary_root_transition(
    *, operation: str, value: Any, selected_rows: Any, before_proofs: Any, mutations: Any,
) -> dict[str, Any]:
    transition = validate_primary_root_transition(value)
    expected = derive_primary_root_transition(
        operation=operation, business_before_roots=transition["businessBeforeRoots"],
        authorization_before_roots=transition["authorizationBeforeRoots"],
        selected_rows=selected_rows, before_proofs=before_proofs, mutations=mutations,
    )
    if canonical_bytes(expected) != canonical_bytes(transition):
        raise PrimaryRadixMutationError("primary root transition differs from recomputed complete delta")
    return expected
