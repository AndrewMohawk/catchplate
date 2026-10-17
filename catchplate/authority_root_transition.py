"""Closed, bounded primary-root transition wire profile and recomputation.

Before heads are supplied evidence, not an independent currentness authority.
Physical key columns and per-operation dependency classes come from measured
source, never a key shape inferred from a selected row or mutable DB metadata.
The separate work profile below does not replace transition workUnits limits.
"""
from __future__ import annotations

from typing import Any

from catchplate import authority_audit_capacity, authority_contract
from catchplate import authority_challenge_retention
from catchplate.authority_radix_mutation import (
    PrimaryRadixLimits,
    PrimaryRadixMembershipResult,
    PrimaryRadixMutationError,
    PrimaryRoot,
    evaluate_primary_radix_batch,
    evaluate_primary_radix_memberships,
)
from catchplate.authority_transition_core import canonical_bytes, framed_digest


TRANSITION_SCHEMA = "catchplate.policyAuthorityPrimaryRootTransition/v1"
TRANSITION_PROFILE = "catchplate.policyAuthorityPrimaryRootTransitionProfile/v2"
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


def primary_plan_input_metric_bounds(operation: str) -> dict[str, int]:
    """Source-owned bounds for the additional pre-kernel verification phase.

    These are not persisted root-transition metrics or kernel workUnits. Root
    descriptor construction can consult the cold empty ladder before entering
    the engine, so it receives its own conservative allowance. The membership
    engine retains its separate cold allowance and charges every full proof.
    Empty-mutation capacity admission hashes each selected BusinessKey and, for
    a participating operation, the compact counter state. Module import work,
    SQL proof production and later delta/payload verification are separate.
    """
    spec = authority_contract.operation_spec(operation)
    depth = authority_contract.TREE_DEPTH
    selected = spec["maximumQueryRows"]
    root_allowance = depth + 2
    membership_hashes = depth + 2 + selected * (depth + 6)
    audit_hashes = selected + int(spec["globalAuditCapacity"])
    shared = metric_bounds()
    return {
        "selectedRows": selected,
        "proofVectors": shared["proofVectors"],
        "proofChildSlots": shared["proofChildSlots"],
        "rootDescriptorHashAllowance": root_allowance,
        "membershipHashWork": membership_hashes,
        "auditCapacityHashAllowance": audit_hashes,
        "totalHashWork": root_allowance + membership_hashes + audit_hashes,
        "inputBytes": shared["inputBytes"],
        "jsonNodes": shared["jsonNodes"],
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
    from catchplate.authority_primary_contract import primary_table_contracts

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
                "catchplate.policyAuthorityAuthorizationRow/v1", table.encode("ascii"),
                canonical_bytes(key), b"present" if present else b"absent", canonical_bytes(row),
            ),
        })
    if tables != set(contracts):
        raise PrimaryRadixMutationError("authorization source selections do not cover declared relations")
    result.sort(key=lambda entry: (entry["table"], canonical_bytes(entry["selector"])))
    return result


def verify_primary_plan_inputs(
    *, operation: str, business_before_roots: Any, authorization_before_roots: Any,
    selected_rows: Any, before_proofs: Any,
) -> PrimaryRadixMembershipResult:
    """Reverify selected inputs before a kernel, returning the actual snapshots.

    This always invokes the real membership engine, with source table contracts
    and no mutations; no caller-created result or alternate limits are accepted.
    The returned nested dictionaries are owned but mutable, not authority tokens.
    The caller must use these rows/proofs, then independently recompute the final
    mutation delta. This phase does not authenticate earlier deferred SQL
    predicates, predicate completeness, or independently current before roots.

    The engine's input-byte metric covers its one canonical snapshot. Capacity
    admission separately enforces the original business 4 MiB selected envelope
    plus the exact framework allowance; its bounded canonical passes are not
    additional proof input or a claim of a whole-process allocation ceiling.
    """
    from catchplate.authority_primary_contract import primary_table_contracts

    spec = authority_contract.operation_spec(operation)
    bounds = primary_plan_input_metric_bounds(operation)
    for inventory in (business_before_roots, authorization_before_roots,
                      selected_rows, before_proofs):
        if type(inventory) not in (list, tuple):
            raise PrimaryRadixMutationError("primary plan input inventory is not an array")
    if (len(business_before_roots) + len(authorization_before_roots) > authority_contract.MAX_QUERY_PROOFS
            or len(selected_rows) > bounds["selectedRows"]
            or len(before_proofs) != len(selected_rows)):
        raise PrimaryRadixMutationError("primary plan input inventory exceeds operation bounds")

    # Reserve before constructors can consult empty_digest. The genuine engine
    # enforces its own hash allowance before reconstruction; do not discount it
    # merely because these constructors may have warmed the same empty ladder.
    charged_hashes = bounds["rootDescriptorHashAllowance"]
    business = _roots(list(business_before_roots))
    authorization = _roots(list(authorization_before_roots))
    memberships = evaluate_primary_radix_memberships(
        table_contracts=primary_table_contracts(operation),
        business_before_roots=business, authorization_before_roots=authorization,
        selected_rows=tuple(selected_rows), before_proofs=tuple(before_proofs),
        limits=PrimaryRadixLimits(
            max_selected_rows=spec["maximumQueryRows"], max_mutations=spec["maximumMutations"],
            max_proof_vectors=bounds["proofVectors"], max_proof_child_slots=bounds["proofChildSlots"],
            max_hashes=bounds["membershipHashWork"], max_input_bytes=bounds["inputBytes"],
            max_json_depth=128, max_json_nodes=bounds["jsonNodes"],
        ),
    )
    if (memberships.result.business_after_roots != business
            or memberships.result.authorization_after_roots != authorization
            or memberships.result.metrics.mutations != 0
            or memberships.result.metrics.recomputed_ancestors != 0):
        raise PrimaryRadixMutationError("primary plan membership verification changed before roots")
    charged_hashes += memberships.result.metrics.hash_work
    # Reserve actual source-capacity validation work before calling it. This
    # reuses the owned engine rows and creates neither a counter mutation nor a
    # baseline when the required global counter is missing.
    charged_hashes += len(memberships.selected_rows) + int(spec["globalAuditCapacity"])
    if charged_hashes > bounds["totalHashWork"]:
        raise PrimaryRadixMutationError("primary plan input hash budget exceeded")
    try:
        authority_audit_capacity.validate_capacity_transition(
            operation=operation, selected_rows=memberships.selected_rows, mutations=(),
        )
    except (authority_audit_capacity.AuditCapacityError, ValueError) as exc:
        raise PrimaryRadixMutationError("primary plan audit capacity inputs changed") from exc
    return memberships


def derive_primary_root_transition(
    *, operation: str, business_before_roots: Any, authorization_before_roots: Any,
    selected_rows: Any, before_proofs: Any, mutations: Any,
) -> dict[str, Any]:
    from catchplate.authority_primary_contract import primary_table_contracts

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
    authority_challenge_retention.validate_inline_delta(
        operation=operation, selected_rows=selected_rows, mutations=mutations,
    )
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
