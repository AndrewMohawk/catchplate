"""Own independent revocation observations and project the actual plan subset.

These ordinary data helpers do not authenticate a reader, enroll a root or
prove a population. The genuine .52 reader admits full source metadata; this
handoff checks its closed scalar/source shape and retains every commitment.
The planner must independently acquire and compare the same full 7+2+9 roots
before selecting source read roles plus profiles of its actual mutations.
Genuine proofs cover the selected reads and effects, not unused populations.
Primary metadata absent from the planner's compact vectors is not compared as
if it had been reacquired. No SQL, clock, signature or registry is used here.

Fixed source inventories and DTO/graph scaffolding are outside H/B/N. Actual
ownership uses the existing recursive CopyBudget, and equality uses the real
canonical encoders/comparison. There is no new allowance or refunded work.
"""
from __future__ import annotations

from serverware import authority_complete_query as complete
from serverware import authority_complete_query_batch as batch
from serverware import authority_contract as authority
from serverware import authority_index_contract as counted
from serverware import authority_index_heads as heads
from serverware import authority_index_projection as projection
from serverware import authority_query_reads as reads
from serverware import authority_revocation_plan as plan
from serverware import authority_revocation_plan_production as production
from serverware import authority_revocation_roots as roots


_PARTIAL_CONTEXT_FIELDS = production._CONTEXT_FIELDS - {"expectedBefore"}
_HEAD_FIELDS = ("index_id", "table_name", "counted_profile", "projection_digest",
    "projection_manifest_digest", "index_revision", "root_digest", "leaf_count")
_MUTATION_TABLES = frozenset(authority.operation_spec(complete.OPERATION)["businessWrites"])


class ObservedRevocationError(ValueError):
    pass


def _validate_partial_context(context, work):
    """Validate the genuine fourteen independent fields, without fake roots."""
    batch._SharedLedger(work)
    plan.contract._object(context, _PARTIAL_CONTEXT_FIELDS, "observed production context")
    plan._expectation_context(context)


def _digest(value):
    if type(value) is not str or len(value) != 71 or roots._DIGEST.fullmatch(value) is None:
        raise ObservedRevocationError("observed root digest is not canonical")


def _counter(value):
    if type(value) is not int or not 0 <= value <= counted.I64_MAX:
        raise ObservedRevocationError("observed root counter is not an exact int64")


def _validate_inventory(inventory):
    if type(inventory) is not roots._RootInventory:
        raise ObservedRevocationError("observed root inventory has an unexpected carrier")
    for rows, names in ((inventory.business_roots, roots._BUSINESS_TABLES),
                        (inventory.authorization_roots, roots._AUTHORIZATION_TABLES)):
        if type(rows) is not tuple or len(rows) != len(names):
            raise ObservedRevocationError("observed primary inventory is not the complete source set")
        for row, table in zip(rows, names):
            if type(row) is not roots._PrimaryObservation:
                raise ObservedRevocationError("observed primary row has an unexpected carrier")
            if (type(row.table_name) is not str or row.table_name != table
                    or type(row.tree_depth) is not int or row.tree_depth != authority.TREE_DEPTH
                    or type(row.tree_radix) is not int or row.tree_radix != authority.TREE_RADIX):
                raise ObservedRevocationError("observed primary row differs from its source schema")
            for value in (row.root_revision, row.leaf_count, row.updated_at_epoch_ns):
                _counter(value)
            _digest(row.root_digest)
            _digest(row.manifest_digest)
            if row.manifest_digest != plan._QUERY_MANIFEST_DIGEST:
                raise ObservedRevocationError("observed primary manifest differs from the global source")
    if type(inventory.counted_heads) is not tuple or len(inventory.counted_heads) != len(roots._HEAD_IDS):
        raise ObservedRevocationError("observed counted inventory is not the complete source set")
    for row, identity in zip(inventory.counted_heads, roots._HEAD_IDS):
        if type(row) is not heads.CapturedIndexHead or type(row.index_root) is not counted.CountedNode:
            raise ObservedRevocationError("observed counted row has an unexpected carrier")
        if (type(row.index_id) is not str or row.index_id != identity
                or type(row.table) is not str or row.table != projection._definition(identity).table
                or type(row.counted_profile) is not str or row.counted_profile != counted.PROFILE):
            raise ObservedRevocationError("observed counted row differs from its source profile")
        for value in (row.projection_digest, row.projection_manifest_digest, row.index_root.digest):
            _digest(value)
        _counter(row.index_revision)
        _counter(row.index_root.count)


def _inventory_graph(inventory):
    return {
        "businessRoots": [{name: getattr(row, name) for name in roots._PRIMARY_FIELDS}
                          for row in inventory.business_roots],
        "authorizationRoots": [{name: getattr(row, name) for name in roots._PRIMARY_FIELDS}
                               for row in inventory.authorization_roots],
        "countedHeads": [dict(zip(_HEAD_FIELDS, (row.index_id, row.table, row.counted_profile,
            row.projection_digest, row.projection_manifest_digest, row.index_revision,
            row.index_root.digest, row.index_root.count))) for row in inventory.counted_heads],
    }


def _capture_root_inventory(root_inventory, *, work):
    """Detach exact bounded scalar observations before any external callback."""
    batch._SharedLedger(work)
    _validate_inventory(root_inventory)
    owned = reads._CopyBudget(work).copy(_inventory_graph(root_inventory))
    result = roots._RootInventory(
        tuple(roots._PrimaryObservation(*(row[name] for name in roots._PRIMARY_FIELDS))
              for row in owned["businessRoots"]),
        tuple(roots._PrimaryObservation(*(row[name] for name in roots._PRIMARY_FIELDS))
              for row in owned["authorizationRoots"]),
        tuple(heads.CapturedIndexHead(row["index_id"], row["table_name"], row["counted_profile"],
            row["projection_digest"], row["projection_manifest_digest"], row["index_revision"],
            counted.CountedNode(row["root_digest"], row["leaf_count"])) for row in owned["countedHeads"]),
    )
    _validate_inventory(result)
    return result


def _inventory_before(root_inventory):
    """Render commitments only; this fixed graph is not a proof or capture."""
    _validate_inventory(root_inventory)
    def primary(rows):
        return [{"table": row.table_name, "rootRevision": row.root_revision,
                 "rootDigest": row.root_digest, "leafCount": row.leaf_count} for row in rows]
    return {"businessBeforeRoots": primary(root_inventory.business_roots),
        "authorizationBeforeRoots": primary(root_inventory.authorization_roots),
        "indexBeforeHeads": [{"indexId": row.index_id, "indexRevision": row.index_revision,
            "rootDigest": row.index_root.digest, "leafCount": row.index_root.count}
            for row in root_inventory.counted_heads]}


def _names(values, maximum, label):
    if (type(values) is not tuple or len(values) > maximum
            or any(type(value) is not str or not 1 <= len(value) <= 128 for value in values)):
        raise ObservedRevocationError(label)


def _project_expected_context(context, root_inventory, *, acquired_before,
        query_roles, mutated_tables, write_index_ids, work):
    """Compare the full acquisition, then project independently owned values.

    The planner extracts the scalar selection inputs from its genuine queries,
    effects and write proofs. Calling this helper with invented observations does
    not replace that acquisition. Inputs have already been owned before callbacks.
    """
    _validate_partial_context(context, work)
    full_before = _inventory_before(root_inventory)
    plan.semantics._expected_before(acquired_before)
    plan.semantics._canonical_equal(acquired_before, full_before, work=work,
        label="full acquired roots differ from independent observations")
    _names(query_roles, len(complete.ROLES), "observed query roles are not bounded source names")
    if len(query_roles) != len(complete.ROLES) or set(query_roles) != set(complete.ROLES):
        raise ObservedRevocationError("observed query roles are not the exact six-role inventory")
    _names(mutated_tables, plan.contract.MAX_MUTATIONS, "observed mutation tables are not bounded source names")
    if any(table not in _MUTATION_TABLES for table in mutated_tables):
        raise ObservedRevocationError("observed mutation table is outside the source write inventory")
    _names(write_index_ids, len(roots._HEAD_IDS), "observed write heads are not bounded source names")
    writes = {identity for table in mutated_tables for identity in projection.index_ids_for_table(table)}
    if tuple(sorted(writes)) != write_index_ids:
        raise ObservedRevocationError("observed write heads differ from all actual mutation profiles")
    selected = writes | {complete._role(complete.OPERATION, name).index_id for name in query_roles}
    before = {"businessBeforeRoots": full_before["businessBeforeRoots"],
        "authorizationBeforeRoots": full_before["authorizationBeforeRoots"],
        "indexBeforeHeads": [row for row in full_before["indexBeforeHeads"] if row["indexId"] in selected]}
    projected = reads._CopyBudget(work).copy({**context, "expectedBefore": before})
    production._validate_context(projected, work)
    return projected
