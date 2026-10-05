"""Genuine relative recovery terminal writes, not maintenance closure.

One original ceremony plus its challenge, or one original revocation, is
replayed against the complete source primary vector. The actual terminal
worker derives OLD/NEW effects and inline references; the actual primary
engine then computes their roots/nodes. All nine potential challenge profiles
receive source-derived leaf changes, including empty changes for untouched
profiles. No supplied mutation, overlay, leaf change or success DTO is input.

The enclosing owner must still acquire/authenticate the complete expiry range
or all four sequential prune ranges/ranks, rebase later raw proofs against
actual preceding roots, enforce uniqueness/order/cardinality, and fold every
current counted root. In particular overflow rank is after that table's old
deletions. These outputs do not establish any of those obligations, current
root authority, signing, SQL, witness custody or registry availability.
"""
from __future__ import annotations

from dataclasses import dataclass, replace

from serverware import authority_complete_query_batch as batch
from serverware import authority_complete_read_write as read_write
from serverware import authority_index_heads as heads
from serverware import authority_index_projection as projection
from serverware import authority_indexed_mutation as indexed
from serverware import authority_recovery_terminal as terminal
from serverware.authority_index_mutation import IndexLeafChange
from serverware.authority_query_read_work import _ValidationWork


core, primary, contract = terminal.core, terminal.primary, terminal.contract
OPERATIONS = (terminal.recovery.EXPIRE, terminal.recovery.PRUNE)
MAX_SELECTED_ROWS = 2
MAX_MUTATIONS = 2


class RecoveryTerminalTransitionError(core.TransitionKernelError):
    pass


@dataclass(frozen=True, slots=True)
class _IndexChanges:
    index_id: str
    changes: tuple[IndexLeafChange, ...]
    revision_delta: int


@dataclass(frozen=True, slots=True)
class _RowComputation:
    """Private invocation output; never accepted instead of raw originals."""

    phase: str
    mutations: tuple[dict, ...]
    business_before_roots: tuple[primary.PrimaryRoot, ...]
    authorization_before_roots: tuple[primary.PrimaryRoot, ...]
    business_after_roots: tuple[primary.PrimaryRoot, ...]
    authorization_after_roots: tuple[primary.PrimaryRoot, ...]
    primary_nodes: dict
    index_changes: tuple[_IndexChanges, ...]


def _require(value):
    if not value:
        raise RecoveryTerminalTransitionError("recovery terminal transition differs from its source originals")


def _reserve_primary(selected, proofs, mutations, work):
    """Prepay hidden raw-engine copies/encodings, in addition to its metrics.

    The primary metric counts one canonical aggregate, not every internal
    normalization, scalar encoding, proof framing, row/CAS encoding and branch
    hash material. This is the exact-primary reader's S/P reservation extended
    by six measured mutation graphs and fixed depth scaffolding for two paths.
    There is no refund, new work object or reset. Large supported individual
    rows may exhaust this combined relative stage; no whole-family capacity
    or complete-population parity is claimed by this bounded component.
    """
    size, nodes = work.measure(selected)
    proof_size, proof_nodes = work.measure(proofs)
    mutation_size, mutation_nodes = work.measure(mutations)
    work.charge(input_bytes=6 * size + 7 * proof_size + 6 * mutation_size + 4 * 1024 * 1024,
        json_nodes=2 * (nodes + proof_nodes + mutation_nodes) + 32768)


def _projection_work(identity, row, work):
    # The genuine primary engine already owns the full OLD/NEW rows. Only
    # declared source scalars are copied/projected, never nine full payloads.
    definition = projection._definition(identity)
    work.charge(input_bytes=4096, json_nodes=128)
    referenced = {name: row[name] for name, _kind in definition.row_fields}
    work.prepare_copy(referenced)
    for value in referenced.values():
        if type(value) is str:
            work.prepare_utf8(value)
    work.prepare_encoding(definition.document(), ensure_ascii=False)
    partition = {name: referenced[name] for name in definition.partition_fields if name in referenced}
    work.prepare_encoding(partition, ensure_ascii=False)


def evaluate_row(*, phase, context, business_before_roots, authorization_before_roots,
        before_proofs, terminal_retention_seconds, maximum_retained, work):
    """Derive and replay one relative expire/prune write on the original work."""
    _require(type(work) is _ValidationWork and type(context) is core.KernelContext
        and type(context.operation) is str and context.operation in OPERATIONS
        and type(phase) is str and type(context.selected_rows) is tuple
        and 1 <= len(context.selected_rows) <= MAX_SELECTED_ROWS
        and type(before_proofs) is tuple and len(before_proofs) == len(context.selected_rows)
        and type(business_before_roots) is tuple and type(authorization_before_roots) is tuple
        and len(business_before_roots) + len(authorization_before_roots) <= 3
        and all(type(root) is primary.PrimaryRoot
            for root in (*business_before_roots, *authorization_before_roots)))
    # Fixed metadata covers source inventories, returned containers and at most
    # two 65-node overlay paths. Body-dependent work is accounted separately.
    work.charge(input_bytes=64 * 1024, json_nodes=4096)
    work.charge(hashes=(contract.TREE_DEPTH + 1)
        * (len(business_before_roots) + len(authorization_before_roots)))
    business = tuple(primary.PrimaryRoot(root.table, root.root_revision, root.root_digest, root.leaf_count)
        for root in business_before_roots)
    authorization = tuple(primary.PrimaryRoot(root.table, root.root_revision, root.root_digest, root.leaf_count)
        for root in authorization_before_roots)
    _reserve_primary(context.selected_rows, before_proofs, (), work)
    effects = terminal.evaluate_row(phase=phase, context=context,
        business_before_roots=business, authorization_before_roots=authorization,
        before_proofs=before_proofs, terminal_retention_seconds=terminal_retention_seconds,
        maximum_retained=maximum_retained, work=work)
    _require(effects.affected is True and 1 <= len(effects.mutations) <= MAX_MUTATIONS)
    source = terminal.contracts.primary_table_contracts(context.operation)
    _reserve_primary(context.selected_rows, before_proofs, effects.mutations, work)
    limits = read_write._write_limits(contract.operation_spec(context.operation), batch._SharedLedger(work))
    limits = replace(limits, primary=replace(limits.primary,
        max_selected_rows=MAX_SELECTED_ROWS, max_mutations=MAX_MUTATIONS,
        max_proof_vectors=MAX_SELECTED_ROWS * contract.TREE_DEPTH,
        max_proof_child_slots=MAX_SELECTED_ROWS * contract.TREE_DEPTH * contract.TREE_RADIX,
        max_hashes=min(limits.primary.max_hashes, 66 + 136 * MAX_SELECTED_ROWS)))
    budget = indexed._Budget(limits, work)
    nodes = {}
    verified = indexed._verify_primary(table_contracts=source,
        business_before_roots=business, authorization_before_roots=authorization,
        selected_rows=context.selected_rows, before_proofs=before_proofs, mutations=effects.mutations,
        budget=budget, captured_nodes=nodes)
    _require(len(verified.mutations) == len(effects.mutations))
    identities = heads._recovery_write_ids(context.operation)
    _require(identities == projection.index_ids_for_table(terminal.retention.CHALLENGE_TABLE)
        and len(identities) == 9)
    affected_ids = tuple(sorted({identity for mutation in verified.mutations
        for identity in projection.index_ids_for_table(mutation["table"])}))
    _require(affected_ids in ((), identities))
    for mutation in verified.mutations:
        if mutation["table"] == terminal.retention.CHALLENGE_TABLE and mutation["row"] is not None:
            size, count = work.prepare_encoding(mutation["row"], ensure_ascii=False)
            work.charge(input_bytes=size, json_nodes=count)
            work.charge(input_bytes=24 + len("serverware.policyAuthorityAuthenticatedRow/v1")
                + len(terminal.retention.CHALLENGE_TABLE) + size)
    prepared = indexed._prepare_owned_primary_changes(mutations=verified.mutations,
        before_proofs=verified.before_proofs, business_after_roots=verified.result.business_after_roots,
        index_ids=affected_ids, budget=budget)
    challenge_mutations = prepared.by_table.get(terminal.retention.CHALLENGE_TABLE, ())
    _require(len(challenge_mutations) <= 1)
    changes = []
    for identity in identities:
        for mutation in challenge_mutations:
            for image in (mutation["expectedRow"], mutation["row"]):
                if image is not None:
                    _projection_work(identity, image, work)
        leaves, delta, _allowance = indexed._changes_for_index(identity, challenge_mutations,
            prepared.old_digests, prepared.new_digests, budget)
        changes.append(_IndexChanges(identity, leaves, delta))
    result = verified.result
    return _RowComputation(phase, verified.mutations, business,
        authorization, result.business_after_roots,
        result.authorization_after_roots, nodes, tuple(changes))
