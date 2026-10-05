"""Raw one-phase challenge plans with genuine read and write-root replay.

This is the deterministic phase body of the separate compound successor, not
the public v3 plan or a commit capability.  No proposed mutation or successful
proof result is accepted.  Exact count/range/primary evidence determines the
legacy batch, then the actual primary/counted engines compute every NEW root.
The enclosing owner supplies the independently held request, cutoff and roots;
it must retain one SQL transaction and the original phase order/deadline.

Encoding/transport is a distinct source-owned compound stage.  This component
does not replace its supplied verifier allowance or inline all phase originals
into one oversized generic plan.  Returned observations are never proof inputs.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from serverware import authority_challenge_counts as counts
from serverware import authority_challenge_maintenance as maintenance
from serverware import authority_challenge_retention as retention
from serverware import authority_complete_query_batch as batch
from serverware import authority_complete_read_write as read_write
from serverware import authority_contract as contract
from serverware import authority_index_heads as heads
from serverware import authority_index_projection as projection
from serverware import authority_indexed_mutation as indexed
from serverware import authority_radix_mutation as primary
from serverware import authority_transition_core as core
from serverware.authority_index_contract import IndexLeaf, OpaqueSubtree
from serverware.authority_query_read_work import _ValidationWork


SCHEMA = "serverware.policyAuthorityChallengeMaintenancePhase/v1"
READ_SCHEMA = "serverware.policyAuthorityChallengeMaintenanceRead/v1"
CONTEXT_FIELDS = frozenset({
    "requestDigest", "cycle", "phase", "cutoffUs", "retentionUs", "retainedLimit",
})
FIELDS = CONTEXT_FIELDS | {
    "schema", "sourceRevision", "primaryBefore", "countedBefore", "selectedRows",
    "beforeProofs", "countEvidence", "rangeEvidence", "rankEvidence", "writeFrontiers",
}
READ_FIELDS = FIELDS - {"writeFrontiers"}


class ChallengePhasePlanError(core.TransitionKernelError):
    pass


@dataclass(frozen=True, slots=True)
class PhaseComputation:
    """Locally computed relative observations, not authorization or custody."""

    context: dict[str, Any]
    primary_before: primary.PrimaryRoot
    primary_after: primary.PrimaryRoot
    counted_before: tuple[heads.CapturedIndexHead, ...]
    counted_after: tuple[heads.CapturedIndexHead, ...]
    selected_rows: tuple[dict[str, Any], ...]
    before_proofs: tuple[dict[str, Any], ...]
    mutations: tuple[dict[str, Any], ...]
    available: int


@dataclass(frozen=True, slots=True)
class _PhaseProduction:
    computation: PhaseComputation
    overlay: _PhaseNodes | None


@dataclass(frozen=True, slots=True)
class _PhaseNodes:
    """Only nodes actually computed by the same phase's genuine engines."""

    primary_nodes: dict
    counted_nodes: dict


@dataclass(slots=True)
class _PreparedPhase:
    """Private same-owner read derivation, never a plan/authority input.

    The source compound owns distinct read and write-replay ledgers. Keeping
    this engine-derived graph private between those two fixed stages avoids
    pretending that three full 256-proof traversals fit one 1M-node allowance.
    The write stage still verifies every original primary proof itself.
    """

    context: dict[str, Any]
    primary_before: primary.PrimaryRoot
    before: tuple[heads.CapturedIndexHead, ...]
    phase: maintenance.MaintenancePhase
    writes: list[dict[str, Any]] | None
    identities: tuple[str, ...]
    consumed: bool = False
    write_position: int = 0
    series_started: bool = False
    primary_after: primary.PrimaryRoot | None = None
    after_heads: list = field(default_factory=list)
    primary_nodes: dict = field(default_factory=dict)
    counted_nodes: dict = field(default_factory=dict)


def _context(value):
    if type(value) is not dict or set(value) != CONTEXT_FIELDS:
        raise ChallengePhasePlanError("challenge phase context is not source closed")
    core.require_digest(value["requestDigest"], "challenge maintenance request")
    maintenance._integer(value["cycle"], 0, 1)
    maintenance.phase_role(value["phase"])
    maintenance._integer(value["cutoffUs"])
    maintenance._integer(value["retentionUs"], 1)
    maintenance._integer(value["retainedLimit"], 0, 1_000_000)


def _records(entries, maximum):
    if type(entries) is not list or len(entries) > maximum:
        raise ChallengePhasePlanError("challenge write frontier exceeds its source phase bound")
    result = []
    for entry in entries:
        if type(entry) is not dict:
            raise ChallengePhasePlanError("challenge write frontier is not closed data")
        if set(entry) == {"kind", "key", "primaryKeyDigest", "primaryRowDigest"} and entry["kind"] == "leaf":
            result.append(IndexLeaf(entry["key"], entry["primaryKeyDigest"], entry["primaryRowDigest"]))
        elif set(entry) == {"kind", "prefix", "digest", "count"} and entry["kind"] == "opaque":
            result.append(OpaqueSubtree(entry["prefix"], entry["digest"], entry["count"]))
        else:
            raise ChallengePhasePlanError("challenge write frontier record is not source declared")
    return tuple(result)


def _prepare(*, body: dict[str, Any], expected_context: dict[str, Any],
        expected_primary: dict[str, Any], expected_heads: tuple[heads.CapturedIndexHead, ...],
        work: _ValidationWork, separate_frontiers: bool) -> _PreparedPhase:
    """Independently recompute the exact phase from retained raw evidence.

    ``expected_*`` are supplied by the actual surrounding transaction/parent
    verifier, never taken from a received body.  This relative worker checks
    their equality, not their currentness.  The same API runs during plan
    production and independent executor replay; no declared after-root or
    mutation can bypass either real proof engine.
    """
    if type(work) is not _ValidationWork or type(separate_frontiers) is not bool:
        raise ChallengePhasePlanError("challenge phase requires the original verifier meter")
    if (type(body) is not dict or set(body) != (READ_FIELDS if separate_frontiers else FIELDS)
            or type(expected_heads) is not tuple or len(expected_heads) != 9):
        raise ChallengePhasePlanError("challenge phase body or original head inventory is not closed")
    # All graphs, including independently held comparison inputs, are owned
    # before constructors, hashers or semantic callbacks can inspect them.
    owned = batch._JSONCapture(batch._SharedLedger(work)).visit({
        "body": body, "expectedContext": expected_context, "expectedPrimary": expected_primary,
        "expectedHeads": [maintenance.head_wire(head) for head in expected_heads],
    })
    body = owned["body"]
    expected_context = owned["expectedContext"]
    _context(expected_context)
    context = {name: body[name] for name in CONTEXT_FIELDS}
    _context(context)
    work.prepare_comparison(context, expected_context)
    if (body["schema"] != (READ_SCHEMA if separate_frontiers else SCHEMA)
            or body["sourceRevision"] != contract.SOURCE_REVISION
            or context != expected_context):
        raise ChallengePhasePlanError("challenge phase differs from its original source/context")
    work.prepare_comparison(body["primaryBefore"], owned["expectedPrimary"])
    work.prepare_comparison(body["countedBefore"], owned["expectedHeads"])
    if (body["primaryBefore"] != owned["expectedPrimary"]
            or body["countedBefore"] != owned["expectedHeads"]):
        raise ChallengePhasePlanError("challenge phase changed the original primary/counted roots")
    work.charge(hashes=contract.TREE_DEPTH + 1)
    primary_before = maintenance._root(body["primaryBefore"])
    identities = heads.required_index_ids(maintenance.OPERATION, include_write_heads=True)
    raw_heads = body["countedBefore"]
    if (type(raw_heads) is not list or len(raw_heads) != len(identities)
            or any(type(item) is not dict for item in raw_heads)
            or tuple(item.get("indexId") for item in raw_heads) != identities):
        raise ChallengePhasePlanError("challenge phase does not bind every fixed challenge index")
    captured = []
    for item in raw_heads:
        work.charge(hashes=projection.PROFILE_HASH_WORK)
        profile = projection.profile_for(item["indexId"])
        captured.append(maintenance._head(item, profile, primary_before, work))
    before = tuple(captured)
    head_map = {head.index_id: head for head in before}
    role = maintenance.phase_role(context["phase"])
    profile, _interval = counts.source_interval(role, user_id="", cutoff_us=context["cutoffUs"],
        rate_window_us=1, retention_us=context["retentionUs"], work=work)
    phase = maintenance._derive_owned(phase=context["phase"], cutoff_us=context["cutoffUs"],
        retention_us=context["retentionUs"], retained_limit=context["retainedLimit"],
        raw={"primary": body["primaryBefore"], "head": maintenance.head_wire(head_map[profile.index_id]),
             "selected": body["selectedRows"], "proofs": body["beforeProofs"],
             "count": body["countEvidence"], "range": body["rangeEvidence"], "rank": body["rankEvidence"]},
        work=work)
    writes = None
    if not separate_frontiers:
        write_ids = identities if phase.mutations else ()
        writes = body["writeFrontiers"]
        if (type(writes) is not list or len(writes) != len(write_ids)
                or any(type(item) is not dict or set(item) != {"indexId", "frontier"} for item in writes)
                or tuple(item["indexId"] for item in writes) != write_ids):
            raise ChallengePhasePlanError("challenge phase write proof inventory is not exact")
    return _PreparedPhase(context, primary_before, before, phase, writes, identities)


def _prepare_phase(*, body, expected_context, expected_primary, expected_heads, work):
    """Original aggregate raw format: every frontier remains compulsory."""
    return _prepare(body=body, expected_context=expected_context,
        expected_primary=expected_primary, expected_heads=expected_heads,
        work=work, separate_frontiers=False)


def _prepare_read_phase(*, body, expected_context, expected_primary, expected_heads, work):
    """Private compound read stage, without inlining nine write frontiers.

    The separate schema is not accepted by ``compute_phase``. This private
    preparation cannot complete via the aggregate finisher: the actual chain
    must consume every source-index page and rerun each genuine write engine.
    No verdict, computed mutation or after-root appears in either format.
    """
    return _prepare(body=body, expected_context=expected_context,
        expected_primary=expected_primary, expected_heads=expected_heads,
        work=work, separate_frontiers=True)


def _finish_phase(prepared, *, work, retain_nodes):
    """Second fixed stage, called only with the owner's private preparation.

    This object is not accepted by any public plan verifier. The surrounding
    chain constructs and retains it itself, exposes none of its mutable graphs,
    and independently binds it to the same position and preceding roots.
    """
    if (type(prepared) is not _PreparedPhase or prepared.consumed is not False
            or prepared.series_started is not False
            or prepared.writes is None
            or type(work) is not _ValidationWork or type(retain_nodes) is not bool):
        raise ChallengePhasePlanError("challenge phase write replay is not the original unused preparation")
    prepared.consumed = True
    context, primary_before, before = prepared.context, prepared.primary_before, prepared.before
    phase, writes, identities = prepared.phase, prepared.writes, prepared.identities
    if not phase.mutations:
        return _PhaseProduction(PhaseComputation(context, primary_before, primary_before, before, before,
            phase.selected_rows, phase.before_proofs, (), phase.available), None)
    computed, after, observed = _replay_writes(prepared, writes, identities, work, retain_nodes)
    return _PhaseProduction(PhaseComputation(context, primary_before, computed.primary.business_after_roots[0],
        before, after, phase.selected_rows, phase.before_proofs, phase.mutations, phase.available),
        _PhaseNodes(observed.primary_nodes, observed.counted_nodes) if retain_nodes else None)


def _replay_writes(prepared, writes, identities, work, retain_nodes, *, component=False,
                   private_frontier=None):
    primary_before, before, phase = prepared.primary_before, prepared.before, prepared.phase
    head_map = {head.index_id: head for head in before}
    spec = contract.operation_spec(maintenance.OPERATION)
    ledger = batch._SharedLedger(work)
    limits = read_write._write_limits(spec, ledger)
    if private_frontier is None:
        inputs = tuple(indexed.IndexedMutationInput(item["indexId"],
            head_map[item["indexId"]].index_revision, head_map[item["indexId"]].index_root,
            _records(item["frontier"], limits.index.max_frontier_entries)) for item in writes)
    else:
        if not component or len(identities) != 1 or type(private_frontier) is not tuple:
            raise ChallengePhasePlanError("challenge frontier is not a private single-index component")
        head = head_map[identities[0]]
        # These are immutable raw records constructed from retained pages and
        # genuine preceding overlays. The real engine still snapshots and
        # validates every scalar, then reconstructs the full before root.
        inputs = (indexed.IndexedMutationInput(head.index_id, head.index_revision,
            head.index_root, private_frontier),)
    calculate = (indexed._evaluate_challenge_index_component if component else
        indexed._evaluate_indexed_primary_overlay if retain_nodes
        else indexed.evaluate_indexed_primary_batch)
    observed = calculate(
        table_contracts=(primary.PrimaryTableContract(retention.CHALLENGE_TABLE, ("id",), True, "business"),),
        business_before_roots=(primary_before,), authorization_before_roots=(),
        selected_rows=phase.selected_rows, before_proofs=phase.before_proofs,
        mutations=phase.mutations, index_inputs=inputs, limits=limits)
    computed = observed.result if retain_nodes else observed
    ledger.charge(hashes=computed.metrics.hashes, input_bytes=computed.metrics.input_bytes,
        json_nodes=computed.metrics.primary.json_nodes)
    if (len(computed.primary.business_after_roots) != 1
            or computed.primary.authorization_after_roots
            or tuple(item.index_id for item in computed.after_heads) != identities):
        raise ChallengePhasePlanError("challenge phase genuine write inventory changed")
    after = tuple(heads.CapturedIndexHead(item.index_id, head_map[item.index_id].table,
        head_map[item.index_id].counted_profile, head_map[item.index_id].projection_digest,
        head_map[item.index_id].projection_manifest_digest, item.index_revision, item.index_root)
        for item in computed.after_heads)
    return computed, after, observed


def _finish_phase_index(prepared, *, index_id, work, private_frontier=None):
    """One source-fixed compound write stage, never a caller-selected subset.

    The ordinary aggregate evaluator's caps are unchanged. Here every index
    independently replays the same full primary originals and mutations under
    its original caps. Completion requires all nine source identities in order
    and identical independently calculated primary-after roots. SQL mutations
    are returned once only, after the entire private series has completed.
    """
    if (type(prepared) is not _PreparedPhase or prepared.consumed is not False
            or type(work) is not _ValidationWork or type(index_id) is not str
            or prepared.write_position >= len(prepared.identities)
            or index_id != prepared.identities[prepared.write_position]):
        if type(prepared) is _PreparedPhase:
            prepared.consumed = True
        raise ChallengePhasePlanError("challenge write index is not the exact next source stage")
    prepared.series_started = True
    try:
        if prepared.phase.mutations:
            if prepared.writes is None:
                if type(private_frontier) is not tuple:
                    raise ChallengePhasePlanError("challenge separated frontier has not been retained")
                entries = ()
            else:
                if private_frontier is not None:
                    raise ChallengePhasePlanError("challenge aggregate frontier cannot be replaced")
                entry = prepared.writes[prepared.write_position]
                if entry["indexId"] != index_id:
                    raise ChallengePhasePlanError("challenge retained frontier order changed")
                entries = (entry,)
            computed, after, observed = _replay_writes(prepared, entries, (index_id,), work, True,
                component=True, private_frontier=private_frontier)
            root = computed.primary.business_after_roots[0]
            if prepared.primary_after is not None and root != prepared.primary_after:
                raise ChallengePhasePlanError("challenge index stages computed different primary-after roots")
            if prepared.primary_after is None:
                prepared.primary_after = root
                prepared.primary_nodes = observed.primary_nodes
            prepared.after_heads.append(after[0])
            prepared.counted_nodes[index_id] = observed.counted_nodes[index_id]
        else:
            if private_frontier is not None:
                raise ChallengePhasePlanError("challenge empty mutation phase carries a write frontier")
            prepared.primary_after = prepared.primary_before
            prepared.after_heads.append(prepared.before[prepared.write_position])
        prepared.write_position += 1
        if prepared.write_position != len(prepared.identities):
            return None
        prepared.consumed = True
        after = tuple(prepared.after_heads)
        if tuple(head.index_id for head in after) != prepared.identities:
            raise ChallengePhasePlanError("challenge compound omitted a required write-root stage")
        phase = prepared.phase
        return _PhaseProduction(PhaseComputation(prepared.context, prepared.primary_before,
            prepared.primary_after, prepared.before, after, phase.selected_rows,
            phase.before_proofs, phase.mutations, phase.available),
            _PhaseNodes(prepared.primary_nodes, prepared.counted_nodes) if phase.mutations else None)
    except BaseException:
        prepared.consumed = True
        raise


def compute_phase(*, body: dict[str, Any], expected_context: dict[str, Any],
        expected_primary: dict[str, Any], expected_heads: tuple[heads.CapturedIndexHead, ...],
        work: _ValidationWork) -> PhaseComputation:
    """Independently reconstruct this phase from raw, retained originals."""
    prepared = _prepare_phase(body=body, expected_context=expected_context,
        expected_primary=expected_primary, expected_heads=expected_heads,
        work=work)
    return _finish_phase(prepared, work=work, retain_nodes=False).computation


def _produce_phase(*, body, expected_context, expected_primary, expected_heads, work):
    """Run identical proof replay and retain actual nodes for the next phase.

    This is conditional evidence production, not SQL future-state observation.
    It accepts raw phase evidence, never a successful phase result or overlay.
    """
    prepared = _prepare_phase(body=body, expected_context=expected_context,
        expected_primary=expected_primary, expected_heads=expected_heads,
        work=work)
    return _finish_phase(prepared, work=work, retain_nodes=True)
