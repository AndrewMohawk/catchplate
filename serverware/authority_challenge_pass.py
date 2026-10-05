"""One actual raw-page maintenance replay on the source-fixed stage schedule.

This is the common computation used by the held-snapshot producer and by
independent retained-page replay. It never accepts a computed mutation, root,
candidate list, page count or successful-proof DTO. The actual outer owner
still admits the request/configuration/current root, owns the physical SQL
transaction and absolute deadline, and decides commit versus rollback.

Raw callbacks are deliberately not authority: every returned body is replayed
through this invocation's genuine chain. A tentative executor callback may
apply each computed row to its one outer transaction, but must roll back all
of those writes unless the entire parent and manifest independently close.
No callback may commit, renew the clock, or substitute a work allowance.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_challenge_candidate_reader as candidates
from serverware import authority_challenge_chain as chain_module
from serverware import authority_challenge_compound as compound_module
from serverware import authority_challenge_counts as counts
from serverware import authority_challenge_frontier_reader as writes
from serverware import authority_challenge_manifest as manifests
from serverware import authority_challenge_primary_reader as primary
from serverware import authority_index_count_reader as count_reader
from serverware import authority_index_reader as reader
from serverware import authority_planner as planner
from serverware import authority_revocation_wire as wire
from serverware.authority_store import current_root_observation as transaction_source


OUTSIDE_SCHEMA = "serverware.policyAuthorityChallengeOutsideOriginal/v1"
ROW_EFFECT_SCHEMA = "serverware.policyAuthorityChallengeMaintenanceRowEffect/v1"
PHASE_EFFECT_SCHEMA = "serverware.policyAuthorityChallengeMaintenancePhaseEffect/v1"


class ChallengePassError(ValueError):
    pass


class _Trace(planner.PlannerTrace):
    """Actual bounded read fragment, not a completed global-audit trace."""

    def __init__(self, operation):
        super().__init__(operation=operation, _challenge_successor=True)

    def read(self, table, key):
        if table == transaction_source._TRANSACTION_TABLE:
            if (type(key) is not dict or set(key) != {"profile", "rowLimit"}
                    or key["profile"] != transaction_source._TRANSACTION_PROFILE
                    or type(key["rowLimit"]) is not int or key["rowLimit"] != 2):
                raise ChallengePassError("challenge snapshot observation is not the fixed physical query")
            self._append("read", table, key)
        else:
            super().read(table, key)


@dataclass(frozen=True, slots=True)
class MaintenancePassObservation:
    """Relative local computation; never an admission or commit capability."""

    decision: chain_module.MaintenanceDecision
    manifest: dict
    metrics: compound_module.CompoundMetrics


def _decode(body, work):
    value = wire._decode_object(body, work=work, maximum_bytes=reader.MAX_TRANSPORT_BYTES)
    actual = work.wire(value)
    work.charge(input_bytes=len(actual) + len(body))
    if actual != body:
        raise ChallengePassError("challenge original is not its exact canonical byte form")
    return value


def run_pass(*, operation, chain, compound, manifest, cursor, check,
             read_original=None, observe_original=None, apply_mutation=None, seal_stage=None,
             observe_effect=None):
    """Consume one fixed pass, with at most one raw body alive at a time.

    With ``read_original=None`` every acquisition is the actual source SQL
    reader on the caller's held snapshot. Otherwise the private retained
    reader supplies bytes using (phase, kind, index, ordinal, stage); its
    actual connection/peer/custody owner must account its physical transport
    on the supplied original stage and retain the same absolute deadline.

    ``observe_original`` receives those same identity fields plus bytes and
    their freshly computed descriptor. It is useful for the sole second
    snapshot pass's immutable retention, never for replacing proof replay.
    The source outer owner binds both passes and compares their whole fresh
    manifests. This function cannot start an extra pass or create a ledger.
    """
    if (type(chain) is not chain_module.MaintenanceChain
            or type(compound) is not compound_module.MaintenanceCompound
            or compound._chain is not chain
            or type(manifest) is not manifests.MaintenanceManifest
            or operation not in ("webauthn.challenge.create", "webauthn.challenge.maintain")
            or type(operation) is not str or not callable(check)
            or any(value is not None and not callable(value)
                for value in (read_original, observe_original, apply_mutation, seal_stage, observe_effect))):
        raise ChallengePassError("challenge pass lacks its exact source owners")
    original = (operation, chain, compound, manifest, cursor, check,
        read_original, observe_original, apply_mutation, seal_stage, observe_effect)
    evidence, body, geometry = {}, None, None
    phase_rows = None
    decision = finished_manifest = None
    anchors_checked = False

    def local(stage):
        if any(now is not held for now, held in zip(
                (operation, chain, compound, manifest, cursor, check,
                 read_original, observe_original, apply_mutation, seal_stage, observe_effect), original)):
            raise ChallengePassError("challenge pass original owner changed")
        stage.check()

    def external(stage, callback):
        local(stage)
        if check(stage) is not None:
            raise ChallengePassError("challenge original-owner check returned a verdict")
        local(stage)
        result = callback()
        local(stage)
        if check(stage) is not None:
            raise ChallengePassError("challenge original-owner check returned a verdict")
        local(stage)
        return result

    def acquire(stage, phase, kind, index_id, ordinal, producer):
        raw = (external(stage, producer) if read_original is None else external(stage,
            lambda: read_original(phase, kind, index_id, ordinal, stage)))
        if type(raw) is not bytes or not 2 <= len(raw) <= reader.MAX_TRANSPORT_BYTES:
            raise ChallengePassError("challenge page is not bounded original bytes")
        descriptor = manifest.append(phase_ordinal=phase, kind=kind, index_id=index_id,
            ordinal=ordinal, body_bytes=raw, work=stage.work)
        if observe_original is not None:
            result = external(stage, lambda: observe_original(
                phase, kind, index_id, ordinal, raw, descriptor, stage))
            if result is not None:
                raise ChallengePassError("challenge retention callback returned a substituted result")
        return raw

    def raw_count(stage, trace, coordinates, role):
        profile, head, interval = coordinates
        acquired = count_reader.acquire_count_frontier(cursor, profile=profile,
            index_revision=head.index_revision, expected_root=head.index_root,
            interval=interval, trace=trace, work=stage.work, acquisition=stage.acquisition)
        return stage.work.wire(counts.evidence(role, acquired, work=stage.work))

    def effect(stage, kind, phase, ordinal, value):
        # This is same-call output only. The original raw-page proof and final
        # parent still have to close before any protected custody header may
        # become executable. No supplied effect or returned verdict is read.
        raw = stage.work.wire(value)
        if not 2 <= len(raw) <= reader.MAX_TRANSPORT_BYTES:
            raise ChallengePassError("challenge derived effect exceeds its one-row body bound")
        if external(stage, lambda: observe_effect(kind, phase, ordinal, raw, stage)) is not None:
            raise ChallengePassError("challenge derived-effect callback returned a verdict")

    def phase_effect(stage, kind, phase, row_count):
        effect(stage, kind, phase, 0, {"schema": PHASE_EFFECT_SCHEMA,
            "phaseOrdinal": phase, "rowCount": row_count,
            "primaryRoot": chain._root.json_projection(),
            "indexHeads": [chain_module.maintenance.head_wire(head) for head in chain._heads]})

    try:
        while compound.next_stage is not None:
            phase_name, name = compound.next_stage
            phase_ordinal = compound_module.PHASES.index(phase_name)
            phase = phase_name.split("-", 1)[-1]
            trace = _Trace(operation) if compound.needs_acquisition else None
            with compound.stage(phase_name, name,
                    cursor=cursor if trace is not None else None, trace=trace) as stage:
                local(stage)
                if check(stage) is not None:
                    raise ChallengePassError("challenge original-owner check returned a verdict")
                local(stage)
                if not anchors_checked:
                    context = chain._context
                    expected = {name: context[name] for name in (
                        "requestDigest", "cutoffUs", "retentionUs", "maximumRetained",
                        "challengeType", "userId", "scopeKey", "replaceScope")}
                    expected.update(operation=operation,
                        originalDeadlineNs=compound._deadline,
                        primaryRoot=context["primary"], indexHeads=context["heads"])
                    left = stage.work.wire(expected)
                    right = stage.work.wire({name: manifest._context[name] for name in expected})
                    stage.work.charge(input_bytes=len(left) + len(right))
                    if left != right:
                        raise ChallengePassError("challenge parent manifest differs from the actual chain originals")
                    anchors_checked = True
                if name.startswith("count-acquire:"):
                    role = name.split(":", 1)[1]
                    ordinal = chain.schedule_state().count_roles.index(role)
                    body = acquire(stage, phase_ordinal, "count", "", ordinal,
                        lambda: raw_count(stage, trace,
                            chain.count_input(role=role, work=stage.work), role))
                elif name.startswith("count-proof:"):
                    role = name.split(":", 1)[1]
                    evidence[role] = chain.rebase_count(role=role,
                        original_evidence=_decode(body, stage.work), work=stage.work)
                    body = None
                elif name == "phase-open":
                    if phase == "scope":
                        chain.begin_scope(count_evidence=evidence.pop(counts.SCOPE_ROLE, None), work=stage.work)
                    elif phase != "admission":
                        role = chain.schedule_state().count_roles[0]
                        chain.begin_phase(count_evidence=evidence.pop(role), work=stage.work)
                        phase_rows = chain.schedule_state().row_count
                        if observe_effect is not None:
                            phase_effect(stage, "phase-before", phase_ordinal, phase_rows)
                elif name.startswith("candidate-acquire:"):
                    ordinal = int(name.split(":", 1)[1])
                    def collect_candidate():
                        head, interval, offset = chain.candidate_input(ordinal=ordinal, work=stage.work)
                        return candidates.acquire_candidate_page(cursor, phase=phase, head=head,
                            interval=interval, base_offset=offset, ordinal=ordinal, trace=trace,
                            work=stage.work, acquisition=stage.acquisition)
                    raw = acquire(stage, phase_ordinal, "candidate", "", ordinal, collect_candidate)
                    chain.accept_candidate_page(body_bytes=raw, work=stage.work)
                    del raw
                elif name.startswith("primary-acquire:"):
                    ordinal = int(name.split(":", 1)[1])
                    body = acquire(stage, phase_ordinal, "primary", "", ordinal,
                        lambda: primary.acquire_primary_original(cursor, phase=phase,
                            primary_id=chain.candidate_id(ordinal=ordinal, work=stage.work),
                            primary_root=chain._original_root, trace=trace,
                            work=stage.work, acquisition=stage.acquisition))
                elif name.startswith("primary-rebase:"):
                    raw = _decode(body, stage.work)
                    if set(raw) != {"schema", "selectedRows", "beforeProofs"} or raw["schema"] != primary.SCHEMA:
                        raise ChallengePassError("challenge primary original changed its closed source shape")
                    if type(raw["selectedRows"]) is not list or type(raw["beforeProofs"]) is not list:
                        raise ChallengePassError("challenge primary original arrays are not exact")
                    chain.capture_primary(selected_rows=tuple(raw["selectedRows"]),
                        before_proofs=tuple(raw["beforeProofs"]), work=stage.work)
                    chain.rebase_primary(work=stage.work)
                    body = None
                    del raw
                elif name.startswith("primary-proof:"):
                    if phase == "scope":
                        chain.consume_scope_row(work=stage.work)
                    else:
                        before = chain._stream_phase._root
                        mutation = chain.consume_row(work=stage.work)
                        if observe_effect is not None:
                            effect(stage, "row", phase_ordinal, int(name.split(":", 1)[1]), {
                                "schema": ROW_EFFECT_SCHEMA, "phaseOrdinal": phase_ordinal,
                                "rowOrdinal": int(name.split(":", 1)[1]), "mutation": mutation,
                                "primaryBefore": before.json_projection(),
                                "primaryAfter": chain._stream_phase._root.json_projection()})
                        if apply_mutation is not None:
                            returned = external(stage, lambda: apply_mutation(mutation, stage))
                            if returned is not None:
                                raise ChallengePassError("challenge executor callback returned a verdict")
                        del mutation
                elif name == "range-acquire":
                    def collect_range():
                        profile, head, interval = chain.range_input(work=stage.work)
                        acquired = count_reader.acquire_count_frontier(cursor, profile=profile,
                            index_revision=head.index_revision, expected_root=head.index_root,
                            interval=interval, trace=trace, work=stage.work, acquisition=stage.acquisition)
                        outside = set(reader.outside_prefixes(interval))
                        return stage.work.wire({"schema": OUTSIDE_SCHEMA, "frontier": [
                            {"prefix": item.prefix, "digest": item.digest, "count": item.count}
                            for item in acquired.frontier if item.prefix in outside]})
                    body = acquire(stage, phase_ordinal, "range", "", 0, collect_range)
                elif name == "range-proof":
                    raw = _decode(body, stage.work)
                    if set(raw) != {"schema", "frontier"} or raw["schema"] != OUTSIDE_SCHEMA:
                        raise ChallengePassError("challenge outside originals changed their source shape")
                    evidence["range"] = chain.rebase_range(original_outside_nodes=raw["frontier"], work=stage.work)
                    body = None
                    del raw
                elif name == "rank-acquire":
                    body = acquire(stage, phase_ordinal, "rank", "", 0,
                        lambda: raw_count(stage, trace, chain.rank_input(work=stage.work), "overflow_skip_count"))
                elif name == "rank-proof":
                    evidence["rank"] = chain.rebase_rank(original_evidence=_decode(body, stage.work), work=stage.work)
                    body = None
                elif name == "read-close":
                    chain.close_phase_reads(range_evidence=evidence.pop("range", None),
                        rank_evidence=evidence.pop("rank", None), work=stage.work)
                elif name.startswith("write-geometry:"):
                    index_id = name.split(":", 1)[1]
                    inputs = chain.begin_write_index(index_id=index_id, work=stage.work)
                    geometry = writes.capture_frontier_geometry(head=inputs["head"],
                        target_keys=inputs["targetKeys"], work=stage.work)
                elif name.startswith("write-acquire:"):
                    _, index_id, ordinal = name.split(":")
                    body = acquire(stage, phase_ordinal, "write", index_id, int(ordinal),
                        lambda: writes.acquire_frontier_page(cursor, geometry=geometry, ordinal=int(ordinal),
                            trace=trace, work=stage.work, acquisition=stage.acquisition))
                elif name.startswith("write-rebase:"):
                    chain.accept_write_page(body_bytes=body, work=stage.work)
                    body = None
                elif name.startswith("write-proof:"):
                    chain.advance(index_id=name.split(":", 1)[1], work=stage.work)
                    geometry = None
                elif name == "phase-close":
                    if phase == "scope":
                        chain.finish_scope(range_evidence=evidence.pop("range", None), work=stage.work)
                    elif phase == "admission":
                        decision = chain.finish(pending_evidence=evidence, work=stage.work)
                        evidence = {}
                        finished_manifest = manifest.finish(work=stage.work)
                    elif observe_effect is not None:
                        # The ninth real index fold advanced the chain. Its
                        # exact after roots, not callback supplied roots, close
                        # this phase even when the authenticated row count is0.
                        phase_effect(stage, "phase-after", phase_ordinal, phase_rows)
                    phase_rows = None
                    if evidence or body is not None or geometry is not None:
                        raise ChallengePassError("challenge phase left an unconsumed original")
                else:
                    raise ChallengePassError("challenge pass encountered an undeclared source stage")
                if seal_stage is not None:
                    # The native snapshot owner makes its final continuity
                    # read and seals the actual read-only trace fragment on
                    # this original ledger. Do not call check(stage) again:
                    # that would add unsealed SQL after the fragment hash.
                    local(stage)
                    if seal_stage(stage) is not None:
                        raise ChallengePassError("challenge stage sealing returned a verdict")
                local(stage)
        metrics = compound.finish()
        if type(decision) is not chain_module.MaintenanceDecision or type(finished_manifest) is not dict:
            raise ChallengePassError("challenge pass did not close its actual chain and manifest")
        return MaintenancePassObservation(decision, finished_manifest, metrics)
    except BaseException:
        compound.close()
        chain.close()
        raise
