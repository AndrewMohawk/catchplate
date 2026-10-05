"""Genuine streamed maintenance replay joined to a complete root vector.

This family is deliberately separate from aggregate successor packets: six
independent 256-row pruning phases must not be flattened into the generic
256-proof/512-mutation envelope or silently split into commits. Every original
page is replayed through the real bounded stages. Only that same invocation's
computed challenge root and nine counted heads replace their exact predecessor
descriptors; every other source descriptor is retained byte-for-byte.

The full vector still supplies no enrollment/currentness/capability authority.
Protected current-root reservation and the actual single SQL transaction must
surround execution. An optional mutation callback is tentative and must roll
back on any later error. No successful replay result is accepted as input.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_challenge_compound as compound
from serverware import authority_challenge_maintenance as maintenance
from serverware import authority_challenge_manifest as manifest
from serverware import authority_challenge_plan as plan
from serverware import authority_current_root_vector as vector


SCHEMA = "serverware.policyAuthorityChallengeMaintenanceVectorReplay/v1"
_TABLE = "webauthn_challenges"
_PHASES = ("pre-expire", "pre-old", "pre-overflow", "scope",
    "post-expire", "post-old", "post-overflow", "admission")
MAX_PRIMARY_EVENTS = 6 * maintenance.BATCH_SIZE
OPERATION = "webauthn.challenge.maintain"


class ChallengeCurrentRootError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class MaintenanceVectorObservation:
    """Same-call relative observations, never an execution candidate token."""

    plan_digest: str
    manifest_digest: str
    before_vector_bytes: bytes
    after_vector_bytes: bytes
    before_vector_digest: str
    after_vector_digest: str
    result: dict
    original_interval: tuple[int, int]
    primary_events: int
    replay: plan.VerifiedMaintenancePlan


def _require(value):
    if not value:
        raise ChallengeCurrentRootError("streamed maintenance roots differ from their complete source predecessors")


def _head(value):
    # Exact source descriptors have already been validated by their real
    # family/vector consumers; this is only the one rootCount/leafCount rename.
    return {"indexId": value["indexId"], "table": value["table"],
        "countedProfile": value["countedProfile"], "projectionDigest": value["projectionDigest"],
        "projectionManifestDigest": value["projectionManifestDigest"],
        "indexRevision": value["indexRevision"], "rootDigest": value["rootDigest"],
        "leafCount": value["rootCount"]}


def _join_before(before, context, work):
    _require(compound.PHASES == _PHASES and maintenance.BATCH_SIZE == 256
        and set(manifest.WRITE_IDS) == set(vector.projection.index_ids_for_table(_TABLE)))
    work.prepare_scan(before)
    primary = next(root for root in before["primaryRoots"] if root["table"] == _TABLE)
    plan._same(primary, context["primaryRoot"], work)
    heads = {head["indexId"]: head for head in before["countedRoots"]}
    for raw in context["indexHeads"]:
        work.prepare_copy(raw)
        plan._same(heads[raw["indexId"]], _head(raw), work)


def validate_necessary_delta(*, before_vector_bytes, after_vector_bytes, work):
    """Source-specific compound compatibility, not proof or root authority.

    The generic operation remains bounded to256 rows per independent phase.
    Its six-phase single-commit protocol has at most1536 actual primary events;
    flattening that schedule into a generic proof/mutation envelope is refused
    elsewhere. This necessary check admits only that fixed descriptor delta.
    The execution owner must still replay every original bounded phase.
    """
    from serverware import authority_current_root_delta as delta

    writable, indexes, maximum = delta._source(OPERATION)
    _require(writable == frozenset({_TABLE}) and indexes == frozenset(manifest.WRITE_IDS)
        and maximum == 256 and compound.PHASES == _PHASES and maintenance.BATCH_SIZE == 256)
    before = vector._decode_on_work(before_vector_bytes, work=work)
    after = vector._decode_on_work(after_vector_bytes, work=work)
    events = 0
    for old, new in zip(before["primaryRoots"], after["primaryRoots"], strict=True):
        if old["table"] != _TABLE:
            plan._same(old, new, work)
            continue
        events = delta._delta(old, new, "rootRevision", MAX_PRIMARY_EVENTS, work,
            "compound challenge primary root")
        _require(new["leafCount"] <= old["leafCount"])
    for old, new in zip(before["countedRoots"], after["countedRoots"], strict=True):
        if old["indexId"] not in indexes:
            plan._same(old, new, work)
        else:
            delta._delta(old, new, "indexRevision", events, work,
                "compound challenge counted root")
    return before, after


def _lift(before, decision, work):
    """Private suffix reached only after this call's whole authentic replay."""
    _require(type(decision) is plan.chains.MaintenanceDecision)
    after = vector._Capture(vector.capture._SharedLedger(work), maximum_bytes=vector.MAX_BYTES).visit(before)
    primary = decision.primary_after.json_projection()
    work.prepare_copy(primary)
    old_primary = next(root for root in before["primaryRoots"] if root["table"] == _TABLE)
    events = primary["rootRevision"] - old_primary["rootRevision"]
    _require(primary["table"] == _TABLE and type(events) is int
        and 0 <= events <= MAX_PRIMARY_EVENTS
        and 0 <= old_primary["leafCount"] - primary["leafCount"] <= events)
    if events == 0:
        plan._same(primary, old_primary, work)
    for root in after["primaryRoots"]:
        if root["table"] == _TABLE:
            root.update(primary)
    _require(tuple(head.index_id for head in decision.counted_after) == manifest.WRITE_IDS)
    for new in decision.counted_after:
        raw = maintenance.head_wire(new)
        work.prepare_copy(raw)
        actual = _head(raw)
        target = next(head for head in after["countedRoots"] if head["indexId"] == new.index_id)
        delta = actual["indexRevision"] - target["indexRevision"]
        _require(type(delta) is int and 0 <= delta <= events
            and abs(actual["leafCount"] - target["leafCount"]) <= delta)
        if delta == 0:
            plan._same(actual, target, work)
        # Source profile metadata cannot change during a row mutation.
        plan._same({name: actual[name] for name in (
            "indexId", "table", "countedProfile", "projectionDigest", "projectionManifestDigest")},
            {name: target[name] for name in (
                "indexId", "table", "countedProfile", "projectionDigest", "projectionManifestDigest")}, work)
        target.update(actual)
    return after, events


def replay_to_complete_vector(*, envelope_bytes, request_bytes, manifest_bytes,
        expectations, planner_public_key, before_vector_bytes, read_original, check,
        work, apply_mutation=None, observe_effect=None):
    """Authenticate/recompute raw pages; never lift a supplied after-root DTO."""
    expected = plan._expectations(expectations, work)
    before = vector._decode_on_work(before_vector_bytes, work=work)
    _join_before(before, expected["context"], work)
    verified = plan.verify_maintenance_parent(envelope_bytes=envelope_bytes,
        request_bytes=request_bytes, manifest_bytes=manifest_bytes, expectations=expected,
        planner_public_key=planner_public_key, read_original=read_original,
        check=check, work=work, apply_mutation=apply_mutation, observe_effect=observe_effect)
    decision = verified.replay.observation.decision
    after, events = _lift(before, decision, work)
    after_bytes = vector._encode_on_work(after, work=work)
    before_digest = vector.framing._frame(vector.IDENTITY_DOMAIN, (before_vector_bytes,), work)
    after_digest = vector.framing._frame(vector.IDENTITY_DOMAIN, (after_bytes,), work)
    # The original signed bytes were authenticated above. Decode only to
    # preserve their real interval/manifest commitment; never sample a clock
    # here or substitute these historical fields for current-root admission.
    original = plan.evidence.wire._decode_object(verified.envelope_bytes, work=work,
        maximum_bytes=plan.MAX_PARENT_BYTES, maximum_nodes=plan.MAX_PARENT_NODES,
        maximum_depth=plan.MAX_PARENT_DEPTH)["payload"]
    result = {"schema": SCHEMA, "replacementOverflow": decision.replacement_overflow,
        "pruningPending": decision.pruning_pending, "retainedLimit": decision.retained_limit}
    work.prepare_copy(result)
    return MaintenanceVectorObservation(verified.plan_digest, original["manifestDigest"],
        before_vector_bytes, after_bytes, before_digest, after_digest, result,
        (original["issuedAtEpochNs"], original["expiresAtEpochNs"]), events, verified)
