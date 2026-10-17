"""Derive immutable scalar execution framing from one genuine proof replay.

Only the real same-call replay may emit bodies. Rows remain opaque originals,
not caller-supplied mutation DTOs; phase bodies supply the genuine source row
counts. At most1548 scalar descriptors survive this call, never a collection
of full rows. Every event spends its existing child stage allowance. The seed
and final header spend the original parent allowance, without replacing either.

retain_effect(step_ordinal, body_bytes, descriptor, stage) retains tentative
originals and returns None. Failure at any point leaves them non-executable:
only the later independently admitted issuer may seal the complete header in
protected custody. This codec issues no grant, opens no transaction, writes no
business row, renews no deadline, and accepts no completed observation as input.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

from catchplate import authority_challenge_current_root as current_root
from catchplate import authority_challenge_pass as source_pass
from catchplate.authority_query_read_work import _ValidationWork


plan, compound = current_root.plan, current_root.compound
SCHEMA = "catchplate.policyAuthorityChallengeMaintenanceExecutionStream/v1"
IDENTITY_DOMAIN = "catchplate.policyAuthorityChallengeMaintenanceExecutionStreamIdentity/v1"
SEED_DOMAIN = "catchplate.policyAuthorityChallengeMaintenanceExecutionStreamSeed/v1"
STEP_DOMAIN = "catchplate.policyAuthorityChallengeMaintenanceExecutionStreamStep/v1"
RESULT_DOMAIN = "catchplate.policyAuthorityControlledWriterResult/v2"
PHASES = (0, 1, 2, 4, 5, 6)
MAX_STEPS = len(PHASES) * (256 + 2)
MAX_BODY_BYTES = 4 * 1024 * 1024
MAX_HEADER_BYTES = 1024 * 1024
MAX_HEADER_NODES = 32768
_DESCRIPTOR_FIELDS = ("kind", "phaseOrdinal", "rowOrdinal", "byteCount", "digest")
_PHASE_FIELDS = frozenset({"schema", "phaseOrdinal", "rowCount", "primaryRoot", "indexHeads"})


class ChallengeExecutionStreamError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class DerivedExecutionStream:
    """Freely constructible output carrier, never an execution authority."""

    header_bytes: bytes
    header_digest: str
    observation: current_root.MaintenanceVectorObservation


def _require(value):
    if not value:
        raise ChallengeExecutionStreamError("maintenance effect stream differs from its genuine source order")


class _Schedule:
    """Six closed before/row/after sequences, including all zero-row phases."""

    def __init__(self):
        self.position = self.seen = self.rows = 0
        self.count = None

    def advance(self, kind, phase, ordinal, count):
        _require(type(kind) is str and kind in ("phase-before", "row", "phase-after")
            and type(phase) is int and type(ordinal) is int
            and self.position < len(PHASES) and phase == PHASES[self.position])
        if kind == "phase-before":
            _require(self.count is None and ordinal == 0
                and type(count) is int and 0 <= count <= 256)
            self.count, self.seen = count, 0
        elif kind == "row":
            _require(count is None and self.count is not None
                and ordinal == self.seen and self.seen < self.count)
            self.seen += 1
            self.rows += 1
        else:
            _require(self.count is not None and type(count) is int
                and count == self.count == self.seen and ordinal == 0)
            self.position += 1
            self.count = None

    def finish(self):
        _require(self.position == len(PHASES) and self.count is None)


def _phase_count(raw, phase, work):
    # Only the small fixed nine-head phase record needs decoding. Full row
    # originals are already emitted by the genuine primary proof engine.
    value = plan.evidence.wire._decode_object(raw, work=work,
        maximum_bytes=plan.MAX_PARENT_BYTES, maximum_nodes=plan.MAX_PARENT_NODES,
        maximum_depth=plan.MAX_PARENT_DEPTH)
    plan._object(value, _PHASE_FIELDS)
    _require(type(value["schema"]) is str and value["schema"] == source_pass.PHASE_EFFECT_SCHEMA
        and type(value["phaseOrdinal"]) is int and value["phaseOrdinal"] == phase
        and type(value["rowCount"]) is int and 0 <= value["rowCount"] <= 256)
    canonical = work.wire(value)
    work.charge(input_bytes=len(canonical) + len(raw))
    _require(canonical == raw)
    return value["rowCount"]


def _descriptor(values, work):
    _require(type(values) is tuple and len(values) == len(_DESCRIPTOR_FIELDS)
        and type(work) is _ValidationWork)
    # The two held five-scalar tuples conservatively cover the destination
    # object's canonical bytes/nodes. Reserve before constructing the dict,
    # including when the parent later materializes its final steps array.
    work.prepare_copy((_DESCRIPTOR_FIELDS, values))
    return dict(zip(_DESCRIPTOR_FIELDS, values, strict=True))


class _Collector:
    """Invocation-private output sink, never a public body acceptance API."""

    def __init__(self, seed, retain):
        self.chain, self.retain = seed, retain
        self.schedule = _Schedule()
        self.descriptors = []
        self.total_bytes = 0
        self.active = True
        self.busy = self.failed = False

    def observe(self, kind, phase, ordinal, raw, stage):
        try:
            _require(self.active and not self.failed and not self.busy
                and type(stage) is compound._Stage and type(stage.work) is _ValidationWork
                and type(kind) is str and kind in ("phase-before", "row", "phase-after")
                and type(phase) is int and type(ordinal) is int
                and type(raw) is bytes and 2 <= len(raw) <= MAX_BODY_BYTES
                and len(self.descriptors) < MAX_STEPS)
            self.busy = True
            stage.check()
            work = stage.work
            count = _phase_count(raw, phase, work) if kind != "row" else None
            self.schedule.advance(kind, phase, ordinal, count)
            work.charge(hashes=1, input_bytes=len(raw))
            digest = "sha256:" + hashlib.sha256(raw).hexdigest()
            descriptor = _descriptor((kind, phase, ordinal, len(raw), digest), work)
            encoded = work.wire(descriptor)
            chain = plan.evidence.plan._frame(STEP_DOMAIN,
                (plan.evidence.plan._ascii(self.chain, work), encoded), work)
            # The callback gets a separate shallow object, not a retained
            # mutable descriptor. Both allocation and readback spend this stage.
            work.prepare_copy(descriptor)
            borrowed = dict(descriptor)
            stage.check()
            _require(self.retain(len(self.descriptors), raw, borrowed, stage) is None)
            _require(self.active and not self.failed and self.busy and stage.work is work)
            stage.check()
            after = work.wire(borrowed)
            work.charge(input_bytes=len(after) + len(encoded))
            _require(after == encoded)
            work.prepare_copy(descriptor)
            self.descriptors.append((kind, phase, ordinal, len(raw), digest))
            self.chain = chain
            self.total_bytes += len(raw)
            _require(self.total_bytes <= MAX_STEPS * MAX_BODY_BYTES)
            stage.check()
        except BaseException:
            self.failed = True
            raise
        finally:
            self.busy = False

    def finish(self):
        _require(not self.active and not self.busy and not self.failed)
        self.schedule.finish()
        _require(len(self.descriptors) == self.schedule.rows + 2 * len(PHASES))


def _raw(raw, maximum):
    _require(type(raw) is bytes and 2 <= len(raw) <= maximum)


def derive_stream(*, envelope_bytes, request_bytes, manifest_bytes, expectations,
        planner_public_key, before_vector_bytes, read_original, check, retain_effect, work):
    """Replay exactly once; publish a header only after all genuine joins close."""
    _require(type(work) is _ValidationWork and callable(retain_effect)
        and callable(read_original) and callable(check)
        and compound.PHASES == ("pre-expire", "pre-old", "pre-overflow", "scope",
            "post-expire", "post-old", "post-overflow", "admission")
        and current_root.maintenance.BATCH_SIZE == 256)
    _raw(envelope_bytes, plan.MAX_PARENT_BYTES)
    _raw(manifest_bytes, plan.manifests.MAX_MANIFEST_BYTES)
    _raw(before_vector_bytes, current_root.vector.MAX_BYTES)
    frame = plan.evidence.plan._frame
    bindings = {"planDigest": frame(plan.IDENTITY_DOMAIN, (envelope_bytes,), work),
        "manifestDigest": frame(plan.MANIFEST_DOMAIN, (manifest_bytes,), work),
        "beforeVectorDigest": frame(current_root.vector.IDENTITY_DOMAIN, (before_vector_bytes,), work)}
    seed = frame(SEED_DOMAIN, (work.wire(bindings),), work)
    collector = _Collector(seed, retain_effect)
    try:
        observed = current_root.replay_to_complete_vector(envelope_bytes=envelope_bytes,
            request_bytes=request_bytes, manifest_bytes=manifest_bytes, expectations=expectations,
            planner_public_key=planner_public_key, before_vector_bytes=before_vector_bytes,
            read_original=read_original, check=check, work=work, observe_effect=collector.observe)
    finally:
        # Even a callback retained elsewhere cannot append after this replay.
        collector.active = False
    collector.finish()
    _require(type(observed) is current_root.MaintenanceVectorObservation
        and observed.primary_events == collector.schedule.rows)
    plan._same(bindings, {"planDigest": observed.plan_digest,
        "manifestDigest": observed.manifest_digest,
        "beforeVectorDigest": observed.before_vector_digest}, work)
    # This is the already-authenticated original, not mutable caller expectations.
    payload = plan.evidence.wire._decode_object(observed.replay.envelope_bytes, work=work,
        maximum_bytes=plan.MAX_PARENT_BYTES, maximum_nodes=plan.MAX_PARENT_NODES,
        maximum_depth=plan.MAX_PARENT_DEPTH)["payload"]
    steps = []
    for values in collector.descriptors:
        steps.append(_descriptor(values, work))
    result_raw = work.wire(observed.result)
    header = {"schema": SCHEMA, "sourceRevision": payload["sourceRevision"],
        **{name: payload[name] for name in ("operation", "operationId", "requestDigest", "configurationDigest")},
        **bindings, "afterVectorDigest": observed.after_vector_digest,
        "resultDigest": frame(RESULT_DOMAIN, (result_raw,), work),
        "stepCount": len(steps), "totalBodyBytes": collector.total_bytes,
        "chainDigest": collector.chain, "steps": steps}
    raw = plan.evidence.plan.retained._bounded_wire(header,
        plan.evidence.capture._SharedLedger(work), maximum_bytes=MAX_HEADER_BYTES,
        maximum_nodes=MAX_HEADER_NODES)
    return DerivedExecutionStream(raw, frame(IDENTITY_DOMAIN, (raw,), work), observed)
