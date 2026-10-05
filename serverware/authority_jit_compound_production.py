"""Configured native JIT production, immutable custody and independent replay.

One real read planner captures originals; only its normal resource closure
permits sealing/signing/persistence. The same configured page caller then
reads every retained original for genuine replay before any result is released.
No supplied observation, signer, custody callback or replacement clock is an
input. These outputs do not replace current-root/capability/execution admission.

The original caller allowance owns capture and native setup. Exactly seal,
sign, one persist per actual original (at most 67), and verify-parent receive
source-fixed child allowances. Native and replay compound children remain
their separate original owners. Physical metrics on native output cover its
children only: the native owner's twelve setup SELECTs are NOT included there.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import os
import threading
import time

from serverware import authority_jit_compound_plan as plan
from serverware import authority_jit_compound_planning as planning
from serverware import authority_jit_original_configuration as configuration
from serverware import authority_jit_original_service as service
from serverware import authority_jit_original_spool as spool_source
from serverware.authority_query_read_work import (
    MAX_HASHES, MAX_INPUT_BYTES, MAX_JSON_NODES, QueryReadValidationLimits,
    QueryReadValidationMetrics, _ValidationWork,
)


compound, source, evidence, clock = plan.compound, plan.source, plan.evidence, plan.clock
MAX_PRODUCTION_STAGES = 3 + compound.MAX_ORIGINALS
_COUNTERS = ("hash_work", "input_bytes", "json_nodes")
_CALLER_FIELDS = ("_configured", "_check_owner", "_window", "_held", "_identity")


class JitCompoundProductionError(ValueError):
    pass


def _require(value):
    if not value:
        raise JitCompoundProductionError("JIT production lost its original components, order or allowance")


def _values(work):
    source.batch._SharedLedger(work)
    return tuple(getattr(work, name) for name in _COUNTERS)


def _metrics(values):
    return QueryReadValidationMetrics(*values)


@dataclass(frozen=True, slots=True)
class _ProductionStage:
    """Fixed source call-site observation; native borrows the original parent."""

    name: str
    work: _ValidationWork


@dataclass(frozen=True, slots=True)
class ProductionStageMetrics:
    name: str
    work: QueryReadValidationMetrics


@dataclass(frozen=True, slots=True)
class ProducedJitCompoundPlan:
    """Actual same-call outputs, never accepted as proof or custody inputs."""

    verified: plan.VerifiedJitCompoundPlan
    native: compound.JitPassObservation
    parent_work: QueryReadValidationMetrics
    stages: tuple[ProductionStageMetrics, ...]
    total_work: QueryReadValidationMetrics


class _Production:
    def __init__(self, producer, window, deadline, check, work):
        _require(type(work) is _ValidationWork and callable(check))
        self.producer, self.parent = producer, work
        self.window = clock._validate(window)
        _require(type(deadline) is int and self.window[2] < deadline <= self.window[4])
        self.deadline = deadline
        self.expires = self.window[0] + deadline - self.window[1]
        _require(self.window[0] < self.expires <= self.window[3])
        self.check = check
        self.process = os.getpid(), threading.get_ident()
        self.parent_limits = work.limits
        self.parent_bounds = (work.limits.max_hashes, work.limits.max_input_bytes, work.limits.max_json_nodes)
        self.start = self.previous = _values(work)
        self.held = (producer, work, self.window, deadline, self.expires, check,
            self.process, self.parent_limits, self.parent_bounds)
        self.native_stage = _ProductionStage("native", work)
        self.active = self.native_stage
        self.active_held = (self.native_stage, self.native_stage.name, work, work.limits)
        self.active_previous = self.start
        self.sealed, self.stage_metrics = [], []
        self.schedule = None
        self.parent_frozen = None
        self.last = 0
        self.failed = self.busy = False

    def local(self):
        _require(not self.failed and self.process == (os.getpid(), threading.get_ident())
            and all(actual is original for actual, original in zip(
                (self.producer, self.parent, self.window, self.deadline, self.expires, self.check,
                 self.process, self.parent_limits, self.parent_bounds), self.held, strict=True)))
        self.producer._local()
        _require(self.parent.limits is self.parent_limits
            and (self.parent_limits.max_hashes, self.parent_limits.max_input_bytes,
                self.parent_limits.max_json_nodes) == self.parent_bounds)
        current = _values(self.parent)
        _require(all(before <= value <= maximum for before, value, maximum
            in zip(self.previous, current, self.parent_bounds, strict=True))
            and (self.parent_frozen is None or current == self.parent_frozen))
        self.previous = current
        if self.active is not None:
            stage, name, active_work, limits = self.active_held
            _require(self.active is stage and stage.name is name
                and stage.work is active_work and active_work.limits is limits)
            if stage is not self.native_stage:
                _require((limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
                    == (MAX_HASHES, MAX_INPUT_BYTES, MAX_JSON_NODES))
            current = _values(active_work)
            _require(all(before <= value for before, value in zip(self.active_previous, current, strict=True)))
            self.active_previous = current
        for stage, name, original_work, limits, values in self.sealed:
            _require(stage.name is name and stage.work is original_work
                and original_work.limits is limits and _values(original_work) == values
                and (limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
                    == (MAX_HASHES, MAX_INPUT_BYTES, MAX_JSON_NODES))

    def live(self, work):
        self.local()
        _require(type(work) is _ValidationWork)
        _require(evidence.production._callback(work,
            lambda: service._PageCaller._live(self.producer._page_caller, work)) is None)
        now = clock._check_on_work(self.window, work=work)
        current = evidence.production._callback(work, time.monotonic_ns)
        _require(type(current) is int and self.last <= current < self.deadline and now < self.expires)
        self.last = current
        self.local()

    def checked(self, stage):
        try:
            _require(not self.busy and self.active is not None and (stage is self.active or (
                self.active.name == "verify-parent" and type(stage) is compound._Stage
                and stage._owner._active is stage and stage.acquisition is None)))
            self.live(stage.work)
            self.busy = True
            _require(evidence.production._callback(stage.work, lambda: self.check(stage)) is None)
            self.live(stage.work)
        except BaseException:
            self.failed = True
            raise
        finally:
            self.busy = False

    def freeze(self, count):
        self.local()
        _require(self.active is self.native_stage and self.schedule is None
            and type(count) is int and 1 <= count <= compound.MAX_ORIGINALS)
        # Prepay the bounded final totals/stage tuple/output construction before
        # this original parent becomes suspended for all producing children.
        self.parent.charge(input_bytes=65536, json_nodes=2048)
        self.schedule = ("seal", "sign", *("persist:" + str(i) for i in range(count)), "verify-parent")
        self.parent_frozen = _values(self.parent)
        self.active = None
        self.active_held = None

    @contextmanager
    def stage(self, name):
        try:
            self.local()
            _require(self.active is None and self.schedule is not None
                and len(self.sealed) < len(self.schedule) <= MAX_PRODUCTION_STAGES
                and name == self.schedule[len(self.sealed)])
            work = _ValidationWork(QueryReadValidationLimits())
            # Fixed source-local stage/guard metadata, separate from actual
            # raw body hashing, signing, transport and replay work below.
            # During delegated replay, compound's own upfront 2 MiB/131072
            # bookkeeping debit covers its checks plus <=20 producer scans
            # of <=69 sealed ledgers per real child; callbacks stay neutral.
            work.charge(input_bytes=1024 * 1024, json_nodes=65536)
            stage = _ProductionStage(name, work)
            limits = work.limits
            self.active = stage
            self.active_held = stage, name, work, limits
            self.active_previous = _values(work)
            self.checked(stage)
            yield stage
            _require(self.active is stage and stage.work is work and work.limits is limits)
            self.checked(stage)
            values = _values(work)
            _require((limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes)
                == (MAX_HASHES, MAX_INPUT_BYTES, MAX_JSON_NODES))
            self.sealed.append((stage, name, work, limits, values))
            self.stage_metrics.append(ProductionStageMetrics(name, _metrics(values)))
            self.active = None
            self.active_held = None
            self.local()
        except BaseException:
            self.failed = True
            raise

    def finish(self, native, verified):
        self.local()
        _require(self.active is None and len(self.sealed) == len(self.schedule)
            and tuple(value.name for value in self.stage_metrics) == self.schedule
            and type(native) is compound.JitPassObservation
            and type(verified) is plan.VerifiedJitCompoundPlan)
        parent = tuple(value - before for value, before in zip(_values(self.parent), self.start, strict=True))
        totals = list(parent)
        for metrics in self.stage_metrics:
            for index, name in enumerate(_COUNTERS):
                totals[index] += getattr(metrics.work, name)
        for observed in (native, verified.replay):
            _require(type(observed) is compound.JitPassObservation and len(observed.stages) <= compound.MAX_STAGES)
            for index, name in enumerate(_COUNTERS):
                value = getattr(observed.total_work, name)
                _require(type(value) is int and 0 <= value <= compound.MAX_STAGES
                    * (MAX_HASHES, MAX_INPUT_BYTES, MAX_JSON_NODES)[index])
                totals[index] += value
        ceilings = tuple((1 + len(self.schedule) + 2 * compound.MAX_STAGES) * maximum
            for maximum in (MAX_HASHES, MAX_INPUT_BYTES, MAX_JSON_NODES))
        _require(all(type(value) is int and 0 <= value <= maximum
            for value, maximum in zip(totals, ceilings, strict=True)))
        return ProducedJitCompoundPlan(verified, native, _metrics(parent),
            tuple(self.stage_metrics), _metrics(totals))


class _JitCompoundProducer:
    """Inert, one-shot composition of actual configured source components."""

    __slots__ = ("_read_planner", "_page_caller", "_held", "_used")

    def __init__(self, *, read_planner, page_caller):
        _require(type(read_planner) is planning.JitCompoundReadPlanner
            and type(page_caller) is service._PageCaller)
        selected = page_caller._configured
        snapshot = configuration._snapshot(selected)
        _require(selected.local_role == "planner")
        planning.existing._configuration(read_planner._configured)
        _require(read_planner._configured[2][4:] == selected.planner_identity)
        self._read_planner, self._page_caller = read_planner, page_caller
        self._held = (read_planner, read_planner._configured, page_caller,
            tuple(getattr(page_caller, name) for name in _CALLER_FIELDS), selected, snapshot)
        self._used = False

    def _local(self):
        _require(type(self) is _JitCompoundProducer)
        planner, configured, caller, fields, selected, snapshot = self._held
        _require(self._read_planner is planner and planner._configured is configured
            and self._page_caller is caller and caller._configured is selected
            and all(getattr(caller, name) is value for name, value in zip(_CALLER_FIELDS, fields, strict=True))
            and configuration._snapshot(selected) is snapshot)

    def produce(self, *, request, business_before_roots, authorization_before_roots,
            expected_counted_heads, live_window, original_deadline_ns, check, work):
        self._local()
        _require(not self._used and type(work) is _ValidationWork and callable(check))
        self._used = True
        entry_metrics = _values(work)
        # Own request and all independent anchors before external callbacks.
        work.charge(input_bytes=65536, json_nodes=2048)
        _require(type(request) is dict and type(business_before_roots) is tuple
            and type(authorization_before_roots) is tuple and type(expected_counted_heads) is tuple
            and len(business_before_roots) == len(authorization_before_roots) == 4
            and len(expected_counted_heads) == 12)
        owner = _Production(self, live_window, original_deadline_ns, check, work)
        # produce-entry accounting includes capture, not caller pre-factory work.
        owner.start = entry_metrics
        _require(owner.window is self._page_caller._window)
        configured = self._page_caller._configured
        _require(owner.window[5] <= configured.maximum_age_ns
            and owner.window[6] <= configured.maximum_clock_skew_ns)
        owned = source.reads._CopyBudget(work).copy({"request": request,
            "business": business_before_roots, "authorization": authorization_before_roots,
            "heads": expected_counted_heads})
        source._request(owned["request"], work)
        request_bytes = work.wire(owned["request"])
        policy_values = self._read_planner._configured[3]
        work.prepare_copy(policy_values)
        policy = dict(zip(source._POLICY_FIELDS, policy_values, strict=True))
        spool = spool_source._JitOriginalSpool(original_deadline_ns=original_deadline_ns, work=work)

        def retain(kind, ordinal, body, child):
            owner.live(child)
            spool.retain(kind, ordinal, body, child)
            owner.live(child)

        try:
            owner.checked(owner.native_stage)
            native = self._read_planner.acquire_pass(request=owned["request"],
                business_before_roots=tuple(owned["business"]),
                authorization_before_roots=tuple(owned["authorization"]),
                expected_counted_heads=tuple(owned["heads"]), now_epoch_ns=owner.window[0],
                deadline_epoch_ns=owner.expires, live_window=owner.window,
                check=lambda: owner.checked(owner.native_stage), work=work, retain_original=retain)
            owner.checked(owner.native_stage)
            _require(type(native) is compound.JitPassObservation)
            context = plan._decode(native.context_bytes, plan.MAX_CONTEXT_BYTES, work)
            manifest = plan._decode(native.original_manifest_bytes, plan.MAX_MANIFEST_BYTES, work)
            plan._object(context, spool_source._CONTEXT_FIELDS)
            plan._object(manifest, plan.MANIFEST_FIELDS)
            descriptors = manifest["originals"]
            _require(type(descriptors) is list and 1 <= len(descriptors) <= compound.MAX_ORIGINALS)
            work.prepare_copy(descriptors)
            originals = tuple((item["kind"], item["ordinal"], item["byteLength"], item["digest"])
                for item in descriptors)
            work.charge(input_bytes=16384, json_nodes=512)
            expected = {"requestDigest": owned["request"]["requestDigest"],
                "operationId": owned["request"]["operationId"],
                "configurationDigest": configured.configuration_digest,
                "plannerIdentity": dict(zip(configuration._IDENTITY_FIELDS, configured.planner_identity, strict=True)),
                "plannerSpkiDigest": configured.planner_spki_digest, "assertionPolicy": policy,
                "businessBeforeRoots": list(owned["business"]),
                "authorizationBeforeRoots": list(owned["authorization"]),
                "countedBeforeHeads": list(owned["heads"]), "databaseCutoffUs": context["databaseCutoffUs"],
                "originalDeadlineNs": original_deadline_ns,
                "maximumPlanAgeNs": owner.window[5], "maximumClockSkewNs": owner.window[6]}
            owner.freeze(len(originals))
            with owner.stage("seal") as stage:
                spool.seal(context_bytes=native.context_bytes,
                    manifest_bytes=native.original_manifest_bytes, work=stage.work)
                plan._same(spool.keys(work=stage.work), tuple((kind, ordinal)
                    for kind, ordinal, _length, _digest in originals), stage.work)
            with owner.stage("sign") as stage:
                envelope = plan._sign_parent_on_work(request_bytes=request_bytes,
                    context_bytes=native.context_bytes, manifest_bytes=native.original_manifest_bytes,
                    expectations=expected, planner_private_key=configured.private_key,
                    planner_public_key=configured.planner_public_key, issued_at_epoch_ns=owner.window[0],
                    expires_at_epoch_ns=owner.expires, live_window=owner.window, work=stage.work)
                parent_digest = evidence.plan._frame(plan.IDENTITY_DOMAIN, (envelope,), stage.work)
                manifest_digest = evidence.plan._frame(plan.MANIFEST_DOMAIN,
                    (native.original_manifest_bytes,), stage.work)

            def page_context(kind, ordinal, current_work):
                current_work.charge(input_bytes=4096, json_nodes=64)
                return {"parent_plan_digest": parent_digest, "original_manifest_digest": manifest_digest,
                    "source_revision": source.authority.SOURCE_REVISION, "operation": compound.OPERATION,
                    "operation_id": expected["operationId"], "request_digest": expected["requestDigest"],
                    "configuration_digest": configured.configuration_digest,
                    "page_kind": kind, "page_ordinal": ordinal}

            for position, (kind, ordinal, length, digest) in enumerate(originals):
                with owner.stage("persist:" + str(position)) as stage:
                    raw = spool.read(kind, ordinal, stage.work)
                    stage.work.charge(input_bytes=1024, json_nodes=16)
                    _require(len(raw) == length)
                    self._page_caller.persist(context=page_context(kind, ordinal, stage.work), body_bytes=raw,
                        descriptor={"digest": digest, "byteCount": length},
                        original_deadline_ns=original_deadline_ns, work=stage.work)
                    owner.live(stage.work)

            def read(kind, ordinal, child):
                owner.live(child)
                result = self._page_caller.read(context=page_context(kind, ordinal, child),
                    original_deadline_ns=original_deadline_ns, work=child)
                owner.live(child)
                return result

            with owner.stage("verify-parent") as stage:
                verified = plan.verify_retained(envelope_bytes=envelope, request_bytes=request_bytes,
                    context_bytes=native.context_bytes, manifest_bytes=native.original_manifest_bytes,
                    expectations=expected, planner_public_key=configured.planner_public_key,
                    live_window=owner.window, read_original=read, check=owner.checked, work=stage.work)
                plan._same(verified.plan_digest, parent_digest, stage.work)
                plan._same_bytes(verified.context_bytes, native.context_bytes, stage.work)
                plan._same_bytes(verified.manifest_bytes, native.original_manifest_bytes, stage.work)
            owner.live(work)
            result = owner.finish(native, verified)
            owner.live(work)
            return result
        except BaseException:
            owner.failed = True
            raise
