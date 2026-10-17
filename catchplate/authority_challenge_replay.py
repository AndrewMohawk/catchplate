"""Independently replay retained maintenance bytes on one source schedule.

The caller admits the signed parent/current roots, owns retained-page custody
and any tentative SQL transaction, and must roll back unless the entire parent
closes. This component supplies none of that authority. Every page callback is
mandatory: there is no live SQL acquisition fallback, caller proof verdict,
replacement allowance, extra pass, deadline renewal or resource close.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import threading
import time

from catchplate import authority_challenge_chain as chains
from catchplate import authority_challenge_compound as compounds
from catchplate import authority_challenge_maintenance as maintenance
from catchplate import authority_challenge_manifest as manifests
from catchplate import authority_challenge_pass as passes
from catchplate import authority_index_projection as projection
from catchplate import authority_index_reader as reader
from catchplate.authority_query_read_work import (
    MAX_HASHES, MAX_INPUT_BYTES, MAX_JSON_NODES, QueryReadValidationLimits,
    QueryReadValidationMetrics, _ValidationWork,
)


class ChallengeReplayError(ValueError):
    pass


def _require(value):
    if not value:
        raise ChallengeReplayError("retained challenge maintenance replay custody changed")


@dataclass(frozen=True, slots=True)
class MaintenanceReplayObservation:
    """Relative verified computation only; never permission to commit."""

    observation: passes.MaintenancePassObservation
    initial_work: QueryReadValidationMetrics
    total_work: QueryReadValidationMetrics
    total_acquisition: compounds.AcquisitionMetrics


class _ReplayCursor:
    """Identity for raw-body accounting; it cannot execute physical SQL."""

    def __init__(self, owner):
        self._owner = owner

    def execute(self, *_args, **_kwargs):
        self._owner._failed = True
        raise ChallengeReplayError("retained replay has no SQL acquisition fallback")


class _Replay:
    def __init__(self, *, context, expected_manifest, read_original, check, apply_mutation,
                 observe_effect=None):
        _require(callable(read_original) and callable(check)
            and (apply_mutation is None or callable(apply_mutation))
            and (observe_effect is None or callable(observe_effect)))
        self._read_original, self._check_callback, self._apply_mutation = read_original, check, apply_mutation
        self._observe_effect = observe_effect
        self._process = os.getpid(), threading.get_ident()
        self._failed = self._closed = self._busy = False
        self._clock = 0
        self._initial = _ValidationWork(QueryReadValidationLimits())
        self._initial_limits = self._initial.limits
        self._context = manifests._context(context, self._initial)
        self._expected = manifests._validate(expected_manifest, self._initial)
        self._context_bytes = self._initial.wire(self._context)
        expected_context = self._initial.wire(self._expected["context"])
        self._initial.charge(input_bytes=len(self._context_bytes) + len(expected_context))
        _require(self._context_bytes == expected_context)
        self._deadline = self._context["originalDeadlineNs"]
        self._cursor = _ReplayCursor(self)
        self._held = (self._read_original, self._check_callback, self._apply_mutation, self._observe_effect,
            self._context, self._expected, self._deadline, self._cursor,
            self._initial, self._initial_limits)
        self._chain = self._compound = self._manifest = None
        self._workers = None
        self._local()

    def _local(self):
        try:
            _require(not self._failed and not self._closed
                and self._process == (os.getpid(), threading.get_ident())
                and all(actual is held for actual, held in zip((
                    self._read_original, self._check_callback, self._apply_mutation, self._observe_effect,
                    self._context, self._expected, self._deadline, self._cursor,
                    self._initial, self._initial_limits), self._held, strict=True))
                and self._cursor._owner is self
                and self._initial.limits is self._initial_limits
                and self._initial_limits == QueryReadValidationLimits())
            if self._workers is not None:
                _require(all(actual is held for actual, held in zip(
                    (self._chain, self._compound, self._manifest), self._workers, strict=True)))
            now = time.monotonic_ns()
            _require(type(now) is int and self._clock <= now < self._deadline)
            self._clock = now
        except BaseException:
            self._failed = True
            raise

    def _context_check(self, work):
        self._local()
        raw = work.wire(self._context)
        work.charge(input_bytes=len(raw) + len(self._context_bytes))
        _require(raw == self._context_bytes)

    def _stamp(self, stage):
        self._local()
        _require(type(stage) is compounds._Stage and stage._owner is self._compound
            and self._compound._active is stage)
        stage.check()
        work, acquisition = stage.work, stage.acquisition
        held = (stage, work, work.limits, acquisition, stage._cursor, stage._trace)
        values = work.hash_work, work.input_bytes, work.json_nodes
        maxima = MAX_HASHES, MAX_INPUT_BYTES, MAX_JSON_NODES
        if acquisition is not None:
            _require(stage._cursor is self._cursor and acquisition.cursor is self._cursor
                and acquisition.trace is stage._trace and acquisition.work is work
                and type(acquisition) is reader._ReadAcquisitionBudget
                and acquisition.limits == reader._ReadAcquisitionLimits()
                and acquisition.sql_reads == acquisition.returned_rows == 0
                and stage._trace._entries == [])
            acquisition.require_idle(self._cursor, stage._trace, work)
            _require(acquisition._reading is False and acquisition._read_phase_active is False)
            held += acquisition.limits, acquisition._identity
            values += acquisition.parameter_bytes, acquisition.transport_bytes
            maxima += reader.MAX_PARAMETER_BYTES, reader.MAX_TRANSPORT_BYTES
        else:
            _require(stage._cursor is None and stage._trace is None)
        _require(all(type(value) is int and 0 <= value <= maximum
            for value, maximum in zip(values, maxima, strict=True)))
        return held, values

    def _callback(self, stage, callback):
        try:
            self._context_check(stage.work)
            before = self._stamp(stage)
            result = callback()
            after = self._stamp(stage)
            _require(all(actual is held for actual, held in zip(after[0], before[0], strict=True))
                and all(current >= previous for current, previous in zip(after[1], before[1], strict=True)))
            self._context_check(stage.work)
            return result
        except BaseException:
            self._failed = True
            raise

    def _check(self, stage):
        _require(self._callback(stage, lambda: self._check_callback(stage)) is None)

    def _read(self, phase, kind, index_id, ordinal, stage):
        raw = self._callback(stage, lambda: self._read_original(phase, kind, index_id, ordinal, stage))
        try:
            _require(type(raw) is bytes and 2 <= len(raw) <= manifests.MAX_BODY_BYTES)
            self._stamp(stage)
            acquisition = stage.acquisition
            _require(acquisition is not None
                and len(raw) <= acquisition.limits.max_transport_bytes - acquisition.transport_bytes)
            # Raw retained-body bytes, deliberately not SQL row/PG wire size.
            # The actual adapter independently accounts its controls/framing.
            stage.work.charge(input_bytes=len(raw))
            acquisition.transport_bytes += len(raw)
            self._stamp(stage)
            return raw
        except BaseException:
            self._failed = True
            if stage.acquisition is not None:
                stage.acquisition.failed = True
            raise

    def _apply(self, mutation, stage):
        original = stage.work.wire(mutation)
        result = self._callback(stage, lambda: self._apply_mutation(mutation, stage))
        after = stage.work.wire(mutation)
        stage.work.charge(input_bytes=len(original) + len(after))
        _require(result is None and original == after)

    def _effect(self, kind, phase, ordinal, raw, stage):
        _require(type(raw) is bytes and 2 <= len(raw) <= manifests.MAX_BODY_BYTES)
        result = self._callback(stage,
            lambda: self._observe_effect(kind, phase, ordinal, raw, stage))
        _require(result is None)

    def run(self):
        self._local()
        if self._busy:
            self._failed = True
            raise ChallengeReplayError("challenge retained replay cannot be reentered")
        self._busy = True
        try:
            work, context = self._initial, self._context
            self._context_check(work)
            work.charge(hashes=maintenance.contract.TREE_DEPTH + 1)
            root = maintenance._root(context["primaryRoot"])
            captured = []
            for raw in context["indexHeads"]:
                work.charge(hashes=projection.PROFILE_HASH_WORK)
                captured.append(maintenance._head(raw, projection.profile_for(raw["indexId"]), root, work))
            self._chain = chains.MaintenanceChain(request_digest=context["requestDigest"],
                cutoff_us=context["cutoffUs"], retention_us=context["retentionUs"],
                maximum_retained=context["maximumRetained"], challenge_type=context["challengeType"],
                user_id=context["userId"], scope_key=context["scopeKey"], replace_scope=context["replaceScope"],
                primary_root=context["primaryRoot"], index_heads=tuple(captured), work=work)
            self._manifest = manifests.MaintenanceManifest(context=context, work=work)
            self._compound = compounds.MaintenanceCompound(request_digest=context["requestDigest"],
                original_deadline_ns=self._deadline, chain=self._chain)
            self._workers = self._chain, self._compound, self._manifest
            observed = passes.run_pass(operation=context["operation"], chain=self._chain,
                compound=self._compound, manifest=self._manifest, cursor=self._cursor,
                check=self._check, read_original=self._read,
                apply_mutation=self._apply if self._apply_mutation is not None else None,
                observe_effect=self._effect if self._observe_effect is not None else None)
            self._local()
            _require(type(observed) is passes.MaintenancePassObservation)
            manifests.compare_manifest(expected=self._expected, actual=observed.manifest, work=work)
            self._context_check(work)
            total = QueryReadValidationMetrics(*(getattr(work.metrics, name)
                + getattr(observed.metrics.total_work, name)
                for name in ("hash_work", "input_bytes", "json_nodes")))
            _require(all(type(value) is int and 0 <= value <= (compounds.MAX_STAGES + 1) * maximum
                for value, maximum in zip((total.hash_work, total.input_bytes, total.json_nodes),
                    (MAX_HASHES, MAX_INPUT_BYTES, MAX_JSON_NODES), strict=True)))
            self._local()
            self._closed = True
            return MaintenanceReplayObservation(observed, work.metrics, total, observed.metrics.total_acquisition)
        except BaseException:
            self._failed = True
            for worker in (self._compound, self._chain, self._manifest):
                if worker is not None:
                    worker.close()
            raise
        finally:
            self._busy = False


def replay_maintenance(*, context, expected_manifest, read_original, check, apply_mutation=None,
                       observe_effect=None):
    """One actual proof replay; parent authority and rollback stay external."""
    return _Replay(context=context, expected_manifest=expected_manifest,
        read_original=read_original, check=check, apply_mutation=apply_mutation,
        observe_effect=observe_effect).run()
