"""Source-fixed maintenance stage ownership, not authority or a transaction.

The legacy maintenance call has two three-phase pruning passes surrounding
read-only replacement-slot discovery, then admission. This is one physical
proof/acquisition pass. Every row and write-page loop is derived from the held
chain's genuine count and geometry, never a supplied count or resume offset.
The 256 original primary rows stay in one logical mutation batch; individual
raw row/proof stages retain the unchanged 64 MiB work allowance. A separate
planner retention pass requires its own explicit, original-deadline owner.

Every allowance is created here once, spent metrics are accumulated, and the
exact schedule is exhausted before a result can be observed. The caller still
owns the actual single SQL transaction, authenticated root chain, raw bodies
and original admission. No method commits, renews a deadline or grants access.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import os
import threading
import time

from catchplate import authority_contract as contract
from catchplate import authority_challenge_frontier_reader as frontier
from catchplate import authority_index_heads as heads
from catchplate import authority_index_reader as reader
from catchplate import authority_transition_core as core
from catchplate.authority_query_read_work import (
    MAX_HASHES, MAX_INPUT_BYTES, MAX_JSON_NODES, QueryReadValidationLimits,
    QueryReadValidationMetrics, _ValidationWork,
)


SCHEMA = "catchplate.policyAuthorityChallengeCompoundSchedule/v2"
PHASES = ("pre-expire", "pre-old", "pre-overflow", "scope",
    "post-expire", "post-old", "post-overflow", "admission")
WRITE_IDS = heads.required_index_ids("webauthn.challenge.maintain", include_write_heads=True)
STAGES = ("count-acquire:{role}", "count-proof:{role}", "phase-open",
    "candidate-acquire:{page}", "primary-acquire:{row}", "primary-rebase:{row}",
    "primary-proof:{row}", "range-acquire", "range-proof", "rank-acquire",
    "rank-proof", "read-close", "write-geometry:{index}", "write-acquire:{index}:{page}",
    "write-rebase:{index}:{page}", "write-proof:{index}", "phase-close")
MAX_ROWS = contract.MAX_QUERY_PROOFS
MAX_CANDIDATE_PAGES = 1 + 4 * sum(name not in ("scope", "admission") for name in PHASES)
MAX_WRITE_PAGES = (frontier.MAX_PARENTS + frontier.PARENTS_PER_PAGE - 1) // frontier.PARENTS_PER_PAGE
# Bounds on this source algorithm, not a caller's requested stage inventory.
MAX_STAGES = len(PHASES) * (6 + 3 + MAX_CANDIDATE_PAGES + 3 * MAX_ROWS + 4
    + len(WRITE_IDS) * (2 + 2 * MAX_WRITE_PAGES))
MAX_ACQUISITION_STAGES = len(PHASES) * (3 + MAX_CANDIDATE_PAGES + MAX_ROWS + 2
    + len(WRITE_IDS) * MAX_WRITE_PAGES)
_PHASE_ROLES = {"expire": ("expired_remaining",), "old": ("old_remaining",),
    "overflow": ("admission_terminal_count",),
    "admission": ("expired_remaining", "old_remaining", "admission_terminal_count")}


class ChallengeCompoundError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class AcquisitionMetrics:
    sql_reads: int
    returned_rows: int
    parameter_bytes: int
    transport_bytes: int


@dataclass(frozen=True, slots=True)
class StageMetrics:
    ordinal: int
    phase: str
    stage: str
    work: QueryReadValidationMetrics
    acquisition: AcquisitionMetrics | None


@dataclass(frozen=True, slots=True)
class CompoundMetrics:
    stages: tuple[StageMetrics, ...]
    total_work: QueryReadValidationMetrics
    total_acquisition: AcquisitionMetrics


def schedule_binding():
    """Fresh public source schedule; a parent must bind it, not a caller list."""
    return {"schema": SCHEMA, "sourceRevision": contract.SOURCE_REVISION,
        "phases": list(PHASES), "stages": list(STAGES), "writeIndexes": list(WRITE_IDS),
        "geometry": {"rowsPerPhase": MAX_ROWS, "candidatePages": MAX_CANDIDATE_PAGES,
            "parentsPerWritePage": frontier.PARENTS_PER_PAGE, "writePages": MAX_WRITE_PAGES},
        "passes": 1,
        "stageLimits": {"hashes": MAX_HASHES, "inputBytes": MAX_INPUT_BYTES,
            "jsonNodes": MAX_JSON_NODES},
        "acquisitionLimits": {"sqlReads": reader.MAX_CUMULATIVE_SQL_READS,
            "parameterBytes": reader.MAX_PARAMETER_BYTES,
            "transportBytes": reader.MAX_TRANSPORT_BYTES}}


class _Stage:
    """Borrowed stage objects cannot be reused after their context closes."""

    __slots__ = ("_owner", "work", "acquisition", "_work", "_limits",
        "_acquisition", "_acquisition_limits", "_cursor", "_trace", "_previous")

    def __init__(self, owner, cursor, trace):
        self._owner = owner
        self.work = self._work = _ValidationWork(QueryReadValidationLimits())
        self._limits = self.work.limits
        self._cursor, self._trace = cursor, trace
        self.acquisition = self._acquisition = (
            reader._ReadAcquisitionBudget(cursor, trace, work=self.work)
            if cursor is not None else None)
        self._acquisition_limits = self.acquisition.limits if self.acquisition is not None else None
        self._previous = (0,) * 7

    def check(self):
        """Actual callers invoke this around callbacks; no supplied verdict."""
        self._owner._check(self)

    def _snapshot(self):
        if (type(self.work) is not _ValidationWork or self.work is not self._work
                or self.work.limits is not self._limits
                or self._limits != QueryReadValidationLimits()
                or self.acquisition is not self._acquisition):
            raise ChallengeCompoundError("challenge stage allowance was replaced")
        work = self.work.metrics
        values = (work.hash_work, work.input_bytes, work.json_nodes)
        maxima = (MAX_HASHES, MAX_INPUT_BYTES, MAX_JSON_NODES)
        physical = None
        if self.acquisition is not None:
            acquisition = self.acquisition
            if (type(acquisition) is not reader._ReadAcquisitionBudget
                    or acquisition.limits is not self._acquisition_limits
                    or acquisition.limits != reader._ReadAcquisitionLimits()):
                raise ChallengeCompoundError("challenge acquisition allowance was replaced")
            acquisition.require_idle(self._cursor, self._trace, self.work)
            if acquisition._reading or acquisition._read_phase_active:
                raise ChallengeCompoundError("challenge acquisition callback has not closed")
            physical = AcquisitionMetrics(acquisition.sql_reads, acquisition.returned_rows,
                acquisition.parameter_bytes, acquisition.transport_bytes)
            values += (physical.sql_reads, physical.returned_rows,
                physical.parameter_bytes, physical.transport_bytes)
            maxima += (reader.MAX_CUMULATIVE_SQL_READS,
                reader.MAX_CUMULATIVE_SQL_READS * reader.MAX_NODE_IDENTITIES,
                reader.MAX_PARAMETER_BYTES, reader.MAX_TRANSPORT_BYTES)
        else:
            values += (0, 0, 0, 0)
            maxima += (0, 0, 0, 0)
        if any(type(value) is not int or value < previous or value > maximum
               for value, previous, maximum in zip(values, self._previous, maxima)):
            raise ChallengeCompoundError("challenge stage counters were reset or exceeded")
        self._previous = values
        return work, physical


class MaintenanceCompound:
    """Non-reentrant source schedule bound to an already admitted deadline.

    Nothing accepts caller metrics, limits or a resume position. A refusal or
    cancellation permanently closes this owner. Its surrounding SQL owner
    decides whether the legacy admission-refusal path commits maintenance;
    stage failures never authorize that path.
    """

    def __init__(self, *, request_digest: str, original_deadline_ns: int, chain):
        # Lazy import avoids the chain's PHASES dependency. Capture the actual
        # source class method, never a caller callback or an observation DTO.
        from catchplate.authority_challenge_chain import MaintenanceChain, _ScheduleState
        core.require_digest(request_digest, "challenge compound request")
        if type(original_deadline_ns) is not int or not 0 < original_deadline_ns < 2**63:
            raise ChallengeCompoundError("challenge compound deadline is not original")
        if type(chain) is not MaintenanceChain or chain._context["requestDigest"] != request_digest:
            raise ChallengeCompoundError("challenge compound requires its original actual chain")
        self._chain = self._original_chain = chain
        self._chain_type, self._state_type = MaintenanceChain, _ScheduleState
        self._state_reader = MaintenanceChain.schedule_state
        self._request_digest = request_digest
        self._deadline = original_deadline_ns
        self._process = os.getpid(), threading.get_ident()
        self._original = (request_digest, original_deadline_ns, self._process)
        self._last_clock = 0
        self._position = 0
        self._active = None
        self._failed = self._closed = False
        self._records = []
        self._sealed = []
        self._totals = [0] * 7
        self._check()
        self._schedule = self._source_schedule()
        self._expected = next(self._schedule)

    def _state(self, ordinal):
        if self._chain is not self._original_chain or type(self._chain) is not self._chain_type:
            raise ChallengeCompoundError("challenge compound chain owner was replaced")
        state = self._state_reader(self._chain)
        if (type(state) is not self._state_type or type(state.phase_ordinal) is not int
                or state.phase_ordinal != ordinal):
            raise ChallengeCompoundError("challenge compound chain phase did not advance exactly")
        if ordinal == len(PHASES):
            return state
        if state.phase_name != PHASES[ordinal] or type(state.count_roles) is not tuple:
            raise ChallengeCompoundError("challenge compound phase observation is not source fixed")
        phase = PHASES[ordinal]
        roles = ((), ("scope_replacement_count",)) if phase == "scope" else (
            _PHASE_ROLES[phase.split("-", 1)[-1]],)
        if state.count_roles not in roles or any(type(role) is not str for role in state.count_roles):
            raise ChallengeCompoundError("challenge compound count roles changed source order")
        maximum_rows = MAX_ROWS - 1 if phase == "scope" else MAX_ROWS
        if (state.row_count is not None and (type(state.row_count) is not int
                or not 0 <= state.row_count <= maximum_rows)):
            raise ChallengeCompoundError("challenge compound row count is not authenticated and bounded")
        integers = ((state.rows_consumed, state.row_count or 0),
            (state.index_position, len(WRITE_IDS)), (state.pages_consumed, state.page_count or 0))
        if (any(type(value) is not int or not 0 <= value <= maximum for value, maximum in integers)
                or type(state.reads_closed) is not bool or type(state.range_required) is not bool
                or state.page_count is not None and (type(state.page_count) is not int
                    or not 0 <= state.page_count <= MAX_WRITE_PAGES)
                or state.candidate_page_count is not None and (type(state.candidate_page_count) is not int
                    or not 0 <= state.candidate_page_count <= MAX_CANDIDATE_PAGES)):
            raise ChallengeCompoundError("challenge compound physical geometry is not source bounded")
        return state

    def _source_schedule(self):
        """One pass; loop sizes come only from this chain's actual proof work."""
        for ordinal, phase in enumerate(PHASES):
            initial = self._state(ordinal)
            for role in initial.count_roles:
                yield phase, "count-acquire:" + role, True
                self._state(ordinal)
                yield phase, "count-proof:" + role, False
                self._state(ordinal)
            yield phase, "phase-open", False
            opened = self._state(ordinal)
            if opened.count_roles != initial.count_roles:
                raise ChallengeCompoundError("challenge compound count inventory changed after acquisition")
            if phase != "admission":
                rows, candidates = opened.row_count, opened.candidate_page_count
                if (type(rows) is not int or type(candidates) is not int
                        or (rows == 0) != (candidates == 0) or opened.rows_consumed != 0):
                    raise ChallengeCompoundError("challenge compound lacks a newly authenticated phase count")

                def current():
                    state = self._state(ordinal)
                    if (state.row_count != rows or state.count_roles != initial.count_roles
                            or state.candidate_page_count != candidates
                            or state.range_required != opened.range_required):
                        raise ChallengeCompoundError("challenge compound authenticated phase geometry changed")
                    return state

                for page in range(candidates):
                    yield phase, "candidate-acquire:" + str(page), True
                    if current().rows_consumed != 0:
                        raise ChallengeCompoundError("challenge candidate acquisition consumed a row")
                for row in range(rows):
                    if current().rows_consumed != row:
                        raise ChallengeCompoundError("challenge compound primary row ordinal changed")
                    for name in ("primary-acquire", "primary-rebase", "primary-proof"):
                        yield phase, name + ":" + str(row), name == "primary-acquire"
                        expected = row + int(name == "primary-proof")
                        if current().rows_consumed != expected:
                            raise ChallengeCompoundError("challenge compound row proof did not consume exactly one original")
                if opened.range_required:
                    yield phase, "range-acquire", True
                    current()
                    yield phase, "range-proof", False
                    current()
                if phase.endswith("-overflow") and rows:
                    yield phase, "rank-acquire", True
                    current()
                    yield phase, "rank-proof", False
                    current()
                if phase != "scope":
                    yield phase, "read-close", False
                    if not current().reads_closed:
                        raise ChallengeCompoundError("challenge compound candidate proof remains incomplete")
                    for index_position, index_id in enumerate(WRITE_IDS):
                        state = current()
                        idle_pages = 0 if rows == 0 else None
                        if state.index_position != index_position or state.page_count != idle_pages:
                            raise ChallengeCompoundError("challenge compound write index is not the exact next original")
                        if rows:
                            yield phase, "write-geometry:" + index_id, False
                            state = current()
                            pages = state.page_count
                            if (type(pages) is not int or not 1 <= pages <= MAX_WRITE_PAGES
                                    or state.pages_consumed != 0 or state.index_position != index_position):
                                raise ChallengeCompoundError("challenge compound lacks source-derived write geometry")
                            for page in range(pages):
                                yield phase, "write-acquire:" + index_id + ":" + str(page), True
                                state = current()
                                if state.page_count != pages or state.pages_consumed != page:
                                    raise ChallengeCompoundError("challenge compound raw write page was skipped or consumed early")
                                yield phase, "write-rebase:" + index_id + ":" + str(page), False
                                state = current()
                                if state.page_count != pages or state.pages_consumed != page + 1:
                                    raise ChallengeCompoundError("challenge compound write page was not consumed exactly once")
                        yield phase, "write-proof:" + index_id, False
                        if index_position + 1 < len(WRITE_IDS):
                            state = current()
                            if state.index_position != index_position + 1 or state.page_count != idle_pages:
                                raise ChallengeCompoundError("challenge compound actual index fold did not close")
                        else:
                            self._state(ordinal + 1)
            yield phase, "phase-close", False
            self._state(ordinal + 1)

    @property
    def next_stage(self):
        """Detached source position, never an API for requesting more work."""
        self._check()
        return None if self._expected is None else self._expected[:2]

    @property
    def needs_acquisition(self):
        self._check()
        return self._expected is not None and self._expected[2]

    def _check(self, stage=None):
        try:
            if (self._failed or self._closed
                    or type(self._deadline) is not int
                    or (self._request_digest, self._deadline, self._process) != self._original
                    or (os.getpid(), threading.get_ident()) != self._process
                    or stage is not None and self._active is not stage):
                raise ChallengeCompoundError("challenge compound owner is closed or changed")
            now = time.monotonic_ns()
            if type(now) is not int or not self._last_clock <= now < self._deadline:
                raise ChallengeCompoundError("challenge compound original deadline elapsed")
            self._last_clock = now
            if stage is not None:
                stage._snapshot()
        except BaseException:
            self._failed = True
            raise

    @contextmanager
    def stage(self, phase: str, stage: str, *, cursor=None, trace=None):
        """Enter the exact next stage; even a caught nested entry poisons it."""
        try:
            self._check()
            if (self._active is not None or self._position >= MAX_STAGES
                    or type(phase) is not str or type(stage) is not str
                    or self._expected is None or (phase, stage) != self._expected[:2]
                    or (cursor is None) != (trace is None)
                    or self._expected[2] != (cursor is not None)):
                raise ChallengeCompoundError("challenge compound stage is not the exact next source stage")
            current = _Stage(self, cursor, trace)
            self._active = current
            current.check()
            yield current
            current.check()
            measured, physical = current._snapshot()
            values = current._previous
            maxima = (MAX_STAGES * MAX_HASHES, MAX_STAGES * MAX_INPUT_BYTES,
                MAX_STAGES * MAX_JSON_NODES,
                MAX_ACQUISITION_STAGES * reader.MAX_CUMULATIVE_SQL_READS,
                MAX_ACQUISITION_STAGES * reader.MAX_CUMULATIVE_SQL_READS * reader.MAX_NODE_IDENTITIES,
                MAX_ACQUISITION_STAGES * reader.MAX_PARAMETER_BYTES,
                MAX_ACQUISITION_STAGES * reader.MAX_TRANSPORT_BYTES)
            if any(value > maximum - total for value, total, maximum
                   in zip(values, self._totals, maxima)):
                raise ChallengeCompoundError("challenge compound cumulative work exceeds source bounds")
            self._totals = [total + value for total, value in zip(self._totals, values)]
            self._records.append(StageMetrics(self._position, phase, stage, measured, physical))
            self._sealed.append((current, values))
            self._position += 1
            self._expected = next(self._schedule, None)
        except BaseException:
            self._failed = True
            raise
        finally:
            self._active = None

    def finish(self) -> CompoundMetrics:
        try:
            self._check()
            if self._active is not None or self._expected is not None:
                raise ChallengeCompoundError("challenge compound schedule is incomplete")
            self._state(len(PHASES))
            # Inspect each original ledger, not merely its returned snapshot.
            for stage, original_values in self._sealed:
                stage._snapshot()
                if stage._previous != original_values:
                    raise ChallengeCompoundError("challenge closed stage was spent after its source position")
            self._closed = True
            return CompoundMetrics(tuple(self._records),
                QueryReadValidationMetrics(*self._totals[:3]), AcquisitionMetrics(*self._totals[3:]))
        except BaseException:
            self._failed = True
            raise

    def close(self):
        """Retire only this accounting owner, never supplied SQL resources."""
        self._closed = True
