"""Deterministic compound-accounting components, not SQL or authority admission.

Chain observations, cursor/trace, clock and process boundaries are doubled.
No chain proof result is claimed: these are scheduler/accounting controls. Positive work is
spent by the real work/acquisition ledgers; no supplied success metrics stand
in for proof replay, a PostgreSQL transaction or a signed parent plan.
"""
from __future__ import annotations

import hashlib
import json
import unittest
from unittest import mock

from serverware import authority_challenge_compound as compound
from serverware import authority_contract as contract
from serverware import authority_challenge_chain as chain_module
from serverware import authority_index_reader as reader
from serverware.authority_query_read_work import (
    MAX_HASHES, MAX_INPUT_BYTES, MAX_JSON_NODES,
    QueryReadValidationLimits, _ValidationWork,
)


PHASES = ("pre-expire", "pre-old", "pre-overflow", "scope",
          "post-expire", "post-old", "post-overflow", "admission")
REQUEST = "sha256:" + "a" * 64


class ChainDouble:
    """Only the observation seam, never raw proof or SQL admission."""

    def __init__(self, rows=None, *, scope_enabled=False, scope_overflow=False, pages=2):
        self._context = {"requestDigest": REQUEST}
        self.row_counts = rows or {}
        self.scope_enabled, self.scope_overflow = scope_enabled, scope_overflow
        self.write_pages = pages
        self.position = 0
        self._reset()

    def _reset(self):
        self.opened = self.consumed = self.index = self.page_consumed = 0
        self.pages = None
        self.reads_closed = False

    def advance(self):
        self.position += 1
        self._reset()

    def schedule_state(self):
        if self.position == len(PHASES):
            return chain_module._ScheduleState(8, "complete", (), 0, 0, True, 0, 0, 0, 0, False)
        phase = PHASES[self.position]
        roles = (compound._PHASE_ROLES[phase.split("-", 1)[-1]] if phase != "scope"
            else ("scope_replacement_count",) if self.scope_enabled else ())
        count = self.row_counts.get(phase, 0) if self.opened else None
        if phase == "admission" or phase == "scope" and self.opened and (
                not self.scope_enabled or self.scope_overflow):
            count = 0
        candidates = None if count is None else int(count > 0)
        required = (phase == "scope" and self.scope_enabled and not self.scope_overflow
            or phase not in ("scope", "admission") and count != 0)
        return chain_module._ScheduleState(self.position, phase, roles, count,
            self.consumed, self.reads_closed, self.index,
            self.pages if self.pages is not None else 0 if count == 0 else None,
            self.page_consumed, candidates, required)

    def perform(self, phase, name):
        if name == "phase-open":
            self.opened = 1
        elif name.startswith("primary-proof:"):
            self.consumed += 1
        elif name == "read-close":
            self.reads_closed = True
        elif name.startswith("write-geometry:"):
            self.pages, self.page_consumed = self.write_pages, 0
        elif name.startswith("write-rebase:"):
            self.page_consumed += 1
        elif name.startswith("write-proof:"):
            self.index += 1
            self.pages, self.page_consumed = None, 0
            if self.index == len(compound.WRITE_IDS):
                self.advance()
        elif name == "phase-close" and phase in ("scope", "admission"):
            self.advance()


class CursorDouble:
    """Recording component double: no SQL engine, connection or transaction."""

    def __init__(self):
        self.executions = []
        self.fetches = []
        self.closes = 0

    def execute(self, statement, parameters):
        self.executions.append((statement, parameters))
        return self

    def fetchmany(self, maximum):
        self.fetches.append(maximum)
        return [{"value": "v"}]

    def close(self):
        self.closes += 1
        raise AssertionError("compound accounting must never close its borrowed cursor")


class TraceDouble:
    """Records trace calls only; it does not claim trace serialization work."""

    def __init__(self):
        self.reads = []

    def read(self, table, key):
        self.reads.append((table, key))


def acquire(stage, cursor, trace):
    # Actual frame accounting: parameters 20 B; returned transport 21 B;
    # UTF-8 measure/encode plus length frames 50 B / eight scalar nodes.
    with stage.acquisition.scope(cursor, trace, stage.work):
        rows = stage.acquisition.read("synthetic_history", {"id": "row"},
            "component read, never sent to PostgreSQL", ("key", 7), 1)
        stage.acquisition.charge("node", rows[0], ("value",))


def encode_and_hash(stage, ordinal):
    raw = stage.work.wire({"ordinal": ordinal})
    stage.work.charge(hashes=1, input_bytes=len(raw))
    return hashlib.sha256(raw).digest()


class ChallengeCompoundTests(unittest.TestCase):
    def setUp(self):
        clock_patch = mock.patch.object(compound.time, "monotonic_ns", return_value=10)
        self.clock = clock_patch.start()
        self.addCleanup(clock_patch.stop)
        self.cursor, self.trace = CursorDouble(), TraceDouble()
        chain_patch = mock.patch.object(chain_module, "MaintenanceChain", ChainDouble)
        chain_patch.start()
        self.addCleanup(chain_patch.stop)

    def tearDown(self):
        self.assertEqual(self.cursor.closes, 0)

    def owner(self, chain=None):
        return compound.MaintenanceCompound(request_digest=REQUEST,
            original_deadline_ns=1000, chain=chain or ChainDouble())

    def stage(self, owner, phase=None, stage=None):
        phase = phase if phase is not None else owner.next_stage[0]
        stage = stage if stage is not None else owner.next_stage[1]
        arguments = dict(cursor=self.cursor, trace=self.trace) if owner.needs_acquisition else {}
        return owner.stage(phase, stage, **arguments)

    def complete(self, owner):
        held = []
        while owner.next_stage is not None:
            phase, name = owner.next_stage
            with self.stage(owner, phase, name) as stage:
                held.append(stage)
                if stage.acquisition is not None:
                    acquire(stage, self.cursor, self.trace)
                else:
                    encode_and_hash(stage, len(held) - 1)
                owner._chain.perform(phase, name)
                stage.check()
        return held

    def assert_poisoned(self, owner):
        with self.assertRaises(compound.ChallengeCompoundError):
            with self.stage(owner):
                self.fail("failed owner admitted another allowance")
        with self.assertRaises(compound.ChallengeCompoundError):
            owner.finish()

    def test_source_schedule_reports_all_actual_work_and_acquisition_totals(self):
        self.assertEqual(compound.PHASES, PHASES)
        binding = compound.schedule_binding()
        self.assertEqual(binding["schema"], "serverware.policyAuthorityChallengeCompoundSchedule/v2")
        self.assertEqual(binding["sourceRevision"], contract.SOURCE_REVISION)
        self.assertEqual(binding["passes"], 1)
        self.assertEqual(binding["stageLimits"], {
            "hashes": MAX_HASHES, "inputBytes": MAX_INPUT_BYTES, "jsonNodes": MAX_JSON_NODES})
        self.assertEqual(binding["writeIndexes"], list(compound.WRITE_IDS))
        binding["phases"].clear()
        self.assertEqual(compound.schedule_binding()["phases"], list(PHASES))
        owner = self.owner()
        held = self.complete(owner)
        result = owner.finish()
        self.assertEqual(owner._deadline, 1000)
        self.assertEqual(len(held), 94)
        self.assertEqual(len({id(stage.work) for stage in held}), len(held))
        totals = [0, 0, 0]
        for ordinal, (record, stage) in enumerate(zip(result.stages, held)):
            self.assertEqual(record.ordinal, ordinal)
            if stage.acquisition is not None:
                self.assertEqual(record.work, compound.QueryReadValidationMetrics(0, 50, 8))
                self.assertEqual(record.acquisition, compound.AcquisitionMetrics(1, 1, 20, 21))
            else:
                size = len(json.dumps({"ordinal": ordinal}, sort_keys=True, separators=(",", ":")).encode())
                self.assertEqual(record.work, compound.QueryReadValidationMetrics(1, 3 * size, 6))
                self.assertIsNone(record.acquisition)
            totals = [total + value for total, value in zip(totals,
                (record.work.hash_work, record.work.input_bytes, record.work.json_nodes))]
        self.assertEqual(result.total_work, compound.QueryReadValidationMetrics(*totals))
        self.assertEqual(result.total_acquisition, compound.AcquisitionMetrics(9, 9, 180, 189))
        self.assertEqual(len(self.cursor.executions), 9)
        self.assertEqual(self.cursor.fetches, [2] * 9)
        self.assert_poisoned(owner)

    def test_observation_seam_fixes_row_and_physical_page_order(self):
        owner = self.owner(ChainDouble({"pre-expire": 2, "scope": 1}, scope_enabled=True))
        self.complete(owner)
        result = owner.finish()
        first = [record.stage for record in result.stages if record.phase == "pre-expire"]
        self.assertEqual([name for name in first if name.startswith("primary-")],
            [name + ":" + str(row) for row in range(2)
                for name in ("primary-acquire", "primary-rebase", "primary-proof")])
        for index in compound.WRITE_IDS:
            self.assertEqual([name for name in first if index in name],
                ["write-geometry:" + index,
                 "write-acquire:" + index + ":0", "write-rebase:" + index + ":0",
                 "write-acquire:" + index + ":1", "write-rebase:" + index + ":1",
                 "write-proof:" + index])
        scoped = [record.stage for record in result.stages if record.phase == "scope"]
        self.assertIn("range-proof", scoped)
        self.assertFalse(any(name.startswith("write-") for name in scoped))

    def test_scope_overflow_has_no_partial_rows_or_range_allowance(self):
        owner = self.owner(ChainDouble({"scope": 255}, scope_enabled=True, scope_overflow=True))
        self.complete(owner)
        scoped = [record.stage for record in owner.finish().stages if record.phase == "scope"]
        self.assertEqual(scoped, ["count-acquire:scope_replacement_count",
            "count-proof:scope_replacement_count", "phase-open", "phase-close"])
        owner = self.owner(ChainDouble(scope_enabled=True))
        self.complete(owner)
        scoped = [record.stage for record in owner.finish().stages if record.phase == "scope"]
        self.assertIn("range-acquire", scoped)

    def test_missing_row_progress_cannot_obtain_the_next_allowance(self):
        owner = self.owner(ChainDouble({"pre-expire": 2}))
        while owner.next_stage != ("pre-expire", "primary-proof:0"):
            phase, name = owner.next_stage
            with self.stage(owner):
                owner._chain.perform(phase, name)
        with self.assertRaises(compound.ChallengeCompoundError):
            with self.stage(owner):
                pass
        self.assert_poisoned(owner)

    def test_late_closed_ledger_changes_poison_finish_permanently(self):
        owner = self.owner()
        held = self.complete(owner)
        held[0].work.charge(hashes=1)
        with self.assertRaises(compound.ChallengeCompoundError):
            owner.finish()
        self.assert_poisoned(owner)

    def test_skipped_repeated_extra_and_caught_nested_stages_poison_owner(self):
        for mode in ("skip", "repeat", "extra", "nested"):
            with self.subTest(mode=mode):
                owner = self.owner()
                with self.assertRaises(compound.ChallengeCompoundError):
                    if mode == "skip":
                        with self.stage(owner, stage="phase-open"):
                            self.fail("skipped acquisition was accepted")
                    elif mode == "repeat":
                        with self.stage(owner):
                            pass
                        with self.stage(owner, stage="count-acquire:expired_remaining"):
                            self.fail("repeated acquisition was accepted")
                    elif mode == "extra":
                        self.complete(owner)
                        with self.stage(owner, "admission", "phase-close"):
                            self.fail("extra allowance was accepted")
                    else:
                        with self.stage(owner):
                            with self.assertRaises(compound.ChallengeCompoundError):
                                with self.stage(owner):
                                    self.fail("nested allowance was accepted")
                            # Catching the inner refusal must not rescue the outer stage.
                self.assert_poisoned(owner)

    def test_actual_counter_snapshots_cannot_be_reset_or_exceeded(self):
        counters = (("work", "hash_work", MAX_HASHES), ("work", "input_bytes", MAX_INPUT_BYTES),
            ("work", "json_nodes", MAX_JSON_NODES),
            ("acquisition", "sql_reads", reader.MAX_CUMULATIVE_SQL_READS),
            ("acquisition", "returned_rows", reader.MAX_CUMULATIVE_SQL_READS * reader.MAX_NODE_IDENTITIES),
            ("acquisition", "parameter_bytes", reader.MAX_PARAMETER_BYTES),
            ("acquisition", "transport_bytes", reader.MAX_TRANSPORT_BYTES))
        for target, field, maximum in counters:
            for replacement in (0, maximum + 1, True):
                with self.subTest(target=target, field=field, replacement=replacement):
                    owner = self.owner()
                    with self.assertRaises(compound.ChallengeCompoundError):
                        with self.stage(owner) as stage:
                            acquire(stage, self.cursor, self.trace)
                            encode_and_hash(stage, 0)
                            stage.check()  # Genuine spent counters are now observed.
                            self.assertGreater(getattr(getattr(stage, target), field), 0)
                            setattr(getattr(stage, target), field, replacement)
                            stage.check()
                    self.assert_poisoned(owner)

    def test_replaced_work_limits_and_acquisition_identity_are_refused(self):
        changes = (
            lambda stage: setattr(stage, "work", _ValidationWork(QueryReadValidationLimits())),
            lambda stage: setattr(stage.work, "limits", QueryReadValidationLimits()),
            lambda stage: setattr(stage, "acquisition", reader._ReadAcquisitionBudget(
                self.cursor, self.trace, work=stage.work)),
            lambda stage: setattr(stage.acquisition, "limits", reader._ReadAcquisitionLimits()),
            lambda stage: setattr(stage.acquisition, "work", _ValidationWork(QueryReadValidationLimits())),
            lambda stage: setattr(stage.acquisition, "cursor", CursorDouble()),
            lambda stage: setattr(stage.acquisition, "trace", TraceDouble()),
        )
        for ordinal, change in enumerate(changes):
            with self.subTest(replacement=ordinal):
                owner = self.owner()
                with self.assertRaises(ValueError):
                    with self.stage(owner) as stage:
                        change(stage)
                        stage.check()
                self.assert_poisoned(owner)

    def test_original_deadline_backward_clock_and_process_identity_are_retained(self):
        for now in (1000, 1001, 9, True):
            with self.subTest(now=now):
                self.clock.return_value = 10
                owner = self.owner()
                with self.assertRaises(compound.ChallengeCompoundError):
                    with self.stage(owner):
                        self.clock.return_value = now
                self.clock.return_value = 10
                self.assertEqual(owner._deadline, 1000)
                self.assert_poisoned(owner)
        for boundary in (compound.os, compound.threading):
            owner = self.owner()
            method = "getpid" if boundary is compound.os else "get_ident"
            with mock.patch.object(boundary, method, return_value=-1):
                with self.assertRaises(compound.ChallengeCompoundError):
                    with self.stage(owner):
                        self.fail("different process/thread was accepted")
            self.assert_poisoned(owner)

    def test_cancellation_preserves_original_exception_and_poisoning(self):
        class Cancelled(BaseException):
            pass
        for failure in (Cancelled("synthetic cancellation"), KeyboardInterrupt(), SystemExit(7)):
            with self.subTest(kind=type(failure).__name__):
                owner = self.owner()
                with self.assertRaises(type(failure)) as caught:
                    with self.stage(owner):
                        raise failure
                self.assertIs(caught.exception, failure)
                self.assert_poisoned(owner)

    def test_incomplete_finish_close_and_borrowed_stage_never_close_cursor(self):
        owner = self.owner()
        with self.assertRaises(compound.ChallengeCompoundError):
            owner.finish()
        self.assert_poisoned(owner)
        owner = self.owner()
        owner.close()
        owner.close()
        self.assert_poisoned(owner)
        owner = self.owner()
        with self.assertRaises(compound.ChallengeCompoundError):
            with self.stage(owner):
                owner.close()
        self.assert_poisoned(owner)
        owner = self.owner()
        with self.stage(owner) as held:
            acquire(held, self.cursor, self.trace)
        with self.assertRaises(compound.ChallengeCompoundError):
            held.check()
        self.assert_poisoned(owner)


if __name__ == "__main__":
    unittest.main()
