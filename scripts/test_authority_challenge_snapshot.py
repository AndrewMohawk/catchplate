"""Real empty-root proof passes with explicit native-SQL component doubles.

Only the public constructor's native psycopg gate is bypassed in the private
fixture, and that constructor is separately shown to reject these doubles.
No source proof engine, pass, chain, trace, meter or guard is replaced. Empty
SQL node observations are replayed against independently constructed genuine
empty primary/counting roots; this is not PostgreSQL/TLS/currentness evidence.
"""
from __future__ import annotations

import hashlib
import os
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

from catchplate import authority_challenge_snapshot as snapshot
from test_authority_challenge_manifest import context


class CursorDouble:
    def __init__(self, connection):
        self.connection, self.closed, self.closes = connection, False, 0
        self.owner = None
        self.calls, self.results = [], []
        self.transaction_row = dict(server_version_num=160006, backend_pid=123,
            virtual_transaction="3/123", transaction_isolation="serializable",
            transaction_read_only="on", transaction_deferrable="on", statement_timeout="1s",
            lock_timeout="1s", idle_in_transaction_session_timeout="1s")

    def execute(self, sql, parameters):
        stage = self.owner._current[0]
        if stage.acquisition is None:
            raise AssertionError("proof-only stage attempted SQL")
        self.calls.append((self.owner._pass_ordinal, self.owner._compound._position, sql, parameters))
        if sql == snapshot.transaction_source._TRANSACTION_SQL and parameters == ():
            self.results = [self.transaction_row.copy()]
        elif (sql.startswith(f'SELECT {snapshot.reader._NODE_SELECT} FROM '
                f'"catchplate_metadata"."{snapshot.reader.NODE_TABLE}" AS node JOIN (VALUES ')
                and parameters[-2] in snapshot.compounds.WRITE_IDS
                and type(parameters[-1]) is int and 1 <= parameters[-1] <= 257):
            self.results = []
        else:
            raise AssertionError("empty-root component received an unexpected physical query")
        return self

    def fetchmany(self, maximum):
        if type(maximum) is not int or not 1 <= maximum <= 257:
            raise AssertionError("physical fetch lost its source row bound")
        return self.results[:maximum]

    def close(self):
        self.closes += 1
        raise AssertionError("snapshot borrower must not close the caller's cursor")


def component_owner(*, check=None):
    owner = snapshot.MaintenanceAcquisition.__new__(snapshot.MaintenanceAcquisition)
    connection = SimpleNamespace(closed=False, autocommit=False, pgconn=object(),
        info=SimpleNamespace(transaction_status=2), _num_transactions=1)
    cursor = CursorDouble(connection)
    transaction = SimpleNamespace(connection=connection, pgconn=connection.pgconn,
        _entered=True, _exited=False, _outer_transaction=True, _stack_index=0)
    owner._cursor, owner._connection, owner._transaction = cursor, connection, transaction
    owner._physical = connection.pgconn
    owner._check_callback = (lambda: None) if check is None else check
    owner._held = cursor, connection, transaction, connection.pgconn, owner._check_callback
    owner._process = os.getpid(), threading.get_ident()
    owner._failed = owner._closed = owner._busy = False
    owner._state, owner._clock, owner._original_transaction = "new", 0, None
    owner._current = owner._compound = owner._chain = owner._manifest = None
    owner._proxy = snapshot._Cursor(owner)
    owner._proxy_original = owner._proxy
    owner._records = []
    owner._initial = snapshot._ValidationWork(snapshot.QueryReadValidationLimits())
    owner._initial_limits = owner._initial.limits
    caller_context = context()
    caller_context["originalDeadlineNs"] = 1000
    owner._context = snapshot.manifests._context(caller_context, owner._initial)
    owner._context_bytes = owner._initial.wire(owner._context)
    owner._deadline = owner._original_deadline = 1000
    cursor.owner = owner
    owner._local()
    return owner, caller_context


class ChallengeSnapshotTests(unittest.TestCase):
    def setUp(self):
        patch = mock.patch.object(snapshot.time, "monotonic_ns", return_value=10)
        self.clock = patch.start()
        self.addCleanup(patch.stop)

    def poisoned(self, owner):
        with self.assertRaises(snapshot.ChallengeSnapshotError):
            owner.produce()
        with self.assertRaises(snapshot.ChallengeSnapshotError):
            owner.retain(lambda *args: None)
        self.assertEqual(owner._cursor.closes, 0)

    def test_two_actual_source_passes_replay_same_snapshot_and_close_exact_metrics(self):
        owner, caller_context = component_owner()
        caller_context["userId"] = "changed caller-owned value"
        first = owner.produce()
        self.assertFalse(first.decision.pruning_pending)
        self.assertFalse(first.decision.replacement_overflow)
        self.assertEqual(first.decision.primary_after.leaf_count, 0)
        first.manifest["groups"].clear()  # Not the owner's private commitment.
        retained = []
        def consume(phase, kind, index_id, ordinal, raw, descriptor, stage):
            self.assertIs(type(raw), bytes)
            self.assertEqual(descriptor, {"byteCount": len(raw),
                "digest": "sha256:" + hashlib.sha256(raw).hexdigest()})
            retained.append((phase, kind, index_id, ordinal))
        second, measured = owner.retain(consume)
        self.assertEqual(second.decision, first.decision)
        self.assertEqual(len(second.manifest["groups"]), 89)
        self.assertEqual(retained, [(phase, "count", "", ordinal)
            for phase in (0, 1, 2, 4, 5, 6, 7)
            for ordinal in range(3 if phase == 7 else 1)])
        self.assertEqual(tuple(record.pass_ordinal for record in measured.passes), (0, 1))
        self.assertEqual(measured.total_acquisition.sql_reads, len(owner._cursor.calls))
        self.assertEqual(measured.total_acquisition.sql_reads,
            sum(record.trace.sql_reads for record in measured.passes))
        for record in measured.passes:
            self.assertEqual(record.trace.fragments,
                sum(stage.acquisition is not None for stage in record.stages.stages))
            self.assertTrue(record.trace.chain_digest.startswith("sha256:"))
            self.assertGreater(record.initial_work.input_bytes, 0)
        for name in ("hash_work", "input_bytes", "json_nodes"):
            self.assertEqual(getattr(measured.total_work, name), sum(
                getattr(record.initial_work, name) + getattr(record.stages.total_work, name)
                for record in measured.passes))
        self.assertEqual(owner._deadline, 1000)
        self.poisoned(owner)

    def test_virtual_transaction_and_native_outer_identity_cannot_change_between_passes(self):
        for change in (lambda owner: owner._cursor.transaction_row.update(virtual_transaction="3/124"),
                lambda owner: owner._cursor.transaction_row.update(transaction_read_only="off"),
                lambda owner: owner._cursor.transaction_row.update(transaction_deferrable="off"),
                lambda owner: setattr(owner._transaction, "_exited", True),
                lambda owner: setattr(owner._connection, "pgconn", object())):
            with self.subTest(change=change):
                owner, _ = component_owner()
                owner.produce()
                change(owner)
                delivered = []
                with self.assertRaises(ValueError):
                    owner.retain(lambda *args: delivered.append(args))
                self.assertEqual(delivered, [])
                self.poisoned(owner)

    def test_original_context_deadline_and_first_pass_decision_remain_bound(self):
        for change in (lambda owner: owner._context.update(configurationDigest="sha256:" + "d" * 64),
                lambda owner: setattr(owner, "_deadline", 2000),
                lambda owner: setattr(owner, "_first_decision", b"changed")):
            with self.subTest(change=change):
                owner, _ = component_owner()
                owner.produce()
                change(owner)
                with self.assertRaises(ValueError):
                    owner.retain(lambda *args: None)
                self.poisoned(owner)
        owner, _ = component_owner()
        self.clock.return_value = 1000
        with self.assertRaises(snapshot.ChallengeSnapshotError):
            owner.produce()
        self.assertEqual(owner._cursor.calls, [])

    def test_retention_callback_descriptor_verdict_reentry_and_cancel_poison_owner(self):
        def changed_descriptor(*arguments):
            arguments[5]["byteCount"] += 1
        for callback in (changed_descriptor, lambda *args: True):
            owner, _ = component_owner()
            owner.produce()
            with self.assertRaises(snapshot.ChallengeSnapshotError):
                owner.retain(callback)
            self.poisoned(owner)
        owner, _ = component_owner()
        owner.produce()
        def reenter(*args):
            with self.assertRaises(snapshot.ChallengeSnapshotError):
                owner.retain(lambda *unused: None)
        with self.assertRaises(snapshot.ChallengeSnapshotError):
            owner.retain(reenter)
        self.poisoned(owner)
        owner, _ = component_owner()
        owner.produce()
        cancellation = KeyboardInterrupt()
        def cancel(*args):
            raise cancellation
        with self.assertRaises(KeyboardInterrupt) as caught:
            owner.retain(cancel)
        self.assertIs(caught.exception, cancellation)
        self.poisoned(owner)

    def test_proof_only_stages_cannot_start_sql_and_original_ledgers_cannot_be_replaced(self):
        holder = {}
        def attempt_read():
            owner = holder["owner"]
            if owner._current[3] is None:
                with self.assertRaises(snapshot.ChallengeSnapshotError):
                    owner._proxy.execute(snapshot.transaction_source._TRANSACTION_SQL, ())
        owner, _ = component_owner(check=attempt_read)
        holder["owner"] = owner
        with self.assertRaises(snapshot.ChallengeSnapshotError):
            owner.produce()
        self.poisoned(owner)
        owner, _ = component_owner()
        owner._initial.limits = snapshot.QueryReadValidationLimits()
        with self.assertRaises(snapshot.ChallengeSnapshotError):
            owner.produce()
        self.assertEqual(owner._cursor.calls, [])
        self.poisoned(owner)

    def test_public_constructor_refuses_doubles_and_retention_cannot_precede_production(self):
        owner, selected = component_owner()
        with self.assertRaises(snapshot.ChallengeSnapshotError):
            snapshot.MaintenanceAcquisition(cursor=owner._cursor, connection=owner._connection,
                transaction=owner._transaction, context=selected, check=lambda: None)
        with self.assertRaises(snapshot.ChallengeSnapshotError):
            owner.retain(lambda *args: None)
        self.poisoned(owner)


if __name__ == "__main__":
    unittest.main()
