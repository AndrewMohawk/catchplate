"""Two-pass component controls, not native PostgreSQL/TLS admission.

The component fixture bypasses ONLY the public constructor's exact psycopg
type gate. Its cursor/transaction and SQL acquisition are explicit doubles.
Actual owner ordering, original-transaction query decoding, ledgers and the
complete history proof engine run against independently constructed proofs.
"""
from __future__ import annotations

import hashlib
import os
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

from serverware import authority_recovery_history_acquisition as acquisition
from serverware import authority_recovery_history as history
from serverware.authority_index_contract import CountedNode
from serverware.authority_index_heads import CapturedIndexHead
from test_authority_recovery_history import Fixture, credential


class CursorDouble:
    def __init__(self, connection):
        self.connection, self.closed, self.closes = connection, False, 0
        self.row = dict(server_version_num=160006, backend_pid=123,
            virtual_transaction="3/123", transaction_isolation="serializable",
            transaction_read_only="on", transaction_deferrable="on", statement_timeout="1s",
            lock_timeout="1s", idle_in_transaction_session_timeout="1s")
        self.calls = []

    def execute(self, sql, parameters):
        if sql != acquisition.transaction_source._TRANSACTION_SQL or parameters != ():
            raise AssertionError("component cursor only handles the fixed transaction query")
        self.calls.append(sql)
        return self

    def fetchmany(self, maximum):
        if maximum != 2:
            raise AssertionError("transaction query changed its bounded fetch")
        return [self.row.copy()]

    def close(self):
        self.closes += 1
        raise AssertionError("borrowed cursor must not close")


def component_owner(fixture):
    # Not a successful native admission substitute: public construction with
    # these same doubles is explicitly refused in a separate control.
    owner = acquisition.HistoryAcquisition.__new__(acquisition.HistoryAcquisition)
    connection = SimpleNamespace(closed=False, autocommit=False, pgconn=object(),
        info=SimpleNamespace(transaction_status=2), _num_transactions=1)
    cursor = CursorDouble(connection)
    transaction = SimpleNamespace(connection=connection, pgconn=connection.pgconn,
        _entered=True, _exited=False, _outer_transaction=True, _stack_index=0)
    owner._cursor, owner._connection, owner._transaction = cursor, connection, transaction
    owner._physical, owner._check = connection.pgconn, lambda: None
    owner._held = cursor, connection, transaction, connection.pgconn, owner._check, 1000
    owner._deadline, owner._clock = 1000, 0
    owner._process = os.getpid(), threading.get_ident()
    owner._failed = owner._closed = owner._busy = False
    owner._state, owner._original_transaction = "new", None
    owner._operation, owner._phases = "webauthn.recovery.create", []
    owner._first = acquisition._Phase(owner, 0, "count", 0)
    arguments = dict(operation=owner._operation, user_id="target", cutoff_us=1,
        maximum_count=1000, maximum_bytes=4 * 1024 * 1024,
        primary_root=fixture.primary.root.json_projection(), index_head=fixture.head)
    context, owner._root, owner._profile, owner._counted, owner._whole = history._context(
        **arguments, work=owner._first.work)
    owner._context = context
    head = context["indexHead"]
    owner._head = CapturedIndexHead(head["indexId"], head["table"], head["countedProfile"],
        head["projectionDigest"], head["projectionManifestDigest"], head["indexRevision"],
        CountedNode(head["rootDigest"], head["rootCount"]))
    owner._anchors = (owner._operation, owner._context, owner._root, owner._profile,
        owner._counted, owner._whole, owner._head, owner._first.work.wire(context))
    owner._external(owner._first, owner._check)
    return owner, arguments


class HistoryAcquisitionTests(unittest.TestCase):
    def setUp(self):
        clock_patch = mock.patch.object(acquisition.time, "monotonic_ns", return_value=10)
        self.clock = clock_patch.start()
        self.addCleanup(clock_patch.stop)
        self.fixture = Fixture()
        self.reads = []
        def emit(kind, cursor, **arguments):
            ordinal = arguments.get("ordinal", 0)
            self.reads.append((kind, ordinal))
            raw = self.fixture.count_body if kind == "count" else self.fixture.pages[ordinal]
            # This source boundary is doubled; no successful SQL is claimed.
            # Spend actual hash work while the genuine proof engine below
            # independently validates every returned synthetic original.
            arguments["work"].charge(hashes=1, input_bytes=len(raw))
            hashlib.sha256(raw).digest()
            return raw
        for name, kind in (("acquire_history_count", "count"), ("acquire_history_page", "row")):
            patcher = mock.patch.object(acquisition.capture, name,
                side_effect=lambda cursor, _kind=kind, **kwargs: emit(_kind, cursor, **kwargs))
            patcher.start()
            self.addCleanup(patcher.stop)

    def checked(self):
        owner, arguments = component_owner(self.fixture)
        owner.assert_context(**arguments)
        return owner

    def assert_poisoned(self, owner):
        with self.assertRaises(acquisition.HistoryAcquisitionError):
            owner.produce()
        with self.assertRaises(acquisition.HistoryAcquisitionError):
            owner.retain(lambda *args: None)
        self.assertEqual(owner._cursor.closes, 0)

    def test_two_real_proof_passes_match_bytes_and_report_actual_fragment_totals(self):
        owner = self.checked()
        manifest, observation = owner.produce()
        self.assertEqual(manifest, self.fixture.manifest())
        self.assertEqual(observation.digest, self.fixture.verify().digest)
        # The returned manifest is not the owner's retained private graph.
        manifest["pages"].clear()
        retained = []
        def consume(kind, ordinal, raw, descriptor):
            retained.append((kind, ordinal, raw, descriptor))
        result = owner.retain(consume)
        self.assertEqual(self.reads, [("count", 0), ("row", 0), ("row", 1)] * 2)
        self.assertEqual([(kind, ordinal, raw) for kind, ordinal, raw, _ in retained],
            [("count", 0, self.fixture.count_body), ("row", 0, self.fixture.pages[0]),
             ("row", 1, self.fixture.pages[1])])
        self.assertEqual([(phase.pass_ordinal, phase.kind, phase.ordinal) for phase in result.phases],
            [(run, kind, ordinal) for run in (0, 1) for kind, ordinal in (("count", 0), ("row", 0), ("row", 1))])
        self.assertEqual(result.sql_reads, len(owner._cursor.calls))
        self.assertEqual(result.sql_reads, sum(phase.trace_entries for phase in result.phases))
        for name in ("hash_work", "input_bytes", "json_nodes"):
            self.assertEqual(getattr(result.total_work, name), sum(getattr(phase.work, name) for phase in result.phases))
        for name in ("returned_rows", "parameter_bytes", "transport_bytes"):
            self.assertEqual(getattr(result, name), sum(getattr(phase, name) for phase in result.phases))
        self.assertTrue(all(phase.trace_digest.startswith("sha256:") for phase in result.phases))
        self.assertEqual(owner._deadline, 1000)
        self.assert_poisoned(owner)

    def test_changed_second_pass_bytes_fail_before_delivery(self):
        owner = self.checked()
        owner.produce()
        self.fixture.pages[0] += b"\n"
        delivered = []
        with self.assertRaises(acquisition.HistoryAcquisitionError):
            owner.retain(lambda kind, ordinal, raw, descriptor: delivered.append((kind, ordinal)))
        self.assertEqual(delivered, [("count", 0)])
        self.assert_poisoned(owner)

    def test_original_virtual_transaction_settings_deadline_and_context_are_required(self):
        for field, changed in (("virtual_transaction", "3/124"),
                ("transaction_read_only", "off"), ("transaction_deferrable", "off"),
                ("statement_timeout", "2s")):
            with self.subTest(field=field):
                owner = self.checked()
                owner._cursor.row[field] = changed
                with self.assertRaises(ValueError):
                    owner.produce()
                self.assert_poisoned(owner)
        owner, arguments = component_owner(self.fixture)
        with self.assertRaises(acquisition.HistoryAcquisitionError):
            owner.assert_context(**dict(arguments, cutoff_us=2))
        self.assert_poisoned(owner)
        owner, arguments = component_owner(Fixture([credential("only")]))
        changed_root = dict(arguments["primary_root"], leafCount=True)
        with self.assertRaises(ValueError):
            owner.assert_context(**dict(arguments, primary_root=changed_root))
        self.assert_poisoned(owner)
        owner = self.checked()
        self.clock.return_value = 1000
        with self.assertRaises(acquisition.HistoryAcquisitionError):
            owner.produce()
        self.clock.return_value = 10
        self.assert_poisoned(owner)
        for change in (lambda owner: setattr(owner, "_deadline", 2000),
                       lambda owner: owner._context.update(cutoffUs=2)):
            owner = self.checked()
            change(owner)
            with self.assertRaises(acquisition.HistoryAcquisitionError):
                owner.produce()
            self.assert_poisoned(owner)

    def test_caught_reentry_cancellation_and_replaced_ledger_poison_without_closing(self):
        owner = self.checked()
        owner.produce()
        def nested(*args):
            with self.assertRaises(acquisition.HistoryAcquisitionError):
                owner.retain(lambda *unused: None)
        with self.assertRaises(acquisition.HistoryAcquisitionError):
            owner.retain(nested)
        self.assert_poisoned(owner)
        owner = self.checked()
        owner.produce()
        failure = KeyboardInterrupt()
        def cancel(*args):
            raise failure
        with self.assertRaises(KeyboardInterrupt) as caught:
            owner.retain(cancel)
        self.assertIs(caught.exception, failure)
        self.assert_poisoned(owner)
        owner = self.checked()
        owner._first.work.limits = acquisition.QueryReadValidationLimits()
        with self.assertRaises(acquisition.HistoryAcquisitionError):
            owner.produce()
        self.assert_poisoned(owner)

    def test_public_constructor_rejects_component_doubles(self):
        owner, arguments = component_owner(self.fixture)
        with self.assertRaises(acquisition.HistoryAcquisitionError):
            acquisition.HistoryAcquisition(cursor=owner._cursor, connection=owner._connection,
                transaction=owner._transaction, original_deadline_ns=1000, check=lambda: None, **arguments)
        self.assertEqual(owner._cursor.closes, 0)


if __name__ == "__main__":
    unittest.main()
