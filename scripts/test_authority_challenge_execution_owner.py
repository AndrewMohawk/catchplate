#!/usr/bin/env python3
"""UNRUN source/inert controls; no successful native SQL or witness fiction."""
from __future__ import annotations

import inspect
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from serverware import authority_challenge_execution_owner as owner
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork


def settings():
    return dict(dsn="postgresql://metadata.invalid/authority", connect_timeout_seconds=2,
        tls_client_dn="CN=synthetic-source-control", tls_client_serial="01", tls_issuer_dn="CN=synthetic-ca",
        query_manifest_digest="sha256:" + "1" * 64, expected_structure_manifest_digest="sha256:" + "2" * 64)


def work():
    return _ValidationWork(QueryReadValidationLimits())


class MaintenanceOwnerControls(unittest.TestCase):
    def test_configuration_is_inert_and_closed_to_distinct_source_role(self):
        with mock.patch.object(owner.connection, "_run_on_configuration", side_effect=AssertionError("native IO")) as call:
            issued = owner.MaintenanceExecutionIssuer(**settings())
            self.assertEqual(issued._configured[2], owner.contract.ISSUER_ROLE)
            self.assertFalse(issued._active)
            self.assertFalse(issued._failed)
            call.assert_not_called()
        for field, value in (("connect_timeout_seconds", True), ("dsn", "bad\nDSN"),
                ("expected_structure_manifest_digest", "not-a-digest")):
            with self.subTest(field=field), self.assertRaises((ValueError, RuntimeError)):
                owner.MaintenanceExecutionIssuer(**dict(settings(), **{field: value}))

    def test_actual_owner_guard_is_neutral_and_reentry_or_pin_replacement_refuses(self):
        issued = owner.MaintenanceExecutionIssuer(**settings())
        configured, held = owner._enter(issued, owner.MaintenanceExecutionIssuer, owner.contract.ISSUER_ROLE)
        meter = work()
        before = meter.metrics
        self.assertIsNone(held(meter))
        self.assertEqual(meter.metrics, before)
        with self.assertRaises(owner.ChallengeExecutionOwnerError):
            owner._enter(issued, owner.MaintenanceExecutionIssuer, owner.contract.ISSUER_ROLE)
        issued._configured = tuple(list(configured))
        with self.assertRaises(owner.ChallengeExecutionOwnerError):
            held(meter)

    def test_bad_originals_poison_issuer_before_any_database_callback(self):
        issued = owner.MaintenanceExecutionIssuer(**settings())
        values = dict(originals=(), expectations={}, planner_public_key=None,
            enrollment_bytes=b"{}", root_public_key=None, reserve_request_bytes=b"{}",
            reserve_receipt_bytes=b"{}", snapshot_bytes=b"{}", grant_bytes=b"{}",
            grant_enrollment_bytes=b"{}", expected_authorization_digest="sha256:" + "3" * 64,
            expected_database_id="test", expected_generation_digest="sha256:" + "4" * 64,
            expected_pending_sequence=1, expected_pending_head_digest="sha256:" + "5" * 64,
            expected_fence=1, live_window=(), read_original=lambda *_args: b"{}",
            check=lambda _stage: None, work=work())
        with mock.patch.object(owner.connection, "_run_on_configuration", side_effect=AssertionError("native IO")) as call:
            with self.assertRaises(owner.ChallengeExecutionOwnerError):
                issued.issue(**values)
            self.assertTrue(issued._failed)
            self.assertFalse(issued._active)
            with self.assertRaises(owner.ChallengeExecutionOwnerError):
                issued.issue(**values)
            call.assert_not_called()

    def test_executor_requires_actual_attempt_owner_not_a_matching_dto(self):
        class Verdict:
            structure_manifest_digest = settings()["expected_structure_manifest_digest"]
        with self.assertRaises(owner.ChallengeExecutionOwnerError):
            owner.MaintenanceExecutionExecutor(**settings(), attempt_owner=Verdict())

    def test_public_apis_never_admit_packet_mutations_or_success_observations(self):
        issuer = set(inspect.signature(owner.MaintenanceExecutionIssuer.issue).parameters)
        executor = set(inspect.signature(owner.MaintenanceExecutionExecutor.execute).parameters)
        self.assertFalse({"packet_bytes", "prepared", "mutations", "result", "after_roots"} & issuer)
        self.assertEqual(executor, {"self", "pending_decision_digest", "packet_digest",
            "live_window", "original_deadline_ns", "work"})
        source = inspect.getsource(owner.MaintenanceExecutionIssuer.issue)
        self.assertEqual(source.count("packet._prepare_on_work("), 1)
        self.assertLess(source.index("packet._prepare_on_work("), source.index("session.seal("))
        self.assertIn("work=stage.work", source)
        execute = inspect.getsource(owner.MaintenanceExecutionExecutor.execute)
        self.assertLess(execute.index("._claim_on_work("), execute.index("connection._run_on_configuration("))
        self.assertNotIn(".commit(", source + execute)
        self.assertNotIn("_ValidationWork(", inspect.getsource(owner))


if __name__ == "__main__":
    unittest.main()
