#!/usr/bin/env python3
"""Native-JIT retention joins, not native admission or database acceptance.

Fixtures use genuine synthetic encryption/signatures from the custody suite,
but these tests exercise only public/sealed retention grammar and integrity.
The real executor functions stop at a writer sentinel or an inert cursor before
INSERT; PostgreSQL, native owners, services and deployment are not exercised.
No crypto admission is mocked as a successful native verdict.
"""
from __future__ import annotations

import base64
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
_external = []


def no_external_effects(event, _arguments):
    if event.startswith(("socket.", "sqlite3.")) or event in {
            "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn"}:
        _external.append(event)
        raise AssertionError("retention component tests forbid external effects")


if __name__ == "__main__":
    os.environ["SERVERWARE_PROCESS_MODE"] = "metadata-bootstrap"
    os.environ["SERVERWARE_RELEASE_CHANNEL"] = "dev"
    sys.addaudithook(no_external_effects)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from scripts import test_authority_native_jit_review_custody as synthetic
from scripts import test_authority_release_private_input as legacy
from serverware import authority_native_jit_submission as submission
from serverware import authority_release_private_input as privacy
from serverware import native_jit_review_material as material
from serverware.authority_store import executor_v9 as executor
from serverware.authority_store import native_jit_retention as retention

NOW, MONO, SECOND = synthetic.NOW, synthetic.MONO, synthetic.SECOND
PIN = "sha256:" + "a" * 64
ABSENT = object()


def canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
        separators=(",", ":")).encode("ascii")


def originals(fixture):
    return {"parentOriginal": canonical(fixture.parent).decode("ascii"),
        "childOriginal": canonical(fixture.child).decode("ascii"),
        "pairOriginal": canonical(fixture.pair).decode("ascii"),
        "evidenceOriginal": canonical(fixture.proof).decode("ascii")}


def partial_payload(fixture, retained=ABSENT):
    # Deliberately incomplete: these tests must not manufacture a valid signed
    # plan, SQL mutation, native startup or successful writer admission.
    return {"schema": "serverware.policyAuthorityPlannerResponse/v3",
        "typedRequest": copy.deepcopy(fixture.parent),
        "measuredPlan": {"operation": "release.reserve", "deadlineEpochNs": NOW + 20 * SECOND},
        **({} if retained is ABSENT else {"nativeJitPending": copy.deepcopy(retained)})}


def retained_row(payload, raw=None):
    original = canonical(payload) if raw is None else raw
    return {"exact_plan_base64url": base64.urlsafe_b64encode(original).rstrip(b"=").decode("ascii"),
        "exact_plan_bytes_digest": "sha256:" + hashlib.sha256(original).hexdigest(),
        "exact_plan_byte_count": len(original)}


class WriterReached(Exception):
    """Terminal observation before real writer admission, never its success."""


class InsertReached(Exception):
    """Inert-cursor terminal before INSERT, never an executed SQL statement."""


class LockedPlannerCursor:
    def __init__(self, row):
        self.row, self.statements = row, []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, statement, _values):
        if statement.startswith("INSERT INTO serverware_metadata.policy_authority_execution_envelopes"):
            raise InsertReached()
        self.statements.append(statement)
        if statement != ("SELECT * FROM serverware_metadata.policy_authority_planner_transactions "
                "WHERE planner_transaction_id = %s FOR UPDATE"):
            raise AssertionError("unexpected statement in inert cursor")
        return self

    def fetchone(self):
        return copy.deepcopy(self.row)


class NativeJitExecutorRetentionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki = synthetic.SyntheticNitro()

    def setUp(self):
        self.fixture = synthetic.Fixture(self.pki)
        self.retained = originals(self.fixture)
        self.clock = patch.object(executor.time, "time_ns", return_value=NOW)
        self.monotonic = patch.object(executor.time, "monotonic_ns", return_value=MONO)
        self.clock.start(); self.monotonic.start()
        self.addCleanup(self.clock.stop); self.addCleanup(self.monotonic.stop)

    def tearDown(self):
        self.assertEqual(_external, [], "an external-effect refusal is never a passing negative")

    def locked(self, row=None, retained=None, typed=None, deadline=NOW + 20 * SECOND):
        return retention.require_locked_plan(row or retained_row(partial_payload(self.fixture, self.retained)),
            typed_request=self.fixture.parent if typed is None else typed,
            retained=self.retained if retained is None else retained, deadline_epoch_ns=deadline)

    def reserve_arguments(self, typed=None, retained=ABSENT):
        request = self.fixture.parent if typed is None else typed
        return {"envelope_id": PIN, "parent_envelope_id": PIN, "operation": request["operation"],
            "operation_id": request["operationId"], "request_digest": request["requestDigest"],
            "capability_id": PIN, "planner_transaction_id": PIN, "authorization_projection_digest": PIN,
            "exact_request_bytes": canonical(request), "deadline_monotonic_ns": MONO + 20 * SECOND,
            "deadline_epoch_ns": NOW + 20 * SECOND, "fence": 1, "reserved_at_epoch_ns": NOW,
            "connection": Mock(), **({} if retained is ABSENT else {"native_jit_pending": retained})}

    def planner_row(self):
        args = self.reserve_arguments()
        return {**retained_row(partial_payload(self.fixture, self.retained)),
            **{name: args[name] for name in ("operation", "operation_id", "request_digest", "capability_id",
                "authorization_projection_digest", "deadline_monotonic_ns", "deadline_epoch_ns", "fence", "reserved_at_epoch_ns")},
            "plan_protocol": "v3", "retained_record_digest": None, "status": "planned"}

    def complete(self, payload):
        return executor.complete_authority_planner_transaction(planner_transaction_id=PIN,
            authorization_projection_digest=PIN, exact_plan_bytes=canonical(payload),
            planned_at_epoch_ns=NOW, connection=Mock())

    def refused_locked(self, **kwargs):
        with self.assertRaisesRegex(ValueError, "^" + retention.ERROR + "$") as caught:
            self.locked(**kwargs)
        self.assertIsNone(caught.exception.__cause__)

    def test_exact_locked_originals_are_joined_without_returning_admission_or_mutating_them(self):
        row = retained_row(partial_payload(self.fixture, self.retained))
        before = canonical([row, self.fixture.parent, self.retained])
        self.assertIsNone(self.locked(row=row))
        self.assertEqual(canonical([row, self.fixture.parent, self.retained]), before)
        self.assertEqual(set(self.retained), {"parentOriginal", "childOriginal", "pairOriginal", "evidenceOriginal"})
        self.assertEqual(len(self.fixture.parent), 7)

    def test_locked_plan_hash_count_and_base64_are_all_exact(self):
        original = retained_row(partial_payload(self.fixture, self.retained))
        for field, value in (("exact_plan_bytes_digest", PIN), ("exact_plan_byte_count", True),
                ("exact_plan_byte_count", original["exact_plan_byte_count"] + 1),
                ("exact_plan_base64url", original["exact_plan_base64url"] + "="),
                ("exact_plan_base64url", ""), ("exact_plan_base64url", "PRIVATE_NOT_BASE64!")):
            self.refused_locked(row={**original, field: value})

    def test_locked_plan_noncanonical_duplicate_and_nonascii_originals_are_refused(self):
        payload = partial_payload(self.fixture, self.retained)
        for raw in (canonical(payload) + b"\n", b'{"schema":1,"schema":2}', b'{"x":"\xff"}'):
            self.refused_locked(row=retained_row(payload, raw))

    def test_locked_parent_request_and_each_literal_original_cannot_be_substituted(self):
        typed = copy.deepcopy(self.fixture.parent); typed["operationId"] = PIN
        self.refused_locked(typed=typed)
        for field in self.retained:
            changed = {**self.retained, field: self.retained[field] + "\n"}
            self.refused_locked(retained=changed)

    def test_independently_valid_second_pair_for_same_parent_cannot_replace_the_locked_original(self):
        f = self.fixture
        f.pair = material.seal_release_pair(f.scope, f.runtime["privateDocuments"],
            key_id=synthetic.KEY_ID, kek=AESGCM(synthetic.KEY), now_epoch_ns=NOW)
        f.statement["pairSha256"] = synthetic.sha256(canonical(f.pair))
        f.proof = f.sign_proof()
        other = originals(f)
        self.assertNotEqual(other["pairOriginal"], self.retained["pairOriginal"])
        self.assertIsNone(submission.validate_retained(other, typed_request=f.parent, deadline_epoch_ns=NOW + 20 * SECOND))
        self.refused_locked(retained=other)

    def test_missing_retained_field_runtime_extras_and_null_are_not_optional_authority(self):
        self.refused_locked(row=retained_row(partial_payload(self.fixture)))
        for value in (None, {}, {**self.retained, "runtimeOriginal": canonical(self.fixture.runtime).decode("ascii")},
                {**self.retained, "privateDocuments": self.fixture.runtime["privateDocuments"]}):
            with self.assertRaisesRegex(ValueError, "^" + retention.ERROR + "$"):
                retention.require_locked_plan(retained_row(partial_payload(self.fixture, value)),
                    typed_request=self.fixture.parent, retained=value, deadline_epoch_ns=NOW + 20 * SECOND)

    def test_locked_operation_deadline_and_schema_are_not_reinterpreted(self):
        for field, value in (("operation", "release.v1.reserve"), ("deadlineEpochNs", True),
                ("deadlineEpochNs", NOW + 21 * SECOND)):
            payload = partial_payload(self.fixture, self.retained); payload["measuredPlan"][field] = value
            self.refused_locked(row=retained_row(payload))
        payload = partial_payload(self.fixture, self.retained); payload["schema"] = "other"
        self.refused_locked(row=retained_row(payload))

    def test_deadline_cannot_outlive_seal_even_when_locked_bytes_match(self):
        deadline = NOW + 31 * SECOND
        payload = partial_payload(self.fixture, self.retained); payload["measuredPlan"]["deadlineEpochNs"] = deadline
        self.refused_locked(row=retained_row(payload), deadline=deadline)

    def test_reservation_missing_retained_evidence_preserves_the_existing_public_only_refusal(self):
        for retained in (ABSENT, None):
            with patch.object(executor, "_require_planner_writer", side_effect=WriterReached) as writer:
                with self.assertRaisesRegex(privacy.PrivateReleaseInputError, "^" + privacy.ERROR + "$"):
                    executor.reserve_authority_execution_envelope(**self.reserve_arguments(retained=retained))
                writer.assert_not_called()

    def test_reservation_raw_runtime_or_malformed_retention_stops_before_writer(self):
        for value in ({}, [], False, {**self.retained, "runtimeOriginal": canonical(self.fixture.runtime).decode("ascii")},
                {**self.retained, "evidenceOriginal": "PRIVATE_INVALID_ORIGINAL"}):
            with patch.object(executor, "_require_planner_writer", side_effect=WriterReached) as writer:
                with self.assertRaisesRegex(submission.SubmissionError, "^" + submission.ERROR + "$"):
                    executor.reserve_authority_execution_envelope(**self.reserve_arguments(retained=value))
                writer.assert_not_called()

    def test_actual_reservation_joins_locked_plan_then_stops_before_any_insert(self):
        cursor = LockedPlannerCursor(self.planner_row()); writer = Mock(); writer.cursor.return_value = cursor
        before = canonical([self.fixture.parent, self.retained])
        with patch.object(executor, "_require_planner_writer", return_value=writer):
            with self.assertRaises(InsertReached):
                executor.reserve_authority_execution_envelope(**self.reserve_arguments(retained=self.retained))
        self.assertEqual(len(cursor.statements), 1)
        self.assertEqual(canonical([self.fixture.parent, self.retained]), before)

    def test_actual_reservation_refuses_changed_locked_original_before_insert(self):
        for change in ({"exact_plan_bytes_digest": PIN},
                retained_row(partial_payload(self.fixture, {**self.retained, "childOriginal": "{}"}))):
            cursor = LockedPlannerCursor({**self.planner_row(), **change}); writer = Mock(); writer.cursor.return_value = cursor
            with patch.object(executor, "_require_planner_writer", return_value=writer):
                with self.assertRaisesRegex(ValueError, "^" + retention.ERROR + "$"):
                    executor.reserve_authority_execution_envelope(**self.reserve_arguments(retained=self.retained))
            self.assertEqual(len(cursor.statements), 1)

    def test_actual_reservation_rechecks_elapsed_clipped_deadline_after_lock_before_insert(self):
        cursor = LockedPlannerCursor(self.planner_row()); writer = Mock(); writer.cursor.return_value = cursor
        with patch.object(executor, "_require_planner_writer", return_value=writer), \
                patch.object(executor.time, "time_ns", side_effect=[NOW, NOW + 21 * SECOND]), \
                patch.object(executor.time, "monotonic_ns", side_effect=[MONO, MONO + 21 * SECOND]):
            with self.assertRaisesRegex(ValueError, "deadline binding is stale or inconsistent"):
                executor.reserve_authority_execution_envelope(**self.reserve_arguments(retained=self.retained))
        self.assertEqual(len(cursor.statements), 1)

    def test_ordinary_null_jit_reservation_still_reaches_unchanged_writer_admission(self):
        typed = legacy.request("release.reserve", legacy.values("release.reserve", None))
        with patch.object(executor, "_require_planner_writer", side_effect=WriterReached) as writer, \
                patch.object(retention, "require_locked_plan", side_effect=AssertionError("native join on ordinary request")):
            with self.assertRaises(WriterReached):
                executor.reserve_authority_execution_envelope(**self.reserve_arguments(typed=typed))
            writer.assert_called_once()

    def test_completion_missing_four_originals_keeps_exact_legacy_refusal_before_writer(self):
        with patch.object(executor, "_require_planner_writer", side_effect=WriterReached) as writer:
            with self.assertRaisesRegex(privacy.PrivateReleaseInputError, "^" + privacy.ERROR + "$"):
                self.complete(partial_payload(self.fixture))
            writer.assert_not_called()

    def test_completion_explicit_null_extra_runtime_or_wrong_operation_never_relaxes_closed_roster(self):
        cases = [partial_payload(self.fixture, value) for value in (None, {}, False,
            {**self.retained, "runtimeOriginal": canonical(self.fixture.runtime).decode("ascii")})]
        wrong = partial_payload(self.fixture, self.retained); wrong["measuredPlan"]["operation"] = "jit.request"; cases.append(wrong)
        for payload in cases:
            with patch.object(executor, "_require_planner_writer", side_effect=WriterReached) as writer:
                with self.assertRaisesRegex(submission.SubmissionError, "^" + submission.ERROR + "$"):
                    self.complete(payload)
                writer.assert_not_called()

    def test_completion_exact_retained_grammar_still_requires_the_entire_existing_plan(self):
        payload = partial_payload(self.fixture, self.retained); before = canonical(payload)
        with patch.object(executor, "_require_planner_writer", side_effect=WriterReached) as writer:
            with self.assertRaisesRegex(ValueError, "^authority measured plan binding is not exact$"):
                self.complete(payload)
            writer.assert_not_called()
        self.assertEqual(canonical(payload), before)

    def test_completion_cannot_extend_original_seal_deadline_or_attach_native_evidence_to_ordinary_request(self):
        later = partial_payload(self.fixture, self.retained); later["measuredPlan"]["deadlineEpochNs"] = NOW + 31 * SECOND
        ordinary = partial_payload(self.fixture, self.retained)
        ordinary["typedRequest"] = legacy.request("release.reserve", legacy.values("release.reserve", None))
        for payload in (later, ordinary):
            with patch.object(executor, "_require_planner_writer", side_effect=WriterReached) as writer:
                with self.assertRaisesRegex(submission.SubmissionError, "^" + submission.ERROR + "$"):
                    self.complete(payload)
                writer.assert_not_called()

    def test_actual_sql_route_priority_is_closed_to_native_pending_insert_and_keeps_existing_tiebreakers(self):
        # This is a source-contract assertion, not a PostgreSQL execution.
        # The isolated PG companion exercises this exact extracted ORDER BY.
        tree = ast.parse((ROOT / "serverware/authority_store/executor_v9.py").read_bytes())
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
            and node.name == "install_authority_v9_executor"]
        self.assertEqual(len(functions), 1)
        fragments = [node.value for node in ast.walk(functions[0])
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
            and "FOR mutation IN" in node.value]
        self.assertEqual(len(fragments), 1)
        fragment = fragments[0]
        self.assertEqual(fragment.count("ORDER BY CASE"), 1)
        actual = fragment.split("ORDER BY CASE", 1)[1].split("LOOP", 1)[0]
        expected = """
            WHEN capability.operation IN ('setup.session.create', 'oauth.setup.create')
                AND planned.value->>'table' = 'setup_sessions'
                AND planned.value->>'operation' = 'INSERT'
            THEN 0
            WHEN capability.operation = 'release.reserve'
                AND planned.value->>'table' = 'routes'
                AND planned.value->>'operation' = 'INSERT'
                AND EXISTS (
                    SELECT 1
                    FROM pg_catalog.jsonb_array_elements(
                        planner.mutation_plan_json::pg_catalog.jsonb
                    ) AS native_pending_marker(value)
                    WHERE native_pending_marker.value->>'table' =
                        'policy_authority_native_jit_review_pairs'
                      AND native_pending_marker.value->>'operation' = 'INSERT'
                )
            THEN 0 ELSE 1 END,
            planned.value->>'table' COLLATE "C",
            planned.value->>'keyDigest' COLLATE "C",
            planned.value->>'operation' COLLATE "C"
        """
        self.assertEqual(" ".join(actual.split()), " ".join(expected.split()))


if __name__ == "__main__":
    unittest.main()
