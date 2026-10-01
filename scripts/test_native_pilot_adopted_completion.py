#!/usr/bin/env python3
"""Pure final-result association controls; no live owner, exit or reap claim.

Synthetic request/action/result originals exercise the selected terminal codec.
Actual process EOF, PIDFD wait, approved-file custody and service cleanup remain
the production owner's checks, not capabilities built by this fixture.
"""
from __future__ import annotations

import copy
import ast
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "scripts"))

from serverware import native_pilot_adopted_phase_profile as profile
from serverware import native_pilot_interactive as interactive
from serverware import native_pilot_supervisor_process as process

p = process.p


def fixture(*, run=False):
    handoff = dict(apiVersion="serverware.nativeGenerationOriginHandoff/v1", okForAction=False,
        automaticRetryAllowed=False, originSha256=p.sha(b"synthetic-origin-only"))
    action = dict(action="run-interactive", originHandoffSha256=p.sha(p.canonical(handoff)),
        stopAtBoottimeNanos=500, expiresAtUnixNanos=5000) if run else {"action": "stop"}
    input_raw = p.canonical(action)
    conductor = dict(apiVersion="serverware.nativePilotOperatorRequest/v2", sequence=len(process.STAGES),
        phase="shutdown", payload={"originHandoff": handoff}, deadlineBoottimeNs="1000", expiresAtUnixNanos="9000")
    request = dict(apiVersion=profile.API, sequence=len(profile.BY_NAME), conductorSequence=len(process.STAGES),
        conductorRequestSha256=p.sha(p.canonical(conductor)), phase="shutdown", jobIndex=1, job="stop",
        deadlineBoottimeNs="1000", expiresAtUnixNanos="9000", conductorRequest=conductor,
        previousResult={"phase": "generation-origin", "job": "observe-generation-origin", "result": {"action": "observe-installed-generation"}})
    # This independently named value represents a literal test result, not a
    # reconstructed production result or a claim that any action was executed.
    result_raw = p.canonical(copy.deepcopy(action))
    value = dict(apiVersion=process.ADOPTED_RESULT_API, status="stopped-cleanup-complete", phase="shutdown",
        pilotAcceptanceVerified=False, productionReleaseEligible=False, deadlineBoottimeNs="1000", expiresAtUnixNanos="9000",
        finalResult=dict(job="stop", inputSha256=p.sha(input_raw), resultOriginal=result_raw.decode("ascii"), resultSha256=p.sha(result_raw)))
    if run:
        value["interactiveResult"] = dict(apiVersion=interactive.RESULT_API, actionSha256=p.sha(input_raw),
            originHandoffSha256=action["originHandoffSha256"], startedAtBoottimeNanos=100,
            endedAtBoottimeNanos=510, endedAtUnixNanos=3000, reason="approved-interval-ended")
    return dict(value=value, request=request, input_raw=input_raw, result_raw=result_raw,
        now_boottime_ns=700, now_unix_ns=4000)


def checked(case, **clocks):
    return process.completion_value(p.canonical(case["value"]), request_raw=p.canonical(case["request"]),
        input_raw=case["input_raw"], input_sha256=p.sha(case["input_raw"]),
        now_boottime_ns=clocks.get("now_boottime_ns", case["now_boottime_ns"]),
        now_unix_ns=clocks.get("now_unix_ns", case["now_unix_ns"]))


class AdoptedCompletionControls(unittest.TestCase):
    def test_exact_stop_result_literal_and_original_bounds(self):
        case = fixture(); value = checked(case)
        self.assertEqual(value, case["value"])
        self.assertEqual(value["finalResult"]["resultOriginal"].encode("ascii"), case["result_raw"])
        self.assertIsNot(value, case["value"])

    def test_interactive_completion_uses_actual_ended_interval_not_new_admission(self):
        case = fixture(run=True)
        value = checked(case)
        self.assertGreater(case["now_boottime_ns"], 500)
        self.assertEqual(value["interactiveResult"]["endedAtBoottimeNanos"], 510)
        self.assertEqual(value["finalResult"]["resultOriginal"].encode("ascii"), case["result_raw"])

    def test_old_terminal_and_new_success_are_separate_closed_profiles(self):
        for change in ({"apiVersion": "serverware.nativePilotAuthorityCoordinatorResult/v1"},
                {"status": "failed-cleanup-complete"}, {"phase": "starting"},
                {"pilotAcceptanceVerified": True}, {"productionReleaseEligible": True}, {"extra": True}):
            case = fixture(); case["value"].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError): checked(case)
        case = fixture()
        with self.assertRaises(ValueError):
            interactive.check_terminal(case["value"], action=None, origin_handoff=None,
                deadline_boottime_ns=None, now_boottime_ns=700, now_unix_ns=4000)

    def test_exact_independent_input_and_literal_result_hashes_cannot_be_replaced(self):
        for update in ({"job": "observe-generation-origin"}, {"inputSha256": p.sha(b"different-input")},
                {"resultSha256": p.sha(b"different-result")}, {"extra": True}):
            case = fixture(); case["value"]["finalResult"].update(update)
            with self.subTest(update=update), self.assertRaises(ValueError): checked(case)
        for result_raw in (b'{"action":"deny"}', b'{ "action":"stop"}', b'{"action":"stop","serviceReady":true}'):
            case = fixture(); case["value"]["finalResult"].update(resultOriginal=result_raw.decode("ascii"), resultSha256=p.sha(result_raw))
            with self.subTest(result=result_raw), self.assertRaises(ValueError): checked(case)

    def test_original_request_and_both_terminal_caps_never_renew(self):
        for field in ("deadlineBoottimeNs", "expiresAtUnixNanos"):
            case = fixture(); case["value"][field] = str(int(case["value"][field]) + 1)
            with self.subTest(field=field), self.assertRaises(ValueError): checked(case)
        for run, clocks in ((False, {"now_boottime_ns": 1000}), (False, {"now_unix_ns": 9000}),
                (True, {"now_unix_ns": 5000})):
            with self.subTest(run=run, clocks=clocks), self.assertRaises(ValueError): checked(fixture(run=run), **clocks)
        for field, value in (("sequence", 175), ("jobIndex", True), ("conductorSequence", True), ("job", "cohort-release"),
                ("conductorRequestSha256", p.sha(b"other"))):
            case = fixture(); case["request"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): checked(case)

    def test_interval_evidence_is_required_exact_and_never_business_success(self):
        case = fixture(run=True); del case["value"]["interactiveResult"]
        with self.assertRaises(ValueError): checked(case)
        for field, value in (("actionSha256", p.sha(b"wrong")), ("reason", "business-success"),
                ("endedAtBoottimeNanos", 499), ("endedAtUnixNanos", 5000)):
            case = fixture(run=True); case["value"]["interactiveResult"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): checked(case)
        case = fixture(); case["value"]["interactiveResult"] = fixture(run=True)["value"]["interactiveResult"]
        with self.assertRaises(ValueError): checked(case)

    def test_result_source_and_predecessor_must_still_be_the_final_stop_job(self):
        case = fixture(run=True)
        raw = p.canonical({**p.document(case["input_raw"], 4096), "stopAtBoottimeNanos": 501})
        case["value"]["finalResult"].update(resultOriginal=raw.decode("ascii"), resultSha256=p.sha(raw))
        with self.assertRaises(ValueError): checked(case)
        case = fixture(); case["request"]["previousResult"]["job"] = "driver-bootstrap"
        with self.assertRaises(ValueError): checked(case)

    def test_public_completion_dictionary_cannot_construct_a_retained_owner(self):
        with self.assertRaises(ValueError):
            process.AuthorityCoordinatorProcess.completion_original(fixture()["value"])

    def test_source_cancellation_gates_transcript_success_not_known_handle_retirement(self):
        # A source-only control, not a fake successful process/supervisor owner.
        tree = ast.parse((ROOT / "serverware/native_pilot_adopted_supervisor.py").read_text())
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef)
            and node.name == "AdoptedCommissioningSupervisor")
        close = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == "close")
        gate = next(node for node in close.body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "transcript_success" for target in node.targets))
        expected = ast.parse('result["status"] == "stopped-cleanup-complete" and not cancel', mode="eval").body
        self.assertEqual(ast.dump(gate.value), ast.dump(expected))
        guarded = [node for node in close.body if isinstance(node, ast.If)
            and isinstance(node.test, ast.Name) and node.test.id == "transcript_success"]
        self.assertEqual(len(guarded), 2)
        direct = [ast.unparse(node) for node in close.body if isinstance(node, (ast.For, ast.Expr, ast.Return))]
        self.assertTrue(any("for original in self._retained" in text for text in direct))
        self.assertIn("self._policy.close()", direct)
        self.assertIn("return result", direct)


if __name__ == "__main__": unittest.main()
