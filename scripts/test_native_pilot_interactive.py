#!/usr/bin/env python3
"""Pure interval grammar/association controls, not a running pilot fixture.

No child, private authority, inspected peer or workload result is manufactured.
Actual owner progress, cancellation and cleanup remain integration boundaries.
"""
import copy
from pathlib import Path
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS)); sys.path.insert(0, str(SCRIPTS.parent))
from serverware import native_pilot_interactive as interval
from serverware import native_shadow_nitro_profile as p


def fixture():
    handoff = {"apiVersion": "serverware.nativeGenerationOriginHandoff/v1",
        "okForAction": False, "automaticRetryAllowed": False, "originSha256": "sha256:" + "a" * 64}
    policy = {"apiVersion": interval.API, "stopAtBoottimeNanos": 500, "expiresAtUnixNanos": 5000}
    action = {"action": "run-interactive", "originHandoffSha256": p.sha(p.canonical(handoff)),
        "stopAtBoottimeNanos": 500, "expiresAtUnixNanos": 5000}
    result = {"apiVersion": interval.RESULT_API, "actionSha256": p.sha(p.canonical(action)),
        "originHandoffSha256": action["originHandoffSha256"], "startedAtBoottimeNanos": 100,
        "endedAtBoottimeNanos": 510, "endedAtUnixNanos": 3000, "reason": "approved-interval-ended"}
    terminal = {"apiVersion": "serverware.nativePilotOperatorResult/v1", "status": "stopped-cleanup-complete",
        "phase": "shutdown", "pilotAcceptanceVerified": False, "productionReleaseEligible": False,
        "interactiveResult": copy.deepcopy(result)}
    return policy, handoff, action, result, terminal


class InteractiveTests(unittest.TestCase):
    def test_continuation_v1_and_v2_keep_closed_independent_selections(self):
        from serverware import native_pilot_supervisor_continuation_policy as continuation
        from test_native_pilot_continuation_profile import policy_fixture, bridge_fixture
        source, _, _ = bridge_fixture()
        legacy = {"apiVersion": continuation.API,
            "endpointImages": {role: {"path": "/opt/serverware/" + role + ".squashfs",
                "sha256": p.sha(role.encode("ascii"))} for role in continuation.cohort.ENDPOINT_ROLES},
            "constructedAdmission": policy_fixture(source)}
        selected = {**legacy, "apiVersion": continuation.INTERACTIVE_API, "interactive": fixture()[0]}
        self.assertEqual(continuation.validate_policy(legacy), legacy)
        self.assertEqual(continuation.validate_policy(selected), selected)
        for changed in ({**legacy, "interactive": fixture()[0]},
                {**selected, "apiVersion": "serverware.nativePilotSupervisorContinuationPolicy/v3"},
                {key: value for key, value in selected.items() if key != "interactive"},
                {**selected, "interactive": {**fixture()[0], "durationNanos": 100}},
                {**selected, "endpointImages": {}}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                continuation.validate_policy(changed)

    def test_closed_static_policy_has_no_command_duration_or_authority(self):
        policy, *_ = fixture()
        checked = interval.validate_policy(policy)
        self.assertEqual(checked, policy)
        self.assertIsNot(checked, policy)
        for name, value in (("command", "true"), ("durationNanos", 200), ("approved", True)):
            with self.subTest(name=name), self.assertRaises(ValueError):
                interval.validate_policy({**policy, name: value})

    def test_absolute_integer_ceilings_are_not_renewed_or_generic_u64(self):
        policy, *_ = fixture()
        for name in interval.FIELDS[1:]:
            for value in (True, 0, -1, "500", 1 << 63):
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    interval.validate_policy({**policy, name: value})

    def test_action_binds_exact_actual_handoff_data(self):
        _, handoff, action, *_ = fixture()
        self.assertEqual(interval.validate_action(action, origin_handoff=handoff), action)
        for changed in ({**handoff, "originSha256": "sha256:" + "b" * 64}, {**handoff, "okForAction": True},
                {**handoff, "automaticRetryAllowed": True}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                interval.validate_action(action, origin_handoff=changed)
        with self.assertRaises(ValueError):
            interval.validate_action({**action, "requestSucceeded": True}, origin_handoff=handoff)

    def test_factual_result_binds_action_and_original_stop(self):
        _, handoff, action, result, _ = fixture()
        self.assertEqual(interval.check_result(result, action=action, origin_handoff=handoff), result)
        for changed in ({**action, "stopAtBoottimeNanos": 600}, {**action, "expiresAtUnixNanos": 6000}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                interval.check_result(result, action=changed, origin_handoff=handoff)
        for field, value in (("actionSha256", "sha256:" + "c" * 64), ("originHandoffSha256", "sha256:" + "d" * 64),
                ("reason", "request-allowed"), ("startedAtBoottimeNanos", 500),
                ("endedAtBoottimeNanos", 499), ("endedAtUnixNanos", 5000)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                interval.check_result({**result, field: value}, action=action, origin_handoff=handoff)

    def test_terminal_interval_requires_retained_action_and_original_deadline(self):
        _, handoff, action, _, terminal = fixture()
        options = dict(action=action, origin_handoff=handoff, deadline_boottime_ns=600,
            now_boottime_ns=700, now_unix_ns=4000)
        self.assertEqual(interval.check_terminal(terminal, **options), terminal)
        for change in (dict(action=None), dict(deadline_boottime_ns=510),
                dict(now_boottime_ns=509), dict(now_unix_ns=2999)):
            with self.subTest(change=change), self.assertRaises(ValueError):
                interval.check_terminal(terminal, **{**options, **change})

    def test_failure_and_legacy_paths_cannot_carry_interval_evidence(self):
        _, handoff, action, _, terminal = fixture()
        options = dict(action=action, origin_handoff=handoff, deadline_boottime_ns=600,
            now_boottime_ns=700, now_unix_ns=4000)
        failed = {**terminal, "status": "failed-cleanup-complete"}
        with self.assertRaises(ValueError):
            interval.check_terminal(failed, **options)
        del failed["interactiveResult"]
        self.assertEqual(interval.check_terminal(failed, **options), failed)
        legacy = {key: value for key, value in terminal.items() if key != "interactiveResult"}
        self.assertEqual(interval.check_terminal(legacy, **{**options, "action": None}), legacy)
        with self.assertRaises(ValueError):
            interval.check_terminal(legacy, **options)

    def test_result_does_not_accept_allow_deny_or_cleanup_claims(self):
        _, handoff, action, result, _ = fixture()
        for name in ("requestAllowed", "requestDenied", "pilotAcceptanceVerified", "cleanupComplete"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                interval.check_result({**result, name: True}, action=action, origin_handoff=handoff)


if __name__ == "__main__":
    unittest.main()
