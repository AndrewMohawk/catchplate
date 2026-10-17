#!/usr/bin/env python3
"""Stdlib orchestration controls; tiny local children, no product tests/network."""
import json
import hashlib
import io
import os
import re
from contextlib import redirect_stderr
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import run_ordinary_regression as runner


class RunnerTests(unittest.TestCase):
    def child(self, code, seconds=3):
        return runner.run_process([sys.executable, "-I", "-B", "-c", code],
            cwd=runner.ROOT, env={"PATH": os.defpath}, seconds=seconds)

    def test_manifest_is_explicit_component_only_and_all_paths_exist(self):
        paths = [row.script for row in runner.SUITES]
        self.assertEqual(len(paths), len(set(paths)))
        self.assertEqual({row.category for row in runner.SUITES}, {"backend", "notifications", "ui_contract"})
        for script in ("test_authority_api_classification.py",
                "test_jit_denial_api.py", "test_runtime_grant_publication.py", "test_authority_jit_denial.py",
                "test_native_jit_decision_fences_http.py",
                "test_authority_jit_approval.py", "test_authority_jit_request.py",
                "test_authority_jit_private_request.py", "test_native_jit_review_material.py",
                "test_native_jit_review_owner.py",
                "test_authority_native_jit_review_custody.py",
                "test_authority_native_jit_review_registration.py",
                "test_authority_transition_registry.py",
                "test_authority_schema_source.py",
                "test_authority_verifier_read_source.py",
                "test_authority_table_acl_source.py",
                "test_authority_revocation_proof_bundle.py",
                "test_authority_index_join.py", "test_authority_indexed_mutation.py",
                "test_authority_complete_query_batch.py", "test_authority_counted_root_transition.py",
                "test_authority_complete_read_write.py", "test_authority_revocation_read_write.py",
                "test_native_jit_review_open_owner.py",
                "test_authority_native_jit_review_current_chunks.py",
                "test_authority_native_jit_review_current_read.py",
                "test_authority_native_jit_review_transport.py",
                "test_authority_native_jit_review_open.py",
                "test_authority_native_jit_review_plan.py",
                "test_authority_native_jit_review_plan_replay.py",
                "test_authority_launcher_native_review_credentials.py",
                "test_native_jit_review_portal.py",
                "test_authority_native_jit_pending.py",
                "test_authority_native_jit_executor_retention.py",
                "test_native_jit_legacy_reader.py",
                "test_native_jit_sqlite_bootstrap.py",
                "test_authority_native_jit_submission.py",
                "test_authority_native_jit_retained_history.py",
                "test_native_jit_submission_http.py",
                "test_authority_release_private_input.py", "test_authority_release_private_request.py",
                "test_authority_release_private_ingress.py", "test_native_jit_prepare.py",
                "test_approval_history_metadata.py"):
            denial = next(row for row in runner.SUITES if row.script == script)
            expected_seconds = {"test_authority_revocation_proof_bundle.py": 180,
                "test_authority_native_jit_review_plan_replay.py": 360}.get(script, 60)
            self.assertEqual((denial.category, denial.runtime, denial.arguments, denial.seconds),
                ("backend", "python", (), expected_seconds))
        self.assertIn("test_operator_notification_google_events.py", paths)
        self.assertIn("test_approval_capabilities_http.py", paths)
        self.assertIn("test_authority_jit_review_receipt.py", paths)
        for script in ("test_operator_workload_renewal_contract.py", "test_proxy_managed_renewal.py",
                "test_operator_workload_renewal_store.py", "test_operator_workload_renewal_api.py",
                "test_operator_workload_renewal.py", "test_managed_client.py",
                "test_operator_managed_helper_connected.py"):
            self.assertIn(script, paths)
        self.assertIn("test_operator_catalog_github_app.py", paths)
        bytecode = next(row for row in runner.SUITES if row.script == "test_prepare_operator_python_bytecode.py")
        self.assertEqual((bytecode.category, bytecode.runtime, bytecode.arguments, bytecode.seconds),
            ("backend", "python", (), 60))
        x_catalog = next(row for row in runner.SUITES if row.script == "test_operator_catalog_x_post.py")
        self.assertEqual((x_catalog.category, x_catalog.runtime, x_catalog.arguments, x_catalog.seconds),
            ("backend", "python", (), 240))
        for script in ("test_operator_public_proxy.py", "test_operator_public_proxy_control.py"):
            public_proxy = next(row for row in runner.SUITES if row.script == script)
            self.assertEqual((public_proxy.category, public_proxy.runtime, public_proxy.arguments, public_proxy.seconds),
                ("backend", "python", (), 60))
        gmail = next(row for row in runner.SUITES if row.script == "test_operator_gmail_sdk_languages.cjs")
        self.assertEqual((gmail.category, gmail.runtime, gmail.arguments, gmail.seconds),
            ("ui_contract", "node", (), 60))
        gmail_age = next(row for row in runner.SUITES if row.script == "test_operator_gmail_age_ui.cjs")
        self.assertEqual((gmail_age.category, gmail_age.runtime, gmail_age.arguments, gmail_age.seconds),
            ("ui_contract", "node", (), 60))
        age_receipt = {"ok": True, "groups": 8, "browser": False, "providerRequests": 0,
            "applicationRequests": 0, "scope": "actual backend descriptor and isolated UI draft/review/download functions"}
        self.assertEqual(runner.node_completion(gmail_age.script, json.dumps(age_receipt).encode()), 8)
        self.assertIsNone(runner.node_completion(gmail_age.script,
            json.dumps({**age_receipt, "groups": 0}).encode()))
        decisions = next(row for row in runner.SUITES if row.script == "test_approval_decision_ui.cjs")
        self.assertEqual((decisions.category, decisions.runtime, decisions.arguments, decisions.seconds),
            ("ui_contract", "node", (), 60))
        pending = next(row for row in runner.SUITES if row.script == "test_operator_pending_actions_ui.cjs")
        self.assertEqual((pending.category, pending.runtime, pending.arguments, pending.seconds),
            ("ui_contract", "node", (), 60))
        review = next(row for row in runner.SUITES if row.script == "test_native_jit_review_portal.cjs")
        self.assertEqual((review.category, review.runtime, review.arguments, review.seconds),
            ("ui_contract", "node", (), 60))
        auth_state = next(row for row in runner.SUITES if row.script == "test_operator_auth_state_ui.cjs")
        self.assertEqual((auth_state.category, auth_state.runtime, auth_state.arguments, auth_state.seconds),
            ("ui_contract", "node", (), 60))
        mutation_recovery = next(row for row in runner.SUITES
            if row.script == "test_operator_mutation_recovery_browser.cjs")
        self.assertEqual((mutation_recovery.category, mutation_recovery.runtime,
            mutation_recovery.arguments, mutation_recovery.seconds),
            ("ui_contract", "node", ("--self-test",), 60))
        self.assertNotIn("test_native_jit_review_signers.py", paths)
        assets = next(row for row in runner.SUITES if row.script == "test_operator_catalog_assets.py")
        self.assertEqual((assets.category, assets.runtime, assets.arguments, assets.seconds),
            ("ui_contract", "python", (), 60))
        for script in ("test_operator_guided_checker.py", "test_operator_guided_fixture.py",
                "test_operator_guided_browser.cjs"):
            guided = next(row for row in runner.SUITES if row.script == script)
            node = script.endswith(".cjs")
            self.assertEqual((guided.category, guided.runtime, guided.arguments, guided.seconds),
                ("ui_contract" if node else "backend", "node" if node else "python", (), 60))
        x_backend = {"test_operator_x_accounts_api.py", "test_operator_x_transport.py",
            "test_operator_x_refresh.py", "test_operator_x_lease_reconciliation.py",
            "test_operator_x_lease_boundary.py", "test_operator_x_secret_boundary.py",
            "test_operator_x_readiness.py", "test_operator_x_quota.py", "test_operator_x_quota_api.py"}
        x_ui = {"test_operator_x_accounts_ui.cjs", "test_operator_x_configuration_ui.mjs",
            "test_operator_x_quota_ui.cjs"}
        x_fixture = {"test_operator_x_post_profiles.py", "test_operator_x_post_fixture.py",
            "test_operator_x_quota_fixture.py", "test_operator_x_quota_checker.py",
            "test_operator_x_quota_fault_fixture.py", "test_operator_x_quota_fault_checker.py",
            "test_operator_x_post_checker.py", "test_prepare_operator_x_post_fixture.py",
            "test_run_operator_x_post_fixture.py"}
        relay = "test_operator_x_quota_fault_relay.py"
        self.assertTrue(x_fixture <= set(paths))
        self.assertEqual({row.script for row in runner.SUITES if row.script.startswith(
            ("test_operator_x_", "test_prepare_operator_x_", "test_run_operator_x_"))},
            x_backend | x_ui | x_fixture | {relay})
        observers = {"test_operator_rollout_x_quota.py", "test_operator_rollout_snapshot.py",
            "test_operator_source_revision_retained.py", "test_operator_source_revision_retained_host.py"}
        self.assertTrue(observers <= set(paths))
        for row in runner.SUITES:
            if row.script in x_backend:
                self.assertEqual((row.category, row.runtime, row.arguments, row.seconds),
                    ("backend", "python", (), 240))
            elif row.script in x_ui:
                self.assertEqual((row.category, row.runtime, row.arguments, row.seconds),
                    ("ui_contract", "node", (), 60))
            elif row.script in x_fixture | observers:
                self.assertEqual((row.category, row.runtime, row.arguments, row.seconds),
                    ("backend", "python", (), 60))
            elif row.script == relay:
                self.assertEqual((row.category, row.runtime, row.arguments, row.seconds),
                    ("backend", "python", ("--loopback",), 60))
        for excluded in ("test_operator_x_lifecycle_connected.py", "test_operator_x_configuration_connected.py",
                "test_operator_x_browser.cjs"):
            self.assertNotIn(excluded, paths)
        self.assertEqual((runner.MAX_SECONDS, runner.MAX_OUTPUT_BYTES), (900, 100 * 1024))
        for row in runner.SUITES:
            self.assertTrue((runner.ROOT / "scripts" / row.script).is_file())
            self.assertTrue(row.script.startswith("test_"))
            self.assertLessEqual(row.seconds,
                360 if row.script == "test_authority_native_jit_review_plan_replay.py" else 240)
            self.assertNotIn("/", row.script)
        catalog = next(row for row in runner.SUITES if row.script == "test_operator_catalog_browser.cjs")
        self.assertEqual(catalog.arguments, ("--self-test",))
        self.assertNotIn("test_operator_ordinary_modes_browser.cjs", paths)

    def test_fixed_partitions_are_disjoint_complete_ordered_and_bounded(self):
        self.assertEqual(runner.PARTITIONS, ("all", "python-1", "python-2", "python-3", "native-review", "node"))
        self.assertEqual(runner.partition_suites("all"), (runner.SUITES, 900))
        shards = {name: runner.partition_suites(name) for name in runner.PARTITIONS[1:]}
        names = [suite.script for selected, _ in shards.values() for suite in selected]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(set(names), {suite.script for suite in runner.SUITES})
        python = tuple(suite for suite in runner.SUITES if suite.runtime == "python")
        ordinary_python = tuple(suite for suite in python
            if suite.script != "test_authority_native_jit_review_plan_replay.py")
        self.assertEqual(shards["python-1"][0] + shards["python-2"][0] + shards["python-3"][0], ordinary_python)
        self.assertEqual(shards["python-1"][0][-1].script, "test_operator_workload_renewal.py")
        self.assertEqual(shards["python-2"][0][0].script, "test_managed_client.py")
        self.assertEqual(shards["python-2"][0][-1].script, "test_native_jit_prepare.py")
        self.assertEqual(shards["python-3"][0][0].script, "test_authority_complete_read_write.py")
        self.assertEqual(tuple(len(selected) for selected, _ in shards.values()), (16, 41, 43, 1, 18))
        self.assertEqual((len(runner.SUITES), len(python)), (119, 101))
        self.assertEqual(shards["node"][0], tuple(suite for suite in runner.SUITES if suite.runtime == "node"))
        for partition, (selected, budget) in shards.items():
            self.assertTrue(selected)
            self.assertEqual(budget, 600)
            self.assertEqual(runner.partition_suites(partition), (selected, budget))
            selected_names = {suite.script for suite in selected}
            self.assertEqual(selected, tuple(suite for suite in runner.SUITES if suite.script in selected_names))

    def test_native_review_partition_has_exact_suite_and_unchanged_outer_limits(self):
        name = "test_authority_native_jit_review_plan_replay.py"
        self.assertEqual(runner.NATIVE_REVIEW_SUITE, name)
        selected, budget = runner.partition_suites("native-review")
        self.assertEqual(selected, (runner.Suite("backend", name, seconds=360),))
        self.assertEqual((budget, runner.MAX_SECONDS, runner.MAX_PARTITION_SECONDS,
            runner.MAX_OUTPUT_BYTES), (600, 900, 600, 100 * 1024))
        for partition in ("python-1", "python-2", "python-3", "node"):
            self.assertNotIn(name, [suite.script for suite in runner.partition_suites(partition)[0]])

    def test_native_review_missing_duplicate_wrong_runtime_and_changed_profile_refuse(self):
        name = "test_authority_native_jit_review_plan_replay.py"
        native = runner.Suite("backend", name, seconds=360)
        invalid = ((runner.SUITES[0],), (native, native),
            (runner.Suite("backend", name, runtime="node", seconds=360),),
            (runner.Suite("backend", name, seconds=180),),
            (runner.Suite("backend", name, seconds=361),),
            (runner.Suite("backend", name, arguments=("--extra",), seconds=360),))
        for suites in invalid:
            with self.subTest(suites=suites), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "new"
                args = SimpleNamespace(partition="native-review", output=output)
                with patch.object(runner, "SUITES", suites), \
                        patch.object(runner, "require_offline_network") as offline, \
                        patch.object(runner.subprocess, "Popen") as child, self.assertRaises(runner.Refused):
                    runner.run(args)
                offline.assert_not_called()
                child.assert_not_called()
                self.assertFalse(output.exists())

    def test_native_review_execution_clips_360_seconds_to_remaining_600_second_partition(self):
        native = next(suite for suite in runner.SUITES
            if suite.script == "test_authority_native_jit_review_plan_replay.py")
        synthetic = {"status": "passed", "exitCode": 0, "observedUnittestCounts": [14]}
        for elapsed, expected_seconds in ((0, 360), (598, 2), (600, None)):
            with self.subTest(elapsed=elapsed), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "results"
                args = SimpleNamespace(python=sys.executable, node=sys.executable,
                    dependency_root=None, output=output, partition="native-review")
                with patch.object(runner, "require_offline_network"), \
                        patch.object(runner.time, "monotonic", side_effect=[10, 10 + elapsed, 10 + elapsed]), \
                        patch.object(runner, "run_process", return_value=synthetic) as run, patch("builtins.print"):
                    self.assertEqual(runner.run(args), int(expected_seconds is None))
                if expected_seconds is None:
                    run.assert_not_called()
                else:
                    run.assert_called_once()
                    self.assertEqual(run.call_args.kwargs["seconds"], expected_seconds)
                    self.assertEqual(run.call_args.args[0], [str(Path(sys.executable).resolve()), "-B",
                        str(runner.ROOT / "scripts" / native.script)])
                receipt = json.loads((output / "result.json").read_text())
                self.assertEqual((receipt["partition"], receipt["maximumSeconds"], receipt["totalSuiteCount"]),
                    ("native-review", 600, 119))
                self.assertEqual([suite["script"] for suite in receipt["suites"]], [native.script])
                self.assertEqual(receipt["suites"][0]["status"],
                    "not_run_budget" if expected_seconds is None else "passed")

    def test_revocation_proof_bundle_deadline_preserves_roster_and_partition_budget(self):
        selected, budget = runner.partition_suites("python-2")
        proof = [suite for suite in selected
            if suite.script == "test_authority_revocation_proof_bundle.py"]
        self.assertEqual(len(proof), 1)
        self.assertEqual(proof[0].seconds, 180)
        self.assertEqual(proof[0].arguments, ())
        self.assertEqual(len(runner.SUITES), 119)
        self.assertEqual(budget, 600)
        self.assertEqual(runner.MAX_PARTITION_SECONDS, 600)

    def test_invalid_partitions_and_broken_partition_rosters_are_refused(self):
        for partition in (None, True, 1, [], "", "python", "python-4", "node ", "ALL", "../node"):
            with self.subTest(partition=partition), self.assertRaises(runner.Refused):
                runner.partition_suites(partition)
        first = runner.SUITES[0]
        boundaries = tuple(runner.Suite("backend", script) for script in runner.PYTHON_PARTITION_BOUNDARIES)
        for suites, partition in (((), "all"), ((first, first), "node"),
                ((runner.Suite("backend", "test_invalid.py", "unknown"),), "all"),
                ((first,), "python-1"), ((first,), "node"),
                (boundaries, "python-3"), ((*reversed(boundaries), first), "python-1")):
            with self.subTest(partition=partition, suites=suites), \
                    patch.object(runner, "SUITES", suites), self.assertRaises(runner.Refused):
                runner.partition_suites(partition)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "new"
            args = SimpleNamespace(partition="python-4", output=output)
            with patch.object(runner, "require_offline_network") as offline, \
                    patch.object(runner.subprocess, "Popen") as child, self.assertRaises(runner.Refused):
                runner.run(args)
            offline.assert_not_called()
            child.assert_not_called()
            self.assertFalse(output.exists())

    def test_cli_defaults_to_all_and_rejects_unknown_partition_before_run(self):
        original_umask = os.umask(0o077)
        try:
            with patch.object(sys, "argv", ["runner", "--output", "/unused"]), \
                    patch.object(runner, "run", return_value=0) as run:
                self.assertEqual(runner.main(), 0)
            self.assertEqual(run.call_args.args[0].partition, "all")
            with patch.object(sys, "argv", ["runner", "--output", "/unused", "--partition", "python-4"]), \
                    patch.object(runner, "run") as run, redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as error:
                runner.main()
            self.assertEqual(error.exception.code, 2)
            run.assert_not_called()
        finally:
            os.umask(original_umask)

    def test_partition_execution_records_identity_and_never_exceeds_its_budget(self):
        first = runner.SUITES[0]
        boundary1, boundary2 = tuple(next(suite for suite in runner.SUITES if suite.script == script)
            for script in runner.PYTHON_PARTITION_BOUNDARIES)
        second = next(suite for suite in runner.SUITES if suite.script == "test_authority_verifier_read_source.py")
        nodes = tuple(suite for suite in runner.SUITES if suite.runtime == "node")[:2]
        cases = {"all": ((first, boundary1), 900), "python-1": ((first, boundary1, boundary2, second), 600),
            "python-2": ((boundary1, first, boundary2, second), 600),
            "python-3": ((boundary1, boundary2, first, second), 600), "node": ((first, *nodes), 600)}
        synthetic = {"status": "passed", "exitCode": 0, "observedUnittestCounts": [1], "observedNodeGroups": 1}
        for partition, (suites, limit) in cases.items():
            with self.subTest(partition=partition), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "results"
                args = SimpleNamespace(python=sys.executable, node=sys.executable,
                    dependency_root=None, output=output, partition=partition)
                with patch.object(runner, "SUITES", suites), patch.object(runner, "require_offline_network"), \
                        patch.object(runner.time, "monotonic", side_effect=[10, 10 + limit - 2, 10 + limit, 10 + limit]), \
                        patch.object(runner, "run_process", return_value=synthetic) as run, patch("builtins.print"):
                    selected, _ = runner.partition_suites(partition)
                    self.assertEqual(runner.run(args), 1)
                self.assertEqual(run.call_count, 1)
                self.assertEqual(run.call_args.kwargs["seconds"], 2)
                result = json.loads((output / "result.json").read_text())
                self.assertEqual((result["partition"], result["maximumSeconds"], result["totalSuiteCount"]),
                    (partition, limit, len(suites)))
                self.assertFalse(result["success"])
                self.assertEqual([row["script"] for row in result["suites"]], [suite.script for suite in selected])
                self.assertEqual([row["status"] for row in result["suites"]], ["passed", "not_run_budget"])
                self.assertIsNone(result["suites"][1]["exitCode"])
                expected_roster = [{"category": suite.category, "script": suite.script, "runtime": suite.runtime,
                    "arguments": list(suite.arguments), "seconds": suite.seconds} for suite in suites]
                self.assertEqual(result["suiteRosterSha256"], hashlib.sha256(json.dumps(expected_roster,
                    sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest())

    def test_offline_check_rejects_any_nonloopback_interface_or_route(self):
        def check(interfaces, route="Iface\n", ipv6=""):
            with patch.object(runner.Path, "iterdir", return_value=[Path(value) for value in interfaces]), \
                    patch.object(runner.Path, "read_text", side_effect=[route, ipv6]):
                runner.require_offline_network()
        check(["lo"])
        for values in ((["lo", "eth0"], "Iface\n", ""), (["lo"], "Iface\neth0 0\n", ""),
                       (["lo"], "Iface\n", "0000 eth0\n"), ([], "Iface\n", "")):
            with self.subTest(values=values), self.assertRaises(runner.Refused):
                check(*values)
        with patch.object(runner.Path, "iterdir", side_effect=OSError), self.assertRaises(runner.Refused):
            runner.require_offline_network()

    def test_environment_drops_ambient_credentials_and_uses_fresh_fixture_paths(self):
        with patch.dict(os.environ, {"CATCHPLATE_ADMIN_TOKEN": "canary", "HTTPS_PROXY": "canary",
                "NODE_OPTIONS": "canary", "AWS_SECRET_ACCESS_KEY": "canary", "PYTHONSTARTUP": "canary"}):
            value = runner.environment(Path("/source"), Path("/scratch"), "/bin/python", "/tools/node", Path("/deps"))
        self.assertNotIn("canary", json.dumps(value))
        self.assertEqual(value["CATCHPLATE_DATA_DIR"], "/scratch/data")
        self.assertEqual(value["PYTHONPATH"], "/source:/source/scripts:/deps")
        self.assertEqual(value["HOME"], value["TMPDIR"])

    def test_failure_projection_keeps_test_location_not_secret_messages(self):
        canary = "PRIVATE_CANARY_DO_NOT_RETAIN"
        raw = ('FAIL: test_exact_binding (fixture.Tests)\n'
            '  File "/private/fixture.py", line 12, in test_exact_binding\n'
            'AssertionError: ' + canary + '\n-----BEGIN PRIVATE KEY-----\n' + canary +
            '\n-----END PRIVATE KEY-----\nRan 3 tests in 0.005s\n').encode()
        value = runner.diagnostics(raw)
        self.assertNotIn(canary, json.dumps(value))
        self.assertEqual(value["failedTests"], ["test_exact_binding"])
        self.assertEqual(value["frames"], [{"file": "fixture.py", "line": 12}])
        self.assertEqual(value["exceptionTypes"], ["AssertionError"])
        self.assertEqual(value["observedUnittestCounts"], [3])

    def test_real_children_exit_failure_timeout_and_output_bounds(self):
        self.assertEqual(self.child("print('ok')")["status"], "passed")
        failure = self.child("raise RuntimeError('PRIVATE_CANARY')")
        self.assertEqual((failure["status"], failure["exitCode"]), ("failed", 1))
        self.assertNotIn("PRIVATE_CANARY", json.dumps(failure))
        self.assertEqual(self.child("import time; time.sleep(10)", seconds=0.1)["status"], "timeout")
        self.assertEqual(self.child("import os; os.write(1,b'x'*200000)")["status"], "output_limit")
        self.assertEqual(self.child("print('OK (skipped=1)')")["status"], "required_tests_skipped")

    def test_known_node_failure_projects_only_bounded_numeric_receipt(self):
        script = "test_operator_github_app_ui.mjs"
        canary = "PRIVATE_CANARY_DO_NOT_RETAIN"
        prefix = ("PASS prior group\n" + canary + "\n").encode()
        def wire(value):
            return prefix + json.dumps(value).encode() + b"\n"
        valid = {"ok": False, "group": 18, "frames": [[411, 14], [447, 44]]}
        raw = wire(valid)
        baseline = runner.diagnostics(raw)
        observed = runner.diagnostics(raw, completion_script=script)
        self.assertEqual(observed.pop("observedNodeFailure"), {"script": script, "group": 18,
            "frames": [{"line": 411, "column": 14}, {"line": 447, "column": 44}]})
        self.assertEqual(observed, baseline)
        self.assertNotIn(canary, json.dumps(observed))
        for group, frames in ((0, []), (10000, [[9999999, 9999999]] * 5)):
            value = runner.diagnostics(wire({"ok": False, "group": group, "frames": frames}), completion_script=script)
            self.assertEqual(value["observedNodeFailure"]["group"], group)
            self.assertEqual(len(value["observedNodeFailure"]["frames"]), len(frames))
        for other in (None, "test_operator_pending_actions_ui.cjs", "../" + script):
            self.assertNotIn("observedNodeFailure", runner.diagnostics(raw, completion_script=other))

    def test_known_node_failure_rejects_extra_duplicate_typed_and_unbounded_fields(self):
        script = "test_operator_github_app_ui.mjs"
        canary = "PRIVATE_CANARY_DO_NOT_RETAIN"
        valid = {"ok": False, "group": 18, "frames": [[411, 14]]}
        changed = [None, [], {**valid, "message": canary}, {**valid, "script": canary},
            *({key: item for key, item in valid.items() if key != missing} for missing in valid),
            *({**valid, "ok": value} for value in (True, 0, None, "false")),
            *({**valid, "group": value} for value in (-1, 10001, True, 1.0, None, canary)),
            *({**valid, "frames": value} for value in (None, {}, canary, [[1, 1]] * 6, [[1]], [[1, 1, 1]],
                [[0, 1]], [[1, -1]], [[10000000, 1]], [[1, 10000000]], [[True, 1]], [[1, 1.0]],
                [[canary, 1]], [{"line": 1, "column": 1}]))]
        invalid = [json.dumps(value).encode() + b"\n" for value in changed]
        terminal = json.dumps(valid).encode()
        invalid += [b"", terminal + b"\nextra\n", terminal + b"\n\n", b" " * 513 + terminal,
            b'{"ok":false,"group":18,"group":19,"frames":[]}',
            b'{"ok":true,"ok":false,"group":18,"frames":[]}',
            b'{"ok":false,"group":18,"frames":[],"frames":[]}',
            b'{"ok":false,"group":18,"frames":[],"message":"\xff"}']
        for raw in invalid:
            with self.subTest(raw_sha256=hashlib.sha256(raw).hexdigest()):
                result = runner.diagnostics(raw, completion_script=script)
                self.assertNotIn("observedNodeFailure", result)
                self.assertNotIn(canary, json.dumps(result))
                self.assertEqual(result["outputSha256"], hashlib.sha256(raw).hexdigest())

    def test_known_node_failure_child_keeps_failed_exit_and_no_completion_claim(self):
        terminal = json.dumps({"ok": False, "group": 18, "frames": [[411, 14]]})
        code = "print('PRIVATE_CANARY'); print(" + repr(terminal) + "); raise SystemExit(1)"
        result = runner.run_process([sys.executable, "-I", "-B", "-c", code], cwd=runner.ROOT,
            env={"PATH": os.defpath}, seconds=3, completion_script="test_operator_github_app_ui.mjs")
        self.assertEqual((result["status"], result["exitCode"]), ("failed", 1))
        self.assertEqual(result["observedNodeFailure"]["group"], 18)
        self.assertIsNone(result["observedNodeGroups"])
        self.assertNotIn("PRIVATE_CANARY", json.dumps(result))

    def test_exited_leader_cleanup_preserves_owned_group_with_or_without_inherited_pipe(self):
        for inherited_pipe in (False, True):
            with self.subTest(inherited_pipe=inherited_pipe), tempfile.TemporaryDirectory() as directory:
                marker = Path(directory) / "child-pid"
                code = ("import os,time,pathlib\n"
                    "pid=os.fork()\n"
                    "if pid == 0:\n"
                    + (" os.close(1); os.close(2)\n" if not inherited_pipe else "")
                    + f" pathlib.Path({str(marker)!r}).write_text(str(os.getpid()))\n"
                    " time.sleep(10)\n"
                    "else:\n"
                    f" while not pathlib.Path({str(marker)!r}).exists(): time.sleep(0.001)\n"
                    " os._exit(0)\n")
                observed = []
                actual_cleanup = runner.stop_group
                def cleanup(process):
                    observed.append(runner.child_exit_status(process))
                    self.assertIsNone(process.returncode)  # Leader has not been reaped.
                    actual_cleanup(process)
                with patch.object(runner, "stop_group", side_effect=cleanup):
                    result = self.child(code, seconds=0.5)
                self.assertEqual(observed, [0])
                self.assertEqual(result["status"], "timeout" if inherited_pipe else "passed")
                child = int(marker.read_text())
                deadline = time.monotonic() + 1
                while time.monotonic() < deadline:
                    try:
                        state = Path(f"/proc/{child}/stat").read_text().split(")", 1)[1].split()[0]
                    except (FileNotFoundError, ProcessLookupError):
                        break
                    if state == "Z":  # Awaiting the isolated container's init reaper.
                        break
                    time.sleep(0.01)
                else:
                    self.fail("owned residual child remained alive")

    def test_lost_child_ownership_refuses_signaling_or_reaping(self):
        process = SimpleNamespace(pid=12345, returncode=None, wait=lambda **kwargs: self.fail("unowned wait"))
        with patch.object(runner.os, "waitid", side_effect=ChildProcessError), \
                patch.object(runner.os, "killpg") as kill, self.assertRaises(runner.Refused):
            runner.stop_group(process)
        kill.assert_not_called()
        with patch.object(runner.os, "waitid", return_value=None), patch.object(runner.os, "getpgid", return_value=54321), \
                patch.object(runner.os, "killpg") as kill, self.assertRaises(runner.Refused):
            runner.stop_group(process)
        kill.assert_not_called()

    def test_node_completion_requires_exact_current_summary_and_positive_group_evidence(self):
        common = {"ok": True, "browser": False, "network": False, "generated_recipe_executed": False}
        examples = {
            "test_operator_catalog_browser.cjs": ({"ok": True,
                "scope": "pure exported client command generator; no browser or requests"}, ""),
            "test_operator_guided_browser.cjs": ({"ok": True, "browser": False, "network": False,
                "providerRequests": 0, "scope": "pure guided browser protocol and private download controls"}, "PASS fixture\n"),
            "test_operator_mutation_recovery_browser.cjs": ({"ok": True, "browser": False, "network": False,
                "scope": "pure ordinary mutation recovery and exact receipt controls"}, "PASS fixture\n"),
            "test_operator_npm_ui.cjs": ({**common,
                "scope": "public catalog, inert DOM connect/download handlers, npm recipe and source-pin joins; not browser or provider acceptance"}, "PASS fixture\n"),
            "test_operator_npm_publish_ui.cjs": (common, "PASS fixture\n"),
            "test_operator_npm_install_ui.cjs": (common, "PASS fixture\n"),
            "test_operator_github_app_ui.mjs": ({"ok": True, "network": False, "browser": False, "provider": False,
                "scope": "actual UI functions and core mutation; inert DOM and independent in-memory API, not provider acceptance"}, "PASS fixture\n"),
            "test_operator_gmail_sdk_languages.cjs": ({"ok": True, "browser": False, "sdk": False,
                "providerRequests": 0, "scope": "pure UI helper and inert local shell stubs"}, ""),
            "test_operator_x_accounts_ui.cjs": ({"ok": True, "browser": False, "network": False,
                "scope": "actual public UI helpers and controller with inert DOM; no provider or backend acceptance"}, "PASS fixture\n"),
            "test_operator_x_configuration_ui.mjs": ({"ok": True, "browser": False, "network": False,
                "scope": "actual JS with inert DOM and independent synthetic API DTOs; not backend, browser or provider acceptance"}, "PASS fixture\n"),
            "test_operator_x_quota_ui.cjs": ({"ok": True, "browser": False, "network": False,
                "scope": "shared X posting-attempt quota UI contracts; no backend or enforcement acceptance"}, "PASS fixture\n"),
            "test_approval_decision_ui.cjs": ({"ok": True, "browser": False, "network": False,
                "scope": "actual approval UI functions with inert DOM and synthetic API/WebAuthn; not browser or protected authority acceptance"}, "PASS fixture\n"),
            "test_operator_workload_renewal_ui.cjs": ({"ok": True, "browser": False, "network": False,
                "source": "closed renewal DTO and inert DOM only"}, "PASS fixture\n"),
            "test_operator_pending_actions_ui.cjs": ({"ok": True, "backendAcceptance": False,
                "nativeReviewAcceptance": False,
                "scope": "pending-actions UI with inert DOM and synthetic API replies",
                "sourceSha256": hashlib.sha256((runner.ROOT /
                    "catchplate/operator_demo_web/workspace_pending_actions.js").read_bytes()).hexdigest()}, "PASS fixture\n"),
            "test_operator_common_apps_ui.cjs": ({"ok": True, "providers": 12, "operations": 15,
                "scope": "pure catalog, derived authority, public request examples and download contract; no provider or browser traffic"}, ""),
            "test_native_jit_review_portal.cjs": ({"ok": True, "synthetic": True,
                "nativeAdmission": False, "providerRequests": False}, "PASS fixture\n"),
            "test_operator_auth_state_ui.cjs": ({"ok": True,
                "scope": "actual workspace, notification and audit controllers; inert DOM and synthetic deferred GETs, not browser or backend acceptance"}, "PASS fixture\n"),
        }
        self.assertEqual({row.script for row in runner.SUITES if row.runtime == "node"},
            set(examples) | {"test_operator_runtime_browser_assets.cjs"})
        for script, (shape, prefix) in examples.items():
            def wire(value):
                return (prefix + json.dumps(value) + "\n").encode()
            valid = {**shape, "groups": 1}
            with self.subTest(script=script):
                self.assertEqual(runner.node_completion(script, wire(valid)), 1)
                for changed in ({**valid, "groups": 0}, {**valid, "groups": True}, {**valid, "groups": 1.0},
                        {**valid, "ok": False}, {**valid, "skipped": 1}, {**valid, "secret": "canary"}):
                    self.assertIsNone(runner.node_completion(script, wire(changed)))
                for key in shape:
                    self.assertIsNone(runner.node_completion(script, wire({name: value for name, value in valid.items()
                        if name != key})))
                    if type(shape[key]) is bool:
                        self.assertIsNone(runner.node_completion(script, wire({**valid, key: not shape[key]})))
                        self.assertIsNone(runner.node_completion(script, wire({**valid, key: 0})))
                    else:
                        self.assertIsNone(runner.node_completion(script, wire({**valid, key: "unreviewed-scope-or-source"})))
                self.assertIsNone(runner.node_completion(script, b""))
                self.assertIsNone(runner.node_completion(script, wire(valid) + b"extra\n"))
                self.assertIsNone(runner.node_completion(script, wire(valid).replace(b'"groups": 1', b'"groups": 1,"groups": 1')))
        quota = "test_operator_x_quota_ui.cjs"
        quota_shape = examples[quota][0]
        for count in (2, 11, 12):
            terminal = json.dumps({**quota_shape, "groups": count}).encode() + b"\n"
            self.assertEqual(runner.node_completion(quota, b"PASS fixture\n" * count + terminal), count)
            self.assertIsNone(runner.node_completion(quota, b"PASS fixture\n" * (count - 1) + terminal))
            self.assertIsNone(runner.node_completion(quota, b"PASS fixture\n" * (count + 1) + terminal))
            self.assertIsNone(runner.node_completion(quota, b"PASS fixture\n" * count + terminal.replace(
                b"no backend or enforcement acceptance", b"backend and enforcement accepted")))
        asset = "test_operator_runtime_browser_assets.cjs"
        self.assertEqual(runner.node_completion(asset,
            b"PASS fixture\n" * 33 + b"PASS 33 pure runtime-browser asset groups; no browser or service calls\n"), 33)
        for raw in (b"", b"PASS 0 pure runtime-browser asset groups; no browser or service calls\n",
                b"PASS 2 pure runtime-browser asset groups; no browser or service calls\n",
                b"PASS fixture\n" * 32 + b"PASS 33 pure runtime-browser asset groups; no browser or service calls\n"):
            self.assertIsNone(runner.node_completion(asset, raw))
        pending = "test_operator_pending_actions_ui.cjs"
        pending_shape = {**examples[pending][0], "groups": 18}
        def pending_wire(value, count=18):
            return b"PASS fixture\n" * count + json.dumps(value).encode() + b"\n"
        self.assertEqual(runner.node_completion(pending, pending_wire(pending_shape)), 18)
        for count in (17, 19):
            self.assertIsNone(runner.node_completion(pending, pending_wire(pending_shape, count)))
        for digest in ("0" * 64, "not-a-hash", None):
            self.assertIsNone(runner.node_completion(pending, pending_wire({**pending_shape, "sourceSha256": digest})))
        with patch.object(runner.Path, "read_bytes", side_effect=OSError):
            self.assertIsNone(runner.node_completion(pending, pending_wire(pending_shape)))
        script = "test_operator_npm_install_ui.cjs"
        for code, status in (("print('')", "node_completion_unobserved"),
                ("raise RuntimeError('private')", "failed")):
            result = runner.run_process([sys.executable, "-I", "-B", "-c", code], cwd=runner.ROOT,
                env={"PATH": os.defpath}, seconds=3, completion_script=script)
            self.assertEqual(result["status"], status)

    def test_missing_runtime_and_offline_refusal_happen_before_output_or_children(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "new"
            args = SimpleNamespace(python=sys.executable, node=sys.executable, dependency_root=None, output=output, partition="all")
            with patch.object(runner, "require_offline_network", side_effect=runner.Refused("network_none_required")), \
                    patch.object(runner.subprocess, "Popen") as child, self.assertRaises(runner.Refused):
                runner.run(args)
            child.assert_not_called()
            self.assertFalse(output.exists())
            args.node = str(Path(directory) / "missing")
            with patch.object(runner, "require_offline_network"), self.assertRaises(OSError):
                runner.run(args)
            self.assertFalse(output.exists())

    def test_failure_does_not_skip_independent_suite_or_turn_green(self):
        selected = runner.SUITES[:2]
        results = [{"status": "failed", "exitCode": 1},
            {"status": "passed", "exitCode": 0, "observedUnittestCounts": [1]}]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "results"
            args = SimpleNamespace(python=sys.executable, node=sys.executable, dependency_root=None, output=output, partition="all")
            with patch.object(runner, "require_offline_network"), patch.object(runner, "SUITES", selected), \
                    patch.object(runner, "run_process", side_effect=results) as run, patch("builtins.print"):
                self.assertEqual(runner.run(args), 1)
            self.assertEqual(run.call_count, 2)
            result = json.loads((output / "result.json").read_text())
            self.assertFalse(result["success"])
            self.assertFalse(result["productionAcceptance"])
            self.assertIn("stock_sdk", result["notExecuted"])
            self.assertEqual(result["managedClientRequirementsSha256"], hashlib.sha256(
                (runner.ROOT / "examples/managed-client/requirements.lock").read_bytes()).hexdigest())
            with patch.object(runner, "require_offline_network"), self.assertRaises(runner.Refused):
                runner.run(args)

    def test_fault_and_observer_commands_preserve_exact_arguments_and_receipts(self):
        expected = {
            "test_operator_x_quota_fault_relay.py": ["--loopback"],
            "test_operator_x_quota_fault_fixture.py": [],
            "test_operator_x_quota_fault_checker.py": [],
            "test_operator_rollout_x_quota.py": [],
            "test_operator_rollout_snapshot.py": [],
        }
        selected = tuple(row for row in runner.SUITES if row.script in expected)
        self.assertEqual(len(selected), len(expected))
        # Exercise orchestration only, never the loopback/product test bodies.
        synthetic = {"status": "passed", "exitCode": 0, "observedUnittestCounts": [1]}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "results"
            args = SimpleNamespace(python=sys.executable, node=sys.executable, dependency_root=None, output=output, partition="all")
            with patch.object(runner, "require_offline_network") as offline, \
                    patch.object(runner, "SUITES", selected), \
                    patch.object(runner, "run_process", return_value=synthetic) as run, patch("builtins.print"):
                self.assertEqual(runner.run(args), 0)
            offline.assert_called_once_with()
            self.assertEqual(run.call_count, len(expected))
            rows = json.loads((output / "result.json").read_text())["suites"]
            for suite, call, receipt in zip(selected, run.call_args_list, rows):
                self.assertEqual(call.args[0], [str(Path(sys.executable).resolve()), "-B",
                    str(runner.ROOT / "scripts" / suite.script), *expected[suite.script]])
                self.assertEqual(call.kwargs["seconds"], 60)
                self.assertIsNone(call.kwargs["completion_script"])
                self.assertEqual((receipt["script"], receipt["arguments"], receipt["category"]),
                    (suite.script, expected[suite.script], "backend"))

    def test_workflow_has_no_live_credentials_build_or_privileged_test_mounts(self):
        value = (runner.ROOT / ".github/workflows/ordinary-regression.yml").read_text()
        for required in ("pull_request:", "branches: [main]", "contents: read", "--network none",
                "--read-only", "--cap-drop ALL", "no-new-privileges", "--memory 2g", "--cpus 2",
                "--require-hashes", "--only-binary=:all:", "test_run_ordinary_regression.py",
                "--isolated", "--index-url https://pypi.org/simple",
                "src=$GITHUB_WORKSPACE/examples/managed-client/requirements.lock,dst=/managed-client-requirements.lock,readonly",
                "-r /requirements.lock -r /managed-client-requirements.lock",
                "dst=/usr/lib/x86_64-linux-gnu/libatomic.so.1,readonly", "/tools/node --version",
                "--tmpfs /tmp:rw,exec,nosuid,nodev,size=512m,mode=1777"):
            self.assertIn(required, value)
        for forbidden in ("pull_request_target:", "secrets.", "docker build", "/var/run/docker.sock", "--privileged"):
            self.assertNotIn(forbidden, value)
        self.assertLess(value.index("test_run_ordinary_regression.py"), value.index("run_ordinary_regression.py --node"))
        makefile = (runner.ROOT / "Makefile").read_text()
        isolated = makefile.split("override CODER_ISOLATED_TEST_SCRIPTS :=", 1)[1].split("\n\n", 1)[0]
        self.assertNotIn("scripts/test_managed_client.py", isolated)
        self.assertIn("--with-requirements examples/managed-client/requirements.lock", makefile)

    def test_workflow_partitions_and_signer_job_are_independent(self):
        value = (runner.ROOT / ".github/workflows/ordinary-regression.yml").read_text()
        events = value.split("\npermissions:\n", 1)[0]
        self.assertIn("\n  pull_request:\n  push:\n", events)
        self.assertIn("\n    paths-ignore:\n      - 'docs/**'\n      - 'goal.md'\n      - 'docker/**/README.md'\n  workflow_dispatch:\n", events)
        self.assertEqual(events.count("paths-ignore:"), 1)
        components, signers = value.split("\n  signers:\n", 1)
        self.assertIn("\n  components:\n", components)
        self.assertIn("fail-fast: false", components)
        matrices = re.findall(r"(?m)^        partition: \[([^\]\n]+)\]$", components)
        self.assertEqual(matrices, ["python-1, python-2, python-3, native-review, node"])
        self.assertEqual(tuple(matrices[0].split(", ")), runner.PARTITIONS[1:])
        self.assertIn('--partition "${{ matrix.partition }}"', components)
        self.assertIn("timeout --kill-after=10s 660s docker run", components)
        self.assertIn("name: ordinary-component-results-${{ matrix.partition }}", components)
        self.assertNotIn("run_native_jit_review_signers.py", components)
        self.assertNotIn("needs:", signers)
        self.assertIn("timeout --kill-after=10s 75s docker run", signers)
        self.assertIn("--network none", signers)
        self.assertIn("--user 0:0 --read-only --cap-drop ALL", signers)
        self.assertIn("scripts/run_native_jit_review_signers.py --dependency-root /deps", signers)
        self.assertIn("name: ordinary-signer-results", signers)
        self.assertEqual(value.count("if: always()"), 2)
        self.assertNotIn("continue-on-error", value)


if __name__ == "__main__":
    unittest.main(verbosity=2)
