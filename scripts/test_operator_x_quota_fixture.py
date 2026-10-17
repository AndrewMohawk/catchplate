"""Inert quota-profile and exact restart controls, never runtime acceptance.

Synthetic clocks/inspect rows model only the declared boundaries. No socket,
SDK, subprocess, Docker, provider or real application state is accessed.
"""
from __future__ import annotations

import ast
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


def forbid_runtime(event, args):
    if event.startswith(("socket.", "subprocess.", "os.exec", "os.spawn", "os.posix_spawn")) \
            or event in {"os.system", "os.fork", "os.forkpty", "os.kill", "os.killpg"}:
        raise AssertionError("inert quota test attempted runtime I/O")


sys.addaudithook(forbid_runtime)
from scripts import operator_x_post_fixture as provider
from scripts import operator_x_post_fixture_network as network
from scripts import prepare_operator_x_post_fixture as recipe
from scripts import run_operator_x_post_fixture as runner
from scripts.test_operator_x_post_fixture import Flow
from scripts.test_prepare_operator_x_post_fixture import ARGS, PINS
from scripts.test_run_operator_x_post_fixture import IDS, inspect_rows


def quota_flow():
    flow = Flow()
    flow.state = provider.QuotaState(wall=lambda: flow.clock.wall, monotonic=lambda: flow.clock.mono)
    return flow


def request():
    return {"schema": "catchplate.privateXQuotaRestartRequest/v1",
        "run_id": "10000000-0000-4000-8000-000000000001", "phase": "after_three",
        "policy_hash": "sha256:" + "a" * 64,
        "credential_id": "20000000-0000-4000-8000-000000000002",
        "application_ids": ["30000000-0000-4000-8000-000000000003", "40000000-0000-4000-8000-000000000004"],
        "initial_access_expires_at_epoch_ms": 1800000120000}


def acknowledgement(value):
    return {"schema": "catchplate.privateXQuotaRestartAck/v1", "status": "retained_restarted",
        "request_sha256": "sha256:" + hashlib.sha256(network.quota_json(value)).hexdigest()}


class ProfileTests(unittest.TestCase):
    def test_preservation_key_roster_matches_actual_provider_key_owner_without_importing_app(self):
        # Read only the maintained owner's literal filename. Importing the app
        # or provider-key runtime into the snapshot helper is not necessary.
        source = Path(__file__).resolve().parents[1] / "catchplate/operator_provider_key.py"
        owner = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        names = [node.value for node in owner.body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "FILENAME" for target in node.targets)]
        self.assertEqual(len(names), 1)
        filename = ast.literal_eval(names[0])
        self.assertEqual(filename, "provider-key.json")
        self.assertEqual(network.QUOTA_KEY_FILES, ("/data/master.key", "/data/policy-signing-ed25519.pem",
            "/data/response-signing-ed25519.pem", "/x-custody/" + filename))
        # All four hashes remain mandatory: the real snapshot's comprehension
        # has no existence filter, fallback key name or ignored missing leaf.
        module = ast.parse(Path(network.__file__).read_text(encoding="utf-8"))
        snapshot = next(node for node in module.body if isinstance(node, ast.FunctionDef)
            and node.name == "quota_preservation_snapshot")
        keys = next(node.value for node in ast.walk(snapshot) if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "keys" for target in node.targets))
        self.assertIsInstance(keys, ast.DictComp)
        self.assertEqual(len(keys.generators), 1)
        self.assertEqual(ast.unparse(keys.generators[0].iter), "QUOTA_KEY_FILES")
        self.assertEqual(keys.generators[0].ifs, [])
        self.assertEqual(ast.unparse(keys.value), "file_hash(Path(name))")

    def test_default_recipe_unchanged_and_only_explicit_quota_changes(self):
        original = recipe.build(*ARGS, **PINS)
        self.assertEqual(recipe.build(*ARGS, **PINS, quota=False), original)
        quota = recipe.build(*ARGS, **PINS, quota=True)
        expected = deepcopy(original)
        expected["services"]["provider"]["command"] += ["--profile", "quota"]
        expected["services"]["check"]["command"][0] = "/app/scripts/check_operator_x_quota.py"
        for name in ("catchplate", "decision-gate-rs"):
            expected["services"][name]["environment"]["CATCHPLATE_OPERATOR_X_POST_ATTEMPT_QUOTA_ENABLED"] = "1"
        self.assertEqual(quota, expected)
        recipe.validate(quota, *ARGS, **PINS, quota=True)
        with self.assertRaises(ValueError): recipe.validate(quota, *ARGS, **PINS)
        for value in (None, 0, 1, "quota", [], {}):
            with self.subTest(value=value), self.assertRaises(ValueError): recipe.build(*ARGS, **PINS, quota=value)
        self.assertEqual((recipe.INITIAL_TOKEN_SECONDS, recipe.CHECKER_SECONDS, recipe.KEEPER_SECONDS,
            recipe.EDGE_SECONDS, runner.WORK_SECONDS), (120, 180, 300, 240, 390))

    def test_four_posts_original_expiry_and_genuine_second_consent_same_subject(self):
        flow = quota_flow(); flow.connect()
        first = deepcopy(flow.first)
        expiry = flow.state.observations()["initialAccessExpiresAtEpochMs"]
        for client in ("node", "python", "go"):
            self.assertEqual(flow.post(client, first)[0], 201)
        flow.clock.advance(121)
        self.assertEqual(flow.refresh()[0], 200)
        second = deepcopy(flow.second)
        self.assertEqual(flow.identity(second)[0], 200)
        self.assertEqual(flow.post("node", second)[0], 201)
        for token in (first, second):
            for hint in ("access_token", "refresh_token"):
                self.assertEqual(flow.revoke(token, hint)[0], 200)
        self.assertTrue(flow.state.observations()["cleanupComplete"])
        alias = flow.connect()
        self.assertNotEqual(alias["access_token"], first["access_token"])
        self.assertFalse(flow.state.observations()["cleanupComplete"])
        for hint in ("access_token", "refresh_token"):
            self.assertEqual(flow.revoke(alias, hint)[0], 200)
        view = flow.state.observations()
        self.assertEqual(view["schema"], "catchplate.privateXQuotaProvider/v1")
        self.assertEqual(view["counts"], {"total": 18, "authorize": 2, "code": 2,
            "refresh": 1, "identity": 3, "revoke": 6, "posts": 4, "rejected": 0})
        self.assertEqual(view["issuedTokenFamilies"], [{"alias": 1, "generation": 1},
            {"alias": 1, "generation": 2}, {"alias": 2, "generation": 1}])
        self.assertNotIn("issuedGenerations", view)
        self.assertEqual(view["initialAccessExpiresAtEpochMs"], expiry)
        self.assertTrue(view["initialAccessExpired"] and view["refreshAfterInitialExpiry"] and view["cleanupComplete"])
        self.assertEqual([(row["client"], row["alias"], row["generation"]) for row in view["posts"]],
            [("node", 1, 1), ("python", 1, 1), ("go", 1, 1), ("node", 1, 2)])
        self.assertEqual([row["alias"] for row in view["revocations"]], [1, 1, 1, 1, 2, 2])
        for row in view["posts"]:
            self.assertEqual(set(row), provider.POST_KEYS | {"alias"})
            self.assertEqual(row["responseBodySha256"], provider.sha(provider.response_body(row["ordinal"])))
        public = network.quota_json(view)
        for secret in (provider.CLIENT_SECRET, flow.code, flow.verifier, flow.browser_state,
                *[token[hint] for token in (first, second, alias) for hint in ("access_token", "refresh_token")]):
            self.assertNotIn(secret.encode(), public)

    def test_quota_profile_refuses_early_refresh_fifth_post_and_unrevoked_reconnect(self):
        flow = quota_flow(); flow.connect()
        self.assertEqual(flow.authorize()[0], 400)
        flow.clock.advance(61)
        self.assertEqual(flow.refresh()[0], 400)
        self.assertEqual(flow.state.observations()["issuedTokenFamilies"], [{"alias": 1, "generation": 1}])
        flow = quota_flow(); flow.connect(); first = deepcopy(flow.first)
        for client in ("node", "python", "go"): self.assertEqual(flow.post(client, first)[0], 201)
        flow.clock.advance(121); flow.refresh(); self.assertEqual(flow.identity(flow.second)[0], 200)
        self.assertEqual(flow.post("node", flow.second)[0], 201)
        self.assertEqual(flow.post("python", flow.second)[0], 400)
        for token in (first, flow.second):
            self.assertEqual(flow.revoke(token, "access_token")[0], 200)
        self.assertEqual(flow.authorize()[0], 400)  # Refresh tokens still live.
        for token in (first, flow.second): self.assertEqual(flow.revoke(token, "refresh_token")[0], 200)
        alias = flow.connect()
        self.assertEqual(flow.post("node", alias)[0], 400)
        self.assertEqual(flow.refresh()[0], 400)  # No second-family refresh lane.
        for hint in ("access_token", "refresh_token"): self.assertEqual(flow.revoke(alias, hint)[0], 200)
        self.assertEqual(flow.authorize()[0], 400)  # No third consent.
        self.assertEqual(len(flow.state.observations()["posts"]), 4)

    def test_checkpoint_is_exact_public_typed_and_bound(self):
        value = request(); self.assertIs(network.quota_checkpoint(value), value)
        ack = acknowledgement(value); self.assertIs(network.quota_checkpoint(ack, ack=True), ack)
        mutations = [dict(value, schema="foreign"), dict(value, phase="restart_again"),
            dict(value, extra="forbidden"), dict(value, initial_access_expires_at_epoch_ms=True),
            dict(value, initial_access_expires_at_epoch_ms=2**53), dict(value, policy_hash="a" * 64),
            dict(value, run_id="not-uuid"), dict(value, credential_id=value["run_id"]),
            dict(value, application_ids=[value["application_ids"][0]] * 2),
            dict(value, application_ids=tuple(value["application_ids"]))]
        for changed in mutations:
            with self.subTest(value=changed), self.assertRaises((ValueError, TypeError)):
                network.quota_checkpoint(changed)
        for changed in (dict(ack, status="pending"), dict(ack, request_sha256="f" * 64),
                dict(ack, secret="forbidden"), dict(ack, request_sha256=True)):
            with self.assertRaises(ValueError): network.quota_checkpoint(changed, ack=True)

    def test_checkpoint_real_temporary_files_atomic_ack_and_unsafe_file_refusals(self):
        # Only UID/GID are synthetic kernel controls. Real no-follow opens,
        # exclusive links, modes, canonical bytes and fsync run on owned files.
        with tempfile.TemporaryDirectory(prefix="x-quota-checkpoint-unit-") as name:
            root = Path(name); root.chmod(0o700)
            actual_lstat, actual_fstat = Path.lstat, os.fstat
            def owned(row):
                keys = ("st_dev", "st_ino", "st_size", "st_mode", "st_nlink", "st_mtime_ns", "st_ctime_ns")
                return SimpleNamespace(**{key: getattr(row, key) for key in keys}, st_uid=10001, st_gid=10001)
            with patch.object(network, "Path", side_effect=lambda value: root if value == "/client-work" else Path(value)), \
                    patch.object(Path, "lstat", autospec=True, side_effect=lambda path: owned(actual_lstat(path))), \
                    patch.object(network.os, "fstat", side_effect=lambda fd: owned(actual_fstat(fd))), \
                    patch.object(network.os, "geteuid", return_value=10001), \
                    patch.object(network.os, "getegid", return_value=10001):
                self.assertIsNone(network.read_quota_checkpoint())
                path = root / network.QUOTA_REQUEST
                path.write_bytes(network.quota_json(request())); path.chmod(0o600)
                self.assertEqual(network.read_quota_checkpoint(), request())
                with self.assertRaises(ValueError): network.acknowledge_quota_restart("sha256:" + "f" * 64)
                self.assertFalse((root / network.QUOTA_ACK).exists())
                ack = acknowledgement(request())
                self.assertEqual(network.acknowledge_quota_restart(ack["request_sha256"]), ack)
                self.assertEqual(network.read_quota_checkpoint(ack=True), ack)
                self.assertEqual(actual_lstat(root / network.QUOTA_ACK).st_nlink, 1)
                with self.assertRaises(FileExistsError): network.acknowledge_quota_restart(ack["request_sha256"])
                self.assertEqual(network.read_quota_checkpoint(ack=True), ack)
                path.chmod(0o644)
                with self.assertRaises(ValueError): network.read_quota_checkpoint()
                path.chmod(0o600); os.link(path, root / "extra-link")
                with self.assertRaises(ValueError): network.read_quota_checkpoint()
                (root / "extra-link").unlink()
                path.write_bytes(network.quota_json(request()) + b"\n")
                with self.assertRaises(ValueError): network.read_quota_checkpoint()
                path.unlink(); path.symlink_to(root / network.QUOTA_ACK)
                with self.assertRaises(OSError): network.read_quota_checkpoint()


class RestartTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(runner.time, "monotonic", return_value=1000.0))
        self.enterContext(patch.object(runner.time, "time", return_value=1800000000.0))
        self.enterContext(patch.object(runner.time, "sleep"))

    def instance(self):
        value = runner.XPostRun(SimpleNamespace(source=Path("/synthetic"), evidence=Path("/synthetic")))
        value.deadline = 1285
        config = recipe.build(*ARGS, **PINS, quota=True)
        before, _ = inspect_rows(config)
        for row in before: row["State"]["Status"] = "running"
        after = deepcopy(before)
        for row in after:
            if row["Id"] in (IDS["catchplate"], IDS["decision-gate-rs"]):
                row["State"]["StartedAt"] = "2026-10-12T12:00:01Z"
        value.container_rows = Mock(side_effect=[before, after])
        context = request()
        retained = {"schema": "synthetic snapshot double", "claimed": 3, "outstanding": 0,
            "policy_hash": context["policy_hash"], "credential_id": context["credential_id"],
            "application_ids": context["application_ids"]}
        value.quota_helper = Mock(side_effect=[retained, deepcopy(retained), acknowledgement(context)])
        value.public_view = Mock(return_value={"synthetic": "unchanged public view"})
        value.quota_provider_snapshot = Mock(return_value={"initialAccessExpiresAtEpochMs": context["initial_access_expires_at_epoch_ms"]})
        value.quota_wait_healthy, value.save = Mock(), Mock()
        value.command = Mock(return_value=b'{"Status":"exited","Pid":0,"OOMKilled":false}')
        return value, before, after, retained

    def test_exact_one_gate_then_app_restart_preserves_original_clock_and_all_other_ids(self):
        value, _, _, _ = self.instance()
        value.restart_for_quota(IDS, request())
        self.assertEqual([call.args[0] for call in value.command.call_args_list],
            ["quota-stop-gate", "quota-stopped-gate", "quota-stop-app", "quota-stopped-app", "quota-start-app", "quota-start-gate"])
        self.assertEqual(value.command.call_args_list[0].args[1], ["docker", "stop", "--time", "5", IDS["decision-gate-rs"]])
        self.assertEqual(value.command.call_args_list[2].args[1], ["docker", "stop", "--time", "5", IDS["catchplate"]])
        self.assertEqual(value.command.call_args_list[4].args[1], ["docker", "start", IDS["catchplate"]])
        self.assertEqual(value.command.call_args_list[5].args[1], ["docker", "start", IDS["decision-gate-rs"]])
        self.assertEqual(value.deadline, 1285)
        self.assertEqual([call.args for call in value.quota_wait_healthy.call_args_list],
            [(IDS["catchplate"], "app", 25), (IDS["decision-gate-rs"], "gate", 15)])
        self.assertEqual(value.quota_helper.call_args_list[-1].args,
            (IDS["check"], "quota-ack", "once", "--request-sha256", acknowledgement(request())["request_sha256"]))
        receipt = value.quota_restart
        self.assertTrue(receipt["originalProviderEdgeKeeperUnchanged"] and receipt["originalDeadlineUnchanged"])
        self.assertEqual({key: row["manualRestarts"] for key, row in receipt["restarted"].items()},
            {"catchplate": 1, "decision-gate-rs": 1})
        with self.assertRaises(ValueError): value.restart_for_quota(IDS, request())
        self.assertEqual(value.command.call_count, 6)

    def test_restart_drift_or_failure_never_acknowledges_or_retries(self):
        for mode in ("snapshot", "context", "provider", "edge_restart", "image", "app_not_restarted", "stop_failure", "budget", "expiry"):
            value, before, after, retained = self.instance()
            if mode == "snapshot": value.quota_helper.side_effect = [retained, dict(retained, claimed=0)]
            elif mode == "context": value.quota_helper.side_effect = [dict(retained, policy_hash="sha256:" + "f" * 64)]
            elif mode == "provider": value.quota_provider_snapshot.side_effect = [dict(initialAccessExpiresAtEpochMs=1800000120001)]
            elif mode == "edge_restart": after[4]["State"]["StartedAt"] = "changed"
            elif mode == "image": after[2]["Image"] = "sha256:" + "f" * 64
            elif mode == "app_not_restarted": after[2]["State"]["StartedAt"] = before[2]["State"]["StartedAt"]
            elif mode == "stop_failure": value.command.side_effect = ValueError("synthetic stop refused")
            elif mode == "budget": value.deadline = 1060
            elif mode == "expiry": self.enterContext(patch.object(runner.time, "time", return_value=1800000120.0))
            with self.subTest(mode=mode), self.assertRaises(ValueError): value.restart_for_quota(IDS, request())
            self.assertFalse(hasattr(value, "quota_restart"))
            self.assertFalse(any(call.args[1] == "quota-ack" for call in value.quota_helper.call_args_list))

    def test_checker_rendezvous_requests_once_and_requires_completed_restart(self):
        value, _, _, _ = self.instance()
        value.command = Mock(side_effect=[json.dumps({"Status": status, "OOMKilled": False, "ExitCode": 0}).encode()
            for status in ("running", "running", "running", "exited")])
        value.quota_helper = Mock(side_effect=[None, request()])
        value.restart_for_quota = Mock(side_effect=lambda *_: setattr(value, "quota_restart", {"completed": True}))
        self.assertEqual(value.quota_checker_wait(IDS), 0)
        value.restart_for_quota.assert_called_once_with(IDS, request())
        self.assertEqual(value.quota_helper.call_count, 2)
        self.assertEqual(value.deadline, 1285)
        value, _, _, _ = self.instance()
        value.command = Mock(return_value=b'{"Status":"exited","OOMKilled":false,"ExitCode":0}')
        with self.assertRaises(ValueError): value.quota_checker_wait(IDS)
        value.quota_helper.assert_not_called()

    def test_provider_checkpoint_rejects_wrong_generation_counts_or_reset_expiry(self):
        flow = quota_flow(); flow.connect()
        for client in ("node", "python", "go"): flow.post(client, flow.first)
        view = flow.state.observations()
        value, _, _, _ = self.instance(); value.command.return_value = network.quota_json(view)
        del value.quota_provider_snapshot  # Exercise the real bounded projection, not the orchestration double.
        self.assertEqual(value.quota_provider_snapshot(IDS["provider"], "unit"), view)
        for changed in (dict(view, issuedTokenFamilies=[{"alias": 1, "generation": 2}]),
                dict(view, initialAccessExpired=True), dict(view, overflowed=True),
                dict(view, counts=dict(view["counts"], posts=4)), dict(view, terminal="expired")):
            value.command.return_value = network.quota_json(changed)
            with self.assertRaises(ValueError): value.quota_provider_snapshot(IDS["provider"], "unit")


if __name__ == "__main__":
    unittest.main()
