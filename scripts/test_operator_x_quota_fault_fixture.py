"""Inert controls for the separate claim-ACK fault lane, not runtime proof.

Real fixture projections run with synthetic clocks and inspect records. The
audit hook rejects sockets, subprocesses, signals and container execution.
"""
from __future__ import annotations

import ast
from contextlib import redirect_stderr
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch


def forbid_runtime(event, args):
    if event.startswith(("socket.", "subprocess.", "os.exec", "os.spawn", "os.posix_spawn")) \
            or event in {"os.system", "os.fork", "os.forkpty", "os.kill", "os.killpg"}:
        raise AssertionError("inert fault fixture test attempted runtime I/O")


sys.addaudithook(forbid_runtime)
from scripts import operator_x_post_fixture as provider
from scripts import operator_x_post_fixture_network as network
from scripts import prepare_operator_x_post_fixture as recipe
from scripts import run_operator_x_post_fixture as runner
from scripts.test_operator_x_post_fixture import Flow
from scripts.test_prepare_operator_x_post_fixture import ARGS, PINS
from scripts.test_run_operator_x_post_fixture import FixedDateTime, IDS, inspect_rows, stamp

RELAY_ID = format(7, "064x")


def fault_flow():
    flow = Flow()
    flow.state = provider.FaultState(wall=lambda: flow.clock.wall, monotonic=lambda: flow.clock.mono)
    return flow


def fault_rows(config):
    rows, images = inspect_rows(config)
    synthetic = deepcopy(config)
    synthetic["services"]["provider"] = deepcopy(config["services"]["quota-relay"])
    relay = inspect_rows(synthetic)[0][1]
    relay["Id"] = RELAY_ID
    relay["Config"]["Labels"]["com.docker.compose.service"] = "quota-relay"
    rows.append(relay)
    return rows, images


class FaultFixtureTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(runner.time, "monotonic", return_value=1000.0))
        self.enterContext(patch.object(runner.time, "sleep", side_effect=AssertionError("unexpected wait")))
        self.enterContext(patch.object(runner.datetime, "datetime", FixedDateTime))

    def instance(self, mode="drop-ack"):
        value = runner.XPostRun(SimpleNamespace(source=Path("/synthetic"), evidence=Path("/synthetic"),
            quota=False, quota_fault=mode))
        value.save, value.wait_edge_ready = Mock(), Mock()
        return value

    def test_closed_additive_recipe_leaves_default_and_quota_lanes_unchanged(self):
        original = recipe.build(*ARGS, **PINS)
        quota = recipe.build(*ARGS, **PINS, quota=True)
        self.assertEqual(recipe.build(*ARGS, **PINS, fault_mode=None), original)
        self.assertEqual(recipe.build(*ARGS, **PINS, quota=True, fault_mode=None), quota)
        self.assertNotIn("quota-relay", original["services"])
        self.assertNotIn("quota-relay", quota["services"])
        for mode in ("drop-ack", "revoke-before-release"):
            config = recipe.build(*ARGS, **PINS, fault_mode=mode)
            recipe.validate(config, *ARGS, **PINS, fault_mode=mode)
            expected = deepcopy(original)
            services = expected["services"]
            for name in ("catchplate", "decision-gate-rs"):
                services[name]["environment"]["CATCHPLATE_OPERATOR_X_POST_ATTEMPT_QUOTA_ENABLED"] = "1"
            services["provider"]["command"] += ["--profile", "fault"]
            services["x-post-pki"]["command"] += ["--profile", "fault"]
            services["check"]["command"][0] = "/app/scripts/check_operator_x_quota_fault.py"
            services["check"]["command"] += ["--fault-mode", mode]
            services["catchplate"]["environment"]["CATCHPLATE_WEB_HOST"] = "127.0.0.1"
            gate_hosts = next(row for row in services["decision-gate-rs"]["volumes"]
                if row["target"] == "/etc/hosts")
            gate_hosts["source"] = str(ARGS[3] / "runtime/upstream-data/x-network/hosts-fault-gate")
            without_relay = deepcopy(config)
            relay = without_relay["services"].pop("quota-relay")
            self.assertEqual(without_relay, expected)
            self.assertEqual(config["services"]["decision-gate-rs"]["environment"]
                ["CATCHPLATE_CONTROL_PLANE_CREDENTIAL_LEASE_URL"],
                "http://catchplate:3000/api/data-plane/credential-leases")
            for name, service in config["services"].items():
                for mount in service["volumes"]:
                    if mount["target"] == "/etc/hosts":
                        leaf = "hosts-fault-gate" if name == "decision-gate-rs" else "hosts"
                        self.assertEqual(mount, recipe.bind(ARGS[3] / "runtime/upstream-data/x-network" / leaf,
                            "/etc/hosts"))
            self.assertEqual(set(config["services"]), set(original["services"]) | {"quota-relay"})
            self.assertEqual(relay["command"], ["python", "-B", "-m", "scripts.operator_x_quota_fault_relay",
                "--lifetime-seconds", "240"])
            self.assertEqual(relay["depends_on"], {"catchplate": {"condition": "service_healthy"}})
            self.assertEqual((relay["cpus"], relay["mem_limit"], relay["memswap_limit"], relay["pids_limit"]),
                (0.25, "128m", "128m", 32))
            self.assertEqual({row["target"] for row in relay["volumes"]},
                {"/app", "/etc/hosts", "/etc/resolv.conf", "/private-audit-fixture.json"})
            self.assertTrue(all(row["read_only"] and not row["bind"]["create_host_path"] for row in relay["volumes"]))
            marker = next(row for row in relay["volumes"] if row["target"] == "/private-audit-fixture.json")
            self.assertEqual(marker["source"], str(ARGS[3] / "runtime/.private-fixture.json"))
            for key in ("image", "entrypoint", "environment", "working_dir", "network_mode", "user", "init",
                    "read_only", "cap_drop", "security_opt", "logging", "restart", "pull_policy", "tmpfs"):
                self.assertEqual(relay[key], original["services"]["provider"][key])
            for key in ("ports", "expose", "networks", "extra_hosts", "privileged", "devices", "env_file"):
                self.assertNotIn(key, relay)
            health = relay["healthcheck"]
            self.assertEqual({key: health[key] for key in ("interval", "timeout", "retries", "start_period")},
                {"interval": "3s", "timeout": "3s", "retries": 3, "start_period": "1s"})
            self.assertIn("http://127.0.0.1:3001/__fault/status", health["test"][-1])
            self.assertIn("ProxyHandler({})", health["test"][-1])
            self.assertIn("read(4097)", health["test"][-1])
            with self.assertRaises(ValueError): recipe.validate(config, *ARGS, **PINS)
        for value in (True, 1, "", "drop_ack", "both", [], {}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                recipe.build(*ARGS, **PINS, fault_mode=value)
        with self.assertRaises(ValueError): recipe.build(*ARGS, **PINS, quota=True, fault_mode="drop-ack")
        self.assertEqual((recipe.INITIAL_TOKEN_SECONDS, recipe.CHECKER_SECONDS, recipe.KEEPER_SECONDS,
            recipe.EDGE_SECONDS, recipe.FAULT_RELAY_SECONDS, runner.WORK_SECONDS), (120, 180, 300, 240, 240, 390))

    def test_fault_gate_hosts_change_only_catchplate_and_recipe_refuses_other_wiring(self):
        def mapping(raw):
            result = {}
            for line in raw.decode("ascii").splitlines():
                address, *names = line.split()
                for name in names:
                    self.assertNotIn(name, result)
                    result[name] = address
            return result
        original = mapping(network.HOSTS)
        self.assertEqual(original["catchplate"], "127.0.0.1")
        self.assertEqual(network.FAULT_GATE_HOSTS_NAME, "hosts-fault-gate")
        self.assertEqual(network.FAULT_GATE_IP, "127.0.0.2")
        self.assertEqual(mapping(network.FAULT_GATE_HOSTS), dict(original, catchplate="127.0.0.2"))
        config = recipe.build(*ARGS, **PINS, fault_mode="drop-ack")
        for target, value in (("source", "/synthetic/wrong-hosts"), ("read_only", False)):
            changed = deepcopy(config)
            mount = next(row for row in changed["services"]["decision-gate-rs"]["volumes"]
                if row["target"] == "/etc/hosts")
            mount[target] = value
            with self.subTest(target=target), self.assertRaises(ValueError):
                recipe.validate(changed, *ARGS, **PINS, fault_mode="drop-ack")
        for service, field, value in (("catchplate", "CATCHPLATE_WEB_HOST", "0.0.0.0"),
                ("decision-gate-rs", "CATCHPLATE_CONTROL_PLANE_CREDENTIAL_LEASE_URL",
                    "http://catchplate:3001/api/data-plane/credential-leases")):
            changed = deepcopy(config); changed["services"][service]["environment"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                recipe.validate(changed, *ARGS, **PINS, fault_mode="drop-ack")

    def test_offline_pki_selects_extra_gate_hosts_only_for_fault_profile(self):
        for profile in ("sdk", "quota", "fault"):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "x-network"
                with patch.object(network, "Path", side_effect=lambda value:
                        root if value == "/upstream-data/x-network" else Path(value)), \
                        patch.object(network.os, "geteuid", return_value=10001), \
                        patch.object(network, "assert_isolated_network") as isolation:
                    network.prepare_network_files(fault_gate=profile == "fault")
                    isolation.assert_called_once_with(attached=False)
                    expected = {"hosts": network.HOSTS, "resolv.conf": network.RESOLV}
                    if profile == "fault":
                        expected["hosts-fault-gate"] = network.FAULT_GATE_HOSTS
                    self.assertEqual({path.name: path.read_bytes() for path in root.iterdir()}, expected)
                    self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
                    self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o444
                        and path.stat().st_nlink == 1 for path in root.iterdir()))
                    with self.assertRaises(ValueError):
                        network.prepare_network_files(fault_gate=profile == "fault")
                with patch.object(sys, "argv", ["fixture", "--setup", "--profile", profile]), \
                        patch.object(provider, "setup") as setup, patch.object(provider.os, "umask"), \
                        patch.object(provider.signal, "alarm"):
                    provider.main()
                    setup.assert_called_once_with(fault_gate=profile == "fault")
        setup = next(node for node in ast.parse(Path(provider.__file__).read_text()).body
            if isinstance(node, ast.FunctionDef) and node.name == "setup")
        calls = [node for node in ast.walk(setup) if isinstance(node, ast.Call)
            and ast.unparse(node.func) == "network.prepare_network_files"]
        self.assertEqual([ast.unparse(node) for node in calls],
            ["network.prepare_network_files(fault_gate=fault_gate)"])

    def test_gate_network_proof_is_explicit_and_provider_view_remains_strict(self):
        def prove(view, hosts, *, wrong_catchplate=False):
            mapping = {name: line.split()[0] for line in hosts.decode("ascii").splitlines()
                for name in line.split()[1:]}
            if wrong_catchplate:
                mapping["catchplate"] = "127.0.0.1"
            paths = {"/etc/hosts": hosts, "/etc/resolv.conf": network.RESOLV}
            with patch.object(network.isolated, "assert_isolated_network") as base, \
                    patch.object(network, "Path", side_effect=lambda path: Mock(read_bytes=Mock(return_value=paths[path]))), \
                    patch.object(network.socket, "socket", return_value=MagicMock()) as socket_factory, \
                    patch.object(network.socket, "getaddrinfo", side_effect=lambda host, *args:
                        [(network.socket.AF_INET, network.socket.SOCK_STREAM, 6, "", (mapping[host], 443))]):
                network.assert_isolated_network(view=view)
                base.assert_called_once_with(attached=False)
                calls = socket_factory.return_value.__enter__.return_value.bind.call_args_list
                self.assertEqual([row.args for row in calls], [((network.FIXTURE_IP, 0),)] +
                    ([(("127.0.0.2", 0),)] if view == "fault-gate" else []))
        prove("ordinary", network.HOSTS)
        prove("fault-gate", network.FAULT_GATE_HOSTS)
        for view, hosts, wrong in (("ordinary", network.FAULT_GATE_HOSTS, False),
                ("fault-gate", network.HOSTS, False), ("fault-gate", network.FAULT_GATE_HOSTS, True),
                ("fault-gate", network.FAULT_GATE_HOSTS + b"127.0.0.1 extra\n", False),
                ("alternate", network.HOSTS, False)):
            with self.subTest(view=view, wrong=wrong), self.assertRaises(ValueError):
                prove(view, hosts, wrong_catchplate=wrong)
        with self.assertRaises(ValueError):
            network.assert_isolated_network(attached=False, view="fault-gate")

    def test_provider_one_consent_original_expiry_zero_posts_and_two_revocations(self):
        flow = fault_flow(); token = flow.connect()
        initial = flow.state.observations()
        self.assertEqual(initial["initialAccessExpiresAtEpochMs"] - initial["initialAccessIssuedAtEpochMs"], 120000)
        for hint in ("access_token", "refresh_token"):
            self.assertEqual(flow.revoke(token, hint)[0], 200)
        view = flow.state.observations()
        self.assertEqual(set(view), set(Flow().state.observations()))
        self.assertEqual(view["schema"], "catchplate.privateXQuotaFaultProvider/v1")
        self.assertEqual(view["counts"], {"total": 5, "authorize": 1, "code": 1, "refresh": 0,
            "identity": 1, "revoke": 2, "posts": 0, "rejected": 0})
        self.assertEqual(view["issuedGenerations"], [1]); self.assertEqual(view["posts"], [])
        self.assertEqual(view["initialAccessExpiresAtEpochMs"], initial["initialAccessExpiresAtEpochMs"])
        self.assertTrue(view["cleanupComplete"]); self.assertFalse(view["refreshAfterInitialExpiry"])
        self.assertEqual([row["generation"] for row in view["revocations"]], [1, 1])
        public = provider.encoded(view)
        for secret in (provider.CLIENT_SECRET, flow.code, flow.verifier, flow.browser_state,
                token["access_token"], token["refresh_token"]):
            self.assertNotIn(secret.encode(), public)

    def test_provider_refuses_every_post_refresh_and_second_consent(self):
        for client in ("node", "python", "go"):
            flow = fault_flow(); token = flow.connect()
            self.assertEqual(flow.post(client, token)[0], 400)
            view = flow.state.observations()
            self.assertEqual(view["posts"], []); self.assertEqual(view["counts"]["rejected"], 1)
        flow = fault_flow(); token = flow.connect()
        expiry = flow.state.observations()["initialAccessExpiresAtEpochMs"]
        flow.clock.advance(121)
        self.assertEqual(flow.refresh()[0], 400)
        self.assertEqual(flow.state.observations()["issuedGenerations"], [1])
        self.assertEqual(flow.state.observations()["initialAccessExpiresAtEpochMs"], expiry)
        for hint in ("access_token", "refresh_token"):
            self.assertEqual(flow.revoke(token, hint)[0], 200)
        self.assertEqual(flow.authorize()[0], 400)

    def test_seven_exact_services_only_for_explicit_fault_lane(self):
        config = recipe.build(*ARGS, **PINS, fault_mode="drop-ack")
        rows, images = fault_rows(config)
        value = self.instance(); value.container_rows = Mock(return_value=rows)
        value.image_environments = {image: {"PATH": "/usr/bin:/bin"} for image in images}
        self.assertEqual(value.inspect_runtime(config, images, keeper_anchor=950), dict(IDS, **{"quota-relay": RELAY_ID}))
        self.assertEqual(value.fault_relay_started_at, stamp(20))
        for mode in (None, "unknown"):
            value.args.quota_fault = mode
            with self.assertRaises(ValueError): value.inspect_runtime(config, images, keeper_anchor=950)
        value.args.quota_fault = "drop-ack"
        mutations = [lambda rows: rows.pop(), lambda rows: rows.append(deepcopy(rows[-1])),
            lambda rows: rows[-1]["HostConfig"].update(NetworkMode="host"),
            lambda rows: rows[-1]["Config"]["Env"].append("HTTP_PROXY=untrusted"),
            lambda rows: rows[-1]["Config"]["Cmd"].append("--target=http://elsewhere"),
            lambda rows: rows[-1]["State"].update(StartedAt=stamp(30)),
            lambda rows: rows[-1]["State"]["Health"].update(Status="starting"),
            lambda rows: rows[-1]["Mounts"].append({"Type": "bind", "Source": "/private", "Destination": "/data", "RW": False})]
        for index, mutate in enumerate(mutations):
            changed = deepcopy(rows); mutate(changed); value.container_rows.return_value = changed
            with self.subTest(index=index), self.assertRaises(ValueError):
                value.inspect_runtime(config, images, keeper_anchor=950)

    def test_app_publication_then_relay_then_gate_and_no_fallback_after_failure(self):
        for failure in (None, "publication", "fault-relay-start"):
            value = self.instance(); calls = []
            def record(name, *args, **kwargs):
                calls.append((name, args, kwargs))
                if failure == name: raise ValueError("synthetic setup refusal")
                return {"public": "synthetic retained publication"}
            value.command = record
            value.public_view = lambda *a, **kw: record("publication", *a, **kw)
            value.container_rows = Mock(return_value=[{"Id": IDS[name], "Config": {"Labels": {
                "com.docker.compose.service": name}}} for name in ("network", "provider", "catchplate")])
            if failure is None:
                value.start_app_then_gate(["docker", "compose"])
                self.assertEqual([row[0] for row in calls], ["app-start", "publication", "fault-relay-start", "gate-start"])
                self.assertEqual(calls[2][1], (["docker", "compose", "up", "-d", "--no-build", "--pull", "never",
                    "--no-deps", "--wait", "--wait-timeout", "12", "quota-relay"], 15))
                # Permit one timed-out cold probe and the next bounded probe;
                # do not reset any relay, keeper, checker or credential clock.
                self.assertGreater(12, 1 + 3 + 3 + 3)
                self.assertEqual((recipe.PRECHECK_SECONDS, recipe.KEEPER_SECONDS,
                    recipe.CHECKER_SECONDS, recipe.FAULT_RELAY_SECONDS,
                    recipe.INITIAL_TOKEN_SECONDS, runner.WORK_SECONDS), (75, 300, 180, 240, 120, 390))
            else:
                with self.assertRaises(ValueError): value.start_app_then_gate(["docker", "compose"])
                self.assertEqual([row[0] for row in calls], ["app-start", "publication"] +
                    (["fault-relay-start"] if failure == "fault-relay-start" else []))

    def test_final_dispatch_reuses_original_relay_identity_and_lifetime(self):
        value = self.instance(); value.fault_relay_started_at = stamp(5); value.deadline = 1250
        state = {"Status": "running", "OOMKilled": False, "Health": {"Status": "healthy"}, "StartedAt": stamp(5)}
        value.command = Mock(return_value=json.dumps(state).encode())
        self.assertIsNone(value.admit_fault_relay_window(RELAY_ID))
        self.assertEqual(value.deadline, 1250)
        value.command.assert_called_once_with("fault-relay-launch-state",
            ["docker", "inspect", "--format", "{{json .State}}", RELAY_ID], 3)
        for changed in (dict(state, Status="exited"), dict(state, OOMKilled=True),
                dict(state, Health={"Status": "unhealthy"}), dict(state, StartedAt=stamp(4))):
            value.command.return_value = json.dumps(changed).encode()
            with self.assertRaises(ValueError): value.admit_fault_relay_window(RELAY_ID)
        for age in (-1, 30, 240):
            value.fault_relay_started_at = stamp(age)
            value.command.return_value = json.dumps(dict(state, StartedAt=stamp(age))).encode()
            with self.assertRaises(ValueError): value.admit_fault_relay_window(RELAY_ID)
        value.command.reset_mock()
        with self.assertRaises(ValueError): value.admit_fault_relay_window("short")
        value.command.assert_not_called()

    def test_actual_result_lane_guard_and_no_quota_restart_for_faults(self):
        tree = ast.parse(Path(runner.__file__).read_text())
        execute = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "execute")
        guard = next(node for node in ast.walk(execute) if isinstance(node, ast.If)
            and "result['faultMode']" in ast.unparse(node))
        code = compile(ast.fix_missing_locations(ast.Module(body=[guard], type_ignores=[])), runner.__file__, "exec")
        for mode in ("drop-ack", "revoke-before-release"):
            exec(code, {"fault_mode": mode, "result": {"faultMode": mode}, "require": runner.require})
            for wrong in ({}, {"faultMode": "unknown"}, {"faultMode": None}):
                with self.assertRaises((ValueError, KeyError)):
                    exec(code, {"fault_mode": mode, "result": wrong, "require": runner.require})
        wait = next(node.value for node in ast.walk(execute) if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "exit_code" for target in node.targets))
        wait_code = compile(ast.Expression(body=wait), runner.__file__, "eval")
        instance = SimpleNamespace(quota_checker_wait=Mock(side_effect=AssertionError("fault cannot restart")),
            command=Mock(return_value=b"0"))
        self.assertEqual(eval(wait_code, {"self": instance, "quota": False, "identities": IDS, "checker": IDS["check"]}), 0)
        instance.command.assert_called_once_with("checker-wait", ["docker", "wait", IDS["check"]], 190)

    def test_closed_cli_requires_separate_fresh_lanes(self):
        argv = ["runner"]
        for name in ("source", "job-root", "evidence", "binary", "go", "node", "node-modules", "initializer", "python-runtime", "python-packages"):
            argv += ["--" + name, "/synthetic/" + name]
        argv += ["--commit", "e" * 40]
        for name, value in PINS.items(): argv += ["--" + name.replace("_", "-"), value]
        for mode in ("drop-ack", "revoke-before-release"):
            instance = SimpleNamespace(execute=Mock(return_value=0))
            with patch.object(runner.sys, "argv", argv + ["--quota-fault", mode]), \
                    patch.object(runner, "XPostRun", return_value=instance) as construct, \
                    patch.object(runner.os, "umask"), patch.dict(os.environ, {}):
                self.assertEqual(runner.main(), 0)
                self.assertFalse(construct.call_args.args[0].quota)
                self.assertEqual(construct.call_args.args[0].quota_fault, mode)
        for extra in (["--quota", "--quota-fault", "drop-ack"], ["--quota-fault", "drop_ack"],
                ["--quota-fault", "both"], ["--relay-target", "http://elsewhere"]):
            with patch.object(runner.sys, "argv", argv + extra), patch.object(runner, "XPostRun") as construct, \
                    redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                runner.main()
            construct.assert_not_called()


if __name__ == "__main__":
    unittest.main()
