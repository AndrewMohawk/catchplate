"""Pure recipe/orchestration controls, NOT Docker, SDK or provider acceptance.

Calls actual closed builders, inspector, deadline and inherited cleanup helpers.
Container metadata/command outputs are deliberately synthetic. No socket,
subprocess, image, secret, initializer, or real client is executed.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import datetime
import json
from pathlib import Path
import socket
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import prepare_operator_gmail_sdk_fixture as recipe
from scripts import run_operator_gmail_sdk_fixture as runner
from scripts import run_operator_x_examples_fixture as legacy
from scripts import operator_gmail_sdk_fixture_network as glue


SOURCE = Path("/synthetic/source")
BINARY, INITIALIZER, GO = (Path("/synthetic/" + name) for name in ("gate", "initialize.py", "google-gmail"))
JOB = Path("/srv/catchplate-fast/tmp/catchplate-gmail-sdk-private.abcdef12")
ARGS = (SOURCE, BINARY, INITIALIZER, JOB, GO)
PINS = {"expected_binary_sha256": "a" * 64, "expected_go_sha256": "b" * 64}
NOW = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)


class FixedDateTime(datetime.datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW


def rows_for(config):
    images = {value: "sha256:" + str(index) * 64 for index, value in enumerate(
        sorted({service["image"] for service in config["services"].values()}), 1)}
    identities = {name: format(index, "064x") for index, name in enumerate(sorted(recipe.RUNTIME_SERVICES), 1)}
    rows = []
    for name in sorted(recipe.RUNTIME_SERVICES):
        service = config["services"][name]
        rows.append({"Id": identities[name], "Image": images[service["image"]], "RestartCount": 0,
            "Config": {"User": service["user"], "Labels": {"com.docker.compose.project": config["name"],
                "com.docker.compose.service": name}},
            "State": {"OOMKilled": False, "Status": "created" if name == "check" else "running",
                "Health": {"Status": "healthy"}, "StartedAt": (NOW - datetime.timedelta(seconds=10)).isoformat()},
            "HostConfig": {"Privileged": False, "ReadonlyRootfs": True, "PortBindings": {},
                "NetworkMode": "none" if name == "network" else "container:" + identities["network"],
                "CapDrop": ["ALL"], "CapAdd": ["CAP_" + cap for cap in service.get("cap_add", [])],
                "SecurityOpt": ["no-new-privileges:true"]},
            "Mounts": [{"Type": "bind", "Source": mount["source"], "Destination": mount["target"],
                "RW": not mount["read_only"]} for mount in service["volumes"]]})
    return rows, images


class GmailSdkRecipeTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(subprocess, "Popen", side_effect=AssertionError("no subprocess in pure test")))
        self.enterContext(patch.object(socket, "socket", side_effect=AssertionError("no socket in pure test")))
        self.config = recipe.build(*ARGS, **PINS)

    def test_closed_go_only_topology_and_public_trust_mounts(self):
        services = self.config["services"]
        self.assertEqual(set(services), recipe.RUNTIME_SERVICES | {"initialize", "basic-pki"})
        self.assertNotIn("networks", self.config)
        for name, service in services.items():
            self.assertEqual(service["network_mode"], "none" if name in {"initialize", "network", "basic-pki"} else "service:network")
            self.assertTrue(service["read_only"])
            self.assertEqual(service["restart"], "no")
            self.assertEqual(service["pull_policy"], "never")
            self.assertEqual(service["cap_drop"], ["ALL"])
            self.assertFalse(service.get("ports"))
            self.assertFalse(service.get("networks"))
            for mount in service["volumes"]:
                self.assertFalse(mount["bind"]["create_host_path"])
                self.assertNotIn("node_modules", mount["target"])
                self.assertNotIn("client-dependencies", mount["target"])
                self.assertNotIn("example-python", mount["target"])
                if mount["source"] in map(str, (SOURCE, BINARY, INITIALIZER, GO)):
                    self.assertTrue(mount["read_only"])
        check = services["check"]
        self.assertEqual(check["image"], recipe.base.APP_IMAGE)
        self.assertEqual(check["environment"], {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": "/app"})
        mounts = {item["target"]: item for item in check["volumes"]}
        self.assertEqual(mounts[recipe.GO_TARGET], recipe.base.bind(GO, "/example-go/google-gmail"))
        for source, target in (("inner-ca.pem", "inner-ca.pem"), ("outer-ca.pem", "outer-ca.pem"),
                ("requests-ca.pem", "combined-ca.pem")):
            self.assertEqual(mounts["/client-trust/" + target], recipe.base.bind(
                JOB / "runtime/https-proxy/basic-pki" / source, "/client-trust/" + target))
        self.assertEqual(check["command"][check["command"].index("--proxy-url") + 1], recipe.PROXY_URL)
        self.assertEqual(check["command"][check["command"].index("--expected-go-sha256") + 1], PINS["expected_go_sha256"])

    def test_original_google_profile_and_timers_are_not_mutated(self):
        google = recipe.google
        self.assertEqual(google.GMAIL_JOB_LIFETIME_SECONDS, 300)
        self.assertEqual(google.GMAIL_JOB_CHECKER_SECONDS, 180)
        self.assertEqual((recipe.KEEPER_SECONDS, recipe.EDGE_SECONDS, recipe.PRECHECK_SECONDS), (300, 240, 75))
        self.assertEqual(recipe.CHECKER_OUTER_SECONDS + recipe.PRECHECK_SECONDS + 15, recipe.KEEPER_SECONDS)
        self.assertEqual(glue.google.keep_namespace.__module__, "scripts.operator_google_fixture_setup")
        template = JOB.with_name("catchplate-google-private.abcdef12")
        inherited = google.build(SOURCE, BINARY, INITIALIZER, template, profile=google.GMAIL_JOB_PROFILE,
            expected_binary_sha256=PINS["expected_binary_sha256"], client_dependencies=google.GMAIL_CLIENT_DEPENDENCIES,
            client_dependencies_manifest_sha256=google.GMAIL_CLIENT_MANIFEST_SHA256)
        self.assertEqual(inherited["services"]["provider"]["command"][3], "scripts.operator_gmail_job_fixture")
        self.assertIn(recipe.base.bind(google.GMAIL_CLIENT_DEPENDENCIES, "/client-dependencies"),
            inherited["services"]["check"]["volumes"])
        self.assertEqual(self.config["services"]["network"]["command"], inherited["services"]["network"]["command"])
        self.assertEqual(self.config["services"]["provider"]["command"][-2:], ["--lifetime-seconds", "300"])
        self.assertEqual(self.config["services"]["basic-pki"]["volumes"][1],
            recipe.base.bind(JOB / "runtime/https-proxy", "/fixture-runtime", False))

    def test_browser_endpoint_config_hosts_and_checker_are_one_closed_choice(self):
        from scripts import check_operator_gmail_sdk as checker
        enabled = recipe.build(*ARGS, **PINS, browser_permission=True)
        url = "https://catchplate-gmail-proxy.example.com"
        for mode, config, expected in ((False, self.config, "https://proxy.operator-basic.example.test:8443"),
                                      (True, enabled, url)):
            services = config["services"]
            command = services["check"]["command"]
            self.assertEqual(command[command.index("--proxy-url") + 1], expected)
            self.assertEqual(checker.fixture_proxy(mode), (expected, "127.0.0.2" if mode else "127.0.0.1"))
            self.assertEqual(services["initialize"]["command"][-1], "browser-initialize" if mode else "initialize")
            self.assertEqual(services["edge"]["command"][-1], "browser-edge" if mode else "edge")
            self.assertEqual("--proxy-hostname" in services["basic-pki"]["command"], mode)
        for service in ("catchplate", "decision-gate-rs"):
            self.assertEqual(enabled["services"][service]["environment"]["CATCHPLATE_OPERATOR_DEMO_PROXY_URL"], url)
            self.assertEqual(self.config["services"][service]["environment"]["CATCHPLATE_OPERATOR_DEMO_PROXY_URL"],
                "https://catchplate-proxy.example.com")
        original = b"127.0.0.1 localhost catchplate decision-gate-rs catchplate-demo.example.com\n93.184.216.34 gmail.googleapis.com\n"
        self.assertEqual(glue.hosts_bytes(original), original.replace(b"catchplate-demo.example.com\n",
            b"catchplate-demo.example.com proxy.operator-basic.example.test\n"))
        self.assertEqual(glue.hosts_bytes(original, browser_permission=True),
            original + b"127.0.0.2 catchplate-gmail-proxy.example.com\n")
        for value in (None, 0, 1, "true"):
            with self.subTest(value=value), self.assertRaises(checker.CheckFailure): checker.fixture_proxy(value)
            with self.subTest(value=value), self.assertRaises(ValueError): glue.hosts_bytes(original, browser_permission=value)
        for service in ("catchplate", "decision-gate-rs"):
            for altered in ("https://catchplate-proxy.example.com", "https://proxy.operator-basic.example.test:8443", url + ":443"):
                wrong = deepcopy(enabled)
                wrong["services"][service]["environment"]["CATCHPLATE_OPERATOR_DEMO_PROXY_URL"] = altered
                with self.subTest(service=service, altered=altered), self.assertRaises(ValueError):
                    recipe.validate(wrong, *ARGS, **PINS, browser_permission=True)
        for service in ("initialize", "edge", "basic-pki", "check"):
            wrong = deepcopy(enabled)
            wrong["services"][service]["command"] = deepcopy(self.config["services"][service]["command"])
            with self.subTest(service=service), self.assertRaises(ValueError):
                recipe.validate(wrong, *ARGS, **PINS, browser_permission=True)

    def test_actual_checker_peer_guard_refuses_mode_origin_and_address_drift(self):
        # Synthetic resolved peers only; the actual constructor's guard runs.
        # Accepted cases stop at their first file pin, never read files/connect.
        from scripts import check_operator_gmail_sdk as checker
        from scripts.check_operator_demo import CheckFailure
        stop = RuntimeError("fixture stopped before file pin")
        for mode in (False, True):
            url, address = checker.fixture_proxy(mode)
            for wrong in (None, "origin", "proxy", "control", "management"):
                args = SimpleNamespace(browser_permission=mode, proxy_url=url if wrong != "origin" else url + ":443")
                def resolved(owner, _args):
                    owner.control = SimpleNamespace(address="127.0.0.2" if wrong == "control" else "127.0.0.1")
                    owner.management = SimpleNamespace(address="127.0.0.2" if wrong == "management" else "127.0.0.1")
                    owner.proxy = SimpleNamespace(address=("127.0.0.1" if mode else "127.0.0.2") if wrong == "proxy" else address)
                with self.subTest(mode=mode, wrong=wrong), \
                     patch.object(checker.base.GoogleRefreshCheck, "__init__", resolved), \
                     patch.object(checker, "read_pin", side_effect=stop) as read:
                    with self.assertRaises(CheckFailure if wrong else RuntimeError) as caught:
                        checker.GmailSdkCheck(args)
                    if wrong: read.assert_not_called()
                    else:
                        self.assertIs(caught.exception, stop)
                        self.assertEqual(read.call_count, 1)

    def test_exact_recipe_rejects_omitted_extra_services_ports_and_network_interfaces(self):
        recipe.validate(self.config, *ARGS, **PINS)
        def mutate(value, case):
            if case == "missing": del value["services"]["edge"]
            elif case == "extra": value["services"]["other"] = deepcopy(value["services"]["check"])
            elif case == "ports": value["services"]["edge"]["ports"] = ["8443:8443"]
            elif case == "network": value["services"]["network"]["network_mode"] = "host"
            elif case == "bridge": value["services"]["provider"]["networks"] = {"outside": {}}
            elif case == "ca-write": value["services"]["check"]["volumes"][-1]["read_only"] = False
            else: value["services"]["provider"]["command"][-1] = "301"
        for case in ("missing", "extra", "ports", "network", "bridge", "ca-write", "lifetime"):
            value = deepcopy(self.config); mutate(value, case)
            with self.subTest(case=case), self.assertRaises(ValueError):
                recipe.validate(value, *ARGS, **PINS)

    def test_scalar_pins_paths_and_existing_job_refuse_before_initializer(self):
        for key in PINS:
            for value in (None, True, 123, "a" * 63, "A" * 64, "sha256:" + "a" * 64):
                pins = dict(PINS); pins[key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    recipe.build(*ARGS, **pins)
        for root in (JOB.with_name("catchplate-google-private.abcdef12"), Path("/tmp") / JOB.name):
            with self.assertRaises(ValueError):
                recipe.build(SOURCE, BINARY, INITIALIZER, root, GO, **PINS)
        for value in ("relative", "/synthetic/../source"):
            with self.assertRaises(argparse.ArgumentTypeError): runner.absolute_path(value)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source, job, evidence = (root / name for name in ("source", "job", "evidence"))
            for path in (source, job, evidence): path.mkdir(mode=0o700)
            (job / "prior.claim").write_text("retained synthetic prior attempt")
            args = SimpleNamespace(source=source, job_root=job, evidence=evidence, commit="a" * 40)
            run = runner.GmailSdkRun(args)
            with patch.object(run, "command", side_effect=AssertionError("initializer replay")), self.assertRaises(ValueError):
                run.execute()
            self.assertEqual(list(evidence.iterdir()), [])
            self.assertEqual((job / "prior.claim").read_text(), "retained synthetic prior attempt")


class GmailSdkRunnerTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(subprocess, "Popen", side_effect=AssertionError("no subprocess in pure test")))
        self.enterContext(patch.object(socket, "socket", side_effect=AssertionError("no socket in pure test")))
        self.enterContext(patch.object(runner.datetime, "datetime", FixedDateTime))
        self.clock = self.enterContext(patch.object(runner.time, "monotonic", return_value=100.0))
        self.config = recipe.build(*ARGS, **PINS)
        self.rows, self.images = rows_for(self.config)
        self.run = runner.GmailSdkRun(SimpleNamespace())
        self.run.project, self.run.services = self.config["name"], self.config["services"]
        self.run.deadline = 165.0  # Original keeper anchor90 + precheck75.
        self.saved = {}
        self.run.save = lambda name, value: self.saved.setdefault(name, value)

    def inspect(self, rows=None, *, anchor=90):
        rows = self.rows if rows is None else rows
        def output(name, arguments, seconds=30):
            if name == "created-ids": return ("\n".join(row["Id"] for row in rows) + "\n").encode()
            if name == "created-inspect": return json.dumps(rows).encode()
            if name == "edge-ready": return b'{"ready":true,"syntheticOnly":true,"headerRewriting":false}'
            if name == "edge-ready-state-0": return b'{"Status":"running","OOMKilled":false}'
            raise AssertionError("unexpected synthetic inspector command")
        with patch.object(self.run, "command", side_effect=output):
            return self.run.inspect_runtime(self.config, self.images, recipe, keeper_anchor=anchor)

    def test_actual_inspector_uses_gmail_roster_and_exact_namespace_mounts(self):
        self.assertEqual(self.inspect(), next(row["Id"] for row in self.rows
            if row["Config"]["Labels"]["com.docker.compose.service"] == "check"))
        self.assertEqual(len(self.saved["container-observations.json"]), 6)
        self.assertIs(runner.GmailSdkRun.container_rows, runner.Run.container_rows)
        self.assertIs(runner.GmailSdkRun.no_project_networks, runner.Run.no_project_networks)
        self.assertIsNot(runner.GmailSdkRun.cleanup, runner.Run.cleanup)
        self.assertEqual(legacy.RUNTIME_SERVICES,
            {"network", "x", "catchplate", "decision-gate-rs", "edge", "check"})

    def test_inspector_rejects_real_containment_shapes_and_expired_original_budget(self):
        for case in ("missing", "foreign-service", "foreign-project", "network", "port", "writable", "mount", "cap",
                "image", "unhealthy", "oom", "restart", "old-keeper", "old-provider", "old-edge"):
            rows = deepcopy(self.rows)
            row = next(item for item in rows if item["Config"]["Labels"]["com.docker.compose.service"] == "provider")
            if case == "missing": rows.remove(row)
            elif case == "foreign-service": row["Config"]["Labels"]["com.docker.compose.service"] = "x"
            elif case == "foreign-project": row["Config"]["Labels"]["com.docker.compose.project"] = "other"
            elif case == "network": row["HostConfig"]["NetworkMode"] = "host"
            elif case == "port": row["HostConfig"]["PortBindings"] = {"443/tcp": [{"HostPort": "443"}]}
            elif case == "writable": row["HostConfig"]["ReadonlyRootfs"] = False
            elif case == "mount": row["Mounts"][0]["RW"] = True
            elif case == "cap": row["HostConfig"]["CapAdd"] = ["CAP_NET_ADMIN"]
            elif case == "image": row["Image"] = "sha256:" + "f" * 64
            elif case == "unhealthy": row["State"]["Health"]["Status"] = "unhealthy"
            elif case == "oom": row["State"]["OOMKilled"] = True
            elif case == "restart": row["RestartCount"] = 1
            else:
                name = {"old-keeper": "network", "old-provider": "provider", "old-edge": "edge"}[case]
                selected = next(item for item in rows if item["Config"]["Labels"]["com.docker.compose.service"] == name)
                selected["State"]["StartedAt"] = (NOW - datetime.timedelta(seconds=80)).isoformat()
            with self.subTest(case=case), self.assertRaises(ValueError): self.inspect(rows)
        with self.assertRaises(ValueError): self.inspect(anchor=25)

    def test_commands_preserve_one_deadline_and_reserve_forced_reap(self):
        self.run.deadline = 110
        with patch.object(runner.Run, "command", autospec=True, return_value=b"observed") as inherited:
            self.assertEqual(self.run.command("phase", ["not-executed"], 30), b"observed")
            self.assertEqual(inherited.call_args.args[-1], 4)
            self.assertEqual(self.run.deadline, 110)
            self.clock.return_value = 104
            with self.assertRaises(ValueError): self.run.command("late", ["not-executed"], 30)
            self.assertEqual(inherited.call_count, 1)

    def test_edge_delayed_readiness_observes_same_process_and_preserves_original_deadline(self):
        edge = "e" * 64
        calls, sleeps = [], []
        ready = b'{"ready":true,"syntheticOnly":true,"headerRewriting":false}'
        def output(owner, name, arguments, seconds=30):
            self.assertIs(owner, self.run)
            self.assertEqual(arguments[-1], edge)
            self.assertGreater(seconds, 0)
            self.assertLessEqual(seconds, 2)
            calls.append((name, arguments))
            if arguments[:2] == ["docker", "logs"]:
                return ready if name == "edge-ready-2" else b""
            self.assertEqual(arguments, ["docker", "inspect", "--format", "{{json .State}}", edge])
            return b'{"Status":"running","OOMKilled":false}'
        def sleep(seconds):
            self.assertGreater(seconds, 0)
            self.assertLessEqual(seconds, 0.25)
            sleeps.append(seconds)
            self.clock.return_value += seconds
        with patch.object(runner.Run, "command", autospec=True, side_effect=output), \
                patch.object(runner.time, "sleep", side_effect=sleep):
            self.assertIsNone(self.run.wait_edge_ready(edge))
        self.assertEqual([name for name, _ in calls], ["edge-ready", "edge-ready-state-0",
            "edge-ready-1", "edge-ready-state-1", "edge-ready-2", "edge-ready-state-2"])
        self.assertEqual(sleeps, [0.25, 0.25])
        self.assertEqual(self.run.deadline, 165.0)
        self.assertEqual(self.clock.return_value, 100.5)

    def test_edge_ready_log_does_not_override_termination_oom_or_malformed_output(self):
        edge = "e" * 64
        ready = b'{"ready":true,"syntheticOnly":true,"headerRewriting":false}'
        for raw, state in ((b"", {"Status": "exited", "OOMKilled": False}),
                (ready, {"Status": "exited", "OOMKilled": False}),
                (ready, {"Status": "running", "OOMKilled": True}),
                (b"{}", None), (b"not-json", None)):
            calls = []
            def output(owner, name, arguments, seconds=30):
                self.assertIs(owner, self.run)
                self.assertEqual(arguments[-1], edge)
                calls.append(name)
                if arguments[:2] == ["docker", "logs"]: return raw
                self.assertIsNotNone(state, "malformed nonempty logs must fail before another observation")
                self.assertEqual(arguments, ["docker", "inspect", "--format", "{{json .State}}", edge])
                return json.dumps(state).encode()
            with self.subTest(raw=raw, state=state), \
                    patch.object(runner.Run, "command", autospec=True, side_effect=output), \
                    patch.object(runner.time, "sleep", side_effect=AssertionError("terminated edge must not wait")), \
                    self.assertRaises(ValueError):
                self.run.wait_edge_ready(edge)
            self.assertEqual(calls, ["edge-ready"] if state is None else ["edge-ready", "edge-ready-state-0"])
            self.assertEqual(self.run.deadline, 165.0)

    def test_edge_readiness_uses_original_cutoff_including_time_spent_in_final_state_read(self):
        edge = "e" * 64
        self.run.deadline = 106.0  # No remaining observation budget after reap reserve.
        with patch.object(runner.Run, "command", autospec=True) as inherited, self.assertRaises(ValueError):
            self.run.wait_edge_ready(edge)
        inherited.assert_not_called()
        self.assertEqual(self.run.deadline, 106.0)
        for expire_during_state in (False, True):
            self.clock.return_value = 100.0
            self.run.deadline = 107.0
            calls = []
            def output(owner, name, arguments, seconds=30):
                self.assertIs(owner, self.run)
                self.assertEqual(arguments[-1], edge)
                self.assertGreater(seconds, 0)
                self.assertLessEqual(seconds, 101.0 - self.clock.return_value)
                calls.append(name)
                if arguments[:2] == ["docker", "logs"]:
                    return b'{"ready":true,"syntheticOnly":true,"headerRewriting":false}' if expire_during_state else b""
                self.assertEqual(arguments, ["docker", "inspect", "--format", "{{json .State}}", edge])
                if expire_during_state: self.clock.return_value = 101.0
                return b'{"Status":"running","OOMKilled":false}'
            def sleep(seconds):
                self.assertLessEqual(seconds, 0.25)
                self.clock.return_value += seconds
            with self.subTest(expire_during_state=expire_during_state), \
                    patch.object(runner.Run, "command", autospec=True, side_effect=output), \
                    patch.object(runner.time, "sleep", side_effect=sleep), self.assertRaises(ValueError):
                self.run.wait_edge_ready(edge)
            self.assertEqual(len(calls), 2 if expire_during_state else 8)
            self.assertEqual(self.clock.return_value, 101.0)
            self.assertEqual(self.run.deadline, 107.0)

    def test_cleanup_removes_only_owned_ids_and_propagates_listing_failures(self):
        for failure in (None, "cleanup-before-ids", "cleanup-after-ids", "cleanup-networks"):
            seen = []
            def output(name, arguments, seconds=30):
                seen.append((name, arguments, seconds))
                if name == failure: raise ValueError("synthetic listing refusal")
                if name == "cleanup-before-ids": return ("\n".join(row["Id"] for row in self.rows) + "\n").encode()
                if name == "cleanup-before-inspect": return json.dumps(self.rows).encode()
                return b""
            with self.subTest(failure=failure), patch.object(self.run, "command", side_effect=output):
                clean, errors = self.run.cleanup()
            self.assertEqual(clean, failure is None)
            self.assertEqual(self.run.deadline, 160)
            mutations = [argv for name, argv, _ in seen if name in {"cleanup-stop", "cleanup-remove"}]
            if failure == "cleanup-before-ids":
                self.assertEqual(mutations, [])
                self.assertEqual(errors, ["inspect"])
            else:
                ids = [row["Id"] for row in self.rows]
                self.assertEqual(mutations, [["docker", "stop", "--time", "5", *ids], ["docker", "rm", "--force", *ids]])
                self.assertFalse(any("initialize" in argv for _, argv, _ in seen))
                if failure is not None: self.assertIn("verification", errors)


if __name__ == "__main__":
    unittest.main()
