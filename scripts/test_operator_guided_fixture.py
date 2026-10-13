"""Pure guided recipe/runner controls; no browser, process, socket or SDK run."""
from __future__ import annotations

from copy import deepcopy
import datetime
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
        raise AssertionError("pure guided fixture attempted runtime I/O")


sys.addaudithook(forbid_runtime)
from scripts import prepare_operator_guided_fixture as recipe
from scripts import run_operator_guided_fixture as runner
from scripts import operator_guided_fixture_network as network

ROOT = Path("/srv/catchplate-fast/tmp/serverware-guided-private.abcdef12")
ARGS = (Path("/synthetic/source"), Path("/synthetic/gate"), Path("/synthetic/initializer.py"), ROOT)
PIN = "a" * 64
NOW = datetime.datetime(2026, 10, 12, 12, tzinfo=datetime.timezone.utc)


class FixedDateTime(datetime.datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW if tz else NOW.replace(tzinfo=None)


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.config = recipe.build(*ARGS, expected_binary_sha256=PIN)

    def test_closed_recipe_has_no_seed_or_external_network_and_original_bounds(self):
        self.assertEqual(set(self.config), {"name", "services"})
        services = self.config["services"]
        self.assertEqual(set(services), {"initialize", "network-files", "basic-pki", "network", "provider",
            "serverware", "decision-gate-rs", "edge", "check"})
        self.assertEqual((runner.WORK_SECONDS, runner.CLEANUP_SECONDS, recipe.KEEPER_SECONDS, recipe.EDGE_SECONDS,
            recipe.CHECKER_SECONDS, recipe.CHECKER_OUTER_SECONDS, recipe.PRECHECK_SECONDS), (300, 60, 300, 240, 180, 190, 75))
        for name, service in services.items():
            self.assertEqual(service["network_mode"], "none" if name in {"initialize", "network-files", "basic-pki", "network"}
                else "service:network")
            self.assertTrue(service["read_only"]); self.assertEqual(service["cap_drop"], ["ALL"])
            self.assertEqual(service["pull_policy"], "never"); self.assertEqual(service["restart"], "no")
            self.assertEqual(service["mem_limit"], service["memswap_limit"])
            self.assertLessEqual(service["cpus"], 2); self.assertLessEqual(service["pids_limit"], 128)
            for forbidden in ("networks", "ports", "expose", "dns", "extra_hosts", "privileged", "devices", "env_file"):
                self.assertNotIn(forbidden, service)
            self.assertNotIn("NET_ADMIN", service.get("cap_add", []))
            self.assertEqual(len(service["volumes"]), len({row["target"] for row in service["volumes"]}))
        self.assertEqual(services["initialize"]["command"], ["python", "-B", "/initialize.py"])
        self.assertEqual(services["provider"]["command"], ["python", "-B", "scripts/demo_upstream.py"])
        self.assertEqual(services["serverware"]["depends_on"], {"provider": {"condition": "service_healthy"}})
        self.assertFalse(any("seed" in str(value).lower() for service in services.values() for value in service.get("command", [])))

    def test_curated_gate_only_has_publication_and_exact_original_leaf_overlays(self):
        services = self.config["services"]
        app, gate = services["serverware"], services["decision-gate-rs"]
        self.assertEqual(app["environment"]["SERVERWARE_OPERATOR_GATE_PUBLICATION_ENABLED"], "1")
        for service in (app, gate):
            self.assertEqual(service["environment"]["SERVERWARE_OPERATOR_DEMO_FIXTURE_CIDRS"], '["127.0.0.2/32"]')
            self.assertEqual(service["environment"]["SERVERWARE_OPERATOR_DEMO_UPSTREAMS"], '["https://demo-upstream:8443"]')
            self.assertEqual(service["environment"]["SERVERWARE_OPERATOR_DEMO_PROXY_URL"], "https://serverware-gmail-proxy.example.com")
            self.assertNotIn("SERVERWARE_OPERATOR_MANAGED_X_ENABLED", service["environment"])
        mounts = {row["target"]: row for row in gate["volumes"] if row["target"].startswith("/data")}
        self.assertEqual(set(mounts), {"/data", *("/data/" + name for name in recipe.LEAVES)})
        self.assertEqual(mounts["/data"]["source"], str(ROOT / "runtime/app-data/gate-runtime"))
        for leaf in recipe.LEAVES:
            self.assertEqual(mounts["/data/" + leaf]["source"], str(ROOT / "runtime/app-data" / leaf))
        self.assertTrue(all(row["read_only"] for row in mounts.values()))
        self.assertTrue(all(not row["bind"]["create_host_path"] for row in gate["volumes"]))

    def test_fixed_checker_cli_private_stdio_curl_pin_and_separate_trust(self):
        check = self.config["services"]["check"]
        self.assertIs(check["stdin_open"], True); self.assertIs(check["tty"], False)
        self.assertEqual(check["image"], recipe.basic.CLIENT_IMAGE)
        self.assertEqual(check["entrypoint"], ["/usr/bin/python3.10", "-B"])
        self.assertEqual(check["command"][0], "/app/scripts/check_operator_guided.py")
        args = dict(zip(check["command"][1::2], check["command"][2::2]))
        self.assertEqual(args["--control-base"], "http://127.0.0.1:3000")
        self.assertEqual(args["--management-base"], "http://127.0.0.1:9091")
        self.assertEqual(args["--operator-origin"], "https://serverware-guided.example.com")
        self.assertEqual(args["--proxy-url"], "https://serverware-gmail-proxy.example.com")
        self.assertEqual(args["--expected-binary-sha256"], "sha256:" + PIN)
        self.assertEqual(args["--curl-binary"], "/usr/bin/curl")
        self.assertEqual(args["--expected-curl-sha256"], "0ca2b923679ab186f6512c7512e131a1c5c1b43d4cb5d55933998405b39e85bf")
        self.assertEqual(args["--timeout-seconds"], "180")
        self.assertEqual(args["--ca-file"], "/client-trust/inner-ca.pem")
        self.assertEqual(args["--proxy-ca-file"], "/client-trust/outer-ca.pem")
        self.assertEqual(check["environment"], {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": "/app"})
        self.assertEqual(check["logging"], {"driver": "none", "options": {}})
        for name, service in self.config["services"].items():
            if name != "check":
                self.assertEqual(service["logging"], {"driver": "local", "options": {"max-size": "2m", "max-file": "2"}})
        self.assertNotIn("/client-dependencies", {row["target"] for row in check["volumes"]})
        self.assertEqual(self.config["services"]["basic-pki"]["command"], ["-m", "scripts.operator_guided_fixture_network", "pki"])

    def test_exact_recipe_recomputation_rejects_roster_origin_mount_and_lifetime_drift(self):
        recipe.validate(self.config, *ARGS, expected_binary_sha256=PIN)
        mutations = [lambda c: c["services"]["check"].update(stdin_open=False),
            lambda c: c["services"]["check"].update(logging={"driver": "local", "options": {}}),
            lambda c: c["services"]["check"]["logging"].update(options={"max-size": "2m"}),
            lambda c: c["services"]["network"].update(network_mode="host"),
            lambda c: c["services"]["edge"]["command"].append("--lifetime-seconds=999"),
            lambda c: c["services"]["serverware"]["environment"].update(SERVERWARE_PUBLIC_URL="https://different.example.com"),
            lambda c: c["services"]["decision-gate-rs"]["volumes"][-1].update(read_only=False),
            lambda c: c["services"].pop("network-files")]
        for mutate in mutations:
            changed = deepcopy(self.config); mutate(changed)
            with self.assertRaises(ValueError): recipe.validate(changed, *ARGS, expected_binary_sha256=PIN)
        with self.assertRaises(ValueError): recipe.build(*ARGS[:3], Path("/tmp") / ROOT.name, expected_binary_sha256=PIN)

    def test_network_contract_contains_only_fixed_loopback_hosts_and_one_shot_files(self):
        self.assertEqual(network.HOSTS, b"127.0.0.1 localhost serverware decision-gate-rs serverware-guided.example.com serverware-gmail-proxy.example.com\n127.0.0.2 demo-upstream\n")
        self.assertEqual(network.RESOLV, b"nameserver 127.0.0.1\noptions attempts:1 timeout:1\n")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "hosts"
            network.write_once(path, network.HOSTS)
            self.assertEqual(path.read_bytes(), network.HOSTS)
            self.assertEqual(path.stat().st_mode & 0o777, 0o400)
            with self.assertRaises(FileExistsError): network.write_once(path, b"replacement")
            self.assertEqual(path.read_bytes(), network.HOSTS)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="guided-unit-"))).resolve()
        self.enterContext(patch.object(runner.time, "monotonic", return_value=1000.0))
        self.enterContext(patch.object(runner.datetime, "datetime", FixedDateTime))

    def instance(self):
        value = runner.GuidedRun(SimpleNamespace(source=self.root, job_root=self.root, evidence=self.root,
            expected_binary_sha256=PIN))
        value.save = Mock()
        return value

    def test_only_pinned_client_image_admits_its_exact_overridden_image_entrypoint(self):
        client = "sha256:b2ce90db12b1df24e9d405fcd1e48d50ebad0039e523d30fde8fb1fb64fafafa"
        self.assertEqual(recipe.basic.CLIENT_IMAGE, client)
        self.assertTrue(runner.admitted_image_entrypoint(client, ["/entrypoint.sh"]))
        for invalid in (None, [], "/entrypoint.sh", ["/entrypoint.sh", "extra"], ["/bin/sh"], ["/usr/bin/python3.10", "-B"]):
            with self.subTest(entrypoint=invalid):
                self.assertFalse(runner.admitted_image_entrypoint(client, invalid))
        config = recipe.build(*ARGS, expected_binary_sha256=PIN)
        for image in {service["image"] for service in config["services"].values()} - {client}:
            self.assertTrue(runner.admitted_image_entrypoint(image, None))
            self.assertTrue(runner.admitted_image_entrypoint(image, []))
            for invalid in (["/entrypoint.sh"], ["/bin/sh"], "", False):
                with self.subTest(image=image, entrypoint=invalid):
                    self.assertFalse(runner.admitted_image_entrypoint(image, invalid))
        self.assertEqual(config["services"]["check"]["entrypoint"], ["/usr/bin/python3.10", "-B"])

    def test_dispatch_rechecks_original_edge_and_bounds_browser_by_original_keeper_and_work(self):
        value = self.instance()
        value.edge_started_at = (NOW - datetime.timedelta(seconds=10)).isoformat()
        state = {"Status": "running", "OOMKilled": False, "StartedAt": value.edge_started_at}
        value.command = Mock(return_value=json.dumps(state).encode())
        self.assertEqual(value.admit_checker_window("e" * 64, keeper_anchor=960, work_anchor=930), 1230)
        self.assertEqual(value.admit_checker_window("e" * 64, keeper_anchor=950, work_anchor=980), 1235)
        for changes, keeper, begun in (({"Status": "exited"}, 960, 930), ({"OOMKilled": True}, 960, 930),
                ({"StartedAt": NOW.isoformat()}, 960, 930), ({}, 925, 930), ({}, 950, 896)):
            value.command.return_value = json.dumps(dict(state, **changes)).encode()
            with self.assertRaises(ValueError): value.admit_checker_window("e" * 64, keeper_anchor=keeper, work_anchor=begun)
        for age in (-1, 50, 240):
            value.edge_started_at = (NOW - datetime.timedelta(seconds=age)).isoformat()
            value.command.return_value = json.dumps(dict(state, StartedAt=value.edge_started_at)).encode()
            with self.assertRaises(ValueError): value.admit_checker_window("e" * 64, keeper_anchor=960, work_anchor=930)

    def test_reused_runtime_check_adds_actual_checker_open_stdin_and_no_tty_binding(self):
        value = self.instance(); ids = {"check": "a" * 64}
        row = {"Id": ids["check"], "Config": {"Labels": {"com.docker.compose.service": "check"}, "OpenStdin": True, "Tty": False}}
        value.container_rows = Mock(return_value=[row])
        with patch.object(runner.XPostRun, "inspect_runtime", return_value=ids):
            self.assertEqual(value.inspect_runtime({}, {}, keeper_anchor=950), ids)
            for field, invalid in (("OpenStdin", False), ("Tty", True)):
                changed = deepcopy(row); changed["Config"][field] = invalid; value.container_rows.return_value = [changed]
                with self.assertRaises(ValueError): value.inspect_runtime({}, {}, keeper_anchor=950)
            value.container_rows.return_value = [dict(row, Id="b" * 64)]
            with self.assertRaises(ValueError): value.inspect_runtime({}, {}, keeper_anchor=950)

    def test_only_known_chromium_cache_ancestor_alias_is_admitted_with_original_pin(self):
        value = self.instance(); value.source_unchanged = Mock()
        value.args.binary, value.args.initializer = self.root / "gate", self.root / "initializer.py"
        canonical = Path("/srv/catchplate-fast/home-offload/operator/.cache/ms-playwright/"
            "chromium_headless_shell-1208/chrome-headless-shell-linux64/chrome-headless-shell")
        self.assertEqual(runner.CHROME_CANONICAL, canonical)
        pins = {value.args.binary: PIN, value.args.initializer: recipe.base.INITIALIZER_SHA256,
            runner.NODE: runner.NODE_SHA256, runner.CHROME: "27e55cc30e487493b89b663085d6deeb0707be201a568657c922fac9076c317c"}
        resolutions = {path: path for path in pins}
        with patch.object(Path, "is_file", return_value=True), patch.object(Path, "is_symlink", autospec=True, return_value=False) as symlink, \
                patch.object(Path, "stat", return_value=SimpleNamespace(st_mode=0o100644)), \
                patch.object(Path, "resolve", autospec=True, side_effect=resolutions.__getitem__), \
                patch.object(recipe.base, "digest", side_effect=pins.__getitem__):
            self.assertEqual(value.inputs("direct"), {str(path): pin for path, pin in pins.items()})
            resolutions[runner.CHROME] = canonical
            self.assertEqual(value.inputs("known-alias"), {str(path): pin for path, pin in pins.items()})
            for path in pins:
                original = resolutions[path]
                resolutions[path] = self.root / "alternate-target"
                with self.subTest(path=path), self.assertRaises(ValueError): value.inputs("alternate")
                resolutions[path] = original
            pins[runner.CHROME] = "f" * 64
            with self.assertRaises(ValueError): value.inputs("wrong-hash")
            pins[runner.CHROME] = runner.CHROME_SHA256
            symlink.side_effect = lambda path: path == runner.CHROME
            with self.assertRaises(ValueError):
                value.inputs("leaf-symlink")

    def test_browser_preflight_creates_private_pinned_temporary_directory_without_starting(self):
        value = self.instance(); value.project = "serverware-guided-private-" + "a" * 12
        value.browser_units = Mock(return_value=False)
        value.command = Mock(return_value=b"default.target static -\n")
        with patch.object(runner.recipe.base, "digest", return_value="b" * 64):
            value.browser_preflight()
        self.assertEqual(value.browser_tmp.parent, self.root)
        self.assertEqual(value.browser_tmp.stat().st_mode & 0o777, 0o700)
        self.assertEqual(value.browser_tmp_identity, (value.browser_tmp.stat().st_dev, value.browser_tmp.stat().st_ino))
        self.assertFalse(value.browser_unit_armed)
        self.assertEqual(value.command.call_count, 1)
        receipt = value.save.call_args.args[1]
        self.assertEqual((receipt["runtimeMaxSeconds"], receipt["killMode"], receipt["temporaryDownloadArtifacts"]),
            (185, "control-group", True))

    def test_cleanup_removes_only_pinned_temp_after_browser_and_checker_before_remaining_ids(self):
        value = self.instance(); events = []
        value.browser_tmp = Path(tempfile.mkdtemp(prefix="browser-", dir=self.root))
        info = value.browser_tmp.stat(); value.browser_tmp_identity = (info.st_dev, info.st_ino)
        (value.browser_tmp / "private-download").write_bytes(b"synthetic-private-config")
        value.browser_cleanup = lambda: events.append("browser") or True
        rows = [{"Id": char * 64, "Config": {"Labels": {"com.docker.compose.service": name}}}
            for name, char in (("network", "a"), ("check", "b"))]
        value.container_rows = Mock(side_effect=[rows, []]); value.no_project_networks = Mock(return_value=True)
        value.command = lambda name, argv, seconds: events.append((name, argv)) or b""
        self.assertEqual(value.cleanup(), (True, []))
        self.assertEqual(events[0], "browser")
        self.assertEqual(events[1], ("cleanup-check-remove", ["docker", "rm", "--force", "b" * 64]))
        self.assertFalse(value.browser_tmp.exists()); self.assertEqual(value.deadline, 1060)
        self.assertIn(("cleanup-remove", ["docker", "rm", "--force", "a" * 64]), events)

    def test_cleanup_retains_unowned_temporary_directory_and_never_reports_success(self):
        value = self.instance(); value.browser_cleanup = Mock(return_value=True)
        value.browser_tmp = Path(tempfile.mkdtemp(prefix="browser-", dir=self.root))
        info = value.browser_tmp.stat(); value.browser_tmp_identity = (info.st_dev, info.st_ino + 1)
        value.container_rows = Mock(side_effect=[[], []]); value.no_project_networks = Mock(return_value=True)
        self.assertEqual(value.cleanup(), (False, ["browser-cleanup"]))
        self.assertTrue(value.browser_tmp.is_dir())

    def test_failed_first_checker_removal_never_captures_private_frames_as_logs(self):
        value = self.instance(); value.browser_cleanup = Mock(return_value=True)
        rows = [{"Id": char * 64, "Config": {"Labels": {"com.docker.compose.service": name}}}
            for name, char in (("network", "a"), ("check", "b"))]
        value.container_rows = Mock(side_effect=[rows, []]); value.no_project_networks = Mock(return_value=True)
        calls = []
        def command(name, argv, seconds):
            calls.append((name, argv))
            if name == "cleanup-check-remove":
                raise ValueError("synthetic removal uncertainty")
            return b""
        value.command = command
        self.assertEqual(value.cleanup(), (False, ["checker-remove"]))
        self.assertEqual(calls[0], ("cleanup-check-remove", ["docker", "rm", "--force", "b" * 64]))
        self.assertIn(("retained-network-logs", ["docker", "logs", "--tail", "120", "a" * 64]), calls)
        self.assertFalse(any(argv[:2] == ["docker", "logs"] and "b" * 64 in argv for _, argv in calls))
        self.assertIn(("cleanup-stop", ["docker", "stop", "--time", "5", "a" * 64, "b" * 64]), calls)
        self.assertIn(("cleanup-remove", ["docker", "rm", "--force", "a" * 64, "b" * 64]), calls)
        self.assertEqual(value.deadline, 1060)


if __name__ == "__main__":
    unittest.main()
