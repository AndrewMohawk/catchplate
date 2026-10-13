"""Inert runner controls. Doubles are not SDK, container or provider acceptance.

An audit hook refuses process and socket creation even during runner imports.
Small temporary files cover custody of input paths and retained test receipts.
"""
from __future__ import annotations

import ast
from contextlib import redirect_stdout, redirect_stderr
from copy import deepcopy
import datetime
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch


def forbid_runtime(event, args):
    if event.startswith(("socket.", "subprocess.", "os.exec", "os.spawn", "os.posix_spawn")) \
            or event in {"os.system", "os.fork", "os.forkpty", "os.kill", "os.killpg"}:
        raise AssertionError("inert runner test attempted runtime I/O")


sys.addaudithook(forbid_runtime)
from scripts import run_operator_x_post_fixture as runner

NOW = datetime.datetime(2026, 10, 12, 12, tzinfo=datetime.timezone.utc)
IMAGE = "sha256:" + "d" * 64
NAMES = ("network", "provider", "serverware", "decision-gate-rs", "edge", "check")
IDS = {name: format(index, "064x") for index, name in enumerate(NAMES, 1)}
PINS = dict(expected_binary_sha256="a" * 64, expected_go_sha256="b" * 64,
    expected_dependencies_sha256="c" * 64)


def stamp(age):
    return (NOW - datetime.timedelta(seconds=age)).isoformat().replace("+00:00", "Z")


class FixedDateTime(datetime.datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW if tz is not None else NOW.replace(tzinfo=None)


def configuration():
    paths = [Path("/synthetic/" + name) for name in
        ("source", "gate", "initialize.py", "unused", "node", "modules", "python", "packages", "go")]
    paths[3] = Path("/srv/catchplate-fast/tmp/serverware-x-post-private.abcdef12")
    return runner.recipe.build(*paths, **PINS)


def inspect_rows(config):
    rows, images = [], {}
    for name in NAMES:
        service = config["services"][name]
        images[service["image"]] = service["image"].removeprefix("python@")
        rows.append({"Id": IDS[name], "Image": images[service["image"]], "RestartCount": 0,
            "State": {"Status": "created" if name == "check" else "running", "OOMKilled": False,
                "StartedAt": stamp(5 if name == "edge" else 20), "Health": {"Status": "healthy"}},
            "Config": {"Labels": {"com.docker.compose.project": config["name"], "com.docker.compose.service": name},
                "User": service["user"], "Entrypoint": service["entrypoint"], "Cmd": service["command"],
                "WorkingDir": service["working_dir"], "Env": ["PATH=/usr/bin:/bin"] +
                    [key + "=" + value for key, value in service.get("environment", {}).items()]},
            "HostConfig": {"Privileged": False, "ReadonlyRootfs": True, "PortBindings": {},
                "NetworkMode": "none" if name == "network" else "container:" + IDS["network"],
                "CapDrop": ["ALL"], "CapAdd": service.get("cap_add", []), "SecurityOpt": ["no-new-privileges:true"],
                "Memory": runner.memory_bytes(service["mem_limit"]), "MemorySwap": runner.memory_bytes(service["mem_limit"]),
                "NanoCpus": int(service["cpus"] * 10**9), "PidsLimit": service["pids_limit"], "Init": service["init"],
                "RestartPolicy": {"Name": "no"}, "Sysctls": service.get("sysctls", {}),
                "LogConfig": {"Type": service["logging"]["driver"], "Config": service["logging"]["options"]},
                "Tmpfs": dict(value.split(":", 1) for value in service["tmpfs"])},
            "Mounts": [{"Type": "bind", "Source": mount["source"], "Destination": mount["target"],
                "RW": not mount["read_only"]} for mount in service["volumes"]]})
    return rows, images


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(runner.time, "monotonic", return_value=1000.0))
        self.enterContext(patch.object(runner.time, "sleep", side_effect=AssertionError("unexpected real wait")))
        self.enterContext(patch.object(runner.datetime, "datetime", FixedDateTime))
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="x-post-runner-unit-"))).resolve()

    def instance(self):
        value = runner.XPostRun(SimpleNamespace(source=self.root, evidence=self.root))
        value.save, value.wait_edge_ready = Mock(), Mock()
        return value

    def test_fault_gate_probe_runs_without_local_imports_and_keeps_all_isolation_guards(self):
        import pathlib
        import socket
        probe = runner.FAULT_GATE_NETWORK_PROBE
        imports = [ast.unparse(node) for node in ast.parse(probe).body
            if isinstance(node, (ast.Import, ast.ImportFrom))]
        self.assertEqual(imports, ["import socket", "from pathlib import Path"])
        self.assertNotIn("scripts", probe)
        self.assertNotIn("sys.path", probe)
        files = {"/proc/net/route": b"Iface Destination Gateway Flags RefCnt Use Metric Mask\n"
            b"lo 22D8B85D 00000000 0001 0 0 0 FFFFFFFF\n",
            "/proc/net/ipv6_route": b"00000000000000000000000000000001 80 00 lo\n",
            "/proc/sys/net/ipv4/ip_nonlocal_bind": b"0\n",
            "/etc/hosts": runner.network.FAULT_GATE_HOSTS, "/etc/resolv.conf": runner.network.RESOLV}
        dns = {name: row[0] for row in (line.split() for line in files["/etc/hosts"].decode().splitlines())
            for name in row[1:]}
        def run(*, changed_files=None, interfaces=None, changed_dns=None, bind_failure=False):
            selected = dict(files, **(changed_files or {}))
            addresses = dict(dns, **(changed_dns or {}))
            channel = MagicMock()
            if bind_failure:
                channel.__enter__.return_value.bind.side_effect = OSError("synthetic missing loopback address")
            def path(value):
                raw = selected[value]
                return SimpleNamespace(read_bytes=lambda: raw, read_text=lambda **kwargs: raw.decode("ascii"))
            with patch.object(pathlib, "Path", side_effect=path), \
                    patch.object(socket, "if_nameindex", return_value=interfaces or [(1, "lo")]), \
                    patch.object(socket, "socket", return_value=channel), \
                    patch.object(socket, "getaddrinfo", side_effect=lambda host, *args:
                        [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))
                            for address in ([addresses[host]] if isinstance(addresses[host], str) else addresses[host])]) as resolve:
                exec(compile(probe, "<fixed-gate-network-proof>", "exec"), {})
                self.assertEqual([call.args for call in channel.__enter__.return_value.bind.call_args_list],
                    [((runner.network.FIXTURE_IP, 0),), (("127.0.0.2", 0),)])
                self.assertEqual({call.args[0] for call in resolve.call_args_list},
                    {"x.com", "api.x.com", runner.network.CONTROL_HOST, runner.network.PROXY_HOST,
                        "decision-gate-rs", "serverware"})
        run()
        controls = [dict(interfaces=[(1, "lo"), (2, "eth0")]),
            dict(changed_files={"/proc/net/route": files["/proc/net/route"] + b"lo 00000000 0 0 0 0 0 0\n"}),
            dict(changed_files={"/proc/net/route": files["/proc/net/route"] + b"eth0 22D8B85D 0 0 0 0 0 0\n"}),
            dict(changed_files={"/proc/net/route": b"header\nlo short\n"}),
            dict(changed_files={"/proc/net/ipv6_route": b"00 00 eth0\n"}),
            dict(changed_files={"/proc/sys/net/ipv4/ip_nonlocal_bind": b"1\n"}),
            dict(changed_files={"/etc/hosts": runner.network.HOSTS}),
            dict(changed_files={"/etc/resolv.conf": b"nameserver 8.8.8.8\n"}),
            dict(changed_dns={"serverware": "127.0.0.1"}),
            dict(changed_dns={"api.x.com": [runner.network.FIXTURE_IP, "127.0.0.1"]}),
            dict(bind_failure=True)]
        for index, control in enumerate(controls):
            with self.subTest(index=index), self.assertRaises((ValueError, OSError)):
                run(**control)

    def test_fault_gate_probe_keeps_exact_gate_id_command_deadline_and_provider_proof(self):
        tree = ast.parse(Path(runner.__file__).read_text())
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute) and node.func.attr == "command"
            and node.args and isinstance(node.args[0], ast.Constant)]
        gate = next(node for node in calls if node.args[0].value == "fault-gate-network-proof")
        command = Mock()
        exec(compile(ast.fix_missing_locations(ast.Module(body=[ast.Expr(gate)], type_ignores=[])),
            runner.__file__, "exec"), {"self": SimpleNamespace(command=command), "identities": IDS,
                "FAULT_GATE_NETWORK_PROBE": runner.FAULT_GATE_NETWORK_PROBE})
        command.assert_called_once_with("fault-gate-network-proof", ["docker", "exec",
            IDS["decision-gate-rs"], "python", "-B", "-c", runner.FAULT_GATE_NETWORK_PROBE], 5)
        provider = next(node for node in calls if node.args[0].value == "network-proof")
        self.assertIn("assert_isolated_network()", ast.unparse(provider))
        self.assertIn("identities['provider']", ast.unparse(provider))
        self.assertFalse(any(mount["target"] == "/app" or mount["target"].startswith("/app/")
            for mount in configuration()["services"]["decision-gate-rs"]["volumes"]))

    def test_original_fixed_budgets_and_dispatch_time_edge_identity(self):
        self.assertEqual((runner.WORK_SECONDS, runner.CLEANUP_SECONDS, runner.recipe.KEEPER_SECONDS,
            runner.recipe.PRECHECK_SECONDS, runner.recipe.EDGE_SECONDS, runner.recipe.CHECKER_OUTER_SECONDS),
            (390, 60, 300, 75, 240, 210))
        value = self.instance(); value.edge_started_at = stamp(5)
        state = {"Status": "running", "OOMKilled": False, "StartedAt": value.edge_started_at}
        value.command = Mock(return_value=json.dumps(state).encode())
        self.assertEqual(value.admit_checker_window(IDS["edge"], keeper_anchor=950, work_anchor=900), 1235)
        self.assertEqual(value.admit_checker_window(IDS["edge"], keeper_anchor=980, work_anchor=850), 1240)
        value.command.assert_called_with("edge-launch-state",
            ["docker", "inspect", "--format", "{{json .State}}", IDS["edge"]], 3)
        for changed, keeper, work in ((dict(state, StartedAt=stamp(4)), 950, 900),
                (dict(state, Status="exited"), 950, 900), (dict(state, OOMKilled=True), 950, 900),
                (state, 925, 900), (state, 950, 820)):
            value.command.return_value = json.dumps(changed).encode()
            with self.subTest(changed=changed, keeper=keeper, work=work), self.assertRaises(ValueError):
                value.admit_checker_window(IDS["edge"], keeper_anchor=keeper, work_anchor=work)
        for age in (-1, 30, 240):
            value.edge_started_at = stamp(age)
            value.command.return_value = json.dumps(dict(state, StartedAt=stamp(age))).encode()
            with self.subTest(age=age), self.assertRaises(ValueError):
                value.admit_checker_window(IDS["edge"], keeper_anchor=950, work_anchor=900)

    def test_actual_inspection_requires_six_exact_services_pins_mounts_and_environment(self):
        config = configuration(); rows, images = inspect_rows(config)
        value = self.instance(); value.container_rows = Mock(return_value=rows)
        value.image_environments = {image: {"PATH": "/usr/bin:/bin"} for image in images}
        self.assertEqual(value.inspect_runtime(config, images, keeper_anchor=950), IDS)
        self.assertEqual(value.edge_started_at, stamp(5))
        value.wait_edge_ready.assert_called_once_with(IDS["edge"])
        mutations = [lambda r: r.pop(), lambda r: r.append(deepcopy(r[0])),
            lambda r: r[1].update(Image="sha256:" + "f" * 64), lambda r: r[0].update(RestartCount=1),
            lambda r: r[0]["State"].update(OOMKilled=True), lambda r: r[2]["State"]["Health"].update(Status="starting"),
            lambda r: r[-1]["State"].update(Status="running"), lambda r: r[1]["HostConfig"].update(NetworkMode="host"),
            lambda r: r[1]["HostConfig"].update(PortBindings={"443/tcp": [{"HostPort": "443"}]}),
            lambda r: r[1]["HostConfig"].update(Privileged=True), lambda r: r[1]["HostConfig"].update(ReadonlyRootfs=False),
            lambda r: r[1]["HostConfig"].update(PidsLimit=999), lambda r: r[1]["HostConfig"].update(MemorySwap=-1),
            lambda r: r[1]["HostConfig"].update(Devices=[{"PathOnHost": "/dev/null"}]),
            lambda r: r[1]["Config"]["Env"].append("NODE_OPTIONS=unreviewed"),
            lambda r: r[1]["Config"]["Env"].append("PATH=/different"),
            lambda r: r[1]["Mounts"][0].update(RW=not r[1]["Mounts"][0]["RW"]),
            lambda r: r[1]["Mounts"].append({"Type": "volume", "Name": "unowned"}),
            lambda r: r[4]["State"].update(StartedAt=stamp(30)),
            lambda r: r[0]["State"].update(StartedAt=stamp(75))]
        for index, mutate in enumerate(mutations):
            changed = deepcopy(rows); mutate(changed); value.container_rows.return_value = changed
            with self.subTest(index=index), self.assertRaises((ValueError, KeyError)):
                value.inspect_runtime(config, images, keeper_anchor=950)

    def test_app_publication_is_observed_before_gate_creation_and_failure_is_terminal(self):
        value = self.instance(); calls = []
        value.command = lambda name, argv, seconds: calls.append((name, argv, seconds))
        value.container_rows = Mock(return_value=[{"Id": IDS[name], "Config": {"Labels": {
            "com.docker.compose.service": name}}} for name in NAMES[:3]])
        value.public_view = Mock(side_effect=lambda *a, **kw: calls.append(("publication", a, kw)) or {"pinned": True})
        value.start_app_then_gate(["docker", "compose", "-p", "synthetic"])
        self.assertEqual([row[0] for row in calls], ["app-start", "publication", "gate-start"])
        self.assertEqual(calls[0][1][-2:], ["provider", "serverware"])
        self.assertIn("--no-deps", calls[-1][1]); self.assertEqual(calls[-1][1][-1], "decision-gate-rs")
        self.assertEqual(value.initial_view, {"pinned": True})
        calls.clear(); value.public_view.side_effect = ValueError("publication refused")
        with self.assertRaises(ValueError): value.start_app_then_gate(["docker", "compose"])
        self.assertEqual([row[0] for row in calls], ["app-start"])
        value.container_rows.return_value.append({"Id": IDS["decision-gate-rs"], "Config": {"Labels": {
            "com.docker.compose.service": "decision-gate-rs"}}})
        calls.clear()
        with self.assertRaises(ValueError): value.start_app_then_gate(["docker", "compose"])
        self.assertEqual([row[0] for row in calls], ["app-start"])

    def test_command_owned_group_cleanup_on_success_nonzero_timeout_and_observation_error(self):
        for index, outcome in enumerate((0, 2, RuntimeError("observation"), "timeout")):
            value = self.instance(); events = []
            process = SimpleNamespace(pid=1234, returncode=None)
            def launch(argv, **kwargs):
                self.assertEqual(argv, ["synthetic-command"])
                self.assertTrue(kwargs["start_new_session"])
                self.assertIs(kwargs["preexec_fn"], runner.limit_command_logs)
                self.assertEqual(kwargs["stdin"], runner.subprocess.DEVNULL)
                kwargs["stdout"].write(b"synthetic output\n")
                return process
            def observe(candidate):
                self.assertIs(candidate, process); events.append("observe")
                if isinstance(outcome, Exception): raise outcome
                return None if outcome == "timeout" else outcome
            def cleanup(candidate):
                self.assertIs(candidate, process); self.assertIsNone(candidate.returncode); events.append("cleanup")
            with self.subTest(outcome=outcome), patch.object(runner.subprocess, "Popen", side_effect=launch), \
                    patch.object(runner, "child_exit_status", side_effect=observe), \
                    patch.object(runner, "stop_group", side_effect=cleanup), redirect_stdout(io.StringIO()):
                clock = [1000, 1002] if outcome == "timeout" else [1000, 1000]
                with patch.object(runner.time, "monotonic", side_effect=clock):
                    if outcome == 0:
                        self.assertEqual(value.command("command-" + str(index), ["synthetic-command"], 1), b"synthetic output\n")
                    else:
                        with self.assertRaises((ValueError, RuntimeError)):
                            value.command("command-" + str(index), ["synthetic-command"], 1)
            self.assertEqual(events, ["observe", "cleanup"])

    def test_command_reserves_cleanup_budget_and_rejects_unbounded_inputs_before_spawn(self):
        value = self.instance(); value.deadline = 1006
        with patch.object(runner.subprocess, "Popen") as launch, self.assertRaises(ValueError):
            value.command("budget", ["synthetic"])
        launch.assert_not_called()
        value.deadline = None
        for name, seconds in (("../outside", 1), ("bad name", 1), ("a" * 81, 1), ("bounds", 0), ("bounds", 211)):
            with self.subTest(name=name, seconds=seconds), patch.object(runner.subprocess, "Popen") as launch, self.assertRaises(ValueError):
                value.command(name, ["synthetic"], seconds)
            launch.assert_not_called()
        value.deadline = 1008
        with patch.object(runner.subprocess, "Popen", return_value=SimpleNamespace(pid=1234, returncode=None)), \
                patch.object(runner, "child_exit_status", return_value=0), patch.object(runner, "stop_group") as cleanup, \
                patch.object(runner.time, "monotonic", side_effect=[1000, 1000, 1002]), redirect_stdout(io.StringIO()), self.assertRaises(ValueError):
            value.command("capped", ["synthetic"], 30)
        cleanup.assert_called_once()

    def test_discovery_binds_exact_container_ids_and_project_service_labels(self):
        value = self.instance(); value.project = "synthetic"; value.services = {name: {} for name in NAMES}
        row = {"Id": IDS["check"], "Config": {"Labels": {
            "com.docker.compose.project": "synthetic", "com.docker.compose.service": "check"}}}
        value.command = Mock(side_effect=[IDS["check"].encode(), json.dumps([row]).encode()])
        self.assertEqual(value.container_rows("unit"), [row])
        self.assertEqual(value.command.call_args_list[-1].args[1], ["docker", "inspect", IDS["check"]])
        for ids, changed in (("short", row), (IDS["check"] + " " + IDS["check"], row),
                (IDS["check"], dict(row, Id=IDS["edge"]))):
            value.command = Mock(side_effect=[ids.encode(), json.dumps([changed]).encode()])
            with self.subTest(ids=ids), self.assertRaises(ValueError): value.container_rows("unit")
        for key, changed in (("com.docker.compose.project", "foreign"), ("com.docker.compose.service", "unknown")):
            invalid = deepcopy(row); invalid["Config"]["Labels"][key] = changed
            value.command = Mock(side_effect=[IDS["check"].encode(), json.dumps([invalid]).encode()])
            with self.assertRaises(ValueError): value.container_rows("unit")

    def test_cleanup_removes_exact_checker_first_then_owned_ids_and_verifies_absence(self):
        rows = [{"Id": IDS[name], "Config": {"Labels": {"com.docker.compose.service": name}}} for name in NAMES]
        for fail in (False, True):
            value = self.instance(); value.container_rows = Mock(side_effect=[rows, []])
            value.no_project_networks = Mock(return_value=True); calls = []
            def command(name, argv, seconds):
                calls.append((name, argv, seconds))
                if fail and name == "cleanup-check-remove": raise ValueError("synthetic removal failure")
            value.command = command
            clean, errors = value.cleanup()
            self.assertEqual(clean, not fail); self.assertEqual(errors, ["checker-remove"] if fail else [])
            self.assertEqual(calls[1], ("cleanup-check-remove", ["docker", "rm", "--force", IDS["check"]], 10))
            selected = list(IDS.values()) if fail else [IDS[name] for name in NAMES if name != "check"]
            self.assertIn(("cleanup-stop", ["docker", "stop", "--time", "5", *selected], 15), calls)
            self.assertIn(("cleanup-remove", ["docker", "rm", "--force", *selected], 10), calls)
            self.assertEqual(value.deadline, 1060)
            value.no_project_networks.assert_called_once_with("cleanup-networks")
        value = self.instance(); value.container_rows = Mock(side_effect=ValueError("unknown identities")); value.command = Mock()
        self.assertEqual(value.cleanup(), (False, ["inspect"])); value.command.assert_not_called()
        value.container_rows = Mock(return_value=[rows[-1], deepcopy(rows[-1])])
        self.assertEqual(value.cleanup(), (False, ["checker-identity"])); value.command.assert_not_called()

    def test_input_pins_and_external_dependency_mountpoint_fail_closed(self):
        value = self.instance(); value.source_unchanged = Mock()
        args = value.args
        args.expected_binary_sha256, args.expected_go_sha256 = "a" * 64, "b" * 64
        for name in ("binary", "go", "node", "initializer"):
            path = self.root / name; path.write_bytes(b"synthetic"); path.chmod(0o644); setattr(args, name, path)
        atomic = self.root / "atomic"; atomic.write_bytes(b"synthetic"); atomic.chmod(0o644)
        adjacent = self.root / runner.recipe.NODE_MODULES; adjacent.mkdir(parents=True)
        args.node_modules = self.root / "external"; args.node_modules.mkdir()
        args.python_runtime, args.python_packages = self.root / "python", self.root / "packages"
        manifest = {"synthetic": "complete inventory double"}
        args.expected_dependencies_sha256 = runner.recipe.dependencies_sha256(manifest)
        pins = {args.binary: args.expected_binary_sha256, args.go: args.expected_go_sha256,
            args.node: runner.recipe.NODE_SHA256, args.initializer: runner.recipe.base.INITIALIZER_SHA256,
            atomic: runner.recipe.LIBATOMIC_SHA256}
        with patch.object(runner.recipe, "LIBATOMIC", atomic), patch.object(runner.recipe.base, "digest", side_effect=pins.__getitem__), \
                patch.object(runner.recipe, "dependencies", return_value=manifest) as inventory:
            self.assertEqual(value.inputs("before"), manifest)
            value.source_unchanged.assert_called_once_with("before"); inventory.assert_called_once()
            (adjacent / "unexpected").write_bytes(b"not empty")
            with self.assertRaises(ValueError): value.inputs("occupied")
            args.node_modules = adjacent
            args.expected_dependencies_sha256 = "f" * 64
            with self.assertRaises(ValueError): value.inputs("drift")
            args.expected_dependencies_sha256 = runner.recipe.dependencies_sha256(manifest)
            args.go.chmod(0o600)
            with self.assertRaises(ValueError): value.inputs("unreadable")

    def test_bytecode_pre_post_validator_and_actual_image_join_are_required(self):
        from scripts import prepare_operator_python_bytecode as bytecode
        value = self.instance()
        self.assertIsNone(value.bytecode_input("before"))
        value.save.assert_not_called()
        self.assertIsNone(value.admit_bytecode_image("unused without artifact"))
        value.args.python_bytecode = self.root / "bytecode"
        value.args.expected_python_bytecode_manifest_sha256 = "d" * 64
        value.args.commit = "e" * 40
        # Explicit validator double: package/header/source integrity is tested
        # by the bytecode owner's suite, not fabricated by this wiring control.
        receipt = {"schema": "synthetic validator receipt", "manifestSha256": "d" * 64,
            "image": bytecode.APP_IMAGE, "payload": "unchanged synthetic identity"}
        with patch.object(bytecode, "validate", return_value=receipt) as validate:
            self.assertEqual(value.bytecode_input("before"), receipt)
            validate.assert_called_once_with(value.args.python_bytecode, source=self.root,
                commit="e" * 40, expected_manifest_sha256="d" * 64)
            value.save.assert_called_with("python-bytecode-before.json", receipt)
            self.assertIsNone(value.admit_bytecode_image(bytecode.APP_IMAGE))
            with self.assertRaises(ValueError): value.admit_bytecode_image("sha256:" + "f" * 64)
            self.assertEqual(value.bytecode_input("after"), receipt)
            self.assertEqual(validate.call_count, 2)
            value.save.assert_called_with("python-bytecode-after.json", receipt)
            for changed in (dict(receipt, payload="changed"), dict(receipt, image="sha256:" + "f" * 64)):
                validate.return_value = changed
                with self.assertRaises(ValueError): value.bytecode_input("after")
            validate.side_effect = ValueError("synthetic invalid manifest or source")
            with self.assertRaises(ValueError): value.bytecode_input("after")
        value.args.expected_python_bytecode_manifest_sha256 = None
        with self.assertRaises(ValueError): value.bytecode_input("before")

    def test_bytecode_image_check_precedes_creation_and_postcheck_uses_real_input_path(self):
        tree = ast.parse(Path(runner.__file__).read_text())
        execute = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "execute")
        body = next(node for node in execute.body if isinstance(node, ast.Try)).body
        source = [ast.unparse(node) for node in body]
        image = next(index for index, row in enumerate(source) if row.startswith("self.admit_bytecode_image("))
        armed = source.index("armed = True")
        self.assertLess(image, armed)
        self.assertTrue(any("self.inputs('before')" in row for row in source[:image]))
        self.assertTrue(any("self.inputs('after')" in row for row in source[image:]))
        inputs = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "inputs")
        self.assertIn("self.bytecode_input(suffix)", ast.unparse(inputs))
        # Actual runtime mount inspector covers both mounts, not just recipe
        # labels. Synthetic inspect rows here remain explicitly non-runtime.
        from scripts import prepare_operator_python_bytecode as bytecode
        config = configuration()
        config["services"]["serverware"]["volumes"] += bytecode.mounts(Path('/synthetic/cache'))
        rows, images = inspect_rows(config)
        value = self.instance(); value.container_rows = Mock(return_value=rows)
        value.image_environments = {image: {"PATH": "/usr/bin:/bin"} for image in images}
        self.assertEqual(value.inspect_runtime(config, images, keeper_anchor=950), IDS)
        for target in ("/app/serverware/__pycache__", "/app/serverware/authority_store/__pycache__"):
            changed = deepcopy(rows)
            app = next(row for row in changed if row["Id"] == IDS["serverware"])
            next(mount for mount in app["Mounts"] if mount["Destination"] == target)["RW"] = True
            value.container_rows.return_value = changed
            with self.subTest(target=target), self.assertRaises(ValueError):
                value.inspect_runtime(config, images, keeper_anchor=950)

    def test_cli_has_no_provider_override_and_clears_ambient_docker_endpoint(self):
        argv = ["runner"]
        for name in ("source", "job-root", "evidence", "binary", "go", "node", "node-modules", "initializer", "python-runtime", "python-packages"):
            argv.extend(["--" + name, "/synthetic/" + name])
        argv += ["--commit", "e" * 40]
        for name, value in PINS.items(): argv.extend(["--" + name.replace("_", "-"), value])
        instance = SimpleNamespace(execute=Mock(return_value=0))
        with patch.object(runner.sys, "argv", argv), patch.object(runner, "XPostRun", return_value=instance) as construct, \
                patch.object(runner.os, "umask") as umask, patch.dict(os.environ, {"DOCKER_HOST": "tcp://forbidden",
                    "DOCKER_CONTEXT": "foreign", "DOCKER_API_VERSION": "999", "DOCKER_TLS_VERIFY": "1", "DOCKER_CERT_PATH": "/secret"}):
            self.assertEqual(runner.main(), 0)
            self.assertEqual(os.environ["DOCKER_HOST"], "unix:///var/run/docker.sock")
            self.assertFalse(any(key in os.environ for key in ("DOCKER_CONTEXT", "DOCKER_API_VERSION", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH")))
            self.assertEqual(construct.call_args.args[0].expected_dependencies_sha256, "c" * 64)
            umask.assert_called_once_with(0o077)
        for option in ("--provider-url", "--timeout-seconds", "--keep-containers", "--recipe-module"):
            with patch.object(runner.sys, "argv", argv + [option, "untrusted"]), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                runner.main()
        for extra in (["--python-bytecode", "/synthetic/cache"],
                ["--expected-python-bytecode-manifest-sha256", "d" * 64]):
            with patch.object(runner.sys, "argv", argv + extra), redirect_stderr(io.StringIO()), \
                    patch.object(runner, "XPostRun") as construct, self.assertRaises(SystemExit):
                runner.main()
            construct.assert_not_called()
        with patch.object(runner.sys, "argv", argv + ["--python-bytecode", "/synthetic/cache",
                "--expected-python-bytecode-manifest-sha256", "d" * 64]), \
                patch.object(runner, "XPostRun", return_value=instance) as construct, \
                patch.object(runner.os, "umask"), patch.dict(os.environ, {}):
            self.assertEqual(runner.main(), 0)
            self.assertEqual(construct.call_args.args[0].python_bytecode, Path("/synthetic/cache"))
            self.assertEqual(construct.call_args.args[0].expected_python_bytecode_manifest_sha256, "d" * 64)

    def test_actual_result_pin_guard_and_terminal_boundary_without_fake_end_to_end_acceptance(self):
        # Exercise the actual isolated guard, not a duplicate comparison. The
        # full checker schema remains delegated to its existing pure validator.
        tree = ast.parse(Path(runner.__file__).read_text())
        execute = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "execute")
        body = next(node for node in execute.body if isinstance(node, ast.Try)).body
        index = next(i for i, node in enumerate(body) if isinstance(node, ast.ImportFrom)
            and node.module == "scripts.check_operator_x_post")
        self.assertEqual([(item.name, item.asname) for item in body[index].names], [("validate_success_result", None)])
        self.assertEqual(ast.unparse(body[index + 1]), "if quota:\n    from scripts.check_operator_x_quota import validate_success_result")
        self.assertEqual(ast.unparse(body[index + 2]), "if fault_mode is not None:\n    from scripts.check_operator_x_quota_fault import validate_success_result")
        self.assertEqual(ast.unparse(body[index + 3]), "result = json.loads(raw)")
        self.assertEqual(ast.unparse(body[index + 4]), "validate_success_result(result)")
        guard = ast.fix_missing_locations(ast.Module(body=[body[index + 5]], type_ignores=[]))
        compiled = compile(guard, str(Path(runner.__file__)), "exec")
        valid = {"dataPlaneBinaryDigest": "sha256:" + "a" * 64,
            "goExampleSha256": "b" * 64, "dependenciesSha256": "c" * 64}
        namespace = {"args": SimpleNamespace(**PINS), "require": runner.require, "result": valid}
        exec(compiled, namespace)
        for field in valid:
            for changed in (dict(valid, **{field: "f" * 64}), {k: v for k, v in valid.items() if k != field}):
                with self.subTest(field=field), self.assertRaises((ValueError, KeyError)):
                    exec(compiled, dict(namespace, result=changed))
        old_name = dict(valid); old_name["sdkDependenciesSha256"] = old_name.pop("dependenciesSha256")
        with self.assertRaises(KeyError): exec(compiled, dict(namespace, result=old_name))
        pki_index = next(i for i, node in enumerate(body) if isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute)
            and node.value.func.attr == 'command' and node.value.args
            and isinstance(node.value.args[0], ast.Constant) and node.value.args[0].value == 'basic-pki')
        self.assertEqual(ast.unparse(body[pki_index - 1]), "phase = 'proxy-pki'")
        pki = compile(ast.fix_missing_locations(ast.Module(body=body[pki_index - 1:pki_index + 1],
            type_ignores=[])), str(Path(runner.__file__)), 'exec')
        original = ValueError('fixed synthetic PKI refusal')
        command = Mock(side_effect=original)
        state = {'self': SimpleNamespace(command=command), 'compose': ['docker', 'compose']}
        with self.assertRaises(ValueError) as failure: exec(pki, state)
        self.assertIs(failure.exception, original)
        self.assertEqual(state['phase'], 'proxy-pki')
        command.assert_called_once_with('basic-pki', ['docker', 'compose', '--profile', 'basic-pki',
            'run', '--rm', '--no-deps', '--pull', 'never', 'basic-pki'], 25)
        terminal = next(node for node in ast.walk(execute) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute) and node.func.attr == "save"
            and node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value == "terminal.json")
        expression = compile(ast.Expression(body=terminal.args[1]), str(Path(runner.__file__)), "eval")
        receipt = eval(expression, {"phase": "complete", "success": True, "clean": True, "errors": [],
            "time": runner.time, "begun": 990, "failure": None, "quota": False, "fault_mode": None})
        self.assertEqual(receipt, {"schema": "serverware.privateXPostRun/v1", "phase": "complete", "success": True,
            "cleanup": True, "cleanupErrors": [], "elapsedSeconds": 10.0, "syntheticOnly": True,
            "realXVerified": False, "productionReady": False})


if __name__ == "__main__":
    unittest.main()
