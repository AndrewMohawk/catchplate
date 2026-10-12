"""Inert recipe, artifact, runtime-inspection and exact-ID cleanup controls."""
from copy import deepcopy
import datetime
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from scripts import prepare_operator_github_app_examples_fixture as recipe
from scripts import run_operator_github_app_examples_fixture as runner

SOURCE, BINARY, INITIALIZER, NODE, MODULES, PYTHON, PACKAGES, GO = (
    Path("/synthetic/" + name) for name in ("source", "gate", "initialize.py", "node", "node_modules", "venv", "packages", "go"))
MODULES = SOURCE / recipe.NODE_EXAMPLE / "node_modules"
JOB = Path("/srv/catchplate-fast/tmp/serverware-github-app-private.abcdef12")
ARGS = (SOURCE, BINARY, INITIALIZER, JOB, NODE, MODULES, PYTHON, PACKAGES, GO)
PINS = {"expected_binary_sha256": "a" * 64, "expected_go_sha256": "b" * 64}


def inspected(config):
    images = {value: "sha256:" + format(i, "064x") for i, value in enumerate(
        sorted({v["image"] for v in config["services"].values()}), 1)}
    ids = {name: format(i, "064x") for i, name in enumerate(sorted(recipe.RUNTIME_SERVICES), 1)}
    rows = []
    for name in sorted(recipe.RUNTIME_SERVICES):
        service = config["services"][name]
        rows.append({"Id": ids[name], "Image": images[service["image"]], "RestartCount": 0,
            "Config": {"User": service["user"], "Entrypoint": service.get("entrypoint", []), "Cmd": service["command"],
                "WorkingDir": service["working_dir"], "Env": ["PATH=/usr/bin:/bin"] + [k + "=" + v for k, v in service.get("environment", {}).items()],
                "Labels": {"com.docker.compose.project": config["name"], "com.docker.compose.service": name}},
            "State": {"OOMKilled": False, "Status": "created" if name == "check" else "running", "Health": {"Status": "healthy"},
                "StartedAt": datetime.datetime.now(datetime.timezone.utc).isoformat()},
            "HostConfig": {"Privileged": False, "ReadonlyRootfs": True, "PortBindings": {},
                "NetworkMode": "none" if name == "network" else "container:" + ids["network"],
                "CapDrop": ["ALL"], "CapAdd": ["CAP_" + value for value in service.get("cap_add", [])],
                "SecurityOpt": ["no-new-privileges:true"], "Memory": runner.memory_bytes(service["mem_limit"]),
                "MemorySwap": runner.memory_bytes(service["memswap_limit"]), "NanoCpus": int(service["cpus"] * 10**9),
                "PidsLimit": service["pids_limit"], "Init": service["init"], "RestartPolicy": {"Name": "no"},
                "Sysctls": service.get("sysctls", {}), "LogConfig": {"Type": service["logging"]["driver"], "Config": service["logging"]["options"]},
                "Tmpfs": dict(v.split(":", 1) for v in service["tmpfs"]), "Binds": None},
            "Mounts": [{"Type": "bind", "Source": v["source"], "Destination": v["target"], "RW": not v["read_only"]} for v in service["volumes"]]})
    return rows, images


class RecipeTests(unittest.TestCase):
    def setUp(self):
        for name in ("socket.socket", "socket.create_connection", "socket.getaddrinfo", "subprocess.Popen"):
            self.enterContext(patch(name, side_effect=AssertionError("inert test attempted runtime I/O")))
        self.config = recipe.build(*ARGS, **PINS)

    def test_dormant_six_runtime_roster_and_private_network_bounds(self):
        self.assertEqual(set(self.config), {"name", "services"})
        self.assertEqual(set(self.config["services"]), recipe.RUNTIME_SERVICES | {"initialize", "github-pki", "basic-pki"})
        for name, service in self.config["services"].items():
            self.assertEqual(service["network_mode"], "none" if name in {"initialize", "github-pki", "basic-pki", "network"} else "service:network")
            self.assertTrue(service["read_only"])
            self.assertEqual(service["pull_policy"], "never")
            self.assertEqual(service["restart"], "no")
            self.assertEqual(service["cap_drop"], ["ALL"])
            self.assertLessEqual(service["cpus"], 2)
            self.assertLessEqual(service["pids_limit"], 128)
            self.assertEqual(service["mem_limit"], service["memswap_limit"])
            for key in ("ports", "expose", "networks", "dns", "privileged", "devices", "pid", "env_file", "volumes_from"):
                self.assertNotIn(key, service)
            self.assertNotIn("HOME", service.get("environment", {}))
        self.assertEqual((recipe.KEEPER_SECONDS, recipe.EDGE_SECONDS, recipe.CHECKER_SECONDS, recipe.PRECHECK_SECONDS), (300, 240, 180, 75))
        self.assertLess(recipe.PRECHECK_SECONDS + recipe.CHECKER_OUTER_SECONDS + 15, recipe.KEEPER_SECONDS)

    def test_private_generated_app_key_only_checker_and_public_ca_only_app(self):
        private = {"app-key.pem": "/client-secrets/github-app.pem",
            "app-replacement-key.pem": "/client-secrets/github-app-replacement.pem"}
        observed = set()
        for name, service in self.config["services"].items():
            for mount in service["volumes"]:
                self.assertFalse(mount["bind"]["create_host_path"])
                leaf = Path(mount["source"]).name
                if leaf in private:
                    observed.add(leaf)
                    self.assertEqual((name, mount["target"], mount["read_only"]), ("check", private[leaf], True))
                if name in {"serverware", "decision-gate-rs", "github"}:
                    self.assertNotIn(leaf, private)
        self.assertEqual(observed, set(private))
        provider_targets = {m["target"] for m in self.config["services"]["github"]["volumes"]}
        self.assertTrue({"/github/app-public.pem", "/github/app-replacement-public.pem"} <= provider_targets)
        app = self.config["services"]["serverware"]
        self.assertEqual(app["environment"]["SSL_CERT_FILE"], "/github-public/ca.pem")
        self.assertEqual(app["command"], ["python", "-B", "-m", "serverware.operator_demo_runner"])
        self.assertEqual(self.config["services"]["github-pki"]["command"],
            ["python", "-B", "-m", "scripts.operator_github_app_examples_fixture", "--setup"])
        check = self.config["services"]["check"]
        mounts = {m["target"]: m for m in check["volumes"]}
        for target in ("/app/examples/github-issues-node/node_modules", "/example-python", "/example-python/lib/python3.12/site-packages",
                "/example-go/github-issues", "/client-trust/requests-ca.pem", "/client-trust/inner-ca.pem", "/client-trust/outer-ca.pem"):
            self.assertTrue(mounts[target]["read_only"])
        self.assertEqual(check["command"][0], "/app/scripts/check_operator_github_app_examples.py")
        self.assertEqual(check["command"][-2:], ["--replacement-key-file", "/client-secrets/github-app-replacement.pem"])

    def test_exact_recipe_rejects_new_authority_environment_or_runtime_shape(self):
        recipe.validate(self.config, *ARGS, **PINS)
        for kind in ("ports", "network", "key", "ssl", "command", "memory"):
            value = deepcopy(self.config)
            app = value["services"]["serverware"]
            if kind == "ports": app["ports"] = ["3000:3000"]
            elif kind == "network": app["network_mode"] = "host"
            elif kind == "key": app["volumes"].append(recipe.bind(Path("/live/key.pem"), "/live-key"))
            elif kind == "ssl": app["environment"]["SSL_CERT_FILE"] = "/unknown/ca.pem"
            elif kind == "command": app["command"] = ["different"]
            else: app["mem_limit"] = "2g"
            with self.subTest(kind=kind), self.assertRaises(ValueError): recipe.validate(value, *ARGS, **PINS)

    def test_runtime_inspector_requires_all_actual_services_env_mounts_limits_and_ids(self):
        rows, images = inspected(self.config)
        run = runner.AppExamplesRun(SimpleNamespace())
        run.image_environments = {image: {"PATH": "/usr/bin:/bin"} for image in images}
        run.save, run.wait_edge_ready = Mock(), Mock()
        for kind in ("none", "missing", "namespace", "tls", "bind", "cmd", "cpu", "cap", "restart", "age"):
            changed = deepcopy(rows)
            row = next(r for r in changed if r["Config"]["Labels"]["com.docker.compose.service"] == "serverware")
            if kind == "missing": changed.pop()
            elif kind == "namespace": row["HostConfig"]["NetworkMode"] = "host"
            elif kind == "tls": row["Config"]["Env"].append("PYTHONHTTPSVERIFY=0")
            elif kind == "bind": row["Mounts"][0]["RW"] = True
            elif kind == "cmd": row["Config"]["Cmd"] = ["different"]
            elif kind == "cpu": row["HostConfig"]["NanoCpus"] += 1
            elif kind == "cap": row["HostConfig"]["CapAdd"] = ["CAP_SYS_ADMIN"]
            elif kind == "restart": row["RestartCount"] = 1
            elif kind == "age":
                next(r for r in changed if r["Config"]["Labels"]["com.docker.compose.service"] == "network")["State"]["StartedAt"] = "2020-01-01T00:00:00Z"
            run.container_rows = Mock(return_value=changed)
            with patch.object(runner.time, "monotonic", return_value=10), self.subTest(kind=kind):
                if kind == "none": self.assertEqual(run.inspect_runtime(self.config, images, keeper_anchor=0),
                    next(r["Id"] for r in rows if r["Config"]["Labels"]["com.docker.compose.service"] == "check"))
                else:
                    with self.assertRaises(ValueError): run.inspect_runtime(self.config, images, keeper_anchor=0)

    def test_cleanup_removes_exact_checker_before_rest_and_verifies_empty_project(self):
        rows, _ = inspected(self.config)
        run = runner.AppExamplesRun(SimpleNamespace())
        run.container_rows = Mock(side_effect=[rows, []]); run.no_project_networks = Mock(return_value=True)
        run.command = Mock(return_value=b"")
        clean, errors = run.cleanup()
        self.assertTrue(clean); self.assertEqual(errors, [])
        calls = [call.args for call in run.command.call_args_list]
        first = next(c for c in calls if c[0] == "cleanup-check-remove")
        checker_id = next(r["Id"] for r in rows if r["Config"]["Labels"]["com.docker.compose.service"] == "check")
        self.assertEqual(first[1], ["docker", "rm", "--force", checker_id])
        stop = next(c for c in calls if c[0] == "cleanup-stop")
        self.assertLess(calls.index(first), calls.index(stop))
        self.assertEqual(set(stop[1][4:]), {r["Id"] for r in rows} - {checker_id})
        run.container_rows = Mock(side_effect=ValueError("unknown identities")); run.command.reset_mock()
        self.assertEqual(run.cleanup(), (False, ["inspect"]))
        run.command.assert_not_called()

    def test_nonempty_root_rejected_before_any_command_or_claim(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, job, evidence = (root / name for name in ("source", "job", "evidence"))
            for path in (source, job, evidence): path.mkdir(mode=0o700)
            (job / "retained").write_text("owned previous attempt")
            run = runner.AppExamplesRun(SimpleNamespace(source=source, job_root=job, evidence=evidence, commit="a" * 40))
            run.command = Mock(side_effect=AssertionError("no runtime expected"))
            with self.assertRaises(ValueError): run.execute()
            run.command.assert_not_called()
            self.assertEqual(list(evidence.iterdir()), [])
            self.assertEqual((job / "retained").read_text(), "owned previous attempt")

    def test_image_entrypoint_optional_map_key_preserves_strict_prelaunch_admission(self):
        # Docker may omit an unset map key. Assert the actual command uses
        # map indexing; the injected CLI response models its JSON projection.
        # No Docker process or fixture startup is executed by this control.
        for image_config in ({"Env": ["PATH=/usr/bin:/bin"]},
                {"Env": ["PATH=/usr/bin:/bin"], "Entrypoint": None},
                {"Env": ["PATH=/usr/bin:/bin"], "Entrypoint": []},
                {"Env": ["PATH=/usr/bin:/bin"], "Entrypoint": ["/unexpected"]}):
            with self.subTest(image_config=image_config), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source, job, evidence = (root / name for name in ("source", "job", "evidence"))
                for path in (source, job, evidence): path.mkdir(mode=0o700)
                run = runner.AppExamplesRun(SimpleNamespace(source=source, job_root=job, evidence=evidence,
                    commit="a" * 40, binary=BINARY, initializer=INITIALIZER, node=NODE, node_modules=MODULES,
                    python_runtime=PYTHON, python_packages=PACKAGES, go=GO, **PINS))
                run.save, run.inputs, run.cleanup = Mock(), Mock(return_value={}), Mock()
                run.container_rows = Mock(return_value=[])
                # Stop before arming/creating any runtime, after image admission.
                run.no_project_networks = Mock(return_value=False)
                def command(name, arguments, seconds):
                    self.assertTrue(name.startswith("image-"))
                    self.assertEqual(arguments[:4], ["docker", "image", "inspect", "--format"])
                    self.assertEqual(arguments[4], '{"id":{{json .Id}},"environment":{{json .Config.Env}},'
                        '"entrypoint":{{json (index .Config "Entrypoint")}}}')
                    self.assertEqual(seconds, 10)
                    image = arguments[5]
                    return json.dumps({"id": image if image.startswith("sha256:") else "sha256:" + "c" * 64,
                        "environment": image_config["Env"], "entrypoint": image_config.get("Entrypoint")}).encode()
                run.command = Mock(side_effect=command)
                with patch.object(runner, "__file__", str(source / runner.SOURCE_SCRIPT)), \
                        patch.object(recipe, "build", return_value=self.config), patch("builtins.print"):
                    self.assertEqual(run.execute(), 1)
                if image_config.get("Entrypoint") in (None, []):
                    expected_images = {service["image"] for service in self.config["services"].values()}
                    self.assertEqual(run.command.call_count, len(expected_images))
                    self.assertEqual(run.image_environments, {image: {"PATH": "/usr/bin:/bin"} for image in expected_images})
                    run.container_rows.assert_called_once_with("preexisting")
                    run.no_project_networks.assert_called_once_with("preexisting-networks")
                else:
                    self.assertEqual(run.command.call_count, 1)
                    run.container_rows.assert_not_called()
                    run.no_project_networks.assert_not_called()
                run.cleanup.assert_not_called()
                self.assertEqual(list(job.iterdir()), [])
                self.assertEqual(list(evidence.iterdir()), [])

    def test_full_dependency_inventory_pins_bytes_and_symlink_targets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); root.chmod(0o755)
            node, python, runtime = (root / name for name in ("node", "python", "runtime"))
            for directory in (node, python, runtime): directory.mkdir(mode=0o755); directory.chmod(0o755)
            def write(path, value):
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                for parent in path.parents:
                    if parent == root: break
                    parent.chmod(0o755)
                path.write_text(value); path.chmod(0o644)
            for name, version in (("@octokit/rest", "22.0.1"), ("undici", "8.11.2")):
                write(node / name / "package.json", json.dumps({"name": name, "version": version}))
            for name, version in (("PyGithub", "2.10.0"), ("requests", "2.34.2"), ("urllib3", "2.8.0"), ("certifi", "2026.7.22")):
                write(python / (name + ".dist-info/METADATA"), "Name: " + name + "\nVersion: " + version + "\n")
            write(runtime / "pyvenv.cfg", "home = /usr/local/bin\ninclude-system-site-packages = false\nversion = 3.12.12\n")
            (runtime / "bin").mkdir(mode=0o755)
            for name, target in (("python", "/usr/local/bin/python"), ("python3", "python"), ("python3.12", "python")):
                (runtime / "bin" / name).symlink_to(target)
            initial = recipe.dependencies(node, runtime, python)
            pin = recipe.dependencies_sha256(initial)
            write(node / "undici/new.js", "synthetic extra code")
            self.assertNotEqual(recipe.dependencies_sha256(recipe.dependencies(node, runtime, python)), pin)
            (node / "alias").symlink_to("undici/new.js")
            with self.assertRaises(ValueError): recipe.dependencies(node, runtime, python)
            (node / "alias").unlink()
            (runtime / "bin/python").unlink(); (runtime / "bin/python").symlink_to("/other/interpreter")
            with self.assertRaises(ValueError): recipe.dependencies(node, runtime, python)


if __name__ == "__main__":
    unittest.main()
