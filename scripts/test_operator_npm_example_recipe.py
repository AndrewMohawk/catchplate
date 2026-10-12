"""Inert npm-example recipe/runner contracts, not SDK or Docker acceptance.

Actual builders and inspectors consume synthetic paths, files and container
observations. Subprocess and socket boundaries are forbidden throughout tests.
"""
from __future__ import annotations

from copy import deepcopy
import datetime
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import prepare_operator_npm_example_fixture as recipe
from scripts import run_operator_npm_example_fixture as runner
from scripts import run_operator_gmail_sdk_fixture as inherited
from scripts import run_operator_x_examples_fixture as common


SOURCE, BINARY, INITIALIZER = (Path("/synthetic/" + name) for name in ("source", "gate", "initialize.py"))
NODE = Path("/home/catchplate/.nvm/versions/node/v25.5.0/bin/node")
MODULES = SOURCE / "examples/npm-registry/node_modules"
JOB = Path("/srv/catchplate-fast/tmp/serverware-npm-example-private.abcdef12")
ARGS = (SOURCE, BINARY, INITIALIZER, JOB, NODE, MODULES)
PINS = {"expected_binary_sha256": "a" * 64, "expected_node_modules_sha256": "b" * 64}
RUNTIME = {"network", "npm-registry", "serverware", "decision-gate-rs", "edge", "check"}
NOW = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)


class FixedDateTime(datetime.datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW


def rows_for(config):
    images = {value: "sha256:" + str(index) * 64 for index, value in enumerate(
        sorted({service["image"] for service in config["services"].values()}), 1)}
    identities = {name: format(index, "064x") for index, name in enumerate(sorted(RUNTIME), 1)}
    rows = []
    for name in sorted(RUNTIME):
        service = config["services"][name]
        memory = int(service["mem_limit"][:-1]) * (1024**2 if service["mem_limit"][-1] == "m" else 1024**3)
        rows.append({"Id": identities[name], "Image": images[service["image"]], "RestartCount": 0,
            "Config": {"User": service["user"], "Entrypoint": service["entrypoint"], "Cmd": service["command"],
                "WorkingDir": service["working_dir"], "Env": ["PATH=/usr/local/bin:/usr/bin:/bin"] + [
                    key + "=" + value for key, value in service.get("environment", {}).items()],
                "Labels": {"com.docker.compose.project": config["name"], "com.docker.compose.service": name}},
            "State": {"OOMKilled": False, "Status": "created" if name == "check" else "running",
                "Health": {"Status": "healthy"}, "StartedAt": (NOW - datetime.timedelta(seconds=10)).isoformat()},
            "HostConfig": {"Privileged": False, "ReadonlyRootfs": True, "PortBindings": {},
                "NetworkMode": "none" if name == "network" else "container:" + identities["network"],
                "CapDrop": ["ALL"], "CapAdd": ["CAP_" + cap for cap in service.get("cap_add", [])],
                "SecurityOpt": ["no-new-privileges:true"], "Memory": memory, "MemorySwap": memory,
                "NanoCpus": int(service["cpus"] * 10**9), "PidsLimit": service["pids_limit"], "Init": service["init"],
                "RestartPolicy": {"Name": "no"}, "Sysctls": service.get("sysctls", {}),
                "LogConfig": {"Type": service["logging"]["driver"], "Config": service["logging"]["options"]},
                "Tmpfs": dict(value.split(":", 1) for value in service["tmpfs"]), "Binds": None},
            "Mounts": [{"Type": "bind", "Source": mount["source"], "Destination": mount["target"],
                "RW": not mount["read_only"]} for mount in service["volumes"]]})
    return rows, images


class InertTests(unittest.TestCase):
    def setUp(self):
        for target in ("socket.socket", "socket.create_connection", "socket.getaddrinfo",
                "subprocess.Popen", "subprocess.run"):
            self.enterContext(patch(target, side_effect=AssertionError("unexpected runtime I/O in inert test")))


class NpmExampleRecipeTests(InertTests):
    def setUp(self):
        super().setUp()
        self.config = recipe.build(*ARGS, **PINS)

    def test_exact_runtime_roster_and_network_none_containment(self):
        self.assertEqual(set(self.config), {"name", "services"})
        self.assertEqual(recipe.RUNTIME_SERVICES, RUNTIME)
        self.assertEqual(set(self.config["services"]), RUNTIME | {"initialize", "npm-pki", "basic-pki"})
        for name, service in self.config["services"].items():
            self.assertEqual(service["network_mode"], "none" if name in
                {"initialize", "npm-pki", "basic-pki", "network"} else "service:network")
            for forbidden in ("ports", "expose", "networks", "extra_hosts", "dns", "privileged",
                    "devices", "pid", "ipc", "env_file", "volumes_from"):
                self.assertNotIn(forbidden, service)
            self.assertTrue(service["read_only"])
            self.assertEqual(service["restart"], "no")
            self.assertEqual(service["pull_policy"], "never")
            self.assertEqual(service["cap_drop"], ["ALL"])
            self.assertIn("no-new-privileges:true", service["security_opt"])
            self.assertNotIn("HOME", service.get("environment", {}))
            self.assertEqual(len(service["volumes"]), len({row["target"] for row in service["volumes"]}))
            for mount in service["volumes"]:
                self.assertFalse(mount["bind"]["create_host_path"])

    def test_adjacent_full_dependencies_and_existing_image_account_without_home_override(self):
        check = self.config["services"]["check"]
        self.assertEqual(check["image"], recipe.base.APP_IMAGE)
        self.assertEqual(check["user"], "10001:10001")
        self.assertEqual(check["environment"], {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": "/app"})
        mounts = {row["target"]: row for row in check["volumes"]}
        self.assertEqual(mounts["/app"]["source"], str(SOURCE))
        self.assertEqual(mounts["/node"]["source"], str(NODE))
        self.assertEqual(mounts["/app/examples/npm-registry/node_modules"]["source"], str(MODULES))
        self.assertEqual(mounts["/usr/lib/x86_64-linux-gnu/libatomic.so.1"]["source"],
            "/usr/lib/x86_64-linux-gnu/libatomic.so.1.2.0")
        for target in ("/app", "/node", "/app/examples/npm-registry/node_modules",
                "/usr/lib/x86_64-linux-gnu/libatomic.so.1", "/client-trust/inner-ca.pem", "/client-trust/outer-ca.pem"):
            self.assertTrue(mounts[target]["read_only"])
        for target in mounts:
            self.assertNotIn(target, {"/npm", "/etc/passwd", "/etc/group", "/home", "/home/serverware"})
        self.assertEqual(check["command"][0], "/app/scripts/check_operator_npm_example.py")
        self.assertNotIn("operator_npm_publish_job.mjs", json.dumps(check))
        self.assertTrue(any(value.startswith("/tmp:") and "uid=10001" in value and "mode=0700" in value
            for value in check["tmpfs"]))

    def test_original_lifetimes_resource_bounds_and_executable_pins(self):
        self.assertEqual(recipe.NODE_SHA256, "3dc3f85ca5539ca81b7d106992ebcd82d09bce27326016873653a661ad6b2a7d")
        self.assertEqual(recipe.LIBATOMIC_SHA256, "9d8a34468e614a71a6427dbabb0ac24eb8cb1e324dc6aa3bf95eb6f59201f000")
        self.assertEqual((recipe.KEEPER_SECONDS, recipe.EDGE_SECONDS, recipe.PRECHECK_SECONDS), (300, 240, 75))
        self.assertEqual((recipe.CHECKER_SECONDS, recipe.CHECKER_OUTER_SECONDS), (180, 210))
        self.assertEqual(recipe.PRECHECK_SECONDS + recipe.CHECKER_OUTER_SECONDS + 15, recipe.KEEPER_SECONDS)
        self.assertEqual(self.config["services"]["npm-registry"]["command"][-2:], ["--lifetime-seconds", "300"])
        for service in self.config["services"].values():
            self.assertLessEqual(service["cpus"], 2)
            self.assertLessEqual(service["pids_limit"], 128)
            self.assertEqual(service["mem_limit"], service["memswap_limit"])
            self.assertIn(service["mem_limit"], {"64m", "128m", "256m", "512m", "1g"})

    def test_exact_recomputation_rejects_containment_command_pin_and_environment_drift(self):
        recipe.validate(self.config, *ARGS, **PINS)
        for case in ("missing", "extra", "ports", "network", "modules", "write", "home", "account", "command", "time"):
            changed = deepcopy(self.config)
            check = changed["services"]["check"]
            if case == "missing": del changed["services"]["edge"]
            elif case == "extra": changed["services"]["other"] = deepcopy(check)
            elif case == "ports": check["ports"] = ["3000:3000"]
            elif case == "network": check["network_mode"] = "host"
            elif case == "modules":
                next(row for row in check["volumes"] if row["target"].endswith("/node_modules"))["source"] = "/different/tree"
            elif case == "write": next(row for row in check["volumes"] if row["target"] == "/node")["read_only"] = False
            elif case == "home": check["environment"]["HOME"] = "/tmp/override"
            elif case == "account": check["user"] = "0:0"
            elif case == "command": check["command"][0] = "/app/scripts/check_operator_npm_publish.py"
            else: changed["services"]["npm-registry"]["command"][-1] = "301"
            with self.subTest(case=case), self.assertRaises(ValueError):
                recipe.validate(changed, *ARGS, **PINS)

    def test_new_root_and_exact_pins_refuse_before_runtime(self):
        for key in PINS:
            for invalid in (None, True, "a" * 63, "A" * 64, "sha256:" + "a" * 64):
                changed = dict(PINS); changed[key] = invalid
                with self.subTest(key=key, invalid=invalid), self.assertRaises(ValueError):
                    recipe.build(*ARGS, **changed)
        for root in (Path("/tmp") / JOB.name, JOB.with_name("serverware-npm-publish-private.abcdef12")):
            with self.assertRaises(ValueError): recipe.build(*ARGS[:3], root, *ARGS[4:], **PINS)
        for node, modules in ((Path("/different/node"), MODULES), (NODE, Path("/detached/node_modules"))):
            with self.assertRaises(ValueError):
                recipe.build(*ARGS[:4], node, modules, **PINS)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source, job, evidence = (root / name for name in ("source", "job", "evidence"))
            for path in (source, job, evidence): path.mkdir(mode=0o700)
            retained = job / "prior.claim"
            retained.write_text("synthetic retained attempt")
            run = runner.NpmExampleRun(SimpleNamespace(source=source, job_root=job, evidence=evidence, commit="a" * 40))
            with patch.object(run, "command", side_effect=AssertionError("must not launch")), self.assertRaises(ValueError):
                run.execute()
            self.assertEqual(retained.read_text(), "synthetic retained attempt")
            self.assertEqual(list(evidence.iterdir()), [])


class DependencyInventoryTests(InertTests):
    def setUp(self):
        super().setUp()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o755)
        for relative in ("pacote", "pacote/bin", ".bin"):
            path = self.root / relative
            path.mkdir(); path.chmod(0o755)
        self.entry = self.root / "pacote/bin/index.js"
        self.entry.write_bytes(b"synthetic package entry\n"); self.entry.chmod(0o644)
        package = self.root / "pacote/package.json"
        package.write_bytes(b'{"name":"pacote","version":"21.5.1"}\n'); package.chmod(0o644)
        self.link = self.root / ".bin/pacote"
        self.link.symlink_to("../pacote/bin/index.js")

    def test_full_regular_bytes_and_explicit_bin_links_are_deterministically_bound(self):
        expected = {"files": {str(path.relative_to(self.root)): {
                "size": len(path.read_bytes()), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            for path in (self.entry, self.root / "pacote/package.json")},
            "symlinks": {".bin/pacote": {"target": "../pacote/bin/index.js"}}}
        observed = recipe.dependency_inventory(self.root)
        self.assertEqual(observed, expected)
        canonical = json.dumps(expected, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        self.assertEqual(recipe.dependency_sha256(observed), hashlib.sha256(canonical).hexdigest())
        self.assertEqual(recipe.dependency_sha256({"symlinks": expected["symlinks"], "files": dict(
            reversed(list(expected["files"].items())))}), recipe.dependency_sha256(expected))
        self.assertEqual(recipe.dependency_inventory(self.root), observed)
        self.entry.write_bytes(b"different same-owned input\n")
        self.assertNotEqual(recipe.dependency_sha256(recipe.dependency_inventory(self.root)),
            recipe.dependency_sha256(observed))

    def test_inventory_refuses_external_absolute_dangling_and_unreviewed_link_positions(self):
        for target in (str(self.entry), "../../outside.js", "../pacote/missing.js"):
            self.link.unlink(); self.link.symlink_to(target)
            with self.subTest(target=target), self.assertRaises((ValueError, OSError)):
                recipe.dependency_inventory(self.root)
        self.link.unlink(); self.link.symlink_to("../pacote/bin/index.js")
        stray = self.root / "pacote/alias.js"
        stray.symlink_to("bin/index.js")
        with self.assertRaises(ValueError): recipe.dependency_inventory(self.root)

    def test_inventory_refuses_hardlinks_unreadable_files_and_git_or_symlinked_roots(self):
        hard = self.root / "duplicate.js"
        os.link(self.entry, hard)
        with self.assertRaises(ValueError): recipe.dependency_inventory(self.root)
        hard.unlink()
        self.entry.chmod(0o600)
        with self.assertRaises(ValueError): recipe.dependency_inventory(self.root)
        self.entry.chmod(0o644)
        git = self.root / ".git"
        git.mkdir(); git.chmod(0o755)
        with self.assertRaises(ValueError): recipe.dependency_inventory(self.root)
        git.rmdir()
        link = self.root / "root-alias"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError): recipe.dependency_inventory(link)

    def test_exact_manifest_pin_and_both_top_level_and_bundled_package_versions(self):
        identities = (("npm", "npm", "11.20.0"), ("pacote", "pacote", "21.5.1"),
            ("npm-registry-fetch", "npm-registry-fetch", "19.1.1"),
            ("npm/node_modules/pacote", "pacote", "21.5.1"),
            ("npm/node_modules/npm-registry-fetch", "npm-registry-fetch", "19.1.1"))
        for relative, name, version in identities:
            directory = self.root / relative
            directory.mkdir(parents=True, exist_ok=True)
            for parent in (directory, *directory.parents):
                if not parent.is_relative_to(self.root): break
                parent.chmod(0o755)
            path = directory / "package.json"
            path.write_text(json.dumps({"name": name, "version": version})); path.chmod(0o644)
        original = recipe.dependency_inventory(self.root)
        expected = recipe.dependency_sha256(original)
        self.assertEqual(recipe.validate_dependencies(self.root, expected), original)
        with self.assertRaises(ValueError): recipe.validate_dependencies(self.root, "0" * 64)
        for relative, name, version in identities:
            path = self.root / relative / "package.json"
            for value in ({"name": name, "version": "99.0.0"}, {"name": "other", "version": version}):
                path.write_text(json.dumps(value))
                # Recompute the byte pin so package-identity validation, not a
                # stale hash mismatch, must be responsible for this rejection.
                changed = recipe.dependency_sha256(recipe.dependency_inventory(self.root))
                with self.subTest(package=relative, value=value), self.assertRaises(ValueError):
                    recipe.validate_dependencies(self.root, changed)
            path.write_text(json.dumps({"name": name, "version": version}))
        self.assertEqual(recipe.validate_dependencies(self.root, expected), original)


class NpmExampleRunnerTests(InertTests):
    def setUp(self):
        super().setUp()
        self.enterContext(patch.object(runner.datetime, "datetime", FixedDateTime))
        self.clock = self.enterContext(patch.object(runner.time, "monotonic", return_value=100.0))
        self.config = recipe.build(*ARGS, **PINS)
        self.rows, self.images = rows_for(self.config)
        self.run = runner.NpmExampleRun(SimpleNamespace(commit="a" * 40))
        self.run.project, self.run.services = self.config["name"], self.config["services"]
        self.run.deadline = 165.0
        self.run.image_environments = {image: {"PATH": "/usr/local/bin:/usr/bin:/bin"} for image in self.images}
        self.saved = {}
        self.run.save = lambda name, value: self.saved.setdefault(name, value)

    def inspect(self, rows=None, *, anchor=90):
        rows = self.rows if rows is None else rows
        def output(name, argv, seconds=30):
            if name == "created-ids": return ("\n".join(row["Id"] for row in rows) + "\n").encode()
            if name == "created-inspect": return json.dumps(rows).encode()
            if name == "edge-ready": return b'{"ready":true,"syntheticOnly":true,"headerRewriting":false}'
            if name == "edge-ready-state-0": return b'{"Status":"running","OOMKilled":false}'
            raise AssertionError("unexpected inert inspector command")
        with patch.object(self.run, "command", side_effect=output):
            return self.run.inspect_runtime(self.config, self.images, recipe, keeper_anchor=anchor)

    def test_actual_six_runtime_inspection_returns_only_exact_checker_and_reuses_deadlines(self):
        expected = next(row["Id"] for row in self.rows if row["Config"]["Labels"]["com.docker.compose.service"] == "check")
        self.assertEqual(self.inspect(), expected)
        self.assertEqual(len(self.saved["container-observations.json"]), 6)
        self.assertIs(runner.NpmExampleRun.command, inherited.GmailSdkRun.command)
        self.assertIs(runner.NpmExampleRun.wait_edge_ready, inherited.GmailSdkRun.wait_edge_ready)
        self.assertIs(runner.NpmExampleRun.container_rows, common.Run.container_rows)
        self.assertIs(runner.NpmExampleRun.no_project_networks, common.Run.no_project_networks)
        self.assertEqual((runner.WORK_SECONDS, runner.CLEANUP_SECONDS), (390, 60))

    def test_actual_inspector_rejects_namespaces_identity_bindings_resources_and_environment(self):
        cases = ("missing", "foreign-service", "foreign-project", "network", "ports", "writable", "mount", "cap",
            "image", "health", "oom", "restart", "user", "entrypoint", "command", "cwd", "memory", "swap",
            "cpus", "pids", "init", "restart-policy", "sysctl", "logging", "tmpfs", "legacy-bind", "device",
            "volume", "home", "node-options", "duplicate-env", "changed-env")
        for case in cases:
            rows = deepcopy(self.rows)
            row = next(item for item in rows if item["Config"]["Labels"]["com.docker.compose.service"] == "check")
            host, actual = row["HostConfig"], row["Config"]
            if case == "missing": rows.remove(row)
            elif case == "foreign-service": actual["Labels"]["com.docker.compose.service"] = "other"
            elif case == "foreign-project": actual["Labels"]["com.docker.compose.project"] = "other"
            elif case == "network": host["NetworkMode"] = "host"
            elif case == "ports": host["PortBindings"] = {"443/tcp": [{"HostPort": "443"}]}
            elif case == "writable": host["ReadonlyRootfs"] = False
            elif case == "mount": row["Mounts"][0]["RW"] = True
            elif case == "cap": host["CapAdd"] = ["CAP_NET_ADMIN"]
            elif case == "image": row["Image"] = "sha256:" + "f" * 64
            elif case == "health":
                next(item for item in rows if item["Config"]["Labels"]["com.docker.compose.service"] == "npm-registry")["State"]["Health"]["Status"] = "unhealthy"
            elif case == "oom": row["State"]["OOMKilled"] = True
            elif case == "restart": row["RestartCount"] = 1
            elif case == "user": actual["User"] = "0:0"
            elif case == "entrypoint": actual["Entrypoint"] = ["different"]
            elif case == "command": actual["Cmd"] = ["different"]
            elif case == "cwd": actual["WorkingDir"] = "/"
            elif case == "memory": host["Memory"] += 1
            elif case == "swap": host["MemorySwap"] += 1
            elif case == "cpus": host["NanoCpus"] += 1
            elif case == "pids": host["PidsLimit"] += 1
            elif case == "init": host["Init"] = not host["Init"]
            elif case == "restart-policy": host["RestartPolicy"]["Name"] = "always"
            elif case == "sysctl": host["Sysctls"] = {"net.ipv4.ip_nonlocal_bind": "1"}
            elif case == "logging": host["LogConfig"]["Config"]["max-size"] = "99m"
            elif case == "tmpfs": host["Tmpfs"]["/tmp"] = "rw,size=1g"
            elif case == "legacy-bind": host["Binds"] = ["/outside:/inside"]
            elif case == "device": host["Devices"] = [{"PathOnHost": "/dev/example"}]
            elif case == "volume": row["Mounts"].append({"Type": "volume", "Destination": "/outside"})
            elif case == "home": actual["Env"].append("HOME=/different")
            elif case == "node-options": actual["Env"].append("NODE_OPTIONS=--require=/different")
            elif case == "duplicate-env": actual["Env"].append(actual["Env"][0])
            else: actual["Env"] = ["PYTHONPATH=/different" if value.startswith("PYTHONPATH=") else value for value in actual["Env"]]
            with self.subTest(case=case), self.assertRaises(ValueError): self.inspect(rows)

    def test_original_keeper_and_edge_clocks_cannot_be_renewed_by_inspection(self):
        for name, age in (("network", 75), ("npm-registry", 75), ("edge", 30)):
            rows = deepcopy(self.rows)
            row = next(item for item in rows if item["Config"]["Labels"]["com.docker.compose.service"] == name)
            row["State"]["StartedAt"] = (NOW - datetime.timedelta(seconds=age)).isoformat()
            with self.subTest(service=name), self.assertRaises(ValueError): self.inspect(rows)
        with self.assertRaises(ValueError): self.inspect(anchor=25)
        self.run.deadline = 110.0
        with patch.object(common.Run, "command", autospec=True, return_value=b"observation") as command:
            self.assertEqual(self.run.command("phase", ["not-executed"], 30), b"observation")
            self.assertEqual(command.call_args.args[-1], 4.0)
            self.clock.return_value = 104.0
            with self.assertRaises(ValueError): self.run.command("late", ["not-executed"], 30)
            self.assertEqual(command.call_count, 1)
        self.assertEqual(self.run.deadline, 110.0)

    def test_cleanup_contains_detached_workers_first_and_only_mutates_exact_owned_ids(self):
        checker = next(row["Id"] for row in self.rows if row["Config"]["Labels"]["com.docker.compose.service"] == "check")
        for refusal in (None, "cleanup-before-ids", "cleanup-check-remove", "cleanup-after-ids", "cleanup-networks"):
            calls = []
            def output(name, argv, seconds=30):
                calls.append((name, argv, seconds))
                if name == refusal: raise ValueError("synthetic closed refusal")
                if name == "cleanup-before-ids": return ("\n".join(row["Id"] for row in self.rows) + "\n").encode()
                if name == "cleanup-before-inspect": return json.dumps(self.rows).encode()
                return b""
            with self.subTest(refusal=refusal), patch.object(self.run, "command", side_effect=output):
                clean, errors = self.run.cleanup()
            self.assertEqual(clean, refusal is None)
            self.assertEqual(self.run.deadline, 160.0)
            writes = [argv for name, argv, _ in calls if name.startswith("cleanup-") and argv[:2] in
                (["docker", "rm"], ["docker", "stop"])]
            if refusal == "cleanup-before-ids":
                self.assertEqual(writes, []); self.assertEqual(errors, ["inspect"])
            else:
                remaining = [row["Id"] for row in self.rows if row["Id"] != checker or refusal == "cleanup-check-remove"]
                self.assertEqual(writes, [["docker", "rm", "--force", checker],
                    ["docker", "stop", "--time", "5", *remaining], ["docker", "rm", "--force", *remaining]])
                if refusal == "cleanup-check-remove": self.assertIn("checker-remove", errors)

    def test_clean_commit_is_checked_independently_before_and_after(self):
        for suffix in ("before", "after"):
            for bad in (None, "commit", "dirty"):
                calls = []
                def output(name, argv, seconds=30):
                    calls.append((name, argv, seconds))
                    if name == "source-commit-" + suffix:
                        return (("b" if bad == "commit" else "a") * 40 + "\n").encode()
                    return b" M tracked-file\n" if bad == "dirty" else b""
                with self.subTest(suffix=suffix, bad=bad), patch.object(self.run, "command", side_effect=output):
                    if bad is None: self.run.source_unchanged(suffix)
                    else:
                        with self.assertRaises(ValueError): self.run.source_unchanged(suffix)
                self.assertEqual(calls[0], ("source-commit-" + suffix, ["git", "rev-parse", "HEAD"], 10))
                if bad == "commit": self.assertEqual(len(calls), 1)
                else: self.assertEqual(calls[1], ("source-status-" + suffix, ["git", "status", "--porcelain=v1"], 10))


if __name__ == "__main__":
    unittest.main()
