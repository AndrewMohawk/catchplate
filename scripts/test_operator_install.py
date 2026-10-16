#!/usr/bin/env python3
"""Focused installer contracts, not fresh-install or provider acceptance.

Run as root in the bounded cached test container: network none, no Docker
socket, read-only checkout/rootfs, private /tmp tmpfs. Filesystem ownership and
permissions are real; external Docker commands are replaced by fixed doubles.
"""
from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from operator_install import bootstrap, compose, config, lifecycle, process, runtime, state as installed


PASSWORD = b"synthetic-install-password-not-for-use"
IMAGE = "sha256:" + "1" * 64
EDGE_IMAGE = "sha256:" + "2" * 64
ARTIFACT = {"schema": "serverware.standaloneArtifact/v1", "sourceRevision": "3" * 40,
    "sourceTreeDigest": "sha256:" + "4" * 64, "compilerInputsDigest": "sha256:" + "5" * 64,
    "dataPlaneBinaryDigest": "sha256:" + "6" * 64}
REAL_RUN = process.run


def tree(path: Path) -> dict:
    """Only the small newly-created test tree, including identities and modes."""
    result = {}
    for item in [path, *sorted(path.rglob("*"))]:
        info = item.lstat()
        result[str(item.relative_to(path))] = (info.st_ino, stat.S_IMODE(info.st_mode),
            info.st_uid, info.st_gid, info.st_nlink,
            hashlib.sha256(item.read_bytes()).hexdigest() if stat.S_ISREG(info.st_mode) else None)
    return result


class InstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0 or {name for _, name in socket.if_nameindex()} != {"lo"}:
            raise RuntimeError("installer filesystem tests require the isolated root test container")
        if Path("/var/run/docker.sock").exists():
            raise RuntimeError("installer tests must not receive a Docker socket")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="operator-install-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.state = self.root / "instance"
        self.path = self.root / "config.json"
        self.values = {
            "schema": "serverware.standaloneInstall/v1", "project_name": "serverware-install-test",
            "state_dir": str(self.state), "console_origin": "https://console.example.com",
            "proxy_origin": "https://proxy.example.com", "allowed_upstreams": ["https://api.github.com"],
            "tls_certificate": str(self.root / "tls.crt"), "tls_private_key": str(self.root / "tls.key"),
        }
        self.save_config()
        self.reset_docker()

    def reset_docker(self):
        self.commands, self.running, self.networks = [], {}, {}
        self.ids = dict(zip(lifecycle.SERVICES, ("a" * 64, "b" * 64, "c" * 64)))
        self.publish = True
        self.fail_network = self.fail_compose = self.ignore_stop = False

    def tls_inputs(self):
        REAL_RUN(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-nodes", "-keyout", self.values["tls_private_key"], "-out", self.values["tls_certificate"],
            "-days", "1", "-subj", "/CN=console.example.com", "-addext",
            "subjectAltName=DNS:console.example.com,DNS:proxy.example.com"])
        Path(self.values["tls_private_key"]).chmod(0o600)

    def save_config(self, values=None):
        self.path.write_text(json.dumps(self.values if values is None else values), encoding="utf-8")
        self.path.chmod(0o600)

    def test_config_defaults_are_private_no_ports_and_explicit_origins(self):
        value = config.load_config(self.path)
        self.assertEqual(value["publish_address"], None)
        self.assertEqual(value["admin_username"], "admin")
        self.assertEqual(value["paired_image"], "serverware-standalone:local")
        self.assertEqual(value["allowed_upstreams"], ["https://api.github.com"])
        self.assertEqual(value["state_dir"], str(self.state))
        self.assertFalse(self.state.exists(), "configuration validation must not initialize state")

    def test_documented_configuration_loads_without_repair(self):
        example = Path(__file__).resolve().parents[1] / "docker/serverware-standalone/config.example.json"
        value = config.load_config(example)
        self.assertNotEqual(value["console_origin"], value["proxy_origin"])
        self.assertEqual(value["publish_address"], "0.0.0.0:443")

    def test_invalid_or_ambiguous_configurations_fail_before_external_commands(self):
        changes = [
            {"schema": "other"}, {"unexpected": True}, {"state_dir": "/"}, {"state_dir": "relative"},
            {"state_dir": str(self.root / "a" / ".." / "instance")},
            {"console_origin": "http://console.example.com"}, {"console_origin": "https://user:secret@console.example.com"},
            {"console_origin": "https://console.example.com/path"}, {"console_origin": "https://console.example.com?x=y"},
            {"console_origin": "https://127.0.0.1"}, {"console_origin": "https://proxy.example.com"},
            {"proxy_origin": "https://proxy.example.com:444"}, {"project_name": "../other"},
            {"allowed_upstreams": []}, {"allowed_upstreams": ["https://api.github.com"] * 2},
            {"allowed_upstreams": ["https://api.github.com/path"]},
            {"allowed_upstreams": ["https://provider" + str(i) + ".example.com" for i in range(33)]},
            {"allowed_upstreams": ["https://demo-upstream:8443"]},
            {"project_name": "serverware-operator-demo"},
            {"network_subnets": {"control": "172.30.0.0/24", "outbound": "172.30.0.0/25"}},
            {"network_subnets": {"control": "8.8.8.0/24", "outbound": "172.30.1.0/24"}},
            {"network_subnets": {"control": "172.30.0.1/24", "outbound": "172.30.1.0/24"}},
            {"network_subnets": {"control": "172.30.0.0/29", "outbound": "172.30.1.0/24"}},
            {"network_subnets": {"control": "172.30.0.0/24"}},
        ]
        with patch.object(process, "run", side_effect=AssertionError("configuration attempted an external command")):
            for change in changes:
                with self.subTest(fields=tuple(change)):
                    self.save_config({**self.values, **change})
                    with self.assertRaises(config.InstallError):
                        config.load_config(self.path)
                    self.assertFalse(self.state.exists())

    def test_configuration_symlink_and_duplicate_keys_are_refused(self):
        alias = self.root / "alias.json"
        alias.symlink_to(self.path)
        with self.assertRaises(config.InstallError):
            config.load_config(alias)
        self.path.write_text('{"schema":"serverware.standaloneInstall/v1","schema":"other"}', encoding="utf-8")
        with self.assertRaises(config.InstallError):
            config.load_config(self.path)

    def test_real_root_initialization_lock_is_private_exclusive_and_preserved(self):
        with installed.instance_lock(self.state, initialize=True):
            root_info, lock_info = self.state.stat(), (self.state / ".install.lock").stat()
            self.assertEqual((root_info.st_uid, root_info.st_gid, stat.S_IMODE(root_info.st_mode)), (0, 0, 0o700))
            self.assertEqual((lock_info.st_uid, lock_info.st_gid, stat.S_IMODE(lock_info.st_mode)), (0, 0, 0o600))
            with self.assertRaises(config.InstallError):
                with installed.instance_lock(self.state):
                    self.fail("simultaneous exclusive operation was admitted")
        before = tree(self.state)
        with self.assertRaises(config.InstallError):
            with installed.instance_lock(self.state, initialize=True):
                self.fail("existing installation was overwritten")
        self.assertEqual(tree(self.state), before)
        occupied = self.root / "occupied"
        occupied.mkdir(mode=0o700)
        (occupied / "retained.data").write_bytes(b"user-owned-state")
        before = tree(occupied)
        with self.assertRaises(config.InstallError):
            with installed.instance_lock(occupied, initialize=True):
                self.fail("unrelated state was adopted")
        self.assertEqual(tree(occupied), before)

    def test_state_paths_refuse_symlink_parents_leaves_and_lock_files(self):
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        sentinel = outside / "sentinel"
        sentinel.write_bytes(b"retained")
        alias = self.root / "alias"
        alias.symlink_to(outside, target_is_directory=True)
        before = tree(outside)
        for selected in (alias, alias / "new-instance"):
            with self.subTest(path=selected.name), self.assertRaises(config.InstallError):
                with installed.instance_lock(selected, initialize=True):
                    self.fail("symlink state path was admitted")
        self.assertEqual(tree(outside), before)
        self.state.mkdir(mode=0o700)
        (self.state / ".install.lock").symlink_to(sentinel)
        with self.assertRaises((config.InstallError, OSError)):
            with installed.instance_lock(self.state):
                self.fail("symlink lock was opened")
        self.assertEqual(tree(outside), before)

    def test_private_file_creation_uses_real_runtime_owner_and_never_overwrites(self):
        self.state.mkdir(mode=0o700)
        secret = self.state / "synthetic.token"
        installed.write_file(secret, b"synthetic-test-token", owner=10001)
        info = secret.stat()
        self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink), (10001, 10001, 0o600, 1))
        before = tree(self.state)
        with self.assertRaises(FileExistsError):
            installed.write_file(secret, b"replacement-must-not-land", owner=10001)
        self.assertEqual(tree(self.state), before)

    def test_bootstrap_creates_private_separated_state_and_repeat_refuses_without_changes(self):
        self.tls_inputs()
        with patch.object(process, "run", side_effect=self.docker), redirect_stdout(io.StringIO()) as output:
            result = bootstrap.initialize(self.path, PASSWORD)
            self.manifest = installed.load_manifest(self.state)
            self.assertEqual(result["status"], "initialized")
            self.assertEqual(result["image_id"], IMAGE)
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(self.networks, {})
            for name in bootstrap.DIRECTORIES:
                info = (self.state / name).stat()
                self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)), (10001, 10001, 0o700))
            for name in ("app-data", "gate-data", "provider-custody", "x-custody", "notification-custody", "ecr-artifacts"):
                self.assertEqual(list((self.state / name).iterdir()), [])
            tokens = [(self.state / "service-secrets" / name).read_bytes().strip() for name in installed.TOKEN_FILES]
            self.assertEqual(len(set(tokens)), 7)
            public = (self.state / "manifest.json").read_bytes() + (self.state / "compose.json").read_bytes() + json.dumps(result).encode()
            for secret in [PASSWORD, Path(self.values["tls_private_key"]).read_bytes(), *tokens]:
                self.assertNotIn(secret, public)
            self.assertTrue((self.state / "edge-secrets/htpasswd").read_bytes().startswith(b"admin:$6$"))
            self.assertNotIn(PASSWORD, (self.state / "edge-secrets/htpasswd").read_bytes())
            for name in installed.PINNED_FILES:
                info = (self.state / name).stat()
                owner = 0 if name == "compose.json" else 10001
                self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink), (owner, owner, 0o600, 1))
            before, commands = tree(self.state), len(self.commands)
            with self.assertRaises(config.InstallError):
                bootstrap.initialize(self.path, PASSWORD)
            self.assertEqual(len(self.commands), commands)
            self.assertEqual(tree(self.state), before)
        self.assertFalse(any("up" in command or "build" in command for command in self.commands))

    def test_bootstrap_partial_state_is_preserved_and_never_adopted(self):
        self.tls_inputs()
        self.fail_compose = True
        with patch.object(process, "run", side_effect=self.docker):
            with self.assertRaises(config.InstallError):
                bootstrap.initialize(self.path, PASSWORD)
            self.assertFalse((self.state / "manifest.json").exists(), "manifest must be committed last")
            self.assertTrue((self.state / "service-secrets/admin.token").is_file())
            before, commands = tree(self.state), len(self.commands)
            with self.assertRaises(config.InstallError):
                bootstrap.initialize(self.path, PASSWORD)
            self.assertEqual(len(self.commands), commands)
            self.assertEqual(tree(self.state), before)

    def test_bootstrap_network_preflight_failure_leaves_no_state_and_cleans_only_owned_network(self):
        self.tls_inputs()
        self.fail_network = True
        with patch.object(process, "run", side_effect=self.docker), self.assertRaises(config.InstallError):
            bootstrap.initialize(self.path, PASSWORD)
        self.assertFalse(self.state.exists())
        self.assertEqual(self.networks, {})
        self.assertEqual([command[-1] for command in self.commands if command[:3] == ("docker", "network", "rm")], ["d" * 64])

    def test_command_failures_keep_only_bounded_private_output_not_arguments_or_input(self):
        arguments = ["synthetic-command", "private-argument-not-to-log"]
        stdout, stderr = b"o" * 300000, b"e" * 300000
        failures = [subprocess.CompletedProcess(arguments, 1, stdout, stderr),
            subprocess.TimeoutExpired(arguments, 3, output=stdout, stderr=stderr)]
        for failure in failures:
            outcome = {"side_effect": failure} if isinstance(failure, Exception) else {"return_value": failure}
            with self.subTest(timeout=isinstance(failure, Exception)), \
                    patch.object(process.subprocess, "run", **outcome), \
                    patch.object(process.tempfile, "tempdir", str(self.root)), \
                    self.assertRaises(config.InstallError) as caught:
                REAL_RUN(arguments, input=PASSWORD, timeout=3)
            log = Path(caught.exception.diagnostic_path)
            self.assertEqual(log.parent, self.root)
            info, data = log.stat(), log.read_bytes()
            self.assertEqual((info.st_uid, stat.S_IMODE(info.st_mode), info.st_nlink), (0, 0o600, 1))
            self.assertLess(len(data), 525000)
            self.assertIn(b"o" * 262144, data)
            self.assertIn(b"e" * 262144, data)
            self.assertNotIn(PASSWORD, data)
            self.assertNotIn(arguments[1].encode(), data)
            self.assertNotIn("private-argument", str(caught.exception))

    def model(self, **changes):
        value = {**config.load_config(self.path), "paired_image": IMAGE, "edge_image": EDGE_IMAGE, **changes}
        return compose.render(value, ARTIFACT, "spiffe://serverware/standalone/test")

    def test_compose_default_has_only_three_services_and_no_fixture_or_published_ports(self):
        model = self.model()
        self.assertEqual(set(model["services"]), {"serverware", "decision-gate-rs", "edge"})
        self.assertTrue(model["networks"]["control"]["internal"])
        self.assertEqual(model["services"]["edge"]["networks"], ["control", "outbound"])
        for service in model["services"].values():
            self.assertFalse(service.get("ports"))
            self.assertNotIn("build", service)
            self.assertEqual(service["pull_policy"], "never")
            self.assertEqual(service["user"], "10001:10001")
            self.assertTrue(service["read_only"])
            self.assertEqual(service["cap_drop"], ["ALL"])
            for mount in service["volumes"]:
                self.assertFalse(mount["bind"]["create_host_path"])
                self.assertTrue(Path(mount["source"]).is_relative_to(self.state))
                self.assertNotEqual(mount["target"], "/app", "image owns source; no checkout overlay")
                self.assertNotIn("docker.sock", mount["target"])
        for name in ("serverware", "decision-gate-rs"):
            environment = model["services"][name]["environment"]
            self.assertEqual(environment["SERVERWARE_OPERATOR_DEMO_FIXTURE_CIDRS"], "[]")
            self.assertEqual(json.loads(environment["SERVERWARE_OPERATOR_DEMO_UPSTREAMS"]), ["https://api.github.com"])
        self.assertEqual(model["services"]["serverware"]["environment"]["SERVERWARE_DEV_DEMO_SEED"], "0")
        self.assertEqual(model["services"]["serverware"]["image"], model["services"]["decision-gate-rs"]["image"])

    def test_gate_gets_only_publication_ca_and_its_three_service_tokens(self):
        model = self.model()
        gate = model["services"]["decision-gate-rs"]
        mounts = {mount["target"]: mount for mount in gate["volumes"]}
        self.assertEqual(set(mounts), {"/data", "/gate-data", "/data/.operator-publication.lock",
            "/data/.serverware-operator-demo.json", "/data/mitmproxy/mitmproxy-ca-cert.pem",
            "/data/mitmproxy/mitmproxy-ca.pem", "/run/secrets/serverware/credential-lease.token",
            "/run/secrets/serverware/audit.token", "/run/secrets/serverware/management.token"})
        self.assertEqual(mounts["/data"]["source"], str(self.state / "app-data/gate-runtime"))
        self.assertTrue(all(mount["read_only"] for target, mount in mounts.items() if target != "/gate-data"))
        self.assertFalse(mounts["/gate-data"]["read_only"])
        self.assertNotIn("admin.token", json.dumps(gate))
        self.assertNotIn("custody", json.dumps(gate))
        self.assertNotIn(PASSWORD.decode(), json.dumps(model))

    def test_explicit_host_publish_is_only_the_tls_edge(self):
        for address in ("127.0.0.1:443", "0.0.0.0:443", "[::1]:443"):
            with self.subTest(address=address):
                services = self.model(publish_address=address)["services"]
                self.assertEqual(services["edge"]["ports"], [address + ":8443"])
                self.assertFalse(services["serverware"].get("ports"))
                self.assertFalse(services["decision-gate-rs"].get("ports"))

    def test_optional_network_ranges_are_exact_and_do_not_change_existing_networks(self):
        subnets = {"control": "172.30.0.0/24", "outbound": "172.30.1.0/24"}
        self.save_config({**self.values, "network_subnets": subnets})
        model = self.model()
        for name in subnets:
            self.assertEqual(model["networks"][name]["ipam"], {"config": [{"subnet": subnets[name]}]})
            self.assertNotIn("external", model["networks"][name])
            self.assertNotIn("name", model["networks"][name])
        self.assertEqual(len({service["labels"][lifecycle.LABEL] for service in model["services"].values()}), 1)

    def test_baked_runtime_start_reads_only_small_artifact_and_executes_no_build(self):
        artifact_path = self.root / "artifact.json"
        artifact_path.write_text(json.dumps(ARTIFACT), encoding="utf-8")
        for role, binary in (("app", sys.executable), ("gate", "/usr/local/bin/serverware-decision-gate")):
            with self.subTest(role=role), patch.object(runtime, "ARTIFACT", artifact_path), \
                    patch.object(sys, "argv", ["runtime.py", role]), \
                    patch.object(os, "execv") as execute, \
                    patch.object(Path, "rglob", side_effect=AssertionError("runtime scanned a source tree")), \
                    patch.object(os, "walk", side_effect=AssertionError("runtime scanned a source tree")):
                runtime.main()
                self.assertEqual(execute.call_count, 1)
                self.assertEqual(execute.call_args.args[0], binary)

    def retained_installation(self):
        """A tiny synthetic retained store, not a bootstrap or app-success claim."""
        value = {**config.load_config(self.path), "paired_image": IMAGE, "edge_image": EDGE_IMAGE}
        identifier = "11111111-2222-4333-8444-555555555555"
        with installed.instance_lock(self.state, initialize=True):
            for name in ("app-data", "gate-data", "service-secrets", "edge", "edge-secrets"):
                directory = self.state / name
                directory.mkdir(mode=0o700)
                os.chown(directory, 10001, 10001)
            files = {}
            for name in sorted(installed.PINNED_FILES):
                data = (installed.encoded(compose.render(value, ARTIFACT, identifier)) if name == "compose.json"
                    else ("synthetic-unit-only-" + name).encode())
                installed.write_file(self.state / name, data, owner=0 if name == "compose.json" else 10001)
                files[name] = installed.digest(data)
            self.manifest = {"schema": installed.SCHEMA, "config": value, "instance_id": identifier,
                "images": {"paired": {"id": IMAGE}, "edge": {"id": EDGE_IMAGE}}, "artifact": ARTIFACT, "files": files}
            installed.write_manifest(self.state, self.manifest, exclusive=True)
        self.reset_docker()

    def publish_files(self):
        # The fake Docker app creates only bounded structural publication files.
        # Real app/schema/signing/CA semantics are reserved for runtime acceptance.
        root = self.state / "app-data"
        for relative in compose.PUBLICATION_FILES:
            destination = root / relative
            if not destination.parent.exists():
                destination.parent.mkdir(mode=0o700)
                os.chown(destination.parent, 10001, 10001)
            if not destination.exists():
                installed.write_file(destination, b"synthetic-publication-only", owner=10001)
        database = root / "serverware.sqlite3"
        if not database.exists():
            with sqlite3.connect(database) as connection:
                connection.execute("CREATE TABLE unit_state (id INTEGER PRIMARY KEY)")
                connection.execute("INSERT INTO unit_state VALUES (1)")
            database.chmod(0o600)
            os.chown(database, 10001, 10001)

    def docker(self, args, *, input=None, timeout=30):
        """Closed Docker double; only explicitly selected local OpenSSL is real."""
        self.commands.append(tuple(args))
        if args[0] == "openssl":
            return REAL_RUN(args, input=input, timeout=timeout)
        if args[:3] == ["docker", "context", "inspect"]:
            return b'"unix:///var/run/docker.sock"'
        if args[:2] == ["docker", "info"]:
            return b'[]'
        if args == ["docker", "compose", "version", "--short"]:
            return b'2.0.0'
        if args[:2] == ["docker", "ps"]:
            return "\n".join(self.ids[name] for name in self.running).encode()
        if args[:3] in (["docker", "network", "ls"], ["docker", "volume", "ls"]):
            return b''
        if args[:3] == ["docker", "image", "inspect"]:
            paired = args[-1] in ("serverware-standalone:local", IMAGE)
            return json.dumps({"Id": IMAGE if paired else EDGE_IMAGE, "Os": "linux", "Architecture": "amd64",
                "RepoDigests": [], "Config": {"Labels": {
                    "io.serverware.artifact.schema": ARTIFACT["schema"],
                    "io.serverware.artifact.path": "/opt/serverware/artifact.json",
                    "org.opencontainers.image.revision": ARTIFACT["sourceRevision"]} if paired else {}}}).encode()
        if args[:2] == ["docker", "run"]:
            self.assertEqual(args[args.index("--network") + 1], "none")
            self.assertEqual(args[args.index("--pull") + 1], "never")
            self.assertIn("--read-only", args)
            self.assertFalse(set(args) & {"--mount", "--volume", "-v"})
            self.assertIn(IMAGE, args)
            return json.dumps(ARTIFACT).encode()
        if args[:3] == ["docker", "network", "create"]:
            if self.fail_network and self.networks:
                raise config.InstallError("synthetic network capacity refusal")
            identifier = ("d" if args[-1].endswith("-control") else "e") * 64
            label = args[args.index("--label") + 1].split("=", 1)
            self.networks[identifier] = dict([label])
            self.assertFalse(self.state.exists())
            return identifier.encode()
        if args[:3] == ["docker", "network", "inspect"]:
            return json.dumps(self.networks[args[-1]]).encode()
        if args[:3] == ["docker", "network", "rm"]:
            self.assertIn(args[-1], self.networks)
            del self.networks[args[-1]]
            return b''
        if args[:3] == ["docker", "container", "inspect"]:
            self.assertIn(args[-1], self.ids.values())
            name = next(name for name, identifier in self.ids.items() if identifier == args[-1])
            return json.dumps({lifecycle.LABEL: self.manifest["instance_id"],
                "com.docker.compose.project": self.values["project_name"], "com.docker.compose.service": name}).encode()
        if args[:2] == ["docker", "inspect"]:
            name = next(name for name, identifier in self.ids.items() if identifier == args[-1])
            if args[args.index("--format") + 1] == "{{json .Image}}":
                return json.dumps(EDGE_IMAGE if name == "edge" else IMAGE).encode()
            return json.dumps({"Status": self.running[name], "Health": {"Status": "healthy"}}).encode()
        if args[:2] == ["docker", "compose"] and args[2:6] == ["--project-name", self.values["project_name"], "--file", str(self.state / "compose.json")]:
            operation = args[6:]
            if operation == ["config", "--quiet"]:
                self.assertFalse((self.state / "manifest.json").exists())
                if self.fail_compose:
                    raise config.InstallError("synthetic compose validation refusal")
                return b''
            if operation[:3] == ["ps", "--all", "--quiet"]:
                return self.ids[operation[-1]].encode() if operation[-1] in self.running else b''
            if len(operation) == 7 and operation[:6] == ["up", "--detach", "--no-deps", "--no-build", "--pull", "never"] and operation[-1] in lifecycle.SERVICES:
                self.running[operation[-1]] = "running"
                if operation[-1] == "serverware" and self.publish:
                    self.publish_files()
                return b''
            if operation == ["exec", "-T", "serverware", "python", "-B", "-m", "scripts.operator_install.runtime", "pair-status"]:
                self.assertTrue(lifecycle._publication_ready(self.manifest))
                self.assertEqual(self.running.get("decision-gate-rs"), "running")
                return json.dumps({"ready": True, "policy_hash": "sha256:" + "7" * 64,
                    "loaded_policy_hash": "sha256:" + "7" * 64}).encode()
            if operation == ["stop", "--timeout", "30", "edge", "decision-gate-rs", "serverware"]:
                if not self.ignore_stop:
                    self.running = {name: "exited" for name in self.running}
                return b''
        self.fail("unexpected installer command category: " + "/".join(args[:2]))

    def test_start_status_stop_reopen_use_pinned_state_and_order_without_build_or_reset(self):
        self.retained_installation()
        with patch.object(process, "run", side_effect=self.docker):
            self.assertEqual(lifecycle.start(self.state)["status"], "ready")
            ups = [command[-1] for command in self.commands if "up" in command]
            self.assertEqual(ups, list(lifecycle.SERVICES))
            pair_index = next(i for i, command in enumerate(self.commands) if command[-1] == "pair-status")
            edge_index = next(i for i, command in enumerate(self.commands) if "up" in command and command[-1] == "edge")
            self.assertLess(pair_index, edge_index)
            before = tree(self.state)
            self.path.unlink()  # Reopening must not require the old public input file.
            with patch.object(Path, "rglob", side_effect=AssertionError("lifecycle walked the checkout")), \
                    patch.object(os, "walk", side_effect=AssertionError("lifecycle walked the checkout")):
                self.assertEqual(lifecycle.status(self.state)["status"], "ready")
                self.assertEqual(lifecycle.start(self.state)["status"], "ready")
                self.assertEqual(len([command for command in self.commands if "up" in command]), 3,
                    "already-ready start must not restart services")
                self.assertEqual(lifecycle.stop(self.state)["status"], "stopped")
                self.assertEqual(lifecycle.status(self.state)["status"], "not_ready")
                self.assertEqual(lifecycle.start(self.state)["status"], "ready")
            self.assertEqual(tree(self.state), before, "stop/status/reopen preserve every fixture file and CA identity")
        for command in self.commands:
            self.assertFalse(set(command) & {"build", "pull", "down", "rm", "--volumes"})

    def test_missing_publication_stops_startup_before_gate_or_edge(self):
        self.retained_installation()
        self.publish = False
        ticks = iter([0.0, 0.0, 0.0, 10.0, 10.0])
        with patch.object(process, "run", side_effect=self.docker), \
                patch.object(lifecycle.time, "monotonic", side_effect=lambda: next(ticks, 10.0)), \
                patch.object(lifecycle.time, "sleep"):
            with self.assertRaises(config.InstallError):
                lifecycle.start(self.state, timeout=5)
        self.assertEqual([command[-1] for command in self.commands if "up" in command], ["serverware"])

    def test_changed_installed_compose_is_refused_without_lifecycle_writes(self):
        self.retained_installation()
        (self.state / "compose.json").write_bytes(b'{}\n')
        before = tree(self.state)
        with patch.object(process, "run", side_effect=self.docker):
            for operation in (lifecycle.start, lifecycle.stop, lifecycle.status):
                with self.subTest(operation=operation.__name__), self.assertRaises(config.InstallError):
                    operation(self.state)
        self.assertEqual(tree(self.state), before)
        self.assertFalse(any(set(command) & {"up", "stop", "restart", "down", "rm"} for command in self.commands))

    def test_expired_start_deadline_does_not_start_next_service(self):
        self.retained_installation()
        with patch.object(process, "run", side_effect=self.docker), \
                patch.object(lifecycle.time, "monotonic", side_effect=[0.0, 6.0]):
            with self.assertRaises(config.InstallError):
                lifecycle.start(self.state, timeout=5)
        self.assertFalse(any("up" in command for command in self.commands))

    def test_stop_does_not_claim_success_while_container_still_running(self):
        self.retained_installation()
        self.running = {name: "running" for name in lifecycle.SERVICES}
        self.ignore_stop = True
        with patch.object(process, "run", side_effect=self.docker), self.assertRaises(config.InstallError):
            lifecycle.stop(self.state)

    def test_running_image_or_resource_role_mismatch_refuses_adoption(self):
        self.retained_installation()
        self.running = {"serverware": "running"}
        for mismatch in ("image", "role"):
            def response(args, **kwargs):
                value = self.docker(args, **kwargs)
                if mismatch == "image" and "{{json .Image}}" in args:
                    return json.dumps("sha256:" + "9" * 64).encode()
                if mismatch == "role" and args[:3] == ["docker", "container", "inspect"]:
                    labels = json.loads(value)
                    labels["com.docker.compose.service"] = "unexpected"
                    return json.dumps(labels).encode()
                return value
            with self.subTest(mismatch=mismatch), patch.object(process, "run", side_effect=response), self.assertRaises(config.InstallError):
                lifecycle.start(self.state)
        self.assertFalse(any("up" in command for command in self.commands))

    def test_tls_recovery_marker_status_is_read_only_maintenance_not_ready(self):
        self.retained_installation()
        self.running = {name: "running" for name in lifecycle.SERVICES}
        marker = self.state / "tls-replacement.json"
        for kind in ("regular", "dangling-symlink"):
            if kind == "regular":
                installed.write_file(marker, b"synthetic-incomplete-recovery")
            else:
                marker.unlink()
                marker.symlink_to(self.state / "absent-recovery-target")
            before = tree(self.state)
            self.commands.clear()
            with self.subTest(kind=kind), patch.object(process, "run", side_effect=self.docker):
                value = lifecycle.status(self.state)
                self.assertEqual(value["status"], "maintenance_required")
                self.assertEqual(set(value["services"]), set(lifecycle.SERVICES))
                with self.assertRaises(config.InstallError):
                    lifecycle.start(self.state)
            self.assertEqual(tree(self.state), before)
            self.assertFalse(any(command[-1] == "pair-status" or set(command) & {"up", "restart", "stop", "rm"}
                for command in self.commands))


if __name__ == "__main__":
    unittest.main(verbosity=2)
