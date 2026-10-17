#!/usr/bin/env python3
"""Opt-in X deployment contract; no daemon, provider or live-state access.

Compose tests render repository layers with synthetic paths and an empty envfile.
The historical Google candidate exercises merge compatibility, NOT current binary
admission. Custody tests reuse explicit config/active-owner test doubles, while
the filesystem and actual X runtime admission checks remain real.
"""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import yaml
from scripts import test_operator_managed_google_deployment as google
from scripts import test_operator_x_admission as admitted

STACK = ROOT / "docker/catchplate-operator-demo"
LAYER = STACK / "docker-compose.managed-x.yml"
FLAG = "CATCHPLATE_OPERATOR_MANAGED_X_ENABLED"
DIRECTORY = "CATCHPLATE_OPERATOR_X_CUSTODY_DIR"
INPUT = "OPERATOR_MANAGED_X_CUSTODY_DIR"
SOURCE = "${OPERATOR_MANAGED_X_CUSTODY_DIR:?Set the reviewed app-only X custody directory}"


def expected():
    return {"services": {
        "catchplate": {"environment": {FLAG: "1", DIRECTORY: "/x-custody"},
            "volumes": [google.bind(SOURCE, "/x-custody", False)]},
        "decision-gate-rs": {"environment": {FLAG: "1"}},
    }}


def validate(layer):
    if layer != expected():
        raise ValueError("managed X deployment layer differs")


class LayerTests(unittest.TestCase):
    def setUp(self):
        self.layer = yaml.load(LAYER.read_text(), Loader=google.ClosedLoader)

    def test_exact_optional_layer_has_no_other_permissions_or_inputs(self):
        validate(self.layer)
        self.assertNotIn("managed-x", (STACK / "docker-compose.yml").read_text())
        app = self.layer["services"]["catchplate"]
        self.assertEqual(app["volumes"], [google.bind(SOURCE, "/x-custody", False)])
        self.assertEqual(self.layer["services"]["decision-gate-rs"], {"environment": {FLAG: "1"}})

    def test_gate_exposure_unsafe_mount_and_unrelated_changes_refuse(self):
        changes = []
        for field in ("ports", "networks", "command", "labels", "dns", "user"):
            changed = deepcopy(self.layer)
            changed["services"]["catchplate"][field] = "unreviewed"
            changes.append(changed)
        changed = deepcopy(self.layer)
        changed["services"]["decision-gate-rs"]["volumes"] = [google.bind(SOURCE, "/x-custody", True)]
        changes.append(changed)
        for field, value in (("source", "${OPERATOR_MANAGED_X_CUSTODY_DIR:-/data/x}"),
                ("target", "/data/x"), ("read_only", True), ("bind", {"create_host_path": True})):
            changed = deepcopy(self.layer)
            changed["services"]["catchplate"]["volumes"][0][field] = value
            changes.append(changed)
        changed = deepcopy(self.layer)
        changed["services"]["catchplate"]["environment"]["CATCHPLATE_OPERATOR_DEMO_UPSTREAMS"] = "[]"
        changes.append(changed)
        for changed in changes:
            with self.assertRaisesRegex(ValueError, "^managed X deployment layer differs$"):
                validate(changed)
        with self.assertRaises(ValueError):
            yaml.load("services: {}\nservices: {}\n", Loader=google.ClosedLoader)


class RenderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.docker = shutil.which("docker")
        if cls.docker is None:
            raise unittest.SkipTest("Docker Compose unavailable; closed source/admission controls still run")
        temporary = tempfile.TemporaryDirectory(prefix="x-compose-contract-")
        cls.addClassCleanup(temporary.cleanup)
        cls.directory = Path(temporary.name)
        (cls.directory / "docker-config").mkdir(mode=0o700)
        cls.env = {"PATH": os.defpath, "HOME": str(cls.directory),
            "DOCKER_CONFIG": str(cls.directory / "docker-config"),
            "DOCKER_HOST": "unix://" + str(cls.directory / "no-daemon.sock"),
            "COMPOSE_DISABLE_ENV_FILE": "1", "COMPOSE_ANSI": "never",
            "OPERATOR_DEMO_DATA_ROOT": str(cls.directory / "data"),
            "OPERATOR_DEMO_SDK_SOURCE": str(cls.directory / "sdk-source"),
            "OPERATOR_DEMO_RUST_BINARY": str(cls.directory / "gate"),
            "OPERATOR_DEMO_RUST_BINARY_SHA256": "1" * 64,
            "OPERATOR_DEMO_UPSTREAMS": '["https://demo-upstream:8443","https://api.github.com",'
                '"https://registry.npmjs.org","https://gmail.googleapis.com"]',
            "TRAEFIK_IPV4": "172.16.0.2",
            "OPERATOR_MANAGED_SOURCE": str(cls.directory / "managed-source"),
            "OPERATOR_MANAGED_PROVIDER_CUSTODY_DIR": str(cls.directory / "google"),
            "OPERATOR_DEMO_NOTIFICATIONS_CUSTODY_DIR": str(cls.directory / "notifications"),
            "OPERATOR_DEMO_NOTIFICATIONS_ENABLED": "1",
            INPUT: str(cls.directory / "x")}
        probe = subprocess.run([cls.docker, "compose", "version", "--short"], env=cls.env,
            capture_output=True, timeout=10, check=False)
        if probe.returncode:
            raise unittest.SkipTest("Docker Compose plugin unavailable")
        cls.baseline = cls.render(False)
        cls.candidate = cls.render(True)

    @classmethod
    def invoke(cls, include_x, env):
        command = [cls.docker, "compose", "--project-directory", str(cls.directory),
            "--project-name", "managed-x-source-test", "--env-file", "/dev/null"]
        layers = ["docker-compose.yml", "docker-compose.managed-google-candidate.yml",
            "docker-compose.curated-gate.yml", "docker-compose.notifications.yml"]
        if include_x:
            layers.append(LAYER.name)
        for layer in layers:
            command += ["-f", str(STACK / layer)]
        return subprocess.run(command + ["config", "--format", "json"], env=env,
            capture_output=True, timeout=15, check=False)

    @classmethod
    def render(cls, include_x):
        result = cls.invoke(include_x, cls.env)
        if result.returncode or len(result.stdout) > 1024 * 1024:
            raise AssertionError("synthetic Compose render failed")
        return json.loads(result.stdout)

    def test_full_render_changes_only_three_env_entries_and_one_app_bind(self):
        candidate = deepcopy(self.candidate)
        app = candidate["services"]["catchplate"]
        gate = candidate["services"]["decision-gate-rs"]
        self.assertEqual(app["environment"].pop(FLAG), "1")
        self.assertEqual(app["environment"].pop(DIRECTORY), "/x-custody")
        self.assertEqual(gate["environment"].pop(FLAG), "1")
        selected = [item for item in app["volumes"] if item["target"] == "/x-custody"]
        self.assertEqual(len(selected), 1)
        actual = dict(selected[0])
        self.assertIs(actual.pop("read_only", False), False)
        self.assertEqual(actual, {"type": "bind", "source": self.env[INPUT],
            "target": "/x-custody", "bind": {"create_host_path": False}})
        app["volumes"].remove(selected[0])
        self.assertEqual(candidate, self.baseline)

    def test_render_retains_curated_gate_and_no_other_service_can_see_x(self):
        users = []
        for name, service in self.candidate["services"].items():
            for mount in service.get("volumes", []):
                if mount.get("type") != "bind":
                    continue
                source, x = Path(mount["source"]), Path(self.env[INPUT])
                if source == x or x.is_relative_to(source) or source.is_relative_to(x):
                    users.append((name, mount["target"]))
        self.assertEqual(users, [("catchplate", "/x-custody")])
        gate = self.candidate["services"]["decision-gate-rs"]
        data = next(item for item in gate["volumes"] if item["target"] == "/data")
        self.assertEqual(data["source"], self.env["OPERATOR_DEMO_DATA_ROOT"] + "/app-data/gate-runtime")
        self.assertIs(data["read_only"], True)
        for service in self.candidate["services"].values():
            self.assertFalse(service.get("ports"))
        self.assertNotIn("api.x.com", self.env["OPERATOR_DEMO_UPSTREAMS"])

    def test_unset_and_empty_custody_input_fail_before_any_daemon_access(self):
        for value in (None, ""):
            env = dict(self.env)
            if value is None:
                del env[INPUT]
            else:
                env[INPUT] = value
            result = self.invoke(True, env)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(INPUT.encode(), result.stderr)
            self.assertEqual(result.stdout, b"")
        self.assertFalse((self.directory / "x").exists())


class CustodyTests(unittest.TestCase):
    def setUp(self):
        self.fixture = admitted.XAdmissionTests("runTest")
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()

    def test_existing_private_custody_is_admitted_without_creating_material(self):
        result = admitted.admission.require_runtime()
        self.assertEqual(result.path, self.fixture.x)
        self.assertEqual(list(self.fixture.x.iterdir()), [])
        self.assertEqual(list(self.fixture.data.iterdir()), [])
        self.assertEqual(list(self.fixture.google.iterdir()), [])

    def test_missing_symlink_and_nonprivate_custody_refuse(self):
        alias = self.fixture.root / "alias"
        alias.symlink_to(self.fixture.x, target_is_directory=True)
        for path in ("", "relative", str(self.fixture.root / "missing"), str(alias), "/"):
            with patch.dict(os.environ, {DIRECTORY: path}):
                self.fixture.refused(admitted.admission.require_runtime)
        for mode in (0o750, 0o755, 0o777):
            self.fixture.x.chmod(mode)
            self.fixture.refused(admitted.admission.require_runtime)
        self.fixture.x.chmod(0o700)
        self.assertEqual(list(self.fixture.x.iterdir()), [])

    def test_data_and_google_custody_overlap_refuse(self):
        for root in (self.fixture.data, self.fixture.google):
            nested = root / "x"
            nested.mkdir(mode=0o700)
            for path in (root, nested):
                with patch.dict(os.environ, {DIRECTORY: str(path)}):
                    self.fixture.refused(admitted.admission.require_runtime)
        nested = self.fixture.x / "google"
        nested.mkdir(mode=0o700)
        with patch.dict(os.environ, {admitted.GOOGLE_DIRECTORY: str(nested)}):
            self.fixture.refused(admitted.admission.require_runtime)


if __name__ == "__main__":
    unittest.main()
