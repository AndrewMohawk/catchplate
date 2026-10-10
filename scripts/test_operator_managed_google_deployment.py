#!/usr/bin/env python3
"""Pure candidate-layer contracts, not Compose resolution or deployment proof.

Reads repository source only. No subprocess, Docker, application import, state,
key, provider, receiver or environment-file access. Root must separately resolve
Compose and verify actual source/binary provenance, empty custody and mounts.
"""
from __future__ import annotations

import ast
from copy import deepcopy
from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
STACK = ROOT / "docker/serverware-operator-demo"
CANDIDATE = STACK / "docker-compose.managed-google-candidate.yml"
BINARY_SHA256 = "333ff7a3db00ab2bf03644fc965aed9b691bdd6ddc4ec651273e6d0c36f053e0"
BINARY = "/srv/catchplate-fast/projects/serverware-operator-artifacts/sha256-" + BINARY_SHA256 + "/serverware-decision-gate"
SOURCE = "${OPERATOR_MANAGED_SOURCE:?Set the reviewed immutable managed source directory}"
PROVIDER = "${OPERATOR_MANAGED_PROVIDER_CUSTODY_DIR:?Set the reviewed empty app-only provider custody directory}"
ENVIRONMENT = {
    "SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST": "sha256:" + BINARY_SHA256,
    "SERVERWARE_OPERATOR_MANAGED_GOOGLE_ENABLED": "1",
    "SERVERWARE_OPERATOR_PROVIDER_CUSTODY_DIR": "/provider-custody",
    "SERVERWARE_PROCESS_MODE": "serverware-control-plane",
    "SERVERWARE_METADATA_STORE_BACKEND": "sqlite",
    "SERVERWARE_AUDIT_STORE_BACKEND": "sqlite",
    "SERVERWARE_GRANT_STORE_BACKEND": "sqlite",
    "SERVERWARE_RELEASE_CHANNEL": "dev",
    "SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": "0",
    "SERVERWARE_KEY_RELEASE_REQUIRED": "0",
    "SERVERWARE_DEV_AUTHENTICATOR": "0",
    "SERVERWARE_DEV_DEMO_SEED": "0",
}


class ClosedLoader(yaml.SafeLoader):
    """The new layer uses no anchors, merge keys or custom YAML tags."""


def unique_mapping(loader, node):
    result = {}
    for key, value in node.value:
        name = loader.construct_object(key, deep=True)
        if type(name) is not str or name in result:
            raise ValueError("candidate mapping refused")
        result[name] = loader.construct_object(value, deep=True)
    return result


ClosedLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def bind(source, target, readonly):
    return {"type": "bind", "source": source, "target": target,
        "read_only": readonly, "bind": {"create_host_path": False}}


def expected():
    return {"services": {
        "serverware": {"environment": dict(ENVIRONMENT), "volumes": [
            bind(SOURCE, "/app", True), bind(PROVIDER, "/provider-custody", False)]},
        "decision-gate-rs": {"environment": {"SERVERWARE_OPERATOR_MANAGED_GOOGLE_ENABLED": "1"},
            "volumes": [bind(BINARY, "/usr/local/bin/serverware-decision-gate", True)]},
    }}


def validate(candidate):
    if candidate != expected():
        raise ValueError("managed candidate layer differs")


class ManagedDeploymentTests(unittest.TestCase):
    def setUp(self):
        self.raw = CANDIDATE.read_text(encoding="utf-8")
        self.candidate = yaml.load(self.raw, Loader=ClosedLoader)

    def test_closed_two_service_layer_has_only_reviewed_env_and_binds(self):
        validate(self.candidate)
        self.assertEqual(set(self.candidate), {"services"})
        for service in self.candidate["services"].values():
            self.assertEqual(set(service), {"environment", "volumes"})

    def test_flags_match_the_existing_proven_fixture_without_importing_it(self):
        tree = ast.parse((ROOT / "scripts/prepare_operator_managed_google_gate_fixture.py").read_text())
        build = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "build")
        updates = [node for node in ast.walk(build) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute) and node.func.attr == "update"
            and ast.unparse(node.func.value) == "app['environment']"]
        self.assertEqual(len(updates), 1)
        fixture = ast.literal_eval(updates[0].args[0])
        actual = self.candidate["services"]["serverware"]["environment"]
        self.assertEqual({key: actual[key] for key in fixture}, fixture)
        self.assertEqual(actual["SERVERWARE_RELEASE_CHANNEL"], "dev")

    def test_source_required_without_default_and_binary_pair_literal(self):
        app, gate = (self.candidate["services"][name] for name in ("serverware", "decision-gate-rs"))
        self.assertEqual(app["volumes"][0], bind(SOURCE, "/app", True))
        self.assertRegex(SOURCE, r"^\$\{OPERATOR_MANAGED_SOURCE:\?[^}]+\}$")
        self.assertEqual(gate["volumes"], [bind(BINARY, "/usr/local/bin/serverware-decision-gate", True)])
        self.assertEqual(app["environment"]["SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST"], "sha256:" + BINARY_SHA256)
        self.assertNotIn("${", BINARY)

    def test_provider_custody_is_required_app_only_and_not_auto_created(self):
        app, gate = (self.candidate["services"][name] for name in ("serverware", "decision-gate-rs"))
        self.assertEqual(app["volumes"][1], bind(PROVIDER, "/provider-custody", False))
        self.assertRegex(PROVIDER, r"^\$\{OPERATOR_MANAGED_PROVIDER_CUSTODY_DIR:\?[^}]+\}$")
        self.assertNotIn("SERVERWARE_OPERATOR_PROVIDER_CUSTODY_DIR", gate["environment"])
        self.assertNotIn("/provider-custody", {item["target"] for item in gate["volumes"]})
        self.assertIn("existing EMPTY app-owned 0700 directory", self.raw)
        self.assertIn("including bind aliases", self.raw)

    def test_no_legacy_google_profile_credential_seed_or_destination_change(self):
        base = yaml.safe_load((STACK / "docker-compose.yml").read_text())
        for name in ("serverware", "decision-gate-rs"):
            effective = {**base["services"][name]["environment"], **self.candidate["services"][name]["environment"]}
            self.assertNotIn("SERVERWARE_OPERATOR_GOOGLE_PROFILE", effective)
            self.assertFalse(any(key.startswith("SERVERWARE_GOOGLE_") for key in effective))
            self.assertNotIn("SERVERWARE_OPERATOR_DEMO_UPSTREAMS", self.candidate["services"][name]["environment"])
        self.assertNotIn("managed-prepare", self.candidate["services"])
        self.assertEqual(self.candidate["services"]["serverware"]["environment"]["SERVERWARE_DEV_DEMO_SEED"], "0")

    def test_existing_curated_layer_replaces_gate_data_without_provider_exposure(self):
        curated = yaml.safe_load((STACK / "docker-compose.curated-gate.yml").read_text())
        self.assertEqual(set(curated), {"services"})
        self.assertEqual(set(curated["services"]), {"serverware", "decision-gate-rs"})
        self.assertEqual(curated["services"]["serverware"], {"environment": {"SERVERWARE_OPERATOR_GATE_PUBLICATION_ENABLED": "1"}})
        gate = curated["services"]["decision-gate-rs"]
        self.assertEqual(set(gate), {"volumes"})
        mounts = {item["target"]: item for item in gate["volumes"]}
        self.assertEqual(len(mounts), len(gate["volumes"]))
        self.assertEqual(set(mounts), {"/data", "/data/.operator-publication.lock", "/data/.serverware-operator-demo.json",
            "/data/mitmproxy/mitmproxy-ca-cert.pem", "/data/mitmproxy/mitmproxy-ca.pem"})
        self.assertTrue(mounts["/data"]["source"].endswith("/app-data/gate-runtime"))
        for mount in mounts.values():
            self.assertIs(mount["read_only"], True)
            self.assertEqual(mount["bind"], {"create_host_path": False})

    def test_candidate_cannot_override_notifications_or_other_services(self):
        # Source-node inspection avoids interpreting Compose's !reset extension.
        notification = yaml.compose((STACK / "docker-compose.notifications.yml").read_text())
        services = dict(notification.value)[next(node for node, _ in notification.value if node.value == "services")]
        self.assertEqual([key.value for key, _ in services.value], ["serverware"])
        self.assertNotIn("SERVERWARE_OPERATOR_NOTIFICATIONS_", self.raw)
        for name in ("edge", "demo-upstream"):
            self.assertNotIn(name, self.candidate["services"])
        self.assertNotIn("/notification-custody", {item["target"] for service in self.candidate["services"].values()
            for item in service["volumes"]})

    def test_drift_and_duplicate_keys_are_rejected(self):
        mutations = []
        for key in ("networks", "image", "command", "ports", "healthcheck"):
            changed = deepcopy(self.candidate)
            changed["services"]["serverware"][key] = "unreviewed"
            mutations.append(changed)
        changed = deepcopy(self.candidate)
        changed["services"]["decision-gate-rs"]["volumes"].append(bind(PROVIDER, "/provider-custody", True))
        mutations.append(changed)
        changed = deepcopy(self.candidate)
        changed["services"]["serverware"]["environment"]["SERVERWARE_OPERATOR_MANAGED_GOOGLE_ENABLED"] = "0"
        mutations.append(changed)
        for candidate in mutations:
            with self.assertRaisesRegex(ValueError, "^managed candidate layer differs$"):
                validate(candidate)
        with self.assertRaisesRegex(ValueError, "^candidate mapping refused$"):
            yaml.load("services: {}\nservices: {}\n", Loader=ClosedLoader)


if __name__ == "__main__":
    unittest.main()
