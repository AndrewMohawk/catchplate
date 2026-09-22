#!/usr/bin/env python3
"""Exercise exact custody topology and lifecycle provenance with local fixtures."""

from __future__ import annotations

import copy
import json
import unittest
from unittest.mock import patch

import generate_release_provenance as provenance
import test_development_compose as compose_tests


COMPOSE_FILES = ["docker-compose.yml", "docker-compose.custody.yml"]
IMAGE_ID = "sha256:" + "1" * 64


def container_fixture(service: str) -> dict:
    oneshot = service in provenance.CUSTODY_ONESHOT_SERVICES
    return {
        "Id": "container-" + service,
        "Image": IMAGE_ID,
        "RestartCount": 0,
        "Config": {"Labels": {"com.docker.compose.service": service}, "User": "65521:65519"},
        "HostConfig": {"ReadonlyRootfs": True},
        "Mounts": [],
        "State": {
            "Status": "exited" if oneshot else "running",
            "Running": not oneshot,
            "OOMKilled": False,
            "Dead": False,
            "Restarting": False,
            "Error": "",
            "StartedAt": "2026-09-22T10:00:00Z",
            "FinishedAt": "2026-09-22T10:00:01Z" if oneshot else "0001-01-01T00:00:00Z",
            "ExitCode": 0,
        },
    }


class DevelopmentProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        renderer = compose_tests.DevelopmentComposeTests()
        cls.custody_model = renderer.model(renderer.render(
            profile=True, override=True, environment=compose_tests.custody_environment()
        ))

    def classify(self, model: dict) -> tuple[str, ...]:
        return provenance.development_compose_services(model, COMPOSE_FILES, ["custody"])

    def test_exact_custody_topology_is_supported(self) -> None:
        self.assertEqual(self.classify(self.custody_model), provenance.CUSTODY_DEV_SERVICES)
        self.assertEqual(len(provenance.CUSTODY_DEV_SERVICES), 15)

    def test_topology_requires_every_named_role_and_rejects_extras(self) -> None:
        for service in provenance.CUSTODY_DEV_SERVICES:
            with self.subTest(missing=service):
                candidate = copy.deepcopy(self.custody_model)
                del candidate["services"][service]
                with self.assertRaises(ValueError):
                    self.classify(candidate)
        candidate = copy.deepcopy(self.custody_model)
        candidate["services"]["unexpected-worker"] = candidate["services"]["custody-runtime"]
        with self.assertRaises(ValueError):
            self.classify(candidate)

    def test_custody_roles_reject_wrong_identity_network_or_build_owner(self) -> None:
        for service in provenance.CUSTODY_V2_SERVICES:
            for key, value in (
                ("image", "untrusted:latest"),
                ("build", {"context": "."}),
                ("pull_policy", "always"),
                ("user", "0:0"),
                ("network_mode", "host"),
                ("read_only", False),
                ("command", ["--check-readiness"]),
                ("privileged", True),
                ("cap_add", ["SYS_ADMIN"]),
            ):
                with self.subTest(service=service, setting=key):
                    candidate = copy.deepcopy(self.custody_model)
                    candidate["services"][service][key] = value
                    with self.assertRaises(ValueError):
                        self.classify(candidate)

    def test_gate_requires_exact_declared_driver_groups(self) -> None:
        for groups in (["10003"], ["10003", "65519", "0"], ["10003", "65519", "65518", "42"]):
            candidate = copy.deepcopy(self.custody_model)
            candidate["services"]["decision-gate-rs"]["group_add"] = groups
            with self.subTest(groups=groups), self.assertRaises(ValueError):
                self.classify(candidate)

    def test_activation_requires_the_same_generation_and_successful_dependency(self) -> None:
        candidate = copy.deepcopy(self.custody_model)
        candidate["services"]["response-v2-generation-activation"]["environment"][
            "SERVERWARE_RESPONSE_V2_PROVIDER_GENERATION_SHA256"
        ] = "sha256:" + "2" * 64
        with self.assertRaises(ValueError):
            self.classify(candidate)
        candidate = copy.deepcopy(self.custody_model)
        candidate["services"]["decision-gate-rs"]["depends_on"][
            "response-v2-generation-activation"
        ]["condition"] = "service_started"
        with self.assertRaises(ValueError):
            self.classify(candidate)

    def test_activation_rejects_missing_replaced_or_writable_peer_mount(self) -> None:
        target = "/run/serverware-response-v2/credential-transport"
        for mutation in ("missing", "replacement", "writable"):
            candidate = copy.deepcopy(self.custody_model)
            activation = candidate["services"]["response-v2-generation-activation"]
            mount = next(mount for mount in activation["volumes"] if mount["target"] == target)
            if mutation == "missing":
                activation["volumes"].remove(mount)
            elif mutation == "replacement":
                mount["source"] = "another-generation-socket"
            else:
                mount["read_only"] = False
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.classify(candidate)

    def test_all_custody_images_must_match_in_both_inventories(self) -> None:
        images = {name: {"image_id": IMAGE_ID} for name in provenance.CUSTODY_DEV_SERVICES}
        containers = {name: {"image": IMAGE_ID} for name in provenance.CUSTODY_DEV_SERVICES}
        provenance.verify_development_image_identity(provenance.CUSTODY_DEV_SERVICES, images, containers)
        for name in provenance.CUSTODY_GATE_IMAGE_SERVICES:
            for inventory in ("images", "containers"):
                candidate_images, candidate_containers = copy.deepcopy((images, containers))
                if inventory == "images":
                    candidate_images[name]["image_id"] = "sha256:" + "2" * 64
                else:
                    candidate_containers[name]["image"] = "sha256:" + "2" * 64
                with self.subTest(service=name, inventory=inventory), self.assertRaises(ValueError):
                    provenance.verify_development_image_identity(
                        provenance.CUSTODY_DEV_SERVICES, candidate_images, candidate_containers
                    )


class DevelopmentContainerInventoryTests(unittest.TestCase):
    def test_one_shots_require_successful_terminal_execution(self) -> None:
        for service in provenance.CUSTODY_ONESHOT_SERVICES:
            baseline = container_fixture(service)
            result = provenance.development_container_execution(service, baseline)
            self.assertEqual(result["lifecycle"], "completed-successfully")
            self.assertEqual(result["exit_code"], 0)
            for field, value in (
                ("ExitCode", 1), ("ExitCode", False), ("OOMKilled", True),
                ("Status", "running"), ("Running", True), ("Dead", True),
                ("Restarting", True), ("Error", "runtime error"),
                ("FinishedAt", "0001-01-01T00:00:00Z"),
                ("StartedAt", "0001-01-01T00:00:00Z"),
                ("FinishedAt", ""), ("StartedAt", ""),
            ):
                candidate = copy.deepcopy(baseline)
                candidate["State"][field] = value
                with self.subTest(service=service, field=field, value=value):
                    self.assertIsNone(provenance.development_container_execution(service, candidate))
            candidate = copy.deepcopy(baseline)
            candidate["RestartCount"] = 1
            self.assertIsNone(provenance.development_container_execution(service, candidate))

    def test_exited_long_running_service_is_not_success(self) -> None:
        inspected = container_fixture("serverware")
        inspected["State"].update(Status="exited", Running=False, ExitCode=0)
        self.assertIsNone(provenance.development_container_execution("serverware", inspected))

    def inventory_run(self, *, duplicate: bool = False, drift: bool = False):
        services = ("serverware", "response-v2-generation-bootstrap", "response-v2-generation-activation")
        fixtures = {name: container_fixture(name) for name in services}
        inspections: dict[str, int] = {}

        def run(command: list[str]) -> str:
            if command[:2] == ["docker", "inspect"]:
                name = command[-1].removeprefix("container-")
                result = copy.deepcopy(fixtures[name])
                inspections[name] = inspections.get(name, 0) + 1
                if drift and name == services[-1] and inspections[name] % 2 == 0:
                    result["State"]["FinishedAt"] = "2026-09-22T10:00:02Z"
                return json.dumps([result])
            self.assertEqual(command[:4], ["docker", "compose", "ps", "--all"])
            name = command[-1]
            status = command[command.index("--status") + 1]
            self.assertEqual(status, "exited" if name in provenance.CUSTODY_ONESHOT_SERVICES else "running")
            identity = fixtures[name]["Id"]
            return identity + ("\nanother-container" if duplicate and name == services[-1] else "")

        with patch.object(provenance, "run", side_effect=run), patch.object(provenance.time, "sleep"):
            return provenance.container_inventory(services)

    def test_inventory_records_running_and_completed_services(self) -> None:
        result = self.inventory_run()
        self.assertEqual(result["serverware"]["execution"]["lifecycle"], "running")
        for service in provenance.CUSTODY_ONESHOT_SERVICES:
            self.assertEqual(result[service]["execution"]["lifecycle"], "completed-successfully")

    def test_duplicate_or_changed_terminal_container_is_rejected(self) -> None:
        for kwargs in ({"duplicate": True}, {"drift": True}):
            with self.subTest(**kwargs), self.assertRaises(RuntimeError):
                self.inventory_run(**kwargs)


if __name__ == "__main__":
    unittest.main()
