#!/usr/bin/env python3
"""Check development/custody Compose selection without using a Docker daemon."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
GENERATION_PIN = "sha256:" + "1" * 64
BOOTSTRAP_DIRECTORY = "/catchplate-compose-contract/generation-bootstrap"
PUBLIC_DIRECTORY = "/catchplate-compose-contract/generation-public"
GENERATION_INPUTS = (
    "CATCHPLATE_RESPONSE_V2_PROVIDER_GENERATION_SHA256",
    "CATCHPLATE_RESPONSE_OBSERVATION_V2_BOOTSTRAP_KEY_DIR",
    "CATCHPLATE_RESPONSE_OBSERVATION_V2_GENERATION_PUBLIC_CREDENTIAL_DIR",
)


def clean_environment() -> dict[str, str]:
    environment = {
        name: value
        for name, value in os.environ.items()
        if name in {"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR"}
    }
    # Config rendering must work without daemon access. These fixture paths are
    # never created or mounted, and no fixture is usable authority material.
    environment["DOCKER_HOST"] = "unix:///catchplate-compose-contract-no-daemon.sock"
    return environment


def custody_environment() -> dict[str, str]:
    environment = clean_environment()
    environment.update(
        {
            "CATCHPLATE_POLICY_CUSTODY_DRIVER_GID": "65518",
            "CATCHPLATE_RESPONSE_V2_PROVIDER_GENERATION_SHA256": GENERATION_PIN,
            "CATCHPLATE_RESPONSE_OBSERVATION_V2_BOOTSTRAP_KEY_DIR": BOOTSTRAP_DIRECTORY,
            "CATCHPLATE_RESPONSE_OBSERVATION_V2_GENERATION_PUBLIC_CREDENTIAL_DIR": PUBLIC_DIRECTORY,
            "CATCHPLATE_RESPONSE_OBSERVATION_V2_PUBLIC_CONFIG_DIR": "/catchplate-compose-contract/public-config",
            "CATCHPLATE_RESPONSE_OBSERVATION_V2_STATE_KEY_DIR": "/catchplate-compose-contract/state-key",
            "CATCHPLATE_RESPONSE_OBSERVATION_V2_CREDENTIAL_KEY_DIR": "/catchplate-compose-contract/transport-key",
            "CATCHPLATE_RESPONSE_OBSERVATION_V2_POLICY_KEY_DIR": "/catchplate-compose-contract/policy-key",
            "CATCHPLATE_RESPONSE_OBSERVATION_V2_LEDGER_KEY_DIR": "/catchplate-compose-contract/ledger-key",
            "CATCHPLATE_RESPONSE_OBSERVATION_V2_RELEASE_KEY_DIR": "/catchplate-compose-contract/release-key",
            "CATCHPLATE_RESPONSE_OBSERVATION_V2_WATCHDOG_KEY_DIR": "/catchplate-compose-contract/watchdog-key",
            "CATCHPLATE_RESPONSE_OBSERVATION_V2_GENERATION_ID": "compose-contract",
            "CATCHPLATE_RESPONSE_OBSERVATION_V2_SOURCE_COMMIT_SHA256": GENERATION_PIN,
            "CATCHPLATE_RESPONSE_OBSERVATION_V2_SOURCE_TREE_SHA256": GENERATION_PIN,
            "CATCHPLATE_RESPONSE_OBSERVATION_V2_ROLE_KEYS_JSON": "{}",
            "CATCHPLATE_RESPONSE_OBSERVATION_V2_SIGNER_KEY_SHA256": GENERATION_PIN,
            "CATCHPLATE_RESPONSE_OBSERVATION_V2_ROLE_IDENTITY_ROOT_SHA256": GENERATION_PIN,
            "CATCHPLATE_RESPONSE_OBSERVATION_V2_PROOF_PINS_ROOT_SHA256": GENERATION_PIN,
            "CATCHPLATE_POLICY_SHADOW_TRUST_MANIFEST_SHA256": GENERATION_PIN,
            "CATCHPLATE_POLICY_SHADOW_RUNTIME_ATTESTATION_VERIFIER_SHA256": GENERATION_PIN,
            "CATCHPLATE_POLICY_SHADOW_PUBLICATION_HANDOFF_SHA256": GENERATION_PIN,
            "CATCHPLATE_POLICY_SHADOW_TRUST_MANIFEST_FILE": "/catchplate-compose-contract/trust-manifest.json",
            "CATCHPLATE_POLICY_SHADOW_CUSTODY_CONFIG_FILE": "/catchplate-compose-contract/custody.json",
            "CATCHPLATE_POLICY_SHADOW_TRUSTED_HOST_HELPER_DIR": "/catchplate-compose-contract/helpers",
            "CATCHPLATE_POLICY_CUSTODY_SOCKET_DIR": "/catchplate-compose-contract/sockets",
        }
    )
    return environment


class DevelopmentComposeTests(unittest.TestCase):
    def render(
        self,
        *,
        profile: bool = False,
        override: bool = False,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = [
            "docker", "compose", "--project-name", "catchplate-compose-contract",
            "--env-file", "/dev/null", "-f", str(ROOT / "docker-compose.yml"),
        ]
        if profile:
            command.extend(["--profile", "custody"])
        if override:
            command.extend(["-f", str(ROOT / "docker-compose.custody.yml")])
        command.extend(["config", "--format", "json"])
        return subprocess.run(
            command,
            cwd=ROOT,
            env=environment if environment is not None else clean_environment(),
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )

    def model(self, result: subprocess.CompletedProcess[str]) -> dict:
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_default_development_requires_no_custody_configuration(self) -> None:
        model = self.model(self.render())
        self.assertEqual(
            set(model["services"]),
            {"catchplate", "audit-anchor", "grant-store", "demo-upstream", "decision-gate-rs"},
        )
        for service in model["services"].values():
            for port in service.get("ports", []):
                self.assertEqual(port["host_ip"], "127.0.0.1")

    def test_development_host_ports_can_be_changed_without_exposing_listeners(self) -> None:
        environment = clean_environment()
        environment.update(
            {
                "CATCHPLATE_CONTROL_PLANE_HOST_PORT": "13000",
                "CATCHPLATE_AUDIT_ANCHOR_HOST_PORT": "19100",
                "CATCHPLATE_DECISION_GATE_PROXY_HOST_PORT": "18080",
                "CATCHPLATE_DECISION_GATE_DIRECT_HOST_PORT": "19090",
                "CATCHPLATE_DECISION_GATE_MANAGEMENT_HOST_PORT": "19091",
            }
        )
        model = self.model(self.render(environment=environment))
        actual = {
            (name, int(port["target"]), int(port["published"]), port["host_ip"])
            for name, service in model["services"].items()
            for port in service.get("ports", [])
        }
        self.assertEqual(
            actual,
            {
                ("catchplate", 3000, 13000, "127.0.0.1"),
                ("audit-anchor", 9100, 19100, "127.0.0.1"),
                ("decision-gate-rs", 9090, 18080, "127.0.0.1"),
                ("decision-gate-rs", 9090, 19090, "127.0.0.1"),
                ("decision-gate-rs", 9091, 19091, "127.0.0.1"),
            },
        )
        catchplate_environment = model["services"]["catchplate"]["environment"]
        self.assertEqual(catchplate_environment["CATCHPLATE_PUBLIC_URL"], "http://localhost:13000")
        for variable, path in (
            ("CATCHPLATE_GOOGLE_OAUTH_REDIRECT_URI", "/api/oauth/callback/google"),
            ("CATCHPLATE_X_OAUTH_REDIRECT_URI", "/api/oauth/callback/x"),
            ("CATCHPLATE_OIDC_REDIRECT_URI", "/api/auth/oidc/callback"),
        ):
            self.assertEqual(catchplate_environment[variable], "http://localhost:13000" + path)

    def test_explicit_public_url_and_callback_override_host_port_defaults(self) -> None:
        environment = clean_environment()
        environment.update(
            {
                "CATCHPLATE_CONTROL_PLANE_HOST_PORT": "13000",
                "CATCHPLATE_PUBLIC_URL": "https://portal.example.test",
                "CATCHPLATE_X_OAUTH_REDIRECT_URI": "https://callback.example.test/x",
            }
        )
        service_environment = self.model(self.render(environment=environment))["services"]["catchplate"]["environment"]
        self.assertEqual(service_environment["CATCHPLATE_PUBLIC_URL"], "https://portal.example.test")
        self.assertEqual(
            service_environment["CATCHPLATE_GOOGLE_OAUTH_REDIRECT_URI"],
            "https://portal.example.test/api/oauth/callback/google",
        )
        self.assertEqual(
            service_environment["CATCHPLATE_OIDC_REDIRECT_URI"],
            "https://portal.example.test/api/auth/oidc/callback",
        )
        self.assertEqual(
            service_environment["CATCHPLATE_X_OAUTH_REDIRECT_URI"],
            "https://callback.example.test/x",
        )

    def test_profile_alone_does_not_provision_or_enable_custody(self) -> None:
        services = self.model(self.render(profile=True))["services"]
        self.assertNotIn("response-v2-generation-activation", services)
        gate_environment = services["decision-gate-rs"]["environment"]
        self.assertNotIn("CATCHPLATE_RESPONSE_PROOF_CUSTODY_SOCKET", gate_environment)
        self.assertNotIn("CATCHPLATE_RESPONSE_OBSERVATION_V2_SOCKET", gate_environment)
        for name in ("response-v2-generation-bootstrap", "response-v2-state-authority"):
            self.assertNotIn(GENERATION_INPUTS[0], services[name]["environment"])
            targets = {mount["target"] for mount in services[name]["volumes"]}
            self.assertNotIn("/run/credentials/catchplate-response-v2-generation-bootstrap", targets)
            self.assertNotIn("/run/credentials/catchplate-response-v2-generation-public", targets)

    def test_custody_override_preserves_required_authority_inputs(self) -> None:
        for variable in GENERATION_INPUTS:
            for value in (None, ""):
                with self.subTest(variable=variable, value=value):
                    environment = custody_environment()
                    if value is None:
                        del environment[variable]
                    else:
                        environment[variable] = value
                    result = self.render(profile=True, override=True, environment=environment)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(variable, result.stderr)

    def test_custody_activation_is_resolved_and_gates_proxy_startup(self) -> None:
        services = self.model(
            self.render(profile=True, override=True, environment=custody_environment())
        )["services"]
        for name in (
            "response-v2-generation-bootstrap",
            "response-v2-state-authority",
            "response-v2-generation-activation",
        ):
            self.assertEqual(services[name]["environment"][GENERATION_INPUTS[0]], GENERATION_PIN)
        for name, source, target in (
            ("response-v2-generation-bootstrap", BOOTSTRAP_DIRECTORY, "/run/credentials/catchplate-response-v2-generation-bootstrap"),
            ("response-v2-generation-activation", BOOTSTRAP_DIRECTORY, "/run/credentials/catchplate-response-v2-generation-bootstrap"),
            ("response-v2-state-authority", PUBLIC_DIRECTORY, "/run/credentials/catchplate-response-v2-generation-public"),
        ):
            mounts = [mount for mount in services[name]["volumes"] if mount["target"] == target]
            self.assertEqual(len(mounts), 1)
            self.assertEqual(mounts[0]["source"], source)
            self.assertIs(mounts[0]["read_only"], True)
        activation = services["response-v2-generation-activation"]
        self.assertEqual(activation["image"], services["decision-gate-rs"]["image"])
        self.assertNotIn("build", activation)
        self.assertEqual(activation["pull_policy"], "never")
        self.assertEqual(activation["network_mode"], "none")
        self.assertIs(activation["read_only"], True)
        self.assertEqual(activation["user"], "65521:65519")
        self.assertEqual(activation["command"][0], "--activate-generation")
        self.assertEqual(
            activation["depends_on"]["response-v2-custody-router"]["condition"],
            "service_healthy",
        )
        self.assertEqual(
            services["decision-gate-rs"]["depends_on"]["response-v2-generation-activation"]["condition"],
            "service_completed_successfully",
        )


if __name__ == "__main__":
    unittest.main()
