#!/usr/bin/env python3
from __future__ import annotations

import copy
import ast
import base64
import json
import hashlib
import importlib.util
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import build_production_images
import generate_release_provenance
import serverware_source_tree
import verify_codebase_attestation
import verify_reproducible_builds
from test_development_compose import clean_environment, custody_environment

ROOT = Path(__file__).resolve().parent.parent


def production_compose_fixture_environment(
    base: dict[str, str] | None = None,
) -> dict[str, str]:
    """Render-only inputs: never provision or claim usable release authority."""
    compose = (ROOT / "docker-compose.production.yml").read_text(encoding="utf-8")
    environment = clean_environment()
    environment.update(base or {})
    for name in re.findall(r"\$\{([A-Z0-9_]+):\?[^}]*\}", compose):
        environment.setdefault(name, "serverware-compose-test-value")
    # Each short-syntax bind source gets a distinct, nonexistent absolute path.
    # Do not confuse required host IPs with volume sources or invent named volumes.
    for name in re.findall(r"^\s*- \$\{([A-Z0-9_]+):\?[^}]*\}(?=[:/])", compose, re.MULTILINE):
        if name not in (base or {}):
            environment[name] = f"/serverware-compose-contract/{name.lower()}"
    if "SERVERWARE_CONTROL_PLANE_IMAGE" not in (base or {}):
        environment["SERVERWARE_CONTROL_PLANE_IMAGE"] = "registry.test/serverware-control@sha256:" + "1" * 64
    if "SERVERWARE_DECISION_GATE_IMAGE" not in (base or {}):
        environment["SERVERWARE_DECISION_GATE_IMAGE"] = "registry.test/serverware-gate@sha256:" + "2" * 64
    for name, value in {
        "SERVERWARE_POLICY_CUSTODY_DRIVER_GID": "65518",
        "SERVERWARE_PROXY_BIND_ADDRESS": "127.0.0.1",
    }.items():
        if name not in (base or {}):
            environment[name] = value
    # A caller cannot accidentally turn a render-only fixture into daemon access.
    environment["DOCKER_HOST"] = clean_environment()["DOCKER_HOST"]
    return environment


def final_stage_lines(path: Path) -> list[str]:
    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.strip().startswith("#")]
    from_indexes = [index for index, line in enumerate(lines) if line.upper().startswith("FROM ")]
    if not from_indexes:
        raise AssertionError(f"{path} has no FROM")
    return lines[from_indexes[-1] :]


def assert_distroless_no_shell(path: Path, expected_base: str) -> None:
    final = final_stage_lines(path)
    first = final[0]
    if expected_base not in first or ":nonroot" not in first:
        raise AssertionError(f"{path} final stage is not pinned to the expected nonroot distroless base: {first}")
    forbidden_prefixes = ("RUN ", "SHELL ")
    for line in final[1:]:
        upper = line.upper()
        if upper.startswith(forbidden_prefixes):
            raise AssertionError(f"{path} final stage uses shell-capable Dockerfile instruction: {line}")
    if not any(line.upper().startswith("USER NONROOT:NONROOT") for line in final):
        raise AssertionError(f"{path} final stage does not run as nonroot")
    if any(" /bin/" in line or " /busybox" in line for line in final):
        raise AssertionError(f"{path} final stage references a shell path: {final}")


def assert_base_images_pinned(path: Path) -> None:
    from_lines = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip().upper().startswith("FROM ")
    ]
    mutable = []
    declared = set()
    for line in from_lines:
        fields = line.split()
        if len(fields) not in {2, 4} or (len(fields) == 4 and fields[2].upper() != "AS"):
            raise AssertionError(f"unsupported production FROM: {line}")
        if "@sha256:" not in fields[1] and fields[1].lower() != "scratch" and fields[1] not in declared:
            mutable.append(line)
        if len(fields) == 4:
            declared.add(fields[3])
    if not from_lines or mutable:
        raise AssertionError(f"{path} contains a mutable production base image: {from_lines}")


def assert_oci_traceability(path: Path) -> None:
    final = final_stage_lines(path)
    required = {
        "ORG.OPENCONTAINERS.IMAGE.SOURCE",
        "ORG.OPENCONTAINERS.IMAGE.REVISION",
        "DEV.SERVERWARE.SOURCE_TREE_DIGEST",
    }
    joined = "\n".join(line.upper() for line in final)
    missing = sorted(item for item in required if item not in joined)
    if missing:
        raise AssertionError(f"{path} final stage is missing OCI/source labels: {missing}")


def assert_dockerignore() -> None:
    ignored = set((ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines())
    required = {".git", ".tmp", "**/target", "ops/production-readiness.env", "*.pem", "*.key"}
    required.update(f"**/{part}" for part in serverware_source_tree.EXCLUDED_PARTS)
    missing = sorted(required - ignored)
    if missing:
        raise AssertionError(f".dockerignore does not exclude local build/secrets material: {missing}")
    allowed_cache_inputs = {
        "!production-dependencies/cache",
        "!production-dependencies/cache/python-wheelhouse-linux-amd64.tar.gz",
        "!production-dependencies/cache/cargo-vendor.tar.gz",
        "!production-dependencies/cache/musl-1.2.5-r12.apk",
        "!production-dependencies/cache/musl-dev-1.2.5-r12.apk",
    }
    exceptions = {line for line in ignored if line.startswith("!") and "cache" in line}
    if exceptions != allowed_cache_inputs or "production-dependencies/cache/**" not in ignored:
        raise AssertionError("Docker context must include only the fixed offline cache inputs")


def services_mounting_source(model: dict[str, object], source: str) -> set[str]:
    services = model.get("services") or {}
    return {
        str(service)
        for service, raw_config in services.items()
        if isinstance(raw_config, dict)
        and any(
            isinstance(mount, dict) and mount.get("source") == source
            for mount in (raw_config.get("volumes") or [])
        )
    }


def assert_control_plane_management_is_disabled(model: dict[str, object]) -> None:
    control = model["services"]["serverware"]
    environment = control.get("environment") or {}
    if environment.get("SERVERWARE_DECISION_GATE_BASE") not in (None, ""):
        raise AssertionError(
            "production control plane must use shared grants, not any gate-management URL"
        )


def assert_production_dependencies() -> None:
    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8").lower()
    if "mitmproxy" in requirements:
        raise AssertionError("production requirements must not include mitmproxy")
    dockerfile = (ROOT / "Dockerfile.production").read_text(encoding="utf-8")
    if "serverware.control_plane_runner" not in dockerfile:
        raise AssertionError("production image must start the control-plane runner, not the prototype mitmproxy runner")
    if "requirements.lock" not in dockerfile or "--require-hashes" not in dockerfile:
        raise AssertionError("production control-plane dependencies must use the hash-locked requirements file")
    if (
        "serverware.productionImage/v1" not in dockerfile
        or ".serverware-production-image" not in dockerfile
    ):
        raise AssertionError(
            "production control-plane image must contain its non-environment startup marker"
        )
    if (
        "mkdir -p /runtime/custody-trust /runtime/gate-materials" not in dockerfile
        or "chmod 0750 /runtime/gate-materials" not in dockerfile
        or (
            "COPY --from=runtime-tree --chown=65532:65532 --chmod=0750 "
            "/runtime/gate-materials /run/serverware/gate"
        )
        not in dockerfile
    ):
        raise AssertionError(
            "production image must seed the shared gate volume for the "
            "service-owned policy-directory lock"
        )
    config_source = (ROOT / "serverware" / "config.py").read_text(encoding="utf-8")
    if "_PRODUCTION_IMAGE_MARKER_PRESENT or os.getenv" not in config_source:
        raise AssertionError(
            "control-plane production detection must prefer the baked image marker"
        )
    if not (ROOT / "requirements.lock").is_file():
        raise AssertionError("production hash-locked requirements file is missing")
    prototype = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    if (
        "FROM production-dependencies AS production-runtime" not in prototype
        or final_stage_lines(ROOT / "Dockerfile")[0] != "FROM production-runtime AS runtime"
    ):
        raise AssertionError("default development image must use the production dependency stage, not proxy-test dependencies")
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    if "SERVERWARE_INSTALL_PROTOTYPE_MITMPROXY" in compose:
        raise AssertionError("default docker-compose.yml must not enable the mitmproxy prototype")
    dev_result = subprocess.run(
        ["docker", "compose", "--env-file", "/dev/null", "--profile", "custody", "config", "--format", "json"],
        cwd=ROOT,
        env=clean_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if dev_result.returncode != 0:
        raise AssertionError(
            f"development Compose model did not parse: {dev_result.stderr.decode(errors='replace')}"
        )
    dev_model = json.loads(dev_result.stdout)
    dev_proxy_ports = [
        binding
        for binding in dev_model["services"]["decision-gate-rs"].get("ports", [])
        if int(binding["target"]) == 9090 and str(binding.get("published")) == "8080"
    ]
    if len(dev_proxy_ports) != 1 or dev_proxy_ports[0].get("host_ip") != "127.0.0.1":
        raise AssertionError("default development agent proxy must publish 8080 only on loopback")
    try:
        generate_release_provenance.development_compose_services(
            dev_model, ["docker-compose.yml"], ["custody"]
        )
    except ValueError:
        pass
    else:
        raise AssertionError(
            "custody provenance accepted the profile without the required override"
        )
    custody_result = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            "/dev/null",
            "--profile",
            "custody",
            "-f",
            "docker-compose.yml",
            "-f",
            "docker-compose.custody.yml",
            "config",
            "--format",
            "json",
        ],
        cwd=ROOT,
        env=custody_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if custody_result.returncode != 0:
        raise AssertionError(
            f"custody Compose model did not parse: {custody_result.stderr.decode(errors='replace')}"
        )
    custody_model = json.loads(custody_result.stdout)
    if (
        generate_release_provenance.development_compose_services(
            custody_model,
            ["docker-compose.yml", "docker-compose.custody.yml"],
            ["custody"],
        )
        != generate_release_provenance.CUSTODY_DEV_SERVICES
    ):
        raise AssertionError("merged custody Compose topology was not classified exactly")
    wrong_client_uid = copy.deepcopy(custody_model)
    wrong_client_uid["services"]["custody-runtime"]["environment"][
        "SERVERWARE_CUSTODY_EXPECTED_CLIENT_UID"
    ] = "0"
    try:
        generate_release_provenance.development_compose_services(
            wrong_client_uid,
            ["docker-compose.yml", "docker-compose.custody.yml"],
            ["custody"],
        )
    except ValueError:
        pass
    else:
        raise AssertionError("custody provenance accepted the wrong authenticated client UID")
    custody_model_mutations = (
        (
            "unequal configured image references",
            lambda candidate: candidate["services"]["custody-runtime"].__setitem__(
                "image", "serverware-custody:dev"
            ),
        ),
        (
            "custody build ownership",
            lambda candidate: candidate["services"]["custody-runtime"].__setitem__(
                "build",
                {
                    "context": str(ROOT),
                    "dockerfile": "data-plane/decision-gate-rs/Dockerfile",
                },
            ),
        ),
        (
            "custody image pulling",
            lambda candidate: candidate["services"]["custody-runtime"].__setitem__(
                "pull_policy", "missing"
            ),
        ),
        (
            "missing gate build ownership",
            lambda candidate: candidate["services"]["decision-gate-rs"].pop(
                "build", None
            ),
        ),
    )
    for description, mutate in custody_model_mutations:
        candidate = copy.deepcopy(custody_model)
        mutate(candidate)
        try:
            generate_release_provenance.development_compose_services(
                candidate,
                ["docker-compose.yml", "docker-compose.custody.yml"],
                ["custody"],
            )
        except ValueError:
            pass
        else:
            raise AssertionError(f"custody provenance accepted {description}")
    if services_mounting_source(dev_model, "serverware-response-signing-private") != {"serverware"}:
        raise AssertionError("development response-signing private volume must be mounted only by the control plane")
    if services_mounting_source(dev_model, "serverware-custody-state") != {"custody-runtime"}:
        raise AssertionError("development custody state volume must be mounted only by custody")
    if (
        (dev_model["services"]["custody-runtime"].get("environment") or {}).get(
            "SERVERWARE_CUSTODY_ATTEMPT_LEDGER_DIRECTORY"
        )
        != "/var/lib/serverware-custody"
    ):
        raise AssertionError("development custody must use its private persistent attempt ledger")
    dev_serverware_env = dev_model["services"]["serverware"].get("environment") or {}
    if (
        dev_serverware_env.get("SERVERWARE_RESPONSE_SIGNING_KEY")
        != "/run/serverware/response-signing-private/response-signing-ed25519.pem"
    ):
        raise AssertionError("development response-signing key must use the control-plane-only volume")
    production_compose_path = ROOT / "docker-compose.production.yml"
    production_compose = production_compose_path.read_text(encoding="utf-8")
    if "SERVERWARE_DECISION_GATE_BASE" in production_compose:
        raise AssertionError("production control plane must not use the decision-gate management listener")
    if (
        "SERVERWARE_CONTROL_PLANE_GRANT_CONSUME_URL: "
        "https://serverware:3000/api/data-plane/grants/consume"
    ) not in production_compose:
        raise AssertionError("production decision gate must use authenticated shared grant consumption")
    if "SERVERWARE_DECISION_GATE_MANAGEMENT_HOST: 127.0.0.1" not in production_compose:
        raise AssertionError("production decision-gate management listener must be loopback-only")
    if "serverware-data:/data:ro" in production_compose:
        raise AssertionError("production decision gate must not mount control-plane private state")
    if "serverware-gate-materials:/run/serverware/gate:ro" not in production_compose:
        raise AssertionError("production decision gate must mount only the scoped gate-material volume")
    compose_env = production_compose_fixture_environment()
    bind_mount_fixtures = {
        "SERVERWARE_CONTROL_PLANE_TLS_DIR": "/tmp/serverware-compose-test-tls",
        "SERVERWARE_ATTESTATION_HELPER_DIR": "/tmp/serverware-compose-test-helpers",
        "SERVERWARE_NITRO_ROOT_CERT": "/tmp/serverware-compose-test-nitro-root.pem",
        "SERVERWARE_NITRO_KMS_MATERIALS_FILE": "/tmp/serverware-compose-test-kms-materials.json",
        "SERVERWARE_RELEASE_PROVENANCE_FILE": "/tmp/serverware-compose-test-provenance.json",
        "SERVERWARE_IMAGE_SIGNATURES_FILE": "/tmp/serverware-compose-test-signatures.json",
        "SERVERWARE_GOOGLE_OAUTH_CLIENT_SECRET_FILE": "/tmp/serverware-compose-test-google-oauth-secret",
        "SERVERWARE_X_OAUTH_CLIENT_SECRET_FILE": "/tmp/serverware-compose-test-x-oauth-secret",
        "SERVERWARE_OIDC_CLIENT_SECRET_FILE": "/tmp/serverware-compose-test-oidc-secret",
        "SERVERWARE_RESPONSE_SIGNING_PRIVATE_KEY_FILE": "/tmp/serverware-compose-test-response-signing-key",
        "SERVERWARE_SETUP_ENROLLMENT_VERIFIER_PUBLIC_KEY": "/tmp/serverware-compose-test-enrollment-verifier.pub.pem",
        "SERVERWARE_SETUP_HARDWARE_VERIFIER_PUBLIC_KEY": "/tmp/serverware-compose-test-hardware-verifier.pub.pem",
        "SERVERWARE_SETUP_FINAL_AUTHORITY_PUBLIC_KEY": "/tmp/serverware-compose-test-final-authority.pub.pem",
        "SERVERWARE_WEBAUTHN_RECOVERY_ROOT_PUBLIC_KEY": "/tmp/serverware-compose-test-recovery-root.pub.pem",
        "SERVERWARE_AUDIT_ANCHOR_TLS_DIR": "/tmp/serverware-compose-test-anchor-tls",
    }
    compose_env.update(bind_mount_fixtures)
    compose_env["SERVERWARE_CONTROL_PLANE_IMAGE"] = "registry.test/serverware-control@sha256:" + "1" * 64
    compose_env["SERVERWARE_DECISION_GATE_IMAGE"] = "registry.test/serverware-gate@sha256:" + "2" * 64
    result = subprocess.run(
        ["docker", "compose", "--env-file", "/dev/null", "-f", str(production_compose_path), "config", "--format", "json"],
        cwd=ROOT,
        env=compose_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"production Compose model did not parse: {result.stderr.decode(errors='replace')}")
    model = json.loads(result.stdout)
    assert_control_plane_management_is_disabled(model)
    for management_url in (
        "http://127.0.0.1:9091",
        "http://decision-gate-rs:9091",
        "https://management.invalid:9091",
    ):
        candidate = copy.deepcopy(model)
        candidate["services"]["serverware"]["environment"][
            "SERVERWARE_DECISION_GATE_BASE"
        ] = management_url
        try:
            assert_control_plane_management_is_disabled(candidate)
        except AssertionError as exc:
            if "must use shared grants" not in str(exc):
                raise
        else:
            raise AssertionError("production model admitted control-plane gate-management access")
    generate_release_provenance.validate_production_custody_topology(model, compose_env)

    def expect_custody_topology_rejection(
        label: str, mutate: object, expected_error: str | None = None,
    ) -> None:
        candidate = copy.deepcopy(model)
        mutate(candidate)
        try:
            generate_release_provenance.validate_production_custody_topology(
                candidate, compose_env
            )
        except ValueError as exc:
            if expected_error is not None and expected_error not in str(exc):
                raise AssertionError(f"{label} reached the wrong guard: {exc}") from exc
            return
        raise AssertionError(f"production custody validator accepted {label}")

    def set_service_value(service: str, key: str, value: object):
        return lambda candidate: candidate["services"][service].__setitem__(key, value)

    def set_service_env(service: str, key: str, value: str):
        return lambda candidate: candidate["services"][service]["environment"].__setitem__(key, value)

    def make_mount_writable(service: str, target: str):
        def mutate(candidate: dict[str, object]) -> None:
            for mount in candidate["services"][service]["volumes"]:
                if mount.get("target") == target:
                    mount["read_only"] = False
                    return
            raise AssertionError(f"fixture mount missing: {service} {target}")

        return mutate

    def leak_private_key(candidate: dict[str, object]) -> None:
        private_mount = next(
            mount
            for mount in candidate["services"]["serverware"]["volumes"]
            if mount.get("source")
            == bind_mount_fixtures["SERVERWARE_RESPONSE_SIGNING_PRIVATE_KEY_FILE"]
        )
        candidate["services"]["decision-gate-rs"]["volumes"].append(
            copy.deepcopy(private_mount)
        )

    def leak_private_key_parent(candidate: dict[str, object]) -> None:
        candidate["services"]["decision-gate-rs"]["volumes"].append(
            {
                "type": "bind",
                "source": str(
                    Path(
                        bind_mount_fixtures[
                            "SERVERWARE_RESPONSE_SIGNING_PRIVATE_KEY_FILE"
                        ]
                    ).parent
                ),
                "target": "/run/serverware/leaked-host-parent",
                "read_only": True,
            }
        )

    def leak_custody_state(candidate: dict[str, object]) -> None:
        state_mount = next(
            mount
            for mount in candidate["services"]["custody-runtime"]["volumes"]
            if mount.get("source") == "serverware-custody-state"
        )
        candidate["services"]["serverware"]["volumes"].append(copy.deepcopy(state_mount))

    def alter_pinned_healthcheck(candidate: dict[str, object]) -> None:
        candidate["services"]["serverware"]["healthcheck"]["test"][-1] = "socket-health"

    for label, mutate in (
        ("custody network access", set_service_value("custody-runtime", "network_mode", None)),
        ("custody sharing the gate UID", set_service_value("custody-runtime", "user", "65532:65530")),
        ("wrong custody client UID", set_service_env("custody-runtime", "SERVERWARE_CUSTODY_EXPECTED_CLIENT_UID", "65531")),
        ("wrong gate custody UID", set_service_env("decision-gate-rs", "SERVERWARE_RESPONSE_PROOF_CUSTODY_EXPECTED_UID", "65532")),
        ("missing gate socket GID", set_service_value("decision-gate-rs", "group_add", [])),
        ("writable custody trust mount", make_mount_writable("custody-runtime", "/run/serverware/custody-trust")),
        ("writable gate socket mount", make_mount_writable("decision-gate-rs", "/run/serverware-custody")),
        ("private key leaked to the gate", leak_private_key),
        ("private key parent leaked to the gate", leak_private_key_parent),
        ("custody state leaked to the control plane", leak_custody_state),
        (
            "control-plane readiness without active key and HTTPS checks",
            set_service_value("serverware", "healthcheck", {"test": ["CMD", "true"]}),
        ),
        ("altered marker-preserving control-plane readiness", alter_pinned_healthcheck),
        ("custody racing trust publication", lambda candidate: candidate["services"]["custody-runtime"]["depends_on"]["serverware"].__setitem__("condition", "service_started")),
    ):
        expect_custody_topology_rejection(label, mutate)

    for label, mutate, expected_error in (
        ("extra privileged gate group", set_service_value("decision-gate-rs", "group_add", ["65519", "65518", "65530", "0"]), "only the v2, custody, and declared host driver groups"),
        ("missing v2 gate group", set_service_value("decision-gate-rs", "group_add", ["65518", "65530"]), "only the v2, custody, and declared host driver groups"),
        ("wrong host driver group", lambda candidate: candidate["x-serverware-policy-custody-host-contract"].__setitem__("driverGroupGid", "65517"), "distinct env-bound host driver group"),
        ("unbound gate namespace", set_service_value("decision-gate-rs", "network_mode", "host"), "share only the control-plane network namespace"),
        ("gate extra network", set_service_value("decision-gate-rs", "networks", {"default": {}}), "share only the control-plane network namespace"),
        ("gate-owned publication", set_service_value("decision-gate-rs", "ports", [{"target": 9090, "published": "8080"}]), "share only the control-plane network namespace"),
        ("missing control publications", set_service_value("serverware", "ports", []), "publish only loopback control and the env-bound proxy"),
        ("disabled healthcheck", set_service_value("serverware", "healthcheck", {"test": list(generate_release_provenance.PRODUCTION_CONTROL_HEALTHCHECK_COMMAND), "disable": True}), "exact isolated authority entrypoint"),
        ("changed healthcheck mode", alter_pinned_healthcheck, "exact isolated authority entrypoint"),
        ("missing isolated healthcheck flag", set_service_value("serverware", "healthcheck", {"test": [part for part in generate_release_provenance.PRODUCTION_CONTROL_HEALTHCHECK_COMMAND if part != "-I"]}), "exact isolated authority entrypoint"),
        ("inline healthcheck injection", set_service_value("serverware", "healthcheck", {"test": ["CMD", "/usr/bin/python3", "-c", "raise SystemExit(0)"]}), "exact isolated authority entrypoint"),
    ):
        expect_custody_topology_rejection(label, mutate, expected_error)
    for target, field, value in (
        (3000, "host_ip", "0.0.0.0"),
        (9090, "host_ip", "0.0.0.0"),
        (9090, "target", 9091),
        (9090, "protocol", "udp"),
    ):
        def alter_port(candidate: dict[str, object]) -> None:
            next(port for port in candidate["services"]["serverware"]["ports"] if port["target"] == target)[field] = value
        expect_custody_topology_rejection(
            f"changed {target} {field}", alter_port,
            "publish only loopback control and the env-bound proxy",
        )
    for driver_gid in ("", "0", "65519", "65530", "65532", "4294967295", "driver"):
        candidate_env = {**compose_env, "SERVERWARE_POLICY_CUSTODY_DRIVER_GID": driver_gid}
        try:
            generate_release_provenance.validate_production_custody_topology(model, candidate_env)
        except ValueError as exc:
            if "distinct env-bound host driver group" not in str(exc):
                raise
        else:
            raise AssertionError(f"production accepted invalid host driver GID: {driver_gid!r}")

    if set(model["services"]) != {
        "serverware",
        "audit-anchor",
        "policy-authority-runtime",
        "policy-authority-verifier",
        "policy-authority-issuer",
        "policy-authority-executor",
        "policy-authority-external-witness-ready",
        "custody-runtime",
        "decision-gate-rs",
        "response-v2-generation-bootstrap",
        "response-v2-state-authority",
        "response-v2-credential-transport",
        "response-v2-policy-proof-verifier",
        "response-v2-immutable-artifact-ledger",
        "response-v2-release-attestor-publisher",
        "response-v2-cleanup-watchdog",
        "response-v2-custody-router",
        "response-v2-generation-activation",
    }:
        raise AssertionError(f"production Compose service set is not closed and complete: {sorted(model['services'])}")
    custody = model["services"]["custody-runtime"]
    gate = model["services"]["decision-gate-rs"]
    if model["services"]["serverware"]["healthcheck"]["test"] != list(generate_release_provenance.PRODUCTION_CONTROL_HEALTHCHECK_COMMAND):
        raise AssertionError("production readiness must use the exact isolated authority entrypoint")
    health_source = ast.parse((ROOT / "serverware" / "authority_fd_entrypoint.py").read_text(encoding="utf-8"))
    healthcheck_command = next(
        ast.literal_eval(node.value)
        for node in health_source.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "CONTROL_PLANE_HEALTH_CODE" for target in node.targets)
    )
    if (
        "validate_response_signing_key_custody" not in healthcheck_command
        or "sys.exit(1)" not in healthcheck_command
        or "assert " in healthcheck_command
        or "__debug__" in healthcheck_command
        or generate_release_provenance.sha256_prefixed_bytes(healthcheck_command.encode("utf-8"))
        != generate_release_provenance.PRODUCTION_CONTROL_HEALTHCHECK_SHA256
    ):
        raise AssertionError(
            "production control-plane readiness is not explicit under optimized Python"
        )
    if custody.get("image") != gate.get("image") or custody.get("build"):
        raise AssertionError("production custody must use the immutable decision-gate image without a build override")
    if custody.get("user") != "65531:65530" or gate.get("user") != "65532:65532":
        raise AssertionError("production custody and gate must use explicit distinct UIDs")
    if custody.get("network_mode") != "none":
        raise AssertionError("production custody must have no network namespace access")
    if custody.get("entrypoint") != ["/usr/local/bin/serverware-custody-runtime"]:
        raise AssertionError("production custody must override the gate entrypoint with the embedded custody runtime")
    if services_mounting_source(model, bind_mount_fixtures["SERVERWARE_RESPONSE_SIGNING_PRIVATE_KEY_FILE"]) != {"serverware"}:
        raise AssertionError("production control-plane response-signing private key must not be mounted by gate or custody")
    gate_ca_mounts = [
        mount
        for mount in gate.get("volumes") or []
        if mount.get("target") == "/run/serverware/tls/ca.pem"
    ]
    if (
        len(gate_ca_mounts) != 1
        or gate_ca_mounts[0].get("source")
        != bind_mount_fixtures["SERVERWARE_CONTROL_PLANE_TLS_DIR"] + "/ca.pem"
        or gate_ca_mounts[0].get("read_only") is not True
    ):
        raise AssertionError(
            "production decision gate must mount only the control-plane CA file"
        )
    if services_mounting_source(model, "serverware-custody-state") != {"custody-runtime"}:
        raise AssertionError("production custody state volume must be mounted only by custody")
    if services_mounting_source(model, "serverware-custody-trust") != {"serverware", "custody-runtime"}:
        raise AssertionError("production custody trust volume must be shared only by control plane and custody")
    if services_mounting_source(model, "serverware-custody-socket") != {"custody-runtime", "decision-gate-rs"}:
        raise AssertionError("production custody socket volume must be shared only by custody and decision gate")
    custody_env = custody.get("environment") or {}
    if custody_env.get("SERVERWARE_CUSTODY_EXPECTED_CLIENT_UID") != "65532":
        raise AssertionError("production custody must authenticate the explicit decision-gate UID")
    if (
        custody_env.get("SERVERWARE_CUSTODY_ATTEMPT_LEDGER_DIRECTORY")
        != "/var/lib/serverware-custody"
    ):
        raise AssertionError("production custody must use its private persistent attempt ledger")
    gate_environment = gate.get("environment") or {}
    if (
        gate_environment.get("SERVERWARE_RESPONSE_PROOF_CUSTODY_SOCKET")
        != "/run/serverware-custody/custody.sock"
        or gate_environment.get("SERVERWARE_RESPONSE_PROOF_CUSTODY_EXPECTED_UID") != "65531"
    ):
        raise AssertionError("production decision gate must pin the custody socket and distinct custody UID")
    gate_dockerfile = (ROOT / "data-plane" / "decision-gate-rs" / "Dockerfile.production").read_text(encoding="utf-8")
    if "serverware-custody-runtime /usr/local/bin/serverware-custody-runtime" not in gate_dockerfile:
        raise AssertionError("production decision-gate image must contain the custody runtime binary")
    ports = model["services"]["serverware"].get("ports") or []
    control_ports = [binding for binding in ports if int(binding["target"]) == 3000]
    if len(control_ports) != 1 or control_ports[0].get("host_ip") != "127.0.0.1" or str(control_ports[0].get("published")) != "3000":
        raise AssertionError(f"production control plane must be loopback-bound behind the deployment ingress: {control_ports}")
    if gate.get("ports") or gate.get("networks") or gate.get("network_mode") != "service:serverware":
        raise AssertionError("production gate must share the control-plane namespace without separate publication")
    if any(int(binding["target"]) == 9091 for binding in ports):
        raise AssertionError("production must not publish the decision-gate management listener")
    proxy_ports = [binding for binding in ports if int(binding["target"]) == 9090]
    if len(ports) != 2 or len(proxy_ports) != 1 or str(proxy_ports[0].get("published")) != "8080" or proxy_ports[0].get("host_ip") != compose_env["SERVERWARE_PROXY_BIND_ADDRESS"]:
        raise AssertionError(f"production must publish only container proxy port 9090 as host port 8080: {ports}")
    gate_mounts = model["services"]["decision-gate-rs"].get("volumes") or []
    gate_targets = {str(mount.get("target")) for mount in gate_mounts}
    if "/data" in gate_targets or "/run/serverware/gate" not in gate_targets:
        raise AssertionError(f"production decision gate has an unsafe private-state mount: {gate_mounts}")
    for name in (
        "SERVERWARE_ATTESTATION_EXECUTABLE_SHA256_MANIFEST",
        "SERVERWARE_POLICY_HIGH_WATER_FILE",
        "SERVERWARE_POLICY_MIN_SEQUENCE",
        "SERVERWARE_POLICY_MIN_ROLLBACK_EPOCH",
        "SERVERWARE_DECISION_GATE_PROXY_WORKERS",
    ):
        if not str(gate_environment.get(name) or "").strip():
            raise AssertionError(f"production decision gate is missing {name}")
    if int(gate_environment["SERVERWARE_DECISION_GATE_PROXY_WORKERS"]) > 24:
        raise AssertionError("production decision-gate worker count exceeds the 512 MiB memory safety bound")


def assert_development_image_identity_validation() -> None:
    shared_image_id = "sha256:" + "1" * 64
    other_image_id = "sha256:" + "2" * 64
    images = {
        service: {"image_id": shared_image_id}
        for service in generate_release_provenance.CUSTODY_DEV_SERVICES
    }
    containers = {
        service: {"image": shared_image_id}
        for service in generate_release_provenance.CUSTODY_DEV_SERVICES
    }
    generate_release_provenance.verify_development_image_identity(
        generate_release_provenance.CUSTODY_DEV_SERVICES,
        images,
        containers,
    )

    mutations = (
        (
            "missing v2 activation image",
            lambda candidate_images, _candidate_containers: candidate_images.pop(
                "response-v2-generation-activation"
            ),
        ),
        (
            "different v2 transport container image",
            lambda _candidate_images, candidate_containers: candidate_containers[
                "response-v2-credential-transport"
            ].__setitem__("image", other_image_id),
        ),
        (
            "unequal image inventory IDs",
            lambda candidate_images, _candidate_containers: candidate_images[
                "decision-gate-rs"
            ].__setitem__("image_id", other_image_id),
        ),
        (
            "unequal running container image IDs",
            lambda _candidate_images, candidate_containers: candidate_containers[
                "decision-gate-rs"
            ].__setitem__("image", other_image_id),
        ),
        (
            "running image IDs that differ from inventory",
            lambda _candidate_images, candidate_containers: [
                candidate_containers[service].__setitem__("image", other_image_id)
                for service in ("custody-runtime", "decision-gate-rs")
            ],
        ),
    )
    for description, mutate in mutations:
        candidate_images = copy.deepcopy(images)
        candidate_containers = copy.deepcopy(containers)
        mutate(candidate_images, candidate_containers)
        try:
            generate_release_provenance.verify_development_image_identity(
                generate_release_provenance.CUSTODY_DEV_SERVICES,
                candidate_images,
                candidate_containers,
            )
        except ValueError:
            pass
        else:
            raise AssertionError(f"development provenance accepted {description}")


def assert_production_schema_build_stages(dockerfile: str) -> None:
    """Source regression contract, not a general Dockerfile/shell validator."""
    stages: dict[str, list[str]] = {}
    origins: dict[str, str] = {}
    current: list[str] = []
    for raw in dockerfile.splitlines():
        line = raw.strip()
        if line.upper().startswith("FROM "):
            alias = re.search(r"\sAS\s+([a-zA-Z0-9_-]+)$", line, re.IGNORECASE)
            current = []
            if alias is not None:
                name = alias.group(1)
                if name in stages:
                    raise AssertionError(f"duplicate production build stage: {name}")
                stages[name] = current
                origins[name] = line
        elif line and not line.startswith("#"):
            current.append(line.removesuffix("\\").rstrip().removesuffix(";").rstrip())

    if origins.get("source-preparation") != (
        "FROM rust:1.88-slim-bookworm@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89 AS source-preparation"
    ) or origins.get("build") != "FROM source-preparation AS build":
        raise AssertionError("build must inherit the fixed pinned verified source-preparation stage")
    for name in ("build", "launcher-build"):
        if name not in stages:
            raise AssertionError(f"missing production schema build stage: {name}")
        lines = stages["source-preparation"] + stages[name] if name == "build" else stages[name]
        copies = [index for index, line in enumerate(lines)
                  if line == "cp -R /source/schemas /schemas"]
        builds = [index for index, line in enumerate(lines)
                  if line == "RUN --network=none /usr/local/bin/serverware-cargo-build --release --frozen"]
        if len(copies) != 1 or len(builds) != 1 or copies[0] >= builds[0]:
            raise AssertionError(f"{name} must copy verified schemas before its offline Rust build")
        if name == "build":
            prerequisites = (
                "tar --no-same-owner -xf /source-contract/source.tar -C /source",
                "sha256sum -c /source-contract/source.files.sha256",
                "done < /source-contract/source.files.mode",
            )
        else:
            prerequisites = ("COPY --from=source-preparation /source /source",)
        positions = []
        for requirement in prerequisites:
            if lines.count(requirement) != 1:
                raise AssertionError(f"{name} must retain verified-source prerequisite: {requirement}")
            positions.append(lines.index(requirement))
        if positions != sorted(positions) or positions[-1] >= copies[0]:
            raise AssertionError(f"{name} must verify source before copying embedded schemas")


def assert_reproducible_rust_binary_config() -> None:
    development = (ROOT / "data-plane/decision-gate-rs/Dockerfile").read_text(encoding="utf-8")
    if "COPY schemas /schemas" not in development:
        raise AssertionError("development Rust image must package its embedded schemas")
    production = (ROOT / "data-plane/decision-gate-rs/Dockerfile.production").read_text(encoding="utf-8")
    assert_production_schema_build_stages(production)
    # Mutate each stage independently: a valid copy in another stage cannot
    # compensate for missing, redirected, unverified or late source here.
    sections = re.split(r"(?=^FROM )", production, flags=re.MULTILINE)
    for stage in ("build", "launcher-build"):
        source_stage = "source-preparation" if stage == "build" else stage
        index = next(index for index, section in enumerate(sections)
                     if re.search(rf" AS {re.escape(source_stage)}$", section.splitlines()[0] if section else ""))
        end = index + (2 if stage == "build" else 1)
        if stage == "build" and sections[index + 1].splitlines()[0] != "FROM source-preparation AS build":
            raise AssertionError("build must directly inherit source-preparation")
        original = "".join(sections[index:end])
        copy_line = next(line for line in original.splitlines(keepends=True)
                         if line.strip().startswith("cp -R /source/schemas /schemas"))
        changed_cases = {
            "missing copy": original.replace(copy_line, ""),
            "unverified source": original.replace("cp -R /source/schemas /schemas", "cp -R /unverified/schemas /schemas"),
            "wrong destination": original.replace("cp -R /source/schemas /schemas", "cp -R /source/schemas /wrong-schemas"),
            "late copy": original.replace(copy_line, "") + "\n" + copy_line,
        }
        prerequisite = (
            "sha256sum -c /source-contract/source.files.sha256"
            if stage == "build" else "COPY --from=source-preparation /source /source"
        )
        changed_cases["missing source verification"] = original.replace(prerequisite, "# omitted prerequisite")
        for label, section in changed_cases.items():
            candidate = list(sections)
            candidate[index:end] = [section]
            try:
                assert_production_schema_build_stages("".join(candidate))
            except AssertionError as exc:
                if stage not in str(exc):
                    raise AssertionError(f"{stage} {label} reached wrong stage guard: {exc}") from exc
            else:
                raise AssertionError(f"production accepted {stage} {label}")
    cargo = (ROOT / "data-plane" / "decision-gate-rs" / "Cargo.toml").read_text(encoding="utf-8")
    if "[profile.release]" not in cargo or 'strip = "symbols"' not in cargo:
        raise AssertionError("Rust release binaries must strip nondeterministic symbol tables")


def assert_deterministic_development_ledger_seed(dockerfile: str) -> None:
    expected_payload = {
        "apiVersion": "serverware.custodyAttemptLedger/v2",
        "commitSequence": 0,
        "activeBindingCount": 0,
        "activeBindingsAccumulator": "A" * 43,
        "prunedThroughEpochMs": 0,
        "maxObservedEpochMs": 0,
    }
    payloads = re.findall(r"^\s*ledger_payload='([^']+)';", dockerfile, re.MULTILINE)
    if len(payloads) != 1:
        raise AssertionError("development image must define one literal empty ledger payload")
    expected_bytes = json.dumps(expected_payload, sort_keys=True, separators=(",", ":"))
    if payloads[0] != expected_bytes:
        raise AssertionError("development ledger seed must be the canonical empty v2 manifest payload")
    required = (
        "ledger_directory=/runtime-layout/serverware-custody-state;",
        'install -d -m 0700 "$ledger_directory";',
        'ledger_checksum="$(printf \'%s\' "$ledger_payload" | sha256sum)";',
        'ledger_checksum="${ledger_checksum%% *}";',
        'test "${#ledger_checksum}" -eq 64;',
        "*[!0-9a-f]*)",
        'printf \'{"checksum":"sha256:%s","payload":%s}\'',
        '"$ledger_checksum" "$ledger_payload" > "$ledger_directory/manifest.json";',
        'chmod 0600 "$ledger_directory/manifest.json";',
        'install -m 0600 /dev/null "$ledger_directory/ledger.lock";',
        'test "$(wc -c < "$ledger_directory/ledger.lock")" -eq 0;',
        'test "$(wc -c < "$ledger_directory/manifest.json")" -le 1024;',
    )
    missing = [value for value in required if value not in dockerfile]
    if missing:
        raise AssertionError(f"development ledger seed lost checksum, permissions, or empty-lock checks: {missing}")
    envelope = json.dumps(
        {"checksum": "sha256:" + hashlib.sha256(expected_bytes.encode("ascii")).hexdigest(), "payload": expected_payload},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    if len(envelope) > 1024:
        raise AssertionError("canonical empty ledger envelope exceeds the image seed bound")


def assert_custody_ledger_image_seed() -> None:
    # Production still runs the Rust initializer; development constructs its
    # canonical empty state without executing a freshly built runtime at build
    # time. Both paths must retain the same private runtime volume contract.
    for relative, ownership in (
        ("data-plane/decision-gate-rs/Dockerfile", "10002:10003"),
        ("data-plane/decision-gate-rs/Dockerfile.production", "65531:65530"),
    ):
        dockerfile = (ROOT / relative).read_text(encoding="utf-8")
        required = (
            f"COPY --from=build --chown={ownership} --chmod=0700 /runtime-layout/serverware-custody-state /var/lib/serverware-custody",
            f"COPY --from=build --chown={ownership} --chmod=0600 /runtime-layout/serverware-custody-state/manifest.json /var/lib/serverware-custody/manifest.json",
            f"COPY --from=build --chown={ownership} --chmod=0600 /runtime-layout/serverware-custody-state/ledger.lock /var/lib/serverware-custody/ledger.lock",
        )
        if relative.endswith("Dockerfile.production"):
            required += (
                "SERVERWARE_CUSTODY_ATTEMPT_LEDGER_DIRECTORY=/runtime-layout/serverware-custody-state",
                "/src/target/release/serverware-custody-runtime --initialize-attempt-ledger",
            )
        else:
            assert_deterministic_development_ledger_seed(dockerfile)
            for old, replacement in (
                ('"activeBindingCount":0', '"activeBindingCount":1'),
                ('"commitSequence":0', '"commitSequence":1'),
                ('"maxObservedEpochMs":0', '"maxObservedEpochMs":1'),
                ('"prunedThroughEpochMs":0', '"prunedThroughEpochMs":1'),
                ("A" * 43, "B" + "A" * 42),
                ("custodyAttemptLedger/v2", "custodyAttemptLedger/v1"),
                ("| sha256sum", "| sha512sum"),
                ('chmod 0600 "$ledger_directory/manifest.json"', 'chmod 0644 "$ledger_directory/manifest.json"'),
                ("install -m 0600 /dev/null", "install -m 0644 /dev/null"),
            ):
                changed = dockerfile.replace(old, replacement, 1)
                try:
                    assert_deterministic_development_ledger_seed(changed)
                except AssertionError:
                    pass
                else:
                    raise AssertionError(f"ledger seed regression checker accepted changed {old!r}")
        missing = [value for value in required if value not in dockerfile]
        if missing:
            raise AssertionError(
                f"{relative} does not seed a fresh custody ledger in the image: {missing}"
            )


def assert_gate_response_context_publish_wait() -> None:
    expected = "sha256:" + "a" * 64
    with mock.patch.object(
        generate_release_provenance,
        "request_json",
        side_effect=[
            {"attested_response_context": {"provenance_digest": None}},
            {"attested_response_context": {"provenance_digest": expected}},
        ],
    ), mock.patch.object(generate_release_provenance.time, "sleep"):
        observed = generate_release_provenance.wait_for_gate_response_context(
            "http://gate.test:9091",
            "provenance_digest",
            expected,
        )
    if (observed.get("attested_response_context") or {}).get("provenance_digest") != expected:
        raise AssertionError("release publisher returned before the gate adopted its response context")
    for relative in (
        "data-plane/decision-gate-rs/Dockerfile",
        "data-plane/decision-gate-rs/Dockerfile.production",
    ):
        dockerfile = (ROOT / relative).read_text(encoding="utf-8")
        if "--build-id=none" not in dockerfile:
            raise AssertionError(f"{relative} must omit nondeterministic GNU linker build IDs")
        lock_mode = "--frozen" if relative.endswith("Dockerfile.production") else "--locked"
        command = "/usr/local/bin/serverware-cargo-build" if relative.endswith("Dockerfile.production") else "cargo build"
        if f"{command} --release {lock_mode}" not in dockerfile:
            raise AssertionError(f"{relative} must build the lockfile-pinned Rust release")


def assert_static_launcher_artifact_embedded() -> None:
    path = ROOT / "data-plane" / "decision-gate-rs" / "Dockerfile.production"
    dockerfile = path.read_text(encoding="utf-8")
    required = (
        "FROM rust:1.88-alpine3.22@sha256:64eba3726734dcfe89e0a62a0485007a3ab7c7372ce5b38c621d8812f70215f0 AS launcher-build",
        "COPY production-dependencies/cache/musl-1.2.5-r12.apk",
        "RUN --network=none /usr/local/bin/serverware-cargo-build --release --frozen \\\n        --bin serverware-production-launcher",
        "FROM scratch AS production-launcher-artifact",
        "COPY --from=launcher-build /src/target/release/serverware-production-launcher /serverware-production-launcher",
        "COPY --from=launcher-build /src/target/release/serverware-production-launcher /usr/local/libexec/serverware-production-launcher",
    )
    missing = [line for line in required if line not in dockerfile]
    if missing:
        raise AssertionError(f"production decision-gate image does not preserve the static launcher artifact contract: {missing}")


def assert_launcher_digest_measurement_contract() -> None:
    gate_digest = sha256_prefixed(b"decision-gate")
    launcher_digest = sha256_prefixed(b"static-launcher")
    with mock.patch.object(
        build_production_images,
        "image_file_sha256",
        side_effect=[gate_digest, launcher_digest],
    ) as measured:
        digests = build_production_images.decision_gate_binary_digests("sha256:" + "a" * 64)
    if digests != {
        "binary_digest": gate_digest,
        "launcher_binary_digest": launcher_digest,
    }:
        raise AssertionError(f"production image build did not declare both decision-gate binary digests: {digests}")
    expected_calls = [
        mock.call("sha256:" + "a" * 64, "/usr/local/bin/serverware-decision-gate"),
        mock.call("sha256:" + "a" * 64, "/usr/local/libexec/serverware-production-launcher"),
    ]
    if measured.call_args_list != expected_calls:
        raise AssertionError(f"production image build measured the wrong binary paths: {measured.call_args_list}")


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def independent_lock_inventory(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    pattern = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s\\]+)\s+\\$")
    for raw in path.read_text(encoding="utf-8").splitlines():
        match = pattern.fullmatch(raw)
        if match is None:
            continue
        name = re.sub(r"[-_.]+", "-", match.group(1)).lower()
        if name in entries:
            raise AssertionError(f"test fixture has duplicate locked package {name}")
        entries[name] = match.group(2)
    if not entries:
        raise AssertionError("test fixture has no locked packages")
    return entries


def expect_lock_failure(content: str, expected: str, *, forbidden: str | None = None) -> None:
    with tempfile.TemporaryDirectory(prefix="serverware-lock-test-") as raw_tmp:
        path = Path(raw_tmp) / "requirements.lock"
        path.write_text(content, encoding="utf-8")
        try:
            generate_release_provenance.python_dependency_inventory(production=True, path=path)
        except ValueError as exc:
            message = str(exc)
            if expected not in message:
                raise AssertionError(f"lock failure did not mention {expected!r}: {message}") from exc
            if forbidden and forbidden in message:
                raise AssertionError("lock parser exposed rejected requirement contents") from exc
        else:
            raise AssertionError(f"malformed lock unexpectedly passed: {expected}")


def assert_release_python_dependency_inventory() -> None:
    lock_path = ROOT / "requirements.lock"
    lock_bytes = lock_path.read_bytes()
    expected = independent_lock_inventory(lock_path)
    expected_hash_count = sum(
        1 for raw in lock_path.read_text(encoding="utf-8").splitlines() if raw.strip().startswith("--hash=")
    )
    production_items, manifest = generate_release_provenance.python_dependency_inventory(production=True)
    actual = {item["name"]: item["version"] for item in production_items}
    if actual != expected:
        raise AssertionError(f"production provenance does not inventory the complete lock: {actual} != {expected}")
    if manifest != {
        "format": "pip-requirements-lock/v1",
        "mode": "transitive-production-lock",
        "path": "requirements.lock",
        "sha256": sha256_prefixed(lock_bytes),
        "require_hashes": True,
        "packages": len(expected),
        "hashes": expected_hash_count,
    }:
        raise AssertionError(f"production dependency manifest binding is incomplete: {manifest}")
    for item in production_items:
        hashes = item.get("hashes")
        if not hashes or len(hashes) != item.get("hash_count"):
            raise AssertionError(f"locked package has incomplete hash inventory: {item['name']}")
        if len(hashes) != len(set(hashes)) or any(re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None for value in hashes):
            raise AssertionError(f"locked package has invalid hashes: {item['name']}")
        if item.get("hashes_sha256") != generate_release_provenance.sha256_prefixed_json(sorted(hashes)):
            raise AssertionError(f"locked package hash-set binding is wrong: {item['name']}")

    development_items, development_manifest = generate_release_provenance.python_dependency_inventory(production=False)
    expected_development = generate_release_provenance.development_python_sbom(ROOT / "requirements.txt")
    if development_items != expected_development:
        raise AssertionError("development provenance no longer preserves the direct requirements.txt inventory")
    if development_manifest["path"] != "requirements.txt" or development_manifest["require_hashes"] is not False:
        raise AssertionError(f"development dependency mode changed unexpectedly: {development_manifest}")
    if len(production_items) <= len(development_items):
        raise AssertionError("production provenance did not expand direct dependencies to the transitive lock set")

    with tempfile.TemporaryDirectory(prefix="serverware-lock-digest-test-") as raw_tmp:
        mutated_path = Path(raw_tmp) / "requirements.lock"
        mutated_path.write_bytes(lock_bytes + b"# digest-binding probe\n")
        mutated_items, mutated_manifest = generate_release_provenance.python_dependency_inventory(
            production=True,
            path=mutated_path,
        )
        if mutated_items != production_items:
            raise AssertionError("comment-only lock mutation unexpectedly changed the package inventory")
        if mutated_manifest["sha256"] == manifest["sha256"]:
            raise AssertionError("production dependency manifest digest did not bind all lockfile bytes")

    cyclonedx = generate_release_provenance.cyclonedx_sbom(
        production_items,
        [],
        created_at="2026-01-01T00:00:00+00:00",
        source_digest="sha256:" + "1" * 64,
        python_manifest=manifest,
    )
    properties = {item["name"]: item["value"] for item in cyclonedx["metadata"]["properties"]}
    if properties.get("serverware:pythonDependencyManifestSha256") != manifest["sha256"]:
        raise AssertionError("CycloneDX metadata does not bind requirements.lock")
    if properties.get("serverware:pythonDependencyManifestRequiresHashes") != "true":
        raise AssertionError("CycloneDX metadata does not require lock hashes")
    components = {
        component["name"]: component["version"]
        for component in cyclonedx["components"]
        if component["purl"].startswith("pkg:pypi/")
    }
    if components != expected:
        raise AssertionError(f"CycloneDX does not inventory the complete lock: {components} != {expected}")
    bom_refs = [component["bom-ref"] for component in cyclonedx["components"]]
    if len(bom_refs) != len(set(bom_refs)):
        raise AssertionError("CycloneDX contains duplicate component references")
    for component in cyclonedx["components"]:
        component_properties = {item["name"]: item["value"] for item in component["properties"]}
        if "serverware:pipArtifactHashesSha256" not in component_properties:
            raise AssertionError(f"CycloneDX component does not bind its lock hashes: {component['name']}")


def assert_malformed_python_locks_fail_closed() -> None:
    h1 = "sha256:" + "1" * 64
    h2 = "sha256:" + "2" * 64
    expect_lock_failure("alpha==1.0\n", "unsupported requirement")
    expect_lock_failure(f"alpha==1.0 \\\n    --hash={h1} \\\n\n", "interrupted entry")
    expect_lock_failure(
        f"alpha==1.0 \\\n    --hash={h1}\nalpha==2.0 \\\n    --hash={h2}\n",
        "duplicate package",
    )
    expect_lock_failure(
        f"alpha_beta==1.0 \\\n    --hash={h1}\nalpha-beta==1.0 \\\n    --hash={h2}\n",
        "duplicate package",
    )
    expect_lock_failure(
        f"alpha==1.0 \\\n    --hash={h1} \\\n    --hash={h1}\n",
        "duplicate hash",
    )
    expect_lock_failure("alpha==1.0 \\\n    --hash=sha256:ABCDEF\n", "invalid hash")
    expect_lock_failure("--index-url=https://user:super-secret@example.invalid/simple\n", "unsupported requirement", forbidden="super-secret")
    expect_lock_failure("alpha @ https://user:super-secret@example.invalid/alpha.whl\n", "unsupported requirement", forbidden="super-secret")
    expect_lock_failure(f"alpha==1.0; python_version > '3.10' \\\n    --hash={h1}\n", "unsupported requirement")
    expect_lock_failure(f"alpha==1.0 \\\n    --hash={h1} \\\n", "unterminated")


def run_dry_build() -> dict:
    result = subprocess.run(
        [sys.executable, "scripts/build_production_images.py", "--dry-run"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    detail = result.stderr.decode("utf-8", errors="replace") + result.stdout.decode("utf-8", errors="replace")
    if result.returncode != 0:
        raise AssertionError(f"production image build dry-run failed: {detail}")
    return json.loads(result.stdout.decode("utf-8"))


def assert_source_tree_digest_covers_untracked_source() -> None:
    probes = {
        ROOT / "scripts" / "__source_digest_probe__.py": b"# source digest coverage probe\nVALUE = 1\n",
        ROOT / "data-plane" / "decision-gate-rs" / "src" / "__source_digest_probe__.rs": b"const VALUE: u8 = 1;\n",
        ROOT / "docs" / "images" / "__source_digest_probe__.png": b"not-a-real-png-source-digest-probe",
    }
    for probe, content in probes.items():
        if probe.exists():
            raise AssertionError(f"unexpected source digest probe already exists: {probe}")
        before = build_production_images.source_tree_digest(
            development_dirty_tree=True
        )
        try:
            probe.parent.mkdir(parents=True, exist_ok=True)
            probe.write_bytes(content)
            after = build_production_images.source_tree_digest(
                development_dirty_tree=True
            )
            try:
                build_production_images.source_tree_digest()
            except ValueError as exc:
                if "clean index and worktree" not in str(exc):
                    raise AssertionError(
                        f"dirty production source failed for the wrong reason: {exc}"
                    ) from exc
            else:
                raise AssertionError(
                    f"production source accepted untracked build input: {probe}"
                )
        finally:
            probe.unlink(missing_ok=True)
        if before == after:
            raise AssertionError(f"source_tree_digest did not change for an untracked {probe.suffix} file")


SOURCE_CONTRACT_INPUTS = (
    ("ARCHIVE", "source.tar", "source_archive"),
    ("MANIFEST", "source-manifest.json", "source_manifest"),
    ("FILE_LIST", "source.files", "source_file_list"),
    ("FILE_HASHES", "source.files.sha256", "source_file_hashes"),
    ("FILE_MODES", "source.files.mode", "source_file_modes"),
)
PYTHON_CACHE_INPUT = "production-dependencies/cache/python-wheelhouse-linux-amd64.tar.gz"
RUST_CACHE_INPUTS = (
    "production-dependencies/cache/cargo-vendor.tar.gz",
    "production-dependencies/cache/musl-1.2.5-r12.apk",
    "production-dependencies/cache/musl-dev-1.2.5-r12.apk",
)
COMMITTED_COPY_INPUTS = (
    "requirements.lock", "production-dependencies/python-linux-amd64.sha256",
)


def production_copy_stages(dockerfile: str) -> tuple[dict[str, list[str]], list[tuple[str, str, str]]]:
    """Closed source regression grammar; unsupported COPY forms fail explicitly."""
    stages: dict[str, list[str]] = {}
    local: list[tuple[str, str, str]] = []
    stage = ""
    continued = False
    for raw in dockerfile.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        opcode = fields[0].upper()
        instruction = not continued
        continued = line.endswith("\\")
        if instruction and opcode == "FROM":
            if len(fields) == 4 and fields[2].upper() == "AS":
                stage = fields[3]
            elif len(fields) == 2:
                stage = f"unnamed-stage-{len(stages)}"
            else:
                raise AssertionError(f"unsupported production FROM: {line}")
            if stage in stages:
                raise AssertionError(f"duplicate production stage: {stage}")
            stages[stage] = [line]
            continue
        if not stage:
            raise AssertionError("production instruction precedes FROM")
        stages[stage].append(line.removesuffix("\\").rstrip().removesuffix(";").rstrip())
        if instruction and opcode == "ADD":
            raise AssertionError("production input classification does not permit ADD")
        if not instruction or opcode != "COPY":
            continue
        options = []
        while len(fields) > 1 and fields[1].startswith("--"):
            options.append(fields.pop(1))
        if len(fields) != 3 or any(token.startswith("[") for token in fields):
            raise AssertionError(f"unsupported production COPY: {line}")
        from_options = [option for option in options if option.startswith("--from=")]
        if from_options:
            origin = from_options[0].removeprefix("--from=")
            if len(from_options) != 1 or origin == stage or origin not in stages:
                raise AssertionError(f"COPY must use an earlier declared stage: {line}")
            if any(not option.startswith(("--from=", "--chown=", "--chmod=")) for option in options):
                raise AssertionError(f"unsupported production COPY option: {line}")
        else:
            if options:
                raise AssertionError(f"unsupported local production COPY option: {line}")
            local.append((stage, fields[1], fields[2]))
    return stages, local


def require_stage_order(stages: dict[str, list[str]], stage: str, markers: tuple[str, ...]) -> None:
    lines = stages.get(stage, [])
    positions = []
    for marker in markers:
        if lines.count(marker) != 1:
            raise AssertionError(f"{stage} must retain exactly one input guard: {marker}")
        positions.append(lines.index(marker))
    if positions != sorted(positions) or len(positions) != len(set(positions)):
        raise AssertionError(f"{stage} input guards must precede consumption in order")


def assert_production_copy_classification(dockerfile: str, *, family: str) -> None:
    stages, actual = production_copy_stages(dockerfile)
    if family not in {"python", "rust"}:
        raise AssertionError("unknown production Dockerfile family")
    cache_stage = f"{family}-production-dependency-cache"
    source_stage = "verified-production-source" if family == "python" else "source-preparation"
    cache_inputs = (PYTHON_CACHE_INPUT,) if family == "python" else RUST_CACHE_INPUTS
    committed_inputs = COMMITTED_COPY_INPUTS if family == "python" else ()
    expected = [
        (cache_stage, source, f"/dependency-cache/{Path(source).name}")
        for source in committed_inputs
    ] + [
        (cache_stage, source, f"/dependency-cache/cache/{Path(source).name}")
        for source in cache_inputs
    ] + [
        (source_stage, "${SERVERWARE_SOURCE_" + suffix + "}", f"/source-contract/{destination}")
        for suffix, destination, _ in SOURCE_CONTRACT_INPUTS
    ]
    if actual != expected:
        raise AssertionError(f"{family} root COPY inventory differs from the closed source/dependency/contract inputs")
    if stages[cache_stage][0] != f"FROM scratch AS {cache_stage}":
        raise AssertionError(f"{cache_stage} must contain only explicitly copied inputs")

    extraction = "tar --no-same-owner -xf /source-contract/source.tar -C /source"
    for suffix, destination, _ in SOURCE_CONTRACT_INPUTS:
        variable = "SERVERWARE_SOURCE_" + suffix
        digest_check = (
            "printf '%s  %s\\n' \"${" + variable + "_SHA256#sha256:}\" "
            + f"/source-contract/{destination} | sha256sum -c -"
        )
        require_stage_order(stages, source_stage, (
            f"ARG {variable}", f"ARG {variable}_SHA256",
            "COPY ${" + variable + "} /source-contract/" + destination,
            "RUN --network=none set -eu", f'test -n "${{{variable}_SHA256}}"',
            digest_check, "tar -tf /source-contract/source.tar > /source-contract/archive.files",
        ))
    require_stage_order(stages, source_stage, (
        "tar -tf /source-contract/source.tar > /source-contract/archive.files",
        "printf '%s  %s\\n' \"${SERVERWARE_SOURCE_FILE_LIST_SHA256#sha256:}\" /source-contract/archive.files | sha256sum -c -",
        extraction,
        "sha256sum -c /source-contract/source.files.sha256",
        'test -n "${expected_mode}"', 'test -n "${relative}"',
        'test -f "/source/${relative}"', 'test ! -L "/source/${relative}"',
        'test "$(stat -c \'%a\' "/source/${relative}")" = "${expected_mode}"',
        "done < /source-contract/source.files.mode",
    ))
    if family == "python":
        require_stage_order(stages, "python-deps", (
            "COPY --from=python-production-dependency-cache /dependency-cache /dependency-cache",
            "RUN --network=none set -eu", "cd /dependency-cache",
            'test "$(grep -Ec \'^[0-9a-f]{64}  \' python-linux-amd64.sha256)" -eq 2',
            "grep -E '^[0-9a-f]{64}  ' python-linux-amd64.sha256 | sha256sum -c -",
            "tar -xzf cache/python-wheelhouse-linux-amd64.tar.gz",
            "python -m pip install", "--no-index", "--only-binary=:all:",
            "--find-links=/dependency-cache/wheelhouse", "--require-hashes",
            "-r /dependency-cache/requirements.lock",
        ))
    else:
        require_stage_order(stages, "source-preparation", (
            "FROM rust:1.88-slim-bookworm@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89 AS source-preparation",
            "COPY --from=rust-production-dependency-cache /dependency-cache /dependency-cache",
            "done < /source-contract/source.files.mode",
            "cp /source/data-plane/decision-gate-rs/Cargo.toml /dependency-cache/data-plane/decision-gate-rs/Cargo.toml",
            "cp /source/data-plane/decision-gate-rs/Cargo.lock /dependency-cache/data-plane/decision-gate-rs/Cargo.lock",
            "cp /source/production-dependencies/rust-linux-amd64.sha256 /dependency-cache/rust-linux-amd64.sha256",
            "cd /dependency-cache", "sha256sum -c rust-linux-amd64.sha256",
            "tar -xzf cache/cargo-vendor.tar.gz -C /src",
        ))
        require_stage_order(stages, "build", (
            "FROM source-preparation AS build",
            "RUN --network=none rustc --edition=2021 /source/scripts/cargo_build_diagnostics.rs -o /usr/local/bin/serverware-cargo-build",
            "RUN --network=none /usr/local/bin/serverware-cargo-build --release --frozen",
        ))
        require_stage_order(stages, "launcher-build", (
            "COPY --from=source-preparation /source /source",
            "COPY --from=source-preparation /dependency-cache /dependency-cache",
            "RUN --network=none set -eu", "cd /dependency-cache",
            'test "$(grep -Ec \'^[0-9a-f]{64}  \' rust-linux-amd64.sha256)" -eq 5',
            "grep -E '^[0-9a-f]{64}  ' rust-linux-amd64.sha256 | sha256sum -c -",
            "apk", "--no-network", "--repositories-file /dev/null", "add",
            "cache/musl-1.2.5-r12.apk", "cache/musl-dev-1.2.5-r12.apk",
            "tar -xzf cache/cargo-vendor.tar.gz -C /src",
            "RUN --network=none rustc --edition=2021 /source/scripts/cargo_build_diagnostics.rs -o /usr/local/bin/serverware-cargo-build",
            "RUN --network=none /usr/local/bin/serverware-cargo-build --release --frozen",
            "--bin serverware-production-launcher --bin serverware-native-response-verifier",
        ))


def assert_copy_input_manifests_and_arguments() -> None:
    # Parse the actual closed, committed inventories. This does not claim the
    # archives exist or match their pins; prefetch verify remains that gate.
    spec = importlib.util.spec_from_file_location(
        "copy_surface_dependency_manifest", ROOT / "production-dependencies/prefetch.py"
    )
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load the dependency manifest parser")
    prefetch = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(prefetch)
    entries = prefetch.expected_cache_entries(prefetch.manifests())
    expected_cache = {PYTHON_CACHE_INPUT, *RUST_CACHE_INPUTS}
    if {"production-dependencies/" + relative for relative in entries} != expected_cache:
        raise AssertionError("Docker cache COPY inputs differ from the four pinned artifacts")
    for source in (*COMMITTED_COPY_INPUTS, "production-dependencies/rust-linux-amd64.sha256"):
        if not serverware_source_tree.is_source_file(ROOT / source, ROOT):
            raise AssertionError(f"dependency authority input is not covered by source identity: {source}")
    tracked = subprocess.run(
        ["git", "ls-tree", "-rz", "--name-only", "HEAD", "--", *COMMITTED_COPY_INPUTS],
        cwd=ROOT, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ).stdout.decode("utf-8").split("\0")
    if set(tracked) - {""} != set(COMMITTED_COPY_INPUTS):
        raise AssertionError("literal Docker source inputs must be committed files")
    if set(build_production_images.PRIVATE_CONTEXT_FILES) != {
        "Dockerfile.production", "data-plane/decision-gate-rs/Dockerfile.production",
        *COMMITTED_COPY_INPUTS, *expected_cache,
    } or len(build_production_images.PRIVATE_CONTEXT_FILES) != 8:
        raise AssertionError("private Docker context expanded beyond the closed literal input inventory")

    # Independent sentinel values test the real pure build-argument wiring; they
    # are not a generated source contract or evidence about an actual archive.
    metadata = {
        "source": "fixture-source", "revision": "fixture-revision", "created": "fixture-time",
        "source_tree_digest": "sha256:" + "f" * 64,
        "source_identity_mode": "production-commit", "production_release_eligible": True,
        "source_date_epoch": "1",
    }
    expected_arguments = {}
    for index, (suffix, destination, key) in enumerate(SOURCE_CONTRACT_INPUTS, 1):
        metadata[key + "_path"] = "production-dependencies/cache/source-contract/" + destination
        metadata[key + "_digest"] = "sha256:" + str(index) * 64
        expected_arguments["SERVERWARE_SOURCE_" + suffix] = metadata[key + "_path"]
        expected_arguments["SERVERWARE_SOURCE_" + suffix + "_SHA256"] = metadata[key + "_digest"]
    arguments = build_production_images.source_build_arguments(metadata)
    if len(arguments) % 2 or any(flag != "--build-arg" for flag in arguments[::2]):
        raise AssertionError("source-contract argument transport changed")
    observed = [value.split("=", 1) for value in arguments[1::2]]
    if len({name for name, _ in observed}) != len(observed):
        raise AssertionError("source-contract arguments contain duplicate assignments")
    if {name: value for name, value in observed if name in expected_arguments} != expected_arguments:
        raise AssertionError("generated source-contract paths and digests are cross-wired")


def assert_source_tree_covers_production_copy_surface() -> None:
    dockerfiles = (
        ROOT / "Dockerfile.production",
        ROOT / "data-plane" / "decision-gate-rs" / "Dockerfile.production",
    )
    assert_copy_input_manifests_and_arguments()
    for dockerfile, family in zip(dockerfiles, ("python", "rust"), strict=True):
        source = dockerfile.read_text(encoding="utf-8")
        assert_production_copy_classification(source, family=family)
        first_copy = next(line for line in source.splitlines() if line.startswith("COPY "))
        cases = [
            ("extra cache input", source + "\nCOPY production-dependencies/cache/unpinned.tar /extra\n", "root COPY inventory"),
            ("unbound build argument", source + "\nCOPY ${UNBOUND_INPUT} /extra\n", "root COPY inventory"),
            ("wrong destination", source.replace(first_copy, first_copy + "-wrong", 1), "root COPY inventory"),
            ("wrong stage", source.replace(first_copy + "\n", "", 1) + "\n" + first_copy + "\n", "root COPY inventory"),
            ("wrong generated destination", source.replace("COPY ${SERVERWARE_SOURCE_ARCHIVE} /source-contract/source.tar", "COPY ${SERVERWARE_SOURCE_ARCHIVE} /unverified/source.tar", 1), "root COPY inventory"),
            ("external COPY stage", source + "\nCOPY --from=unverified-image /payload /extra\n", "earlier declared stage"),
            ("ADD input", source + "\nADD unclassified /extra\n", "does not permit ADD"),
        ]
        for suffix, destination, _ in SOURCE_CONTRACT_INPUTS:
            check = (
                "printf '%s  %s\\n' \"${SERVERWARE_SOURCE_" + suffix
                + "_SHA256#sha256:}\" /source-contract/" + destination + " | sha256sum -c -"
            )
            if source.count(check) != 1:
                raise AssertionError("generated-input mutation fixture lacks its exact checksum guard")
            cases.append((f"missing {suffix} digest", source.replace(check, ":", 1), "input guard"))
        digest_line = next(line for line in source.splitlines(keepends=True)
                           if '"${SERVERWARE_SOURCE_ARCHIVE_SHA256#sha256:}"' in line)
        extract_line = next(line for line in source.splitlines(keepends=True)
                            if "tar --no-same-owner -xf /source-contract/source.tar -C /source" in line)
        cases.append(("late archive digest", source.replace(digest_line, "", 1).replace(
            extract_line, extract_line + digest_line, 1), "precede consumption"))
        dependency_check = (
            "grep -E '^[0-9a-f]{64}  ' python-linux-amd64.sha256 | sha256sum -c -"
            if family == "python" else "sha256sum -c rust-linux-amd64.sha256"
        )
        cases.append(("missing dependency digest", source.replace(dependency_check, ":", 1), "input guard"))
        if family == "rust":
            launcher_check = "grep -E '^[0-9a-f]{64}  ' rust-linux-amd64.sha256 | sha256sum -c -"
            cases.append(("missing launcher dependency digest", source.replace(launcher_check, ":", 1), "input guard"))
            cases.append(("online APK installation", source.replace("        --no-network \\\n", "", 1), "input guard"))
        for label, candidate, expected_error in cases:
            try:
                assert_production_copy_classification(candidate, family=family)
            except AssertionError as exc:
                if expected_error not in str(exc):
                    raise AssertionError(f"{family} {label} reached the wrong input guard: {exc}") from exc
            else:
                raise AssertionError(f"{family} Docker input contract accepted {label}")

    with tempfile.TemporaryDirectory(prefix="serverware-source-copy-surface-") as checkout_raw:
        checkout = Path(checkout_raw)
        (checkout / "scripts").mkdir()
        (checkout / "policies").mkdir()
        (checkout / ".gitignore").write_text("scripts/ignored-build-input\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(checkout)], check=True)
        subprocess.run(["git", "-C", str(checkout), "add", ".gitignore"], check=True)

        baseline = serverware_source_tree.source_tree_digest(
            checkout,
            production=False,
        )
        ignored = checkout / "scripts" / "ignored-build-input"
        ignored.write_bytes(b"ignored opaque input\x00v1\n")
        ignored_check = subprocess.run(
            ["git", "-C", str(checkout), "check-ignore", "-q", "scripts/ignored-build-input"],
            check=False,
        )
        if ignored_check.returncode != 0:
            raise AssertionError("ignored source-tree adversarial fixture is not ignored by Git")
        ignored_digest = serverware_source_tree.source_tree_digest(
            checkout,
            production=False,
        )
        ignored_entry = next(
            (
                item
                for item in serverware_source_tree.source_tree_files(checkout)
                if item["path"] == "scripts/ignored-build-input"
            ),
            None,
        )
        if ignored_entry is None or ignored_digest == baseline:
            raise AssertionError("source-tree manifest omitted an ignored opaque file under a production COPY root")
        ignored.write_bytes(b"ignored opaque input\x00v2\n")
        if (
            serverware_source_tree.source_tree_digest(
                checkout,
                production=False,
            )
            == ignored_digest
        ):
            raise AssertionError("source-tree digest did not bind every byte of an ignored production COPY input")

        opaque_policy = checkout / "policies" / "emergency-policy"
        opaque_policy.write_bytes(b"opaque untracked policy\x00v1\n")
        untracked = subprocess.run(
            ["git", "-C", str(checkout), "ls-files", "--others", "--exclude-standard", "-z"],
            stdout=subprocess.PIPE,
            check=True,
        ).stdout.split(b"\0")
        if b"policies/emergency-policy" not in untracked:
            raise AssertionError("opaque policy adversarial fixture is not untracked")
        policy_digest = serverware_source_tree.source_tree_digest(
            checkout,
            production=False,
        )
        policy_entry = next(
            (
                item
                for item in serverware_source_tree.source_tree_files(checkout)
                if item["path"] == "policies/emergency-policy"
            ),
            None,
        )
        if policy_entry is None:
            raise AssertionError("source-tree manifest omitted an opaque untracked policy file")
        opaque_policy.write_bytes(b"opaque untracked policy\x00v2\n")
        if (
            serverware_source_tree.source_tree_digest(
                checkout,
                production=False,
            )
            == policy_digest
        ):
            raise AssertionError("source-tree digest did not bind every byte of an opaque untracked policy file")


def source_fixture_git(checkout: Path, *arguments: str) -> bytes:
    return subprocess.run(
        [
            str(serverware_source_tree.GIT_EXECUTABLE),
            "-C", str(checkout),
            "-c", "core.hooksPath=/dev/null",
            "-c", "commit.gpgsign=false",
            "-c", "user.name=Serverware Test",
            "-c", "user.email=serverware@example.invalid",
            *arguments,
        ],
        env=serverware_source_tree.GIT_ENVIRONMENT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    ).stdout


def assert_production_source_tree_manifest() -> None:
    with tempfile.TemporaryDirectory() as checkout_raw:
        checkout = Path(checkout_raw)
        expected = {
            ".gitignore": b".tmp/\n",
            ".buildrc": b"strict=true\n",
            "ops/production-readiness.env.example": b"MODE=production\n",
            "scripts/release-tool": b"#!/bin/sh\nexit 0\n",
            "tracked-build-input.opaque": b"tracked opaque build input\n",
        }
        for relative, content in expected.items():
            path = checkout / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        executable = checkout / "scripts" / "release-tool"
        executable.chmod(0o755)
        opaque = checkout / "tracked-build-input.opaque"
        source_fixture_git(checkout, "init", "--object-format=sha1", "-q")
        source_fixture_git(checkout, "add", "-A")
        source_fixture_git(checkout, "commit", "-q", "-m", "production source fixture")
        output = checkout / ".tmp" / "source-contract"

        first = serverware_source_tree.production_source_contract(checkout, output)
        archive_bytes = (checkout / first["archivePath"]).read_bytes()
        second = serverware_source_tree.production_source_contract(checkout, output)
        if first != second:
            raise AssertionError("production source contract is not deterministic at the same clean commit")
        if (checkout / second["archivePath"]).read_bytes() != archive_bytes:
            raise AssertionError("production source archive bytes are not deterministic")
        manifest = first["sourceTreeManifest"]
        if (
            manifest["version"] != "serverware.sourceTree/v3"
            or first["identityMode"] != "production-commit"
            or manifest["identityMode"] != first["identityMode"]
            or first["productionReleaseEligible"] is not True
            or manifest["productionReleaseEligible"] is not True
            or first["commit"] != source_fixture_git(checkout, "rev-parse", "HEAD").decode("ascii").strip()
            or first["gitTree"] != source_fixture_git(checkout, "rev-parse", "HEAD^{tree}").decode("ascii").strip()
            or manifest["commit"] != first["commit"]
            or manifest["gitTree"] != first["gitTree"]
        ):
            raise AssertionError("production source contract lost its exact v3 commit identity")
        entries = {item["path"]: item for item in manifest["files"]}
        if set(entries) != set(expected) or len(manifest["files"]) != len(expected):
            raise AssertionError(f"production manifest changed the exact tracked inventory: {sorted(entries)}")
        for relative, content in expected.items():
            entry = entries[relative]
            if (
                entry["type"] != "file"
                or entry["mode"] != ("100755" if relative == "scripts/release-tool" else "100644")
                or entry["bytes"] != len(content)
                or entry["sha256"] != "sha256:" + hashlib.sha256(content).hexdigest()
                or entry["gitBlob"] != source_fixture_git(checkout, "rev-parse", f"HEAD:{relative}").decode("ascii").strip()
            ):
                raise AssertionError(f"production manifest lost tracked bytes/mode/blob identity: {relative}")
        with tarfile.open(checkout / first["archivePath"], "r:") as archive:
            members = archive.getmembers()
            if [member.name for member in members] != [item["path"] for item in manifest["files"]]:
                raise AssertionError("production archive inventory differs from the committed manifest")
            for member in members:
                if not member.isfile() or member.mode != (0o755 if member.name == "scripts/release-tool" else 0o644):
                    raise AssertionError(f"production archive lost regular-file mode: {member.name}")
                content = archive.extractfile(member)
                if content is None or content.read() != expected[member.name]:
                    raise AssertionError(f"production archive lost committed input bytes: {member.name}")

        def rejected(expected_error: str) -> None:
            try:
                serverware_source_tree.production_source_contract(checkout, output)
            except ValueError as exc:
                if expected_error not in str(exc):
                    raise AssertionError(f"production source failed at the wrong guard: {exc}") from exc
            else:
                raise AssertionError(f"production source accepted invalid input: {expected_error}")

        dirty_error = "requires a clean index and worktree at the exact commit"
        executable.write_bytes(b"#!/bin/sh\nexit 1\n")
        rejected(dirty_error)
        executable.write_bytes(expected["scripts/release-tool"])
        executable.chmod(0o644)
        rejected(dirty_error)
        executable.chmod(0o755)
        opaque.unlink()
        rejected(dirty_error)
        opaque.write_bytes(expected["tracked-build-input.opaque"])
        untracked = checkout / "scripts" / "untracked-input"
        untracked.write_bytes(b"uncommitted source\n")
        rejected(dirty_error)
        untracked.unlink()
        opaque.write_bytes(b"staged different input\n")
        source_fixture_git(checkout, "add", "tracked-build-input.opaque")
        opaque.write_bytes(expected["tracked-build-input.opaque"])
        rejected("index differs from the exact HEAD tree")
        source_fixture_git(checkout, "add", "tracked-build-input.opaque")
        if serverware_source_tree.production_source_contract(checkout, output) != first:
            raise AssertionError("restoring source fixture bytes/index did not restore the original contract")

        # Commit the symlink so the regular-tracked-file guard, not dirtiness, rejects it.
        symlink = checkout / "scripts" / "release-tool-link"
        symlink.symlink_to("release-tool")
        source_fixture_git(checkout, "add", "scripts/release-tool-link")
        source_fixture_git(checkout, "commit", "-q", "-m", "forbidden tracked symlink fixture")
        rejected("symlinks, submodules, and special Git entries are forbidden: scripts/release-tool-link")


def assert_development_source_tree_manifest() -> None:
    with tempfile.TemporaryDirectory() as export_raw:
        exported = Path(export_raw)
        (exported / "ops").mkdir()
        (exported / "scripts").mkdir()
        # A declared build input, unlike the arbitrary tracked-only production names.
        (exported / ".dockerignore").write_text(".git\n.tmp\n", encoding="utf-8")
        (exported / "ops" / "production-readiness.env.example").write_text("MODE=production\n", encoding="utf-8")
        (exported / "ops" / "production-readiness.env").write_text("SECRET=runtime-only\n", encoding="utf-8")
        launcher = exported / "scripts" / "release-tool"
        launcher.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        launcher.chmod(0o755)
        first = serverware_source_tree.source_tree_summary(exported, production=False)
        second = serverware_source_tree.source_tree_summary(exported, production=False)
        if first != second:
            raise AssertionError("development source manifest is not deterministic outside a Git checkout")
        if (
            first["version"] != "serverware.sourceTree/v3"
            or first["identityMode"] != "development-dirty-tree"
            or first["productionReleaseEligible"] is not False
            or any(first[key] is not None for key in ("commit", "commitTimestamp", "gitTree"))
        ):
            raise AssertionError("development filesystem identity acquired production release eligibility")
        entries = {item["path"]: item for item in first["files"]}
        expected = {".dockerignore", "ops/production-readiness.env.example", "scripts/release-tool"}
        if set(entries) != expected or len(first["files"]) != len(expected):
            raise AssertionError(f"development source selection changed: {sorted(entries)}")
        if entries["scripts/release-tool"]["mode"] != "100755":
            raise AssertionError("development source manifest omitted executable mode")
        source_fixture_git(exported, "init", "--object-format=sha1", "-q")
        source_fixture_git(exported, "add", ".dockerignore", "ops/production-readiness.env.example", "scripts/release-tool")
        if serverware_source_tree.source_tree_summary(exported, production=False) != first:
            raise AssertionError("development filesystem identity changed after Git metadata/index creation")
        launcher.chmod(0o644)
        if serverware_source_tree.source_tree_digest(exported, production=False) == first["digest"]:
            raise AssertionError("development source digest did not commit to executable mode")
        launcher.chmod(0o755)
        symlink = exported / "scripts" / "release-tool-link"
        symlink.symlink_to("release-tool")
        try:
            serverware_source_tree.source_tree_summary(exported, production=False)
        except ValueError as exc:
            if "development source forbids symlinks: scripts/release-tool-link" not in str(exc):
                raise AssertionError(f"development source symlink failed at the wrong guard: {exc}") from exc
        else:
            raise AssertionError("development source unexpectedly accepted a symlink")
        symlink.unlink()
        launcher.unlink()
        missing = serverware_source_tree.source_tree_summary(exported, production=False)
        if (
            any(item["path"] == "scripts/release-tool" for item in missing["files"])
            or missing["digest"] == first["digest"]
            or missing["productionReleaseEligible"] is not False
        ):
            raise AssertionError("development source snapshot did not reflect a removed selected input")


def assert_source_tree_manifest_metadata_and_git_fallback() -> None:
    # Preserve the original coverage selector while testing the two v3 modes
    # independently; production identity never falls back to filesystem input.
    assert_production_source_tree_manifest()
    assert_development_source_tree_manifest()


def assert_source_contract_output_hardening() -> None:
    with tempfile.TemporaryDirectory(prefix="serverware-source-contract-output-") as checkout_raw:
        checkout = Path(checkout_raw)
        (checkout / "scripts").mkdir()
        (checkout / "scripts" / "release-tool.py").write_text(
            "VALUE = 1\n",
            encoding="utf-8",
        )
        (checkout / ".gitignore").write_text(".tmp/\n", encoding="utf-8")
        source_fixture_git(checkout, "init", "--object-format=sha1", "-q")
        source_fixture_git(checkout, "add", ".gitignore", "scripts/release-tool.py")
        source_fixture_git(checkout, "commit", "-q", "-m", "source contract fixture")

        valid_output = checkout / ".tmp" / "source-contract"
        contract = serverware_source_tree.production_source_contract(
            checkout,
            valid_output,
        )
        if not (checkout / contract["archivePath"]).is_file():
            raise AssertionError("production source contract did not publish its archive")

        real_output = checkout / ".tmp" / "real-output"
        real_output.mkdir()
        linked_output = checkout / ".tmp" / "linked-output"
        linked_output.symlink_to(real_output, target_is_directory=True)
        invalid_outputs = (
            (linked_output, "non-symlink directory"),
            (checkout / "artifacts" / "source-contract", "source-excluded directory"),
            (checkout, "must not be the worktree root"),
            (checkout.parent / "outside-source-contract", "inside the worktree"),
        )
        for output, expected_error in invalid_outputs:
            try:
                serverware_source_tree.production_source_contract(checkout, output)
            except ValueError as exc:
                if expected_error not in str(exc):
                    raise AssertionError(
                        f"unsafe source-contract output failed for the wrong reason: {exc}"
                    ) from exc
            else:
                raise AssertionError(
                    f"production source contract accepted unsafe output directory: {output}"
                )


def assert_release_source_tree_digest_callers_agree() -> None:
    build_digest = build_production_images.source_tree_digest()
    provenance_source = generate_release_provenance.source_tree(production=True)
    provenance_digest = provenance_source["digest"]
    attestation_digest = verify_codebase_attestation.source_tree_digest(ROOT)
    if len({build_digest, provenance_digest, attestation_digest}) != 1:
        raise AssertionError(
            "release source-tree digest callers disagree: "
            f"build={build_digest} provenance={provenance_digest} attestation={attestation_digest}"
        )
    entries = {item["path"]: item for item in provenance_source["sourceTreeManifest"]["files"]}
    for required in (".dockerignore", ".gitignore", "ops/production-readiness.env.example"):
        if required not in entries:
            raise AssertionError(f"release source-tree digest omitted required tracked input: {required}")
    if any(not {"path", "type", "mode"}.issubset(item) for item in entries.values()):
        raise AssertionError("release source-tree manifest omitted path/type/mode metadata")


def assert_production_release_key_is_pinned() -> None:
    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        private_path = tmp / "release.pem"
        public_path = tmp / "release.pub.pem"
        missing_path = tmp / "missing.pem"
        try:
            generate_release_provenance.load_release_key(
                missing_path,
                allow_create=False,
                require_owner_only=True,
            )
        except ValueError:
            pass
        else:
            raise AssertionError("production release signing generated a missing key")

        key = Ed25519PrivateKey.generate()
        private_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        private_path.chmod(0o600)
        public_path.write_bytes(
            key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        loaded = generate_release_provenance.load_production_release_key(
            private_path,
            public_path,
        )
        if generate_release_provenance.public_key_id(loaded.public_key()) != (
            generate_release_provenance.public_key_id(key.public_key())
        ):
            raise AssertionError("production release signing changed the configured key")

        private_path.chmod(0o644)
        try:
            generate_release_provenance.load_production_release_key(
                private_path,
                public_path,
            )
        except ValueError as exc:
            if "group or other" not in str(exc):
                raise AssertionError(
                    f"permissive production key failed for the wrong reason: {exc}"
                ) from exc
        else:
            raise AssertionError("production release signing accepted a permissive private key")

        private_path.chmod(0o600)
        other = Ed25519PrivateKey.generate()
        public_path.write_bytes(
            other.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        try:
            generate_release_provenance.load_production_release_key(
                private_path,
                public_path,
            )
        except ValueError as exc:
            if "does not match" not in str(exc):
                raise AssertionError(
                    f"mismatched production key failed for the wrong reason: {exc}"
                ) from exc
        else:
            raise AssertionError("production release signing accepted an untrusted private key")


def assert_release_key_short_writes_are_completed() -> None:
    with tempfile.TemporaryDirectory(prefix="serverware-release-key-write-") as tmp_raw:
        key_path = Path(tmp_raw) / "release-signing.pem"
        original_write = generate_release_provenance.os.write

        def short_write(descriptor: int, value: object) -> int:
            return original_write(descriptor, memoryview(value)[:7])

        generate_release_provenance.os.write = short_write
        try:
            key = generate_release_provenance.load_release_key(key_path)
        finally:
            generate_release_provenance.os.write = original_write
        encoded = key_path.read_bytes()
        loaded = serialization.load_pem_private_key(encoded, password=None)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise AssertionError("short-write release key did not produce a complete Ed25519 key")
        if (
            generate_release_provenance.public_key_id(loaded.public_key())
            != generate_release_provenance.public_key_id(key.public_key())
        ):
            raise AssertionError("short-write release key changed during persistence")


def assert_production_reproducibility_binds_image_outputs() -> None:
    def digest(character: str) -> str:
        return "sha256:" + character * 64

    launch_authority = build_production_images.launch_authority_metadata()
    source_tree_digest = digest("1")
    expected_images = {
        "serverware-control": {
            "local_build_image_id": digest("2"),
        },
        "serverware-decision-gate": {
            "local_build_image_id": digest("3"),
            "binary_digest": digest("4"),
            "launcher_binary_digest": digest("5"),
            **launch_authority,
        },
    }
    verification = {
        "apiVersion": verify_reproducible_builds.VERIFICATION_API_VERSION,
        "kind": verify_reproducible_builds.VERIFICATION_KIND,
        "ok": True,
        "reproducible": True,
        "scope": {
            "artifact_reproducibility_only": True,
            "independent_execution_proven": True,
            "hardware_proof": False,
        },
        "inputs": {
            "left": {
                "attestation": {
                    "builder_id": "builder.example/alpha",
                    "key_id": digest("6"),
                    "signature_verified": True,
                    "operator_trusted": True,
                }
            },
            "right": {
                "attestation": {
                    "builder_id": "builder.example/bravo",
                    "key_id": digest("7"),
                    "signature_verified": True,
                    "operator_trusted": True,
                }
            },
        },
        "source_tree_digest": source_tree_digest,
        "comparison_sha256": digest("8"),
        "images": [
            {
                "service": "serverware-control",
                "image_id": expected_images["serverware-control"][
                    "local_build_image_id"
                ],
            },
            {
                "service": "serverware-decision-gate",
                "image_id": expected_images["serverware-decision-gate"][
                    "local_build_image_id"
                ],
                "rust_binary_sha256": expected_images["serverware-decision-gate"][
                    "binary_digest"
                ],
                "launcher_binary_sha256": expected_images["serverware-decision-gate"][
                    "launcher_binary_digest"
                ],
                **launch_authority,
            },
        ],
        "mismatches": [],
    }

    with tempfile.TemporaryDirectory() as tmp_raw:
        verification_path = Path(tmp_raw) / "reproducible-build-verification.json"
        signature_path = Path(tmp_raw) / "reproducible-build-verification.signature.json"
        trusted_public_key_path = Path(tmp_raw) / "reproducible-build-verification.pub.pem"
        # This local key authenticates only synthetic fixture bytes. It does not
        # establish that independent production builders actually ran.
        signing_key = Ed25519PrivateKey.from_private_bytes(b"\x19" * 32)
        key_info = generate_release_provenance.public_key_info(signing_key)
        trusted_public_key_path.write_text(key_info["pem"], encoding="ascii")

        def verify_binding() -> dict[str, object]:
            return generate_release_provenance.production_reproducibility_binding(
                verification_path,
                signature_path=signature_path,
                trusted_public_key_path=trusted_public_key_path,
                expected_source_tree_digest=source_tree_digest,
                expected_images=expected_images,
            )

        def bind() -> dict[str, object]:
            verification_path.write_text(
                json.dumps(verification, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            payload = {
                "apiVersion": "serverware.externalArtifactSignature/v1",
                "artifactSha256": "sha256:" + hashlib.sha256(verification_path.read_bytes()).hexdigest(),
                "purpose": "reproducible-build-verification",
            }
            signature = {
                **payload,
                "kind": "ExternalArtifactSignature",
                "algorithm": "Ed25519",
                "signerKeyId": key_info["spki_sha256"],
                "signature": "ed25519:" + base64.urlsafe_b64encode(
                    signing_key.sign(
                        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
                    )
                ).decode("ascii").rstrip("="),
            }
            signature_path.write_text(
                json.dumps(signature, sort_keys=True) + "\n", encoding="ascii"
            )
            return verify_binding()

        binding = bind()
        if binding.get("images") != verification["images"]:
            raise AssertionError(
                f"production provenance did not retain exact reproducible image outputs: {binding}"
            )
        for field, artifact in (
            ("verification_sha256", verification_path),
            ("verification_signature_sha256", signature_path),
            ("verification_trusted_public_key_sha256", trusted_public_key_path),
        ):
            if binding.get(field) != "sha256:" + hashlib.sha256(artifact.read_bytes()).hexdigest():
                raise AssertionError(f"reproducibility binding did not retain authenticated {field}")
        if binding.get("verification_signer_key_id") != key_info["spki_sha256"]:
            raise AssertionError("reproducibility binding did not retain the separately pinned fixture signer")

        def reject_authentication(expected_error: str) -> None:
            try:
                verify_binding()
            except ValueError as exc:
                if expected_error not in str(exc):
                    raise AssertionError(f"reproducibility authentication failed for the wrong reason: {exc}") from exc
            else:
                raise AssertionError("reproducibility binding accepted unauthenticated fixture bytes")

        report_bytes = verification_path.read_bytes()
        verification_path.write_bytes(report_bytes + b" ")
        reject_authentication("detached signature binding is invalid")
        verification_path.write_bytes(report_bytes)
        signature_bytes = signature_path.read_bytes()
        signature = json.loads(signature_bytes)
        signature["signature"] = "ed25519:" + base64.urlsafe_b64encode(b"\x00" * 64).decode("ascii").rstrip("=")
        signature_path.write_text(json.dumps(signature) + "\n", encoding="ascii")
        reject_authentication("detached signature verification failed")
        signature_path.write_bytes(signature_bytes)
        signature = json.loads(signature_bytes)
        signature["purpose"] = "policy-activation-verification"
        signature_path.write_text(json.dumps(signature) + "\n", encoding="ascii")
        reject_authentication("detached signature binding is invalid")
        signature_path.write_bytes(signature_bytes)
        wrong_key = Ed25519PrivateKey.from_private_bytes(b"\x20" * 32)
        trusted_public_key_path.write_text(
            generate_release_provenance.public_key_info(wrong_key)["pem"], encoding="ascii"
        )
        reject_authentication("detached signature binding is invalid")
        trusted_public_key_path.write_text(key_info["pem"], encoding="ascii")
        verify_binding()

        mutations = (
            (0, "image_id", digest("9"), "serverware-control image ID"),
            (1, "image_id", digest("a"), "serverware-decision-gate image ID"),
            (
                1,
                "rust_binary_sha256",
                digest("b"),
                "decision-gate Rust binary",
            ),
        )
        for index, field, invalid_value, expected_error in mutations:
            original = verification["images"][index][field]
            verification["images"][index][field] = invalid_value
            try:
                bind()
            except ValueError as exc:
                if expected_error not in str(exc):
                    raise AssertionError(
                        f"{field} mismatch failed for the wrong reason: {exc}"
                    ) from exc
            else:
                raise AssertionError(
                    f"production provenance accepted mismatched {field}"
                )
            finally:
                verification["images"][index][field] = original


def main() -> None:
    assert_dockerignore()
    assert_production_dependencies()
    assert_development_image_identity_validation()
    assert_reproducible_rust_binary_config()
    assert_custody_ledger_image_seed()
    assert_gate_response_context_publish_wait()
    assert_static_launcher_artifact_embedded()
    assert_launcher_digest_measurement_contract()
    assert_release_python_dependency_inventory()
    assert_malformed_python_locks_fail_closed()
    assert_source_tree_digest_covers_untracked_source()
    assert_source_tree_covers_production_copy_surface()
    assert_source_tree_manifest_metadata_and_git_fallback()
    assert_source_contract_output_hardening()
    assert_release_source_tree_digest_callers_agree()
    assert_production_release_key_is_pinned()
    assert_release_key_short_writes_are_completed()
    assert_production_reproducibility_binds_image_outputs()
    assert_distroless_no_shell(ROOT / "Dockerfile.production", "gcr.io/distroless/python3-debian12")
    assert_base_images_pinned(ROOT / "Dockerfile.production")
    assert_oci_traceability(ROOT / "Dockerfile.production")
    assert_distroless_no_shell(
        ROOT / "data-plane" / "decision-gate-rs" / "Dockerfile.production",
        "gcr.io/distroless/cc-debian12",
    )
    assert_base_images_pinned(ROOT / "data-plane" / "decision-gate-rs" / "Dockerfile.production")
    assert_oci_traceability(ROOT / "data-plane" / "decision-gate-rs" / "Dockerfile.production")
    plan = run_dry_build()
    dockerfiles = {item["dockerfile"] for item in plan.get("commands") or []}
    if dockerfiles != {"Dockerfile.production", "data-plane/decision-gate-rs/Dockerfile.production"}:
        raise AssertionError(f"production build dry-run used the wrong Dockerfiles: {plan}")
    metadata = plan.get("metadata") or {}
    if not str(metadata.get("source_tree_digest", "")).startswith("sha256:"):
        raise AssertionError(f"production build plan did not bind a source tree digest: {plan}")
    for item in plan.get("commands") or []:
        argv = item.get("argv") or []
        if "SERVERWARE_SOURCE_TREE_DIGEST=" not in " ".join(argv):
            raise AssertionError(f"production build command did not pass traceability build args: {item}")
        if "SOURCE_DATE_EPOCH=" not in " ".join(argv):
            raise AssertionError(f"production build command did not pass a deterministic timestamp: {item}")
    print(json.dumps({"ok": True, "production_image_builds": "pass"}, sort_keys=True))


if __name__ == "__main__":
    main()
