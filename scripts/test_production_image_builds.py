#!/usr/bin/env python3
from __future__ import annotations

import copy
import json
import hashlib
import os
import re
import subprocess
import sys
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

ROOT = Path(__file__).resolve().parent.parent


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
    mutable = [
        line
        for line in from_lines
        if "@sha256:" not in line
        and re.fullmatch(r"FROM\s+scratch(?:\s+AS\s+[A-Za-z0-9._-]+)?", line, re.IGNORECASE) is None
    ]
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
    config_source = (ROOT / "serverware" / "config.py").read_text(encoding="utf-8")
    if "_PRODUCTION_IMAGE_MARKER_PRESENT or os.getenv" not in config_source:
        raise AssertionError(
            "control-plane production detection must prefer the baked image marker"
        )
    if not (ROOT / "requirements.lock").is_file():
        raise AssertionError("production hash-locked requirements file is missing")
    prototype = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    if "SERVERWARE_INSTALL_PROTOTYPE_MITMPROXY=0" not in prototype:
        raise AssertionError("prototype Dockerfile must default mitmproxy installation off")
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    if "SERVERWARE_INSTALL_PROTOTYPE_MITMPROXY" in compose:
        raise AssertionError("default docker-compose.yml must not enable the mitmproxy prototype")
    if '"127.0.0.1:8080:9090"' not in compose:
        raise AssertionError("default docker-compose.yml must expose the Rust decision gate on a loopback-only agent proxy port")
    dev_result = subprocess.run(
        ["docker", "compose", "--profile", "custody", "config", "--format", "json"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if dev_result.returncode != 0:
        raise AssertionError(
            f"development Compose model did not parse: {dev_result.stderr.decode(errors='replace')}"
        )
    dev_model = json.loads(dev_result.stdout)
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
    compose_env = os.environ.copy()
    for name in re.findall(r"\$\{([A-Z0-9_]+):\?[^}]*\}", production_compose):
        compose_env.setdefault(name, "serverware-compose-test-value")
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
        ["docker", "compose", "-f", str(production_compose_path), "config", "--format", "json"],
        cwd=ROOT,
        env=compose_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"production Compose model did not parse: {result.stderr.decode(errors='replace')}")
    model = json.loads(result.stdout)
    generate_release_provenance.validate_production_custody_topology(model, compose_env)

    def expect_custody_topology_rejection(label: str, mutate: object) -> None:
        candidate = copy.deepcopy(model)
        mutate(candidate)
        try:
            generate_release_provenance.validate_production_custody_topology(
                candidate, compose_env
            )
        except ValueError:
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
        candidate["services"]["serverware"]["healthcheck"]["test"][3] += "; pass"

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

    if set(model["services"]) != {
        "serverware",
        "audit-anchor",
        "custody-runtime",
        "decision-gate-rs",
    }:
        raise AssertionError(f"production Compose service set is not closed and complete: {sorted(model['services'])}")
    custody = model["services"]["custody-runtime"]
    gate = model["services"]["decision-gate-rs"]
    healthcheck_command = model["services"]["serverware"]["healthcheck"]["test"][3]
    if (
        "validate_response_signing_key_custody" not in healthcheck_command
        or "sys.exit(1)" not in healthcheck_command
        or "assert " in healthcheck_command
        or "__debug__" in healthcheck_command
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
    control_ports = model["services"]["serverware"].get("ports") or []
    if len(control_ports) != 1 or control_ports[0].get("host_ip") != "127.0.0.1":
        raise AssertionError(f"production control plane must be loopback-bound behind the deployment ingress: {control_ports}")
    ports = model["services"]["decision-gate-rs"].get("ports") or []
    if any(int(binding["target"]) == 9091 for binding in ports):
        raise AssertionError("production must not publish the decision-gate management listener")
    proxy_ports = [binding for binding in ports if int(binding["target"]) == 9090]
    if len(proxy_ports) != 1 or str(proxy_ports[0].get("published")) != "8080":
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


def assert_reproducible_rust_binary_config() -> None:
    for relative in (
        "data-plane/decision-gate-rs/Dockerfile",
        "data-plane/decision-gate-rs/Dockerfile.production",
    ):
        dockerfile = (ROOT / relative).read_text(encoding="utf-8")
        if "COPY schemas /schemas" not in dockerfile:
            raise AssertionError(
                f"{relative} must package the schemas embedded by the Rust gate"
            )
    cargo = (ROOT / "data-plane" / "decision-gate-rs" / "Cargo.toml").read_text(encoding="utf-8")
    if "[profile.release]" not in cargo or 'strip = "symbols"' not in cargo:
        raise AssertionError("Rust release binaries must strip nondeterministic symbol tables")


def assert_custody_ledger_image_seed() -> None:
    for relative, ownership in (
        ("data-plane/decision-gate-rs/Dockerfile", "10002:10003"),
        ("data-plane/decision-gate-rs/Dockerfile.production", "65531:65530"),
    ):
        dockerfile = (ROOT / relative).read_text(encoding="utf-8")
        required = (
            "SERVERWARE_CUSTODY_ATTEMPT_LEDGER_DIRECTORY=/runtime-layout/serverware-custody-state",
            "/src/target/release/serverware-custody-runtime --initialize-attempt-ledger",
            f"COPY --from=build --chown={ownership} --chmod=0700 /runtime-layout/serverware-custody-state /var/lib/serverware-custody",
            f"COPY --from=build --chown={ownership} --chmod=0600 /runtime-layout/serverware-custody-state/manifest.json /var/lib/serverware-custody/manifest.json",
            f"COPY --from=build --chown={ownership} --chmod=0600 /runtime-layout/serverware-custody-state/ledger.lock /var/lib/serverware-custody/ledger.lock",
        )
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
        if f"cargo build --release {lock_mode}" not in dockerfile:
            raise AssertionError(f"{relative} must build the lockfile-pinned Rust release")


def assert_static_launcher_artifact_embedded() -> None:
    path = ROOT / "data-plane" / "decision-gate-rs" / "Dockerfile.production"
    dockerfile = path.read_text(encoding="utf-8")
    required = (
        "FROM rust:1.88-alpine3.22@sha256:64eba3726734dcfe89e0a62a0485007a3ab7c7372ce5b38c621d8812f70215f0 AS launcher-build",
        "COPY production-dependencies/cache/musl-1.2.5-r12.apk",
        "--network=none cargo build --release --frozen --bin serverware-production-launcher",
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
        before = build_production_images.source_tree_digest()
        try:
            probe.parent.mkdir(parents=True, exist_ok=True)
            probe.write_bytes(content)
            after = build_production_images.source_tree_digest()
        finally:
            probe.unlink(missing_ok=True)
        if before == after:
            raise AssertionError(f"source_tree_digest did not change for an untracked {probe.suffix} file")


def local_copy_inputs(path: Path) -> list[str]:
    inputs: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        fields = raw.strip().split()
        if (
            not fields
            or fields[0].upper() != "COPY"
            or any(field.startswith("--from=") for field in fields[1:])
        ):
            continue
        while len(fields) > 1 and fields[1].startswith("--"):
            fields.pop(1)
        if len(fields) < 3:
            raise AssertionError(f"unsupported production COPY instruction in {path}: {raw}")
        inputs.extend(fields[1:-1])
    return inputs


def assert_source_tree_covers_production_copy_surface() -> None:
    dockerfiles = (
        ROOT / "Dockerfile.production",
        ROOT / "data-plane" / "decision-gate-rs" / "Dockerfile.production",
    )
    for dockerfile in dockerfiles:
        for source in local_copy_inputs(dockerfile):
            source_path = ROOT / source
            if source_path.is_dir():
                source_root = Path(source).parts[0]
                if source_root not in serverware_source_tree.SOURCE_ROOTS:
                    raise AssertionError(
                        f"source-tree manifest does not include every untracked byte under {source} copied by {dockerfile}"
                    )
            elif not serverware_source_tree.is_source_file(source_path, ROOT):
                raise AssertionError(f"source-tree manifest omits root input {source} copied by {dockerfile}")

    with tempfile.TemporaryDirectory(prefix="serverware-source-copy-surface-") as checkout_raw:
        checkout = Path(checkout_raw)
        (checkout / "scripts").mkdir()
        (checkout / "policies").mkdir()
        (checkout / ".gitignore").write_text("scripts/ignored-build-input\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(checkout)], check=True)
        subprocess.run(["git", "-C", str(checkout), "add", ".gitignore"], check=True)

        baseline = serverware_source_tree.source_tree_digest(checkout)
        ignored = checkout / "scripts" / "ignored-build-input"
        ignored.write_bytes(b"ignored opaque input\x00v1\n")
        ignored_check = subprocess.run(
            ["git", "-C", str(checkout), "check-ignore", "-q", "scripts/ignored-build-input"],
            check=False,
        )
        if ignored_check.returncode != 0:
            raise AssertionError("ignored source-tree adversarial fixture is not ignored by Git")
        ignored_digest = serverware_source_tree.source_tree_digest(checkout)
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
        if serverware_source_tree.source_tree_digest(checkout) == ignored_digest:
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
        policy_digest = serverware_source_tree.source_tree_digest(checkout)
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
        if serverware_source_tree.source_tree_digest(checkout) == policy_digest:
            raise AssertionError("source-tree digest did not bind every byte of an opaque untracked policy file")


def assert_source_tree_manifest_metadata_and_git_fallback() -> None:
    with tempfile.TemporaryDirectory() as checkout_raw:
        checkout = Path(checkout_raw)
        (checkout / "ops").mkdir()
        (checkout / "scripts").mkdir()
        (checkout / ".buildrc").write_text("strict=true\n", encoding="utf-8")
        (checkout / "ops" / "production-readiness.env.example").write_text("MODE=production\n", encoding="utf-8")
        executable = checkout / "scripts" / "release-tool"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o755)
        opaque = checkout / "tracked-build-input.opaque"
        opaque.write_bytes(b"tracked opaque build input\n")
        symlink = checkout / "scripts" / "release-tool-link"
        symlink.symlink_to("release-tool")
        subprocess.run(["git", "init", "-q", str(checkout)], check=True)
        subprocess.run(["git", "-C", str(checkout), "add", "-A"], check=True)

        first = serverware_source_tree.source_tree_summary(checkout)
        second = serverware_source_tree.source_tree_summary(checkout)
        if first != second:
            raise AssertionError("source-tree manifest is not deterministic inside a Git checkout")
        entries = {item["path"]: item for item in first["files"]}
        expected = {
            ".buildrc",
            "ops/production-readiness.env.example",
            "scripts/release-tool",
            "scripts/release-tool-link",
            "tracked-build-input.opaque",
        }
        if not expected.issubset(entries):
            raise AssertionError(f"source-tree manifest omitted tracked inputs: {sorted(expected - set(entries))}")
        if entries["scripts/release-tool"].get("mode") != "100755":
            raise AssertionError(f"source-tree manifest omitted executable mode: {entries['scripts/release-tool']}")
        link_entry = entries["scripts/release-tool-link"]
        if link_entry.get("type") != "symlink" or link_entry.get("mode") != "120000" or link_entry.get("target") != "release-tool":
            raise AssertionError(f"source-tree manifest followed or misrepresented a symlink: {link_entry}")
        if any(item["path"].startswith(".git/") for item in first["files"]):
            raise AssertionError("source-tree manifest included Git metadata")

        executable.chmod(0o644)
        mode_digest = serverware_source_tree.source_tree_digest(checkout)
        if mode_digest == first["digest"]:
            raise AssertionError("source-tree digest did not commit to executable mode")
        executable.chmod(0o755)
        symlink.unlink()
        symlink.symlink_to("../.buildrc")
        link_digest = serverware_source_tree.source_tree_digest(checkout)
        if link_digest == first["digest"]:
            raise AssertionError("source-tree digest did not commit to symlink target")
        symlink.unlink()
        symlink.symlink_to("release-tool")
        opaque.unlink()
        missing = serverware_source_tree.source_tree_summary(checkout)
        missing_entry = next(item for item in missing["files"] if item["path"] == "tracked-build-input.opaque")
        if missing_entry.get("type") != "missing" or missing["digest"] == first["digest"]:
            raise AssertionError(f"source-tree manifest did not commit to a deleted tracked input: {missing_entry}")

    with tempfile.TemporaryDirectory() as export_raw:
        exported = Path(export_raw)
        (exported / "ops").mkdir()
        (exported / "scripts").mkdir()
        (exported / ".buildrc").write_text("strict=true\n", encoding="utf-8")
        (exported / "ops" / "production-readiness.env.example").write_text("MODE=production\n", encoding="utf-8")
        (exported / "ops" / "production-readiness.env").write_text("SECRET=runtime-only\n", encoding="utf-8")
        launcher = exported / "scripts" / "release-tool"
        launcher.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        launcher.chmod(0o755)
        (exported / "scripts" / "release-tool-link").symlink_to("release-tool")

        first = serverware_source_tree.source_tree_summary(exported)
        second = serverware_source_tree.source_tree_summary(exported)
        if first != second:
            raise AssertionError("source-tree manifest is not deterministic outside a Git checkout")
        entries = {item["path"]: item for item in first["files"]}
        for required in (".buildrc", "ops/production-readiness.env.example", "scripts/release-tool-link"):
            if required not in entries:
                raise AssertionError(f"Git-independent source-tree manifest omitted {required}")
        if "ops/production-readiness.env" in entries:
            raise AssertionError("Git-independent source-tree manifest included the runtime production secret env")


def assert_release_source_tree_digest_callers_agree() -> None:
    build_digest = build_production_images.source_tree_digest()
    provenance_digest = generate_release_provenance.source_tree()["digest"]
    attestation_digest = verify_codebase_attestation.source_tree_digest(ROOT)
    if len({build_digest, provenance_digest, attestation_digest}) != 1:
        raise AssertionError(
            "release source-tree digest callers disagree: "
            f"build={build_digest} provenance={provenance_digest} attestation={attestation_digest}"
        )
    entries = {item["path"]: item for item in serverware_source_tree.source_tree_files(ROOT)}
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

        def bind() -> dict[str, object]:
            verification_path.write_text(
                json.dumps(verification, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            return generate_release_provenance.production_reproducibility_binding(
                verification_path,
                expected_source_tree_digest=source_tree_digest,
                expected_images=expected_images,
            )

        binding = bind()
        if binding.get("images") != verification["images"]:
            raise AssertionError(
                f"production provenance did not retain exact reproducible image outputs: {binding}"
            )

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
    assert_release_source_tree_digest_callers_agree()
    assert_production_release_key_is_pinned()
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
