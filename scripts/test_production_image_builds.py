#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import build_production_images
import generate_release_provenance
import verify_codebase_attestation

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
    missing = sorted(required - ignored)
    if missing:
        raise AssertionError(f".dockerignore does not exclude local build/secrets material: {missing}")


def assert_production_dependencies() -> None:
    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8").lower()
    if "mitmproxy" in requirements:
        raise AssertionError("production requirements must not include mitmproxy")
    dockerfile = (ROOT / "Dockerfile.production").read_text(encoding="utf-8")
    if "serverware.control_plane_runner" not in dockerfile:
        raise AssertionError("production image must start the control-plane runner, not the prototype mitmproxy runner")
    prototype = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    if "SERVERWARE_INSTALL_PROTOTYPE_MITMPROXY=0" not in prototype:
        raise AssertionError("prototype Dockerfile must default mitmproxy installation off")
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    if "SERVERWARE_INSTALL_PROTOTYPE_MITMPROXY" in compose:
        raise AssertionError("default docker-compose.yml must not enable the mitmproxy prototype")
    if '"8080:9090"' not in compose:
        raise AssertionError("default docker-compose.yml must expose the Rust decision gate on the agent proxy port")


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
    probe = ROOT / "scripts" / "__source_digest_probe__.py"
    if probe.exists():
        raise AssertionError(f"unexpected source digest probe already exists: {probe}")
    before = build_production_images.source_tree_digest()
    try:
        probe.write_text("# source digest coverage probe\nVALUE = 1\n", encoding="utf-8")
        after = build_production_images.source_tree_digest()
    finally:
        probe.unlink(missing_ok=True)
    if before == after:
        raise AssertionError("source_tree_digest did not change for a new untracked source file")


def assert_release_source_tree_digest_callers_agree() -> None:
    build_digest = build_production_images.source_tree_digest()
    provenance_digest = generate_release_provenance.source_tree()["digest"]
    attestation_digest = verify_codebase_attestation.source_tree_digest(ROOT)
    if len({build_digest, provenance_digest, attestation_digest}) != 1:
        raise AssertionError(
            "release source-tree digest callers disagree: "
            f"build={build_digest} provenance={provenance_digest} attestation={attestation_digest}"
        )


def main() -> None:
    assert_dockerignore()
    assert_production_dependencies()
    assert_source_tree_digest_covers_untracked_source()
    assert_release_source_tree_digest_callers_agree()
    assert_distroless_no_shell(ROOT / "Dockerfile.production", "gcr.io/distroless/python3-debian12")
    assert_oci_traceability(ROOT / "Dockerfile.production")
    assert_distroless_no_shell(
        ROOT / "data-plane" / "decision-gate-rs" / "Dockerfile.production",
        "gcr.io/distroless/cc-debian12",
    )
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
    print(json.dumps({"ok": True, "production_image_builds": "pass"}, sort_keys=True))


if __name__ == "__main__":
    main()
