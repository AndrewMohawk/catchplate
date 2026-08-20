#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shlex
import subprocess
import tempfile
from pathlib import Path

import build_production_images
import generate_production_launch_manifest

ROOT = Path(__file__).resolve().parent.parent
RFC8032_PUBLIC_KEY_HEX = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
RFC8032_KEY_ID = "sha256:06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9"
RFC8032_FILE_SHA256 = "sha256:40d359139cfd8af4ff3ebfbf9c8845468ca7876582189c11d3293b832f660632"


def build_metadata_fixture() -> dict[str, object]:
    digest = "sha256:" + "2" * 64
    return {
        "source": "https://example.invalid/serverware",
        "revision": "1" * 40,
        "created": "2026-01-01T00:00:00Z",
        "source_date_epoch": "1767225600",
        "source_tree_digest": digest,
        "source_archive_digest": digest,
        "source_archive_path": "production-dependencies/cache/source-contract/source.tar",
        "source_manifest_digest": digest,
        "source_manifest_path": "production-dependencies/cache/source-contract/source.manifest.json",
        "source_file_list_digest": digest,
        "source_file_list_path": "production-dependencies/cache/source-contract/source.files",
        "source_file_hashes_digest": digest,
        "source_file_hashes_path": "production-dependencies/cache/source-contract/source.files.sha256",
        "source_file_modes_digest": digest,
        "source_file_modes_path": "production-dependencies/cache/source-contract/source.files.mode",
        "source_identity_mode": "production-commit",
        "production_release_eligible": True,
        "image_title_suffix": "production test",
        "launch_authority_key_id": RFC8032_KEY_ID,
        "launch_authority_root_sha256": RFC8032_FILE_SHA256,
    }


def expect_invalid_trust_root(content: bytes) -> None:
    with tempfile.TemporaryDirectory(prefix="serverware-launch-authority-test-") as raw_tmp:
        path = Path(raw_tmp) / "launch-authority-root.ed25519.hex"
        path.write_bytes(content)
        try:
            build_production_images.launch_authority_metadata(path)
        except RuntimeError:
            return
        raise AssertionError(f"malformed launch authority root unexpectedly passed: {content!r}")


def assert_malformed_trust_roots_fail_closed() -> None:
    valid = RFC8032_PUBLIC_KEY_HEX.encode("ascii")
    for malformed in (
        b"",
        valid,
        valid.upper() + b"\n",
        valid[:-1] + b"\n",
        valid + b"0\n",
        b"g" + valid[1:] + b"\n",
        valid + b"\n\n",
        b"00" * 32 + b"\n",
        b"ff" * 32 + b"\n",
    ):
        expect_invalid_trust_root(malformed)

    with tempfile.TemporaryDirectory(prefix="serverware-launch-authority-symlink-test-") as raw_tmp:
        tmp = Path(raw_tmp)
        target = tmp / "target"
        target.write_bytes(valid + b"\n")
        symlink = tmp / "launch-authority-root.ed25519.hex"
        symlink.symlink_to(target.name)
        try:
            build_production_images.launch_authority_metadata(symlink)
        except RuntimeError:
            pass
        else:
            raise AssertionError("launch authority trust root unexpectedly accepted a symlink")


def assert_deterministic_launch_authority_metadata() -> None:
    with tempfile.TemporaryDirectory(prefix="serverware-launch-authority-vector-") as raw_tmp:
        path = Path(raw_tmp) / "launch-authority-root.ed25519.hex"
        path.write_bytes(RFC8032_PUBLIC_KEY_HEX.encode("ascii") + b"\n")
        expected = {
            "launch_authority_key_id": RFC8032_KEY_ID,
            "launch_authority_root_sha256": RFC8032_FILE_SHA256,
        }
        first = build_production_images.launch_authority_metadata(path)
        second = build_production_images.launch_authority_metadata(path)
        if first != expected or second != expected:
            raise AssertionError(f"launch authority metadata is not deterministic: {first!r}, {second!r}")

        gate_binding = build_production_images.image_launch_authority_binding(
            "serverware-decision-gate", first
        )
        if gate_binding != expected:
            raise AssertionError(f"decision-gate image metadata did not bind the trust root: {gate_binding}")
        if build_production_images.image_launch_authority_binding("serverware-control", first):
            raise AssertionError("control image unexpectedly repeated decision-gate trust-root metadata")

    committed = build_production_images.launch_authority_metadata()
    if set(committed) != set(build_production_images.LAUNCH_AUTHORITY_METADATA_FIELDS):
        raise AssertionError(f"committed trust root returned incomplete metadata: {committed}")


def assert_launch_authority_is_not_a_build_arg() -> None:
    metadata = build_metadata_fixture()
    argv = build_production_images.build_command(
        "data-plane/decision-gate-rs/Dockerfile.production",
        "serverware/decision-gate:test",
        platform="linux/amd64",
        metadata=metadata,
        context=ROOT,
    )
    serialized = "\0".join(argv).lower()
    if "launch_authority" in serialized or "launch-authority" in serialized:
        raise AssertionError(f"production build command exposed a launch authority build argument: {argv}")
    if RFC8032_KEY_ID in serialized or RFC8032_FILE_SHA256 in serialized:
        raise AssertionError(f"production build command exposed launch authority metadata values: {argv}")


def assert_build_contract_version() -> None:
    if build_production_images.BUILD_API_VERSION != "serverware.productionImagesBuild/v2":
        raise AssertionError(
            f"production image build contract was not promoted to v2: {build_production_images.BUILD_API_VERSION}"
        )
    if build_production_images.BUILD_KIND != "ProductionImagesBuild":
        raise AssertionError(f"unexpected production image build kind: {build_production_images.BUILD_KIND}")


def dockerfile_stage(lines: list[str], name: str) -> list[str]:
    start = next(
        (
            index
            for index, line in enumerate(lines)
            if line.upper().startswith("FROM ") and line.upper().endswith(f" AS {name.upper()}")
        ),
        None,
    )
    if start is None:
        raise AssertionError(f"production Dockerfile is missing stage {name}")
    end = next(
        (index for index in range(start + 1, len(lines)) if lines[index].upper().startswith("FROM ")),
        len(lines),
    )
    return lines[start:end]


def assert_dockerfile_copies_trust_into_rust_builds() -> None:
    required = "COPY data-plane/decision-gate-rs/trust ./trust"
    dockerfiles = (
        (ROOT / "data-plane/decision-gate-rs/Dockerfile", ("build",)),
        (
            ROOT / "data-plane/decision-gate-rs/Dockerfile.production",
            ("build", "launcher-build"),
        ),
    )
    for path, stages in dockerfiles:
        lines = [
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        for stage in stages:
            stage_lines = dockerfile_stage(lines, stage)
            if stage_lines.count(required) != 1:
                raise AssertionError(
                    f"{path.relative_to(ROOT)} stage {stage} does not copy the trust directory once"
                )

    production_lines = [
        line.strip()
        for line in dockerfiles[1][0].read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    authority_args = [
        line
        for line in production_lines
        if line.upper().startswith("ARG ")
        and ("AUTHORITY" in line.upper() or "ED25519" in line.upper())
    ]
    if authority_args:
        raise AssertionError(f"production Dockerfile exposes a launch authority key override: {authority_args}")


def run(command: list[str], *, timeout: int = 1200) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise AssertionError(f"required runtime test command is unavailable: {command[0]}") from exc


def assert_python_runtime_docker_contract() -> None:
    dockerfile_path = ROOT / "Dockerfile.production"
    dockerfile = dockerfile_path.read_text(encoding="utf-8")
    lines = [line.strip() for line in dockerfile.splitlines() if line.strip()]
    dependency_stage = dockerfile_stage(lines, "python-deps")
    source_stage = dockerfile_stage(lines, "verified-production-source")
    runtime_stage = dockerfile_stage(lines, "production-python-runtime-tree")
    artifact_stage = dockerfile_stage(lines, "production-python-runtime-artifact")
    dependency_text = "\n".join(dependency_stage)
    if "SERVERWARE_SOURCE_" in dependency_text or "/source-contract" in dependency_text:
        raise AssertionError("standalone Python dependency closure still requires application source")
    source_text = "\n".join(source_stage)
    for required in (
        "ARG SERVERWARE_SOURCE_ARCHIVE",
        "COPY ${SERVERWARE_SOURCE_ARCHIVE} /source-contract/source.tar",
        "sha256sum -c /source-contract/source.files.sha256",
    ):
        if required not in source_text:
            raise AssertionError(f"verified production source stage omits {required}")
    if "COPY --from=verified-production-source /source/serverware /runtime/app/serverware" not in dockerfile:
        raise AssertionError("production runtime does not consume the verified source stage")
    required_runtime = (
        "FROM python:3.11-slim-bookworm@sha256:0030323c9ce4d6dfab5f0812577cb0abd13c806f86b3a1f5b5d8f200ebb1421c AS production-python-runtime-tree",
        "COPY --from=python-deps /deps /deps",
        "cp -L /usr/local/bin/python3 /runtime/python/bin/python3",
        "cp -RL /usr/local/lib/python3.11/. /runtime/python/lib/python3.11/",
        "cp -L /usr/local/lib/libpython3.11.so.1.0 /runtime/python/lib/libpython3.11.so.1.0",
        "cp -RL /deps/. /vendor/",
    )
    runtime_text = "\n".join(runtime_stage)
    missing = [value for value in required_runtime if value not in runtime_text]
    if missing:
        raise AssertionError(f"production Python runtime stage is incomplete: {missing}")
    expected_artifact_copies = {
        "COPY --from=production-python-runtime-tree /runtime /runtime",
        "COPY --from=production-python-runtime-tree /vendor /vendor",
    }
    if not expected_artifact_copies.issubset(set(artifact_stage)):
        raise AssertionError("production Python runtime artifact does not export runtime and vendor")

    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    for required in (
        "build-production-python-runtime:",
        "--target production-python-runtime-artifact",
        "PRODUCTION_PYTHON_RUNTIME_ARTIFACT_DIRECTORY",
        "PRODUCTION_PYTHON_RUNTIME_ARTIFACT_DIRECTORY must not already exist",
        "PRODUCTION_LAUNCHER_BUILD_DIRECTORY must not already exist",
        "SERVERWARE_PRODUCTION_PYTHON_RUNTIME_ARTIFACT=",
        "$(MAKE) build-production-python-runtime",
    ):
        if required not in makefile:
            raise AssertionError(f"production Make flow omits runtime artifact contract: {required}")
    proof_position = makefile.find("\nproduction-release-proof:")
    deploy_position = makefile.find("\n\t$(MAKE) deploy-production", proof_position)
    runtime_position = makefile.find("\n\t$(MAKE) build-production-python-runtime", proof_position)
    if proof_position < 0 or runtime_position < 0 or deploy_position < 0 or runtime_position > deploy_position:
        raise AssertionError("production release proof does not build the Python runtime before deploy")


def assert_production_artifact_build_contract() -> None:
    metadata = build_metadata_fixture()
    command = build_production_images.artifact_build_command(
        "data-plane/decision-gate-rs/Dockerfile.production",
        "production-launcher-artifact",
        "type=local,dest=/tmp/launcher",
        network="none",
        platform="linux/amd64",
        metadata=metadata,
        context=Path("/private/serverware-build-context"),
    )
    serialized = "\0".join(command)
    for required in (
        "docker\0buildx\0build",
        "--network=none",
        "--target\0production-launcher-artifact",
        f"SERVERWARE_SOURCE_ARCHIVE={metadata['source_archive_path']}",
        f"SERVERWARE_SOURCE_ARCHIVE_SHA256={metadata['source_archive_digest']}",
        f"SERVERWARE_SOURCE_TREE_DIGEST={metadata['source_tree_digest']}",
    ):
        if required not in serialized:
            raise AssertionError(f"production artifact command omits {required}")
    try:
        build_production_images.artifact_build_command(
            "Dockerfile.production",
            "production-launcher-artifact",
            "type=local,dest=/tmp/launcher",
            network="none",
            platform="linux/amd64",
            metadata=metadata,
            context=Path("/private/serverware-build-context"),
        )
    except RuntimeError:
        pass
    else:
        raise AssertionError("production artifact helper accepted an unapproved Dockerfile/target pair")


def assert_deploy_receives_runtime_artifact() -> None:
    with tempfile.TemporaryDirectory(prefix="serverware-deploy-runtime-") as raw_tmp:
        temporary = Path(raw_tmp).resolve()
        artifact = temporary / "artifact"
        python = artifact / "runtime" / "python" / "bin" / "python3"
        python.parent.mkdir(parents=True)
        python.write_bytes(b"test fixture")
        python.chmod(0o700)
        (artifact / "vendor").mkdir()
        deploy = temporary / "deploy.sh"
        deploy.write_text(
            "#!/bin/sh\n"
            "test \"$SERVERWARE_PRODUCTION_PYTHON_RUNTIME_ARTIFACT\" = "
            + shlex.quote(str(artifact))
            + "\n",
            encoding="ascii",
        )
        deploy.chmod(0o700)
        result = run(
            [
                "make",
                "deploy-production",
                f"PRODUCTION_PYTHON_RUNTIME_ARTIFACT_DIRECTORY={artifact}",
                f"PRODUCTION_DEPLOY_COMMAND={deploy}",
            ]
        )
        if result.returncode != 0:
            raise AssertionError(
                f"deploy command did not receive the runtime artifact path:\n{result.stdout}\n{result.stderr}"
            )


def assert_exported_python_runtime() -> None:
    with tempfile.TemporaryDirectory(prefix="serverware-production-python-runtime-") as raw_tmp:
        artifact = Path(raw_tmp).resolve() / "artifact"
        artifact.mkdir()
        build = run(
            [
                "docker",
                "buildx",
                "build",
                "--platform",
                "linux/amd64",
                "--target",
                "production-python-runtime-artifact",
                "--build-arg",
                "SOURCE_DATE_EPOCH=1767225600",
                "--output",
                f"type=local,dest={artifact}",
                "-f",
                "Dockerfile.production",
                ".",
            ]
        )
        if build.returncode != 0:
            raise AssertionError(f"production Python runtime export failed:\n{build.stdout}\n{build.stderr}")

        python = artifact / "runtime" / "python" / "bin" / "python3"
        stdlib = artifact / "runtime" / "python" / "lib" / "python3.11"
        lib_dynload = stdlib / "lib-dynload"
        libpython = artifact / "runtime" / "python" / "lib" / "libpython3.11.so.1.0"
        vendor = artifact / "vendor"
        for path in (python, stdlib, lib_dynload, libpython, vendor):
            if not path.exists():
                raise AssertionError(f"exported production Python runtime is missing {path.relative_to(artifact)}")
        if not os.access(python, os.X_OK):
            raise AssertionError("exported production Python is not executable")
        if not any(path.is_file() for path in lib_dynload.glob("*.so")):
            raise AssertionError("exported lib-dynload contains no CPython extension modules")
        symlinks = [str(path.relative_to(artifact)) for path in artifact.rglob("*") if path.is_symlink()]
        if symlinks:
            raise AssertionError(f"exported production Python runtime contains symlinks: {symlinks[:10]}")
        generate_production_launch_manifest.validate_cpython_elf64(
            python.read_bytes(), "python3.11"
        )

        release = "/opt/serverware/release"
        smoke_code = (
            "import json,os,sys;"
            f"roots=['{release}',"
            f"'{release}/runtime/python/lib/python3.11',"
            f"'{release}/runtime/python/lib/python3.11/lib-dynload',"
            f"'{release}/vendor'];"
            "sys.path[:]=roots;sys.path_importer_cache.clear();"
            "import _ssl,cryptography;"
            "maps=open('/proc/self/maps',encoding='ascii').read();"
            f"assert '{release}/runtime/python/lib/libpython3.11.so.1.0' in maps;"
            "assert sys.path==roots;"
            "print(json.dumps({'ok':True,'version':list(sys.version_info[:2])},sort_keys=True))"
        )
        smoke_tag = f"serverware-python-runtime-smoke:{os.getpid()}"
        load = run(
            [
                "docker",
                "buildx",
                "build",
                "--platform",
                "linux/amd64",
                "--target",
                "production-python-runtime-tree",
                "--build-arg",
                "SOURCE_DATE_EPOCH=1767225600",
                "--load",
                "--tag",
                smoke_tag,
                "-f",
                "Dockerfile.production",
                ".",
            ]
        )
        if load.returncode != 0:
            raise AssertionError(f"production Python runtime smoke image failed:\n{load.stdout}\n{load.stderr}")
        try:
            smoke = run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--platform",
                    "linux/amd64",
                    "--mount",
                    f"type=bind,src={artifact},dst={release},readonly",
                    "--entrypoint",
                    f"{release}/runtime/python/bin/python3",
                    smoke_tag,
                    "-I",
                    "-c",
                    smoke_code,
                ]
            )
            if smoke.returncode != 0:
                raise AssertionError(
                    f"exported production Python smoke test failed:\n{smoke.stdout}\n{smoke.stderr}"
                )
            summary = json.loads(smoke.stdout)
            if summary != {"ok": True, "version": [3, 11]}:
                raise AssertionError(f"unexpected exported production Python summary: {summary}")
        finally:
            run(["docker", "image", "rm", "--force", smoke_tag], timeout=120)


def main() -> None:
    assert_build_contract_version()
    assert_malformed_trust_roots_fail_closed()
    assert_deterministic_launch_authority_metadata()
    assert_launch_authority_is_not_a_build_arg()
    assert_dockerfile_copies_trust_into_rust_builds()
    assert_python_runtime_docker_contract()
    assert_production_artifact_build_contract()
    assert_deploy_receives_runtime_artifact()
    assert_exported_python_runtime()
    print(json.dumps({"ok": True, "build_production_images": "pass"}, sort_keys=True))


if __name__ == "__main__":
    main()
