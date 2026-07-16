#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DEPENDENCY_DIR = ROOT / "production-dependencies"
CACHE_DIR = DEPENDENCY_DIR / "cache"

PLATFORM = "linux/amd64"
# Immutable amd64 child manifests of the multi-platform indexes used by the Dockerfiles.
PYTHON_IMAGE = (
    "python@"
    "sha256:28255a3ace7eb4c48bc1b57b90af29e1bc82b4fd6c60614a8e3dce61b87ff941"
)
RUST_DEBIAN_IMAGE = (
    "rust@"
    "sha256:a6cab604fa016ac022e78c24038497eb7617ab59150ca4c3dd2ede0fbd514d4b"
)
RUST_ALPINE_IMAGE = (
    "rust:1.88-alpine3.22@"
    "sha256:64eba3726734dcfe89e0a62a0485007a3ab7c7372ce5b38c621d8812f70215f0"
)

PYTHON_ARCHIVE = "cache/python-wheelhouse-linux-amd64.tar.gz"
CARGO_ARCHIVE = "cache/cargo-vendor.tar.gz"
MUSL_APK = "cache/musl-1.2.5-r12.apk"
MUSL_DEV_APK = "cache/musl-dev-1.2.5-r12.apk"

PYTHON_MANIFEST = DEPENDENCY_DIR / "python-linux-amd64.sha256"
RUST_MANIFEST = DEPENDENCY_DIR / "rust-linux-amd64.sha256"
PYTHON_INPUTS = ("requirements.lock", PYTHON_ARCHIVE)
RUST_INPUTS = (
    "data-plane/decision-gate-rs/Cargo.toml",
    "data-plane/decision-gate-rs/Cargo.lock",
    CARGO_ARCHIVE,
    MUSL_APK,
    MUSL_DEV_APK,
)


def run(command: list[str]) -> None:
    subprocess.run(command, cwd=ROOT, check=True)


def docker_run(image: str, scratch: Path, command: list[str]) -> None:
    run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            PLATFORM,
            "--mount",
            f"type=bind,src={ROOT},dst=/workspace,readonly",
            "--mount",
            f"type=bind,src={scratch},dst=/scratch",
            "--workdir",
            "/workspace",
            image,
            *command,
        ]
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def input_path(relative: str) -> Path:
    relative_path = Path(relative)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise RuntimeError(f"invalid dependency input path: {relative}")
    base = DEPENDENCY_DIR if relative_path.parts[0] == "cache" else ROOT
    path = (base / relative_path).resolve()
    if base not in path.parents:
        raise RuntimeError(f"dependency input escapes its base directory: {relative}")
    return path


def manifest_text(inputs: tuple[str, ...]) -> str:
    return "".join(f"{sha256(input_path(path))}  {path}\n" for path in inputs)


def verify_manifest(path: Path, inputs: tuple[str, ...]) -> None:
    if not path.is_file():
        raise RuntimeError(f"missing pinned dependency manifest: {path.relative_to(ROOT)}")
    expected = manifest_text(inputs)
    actual = path.read_text(encoding="ascii")
    if actual != expected:
        raise RuntimeError(
            f"dependency cache does not match {path.relative_to(ROOT)}; "
            "run refresh only for an intentional dependency update"
        )


def verify() -> None:
    verify_manifest(PYTHON_MANIFEST, PYTHON_INPUTS)
    verify_manifest(RUST_MANIFEST, RUST_INPUTS)


def fetch() -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".prefetch-", dir=DEPENDENCY_DIR) as raw_scratch:
        scratch = Path(raw_scratch).resolve()
        docker_run(
            PYTHON_IMAGE,
            scratch,
            [
                "sh",
                "-ec",
                "python -m pip download --quiet --disable-pip-version-check "
                "--only-binary=:all: --require-hashes "
                "--dest /scratch/wheelhouse -r /workspace/requirements.lock; "
                "tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner "
                "-cf - -C /scratch wheelhouse | gzip -n > "
                "/scratch/python-wheelhouse-linux-amd64.tar.gz",
            ],
        )
        docker_run(
            RUST_DEBIAN_IMAGE,
            scratch,
            [
                "sh",
                "-ec",
                "cargo vendor --quiet --locked --versioned-dirs "
                "--manifest-path /workspace/data-plane/decision-gate-rs/Cargo.toml "
                "/scratch/vendor >/dev/null; "
                "tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner "
                "-cf - -C /scratch vendor | gzip -n > /scratch/cargo-vendor.tar.gz",
            ],
        )
        docker_run(
            RUST_ALPINE_IMAGE,
            scratch,
            [
                "sh",
                "-ec",
                "apk update >/dev/null; "
                "apk fetch --output /scratch musl musl-dev",
            ],
        )

        generated = {
            PYTHON_ARCHIVE: scratch / "python-wheelhouse-linux-amd64.tar.gz",
            CARGO_ARCHIVE: scratch / "cargo-vendor.tar.gz",
            MUSL_APK: scratch / "musl-1.2.5-r12.apk",
            MUSL_DEV_APK: scratch / "musl-dev-1.2.5-r12.apk",
        }
        for relative, source in generated.items():
            if not source.is_file():
                raise RuntimeError(f"prefetch did not produce {source.name}")
            destination = input_path(relative)
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_suffix(destination.suffix + ".tmp")
            shutil.copyfile(source, temporary)
            temporary.replace(destination)


def refresh_manifests() -> None:
    PYTHON_MANIFEST.write_text(manifest_text(PYTHON_INPUTS), encoding="ascii")
    RUST_MANIFEST.write_text(manifest_text(RUST_INPUTS), encoding="ascii")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prefetch and verify pinned offline production build dependencies."
    )
    parser.add_argument("action", choices=("fetch", "verify", "refresh"))
    args = parser.parse_args()

    if args.action == "verify":
        verify()
        return

    fetch()
    if args.action == "refresh":
        refresh_manifests()
    verify()


if __name__ == "__main__":
    main()
