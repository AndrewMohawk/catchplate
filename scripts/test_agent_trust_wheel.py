#!/usr/bin/env python3
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
EVIDENCE_SOURCE = Path("scripts/verify_onboarding_evidence.py")
EVIDENCE_MODULE = Path("catchplate_agent_trust/onboarding_evidence.py")
EVIDENCE_ENTRY_POINT = (
    "catchplate-evidence = catchplate_agent_trust.onboarding_evidence:main"
)


def _run(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def _record_digest(value: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(value).digest()).decode("ascii")
    return "sha256=" + encoded.rstrip("=")


def _build_wheel(
    python: str,
    source: Path,
    destination: Path,
    *,
    env: dict[str, str],
) -> Path:
    _run(
        [
            python,
            "-m",
            "pip",
            "wheel",
            "--no-build-isolation",
            "--no-deps",
            "--no-index",
            "--wheel-dir",
            str(destination),
            str(source),
        ],
        cwd=source.parent,
        env=env,
    )
    wheels = sorted(destination.glob("catchplate_enrollment-*.whl"))
    if len(wheels) != 1:
        raise AssertionError(f"expected one custom wheel, found: {wheels}")
    return wheels[0]


def _verify_wheel(wheel: Path) -> None:
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        if names != sorted(names):
            raise AssertionError("wheel members are not sorted")
        module_name = EVIDENCE_MODULE.as_posix()
        if names.count(module_name) != 1:
            raise AssertionError(f"expected one packaged verifier module: {names}")
        if EVIDENCE_SOURCE.as_posix() in names:
            raise AssertionError("wheel duplicated the verifier under scripts/")
        if archive.read(module_name) != (ROOT / EVIDENCE_SOURCE).read_bytes():
            raise AssertionError("packaged verifier differs from its canonical source")

        entry_points_name = next(
            name for name in names if name.endswith(".dist-info/entry_points.txt")
        )
        entry_points = archive.read(entry_points_name).decode("ascii").splitlines()
        if entry_points.count(EVIDENCE_ENTRY_POINT) != 1:
            raise AssertionError(f"missing evidence entry point: {entry_points}")

        record_name = next(name for name in names if name.endswith(".dist-info/RECORD"))
        rows = {
            row[0]: (row[1], row[2])
            for row in csv.reader(io.StringIO(archive.read(record_name).decode("ascii")))
        }
        if set(rows) != set(names):
            raise AssertionError(
                f"RECORD member mismatch: missing={set(names) - set(rows)}, "
                f"extra={set(rows) - set(names)}"
            )
        for name in names:
            digest, size = rows[name]
            if name == record_name:
                if (digest, size) != ("", ""):
                    raise AssertionError("RECORD must leave its own digest and size empty")
                continue
            value = archive.read(name)
            if digest != _record_digest(value) or size != str(len(value)):
                raise AssertionError(f"invalid RECORD entry for {name}")


def main() -> None:
    python = getattr(sys, "_base_executable", None) or shutil.which("python3") or sys.executable
    with tempfile.TemporaryDirectory(prefix="catchplate-agent-trust-wheel-") as tmp:
        temporary = Path(tmp)
        source = temporary / "source"
        source.mkdir()
        shutil.copy2(ROOT / "pyproject.toml", source / "pyproject.toml")
        shutil.copytree(ROOT / "catchplate_agent_trust", source / "catchplate_agent_trust")
        (source / "scripts").mkdir()
        shutil.copy2(ROOT / EVIDENCE_SOURCE, source / EVIDENCE_SOURCE)

        environment = os.environ.copy()
        environment["SOURCE_DATE_EPOCH"] = "1767225600"
        environment["PIP_CONFIG_FILE"] = os.devnull
        environment["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
        first_directory = temporary / "wheel-first"
        second_directory = temporary / "wheel-second"
        first_directory.mkdir()
        second_directory.mkdir()
        first = _build_wheel(python, source, first_directory, env=environment)
        second = _build_wheel(python, source, second_directory, env=environment)
        if first.name != second.name or first.read_bytes() != second.read_bytes():
            raise AssertionError(
                "repeated wheel builds are not byte-for-byte reproducible: "
                f"{hashlib.sha256(first.read_bytes()).hexdigest()} != "
                f"{hashlib.sha256(second.read_bytes()).hexdigest()}"
            )
        _verify_wheel(first)

        venv = temporary / "venv"
        _run(
            [python, "-m", "venv", "--system-site-packages", str(venv)],
            cwd=temporary,
            env=environment,
        )
        scripts = venv / ("Scripts" if os.name == "nt" else "bin")
        venv_python = scripts / ("python.exe" if os.name == "nt" else "python")
        install_environment = environment.copy()
        install_environment["PIP_NO_INDEX"] = "1"
        install_environment["PYTHONNOUSERSITE"] = "1"
        _run(
            [
                str(venv_python),
                "-m",
                "pip",
                "install",
                "--no-index",
                "--no-deps",
                str(first),
            ],
            cwd=temporary,
            env=install_environment,
        )

        executable = scripts / (
            "catchplate-evidence.exe" if os.name == "nt" else "catchplate-evidence"
        )
        help_result = _run(
            [str(executable), "--help"],
            cwd=temporary,
            env=install_environment,
        )
        if "local-integrity-only" not in help_result.stdout:
            raise AssertionError(help_result.stdout)
        if "execution, server, provenance, or TEE attestation" not in help_result.stdout:
            raise AssertionError(help_result.stdout)

        installed = _run(
            [
                str(venv_python),
                "-c",
                (
                    "import importlib.metadata as metadata,json;"
                    "import catchplate_agent_trust.onboarding_evidence as evidence;"
                    "distribution=metadata.distribution('catchplate-enrollment');"
                    "print(json.dumps({'module':evidence.__file__,"
                    "'classification':evidence.ASSURANCE['classification'],"
                    "'entryPoints':sorted("
                    "[{'name':entry.name,'value':entry.value} "
                    "for entry in distribution.entry_points "
                    "if entry.group=='console_scripts'],"
                    "key=lambda entry:(entry['name'],entry['value']))}))"
                ),
            ],
            cwd=temporary,
            env=install_environment,
        )
        facts = json.loads(installed.stdout)
        if str(ROOT) in facts["module"]:
            raise AssertionError(f"verifier imported from repository: {facts}")
        if facts["classification"] != "local-integrity-only":
            raise AssertionError(f"assurance label changed: {facts}")
        if {
            "name": "catchplate-evidence",
            "value": "catchplate_agent_trust.onboarding_evidence:main",
        } not in facts["entryPoints"]:
            raise AssertionError(f"installed entry point missing: {facts}")

        print(
            json.dumps(
                {
                    "ok": True,
                    "wheel": first.name,
                    "sha256": hashlib.sha256(first.read_bytes()).hexdigest(),
                    "catchplateEvidenceHelp": "pass",
                    "record": "pass",
                    "reproducible": True,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )


if __name__ == "__main__":
    main()
