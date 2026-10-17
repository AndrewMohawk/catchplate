"""Minimal agent-side Catchplate enrollment and attestation trust tools."""

from __future__ import annotations

import importlib.metadata
from functools import lru_cache
import re
import tomllib
from pathlib import Path


ENROLLMENT_TOOLING_API_VERSION = "catchplate.agentEnrollmentTooling/v1"
PROJECT_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
PROJECT_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+!-]*$")


def _validate_project_identity(name: object, version: object) -> tuple[str, str]:
    if (
        not isinstance(name, str)
        or not name
        or name.strip() != name
        or not name.isascii()
        or PROJECT_NAME_RE.fullmatch(name) is None
    ):
        raise RuntimeError("catchplate enrollment package name is invalid")
    if (
        not isinstance(version, str)
        or not version
        or version.strip() != version
        or not version.isascii()
        or PROJECT_VERSION_RE.fullmatch(version) is None
    ):
        raise RuntimeError("catchplate enrollment package version is invalid")
    return name, version


def _project_identity() -> tuple[str, str]:
    source_metadata = Path(__file__).resolve().parent.parent / "pyproject.toml"
    if source_metadata.is_file():
        project = tomllib.loads(source_metadata.read_text(encoding="utf-8")).get("project")
        if not isinstance(project, dict):
            raise RuntimeError("source pyproject.toml is missing [project] metadata")
        return _validate_project_identity(project.get("name"), project.get("version"))

    package_name = __name__.split(".", 1)[0]
    distribution_names = sorted(set(importlib.metadata.packages_distributions().get(package_name, ())))
    if len(distribution_names) != 1:
        raise RuntimeError(
            "installed catchplate enrollment package must map to exactly one distribution"
        )
    distribution = importlib.metadata.distribution(distribution_names[0])
    return _validate_project_identity(distribution.metadata.get("Name"), distribution.version)


@lru_cache(maxsize=1)
def _tooling_identity() -> tuple[str, str]:
    # Public-original parsers also run from measured sealed source descriptors.
    # Package metadata is required only when the tooling identity is requested.
    # Cache successful strict discovery, never a missing-metadata substitute.
    return _project_identity()


def __getattr__(name: str) -> str:
    if name not in {"DISTRIBUTION_NAME", "__version__", "ENROLLMENT_CLI_COMMAND"}:
        raise AttributeError(name)
    distribution, version = _tooling_identity()
    return version if name == "__version__" else distribution


def enrollment_tooling_contract() -> dict[str, object]:
    distribution, version = _tooling_identity()
    expected_output = f"{distribution} {version}"
    return {
        "apiVersion": ENROLLMENT_TOOLING_API_VERSION,
        "command": distribution,
        "distribution": distribution,
        "version": version,
        "versionCheck": [distribution, "--version"],
        "expectedVersionOutput": expected_output,
    }


def validate_enrollment_tooling(packet: object) -> dict[str, object]:
    if not isinstance(packet, dict):
        raise ValueError("enrollment packet must be a JSON object")
    tooling = packet.get("tooling")
    if not isinstance(tooling, dict):
        raise ValueError("enrollment packet is missing the required tooling contract")
    expected = enrollment_tooling_contract()
    if set(tooling) != set(expected):
        raise ValueError("enrollment tooling contract fields do not match the closed schema")
    if tooling.get("apiVersion") != ENROLLMENT_TOOLING_API_VERSION:
        raise ValueError("enrollment tooling contract API version is unsupported")
    if tooling.get("command") != expected["command"]:
        raise ValueError("enrollment tooling contract requires an unsupported command")
    if tooling.get("distribution") != expected["distribution"]:
        raise ValueError("enrollment tooling contract requires an unsupported distribution")
    required_version = tooling.get("version")
    if required_version != expected["version"]:
        raise ValueError(
            f"enrollment packet requires {expected['command']} version "
            f"{required_version!r}; running version is {expected['version']!r}"
        )
    if tooling.get("versionCheck") != expected["versionCheck"]:
        raise ValueError("enrollment tooling contract version check invocation is invalid")
    if tooling.get("expectedVersionOutput") != expected["expectedVersionOutput"]:
        raise ValueError("enrollment tooling contract expected version output is invalid")
    return tooling
