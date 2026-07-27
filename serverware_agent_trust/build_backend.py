from __future__ import annotations

import base64
import csv
import hashlib
import io
import os
import re
import time
import zipfile
from pathlib import Path

from . import DISTRIBUTION_NAME, ENROLLMENT_CLI_COMMAND, __version__


NAME = DISTRIBUTION_NAME
NORMALIZED_NAME = re.sub(r"[-_.]+", "_", NAME)
VERSION = __version__
NORMALIZED_VERSION = re.sub(r"[^A-Za-z0-9.]+", "_", VERSION)
DIST_INFO = f"{NORMALIZED_NAME}-{NORMALIZED_VERSION}.dist-info"
WHEEL_NAME = f"{NORMALIZED_NAME}-{NORMALIZED_VERSION}-py3-none-any.whl"
ONBOARDING_EVIDENCE_SOURCE = Path("scripts/verify_onboarding_evidence.py")
ONBOARDING_EVIDENCE_MODULE = Path("serverware_agent_trust/onboarding_evidence.py")


def _metadata() -> bytes:
    return (
        "Metadata-Version: 2.3\n"
        f"Name: {NAME}\n"
        f"Version: {VERSION}\n"
        "Summary: Clean-room Serverware enrollment and attestation verification commands\n"
        "Requires-Python: >=3.11\n"
        "Requires-Dist: cryptography==48.0.1\n"
        "\n"
    ).encode("ascii")


def _wheel_metadata() -> bytes:
    return (
        "Wheel-Version: 1.0\n"
        "Generator: serverware-agent-trust-build-backend\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n"
        "\n"
    ).encode("ascii")


def _entry_points() -> bytes:
    return (
        "[console_scripts]\n"
        "serverware-attestation = serverware_agent_trust.attestation:console_main\n"
        "serverware-evidence = serverware_agent_trust.onboarding_evidence:main\n"
        f"{ENROLLMENT_CLI_COMMAND} = serverware_agent_trust.enrollment:console_main\n"
    ).encode("ascii")


def _record_digest(value: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(value).digest()).decode("ascii")
    return "sha256=" + encoded.rstrip("=")


def _zip_timestamp() -> tuple[int, int, int, int, int, int]:
    raw = os.getenv("SOURCE_DATE_EPOCH", "315532800")
    try:
        epoch = int(raw)
    except ValueError as exc:
        raise ValueError("SOURCE_DATE_EPOCH must be an integer") from exc
    epoch = min(max(epoch, 315532800), 4354819198)
    value = time.gmtime(epoch)
    return value.tm_year, value.tm_mon, value.tm_mday, value.tm_hour, value.tm_min, value.tm_sec


def _wheel_files(root: Path) -> dict[str, bytes]:
    package = root / "serverware_agent_trust"
    files = {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(package.glob("*.py"))
        if path.is_file()
    }
    if "serverware_agent_trust/__init__.py" not in files:
        raise ValueError("clean-room package is missing serverware_agent_trust/__init__.py")
    evidence_source = root / ONBOARDING_EVIDENCE_SOURCE
    if not evidence_source.is_file():
        raise ValueError(
            "clean-room package is missing canonical onboarding evidence source "
            f"{ONBOARDING_EVIDENCE_SOURCE.as_posix()}"
        )
    evidence_module = ONBOARDING_EVIDENCE_MODULE.as_posix()
    if evidence_module in files:
        raise ValueError(
            f"{evidence_module} must be sourced only from "
            f"{ONBOARDING_EVIDENCE_SOURCE.as_posix()}"
        )
    files[evidence_module] = evidence_source.read_bytes()
    files[f"{DIST_INFO}/METADATA"] = _metadata()
    files[f"{DIST_INFO}/WHEEL"] = _wheel_metadata()
    files[f"{DIST_INFO}/entry_points.txt"] = _entry_points()
    return files


def _record(files: dict[str, bytes]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for path in sorted(files):
        value = files[path]
        writer.writerow((path, _record_digest(value), len(value)))
    writer.writerow((f"{DIST_INFO}/RECORD", "", ""))
    return output.getvalue().encode("ascii")


def _write_member(archive: zipfile.ZipFile, path: str, value: bytes) -> None:
    info = zipfile.ZipInfo(path, _zip_timestamp())
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    archive.writestr(info, value)


def build_wheel(
    wheel_directory: str,
    config_settings: dict[str, object] | None = None,
    metadata_directory: str | None = None,
) -> str:
    del config_settings, metadata_directory
    root = Path.cwd()
    files = _wheel_files(root)
    files[f"{DIST_INFO}/RECORD"] = _record(files)
    destination = Path(wheel_directory)
    destination.mkdir(parents=True, exist_ok=True)
    wheel_path = destination / WHEEL_NAME
    with zipfile.ZipFile(wheel_path, "w") as archive:
        for path in sorted(files):
            _write_member(archive, path, files[path])
    return WHEEL_NAME


def prepare_metadata_for_build_wheel(
    metadata_directory: str,
    config_settings: dict[str, object] | None = None,
) -> str:
    del config_settings
    destination = Path(metadata_directory) / DIST_INFO
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "METADATA").write_bytes(_metadata())
    (destination / "WHEEL").write_bytes(_wheel_metadata())
    (destination / "entry_points.txt").write_bytes(_entry_points())
    return DIST_INFO
