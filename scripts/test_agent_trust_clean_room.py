#!/usr/bin/env python3
"""Validate the agent-trust wheelhouse in a networkless Docker clean room.

This is checksum-closed local validation. It does not establish source
provenance, image provenance, independent execution, or TEE attestation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
VERIFIER = ROOT / "scripts" / "verify_offline_artifact_manifest.py"
DEFAULT_IMAGE = "docker.io/library/python:3.11.15-slim-bookworm"
MANIFEST_NAME = "wheelhouse-manifest.json"
CHECKSUMS_NAME = "SHA256SUMS"
REQUIREMENTS_NAME = "requirements.lock"
EXPECTED_LABEL = "serverware-enrollment-cpython311-linux-amd64"
EXPECTED_TARGET = {
    "implementation": "cp",
    "python_tag": "cp311",
    "platform_tag": "manylinux2014_x86_64",
    "architecture": "amd64",
}
EXPECTED_UID = 65532
EXPECTED_GID = 65532
TMPFS_BYTES = 256 * 1024 * 1024
RESULT_PREFIX = "SERVERWARE_CLEAN_ROOM_RESULT="
ASSURANCE_CLASSIFICATION = "checksum-closed-local-clean-room-validation"
PACKAGE_WHEEL_RE = re.compile(
    r"^serverware_enrollment-[A-Za-z0-9][A-Za-z0-9._+]*-py3-none-any\.whl$"
)
LOCK_REQUIREMENT_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9][A-Za-z0-9._+!-]*)"
)
OFFICIAL_IMAGE_RE = re.compile(
    r"^docker\.io/library/python:"
    r"3\.11\.[0-9]+-slim-(?:bookworm|bullseye)"
    r"(?:@sha256:[0-9a-f]{64})?$"
)
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


CONTAINER_SCRIPT = r"""
set -eu

fail() {
    printf '%s\n' "$1" >&2
    exit 1
}

run_logged() {
    label="$1"
    shift
    if ! "$@" >"/work/${label}.log" 2>&1; then
        printf '%s\n' "${label} failed:" >&2
        cat "/work/${label}.log" >&2
        exit 1
    fi
}

[ "$(id -u)" = "${EXPECTED_UID}" ] || fail "clean-room process is not the required non-root UID"
[ "$(id -g)" = "${EXPECTED_GID}" ] || fail "clean-room process is not the required non-root GID"

if (umask 077; : > /wheelhouse/.serverware-write-probe) 2>/work/mount-write-probe.log; then
    rm -f /wheelhouse/.serverware-write-probe
    fail "wheelhouse bind mount is writable"
fi

mkdir -p /work/home /work/tmp

python3 -I - <<'PY'
from __future__ import annotations

import json
import os
import platform
import re
import sys
from pathlib import Path


def mount_record(target: str) -> dict[str, object]:
    for raw in Path("/proc/self/mountinfo").read_text(encoding="ascii").splitlines():
        before, separator, after = raw.partition(" - ")
        if not separator:
            continue
        fields = before.split()
        if len(fields) < 6 or fields[4] != target:
            continue
        trailing = after.split()
        if len(trailing) < 3:
            raise SystemExit(f"mountinfo record for {target} is incomplete")
        return {
            "filesystem": trailing[0],
            "options": sorted(set(fields[5].split(","))),
            "superOptions": sorted(set(trailing[2].split(","))),
        }
    raise SystemExit(f"required mount is missing: {target}")


def tmpfs_size(record: dict[str, object]) -> int:
    for option in record["superOptions"]:
        if not option.startswith("size="):
            continue
        value = option.removeprefix("size=")
        match = re.fullmatch(r"([0-9]+)([kKmMgG]?)", value)
        if match is None:
            raise SystemExit(f"tmpfs size is not parseable: {value}")
        scale = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}
        return int(match.group(1)) * scale[match.group(2).lower()]
    raise SystemExit("tmpfs mount does not expose a size limit")


if os.getuid() == 0:
    raise SystemExit("clean-room process is running as root")
if platform.python_implementation() != "CPython" or sys.version_info[:2] != (3, 11):
    raise SystemExit("clean-room image is not CPython 3.11")
if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
    raise SystemExit("clean-room image is not Linux amd64")

mounts = {
    "/": mount_record("/"),
    "/wheelhouse": mount_record("/wheelhouse"),
    "/work": mount_record("/work"),
}
if "ro" not in mounts["/"]["options"]:
    raise SystemExit("container root filesystem is not read-only")
if "ro" not in mounts["/wheelhouse"]["options"]:
    raise SystemExit("wheelhouse bind mount is not read-only")
if mounts["/work"]["filesystem"] != "tmpfs" or "rw" not in mounts["/work"]["options"]:
    raise SystemExit("clean-room work directory is not a writable tmpfs")
if not {"nosuid", "nodev"}.issubset(set(mounts["/work"]["options"])):
    raise SystemExit("clean-room tmpfs is missing nosuid or nodev")
size = tmpfs_size(mounts["/work"])
expected_size = int(os.environ["EXPECTED_TMPFS_BYTES"])
if size <= 0 or size > expected_size:
    raise SystemExit(f"clean-room tmpfs exceeds its bound: {size} > {expected_size}")

status = {}
for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
    key, separator, value = line.partition(":")
    if separator:
        status[key] = value.strip()
for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
    if int(status.get(field, "-1"), 16) != 0:
        raise SystemExit(f"container retained Linux capabilities: {field}")
if status.get("NoNewPrivs") != "1":
    raise SystemExit("no-new-privileges is not active")
if status.get("Seccomp") != "2":
    raise SystemExit("the Docker seccomp filter is not active")

interfaces = sorted(
    line.split(":", 1)[0].strip()
    for line in Path("/proc/net/dev").read_text(encoding="ascii").splitlines()
    if ":" in line
)
if "lo" not in interfaces:
    raise SystemExit("network-none container has no loopback interface")
interface_states = {
    name: Path(f"/sys/class/net/{name}/operstate")
    .read_text(encoding="ascii")
    .strip()
    for name in interfaces
}
active_non_loopback = {
    name: state
    for name, state in interface_states.items()
    if name != "lo" and state != "down"
}
if active_non_loopback:
    raise SystemExit(
        "network-none container exposed active non-loopback interfaces: "
        f"{active_non_loopback}"
    )
ipv4_route_interfaces = {
    line.split()[0]
    for line in Path("/proc/net/route").read_text(encoding="ascii").splitlines()[1:]
    if line.split()
}
ipv6_route_interfaces = {
    fields[-1]
    for line in Path("/proc/net/ipv6_route").read_text(encoding="ascii").splitlines()
    if len(fields := line.split()) >= 10
}
non_loopback_routes = sorted(
    (ipv4_route_interfaces | ipv6_route_interfaces) - {"lo"}
)
if non_loopback_routes:
    raise SystemExit(
        "network-none container exposed non-loopback routes: "
        f"{non_loopback_routes}"
    )

Path("/work/preflight.json").write_text(
    json.dumps(
        {
            "capabilities": "none",
            "gid": os.getgid(),
            "interfaceStates": interface_states,
            "machine": platform.machine(),
            "mounts": mounts,
            "nonLoopbackRoutes": non_loopback_routes,
            "noNewPrivileges": True,
            "python": platform.python_version(),
            "seccomp": "filter",
            "system": platform.system(),
            "tmpfsBytes": size,
            "uid": os.getuid(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ),
    encoding="ascii",
)
PY

run_logged venv python3 -I -m venv --copies /work/venv
run_logged dependencies \
    /work/venv/bin/python -I -m pip --isolated install \
    --no-index \
    --no-cache-dir \
    --no-compile \
    --require-hashes \
    --only-binary=:all: \
    --find-links=/wheelhouse \
    --requirement=/wheelhouse/requirements.lock
run_logged package \
    /work/venv/bin/python -I -m pip --isolated install \
    --no-index \
    --no-cache-dir \
    --no-compile \
    --no-deps \
    "/wheelhouse/${PACKAGE_WHEEL}"

run_logged enrollment-help /work/venv/bin/serverware-enrollment --help
run_logged attestation-help /work/venv/bin/serverware-attestation --help
run_logged evidence-help /work/venv/bin/serverware-evidence --help

[ -s /work/enrollment-help.log ] || fail "serverware-enrollment --help returned no output"
[ -s /work/attestation-help.log ] || fail "serverware-attestation --help returned no output"
[ -s /work/evidence-help.log ] || fail "serverware-evidence --help returned no output"
grep -F "local-integrity-only" /work/evidence-help.log >/dev/null ||
    fail "serverware-evidence no longer discloses local-integrity-only assurance"
grep -F "execution, server, provenance, or TEE attestation" /work/evidence-help.log >/dev/null ||
    fail "serverware-evidence no longer discloses its assurance exclusions"

/work/venv/bin/python -I - <<'PY'
from __future__ import annotations

import importlib.metadata
import json
from pathlib import Path

import cryptography
import serverware_agent_trust


preflight = json.loads(Path("/work/preflight.json").read_text(encoding="ascii"))
distribution = importlib.metadata.distribution("serverware-enrollment")
if distribution.version != serverware_agent_trust.__version__:
    raise SystemExit("imported package version differs from installed distribution")
if serverware_agent_trust.DISTRIBUTION_NAME != "serverware-enrollment":
    raise SystemExit("imported distribution name is unexpected")

entry_points = sorted(
    entry.name
    for entry in distribution.entry_points
    if entry.group == "console_scripts"
)
expected_entry_points = [
    "serverware-attestation",
    "serverware-enrollment",
    "serverware-evidence",
]
if entry_points != expected_entry_points:
    raise SystemExit(f"installed console entry points are incomplete: {entry_points}")

print(
    "SERVERWARE_CLEAN_ROOM_RESULT="
    + json.dumps(
        {
            "assurance": {
                "classification": "checksum-closed-local-clean-room-validation",
                "notEstablished": [
                    "image-provenance",
                    "independent-execution",
                    "source-provenance",
                    "tee-attestation",
                ],
            },
            "commands": {
                "serverware-attestation --help": "pass",
                "serverware-enrollment --help": "pass",
                "serverware-evidence --help": "pass",
            },
            "cryptographyVersion": cryptography.__version__,
            "entryPoints": entry_points,
            "package": {
                "distribution": serverware_agent_trust.DISTRIBUTION_NAME,
                "import": "pass",
                "version": serverware_agent_trust.__version__,
            },
            "runtime": preflight,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
)
PY
"""


class ValidationError(RuntimeError):
    pass


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"JSON document contains duplicate key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise ValidationError(f"JSON document contains non-standard constant: {value}")


def _load_json_text(value: str, label: str) -> Any:
    try:
        return json.loads(
            value,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ValidationError(f"{label} is not strict JSON: {exc}") from exc


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _stable_sha256(path: Path) -> tuple[int, str]:
    if not hasattr(os, "O_NOFOLLOW"):
        raise ValidationError("this platform cannot reject symlinks while hashing")
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW,
        )
    except OSError as exc:
        raise ValidationError(f"cannot open regular file without following links: {path}") from exc
    digest = hashlib.sha256()
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValidationError(f"required path is not a regular file: {path}")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        if _file_identity(before) != _file_identity(after):
            raise ValidationError(f"file changed while it was hashed: {path}")
        return before.st_size, digest.hexdigest()
    finally:
        os.close(descriptor)


def _run_checked(
    command: list[str],
    *,
    label: str,
    timeout: int,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise ValidationError(f"{label} executable is unavailable: {command[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ValidationError(f"{label} timed out after {timeout} seconds") from exc
    if result.returncode != 0:
        details = "\n".join(
            section
            for section in (
                result.stdout.strip(),
                result.stderr.strip(),
            )
            if section
        )
        suffix = f"\n{details}" if details else ""
        raise ValidationError(f"{label} failed with exit code {result.returncode}{suffix}")
    return result


def _validate_wheelhouse_root(value: Path) -> Path:
    candidate = value.expanduser().absolute()
    if candidate.is_symlink() or not candidate.is_dir():
        raise ValidationError(f"wheelhouse must be a real directory: {candidate}")
    root = candidate.resolve()
    if "," in str(root) or "\n" in str(root) or "\r" in str(root):
        raise ValidationError("wheelhouse path cannot be represented safely as a Docker bind mount")
    return root


def _invoke_repository_verifier(root: Path, *, timeout: int) -> dict[str, Any]:
    result = _run_checked(
        [
            sys.executable,
            "-I",
            str(VERIFIER),
            "--root",
            str(root),
            "--manifest",
            str(root / MANIFEST_NAME),
            "--checksums",
            str(root / CHECKSUMS_NAME),
            "--label",
            EXPECTED_LABEL,
            "--python-tag",
            EXPECTED_TARGET["python_tag"],
            "--platform-tag",
            EXPECTED_TARGET["platform_tag"],
            "--architecture",
            EXPECTED_TARGET["architecture"],
        ],
        label="strict wheelhouse verification",
        timeout=timeout,
        cwd=ROOT,
    )
    document = _load_json_text(result.stdout, "strict verifier output")
    expected_fields = {
        "checksums_sha256",
        "files",
        "manifest_sha256",
        "ok",
        "target",
    }
    if not isinstance(document, dict) or set(document) != expected_fields:
        raise ValidationError("strict verifier output fields are incomplete or unknown")
    if document["ok"] is not True or document["target"] != EXPECTED_TARGET:
        raise ValidationError("strict verifier did not confirm the required Linux amd64 target")
    return document


def _read_manifest(root: Path) -> dict[str, Any]:
    size, _ = _stable_sha256(root / MANIFEST_NAME)
    if size > 1024 * 1024:
        raise ValidationError("wheelhouse manifest exceeds the 1 MiB limit")
    try:
        raw = (root / MANIFEST_NAME).read_bytes()
        document = _load_json_text(raw.decode("ascii"), "wheelhouse manifest")
    except (OSError, UnicodeError) as exc:
        raise ValidationError(f"cannot read wheelhouse manifest: {exc}") from exc
    if not isinstance(document, dict):
        raise ValidationError("wheelhouse manifest root is not an object")
    if document.get("label") != EXPECTED_LABEL or document.get("target") != EXPECTED_TARGET:
        raise ValidationError("wheelhouse manifest is not the required Linux amd64 closure")
    return document


def _locked_dependencies(root: Path) -> list[str]:
    try:
        text = (root / REQUIREMENTS_NAME).read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise ValidationError(f"cannot read {REQUIREMENTS_NAME}: {exc}") from exc
    names = [
        re.sub(r"[-_.]+", "_", match.group(1)).lower()
        for line in text.splitlines()
        if (match := LOCK_REQUIREMENT_RE.match(line)) is not None
    ]
    if not names or len(names) != len(set(names)):
        raise ValidationError("requirements.lock has no unique, pinned dependency set")
    return sorted(names)


def _select_package_wheel(root: Path, manifest: dict[str, Any]) -> tuple[str, str]:
    files = manifest.get("files")
    if not isinstance(files, list):
        raise ValidationError("wheelhouse manifest has no file closure")
    names = [
        entry.get("path")
        for entry in files
        if isinstance(entry, dict) and isinstance(entry.get("path"), str)
    ]
    if len(names) != len(files):
        raise ValidationError("wheelhouse manifest contains malformed file entries")
    package_wheels = [name for name in names if PACKAGE_WHEEL_RE.fullmatch(name)]
    if len(package_wheels) != 1:
        raise ValidationError(
            f"wheelhouse must contain exactly one Serverware package wheel: {package_wheels}"
        )
    if names.count(REQUIREMENTS_NAME) != 1:
        raise ValidationError("wheelhouse must contain exactly one requirements.lock")

    dependency_wheels = [
        name for name in names if name.endswith(".whl") and name not in package_wheels
    ]
    expected_dependencies = _locked_dependencies(root)
    matched: set[str] = set()
    for dependency in expected_dependencies:
        matches = [
            wheel
            for wheel in dependency_wheels
            if wheel.lower().startswith(dependency + "-")
        ]
        if len(matches) != 1:
            raise ValidationError(
                f"locked dependency must map to exactly one wheel: {dependency} -> {matches}"
            )
        matched.update(matches)
    expected_names = {
        REQUIREMENTS_NAME,
        package_wheels[0],
        *matched,
    }
    if set(names) != expected_names:
        raise ValidationError(
            "wheelhouse contains artifacts outside the exact package and dependency closure: "
            f"{sorted(set(names) - expected_names)}"
        )

    manifest_entry = next(entry for entry in files if entry["path"] == package_wheels[0])
    digest = manifest_entry.get("sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValidationError("Serverware package wheel has no valid manifest digest")
    return package_wheels[0], digest


def _copy_stable(source: Path, destination: Path) -> None:
    if not hasattr(os, "O_NOFOLLOW"):
        raise ValidationError("this platform cannot snapshot without following symlinks")
    source_fd = os.open(
        source,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW,
    )
    destination_fd = -1
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValidationError(f"snapshot source is not a regular file: {source}")
        destination_fd = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | os.O_NOFOLLOW,
            0o400,
        )
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                view = view[written:]
        os.fsync(destination_fd)
        after = os.fstat(source_fd)
        if _file_identity(before) != _file_identity(after):
            raise ValidationError(f"wheelhouse changed while it was snapshotted: {source.name}")
    finally:
        os.close(source_fd)
        if destination_fd >= 0:
            os.close(destination_fd)


def _snapshot_wheelhouse(source: Path) -> Path:
    snapshot = Path(
        tempfile.mkdtemp(prefix=".agent-trust-clean-room-", dir=source.parent)
    ).resolve()
    try:
        for path in sorted(source.iterdir(), key=lambda item: item.name):
            _copy_stable(path, snapshot / path.name)
        for path in snapshot.iterdir():
            path.chmod(0o444)
        snapshot.chmod(0o555)
        return snapshot
    except BaseException:
        _remove_snapshot(snapshot)
        raise


def _remove_snapshot(snapshot: Path) -> None:
    if not snapshot.exists():
        return
    try:
        snapshot.chmod(0o700)
        for path in snapshot.iterdir():
            try:
                path.chmod(0o600)
            except OSError:
                pass
    finally:
        shutil.rmtree(snapshot, ignore_errors=False)


def _validate_image_reference(image: str) -> None:
    if not OFFICIAL_IMAGE_RE.fullmatch(image):
        raise ValidationError(
            "image must use the official docker.io/library/python namespace and an "
            "exact CPython 3.11 patch-level slim Bookworm or Bullseye tag"
        )


def _inspect_image(
    docker: str,
    image: str,
    *,
    timeout: int,
) -> tuple[str, dict[str, Any]]:
    _validate_image_reference(image)
    result = _run_checked(
        [docker, "image", "inspect", image],
        label=(
            "clean-room image inspection; the image must be preloaded because this "
            "validator never pulls"
        ),
        timeout=min(timeout, 60),
    )
    documents = _load_json_text(result.stdout, "Docker image inspection")
    if not isinstance(documents, list) or len(documents) != 1:
        raise ValidationError("Docker image inspection did not return exactly one image")
    document = documents[0]
    if not isinstance(document, dict):
        raise ValidationError("Docker image inspection returned an invalid object")
    image_id = document.get("Id")
    if not isinstance(image_id, str) or SHA256_RE.fullmatch(image_id) is None:
        raise ValidationError("Docker image has no immutable local image ID")
    if document.get("Os") != "linux" or document.get("Architecture") != "amd64":
        raise ValidationError(
            "clean-room image must be preloaded for linux/amd64; "
            f"found {document.get('Os')}/{document.get('Architecture')}"
        )
    repo_digests = document.get("RepoDigests")
    if repo_digests is None:
        repo_digests = []
    if (
        not isinstance(repo_digests, list)
        or any(not isinstance(value, str) for value in repo_digests)
    ):
        raise ValidationError("Docker image RepoDigests are malformed")
    facts = {
        "architecture": document["Architecture"],
        "id": image_id,
        "os": document["Os"],
        "reference": image,
        "repoDigests": sorted(repo_digests),
    }
    return image_id, facts


def _container_name() -> str:
    return f"serverware-agent-trust-{os.getpid()}-{secrets.token_hex(6)}"


def _cleanup_container(docker: str, name: str) -> None:
    try:
        subprocess.run(
            [docker, "rm", "--force", name],
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        inspection = subprocess.run(
            [docker, "container", "inspect", name],
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except FileNotFoundError as exc:
        raise ValidationError("Docker CLI disappeared during container cleanup") from exc
    except subprocess.TimeoutExpired as exc:
        raise ValidationError("Docker container cleanup timed out") from exc
    if inspection.returncode == 0:
        raise ValidationError(f"clean-room container remained after cleanup: {name}")


def _run_container(
    docker: str,
    *,
    image_id: str,
    snapshot: Path,
    package_wheel: str,
    timeout: int,
) -> dict[str, Any]:
    name = _container_name()
    command = [
        docker,
        "run",
        "--name",
        name,
        "--rm",
        "--pull=never",
        "--platform=linux/amd64",
        "--network=none",
        "--read-only",
        "--user",
        f"{EXPECTED_UID}:{EXPECTED_GID}",
        "--cap-drop=ALL",
        "--security-opt",
        "no-new-privileges=true",
        "--pids-limit=128",
        "--memory=512m",
        "--memory-swap=512m",
        "--cpus=1.0",
        "--tmpfs",
        (
            "/work:rw,nosuid,nodev,exec,"
            f"size={TMPFS_BYTES},mode=0700,uid={EXPECTED_UID},gid={EXPECTED_GID}"
        ),
        "--mount",
        f"type=bind,source={snapshot},target=/wheelhouse,readonly",
        "--workdir",
        "/work",
        "--hostname",
        "serverware-clean-room",
        "--env",
        f"EXPECTED_UID={EXPECTED_UID}",
        "--env",
        f"EXPECTED_GID={EXPECTED_GID}",
        "--env",
        f"EXPECTED_TMPFS_BYTES={TMPFS_BYTES}",
        "--env",
        f"PACKAGE_WHEEL={package_wheel}",
        "--env",
        "HOME=/work/home",
        "--env",
        "TMPDIR=/work/tmp",
        "--env",
        "PIP_CONFIG_FILE=/dev/null",
        "--env",
        "PIP_DISABLE_PIP_VERSION_CHECK=1",
        "--env",
        "PIP_NO_CACHE_DIR=1",
        "--env",
        "PIP_NO_INDEX=1",
        "--env",
        "PIP_ONLY_BINARY=:all:",
        "--env",
        "PIP_RETRIES=0",
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
        "--env",
        "PYTHONNOUSERSITE=1",
        "--entrypoint",
        "/bin/sh",
        image_id,
        "-c",
        CONTAINER_SCRIPT,
    ]
    try:
        result = _run_checked(
            command,
            label="Docker clean-room validation",
            timeout=timeout,
            cwd=ROOT,
        )
    finally:
        _cleanup_container(docker, name)

    lines = [line for line in result.stdout.splitlines() if line.strip()]
    result_lines = [line for line in lines if line.startswith(RESULT_PREFIX)]
    if len(result_lines) != 1 or len(lines) != 1:
        raise ValidationError(
            "clean-room output must contain exactly one bounded result record"
        )
    facts = _load_json_text(
        result_lines[0].removeprefix(RESULT_PREFIX),
        "clean-room result",
    )
    if not isinstance(facts, dict):
        raise ValidationError("clean-room result is not an object")
    assurance = facts.get("assurance")
    if (
        not isinstance(assurance, dict)
        or assurance.get("classification") != ASSURANCE_CLASSIFICATION
    ):
        raise ValidationError("clean-room result changed its assurance classification")
    return facts


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Strictly verify an enrollment/evidence wheelhouse and install it in a "
            "networkless, non-root, read-only Docker clean room."
        ),
        epilog=(
            "Assurance: checksum-closed local clean-room validation only; this does "
            "not establish source provenance, image provenance, independent "
            "execution, or TEE attestation. The image must already exist locally."
        ),
    )
    parser.add_argument(
        "--wheelhouse",
        required=True,
        type=Path,
        help="path containing wheelhouse-manifest.json, SHA256SUMS, and the wheel closure",
    )
    parser.add_argument(
        "--image",
        default=DEFAULT_IMAGE,
        help=f"preloaded official CPython 3.11 slim image (default: {DEFAULT_IMAGE})",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="maximum Docker clean-room runtime in seconds (default: 300)",
    )
    args = parser.parse_args()
    if args.timeout < 30 or args.timeout > 1800:
        parser.error("--timeout must be between 30 and 1800 seconds")
    return args


def main() -> None:
    args = _parse_args()
    snapshot: Path | None = None
    try:
        wheelhouse = _validate_wheelhouse_root(args.wheelhouse)
        verifier_size, verifier_digest = _stable_sha256(VERIFIER)
        source_verification = _invoke_repository_verifier(
            wheelhouse,
            timeout=min(args.timeout, 120),
        )
        manifest = _read_manifest(wheelhouse)
        package_wheel, package_digest = _select_package_wheel(wheelhouse, manifest)

        snapshot = _snapshot_wheelhouse(wheelhouse)
        snapshot_verification = _invoke_repository_verifier(
            snapshot,
            timeout=min(args.timeout, 120),
        )
        if snapshot_verification != source_verification:
            raise ValidationError("private wheelhouse snapshot differs from verified source")

        docker = shutil.which("docker")
        if docker is None:
            raise ValidationError("Docker CLI is unavailable")
        image_id, image_facts = _inspect_image(
            docker,
            args.image,
            timeout=args.timeout,
        )
        container_facts = _run_container(
            docker,
            image_id=image_id,
            snapshot=snapshot,
            package_wheel=package_wheel,
            timeout=args.timeout,
        )

        final_snapshot_verification = _invoke_repository_verifier(
            snapshot,
            timeout=min(args.timeout, 120),
        )
        final_source_verification = _invoke_repository_verifier(
            wheelhouse,
            timeout=min(args.timeout, 120),
        )
        if (
            final_snapshot_verification != source_verification
            or final_source_verification != source_verification
        ):
            raise ValidationError("wheelhouse changed during clean-room validation")
        final_verifier_size, final_verifier_digest = _stable_sha256(VERIFIER)
        if (final_verifier_size, final_verifier_digest) != (
            verifier_size,
            verifier_digest,
        ):
            raise ValidationError("repository verifier changed during clean-room validation")

        print(
            json.dumps(
                {
                    "assurance": {
                        "classification": ASSURANCE_CLASSIFICATION,
                        "notEstablished": [
                            "image-provenance",
                            "independent-execution",
                            "source-provenance",
                            "tee-attestation",
                        ],
                    },
                    "container": container_facts,
                    "image": image_facts,
                    "ok": True,
                    "packageWheel": {
                        "path": package_wheel,
                        "sha256": "sha256:" + package_digest,
                    },
                    "repositoryVerifier": {
                        "path": VERIFIER.relative_to(ROOT).as_posix(),
                        "sha256": "sha256:" + verifier_digest,
                        "size": verifier_size,
                    },
                    "wheelhouse": source_verification,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    except ValidationError as exc:
        raise SystemExit(str(exc)) from exc
    finally:
        if snapshot is not None:
            _remove_snapshot(snapshot)


if __name__ == "__main__":
    main()
