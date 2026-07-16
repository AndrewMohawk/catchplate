#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import shlex
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import serverware_source_tree
from serverware.http_client import request_bytes
import build_production_images
import merge_production_images_env
import publish_production_images
import run_production_readiness
import verify_reproducible_builds

DEV_SERVICES = (
    "serverware",
    "audit-anchor",
    "grant-store",
    "demo-upstream",
    "decision-gate-rs",
)
CUSTODY_DEV_SERVICES = (*DEV_SERVICES[:-1], "custody-runtime", DEV_SERVICES[-1])
PRODUCTION_CONTROL_HEALTHCHECK_SHA256 = (
    "sha256:edbdc5b8790e94a6e3ccd62f190763d5ba2ef3acc17d93a8a38a8bd4aa1b33df"
)
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
PRODUCTION_PROVENANCE_VERSION = 2
PRODUCTION_PROVENANCE_RECORD_TYPE = "release.provenance.v2"
LOCK_REQUIREMENT_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?)"
    r"==(?P<version>[A-Za-z0-9][A-Za-z0-9._+!-]{0,127})\s+\\$"
)
LOCK_HASH_RE = re.compile(
    r"^--hash=(?P<digest>sha256:[0-9a-f]{64})(?:\s+(?P<continued>\\))?$"
)


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_raw = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_raw)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


MAX_PYTHON_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_RELEASE_INPUT_BYTES = 16 * 1024 * 1024


def canonical_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=True)


def sha256_prefixed_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_prefixed_json(value: Any) -> str:
    return sha256_prefixed_bytes(canonical_json(value).encode("utf-8"))


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def run(args: list[str], *, input_bytes: bytes | None = None) -> str:
    return subprocess.check_output(
        args, cwd=ROOT, input=input_bytes, text=input_bytes is None
    ).strip()


def request_json(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    payload: Any | None = None,
    ca_bundle: Path | None = None,
    timeout: float = 10,
) -> dict[str, Any]:
    data = None if payload is None else canonical_json(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    if payload is not None:
        req.add_header("Content-Type", "application/json")
    context = ssl.create_default_context(cafile=str(ca_bundle)) if ca_bundle else None
    return json.loads(
        request_bytes(
            req, timeout=timeout, max_bytes=8 * 1024 * 1024, context=context
        ).body
    )


def path_from_arg(raw: str) -> Path:
    path = Path(raw)
    return path if path.is_absolute() else ROOT / path


def reject_duplicate_json_object_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def reject_non_finite_json_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def read_bounded_regular_file(path: Path, label: str, *, max_bytes: int) -> bytes:
    if not hasattr(os, "O_NOFOLLOW"):
        raise ValueError(f"{label} cannot be opened safely on this platform")
    descriptor = os.open(
        path,
        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{label} must be a regular non-symlink file: {path}")
        if metadata.st_size < 1 or metadata.st_size > max_bytes:
            raise ValueError(
                f"{label} must contain between 1 and {max_bytes} bytes: {path}"
            )
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            raise ValueError(f"{label} exceeds {max_bytes} bytes: {path}")
        if len(data) != metadata.st_size:
            raise ValueError(f"{label} changed while it was being snapshotted: {path}")
        return data
    finally:
        os.close(descriptor)


def load_json_snapshot(
    path: Path,
    label: str,
    *,
    max_bytes: int = MAX_RELEASE_INPUT_BYTES,
) -> tuple[dict[str, Any], bytes]:
    try:
        data = read_bounded_regular_file(path, label, max_bytes=max_bytes)
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=reject_duplicate_json_object_keys,
            parse_constant=reject_non_finite_json_constant,
        )
    except Exception as exc:
        raise ValueError(f"{label} is not valid JSON: {path}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object: {path}")
    return value, data


def load_json(path: Path, label: str) -> dict[str, Any]:
    value, _ = load_json_snapshot(path, label)
    return value


def require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{label} must be sha256:<64 lowercase hex>")
    return value


def launch_authority_binding(value: Any, label: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return {
        field: require_sha256(value.get(field), f"{label} {field}")
        for field in build_production_images.LAUNCH_AUTHORITY_METADATA_FIELDS
    }


def validate_production_anchor(url: str, token: str) -> None:
    parsed = urllib.parse.urlparse(url)
    hostname = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not hostname:
        raise ValueError("production release anchor must be an HTTPS URL")
    if hostname in {"localhost", "127.0.0.1", "::1"} or hostname.endswith(".localhost"):
        raise ValueError("production release anchor must not be loopback")
    if len(token) < 32:
        raise ValueError(
            "production release anchor token must be at least 32 characters"
        )


def load_release_key(
    path: Path,
    *,
    allow_create: bool = True,
    require_owner_only: bool = False,
) -> Ed25519PrivateKey:
    if require_owner_only:
        if path.is_symlink() or not path.is_file():
            raise ValueError(
                "production release signing key must be an existing regular non-symlink file"
            )
        if path.stat().st_mode & 0o077:
            raise ValueError(
                "production release signing key must not be accessible by group or other users"
            )
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("release signing key must be Ed25519")
        return key
    if not allow_create:
        raise ValueError("production release signing key does not exist")
    key = Ed25519PrivateKey.generate()
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(path, 0o600)
    return key


def load_release_public_key(path: Path) -> Ed25519PublicKey:
    if path.is_symlink() or not path.is_file():
        raise ValueError(
            "trusted release public key must be an existing regular non-symlink file"
        )
    if path.stat().st_size > 65536:
        raise ValueError("trusted release public key exceeds 65536 bytes")
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("trusted release public key must be Ed25519")
    return key


def public_key_id(key: Ed25519PublicKey) -> str:
    return sha256_prefixed_bytes(
        key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def load_production_release_key(
    private_path: Path, trusted_public_path: Path
) -> Ed25519PrivateKey:
    private_key = load_release_key(
        private_path,
        allow_create=False,
        require_owner_only=True,
    )
    trusted_public_key = load_release_public_key(trusted_public_path)
    if public_key_id(private_key.public_key()) != public_key_id(trusted_public_key):
        raise ValueError(
            "production release signing key does not match the independently trusted public key"
        )
    return private_key


def public_key_info(key: Ed25519PrivateKey) -> dict[str, str]:
    public_key = key.public_key()
    pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {"pem": pem, "spki_sha256": sha256_prefixed_bytes(der)}


def source_tree() -> dict[str, Any]:
    summary = serverware_source_tree.source_tree_summary(ROOT)
    summary["git"] = git_source_info()
    return summary


def git_source_info() -> dict[str, Any]:
    def maybe(args: list[str]) -> str | None:
        try:
            return run(args)
        except Exception:
            return None

    status = maybe(["git", "status", "--short"])
    return {
        "commit": maybe(["git", "rev-parse", "HEAD"]),
        "branch": maybe(["git", "rev-parse", "--abbrev-ref", "HEAD"]),
        "remote_origin": maybe(["git", "remote", "get-url", "origin"]),
        "dirty": bool(status),
        "status_short": status or "",
    }


def development_python_sbom(path: Path) -> list[dict[str, str]]:
    items = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name, version = (line.split("==", 1) + [""])[:2] if "==" in line else (line, "")
        items.append(
            {"ecosystem": "pypi", "name": name, "version": version, "requirement": line}
        )
    return items


def canonical_python_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def read_python_manifest(path: Path) -> bytes:
    data = path.read_bytes()
    if not data:
        raise ValueError("Python dependency manifest is empty")
    if len(data) > MAX_PYTHON_MANIFEST_BYTES:
        raise ValueError("Python dependency manifest exceeds the size limit")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Python dependency manifest is not UTF-8") from exc
    return data


def parse_hashed_requirements_lock(data: bytes) -> list[dict[str, Any]]:
    text = data.decode("utf-8")
    items: list[dict[str, Any]] = []
    names: set[str] = set()
    current: dict[str, Any] | None = None

    for line_number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            if current is not None:
                raise ValueError(
                    f"requirements lock has an interrupted entry before line {line_number}"
                )
            continue

        if current is None:
            if raw != raw.lstrip():
                raise ValueError(
                    f"requirements lock has an unexpected continuation at line {line_number}"
                )
            match = LOCK_REQUIREMENT_RE.fullmatch(stripped)
            if match is None:
                raise ValueError(
                    f"requirements lock has an unsupported requirement at line {line_number}"
                )
            name = canonical_python_name(match.group("name"))
            if name in names:
                raise ValueError(
                    f"requirements lock has a duplicate package at line {line_number}"
                )
            current = {
                "ecosystem": "pypi",
                "name": name,
                "version": match.group("version"),
                "requirement": f"{name}=={match.group('version')}",
                "hashes": [],
                "line": line_number,
            }
            continue

        if raw == raw.lstrip():
            raise ValueError(
                f"requirements lock entry at line {current['line']} has no hashes"
            )
        match = LOCK_HASH_RE.fullmatch(stripped)
        if match is None:
            raise ValueError(
                f"requirements lock has an invalid hash continuation at line {line_number}"
            )
        digest = match.group("digest")
        if digest in current["hashes"]:
            raise ValueError(
                f"requirements lock has a duplicate hash at line {line_number}"
            )
        current["hashes"].append(digest)
        if match.group("continued") is None:
            hashes = sorted(current["hashes"])
            current["hashes"] = hashes
            current["hash_count"] = len(hashes)
            current["hashes_sha256"] = sha256_prefixed_json(hashes)
            current.pop("line")
            names.add(current["name"])
            items.append(current)
            current = None

    if current is not None:
        raise ValueError(
            f"requirements lock entry at line {current['line']} is unterminated"
        )
    if not items:
        raise ValueError("requirements lock contains no packages")
    return sorted(items, key=lambda item: (item["name"], item["version"]))


def manifest_display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.name


def python_dependency_inventory(
    *,
    production: bool,
    path: Path | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    selected = path or ROOT / (
        "requirements.lock" if production else "requirements.txt"
    )
    data = read_python_manifest(selected)
    if production:
        items = parse_hashed_requirements_lock(data)
        mode = "transitive-production-lock"
        manifest_format = "pip-requirements-lock/v1"
        require_hashes = True
        hash_count = sum(int(item["hash_count"]) for item in items)
    else:
        items = development_python_sbom(selected)
        mode = "direct-development"
        manifest_format = "pip-requirements/v1"
        require_hashes = False
        hash_count = 0
    manifest = {
        "format": manifest_format,
        "mode": mode,
        "path": manifest_display_path(selected),
        "sha256": sha256_prefixed_bytes(data),
        "require_hashes": require_hashes,
        "packages": len(items),
        "hashes": hash_count,
    }
    return items, manifest


def python_sbom(*, production: bool = False) -> list[dict[str, Any]]:
    items, _ = python_dependency_inventory(production=production)
    return items


def rust_sbom() -> list[dict[str, str]]:
    lock = tomllib.loads(
        (ROOT / "data-plane/decision-gate-rs/Cargo.lock").read_text(encoding="utf-8")
    )
    items = []
    for package in lock.get("package", []):
        item = {
            "ecosystem": "cargo",
            "name": str(package.get("name", "")),
            "version": str(package.get("version", "")),
        }
        if package.get("source"):
            item["source"] = str(package["source"])
        if package.get("checksum"):
            item["checksum"] = str(package["checksum"])
        items.append(item)
    return sorted(
        items, key=lambda item: (item["name"], item["version"], item.get("source", ""))
    )


def package_url(ecosystem: str, name: str, version: str) -> str:
    encoded_name = urllib.parse.quote(name, safe="@/._-")
    encoded_version = urllib.parse.quote(version, safe="._-")
    if version:
        return f"pkg:{ecosystem}/{encoded_name}@{encoded_version}"
    return f"pkg:{ecosystem}/{encoded_name}"


def cyclonedx_sbom(
    python_items: list[dict[str, Any]],
    rust_items: list[dict[str, str]],
    *,
    created_at: str,
    source_digest: str,
    python_manifest: dict[str, Any],
) -> dict[str, Any]:
    components: list[dict[str, Any]] = []
    for item in python_items:
        purl = package_url("pypi", item["name"].lower(), item.get("version", ""))
        properties = [{"name": "serverware:ecosystem", "value": "pypi"}]
        if item.get("hashes_sha256"):
            properties.extend(
                [
                    {
                        "name": "serverware:pipArtifactHashCount",
                        "value": str(item["hash_count"]),
                    },
                    {
                        "name": "serverware:pipArtifactHashesSha256",
                        "value": item["hashes_sha256"],
                    },
                ]
            )
        components.append(
            {
                "type": "library",
                "bom-ref": purl,
                "name": item["name"],
                "version": item.get("version", ""),
                "purl": purl,
                "properties": properties,
            }
        )
    for item in rust_items:
        purl = package_url("cargo", item["name"], item.get("version", ""))
        component: dict[str, Any] = {
            "type": "library",
            "bom-ref": purl,
            "name": item["name"],
            "version": item.get("version", ""),
            "purl": purl,
            "properties": [{"name": "serverware:ecosystem", "value": "cargo"}],
        }
        checksum = item.get("checksum")
        if checksum:
            component["hashes"] = [{"alg": "SHA-256", "content": checksum}]
        if item.get("source"):
            component["externalReferences"] = [
                {"type": "distribution", "url": item["source"]}
            ]
        components.append(component)

    components = sorted(components, key=lambda item: (item["purl"], item["bom-ref"]))
    serial_seed = sha256_prefixed_json(
        {"components": components, "source_tree": source_digest}
    )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, serial_seed)}",
        "version": 1,
        "metadata": {
            "timestamp": created_at,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "serverware-release-provenance",
                        "version": "1",
                    }
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": "pkg:generic/serverware@0.1.0",
                "name": "serverware",
                "version": "0.1.0",
            },
            "properties": [
                {"name": "serverware:sourceTreeDigest", "value": source_digest},
                {
                    "name": "serverware:pythonDependencyManifest",
                    "value": python_manifest["path"],
                },
                {
                    "name": "serverware:pythonDependencyManifestFormat",
                    "value": python_manifest["format"],
                },
                {
                    "name": "serverware:pythonDependencyManifestMode",
                    "value": python_manifest["mode"],
                },
                {
                    "name": "serverware:pythonDependencyManifestSha256",
                    "value": python_manifest["sha256"],
                },
                {
                    "name": "serverware:pythonDependencyManifestRequiresHashes",
                    "value": str(bool(python_manifest["require_hashes"])).lower(),
                },
            ],
        },
        "components": components,
    }


def development_compose_command(
    compose_files: list[str], compose_profiles: list[str]
) -> list[str]:
    command = ["docker", "compose"]
    project_name = os.environ.get("COMPOSE_PROJECT_NAME", "")
    if project_name:
        command.extend(["--project-name", project_name])
    for compose_file in compose_files:
        command.extend(["--file", compose_file])
    for profile in compose_profiles:
        command.extend(["--profile", profile])
    return command


def image_inventory(
    services: tuple[str, ...] = DEV_SERVICES,
    *,
    compose_command: list[str] | None = None,
) -> dict[str, Any]:
    compose_command = compose_command or ["docker", "compose"]
    images = {}
    for service in services:
        image_id = run([*compose_command, "images", "-q", service])
        if not image_id:
            raise RuntimeError(f"compose image is missing for {service}")
        inspect = json.loads(run(["docker", "image", "inspect", image_id]))[0]
        images[service] = {
            "image_id": inspect["Id"],
            "repo_tags": inspect.get("RepoTags") or [],
            "repo_digests": inspect.get("RepoDigests") or [],
            "created": inspect.get("Created"),
            "os": inspect.get("Os"),
            "architecture": inspect.get("Architecture"),
        }
    return images


def container_inventory(
    services: tuple[str, ...] = DEV_SERVICES,
    *,
    compose_command: list[str] | None = None,
) -> dict[str, Any]:
    compose_command = compose_command or ["docker", "compose"]
    inspected: dict[str, dict[str, Any]] | None = None
    for _ in range(50):
        candidate: dict[str, dict[str, Any]] = {}
        for service in services:
            container_ids = run(
                [*compose_command, "ps", "--status", "running", "-q", service]
            ).splitlines()
            if len(container_ids) != 1:
                candidate = {}
                break
            inspect = json.loads(run(["docker", "inspect", container_ids[0]]))[0]
            labels = (inspect.get("Config") or {}).get("Labels") or {}
            if (
                inspect.get("State", {}).get("Running") is not True
                or labels.get("com.docker.compose.service") != service
            ):
                candidate = {}
                break
            candidate[service] = inspect
        if len(candidate) == len(services) and all(
            run([*compose_command, "ps", "--status", "running", "-q", service])
            == candidate[service]["Id"]
            and json.loads(run(["docker", "inspect", candidate[service]["Id"]]))[0]
            .get("State", {})
            .get("Running")
            is True
            for service in services
        ):
            inspected = candidate
            break
        time.sleep(0.1)
    if inspected is None:
        raise RuntimeError(
            "development Compose containers did not provide one stable running generation"
        )

    containers = {}
    for service in services:
        inspect = inspected[service]
        host = inspect["HostConfig"]
        config = inspect["Config"]
        containers[service] = {
            "container_id": inspect["Id"],
            "image": inspect["Image"],
            "user": config.get("User") or "",
            "readonly_rootfs": bool(host.get("ReadonlyRootfs")),
            "cap_drop": host.get("CapDrop") or [],
            "security_opt": host.get("SecurityOpt") or [],
            "pids_limit": host.get("PidsLimit"),
            "tmpfs": host.get("Tmpfs") or {},
            "mounts": [
                {
                    "type": item.get("Type"),
                    "destination": item.get("Destination"),
                    "mode": item.get("Mode"),
                    "rw": item.get("RW"),
                }
                for item in inspect.get("Mounts", [])
            ],
        }
    return containers


def development_compose_services(
    model: dict[str, Any], compose_files: list[str], compose_profiles: list[str]
) -> tuple[str, ...]:
    services = model.get("services") if isinstance(model, dict) else None
    if not isinstance(services, dict):
        raise ValueError("rendered development Compose model has no services")
    service_set = set(services)
    if service_set == set(DEV_SERVICES):
        return DEV_SERVICES
    if service_set != set(CUSTODY_DEV_SERVICES):
        raise ValueError(
            "development Compose services must be exactly the ordinary or custody topology"
        )

    if [Path(value).name for value in compose_files] != [
        "docker-compose.yml",
        "docker-compose.custody.yml",
    ] or compose_profiles != ["custody"]:
        raise ValueError(
            "custody provenance requires the base Compose file, custody override, and custody profile"
        )
    custody = services.get("custody-runtime") or {}
    gate = services.get("decision-gate-rs") or {}
    custody_env = custody.get("environment") or {}
    gate_env = gate.get("environment") or {}
    if (
        custody.get("network_mode") != "none"
        or custody.get("user") != "10002:10003"
        or gate.get("user") != "10001:10001"
        or custody_env.get("SERVERWARE_CUSTODY_EXPECTED_CLIENT_UID") != "10001"
        or gate_env.get("SERVERWARE_RESPONSE_PROOF_CUSTODY_SOCKET")
        != "/run/serverware-custody/custody.sock"
        or gate_env.get("SERVERWARE_RESPONSE_PROOF_CUSTODY_EXPECTED_UID") != "10002"
        or {str(value) for value in (gate.get("group_add") or [])} != {"10003"}
        or ((gate.get("depends_on") or {}).get("custody-runtime") or {}).get(
            "condition"
        )
        != "service_started"
    ):
        raise ValueError(
            "rendered development gate is not configured for the custody runtime"
        )
    if not any(
        isinstance(item, dict)
        and item.get("source") == "serverware-custody-socket"
        and item.get("target") == "/run/serverware-custody"
        and bool(item.get("read_only", False))
        for item in (gate.get("volumes") or [])
    ):
        raise ValueError("rendered development gate lacks the read-only custody socket mount")
    return CUSTODY_DEV_SERVICES


def production_image_inventory(
    *,
    build_path: Path,
    published_path: Path,
    images_env_path: Path,
    expected_source_tree_digest: str,
) -> dict[str, Any]:
    build = load_json(build_path, "production image build artifact")
    published = load_json(published_path, "published production image artifact")
    if (
        build.get("apiVersion") != build_production_images.BUILD_API_VERSION
        or build.get("kind") != build_production_images.BUILD_KIND
    ):
        raise ValueError(
            f"production image build artifact must use {build_production_images.BUILD_API_VERSION}"
        )
    if (
        published.get("apiVersion") != publish_production_images.PUBLISHED_API_VERSION
        or published.get("kind") != publish_production_images.PUBLISHED_KIND
    ):
        raise ValueError(
            f"published production image artifact must use {publish_production_images.PUBLISHED_API_VERSION}"
        )
    if build.get("ok") is not True or published.get("ok") is not True:
        raise ValueError("production image build and publish artifacts must both be ok")
    build_metadata = (
        build.get("metadata") if isinstance(build.get("metadata"), dict) else {}
    )
    build_source = build_metadata.get("source_tree_digest")
    if build_source != expected_source_tree_digest:
        raise ValueError(
            "production image build source tree does not match current release source tree"
        )
    expected_launch_authority = launch_authority_binding(
        build_metadata, "production image build metadata"
    )
    if ((build.get("no_shell") or {}).get("ok")) is not True:
        raise ValueError("production image build did not pass no-shell verification")
    if ((published.get("remote_no_shell") or {}).get("ok")) is not True:
        raise ValueError(
            "published production images did not pass remote no-shell verification"
        )

    image_value = merge_production_images_env.load_images_fragment(images_env_path)
    image_refs = merge_production_images_env.validate_production_images(image_value)
    assignments = merge_production_images_env.service_image_assignments(image_refs)
    expected_refs = {
        "serverware-control": assignments[
            merge_production_images_env.CONTROL_IMAGE_KEY
        ],
        "serverware-decision-gate": assignments[
            merge_production_images_env.DECISION_GATE_IMAGE_KEY
        ],
    }
    build_by_service = {
        str(item.get("service")): item
        for item in build.get("images") or []
        if isinstance(item, dict) and item.get("service")
    }
    published_by_service = {
        str(item.get("service")): item
        for item in published.get("images") or []
        if isinstance(item, dict) and item.get("service")
    }
    if set(build_by_service) != set(expected_refs) or set(published_by_service) != set(
        expected_refs
    ):
        raise ValueError(
            "production build, publish, and image-ref artifacts must contain exactly control and decision-gate"
        )

    inventory: dict[str, Any] = {}
    for service, expected_ref in expected_refs.items():
        built = build_by_service[service]
        pushed = published_by_service[service]
        local_image_id = require_sha256(
            built.get("image_id"), f"{service} local image id"
        )
        if pushed.get("local_image_id") != local_image_id:
            raise ValueError(
                f"published {service} was not produced from the measured local image"
            )
        remote_image_id = require_sha256(
            pushed.get("remote_image_id"), f"{service} remote image id"
        )
        config_id = require_sha256(
            pushed.get("config_id"), f"{service} published config id"
        )
        if not (
            hmac.compare_digest(local_image_id, remote_image_id)
            and hmac.compare_digest(local_image_id, config_id)
        ):
            raise ValueError(
                f"published {service} local, remote, and approved config IDs must be identical"
            )
        if pushed.get("repo_digest") != expected_ref:
            raise ValueError(
                f"published {service} digest ref does not match the immutable image fragment"
            )
        manifest_digest = require_sha256(
            expected_ref.rsplit("@", 1)[1], f"{service} registry manifest digest"
        )
        entry = {
            "image_id": manifest_digest,
            "repo_digests": [expected_ref],
            "config_id": config_id,
            "local_build_image_id": local_image_id,
            "remote_image_id": remote_image_id,
            "dockerfile": built.get("dockerfile"),
        }
        if service == "serverware-decision-gate":
            built_binary = require_sha256(
                built.get("binary_digest"), "built decision-gate binary digest"
            )
            published_binary = require_sha256(
                pushed.get("binary_digest"), "published decision-gate binary digest"
            )
            if built_binary != published_binary:
                raise ValueError(
                    "published decision-gate executable does not match the measured build executable"
                )
            built_launcher = require_sha256(
                built.get("launcher_binary_digest"),
                "built production launcher binary digest",
            )
            published_launcher = require_sha256(
                pushed.get("launcher_binary_digest"),
                "published production launcher binary digest",
            )
            if built_launcher != published_launcher:
                raise ValueError(
                    "published production launcher does not match the measured build launcher"
                )
            built_launch_authority = launch_authority_binding(
                built, "built decision-gate launch authority"
            )
            published_launch_authority = launch_authority_binding(
                pushed, "published decision-gate launch authority"
            )
            if built_launch_authority != expected_launch_authority:
                raise ValueError(
                    "built decision-gate launch-authority binding does not match build metadata"
                )
            if published_launch_authority != expected_launch_authority:
                raise ValueError(
                    "published decision-gate launch-authority binding does not match the measured build"
                )
            entry["binary_digest"] = built_binary
            entry["launcher_binary_digest"] = built_launcher
            entry.update(expected_launch_authority)
        inventory[service] = entry
    return inventory


def production_reproducibility_binding(
    path: Path,
    *,
    expected_source_tree_digest: str,
    expected_images: dict[str, Any],
) -> dict[str, Any]:
    verification, verification_bytes = load_json_snapshot(
        path,
        "reproducible build verification",
    )
    if (
        verification.get("apiVersion")
        != verify_reproducible_builds.VERIFICATION_API_VERSION
        or verification.get("kind") != verify_reproducible_builds.VERIFICATION_KIND
    ):
        raise ValueError(
            "reproducible build verification must use "
            f"{verify_reproducible_builds.VERIFICATION_API_VERSION}"
        )
    if (
        verification.get("ok") is not True
        or verification.get("reproducible") is not True
    ):
        raise ValueError("reproducible build verification is not a reproducible pass")
    if verification.get("mismatches") != []:
        raise ValueError("reproducible build verification contains mismatches")
    scope = (
        verification.get("scope") if isinstance(verification.get("scope"), dict) else {}
    )
    if (
        scope.get("artifact_reproducibility_only") is not True
        or scope.get("independent_execution_proven") is not True
        or scope.get("hardware_proof") is not False
    ):
        raise ValueError(
            "reproducible build verification does not prove independent artifact builds"
        )
    source_tree_digest = require_sha256(
        verification.get("source_tree_digest"),
        "reproducible build verification source_tree_digest",
    )
    if source_tree_digest != expected_source_tree_digest:
        raise ValueError(
            "reproducible build verification source tree does not match release source"
        )
    comparison_sha256 = require_sha256(
        verification.get("comparison_sha256"),
        "reproducible build verification comparison_sha256",
    )
    inputs = (
        verification.get("inputs")
        if isinstance(verification.get("inputs"), dict)
        else {}
    )
    builders: list[dict[str, str]] = []
    for side in ("left", "right"):
        input_value = inputs.get(side) if isinstance(inputs.get(side), dict) else {}
        attestation = (
            input_value.get("attestation")
            if isinstance(input_value.get("attestation"), dict)
            else {}
        )
        builder_id = attestation.get("builder_id")
        if not isinstance(builder_id, str) or not builder_id:
            raise ValueError(
                f"reproducible build verification {side} builder identity is missing"
            )
        key_id = require_sha256(
            attestation.get("key_id"),
            f"reproducible build verification {side} builder key_id",
        )
        if (
            attestation.get("signature_verified") is not True
            or attestation.get("operator_trusted") is not True
        ):
            raise ValueError(
                f"reproducible build verification {side} builder is not trusted and signature-verified"
            )
        builders.append({"builder_id": builder_id, "key_id": key_id})
    if len({item["builder_id"] for item in builders}) != 2:
        raise ValueError(
            "reproducible build verification builders are not independent identities"
        )
    if len({item["key_id"] for item in builders}) != 2:
        raise ValueError(
            "reproducible build verification builders do not use independent keys"
        )

    images = verification.get("images")
    if not isinstance(images, list):
        raise ValueError("reproducible build verification images must be a list")
    by_service = {
        str(item.get("service")): item
        for item in images
        if isinstance(item, dict) and item.get("service")
    }
    if (
        set(by_service) != {"serverware-control", "serverware-decision-gate"}
        or len(images) != 2
    ):
        raise ValueError(
            "reproducible build verification must bind exactly both production images"
        )
    if set(expected_images) != {"serverware-control", "serverware-decision-gate"}:
        raise ValueError(
            "release inventory must contain exactly both production images"
        )

    image_bindings: list[dict[str, str]] = []
    for service in ("serverware-control", "serverware-decision-gate"):
        reproducible_image_id = require_sha256(
            by_service[service].get("image_id"),
            f"reproducible build verification {service} image_id",
        )
        expected_image_id = require_sha256(
            expected_images[service].get("local_build_image_id"),
            f"release inventory {service} local build image id",
        )
        remote_image_id = require_sha256(
            expected_images[service].get("remote_image_id", expected_image_id),
            f"release inventory {service} remote image id",
        )
        approved_config_id = require_sha256(
            expected_images[service].get("config_id", remote_image_id),
            f"release inventory {service} approved config id",
        )
        if not (
            hmac.compare_digest(expected_image_id, remote_image_id)
            and hmac.compare_digest(expected_image_id, approved_config_id)
        ):
            raise ValueError(
                f"release inventory {service} local, remote, and approved config IDs differ"
            )
        if reproducible_image_id != expected_image_id:
            raise ValueError(
                f"reproducible {service} image ID does not match production build evidence"
            )
        image_bindings.append({"service": service, "image_id": reproducible_image_id})

    gate = by_service["serverware-decision-gate"]
    reproducible_rust_binary = require_sha256(
        gate.get("rust_binary_sha256"),
        "reproducible build verification decision-gate Rust binary digest",
    )
    expected_rust_binary = require_sha256(
        expected_images["serverware-decision-gate"].get("binary_digest"),
        "release inventory decision-gate Rust binary digest",
    )
    if reproducible_rust_binary != expected_rust_binary:
        raise ValueError(
            "reproducible decision-gate Rust binary does not match production build evidence"
        )
    reproducible_launcher = require_sha256(
        gate.get("launcher_binary_sha256"),
        "reproducible build verification launcher binary digest",
    )
    expected_launcher = require_sha256(
        expected_images["serverware-decision-gate"].get("launcher_binary_digest"),
        "release inventory launcher binary digest",
    )
    if reproducible_launcher != expected_launcher:
        raise ValueError(
            "reproducible production launcher does not match build and publish evidence"
        )
    reproducible_launch_authority = launch_authority_binding(
        gate, "reproducible build verification decision-gate launch authority"
    )
    expected_launch_authority = launch_authority_binding(
        expected_images["serverware-decision-gate"],
        "release inventory decision-gate launch authority",
    )
    if reproducible_launch_authority != expected_launch_authority:
        raise ValueError(
            "reproducible decision-gate launch-authority binding does not match build and publish evidence"
        )
    return {
        "apiVersion": verify_reproducible_builds.VERIFICATION_API_VERSION,
        "kind": verify_reproducible_builds.VERIFICATION_KIND,
        "verification_sha256": sha256_prefixed_bytes(verification_bytes),
        "comparison_sha256": comparison_sha256,
        "source_tree_digest": source_tree_digest,
        "builders": builders,
        "images": [
            image_bindings[0],
            {
                **image_bindings[1],
                "rust_binary_sha256": reproducible_rust_binary,
                "launcher_binary_sha256": reproducible_launcher,
                **reproducible_launch_authority,
            },
        ],
        "launcher_binary_sha256": reproducible_launcher,
        **reproducible_launch_authority,
    }


def validate_production_custody_topology(
    model: dict[str, Any], loaded_env: dict[str, str]
) -> None:
    services = model.get("services") if isinstance(model, dict) else None
    if not isinstance(services, dict):
        raise ValueError("rendered production Compose model has no services")
    serverware = services.get("serverware") or {}
    custody = services.get("custody-runtime") or {}
    gate = services.get("decision-gate-rs") or {}

    if custody.get("network_mode") != "none":
        raise ValueError("production custody must use network_mode none")
    if custody.get("user") != "65531:65530":
        raise ValueError("production custody must run as explicit UID 65531 and socket GID 65530")
    if gate.get("user") != "65532:65532":
        raise ValueError("production decision gate must run as explicit UID 65532")
    if {str(value) for value in (gate.get("group_add") or [])} != {"65530"}:
        raise ValueError("production decision gate must receive only custody socket GID 65530")

    custody_env = custody.get("environment") or {}
    gate_env = gate.get("environment") or {}
    if custody_env.get("SERVERWARE_CUSTODY_EXPECTED_CLIENT_UID") != "65532":
        raise ValueError("production custody must authenticate decision-gate UID 65532")
    if (
        custody_env.get("SERVERWARE_CUSTODY_ATTEMPT_LEDGER_DIRECTORY")
        != "/var/lib/serverware-custody"
    ):
        raise ValueError("production custody must use its private persistent attempt ledger")
    if (
        gate_env.get("SERVERWARE_RESPONSE_PROOF_CUSTODY_SOCKET")
        != "/run/serverware-custody/custody.sock"
        or gate_env.get("SERVERWARE_RESPONSE_PROOF_CUSTODY_EXPECTED_UID") != "65531"
        or gate_env.get("SERVERWARE_RESPONSE_PROOF_CUSTODY_STARTUP_TIMEOUT_MS") != "30000"
    ):
        raise ValueError("production decision gate must pin custody UID 65531 with a 30-second startup deadline")

    def mounts(service: dict[str, Any]) -> list[dict[str, Any]]:
        return [item for item in (service.get("volumes") or []) if isinstance(item, dict)]

    def require_mount(
        service_name: str,
        *,
        source: str,
        target: str,
        read_only: bool,
    ) -> None:
        service = services[service_name]
        if not any(
            item.get("source") == source
            and item.get("target") == target
            and bool(item.get("read_only", False)) is read_only
            for item in mounts(service)
        ):
            access = "read-only" if read_only else "read-write"
            raise ValueError(
                f"production {service_name} must {access} mount {source} at {target}"
            )

    def consumers(source: str) -> set[str]:
        return {
            name
            for name, service in services.items()
            if any(item.get("source") == source for item in mounts(service))
        }

    response_key_source = loaded_env.get("SERVERWARE_RESPONSE_SIGNING_PRIVATE_KEY_FILE", "")
    if not response_key_source:
        raise ValueError("production response-signing private key source is not configured")
    require_mount(
        "serverware",
        source=response_key_source,
        target="/run/secrets/serverware-response-signing-key",
        read_only=True,
    )
    if consumers(response_key_source) != {"serverware"}:
        raise ValueError("production response-signing private key must be mounted only by serverware")

    control_plane_tls_source = loaded_env.get("SERVERWARE_CONTROL_PLANE_TLS_DIR", "")
    if not control_plane_tls_source:
        raise ValueError("production control-plane TLS source is not configured")
    gate_ca_source = str(Path(control_plane_tls_source) / "ca.pem")
    require_mount(
        "decision-gate-rs",
        source=gate_ca_source,
        target="/run/serverware/tls/ca.pem",
        read_only=True,
    )
    if any(
        str(item.get("target", "")).startswith("/run/serverware/tls")
        and not (
            item.get("source") == gate_ca_source
            and item.get("target") == "/run/serverware/tls/ca.pem"
            and bool(item.get("read_only", False))
        )
        for item in mounts(gate)
    ):
        raise ValueError("production decision gate may mount only the control-plane CA file")

    def canonical_host_path(value: str) -> Path:
        path = Path(value).expanduser()
        if not path.is_absolute():
            raise ValueError("production bind-mount sources must use absolute host paths")
        return path.resolve(strict=False)

    def host_paths_alias_or_overlap(left: str, right: str) -> bool:
        left_path = canonical_host_path(left)
        right_path = canonical_host_path(right)
        if left_path == right_path or left_path in right_path.parents or right_path in left_path.parents:
            return True
        try:
            return left_path.exists() and right_path.exists() and left_path.samefile(right_path)
        except OSError:
            return False

    for mount in mounts(gate):
        source = mount.get("source")
        if mount.get("type") == "bind" and isinstance(source, str):
            if host_paths_alias_or_overlap(response_key_source, source):
                raise ValueError(
                    "production response-signing private key must not alias or fall beneath a gate-visible bind mount"
                )

    trust_source = "serverware-custody-trust"
    require_mount(
        "serverware",
        source=trust_source,
        target="/run/serverware/custody-trust",
        read_only=False,
    )
    require_mount(
        "custody-runtime",
        source=trust_source,
        target="/run/serverware/custody-trust",
        read_only=True,
    )
    if consumers(trust_source) != {"serverware", "custody-runtime"}:
        raise ValueError("production custody trust volume has an unexpected consumer")

    socket_source = "serverware-custody-socket"
    require_mount(
        "custody-runtime",
        source=socket_source,
        target="/run/serverware-custody",
        read_only=False,
    )
    require_mount(
        "decision-gate-rs",
        source=socket_source,
        target="/run/serverware-custody",
        read_only=True,
    )
    if consumers(socket_source) != {"custody-runtime", "decision-gate-rs"}:
        raise ValueError("production custody socket volume has an unexpected consumer")

    state_source = "serverware-custody-state"
    require_mount(
        "custody-runtime",
        source=state_source,
        target="/var/lib/serverware-custody",
        read_only=False,
    )
    if consumers(state_source) != {"custody-runtime"}:
        raise ValueError("production custody state volume must be private to custody")

    serverware_healthcheck = serverware.get("healthcheck") or {}
    healthcheck_test = serverware_healthcheck.get("test") or []
    healthcheck_command = str(healthcheck_test[3]) if len(healthcheck_test) == 4 else ""
    if healthcheck_test[:3] != ["CMD", "/usr/bin/python3", "-c"] or (
        sha256_prefixed_bytes(healthcheck_command.encode("utf-8"))
        != PRODUCTION_CONTROL_HEALTHCHECK_SHA256
    ):
        raise ValueError("production control-plane readiness program is not the pinned command")
    if not all(
        marker in healthcheck_command
        for marker in (
            "/run/serverware/custody-trust/control-plane-response-signing.pub.pem",
            "/run/serverware/custody-trust/control-plane-response-signing.key-id",
            "/run/secrets/serverware-response-signing-key",
            "https://serverware:3000/healthz",
            "/run/serverware/tls/ca.pem",
            "validate_response_signing_key_custody",
            "sys.exit(1)",
        )
    ) or "assert " in healthcheck_command or "__debug__" in healthcheck_command:
        raise ValueError(
            "production control-plane readiness must verify live HTTPS health and published custody trust against the active private key"
        )
    if ((custody.get("depends_on") or {}).get("serverware") or {}).get("condition") != "service_healthy":
        raise ValueError("production custody must wait for control-plane trust publication readiness")
    if ((gate.get("depends_on") or {}).get("custody-runtime") or {}).get("condition") != "service_started":
        raise ValueError("production decision gate must start only after custody starts")
    if gate.get("restart") != "on-failure":
        raise ValueError("production decision gate must restart after a custody startup failure")


def production_compose_model(
    *, compose_file: Path, env_file: Path, images: dict[str, Any]
) -> tuple[str, dict[str, Any]]:
    loaded_env = run_production_readiness.load_env_file(env_file)
    raw = run(
        [
            "docker",
            "compose",
            "--env-file",
            str(env_file),
            "-f",
            str(compose_file),
            "config",
            "--format",
            "json",
        ]
    )
    try:
        model = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("rendered production Compose model is not JSON") from exc
    services = model.get("services") if isinstance(model, dict) else None
    if not isinstance(services, dict):
        raise ValueError("rendered production Compose model has no services")
    expected_images = {
        "serverware": images["serverware-control"]["repo_digests"][0],
        "audit-anchor": images["serverware-control"]["repo_digests"][0],
        "custody-runtime": images["serverware-decision-gate"]["repo_digests"][0],
        "decision-gate-rs": images["serverware-decision-gate"]["repo_digests"][0],
    }
    if set(services) != set(expected_images):
        raise ValueError(
            f"production Compose services must be exactly {sorted(expected_images)}"
        )
    for service, expected_image in expected_images.items():
        config = services[service]
        if not isinstance(config, dict) or config.get("image") != expected_image:
            raise ValueError(
                f"production Compose service {service} does not use its immutable published image"
            )
        if "build" in config:
            raise ValueError(
                f"production Compose service {service} must not contain a build directive"
            )
    validate_production_custody_topology(model, loaded_env)
    networks = model.get("networks") if isinstance(model.get("networks"), dict) else {}
    for name in ("gate-control", "anchor-control"):
        if (
            not isinstance(networks.get(name), dict)
            or networks[name].get("internal") is not True
        ):
            raise ValueError(f"production Compose network {name} must be internal")
    if set((services["audit-anchor"].get("networks") or {})) != {"anchor-control"}:
        raise ValueError(
            "production audit-anchor must only join the internal anchor-control network"
        )
    for service in ("serverware", "decision-gate-rs"):
        devices = services[service].get("devices") or []
        if not any(
            isinstance(item, dict) and item.get("source") == "/dev/nsm"
            for item in devices
        ):
            raise ValueError(
                f"production Compose service {service} must receive /dev/nsm"
            )
        mounts = services[service].get("volumes") or []
        expected_artifacts = {
            "/run/serverware/release/release-provenance.json": loaded_env.get(
                "SERVERWARE_RELEASE_PROVENANCE_FILE"
            ),
            "/run/serverware/release/image-signatures.json": loaded_env.get(
                "SERVERWARE_IMAGE_SIGNATURES_FILE"
            ),
        }
        for target, source in expected_artifacts.items():
            if not any(
                isinstance(item, dict)
                and item.get("type") == "bind"
                and item.get("source") == source
                and item.get("target") == target
                and item.get("read_only") is True
                for item in mounts
            ):
                raise ValueError(
                    f"production Compose service {service} must read-only mount {target}"
                )
    serverware_env = services["serverware"].get("environment") or {}
    if serverware_env.get("SERVERWARE_DECISION_GATE_BASE"):
        raise ValueError(
            "production control plane must not use the gate's local management API"
        )
    if (
        serverware_env.get("SERVERWARE_AUDIT_ANCHOR_URL")
        != "https://audit-anchor:9100/anchors"
    ):
        raise ValueError(
            "production audit-anchor transport must use the internal HTTPS endpoint"
        )
    if (
        serverware_env.get("SERVERWARE_AUDIT_ANCHOR_CA_BUNDLE")
        != "/run/serverware/tls/ca.pem"
    ):
        raise ValueError(
            "production control plane must verify the audit-anchor TLS certificate"
        )
    gate_env = services["decision-gate-rs"].get("environment") or {}
    if gate_env.get("SERVERWARE_DECISION_GATE_MANAGEMENT_HOST") != "127.0.0.1":
        raise ValueError(
            "production decision-gate management listener must bind container loopback"
        )
    anchor_env = services["audit-anchor"].get("environment") or {}
    if (
        anchor_env.get("SERVERWARE_AUDIT_ANCHOR_TLS_CERT_FILE")
        != "/run/serverware/anchor-tls/audit-anchor.crt"
    ):
        raise ValueError("production audit-anchor TLS certificate path is not fixed")
    if (
        anchor_env.get("SERVERWARE_AUDIT_ANCHOR_TLS_KEY_FILE")
        != "/run/serverware/anchor-tls/audit-anchor.key"
    ):
        raise ValueError("production audit-anchor TLS key path is not fixed")
    anchor_mounts = services["audit-anchor"].get("volumes") or []
    if not any(
        isinstance(item, dict)
        and item.get("type") == "bind"
        and item.get("source") == loaded_env.get("SERVERWARE_AUDIT_ANCHOR_TLS_DIR")
        and item.get("target") == "/run/serverware/anchor-tls"
        and item.get("read_only") is True
        for item in anchor_mounts
    ):
        raise ValueError(
            "production audit-anchor must read-only mount its TLS directory"
        )
    canonical = canonical_json(model)
    summary = {
        "file": str(compose_file),
        "services": sorted(services),
        "images": expected_images,
        "internal_networks": ["anchor-control", "gate-control"],
        "sha256": sha256_prefixed_bytes(canonical.encode("utf-8")),
    }
    return canonical, summary


def write_container_file(
    service: str,
    path: str,
    data: bytes,
    *,
    compose_command: list[str] | None = None,
) -> None:
    compose_command = compose_command or ["docker", "compose"]
    command = f"cat > {shlex.quote(path)}"
    subprocess.run(
        [*compose_command, "exec", "-T", service, "sh", "-c", command],
        cwd=ROOT,
        input=data,
        check=True,
    )


def wait_for_gate_response_context(
    gate_base: str,
    field: str,
    expected_digest: str,
    *,
    timeout: float = 10,
) -> dict[str, Any]:
    deadline = time.time() + timeout
    last: dict[str, Any] = {}
    while time.time() < deadline:
        try:
            last = request_json(f"{gate_base.rstrip('/')}/healthz")
        except Exception:
            time.sleep(0.25)
            continue
        context = last.get("attested_response_context") or {}
        if context.get(field) == expected_digest:
            return last
        time.sleep(0.25)
    raise RuntimeError(
        f"decision-gate signed response context did not adopt {field}={expected_digest}: {last}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate signed Serverware release provenance and anchor it."
    )
    parser.add_argument(
        "--production",
        action="store_true",
        help="Bind provenance to published images and docker-compose.production.yml.",
    )
    parser.add_argument("--base", default=os.getenv("BASE", "http://localhost:3000"))
    parser.add_argument(
        "--gate", default=os.getenv("DECISION_GATE_BASE", "http://localhost:9090")
    )
    parser.add_argument(
        "--anchor",
        default=os.getenv(
            "SERVERWARE_RELEASE_ANCHOR_BASE", os.getenv("AUDIT_ANCHOR_BASE", "")
        ),
    )
    parser.add_argument(
        "--anchor-ca-bundle",
        default=os.getenv("SERVERWARE_RELEASE_ANCHOR_CA_BUNDLE", ""),
    )
    parser.add_argument(
        "--admin-token", default=os.getenv("SERVERWARE_ADMIN_TOKEN", "dev-admin-token")
    )
    parser.add_argument(
        "--anchor-token", default=os.getenv("SERVERWARE_AUDIT_ANCHOR_TOKEN", "")
    )
    parser.add_argument("--env-file", default="ops/production-readiness.env")
    parser.add_argument("--compose-file", default="docker-compose.production.yml")
    parser.add_argument(
        "--production-images-build", default=".tmp/production-images-build.json"
    )
    parser.add_argument(
        "--production-images-published", default=".tmp/production-images-published.json"
    )
    parser.add_argument("--production-images-env", default=".tmp/production-images.env")
    parser.add_argument(
        "--reproducible-build-verification",
        default=".tmp/reproducible-build-verification.json",
    )
    parser.add_argument("--out", default=".tmp/release-provenance.json")
    parser.add_argument("--sbom-out", default=".tmp/sbom.cdx.json")
    parser.add_argument(
        "--key", default=os.getenv("SERVERWARE_RELEASE_PROVENANCE_SIGNING_KEY", "")
    )
    parser.add_argument(
        "--trusted-public-key",
        default=os.getenv("SERVERWARE_RELEASE_PROVENANCE_TRUSTED_PUBLIC_KEY", ""),
    )
    parser.add_argument("--container-out", default="/data/release-provenance.json")
    args = parser.parse_args()

    created_at = datetime.now(timezone.utc).isoformat()
    nonce = f"release-provenance-{int(time.time() * 1000)}"

    source = source_tree()
    development_compose_cli: list[str] | None = None
    if args.production:
        env_file = path_from_arg(args.env_file)
        compose_file = path_from_arg(args.compose_file)
        loaded_env = run_production_readiness.load_env_file(env_file)
        args.anchor = args.anchor or loaded_env.get(
            "SERVERWARE_RELEASE_ANCHOR_BASE", ""
        )
        args.anchor_token = args.anchor_token or loaded_env.get(
            "SERVERWARE_AUDIT_ANCHOR_TOKEN", ""
        )
        args.anchor_ca_bundle = args.anchor_ca_bundle or loaded_env.get(
            "SERVERWARE_RELEASE_ANCHOR_CA_BUNDLE", ""
        )
        args.key = args.key or loaded_env.get(
            "SERVERWARE_RELEASE_PROVENANCE_SIGNING_KEY", ""
        )
        args.trusted_public_key = args.trusted_public_key or loaded_env.get(
            "SERVERWARE_RELEASE_PROVENANCE_TRUSTED_PUBLIC_KEY", ""
        )
        if not args.key:
            raise ValueError(
                "production release provenance requires SERVERWARE_RELEASE_PROVENANCE_SIGNING_KEY or --key"
            )
        if not args.trusted_public_key:
            raise ValueError(
                "production release provenance requires SERVERWARE_RELEASE_PROVENANCE_TRUSTED_PUBLIC_KEY or --trusted-public-key"
            )
        validate_production_anchor(args.anchor, args.anchor_token)
        images = production_image_inventory(
            build_path=path_from_arg(args.production_images_build),
            published_path=path_from_arg(args.production_images_published),
            images_env_path=path_from_arg(args.production_images_env),
            expected_source_tree_digest=source["digest"],
        )
        reproducible_build = production_reproducibility_binding(
            path_from_arg(args.reproducible_build_verification),
            expected_source_tree_digest=source["digest"],
            expected_images=images,
        )
        production_launch_authority = launch_authority_binding(
            images["serverware-decision-gate"],
            "production decision-gate release inventory",
        )
        compose_config, compose_summary = production_compose_model(
            compose_file=compose_file,
            env_file=env_file,
            images=images,
        )
        if loaded_env.get("SERVERWARE_PRODUCTION_IMAGES") != ",".join(
            images[service]["repo_digests"][0]
            for service in ("serverware-control", "serverware-decision-gate")
        ):
            raise ValueError(
                "production readiness env image list does not match the published image evidence"
            )
        containers: dict[str, Any] = {}
        control_attestation = None
        gate_attestation = None
        audit_verify = None
        anchor_verify = None
    else:
        args.anchor = args.anchor or "http://localhost:9100"
        args.anchor_token = args.anchor_token or "dev-audit-anchor-token"
        compose_files = os.environ.get("COMPOSE_FILE", "docker-compose.yml").split(os.pathsep)
        compose_profiles = sorted(
            value
            for value in os.environ.get("COMPOSE_PROFILES", "").split(",")
            if value
        )
        development_compose_cli = development_compose_command(
            compose_files, compose_profiles
        )
        compose_config = run([*development_compose_cli, "config"])
        compose_model = json.loads(
            run([*development_compose_cli, "config", "--format", "json"])
        )
        development_services = development_compose_services(
            compose_model, compose_files, compose_profiles
        )
        compose_summary = {
            "files": compose_files,
            "profiles": compose_profiles,
            "services": list(development_services),
            "sha256": sha256_prefixed_bytes(compose_config.encode("utf-8")),
        }
        images = image_inventory(
            development_services, compose_command=development_compose_cli
        )
        containers = container_inventory(
            development_services, compose_command=development_compose_cli
        )
        control_attestation = None
        gate_attestation = None
        audit_verify = None
        anchor_verify = None
        reproducible_build = None
        production_launch_authority = None
    anchor_ca_bundle = (
        path_from_arg(args.anchor_ca_bundle) if args.anchor_ca_bundle else None
    )
    if args.production and anchor_ca_bundle and not anchor_ca_bundle.is_file():
        raise ValueError(
            f"production release anchor CA bundle does not exist: {anchor_ca_bundle}"
        )
    admin_headers = {"X-Serverware-Admin-Token": args.admin_token}
    anchor_headers = {"X-Serverware-Audit-Anchor-Token": args.anchor_token}
    if not args.production:
        control_attestation = request_json(
            f"{args.base.rstrip('/')}/attestation?nonce={nonce}-control"
        )
        gate_attestation = request_json(
            f"{args.gate.rstrip('/')}/attestation?nonce={nonce}-gate"
        )
        audit_verify = request_json(
            f"{args.base.rstrip('/')}/api/audit/verify",
            headers=admin_headers,
            timeout=60,
        )
        anchor_verify = request_json(
            f"{args.anchor.rstrip('/')}/anchors/verify",
            headers=anchor_headers,
            timeout=60,
        )
    py_sbom, python_manifest = python_dependency_inventory(production=args.production)
    cargo_sbom = rust_sbom()
    cyclonedx = cyclonedx_sbom(
        py_sbom,
        cargo_sbom,
        created_at=created_at,
        source_digest=source["digest"],
        python_manifest=python_manifest,
    )
    sbom_out_path = ROOT / args.sbom_out
    sbom_out_path.parent.mkdir(parents=True, exist_ok=True)
    sbom_out_path.write_text(
        json.dumps(cyclonedx, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    cyclonedx_digest = sha256_prefixed_bytes(sbom_out_path.read_bytes())
    provenance = {
        "version": PRODUCTION_PROVENANCE_VERSION if args.production else 1,
        "created_at": created_at,
        "source": "serverware-digest-pinned-production-release"
        if args.production
        else "serverware-docker-dev-release",
        "compose_config_sha256": sha256_prefixed_bytes(compose_config.encode("utf-8")),
        "compose": compose_summary,
        "source_tree": source,
        "build_recipe": {
            "source_tree_digest": source["digest"],
            "compose_config_sha256": sha256_prefixed_bytes(
                compose_config.encode("utf-8")
            ),
            "commands": [
                *(
                    [
                        "make build-production-images",
                        "make decision-gate-bench-evidence",
                        "make publish-production-images",
                        "make merge-production-images-env",
                        "make build-production-launcher",
                        "make production-release-provenance",
                        "make sign-production-images",
                    ]
                    if args.production
                    else [
                        "docker compose build",
                        "docker compose up",
                        "make release-provenance",
                        "make image-signatures",
                    ]
                ),
            ],
            "rebuild_verifier": "scripts/verify_codebase_attestation.py",
        },
        "images": images,
        **(
            {
                "launch_authority": production_launch_authority,
                "reproducible_build": reproducible_build,
            }
            if args.production
            else {}
        ),
        "containers": containers,
        "sbom": {
            "format": "serverware.sbom/v1",
            "python_manifest": python_manifest,
            "python": py_sbom,
            "rust": cargo_sbom,
            "cyclonedx": {
                "format": "CycloneDX",
                "spec_version": cyclonedx["specVersion"],
                "path": args.sbom_out,
                "sha256": cyclonedx_digest,
                "components": len(cyclonedx["components"]),
            },
        },
        "attestations_before_publish": (
            {
                "control_plane": control_attestation,
                "decision_gate": gate_attestation,
            }
            if not args.production
            else None
        ),
        "runtime_evidence": "separate-production-host-readiness-proof"
        if args.production
        else "development-compose-runtime",
        "audit_chain": audit_verify,
        "anchor_chain": anchor_verify,
    }
    provenance_digest = sha256_prefixed_json(provenance)

    if args.production:
        key = load_production_release_key(
            path_from_arg(args.key),
            path_from_arg(args.trusted_public_key),
        )
    else:
        key = load_release_key(
            path_from_arg(args.key or ".tmp/release-signing-ed25519.pem")
        )
    key_info = public_key_info(key)
    signature = "ed25519:" + b64e(key.sign(canonical_json(provenance).encode("utf-8")))
    document = {
        "provenance": provenance,
        "provenance_digest": provenance_digest,
        "signature": signature,
        "release_signing_key_id": key_info["spki_sha256"],
        "release_signing_public_key_pem": key_info["pem"],
    }

    out_path = ROOT / args.out
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if not args.production:
        atomic_write_json(out_path, document)
        write_container_file(
            "serverware",
            args.container_out,
            out_path.read_bytes(),
            compose_command=development_compose_cli,
        )
        wait_for_gate_response_context(
            args.gate,
            "provenance_digest",
            provenance_digest,
        )
        published_control = request_json(
            f"{args.base.rstrip('/')}/attestation?nonce={nonce}-published-control"
        )
        published_gate = request_json(
            f"{args.gate.rstrip('/')}/attestation?nonce={nonce}-published-gate"
        )
        if published_control.get("provenance_digest") != provenance_digest:
            raise RuntimeError(
                f"control-plane attestation did not bind provenance digest: {published_control}"
            )
        if published_gate.get("provenance_digest") != provenance_digest:
            raise RuntimeError(
                f"decision-gate attestation did not bind provenance digest: {published_gate}"
            )
    else:
        published_control = None
        published_gate = None

    record = {
        "type": PRODUCTION_PROVENANCE_RECORD_TYPE
        if args.production
        else "release.provenance.v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "provenance_digest": provenance_digest,
        "signature": signature,
        "release_signing_key_id": key_info["spki_sha256"],
        "control_plane_policy_hash": published_control.get("policy_bundle_digest")
        if published_control
        else None,
        "decision_gate_policy_hash": published_gate.get("policy_bundle_digest")
        if published_gate
        else None,
        "data_plane_binary_digest": (
            published_gate.get("data_plane_binary_digest")
            if published_gate
            else (provenance["images"].get("serverware-decision-gate") or {}).get(
                "binary_digest"
            )
        ),
        "production_launcher_binary_digest": (
            (provenance["images"].get("serverware-decision-gate") or {}).get(
                "launcher_binary_digest"
            )
            if args.production
            else None
        ),
        **(
            {
                **production_launch_authority,
                "reproducible_build_verification_sha256": reproducible_build[
                    "verification_sha256"
                ],
            }
            if args.production
            else {}
        ),
        "image_ids": {
            service: item["image_id"] for service, item in provenance["images"].items()
        },
        "sbom_counts": {
            "python": len(provenance["sbom"]["python"]),
            "rust": len(provenance["sbom"]["rust"]),
            "cyclonedx_components": provenance["sbom"]["cyclonedx"]["components"],
        },
        "sbom_cyclonedx_sha256": provenance["sbom"]["cyclonedx"]["sha256"],
    }
    anchor_response = request_json(
        f"{args.anchor.rstrip('/')}/anchors",
        method="POST",
        headers=anchor_headers,
        payload={"records": [record]},
        ca_bundle=anchor_ca_bundle,
        timeout=60,
    )
    anchors = request_json(
        f"{args.anchor.rstrip('/')}/anchors?limit=100",
        headers=anchor_headers,
        ca_bundle=anchor_ca_bundle,
        timeout=60,
    )
    anchored = any(
        (item.get("record") or {}).get("provenance_digest") == provenance_digest
        for item in anchors.get("items", [])
    )
    if not anchored:
        raise RuntimeError(
            "release provenance digest was not found in the transparency anchor log"
        )
    accepted = (anchor_response.get("anchors") or [{}])[0]
    sequence = accepted.get("sequence")
    inclusion = request_json(
        f"{args.anchor.rstrip('/')}/anchors/inclusion/{sequence}",
        headers=anchor_headers,
        ca_bundle=anchor_ca_bundle,
        timeout=60,
    )
    if inclusion.get("verified") is not True:
        raise RuntimeError(
            f"release provenance inclusion proof did not verify: {inclusion}"
        )
    if (inclusion.get("item") or {}).get("record", {}).get(
        "provenance_digest"
    ) != provenance_digest:
        raise RuntimeError(
            f"release provenance inclusion proof returned the wrong record: {inclusion}"
        )

    document["published_attestations"] = (
        {
            "control_plane": published_control,
            "decision_gate": published_gate,
        }
        if not args.production
        else None
    )
    document["transparency"] = {
        "record": record,
        "anchor_response": anchor_response,
        "inclusion_proof": inclusion,
    }
    atomic_write_json(out_path, document)
    if not args.production:
        write_container_file(
            "serverware",
            args.container_out,
            out_path.read_bytes(),
            compose_command=development_compose_cli,
        )

    print(
        json.dumps(
            {
                "ok": True,
                "release_provenance": "pass",
                "production": args.production,
                "out": args.out,
                "provenance_digest": provenance_digest,
                "release_signing_key_id": key_info["spki_sha256"],
                "production_launcher_binary_digest": (
                    (provenance["images"].get("serverware-decision-gate") or {}).get(
                        "launcher_binary_digest"
                    )
                    if args.production
                    else None
                ),
                **(
                    {
                        **production_launch_authority,
                        "reproducible_build_verification_sha256": reproducible_build[
                            "verification_sha256"
                        ],
                    }
                    if args.production
                    else {}
                ),
                "anchored": anchored,
                "transparency_mode": anchor_response.get("mode"),
                "inclusion_verified": inclusion.get("verified") is True,
                "sbom": {
                    "python": len(provenance["sbom"]["python"]),
                    "python_manifest": provenance["sbom"]["python_manifest"]["path"],
                    "python_manifest_sha256": provenance["sbom"]["python_manifest"][
                        "sha256"
                    ],
                    "rust": len(provenance["sbom"]["rust"]),
                    "cyclonedx_components": provenance["sbom"]["cyclonedx"][
                        "components"
                    ],
                    "cyclonedx_sha256": provenance["sbom"]["cyclonedx"]["sha256"],
                },
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        raise SystemExit(f"release provenance generation failed: {exc}") from exc
