#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shlex
import subprocess
import sys
import time
import tomllib
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import serverware_source_tree

ROOT = Path(__file__).resolve().parent.parent
SERVICES = ("serverware", "audit-anchor", "grant-store", "demo-upstream", "decision-gate-rs")


def canonical_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=True)


def sha256_prefixed_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_prefixed_json(value: Any) -> str:
    return sha256_prefixed_bytes(canonical_json(value).encode("utf-8"))


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def run(args: list[str], *, input_bytes: bytes | None = None) -> str:
    return subprocess.check_output(args, cwd=ROOT, input=input_bytes, text=input_bytes is None).strip()


def request_json(url: str, *, method: str = "GET", headers: dict[str, str] | None = None, payload: Any | None = None) -> dict[str, Any]:
    data = None if payload is None else canonical_json(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    if payload is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.loads(response.read())


def load_release_key(path: Path) -> Ed25519PrivateKey:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
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


def python_sbom() -> list[dict[str, str]]:
    items = []
    for raw in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name, version = (line.split("==", 1) + [""])[:2] if "==" in line else (line, "")
        items.append({"ecosystem": "pypi", "name": name, "version": version, "requirement": line})
    return items


def rust_sbom() -> list[dict[str, str]]:
    lock = tomllib.loads((ROOT / "data-plane/decision-gate-rs/Cargo.lock").read_text(encoding="utf-8"))
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
    return sorted(items, key=lambda item: (item["name"], item["version"], item.get("source", "")))


def package_url(ecosystem: str, name: str, version: str) -> str:
    encoded_name = urllib.parse.quote(name, safe="@/._-")
    encoded_version = urllib.parse.quote(version, safe="._-")
    if version:
        return f"pkg:{ecosystem}/{encoded_name}@{encoded_version}"
    return f"pkg:{ecosystem}/{encoded_name}"


def cyclonedx_sbom(python_items: list[dict[str, str]], rust_items: list[dict[str, str]], *, created_at: str, source_digest: str) -> dict[str, Any]:
    components: list[dict[str, Any]] = []
    for item in python_items:
        purl = package_url("pypi", item["name"].lower(), item.get("version", ""))
        components.append(
            {
                "type": "library",
                "bom-ref": purl,
                "name": item["name"],
                "version": item.get("version", ""),
                "purl": purl,
                "properties": [{"name": "serverware:ecosystem", "value": "pypi"}],
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
            component["externalReferences"] = [{"type": "distribution", "url": item["source"]}]
        components.append(component)

    components = sorted(components, key=lambda item: (item["purl"], item["bom-ref"]))
    serial_seed = sha256_prefixed_json({"components": components, "source_tree": source_digest})
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
            "properties": [{"name": "serverware:sourceTreeDigest", "value": source_digest}],
        },
        "components": components,
    }


def image_inventory() -> dict[str, Any]:
    images = {}
    for service in SERVICES:
        image_id = run(["docker", "compose", "images", "-q", service])
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


def container_inventory() -> dict[str, Any]:
    containers = {}
    for service in SERVICES:
        container_id = run(["docker", "compose", "ps", "-q", service])
        if not container_id:
            raise RuntimeError(f"compose container is not running for {service}")
        inspect = json.loads(run(["docker", "inspect", container_id]))[0]
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


def write_container_file(service: str, path: str, data: bytes) -> None:
    command = f"cat > {shlex.quote(path)}"
    subprocess.run(
        ["docker", "compose", "exec", "-T", service, "sh", "-c", command],
        cwd=ROOT,
        input=data,
        check=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate signed Serverware release provenance and anchor it.")
    parser.add_argument("--base", default=os.getenv("BASE", "http://localhost:3000"))
    parser.add_argument("--gate", default=os.getenv("DECISION_GATE_BASE", "http://localhost:9090"))
    parser.add_argument("--anchor", default=os.getenv("AUDIT_ANCHOR_BASE", "http://localhost:9100"))
    parser.add_argument("--admin-token", default=os.getenv("SERVERWARE_ADMIN_TOKEN", "dev-admin-token"))
    parser.add_argument("--anchor-token", default=os.getenv("SERVERWARE_AUDIT_ANCHOR_TOKEN", "dev-audit-anchor-token"))
    parser.add_argument("--out", default=".tmp/release-provenance.json")
    parser.add_argument("--sbom-out", default=".tmp/sbom.cdx.json")
    parser.add_argument("--key", default=".tmp/release-signing-ed25519.pem")
    parser.add_argument("--container-out", default="/data/release-provenance.json")
    args = parser.parse_args()

    created_at = datetime.now(timezone.utc).isoformat()
    nonce = f"release-provenance-{int(time.time() * 1000)}"
    admin_headers = {"X-Serverware-Admin-Token": args.admin_token}
    anchor_headers = {"X-Serverware-Audit-Anchor-Token": args.anchor_token}

    compose_config = run(["docker", "compose", "config"])
    source = source_tree()
    py_sbom = python_sbom()
    cargo_sbom = rust_sbom()
    cyclonedx = cyclonedx_sbom(py_sbom, cargo_sbom, created_at=created_at, source_digest=source["digest"])
    sbom_out_path = ROOT / args.sbom_out
    sbom_out_path.parent.mkdir(parents=True, exist_ok=True)
    sbom_out_path.write_text(json.dumps(cyclonedx, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    cyclonedx_digest = sha256_prefixed_bytes(sbom_out_path.read_bytes())
    control_attestation = request_json(f"{args.base.rstrip('/')}/attestation?nonce={nonce}-control")
    gate_attestation = request_json(f"{args.gate.rstrip('/')}/attestation?nonce={nonce}-gate")
    audit_verify = request_json(f"{args.base.rstrip('/')}/api/audit/verify", headers=admin_headers)
    anchor_verify = request_json(f"{args.anchor.rstrip('/')}/anchors/verify", headers=anchor_headers)

    provenance = {
        "version": 1,
        "created_at": created_at,
        "source": "serverware-docker-dev-release",
        "compose_config_sha256": sha256_prefixed_bytes(compose_config.encode("utf-8")),
        "source_tree": source,
        "build_recipe": {
            "source_tree_digest": source["digest"],
            "compose_config_sha256": sha256_prefixed_bytes(compose_config.encode("utf-8")),
            "commands": [
                "docker compose build",
                "docker compose up",
                "make release-provenance",
                "make image-signatures",
            ],
            "rebuild_verifier": "scripts/verify_codebase_attestation.py",
        },
        "images": image_inventory(),
        "containers": container_inventory(),
        "sbom": {
            "format": "serverware.sbom/v1",
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
        "attestations_before_publish": {
            "control_plane": control_attestation,
            "decision_gate": gate_attestation,
        },
        "audit_chain": audit_verify,
        "anchor_chain": anchor_verify,
    }
    provenance_digest = sha256_prefixed_json(provenance)

    key = load_release_key(ROOT / args.key)
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
    out_path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_container_file("serverware", args.container_out, out_path.read_bytes())

    published_control = request_json(f"{args.base.rstrip('/')}/attestation?nonce={nonce}-published-control")
    published_gate = request_json(f"{args.gate.rstrip('/')}/attestation?nonce={nonce}-published-gate")
    if published_control.get("provenance_digest") != provenance_digest:
        raise RuntimeError(f"control-plane attestation did not bind provenance digest: {published_control}")
    if published_gate.get("provenance_digest") != provenance_digest:
        raise RuntimeError(f"decision-gate attestation did not bind provenance digest: {published_gate}")

    record = {
        "type": "release.provenance.v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "provenance_digest": provenance_digest,
        "signature": signature,
        "release_signing_key_id": key_info["spki_sha256"],
        "control_plane_policy_hash": published_control.get("policy_bundle_digest"),
        "decision_gate_policy_hash": published_gate.get("policy_bundle_digest"),
        "data_plane_binary_digest": published_gate.get("data_plane_binary_digest"),
        "image_ids": {service: item["image_id"] for service, item in provenance["images"].items()},
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
    )
    anchors = request_json(f"{args.anchor.rstrip('/')}/anchors?limit=100", headers=anchor_headers)
    anchored = any((item.get("record") or {}).get("provenance_digest") == provenance_digest for item in anchors.get("items", []))
    if not anchored:
        raise RuntimeError("release provenance digest was not found in the transparency anchor log")
    accepted = (anchor_response.get("anchors") or [{}])[0]
    sequence = accepted.get("sequence")
    inclusion = request_json(f"{args.anchor.rstrip('/')}/anchors/inclusion/{sequence}", headers=anchor_headers)
    if inclusion.get("verified") is not True:
        raise RuntimeError(f"release provenance inclusion proof did not verify: {inclusion}")
    if (inclusion.get("item") or {}).get("record", {}).get("provenance_digest") != provenance_digest:
        raise RuntimeError(f"release provenance inclusion proof returned the wrong record: {inclusion}")

    document["published_attestations"] = {
        "control_plane": published_control,
        "decision_gate": published_gate,
    }
    document["transparency"] = {
        "record": record,
        "anchor_response": anchor_response,
        "inclusion_proof": inclusion,
    }
    out_path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_container_file("serverware", args.container_out, out_path.read_bytes())

    print(
        json.dumps(
            {
                "ok": True,
                "release_provenance": "pass",
                "out": args.out,
                "provenance_digest": provenance_digest,
                "release_signing_key_id": key_info["spki_sha256"],
                "anchored": anchored,
                "transparency_mode": anchor_response.get("mode"),
                "inclusion_verified": inclusion.get("verified") is True,
                "sbom": {
                    "python": len(provenance["sbom"]["python"]),
                    "rust": len(provenance["sbom"]["rust"]),
                    "cyclonedx_components": provenance["sbom"]["cyclonedx"]["components"],
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
