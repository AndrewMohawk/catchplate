#!/usr/bin/env python3
"""Render one private HTTPS-proxy Basic fixture; never launch any phase.

The original relay-free preparer remains unchanged. This separate recipe adds
only a fixed TLS edge, offline fresh PKI, and a dormant stock-client checker.
Inputs are a readable detached source archive plus its externally pinned full
manifest, NOT an invented Git checkout. Runtime/preflight execution is separate.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

from scripts import prepare_operator_catalog_fixture as base


CLIENT_IMAGE = "sha256:b2ce90db12b1df24e9d405fcd1e48d50ebad0039e523d30fde8fb1fb64fafafa"
CURL_SHA256 = "0ca2b923679ab186f6512c7512e131a1c5c1b43d4cb5d55933998405b39e85bf"
DEPENDENCIES = Path("/srv/catchplate-fast/projects/catchplate-operator-workspace-evidence/requests-dependencies.6BgfNK0L")
DEPENDENCY_MANIFEST_SHA256 = "d932320e6f32eeca7f496abea639c1a80cf5afd0ba3642011e2a41cee3a70059"
PROXY_HOST = "proxy.operator-basic.example.test"
CHECKER = "scripts/check_operator_proxy_basic.py"
SETUP = "scripts/operator_proxy_basic_fixture_setup.py"
RELAY = "scripts/operator_proxy_basic_tls.py"


def build(source, binary, initializer, root, subnet, *, expected_binary_sha256):
    """Pure, single-purpose Compose builder; no imports of runtime application code."""
    binary_sha = base.validated_binary_sha256(expected_binary_sha256)
    base.require(root.parent == base.SCRATCH and re.fullmatch(
        r"catchplate-proxy-basic-private\.[A-Za-z0-9]{6,32}", root.name), "fresh Basic NVMe root required")
    template = root.with_name("catchplate-catalog-private." + root.name.split(".", 1)[1])
    config = base.build(source, binary, initializer, template, subnet, expected_binary_sha256=binary_sha)
    runtime = root / "runtime"
    for service in config["services"].values():
        for mount in service["volumes"]:
            path = Path(mount["source"])
            if path.is_relative_to(template):
                mount["source"] = str(root / path.relative_to(template))
    config["name"] = "catchplate-proxy-basic-private-" + hashlib.sha256(root.name.encode()).hexdigest()[:12]
    services = config["services"]
    network = ipaddress.ip_network(subnet, strict=True)
    gate_ip, edge_ip, client_ip = (str(network.network_address + value) for value in (4, 5, 6))
    pki = runtime / "basic-pki"

    # Retain the baseline runtime hardening, but no fixture command, state mount
    # or healthcheck. In particular, polling the edge would spend its32 sockets.
    common = deepcopy(services["demo-upstream"])
    for key in ("command", "environment", "volumes", "healthcheck", "depends_on", "networks"):
        common.pop(key, None)
    common["environment"] = {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": "/app"}
    services["edge"] = {**deepcopy(common), "image": base.GATE_IMAGE, "profiles": ["edge"],
        "mem_limit": "128m", "memswap_limit": "128m", "pids_limit": 32,
        "networks": {"fixture": {"ipv4_address": edge_ip, "aliases": [PROXY_HOST]}},
        "entrypoint": ["python", "-B"], "command": ["/app/" + RELAY,
            "--listen-address", edge_ip, "--gate-address", gate_ip,
            "--cert-file", "/edge/cert.pem", "--key-file", "/edge/key.pem", "--lifetime-seconds", "240"],
        "volumes": [base.bind(source, "/app"), base.bind(pki / "outer-cert.pem", "/edge/cert.pem"),
                    base.bind(pki / "outer-key.pem", "/edge/key.pem")]}
    services["basic-pki"] = {**deepcopy(common), "image": base.APP_IMAGE, "profiles": ["basic-pki"],
        "user": "0:0", "network_mode": "none", "cap_add": ["CHOWN", "DAC_OVERRIDE"],
        "pids_limit": 32, "entrypoint": ["python", "-B"],
        "command": ["/app/" + SETUP, "--runtime-root", "/fixture-runtime", "--inner-ca-file", "/inner-ca.pem"],
        "volumes": [base.bind(source, "/app"), base.bind(runtime, "/fixture-runtime", False),
                    base.bind(runtime / "app-data/mitmproxy/mitmproxy-ca-cert.pem", "/inner-ca.pem")]}
    services["basic-pki"].pop("dns", None)  # network-none has no DNS/bridge attachment.
    services["check"] = {**deepcopy(common), "image": CLIENT_IMAGE, "profiles": ["check"],
        "cpus": 1, "mem_limit": "512m", "memswap_limit": "512m", "pids_limit": 64,
        "networks": {"fixture": {"ipv4_address": client_ip}},
        "environment": {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": "/app:/client-dependencies/site-packages"},
        "entrypoint": ["/usr/bin/python3.10", "-B"], "command": ["/app/" + CHECKER,
            "--control-base", "http://catchplate:3000", "--management-base", "http://" + gate_ip + ":9091",
            "--proxy-url", "https://" + PROXY_HOST + ":8443", "--operator-origin", base.ORIGIN,
            "--expected-binary-sha256", "sha256:" + binary_sha,
            "--ca-file", "/client-trust/inner-ca.pem", "--proxy-ca-file", "/client-trust/outer-ca.pem",
            "--requests-ca-file", "/client-trust/requests-ca.pem", "--upstream-ca-file", "/client-trust/upstream-ca.pem",
            "--admin-token-file", "/client-secrets/admin.token", "--fixture-marker-file", "/private-fixture.json",
            "--run-claim-file", "/client-work/.operator-catalog-acceptance.claim",
            "--curl-binary", "/usr/bin/curl", "--timeout-seconds", "120"],
        "volumes": [base.bind(source, "/app"), base.bind(DEPENDENCIES, "/client-dependencies"),
            base.bind(runtime / "client-work", "/client-work", False),
            base.bind(runtime / "service-secrets/admin.token", "/client-secrets/admin.token"),
            base.bind(runtime / ".private-fixture.json", "/private-fixture.json"),
            base.bind(runtime / "upstream-data/demo-upstream/ca.pem", "/client-trust/upstream-ca.pem")]
            + [base.bind(pki / name, "/client-trust/" + name)
               for name in ("outer-ca.pem", "inner-ca.pem", "requests-ca.pem")]}
    return config


def validate(config, source, binary, initializer, root, subnet, *, expected_binary_sha256):
    # Exact recomputation closes every field, including dormant profiles and
    # mounts. It does not weaken or extend the original four-service validator.
    base.require(config == build(source, binary, initializer, root, subnet,
        expected_binary_sha256=expected_binary_sha256), "private Basic recipe differs")


def inventory(root, *, limit, byte_limit):
    """Bounded detached-archive inventory; reject unreadable or indirect inputs."""
    base.require(root.is_absolute() and root.resolve() == root and not root.is_symlink(), "exact readable archive required")
    pending, result, entries, total = [root], {}, 0, 0
    while pending:
        directory = pending.pop()
        info = directory.lstat()
        base.require(stat.S_ISDIR(info.st_mode) and info.st_mode & 5 == 5, "archive directory not readable by runtime UID")
        for path in directory.iterdir():
            entries += 1
            base.require(entries <= limit * 3 and path.name != ".git", "archive entry bound or Git state refused")
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                pending.append(path)
                continue
            base.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_mode & 4
                and info.st_size <= 64 * 1024**2, "archive file is indirect, unreadable or oversized")
            total += info.st_size
            base.require(len(result) < limit and total <= byte_limit, "archive inventory bound exceeded")
            result[path.relative_to(root).as_posix()] = {"size": info.st_size, "sha256": base.digest(path)}
    return result


def pinned_json(path, expected_sha):
    base.validated_binary_sha256(expected_sha)
    base.require(path.is_absolute() and path.resolve() == path and not path.is_symlink()
        and path.is_file() and path.stat().st_size <= 4 * 1024**2
        and base.digest(path) == expected_sha, "external manifest pin differs")
    return json.loads(path.read_text())


def source_inventory(source, manifest_path, manifest_sha, commit):
    base.require(isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}", commit), "explicit source commit required")
    manifest = pinned_json(manifest_path, manifest_sha)
    base.require(isinstance(manifest, dict) and set(manifest) == {"schema", "sourceCommit", "files"}
        and manifest["schema"] == "catchplate.privateProxyBasicSource/v1" and manifest["sourceCommit"] == commit,
        "source archive provenance differs")
    expected = manifest["files"]
    base.require(isinstance(expected, dict) and 0 < len(expected) <= 16384, "bounded full source inventory required")
    for name, value in expected.items():
        relative = PurePosixPath(name)
        base.require(isinstance(name, str) and relative.as_posix() == name and not relative.is_absolute()
            and ".." not in relative.parts and bool(relative.parts), "source inventory path refused")
        base.validated_binary_sha256(value)
    observed = inventory(source, limit=16384, byte_limit=512 * 1024**2)
    base.require({name: row["sha256"] for name, row in observed.items()} == expected, "detached source archive differs")
    base.require({CHECKER, SETUP, RELAY, "scripts/demo_upstream.py",
        "scripts/operator_ordinary_client_fixture.py"} <= expected.keys(), "paired fixture sources missing")
    return expected


def dependency_inventory():
    manifest = pinned_json(DEPENDENCIES / "manifest.json", DEPENDENCY_MANIFEST_SHA256)
    observed = inventory(DEPENDENCIES, limit=2048, byte_limit=8 * 1024**2)
    observed.pop("manifest.json")
    base.require(manifest.get("schema") == "catchplate.syntheticRequestsDependencies/v1"
        and manifest.get("moduleSubdirectory") == "site-packages" and len(manifest.get("files", [])) == 143,
        "retained client dependency shape differs")
    expected = {row["path"]: {"size": row["size"], "sha256": row["sha256"]} for row in manifest["files"]}
    base.require(len(expected) == 143 and observed == expected, "retained client dependency payload differs")


def prepare(args):
    config = build(args.source, args.binary, args.initializer, args.job_root, args.subnet,
                   expected_binary_sha256=args.expected_binary_sha256)
    base.fresh_root(args.job_root, must_exist=args.write)
    sources = source_inventory(args.source, args.source_manifest, args.expected_source_manifest_sha256,
                               args.expected_source_commit)
    for path, expected in ((args.binary, args.expected_binary_sha256), (args.initializer, base.INITIALIZER_SHA256)):
        base.require(path.resolve() == path and not path.is_symlink() and path.is_file()
            and base.digest(path) == expected, "reviewed executable or initializer differs")
    dependency_inventory()
    compose = json.dumps(config, indent=2, sort_keys=True) + "\n"
    manifest = {"schema": "catchplate.privateProxyBasicPreparation/v1", "project": config["name"],
        "jobRoot": str(args.job_root), "source": str(args.source), "sourceCommit": args.expected_source_commit,
        "sourceManifest": str(args.source_manifest), "sourceManifestSha256": args.expected_source_manifest_sha256,
        "sourceSha256": sources, "sourceKind": "detached-archive", "binary": str(args.binary),
        "binarySha256": args.expected_binary_sha256, "initializer": str(args.initializer),
        "initializerSha256": base.INITIALIZER_SHA256, "clientImage": CLIENT_IMAGE,
        "clientDependencies": str(DEPENDENCIES), "clientDependencyManifestSha256": DEPENDENCY_MANIFEST_SHA256,
        "curlPath": "/usr/bin/curl", "curlSha256": CURL_SHA256,
        "composeSha256": hashlib.sha256(compose.encode()).hexdigest(), "subnet": args.subnet,
        "phaseOrder": ["initialize", "baseline-startup", "basic-pki", "edge-startup", "isolation", "check", "teardown"],
        "rootPreflightRequired": ["filesystem-capacity", "subnet-conflicts", "cached-images", "new-binary-acceptance",
            "actual-container-mounts-bounds", "actual-executable-digest", "shared-publication-lock", "client-curl-digest"],
        "automaticExecution": False, "launched": False, "productionReady": False,
        "checkerDeadlineSeconds": 120, "edgeLifetimeSeconds": 240, "freshApiNaturalExpiryVerified": False}
    if args.write:
        base.fresh_root(args.job_root, must_exist=True)
        (args.job_root / "runtime").mkdir(mode=0o700)
        for name, value in (("compose.json", compose), ("preparation.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")):
            descriptor = os.open(args.job_root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "w") as output:
                output.write(value)
                output.flush()
                os.fsync(output.fileno())
    return {"preparation": manifest, "compose": config}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "source-manifest", "binary", "initializer", "job-root"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("expected-source-manifest-sha256", "expected-binary-sha256"):
        parser.add_argument("--" + name, type=base.validated_binary_sha256, required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--subnet", required=True)
    parser.add_argument("--write", action="store_true")
    try:
        print(json.dumps(prepare(parser.parse_args()), indent=2, sort_keys=True))
    except (ValueError, OSError, KeyError, TypeError):
        raise SystemExit("Private Basic preparation refused; no input or exception details emitted") from None


if __name__ == "__main__":
    main()
