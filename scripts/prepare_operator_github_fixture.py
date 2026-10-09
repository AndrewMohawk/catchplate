#!/usr/bin/env python3
"""Render a dormant private GitHub SDK fixture; no Docker or SDK execution.

Reuses the separate private HTTPS-edge recipe, not the original relay-free
catalog preparer. Every source/SDK/executable is externally pinned. All runtime
phases are explicit; ordinary startup never runs acceptance or acquires deps.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re

from scripts import prepare_operator_proxy_basic_fixture as basic
from scripts.prepare_operator_catalog_fixture import bind, digest, require, validated_binary_sha256

base = basic.base
NODE_SHA256 = "3dc3f85ca5539ca81b7d106992ebcd82d09bce27326016873653a661ad6b2a7d"
LOCK_SHA256 = "1d4b07947867c9476eccda94c4673d73212092f3c2ccea6980d2c5dbf8126092"
CHECKER, JOB, FIXTURE = ("scripts/" + name for name in
    ("check_operator_github.py", "operator_github_job.mjs", "operator_github_fixture.py"))


def build(source, binary, initializer, root, subnet, node, sdk, *, expected_binary_sha256):
    require(root.parent == base.SCRATCH and re.fullmatch(r"serverware-github-private\.[A-Za-z0-9]{6,32}", root.name),
            "fresh private GitHub NVMe root required")
    template = root.with_name("serverware-proxy-basic-private." + root.name.split(".", 1)[1])
    config = basic.build(source, binary, initializer, template, subnet, expected_binary_sha256=expected_binary_sha256)
    for service in config["services"].values():
        for mount in service["volumes"]:
            path = Path(mount["source"])
            if path.is_relative_to(template): mount["source"] = str(root / path.relative_to(template))
    config["name"] = "serverware-github-private-" + hashlib.sha256(root.name.encode()).hexdigest()[:12]
    services, runtime = config["services"], root / "runtime"
    network = ipaddress.ip_network(subnet, strict=True)
    demo_ip, gate_ip, github_ip = (str(network.network_address + number) for number in (2, 4, 7))
    for name in ("serverware", "decision-gate-rs"):
        environment = services[name]["environment"]
        environment["SERVERWARE_OPERATOR_DEMO_UPSTREAMS"] = '["https://demo-upstream:8443","https://api.github.com"]'
        environment["SERVERWARE_OPERATOR_DEMO_FIXTURE_CIDRS"] = json.dumps([demo_ip + "/32", github_ip + "/32"])
        services[name]["extra_hosts"] = ["api.github.com:" + github_ip]
    gate = services["decision-gate-rs"]
    gate["environment"]["SERVERWARE_UPSTREAM_CA_BUNDLE"] = "/github-public/gate-ca.pem"
    gate["volumes"].append(bind(runtime / "upstream-data/github/gate-ca.pem", "/github-public/gate-ca.pem"))
    common = deepcopy(services["demo-upstream"])
    for key in ("command", "environment", "volumes", "healthcheck", "depends_on", "networks"):
        common.pop(key, None)
    common.update(image=base.APP_IMAGE, environment={"PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": "/app"},
                  cpus=0.5, mem_limit="256m", memswap_limit="256m", pids_limit=32)
    services["github-pki"] = {**deepcopy(common), "profiles": ["github-pki"], "network_mode": "none",
        "command": ["python", "-B", "/app/" + FIXTURE, "--setup"],
        "volumes": [bind(source, "/app"), bind(runtime / "upstream-data", "/upstream-data", False),
            bind(runtime / "upstream-data/demo-upstream/ca.pem", "/demo-ca.pem"),
            bind(runtime / ".private-fixture.json", "/private-fixture.json")]}
    services["github-pki"].pop("dns", None)
    services["github"] = {**deepcopy(common),
        "networks": {"fixture": {"ipv4_address": github_ip, "aliases": ["api.github.com"]}},
        "sysctls": {"net.ipv4.ip_unprivileged_port_start": "0"},
        "command": ["python", "-B", "/app/" + FIXTURE, "--listen-address", github_ip, "--lifetime-seconds", "300"],
        "volumes": [bind(source, "/app")] + [bind(runtime / "upstream-data/github" / name, "/github/" + name)
            for name in ("cert.pem", "key.pem", "ca.pem")],
        "healthcheck": {"test": ["CMD", "python", "-c",
            "import ssl,urllib.request; c=ssl.create_default_context(cafile='/github/ca.pem'); "
            "o=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=c)); "
            "r=o.open('https://api.github.com/_fixture/observations',timeout=2); raise SystemExit(0 if r.status==200 else 1)"],
            "interval": "3s", "timeout": "3s", "retries": 10, "start_period": "3s"}}
    services["serverware"]["depends_on"]["github"] = {"condition": "service_healthy"}
    check = services["check"]
    check["extra_hosts"] = ["api.github.com:" + github_ip]
    check["environment"] = {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": "/app"}
    check["command"] = ["/app/" + CHECKER, "--control-base", "http://serverware:3000",
        "--management-base", "http://" + gate_ip + ":9091", "--proxy-url", "https://" + basic.PROXY_HOST + ":8443",
        "--operator-origin", base.ORIGIN, "--expected-binary-sha256", "sha256:" + expected_binary_sha256,
        "--ca-file", "/client-trust/inner-ca.pem", "--proxy-ca-file", "/client-trust/outer-ca.pem",
        "--upstream-ca-file", "/client-trust/github-ca.pem", "--admin-token-file", "/client-secrets/admin.token",
        "--fixture-marker-file", "/private-fixture.json", "--run-claim-file", "/client-work/.operator-catalog-acceptance.claim",
        "--timeout-seconds", "180"]
    check["volumes"] = [bind(source, "/app"), bind(node, "/node"), bind(sdk / "node_modules", "/sdk/node_modules"),
        bind(runtime / "client-work", "/client-work", False), bind(runtime / "service-secrets/admin.token", "/client-secrets/admin.token"),
        bind(runtime / ".private-fixture.json", "/private-fixture.json"),
        bind(runtime / "upstream-data/github/ca.pem", "/client-trust/github-ca.pem")]
    check["volumes"] += [bind(runtime / "basic-pki" / name, "/client-trust/" + name) for name in ("inner-ca.pem", "outer-ca.pem")]
    return config


def prepare(args):
    config = build(args.source, args.binary, args.initializer, args.job_root, args.subnet,
        args.node_binary, args.sdk_root, expected_binary_sha256=args.expected_binary_sha256)
    base.fresh_root(args.job_root, must_exist=args.write)
    # Reuse detached full-source validation, not base.prepare's live Git reader.
    source_files = basic.source_inventory(args.source, args.source_manifest,
        args.expected_source_manifest_sha256, args.expected_source_commit)
    require({CHECKER, JOB, FIXTURE, "scripts/prepare_operator_github_fixture.py"} <= source_files.keys(),
        "paired GitHub fixture sources absent")
    for path, expected in ((args.binary, args.expected_binary_sha256), (args.node_binary, NODE_SHA256),
                           (args.initializer, base.INITIALIZER_SHA256)):
        require(path.is_absolute() and path.resolve() == path and path.is_file() and not path.is_symlink()
            and digest(path) == expected and path.stat().st_mode & 4, "pinned executable differs or unreadable")
    require(digest(args.sdk_root / "package-lock.json") == LOCK_SHA256, "exact acquired SDK lock differs")
    manifest = basic.pinned_json(args.sdk_manifest, args.expected_sdk_manifest_sha256)
    observed = basic.inventory(args.sdk_root / "node_modules", limit=8192, byte_limit=64 * 1024**2)
    require(manifest == {"schema": "serverware.privateGithubDependencies/v1", "packageLockSha256": LOCK_SHA256, "files": observed},
        "externally pinned full SDK payload differs")
    for package, version in (("@octokit/rest", "22.0.1"), ("undici", "8.11.2")):
        value = json.loads((args.sdk_root / "node_modules" / package / "package.json").read_text())
        require(value.get("name") == package and value.get("version") == version, "SDK package identity differs")
    compose = json.dumps(config, indent=2, sort_keys=True) + "\n"
    receipt = {"schema": "serverware.privateGithubPreparation/v1", "project": config["name"],
        "jobRoot": str(args.job_root), "source": str(args.source), "sourceCommit": args.expected_source_commit,
        "sourceManifestSha256": args.expected_source_manifest_sha256, "sourceSha256": source_files,
        "binary": str(args.binary), "binarySha256": args.expected_binary_sha256,
        "nodeBinary": str(args.node_binary), "nodeSha256": NODE_SHA256, "sdkRoot": str(args.sdk_root),
        "sdkManifestSha256": args.expected_sdk_manifest_sha256, "sdkLockSha256": LOCK_SHA256,
        "sdkPackages": {"@octokit/rest": "22.0.1", "undici": "8.11.2"},
        "clientImage": basic.CLIENT_IMAGE, "composeSha256": hashlib.sha256(compose.encode()).hexdigest(), "subnet": args.subnet,
        "phaseOrder": ["initialize", "demo-upstream-only", "github-pki-network-none", "github-app-gate-startup",
            "basic-pki-network-none", "edge-startup", "isolation-and-executable-inspection", "one-shot-check", "teardown"],
        "rootPreflightRequired": ["capacity", "subnet-conflicts", "cached-images", "new-normal-binary-acceptance",
            "source-and-sdk-readable-by-10001", "actual-mounts-bounds-internal-network-no-ports", "actual-binary-digest",
            "shared-publication-lock", "Node-startup-and-SDK-imports", "fixture-and-edge-lifetime-budget"],
        "checkerDeadlineSeconds": 180, "automaticExecution": False, "launched": False,
        "syntheticOnly": True, "productionReady": False, "realGithubVerified": False}
    if args.write:
        base.fresh_root(args.job_root, must_exist=True)
        (args.job_root / "runtime").mkdir(mode=0o700)
        for name, content in (("compose.json", compose), ("preparation.json", json.dumps(receipt, indent=2, sort_keys=True) + "\n")):
            descriptor = os.open(args.job_root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "w") as output:
                output.write(content); output.flush(); os.fsync(output.fileno())
    return {"preparation": receipt, "compose": config}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "source-manifest", "binary", "initializer", "job-root", "node-binary", "sdk-root", "sdk-manifest"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("expected-source-manifest-sha256", "expected-sdk-manifest-sha256", "expected-binary-sha256"):
        parser.add_argument("--" + name, type=validated_binary_sha256, required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--subnet", required=True)
    parser.add_argument("--write", action="store_true")
    try:
        print(json.dumps(prepare(parser.parse_args()), indent=2, sort_keys=True))
    except (ValueError, OSError, KeyError, TypeError):
        raise SystemExit("Private GitHub preparation refused; no input details emitted") from None


if __name__ == "__main__":
    main()
