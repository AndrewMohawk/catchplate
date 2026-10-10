#!/usr/bin/env python3
"""Render a dormant X SDK fixture using the accepted isolated topology.

Never launches containers, executes clients or changes a provider destination.
The separate runner must join pinned Python/Go payloads and the observed initial
revision before its one-shot checker can run. No old binary pin is a default.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re

from scripts import prepare_operator_github_fixture as inherited
from scripts.prepare_operator_catalog_fixture import bind, digest, require, validated_binary_sha256
from scripts.operator_x_fixture_network import FIXTURE_IP, HOSTS, RESOLV, KEEPER_SECONDS, EDGE_SECONDS

base, basic = inherited.base, inherited.basic
NODE_SHA256 = inherited.NODE_SHA256
LOCK_SHA256 = "4466ce2fb3b0e987637721a9efc046124761b9a6540accfa381d4bc03afbe82c"
CHECKER = "scripts/check_operator_x_examples.py"
FIXTURE = "scripts/operator_x_examples_fixture.py"
NETWORK_HELPER = "scripts/operator_x_fixture_network.py"


def build(source, binary, initializer, root, node, sdk, *, expected_binary_sha256):
    require(root.parent == base.SCRATCH and re.fullmatch(r"serverware-x-private\.[A-Za-z0-9]{6,32}", root.name),
        "fresh private X NVMe root required")
    template = root.with_name("serverware-github-private." + root.name.split(".", 1)[1])
    config = inherited.build(source, binary, initializer, template, node, sdk,
        expected_binary_sha256=expected_binary_sha256)
    config["name"] = "serverware-x-private-" + hashlib.sha256(root.name.encode()).hexdigest()[:12]
    services, runtime = config["services"], root / "runtime"
    # Only known inherited private paths are rewritten; arbitrary strings and
    # production environment values are never recursively substituted.
    for service in services.values():
        for mount in service["volumes"]:
            path = Path(mount["source"])
            if path.is_relative_to(template):
                relative = path.relative_to(template)
                parts = tuple("x" if p == "github" else "x-network" if p == "github-network" else p
                    for p in relative.parts)
                mount["source"] = str(root.joinpath(*parts))
            target = mount["target"]
            if target.startswith("/github/"):
                mount["target"] = "/x/" + target.removeprefix("/github/")
            elif target == "/github-public/ca.pem":
                mount["target"] = "/x-public/ca.pem"
            elif target == "/client-trust/github-ca.pem":
                mount["target"] = "/client-trust/x-ca.pem"
    services["x-pki"] = services.pop("github-pki")
    services["x-pki"]["profiles"] = ["x-pki"]
    services["x-pki"]["command"] = ["python", "-B", "-m", "scripts.operator_x_examples_fixture", "--setup"]
    services["x"] = services.pop("github")
    services["x"]["command"] = ["python", "-B", "-m", "scripts.operator_x_examples_fixture", "--lifetime-seconds", "300"]
    services["x"]["healthcheck"]["test"] = ["CMD", "python", "-c",
        "import ssl,urllib.request; c=ssl.create_default_context(cafile='/x/ca.pem'); "
        "o=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=c)); "
        "r=o.open('https://api.x.com/_fixture/observations',timeout=2); raise SystemExit(0 if r.status==200 else 1)"]
    services["network"]["command"] = ["python", "-B", "-m", "scripts.operator_x_fixture_network", "network"]
    services["edge"]["command"] = ["-m", "scripts.operator_x_fixture_network", "edge"]
    services["serverware"]["depends_on"] = {"x": {"condition": "service_healthy"}}
    for name in ("serverware", "decision-gate-rs"):
        services[name]["environment"]["SERVERWARE_OPERATOR_DEMO_UPSTREAMS"] = '["https://api.x.com"]'
    services["decision-gate-rs"]["environment"]["SERVERWARE_UPSTREAM_CA_BUNDLE"] = "/x-public/ca.pem"
    check = services["check"]
    check["command"][0] = "/app/" + CHECKER
    position = check["command"].index("--upstream-ca-file") + 1
    check["command"][position] = "/client-trust/x-ca.pem"
    check["volumes"] = [mount for mount in check["volumes"]
        if mount["target"] not in {"/sdk/node_modules", "/client-trust/requests-ca.pem"}]
    check["volumes"].append(bind(sdk / "node_modules", "/app/examples/x-username-node/node_modules"))
    require(set(services) == {"initialize", "x-pki", "basic-pki", "network", "x", "serverware",
        "decision-gate-rs", "edge", "check"}, "X fixture service roster differs")
    return config


def validate(config, source, binary, initializer, root, node, sdk, *, expected_binary_sha256):
    require(config == build(source, binary, initializer, root, node, sdk,
        expected_binary_sha256=expected_binary_sha256), "isolated X recipe differs")


def prepare(args):
    config = build(args.source, args.binary, args.initializer, args.job_root, args.node_binary, args.sdk_root,
        expected_binary_sha256=args.expected_binary_sha256)
    base.fresh_root(args.job_root, must_exist=args.write)
    sources = basic.source_inventory(args.source, args.source_manifest,
        args.expected_source_manifest_sha256, args.expected_source_commit)
    require({CHECKER, FIXTURE, NETWORK_HELPER, "scripts/prepare_operator_x_fixture.py",
        "examples/x-username-node/client.mjs", "examples/x-username-python/username.py",
        "examples/x-username-go/main.go"} <= sources.keys(), "paired X source roster absent")
    for path, expected in ((args.binary, args.expected_binary_sha256), (args.node_binary, NODE_SHA256),
            (args.initializer, base.INITIALIZER_SHA256)):
        require(path.is_absolute() and path.resolve() == path and path.is_file() and not path.is_symlink()
            and digest(path) == expected and path.stat().st_mode & 4, "pinned executable differs or unreadable")
    require(digest(args.sdk_root / "package-lock.json") == LOCK_SHA256, "exact acquired X SDK lock differs")
    manifest = basic.pinned_json(args.sdk_manifest, args.expected_sdk_manifest_sha256)
    observed = basic.inventory(args.sdk_root / "node_modules", limit=8192, byte_limit=64 * 1024**2)
    require(manifest == {"schema": "serverware.privateXDependencies/v1", "packageLockSha256": LOCK_SHA256,
        "files": observed}, "externally pinned full X SDK payload differs")
    for package, version in (("@xdevplatform/xdk", "0.6.6"), ("undici", "8.11.2")):
        value = json.loads((args.sdk_root / "node_modules" / package / "package.json").read_text())
        require(value.get("name") == package and value.get("version") == version, "X SDK package identity differs")
    compose = json.dumps(config, indent=2, sort_keys=True) + "\n"
    receipt = {"schema": "serverware.privateXPreparation/v1", "project": config["name"],
        "jobRoot": str(args.job_root), "source": str(args.source), "sourceCommit": args.expected_source_commit,
        "sourceManifestSha256": args.expected_source_manifest_sha256, "sourceSha256": sources,
        "binary": str(args.binary), "binarySha256": args.expected_binary_sha256,
        "nodeBinary": str(args.node_binary), "nodeSha256": NODE_SHA256, "sdkRoot": str(args.sdk_root),
        "sdkManifestSha256": args.expected_sdk_manifest_sha256, "sdkLockSha256": LOCK_SHA256,
        "sdkPackages": {"@xdevplatform/xdk": "0.6.6", "undici": "8.11.2"},
        "composeSha256": hashlib.sha256(compose.encode()).hexdigest(),
        "network": {"mode": "none", "interfaces": ["lo"], "fixtureOnlyAddress": FIXTURE_IP,
            "hostPorts": [], "defaultRoute": False, "externalProviderContact": False,
            "hostsSha256": hashlib.sha256(HOSTS).hexdigest(), "resolvSha256": hashlib.sha256(RESOLV).hexdigest()},
        "phaseOrder": ["initialize", "x-pki-network-none", "network-keeper-startup", "x-app-gate-startup",
            "basic-pki-network-none", "edge-startup", "isolation-and-executable-inspection", "one-shot-check", "teardown"],
        "runnerJoinRequired": ["pinned-Python-runtime-image-and-dependencies", "pinned-Go-binary-build-receipt",
            "expected-Go-sha256", "observed-initial-revision", "final-compose-pin-and-exact-mount-inspection"],
        "rootPreflightRequired": ["capacity", "cached-images", "new-normal-X-binary-acceptance",
            "source-and-SDK-readable-by-10001", "actual-shared-network-none-no-ports", "actual-binary-digest",
            "shared-publication-lock", "keeper-fixture-and-edge-lifetime-budget", "bounded-one-shot-cleanup"],
        "checkerDeadlineSeconds": 180, "keeperLifetimeSeconds": KEEPER_SECONDS,
        "providerLifetimeSeconds": 300, "edgeLifetimeSeconds": EDGE_SECONDS,
        "automaticExecution": False, "launched": False, "runnerJoined": False,
        "syntheticOnly": True, "productionReady": False, "realXVerified": False}
    if args.write:
        base.fresh_root(args.job_root, must_exist=True)
        (args.job_root / "runtime").mkdir(mode=0o700)
        for name, content in (("compose.json", compose), ("preparation.json", json.dumps(receipt, indent=2, sort_keys=True) + "\n")):
            descriptor = os.open(args.job_root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "w") as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
    return {"preparation": receipt, "compose": config}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "source-manifest", "binary", "initializer", "job-root", "node-binary", "sdk-root", "sdk-manifest"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("expected-source-manifest-sha256", "expected-sdk-manifest-sha256", "expected-binary-sha256"):
        parser.add_argument("--" + name, type=validated_binary_sha256, required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--write", action="store_true")
    try:
        print(json.dumps(prepare(parser.parse_args()), indent=2, sort_keys=True))
    except (ValueError, OSError, KeyError, TypeError):
        raise SystemExit("Private X preparation refused; no input details emitted") from None


if __name__ == "__main__":
    main()
