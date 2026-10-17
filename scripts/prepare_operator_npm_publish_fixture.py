#!/usr/bin/env python3
"""Prepare, never launch, one private stock npm publish acceptance recipe."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re

from scripts import prepare_operator_npm_metadata_fixture as metadata
from scripts.prepare_operator_catalog_fixture import bind, digest, require, validated_binary_sha256

base, basic = metadata.base, metadata.basic
CHECKER = "scripts/check_operator_npm_publish.py"
JOB = "scripts/operator_npm_publish_job.mjs"
FIXTURE = "scripts/operator_npm_publish_fixture.py"


def build(source, binary, initializer, root, node, npm, *, expected_binary_sha256):
    require(root.parent == base.SCRATCH and re.fullmatch(r"catchplate-npm-publish-private\.[A-Za-z0-9]{6,32}", root.name),
        "fresh private npm publish root required")
    old_root = root.with_name("catchplate-npm-metadata-private." + root.name.split(".", 1)[1])
    config = metadata.build(source, binary, initializer, old_root, node, npm,
        expected_binary_sha256=expected_binary_sha256)
    config["name"] = "catchplate-npm-publish-private-" + hashlib.sha256(root.name.encode()).hexdigest()[:12]
    for service in config["services"].values():
        for mount in service["volumes"]:
            path = Path(mount["source"])
            if path.is_relative_to(old_root):
                mount["source"] = str(root / path.relative_to(old_root))
    services, runtime = config["services"], root / "runtime"
    for name in ("npm-pki", "npm-registry"):
        services[name]["command"] = [value.replace("scripts.operator_npm_metadata_fixture", "scripts.operator_npm_publish_fixture")
            for value in services[name]["command"]]
    services["npm-registry"]["volumes"].append(bind(runtime / "upstream-data/npm-publish-state", "/npm-state", False))
    check = services["check"]
    check["command"] = [value.replace(metadata.CHECKER, CHECKER) for value in check["command"]]
    check["volumes"].append(bind(runtime / "upstream-data/npm/packages", "/client-packages"))
    return config


def validate(config, *args, **kwargs):
    require(config == build(*args, **kwargs), "isolated npm publish recipe differs")


def prepare(args):
    config = build(args.source, args.binary, args.initializer, args.job_root, args.node_binary,
        args.npm_root, expected_binary_sha256=args.expected_binary_sha256)
    base.fresh_root(args.job_root, must_exist=args.write)
    source_files = basic.source_inventory(args.source, args.source_manifest,
        args.expected_source_manifest_sha256, args.expected_source_commit)
    require({CHECKER, JOB, FIXTURE, "scripts/prepare_operator_npm_publish_fixture.py", metadata.NETWORK_HELPER,
        metadata.FIXTURE, "scripts/prepare_operator_npm_metadata_fixture.py"} <= source_files.keys(), "paired publish fixture sources absent")
    for path, expected in ((args.binary, args.expected_binary_sha256), (args.node_binary, metadata.NODE_SHA256),
            (args.initializer, base.INITIALIZER_SHA256)):
        require(path.is_absolute() and path.resolve() == path and path.is_file() and not path.is_symlink()
            and digest(path) == expected and path.stat().st_mode & 4, "pinned executable differs or unreadable")
    manifest = basic.pinned_json(args.npm_manifest, args.expected_npm_manifest_sha256)
    observed = basic.inventory(args.npm_root, limit=4096, byte_limit=64 * 1024**2)
    require(len(observed) == 1782 and manifest == {"schema": "catchplate.privateNpmMetadataDependencies/v1",
        "packages": metadata.PACKAGES, "files": observed}, "externally pinned full npm tree differs")
    for name, version in metadata.PACKAGES.items():
        relative = "package.json" if name == "npm" else "node_modules/" + name + "/package.json"
        package = json.loads((args.npm_root / relative).read_text())
        require(package.get("name") == name and package.get("version") == version, "stock npm dependency identity differs")
    compose = json.dumps(config, indent=2, sort_keys=True) + "\n"
    receipt = {"schema": "catchplate.privateNpmPublishPreparation/v1", "project": config["name"],
        "jobRoot": str(args.job_root), "source": str(args.source), "sourceCommit": args.expected_source_commit,
        "sourceManifestSha256": args.expected_source_manifest_sha256, "sourceSha256": source_files,
        "binary": str(args.binary), "binarySha256": args.expected_binary_sha256,
        "nodeBinary": str(args.node_binary), "nodeSha256": metadata.NODE_SHA256,
        "npmRoot": str(args.npm_root), "npmManifestSha256": args.expected_npm_manifest_sha256,
        "packages": metadata.PACKAGES, "clientImage": basic.CLIENT_IMAGE,
        "composeSha256": hashlib.sha256(compose.encode()).hexdigest(),
        "network": {"mode": "none", "interfaces": ["lo"], "fixtureOnlyAddress": metadata.FIXTURE_IP,
            "hostPorts": [], "defaultRoute": False, "externalProviderContact": False,
            "hostsSha256": hashlib.sha256(metadata.HOSTS).hexdigest(), "resolvSha256": hashlib.sha256(metadata.RESOLV).hexdigest()},
        "phaseOrder": ["initialize", "npm-pki-network-none", "network-keeper-startup", "npm-app-gate-startup",
            "basic-pki-network-none", "edge-startup", "isolation-and-executable-inspection", "one-shot-check", "teardown"],
        "rootPreflightRequired": ["capacity", "cached-images", "frozen-source-and-normal-binary-join",
            "source-and-npm-readable-by-10001", "actual-mounts-bounds-shared-network-none-no-ports",
            "actual-binary-digest", "shared-publication-lock", "Node-startup-and-stock-npm-imports",
            "keeper-fixture-and-edge-original-lifetime", "before-and-after-source-and-npm-manifests"],
        "checkerDeadlineSeconds": 180, "keeperLifetimeSeconds": metadata.KEEPER_SECONDS,
        "providerLifetimeSeconds": 300, "edgeLifetimeSeconds": metadata.EDGE_SECONDS,
        "maxClientCommands": 7, "automaticExecution": False, "launched": False,
        "syntheticOnly": True, "productionReady": False, "realNpmVerified": False, "npmInstallVerified": False}
    if args.write:
        base.fresh_root(args.job_root, must_exist=True); (args.job_root / "runtime").mkdir(mode=0o700)
        for name, raw in (("compose.json", compose), ("preparation.json", json.dumps(receipt, indent=2, sort_keys=True) + "\n")):
            descriptor = os.open(args.job_root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "w") as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    return {"preparation": receipt, "compose": config}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "source-manifest", "binary", "initializer", "job-root", "node-binary", "npm-root", "npm-manifest"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("expected-source-manifest-sha256", "expected-npm-manifest-sha256", "expected-binary-sha256"):
        parser.add_argument("--" + name, type=validated_binary_sha256, required=True)
    parser.add_argument("--expected-source-commit", required=True); parser.add_argument("--write", action="store_true")
    try:
        print(json.dumps(prepare(parser.parse_args()), indent=2, sort_keys=True))
    except (ValueError, OSError, KeyError, TypeError):
        raise SystemExit("Private npm publish preparation refused; no input details emitted") from None
