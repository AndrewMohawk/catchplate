#!/usr/bin/env python3
"""Prepare, never launch, the existing Basic fixture with a curated gate mount.

The actual app creates gate-runtime during normal startup. Start only the app
and synthetic upstream first; do not create the gate until those files exist.
The unchanged stock-client checker already tests two signed policy reloads,
Requests/curl Basic, Bearer regression and TLS/authentication refusal controls.
No policy, database, key, Docker, Git or provider operation occurs here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re

from scripts import prepare_operator_proxy_basic_fixture as basic

base = basic.base
CHECKER = "scripts/check_operator_curated_gate.py"
LEAVES = (".operator-publication.lock", ".catchplate-operator-demo.json",
          "mitmproxy/mitmproxy-ca-cert.pem", "mitmproxy/mitmproxy-ca.pem")


def build(source, binary, initializer, root, subnet, *, expected_binary_sha256):
    """Pure closed recipe derived from, not replacing, the Basic fixture."""
    base.require(root.parent == base.SCRATCH and re.fullmatch(
        r"catchplate-curated-gate-private\.[A-Za-z0-9]{6,32}", root.name), "fresh curated fixture root required")
    template = root.with_name("catchplate-proxy-basic-private." + root.name.split(".", 1)[1])
    config = basic.build(source, binary, initializer, template, subnet, expected_binary_sha256=expected_binary_sha256)
    for service in config["services"].values():
        for mount in service["volumes"]:
            path = Path(mount["source"])
            if path.is_relative_to(template):
                mount["source"] = str(root / path.relative_to(template))
    config["name"] = "catchplate-curated-gate-private-" + hashlib.sha256(root.name.encode()).hexdigest()[:12]
    config["services"]["catchplate"]["environment"]["CATCHPLATE_OPERATOR_GATE_PUBLICATION_ENABLED"] = "1"
    data = root / "runtime/app-data"
    gate = config["services"]["decision-gate-rs"]
    for mount in gate["volumes"]:
        if mount["target"] == "/data":
            mount["source"] = str(data / "gate-runtime")
    gate["volumes"].extend(base.bind(data / name, "/data/" + name) for name in LEAVES)
    return config


def validate(config, source, binary, initializer, root, subnet, *, expected_binary_sha256):
    base.require(config == build(source, binary, initializer, root, subnet,
        expected_binary_sha256=expected_binary_sha256), "curated fixture recipe differs")


def prepare(args):
    config = build(args.source, args.binary, args.initializer, args.job_root, args.subnet,
        expected_binary_sha256=args.expected_binary_sha256)
    base.fresh_root(args.job_root, must_exist=args.write)
    sources = basic.source_inventory(args.source, args.source_manifest, args.expected_source_manifest_sha256,
        args.expected_source_commit)
    base.require({CHECKER, "scripts/prepare_operator_curated_gate_fixture.py", "catchplate/operator_gate_publication.py"}
        <= sources.keys(), "curated fixture source missing")
    for path, expected in ((args.binary, args.expected_binary_sha256), (args.initializer, base.INITIALIZER_SHA256)):
        base.require(path.resolve() == path and path.is_file() and not path.is_symlink()
            and base.digest(path) == expected, "actual Rust binary or existing initializer differs")
    basic.dependency_inventory()
    compose = json.dumps(config, indent=2, sort_keys=True) + "\n"
    receipt = {"schema": "catchplate.privateCuratedGatePreparation/v1", "project": config["name"],
        "jobRoot": str(args.job_root), "source": str(args.source), "sourceCommit": args.expected_source_commit,
        "sourceManifest": str(args.source_manifest), "sourceManifestSha256": args.expected_source_manifest_sha256,
        "sourceFiles": len(sources), "binary": str(args.binary), "binarySha256": args.expected_binary_sha256,
        "initializer": str(args.initializer), "initializerSha256": base.INITIALIZER_SHA256,
        "subnet": args.subnet, "composeSha256": hashlib.sha256(compose.encode()).hexdigest(),
        "clientChecker": basic.CHECKER, "clientCheckerSha256": sources[basic.CHECKER],
        "clientImage": basic.CLIENT_IMAGE, "clientDependencyManifestSha256": basic.DEPENDENCY_MANIFEST_SHA256,
        "phaseOrder": ["initialize", "start-upstream-and-app-only", "wait-app-healthy-and-export-tree",
            "create-start-gate", "basic-pki", "edge-startup", "curated-probe-before", "unchanged-basic-check",
            "curated-probe-after", "teardown"],
        "rootPreflightRequired": ["capacity", "cached-images", "subnet-conflicts", "actual-container-isolation",
            "source-binary-and-client-provenance", "publication-lock-and-private-file-isolation"],
        "automaticExecution": False, "launched": False, "productionReady": False, "realProviderVerified": False}
    if args.write:
        base.fresh_root(args.job_root, must_exist=True)
        (args.job_root / "runtime").mkdir(mode=0o700)
        for name, text in (("compose.json", compose), ("preparation.json", json.dumps(receipt, indent=2, sort_keys=True) + "\n")):
            descriptor = os.open(args.job_root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "w") as stream:
                stream.write(text); stream.flush(); os.fsync(stream.fileno())
    return {"preparation": receipt, "compose": config}


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
        raise SystemExit("Curated fixture preparation refused; no input details emitted") from None


if __name__ == "__main__":
    main()
