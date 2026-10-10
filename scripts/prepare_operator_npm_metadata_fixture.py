#!/usr/bin/env python3
"""Render a dormant, network-none stock npm metadata acceptance recipe.

Reuses the existing hardened Basic-proxy fixture and its detached-source
inventory. All Node/npm bytes are separately pinned. No Docker, downloads,
provider access, live mounts or acceptance execution occurs here.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re

from scripts import prepare_operator_proxy_basic_fixture as basic
from scripts.prepare_operator_catalog_fixture import bind, digest, require, validated_binary_sha256
from scripts.operator_npm_metadata_fixture_network import FIXTURE_IP, HOSTS, RESOLV, KEEPER_SECONDS, EDGE_SECONDS

base = basic.base
NODE_SHA256 = "3dc3f85ca5539ca81b7d106992ebcd82d09bce27326016873653a661ad6b2a7d"
PACKAGES = {"npm": "11.8.0", "pacote": "21.0.4", "npm-registry-fetch": "19.1.1"}
CHECKER = "scripts/check_operator_npm_metadata.py"
JOB = "scripts/operator_npm_metadata_job.mjs"
FIXTURE = "scripts/operator_npm_metadata_fixture.py"
NETWORK_HELPER = "scripts/operator_npm_metadata_fixture_network.py"


def build(source, binary, initializer, root, node, npm, *, expected_binary_sha256):
    require(root.parent == base.SCRATCH and re.fullmatch(r"serverware-npm-metadata-private\.[A-Za-z0-9]{6,32}", root.name),
        "fresh private npm metadata root required")
    template = root.with_name("serverware-proxy-basic-private." + root.name.split(".", 1)[1])
    config = basic.build(source, binary, initializer, template, "172.16.249.48/28",
        expected_binary_sha256=expected_binary_sha256)
    for service in config["services"].values():
        for mount in service["volumes"]:
            path = Path(mount["source"])
            if path.is_relative_to(template):
                mount["source"] = str(root / path.relative_to(template))
    config["name"] = "serverware-npm-metadata-private-" + hashlib.sha256(root.name.encode()).hexdigest()[:12]
    config.pop("networks")
    services, runtime = config["services"], root / "runtime"
    common = deepcopy(services.pop("demo-upstream"))
    for key in ("command", "environment", "volumes", "healthcheck", "depends_on", "networks", "dns"):
        common.pop(key, None)
    common.update(image=base.APP_IMAGE, environment={"PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": "/app"},
        cpus=0.5, mem_limit="256m", memswap_limit="256m", pids_limit=32)
    hosts = [bind(runtime / "upstream-data/npm-network/hosts", "/etc/hosts"),
        bind(runtime / "upstream-data/npm-network/resolv.conf", "/etc/resolv.conf")]
    for name in ("serverware", "decision-gate-rs"):
        services[name]["environment"]["SERVERWARE_OPERATOR_DEMO_UPSTREAMS"] = '["https://registry.npmjs.org"]'
        services[name]["environment"].pop("SERVERWARE_OPERATOR_DEMO_FIXTURE_CIDRS")
        services[name]["volumes"] = [row for row in services[name]["volumes"] if row["target"] != "/demo-upstream"]
    services["serverware"]["depends_on"] = {"npm-registry": {"condition": "service_healthy"}}
    services["serverware"]["environment"]["SERVERWARE_DECISION_GATE_BASE"] = "http://127.0.0.1:9091"
    gate = services["decision-gate-rs"]
    gate["environment"].update(SERVERWARE_UPSTREAM_CA_BUNDLE="/npm-public/ca.pem",
        SERVERWARE_DECISION_GATE_HOST="127.0.0.1", SERVERWARE_DECISION_GATE_MANAGEMENT_HOST="127.0.0.1")
    gate["volumes"].append(bind(runtime / "upstream-data/npm/ca.pem", "/npm-public/ca.pem"))
    gate["healthcheck"] = base.health("http://127.0.0.1:9091/healthz", start=20)
    services["npm-pki"] = {**deepcopy(common), "profiles": ["npm-pki"], "network_mode": "none",
        "command": ["python", "-B", "-m", "scripts.operator_npm_metadata_fixture", "--setup"],
        "volumes": [bind(source, "/app"), bind(runtime / "upstream-data", "/upstream-data", False),
            bind(runtime / ".private-fixture.json", "/private-fixture.json")]}
    services["network"] = {**deepcopy(common), "user": "0:0", "init": False, "network_mode": "none",
        "cap_add": ["NET_ADMIN", "SETUID", "SETGID"], "cpus": 0.25, "pids_limit": 16,
        "command": ["python", "-B", "-m", "scripts.operator_npm_metadata_fixture_network", "network"],
        "sysctls": {"net.ipv4.ip_unprivileged_port_start": "0", "net.ipv4.ip_nonlocal_bind": "0"},
        "volumes": [bind(source, "/app"), bind(runtime / "upstream-data/npm-network", "/fixture-network", False), *hosts],
        "healthcheck": {"test": ["CMD", "python", "-c",
            "import os,stat; os.setgroups([]); os.setgid(10001); os.setuid(10001); "
            "s=os.stat('/fixture-network/ready',follow_symlinks=False); "
            "raise SystemExit(0 if stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==0o400 "
            "and s.st_uid==s.st_gid==10001 and s.st_nlink==1 and 0<s.st_size<=1024 else 1)"],
            "interval": "2s", "timeout": "3s", "retries": 10, "start_period": "3s"}}
    services["npm-registry"] = {**deepcopy(common), "depends_on": {"network": {"condition": "service_healthy"}},
        "command": ["python", "-B", "-m", "scripts.operator_npm_metadata_fixture", "--lifetime-seconds", "300"],
        "volumes": [bind(source, "/app")] + [bind(runtime / "upstream-data/npm" / name, "/npm-fixture/" + name)
            for name in ("cert.pem", "key.pem", "ca.pem")],
        "healthcheck": {"test": ["CMD", "python", "-c",
            "import ssl,urllib.request; c=ssl.create_default_context(cafile='/npm-fixture/ca.pem'); "
            "o=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=c)); "
            "r=o.open('https://registry.npmjs.org/_fixture/observations',timeout=2); raise SystemExit(0 if r.status==200 else 1)"],
            "interval": "3s", "timeout": "3s", "retries": 10, "start_period": "3s"}}
    services["edge"].update(entrypoint=["python", "-B"],
        command=["-m", "scripts.operator_npm_metadata_fixture_network", "edge"])
    check = services["check"]
    check["environment"] = {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": "/app"}
    check["command"] = ["/app/" + CHECKER, "--control-base", "http://serverware:3000",
        "--management-base", "http://127.0.0.1:9091", "--proxy-url", "https://" + basic.PROXY_HOST + ":8443",
        "--operator-origin", base.ORIGIN, "--expected-binary-sha256", "sha256:" + expected_binary_sha256,
        "--ca-file", "/client-trust/inner-ca.pem", "--proxy-ca-file", "/client-trust/outer-ca.pem",
        "--upstream-ca-file", "/client-trust/npm-ca.pem", "--admin-token-file", "/client-secrets/admin.token",
        "--fixture-marker-file", "/private-fixture.json", "--run-claim-file", "/client-work/.operator-catalog-acceptance.claim",
        "--timeout-seconds", "180"]
    check["volumes"] = [bind(source, "/app"), bind(node, "/node"), bind(npm, "/npm"),
        bind(runtime / "client-work", "/client-work", False), bind(runtime / "service-secrets/admin.token", "/client-secrets/admin.token"),
        bind(runtime / ".private-fixture.json", "/private-fixture.json"),
        bind(runtime / "upstream-data/npm/ca.pem", "/client-trust/npm-ca.pem")]
    check["volumes"] += [bind(runtime / "basic-pki" / name, "/client-trust/" + name)
        for name in ("inner-ca.pem", "outer-ca.pem", "requests-ca.pem")]
    for name in ("serverware", "decision-gate-rs", "npm-registry", "edge", "check"):
        service = services[name]; service.pop("networks", None); service.pop("dns", None)
        service["network_mode"] = "service:network"; service["volumes"] += deepcopy(hosts)
    services["initialize"].pop("dns", None)
    return config


def validate(config, source, binary, initializer, root, node, npm, *, expected_binary_sha256):
    require(config == build(source, binary, initializer, root, node, npm,
        expected_binary_sha256=expected_binary_sha256), "isolated npm metadata recipe differs")


def prepare(args):
    config = build(args.source, args.binary, args.initializer, args.job_root, args.node_binary,
        args.npm_root, expected_binary_sha256=args.expected_binary_sha256)
    base.fresh_root(args.job_root, must_exist=args.write)
    source_files = basic.source_inventory(args.source, args.source_manifest,
        args.expected_source_manifest_sha256, args.expected_source_commit)
    require({CHECKER, JOB, FIXTURE, NETWORK_HELPER, "scripts/prepare_operator_npm_metadata_fixture.py"} <= source_files.keys(),
        "paired npm fixture sources absent")
    for path, expected in ((args.binary, args.expected_binary_sha256), (args.node_binary, NODE_SHA256),
            (args.initializer, base.INITIALIZER_SHA256)):
        require(path.is_absolute() and path.resolve() == path and path.is_file() and not path.is_symlink()
            and digest(path) == expected and path.stat().st_mode & 4, "pinned executable differs or unreadable")
    manifest = basic.pinned_json(args.npm_manifest, args.expected_npm_manifest_sha256)
    observed = basic.inventory(args.npm_root, limit=4096, byte_limit=64 * 1024**2)
    require(len(observed) == 1782 and manifest == {"schema": "serverware.privateNpmMetadataDependencies/v1",
        "packages": PACKAGES, "files": observed}, "externally pinned full npm tree differs")
    for name, version in PACKAGES.items():
        path = args.npm_root / ("package.json" if name == "npm" else "node_modules/" + name + "/package.json")
        package = json.loads(path.read_text())
        require(package.get("name") == name and package.get("version") == version, "stock npm dependency identity differs")
    compose = json.dumps(config, indent=2, sort_keys=True) + "\n"
    receipt = {"schema": "serverware.privateNpmMetadataPreparation/v1", "project": config["name"],
        "jobRoot": str(args.job_root), "source": str(args.source), "sourceCommit": args.expected_source_commit,
        "sourceManifestSha256": args.expected_source_manifest_sha256, "sourceSha256": source_files,
        "binary": str(args.binary), "binarySha256": args.expected_binary_sha256,
        "nodeBinary": str(args.node_binary), "nodeSha256": NODE_SHA256, "npmRoot": str(args.npm_root),
        "npmManifestSha256": args.expected_npm_manifest_sha256, "packages": PACKAGES,
        "clientImage": basic.CLIENT_IMAGE, "composeSha256": hashlib.sha256(compose.encode()).hexdigest(),
        "network": {"mode": "none", "interfaces": ["lo"], "fixtureOnlyAddress": FIXTURE_IP,
            "hostPorts": [], "defaultRoute": False, "externalProviderContact": False,
            "hostsSha256": hashlib.sha256(HOSTS).hexdigest(), "resolvSha256": hashlib.sha256(RESOLV).hexdigest()},
        "phaseOrder": ["initialize", "npm-pki-network-none", "network-keeper-startup", "npm-app-gate-startup",
            "basic-pki-network-none", "edge-startup", "isolation-and-executable-inspection", "one-shot-check", "teardown"],
        "rootPreflightRequired": ["capacity", "cached-images", "new-normal-binary-acceptance",
            "source-and-npm-readable-by-10001", "actual-mounts-bounds-shared-network-none-no-ports", "actual-binary-digest",
            "shared-publication-lock", "Node-startup-and-stock-npm-imports", "keeper-fixture-and-edge-lifetime-budget"],
        "checkerDeadlineSeconds": 180, "keeperLifetimeSeconds": KEEPER_SECONDS,
        "providerLifetimeSeconds": 300, "edgeLifetimeSeconds": EDGE_SECONDS,
        "automaticExecution": False, "launched": False, "syntheticOnly": True,
        "productionReady": False, "realNpmVerified": False, "npmInstallVerified": False}
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
        raise SystemExit("Private npm metadata preparation refused; no input details emitted") from None
