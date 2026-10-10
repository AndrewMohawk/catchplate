#!/usr/bin/env python3
"""Pure dormant Alchemy topology; explicit runner owns every runtime action.

Reuses the accepted X/GitHub network-none recipe. No dependency inventory,
installation, image pull, source mutation, PKI creation or container launch.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

from scripts import prepare_operator_x_fixture as inherited
from scripts.prepare_operator_catalog_fixture import require, validated_binary_sha256
from scripts.operator_alchemy_fixture_network import PROVIDER_HOSTS

base, basic = inherited.base, inherited.basic
NODE_SHA256 = inherited.NODE_SHA256
CHECKER = "scripts/check_operator_alchemy_examples.py"
FIXTURE = "scripts/operator_alchemy_examples_fixture.py"
NETWORK_HELPER = "scripts/operator_alchemy_fixture_network.py"


def build(source, binary, initializer, root, node, sdk, *, expected_binary_sha256):
    require(root.parent == base.SCRATCH and re.fullmatch(r"serverware-alchemy-private\.[A-Za-z0-9]{6,32}", root.name),
        "fresh private Alchemy NVMe root required")
    template = root.with_name("serverware-x-private." + root.name.split(".", 1)[1])
    config = inherited.build(source, binary, initializer, template, node, sdk,
        expected_binary_sha256=expected_binary_sha256)
    config["name"] = "serverware-alchemy-private-" + hashlib.sha256(root.name.encode()).hexdigest()[:12]
    services = config["services"]
    for service in services.values():
        for mount in service["volumes"]:
            path = Path(mount["source"])
            if path.is_relative_to(template):
                parts = tuple("alchemy" if part == "x" else "alchemy-network" if part == "x-network" else part
                    for part in path.relative_to(template).parts)
                mount["source"] = str(root.joinpath(*parts))
            target = mount["target"]
            if target.startswith("/x/"):
                mount["target"] = "/alchemy/" + target.removeprefix("/x/")
            elif target == "/x-public/ca.pem":
                mount["target"] = "/alchemy-public/ca.pem"
            elif target == "/client-trust/x-ca.pem":
                mount["target"] = "/client-trust/alchemy-ca.pem"
            elif target == "/app/examples/x-username-node/node_modules":
                mount["target"] = "/app/examples/alchemy-chain-status-node/node_modules"
    services["alchemy-pki"] = services.pop("x-pki")
    services["alchemy-pki"]["profiles"] = ["alchemy-pki"]
    services["alchemy-pki"]["command"] = ["python", "-B", "-m", "scripts.operator_alchemy_examples_fixture", "--setup"]
    services["alchemy"] = services.pop("x")
    services["alchemy"]["command"] = ["python", "-B", "-m", "scripts.operator_alchemy_examples_fixture", "--lifetime-seconds", "300"]
    services["alchemy"]["healthcheck"]["test"] = ["CMD", "python", "-c",
        "import ssl,urllib.request; c=ssl.create_default_context(cafile='/alchemy/ca.pem'); "
        "o=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=c)); "
        "r=o.open('https://eth-mainnet.g.alchemy.com/_fixture/observations',timeout=2); raise SystemExit(0 if r.status==200 else 1)"]
    services["network"]["command"] = ["python", "-B", "-m", "scripts.operator_alchemy_fixture_network", "network"]
    services["edge"]["command"] = ["-m", "scripts.operator_alchemy_fixture_network", "edge"]
    services["serverware"]["depends_on"] = {"alchemy": {"condition": "service_healthy"}}
    for name in ("serverware", "decision-gate-rs"):
        services[name]["environment"]["SERVERWARE_OPERATOR_DEMO_UPSTREAMS"] = json.dumps(
            ["https://" + host for host in PROVIDER_HOSTS], separators=(",", ":"))
    services["decision-gate-rs"]["environment"]["SERVERWARE_UPSTREAM_CA_BUNDLE"] = "/alchemy-public/ca.pem"
    check = services["check"]
    check["command"][0] = "/app/" + CHECKER
    check["command"][check["command"].index("--upstream-ca-file") + 1] = "/client-trust/alchemy-ca.pem"
    require(set(services) == {"initialize", "alchemy-pki", "basic-pki", "network", "alchemy",
        "serverware", "decision-gate-rs", "edge", "check"}, "Alchemy fixture service roster differs")
    return config


def validate(config, source, binary, initializer, root, node, sdk, *, expected_binary_sha256):
    require(config == build(source, binary, initializer, root, node, sdk,
        expected_binary_sha256=expected_binary_sha256), "isolated Alchemy recipe differs")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "binary", "initializer", "job-root", "node-binary", "sdk-root"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--expected-binary-sha256", type=validated_binary_sha256, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.source, args.binary, args.initializer, args.job_root, args.node_binary,
        args.sdk_root, expected_binary_sha256=args.expected_binary_sha256), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
