#!/usr/bin/env python3
"""Render a dormant Go-only Gmail SDK fixture; never launch or acquire anything.

Retains the accepted Google setup/90-second token lifetime and real app/gate.
No Node, external Python runtime, SDK overlay, provider URL override, or build.
The executor must verify the exact clean source commit before initialization.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re

from scripts import prepare_operator_google_fixture as google
from scripts import prepare_operator_proxy_basic_fixture as basic
from scripts.operator_gmail_sdk_fixture_network import KEEPER_SECONDS, EDGE_SECONDS
from scripts.operator_google_fixture import CONTROL_ORIGIN

base = google.base
PROXY_URL = "https://" + basic.PROXY_HOST + ":8443"
GO_TARGET = "/example-go/google-gmail"
CHECKER = "/app/scripts/check_operator_gmail_sdk.py"
RUNTIME_SERVICES = {"network", "provider", "serverware", "decision-gate-rs", "edge", "check"}
CHECKER_SECONDS, CHECKER_OUTER_SECONDS, PRECHECK_SECONDS = 180, 210, 75


def build(source, binary, initializer, root, go, *, expected_binary_sha256, expected_go_sha256):
    base.validated_binary_sha256(expected_go_sha256)
    base.require(root.parent == base.SCRATCH and re.fullmatch(r"serverware-gmail-sdk-private\.[A-Za-z0-9]{6,32}", root.name),
        "fresh private Gmail SDK root required")
    template = root.with_name("serverware-google-private." + root.name.split(".", 1)[1])
    # Reuse the pure, closed Gmail-job manifest; its Requests mount is removed
    # below, not inspected, imported, or required by this Go-only sibling.
    config = google.build(source, binary, initializer, template, profile=google.GMAIL_JOB_PROFILE,
        expected_binary_sha256=expected_binary_sha256,
        client_dependencies=google.GMAIL_CLIENT_DEPENDENCIES,
        client_dependencies_manifest_sha256=google.GMAIL_CLIENT_MANIFEST_SHA256)
    config["name"] = "serverware-gmail-sdk-private-" + hashlib.sha256(root.name.encode()).hexdigest()[:12]
    services, runtime = config["services"], root / "runtime"
    for service in services.values():
        for mount in service["volumes"]:
            path = Path(mount["source"])
            if path.is_relative_to(template):
                mount["source"] = str(root / path.relative_to(template))
            if mount["target"] == "/etc/hosts":
                mount["source"] = str(runtime / "gmail-sdk-hosts")
    services["initialize"]["command"] = ["python", "-B", "-m", "scripts.operator_gmail_sdk_fixture_network", "initialize"]
    services["provider"]["command"] = ["python", "-B", "-m", "scripts.operator_gmail_sdk_fixture", "--lifetime-seconds", "300"]
    check = services["check"]
    check.update(image=base.APP_IMAGE, cpus=1, mem_limit="512m", memswap_limit="512m")
    check["environment"] = {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": "/app"}
    check["command"][2] = CHECKER
    check["command"][check["command"].index("--proxy-url") + 1] = PROXY_URL
    check["command"][check["command"].index("--ca-file") + 1] = "/client-trust/inner-ca.pem"
    check["command"] += ["--proxy-ca-file", "/client-trust/outer-ca.pem",
        "--combined-ca-file", "/client-trust/combined-ca.pem", "--expected-go-sha256", expected_go_sha256]
    check["volumes"] = [mount for mount in check["volumes"] if mount["target"] != "/client-dependencies"]
    pki = runtime / "https-proxy/basic-pki"
    check["volumes"] += [base.bind(go, GO_TARGET),
        base.bind(pki / "inner-ca.pem", "/client-trust/inner-ca.pem"),
        base.bind(pki / "outer-ca.pem", "/client-trust/outer-ca.pem"),
        base.bind(pki / "requests-ca.pem", "/client-trust/combined-ca.pem")]
    common = deepcopy(services["provider"])
    for key in ("command", "volumes", "healthcheck", "depends_on"):
        common.pop(key, None)
    services["basic-pki"] = {**deepcopy(common), "image": base.APP_IMAGE, "profiles": ["basic-pki"],
        "user": "0:0", "network_mode": "none", "cap_add": ["CHOWN", "DAC_OVERRIDE"],
        "command": ["python", "-B", "/app/" + basic.SETUP,
            "--runtime-root", "/fixture-runtime", "--inner-ca-file", "/inner-ca.pem"],
        "volumes": [base.bind(source, "/app"), base.bind(runtime / "https-proxy", "/fixture-runtime", False),
            base.bind(runtime / "app-data/mitmproxy/mitmproxy-ca-cert.pem", "/inner-ca.pem")]}
    services["edge"] = {**deepcopy(common), "profiles": ["edge"],
        "command": ["python", "-B", "-m", "scripts.operator_gmail_sdk_fixture_network", "edge"],
        "volumes": [base.bind(source, "/app"), base.bind(pki / "outer-cert.pem", "/edge/cert.pem"),
            base.bind(pki / "outer-key.pem", "/edge/key.pem"),
            base.bind(runtime / "gmail-sdk-hosts", "/etc/hosts"),
            base.bind(runtime / "fixture-resolv.conf", "/etc/resolv.conf")]}
    base.require(set(services) == RUNTIME_SERVICES | {"initialize", "basic-pki"} and "networks" not in config,
        "Gmail SDK service roster differs")
    base.require(all(not service.get("ports") and not service.get("networks") for service in services.values()),
        "Gmail SDK external network refused")
    return config


def validate(config, *args, **kwargs):
    base.require(config == build(*args, **kwargs), "Gmail SDK recipe differs")


def prepare(args):
    base.require(re.fullmatch(r"[0-9a-f]{40}", args.commit), "explicit source commit required")
    base.require(args.source.is_absolute() and args.source.resolve() == args.source
        and args.source.is_dir() and not args.source.is_symlink(), "canonical source directory required")
    base.fresh_root(args.job_root, must_exist=args.write)
    for path, expected in ((args.binary, args.expected_binary_sha256), (args.go, args.expected_go_sha256),
            (args.initializer, base.INITIALIZER_SHA256)):
        base.require(path.is_absolute() and path.resolve() == path and path.is_file() and not path.is_symlink()
            and base.digest(path) == expected and path.stat().st_mode & 4, "pinned input differs")
    config = build(args.source, args.binary, args.initializer, args.job_root, args.go,
        expected_binary_sha256=args.expected_binary_sha256, expected_go_sha256=args.expected_go_sha256)
    compose = json.dumps(config, sort_keys=True, indent=2) + "\n"
    receipt = {"schema": "serverware.privateGmailSdkPreparation/v1", "sourceCommit": args.commit,
        "source": str(args.source), "sourceCommitValidationRequiredByRunner": True,
        "binarySha256": args.expected_binary_sha256, "goSha256": args.expected_go_sha256,
        "initializerSha256": base.INITIALIZER_SHA256, "project": config["name"],
        "composeSha256": hashlib.sha256(compose.encode()).hexdigest(),
        "checkerSeconds": CHECKER_SECONDS, "keeperSeconds": KEEPER_SECONDS, "edgeSeconds": EDGE_SECONDS,
        "maximumPrecheckSeconds": PRECHECK_SECONDS, "initialAccessTokenSeconds": 90,
        "syntheticOnly": True, "automaticExecution": False, "realGoogleVerified": False}
    if args.write:
        (args.job_root / "runtime").mkdir(mode=0o700)
        for name, value in (("compose.json", config), ("preparation.json", receipt)):
            fd = os.open(args.job_root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w") as stream:
                json.dump(value, stream, sort_keys=True, indent=2); stream.write("\n")
                stream.flush(); os.fsync(stream.fileno())
    return {"preparation": receipt, "compose": config}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "binary", "initializer", "job-root", "go"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--commit", required=True)
    for name in ("expected-binary-sha256", "expected-go-sha256"):
        parser.add_argument("--" + name, type=base.validated_binary_sha256, required=True)
    parser.add_argument("--write", action="store_true")
    try:
        print(json.dumps(prepare(parser.parse_args()), sort_keys=True, indent=2))
    except (ValueError, OSError, KeyError, TypeError):
        raise SystemExit("Private Gmail SDK preparation refused; no input details emitted") from None


if __name__ == "__main__":
    main()
