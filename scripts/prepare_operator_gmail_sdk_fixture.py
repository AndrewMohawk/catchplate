#!/usr/bin/env python3
"""Render a dormant Gmail SDK fixture; never launch or acquire anything.

Retains the accepted Google setup/90-second token lifetime and real app/gate.
Go remains the default. Explicit paired mode pins existing Node/Python payloads.
No provider URL override, installation, acquisition or build.
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
from scripts.operator_gmail_sdk_fixture_network import KEEPER_SECONDS, EDGE_SECONDS, BROWSER_PROXY_HOST, BROWSER_PROXY_URL
from scripts.operator_google_fixture import CONTROL_ORIGIN
from scripts import operator_gmail_sdk_profiles as profiles
from scripts.prepare_operator_npm_example_fixture import dependency_inventory
from scripts.run_operator_x_examples_fixture import PYTHON_IMAGE, LIBATOMIC

base = google.base
PROXY_URL = "https://" + basic.PROXY_HOST + ":8443"
GO_TARGET = "/example-go/google-gmail"
CHECKER = "/app/scripts/check_operator_gmail_sdk.py"
RUNTIME_SERVICES = {"network", "provider", "catchplate", "decision-gate-rs", "edge", "check"}
CHECKER_SECONDS, CHECKER_OUTER_SECONDS, PRECHECK_SECONDS = 180, 210, 75
LIBATOMIC_SHA256 = "9d8a34468e614a71a6427dbabb0ac24eb8cb1e324dc6aa3bf95eb6f59201f000"


def paired_dependencies(node_modules, python_runtime, python_packages):
    """Complete installed payload observations; no import, install or fetch."""
    node = dependency_inventory(node_modules)
    python = basic.inventory(python_packages, limit=20000, byte_limit=256 * 1024**2)
    for name, version in (("@googleapis/gmail", "22.0.1"), ("undici", "8.11.2"),
            ("googleapis-common", "9.2.0"), ("gaxios", "7.3.1")):
        value = json.loads((node_modules / name / "package.json").read_text())
        base.require(value.get("name") == name and value.get("version") == version, "paired Node version differs")
    config = python_runtime / "pyvenv.cfg"
    base.require(python_runtime.is_absolute() and python_runtime.resolve() == python_runtime
        and config.is_file() and not config.is_symlink() and config.stat().st_size <= 4096,
        "paired Python runtime differs")
    base.require("version = " + profiles.PYTHON_VERSION in config.read_text().splitlines(), "paired Python version differs")
    links = {}
    for name, target in (("python", "/usr/local/bin/python"), ("python3", "python"), ("python3.12", "python")):
        path = python_runtime / "bin" / name
        base.require(path.is_symlink() and path.readlink().as_posix() == target, "paired Python interpreter linkage differs")
        links[name] = target
    return {"schema": "catchplate.privateGmailSdkDependencies/v1", "node": node, "python": python,
        "pythonRuntime": {"pyvenvSha256": base.digest(config), "links": links}}


def dependencies_sha256(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()


def build(source, binary, initializer, root, go, *, expected_binary_sha256, expected_go_sha256,
          browser_permission=False, sdk_pair=False, age_profile=False, node=None, node_modules=None,
          python_runtime=None, python_packages=None, expected_dependencies_sha256=None):
    base.require(type(browser_permission) is bool, "browser permission opt-in differs")
    base.require(type(sdk_pair) is bool and not (sdk_pair and browser_permission), "paired browser mode refused")
    base.require(type(age_profile) is bool and (not age_profile or sdk_pair), "age profile requires paired Python payload")
    if sdk_pair:
        base.require(go is None and expected_go_sha256 is None
            and all(isinstance(path, Path) and path.is_absolute() and ".." not in path.parts
                for path in (node, node_modules, python_runtime, python_packages)), "paired inputs differ")
        base.validated_binary_sha256(expected_dependencies_sha256)
    else:
        base.validated_binary_sha256(expected_go_sha256)
        base.require(all(value is None for value in (node, node_modules, python_runtime, python_packages,
            expected_dependencies_sha256)), "Go fixture refuses paired inputs")
    base.require(root.parent == base.SCRATCH and re.fullmatch(r"catchplate-gmail-sdk-private\.[A-Za-z0-9]{6,32}", root.name),
        "fresh private Gmail SDK root required")
    template = root.with_name("catchplate-google-private." + root.name.split(".", 1)[1])
    # Reuse the pure, closed Gmail-job manifest; its Requests mount is removed
    # below, not inspected, imported, or required by this Go-only sibling.
    config = google.build(source, binary, initializer, template, profile=google.GMAIL_JOB_PROFILE,
        expected_binary_sha256=expected_binary_sha256,
        client_dependencies=google.GMAIL_CLIENT_DEPENDENCIES,
        client_dependencies_manifest_sha256=google.GMAIL_CLIENT_MANIFEST_SHA256)
    config["name"] = "catchplate-gmail-sdk-private-" + hashlib.sha256(root.name.encode()).hexdigest()[:12]
    services, runtime = config["services"], root / "runtime"
    for service in services.values():
        for mount in service["volumes"]:
            path = Path(mount["source"])
            if path.is_relative_to(template):
                mount["source"] = str(root / path.relative_to(template))
            if mount["target"] == "/etc/hosts":
                mount["source"] = str(runtime / "gmail-sdk-hosts")
    services["initialize"]["command"] = ["python", "-B", "-m", "scripts.operator_gmail_sdk_fixture_network",
        "browser-initialize" if browser_permission else "initialize"]
    services["provider"]["command"] = ["python", "-B", "-m", "scripts.operator_gmail_sdk_fixture", "--lifetime-seconds", "300"]
    check = services["check"]
    check.update(image=base.APP_IMAGE, cpus=1, mem_limit="512m", memswap_limit="512m")
    check["environment"] = {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": "/app"}
    check["command"][2] = CHECKER
    check["command"][check["command"].index("--proxy-url") + 1] = BROWSER_PROXY_URL if browser_permission else PROXY_URL
    check["command"][check["command"].index("--ca-file") + 1] = "/client-trust/inner-ca.pem"
    check["command"] += ["--proxy-ca-file", "/client-trust/outer-ca.pem",
        "--combined-ca-file", "/client-trust/combined-ca.pem"]
    if sdk_pair:
        services["provider"]["command"].append("--sdk-pair")
        check.update(image=PYTHON_IMAGE, entrypoint=[])
        check["command"] = ["/example-python/bin/python", "-B", *check["command"][2:],
            "--sdk-pair", "--expected-dependencies-sha256", expected_dependencies_sha256]
        check["volumes"] += [base.bind(node, "/node"),
            base.bind(node_modules, "/app/" + profiles.NODE_MODULES),
            base.bind(python_runtime, "/example-python"), base.bind(python_packages, profiles.PYTHON_PACKAGES),
            base.bind(LIBATOMIC, "/usr/lib/x86_64-linux-gnu/libatomic.so.1")]
    else:
        check["command"] += ["--expected-go-sha256", expected_go_sha256]
    if age_profile:
        services["provider"]["command"].append("--age-profile")
        check["command"].append("--age-profile")
    if browser_permission:
        check["command"].append("--browser-permission")
        check["stdin_open"] = True
        for name in ("catchplate", "decision-gate-rs"):
            services[name]["environment"]["CATCHPLATE_OPERATOR_DEMO_PROXY_URL"] = BROWSER_PROXY_URL
    check["volumes"] = [mount for mount in check["volumes"] if mount["target"] != "/client-dependencies"]
    pki = runtime / "https-proxy/basic-pki"
    if not sdk_pair:
        check["volumes"].append(base.bind(go, GO_TARGET))
    check["volumes"] += [
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
    if browser_permission:
        services["basic-pki"]["command"] += ["--proxy-hostname", BROWSER_PROXY_HOST]
    services["edge"] = {**deepcopy(common), "profiles": ["edge"],
        "command": ["python", "-B", "-m", "scripts.operator_gmail_sdk_fixture_network",
            "browser-edge" if browser_permission else "edge"],
        "volumes": [base.bind(source, "/app"), base.bind(pki / "outer-cert.pem", "/edge/cert.pem"),
            base.bind(pki / "outer-key.pem", "/edge/key.pem"),
            base.bind(runtime / "gmail-sdk-hosts", "/etc/hosts"),
            base.bind(runtime / "fixture-resolv.conf", "/etc/resolv.conf")]}
    base.require(set(services) == RUNTIME_SERVICES | {"initialize", "basic-pki"} and "networks" not in config,
        "Gmail SDK service roster differs")
    base.require(all(not service.get("ports") and not service.get("networks") for service in services.values()),
        "Gmail SDK external network refused")
    base.require(all(len({mount["target"] for mount in service["volumes"]}) == len(service["volumes"])
        for service in services.values()), "Gmail SDK duplicate mount target")
    return config


def pair_kwargs(args):
    base.require(not getattr(args, "age_profile", False) or getattr(args, "sdk_pair", False),
        "age profile requires paired Python payload")
    if not getattr(args, "sdk_pair", False):
        return {}
    return {"sdk_pair": True, **({"age_profile": True} if getattr(args, "age_profile", False) else {}),
        **{name: getattr(args, name) for name in
        ("node", "node_modules", "python_runtime", "python_packages", "expected_dependencies_sha256")}}


def verify_paired_inputs(args):
    # OCI cannot create a nested bind target beneath an already read-only
    # source mount. The caller supplies this empty, ignored directory before
    # source freeze; it contains no installed payload and is never populated.
    mountpoint = args.source / profiles.NODE_MODULES
    base.require(mountpoint.is_dir() and not mountpoint.is_symlink()
        and mountpoint.resolve() == mountpoint and not any(mountpoint.iterdir()),
        "paired source requires an empty node_modules mountpoint before launch")
    value = paired_dependencies(args.node_modules, args.python_runtime, args.python_packages)
    base.require(base.digest(args.node) == profiles.NODE_SHA256 and base.digest(LIBATOMIC) == LIBATOMIC_SHA256
        and dependencies_sha256(value) == args.expected_dependencies_sha256, "paired dependency or binary pin differs")
    # Every installed distribution is pinned, including the existing unused
    # venv bootstrap pip. No installer is invoked. Full bytes are hashed above.
    expected = {"pip": "24.0"}
    for line in (args.source / "examples/google-gmail-python/requirements.txt").read_text().splitlines():
        if line and not line.startswith("#"):
            name, version = line.split("==")
            expected[name.lower().replace("_", "-")] = version
    observed = {}
    for name in value["python"]:
        if name.endswith(".dist-info/METADATA"):
            rows = (args.python_packages / name).read_text().splitlines()
            names = [row[6:] for row in rows if row.startswith("Name: ")]
            versions = [row[9:] for row in rows if row.startswith("Version: ")]
            base.require(len(names) == len(versions) == 1, "paired Python metadata differs")
            key = names[0].lower().replace("_", "-")
            base.require(key not in observed, "paired Python distribution duplicated")
            observed[key] = versions[0]
    base.require(observed == expected, "paired Python installed requirements differ")
    return value


def validate(config, *args, **kwargs):
    base.require(config == build(*args, **kwargs), "Gmail SDK recipe differs")


def prepare(args):
    base.require(re.fullmatch(r"[0-9a-f]{40}", args.commit), "explicit source commit required")
    base.require(args.source.is_absolute() and args.source.resolve() == args.source
        and args.source.is_dir() and not args.source.is_symlink(), "canonical source directory required")
    base.fresh_root(args.job_root, must_exist=args.write)
    selected = [(args.binary, args.expected_binary_sha256), (args.initializer, base.INITIALIZER_SHA256)]
    if getattr(args, "sdk_pair", False):
        verify_paired_inputs(args)
    else:
        selected.append((args.go, args.expected_go_sha256))
    for path, expected in selected:
        base.require(path.is_absolute() and path.resolve() == path and path.is_file() and not path.is_symlink()
            and base.digest(path) == expected and path.stat().st_mode & 4, "pinned input differs")
    config = build(args.source, args.binary, args.initializer, args.job_root, args.go,
        expected_binary_sha256=args.expected_binary_sha256, expected_go_sha256=args.expected_go_sha256,
        browser_permission=getattr(args, "browser_permission", False), **pair_kwargs(args))
    compose = json.dumps(config, sort_keys=True, indent=2) + "\n"
    receipt = {"schema": "catchplate.privateGmailSdkPreparation/v1", "sourceCommit": args.commit,
        "source": str(args.source), "sourceCommitValidationRequiredByRunner": True,
        "binarySha256": args.expected_binary_sha256, "goSha256": args.expected_go_sha256,
        "initializerSha256": base.INITIALIZER_SHA256, "project": config["name"],
        "composeSha256": hashlib.sha256(compose.encode()).hexdigest(),
        "checkerSeconds": CHECKER_SECONDS, "keeperSeconds": KEEPER_SECONDS, "edgeSeconds": EDGE_SECONDS,
        "maximumPrecheckSeconds": PRECHECK_SECONDS, "initialAccessTokenSeconds": 90,
        "syntheticOnly": True, "automaticExecution": False, "realGoogleVerified": False}
    if getattr(args, "sdk_pair", False):
        receipt.pop("goSha256")
        receipt.update(schema="catchplate.privateGmailSdkPreparation/v2", nodeSha256=profiles.NODE_SHA256,
            sdkDependenciesSha256=args.expected_dependencies_sha256)
    if getattr(args, "age_profile", False):
        receipt["ageProfile"] = True
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
    for name in ("source", "binary", "initializer", "job-root"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--commit", required=True)
    for name in ("expected-binary-sha256",):
        parser.add_argument("--" + name, type=base.validated_binary_sha256, required=True)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--browser-permission", action="store_true")
    parser.add_argument("--sdk-pair", action="store_true")
    parser.add_argument("--age-profile", action="store_true")
    for name in ("go", "node", "node-modules", "python-runtime", "python-packages"):
        parser.add_argument("--" + name, type=Path)
    for name in ("expected-go-sha256", "expected-dependencies-sha256"):
        parser.add_argument("--" + name, type=base.validated_binary_sha256)
    try:
        print(json.dumps(prepare(parser.parse_args()), sort_keys=True, indent=2))
    except (ValueError, OSError, KeyError, TypeError):
        raise SystemExit("Private Gmail SDK preparation refused; no input details emitted") from None


if __name__ == "__main__":
    main()
