#!/usr/bin/env python3
"""Pure dormant recipe for one GitHub App/renewal/three-SDK private proof.

No command execution, application imports, dependency acquisition or key files.
The explicit PKI setup phase generates the private synthetic App key at runtime.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import stat

from scripts import prepare_operator_github_fixture as github
from scripts.prepare_operator_catalog_fixture import bind, require
from scripts.run_operator_x_examples_fixture import PYTHON_IMAGE, LIBATOMIC

base, basic = github.base, github.basic
NODE_SHA256 = github.NODE_SHA256
LIBATOMIC_SHA256 = "9d8a34468e614a71a6427dbabb0ac24eb8cb1e324dc6aa3bf95eb6f59201f000"
RUNTIME_SERVICES = {"network", "github", "catchplate", "decision-gate-rs", "edge", "check"}
KEEPER_SECONDS, EDGE_SECONDS = github.KEEPER_SECONDS, github.EDGE_SECONDS
CHECKER_SECONDS, CHECKER_OUTER_SECONDS, PRECHECK_SECONDS = 180, 190, 75
NODE_EXAMPLE = "examples/github-issues-node"


def build(source, binary, initializer, root, node, node_modules, python_runtime, python_packages, go,
          *, expected_binary_sha256, expected_go_sha256):
    require(root.parent == base.SCRATCH and re.fullmatch(r"catchplate-github-app-private\.[A-Za-z0-9]{6,32}", root.name),
        "fresh private GitHub App root required")
    require(node_modules == source / NODE_EXAMPLE / "node_modules", "adjacent complete Node dependencies required")
    base.validated_binary_sha256(expected_go_sha256)
    template = root.with_name("catchplate-github-private." + root.name.split(".", 1)[1])
    config = github.build(source, binary, initializer, template, node, source / NODE_EXAMPLE,
        expected_binary_sha256=expected_binary_sha256)
    for service in config["services"].values():
        for mount in service["volumes"]:
            path = Path(mount["source"])
            if path.is_relative_to(template):
                mount["source"] = str(root / path.relative_to(template))
    config["name"] = "catchplate-github-app-private-" + hashlib.sha256(root.name.encode()).hexdigest()[:12]
    services, runtime = config["services"], root / "runtime"
    for name in ("github-pki", "github"):
        services[name]["command"] = ["python", "-B", "-m", "scripts.operator_github_app_examples_fixture"]
    services["github-pki"]["command"].append("--setup")
    services["github"]["volumes"].append(bind(runtime / "upstream-data/github/app-public.pem", "/github/app-public.pem"))
    services["github"]["volumes"].append(bind(runtime / "upstream-data/github/app-replacement-public.pem", "/github/app-replacement-public.pem"))
    # Production urllib still performs normal HTTPS verification. Only this
    # network-none app process trusts the newly generated synthetic provider CA.
    services["catchplate"]["environment"]["SSL_CERT_FILE"] = "/github-public/ca.pem"
    services["catchplate"]["volumes"].append(bind(runtime / "upstream-data/github/ca.pem", "/github-public/ca.pem"))
    check = services["check"]
    check["image"], check["entrypoint"] = PYTHON_IMAGE, ["/example-python/bin/python", "-B"]
    check["command"][0] = "/app/scripts/check_operator_github_app_examples.py"
    check["command"] += ["--expected-go-sha256", expected_go_sha256, "--expected-initial-revision", "1",
        "--app-key-file", "/client-secrets/github-app.pem",
        "--replacement-key-file", "/client-secrets/github-app-replacement.pem"]
    check["volumes"] = [mount for mount in check["volumes"] if mount["target"] != "/sdk/node_modules"]
    check["volumes"] += [bind(node_modules, "/app/" + NODE_EXAMPLE + "/node_modules"),
        bind(LIBATOMIC, "/usr/lib/x86_64-linux-gnu/libatomic.so.1"), bind(python_runtime, "/example-python"),
        bind(python_packages, "/example-python/lib/python3.12/site-packages"), bind(go, "/example-go/github-issues"),
        bind(runtime / "basic-pki/requests-ca.pem", "/client-trust/requests-ca.pem"),
        bind(runtime / "upstream-data/github/app-key.pem", "/client-secrets/github-app.pem"),
        bind(runtime / "upstream-data/github/app-replacement-key.pem", "/client-secrets/github-app-replacement.pem")]
    require(set(services) == RUNTIME_SERVICES | {"initialize", "github-pki", "basic-pki"}
        and "networks" not in config, "closed GitHub App service roster required")
    for service in services.values():
        require(len({mount["target"] for mount in service["volumes"]}) == len(service["volumes"]),
            "duplicate fixture mount target refused")
    return config


def validate(config, *args, **kwargs):
    require(config == build(*args, **kwargs), "GitHub App fixture recipe differs")


def dependencies(node_modules, python_runtime, python_packages):
    """Full read-only payload pin; this does not install or import SDK packages."""
    node = basic.inventory(node_modules, limit=8192, byte_limit=64 * 1024**2)
    python = basic.inventory(python_packages, limit=20000, byte_limit=256 * 1024**2)
    for name, version in (("@octokit/rest", "22.0.1"), ("undici", "8.11.2")):
        metadata = json.loads((node_modules / name / "package.json").read_text())
        require(metadata.get("name") == name and metadata.get("version") == version, "Node SDK pin differs")
    for name, version in (("PyGithub", "2.10.0"), ("requests", "2.34.2"), ("urllib3", "2.8.0"), ("certifi", "2026.7.22")):
        matched = [path for path in python if path.endswith(".dist-info/METADATA")
            and (python_packages / path).read_text().splitlines().count("Name: " + name) == 1
            and (python_packages / path).read_text().splitlines().count("Version: " + version) == 1]
        require(len(matched) == 1, "Python SDK pin differs")
    require(python_runtime.is_absolute() and python_runtime.resolve() == python_runtime
        and stat.S_ISDIR(python_runtime.lstat().st_mode), "Python runtime directory differs")
    config = python_runtime / "pyvenv.cfg"
    require(config.is_file() and not config.is_symlink() and config.stat().st_size <= 4096, "Python venv config differs")
    links = {}
    # The pinned interpreter image supplies this exact base interpreter. No
    # arbitrary runtime symlinks or host interpreter executables are followed.
    for name, target in (("python", "/usr/local/bin/python"), ("python3", "python"), ("python3.12", "python")):
        path = python_runtime / "bin" / name
        require(path.is_symlink() and path.readlink().as_posix() == target, "Python interpreter linkage differs")
        links[name] = target
    return {"schema": "catchplate.privateGithubAppDependencies/v1", "node": node, "python": python,
        "pythonRuntime": {"pyvenvSha256": base.digest(config), "links": links}}


def dependencies_sha256(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()
