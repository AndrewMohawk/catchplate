#!/usr/bin/env python3
"""Closed managed-X posting recipe and read-only installed-payload inventory.

No application imports, installation, image pull, initialization or launch.
The runner must start the actual app before creating the curated gate bind.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

from scripts import prepare_operator_x_fixture as inherited
from scripts import operator_x_post_profiles as profiles
from scripts.prepare_operator_catalog_fixture import bind, require
from scripts.run_operator_x_examples_fixture import PYTHON_IMAGE, LIBATOMIC

base, basic = inherited.base, inherited.basic
NODE_SHA256 = profiles.NODE_SHA256
LIBATOMIC_SHA256 = "9d8a34468e614a71a6427dbabb0ac24eb8cb1e324dc6aa3bf95eb6f59201f000"
NODE_MODULES = profiles.NODE_MODULES
CONTROL_ORIGIN = "https://serverware-x.example.test"
CHECKER = "/app/scripts/check_operator_x_post.py"
RUNTIME_SERVICES = {"network", "provider", "serverware", "decision-gate-rs", "edge", "check"}
INITIAL_TOKEN_SECONDS, CHECKER_SECONDS = 120, 180
KEEPER_SECONDS, EDGE_SECONDS = 300, 240
CHECKER_OUTER_SECONDS, PRECHECK_SECONDS = 210, 75
LEAVES = (".operator-publication.lock", ".serverware-operator-demo.json",
    "mitmproxy/mitmproxy-ca-cert.pem", "mitmproxy/mitmproxy-ca.pem")
RUNTIME_LINKS = {"bin/python": "/usr/local/bin/python", "bin/python3": "python",
    "bin/python3.12": "python", "lib64": "lib"}
PYTHON_VERSIONS = profiles.PYTHON_DEPENDENCIES


def tree_inventory(root, *, kind):
    """Exact bounded bytes/types/modes; directory links are never traversed."""
    require(kind in {"node", "python", "runtime"}, "dependency kind differs")
    require(isinstance(root, Path) and root.is_absolute() and root.resolve() == root
        and not root.is_symlink(), "canonical dependency root required")
    limit, byte_limit = {"node": (8192, 64 * 1024**2), "python": (20000, 256 * 1024**2),
        "runtime": (4096, 32 * 1024**2)}[kind]
    files, directories, links, pending = {}, {}, {}, [root]
    entries = total = 0
    while pending:
        directory = pending.pop()
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_mode & 5 == 5, "dependency directory unreadable")
        directories[directory.relative_to(root).as_posix()] = stat.S_IMODE(info.st_mode)
        for path in sorted(directory.iterdir()):
            entries += 1
            require(entries <= 2 * limit and path.name != ".git", "dependency entry bound exceeded")
            relative, before = path.relative_to(root).as_posix(), path.lstat()
            require(relative.isascii() and not any(ord(c) < 32 or ord(c) == 127 for c in relative),
                "dependency path refused")
            mode = stat.S_IMODE(before.st_mode)
            if stat.S_ISDIR(before.st_mode):
                pending.append(path)
            elif stat.S_ISLNK(before.st_mode):
                target = os.readlink(path)
                if kind == "runtime":
                    require(RUNTIME_LINKS.get(relative) == target, "Python runtime link differs")
                else:
                    require(kind == "node" and path.parent.name == ".bin" and len(links) < 256
                        and 0 < len(target) <= 4096 and target.isascii()
                        and not any(ord(c) < 32 or ord(c) == 127 for c in target)
                        and not Path(target).is_absolute() and path.resolve(strict=True).is_relative_to(root)
                        and path.resolve(strict=True).is_file(), "dependency link escapes selected tree")
                links[relative] = {"target": target, "mode": mode}
            else:
                require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_mode & 4
                    and before.st_size <= byte_limit, "dependency file refused")
                total += before.st_size
                require(len(files) < limit and total <= byte_limit, "dependency byte bound exceeded")
                digest = base.digest(path)
                after = path.lstat()
                identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mode,
                    value.st_mtime_ns, value.st_ctime_ns, value.st_nlink)
                require(identity(before) == identity(after), "dependency changed during inventory")
                files[relative] = {"size": before.st_size, "sha256": digest, "mode": mode}
        after = directory.lstat()
        require((info.st_dev, info.st_ino, info.st_mode, info.st_mtime_ns, info.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_mode, after.st_mtime_ns, after.st_ctime_ns),
            "dependency directory changed during inventory")
    require(bool(files), "empty dependency payload refused")
    if kind == "runtime":
        require({name: row["target"] for name, row in links.items()} == RUNTIME_LINKS,
            "complete Python runtime links required")
    return {"files": files, "directories": directories, "symlinks": links}


def dependencies(node_modules, python_runtime, python_packages):
    observed = {"schema": "serverware.privateXPostDependencies/v1",
        "node": tree_inventory(node_modules, kind="node"),
        "python": tree_inventory(python_packages, kind="python"),
        "pythonRuntime": tree_inventory(python_runtime, kind="runtime")}
    for name, version in profiles.NODE_DEPENDENCIES.items():
        path = node_modules / name / "package.json"
        require(path.stat().st_size <= 128 * 1024, "Node package identity oversized")
        value = json.loads(path.read_text())
        require(value.get("name") == name and value.get("version") == version, "Node SDK version differs")
    metadata = [name for name in observed["python"]["files"] if name.endswith(".dist-info/METADATA")]
    for name, version in PYTHON_VERSIONS.items():
        matches = []
        for relative in metadata:
            path = python_packages / relative
            require(path.stat().st_size <= 1024 * 1024, "Python package metadata oversized")
            lines = path.read_text().splitlines()
            if lines.count("Name: " + name) == lines.count("Version: " + version) == 1:
                matches.append(relative)
        require(len(matches) == 1, "Python SDK version differs")
    config = python_runtime / "pyvenv.cfg"
    require(config.stat().st_size <= 4096 and "version = " + profiles.PYTHON_VERSION in config.read_text().splitlines(),
        "Python runtime version differs")
    return observed


def dependencies_sha256(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()


def build(source, binary, initializer, root, node, node_modules, python_runtime, python_packages, go,
          *, expected_binary_sha256, expected_go_sha256, expected_dependencies_sha256):
    require(root.parent == base.SCRATCH and re.fullmatch(r"serverware-x-post-private\.[A-Za-z0-9]{6,32}", root.name),
        "fresh private X posting root required")
    for value in (expected_binary_sha256, expected_go_sha256, expected_dependencies_sha256):
        base.validated_binary_sha256(value)
    require(all(isinstance(path, Path) and path.is_absolute() and ".." not in path.parts for path in
        (source, binary, initializer, node, node_modules, python_runtime, python_packages, go)), "absolute fixed inputs required")
    template = root.with_name("serverware-x-private." + root.name.split(".", 1)[1])
    config = inherited.build(source, binary, initializer, template, node, source / "examples/x-post-node",
        expected_binary_sha256=expected_binary_sha256)
    for service in config["services"].values():
        for mount in service["volumes"]:
            path = Path(mount["source"])
            if path.is_relative_to(template):
                mount["source"] = str(root / path.relative_to(template))
        service.setdefault("entrypoint", [])
    config["name"] = "serverware-x-post-private-" + hashlib.sha256(root.name.encode()).hexdigest()[:12]
    services, runtime = config["services"], root / "runtime"
    initialize = services["initialize"]
    initialize.update(command=["python", "-B", "-m", "scripts.operator_x_post_fixture_network", "initialize"],
        working_dir="/app", environment={"PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": "/app"})
    initialize["volumes"].append(bind(source, "/app"))
    services["x-post-pki"] = services.pop("x-pki")
    services["x-post-pki"].update(profiles=["x-post-pki"],
        command=["python", "-B", "-m", "scripts.operator_x_post_fixture", "--setup"])
    provider = services["provider"] = services.pop("x")
    provider["command"] = ["python", "-B", "-m", "scripts.operator_x_post_fixture", "--lifetime-seconds", "300"]
    provider["volumes"] = [mount for mount in provider["volumes"] if not mount["target"].startswith("/x/")]
    provider["volumes"].append(bind(runtime / "upstream-data/x", "/x", False))
    provider["healthcheck"]["test"] = ["CMD", "python", "-c",
        "import ssl,urllib.request; c=ssl.create_default_context(cafile='/x/ca.pem'); "
        "o=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=c)); "
        "r=o.open('https://api.x.com/__test__/observations',timeout=2); raise SystemExit(0 if r.status==200 else 1)"]
    services["network"]["command"] = ["python", "-B", "-m", "scripts.operator_x_post_fixture_network", "network"]
    services["edge"]["command"] = ["-m", "scripts.operator_x_post_fixture_network", "edge"]
    app, gate = services["serverware"], services["decision-gate-rs"]
    app["depends_on"] = {"provider": {"condition": "service_healthy"}}
    app["environment"].update(SERVERWARE_PUBLIC_URL=CONTROL_ORIGIN,
        SERVERWARE_PROCESS_MODE="serverware-control-plane", SERVERWARE_METADATA_STORE_BACKEND="sqlite",
        SERVERWARE_AUDIT_STORE_BACKEND="sqlite", SERVERWARE_GRANT_STORE_BACKEND="sqlite",
        SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED="0", SERVERWARE_KEY_RELEASE_REQUIRED="0",
        SERVERWARE_DEV_AUTHENTICATOR="0", SERVERWARE_DEV_DEMO_SEED="0",
        SERVERWARE_OPERATOR_GATE_PUBLICATION_ENABLED="1", SERVERWARE_OPERATOR_MANAGED_X_ENABLED="1",
        SERVERWARE_OPERATOR_X_CUSTODY_DIR="/x-custody", SSL_CERT_FILE="/x-public/ca.pem")
    app["volumes"] += [bind(runtime / "x-custody", "/x-custody", False),
        bind(runtime / "upstream-data/x/ca.pem", "/x-public/ca.pem")]
    gate["environment"]["SERVERWARE_OPERATOR_MANAGED_X_ENABLED"] = "1"
    gate["volumes"] = [mount for mount in gate["volumes"] if mount["target"] != "/data"]
    gate["volumes"] += [bind(runtime / "app-data/gate-runtime", "/data"),
        *(bind(runtime / "app-data" / leaf, "/data/" + leaf) for leaf in LEAVES)]
    check = services["check"]
    check.update(image=PYTHON_IMAGE, entrypoint=["/example-python/bin/python", "-B"])
    check["command"] = [CHECKER, "--control-base", CONTROL_ORIGIN, "--operator-origin", CONTROL_ORIGIN,
        "--management-base", "http://127.0.0.1:9091", "--proxy-url", "https://" + basic.PROXY_HOST + ":8443",
        "--expected-binary-sha256", "sha256:" + expected_binary_sha256,
        "--expected-go-sha256", expected_go_sha256, "--expected-dependencies-sha256", expected_dependencies_sha256,
        "--dependencies-file", "/client-dependencies.json", "--expected-initial-revision", "1",
        "--ca-file", "/client-trust/inner-ca.pem", "--proxy-ca-file", "/client-trust/outer-ca.pem",
        "--upstream-ca-file", "/x-public/ca.pem", "--control-ca-file", "/x-public/ca.pem",
        "--admin-token-file", "/client-secrets/admin.token", "--fixture-marker-file", "/private-fixture.json",
        "--run-claim-file", "/client-work/.operator-catalog-acceptance.claim", "--timeout-seconds", "180"]
    check["volumes"] = [mount for mount in check["volumes"]
        if mount["target"] not in {"/app/examples/x-username-node/node_modules", "/client-trust/x-ca.pem"}]
    check["volumes"] += [bind(node_modules, "/app/" + NODE_MODULES), bind(python_runtime, "/example-python"),
        bind(python_packages, "/example-python/lib/python3.12/site-packages"), bind(go, "/example-go/x-post"),
        bind(LIBATOMIC, "/usr/lib/x86_64-linux-gnu/libatomic.so.1"),
        bind(runtime / "upstream-data/x/ca.pem", "/x-public/ca.pem"), bind(root / "dependencies.json", "/client-dependencies.json")]
    require(set(services) == RUNTIME_SERVICES | {"initialize", "x-post-pki", "basic-pki"}
        and set(config) == {"name", "services"}, "closed X posting service roster required")
    for service in services.values():
        require(len(service["volumes"]) == len({mount["target"] for mount in service["volumes"]}), "duplicate fixture mount")
    return config


def validate(config, *args, **kwargs):
    require(config == build(*args, **kwargs), "X posting fixture recipe differs")
