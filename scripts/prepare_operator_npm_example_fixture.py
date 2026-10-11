#!/usr/bin/env python3
"""Pure recipe and bounded dependency inventory for one npm example fixture.

No installation, image acquisition, initializer or client execution. The runner
separately requires a clean exact commit and pins all already-acquired bytes.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

from scripts import prepare_operator_npm_publish_fixture as publish

metadata, base = publish.metadata, publish.base
NODE = Path("/home/catchplate/.nvm/versions/node/v25.5.0/bin/node")
NODE_SHA256 = metadata.NODE_SHA256
LIBATOMIC = Path("/usr/lib/x86_64-linux-gnu/libatomic.so.1.2.0")
LIBATOMIC_SHA256 = "9d8a34468e614a71a6427dbabb0ac24eb8cb1e324dc6aa3bf95eb6f59201f000"
DEPENDENCIES = "examples/npm-registry/node_modules"
DEPENDENCIES_TARGET = "/app/" + DEPENDENCIES
CHECKER = "/app/scripts/check_operator_npm_example.py"
RUNTIME_SERVICES = {"network", "npm-registry", "serverware", "decision-gate-rs", "edge", "check"}
KEEPER_SECONDS, EDGE_SECONDS = metadata.KEEPER_SECONDS, metadata.EDGE_SECONDS
CHECKER_SECONDS, CHECKER_OUTER_SECONDS, PRECHECK_SECONDS = 180, 210, 75


def dependency_inventory(root):
    """Inventory actual npm files and contained links without following dirs.

    Unlike the historical detached-source inventory, npm's .bin links are
    permitted, but only relative links resolving to a regular file in this tree.
    No timestamps, caller labels or supplied content digests enter the manifest.
    """
    base.require(isinstance(root, Path) and root.is_absolute() and root.resolve() == root
        and not root.is_symlink(), "canonical dependency tree required")
    pending, files, links, entries, total = [root], {}, {}, 0, 0
    while pending:
        directory = pending.pop()
        info = directory.lstat()
        base.require(stat.S_ISDIR(info.st_mode) and info.st_mode & 5 == 5,
            "dependency directory unreadable")
        for path in sorted(directory.iterdir()):
            entries += 1
            base.require(entries <= 16000 and path.name != ".git", "dependency inventory bound exceeded")
            info = path.lstat()
            relative = path.relative_to(root).as_posix()
            base.require(relative.isascii() and not any(ord(c) < 32 or ord(c) == 127 for c in relative),
                "dependency path refused")
            if stat.S_ISDIR(info.st_mode):
                pending.append(path)
            elif stat.S_ISLNK(info.st_mode):
                target = os.readlink(path)
                resolved = path.resolve(strict=True)
                base.require(path.parent.name == ".bin" and len(links) < 256 and target.isascii() and 0 < len(target) <= 4096
                    and not any(ord(c) < 32 or ord(c) == 127 for c in target)
                    and not Path(target).is_absolute() and resolved.is_relative_to(root)
                    and resolved.is_file(), "dependency link escapes the selected tree")
                links[relative] = {"target": target}
            else:
                base.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_mode & 4
                    and info.st_size <= 64 * 1024**2, "dependency file refused")
                total += info.st_size
                base.require(len(files) < 8192 and total <= 128 * 1024**2, "dependency byte bound exceeded")
                value = base.digest(path)
                after = path.lstat()
                base.require((info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_mtime_ns, info.st_ctime_ns)
                    == (after.st_dev, after.st_ino, after.st_size, after.st_mode, after.st_mtime_ns, after.st_ctime_ns),
                    "dependency changed during inventory")
                files[relative] = {"size": info.st_size, "sha256": value}
    base.require(bool(files), "empty dependency inventory refused")
    return {"files": files, "symlinks": links}


def dependency_sha256(manifest):
    return hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True).encode("ascii")).hexdigest()


def validate_dependencies(root, expected):
    base.validated_binary_sha256(expected)
    observed = dependency_inventory(root)
    base.require(dependency_sha256(observed) == expected, "dependency tree pin differs")
    for name, version in metadata.PACKAGES.items():
        paths = [root / name / "package.json"]
        if name != "npm":
            paths.append(root / "npm/node_modules" / name / "package.json")
        for path in paths:
            base.require(path.stat().st_size <= 128 * 1024, "dependency package identity oversized")
            value = json.loads(path.read_text(encoding="utf-8"))
            base.require(value.get("name") == name and value.get("version") == version,
                "dependency package version differs")
    return observed


def build(source, binary, initializer, root, node, node_modules, *,
          expected_binary_sha256, expected_node_modules_sha256):
    """Pure exact recipe; none of these paths is opened here."""
    base.validated_binary_sha256(expected_binary_sha256)
    base.validated_binary_sha256(expected_node_modules_sha256)
    base.require(all(isinstance(path, Path) and path.is_absolute() and ".." not in path.parts
        for path in (source, binary, initializer, root, node, node_modules)), "absolute fixture paths required")
    base.require(root.parent == base.SCRATCH and re.fullmatch(r"serverware-npm-example-private\.[A-Za-z0-9]{6,32}", root.name),
        "fresh private npm example root required")
    base.require(node == NODE and node_modules == source / DEPENDENCIES,
        "fixed Node and source-adjacent dependencies required")
    template = root.with_name("serverware-npm-publish-private." + root.name.split(".", 1)[1])
    config = publish.build(source, binary, initializer, template, node, node_modules,
        expected_binary_sha256=expected_binary_sha256)
    config["name"] = "serverware-npm-example-private-" + hashlib.sha256(root.name.encode()).hexdigest()[:12]
    for service in config["services"].values():
        # Explicit empty entrypoint suppresses image defaults; commands remain
        # the existing accepted interpreter/normal application entrypoints.
        service.setdefault("entrypoint", [])
        for mount in service["volumes"]:
            path = Path(mount["source"])
            if path.is_relative_to(template):
                mount["source"] = str(root / path.relative_to(template))
    for name in ("npm-pki", "npm-registry"):
        service = config["services"][name]
        service["command"] = [value.replace("scripts.operator_npm_publish_fixture",
            "scripts.operator_npm_example_fixture") for value in service["command"]]
    check = config["services"]["check"]
    check.update(image=base.APP_IMAGE, entrypoint=["python", "-B"])
    check["command"] = [value.replace("/app/" + publish.CHECKER, CHECKER) for value in check["command"]]
    check["command"] += ["--expected-node-modules-sha256", expected_node_modules_sha256]
    for mount in check["volumes"]:
        if mount["target"] == "/npm":
            mount["target"] = DEPENDENCIES_TARGET
    check["volumes"].append(base.bind(LIBATOMIC, "/usr/lib/x86_64-linux-gnu/libatomic.so.1"))
    base.require(set(config["services"]) == RUNTIME_SERVICES | {"initialize", "npm-pki", "basic-pki"}
        and "networks" not in config, "npm example service roster differs")
    base.require(all(not service.get("ports") and not service.get("networks")
        and "HOME" not in service.get("environment", {}) for service in config["services"].values()),
        "npm example external configuration refused")
    return config


def validate(config, *args, **kwargs):
    base.require(config == build(*args, **kwargs), "npm example recipe differs")
