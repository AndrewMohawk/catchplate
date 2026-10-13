#!/usr/bin/env python3
"""Export the actual portal document without importing or starting the app.

This is a synthetic rendered-UI fixture, not a server/authority/authentication
test. Only the already-pure policy-template renderer is evaluated. HTML and all
portal script/style fragments are taken unchanged from their AST string literals
and bounded literal/import/concatenation/replace compositions.
The request-time profile is explicit: protected static creation, no rotation,
OAuth unavailable, no development seed or sandbox decoration.

Prepare only; the separate browser helper never starts a browser or a server.
Example (use a fresh owned output directory):
  python3 -B scripts/prepare_approval_denial_browser_fixture.py \
    --source /path/to/serverware --expect-app-sha256 <reviewed sha256> \
    --output /tmp/fresh-owned-directory/fixture.json
"""

from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat


MAX_FILE = 4 * 1024 * 1024
MAX_TOTAL = 16 * 1024 * 1024


def literal(tree: ast.Module, name: str):
    values = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name for target in node.targets
        ):
            try:
                values.append(ast.literal_eval(node.value))
            except (ValueError, TypeError):
                pass
    if len(values) != 1:
        raise ValueError(f"expected one source literal: {name}")
    return values[0]


def export_fixture(source: Path, expected_app_hash: str) -> dict:
    source = source.resolve(strict=True)
    pins: dict[str, str] = {}
    trees: dict[str, ast.Module] = {}
    total = 0

    def read(relative: str) -> bytes:
        nonlocal total
        if not re.fullmatch(r"(?:serverware/[a-z_]+\.py|policies/credential-limits\.examples\.json)", relative):
            raise ValueError("source path is outside the bounded portal roster")
        descriptor = os.open(source / relative, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_FILE:
                raise ValueError("source file is not bounded regular data")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                raw = stream.read(MAX_FILE + 1)
            after = os.fstat(descriptor)
            if len(raw) != before.st_size or (
                before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns
            ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                raise ValueError("source changed while reading")
        finally:
            os.close(descriptor)
        total += len(raw)
        if total > MAX_TOTAL or len(pins) >= 32:
            raise ValueError("portal source roster exceeded its bound")
        pins[relative] = hashlib.sha256(raw).hexdigest()
        return raw

    def tree(relative: str) -> ast.Module:
        if relative not in trees:
            trees[relative] = ast.parse(read(relative), filename=relative)
        return trees[relative]

    composed: dict[tuple[str, str], str] = {}

    def fragment(relative: str, name: str, ancestors: tuple = ()) -> str:
        identity = (relative, name)
        if identity in composed:
            return composed[identity]
        if identity in ancestors or len(ancestors) >= 16:
            raise ValueError("portal fragment import cycle or depth limit")
        module = tree(relative)
        assignments = [node.value for node in module.body if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
        if len(assignments) != 1:
            raise ValueError("expected one portal fragment assignment")
        imported = {alias.asname or alias.name: (node.module, alias.name)
                    for node in module.body if isinstance(node, ast.ImportFrom)
                    and node.module and node.module.startswith("serverware.portal_")
                    for alias in node.names}

        def string(node: ast.AST, depth: int = 0) -> str:
            if depth > 32:
                raise ValueError("portal string composition depth limit")
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value
            elif isinstance(node, ast.Name):
                target, target_name = imported.get(node.id, (relative[:-3].replace("/", "."), node.id))
                value = fragment(target.replace(".", "/") + ".py", target_name, (*ancestors, identity))
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                value = string(node.left, depth + 1) + string(node.right, depth + 1)
            elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                  and node.func.attr == "replace" and len(node.args) == 2 and not node.keywords):
                original = string(node.func.value, depth + 1)
                marker, replacement = (string(arg, depth + 1) for arg in node.args)
                if not marker or original.count(marker) != 1:
                    raise ValueError("nested portal placeholder missing or duplicated")
                value = original.replace(marker, replacement)
            else:
                raise ValueError("portal fragment uses unsupported nonliteral composition")
            if len(value.encode("utf-8")) > MAX_TOTAL:
                raise ValueError("portal fragment composition exceeds its bound")
            return value

        composed[identity] = string(assignments[0])
        return composed[identity]

    app = tree("serverware/app.py")
    if pins["serverware/app.py"] != expected_app_hash:
        raise ValueError("app.py differs from the reviewed source")
    html = literal(app, "UI_HTML")

    def replace_once(marker: str, value: str) -> None:
        nonlocal html
        if not isinstance(value, str) or html.count(marker) != 1:
            raise ValueError("portal substitution is missing or duplicated")
        html = html.replace(marker, value)

    # Use the maintained pure renderer, not an independently copied template
    # implementation. No top-level application/module code is evaluated.
    renderers = [node for node in app.body if isinstance(node, ast.FunctionDef)
                 and node.name == "_portal_policy_templates_json"]
    if len(renderers) != 1 or renderers[0].decorator_list or any(
        isinstance(node, (ast.Import, ast.ImportFrom)) for node in ast.walk(renderers[0])
    ):
        raise ValueError("policy renderer no longer has the reviewed pure shape")
    catalog = json.loads(read("policies/credential-limits.examples.json"))
    namespace = {"Any": object, "copy": copy, "json": json,
                 "_PORTAL_POLICY_TEMPLATE_SPECS": literal(app, "_PORTAL_POLICY_TEMPLATE_SPECS"),
                 "_read_portal_policy_examples": lambda: copy.deepcopy(catalog)}
    exec(compile(ast.Module(body=renderers, type_ignores=[]), "portal-policy-renderer", "exec"), namespace)
    replace_once(literal(app, "_PORTAL_POLICY_TEMPLATES_PLACEHOLDER"),
                 namespace["_portal_policy_templates_json"]())

    imports = {alias.asname or alias.name: (node.module, alias.name)
               for node in app.body if isinstance(node, ast.ImportFrom)
               and node.module and node.module.startswith("serverware.portal_")
               for alias in node.names}
    fragment_loops = [node for node in app.body if isinstance(node, ast.For)
                      and isinstance(node.target, ast.Tuple)
                      and [getattr(item, "id", None) for item in node.target.elts]
                      == ["_portal_placeholder", "_portal_fragment"]]
    if len(fragment_loops) != 1 or not isinstance(fragment_loops[0].iter, ast.Tuple):
        raise ValueError("portal fragment roster changed shape")
    for pair in fragment_loops[0].iter.elts:
        if not isinstance(pair, ast.Tuple) or len(pair.elts) != 2 or not isinstance(pair.elts[1], ast.Name):
            raise ValueError("portal fragment is no longer a literal import")
        module, name = imports[pair.elts[1].id]
        replace_once(ast.literal_eval(pair.elts[0]), fragment(module.replace(".", "/") + ".py", name))

    documents = [node for node in app.body if isinstance(node, ast.FunctionDef)
                 and node.name == "_portal_document"]
    if len(documents) != 1:
        raise ValueError("portal document renderer changed shape")
    secrets = [node.value for node in documents[0].body if isinstance(node, ast.Assign)
               and any(isinstance(target, ast.Name) and target.id == "secret_field" for target in node.targets)]
    if len(secrets) != 1 or not isinstance(secrets[0], ast.IfExp):
        raise ValueError("protected static field is no longer a literal branch")
    replace_once("__SERVERWARE_STATIC_SECRET_FIELD__", ast.literal_eval(secrets[0].body))
    replace_once("__SERVERWARE_ENROLLED_OAUTH_PROFILE__", json.dumps("unavailable"))
    replace_once("__SERVERWARE_DEMO_SEED_BUTTON__", "")
    replace_once("__SERVERWARE_STATIC_PROTECTED__", "true")
    replace_once("__SERVERWARE_STATIC_ROTATION_SELECTED__", "false")
    if re.search(r"__SERVERWARE_[A-Z_]+__", html):
        raise ValueError("unresolved portal placeholder")
    encoded = html.encode("utf-8")
    if len(encoded) > MAX_TOTAL:
        raise ValueError("rendered portal exceeds fixture bound")
    return {"schema": "serverware.approvalDenialBrowserFixture/v1", "syntheticOnly": True,
            "html": html, "htmlSha256": hashlib.sha256(encoded).hexdigest(),
            "sourceSha256": dict(sorted(pins.items())),
            "profile": {"protectedStaticCredentials": True, "protectedStaticRotation": False,
                        "enrolledOAuthProfile": "unavailable", "demoSeed": False,
                        "developmentSandboxDecoration": False}}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--expect-app-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{64}", args.expect_app_sha256):
        parser.error("--expect-app-sha256 must be the reviewed literal SHA-256")
    fixture = export_fixture(args.source, args.expect_app_sha256)
    raw = (json.dumps(fixture, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
    print(json.dumps({"schema": fixture["schema"], "syntheticOnly": True,
                      "fixtureSha256": hashlib.sha256(raw).hexdigest(),
                      "htmlSha256": fixture["htmlSha256"], "sourceFiles": len(fixture["sourceSha256"])}))


if __name__ == "__main__":
    main()
