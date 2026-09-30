#!/usr/bin/env python3
"""Offline fixed Setup issuer roots, with a recorded bounded Python import closure.

No issuer is invoked here. Source, wheels and native build tools must already be
admitted by Dockerfile.production. No key/configuration enters any image.
"""
from __future__ import annotations
import ast
import hashlib
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

sys.path.insert(0, "/source/scripts")
from package_native_broker_runtime import (
    Closure, ENV, INTERPRETER, MAX_TOTAL, PACKAGES as CRYPTO_PACKAGES, SITE, SOURCE,
    canonical, original, require, sha,
)

PACKAGES = {**CRYPTO_PACKAGES, "cbor2": "5.9.0"}
PROFILES = (
    ("setup-native-hardware-verifier", "verify_native_setup_hardware.py"),
    ("setup-native-proxy-verifier", "verify_native_setup_proxy.py"),
    ("setup-native-final-authority", "issue_native_setup_final.py"),
)
# Explicit actual runtime lazy imports: native Originals selects final; the
# hardware chain calls runtime-policy -> buffered-capture/receipt, CA -> work
# accounting, and canary association -> full signed configuration digest.
# Uncalled transition/request-effect factories are NOT recursively packaged.
ROOT_MODULES = (
    "serverware.native_setup_independent_verifier", "serverware.native_setup_independent_originals",
    "serverware.native_setup_final_authority", "serverware.authority_setup_native_final",
    "serverware.authority_setup_native_runtime_policy", "serverware.authority_setup_native_runtime_capture",
    "serverware.authority_setup_native_runtime_receipt", "serverware.authority_query_read_work",
    "serverware.authority_policy_canary_policy", "scripts.verify_nitro_tee",
)
FORBIDDEN = frozenset({"serverware.app", "serverware.db", "serverware.authority_service",
    "serverware.authority_factory", "serverware.authority_client", "serverware.authority_transitions"})
PREFIXES = ("serverware.", "serverware_agent_trust.", "scripts.")


def source_path(module):
    require(re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*)*", module) is not None,
            "invalid source import name")
    base = SOURCE.joinpath(*module.split("."))
    choices = [path for path in (base.with_suffix(".py"), base / "__init__.py") if path.is_file()]
    require(len(choices) <= 1, "ambiguous source import")
    return choices[0] if choices else None


def source_inventory():
    """Build-only AST admission, no eval/import of source while discovering it.

    Follow module-scope imports (including guarded imports), not uncalled SQL
    factories buried in a shared data verifier. The small explicit lazy roots
    above are source-owned. Refuse unexpected third-party/server/store imports
    instead of silently copying the whole control-plane graph.
    """
    pending, selected = list(ROOT_MODULES), {}

    def add(module):
        require(module not in FORBIDDEN and not module.startswith(("serverware.authority_store",
            "serverware.control_plane", "serverware.portal_")), "issuer closure reached control-plane execution")
        if module in {"serverware", "serverware_agent_trust", "scripts"} or module.startswith(PREFIXES):
            path = source_path(module)
            require(path is not None or module == "scripts", "issuer source dependency is absent")
            if path is not None and module not in selected:
                pending.append(module)
            return
        require(module.split(".", 1)[0] in sys.stdlib_module_names | {"cryptography", "cbor2", "cffi", "pycparser"},
                "issuer has an unadmitted third-party dependency")

    while pending:
        module = pending.pop()
        if module in selected:
            continue
        require(len(selected) < 192, "issuer source module bound exceeded")
        path = source_path(module)
        require(path is not None, "issuer root source is absent")
        raw = original(path)
        require(len(raw) <= 2 * 1024 * 1024, "issuer module too large")
        selected[module] = path
        require(sum(p.stat().st_size for p in selected.values()) <= 16 * 1024 * 1024, "issuer source closure too large")
        parts = module.split(".")
        for index in range(1, len(parts)):
            add(".".join(parts[:index]))
        package = module if path.name == "__init__.py" else module.rpartition(".")[0]

        class Imports(ast.NodeVisitor):
            def visit_FunctionDef(self, node): pass
            def visit_AsyncFunctionDef(self, node): pass
            def visit_Lambda(self, node): pass
            def visit_Import(self, node):
                for alias in node.names: add(alias.name)
            def visit_ImportFrom(self, node):
                if node.level:
                    components = package.split(".")
                    require(node.level <= len(components), "source relative import escapes package")
                    base = ".".join(components[:len(components)-node.level+1])
                    if node.module: base += "." + node.module
                else: base = node.module or ""
                add(base)
                # `from package import module` imports the child if it exists;
                # ordinary names/functions do not become invented module files.
                if base in {"serverware", "serverware_agent_trust", "scripts"} or base.startswith(PREFIXES):
                    for alias in node.names:
                        if alias.name != "*" and source_path(base + "." + alias.name) is not None:
                            add(base + "." + alias.name)

        Imports().visit(ast.parse(raw, filename=str(path)))
    return selected


def build(purpose, entry_name, modules, epoch):
    root, output = Path("/" + purpose + "-runtime"), Path("/setup-issuers-output") / purpose
    root.mkdir(); output.mkdir()
    closure = Closure(epoch, purpose=purpose)
    entrypoint = Path("/opt/serverware/scripts") / entry_name
    closure.add(INTERPRETER, INTERPRETER, executable=True)
    closure.add(Path("/usr/local/lib/libpython3.11.so.1.0"), Path("/usr/local/lib/libpython3.11.so.1.0"))
    closure.tree(Path("/usr/local/lib/python3.11"), Path("/usr/local/lib/python3.11"), stdlib=True)
    for package, version in PACKAGES.items():
        metadata = Path("/deps") / f"{package}-{version}.dist-info"
        require(metadata.is_dir(), "locked issuer dependency unavailable")
        closure.tree(Path("/deps") / package, SITE / package)
        closure.tree(metadata, SITE / metadata.name)
    for pattern in ("_cffi_backend*.so", "_cbor2*.so"):
        extensions = sorted(Path("/deps").glob(pattern))
        require(len(extensions) == 1, "ambiguous or absent issuer native extension")
        closure.add(extensions[0], SITE / extensions[0].name)
    for module, path in sorted(modules.items()):
        closure.add(path, SITE / path.relative_to(SOURCE))
    # The real trust package reads its original project identity here. Do not
    # synthesize a distribution/version or omit this lazy runtime dependency.
    closure.add(SOURCE / "pyproject.toml", SITE / "pyproject.toml")
    closure.add(SOURCE / "scripts" / entry_name, entrypoint)
    closure.libraries()
    targets = closure.setup_issuer_mount_targets()
    inventory = closure.finish()
    # Deferred build admission only: import the actual roots and lazy modules,
    # never call hardware()/proxy()/run(), generate keys or verify live inputs.
    probe = "import importlib; " + "; ".join("importlib.import_module(" + repr(name) + ")" for name in ROOT_MODULES)
    probe += "; from importlib.metadata import version; assert version('cryptography') == '50.0.0'; assert version('cbor2') == '5.9.0'"
    subprocess.run(["/usr/sbin/chroot", str(root), str(INTERPRETER), "-I", "-B", "-c", probe],
        env=ENV, check=True, timeout=30)
    image = output / (purpose + "-runtime.squashfs")
    subprocess.run(["/usr/bin/mksquashfs", str(root), str(image), "-noappend", "-no-recovery",
        "-no-xattrs", "-no-exports", "-all-root", "-root-mode", "0555", "-comp", "gzip",
        "-b", "131072", "-processors", "1", "-mem", "256M", "-mkfs-time", str(epoch),
        "-all-time", str(epoch), "-reproducible", "-no-progress", "-exit-on-error"], env=ENV, check=True, timeout=300)
    require(0 < image.stat().st_size <= MAX_TOTAL, "Setup issuer image exceeds bound")
    with image.open("rb") as stream:
        image_hash = "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()
    runtime = {"profile":"sealed-memfd-squashfs-v1", "imagePath":"/opt/serverware/"+image.name,
        "imageSha256":image_hash, "interpreterSha256":closure.files[str(INTERPRETER)]["sha256"],
        "entrypointSha256":closure.files[str(entrypoint)]["sha256"]}
    manifest = {"apiVersion":"serverware.setupNativeIndependentIssuerRuntimeBuild/v1", "purpose":purpose,
        "runtimeImage":runtime, "sourceManifestSha256":sha(original(Path("/source-contract/source-manifest.json"))),
        "sourceDateEpoch":epoch, "imageBytes":image.stat().st_size, "packages":PACKAGES,
        "sourceModules":sorted(modules), "files":inventory, "mountTargets":targets, "releaseAuthority":False}
    (output / (purpose+"-runtime.json")).write_bytes(canonical(manifest))
    for path in output.iterdir():
        path.chmod(0o444); os.utime(path, (epoch,epoch))
    output.chmod(0o555); os.utime(output, (epoch,epoch))


def main():
    require(len(sys.argv)==1 and os.geteuid()==0 and platform.machine()=="x86_64"
        and sys.version_info[:2]==(3,11), "Setup packager requires fixed offline build stage")
    stamp = os.environ.get("SOURCE_DATE_EPOCH", "")
    require(re.fullmatch(r"0|[1-9][0-9]{0,9}", stamp) is not None and int(stamp)<=2**32-1, "invalid source timestamp")
    modules = source_inventory()
    Path("/setup-issuers-output").mkdir()
    for purpose, entry_name in PROFILES:
        build(purpose, entry_name, modules, int(stamp))


if __name__ == "__main__": main()
