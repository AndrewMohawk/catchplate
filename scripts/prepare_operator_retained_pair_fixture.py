#!/usr/bin/env python3
"""Prepare the exact 8a app / e752 gate / corrected 3cf checker regression.

No Docker, subprocess, Git, socket, provider or runtime initialization calls.
Default is read-only; --write requires caller-created fresh empty 0700 job and
evidence directories. Root must separately inspect capacity, cached images,
subnet conflicts, the resulting model and actual runtime isolation before any
checker execution. Do not substitute this private fixture for a live rollout.
--verify-prepared is read-only and requires an externally retained plan hash;
run it both before and after the separately authorized, one-shot checker.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from types import SimpleNamespace

COMMIT = "8a8d4b06678193d51e2b875a471cbeb7cb1b5ddf"
SOURCE = Path("/srv/catchplate-fast/projects/serverware-operator-artifacts/source-" + COMMIT)
CANONICAL_MANIFEST = "b3ac8f02465089754e1b6ac5260af104a0a1303f11751fd7998ce1d24fb1bbd0"
EVIDENCE_ROOT = Path("/srv/catchplate-fast/projects/serverware-operator-workspace-evidence")
SOURCE_RECEIPT = EVIDENCE_ROOT / "demo-ux-rollout.TCi8atvI/source-verification.json"
BINARY_SHA = "e7529b4484228ebdbf2be1ebb471a80a78a3e127673f0bc6dcb4921db92489e2"
BINARY = SOURCE.parent / ("sha256-" + BINARY_SHA) / "serverware-decision-gate"
INITIALIZER = Path("/srv/catchplate-fast/projects/serverware-operator-audit-integration/scripts/private_operator_audit/initialize.py")
ISOLATION_CHECKER = EVIDENCE_ROOT / "proxy-basic.PvuAduRH/verify-private-isolation.py"
ISOLATION_SHA = "e0f58ef32560bd1de7bae3fa0c914550d0e0ed5acff799ff4a4f85410ef0b047"
CHECKER_COMMIT = "3cfeb9a3ae088a7a8bce9bd063a569bf32a305e4"
CHECKER_SHA = "507df7220535332552bea6eb4c83dc531b133014974af423f868da0cdab295fe"
CHECKER = SOURCE.parent / ("checker-" + CHECKER_COMMIT) / "scripts/check_operator_proxy_basic.py"
CHECKER_TARGET = "/checker/check_operator_proxy_basic.py"
IMPORTS = tuple("scripts." + name for name in (
    "check_operator_catalog", "operator_catalog_feature_checks", "check_operator_demo",
    "check_development_sandbox", "check_operator_key_replacement", "check_operator_ordinary_client",
    "operator_ordinary_client_fixture", "operator_proxy_basic_tls"))

# Executed only by the separately authorized checker container, never by this
# preparer. Isolated Python excludes inherited PYTHONPATH/site-package fallbacks.
# No credential or network operation occurs before the first provenance check.
LAUNCHER = '''import hashlib, importlib.util, json, stat, sys, sysconfig
from pathlib import Path

def require(value):
    if not value:
        raise ValueError("private checker provenance refused")

def pinned(path, expected):
    require(path.is_absolute() and path.resolve() == path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
        and info.st_mode & 4 and not info.st_mode & 0o222 and info.st_size <= 8 * 1024**2)
    require(hashlib.sha256(path.read_bytes()).hexdigest() == expected)

def verify_files():
    pinned(Path(CHECKER_PATH), CHECKER_HASH)
    for name, expected in SCRIPT_HASHES.items():
        pinned(Path("/app") / (name.replace(".", "/") + ".py"), expected)
    root = Path("/client-dependencies")
    pinned(root / "manifest.json", DEPENDENCY_HASH)
    manifest = json.loads((root / "manifest.json").read_text())
    require(manifest["schema"] == "serverware.syntheticRequestsDependencies/v1"
        and manifest["moduleSubdirectory"] == "site-packages" and len(manifest["files"]) == 143)
    expected = {row["path"]: row["sha256"] for row in manifest["files"]}
    require(len(expected) == 143)
    pending, seen, entries, total = [root], set(), 0, 0
    while pending:
        directory = pending.pop()
        require(directory.resolve() == directory and stat.S_ISDIR(directory.lstat().st_mode))
        for path in directory.iterdir():
            entries += 1
            require(entries <= 6144)
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                pending.append(path)
                continue
            relative = path.relative_to(root).as_posix()
            if relative == "manifest.json":
                continue
            require(relative in expected)
            pinned(path, expected[relative])
            total += info.st_size
            require(total <= 8 * 1024**2)
            seen.add(relative)
    require(seen == set(expected))
    return expected

def verify_imports(dependencies):
    require(list(sys.modules["scripts"].__path__) == ["/app/scripts"])
    expected = {name: "/app/" + name.replace(".", "/") + ".py" for name in SCRIPT_HASHES}
    expected["scripts.check_operator_proxy_basic"] = CHECKER_PATH
    actual = {name: module for name, module in sys.modules.items() if name.startswith("scripts.")}
    require(set(actual) == set(expected))
    for name, module in actual.items():
        require(module.__file__ == expected[name] and module.__spec__.origin == expected[name])
    for name, module in tuple(sys.modules.items()):
        if name.split(".")[0] in {"requests", "urllib3", "certifi", "chardet", "idna"}:
            path = Path(module.__file__)
            require(module.__spec__.origin == str(path))
            require(path.is_relative_to("/client-dependencies"))
            relative = path.relative_to("/client-dependencies").as_posix()
            require(relative in dependencies)
            pinned(path, dependencies[relative])
    require({"requests", "urllib3"} <= set(sys.modules))

def run():
    require(sys.flags.isolated == 1 and sys.flags.optimize == 0 and sys.dont_write_bytecode)
    dependencies = verify_files()
    stdlib = sysconfig.get_path("stdlib")
    allowed = {stdlib, sysconfig.get_path("platstdlib"), sysconfig.get_config_var("DESTSHARED"),
        str(Path(stdlib).parent / ("python" + str(sys.version_info.major) + str(sys.version_info.minor) + ".zip"))}
    sys.path[:] = ["/app", "/client-dependencies/site-packages"] + [value for value in sys.path if value in allowed]
    import scripts
    require(list(scripts.__path__) == ["/app/scripts"])
    spec = importlib.util.spec_from_file_location("scripts.check_operator_proxy_basic", CHECKER_PATH)
    checker = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = checker
    spec.loader.exec_module(checker)
    verify_imports(dependencies)
    sys.argv[0] = CHECKER_PATH
    try:
        return checker.main()
    finally:
        require(verify_files() == dependencies)
        verify_imports(dependencies)

try:
    result = run()
except Exception:
    raise SystemExit("Private checker source/import verification or invocation refused") from None
raise SystemExit(result)
'''


def checker_launcher(files, dependency_sha):
    pins = {name: files[name.replace(".", "/") + ".py"] for name in IMPORTS}
    for value in (*pins.values(), dependency_sha):
        assert isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
    return ("CHECKER_PATH = " + repr(CHECKER_TARGET) + "\nCHECKER_HASH = " + repr(CHECKER_SHA)
        + "\nDEPENDENCY_HASH = " + repr(dependency_sha) + "\nSCRIPT_HASHES = " + repr(pins) + "\n" + LAUNCHER)


def corrected_recipe(config, files, basic):
    """Change only the dormant checker launch and one read-only file mount."""
    result = deepcopy(config)
    checker = result["services"]["check"]
    assert checker["command"][0] == "/app/" + basic.CHECKER
    checker["entrypoint"] = ["/usr/bin/python3.10", "-I", "-B", "-c"]
    checker["command"] = [checker_launcher(files, basic.DEPENDENCY_MANIFEST_SHA256)] + checker["command"][1:]
    checker["environment"].pop("PYTHONPATH")
    checker["volumes"].append(basic.base.bind(CHECKER, CHECKER_TARGET))
    return result


def pinned_checker():
    assert CHECKER.is_absolute() and CHECKER.resolve() == CHECKER
    info = CHECKER.lstat()
    assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) in {0o444, 0o555}
    assert info.st_nlink == 1 and 0 < info.st_size <= 1024**2
    assert hashlib.sha256(CHECKER.read_bytes()).hexdigest() == CHECKER_SHA


def frozen_source():
    """Check the parent-verified exact Git archive before importing its preparer."""
    assert SOURCE.is_absolute() and SOURCE.resolve() == SOURCE
    assert SOURCE_RECEIPT.is_file() and not SOURCE_RECEIPT.is_symlink() and SOURCE_RECEIPT.stat().st_size <= 8192
    assert json.loads(SOURCE_RECEIPT.read_text()) == {"ok": True, "commit": COMMIT, "source": str(SOURCE),
        "files": 4811, "git_blob_equality": True, "world_readable_and_nonwritable": True,
        "manifest_sha256": CANONICAL_MANIFEST}
    pending, manifest, entries, total = [SOURCE], [], 0, 0
    while pending:
        directory = pending.pop()
        info = directory.lstat()
        assert stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o555
        for path in directory.iterdir():
            entries += 1
            assert entries <= 32768 and path.name != ".git"
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                pending.append(path)
                continue
            assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 64 * 1024**2
            mode = stat.S_IMODE(info.st_mode)
            assert mode in {0o444, 0o555}
            total += info.st_size
            assert total <= 512 * 1024**2 and len(manifest) < 16384
            manifest.append([path.relative_to(SOURCE).as_posix(), "100755" if mode == 0o555 else "100644",
                hashlib.sha256(path.read_bytes()).hexdigest()])
    assert len(manifest) == 4811
    assert hashlib.sha256(json.dumps(sorted(manifest), separators=(",", ":")).encode()).hexdigest() == CANONICAL_MANIFEST
    return {name: digest for name, _mode, digest in manifest}


def write_new(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())


def prepare(args):
    files = frozen_source()
    pinned_checker()
    # Import only the exact, now-verified candidate recipe and its pure builder.
    sys.path.insert(0, str(SOURCE))
    from scripts import prepare_operator_proxy_basic_fixture as basic
    base = basic.base
    assert Path(basic.__file__).resolve().is_relative_to(SOURCE)
    assert Path(base.__file__).resolve().is_relative_to(SOURCE)
    assert args.evidence_dir.parent == EVIDENCE_ROOT and re.fullmatch(
        r"private-retained-pair\.[A-Za-z0-9]{6,32}", args.evidence_dir.name)
    verify = getattr(args, "verify_prepared", False)
    plan_pin = getattr(args, "expected_plan_sha256", None)
    assert not (args.write and verify) and (bool(plan_pin) == verify)
    if not verify:
        for directory in (args.job_root, args.evidence_dir):
            base.fresh_root(directory, must_exist=args.write)
    else:
        for directory in (args.job_root, args.evidence_dir):
            info = directory.lstat()
            assert directory.resolve() == directory and stat.S_ISDIR(info.st_mode)
            assert info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700
    config = basic.build(SOURCE, BINARY, INITIALIZER, args.job_root, args.subnet, expected_binary_sha256=BINARY_SHA)
    basic.validate(config, SOURCE, BINARY, INITIALIZER, args.job_root, args.subnet, expected_binary_sha256=BINARY_SHA)
    config = corrected_recipe(config, files, basic)
    for path, expected in ((BINARY, BINARY_SHA), (INITIALIZER, base.INITIALIZER_SHA256), (ISOLATION_CHECKER, ISOLATION_SHA)):
        assert path.resolve() == path and path.is_file() and not path.is_symlink() and base.digest(path) == expected
    basic.dependency_inventory()
    source_manifest = {"schema": "serverware.privateProxyBasicSource/v1", "sourceCommit": COMMIT, "files": files}
    source_manifest_path = args.evidence_dir / "source-manifest.json"
    plan = {"schema": "serverware.exactRetainedPairPreparation/v2", "sourceCommit": COMMIT,
        "canonicalSourceManifestSha256": CANONICAL_MANIFEST, "binarySha256": BINARY_SHA,
        "checkerSourceCommit": CHECKER_COMMIT, "checkerSource": str(CHECKER), "checkerSha256": CHECKER_SHA,
        "checkerMountTarget": CHECKER_TARGET, "checkerHelperSourceCommit": COMMIT,
        "checkerHelperSha256": {name: files[name.replace(".", "/") + ".py"] for name in IMPORTS},
        "checkerLauncherSha256": hashlib.sha256(config["services"]["check"]["command"][0].encode()).hexdigest(),
        "checkerImportsAndDependenciesVerificationRequiredBeforeAndAfter": True,
        "manifestVerificationRequired": ["after-preparation", "before-checker", "after-checker"],
        "manifestVerificationMode": "--verify-prepared --expected-plan-sha256 <independently retained pin>",
        "jobRoot": str(args.job_root), "evidenceDirectory": str(args.evidence_dir), "subnet": args.subnet,
        "phaseOrder": ["network-none-import-help", "initialize", "baseline-startup", "basic-pki", "create-check",
            "edge-startup", "isolation", "verify-prepared", "check-once", "verify-prepared",
            "retain-evidence-and-stop-private-fixture"],
        "importOnlyPreflight": {"networkMode": "none", "readOnly": True, "user": "10001:10001",
            "image": basic.CLIENT_IMAGE, "entrypoint": config["services"]["check"]["entrypoint"],
            "launcherFrom": "compose.services.check.command[0]", "arguments": ["--help"],
            "mountTargetsOnly": ["/app", "/client-dependencies", CHECKER_TARGET],
            "cpus": 1, "memoryMiB": 512, "pidsLimit": 64, "deadlineSeconds": 30,
            "fixtureAuthorityMounted": False, "beforeInitializerOrEdge": True},
        "rootPreflightRequired": ["free-capacity-and-load", "cached-images", "nonoverlapping-subnet",
            "exact-compose-model", "actual-container-isolation", "running-gate-and-shared-lock",
            "running-checker-network-and-curl-digest"],
        "isolationChecker": str(ISOLATION_CHECKER), "isolationCheckerSha256": ISOLATION_SHA,
        "baselineStartupLimitSeconds": 150, "checkerLimitSeconds": 120, "edgeLifetimeSeconds": 240,
        "peakDeclaredCpuLimit": 5, "peakDeclaredMemoryMiB": 2432,
        "automaticExecution": False, "launched": False, "productionReady": False,
        "freshApiNaturalExpiryVerified": False, "written": bool(args.write or verify)}
    if args.write:
        write_new(source_manifest_path, source_manifest)
        result = basic.prepare(SimpleNamespace(source=SOURCE, source_manifest=source_manifest_path,
            expected_source_manifest_sha256=base.digest(source_manifest_path), expected_source_commit=COMMIT,
            binary=BINARY, expected_binary_sha256=BINARY_SHA, initializer=INITIALIZER,
            job_root=args.job_root, subnet=args.subnet, write=False))
        assert config == corrected_recipe(result["compose"], files, basic)
        preparation = result["preparation"]
        preparation.update(checkerSourceCommit=CHECKER_COMMIT, checkerSource=str(CHECKER), checkerSha256=CHECKER_SHA,
            checkerHelperSourceCommit=COMMIT, checkerLauncherSha256=plan["checkerLauncherSha256"],
            phaseOrder=plan["phaseOrder"],
            composeSha256=hashlib.sha256((json.dumps(config, indent=2, sort_keys=True) + "\n").encode()).hexdigest())
        base.fresh_root(args.job_root, must_exist=True)
        (args.job_root / "runtime").mkdir(mode=0o700)
        write_new(args.job_root / "compose.json", config)
        write_new(args.job_root / "preparation.json", preparation)
        plan.update(project=result["preparation"]["project"],
            sourceManifestSha256=result["preparation"]["sourceManifestSha256"],
            preparationSha256=base.digest(args.job_root / "preparation.json"),
            composeSha256=base.digest(args.job_root / "compose.json"))
        assert frozen_source() == files
        pinned_checker()
        basic.dependency_inventory()
        write_new(args.evidence_dir / "exact-pair-plan.json", plan)
        plan["planFileSha256"] = base.digest(args.evidence_dir / "exact-pair-plan.json")
    elif verify:
        retained = basic.pinned_json(args.evidence_dir / "exact-pair-plan.json", plan_pin)
        for key in ("project", "sourceManifestSha256", "preparationSha256", "composeSha256"):
            plan[key] = retained[key]
        assert plan == retained and plan["project"] == config["name"]
        assert basic.pinned_json(source_manifest_path, plan["sourceManifestSha256"]) == source_manifest
        assert basic.pinned_json(args.job_root / "compose.json", plan["composeSha256"]) == config
        preparation = basic.pinned_json(args.job_root / "preparation.json", plan["preparationSha256"])
        assert preparation["composeSha256"] == plan["composeSha256"]
        assert preparation["sourceSha256"] == files and preparation["sourceCommit"] == COMMIT
        assert preparation["checkerSourceCommit"] == CHECKER_COMMIT and preparation["checkerSha256"] == CHECKER_SHA
        plan["verificationOnly"] = True
        plan["planFileSha256"] = plan_pin
    return plan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--job-root", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--subnet", required=True)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--write", action="store_true")
    modes.add_argument("--verify-prepared", action="store_true")
    parser.add_argument("--expected-plan-sha256")
    os.umask(0o077)
    try:
        if sys.flags.optimize:
            raise ValueError("optimized preparation is refused")
        print(json.dumps(prepare(parser.parse_args()), indent=2, sort_keys=True))
    except Exception:
        raise SystemExit("Exact private pair preparation refused; retain any partial output and do not retry.") from None


if __name__ == "__main__":
    main()
