#!/usr/bin/env python3
"""Prepare only the exact 8a app / e752 gate private stock-client regression.

No Docker, subprocess, Git, socket, provider or runtime initialization calls.
Default is read-only; --write requires caller-created fresh empty 0700 job and
evidence directories. Root must separately inspect capacity, cached images,
subnet conflicts, the resulting model and actual runtime isolation before any
checker execution. Do not substitute this private fixture for a live rollout.
"""
from __future__ import annotations

import argparse
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


def frozen_source():
    """Check the parent-verified exact Git archive before importing its preparer."""
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
    # Import only the exact, now-verified candidate recipe and its pure builder.
    sys.path.insert(0, str(SOURCE))
    from scripts import prepare_operator_proxy_basic_fixture as basic
    base = basic.base
    assert Path(basic.__file__).resolve().is_relative_to(SOURCE)
    assert Path(base.__file__).resolve().is_relative_to(SOURCE)
    assert args.evidence_dir.parent == EVIDENCE_ROOT and re.fullmatch(
        r"private-retained-pair\.[A-Za-z0-9]{6,32}", args.evidence_dir.name)
    for directory in (args.job_root, args.evidence_dir):
        base.fresh_root(directory, must_exist=args.write)
    config = basic.build(SOURCE, BINARY, INITIALIZER, args.job_root, args.subnet, expected_binary_sha256=BINARY_SHA)
    basic.validate(config, SOURCE, BINARY, INITIALIZER, args.job_root, args.subnet, expected_binary_sha256=BINARY_SHA)
    for path, expected in ((BINARY, BINARY_SHA), (INITIALIZER, base.INITIALIZER_SHA256), (ISOLATION_CHECKER, ISOLATION_SHA)):
        assert path.resolve() == path and path.is_file() and not path.is_symlink() and base.digest(path) == expected
    basic.dependency_inventory()
    source_manifest = {"schema": "serverware.privateProxyBasicSource/v1", "sourceCommit": COMMIT, "files": files}
    source_manifest_path = args.evidence_dir / "source-manifest.json"
    plan = {"schema": "serverware.exactRetainedPairPreparation/v1", "sourceCommit": COMMIT,
        "canonicalSourceManifestSha256": CANONICAL_MANIFEST, "binarySha256": BINARY_SHA,
        "jobRoot": str(args.job_root), "evidenceDirectory": str(args.evidence_dir), "subnet": args.subnet,
        "phaseOrder": ["initialize", "baseline-startup", "basic-pki", "create-check", "edge-startup",
            "isolation", "check-once", "retain-evidence-and-stop-private-fixture"],
        "rootPreflightRequired": ["free-capacity-and-load", "cached-images", "nonoverlapping-subnet",
            "exact-compose-model", "actual-container-isolation", "running-gate-and-shared-lock",
            "running-checker-network-and-curl-digest"],
        "isolationChecker": str(ISOLATION_CHECKER), "isolationCheckerSha256": ISOLATION_SHA,
        "baselineStartupLimitSeconds": 150, "checkerLimitSeconds": 120, "edgeLifetimeSeconds": 240,
        "peakDeclaredCpuLimit": 5, "peakDeclaredMemoryMiB": 2432,
        "automaticExecution": False, "launched": False, "productionReady": False,
        "freshApiNaturalExpiryVerified": False, "written": args.write}
    if args.write:
        write_new(source_manifest_path, source_manifest)
        result = basic.prepare(SimpleNamespace(source=SOURCE, source_manifest=source_manifest_path,
            expected_source_manifest_sha256=base.digest(source_manifest_path), expected_source_commit=COMMIT,
            binary=BINARY, expected_binary_sha256=BINARY_SHA, initializer=INITIALIZER,
            job_root=args.job_root, subnet=args.subnet, write=True))
        plan.update(project=result["preparation"]["project"],
            sourceManifestSha256=result["preparation"]["sourceManifestSha256"],
            preparationSha256=base.digest(args.job_root / "preparation.json"),
            composeSha256=base.digest(args.job_root / "compose.json"))
        write_new(args.evidence_dir / "exact-pair-plan.json", plan)
    return plan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--job-root", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--subnet", required=True)
    parser.add_argument("--write", action="store_true")
    os.umask(0o077)
    try:
        print(json.dumps(prepare(parser.parse_args()), indent=2, sort_keys=True))
    except Exception:
        raise SystemExit("Exact private pair preparation refused; retain any partial output and do not retry.") from None


if __name__ == "__main__":
    main()
