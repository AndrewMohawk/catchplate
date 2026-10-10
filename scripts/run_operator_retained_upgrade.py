#!/usr/bin/env python3
"""One-shot exact 1deb -> 8a retained-upgrade harness; never launch containers.

Parent supplies network-none, read-only root and source mounts, UID/GID 10001,
one CPU, 1 GiB memory, 96 PIDs, a fresh writable /scratch, and a 210-second outer
deadline. Mount this file and test_operator_retained_upgrade.py separately at
/test-runner, never over either application archive. Source verification
receipts must come from the parent's independent exact-Git-blob comparison.
No live state, provider, gate, Docker socket or host network is required.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import time
import unittest

import test_operator_retained_upgrade as selected

CANDIDATE_MANIFEST = "b3ac8f02465089754e1b6ac5260af104a0a1303f11751fd7998ce1d24fb1bbd0"
PREVIOUS_MANIFEST = "e5b70ccce9bcfc3065801391de59022648bbc645fa819b06840ba43412a73ff5"
ARTIFACTS = Path("/srv/catchplate-fast/projects/serverware-operator-artifacts")
TEST = "test_old_source_saved_authority_survives_current_google_off_upgrade_and_reopen"
SCRATCH = Path("/scratch")


def verify_archive(source, receipt_path, *, commit, expected_digest, file_count):
    """Recheck the mounted bytes without importing or executing their code."""
    assert re.fullmatch(r"[0-9a-f]{64}", expected_digest)
    assert receipt_path.is_file() and not receipt_path.is_symlink() and receipt_path.stat().st_size <= 8192
    receipt = json.loads(receipt_path.read_text())
    assert receipt == {"ok": True, "commit": commit, "source": str(ARTIFACTS / ("source-" + commit)),
        "files": file_count, "git_blob_equality": True, "world_readable_and_nonwritable": True,
        "manifest_sha256": expected_digest}, "independent source receipt differs"
    assert source.is_absolute() and source.resolve() == source
    pending, manifest, entries, total = [source], [], 0, 0
    while pending:
        directory = pending.pop()
        info = directory.lstat()
        assert stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o555
        for path in directory.iterdir():
            entries += 1
            assert entries <= 32768 and path.name != ".git", "source entry bound or Git state refused"
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                pending.append(path)
                continue
            assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 64 * 1024**2
            mode = stat.S_IMODE(info.st_mode)
            assert mode in {0o444, 0o555}, "source is not frozen and readable"
            total += info.st_size
            assert total <= 512 * 1024**2 and len(manifest) < 16384, "source inventory bound exceeded"
            manifest.append([path.relative_to(source).as_posix(), "100755" if mode == 0o555 else "100644",
                hashlib.sha256(path.read_bytes()).hexdigest()])
    assert len(manifest) == file_count
    observed = hashlib.sha256(json.dumps(sorted(manifest), separators=(",", ":")).encode()).hexdigest()
    assert observed == expected_digest, "mounted source differs from the exact selected Git archive"
    return {"commit": commit, "files": file_count, "manifest_sha256": observed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--previous-receipt", required=True, type=Path)
    parser.add_argument("--candidate-receipt", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    assert SCRATCH.is_dir() and SCRATCH.resolve() == SCRATCH
    with (SCRATCH / "run.claim").open("x") as claim:
        claim.write("one exact retained-upgrade selection; no retries\n")
    signal.alarm(200)
    started = time.monotonic()
    identities = {
        "previous": verify_archive(selected.PREVIOUS, args.previous_receipt, commit=selected.PREVIOUS_COMMIT,
            expected_digest=PREVIOUS_MANIFEST, file_count=4780),
        "candidate": verify_archive(selected.ROOT, args.candidate_receipt, commit=selected.CANDIDATE_COMMIT,
            expected_digest=CANDIDATE_MANIFEST, file_count=4811),
    }
    os.environ["TMPDIR"] = str(SCRATCH)
    suite = selected.OperatorRetainedUpgradeTests
    assert unittest.defaultTestLoader.getTestCaseNames(suite) == [TEST]
    result = unittest.TextTestRunner(verbosity=2, failfast=True).run(unittest.TestSuite([suite(TEST)]))
    passed = result.wasSuccessful() and result.testsRun == 1 and not result.skipped
    # No test may mutate either source archive, including through a wrong mount.
    verify_archive(selected.PREVIOUS, args.previous_receipt, commit=selected.PREVIOUS_COMMIT,
        expected_digest=PREVIOUS_MANIFEST, file_count=4780)
    verify_archive(selected.ROOT, args.candidate_receipt, commit=selected.CANDIDATE_COMMIT,
        expected_digest=CANDIDATE_MANIFEST, file_count=4811)
    receipt = {"passed": passed, "tests_run": result.testsRun, "failures": len(result.failures),
        "errors": len(result.errors), "skipped": len(result.skipped),
        "elapsed_seconds": round(time.monotonic() - started, 3), "test": TEST, "sources": identities,
        "harness_sha256": hashlib.sha256(Path(selected.__file__).read_bytes()).hexdigest(),
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "fixture_aged_expiry": True, "natural_expiry_verified": False,
        "scope": "synthetic retained Google-OFF and notifications-OFF upgrade/reopen; no gate, live data or provider"}
    with (SCRATCH / "result.json").open("x") as output:
        json.dump(receipt, output, indent=2, sort_keys=True)
        output.write("\n")
    signal.alarm(0)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
