#!/usr/bin/env python3
"""Separate capless-root custody units; never authority/native acceptance.

Prepare only the fixed public fixture as the ordinary host user. Execute only
inside the isolated UID-0, read-only, network-none container from CI. No Docker,
dependency installation or production startup occurs here. One sanitized JSON
receipt goes to stdout for the ordinary host user to retain; raw test streams
and ephemeral keys never leave the bounded child collector.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import run_ordinary_regression as bounded

SCHEMA = "serverware.nativeReviewSignerUnits/v1"
CANARY = b"serverware synthetic nonroot signer fixture\n"
FIXTURE = "SERVERWARE_TEST_NONROOT_KEY_FIXTURE"
FIXTURE_UID = FIXTURE + "_UID"
SCRIPT = "scripts/test_native_jit_review_signers.py"
SOURCE_FILES = (SCRIPT, "scripts/run_native_jit_review_signers.py", "scripts/run_ordinary_regression.py",
    "serverware/authority_native_jit_review_open_signers.py", "serverware/authority_service.py",
    "serverware/authority_launch_guard.py", "serverware/authority_native_jit_review_open_custody.py",
    "serverware/authority_native_jit_review_assignment.py", "serverware/authority_stage_zero_contract.py",
    "requirements.lock")


def require(value, reason):
    if not value:
        raise bounded.Refused(reason)


def prepare_fixture(path):
    require(0 < os.getuid() == os.geteuid() < 2**32 - 1, "nonroot_preparer_required")
    require(path.is_absolute() and path.parent.is_dir(), "fixture_parent_required")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
    try:
        require(os.write(descriptor, CANARY) == len(CANARY), "fixture_write_incomplete")
        os.fsync(descriptor)
        value = os.fstat(descriptor)
        require(stat.S_ISREG(value.st_mode) and value.st_uid == os.getuid()
            and stat.S_IMODE(value.st_mode) == 0o400 and value.st_nlink == 1
            and value.st_size == len(CANARY), "fixture_metadata_differs")
    finally:
        os.close(descriptor)
    require(path.read_bytes() == CANARY, "fixture_content_differs")
    return {"schema": SCHEMA, "success": True, "phase": "public-fixture-only",
        "fixtureUid": value.st_uid, "fixtureSha256": hashlib.sha256(CANARY).hexdigest(),
        "productionAcceptance": False}


def source_pins():
    result = {}
    for name in SOURCE_FILES:
        path = ROOT / name
        require(path.is_file() and not path.is_symlink(), "source_unavailable")
        result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def run(dependencies):
    bounded.require_offline_network()
    require(os.getuid() == os.geteuid() == 0, "isolated_root_required")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    require(all(int(status[name].strip(), 16) == 0 for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
        and status["NoNewPrivs"].strip() == "1", "capless_no_new_privileges_required")
    require(dependencies is not None and dependencies.is_dir(), "dependency_root_required")
    for path in (Path("/"), ROOT, dependencies):
        require(os.statvfs(path).f_flag & os.ST_RDONLY, "readonly_container_inputs_required")
    fixture, uid = os.environ.get(FIXTURE, ""), os.environ.get(FIXTURE_UID, "")
    require(fixture and Path(fixture).is_absolute() and uid.isascii() and uid.isdecimal()
        and len(uid) <= 10 and str(int(uid)) == uid and 0 < int(uid) < 2**32 - 1,
        "explicit_nonroot_fixture_required")
    require(os.statvfs(fixture).f_flag & os.ST_RDONLY, "readonly_fixture_required")
    before = source_pins()
    python = bounded.executable(sys.executable)
    with tempfile.TemporaryDirectory(prefix="native-review-signers-child-") as directory:
        environment = bounded.environment(ROOT, Path(directory), python, python, dependencies)
        environment.update({FIXTURE: fixture, FIXTURE_UID: uid})
        outcome = bounded.run_process([python, "-B", str(ROOT / SCRIPT)], cwd=ROOT,
            env=environment, seconds=60)
    after = source_pins()
    success = outcome["status"] == "passed" and outcome["observedUnittestCounts"] == [22] \
        and outcome["observedSkippedTests"] == 0 and before == after
    return {"schema": SCHEMA, "success": success, "phase": "isolated-custody-units",
        "script": SCRIPT, "maximumSeconds": 60, "maximumOutputBytes": bounded.MAX_OUTPUT_BYTES,
        "expectedTests": 22, "fixtureUid": int(uid), "sourceBefore": before, "sourceAfter": after,
        "sourceUnchanged": before == after, "outcome": outcome,
        "productionAcceptance": False, "nativeAcceptance": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare-fixture", type=Path)
    parser.add_argument("--dependency-root", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        require(not (args.prepare_fixture and args.dependency_root), "exclusive_mode_required")
        result = prepare_fixture(args.prepare_fixture) if args.prepare_fixture else run(args.dependency_root)
    except Exception as error:
        reason = str(error) if isinstance(error, bounded.Refused) else "signer_unit_orchestration_failed"
        result = {"schema": SCHEMA, "success": False, "phase": "preflight-or-orchestration",
            "reason": reason, "productionAcceptance": False, "nativeAcceptance": False}
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
