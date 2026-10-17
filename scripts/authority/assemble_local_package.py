#!/usr/bin/env python3
"""Existing local generator, with an explicit pre-witness core boundary."""
from datetime import datetime, timezone
from pathlib import Path
import os
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
USAGE = """Usage: python -I -B scripts/authority/assemble_local_package.py --mode core|package --spec-fd N --spec-sha256 sha256:HEX --trust-fd N --trust-sha256 sha256:HEX

Root-only public-data assembly from two distinct protected root0400 originals.
The existing generator spec selects the actual frozen artifact tree, existing
signed configurations/evidence/trust documents and generation intent. No keys,
credentials, receipts, runtime identities or authority approvals are created.

core: generation has its original six intent fields and NO witnessCheckpoint.
      Emits the measured existing Generation/v7 core for a real witness append.
package: generation additionally contains the actual signed witness checkpoint.
         Remeasures the same inputs and emits the existing unsigned Package/v7.
The final validator requires that checkpoint to bind the exact derived core.
Both modes require the explicit trusted-host-local Python bootstrap profile.

Output is exact canonical JSON without a newline, to a root-owned pipe. Require
the entire output AND exit0. The original generation/evidence expiry also bounds
elapsed BOOTTIME; external supervision must bound kernel IO stalls. No files,
trust high-water, witness history or installer state are changed here. No native,
external-witness, rootfs-completeness or hardware assurance is established.
"""


def arguments(argv):
    flags = ["--mode", "--spec-fd", "--spec-sha256", "--trust-fd", "--trust-sha256"]
    if len(argv) != 10 or argv[::2] != flags or argv[1] not in ("core", "package"):
        raise ValueError("fixed local assembly arguments required")
    values = {"mode": argv[1]}
    for flag, raw in zip(argv[2::2], argv[3::2]):
        name = flag[2:].replace("-", "_")
        if name.endswith("_fd"):
            value = int(raw)
            if str(value) != raw or not 3 <= value < 2**31:
                raise ValueError("descriptor refused")
        else:
            value = raw
            if len(raw) != 71 or not raw.startswith("sha256:") or any(c not in "0123456789abcdef" for c in raw[7:]):
                raise ValueError("pin refused")
        values[name] = value
    if values["spec_fd"] == values["trust_fd"]:
        raise ValueError("descriptor alias refused")
    return values


def encode_result(mode, value):
    """Exact bytes accepted by the existing witness and package-signing inputs."""
    from catchplate import authority_artifact_spec as spec
    if mode == "core":
        spec.validate_generation_core(value)
    elif mode == "package":
        spec.validate_unsigned_artifact_package(value)
    else:
        raise ValueError("local assembly mode refused")
    return spec.canonical_json_bytes(value)


def run(*, mode, spec_fd, spec_sha256, trust_fd, trust_sha256):
    from scripts.authority import generate_artifact_bundle as generator
    from scripts.authority import native_pilot_authority_io as io
    from catchplate import authority_artifact_spec as contract
    from catchplate.authority_local_artifacts import document, sha

    io._process()
    if mode not in ("core", "package") or spec_fd == trust_fd:
        raise ValueError("local assembly mode or descriptor refused")
    initial_boot, initial_unix = io._clock(), time.time_ns()
    sources = []
    for fd, pin in ((spec_fd, spec_sha256), (trust_fd, trust_sha256)):
        identity = io._input(fd, io.MAX_PUBLIC)
        raw = io.read_public(fd, io.MAX_PUBLIC)
        if sha(raw) != pin:
            raise ValueError("public original pin differs")
        sources.append((fd, identity, raw))
    if sources[0][1][:2] == sources[1][1][:2]:
        raise ValueError("public inode alias refused")
    selected, trust = (document(row[2], io.MAX_PUBLIC) for row in sources)
    if selected.get("trustMode") != {
        "mode": "trusted-host-local", "hardwareBacked": False,
        "externalWitnessRequired": False, "teeQuoteRequired": False,
        "imaAppraisalRequired": False,
    }:
        raise ValueError("only explicit trusted-host-local assembly is permitted")
    # These are the original source intervals, never a new admission window.
    expiry = min(int(contract._require_timestamp(value, name="original expiry").timestamp()) * 1_000_000_000
        for value in (selected["generation"]["validUntil"],
                      selected["stableSnapshotReceipt"]["payload"]["expiresAt"],
                      selected["closureReceipt"]["payload"]["expiresAt"]))
    deadline = initial_boot + expiry - initial_unix
    previous_boot, previous_unix = initial_boot, initial_unix

    def check():
        nonlocal previous_boot, previous_unix
        now_boot, now_unix = io._clock(), time.time_ns()
        if not previous_boot <= now_boot < deadline or not previous_unix <= now_unix < expiry:
            raise ValueError("original assembly clock bounds changed or expired")
        previous_boot, previous_unix = now_boot, now_unix
        for fd, identity, _ in sources:
            if io._input(fd, io.MAX_PUBLIC) != identity:
                raise ValueError("retained public original changed")

    check()
    instant = datetime.fromtimestamp(initial_unix // 1_000_000_000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if mode == "core":
        value = generator.prepare_local_generation_core(selected, trust_state=trust, validation_time=instant)
    else:
        value = generator._build_package(selected, trust_state=trust, validation_time=instant)
        if value["bundle"]["stageZero"]["interfaceSchema"] != contract.LOCAL_STAGE_ZERO_INTERFACE_SCHEMA:
            raise ValueError("local Python bootstrap required")
    raw = encode_result(mode, value)
    for fd, _, original in sources:
        if io.read_public(fd, io.MAX_PUBLIC) != original:
            raise ValueError("retained public bytes changed")
    check()
    io.write_public(raw, deadline_boottime_ns=deadline, check=check)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--help"]:
        print(USAGE, end="")
        return 0
    try:
        run(**arguments(argv))
        return 0
    except BaseException:
        try:
            os.write(2, b"local assembly refused; no package signature, checkpoint or installation produced\n")
        except OSError:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
