#!/usr/bin/env python3
"""Export the fixed public bootstrap runtime, never an operational runtime.

The consumer is native_guest/driver_bootstrap.rs::Cold::image (BootstrapRuntime)
under data-plane/decision-gate-rs/src/policy_custody/services/. Its existing
schema is native-shadow-driver-bootstrap.v1.schema.json#/$defs/bootstrapRuntime.
Both fields are source-fixed constants, not operator defaults or authority.

API: --out ABSOLUTE_NEW_DIRECTORY writes only runtime.json, canonical ASCII
without a trailing LF. The separate export metadata goes to stdout. Pass that
file to build_native_pilot_artifacts.py public-inputs --runtime; the independently
authenticated public-input manifest remains required for build admission.

This original belongs to measured-bootstrap-late-runtime-static-amd64-v1 and is
pinned as image.bootstrapRuntimeSha256 by the actual driver bootstrap owner.
It is not the legacy closure's full role runtime or the later operational C9
runtime. No policy, provenance, credentials, signatures, images or live owners
are supplied or reconstructed by this exporter.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import sys

from build_native_pilot_artifacts import new_output, read_original, write_bytes
from build_production_images import canonical_json


def runtime_original() -> bytes:
    return canonical_json({
        "apiVersion": "serverware.nativeShadowDriverBootstrapRuntime/v1",
        "purpose": "measure-final-driver-before-operational-admission",
    }).encode("ascii")


def export(output: Path) -> dict[str, object]:
    raw = runtime_original()
    directory = new_output(output)
    path = directory / "runtime.json"
    write_bytes(path, raw)
    if read_original(path, 65536) != raw:
        raise RuntimeError("written bootstrap runtime differs from its fixed original")
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return {
        "apiVersion": "serverware.nativeShadowBootstrapRuntimeExport/v1",
        "profile": "bootstrap-only",
        "runtimeProfile": "serverware.nativeShadowDriverBootstrapRuntime/v1",
        "file": "runtime.json",
        "sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "releaseAuthority": False,
        "liveReady": False,
        "launchPrepared": False,
        "independentPinAuthenticated": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True,
                        help="new absolute output directory under an existing non-symlink parent")
    args = parser.parse_args()
    print(canonical_json(export(args.out)))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(canonical_json({"ok": False, "error": str(error), "automaticRetryAllowed": False}),
              file=sys.stderr)
        raise SystemExit(1) from error
