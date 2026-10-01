#!/usr/bin/env python3
"""Fixed local installer; public authority and private signing inputs are supplied."""
from __future__ import annotations

from pathlib import Path
import signal
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
USAGE = """Usage: python -I -B scripts/authority/local_install.py --configuration-fd N --configuration-sha256 sha256:HEX --package-fd N --package-sha256 sha256:HEX --verification-fd N --verification-sha256 sha256:HEX --source-root-fd N --signing-key-fd N

Root-only explicit trusted-host-local installation, never native/production
admission or activation. Supply root0400 pinned canonical configuration, genuine
signed artifact package and authorized verification receipt; retained source-root
FD; and an independently provisioned sealed32-byte artifact-provisioner key.
The existing root0750 destination contains the independently maintained root0400
trust-state.json pinned by configuration. Its high-water is never advanced here.

Requires x86_64 Linux openat2/renameat2, actual inode generations, fs-verity and
immutable flags, with CAP_CHOWN/DAC_OVERRIDE/FOWNER/LINUX_IMMUTABLE. Source must
be an actual readonly mount or fully immutable tree matching signed snapshot.
Original boot/BOOTTIME/UNIX limits never renew; use an external process watchdog
for kernel IO stalls. Failure preserves staging, state and published artifacts;
there is no automatic retry, reset, deletion, rollback or current symlink.
Success exposes exact plan/receipt/state files under destination/receipts only
after real publication, durable readback and known descriptor/lock close.
"""


def arguments(argv):
    names = ("configuration", "package", "verification")
    expected = [flag for name in names for flag in ("--" + name + "-fd", "--" + name + "-sha256")]
    expected += ["--source-root-fd", "--signing-key-fd"]
    if len(argv) != 16 or argv[::2] != expected:
        raise ValueError("fixed installer arguments required")
    result = {}
    for flag, value in zip(argv[::2], argv[1::2]):
        name = flag[2:].replace("-", "_")
        if name.endswith("_fd"):
            fd = int(value)
            if str(fd) != value or not 3 <= fd < 2**31: raise ValueError("invalid descriptor")
            result[name] = fd
        else:
            if len(value) != 71 or not value.startswith("sha256:") or any(c not in "0123456789abcdef" for c in value[7:]):
                raise ValueError("invalid public pin")
            result[name] = value
    fds = [value for key, value in result.items() if key.endswith("_fd")]
    if len(set(fds)) != len(fds): raise ValueError("descriptor alias refused")
    return result


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--help"]:
        print(USAGE, end=""); return 0
    try:
        selected = arguments(argv)
    except (ValueError, TypeError):
        print("local installation refused: use --help", file=sys.stderr); return 2
    from serverware.authority_local_install import LocalAuthorityInstaller
    from serverware.authority_artifact_spec import canonical_json_bytes
    owner = None
    def cancelled(signo, frame):
        raise KeyboardInterrupt()
    for signo in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signo, cancelled)
    try:
        owner = LocalAuthorityInstaller.open(**selected)
        result = owner.run()
        print(canonical_json_bytes(result).decode("ascii")); return 0
    except BaseException as error:
        owner = getattr(error, "owner", None) or owner
        try:
            if owner is not None: owner.close()
        except BaseException:
            print("local installation failed; descriptor close uncertain; artifacts preserved; no retry", file=sys.stderr)
            return 1
        print("local installation failed; partial artifacts preserved; no retry or activation", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
