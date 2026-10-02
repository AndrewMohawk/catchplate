#!/usr/bin/env python3
"""Explicit one-shot local installed-generation-zero trust commit."""
from pathlib import Path
import signal
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
USAGE = """Usage: python -I -B scripts/authority/local_trust_commit.py --approval-fd N --approval-sha256 sha256:HEX --trust-fd N --trust-sha256 sha256:HEX --package-fd N --package-sha256 sha256:HEX --verification-fd N --verification-sha256 sha256:HEX --destination-fd N --witness-directory-fd N

Root-only trusted-host-local first-generation commit, strictly sequence -1 to 0.
Four protected root0400/sealed public originals are independently pinned; the
trust FD must be the actual preprovisioned destination/trust-state.json inode.
Directory FDs identify the approved root0750 installation and root0700 artifact
witness stores. No keys, passwords, arbitrary paths, commands or updates.

The protected approval binds original boot/BOOTTIME/UNIX limits (<=300 seconds),
exact destination path/dev/inode and witness dev/inode, package/verification,
plan, signed provisioning receipt, Receipted terminal state and witness-head
hashes, plus installer request/transition IDs. Actual fixed named records and
installed inode/verity/immutable identities are checked under both existing
locks. Every existing signature and package profile remains required.

Only existing TrustState/v1 is advanced, and the actual package consumer must
accept the result as CurrentExactRetry. A fixed root0400 O_EXCL pending file is
fsynced then atomically exchanged with trust-state.json. The displaced prior
state stays at .trust-state-commit.pending. Success requires fsync/readback,
retained checks and known close within original clocks. Failure may occur AFTER
exchange: preserve BOTH files, never retry, unlink, reset, restore or roll back.
No hidden initial trust bootstrap, new signature/receipt/witness append, service
activation, native/TEE eligibility or hostile-root rollback protection is claimed.
This is cooperative local-root CAS. An external supervisor bounds kernel stalls.
Supplied FDs are borrowed; actual duplicates remain held on uncertain cleanup.
"""


def arguments(argv):
    names = [flag for source in ("approval", "trust", "package", "verification")
        for flag in ("--" + source + "-fd", "--" + source + "-sha256")]
    names += ["--destination-fd", "--witness-directory-fd"]
    if len(argv) != 20 or argv[::2] != names:
        raise ValueError("fixed trust commit arguments required")
    result = {}
    for name, raw in zip(names, argv[1::2]):
        key = name[2:].replace("-", "_")
        if name.endswith("-fd"):
            value = int(raw)
            if str(value) != raw or not 3 <= value < 2**31:
                raise ValueError("descriptor refused")
            result[key] = value
        else:
            if len(raw) != 71 or not raw.startswith("sha256:") or any(c not in "0123456789abcdef" for c in raw[7:]):
                raise ValueError("public pin refused")
            result[key] = raw
    if len({value for key, value in result.items() if key.endswith("_fd")}) != 6:
        raise ValueError("descriptor alias refused")
    return result


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--help"]:
        print(USAGE, end=""); return 0
    try:
        selected = arguments(argv)
    except (ValueError, TypeError):
        print("local trust commit refused: use --help", file=sys.stderr); return 2
    from serverware.authority_local_trust_commit import LocalArtifactTrustCommit
    from serverware.authority_artifact_spec import canonical_json_bytes
    from serverware.authority_local_install import _owning
    owner = None
    def cancelled(signo, frame):
        raise KeyboardInterrupt()
    for signo in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signo, cancelled)
    try:
        with _owning():
            try:
                owner = LocalArtifactTrustCommit.open(**selected)
            except BaseException as error:
                owner = getattr(error, "owner", None)
                raise
        result = owner.run()
        print(canonical_json_bytes(result).decode("ascii")); return 0
    except BaseException as error:
        owner = getattr(error, "owner", None) or owner
        try:
            if owner is not None:
                owner.close()
        except BaseException:
            import os
            os.write(2, b"local trust commit cleanup unknown; actual owner retained\n")
            for signo in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                signal.signal(signo, signal.SIG_IGN)
            while True:
                signal.pause()
        print("local trust commit failed; exchange may have happened; preserve state; no retry or activation", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
