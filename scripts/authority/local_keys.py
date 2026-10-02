#!/usr/bin/env python3
"""Fixed local key creation, never trust authorization or installation."""
from pathlib import Path
import signal
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
USAGE = """Usage: python -I -B scripts/authority/local_keys.py --approval-fd N --approval-sha256 sha256:HEX --directory-fd N

Root-only fixed20 Ed25519 keys in an actually empty approved root0700 directory:
13 artifact purposes, a separate configuration-root and six service response
keys. Canonical protected approval pins actual directory dev/inode, boot and
original BOOTTIME/UNIX caps (maximum300seconds). No arbitrary names or paths.
Supplied FDs transfer to the actual provisioner and close on known cleanup.

The separately selected GenesisAuditKeyProvisioningApproval/v1 profile creates
only one dedicated audit-inclusion Ed25519 key in another empty root0700
directory. Its protected approval embeds the exact existing fixed20 public
inventory; all public digests are checked and the new key must differ from all
20. Fixed paths are keys/genesis/audit-inclusion.pub and
private/genesis/audit-inclusion.seed, with a separate genesis-audit inventory.
This does not modify the original20, register the new key or grant audit trust.
The old approval/schema/8192-byte limit still select exactly the original20.

Private raw32 seeds are root0400 under private/; public raw32 files are under
keys/. Public-only public-roster.json and inventory.json contain no secret bytes
or private-key hashes. Files publish no-replace, fsync and read back; inventory
publishes last. Core dumps/dumpability are disabled before CSPRNG generation.
Private readback must derive exactly the observed public key. Later signers need
separately sealed memfd copies; these files grant no signing/trust authority.

Partial files persist on failure. No overwrite, adoption, reset, cleanup delete
or automatic retry. Unknown descriptor close retains the actual owner. Require
complete public inventory output and exit0; output is not accepted on failure.
Local root has key access; no hardware custody, independent administration,
reliable memory erasure, accepted package or successful installation is claimed.
An external supervisor must bound kernel stalls within the original window.
"""


def arguments(argv):
    if len(argv) != 6 or argv[::2] != ["--approval-fd", "--approval-sha256", "--directory-fd"]:
        raise ValueError("fixed local key arguments required")
    result = dict(approval_sha256=argv[3])
    for name, raw in (("approval_fd", argv[1]), ("directory_fd", argv[5])):
        value = int(raw)
        if str(value) != raw or not 3 <= value < 2**31: raise ValueError("descriptor refused")
        result[name] = value
    pin = result["approval_sha256"]
    if len(pin) != 71 or not pin.startswith("sha256:") or any(c not in "0123456789abcdef" for c in pin[7:]):
        raise ValueError("approval pin refused")
    if result["approval_fd"] == result["directory_fd"]: raise ValueError("descriptor alias refused")
    return result


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--help"]: print(USAGE, end=""); return 0
    owner = None
    def cancelled(signo, frame): raise KeyboardInterrupt()
    for signo in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP): signal.signal(signo, cancelled)
    try:
        from serverware.authority_local_keys import LocalKeyProvisioner
        from scripts.authority import native_pilot_authority_io as io
        owner = LocalKeyProvisioner(**arguments(argv))
        raw = owner.run()
        owner.close()
        io.write_public(raw, deadline_boottime_ns=owner.selected["deadlineBoottimeNs"], check=owner.check_clock)
        return 0
    except BaseException as error:
        owner = getattr(error, "owner", None) or owner
        known = owner is None
        if owner is not None:
            try: owner.close(); known = True
            except BaseException: pass
        import os
        try: os.write(2, b"local key provisioning failed; partial files retained; no retry or inventory acceptance\n")
        except OSError: pass
        if not known:
            try: os.write(2, b"descriptor cleanup unknown; actual key provisioner retained\n")
            except OSError: pass
            while True:
                try: signal.pause()
                except BaseException: continue
        return 1


if __name__ == "__main__": raise SystemExit(main())
