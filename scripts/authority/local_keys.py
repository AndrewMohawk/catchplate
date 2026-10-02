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

The separate EnrollmentKeyProvisioningApproval/v1 profile embeds both prior
public inventories and creates only authorization + registration-evidence keys
under keys/enrollment/ and private/enrollment/ in a third empty root0700
directory. Both must differ from all21 and each other. Neither prior profile
changes. Inventory creation grants no enrollment or registration authority;
the existing signed purpose policies and actual hardware ceremony remain.

The separately selected RegistrationChainKeyProvisioningApproval/v1 creates
exactly six NEW keys in a fourth empty root0700 directory: execution-caller,
finalization-caller, computation, completion, state, and grant-authorizer. It
embeds all three preceding public inventories; all29 keys must differ. Fixed
paths are keys/registration-chain/ and private/registration-chain/. The shared
current-root and grant keys serve the explicitly delegated first-registration
execution/finalization chain only; inventory creation does not enroll them,
initialize a vector, authorize a request, or add any OIDC/activation purpose.
The two caller private copies belong in separately admitted FD203 and FD204;
they are never aliases of enrollment authorization or evidence signing keys.

The separately selected StartupKeyProvisioningApproval/v1 creates eight keys
in a fifth empty root0700 directory: launch-runtime, launch-verifier,
launch-planner, launch-planner-writer, launch-issuer, launch-executor,
launch-witness, and rbac-enrollment-root. It embeds all four preceding public
inventories; all37 keys must differ. Fixed paths are keys/startup/ and
private/startup/. Launch identity keys are not service response keys. The RBAC
root is not the configuration or artifact root. Creation does not issue launch
certificates, sign witness enrollment, provision a database or admit a service.

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
