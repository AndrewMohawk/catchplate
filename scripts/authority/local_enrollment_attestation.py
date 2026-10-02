#!/usr/bin/env python3
"""Issue only the existing bounded observed-static local signer attestation."""
from pathlib import Path
import signal
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
USAGE = """Usage: python -I -B scripts/authority/local_enrollment_attestation.py --approval-fd N --approval-sha256 sha256:HEX --signing-key-fd N --signer-public-key-fd N --listener-fd N --replay-directory-fd N

Explicit root metadata-bootstrap/dev producer, never a signer-process launcher.
Protected approval selects actual fixed20/audit/enrollment public inventories,
bounded existing runtime-file bytes and original <=300s BOOTTIME/UNIX limits.
Signer public key is actual root0400 raw32; config-root signing key is separately
delegated sealed root0400 raw32. All input FDs are borrowed, distinct and remain
caller-owned. No key is created or repurposed. Runtime files must be retained,
root-owned, and either mode-nonwritable or on an actual read-only filesystem.

Supply the genuine nonblocking activated Unix stream listener at the existing
/run/serverware/registration-evidence/signer.sock (UID65517:GID65532,0660), and
the actual empty UID65517:GID65517,0700 replay directory at
/var/lib/serverware/registration-evidence-replay. Their actual descriptor/path
identities are pinned. No listener/directory or installed package is invented.
The existing signer entrypoint/runner independently checks actual later launch.

Output is the existing signed trusted-local signer attestation, canonical JSON
to a root-owned pipe. Accept complete output AND known cleanup/exit0. The public
measurement preimages are also available as owner.observation_original to a
retaining local driver. No live PID, complete import closure, native/TEE/HSM,
independent administration or installed-authority-package claim is made.

IMPORTANT: <=300s is the entire signer lifetime, not just bootstrap admission.
Prepare independent package/runtime inputs first and have hardware/operator
ready; then attest -> configure/sign -> admit -> register within that original
window. No implicit renewal, retry, deletion or rollback. Kernel stalls need
an external original-window supervisor; uncertain owned close retains owner.
"""


def arguments(argv):
    flags = ["--approval-fd", "--approval-sha256", "--signing-key-fd", "--signer-public-key-fd", "--listener-fd", "--replay-directory-fd"]
    if len(argv) != 12 or argv[::2] != flags:
        raise ValueError("fixed local enrollment attestation arguments required")
    result = dict(approval_sha256=argv[3])
    for name, raw in zip(("approval_fd", "signing_key_fd", "signer_public_key_fd", "listener_fd", "replay_directory_fd"),
            (argv[1], argv[5], argv[7], argv[9], argv[11]), strict=True):
        value = int(raw)
        if str(value) != raw or not 3 <= value < 2**31: raise ValueError("descriptor refused")
        result[name] = value
    descriptors = [value for name, value in result.items() if name.endswith("_fd")]
    pin = result["approval_sha256"]
    if len(set(descriptors)) != 5 or len(pin) != 71 or not pin.startswith("sha256:") or any(c not in "0123456789abcdef" for c in pin[7:]):
        raise ValueError("descriptor alias or original pin refused")
    return result


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--help"]: print(USAGE, end=""); return 0
    owner = None
    def cancelled(_number, _frame): raise KeyboardInterrupt()
    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP): signal.signal(number, cancelled)
    try:
        from serverware.authority_local_enrollment_attestation import LocalEnrollmentSignerAttestationIssuer
        owner = LocalEnrollmentSignerAttestationIssuer(**arguments(argv))
        owner.publish()
        return 0
    except BaseException as error:
        owner = getattr(error, "owner", None) or owner
        known = owner is None
        if owner is not None:
            try: owner.close(); known = True
            except BaseException: pass
        import os
        try: os.write(2, b"local enrollment signer attestation failed; no launch or admission claimed\n")
        except OSError: pass
        if not known:
            while True:
                try: signal.pause()
                except BaseException: continue
        return 1


if __name__ == "__main__": raise SystemExit(main())
