#!/usr/bin/env python3
"""Publish one actual parked local process's existing signed launch pair."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
USAGE = """Usage: python -I -B scripts/authority/local_launch_authorization.py --approval-fd N --approval-sha256 sha256:HEX --exchange-directory-fd N --root-key-fd N --certificate-key-fd N

Root-only, one-shot trusted-host-local issuance. The protected LaunchAuthorization
Approval/v1 fixes the exact unsigned manifest payload, observed-process original
hash, exchange root0700 identity, launch public key, explicit configuration-root
delegation to the existing manifest domain, boot and original <=300s dual clocks.
The current signed package/trust and authentic verification/installation receipts
are literal payload inputs, never invented here. Keys must be distinct sealed
raw32 Ed25519 descriptors: the explicitly installed configuration/launch root and
the current package's purpose-authorized launch-certificate-issuer.

The issuer reads actual observation.json, retains the live process PIDFD and
checks its real descriptors, installed inode generation/verity, root credentials,
launch key, executable mappings/vDSO, argv, environment and original clocks.
Kernel access to pidfd_getfd, map_files and process memory is required. Same
PID/mount/user/time namespaces; actual boot arguments vsyscall=none and
ima_appraise=off. Kernel release/command digests hash literal proc-file bytes.
No native/TEE/HSM/independent-administrator claim or arbitrary command is accepted.

Atomically publishes certificate.json FIRST, manifest.json LAST, root0400,
exclusive/no overwrite, to the existing startup exchange directory. Partial
files are preserved; do not retry/adopt/reset. No keys are generated or printed.
The parent and child still perform actual launch admission; publication is not
readiness or successful service startup. Five service roles ALSO require their
separate genuine five-role cohort evidence.json, which this command does NOT
produce. Runtime/witness need no cohort. Input FDs are borrowed; actual acquired
handles remain in the error owner on uncertain cleanup. Externally bound kernel
IO stalls. Local Python key copies are not guaranteed erased.
"""


def arguments(argv):
    names = ["--approval-fd", "--approval-sha256", "--exchange-directory-fd", "--root-key-fd", "--certificate-key-fd"]
    if len(argv) != 10 or argv[::2] != names:
        raise ValueError("fixed local launch arguments required")
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
    if len({value for key, value in result.items() if key.endswith("_fd")}) != 4:
        raise ValueError("descriptor aliases refused")
    return result


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--help"]:
        print(USAGE, end="")
        return 0
    owner = None
    try:
        from serverware.authority_local_launch_authorization import LocalLaunchAuthorizationIssuer, LocalLaunchAuthorizationError
        try:
            owner = LocalLaunchAuthorizationIssuer.open(**arguments(argv))
            owner.publish()
        except LocalLaunchAuthorizationError as error:
            owner = error.owner
            raise
        owner.close()
        # No post-delivery parked-process check: the real parent may already have
        # delivered and the same child may already have dropped its identity.
        return 0
    except BaseException:
        if owner is not None:
            try:
                owner.close()
            except BaseException:
                import os
                import signal
                os.write(2, b"local launch issuer cleanup unknown; owner retained\n")
                while True:
                    signal.pause()
        import os
        os.write(2, b"local launch pair refused; preserve partial files; no retry or admission claimed\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
