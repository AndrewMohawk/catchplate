#!/usr/bin/env python3
"""One explicit first-registration scope decision, no unattended approval."""
from pathlib import Path
import os
import signal
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
USAGE = """Usage: python -I -B scripts/authority/local_registration_context.py --prepare-directory
   or: python -I -B scripts/authority/local_registration_context.py --approval-fd N --approval-sha256 sha256:HEX --signing-key-fd N

Development-only root metadata-bootstrap producer. No arbitrary paths, hooks,
SQL, new keys, hardware registration or automatic head selection.

Before cold bootstrap, --prepare-directory creates ONLY absent fixed
/run/catchplate/registration-contexts root:65532 0750 and requests/ 65532:65532
0700. Its canonical {path,device,inode} output must be pinned in explicitly
selected execution/v4 and finalization/v5 nested bootstraps. Existing parent
v4 and existing independently signed enrollments remain required. The actual
launcher owns this directory creation and retained original lifetime.

The application authenticates its present caller, retains the genuine grant,
and publishes requests/{execution|finalization}-HEX-{reserve|execute}.json
(app-owned 0400, no overwrite). It waits only within the SAME original call.
Root automation reads that complete public-original request as UNTRUSTED DATA.
Request bytes are capped below 16 MiB so literal escaping plus the independent
approval wrapper remains within the existing 32 MiB protected-public limit.
It independently selects the current predecessor or pending scope; a request,
receipt, local locator or signature history alone grants no such authority.

Protected approval exact fields: schema=catchplate.authorityTrustedHostLocalRegistrationContextApproval/v1,
directory, requestOriginal, requestSha256, scope, issuedAtMonotonicNs,
issuedAtUnixNanos. Scope is {sequence,headDigest,nextFence} for reserve, or
{sequence,headDigest,fence} for execute. The latter uses the SAME two original
issue times from the root-signed predecessor context, never a renewed window.
The request includes that exact prior original. The existing full grant and
packet preparer authenticate actual inputs; packet/authorization pins are
derived, never guessed. The real application replays custody and signer subject.

Approval is root0400 protected public FD+SHA; signing key is separately delegated
sealed root0400 raw32 config-root FD. They remain caller-owned and may not alias.
The one-shot response is atomically published, root:65532 0440, in the fixed
parent directory under the same request basename. Output is only path+SHA.
No overwrite/reset/retry. A failure may leave a pending or published record;
it is not rollback. Unknown close retains ownership and does not exit success.

This requires independently operated timely root automation. Existing live
grant/transport caps are at most 30 seconds; the broader 300-second signer
window does not extend them. Real hardware/operator readiness is still needed.
Neither publication nor file delivery proves SQL commit or enrollment success.
"""


def arguments(argv):
    if len(argv) != 6 or argv[::2] != ["--approval-fd", "--approval-sha256", "--signing-key-fd"]:
        raise ValueError("fixed local context arguments required")
    values = [int(argv[index]) for index in (1, 5)]
    if any(str(value) != argv[index] or not 3 <= value < 2**31 for value, index in zip(values, (1, 5))) or values[0] == values[1]:
        raise ValueError("distinct protected descriptors required")
    pin = argv[3]
    if len(pin) != 71 or not pin.startswith("sha256:") or any(c not in "0123456789abcdef" for c in pin[7:]):
        raise ValueError("exact public original pin required")
    return dict(approval_fd=values[0], approval_sha256=pin, signing_key_fd=values[1])


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--help"]:
        print(USAGE, end=""); return 0
    owner = None
    def cancelled(_number, _frame): raise KeyboardInterrupt()
    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP): signal.signal(number, cancelled)
    try:
        from catchplate import authority_local_registration_context as context
        if argv == ["--prepare-directory"]:
            result = context.prepare_directory()
        else:
            owner = context.LocalRegistrationContextIssuer(**arguments(argv))
            result = owner.run()
        raw = context.canonical(result) + b"\n"
        # This receipt contains public path/pin scalars only, never originals.
        if os.write(1, raw) != len(raw): raise ValueError("partial receipt output")
        return 0
    except BaseException as error:
        owner = getattr(error, "owner", None) or owner
        known = owner is None
        if owner is not None:
            try: owner.close(); known = True
            except BaseException: pass
        try: os.write(2, b"local registration context failed; no retry or SQL result claimed\n")
        except OSError: pass
        if not known:
            while True:
                try: signal.pause()
                except BaseException: continue
        return 1


if __name__ == "__main__": raise SystemExit(main())
