#!/usr/bin/env python3
"""Fixed activation key creation only; never a service or trust provisioner."""
from pathlib import Path
import signal
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

USAGE = """Usage: python -I -B scripts/authority/local_activation_keys.py --approval-fd N --approval-sha256 sha256:HEX --directory-fd N

Create the separate fixed10 Ed25519 +5 raw32 activation-key inventory in an
actually empty, explicitly approved root:root0700 directory. The canonical
root0400 approval binds its original boot/epoch bounds and all five preceding
public inventories, including startup keys. No arbitrary purposes or paths.
Existing LocalKeys profiles remain unchanged. No runtime/state root replacement,
grant, enrollment, socket, database right or active service is created here.

Only public keys and raw encryption-key SHA256 commitments appear in output;
encryption bytes never become public keys. Private seeds/keys are root0400.
Files are no-replace, fsynced and read back; inventory.json publishes last.
The actual owner takes supplied descriptors. Partial files persist on failure;
no automatic retry, overwrite, adoption or deletion. Unknown cleanup retains
the actual owner. Accept output only with exit0. Local-root key access remains;
hardware custody and reliable memory erasure are not claimed. An external
supervisor must bound native stalls within the original absolute allowance.
"""


def arguments(argv):
    from scripts.authority.local_keys import arguments as fixed_arguments
    return fixed_arguments(argv)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--help"]:
        print(USAGE, end="")
        return 0
    owner = None

    def cancelled(signo, frame):
        raise KeyboardInterrupt()

    for signo in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signo, cancelled)
    try:
        from serverware.authority_local_activation_keys import LocalActivationKeyProvisioner
        from scripts.authority import native_pilot_authority_io as io
        owner = LocalActivationKeyProvisioner(**arguments(argv))
        raw = owner.run()
        owner.close()
        io.write_public(raw, deadline_boottime_ns=owner.deadline_boottime_ns, check=owner.check_clock)
        return 0
    except BaseException as error:
        owner = getattr(error, "owner", None) or owner
        known = owner is None
        if owner is not None:
            try:
                owner.close()
                known = True
            except BaseException:
                pass
        import os
        try:
            os.write(2, b"activation key provisioning failed; partial files retained; no retry or inventory acceptance\n")
        except OSError:
            pass
        if not known:
            try:
                os.write(2, b"descriptor cleanup unknown; actual activation key owner retained\n")
            except OSError:
                pass
            while True:
                try:
                    signal.pause()
                except BaseException:
                    continue
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
