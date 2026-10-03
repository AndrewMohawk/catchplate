#!/usr/bin/env python3
"""Sign one exact carry-forward archive; never admit or restart a runtime."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
ORIGINAL_FLAGS = (
    "--current-package-fd", "--current-trust-state-fd", "--current-configuration-fd",
    "--previous-package-fd", "--previous-trust-state-fd", "--previous-configuration-fd",
    "--previous-runtime-evidence-fd",
)
USAGE = """Usage: python -I -B scripts/authority/local_historical_archive.py --approval-fd N --approval-sha256 sha256:HEX --signing-key-fd N
  --current-package-fd N --current-trust-state-fd N --current-configuration-fd N
  --previous-package-fd N --previous-trust-state-fd N --previous-configuration-fd N
  --previous-runtime-evidence-fd N

All arguments are required in this exact order. Run as root with -I -B.
The protected HistoricalArchiveApproval/v1 independently pins all seven exact
originals, current and previous configuration roots, explicit current-root
signing delegation, boot identity, and original issuing/runtime bounds. Public
original FDs must be read-only root0400; the matching current configuration-root
key must be an already provisioned, sealed raw32 memfd. FD possession alone
does not approve its contents or grant a signing purpose.

The owner retains duplicate descriptors and rechecks their identity and bytes.
It verifies the actual current package/configuration and complete prior archive,
preserves prior entries and intervals, and signs only the new current-scope
archive. It does not renew historical evidence, advance trust, generate keys,
admit a new cohort, authorize restart, or establish current database/witness
truth. The v4 cohort consumer still requires genuine current-cohort admission.
No file/state reset, fallback, retry, or extension of original bounds is allowed.

Stdout is only the canonical signed archive on a bounded root-owned write-only
pipe, without a newline. Accept complete output AND exit0; partial output or
any failure is not an archive handoff. Owned descriptors close on success or
failure; borrowed caller descriptors are not closed by the owner. Externally
bound kernel IO stalls. Local Python key custody is not hardware isolation or
guaranteed erasure. Error output contains only a fixed refusal message.
"""


def arguments(argv):
    from serverware.authority_local_historical_archive import ORIGINAL_NAMES

    names = ("--approval-fd", "--approval-sha256", "--signing-key-fd", *ORIGINAL_FLAGS)
    if len(argv) != 2 * len(names) or tuple(argv[::2]) != names:
        raise ValueError("fixed historical archive arguments required")
    values = {}
    for name, raw in zip(names, argv[1::2], strict=True):
        if name.endswith("-fd"):
            value = int(raw)
            if str(value) != raw or not 3 <= value < 2**31:
                raise ValueError("descriptor refused")
        else:
            if len(raw) != 71 or not raw.startswith("sha256:") or any(c not in "0123456789abcdef" for c in raw[7:]):
                raise ValueError("public pin refused")
            value = raw
        values[name] = value
    descriptors = [value for name, value in values.items() if name.endswith("-fd")]
    if len(set(descriptors)) != len(descriptors):
        raise ValueError("descriptor aliases refused")
    return dict(approval_fd=values["--approval-fd"], approval_sha256=values["--approval-sha256"],
        signing_key_fd=values["--signing-key-fd"],
        original_fds={name: values[flag] for name, flag in zip(ORIGINAL_NAMES, ORIGINAL_FLAGS, strict=True)})


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--help"]:
        print(USAGE, end="")
        return 0
    owner = None
    try:
        from serverware.authority_local_historical_archive import LocalHistoricalArchiveIssuer
        try:
            owner = LocalHistoricalArchiveIssuer(**arguments(argv))
            owner.publish()
        finally:
            if owner is not None:
                owner.close()
        return 0
    except BaseException:
        try:
            import os
            os.write(2, b"local historical archive refused; no retry or runtime admission claimed\n")
        except OSError:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
