#!/usr/bin/env python3
"""Sign only an exact independently selected local service/witness configuration."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
USAGE = """Usage: python -I -B scripts/authority/local_configuration.py --approval-fd N --approval-sha256 sha256:HEX --signing-key-fd N

Run as root with the protected root0400 canonical ConfigurationApproval/v1
original and a separately provisioned sealed32-byte configuration-root key.
The approval fixes one exact service-v6 or replay-witness-v4 unsigned payload,
its hash, local generation intent, literal seven-role files and references,
actual five-role certificate issuance originals, runtime public keys and the
configuration-root public key, boot and original five-minute maximum clocks.
Witness signing also requires the actual signed service configuration original.

All public joins are checked before private-key access. This command does not
generate keys, TLS credentials, DB/process observations, replay history, package
or attestation receipts. It makes no native/TEE, independent-administrator or
live-launch admission claim. Existing consumers retain those admission checks.

Writes one existing signed configuration envelope as exact canonical JSON to a
root-owned pipe without a newline. Accept only complete output AND exit0. No
file/state/trust changes, retry or deadline extension; externally bound kernel
IO stalls. Python-held local keys are not hardware custody or reliably erased.
"""


def arguments(argv):
    if len(argv) != 6 or argv[::2] != ["--approval-fd", "--approval-sha256", "--signing-key-fd"]:
        raise ValueError("fixed local configuration arguments required")
    result = {}
    for name, raw in (("approval_fd", argv[1]), ("signing_key_fd", argv[5])):
        value = int(raw)
        if str(value) != raw or not 3 <= value < 2**31:
            raise ValueError("descriptor refused")
        result[name] = value
    pin = argv[3]
    if len(pin) != 71 or not pin.startswith("sha256:") or any(c not in "0123456789abcdef" for c in pin[7:]):
        raise ValueError("public pin refused")
    if result["approval_fd"] == result["signing_key_fd"]:
        raise ValueError("descriptor alias refused")
    result["approval_sha256"] = pin
    return result


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--help"]:
        print(USAGE, end="")
        return 0
    try:
        from serverware.authority_local_configuration import LocalConfigurationIssuer
        LocalConfigurationIssuer(**arguments(argv)).publish()
        return 0
    except BaseException:
        try:
            import os
            os.write(2, b"local configuration signing refused; no retry or runtime admission claimed\n")
        except OSError:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
