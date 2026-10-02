#!/usr/bin/env python3
"""Issue only three genuine local cold successor enrollments; never launch/SQL."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
OPTIONS = ("approval-fd", "approval-sha256", "source-directory-fd", "signing-key-fd",
           "issuer-tls-key-fd", "executor-tls-key-fd", "recovery-tls-key-fd")
USAGE = """Usage: python -I -B scripts/authority/local_successor_enrollment.py --approval-fd N --approval-sha256 sha256:HEX --source-directory-fd N --signing-key-fd N --issuer-tls-key-fd N --executor-tls-key-fd N --recovery-tls-key-fd N

Root only. Independently supplied canonical approval, frozen measured source
directory, sealed raw32 configuration-root key, and three sealed original PEM
TLS private keys. No paths, commands, DSNs or private key bytes in arguments.
Signs explicit trusted-host-local COLD enrollments and projects the existing18
bootstrap pin values. No running process, TEE, complete closure, DB admission,
key generation, role/grant changes or independent administrator claim.
Root-owned output pipe only; accept full canonical output AND exit0. No retry.
"""


def arguments(argv):
    if len(argv) != 14 or argv[::2] != ["--" + name for name in OPTIONS]:
        raise ValueError("fixed cold enrollment arguments required")
    result = {}
    for name, value in zip(OPTIONS, argv[1::2]):
        if name == "approval-sha256":
            if len(value) != 71 or not value.startswith("sha256:") or any(c not in "0123456789abcdef" for c in value[7:]):
                raise ValueError("pin refused")
        else:
            number = int(value)
            if str(number) != value or not 3 <= number < 2**31: raise ValueError("descriptor refused")
            value = number
        result[name.replace("-", "_")] = value
    if len({value for name, value in result.items() if name.endswith("_fd")}) != 6:
        raise ValueError("descriptor alias refused")
    return result


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--help"]:
        print(USAGE, end=""); return 0
    owner = None
    try:
        from serverware.authority_local_successor_enrollment import LocalSuccessorColdEnrollment, ColdEnrollmentError
        try: owner = LocalSuccessorColdEnrollment(**arguments(argv))
        except ColdEnrollmentError as error: owner = error.owner; raise
        owner.publish(); owner.close(); return 0
    except BaseException:
        if owner is not None:
            try: owner.close()
            except BaseException:
                import signal
                while True: signal.pause()  # Retain the actual uncertain descriptor owner.
        print("cold successor enrollment refused; no retry or database admission claimed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
