#!/usr/bin/env python3
"""Fixed local registration root-delegation connector; no SQL or key generation."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
OPTIONS = ("approval-fd", "approval-sha256", "signing-key-fd", "context-directory-fd")
USAGE = """Usage: python -I -B scripts/authority/local_registration_enrollment.py --approval-fd N --approval-sha256 sha256:HEX --signing-key-fd N --context-directory-fd N

Development metadata-bootstrap only. Requires protected independent approval,
the sealed existing configuration-root key, and the actual prepared fixed
registration-context directory. Authenticates public key inventories, Service6
and five-role cohort; signs the existing four enrollments and outer bootstrap4.
Complete initial vector must be independently approved from genuine observation.
No SQL, keys, receipts, grants, contexts, hardware ceremony or future FD custody
is created. All input descriptors stay caller-owned. Accept complete canonical
public output AND exit0; no automatic retry or lifetime renewal.
"""


def arguments(argv):
    if len(argv) != 8 or argv[::2] != ["--" + name for name in OPTIONS]:
        raise ValueError("fixed enrollment arguments required")
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
    if len({value for name, value in result.items() if name.endswith("_fd")}) != 3:
        raise ValueError("descriptor alias refused")
    return result


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--help"]:
        print(USAGE, end=""); return 0
    owner = None
    try:
        from catchplate.authority_local_registration_enrollment import LocalRegistrationEnrollment
        owner = LocalRegistrationEnrollment(**arguments(argv))
        owner.publish(); owner.close(); return 0
    except BaseException:
        if owner is not None: owner.close()
        print("local registration enrollment refused; no database or hardware admission claimed", file=sys.stderr)
        return 1


if __name__ == "__main__": raise SystemExit(main())
