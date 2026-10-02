#!/usr/bin/env python3
"""Prepare only existing local first-registration configuration policy fields."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
USAGE = """Usage: python -I -B scripts/authority/local_enrollment_configuration.py --approval-fd N --approval-sha256 sha256:HEX

Explicit nonproduction metadata-bootstrap/dev command. The protected root0400
EnrollmentConfigurationApproval/v1 original binds a complete unsigned local
ConfigurationApproval, actual fixed20/audit/enrollment public inventories,
genuine root-signed registration signer attestation and explicit issuer/age
policy. Two new enrollment keys must be distinct from all21 and each other.

Projects only existing registration evidence, finalization and enrollment
authorization policies plus their two planner operations. Other policies,
generation and original clocks remain unchanged. The original configuration
expiry must fit the real signed signer attestation; no extension or renewal.
Trust installation/staging stay disabled. Genuine hardware enrollment remains
required; neither a credential, signer attestation nor registration is made.

Borrow one inherited public FD and write one exact canonical unsigned existing
ConfigurationApproval to a root-owned pipe, no newline. Accept only complete
output AND exit0. The existing local_configuration signer separately admits it.
No keys, signatures, SQL, process/listener/descriptor provisioning or rollback;
kernel IO stalls need an external original-window supervisor.
"""


def arguments(argv):
    if len(argv) != 4 or argv[::2] != ["--approval-fd", "--approval-sha256"]:
        raise ValueError("fixed local enrollment configuration arguments required")
    fd, pin = int(argv[1]), argv[3]
    if str(fd) != argv[1] or not 3 <= fd < 2**31 or len(pin) != 71 or not pin.startswith("sha256:") or any(c not in "0123456789abcdef" for c in pin[7:]):
        raise ValueError("protected descriptor or original pin refused")
    return dict(approval_fd=fd, approval_sha256=pin)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--help"]:
        print(USAGE, end="")
        return 0
    try:
        from serverware.authority_local_enrollment_configuration import LocalEnrollmentConfigurationBuilder
        LocalEnrollmentConfigurationBuilder(**arguments(argv)).publish()
        return 0
    except BaseException:
        try:
            import os
            os.write(2, b"local enrollment configuration preparation refused; no signature or enrollment claimed\n")
        except OSError:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
