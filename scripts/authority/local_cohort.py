#!/usr/bin/env python3
"""Issue one real observed five-service local cohort; never launch services."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
ROLES = ("executor", "issuer", "planner", "planner-writer", "verifier")
USAGE = """Usage: python -I -B scripts/authority/local_cohort.py --approval-fd N --approval-sha256 sha256:HEX --signing-key-fd N [fixed role pairs below, in this exact order]
  --executor-approval-fd N --executor-exchange-directory-fd N
  --issuer-approval-fd N --issuer-exchange-directory-fd N
  --planner-approval-fd N --planner-exchange-directory-fd N
  --planner-writer-approval-fd N --planner-writer-exchange-directory-fd N
  --verifier-approval-fd N --verifier-exchange-directory-fd N

Root-only, one-shot, same-kernel trusted-host-local issuance. CohortApproval/v1
pins the genuine signed Service6 original, the exact five original launch
approvals/observations/issued manifest/certificate hashes and root0700 exchange
identities, explicit configuration-root delegation, boot and original <=300s
dual limits. All actual processes remain parked pending evidence.json. Existing
PIDFD/proc/descriptor/installed-source/mapping checks are mandatory; access to
pidfd_getfd, map_files and process memory is required. No predicted processes,
arbitrary commands, native/TEE/HSM or independent-administrator claim.

The only signing input is the explicitly delegated sealed raw32 configuration
root key. No service or launch-certificate private signing key is borrowed.
Existing package-authorized launch certificates and root-signed manifests must
already exist in each exchange. The exact signed Service6 must also match every
actual child's retained configuration descriptor and installed package binding.

Publishes the same existing signedTrustedHostLocalAttestationCohort/v1 to all
five evidence.json files, complete root0400/no-replace. Each publication may
immediately release that child. Later checks retain its originals but require
only unreleased children to remain parked. Partial release is irreversible:
preserve files and owners, no reset/retry/deletion. No service readiness claim.
Original receipt intervals are not renewed. All acquired handles are retained
on uncertain cleanup; caller input FDs are borrowed and children are not killed.

After all five publications, stdout is ONLY the exact existing signed verifier
inner receipt for the RuntimeTrust issuer. Stdout must be a bounded root-owned
write-only pipe, not a terminal; receipt output remains within original clocks.
No key bytes are printed. Externally bound kernel IO stalls. This local Python
process does not claim guaranteed key-copy erasure or independent custody.
"""


def arguments(argv):
    names = ["--approval-fd", "--approval-sha256", "--signing-key-fd"]
    for role in ROLES:
        names += [f"--{role}-approval-fd", f"--{role}-exchange-directory-fd"]
    if len(argv) != 2 * len(names) or argv[::2] != names:
        raise ValueError("fixed cohort arguments required")
    values = {}
    for name, raw in zip(names, argv[1::2]):
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
        signing_key_fd=values["--signing-key-fd"], role_inputs={role: dict(
            approval_fd=values[f"--{role}-approval-fd"],
            exchange_directory_fd=values[f"--{role}-exchange-directory-fd"]) for role in ROLES})


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--help"]:
        print(USAGE, end="")
        return 0
    owner = None
    try:
        from serverware.authority_local_cohort import LocalCohortIssuer, LocalCohortError, io
        try:
            owner = LocalCohortIssuer.open(**arguments(argv))
            owner.publish()
            io.write_public(owner.verifier_original(), deadline_boottime_ns=owner.value["deadlineBoottimeNs"], check=owner.check)
        except LocalCohortError as error:
            owner = error.owner
            raise
        owner.close()
        return 0
    except BaseException:
        if owner is not None:
            try:
                owner.close()
            except BaseException:
                import os
                import signal
                os.write(2, b"local cohort cleanup unknown; owner retained\n")
                while True:
                    signal.pause()
        import os
        os.write(2, b"local cohort refused; preserve partial release; no retry or readiness claimed\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
