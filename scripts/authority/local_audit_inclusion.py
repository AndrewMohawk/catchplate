#!/usr/bin/env python3
"""Emit the actual first-genesis inclusion from restricted local PostgreSQL reads."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

USAGE = """Usage: python -I -B scripts/authority/local_audit_inclusion.py \
--approval-fd N --approval-sha256 sha256:HEX --metadata-dsn-fd N \
--audit-dsn-fd N --signing-key-fd N

Separate root-only trusted-host process; approval is protected root:root0400.
DSNs are independently provisioned sealed root:root0400 originals, not argv/env
credentials; metadata uses the separate fixed local audit-inclusion SELECT-only
role, provisioned explicitly by provision_local_audit_reader.py. Existing verifier
grants are not widened. The matching grants and authentication must actually exist.
Audit uses its already bootstrapped restricted role. The existing independently
provisioned audit-inclusion key must be a sealed32-byte FD and actual current key.
No schema, grants, keys, event, outbox completion or authority state is created.

Only first genesis: all policy publication/finalization/inclusion history must be
absent in the actual snapshot. An actual signed preparation, terminal audited
outbox and bounded full audit prefix (256 rows/32MiB, no encrypted legacy preimage)
are mandatory. The policy inclusion sequence is1, not the audit table sequence.
Writes one existing PolicyAuthorityAuditInclusion/v1 record to a root-owned pipe.
Require complete output AND exit0; never retry partial output. Existing genesis
v2 finalize/current-signature/WebAuthn admission remains mandatory. These are
historical snapshots, not a continuing absence/currentness claim; continuation
requires a persistent inclusion ledger. Co-location is NOT independent
administration, hardware custody, external transparency or production approval.
An external supervisor must bound PostgreSQL/kernel stalls under original limits.
"""


def arguments(argv):
    names = ["--approval-fd", "--approval-sha256", "--metadata-dsn-fd", "--audit-dsn-fd", "--signing-key-fd"]
    if len(argv) != 10 or argv[::2] != names:
        raise ValueError("fixed first-inclusion arguments required")
    result = dict(zip((name[2:].replace("-", "_") for name in names), argv[1::2]))
    for name in ("approval_fd", "metadata_dsn_fd", "audit_dsn_fd", "signing_key_fd"):
        raw = result[name]; result[name] = int(raw)
        if str(result[name]) != raw or not 3 <= result[name] < 2**31:
            raise ValueError("first-inclusion descriptor refused")
    return result


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--help"]:
        print(USAGE, end=""); return 0
    owner = None
    try:
        selected = arguments(argv)
        from serverware.authority_local_audit_inclusion import LocalAuditInclusionIssuer
        owner = LocalAuditInclusionIssuer(**selected)
        owner.publish()
        owner.close()
        return 0
    except BaseException:
        known = owner is None
        if owner is not None:
            try: owner.close(); known = True
            except BaseException: pass
        import os
        try:
            os.write(2, b"first audit inclusion refused; output is not accepted; no retry\n")
        except OSError: pass
        if not known:
            try: os.write(2, b"database cleanup unknown; actual issuer owner retained\n")
            except OSError: pass
            import signal
            while True:
                try: signal.pause()
                except BaseException: continue
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
