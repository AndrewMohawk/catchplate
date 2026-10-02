#!/usr/bin/env python3
"""Fixed local TLS issuance; no live database or installation effects."""
from pathlib import Path
import os
import signal
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
USAGE = """Usage: python -I -B scripts/authority/local_database_credentials.py --approval-fd N --approval-sha256 sha256:HEX --output-directory-fd N

Explicit metadata-bootstrap process mode, nonproduction development channel.
Protected root0400 approval pins an empty root0700 output directory, twelve
existing LOGIN identities, intended owners, server DNS name/client network and
original operation/certificate bounds. Optional separately provisioned local
audit reader adds only its fixed purpose; no NOLOGIN owner credential is issued.

Generates a distinct P256 CA/server/client key set and genuine certificates.
Writes root0400 staging originals, verify-full DSNs, scoped cert-auth HBA/server
fragments and public issuance/inventory records without replacement. No keys or
DSNs are printed. No password, role, schema, grant, network or database is changed.
The runtime paths are /run/serverware/database-tls/PURPOSE/{ca.pem,certificate.pem,
private-key.pem}; later installation must genuinely make private keys readable
only by their intended owner in root-protected traversable directories.

Inventory is last; complete files plus exit0 are required. Failure may retain
partial PRIVATE material; no rollback, overwrite, automatic retry or deletion.
Local/co-located custody is not hardware or independent administration. Issuance
is not installation, role existence, backend-session observation or authority
admission. External supervision must bound stalled kernel/crypto operations.
"""


def arguments(argv):
    if len(argv) != 6 or argv[::2] != ["--approval-fd", "--approval-sha256", "--output-directory-fd"]:
        raise ValueError("fixed local database arguments required")
    result = dict(approval_fd=int(argv[1]), approval_sha256=argv[3], output_directory_fd=int(argv[5]))
    if any(str(result[name]) != raw or not 3 <= result[name] < 2**31 for name, raw in (("approval_fd", argv[1]), ("output_directory_fd", argv[5]))):
        raise ValueError("descriptor refused")
    if result["approval_fd"] == result["output_directory_fd"]: raise ValueError("descriptor alias")
    return result


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--help"]: print(USAGE, end=""); return 0
    owner = None
    try:
        selected = arguments(argv)
        if os.environ.get("SERVERWARE_PROCESS_MODE") != "metadata-bootstrap" or os.environ.get("SERVERWARE_RELEASE_CHANNEL") != "dev":
            raise ValueError("explicit offline development mode required")
        from serverware import config
        if config.PRODUCTION_IMAGE: raise ValueError("production refused")
        from serverware.authority_local_database_credentials import LocalDatabaseCredentialIssuer
        def cancel(_signo, _frame): raise KeyboardInterrupt()
        for signo in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP): signal.signal(signo, cancel)
        owner = LocalDatabaseCredentialIssuer(**selected)
        owner.run()
        owner.check()
        owner.close()
        if time.clock_gettime_ns(time.CLOCK_BOOTTIME) >= owner.selected["deadlineBoottimeNs"] or time.time_ns() >= owner.selected["expiresAtUnixNanos"]:
            raise ValueError("original issuance bounds expired during close")
        print("local database credentials staged; database and installation unchanged")
        return 0
    except BaseException:
        known = owner is None
        if owner is not None:
            try: owner.close(); known = True
            except BaseException: pass
        os.write(2, b"local database issuance refused or failed; partial private staging retained; no retry\n")
        if not known:
            while True:
                try: signal.pause()
                except BaseException: continue
        return 1


if __name__ == "__main__": raise SystemExit(main())
