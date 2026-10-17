#!/usr/bin/env python3
"""Explicit absent-role-only addition; never run automatically by the issuer."""
from pathlib import Path
import json
import os
import signal
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

USAGE = """Usage: python -I -B scripts/authority/provision_local_audit_reader.py --plan
   or: python -I -B scripts/authority/provision_local_audit_reader.py \
--apply --database NAME --admin-dsn-fd N

Explicit offline metadata-bootstrap mode, non-production image only. Applies one
new fixed local inclusion reader role and SELECT/USAGE grants inside an actual
administrator transaction. Requires the metadata schema already bootstrapped.
Refuses any existing role; never reruns or changes the 13-role foundation.
Admin DSN must be a sealed root:root0400 FD, with explicit database/user/host/port;
network connections require sslmode=verify-full. No credential is issued or logged.
Existing runtime/verifier roles are unchanged. Matching runtime authentication
must still be independently provisioned before the inclusion issuer is runnable.
On failure inspect the real database outcome before retry; no automatic retry.
"""


def arguments(argv):
    if argv == ["--plan"]: return None
    if len(argv) != 5 or argv[0:2] != ["--apply", "--database"] or argv[3] != "--admin-dsn-fd":
        raise ValueError("fixed local reader provisioning arguments required")
    import re
    if re.fullmatch(r"[a-z][a-z0-9_]{0,62}", argv[2]) is None:
        raise ValueError("database name refused")
    fd = int(argv[4])
    if str(fd) != argv[4] or not 3 <= fd < 2**31: raise ValueError("admin descriptor refused")
    return dict(database=argv[2], fd=fd)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--help"]: print(USAGE, end=""); return 0
    connections = []
    try:
        selected = arguments(argv)
        from catchplate import authority_local_audit_reader as reader
        if selected is None:
            print(json.dumps(dict(role=reader.ROLE, schema=reader.SCHEMA, selectTables=sorted(reader.TABLES),
                credentialsIssued=False, databaseContacted=False), sort_keys=True)); return 0
        if os.environ.get("CATCHPLATE_PROCESS_MODE") != "metadata-bootstrap":
            raise ValueError("explicit offline mode required")
        from scripts.authority import native_pilot_authority_io as io
        io._process()
        from catchplate import config
        if config.PRODUCTION_IMAGE or os.environ.get("CATCHPLATE_RELEASE_CHANNEL", "").strip() == "production":
            raise ValueError("local reader provisioning refuses production")
        io._input(selected["fd"], 16384, private=True)
        original = io.read_public(selected["fd"], 16384)
        dsn = original.decode("utf-8")
        import psycopg
        from psycopg.rows import dict_row
        parsed = psycopg.conninfo.conninfo_to_dict(dsn)
        if (not dsn or dsn != dsn.strip() or any(c in dsn for c in "\r\n\0")
            or set(parsed) & {"service", "servicefile", "options"}
            or parsed.get("dbname") != selected["database"] or not parsed.get("user")
            or not parsed.get("host") or "," in parsed["host"] or not parsed.get("port")
            or (not parsed["host"].startswith("/") and parsed.get("sslmode") != "verify-full")):
            raise ValueError("explicit pinned admin connection required")
        deadline = time.clock_gettime_ns(time.CLOCK_BOOTTIME) + 30_000_000_000
        def check():
            io._process()
            if time.clock_gettime_ns(time.CLOCK_BOOTTIME) >= deadline or io.read_public(selected["fd"], 16384) != original:
                raise ValueError("original provisioning bound changed or expired")
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM, signal.SIGHUP})
        try:
            connection = psycopg.connect(dsn, connect_timeout=2, row_factory=dict_row,
                options="-c search_path=pg_catalog -c statement_timeout=5000 -c lock_timeout=1000 -c idle_in_transaction_session_timeout=5000")
            connections.append(connection)
        finally: signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        reader.provision(connection, database=selected["database"], check=check)
        check()
        connection.commit()
        connection.close()
        connections.pop()
        print(json.dumps(dict(role=reader.ROLE, status="created-select-only-reader", credentialsIssued=False), sort_keys=True))
        return 0
    except BaseException:
        try:
            while connections:
                connection = connections[-1]
                try: connection.rollback()
                finally: connection.close()
                connections.pop()
        except BaseException:
            os.write(2, b"local reader provisioning cleanup unknown; connection retained\n")
            while True:
                try: signal.pause()
                except BaseException: continue
        print("local reader provisioning refused or failed; inspect outcome before retry; credentials withheld", file=sys.stderr)
        return 1


if __name__ == "__main__": raise SystemExit(main())
