#!/usr/bin/env python3
"""Explicit offline PostgreSQL bootstrap; never an application-startup fallback."""
from __future__ import annotations

import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
CONTRACT = "serverware.metadataStoreBootstrap/v1"
BACKENDS = ("METADATA_STORE", "AUDIT_STORE", "GRANT_STORE")
REQUIRED = (
    "SERVERWARE_METADATA_STORE_ADMIN_POSTGRES_DSN",
    "SERVERWARE_AUDIT_STORE_ADMIN_POSTGRES_DSN",
    "SERVERWARE_METADATA_STORE_POSTGRES_DSN",
    "SERVERWARE_AUDIT_STORE_POSTGRES_DSN",
    "SERVERWARE_GRANT_STORE_POSTGRES_DSN",
    "SERVERWARE_METADATA_STORE_RUNTIME_ROLE",
    "SERVERWARE_AUDIT_STORE_RUNTIME_ROLE",
    "SERVERWARE_METADATA_STORE_AUTHORITY_EXECUTOR_ROLE",
    "SERVERWARE_METADATA_STORE_AUTHORITY_VERIFIER_ROLE",
)
RECOVERY_REQUIRED = (
    "SERVERWARE_WEBAUTHN_RECOVERY_WITNESS_ADMIN_POSTGRES_DSN",
    "SERVERWARE_WEBAUTHN_RECOVERY_WITNESS_POSTGRES_DSN",
    "SERVERWARE_WEBAUTHN_RECOVERY_WITNESS_RUNTIME_ROLE",
)
USAGE = """Usage: python -I -B scripts/bootstrap_metadata_store.py [--help]

Run only in a separately configured SERVERWARE_PROCESS_MODE=metadata-bootstrap
process with PostgreSQL metadata, audit and grant backends, their configured
admin/runtime identities, and genuine existing authority pins and services.
No roles, credentials, pins or approvals are generated. Normal runtime startup
is unchanged. Failure may leave partial initialization; do not assume rollback.
"""


def _preflight() -> None:
    if os.environ.get("SERVERWARE_PROCESS_MODE", "").strip() != "metadata-bootstrap":
        raise ValueError("explicit offline process mode is required")
    for backend in BACKENDS:
        if os.environ.get("SERVERWARE_" + backend + "_BACKEND", "").strip().lower() not in {
            "postgres", "postgresql"
        }:
            raise ValueError("PostgreSQL store configuration is required")
    required = REQUIRED
    if os.environ.get("SERVERWARE_WEBAUTHN_RECOVERY_WITNESS_BACKEND", "sqlite").strip().lower() in {
        "postgres", "postgresql"
    }:
        required += RECOVERY_REQUIRED
    if any(not os.environ.get(name, "").strip() for name in required):
        raise ValueError("required offline database configuration is missing")


def _load_db():
    from serverware import db
    return db


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments == ["--help"]:
        print(USAGE, end="")
        return 0
    if arguments:
        print("metadata bootstrap refused: no configuration arguments are accepted; use --help", file=sys.stderr)
        return 2
    try:
        _preflight()
    except ValueError:
        print("metadata bootstrap refused: explicit offline PostgreSQL configuration is required", file=sys.stderr)
        return 2
    try:
        db = _load_db()
        db._reject_runtime_metadata_admin_dsn()
        if db.metadata_store_backend_name() != "postgres" or db.audit_store_backend_name() != "postgres":
            raise ValueError("loaded database backends differ from the selected configuration")
        for kind in ("ISSUER", "EXECUTOR", "RECOVERY"):
            db._successor_installation_pins(kind)
        db._policy_authority_verifier_public_key()
        # The existing installer remains the sole semantic role, schema and
        # authority admission. Never replace its pins or turn off its guards.
        db.init_db(bootstrap_contract_id=CONTRACT)
    except (Exception, KeyboardInterrupt):
        # Database/library exception strings can contain credential-bearing
        # connection details. Do not serialize them or claim atomic rollback.
        print("metadata bootstrap failed; partial initialization may remain; no runtime readiness is asserted", file=sys.stderr)
        return 1
    print("metadata bootstrap completed; active-policy and service readiness are not asserted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
