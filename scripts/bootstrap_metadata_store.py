#!/usr/bin/env python3
"""Explicit offline PostgreSQL bootstrap; never an application-startup fallback."""
from __future__ import annotations

import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
CONTRACT = "catchplate.metadataStoreBootstrap/v1"
BACKENDS = ("METADATA_STORE", "AUDIT_STORE", "GRANT_STORE")
REQUIRED = (
    "CATCHPLATE_METADATA_STORE_ADMIN_POSTGRES_DSN",
    "CATCHPLATE_AUDIT_STORE_ADMIN_POSTGRES_DSN",
    "CATCHPLATE_METADATA_STORE_POSTGRES_DSN",
    "CATCHPLATE_AUDIT_STORE_POSTGRES_DSN",
    "CATCHPLATE_GRANT_STORE_POSTGRES_DSN",
    "CATCHPLATE_METADATA_STORE_RUNTIME_ROLE",
    "CATCHPLATE_AUDIT_STORE_RUNTIME_ROLE",
    "CATCHPLATE_METADATA_STORE_AUTHORITY_EXECUTOR_ROLE",
    "CATCHPLATE_METADATA_STORE_AUTHORITY_VERIFIER_ROLE",
)
RECOVERY_REQUIRED = (
    "CATCHPLATE_WEBAUTHN_RECOVERY_WITNESS_ADMIN_POSTGRES_DSN",
    "CATCHPLATE_WEBAUTHN_RECOVERY_WITNESS_POSTGRES_DSN",
    "CATCHPLATE_WEBAUTHN_RECOVERY_WITNESS_RUNTIME_ROLE",
)
USAGE = """Usage: python -I -B scripts/bootstrap_metadata_store.py [--help]

Run only in a separately configured CATCHPLATE_PROCESS_MODE=metadata-bootstrap
process with PostgreSQL metadata, audit and grant backends, their configured
admin/runtime identities, and genuine existing authority pins and services.
No credentials, pins or approvals are generated. Normal runtime startup is
unchanged. Failure may leave partial initialization; do not assume rollback.

The local development coordinator may supply an initial RBAC timestamp and
its original UNIX window through the fixed Python API only. This prospective
initial-state recipe refuses existing state/bindings and production use. It is
not an observed database head, a CLI flag, or permission to renew an approval.
Its explicit local audit-reader profile creates only that absent fixed role,
before the first schema contract is sealed; no existing role is adopted.
"""


def _preflight() -> None:
    if os.environ.get("CATCHPLATE_PROCESS_MODE", "").strip() != "metadata-bootstrap":
        raise ValueError("explicit offline process mode is required")
    for backend in BACKENDS:
        if os.environ.get("CATCHPLATE_" + backend + "_BACKEND", "").strip().lower() not in {
            "postgres", "postgresql"
        }:
            raise ValueError("PostgreSQL store configuration is required")
    required = REQUIRED
    if os.environ.get("CATCHPLATE_WEBAUTHN_RECOVERY_WITNESS_BACKEND", "sqlite").strip().lower() in {
        "postgres", "postgresql"
    }:
        required += RECOVERY_REQUIRED
    if any(not os.environ.get(name, "").strip() for name in required):
        raise ValueError("required offline database configuration is missing")


def _load_db():
    from catchplate import db
    return db


def _prepare_bootstrap(*, initial_rbac_timestamp_epoch_ns, original_issued_at_unix_ns,
                       original_expires_at_unix_ns):
    _preflight()
    local_initial_rbac = None
    if any(value is not None for value in (initial_rbac_timestamp_epoch_ns,
            original_issued_at_unix_ns, original_expires_at_unix_ns)):
        from catchplate.authority_local_rbac_bootstrap import selected_timestamp
        local_initial_rbac = dict(initialRbacTimestamp=initial_rbac_timestamp_epoch_ns,
            issuedAtUnixNanos=original_issued_at_unix_ns, expiresAtUnixNanos=original_expires_at_unix_ns)
        selected_timestamp(local_initial_rbac)
    return local_initial_rbac


def _execute_bootstrap(local_initial_rbac, *, local_audit_reader_profile=None):
    if local_audit_reader_profile is not None:
        from catchplate import authority_local_audit_reader as reader
        from catchplate.authority_local_rbac_bootstrap import selected_timestamp
        reader.require_profile(local_audit_reader_profile)
        selected_timestamp(local_initial_rbac)
    db = _load_db()
    db._reject_runtime_metadata_admin_dsn()
    if db.metadata_store_backend_name() != "postgres" or db.audit_store_backend_name() != "postgres":
        raise ValueError("loaded database backends differ from the selected configuration")
    for kind in ("ISSUER", "EXECUTOR", "RECOVERY"):
        db._successor_installation_pins(kind)
    db._policy_authority_verifier_public_key()
    # The existing installer remains the sole semantic role, schema and
    # authority admission. Never replace its pins or turn off its guards.
    if local_initial_rbac is None:
        db.init_db(bootstrap_contract_id=CONTRACT)
    elif local_audit_reader_profile is None:
        db.init_db(bootstrap_contract_id=CONTRACT, local_initial_rbac=local_initial_rbac)
    else:
        db.init_db(bootstrap_contract_id=CONTRACT, local_initial_rbac=local_initial_rbac,
            local_audit_reader_profile=local_audit_reader_profile)


def bootstrap(*, initial_rbac_timestamp_epoch_ns: int | None = None,
              original_issued_at_unix_ns: int | None = None,
              original_expires_at_unix_ns: int | None = None,
              local_audit_reader_profile: str | None = None) -> None:
    """Run the exact offline path, preserving errors for a private caller.

    Errors may contain connection secrets; callers must not publish their text.
    Failure can leave partial initialization and does not authorize a retry.
    """
    local_initial_rbac = _prepare_bootstrap(
        initial_rbac_timestamp_epoch_ns=initial_rbac_timestamp_epoch_ns,
        original_issued_at_unix_ns=original_issued_at_unix_ns,
        original_expires_at_unix_ns=original_expires_at_unix_ns)
    _execute_bootstrap(local_initial_rbac, local_audit_reader_profile=local_audit_reader_profile)


def main(argv: list[str] | None = None, *, initial_rbac_timestamp_epoch_ns: int | None = None,
         original_issued_at_unix_ns: int | None = None, original_expires_at_unix_ns: int | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments == ["--help"]:
        print(USAGE, end="")
        return 0
    if arguments:
        print("metadata bootstrap refused: no configuration arguments are accepted; use --help", file=sys.stderr)
        return 2
    try:
        local_initial_rbac = _prepare_bootstrap(
            initial_rbac_timestamp_epoch_ns=initial_rbac_timestamp_epoch_ns,
            original_issued_at_unix_ns=original_issued_at_unix_ns,
            original_expires_at_unix_ns=original_expires_at_unix_ns)
    except ValueError:
        print("metadata bootstrap refused: explicit offline PostgreSQL configuration is required", file=sys.stderr)
        return 2
    try:
        _execute_bootstrap(local_initial_rbac)
    except (Exception, KeyboardInterrupt):
        # Database/library exception strings can contain credential-bearing
        # connection details. Do not serialize them or claim atomic rollback.
        print("metadata bootstrap failed; partial initialization may remain; no runtime readiness is asserted", file=sys.stderr)
        return 1
    print("metadata bootstrap completed; active-policy and service readiness are not asserted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
