"""Additive native-pair DDL, not an installer or an admission mechanism.

The protected/immutable source inventories supply the PostgreSQL mutation
guards. The native parent operation supplies its sole INSERT template. This
schema never adopts an existing row, backfills data, extends an expiry, or
converts legacy ciphertext/evidence into native custody.
"""
from __future__ import annotations

from catchplate import authority_contract
from catchplate import authority_native_jit_retention_contract as retention


TABLES = retention.TABLES


def source() -> str:
    """Return only source-fixed DDL; callers own installation and migration."""
    columns = []
    for name in retention.COLUMNS:
        kind = "BIGINT" if name in retention.EPOCH_COLUMNS else "TEXT"
        constraints = " NOT NULL"
        if (name,) == retention.PRIMARY_KEY:
            constraints += " PRIMARY KEY"
        if (name,) in retention.UNIQUE_KEYS:
            constraints += " UNIQUE"
        columns.append(f" {name} {kind}{constraints}")
    checks = [
        f" CHECK (approval_request_id ~ '{retention.UUID_PATTERN}')",
        f" CHECK (secret_kek_id ~ '{retention.KEK_PATTERN}')",
    ]
    checks.extend(
        f" CHECK ({name} ~ '{retention.DIGEST_PATTERN}'"
        f" AND {name} <> '{retention.ZERO_DIGEST}')"
        for name in retention.DIGEST_COLUMNS
    )
    # Canonical originals are printable ASCII, so this length is also their
    # byte count. Structural/canonical JSON and every cryptographic join are
    # independently checked before the measured parent plan can insert them.
    checks.extend(
        f" CHECK (length({name}) BETWEEN 2 AND {maximum}"
        f" AND {name} ~ '^[ -~]+$')"
        for name, maximum in retention.ORIGINAL_LIMITS.items()
    )
    checks.extend(
        f" CHECK ({name} BETWEEN 1 AND {retention.MAX_EPOCH_NS})"
        for name in retention.EPOCH_COLUMNS
    )
    checks.extend((
        " CHECK (issued_at_epoch_ns <= recorded_at_epoch_ns"
        " AND recorded_at_epoch_ns < seal_expires_at_epoch_ns"
        " AND seal_expires_at_epoch_ns <= document_expires_at_epoch_ns)",
        " CHECK (seal_expires_at_epoch_ns - issued_at_epoch_ns"
        f" <= {retention.MAX_SEAL_INTERVAL_NS})",
        f" CHECK (source_revision = '{authority_contract.SOURCE_REVISION}')",
        " FOREIGN KEY (approval_request_id) REFERENCES approval_requests(id)"
        " ON UPDATE NO ACTION ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED",
    ))
    return (f"\nCREATE TABLE IF NOT EXISTS {retention.TABLE} (\n"
        + ",\n".join(columns + checks) + "\n);\n")
