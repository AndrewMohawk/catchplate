"""Closed schema programs for comparison and the receipt-only v9 repair.

Pure source construction only: no database, runtime registry, DDL execution or
authority admission. The legacy variant is never a general migration input.
"""

from __future__ import annotations

from serverware.authority_store.metadata_schema_source import metadata_schema_source

COMPLETED_V9_RECEIPT_TABLE = "policy_authority_v9_offline_migration_receipts"
_RECEIPT_TABLE_START = (
    "CREATE TABLE IF NOT EXISTS\n"
    "            policy_authority_v9_offline_migration_receipts ("
)
_RECEIPT_TABLE_SUCCESSOR = (
    "CREATE TABLE IF NOT EXISTS\n"
    "            policy_authority_authorization_dependency_manifests ("
)
_LEGACY_RECEIPT_TABLE_SOURCE = """
        CREATE TABLE IF NOT EXISTS
            policy_authority_v9_offline_migration_receipts (
                contract_id TEXT PRIMARY KEY,
                source_version BIGINT NOT NULL,
                target_version BIGINT NOT NULL,
                before_manifest_json TEXT NOT NULL,
                before_manifest_digest TEXT NOT NULL,
                before_row_counts_json TEXT NOT NULL,
                before_row_counts_digest TEXT NOT NULL,
                after_manifest_json TEXT NOT NULL,
                after_manifest_digest TEXT NOT NULL,
                after_row_counts_json TEXT NOT NULL,
                after_row_counts_digest TEXT NOT NULL,
                operation_contract_digest TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                receipt_digest TEXT NOT NULL UNIQUE,
                signer_identity_digest TEXT,
                signature_algorithm TEXT,
                detached_signature TEXT,
                detached_signature_digest TEXT UNIQUE,
                status TEXT NOT NULL,
                completed_at TEXT NOT NULL,
                CHECK (
                    contract_id =
                    'serverware.policyCandidateAuthorityOfflineMigration/v2:v8-to-v9'
                ),
                CHECK (source_version = 8),
                CHECK (target_version = 9),
                CHECK (status = 'completed'),
                CHECK (length(before_manifest_json) BETWEEN 2 AND 67108864),
                CHECK (length(after_manifest_json) BETWEEN 2 AND 67108864),
                CHECK (length(before_row_counts_json) BETWEEN 2 AND 4194304),
                CHECK (length(after_row_counts_json) BETWEEN 2 AND 4194304),
                CHECK (length(receipt_json) BETWEEN 2 AND 67108864),
                CHECK (
                    signer_identity_digest IS NOT NULL
                    AND signature_algorithm = 'Ed25519'
                    AND detached_signature IS NOT NULL
                    AND detached_signature_digest IS NOT NULL
                )
            );
"""


def completed_v9_schema_programs(source_schema_program: str) -> tuple[str, str]:
    """Return the target receipt declaration and exact legacy full program.

    Accept only the complete current source, before any slicing or replacement.
    The unchanged base schema and nonreceipt extension must remain in both
    structural comparisons; terminal-custody row populations are excluded by
    the separate migration population commitment, never by this constructor.
    """
    canonical = metadata_schema_source()
    if type(source_schema_program) is not str or source_schema_program != canonical:
        raise ValueError("completed-v9 repair requires the canonical complete metadata source")
    if (
        canonical.count(_RECEIPT_TABLE_START) != 1
        or canonical.count(_RECEIPT_TABLE_SUCCESSOR) != 1
    ):
        raise ValueError("completed-v9 receipt source boundaries are not unique")
    start = canonical.index(_RECEIPT_TABLE_START)
    end = canonical.index(_RECEIPT_TABLE_SUCCESSOR)
    if end <= start:
        raise ValueError("completed-v9 receipt source boundaries are not ordered")
    target = canonical[start:end]
    required_fragments = (
        "migration_name TEXT NOT NULL",
        "migration_sha256 TEXT NOT NULL",
        "source_revision TEXT NOT NULL",
        "signer_identity_digest TEXT NOT NULL",
        "signer_public_key_base64url TEXT NOT NULL",
        "signature_algorithm TEXT NOT NULL",
        "detached_signature TEXT NOT NULL",
        "detached_signature_digest TEXT NOT NULL UNIQUE",
    )
    if (
        not target.strip().endswith(";")
        or target.count("CREATE TABLE IF NOT EXISTS") != 1
        or any(target.count(fragment) != 1 for fragment in required_fragments)
    ):
        raise ValueError("completed-v9 target receipt declaration is not exact")
    legacy = (
        canonical[:start]
        + _LEGACY_RECEIPT_TABLE_SOURCE
        + "\n        "
        + canonical[end:]
    )
    return target, legacy


def require_metadata_schema_program(
    source_schema_program: str,
    *,
    legacy_completed_v9_receipt: bool = False,
) -> None:
    """Reject arbitrary/partial DDL before any expected-schema engine work."""
    if type(source_schema_program) is not str or type(legacy_completed_v9_receipt) is not bool:
        raise ValueError("metadata schema source and receipt variant must have exact types")
    expected = metadata_schema_source()
    if legacy_completed_v9_receipt:
        _, expected = completed_v9_schema_programs(expected)
    if source_schema_program != expected:
        raise ValueError("metadata schema source is not the exact selected complete program")
