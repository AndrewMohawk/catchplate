"""Source-owned storage grammar for an atomically retained native JIT pair.

These constants authorize neither insertion nor disclosure. The existing
parent transaction must admit the genuine proof, commit the complete pending
transition, and authenticate the resulting business root. Private runtime
documents and caller-supplied verification verdicts have no storage field.
"""
from __future__ import annotations

from types import MappingProxyType


TABLE = "policy_authority_native_jit_review_pairs"
TABLES = (TABLE,)
PRIMARY_KEY = ("approval_request_id",)
UNIQUE_KEYS = (("parent_request_digest",), ("child_request_digest",))
MUTATION_KINDS = ("INSERT",)
COLUMNS = (
    "approval_request_id",
    "parent_request_digest",
    "parent_operation_id",
    "child_request_digest",
    "child_operation_id",
    "parent_request_original",
    "child_request_original",
    "pair_original",
    "proof_original",
    "pair_sha256",
    "proof_sha256",
    "source_contract_digest",
    "control_plane_configuration_digest",
    "owner_scope_digest",
    "secret_kek_id",
    "issued_at_epoch_ns",
    "seal_expires_at_epoch_ns",
    "document_expires_at_epoch_ns",
    "recorded_at_epoch_ns",
    "source_revision",
)
ORIGINAL_LIMITS = MappingProxyType({
    "parent_request_original": 512 * 1024,
    "child_request_original": 512 * 1024,
    "pair_original": 1024 * 1024,
    "proof_original": 128 * 1024,
})
DIGEST_COLUMNS = (
    "parent_request_digest", "parent_operation_id",
    "child_request_digest", "child_operation_id",
    "pair_sha256", "proof_sha256", "source_contract_digest",
    "control_plane_configuration_digest", "owner_scope_digest",
)
EPOCH_COLUMNS = (
    "issued_at_epoch_ns", "seal_expires_at_epoch_ns",
    "document_expires_at_epoch_ns", "recorded_at_epoch_ns",
)
MAX_EPOCH_NS = 2**63 - 1
MAX_SEAL_INTERVAL_NS = 30_000_000_000
DIGEST_PATTERN = "^sha256:[0-9a-f]{64}$"
ZERO_DIGEST = "sha256:" + "0" * 64
UUID_PATTERN = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
KEK_PATTERN = "^attested-memory-kek:[0-9a-f]{24}$"
