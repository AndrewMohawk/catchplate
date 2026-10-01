"""Source-owned primary keys and operation-relative primary-root contracts.

This is committed schema metadata, not a database-discovered key catalogue.
The map records the active CREATE TABLE declarations in db.py's metadata
schema and executor_v9.authority_v9_schema_source; retired SQL comments do not
define keys. Real database/schema admission still has to verify these contracts.
Neither the source manifest nor its digest grants root currentness or mutation
authority. This module does not import the database or transition registry.
"""
from __future__ import annotations

import hashlib
import json
from types import MappingProxyType
from typing import Any, Mapping

from serverware import authority_contract
from serverware.authority_radix_mutation import PrimaryTableContract


# Explicit ordered PRIMARY KEY columns, reviewed against active source DDL.
# Keep this inventory exact: an operation adding a relation must add its reviewed
# source key, rather than learning a key from the same database being verified.
PRIMARY_KEY_COLUMNS: Mapping[str, tuple[str, ...]] = MappingProxyType({
    "setup_native_enrollments": ("session_id",),
    "setup_native_ca_installations": ("session_id",),
    "setup_native_canary_associations": ("session_id",),
    "setup_native_runtime_attempts": ("session_id",),
    "setup_native_hardware_attempts": ("session_id",),
    "setup_native_final_attempts": ("session_id",),
    "setup_policy_continuations": ("session_id",),
    "policy_native_canary_ready": ("canary_id",),
    "policy_native_canary_heads": ("canary_id",),
    "policy_native_activation_preparations": ("canary_id",),
    "policy_native_activation_finalizations": ("canary_id",),
    "policy_native_activation_holds": ("scope",),
    "approval_grant_consumptions": ("id",),
    "approval_grants": ("id",),
    "approval_request_decisions": ("approval_request_id", "approver_id"),
    "approval_requests": ("id",),
    "approval_review_receipts": ("id",),
    "control_plane_approvals": ("id",),
    "credential_generations": ("credential_id",),
    "credential_currentness_roots": ("id",),
    "credential_currentness_holders": ("id",),
    "credential_currentness_challenges": ("id",),
    "credential_currentness_barriers": ("id",),
    "credential_lease_nonces": ("recipient_key_id", "nonce_sha256"),
    "credential_lease_replay_state": ("scope",),
    "credentials": ("id",),
    "durable_budget_definitions": ("budget_key",),
    "durable_budget_events": ("reservation_id",),
    "metadata_audit_outbox": ("id",),
    "oidc_browser_sessions": ("id",),
    "oidc_session_activation_deliveries": ("id",),
    "pending_oauth_credentials": ("id",),
    "oauth_exchange_reservations": ("id",),
    "oauth_measured_exchange_custody": ("id",),
    "oauth_measured_setup_custody": ("id",),
    "oauth_setup_audit_links": ("id",),
    "oauth_reconnect_authorizations": ("id",),
    "oauth_measured_reconnect_custody": ("id",),
    "oauth_retirement_scope_heads": ("id",),
    "oauth_retirement_scopes": ("id",),
    "oauth_retirement_successions": ("id",),
    "oauth_measured_succession_custody": ("id",),
    "oauth_retirement_succession_materials": ("id",),
    "oauth_retirement_succession_attempts": ("id",),
    "oauth_retirement_successor_generations": ("id",),
    "oauth_retirement_succession_snapshots": ("id",),
    "setup_session_events": ("id",),
    "oauth_refresh_reservations": ("id",),
    "oauth_measured_refresh_custody": ("id",),
    "oauth_measured_refresh_cleanup_custody": ("id",),
    "oauth_refresh_cleanup_reservations": ("id",),
    "oauth_refresh_cleanup_attempts": ("id",),
    "oauth_family_retirements": ("id",),
    "oauth_pending_family_retirements": ("id",),
    "oauth_pending_retirement_reservations": ("id",),
    "oauth_pending_retirement_attempts": ("id",),
    "oauth_measured_pending_retirement_custody": ("id",),
    "oauth_provider_retirements": ("id",),
    "oauth_capture_retirement_reservations": ("id",),
    "oauth_capture_retirement_attempts": ("id",),
    "oauth_measured_capture_retirement_custody": ("id",),
    "oauth_revocation_reservations": ("id",),
    "oauth_revocation_attempts": ("id",),
    "oauth_revocation_work": ("id",),
    "setup_sessions": ("id",),
    "policy_activation_aborts": ("preparation_digest",),
    "policy_activation_approval_consumptions": ("approval_id",),
    "policy_activation_approval_members": ("approval_id", "member_ordinal"),
    "policy_activation_approvals": ("approval_id",),
    "policy_activation_attempts": ("activation_attempt_id",),
    "policy_activation_export_attestations": ("export_id",),
    "policy_activation_export_authorization_heads": ("export_id",),
    "policy_activation_export_authorization_receipts": (
        "export_id", "authorization_revision", "page_ordinal",
    ),
    "policy_activation_export_authorizations": ("export_id", "authorization_revision"),
    "policy_activation_export_issuances": ("export_id",),
    "policy_activation_export_page_attestations": ("export_id", "page_ordinal"),
    "policy_activation_export_pages": ("export_id", "page_ordinal"),
    "policy_activation_finalizations": ("preparation_digest",),
    "policy_activation_finalized_exports": ("activation_attempt_id",),
    "policy_activation_heads": ("activation_attempt_id",),
    "policy_activation_preparations": ("preparation_digest",),
    "policy_activation_prepared_transitions": ("preparation_digest", "transition_ordinal"),
    "policy_activation_publication_receipts": ("publication_receipt_envelope_digest",),
    "policy_activation_revisions": ("activation_attempt_id", "revision"),
    "policy_activation_rollback_consumptions": ("rollback_authorization_payload_digest",),
    "policy_activation_webauthn_assertions": ("assertion_receipt_digest",),
    "policy_authority_activation_evidence_bindings": ("preparation_digest",),
    "policy_authority_audit_inclusion_heads": ("audit_store_identity_digest",),
    "policy_authority_audit_inclusion_receipts": ("inclusion_receipt_envelope_digest",),
    "policy_authority_bounded_aggregate_states": ("aggregate_id",),
    "policy_authority_continuations": ("continuation_digest",),
    "policy_authority_evidence_verifications": ("verification_receipt_digest",),
    "policy_authority_exact_pages": ("page_digest",),
    "policy_authority_external_evidence_receipts": ("evidence_digest",),
    "policy_authority_genesis_finalizations": ("genesis_preparation_digest",),
    "policy_authority_genesis_preparations": ("genesis_preparation_digest",),
    "policy_authority_opaque_values": ("opaque_id",),
    "policy_authority_sealed_values": ("sealed_value_id",),
    "policy_authority_secondary_index_heads": ("index_id",),
    "policy_authority_tombstones": ("tombstone_id",),
    "policy_authority_transition_audits": ("transition_digest",),
    "policy_authority_trusted_keys": ("evidence_kind", "key_revision"),
    "policy_authority_trusted_key_heads": ("evidence_kind",),
    "policy_authority_trusted_key_revocations": ("evidence_kind", "signing_key_id"),
    "policy_authority_work_pages": ("page_id",),
    "policy_canaries": ("canary_id",),
    "policy_canary_heads": ("canary_id",),
    "policy_canary_assignments": ("assignment_envelope_digest",),
    "policy_canary_assignment_members": ("assignment_envelope_digest", "member_ordinal"),
    "policy_canary_load_receipts": ("load_receipt_envelope_digest",),
    "policy_canary_revisions": ("canary_id", "revision"),
    "policy_canary_intake_batches": ("request_id",),
    "policy_canary_delivery_slots": ("id",),
    "policy_canary_delivery_heads": ("id",),
    "policy_canary_delivery_parts": ("slot_id", "ordinal"),
    "policy_canary_instances": ("canary_id", "instance_id", "boot_id"),
    "policy_canary_custody_evidence": ("custody_evidence_envelope_digest",),
    "policy_canary_custody_heads": ("assignment_envelope_digest", "member_ordinal", "canary_id", "instance_id", "boot_id", "generation_id_digest"),
    "policy_canary_ingress_observations": ("ingress_envelope_digest",),
    "policy_canary_active_decisions": ("active_decision_envelope_digest",),
    "policy_canary_shadow_observations": ("shadow_observation_envelope_digest",),
    "policy_canary_instance_revisions": ("canary_id", "instance_id", "boot_id", "revision"),
    "policy_canary_instance_heads": ("canary_id", "instance_id", "boot_id"),
    "policy_canary_checkpoints": ("canary_id", "instance_id", "boot_id", "checkpoint_sequence"),
    "policy_canary_checkpoint_heads": ("canary_id", "instance_id", "boot_id"),
    "policy_canary_checkpoint_aggregates": ("canary_id", "instance_id", "boot_id", "checkpoint_sequence"),
    "policy_compiler_authority_analyses": ("analysis_envelope_digest",),
    "policy_canary_readiness": ("readiness_envelope_digest",),
    "policy_activation_rollback_authority_revocations": ("revocation_envelope_digest",),
    "policy_candidate_artifacts": ("artifact_envelope_digest",),
    "policy_high_water": ("scope",),
    "policy_publications": ("policy_hash",),
    "policy_runtime_evidence_verifications": ("verification_receipt_digest",),
    "policy_runtime_attestations": ("attestation_receipt_envelope_digest",),
    "policy_runtime_role_keys": ("assignment_envelope_digest", "member_ordinal", "role", "public_key_digest"),
    "policy_runtime_role_key_revocations": ("revocation_envelope_digest",),
    "policy_shadow_generation_publications": ("generation_publication_envelope_digest",),
    "policy_shadow_runtime_attestation_handoffs": ("runtime_attestation_handoff_digest",),
    "policy_shadow_generation_claims": ("request_id",),
    "policy_state_bundles": ("reservation_id",),
    "rate_limit_counters": ("counter_key",),
    "rbac_authority_state": ("authority_id",),
    "rbac_role_bindings": ("subject_id",),
    "release_authorization_attempts": ("attempt_id",),
    "release_authorization_credential_issuances": ("attempt_id",),
    "release_authorization_events": ("id",),
    "release_authorization_quota_reservations": ("attempt_id", "counter_key"),
    "routes": ("id",),
    "traversal_budget_chains": ("chain_key",),
    "traversal_budget_cursors": ("cursor_digest",),
    "traversal_budget_page_reservations": ("reservation_id",),
    "webauthn_challenges": ("id",),
    "webauthn_credentials": ("id",),
    "webauthn_trust_publication_high_water": ("authority_scope",),
    "webauthn_trust_publications": ("id",),
})


def _require_coverage() -> None:
    required = {
        table
        for spec in authority_contract.OPERATIONS.values()
        for category in ("businessReads", "businessWrites", "authorizationReads")
        for table in spec[category]
    }
    if set(PRIMARY_KEY_COLUMNS) != required:
        raise ValueError("source primary-key inventory differs from authority relation closure")


def primary_table_contracts(operation: str) -> tuple[PrimaryTableContract, ...]:
    """Return fresh immutable contracts derived only from measured source."""
    _require_coverage()
    spec = authority_contract.operation_spec(operation)
    business = set(spec["businessReads"]) | set(spec["businessWrites"])
    authorization = set(spec["authorizationReads"])
    if business & authorization:
        raise ValueError("source primary-root classes overlap")
    return tuple(
        PrimaryTableContract(
            table=table,
            key_columns=PRIMARY_KEY_COLUMNS[table],
            write_access=table in spec["businessWrites"],
            root_class="business" if table in business else "authorization",
        )
        for table in sorted(business | authorization)
    )


def source_query_manifest() -> list[dict[str, Any]]:
    """Exact global business manifest, preserving db.py operation array order."""
    _require_coverage()
    result: list[dict[str, Any]] = []
    for operation, spec in authority_contract.OPERATIONS.items():
        tables = sorted(set(spec["businessReads"]) | set(spec["businessWrites"]))
        handler_digest = authority_contract.handler_contract_digest(operation)
        for ordinal, table in enumerate(tables, start=1):
            result.append({
                "ordinal": ordinal,
                "predicateId": f"serverware.policyAuthorityQuery/{operation}/{ordinal}/{table}/v3",
                "table": table,
                "handlerDigest": handler_digest,
                "indexContract": "incremental-authenticated-relation-root-v3",
                "predicateKind": "relation-root-and-explicit-key-set",
                "selectorSource": "closed-operation-argument-path-v1",
                "selectorPaths": [list(path) for path in spec["selectors"].get(table, ())],
                "proofKind": "radix16-canonical-multiproof-v2",
                "exactAbsence": True,
                "maximumRows": authority_contract.MAX_SELECTORS_PER_OPERATION,
                "operation": operation,
                "keyColumns": list(PRIMARY_KEY_COLUMNS[table]),
                "writeAccess": table in spec["businessWrites"],
            })
    return result


def source_authorization_manifest() -> list[dict[str, Any]]:
    """Exact global authorization manifest, sorted as its db.py producer."""
    _require_coverage()
    return [
        {
            "operation": operation,
            "ordinal": ordinal,
            "table": table,
            "keyColumns": list(PRIMARY_KEY_COLUMNS[table]),
            "predicateKind": "primary-key-full-row-and-authenticated-root-v1",
            "exactAbsence": True,
        }
        for operation, spec in sorted(authority_contract.OPERATIONS.items())
        for ordinal, table in enumerate(sorted(spec["authorizationReads"]), start=1)
    ]


def _manifest_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
                      separators=(",", ":"), sort_keys=True)


def _manifest_digest(domain: str, value: Any) -> str:
    # Match schema._policy_candidate_authority_framed_digest + db_common.dumps,
    # not the separate domain-NUL business/proof transport framing.
    encoded_domain = domain.encode("ascii")
    payload = _manifest_json(value).encode("ascii")
    digest = hashlib.sha256()
    for frame in (encoded_domain, payload):
        digest.update(len(frame).to_bytes(8, "big"))
        digest.update(frame)
    return "sha256:" + digest.hexdigest()


def source_query_manifest_digest() -> str:
    return _manifest_digest("serverware.policyAuthorityQueryManifest/v1", source_query_manifest())


def source_authorization_manifest_digest() -> str:
    return _manifest_digest("serverware.policyAuthorityAuthorizationManifest/v1", source_authorization_manifest())


def query_manifest_entry_digest(entry: Mapping[str, Any]) -> str:
    """Transport digest only; callers must compare entry to its source value."""
    return _manifest_digest("serverware.policyAuthorityQueryManifestEntry/v1", dict(entry))


def authorization_manifest_entry_digest(entry: Mapping[str, Any]) -> str:
    """Transport digest only; callers must compare entry to its source value."""
    return _manifest_digest("serverware.policyAuthorityAuthorizationManifestEntry/v1", dict(entry))


def validate_planner_manifest_rows(
    operation: str, rows: Any, *, authorization: bool,
) -> tuple[dict[str, Any], ...]:
    """Admit exact fetched metadata against source, not a copied digest label.

    The SQL caller supplies its fixed column projection in ordinal order. Every
    field, including serialized JSON and numeric flag types, must equal the
    independently source-derived value. Returned selection entries are fresh
    source projections; no database-owned row object escapes admission.
    """
    if (type(operation) is not str or type(authorization) is not bool
            or type(rows) not in (list, tuple)
            or len(rows) > authority_contract.MAX_QUERY_PROOFS):
        raise ValueError("planner manifest admission arguments are not bounded and exact")
    authority_contract.operation_spec(operation)
    manifest = source_authorization_manifest() if authorization else source_query_manifest()
    entries = [entry for entry in manifest if entry["operation"] == operation]
    if len(rows) != len(entries) or (not authorization and not entries):
        raise ValueError("planner manifest source coverage changed")
    domain = ("serverware.policyAuthorityAuthorizationManifest/v1" if authorization
              else "serverware.policyAuthorityQueryManifest/v1")
    manifest_digest = _manifest_digest(domain, manifest)
    result = []
    for row, entry in zip(rows, entries):
        entry_digest = (authorization_manifest_entry_digest(entry) if authorization
                        else query_manifest_entry_digest(entry))
        expected = {
            "ordinal": entry["ordinal"], "table_name": entry["table"],
            "key_columns_json": _manifest_json(entry["keyColumns"]),
            "predicate_kind": entry["predicateKind"], "exact_absence": 1,
            "entry_digest": entry_digest, "manifest_digest": manifest_digest,
            "source_revision": authority_contract.SOURCE_REVISION,
        }
        if not authorization:
            expected.update({
                "predicate_id": entry["predicateId"], "handler_digest": entry["handlerDigest"],
                "write_access": int(entry["writeAccess"]),
                "selector_paths_json": _manifest_json(entry["selectorPaths"]),
                "proof_kind": entry["proofKind"], "maximum_rows": entry["maximumRows"],
                "index_contract": entry["indexContract"], "selector_source": entry["selectorSource"],
            })
        if (type(row) is not dict or len(row) != len(expected) or set(row) != set(expected)
                or any(type(row[field]) is not type(value) or row[field] != value
                       for field, value in expected.items())):
            raise ValueError("planner manifest row differs from measured source")
        result.append({
            "ordinal": entry["ordinal"],
            "predicateId": (
                f"serverware.policyAuthorityAuthorizationQuery/{operation}/{entry['ordinal']}/{entry['table']}/v1"
                if authorization else entry["predicateId"]
            ),
            "table": entry["table"], "keyColumns": list(entry["keyColumns"]),
            "writeAccess": False if authorization else entry["writeAccess"],
            "selectorPaths": [] if authorization else [list(path) for path in entry["selectorPaths"]],
            "maximumRows": authority_contract.MAX_QUERY_PROOFS if authorization else entry["maximumRows"],
            "entryDigest": entry_digest,
        })
    return tuple(result)
