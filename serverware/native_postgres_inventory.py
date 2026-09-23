"""Closed source inventory for the still-unprepared native PostgreSQL batch.

This is authored test identity data, not discovery, execution permission or a
claim that a controller has prepared these suites. Consumers use this fixed
inventory; no caller-selected scripts, selectors or deadlines are admitted.
"""
from __future__ import annotations

from dataclasses import dataclass
import re


INVENTORY_SCHEMA = "serverware.nativePostgresInventory/v1"
TOTAL_TESTS = 184


@dataclass(frozen=True, slots=True)
class NativePostgresSuite:
    script: str
    test_ids: tuple[str, ...]
    disposable_cluster: bool
    timeout_seconds: int


SUITES: tuple[NativePostgresSuite, ...] = (
    NativePostgresSuite(
        script="scripts/test_webauthn_trust_projection_postgres.py",
        test_ids=(
            "WebAuthnTrustProjectionPostgresTests.test_both_rows_remain_write_locked_until_transaction_ends",
            "WebAuthnTrustProjectionPostgresTests.test_connection_admission_rejects_tcp_and_configuration_overrides",
            "WebAuthnTrustProjectionPostgresTests.test_exact_projection_uses_real_publication_and_high_water_columns",
            "WebAuthnTrustProjectionPostgresTests.test_join_mismatches_and_unpublished_status_are_denied",
            "WebAuthnTrustProjectionPostgresTests.test_matching_values_on_different_publications_cannot_be_combined",
            "WebAuthnTrustProjectionPostgresTests.test_missing_either_row_is_denied",
            "WebAuthnTrustProjectionPostgresTests.test_namespace_matches_existing_quoted_identifier_contract",
            "WebAuthnTrustProjectionPostgresTests.test_witness_and_revocation_values_are_from_the_same_locked_high_water",
        ),
        disposable_cluster=False,
        timeout_seconds=300,
    ),
    NativePostgresSuite(
        script="scripts/test_postgres_trigger_manifest.py",
        test_ids=(
            "PostgresTriggerManifestTests.test_each_mode_changes_both_manifests_without_changing_definition",
            "PostgresTriggerManifestTests.test_legacy_mode_omission_is_not_normalized_to_current",
            "PostgresTriggerManifestTests.test_mode_serializer_rejects_missing_or_unknown_values",
            "PostgresTriggerManifestTests.test_modes_are_not_boolean_equivalents_in_origin_session",
            "PostgresTriggerManifestTests.test_namespace_and_table_are_exact_not_search_path_or_prefix",
        ),
        disposable_cluster=False,
        timeout_seconds=300,
    ),
    NativePostgresSuite(
        script="scripts/test_authority_mutation_postgres.py",
        test_ids=(
            "AuthorityMutationPostgresTests.test_all_three_selector_paths_use_exact_quoted_namespace_and_hold_locks",
            "AuthorityMutationPostgresTests.test_cardinality_zero_or_multiple_rolls_back",
            "AuthorityMutationPostgresTests.test_closed_object_guards_use_real_postgres_for_exact_sets",
            "AuthorityMutationPostgresTests.test_composite_keys_and_nullable_selector_fields_remain_typed",
            "AuthorityMutationPostgresTests.test_expected_row_requires_explicit_null_or_exact_object",
            "AuthorityMutationPostgresTests.test_insert_collision_and_absent_update_delete_are_rejected",
            "AuthorityMutationPostgresTests.test_insert_update_delete_execute_exact_shared_sql",
            "AuthorityMutationPostgresTests.test_key_catalog_closure_rejects_empty_partial_and_inexact_selectors",
            "AuthorityMutationPostgresTests.test_later_failed_mutation_rolls_back_prior_write_in_same_statement",
            "AuthorityMutationPostgresTests.test_payload_key_cannot_retarget_update_and_key_moves_roll_back",
            "AuthorityMutationPostgresTests.test_post_rows_are_exact_and_missing_images_are_not_null",
            "AuthorityMutationPostgresTests.test_presence_matchers_reject_missing_coerced_and_stale_images",
            "AuthorityMutationPostgresTests.test_source_interpolation_and_namespace_input_boundary",
            "AuthorityMutationPostgresTests.test_trigger_changed_postcondition_and_delete_survivor_roll_back",
        ),
        disposable_cluster=False,
        timeout_seconds=300,
    ),
    NativePostgresSuite(
        script="scripts/test_authority_root_transition_postgres.py",
        test_ids=(
            "AuthorityRootTransitionPostgresTests.test_authorization_after_tamper_rolls_back_business_write",
            "AuthorityRootTransitionPostgresTests.test_business_after_digest_revision_and_count_mismatch_roll_back",
            "AuthorityRootTransitionPostgresTests.test_changed_before_roots_are_rejected_without_writes",
            "AuthorityRootTransitionPostgresTests.test_duplicate_closed_members_are_not_hidden_by_jsonb",
            "AuthorityRootTransitionPostgresTests.test_exact_payload_value_join_denies_changed_request_result_and_projection",
            "AuthorityRootTransitionPostgresTests.test_exact_plan_hash_length_and_base64_are_mandatory",
            "AuthorityRootTransitionPostgresTests.test_exact_request_persisted_byte_anchors_are_independent",
            "AuthorityRootTransitionPostgresTests.test_historical_replay_ignores_later_current_heads",
            "AuthorityRootTransitionPostgresTests.test_invalid_json_and_invalid_utf8_bytes_abort_without_writes",
            "AuthorityRootTransitionPostgresTests.test_locked_row_identity_and_snapshot_are_not_selected_by_payload",
            "AuthorityRootTransitionPostgresTests.test_metric_exponent_and_fraction_tokens_are_not_integer_aliases",
            "AuthorityRootTransitionPostgresTests.test_ninth_digest_frame_is_reserved_for_snapshot_v3",
            "AuthorityRootTransitionPostgresTests.test_old_missing_and_extra_plan_fields_are_denied",
            "AuthorityRootTransitionPostgresTests.test_persisted_tree_utf8_serializer_remains_distinct_and_does_not_normalize",
            "AuthorityRootTransitionPostgresTests.test_profile_and_metric_type_bounds_and_counts_are_closed",
            "AuthorityRootTransitionPostgresTests.test_real_shared_sql_accepts_ascii_plan_with_escaped_unicode",
            "AuthorityRootTransitionPostgresTests.test_request_and_result_canonical_spelling_is_not_replaced_by_reserialization",
            "AuthorityRootTransitionPostgresTests.test_root_descriptor_types_order_and_manifest_inventory_are_exact",
            "AuthorityRootTransitionPostgresTests.test_source_wiring_keeps_load_before_replay_and_after_guard_before_publication",
            "AuthorityRootTransitionPostgresTests.test_transition_digest_must_match_even_with_fresh_byte_digest",
            "AuthorityRootTransitionPostgresTests.test_wire_unicode_key_row_projection_and_result_domains_match_python",
        ),
        disposable_cluster=False,
        timeout_seconds=300,
    ),
    NativePostgresSuite(
        script="scripts/test_authority_primary_tree_postgres.py",
        test_ids=(
            "AuthorityPrimaryTreePostgresTests.test_actual_schema_and_empty_ladder_match_independent_genesis",
            "AuthorityPrimaryTreePostgresTests.test_batched_native_reader_matches_singletons_and_independent_cross_relation_proofs",
            "AuthorityPrimaryTreePostgresTests.test_batched_native_reader_rejects_bounded_projection_and_stale_node_revision",
            "AuthorityPrimaryTreePostgresTests.test_duplicate_insert_changes_no_rows_nodes_roots_or_history",
            "AuthorityPrimaryTreePostgresTests.test_missing_or_wrong_manifest_root_rejects_real_trigger_write_atomically",
            "AuthorityPrimaryTreePostgresTests.test_post_write_failure_rolls_back_entire_tree_and_allows_same_row_retry",
            "AuthorityPrimaryTreePostgresTests.test_real_preparation_row_insert_matches_after_root_and_preserves_outbox",
            "AuthorityPrimaryTreePostgresTests.test_real_trigger_insert_update_delete_roots_leaves_and_history",
            "AuthorityPrimaryTreePostgresTests.test_same_value_update_advances_revision_without_changing_digest_or_count",
        ),
        disposable_cluster=False,
        timeout_seconds=300,
    ),
    NativePostgresSuite(
        script="scripts/test_authority_audit_initialization_postgres.py",
        test_ids=(
            "AuditInitializationPostgresSourceTests.test_actual_adapter_owns_no_transaction_or_dml_and_closes_stream",
            "AuditInitializationPostgresTests.test_actual_nonserializable_readonly_and_idle_sessions_are_rejected",
            "AuditInitializationPostgresTests.test_actual_stream_component_preserves_oversized_identity_as_rejection",
            "AuditInitializationPostgresTests.test_adapter_leaves_transaction_and_savepoint_owned_by_caller",
            "AuditInitializationPostgresTests.test_authentic_wrong_computed_commitments_pass_preflight_but_not_real_database_recomputation",
            "AuditInitializationPostgresTests.test_authentic_wrong_purpose_source_pin_and_checkpoint_link_reject_before_sql",
            "AuditInitializationPostgresTests.test_both_bad_real_signatures_reject_before_idle_connection_runs_sql",
            "AuditInitializationPostgresTests.test_changed_context_time_and_root_inputs_reject_before_idle_database_access",
            "AuditInitializationPostgresTests.test_changed_full_row_without_tree_update_rejects_stale_membership",
            "AuditInitializationPostgresTests.test_corrupted_actual_proof_node_is_rejected",
            "AuditInitializationPostgresTests.test_crossed_expected_root_revision_digest_and_count_are_rejected",
            "AuditInitializationPostgresTests.test_empty_and_empty_after_history_both_use_actual_empty_proofs",
            "AuditInitializationPostgresTests.test_exact_empty_query_budget_includes_timeout_commands_and_eof_fetch",
            "AuditInitializationPostgresTests.test_existing_global_counter_is_not_returned_as_new_initialization",
            "AuditInitializationPostgresTests.test_extra_orphan_leaf_metadata_rejects_unchanged_committed_root",
            "AuditInitializationPostgresTests.test_full_signed_evidence_is_charged_not_only_its_smaller_preparation",
            "AuditInitializationPostgresTests.test_missing_base_row_with_retained_leaf_cannot_be_omitted",
            "AuditInitializationPostgresTests.test_missing_head_or_wrong_source_manifest_fails_closed",
            "AuditInitializationPostgresTests.test_missing_stored_leaf_rejects_present_base_row",
            "AuditInitializationPostgresTests.test_mixed_unicode_rows_match_independent_full_preparation_without_writes",
            "AuditInitializationPostgresTests.test_other_aggregate_leaves_are_preserved_by_real_absence_proof",
            "AuditInitializationPostgresTests.test_oversized_full_row_is_rejected_not_filtered_out",
            "AuditInitializationPostgresTests.test_oversized_stored_proof_text_is_rejected_before_admission",
            "AuditInitializationPostgresTests.test_owned_context_survives_controlled_caller_mutation_after_first_real_sql",
            "AuditInitializationPostgresTests.test_row_query_total_byte_and_record_budgets_fail_without_partial_success",
            "AuditInitializationPostgresTests.test_signed_claims_cannot_replace_corrupted_stored_full_row_or_proof",
            "AuditInitializationPostgresTests.test_signed_empty_snapshot_matches_independent_evidence_and_leaves_no_counter",
            "AuditInitializationPostgresTests.test_signed_mixed_unicode_and_other_aggregate_use_real_proofs_and_exact_bytes",
            "AuditInitializationPostgresTests.test_signed_retry_is_repeatable_and_caller_retains_rollback_and_cursor_ownership",
            "AuditInitializationPostgresTests.test_unindexed_outbox_row_is_not_hidden_by_leaf_join",
            "AuditInitializationPostgresTests.test_valid_signed_intent_still_requires_caller_owned_active_transaction",
        ),
        disposable_cluster=False,
        timeout_seconds=300,
    ),
    NativePostgresSuite(
        script="scripts/test_authority_audit_initialization_store_postgres.py",
        test_ids=(
            "AuditInitializationStorePostgresTests.test_actual_enrollment_lock_timeout_closes_handle_without_partial_record",
            "AuditInitializationStorePostgresTests.test_actual_metadata_corruption_rolls_back_store_and_preserves_caller_transaction",
            "AuditInitializationStorePostgresTests.test_actual_metadata_query_budget_failure_does_not_advance_store_head",
            "AuditInitializationStorePostgresTests.test_authentic_different_request_conflicts_without_replacing_committed_record",
            "AuditInitializationStorePostgresTests.test_candidate_with_reset_unused_head_cannot_be_returned_or_overwritten",
            "AuditInitializationStorePostgresTests.test_database_role_and_system_identifier_pins_are_checked_on_both_paths",
            "AuditInitializationStorePostgresTests.test_disabled_internal_foreign_key_triggers_deny_before_record_or_lookup",
            "AuditInitializationStorePostgresTests.test_effective_database_schema_table_column_and_grant_option_drift_denies",
            "AuditInitializationStorePostgresTests.test_enrollment_bytes_must_match_exact_configured_generation_and_pins",
            "AuditInitializationStorePostgresTests.test_exact_historical_lookup_does_not_relabel_retained_source_revision",
            "AuditInitializationStorePostgresTests.test_exact_record_replay_retains_original_bytes_after_metadata_evolution",
            "AuditInitializationStorePostgresTests.test_existing_unused_enrollment_lookup_returns_none_without_manufacturing_candidate",
            "AuditInitializationStorePostgresTests.test_expired_request_cannot_record_but_exact_lookup_retains_original_record",
            "AuditInitializationStorePostgresTests.test_external_composite_typed_table_cannot_substitute_for_source_relation",
            "AuditInitializationStorePostgresTests.test_extra_index_rls_and_relation_owner_drift_are_not_silent_repairs",
            "AuditInitializationStorePostgresTests.test_head_claim_without_candidate_is_not_an_unused_enrollment",
            "AuditInitializationStorePostgresTests.test_invalid_real_signatures_leave_store_idle_and_rows_unchanged",
            "AuditInitializationStorePostgresTests.test_missing_enrollment_fails_closed_without_automatic_enrollment",
            "AuditInitializationStorePostgresTests.test_owner_and_runtime_flags_and_membership_both_directions_deny",
            "AuditInitializationStorePostgresTests.test_public_and_redundant_column_reads_fail_raw_acl_closure_only",
            "AuditInitializationStorePostgresTests.test_real_record_commit_reopen_returns_exact_original_candidate_bytes",
            "AuditInitializationStorePostgresTests.test_real_sql_head_failure_rolls_back_candidate_then_allows_exact_retry",
            "AuditInitializationStorePostgresTests.test_replaced_foreign_key_internal_delete_action_is_not_source_equivalent",
            "AuditInitializationStorePostgresTests.test_retained_candidate_byte_corruption_is_not_accepted_as_exact_replay",
            "AuditInitializationStorePostgresTests.test_runtime_login_and_exact_owner_grants_are_real_catalog_state",
            "AuditInitializationStorePostgresTests.test_source_check_expression_missing_and_unvalidated_constraint_drift_denies",
            "AuditInitializationStorePostgresTests.test_store_connection_requires_idle_non_autocommit_and_separate_metadata_session",
            "AuditInitializationStorePostgresTests.test_store_limits_reject_non_integer_unbounded_and_zero_values",
            "AuditInitializationStorePostgresTests.test_superuser_connection_and_missing_required_runtime_select_cannot_bypass_admission",
            "AuditInitializationStoreSourceTests.test_source_preflight_owned_transaction_commit_and_fixed_consumers_are_bound",
            "LocalInitializationRepresentationTests.test_constructor_bypassed_incomplete_or_mutable_pins_are_revalidated",
            "LocalInitializationRepresentationTests.test_database_identity_copy_owns_inputs_and_public_lookup_revalidates_bypassed_contexts",
            "LocalInitializationRepresentationTests.test_database_identity_requires_exact_bounded_types_and_separate_roles",
            "LocalInitializationRepresentationTests.test_enrollment_owns_frozen_copies_of_original_trust_and_both_pins",
            "LocalInitializationRepresentationTests.test_local_candidate_state_is_closed_frozen_and_never_installation_permission",
            "LocalInitializationRepresentationTests.test_lossy_or_forbidden_json_and_raw_bounds_raise_public_store_error",
        ),
        disposable_cluster=True,
        timeout_seconds=900,
    ),
    NativePostgresSuite(
        script="scripts/test_authority_global_audit_capacity_postgres.py",
        test_ids=(
            "AuthorityGlobalAuditCapacityPostgresTests.test_all_existing_status_pairs_and_same_value_updates",
            "AuthorityGlobalAuditCapacityPostgresTests.test_capacity_underflow_and_overflow_reject",
            "AuthorityGlobalAuditCapacityPostgresTests.test_compact_byte_ceiling_applies_to_complete_row",
            "AuthorityGlobalAuditCapacityPostgresTests.test_counter_integers_never_accept_boolean_string_or_fraction",
            "AuthorityGlobalAuditCapacityPostgresTests.test_delete_arithmetic_does_not_create_an_unavailable_source_template",
            "AuthorityGlobalAuditCapacityPostgresTests.test_empty_replay_requires_valid_selected_counter_and_no_counter_mutation",
            "AuthorityGlobalAuditCapacityPostgresTests.test_exact_keys_digests_missing_and_duplicate_selected_identities",
            "AuthorityGlobalAuditCapacityPostgresTests.test_insert_status_and_invalid_old_or_new_status_reject",
            "AuthorityGlobalAuditCapacityPostgresTests.test_installed_signature_invoker_mode_and_source_identity",
            "AuthorityGlobalAuditCapacityPostgresTests.test_missing_duplicate_and_coherently_altered_counter_mutations",
            "AuthorityGlobalAuditCapacityPostgresTests.test_mixed_net_zero_batch_still_advances_insert_sequence",
            "AuthorityGlobalAuditCapacityPostgresTests.test_mutation_closure_cas_template_and_key_movement",
            "AuthorityGlobalAuditCapacityPostgresTests.test_nonparticipant_and_unrelated_mutations_are_not_global_audit_work",
            "AuthorityGlobalAuditCapacityPostgresTests.test_one_and_seven_inserts_match_independent_rows_and_real_producer",
            "AuthorityGlobalAuditCapacityPostgresTests.test_operation_inventory_caps_are_enforced_before_duplicate_walk",
            "AuthorityGlobalAuditCapacityPostgresTests.test_participating_operation_keeps_unrelated_aggregate_changes_separate",
            "AuthorityGlobalAuditCapacityPostgresTests.test_required_work_charges_actual_framework_and_preserves_business_ceiling",
            "AuthorityGlobalAuditCapacityPostgresTests.test_revision_and_insert_sequence_bigint_overflow_reject",
            "AuthorityGlobalAuditCapacityPostgresTests.test_selected_presence_null_and_closed_field_types",
            "AuthorityGlobalAuditCapacityPostgresTests.test_self_consistent_alternative_counter_profiles_reject",
            "AuthorityGlobalAuditCapacityPostgresTests.test_sql_null_inputs_reject_and_jsonb_is_not_raw_token_admission",
            "AuthorityGlobalAuditCapacityPostgresTests.test_state_bytes_and_hash_are_both_exact",
            "AuthorityGlobalAuditCapacityPostgresTests.test_time_is_monotonic_input_not_an_authenticated_clock",
            "AuthorityGlobalAuditCapacityPostgresTests.test_unicode_outbox_id_byte_boundary_and_wire_digest_parity",
            "AuthorityGlobalAuditCapacityPostgresTests.test_work_token_types_and_bigint_coercion_are_separate_boundaries",
        ),
        disposable_cluster=False,
        timeout_seconds=300,
    ),
    NativePostgresSuite(
        script="scripts/test_authority_verifier_read_postgres.py",
        test_ids=(
            "AuthorityVerifierReadPostgresTests.test_all_column_select_is_not_full_table_select",
            "AuthorityVerifierReadPostgresTests.test_all_three_sequence_privileges_deny",
            "AuthorityVerifierReadPostgresTests.test_column_only_writes_deny",
            "AuthorityVerifierReadPostgresTests.test_database_create_and_temporary_deny",
            "AuthorityVerifierReadPostgresTests.test_each_missing_required_table_denies",
            "AuthorityVerifierReadPostgresTests.test_exact_four_table_positive",
            "AuthorityVerifierReadPostgresTests.test_extra_column_only_select_denies",
            "AuthorityVerifierReadPostgresTests.test_extra_table_and_view_select_denies",
            "AuthorityVerifierReadPostgresTests.test_function_execute_denies",
            "AuthorityVerifierReadPostgresTests.test_membership_in_either_direction_denies",
            "AuthorityVerifierReadPostgresTests.test_missing_role_or_namespace_denies",
            "AuthorityVerifierReadPostgresTests.test_public_allowed_table_select_still_denies",
            "AuthorityVerifierReadPostgresTests.test_public_column_select_and_write_deny",
            "AuthorityVerifierReadPostgresTests.test_public_function_execute_denies",
            "AuthorityVerifierReadPostgresTests.test_public_schema_usage_and_create_deny",
            "AuthorityVerifierReadPostgresTests.test_public_sequence_privileges_deny",
            "AuthorityVerifierReadPostgresTests.test_required_name_cannot_be_a_view",
            "AuthorityVerifierReadPostgresTests.test_role_login_and_each_elevated_flag_deny",
            "AuthorityVerifierReadPostgresTests.test_schema_create_and_missing_usage_deny",
            "AuthorityVerifierReadPostgresTests.test_table_column_and_schema_grant_options_deny",
            "AuthorityVerifierReadPostgresTests.test_table_writes_deny",
        ),
        disposable_cluster=True,
        timeout_seconds=300,
    ),
    NativePostgresSuite(
        script="scripts/test_authority_wire_json_postgres.py",
        test_ids=(
            "AuthorityWireJsonPostgresTests.test_ascii_controls_del_quote_backslash_and_slash_match_python",
            "AuthorityWireJsonPostgresTests.test_bmp_astral_edges_and_surrogate_pair_input_are_exact",
            "AuthorityWireJsonPostgresTests.test_existing_tree_json_remains_utf8_while_wire_and_domain_digest_match_python",
            "AuthorityWireJsonPostgresTests.test_fixed_profiles_cannot_be_increased_by_direct_helper_call",
            "AuthorityWireJsonPostgresTests.test_fractional_and_scale_bearing_jsonb_numbers_are_denied",
            "AuthorityWireJsonPostgresTests.test_installed_helper_inventory_modes_and_renderer_namespace_are_closed",
            "AuthorityWireJsonPostgresTests.test_jsonb_numeric_token_normalization_is_not_raw_integer_admission",
            "AuthorityWireJsonPostgresTests.test_jsonb_rejects_nul_unpaired_surrogates_and_invalid_utf8_before_serializer",
            "AuthorityWireJsonPostgresTests.test_nested_lossless_values_preserve_types_and_compact_separators",
            "AuthorityWireJsonPostgresTests.test_object_keys_sort_by_scalar_not_utf16_locale_or_jsonb_storage_order",
            "AuthorityWireJsonPostgresTests.test_primitives_and_exact_integers_beyond_machine_word_ranges",
            "AuthorityWireJsonPostgresTests.test_public_entry_checks_exact_depth_boundary",
            "AuthorityWireJsonPostgresTests.test_recursive_node_key_depth_and_byte_budgets_do_not_reset_per_child",
            "AuthorityWireJsonPostgresTests.test_string_byte_measurement_checks_both_exact_boundary_and_escape_expansion",
        ),
        disposable_cluster=False,
        timeout_seconds=300,
    ),
)


# The order is the closed batch order, not lexical filename order. The booleans
# encode an extra fixture CLI acknowledgement; False never permits a real or
# shared database. All ten suites require a prepared disposable local cluster.
_SUITE_SHAPES = (
    ("scripts/test_webauthn_trust_projection_postgres.py", 8, False, 300),
    ("scripts/test_postgres_trigger_manifest.py", 5, False, 300),
    ("scripts/test_authority_mutation_postgres.py", 14, False, 300),
    ("scripts/test_authority_root_transition_postgres.py", 21, False, 300),
    ("scripts/test_authority_primary_tree_postgres.py", 9, False, 300),
    ("scripts/test_authority_audit_initialization_postgres.py", 31, False, 300),
    ("scripts/test_authority_audit_initialization_store_postgres.py", 36, True, 900),
    ("scripts/test_authority_global_audit_capacity_postgres.py", 25, False, 300),
    ("scripts/test_authority_verifier_read_postgres.py", 21, True, 300),
    ("scripts/test_authority_wire_json_postgres.py", 14, False, 300),
)
_TEST_ID = re.compile(r"[A-Za-z][A-Za-z0-9_]*\.test_[a-z][a-z0-9_]*", re.ASCII)


def validate_inventory() -> None:
    """Validate this source-owned inventory, without loading or running tests.

    This checks shape and internal consistency only. Actual fixture discovery,
    source digest binding and complete observed results are separate checks.
    """
    if (type(INVENTORY_SCHEMA) is not str or INVENTORY_SCHEMA != "serverware.nativePostgresInventory/v1"
            or type(SUITES) is not tuple or len(SUITES) != 10
            or type(TOTAL_TESTS) is not int or TOTAL_TESTS != 184):
        raise ValueError("native PostgreSQL inventory envelope differs from source")
    seen_scripts: set[str] = set()
    seen_tests: set[str] = set()
    total = 0
    for suite, (script, count, disposable, timeout) in zip(SUITES, _SUITE_SHAPES):
        if (type(suite) is not NativePostgresSuite
                or type(suite.script) is not str or suite.script != script
                or suite.script in seen_scripts
                or type(suite.test_ids) is not tuple or len(suite.test_ids) != count
                or type(suite.disposable_cluster) is not bool or suite.disposable_cluster is not disposable
                or type(suite.timeout_seconds) is not int or suite.timeout_seconds != timeout):
            raise ValueError("native PostgreSQL suite differs from its fixed source shape")
        seen_scripts.add(suite.script)
        previous = ""
        for test_id in suite.test_ids:
            if (type(test_id) is not str or not 1 <= len(test_id) <= 256
                    or _TEST_ID.fullmatch(test_id) is None
                    or test_id <= previous or test_id in seen_tests):
                raise ValueError("native PostgreSQL test identities are invalid, duplicated or unsorted")
            previous = test_id
            seen_tests.add(test_id)
            total += 1
    if total != TOTAL_TESTS:
        raise ValueError("native PostgreSQL test total differs from source")
