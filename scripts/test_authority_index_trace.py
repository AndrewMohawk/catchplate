#!/usr/bin/env python3
"""Exact hash-free read-marker admission, not enabled planner authority.

Literal markers are independent of the production validator. Real producer
interop uses deterministic SQL responders, not PostgreSQL or successful proof
substitutes. This authored suite establishes no live schema, current roots,
interval completeness, public v3 admission or additional trace allowance.
"""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import sys
from types import MappingProxyType
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_complete_query as complete
from serverware import authority_index_heads as heads
from serverware import authority_index_reader as reader
from serverware import authority_index_trace as trace_contract
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork
import test_authority_index_frontier as frontier_oracle
import test_authority_index_heads as head_oracle


OPERATION = "webauthn.credential.revoke"
HEAD_TABLE = "policy_authority_counted_index_heads"
LEAF_TABLE = "policy_authority_counted_index_leaves"
NODE_TABLE = "policy_authority_counted_index_nodes"
HEAD_PROFILE = "serverware.policyAuthorityCountedHeadRead/v1"
RANGE_PROFILE = "serverware.policyAuthorityCountedIndexRead/v1"
PRIMARY_PROFILE = "serverware.policyAuthorityCompletePrimaryRead/v1"
DIGEST = "sha256:" + "a" * 64
ROLES = (
    ("sessions_pending_webauthn", "oidc_browser_sessions", "webauthn_session_credential_status"),
    ("sessions_active", "oidc_browser_sessions", "webauthn_session_credential_status"),
    ("grants", "approval_grants", "webauthn_grant_approver_active"),
    ("approvals", "control_plane_approvals", "webauthn_control_approval_approved"),
    ("global_registration_challenges", "webauthn_challenges", "webauthn_registration_unused_global"),
)
HEAD_IDS = tuple(sorted((
    "webauthn_credential_id", "webauthn_credential_user_history", "webauthn_credential_live_trust",
    "webauthn_registration_unused_global", "webauthn_registration_unused_user",
    "webauthn_session_credential_status", "webauthn_grant_approver_active",
    "webauthn_control_approval_approved",
)))


def head_marker():
    return {"profile": HEAD_PROFILE, "indexIds": list(HEAD_IDS), "rowLimit": 9}


def context(role=ROLES[2]):
    name, table, index_id = role
    return {"profile": RANGE_PROFILE,
        "queryId": f"serverware.policyAuthorityQuery/{OPERATION}/{name}/{table}/v1",
        "indexId": index_id, "projectionDigest": DIGEST,
        "indexRevision": 17, "rootDigest": "sha256:" + "b" * 64, "rootCount": 2}


def leaf_marker(role=ROLES[2]):
    return {**context(role), "lower": "1" * 160, "upper": "2" * 160, "limit": 3}


def node_marker(role=ROLES[2]):
    return {**context(role), "prefixes": [{"depth": 1, "pathPrefix": "0"},
            {"depth": 2, "pathPrefix": "af"}], "limit": 3}


def primary_marker(role=ROLES[2]):
    value = context(role)
    return {"profile": PRIMARY_PROFILE, "queryId": value["queryId"], "indexId": value["indexId"],
            "primaryId": "member-雪", "primaryKeyDigest": DIGEST, "limit": 2}


class ValidationTrace:
    """Real producer trace sink, not a PlannerTrace admission substitute."""
    def __init__(self):
        self.operation, self.entries = OPERATION, []

    def read(self, table, key):
        # Producer hashing outside this callback remains genuine. Validation
        # itself must not reconstruct a profile, interval or source digest.
        with mock.patch.object(hashlib, "sha256", side_effect=AssertionError("trace hashed")):
            trace_contract.validate_complete_read_trace(self.operation, table, key)
        self.entries.append((table, copy.deepcopy(key)))


class AuthorityIndexTraceTests(unittest.TestCase):
    def check(self, table, key):
        return trace_contract.validate_complete_read_trace(OPERATION, table, key)

    def reject(self, table, key):
        with self.assertRaises(trace_contract.IndexTraceError):
            self.check(table, key)

    def test_all_five_source_roles_and_head_union_validate_without_any_hash(self):
        with mock.patch.object(hashlib, "sha256", side_effect=AssertionError("trace hashed")):
            self.assertIsNone(self.check(HEAD_TABLE, head_marker()))
            for role in ROLES:
                with self.subTest(role=role[0]):
                    self.assertIsNone(self.check(LEAF_TABLE, leaf_marker(role)))
                    self.assertIsNone(self.check(NODE_TABLE, node_marker(role)))
                    self.assertIsNone(self.check(role[1], primary_marker(role)))
        self.assertEqual(trace_contract.PRIMARY_READ_PROFILE, PRIMARY_PROFILE)

    def test_literal_query_identities_match_actual_source_declarations_without_role_recipe_copy(self):
        arguments = {"record_id": "credential-雪", "source": "explicit", "oidc_session_ids": [],
            "approval_grant_ids": [], "control_plane_approval_ids": [], "registration_challenge_ids": []}
        for role in ROLES:
            query = complete.bind_query(OPERATION, role[0], arguments=arguments, cutoff_us=1)
            self.assertEqual((query.query_id, query.table, query.index_id),
                             (context(role)["queryId"], role[1], role[2]))
            self.check(LEAF_TABLE, leaf_marker(role))

    def test_actual_head_and_range_producers_emit_only_admitted_markers(self):
        head_cursor, head_trace = head_oracle.Cursor(head_oracle.source_rows()), ValidationTrace()
        work = _ValidationWork(QueryReadValidationLimits())
        acquisition = reader._ReadAcquisitionBudget(head_cursor, head_trace, work=work)
        observed = heads.read_operation_index_heads(head_cursor, operation=OPERATION,
            trace=head_trace, work=work, acquisition=acquisition)
        self.assertEqual(tuple(item.index_id for item in observed), HEAD_IDS)
        self.assertEqual(head_trace.entries, [(HEAD_TABLE, head_marker())])
        rows = [{"id": "member-雪", "approver_webauthn_credential_id": "credential-雪", "state": "active"},
                {"id": "outside", "approver_webauthn_credential_id": "other", "state": "active"}]
        store = frontier_oracle.IndependentStoredIndex(rows)
        cursor, trace = frontier_oracle.StoredIndexCursor(store), ValidationTrace()
        result = reader.read_complete_frontier(cursor, query=store.query, expected_root=store.tree.root,
            index_revision=store.revision, trace=trace)
        self.assertEqual(result.root, store.tree.root)
        self.assertEqual(len(trace.entries), len(cursor.calls))
        self.assertEqual(trace.entries[0][0], LEAF_TABLE)
        self.assertTrue(all(table == NODE_TABLE for table, _ in trace.entries[1:]))

    def test_operation_and_table_admission_is_exact_and_never_generic_metadata_access(self):
        class Text(str):
            pass
        for operation in (None, True, "jit.consume", "webauthn.trust.stage", Text(OPERATION)):
            with self.subTest(operation=operation), self.assertRaises(trace_contract.IndexTraceError):
                trace_contract.validate_complete_read_trace(operation, HEAD_TABLE, head_marker())
        for table in (None, True, "", "x" * 129, Text(LEAF_TABLE),
                      "policy_authority_roots", "policy_authority_counted_index_other", "webauthn_credentials"):
            self.reject(table, leaf_marker())
        for table in (HEAD_TABLE, LEAF_TABLE, NODE_TABLE):
            self.reject(table, None)
            self.reject(table, {"id": "ordinary-key"})

    def test_all_outer_marker_objects_are_closed_and_require_exact_json_types(self):
        class Object(dict):
            pass
        class Text(str):
            pass
        for table, good in ((HEAD_TABLE, head_marker()), (LEAF_TABLE, leaf_marker()),
                            (NODE_TABLE, node_marker()), (ROLES[2][1], primary_marker())):
            missing = dict(good)
            missing.pop("profile")
            renamed = dict(good)
            profile = renamed.pop("profile")
            renamed[Text("profile")] = profile
            for bad in (missing, {**good, "extra": 1}, list(good), Object(good),
                        MappingProxyType(good), renamed, {**good, "profile": Text(good["profile"])}):
                with self.subTest(table=table, shape=type(bad)):
                    self.reject(table, bad)

    def test_head_inventory_delegates_real_hash_free_guard_and_retains_exact_union(self):
        original = heads.validate_head_trace_key
        with mock.patch.object(heads, "validate_head_trace_key", wraps=original) as actual:
            self.check(HEAD_TABLE, head_marker())
        self.assertEqual(actual.call_count, 1)
        self.assertEqual(actual.call_args.args, (OPERATION, head_marker()))
        for ids in (list(HEAD_IDS[:-1]), list(reversed(HEAD_IDS)), list(HEAD_IDS) + [HEAD_IDS[0]],
                    [HEAD_IDS[0], *HEAD_IDS[:-1]], tuple(HEAD_IDS),
                    [*HEAD_IDS[:-1], "webauthn_publication_status"]):
            self.reject(HEAD_TABLE, {**head_marker(), "indexIds": ids})
        for limit in (True, 8, 10, "9"):
            self.reject(HEAD_TABLE, {**head_marker(), "rowLimit": limit})

    def test_query_and_index_identities_cannot_cross_source_roles_or_tables(self):
        for role in ROLES:
            good = leaf_marker(role)
            wrong_table = good["queryId"].replace(role[1], "webauthn_credentials")
            for key in ({**good, "queryId": wrong_table}, {**good, "queryId": good["queryId"] + "/extra"},
                        {**good, "queryId": True}, {**good, "indexId": "webauthn_credential_id"},
                        {**good, "indexId": "x" * 129}, {**good, "profile": PRIMARY_PROFILE}):
                self.reject(LEAF_TABLE, key)
            self.reject("webauthn_credentials", primary_marker(role))
        # Both session roles genuinely share one index; this is not a duplicate
        # query-ID exemption for any role outside the fixed source declarations.
        self.assertEqual(context(ROLES[0])["indexId"], context(ROLES[1])["indexId"])
        self.assertNotEqual(context(ROLES[0])["queryId"], context(ROLES[1])["queryId"])

    def test_context_digests_have_canonical_shape_without_claiming_source_commitment_binding(self):
        for field in ("projectionDigest", "rootDigest"):
            for value in (None, 1, "sha256:" + "A" * 64, "sha256:" + "g" * 64,
                          "sha256:" + "a" * 63, "sha256:" + "a" * 65, "sha256:" + "a" * 63 + "\x00"):
                self.reject(LEAF_TABLE, {**leaf_marker(), field: value})
            # Hash-free shape admission cannot authenticate these arbitrary
            # commitments; real producer context and reconstruction still must.
            self.check(LEAF_TABLE, {**leaf_marker(), field: "sha256:" + "0" * 64})

    def test_range_revision_and_count_are_nonnegative_exact_int64_with_empty_genesis_shape(self):
        for field in ("indexRevision", "rootCount"):
            for value in (-1, 2**63, True, 1.0, "1", None):
                self.reject(NODE_TABLE, {**node_marker(), field: value})
        self.check(LEAF_TABLE, {**leaf_marker(), "indexRevision": 0, "rootCount": 0})
        self.check(LEAF_TABLE, {**leaf_marker(), "indexRevision": 2**63 - 1, "rootCount": 2**63 - 1})
        self.reject(LEAF_TABLE, {**leaf_marker(), "indexRevision": 0, "rootCount": 1})

    def test_leaf_bounds_are_exact_hex_intervals_and_source_sentinel_limits(self):
        for upper in (None, "1" * 160, "f" * 160):
            for limit in (2, 33):
                self.check(LEAF_TABLE, {**leaf_marker(), "upper": upper, "limit": limit})
        for field in ("lower", "upper"):
            for value in (True, 0, "a" * 159, "a" * 161, "A" * 160, "g" * 160):
                self.reject(LEAF_TABLE, {**leaf_marker(), field: value})
        self.reject(LEAF_TABLE, {**leaf_marker(), "lower": None})
        self.reject(LEAF_TABLE, {**leaf_marker(), "upper": "0" * 160})
        for limit in (True, 1, 34, 2.0, "2"):
            self.reject(LEAF_TABLE, {**leaf_marker(), "limit": limit})

    def test_node_batch_inventory_uses_exact_256_maximum_and_n_plus_one_sentinel(self):
        prefixes = [{"depth": 2, "pathPrefix": f"{value:02x}"} for value in range(256)]
        self.check(NODE_TABLE, {**node_marker(), "prefixes": prefixes, "limit": 257})
        self.check(NODE_TABLE, {**node_marker(), "prefixes": [{"depth": 160, "pathPrefix": "f" * 160}], "limit": 2})
        for values in ([], tuple(prefixes), prefixes + [{"depth": 3, "pathPrefix": "fff"}]):
            self.reject(NODE_TABLE, {**node_marker(), "prefixes": values, "limit": len(values) + 1})
        for limit in (True, 2, 4, 3.0, "3"):
            self.reject(NODE_TABLE, {**node_marker(), "limit": limit})

    def test_node_prefixes_are_closed_exact_depth_matched_sorted_unique_values(self):
        variants = (
            [{"depth": 1, "pathPrefix": "0", "extra": 1}], [{"depth": 1}],
            [{"depth": True, "pathPrefix": "0"}], [{"depth": 0, "pathPrefix": ""}],
            [{"depth": 161, "pathPrefix": "f" * 161}], [{"depth": 2, "pathPrefix": "f"}],
            [{"depth": 1, "pathPrefix": "A"}], [{"depth": 1, "pathPrefix": None}],
            [{"depth": 1, "pathPrefix": "0"}] * 2,
            [{"depth": 1, "pathPrefix": "b"}, {"depth": 2, "pathPrefix": "af"}],
        )
        for prefixes in variants:
            self.reject(NODE_TABLE, {**node_marker(), "prefixes": prefixes, "limit": len(prefixes) + 1})

    def test_primary_lookup_id_obeys_actual_lossless_utf8_4096_byte_codec(self):
        class Text(str):
            pass
        for identifier in ("", "a" * 4096, "雪" * 1365 + "a", "😀" * 1024):
            self.check(ROLES[2][1], {**primary_marker(), "primaryId": identifier})
        for identifier in (None, 1, True, Text("id"), "a" * 4097, "雪" * 1365 + "ab",
                           "😀" * 1024 + "a", "nul\x00id", "\ud800", "\udfff"):
            self.reject(ROLES[2][1], {**primary_marker(), "primaryId": identifier})

    def test_primary_marker_has_exact_digest_sentinel_role_and_no_range_or_mutation_access(self):
        good = primary_marker()
        for field, value in (("primaryKeyDigest", "sha256:" + "F" * 64), ("primaryKeyDigest", None),
                             ("limit", True), ("limit", 1), ("limit", 3),
                             ("profile", RANGE_PROFILE), ("indexId", ROLES[3][2])):
            self.reject(ROLES[2][1], {**good, field: value})
        for field, value in (("where", "1=1"), ("operation", "UPDATE"), ("row", {}), ("lower", "0" * 160)):
            self.reject(ROLES[2][1], {**good, field: value})
        self.reject(LEAF_TABLE, good)
        self.reject(NODE_TABLE, good)
        self.reject(HEAD_TABLE, good)

    def test_validation_does_not_mutate_inputs_mint_tokens_or_accept_unknown_options(self):
        markers = ((HEAD_TABLE, head_marker()), (LEAF_TABLE, leaf_marker()),
                   (NODE_TABLE, node_marker()), (ROLES[2][1], primary_marker()))
        expected = copy.deepcopy(markers)
        with mock.patch.object(hashlib, "sha256", side_effect=AssertionError("trace hashed")):
            for table, key in markers:
                self.assertIsNone(self.check(table, key))
                self.assertIsNone(self.check(table, key))
                self.reject(table, {**key, "proof": "caller-success"})
        self.assertEqual(markers, expected)
        with self.assertRaises(TypeError):
            trace_contract.validate_complete_read_trace(OPERATION, LEAF_TABLE, leaf_marker(), verified=True)


if __name__ == "__main__":
    unittest.main()
