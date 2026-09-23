#!/usr/bin/env python3
"""Operation-bound read batches over independent primary and counted trees.

The real global membership engine and all five real range/primary joins run
against independent tree encodings. No prior observation token, successful
verifier, SQL connection, registry or current-root authority is substituted.
These authored, unrun controls do not establish an admitted clock, maintained
index population, complete ordinary QueryReads, audit capacity, writer effects,
Snapshot transport, kernel activation or independent checkpoint currentness.
"""
from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_audit_capacity as capacity
from serverware import authority_complete_query as complete
from serverware import authority_complete_query_batch as batch
from serverware import authority_contract
from serverware import authority_index_contract as counted
from serverware import authority_index_join as joined
from serverware import authority_index_projection as projection
from serverware import authority_primary_contract as primary_contract
from serverware import authority_radix_mutation as primary
import test_authority_complete_query as declaration_oracle
import test_authority_index_join as join_oracle
import test_authority_index_range as range_oracle
import test_authority_radix_mutation as primary_oracle


OPERATION = "webauthn.credential.revoke"
CUTOFF_US = 1_000_007
ROLES = ("sessions_pending_webauthn", "sessions_active", "grants", "approvals",
         "global_registration_challenges")
READ_INDEX_IDS = tuple(sorted(("webauthn_session_credential_status",
    "webauthn_grant_approver_active", "webauthn_control_approval_approved",
    "webauthn_registration_unused_global")))
ALL_INDEX_IDS = ("webauthn_credential_id", "webauthn_credential_user_history", "webauthn_credential_live_trust",
    "webauthn_registration_unused_global", "webauthn_registration_unused_user",
    "webauthn_session_credential_status", "webauthn_grant_approver_active", "webauthn_control_approval_approved",
    "webauthn_publication_bundle_digest", "webauthn_publication_status", "webauthn_publication_generation")


def values(value):
    return {field.name: getattr(value, field.name) for field in fields(value)}


def forged(value, **changes):
    result = object.__new__(type(value))
    for field in fields(value):
        object.__setattr__(result, field.name, changes.get(field.name, getattr(value, field.name)))
    return result


def session(identifier, status, credential="credential-雪"):
    return {"id": identifier, "bound_webauthn_credential_id": credential, "status": status,
            "metadata": {"note": "full row 雪", "flags": [True, None]}}


def default_rows(*, approval=False):
    return {
        "webauthn_credentials": [{"id": "credential-雪", "credential_id": "public-key",
                                  "user_id": "user", "sign_count": 3}],
        "oidc_browser_sessions": [session("pending", "pending_webauthn"),
            session("active", "active"), session("unrelated", "active", "other")],
        "approval_grants": [
            {"id": "grant", "approver_webauthn_credential_id": "credential-雪", "state": "active"},
            {"id": "inactive", "approver_webauthn_credential_id": "credential-雪", "state": "consumed"}],
        "control_plane_approvals": [{"id": "approval", "approver_webauthn_credential_id": "credential-雪",
                                    "status": "approved" if approval else "denied"}],
        "webauthn_challenges": [
            {"id": "future", "challenge_type": "registration", "used_at": None,
             "expires_at": "1970-01-01T00:00:02+00:00", "user_id": "user"},
            {"id": "past", "challenge_type": "registration", "used_at": None,
             "expires_at": "1970-01-01T00:00:01+00:00", "user_id": "other"},
            {"id": "used", "challenge_type": "registration", "used_at": "used",
             "expires_at": "1970-01-01T00:00:03+00:00", "user_id": "user"}],
    }


class BatchFixture:
    """One global population; per-query oracles independently share its roots."""

    def __init__(self, rows=None, *, arguments=None, cutoff_us=CUTOFF_US, extra_keys=()):
        self.rows = copy.deepcopy(default_rows() if rows is None else rows)
        self.intent = copy.deepcopy(declaration_oracle.arguments() if arguments is None else arguments)
        self.cutoff_us = cutoff_us
        self.contracts = primary_contract.primary_table_contracts(OPERATION)
        self.trees = {item.table: primary_oracle.IndependentTree(self.rows.get(item.table, []),
            table=item.table, columns=item.key_columns, revision=17) for item in self.contracts}
        self.queries = tuple(complete.bind_query(OPERATION, role, arguments=self.intent,
                                               cutoff_us=cutoff_us) for role in ROLES)
        self.joins = {}
        for role, table, index_id, _ in declaration_oracle.ROLE_SPECS:
            self.joins[role] = join_oracle.JoinFixture(self.rows.get(table, []), index_id=index_id,
                selector=declaration_oracle.selector_for(role, record_id=self.intent["record_id"],
                                                        cutoff_us=cutoff_us),
                expiry_us={"past": 1_000_000, "future": 2_000_000, "used": 3_000_000},
                primary_revision=17, index_revision=29)
            if self.joins[role].primary.root != self.trees[table].root:
                raise AssertionError("independent per-query and global primary populations differ")
        selected = {}
        for info in self.joins.values():
            for item in info.selected:
                selected[(item["table"], item["keyDigest"])] = item
        point_keys = (("webauthn_credentials", {"id": self.intent["record_id"]}),
                      ("metadata_audit_outbox", {"id": "absent-point"}), *extra_keys)
        for table, key in point_keys:
            item = self.trees[table].selected(key)
            selected[(table, item["keyDigest"])] = item
        self.selected = tuple(selected[key] for key in sorted(selected))
        self.proofs = tuple(self.trees[item["table"]].proof(item) for item in self.selected)

    def arguments(self):
        indexes = {info.profile.index_id: info for info in self.joins.values()}
        return {
            "operation": OPERATION, "arguments": copy.deepcopy(self.intent), "cutoff_us": self.cutoff_us,
            "queries": copy.deepcopy(self.queries),
            "business_before_roots": [self.trees[item.table].root.json_projection()
                                      for item in self.contracts if item.root_class == "business"],
            "authorization_before_roots": [self.trees[item.table].root.json_projection()
                                           for item in self.contracts if item.root_class == "authorization"],
            "selected_rows": copy.deepcopy(self.selected), "before_proofs": copy.deepcopy(self.proofs),
            "read_heads": tuple(batch.CompleteQueryHead(index_id, 29, copy.deepcopy(indexes[index_id].index.root))
                                for index_id in READ_INDEX_IDS),
            "query_frontiers": tuple(batch.CompleteQueryFrontier(query.query_id,
                copy.deepcopy(self.joins[query.role].frontier)) for query in self.queries),
        }

    def primary_document(self):
        return {
            "contracts": [{"table": item.table, "keyColumns": list(item.key_columns),
                "writeAccess": item.write_access, "rootClass": item.root_class} for item in self.contracts],
            "businessRoots": [self.trees[item.table].root.json_projection()
                              for item in self.contracts if item.root_class == "business"],
            "authorizationRoots": [self.trees[item.table].root.json_projection()
                                   for item in self.contracts if item.root_class == "authorization"],
            "selected": list(self.selected), "proofs": list(self.proofs), "mutations": [],
        }

    def primary_metrics(self):
        document = self.primary_document()
        count = len(self.selected)
        return {"selected_rows": count, "mutations": 0, "proof_vectors": count * 64,
            "proof_child_slots": count * 1024, "recomputed_ancestors": 0,
            "hash_work": 66 + sum(70 if row["present"] else 68 for row in self.selected),
            "input_bytes": len(primary_oracle.wire_json(document)),
            "json_nodes": join_oracle.graph_nodes(document)}

    def ownership_document(self):
        """Literal normalized input framing, independent of the production copier."""
        inputs = self.arguments()
        frontiers = []
        for query in self.queries:
            records = []
            for item in self.joins[query.role].frontier:
                if type(item) is counted.IndexLeaf:
                    records.append({"kind": "leaf", "key": item.key,
                        "primaryKeyDigest": item.primary_key_digest, "primaryRowDigest": item.primary_row_digest})
                else:
                    records.append({"kind": "opaque", "prefix": item.prefix,
                                    "digest": item.digest, "count": item.count})
            frontiers.append({"queryId": query.query_id, "frontier": records})
        return {
            "operation": OPERATION, "arguments": self.intent, "cutoffUs": self.cutoff_us,
            "queries": [{"operation": OPERATION, "role": role,
                "selectorItems": [list(pair) for pair in sorted(declaration_oracle.selector_for(
                    role, record_id=self.intent["record_id"], cutoff_us=self.cutoff_us).items())],
                "maximumRows": max(1, len(self.intent[hint]))}
                for role, _, _, hint in declaration_oracle.ROLE_SPECS],
            "businessBeforeRoots": inputs["business_before_roots"],
            "authorizationBeforeRoots": inputs["authorization_before_roots"],
            "selectedRows": list(self.selected), "beforeProofs": list(self.proofs),
            "readHeads": [{"indexId": item.index_id, "indexRevision": item.index_revision,
                           "rootDigest": item.index_root.digest, "leafCount": item.index_root.count}
                          for item in inputs["read_heads"]],
            "queryFrontiers": frontiers,
        }

    def join_metrics(self, role):
        info = self.joins[role]
        selected_map = {item["keyDigest"]: item for item in info.selected}
        members = tuple(selected_map[leaf.primary_key_digest] for leaf in info.index.matches(info.interval))
        proof_map = {item["keyDigest"]: item for item in info.proofs}
        proofs = tuple(proof_map[item["keyDigest"]] for item in members)
        primary_values = join_oracle.primary_metrics(info.primary, members, proofs)
        index_values = range_oracle.metric_oracle(info.profile, info.index.root, info.interval, info.frontier)
        context_bytes = len(primary_oracle.wire_json(join_oracle.context_document(info)))
        return {"primary": primary_values, "index": index_values, "context_hashes": 69,
            "projection_hashes": 2 + 2 * len(members), "context_bytes": context_bytes,
            "total_hashes": primary_values["hash_work"] + index_values["hashes"] + 71 + 2 * len(members),
            "total_input_bytes": primary_values["input_bytes"] + index_values["input_bytes"] + context_bytes}


class CompleteQueryBatchTests(unittest.TestCase):
    def setUp(self):
        self.fixture = BatchFixture()

    def verify(self, fixture=None, **changes):
        inputs = (self.fixture if fixture is None else fixture).arguments()
        inputs.update(changes)
        return batch.verify_complete_query_batch(**inputs)

    def assert_observation(self, fixture, result):
        self.assertEqual(result.operation, OPERATION)
        self.assertEqual(result.arguments, fixture.intent)
        self.assertEqual(result.cutoff_us, fixture.cutoff_us)
        self.assertEqual(result.selected_rows, fixture.selected)
        self.assertEqual(result.before_proofs, fixture.proofs)
        self.assertEqual(result.queries, fixture.queries)
        self.assertEqual(tuple(head.index_id for head in result.read_heads), READ_INDEX_IDS)
        self.assertEqual(tuple(key for key, _ in result.joined_reads),
                         tuple(query.query_id for query in fixture.queries))
        self.assertEqual(values(result.primary.metrics), fixture.primary_metrics())
        self.assertIs(result.metrics.primary, result.primary.metrics)
        self.assertEqual(result.primary.business_after_roots, result.business_before_roots)
        self.assertEqual(result.primary.authorization_after_roots, result.authorization_before_roots)
        self.assertEqual(result.metrics.context_hashes, 95)
        for query, (query_id, observation), (metric_id, metrics) in zip(
                fixture.queries, result.joined_reads, result.metrics.queries):
            with self.subTest(role=query.role):
                info = fixture.joins[query.role]
                self.assertEqual((query_id, metric_id), (query.query_id, query.query_id))
                self.assertEqual(observation.anchor, info.anchor)
                self.assertEqual(observation.interval, info.interval)
                self.assertEqual(observation.leaves, info.index.matches(info.interval))
                expected = fixture.join_metrics(query.role)
                actual = values(metrics)
                actual["primary"], actual["index"] = values(metrics.primary), values(metrics.index)
                self.assertEqual(actual, expected)
                self.assertIs(metrics, observation.metrics)

    def test_actual_five_joins_preserve_four_read_heads_and_independent_phase_metrics(self):
        result = self.verify()
        self.assert_observation(self.fixture, result)
        self.assertEqual(len(result.queries), 5)
        self.assertEqual(len(result.read_heads), 4)
        pending, active = (observation for _, observation in result.joined_reads[:2])
        self.assertEqual(pending.anchor, active.anchor)
        self.assertNotEqual(pending.interval, active.interval)
        self.assertEqual(result.joined_reads[3][1].leaves, ())

    def test_real_global_membership_and_each_real_join_run_without_result_token_inputs(self):
        original_membership = primary.evaluate_primary_radix_memberships
        original_join = joined.join_index_range
        memberships, joins = [], []
        def membership(**inputs):
            result = original_membership(**inputs)
            memberships.append((inputs, result))
            return result
        def join(**inputs):
            result = original_join(**inputs)
            joins.append((inputs, result))
            return result
        with mock.patch.object(primary, "evaluate_primary_radix_memberships", side_effect=membership), \
                mock.patch.object(joined, "join_index_range", side_effect=join):
            result = self.verify()
        self.assertEqual(len(memberships), 6)
        self.assertEqual(len(joins), 5)
        self.assertGreater(len(memberships[0][0]["table_contracts"]), 1)
        self.assertIs(result.primary, memberships[0][1].result)
        # Observe the actual phase inputs under ordinary fixture pressure.
        # Independent capture/envelope encodings seed the consumed ledger;
        # each real result is then charged once, without replacing a verifier.
        ownership = self.fixture.ownership_document()
        business = [item for item in self.fixture.selected if not (
            item["table"] == capacity.AGGREGATE_TABLE and item["key"] == {"aggregate_id": capacity.AGGREGATE_ID})]
        envelopes = (business, list(self.fixture.selected))
        consumed_hashes = 95
        consumed_bytes = len(primary_oracle.wire_json(ownership)) + sum(
            len(primary_oracle.wire_json(value)) for value in envelopes)
        consumed_nodes = join_oracle.graph_nodes(ownership) + sum(
            join_oracle.graph_nodes(value) for value in envelopes)
        spec = authority_contract.operation_spec(OPERATION)
        self.assertEqual((spec["maximumQueryRows"], spec["maximumMutations"]), (193, 137))
        self.assertEqual(values(memberships[0][0]["limits"]), {
            "max_selected_rows": 193, "max_mutations": 137,
            "max_proof_vectors": 64 * 193, "max_proof_child_slots": 1024 * 193,
            "max_hashes": min(66 + 70 * 193, 8_000_000 - consumed_hashes),
            "max_input_bytes": 64 * 1024 * 1024 - consumed_bytes,
            "max_json_depth": 128, "max_json_nodes": 1_000_000 - consumed_nodes,
        })
        global_metrics = memberships[0][1].result.metrics
        consumed_hashes += global_metrics.hash_work
        consumed_bytes += global_metrics.input_bytes
        consumed_nodes += global_metrics.json_nodes
        for ordinal, (query, (phase, observation)) in enumerate(zip(self.fixture.queries, joins)):
            with self.subTest(phase=query.role):
                remaining_hashes = 8_000_000 - consumed_hashes
                remaining_bytes = 64 * 1024 * 1024 - consumed_bytes
                remaining_nodes = 1_000_000 - consumed_nodes
                maximum = declaration_oracle.complete_document(query.role)["maximumRows"]
                opened = 1 + 160 * maximum + 2 * 160
                limits = phase["limits"]
                self.assertEqual(values(limits.primary), {
                    "max_selected_rows": maximum, "max_mutations": 137,
                    "max_proof_vectors": 64 * maximum, "max_proof_child_slots": 1024 * maximum,
                    "max_hashes": min(66 + 70 * maximum, remaining_hashes),
                    "max_input_bytes": remaining_bytes, "max_json_depth": 128,
                    "max_json_nodes": remaining_nodes,
                })
                self.assertEqual(values(limits.index), {
                    "max_entries": 4800 + maximum, "max_leaves": maximum,
                    "max_opened_nodes": opened, "max_hashes": min(16 * opened + maximum, remaining_hashes),
                    "max_input_bytes": min(4 * 1024 * 1024, remaining_bytes),
                })
                self.assertEqual(limits.max_total_hashes, min(1_100_000, remaining_hashes))
                self.assertEqual(limits.max_total_input_bytes,
                                 min(64 * 1024 * 1024 + 4 * 1024 * 1024 + 262144, remaining_bytes))
                inner = values(limits.primary)
                inner["max_hashes"] = min(inner["max_hashes"], limits.max_total_hashes
                    - 69 - 2 - observation.metrics.index.hashes - 2 * len(observation.leaves))
                inner["max_input_bytes"] = min(inner["max_input_bytes"], limits.max_total_input_bytes
                    - observation.metrics.context_bytes - observation.metrics.index.input_bytes)
                self.assertEqual(values(memberships[ordinal + 1][0]["limits"]), inner)
                consumed_hashes += observation.metrics.total_hashes
                consumed_bytes += observation.metrics.total_input_bytes
                consumed_nodes += observation.metrics.primary.json_nodes
        self.assertEqual((consumed_hashes, consumed_bytes, consumed_nodes),
                         (result.metrics.total_hashes, result.metrics.total_input_bytes,
                          result.metrics.total_json_nodes))
        for (_, actual), (_, observed) in zip(joins, result.joined_reads):
            self.assertIs(actual, observed)
        self.assertEqual(joins[0][0]["anchor"], joins[1][0]["anchor"])
        with self.assertRaises(TypeError):
            self.verify(verified_result=result)
        with self.assertRaises(batch.CompleteQueryBatchError):
            self.verify(read_heads=result)

    def test_all_five_empty_queries_retain_four_empty_heads_and_actual_reconstructions(self):
        fixture = BatchFixture(rows={})
        result = self.verify(fixture)
        self.assert_observation(fixture, result)
        self.assertEqual(len(result.joined_reads), 5)
        self.assertTrue(all(observation.leaves == () for _, observation in result.joined_reads))
        self.assertTrue(all(head.index_root.count == 0 for head in result.read_heads))
        self.assertTrue(all(metrics.index.hashes > 0 and metrics.primary.hash_work == 66
                            for _, metrics in result.metrics.queries))

    def test_source_query_and_frontier_inventories_reject_missing_duplicate_and_misaligned_roles(self):
        inputs = self.fixture.arguments()
        queries, frontiers = inputs["queries"], inputs["query_frontiers"]
        cases = (
            {"queries": queries[:-1]}, {"queries": queries + queries[:1]},
            {"queries": queries[:-1] + queries[:1]},
            {"query_frontiers": frontiers[:-1]}, {"query_frontiers": frontiers + frontiers[:1]},
            {"query_frontiers": (frontiers[1], frontiers[0], *frontiers[2:])},
            {"query_frontiers": (forged(frontiers[0], query_id=queries[-1].query_id), *frontiers[1:])},
        )
        for ordinal, changes in enumerate(cases):
            with self.subTest(case=ordinal), self.assertRaises(batch.CompleteQueryBatchError):
                self.verify(**changes)

    def test_read_head_closure_is_exact_shared_sorted_and_source_profile_bound(self):
        heads = self.fixture.arguments()["read_heads"]
        self.assertEqual(heads[0].index_root.count, 0)
        self.assertGreater(heads[1].index_root.count, 0)
        genesis = (replace(heads[0], index_revision=0), *heads[1:])
        self.assertEqual(self.verify(read_heads=genesis).read_heads[0].index_revision, 0)
        variants = (heads[:-1], heads + heads[:1], tuple(reversed(heads)),
            (forged(heads[0], index_id="webauthn_credential_id"), *heads[1:]),
            (forged(heads[0], index_root=heads[1].index_root), *heads[1:]),
            (forged(heads[0], index_revision=True), *heads[1:]),
            (heads[0], forged(heads[1], index_revision=0), *heads[2:]))
        for ordinal, candidate in enumerate(variants):
            with self.subTest(case=ordinal), self.assertRaises(batch.CompleteQueryBatchError):
                self.verify(read_heads=candidate)

    def test_bindings_rederive_supplied_source_record_cutoff_status_and_hint_lengths(self):
        inputs = self.fixture.arguments()
        for field, replacement in (("source", "trust-withdrawal"), ("record_id", "other"),
                                   ("oidc_session_ids", ["one"]), ("approval_grant_ids", [])):
            intent = copy.deepcopy(inputs["arguments"])
            intent[field] = replacement
            with self.subTest(field=field), self.assertRaises(batch.CompleteQueryBatchError):
                self.verify(arguments=intent)
        for cutoff in (CUTOFF_US + 1, True, 2**63):
            with self.subTest(cutoff=cutoff), self.assertRaises(batch.CompleteQueryBatchError):
                self.verify(cutoff_us=cutoff)
        altered = forged(inputs["queries"][0],
            selector_items=(("credential_record_id", "credential-雪"), ("status", "active")))
        with self.assertRaises(batch.CompleteQueryBatchError):
            self.verify(queries=(altered, *inputs["queries"][1:]))
        with self.assertRaises(batch.CompleteQueryBatchError):
            self.verify(operation="webauthn.trust.stage")

    def test_primary_global_inventory_keeps_unchanged_roots_and_denies_class_or_key_aliases(self):
        inputs = self.fixture.arguments()
        roots = inputs["business_before_roots"]
        self.assertTrue(any(root["table"] == "metadata_audit_outbox" for root in roots))
        self.assertEqual(inputs["authorization_before_roots"], [])
        for changes in ({"business_before_roots": roots[:-1]},
                        {"business_before_roots": roots + roots[:1]},
                        {"business_before_roots": roots[1:], "authorization_before_roots": roots[:1]}):
            with self.subTest(changes=tuple(changes)), self.assertRaises(batch.CompleteQueryBatchError):
                self.verify(**changes)
        for field, replacement in (("table", "not_a_source_table"), ("key", {"not_id": "x"}),
                                   ("keyDigest", "sha256:" + "f" * 64), ("present", 1)):
            selected = copy.deepcopy(inputs["selected_rows"])
            selected[0][field] = replacement
            with self.subTest(field=field), self.assertRaises(batch.CompleteQueryBatchError):
                self.verify(selected_rows=selected)

    def test_valid_point_only_presence_absence_and_query_overlap_do_not_imply_ordinary_closure(self):
        result = self.verify()
        query_addresses = {(observation.anchor.primary_root.table, leaf.primary_key_digest)
                           for _, observation in result.joined_reads for leaf in observation.leaves}
        outside = [row for row in result.selected_rows if (row["table"], row["keyDigest"]) not in query_addresses]
        self.assertEqual({row["present"] for row in outside}, {False, True})
        self.assertEqual(len(outside), 2)
        duplicate = (*self.fixture.selected, self.fixture.selected[0])
        with self.assertRaises(batch.CompleteQueryBatchError):
            self.verify(selected_rows=duplicate, before_proofs=(*self.fixture.proofs, self.fixture.proofs[0]))
        selected = copy.deepcopy(self.fixture.selected)
        selected[0]["contractSelector"] = "caller-selector"
        with self.assertRaises(batch.CompleteQueryBatchError):
            self.verify(selected_rows=selected)

    def test_shared_session_union_accepts_32_and_rejects_33_when_each_role_fits(self):
        intent = declaration_oracle.arguments()
        intent["oidc_session_ids"] = [f"hint-{index:02}" for index in range(32)]
        for pending, active, admitted in ((16, 16, True), (17, 16, False)):
            rows = default_rows()
            rows["oidc_browser_sessions"] = (
                [session(f"pending-{index:02}", "pending_webauthn") for index in range(pending)]
                + [session(f"active-{index:02}", "active") for index in range(active)])
            fixture = BatchFixture(rows, arguments=intent)
            self.assertLessEqual(pending, 32)
            self.assertLessEqual(active, 32)
            with self.subTest(pending=pending, active=active):
                if admitted:
                    result = self.verify(fixture)
                    members = {(observation.anchor.primary_root.table, leaf.primary_key_digest)
                               for _, observation in result.joined_reads[:2] for leaf in observation.leaves}
                    self.assertEqual(len(members), 32)
                    self.assertEqual(sum(len(observation.leaves) for _, observation in result.joined_reads[:2]), 32)
                else:
                    with self.assertRaises(batch.CompleteQueryBatchError):
                        self.verify(fixture)

    def test_hint_limits_are_fail_closed_allowances_not_truncation_or_complete_count_hints(self):
        rows = default_rows()
        rows["oidc_browser_sessions"] = [session(f"pending-{index}", "pending_webauthn") for index in range(3)]
        fixture = BatchFixture(rows)
        self.assertEqual(fixture.queries[0].maximum_rows, 2)
        self.assertEqual(len(fixture.joins["sessions_pending_webauthn"].selected), 3)
        with self.assertRaises(batch.CompleteQueryBatchError):
            self.verify(fixture)
        intent = declaration_oracle.arguments()
        intent["oidc_session_ids"] = []
        rows["oidc_browser_sessions"] = rows["oidc_browser_sessions"][:1]
        single = BatchFixture(rows, arguments=intent)
        self.assertEqual(single.queries[0].maximum_rows, 1)
        self.assertEqual(len(self.verify(single).joined_reads[0][1].leaves), 1)
        with self.assertRaises(TypeError):
            self.verify(limits={"maximumRows": 1024})

    def test_real_primary_sibling_and_full_row_corruption_are_rejected(self):
        inputs = self.fixture.arguments()
        proofs = copy.deepcopy(inputs["before_proofs"])
        vector = proofs[0]["siblings"][0]
        sibling = (int(vector["selectedNibble"], 16) + 1) % 16
        vector["childDigests"][sibling] = "sha256:" + "e" * 64
        primary_oracle.refresh_proof_digest(proofs[0])
        with self.assertRaises(batch.CompleteQueryBatchError):
            self.verify(before_proofs=proofs)
        selected = copy.deepcopy(inputs["selected_rows"])
        present = next(item for item in selected if item["present"])
        present["row"]["uncommitted_full_row_field"] = "changed"
        with self.assertRaises(batch.CompleteQueryBatchError):
            self.verify(selected_rows=selected)

    def test_counted_omission_false_leaf_and_interior_opaque_fail_genuine_reconstruction(self):
        inputs = self.fixture.arguments()
        first = inputs["query_frontiers"][0]
        member = next(item for item in first.frontier if type(item) is counted.IndexLeaf)
        candidates = (
            tuple(item for item in first.frontier if item is not member),
            tuple(replace(item, primary_row_digest="sha256:" + "e" * 64) if item is member else item
                  for item in first.frontier),
            tuple(self.fixture.joins[ROLES[0]].index.opaque(member.key) if item is member else item
                  for item in first.frontier),
        )
        for ordinal, frontier in enumerate(candidates):
            with self.subTest(case=ordinal), self.assertRaises(batch.CompleteQueryBatchError):
                self.verify(query_frontiers=(replace(first, frontier=frontier), *inputs["query_frontiers"][1:]))

    def test_every_counted_member_requires_its_exact_global_primary_selection(self):
        inputs = self.fixture.arguments()
        member = self.fixture.joins[ROLES[0]].selected[0]
        address = (member["table"], member["keyDigest"])
        selected = tuple(item for item in inputs["selected_rows"]
                         if (item["table"], item["keyDigest"]) != address)
        proofs = tuple(item for item in inputs["before_proofs"]
                       if (item["table"], item["keyDigest"]) != address)
        self.assertEqual(len(selected), len(inputs["selected_rows"]) - 1)
        with self.assertRaises(batch.CompleteQueryBatchError):
            self.verify(selected_rows=selected, before_proofs=proofs)

    def test_valid_changed_primary_pair_cannot_join_an_older_counted_population(self):
        inputs = self.fixture.arguments()
        table = "oidc_browser_sessions"
        rows = copy.deepcopy(self.fixture.rows[table])
        rows[0]["bound_webauthn_credential_id"] = "different-credential"
        replacement = primary_oracle.IndependentTree(rows, table=table, revision=18)
        selected = tuple(replacement.selected(item["key"]) if item["table"] == table else item
                         for item in inputs["selected_rows"])
        proofs = tuple(replacement.proof(item) if item["table"] == table else
                       self.fixture.trees[item["table"]].proof(item) for item in selected)
        roots = [replacement.root.json_projection() if item["table"] == table else item
                 for item in inputs["business_before_roots"]]
        with self.assertRaises(batch.CompleteQueryBatchError):
            self.verify(business_before_roots=roots, selected_rows=selected, before_proofs=proofs)

    def test_all_later_query_evidence_and_global_graph_are_owned_before_first_context_hash(self):
        inputs = self.fixture.arguments()
        original = projection._framed_hash
        observed = []
        def hashing(*frames):
            if not observed:
                observed.append(True)
                inputs["arguments"]["record_id"] = "caller-mutated"
                inputs["arguments"]["oidc_session_ids"].clear()
                for root in inputs["business_before_roots"]:
                    root["rootRevision"] += 100
                    root["rootDigest"] = "sha256:" + "e" * 64
                object.__setattr__(inputs["queries"][-1], "maximum_rows", 32)
                object.__setattr__(inputs["read_heads"][-1], "index_revision", 500)
                object.__setattr__(inputs["read_heads"][-1].index_root, "digest", "sha256:" + "f" * 64)
                later = next(item for item in inputs["query_frontiers"][-1].frontier
                             if type(item) is counted.IndexLeaf)
                object.__setattr__(later, "primary_row_digest", "sha256:" + "d" * 64)
                inputs["selected_rows"][0]["row"]["changed_after_snapshot"] = True
                inputs["before_proofs"][-1]["rowDigest"] = "sha256:" + "c" * 64
            return original(*frames)
        with mock.patch.object(projection, "_framed_hash", side_effect=hashing):
            result = batch.verify_complete_query_batch(**inputs)
        self.assertEqual(observed, [True])
        self.assert_observation(self.fixture, result)

    def test_owned_outputs_are_detached_observations_not_reusable_verification_tokens(self):
        inputs = self.fixture.arguments()
        result = batch.verify_complete_query_batch(**inputs)
        self.assertIsNot(result.arguments, inputs["arguments"])
        self.assertIsNot(result.selected_rows[0], inputs["selected_rows"][0])
        self.assertIsNot(result.before_proofs[0], inputs["before_proofs"][0])
        result.arguments["record_id"] = "modified-observation"
        result.selected_rows[0]["row"]["metadata"] = "modified-observation"
        self.assertEqual(inputs["arguments"], self.fixture.intent)
        self.assertEqual(inputs["selected_rows"], self.fixture.selected)
        with self.assertRaises(FrozenInstanceError):
            result.cutoff_us = 0
        with self.assertRaises(FrozenInstanceError):
            result.read_heads[0].index_revision = 0
        with self.assertRaises(batch.CompleteQueryBatchError):
            self.verify(query_frontiers=result.joined_reads)

    def test_exact_aggregate_accounting_charges_ownership_envelopes_and_all_repeated_work(self):
        result = self.verify()
        ownership = self.fixture.ownership_document()
        business = [item for item in self.fixture.selected if not (
            item["table"] == capacity.AGGREGATE_TABLE and item["key"] == {"aggregate_id": capacity.AGGREGATE_ID})]
        envelopes = (business, list(self.fixture.selected))
        ownership_bytes = len(primary_oracle.wire_json(ownership))
        ownership_nodes = join_oracle.graph_nodes(ownership)
        envelope_bytes = sum(len(primary_oracle.wire_json(value)) for value in envelopes)
        envelope_nodes = sum(join_oracle.graph_nodes(value) for value in envelopes)
        primary_values = self.fixture.primary_metrics()
        query_values = [self.fixture.join_metrics(role) for role in ROLES]
        metrics = result.metrics
        self.assertEqual((metrics.ownership_bytes, metrics.ownership_nodes),
                         (ownership_bytes, ownership_nodes))
        self.assertEqual((metrics.selected_envelope_bytes, metrics.selected_envelope_nodes),
                         (envelope_bytes, envelope_nodes))
        self.assertEqual(metrics.total_hashes,
            95 + primary_values["hash_work"] + sum(item["total_hashes"] for item in query_values))
        self.assertEqual(metrics.total_input_bytes,
            ownership_bytes + envelope_bytes + primary_values["input_bytes"]
            + sum(item["total_input_bytes"] for item in query_values))
        self.assertEqual(metrics.total_json_nodes,
            ownership_nodes + envelope_nodes + primary_values["json_nodes"]
            + sum(item["primary"]["json_nodes"] for item in query_values))
        self.assertGreater(sum(item["primary"]["hash_work"] for item in query_values), 5 * 66)
        manifest = join_oracle.framed("serverware.policyAuthorityIndexProjectionManifest/v1",
            join_oracle.utf8_json([join_oracle.descriptor(name) for name in ALL_INDEX_IDS]))
        self.assertEqual(result.projection_manifest_digest, manifest)

    def test_business_192_and_optional_exact_framework_slot_are_separate_source_allowances(self):
        rows = default_rows()
        # Four complete members plus the credential point and outbox absence
        # make six ordinary selections. Add 186 independent point rows.
        extra = [{"id": f"point-{index:03}", "sign_count": index} for index in range(186)]
        rows["webauthn_credentials"].extend(extra)
        point_keys = tuple(("webauthn_credentials", {"id": row["id"]}) for row in extra)
        absent_counter = (capacity.AGGREGATE_TABLE, {"aggregate_id": capacity.AGGREGATE_ID})
        fixture = BatchFixture(rows, extra_keys=(*point_keys, absent_counter))
        self.assertEqual(len(fixture.selected), 193)
        counter = next(item for item in fixture.selected if item["table"] == capacity.AGGREGATE_TABLE)
        self.assertIs(counter["present"], False)
        self.assertEqual(self.verify(fixture).primary.metrics.selected_rows, 193)
        # A different key in the same table remains an ordinary business row.
        alias = BatchFixture(rows, extra_keys=(*point_keys,
            (capacity.AGGREGATE_TABLE, {"aggregate_id": "not-the-global-counter"})))
        self.assertEqual(len(alias.selected), 193)
        original = primary.evaluate_primary_radix_memberships
        with mock.patch.object(primary, "evaluate_primary_radix_memberships", wraps=original) as observe:
            with self.assertRaises(batch.CompleteQueryBatchError):
                self.verify(alias)
        self.assertEqual(observe.call_count, 0)
        duplicate = fixture.arguments()
        duplicate["selected_rows"] += (counter,)
        duplicate["before_proofs"] += (fixture.trees[capacity.AGGREGATE_TABLE].proof(counter),)
        with self.assertRaises(batch.CompleteQueryBatchError):
            batch.verify_complete_query_batch(**duplicate)

    def test_real_business_and_framework_envelope_limits_reject_before_membership(self):
        business = self.fixture.arguments()
        present = next(item for item in business["selected_rows"] if item["present"])
        present["row"]["padding"] = "x" * authority_contract.MAX_REQUEST_BYTES
        framework_fixture = BatchFixture(extra_keys=((capacity.AGGREGATE_TABLE,
                                                       {"aggregate_id": capacity.AGGREGATE_ID}),))
        framework = framework_fixture.arguments()
        counter = next(item for item in framework["selected_rows"] if item["table"] == capacity.AGGREGATE_TABLE)
        counter["present"] = True
        counter["row"] = {"aggregate_id": capacity.AGGREGATE_ID,
                          "padding": "x" * authority_contract.MAX_PLAN_SELECTED_BYTES}
        original = primary.evaluate_primary_radix_memberships
        for label, inputs in (("business", business), ("framework", framework)):
            with self.subTest(envelope=label), \
                    mock.patch.object(primary, "evaluate_primary_radix_memberships", wraps=original) as observe:
                with self.assertRaisesRegex(batch.CompleteQueryBatchError, "byte bound"):
                    batch.verify_complete_query_batch(**inputs)
                self.assertEqual(observe.call_count, 0)

    def test_raw_context_types_and_fixed_accounting_ceilings_cannot_be_caller_expanded(self):
        inputs = self.fixture.arguments()
        variants = (
            {"queries": list(inputs["queries"])}, {"read_heads": list(inputs["read_heads"])},
            {"selected_rows": list(inputs["selected_rows"])},
            {"read_heads": (object.__new__(batch.CompleteQueryHead), *inputs["read_heads"][1:])},
            {"query_frontiers": (object.__new__(batch.CompleteQueryFrontier), *inputs["query_frontiers"][1:])},
        )
        for ordinal, changes in enumerate(variants):
            with self.subTest(case=ordinal), self.assertRaises(batch.CompleteQueryBatchError):
                self.verify(**changes)
        self.assertEqual((batch.MAX_TOTAL_HASHES, batch.MAX_TOTAL_INPUT_BYTES,
                          batch.MAX_TOTAL_JSON_NODES, batch.MAX_JSON_DEPTH),
                         (8_000_000, 64 * 1024 * 1024, 1_000_000, 128))
        # Private accounting boundaries only, not a claim that a whole valid
        # five-query proof graph can attain all three exact maxima together.
        for dimension, limit in (("hashes", 8_000_000), ("input_bytes", 64 * 1024 * 1024),
                                 ("json_nodes", 1_000_000)):
            ledger = batch._Ledger()
            ledger.charge(**{dimension: limit})
            with self.subTest(dimension=dimension), self.assertRaises(batch.CompleteQueryBatchError):
                ledger.charge(**{dimension: 1})
            with self.assertRaises(batch.CompleteQueryBatchError):
                ledger.remaining()


if __name__ == "__main__":
    unittest.main()
