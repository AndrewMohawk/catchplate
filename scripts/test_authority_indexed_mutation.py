#!/usr/bin/env python3
"""Actual primary/CAS plus fixed-profile counted-index mutation components.

Expected primary trees, eleven profile encodings, counted roots and sparse
frontiers are built independently of the production projection/evaluators.
No SQL, registry, installed index, signed/current checkpoint, kernel admission
or atomic writer maintenance is established by these authored pure fixtures.
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

from serverware import authority_index_contract as contract
from serverware import authority_index_mutation as sparse
from serverware import authority_indexed_mutation as indexed
from serverware import authority_radix_mutation as primary
from serverware.authority_query_read_work import _ValidationWork, QueryReadValidationLimits
import test_authority_radix_mutation as primary_oracle
import test_authority_index_join as join_oracle
import test_authority_index_range as counted_oracle


PROFILE_TABLES = {
    "webauthn_credentials": ("webauthn_credential_id", "webauthn_credential_user_history",
                             "webauthn_credential_live_trust"),
    "webauthn_challenges": ("webauthn_registration_unused_global", "webauthn_registration_unused_user",
        "webauthn_challenge_unused_global", "webauthn_challenge_unused_user",
        "webauthn_challenge_created_global", "webauthn_challenge_created_user",
        "webauthn_challenge_terminal_unreferenced_global", "webauthn_challenge_scope_unused",
        "webauthn_challenge_value"),
    "oidc_browser_sessions": ("webauthn_session_credential_status", "oidc_session_token_digest"),
    "oidc_session_activation_deliveries": ("oidc_activation_delivery_session_id",
        "oidc_activation_delivery_old_token_digest", "oidc_activation_delivery_new_token_digest",
        "oidc_activation_delivery_assertion_digest", "oidc_activation_delivery_challenge_id"),
    "approval_grants": ("webauthn_grant_approver_active",),
    "control_plane_approvals": ("webauthn_control_approval_approved",),
    "webauthn_trust_publications": ("webauthn_publication_bundle_digest", "webauthn_publication_status",
                                  "webauthn_publication_generation"),
}

EPOCH = "1970-01-01T00:00:00+00:00"
CHALLENGE_ID = "00000000-0000-0000-0000-000000000001"


def challenge(identifier=CHALLENGE_ID, **changes):
    """Complete synthetic fresh-source row; no legacy challenge-ID adoption."""
    return {"id": identifier, "challenge_type": "registration", "used_at": None,
            "expires_at": EPOCH, "created_at": EPOCH, "user_id": "user",
            "challenge": "fixture-challenge", "scope_key": None,
            "retention_reference_mask": 0, **changes}


def values(value):
    return {field.name: getattr(value, field.name) for field in fields(value)}


def forged(value, **changes):
    result = object.__new__(type(value))
    for field in fields(value):
        object.__setattr__(result, field.name, changes.get(field.name, getattr(value, field.name)))
    return result


def image_leaf(profile, row, expiry_us=None):
    if row is None:
        return None
    key_digest = primary_oracle.wire_digest("serverware.policyAuthorityBusinessKey/v1",
        profile.table.encode("ascii"), primary_oracle.wire_json({"id": row["id"]}))
    row_digest = primary_oracle.sql_digest("serverware.policyAuthorityAuthenticatedRow/v1",
        profile.table.encode("ascii"), primary_oracle.sql_json(row))
    return join_oracle.expected_leaf(profile, row, {"keyDigest": key_digest},
                                    {"rowDigest": row_digest}, expiry_us=expiry_us)


def sparse_frontier(tree, targets):
    """Select maximal positive sibling terminals from independent stored nodes.

    A finite set of proper ancestors determines opened paths. This directly
    selects stored terminals; it neither calls the sparse verifier nor a
    production complement/frontier routine. Missing target leaves stay implicit.
    """
    opened = {""} | {path[:depth] for path in targets for depth in range(160)}
    result = []
    for prefix, (_, count) in tree.nodes.items():
        if not prefix or count == 0:
            continue
        if prefix in targets:
            result.append(tree.leaves[prefix])
        elif prefix not in opened and prefix[:-1] in opened:
            result.append(tree.opaque(prefix))
    return tuple(sorted(result, key=lambda value:
        value.key if type(value) is contract.IndexLeaf else value.prefix))


def credential(identifier="credential", **changes):
    return {"id": identifier, "credential_id": "credential-雪", "user_id": "user-é",
            "revoked_at": None, "attestation_trusted": 1, "sign_count": 3,
            "metadata": {"note": "unchanged", "flags": [True, None]}, **changes}


def index_metrics(info):
    targets = info["targets"]
    opened = {""} | {path[:depth] for path in targets for depth in range(160)}
    work = []
    for ordinal, tree in enumerate((info["before"], info["after"])):
        hashes = sum(images[ordinal] is not None for images in targets.values())
        for prefix in opened:
            populated = sum(tree.nodes.get(prefix + digit, (None, 0))[1] > 0 for digit in "0123456789abcdef")
            hashes += 1 if populated == 0 else 17 - populated
        work.append(hashes)
    profile, root = info["profile"], info["before"].root
    scalars = ["serverware.policyAuthorityIndexMutationInput/v1",
        "serverware.policyAuthorityCountedIndex/v1", profile.index_id, profile.table,
        profile.projection_digest, "160", root.digest, str(root.count),
        str(len(targets)), str(len(info["frontier"]))]
    for path, images in sorted(targets.items()):
        scalars.extend(("change", path))
        for name, leaf in zip(("before", "after"), images):
            if leaf is None:
                scalars.append(name + "-absent")
            else:
                scalars.extend((name + "-leaf", leaf.key, leaf.primary_key_digest, leaf.primary_row_digest))
    for value in info["frontier"]:
        if type(value) is contract.IndexLeaf:
            scalars.extend(("leaf", value.key, value.primary_key_digest, value.primary_row_digest))
        else:
            scalars.extend(("opaque", value.prefix, value.digest, str(value.count)))
    return {"changes": len(targets), "frontier_entries": len(info["frontier"]),
            "opened_nodes": len(opened), "child_slots": 32 * len(opened),
            "before_hashes": work[0], "after_hashes": work[1],
            "input_bytes": sum(8 + len(value.encode("ascii")) for value in scalars)}


def primary_metrics(arguments):
    document = {
        "contracts": [{"table": item.table, "keyColumns": list(item.key_columns),
                       "writeAccess": item.write_access, "rootClass": item.root_class}
                      for item in arguments["table_contracts"]],
        "businessRoots": [{"table": item.table, "rootRevision": item.root_revision,
                           "rootDigest": item.root_digest, "leafCount": item.leaf_count}
                          for item in arguments["business_before_roots"]],
        "authorizationRoots": [{"table": item.table, "rootRevision": item.root_revision,
                                "rootDigest": item.root_digest, "leafCount": item.leaf_count}
                               for item in arguments["authorization_before_roots"]],
        "selected": list(arguments["selected_rows"]), "proofs": list(arguments["before_proofs"]),
        "mutations": list(arguments["mutations"]),
    }
    ancestors = set()
    for mutation in arguments["mutations"]:
        path = primary_oracle.sql_digest("serverware.policyAuthorityAuthenticatedKey/v1",
            mutation["table"].encode("ascii"), primary_oracle.sql_json(mutation["key"]))[7:]
        ancestors.update((mutation["table"], path[:depth]) for depth in range(64))
    count = len(arguments["selected_rows"])
    return {"selected_rows": count, "mutations": len(arguments["mutations"]),
            "proof_vectors": 64 * count, "proof_child_slots": 1024 * count,
            "recomputed_ancestors": len(ancestors),
            "hash_work": 66 + sum(70 if row["present"] else 68 for row in arguments["selected_rows"])
                         + 2 * sum(value["row"] is not None for value in arguments["mutations"]) + len(ancestors),
            "input_bytes": len(primary_oracle.wire_json(document)), "json_nodes": join_oracle.graph_nodes(document)}


def context_bytes(index_inputs):
    scalars = ["serverware.policyAuthorityIndexedMutationInput/v1", str(len(index_inputs))]
    for item in index_inputs:
        scalars.extend((item.index_id, str(item.index_revision), item.index_root.digest,
                        str(item.index_root.count), str(len(item.frontier))))
    return sum(8 + len(value.encode("ascii")) for value in scalars)


class MutationFixture:
    """Independent before/after population and expected per-profile changes."""
    def __init__(self, tables, actions, *, expiry_before=None, expiry_after=None):
        self.tables = copy.deepcopy(tables)
        self.actions = copy.deepcopy(actions)
        self.expiry_before = {} if expiry_before is None else dict(expiry_before)
        self.expiry_after = self.expiry_before.copy() if expiry_after is None else dict(expiry_after)
        self.trees = {table: primary_oracle.IndependentTree(rows, table=table, revision=17)
                      for table, rows in sorted(self.tables.items())}
        self.selected = tuple(self.trees[table].selected({"id": identifier})
                              for table, identifier, _, _ in self.actions)
        self.proofs = tuple(self.trees[row["table"]].proof(row) for row in self.selected)
        self.mutations = tuple(primary_oracle.change(selected, operation, after)
            for selected, (_, _, operation, after) in zip(self.selected, self.actions))
        after_tables = {table: {row["id"]: copy.deepcopy(row) for row in rows}
                        for table, rows in self.tables.items()}
        for table, identifier, _, after in self.actions:
            after_tables[table].pop(identifier, None)
            if after is not None:
                after_tables[table][after["id"]] = copy.deepcopy(after)
        self.after_tables = {table: list(rows.values()) for table, rows in after_tables.items()}
        self.after_trees = {table: primary_oracle.IndependentTree(rows, table=table,
            revision=17 + sum(action[0] == table for action in self.actions))
            for table, rows in self.after_tables.items()}
        self.indexes = {}
        for table in sorted({action[0] for action in self.actions}):
            for index_id in PROFILE_TABLES.get(table, ()):
                profile = join_oracle.expected_profile(index_id)
                old_leaves = [image_leaf(profile, row, self.expiry_before.get(row["id"]))
                              for row in self.tables[table]]
                new_leaves = [image_leaf(profile, row, self.expiry_after.get(row["id"]))
                              for row in self.after_tables[table]]
                before = counted_oracle.IndependentIndex([leaf for leaf in old_leaves if leaf is not None], profile)
                after = counted_oracle.IndependentIndex([leaf for leaf in new_leaves if leaf is not None], profile)
                targets, revision_delta = {}, 0
                for mutation in self.mutations:
                    if mutation["table"] != table:
                        continue
                    old = image_leaf(profile, mutation["expectedRow"], self.expiry_before.get(mutation["key"]["id"]))
                    new = image_leaf(profile, mutation["row"], self.expiry_after.get(mutation["key"]["id"]))
                    revision_delta += int(old is not None or new is not None)
                    if old is not None:
                        targets.setdefault(old.key, [None, None])[0] = old
                    if new is not None:
                        targets.setdefault(new.key, [None, None])[1] = new
                self.indexes[index_id] = {"profile": profile, "before": before, "after": after,
                    "targets": targets, "frontier": sparse_frontier(before, targets),
                    "revision_before": 29, "revision_delta": revision_delta}

    def arguments(self):
        return {"table_contracts": tuple(tree.contract() for tree in self.trees.values()),
            "business_before_roots": tuple(tree.root for tree in self.trees.values()),
            "authorization_before_roots": (), "selected_rows": copy.deepcopy(self.selected),
            "before_proofs": copy.deepcopy(self.proofs), "mutations": copy.deepcopy(self.mutations),
            "index_inputs": tuple(indexed.IndexedMutationInput(index_id, info["revision_before"],
                info["before"].root, info["frontier"]) for index_id, info in sorted(self.indexes.items())),
            "limits": indexed.IndexedMutationLimits(primary_oracle.LIMITS, sparse.IndexMutationLimits())}


class IndexedMutationTests(unittest.TestCase):
    def setUp(self):
        self.before = credential()
        self.after = {**self.before, "sign_count": 4}
        self.fixture = MutationFixture({"webauthn_credentials": [self.before, credential("opaque", user_id="other")]},
            (("webauthn_credentials", self.before["id"], "UPDATE", self.after),))

    def verify(self, fixture=None, **changes):
        arguments = (self.fixture if fixture is None else fixture).arguments()
        arguments.update(changes)
        return indexed.evaluate_indexed_primary_batch(**arguments)

    def assert_exact(self, fixture):
        arguments = fixture.arguments()
        result = indexed.evaluate_indexed_primary_batch(**arguments)
        self.assertEqual(result.primary.business_after_roots,
                         tuple(fixture.after_trees[table].root for table in sorted(fixture.after_trees)))
        self.assertEqual(result.primary.authorization_after_roots, ())
        expected_before, expected_after = [], []
        for index_id, info in sorted(fixture.indexes.items()):
            expected_before.append(indexed.IndexedMutationHead(index_id, info["revision_before"], info["before"].root))
            expected_after.append(indexed.IndexedMutationHead(index_id,
                info["revision_before"] + info["revision_delta"], info["after"].root))
        self.assertEqual(result.before_heads, tuple(expected_before))
        self.assertEqual(result.after_heads, tuple(expected_after))
        self.assertEqual(tuple(name for name, _ in result.metrics.indexes), tuple(sorted(fixture.indexes)))
        for name, metrics in result.metrics.indexes:
            self.assertEqual(values(metrics), index_metrics(fixture.indexes[name]))
        expected_projection = sum(2 * len(PROFILE_TABLES.get(mutation["table"], ()))
            * (int(mutation["expectedRow"] is not None) + int(mutation["row"] is not None))
            for mutation in fixture.mutations)
        expected_new_rows = sum(mutation["row"] is not None and mutation["table"] in PROFILE_TABLES
                                for mutation in fixture.mutations)
        self.assertEqual(result.metrics.context_hashes, len(fixture.indexes))
        self.assertEqual(result.metrics.projection_hash_allowance, expected_projection)
        self.assertEqual(result.metrics.new_row_hashes, expected_new_rows)
        self.assertEqual(result.metrics.primary, result.primary.metrics)
        expected_primary = primary_metrics(arguments)
        self.assertEqual(values(result.primary.metrics), expected_primary)
        self.assertEqual(result.metrics.input_bytes, expected_primary["input_bytes"]
                         + context_bytes(arguments["index_inputs"])
                         + sum(index_metrics(info)["input_bytes"] for info in fixture.indexes.values()))
        self.assertEqual(result.metrics.hashes, result.primary.metrics.hash_work + len(fixture.indexes)
                         + expected_projection + expected_new_rows
                         + sum(metrics.hashes for _, metrics in result.metrics.indexes))
        return result

    def test_nonselector_fullrow_update_changes_all_three_credential_commitments(self):
        result = self.assert_exact(self.fixture)
        self.assertEqual(len(result.after_heads), 3)
        for before, after in zip(result.before_heads, result.after_heads):
            self.assertEqual(after.index_revision, before.index_revision + 1)
            self.assertEqual(after.index_root.count, before.index_root.count)
            self.assertNotEqual(after.index_root.digest, before.index_root.digest)
        for info in self.fixture.indexes.values():
            self.assertEqual(len(info["targets"]), 1)
            old, new = next(iter(info["targets"].values()))
            self.assertEqual(old.key, new.key)
            self.assertNotEqual(old.primary_row_digest, new.primary_row_digest)

    def test_credential_partition_moves_and_live_trust_removal_update_entire_fixed_closure(self):
        after = {**self.before, "credential_id": "new-credential", "user_id": "new-user", "revoked_at": "revoked"}
        fixture = MutationFixture({"webauthn_credentials": [self.before]},
                                  (("webauthn_credentials", self.before["id"], "UPDATE", after),))
        result = self.assert_exact(fixture)
        counts = {head.index_id: head.index_root.count for head in result.after_heads}
        self.assertEqual(counts, {"webauthn_credential_id": 1, "webauthn_credential_user_history": 1,
                                 "webauthn_credential_live_trust": 0})
        self.assertEqual(len(fixture.indexes["webauthn_credential_id"]["targets"]), 2)
        self.assertEqual(len(fixture.indexes["webauthn_credential_user_history"]["targets"]), 2)
        self.assertEqual(len(fixture.indexes["webauthn_credential_live_trust"]["targets"]), 1)

    def test_challenge_expiry_user_and_membership_moves_cover_both_registration_indexes(self):
        before = challenge(user_id="old-user")
        moved = {**before, "expires_at": "1970-01-01T00:00:00.000001+00:00", "user_id": "new-user"}
        for after in (moved, {**moved, "used_at": EPOCH}):
            with self.subTest(member=after["used_at"] is None):
                fixture = MutationFixture({"webauthn_challenges": [before]},
                    (("webauthn_challenges", CHALLENGE_ID, "UPDATE", after),),
                    expiry_before={CHALLENGE_ID: 0}, expiry_after={CHALLENGE_ID: 1})
                result = self.assert_exact(fixture)
                self.assertEqual(len(result.after_heads), 9)
                for head in result.after_heads:
                    if head.index_id in ("webauthn_registration_unused_global", "webauthn_registration_unused_user",
                            "webauthn_challenge_unused_global", "webauthn_challenge_unused_user",
                            "webauthn_challenge_scope_unused"):
                        self.assertEqual(head.index_root.count, int(after["used_at"] is None))
                    elif head.index_id == "webauthn_challenge_terminal_unreferenced_global":
                        self.assertEqual(head.index_root.count, int(after["used_at"] is not None))
                    else:
                        self.assertEqual(head.index_root.count, 1)
                    self.assertEqual(head.index_revision,
                        29 if head.index_id == "webauthn_challenge_terminal_unreferenced_global"
                        and after["used_at"] is None else 30)

    def test_neither_member_still_requires_both_heads_and_real_readonly_root_folds(self):
        before = challenge(challenge_type="authentication")
        retained_id = "00000000-0000-0000-0000-000000000002"
        retained = {**before, "id": retained_id, "challenge_type": "registration"}
        fixture = MutationFixture({"webauthn_challenges": [before, retained]},
            (("webauthn_challenges", CHALLENGE_ID, "UPDATE", {**before, "used_at": EPOCH}),),
            expiry_before={CHALLENGE_ID: 0, retained_id: 0})
        result = self.assert_exact(fixture)
        # The two registration indexes still see neither image. New source
        # challenge profiles must independently maintain this same full row.
        legacy = ("webauthn_registration_unused_global", "webauthn_registration_unused_user")
        self.assertEqual(tuple(head for head in result.before_heads if head.index_id in legacy),
                         tuple(head for head in result.after_heads if head.index_id in legacy))
        self.assertEqual(len(result.after_heads), 9)
        for name in legacy:
            info = fixture.indexes[name]
            self.assertEqual(info["targets"], {})
            self.assertTrue(info["frontier"])
            self.assertTrue(all(type(value) is contract.OpaqueSubtree and len(value.prefix) == 1
                                for value in info["frontier"]))
        for name, metrics in result.metrics.indexes:
            if name not in legacy:
                continue
            self.assertEqual((metrics.changes, metrics.opened_nodes, metrics.child_slots), (0, 1, 32))
            self.assertGreater(metrics.before_hashes, 0)
            self.assertEqual(metrics.before_hashes, metrics.after_hashes)

    def test_publication_bundle_status_and_generation_moves_update_all_three_profiles(self):
        before = {"id": "publication", "scope": "global", "status": "pending",
                  "bundle_digest": "old-bundle", "rollback_epoch": -1, "sequence": 7}
        after = {**before, "status": "published", "bundle_digest": "new-bundle", "rollback_epoch": 0, "sequence": 1}
        fixture = MutationFixture({"webauthn_trust_publications": [before]},
                                  (("webauthn_trust_publications", "publication", "UPDATE", after),))
        result = self.assert_exact(fixture)
        self.assertEqual(len(result.after_heads), 3)
        for info in fixture.indexes.values():
            self.assertEqual(len(info["targets"]), 2)
            self.assertEqual(info["revision_delta"], 1)
        self.assertTrue(all(head.index_root.count == 1 and head.index_revision == 30 for head in result.after_heads))

    def test_session_grant_and_approval_binding_moves_and_membership_removals(self):
        cases = (("oidc_browser_sessions", "bound_webauthn_credential_id", "status", "active", "revoked"),
                 ("approval_grants", "approver_webauthn_credential_id", "state", "active", "inactive"),
                 ("control_plane_approvals", "approver_webauthn_credential_id", "status", "approved", "rejected"))
        for table, binding, field, member, nonmember in cases:
            before = {"id": "same-id", binding: "old-credential", field: member}
            if table == "oidc_browser_sessions":
                before["token_digest"] = "sha256:" + "a" * 64
            for after in ({**before, binding: "new-credential"}, {**before, field: nonmember}):
                with self.subTest(table=table, value=after[field]):
                    fixture = MutationFixture({table: [before]}, ((table, "same-id", "UPDATE", after),))
                    result = self.assert_exact(fixture)
                    self.assertEqual(len(result.after_heads), 2 if table == "oidc_browser_sessions" else 1)
                    for head in result.after_heads:
                        self.assertEqual(head.index_root.count,
                            1 if head.index_id == "oidc_session_token_digest" else int(after[field] == member))
                        self.assertEqual(head.index_revision, 30)

    def test_all_eleven_profiles_and_same_primary_id_across_tables_remain_distinct(self):
        # Retain the historical test ID while covering the exact current roster.
        identifier = CHALLENGE_ID
        tables = {
            "webauthn_credentials": [credential(identifier)],
            "webauthn_challenges": [challenge(identifier)],
            "oidc_browser_sessions": [{"id": identifier, "bound_webauthn_credential_id": "credential",
                "status": "active", "token_digest": "sha256:" + "a" * 64}],
            "oidc_session_activation_deliveries": [{"id": identifier, "session_id": "session",
                "old_token_digest": "sha256:" + "a" * 64, "new_token_digest": "sha256:" + "b" * 64,
                "assertion_digest": "sha256:" + "c" * 64, "challenge_id": identifier}],
            "approval_grants": [{"id": identifier, "approver_webauthn_credential_id": "credential", "state": "active"}],
            "control_plane_approvals": [{"id": identifier, "approver_webauthn_credential_id": "credential", "status": "approved"}],
            "webauthn_trust_publications": [{"id": identifier, "scope": "global", "status": "pending",
                "bundle_digest": "bundle", "rollback_epoch": 0, "sequence": 1}],
        }
        actions = tuple((table, identifier, "UPDATE", {**rows[0], "nonselector": "new-fullrow-雪"})
                        for table, rows in sorted(tables.items()))
        fixture = MutationFixture(tables, actions, expiry_before={identifier: 0})
        result = self.assert_exact(fixture)
        self.assertEqual(len(result.after_heads), 24)
        self.assertEqual({head.index_id for head in result.after_heads}, set(join_oracle.INDEX_IDS))
        self.assertEqual(len({row["keyDigest"] for row in fixture.selected}), 7)
        arguments = fixture.arguments()
        reordered = indexed.evaluate_indexed_primary_batch(**{**arguments,
            "selected_rows": tuple(reversed(arguments["selected_rows"])),
            "before_proofs": arguments["before_proofs"][1:] + arguments["before_proofs"][:1],
            "mutations": tuple(reversed(arguments["mutations"]))})
        self.assertEqual(reordered.before_heads, result.before_heads)
        self.assertEqual(reordered.after_heads, result.after_heads)
        self.assertEqual(reordered.primary.business_after_roots, result.primary.business_after_roots)

    def test_session_token_index_remains_required_and_populated_after_revocation(self):
        before = {"id": "session", "bound_webauthn_credential_id": "credential", "status": "active",
                  "token_digest": "sha256:" + "a" * 64}
        after = {**before, "status": "revoked"}
        fixture = MutationFixture({"oidc_browser_sessions": [before]},
            (("oidc_browser_sessions", "session", "UPDATE", after),))
        result = self.assert_exact(fixture)
        self.assertEqual({head.index_id: (head.index_revision, head.index_root.count)
                          for head in result.after_heads},
                         {"oidc_session_token_digest": (30, 1),
                          "webauthn_session_credential_status": (30, 0)})
        arguments = fixture.arguments()
        for omitted in ("oidc_session_token_digest", "webauthn_session_credential_status"):
            with self.subTest(omitted=omitted), self.assertRaisesRegex(
                    indexed.IndexedMutationError, "exactly every affected source profile"):
                indexed.evaluate_indexed_primary_batch(**{**arguments,
                    "index_inputs": tuple(item for item in arguments["index_inputs"] if item.index_id != omitted)})
        changed = MutationFixture({"oidc_browser_sessions": [before]},
            (("oidc_browser_sessions", "session", "UPDATE",
              {**after, "token_digest": "sha256:" + "b" * 64}),))
        self.assert_exact(changed)
        self.assertEqual(len(changed.indexes["oidc_session_token_digest"]["targets"]), 2)

    def test_equal_rows_advance_each_member_revision_even_when_all_digests_stay_equal(self):
        fixture = MutationFixture({"webauthn_credentials": [self.before]},
            (("webauthn_credentials", self.before["id"], "UPDATE", self.before),))
        result = self.assert_exact(fixture)
        self.assertEqual(result.primary.business_after_roots[0].root_digest,
                         fixture.trees["webauthn_credentials"].root.root_digest)
        for before, after in zip(result.before_heads, result.after_heads):
            self.assertEqual(before.index_root, after.index_root)
            self.assertEqual(after.index_revision, before.index_revision + 1)

    def test_explicit_delete_insert_moves_primary_id_and_advances_each_profile_twice(self):
        new = {**self.before, "id": "replacement"}
        fixture = MutationFixture({"webauthn_credentials": [self.before]},
            (("webauthn_credentials", self.before["id"], "DELETE", None),
             ("webauthn_credentials", new["id"], "INSERT", new)))
        result = self.assert_exact(fixture)
        self.assertEqual(result.primary.business_after_roots[0].root_revision, 19)
        for head in result.after_heads:
            self.assertEqual((head.index_revision, head.index_root.count), (31, 1))
        changed = self.fixture.arguments()
        changed["mutations"][0]["row"]["id"] = "replacement"
        with self.assertRaisesRegex(primary.PrimaryRadixMutationError, "original key changed"):
            indexed.evaluate_indexed_primary_batch(**changed)

    def test_primary_fullrow_cas_proof_and_selected_membership_fail_before_projection(self):
        for mode in ("selected-row", "old-cas", "proof-digest", "proof-content"):
            arguments = self.fixture.arguments()
            if mode == "selected-row":
                arguments["selected_rows"][0]["row"]["sign_count"] = 999
            elif mode == "old-cas":
                arguments["mutations"][0]["expectedRow"]["sign_count"] = 999
            else:
                arguments["before_proofs"][0]["rowDigest"] = "sha256:" + "0" * 64
                if mode == "proof-content":
                    primary_oracle.refresh_proof_digest(arguments["before_proofs"][0])
            actual_projection = indexed.projection.project_row
            with self.subTest(mode=mode), mock.patch.object(indexed.projection, "project_row", wraps=actual_projection) as project:
                with self.assertRaises(primary.PrimaryRadixMutationError):
                    indexed.evaluate_indexed_primary_batch(**arguments)
                self.assertEqual(project.call_count, 0)

    def test_missing_extra_duplicate_and_unsorted_index_heads_are_not_partial_success(self):
        arguments = self.fixture.arguments()
        inputs = arguments["index_inputs"]
        other = join_oracle.expected_profile("webauthn_registration_unused_global")
        empty = counted_oracle.IndependentIndex([], other)
        extra = indexed.IndexedMutationInput(other.index_id, 0, empty.root, ())
        for inventory in (inputs[:-1], (), tuple(sorted((*inputs, extra), key=lambda value: value.index_id))):
            with self.subTest(inventory=tuple(value.index_id for value in inventory)), \
                    self.assertRaisesRegex(indexed.IndexedMutationError, "exactly every affected source profile"):
                indexed.evaluate_indexed_primary_batch(**{**arguments, "index_inputs": inventory})
        for inventory in (inputs + (inputs[-1],), tuple(reversed(inputs))):
            with self.subTest(inventory=tuple(value.index_id for value in inventory)), \
                    self.assertRaisesRegex(indexed.IndexedMutationError, "source sorted and unique"):
                indexed.evaluate_indexed_primary_batch(**{**arguments, "index_inputs": inventory})

    def test_omitted_old_leaf_opaque_sibling_and_cross_profile_root_are_rejected(self):
        arguments = self.fixture.arguments()
        inputs = arguments["index_inputs"]
        first = inputs[0]
        leaf_ordinal = next(index for index, value in enumerate(first.frontier) if type(value) is contract.IndexLeaf)
        opaque_ordinal = next(index for index, value in enumerate(first.frontier) if type(value) is contract.OpaqueSubtree)
        for ordinal, reason in ((leaf_ordinal, "omitted a required before leaf"),
                                (opaque_ordinal, "reconstructed before root or count")):
            changed = replace(first, frontier=first.frontier[:ordinal] + first.frontier[ordinal + 1:])
            with self.subTest(ordinal=ordinal), self.assertRaisesRegex(sparse.IndexMutationError, reason):
                indexed.evaluate_indexed_primary_batch(**{**arguments, "index_inputs": (changed, *inputs[1:])})
        for changed in (replace(first, index_root=inputs[1].index_root),
                        replace(first, index_root=replace(first.index_root, count=first.index_root.count - 1))):
            with self.subTest(root=changed.index_root), self.assertRaisesRegex(sparse.IndexMutationError, "reconstructed before root"):
                indexed.evaluate_indexed_primary_batch(**{**arguments, "index_inputs": (changed, *inputs[1:])})

    def test_new_partition_path_requires_real_absence_not_an_opaque_or_existing_leaf(self):
        after = {**self.before, "credential_id": "new-partition"}
        fixture = MutationFixture({"webauthn_credentials": [self.before, credential("padding")]},
            (("webauthn_credentials", self.before["id"], "UPDATE", after),))
        self.assert_exact(fixture)
        arguments = fixture.arguments()
        item = arguments["index_inputs"][0]
        info = fixture.indexes[item.index_id]
        old = next(images[0] for images in info["targets"].values() if images[0] is not None)
        new = next(images[1] for images in info["targets"].values() if images[1] is not None)
        # Replace an unrelated indexed member, retaining the paired count,
        # with a bogus already-occupied new path. This is deliberately not a
        # globally consistent population; the touched absence must catch it.
        occupied = counted_oracle.IndependentIndex([old, new], info["profile"])
        bad_frontier = sparse_frontier(occupied, info["targets"])
        for supplied, reason in ((bad_frontier, "not its exact before image"),
                (tuple(value for value in bad_frontier if not
                       (type(value) is contract.IndexLeaf and value.key == new.key)), "reconstructed before root")):
            changed = replace(item, index_root=occupied.root, frontier=supplied)
            with self.subTest(reason=reason), self.assertRaisesRegex(sparse.IndexMutationError, reason):
                indexed.evaluate_indexed_primary_batch(**{**arguments,
                    "index_inputs": (changed, *arguments["index_inputs"][1:])})
        hidden = replace(item, frontier=(info["before"].opaque(old.key[:1]),))
        with self.assertRaisesRegex(sparse.IndexMutationError, "untouched immediate sibling"):
            indexed.evaluate_indexed_primary_batch(**{**arguments,
                "index_inputs": (hidden, *arguments["index_inputs"][1:])})

    def test_fixed_projection_validation_applies_to_both_verified_old_and_new_images(self):
        for field, value in (("attestation_trusted", True), ("user_id", None), ("credential_id", "\x00")):
            arguments = self.fixture.arguments()
            arguments["mutations"][0]["row"][field] = value
            with self.subTest(field=field), self.assertRaises(indexed.projection.IndexProjectionError):
                indexed.evaluate_indexed_primary_batch(**arguments)
        bad_old = credential(attestation_trusted=True)
        fixture = MutationFixture({"webauthn_credentials": [bad_old]},
            (("webauthn_credentials", bad_old["id"], "UPDATE", {**bad_old, "attestation_trusted": 1}),))
        with self.assertRaises(indexed.projection.IndexProjectionError):
            self.verify(fixture)
        before = challenge()
        fixture = MutationFixture({"webauthn_challenges": [before]},
            (("webauthn_challenges", CHALLENGE_ID, "UPDATE", before),), expiry_before={CHALLENGE_ID: 0})
        arguments = fixture.arguments()
        arguments["mutations"][0]["row"]["expires_at"] = "1970-01-01T00:00:00Z"
        with self.assertRaises(indexed.projection.IndexProjectionError):
            indexed.evaluate_indexed_primary_batch(**arguments)

    def test_before_and_after_index_counts_cannot_exceed_paired_primary_descriptors(self):
        arguments = self.fixture.arguments()
        item = arguments["index_inputs"][0]
        info = self.fixture.indexes[item.index_id]
        rogue = image_leaf(info["profile"], credential("rogue"))
        overfull = counted_oracle.IndependentIndex([*info["before"].leaves.values(), rogue], info["profile"])
        changed = replace(item, index_root=overfull.root, frontier=sparse_frontier(overfull, info["targets"]))
        with self.assertRaisesRegex(indexed.IndexedMutationError, "before count exceeds its primary population descriptor"):
            indexed.evaluate_indexed_primary_batch(**{**arguments,
                "index_inputs": (changed, *arguments["index_inputs"][1:])})
        excluded = credential("excluded", revoked_at="revoked")
        retained = credential("retained")
        fixture = MutationFixture({"webauthn_credentials": [excluded, retained]},
                                  (("webauthn_credentials", "excluded", "DELETE", None),))
        arguments = fixture.arguments()
        index_id = "webauthn_credential_live_trust"
        info = fixture.indexes[index_id]
        rogue = image_leaf(info["profile"], credential("rogue-live"))
        overfull = counted_oracle.IndependentIndex([*info["before"].leaves.values(), rogue], info["profile"])
        changed_inputs = tuple(replace(item, index_root=overfull.root, frontier=sparse_frontier(overfull, ()))
                              if item.index_id == index_id else item for item in arguments["index_inputs"])
        with self.assertRaisesRegex(indexed.IndexedMutationError, "after count exceeds its primary population descriptor"):
            indexed.evaluate_indexed_primary_batch(**{**arguments, "index_inputs": changed_inputs})
        # Necessary count consistency only, not an index-population theorem.

    def test_projection_consumes_only_owned_primary_and_presnapshotted_index_inputs(self):
        arguments = self.fixture.arguments()
        expected = indexed.evaluate_indexed_primary_batch(**copy.deepcopy(arguments))
        genuine = primary.evaluate_primary_radix_inputs
        called = []
        def verify_then_mutate_callers(**kwargs):
            verified = genuine(**kwargs)
            called.append(verified)
            arguments["selected_rows"][0]["row"]["user_id"] = "caller-old"
            arguments["mutations"][0]["expectedRow"]["user_id"] = "caller-cas"
            arguments["mutations"][0]["row"]["user_id"] = "caller-new"
            arguments["before_proofs"][0]["rowDigest"] = "sha256:" + "0" * 64
            object.__setattr__(arguments["business_before_roots"][0], "leaf_count", 0)
            item = arguments["index_inputs"][0]
            object.__setattr__(item, "index_revision", 999)
            object.__setattr__(item.index_root, "count", 0)
            leaf = next(value for value in item.frontier if type(value) is contract.IndexLeaf)
            object.__setattr__(leaf, "primary_row_digest", "sha256:" + "0" * 64)
            return verified
        with mock.patch.object(primary, "evaluate_primary_radix_inputs", verify_then_mutate_callers):
            result = indexed.evaluate_indexed_primary_batch(**arguments)
        self.assertEqual(len(called), 1)
        self.assertEqual(result, expected)
        self.assertNotEqual(called[0].mutations, arguments["mutations"])
        for value, field in ((result, "after_heads"), (result.after_heads[0], "index_revision"),
                             (result.after_heads[0].index_root, "count"), (result.metrics, "input_bytes")):
            with self.subTest(type=type(value)), self.assertRaises(FrozenInstanceError):
                setattr(value, field, 0)
        # The observer always invokes the real engine; this is controlled
        # caller mutation, not threaded execution or a verifier substitute.

    def test_aggregate_exact_budgets_and_delegated_phase_clamps_account_frontiers_once(self):
        arguments = self.fixture.arguments()
        expected = self.assert_exact(self.fixture)
        limits = replace(arguments["limits"], max_total_hashes=expected.metrics.hashes,
                         max_total_input_bytes=expected.metrics.input_bytes)
        primary_calls, index_calls = [], []
        genuine_primary = primary.evaluate_primary_radix_inputs
        genuine_index = sparse.evaluate_index_mutations
        def observe_primary(**kwargs):
            primary_calls.append(kwargs)
            return genuine_primary(**kwargs)
        def observe_index(**kwargs):
            index_calls.append(kwargs)
            return genuine_index(**kwargs)
        with mock.patch.object(primary, "evaluate_primary_radix_inputs", observe_primary), \
                mock.patch.object(sparse, "evaluate_index_mutations", observe_index):
            actual = indexed.evaluate_indexed_primary_batch(**{**arguments, "limits": limits})
        self.assertEqual(actual, expected)
        self.assertEqual(len(primary_calls), 1)
        reserved = {}
        for item in arguments["index_inputs"]:
            scalars = []
            for value in item.frontier:
                scalars.extend(("leaf", value.key, value.primary_key_digest, value.primary_row_digest)
                    if type(value) is contract.IndexLeaf else ("opaque", value.prefix, value.digest, str(value.count)))
            reserved[item.index_id] = sum(8 + len(value.encode("ascii")) for value in scalars)
        initial_bytes = context_bytes(arguments["index_inputs"]) + sum(reserved.values())
        self.assertEqual(primary_calls[0]["limits"].max_input_bytes,
                         min(limits.primary.max_input_bytes, limits.max_total_input_bytes - initial_bytes))
        self.assertEqual(primary_calls[0]["limits"].max_hashes,
                         min(limits.primary.max_hashes, limits.max_total_hashes))
        used_bytes = initial_bytes + expected.primary.metrics.input_bytes
        used_hashes = expected.primary.metrics.hash_work + expected.metrics.new_row_hashes
        self.assertEqual(len(index_calls), len(self.fixture.indexes))
        for call, (index_id, metrics) in zip(index_calls, expected.metrics.indexes):
            info = self.fixture.indexes[index_id]
            used_hashes += 1 + 4  # One profile and both nonnull images of this one mutation.
            self.assertEqual(call["profile"], info["profile"])
            self.assertEqual(call["changes"], tuple(sparse.IndexLeafChange(path, *images)
                for path, images in sorted(info["targets"].items())))
            self.assertEqual(call["limits"].max_hashes,
                             min(limits.index.max_hashes, limits.max_total_hashes - used_hashes))
            self.assertEqual(call["limits"].max_input_bytes,
                             min(limits.index.max_input_bytes, limits.max_total_input_bytes - used_bytes + reserved[index_id]))
            used_hashes += metrics.hashes
            used_bytes += metrics.input_bytes - reserved[index_id]
        self.assertEqual((used_hashes, used_bytes), (limits.max_total_hashes, limits.max_total_input_bytes))
        for field in ("max_total_hashes", "max_total_input_bytes"):
            with self.subTest(field=field), self.assertRaises((indexed.IndexedMutationError,
                    sparse.IndexMutationError, primary.PrimaryRadixMutationError)):
                indexed.evaluate_indexed_primary_batch(**{**arguments,
                    "limits": replace(limits, **{field: getattr(limits, field) - 1})})

    def test_malformed_contexts_and_preverified_containers_are_not_accepted_as_inputs(self):
        arguments = self.fixture.arguments()
        first = arguments["index_inputs"][0]
        class InputSubclass(indexed.IndexedMutationInput):
            pass
        bad = (None, {}, object.__new__(indexed.IndexedMutationInput), InputSubclass(**values(first)),
               forged(first, index_id="unknown"), forged(first, index_revision=True),
               forged(first, index_revision=-1), forged(first, index_revision=2**63),
               forged(first, frontier=[]), forged(first, frontier=(object(),)),
               forged(first, index_root=forged(first.index_root, count=True)))
        for item in bad:
            with self.subTest(kind=type(item)), self.assertRaises(contract.IndexRangeError):
                indexed.evaluate_indexed_primary_batch(**{**arguments,
                    "index_inputs": (item, *arguments["index_inputs"][1:])})
        result = indexed.evaluate_indexed_primary_batch(**arguments)
        for item in (list(arguments["index_inputs"]), result, arguments["index_inputs"] * 9):
            with self.subTest(kind=type(item)), self.assertRaisesRegex(indexed.IndexedMutationError, "bounded exact tuple"):
                indexed.evaluate_indexed_primary_batch(**{**arguments, "index_inputs": item})
        for name in ("verified_primary", "projection", "changes"):
            with self.subTest(keyword=name), self.assertRaises(TypeError):
                indexed.evaluate_indexed_primary_batch(**{**arguments, name: result})
        for field in ("max_total_hashes", "max_total_input_bytes"):
            with self.subTest(field=field), self.assertRaises(indexed.IndexedMutationError):
                indexed.evaluate_indexed_primary_batch(**{**arguments,
                    "limits": forged(arguments["limits"], **{field: True})})

    def test_index_genesis_and_revision_overflow_follow_membership_event_rules(self):
        fixture = MutationFixture({"webauthn_credentials": []},
            (("webauthn_credentials", self.before["id"], "INSERT", self.before),))
        arguments = fixture.arguments()
        genesis = tuple(replace(item, index_revision=0) for item in arguments["index_inputs"])
        result = indexed.evaluate_indexed_primary_batch(**{**arguments, "index_inputs": genesis})
        self.assertTrue(all(head.index_revision == 0 and head.index_root.count == 0 for head in result.before_heads))
        self.assertEqual(tuple(head.index_root for head in result.after_heads),
                         tuple(info["after"].root for _, info in sorted(fixture.indexes.items())))
        self.assertTrue(all(head.index_revision == 1 for head in result.after_heads))
        arguments = self.fixture.arguments()
        for revision, reason in ((0, "genesis count"), (2**63 - 1, "revision overflows")):
            inputs = tuple(replace(item, index_revision=revision) for item in arguments["index_inputs"])
            with self.subTest(revision=revision), self.assertRaisesRegex(indexed.IndexedMutationError, reason):
                indexed.evaluate_indexed_primary_batch(**{**arguments, "index_inputs": inputs})
        # Genesis here is only a supplied empty-tree state, not bootstrap or
        # initialization authorization for an installed database.

    def test_readonly_business_and_authorization_roots_preserve_real_primary_memberships(self):
        arguments = self.fixture.arguments()
        extra = primary_oracle.IndependentTree([{"id": "read-only", "value": 7}], table="items")
        auth = primary_oracle.IndependentTree([{"id": "auth", "allowed": True}], table="authorization")
        selections = (extra.selected({"id": "read-only"}), auth.selected({"id": "auth"}))
        result = indexed.evaluate_indexed_primary_batch(**{**arguments,
            "table_contracts": (*arguments["table_contracts"], extra.contract(writable=False),
                                auth.contract(writable=False, root_class="authorization")),
            "business_before_roots": (*arguments["business_before_roots"], extra.root),
            "authorization_before_roots": (auth.root,),
            "selected_rows": (*arguments["selected_rows"], *selections),
            "before_proofs": (auth.proof(selections[1]), *arguments["before_proofs"], extra.proof(selections[0]))})
        self.assertEqual(result.primary.business_after_roots,
                         (extra.root, self.fixture.after_trees["webauthn_credentials"].root))
        self.assertEqual(result.primary.authorization_after_roots, (auth.root,))
        self.assertEqual(result.after_heads, self.assert_exact(self.fixture).after_heads)

    def test_shared_primary_uses_real_remaining_hash_byte_and_node_limits(self):
        arguments = self.fixture.arguments()
        expected = primary_metrics(arguments)
        units = tuple(expected[name] for name in ("hash_work", "input_bytes", "json_nodes"))
        prior = (7, 101, 13)
        raw = {name: arguments[name] for name in ("table_contracts", "business_before_roots",
            "authorization_before_roots", "selected_rows", "before_proofs", "mutations")}
        for dimension in (None, 0, 1, 2):
            maxima = [left + right for left, right in zip(prior, units)]
            if dimension is not None:
                maxima[dimension] -= 1
            work = _ValidationWork(QueryReadValidationLimits(*maxima))
            work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
            budget = indexed._Budget(arguments["limits"], work=work)
            with self.subTest(dimension=dimension), mock.patch.object(primary,
                    "evaluate_primary_radix_inputs", wraps=primary.evaluate_primary_radix_inputs) as actual:
                if dimension is None:
                    verified = indexed._verify_primary(**raw, budget=budget)
                    self.assertEqual(values(verified.result.metrics), expected)
                    self.assertEqual((work.hash_work, work.input_bytes, work.json_nodes), tuple(maxima))
                    self.assertEqual((budget.hashes, budget.input_bytes, budget.json_nodes), units)
                    self.assertIs(budget.work, work)
                else:
                    with self.assertRaises(primary.PrimaryRadixMutationError):
                        indexed._verify_primary(**raw, budget=budget)
                self.assertEqual(actual.call_count, 1)
                limits = actual.call_args.kwargs["limits"]
                self.assertEqual((limits.max_hashes, limits.max_input_bytes, limits.max_json_nodes),
                    tuple(total - spent for total, spent in zip(maxima, prior)))

    def test_raw_owned_preparation_is_same_recipe_with_real_repeated_shared_hash_work(self):
        arguments = self.fixture.arguments()
        raw = {name: arguments[name] for name in ("table_contracts", "business_before_roots",
            "authorization_before_roots", "selected_rows", "before_proofs", "mutations")}
        verified = primary.evaluate_primary_radix_inputs(**raw, limits=arguments["limits"].primary)
        names = tuple(sorted(self.fixture.indexes))
        expected_hashes = sum(mutation["row"] is not None for mutation in self.fixture.mutations)
        expected_hashes += len(names) + sum(2 * (int(mutation["expectedRow"] is not None)
            + int(mutation["row"] is not None)) * len(PROFILE_TABLES[mutation["table"]])
            for mutation in self.fixture.mutations)
        prior = (5, 71, 11)
        work = _ValidationWork(QueryReadValidationLimits(max_hashes=prior[0] + 2 * expected_hashes))
        work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
        budget = indexed._Budget(arguments["limits"], work=work)
        with mock.patch.object(primary, "evaluate_primary_radix_inputs",
                side_effect=AssertionError("preparation repeated the primary proof")):
            for invocation in (1, 2):
                prepared = indexed._prepare_owned_primary_changes(mutations=verified.mutations,
                    before_proofs=verified.before_proofs,
                    business_after_roots=verified.result.business_after_roots,
                    index_ids=names, budget=budget)
                self.assertIsNone(prepared.verified)
                for item in arguments["index_inputs"]:
                    profile, changes, delta, allowance = indexed._prepare_index_changes(item, prepared, budget)
                    info = self.fixture.indexes[item.index_id]
                    self.assertEqual(profile, info["profile"])
                    self.assertEqual(changes, tuple(sparse.IndexLeafChange(key, *images)
                        for key, images in sorted(info["targets"].items())))
                    self.assertEqual(delta, info["revision_delta"])
                    self.assertEqual(allowance, 4)
                self.assertEqual((work.hash_work, work.input_bytes, work.json_nodes),
                    (prior[0] + invocation * expected_hashes, prior[1], prior[2]))
        legacy = indexed._Budget(arguments["limits"])
        with mock.patch.object(indexed, "_prepare_owned_primary_changes",
                wraps=indexed._prepare_owned_primary_changes) as inner:
            wrapped = indexed._prepare_primary_changes(verified, names, legacy)
        self.assertEqual(inner.call_count, 1)
        self.assertIs(wrapped.verified, verified)
        self.assertEqual(replace(wrapped, verified=None), prepared)
        # Raw descriptors are reusable internal values, not proof tokens. The
        # public evaluator still accepts only its original raw-input API.
        with self.assertRaises(TypeError):
            indexed.evaluate_indexed_primary_batch(**arguments, prepared=prepared)

    def test_owned_preparation_source_closure_precedes_hash_and_shared_exhaustion(self):
        arguments = self.fixture.arguments()
        raw = {name: arguments[name] for name in ("table_contracts", "business_before_roots",
            "authorization_before_roots", "selected_rows", "before_proofs", "mutations")}
        verified = primary.evaluate_primary_radix_inputs(**raw, limits=arguments["limits"].primary)
        names = tuple(sorted(self.fixture.indexes))
        for bad in ((), names[:-1], tuple(reversed(names))):
            work = _ValidationWork(QueryReadValidationLimits())
            with self.subTest(index_ids=bad), mock.patch.object(indexed.radix, "_tree_digest",
                    wraps=indexed.radix._tree_digest) as actual:
                with self.assertRaisesRegex(indexed.IndexedMutationError, "every affected source profile"):
                    indexed._prepare_owned_primary_changes(mutations=verified.mutations,
                        before_proofs=verified.before_proofs,
                        business_after_roots=verified.result.business_after_roots,
                        index_ids=bad, budget=indexed._Budget(arguments["limits"], work=work))
                self.assertEqual(actual.call_count, 0)
                self.assertEqual((work.hash_work, work.input_bytes, work.json_nodes), (0, 0, 0))
        work = _ValidationWork(QueryReadValidationLimits(max_hashes=1))
        work.charge(hashes=1)
        with mock.patch.object(indexed.radix, "_tree_digest", wraps=indexed.radix._tree_digest) as actual:
            with self.assertRaisesRegex(indexed.IndexedMutationError, "aggregate hash budget"):
                indexed._prepare_owned_primary_changes(mutations=verified.mutations,
                    before_proofs=verified.before_proofs,
                    business_after_roots=verified.result.business_after_roots,
                    index_ids=names, budget=indexed._Budget(arguments["limits"], work=work))
        self.assertEqual(actual.call_count, 0)
        self.assertEqual(work.hash_work, 1)


if __name__ == "__main__":
    unittest.main()
