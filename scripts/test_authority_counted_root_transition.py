#!/usr/bin/env python3
"""Unrun root-relative counted write-document controls with real evaluators.

Independent primary/count trees and literal projection descriptors define the
oracles. Source operation contracts restrict table classes and work ceilings;
these small rows are not admitted kernel intents. No database, signer, current
checkpoint, complete query/read-head vector or Snapshot authority is supplied.
Observers always delegate the real verifier/hash, never substitute a success.
"""
from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError, replace
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_counted_root_transition as transition
from serverware import authority_index_contract as counted
from serverware import authority_indexed_mutation as indexed
from serverware import authority_index_projection as projection
from serverware import authority_primary_contract as primary_contract
from serverware import authority_radix_mutation as primary
from serverware import authority_radix_proof as radix
import test_authority_indexed_mutation as mutation_oracle
import test_authority_index_join as profile_oracle
import test_authority_radix_mutation as primary_oracle


COUNTER = "webauthn.counter.cas"
REVOKE = "webauthn.credential.revoke"
STAGE = "webauthn.trust.stage"
SCHEMA = "serverware.policyAuthorityCountedRootTransition/v1"
PROFILE = "serverware.policyAuthorityCountedRootTransitionProfile/v1"
COUNTED_PROFILE = "serverware.policyAuthorityCountedIndex/v1"
# Shared independent literal descriptors, not the source projector's manifest.
INDEX_IDS = profile_oracle.INDEX_IDS


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def framed(domain, payload):
    digest = hashlib.sha256()
    for value in (domain.encode("ascii"), payload):
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    return "sha256:" + digest.hexdigest()


def transition_digest(payload):
    # Wire documents retain the legacy domain+NUL family; counted projection
    # descriptors instead length-frame the domain as well as every payload.
    digest = hashlib.sha256(SCHEMA.encode("ascii") + b"\x00")
    digest.update(len(payload).to_bytes(8, "big"))
    digest.update(payload)
    return "sha256:" + digest.hexdigest()


def root_document(root):
    return {"table": root.table, "rootRevision": root.root_revision,
            "rootDigest": root.root_digest, "leafCount": root.leaf_count}


def projection_manifest():
    return framed("serverware.policyAuthorityIndexProjectionManifest/v1",
                  profile_oracle.utf8_json([profile_oracle.descriptor(name) for name in INDEX_IDS]))


class OperationFixture:
    """Full source primary closure plus independent affected-index populations."""
    def __init__(self, operation, tables, actions, *, extra_selections=()):
        self.operation = operation
        self.contracts = primary_contract.primary_table_contracts(operation)
        complete_tables = {item.table: copy.deepcopy(tables.get(item.table, [])) for item in self.contracts}
        if set(tables) - set(complete_tables):
            raise AssertionError("fixture row table is outside the genuine operation closure")
        initial_tables = {item.table: complete_tables[item.table] if item.key_columns == ("id",) else []
                          for item in self.contracts}
        if any(next(item.key_columns for item in self.contracts if item.table == action[0]) != ("id",)
               for action in actions):
            raise AssertionError("this component fixture mutates only source id-keyed rows")
        self.model = mutation_oracle.MutationFixture(initial_tables, actions)
        # MutationFixture's generic trees use id; rebuild source composite or
        # alternate-key tables even when empty, before selecting those rows.
        for item in self.contracts:
            if item.key_columns != ("id",):
                self.model.tables[item.table] = copy.deepcopy(complete_tables[item.table])
                self.model.after_tables[item.table] = copy.deepcopy(complete_tables[item.table])
            for inventory, rows in ((self.model.trees, complete_tables[item.table]),
                                    (self.model.after_trees, self.model.after_tables[item.table])):
                inventory[item.table] = primary_oracle.IndependentTree(rows, table=item.table,
                    columns=item.key_columns, revision=inventory[item.table].root.root_revision)
        self.selected = copy.deepcopy(self.model.selected)
        self.proofs = copy.deepcopy(self.model.proofs)
        for table, key in extra_selections:
            selected = self.model.trees[table].selected(key)
            self.selected += (selected,)
            self.proofs += (self.model.trees[table].proof(selected),)

    def arguments(self):
        return {"operation": self.operation,
            "business_before_roots": [root_document(self.model.trees[item.table].root)
                                      for item in self.contracts if item.root_class == "business"],
            "authorization_before_roots": [root_document(self.model.trees[item.table].root)
                                           for item in self.contracts if item.root_class == "authorization"],
            "selected_rows": copy.deepcopy(self.selected), "before_proofs": copy.deepcopy(self.proofs),
            "mutations": copy.deepcopy(self.model.mutations),
            "index_inputs": self.model.arguments()["index_inputs"]}

    def primary_arguments(self):
        return {"table_contracts": self.contracts,
            "business_before_roots": tuple(self.model.trees[item.table].root for item in self.contracts
                                           if item.root_class == "business"),
            "authorization_before_roots": tuple(self.model.trees[item.table].root for item in self.contracts
                                                if item.root_class == "authorization"),
            "selected_rows": self.selected, "before_proofs": self.proofs, "mutations": self.model.mutations}

    def expected_primary(self):
        names = {"selected_rows": "selectedRows", "mutations": "mutations", "proof_vectors": "proofVectors",
                 "proof_child_slots": "proofChildSlots", "recomputed_ancestors": "recomputedAncestors",
                 "hash_work": "hashWork", "input_bytes": "inputBytes", "json_nodes": "jsonNodes"}
        arguments = self.arguments()
        return {"schema": "serverware.policyAuthorityPrimaryRootTransition/v1",
            "profile": "serverware.policyAuthorityPrimaryRootTransitionProfile/v2",
            "businessBeforeRoots": arguments["business_before_roots"],
            "authorizationBeforeRoots": arguments["authorization_before_roots"],
            "businessAfterRoots": [root_document(self.model.after_trees[item.table].root)
                                   for item in self.contracts if item.root_class == "business"],
            "authorizationAfterRoots": [root_document(self.model.after_trees[item.table].root)
                                        for item in self.contracts if item.root_class == "authorization"],
            "metrics": {names[name]: value for name, value in
                        mutation_oracle.primary_metrics(self.primary_arguments()).items()}}

    def expected_heads(self, after=False):
        result = []
        for index_id, info in sorted(self.model.indexes.items()):
            profile = info["profile"]
            root = info["after" if after else "before"].root
            result.append({"indexId": index_id, "table": profile.table,
                "projectionDigest": profile.projection_digest,
                "indexRevision": info["revision_before"] + (info["revision_delta"] if after else 0),
                "rootDigest": root.digest, "leafCount": root.count})
        return result

    def expected_document(self):
        fields = {"changes": "changes", "frontier_entries": "frontierEntries", "opened_nodes": "openedNodes",
                  "child_slots": "childSlots", "before_hashes": "beforeHashes", "after_hashes": "afterHashes",
                  "input_bytes": "inputBytes"}
        indexes = [{"indexId": index_id, **{fields[name]: value for name, value in
                    mutation_oracle.index_metrics(info).items()}}
                   for index_id, info in sorted(self.model.indexes.items())]
        primary_value = self.expected_primary()
        projection_work = sum(2 * len(mutation_oracle.PROFILE_TABLES.get(item["table"], ()))
            * (int(item["expectedRow"] is not None) + int(item["row"] is not None)) for item in self.model.mutations)
        new_rows = sum(item["table"] in mutation_oracle.PROFILE_TABLES and item["row"] is not None
                       for item in self.model.mutations)
        context = len(self.model.indexes)
        metrics = {"indexes": indexes, "contextHashes": context, "projectionHashAllowance": projection_work,
            "newRowHashes": new_rows,
            "hashWork": primary_value["metrics"]["hashWork"] + context + projection_work + new_rows
                        + sum(row["beforeHashes"] + row["afterHashes"] for row in indexes),
            "inputBytes": primary_value["metrics"]["inputBytes"]
                          + mutation_oracle.context_bytes(self.arguments()["index_inputs"])
                          + sum(row["inputBytes"] for row in indexes)}
        return {"schema": SCHEMA, "profile": PROFILE, "scope": "write-effects-only", "operation": self.operation,
            "countedProfile": COUNTED_PROFILE, "projectionManifestDigest": projection_manifest(),
            "primaryTransition": primary_value, "indexBeforeHeads": self.expected_heads(),
            "indexAfterHeads": self.expected_heads(True), "metrics": metrics}


class CountedRootTransitionTests(unittest.TestCase):
    def setUp(self):
        self.before = mutation_oracle.credential()
        self.after = {**self.before, "sign_count": 4}
        self.fixture = OperationFixture(COUNTER,
            {"webauthn_credentials": [self.before, mutation_oracle.credential("untouched", user_id="another")]},
            (("webauthn_credentials", self.before["id"], "UPDATE", self.after),))

    def derive(self, fixture=None, **changes):
        arguments = (self.fixture if fixture is None else fixture).arguments()
        arguments.update(changes)
        return transition.derive_counted_root_transition(**arguments)

    def verify(self, value, fixture=None, **changes):
        arguments = (self.fixture if fixture is None else fixture).arguments()
        del arguments["business_before_roots"], arguments["authorization_before_roots"]
        arguments.update(changes)
        return transition.verify_counted_root_transition(value=value, **arguments)

    def assert_roots(self, result, fixture=None):
        fixture = self.fixture if fixture is None else fixture
        value = result.json_projection()
        self.assertEqual(value["primaryTransition"], fixture.expected_primary())
        self.assertEqual(value["indexBeforeHeads"], fixture.expected_heads())
        self.assertEqual(value["indexAfterHeads"], fixture.expected_heads(True))
        self.assertEqual(result.canonical_bytes, canonical(value))
        self.assertEqual(result.digest, transition_digest(canonical(value)))
        return value

    def test_exact_wire_metrics_and_packaging_have_independent_complete_oracles(self):
        result = self.derive()
        expected = self.fixture.expected_document()
        self.assertEqual(result.json_projection(), expected)
        self.assertEqual(result.canonical_bytes, canonical(expected))
        self.assertEqual(result.digest, transition_digest(canonical(expected)))
        self.assertEqual(result.packaging.wrapper_hash_allowance, 116)
        self.assertEqual(result.packaging.document_bytes, len(canonical(expected)))
        self.assertEqual(result.packaging.total_hash_work, 116 + expected["metrics"]["hashWork"])
        self.assertEqual(result.packaging.total_input_bytes,
                         len(canonical(expected)) + expected["metrics"]["inputBytes"])
        self.assertEqual(transition.counted_root_transition_digest(expected), result.digest)
        self.assertEqual(self.verify(expected).canonical_bytes, result.canonical_bytes)

    def test_real_combined_evaluation_once_retains_actual_primary_result_identity(self):
        calls = []
        original = indexed.evaluate_indexed_primary_batch
        def observe(**arguments):
            actual = original(**arguments)
            calls.append((arguments, actual))
            return actual
        with mock.patch.object(indexed, "evaluate_indexed_primary_batch", side_effect=observe):
            result = self.derive()
        self.assertEqual(len(calls), 1)
        self.assertIs(result.primary, calls[0][1].primary)
        self.assert_roots(result)
        self.assertEqual(calls[0][0]["table_contracts"], self.fixture.contracts)
        self.assertEqual(calls[0][0]["limits"].max_total_hashes, 8_000_000 - 116)
        self.assertEqual(calls[0][0]["limits"].max_total_input_bytes, 64 * 1024 * 1024 - 256 * 1024)

    def test_equal_update_advances_primary_and_all_member_revisions_without_hash_changes(self):
        fixture = OperationFixture(COUNTER, {"webauthn_credentials": [self.before]},
            (("webauthn_credentials", self.before["id"], "UPDATE", copy.deepcopy(self.before)),))
        value = self.assert_roots(self.derive(fixture), fixture)
        for before, after in zip(value["indexBeforeHeads"], value["indexAfterHeads"]):
            self.assertEqual(after, {**before, "indexRevision": before["indexRevision"] + 1})
        before = value["primaryTransition"]["businessBeforeRoots"][0]
        self.assertEqual(value["primaryTransition"]["businessAfterRoots"], [{**before, "rootRevision": 18}])

    def test_partition_move_and_nonmember_profile_preserve_exact_fixed_write_closure(self):
        old = {**self.before, "revoked_at": "already-revoked"}
        new = {**old, "credential_id": "another", "user_id": "next"}
        fixture = OperationFixture(COUNTER, {"webauthn_credentials": [old]},
                                  (("webauthn_credentials", old["id"], "UPDATE", new),))
        value = self.assert_roots(self.derive(fixture), fixture)
        self.assertEqual(len(value["indexBeforeHeads"]), 3)
        for before, after in zip(value["indexBeforeHeads"], value["indexAfterHeads"]):
            if before["indexId"] == "webauthn_credential_live_trust":
                self.assertEqual(before, after)
            else:
                self.assertEqual(after["indexRevision"], before["indexRevision"] + 1)
                self.assertNotEqual(after["rootDigest"], before["rootDigest"])

    def test_normalized_primary_key_delete_insert_advances_twice_and_update_cannot_move_key(self):
        new = {**self.before, "id": "replacement"}
        fixture = OperationFixture(REVOKE, {"webauthn_credentials": [self.before]},
            (("webauthn_credentials", self.before["id"], "DELETE", None),
             ("webauthn_credentials", new["id"], "INSERT", new)))
        value = self.assert_roots(self.derive(fixture), fixture)
        self.assertEqual({head["indexRevision"] for head in value["indexAfterHeads"]}, {31})
        arguments = self.fixture.arguments()
        arguments["mutations"][0]["row"]["id"] = "not-the-selected-key"
        with self.assertRaises(transition.CountedRootTransitionError):
            transition.derive_counted_root_transition(**arguments)

    def test_omitted_duplicate_extra_or_swapped_write_profiles_are_rejected(self):
        source = self.fixture.arguments()["index_inputs"]
        altered = replace(source[0], index_id=source[1].index_id)
        extra_profile = profile_oracle.expected_profile("webauthn_publication_status")
        empty = mutation_oracle.counted_oracle.IndependentIndex([], extra_profile)
        extra = indexed.IndexedMutationInput(extra_profile.index_id, 0, empty.root, ())
        for inputs in (source[:-1], (source[0], *source), tuple(reversed(source)),
                       (altered, *source[1:]), tuple(sorted((*source, extra), key=lambda value: value.index_id))):
            with self.subTest(inputs=inputs), self.assertRaises(transition.CountedRootTransitionError):
                self.derive(index_inputs=inputs)

    def test_supplied_result_object_is_not_an_accepted_verification_capability(self):
        result = self.derive()
        for value in (result, result.primary):
            with self.subTest(value=type(value)), self.assertRaises(transition.CountedRootTransitionError):
                self.verify(value)
        with self.assertRaises(TypeError):
            transition.derive_counted_root_transition(**self.fixture.arguments(), verified_result=result.primary)

    def test_primary_inventory_includes_unchanged_and_read_only_operation_roots(self):
        publication = {"id": "publication", "scope": "global", "status": "pending", "bundle_digest": "bundle",
                       "rollback_epoch": 0, "sequence": 1}
        high_water = {"authority_scope": "global", "sequence": 1}
        fixture = OperationFixture(STAGE,
            {"webauthn_trust_publications": [publication], "webauthn_trust_publication_high_water": [high_water]},
            (("webauthn_trust_publications", "publication", "UPDATE", {**publication, "status": "published"}),),
            extra_selections=(("webauthn_trust_publication_high_water", {"authority_scope": "global"}),))
        value = self.assert_roots(self.derive(fixture), fixture)
        roots = value["primaryTransition"]
        self.assertTrue(roots["authorizationBeforeRoots"])
        self.assertEqual(roots["authorizationBeforeRoots"], roots["authorizationAfterRoots"])
        arguments = fixture.arguments()
        for field in ("business_before_roots", "authorization_before_roots"):
            with self.subTest(field=field), self.assertRaises(transition.CountedRootTransitionError):
                self.derive(fixture, **{field: arguments[field][:-1]})
        with self.assertRaises(transition.CountedRootTransitionError):
            self.derive(fixture, business_before_roots=arguments["authorization_before_roots"],
                        authorization_before_roots=arguments["business_before_roots"])
        altered = copy.deepcopy(value)
        altered["primaryTransition"]["authorizationAfterRoots"][0]["rootRevision"] += 1
        with self.assertRaises(transition.CountedRootTransitionError):
            self.verify(altered, fixture)
        broader = OperationFixture(REVOKE, {"webauthn_credentials": [self.before]},
            (("webauthn_credentials", self.before["id"], "UPDATE", self.after),))
        self.assert_roots(self.derive(broader), broader)
        roots = broader.arguments()["business_before_roots"]
        self.assertIn("metadata_audit_outbox", {item["table"] for item in roots})
        with self.assertRaises(transition.CountedRootTransitionError):
            self.derive(broader, business_before_roots=[item for item in roots if item["table"] != "metadata_audit_outbox"])

    def test_read_only_counted_profiles_are_not_claimed_by_write_effects_document(self):
        fixture = OperationFixture(COUNTER, {"webauthn_credentials": [self.before]}, (),
            extra_selections=(("webauthn_credentials", {"id": self.before["id"]}),))
        value = self.assert_roots(self.derive(fixture), fixture)
        self.assertEqual(value["scope"], "write-effects-only")
        self.assertEqual((value["indexBeforeHeads"], value["indexAfterHeads"], value["metrics"]["indexes"]), ([], [], []))
        self.assertEqual(value["primaryTransition"]["businessBeforeRoots"], value["primaryTransition"]["businessAfterRoots"])
        for field in ("queryEvidence", "completeQueryRoots", "snapshot"):
            self.assertNotIn(field, value)
        with self.assertRaises(transition.CountedRootTransitionError):
            self.derive(fixture, index_inputs=self.fixture.arguments()["index_inputs"])

    def test_actual_primary_proof_old_row_and_counted_frontier_corruption_reject(self):
        arguments = self.fixture.arguments()
        damaged_proof = copy.deepcopy(arguments["before_proofs"])
        damaged_proof[0]["siblings"][20]["childDigests"][0] = "sha256:" + "f" * 64
        primary_oracle.refresh_proof_digest(damaged_proof[0])
        with self.assertRaises(transition.CountedRootTransitionError):
            self.derive(before_proofs=damaged_proof)
        bad_changes = copy.deepcopy(arguments["mutations"])
        bad_changes[0]["expectedRow"]["metadata"]["note"] = "not-the-proven-old-image"
        with self.assertRaises(transition.CountedRootTransitionError):
            self.derive(mutations=bad_changes)
        inputs = arguments["index_inputs"]
        entry = inputs[0]
        leaf_index = next(number for number, value in enumerate(entry.frontier) if type(value) is counted.IndexLeaf)
        frontier = list(entry.frontier)
        frontier[leaf_index] = replace(frontier[leaf_index], primary_row_digest="sha256:" + "e" * 64)
        for corrupt in (tuple(frontier), ()):
            with self.subTest(frontier=corrupt), self.assertRaises(transition.CountedRootTransitionError):
                self.derive(index_inputs=(replace(entry, frontier=corrupt), *inputs[1:]))

    def test_claimed_after_roots_revisions_and_metrics_must_equal_real_recomputation(self):
        value = self.derive().json_projection()
        variants = []
        for field, replacement in (("rootDigest", "sha256:" + "f" * 64),
                                   ("leafCount", value["indexAfterHeads"][0]["leafCount"] + 1),
                                   ("indexRevision", value["indexAfterHeads"][0]["indexRevision"] + 1)):
            changed = copy.deepcopy(value)
            changed["indexAfterHeads"][0][field] = replacement
            variants.append(changed)
        changed = copy.deepcopy(value)
        changed["primaryTransition"]["businessAfterRoots"][0]["rootRevision"] += 1
        variants.append(changed)
        changed = copy.deepcopy(value)
        changed["metrics"]["newRowHashes"] -= 1
        changed["metrics"]["hashWork"] -= 1
        # This closed, internally summed claim is still not genuine evidence.
        self.assertEqual(transition.validate_counted_root_transition(changed), changed)
        variants.append(changed)
        for ordinal, changed in enumerate(variants):
            with self.subTest(case=ordinal), self.assertRaises(transition.CountedRootTransitionError):
                self.verify(changed)

    def test_wire_envelope_profile_manifest_head_shapes_and_extra_fields_are_closed(self):
        value = self.derive().json_projection()
        variants = [None, (), self.derive(), {**value, "extra": None},
                    {key: item for key, item in value.items() if key != "scope"}]
        for field, replacement in (("schema", SCHEMA + "x"), ("profile", PROFILE + "x"),
                                   ("scope", "complete-query-and-write"), ("countedProfile", COUNTED_PROFILE + "x"),
                                   ("projectionManifestDigest", "sha256:" + "f" * 64), ("operation", "unknown")):
            variants.append({**value, field: replacement})
        for field, replacement in (("indexId", "unknown_index"), ("table", "webauthn_challenges"),
                                   ("projectionDigest", "sha256:" + "f" * 64), ("extra", None)):
            changed = copy.deepcopy(value)
            changed["indexBeforeHeads"][0][field] = replacement
            variants.append(changed)
        for changed in variants:
            with self.subTest(kind=type(changed)), self.assertRaises(transition.CountedRootTransitionError):
                transition.validate_counted_root_transition(changed)

    def test_exact_integer_revision_count_and_metric_types_reject_aliases(self):
        value = self.derive().json_projection()
        for replacement in (True, False, 29.0, "29", -1, 2**63):
            for vector, field in (("indexBeforeHeads", "indexRevision"), ("indexAfterHeads", "leafCount")):
                changed = copy.deepcopy(value)
                changed[vector][0][field] = replacement
                with self.subTest(vector=vector, field=field, replacement=replacement), self.assertRaises(transition.CountedRootTransitionError):
                    transition.validate_counted_root_transition(changed)
        for field in ("contextHashes", "projectionHashAllowance", "newRowHashes", "hashWork", "inputBytes"):
            changed = copy.deepcopy(value)
            changed["metrics"][field] = float(changed["metrics"][field])
            with self.subTest(field=field), self.assertRaises(transition.CountedRootTransitionError):
                transition.validate_counted_root_transition(changed)
        changed = copy.deepcopy(value)
        changed["primaryTransition"]["businessBeforeRoots"][0]["rootRevision"] = True
        with self.assertRaises(transition.CountedRootTransitionError):
            transition.validate_counted_root_transition(changed)

    def test_returned_bytes_and_fresh_projection_are_immutable_owned_observations(self):
        result = self.derive()
        original_bytes = result.canonical_bytes
        first, second = result.json_projection(), result.json_projection()
        first["indexBeforeHeads"][0]["rootDigest"] = "sha256:" + "f" * 64
        first["primaryTransition"]["businessBeforeRoots"].clear()
        self.assertEqual(result.canonical_bytes, original_bytes)
        self.assertEqual(result.json_projection(), second)
        validated = transition.validate_counted_root_transition(second)
        validated["metrics"]["indexes"].clear()
        self.assertTrue(second["metrics"]["indexes"])
        for target, field, replacement in ((result, "digest", "sha256:" + "e" * 64),
                                          (result.packaging, "total_hash_work", 0)):
            with self.subTest(field=field), self.assertRaises(FrozenInstanceError):
                setattr(target, field, replacement)

    def test_primary_before_vectors_are_owned_before_first_real_context_hash(self):
        publication = {"id": "publication", "scope": "global", "status": "pending", "bundle_digest": "bundle",
                       "rollback_epoch": 0, "sequence": 1}
        high_water = {"authority_scope": "global", "sequence": 1}
        stage = OperationFixture(STAGE,
            {"webauthn_trust_publications": [publication], "webauthn_trust_publication_high_water": [high_water]},
            (("webauthn_trust_publications", "publication", "UPDATE", {**publication, "status": "published"}),),
            extra_selections=(("webauthn_trust_publication_high_water", {"authority_scope": "global"}),))
        self.assertTrue(stage.arguments()["authorization_before_roots"])
        original = projection._framed_hash
        for fixture in (self.fixture, stage):
            with self.subTest(operation=fixture.operation):
                arguments = fixture.arguments()
                expected = fixture.expected_document()
                changed = []
                def observe(*values):
                    if not changed:
                        changed.append(True)
                        for field in ("business_before_roots", "authorization_before_roots"):
                            for descriptor in arguments[field]:
                                descriptor["rootRevision"] += 500
                                descriptor["rootDigest"] = "sha256:" + "f" * 64
                    return original(*values)
                with mock.patch.object(projection, "_framed_hash", side_effect=observe):
                    result = transition.derive_counted_root_transition(**arguments)
                self.assertEqual(changed, [True])
                self.assertEqual(result.json_projection(), expected)

    def test_owned_claim_document_cannot_change_during_actual_verification_context_hash(self):
        value = self.derive().json_projection()
        expected = copy.deepcopy(value)
        original = projection._framed_hash
        changed = []
        def observe(*values):
            if not changed:
                changed.append(True)
                value["indexAfterHeads"][0]["indexRevision"] += 500
                value["metrics"]["hashWork"] = 1
            return original(*values)
        with mock.patch.object(projection, "_framed_hash", side_effect=observe):
            result = self.verify(value)
        self.assertEqual(changed, [True])
        self.assertEqual(result.json_projection(), expected)

    def test_engine_owned_images_frontier_and_roots_survive_later_real_hash_callback(self):
        arguments = self.fixture.arguments()
        expected = self.fixture.expected_document()
        original_snapshot, original_hash = primary._Budget.snapshot, radix._tree_digest
        state = {"snapshot_complete": False, "mutated": False}
        def snapshot(budget, value, depth=0, ancestors=frozenset()):
            result = original_snapshot(budget, value, depth, ancestors)
            if depth == 0:
                state["snapshot_complete"] = True
            return result
        def hashed(*values):
            if state["snapshot_complete"] and not state["mutated"]:
                state["mutated"] = True
                arguments["selected_rows"][0]["row"]["metadata"]["note"] = "caller changed"
                arguments["mutations"][0]["row"]["sign_count"] = 999
                arguments["before_proofs"][0]["siblings"].clear()
                arguments["business_before_roots"][0]["rootRevision"] = 999
                object.__setattr__(arguments["index_inputs"][0].index_root, "digest", "sha256:" + "f" * 64)
                first_leaf = next(item for item in arguments["index_inputs"][0].frontier
                                  if type(item) is counted.IndexLeaf)
                object.__setattr__(first_leaf, "primary_row_digest", "sha256:" + "e" * 64)
            return original_hash(*values)
        with mock.patch.object(primary._Budget, "snapshot", new=snapshot), \
                mock.patch.object(radix, "_tree_digest", side_effect=hashed):
            result = transition.derive_counted_root_transition(**arguments)
        self.assertEqual(state, {"snapshot_complete": True, "mutated": True})
        self.assertEqual(result.json_projection(), expected)

    def test_verification_reuses_one_real_combined_evaluation_not_a_cached_success(self):
        claimed = self.derive().json_projection()
        original = indexed.evaluate_indexed_primary_batch
        observed = []
        def evaluate(**arguments):
            result = original(**arguments)
            observed.append(result)
            return result
        with mock.patch.object(indexed, "evaluate_indexed_primary_batch", side_effect=evaluate):
            verified = self.verify(claimed)
        self.assertEqual(len(observed), 1)
        self.assertIs(verified.primary, observed[0].primary)
        changed = copy.deepcopy(self.fixture.arguments()["mutations"])
        changed[0]["row"]["sign_count"] = 50
        observed.clear()
        with mock.patch.object(indexed, "evaluate_indexed_primary_batch", side_effect=evaluate), \
                self.assertRaises(transition.CountedRootTransitionError):
            self.verify(claimed, mutations=changed)
        self.assertEqual(len(observed), 1)

    def test_operation_inventory_and_document_work_bounds_are_not_caller_expandable(self):
        self.assertEqual((transition.WRAPPER_HASH_ALLOWANCE, transition.MAX_DOCUMENT_BYTES,
                          transition.MAX_TOTAL_HASHES, transition.MAX_TOTAL_INPUT_BYTES),
                         (116, 256 * 1024, 8_000_000, 64 * 1024 * 1024))
        original = indexed.evaluate_indexed_primary_batch
        arguments = self.fixture.arguments()
        oversized = (("selected_rows", arguments["selected_rows"] * 257),
                     ("mutations", arguments["mutations"] * 513))
        for name, value in oversized:
            with self.subTest(field=name), mock.patch.object(indexed, "evaluate_indexed_primary_batch", wraps=original) as engine:
                changes = {name: value}
                if name == "selected_rows":
                    changes["before_proofs"] = arguments["before_proofs"] * 257
                with self.assertRaises(transition.CountedRootTransitionError):
                    self.derive(**changes)
                engine.assert_not_called()
        with self.assertRaises(TypeError):
            transition.derive_counted_root_transition(**arguments, max_total_hashes=9_000_000)
        value = self.derive().json_projection()
        # Oversized malformed scalars, not a claim that a valid closed wire
        # can reach its 256-KiB ceiling or that input allocations are bounded.
        for field in ("operation", "projectionManifestDigest"):
            altered = {**value, field: "x" * (256 * 1024 + 1)}
            with self.subTest(field=field), self.assertRaises(transition.CountedRootTransitionError):
                transition.validate_counted_root_transition(altered)
        altered = copy.deepcopy(value)
        altered["metrics"]["hashWork"] = 8_000_000
        with self.assertRaises(transition.CountedRootTransitionError):
            transition.validate_counted_root_transition(altered)
        # Every scalar and array separately satisfies the snapshot's source
        # shape limits, but their aggregate compact wire is 301,843 bytes.
        # This malformed outer graph is deliberately only a copier-bound
        # control, not a claim that valid transition documents reach the cap.
        graph = [["x" * 128] * 256 for _ in range(9)]
        self.assertEqual(2 + 8 + 9 * (2 + 255 + 256 * 130), 301843)
        observed = []
        original_canonical = transition.canonical_bytes
        def encode(item):
            observed.append(type(item))
            return original_canonical(item)
        with mock.patch.object(transition, "canonical_bytes", side_effect=encode), \
                self.assertRaisesRegex(transition.CountedRootTransitionError, "canonical byte bound"):
            transition.validate_counted_root_transition(graph)
        self.assertEqual(observed, [str] * 2001)
        # The last bounded scalar is encoded before its charge rejects; no
        # array/object or complete oversized document reaches serialization.

    def test_current_source_context_hash_inventory_is_exact_and_finite(self):
        with mock.patch.object(projection, "profile_for", wraps=projection.profile_for) as profiles, \
                mock.patch.object(counted, "empty_node", wraps=counted.empty_node) as empties, \
                mock.patch.object(projection, "projection_manifest_digest",
                    wraps=projection.projection_manifest_digest) as manifest:
            context = transition._context(COUNTER)
        self.assertEqual(profiles.call_args_list, [mock.call(name) for name in INDEX_IDS])
        self.assertEqual(empties.call_args_list,
                         [mock.call(context.profiles[name], "") for name in INDEX_IDS])
        self.assertEqual((len(context.profiles), profiles.call_count, empties.call_count, manifest.call_count),
                         (24, 24, 24, 1))
        self.assertEqual(max(sum(value.table == table for value in context.profiles.values())
                             for table in {value.table for value in context.profiles.values()}), 9)
        with mock.patch.object(transition, "framed_digest", wraps=transition.framed_digest) as digest:
            result = self.derive()
        self.assertEqual(digest.call_args_list, [mock.call(SCHEMA, result.canonical_bytes)])
        self.assertEqual(result.packaging.wrapper_hash_allowance, 66 + 24 + 24 + 1 + 1)

    def test_changed_source_inventory_and_overbound_head_metrics_are_refused(self):
        variants = (INDEX_IDS[:-1], (*INDEX_IDS, "unknown_index"), tuple(reversed(INDEX_IDS)),
                    (*INDEX_IDS[:-1], "unknown_index"), (*INDEX_IDS[:-1], INDEX_IDS[0]), list(INDEX_IDS))
        for ordinal, inventory in enumerate(variants):
            with self.subTest(inventory=ordinal), mock.patch.object(projection, "INDEX_IDS", inventory), \
                    mock.patch.object(projection, "profile_for", wraps=projection.profile_for) as profiles, \
                    mock.patch.object(counted, "empty_node", wraps=counted.empty_node) as empties:
                with self.assertRaisesRegex(transition.CountedRootTransitionError, "inventory changed"):
                    transition._context(COUNTER)
                self.assertEqual((profiles.call_count, empties.call_count), (0, 0))
        for work in (3, 2.0, True):
            with self.subTest(row_hash_work=work), mock.patch.object(projection, "ROW_HASH_WORK", work), \
                    mock.patch.object(projection, "profile_for", wraps=projection.profile_for) as profiles:
                with self.assertRaisesRegex(transition.CountedRootTransitionError, "inventory changed"):
                    transition._context(COUNTER)
                profiles.assert_not_called()
        genuine_profile = projection.profile_for
        def changed_table(name):
            profile = genuine_profile(name)
            return (replace(profile, table="fixture_changed_table")
                    if name == "webauthn_challenge_value" else profile)
        with mock.patch.object(projection, "profile_for", side_effect=changed_table), \
                mock.patch.object(counted, "empty_node", wraps=counted.empty_node) as empties:
            with self.assertRaisesRegex(transition.CountedRootTransitionError, "table profile/hash inventory changed"):
                transition._context(COUNTER)
            empties.assert_not_called()
        value = self.derive().json_projection()
        too_many = copy.deepcopy(value)
        too_many["indexBeforeHeads"] *= 9  # 27 entries exceed the exact 24-profile cap.
        with self.assertRaisesRegex(transition.CountedRootTransitionError, "bounded array"):
            transition.validate_counted_root_transition(too_many)
        for field, number in (("contextHashes", 25), ("projectionHashAllowance", 38)):
            changed = copy.deepcopy(value)
            changed["metrics"][field] = number
            with self.subTest(metric=field), self.assertRaisesRegex(
                    transition.CountedRootTransitionError, "exact bounded value"):
                transition.validate_counted_root_transition(changed)

    def test_nine_challenge_profiles_charge_real_work_and_require_every_head(self):
        before = mutation_oracle.challenge()
        after = {**before, "used_at": mutation_oracle.EPOCH}
        fixture = OperationFixture(REVOKE, {"webauthn_challenges": [before]},
            (("webauthn_challenges", before["id"], "UPDATE", after),))
        result = self.derive(fixture)
        value = self.assert_roots(result, fixture)
        self.assertEqual(value, fixture.expected_document())
        self.assertEqual((len(value["indexBeforeHeads"]), value["metrics"]["contextHashes"],
                          value["metrics"]["projectionHashAllowance"]), (9, 9, 36))
        inputs = fixture.arguments()["index_inputs"]
        for omitted in ("webauthn_registration_unused_global", "webauthn_challenge_value"):
            with self.subTest(omitted=omitted), self.assertRaises(transition.CountedRootTransitionError):
                self.derive(fixture, index_inputs=tuple(item for item in inputs if item.index_id != omitted))
        altered = copy.deepcopy(value)
        altered["metrics"]["projectionHashAllowance"] -= 2
        altered["metrics"]["hashWork"] -= 2
        self.assertEqual(transition.validate_counted_root_transition(altered), altered)
        with mock.patch.object(indexed, "evaluate_indexed_primary_batch",
                wraps=indexed.evaluate_indexed_primary_batch) as engine:
            with self.assertRaisesRegex(transition.CountedRootTransitionError, "recomputed complete write delta"):
                self.verify(altered, fixture)
            self.assertEqual(engine.call_count, 1)

    def test_int64_revision_overflow_and_bypassed_counted_contexts_fail_closed(self):
        inputs = self.fixture.arguments()["index_inputs"]
        for revision in (True, 29.0, -1, 2**63, 2**63 - 1):
            with self.subTest(revision=revision), self.assertRaises(transition.CountedRootTransitionError):
                self.derive(index_inputs=(replace(inputs[0], index_revision=revision), *inputs[1:]))
        for field, replacement in (("count", True), ("digest", "not-a-digest")):
            forged = object.__new__(counted.CountedNode)
            object.__setattr__(forged, "count", inputs[0].index_root.count)
            object.__setattr__(forged, "digest", inputs[0].index_root.digest)
            object.__setattr__(forged, field, replacement)
            with self.subTest(field=field), self.assertRaises(transition.CountedRootTransitionError):
                self.derive(index_inputs=(replace(inputs[0], index_root=forged), *inputs[1:]))
        old = {**self.before, "revoked_at": "already-revoked"}
        fixture = OperationFixture(COUNTER, {"webauthn_credentials": [old]},
                                  (("webauthn_credentials", old["id"], "UPDATE", {**old, "sign_count": 50}),))
        fixture.model.indexes["webauthn_credential_live_trust"]["revision_before"] = 2**63 - 1
        result = self.derive(fixture)
        self.assertEqual(result.json_projection(), fixture.expected_document())


if __name__ == "__main__":
    unittest.main()
