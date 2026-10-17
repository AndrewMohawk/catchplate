#!/usr/bin/env python3
"""UNRUN connected JIT originals, real synthetic ES256 and independent trees.

The fixture has complete flat source-column rows, unlike a minimal semantic
fixture. Canonical raw chunks/proofs/frontiers cross the actual component
boundaries; no successful acquisition, receipt, primary or currentness DTO is
an input. The source projector is reused, so it is not an independent codec
oracle. This is not native SQL/TLS, a compound-clock/capacity test, root-currentness
admission, signed parent custody, or a complete deployed producer claim.
"""
from __future__ import annotations

import copy
from dataclasses import replace
from datetime import timedelta
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from catchplate import authority_jit_assertion_transition as semantics
from catchplate import authority_jit_indexed_phases as indexed
from catchplate import authority_jit_original_frames as raw
from catchplate import authority_jit_primary_rows as primary
from catchplate import authority_jit_receipt_absence as absence
from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork
from test_authority_index_range import IndependentIndex
from test_authority_jit_assertion_planning import configuration, originals
from test_authority_jit_primary_chunks import frames, native, row as flat_row
from test_authority_radix_mutation import IndependentTree, refresh_proof_digest
from test_authority_radix_proof import sql_digest, sql_json


def meter():
    return _ValidationWork(QueryReadValidationLimits())


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def projected_tree(identity, tree):
    profile = indexed.projection.profile_for(identity)
    leaves = []
    for row in tree.rows.values():
        selected = tree.selected(tree.key(row))
        digest = sql_digest("catchplate.policyAuthorityAuthenticatedRow/v1",
            profile.table.encode("ascii"), sql_json(row))
        leaf = indexed.projection.project_row(identity, row,
            primary_key_digest=selected["keyDigest"], primary_row_digest=digest)
        if leaf is not None:
            leaves.append(leaf)
    return IndependentIndex(leaves, profile=profile)


def connected_fixture():
    """Raw reusable anchors/trees only; the eighth key is not selected here."""
    values, request, minimal, _business, _authorization = originals()
    queries = primary.source.receipt.queries(request["arguments"])
    source_rows = {}
    for ordinal, query in enumerate(queries):
        selected = minimal[query.table].selected(query.absent_key)
        source_rows[query.table] = []
        if not selected["present"]:
            continue
        row = flat_row(ordinal)
        # Complete the source schema with ordinary synthetic scalar data.
        # Semantically meaningful assertion/policy/trust values below remain
        # the actual ES256 fixture originals, not successful verdicts.
        for name, value in tuple(row.items()):
            if value == "text" and name.endswith("_at"):
                row[name] = values["verified_at"].isoformat()
            elif value == "text" and name.endswith("_json"):
                row[name] = "{}"
            elif value == "text" and name.endswith("_digest"):
                row[name] = "sha256:" + "8" * 64
        if query.table == "webauthn_credentials":
            row.update(transports="[]", attestation_trust_path="[]")
        row.update(selected["row"])
        if set(row) != {name for name, _kind in raw.chunks._COLUMNS[query.table]}:
            raise AssertionError("connected fixture is not the complete source row")
        source_rows[query.table] = [row]
    source_rows[semantics.source.RECEIPT_TABLE] = []
    contracts = primary.source.primary_contract.primary_table_contracts(primary.source.OPERATION)
    trees = {item.table: IndependentTree(source_rows[item.table], table=item.table,
        columns=item.key_columns) for item in contracts}
    heads, inputs = [], []
    for identity in indexed.heads._jit_receipt_ids():
        profile = indexed.projection.profile_for(identity)
        counted = projected_tree(identity, trees[profile.table])
        head = indexed.read_write.CompleteReadWriteHead(identity, 7, counted.root)
        # The complete independent one-row tree supplies every occupied leaf;
        # this raw frontier makes no fold/completeness verdict of its own.
        frontier = tuple(counted.leaves[key] for key in sorted(counted.leaves))
        heads.append(head)
        inputs.append(indexed.indexed.IndexedMutationInput(identity, head.index_revision, head.index_root, frontier))
    delta = values["verified_at"] - primary._EPOCH
    cutoff = (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds
    return dict(request=request, assertion_policy=configuration()["assertion_policy"],
        business_before_roots=tuple(trees[item.table].root for item in contracts if item.root_class == "business"),
        authorization_before_roots=tuple(trees[item.table].root for item in contracts
            if item.root_class == "authorization"), counted_before_heads=tuple(heads),
        database_cutoff_us=cutoff, queries=queries, trees=trees, index_inputs=tuple(inputs))


def capture_seven(case, *, corrupt_original=False):
    owner = primary._JitPrimaryRows(request=case["request"],
        business_before_roots=case["business_before_roots"],
        authorization_before_roots=case["authorization_before_roots"],
        database_cutoff_us=case["database_cutoff_us"], work=meter())
    retained_chunks = []
    for ordinal, query in enumerate(case["queries"]):
        tree = case["trees"][query.table]
        selected = tree.selected(query.absent_key)
        codec = owner.begin_row(meter())
        supplied = copy.deepcopy(selected["row"])
        if corrupt_original and ordinal == 0:
            supplied["method"] = "changed-original"
        pages = tuple([record] for record in frames(native(supplied))) if selected["present"] else ([],)
        for page in pages:
            original = canonical(page)
            work = meter()
            owner.consume_chunk(raw.decode_chunk(original, work=work), work)
            retained = raw.encode_consumed_chunk(codec, work=work)
            if retained != original:
                raise AssertionError("actual consumed native chunk changed its retained bytes")
            retained_chunks.append(retained)
        actual = owner.decode_row(meter())
        if not corrupt_original and actual != selected:
            raise AssertionError("source native decoder changed independent original")
        work = meter()
        proof = raw.decode_proof(raw.encode_proof(tree.proof(selected), work=work), work=work)
        owner.admit_proof(proof, work)
    return owner, owner.finish(meter()), tuple(retained_chunks)


def first_receipt(captured, policy, *, shifted_cutoff=False):
    context = captured.context
    if shifted_cutoff:
        context = replace(context, database_now=context.database_now + timedelta(microseconds=1))
    owner = semantics._JitAssertionReceipt(context, assertion_policy=policy, work=meter())
    owner.actor_policy(meter())
    digest = owner.receipt(meter())
    return owner, digest


class JitConnectedOriginalControls(unittest.TestCase):
    def test_raw_seven_to_real_receipt_eighth_full_transition_and_all_indexed_roots(self):
        case = connected_fixture()
        rows, captured, retained_chunks = capture_seven(case)
        receipt, first_digest = first_receipt(captured, case["assertion_policy"])
        self.assertEqual(len(case["business_before_roots"]), 4)
        self.assertEqual(len(case["authorization_before_roots"]), 4)
        self.assertEqual(captured.business_before_roots, case["business_before_roots"])
        self.assertEqual(captured.authorization_before_roots, case["authorization_before_roots"])
        self.assertEqual(len(captured.context.selected_rows), 7)
        self.assertEqual(len(captured.context.query_reads), 7)
        self.assertIn(b"[]", retained_chunks)  # Real independent absent RBAC row.
        self.assertNotIn(semantics.source.RECEIPT_TABLE,
            {item["table"] for item in captured.context.selected_rows})
        eighth = absence._JitReceiptAbsence(rows=rows, receipt_owner=receipt, work=meter())
        query, root = eighth.query_inputs()
        self.assertEqual(query.absent_key, {"assertion_receipt_digest": first_digest})
        self.assertTrue(query.require_absence)
        self.assertEqual(root, case["trees"][query.table].root)
        selected = case["trees"][query.table].selected(query.absent_key)
        self.assertIs(selected["present"], False)
        work = meter()
        proof = raw.decode_proof(raw.encode_proof(case["trees"][query.table].proof(selected), work=work), work=work)
        eighth.admit(selected_row=selected, before_proof=proof, work=work)
        full = eighth.finish(meter())
        self.assertEqual(full.business_before_roots, case["business_before_roots"])
        self.assertEqual(full.authorization_before_roots, case["authorization_before_roots"])
        self.assertEqual(tuple(item.query_id for item in full.context.query_reads),
            tuple(item.query_id for item in (*case["queries"], query)))
        transition = semantics._JitAssertionTransition(full.context,
            assertion_policy=case["assertion_policy"], work=meter())
        self.assertIsNone(transition.actor_policy(meter()))
        self.assertEqual(transition.receipt(meter()), first_digest)
        self.assertEqual(transition._receipt, receipt._receipt)
        for stage in (transition.base_mutations, transition.normalize_selected, transition.normalize_mutations,
                transition.validate_inventory, transition.expand_inline):
            self.assertIsNone(stage(meter()))
        effects = transition.finish(meter())
        self.assertEqual(transition._phase, 9)
        self.assertEqual(len(effects.mutations), 3)
        mutations = {item["table"]: item for item in effects.mutations}
        receipt_mutation = mutations[semantics.source.RECEIPT_TABLE]
        self.assertEqual(receipt_mutation["row"], receipt._receipt)
        self.assertEqual(receipt_mutation["key"], query.absent_key)
        self.assertIsNone(receipt_mutation["expectedRow"])
        self.assertEqual(effects.result["assertion_receipt_digest"], first_digest)
        challenge = mutations["webauthn_challenges"]
        expected_challenge = {**challenge["expectedRow"], "used_at": receipt._receipt["verified_at"],
            "retention_reference_mask": 2, "retention_jit_receipt_digest": first_digest,
            "retention_jit_row_digest": sql_digest("catchplate.policyAuthorityAuthenticatedRow/v1",
                semantics.source.RECEIPT_TABLE.encode("ascii"), sql_json(receipt._receipt))}
        self.assertEqual(challenge["row"], expected_challenge)
        credential = mutations["webauthn_credentials"]
        self.assertEqual(credential["row"], {**credential["expectedRow"],
            "sign_count": receipt._receipt["sign_count_after"], "last_used_at": receipt._receipt["verified_at"],
            "updated_at": receipt._receipt["verified_at"]})
        owner = indexed._JitIndexedPhases(business_before_roots=full.business_before_roots,
            authorization_before_roots=full.authorization_before_roots,
            counted_before_heads=case["counted_before_heads"], work=meter())
        originals_by_table = {item["table"]: item for item in full.context.selected_rows}
        proofs_by_table = {item["table"]: item for item in full.before_proofs}
        for table in indexed.PRIMARY_TABLES:
            self.assertIsNone(owner.verify_primary(selected_row=originals_by_table[table],
                before_proof=proofs_by_table[table], mutation=mutations[table], work=meter()))
        self.assertIsNone(owner.prepare_primary(meter()))
        observations = []
        for original in case["index_inputs"]:
            observations.append(owner.prepare_index(meter()))
            work = meter()
            frontier = raw.decode_index(raw.encode_index(original, work=work), work=work)
            self.assertIsNone(owner.fold_index(frontier, work=work))
        actual = owner.finish(meter())
        self.assertEqual(len(actual.stage_work), 30)
        self.assertEqual(actual.result.metrics.primary.mutations, 3)
        self.assertEqual(actual.result.metrics.new_row_hashes, 2)
        self.assertEqual(len(actual.result.primary.business_after_roots), 4)
        self.assertEqual(actual.result.primary.authorization_after_roots, case["authorization_before_roots"])
        for root in actual.result.primary.authorization_after_roots:
            self.assertEqual(root, case["trees"][root.table].root)
        after_trees = {}
        for root in actual.result.primary.business_after_roots:
            tree = case["trees"][root.table]
            mutation = mutations.get(root.table)
            if mutation is None:
                self.assertEqual(root, tree.root)  # The read-only approval business root stays exact.
                continue
            remaining = [row for row in tree.rows.values() if tree.key(row) != mutation["key"]]
            after_trees[root.table] = IndependentTree([*remaining, mutation["row"]], table=tree.table,
                columns=tree.columns, revision=tree.root.root_revision + 1)
            self.assertEqual(root, after_trees[root.table].root)
        self.assertEqual(tuple(head.index_id for head in actual.result.after_heads), indexed.heads._jit_receipt_ids())
        for observation, head in zip(observations, actual.result.after_heads, strict=True):
            profile = indexed.projection.profile_for(head.index_id)
            self.assertEqual(head.index_root, projected_tree(head.index_id, after_trees[profile.table]).root)
            self.assertEqual(head.index_revision, observation.index_revision + int(bool(observation.changes)))

    def test_changed_original_shifted_cutoff_and_false_eighth_proof_are_refused(self):
        with self.subTest(defect="native-original"), self.assertRaises(ValueError):
            capture_seven(connected_fixture(), corrupt_original=True)
        case = connected_fixture()
        rows, captured, _raw = capture_seven(case)
        receipt, _digest = first_receipt(captured, case["assertion_policy"], shifted_cutoff=True)
        with self.subTest(defect="original-cutoff"), self.assertRaises(ValueError):
            absence._JitReceiptAbsence(rows=rows, receipt_owner=receipt, work=meter())
        case = connected_fixture()
        rows, captured, _raw = capture_seven(case)
        receipt, _digest = first_receipt(captured, case["assertion_policy"])
        owner = absence._JitReceiptAbsence(rows=rows, receipt_owner=receipt, work=meter())
        query, _root = owner.query_inputs()
        selected = case["trees"][query.table].selected(query.absent_key)
        proof = case["trees"][query.table].proof(selected)
        proof["siblings"][0]["childDigests"][0] = "sha256:" + "f" * 64
        refresh_proof_digest(proof)  # Self-consistent raw framing, not a genuine original-root proof.
        work = meter()
        proof = raw.decode_proof(raw.encode_proof(proof, work=work), work=work)
        with self.subTest(defect="eighth-membership"), self.assertRaises(ValueError):
            owner.admit(selected_row=selected, before_proof=proof, work=work)
        self.assertTrue(owner._failed)


if __name__ == "__main__":
    unittest.main()
