#!/usr/bin/env python3
"""Pure actual-code controls, not PostgreSQL/current-root/native admission.

Synthetic full SQL rows and independent radix trees exercise the actual closed
chunk/replay schedule, token join and membership engine. They do not authenticate
the test request, current roots, native challenge, route policy or cold owner.
The head controls exercise purpose domains/framing only, not an enrolled live
root service. No connections, injected successful authority or provider calls.
"""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import sys
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware import authority_current_root_decisions as decisions
from serverware import authority_current_root_service as service
from serverware import authority_native_jit_review_current_read as source
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork
from test_authority_native_jit_review_current_chunks import frames, native, row as template_row
from test_authority_radix_mutation import IndependentTree, refresh_proof_digest


TOKEN = b"A" * 64
DIGEST = "sha256:" + "a" * 64


def meter():
    return _ValidationWork(QueryReadValidationLimits())


def window():
    work = meter()
    return source.head.clock._open_on_work(deadline_epoch_ns=time.time_ns() + 30_000_000_000,
        maximum_lifetime_ns=30_000_000_000, maximum_clock_skew_ns=0, work=work)


def budget(operation=source.contract.AUTHORIZE):
    return source.NativeJitReviewReadBudget(operation, parent_work=meter(),
        live_window=window(), deadline_ns=time.monotonic_ns() + 30_000_000_000)


def fixture(operation=source.contract.AUTHORIZE, *, absent_receipt=False):
    request = {"operation": operation, "requestDigest": DIGEST,
        "arguments": {"session_id": "session-one", "approval_request_id": "approval-one"}}
    owned, rows, queries, grouped = {}, [], [], {}
    names = source._NAMES if operation == source.contract.RECEIPT else source._BASE_NAMES
    for slot, name in enumerate(names):
        query = source._query(operation, name, source._selector(name, request, owned, "publication-one"))
        row = template_row(slot)
        row.update(query.absent_key)
        if name == "session":
            row.update(token_digest="sha256:" + hashlib.sha256(TOKEN).hexdigest(),
                user_id="reviewer-one", bound_webauthn_credential_id="credential-one", status="active",
                expires_at="2099-01-01T00:00:00+00:00", provider_expires_at="2099-01-01T00:00:00+00:00")
        elif name == "credential":
            row.update(user_id="reviewer-one", revoked_at=None)
        elif name == "trust_publication":
            high = owned["trust_high_water"]
            row.update(scope="global", status="published", bundle_digest=high["publication_digest"],
                payload_digest=high["metadata_blob_digest"], rollback_epoch=high["rollback_epoch"],
                sequence=high["publication_sequence"])
        if absent_receipt and name == "receipt":
            row = None
        owned[name] = row
        rows.append(row)
        queries.append(query)
        grouped.setdefault(query.table, [])
        if row is not None:
            grouped[query.table].append(row)
    trees = {table: IndependentTree(values, table=table,
        columns=source.primary_contract.PRIMARY_KEY_COLUMNS[table]) for table, values in grouped.items()}
    originals = []
    for query, row in zip(queries, rows):
        tree = trees[query.table]
        selected = tree.selected(query.absent_key)
        raw_chunks = (source.core.canonical_bytes({"rows": []}),) if row is None else tuple(
            source.core.canonical_bytes({"rows": [record]}) for record in frames(native(row)))
        originals.append({"chunks": raw_chunks, "proof": source.core.canonical_bytes(tree.proof(selected))})
    return request, {"rows": tuple(originals), "trustPublicationId": "publication-one"}, trees, rows


class NativeJitReviewReadControls(unittest.TestCase):
    def replay_rows(self, request, originals, trees, *, token=TOKEN):
        owned_budget = budget(request["operation"])
        with owned_budget.stage("admission") as work:
            token_digest = source._token_digest(token, work)
        result = source._rows(request, token_digest, {table: tree.root for table, tree in trees.items()},
            originals, owned_budget)
        return result, owned_budget

    def test_actual_nine_and_thirteen_rows_and_query_records(self):
        for operation, count in ((source.contract.AUTHORIZE, 9), (source.contract.RECEIPT, 13)):
            with self.subTest(operation=operation):
                request, originals, trees, expected = fixture(operation)
                result, owned = self.replay_rows(request, originals, trees)
                self.assertEqual([selected["row"] for selected in result[0]], expected)
                self.assertEqual(len(result[0]), count)
                self.assertEqual(len(result[1]), count)
                self.assertEqual(len(result[2]), count)
                self.assertEqual(result[3], originals["rows"])
                self.assertEqual(len({record.query_id for record in result[2]}), count)
                self.assertLess(owned.selected_bytes, source.MAX_SELECTED_BYTES)
                self.assertTrue(all(record.returned_row_count == 1 for record in result[2]))

    def test_receipt_absence_is_real_tree_absence(self):
        request, originals, trees, _ = fixture(source.contract.RECEIPT, absent_receipt=True)
        result, _ = self.replay_rows(request, originals, trees)
        self.assertIsNone(result[0][9]["row"])
        self.assertFalse(result[0][9]["present"])
        self.assertFalse(result[1][9]["present"])
        self.assertEqual(result[2][9].returned_row_count, 0)

    def test_wrong_original_token_stops_before_dependent_credential(self):
        request, originals, trees, _ = fixture()
        owned = budget()
        with self.assertRaises(ValueError):
            source._rows(request, source._token_digest(b"B" * 64, meter()),
                {table: tree.root for table, tree in trees.items()}, originals, owned)
        self.assertNotIn(("row-open", 1, 0), owned._stages)
        self.assertTrue(owned._failed)

    def test_session_membership_failure_stops_before_token_or_selectors(self):
        request, originals, trees, _ = fixture()
        changed = copy.deepcopy(originals)
        proof = source._read_json(changed["rows"][0]["proof"], source.MAX_PROOF_BYTES, meter())
        proof["rootRevision"] += 1
        refresh_proof_digest(proof)
        changed["rows"][0]["proof"] = source.core.canonical_bytes(proof)
        owned = budget()
        with self.assertRaises(ValueError):
            source._rows(request, source._token_digest(TOKEN, meter()),
                {table: tree.root for table, tree in trees.items()}, changed, owned)
        self.assertNotIn(("row-open", 1, 0), owned._stages)

    def test_publication_candidate_must_join_authenticated_high_water(self):
        request, originals, trees, rows = fixture()
        changed_row = copy.deepcopy(rows[3])
        changed_row["bundle_digest"] = "different"
        replacement = IndependentTree([changed_row], table="webauthn_trust_publications")
        trees[replacement.table] = replacement
        changed = copy.deepcopy(originals)
        changed_original = {"chunks": tuple(source.core.canonical_bytes({"rows": [record]})
            for record in frames(native(changed_row))), "proof": source.core.canonical_bytes(
                replacement.proof(replacement.selected({"id": "publication-one"})))}
        changed["rows"] = changed["rows"][:3] + (changed_original,) + changed["rows"][4:]
        with self.assertRaises(ValueError):
            self.replay_rows(request, changed, trees)

    def test_extra_chunk_and_extra_row_are_not_silently_ignored(self):
        request, originals, trees, _ = fixture()
        changed = copy.deepcopy(originals)
        changed["rows"][0]["chunks"] += changed["rows"][0]["chunks"]
        with self.assertRaises(ValueError):
            self.replay_rows(request, changed, trees)
        changed = copy.deepcopy(originals)
        changed["rows"] += (changed["rows"][0],)
        with self.assertRaises(ValueError):
            self.replay_rows(request, changed, trees)

    def test_real_radix_membership_refuses_row_and_proof_corruption(self):
        row = {"id": "one", "value": "original"}
        tree = IndependentTree([row])
        selected, proof = tree.selected({"id": "one"}), tree.proof(tree.selected({"id": "one"}))
        source._membership(selected, proof, tree.root, len(source.core.canonical_bytes(row)), meter())
        changed = copy.deepcopy(selected)
        changed["row"]["value"] = "changed"
        with self.assertRaises(ValueError):
            source._membership(changed, proof, tree.root, len(source.core.canonical_bytes(changed["row"])), meter())
        proof["proofDigest"] = "sha256:" + "0" * 64
        with self.assertRaises(ValueError):
            source._membership(selected, proof, tree.root, len(source.core.canonical_bytes(row)), meter())

    def test_work_stages_are_once_only_and_failure_poisoned(self):
        owned = budget()
        with owned.stage("input-capture") as work:
            work.charge(input_bytes=1)
        with self.assertRaises(ValueError):
            with owned.stage("input-capture"):
                self.fail("duplicate stage accepted")
        with self.assertRaises(ValueError):
            with owned.stage("head"):
                self.fail("poisoned pass accepted")

    def test_parent_or_closed_child_spending_invalidates_later_stage(self):
        for parent in (True, False):
            with self.subTest(parent=parent):
                owned = budget()
                with owned.stage("input-capture") as child:
                    pass
                (owned.parent_work if parent else child).charge(input_bytes=1)
                with self.assertRaises(ValueError):
                    with owned.stage("head"):
                        self.fail("changed original ledger accepted")

    def test_aggregate_and_deadline_limits_fail_closed(self):
        for field, value in (("selected_bytes", source.MAX_SELECTED_BYTES + 1),
                ("original_bytes", source.MAX_ORIGINAL_BYTES + 1),
                ("data_chunks", source.chunks.MAX_TOTAL_DATA_CHUNKS + 1),
                ("sql_reads", source.MAX_SQL_READS + 1)):
            owned = budget()
            setattr(owned, field, value)
            with self.subTest(field=field), self.assertRaises(ValueError):
                with owned.stage("head"):
                    self.fail("over-budget pass accepted")
        with self.assertRaises(ValueError):
            owned = source.NativeJitReviewReadBudget(source.contract.AUTHORIZE, parent_work=meter(),
                live_window=window(), deadline_ns=1)
            with owned.stage("head"):
                self.fail("expired pass accepted")

    def test_token_original_is_exact_and_not_a_digest_argument(self):
        self.assertEqual(source._token_digest(TOKEN, meter()),
            "sha256:" + hashlib.sha256(TOKEN).hexdigest())
        for bad in (TOKEN[:-1], TOKEN + b"A", TOKEN[:-1] + b"\x80", DIGEST.encode("ascii"), "A" * 64, None):
            with self.subTest(kind=type(bad).__name__), self.assertRaises(ValueError):
                source._token_digest(bad, meter())

    def test_closed_original_refusal_poisoned_without_any_root_admission(self):
        owned = budget()
        with self.assertRaises(ValueError):
            source.admit_original_reads_on_work({}, request={"operation": source.contract.AUTHORIZE},
                session_token_original=TOKEN, root_public_key=None, enrollment_original=b"{}",
                live_window=owned.live_window, work=owned.parent_work, budget=owned)
        self.assertTrue(owned._failed)
        self.assertEqual(owned._stages, {})

    def test_original_capture_detaches_all_containers_before_later_callbacks(self):
        _, packet, _, _ = fixture()
        packet.update(schema=source.SCHEMA, operation=source.contract.AUTHORIZE,
            requestDigest=DIGEST, databaseNowEpochNs=time.time_ns(),
            completeRootVectorOriginal=b"{}", headQueryOriginal=b"{}", headObservationOriginal=b"{}",
            finalHeadQueryOriginal=b"{}", finalHeadObservationOriginal=b"{}")
        held = source._snapshot_originals(packet, source.contract.AUTHORIZE, meter())
        original_frame = held["rows"][0]["chunks"][0]

        def later_callback():
            packet["finalHeadObservationOriginal"] = b'{"changed":true}'
            packet["finalHeadQueryOriginal"] = b'{"changed":true}'
            packet["completeRootVectorOriginal"] = b'{"changed":true}'
            packet["rows"][0]["chunks"] = (b'{"changed":true}',)
            packet["rows"][0]["proof"] = b'{"changed":true}'
            packet["rows"] = ()

        later_callback()
        self.assertEqual(held["finalHeadObservationOriginal"], b"{}")
        self.assertEqual(held["finalHeadQueryOriginal"], b"{}")
        self.assertEqual(held["completeRootVectorOriginal"], b"{}")
        self.assertEqual(len(held["rows"]), 9)
        self.assertIs(held["rows"][0]["chunks"][0], original_frame)
        self.assertNotEqual(held["rows"][0]["proof"], b'{"changed":true}')

    def test_review_head_purpose_domains_and_magic_are_distinct(self):
        originals, magics = [], []
        for operation in source.contract.OPERATIONS:
            original = source.head._encode_query_on_work(enrollment_digest=DIGEST, context_digest=DIGEST,
                expected_vector_digest=DIGEST, challenge="1" * 64, work=meter(), operation=operation)
            self.assertEqual(source.head._decode_query_on_work(original, work=meter(), operation=operation)["operation"], operation)
            originals.append(original)
            magics.extend(source.transport._native_jit_review_head_magics(operation))
        self.assertNotEqual(originals[0], originals[1])
        self.assertEqual(len(set(magics)), 4)
        with self.assertRaises(ValueError):
            source.head._decode_query_on_work(originals[0], work=meter(), operation=source.contract.RECEIPT)
        with self.assertRaises(source.transport.AuthorityTransportError):
            source.transport._native_jit_review_head_magics("jit.assertion.issue")

    def test_native_service_peer_profile_is_explicit_and_disjoint(self):
        # Configuration-only sentinel of the exact class. It has no initialized
        # keys/state and is never called; no fabricated owner result is accepted.
        owner = object.__new__(decisions.CurrentRootDecisionOwner)
        old = service.CurrentRootDecisionService._with_public_revocation(owner=owner, timeout_seconds=1)
        self.assertEqual(len(old._snapshot_configuration()), 17)
        fresh = service.CurrentRootDecisionService._with_native_jit_review(owner=owner, timeout_seconds=1,
            admitted_planner_peer_uid=64000, admitted_planner_peer_gid=64000)
        self.assertEqual(fresh._snapshot_configuration()[:17], old._snapshot_configuration())
        self.assertEqual(fresh._snapshot_configuration()[17], (64000, 64000))
        for uid, gid in ((0, 0), (65520, 65520), (65514, 65514), (64000, 64001), (True, True)):
            with self.subTest(uid=uid, gid=gid), self.assertRaises(RuntimeError):
                service.CurrentRootDecisionService._with_native_jit_review(owner=owner, timeout_seconds=1,
                    admitted_planner_peer_uid=uid, admitted_planner_peer_gid=gid)


if __name__ == "__main__":
    unittest.main()
