#!/usr/bin/env python3
"""Actual mixed source-observation binding and complete read/write proofs.

Independent source documents, ordered records and full populations supply the
expected observations. Every instrumented worker delegates its real body; no
proof, admitted token or successful verifier is substituted. The mutations,
assertion IDs, aggregate row and roots are synthetic component inputs, not
kernel authorization, counter initialization or independent currentness.
All authored controls are source-only and unrun.
"""
from __future__ import annotations

import copy
from dataclasses import fields, replace
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_complete_query_batch as query_batch
from serverware import authority_complete_read_write as read_write
from serverware import authority_query_read_work as accounting
from serverware import authority_query_reads as reads
from serverware import authority_radix_mutation as primary
from serverware import authority_revocation_read_write as admission
from serverware import authority_transition_core as core
from serverware import authority_transition_webauthn as candidate
import authority_revocation_observation_fixture as fixture_oracle
import test_authority_query_reads_measured as observation_oracle
import test_authority_revocation_query_program as recipe_oracle
import test_authority_revocation_query_work as generation_oracle


def forged(value, **changes):
    result = object.__new__(type(value))
    for field in fields(value):
        object.__setattr__(result, field.name, changes.get(field.name, getattr(value, field.name)))
    return result


def record_named(records, fragment):
    matches = [record for record in records if f"/{fragment}/" in record.query_id]
    if len(matches) != 1:
        raise AssertionError("fixture needs exactly one named source query")
    return matches[0]


def replace_record(records, replacement):
    return tuple(replacement if record.query_id == replacement.query_id else record for record in records)


def metrics_value(value):
    return {"hash_work": value.hash_work, "input_bytes": value.input_bytes, "json_nodes": value.json_nodes}


def unit_metrics(hashes=0, input_bytes=0, json_nodes=0):
    return {"hash_work": hashes, "input_bytes": input_bytes, "json_nodes": json_nodes}


def independent_observation_work(fixture):
    """Real validator schedule including the four proved high-water references.

    Primitive framing/copy arithmetic is reused from the independent measured
    fixture, not its id-only population adapter. Actual source primary columns
    from our independent trees also cover the counter's aggregate_id key.
    """
    expected = observation_oracle.ExpectedWork()
    documents = {document["queryId"]: document for document in fixture.documents}
    resolved_documents = {document["queryId"]: document for document in fixture.resolved_documents}
    queries = fixture.query_program
    records = fixture.query_reads

    def values(query):
        return (tuple(predicate.value for predicate in query.predicates)
                + (() if query.absent_key is None else tuple(query.absent_key.values())))

    def reference_key_copies(query):
        for value in values(query):
            if type(value) is core.SelectedRowFieldReference:
                expected.encoding(value.key)

    def key_work(key):
        expected.copy(key)
        expected.encoding(key)

    def selected_address(selected):
        key_work(selected["key"])
        if selected["present"]:
            columns = fixture.read_write.read.trees[selected["table"]].columns
            key_work({column: selected["row"][column] for column in columns})
        expected.hashes += 1
        expected.address(reads.QueryReadAddress(selected["table"], fixture_oracle.wire(selected["key"]),
            selected["keyDigest"], selected["present"]))

    for query in queries:
        document = documents[query.query_id]
        if document["schema"] == "serverware.policyAuthorityCompleteIndexQuery/v1":
            for _ in range(8):
                expected.profile(query)
        else:
            for value in values(query):
                if type(value) is core.SelectedRowFieldReference:
                    expected.copy(value.key)
                    expected.encoding(value.key, copies=1)
                else:
                    expected.copy(value)
            if query.absent_key is not None:
                for name in query.absent_key:
                    expected.copy(name)
            reference_key_copies(query)
        expected.encoding(document)
        expected.bytes += len(fixture_oracle.wire(document))
    for ordinal, record in enumerate(records):
        addresses = sum(observation_oracle.address_bytes(address) for address in record.addresses)
        header = observation_oracle.record_bytes(record) - addresses
        expected.bytes += 2 * (2 * header + addresses)
        expected.record(record, 4 + len(records) - 1 - ordinal)
        expected.bytes += header
    for selected in fixture.selected_rows:
        selected_address(selected)
    for query, resolved, record, ordered in zip(queries, fixture.resolved_program, records, fixture.ordered_rows):
        document = documents[query.query_id]
        resolved_document = resolved_documents[query.query_id]
        ordinary = document["schema"] == "serverware.policyAuthorityQueryProgram/v1"
        if ordinary:
            for before, after in zip(values(query), values(resolved)):
                if type(before) is core.SelectedRowFieldReference:
                    key_work(before.key)
                expected.copy(after)
            reference_key_copies(query)  # resolution-shape projection
        expected.encoding(resolved_document)
        expected.encoding(resolved_document)
        if ordinary:
            reference_key_copies(query)  # retained declared projection
        expected.encoding(document)
        expected.encoding(resolved_document)
        expected.bytes += len(fixture_oracle.wire(document)) + len(fixture_oracle.wire(resolved_document))
        for selected in ordered:
            selected_address(selected)
        if ordinary and record.returned_row_count == 0 and resolved.absent_key is not None:
            key_work(resolved.absent_key)
    return unit_metrics(expected.hashes, expected.bytes, expected.nodes)


def independent_metrics(fixture):
    """Literal normalized ownership plus genuine semantic phase arithmetic."""
    document = fixture.read_write.ownership_document()
    raw_records = [{"queryId": record.query_id,
        "declaredQueryJson": record.declared_query_json.decode("ascii"),
        "resolvedQueryJson": record.resolved_query_json.decode("ascii"),
        "addresses": [{"table": address.table, "keyJson": address.key_json.decode("ascii"),
            "keyDigest": address.key_digest, "present": address.present} for address in record.addresses],
        "returnedRowCount": record.returned_row_count} for record in fixture.query_reads]
    document.update(requestDigest=fixture.request_digest,
        assertionBinding=copy.deepcopy(fixture.assertion_binding), queryReads=raw_records)
    raw_bytes = sum(len(record.declared_query_json) + len(record.resolved_query_json)
        + sum(len(address.key_json) for address in record.addresses) for record in fixture.query_reads)
    ownership_bytes = len(fixture_oracle.wire(document))
    ownership_nodes = observation_oracle.graph_nodes(document)

    class SourceAdapter:
        values = fixture.values
        inputs = {"arguments": fixture.arguments, "cutoff_us": fixture.cutoff_us,
                  "request_digest": fixture.request_digest}
        signer = fixture.signer_id
        challenge = fixture.assertion_binding["challengeId"]

    generated = generation_oracle.expected_work(SourceAdapter())
    generation = unit_metrics(*generated.tuple())
    raw_queries = document["queries"]
    declaration = unit_metrics(0, 4 * len(fixture_oracle.wire(raw_queries)),
                                4 * observation_oracle.graph_nodes(raw_queries))
    observations = independent_observation_work(fixture)
    observations["input_bytes"] += raw_bytes + sum(observation_oracle.record_bytes(record)
                                                   for record in fixture.query_reads)
    point = unit_metrics()
    complete = unit_metrics()
    for ordinal, (source, resolved, ordered) in enumerate(zip(
            fixture.documents, fixture.resolved_documents, fixture.ordered_rows)):
        if source["schema"] == "serverware.policyAuthorityQueryProgram/v1":
            key = source["absentKey"]
            if key is None:
                # The only admitted non-PK query is the actual publication
                # join. Its real resolver repeats snapshot/prefix/selection
                # work under the SAME ledger, not a result-token shortcut.
                lookup = observation_oracle.ExpectedWork()

                def key_work(value):
                    lookup.copy(value)
                    lookup.encoding(value)

                for predicate in source["predicates"]:
                    value = predicate["value"]
                    if type(value) is dict:
                        lookup.copy(value["key"])
                        lookup.encoding(value["key"], copies=1)
                        lookup.encoding(value["key"])  # declared contract's hidden copy
                    else:
                        lookup.copy(value)
                lookup.encoding(source)
                lookup.bytes += len(fixture_oracle.wire(source))
                for record in fixture.query_reads[:ordinal]:
                    address_bytes = sum(observation_oracle.address_bytes(item) for item in record.addresses)
                    header_bytes = observation_oracle.record_bytes(record) - address_bytes
                    lookup.bytes += 6 * header_bytes + 4 * address_bytes
                for selected in fixture.selected_rows:
                    key_work(selected["key"])
                    if selected["present"]:
                        columns = fixture.read_write.read.trees[selected["table"]].columns
                        key_work({column: selected["row"][column] for column in columns})
                    lookup.hashes += 1
                    lookup.address(reads.QueryReadAddress(selected["table"], fixture_oracle.wire(selected["key"]),
                        selected["keyDigest"], selected["present"]))
                for before, after in zip(source["predicates"], resolved["predicates"]):
                    if type(before["value"]) is dict:
                        key_work(before["value"]["key"])
                    lookup.copy(after["value"])
                row = ordered[0]["row"]
                predicate_values = {predicate["column"]: predicate["value"]
                                    for predicate in resolved["predicates"]}
                key = ordered[0]["key"]
                point["hash_work"] += lookup.hashes
                point["input_bytes"] += (lookup.bytes + 2 * len(fixture_oracle.wire(fixture.selected_rows))
                    + 4 * len(fixture_oracle.wire(row)) + 4 * len(fixture_oracle.wire(key))
                    + 6 * len(fixture_oracle.wire(predicate_values)))
                point["json_nodes"] += (lookup.nodes + 2 * observation_oracle.graph_nodes(fixture.selected_rows)
                    + 4 * observation_oracle.graph_nodes(row) + 2 * observation_oracle.graph_nodes(key)
                    + 4 * observation_oracle.graph_nodes(predicate_values))
                continue
            point["input_bytes"] += 8 * len(fixture_oracle.wire(key))
            point["json_nodes"] += 6 * observation_oracle.graph_nodes(key)
        else:
            # Keys/order come from independent counted matches in the helper,
            # not the retained record or a production returned observation.
            comparison = {"queryId": source["queryId"], "returnedRowCount": len(ordered),
                "addresses": [[source["table"], selected["keyDigest"], True] for selected in ordered]}
            complete["input_bytes"] += 4 * len(fixture_oracle.wire(comparison))
            complete["json_nodes"] += 4 * observation_oracle.graph_nodes(comparison)

    reader = fixture.read_write.read
    ordinary = [selected for selected in fixture.selected_rows if not (
        selected["table"] == fixture_oracle.counter_oracle.COUNTER_TABLE
        and selected["key"] == {"aggregate_id": fixture_oracle.counter_oracle.COUNTER_ID})]
    envelopes = (ordinary, list(fixture.selected_rows))
    global_work = reader.primary_metrics()
    joins = [reader.join_metrics(query.role) for query in reader.queries]
    writer = fixture.read_write.writer_metrics()
    read_ids = {info.profile.index_id for info in reader.joins.values()}
    proof = unit_metrics(
        101 + 2 * len(set(fixture.read_write.heads) - read_ids) + global_work["hash_work"]
            + sum(item["total_hashes"] for item in joins) + writer["hashes"],
        sum(len(fixture_oracle.wire(value)) for value in envelopes) + global_work["input_bytes"]
            + sum(item["total_input_bytes"] for item in joins) + writer["input_bytes"],
        sum(observation_oracle.graph_nodes(value) for value in envelopes) + global_work["json_nodes"]
            + sum(item["primary"]["json_nodes"] for item in joins) + writer["primary"]["json_nodes"],
    )
    phases = {"generation": generation, "declaration_binding": declaration,
        "observation_validation": observations, "point_binding": point,
        "proof_work": proof, "complete_binding": complete}
    return {"raw_decode_bytes": raw_bytes, "ownership_bytes": ownership_bytes,
        "ownership_nodes": ownership_nodes, **phases,
        "total_hashes": sum(item["hash_work"] for item in phases.values()),
        "total_input_bytes": raw_bytes + ownership_bytes + sum(item["input_bytes"] for item in phases.values()),
        "total_json_nodes": ownership_nodes + sum(item["json_nodes"] for item in phases.values())}


class RevocationReadWriteTests(unittest.TestCase):
    def verify(self, fixture=None, **changes):
        fixture = fixture_oracle.RevocationObservationFixture() if fixture is None else fixture
        inputs = fixture.inputs()
        inputs.update(changes)
        return admission.verify_revocation_read_write_inputs(**inputs)

    def assert_observation(self, fixture, result):
        self.assertEqual(result.operation, fixture_oracle.OPERATION)
        self.assertEqual(result.arguments, fixture.arguments)
        self.assertEqual(result.cutoff_us, fixture.cutoff_us)
        self.assertEqual(result.request_digest, fixture.request_digest)
        self.assertEqual(result.assertion_binding, fixture.assertion_binding)
        self.assertEqual(tuple(query.contract_value() for query in result.query_program), fixture.documents)
        self.assertEqual(result.query_reads, fixture.query_reads)
        self.assertEqual(result.selected_rows, fixture.selected_rows)
        self.assertEqual(result.before_proofs, fixture.before_proofs)
        self.assertEqual(result.mutations, fixture.read_write.mutations)
        self.assertEqual(result.queries, fixture.read_write.read.queries)
        self.assertEqual(tuple(head.index_id for head in result.before_heads), tuple(fixture.read_write.heads))
        self.assertEqual(tuple(head.index_id for head in result.after_heads), tuple(fixture.read_write.heads))
        for before, after in zip(result.before_heads, result.after_heads):
            revision, root = fixture.read_write.heads[before.index_id]
            self.assertEqual((before.index_revision, before.index_root), (revision, root))
            changed = fixture.read_write.indexes.get(before.index_id)
            expected = ((revision, root) if changed is None else
                (revision + changed["revision_delta"], changed["after"].root))
            self.assertEqual((after.index_revision, after.index_root), expected)
        for root_class, actual in (("business", result.write.primary.business_after_roots),
                                   ("authorization", result.write.primary.authorization_after_roots)):
            expected = {contract.table: fixture.read_write.after_trees[contract.table].root
                for contract in fixture.read_write.read.contracts if contract.root_class == root_class}
            self.assertEqual({root.table: root for root in actual}, expected)
        self.assertEqual(tuple(query_id for query_id, _ in result.joined_reads),
                         tuple(query.query_id for query in fixture.read_write.read.queries))
        for query, (_, observation) in zip(fixture.read_write.read.queries, result.joined_reads):
            info = fixture.read_write.read.joins[query.role]
            self.assertEqual(observation.leaves, info.index.matches(info.interval))

    def test_full_mixed_program_and_exact_primary_union_match_independent_populations(self):
        fixture = fixture_oracle.RevocationObservationFixture()
        result = self.verify(fixture)
        self.assert_observation(fixture, result)
        self.assertEqual((len(result.query_program), len(result.selected_rows), len(result.before_heads)), (12, 10, 8))
        self.assertEqual(sum(row["present"] for row in result.selected_rows), 9)
        self.assertEqual(record_named(result.query_reads, "approvals").addresses, ())
        audit = record_named(result.query_reads, "audit_0")
        self.assertEqual((len(audit.addresses), audit.addresses[0].present, audit.returned_row_count), (1, False, 0))
        counter = record_named(result.query_reads, "global_audit_capacity_before_v1")
        self.assertEqual(counter.addresses[0].key_json,
            fixture_oracle.wire({"aggregate_id": fixture_oracle.counter_oracle.COUNTER_ID}))
        self.assertTrue(counter.addresses[0].present)

    def test_same_and_separate_signers_two_members_and_no_audit_keep_source_closure(self):
        for separate, pending, audit in ((True, 1, True), (False, 2, True),
                                        (False, 1, False), (True, 2, False)):
            with self.subTest(separate=separate, pending=pending, audit=audit):
                fixture = fixture_oracle.RevocationObservationFixture(separate_signer=separate,
                    pending_count=pending, include_audit=audit)
                result = self.verify(fixture)
                self.assert_observation(fixture, result)
                self.assertEqual(len(result.query_program), 11 + int(separate) + int(audit))
                self.assertEqual(len(result.selected_rows), 8 + pending + int(separate) + int(audit))
                self.assertEqual(len(record_named(result.query_reads, "sessions_pending_webauthn").addresses), pending)
                self.assertEqual(record_named(result.query_reads, "approvals").addresses, ())

    def test_actual_source_validator_and_private_proof_composer_each_run_once_without_public_resets(self):
        fixture = fixture_oracle.RevocationObservationFixture()
        generation, validation, computation = [], [], []
        actual_generation = candidate._revocation_query_program
        actual_validation = reads._validate_query_reads
        actual_computation = read_write._verify

        def generate(**inputs):
            result = actual_generation(**inputs)
            generation.append((inputs, result))
            return result

        def validate(*args, **inputs):
            result = actual_validation(*args, **inputs)
            validation.append((inputs, result))
            return result

        def compute(*args, **inputs):
            result = actual_computation(*args, **inputs)
            computation.append((args, inputs, result))
            return result

        with patch.object(candidate, "_revocation_query_program", side_effect=generate), \
                patch.object(reads, "_validate_query_reads", side_effect=validate), \
                patch.object(read_write, "_verify", side_effect=compute), \
                patch.object(read_write, "verify_complete_read_write_batch",
                             wraps=read_write.verify_complete_read_write_batch) as public_proof, \
                patch.object(reads, "validate_query_reads_measured",
                             wraps=reads.validate_query_reads_measured) as public_validation:
            result = self.verify(fixture)
        self.assertEqual((len(generation), len(validation), len(computation)), (1, 1, 1))
        self.assertEqual((public_proof.call_count, public_validation.call_count), (0, 0))
        self.assertIs(result.read_primary, computation[0][2].read_primary)
        self.assertIs(result.write, computation[0][2].write)
        self.assertIsNotNone(generation[0][0]["work"])
        self.assertIs(generation[0][0]["work"], validation[0][0]["work"])
        self.assert_observation(fixture, result)

    def test_all_raw_inputs_are_owned_by_one_capture_before_the_first_real_hash(self):
        fixture = fixture_oracle.RevocationObservationFixture(separate_signer=True, pending_count=2)
        inputs = fixture.inputs()
        actual_visit, actual_sha = query_batch._JSONCapture.visit, hashlib.sha256
        top_captures, hash_calls = [], []

        def visit(copier, value, *args, **kwargs):
            depth = kwargs.get("depth", args[0] if args else 0)
            if depth == 0 and copier.retain:
                top_captures.append(value)
            return actual_visit(copier, value, *args, **kwargs)

        def digest(*args, **kwargs):
            if not hash_calls:
                self.assertEqual(len(top_captures), 1)
                inputs["arguments"]["reason"] = "caller changed semantic input"
                inputs["arguments"]["businessIntent"]["arguments"]["reason"] = "caller changed intent"
                inputs["assertion_binding"]["challengeId"] = "caller-changed-challenge"
                for vector in (inputs["business_before_roots"], inputs["authorization_before_roots"]):
                    for root in vector:
                        root["rootDigest"] = "sha256:" + "0" * 64
                next(row for row in inputs["selected_rows"] if row["present"])["row"]["caller_changed"] = True
                inputs["before_proofs"][0]["siblings"][0]["childDigests"][0] = "sha256:" + "0" * 64
                inputs["mutations"][0]["row"]["caller_changed"] = True
                object.__setattr__(inputs["queries"][-1], "selector_items", (("expires_after_us", -1),))
                object.__setattr__(inputs["counted_before_heads"][-1].index_root, "digest", "sha256:" + "0" * 64)
                for inventory in (inputs["query_frontiers"], inputs["write_frontiers"]):
                    terminal = next(item.frontier[-1] for item in reversed(inventory) if item.frontier)
                    field = "primary_row_digest" if hasattr(terminal, "key") else "digest"
                    object.__setattr__(terminal, field, "sha256:" + "0" * 64)
                object.__setattr__(inputs["query_reads"][-1], "declared_query_json", b"{}")
            hash_calls.append(1)
            return actual_sha(*args, **kwargs)

        with patch.object(query_batch._JSONCapture, "visit", new=visit), \
                patch.object(hashlib, "sha256", side_effect=digest):
            result = admission.verify_revocation_read_write_inputs(**inputs)
        self.assertGreater(len(hash_calls), 0)
        self.assertEqual(len(top_captures), 1)
        self.assert_observation(fixture, result)

    def test_present_wrong_point_keys_are_rejected_despite_genuine_rows_and_proofs(self):
        fixture = fixture_oracle.RevocationObservationFixture(separate_signer=True)
        records = fixture.query_reads
        target = record_named(records, "revoked_credential")
        signer = record_named(records, "assertion_credential")
        changed = replace_record(records, replace(target, addresses=signer.addresses))
        changed = replace_record(changed, replace(signer, addresses=target.addresses))
        # The generic observational API intentionally does not prove ordinary
        # predicate truth; swapping these two present addresses preserves union.
        self.assertEqual(reads.validate_query_reads(fixture_oracle.OPERATION,
            queries=fixture.query_program, query_reads=changed, selected_rows=fixture.selected_rows), changed)
        with patch.object(read_write, "_verify", wraps=read_write._verify) as proofs:
            with self.assertRaises(admission.RevocationReadWriteError):
                self.verify(fixture, query_reads=changed)
        self.assertEqual(proofs.call_count, 0)

    def test_two_member_complete_observation_order_must_match_the_actual_join(self):
        fixture = fixture_oracle.RevocationObservationFixture(pending_count=2)
        pending = record_named(fixture.query_reads, "sessions_pending_webauthn")
        reversed_addresses = tuple(reversed(pending.addresses))
        self.assertEqual(len(pending.addresses), 2)
        self.assertNotEqual(pending.addresses, reversed_addresses)
        changed = replace_record(fixture.query_reads, replace(pending, addresses=reversed_addresses))
        self.assertEqual(reads.validate_query_reads(fixture_oracle.OPERATION,
            queries=fixture.query_program, query_reads=changed, selected_rows=fixture.selected_rows), changed)
        with patch.object(read_write, "_verify", wraps=read_write._verify) as proofs:
            with self.assertRaises(admission.RevocationReadWriteError):
                self.verify(fixture, query_reads=changed)
        self.assertEqual(proofs.call_count, 1)

    def test_empty_source_role_cannot_be_omitted_from_retained_observations(self):
        fixture = fixture_oracle.RevocationObservationFixture()
        empty = record_named(fixture.query_reads, "approvals")
        self.assertEqual((empty.addresses, empty.returned_row_count), ((), 0))
        changed = tuple(record for record in fixture.query_reads if record.query_id != empty.query_id)
        with patch.object(read_write, "_verify", wraps=read_write._verify) as proofs:
            with self.assertRaises(admission.RevocationReadWriteError):
                self.verify(fixture, query_reads=changed)
        self.assertEqual(proofs.call_count, 0)

    def test_unknown_extra_ordinary_query_is_not_authorized_by_well_formed_records(self):
        fixture = fixture_oracle.RevocationObservationFixture()
        document = recipe_oracle.point_document("caller-extra", "webauthn_credentials", fixture_oracle.TARGET_ID)
        target = next(row for row in fixture.selected_rows if row["table"] == "webauthn_credentials")
        extra = fixture_oracle.observation_record(document, (target,))
        with patch.object(read_write, "_verify", wraps=read_write._verify) as proofs:
            with self.assertRaises(admission.RevocationReadWriteError):
                self.verify(fixture, query_reads=(*fixture.query_reads, extra))
        self.assertEqual(proofs.call_count, 0)

    def test_five_complete_proof_declarations_must_follow_generated_source_order(self):
        fixture = fixture_oracle.RevocationObservationFixture()
        inputs = fixture.inputs()
        inputs["queries"] = (inputs["queries"][1], inputs["queries"][0], *inputs["queries"][2:])
        inputs["query_frontiers"] = (inputs["query_frontiers"][1], inputs["query_frontiers"][0],
                                     *inputs["query_frontiers"][2:])
        # All six valid role declarations and their corresponding real
        # frontiers remain present; only their source-program order changed.
        self.assertEqual({query.role for query in inputs["queries"]},
                         {query.role for query in fixture.read_write.read.queries})
        with patch.object(read_write, "_verify", wraps=read_write._verify) as proofs:
            with self.assertRaises(admission.RevocationReadWriteError):
                admission.verify_revocation_read_write_inputs(**inputs)
        self.assertEqual(proofs.call_count, 0)

    def test_arguments_cutoff_assertion_ids_and_audited_digest_rebind_the_source_program(self):
        fixture = fixture_oracle.RevocationObservationFixture(separate_signer=True)
        changed_values = {**fixture.values, "record_id": fixture.signer_id}
        changes = (
            {"arguments": recipe_oracle.arguments(changed_values)},
            {"cutoff_us": fixture.cutoff_us + 1},
            {"assertion_binding": {**fixture.assertion_binding, "challengeId": "past"}},
            {"assertion_binding": {**fixture.assertion_binding, "credentialRecordId": fixture_oracle.TARGET_ID}},
            {"request_digest": "sha256:" + "7" * 64},
        )
        for change in changes:
            with self.subTest(field=tuple(change)), \
                    patch.object(read_write, "_verify", wraps=read_write._verify) as proofs:
                with self.assertRaises(admission.RevocationReadWriteError):
                    self.verify(fixture, **change)
            self.assertEqual(proofs.call_count, 0)

    def test_closed_assertion_context_and_canonical_digest_are_required_even_without_audits(self):
        fixture = fixture_oracle.RevocationObservationFixture(include_audit=False)
        changes = (
            {"request_digest": "not-a-digest"},
            {"request_digest": "sha256:" + "G" * 64},
            {"request_digest": b"sha256:" + b"6" * 64},
            {"assertion_binding": {}},
            {"assertion_binding": {**fixture.assertion_binding, "claimedVerified": True}},
            {"assertion_binding": {"credentialRecordId": None, "challengeId": "used"}},
            {"assertion_binding": {"credentialRecordId": "x" * 1025, "challengeId": "used"}},
        )
        for change in changes:
            with self.subTest(field=tuple(change)), \
                    patch.object(candidate, "_revocation_query_program", wraps=candidate._revocation_query_program) as generated:
                with self.assertRaises(admission.RevocationReadWriteError):
                    self.verify(fixture, **change)
            self.assertEqual(generated.call_count, 0)

    def test_retained_query_json_is_never_parsed_into_source_declarations(self):
        fixture = fixture_oracle.RevocationObservationFixture()
        actual_loads = json.loads
        with patch.object(json, "loads", wraps=actual_loads) as parsed:
            result = self.verify(fixture)
        self.assertEqual(parsed.call_count, 1)
        self.assertEqual(actual_loads(parsed.call_args.args[0]), fixture.values)
        self.assert_observation(fixture, result)
        first = fixture.query_reads[0]
        for payload in (first.declared_query_json + b" ", b"{not-json}"):
            changed = replace_record(fixture.query_reads, replace(first, declared_query_json=payload))
            with self.subTest(payload=payload[-10:]), patch.object(json, "loads", wraps=actual_loads) as parsed:
                with self.assertRaises(admission.RevocationReadWriteError):
                    self.verify(fixture, query_reads=changed)
            # The one genuine business-intent normalization is still real.
            self.assertEqual(parsed.call_count, 1)
            self.assertEqual(actual_loads(parsed.call_args.args[0]), fixture.values)

    def test_raw_record_types_ascii_and_cumulative_preflight_fail_before_generation(self):
        fixture = fixture_oracle.RevocationObservationFixture()
        first = fixture.query_reads[0]
        wrong_address = forged(first.addresses[0], key_json=b'"\xff"')
        incomplete_record = object.__new__(reads.QueryRead)
        incomplete_address = object.__new__(reads.QueryReadAddress)
        cases = (
            (forged(first, declared_query_json=bytearray(first.declared_query_json)), *fixture.query_reads[1:]),
            (forged(first, declared_query_json=b"\xff\xff"), *fixture.query_reads[1:]),
            (forged(first, addresses=(wrong_address,)), *fixture.query_reads[1:]),
            list(fixture.query_reads),
            (first,) * 46,
            (forged(first, addresses=first.addresses * 194), *fixture.query_reads[1:]),
            (incomplete_record,),
            (forged(first, addresses=(incomplete_address,)), *fixture.query_reads[1:]),
        )
        for changed in cases:
            with self.subTest(kind=type(changed)), \
                    patch.object(candidate, "_revocation_query_program", wraps=candidate._revocation_query_program) as generated:
                with self.assertRaises(admission.RevocationReadWriteError):
                    self.verify(fixture, query_reads=changed)
            self.assertEqual(generated.call_count, 0)
        # Sharing one immutable byte object isolates aggregate raw decoding,
        # not huge unique allocations or a claimed authentic maximum program.
        payload = b"x" * (1024 * 1024)
        oversized = tuple(forged(first, declared_query_json=payload, resolved_query_json=payload,
                                 addresses=()) for _ in range(33))
        captures = []
        actual_visit = query_batch._JSONCapture.visit

        def visit(copier, *args, **kwargs):
            captures.append(1)
            return actual_visit(copier, *args, **kwargs)

        with patch.object(read_write, "_raw_document", wraps=read_write._raw_document) as normalized, \
                patch.object(query_batch._JSONCapture, "visit", new=visit):
            with self.assertRaises(admission.RevocationReadWriteError):
                self.verify(fixture, query_reads=oversized)
        self.assertEqual((normalized.call_count, len(captures)), (0, 0))

    def test_actual_primary_proof_and_counted_frontier_corruptions_are_recomputed(self):
        fixture = fixture_oracle.RevocationObservationFixture()
        inputs = fixture.inputs()
        proof = next(item for item in inputs["before_proofs"] if item["present"])
        proof["siblings"][0]["childDigests"][0] = "sha256:" + "0" * 64
        fixture_oracle.composition_oracle.primary_oracle.refresh_proof_digest(proof)
        with patch.object(primary, "evaluate_primary_radix_memberships",
                          wraps=primary.evaluate_primary_radix_memberships) as memberships:
            with self.assertRaises(admission.RevocationReadWriteError):
                admission.verify_revocation_read_write_inputs(**inputs)
        self.assertEqual(memberships.call_count, 1)
        inputs = fixture.inputs()
        frontier = inputs["query_frontiers"][0]
        leaves = tuple(item for item in frontier.frontier if hasattr(item, "key"))
        self.assertEqual(len(leaves), 1)
        removed = replace(frontier, frontier=tuple(item for item in frontier.frontier if item is not leaves[0]))
        inputs["query_frontiers"] = (removed, *inputs["query_frontiers"][1:])
        with patch.object(read_write, "_verify", wraps=read_write._verify) as proofs:
            with self.assertRaises(admission.RevocationReadWriteError):
                admission.verify_revocation_read_write_inputs(**inputs)
        self.assertEqual(proofs.call_count, 1)

    def test_owned_results_are_observations_not_substitute_authority_or_input_tokens(self):
        fixture = fixture_oracle.RevocationObservationFixture()
        result = self.verify(fixture)
        result.arguments["reason"] = "changed owned result"
        result.assertion_binding["challengeId"] = "changed owned observation"
        self.assertEqual(fixture.arguments["reason"], "component fixture")
        self.assertEqual(fixture.assertion_binding["challengeId"], "used")
        for replacement in ({"query_reads": result}, {"before_proofs": result.read_primary},
                            {"counted_before_heads": result.write}):
            with self.subTest(field=tuple(replacement)), self.assertRaises(admission.RevocationReadWriteError):
                self.verify(fixture, **replacement)
        self.assertNotIn("authorized", {field.name for field in fields(result)})

    def test_absent_counter_and_present_audit_are_proved_without_capacity_or_replay_authority(self):
        for counter_present, audit_present in ((False, False), (True, True)):
            with self.subTest(counter=counter_present, audit=audit_present):
                fixture = fixture_oracle.RevocationObservationFixture(
                    counter_present=counter_present, audit_present=audit_present)
                result = self.verify(fixture)
                self.assert_observation(fixture, result)
                counter = record_named(result.query_reads, "global_audit_capacity_before_v1")
                audit = record_named(result.query_reads, "audit_0")
                self.assertEqual((counter.addresses[0].present, counter.returned_row_count),
                                 (counter_present, int(counter_present)))
                self.assertEqual((audit.addresses[0].present, audit.returned_row_count),
                                 (audit_present, int(audit_present)))
                self.assertEqual(len(result.mutations), 3)
                self.assertFalse(any(item["table"] in ("metadata_audit_outbox",
                    fixture_oracle.counter_oracle.COUNTER_TABLE) for item in result.mutations))

    def test_all_phase_metrics_match_independent_documents_copy_frames_and_tree_work(self):
        for options in ({}, {"separate_signer": True, "pending_count": 2},
                        {"include_audit": False}, {"counter_present": False}, {"audit_present": True}):
            with self.subTest(options=options):
                fixture = fixture_oracle.RevocationObservationFixture(**options)
                expected = independent_metrics(fixture)
                result = self.verify(fixture)
                actual = {field.name: getattr(result.metrics, field.name) for field in fields(result.metrics)}
                for field in ("generation", "declaration_binding", "observation_validation",
                              "point_binding", "proof_work", "complete_binding"):
                    actual[field] = metrics_value(actual[field])
                self.assertEqual(actual, expected)
                self.assertEqual(result.metrics.generation.hash_work,
                                 24 + 2 * int(options.get("include_audit", True)))
                self.assertEqual(result.metrics.observation_validation.hash_work,
                    8 * 6 + len(fixture.selected_rows) + sum(len(record.addresses) for record in fixture.query_reads))
                self.assert_observation(fixture, result)

    def test_independently_exact_whole_budgets_succeed_and_each_minus_one_denies(self):
        fixture = fixture_oracle.RevocationObservationFixture()
        expected = independent_metrics(fixture)
        limits = {"max_hashes": expected["total_hashes"],
                  "max_input_bytes": expected["total_input_bytes"],
                  "max_json_nodes": expected["total_json_nodes"]}
        result = self.verify(fixture, limits=accounting.QueryReadValidationLimits(**limits))
        self.assert_observation(fixture, result)
        self.assertEqual((result.metrics.total_hashes, result.metrics.total_input_bytes, result.metrics.total_json_nodes),
                         tuple(limits.values()))
        for name in limits:
            tightened = {**limits, name: limits[name] - 1}
            with self.subTest(limit=name), self.assertRaises(admission.RevocationReadWriteError):
                self.verify(fixture, limits=accounting.QueryReadValidationLimits(**tightened))

    def test_generation_and_final_order_use_genuine_remaining_work_without_a_stale_reset(self):
        fixture = fixture_oracle.RevocationObservationFixture()
        expected = independent_metrics(fixture)
        limits = accounting.QueryReadValidationLimits(expected["total_hashes"],
            expected["total_input_bytes"], expected["total_json_nodes"])
        actual_generation, actual_verify = candidate._revocation_query_program, read_write._verify
        actual_complete = admission._bind_complete_order
        generations, proofs, completions = [], [], []

        def generate(**inputs):
            work = inputs["work"]
            generations.append((work.limits, work.metrics))
            return actual_generation(**inputs)

        def prove(owned, ledger, ownership_bytes, ownership_nodes):
            proofs.append((ledger.work, ledger.work.metrics, ledger.remaining()))
            return actual_verify(owned, ledger, ownership_bytes, ownership_nodes)

        def bind(proved, records, work):
            completions.append((work, work.metrics, work.limits))
            return actual_complete(proved, records, work)

        with patch.object(candidate, "_revocation_query_program", side_effect=generate), \
                patch.object(read_write, "_verify", side_effect=prove), \
                patch.object(admission, "_bind_complete_order", side_effect=bind):
            result = self.verify(fixture, limits=limits)
        self.assertEqual((len(generations), len(proofs), len(completions)), (1, 1, 1))
        self.assertEqual(generations[0][0], accounting.QueryReadValidationLimits(
            limits.max_hashes, limits.max_input_bytes - expected["raw_decode_bytes"] - expected["ownership_bytes"],
            limits.max_json_nodes - expected["ownership_nodes"]))
        self.assertEqual(metrics_value(generations[0][1]), unit_metrics())
        before_proof = unit_metrics(0, expected["raw_decode_bytes"] + expected["ownership_bytes"],
                                    expected["ownership_nodes"])
        for phase in ("generation", "declaration_binding", "observation_validation", "point_binding"):
            for name in before_proof:
                before_proof[name] += expected[phase][name]
        self.assertEqual(metrics_value(proofs[0][1]), before_proof)
        self.assertEqual(proofs[0][2], (limits.max_hashes - before_proof["hash_work"],
            limits.max_input_bytes - before_proof["input_bytes"], limits.max_json_nodes - before_proof["json_nodes"]))
        before_complete = {name: before_proof[name] + expected["proof_work"][name] for name in before_proof}
        self.assertEqual(metrics_value(completions[0][1]), before_complete)
        self.assertIs(completions[0][0], proofs[0][0])
        self.assertEqual(completions[0][2], limits)
        self.assertEqual(completions[0][1].hash_work, limits.max_hashes)
        self.assert_observation(fixture, result)
        # The last non-hashing phase is allowed at zero remaining hashes, but
        # must still debit CURRENT remaining bytes after genuine proof work.
        completions.clear()
        proofs.clear()
        with patch.object(read_write, "_verify", side_effect=prove), \
                patch.object(admission, "_bind_complete_order", side_effect=bind):
            with self.assertRaises(admission.RevocationReadWriteError):
                self.verify(fixture, limits=replace(limits, max_input_bytes=limits.max_input_bytes - 1))
        self.assertEqual((len(proofs), len(completions)), (1, 1))
        self.assertEqual(metrics_value(completions[0][1]), before_complete)
        self.assertIs(completions[0][0], proofs[0][0])

    def test_whole_limits_are_exact_downward_only_and_small_budgets_fail_before_hashing(self):
        fixture = fixture_oracle.RevocationObservationFixture()
        source = accounting.QueryReadValidationLimits()
        invalid = (True, {}, unit_metrics(), forged(source, max_hashes=True),
            forged(source, max_input_bytes=64 * 1024 * 1024 + 1),
            forged(source, max_json_nodes=1_000_001), forged(source, max_json_nodes=None),
            object.__new__(accounting.QueryReadValidationLimits))
        for limits in invalid:
            with self.subTest(kind=type(limits)), self.assertRaises(admission.RevocationReadWriteError):
                self.verify(fixture, limits=limits)
        actual_sha = hashlib.sha256
        for limits in (replace(source, max_input_bytes=1), replace(source, max_json_nodes=1)):
            with self.subTest(limits=limits), patch.object(hashlib, "sha256", wraps=actual_sha) as hashes:
                with self.assertRaises(admission.RevocationReadWriteError):
                    self.verify(fixture, limits=limits)
            self.assertEqual(hashes.call_count, 0)
        inputs = fixture.inputs()
        terminals = sum(len(item.frontier) for item in
                        (*inputs["query_frontiers"], *inputs["write_frontiers"]))
        records = len(fixture.query_reads)
        addresses = sum(len(record.addresses) for record in fixture.query_reads)
        # Literal necessary node lower bound for the combined normalized
        # ownership document, not the earlier frontier-only source ceiling.
        minimum = 35 + 11 * records + 9 * (addresses + terminals)
        with patch.object(read_write, "_raw_document", wraps=read_write._raw_document) as normalized, \
                patch.object(hashlib, "sha256", wraps=actual_sha) as hashes:
            with self.assertRaises(admission.RevocationReadWriteError):
                admission.verify_revocation_read_write_inputs(**inputs,
                    limits=replace(source, max_json_nodes=minimum - 1))
        self.assertEqual((normalized.call_count, hashes.call_count), (0, 0))


if __name__ == "__main__":
    unittest.main()
