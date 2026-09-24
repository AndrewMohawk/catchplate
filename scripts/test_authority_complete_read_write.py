#!/usr/bin/env python3
"""Real complete-read/indexed-write composition over independent populations.

All primary/count trees, profile leaves and expected transitions are independent
test oracles. The actual global membership, six joins and indexed writer run;
no successful verifier, authority token, SQL connection or kernel is replaced.
These authored controls are unrun. They do not establish business-kernel intent,
ordinary-query closure, audit capacity, maintained/current roots, atomic SQL,
Snapshot transport, trusted time, signed evidence or production activation.
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
from serverware import authority_complete_query_batch as read_batch
from serverware import authority_complete_read_write as composer
from serverware import authority_contract
from serverware import authority_index_contract as counted
from serverware import authority_index_join as joined
from serverware import authority_index_mutation as sparse
from serverware import authority_index_projection as projection
from serverware import authority_indexed_mutation as indexed
from serverware import authority_radix_mutation as primary
import test_authority_complete_query_batch as read_oracle
import test_authority_index_join as join_oracle
import test_authority_index_range as range_oracle
import test_authority_indexed_mutation as write_oracle
import test_authority_radix_mutation as primary_oracle


OPERATION = "webauthn.credential.revoke"


def values(value):
    return {field.name: getattr(value, field.name) for field in fields(value)}


def forged(value, **changes):
    result = object.__new__(type(value))
    for field in fields(value):
        object.__setattr__(result, field.name, changes.get(field.name, getattr(value, field.name)))
    return result


def template(table, kind, operation=OPERATION):
    matches = [value for value in authority_contract.operation_spec(operation)["mutationTemplates"]
               if value["table"] == table and value["mutation"] == kind]
    if len(matches) != 1:
        raise AssertionError("fixture needs one actual source table/kind template")
    return matches[0]["templateId"]


def default_rows():
    rows = read_oracle.default_rows()
    rows["webauthn_credentials"] = [write_oracle.credential("credential-雪")]
    return rows


def default_actions(rows):
    credential = rows["webauthn_credentials"][0]
    pending = next(row for row in rows["oidc_browser_sessions"] if row["id"] == "pending")
    grant = next(row for row in rows["approval_grants"] if row["id"] == "grant")
    return (
        ("webauthn_credentials", {"id": credential["id"]}, "UPDATE", {**credential, "revoked_at": "revoked"}),
        ("oidc_browser_sessions", {"id": pending["id"]}, "UPDATE", {**pending, "status": "revoked"}),
        ("approval_grants", {"id": grant["id"]}, "UPDATE", {**grant, "state": "consumed"}),
    )


def terminal_document(item):
    if type(item) is counted.IndexLeaf:
        return {"kind": "leaf", "key": item.key, "primaryKeyDigest": item.primary_key_digest,
                "primaryRowDigest": item.primary_row_digest}
    return {"kind": "opaque", "prefix": item.prefix, "digest": item.digest, "count": item.count}


def expected_primary_limits(maximum, hashes, input_bytes, nodes, *, writing=False):
    """Independent literal source bounds for observed actual phase arguments."""
    return {"max_selected_rows": maximum, "max_mutations": 137,
        "max_proof_vectors": 64 * maximum, "max_proof_child_slots": 1024 * maximum,
        "max_hashes": min(66 + (136 if writing else 70) * maximum, hashes),
        "max_input_bytes": input_bytes, "max_json_depth": 128, "max_json_nodes": nodes}


class ReadWriteFixture:
    """One source-wide population, independently rebuilt after exact events."""

    def __init__(self, rows=None, actions=None, *, arguments=None, extra_keys=(), expiry_after=None):
        rows = copy.deepcopy(default_rows() if rows is None else rows)
        actions = copy.deepcopy(default_actions(rows) if actions is None else actions)
        self.actions = actions
        self.read = read_oracle.BatchFixture(rows, arguments=arguments,
            extra_keys=(*extra_keys, *((table, key) for table, key, _, _ in actions)))
        self.rows = {item.table: copy.deepcopy(rows.get(item.table, [])) for item in self.read.contracts}
        before = {(item["table"], primary_oracle.wire_json(item["key"])): item for item in self.read.selected}
        self.mutations = tuple({**primary_oracle.change(before[(table, primary_oracle.wire_json(key))], kind, after),
                               "templateId": template(table, kind)}
                              for table, key, kind, after in actions)
        after_rows = {table: {primary_oracle.sql_json(self.read.trees[table].key(row)): copy.deepcopy(row)
                            for row in population} for table, population in self.rows.items()}
        for table, key, _, after in actions:
            after_rows[table].pop(primary_oracle.sql_json(key), None)
            if after is not None:
                after_rows[table][primary_oracle.sql_json(self.read.trees[table].key(after))] = copy.deepcopy(after)
        self.after_rows = {table: list(rows.values()) for table, rows in after_rows.items()}
        self.after_trees = {item.table: primary_oracle.IndependentTree(self.after_rows[item.table],
            table=item.table, columns=item.key_columns,
            revision=17 + sum(table == item.table for table, _, _, _ in actions)) for item in self.read.contracts}
        self.expiry_before = {"past": 1_000_000, "future": 2_000_000, "used": 3_000_000}
        self.expiry_after = {**self.expiry_before, **({} if expiry_after is None else expiry_after)}
        self.indexes = {}
        for table in sorted({mutation["table"] for mutation in self.mutations}):
            for index_id in write_oracle.PROFILE_TABLES.get(table, ()):
                profile = join_oracle.expected_profile(index_id)
                old_leaves = [write_oracle.image_leaf(profile, row, self.expiry_before.get(row["id"]))
                              for row in self.rows[table]]
                new_leaves = [write_oracle.image_leaf(profile, row, self.expiry_after.get(row["id"]))
                              for row in self.after_rows[table]]
                before_tree = range_oracle.IndependentIndex([leaf for leaf in old_leaves if leaf is not None], profile)
                after_tree = range_oracle.IndependentIndex([leaf for leaf in new_leaves if leaf is not None], profile)
                targets, delta = {}, 0
                for mutation in self.mutations:
                    if mutation["table"] != table:
                        continue
                    identifier = mutation["key"]["id"]
                    old = write_oracle.image_leaf(profile, mutation["expectedRow"], self.expiry_before.get(identifier))
                    new = write_oracle.image_leaf(profile, mutation["row"], self.expiry_after.get(identifier))
                    delta += int(old is not None or new is not None)
                    if old is not None:
                        targets.setdefault(old.key, [None, None])[0] = old
                    if new is not None:
                        targets.setdefault(new.key, [None, None])[1] = new
                self.indexes[index_id] = {"profile": profile, "before": before_tree, "after": after_tree,
                    "targets": targets, "frontier": write_oracle.sparse_frontier(before_tree, targets),
                    "revision_before": 29, "revision_delta": delta}
        read_heads = {info.profile.index_id: (29, info.index.root) for info in self.read.joins.values()}
        for index_id, info in self.indexes.items():
            if index_id in read_heads and read_heads[index_id] != (29, info["before"].root):
                raise AssertionError("independent query/write before populations disagree")
            read_heads[index_id] = (29, info["before"].root)
        self.heads = dict(sorted(read_heads.items()))

    def arguments(self):
        values = self.read.arguments()
        del values["read_heads"]
        return {**values, "mutations": copy.deepcopy(self.mutations),
            "counted_before_heads": tuple(composer.CompleteReadWriteHead(name, revision, copy.deepcopy(root))
                                          for name, (revision, root) in self.heads.items()),
            "write_frontiers": tuple(composer.CompleteWriteFrontier(name, copy.deepcopy(info["frontier"]))
                                     for name, info in sorted(self.indexes.items()))}

    def ownership_document(self):
        document = self.read.ownership_document()
        del document["readHeads"]
        document["countedBeforeHeads"] = [{"indexId": name, "indexRevision": revision,
            "rootDigest": root.digest, "leafCount": root.count} for name, (revision, root) in self.heads.items()]
        document["mutations"] = list(self.mutations)
        document["writeFrontiers"] = [{"indexId": name, "frontier": [terminal_document(item) for item in info["frontier"]]}
                                      for name, info in sorted(self.indexes.items())]
        return document

    def writer_arguments(self):
        return {"table_contracts": self.read.contracts,
            "business_before_roots": tuple(self.read.trees[item.table].root for item in self.read.contracts
                                           if item.root_class == "business"),
            "authorization_before_roots": tuple(self.read.trees[item.table].root for item in self.read.contracts
                                                if item.root_class == "authorization"),
            "selected_rows": self.read.selected, "before_proofs": self.read.proofs, "mutations": self.mutations,
            "index_inputs": tuple(indexed.IndexedMutationInput(name, 29, info["before"].root, info["frontier"])
                                  for name, info in sorted(self.indexes.items()))}

    def writer_metrics(self):
        inputs = self.writer_arguments()
        primary_metrics = write_oracle.primary_metrics(inputs)
        indexes = {name: write_oracle.index_metrics(info) for name, info in self.indexes.items()}
        projections = sum(2 * len(write_oracle.PROFILE_TABLES.get(item["table"], ()))
                          * (int(item["expectedRow"] is not None) + int(item["row"] is not None))
                          for item in self.mutations)
        new_rows = sum(item["row"] is not None and item["table"] in write_oracle.PROFILE_TABLES
                       for item in self.mutations)
        input_bytes = primary_metrics["input_bytes"] + write_oracle.context_bytes(inputs["index_inputs"])
        input_bytes += sum(metric["input_bytes"] for metric in indexes.values())
        hashes = primary_metrics["hash_work"] + len(indexes) + projections + new_rows
        hashes += sum(metric["before_hashes"] + metric["after_hashes"] for metric in indexes.values())
        return {"primary": primary_metrics, "indexes": indexes, "context_hashes": len(indexes),
            "projection_hash_allowance": projections, "new_row_hashes": new_rows,
            "input_bytes": input_bytes, "hashes": hashes}


class CompleteReadWriteTests(unittest.TestCase):
    def setUp(self):
        self.fixture = ReadWriteFixture()

    def verify(self, fixture=None, **changes):
        inputs = (self.fixture if fixture is None else fixture).arguments()
        inputs.update(changes)
        return composer.verify_complete_read_write_batch(**inputs)

    def assert_exact(self, fixture, result):
        self.assertEqual(result.operation, OPERATION)
        self.assertEqual(result.arguments, fixture.read.intent)
        self.assertEqual(result.cutoff_us, fixture.read.cutoff_us)
        self.assertEqual(result.selected_rows, fixture.read.selected)
        self.assertEqual(result.before_proofs, fixture.read.proofs)
        self.assertEqual(result.mutations, fixture.mutations)
        self.assertEqual(result.queries, fixture.read.queries)
        before = tuple((name, revision, root) for name, (revision, root) in fixture.heads.items())
        after = tuple((name, info["revision_before"] + info["revision_delta"], info["after"].root)
            if (info := fixture.indexes.get(name)) is not None else (name, revision, root)
            for name, (revision, root) in fixture.heads.items())
        self.assertEqual(tuple((head.index_id, head.index_revision, head.index_root) for head in result.before_heads), before)
        self.assertEqual(tuple((head.index_id, head.index_revision, head.index_root) for head in result.after_heads), after)
        self.assertEqual(result.read_primary.business_after_roots, result.business_before_roots)
        self.assertEqual(result.read_primary.authorization_after_roots, result.authorization_before_roots)
        self.assertEqual(result.write.primary.business_after_roots,
            tuple(fixture.after_trees[item.table].root for item in fixture.read.contracts if item.root_class == "business"))
        self.assertEqual(result.write.primary.authorization_after_roots,
            tuple(fixture.after_trees[item.table].root for item in fixture.read.contracts if item.root_class == "authorization"))
        self.assertEqual(values(result.read_primary.metrics), fixture.read.primary_metrics())
        expected = fixture.writer_metrics()
        self.assertEqual(values(result.write.primary.metrics), expected["primary"])
        self.assertEqual({name: values(metric) for name, metric in result.write.metrics.indexes}, expected["indexes"])
        for name in ("context_hashes", "projection_hash_allowance", "new_row_hashes", "input_bytes", "hashes"):
            self.assertEqual(getattr(result.write.metrics, name), expected[name])
        self.assertIs(result.metrics.read_primary, result.read_primary.metrics)
        self.assertIs(result.metrics.write, result.write.metrics)
        self.assertEqual(result.metrics.read_context_hashes, 101)
        self.assertEqual(result.metrics.write_context_hashes, 2 * len(set(fixture.heads) - set(read_oracle.READ_INDEX_IDS)))
        self.assertEqual(tuple(query_id for query_id, _ in result.joined_reads),
                         tuple(query.query_id for query in fixture.read.queries))
        for query, (query_id, observation) in zip(fixture.read.queries, result.joined_reads):
            self.assertEqual(query_id, query.query_id)
            info = fixture.read.joins[query.role]
            self.assertEqual(observation.anchor, info.anchor)
            self.assertEqual(observation.leaves, info.index.matches(info.interval))

    def test_true_seven_head_union_and_both_root_transitions_match_independent_populations(self):
        result = self.verify()
        self.assert_exact(self.fixture, result)
        self.assertEqual(len(result.before_heads), 8)
        self.assertEqual(len(result.write.before_heads), 5)
        self.assertEqual(len(result.joined_reads), 6)
        self.assertEqual(result.metrics.write_context_hashes, 6)

    def test_actual_global_five_joins_and_one_indexed_writer_retain_real_result_identity(self):
        memberships, primary_writes, writes, joins = [], [], [], []
        original_membership = primary.evaluate_primary_radix_memberships
        original_inputs = primary.evaluate_primary_radix_inputs
        original_write = indexed.evaluate_indexed_primary_batch
        original_join = joined.join_index_range
        def membership(**inputs):
            result = original_membership(**inputs)
            memberships.append((inputs, result))
            return result
        def primary_inputs(**inputs):
            result = original_inputs(**inputs)
            primary_writes.append((inputs, result))
            return result
        def write(**inputs):
            result = original_write(**inputs)
            writes.append((inputs, result))
            return result
        def join(**inputs):
            result = original_join(**inputs)
            joins.append((inputs, result))
            return result
        with mock.patch.object(primary, "evaluate_primary_radix_memberships", side_effect=membership), \
                mock.patch.object(primary, "evaluate_primary_radix_inputs", side_effect=primary_inputs), \
                mock.patch.object(indexed, "evaluate_indexed_primary_batch", side_effect=write), \
                mock.patch.object(joined, "join_index_range", side_effect=join):
            result = self.verify()
        self.assertEqual((len(memberships), len(primary_writes), len(writes), len(joins)), (7, 1, 1, 6))
        self.assertIs(result.read_primary, memberships[0][1].result)
        self.assertIs(result.write, writes[0][1])
        self.assertIs(result.write.primary, primary_writes[0][1].result)
        self.assertEqual(writes[0][0]["selected_rows"], self.fixture.read.selected)
        self.assertEqual(writes[0][0]["before_proofs"], self.fixture.read.proofs)
        self.assertEqual(writes[0][0]["mutations"], self.fixture.mutations)
        for (_, actual), (_, observation) in zip(joins, result.joined_reads):
            self.assertIs(actual, observation)
        # Source-clamp observations at ordinary fixture pressure, not a claim
        # that every independent work ceiling is simultaneously attainable.
        ownership = self.fixture.ownership_document()
        ordinary = [item for item in self.fixture.read.selected if not (
            item["table"] == capacity.AGGREGATE_TABLE and item["key"] == {"aggregate_id": capacity.AGGREGATE_ID})]
        envelopes = (ordinary, list(self.fixture.read.selected))
        used_hashes = 101
        used_bytes = len(primary_oracle.wire_json(ownership)) + sum(
            len(primary_oracle.wire_json(value)) for value in envelopes)
        used_nodes = join_oracle.graph_nodes(ownership) + sum(
            join_oracle.graph_nodes(value) for value in envelopes)
        self.assertEqual(values(memberships[0][0]["limits"]), expected_primary_limits(
            193, 8_000_000 - used_hashes, 64 * 1024 * 1024 - used_bytes, 1_000_000 - used_nodes))
        metric = memberships[0][1].result.metrics
        used_hashes += metric.hash_work
        used_bytes += metric.input_bytes
        used_nodes += metric.json_nodes
        for ordinal, (query, (inputs, observation)) in enumerate(zip(self.fixture.read.queries, joins)):
            with self.subTest(phase=query.role):
                hashes = 8_000_000 - used_hashes
                input_bytes = 64 * 1024 * 1024 - used_bytes
                nodes = 1_000_000 - used_nodes
                maximum = read_oracle.declaration_oracle.complete_document(query.role,
                    values=self.fixture.read.intent)["maximumRows"]
                opened = 1 + 160 * maximum + 320
                limits = inputs["limits"]
                self.assertEqual(values(limits.primary), expected_primary_limits(maximum, hashes, input_bytes, nodes))
                self.assertEqual(values(limits.index), {
                    "max_entries": 4800 + maximum, "max_leaves": maximum, "max_opened_nodes": opened,
                    "max_hashes": min(16 * opened + maximum, hashes),
                    "max_input_bytes": min(4 * 1024 * 1024, input_bytes)})
                self.assertEqual(limits.max_total_hashes, min(1_100_000, hashes))
                self.assertEqual(limits.max_total_input_bytes,
                                 min(64 * 1024 * 1024 + 4 * 1024 * 1024 + 262144, input_bytes))
                inner = expected_primary_limits(maximum, hashes, input_bytes, nodes)
                inner["max_hashes"] = min(inner["max_hashes"], limits.max_total_hashes
                    - 69 - 2 - observation.metrics.index.hashes - 2 * len(observation.leaves))
                inner["max_input_bytes"] = min(inner["max_input_bytes"], limits.max_total_input_bytes
                    - observation.metrics.context_bytes - observation.metrics.index.input_bytes)
                self.assertEqual(values(memberships[ordinal + 1][0]["limits"]), inner)
                used_hashes += observation.metrics.total_hashes
                used_bytes += observation.metrics.total_input_bytes
                used_nodes += observation.metrics.primary.json_nodes
        used_hashes += 2 * len(set(self.fixture.heads) - set(read_oracle.READ_INDEX_IDS))
        hashes, input_bytes, nodes = (8_000_000 - used_hashes,
            64 * 1024 * 1024 - used_bytes, 1_000_000 - used_nodes)
        limits = writes[0][0]["limits"]
        self.assertEqual(values(limits.primary), expected_primary_limits(193, hashes, input_bytes, nodes, writing=True))
        self.assertEqual(values(limits.index), {"max_changes": 274, "max_frontier_entries": 701456,
            "max_opened_nodes": 43841, "max_hashes": min(2 * (16 * 43841 + 274), hashes),
            "max_input_bytes": input_bytes})
        self.assertEqual((limits.max_total_hashes, limits.max_total_input_bytes), (hashes, input_bytes))
        # The indexed evaluator first reserves every raw sparse frontier plus
        # its context framing. Its real primary call must see that byte debit.
        reservations = 0
        for item in writes[0][0]["index_inputs"]:
            for record in item.frontier:
                scalars = (("leaf", record.key, record.primary_key_digest, record.primary_row_digest)
                    if type(record) is counted.IndexLeaf else
                    ("opaque", record.prefix, record.digest, str(record.count)))
                reservations += sum(8 + len(value.encode("ascii")) for value in scalars)
        reservations += write_oracle.context_bytes(writes[0][0]["index_inputs"])
        inner_write = expected_primary_limits(193, hashes, input_bytes, nodes, writing=True)
        inner_write["max_input_bytes"] -= reservations
        self.assertEqual(values(primary_writes[0][0]["limits"]), inner_write)
        used_hashes += result.write.metrics.hashes
        used_bytes += result.write.metrics.input_bytes
        used_nodes += result.write.metrics.primary.json_nodes
        self.assertEqual((used_hashes, used_bytes, used_nodes),
                         (result.metrics.total_hashes, result.metrics.total_input_bytes, result.metrics.total_json_nodes))

    def test_query_write_overlap_uses_one_before_head_and_read_only_after_heads_are_unchanged(self):
        result = self.verify()
        heads = {head.index_id: head for head in result.before_heads}
        after = {head.index_id: head for head in result.after_heads}
        written = {head.index_id: head for head in result.write.before_heads}
        for _, observation in result.joined_reads:
            head = heads[observation.anchor.index_id]
            self.assertEqual((head.index_revision, head.index_root),
                             (observation.anchor.index_revision, observation.anchor.index_root))
            self.assertEqual(observation.anchor.primary_root,
                             self.fixture.read.trees[observation.anchor.primary_root.table].root)
            if head.index_id in written:
                self.assertEqual((written[head.index_id].index_revision, written[head.index_id].index_root),
                                 (head.index_revision, head.index_root))
        read_only = set(heads) - set(written)
        self.assertEqual(read_only, {"webauthn_control_approval_approved", "webauthn_registration_unused_global"})
        for index_id in read_only:
            self.assertEqual(after[index_id], heads[index_id])

    def test_zero_write_batch_still_verifies_five_empty_reads_and_unchanged_full_roots(self):
        fixture = ReadWriteFixture({}, ())
        result = self.verify(fixture)
        self.assert_exact(fixture, result)
        self.assertEqual(len(result.before_heads), 5)
        self.assertEqual(result.before_heads, result.after_heads)
        self.assertEqual(result.write.before_heads, ())
        self.assertEqual(result.write.after_heads, ())
        self.assertEqual(result.write.primary.metrics.mutations, 0)
        self.assertTrue(all(observation.leaves == () for _, observation in result.joined_reads))
        self.assertEqual(result.metrics.write_context_hashes, 0)

    def test_all_fixed_write_profiles_remain_required_for_two_nonmember_images(self):
        rows = default_rows()
        old = rows["webauthn_credentials"][0]
        old["revoked_at"] = "already-revoked"
        fixture = ReadWriteFixture(rows, (("webauthn_credentials", {"id": old["id"]}, "UPDATE",
                                         {**old, "sign_count": old["sign_count"] + 1}),))
        result = self.verify(fixture)
        self.assert_exact(fixture, result)
        live_id = "webauthn_credential_live_trust"
        self.assertEqual(fixture.indexes[live_id]["targets"], {})
        before = next(head for head in result.before_heads if head.index_id == live_id)
        after = next(head for head in result.after_heads if head.index_id == live_id)
        self.assertEqual(after, before)
        inputs = fixture.arguments()
        with self.assertRaises(composer.CompleteReadWriteError):
            self.verify(fixture, write_frontiers=tuple(item for item in inputs["write_frontiers"] if item.index_id != live_id))
        with self.assertRaises(composer.CompleteReadWriteError):
            self.verify(fixture, counted_before_heads=tuple(item for item in inputs["counted_before_heads"] if item.index_id != live_id))

    def test_equal_member_update_and_partition_move_preserve_exact_event_revision_rules(self):
        rows = default_rows()
        old = rows["oidc_browser_sessions"][0]
        for label, after in (("equal", dict(old)), ("move", {**old, "status": "active"})):
            fixture = ReadWriteFixture(rows, (("oidc_browser_sessions", {"id": old["id"]}, "UPDATE", after),))
            with self.subTest(kind=label):
                result = self.verify(fixture)
                self.assert_exact(fixture, result)
                before = result.write.before_heads[0]
                new = result.write.after_heads[0]
                self.assertEqual(new.index_revision, before.index_revision + 1)
                self.assertEqual(new.index_root.count, before.index_root.count)
                self.assertEqual(len(fixture.indexes[before.index_id]["targets"]), 1 if label == "equal" else 2)
                if label == "equal":
                    self.assertEqual(new.index_root, before.index_root)
                else:
                    self.assertNotEqual(new.index_root, before.index_root)

    def test_full_eight_profile_union_includes_both_challenge_profiles_and_excludes_publication(self):
        rows = default_rows()
        future = next(item for item in rows["webauthn_challenges"] if item["id"] == "future")
        actions = (*default_actions(rows), ("webauthn_challenges", {"id": "future"}, "UPDATE",
                                            {**future, "used_at": "consumed"}))
        fixture = ReadWriteFixture(rows, actions)
        result = self.verify(fixture)
        self.assert_exact(fixture, result)
        self.assertEqual(len(result.before_heads), 9)
        self.assertEqual(result.metrics.write_context_hashes, 8)
        self.assertIn("webauthn_registration_unused_user", {head.index_id for head in result.before_heads})
        inputs = fixture.arguments()
        self.assertIn("webauthn_publication_status", {head.index_id for head in result.before_heads})
        # The historical method ID is retained; publication is now required
        # for proved pending absence, while unrelated profiles remain denied.
        bad = forged(inputs["counted_before_heads"][0], index_id="webauthn_publication_generation")
        with self.assertRaises(composer.CompleteReadWriteError):
            self.verify(fixture, counted_before_heads=(bad, *inputs["counted_before_heads"][1:]))
        publication_id = "webauthn_publication_generation"
        publication = range_oracle.IndependentIndex([], join_oracle.expected_profile(publication_id))
        extra = composer.CompleteReadWriteHead(publication_id, 0, publication.root)
        complete_plus_extra = tuple(sorted((*inputs["counted_before_heads"], extra), key=lambda item: item.index_id))
        self.assertEqual(len(complete_plus_extra), 10)
        self.assertTrue(set(fixture.heads) < {item.index_id for item in complete_plus_extra})
        with self.assertRaisesRegex(composer.CompleteReadWriteError, "union"):
            self.verify(fixture, counted_before_heads=complete_plus_extra)
        mutations = copy.deepcopy(inputs["mutations"])
        mutations[0]["table"] = "webauthn_trust_publications"
        with self.assertRaises(composer.CompleteReadWriteError):
            self.verify(fixture, mutations=mutations)

    def test_source_operation_templates_reject_unknown_cross_operation_kind_and_table_claims(self):
        inputs = self.fixture.arguments()
        candidates = (
            "component-template-not-authority",
            template("webauthn_credentials", "UPDATE", "webauthn.counter.cas"),
            template("webauthn_credentials", "INSERT"),
            template("approval_grants", "UPDATE"),
        )
        original = primary.evaluate_primary_radix_memberships
        for identifier in candidates:
            mutations = copy.deepcopy(inputs["mutations"])
            mutations[0]["templateId"] = identifier
            with self.subTest(template_id=identifier), \
                    mock.patch.object(primary, "evaluate_primary_radix_memberships", wraps=original) as observe:
                with self.assertRaises(composer.CompleteReadWriteError):
                    self.verify(mutations=mutations)
                self.assertEqual(observe.call_count, 0)

    def test_union_and_write_frontier_inventories_reject_omissions_duplicates_and_independent_heads(self):
        inputs = self.fixture.arguments()
        heads, frontiers = inputs["counted_before_heads"], inputs["write_frontiers"]
        read_only = next(item for item in heads if item.index_id == "webauthn_registration_unused_global")
        candidates = (
            {"counted_before_heads": tuple(item for item in heads if item is not read_only)},
            {"counted_before_heads": (*heads, heads[0])},
            {"counted_before_heads": tuple(reversed(heads))},
            {"write_frontiers": frontiers[:-1]}, {"write_frontiers": (*frontiers, frontiers[0])},
            {"write_frontiers": tuple(reversed(frontiers))},
            {"write_frontiers": (*frontiers, composer.CompleteWriteFrontier(read_only.index_id, ()))},
            {"counted_before_heads": (replace(heads[0], index_root=heads[1].index_root), *heads[1:])},
        )
        for ordinal, changes in enumerate(candidates):
            with self.subTest(case=ordinal), self.assertRaises(composer.CompleteReadWriteError):
                self.verify(**changes)
        with self.assertRaises(TypeError):
            self.verify(read_heads=inputs["counted_before_heads"])

    def test_actual_global_primary_read_frontier_and_write_before_image_corruption_reject(self):
        inputs = self.fixture.arguments()
        proofs = copy.deepcopy(inputs["before_proofs"])
        vector = proofs[0]["siblings"][0]
        vector["childDigests"][(int(vector["selectedNibble"], 16) + 1) % 16] = "sha256:" + "e" * 64
        primary_oracle.refresh_proof_digest(proofs[0])
        with self.assertRaises(composer.CompleteReadWriteError):
            self.verify(before_proofs=proofs)
        query_frontier = inputs["query_frontiers"][0]
        leaf = next(item for item in query_frontier.frontier if type(item) is counted.IndexLeaf)
        with self.assertRaises(composer.CompleteReadWriteError):
            self.verify(query_frontiers=(replace(query_frontier,
                frontier=tuple(item for item in query_frontier.frontier if item is not leaf)),
                *inputs["query_frontiers"][1:]))
        write_frontier = next(item for item in inputs["write_frontiers"]
                              if any(type(record) is counted.IndexLeaf for record in item.frontier))
        omitted = replace(write_frontier, frontier=tuple(item for item in write_frontier.frontier
                                                         if type(item) is not counted.IndexLeaf))
        with self.assertRaises(composer.CompleteReadWriteError):
            self.verify(write_frontiers=tuple(omitted if item.index_id == omitted.index_id else item
                                              for item in inputs["write_frontiers"]))
        mutations = copy.deepcopy(inputs["mutations"])
        mutations[0]["expectedRow"]["sign_count"] += 100
        with self.assertRaises(composer.CompleteReadWriteError):
            self.verify(mutations=mutations)

    def test_key_moving_updates_unselected_targets_and_duplicate_events_are_not_admitted(self):
        inputs = self.fixture.arguments()
        changes = copy.deepcopy(inputs["mutations"])
        changes[0]["row"]["id"] = "different-primary-id"
        with self.assertRaises(composer.CompleteReadWriteError):
            self.verify(mutations=changes)
        with self.assertRaises(composer.CompleteReadWriteError):
            self.verify(mutations=(*inputs["mutations"], inputs["mutations"][0]))
        target = inputs["mutations"][0]
        address = (target["table"], target["keyDigest"])
        with self.assertRaises(composer.CompleteReadWriteError):
            self.verify(selected_rows=tuple(item for item in inputs["selected_rows"]
                                           if (item["table"], item["keyDigest"]) != address),
                        before_proofs=tuple(item for item in inputs["before_proofs"]
                                            if (item["table"], item["keyDigest"]) != address))
        # DELETE is a generic low-engine event, not a source template of this
        # explicit-revocation contract. It cannot acquire authority here.
        changes = copy.deepcopy(inputs["mutations"])
        changes[0]["operation"], changes[0]["row"] = "DELETE", None
        with self.assertRaises(composer.CompleteReadWriteError):
            self.verify(mutations=changes)

    def test_query_bindings_empty_role_inventory_and_shared_session_union_remain_enforced(self):
        inputs = self.fixture.arguments()
        changed = copy.deepcopy(inputs["arguments"])
        changed["record_id"] = "another-credential"
        for changes in ({"arguments": changed}, {"cutoff_us": inputs["cutoff_us"] + 1},
                        {"queries": inputs["queries"][:-1]}, {"query_frontiers": inputs["query_frontiers"][:-1]}):
            with self.subTest(change=tuple(changes)), self.assertRaises(composer.CompleteReadWriteError):
                self.verify(**changes)
        rows = default_rows()
        rows["oidc_browser_sessions"] = (
            [read_oracle.session(f"pending-{index:02}", "pending_webauthn") for index in range(17)]
            + [read_oracle.session(f"active-{index:02}", "active") for index in range(16)])
        intent = copy.deepcopy(self.fixture.read.intent)
        intent["oidc_session_ids"] = [f"hint-{index:02}" for index in range(32)]
        fixture = ReadWriteFixture(rows, (), arguments=intent)
        self.assertEqual([len(fixture.read.joins[role].selected) for role in read_oracle.ROLES[:2]], [17, 16])
        with self.assertRaises(composer.CompleteReadWriteError):
            self.verify(fixture)

    def test_all_mutations_union_heads_and_later_frontiers_are_owned_before_first_real_hash(self):
        inputs = self.fixture.arguments()
        original = projection._framed_hash
        observed = []
        def hashing(*frames):
            if not observed:
                observed.append(True)
                inputs["arguments"]["record_id"] = "caller-substitution"
                inputs["mutations"][0]["templateId"] = "caller-substitution"
                inputs["mutations"][0]["row"]["sign_count"] += 1000
                inputs["mutations"][-1]["expectedRow"]["state"] = "caller-substitution"
                for root in inputs["business_before_roots"]:
                    root["rootRevision"] += 50
                    root["rootDigest"] = "sha256:" + "e" * 64
                write_only = next(item for item in inputs["counted_before_heads"]
                                  if item.index_id == "webauthn_credential_id")
                object.__setattr__(write_only, "index_revision", 500)
                object.__setattr__(write_only.index_root, "digest", "sha256:" + "f" * 64)
                later = next(item for item in inputs["write_frontiers"][-1].frontier
                             if type(item) is counted.IndexLeaf)
                object.__setattr__(later, "primary_row_digest", "sha256:" + "d" * 64)
                read_leaf = next(item for item in inputs["query_frontiers"][-2].frontier
                                 if type(item) is counted.IndexLeaf)
                object.__setattr__(read_leaf, "primary_row_digest", "sha256:" + "c" * 64)
                inputs["selected_rows"][0]["row"]["changed"] = True
                inputs["before_proofs"][-1]["rowDigest"] = "sha256:" + "b" * 64
            return original(*frames)
        with mock.patch.object(projection, "_framed_hash", side_effect=hashing):
            result = composer.verify_complete_read_write_batch(**inputs)
        self.assertEqual(observed, [True])
        self.assert_exact(self.fixture, result)

    def test_returned_owned_graphs_and_frozen_heads_are_observations_not_success_tokens(self):
        inputs = self.fixture.arguments()
        result = composer.verify_complete_read_write_batch(**inputs)
        self.assertIsNot(result.mutations[0], inputs["mutations"][0])
        self.assertIsNot(result.mutations[0]["row"], inputs["mutations"][0]["row"])
        self.assertIsNot(result.selected_rows[0], inputs["selected_rows"][0])
        result.mutations[0]["row"]["observation-only"] = True
        result.arguments["record_id"] = "observation-only"
        self.assertEqual(inputs["mutations"], self.fixture.mutations)
        self.assertEqual(inputs["arguments"], self.fixture.read.intent)
        with self.assertRaises(FrozenInstanceError):
            result.cutoff_us = 0
        with self.assertRaises(FrozenInstanceError):
            result.after_heads[0].index_revision = 0
        with self.assertRaises(TypeError):
            self.verify(verified_result=result)
        with self.assertRaises(composer.CompleteReadWriteError):
            self.verify(write_frontiers=result.write)

    def test_exact_context_types_revision_aliases_and_missing_dtos_fail_closed(self):
        inputs = self.fixture.arguments()
        heads, frontiers = inputs["counted_before_heads"], inputs["write_frontiers"]
        variants = (
            {"mutations": list(inputs["mutations"])}, {"counted_before_heads": list(heads)},
            {"counted_before_heads": (object.__new__(composer.CompleteReadWriteHead), *heads[1:])},
            {"write_frontiers": (object.__new__(composer.CompleteWriteFrontier), *frontiers[1:])},
            {"counted_before_heads": (forged(heads[0], index_revision=True), *heads[1:])},
            {"counted_before_heads": (forged(heads[0], index_revision=2**63), *heads[1:])},
            {"counted_before_heads": (forged(heads[0], index_root=forged(heads[0].index_root, count=True)), *heads[1:])},
        )
        for ordinal, changes in enumerate(variants):
            with self.subTest(case=ordinal), self.assertRaises(composer.CompleteReadWriteError):
                self.verify(**changes)
        mutations = copy.deepcopy(inputs["mutations"])
        mutations[0]["row"]["non-lossless-json"] = 0.5
        with self.assertRaises(composer.CompleteReadWriteError):
            self.verify(mutations=mutations)

    def test_cumulative_terminal_minimum_nodes_deny_before_normalized_record_expansion(self):
        inputs = self.fixture.arguments()
        first, second = inputs["write_frontiers"][:2]
        # Reuse valid immutable DTOs: no large unique proof population is
        # constructed. Individually both tuples fit; together their minimum
        # 9 JSON nodes per record already exceed the real one-million cap.
        frontiers = (replace(first, frontier=(first.frontier[0],) * 60_000),
                     replace(second, frontier=(second.frontier[0],) * 60_000),
                     *inputs["write_frontiers"][2:])
        self.assertLess(60_000 * 9, 1_000_000)
        self.assertGreater(120_000 * 9, 1_000_000)
        with mock.patch.object(composer, "_raw_records", wraps=composer._raw_records) as write_records, \
                mock.patch.object(read_batch, "_raw_document", wraps=read_batch._raw_document) as query_document:
            with self.assertRaisesRegex(composer.CompleteReadWriteError, "normalization.*node budget"):
                self.verify(write_frontiers=frontiers)
        self.assertEqual(write_records.call_count, 0)
        self.assertEqual(query_document.call_count, 0)

    def test_source_192_business_rows_plus_optional_exact_framework_absence_are_distinct_slots(self):
        extras = tuple(("metadata_audit_outbox", {"id": f"point-{index:03}"}) for index in range(190))
        framework = (capacity.AGGREGATE_TABLE, {"aggregate_id": capacity.AGGREGATE_ID})
        # Empty queries and zero writes keep this genuine193-proof case
        # separate from maximum joined-member/mutation pressure.
        fixture = ReadWriteFixture({}, (), extra_keys=(*extras, framework))
        self.assertEqual(len(fixture.read.selected), 193)
        self.assertTrue(all(item["present"] is False for item in fixture.read.selected))
        result = self.verify(fixture)
        self.assert_exact(fixture, result)
        self.assertEqual(result.read_primary.metrics.selected_rows, 193)
        self.assertEqual(result.write.primary.metrics.selected_rows, 193)
        self.assertLessEqual(result.metrics.total_json_nodes, 1_000_000)
        alias = ReadWriteFixture({}, (), extra_keys=(*extras,
            (capacity.AGGREGATE_TABLE, {"aggregate_id": "ordinary-aggregate"})))
        self.assertEqual(len(alias.read.selected), 193)
        original = primary.evaluate_primary_radix_memberships
        with mock.patch.object(primary, "evaluate_primary_radix_memberships", wraps=original) as observe:
            with self.assertRaises(composer.CompleteReadWriteError):
                self.verify(alias)
        self.assertEqual(observe.call_count, 0)
        inputs = fixture.arguments()
        inputs["selected_rows"] += (inputs["selected_rows"][0],)
        inputs["before_proofs"] += (inputs["before_proofs"][0],)
        with self.assertRaises(composer.CompleteReadWriteError):
            composer.verify_complete_read_write_batch(**inputs)

    def test_source_136_business_mutations_plus_exact_framework_update_are_not_137_business(self):
        rows = default_rows()
        outbox = [{"id": f"audit-{index:03}", "component_value": 0} for index in range(136)]
        rows["metadata_audit_outbox"] = outbox
        framework = {"aggregate_id": capacity.AGGREGATE_ID, "component_value": 0}
        rows[capacity.AGGREGATE_TABLE] = [framework]
        # The full-row/proof computation is genuine, but this tiny framework
        # row is deliberately not an initialized audit-capacity state claim.
        actions = tuple(("metadata_audit_outbox", {"id": row["id"]}, "UPDATE", {**row, "component_value": 1})
                        for row in outbox) + ((capacity.AGGREGATE_TABLE,
                            {"aggregate_id": capacity.AGGREGATE_ID}, "UPDATE", {**framework, "component_value": 1}),)
        fixture = ReadWriteFixture(rows, actions)
        self.assertEqual(len(fixture.mutations), 137)
        result = self.verify(fixture)
        self.assert_exact(fixture, result)
        self.assertEqual(result.write.primary.metrics.mutations, 137)
        self.assertEqual(result.write.before_heads, ())
        self.assertEqual(result.before_heads, result.after_heads)
        alias_rows = copy.deepcopy(rows)
        alias_rows[capacity.AGGREGATE_TABLE][0]["aggregate_id"] = "ordinary-aggregate"
        alias_actions = (*actions[:-1], (capacity.AGGREGATE_TABLE, {"aggregate_id": "ordinary-aggregate"},
            "UPDATE", {"aggregate_id": "ordinary-aggregate", "component_value": 1}))
        alias = ReadWriteFixture(alias_rows, alias_actions)
        original = primary.evaluate_primary_radix_memberships
        with mock.patch.object(primary, "evaluate_primary_radix_memberships", wraps=original) as observe:
            with self.assertRaises(composer.CompleteReadWriteError):
                self.verify(alias)
        self.assertEqual(observe.call_count, 0)
        with self.assertRaises(composer.CompleteReadWriteError):
            self.verify(fixture, mutations=(*fixture.mutations, fixture.mutations[0]))

    def test_selected_envelope_limit_does_not_invent_a_separate_four_mib_new_image_limit(self):
        inputs = self.fixture.arguments()
        present = next(item for item in inputs["selected_rows"] if item["present"])
        present["row"]["padding"] = "x" * (4 * 1024 * 1024)
        original = primary.evaluate_primary_radix_memberships
        with mock.patch.object(primary, "evaluate_primary_radix_memberships", wraps=original) as observe:
            with self.assertRaises(composer.CompleteReadWriteError):
                composer.verify_complete_read_write_batch(**inputs)
        self.assertEqual(observe.call_count, 0)
        # NEW images belong to the shared64MiB computation budget. This is a
        # genuine source-template/full-CAS calculation, not kernel permission
        # to emit an application audit row or a claim of maximum valid size.
        rows = default_rows()
        old = {"id": "large-new-image", "payload": "old"}
        rows["metadata_audit_outbox"] = [old]
        after = {**old, "payload": "x" * (5 * 1024 * 1024)}
        fixture = ReadWriteFixture(rows, (("metadata_audit_outbox", {"id": old["id"]}, "UPDATE", after),))
        self.assertGreater(len(primary_oracle.wire_json(fixture.mutations)), 4 * 1024 * 1024)
        result = self.verify(fixture)
        self.assert_exact(fixture, result)
        self.assertLess(result.metrics.total_input_bytes, 64 * 1024 * 1024)
        self.assertEqual(result.before_heads, result.after_heads)

    def test_independent_aggregate_metrics_charge_one_ownership_graph_and_every_real_phase(self):
        result = self.verify()
        ownership = self.fixture.ownership_document()
        ordinary = [item for item in self.fixture.read.selected if not (
            item["table"] == capacity.AGGREGATE_TABLE and item["key"] == {"aggregate_id": capacity.AGGREGATE_ID})]
        envelopes = (ordinary, list(self.fixture.read.selected))
        ownership_bytes = len(primary_oracle.wire_json(ownership))
        ownership_nodes = join_oracle.graph_nodes(ownership)
        envelope_bytes = sum(len(primary_oracle.wire_json(value)) for value in envelopes)
        envelope_nodes = sum(join_oracle.graph_nodes(value) for value in envelopes)
        read = self.fixture.read.primary_metrics()
        queries = [self.fixture.read.join_metrics(role) for role in read_oracle.ROLES]
        write = self.fixture.writer_metrics()
        write_context = 2 * len(set(self.fixture.heads) - set(read_oracle.READ_INDEX_IDS))
        metrics = result.metrics
        self.assertEqual((metrics.ownership_bytes, metrics.ownership_nodes), (ownership_bytes, ownership_nodes))
        self.assertEqual((metrics.selected_envelope_bytes, metrics.selected_envelope_nodes),
                         (envelope_bytes, envelope_nodes))
        self.assertEqual((metrics.read_context_hashes, metrics.write_context_hashes), (101, write_context))
        self.assertEqual(metrics.total_hashes,
            101 + write_context + read["hash_work"] + sum(item["total_hashes"] for item in queries) + write["hashes"])
        self.assertEqual(metrics.total_input_bytes,
            ownership_bytes + envelope_bytes + read["input_bytes"]
            + sum(item["total_input_bytes"] for item in queries) + write["input_bytes"])
        self.assertEqual(metrics.total_json_nodes,
            ownership_nodes + envelope_nodes + read["json_nodes"]
            + sum(item["primary"]["json_nodes"] for item in queries) + write["primary"]["json_nodes"])
        self.assertEqual(tuple(query_id for query_id, _ in metrics.queries),
                         tuple(query.query_id for query in self.fixture.read.queries))
        for (_, metric), expected in zip(metrics.queries, queries):
            actual = values(metric)
            actual["primary"], actual["index"] = values(metric.primary), values(metric.index)
            self.assertEqual(actual, expected)
        manifest = join_oracle.framed("serverware.policyAuthorityIndexProjectionManifest/v1",
            join_oracle.utf8_json([join_oracle.descriptor(name) for name in read_oracle.ALL_INDEX_IDS]))
        self.assertEqual(result.projection_manifest_digest, manifest)
        self.assertEqual((composer.MAX_TOTAL_HASHES, composer.MAX_TOTAL_INPUT_BYTES, composer.MAX_TOTAL_JSON_NODES),
                         (8_000_000, 64 * 1024 * 1024, 1_000_000))


if __name__ == "__main__":
    unittest.main()
