#!/usr/bin/env python3
"""Real indexed evaluation over deterministic independent SQL result records.

The cursor below is deliberately NOT PostgreSQL: it checks the producer's
fixed SELECT shape and returns independently committed stored rows. Genuine
primary verification, fixed projections and both sparse folds always run.
No current heads, installed schema, whole-plan trace admission, SQL execution
cost, writer effects or successful-verifier token is supplied by this fixture.
All controls are authored source-only and unrun.
"""
from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError, fields, replace
import hashlib
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_index_contract as contract
from serverware import authority_index_mutation as sparse
from serverware import authority_index_mutation_reader as reader
from serverware import authority_index_projection as projection
from serverware import authority_indexed_mutation as indexed
from serverware import authority_radix_mutation as primary
import test_authority_indexed_mutation as oracle


LEAF_TABLE = "policy_authority_counted_index_leaves"
NODE_TABLE = "policy_authority_counted_index_nodes"
LEAF_FIELDS = ("index_id", "projection_digest", "index_key", "primary_id",
               "primary_key_digest", "primary_row_digest", "index_revision")
NODE_FIELDS = ("index_id", "projection_digest", "depth", "path_prefix",
               "node_digest", "subtree_count", "index_revision")
NIBBLES = "0123456789abcdef"


def frames(*values):
    return sum(8 + len(str(value).encode("utf-8")) for value in values)


def values(value):
    return {field.name: getattr(value, field.name) for field in fields(value)}


def forged(value, **changes):
    result = object.__new__(type(value))
    for field in fields(value):
        object.__setattr__(result, field.name, changes.get(field.name, getattr(value, field.name)))
    return result


def default_fixture():
    before = oracle.credential()
    return oracle.MutationFixture({"webauthn_credentials": [before,
        oracle.credential("opaque", credential_id="other-public", user_id="other")]},
        (("webauthn_credentials", before["id"], "UPDATE", {**before, "sign_count": 4}),))


def all_profiles_fixture():
    credential = oracle.credential("credential")
    challenge = {"id": "challenge", "challenge_type": "registration", "used_at": None,
        "expires_at": "1970-01-01T00:00:00.000001+00:00", "user_id": "old-user"}
    session = {"id": "session", "bound_webauthn_credential_id": "credential", "status": "active"}
    grant = {"id": "grant", "approver_webauthn_credential_id": "credential", "state": "active"}
    approval = {"id": "approval", "approver_webauthn_credential_id": "credential", "status": "approved"}
    publication = {"id": "publication", "scope": "global", "status": "pending",
        "bundle_digest": "old-bundle", "rollback_epoch": -1, "sequence": 7}
    tables = {"webauthn_credentials": [credential, oracle.credential("opaque", user_id="other")],
        "webauthn_challenges": [challenge], "oidc_browser_sessions": [session],
        "approval_grants": [grant], "control_plane_approvals": [approval],
        "webauthn_trust_publications": [publication]}
    # One target per member profile: all eleven genuine full-row commitments
    # change without conflating this positive with maximum partition movement.
    actions = tuple((table, rows[0]["id"], "UPDATE", {**rows[0], "fixture_note": "changed"})
                    for table, rows in tables.items())
    return oracle.MutationFixture(tables, actions,
        expiry_before={"challenge": 1}, expiry_after={"challenge": 1})


def raw_arguments(fixture):
    arguments = fixture.arguments()
    items = arguments.pop("index_inputs")
    arguments["index_before_heads"] = tuple(indexed.IndexedMutationHead(item.index_id,
        item.index_revision, item.index_root) for item in items)
    return arguments


class StoredRows:
    """Reusable exact seven-column stores from independent whole populations."""
    def __init__(self, fixture):
        self.leaves, self.nodes = {}, {}
        for name, info in sorted(fixture.indexes.items()):
            profile = info["profile"]
            for row in fixture.tables[profile.table]:
                leaf = oracle.image_leaf(profile, row, fixture.expiry_before.get(row["id"]))
                if leaf is not None:
                    self.leaves[name, leaf.key] = dict(zip(LEAF_FIELDS, (name, profile.projection_digest,
                        leaf.key, row["id"], leaf.primary_key_digest, leaf.primary_row_digest, 29)))
            for prefix, (digest, count) in info["before"].nodes.items():
                if prefix and count:
                    self.nodes[name, len(prefix), prefix] = dict(zip(NODE_FIELDS,
                        (name, profile.projection_digest, len(prefix), prefix, digest, count, 29)))


def plans(fixture):
    """Independent finite trie cover and actual 256-identity SQL parameters."""
    result = []
    for name, info in sorted(fixture.indexes.items()):
        targets = tuple(sorted(info["targets"]))
        opened = {""} | {key[:depth] for key in targets for depth in range(160)}
        siblings = tuple(sorted({prefix + digit for prefix in opened for digit in NIBBLES}
            - opened - set(targets)))
        batches = []
        for kind, identities in (("leaf", targets), ("node", siblings)):
            for offset in range(0, len(identities), 256):
                batch = identities[offset:offset + 256]
                parameters = (tuple(value for prefix in batch for value in (len(prefix), prefix))
                              if kind == "node" else batch)
                batches.append((kind, batch, (*parameters, name, len(batch) + 1)))
        result.append((name, info, targets, opened, siblings, tuple(batches)))
    return tuple(result)


class Trace:
    def __init__(self):
        self.calls = []

    def read(self, table, key):
        self.calls.append((table, copy.deepcopy(key)))


class Cursor:
    """Bounded in-memory responder, not an SQL interpreter or native database."""
    def __init__(self, store, alter=None):
        self.store, self.alter = store, alter
        self.calls, self.fetches = [], []

    def execute(self, sql, parameters):
        if not sql.startswith("SELECT ") or not isinstance(parameters, tuple):
            raise AssertionError("reader did not issue its fixed parameterized SELECT")
        if 'FROM "serverware_metadata"."' + LEAF_TABLE + '" AS leaf' in sql:
            kind, identities = "leaf", parameters[:-2]
            rows = [self.store.leaves[parameters[-2], key] for key in identities
                    if (parameters[-2], key) in self.store.leaves]
            if sql.count("(%s::pg_catalog.text)") != len(identities):
                raise AssertionError("leaf VALUES does not match exact target identities")
        elif 'FROM "serverware_metadata"."' + NODE_TABLE + '" AS node' in sql:
            kind = "node"
            identities = tuple(zip(parameters[:-2:2], parameters[1:-2:2]))
            rows = [self.store.nodes[parameters[-2], depth, prefix] for depth, prefix in identities
                    if (parameters[-2], depth, prefix) in self.store.nodes]
            if sql.count("(%s::pg_catalog.int4,%s::pg_catalog.text)") != len(identities):
                raise AssertionError("node VALUES does not match exact sibling identities")
        else:
            raise AssertionError("reader accessed an unexpected table or namespace")
        if (not 1 <= len(identities) <= 256 or parameters[-1] != len(identities) + 1
                or not sql.endswith("LIMIT %s") or 'COLLATE "C"' not in sql):
            raise AssertionError("reader changed its bounded C-collated point lookup")
        rows = copy.deepcopy(list(reversed(rows)))  # Database order is not proof order.
        self.calls.append((kind, sql, parameters))
        self.pending = rows if self.alter is None else self.alter(kind, parameters[-2], identities, rows)
        return self

    def fetchmany(self, maximum):
        if maximum != self.calls[-1][2][-1]:
            raise AssertionError("row fetch lost the exact overflow sentinel")
        self.fetches.append(maximum)
        return self.pending


def expected_metrics(fixture, store):
    arguments = fixture.arguments()
    primary_metrics = oracle.primary_metrics(arguments)
    index_metrics = {name: oracle.index_metrics(info) for name, info in fixture.indexes.items()}
    projected = sum(2 * len(oracle.PROFILE_TABLES.get(item["table"], ()))
        * (int(item["expectedRow"] is not None) + int(item["row"] is not None)) for item in fixture.mutations)
    new_rows = sum(item["row"] is not None and item["table"] in oracle.PROFILE_TABLES for item in fixture.mutations)
    hashes = primary_metrics["hash_work"] + len(fixture.indexes) + projected + new_rows
    hashes += sum(value["before_hashes"] + value["after_hashes"] for value in index_metrics.values())
    pure_bytes = primary_metrics["input_bytes"] + oracle.context_bytes(arguments["index_inputs"])
    pure_bytes += sum(value["input_bytes"] for value in index_metrics.values())
    heads = frames("serverware.policyAuthorityCountedMutationReadHeads/v1", len(fixture.indexes))
    heads += sum(frames(name, 29, info["before"].root.digest, info["before"].root.count)
                 for name, info in fixture.indexes.items())
    parameters = returned_bytes = returned = leaf_reads = node_reads = targets_count = siblings_count = 0
    for name, _, targets, _, siblings, batches in plans(fixture):
        targets_count += len(targets)
        siblings_count += len(siblings)
        for kind, batch, bound in batches:
            parameters += frames(*bound)
            leaf_reads += int(kind == "leaf")
            node_reads += int(kind == "node")
            records = ([store.leaves[name, key] for key in batch if (name, key) in store.leaves]
                if kind == "leaf" else [store.nodes[name, len(prefix), prefix] for prefix in batch
                    if (name, len(prefix), prefix) in store.nodes])
            returned += len(records)
            keys = LEAF_FIELDS if kind == "leaf" else NODE_FIELDS
            returned_bytes += sum(frames(kind, *(row[key] for key in keys)) for row in records)
    return {"primary": primary_metrics, "indexes": index_metrics, "projected": projected, "new_rows": new_rows,
        "hashes": hashes, "pure_bytes": pure_bytes, "head_bytes": heads,
        "parameter_bytes": parameters, "transport_bytes": returned_bytes, "returned_rows": returned,
        "leaf_reads": leaf_reads, "node_reads": node_reads, "sql_reads": leaf_reads + node_reads,
        "requested_targets": targets_count, "requested_siblings": siblings_count,
        "input_bytes": pure_bytes + heads + parameters + returned_bytes}


def frontier_bytes(frontier):
    return sum(frames("leaf", item.key, item.primary_key_digest, item.primary_row_digest)
        if type(item) is contract.IndexLeaf else frames("opaque", item.prefix, item.digest, item.count)
        for item in frontier)


def preflight_peak(fixture, store):
    """Independent worst-positive-sibling reservation, not a spent-work metric."""
    actual = expected_metrics(fixture, store)
    proof_bytes = frames("serverware.policyAuthorityIndexedMutationInput/v1", len(fixture.indexes))
    fold_hashes, components = 0, {}
    for name, info, targets, opened, siblings, _ in plans(fixture):
        old = [pair[0] for pair in info["targets"].values() if pair[0] is not None]
        maximum_frontier = len(old) + len(siblings)
        profile, root = info["profile"], info["before"].root
        amount = frames("serverware.policyAuthorityIndexMutationInput/v1", contract.PROFILE,
            name, profile.table, profile.projection_digest, 160, root.digest, root.count,
            len(targets), maximum_frontier)
        for key, pair in sorted(info["targets"].items()):
            amount += frames("change", key)
            for label, leaf in zip(("before", "after"), pair):
                amount += (frames(label + "-absent") if leaf is None else
                    frames(label + "-leaf", leaf.key, leaf.primary_key_digest, leaf.primary_row_digest))
        amount += frontier_bytes(old)
        amount += sum(frames("opaque", prefix, "sha256:" + "0" * 64, (1 << 63) - 1)
                      for prefix in siblings)
        proof_bytes += amount + frames(name, 29, root.digest, root.count, maximum_frontier)
        hashes = 2 * (16 * len(opened) + len(targets))
        fold_hashes += hashes
        components[name] = (amount, hashes, maximum_frontier, len(opened))
    actual_folds = sum(item["before_hashes"] + item["after_hashes"] for item in actual["indexes"].values())
    return {"hashes": actual["hashes"] - actual_folds + fold_hashes,
        "input_bytes": actual["primary"]["input_bytes"] + actual["head_bytes"]
            + actual["parameter_bytes"] + actual["transport_bytes"] + proof_bytes,
        "proof_bytes": proof_bytes, "components": components}


class IndexMutationReaderTests(unittest.TestCase):
    def acquire(self, fixture=None, *, store=None, alter=None, budget=None, trace=None, **changes):
        fixture = default_fixture() if fixture is None else fixture
        cursor = Cursor(StoredRows(fixture) if store is None else store, alter)
        trace = Trace() if trace is None else trace
        arguments = raw_arguments(fixture)
        arguments.update(changes)
        if budget is None:
            result = reader.acquire_indexed_primary_batch(cursor, trace=trace, **arguments)
        else:
            result = reader._acquire_indexed_primary_batch(cursor, trace=trace,
                acquisition_budget=budget, **arguments)
        return result, cursor, trace

    def assert_exact(self, fixture, actual, store=None):
        store = StoredRows(fixture) if store is None else store
        expected = expected_metrics(fixture, store)
        result = actual.result
        self.assertEqual(result.primary.business_after_roots,
            tuple(fixture.after_trees[table].root for table in sorted(fixture.after_trees)))
        self.assertEqual(actual.index_inputs, fixture.arguments()["index_inputs"])
        self.assertEqual(result.before_heads, raw_arguments(fixture)["index_before_heads"])
        self.assertEqual(result.after_heads, tuple(indexed.IndexedMutationHead(name,
            info["revision_before"] + info["revision_delta"], info["after"].root)
            for name, info in sorted(fixture.indexes.items())))
        self.assertEqual(values(result.primary.metrics), expected["primary"])
        self.assertEqual({name: values(metric) for name, metric in result.metrics.indexes}, expected["indexes"])
        self.assertEqual((result.metrics.context_hashes, result.metrics.projection_hash_allowance,
            result.metrics.new_row_hashes), (len(fixture.indexes), expected["projected"], expected["new_rows"]))
        self.assertEqual((result.metrics.hashes, result.metrics.input_bytes), (expected["hashes"], expected["input_bytes"]))
        for field in ("sql_reads", "leaf_reads", "node_reads", "requested_targets", "requested_siblings",
                      "returned_rows", "parameter_bytes", "transport_bytes", "head_bytes", "input_bytes"):
            self.assertEqual(getattr(actual.metrics, field), expected[field], field)
        self.assertEqual((actual.metrics.hash_work, actual.metrics.acquisition_hashes), (expected["hashes"], 0))
        return expected

    def deny_before_sql(self, fixture, *, budget=None, **changes):
        cursor = Cursor(StoredRows(fixture))
        arguments = raw_arguments(fixture)
        arguments.update(changes)
        with self.assertRaises(reader.IndexMutationReadError):
            reader._acquire_indexed_primary_batch(cursor, trace=Trace(), **arguments,
                acquisition_budget=reader._AcquisitionBudget() if budget is None else budget)
        self.assertEqual(cursor.calls, [])

    def test_all_eleven_profiles_reconstruct_independent_full_before_after_populations(self):
        fixture = all_profiles_fixture()
        actual, cursor, trace = self.acquire(fixture)
        self.assert_exact(fixture, actual)
        self.assertEqual(len(actual.result.after_heads), 11)
        self.assertEqual(len(cursor.calls), len(trace.calls))
        self.assertEqual(len(cursor.calls), len(cursor.fetches))

    def test_insert_absence_delete_equal_update_and_partition_moves_use_real_folds(self):
        before = oracle.credential()
        for tables, action in (({"webauthn_credentials": []}, ("INSERT", before)),
                              ({"webauthn_credentials": [before]}, ("DELETE", None)),
                              ({"webauthn_credentials": [before]}, ("UPDATE", before)),
                              ({"webauthn_credentials": [before]}, ("UPDATE", {**before,
                                  "credential_id": "moved", "user_id": "other", "revoked_at": "revoked"}))):
            fixture = oracle.MutationFixture(tables, (("webauthn_credentials", before["id"], *action),))
            with self.subTest(operation=action[0], after=action[1]):
                actual, _, _ = self.acquire(fixture)
                self.assert_exact(fixture, actual)
                self.assertTrue(all(head.index_revision == 30 for head in actual.result.after_heads))

    def test_zero_target_nonmember_profiles_read_sixteen_siblings_and_do_not_skip_verification(self):
        before = {"id": "excluded", "challenge_type": "authentication", "used_at": None,
            "expires_at": "1970-01-01T00:00:00+00:00", "user_id": "user"}
        member = {**before, "id": "member", "challenge_type": "registration"}
        fixture = oracle.MutationFixture({"webauthn_challenges": [before, member]},
            (("webauthn_challenges", "excluded", "UPDATE", {**before, "used_at": "changed"}),),
            expiry_before={"excluded": 0, "member": 0})
        actual, cursor, _ = self.acquire(fixture)
        self.assert_exact(fixture, actual)
        self.assertEqual(actual.result.before_heads, actual.result.after_heads)
        self.assertEqual((actual.metrics.leaf_reads, actual.metrics.node_reads,
                          actual.metrics.requested_targets, actual.metrics.requested_siblings), (0, 2, 0, 32))
        self.assertTrue(all(len(call[2]) == 34 and call[2][-1] == 17 for call in cursor.calls))
        for _, metrics in actual.result.metrics.indexes:
            self.assertEqual((metrics.changes, metrics.opened_nodes, metrics.child_slots), (0, 1, 32))
            self.assertGreater(metrics.before_hashes, 0)

    def test_exact_batched_parameters_trace_profiles_and_record_transport_are_independent(self):
        fixture = default_fixture()
        actual, cursor, trace = self.acquire(fixture)
        self.assert_exact(fixture, actual)
        expected = [(kind, bound) for _, _, _, _, _, batches in plans(fixture)
                    for kind, _, bound in batches]
        self.assertEqual([(kind, parameters) for kind, _, parameters in cursor.calls], expected)
        for (kind, _, bound), (table, key) in zip(cursor.calls, trace.calls):
            self.assertEqual(table, LEAF_TABLE if kind == "leaf" else NODE_TABLE)
            self.assertEqual(key["profile"], "serverware.policyAuthorityCountedIndexMutationRead/v1")
            self.assertEqual((key["indexId"], key["indexRevision"], key["limit"]), (bound[-2], 29, bound[-1]))
            self.assertEqual(set(key), {"profile", "indexId", "projectionDigest", "indexRevision",
                "rootDigest", "rootCount", "limit", "targets" if kind == "leaf" else "prefixes"})

    def test_one_real_primary_once_per_image_projection_and_one_sparse_call_per_profile(self):
        fixture = default_fixture()
        real_primary, real_projection, real_sparse = primary.evaluate_primary_radix_inputs, projection.project_row, sparse.evaluate_index_mutations
        observed = {"primary": [], "projection": [], "sparse": []}

        def primary_call(**kwargs):
            result = real_primary(**kwargs)
            observed["primary"].append((kwargs, result))
            return result

        def project(*args, **kwargs):
            observed["projection"].append((args, kwargs))
            return real_projection(*args, **kwargs)

        def fold(**kwargs):
            result = real_sparse(**kwargs)
            observed["sparse"].append((kwargs, result))
            return result

        with patch.object(primary, "evaluate_primary_radix_inputs", primary_call), \
                patch.object(projection, "project_row", project), patch.object(sparse, "evaluate_index_mutations", fold):
            actual, _, _ = self.acquire(fixture)
        self.assert_exact(fixture, actual)
        self.assertEqual(tuple(map(len, observed.values())), (1, 6, 3))
        self.assertIs(actual.result.primary, observed["primary"][0][1].result)
        self.assertEqual([item[0][0] for item in observed["projection"]],
            [name for name in sorted(fixture.indexes) for _ in range(2)])
        self.assertEqual([item[0]["profile"].index_id for item in observed["sparse"]], sorted(fixture.indexes))

    def test_pure_public_indexed_metrics_are_preserved_except_separately_charged_acquisition_bytes(self):
        fixture = default_fixture()
        expected = expected_metrics(fixture, StoredRows(fixture))
        pure = indexed.evaluate_indexed_primary_batch(**fixture.arguments())
        acquired, _, _ = self.acquire(fixture)
        self.assertEqual(acquired.result.primary, pure.primary)
        self.assertEqual(acquired.result.before_heads, pure.before_heads)
        self.assertEqual(acquired.result.after_heads, pure.after_heads)
        self.assertEqual(pure.metrics.input_bytes, expected["pure_bytes"])
        self.assertEqual(pure.metrics.hashes, expected["hashes"])
        self.assertEqual(replace(acquired.result.metrics, input_bytes=pure.metrics.input_bytes), pure.metrics)
        self.assertEqual(acquired.metrics.input_bytes - pure.metrics.input_bytes,
            expected["head_bytes"] + expected["parameter_bytes"] + expected["transport_bytes"])

    def test_heads_are_exact_sorted_complete_source_inventory_before_any_sql(self):
        fixture = default_fixture()
        heads = raw_arguments(fixture)["index_before_heads"]
        extra_profile = oracle.join_oracle.expected_profile("webauthn_registration_unused_global")
        extra_root = oracle.counted_oracle.IndependentIndex([], extra_profile).root
        extra = indexed.IndexedMutationHead(extra_profile.index_id, 0, extra_root)
        cases = (heads[:-1], heads + (heads[-1],), tuple(reversed(heads)), list(heads),
            tuple(sorted((*heads, extra), key=lambda item: item.index_id)),
            (forged(heads[0], index_id="unknown"), *heads[1:]),
            (forged(heads[0], index_revision=True), *heads[1:]),
            (forged(heads[0], index_revision=0), *heads[1:]),
            (object.__new__(indexed.IndexedMutationHead), *heads[1:]),
            (fixture.arguments()["index_inputs"][0], *heads[1:]))
        for position, value in enumerate(cases):
            with self.subTest(case=position):
                self.deny_before_sql(fixture, index_before_heads=value)
        empty = oracle.MutationFixture({"webauthn_credentials": []},
            (("webauthn_credentials", "credential", "INSERT", oracle.credential()),))
        genesis = tuple(replace(head, index_revision=0) for head in raw_arguments(empty)["index_before_heads"])
        actual, _, _ = self.acquire(empty, index_before_heads=genesis)
        self.assertTrue(all(head.index_revision == 1 for head in actual.result.after_heads))

    def test_missing_duplicate_unexpected_or_forged_old_leaf_records_are_denied(self):
        before = oracle.credential()
        fixture = oracle.MutationFixture({"webauthn_credentials": [before]},
            (("webauthn_credentials", before["id"], "UPDATE", {**before, "credential_id": "moved"}),))
        # The first profile has two targets but just one OLD leaf, so a
        # duplicate fits the row sentinel and reaches duplicate identity checks.
        self.assertEqual(len(plans(fixture)[0][2]), 2)
        mutations = (lambda row: [], lambda row: [row, copy.deepcopy(row)],
            lambda row: [{**row, "index_key": "f" * 160}],
            lambda row: [{**row, "primary_id": "different"}],
            lambda row: [{**row, "primary_row_digest": "sha256:" + "0" * 64}],
            lambda row: [{**row, "primary_key_digest": "sha256:" + "0" * 64}],
            lambda row: [{**row, "projection_digest": "sha256:" + "0" * 64}],
            lambda row: [{**row, "index_revision": 30}],
            lambda row: [{**row, "index_revision": 0}],
            lambda row: [{**row, "primary_id": None}])
        for position, change in enumerate(mutations):
            fired = []

            def alter(kind, name, identities, rows):
                if kind == "leaf" and rows and not fired:
                    fired.append(True)
                    return change(rows[0])
                return rows

            with self.subTest(case=position), self.assertRaises(reader.IndexMutationReadError):
                self.acquire(fixture, alter=alter)
            self.assertEqual(fired, [True])

    def test_missing_or_corrupt_positive_siblings_reach_genuine_before_fold(self):
        fixture = default_fixture()
        for change in (lambda row: [],
                       lambda row: [{**row, "node_digest": "sha256:" + "0" * 64}]):
            fired = []

            def alter(kind, name, identities, rows):
                if kind == "node" and rows and not fired:
                    fired.append(True)
                    return change(rows[0]) + rows[1:]
                return rows

            with patch.object(sparse, "evaluate_index_mutations", wraps=sparse.evaluate_index_mutations) as folds:
                with self.assertRaises(reader.IndexMutationReadError):
                    self.acquire(fixture, alter=alter)
                self.assertEqual(folds.call_count, 1)
            self.assertEqual(fired, [True])
        for changes in ({"depth": True}, {"path_prefix": "f" * 160}, {"subtree_count": 0},
                        {"index_revision": 30}, {"projection_digest": "sha256:" + "0" * 64}):
            fired = []

            def malformed(kind, name, identities, rows):
                if kind == "node" and rows and not fired:
                    fired.append(True)
                    return [{**rows[0], **changes}, *rows[1:]]
                return rows

            with self.subTest(changes=changes), self.assertRaises(reader.IndexMutationReadError):
                self.acquire(fixture, alter=malformed)
            self.assertEqual(fired, [True])

    def test_new_target_must_be_absent_and_rows_are_closed_with_exact_driver_sentinels(self):
        fixture = oracle.MutationFixture({"webauthn_credentials": []},
            (("webauthn_credentials", "credential", "INSERT", oracle.credential()),))
        store = StoredRows(fixture)
        name, info = next(iter(sorted(fixture.indexes.items())))
        key, (_, new) = next(iter(info["targets"].items()))
        store.leaves[name, key] = dict(zip(LEAF_FIELDS, (name, info["profile"].projection_digest,
            key, "credential", new.primary_key_digest, new.primary_row_digest, 29)))
        with self.assertRaises(reader.IndexMutationReadError):
            self.acquire(fixture, store=store)
        ordinary = default_fixture()
        transforms = (lambda row: (row,), lambda row: [row, copy.deepcopy(row)],
            lambda row: [{**row, "unexpected": 1}],
            lambda row: [{name: value for name, value in row.items() if name != "primary_id"}],
            lambda row: [list(row.values())])
        for position, transform in enumerate(transforms):
            def alter(kind, name, identities, rows):
                return transform(rows[0]) if kind == "leaf" and rows else rows
            with self.subTest(case=position), self.assertRaises(reader.IndexMutationReadError):
                self.acquire(ordinary, alter=alter)
        fired = []

        def duplicate_node(kind, name, identities, rows):
            if kind == "node" and rows and not fired:
                fired.append(True)
                return [rows[0], copy.deepcopy(rows[0]), *rows[1:]]
            return rows

        with self.assertRaises(reader.IndexMutationReadError):
            self.acquire(ordinary, alter=duplicate_node)
        self.assertEqual(fired, [True])

    def test_real_primary_corruption_and_last_profile_overflow_deny_before_sql(self):
        fixture = default_fixture()
        bad = raw_arguments(fixture)["selected_rows"]
        bad[0]["row"]["sign_count"] += 1
        self.deny_before_sql(fixture, selected_rows=bad)
        heads = raw_arguments(fixture)["index_before_heads"]
        self.deny_before_sql(fixture, index_before_heads=(*heads[:-1],
            replace(heads[-1], index_revision=(1 << 63) - 1)))
        # A shape-valid but false population is rejected against actual primary
        # counts before SQL, not treated as a current authenticated head.
        self.deny_before_sql(fixture, index_before_heads=(*heads[:-1],
            replace(heads[-1], index_root=contract.CountedNode(heads[-1].index_root.digest, 3))))
        full = all_profiles_fixture()
        bad_mutations = raw_arguments(full)["mutations"]
        next(item for item in bad_mutations if item["table"] == "webauthn_trust_publications")["row"]["sequence"] = True
        self.deny_before_sql(full, mutations=bad_mutations)

    def test_all_profile_sql_and_parameter_preflight_has_no_partial_cursor_calls(self):
        fixture = default_fixture()
        expected = expected_metrics(fixture, StoredRows(fixture))
        self.assertEqual((reader.MAX_IDENTITIES, reader.MAX_SQL_READS, reader.MAX_PARAMETER_BYTES,
                          reader.MAX_TRANSPORT_BYTES), (256, 4096, 4 * 1024 * 1024, 4 * 1024 * 1024))
        for limit in (reader._AcquisitionLimits(max_sql_reads=expected["sql_reads"] - 1),
                      reader._AcquisitionLimits(max_parameter_bytes=expected["parameter_bytes"] - 1)):
            budget = reader._AcquisitionBudget(limit)
            self.deny_before_sql(fixture, budget=budget)
            self.assertTrue(budget.failed)
        tight = reader._AcquisitionLimits(max_sql_reads=expected["sql_reads"],
            max_parameter_bytes=expected["parameter_bytes"], max_transport_bytes=expected["transport_bytes"])
        actual, _, _ = self.acquire(fixture, budget=reader._AcquisitionBudget(tight))
        self.assert_exact(fixture, actual)
        peak = preflight_peak(fixture, StoredRows(fixture))
        limits = raw_arguments(fixture)["limits"]
        for field, amount in (("max_frontier_entries", max(item[2] for item in peak["components"].values()) - 1),
                              ("max_opened_nodes", 159),
                              ("max_hashes", max(item[1] for item in peak["components"].values()) - 1),
                              ("max_input_bytes", max(item[0] for item in peak["components"].values()) - 1)):
            with self.subTest(field=field):
                self.deny_before_sql(fixture, limits=replace(limits, index=replace(limits.index, **{field: amount})))

    def test_independent_conservative_peak_accepts_and_one_less_rejects_without_refunds(self):
        fixture, store = default_fixture(), None
        store = StoredRows(fixture)
        actual_work, peak = expected_metrics(fixture, store), preflight_peak(fixture, store)
        source = raw_arguments(fixture)["limits"]
        limits = replace(source, max_total_hashes=peak["hashes"], max_total_input_bytes=peak["input_bytes"])
        actual, _, _ = self.acquire(fixture, limits=limits)
        self.assert_exact(fixture, actual, store)
        self.assertGreater(peak["hashes"], actual_work["hashes"])
        self.assertGreater(peak["input_bytes"], actual_work["input_bytes"])
        self.deny_before_sql(fixture, limits=replace(limits, max_total_hashes=peak["hashes"] - 1))
        budget = reader._AcquisitionBudget()
        cursor = Cursor(store)
        with patch.object(sparse, "evaluate_index_mutations", wraps=sparse.evaluate_index_mutations) as folds:
            with self.assertRaises(reader.IndexMutationReadError):
                reader._acquire_indexed_primary_batch(cursor, trace=Trace(), acquisition_budget=budget,
                    **{**raw_arguments(fixture), "limits": replace(limits,
                        max_total_input_bytes=peak["input_bytes"] - 1)})
            self.assertEqual(folds.call_count, 0)
        self.assertTrue(budget.failed)
        self.assertGreater(len(cursor.calls), 0)
        # These limits derive from the fixed possible-positive-sibling model.
        # Exact observed totals are not asserted to be an acceptance quota.

    def test_private_reuse_retains_actual_spending_and_every_invocation_delta(self):
        fixture = default_fixture()
        expected, peak = expected_metrics(fixture, StoredRows(fixture)), preflight_peak(fixture, StoredRows(fixture))
        source = raw_arguments(fixture)["limits"]
        limits = replace(source, max_total_hashes=expected["hashes"] + peak["hashes"],
                         max_total_input_bytes=expected["input_bytes"] + peak["input_bytes"])
        budget = reader._AcquisitionBudget(reader._AcquisitionLimits(
            max_sql_reads=2 * expected["sql_reads"], max_parameter_bytes=2 * expected["parameter_bytes"],
            max_transport_bytes=2 * expected["transport_bytes"]))
        for iteration in (1, 2):
            actual, _, _ = self.acquire(fixture, budget=budget, limits=limits)
            self.assert_exact(fixture, actual)
            self.assertEqual((actual.metrics.cumulative_sql_reads, actual.metrics.cumulative_parameter_bytes,
                actual.metrics.cumulative_transport_bytes, actual.metrics.cumulative_hash_work,
                actual.metrics.cumulative_input_bytes), tuple(iteration * expected[key] for key in
                    ("sql_reads", "parameter_bytes", "transport_bytes", "hashes", "input_bytes")))
            self.assertFalse(budget.active)
        self.deny_before_sql(fixture, budget=budget, limits=limits)
        self.assertTrue(budget.failed)
        with patch.object(primary, "evaluate_primary_radix_inputs", wraps=primary.evaluate_primary_radix_inputs) as evaluate:
            self.deny_before_sql(fixture, budget=budget, limits=limits)
            self.assertEqual(evaluate.call_count, 0)
        # Explicit synthetic prior charges are also retained; begin is not a
        # reset primitive. The two calls above cover genuine cumulative reuse.
        prior = reader._AcquisitionBudget()
        engine = prior.begin(source)
        engine.hash_work(7)
        engine.input_work(101)
        prior.active = False
        actual, _, _ = self.acquire(fixture, budget=prior)
        self.assert_exact(fixture, actual)
        self.assertEqual((actual.metrics.cumulative_hash_work, actual.metrics.cumulative_input_bytes),
            (7 + expected["hashes"], 101 + expected["input_bytes"]))

    def test_failed_driver_trace_and_caught_reentrancy_poison_the_original_budget(self):
        fixture = default_fixture()

        class DriverFailure(RuntimeError):
            pass

        class RejectTrace:
            def read(self, table, key):
                raise DriverFailure("local trace sink denies this component read")

        for where in ("trace", "cursor"):
            cursor, budget = Cursor(StoredRows(fixture)), reader._AcquisitionBudget()
            if where == "cursor":
                def fail(*args):
                    raise DriverFailure("deterministic driver failure")
                cursor.execute = fail
            with self.subTest(where=where), self.assertRaises(DriverFailure):
                reader._acquire_indexed_primary_batch(cursor, trace=RejectTrace() if where == "trace" else Trace(),
                    acquisition_budget=budget, **raw_arguments(fixture))
            self.assertEqual(cursor.calls, [])
            self.assertTrue(budget.failed)
            self.deny_before_sql(fixture, budget=budget)
        budget, nested_cursor, entered = reader._AcquisitionBudget(), Cursor(StoredRows(fixture)), []

        def reenter(kind, name, identities, rows):
            if not entered:
                entered.append(True)
                with self.assertRaises(reader.IndexMutationReadError):
                    reader._acquire_indexed_primary_batch(nested_cursor, trace=Trace(),
                        acquisition_budget=budget, **raw_arguments(fixture))
            return rows  # Swallowing the nested error cannot revive the outer call.

        with self.assertRaises(reader.IndexMutationReadError):
            self.acquire(fixture, budget=budget, alter=reenter)
        self.assertEqual(entered, [True])
        self.assertEqual(nested_cursor.calls, [])
        self.assertTrue(budget.failed)
        self.assertFalse(budget.active)
        self.deny_before_sql(fixture, budget=budget)
        self.assert_exact(fixture, self.acquire(fixture, budget=reader._AcquisitionBudget())[0])
        # This is trace exception propagation, not PlannerTrace admission;
        # importing that registry-gated planner would itself violate this lane.

    def test_returned_transport_has_one_cumulative_bound_and_remains_spent_input(self):
        fixture = default_fixture()
        expected = expected_metrics(fixture, StoredRows(fixture))
        budget = reader._AcquisitionBudget(reader._AcquisitionLimits(
            max_transport_bytes=expected["transport_bytes"] - 1))
        with patch.object(sparse, "evaluate_index_mutations", wraps=sparse.evaluate_index_mutations) as fold:
            with self.assertRaises(reader.IndexMutationReadError):
                self.acquire(fixture, budget=budget)
            self.assertEqual(fold.call_count, 0)
        self.assertTrue(budget.failed)
        self.assertGreater(budget.transport_bytes, 0)
        self.assertLessEqual(budget.transport_bytes, expected["transport_bytes"] - 1)
        self.assertGreater(budget.engine.input_bytes, budget.parameter_bytes + budget.transport_bytes)
        self.assertGreater(budget.sql_reads, 0)
        # Earlier committed row revisions are acceptable relative to a supplied
        # later head. The independently recomputed roots still decide validity.
        store = StoredRows(fixture)
        for row in (*store.leaves.values(), *store.nodes.values()):
            row["index_revision"] = 1
        actual, _, _ = self.acquire(fixture, store=store)
        self.assert_exact(fixture, actual, store)

    def test_real_remaining_primary_and_sparse_clamps_credit_only_own_frontier(self):
        fixture = default_fixture()
        expected = expected_metrics(fixture, StoredRows(fixture))
        peak = preflight_peak(fixture, StoredRows(fixture))
        source = raw_arguments(fixture)["limits"]
        limits = replace(source, max_total_hashes=peak["hashes"], max_total_input_bytes=peak["input_bytes"])
        seen_primary, seen_folds = [], []
        real_primary, real_fold = primary.evaluate_primary_radix_inputs, sparse.evaluate_index_mutations

        def evaluate(**kwargs):
            seen_primary.append(kwargs["limits"])
            return real_primary(**kwargs)

        def fold(**kwargs):
            actual = real_fold(**kwargs)
            seen_folds.append((kwargs, actual))
            return actual

        with patch.object(primary, "evaluate_primary_radix_inputs", evaluate), \
                patch.object(sparse, "evaluate_index_mutations", fold), \
                patch.object(indexed, "evaluate_indexed_primary_batch", wraps=indexed.evaluate_indexed_primary_batch) as public:
            actual, _, _ = self.acquire(fixture, limits=limits)
        self.assertEqual(public.call_count, 0)
        self.assertEqual(seen_primary, [replace(limits.primary,
            max_hashes=min(limits.primary.max_hashes, limits.max_total_hashes),
            max_input_bytes=min(limits.primary.max_input_bytes, limits.max_total_input_bytes - expected["head_bytes"]))])
        owned_inputs = fixture.arguments()["index_inputs"]
        reservations = {item.index_id: frontier_bytes(item.frontier) for item in owned_inputs}
        hashes = expected["primary"]["hash_work"] + len(fixture.indexes) + expected["projected"] + expected["new_rows"]
        byte_work = expected["primary"]["input_bytes"] + expected["head_bytes"] + expected["parameter_bytes"]
        byte_work += expected["transport_bytes"] + oracle.context_bytes(owned_inputs) + sum(reservations.values())
        self.assertEqual(len(seen_folds), len(owned_inputs))
        for (kwargs, observed), item in zip(seen_folds, owned_inputs):
            self.assertEqual(kwargs["frontier"], item.frontier)
            self.assertEqual(kwargs["limits"], replace(limits.index,
                max_hashes=min(limits.index.max_hashes, limits.max_total_hashes - hashes),
                max_input_bytes=min(limits.index.max_input_bytes,
                    limits.max_total_input_bytes - byte_work + reservations[item.index_id])))
            hashes += observed.metrics.hashes
            byte_work += observed.metrics.input_bytes - reservations[item.index_id]
        self.assertEqual((hashes, byte_work), (expected["hashes"], expected["input_bytes"]))
        self.assert_exact(fixture, actual)

    def test_heads_are_captured_before_first_real_primary_hash_and_primary_owns_its_images(self):
        fixture = default_fixture()
        arguments, cursor = raw_arguments(fixture), Cursor(StoredRows(fixture))
        hashes, primary_calls = [], []
        real_hash, real_primary = hashlib.sha256, primary.evaluate_primary_radix_inputs

        def sha(*args, **kwargs):
            if not hashes:
                hashes.append(True)
                head = arguments["index_before_heads"][-1]
                object.__setattr__(head, "index_id", "caller-changed")
                object.__setattr__(head, "index_revision", 0)
                object.__setattr__(head, "index_root", contract.CountedNode("sha256:" + "0" * 64, 0))
            return real_hash(*args, **kwargs)

        def evaluate(**kwargs):
            observed = real_primary(**kwargs)
            primary_calls.append(observed)
            # Only after genuine primary ownership has completed. This does
            # not assert a new capture contract for the primary caller graph.
            arguments["mutations"][0]["row"]["sign_count"] = 999
            arguments["selected_rows"][0]["row"]["sign_count"] = 888
            arguments["before_proofs"][0]["rowDigest"] = "sha256:" + "0" * 64
            return observed

        with patch.object(hashlib, "sha256", sha), patch.object(primary, "evaluate_primary_radix_inputs", evaluate):
            actual = reader.acquire_indexed_primary_batch(cursor, trace=Trace(), **arguments)
        self.assertEqual(hashes, [True])
        self.assertEqual(len(primary_calls), 1)
        self.assertIs(actual.result.primary, primary_calls[0].result)
        self.assert_exact(fixture, actual)

    def test_limits_are_exact_source_bounded_and_shared_limits_cannot_be_replaced(self):
        for name, cap in (("max_sql_reads", 4096), ("max_parameter_bytes", 4 * 1024 * 1024),
                          ("max_transport_bytes", 4 * 1024 * 1024)):
            for bad in (True, 0, -1, 1.5, cap + 1):
                with self.subTest(field=name, value=bad), self.assertRaises(reader.IndexMutationReadError):
                    reader._AcquisitionLimits(**{name: bad})
        for malformed in (None, {}, object.__new__(reader._AcquisitionLimits),
                          forged(reader._AcquisitionLimits(), max_sql_reads=True)):
            with self.assertRaises(reader.IndexMutationReadError):
                reader._AcquisitionBudget(malformed)
        fixture = default_fixture()
        source = raw_arguments(fixture)["limits"]
        for malformed in (None, object.__new__(indexed.IndexedMutationLimits),
                          forged(source, max_total_hashes=True), forged(source, max_total_input_bytes=64 * 1024 * 1024 + 1)):
            self.deny_before_sql(fixture, limits=malformed)
        budget = reader._AcquisitionBudget()
        self.assert_exact(fixture, self.acquire(fixture, budget=budget)[0])
        with patch.object(primary, "evaluate_primary_radix_inputs", wraps=primary.evaluate_primary_radix_inputs) as evaluate:
            self.deny_before_sql(fixture, budget=budget, limits=replace(source,
                max_total_input_bytes=source.max_total_input_bytes - 1))
            self.assertEqual(evaluate.call_count, 0)
        self.assertTrue(budget.failed)

    def test_utf8_raw_ids_empty_profile_inventory_and_frozen_non_authority_observations(self):
        identifier = "雪" * 1365 + "a"  # Exactly 4096 UTF-8 bytes, not 4096 characters.
        before = oracle.credential(identifier)
        fixture = oracle.MutationFixture({"webauthn_credentials": [before]},
            (("webauthn_credentials", identifier, "UPDATE", {**before, "sign_count": 4}),))
        self.assertEqual(len(identifier.encode("utf-8")), 4096)
        actual, _, _ = self.acquire(fixture)
        self.assert_exact(fixture, actual)

        def oversized(kind, name, identities, rows):
            return [{**row, "primary_id": identifier + "x"} for row in rows] if kind == "leaf" else rows

        with self.assertRaises(reader.IndexMutationReadError):
            self.acquire(fixture, alter=oversized)
        empty = oracle.MutationFixture({"webauthn_credentials": [oracle.credential()]}, ())
        empty_result, cursor, trace = self.acquire(empty)
        self.assert_exact(empty, empty_result)
        self.assertEqual((empty_result.index_inputs, empty_result.result.before_heads,
                          empty_result.result.after_heads, cursor.calls, trace.calls), ((), (), (), [], []))
        with self.assertRaises(FrozenInstanceError):
            actual.metrics = empty_result.metrics
        with self.assertRaises(FrozenInstanceError):
            actual.result.after_heads[0].index_revision = 999
        # No public successful-result/target shortcut exists. Ordinary Python
        # signature closure and genuine raw primary admission still apply.
        with self.assertRaises(TypeError):
            reader.acquire_indexed_primary_batch(Cursor(StoredRows(fixture)), trace=Trace(),
                **raw_arguments(fixture), verified=actual.result.primary)
        self.deny_before_sql(fixture, mutations=actual.result)


if __name__ == "__main__":
    unittest.main()
