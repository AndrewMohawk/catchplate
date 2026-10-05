#!/usr/bin/env python3
"""Pure counted-range reconstruction against independent small-tree oracles.

The fixture implements its own length-framed hashes and sparse tree builder.
Literal ordered keys are structural inputs, not a SQL/selector codec. Tests do
not establish primary-row joins, index maintenance, trusted roots, currentness,
authorization, native PostgreSQL execution or enabled WebAuthn kernels.
"""
from __future__ import annotations

import copy
import hashlib
import sys
import unittest
from dataclasses import FrozenInstanceError, fields, replace
from itertools import combinations
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_index_contract as contract
from serverware import authority_index_range as ranges
from serverware import authority_query_read_work as measured


PROFILE = "serverware.policyAuthorityCountedIndex/v1"
EMPTY = "serverware.policyAuthorityCountedIndexEmpty/v1"
LEAF = "serverware.policyAuthorityCountedIndexLeaf/v1"
BRANCH = "serverware.policyAuthorityCountedIndexNode/v1"
INPUT = "serverware.policyAuthorityIndexRangeInput/v1"
WIDTH = 160
I64 = 2**63 - 1
NIBBLES = "0123456789abcdef"
TOP = 16**WIDTH


def digest(text):
    return "sha256:" + hashlib.sha256(text.encode("ascii")).hexdigest()


def key(prefix):
    return prefix.ljust(WIDTH, "0")


def leaf(path, identity=None):
    identity = path if identity is None else identity
    return contract.IndexLeaf(path, digest("primary-key:" + identity),
                              digest("primary-row:" + identity))


def framed(domain, *values):
    material = bytearray()
    for value in (domain, *values):
        encoded = value.encode("ascii")
        material.extend(len(encoded).to_bytes(8, "big"))
        material.extend(encoded)
    return "sha256:" + hashlib.sha256(material).hexdigest()


def common(profile):
    return PROFILE, profile.index_id, profile.table, profile.projection_digest, str(WIDTH)


def empty(profile, prefix):
    return framed(EMPTY, *common(profile), str(len(prefix)), prefix, "0"), 0


def member(profile, value):
    return framed(LEAF, *common(profile), str(WIDTH), value.key, "1",
                  value.primary_key_digest, value.primary_row_digest), 1


def parent(profile, prefix, children):
    count = sum(0 if child is None else child[1] for child in children)
    if count == 0:
        return empty(profile, prefix)
    encoded = [str(len(prefix)), prefix, str(count)]
    for ordinal, child in enumerate(children):
        node = empty(profile, prefix + NIBBLES[ordinal]) if child is None else child
        encoded.extend((node[0], str(node[1])))
    return framed(BRANCH, *common(profile), *encoded), count


def assembled(profile, terminals):
    """Rebuild each occupied ancestor once, independently of the verifier."""
    nodes = dict(terminals)
    ancestors = {""} | {path[:depth] for path in terminals for depth in range(len(path))}
    hash_work = 0
    for prefix in sorted(ancestors, key=lambda value: (-len(value), value)):
        children = [nodes.get(prefix + digit) for digit in NIBBLES]
        occupied = sum(child is not None for child in children)
        hash_work += 1 if occupied == 0 else 17 - occupied
        nodes[prefix] = parent(profile, prefix, children)
    return nodes, ancestors, hash_work


def span(prefix):
    scale = 16 ** (WIDTH - len(prefix))
    start = (int(prefix, 16) if prefix else 0) * scale
    return start, start + scale


def intersects(prefix, interval):
    low, high = span(prefix)
    start, end = int(interval.lower, 16), TOP if interval.upper is None else int(interval.upper, 16)
    return start != end and low < end and start < high


class IndependentIndex:
    def __init__(self, values, profile=None):
        self.profile = profile or contract.IndexProfile("component_index", "component_rows", digest("projection"))
        self.leaves = {value.key: value for value in values}
        if len(self.leaves) != len(values):
            raise AssertionError("independent fixture has duplicate keys")
        self.nodes, _, _ = assembled(self.profile,
            {path: member(self.profile, value) for path, value in self.leaves.items()})
        self.root = contract.CountedNode(*self.nodes[""])

    def opaque(self, prefix):
        return contract.OpaqueSubtree(prefix, *self.nodes[prefix])

    def matches(self, interval):
        return tuple(self.leaves[path] for path in sorted(self.leaves)
                     if interval.lower <= path and (interval.upper is None or path < interval.upper))

    def frontier(self, interval):
        result = []

        def walk(prefix):
            node = self.nodes.get(prefix)
            if node is None or node[1] == 0:
                return
            if prefix and not intersects(prefix, interval):
                result.append(self.opaque(prefix))
            elif len(prefix) == WIDTH:
                result.append(self.leaves[prefix])
            else:
                for digit in NIBBLES:
                    walk(prefix + digit)

        walk("")
        return tuple(result)


def metric_oracle(profile, root, interval, frontier):
    values = [INPUT, *common(profile), root.digest, str(root.count), interval.lower,
              "top" if interval.upper is None else interval.upper, str(len(frontier))]
    terminals, members = {}, 0
    for record in frontier:
        if type(record) is contract.IndexLeaf:
            values.extend(("leaf", record.key, record.primary_key_digest, record.primary_row_digest))
            terminals[record.key] = member(profile, record)
            members += 1
        else:
            values.extend(("opaque", record.prefix, record.digest, str(record.count)))
            terminals[record.prefix] = record.digest, record.count
    _, opened, hashes = assembled(profile, terminals)
    return {"entries": len(frontier), "leaves": members, "opened_nodes": len(opened),
            "child_slots": 16 * len(opened), "hashes": hashes + members,
            "input_bytes": sum(8 + len(value.encode("ascii")) for value in values)}


def shared_work_oracle(profile, root, interval, frontier):
    """Literal real hash-frame schedule, independent of production work hooks."""
    frames = []
    terminals = {}
    for record in frontier:
        if type(record) is contract.IndexLeaf:
            frames.append((LEAF, *common(profile), str(WIDTH), record.key, "1",
                           record.primary_key_digest, record.primary_row_digest))
            terminals[record.key] = member(profile, record)
        else:
            terminals[record.prefix] = record.digest, record.count
    nodes, opened, _ = assembled(profile, terminals)
    for prefix in sorted(opened, key=lambda value: (-len(value), value)):
        children = [nodes.get(prefix + digit) for digit in NIBBLES]
        count = sum(child[1] for child in children if child is not None)
        if not count:
            frames.append((EMPTY, *common(profile), str(len(prefix)), prefix, "0"))
            continue
        encoded = [str(len(prefix)), prefix, str(count)]
        for digit, child in zip(NIBBLES, children):
            if child is None:
                path = prefix + digit
                frames.append((EMPTY, *common(profile), str(len(path)), path, "0"))
                child = empty(profile, path)
            encoded.extend((child[0], str(child[1])))
        frames.append((BRANCH, *common(profile), *encoded))
    framing = metric_oracle(profile, root, interval, frontier)["input_bytes"]
    return (len(frames), framing + sum(2 * len(value.encode("ascii")) + 8
                                     for row in frames for value in row),
            2 * sum(len(row) for row in frames))


def projection(value):
    return {field.name: getattr(value, field.name) for field in fields(value)}


def bypassed(value, **changes):
    result = object.__new__(type(value))
    for field in fields(value):
        object.__setattr__(result, field.name, changes.get(field.name, getattr(value, field.name)))
    return result


class AuthorityIndexRangeTests(unittest.TestCase):
    def setUp(self):
        self.tree = IndependentIndex([leaf(path) for path in (
            key("0"), key("0f"), key("1"), key("1f"), key("2"), key("7f"), key("8"), "f" * WIDTH)])
        self.all = contract.KeyInterval(key("0"), None)

    def verify(self, *, tree=None, interval=None, frontier=None, root=None, profile=None, limits=None):
        tree = self.tree if tree is None else tree
        interval = self.all if interval is None else interval
        return ranges.reconstruct_complete_index_range(
            profile=tree.profile if profile is None else profile,
            expected_root=tree.root if root is None else root, interval=interval,
            frontier=tree.frontier(interval) if frontier is None else frontier,
            limits=ranges.IndexRangeLimits() if limits is None else limits)

    def assert_observation(self, tree, interval):
        frontier = tree.frontier(interval)
        result = self.verify(tree=tree, interval=interval, frontier=frontier)
        self.assertEqual(result.profile, tree.profile)
        self.assertEqual(result.interval, interval)
        self.assertEqual(result.leaves, tree.matches(interval))
        self.assertEqual(result.root, tree.root)
        self.assertEqual(projection(result.metrics), metric_oracle(tree.profile, tree.root, interval, frontier))
        return result

    def test_exact_profile_and_all_hash_variants_match_independent_length_framing(self):
        self.assertEqual((contract.PROFILE, contract.KEY_NIBBLES), (PROFILE, WIDTH))
        self.assertEqual((contract.EMPTY_DOMAIN, contract.LEAF_DOMAIN, contract.NODE_DOMAIN),
                         (EMPTY, LEAF, BRANCH))
        profile = self.tree.profile
        for prefix in ("", "0", "a" * 159, "f" * 160):
            self.assertEqual(contract.empty_node(profile, prefix), contract.CountedNode(*empty(profile, prefix)))
        for value in self.tree.leaves.values():
            self.assertEqual(contract.leaf_node(profile, value), contract.CountedNode(*member(profile, value)))
        children = tuple(None if digit not in self.tree.nodes else contract.CountedNode(*self.tree.nodes[digit])
                         for digit in NIBBLES)
        self.assertEqual(contract.branch_node(profile, "", children), self.tree.root)
        self.assertEqual(contract.branch_node(profile, "", (None,) * 16),
                         contract.CountedNode(*empty(profile, "")))
        for malformed in ((), (None,) * 15, (None,) * 17, [None] * 16,
                          (object(),) + (None,) * 15):
            with self.subTest(children=type(malformed)), self.assertRaises(contract.IndexRangeError):
                contract.branch_node(profile, "", malformed)
        # Domain-plus-NUL is the existing wire convention, not this new tree.
        frames = (*common(profile), "0", "", "0")
        wrong = EMPTY.encode("ascii") + b"\0" + b"".join(
            len(value.encode()).to_bytes(8, "big") + value.encode() for value in frames)
        self.assertNotEqual(empty(profile, "")[0], "sha256:" + hashlib.sha256(wrong).hexdigest())

    def test_full_population_reconstructs_root_count_and_exact_independent_metrics(self):
        result = self.assert_observation(self.tree, self.all)
        self.assertEqual((result.root.count, result.metrics.entries, result.metrics.leaves), (8, 8, 8))

    def test_half_open_boundaries_carries_maximum_key_and_top_sentinel(self):
        for interval in (contract.KeyInterval(key("0f"), key("2")),
                         contract.KeyInterval(key("1"), key("1f")),
                         contract.KeyInterval(key("7f"), key("8")),
                         contract.KeyInterval("f" * WIDTH, None),
                         contract.KeyInterval(key("0"), "f" * WIDTH)):
            with self.subTest(interval=interval):
                self.assert_observation(self.tree, interval)
        self.assertEqual([value.key for value in self.verify(interval=contract.KeyInterval(key("0f"), key("2"))).leaves],
                         [key("0f"), key("1"), key("1f")])

    def test_empty_tree_opens_root_and_authenticates_empty_digest_not_only_count(self):
        tree = IndependentIndex([])
        for interval in (self.all, contract.KeyInterval(key("8"), key("8"))):
            result = self.assert_observation(tree, interval)
            self.assertEqual((result.metrics.entries, result.metrics.leaves, result.metrics.opened_nodes,
                              result.metrics.child_slots, result.metrics.hashes), (0, 0, 1, 16, 1))
        with self.assertRaises(contract.IndexRangeError):
            self.verify(tree=tree, root=contract.CountedNode(digest("false-empty"), 0))

    def test_empty_interval_still_reconstructs_populated_root_using_only_outside_opaque_nodes(self):
        interval = contract.KeyInterval(key("1"), key("1"))
        frontier = self.tree.frontier(interval)
        self.assertTrue(frontier)
        self.assertTrue(all(type(value) is contract.OpaqueSubtree and value.prefix for value in frontier))
        self.assertEqual(self.assert_observation(self.tree, interval).leaves, ())
        with self.assertRaises(contract.IndexRangeError):
            self.verify(interval=interval, frontier=())

    def test_nonempty_zero_match_gap_requires_complete_authenticated_frontier(self):
        interval = contract.KeyInterval(key("11"), key("1e"))
        self.assertEqual(self.assert_observation(self.tree, interval).leaves, ())
        frontier = self.tree.frontier(interval)
        for index in range(len(frontier)):
            with self.subTest(omitted=index), self.assertRaises(contract.IndexRangeError):
                self.verify(interval=interval, frontier=frontier[:index] + frontier[index + 1:])

    def test_all_sixteen_branches_and_deep_last_nibble_divergence(self):
        for paths in ([digit + "0" * 159 for digit in NIBBLES],
                      ["a" * 159 + digit for digit in ("0", "1", "f")]):
            tree = IndependentIndex([leaf(path) for path in paths])
            with self.subTest(paths=paths):
                self.assert_observation(tree, self.all)
                self.assert_observation(tree, contract.KeyInterval(paths[1], paths[-1]))

    def test_genuine_opaque_interior_partial_overlap_and_boundary_leaf_are_rejected(self):
        root_children = tuple(self.tree.opaque(digit) for digit in NIBBLES if digit in self.tree.nodes)
        for interval in (contract.KeyInterval(key("1"), key("2")),
                         contract.KeyInterval(key("1f"), key("2"))):
            with self.subTest(interval=interval), self.assertRaisesRegex(contract.IndexRangeError, "intersects"):
                self.verify(interval=interval, frontier=root_children)
        interval = contract.KeyInterval(key("1"), key("1f"))
        frontier = tuple(self.tree.opaque(record.key) if type(record) is contract.IndexLeaf else record
                         for record in self.tree.frontier(interval))
        with self.assertRaisesRegex(contract.IndexRangeError, "intersects"):
            self.verify(interval=interval, frontier=frontier)

    def test_outside_opaque_subtrees_may_be_split_without_changing_complete_result(self):
        interval = contract.KeyInterval(key("2"), key("8"))
        before = self.tree.frontier(interval)
        expanded = []
        for record in before:
            if type(record) is contract.OpaqueSubtree and record.prefix == "1":
                expanded.extend(self.tree.opaque("1" + digit) for digit in NIBBLES if "1" + digit in self.tree.nodes)
            else:
                expanded.append(record)
        self.assertNotEqual(tuple(expanded), before)
        self.assertEqual(self.verify(interval=interval, frontier=tuple(expanded)).leaves, self.tree.matches(interval))

    def test_missing_first_middle_last_and_every_proper_population_subset_reject(self):
        tree = IndependentIndex([leaf(key(prefix)) for prefix in ("0", "1", "f")])
        frontier = tree.frontier(self.all)
        for retained in range(3):
            for subset in combinations(frontier, retained):
                with self.subTest(retained=tuple(item.key for item in subset)), self.assertRaises(contract.IndexRangeError):
                    self.verify(tree=tree, frontier=subset)

    def test_duplicate_out_of_order_and_ancestor_descendant_frontiers_reject(self):
        frontier = self.tree.frontier(self.all)
        for changed in ((frontier[0], *frontier), tuple(reversed(frontier)),
                        (frontier[1], frontier[0], *frontier[2:])):
            with self.subTest(frontier=changed), self.assertRaises(contract.IndexRangeError):
                self.verify(frontier=changed)
        interval = contract.KeyInterval(key("8"), key("8"))
        for changed in ((self.tree.opaque("1"), self.tree.opaque("10")),
                        (self.tree.opaque("1"), self.tree.opaque("1")),
                        (self.tree.opaque("10"), self.tree.opaque("1"))):
            with self.subTest(frontier=changed), self.assertRaisesRegex(contract.IndexRangeError, "prefix-free"):
                self.verify(interval=interval, frontier=changed)

    def test_explicit_empty_zero_count_and_opaque_root_are_not_alternate_spellings(self):
        interval = contract.KeyInterval(key("8"), key("8"))
        valid = self.tree.opaque("1")
        for changed in (bypassed(valid, count=0), bypassed(valid, prefix=""),
                        bypassed(valid, count=0, digest=empty(self.tree.profile, "1")[0])):
            with self.assertRaises(contract.IndexRangeError):
                self.verify(interval=interval, frontier=(changed,))
        with self.assertRaises(contract.IndexRangeError):
            contract.branch_node(self.tree.profile, "", (contract.CountedNode(*empty(self.tree.profile, "0")),) + (None,) * 15)

    def test_false_leaf_opaque_and_root_commitments_reject_without_a_selfdigest_shortcut(self):
        frontier = self.tree.frontier(self.all)
        for field, value in (("key", key("01")), ("primary_key_digest", digest("wrong-key")),
                             ("primary_row_digest", digest("wrong-row"))):
            changed = (replace(frontier[0], **{field: value}), *frontier[1:])
            with self.subTest(field=field), self.assertRaises(contract.IndexRangeError):
                self.verify(frontier=changed)
        interval = contract.KeyInterval(key("8"), key("8"))
        frontier = self.tree.frontier(interval)
        for changed in (replace(frontier[0], digest=digest("false-subtree")),
                        replace(frontier[0], count=frontier[0].count + 1)):
            with self.assertRaises(contract.IndexRangeError):
                self.verify(interval=interval, frontier=(changed, *frontier[1:]))
        for root in (replace(self.tree.root, count=7), replace(self.tree.root, count=9),
                     replace(self.tree.root, digest=digest("wrong-root"))):
            with self.assertRaises(contract.IndexRangeError):
                self.verify(root=root)

    def test_duplicate_primary_key_commitment_rejects_even_under_independently_matching_root(self):
        first, second = leaf(key("0")), leaf(key("1"))
        second = replace(second, primary_key_digest=first.primary_key_digest)
        tree = IndependentIndex([first, second])
        with self.assertRaisesRegex(contract.IndexRangeError, "primary-key commitment"):
            self.verify(tree=tree)

    def test_profile_index_table_projection_and_interval_cannot_be_substituted(self):
        for field, value in (("index_id", "other_index"), ("table", "other_rows"),
                             ("projection_digest", digest("other-projection"))):
            with self.subTest(field=field), self.assertRaises(contract.IndexRangeError):
                self.verify(profile=replace(self.tree.profile, **{field: value}))
        with self.assertRaisesRegex(contract.IndexRangeError, "outside"):
            self.verify(interval=contract.KeyInterval(key("1"), key("2")), frontier=self.tree.frontier(self.all))

    def test_path_bound_empty_and_opaque_transplants_do_not_reconstruct_another_position(self):
        profile = self.tree.profile
        self.assertNotEqual(empty(profile, "0"), empty(profile, "1"))
        self.assertNotEqual(empty(profile, "0"), empty(profile, "00"))
        interval = contract.KeyInterval(key("8"), key("8"))
        frontier = self.tree.frontier(interval)
        changed = tuple(replace(record, prefix="3") if record.prefix == "2" else record for record in frontier)
        with self.assertRaises(contract.IndexRangeError):
            self.verify(interval=interval, frontier=changed)

    def test_subtree_cardinality_limits_include_full_key_and_last_branch(self):
        for prefix, maximum in (("a" * 160, 1), ("a" * 159, 16), ("a" * 145, 16**15)):
            self.assertEqual(contract.OpaqueSubtree(prefix, digest("opaque"), maximum).count, maximum)
            with self.assertRaises(contract.IndexRangeError):
                contract.OpaqueSubtree(prefix, digest("opaque"), maximum + 1)
        profile = self.tree.profile
        with self.assertRaises(contract.IndexRangeError):
            contract.branch_node(profile, "a" * 159,
                (contract.CountedNode(digest("impossible-terminal"), 2),) + (None,) * 15)
        # At a shallow prefix individual I64 counts fit, but their sum does not.
        with self.assertRaisesRegex(contract.IndexRangeError, "overflows"):
            contract.branch_node(profile, "", (contract.CountedNode(digest("a"), I64),
                contract.CountedNode(digest("b"), 1), *((None,) * 14)))

    def test_exact_types_bounded_keys_digests_and_counts_are_revalidated(self):
        opaque = self.tree.opaque("1")
        member_value = self.tree.frontier(self.all)[0]
        for name in ("index_id", "table"):
            for value in ("", "Upper", "x" * 129, "two-parts", "é", "nul\0name", True, b"items"):
                changed = {**projection(self.tree.profile), name: value}
                with self.subTest(field=name, value=value):
                    with self.assertRaises(contract.IndexRangeError):
                        contract.IndexProfile(**changed)
                    with self.assertRaises(contract.IndexRangeError):
                        self.verify(profile=bypassed(self.tree.profile, **{name: value}))
        for value in (True, -1, I64 + 1, "1", 1.0):
            with self.subTest(count=value), self.assertRaises(contract.IndexRangeError):
                self.verify(root=bypassed(self.tree.root, count=value))
        for value in ("", "0" * 159, "0" * 161, "A" * 160, "g" * 160,
                      "\0" + "0" * 159, "é" * 160, "\ud800" * 160, True, b"0" * 160):
            with self.subTest(key=value), self.assertRaises(contract.IndexRangeError):
                self.verify(frontier=(bypassed(member_value, key=value),))
        for value in ("sha256:" + "g" * 64, "SHA256:" + "a" * 64, "sha256:" + "a" * 63,
                      "sha256:" + "a" * 65, b"sha256:" + b"a" * 64, None):
            with self.subTest(digest=value):
                with self.assertRaises(contract.IndexRangeError):
                    self.verify(frontier=(bypassed(member_value, primary_row_digest=value),))
                with self.assertRaises(contract.IndexRangeError):
                    contract.IndexProfile("items", "items", value)
                with self.assertRaises(contract.IndexRangeError):
                    self.verify(profile=bypassed(self.tree.profile, projection_digest=value))
        with self.assertRaises(contract.IndexRangeError):
            self.verify(interval=contract.KeyInterval(key("8"), key("8")), frontier=(bypassed(opaque, count=True),))

    def test_incomplete_and_foreign_contexts_frontiers_and_intervals_reject(self):
        valid = dict(profile=self.tree.profile, expected_root=self.tree.root, interval=self.all,
                     frontier=self.tree.frontier(self.all), limits=ranges.IndexRangeLimits())
        for name, instance in (("profile", self.tree.profile), ("expected_root", self.tree.root),
                               ("interval", self.all), ("limits", valid["limits"])):
            for wrong in (None, {}, object.__new__(type(instance))):
                with self.subTest(name=name, wrong=type(wrong)), self.assertRaises(contract.IndexRangeError):
                    ranges.reconstruct_complete_index_range(**{**valid, name: wrong})
        for frontier in ([], iter(valid["frontier"]), {}, "", (None,),
                         (object.__new__(contract.IndexLeaf),), (object.__new__(contract.OpaqueSubtree),)):
            with self.subTest(frontier=type(frontier)), self.assertRaises(contract.IndexRangeError):
                self.verify(frontier=frontier)
        for interval in (bypassed(self.all, lower=True), bypassed(self.all, upper="f"),
                         bypassed(self.all, lower=key("8"), upper=key("1"))):
            with self.assertRaises(contract.IndexRangeError):
                # Exercise production admission, not the fixture's integer
                # parser on deliberately malformed interval fields.
                self.verify(interval=interval, frontier=valid["frontier"])

    def test_each_explicit_budget_matches_independent_cost_and_one_less_rejects(self):
        interval = contract.KeyInterval(key("0f"), key("8"))
        frontier = self.tree.frontier(interval)
        expected = metric_oracle(self.tree.profile, self.tree.root, interval, frontier)
        budgets = {"max_entries": expected["entries"], "max_leaves": expected["leaves"],
                   "max_opened_nodes": expected["opened_nodes"], "max_hashes": expected["hashes"],
                   "max_input_bytes": expected["input_bytes"]}
        exact = ranges.IndexRangeLimits(**budgets)
        self.assertEqual(projection(self.verify(interval=interval, frontier=frontier, limits=exact).metrics), expected)
        for name, value in budgets.items():
            with self.subTest(budget=name), self.assertRaises(contract.IndexRangeError):
                self.verify(interval=interval, frontier=frontier, limits=replace(exact, **{name: value - 1}))

    def test_budget_types_source_ceilings_and_prebounded_frontier_length(self):
        bounded = ranges.IndexRangeLimits()
        for name, maximum in projection(bounded).items():
            for value in (True, 0, -1, maximum + 1, float(maximum), str(maximum)):
                with self.subTest(name=name, value=value), self.assertRaises(contract.IndexRangeError):
                    self.verify(limits=bypassed(bounded, **{name: value}))
        with self.assertRaisesRegex(contract.IndexRangeError, "bounded exact tuple"):
            self.verify(frontier=(self.tree.frontier(self.all)[0],) * 8193)

    def test_singleton_deep_path_and_repeated_calls_have_no_warm_cache_discount(self):
        tree = IndependentIndex([leaf("a" * WIDTH)])
        frontier = tree.frontier(self.all)
        expected = metric_oracle(tree.profile, tree.root, self.all, frontier)
        self.assertEqual((expected["opened_nodes"], expected["child_slots"], expected["hashes"]),
                         (160, 2560, 2561))
        actual_sha256 = hashlib.sha256
        observed = []
        # Accounting observation only: every production hash delegates to the
        # genuine saved implementation. Build every expected value beforehand.
        for _ in range(2):
            with mock.patch.object(contract.hashlib, "sha256", wraps=actual_sha256) as hashes:
                result = self.verify(tree=tree, frontier=frontier)
                self.assertEqual(hashes.call_count, result.metrics.hashes)
            self.assertEqual(projection(result.metrics), expected)
            self.assertEqual(result.root, tree.root)
            observed.append(result.metrics)
        self.assertEqual(observed[0], observed[1])
        bounded = ranges.IndexRangeLimits(max_hashes=expected["hashes"] - 1)
        with mock.patch.object(contract.hashlib, "sha256", wraps=actual_sha256) as hashes:
            with self.assertRaisesRegex(contract.IndexRangeError, "hash budget"):
                self.verify(tree=tree, frontier=frontier, limits=bounded)
            self.assertLessEqual(hashes.call_count, bounded.max_hashes)

    def test_real_256_leaf_reconstruction_fits_source_budgets_without_reducing_width(self):
        # Spread keys over all two-nibble prefixes, retaining 158 nonshared
        # proper ancestors per key. This is component work, not SQL capacity.
        tree = IndependentIndex([leaf(format(index, "02x") + "0" * 158) for index in range(256)])
        result = self.assert_observation(tree, self.all)
        self.assertEqual((result.metrics.entries, result.metrics.leaves, result.root.count), (256, 256, 256))
        self.assertEqual((result.metrics.opened_nodes, result.metrics.child_slots, result.metrics.hashes),
                         (40465, 647440, 647441))
        self.assertLessEqual(result.metrics.input_bytes, 4194304)
        self.assertLessEqual(result.metrics.opened_nodes, 65536)
        self.assertLessEqual(result.metrics.hashes, 1048576)

    def test_inputs_are_unchanged_and_output_is_frozen_fresh_detached_data(self):
        interval = contract.KeyInterval(key("0f"), key("8"))
        frontier = self.tree.frontier(interval)
        before = copy.deepcopy((self.tree.profile, self.tree.root, interval, frontier))
        result = self.verify(interval=interval, frontier=frontier)
        self.assertEqual((self.tree.profile, self.tree.root, interval, frontier), before)
        self.assertIsNot(result.profile, self.tree.profile)
        self.assertIsNot(result.interval, interval)
        self.assertIsNot(result.root, self.tree.root)
        originals = {record.key: record for record in frontier if type(record) is contract.IndexLeaf}
        for item in result.leaves:
            self.assertIsNot(item, originals[item.key])
        with self.assertRaises(FrozenInstanceError):
            result.root.count = 0
        with self.assertRaises(FrozenInstanceError):
            result.metrics.hashes = 0
        with self.assertRaises(FrozenInstanceError):
            result.leaves = ()
        # Deliberate mutation of the caller's nominally frozen input does not
        # change the already-returned owned snapshots; this is not concurrency.
        object.__setattr__(interval, "upper", None)
        original_leaf = next(record for record in frontier if type(record) is contract.IndexLeaf)
        object.__setattr__(original_leaf, "primary_row_digest", digest("changed-after-return"))
        self.assertEqual(result.interval, before[2])
        self.assertEqual(result.leaves, tuple(record for record in before[3] if type(record) is contract.IndexLeaf))

    def test_supplied_self_consistent_root_is_relative_evidence_not_primary_or_time_authority(self):
        # Arbitrary commitments are structurally valid inputs. No selected row,
        # primary proof, revision, time, signer or source registry is consulted.
        alternative = IndependentIndex([leaf(key("3"), "unjoined-primary-claim")])
        result = self.assert_observation(alternative, self.all)
        self.assertEqual(result.root.count, 1)
        self.assertNotEqual(result.root, self.tree.root)
        with self.assertRaises(contract.IndexRangeError):
            self.verify(tree=alternative, root=self.tree.root)

    def test_shared_work_exact_hash_frame_oracle_preserves_real_range_results(self):
        for tree, bounds in ((IndependentIndex([]), self.all), (self.tree, self.all),
                             (self.tree, contract.KeyInterval(key("1"), key("2"))),
                             (self.tree, contract.KeyInterval(key("8"), key("8")))):
            proof = tree.frontier(bounds)
            expected = shared_work_oracle(tree.profile, tree.root, bounds, proof)
            legacy = self.verify(tree=tree, interval=bounds, frontier=proof)
            work = measured._ValidationWork(measured.QueryReadValidationLimits())
            actual_sha = hashlib.sha256
            with mock.patch.object(hashlib, "sha256", wraps=actual_sha) as hashes:
                observed = ranges._reconstruct_complete_index_range(
                    profile=tree.profile, expected_root=tree.root, interval=bounds,
                    frontier=proof, limits=ranges.IndexRangeLimits(), work=work)
            self.assertEqual(observed, legacy)
            self.assertEqual((work.hash_work, work.input_bytes, work.json_nodes), expected)
            self.assertEqual(hashes.call_count, expected[0])
            self.assertEqual(observed.metrics.hashes, expected[0])

    def test_shared_range_independent_exact_and_each_minus_one_quota(self):
        tree = IndependentIndex([leaf(key("a"))])
        proof = tree.frontier(self.all)
        expected = shared_work_oracle(tree.profile, tree.root, self.all, proof)
        for dimension in (None, 0, 1, 2):
            values = list(expected)
            if dimension is not None:
                values[dimension] -= 1
            work = measured._ValidationWork(measured.QueryReadValidationLimits(*values))
            arguments = dict(profile=tree.profile, expected_root=tree.root, interval=self.all,
                             frontier=proof, limits=ranges.IndexRangeLimits(), work=work)
            if dimension is None:
                self.assertEqual(ranges._reconstruct_complete_index_range(**arguments).root, tree.root)
                self.assertEqual((work.hash_work, work.input_bytes, work.json_nodes), expected)
            else:
                with self.subTest(dimension=dimension), self.assertRaises(measured.QueryReadWorkError):
                    ranges._reconstruct_complete_index_range(**arguments)

    def test_shared_range_preconsumed_work_and_real_repeats_have_no_refund(self):
        tree = IndependentIndex([leaf(key("b"))])
        proof = tree.frontier(self.all)
        expected = shared_work_oracle(tree.profile, tree.root, self.all, proof)
        prior = (7, 101, 13)
        limits = tuple(before + 2 * delta for before, delta in zip(prior, expected))
        work = measured._ValidationWork(measured.QueryReadValidationLimits(*limits))
        work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
        for number in (1, 2):
            result = ranges._reconstruct_complete_index_range(
                profile=tree.profile, expected_root=tree.root, interval=self.all,
                frontier=proof, limits=ranges.IndexRangeLimits(), work=work)
            self.assertEqual(result.root, tree.root)
            self.assertEqual((work.hash_work, work.input_bytes, work.json_nodes),
                             tuple(before + number * delta for before, delta in zip(prior, expected)))
        with self.assertRaises(measured.QueryReadWorkError):
            ranges._reconstruct_complete_index_range(profile=tree.profile, expected_root=tree.root,
                interval=self.all, frontier=proof, limits=ranges.IndexRangeLimits(), work=work)

    def test_shared_range_encoding_reservation_precedes_real_hash_and_no_work_preserves_facade(self):
        tree = IndependentIndex([])
        input_bytes = metric_oracle(tree.profile, tree.root, self.all, ())["input_bytes"]
        work = measured._ValidationWork(measured.QueryReadValidationLimits(
            max_input_bytes=input_bytes + 1))
        with mock.patch.object(hashlib, "sha256", side_effect=AssertionError("unreserved SHA")):
            with self.assertRaises(measured.QueryReadWorkError):
                ranges._reconstruct_complete_index_range(profile=tree.profile, expected_root=tree.root,
                    interval=self.all, frontier=(), limits=ranges.IndexRangeLimits(), work=work)
        actual = ranges._reconstruct_complete_index_range
        with mock.patch.object(ranges, "_reconstruct_complete_index_range", wraps=actual) as worker:
            self.verify(tree=tree)
        self.assertEqual(worker.call_count, 1)
        self.assertIsNone(worker.call_args.kwargs["work"])

    def test_shared_range_work_exact_type_and_empty_helper_real_hash_agree(self):
        class ForeignWork(measured._ValidationWork):
            pass
        for value in (object(), ForeignWork(measured.QueryReadValidationLimits())):
            with self.assertRaises(contract.IndexRangeError):
                ranges._reconstruct_complete_index_range(profile=self.tree.profile,
                    expected_root=self.tree.root, interval=self.all, frontier=(),
                    limits=ranges.IndexRangeLimits(), work=value)
        expected_frames = (EMPTY, *common(self.tree.profile), "0", "", "0")
        expected = (1, sum(2 * len(value) + 8 for value in expected_frames),
                    2 * len(expected_frames))
        work = measured._ValidationWork(measured.QueryReadValidationLimits(*expected))
        ranges._prepare_empty_work(self.tree.profile, "", work)
        self.assertEqual(contract.empty_node(self.tree.profile, ""),
                         contract.CountedNode(*empty(self.tree.profile, "")))
        self.assertEqual((work.hash_work, work.input_bytes, work.json_nodes), expected)


if __name__ == "__main__":
    unittest.main()
