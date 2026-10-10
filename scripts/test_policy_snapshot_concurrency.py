#!/usr/bin/env python3
"""Bounded real-getter/loader concurrency controls, not authority acceptance.

Only external policy I/O, signing compilation and high-water storage are
synthetic. No loader/getter/CAS result is supplied by a mock. Threads synchronize
with bounded Events/Barriers; there are no sleeps, sockets, services or DB writes.
"""
from __future__ import annotations

import ast
from collections import defaultdict
from contextlib import ExitStack
from dataclasses import replace
import inspect
import os
from pathlib import Path
import sys
import textwrap
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class PolicySnapshotConcurrencyTests(unittest.TestCase):
    MISS = ["publication", "stat", "trust", "read", "trust", "compile",
            "high_water", "identity", "trust_recheck", "high_water", "publication"]
    HIT = ["publication", "stat", "trust", "high_water", "identity",
           "trust_recheck", "high_water", "publication"]

    def setUp(self):
        from serverware import policy_bundle as policy
        from serverware import control_plane_policy_file_publication as publication
        self.policy = policy
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.workers, self.releases, self.barriers = [], [], []
        self.addCleanup(self.cleanup_workers)
        self.local, self.lock = threading.local(), threading.RLock()
        self.calls, self.hooks, self.sources = defaultdict(list), {}, {}
        self.path = Path("/synthetic-policy-concurrency/policy.json")
        identity = policy.PolicyFileIdentity(1, 2, 3, 4, 0o100600, 1, 2, 5, 6, "sha256:" + "1" * 64)
        trust = policy.PolicySigningTrustIdentity(
            policy.SecureFileIdentity(1, 3, 3, 4, 0o100600, 1, 2, 5, 6, "sha256:" + "2" * 64),
            "sha256:" + "3" * 64, "sha256:" + "4" * 64)
        snapshot = policy.PolicySnapshot(
            raw={"metadata": {"id": "synthetic-policy", "sequence": 1, "rollbackEpoch": 0},
                 "synthetic": {"copy": [1]}}, hash="sha256:" + "5" * 64,
            principals={}, credentials={}, routes=())
        self.authority = SimpleNamespace(identity=identity, trust=SimpleNamespace(identity=trust), snapshot=snapshot)
        self.loader = policy.PolicyBundleLoader(self.path)
        for name, value in (("POLICY_BUNDLE_PATH", self.path), ("_SNAPSHOT_CACHE_LOCK", self.lock),
                ("_POLICY_BUNDLE_LOADER", self.loader), ("_SNAPSHOT_CACHE", None),
                ("_SNAPSHOT_CACHE_GENERATION", 0), ("POLICY_MIN_SEQUENCE", 1), ("POLICY_MIN_ROLLBACK_EPOCH", 0)):
            self.stack.enter_context(patch.object(policy, name, value))
        # The real publication admission wrapper still normalizes refusal.
        self.stack.enter_context(patch.object(publication, "require_loadable", self.publication))
        for name, function in (("_read_secure_file_stat", self.stat), ("_load_policy_signing_trust", self.trust),
                ("_read_stable_policy_file", self.read), ("compile_policy_bundle", self.compile),
                ("verify_policy_high_water", self.high_water), ("_recheck_policy_path_identity", self.identity),
                ("_recheck_policy_signing_trust", self.trust_recheck), ("_secure_path_exists", lambda *a, **k: True)):
            self.stack.enter_context(patch.object(policy, name, function))

    def step(self, label):
        role = getattr(self.local, "role", "main")
        self.assertEqual(self.lock._is_owned(), getattr(self.local, "outer", False), label)
        self.calls[role].append(label)
        hook = self.hooks.get((role, label))
        if hook:
            hook()
        return self.sources.get(role, self.authority)

    def publication(self, path, *, expected_identity=None):
        source = self.step("publication")
        if expected_identity is not None:
            self.assertEqual(expected_identity, source.identity)

    def stat(self, path, **kwargs):
        source = self.step("stat")
        self.assertEqual(kwargs, {"label": "policy bundle", "expected_mode": 0o600,
                                  "maximum_size": self.policy.MAX_POLICY_BUNDLE_BYTES})
        names = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        return SimpleNamespace(**dict(zip(names, source.identity.stat_components)))

    def trust(self):
        return self.step("trust").trust

    def read(self, path):
        return b"{}", self.step("read").identity

    def compile(self, raw, **kwargs):
        source = self.step("compile")
        self.assertEqual(raw, {})
        self.assertEqual(kwargs, {"verify_signature": True, "validate_schema": True, "signing_trust": source.trust})
        return source.snapshot

    def high_water(self, snapshot):
        self.assertEqual(snapshot, self.step("high_water").snapshot)
        return {}

    def identity(self, path, identity):
        self.assertEqual(identity, self.step("identity").identity)

    def trust_recheck(self, identity):
        self.assertEqual(identity, self.step("trust_recheck").trust.identity)

    def spawn(self, role, operation=None):
        worker = SimpleNamespace(result=[], errors=[], done=threading.Event())
        def run():
            self.local.role = role
            try:
                worker.result.append((operation or self.policy.get_policy_snapshot)())
            except BaseException as error:
                worker.errors.append(error)
            finally:
                worker.done.set()
        worker.thread = threading.Thread(target=run, name="synthetic-policy-" + role)
        self.workers.append(worker)
        worker.thread.start()
        return worker

    def joined(self, worker):
        self.assertTrue(worker.done.wait(4), "synthetic policy worker did not finish")
        worker.thread.join(1)
        self.assertFalse(worker.thread.is_alive())
        self.assertEqual(worker.errors, [])
        self.assertEqual(len(worker.result), 1)
        return worker.result[0]

    def cleanup_workers(self):
        for event in self.releases:
            event.set()
        for barrier in self.barriers:
            barrier.abort()
        for worker in self.workers:
            worker.thread.join(4)
            self.assertFalse(worker.thread.is_alive(), "synthetic policy worker survived cleanup")

    def pause(self, role, label="publication", *, occurrence=2, failure=False):
        entered, release = threading.Event(), threading.Event()
        self.releases.append(release)
        def hook():
            if self.calls[role].count(label) != occurrence:
                return
            entered.set()
            self.assertTrue(release.wait(3), "synthetic validation was not released")
            if failure:
                raise self.policy.PolicyBundleError("synthetic rejected authority")
        self.hooks[(role, label)] = hook
        return entered, release

    def invalidated(self):
        with self.lock:
            self.policy._invalidate_policy_snapshot_cache_locked()

    def assert_private(self, *snapshots):
        for snapshot in snapshots:
            self.assertIsNotNone(snapshot)
            self.assertIsNot(snapshot, self.authority.snapshot)
            self.assertIsNot(snapshot.raw, self.authority.snapshot.raw)
            with self.assertRaises(TypeError):
                snapshot.raw["synthetic"]["copy"].append(99)
        if len(snapshots) == 2:
            self.assertIsNot(snapshots[0], snapshots[1])
            self.assertIsNot(snapshots[0].raw["synthetic"], snapshots[1].raw["synthetic"])
        self.assertEqual(self.authority.snapshot.raw["synthetic"], {"copy": [1]})

    def overlap(self, label):
        barrier = threading.Barrier(2, timeout=3)
        self.barriers.append(barrier)
        for role in ("one", "two"):
            def hook(role=role):
                if self.calls[role].count(label) == 1:
                    barrier.wait()
            self.hooks[(role, label)] = hook
        one, two = self.spawn("one"), self.spawn("two")
        return self.joined(one), self.joined(two)

    def test_cold_readers_both_fully_validate_without_coalescing(self):
        one, two = self.overlap("compile")
        self.assert_private(one, two)
        for role in ("one", "two"):
            self.assertEqual(self.calls[role], self.MISS)
        self.assertIs(self.policy._POLICY_BUNDLE_LOADER, self.loader)
        self.assertIs(self.policy._SNAPSHOT_CACHE, self.loader.cache)
        self.assertEqual(self.policy._SNAPSHOT_CACHE_GENERATION, 1)

    def test_cached_readers_each_recheck_high_water_twice_and_return_private_copies(self):
        self.assert_private(self.policy.get_policy_snapshot())
        one, two = self.overlap("high_water")
        self.assert_private(one, two)
        for role in ("one", "two"):
            self.assertEqual(self.calls[role], self.HIT)
            self.assertEqual(self.calls[role].count("high_water"), 2)

    def test_explicit_invalidation_including_empty_to_empty_fences_inflight_readers(self):
        for warm in (False, True):
            with self.subTest(warm=warm):
                self.invalidated()
                if warm:
                    self.assert_private(self.policy.get_policy_snapshot())
                role = "warm" if warm else "cold"
                entered, release = self.pause(role)
                worker = self.spawn(role)
                self.assertTrue(entered.wait(3))
                generation = self.policy._SNAPSHOT_CACHE_GENERATION
                self.invalidated()
                self.assertIsNone(self.loader.cache)
                self.invalidated()
                self.assertIsNone(self.loader.cache)
                self.assertEqual(self.policy._SNAPSHOT_CACHE_GENERATION, generation + 2)
                release.set()
                self.assertIsNone(self.joined(worker))
                self.assertIsNone(self.loader.cache)
                self.assertEqual(self.policy._SNAPSHOT_CACHE, (None, None, None))

    def test_late_failure_cannot_clear_or_fall_back_to_successful_winner(self):
        entered, release = self.pause("old", failure=True)
        old = self.spawn("old")
        self.assertTrue(entered.wait(3))
        self.assert_private(self.joined(self.spawn("winner")))
        winner = self.loader.cache
        release.set()
        self.assertIsNone(self.joined(old))
        self.assertIs(self.loader.cache, winner)
        self.assertIs(self.policy._SNAPSHOT_CACHE, winner)

    def test_late_success_cannot_overwrite_different_file_trust_or_policy_authority(self):
        variants = {
            "file": dict(identity=replace(self.authority.identity, inode=99)),
            "file_digest": dict(identity=replace(self.authority.identity, file_sha256="sha256:" + "a" * 64)),
            "trust": dict(trust=SimpleNamespace(identity=replace(self.authority.trust.identity, revocation_digest="sha256:" + "b" * 64))),
            "hash": dict(snapshot=replace(self.authority.snapshot, hash="sha256:" + "c" * 64)),
        }
        for field, value in (("id", "different-policy"), ("sequence", 2), ("rollbackEpoch", 1)):
            raw = dict(self.authority.snapshot.raw)
            raw["metadata"] = dict(raw["metadata"], **{field: value})
            variants[field] = dict(snapshot=replace(self.authority.snapshot, raw=raw))
        for name, changed in variants.items():
            with self.subTest(authority=name):
                self.invalidated()
                old_role, winner_role = "old-" + name, "winner-" + name
                self.sources[winner_role] = SimpleNamespace(**(vars(self.authority) | changed))
                entered, release = self.pause(old_role)
                old = self.spawn(old_role)
                self.assertTrue(entered.wait(3))
                self.assertIsNotNone(self.joined(self.spawn(winner_role)))
                winner = self.loader.cache
                release.set()
                self.assertIsNone(self.joined(old))
                self.assertIs(self.loader.cache, winner)
                self.assertIs(self.policy._SNAPSHOT_CACHE, winner)

    def test_path_loader_and_configuration_changes_fence_completion(self):
        for kind in ("path", "loader", "trust_path", "schema", "floor", "release", "revoked"):
            with self.subTest(kind=kind), ExitStack() as changes:
                self.invalidated()
                role = "drift-" + kind
                entered, release = self.pause(role)
                old = self.spawn(role)
                self.assertTrue(entered.wait(3))
                current_loader = self.policy._POLICY_BUNDLE_LOADER
                if kind == "loader":
                    replacement = self.policy.PolicyBundleLoader(self.policy.POLICY_BUNDLE_PATH)
                    changes.enter_context(patch.object(self.policy, "_POLICY_BUNDLE_LOADER", replacement))
                elif kind == "revoked":
                    changes.enter_context(patch.dict(os.environ, {"SERVERWARE_POLICY_REVOKED_SIGNING_KEY_IDS": "synthetic-key"}))
                else:
                    attribute, value = {
                        "path": ("POLICY_BUNDLE_PATH", self.path.with_name("changed.json")),
                        "trust_path": ("POLICY_SIGNING_PUBLIC_KEY_PATH", self.path.with_name("changed.pem")),
                        "schema": ("SCHEMA_DIR", self.path.parent / "changed-schema"),
                        "floor": ("POLICY_MIN_SEQUENCE", 2), "release": ("RELEASE_CHANNEL", "synthetic-changed"),
                    }[kind]
                    changes.enter_context(patch.object(self.policy, attribute, value))
                release.set()
                self.assertIsNone(self.joined(old))
                self.assertIsNone(current_loader.cache)
                self.assertIsNone(self.policy._POLICY_BUNDLE_LOADER.cache)

    def test_path_change_during_configuration_capture_refuses_old_path_result(self):
        original = self.policy._policy_snapshot_configuration
        def capture():
            self.policy.POLICY_BUNDLE_PATH = self.path.with_name("changed-during-capture.json")
            return original()
        with patch.object(self.policy, "_policy_snapshot_configuration", capture):
            self.assertIsNone(self.policy.get_policy_snapshot())
        self.assertIsNone(self.loader.cache)
        self.assertEqual(self.policy._SNAPSHOT_CACHE, (None, None, None))

    def test_unsettled_publication_refuses_cached_and_cold_reads_outside_lock(self):
        for warm in (False, True):
            with self.subTest(warm=warm):
                self.invalidated()
                self.hooks.clear()
                if warm:
                    self.assert_private(self.policy.get_policy_snapshot())
                self.calls["main"].clear()
                def reject():
                    raise ValueError("synthetic unsettled publication")
                self.hooks[("main", "publication")] = reject
                self.assertIsNone(self.policy.get_policy_snapshot())
                self.assertEqual(self.calls["main"], ["publication"])
                self.assertIsNone(self.loader.cache)
                self.assertEqual(self.policy._SNAPSHOT_CACHE, (None, None, None))

    def test_outer_reentrant_lock_preserves_loaded_publication_style_cache_join(self):
        entered, invalidated = threading.Event(), threading.Event()
        def invalidate():
            entered.set()
            self.invalidated()
            invalidated.set()
        self.local.outer = True
        try:
            with self.lock:
                first = self.policy.get_policy_snapshot()
                loader, cache = self.policy._POLICY_BUNDLE_LOADER, self.loader.cache
                contender = self.spawn("publisher", invalidate)
                self.assertTrue(entered.wait(3))
                second = self.policy.get_policy_snapshot()
                self.assertFalse(invalidated.is_set())
                self.assertIs(self.policy._POLICY_BUNDLE_LOADER, loader)
                self.assertEqual(self.loader.cache[0], cache[0])
                self.assertEqual(self.loader.cache[2], cache[2])
                self.assertIs(self.policy._SNAPSHOT_CACHE, self.loader.cache)
                self.assertEqual(first.hash, second.hash)
                self.assert_private(first, second)
        finally:
            self.local.outer = False
        self.assertIsNone(self.joined(contender))
        self.assertTrue(invalidated.is_set())
        self.assertIs(self.policy._POLICY_BUNDLE_LOADER, self.loader)

    def test_both_publication_owners_use_named_invalidation_under_existing_lock(self):
        # Source-owner check only: real helper behavior is exercised above.
        # This does not replace a publication transaction acceptance test.
        for function in (self.policy.write_policy_bundle, self.policy._write_policy_bundle_in_transaction):
            with self.subTest(owner=function.__name__):
                tree = ast.parse(textwrap.dedent(inspect.getsource(function)))
                owners = [node for node in ast.walk(tree) if isinstance(node, ast.With)
                          and any(isinstance(item.context_expr, ast.Name)
                                  and item.context_expr.id == "_SNAPSHOT_CACHE_LOCK" for item in node.items)]
                self.assertEqual(len(owners), 1)
                calls = [node for node in ast.walk(owners[0]) if isinstance(node, ast.Call)
                         and isinstance(node.func, ast.Name) and node.func.id == "_invalidate_policy_snapshot_cache_locked"]
                self.assertEqual(len(calls), 1)
                self.assertEqual((calls[0].args, calls[0].keywords), ([], []))


if __name__ == "__main__":
    unittest.main(verbosity=2)
