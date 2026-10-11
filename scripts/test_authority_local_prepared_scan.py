#!/usr/bin/env python3
"""Prepared scan components, not signed installation or native acceptance.

Real temp files, held FDs, named paths and reads exercise the production path
guards. Process admission, clock samples, source-root admission and kernel
ownership/verity/immutable metadata are explicitly synthetic. No run() occurs.
"""
import inspect
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.test_authority_local_prepared_install import PreparedTree, digest
from serverware import authority_local_artifact_measure as measure
from serverware import authority_local_install as install


class ScanTree(PreparedTree):
    FRESH = "fresh.json"

    def __init__(self, files=None):
        if files is not None:
            self.STATIC = files

    def __enter__(self):
        super().__enter__()
        # pathlib's parents=True applies its requested mode only to the leaf;
        # explicitly establish the required private modes on our own fixtures.
        for tree in (self.source, self.prepared):
            tree.chmod(0o700)
            for path in tree.rglob("*"):
                if path.is_dir():
                    path.chmod(0o700)
        owner = self.owner
        self.clock = {"boot": 100, "epoch": 1000}
        self.full_calls, self.full_completed = 0, 0
        self.link_visits, self.path_calls, self.source_calls = [], 0, 0
        self.context, self.failed_context = None, None
        self.changed, self.path_success_after_change = False, 0
        # A pre-existing destination ancestor is retained in every scan path.
        self.baseline = self.directory / "retained-ancestor"
        self.baseline.mkdir(mode=0o700)
        fd = owner._hold(os.open(self.baseline, install._READ | os.O_DIRECTORY))
        info = self.real_fstat(fd)
        owner.links.append((owner.root, self.baseline.name, fd, (info.st_dev, info.st_ino)))
        self.original_source = self.directory / "original-public-input"
        self.write(self.original_source, b"original bounded public input")
        source = owner._hold(os.open(self.original_source, install._READ))
        owner.sources["input"] = (source, install.protected._identity(os.fstat(source)), b"original bounded public input")
        owner.value.update(bootIdDigest="synthetic-boot", issuedAtBoottimeNs=100, deadlineBoottimeNs=200,
            issuedAtUnixNanos=1000, expiresAtUnixNanos=2000)
        owner.last_boot, owner.last_epoch = 100, 1000
        self.stack.enter_context(patch.object(install, "_boot", return_value="synthetic-boot"))
        self.stack.enter_context(patch.object(install.time, "clock_gettime_ns", side_effect=lambda _clock: self.clock["boot"]))
        self.stack.enter_context(patch.object(install.time, "time_ns", side_effect=lambda: self.clock["epoch"]))
        owner._origin = self.check  # No successful real process admission claim.
        owner._check_source_root = self.source_check
        # Restore production methods behind measuring wrappers: the inherited
        # filesystem fixture intentionally replaces these with inert callbacks.
        owner.check, owner._check_scan_path, owner._check_links = self.full_check, self.path_check, self.links_check
        self.rename = self.stack.enter_context(patch.object(install, "_rename", side_effect=AssertionError("scan consumed tree")))
        self.effects = [self.stack.enter_context(patch.object(owner, name, side_effect=AssertionError("scan mutated installation")))
            for name in ("_publish", "_state", "_copy")]
        return self

    def source_check(self):
        self.source_calls += 1
        if getattr(self, "source_failure", None) is not None:
            raise self.source_failure

    def links_check(self, links):
        self.link_visits.append((self.context, tuple(row[2] for row in links)))
        return install.LocalAuthorityInstaller._check_links(self.owner, links)

    def full_check(self):
        before, self.context = self.context, "full"
        self.full_calls += 1
        try:
            install.LocalAuthorityInstaller.check(self.owner)
            self.full_completed += 1
        except BaseException:
            self.failed_context = "full"
            raise
        finally:
            self.context = before

    def path_check(self, links):
        before, self.context = self.context, "path"
        self.path_calls += 1
        try:
            install.LocalAuthorityInstaller._check_scan_path(self.owner, links)
            if self.changed:
                self.path_success_after_change += 1
        except BaseException:
            self.failed_context = "path"
            raise
        finally:
            self.context = before

    def no_effects(self, case):
        case.assertTrue(self.prepared.is_dir())
        case.assertFalse((self.directory / ".incoming").exists())
        self.rename.assert_not_called()
        for effect in self.effects:
            effect.assert_not_called()


class PreparedScanTests(unittest.TestCase):
    def test_cold_catalog_hits_keep_actual_scan_guards_without_observed_memo_seeding(self):
        files = {"one/nested/empty": b"", "one/nested/leaf": b"public\x00\xffbytes" * 1024,
                 "two/nested/leaf": b"different public bytes"}
        with ScanTree(files) as fixture:
            catalog_rows = []
            for name, raw in files.items():
                with (fixture.prepared / name).open("rb") as held:
                    row = measure.observe_catalog_entry(held.fileno(), check=fixture.owner.check)
                self.assertEqual(row["sha256"], digest(raw))
                inode = fixture.real_stat(fixture.prepared / name).st_ino
                self.assertEqual(sum(size for seen, _, size in fixture.reads if seen == inode), len(raw))
                catalog_rows.append(row)
            encoded = json.dumps({"schema": "serverware.sealedContentCatalog/v1",
                "entries": sorted(catalog_rows, key=lambda row: (row["fsVerityDigest"], row["size"]))},
                sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
            # Producer measurements above read actual bytes. Clear only the
            # observed memo, so adoption must use the explicitly pinned scope.
            self.assertEqual(len(measure._FILE_DIGEST_CACHE), len(files))
            measure._FILE_DIGEST_CACHE.clear()
            fixture.reads.clear(); fixture.link_visits.clear()
            fixture.full_calls = fixture.full_completed = fixture.path_calls = fixture.source_calls = fixture.calls = 0
            fixture.clock.update(boot=101, epoch=1001)
            clocks = (install._boot, install.time.clock_gettime_ns, install.time.time_ns)
            for clock in clocks: clock.reset_mock()
            before = fixture.identities()
            with measure.pinned_content_catalog(encoded, digest(encoded)):
                _, adopted = fixture.adopt()
                self.assertFalse(measure._FILE_DIGEST_CACHE)
            self.assertFalse(measure._FILE_DIGEST_CACHE)
            self.assertEqual({name: row["sha256"] for name, row in adopted.items()},
                             {name: digest(raw) for name, raw in files.items()})
            self.assertEqual(sorted(fixture.reads), sorted(
                (fixture.real_stat(fixture.prepared / name).st_ino, len(raw), 0) for name, raw in files.items()))
            # Empty-file EOF parity is not a claimed body-read saving.
            self.assertEqual((fixture.full_calls, fixture.full_completed), (2, 2))
            self.assertEqual(max(len(fds) for kind, fds in fixture.link_visits if kind == "path"), 4)
            checks = fixture.full_calls + fixture.path_calls
            self.assertEqual((fixture.source_calls, fixture.calls), (checks, checks))
            self.assertEqual([clock.call_count for clock in clocks], [checks] * 3)
            self.assertEqual((fixture.owner.last_boot, fixture.owner.last_epoch), (101, 1001))
            self.assertEqual(fixture.identities(), before)
            fixture.no_effects(self)

    def test_full_sweeps_are_constant_and_path_work_depends_on_depth_not_width(self):
        for width in (1, 8, 24):
            files = {f"branch-{index}/nested/leaf": f"public bytes {index}".encode() for index in range(width)}
            with self.subTest(width=width), ScanTree(files) as fixture:
                before = fixture.identities()
                parents, rows = fixture.adopt()
                self.assertEqual(set(rows), set(files))
                self.assertEqual(len(parents), 1 + 2 * width)
                self.assertEqual(fixture.identities(), before)
                self.assertEqual((fixture.full_calls, fixture.full_completed), (2, 2))
                full = [fds for kind, fds in fixture.link_visits if kind == "full"]
                paths = [fds for kind, fds in fixture.link_visits if kind == "path"]
                self.assertEqual([len(fds) for fds in full], [1, 2 + 2 * width])
                self.assertEqual(len(paths), fixture.path_calls)
                self.assertEqual(max(map(len, paths)), 4)  # baseline, root, branch, nested
                self.assertLessEqual(sum(map(len, paths)), 4 * fixture.path_calls)
                self.assertLessEqual(fixture.path_calls, 20 * width + 4)
                self.assertEqual(fixture.source_calls, fixture.full_calls + fixture.path_calls)
                fixture.no_effects(self)
        for depth in (1, 4):
            path = "/".join([f"depth-{i}" for i in range(depth)] + ["leaf"])
            with self.subTest(depth=depth), ScanTree({path: b"public"}) as fixture:
                fixture.adopt()
                self.assertEqual(max(len(fds) for kind, fds in fixture.link_visits if kind == "path"), depth + 2)
                self.assertEqual(fixture.full_calls, 2)

    def test_current_ancestor_and_baseline_changes_refuse_in_the_path_guard(self):
        for target, change in (("ancestor", "rename"), ("ancestor", "replace"), ("ancestor", "writable"),
                ("ancestor", "owner"), ("baseline", "replace"), ("baseline", "writable")):
            with self.subTest(target=target, change=change), ScanTree({"branch/nested/leaf": b"public"}) as fixture:
                path = fixture.baseline if target == "baseline" else fixture.prepared / "branch"
                def mutate(_fd):
                    if change in {"rename", "replace"}:
                        path.rename(fixture.directory / "retained-original")
                        if change == "replace": path.mkdir(mode=0o700)
                    elif change == "writable":
                        path.chmod(0o722)
                    else:
                        fixture.metadata[fixture.real_stat(path).st_ino] = {"st_uid": 23}
                fixture.after_read = mutate
                with self.assertRaises((ValueError, OSError)):
                    fixture.adopt()
                self.assertEqual(fixture.failed_context, "path")
                self.assertEqual(fixture.full_calls, 1)
                fixture.no_effects(self)

    def test_already_scanned_sibling_is_rechecked_at_full_exit_before_consumption(self):
        with ScanTree({"first/leaf": b"first", "second/leaf": b"second"}) as fixture:
            owner, adopted = fixture.owner, []
            original = owner._adopt
            def adopt(entry, *, check=None):
                if adopted:
                    previous = fixture.prepared / adopted[0].split("/")[0]
                    # This changes the earlier sibling itself, not the current
                    # path or parent directory. Its real inode is retained.
                    previous.chmod(0o722)
                    fixture.changed = True
                row = original(entry, check=check)
                adopted.append(entry["path"])
                return row
            with patch.object(owner, "_adopt", side_effect=adopt):
                with self.assertRaises(ValueError): fixture.adopt()
            self.assertEqual(len(adopted), 2)
            self.assertGreater(fixture.path_success_after_change, 0)
            self.assertEqual((fixture.full_calls, fixture.full_completed, fixture.failed_context), (2, 1, "full"))
            fixture.no_effects(self)

    def test_original_sources_clocks_source_root_and_cancellation_remain_fresh(self):
        for change in ("source", "boot-expired", "wall-expired", "boot-rollback", "wall-rollback", "source-root", "cancel"):
            with self.subTest(change=change), ScanTree({"branch/leaf": b"public"}) as fixture:
                failure = KeyboardInterrupt("synthetic cancellation") if change == "cancel" else ValueError("synthetic source root refused")
                def mutate(_fd):
                    if change == "source": fixture.original_source.chmod(0o400)
                    elif change == "source-root": fixture.source_failure = failure
                    elif change == "cancel":
                        def cancel(): raise failure
                        fixture.cancel = cancel
                    else:
                        key = "boot" if change.startswith("boot") else "epoch"
                        fixture.clock[key] = (200 if key == "boot" else 2000) if change.endswith("expired") else (99 if key == "boot" else 999)
                fixture.after_read = mutate
                with self.assertRaises(KeyboardInterrupt if change == "cancel" else ValueError) as caught:
                    fixture.adopt()
                if change in {"source-root", "cancel"}: self.assertIs(caught.exception, failure)
                self.assertEqual(fixture.failed_context, "path")
                self.assertEqual(fixture.owner.value["deadlineBoottimeNs"], 200)
                self.assertEqual(fixture.owner.value["expiresAtUnixNanos"], 2000)
                fixture.no_effects(self)

    def test_direct_adopt_defaults_to_full_guard_and_does_not_accept_bad_callback(self):
        with ScanTree({"one/leaf": b"public", "other/leaf": b"different"}) as fixture:
            fixture.adopt()
            entry = next(row for row in fixture.entries if row["path"] == "one/leaf")
            fixture.link_visits.clear(); fixture.full_calls = fixture.full_completed = fixture.path_calls = 0
            row = fixture.owner._adopt(entry)
            self.assertEqual(row["sha256"], digest(b"public"))
            self.assertGreaterEqual(fixture.full_calls, 3)
            self.assertEqual(fixture.path_calls, 0)
            self.assertTrue(all(kind == "full" and len(fds) == len(fixture.owner.links) for kind, fds in fixture.link_visits))
            (fixture.prepared / "other").chmod(0o722)
            with self.assertRaises(ValueError): fixture.owner._adopt(entry)
            self.assertEqual(fixture.failed_context, "full")
            with self.assertRaises(ValueError): fixture.owner._adopt(entry, check=False)
            fixture.no_effects(self)

    def test_run_effect_order_is_source_only_and_full_guard_contract_is_retained(self):
        # No successful admission/signing stubs: this is deliberately only the
        # production call placement surrounding the exercised components.
        source = inspect.getsource(install.LocalAuthorityInstaller.run)
        scan = source.index("parents, adopted = self._prepared_tree()")
        directories = source.index('for name in (".incoming", "generations", "receipts")')
        publish = source.index('self._publish(self.name + ".plan.json"')
        prepared = source.index('self._state("Prepared")')
        consume = source.index('_rename(self.root, self.value["preparedStatic"]["relativePath"]')
        self.assertLess(scan, directories); self.assertLess(directories, publish)
        self.assertLess(publish, prepared); self.assertLess(prepared, consume)
        self.assertIn('if prepared:\n                self.check()\n                _rename(', source)
        self.assertNotIn("_check_scan_path", source)
        self.assertNotIn("os.unlink", source)
        check = inspect.getsource(install.LocalAuthorityInstaller.check)
        self.assertLess(check.index("self._check_base()"), check.index("self._check_links(self.links)"))
        self.assertLess(check.index("self._check_links(self.links)"), check.index("self._check_source_root()"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
